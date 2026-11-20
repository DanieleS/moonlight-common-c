#include "Limelight-internal.h"
#include "FrameWarp.h"

#include <math.h>

// The tag of a frame is kept for this many frames (indexed by frame number)
#define FW_TAG_RING_SIZE 64

// Controller packets kept with their send time. A tag that points further back has no stick term.
#define FW_CONTROLLER_RING_SIZE 4096

// A picture whose tag is missing is extrapolated from the two tags before it, for this many frames
#define FW_EXTRAPOLATE_MAX_FRAMES 4
#define FW_EXTRAPOLATE_SEARCH_FRAMES 8

// With no input sent for this long nothing is in flight, so both sides' sums must be equal
#define FW_IDLE_REBASE_US 600000ull

// The shift fades to zero over this long when the model unlocks or Frame Warp stops
#define FW_FADE_US 150000ull

#define FW_MAX_GAIN 100000.0f
#define FW_MAX_FOCAL 1000000.0f

typedef struct _FW_CONTROLLER_ENTRY {
    uint64_t timeUs;
    int16_t x;
    int16_t y;
} FW_CONTROLLER_ENTRY;

typedef struct _FW_TAG_SLOT {
    bool valid;
    FRAME_WARP_TAG tag;
} FW_TAG_SLOT;

static PLT_MUTEX fwLock;
static bool fwLockCreated;

// Read on the input thread without the lock, so a stream that doesn't use Frame Warp pays one load
static atomic_bool fwCounting;

// Everything below is protected by fwLock
static bool fwEnabled;
static uint8_t fwController;
static bool fwHaveModel;
static FRAME_WARP_MODEL fwModel;
static bool fwLoggedUnrequested;

static FRAME_WARP_MASK fwMask;

static FW_TAG_SLOT fwTags[FW_TAG_RING_SIZE];
static uint64_t fwNewestTagRecvUs;

// What this client sent since the request that started Frame Warp, plus the offsets idle rebasing adds
static uint32_t fwSumX;
static uint32_t fwSumY;
static uint32_t fwOffsetX;
static uint32_t fwOffsetY;
static uint32_t fwControllerCount;
static uint32_t fwControllerOffset;
static FW_CONTROLLER_ENTRY* fwControllerRing;
static uint64_t fwLastInputUs;

// Fade out
static float fwShownX;
static float fwShownY;
static bool fwFading;
static uint64_t fwFadeStartUs;
static float fwFadeFromX;
static float fwFadeFromY;

// Counters for the overlay (once per frame, not once per present)
static uint32_t fwCountShifted;
static uint32_t fwCountExtrapolated;
static uint32_t fwCountUntagged;
static bool fwHaveCountedFrame;
static uint32_t fwLastCountedFrame;

static uint16_t readLE16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t readLE32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static float readLEFloat(const uint8_t* p) {
    uint32_t bits = readLE32(p);
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static bool isValidGain(float value) {
    return isfinite(value) && fabsf(value) <= FW_MAX_GAIN;
}

static bool isValidRange(float value, float min, float max) {
    return isfinite(value) && value >= min && value <= max;
}

static int hexDigitValue(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

uint32_t FrameWarpParseControlIds(const char* payload) {
    static const char key[] = "a=x-rl-control:";
    uint32_t ids = 0;
    const char* line;

    if (payload == NULL) {
        return 0;
    }

    line = payload;
    while ((line = strstr(line, key)) != NULL) {
        bool atLineStart = line == payload || line[-1] == '\n' || line[-1] == '\r';

        line += sizeof(key) - 1;
        if (!atLineStart) {
            continue;
        }

        // Tokens run to the end of the line. Anything that isn't a 0x-prefixed id is skipped.
        while (*line != '\0' && *line != '\r' && *line != '\n') {
            if (line[0] == '0' && (line[1] == 'x' || line[1] == 'X') && hexDigitValue(line[2]) >= 0) {
                uint32_t value = 0;
                bool overflow = false;

                line += 2;
                while (hexDigitValue(*line) >= 0) {
                    if (value > 0xFFFFFFF) {
                        overflow = true;
                    }
                    value = (value << 4) | (uint32_t)hexDigitValue(*line);
                    line++;
                }

                if (!overflow && value >= FRAME_WARP_ID_REQUEST && value <= FRAME_WARP_ID_MASK) {
                    ids |= 1u << (value - FRAME_WARP_ID_REQUEST);
                }
            }
            else {
                line++;
            }
        }
    }

    return ids;
}

void FrameWarpEncodeRequest(uint8_t* out, bool enabled, uint8_t controller, uint8_t flags, uint16_t maskMaxWidth) {
    out[0] = 1; // version
    out[1] = enabled ? 1 : 0;
    out[2] = controller;
    out[3] = flags;
    out[4] = (uint8_t)(maskMaxWidth & 0xFF);
    out[5] = (uint8_t)(maskMaxWidth >> 8);
    out[6] = 0;
    out[7] = 0;
}

bool FrameWarpDecodeModel(const uint8_t* data, int length, FRAME_WARP_MODEL* model) {
    FRAME_WARP_MODEL m;

    if (length < FRAME_WARP_MODEL_SIZE_V1 || data[0] != 1) {
        return false;
    }

    m.flags = data[1] & (FRAME_WARP_MODEL_MOUSE_LOCKED | FRAME_WARP_MODEL_STICK_LOCKED);
    m.generation = readLE16(&data[2]);
    m.width = readLE16(&data[4]);
    m.height = readLE16(&data[6]);
    if (m.width == 0 || m.height == 0) {
        return false;
    }

    m.mouseGain[0] = readLEFloat(&data[8]);
    m.mouseGain[1] = readLEFloat(&data[12]);
    m.stickGain[0] = readLEFloat(&data[16]);
    m.stickGain[1] = readLEFloat(&data[20]);
    if (!isValidGain(m.mouseGain[0]) || !isValidGain(m.mouseGain[1]) ||
            !isValidGain(m.stickGain[0]) || !isValidGain(m.stickGain[1])) {
        return false;
    }

    m.deadZone = readLEFloat(&data[24]);
    if (!isValidRange(m.deadZone, 0.0f, 0.5f)) {
        return false;
    }

    m.exponent = readLEFloat(&data[28]);
    if (m.exponent != 1.0f && m.exponent != 1.5f && m.exponent != 2.0f &&
            m.exponent != 2.5f && m.exponent != 3.0f) {
        return false;
    }

    m.maxShift[0] = readLEFloat(&data[32]);
    m.maxShift[1] = readLEFloat(&data[36]);
    if (!isValidRange(m.maxShift[0], 0.0f, 65535.0f) || !isValidRange(m.maxShift[1], 0.0f, 65535.0f)) {
        return false;
    }

    m.lagUs = readLE32(&data[40]);
    m.fit = readLEFloat(&data[44]);
    if (!isValidRange(m.fit, 0.0f, 1.0f)) {
        return false;
    }

    // Older hosts send 48 bytes, which means no lens
    m.focal = 0.0f;
    if (length >= FRAME_WARP_MODEL_SIZE) {
        m.focal = readLEFloat(&data[48]);
        if (!isfinite(m.focal) || (m.focal != 0.0f && (m.focal < 1.0f || m.focal > FW_MAX_FOCAL))) {
            return false;
        }
    }

    *model = m;
    return true;
}

bool FrameWarpDecodeTags(const uint8_t* data, int length, FRAME_WARP_TAG_MESSAGE* message) {
    int count;

    if (length < FRAME_WARP_TAGS_HEADER_SIZE || data[0] != 1) {
        return false;
    }

    count = data[1];
    if (count < 1 || count > FRAME_WARP_MAX_TAGS ||
            length < FRAME_WARP_TAGS_HEADER_SIZE + FRAME_WARP_TAG_SIZE * count) {
        return false;
    }

    message->generation = readLE16(&data[2]);
    message->count = count;
    for (int i = 0; i < count; i++) {
        const uint8_t* p = &data[FRAME_WARP_TAGS_HEADER_SIZE + FRAME_WARP_TAG_SIZE * i];

        message->tags[i].frame = readLE32(&p[0]);
        message->tags[i].mouseX = (int32_t)readLE32(&p[4]);
        message->tags[i].mouseY = (int32_t)readLE32(&p[8]);
        message->tags[i].controllerPackets = readLE32(&p[12]);
        message->tags[i].heldUs = readLE32(&p[16]);
    }

    return true;
}

// Reads one LEB128 run length. Returns false when it runs past the data or is longer than 3 bytes.
static bool readRunLength(const uint8_t* data, int length, int* pos, uint32_t* value) {
    uint32_t result = 0;

    for (int shift = 0; shift < 21; shift += 7) {
        uint8_t b;

        if (*pos >= length) {
            return false;
        }

        b = data[(*pos)++];
        result |= (uint32_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            *value = result;
            return true;
        }
    }

    return false;
}

bool FrameWarpDecodeMask(const uint8_t* data, int length, uint16_t maskMaxWidth, FRAME_WARP_MASK* mask) {
    uint8_t kind;
    uint16_t generation, width, height;
    uint8_t* bits;
    uint32_t byteCount;
    int pos;

    if (length < FRAME_WARP_MASK_HEADER_SIZE || data[0] != 1) {
        return false;
    }

    kind = data[1];
    generation = readLE16(&data[2]);
    width = readLE16(&data[4]);
    height = readLE16(&data[6]);

    if (kind == 0) {
        if (width != 0 || height != 0) {
            return false;
        }

        mask->generation = generation;
        mask->width = 0;
        mask->height = 0;
        mask->bits = NULL;
        return true;
    }

    if (kind != 1 || width == 0 || height == 0 || width > maskMaxWidth ||
            width > FRAME_WARP_MASK_MAX_DIM || height > FRAME_WARP_MASK_MAX_DIM) {
        return false;
    }

    byteCount = ((uint32_t)width * height + 7) / 8;
    bits = calloc(byteCount, 1);
    if (bits == NULL) {
        return false;
    }

    pos = FRAME_WARP_MASK_HEADER_SIZE;
    for (uint32_t y = 0; y < height; y++) {
        uint32_t x = 0;
        bool set = false;
        bool first = true;

        // Runs alternate clear, set, clear... and start with clear. A row that starts set begins
        // with a zero, and no other run is zero.
        while (x < width) {
            uint32_t run;

            if (!readRunLength(data, length, &pos, &run) || (run == 0 && !first) || run > width - x) {
                free(bits);
                return false;
            }

            if (set) {
                for (uint32_t i = x; i < x + run; i++) {
                    uint32_t index = y * width + i;
                    bits[index >> 3] |= (uint8_t)(1u << (index & 7));
                }
            }

            x += run;
            set = !set;
            first = false;
        }
    }

    mask->generation = generation;
    mask->width = width;
    mask->height = height;
    mask->bits = bits;
    return true;
}

void FrameWarpStickCurve(int16_t x, int16_t y, float deadZone, float exponent, float* out) {
    float vx = (float)x / 32767.0f;
    float vy = (float)y / 32767.0f;
    float r;
    float s;

    vx = fmaxf(-1.0f, fminf(1.0f, vx));
    vy = fmaxf(-1.0f, fminf(1.0f, vy));
    r = sqrtf(vx * vx + vy * vy);

    if (r <= deadZone || r <= 0.0f) {
        out[0] = out[1] = 0.0f;
        return;
    }

    s = fminf((r - deadZone) / (1.0f - deadZone), 1.0f);
    s = powf(s, exponent);
    out[0] = vx / r * s;
    out[1] = vy / r * s;
}

static void clearTags(void) {
    memset(fwTags, 0, sizeof(fwTags));
    fwNewestTagRecvUs = 0;
}

static void clearMask(void) {
    free(fwMask.bits);
    memset(&fwMask, 0, sizeof(fwMask));
}

static void resetCounts(void) {
    fwSumX = fwSumY = 0;
    fwOffsetX = fwOffsetY = 0;
    fwControllerCount = 0;
    fwControllerOffset = 0;
    fwLastInputUs = 0;
    clearTags();
}

static void resetAll(void) {
    atomic_store_explicit(&fwCounting, false, memory_order_release);
    fwEnabled = false;
    fwController = FRAME_WARP_NO_CONTROLLER;
    fwHaveModel = false;
    memset(&fwModel, 0, sizeof(fwModel));
    fwLoggedUnrequested = false;
    clearMask();
    resetCounts();
    fwShownX = fwShownY = 0.0f;
    fwFading = false;
    fwCountShifted = fwCountExtrapolated = fwCountUntagged = 0;
    fwHaveCountedFrame = false;
}

void FrameWarpInitialize(void) {
    // The lock is created once and never deleted: the render thread may still ask for a shift
    // while the connection is torn down, and a destroyed lock would make that undefined.
    if (!fwLockCreated) {
        PltCreateMutex(&fwLock);
        fwLockCreated = true;
    }

    PltLockMutex(&fwLock);
    free(fwControllerRing);
    fwControllerRing = NULL;
    resetAll();
    if (FrameWarpNegotiated) {
        fwControllerRing = calloc(FW_CONTROLLER_RING_SIZE, sizeof(*fwControllerRing));
        fwController = (uint8_t)StreamConfig.frameWarpController;
    }
    PltUnlockMutex(&fwLock);
}

void FrameWarpDestroy(void) {
    if (!fwLockCreated) {
        return;
    }

    PltLockMutex(&fwLock);
    atomic_store_explicit(&fwCounting, false, memory_order_release);
    fwEnabled = false;
    fwHaveModel = false;
    free(fwControllerRing);
    fwControllerRing = NULL;
    clearMask();
    PltUnlockMutex(&fwLock);
}

bool FrameWarpPrepareRequest(bool enabled, uint8_t controller) {
    bool starts;

    if (!FrameWarpNegotiated || !fwLockCreated) {
        return false;
    }

    PltLockMutex(&fwLock);
    if (fwControllerRing == NULL) {
        PltUnlockMutex(&fwLock);
        return false;
    }

    starts = enabled && !fwEnabled;
    if (starts) {
        // The host counts from this request on, and so do we
        resetCounts();
        fwHaveModel = false;
        clearMask();
        fwLoggedUnrequested = false;
    }

    fwController = controller;
    fwEnabled = enabled;
    atomic_store_explicit(&fwCounting, enabled, memory_order_release);
    PltUnlockMutex(&fwLock);

    return true;
}

void FrameWarpRequestFailed(void) {
    if (!fwLockCreated) {
        return;
    }

    PltLockMutex(&fwLock);
    fwEnabled = false;
    atomic_store_explicit(&fwCounting, false, memory_order_release);
    PltUnlockMutex(&fwLock);
}

bool FrameWarpIsEnabled(void) {
    bool enabled;

    if (!fwLockCreated) {
        return false;
    }

    PltLockMutex(&fwLock);
    enabled = fwEnabled;
    PltUnlockMutex(&fwLock);
    return enabled;
}

uint8_t FrameWarpGetController(void) {
    uint8_t controller;

    if (!fwLockCreated) {
        return FRAME_WARP_NO_CONTROLLER;
    }

    PltLockMutex(&fwLock);
    controller = fwController;
    PltUnlockMutex(&fwLock);
    return controller;
}

// Messages from a host that wasn't asked are ignored. Must be called with fwLock held.
static bool ignoreUnrequested(void) {
    if (fwEnabled) {
        return false;
    }

    if (!fwLoggedUnrequested) {
        fwLoggedUnrequested = true;
        Limelog("Frame Warp: ignoring a message the host sent without a request\n");
    }
    return true;
}

bool FrameWarpHandleModel(const uint8_t* data, int length) {
    FRAME_WARP_MODEL model;

    if (!FrameWarpDecodeModel(data, length, &model)) {
        return false;
    }

    // A model with a focal length is only meant for a client that asked for the lens
    if (!(StreamConfig.frameWarpFlags & LI_FRAME_WARP_FLAG_LENS)) {
        model.focal = 0.0f;
    }

    PltLockMutex(&fwLock);
    if (ignoreUnrequested()) {
        PltUnlockMutex(&fwLock);
        return false;
    }

    fwModel = model;
    fwHaveModel = true;
    PltUnlockMutex(&fwLock);
    return true;
}

bool FrameWarpHandleMask(const uint8_t* data, int length) {
    FRAME_WARP_MASK mask;
    int maxWidth = StreamConfig.frameWarpMaskMaxWidth;

    // A mask is only taken up to the width we asked for (0 = none at all)
    if (maxWidth < 0) {
        maxWidth = 0;
    }
    else if (maxWidth > FRAME_WARP_MASK_MAX_DIM) {
        maxWidth = FRAME_WARP_MASK_MAX_DIM;
    }

    if (!FrameWarpDecodeMask(data, length, (uint16_t)maxWidth, &mask)) {
        return false;
    }

    PltLockMutex(&fwLock);
    if (ignoreUnrequested()) {
        PltUnlockMutex(&fwLock);
        free(mask.bits);
        return false;
    }

    clearMask();
    fwMask = mask;
    PltUnlockMutex(&fwLock);
    return true;
}

bool FrameWarpHandleTags(const uint8_t* data, int length) {
    FRAME_WARP_TAG_MESSAGE message;
    uint64_t nowUs;

    if (!FrameWarpDecodeTags(data, length, &message)) {
        return false;
    }

    nowUs = PltGetMicroseconds();

    PltLockMutex(&fwLock);
    if (ignoreUnrequested()) {
        PltUnlockMutex(&fwLock);
        return false;
    }

    // Oldest first, so the newest tag of the message wins a slot
    for (int i = 0; i < message.count; i++) {
        FW_TAG_SLOT* slot = &fwTags[message.tags[i].frame % FW_TAG_RING_SIZE];

        slot->valid = true;
        slot->tag = message.tags[i];
    }
    fwNewestTagRecvUs = nowUs;

    // Idle rebase: with no input sent for a while nothing is in flight, so the newest tag holds
    // the host's totals. Take them, so a count that got lost doesn't persist.
    if (fwLastInputUs != 0 && nowUs - fwLastInputUs >= FW_IDLE_REBASE_US) {
        const FRAME_WARP_TAG* newest = &message.tags[message.count - 1];

        fwOffsetX = (uint32_t)newest->mouseX - fwSumX;
        fwOffsetY = (uint32_t)newest->mouseY - fwSumY;
        fwControllerOffset = newest->controllerPackets - fwControllerCount;
    }

    PltUnlockMutex(&fwLock);
    return true;
}

void FrameWarpCountInputPacket(const void* packet) {
    const NV_INPUT_HEADER* header = (const NV_INPUT_HEADER*)packet;

    if (!atomic_load_explicit(&fwCounting, memory_order_acquire)) {
        return;
    }

    // Frame Warp only runs on the encrypted control stream, so the packets are Gen 5+ ones
    if (header->magic == LE32(MOUSE_MOVE_REL_MAGIC_GEN5)) {
        const NV_REL_MOUSE_MOVE_PACKET* mouse = (const NV_REL_MOUSE_MOVE_PACKET*)packet;
        int16_t deltaX = (int16_t)BE16((uint16_t)mouse->deltaX);
        int16_t deltaY = (int16_t)BE16((uint16_t)mouse->deltaY);

        PltLockMutex(&fwLock);
        if (fwEnabled) {
            fwSumX += (uint32_t)(int32_t)deltaX;
            fwSumY += (uint32_t)(int32_t)deltaY;
            fwLastInputUs = PltGetMicroseconds();
        }
        PltUnlockMutex(&fwLock);
    }
    else if (header->magic == LE32(MULTI_CONTROLLER_MAGIC_GEN5)) {
        const NV_MULTI_CONTROLLER_PACKET* controller = (const NV_MULTI_CONTROLLER_PACKET*)packet;
        uint16_t number = LE16((uint16_t)controller->controllerNumber);

        PltLockMutex(&fwLock);
        if (fwEnabled && fwController != FRAME_WARP_NO_CONTROLLER && number == fwController &&
                fwControllerRing != NULL) {
            FW_CONTROLLER_ENTRY* entry = &fwControllerRing[fwControllerCount % FW_CONTROLLER_RING_SIZE];

            entry->timeUs = PltGetMicroseconds();
            entry->x = (int16_t)LE16((uint16_t)controller->rightStickX);
            entry->y = (int16_t)LE16((uint16_t)controller->rightStickY);
            fwControllerCount++;
            fwLastInputUs = entry->timeUs;
        }
        PltUnlockMutex(&fwLock);
    }
}

static bool isLocked(void) {
    return fwEnabled && fwHaveModel && (fwModel.flags & (FRAME_WARP_MODEL_MOUSE_LOCKED | FRAME_WARP_MODEL_STICK_LOCKED));
}

// Finds the tag of a frame, or extrapolates one from the two tags before it
static int lookupTag(uint32_t frame, FRAME_WARP_TAG* out) {
    const FRAME_WARP_TAG* newer = NULL;
    const FRAME_WARP_TAG* older = NULL;
    const FW_TAG_SLOT* slot = &fwTags[frame % FW_TAG_RING_SIZE];

    if (slot->valid && slot->tag.frame == frame) {
        *out = slot->tag;
        return LI_FRAME_WARP_TAG_FOUND;
    }

    for (uint32_t distance = 1; distance <= FW_EXTRAPOLATE_SEARCH_FRAMES; distance++) {
        uint32_t earlier = frame - distance;

        slot = &fwTags[earlier % FW_TAG_RING_SIZE];
        if (!slot->valid || slot->tag.frame != earlier) {
            continue;
        }

        if (newer == NULL) {
            if (distance > FW_EXTRAPOLATE_MAX_FRAMES) {
                break;
            }
            newer = &slot->tag;
        }
        else {
            older = &slot->tag;
            break;
        }
    }

    if (newer != NULL && older != NULL) {
        float steps = (float)(frame - newer->frame) / (float)(newer->frame - older->frame);

        *out = *newer;
        out->mouseX = newer->mouseX + (int32_t)lroundf((float)(int32_t)((uint32_t)newer->mouseX - (uint32_t)older->mouseX) * steps);
        out->mouseY = newer->mouseY + (int32_t)lroundf((float)(int32_t)((uint32_t)newer->mouseY - (uint32_t)older->mouseY) * steps);
        out->controllerPackets = newer->controllerPackets +
                (uint32_t)(int32_t)lroundf((float)(int32_t)(newer->controllerPackets - older->controllerPackets) * steps);
        return LI_FRAME_WARP_TAG_EXTRAPOLATED;
    }

    return LI_FRAME_WARP_TAG_MISSING;
}

// The stick's part of the shift: the integral of the curve of what was sent, from the moment the
// frame's last controller packet had been held by the host until now. Must be called with fwLock held.
static void integrateStick(const FRAME_WARP_TAG* tag, uint64_t nowUs, float* out) {
    uint32_t first = tag->controllerPackets - fwControllerOffset;

    out[0] = out[1] = 0.0f;

    // 0xFFFFFFFF = no packet had arrived, packet 0 = none counted, and an old packet is gone
    if (tag->heldUs == FRAME_WARP_NO_HELD || first == 0 || first > fwControllerCount ||
            fwControllerCount - first >= FW_CONTROLLER_RING_SIZE || fwControllerRing == NULL) {
        return;
    }

    uint64_t tau = fwControllerRing[(first - 1) % FW_CONTROLLER_RING_SIZE].timeUs + tag->heldUs;

    for (uint32_t n = first; n <= fwControllerCount; n++) {
        const FW_CONTROLLER_ENTRY* entry = &fwControllerRing[(n - 1) % FW_CONTROLLER_RING_SIZE];
        uint64_t start = entry->timeUs > tau ? entry->timeUs : tau;
        uint64_t end = nowUs;
        float curve[2];

        if (n < fwControllerCount) {
            uint64_t next = fwControllerRing[n % FW_CONTROLLER_RING_SIZE].timeUs;
            end = next < nowUs ? next : nowUs;
        }

        if (end <= start) {
            continue;
        }

        FrameWarpStickCurve(entry->x, entry->y, fwModel.deadZone, fwModel.exponent, curve);
        out[0] += curve[0] * (float)(end - start) / 1000000.0f;
        out[1] += curve[1] * (float)(end - start) / 1000000.0f;
    }
}

static float clampShift(float value, float limit) {
    return fmaxf(-limit, fminf(limit, value));
}

bool LiGetFrameWarpShift(uint32_t frameNumber, uint64_t nowUs, PLI_FRAME_WARP_SHIFT shift) {
    bool ret = false;

    memset(shift, 0, sizeof(*shift));
    shift->tagStatus = LI_FRAME_WARP_TAG_MISSING;

    if (!FrameWarpNegotiated || !fwLockCreated) {
        return false;
    }

    PltLockMutex(&fwLock);

    if (fwHaveModel) {
        shift->generation = fwModel.generation;
        shift->pictureWidth = fwModel.width;
        shift->pictureHeight = fwModel.height;
        shift->focal = fwModel.focal;
    }

    if (isLocked()) {
        FRAME_WARP_TAG tag;
        bool newFrame = !fwHaveCountedFrame || fwLastCountedFrame != frameNumber;

        fwFading = false;
        shift->fade = 1.0f;
        shift->tagStatus = lookupTag(frameNumber, &tag);

        if (shift->tagStatus != LI_FRAME_WARP_TAG_MISSING) {
            float x = 0.0f;
            float y = 0.0f;

            if (fwModel.flags & FRAME_WARP_MODEL_MOUSE_LOCKED) {
                // The difference is taken as signed 32 bit, so wrapping sums are fine
                int32_t sentX = (int32_t)(fwSumX + fwOffsetX - (uint32_t)tag.mouseX);
                int32_t sentY = (int32_t)(fwSumY + fwOffsetY - (uint32_t)tag.mouseY);

                x += fwModel.mouseGain[0] * (float)sentX;
                y += fwModel.mouseGain[1] * (float)sentY;
            }

            if (fwModel.flags & FRAME_WARP_MODEL_STICK_LOCKED) {
                float stick[2];

                integrateStick(&tag, nowUs, stick);
                x += fwModel.stickGain[0] * stick[0];
                y += fwModel.stickGain[1] * stick[1];
            }

            shift->x = clampShift(x, fwModel.maxShift[0]);
            shift->y = clampShift(y, fwModel.maxShift[1]);
        }

        fwShownX = shift->x;
        fwShownY = shift->y;

        if (newFrame) {
            fwHaveCountedFrame = true;
            fwLastCountedFrame = frameNumber;
            if (shift->tagStatus == LI_FRAME_WARP_TAG_FOUND) {
                fwCountShifted++;
            }
            else if (shift->tagStatus == LI_FRAME_WARP_TAG_EXTRAPOLATED) {
                fwCountExtrapolated++;
            }
            else {
                fwCountUntagged++;
            }
        }

        ret = true;
    }
    else {
        // The model unlocked or Frame Warp stopped: fade what was shown out to nothing
        if (!fwFading && (fwShownX != 0.0f || fwShownY != 0.0f)) {
            fwFading = true;
            fwFadeStartUs = nowUs;
            fwFadeFromX = fwShownX;
            fwFadeFromY = fwShownY;
        }

        if (fwFading) {
            uint64_t elapsed = nowUs > fwFadeStartUs ? nowUs - fwFadeStartUs : 0;

            if (elapsed >= FW_FADE_US) {
                fwFading = false;
                fwShownX = fwShownY = 0.0f;
            }
            else {
                float fade = 1.0f - (float)elapsed / (float)FW_FADE_US;

                shift->x = fwFadeFromX * fade;
                shift->y = fwFadeFromY * fade;
                shift->fade = fade;
                shift->tagStatus = LI_FRAME_WARP_TAG_FOUND;
                ret = true;
            }
        }
    }

    PltUnlockMutex(&fwLock);
    return ret;
}

bool LiIsFrameWarpNegotiated(void) {
    return FrameWarpNegotiated;
}

bool LiGetFrameWarpState(PLI_FRAME_WARP_STATE state) {
    memset(state, 0, sizeof(*state));

    if (!FrameWarpNegotiated || !fwLockCreated) {
        return false;
    }

    PltLockMutex(&fwLock);
    if (fwHaveModel) {
        state->active = isLocked();
        state->mouseLocked = (fwModel.flags & FRAME_WARP_MODEL_MOUSE_LOCKED) != 0;
        state->stickLocked = (fwModel.flags & FRAME_WARP_MODEL_STICK_LOCKED) != 0;
        state->generation = fwModel.generation;
        state->pictureWidth = fwModel.width;
        state->pictureHeight = fwModel.height;
        state->focal = fwModel.focal;
        state->lagUs = fwModel.lagUs;
        state->fit = fwModel.fit;
    }
    PltUnlockMutex(&fwLock);
    return true;
}

uint32_t LiGetFrameWarpMask(uint16_t* generation, uint16_t* width, uint16_t* height,
                            uint8_t* bits, uint32_t capacityBytes) {
    uint32_t byteCount = 0;

    *generation = 0;
    *width = 0;
    *height = 0;

    if (!FrameWarpNegotiated || !fwLockCreated) {
        return 0;
    }

    PltLockMutex(&fwLock);
    *generation = fwMask.generation;
    *width = fwMask.width;
    *height = fwMask.height;
    if (fwMask.bits != NULL) {
        byteCount = ((uint32_t)fwMask.width * fwMask.height + 7) / 8;
        if (bits != NULL && capacityBytes >= byteCount) {
            memcpy(bits, fwMask.bits, byteCount);
        }
    }
    PltUnlockMutex(&fwLock);

    return byteCount;
}

void LiGetFrameWarpCounters(uint32_t* shifted, uint32_t* extrapolated, uint32_t* untagged) {
    *shifted = *extrapolated = *untagged = 0;

    if (!FrameWarpNegotiated || !fwLockCreated) {
        return;
    }

    PltLockMutex(&fwLock);
    *shifted = fwCountShifted;
    *extrapolated = fwCountExtrapolated;
    *untagged = fwCountUntagged;
    PltUnlockMutex(&fwLock);
}
