#pragma once

#include <stdbool.h>
#include <stdint.h>

// Frame Warp (control messages 0x5543..0x5546): the host tags each video frame with the input
// sums that frame reflects, the client adds up what it sent and shifts every picture it draws by
// the difference. Everything here is inert unless FrameWarpNegotiated is set, that is, unless the
// host listed all four ids in an a=x-rl-control line of its RTSP DESCRIBE response and the client
// asked for the feature. The wire format is the one of docs/protocol/frame-warp.md (Nightjar).
//
// All integers are little endian and floats are IEEE-754 binary32. Unknown trailing bytes are
// ignored in every message, and a message that breaks a rule is dropped.

#define FRAME_WARP_ID_REQUEST 0x5543
#define FRAME_WARP_ID_MODEL   0x5544
#define FRAME_WARP_ID_TAGS    0x5545
#define FRAME_WARP_ID_MASK    0x5546

// Bit i is set when the host listed id 0x5543 + i
#define FRAME_WARP_IDS_ALL    0x0F

#define FRAME_WARP_REQUEST_SIZE      8
#define FRAME_WARP_MODEL_SIZE_V1     48 // Older hosts: no focal length
#define FRAME_WARP_MODEL_SIZE        52
#define FRAME_WARP_TAGS_HEADER_SIZE  4
#define FRAME_WARP_TAG_SIZE          20
#define FRAME_WARP_MAX_TAGS          4
#define FRAME_WARP_MASK_HEADER_SIZE  8
#define FRAME_WARP_MASK_MAX_DIM      2048
#define FRAME_WARP_NO_CONTROLLER     0xFF
#define FRAME_WARP_NO_HELD           0xFFFFFFFFu

#define FRAME_WARP_MODEL_MOUSE_LOCKED 0x01
#define FRAME_WARP_MODEL_STICK_LOCKED 0x02

typedef struct _FRAME_WARP_MODEL {
    uint8_t flags;
    uint16_t generation;
    uint16_t width;
    uint16_t height;
    float mouseGain[2];
    float stickGain[2];
    float deadZone;
    float exponent;
    float maxShift[2];
    uint32_t lagUs;
    float fit;
    float focal; // 0 = the picture moves alike everywhere
} FRAME_WARP_MODEL;

typedef struct _FRAME_WARP_TAG {
    uint32_t frame;
    int32_t mouseX;
    int32_t mouseY;
    uint32_t controllerPackets;
    uint32_t heldUs;
} FRAME_WARP_TAG;

typedef struct _FRAME_WARP_TAG_MESSAGE {
    uint16_t generation;
    int count;
    FRAME_WARP_TAG tags[FRAME_WARP_MAX_TAGS]; // Oldest first
} FRAME_WARP_TAG_MESSAGE;

typedef struct _FRAME_WARP_MASK {
    uint16_t generation;
    uint16_t width;
    uint16_t height;
    uint8_t* bits; // NULL for "no mask", else (width * height + 7) / 8 bytes, caller frees
} FRAME_WARP_MASK;

// Reads every a=x-rl-control: line of an SDP payload and returns the FRAME_WARP_IDS_ALL bits of
// the Frame Warp ids they list. Ids are hex with a 0x prefix, separated by commas or spaces.
uint32_t FrameWarpParseControlIds(const char* payload);

// Builds the 8 byte request
void FrameWarpEncodeRequest(uint8_t* out, bool enabled, uint8_t controller, uint8_t flags, uint16_t maskMaxWidth);

// Message decoders. They only validate and decode; false means the message must be dropped.
bool FrameWarpDecodeModel(const uint8_t* data, int length, FRAME_WARP_MODEL* model);
bool FrameWarpDecodeTags(const uint8_t* data, int length, FRAME_WARP_TAG_MESSAGE* message);
bool FrameWarpDecodeMask(const uint8_t* data, int length, uint16_t maskMaxWidth, FRAME_WARP_MASK* mask);

// The stick curve both sides share. x and y are the raw stick shorts, the result is in out[2].
void FrameWarpStickCurve(int16_t x, int16_t y, float deadZone, float exponent, float* out);

// Lifecycle, called by the control stream (initialize before the streams run, destroy at cleanup)
void FrameWarpInitialize(void);
void FrameWarpDestroy(void);

// Records a request that is about to be sent. Returns false when nothing may be sent (not
// negotiated). An enable that starts Frame Warp resets the counts on this side; a repeated enable
// keeps them. A failed send of an enable must be undone with FrameWarpRequestFailed().
bool FrameWarpPrepareRequest(bool enabled, uint8_t controller);
void FrameWarpRequestFailed(void);
bool FrameWarpIsEnabled(void);
uint8_t FrameWarpGetController(void);

// Inbound messages, called on the control receive thread. Returns false when ignored.
bool FrameWarpHandleModel(const uint8_t* data, int length);
bool FrameWarpHandleTags(const uint8_t* data, int length);
bool FrameWarpHandleMask(const uint8_t* data, int length);

// Counts a packet that is going on the wire (after mouse batching and splitting). packet is the
// NV_INPUT_HEADER based input packet. Cheap when Frame Warp is not running.
void FrameWarpCountInputPacket(const void* packet);
