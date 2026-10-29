#include "ClientRoaming.h"

// Client roaming, wire version 1. The client proves its new address to the host with a
// four message exchange on the control port, outside ENet:
//
//   PROBE (client->host)  from the new address
//   CHALLENGE (host->client)  a random number only the holder of the session key can read
//   CONFIRM (client->host)  from the same address, echoing the challenge
//   MIGRATED (host->client)  the host moved the session; every media stream pings at once
//
// Every datagram is 52 bytes: a 20 byte clear header (magic, version, type, session tag, seq),
// a 16 byte AES-128-GCM tag and 16 bytes of sealed payload. The keys come from the launch's
// rikey. All integers are little-endian.

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#define ROAM_VERSION 1

#define ROAM_TYPE_PROBE     1
#define ROAM_TYPE_CHALLENGE 2
#define ROAM_TYPE_CONFIRM   3
#define ROAM_TYPE_MIGRATED  4

#define ROAM_DIR_CLIENT 1
#define ROAM_DIR_HOST   2

#define ROAM_HEADER_SIZE 20 // the AAD
#define ROAM_PROBE_FLAG_MEDIA_REBOUND 0x1

#define ROAM_PROBE_FAST_COUNT       12
#define ROAM_PROBE_FAST_INTERVAL_MS 250
#define ROAM_PROBE_SLOW_INTERVAL_MS 1000
#define ROAM_CONFIRM_INTERVAL_MS    250
#define ROAM_CONFIRM_TIMEOUT_MS     3000
#define ROAM_GIVE_UP_MAX_MS         10000
#define ROAM_SILENCE_MS             1000
#define ROAM_SILENCE_RETRY_MS       10000
#define ROAM_CHECK_INTERVAL_MS      250
#define ROAM_CHANGE_RETRY_MS        250
#define ROAM_TICK_MS                25

#define ROAM_MAX_CONFIRMED  8
#define ROAM_RX_QUEUE_SIZE  8

static const unsigned char roamMagic[4] = { 0x0F, 0xFE, 0x52, 0x4D };

// Keys and sequence numbers
static bool roamInitialized;
static volatile bool roamAccepting;
static unsigned char roamKey[16];
static unsigned char roamTag[8];
static uint32_t clientSeq;
static uint32_t lastHostSeq;

// The sequence numbers are kept per session tag across connections in this process, so a
// reconnect under the same rikey continues where the last one stopped. A new key starts at 1.
static bool persistedValid;
static unsigned char persistedTag[8];
static uint32_t persistedClientSeq;
static uint32_t persistedHostSeq;

// Datagrams from the host, queued by the ENet intercept for the roaming thread
static PLT_MUTEX rxLock;
static bool rxLockCreated;
static unsigned char rxQueue[ROAM_RX_QUEUE_SIZE][ROAM_DATAGRAM_SIZE];
static int rxHead;
static int rxCount;
static bool netChangePending;
static bool netChangeMetered;

// Public status
static volatile int roamStatus;
static volatile uint32_t roamCount;

// Roaming thread state: only touched by that thread
static PLT_THREAD roamThread;
static bool roamThreadStarted;
static bool held;
static bool changeWanted;
static uint64_t changeDeadlineMs;
static uint64_t nextChangeTryMs;
static uint64_t nextCheckMs;
static bool haveFailed;
static uint64_t lastFailMs;
static uint32_t rejectedCount;

static struct {
    bool active;
    bool fromNetworkChange;
    bool mediaRebound;
    uint64_t startMs;
    uint64_t giveUpMs;
    uint64_t nonce;
    int probesSent;
    uint64_t nextProbeMs;
    bool confirming;
    uint64_t confirmStartMs;
    uint64_t nextConfirmMs;
    uint64_t confirmed[ROAM_MAX_CONFIRMED];
    int confirmedCount;
} attempt;

static void putLe32(unsigned char* p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

static void putLe64(unsigned char* p, uint64_t v) {
    putLe32(p, (uint32_t)(v & 0xFFFFFFFFu));
    putLe32(p + 4, (uint32_t)(v >> 32));
}

static uint32_t getLe32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t getLe64(const unsigned char* p) {
    return (uint64_t)getLe32(p) | ((uint64_t)getLe32(p + 4) << 32);
}

// Roaming key (16 bytes) and session tag (8 bytes), each one AES-128 block encryption
// of a fixed label under the rikey.
static bool deriveKeys(const unsigned char rikey[16], unsigned char key[16], unsigned char tag[8]) {
    static const unsigned char keyLabel[16] = { 'R', 'L', 'R', 'O', 'A', 'M', '-', 'K', 'E', 'Y', '-', 'v', '1', 0, 0, 0 };
    static const unsigned char tagLabel[16] = { 'R', 'L', 'R', 'O', 'A', 'M', '-', 'T', 'A', 'G', '-', 'v', '1', 0, 0, 0 };
    unsigned char tagBlock[16];

    if (!PltAes128EncryptBlock(rikey, keyLabel, key)) {
        return false;
    }
    if (!PltAes128EncryptBlock(rikey, tagLabel, tagBlock)) {
        return false;
    }

    memcpy(tag, tagBlock, 8);
    return true;
}

// The nonce is: type, direction, 0, 0, seq (LE), 0, 0, 0, 0
static void buildNonce(unsigned char nonce[12], unsigned char type, unsigned char direction, uint32_t seq) {
    memset(nonce, 0, 12);
    nonce[0] = type;
    nonce[1] = direction;
    putLe32(&nonce[4], seq);
}

// Builds a sealed datagram. The direction is the one of the sender.
static bool roamSeal(const unsigned char key[16], const unsigned char tag[8],
                     unsigned char direction, unsigned char type, uint32_t seq,
                     const unsigned char payload[16], unsigned char out[ROAM_DATAGRAM_SIZE]) {
    unsigned char nonce[12];

    memcpy(out, roamMagic, sizeof(roamMagic));
    out[4] = ROAM_VERSION;
    out[5] = type;
    out[6] = 0;
    out[7] = 0;
    memcpy(&out[8], tag, 8);
    putLe32(&out[16], seq);

    buildNonce(nonce, type, direction, seq);

    // Layout: header (20 bytes, also the AAD), GCM tag (16 bytes), ciphertext (16 bytes)
    return PltAes128GcmSealAad(key, nonce, out, ROAM_HEADER_SIZE, payload, 16, &out[36], &out[20]);
}

// Strict receive rules: anything that is not exactly right is dropped, silently. The replay
// check on seq is up to the caller, which must only record seq after this returned true.
// The direction is the one of the sender.
static bool roamOpen(const unsigned char key[16], const unsigned char tag[8], unsigned char direction,
                     const unsigned char* data, size_t length,
                     unsigned char* type, uint32_t* seq, unsigned char payload[16]) {
    unsigned char nonce[12];
    unsigned char t;
    int i;

    if (length != ROAM_DATAGRAM_SIZE || memcmp(data, roamMagic, sizeof(roamMagic)) != 0) {
        return false;
    }
    if (data[4] != ROAM_VERSION) {
        return false;
    }

    t = data[5];
    if (direction == ROAM_DIR_HOST) {
        if (t != ROAM_TYPE_CHALLENGE && t != ROAM_TYPE_MIGRATED) {
            return false;
        }
    }
    else {
        if (t != ROAM_TYPE_PROBE && t != ROAM_TYPE_CONFIRM) {
            return false;
        }
    }

    if (data[6] != 0 || data[7] != 0) {
        return false;
    }

    *seq = getLe32(&data[16]);
    if (*seq == 0) {
        return false;
    }

    if (memcmp(&data[8], tag, 8) != 0) {
        return false;
    }

    buildNonce(nonce, t, direction, *seq);
    if (!PltAes128GcmOpenAad(key, nonce, data, ROAM_HEADER_SIZE, &data[36], 16, &data[20], payload)) {
        return false;
    }

    // Padding that must be zero
    if (t == ROAM_TYPE_MIGRATED || t == ROAM_TYPE_CONFIRM) {
        for (i = 8; i < 16; i++) {
            if (payload[i] != 0) {
                return false;
            }
        }
    }
    else if (t == ROAM_TYPE_PROBE) {
        for (i = 12; i < 16; i++) {
            if (payload[i] != 0) {
                return false;
            }
        }
    }

    *type = t;
    return true;
}

#ifdef LC_DEBUG
static int hexValue(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    return c - 'a' + 10;
}

static void hexToBytes(const char* hex, unsigned char* out, size_t outLength) {
    size_t i;

    for (i = 0; i < outLength; i++) {
        out[i] = (unsigned char)((hexValue(hex[i * 2]) << 4) | hexValue(hex[i * 2 + 1]));
    }
}

// Known answers shared by every implementation of this protocol
static bool roamSelfCheck(void) {
    static const char* vectors[4] = {
        "0ffe524d0101000052d89ae18eeb023201000000275f7b4c17bd8fa9b0467587697c1a022c64e82c54fdbd5b9645a4373c755ab8",
        "0ffe524d0102000052d89ae18eeb0232010000002954b77944af32c4e11d538346b6a81ec5035975a9ad5739a4f02740e81f59e9",
        "0ffe524d0103000052d89ae18eeb02320200000049a23e8d3d0ab0db81e9b7c106334d238d38b827e46b1abf7a143a1063a29d9c",
        "0ffe524d0104000052d89ae18eeb0232020000007e1ab6560eb57e87dd9d21d46c85fb7430202c7441ef5e9e4cbe141ac2ee8d80"
    };
    static const unsigned char types[4] = { ROAM_TYPE_PROBE, ROAM_TYPE_CHALLENGE, ROAM_TYPE_CONFIRM, ROAM_TYPE_MIGRATED };
    static const uint32_t seqs[4] = { 1, 1, 2, 2 };
    unsigned char rikey[16];
    unsigned char key[16];
    unsigned char tag[8];
    unsigned char expectedKey[16];
    unsigned char expectedTag[8];
    int i;

    for (i = 0; i < 16; i++) {
        rikey[i] = (unsigned char)i;
    }
    hexToBytes("6d553d3fa2e47b32ebb1609b11c82df2", expectedKey, sizeof(expectedKey));
    hexToBytes("52d89ae18eeb0232", expectedTag, sizeof(expectedTag));

    if (!deriveKeys(rikey, key, tag) || memcmp(key, expectedKey, sizeof(key)) != 0 || memcmp(tag, expectedTag, sizeof(tag)) != 0) {
        return false;
    }

    for (i = 0; i < 4; i++) {
        unsigned char payload[16];
        unsigned char sealed[ROAM_DATAGRAM_SIZE];
        unsigned char expected[ROAM_DATAGRAM_SIZE];
        unsigned char openedType;
        uint32_t openedSeq;
        unsigned char opened[16];
        unsigned char direction = (types[i] == ROAM_TYPE_PROBE || types[i] == ROAM_TYPE_CONFIRM) ? ROAM_DIR_CLIENT : ROAM_DIR_HOST;

        memset(payload, 0, sizeof(payload));
        switch (types[i]) {
        case ROAM_TYPE_PROBE:
            putLe64(payload, 0x0123456789abcdefULL);
            putLe32(payload + 8, ROAM_PROBE_FLAG_MEDIA_REBOUND);
            break;
        case ROAM_TYPE_CHALLENGE:
            putLe64(payload, 0x0123456789abcdefULL);
            putLe64(payload + 8, 0xfedcba9876543210ULL);
            break;
        default:
            putLe64(payload, 0xfedcba9876543210ULL);
            break;
        }

        hexToBytes(vectors[i], expected, sizeof(expected));

        if (!roamSeal(key, tag, direction, types[i], seqs[i], payload, sealed) ||
                memcmp(sealed, expected, sizeof(sealed)) != 0) {
            return false;
        }
        if (!roamOpen(key, tag, direction, expected, sizeof(expected), &openedType, &openedSeq, opened) ||
                openedType != types[i] || openedSeq != seqs[i] || memcmp(opened, payload, sizeof(opened)) != 0) {
            return false;
        }
    }

    return true;
}
#endif

bool ClientRoamingIsDatagram(const unsigned char* data, size_t length) {
    return length >= sizeof(roamMagic) && memcmp(data, roamMagic, sizeof(roamMagic)) == 0;
}

void ClientRoamingQueueDatagram(const unsigned char* data, size_t length) {
    if (!roamAccepting || !rxLockCreated || length != ROAM_DATAGRAM_SIZE) {
        return;
    }

    PltLockMutex(&rxLock);
    if (rxCount < ROAM_RX_QUEUE_SIZE) {
        memcpy(rxQueue[(rxHead + rxCount) % ROAM_RX_QUEUE_SIZE], data, ROAM_DATAGRAM_SIZE);
        rxCount++;
    }
    PltUnlockMutex(&rxLock);
}

static bool popDatagram(unsigned char out[ROAM_DATAGRAM_SIZE]) {
    bool ret = false;

    PltLockMutex(&rxLock);
    if (rxCount > 0) {
        memcpy(out, rxQueue[rxHead], ROAM_DATAGRAM_SIZE);
        rxHead = (rxHead + 1) % ROAM_RX_QUEUE_SIZE;
        rxCount--;
        ret = true;
    }
    PltUnlockMutex(&rxLock);

    return ret;
}

void LiNotifyNetworkChanged(bool metered) {
    if (!ClientRoamingNegotiated || !roamAccepting || !rxLockCreated) {
        return;
    }

    PltLockMutex(&rxLock);
    netChangePending = true;
    netChangeMetered = metered;
    PltUnlockMutex(&rxLock);
}

int LiGetClientRoamingStatus(void) {
    return ClientRoamingNegotiated ? roamStatus : LI_ROAMING_IDLE;
}

uint32_t LiGetClientRoamingCount(void) {
    return roamCount;
}

static uint64_t randomU64(void) {
    unsigned char bytes[8];

    PltGenerateRandomData(bytes, sizeof(bytes));
    return getLe64(bytes);
}

// 0 when the sequence space is exhausted: nothing more may be sent under this key
static uint32_t nextClientSeq(void) {
    if (clientSeq == UINT32_MAX) {
        return 0;
    }

    return ++clientSeq;
}

static void sendDatagram(unsigned char type, const unsigned char payload[16]) {
    unsigned char datagram[ROAM_DATAGRAM_SIZE];
    uint32_t seq = nextClientSeq();

    if (seq == 0) {
        return;
    }

    if (!roamSeal(roamKey, roamTag, ROAM_DIR_CLIENT, type, seq, payload, datagram)) {
        Limelog("Roaming: sealing a datagram failed\n");
        return;
    }

    // A send failure is not interesting: the network may be in between two states
    ControlStreamSendRoamDatagram(datagram, sizeof(datagram));
}

static void sendProbe(void) {
    unsigned char payload[16];

    memset(payload, 0, sizeof(payload));
    putLe64(payload, attempt.nonce);
    putLe32(payload + 8, attempt.mediaRebound ? ROAM_PROBE_FLAG_MEDIA_REBOUND : 0);

    sendDatagram(ROAM_TYPE_PROBE, payload);
}

static void sendConfirm(void) {
    unsigned char payload[16];

    if (attempt.confirmedCount == 0) {
        return;
    }

    memset(payload, 0, sizeof(payload));
    putLe64(payload, attempt.confirmed[attempt.confirmedCount - 1]);

    sendDatagram(ROAM_TYPE_CONFIRM, payload);
}

static int giveUpMs(void) {
    int timeoutMs = StreamConfig.controlPeerTimeoutMs > 0 ? StreamConfig.controlPeerTimeoutMs : 10000;

    return MIN(timeoutMs, ROAM_GIVE_UP_MAX_MS);
}

static void startNewProbeBurst(uint64_t now) {
    attempt.nonce = randomU64();
    attempt.probesSent = 0;
    attempt.nextProbeMs = now;
    attempt.confirming = false;
}

static void startAttempt(uint64_t now, bool fromNetworkChange) {
    memset(&attempt, 0, sizeof(attempt));
    attempt.active = true;
    attempt.fromNetworkChange = fromNetworkChange;
    attempt.startMs = now;
    attempt.giveUpMs = now + (uint64_t)giveUpMs();
    startNewProbeBurst(now);

    rejectedCount = 0;
    roamStatus = LI_ROAMING_MOVING;
    Limelog("Roaming: attempt started (%s)\n", fromNetworkChange ? "network change" : "control stream silence");
}

static void endAttempt(void) {
    attempt.active = false;
    roamStatus = held ? LI_ROAMING_HELD : LI_ROAMING_IDLE;
}

static void failAttempt(uint64_t now) {
    Limelog("Roaming: giving up after %u ms (%u datagrams rejected); the stream is left to its normal timeout\n",
            (unsigned int)(now - attempt.startMs), rejectedCount);
    endAttempt();
    haveFailed = true;
    lastFailMs = now;
}

// Same IP (or, for IPv6, the same /64 so a privacy address rotation doesn't count) is no roam
static bool isSameLocalNetworkAddress(const struct sockaddr_storage* a, const struct sockaddr_storage* b) {
    if (a->ss_family != b->ss_family) {
        return false;
    }

    if (a->ss_family == AF_INET) {
        return memcmp(&((const struct sockaddr_in*)a)->sin_addr, &((const struct sockaddr_in*)b)->sin_addr, sizeof(struct in_addr)) == 0;
    }
#ifdef AF_INET6
    else if (a->ss_family == AF_INET6) {
        return memcmp(&((const struct sockaddr_in6*)a)->sin6_addr, &((const struct sockaddr_in6*)b)->sin6_addr, 8) == 0;
    }
#endif

    return false;
}

static bool lookUpLocalAddress(struct sockaddr_storage* newLocal) {
    SOCKADDR_LEN localAddrLen = 0;

    memset(newLocal, 0, sizeof(*newLocal));
    return getLocalAddressByUdpConnect(&RemoteAddr, AddrLen, RtspPortNumber, newLocal, &localAddrLen) == 0;
}

// Binds every new socket first and only then swaps them in, together. If any bind fails the
// new ones are closed and the old ones stay in place.
static bool moveSockets(struct sockaddr_storage* newLocal) {
    SOCKET control = ControlStreamCreateRoamSocket(newLocal);
    SOCKET video;
    SOCKET audio;

    if (control == INVALID_SOCKET) {
        Limelog("Roaming: binding the new control socket failed: %d\n", (int)LastSocketError());
        return false;
    }

    video = VideoStreamCreateSocket(newLocal);
    if (video == INVALID_SOCKET) {
        Limelog("Roaming: binding the new video socket failed: %d\n", (int)LastSocketError());
        closeSocket(control);
        return false;
    }

    audio = AudioStreamCreateSocket(newLocal);
    if (audio == INVALID_SOCKET) {
        Limelog("Roaming: binding the new audio socket failed: %d\n", (int)LastSocketError());
        closeSocket(control);
        closeSocket(video);
        return false;
    }

    if (!ControlStreamSwapSocket(control)) {
        closeSocket(control);
        closeSocket(video);
        closeSocket(audio);
        return false;
    }
    VideoStreamRebind(video);
    AudioStreamRebind(audio);

    memcpy(&LocalAddr, newLocal, sizeof(LocalAddr));

    // The host expects pings from the new ports; the first ones also go out right away
    VideoStreamPingNow();
    AudioStreamPingNow();

    Limelog("Roaming: control, video and audio sockets moved to the new local address\n");
    return true;
}

// A network change was reported: look up the new local address and move to it. Retries for
// up to the give-up time, since the route may not be ready yet when Android reports the change.
static void tryNetworkChange(uint64_t now) {
    struct sockaddr_storage newLocal;

    if (lookUpLocalAddress(&newLocal)) {
        if (isSameLocalNetworkAddress(&newLocal, &LocalAddr)) {
            Limelog("Roaming: the local address toward the host is unchanged, nothing to do\n");
            changeWanted = false;
            return;
        }

        if (moveSockets(&newLocal)) {
            changeWanted = false;
            startAttempt(now, true);
            attempt.mediaRebound = true;
            return;
        }
    }

    if (now >= changeDeadlineMs) {
        Limelog("Roaming: could not move to the new network\n");
        changeWanted = false;
        haveFailed = true;
        lastFailMs = now;
        return;
    }

    nextChangeTryMs = now + ROAM_CHANGE_RETRY_MS;
}

static void processNetworkChange(uint64_t now) {
    bool pending;
    bool metered;

    PltLockMutex(&rxLock);
    pending = netChangePending;
    metered = netChangeMetered;
    netChangePending = false;
    PltUnlockMutex(&rxLock);

    if (pending) {
        if (metered && !(StreamConfig.clientRoaming & LI_ROAMING_ALLOW_METERED)) {
            // No datagram and no wait: the normal timeout decides until an unmetered network shows up
            Limelog("Roaming: the new network is metered and roaming on it is not allowed, holding\n");
            held = true;
            changeWanted = false;
            attempt.active = false;
            roamStatus = LI_ROAMING_HELD;
            return;
        }

        held = false;
        if (roamStatus == LI_ROAMING_HELD) {
            roamStatus = attempt.active ? LI_ROAMING_MOVING : LI_ROAMING_IDLE;
        }

        changeWanted = true;
        changeDeadlineMs = now + (uint64_t)giveUpMs();
        nextChangeTryMs = now;
    }

    if (changeWanted && now >= nextChangeTryMs) {
        tryNetworkChange(now);
    }
}

// The control stream going silent also starts an attempt (a NAT rebinding looks like that).
// The sockets only move if the lookup shows a new local address.
static void checkSilence(uint64_t now) {
    struct sockaddr_storage newLocal;
    int silenceMs;

    if (held || changeWanted) {
        return;
    }

    silenceMs = LiGetControlStreamSilenceMs();

    if (attempt.active) {
        // A silence attempt ends, without being a failure, if the host is heard again before it confirmed
        if (!attempt.fromNetworkChange && !attempt.confirming &&
                silenceMs >= 0 && silenceMs + 200 < (int)(now - attempt.startMs)) {
            Limelog("Roaming: the host is heard again, attempt ended\n");
            endAttempt();
        }
        return;
    }

    if (silenceMs < ROAM_SILENCE_MS) {
        return;
    }

    if (haveFailed && now - lastFailMs < ROAM_SILENCE_RETRY_MS) {
        return;
    }

    if (lookUpLocalAddress(&newLocal) && !isSameLocalNetworkAddress(&newLocal, &LocalAddr)) {
        if (!moveSockets(&newLocal)) {
            haveFailed = true;
            lastFailMs = now;
            return;
        }

        startAttempt(now, false);
        attempt.mediaRebound = true;
    }
    else {
        startAttempt(now, false);
    }
}

static void completeAttempt(uint64_t now) {
    roamCount++;
    Limelog("Roaming: moved after %u ms (move %u, %u datagrams rejected)\n",
            (unsigned int)(now - attempt.startMs), roamCount, rejectedCount);
    endAttempt();

    // Every media stream pings at once so the host learns the new path without waiting
    VideoStreamPingNow();
    AudioStreamPingNow();
}

static void processDatagram(const unsigned char* data, uint64_t now) {
    unsigned char type;
    uint32_t seq;
    unsigned char payload[16];
    uint64_t challenge;
    int i;

    if (!roamOpen(roamKey, roamTag, ROAM_DIR_HOST, data, ROAM_DATAGRAM_SIZE, &type, &seq, payload)) {
        rejectedCount++;
        return;
    }

    // Replays are dropped, and seq is only recorded once the datagram authenticated
    if (seq <= lastHostSeq) {
        rejectedCount++;
        return;
    }
    lastHostSeq = seq;

    if (!attempt.active) {
        return;
    }

    if (type == ROAM_TYPE_CHALLENGE) {
        // Only an answer to the PROBE we have in flight counts
        if (getLe64(payload) != attempt.nonce) {
            rejectedCount++;
            return;
        }

        challenge = getLe64(payload + 8);

        for (i = 0; i < attempt.confirmedCount; i++) {
            if (attempt.confirmed[i] == challenge) {
                break;
            }
        }
        if (i == attempt.confirmedCount) {
            if (attempt.confirmedCount == ROAM_MAX_CONFIRMED) {
                memmove(&attempt.confirmed[0], &attempt.confirmed[1], sizeof(attempt.confirmed[0]) * (ROAM_MAX_CONFIRMED - 1));
                attempt.confirmedCount--;
            }
            attempt.confirmed[attempt.confirmedCount++] = challenge;
        }
        else if (i != attempt.confirmedCount - 1) {
            // Make it the newest
            uint64_t tmp = attempt.confirmed[i];
            memmove(&attempt.confirmed[i], &attempt.confirmed[i + 1], sizeof(attempt.confirmed[0]) * (attempt.confirmedCount - i - 1));
            attempt.confirmed[attempt.confirmedCount - 1] = tmp;
        }

        // Stop probing and confirm until the host reports the move
        if (!attempt.confirming) {
            attempt.confirming = true;
            attempt.confirmStartMs = now;
        }
        sendConfirm();
        attempt.nextConfirmMs = now + ROAM_CONFIRM_INTERVAL_MS;
    }
    else if (type == ROAM_TYPE_MIGRATED) {
        challenge = getLe64(payload);

        for (i = 0; i < attempt.confirmedCount; i++) {
            if (attempt.confirmed[i] == challenge) {
                completeAttempt(now);
                return;
            }
        }

        rejectedCount++;
    }
}

static void advanceAttempt(uint64_t now) {
    if (!attempt.active) {
        return;
    }

    if (now >= attempt.giveUpMs) {
        failAttempt(now);
        return;
    }

    if (attempt.confirming) {
        if (now - attempt.confirmStartMs >= ROAM_CONFIRM_TIMEOUT_MS) {
            Limelog("Roaming: no MIGRATED within %d ms, probing again\n", ROAM_CONFIRM_TIMEOUT_MS);
            startNewProbeBurst(now);
        }
        else if (now >= attempt.nextConfirmMs) {
            sendConfirm();
            attempt.nextConfirmMs = now + ROAM_CONFIRM_INTERVAL_MS;
        }
    }

    if (!attempt.confirming && now >= attempt.nextProbeMs) {
        sendProbe();
        attempt.probesSent++;
        attempt.nextProbeMs = now + (attempt.probesSent < ROAM_PROBE_FAST_COUNT ?
                                     ROAM_PROBE_FAST_INTERVAL_MS : ROAM_PROBE_SLOW_INTERVAL_MS);
    }
}

static void roamTick(uint64_t now) {
    unsigned char datagram[ROAM_DATAGRAM_SIZE];
    int processed = 0;

    ControlStreamReapRetiredSocket(false);

    // A network change restarts a running attempt: the new nonce and give-up time come with
    // the new attempt, and challenges confirmed before no longer count.
    processNetworkChange(now);

    while (processed < ROAM_RX_QUEUE_SIZE && popDatagram(datagram)) {
        processDatagram(datagram, now);
        processed++;
    }

    if (now >= nextCheckMs) {
        nextCheckMs = now + ROAM_CHECK_INTERVAL_MS;
        checkSilence(now);
    }

    advanceAttempt(now);
}

static void roamThreadFunc(void* context) {
    (void)context;

    while (!PltIsThreadInterrupted(&roamThread)) {
        roamTick(PltGetMillis());
        PltSleepMsInterruptible(&roamThread, ROAM_TICK_MS);
    }
}

void ClientRoamingInit(void) {
    if (!rxLockCreated) {
        if (PltCreateMutex(&rxLock) != 0) {
            Limelog("Roaming: creating the lock failed, roaming disabled\n");
            ClientRoamingNegotiated = false;
            return;
        }
        rxLockCreated = true;
    }

    rxHead = 0;
    rxCount = 0;
    netChangePending = false;
    netChangeMetered = false;
    held = false;
    changeWanted = false;
    haveFailed = false;
    rejectedCount = 0;
    nextCheckMs = 0;
    memset(&attempt, 0, sizeof(attempt));
    roamCount = 0;
    roamStatus = LI_ROAMING_IDLE;

    if (!deriveKeys((const unsigned char*)StreamConfig.remoteInputAesKey, roamKey, roamTag)) {
        Limelog("Roaming: key derivation failed, roaming disabled\n");
        ClientRoamingNegotiated = false;
        return;
    }

    if (persistedValid && memcmp(persistedTag, roamTag, sizeof(roamTag)) == 0) {
        clientSeq = persistedClientSeq;
        lastHostSeq = persistedHostSeq;
    }
    else {
        clientSeq = 0;
        lastHostSeq = 0;
    }

#ifdef LC_DEBUG
    if (!roamSelfCheck()) {
        Limelog("Roaming: self check against the known answers FAILED\n");
        LC_ASSERT(false);
    }
#endif

    roamInitialized = true;
    roamAccepting = true;
}

int ClientRoamingStart(void) {
    int err;

    if (!roamInitialized) {
        return 0;
    }

    err = PltCreateThread("Roam", roamThreadFunc, NULL, &roamThread);
    if (err != 0) {
        // Not fatal: the stream just doesn't follow network changes
        Limelog("Roaming: starting the roaming thread failed: %d\n", err);
        roamAccepting = false;
        return 0;
    }

    roamThreadStarted = true;
    return 0;
}

void ClientRoamingStop(void) {
    roamAccepting = false;

    if (roamThreadStarted) {
        PltInterruptThread(&roamThread);
        PltJoinThread(&roamThread);
        roamThreadStarted = false;
    }

    if (roamInitialized) {
        memcpy(persistedTag, roamTag, sizeof(roamTag));
        persistedClientSeq = clientSeq;
        persistedHostSeq = lastHostSeq;
        persistedValid = true;
        roamInitialized = false;
    }
}
