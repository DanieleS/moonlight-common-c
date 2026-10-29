#pragma once

#include "Platform.h"
#include "Limelight.h"
#include "PlatformSockets.h"
#include "PlatformThreads.h"
#include "PlatformCrypto.h"
#include "Video.h"
#include "Input.h"
#include "RtpAudioQueue.h"
#include "RtpVideoQueue.h"
#include "ByteBuffer.h"

#include <enet/enet.h>

// Common globals
extern char* RemoteAddrString;
extern struct sockaddr_storage RemoteAddr;
extern struct sockaddr_storage LocalAddr;
extern SOCKADDR_LEN AddrLen;
extern int AppVersionQuad[4];
extern STREAM_CONFIGURATION StreamConfig;
extern CONNECTION_LISTENER_CALLBACKS ListenerCallbacks;
extern DECODER_RENDERER_CALLBACKS VideoCallbacks;
extern AUDIO_RENDERER_CALLBACKS AudioCallbacks;
extern int NegotiatedVideoFormat;
extern volatile bool ConnectionInterrupted;
extern bool HighQualitySurroundSupported;
extern bool HighQualitySurroundEnabled;
extern OPUS_MULTISTREAM_CONFIGURATION NormalQualityOpusConfig;
extern OPUS_MULTISTREAM_CONFIGURATION HighQualityOpusConfig;
extern int AudioPacketDuration;
extern bool AudioEncryptionEnabled;
extern bool ReferenceFrameInvalidationSupported;
extern bool VideoFecControlSupported;
extern bool ClientRoamingNegotiated;

extern uint16_t RtspPortNumber;
extern uint16_t ControlPortNumber;
extern uint16_t AudioPortNumber;
extern uint16_t VideoPortNumber;

extern SS_PING AudioPingPayload;
extern SS_PING VideoPingPayload;
extern uint32_t ControlConnectData;

extern uint32_t SunshineFeatureFlags;

// Encryption flags shared by Sunshine and Moonlight in RTSP
#define SS_ENC_CONTROL_V2 0x01
#define SS_ENC_VIDEO 0x02
#define SS_ENC_AUDIO 0x04

extern uint32_t EncryptionFeaturesSupported;
extern uint32_t EncryptionFeaturesRequested;
extern uint32_t EncryptionFeaturesEnabled;

// ENet channel ID values
#define CTRL_CHANNEL_GENERIC      0x00
#define CTRL_CHANNEL_URGENT       0x01 // IDR, LTR ACK and RFI
#define CTRL_CHANNEL_KEYBOARD     0x02
#define CTRL_CHANNEL_MOUSE        0x03
#define CTRL_CHANNEL_PEN          0x04
#define CTRL_CHANNEL_TOUCH        0x05
#define CTRL_CHANNEL_SERVERCTL    0x08
#define CTRL_CHANNEL_GAMEPAD_BASE 0x10 // 0x10 to 0x1F by controller index
#define CTRL_CHANNEL_SENSOR_BASE  0x20 // 0x20 to 0x2F by controller index
#define CTRL_CHANNEL_COUNT        0x30

#ifndef UINT24_MAX
#define UINT24_MAX 0xFFFFFF
#endif

#define U16(x) ((unsigned short) ((x) & UINT16_MAX))
#define U24(x) ((unsigned int) ((x) & UINT24_MAX))
#define U32(x) ((unsigned int) ((x) & UINT32_MAX))

#define isBefore16(x, y) (U16((x) - (y)) > (UINT16_MAX/2))
#define isBefore24(x, y) (U24((x) - (y)) > (UINT24_MAX/2))
#define isBefore32(x, y) (U32((x) - (y)) > (UINT32_MAX/2))

#define APP_VERSION_AT_LEAST(a, b, c)                                                       \
    ((AppVersionQuad[0] > (a)) ||                                                           \
     (AppVersionQuad[0] == (a) && AppVersionQuad[1] > (b)) ||                               \
     (AppVersionQuad[0] == (a) && AppVersionQuad[1] == (b) && AppVersionQuad[2] >= (c)))

#define IS_SUNSHINE() (AppVersionQuad[3] < 0)

// Client feature flags for x-ml-general.featureFlags SDP attribute
#define ML_FF_FEC_STATUS 0x01 // Client sends SS_FRAME_FEC_STATUS for frame losses
#define ML_FF_SESSION_ID_V1 0x02 // Client supports X-SS-Ping-Payload and X-SS-Connect-Data
// Vibepollo extension: client wants SS_TEXT_FOCUS_PTYPE messages. Deliberately far from
// the low bits, which upstream allocates in order and other forks already use (0x04 and
// 0x08 carry DualSense haptics in Vibeshine and Moonlight V+, 0x10 remote text context).
// The host's LI_FF_TEXT_FOCUS sits at the same bit for the same reason.
#define ML_FF_TEXT_FOCUS 0x10000

// Vibepollo extension: host -> client text field focus. The payload is little endian:
// version (u8), focus type (u8), reserved (u16), sequence number (u32). A later version
// may append fields, so only shorter payloads are malformed.
#define SS_TEXT_FOCUS_PTYPE 0x3020
#define SS_TEXT_FOCUS_MIN_PAYLOAD_SIZE 8

// Vibepollo extension: client sends SS_CAPTURE_ACTION_PTYPE messages. Next to
// ML_FF_TEXT_FOCUS for the same reasons; the host's LI_FF_CAPTURE_ACTIONS is the same bit.
#define ML_FF_CAPTURE_ACTIONS 0x20000

// Vibepollo extension: client -> host capture request, carried out by the host's
// configured capture tool. The payload is version (u8), action (u8), reserved (u16).
#define SS_CAPTURE_ACTION_PTYPE 0x3021
#define SS_CAPTURE_ACTION_WIRE_VERSION 1

#define UDP_RECV_POLL_TIMEOUT_MS 100

// At this value or above, we will request high quality audio unless CAPABILITY_SLOW_OPUS_DECODER
// is set on the audio renderer.
#define HIGH_AUDIO_BITRATE_THRESHOLD 15000

// Below this value, we will request 20 ms audio frames to reduce bandwidth if the audio
// renderer sets CAPABILITY_SUPPORTS_ARBITRARY_AUDIO_DURATION.
#define LOW_AUDIO_BITRATE_TRESHOLD 5000

// Internal macro for checking the magic byte of the audio configuration value
#define MAGIC_BYTE_FROM_AUDIO_CONFIG(x) ((x) & 0xFF)

int serviceEnetHost(ENetHost* client, ENetEvent* event, enet_uint32 timeoutMs);
int gracefullyDisconnectEnetPeer(ENetHost* host, ENetPeer* peer, enet_uint32 lingerTimeoutMs);
int extractVersionQuadFromString(const char* string, int* quad);
bool isReferenceFrameInvalidationSupportedByDecoder(void);
bool isReferenceFrameInvalidationEnabled(void);
void* extendBuffer(void* ptr, size_t newSize);

void fixupMissingCallbacks(PDECODER_RENDERER_CALLBACKS* drCallbacks, PAUDIO_RENDERER_CALLBACKS* arCallbacks,
    PCONNECTION_LISTENER_CALLBACKS* clCallbacks);
void setRecorderCallbacks(PDECODER_RENDERER_CALLBACKS drCallbacks, PAUDIO_RENDERER_CALLBACKS arCallbacks);

char* getSdpPayloadForStreamConfig(int rtspClientVersion, int* length);

int initializeControlStream(void);
int startControlStream(void);
int stopControlStream(void);
void destroyControlStream(void);
void connectionDetectedFrameLoss(uint32_t startFrame, uint32_t endFrame);
void connectionReceivedCompleteFrame(uint32_t frameIndex, bool frameIsLTR);
void connectionSawFrame(uint32_t frameIndex);
void connectionSendFrameFecStatus(PSS_FRAME_FEC_STATUS fecStatus);
void connectionRecordVideoLoss(uint32_t dataPackets, uint32_t missingDataPackets);
int sendInputPacketOnControlStream(unsigned char* data, int length, uint8_t channelId, uint32_t flags, bool moreData);
void flushInputOnControlStream(void);
bool isControlDataInTransit(void);

int performRtspHandshake(PSERVER_INFORMATION serverInfo);

void initializeVideoDepacketizer(int pktSize);
void destroyVideoDepacketizer(void);
void queueRtpPacket(PRTPV_QUEUE_ENTRY queueEntry);
void stopVideoDepacketizer(void);
void requestDecoderRefresh(void);
void notifyFrameLost(unsigned int frameNumber, bool speculative);

void initializeVideoStream(void);
void destroyVideoStream(void);
void notifyKeyFrameReceived(void);
int startVideoStream(void* rendererContext, int drFlags);
void stopVideoStream(void);

int initializeAudioStream(void);
int notifyAudioPortNegotiationComplete(void);
void destroyAudioStream(void);
int startAudioStream(void* audioContext, int arFlags);
void stopAudioStream(void);

int initializeInputStream(void);
void destroyInputStream(void);
int startInputStream(void);
int stopInputStream(void);
