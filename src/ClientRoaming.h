#pragma once

#include "Limelight-internal.h"

// Client roaming (wire version 1): lets the stream follow a change of the client's network
// without reconnecting. Everything here is inert unless ClientRoamingNegotiated is set, that
// is, unless the host advertised a=x-rl-roaming in its RTSP DESCRIBE response.

#define ROAM_DATAGRAM_SIZE 52

// Called once the roaming capability is known, before the control stream starts. Derives the
// keys from the launch's rikey and arms the handler for datagrams from the host.
void ClientRoamingInit(void);

// Starts the roaming thread. Called once every stream is running.
int ClientRoamingStart(void);

// Stops the roaming thread. Safe to call at any time, including when nothing was started.
void ClientRoamingStop(void);

// True when the data looks like a roaming datagram (it starts with the magic bytes).
bool ClientRoamingIsDatagram(const unsigned char* data, size_t length);

// Called from the ENet intercept (under enetMutex) with a datagram from the host. Only queues
// a copy for the roaming thread: no parsing, no sending, no allocation.
void ClientRoamingQueueDatagram(const unsigned char* data, size_t length);

// Control socket access for the roaming thread (ControlStream.c)
SOCKET ControlStreamCreateRoamSocket(struct sockaddr_storage* localAddr);
bool ControlStreamSwapSocket(SOCKET newSock);
void ControlStreamReapRetiredSocket(bool force);
bool ControlStreamSendRoamDatagram(const unsigned char* data, int length);

// Media socket access for the roaming thread (VideoStream.c, AudioStream.c)
SOCKET VideoStreamCreateSocket(struct sockaddr_storage* localAddr);
void VideoStreamRebind(SOCKET newSock);
void VideoStreamPingNow(void);
SOCKET AudioStreamCreateSocket(struct sockaddr_storage* localAddr);
void AudioStreamRebind(SOCKET newSock);
void AudioStreamPingNow(void);
