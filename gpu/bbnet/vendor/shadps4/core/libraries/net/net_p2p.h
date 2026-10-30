// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <memory>
#include <string_view>

#include "common/types.h"

namespace Core::Net::P2P {
class Keyring;
}

namespace Libraries::Net {
void ConfigureP2P(u16 udp_port, u32 advertised_addr);
u16 StartP2P(u16 udp_port);
void StopP2P();
std::shared_ptr<Core::Net::P2P::Keyring> GetP2PKeyring();

// Used by NP signaling/matching.
bool EnsureP2PTransport();
bool P2PTransportIsReady();
u16 GetP2PConfiguredPort(); // host order
u16 GetP2PBoundPort();      // host order, 0 when not running
u32 GetP2PAdvertisedAddr(); // Network order, 0 if unknown.
// SuperMedo relay through the shadNet server (network order, 0 = none), and the peers
// whose packets go through it.
void SetP2PRelayServer(u32 addr, u16 port);
void UseP2PRelayFor(u32 peer_addr);
// BBSC relay fallback through the BBSC game server's UDP relay (p2p_transport.cpp), by online
// id. addr = the shadNet server's (network order, 0 = off); our public endpoint from the STUN
// echo; our online id; a peer's online id and the endpoint signaling uses for it.
void SetBbscRelayServer(u32 addr);
void SetBbscRelaySelf(u32 addr, u16 port);
void SetBbscRelayLocalId(std::string_view online_id);
void BbscRelayRememberPeer(std::string_view online_id, u32 addr, u16 port);
void BbscRelayKeepAlive(); // the signaling thread, every pass
u16 GetP2PAdvertisedPort();
int P2PSignalingSendTo(const void* data, u32 len, u32 dest_addr, u16 dest_port);
int P2PSignalingRecvFrom(void* buf, u32 len, u32* from_addr, u16* from_port);
int P2PControlSendTo(const void* data, u32 len, u32 dest_addr, u16 dest_port);
int P2PControlRecvFrom(void* buf, u32 len, u32* from_addr, u16* from_port);
int P2PMatching2SendTo(const void* data, u32 len, u32 dest_addr, u16 dest_port);
int P2PMatching2RecvFrom(void* buf, u32 len, u32* from_addr, u16* from_port);

} // namespace Libraries::Net
