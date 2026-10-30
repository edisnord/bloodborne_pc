// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <cstring>
#include <tuple>

#include "common/logging/log.h"
#include "core/net/p2p_transport.h"

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace Core::Net::P2P {

struct DatagramBinding {
    struct Packet {
        std::vector<u8> payload;
        Endpoint from;
        u16 src_vport;
    };
    u16 vport = 0;
    std::shared_ptr<Readiness> readiness;
    std::optional<std::pair<Endpoint, u16>> peer; // set by SetPeer
    std::deque<Packet> queue;
    size_t bytes = 0;
};

struct Connection {
    ConnectionKey key;
    Protection protection;
    std::unique_ptr<TcpConnection> tcp;
    std::shared_ptr<Readiness> readiness;
    std::weak_ptr<ListenerState> listener; // during handshake
    bool pending_accept = false;           // not in accept queue yet
    bool released = true;                  // no socket owns it
};

struct ListenerState {
    u16 vport = 0;
    int backlog = 1;
    Protection protection;
    std::shared_ptr<Readiness> readiness;
    std::deque<std::shared_ptr<Connection>> accept_queue;
    int half_open = 0;
    bool closed = false;
};

namespace {

auto Canonical(const Endpoint& e) {
    std::array<u8, 16> address{};
    u16 port = 0;
    u32 scope = 0;
    if (e.Family() == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(&e.addr);
        std::memcpy(address.data(), &in->sin_addr, 4);
        port = in->sin_port;
    } else if (e.Family() == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&e.addr);
        std::memcpy(address.data(), &in6->sin6_addr, 16);
        port = in6->sin6_port;
        scope = in6->sin6_scope_id;
    }
    return std::tuple{e.Family(), address, port, scope};
}

} // namespace

Endpoint Endpoint::FromSockaddr(const sockaddr* sa, socklen_t len) {
    Endpoint e;
    std::memcpy(&e.addr, sa, std::min<size_t>(static_cast<size_t>(len), sizeof(e.addr)));
    return e;
}

Endpoint Endpoint::IPv4(const char* dotted, u16 port) {
    Endpoint e;
    auto* in = reinterpret_cast<sockaddr_in*>(&e.addr);
    in->sin_family = AF_INET;
    in->sin_port = htons(port);
    inet_pton(AF_INET, dotted, &in->sin_addr);
    return e;
}

socklen_t Endpoint::Length() const {
    return Family() == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
}

u16 Endpoint::Port() const {
    return ntohs(std::get<2>(Canonical(*this)));
}

bool Endpoint::operator<(const Endpoint& other) const {
    return Canonical(*this) < Canonical(other);
}

bool Endpoint::operator==(const Endpoint& other) const {
    return Canonical(*this) == Canonical(other);
}

bool ConnectionKey::operator<(const ConnectionKey& other) const {
    if (!(peer == other.peer)) {
        return peer < other.peer;
    }
    return std::tie(peer_vport, local_vport) < std::tie(other.peer_vport, other.local_vport);
}

void ReadinessFlag::Set(bool ready) {
    if (ready == ready_) {
        return;
    }
    ready_ = ready;
    if (ready) {
        wake_.Signal();
    } else {
        wake_.Drain();
    }
}

Transport::Transport(int family, std::unique_ptr<Codec> codec, const TransportConfig& config)
    : family_(family), codec_(std::move(codec)), config_(config),
      signaling_(std::max<size_t>(config.signaling_channels, 1)),
      iss_state_(static_cast<u64>(Clock::now().time_since_epoch().count()) ^
                 reinterpret_cast<uintptr_t>(this)),
      receive_buffer_(65536) {}

std::shared_ptr<Transport> Transport::Create(int family, const Endpoint& bind_address,
                                             std::unique_ptr<Codec> codec,
                                             const TransportConfig& config, Error* error) {
    std::shared_ptr<Transport> t(new Transport(family, std::move(codec), config));
    if (!t->kick_.Valid()) {
        *error = Error::NoBufs;
        return nullptr;
    }
    t->socket_ = Host::CreateSocket(family, SOCK_DGRAM, 0, error);
    if (t->socket_ == Host::InvalidSocket) {
        return nullptr;
    }
    // Exclusive port. Nobody else should get the port we advertise.
    if ((*error = Host::PrepareBind(t->socket_, false, false)) != Error::Ok ||
        (*error = Host::Bind(t->socket_, bind_address.Sockaddr(), bind_address.Length())) !=
            Error::Ok) {
        return nullptr;
    }
    const int buffer = 1 << 20; // absorb bursts
    setsockopt(t->socket_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buffer),
               sizeof(buffer));
    sockaddr_storage actual{};
    socklen_t actual_len = sizeof(actual);
    getsockname(t->socket_, reinterpret_cast<sockaddr*>(&actual), &actual_len);
    t->bound_port_ =
        Endpoint::FromSockaddr(reinterpret_cast<sockaddr*>(&actual), actual_len).Port();
    t->thread_ = std::thread([raw = t.get()] { raw->ThreadMain(); });
    *error = Error::Ok;
    return t;
}

Transport::~Transport() {
    stop_.store(true);
    kick_.Signal();
    if (thread_.joinable()) {
        thread_.join();
    }
    Host::CloseSocket(socket_); // thread is stopped by now
}

void Transport::SetOutgoingLossForTesting(double probability) {
    std::scoped_lock lock{mutex_};
    loss_for_testing_ = probability;
}

void Transport::SetRelayServer(std::optional<Endpoint> relay_server) {
    std::scoped_lock lock{mutex_};
    relay_server_ = std::move(relay_server);
}

void Transport::UseRelayFor(u32 peer_addr) {
    std::scoped_lock lock{mutex_};
    relayed_peers_.insert(peer_addr);
}

// ---- BBSC relay fallback (from BBSC's bbport-1.7.2 patch, 2026-10-12/13) -----------------------
// Direct P2P needs one side reachable: CGNAT, strict routers and several windows on one PC (no
// hairpin) leave both sides unreachable. Peers go through the BBSC game server's UDP relay
// (gameserver/bbhost_service.py Relay._shad, port 3478 on the shadNet server's address), by
// online id:
//   "BBR1" 0x01 id[16]                       register, every 5 s (keeps our NAT mapping open)
//   "BBR1" 0x02                              registered (from the relay)
//   "BBR1" 0x03 dst[16] src[16] ep[6] packet  packet for dst
//   "BBR1" 0x04 src[16] ep[6] packet          packet from src
//   "BBR1" 0x05 dst[16]                      dst is not on the relay (direct only for 10 s)
// ep = the sender's own public address and port as shadNet sees them (its STUN echo), so the
// receiver files the packet under the endpoint its signaling uses for that peer.
// Every known peer goes through the relay from the first packet; direct copies still go out until
// the peer answers, and a peer without the relay is answered directly. SHADPS4_P2P_RELAY=0 turns
// it off, =auto (or direct) = "direct first, relay after 2 s", =a.b.c.d:port another relay;
// SHADPS4_P2P_RELAY_PORT changes the port (Libraries::Net::SetBbscRelayServer).
// While the BBSC relay answers, the SuperMedo relay is not used: a BBSC server has none, and
// a peer switched to it after 4 s of silence would be cut off.

namespace {
constexpr u8 kBbscMagic[4] = {'B', 'B', 'R', '1'};
constexpr size_t kBbscIdSize = 16;
constexpr size_t kBbscEpSize = 6;
constexpr size_t kBbscEarlyPackets = 32;

std::string BbscPadId(std::string_view online_id) {
    std::string id(online_id.substr(0, kBbscIdSize));
    id.resize(kBbscIdSize, '\0');
    return id;
}

std::string BbscIdText(const std::string& id) {
    return std::string(id.c_str());
}

u64 BbscKey(u32 addr, u16 port) {
    return (static_cast<u64>(addr) << 16) | port;
}
} // namespace

void Transport::SetBbscRelay(std::optional<Endpoint> relay_server, bool force) {
    std::scoped_lock lock{mutex_};
    if (bbsc_.server == relay_server && bbsc_.force == force) {
        return;
    }
    bbsc_.server = std::move(relay_server);
    bbsc_.force = force;
    bbsc_.acked = false;
    bbsc_.silence_logged = false;
    bbsc_.started = Clock::now();
    bbsc_.last_register = {};
    if (bbsc_.server) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(bbsc_.server->Sockaddr());
        LOG_INFO(Lib_Net, "P2P relay fallback: server {:#x}:{}{}", in->sin_addr.s_addr,
                 bbsc_.server->Port(), force ? " (forced for every peer)" : "");
    } else {
        LOG_INFO(Lib_Net, "P2P relay fallback: off");
    }
}

void Transport::SetBbscRelaySelf(u32 addr, u16 port) {
    std::scoped_lock lock{mutex_};
    if (bbsc_.self_addr != addr || bbsc_.self_port != port) {
        LOG_INFO(Lib_Net, "P2P relay fallback: our public endpoint {:#x}:{}", addr, ntohs(port));
    }
    bbsc_.self_addr = addr;
    bbsc_.self_port = port;
}

void Transport::SetBbscRelayLocalId(std::string_view online_id) {
    if (online_id.empty()) {
        return;
    }
    std::scoped_lock lock{mutex_};
    const std::string id = BbscPadId(online_id);
    if (std::find(bbsc_.local_ids.begin(), bbsc_.local_ids.end(), id) == bbsc_.local_ids.end()) {
        bbsc_.local_ids.push_back(id);
        bbsc_.last_register = {};
    }
}

void Transport::BbscRelayRememberPeer(std::string_view online_id, u32 addr, u16 port) {
    if (online_id.empty() || addr == 0 || port == 0) {
        return;
    }
    std::scoped_lock lock{mutex_};
    const std::string id = BbscPadId(online_id);
    // Kept by online id; every endpoint signaling or the relay ever gave for it stays an alias
    // (filed under one endpoint, signaling's sends to another went direct only: one-way relay).
    BbscPeer& peer = bbsc_.peers[id];
    peer.id = id;
    peer.addr = addr;
    peer.port = port;
    BbscAddAlias(id, addr, port, "signaling");
}

void Transport::BbscAddAlias(const std::string& id, u32 addr, u16 port, const char* from) {
    if (addr == 0 || port == 0) {
        return;
    }
    std::string& known = bbsc_.alias[BbscKey(addr, port)];
    if (known == id) {
        return;
    }
    known = id;
    LOG_INFO(Lib_Net, "P2P relay fallback: '{}' known at {:#x}:{} (from {})", BbscIdText(id),
             addr, ntohs(port), from);
}

Transport::BbscPeer* Transport::BbscFindPeer(u32 addr, u16 port) {
    const auto alias = bbsc_.alias.find(BbscKey(addr, port));
    if (alias == bbsc_.alias.end()) {
        return nullptr;
    }
    const auto it = bbsc_.peers.find(alias->second);
    return it == bbsc_.peers.end() ? nullptr : &it->second;
}

void Transport::BbscSendToRelay(const std::vector<u8>& packet) {
    (void)Host::SendTo(socket_, packet.data(), packet.size(), 0, bbsc_.server->Sockaddr(),
                       bbsc_.server->Length());
}

void Transport::BbscRelayKeepAlive() {
    std::scoped_lock lock{mutex_};
    if (!bbsc_.server || bbsc_.local_ids.empty()) {
        return;
    }
    const auto now = Clock::now();
    // Every 5 s once registered, 2 s until then; a server that never answered in 30 s has no
    // BBSC relay (SuperMedo Server, The Hunter's Dream): asked every 30 s only.
    const bool silent = !bbsc_.acked && now - bbsc_.started >= std::chrono::seconds(30);
    if (silent && !bbsc_.silence_logged) {
        bbsc_.silence_logged = true;
        LOG_INFO(Lib_Net, "P2P relay fallback: no BBSC relay answers on this server - direct "
                          "connections only (asked again every 30 s)");
    }
    const auto interval = bbsc_.acked ? std::chrono::seconds(5)
                          : silent    ? std::chrono::seconds(30)
                                      : std::chrono::seconds(2);
    if (bbsc_.last_register != Clock::time_point{} && now - bbsc_.last_register < interval) {
        return;
    }
    bbsc_.last_register = now;
    if (now - bbsc_.last_status >= std::chrono::seconds(30) &&
        (bbsc_.sent != bbsc_.status_sent || bbsc_.received != bbsc_.status_received)) {
        bbsc_.last_status = now;
        bbsc_.status_sent = bbsc_.sent;
        bbsc_.status_received = bbsc_.received;
        std::string peers;
        for (const auto& [id, peer] : bbsc_.peers) {
            if (!peers.empty()) {
                peers += ", ";
            }
            peers += BbscIdText(peer.id);
            peers += !peer.relayed                 ? " direct"
                     : now < peer.missing_until    ? " not on the relay"
                     : peer.relay_seen             ? " relay"
                                                   : " relay (no answer yet)";
        }
        LOG_INFO(Lib_Net,
                 "P2P relay fallback: {} packet(s) sent / {} received through the relay so far; "
                 "peers: {}",
                 bbsc_.sent, bbsc_.received, peers.empty() ? "none" : peers);
    }
    for (const std::string& id : bbsc_.local_ids) {
        std::vector<u8> packet(std::begin(kBbscMagic), std::end(kBbscMagic));
        packet.push_back(0x01);
        packet.insert(packet.end(), id.begin(), id.end());
        BbscSendToRelay(packet);
    }
}

Transport::BbscPath Transport::BbscRoute(std::span<const u8> packet, u32 addr, u16 port) {
    if (!bbsc_.server || !bbsc_.acked || bbsc_.local_ids.empty()) {
        return BbscPath::Direct;
    }
    BbscPeer* const found = BbscFindPeer(addr, port);
    if (found == nullptr) {
        return BbscPath::Direct;
    }
    BbscPeer& peer = *found;
    const auto now = Clock::now();
    if (peer.relayed && now < peer.missing_until) {
        return BbscPath::Direct;
    }
    if (!peer.relayed) {
        if (bbsc_.force) {
            peer.relayed = true;
        } else if (!peer.tx_started) {
            peer.tx_started = true;
            peer.first_tx = now;
        } else if (!peer.direct_rx && now - peer.first_tx >= std::chrono::seconds(2)) {
            peer.relayed = true;
        }
        if (!peer.relayed) {
            // Kept for the switch: signaling sends some packets only once (the activation
            // request); lost directly, the peer ignores everything after it.
            if (!peer.direct_rx && peer.early.size() < kBbscEarlyPackets) {
                peer.early.emplace_back(packet.begin(), packet.end());
            }
            return BbscPath::Direct;
        }
        peer.relayed_since = now;
        LOG_INFO(Lib_Net,
                 "P2P relay fallback: '{}' at {:#x}:{} {} - through the relay ({} earlier "
                 "packet(s) sent again)",
                 BbscIdText(peer.id), peer.addr, ntohs(peer.port),
                 bbsc_.force ? "(forced)" : "sent nothing back directly in 2 s",
                 peer.early.size());
        for (const std::vector<u8>& early : peer.early) {
            BbscSendRelayed(peer, early);
        }
        peer.early.clear();
        peer.early.shrink_to_fit();
    }
    BbscSendRelayed(peer, packet);
    // After the switch, packets still go directly too until the peer answers either way: an
    // emulator without the relay can only be reached directly. A peer that uses the relay gets
    // direct copies for 10 s more, then the relay alone.
    const bool direct_copy =
        !peer.direct_rx && (!peer.relay_seen || now - peer.relayed_since < std::chrono::seconds(10));
    return direct_copy ? BbscPath::Both : BbscPath::Relay;
}

void Transport::BbscSendRelayed(const BbscPeer& peer, std::span<const u8> packet) {
    const std::string& self = bbsc_.local_ids.front();
    std::vector<u8> framed;
    framed.reserve(5 + 2 * kBbscIdSize + kBbscEpSize + packet.size());
    framed.insert(framed.end(), std::begin(kBbscMagic), std::end(kBbscMagic));
    framed.push_back(0x03);
    framed.insert(framed.end(), peer.id.begin(), peer.id.end());
    framed.insert(framed.end(), self.begin(), self.end());
    u8 ep[kBbscEpSize];
    std::memcpy(ep, &bbsc_.self_addr, 4);
    std::memcpy(ep + 4, &bbsc_.self_port, 2);
    framed.insert(framed.end(), ep, ep + kBbscEpSize);
    framed.insert(framed.end(), packet.begin(), packet.end());
    BbscSendToRelay(framed);
    ++bbsc_.sent;
}

void Transport::BbscNoteDirect(u32 addr, u16 port) {
    if (bbsc_.peers.empty()) {
        return;
    }
    BbscPeer* const found = BbscFindPeer(addr, port);
    if (found == nullptr || found->direct_rx) {
        return;
    }
    BbscPeer& peer = *found;
    peer.direct_rx = true;
    peer.early.clear();
    if (peer.relayed && !peer.relay_seen) {
        // It answers directly and never used the relay (an emulator without it, or a NAT hole
        // that took longer than 2 s): direct from now on.
        peer.relayed = false;
        LOG_INFO(Lib_Net, "P2P relay fallback: '{}' reached us directly - back to direct",
                 BbscIdText(peer.id));
    } else {
        LOG_INFO(Lib_Net, "P2P relay fallback: '{}' reached us directly{}", BbscIdText(peer.id),
                 peer.relayed ? " (staying on the relay)" : "");
    }
}

void Transport::BbscReceive(std::span<const u8> packet, Clock::time_point now) {
    if (packet.size() < 5 || std::memcmp(packet.data(), kBbscMagic, 4) != 0) {
        return;
    }
    const u8 kind = packet[4];
    if (kind == 0x02) {
        if (!bbsc_.acked) {
            bbsc_.acked = true;
            LOG_INFO(Lib_Net, "P2P relay fallback: registered with the relay");
        }
        return;
    }
    if (kind == 0x05 && packet.size() >= 5 + kBbscIdSize) {
        const std::string id(reinterpret_cast<const char*>(packet.data() + 5), kBbscIdSize);
        const auto known = bbsc_.peers.find(id);
        if (known != bbsc_.peers.end()) {
            BbscPeer& peer = known->second;
            peer.missing_until = now + std::chrono::seconds(10);
            if (!peer.missing_logged) {
                peer.missing_logged = true;
                LOG_WARNING(Lib_Net,
                            "P2P relay fallback: '{}' is not on the relay (no relay in its build, "
                            "or it is not running) - direct only; if direct does not work "
                            "either, it cannot connect",
                            BbscIdText(peer.id));
            }
        }
        return;
    }
    if (kind != 0x04 || packet.size() < 5 + kBbscIdSize + kBbscEpSize) {
        return;
    }
    const std::string id(reinterpret_cast<const char*>(packet.data() + 5), kBbscIdSize);
    u32 ep_addr = 0;
    u16 ep_port = 0;
    std::memcpy(&ep_addr, packet.data() + 5 + kBbscIdSize, 4);
    std::memcpy(&ep_port, packet.data() + 5 + kBbscIdSize + 4, 2);
    if (!bbsc_.peers.contains(id)) {
        // A peer signaling never looked up: the endpoint it gave, else a made-up one
        // (169.254.x.x, never sent to directly) so the answers go back through the relay.
        BbscPeer& made = bbsc_.peers[id];
        made.id = id;
        if (ep_addr != 0 && ep_port != 0) {
            made.addr = ep_addr;
            made.port = ep_port;
        } else {
            made.addr = htonl(0xA9FE0000u | (bbsc_.next_pseudo++ & 0xFFFFu));
            made.port = htons(3173);
        }
        BbscAddAlias(id, made.addr, made.port, "relay, new peer");
    }
    // Its own endpoint is one more alias; the peer keeps the endpoint signaling knows, so the
    // packet below arrives from where signaling expects it.
    BbscAddAlias(id, ep_addr, ep_port, "relay");
    BbscPeer& peer = bbsc_.peers[id];
    peer.relay_seen = true;
    peer.missing_until = {};
    if (!peer.relayed) {
        peer.relayed = true;
        peer.relayed_since = now;
        LOG_INFO(Lib_Net,
                 "P2P relay fallback: '{}' reached us through the relay - answering the same way",
                 BbscIdText(peer.id));
    }
    ++bbsc_.received;
    sockaddr_in source{};
    source.sin_family = AF_INET;
    source.sin_addr.s_addr = peer.addr;
    source.sin_port = peer.port;
    const size_t head = 5 + kBbscIdSize + kBbscEpSize;
    HandlePacket(packet.subspan(head),
                 Endpoint::FromSockaddr(reinterpret_cast<const sockaddr*>(&source), sizeof(source)),
                 now, true);
}

std::shared_ptr<DatagramSocket> Transport::CreateDatagram() {
    return std::shared_ptr<DatagramSocket>(new DatagramSocket(shared_from_this()));
}

std::shared_ptr<StreamSocket> Transport::CreateStream() {
    return std::shared_ptr<StreamSocket>(new StreamSocket(shared_from_this(), nullptr));
}

Error Transport::SendSignaling(std::span<const u8> data, const Endpoint& to) {
    std::scoped_lock lock{mutex_};
    return SendPacket(codec_->EncodeSignaling(data, to), to);
}

bool Transport::RecvSignaling(size_t channel, std::vector<u8>* data, Endpoint* from) {
    std::scoped_lock lock{mutex_};
    if (channel >= signaling_.size() || signaling_[channel].empty()) {
        return false;
    }
    auto& queue = signaling_[channel];
    *data = std::move(queue.front().first);
    *from = queue.front().second;
    queue.pop_front();
    return true;
}

void Transport::ThreadMain() {
    while (!stop_.load()) {
        std::optional<Clock::time_point> deadline;
        {
            std::scoped_lock lock{mutex_};
            deadline = EarliestDeadline();
            sleeping_until_ = deadline.value_or(Clock::time_point::max());
        }
        const auto result = Host::WaitOne(socket_, Host::Readable, kick_, deadline);
        if (stop_.load()) {
            return;
        }
        if (result == Host::WaitResult::Woken) {
            kick_.Drain();
        }

        std::scoped_lock lock{mutex_};
        sleeping_until_ = Clock::time_point::min();
        const auto now = Clock::now();
        for (int i = 0; i < 1024; ++i) { // don't starve timers
            sockaddr_storage from{};
            socklen_t from_len = sizeof(from);
            const auto r = Host::RecvFrom(socket_, receive_buffer_.data(), receive_buffer_.size(),
                                          0, reinterpret_cast<sockaddr*>(&from), &from_len);
            if (r.error != Error::Ok) {
                break;
            }
            HandlePacket({receive_buffer_.data(), static_cast<size_t>(r.value)},
                         Endpoint::FromSockaddr(reinterpret_cast<sockaddr*>(&from), from_len), now);
        }
        RunTimers(now);
    }
}

std::optional<Clock::time_point> Transport::EarliestDeadline() const {
    std::optional<Clock::time_point> earliest;
    for (const auto& [_, connection] : connections_) {
        const auto d = connection->tcp->NextDeadline();
        if (d && (!earliest || *d < *earliest)) {
            earliest = d;
        }
    }
    return earliest;
}

void Transport::RunTimers(Clock::time_point now) {
    std::vector<std::shared_ptr<Connection>> due;
    for (const auto& [_, connection] : connections_) {
        if (const auto d = connection->tcp->NextDeadline(); d && *d <= now) {
            due.push_back(connection);
        }
    }
    for (const auto& connection : due) {
        connection->tcp->OnTimer(now);
        Update(connection);
    }
}

void Transport::Reschedule(const Connection& connection) {
    if (const auto d = connection.tcp->NextDeadline(); d && *d < sleeping_until_) {
        sleeping_until_ = *d;
        kick_.Signal();
    }
}

// SuperMedo relay frames: "SMRL", kind, IPv4 address and port (network order), packet.
constexpr u8 kRelayMagic[4] = {'S', 'M', 'R', 'L'};
constexpr u8 kRelaySend = 0x02;    // to the server: the address is the destination
constexpr u8 kRelayDeliver = 0x03; // from the server: the address is the source
constexpr size_t kRelayHeaderSize = 11;

Error Transport::SendPacket(std::span<const u8> packet, const Endpoint& to) {
    if (loss_for_testing_ > 0) {
        loss_rng_ ^= loss_rng_ << 13;
        loss_rng_ ^= loss_rng_ >> 7;
        loss_rng_ ^= loss_rng_ << 17;
        if (static_cast<double>(loss_rng_ >> 11) / static_cast<double>(1ull << 53) <
            loss_for_testing_) {
            return Error::Ok;
        }
    }
    if (bbsc_.server && to.Family() == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(to.Sockaddr());
        const BbscPath path = BbscRoute(packet, in->sin_addr.s_addr, in->sin_port);
        if (path == BbscPath::Relay) {
            return Error::Ok;
        }
        if (path == BbscPath::Both) {
            (void)Host::SendTo(socket_, packet.data(), packet.size(), 0, to.Sockaddr(),
                               to.Length());
            return Error::Ok;
        }
    }
    // Not while the BBSC relay answers: that server has no SuperMedo relay.
    if (relay_server_ && !bbsc_.acked && to.Family() == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(to.Sockaddr());
        if (relayed_peers_.contains(in->sin_addr.s_addr)) {
            std::vector<u8> framed(kRelayHeaderSize + packet.size());
            std::memcpy(framed.data(), kRelayMagic, 4);
            framed[4] = kRelaySend;
            std::memcpy(framed.data() + 5, &in->sin_addr.s_addr, 4);
            std::memcpy(framed.data() + 9, &in->sin_port, 2);
            std::memcpy(framed.data() + kRelayHeaderSize, packet.data(), packet.size());
            return Host::SendTo(socket_, framed.data(), framed.size(), 0,
                                relay_server_->Sockaddr(), relay_server_->Length())
                .error;
        }
    }
    const auto r =
        Host::SendTo(socket_, packet.data(), packet.size(), 0, to.Sockaddr(), to.Length());
    return r.error;
}

u32 Transport::NewIss() {
    iss_state_ += 0x9e3779b97f4a7c15ull;
    u64 z = iss_state_;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    z ^= z >> 31;
    const auto clock =
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now().time_since_epoch())
            .count() /
        4;
    return static_cast<u32>(z) + static_cast<u32>(clock);
}

u16 Transport::AllocateVport(bool stream) {
    const u16 first = stream ? 49152 : 32768;
    const u16 last = stream ? 65535 : 49999;
    u16& next = stream ? next_stream_port_ : next_datagram_vport_;
    for (int attempt = 0; attempt <= last - first; ++attempt) {
        const u16 vport = next;
        next = next == last ? first : static_cast<u16>(next + 1);
        const bool used =
            stream ? (stream_vports_in_use_.contains(vport) || listeners_.contains(vport))
                   : datagram_bindings_.contains(vport);
        if (!used) {
            return vport;
        }
    }
    return 0;
}

void Transport::HandlePacket(std::span<const u8> packet, const Endpoint& from,
                             Clock::time_point now, bool relayed) {
    if (!relayed && bbsc_.server && from == *bbsc_.server) {
        BbscReceive(packet, now);
        return;
    }
    if (!relayed && relay_server_ && from == *relay_server_ && packet.size() > kRelayHeaderSize &&
        std::memcmp(packet.data(), kRelayMagic, 4) == 0 && packet[4] == kRelayDeliver) {
        sockaddr_in source{};
        source.sin_family = AF_INET;
        std::memcpy(&source.sin_addr.s_addr, packet.data() + 5, 4);
        std::memcpy(&source.sin_port, packet.data() + 9, 2);
        relayed_peers_.insert(source.sin_addr.s_addr); // answer the way it came
        HandlePacket(packet.subspan(kRelayHeaderSize),
                     Endpoint::FromSockaddr(reinterpret_cast<const sockaddr*>(&source),
                                            sizeof(source)),
                     now, true);
        return;
    }
    if (!relayed && from.Family() == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(from.Sockaddr());
        BbscNoteDirect(in->sin_addr.s_addr, in->sin_port);
    }
    Codec::Decoded decoded = codec_->Decode(packet, from);
    switch (decoded.kind) {
    case Codec::Kind::Stream:
        HandleStreamSegment(decoded.payload, from, now);
        break;
    case Codec::Kind::Datagram:
        HandleDatagram(decoded, from);
        break;
    case Codec::Kind::Signaling: {
        const size_t channel =
            config_.classify_signaling ? config_.classify_signaling(decoded.payload) : 0;
        if (channel < signaling_.size() &&
            signaling_[channel].size() < config_.signaling_queue_packets) {
            signaling_[channel].emplace_back(std::move(decoded.payload), from);
        }
        break;
    }
    case Codec::Kind::Invalid:
        break;
    }
}

void Transport::HandleDatagram(Codec::Decoded& decoded, const Endpoint& from) {
    const auto it = datagram_bindings_.find(decoded.dst_vport);
    if (it == datagram_bindings_.end()) {
        return;
    }
    DatagramBinding& binding = *it->second;
    if (binding.peer &&
        !(binding.peer->first == from && binding.peer->second == decoded.src_vport)) {
        return; // not from the connected peer
    }
    if (binding.bytes + decoded.payload.size() > config_.datagram_queue_bytes) {
        return; // queue full, drop like UDP
    }
    binding.bytes += decoded.payload.size();
    binding.queue.push_back({std::move(decoded.payload), from, decoded.src_vport});
    binding.readiness->readable.Set(true);
}

void Transport::HandleStreamSegment(std::span<const u8> bytes, const Endpoint& from,
                                    Clock::time_point now) {
    std::optional<PseudoHeader> pseudo;
    if (config_.verify_stream_checksum) {
        pseudo = codec_->StreamPseudoHeader(from);
    }
    const auto seg = ParseTcpSegment(bytes, pseudo ? &*pseudo : nullptr);
    if (!seg) {
        return;
    }
    const ConnectionKey key{from, seg->src_port, seg->dst_port};
    if (const auto it = connections_.find(key); it != connections_.end()) {
        const auto connection = it->second;
        if (connection->tcp->State() != TcpState::Closed) {
            connection->tcp->OnSegment(*seg, now);
            Update(connection);
            return;
        }
        if (connection->released) {
            connections_.erase(it);
        }
    }

    const bool bare_syn =
        (seg->flags & (TcpFlag::Syn | TcpFlag::Ack | TcpFlag::Rst)) == TcpFlag::Syn;
    if (bare_syn && !connections_.contains(key)) {
        const auto lit = listeners_.find(seg->dst_port);
        if (lit != listeners_.end()) {
            const auto listener = lit->second;
            if (static_cast<int>(listener->accept_queue.size()) + listener->half_open >=
                listener->backlog) {
                return; // backlog full, peer will retry
            }
            const auto connection =
                NewConnection(key, listener->protection, std::make_shared<Readiness>());
            connection->listener = listener;
            connection->pending_accept = true;
            ++listener->half_open;
            connection->tcp->AcceptSyn(*seg, now);
            Update(connection);
            return;
        }
    }
    // Nobody listening, RST so the peer fails fast.
    if (!pseudo) {
        pseudo = codec_->StreamPseudoHeader(from);
    }
    if (const auto rst = BuildResetFor(*pseudo, *seg)) {
        SendPacket(codec_->EncodeStream(*rst, from, {}), from);
    }
}

std::shared_ptr<Connection> Transport::NewConnection(const ConnectionKey& key,
                                                     Protection protection,
                                                     std::shared_ptr<Readiness> readiness) {
    auto connection = std::make_shared<Connection>();
    connection->key = key;
    connection->protection = protection;
    connection->readiness = std::move(readiness);
    const Endpoint peer = key.peer;
    connection->tcp = std::make_unique<TcpConnection>(
        config_.tcp, codec_->StreamPseudoHeader(peer), key.local_vport, key.peer_vport, NewIss(),
        [this, peer, protection](std::span<const u8> segment) {
            SendPacket(codec_->EncodeStream(segment, peer, protection), peer);
        });
    connections_[key] = connection;
    return connection;
}

void Transport::Update(const std::shared_ptr<Connection>& connection) {
    TcpConnection& tcp = *connection->tcp;
    if (connection->pending_accept) {
        const auto listener = connection->listener.lock();
        const TcpState state = tcp.State();
        if (!listener || listener->closed) {
            connection->pending_accept = false;
            tcp.Abort(); // listener is gone
        } else if (state != TcpState::SynReceived) {
            connection->pending_accept = false;
            --listener->half_open;
            connection->listener.reset();
            if (state != TcpState::Closed) {
                listener->accept_queue.push_back(connection);
                listener->readiness->readable.Set(true);
            }
        }
    }
    connection->readiness->readable.Set(tcp.Readable());
    connection->readiness->writable.Set(tcp.Writable());
    if (tcp.State() == TcpState::Closed && connection->released) {
        const auto it = connections_.find(connection->key);
        if (it != connections_.end() && it->second == connection) {
            connections_.erase(it);
        }
    }
}

DatagramSocket::DatagramSocket(std::shared_ptr<Transport> transport)
    : transport_(std::move(transport)), readiness_(std::make_shared<Readiness>()) {
    readiness_->writable.Set(true); // UDP is always writable
}

DatagramSocket::~DatagramSocket() {
    Close();
}

Error DatagramSocket::Bind(u16 vport) {
    std::scoped_lock lock{transport_->mutex_};
    return BindLocked(vport);
}

Error DatagramSocket::BindLocked(u16 vport) {
    if (binding_) {
        return Error::Inval;
    }
    if (vport == 0 && (vport = transport_->AllocateVport(false)) == 0) {
        return Error::AddrNotAvail;
    }
    if (transport_->datagram_bindings_.contains(vport)) {
        return Error::AddrInUse;
    }
    binding_ = std::make_shared<DatagramBinding>();
    binding_->vport = vport;
    binding_->readiness = readiness_;
    binding_->peer = peer_;
    transport_->datagram_bindings_[vport] = binding_;
    return Error::Ok;
}

Error DatagramSocket::SetPeer(const Endpoint& peer, u16 vport) {
    std::scoped_lock lock{transport_->mutex_};
    if (vport == 0) {
        return Error::AddrNotAvail;
    }
    peer_ = std::pair{peer, vport};
    if (binding_) {
        binding_->peer = peer_;
    }
    return Error::Ok;
}

void DatagramSocket::SetProtection(Protection protection) {
    std::scoped_lock lock{transport_->mutex_};
    protection_ = protection;
}

IoResult DatagramSocket::SendTo(std::span<const u8> data, const Endpoint* to, u16 to_vport,
                                Protection extra) {
    std::scoped_lock lock{transport_->mutex_};
    if (!binding_ && BindLocked(0) != Error::Ok) { // implicit bind
        return {0, Error::AddrNotAvail};
    }
    if (to == nullptr) {
        if (!peer_) {
            return {0, Error::DestAddrReq};
        }
        to = &peer_->first;
        to_vport = peer_->second;
    }
    if (to_vport == 0) {
        return {0, Error::AddrNotAvail};
    }
    const Protection protection{protection_.crypto || extra.crypto,
                                protection_.signature || extra.signature};
    const auto packet =
        transport_->codec_->EncodeDatagram(binding_->vport, to_vport, data, *to, protection);
    const Error e = transport_->SendPacket(packet, *to);
    if (e == Error::WouldBlock || e == Error::NoBufs) {
        // PS4 drops instead of returning ENOBUFS
        return {data.size(), Error::Ok};
    }
    return e == Error::Ok ? IoResult{data.size(), Error::Ok} : IoResult{0, e};
}

IoResult DatagramSocket::RecvFrom(std::span<u8> out, bool peek, Endpoint* from, u16* from_vport) {
    std::scoped_lock lock{transport_->mutex_};
    if (!binding_ || binding_->queue.empty()) {
        return {0, Error::WouldBlock};
    }
    auto& packet = binding_->queue.front();
    const size_t n = std::min(out.size(), packet.payload.size()); // rest is discarded
    std::copy_n(packet.payload.begin(), n, out.begin());
    if (from) {
        *from = packet.from;
    }
    if (from_vport) {
        *from_vport = packet.src_vport;
    }
    if (!peek) {
        binding_->bytes -= packet.payload.size();
        binding_->queue.pop_front();
        if (binding_->queue.empty()) {
            readiness_->readable.Set(false);
        }
    }
    return {n, Error::Ok};
}

u32 DatagramSocket::Events() const {
    std::scoped_lock lock{transport_->mutex_};
    return Host::EvOut | (binding_ && !binding_->queue.empty() ? static_cast<u32>(Host::EvIn) : 0u);
}

u16 DatagramSocket::BoundVport() const {
    std::scoped_lock lock{transport_->mutex_};
    return binding_ ? binding_->vport : 0;
}

u16 DatagramSocket::TransportPort() const {
    return transport_->BoundPort();
}

bool DatagramSocket::GetPeer(Endpoint* peer, u16* peer_vport) const {
    std::scoped_lock lock{transport_->mutex_};
    if (!peer_) {
        return false;
    }
    *peer = peer_->first;
    *peer_vport = peer_->second;
    return true;
}

Protection DatagramSocket::GetProtection() const {
    std::scoped_lock lock{transport_->mutex_};
    return protection_;
}

void DatagramSocket::Close() {
    std::scoped_lock lock{transport_->mutex_};
    if (!binding_) {
        return;
    }
    const auto it = transport_->datagram_bindings_.find(binding_->vport);
    if (it != transport_->datagram_bindings_.end() && it->second == binding_) {
        transport_->datagram_bindings_.erase(it);
    }
    binding_.reset();
}

StreamSocket::StreamSocket(std::shared_ptr<Transport> transport,
                           std::shared_ptr<Readiness> readiness)
    : transport_(std::move(transport)),
      readiness_(readiness ? std::move(readiness) : std::make_shared<Readiness>()) {}

StreamSocket::~StreamSocket() {
    Close();
}

void StreamSocket::SetProtection(Protection protection) {
    std::scoped_lock lock{transport_->mutex_};
    protection_ = protection;
}

Error StreamSocket::Bind(u16 vport) {
    std::scoped_lock lock{transport_->mutex_};
    return BindLocked(vport);
}

Error StreamSocket::BindLocked(u16 vport) {
    if (bound_vport_ != 0 || closed_) {
        return Error::Inval;
    }
    if (vport == 0 && (vport = transport_->AllocateVport(true)) == 0) {
        return Error::AddrNotAvail;
    }
    if (transport_->stream_vports_in_use_.contains(vport)) {
        return Error::AddrInUse;
    }
    ++transport_->stream_vports_in_use_[vport];
    bound_vport_ = vport;
    owns_vport_ = true;
    return Error::Ok;
}

Error StreamSocket::Listen(int backlog) {
    std::scoped_lock lock{transport_->mutex_};
    if (connection_ || closed_) {
        return Error::Inval;
    }
    if (bound_vport_ == 0 && BindLocked(0) != Error::Ok) {
        return Error::AddrNotAvail;
    }
    const int clamped = std::clamp(backlog, 1, transport_->config_.max_backlog);
    if (listener_) {
        listener_->backlog = clamped;
        return Error::Ok;
    }
    listener_ = std::make_shared<ListenerState>();
    listener_->vport = bound_vport_;
    listener_->backlog = clamped;
    listener_->protection = protection_;
    listener_->readiness = readiness_;
    transport_->listeners_[bound_vport_] = listener_;
    return Error::Ok;
}

Error StreamSocket::Connect(const Endpoint& peer, u16 peer_vport) {
    std::scoped_lock lock{transport_->mutex_};
    if (listener_ || closed_) {
        return Error::Inval;
    }
    if (connection_) {
        const TcpState state = connection_->tcp->State();
        return state == TcpState::SynSent || state == TcpState::SynReceived ? Error::Already
                                                                            : Error::IsConn;
    }
    if (peer_vport == 0) {
        return Error::AddrNotAvail;
    }
    if (bound_vport_ == 0 && BindLocked(0) != Error::Ok) {
        return Error::AddrNotAvail;
    }
    const ConnectionKey key{peer, peer_vport, bound_vport_};
    if (transport_->connections_.contains(key)) {
        return Error::AddrInUse; // e.g. old connection in TIME-WAIT
    }
    connection_ = transport_->NewConnection(key, protection_, readiness_);
    connection_->released = false;
    connection_->tcp->Connect(Clock::now());
    transport_->Update(connection_);
    transport_->Reschedule(*connection_);
    return Error::InProgress;
}

Error StreamSocket::ConnectResult() const {
    std::scoped_lock lock{transport_->mutex_};
    if (!connection_) {
        return Error::NotConn;
    }
    const TcpConnection& tcp = *connection_->tcp;
    if (tcp.PendingError() != Error::Ok) {
        return tcp.PendingError();
    }
    switch (tcp.State()) {
    case TcpState::SynSent:
    case TcpState::SynReceived:
        return Error::InProgress;
    case TcpState::Closed:
        return Error::NotConn;
    default:
        return Error::Ok;
    }
}

std::shared_ptr<StreamSocket> StreamSocket::Accept(Endpoint* peer, u16* peer_vport, Error* error) {
    std::scoped_lock lock{transport_->mutex_};
    if (!listener_) {
        *error = Error::Inval;
        return nullptr;
    }
    if (listener_->accept_queue.empty()) {
        *error = Error::WouldBlock;
        return nullptr;
    }
    auto connection = std::move(listener_->accept_queue.front());
    listener_->accept_queue.pop_front();
    if (listener_->accept_queue.empty()) {
        readiness_->readable.Set(false);
    }
    connection->released = false;
    std::shared_ptr<StreamSocket> accepted(new StreamSocket(transport_, connection->readiness));
    accepted->protection_ = connection->protection;
    accepted->bound_vport_ = connection->key.local_vport; // listener owns the vport
    accepted->connection_ = connection;
    if (peer) {
        *peer = connection->key.peer;
    }
    if (peer_vport) {
        *peer_vport = connection->key.peer_vport;
    }
    transport_->Update(connection);
    *error = Error::Ok;
    return accepted;
}

IoResult StreamSocket::Send(std::span<const u8> data) {
    std::scoped_lock lock{transport_->mutex_};
    if (!connection_) {
        return {0, Error::NotConn};
    }
    const auto r = connection_->tcp->Send(data, Clock::now());
    transport_->Update(connection_);
    transport_->Reschedule(*connection_);
    return {r.bytes, r.error};
}

IoResult StreamSocket::Recv(std::span<u8> out, bool peek) {
    std::scoped_lock lock{transport_->mutex_};
    if (!connection_) {
        return {0, Error::NotConn};
    }
    if (read_shutdown_) {
        return {0, Error::Ok};
    }
    const auto r = connection_->tcp->Recv(out, peek, Clock::now());
    transport_->Update(connection_);
    return {r.bytes, r.error};
}

Error StreamSocket::Shutdown(int how) {
    std::scoped_lock lock{transport_->mutex_};
    if (!connection_) {
        return Error::NotConn;
    }
    if (how < 0 || how > 2) {
        return Error::Inval;
    }
    if (how != 1) {
        read_shutdown_ = true;
        readiness_->readable.Set(true); // reads return EOF now
    }
    if (how != 0) {
        connection_->tcp->Shutdown(Clock::now());
        transport_->Update(connection_);
        transport_->Reschedule(*connection_);
    }
    return Error::Ok;
}

void StreamSocket::Close() {
    std::scoped_lock lock{transport_->mutex_};
    if (closed_) {
        return;
    }
    closed_ = true;
    if (listener_) {
        listener_->closed = true;
        const auto it = transport_->listeners_.find(listener_->vport);
        if (it != transport_->listeners_.end() && it->second == listener_) {
            transport_->listeners_.erase(it);
        }
        for (const auto& pending : listener_->accept_queue) {
            pending->tcp->Abort(); // reset unaccepted, like BSD
            transport_->Update(pending);
        }
        listener_->accept_queue.clear();
        listener_.reset();
    }
    if (connection_) {
        connection_->released = true;
        connection_->tcp->Close(Clock::now()); // FIN, or RST if data is unread
        transport_->Update(connection_);
        transport_->Reschedule(*connection_);
        connection_.reset();
    }
    if (owns_vport_) {
        auto& count = transport_->stream_vports_in_use_[bound_vport_];
        if (--count <= 0) {
            transport_->stream_vports_in_use_.erase(bound_vport_);
        }
        owns_vport_ = false;
    }
}

void StreamSocket::Abort() {
    std::scoped_lock lock{transport_->mutex_};
    if (connection_) {
        connection_->tcp->Abort();
        transport_->Update(connection_);
    }
}

u32 StreamSocket::Events() const {
    std::scoped_lock lock{transport_->mutex_};
    if (listener_) {
        return listener_->accept_queue.empty() ? 0u : static_cast<u32>(Host::EvIn);
    }
    if (!connection_) {
        return 0;
    }
    const TcpConnection& tcp = *connection_->tcp;
    u32 events = 0;
    if (tcp.Readable() || read_shutdown_) {
        events |= Host::EvIn;
    }
    if (tcp.Writable()) {
        events |= Host::EvOut;
    }
    if (tcp.PendingError() != Error::Ok) {
        events |= Host::EvErr;
    }
    if (tcp.State() == TcpState::Closed || tcp.State() == TcpState::TimeWait || tcp.ReceivedFin()) {
        events |= Host::EvHup; // TODO: peer FIN alone is RDHUP on Linux, not HUP
    }
    return events;
}

std::optional<TcpState> StreamSocket::State() const {
    std::scoped_lock lock{transport_->mutex_};
    return connection_ ? std::optional{connection_->tcp->State()} : std::nullopt;
}

bool StreamSocket::GetPeer(Endpoint* peer, u16* peer_vport) const {
    std::scoped_lock lock{transport_->mutex_};
    if (!connection_) {
        return false;
    }
    *peer = connection_->key.peer;
    *peer_vport = connection_->key.peer_vport;
    return true;
}

u16 StreamSocket::BoundVport() const {
    std::scoped_lock lock{transport_->mutex_};
    return bound_vport_;
}

u16 StreamSocket::TransportPort() const {
    return transport_->BoundPort();
}

Protection StreamSocket::GetProtection() const {
    std::scoped_lock lock{transport_->mutex_};
    return protection_;
}

} // namespace Core::Net::P2P
