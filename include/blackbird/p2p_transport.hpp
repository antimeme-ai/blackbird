#pragma once

#include "blackbird/foundation.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct BbP2pEndpoint;

namespace blackbird {

inline constexpr std::size_t kP2pPubkeySize = 32U;
inline constexpr std::size_t kP2pSecretKeySize = 32U;
inline constexpr std::size_t kP2pMaxControlFrameBytes = 64U * 1024U;
inline constexpr std::size_t kP2pMaxCausalFrameBytes = 4U * 1024U * 1024U;
inline constexpr std::size_t kP2pMaxEphemeralFrameBytes = 1200U;
inline constexpr std::size_t kP2pMaxRelayUrlBytes = 100U;
inline constexpr std::size_t kP2pMaxDirectAddrs = 8U;
inline constexpr std::size_t kP2pMaxAllowedPeers = 1024U;
inline constexpr std::string_view kP2pAlpn = "blackbird-mp/1";

using P2pPubkey = std::array<std::uint8_t, kP2pPubkeySize>;
using P2pSecretKey = std::array<std::uint8_t, kP2pSecretKeySize>;

enum class P2pRelayPolicy : std::uint8_t {
  allow_relays = 0,
  force_relays = 1,
  no_relays = 2,
};

enum class P2pLane : std::uint8_t {
  control = 0,
  causal = 1,
  ephemeral = 2,
};

enum class P2pEventKind : std::uint8_t {
  none = 0,
  peer_connected = 1,
  peer_disconnected = 2,
  frame_received = 3,
};

// Distinct non-mutually-convertible wrappers prevent parameter swapping while
// allowing callers to pass raw device IDs / relay policies ergonomically.
struct LocalDeviceId {
  std::uint64_t value = 0;
  constexpr LocalDeviceId(std::uint64_t id) noexcept : value(id) {}
};

struct PeerDeviceId {
  std::uint64_t value = 0;
  constexpr PeerDeviceId(std::uint64_t id) noexcept : value(id) {}
};

struct LocalRelayPolicy {
  P2pRelayPolicy value = P2pRelayPolicy::allow_relays;
  constexpr LocalRelayPolicy(P2pRelayPolicy policy) noexcept : value(policy) {}
};

struct RemoteRelayPolicy {
  P2pRelayPolicy value = P2pRelayPolicy::allow_relays;
  constexpr RemoteRelayPolicy(P2pRelayPolicy policy) noexcept : value(policy) {}
};

// Deterministic dial role: peer with strictly smaller positive device_id dials first.
constexpr bool should_dial_peer(LocalDeviceId my_device_id,
                                PeerDeviceId peer_device_id) noexcept {
  return my_device_id.value != 0 && peer_device_id.value != 0 &&
         my_device_id.value < peer_device_id.value;
}

// Non-downgradeable relay policy compatibility:
// - force_relays refuses no_relays (prevents direct-UDP IP leaks).
// - allow_relays and no_relays refuse force_relays (prevents downgrading a
//   force_relays party).
constexpr bool relay_policy_compatible(LocalRelayPolicy local,
                                       RemoteRelayPolicy remote) noexcept {
  if (local.value == P2pRelayPolicy::force_relays &&
      remote.value == P2pRelayPolicy::no_relays) {
    return false;
  }
  if (remote.value == P2pRelayPolicy::force_relays &&
      local.value != P2pRelayPolicy::force_relays) {
    return false;
  }
  return true;
}

bool p2p_iroh_compiled_in() noexcept;
std::size_t p2p_lane_max_frame_bytes(P2pLane lane) noexcept;
std::string_view p2p_relay_policy_name(P2pRelayPolicy policy) noexcept;
std::string_view p2p_lane_name(P2pLane lane) noexcept;

struct P2pDirectAddr {
  std::uint8_t family = 0; // 4 = IPv4, 6 = IPv6
  std::array<std::uint8_t, 16> ip{};
  std::uint16_t port = 0;

  static constexpr P2pDirectAddr ipv4(std::array<std::uint8_t, 4> octets,
                                      std::uint16_t udp_port) noexcept {
    P2pDirectAddr addr{};
    addr.family = 4;
    addr.ip[0] = octets[0];
    addr.ip[1] = octets[1];
    addr.ip[2] = octets[2];
    addr.ip[3] = octets[3];
    addr.port = udp_port;
    return addr;
  }

  static constexpr P2pDirectAddr ipv6(std::array<std::uint8_t, 16> octets,
                                      std::uint16_t udp_port) noexcept {
    P2pDirectAddr addr{};
    addr.family = 6;
    addr.ip = octets;
    addr.port = udp_port;
    return addr;
  }

  bool operator==(const P2pDirectAddr &) const = default;
};

struct P2pEndpointConfig {
  P2pRelayPolicy relay_policy = P2pRelayPolicy::allow_relays;
  std::optional<P2pSecretKey> secret_key;
  std::string relay_url;
};

struct P2pPeerTarget {
  P2pPubkey pubkey{};
  P2pRelayPolicy remote_relay_policy = P2pRelayPolicy::allow_relays;
  std::string relay_url;
  std::vector<P2pDirectAddr> direct_addrs;
  std::uint32_t connect_timeout_ms = 10000;
};

struct P2pEvent {
  P2pEventKind kind = P2pEventKind::none;
  P2pLane lane = P2pLane::control;
  P2pPubkey peer_pubkey{};
  std::vector<std::uint8_t> payload;
  std::uint32_t reason_code = 0;

  bool operator==(const P2pEvent &) const = default;
};

// Zero-leak RAII wrapper over the narrow panic-safe `blackbird-p2p` (iroh v1.5.0)
// QUIC + TLS 1.3 Mutual RPK staticlib.
class P2pEndpoint {
public:
  static Result<P2pEndpoint> create(const P2pEndpointConfig &config = {});

  P2pEndpoint() = default;
  P2pEndpoint(const P2pEndpoint &) = delete;
  P2pEndpoint &operator=(const P2pEndpoint &) = delete;
  P2pEndpoint(P2pEndpoint &&other) noexcept;
  P2pEndpoint &operator=(P2pEndpoint &&other) noexcept;
  ~P2pEndpoint();

  bool valid() const noexcept { return handle_ != nullptr; }
  P2pRelayPolicy relay_policy() const noexcept { return relay_policy_; }

  Result<P2pPubkey> local_pubkey() const;
  Result<std::vector<P2pDirectAddr>> local_direct_addrs() const;

  Result<void> set_allowed_peers(std::span<const P2pPubkey> peers);
  Result<void> revoke_peer(const P2pPubkey &peer_pubkey);
  Result<void> connect_peer(const P2pPeerTarget &target);

  Result<void> send_frame(const P2pPubkey &peer_pubkey, P2pLane lane,
                          std::span<const std::uint8_t> payload);
  Result<void> send_frame(const P2pPubkey &peer_pubkey, P2pLane lane,
                          std::string_view payload);

  // Returns std::nullopt on timeout without error; returns populated P2pEvent on
  // connect, disconnect, or received frame on Lane 0/1/2.
  Result<std::optional<P2pEvent>> poll_event(std::uint32_t timeout_ms = 0);

  void close() noexcept;

private:
  P2pEndpoint(BbP2pEndpoint *handle, P2pRelayPolicy relay_policy) noexcept;

  BbP2pEndpoint *handle_ = nullptr;
  P2pRelayPolicy relay_policy_ = P2pRelayPolicy::allow_relays;
};

} // namespace blackbird
