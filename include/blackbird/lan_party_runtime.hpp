#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/lan_mdns.hpp"
#include "blackbird/lan_party_protocol.hpp"
#include "blackbird/p2p_party_session.hpp"
#include "blackbird/p2p_transport.hpp"
#include "blackbird/peer_identity.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird::lan {

// ---------------------------------------------------------------------------
// Constants & runtime error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

inline constexpr std::size_t kLanRuntimeMaxQueuedEvents = 4096U;
inline constexpr std::size_t kLanRuntimeMaxEventsPerPump = 64U;
inline constexpr std::uint32_t kLanPendingHandshakeTimeoutSec = 15U;
inline constexpr std::string_view kLanDefaultRoomScope = "lan/party";

enum class LanRuntimeError : std::int64_t {
  none = 0,
  invalid_config = 2600,
  invalid_timeout = 2601,
  invalid_direct_target = 2602,
  not_running = 2603,
  not_connected = 2604,
  peer_rejected = 2605,
  peer_not_found = 2606,
  lobby_full = 2607,
  lobby_locked = 2608,
  timed_out = 2609,
  handshake_failed = 2610,
  trust_store_failed = 2611,
  p2p_unavailable = 2612,
  self_target_disallowed = 2613,
};

constexpr LanRuntimeError lan_runtime_error_of(const Error &error) noexcept {
  return static_cast<LanRuntimeError>(error.detail);
}

std::string_view lan_runtime_error_name(LanRuntimeError detail) noexcept;

// ---------------------------------------------------------------------------
// Session states, events, trust verification, and distinct parameter wrappers
// ---------------------------------------------------------------------------

enum class LanSessionState : std::uint8_t {
  stopped = 0,
  hosting = 1,
  connecting = 2,
  handshaking = 3,
  connected = 4,
  timed_out = 5,
  locked_out = 6,
  rejected = 7,
  disconnected = 8,
};

std::string_view lan_session_state_name(LanSessionState state) noexcept;

enum class LanEventKind : std::uint8_t {
  member_joined = 1,
  member_left = 2,
  member_kicked = 3,
  member_rejected = 4,
  roster_updated = 5,
  chat_received = 6,
  pulse_received = 7,
  lobby_locked = 8,
  lobby_timed_out = 9,
  lobby_pin_locked_out = 10,
  connected = 11,
  disconnected = 12,
  welcome_rejected = 13,
  frame_dropped = 14,
};

std::string_view lan_event_kind_name(LanEventKind kind) noexcept;

// Distinct non-mutually-convertible wrapper for chat target selector to prevent
// swappable-parameter ambiguity next to the message body.
struct LanChatTarget {
  std::string value;

  LanChatTarget() : value("@all") {}
  LanChatTarget(std::string target) : value(std::move(target)) {}
  LanChatTarget(std::string_view target) : value(target) {}
  LanChatTarget(const char *target) : value(target != nullptr ? target : "@all") {}
};

// Mandate #5 Safety Number trust verification prompt.
struct LanPeerTrustPrompt {
  std::string display_name;
  std::uint64_t account_id = 0U;
  mp::Ed25519PubKey pubkey{};
  std::string safety_number;
  std::string source_addr;
  bool is_host = false;

  bool operator==(const LanPeerTrustPrompt &) const = default;
};

using LanPeerTrustCallback = std::function<bool(const LanPeerTrustPrompt &prompt)>;

struct LanEvent {
  LanEventKind kind = LanEventKind::frame_dropped;
  mp::Ed25519PubKey peer_pubkey{};
  std::string sender_name;
  std::uint64_t sender_account_id = 0U;
  std::string safety_number;
  std::optional<LanMemberInfo> member = std::nullopt;
  std::vector<LanMemberInfo> roster;
  std::uint64_t roster_epoch = 0U;
  bool lobby_locked = false;
  std::optional<P2pPartyChatMessage> chat = std::nullopt;
  std::optional<P2pPartyEphemeralPulse> pulse = std::nullopt;
  std::string reason;
  std::uint32_t reason_code = 0U;
  std::optional<Error> error = std::nullopt;

  bool operator==(const LanEvent &) const = default;
};

// Formats a 32-byte raw Ed25519 public key into canonical OpenSSH
// "ssh-ed25519 <base64>" syntax for pinning in KnownPeersStore.
Result<std::string> lan_pubkey_to_ssh_ed25519(const mp::Ed25519PubKey &pubkey);

// ---------------------------------------------------------------------------
// Discovery scanner (enforces policy kill-switch, local auth, and <= 60s cap)
// ---------------------------------------------------------------------------

struct DiscoveredLanLobbyInfo {
  DiscoveredLanLobby lobby;
  std::string safety_number;
  std::vector<std::string> direct_targets;

  bool operator==(const DiscoveredLanLobbyInfo &) const = default;
};

using LanScanStopPredicate =
    std::function<bool(const std::vector<DiscoveredLanLobbyInfo> &lobbies)>;

struct LanScanConfig {
  std::uint32_t scan_timeout_sec = kDefaultLanScanTimeoutSec;
  std::uint32_t poll_step_ms = 50U;
  std::uint32_t query_interval_ms = 1000U;
  bool require_local_auth = false;
  LanPolicyPaths policy_paths{};
  EnvLookupFn env_lookup{};
  LocalAuthOptions local_auth_options{};
  LanMdnsSocketConfig mdns_socket_cfg = LanMdnsSocketConfig::production_multicast();
  LanScanStopPredicate stop_when{};
  std::function<void()> on_poll_tick{};
};

Result<std::vector<DiscoveredLanLobbyInfo>>
scan_lan_lobbies(const LanScanConfig &cfg = {});

// ---------------------------------------------------------------------------
// LanPartyHost (1998 LAN Lobby Coordinator over iroh no_relays + mDNS)
// ---------------------------------------------------------------------------

struct LanHostConfig {
  LanIdentity identity;
  std::string lobby_name;
  // Cleansed inside start() into CleansedPin; leave empty for PIN-less lobbies
  // when policy allows require_pin = false.
  std::string pin;
  bool require_pin = false;
  bool require_local_auth = false;
  std::uint32_t idle_timeout_sec = kDefaultLanIdleTimeoutSec;
  std::uint8_t max_members = static_cast<std::uint8_t>(kLanMaxMembers);
  LanPolicyPaths policy_paths{};
  EnvLookupFn env_lookup{};
  LocalAuthOptions local_auth_options{};
  LanMdnsSocketConfig mdns_socket_cfg = LanMdnsSocketConfig::production_multicast();
  bool enable_mdns = true;
  LanPeerTrustCallback trust_callback{};
  std::optional<std::filesystem::path> known_peers_path = std::nullopt;
  bool pin_approved_peers = true;
  LanPinRateLimitConfig pin_rate_limit{};
  std::string room_scope{kLanDefaultRoomScope};
  // Optional 16-char lowercase hex party ID (random 8B via RAND_bytes if empty).
  std::string lan_party_id_override;
};

class LanPartyHost {
public:
  static Result<LanPartyHost> start(LanHostConfig cfg);

  LanPartyHost() noexcept = default;
  LanPartyHost(const LanPartyHost &) = delete;
  LanPartyHost &operator=(const LanPartyHost &) = delete;
  LanPartyHost(LanPartyHost &&other) noexcept;
  LanPartyHost &operator=(LanPartyHost &&other) noexcept;
  ~LanPartyHost() noexcept;

  // Pumps mDNS advertiser (including idle timeout auto-shutoff) and iroh P2P
  // events. Returns the number of newly queued LanEvent entries.
  Result<std::size_t> pump_once(
      std::uint32_t timeout_ms = 0U,
      std::optional<std::chrono::steady_clock::time_point> now_override = std::nullopt);

  Result<void> send_chat(std::string_view body, const LanChatTarget &target = {});
  Result<void> send_pulse(P2pPartyActivityState activity_state,
                          std::string_view status = "");
  Result<void> lock_lobby();
  Result<void> kick_peer(const mp::Ed25519PubKey &pubkey);

  std::optional<LanEvent> pop_event();
  std::vector<LanEvent> drain_events();
  std::size_t pending_event_count() const noexcept { return events_.size(); }

  void stop() noexcept;

  // Inspection accessors
  LanSessionState state() const noexcept { return state_; }
  bool active() const noexcept { return state_ == LanSessionState::hosting; }
  bool locked() const noexcept { return locked_; }
  bool pin_required() const noexcept { return pin_required_; }
  std::uint32_t effective_idle_timeout_sec() const noexcept {
    return effective_idle_timeout_sec_;
  }
  const std::string &lan_party_id() const noexcept { return lan_party_id_; }
  const std::string &lobby_name() const noexcept { return lobby_name_; }
  const mp::Ed25519PubKey &host_pubkey() const noexcept { return identity_.public_key; }
  const std::string &safety_number() const noexcept { return identity_.safety_number; }
  std::uint16_t service_port() const noexcept { return service_port_; }
  std::uint16_t mdns_bound_port() const noexcept { return advertiser_.bound_port(); }
  const std::vector<P2pDirectAddr> &direct_addrs() const noexcept {
    return direct_addrs_;
  }
  const std::vector<std::string> &direct_targets() const noexcept {
    return direct_targets_;
  }
  std::uint64_t roster_epoch() const noexcept { return roster_epoch_; }
  const std::vector<LanMemberInfo> &members() const noexcept { return members_; }
  std::size_t pending_peer_count() const noexcept { return pending_peers_.size(); }
  const LanPinRateLimiter &pin_rate_limiter() const noexcept { return pin_limiter_; }

private:
  struct PendingPeer {
    LanNonce host_nonce{};
    std::chrono::steady_clock::time_point connected_at{};
  };

  void push_event(LanEvent event);
  void close_resources_noexcept() noexcept;
  void transition_timed_out() noexcept;
  void transition_pin_locked_out() noexcept;
  void reject_pending_peer(const mp::Ed25519PubKey &pubkey, std::string_view reason);
  void broadcast_roster_best_effort();
  bool verify_or_pin_peer(const LanPeerTrustPrompt &prompt);
  const LanMemberInfo *find_member(const mp::Ed25519PubKey &pubkey) const noexcept;
  void handle_transport_event(const P2pEvent &ev,
                              std::chrono::steady_clock::time_point now);
  void handle_pending_control_frame(const P2pEvent &ev);
  void handle_admitted_frame(const P2pEvent &ev, const LanMemberInfo &member);

  LanSessionState state_ = LanSessionState::stopped;
  LanIdentity identity_;
  std::string lan_party_id_;
  std::string lobby_name_;
  std::string room_scope_{kLanDefaultRoomScope};
  CleansedPin pin_;
  bool pin_required_ = false;
  bool locked_ = false;
  bool has_peer_joined_ = false;
  std::uint8_t max_members_ = static_cast<std::uint8_t>(kLanMaxMembers);
  std::uint32_t effective_idle_timeout_sec_ = kDefaultLanIdleTimeoutSec;
  std::uint16_t service_port_ = 0U;
  std::chrono::steady_clock::time_point started_at_{};

  P2pEndpoint endpoint_;
  LanMdnsAdvertiser advertiser_;
  std::vector<P2pDirectAddr> direct_addrs_;
  std::vector<std::string> direct_targets_;

  LanPeerTrustCallback trust_callback_;
  std::optional<KnownPeersStore> known_peers_;
  bool pin_approved_peers_ = true;
  LanPinRateLimiter pin_limiter_;

  std::uint64_t roster_epoch_ = 0U;
  std::vector<LanMemberInfo> members_;
  std::map<mp::Ed25519PubKey, PendingPeer> pending_peers_;
  std::deque<LanEvent> events_;
};

// ---------------------------------------------------------------------------
// LanPartyClient (Joiner — mDNS Lobby OR Quake-Style Direct ip:port)
// ---------------------------------------------------------------------------

struct LanClientConfig {
  LanIdentity identity;
  mp::Ed25519PubKey host_pubkey{};
  std::vector<P2pDirectAddr> host_addrs;
  std::vector<std::string> direct_targets;
  std::string expected_lan_party_id;
  std::string expected_host_name;
  // Cleansed inside join() into CleansedPin.
  std::string pin;
  bool require_local_auth = false;
  std::uint32_t connect_timeout_ms = kP2pPartyDefaultConnectTimeoutMs;
  LanPolicyPaths policy_paths{};
  EnvLookupFn env_lookup{};
  LocalAuthOptions local_auth_options{};
  LanPeerTrustCallback trust_callback{};
  std::optional<std::filesystem::path> known_peers_path = std::nullopt;
  bool pin_approved_peers = true;
  std::string room_scope{kLanDefaultRoomScope};
};

class LanPartyClient {
public:
  static Result<LanPartyClient> join(LanClientConfig cfg);

  LanPartyClient() noexcept = default;
  LanPartyClient(const LanPartyClient &) = delete;
  LanPartyClient &operator=(const LanPartyClient &) = delete;
  LanPartyClient(LanPartyClient &&other) noexcept;
  LanPartyClient &operator=(LanPartyClient &&other) noexcept;
  ~LanPartyClient() noexcept;

  Result<std::size_t> pump_once(std::uint32_t timeout_ms = 0U);

  Result<void> send_chat(std::string_view body, const LanChatTarget &target = {});
  Result<void> send_pulse(P2pPartyActivityState activity_state,
                          std::string_view status = "");

  std::optional<LanEvent> pop_event();
  std::vector<LanEvent> drain_events();
  std::size_t pending_event_count() const noexcept { return events_.size(); }

  void stop() noexcept;

  // Inspection accessors
  LanSessionState state() const noexcept { return state_; }
  bool active() const noexcept {
    return state_ == LanSessionState::connecting ||
           state_ == LanSessionState::handshaking ||
           state_ == LanSessionState::connected;
  }
  bool connected() const noexcept { return state_ == LanSessionState::connected; }
  bool lobby_locked() const noexcept { return lobby_locked_; }
  const std::string &lan_party_id() const noexcept { return lan_party_id_; }
  const std::string &lobby_name() const noexcept { return lobby_name_; }
  const std::string &host_name() const noexcept { return host_name_; }
  const mp::Ed25519PubKey &host_pubkey() const noexcept { return host_pubkey_; }
  const std::string &host_safety_number() const noexcept { return host_safety_number_; }
  const std::string &last_rejection_reason() const noexcept {
    return last_rejection_reason_;
  }
  std::uint64_t roster_epoch() const noexcept { return roster_epoch_; }
  const std::vector<LanMemberInfo> &members() const noexcept { return members_; }

private:
  void push_event(LanEvent event);
  void close_resources_noexcept() noexcept;
  void fail_rejected(std::string_view reason);
  bool verify_or_pin_host(std::string_view display_name, std::uint64_t account_id);
  void handle_transport_event(const P2pEvent &ev);
  void handle_control_frame(const P2pEvent &ev);
  void handle_hello(const LanHelloMessage &hello);
  void handle_welcome(const LanWelcomeMessage &welcome);
  void handle_roster(const LanRosterMessage &roster);

  LanSessionState state_ = LanSessionState::stopped;
  LanIdentity identity_;
  mp::Ed25519PubKey host_pubkey_{};
  std::string host_safety_number_;
  std::string source_addr_;
  std::string expected_lan_party_id_;
  std::string expected_host_name_;
  std::string lan_party_id_;
  std::string lobby_name_;
  std::string host_name_;
  std::uint64_t host_account_id_ = 0U;
  std::string room_scope_{kLanDefaultRoomScope};
  CleansedPin pin_;
  bool policy_require_pin_ = false;
  bool pin_required_ = false;
  bool join_sent_ = false;
  bool lobby_locked_ = false;
  std::string last_rejection_reason_;

  P2pEndpoint endpoint_;
  LanPeerTrustCallback trust_callback_;
  std::optional<KnownPeersStore> known_peers_;
  bool pin_approved_peers_ = true;

  std::uint64_t roster_epoch_ = 0U;
  std::vector<LanMemberInfo> members_;
  std::deque<LanEvent> events_;
};

} // namespace blackbird::lan
