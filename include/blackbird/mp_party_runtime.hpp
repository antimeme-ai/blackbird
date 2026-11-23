#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/mp_client.hpp"
#include "blackbird/mp_protocol.hpp"
#include "blackbird/p2p_party_session.hpp"
#include "blackbird/p2p_transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

// ---------------------------------------------------------------------------
// Constants & error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t kMpRuntimeMinPingIntervalMs = 5000U;
inline constexpr std::uint32_t kMpRuntimeMaxPingIntervalMs = 60000U;
inline constexpr std::uint32_t kMpRuntimeDefaultPingIntervalMs = 20000U;
inline constexpr std::uint32_t kMpRuntimeDefaultMaxReconnectAttempts = 8U;
inline constexpr std::uint32_t kMpRuntimeDefaultReconnectBaseMs = 250U;
inline constexpr std::uint32_t kMpRuntimeDefaultReconnectMaxMs = 15000U;
inline constexpr std::uint32_t kMpRuntimeDefaultConnectTimeoutMs =
    kP2pPartyDefaultConnectTimeoutMs;
inline constexpr std::size_t kMpRuntimeMaxQueuedEvents = 4096U;
inline constexpr std::uint16_t kMpWsCloseDeviceRevoked = 4401U;
inline constexpr std::uint16_t kMpWsCloseKickedOrBanned = 4403U;

enum class MpPartyRuntimeError : std::int64_t {
  none = 0,
  invalid_config = 2000,
  missing_identity = 2001,
  runtime_terminated = 2002,
  control_disconnected = 2003,
  reconnect_exhausted = 2004,
  p2p_unavailable = 2005,
  unexpected_opcode = 2006,
  endpoint_build_failed = 2007,
};

constexpr MpPartyRuntimeError mp_party_runtime_error_of(const Error &error) noexcept {
  return static_cast<MpPartyRuntimeError>(error.detail);
}

std::string_view mp_party_runtime_error_name(MpPartyRuntimeError detail) noexcept;

// ---------------------------------------------------------------------------
// Runtime state, configuration, and typed event queue entries
// ---------------------------------------------------------------------------

enum class MpRuntimeState : std::uint8_t {
  attaching = 0,
  connected = 1,
  reconnecting = 2,
  disbanded = 3,
  terminated = 4,
};

std::string_view mp_runtime_state_name(MpRuntimeState state) noexcept;

enum class MpRuntimeEventKind : std::uint8_t {
  hello_acked = 1,
  snapshot_applied = 2,
  member_joined = 3,
  member_updated = 4,
  member_left = 5,
  leader_changed = 6,
  party_disbanded = 7,
  kicked_or_revoked = 8,
  control_disconnected = 9,
  control_reconnected = 10,
  control_error = 11,
  join_request_received = 12,
  peer_connected = 13,
  peer_disconnected = 14,
  chat_received = 15,
  bridge_envelope_received = 16,
  control_notice_received = 17,
  ephemeral_pulse_received = 18,
  peer_evicted = 19,
  frame_dropped = 20,
};

std::string_view mp_runtime_event_kind_name(MpRuntimeEventKind kind) noexcept;

struct MpRuntimeEvent {
  MpRuntimeEventKind kind = MpRuntimeEventKind::frame_dropped;

  // Control-plane fields.
  std::optional<mp::SessionId> session_id = std::nullopt;
  std::uint64_t party_epoch = 0U;
  std::optional<P2pPartySnapshotResult> snapshot_result = std::nullopt;
  std::optional<mp::DeviceId> device_id = std::nullopt;
  std::optional<mp::AccountId> account_id = std::nullopt;
  std::optional<mp::MemberLeaveReason> leave_reason = std::nullopt;
  std::optional<mp::PartyLeaderChangeReason> leader_change_reason = std::nullopt;
  std::optional<mp::PartyDisbandReason> disband_reason = std::nullopt;
  std::optional<mp::ErrorMessage> server_error = std::nullopt;
  std::optional<mp::PartyJoinRequestEventMessage> join_request = std::nullopt;
  std::uint16_t ws_close_code = 0U;

  // P2P data-plane fields (sender_* are attributed EXCLUSIVELY from the
  // authenticated TLS 1.3 Mutual RPK peer_pubkey in the CWT-verified roster).
  P2pLane lane = P2pLane::control;
  P2pPubkey peer_pubkey{};
  std::optional<mp::DeviceId> sender_device_id = std::nullopt;
  std::optional<mp::AccountId> sender_account_id = std::nullopt;
  std::optional<P2pPartyChatMessage> chat = std::nullopt;
  std::optional<P2pPartyBridgeEnvelope> bridge_envelope = std::nullopt;
  std::optional<P2pPartyControlNotice> control_notice = std::nullopt;
  std::optional<P2pPartyEphemeralPulse> ephemeral_pulse = std::nullopt;
  std::uint32_t reason_code = 0U;
  std::optional<Error> error = std::nullopt;

  bool operator==(const MpRuntimeEvent &) const = default;
};

struct MpPartyRuntimeConfig {
  mp::MpClientConfig client_config;
  mp::MpIdentityState identity;
  mp::PartyId party_id;
  mp::RelayPolicy local_relay_policy = mp::RelayPolicy::allow_relays;
  std::optional<std::string> relay_url = std::nullopt;
  std::int64_t max_lease_ttl_s = kP2pPartyDefaultMaxLeaseTtlSecs;
  std::uint32_t max_reconnect_attempts = kMpRuntimeDefaultMaxReconnectAttempts;
  std::uint32_t reconnect_base_ms = kMpRuntimeDefaultReconnectBaseMs;
  std::uint32_t reconnect_max_ms = kMpRuntimeDefaultReconnectMaxMs;
  std::uint32_t p2p_connect_timeout_ms = kMpRuntimeDefaultConnectTimeoutMs;
  // Explicitly opt-in for local loopback tests under RelayPolicy::no_relays only.
  // Production runtimes must keep this false so RFC1918/loopback filtering stays
  // strictly enforced.
  bool allow_loopback_direct_addrs = false;
};

// ---------------------------------------------------------------------------
// Live Control-Plane WS <-> iroh P2P Party Runtime
// ---------------------------------------------------------------------------

class MpPartyRuntime {
public:
  static Result<MpPartyRuntime> attach(MpPartyRuntimeConfig config);

  MpPartyRuntime(const MpPartyRuntime &) = delete;
  MpPartyRuntime &operator=(const MpPartyRuntime &) = delete;
  MpPartyRuntime(MpPartyRuntime &&other) noexcept;
  MpPartyRuntime &operator=(MpPartyRuntime &&other) noexcept;
  ~MpPartyRuntime();

  // Step-driven non-blocking / bounded-timeout event pump.
  // Returns the number of newly queued MpRuntimeEvent entries during this pump.
  Result<std::size_t>
  pump_once(std::uint32_t timeout_ms,
            std::optional<std::int64_t> now_s_override = std::nullopt);

  // Event queue inspection and draining.
  std::optional<MpRuntimeEvent> pop_event();
  std::vector<MpRuntimeEvent> drain_events();
  std::size_t pending_event_count() const noexcept { return events_.size(); }
  bool has_pending_events() const noexcept { return !events_.empty(); }

  // Outbound P2P data-plane senders (fail closed once disbanded/terminated).
  Result<P2pPartyBroadcastResult> broadcast_chat(const P2pPartyChatMessage &message);
  Result<void> send_chat_to(mp::DeviceId device_id, const P2pPartyChatMessage &message);

  Result<P2pPartyBroadcastResult>
  broadcast_bridge_envelope(const P2pPartyBridgeEnvelope &envelope);
  Result<void> send_bridge_envelope_to(mp::DeviceId device_id,
                                       const P2pPartyBridgeEnvelope &envelope);

  Result<P2pPartyBroadcastResult>
  broadcast_control_notice(const P2pPartyControlNotice &notice);
  Result<void> send_control_notice_to(mp::DeviceId device_id,
                                      const P2pPartyControlNotice &notice);

  Result<P2pPartyBroadcastResult>
  broadcast_ephemeral_pulse(const P2pPartyEphemeralPulse &pulse);
  Result<void> send_ephemeral_pulse_to(mp::DeviceId device_id,
                                       const P2pPartyEphemeralPulse &pulse);

  // Outbound control-plane updates.
  Result<void> send_endpoint_update(const mp::EndpointDescriptor &endpoint);
  Result<void> send_endpoint_update();
  Result<void> send_heartbeat_ping();

  // Clean shutdown (idempotent, noexcept): closes WS cleanly (1000) and revokes
  // all active P2P peers before destroying the P2pEndpoint.
  void shutdown() noexcept;

  // Read-only state & roster accessors.
  MpRuntimeState state() const noexcept { return state_; }
  std::vector<P2pPartyPeer> roster() const { return session_.peers(); }
  std::optional<P2pPartyPeer> find_peer(mp::DeviceId device_id) const {
    return session_.find_peer(device_id);
  }
  std::size_t peer_count() const noexcept { return session_.peer_count(); }
  mp::PartyId party_id() const noexcept { return config_.party_id; }
  std::uint64_t party_epoch() const noexcept { return session_.party_epoch(); }
  std::optional<mp::SessionId> session_id() const noexcept { return session_id_; }
  std::optional<mp::AccountId> leader_account_id() const noexcept {
    return session_.leader_account_id();
  }
  std::optional<mp::DeviceId> leader_device_id() const noexcept {
    return session_.leader_device_id();
  }
  std::optional<P2pPubkey> local_pubkey() const noexcept {
    return session_.local_pubkey();
  }
  Result<mp::EndpointDescriptor> local_endpoint_descriptor() const;
  bool has_p2p_endpoint() const noexcept { return session_.has_endpoint(); }
  bool is_control_connected() const noexcept {
    return !is_terminated() && ws_.has_value() && ws_->is_open();
  }
  bool is_terminated() const noexcept {
    return state_ == MpRuntimeState::disbanded || state_ == MpRuntimeState::terminated;
  }
  std::uint32_t ping_interval_ms() const noexcept { return ping_interval_ms_; }
  std::int64_t clock_skew_seconds() const noexcept { return clock_skew_s_; }
  std::uint64_t last_pong_ms() const noexcept { return last_pong_ms_; }
  std::uint32_t reconnect_attempts() const noexcept { return reconnect_attempts_; }
  const P2pPartySession &session() const noexcept { return session_; }
  const MpPartyRuntimeConfig &config() const noexcept { return config_; }

private:
  using SteadyClock = std::chrono::steady_clock;

  struct HandleContext {
    std::int64_t now_s = 0;
    SteadyClock::time_point steady_now{};
    bool has_override_now = false;
  };

  MpPartyRuntime(MpPartyRuntimeConfig config, mp::MpControlClient control_client,
                 mp::MpControlSocket ws, P2pPartySession session) noexcept;

  std::int64_t
  compute_effective_now_s(std::optional<std::int64_t> now_s_override) noexcept;

  void push_event(MpRuntimeEvent event);
  Result<void> ensure_operational() const;
  void handle_ws_event(const mp::MpWsEvent &event, const HandleContext &ctx);
  void handle_mp1_message(const mp::Mp1Message &message, const HandleContext &ctx);
  void handle_transient_ws_disconnect(std::uint16_t close_code,
                                      std::optional<Error> err,
                                      SteadyClock::time_point steady_now);
  void handle_hard_teardown(std::uint16_t close_code);
  void teardown_p2p_session(mp::MemberLeaveReason reason) noexcept;
  void maybe_attempt_reconnect(SteadyClock::time_point steady_now);
  void maybe_send_heartbeat_ping(const HandleContext &ctx,
                                 std::optional<std::int64_t> now_s_override);
  void maybe_retry_pending_dials(SteadyClock::time_point steady_now);
  void publish_local_endpoint_if_changed();
  void translate_and_push_p2p_event(P2pPartyEvent &&p2p_ev);
  bool has_pending_dial_peers() const noexcept;
  std::uint32_t
  compute_reconnect_backoff_ms(std::uint32_t attempt_index) const noexcept;

  MpPartyRuntimeConfig config_;
  mp::MpControlClient control_client_;
  std::optional<mp::MpControlSocket> ws_;
  P2pPartySession session_;

  MpRuntimeState state_ = MpRuntimeState::attaching;
  std::optional<mp::SessionId> session_id_;
  std::uint32_t ping_interval_ms_ = kMpRuntimeDefaultPingIntervalMs;
  std::int64_t clock_skew_s_ = 0;
  std::uint64_t last_pong_ms_ = 0U;
  std::uint32_t next_ws_seq_ = 1U;
  std::optional<mp::EndpointDescriptor> last_published_endpoint_;

  SteadyClock::time_point last_ping_sent_at_{};
  std::optional<std::int64_t> last_ping_sent_override_s_;
  SteadyClock::time_point last_pong_at_{};

  std::uint32_t reconnect_attempts_ = 0U;
  SteadyClock::time_point next_reconnect_at_{};

  std::uint32_t dial_retry_backoff_ms_ = 100U;
  SteadyClock::time_point next_dial_retry_at_{};
  std::optional<std::int64_t> last_effective_now_s_;
  std::size_t pushed_this_pump_ = 0U;

  std::deque<MpRuntimeEvent> events_;
};

} // namespace blackbird
