#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/mp_client.hpp"
#include "blackbird/mp_protocol.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

// ---------------------------------------------------------------------------
// Constants & error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t kMpSocialMinPingIntervalMs = 5000U;
inline constexpr std::uint32_t kMpSocialMaxPingIntervalMs = 60000U;
inline constexpr std::uint32_t kMpSocialDefaultPingIntervalMs = 20000U;
inline constexpr std::uint32_t kMpSocialDefaultMaxReconnectAttempts = 8U;
inline constexpr std::uint32_t kMpSocialDefaultReconnectBaseMs = 250U;
inline constexpr std::uint32_t kMpSocialDefaultReconnectMaxMs = 15000U;
inline constexpr std::size_t kMpSocialMaxQueuedEvents = 4096U;
inline constexpr std::uint16_t kMpSocialWsCloseDeviceRevoked = 4401U;

enum class MpSocialRuntimeError : std::int64_t {
  none = 0,
  invalid_config = 2100,
  missing_identity = 2101,
  runtime_terminated = 2102,
  control_disconnected = 2103,
  reconnect_exhausted = 2104,
  unexpected_opcode = 2105,
  device_revoked = 2106,
};

constexpr MpSocialRuntimeError mp_social_runtime_error_of(const Error &error) noexcept {
  return static_cast<MpSocialRuntimeError>(error.detail);
}

std::string_view mp_social_runtime_error_name(MpSocialRuntimeError detail) noexcept;

// ---------------------------------------------------------------------------
// Runtime state, configuration, and typed event queue entries
// ---------------------------------------------------------------------------

enum class MpSocialRuntimeState : std::uint8_t {
  connecting = 0,
  connected = 1,
  reconnecting = 2,
  revoked = 3,
  terminated = 4,
};

std::string_view mp_social_runtime_state_name(MpSocialRuntimeState state) noexcept;

enum class MpSocialEventKind : std::uint8_t {
  hello_acked = 1,
  presence_snapshot = 2,
  presence_delta = 3,
  social_event = 4,
  party_invite_notify = 5,
  control_disconnected = 6,
  control_reconnected = 7,
  device_revoked = 8,
  control_error = 9,
};

std::string_view mp_social_event_kind_name(MpSocialEventKind kind) noexcept;
std::string_view mp_presence_visibility_name(mp::PresenceVisibility status) noexcept;
std::string_view mp_social_event_msg_kind_name(mp::SocialEventKind kind) noexcept;

struct MpSocialEvent {
  MpSocialEventKind kind = MpSocialEventKind::control_error;

  std::optional<mp::SessionId> session_id = std::nullopt;
  std::uint32_t ping_interval_ms = 0U;
  std::vector<mp::PresenceEntry> presence_entries;
  std::optional<mp::PresenceEntry> presence_entry = std::nullopt;
  std::optional<mp::SocialEventMessage> social = std::nullopt;
  std::optional<mp::PartyInviteNotifyMessage> party_invite = std::nullopt;
  std::optional<mp::ErrorMessage> server_error = std::nullopt;
  std::uint16_t ws_close_code = 0U;
  std::optional<Error> error = std::nullopt;

  bool operator==(const MpSocialEvent &) const = default;
};

// Formats a single-line human-safe notice for any social runtime event.
// All untrusted strings returned by handle_lookup are strictly sanitized
// against terminal escape / control / bidi injection.
std::string format_mp_social_event_notice(
    const MpSocialEvent &event,
    const std::function<std::optional<std::string>(mp::AccountId)> &handle_lookup = {});

struct MpSocialRuntimeConfig {
  mp::MpClientConfig client_config;
  mp::MpIdentityState identity;
  std::uint32_t max_reconnect_attempts = kMpSocialDefaultMaxReconnectAttempts;
  std::uint32_t reconnect_base_ms = kMpSocialDefaultReconnectBaseMs;
  std::uint32_t reconnect_max_ms = kMpSocialDefaultReconnectMaxMs;
};

// ---------------------------------------------------------------------------
// Live Account Social & Presence WebSocket Runtime (GET /v1/ws, MP1)
// ---------------------------------------------------------------------------

class MpSocialRuntime {
public:
  static Result<MpSocialRuntime> connect(MpSocialRuntimeConfig config);

  MpSocialRuntime(const MpSocialRuntime &) = delete;
  MpSocialRuntime &operator=(const MpSocialRuntime &) = delete;
  MpSocialRuntime(MpSocialRuntime &&other) noexcept;
  MpSocialRuntime &operator=(MpSocialRuntime &&other) noexcept;
  ~MpSocialRuntime();

  // Non-blocking / bounded-timeout step-driven event pump.
  // Returns the number of newly queued MpSocialEvent entries during this pump.
  Result<std::size_t>
  pump_once(std::uint32_t timeout_ms,
            std::optional<std::int64_t> now_s_override = std::nullopt);

  // Event queue inspection and draining.
  std::optional<MpSocialEvent> pop_event();
  std::vector<MpSocialEvent> drain_events();
  std::size_t pending_event_count() const noexcept { return events_.size(); }
  bool has_pending_events() const noexcept { return !events_.empty(); }

  // Live in-memory friend presence table.
  std::optional<mp::PresenceEntry> find_presence(mp::AccountId account_id) const;
  std::size_t online_friend_count() const noexcept;
  std::vector<mp::PresenceEntry> presence_snapshot() const;
  std::size_t tracked_presence_count() const noexcept {
    return friend_presence_.size();
  }

  // Outbound presence & keepalive senders (fail closed once revoked/terminated).
  Result<void> set_presence(mp::PresenceVisibility status, bool share_party = false);
  Result<void> set_presence(mp::PresenceVisibility status,
                            std::optional<mp::PartyId> joinable_party_id);
  Result<void> send_heartbeat_ping();

  // Clean shutdown (idempotent, noexcept): sends WS close 1000 and marks terminated.
  void shutdown() noexcept;

  // Read-only state & metadata accessors.
  MpSocialRuntimeState state() const noexcept { return state_; }
  bool is_connected() const noexcept {
    return !is_terminated() && ws_.has_value() && ws_->is_open();
  }
  bool is_terminated() const noexcept {
    return state_ == MpSocialRuntimeState::revoked ||
           state_ == MpSocialRuntimeState::terminated;
  }
  bool is_revoked() const noexcept { return state_ == MpSocialRuntimeState::revoked; }
  std::optional<mp::SessionId> session_id() const noexcept { return session_id_; }
  std::uint32_t ping_interval_ms() const noexcept { return ping_interval_ms_; }
  std::int64_t clock_skew_seconds() const noexcept { return clock_skew_s_; }
  std::uint64_t last_pong_ms() const noexcept { return last_pong_ms_; }
  std::uint32_t reconnect_attempts() const noexcept { return reconnect_attempts_; }
  std::optional<mp::PresenceSetMessage> desired_presence() const noexcept {
    return desired_presence_;
  }
  const MpSocialRuntimeConfig &config() const noexcept { return config_; }

private:
  using SteadyClock = std::chrono::steady_clock;

  struct HandleContext {
    std::int64_t now_s = 0;
    SteadyClock::time_point steady_now{};
    bool has_override_now = false;
  };

  MpSocialRuntime(MpSocialRuntimeConfig config, mp::MpControlClient control_client,
                  mp::MpControlSocket ws) noexcept;

  void push_event(MpSocialEvent event);
  Result<void> ensure_operational() const;
  void handle_ws_event(const mp::MpWsEvent &event, const HandleContext &ctx);
  void handle_mp1_message(const mp::Mp1Message &message, const HandleContext &ctx);
  void handle_transient_ws_disconnect(std::uint16_t close_code,
                                      std::optional<Error> err,
                                      SteadyClock::time_point steady_now);
  void handle_device_revoked(std::uint16_t close_code, std::optional<Error> err);
  void maybe_attempt_reconnect(SteadyClock::time_point steady_now);
  void maybe_send_heartbeat_ping(const HandleContext &ctx,
                                 std::optional<std::int64_t> now_s_override);
  void republish_desired_presence();
  std::uint32_t
  compute_reconnect_backoff_ms(std::uint32_t attempt_index) const noexcept;

  MpSocialRuntimeConfig config_;
  mp::MpControlClient control_client_;
  std::optional<mp::MpControlSocket> ws_;

  MpSocialRuntimeState state_ = MpSocialRuntimeState::connecting;
  std::optional<mp::SessionId> session_id_;
  std::uint32_t ping_interval_ms_ = kMpSocialDefaultPingIntervalMs;
  std::int64_t clock_skew_s_ = 0;
  std::uint64_t last_pong_ms_ = 0U;
  std::uint32_t next_ws_seq_ = 1U;
  std::optional<mp::PresenceSetMessage> desired_presence_;

  std::map<std::uint64_t, mp::PresenceEntry> friend_presence_;

  SteadyClock::time_point last_ping_sent_at_{};
  std::optional<std::int64_t> last_ping_sent_override_s_;
  SteadyClock::time_point last_pong_at_{};

  std::uint32_t reconnect_attempts_ = 0U;
  SteadyClock::time_point next_reconnect_at_{};

  std::size_t pushed_this_pump_ = 0U;
  std::deque<MpSocialEvent> events_;
};

} // namespace blackbird
