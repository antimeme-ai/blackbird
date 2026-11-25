#include "blackbird/mp_social_runtime.hpp"

#include "blackbird/party_chat.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace blackbird {

namespace {

constexpr std::size_t kMaxWsFramesPerPump = 32U;
constexpr std::size_t kMaxSanitizedHandleBytes = 64U;

template <typename T> Result<T> fail(ErrorCode code, MpSocialRuntimeError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_void(ErrorCode code, MpSocialRuntimeError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

std::int64_t current_unix_seconds() noexcept {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::uint64_t current_unix_ms() noexcept {
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
  return ms > 0 ? static_cast<std::uint64_t>(ms) : 0U;
}

constexpr std::int64_t saturating_sub_i64(std::int64_t lhs, std::int64_t rhs) noexcept {
  if (rhs < 0 && lhs > std::numeric_limits<std::int64_t>::max() + rhs) {
    return std::numeric_limits<std::int64_t>::max();
  }
  if (rhs > 0 && lhs < std::numeric_limits<std::int64_t>::min() + rhs) {
    return std::numeric_limits<std::int64_t>::min();
  }
  return lhs - rhs;
}

Result<void> validate_social_config(const MpSocialRuntimeConfig &config) {
  if (!config.identity.account_id.has_value() ||
      !config.identity.device_id.has_value()) {
    return fail_void(ErrorCode::provider_auth, MpSocialRuntimeError::missing_identity);
  }
  if (config.max_reconnect_attempts > 0U &&
      (config.reconnect_base_ms == 0U ||
       config.reconnect_max_ms < config.reconnect_base_ms)) {
    return fail_void(ErrorCode::invalid_range, MpSocialRuntimeError::invalid_config);
  }
  if (config.identity.device_cwt.size() > mp::kMaxCwtBytes) {
    return fail_void(ErrorCode::invalid_range, MpSocialRuntimeError::invalid_config);
  }
  return Result<void>::success();
}

std::string format_peer_label(
    mp::AccountId account_id,
    const std::function<std::optional<std::string>(mp::AccountId)> &handle_lookup) {
  if (handle_lookup) {
    if (const auto raw = handle_lookup(account_id); raw.has_value() && !raw->empty()) {
      std::string_view view{*raw};
      if (!view.empty() && view.front() == '@') {
        view.remove_prefix(1U);
      }
      const std::string clean = party_chat_sanitize(view, kMaxSanitizedHandleBytes);
      if (!clean.empty()) {
        return "@" + clean;
      }
    }
  }
  return "#" + account_id.to_decimal();
}

} // namespace

// ---------------------------------------------------------------------------
// Name & notice formatting helpers
// ---------------------------------------------------------------------------

std::string_view mp_social_runtime_error_name(MpSocialRuntimeError detail) noexcept {
  switch (detail) {
  case MpSocialRuntimeError::none:
    return "none";
  case MpSocialRuntimeError::invalid_config:
    return "invalid_config";
  case MpSocialRuntimeError::missing_identity:
    return "missing_identity";
  case MpSocialRuntimeError::runtime_terminated:
    return "runtime_terminated";
  case MpSocialRuntimeError::control_disconnected:
    return "control_disconnected";
  case MpSocialRuntimeError::reconnect_exhausted:
    return "reconnect_exhausted";
  case MpSocialRuntimeError::unexpected_opcode:
    return "unexpected_opcode";
  case MpSocialRuntimeError::device_revoked:
    return "device_revoked";
  }
  return "unknown";
}

std::string_view mp_social_runtime_state_name(MpSocialRuntimeState state) noexcept {
  switch (state) {
  case MpSocialRuntimeState::connecting:
    return "connecting";
  case MpSocialRuntimeState::connected:
    return "connected";
  case MpSocialRuntimeState::reconnecting:
    return "reconnecting";
  case MpSocialRuntimeState::revoked:
    return "revoked";
  case MpSocialRuntimeState::terminated:
    return "terminated";
  }
  return "unknown";
}

std::string_view mp_social_event_kind_name(MpSocialEventKind kind) noexcept {
  switch (kind) {
  case MpSocialEventKind::hello_acked:
    return "hello_acked";
  case MpSocialEventKind::presence_snapshot:
    return "presence_snapshot";
  case MpSocialEventKind::presence_delta:
    return "presence_delta";
  case MpSocialEventKind::social_event:
    return "social_event";
  case MpSocialEventKind::party_invite_notify:
    return "party_invite_notify";
  case MpSocialEventKind::control_disconnected:
    return "control_disconnected";
  case MpSocialEventKind::control_reconnected:
    return "control_reconnected";
  case MpSocialEventKind::device_revoked:
    return "device_revoked";
  case MpSocialEventKind::control_error:
    return "control_error";
  }
  return "unknown";
}

std::string_view mp_presence_visibility_name(mp::PresenceVisibility status) noexcept {
  switch (status) {
  case mp::PresenceVisibility::invisible:
    return "offline";
  case mp::PresenceVisibility::online:
    return "online";
  case mp::PresenceVisibility::idle:
    return "idle";
  case mp::PresenceVisibility::busy:
    return "busy";
  }
  return "unknown";
}

std::string_view mp_social_event_msg_kind_name(mp::SocialEventKind kind) noexcept {
  switch (kind) {
  case mp::SocialEventKind::friend_request:
    return "friend_request";
  case mp::SocialEventKind::friend_accepted:
    return "friend_accepted";
  case mp::SocialEventKind::unfriended:
    return "unfriended";
  }
  return "unknown";
}

std::string format_mp_social_event_notice(
    const MpSocialEvent &event,
    const std::function<std::optional<std::string>(mp::AccountId)> &handle_lookup) {
  switch (event.kind) {
  case MpSocialEventKind::hello_acked:
    if (event.session_id.has_value()) {
      return "Online social connected (session #" + event.session_id->to_decimal() +
             ")";
    }
    return "Online social connected";

  case MpSocialEventKind::presence_snapshot: {
    std::size_t online = 0U;
    for (const auto &entry : event.presence_entries) {
      if (entry.status != mp::PresenceVisibility::invisible) {
        ++online;
      }
    }
    return "Presence synced: " + std::to_string(online) + "/" +
           std::to_string(event.presence_entries.size()) + " friends online";
  }

  case MpSocialEventKind::presence_delta: {
    if (!event.presence_entry.has_value()) {
      return "Friend presence updated";
    }
    const auto &entry = *event.presence_entry;
    std::string out = format_peer_label(entry.account_id, handle_lookup) + " is now " +
                      std::string{mp_presence_visibility_name(entry.status)};
    if (entry.joinable_party_id.has_value()) {
      out += " (party #" + entry.joinable_party_id->to_decimal() + ")";
    }
    return out;
  }

  case MpSocialEventKind::social_event: {
    if (!event.social.has_value()) {
      return "Social update received";
    }
    const std::string peer =
        format_peer_label(event.social->peer_account_id, handle_lookup);
    switch (event.social->kind) {
    case mp::SocialEventKind::friend_request:
      return "Friend request received from " + peer;
    case mp::SocialEventKind::friend_accepted:
      return peer + " accepted your friend request";
    case mp::SocialEventKind::unfriended:
      return peer + " removed you from friends";
    }
    return "Social update from " + peer;
  }

  case MpSocialEventKind::party_invite_notify: {
    if (!event.party_invite.has_value()) {
      return "Party invite received";
    }
    const auto &inv = *event.party_invite;
    return "Party invite from " +
           format_peer_label(inv.from_account_id, handle_lookup) + " to party #" +
           inv.party_id.to_decimal() + " (invite #" + inv.party_invite_id.to_decimal() +
           ")";
  }

  case MpSocialEventKind::control_disconnected:
    return "Online social disconnected (code " + std::to_string(event.ws_close_code) +
           "), reconnecting...";

  case MpSocialEventKind::control_reconnected:
    return "Online social reconnected";

  case MpSocialEventKind::device_revoked:
    return "Device revoked or unauthorized (code " +
           std::to_string(event.ws_close_code) + "); social runtime stopped";

  case MpSocialEventKind::control_error:
    if (event.server_error.has_value()) {
      return "Online social error (server code " +
             std::to_string(event.server_error->code) + ")";
    }
    if (event.error.has_value()) {
      return "Online social error (" + std::string{error_name(event.error->code)} + ")";
    }
    return "Online social error";
  }
  return "Online social update";
}

// ---------------------------------------------------------------------------
// MpSocialRuntime lifecycle
// ---------------------------------------------------------------------------

MpSocialRuntime::MpSocialRuntime(MpSocialRuntimeConfig config,
                                 mp::MpControlClient control_client,
                                 mp::MpControlSocket ws) noexcept
    : config_(std::move(config)), control_client_(std::move(control_client)),
      ws_(std::move(ws)), state_(MpSocialRuntimeState::connecting),
      last_ping_sent_at_(SteadyClock::now()), last_pong_at_(last_ping_sent_at_) {}

MpSocialRuntime::MpSocialRuntime(MpSocialRuntime &&other) noexcept
    : config_(std::move(other.config_)),
      control_client_(std::move(other.control_client_)), ws_(std::move(other.ws_)),
      state_(other.state_), session_id_(other.session_id_),
      ping_interval_ms_(other.ping_interval_ms_), clock_skew_s_(other.clock_skew_s_),
      last_pong_ms_(other.last_pong_ms_), next_ws_seq_(other.next_ws_seq_),
      desired_presence_(other.desired_presence_),
      friend_presence_(std::move(other.friend_presence_)),
      last_ping_sent_at_(other.last_ping_sent_at_),
      last_ping_sent_override_s_(other.last_ping_sent_override_s_),
      last_pong_at_(other.last_pong_at_),
      reconnect_attempts_(other.reconnect_attempts_),
      next_reconnect_at_(other.next_reconnect_at_) {
  events_.swap(other.events_);
  other.events_.clear();
  other.friend_presence_.clear();
  other.ws_.reset();
  other.state_ = MpSocialRuntimeState::terminated;
}

MpSocialRuntime &MpSocialRuntime::operator=(MpSocialRuntime &&other) noexcept {
  if (this != &other) {
    shutdown();
    config_ = std::move(other.config_);
    control_client_ = std::move(other.control_client_);
    ws_ = std::move(other.ws_);
    state_ = other.state_;
    session_id_ = other.session_id_;
    ping_interval_ms_ = other.ping_interval_ms_;
    clock_skew_s_ = other.clock_skew_s_;
    last_pong_ms_ = other.last_pong_ms_;
    next_ws_seq_ = other.next_ws_seq_;
    desired_presence_ = other.desired_presence_;
    friend_presence_ = std::move(other.friend_presence_);
    last_ping_sent_at_ = other.last_ping_sent_at_;
    last_ping_sent_override_s_ = other.last_ping_sent_override_s_;
    last_pong_at_ = other.last_pong_at_;
    reconnect_attempts_ = other.reconnect_attempts_;
    next_reconnect_at_ = other.next_reconnect_at_;
    pushed_this_pump_ = 0U;
    events_.clear();
    events_.swap(other.events_);
    other.events_.clear();
    other.friend_presence_.clear();
    other.ws_.reset();
    other.state_ = MpSocialRuntimeState::terminated;
  }
  return *this;
}

MpSocialRuntime::~MpSocialRuntime() { shutdown(); }

Result<MpSocialRuntime> MpSocialRuntime::connect(MpSocialRuntimeConfig config) {
  if (const auto cfg_ok = validate_social_config(config); !cfg_ok.has_value()) {
    return Result<MpSocialRuntime>::failure(cfg_ok.error());
  }

  mp::MpControlClient client{config.client_config, config.identity};
  auto ws_res = client.connect_social_ws();
  if (!ws_res.has_value()) {
    return Result<MpSocialRuntime>::failure(ws_res.error());
  }

  return Result<MpSocialRuntime>::success(
      MpSocialRuntime{std::move(config), std::move(client), std::move(ws_res).value()});
}

void MpSocialRuntime::shutdown() noexcept {
  if (ws_.has_value()) {
    (void)ws_->close(1000U);
    ws_.reset();
  }
  if (state_ != MpSocialRuntimeState::revoked) {
    state_ = MpSocialRuntimeState::terminated;
  }
}

// ---------------------------------------------------------------------------
// Event queue & live presence table accessors
// ---------------------------------------------------------------------------

void MpSocialRuntime::push_event(MpSocialEvent event) {
  if (events_.size() >= kMpSocialMaxQueuedEvents) {
    const auto delta_it =
        std::find_if(events_.begin(), events_.end(), [](const MpSocialEvent &ev) {
          return ev.kind == MpSocialEventKind::presence_delta;
        });
    if (delta_it != events_.end()) {
      events_.erase(delta_it);
    } else {
      events_.pop_front();
    }
  }
  events_.push_back(std::move(event));
  ++pushed_this_pump_;
}

std::optional<MpSocialEvent> MpSocialRuntime::pop_event() {
  if (events_.empty()) {
    return std::nullopt;
  }
  MpSocialEvent ev = std::move(events_.front());
  events_.pop_front();
  return ev;
}

std::vector<MpSocialEvent> MpSocialRuntime::drain_events() {
  std::vector<MpSocialEvent> out;
  out.reserve(events_.size());
  while (!events_.empty()) {
    out.push_back(std::move(events_.front()));
    events_.pop_front();
  }
  return out;
}

std::optional<mp::PresenceEntry>
MpSocialRuntime::find_presence(mp::AccountId account_id) const {
  const auto it = friend_presence_.find(account_id.value());
  if (it == friend_presence_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::size_t MpSocialRuntime::online_friend_count() const noexcept {
  std::size_t count = 0U;
  for (const auto &[id, entry] : friend_presence_) {
    (void)id;
    if (entry.status != mp::PresenceVisibility::invisible) {
      ++count;
    }
  }
  return count;
}

std::vector<mp::PresenceEntry> MpSocialRuntime::presence_snapshot() const {
  std::vector<mp::PresenceEntry> out;
  out.reserve(friend_presence_.size());
  for (const auto &[id, entry] : friend_presence_) {
    (void)id;
    out.push_back(entry);
  }
  return out;
}

Result<void> MpSocialRuntime::ensure_operational() const {
  if (state_ == MpSocialRuntimeState::revoked) {
    return fail_void(ErrorCode::provider_auth, MpSocialRuntimeError::device_revoked);
  }
  if (is_terminated()) {
    return fail_void(ErrorCode::conflict, MpSocialRuntimeError::runtime_terminated);
  }
  return Result<void>::success();
}

// ---------------------------------------------------------------------------
// Outbound presence & keepalive senders
// ---------------------------------------------------------------------------

Result<void> MpSocialRuntime::set_presence(mp::PresenceVisibility status,
                                           bool share_party) {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return op;
  }
  if (!ws_.has_value() || !ws_->is_open()) {
    return fail_void(ErrorCode::provider_transport,
                     MpSocialRuntimeError::control_disconnected);
  }
  const mp::PresenceSetMessage msg{status, share_party};
  const std::uint32_t seq = next_ws_seq_++;
  if (next_ws_seq_ == 0U) {
    next_ws_seq_ = 1U;
  }
  const auto res = ws_->send_mp1(seq, mp::Mp1Message{msg});
  if (!res.has_value()) {
    handle_transient_ws_disconnect(1006U, res.error(), SteadyClock::now());
    return res;
  }
  desired_presence_ = msg;
  return Result<void>::success();
}

Result<void>
MpSocialRuntime::set_presence(mp::PresenceVisibility status,
                              std::optional<mp::PartyId> joinable_party_id) {
  return set_presence(status, joinable_party_id.has_value());
}

Result<void> MpSocialRuntime::send_heartbeat_ping() {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return op;
  }
  if (!ws_.has_value() || !ws_->is_open()) {
    return fail_void(ErrorCode::provider_transport,
                     MpSocialRuntimeError::control_disconnected);
  }
  const auto res = ws_->send_ping();
  last_ping_sent_at_ = SteadyClock::now();
  if (!res.has_value()) {
    handle_transient_ws_disconnect(1006U, res.error(), last_ping_sent_at_);
    return res;
  }
  return Result<void>::success();
}

void MpSocialRuntime::republish_desired_presence() {
  if (!desired_presence_.has_value() || is_terminated() || !ws_.has_value() ||
      !ws_->is_open()) {
    return;
  }
  const mp::PresenceSetMessage msg = *desired_presence_;
  const std::uint32_t seq = next_ws_seq_++;
  if (next_ws_seq_ == 0U) {
    next_ws_seq_ = 1U;
  }
  const auto res = ws_->send_mp1(seq, mp::Mp1Message{msg});
  if (!res.has_value()) {
    handle_transient_ws_disconnect(1006U, res.error(), SteadyClock::now());
  }
}

// ---------------------------------------------------------------------------
// Reconnect & heartbeat helpers
// ---------------------------------------------------------------------------

std::uint32_t MpSocialRuntime::compute_reconnect_backoff_ms(
    std::uint32_t attempt_index) const noexcept {
  const std::uint32_t shift = std::min<std::uint32_t>(attempt_index, 20U);
  const std::uint64_t scaled = static_cast<std::uint64_t>(config_.reconnect_base_ms)
                               << shift;
  const auto capped = std::min<std::uint64_t>(
      scaled, static_cast<std::uint64_t>(config_.reconnect_max_ms));
  return static_cast<std::uint32_t>(capped);
}

void MpSocialRuntime::handle_transient_ws_disconnect(
    std::uint16_t close_code, std::optional<Error> err,
    SteadyClock::time_point steady_now) {
  if (is_terminated()) {
    return;
  }
  if (ws_.has_value()) {
    (void)ws_->close(1000U);
    ws_.reset();
  }
  state_ = MpSocialRuntimeState::reconnecting;
  reconnect_attempts_ = 0U;
  last_ping_sent_override_s_.reset();
  if (config_.max_reconnect_attempts > 0U) {
    // On 4001 (session_replaced by another local window), back off to reconnect_max_ms
    // instead of tight-looping reconnects and flooding the transcript.
    const std::uint32_t delay_ms = (close_code == 4001U)
                                       ? config_.reconnect_max_ms
                                       : compute_reconnect_backoff_ms(0U);
    next_reconnect_at_ = steady_now + std::chrono::milliseconds{delay_ms};
  }
  MpSocialEvent ev{};
  ev.kind = MpSocialEventKind::control_disconnected;
  ev.ws_close_code = close_code;
  ev.error = err;
  push_event(std::move(ev));
}

void MpSocialRuntime::handle_device_revoked(std::uint16_t close_code,
                                            std::optional<Error> err) {
  if (ws_.has_value()) {
    (void)ws_->close(1000U);
    ws_.reset();
  }
  friend_presence_.clear();
  state_ = MpSocialRuntimeState::revoked;
  MpSocialEvent ev{};
  ev.kind = MpSocialEventKind::device_revoked;
  ev.ws_close_code = close_code;
  ev.error =
      err.has_value()
          ? err
          : std::optional<Error>{
                Error{ErrorCode::provider_auth,
                      static_cast<std::int64_t>(MpSocialRuntimeError::device_revoked)}};
  push_event(std::move(ev));
}

void MpSocialRuntime::maybe_attempt_reconnect(SteadyClock::time_point steady_now) {
  if (state_ != MpSocialRuntimeState::reconnecting || ws_.has_value() ||
      reconnect_attempts_ >= config_.max_reconnect_attempts ||
      steady_now < next_reconnect_at_) {
    return;
  }
  const std::uint32_t attempt_index = reconnect_attempts_;
  ++reconnect_attempts_;

  auto sock = control_client_.connect_social_ws();
  if (sock.has_value()) {
    ws_.emplace(std::move(sock).value());
    state_ = MpSocialRuntimeState::connecting;
    reconnect_attempts_ = 0U;
    last_ping_sent_at_ = steady_now;
    last_ping_sent_override_s_.reset();
    last_pong_at_ = steady_now;
    MpSocialEvent ev{};
    ev.kind = MpSocialEventKind::control_reconnected;
    push_event(std::move(ev));
    return;
  }

  const Error err = sock.error();
  // Hard terminal stop on non-clock-skew HTTP 401/403 during reconnect!
  if (err.code == ErrorCode::provider_auth &&
      mp::mp_client_error_of(err) != mp::MpClientError::http_clock_skew) {
    handle_device_revoked(kMpSocialWsCloseDeviceRevoked, err);
    return;
  }
  if (reconnect_attempts_ >= config_.max_reconnect_attempts) {
    MpSocialEvent ev{};
    ev.kind = MpSocialEventKind::control_error;
    ev.error =
        Error{ErrorCode::provider_transport,
              static_cast<std::int64_t>(MpSocialRuntimeError::reconnect_exhausted)};
    push_event(std::move(ev));
    return;
  }

  const std::uint32_t next_delay_ms = compute_reconnect_backoff_ms(attempt_index + 1U);
  next_reconnect_at_ = steady_now + std::chrono::milliseconds{next_delay_ms};
}

void MpSocialRuntime::maybe_send_heartbeat_ping(
    const HandleContext &ctx, std::optional<std::int64_t> now_s_override) {
  if (is_terminated() || state_ != MpSocialRuntimeState::connected ||
      !ws_.has_value() || !ws_->is_open()) {
    return;
  }
  bool due = false;
  if (now_s_override.has_value()) {
    if (!last_ping_sent_override_s_.has_value()) {
      last_ping_sent_override_s_ = *now_s_override;
    } else {
      const auto interval_s =
          static_cast<std::int64_t>((ping_interval_ms_ + 999U) / 1000U);
      const std::int64_t elapsed_s =
          saturating_sub_i64(*now_s_override, *last_ping_sent_override_s_);
      if (elapsed_s >= interval_s) {
        due = true;
      }
    }
  } else {
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        ctx.steady_now - last_ping_sent_at_);
    if (elapsed.count() >= static_cast<std::int64_t>(ping_interval_ms_)) {
      due = true;
    }
  }
  if (!due) {
    return;
  }
  const auto res = ws_->send_ping();
  last_ping_sent_at_ = ctx.steady_now;
  if (now_s_override.has_value()) {
    last_ping_sent_override_s_ = *now_s_override;
  }
  if (!res.has_value()) {
    handle_transient_ws_disconnect(1006U, res.error(), ctx.steady_now);
  }
}

// ---------------------------------------------------------------------------
// Control-plane WebSocket & MP1 dispatch
// ---------------------------------------------------------------------------

void MpSocialRuntime::handle_ws_event(const mp::MpWsEvent &event,
                                      const HandleContext &ctx) {
  if (const auto *mp1 = std::get_if<mp::MpWsMp1Frame>(&event)) {
    handle_mp1_message(mp1->frame.message, ctx);
    return;
  }
  if (std::holds_alternative<mp::MpWsPong>(event)) {
    last_pong_at_ = ctx.steady_now;
    last_pong_ms_ = current_unix_ms();
    return;
  }
  if (const auto *closed = std::get_if<mp::MpWsClosed>(&event)) {
    if (closed->code == kMpSocialWsCloseDeviceRevoked) {
      handle_device_revoked(closed->code, std::nullopt);
      return;
    }
    handle_transient_ws_disconnect(closed->code, std::nullopt, ctx.steady_now);
  }
}

void MpSocialRuntime::handle_mp1_message(const mp::Mp1Message &message,
                                         const HandleContext &ctx) {
  if (const auto *hello = std::get_if<mp::HelloAckMessage>(&message)) {
    session_id_ = hello->session_id;
    ping_interval_ms_ = std::clamp(hello->ping_interval_ms, kMpSocialMinPingIntervalMs,
                                   kMpSocialMaxPingIntervalMs);
    constexpr std::uint64_t kMinPlausibleServerNowMs = 1000000000000ULL;
    if (hello->server_now_ms >= kMinPlausibleServerNowMs) {
      const auto server_s = static_cast<std::int64_t>(hello->server_now_ms / 1000U);
      clock_skew_s_ = saturating_sub_i64(server_s, current_unix_seconds());
      control_client_.set_clock_offset_seconds(clock_skew_s_);
    }
    state_ = MpSocialRuntimeState::connected;
    last_ping_sent_at_ = ctx.steady_now;
    if (ctx.has_override_now) {
      last_ping_sent_override_s_ = ctx.now_s;
    } else {
      last_ping_sent_override_s_.reset();
    }
    last_pong_at_ = ctx.steady_now;

    MpSocialEvent ev{};
    ev.kind = MpSocialEventKind::hello_acked;
    ev.session_id = hello->session_id;
    ev.ping_interval_ms = ping_interval_ms_;
    push_event(std::move(ev));

    republish_desired_presence();
    return;
  }

  if (const auto *snap = std::get_if<mp::PresenceSnapshotMessage>(&message)) {
    friend_presence_.clear();
    for (const auto &entry : snap->entries) {
      friend_presence_.insert_or_assign(entry.account_id.value(), entry);
    }
    MpSocialEvent ev{};
    ev.kind = MpSocialEventKind::presence_snapshot;
    ev.presence_entries = snap->entries;
    push_event(std::move(ev));
    return;
  }

  if (const auto *delta = std::get_if<mp::PresenceDeltaMessage>(&message)) {
    friend_presence_.insert_or_assign(delta->entry.account_id.value(), delta->entry);
    MpSocialEvent ev{};
    ev.kind = MpSocialEventKind::presence_delta;
    ev.presence_entry = delta->entry;
    push_event(std::move(ev));
    return;
  }

  if (const auto *social = std::get_if<mp::SocialEventMessage>(&message)) {
    if (social->kind == mp::SocialEventKind::unfriended) {
      friend_presence_.erase(social->peer_account_id.value());
    }
    MpSocialEvent ev{};
    ev.kind = MpSocialEventKind::social_event;
    ev.social = *social;
    push_event(std::move(ev));
    return;
  }

  if (const auto *invite = std::get_if<mp::PartyInviteNotifyMessage>(&message)) {
    MpSocialEvent ev{};
    ev.kind = MpSocialEventKind::party_invite_notify;
    ev.party_invite = *invite;
    push_event(std::move(ev));
    return;
  }

  if (const auto *server_err = std::get_if<mp::ErrorMessage>(&message)) {
    MpSocialEvent ev{};
    ev.kind = MpSocialEventKind::control_error;
    ev.server_error = *server_err;
    push_event(std::move(ev));
    return;
  }

  MpSocialEvent err_ev{};
  err_ev.kind = MpSocialEventKind::control_error;
  err_ev.error =
      Error{ErrorCode::corrupt,
            static_cast<std::int64_t>(MpSocialRuntimeError::unexpected_opcode)};
  push_event(std::move(err_ev));
}

// ---------------------------------------------------------------------------
// Step-driven pump_once
// ---------------------------------------------------------------------------

Result<std::size_t>
MpSocialRuntime::pump_once(std::uint32_t timeout_ms,
                           std::optional<std::int64_t> now_s_override) {
  if (is_terminated()) {
    return Result<std::size_t>::success(0U);
  }

  pushed_this_pump_ = 0U;
  const auto pump_start = SteadyClock::now();

  // 1. Bounded exponential-backoff reconnect when control WS is down.
  if (state_ == MpSocialRuntimeState::reconnecting && !ws_.has_value()) {
    maybe_attempt_reconnect(pump_start);
  }

  // 2. Poll MpControlSocket (bounded first slice, then non-blocking drain).
  if (!is_terminated() && ws_.has_value() && ws_->is_open()) {
    const std::uint32_t clamped_ws_ms = std::min<std::uint32_t>(
        timeout_ms, static_cast<std::uint32_t>(std::numeric_limits<int>::max()));

    for (std::size_t i = 0U; i < kMaxWsFramesPerPump; ++i) {
      if (is_terminated() || !ws_.has_value() || !ws_->is_open()) {
        break;
      }
      const int slice_ms = (i == 0U) ? static_cast<int>(clamped_ws_ms) : 0;
      auto polled = ws_->poll_event(slice_ms);
      const auto now_tick = SteadyClock::now();
      if (!polled.has_value()) {
        handle_transient_ws_disconnect(1006U, polled.error(), now_tick);
        break;
      }
      auto &ws_opt = polled.value();
      if (!ws_opt.has_value()) {
        break;
      }
      const std::int64_t effective_now_s =
          now_s_override.has_value() ? *now_s_override : current_unix_seconds();
      handle_ws_event(*ws_opt, HandleContext{effective_now_s, now_tick,
                                             now_s_override.has_value()});
    }
  }

  // 3. Send MP1:PING heartbeat whenever ping_interval_ms elapses.
  if (!is_terminated()) {
    const std::int64_t post_now_s =
        now_s_override.has_value() ? *now_s_override : current_unix_seconds();
    maybe_send_heartbeat_ping(
        HandleContext{post_now_s, SteadyClock::now(), now_s_override.has_value()},
        now_s_override);
  }

  return Result<std::size_t>::success(pushed_this_pump_);
}

} // namespace blackbird
