#include "blackbird/mp_party_runtime.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/crypto.h>

namespace blackbird {

namespace {

template <typename T> Result<T> fail(ErrorCode code, MpPartyRuntimeError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_void(ErrorCode code, MpPartyRuntimeError detail) {
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

constexpr std::int64_t saturating_add_i64(std::int64_t lhs, std::int64_t rhs) noexcept {
  if (rhs > 0 && lhs > std::numeric_limits<std::int64_t>::max() - rhs) {
    return std::numeric_limits<std::int64_t>::max();
  }
  if (rhs < 0 && lhs < std::numeric_limits<std::int64_t>::min() - rhs) {
    return std::numeric_limits<std::int64_t>::min();
  }
  return lhs + rhs;
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

struct CleanseOptionalSecretGuard {
  std::optional<P2pSecretKey> &secret;

  ~CleanseOptionalSecretGuard() {
    if (secret.has_value()) {
      OPENSSL_cleanse(secret->data(), secret->size());
      secret.reset();
    }
  }
};

constexpr std::size_t kMaxWsFramesPerPump = 32U;
constexpr std::size_t kMaxP2pEventsPerPump = 64U;
constexpr std::uint32_t kMaxWsSliceWithP2pMs = 50U;
constexpr std::uint32_t kInitialDialRetryBackoffMs = 100U;
constexpr std::uint32_t kMaxDialRetryBackoffMs = 2000U;

bool runtime_use_live_iroh() noexcept {
#if defined(BLACKBIRD_HAS_IROH) && !BLACKBIRD_HAS_IROH
  return false;
#else
  return p2p_iroh_compiled_in();
#endif
}

Result<void> validate_runtime_config(const MpPartyRuntimeConfig &config) {
  if (!config.identity.account_id.has_value() ||
      !config.identity.device_id.has_value()) {
    return fail_void(ErrorCode::provider_auth, MpPartyRuntimeError::missing_identity);
  }
  if (config.max_lease_ttl_s <= 0 ||
      config.max_lease_ttl_s > kP2pPartyDefaultMaxLeaseTtlSecs) {
    return fail_void(ErrorCode::invalid_range, MpPartyRuntimeError::invalid_config);
  }
  if (config.max_reconnect_attempts > 0U &&
      (config.reconnect_base_ms == 0U ||
       config.reconnect_max_ms < config.reconnect_base_ms)) {
    return fail_void(ErrorCode::invalid_range, MpPartyRuntimeError::invalid_config);
  }
  if (config.identity.device_cwt.size() > mp::kMaxCwtBytes) {
    return fail_void(ErrorCode::invalid_range, MpPartyRuntimeError::invalid_config);
  }
  const std::string_view relay_url = config.relay_url.has_value()
                                         ? std::string_view{*config.relay_url}
                                         : std::string_view{};
  if (const auto pin_ok =
          mp::validate_pinned_relay_url(config.local_relay_policy, relay_url);
      !pin_ok.has_value()) {
    return pin_ok;
  }
  return Result<void>::success();
}

} // namespace

// ---------------------------------------------------------------------------
// Name helpers
// ---------------------------------------------------------------------------

std::string_view mp_party_runtime_error_name(MpPartyRuntimeError detail) noexcept {
  switch (detail) {
  case MpPartyRuntimeError::none:
    return "none";
  case MpPartyRuntimeError::invalid_config:
    return "invalid_config";
  case MpPartyRuntimeError::missing_identity:
    return "missing_identity";
  case MpPartyRuntimeError::runtime_terminated:
    return "runtime_terminated";
  case MpPartyRuntimeError::control_disconnected:
    return "control_disconnected";
  case MpPartyRuntimeError::reconnect_exhausted:
    return "reconnect_exhausted";
  case MpPartyRuntimeError::p2p_unavailable:
    return "p2p_unavailable";
  case MpPartyRuntimeError::unexpected_opcode:
    return "unexpected_opcode";
  case MpPartyRuntimeError::endpoint_build_failed:
    return "endpoint_build_failed";
  }
  return "unknown";
}

std::string_view mp_runtime_state_name(MpRuntimeState state) noexcept {
  switch (state) {
  case MpRuntimeState::attaching:
    return "attaching";
  case MpRuntimeState::connected:
    return "connected";
  case MpRuntimeState::reconnecting:
    return "reconnecting";
  case MpRuntimeState::disbanded:
    return "disbanded";
  case MpRuntimeState::terminated:
    return "terminated";
  }
  return "unknown";
}

std::string_view mp_runtime_event_kind_name(MpRuntimeEventKind kind) noexcept {
  switch (kind) {
  case MpRuntimeEventKind::hello_acked:
    return "hello_acked";
  case MpRuntimeEventKind::snapshot_applied:
    return "snapshot_applied";
  case MpRuntimeEventKind::member_joined:
    return "member_joined";
  case MpRuntimeEventKind::member_updated:
    return "member_updated";
  case MpRuntimeEventKind::member_left:
    return "member_left";
  case MpRuntimeEventKind::leader_changed:
    return "leader_changed";
  case MpRuntimeEventKind::party_disbanded:
    return "party_disbanded";
  case MpRuntimeEventKind::kicked_or_revoked:
    return "kicked_or_revoked";
  case MpRuntimeEventKind::control_disconnected:
    return "control_disconnected";
  case MpRuntimeEventKind::control_reconnected:
    return "control_reconnected";
  case MpRuntimeEventKind::control_error:
    return "control_error";
  case MpRuntimeEventKind::join_request_received:
    return "join_request_received";
  case MpRuntimeEventKind::peer_connected:
    return "peer_connected";
  case MpRuntimeEventKind::peer_disconnected:
    return "peer_disconnected";
  case MpRuntimeEventKind::chat_received:
    return "chat_received";
  case MpRuntimeEventKind::bridge_envelope_received:
    return "bridge_envelope_received";
  case MpRuntimeEventKind::control_notice_received:
    return "control_notice_received";
  case MpRuntimeEventKind::ephemeral_pulse_received:
    return "ephemeral_pulse_received";
  case MpRuntimeEventKind::peer_evicted:
    return "peer_evicted";
  case MpRuntimeEventKind::frame_dropped:
    return "frame_dropped";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// MpPartyRuntime lifecycle
// ---------------------------------------------------------------------------

MpPartyRuntime::MpPartyRuntime(MpPartyRuntimeConfig config,
                               mp::MpControlClient control_client,
                               mp::MpControlSocket ws, P2pPartySession session) noexcept
    : config_(std::move(config)), control_client_(std::move(control_client)),
      ws_(std::move(ws)), session_(std::move(session)),
      state_(MpRuntimeState::attaching), last_ping_sent_at_(SteadyClock::now()),
      last_pong_at_(last_ping_sent_at_) {}

MpPartyRuntime::MpPartyRuntime(MpPartyRuntime &&other) noexcept
    : config_(std::move(other.config_)),
      control_client_(std::move(other.control_client_)), ws_(std::move(other.ws_)),
      session_(std::move(other.session_)), state_(other.state_),
      session_id_(other.session_id_), ping_interval_ms_(other.ping_interval_ms_),
      clock_skew_s_(other.clock_skew_s_), last_pong_ms_(other.last_pong_ms_),
      next_ws_seq_(other.next_ws_seq_),
      last_published_endpoint_(std::move(other.last_published_endpoint_)),
      last_ping_sent_at_(other.last_ping_sent_at_),
      last_ping_sent_override_s_(other.last_ping_sent_override_s_),
      last_pong_at_(other.last_pong_at_),
      reconnect_attempts_(other.reconnect_attempts_),
      next_reconnect_at_(other.next_reconnect_at_),
      dial_retry_backoff_ms_(other.dial_retry_backoff_ms_),
      next_dial_retry_at_(other.next_dial_retry_at_),
      last_effective_now_s_(other.last_effective_now_s_) {
  events_.swap(other.events_);
  other.events_.clear();
  other.ws_.reset();
  other.state_ = MpRuntimeState::terminated;
}

MpPartyRuntime &MpPartyRuntime::operator=(MpPartyRuntime &&other) noexcept {
  if (this != &other) {
    shutdown();
    config_ = std::move(other.config_);
    control_client_ = std::move(other.control_client_);
    ws_ = std::move(other.ws_);
    session_ = std::move(other.session_);
    state_ = other.state_;
    session_id_ = other.session_id_;
    ping_interval_ms_ = other.ping_interval_ms_;
    clock_skew_s_ = other.clock_skew_s_;
    last_pong_ms_ = other.last_pong_ms_;
    next_ws_seq_ = other.next_ws_seq_;
    last_published_endpoint_ = std::move(other.last_published_endpoint_);
    last_ping_sent_at_ = other.last_ping_sent_at_;
    last_ping_sent_override_s_ = other.last_ping_sent_override_s_;
    last_pong_at_ = other.last_pong_at_;
    reconnect_attempts_ = other.reconnect_attempts_;
    next_reconnect_at_ = other.next_reconnect_at_;
    dial_retry_backoff_ms_ = other.dial_retry_backoff_ms_;
    next_dial_retry_at_ = other.next_dial_retry_at_;
    last_effective_now_s_ = other.last_effective_now_s_;
    pushed_this_pump_ = 0U;
    events_.clear();
    events_.swap(other.events_);
    other.events_.clear();
    other.ws_.reset();
    other.state_ = MpRuntimeState::terminated;
  }
  return *this;
}

MpPartyRuntime::~MpPartyRuntime() { shutdown(); }

Result<MpPartyRuntime> MpPartyRuntime::attach(MpPartyRuntimeConfig config) {
  if (const auto cfg_ok = validate_runtime_config(config); !cfg_ok.has_value()) {
    return Result<MpPartyRuntime>::failure(cfg_ok.error());
  }

  const auto device_key_res =
      mp::Ed25519SigningKey::from_seed(config.identity.device_seed.bytes());
  if (!device_key_res.has_value()) {
    return Result<MpPartyRuntime>::failure(device_key_res.error());
  }
  const P2pPubkey local_pubkey = device_key_res.value().public_key();

  if (!config.identity.account_id.has_value() ||
      !config.identity.device_id.has_value()) {
    return fail<MpPartyRuntime>(ErrorCode::provider_auth,
                                MpPartyRuntimeError::missing_identity);
  }
  const mp::AccountId local_account_id = *config.identity.account_id;
  const mp::DeviceId local_device_id = *config.identity.device_id;

  P2pPartySessionConfig sess_cfg{local_account_id, local_device_id};
  sess_cfg.local_relay_policy = to_p2p_relay_policy(config.local_relay_policy);
  sess_cfg.local_pubkey = local_pubkey;
  sess_cfg.connect_timeout_ms = config.p2p_connect_timeout_ms;
  sess_cfg.max_lease_ttl_s = config.max_lease_ttl_s;
  // Let P2pPartySession dial immediately on snapshot/join/update (including
  // endpoint roaming on already-connected peers), while MpPartyRuntime drives
  // bounded retries for any peers left in dial_pending inside pump_once().
  sess_cfg.auto_dial = true;
  sess_cfg.allow_loopback_direct_addrs = config.allow_loopback_direct_addrs;

  std::optional<P2pPartySession> session_opt;
  if (runtime_use_live_iroh()) {
    P2pEndpointConfig ep_cfg{};
    ep_cfg.relay_policy = to_p2p_relay_policy(config.local_relay_policy);
    ep_cfg.secret_key = config.identity.device_seed.bytes();
    CleanseOptionalSecretGuard secret_guard{ep_cfg.secret_key};
    if (config.relay_url.has_value()) {
      ep_cfg.relay_url = *config.relay_url;
    }
    auto endpoint_res = P2pEndpoint::create(ep_cfg);
    if (!endpoint_res.has_value()) {
      return Result<MpPartyRuntime>::failure(endpoint_res.error());
    }
    auto sess_res = P2pPartySession::create(sess_cfg, std::move(endpoint_res).value());
    if (!sess_res.has_value()) {
      return Result<MpPartyRuntime>::failure(sess_res.error());
    }
    session_opt.emplace(std::move(sess_res).value());
  } else {
    auto sess_res = P2pPartySession::create_detached(sess_cfg);
    if (!sess_res.has_value()) {
      return Result<MpPartyRuntime>::failure(sess_res.error());
    }
    session_opt.emplace(std::move(sess_res).value());
  }

  mp::MpControlClient client{config.client_config, config.identity};
  auto ws_res = client.connect_party_socket(config.party_id);
  if (!ws_res.has_value()) {
    session_opt->close();
    return Result<MpPartyRuntime>::failure(ws_res.error());
  }

  return Result<MpPartyRuntime>::success(
      MpPartyRuntime{std::move(config), std::move(client), std::move(ws_res).value(),
                     std::move(*session_opt)});
}

void MpPartyRuntime::shutdown() noexcept {
  if (ws_.has_value()) {
    (void)ws_->close(1000U);
    ws_.reset();
  }
  teardown_p2p_session(mp::MemberLeaveReason::left);
  if (state_ != MpRuntimeState::disbanded) {
    state_ = MpRuntimeState::terminated;
  }
}

void MpPartyRuntime::teardown_p2p_session(mp::MemberLeaveReason reason) noexcept {
  if (session_.has_active_party() && !session_.disbanded() &&
      config_.identity.device_id.has_value() &&
      config_.identity.account_id.has_value()) {
    const std::uint64_t epoch = std::max<std::uint64_t>(1U, session_.party_epoch());
    (void)session_.apply_member_left(mp::PartyMemberLeftMessage{
        epoch,
        *config_.identity.device_id,
        *config_.identity.account_id,
        reason,
    });
  }
  session_.close();
}

// ---------------------------------------------------------------------------
// Event queue helpers
// ---------------------------------------------------------------------------

void MpPartyRuntime::push_event(MpRuntimeEvent event) {
  if (events_.size() >= kMpRuntimeMaxQueuedEvents) {
    const auto eph_it =
        std::find_if(events_.begin(), events_.end(), [](const MpRuntimeEvent &ev) {
          return ev.kind == MpRuntimeEventKind::ephemeral_pulse_received;
        });
    if (eph_it != events_.end()) {
      events_.erase(eph_it);
    } else {
      events_.pop_front();
    }
  }
  events_.push_back(std::move(event));
  ++pushed_this_pump_;
}

std::optional<MpRuntimeEvent> MpPartyRuntime::pop_event() {
  if (events_.empty()) {
    return std::nullopt;
  }
  MpRuntimeEvent ev = std::move(events_.front());
  events_.pop_front();
  return ev;
}

std::vector<MpRuntimeEvent> MpPartyRuntime::drain_events() {
  std::vector<MpRuntimeEvent> out;
  out.reserve(events_.size());
  while (!events_.empty()) {
    out.push_back(std::move(events_.front()));
    events_.pop_front();
  }
  return out;
}

Result<void> MpPartyRuntime::ensure_operational() const {
  if (is_terminated()) {
    return fail_void(ErrorCode::conflict, MpPartyRuntimeError::runtime_terminated);
  }
  return Result<void>::success();
}

// ---------------------------------------------------------------------------
// Local EndpointDescriptor construction & publication
// ---------------------------------------------------------------------------

Result<mp::EndpointDescriptor> MpPartyRuntime::local_endpoint_descriptor() const {
  mp::EndpointDescriptor ep{};
  ep.transport_kind = mp::TransportKind::iroh_quic;
  if (config_.local_relay_policy != mp::RelayPolicy::no_relays &&
      config_.relay_url.has_value()) {
    ep.relay_url = *config_.relay_url;
  }

  if (config_.local_relay_policy == mp::RelayPolicy::force_relays ||
      !session_.has_endpoint()) {
    if (const auto ok =
            ep.validate_against_policy(config_.local_relay_policy, ep.relay_url);
        !ok.has_value()) {
      return Result<mp::EndpointDescriptor>::failure(ok.error());
    }
    return Result<mp::EndpointDescriptor>::success(std::move(ep));
  }

  const auto raw_addrs = session_.local_direct_addrs();
  if (!raw_addrs.has_value()) {
    return Result<mp::EndpointDescriptor>::failure(raw_addrs.error());
  }

  for (const auto &raw_addr : raw_addrs.value()) {
    if (ep.direct_addrs.size() >= mp::kMaxDirectAddrs) {
      break;
    }
    const auto converted = p2p_direct_addr_to_mp(raw_addr);
    if (!converted.has_value()) {
      continue;
    }
    // Filter each candidate address against the strict MP1 wire + relay policy
    // so production never leaks RFC1918/loopback addresses and wire encoding
    // always succeeds.
    mp::EndpointDescriptor probe{};
    probe.transport_kind = ep.transport_kind;
    probe.relay_url = ep.relay_url;
    probe.direct_addrs.push_back(converted.value());
    if (!probe.validate_against_policy(config_.local_relay_policy, ep.relay_url)
             .has_value()) {
      continue;
    }
    ep.direct_addrs.push_back(converted.value());
  }

  // Trim trailing direct_addrs if serialized descriptor exceeds 256 B ceiling.
  while (!ep.direct_addrs.empty() && !ep.encode().has_value()) {
    ep.direct_addrs.pop_back();
  }
  if (const auto ok =
          ep.validate_against_policy(config_.local_relay_policy, ep.relay_url);
      !ok.has_value()) {
    return Result<mp::EndpointDescriptor>::failure(ok.error());
  }
  return Result<mp::EndpointDescriptor>::success(std::move(ep));
}

Result<void>
MpPartyRuntime::send_endpoint_update(const mp::EndpointDescriptor &endpoint) {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return op;
  }
  if (!ws_.has_value() || !ws_->is_open()) {
    return fail_void(ErrorCode::provider_transport,
                     MpPartyRuntimeError::control_disconnected);
  }
  const std::string_view expected_relay =
      (config_.local_relay_policy != mp::RelayPolicy::no_relays &&
       config_.relay_url.has_value())
          ? std::string_view{*config_.relay_url}
          : std::string_view{};
  if (const auto valid =
          endpoint.validate_against_policy(config_.local_relay_policy, expected_relay);
      !valid.has_value()) {
    return valid;
  }
  const std::uint32_t seq = next_ws_seq_++;
  if (next_ws_seq_ == 0U) {
    next_ws_seq_ = 1U;
  }
  const auto res =
      ws_->send_mp1(seq, mp::Mp1Message{mp::PartyEndpointUpdateMessage{endpoint}});
  if (!res.has_value()) {
    handle_transient_ws_disconnect(1006U, res.error(), SteadyClock::now());
    return res;
  }
  last_published_endpoint_ = endpoint;
  return Result<void>::success();
}

Result<void> MpPartyRuntime::send_endpoint_update() {
  const auto ep = local_endpoint_descriptor();
  if (!ep.has_value()) {
    return Result<void>::failure(ep.error());
  }
  return send_endpoint_update(ep.value());
}

Result<void> MpPartyRuntime::send_heartbeat_ping() {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return op;
  }
  if (!ws_.has_value() || !ws_->is_open()) {
    return fail_void(ErrorCode::provider_transport,
                     MpPartyRuntimeError::control_disconnected);
  }
  const auto res = ws_->send_ping();
  last_ping_sent_at_ = SteadyClock::now();
  if (!res.has_value()) {
    handle_transient_ws_disconnect(1006U, res.error(), last_ping_sent_at_);
    return res;
  }
  return Result<void>::success();
}

void MpPartyRuntime::publish_local_endpoint_if_changed() {
  if (!is_control_connected()) {
    return;
  }
  const auto ep = local_endpoint_descriptor();
  if (!ep.has_value()) {
    MpRuntimeEvent err_ev{};
    err_ev.kind = MpRuntimeEventKind::control_error;
    err_ev.error = ep.error();
    push_event(std::move(err_ev));
    return;
  }
  if (last_published_endpoint_.has_value() && *last_published_endpoint_ == ep.value()) {
    return;
  }
  (void)send_endpoint_update(ep.value());
}

// ---------------------------------------------------------------------------
// Reconnect, heartbeat, and pending dial retry helpers
// ---------------------------------------------------------------------------

std::uint32_t MpPartyRuntime::compute_reconnect_backoff_ms(
    std::uint32_t attempt_index) const noexcept {
  const std::uint32_t shift = std::min<std::uint32_t>(attempt_index, 20U);
  const std::uint64_t scaled = static_cast<std::uint64_t>(config_.reconnect_base_ms)
                               << shift;
  const auto capped = std::min<std::uint64_t>(
      scaled, static_cast<std::uint64_t>(config_.reconnect_max_ms));
  return static_cast<std::uint32_t>(capped);
}

void MpPartyRuntime::handle_transient_ws_disconnect(
    std::uint16_t close_code, std::optional<Error> err,
    SteadyClock::time_point steady_now) {
  if (is_terminated()) {
    return;
  }
  if (ws_.has_value()) {
    (void)ws_->close(1000U);
    ws_.reset();
  }
  state_ = MpRuntimeState::reconnecting;
  reconnect_attempts_ = 0U;
  last_ping_sent_override_s_.reset();
  if (config_.max_reconnect_attempts > 0U) {
    next_reconnect_at_ =
        steady_now + std::chrono::milliseconds{compute_reconnect_backoff_ms(0U)};
  }
  MpRuntimeEvent ev{};
  ev.kind = MpRuntimeEventKind::control_disconnected;
  ev.ws_close_code = close_code;
  ev.error = err;
  push_event(std::move(ev));
}

void MpPartyRuntime::handle_hard_teardown(std::uint16_t close_code) {
  if (ws_.has_value()) {
    (void)ws_->close(1000U);
    ws_.reset();
  }
  const mp::MemberLeaveReason reason = (close_code == kMpWsCloseDeviceRevoked)
                                           ? mp::MemberLeaveReason::device_revoked
                                           : mp::MemberLeaveReason::kicked;
  teardown_p2p_session(reason);
  state_ = MpRuntimeState::terminated;
  MpRuntimeEvent ev{};
  ev.kind = MpRuntimeEventKind::kicked_or_revoked;
  ev.ws_close_code = close_code;
  ev.party_epoch = session_.party_epoch();
  push_event(std::move(ev));
}

void MpPartyRuntime::maybe_attempt_reconnect(SteadyClock::time_point steady_now) {
  if (state_ != MpRuntimeState::reconnecting || ws_.has_value() ||
      reconnect_attempts_ >= config_.max_reconnect_attempts ||
      steady_now < next_reconnect_at_) {
    return;
  }
  const std::uint32_t attempt_index = reconnect_attempts_;
  ++reconnect_attempts_;

  auto sock = control_client_.connect_party_socket(config_.party_id);
  if (sock.has_value()) {
    ws_.emplace(std::move(sock).value());
    state_ = MpRuntimeState::attaching;
    reconnect_attempts_ = 0U;
    last_published_endpoint_.reset();
    last_ping_sent_at_ = steady_now;
    last_ping_sent_override_s_.reset();
    last_pong_at_ = steady_now;
    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::control_reconnected;
    ev.party_epoch = session_.party_epoch();
    push_event(std::move(ev));
    return;
  }

  const Error err = sock.error();
  // MpControlClient::connect_party_socket() already performs /v1/health clock-skew
  // recovery once before returning non-skew provider_auth (e.g. HTTP 401 when the
  // device was revoked while offline): immediately hard-teardown live P2P peers.
  if (err.code == ErrorCode::provider_auth &&
      mp::mp_client_error_of(err) != mp::MpClientError::http_clock_skew) {
    handle_hard_teardown(kMpWsCloseDeviceRevoked);
    return;
  }
  if (reconnect_attempts_ >= config_.max_reconnect_attempts) {
    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::control_error;
    ev.party_epoch = session_.party_epoch();
    ev.error =
        Error{ErrorCode::provider_transport,
              static_cast<std::int64_t>(MpPartyRuntimeError::reconnect_exhausted)};
    push_event(std::move(ev));
    return;
  }

  const std::uint32_t next_delay_ms = compute_reconnect_backoff_ms(attempt_index + 1U);
  next_reconnect_at_ = steady_now + std::chrono::milliseconds{next_delay_ms};
}

void MpPartyRuntime::maybe_send_heartbeat_ping(
    const HandleContext &ctx, std::optional<std::int64_t> now_s_override) {
  if (is_terminated() || state_ != MpRuntimeState::connected || !ws_.has_value() ||
      !ws_->is_open()) {
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

bool MpPartyRuntime::has_pending_dial_peers() const noexcept {
  const auto all_peers = session_.peers();
  return std::any_of(all_peers.begin(), all_peers.end(), [](const P2pPartyPeer &peer) {
    return peer.we_dial && peer.connection_state != P2pPeerConnectionState::connected;
  });
}

void MpPartyRuntime::maybe_retry_pending_dials(SteadyClock::time_point steady_now) {
  if (is_terminated() || !session_.has_endpoint() || !session_.has_active_party() ||
      session_.disbanded() || !has_pending_dial_peers() ||
      steady_now < next_dial_retry_at_) {
    return;
  }
  const auto dial_res = session_.connect_pending_peers();
  if (dial_res.has_value() && dial_res.value().failures.empty() &&
      !has_pending_dial_peers()) {
    dial_retry_backoff_ms_ = kInitialDialRetryBackoffMs;
    return;
  }
  next_dial_retry_at_ = steady_now + std::chrono::milliseconds{dial_retry_backoff_ms_};
  dial_retry_backoff_ms_ =
      std::min<std::uint32_t>(dial_retry_backoff_ms_ * 2U, kMaxDialRetryBackoffMs);
}

// ---------------------------------------------------------------------------
// Control-plane message dispatch
// ---------------------------------------------------------------------------

void MpPartyRuntime::handle_ws_event(const mp::MpWsEvent &event,
                                     const HandleContext &ctx) {
  if (const auto *mp1 = std::get_if<mp::MpWsMp1Frame>(&event)) {
    handle_mp1_message(mp1->frame.message, ctx);
    return;
  }
  if (std::holds_alternative<mp::MpWsPong>(event)) {
    last_pong_at_ = ctx.steady_now;
    last_pong_ms_ = current_unix_ms();
    if (state_ == MpRuntimeState::connected && session_.has_active_party() &&
        !session_.disbanded()) {
      (void)session_.refresh_all_leases(ctx.now_s);
    }
    return;
  }
  if (const auto *closed = std::get_if<mp::MpWsClosed>(&event)) {
    if (closed->code == kMpWsCloseDeviceRevoked ||
        closed->code == kMpWsCloseKickedOrBanned) {
      handle_hard_teardown(closed->code);
      return;
    }
    handle_transient_ws_disconnect(closed->code, std::nullopt, ctx.steady_now);
  }
}

void MpPartyRuntime::handle_mp1_message(const mp::Mp1Message &message,
                                        const HandleContext &ctx) {
  if (const auto *hello = std::get_if<mp::HelloAckMessage>(&message)) {
    session_id_ = hello->session_id;
    ping_interval_ms_ = std::clamp(hello->ping_interval_ms, kMpRuntimeMinPingIntervalMs,
                                   kMpRuntimeMaxPingIntervalMs);
    // Reject implausible server_now_ms (e.g. 0 / pre-2001) so a misbehaving
    // server cannot roll back local signing or lease-expiry clocks.
    constexpr std::uint64_t kMinPlausibleServerNowMs = 1000000000000ULL;
    if (hello->server_now_ms >= kMinPlausibleServerNowMs) {
      const auto server_s = static_cast<std::int64_t>(hello->server_now_ms / 1000U);
      clock_skew_s_ = saturating_sub_i64(server_s, current_unix_seconds());
      control_client_.set_clock_offset_seconds(clock_skew_s_);
      if (!session_.has_active_party()) {
        last_effective_now_s_.reset();
      }
    }
    state_ = MpRuntimeState::connected;
    last_ping_sent_at_ = ctx.steady_now;
    if (ctx.has_override_now) {
      last_ping_sent_override_s_ = ctx.now_s;
    } else {
      last_ping_sent_override_s_.reset();
    }
    last_pong_at_ = ctx.steady_now;

    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::hello_acked;
    ev.session_id = hello->session_id;
    ev.party_epoch = session_.party_epoch();
    push_event(std::move(ev));

    publish_local_endpoint_if_changed();
    return;
  }

  if (const auto *snap = std::get_if<mp::PartySnapshotMessage>(&message)) {
    if (snap->party_id != config_.party_id) {
      MpRuntimeEvent err_ev{};
      err_ev.kind = MpRuntimeEventKind::control_error;
      err_ev.party_epoch = snap->party_epoch;
      err_ev.error = Error{ErrorCode::conflict,
                           static_cast<std::int64_t>(P2pPartyError::party_id_mismatch)};
      push_event(std::move(err_ev));
      return;
    }
    if (config_.local_relay_policy == mp::RelayPolicy::force_relays &&
        config_.relay_url.has_value() && snap->pinned_relay_url != *config_.relay_url) {
      MpRuntimeEvent err_ev{};
      err_ev.kind = MpRuntimeEventKind::control_error;
      err_ev.party_epoch = snap->party_epoch;
      err_ev.error =
          Error{ErrorCode::conflict,
                static_cast<std::int64_t>(P2pPartyError::relay_policy_mismatch)};
      push_event(std::move(err_ev));
      return;
    }
    auto snap_res = session_.apply_snapshot(*snap, ctx.now_s);
    if (!snap_res.has_value()) {
      MpRuntimeEvent err_ev{};
      err_ev.kind = MpRuntimeEventKind::control_error;
      err_ev.party_epoch = snap->party_epoch;
      err_ev.error = snap_res.error();
      push_event(std::move(err_ev));
      return;
    }
    P2pPartySnapshotResult report = std::move(snap_res).value();
    if (session_.has_endpoint()) {
      dial_retry_backoff_ms_ = kInitialDialRetryBackoffMs;
      next_dial_retry_at_ =
          ctx.steady_now + std::chrono::milliseconds{dial_retry_backoff_ms_};
    }
    (void)session_.refresh_all_leases(ctx.now_s);

    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::snapshot_applied;
    ev.party_epoch = session_.party_epoch();
    ev.snapshot_result = std::move(report);
    push_event(std::move(ev));
    return;
  }

  if (const auto *joined = std::get_if<mp::PartyMemberJoinedMessage>(&message)) {
    const auto res = session_.apply_member_joined(*joined, ctx.now_s);
    if (!res.has_value()) {
      MpRuntimeEvent err_ev{};
      err_ev.kind = MpRuntimeEventKind::control_error;
      err_ev.party_epoch = joined->party_epoch;
      err_ev.device_id = joined->member.device_id;
      err_ev.account_id = joined->member.account_id;
      err_ev.error = res.error();
      push_event(std::move(err_ev));
      return;
    }
    if (session_.has_endpoint() && config_.identity.device_id.has_value() &&
        should_dial_peer(LocalDeviceId{config_.identity.device_id->value()},
                         PeerDeviceId{joined->member.device_id.value()})) {
      dial_retry_backoff_ms_ = kInitialDialRetryBackoffMs;
      next_dial_retry_at_ =
          ctx.steady_now + std::chrono::milliseconds{dial_retry_backoff_ms_};
    }
    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::member_joined;
    ev.party_epoch = session_.party_epoch();
    ev.device_id = joined->member.device_id;
    ev.account_id = joined->member.account_id;
    push_event(std::move(ev));
    return;
  }

  if (const auto *updated = std::get_if<mp::PartyMemberUpdatedMessage>(&message)) {
    const auto res = session_.apply_member_updated(*updated, ctx.now_s);
    if (!res.has_value()) {
      MpRuntimeEvent err_ev{};
      err_ev.kind = MpRuntimeEventKind::control_error;
      err_ev.party_epoch = updated->party_epoch;
      err_ev.device_id = updated->device_id;
      err_ev.error = res.error();
      push_event(std::move(err_ev));
      return;
    }
    if (session_.has_endpoint()) {
      const auto peer = session_.find_peer(updated->device_id);
      if (peer.has_value() && peer->we_dial &&
          peer->connection_state != P2pPeerConnectionState::connected) {
        dial_retry_backoff_ms_ = kInitialDialRetryBackoffMs;
        next_dial_retry_at_ =
            ctx.steady_now + std::chrono::milliseconds{dial_retry_backoff_ms_};
      }
    }
    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::member_updated;
    ev.party_epoch = session_.party_epoch();
    ev.device_id = updated->device_id;
    push_event(std::move(ev));
    return;
  }

  if (const auto *left = std::get_if<mp::PartyMemberLeftMessage>(&message)) {
    const auto res = session_.apply_member_left(*left);
    if (!res.has_value()) {
      MpRuntimeEvent err_ev{};
      err_ev.kind = MpRuntimeEventKind::control_error;
      err_ev.party_epoch = left->party_epoch;
      err_ev.device_id = left->device_id;
      err_ev.account_id = left->account_id;
      err_ev.leave_reason = left->reason;
      err_ev.error = res.error();
      push_event(std::move(err_ev));
      return;
    }
    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::member_left;
    ev.party_epoch = session_.party_epoch();
    ev.device_id = left->device_id;
    ev.account_id = left->account_id;
    ev.leave_reason = left->reason;
    push_event(std::move(ev));

    if (config_.identity.device_id.has_value() &&
        left->device_id == *config_.identity.device_id) {
      if (ws_.has_value()) {
        (void)ws_->close(1000U);
        ws_.reset();
      }
      session_.close();
      state_ = MpRuntimeState::terminated;
    }
    return;
  }

  if (const auto *leader = std::get_if<mp::PartyLeaderChangedMessage>(&message)) {
    const auto res = session_.apply_leader_changed(*leader);
    if (!res.has_value()) {
      MpRuntimeEvent err_ev{};
      err_ev.kind = MpRuntimeEventKind::control_error;
      err_ev.party_epoch = leader->party_epoch;
      err_ev.error = res.error();
      push_event(std::move(err_ev));
      return;
    }
    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::leader_changed;
    ev.party_epoch = session_.party_epoch();
    ev.account_id = leader->new_leader_account_id;
    ev.device_id = leader->new_leader_device_id;
    ev.leader_change_reason = leader->reason;
    push_event(std::move(ev));
    return;
  }

  if (const auto *disbanded = std::get_if<mp::PartyDisbandedMessage>(&message)) {
    if (disbanded->party_epoch == 0U || disbanded->party_epoch > mp::kMaxSafeId) {
      MpRuntimeEvent err_ev{};
      err_ev.kind = MpRuntimeEventKind::control_error;
      err_ev.party_epoch = disbanded->party_epoch;
      err_ev.error =
          Error{ErrorCode::invalid_range,
                static_cast<std::int64_t>(P2pPartyError::invalid_party_epoch)};
      push_event(std::move(err_ev));
      return;
    }
    if (session_.has_active_party()) {
      const auto res = session_.apply_disbanded(*disbanded);
      if (!res.has_value()) {
        MpRuntimeEvent err_ev{};
        err_ev.kind = MpRuntimeEventKind::control_error;
        err_ev.party_epoch = disbanded->party_epoch;
        err_ev.error = res.error();
        push_event(std::move(err_ev));
        return;
      }
    }
    if (ws_.has_value()) {
      (void)ws_->close(1000U);
      ws_.reset();
    }
    session_.close();
    state_ = MpRuntimeState::disbanded;

    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::party_disbanded;
    ev.party_epoch = disbanded->party_epoch;
    ev.disband_reason = disbanded->reason;
    push_event(std::move(ev));
    return;
  }

  if (const auto *server_err = std::get_if<mp::ErrorMessage>(&message)) {
    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::control_error;
    ev.server_error = *server_err;
    push_event(std::move(ev));
    return;
  }

  if (const auto *join_req = std::get_if<mp::PartyJoinRequestEventMessage>(&message)) {
    MpRuntimeEvent ev{};
    ev.kind = MpRuntimeEventKind::join_request_received;
    ev.account_id = join_req->account_id;
    ev.device_id = join_req->device_id;
    ev.join_request = *join_req;
    push_event(std::move(ev));
    return;
  }

  MpRuntimeEvent err_ev{};
  err_ev.kind = MpRuntimeEventKind::control_error;
  err_ev.error =
      Error{ErrorCode::corrupt,
            static_cast<std::int64_t>(MpPartyRuntimeError::unexpected_opcode)};
  push_event(std::move(err_ev));
}

// ---------------------------------------------------------------------------
// P2P event translation
// ---------------------------------------------------------------------------

void MpPartyRuntime::translate_and_push_p2p_event(P2pPartyEvent &&p2p_ev) {
  MpRuntimeEvent out{};
  out.lane = p2p_ev.lane;
  out.peer_pubkey = p2p_ev.peer_pubkey;
  out.sender_device_id = p2p_ev.sender_device_id;
  out.sender_account_id = p2p_ev.sender_account_id;
  out.device_id = p2p_ev.sender_device_id;
  out.account_id = p2p_ev.sender_account_id;
  out.reason_code = p2p_ev.reason_code;
  out.error = p2p_ev.drop_error;

  switch (p2p_ev.kind) {
  case P2pPartyEventKind::peer_connected:
    out.kind = MpRuntimeEventKind::peer_connected;
    push_event(std::move(out));
    return;
  case P2pPartyEventKind::peer_disconnected:
    out.kind = MpRuntimeEventKind::peer_disconnected;
    push_event(std::move(out));
    return;
  case P2pPartyEventKind::frame_dropped:
    out.kind = MpRuntimeEventKind::frame_dropped;
    push_event(std::move(out));
    return;
  case P2pPartyEventKind::frame_received:
    if (!p2p_ev.frame.has_value()) {
      out.kind = MpRuntimeEventKind::frame_dropped;
      push_event(std::move(out));
      return;
    }
    if (auto *chat = std::get_if<P2pPartyChatMessage>(&*p2p_ev.frame)) {
      out.kind = MpRuntimeEventKind::chat_received;
      out.chat = std::move(*chat);
    } else if (auto *bridge = std::get_if<P2pPartyBridgeEnvelope>(&*p2p_ev.frame)) {
      out.kind = MpRuntimeEventKind::bridge_envelope_received;
      out.bridge_envelope = std::move(*bridge);
    } else if (auto *notice = std::get_if<P2pPartyControlNotice>(&*p2p_ev.frame)) {
      out.kind = MpRuntimeEventKind::control_notice_received;
      out.control_notice = std::move(*notice);
    } else if (auto *pulse = std::get_if<P2pPartyEphemeralPulse>(&*p2p_ev.frame)) {
      out.kind = MpRuntimeEventKind::ephemeral_pulse_received;
      out.ephemeral_pulse = std::move(*pulse);
    } else {
      out.kind = MpRuntimeEventKind::frame_dropped;
    }
    push_event(std::move(out));
    return;
  }
}

// ---------------------------------------------------------------------------
// Step-driven pump_once
// ---------------------------------------------------------------------------

std::int64_t MpPartyRuntime::compute_effective_now_s(
    std::optional<std::int64_t> now_s_override) noexcept {
  if (now_s_override.has_value()) {
    return *now_s_override;
  }
  std::int64_t now_s = saturating_add_i64(current_unix_seconds(),
                                          control_client_.clock_offset_seconds());
  // Enforce a monotonic floor only once an active party has established its
  // server-adjusted baseline, so negative clock_skew_s_ from initial HelloAck
  // is never masked by a fast local clock.
  if (session_.has_active_party()) {
    if (last_effective_now_s_.has_value() && now_s < *last_effective_now_s_) {
      now_s = *last_effective_now_s_;
    }
    last_effective_now_s_ = now_s;
  }
  return now_s;
}

Result<std::size_t>
MpPartyRuntime::pump_once(std::uint32_t timeout_ms,
                          std::optional<std::int64_t> now_s_override) {
  if (is_terminated()) {
    return Result<std::size_t>::success(0U);
  }

  pushed_this_pump_ = 0U;
  const auto pump_start = SteadyClock::now();
  const auto pump_deadline = pump_start + std::chrono::milliseconds{timeout_ms};

  // 1. Bounded exponential reconnect when control WS is down.
  if (state_ == MpRuntimeState::reconnecting && !ws_.has_value()) {
    maybe_attempt_reconnect(pump_start);
  }

  // 2. Poll MpControlSocket (short bounded slice, draining coalesced frames).
  if (!is_terminated() && ws_.has_value() && ws_->is_open()) {
    const std::uint32_t first_ws_timeout_ms =
        (timeout_ms == 0U) ? 0U
                           : (session_.has_endpoint()
                                  ? std::min<std::uint32_t>(
                                        std::max<std::uint32_t>(1U, timeout_ms / 2U),
                                        kMaxWsSliceWithP2pMs)
                                  : timeout_ms);
    const std::uint32_t clamped_ws_ms = std::min<std::uint32_t>(
        first_ws_timeout_ms,
        static_cast<std::uint32_t>(std::numeric_limits<int>::max()));

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
      // Recompute effective now_s per frame so coalesced frames behind HelloAck
      // immediately use the updated server clock-skew offset.
      const std::int64_t frame_now_s = compute_effective_now_s(now_s_override);
      handle_ws_event(*ws_opt,
                      HandleContext{frame_now_s, now_tick, now_s_override.has_value()});
    }
  }

  const std::int64_t post_ws_now_s = compute_effective_now_s(now_s_override);

  // 3. Send MP1:PING heartbeat whenever ping_interval_ms elapses.
  if (!is_terminated()) {
    maybe_send_heartbeat_ping(
        HandleContext{post_ws_now_s, SteadyClock::now(), now_s_override.has_value()},
        now_s_override);
  }

  // 4. Retry any dial_pending peers whose initial handshake raced peer allowlisting.
  if (!is_terminated()) {
    maybe_retry_pending_dials(SteadyClock::now());
  }

  // 5. Enforce <= 60s lease-TTL & CWT expiry even while control WS is disconnected.
  if (!is_terminated() && session_.peer_count() > 0U) {
    std::map<mp::DeviceId, std::pair<mp::AccountId, P2pPubkey>> peer_meta;
    for (const auto &peer : session_.peers()) {
      peer_meta.emplace(peer.device_id,
                        std::make_pair(peer.account_id, peer.device_pubkey));
    }
    const auto evicted = session_.evict_expired_peers(post_ws_now_s);
    if (evicted.has_value()) {
      for (const auto dev_id : evicted.value()) {
        MpRuntimeEvent ev{};
        ev.kind = MpRuntimeEventKind::peer_evicted;
        ev.device_id = dev_id;
        ev.sender_device_id = dev_id;
        ev.reason_code = 4403U;
        if (const auto it = peer_meta.find(dev_id); it != peer_meta.end()) {
          ev.account_id = it->second.first;
          ev.sender_account_id = it->second.first;
          ev.peer_pubkey = it->second.second;
        }
        push_event(std::move(ev));
      }
    }
  }

  // 6. Pump live P2pPartySession events across Lanes 0/1/2.
  if (!is_terminated() && session_.has_endpoint()) {
    const auto now_before_p2p = SteadyClock::now();
    std::uint32_t first_p2p_timeout_ms = 0U;
    if (timeout_ms > 0U && now_before_p2p < pump_deadline) {
      const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 pump_deadline - now_before_p2p)
                                 .count();
      if (remaining > 0) {
        first_p2p_timeout_ms = static_cast<std::uint32_t>(remaining);
      }
    }

    for (std::size_t i = 0U; i < kMaxP2pEventsPerPump; ++i) {
      if (is_terminated() || !session_.has_endpoint()) {
        break;
      }
      const std::uint32_t slice_ms = (i == 0U) ? first_p2p_timeout_ms : 0U;
      auto polled =
          session_.poll_event(PollTimeoutMs{slice_ms}, PartyNowSeconds{post_ws_now_s});
      if (!polled.has_value()) {
        MpRuntimeEvent err_ev{};
        err_ev.kind = MpRuntimeEventKind::control_error;
        err_ev.error = polled.error();
        push_event(std::move(err_ev));
        break;
      }
      auto &p2p_opt = polled.value();
      if (!p2p_opt.has_value()) {
        break;
      }
      translate_and_push_p2p_event(std::move(*p2p_opt));
    }
  }

  return Result<std::size_t>::success(pushed_this_pump_);
}

// ---------------------------------------------------------------------------
// Outbound P2P senders (fail closed on terminated / disbanded runtime)
// ---------------------------------------------------------------------------

Result<P2pPartyBroadcastResult>
MpPartyRuntime::broadcast_chat(const P2pPartyChatMessage &message) {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return Result<P2pPartyBroadcastResult>::failure(op.error());
  }
  return session_.broadcast_chat(message);
}

Result<void> MpPartyRuntime::send_chat_to(mp::DeviceId device_id,
                                          const P2pPartyChatMessage &message) {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return op;
  }
  return session_.send_chat_to(device_id, message);
}

Result<P2pPartyBroadcastResult>
MpPartyRuntime::broadcast_bridge_envelope(const P2pPartyBridgeEnvelope &envelope) {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return Result<P2pPartyBroadcastResult>::failure(op.error());
  }
  return session_.broadcast_bridge_envelope(envelope);
}

Result<void>
MpPartyRuntime::send_bridge_envelope_to(mp::DeviceId device_id,
                                        const P2pPartyBridgeEnvelope &envelope) {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return op;
  }
  return session_.send_bridge_envelope_to(device_id, envelope);
}

Result<P2pPartyBroadcastResult>
MpPartyRuntime::broadcast_control_notice(const P2pPartyControlNotice &notice) {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return Result<P2pPartyBroadcastResult>::failure(op.error());
  }
  return session_.broadcast_control_notice(notice);
}

Result<void>
MpPartyRuntime::send_control_notice_to(mp::DeviceId device_id,
                                       const P2pPartyControlNotice &notice) {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return op;
  }
  return session_.send_control_notice_to(device_id, notice);
}

Result<P2pPartyBroadcastResult>
MpPartyRuntime::broadcast_ephemeral_pulse(const P2pPartyEphemeralPulse &pulse) {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return Result<P2pPartyBroadcastResult>::failure(op.error());
  }
  return session_.broadcast_ephemeral_pulse(pulse);
}

Result<void>
MpPartyRuntime::send_ephemeral_pulse_to(mp::DeviceId device_id,
                                        const P2pPartyEphemeralPulse &pulse) {
  if (const auto op = ensure_operational(); !op.has_value()) {
    return op;
  }
  return session_.send_ephemeral_pulse_to(device_id, pulse);
}

} // namespace blackbird
