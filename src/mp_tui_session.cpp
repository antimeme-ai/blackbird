#include "blackbird/mp_tui_session.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <pthread.h>
#include <signal.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>

namespace blackbird {

namespace {

template <typename T> Result<T> fail(ErrorCode code, MpTuiSessionError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_void(ErrorCode code, MpTuiSessionError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

class ScopedPipeEnd {
public:
  ScopedPipeEnd() noexcept = default;
  explicit ScopedPipeEnd(int fd) noexcept : fd_(fd) {}
  ScopedPipeEnd(const ScopedPipeEnd &) = delete;
  ScopedPipeEnd &operator=(const ScopedPipeEnd &) = delete;
  ~ScopedPipeEnd() { reset(); }

  int get() const noexcept { return fd_; }
  int release() noexcept { return std::exchange(fd_, -1); }

  void reset(int next = -1) noexcept {
    if (fd_ >= 0) {
      (void)::close(fd_);
    }
    fd_ = next;
  }

private:
  int fd_ = -1;
};

bool configure_nonblock_cloexec(int fd) noexcept {
  const int fd_flags = ::fcntl(fd, F_GETFD, 0);
  if (fd_flags < 0 || ::fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
    return false;
  }
  const int status_flags = ::fcntl(fd, F_GETFL, 0);
  if (status_flags < 0 || ::fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) < 0) {
    return false;
  }
  return true;
}

void block_sigpipe_this_thread() noexcept {
  sigset_t sigpipe_set{};
  sigemptyset(&sigpipe_set);
  sigaddset(&sigpipe_set, SIGPIPE);
  (void)::pthread_sigmask(SIG_BLOCK, &sigpipe_set, nullptr);
}

bool is_valid_utf8_strict(std::string_view text) noexcept {
  const auto *bytes = reinterpret_cast<const std::uint8_t *>(text.data());
  const std::size_t len = text.size();
  std::size_t i = 0U;
  while (i < len) {
    const std::uint8_t b0 = bytes[i];
    if (b0 <= 0x7fU) {
      ++i;
      continue;
    }
    if (b0 >= 0xc2U && b0 <= 0xdfU) {
      if (i + 1U >= len || (bytes[i + 1U] & 0xc0U) != 0x80U) {
        return false;
      }
      i += 2U;
      continue;
    }
    if (b0 >= 0xe0U && b0 <= 0xefU) {
      if (i + 2U >= len || (bytes[i + 1U] & 0xc0U) != 0x80U ||
          (bytes[i + 2U] & 0xc0U) != 0x80U) {
        return false;
      }
      if ((b0 == 0xe0U && bytes[i + 1U] < 0xa0U) ||
          (b0 == 0xedU && bytes[i + 1U] >= 0xa0U)) {
        return false;
      }
      i += 3U;
      continue;
    }
    if (b0 >= 0xf0U && b0 <= 0xf4U) {
      if (i + 3U >= len || (bytes[i + 1U] & 0xc0U) != 0x80U ||
          (bytes[i + 2U] & 0xc0U) != 0x80U || (bytes[i + 3U] & 0xc0U) != 0x80U) {
        return false;
      }
      if ((b0 == 0xf0U && bytes[i + 1U] < 0x90U) ||
          (b0 == 0xf4U && bytes[i + 1U] > 0x8fU)) {
        return false;
      }
      i += 4U;
      continue;
    }
    return false;
  }
  return true;
}

std::int64_t current_unix_ns() noexcept {
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
  return ns > 0 ? static_cast<std::int64_t>(ns) : 1;
}

std::int64_t seconds_to_ns_clamped(std::int64_t secs) noexcept {
  if (secs <= 0) {
    return 0;
  }
  constexpr std::int64_t kNsPerSec = 1000000000LL;
  if (secs > std::numeric_limits<std::int64_t>::max() / kNsPerSec) {
    return std::numeric_limits<std::int64_t>::max();
  }
  return secs * kNsPerSec;
}

bool is_terminated_runtime_state(MpRuntimeState st) noexcept {
  return st == MpRuntimeState::disbanded || st == MpRuntimeState::terminated;
}

std::string compute_fingerprint_safe(const P2pPubkey &pubkey) {
  const auto fp = mp::compute_device_fingerprint(pubkey);
  return fp.has_value() ? fp.value() : std::string{};
}

std::string compute_optional_fingerprint_safe(const std::optional<P2pPubkey> &pubkey) {
  return pubkey.has_value() ? compute_fingerprint_safe(*pubkey) : std::string{};
}

std::string base64_encode_pubkey(const P2pPubkey &pubkey) {
  static constexpr char kAlpha[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(44U);
  std::size_t i = 0U;
  while (i + 3U <= pubkey.size()) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(pubkey[i]) << 16U) |
                                 (static_cast<std::uint32_t>(pubkey[i + 1U]) << 8U) |
                                 static_cast<std::uint32_t>(pubkey[i + 2U]);
    out.push_back(kAlpha[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlpha[(triple >> 6U) & 0x3fU]);
    out.push_back(kAlpha[triple & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = pubkey.size() - i;
  if (rem == 1U) {
    const std::uint32_t triple = static_cast<std::uint32_t>(pubkey[i]) << 16U;
    out.push_back(kAlpha[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(triple >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(pubkey[i]) << 16U) |
                                 (static_cast<std::uint32_t>(pubkey[i + 1U]) << 8U);
    out.push_back(kAlpha[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlpha[(triple >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

void dedup_account_ids_in_place(std::vector<mp::AccountId> &ids) {
  std::size_t write = 0U;
  for (std::size_t read = 0U; read < ids.size(); ++read) {
    const auto id = ids[read];
    bool seen = false;
    for (std::size_t j = 0U; j < write; ++j) {
      if (ids[j] == id) {
        seen = true;
        break;
      }
    }
    if (!seen) {
      ids[write++] = id;
    }
  }
  ids.erase(ids.begin() + static_cast<std::ptrdiff_t>(write), ids.end());
}

std::optional<std::uint64_t>
parse_optional_u64_decimal(const std::optional<std::string> &text) noexcept {
  if (!text.has_value() || text->empty()) {
    return std::nullopt;
  }
  std::uint64_t val = 0U;
  const char *begin = text->data();
  const char *end = begin + text->size();
  const auto res = std::from_chars(begin, end, val, 10);
  if (res.ec != std::errc{} || res.ptr != end || val == 0U) {
    return std::nullopt;
  }
  return val;
}

PartyParticipantState
map_activity_to_participant_state(P2pPartyActivityState st) noexcept {
  switch (st) {
  case P2pPartyActivityState::offline:
    return PartyParticipantState::offline;
  case P2pPartyActivityState::online:
    return PartyParticipantState::online;
  case P2pPartyActivityState::working:
  case P2pPartyActivityState::typing:
    return PartyParticipantState::working;
  case P2pPartyActivityState::idle:
    return PartyParticipantState::idle;
  }
  return PartyParticipantState::online;
}

std::string_view leave_reason_text(mp::MemberLeaveReason reason) noexcept {
  switch (reason) {
  case mp::MemberLeaveReason::left:
    return "left";
  case mp::MemberLeaveReason::kicked:
    return "kicked";
  case mp::MemberLeaveReason::disconnected_timeout:
    return "disconnected_timeout";
  case mp::MemberLeaveReason::device_revoked:
    return "device_revoked";
  case mp::MemberLeaveReason::connect_timeout:
    return "connect_timeout";
  }
  return "unknown";
}

std::string_view
leader_change_reason_text(mp::PartyLeaderChangeReason reason) noexcept {
  switch (reason) {
  case mp::PartyLeaderChangeReason::promoted:
    return "promoted";
  case mp::PartyLeaderChangeReason::auto_migrated:
    return "auto_migrated";
  }
  return "unknown";
}

std::string_view disband_reason_text(mp::PartyDisbandReason reason) noexcept {
  switch (reason) {
  case mp::PartyDisbandReason::leader_disbanded:
    return "leader_disbanded";
  case mp::PartyDisbandReason::empty_timeout:
    return "empty_timeout";
  }
  return "unknown";
}

Result<void> validate_text_field(std::string_view text, std::size_t max_bytes,
                                 bool allow_empty) {
  if (!allow_empty && text.empty()) {
    return fail_void(ErrorCode::invalid_range, MpTuiSessionError::invalid_field);
  }
  if (text.size() > max_bytes) {
    return fail_void(ErrorCode::capacity, MpTuiSessionError::field_too_large);
  }
  if (!is_valid_utf8_strict(text)) {
    return fail_void(ErrorCode::corrupt, MpTuiSessionError::invalid_utf8);
  }
  return Result<void>::success();
}

std::string resolve_local_wire_handle(const MpTuiSessionConfig &config) {
  if (config.local_handle.has_value() && !config.local_handle->empty()) {
    return *config.local_handle;
  }
  const auto &id = config.runtime_config.identity;
  if (!id.handle.empty() && id.handle.size() <= kP2pPartyMaxSenderHandleBytes &&
      is_valid_utf8_strict(id.handle)) {
    return id.handle;
  }
  if (id.device_id.has_value()) {
    if (const auto it = config.peer_metadata.find(id.device_id->value());
        it != config.peer_metadata.end() && !it->second.handle.empty() &&
        it->second.handle.size() <= kP2pPartyMaxSenderHandleBytes &&
        is_valid_utf8_strict(it->second.handle)) {
      return it->second.handle;
    }
    return "peer_" + id.device_id->to_decimal();
  }
  return "local";
}

} // namespace

// ---------------------------------------------------------------------------
// Error naming
// ---------------------------------------------------------------------------

std::string_view mp_tui_session_error_name(MpTuiSessionError detail) noexcept {
  switch (detail) {
  case MpTuiSessionError::none:
    return "none";
  case MpTuiSessionError::invalid_config:
    return "invalid_config";
  case MpTuiSessionError::session_stopped:
    return "session_stopped";
  case MpTuiSessionError::queue_full:
    return "queue_full";
  case MpTuiSessionError::invalid_field:
    return "invalid_field";
  case MpTuiSessionError::field_too_large:
    return "field_too_large";
  case MpTuiSessionError::invalid_utf8:
    return "invalid_utf8";
  case MpTuiSessionError::wake_pipe_failed:
    return "wake_pipe_failed";
  case MpTuiSessionError::send_timeout:
    return "send_timeout";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// MpTuiSession lifecycle
// ---------------------------------------------------------------------------

Result<std::unique_ptr<MpTuiSession>> MpTuiSession::start(MpTuiSessionConfig config) {
  if (config.max_retained_messages == 0U) {
    return fail<std::unique_ptr<MpTuiSession>>(ErrorCode::invalid_range,
                                               MpTuiSessionError::invalid_config);
  }
  const std::size_t max_messages = std::clamp<std::size_t>(
      config.max_retained_messages, 1U, kMpTuiMaxRetainedMessagesCap);
  const std::uint32_t tick_ms =
      std::clamp(config.pump_tick_ms, kMpTuiMinPumpTickMs, kMpTuiMaxPumpTickMs);

  std::string scope = config.room_scope.empty() ? std::string{kMpTuiDefaultRoomScope}
                                                : config.room_scope;
  if (const auto ok = validate_text_field(scope, kP2pPartyMaxRoomScopeBytes, false);
      !ok.has_value()) {
    return Result<std::unique_ptr<MpTuiSession>>::failure(ok.error());
  }

  if (config.local_handle.has_value()) {
    if (const auto ok = validate_text_field(*config.local_handle,
                                            kP2pPartyMaxSenderHandleBytes, false);
        !ok.has_value()) {
      return Result<std::unique_ptr<MpTuiSession>>::failure(ok.error());
    }
  }

  std::optional<std::string> sanitized_org_id;
  std::optional<std::uint64_t> parsed_org_id_u64;
  if (config.org_id.has_value()) {
    if (const auto ok = validate_text_field(*config.org_id, kPartyMaxFieldBytes, false);
        !ok.has_value()) {
      return Result<std::unique_ptr<MpTuiSession>>::failure(ok.error());
    }
    parsed_org_id_u64 = parse_optional_u64_decimal(config.org_id);
    sanitized_org_id = party_chat_sanitize(*config.org_id, kPartyMaxFieldBytes);
  }

  std::optional<std::string> sanitized_group_id;
  if (config.group_id.has_value()) {
    if (const auto ok =
            validate_text_field(*config.group_id, kPartyMaxFieldBytes, false);
        !ok.has_value()) {
      return Result<std::unique_ptr<MpTuiSession>>::failure(ok.error());
    }
    sanitized_group_id = party_chat_sanitize(*config.group_id, kPartyMaxFieldBytes);
  }

  const std::string local_wire_handle = resolve_local_wire_handle(config);
  std::string local_display_handle =
      party_chat_sanitize(local_wire_handle, kPartyMaxAliasBytes);
  if (local_display_handle.empty()) {
    local_display_handle =
        config.runtime_config.identity.device_id.has_value()
            ? ("peer_" + config.runtime_config.identity.device_id->to_decimal())
            : std::string{"local"};
  }

  // Create non-blocking self-pipe first so we fail cleanly without touching
  // network sockets if OS file descriptors are exhausted.
  int pipe_fds[2] = {-1, -1};
  if (::pipe(pipe_fds) != 0) {
    return fail<std::unique_ptr<MpTuiSession>>(ErrorCode::io,
                                               MpTuiSessionError::wake_pipe_failed);
  }
  ScopedPipeEnd read_end{pipe_fds[0]};
  ScopedPipeEnd write_end{pipe_fds[1]};
  if (!configure_nonblock_cloexec(read_end.get()) ||
      !configure_nonblock_cloexec(write_end.get())) {
    return fail<std::unique_ptr<MpTuiSession>>(ErrorCode::io,
                                               MpTuiSessionError::wake_pipe_failed);
  }

  auto runtime_res = MpPartyRuntime::attach(std::move(config.runtime_config));
  if (!runtime_res.has_value()) {
    return Result<std::unique_ptr<MpTuiSession>>::failure(runtime_res.error());
  }

  dedup_account_ids_in_place(config.external_guest_account_ids);

  InitParams init{
      .runtime = std::move(runtime_res).value(),
      .room_scope = std::move(scope),
      .local_wire_handle = local_wire_handle,
      .local_display_handle = std::move(local_display_handle),
      .peer_metadata = std::move(config.peer_metadata),
      .pump_tick_ms = tick_ms,
      .max_retained_messages = max_messages,
      .now_s_override = config.now_s_override,
      .org_id = std::move(sanitized_org_id),
      .group_id = std::move(sanitized_group_id),
      .parsed_org_id_u64 = parsed_org_id_u64,
      .external_guest_account_ids = std::move(config.external_guest_account_ids),
      .party_trust_policy = config.party_trust_policy,
      .org_default_trust = config.org_default_trust,
      .turn_taint = config.turn_taint,
      .wake_read_fd = read_end.release(),
      .wake_write_fd = write_end.release(),
  };
  auto session = std::make_unique<MpTuiSession>(PrivateTag{}, std::move(init));
  session->start_worker();
  return Result<std::unique_ptr<MpTuiSession>>::success(std::move(session));
}

MpTuiSession::MpTuiSession(PrivateTag, InitParams params)
    : runtime_(std::move(params.runtime)), party_id_(runtime_.party_id()),
      local_device_id_(runtime_.config().identity.device_id),
      local_fingerprint_(compute_optional_fingerprint_safe(runtime_.local_pubkey())),
      room_scope_(std::move(params.room_scope)),
      sanitized_room_scope_(
          party_chat_sanitize(room_scope_, kP2pPartyMaxRoomScopeBytes)),
      local_wire_handle_(std::move(params.local_wire_handle)),
      local_display_handle_(std::move(params.local_display_handle)),
      max_retained_messages_(params.max_retained_messages),
      now_s_override_(params.now_s_override), org_id_(std::move(params.org_id)),
      group_id_(std::move(params.group_id)),
      parsed_org_id_u64_(params.parsed_org_id_u64),
      party_trust_policy_(params.party_trust_policy), turn_taint_(params.turn_taint),
      party_epoch_(runtime_.party_epoch()),
      leader_device_id_(runtime_.leader_device_id()),
      peer_metadata_(std::move(params.peer_metadata)),
      external_guest_account_ids_(std::move(params.external_guest_account_ids)),
      internal_turn_taint_(turn_taint_ != nullptr ? *turn_taint_
                                                  : brakes::TurnTaintState{}),
      pump_tick_ms_(params.pump_tick_ms), wake_read_fd_(params.wake_read_fd),
      wake_write_fd_(params.wake_write_fd), state_(runtime_.state()),
      org_default_trust_(params.org_default_trust),
      local_pubkey_(runtime_.local_pubkey()) {
  if (const auto ep = runtime_.local_endpoint_descriptor(); ep.has_value()) {
    local_endpoint_ = ep.value();
  }
  rebuild_participants_locked();
  rebuild_status_summary_locked();
}

MpTuiSession::~MpTuiSession() { stop(); }

void MpTuiSession::start_worker() {
  worker_thread_ = std::jthread(
      [this](const std::stop_token &stop_token) { worker_loop(stop_token); });
}

void MpTuiSession::stop() noexcept {
  std::lock_guard<std::mutex> lifecycle_lock{lifecycle_mu_};
  if (stopped_.load(std::memory_order_acquire)) {
    return;
  }
  stop_requested_.store(true, std::memory_order_release);
  if (worker_thread_.joinable()) {
    worker_thread_.request_stop();
    worker_thread_.join();
  }
  {
    std::lock_guard<std::mutex> lock{state_mu_};
    fail_pending_commands_locked();
    if (!is_terminated_runtime_state(state_)) {
      state_ = MpRuntimeState::terminated;
    }
    last_roster_.clear();
    peer_pulses_.clear();
    rebuild_participants_locked();
    rebuild_status_summary_locked();
  }
  stopped_.store(true, std::memory_order_release);
  close_wake_pipe();
}

// ---------------------------------------------------------------------------
// Wakeup self-pipe helpers (lock-free refcount prevents close/FD-reuse races)
// ---------------------------------------------------------------------------

namespace {

constexpr std::uint64_t kWakeClosingBit = std::uint64_t{1} << 63U;

} // namespace

bool MpTuiSession::try_acquire_wake_user() noexcept {
  std::uint64_t cur = wake_users_.load(std::memory_order_acquire);
  for (;;) {
    if ((cur & kWakeClosingBit) != 0U) {
      return false;
    }
    if (wake_users_.compare_exchange_weak(cur, cur + 1U, std::memory_order_acq_rel,
                                          std::memory_order_acquire)) {
      return true;
    }
  }
}

void MpTuiSession::release_wake_user() noexcept {
  wake_users_.fetch_sub(1U, std::memory_order_release);
}

int MpTuiSession::wake_fd() const noexcept {
  if ((wake_users_.load(std::memory_order_acquire) & kWakeClosingBit) != 0U) {
    return -1;
  }
  return wake_read_fd_.load(std::memory_order_acquire);
}

void MpTuiSession::drain_wake() noexcept {
  if (!try_acquire_wake_user()) {
    return;
  }
  const int fd = wake_read_fd_.load(std::memory_order_acquire);
  if (fd >= 0) {
    std::array<char, 256> buf{};
    for (std::size_t iter = 0U; iter < 512U; ++iter) {
      const ssize_t n = ::read(fd, buf.data(), buf.size());
      if (n > 0) {
        continue;
      }
      if (n < 0 && errno == EINTR) {
        continue;
      }
      break;
    }
  }
  release_wake_user();
}

void MpTuiSession::signal_wake() noexcept {
  if (!try_acquire_wake_user()) {
    return;
  }
  const int fd = wake_write_fd_.load(std::memory_order_acquire);
  if (fd >= 0) {
    const char byte = 1;
    for (;;) {
      const ssize_t n = ::write(fd, &byte, 1U);
      if (n == 1) {
        break;
      }
      if (n < 0 && errno == EINTR) {
        continue;
      }
      // EAGAIN/EWOULDBLOCK simply means unread wake bytes are already buffered.
      break;
    }
  }
  release_wake_user();
}

void MpTuiSession::close_wake_pipe() noexcept {
  wake_users_.fetch_or(kWakeClosingBit, std::memory_order_acq_rel);
  while ((wake_users_.load(std::memory_order_acquire) & ~kWakeClosingBit) != 0U) {
    std::this_thread::yield();
  }
  const int write_fd = wake_write_fd_.exchange(-1, std::memory_order_acq_rel);
  if (write_fd >= 0) {
    (void)::close(write_fd);
  }
  const int read_fd = wake_read_fd_.exchange(-1, std::memory_order_acq_rel);
  if (read_fd >= 0) {
    (void)::close(read_fd);
  }
}

// ---------------------------------------------------------------------------
// Non-blocking outbound command enqueueing & bounded-timeout send_chat
// ---------------------------------------------------------------------------

Result<void> MpTuiSession::post_chat(std::string body, MpTuiChatTarget target,
                                     std::optional<mp::DeviceId> target_device) {
  if (const auto ok = validate_text_field(body, kP2pPartyMaxChatBodyBytes, false);
      !ok.has_value()) {
    return ok;
  }
  std::string target_str =
      target.value.empty() ? std::string{"@all"} : std::move(target.value);
  if (const auto ok =
          validate_text_field(target_str, kP2pPartyMaxTargetSelectorBytes, false);
      !ok.has_value()) {
    return ok;
  }

  std::lock_guard<std::mutex> lock{state_mu_};
  if (stopped_.load(std::memory_order_acquire) ||
      stop_requested_.load(std::memory_order_acquire) ||
      is_terminated_runtime_state(state_)) {
    return fail_void(ErrorCode::stale_handle, MpTuiSessionError::session_stopped);
  }
  if (pending_commands_.size() >= kMpTuiMaxPendingCommands) {
    return fail_void(ErrorCode::capacity, MpTuiSessionError::queue_full);
  }
  PendingCommand cmd{};
  cmd.kind = PendingCommand::Kind::chat;
  cmd.body = std::move(body);
  cmd.target = std::move(target_str);
  cmd.target_device = target_device;
  pending_commands_.push_back(std::move(cmd));
  return Result<void>::success();
}

Result<void> MpTuiSession::post_pulse(P2pPartyActivityState state, std::string status) {
  if (const auto ok =
          validate_text_field(status, kP2pPartyMaxEphemeralStatusBytes, true);
      !ok.has_value()) {
    return ok;
  }

  std::lock_guard<std::mutex> lock{state_mu_};
  if (stopped_.load(std::memory_order_acquire) ||
      stop_requested_.load(std::memory_order_acquire) ||
      is_terminated_runtime_state(state_)) {
    return fail_void(ErrorCode::stale_handle, MpTuiSessionError::session_stopped);
  }
  if (pending_commands_.size() >= kMpTuiMaxPendingCommands) {
    return fail_void(ErrorCode::capacity, MpTuiSessionError::queue_full);
  }
  PendingCommand cmd{};
  cmd.kind = PendingCommand::Kind::pulse;
  cmd.pulse_state = state;
  cmd.pulse_status = std::move(status);
  pending_commands_.push_back(std::move(cmd));
  return Result<void>::success();
}

Result<void> MpTuiSession::post_ping() {
  std::lock_guard<std::mutex> lock{state_mu_};
  if (stopped_.load(std::memory_order_acquire) ||
      stop_requested_.load(std::memory_order_acquire) ||
      is_terminated_runtime_state(state_)) {
    return fail_void(ErrorCode::stale_handle, MpTuiSessionError::session_stopped);
  }
  if (pending_commands_.size() >= kMpTuiMaxPendingCommands) {
    return fail_void(ErrorCode::capacity, MpTuiSessionError::queue_full);
  }
  PendingCommand cmd{};
  cmd.kind = PendingCommand::Kind::ping;
  pending_commands_.push_back(std::move(cmd));
  return Result<void>::success();
}

Result<P2pPartyBroadcastResult> MpTuiSession::send_chat(std::string body,
                                                        MpTuiChatTarget target,
                                                        std::uint32_t timeout_ms) {
  if (const auto ok = validate_text_field(body, kP2pPartyMaxChatBodyBytes, false);
      !ok.has_value()) {
    return Result<P2pPartyBroadcastResult>::failure(ok.error());
  }
  std::string target_str =
      target.value.empty() ? std::string{"@all"} : std::move(target.value);
  if (const auto ok =
          validate_text_field(target_str, kP2pPartyMaxTargetSelectorBytes, false);
      !ok.has_value()) {
    return Result<P2pPartyBroadcastResult>::failure(ok.error());
  }

  auto promise = std::make_shared<std::promise<Result<P2pPartyBroadcastResult>>>();
  auto future = promise->get_future();
  {
    std::lock_guard<std::mutex> lock{state_mu_};
    if (stopped_.load(std::memory_order_acquire) ||
        stop_requested_.load(std::memory_order_acquire) ||
        is_terminated_runtime_state(state_)) {
      return fail<P2pPartyBroadcastResult>(ErrorCode::stale_handle,
                                           MpTuiSessionError::session_stopped);
    }
    if (pending_commands_.size() >= kMpTuiMaxPendingCommands) {
      return fail<P2pPartyBroadcastResult>(ErrorCode::capacity,
                                           MpTuiSessionError::queue_full);
    }
    PendingCommand cmd{};
    cmd.kind = PendingCommand::Kind::chat;
    cmd.body = std::move(body);
    cmd.target = std::move(target_str);
    cmd.chat_promise = std::move(promise);
    pending_commands_.push_back(std::move(cmd));
  }

  const auto clamped_timeout = std::max<std::uint32_t>(1U, timeout_ms);
  if (future.wait_for(std::chrono::milliseconds{clamped_timeout}) !=
      std::future_status::ready) {
    return fail<P2pPartyBroadcastResult>(ErrorCode::busy,
                                         MpTuiSessionError::send_timeout);
  }
  return future.get();
}

// ---------------------------------------------------------------------------
// Metadata updates & snapshot accessors
// ---------------------------------------------------------------------------

void MpTuiSession::update_peer_metadata(mp::DeviceId device_id,
                                        MpPeerDisplayMetadata meta) {
  {
    std::lock_guard<std::mutex> lock{state_mu_};
    peer_metadata_.insert_or_assign(device_id.value(), std::move(meta));
    rebuild_participants_locked();
  }
  signal_wake();
}

void MpTuiSession::update_external_guests(
    std::vector<mp::AccountId> external_guest_account_ids) {
  dedup_account_ids_in_place(external_guest_account_ids);
  {
    std::lock_guard<std::mutex> lock{state_mu_};
    external_guest_account_ids_ = std::move(external_guest_account_ids);
    rebuild_participants_locked();
  }
  signal_wake();
}

bool MpTuiSession::is_external_guest_account(mp::AccountId account_id) const noexcept {
  std::lock_guard<std::mutex> lock{state_mu_};
  return is_external_guest_account_locked(account_id);
}

brakes::TurnTaintState MpTuiSession::turn_taint_snapshot() const {
  std::lock_guard<std::mutex> lock{state_mu_};
  return internal_turn_taint_;
}

MpTuiSessionSnapshot MpTuiSession::snapshot() {
  std::lock_guard<std::mutex> lock{state_mu_};
  MpTuiSessionSnapshot out{};
  out.active =
      !stopped_.load(std::memory_order_acquire) && !is_terminated_runtime_state(state_);
  out.state = state_;
  out.party_id = party_id_;
  out.party_epoch = party_epoch_;
  out.room_scope = sanitized_room_scope_;
  out.participants = participants_;
  out.messages.assign(messages_.begin(), messages_.end());
  out.notices.assign(notices_.begin(), notices_.end());
  notices_.clear();
  out.status_summary = status_summary_;
  out.org_id = org_id_;
  out.group_id = group_id_;
  out.external_guest_account_ids = external_guest_account_ids_;
  return out;
}

PartySnapshot MpTuiSession::to_party_snapshot() const {
  std::lock_guard<std::mutex> lock{state_mu_};
  PartySnapshot out{};
  out.room_scope = sanitized_room_scope_;
  out.mode_override = PartyModeOverride::auto_detect;
  out.participants = participants_;
  out.mode = detect_party_mode(out.participants, out.mode_override);
  out.messages.assign(messages_.begin(), messages_.end());
  return out;
}

bool MpTuiSession::is_active() const noexcept {
  std::lock_guard<std::mutex> lock{state_mu_};
  return !stopped_.load(std::memory_order_acquire) &&
         !is_terminated_runtime_state(state_);
}

MpRuntimeState MpTuiSession::state() const noexcept {
  std::lock_guard<std::mutex> lock{state_mu_};
  return state_;
}

std::optional<mp::EndpointDescriptor> MpTuiSession::local_endpoint_descriptor() const {
  std::lock_guard<std::mutex> lock{state_mu_};
  return local_endpoint_;
}

// ---------------------------------------------------------------------------
// Dedicated background worker loop (exclusive owner of runtime_)
// ---------------------------------------------------------------------------

void MpTuiSession::worker_loop(const std::stop_token &stop_token) {
  block_sigpipe_this_thread();

  while (!stop_token.stop_requested() &&
         !stop_requested_.load(std::memory_order_acquire)) {
    bool notify_tui = false;

    // 1. Drain any queued outbound commands (never holding state_mu_ over I/O).
    std::deque<PendingCommand> batch;
    {
      std::lock_guard<std::mutex> lock{state_mu_};
      batch.swap(pending_commands_);
    }
    for (auto &cmd : batch) {
      if (execute_command(cmd)) {
        notify_tui = true;
      }
    }

    if (runtime_.is_terminated()) {
      {
        std::lock_guard<std::mutex> lock{state_mu_};
        sync_runtime_metadata_locked();
        fail_pending_commands_locked();
      }
      signal_wake();
      break;
    }

    // 2. Bounded non-blocking / short-slice pump of control WS + iroh P2P.
    bool more_commands_waiting = false;
    {
      std::lock_guard<std::mutex> lock{state_mu_};
      more_commands_waiting = !pending_commands_.empty();
    }
    const std::uint32_t slice_ms = more_commands_waiting ? 0U : pump_tick_ms_;
    const auto pump_res = runtime_.pump_once(slice_ms, now_s_override_);
    const auto events = runtime_.drain_events();

    {
      std::lock_guard<std::mutex> lock{state_mu_};
      const MpRuntimeState prev_state = state_;
      const std::uint64_t prev_epoch = party_epoch_;
      const std::size_t prev_peers = last_roster_.size();
      const auto prev_leader = leader_device_id_;

      if (!pump_res.has_value()) {
        push_notice_locked("runtime pump error (" +
                           std::string{error_name(pump_res.error().code)} + ")");
        notify_tui = true;
      }

      for (const auto &ev : events) {
        handle_runtime_event_locked(ev);
        notify_tui = true;
      }

      sync_runtime_metadata_locked();
      if (state_ != prev_state || party_epoch_ != prev_epoch ||
          last_roster_.size() != prev_peers || leader_device_id_ != prev_leader) {
        notify_tui = true;
      }
    }

    if (notify_tui) {
      signal_wake();
    }

    if (runtime_.is_terminated()) {
      {
        std::lock_guard<std::mutex> lock{state_mu_};
        fail_pending_commands_locked();
      }
      signal_wake();
      break;
    }
  }

  // Cleanly tear down control WS + iroh P2P peers exclusively on worker thread.
  runtime_.shutdown();
  {
    std::lock_guard<std::mutex> lock{state_mu_};
    fail_pending_commands_locked();
    state_ = runtime_.state();
    last_roster_.clear();
    peer_pulses_.clear();
    rebuild_participants_locked();
    rebuild_status_summary_locked();
  }
  signal_wake();
}

bool MpTuiSession::execute_command(PendingCommand &cmd) {
  auto fulfill_chat = [&cmd](Result<P2pPartyBroadcastResult> res) {
    if (cmd.chat_promise != nullptr) {
      cmd.chat_promise->set_value(std::move(res));
      cmd.chat_promise.reset();
    }
  };

  if (runtime_.is_terminated()) {
    fulfill_chat(fail<P2pPartyBroadcastResult>(ErrorCode::stale_handle,
                                               MpTuiSessionError::session_stopped));
    return false;
  }

  switch (cmd.kind) {
  case PendingCommand::Kind::chat: {
    const std::int64_t ts_ns = current_unix_ns();
    P2pPartyChatMessage wire_msg{};
    wire_msg.room_scope = room_scope_;
    wire_msg.target_selector = cmd.target;
    wire_msg.sender_handle = local_wire_handle_;
    wire_msg.timestamp_ns = ts_ns;
    wire_msg.body = cmd.body;

    if (cmd.target_device.has_value()) {
      const auto send_res = runtime_.send_chat_to(*cmd.target_device, wire_msg);
      std::lock_guard<std::mutex> lock{state_mu_};
      if (!send_res.has_value()) {
        push_notice_locked("failed to send direct chat to " +
                           format_peer_label_locked(cmd.target_device) + " (" +
                           std::string{error_name(send_res.error().code)} + ")");
        fulfill_chat(Result<P2pPartyBroadcastResult>::failure(send_res.error()));
        return true;
      }
      PartyMessage echo{};
      echo.timestamp_ns = ts_ns;
      echo.sender_id = local_display_handle_;
      echo.sender_role = PartyMemberRole::operator_human;
      echo.sender_host =
          local_device_id_.has_value()
              ? resolve_authenticated_peer_label_locked(*local_device_id_)
              : std::string{"local"};
      echo.sender_fingerprint = local_fingerprint_;
      echo.verified_peer = true;
      echo.untrusted_remote = false;
      echo.target = party_chat_sanitize(cmd.target, kP2pPartyMaxTargetSelectorBytes);
      echo.kind = PartyMessageKind::chat;
      echo.body = party_chat_sanitize(cmd.body, kPartyMaxMessageBytes);
      push_message_locked(std::move(echo));

      P2pPartyBroadcastResult report{};
      report.attempted = 1U;
      report.sent = 1U;
      fulfill_chat(Result<P2pPartyBroadcastResult>::success(std::move(report)));
      return true;
    }

    auto bcast_res = runtime_.broadcast_chat(wire_msg);
    std::lock_guard<std::mutex> lock{state_mu_};
    if (!bcast_res.has_value()) {
      push_notice_locked("chat send failed (" +
                         std::string{error_name(bcast_res.error().code)} + ")");
      fulfill_chat(Result<P2pPartyBroadcastResult>::failure(bcast_res.error()));
      return true;
    }

    const P2pPartyBroadcastResult &report = bcast_res.value();
    if (!report.failures.empty()) {
      push_notice_locked("chat delivery failed for " +
                         std::to_string(report.failures.size()) +
                         (report.failures.size() == 1U ? " peer" : " peers"));
    }
    if (report.sent > 0U || report.attempted == 0U) {
      PartyMessage echo{};
      echo.timestamp_ns = ts_ns;
      echo.sender_id = local_display_handle_;
      echo.sender_role = PartyMemberRole::operator_human;
      echo.sender_host =
          local_device_id_.has_value()
              ? resolve_authenticated_peer_label_locked(*local_device_id_)
              : std::string{"local"};
      echo.sender_fingerprint = local_fingerprint_;
      echo.verified_peer = true;
      echo.untrusted_remote = false;
      echo.target = party_chat_sanitize(cmd.target, kP2pPartyMaxTargetSelectorBytes);
      echo.kind = PartyMessageKind::chat;
      echo.body = party_chat_sanitize(cmd.body, kPartyMaxMessageBytes);
      push_message_locked(std::move(echo));
    }
    fulfill_chat(std::move(bcast_res));
    return true;
  }

  case PendingCommand::Kind::pulse: {
    P2pPartyEphemeralPulse pulse{};
    pulse.activity_state = cmd.pulse_state;
    pulse.timestamp_ns = current_unix_ns();
    pulse.status = cmd.pulse_status;
    const auto res = runtime_.broadcast_ephemeral_pulse(pulse);
    std::lock_guard<std::mutex> lock{state_mu_};
    local_activity_state_ = cmd.pulse_state;
    rebuild_participants_locked();
    if (!res.has_value()) {
      push_notice_locked("pulse send failed (" +
                         std::string{error_name(res.error().code)} + ")");
    }
    return true;
  }

  case PendingCommand::Kind::ping: {
    const auto res = runtime_.send_heartbeat_ping();
    if (!res.has_value()) {
      std::lock_guard<std::mutex> lock{state_mu_};
      push_notice_locked("heartbeat ping failed (" +
                         std::string{error_name(res.error().code)} + ")");
      return true;
    }
    return false;
  }
  }
  return false;
}

void MpTuiSession::handle_runtime_event_locked(const MpRuntimeEvent &event) {
  switch (event.kind) {
  case MpRuntimeEventKind::hello_acked:
    push_notice_locked("connected to online party #" + party_id_.to_decimal());
    return;

  case MpRuntimeEventKind::snapshot_applied: {
    const std::size_t peers = runtime_.peer_count();
    push_notice_locked("party snapshot synced (epoch " +
                       std::to_string(runtime_.party_epoch()) + ", " +
                       std::to_string(peers) + (peers == 1U ? " peer)" : " peers)"));
    return;
  }

  case MpRuntimeEventKind::member_joined:
    push_notice_locked("peer joined: " + format_peer_label_locked(event.device_id));
    return;

  case MpRuntimeEventKind::member_updated:
    return;

  case MpRuntimeEventKind::member_left:
    if (event.device_id.has_value()) {
      peer_pulses_.erase(event.device_id->value());
    }
    push_notice_locked("peer left: " + format_peer_label_locked(event.device_id) +
                       " (" +
                       std::string{event.leave_reason.has_value()
                                       ? leave_reason_text(*event.leave_reason)
                                       : "unknown"} +
                       ")");
    return;

  case MpRuntimeEventKind::leader_changed:
    push_notice_locked(
        "leader changed to " + format_peer_label_locked(event.device_id) + " (" +
        std::string{event.leader_change_reason.has_value()
                        ? leader_change_reason_text(*event.leader_change_reason)
                        : "unknown"} +
        ")");
    return;

  case MpRuntimeEventKind::party_disbanded:
    peer_pulses_.clear();
    push_notice_locked("party disbanded (" +
                       std::string{event.disband_reason.has_value()
                                       ? disband_reason_text(*event.disband_reason)
                                       : "unknown"} +
                       ")");
    return;

  case MpRuntimeEventKind::kicked_or_revoked:
    peer_pulses_.clear();
    push_notice_locked(
        event.ws_close_code == kMpWsCloseDeviceRevoked
            ? "device revoked (4401)"
            : ("kicked or revoked (" + std::to_string(event.ws_close_code) + ")"));
    return;

  case MpRuntimeEventKind::control_disconnected:
    push_notice_locked("reconnecting to party control (close " +
                       std::to_string(event.ws_close_code) + ")");
    return;

  case MpRuntimeEventKind::control_reconnected:
    push_notice_locked("reconnected to party control");
    return;

  case MpRuntimeEventKind::control_error: {
    std::string detail = "control error";
    if (event.server_error.has_value()) {
      detail += " server=" + std::to_string(event.server_error->code);
    }
    if (event.error.has_value()) {
      detail += " code=" + std::string{error_name(event.error->code)};
    }
    push_notice_locked(std::move(detail));
    return;
  }

  case MpRuntimeEventKind::join_request_received:
    push_notice_locked("join request #" +
                       (event.join_request.has_value()
                            ? event.join_request->request_id.to_decimal()
                            : std::string{"?"}) +
                       " from " + format_peer_label_locked(event.device_id));
    return;

  case MpRuntimeEventKind::peer_connected:
    push_notice_locked("peer connected: " +
                       format_peer_label_locked(event.sender_device_id));
    return;

  case MpRuntimeEventKind::peer_disconnected: {
    const auto id =
        event.sender_device_id.has_value() ? event.sender_device_id : event.device_id;
    push_notice_locked("peer disconnected: " + format_peer_label_locked(id));
    return;
  }

  case MpRuntimeEventKind::peer_evicted: {
    const auto id =
        event.sender_device_id.has_value() ? event.sender_device_id : event.device_id;
    if (id.has_value()) {
      peer_pulses_.erase(id->value());
    }
    push_notice_locked("peer evicted: " + format_peer_label_locked(id) + " (reason " +
                       std::to_string(event.reason_code) + ")");
    return;
  }

  case MpRuntimeEventKind::chat_received: {
    // Anti-spoofing invariant: require TLS 1.3 Mutual RPK + CWT authenticated
    // sender_device_id and NEVER trust wire `event.chat->sender_handle`.
    if (!event.chat.has_value() || !event.sender_device_id.has_value()) {
      return;
    }
    const mp::DeviceId sender_dev = *event.sender_device_id;
    const auto roster_peer = runtime_.find_peer(sender_dev);
    std::optional<mp::AccountId> sender_account = event.sender_account_id;
    if (!sender_account.has_value() && roster_peer.has_value()) {
      sender_account = roster_peer->account_id;
    }
    const bool is_ext_guest =
        sender_account.has_value() && is_external_guest_account_locked(*sender_account);

    const std::string sender_fp = compute_fingerprint_safe(event.peer_pubkey);
    std::string safety_number = sender_fp;
    if (roster_peer.has_value()) {
      if (const auto sn = mp::compute_safety_number(roster_peer->account_id,
                                                    roster_peer->root_pubkey);
          sn.has_value()) {
        safety_number = sn.value();
      }
    }

    brakes::PeerProvenance provenance{};
    provenance.origin = brakes::PeerOriginKind::online_peer;
    provenance.peer_pubkey_b64 = base64_encode_pubkey(event.peer_pubkey);
    provenance.safety_number = std::move(safety_number);
    provenance.account_id = sender_account.has_value() ? sender_account->value() : 0U;
    provenance.org_id = parsed_org_id_u64_;
    provenance.is_external_guest = is_ext_guest;
    provenance.effective_trust =
        org_default_trust_.has_value()
            ? std::min(*org_default_trust_, party_trust_policy_.max_default_profile)
            : party_trust_policy_.max_default_profile;

    brakes::EffectivePolicy eff_policy{};
    eff_policy.party_trust = party_trust_policy_;
    brakes::BrakesGate gate{eff_policy, turn_taint_ != nullptr ? *turn_taint_
                                                               : internal_turn_taint_};
    const brakes::PartyTrustProfile clamped_trust = gate.ingest_peer(provenance);
    internal_turn_taint_ = gate.taint();
    if (turn_taint_ != nullptr) {
      *turn_taint_ = gate.taint();
    }

    PartyMessage msg{};
    msg.timestamp_ns =
        event.chat->timestamp_ns > 0 ? event.chat->timestamp_ns : current_unix_ns();
    msg.sender_id = resolve_authenticated_peer_handle_locked(sender_dev);
    msg.sender_role = PartyMemberRole::operator_human;
    msg.sender_host = resolve_authenticated_peer_label_locked(sender_dev);
    if (is_ext_guest) {
      msg.sender_model = "[EXT-GUEST]";
      msg.sender_host += " [EXT-GUEST]";
    }
    msg.sender_fingerprint = sender_fp;
    msg.verified_peer = true;
    msg.untrusted_remote = true;
    const std::string_view raw_target =
        event.chat->target_selector.empty()
            ? std::string_view{"@all"}
            : std::string_view{event.chat->target_selector};
    msg.target = party_chat_sanitize(raw_target, kP2pPartyMaxTargetSelectorBytes);
    msg.kind = PartyMessageKind::chat;
    msg.body = party_chat_sanitize(event.chat->body, kPartyMaxMessageBytes);
    if (is_ext_guest) {
      push_notice_locked(
          "external guest message clamped: " + msg.sender_id + " (trust=" +
          std::string{brakes::party_trust_profile_name(clamped_trust)} + ")");
    }
    push_message_locked(std::move(msg));
    return;
  }

  case MpRuntimeEventKind::control_notice_received: {
    if (!event.control_notice.has_value() || !event.sender_device_id.has_value()) {
      return;
    }
    const std::string safe_text =
        party_chat_sanitize(event.control_notice->text, kP2pPartyMaxControlNoticeBytes);
    std::string line =
        "notice from " + format_peer_label_locked(event.sender_device_id);
    if (!safe_text.empty()) {
      line += ": " + safe_text;
    }
    push_notice_locked(std::move(line));
    return;
  }

  case MpRuntimeEventKind::ephemeral_pulse_received: {
    if (!event.ephemeral_pulse.has_value() || !event.sender_device_id.has_value()) {
      return;
    }
    PeerPulseInfo info{};
    info.activity_state = event.ephemeral_pulse->activity_state;
    info.status = party_chat_sanitize(event.ephemeral_pulse->status,
                                      kP2pPartyMaxEphemeralStatusBytes);
    info.updated_ns = event.ephemeral_pulse->timestamp_ns > 0
                          ? event.ephemeral_pulse->timestamp_ns
                          : current_unix_ns();
    peer_pulses_.insert_or_assign(event.sender_device_id->value(), std::move(info));
    return;
  }

  case MpRuntimeEventKind::bridge_envelope_received:
  case MpRuntimeEventKind::frame_dropped:
    return;
  }
}

void MpTuiSession::sync_runtime_metadata_locked() {
  state_ = runtime_.state();
  party_epoch_ = runtime_.party_epoch();
  leader_device_id_ = runtime_.leader_device_id();
  last_roster_ = runtime_.roster();
  if (const auto ep = runtime_.local_endpoint_descriptor(); ep.has_value()) {
    local_endpoint_ = ep.value();
  }
  rebuild_participants_locked();
  rebuild_status_summary_locked();
}

void MpTuiSession::rebuild_participants_locked() {
  participants_.clear();
  participants_.reserve(last_roster_.size() + 1U);

  const std::int64_t now_ns = current_unix_ns();

  // 1. Local self participant.
  PartyParticipant self{};
  self.id = local_display_handle_;
  self.display_name = local_display_handle_;
  self.role = PartyMemberRole::operator_human;
  self.host = local_device_id_.has_value()
                  ? resolve_authenticated_peer_label_locked(*local_device_id_)
                  : std::string{"local"};
  if (self.host == "online") {
    self.host = "local";
  }
  const bool self_is_leader = local_device_id_.has_value() &&
                              leader_device_id_.has_value() &&
                              *local_device_id_ == *leader_device_id_;
  self.model = self_is_leader ? "online/leader" : "online";
  self.fingerprint = local_fingerprint_;
  self.state = is_terminated_runtime_state(state_)
                   ? PartyParticipantState::offline
                   : map_activity_to_participant_state(local_activity_state_);
  self.last_seen_ns = now_ns;
  self.local_self = true;
  participants_.push_back(std::move(self));

  // 2. Authenticated remote peers from MpPartyRuntime::roster() (CWT-verified).
  for (const auto &peer : last_roster_) {
    PartyParticipant p{};
    const std::string resolved_handle =
        resolve_authenticated_peer_handle_locked(peer.device_id);
    p.id = resolved_handle;
    p.display_name = resolved_handle;
    p.role = PartyMemberRole::operator_human;
    p.host = resolve_authenticated_peer_label_locked(peer.device_id);
    const bool is_leader =
        leader_device_id_.has_value() && *leader_device_id_ == peer.device_id;
    p.model = is_leader ? "online/leader" : "online";
    if (is_external_guest_account_locked(peer.account_id)) {
      p.model += " [EXT-GUEST]";
    }
    p.fingerprint = compute_fingerprint_safe(peer.device_pubkey);

    if (peer.connection_state == P2pPeerConnectionState::connected) {
      if (const auto pulse_it = peer_pulses_.find(peer.device_id.value());
          pulse_it != peer_pulses_.end()) {
        p.state = map_activity_to_participant_state(pulse_it->second.activity_state);
      } else {
        p.state = PartyParticipantState::online;
      }
    } else if (peer.connection_state == P2pPeerConnectionState::disconnected) {
      p.state = PartyParticipantState::offline;
    } else {
      p.state = peer.control_plane_connected ? PartyParticipantState::idle
                                             : PartyParticipantState::offline;
    }

    p.last_seen_ns = peer.last_confirmed_s > 0
                         ? seconds_to_ns_clamped(peer.last_confirmed_s)
                         : now_ns;
    p.local_self = false;
    participants_.push_back(std::move(p));
  }
}

void MpTuiSession::rebuild_status_summary_locked() {
  const std::size_t peer_count = last_roster_.size();
  status_summary_ = "online party #" + party_id_.to_decimal() + " (epoch " +
                    std::to_string(party_epoch_) + ", " + std::to_string(peer_count) +
                    (peer_count == 1U ? " peer, " : " peers, ") +
                    std::string{mp_runtime_state_name(state_)} + ")";
}

void MpTuiSession::push_message_locked(PartyMessage message) {
  message.id = "mp-" + std::to_string(next_message_seq_++);
  while (messages_.size() >= max_retained_messages_) {
    messages_.pop_front();
  }
  messages_.push_back(std::move(message));
}

void MpTuiSession::push_notice_locked(std::string_view notice) {
  std::string safe = party_chat_sanitize(notice, kPartyMaxFieldBytes);
  while (notices_.size() >= kMpTuiMaxRetainedNotices) {
    notices_.pop_front();
  }
  notices_.push_back(std::move(safe));
}

std::string
MpTuiSession::resolve_authenticated_peer_handle_locked(mp::DeviceId device_id) const {
  if (const auto it = peer_metadata_.find(device_id.value());
      it != peer_metadata_.end() && !it->second.handle.empty()) {
    std::string safe = party_chat_sanitize(it->second.handle, kPartyMaxAliasBytes);
    if (!safe.empty()) {
      return safe;
    }
  }
  return "peer_" + device_id.to_decimal();
}

std::string
MpTuiSession::resolve_authenticated_peer_label_locked(mp::DeviceId device_id) const {
  if (const auto it = peer_metadata_.find(device_id.value());
      it != peer_metadata_.end() && !it->second.device_label.empty()) {
    std::string safe = party_chat_sanitize(it->second.device_label, 128U);
    if (!safe.empty()) {
      return safe;
    }
  }
  return "online";
}

std::string
MpTuiSession::format_peer_label_locked(std::optional<mp::DeviceId> device_id) const {
  if (!device_id.has_value()) {
    return "peer_?";
  }
  if (local_device_id_.has_value() && *device_id == *local_device_id_) {
    return local_display_handle_;
  }
  return resolve_authenticated_peer_handle_locked(*device_id);
}

bool MpTuiSession::is_external_guest_account_locked(
    mp::AccountId account_id) const noexcept {
  return std::find(external_guest_account_ids_.begin(),
                   external_guest_account_ids_.end(),
                   account_id) != external_guest_account_ids_.end();
}

void MpTuiSession::fail_pending_commands_locked() noexcept {
  while (!pending_commands_.empty()) {
    auto cmd = std::move(pending_commands_.front());
    pending_commands_.pop_front();
    if (cmd.chat_promise != nullptr) {
      cmd.chat_promise->set_value(fail<P2pPartyBroadcastResult>(
          ErrorCode::stale_handle, MpTuiSessionError::session_stopped));
      cmd.chat_promise.reset();
    }
  }
}

} // namespace blackbird
