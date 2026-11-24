#include "blackbird/mp_room_v2.hpp"

#include "blackbird/json.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>

namespace blackbird {

namespace {

constexpr std::uint64_t kWakeClosingBit = std::uint64_t{1U} << 63U;
constexpr std::uint64_t kWakeCountMask = kWakeClosingBit - 1U;
constexpr std::size_t kMaxRoomTargetBytes = 128U;

template <typename T> Result<T> fail(ErrorCode code, MpRoomV2Error detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_void(ErrorCode code, MpRoomV2Error detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

std::uint64_t wall_now_ms() noexcept {
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
  return ms > 0 ? static_cast<std::uint64_t>(ms) : 0U;
}

std::string strip_at(std::string_view raw) {
  while (!raw.empty() && raw.front() == '@') {
    raw.remove_prefix(1U);
  }
  return std::string{raw};
}

std::optional<std::uint64_t> json_u64_or_decimal(const Value &obj,
                                                 std::string_view key) {
  const Value *f = obj.find(key);
  if (f == nullptr || std::holds_alternative<std::nullptr_t>(f->value())) {
    return std::nullopt;
  }
  if (const auto *s = std::get_if<std::string>(&f->value())) {
    const auto parsed = mp::parse_safe_decimal_id(*s);
    if (parsed.has_value()) {
      return parsed.value();
    }
    return std::nullopt;
  }
  if (const auto *num = std::get_if<Number>(&f->value())) {
    if (const auto *u = std::get_if<std::uint64_t>(&num->storage())) {
      return *u;
    }
    if (const auto *i = std::get_if<std::int64_t>(&num->storage());
        i != nullptr && *i >= 0) {
      return static_cast<std::uint64_t>(*i);
    }
  }
  return std::nullopt;
}

std::optional<std::string> json_opt_string(const Value &obj, std::string_view key) {
  const Value *f = obj.find(key);
  if (f == nullptr) {
    return std::nullopt;
  }
  if (const auto *s = std::get_if<std::string>(&f->value())) {
    return *s;
  }
  return std::nullopt;
}

std::string render_agent_card_body(std::string_view body) {
  ValueLimits limits{};
  limits.bytes = mp::kMaxMp2BodyBytes;
  limits.nodes = 2048U;
  limits.depth = 16U;
  const auto parsed = parse_json(body, limits);
  if (!parsed.has_value() ||
      !std::holds_alternative<Value::Object>(parsed.value().value())) {
    return party_chat_sanitize(body, 2048U);
  }
  const Value &obj = parsed.value();
  const std::string title =
      party_chat_sanitize(json_opt_string(obj, "title").value_or("Agent update"), 160U);
  const std::string summary =
      party_chat_sanitize(json_opt_string(obj, "summary").value_or(""), 512U);
  std::string out = "[agent] " + title;
  if (!summary.empty()) {
    out += " — " + summary;
  }
  if (const Value *files_field = obj.find("files"); files_field != nullptr) {
    if (const auto *arr = std::get_if<Value::Array>(&files_field->value());
        arr != nullptr && !arr->empty()) {
      out += " [";
      const std::size_t shown = std::min<std::size_t>(arr->size(), 6U);
      for (std::size_t i = 0U; i < shown; ++i) {
        if (i > 0U) {
          out += ", ";
        }
        if (const auto *s = std::get_if<std::string>(&(*arr)[i].value())) {
          out += party_chat_sanitize(*s, 96U);
        }
      }
      if (arr->size() > shown) {
        out += ", +" + std::to_string(arr->size() - shown);
      }
      out += "]";
    }
  }
  return out;
}

std::string format_member_display_name(const MpRoomV2Member &m) {
  const std::string handle = party_chat_sanitize(strip_at(m.handle), 64U);
  std::string out = "@" + (handle.empty() ? std::string{"member"} : handle);
  const std::string client = party_chat_sanitize(m.client, 32U);
  const std::string agent = party_chat_sanitize(m.agent_name, 48U);
  if (!client.empty() && !agent.empty() && agent != client &&
      !(client == "blackbird" && agent == "Blackbird")) {
    out += " (" + client + " · " + agent + ")";
  } else if (!client.empty()) {
    out += " (" + client + ")";
  } else if (!agent.empty()) {
    out += " (" + agent + ")";
  }
  return out;
}

PartyParticipantState map_member_state(const MpRoomV2Member &m) noexcept {
  if (m.status == "offline" || m.status == "away") {
    return PartyParticipantState::offline;
  }
  if (m.agent_state == "working" || m.agent_state == "busy" ||
      m.agent_state == "running") {
    return PartyParticipantState::working;
  }
  if (m.agent_state == "idle") {
    return PartyParticipantState::idle;
  }
  return PartyParticipantState::online;
}

PartyMessageKind map_message_kind(std::string_view kind) noexcept {
  if (kind == "agent_card") {
    return PartyMessageKind::leader_update;
  }
  if (kind == "system") {
    return PartyMessageKind::system;
  }
  return PartyMessageKind::chat;
}

std::vector<MpRoomV2Member>
parse_members_array(const Value &obj, std::optional<mp::AccountId> self_account_id) {
  std::vector<MpRoomV2Member> out;
  const Value *field = obj.find("members");
  if (field == nullptr) {
    return out;
  }
  const auto *arr = std::get_if<Value::Array>(&field->value());
  if (arr == nullptr) {
    return out;
  }
  const std::size_t cap = std::min<std::size_t>(arr->size(), 256U);
  out.reserve(cap);
  for (std::size_t i = 0U; i < cap; ++i) {
    const Value &item = (*arr)[i];
    if (!std::holds_alternative<Value::Object>(item.value())) {
      continue;
    }
    const auto acct_raw = json_u64_or_decimal(item, "account_id");
    const auto acct_id = acct_raw.has_value() ? mp::AccountId::create(*acct_raw)
                                              : mp::AccountId::create(1U);
    if (!acct_id.has_value()) {
      continue;
    }
    const std::string raw_handle = json_opt_string(item, "handle").value_or("");
    const std::string clean_handle = party_chat_sanitize(strip_at(raw_handle), 64U);
    if (clean_handle.empty()) {
      continue;
    }
    MpRoomV2Member m{};
    m.account_id = acct_id.value();
    m.handle = clean_handle;
    m.client = party_chat_sanitize(json_opt_string(item, "client").value_or(""), 32U);
    m.agent_name =
        party_chat_sanitize(json_opt_string(item, "agent_name").value_or(""), 48U);
    m.agent_state =
        party_chat_sanitize(json_opt_string(item, "agent_state").value_or(""), 32U);
    m.agent_summary =
        party_chat_sanitize(json_opt_string(item, "agent_summary").value_or(""), 128U);
    m.status =
        party_chat_sanitize(json_opt_string(item, "status").value_or("live"), 24U);
    m.is_self = self_account_id.has_value() && m.account_id == *self_account_id;
    out.push_back(std::move(m));
  }
  return out;
}

std::string generate_client_msg_id(std::uint64_t counter) {
  const auto nonce = mp::generate_nonce_b64url(12U);
  if (nonce.has_value() && !nonce.value().empty()) {
    return "bb-" + std::to_string(counter) + "-" + nonce.value();
  }
  return "bb-" + std::to_string(counter) + "-" + std::to_string(wall_now_ms());
}

bool set_nonblock_cloexec(int fd) noexcept {
  const int fl = ::fcntl(fd, F_GETFL, 0);
  if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) {
    return false;
  }
  const int fdfl = ::fcntl(fd, F_GETFD, 0);
  if (fdfl < 0 || ::fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC) != 0) {
    return false;
  }
  return true;
}

bool is_permanent_close_code(std::uint16_t code) noexcept {
  return code == 4401U || code == 4403U || code == 4404U || code == 1008U;
}

bool is_permanent_connect_error(const Error &err) noexcept {
  const auto ce = mp::mp_client_error_of(err);
  return ce == mp::MpClientError::http_unauthorized ||
         ce == mp::MpClientError::http_forbidden ||
         ce == mp::MpClientError::http_not_found || ce == mp::MpClientError::http_gone;
}

} // namespace

// ---------------------------------------------------------------------------
// Error & state names
// ---------------------------------------------------------------------------

std::string_view mp_room_v2_error_name(MpRoomV2Error detail) noexcept {
  switch (detail) {
  case MpRoomV2Error::none:
    return "none";
  case MpRoomV2Error::invalid_config:
    return "invalid_config";
  case MpRoomV2Error::session_stopped:
    return "session_stopped";
  case MpRoomV2Error::queue_full:
    return "queue_full";
  case MpRoomV2Error::invalid_field:
    return "invalid_field";
  case MpRoomV2Error::field_too_large:
    return "field_too_large";
  case MpRoomV2Error::invalid_utf8:
    return "invalid_utf8";
  case MpRoomV2Error::wake_pipe_failed:
    return "wake_pipe_failed";
  case MpRoomV2Error::protocol_error:
    return "protocol_error";
  }
  return "unknown";
}

std::string_view mp_room_v2_state_name(MpRoomV2State state) noexcept {
  switch (state) {
  case MpRoomV2State::connecting:
    return "connecting";
  case MpRoomV2State::live:
    return "live";
  case MpRoomV2State::reconnecting:
    return "reconnecting";
  case MpRoomV2State::disconnected:
    return "disconnected";
  case MpRoomV2State::stopped:
    return "stopped";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

Result<std::unique_ptr<MpRoomV2Session>> MpRoomV2Session::start(MpRoomV2Config config) {
  if (!config.identity.account_id.has_value() ||
      !config.identity.device_id.has_value()) {
    return fail<std::unique_ptr<MpRoomV2Session>>(ErrorCode::provider_auth,
                                                  MpRoomV2Error::invalid_config);
  }
  std::string ws_path = config.ws_path.empty()
                            ? ("/v1/parties/" + config.party_id.to_decimal() + "/ws")
                            : config.ws_path;
  if (ws_path.empty() || ws_path.front() != '/') {
    return fail<std::unique_ptr<MpRoomV2Session>>(ErrorCode::invalid_range,
                                                  MpRoomV2Error::invalid_config);
  }

  mp::MpControlClient client{config.client_config, config.identity};
  auto sock_res = client.connect_ws_v2(ws_path);
  if (!sock_res.has_value()) {
    return Result<std::unique_ptr<MpRoomV2Session>>::failure(sock_res.error());
  }

  int fds[2] = {-1, -1};
  if (::pipe(fds) != 0) {
    return fail<std::unique_ptr<MpRoomV2Session>>(ErrorCode::io,
                                                  MpRoomV2Error::wake_pipe_failed);
  }
  if (!set_nonblock_cloexec(fds[0]) || !set_nonblock_cloexec(fds[1])) {
    (void)::close(fds[0]);
    (void)::close(fds[1]);
    return fail<std::unique_ptr<MpRoomV2Session>>(ErrorCode::io,
                                                  MpRoomV2Error::wake_pipe_failed);
  }

  std::string local_handle = party_chat_sanitize(strip_at(config.identity.handle), 64U);
  if (local_handle.empty()) {
    local_handle = "you";
  }

  InitParams params{
      std::move(config),
      std::move(client),
      std::move(sock_res).value(),
      std::move(ws_path),
      std::move(local_handle),
      fds[0],
      fds[1],
  };

  auto session = std::make_unique<MpRoomV2Session>(PrivateTag{}, std::move(params));
  session->start_worker();
  return Result<std::unique_ptr<MpRoomV2Session>>::success(std::move(session));
}

MpRoomV2Session::MpRoomV2Session(PrivateTag, InitParams params)
    : client_(std::move(params.client)), socket_(std::move(params.socket)),
      party_id_(params.config.party_id),
      local_account_id_(params.config.identity.account_id),
      ws_path_(std::move(params.ws_path)),
      local_handle_(std::move(params.local_handle)),
      client_name_(params.config.client_name.empty() ? std::string{"blackbird"}
                                                     : params.config.client_name),
      agent_name_(params.config.agent_name.empty() ? std::string{"Blackbird"}
                                                   : params.config.agent_name),
      max_retained_messages_(std::clamp<std::size_t>(
          params.config.max_retained_messages, 1U, kMpRoomV2MaxRetainedMessagesCap)),
      poll_interval_ms_(
          std::clamp<std::uint32_t>(params.config.poll_interval_ms, 5U, 250U)),
      ping_interval_ms_(
          std::clamp<std::uint32_t>(params.config.ping_interval_ms, 1000U, 60000U)),
      reconnect_base_ms_(std::max<std::uint32_t>(params.config.reconnect_base_ms, 50U)),
      reconnect_max_ms_(
          std::max<std::uint32_t>(params.config.reconnect_max_ms, reconnect_base_ms_)),
      state_(MpRoomV2State::connecting),
      room_code_(party_chat_sanitize(params.config.room_code, 32U)),
      room_name_(party_chat_sanitize(params.config.room_name, 128U)),
      share_url_(party_chat_sanitize(params.config.share_url, 256U)),
      wake_read_fd_(params.wake_read_fd), wake_write_fd_(params.wake_write_fd) {
  std::vector<MpRoomV2Member> initial;
  initial.reserve(params.config.initial_members.size() + 1U);
  for (const auto &im : params.config.initial_members) {
    const std::string clean_h = party_chat_sanitize(strip_at(im.handle), 64U);
    if (clean_h.empty()) {
      continue;
    }
    MpRoomV2Member m{};
    m.account_id = im.account_id;
    m.handle = clean_h;
    m.client = party_chat_sanitize(im.client, 32U);
    m.agent_name = party_chat_sanitize(im.agent_name, 48U);
    m.agent_state = party_chat_sanitize(im.agent_state, 32U);
    m.agent_summary = party_chat_sanitize(im.agent_summary, 128U);
    m.status =
        im.status.empty() ? std::string{"live"} : party_chat_sanitize(im.status, 24U);
    m.is_self = local_account_id_.has_value() && m.account_id == *local_account_id_;
    initial.push_back(std::move(m));
  }
  apply_members_locked(initial);
  rebuild_status_summary_locked();
}

MpRoomV2Session::~MpRoomV2Session() { stop(); }

void MpRoomV2Session::start_worker() {
  worker_thread_ = std::jthread([this](const std::stop_token &st) { worker_loop(st); });
}

void MpRoomV2Session::stop() noexcept {
  std::lock_guard<std::mutex> lock(lifecycle_mu_);
  if (stopped_.load(std::memory_order_acquire)) {
    return;
  }
  stop_requested_.store(true, std::memory_order_release);
  if (worker_thread_.joinable()) {
    worker_thread_.request_stop();
    worker_thread_.join();
  }
  {
    std::lock_guard<std::mutex> slock(state_mu_);
    state_ = MpRoomV2State::stopped;
    rebuild_status_summary_locked();
  }
  stopped_.store(true, std::memory_order_release);
  close_wake_pipe();
}

// ---------------------------------------------------------------------------
// Wake pipe
// ---------------------------------------------------------------------------

bool MpRoomV2Session::try_acquire_wake_user() noexcept {
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

void MpRoomV2Session::release_wake_user() noexcept {
  wake_users_.fetch_sub(1U, std::memory_order_acq_rel);
}

int MpRoomV2Session::wake_fd() const noexcept {
  return wake_read_fd_.load(std::memory_order_acquire);
}

void MpRoomV2Session::drain_wake() noexcept {
  if (!try_acquire_wake_user()) {
    return;
  }
  const int rfd = wake_read_fd_.load(std::memory_order_acquire);
  if (rfd >= 0) {
    std::array<std::uint8_t, 64> buf{};
    while (::read(rfd, buf.data(), buf.size()) > 0) {
    }
  }
  release_wake_user();
}

void MpRoomV2Session::signal_wake() noexcept {
  if (!try_acquire_wake_user()) {
    return;
  }
  const int wfd = wake_write_fd_.load(std::memory_order_acquire);
  if (wfd >= 0) {
    const std::uint8_t byte = 1U;
    (void)::write(wfd, &byte, 1U);
  }
  release_wake_user();
}

void MpRoomV2Session::close_wake_pipe() noexcept {
  wake_users_.fetch_or(kWakeClosingBit, std::memory_order_acq_rel);
  while ((wake_users_.load(std::memory_order_acquire) & kWakeCountMask) != 0U) {
    std::this_thread::yield();
  }
  const int rfd = wake_read_fd_.exchange(-1, std::memory_order_acq_rel);
  const int wfd = wake_write_fd_.exchange(-1, std::memory_order_acq_rel);
  if (rfd >= 0) {
    (void)::close(rfd);
  }
  if (wfd >= 0) {
    (void)::close(wfd);
  }
}

// ---------------------------------------------------------------------------
// Outbound APIs
// ---------------------------------------------------------------------------

Result<std::string> MpRoomV2Session::send_chat(std::string body,
                                               MpRoomV2Target target) {
  if (stop_requested_.load(std::memory_order_acquire) ||
      stopped_.load(std::memory_order_acquire)) {
    return fail<std::string>(ErrorCode::stale_handle, MpRoomV2Error::session_stopped);
  }
  if (body.empty()) {
    return fail<std::string>(ErrorCode::invalid_range, MpRoomV2Error::invalid_field);
  }
  if (body.size() > mp::kMaxMp2BodyBytes) {
    return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::field_too_large);
  }
  if (target.value.empty()) {
    target.value = "@all";
  }
  if (target.value.size() > kMaxRoomTargetBytes) {
    return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::field_too_large);
  }

  std::string msg_id;
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (outbox_.size() >= kMpRoomV2MaxPendingOutbox) {
      return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::queue_full);
    }
    ++local_msg_counter_;
    msg_id = generate_client_msg_id(local_msg_counter_);

    MpRoomV2Message optimistic{};
    optimistic.seq = 0U;
    optimistic.ts_ms = wall_now_ms();
    optimistic.client_msg_id = msg_id;
    optimistic.sender_account_id = local_account_id_;
    optimistic.sender_handle = local_handle_;
    optimistic.sender_client = client_name_;
    optimistic.sender_agent_name = agent_name_;
    optimistic.target = party_chat_sanitize(target.value, kMaxRoomTargetBytes);
    optimistic.kind = "chat";
    optimistic.body_encoding = "utf8";
    optimistic.body = body;
    optimistic.rendered_body = party_chat_sanitize(body, 2048U);
    optimistic.delivered = false;
    optimistic.local_self = true;
    upsert_message_locked(std::move(optimistic));

    outbox_.push_back(OutboundMessage{
        msg_id,
        "chat",
        std::move(target.value),
        "utf8",
        std::move(body),
        false,
    });
    rebuild_status_summary_locked();
  }
  signal_wake();
  return Result<std::string>::success(std::move(msg_id));
}

Result<std::string> MpRoomV2Session::send_agent_card(const MpRoomV2AgentCard &card,
                                                     MpRoomV2Target target) {
  if (stop_requested_.load(std::memory_order_acquire) ||
      stopped_.load(std::memory_order_acquire)) {
    return fail<std::string>(ErrorCode::stale_handle, MpRoomV2Error::session_stopped);
  }
  if (card.title.empty() && card.summary.empty()) {
    return fail<std::string>(ErrorCode::invalid_range, MpRoomV2Error::invalid_field);
  }
  if (target.value.empty()) {
    target.value = "@all";
  }

  Value::Object card_obj;
  card_obj.emplace_back("title", Value{card.title});
  card_obj.emplace_back("summary", Value{card.summary});
  if (!card.files.empty()) {
    Value::Array files_arr;
    files_arr.reserve(card.files.size());
    for (const auto &f : card.files) {
      files_arr.emplace_back(f);
    }
    card_obj.emplace_back("files", Value{std::move(files_arr)});
  }
  auto json_res = dump_json(Value::object(std::move(card_obj)));
  if (!json_res.has_value()) {
    return fail<std::string>(ErrorCode::corrupt, MpRoomV2Error::invalid_field);
  }
  std::string body = std::move(json_res).value();
  if (body.size() > mp::kMaxMp2BodyBytes) {
    return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::field_too_large);
  }

  std::string msg_id;
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (outbox_.size() >= kMpRoomV2MaxPendingOutbox) {
      return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::queue_full);
    }
    ++local_msg_counter_;
    msg_id = generate_client_msg_id(local_msg_counter_);

    MpRoomV2Message optimistic{};
    optimistic.seq = 0U;
    optimistic.ts_ms = wall_now_ms();
    optimistic.client_msg_id = msg_id;
    optimistic.sender_account_id = local_account_id_;
    optimistic.sender_handle = local_handle_;
    optimistic.sender_client = client_name_;
    optimistic.sender_agent_name = agent_name_;
    optimistic.target = party_chat_sanitize(target.value, kMaxRoomTargetBytes);
    optimistic.kind = "agent_card";
    optimistic.body_encoding = "utf8";
    optimistic.body = body;
    optimistic.rendered_body = render_agent_card_body(body);
    optimistic.delivered = false;
    optimistic.local_self = true;
    upsert_message_locked(std::move(optimistic));

    outbox_.push_back(OutboundMessage{
        msg_id,
        "agent_card",
        std::move(target.value),
        "utf8",
        std::move(body),
        false,
    });
    rebuild_status_summary_locked();
  }
  signal_wake();
  return Result<std::string>::success(std::move(msg_id));
}

Result<void> MpRoomV2Session::update_status(MpRoomV2StatusUpdate status) {
  if (stop_requested_.load(std::memory_order_acquire) ||
      stopped_.load(std::memory_order_acquire)) {
    return fail_void(ErrorCode::stale_handle, MpRoomV2Error::session_stopped);
  }
  if (status.client.empty()) {
    status.client = client_name_;
  }
  if (status.agent_name.empty()) {
    status.agent_name = agent_name_;
  }
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    pending_status_ = std::move(status);
  }
  signal_wake();
  return Result<void>::success();
}

// ---------------------------------------------------------------------------
// Accessors & snapshots
// ---------------------------------------------------------------------------

bool MpRoomV2Session::is_active() const noexcept {
  if (stopped_.load(std::memory_order_acquire)) {
    return false;
  }
  std::lock_guard<std::mutex> lock(state_mu_);
  return state_ == MpRoomV2State::connecting || state_ == MpRoomV2State::live ||
         state_ == MpRoomV2State::reconnecting;
}

MpRoomV2State MpRoomV2Session::state() const noexcept {
  std::lock_guard<std::mutex> lock(state_mu_);
  return state_;
}

std::string MpRoomV2Session::room_code() const {
  std::lock_guard<std::mutex> lock(state_mu_);
  return room_code_;
}

std::string MpRoomV2Session::share_url() const {
  std::lock_guard<std::mutex> lock(state_mu_);
  return share_url_;
}

std::uint64_t MpRoomV2Session::latest_seq() const noexcept {
  return latest_seq_atomic_.load(std::memory_order_acquire);
}

MpRoomV2Snapshot MpRoomV2Session::snapshot() {
  std::lock_guard<std::mutex> lock(state_mu_);
  MpRoomV2Snapshot snap{};
  snap.active = state_ == MpRoomV2State::connecting || state_ == MpRoomV2State::live ||
                state_ == MpRoomV2State::reconnecting;
  snap.state = state_;
  snap.party_id = party_id_;
  snap.room_code = room_code_;
  snap.room_name = room_name_;
  snap.share_url = share_url_;
  snap.latest_seq = latest_seq_;
  snap.queued_send_count = outbox_.size();
  snap.members = members_;
  snap.messages.assign(messages_.begin(), messages_.end());
  snap.notices.assign(notices_.begin(), notices_.end());
  notices_.clear();
  snap.status_summary = status_summary_;
  return snap;
}

PartySnapshot MpRoomV2Session::to_party_snapshot() const {
  std::lock_guard<std::mutex> lock(state_mu_);
  PartySnapshot snap{};
  snap.room_scope =
      !room_code_.empty() ? ("room/" + room_code_) : std::string{"party/live"};
  snap.mode =
      members_.size() > 1U ? PartyMode::multi_operator : PartyMode::single_operator;
  snap.mode_override = PartyModeOverride::auto_detect;

  snap.participants.reserve(members_.size());
  for (const auto &m : members_) {
    PartyParticipant p{};
    p.id = m.handle;
    p.display_name = format_member_display_name(m);
    p.role = PartyMemberRole::operator_human;
    p.host = m.client;
    p.model = m.agent_name;
    p.state = map_member_state(m);
    p.local_self = m.is_self;
    snap.participants.push_back(std::move(p));
  }

  snap.messages.reserve(messages_.size());
  for (const auto &m : messages_) {
    PartyMessage pm{};
    pm.id =
        !m.client_msg_id.empty() ? m.client_msg_id : ("seq-" + std::to_string(m.seq));
    pm.timestamp_ns = static_cast<std::int64_t>(m.ts_ms) * 1000000LL;
    pm.sender_id = m.sender_handle.empty() ? std::string{"system"}
                                           : ("@" + strip_at(m.sender_handle));
    pm.sender_role = m.kind == "agent_card" ? PartyMemberRole::platoon_leader
                                            : PartyMemberRole::operator_human;
    pm.sender_host = m.sender_client;
    pm.sender_model = m.sender_agent_name;
    pm.verified_peer = true;
    pm.target = m.target.empty() ? std::string{"@all"} : m.target;
    pm.kind = map_message_kind(m.kind);
    std::string body_out = m.rendered_body;
    if (m.local_self && m.kind == "chat") {
      body_out += m.delivered ? " ✓" : " …";
    }
    pm.body = std::move(body_out);
    pm.untrusted_remote = !m.local_self;
    snap.messages.push_back(std::move(pm));
  }
  return snap;
}

// ---------------------------------------------------------------------------
// Internal state helpers
// ---------------------------------------------------------------------------

void MpRoomV2Session::apply_members_locked(const std::vector<MpRoomV2Member> &members) {
  members_ = members;
  bool has_self = false;
  for (auto &m : members_) {
    if (local_account_id_.has_value() && m.account_id == *local_account_id_) {
      m.is_self = true;
      has_self = true;
    }
  }
  if (!has_self && local_account_id_.has_value()) {
    MpRoomV2Member self{};
    self.account_id = *local_account_id_;
    self.handle = local_handle_;
    self.client = client_name_;
    self.agent_name = agent_name_;
    self.agent_state = "idle";
    self.status = "live";
    self.is_self = true;
    members_.insert(members_.begin(), std::move(self));
  }
}

void MpRoomV2Session::upsert_message_locked(MpRoomV2Message msg) {
  if (msg.seq > 0U && seen_seqs_.contains(msg.seq)) {
    // Already observed this authoritative sequence number; update delivery if needed.
    for (auto &existing : messages_) {
      if (existing.seq == msg.seq) {
        existing.delivered = true;
        return;
      }
    }
    return;
  }

  if (!msg.client_msg_id.empty()) {
    for (auto &existing : messages_) {
      if (existing.client_msg_id == msg.client_msg_id) {
        if (msg.seq > 0U) {
          existing.seq = msg.seq;
          seen_seqs_.insert(msg.seq);
          if (msg.seq > latest_seq_) {
            latest_seq_ = msg.seq;
            latest_seq_atomic_.store(latest_seq_, std::memory_order_release);
          }
        }
        if (msg.ts_ms > 0U) {
          existing.ts_ms = msg.ts_ms;
        }
        if (!msg.sender_handle.empty()) {
          existing.sender_handle = msg.sender_handle;
        }
        if (!msg.rendered_body.empty()) {
          existing.rendered_body = msg.rendered_body;
        }
        existing.delivered = existing.delivered || msg.delivered || msg.seq > 0U;
        return;
      }
    }
    if (seen_client_msg_ids_.contains(msg.client_msg_id)) {
      return;
    }
    seen_client_msg_ids_.insert(msg.client_msg_id);
  }

  if (msg.seq > 0U) {
    seen_seqs_.insert(msg.seq);
    if (msg.seq > latest_seq_) {
      latest_seq_ = msg.seq;
      latest_seq_atomic_.store(latest_seq_, std::memory_order_release);
    }
  }

  messages_.push_back(std::move(msg));
  while (messages_.size() > max_retained_messages_) {
    messages_.pop_front();
  }
}

void MpRoomV2Session::push_notice_locked(std::string_view notice) {
  const std::string clean = party_chat_sanitize(notice, 256U);
  if (clean.empty()) {
    return;
  }
  notices_.push_back(clean);
  while (notices_.size() > kMpRoomV2MaxRetainedNotices) {
    notices_.pop_front();
  }
}

void MpRoomV2Session::rebuild_status_summary_locked() {
  switch (state_) {
  case MpRoomV2State::connecting:
    status_summary_ = "◐ Connecting…";
    return;
  case MpRoomV2State::reconnecting:
    if (!outbox_.empty()) {
      status_summary_ =
          "◐ Reconnecting… (" + std::to_string(outbox_.size()) +
          (outbox_.size() == 1U ? " message queued)" : " messages queued)");
    } else {
      status_summary_ = "◐ Reconnecting…";
    }
    return;
  case MpRoomV2State::disconnected:
    status_summary_ = "○ Disconnected";
    return;
  case MpRoomV2State::stopped:
    status_summary_ = "○ Left party";
    return;
  case MpRoomV2State::live: {
    std::string peers;
    std::size_t peer_count = 0U;
    for (const auto &m : members_) {
      if (m.is_self || m.status == "offline") {
        continue;
      }
      if (peer_count > 0U) {
        peers += ", ";
      }
      if (peer_count < 4U) {
        peers += "@" + m.handle;
      }
      ++peer_count;
    }
    if (peer_count > 4U) {
      peers += " +" + std::to_string(peer_count - 4U);
    }
    if (peer_count > 0U) {
      status_summary_ = "● Connected — live with " + peers;
    } else if (!room_code_.empty()) {
      status_summary_ = "● Live — room code " + room_code_;
    } else {
      status_summary_ = "● Live";
    }
    return;
  }
  }
}

// ---------------------------------------------------------------------------
// Inbound `mp2` frame handlers
// ---------------------------------------------------------------------------

void MpRoomV2Session::handle_hello_locked(const Value &obj, FrameAction &action) {
  if (const auto rc = json_opt_string(obj, "room_code");
      rc.has_value() && !rc->empty()) {
    room_code_ = party_chat_sanitize(*rc, 32U);
  }
  if (const auto rn = json_opt_string(obj, "name"); rn.has_value() && !rn->empty()) {
    room_name_ = party_chat_sanitize(*rn, 128U);
  }
  if (const Value *self_field = obj.find("self");
      self_field != nullptr &&
      std::holds_alternative<Value::Object>(self_field->value())) {
    if (const auto sh = json_opt_string(*self_field, "handle");
        sh.has_value() && !sh->empty()) {
      local_handle_ = party_chat_sanitize(strip_at(*sh), 64U);
    }
  }

  const auto parsed_members = parse_members_array(obj, local_account_id_);
  if (!parsed_members.empty()) {
    apply_members_locked(parsed_members);
  }

  if (const Value *hist_field = obj.find("history"); hist_field != nullptr) {
    if (const auto *arr = std::get_if<Value::Array>(&hist_field->value())) {
      for (const auto &ev : *arr) {
        if (std::holds_alternative<Value::Object>(ev.value())) {
          handle_event_locked(ev);
        }
      }
    }
  }

  const std::uint64_t server_latest =
      json_u64_or_decimal(obj, "latest_seq").value_or(0U);
  if (connected_once_ && latest_seq_ > 0U) {
    action.need_send_resume = true;
    action.resume_seq = latest_seq_;
  } else if (server_latest > latest_seq_) {
    action.need_send_resume = true;
    action.resume_seq = latest_seq_;
  }

  const bool was_reconnecting = (state_ == MpRoomV2State::reconnecting);
  state_ = MpRoomV2State::live;
  connected_once_ = true;
  if (was_reconnecting) {
    push_notice_locked("Reconnected to party" + (!room_code_.empty()
                                                     ? (" (" + room_code_ + ")")
                                                     : std::string{}));
  }
  for (auto &out : outbox_) {
    out.sent_on_current_socket = false;
  }
  action.need_flush_outbox = !outbox_.empty();
  rebuild_status_summary_locked();
}

void MpRoomV2Session::handle_event_locked(const Value &obj) {
  const std::uint64_t seq = json_u64_or_decimal(obj, "seq").value_or(0U);
  const std::uint64_t ts_ms = json_u64_or_decimal(obj, "ts_ms").value_or(wall_now_ms());
  const std::string cmsg_id =
      party_chat_sanitize(json_opt_string(obj, "client_msg_id").value_or(""), 128U);
  const std::string target = party_chat_sanitize(
      json_opt_string(obj, "target").value_or("@all"), kMaxRoomTargetBytes);
  const std::string kind =
      party_chat_sanitize(json_opt_string(obj, "kind").value_or("chat"), 32U);
  const std::string encoding =
      party_chat_sanitize(json_opt_string(obj, "body_encoding").value_or("utf8"), 32U);
  const std::string body = json_opt_string(obj, "body").value_or("");

  MpRoomV2Message msg{};
  msg.seq = seq;
  msg.ts_ms = ts_ms;
  msg.client_msg_id = cmsg_id;
  msg.target = target.empty() ? std::string{"@all"} : target;
  msg.kind = kind.empty() ? std::string{"chat"} : kind;
  msg.body_encoding = encoding.empty() ? std::string{"utf8"} : encoding;
  msg.body = body;
  msg.delivered = true;

  if (const Value *sender_field = obj.find("sender");
      sender_field != nullptr &&
      std::holds_alternative<Value::Object>(sender_field->value())) {
    if (const auto acct_raw = json_u64_or_decimal(*sender_field, "account_id");
        acct_raw.has_value()) {
      if (const auto aid = mp::AccountId::create(*acct_raw); aid.has_value()) {
        msg.sender_account_id = aid.value();
      }
    }
    msg.sender_handle = party_chat_sanitize(
        strip_at(json_opt_string(*sender_field, "handle").value_or("")), 64U);
    msg.sender_client =
        party_chat_sanitize(json_opt_string(*sender_field, "client").value_or(""), 32U);
    msg.sender_agent_name = party_chat_sanitize(
        json_opt_string(*sender_field, "agent_name").value_or(""), 48U);
  }
  msg.local_self = local_account_id_.has_value() && msg.sender_account_id.has_value() &&
                   *msg.sender_account_id == *local_account_id_;

  if (msg.kind == "agent_card" && msg.body_encoding == "utf8") {
    msg.rendered_body = render_agent_card_body(msg.body);
  } else if (msg.body_encoding == "opaque_b64") {
    msg.rendered_body = "[encrypted message]";
  } else {
    msg.rendered_body = party_chat_sanitize(msg.body, 2048U);
  }

  // If this event echoes one of our queued messages, remove from retry outbox.
  if (!cmsg_id.empty()) {
    std::erase_if(outbox_, [&](const OutboundMessage &pending) {
      return pending.client_msg_id == cmsg_id;
    });
  }

  upsert_message_locked(std::move(msg));
  rebuild_status_summary_locked();
}

void MpRoomV2Session::handle_ack_locked(const Value &obj) {
  const std::string cmsg_id =
      party_chat_sanitize(json_opt_string(obj, "client_msg_id").value_or(""), 128U);
  const std::uint64_t seq = json_u64_or_decimal(obj, "seq").value_or(0U);
  const std::uint64_t ts_ms = json_u64_or_decimal(obj, "ts_ms").value_or(0U);

  if (!cmsg_id.empty()) {
    std::erase_if(outbox_, [&](const OutboundMessage &pending) {
      return pending.client_msg_id == cmsg_id;
    });
    for (auto &m : messages_) {
      if (m.client_msg_id == cmsg_id) {
        m.delivered = true;
        if (seq > 0U) {
          m.seq = seq;
          seen_seqs_.insert(seq);
        }
        if (ts_ms > 0U) {
          m.ts_ms = ts_ms;
        }
        break;
      }
    }
  }
  if (seq > latest_seq_) {
    latest_seq_ = seq;
    latest_seq_atomic_.store(latest_seq_, std::memory_order_release);
  }
  rebuild_status_summary_locked();
}

void MpRoomV2Session::handle_presence_locked(const Value &obj) {
  const auto parsed_members = parse_members_array(obj, local_account_id_);
  apply_members_locked(parsed_members);
  rebuild_status_summary_locked();
}

void MpRoomV2Session::handle_error_locked(const Value &obj, FrameAction &action) {
  const std::string message =
      party_chat_sanitize(json_opt_string(obj, "message").value_or(""), 200U);
  const std::string code =
      party_chat_sanitize(json_opt_string(obj, "code").value_or("error"), 48U);
  const std::uint64_t retry_ms = json_u64_or_decimal(obj, "retry_ms").value_or(0U);
  if (retry_ms > 0U) {
    action.retry_backoff_ms =
        static_cast<std::uint32_t>(std::min<std::uint64_t>(retry_ms, 30000U));
  }
  if (!message.empty()) {
    push_notice_locked(message);
  } else {
    push_notice_locked("Party error: " + code);
  }
}

void MpRoomV2Session::handle_text_frame_locked(std::string_view json_text,
                                               FrameAction &action) {
  ValueLimits limits{};
  limits.bytes = mp::kMaxMp2FrameBytes;
  limits.nodes = 8192U;
  limits.depth = 32U;
  const auto parsed = parse_json(json_text, limits);
  if (!parsed.has_value() ||
      !std::holds_alternative<Value::Object>(parsed.value().value())) {
    return;
  }
  const Value &obj = parsed.value();
  const auto type = json_opt_string(obj, "t");
  if (!type.has_value()) {
    return;
  }
  if (*type == "hello") {
    handle_hello_locked(obj, action);
  } else if (*type == "event") {
    handle_event_locked(obj);
  } else if (*type == "ack") {
    handle_ack_locked(obj);
  } else if (*type == "presence") {
    handle_presence_locked(obj);
  } else if (*type == "error") {
    handle_error_locked(obj, action);
  }
}

// ---------------------------------------------------------------------------
// Outbound wire framing & worker loop
// ---------------------------------------------------------------------------

bool MpRoomV2Session::send_resume_frame(mp::MpControlSocket &sock,
                                        std::uint64_t last_seq) {
  Value::Object frame;
  frame.emplace_back("v", Value{Number{std::uint64_t{2U}}});
  frame.emplace_back("t", Value{"resume"});
  frame.emplace_back("last_seq", Value{Number{last_seq}});
  const auto dumped = dump_json(Value::object(std::move(frame)));
  if (!dumped.has_value()) {
    return false;
  }
  return sock.send_text(dumped.value()).has_value();
}

bool MpRoomV2Session::flush_outbox(mp::MpControlSocket &sock) {
  std::vector<OutboundMessage> to_send;
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    for (auto &msg : outbox_) {
      if (!msg.sent_on_current_socket) {
        to_send.push_back(msg);
      }
    }
  }
  for (const auto &msg : to_send) {
    Value::Object frame;
    frame.emplace_back("v", Value{Number{std::uint64_t{2U}}});
    frame.emplace_back("t", Value{"send"});
    frame.emplace_back("client_msg_id", Value{msg.client_msg_id});
    frame.emplace_back("kind", Value{msg.kind});
    frame.emplace_back("target", Value{msg.target});
    frame.emplace_back("body_encoding", Value{msg.body_encoding});
    frame.emplace_back("body", Value{msg.body});
    const auto dumped = dump_json(Value::object(std::move(frame)));
    if (!dumped.has_value()) {
      continue;
    }
    if (!sock.send_text(dumped.value()).has_value()) {
      return false;
    }
    std::lock_guard<std::mutex> lock(state_mu_);
    for (auto &pending : outbox_) {
      if (pending.client_msg_id == msg.client_msg_id) {
        pending.sent_on_current_socket = true;
        break;
      }
    }
  }
  return true;
}

bool MpRoomV2Session::flush_pending_status(mp::MpControlSocket &sock) {
  std::optional<MpRoomV2StatusUpdate> st;
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (!pending_status_.has_value()) {
      return true;
    }
    st = std::move(pending_status_);
    pending_status_.reset();
  }
  Value::Object frame;
  frame.emplace_back("v", Value{Number{std::uint64_t{2U}}});
  frame.emplace_back("t", Value{"status"});
  frame.emplace_back("client", Value{st->client});
  frame.emplace_back("agent_name", Value{st->agent_name});
  frame.emplace_back("agent_state", Value{st->agent_state});
  if (!st->agent_summary.empty()) {
    frame.emplace_back("agent_summary", Value{st->agent_summary});
  }
  const auto dumped = dump_json(Value::object(std::move(frame)));
  if (!dumped.has_value()) {
    return true;
  }
  if (!sock.send_text(dumped.value()).has_value()) {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (!pending_status_.has_value()) {
      pending_status_ = std::move(st);
    }
    return false;
  }
  return true;
}

std::uint32_t
MpRoomV2Session::compute_reconnect_backoff_ms(std::uint32_t attempt) const noexcept {
  const std::uint32_t shift = std::min<std::uint32_t>(attempt, 10U);
  const std::uint64_t scaled = static_cast<std::uint64_t>(reconnect_base_ms_) << shift;
  return static_cast<std::uint32_t>(
      std::min<std::uint64_t>(scaled, static_cast<std::uint64_t>(reconnect_max_ms_)));
}

void MpRoomV2Session::worker_loop(const std::stop_token &stop_token) {
  auto last_ping = SteadyClock::now();
  auto next_reconnect_at = SteadyClock::now();
  auto rate_limit_until = SteadyClock::time_point{};
  std::uint32_t reconnect_attempt = 0U;

  auto enter_reconnecting = [&](std::string_view reason) {
    if (socket_.has_value()) {
      (void)socket_->close(1000U);
      socket_.reset();
    }
    const std::uint32_t backoff = compute_reconnect_backoff_ms(reconnect_attempt);
    ++reconnect_attempt;
    next_reconnect_at = SteadyClock::now() + std::chrono::milliseconds{backoff};
    {
      std::lock_guard<std::mutex> lock(state_mu_);
      const bool already_reconnecting = (state_ == MpRoomV2State::reconnecting);
      state_ = MpRoomV2State::reconnecting;
      for (auto &out : outbox_) {
        out.sent_on_current_socket = false;
      }
      if (!already_reconnecting) {
        std::string note = std::string{reason};
        if (!outbox_.empty()) {
          note += " (" + std::to_string(outbox_.size()) +
                  (outbox_.size() == 1U ? " message queued)" : " messages queued)");
        }
        push_notice_locked(note);
      }
      rebuild_status_summary_locked();
    }
    signal_wake();
  };

  while (!stop_token.stop_requested() &&
         !stop_requested_.load(std::memory_order_acquire)) {
    const auto now = SteadyClock::now();

    // 1. Reconnect path when socket is down.
    if (!socket_.has_value() || !socket_->is_open()) {
      if (now < next_reconnect_at) {
        const auto wait_ms = std::min<std::int64_t>(
            poll_interval_ms_, std::chrono::duration_cast<std::chrono::milliseconds>(
                                   next_reconnect_at - now)
                                   .count());
        if (wait_ms > 0) {
          std::this_thread::sleep_for(std::chrono::milliseconds{wait_ms});
        }
        continue;
      }
      auto reconnected = client_.connect_ws_v2(ws_path_);
      if (!reconnected.has_value()) {
        if (is_permanent_connect_error(reconnected.error())) {
          {
            std::lock_guard<std::mutex> lock(state_mu_);
            state_ = MpRoomV2State::disconnected;
            push_notice_locked("Party connection ended — rejoin when ready.");
            rebuild_status_summary_locked();
          }
          signal_wake();
          break;
        }
        enter_reconnecting("Connection dropped — reconnecting automatically");
        continue;
      }
      socket_.emplace(std::move(reconnected).value());
      reconnect_attempt = 0U;
      last_ping = SteadyClock::now();
      continue;
    }

    mp::MpControlSocket &active_sock = *socket_;

    // 2. Flush outbound messages & status when live and not rate-limited.
    bool can_send = false;
    {
      std::lock_guard<std::mutex> lock(state_mu_);
      can_send = (state_ == MpRoomV2State::live);
    }
    if (can_send && now >= rate_limit_until) {
      if (!flush_outbox(active_sock) || !flush_pending_status(active_sock)) {
        enter_reconnecting("Connection dropped — reconnecting automatically");
        continue;
      }
    }

    // 3. Periodic MP2:PING heartbeat.
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_ping)
            .count() >= static_cast<std::int64_t>(ping_interval_ms_)) {
      last_ping = now;
      if (!active_sock.send_ping().has_value()) {
        enter_reconnecting("Connection dropped — reconnecting automatically");
        continue;
      }
    }

    // 4. Poll inbound mp2 text frame.
    const auto polled =
        active_sock.poll_text_frame(static_cast<int>(poll_interval_ms_));
    if (!polled.has_value()) {
      enter_reconnecting("Connection dropped — reconnecting automatically");
      continue;
    }
    if (!polled.value().has_value()) {
      continue;
    }

    const auto &ev = polled.value().value();
    if (std::holds_alternative<mp::MpWsPong>(ev)) {
      continue;
    }
    if (const auto *closed = std::get_if<mp::MpWsClosed>(&ev)) {
      if (is_permanent_close_code(closed->code)) {
        socket_.reset();
        {
          std::lock_guard<std::mutex> lock(state_mu_);
          state_ = MpRoomV2State::disconnected;
          push_notice_locked("Party closed by server.");
          rebuild_status_summary_locked();
        }
        signal_wake();
        break;
      }
      enter_reconnecting("Connection dropped — reconnecting automatically");
      continue;
    }
    if (const auto *text = std::get_if<mp::MpWsTextFrame>(&ev)) {
      FrameAction action{};
      {
        std::lock_guard<std::mutex> lock(state_mu_);
        handle_text_frame_locked(text->payload, action);
      }
      if (action.retry_backoff_ms > 0U) {
        rate_limit_until =
            SteadyClock::now() + std::chrono::milliseconds{action.retry_backoff_ms};
      }
      if (action.need_send_resume) {
        if (!send_resume_frame(active_sock, action.resume_seq)) {
          enter_reconnecting("Connection dropped — reconnecting automatically");
          continue;
        }
      }
      if (action.need_flush_outbox && SteadyClock::now() >= rate_limit_until) {
        if (!flush_outbox(active_sock)) {
          enter_reconnecting("Connection dropped — reconnecting automatically");
          continue;
        }
      }
      signal_wake();
    }
  }

  if (socket_.has_value()) {
    (void)socket_->close(1000U);
    socket_.reset();
  }
}

} // namespace blackbird
