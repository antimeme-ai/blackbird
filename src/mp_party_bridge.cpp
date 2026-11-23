#include "blackbird/mp_party_bridge.hpp"

#include "blackbird/json.hpp"
#include "blackbird/party_chat.hpp"
#include "blackbird/party_lobby.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <ostream>
#include <poll.h>
#include <span>
#include <string>
#include <string_view>
#include <unistd.h>
#include <unordered_set>
#include <utility>
#include <vector>

namespace blackbird {

namespace {

template <typename T> Result<T> fail(ErrorCode code, MpPartyBridgeError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_void(ErrorCode code, MpPartyBridgeError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
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

std::string base64_encode(std::span<const std::uint8_t> bytes) {
  static constexpr char kAlpha[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((bytes.size() + 2U) / 3U) * 4U);
  std::size_t i = 0U;
  while (i + 3U <= bytes.size()) {
    const std::uint32_t t = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                            static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 6U) & 0x3fU]);
    out.push_back(kAlpha[t & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1U) {
    const std::uint32_t t = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t t = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

std::int64_t current_unix_ns() noexcept {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string_view trim_ascii_whitespace(std::string_view s) noexcept {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' ||
                        s.front() == '\n')) {
    s.remove_prefix(1U);
  }
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' ||
                        s.back() == '\n')) {
    s.remove_suffix(1U);
  }
  return s;
}

std::string_view strip_trailing_eol(std::string_view s) noexcept {
  while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) {
    s.remove_suffix(1U);
  }
  return s;
}

std::string_view member_leave_reason_name(mp::MemberLeaveReason reason) noexcept {
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
leader_change_reason_name(mp::PartyLeaderChangeReason reason) noexcept {
  switch (reason) {
  case mp::PartyLeaderChangeReason::promoted:
    return "promoted";
  case mp::PartyLeaderChangeReason::auto_migrated:
    return "auto_migrated";
  }
  return "unknown";
}

std::string_view party_disband_reason_name(mp::PartyDisbandReason reason) noexcept {
  switch (reason) {
  case mp::PartyDisbandReason::leader_disbanded:
    return "leader_disbanded";
  case mp::PartyDisbandReason::empty_timeout:
    return "empty_timeout";
  }
  return "unknown";
}

std::string_view peer_connection_state_name(P2pPeerConnectionState state) noexcept {
  switch (state) {
  case P2pPeerConnectionState::admitted:
    return "admitted";
  case P2pPeerConnectionState::dial_pending:
    return "dial_pending";
  case P2pPeerConnectionState::connected:
    return "connected";
  case P2pPeerConnectionState::disconnected:
    return "disconnected";
  }
  return "unknown";
}

Result<void> validate_text_cap(std::string_view text, std::size_t max_bytes,
                               bool allow_empty) {
  if (!allow_empty && text.empty()) {
    return fail_void(ErrorCode::invalid_range, MpPartyBridgeError::invalid_field);
  }
  if (text.size() > max_bytes) {
    return fail_void(ErrorCode::capacity, MpPartyBridgeError::field_too_large);
  }
  if (!is_valid_utf8_strict(text)) {
    return fail_void(ErrorCode::corrupt, MpPartyBridgeError::invalid_utf8);
  }
  return Result<void>::success();
}

Result<std::uint64_t> parse_u64_number(const Value &val) {
  const auto *num = std::get_if<Number>(&val.value());
  if (num == nullptr) {
    return fail<std::uint64_t>(ErrorCode::invalid_range,
                               MpPartyBridgeError::invalid_device_id);
  }
  if (const auto *u64 = std::get_if<std::uint64_t>(&num->storage())) {
    return Result<std::uint64_t>::success(*u64);
  }
  if (const auto *i64 = std::get_if<std::int64_t>(&num->storage())) {
    if (*i64 < 0) {
      return fail<std::uint64_t>(ErrorCode::invalid_range,
                                 MpPartyBridgeError::invalid_device_id);
    }
    return Result<std::uint64_t>::success(static_cast<std::uint64_t>(*i64));
  }
  return fail<std::uint64_t>(ErrorCode::invalid_range,
                             MpPartyBridgeError::invalid_device_id);
}

struct JsonStringFieldSpec {
  std::string_view key;
  std::size_t max_bytes = 0U;
  bool required = false;
  bool allow_empty = true;
  std::string_view default_value;
};

Result<std::string> extract_string_field(const Value &obj,
                                         const JsonStringFieldSpec &spec) {
  const Value *found = obj.find(spec.key);
  if (found == nullptr) {
    if (spec.required) {
      return fail<std::string>(ErrorCode::corrupt, MpPartyBridgeError::invalid_field);
    }
    return Result<std::string>::success(std::string{spec.default_value});
  }
  const auto *str = std::get_if<std::string>(&found->value());
  if (str == nullptr) {
    return fail<std::string>(ErrorCode::corrupt, MpPartyBridgeError::invalid_field);
  }
  if (const auto ok = validate_text_cap(*str, spec.max_bytes, spec.allow_empty);
      !ok.has_value()) {
    return Result<std::string>::failure(ok.error());
  }
  return Result<std::string>::success(*str);
}

bool has_duplicate_keys(const Value::Object &entries) {
  std::unordered_set<std::string_view> seen;
  seen.reserve(entries.size());
  for (const auto &[key, _] : entries) {
    if (!seen.insert(key).second) {
      return true;
    }
  }
  return false;
}

std::string resolve_chat_sender_handle(const MpRuntimeEvent &event,
                                       const MpPartyRuntime &runtime,
                                       const MpPeerMetadataMap *peer_metadata) {
  if (event.sender_device_id.has_value()) {
    const std::uint64_t dev_raw = event.sender_device_id->value();
    if (peer_metadata != nullptr) {
      if (const auto it = peer_metadata->find(dev_raw);
          it != peer_metadata->end() && !it->second.handle.empty()) {
        return it->second.handle;
      }
    }
    const auto peer = runtime.find_peer(*event.sender_device_id);
    if (peer.has_value()) {
      if (event.chat.has_value() && !event.chat->sender_handle.empty()) {
        return event.chat->sender_handle;
      }
      return "device-" + peer->device_id.to_decimal();
    }
    const auto &local_id = runtime.config().identity;
    if (local_id.device_id.has_value() &&
        *local_id.device_id == *event.sender_device_id && !local_id.handle.empty()) {
      return local_id.handle;
    }
  }
  if (event.chat.has_value() && !event.chat->sender_handle.empty()) {
    return event.chat->sender_handle;
  }
  if (event.sender_device_id.has_value()) {
    return "device-" + event.sender_device_id->to_decimal();
  }
  return "unknown";
}

std::string sanitize_lobby_alias(std::string_view candidate,
                                 std::optional<mp::DeviceId> sender_device_id) {
  std::string out;
  out.reserve(std::min<std::size_t>(candidate.size(), kPartyMaxAliasBytes));
  for (const char ch : candidate) {
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
    if (ok) {
      if (out.empty() && (ch == '-' || ch == '.')) {
        continue;
      }
      out.push_back(ch);
      if (out.size() >= kPartyMaxAliasBytes) {
        break;
      }
    }
  }
  if (valid_party_alias(out)) {
    return out;
  }
  if (sender_device_id.has_value()) {
    std::string fallback = "peer_" + sender_device_id->to_decimal();
    if (valid_party_alias(fallback)) {
      return fallback;
    }
  }
  return "online_peer";
}

std::string resolve_local_sender_handle(const MpPartyRuntime &runtime,
                                        const MpAttachConfig &config) {
  if (config.local_sender_handle.has_value() && !config.local_sender_handle->empty()) {
    return *config.local_sender_handle;
  }
  const auto &id = runtime.config().identity;
  if (!id.handle.empty() && id.handle.size() <= kP2pPartyMaxSenderHandleBytes &&
      is_valid_utf8_strict(id.handle)) {
    return id.handle;
  }
  if (id.device_id.has_value()) {
    return "device-" + id.device_id->to_decimal();
  }
  return "local";
}

std::string serialize_json_line(const Value &val) {
  const auto dumped = dump_json(
      val, ValueLimits{.bytes = 4U * 1024U * 1024U, .nodes = 100000U, .depth = 32U});
  if (dumped.has_value()) {
    return dumped.value();
  }
  return "{\"type\":\"error\",\"error_code\":\"internal_serialize_failed\"}";
}

Value make_ready_event_json(const MpPartyRuntime &runtime, MpAttachMode mode,
                            std::string_view local_handle) {
  Value::Object obj;
  obj.emplace_back("type", Value{"ready"});
  obj.emplace_back("party_id", Value{Number{runtime.party_id().value()}});
  obj.emplace_back("party_epoch", Value{Number{runtime.party_epoch()}});
  obj.emplace_back("state", Value{std::string{mp_runtime_state_name(runtime.state())}});
  obj.emplace_back("mode", Value{std::string{mp_attach_mode_name(mode)}});
  const auto &id = runtime.config().identity;
  if (id.device_id.has_value()) {
    obj.emplace_back("local_device_id", Value{Number{id.device_id->value()}});
  }
  if (id.account_id.has_value()) {
    obj.emplace_back("local_account_id", Value{Number{id.account_id->value()}});
  }
  obj.emplace_back("local_handle", Value{std::string{local_handle}});
  if (const auto pk = runtime.local_pubkey(); pk.has_value()) {
    obj.emplace_back("local_pubkey_b64", Value{base64_encode(*pk)});
  }
  return Value::object(std::move(obj));
}

Value make_closed_event_json(const MpPartyRuntime &runtime, std::string_view reason) {
  Value::Object obj;
  obj.emplace_back("type", Value{"closed"});
  obj.emplace_back("party_id", Value{Number{runtime.party_id().value()}});
  obj.emplace_back("party_epoch", Value{Number{runtime.party_epoch()}});
  obj.emplace_back("state", Value{std::string{mp_runtime_state_name(runtime.state())}});
  obj.emplace_back("reason", Value{std::string{reason}});
  return Value::object(std::move(obj));
}

Value make_command_error_json(const MpPartyRuntime &runtime, std::string_view cmd_name,
                              const Error &err) {
  Value::Object obj;
  obj.emplace_back("type", Value{"command_error"});
  obj.emplace_back("party_id", Value{Number{runtime.party_id().value()}});
  obj.emplace_back("party_epoch", Value{Number{runtime.party_epoch()}});
  if (!cmd_name.empty()) {
    obj.emplace_back("cmd", Value{std::string{cmd_name}});
  }
  obj.emplace_back("error_code", Value{error_name(err.code)});
  obj.emplace_back("error_detail", Value{Number{err.detail}});
  return Value::object(std::move(obj));
}

Value make_broadcast_ack_json(const MpPartyRuntime &runtime, std::string_view cmd_name,
                              const P2pPartyBroadcastResult &res) {
  Value::Object obj;
  obj.emplace_back("type", Value{"ack"});
  obj.emplace_back("cmd", Value{std::string{cmd_name}});
  obj.emplace_back("party_id", Value{Number{runtime.party_id().value()}});
  obj.emplace_back("party_epoch", Value{Number{runtime.party_epoch()}});
  obj.emplace_back("attempted", Value{Number{res.attempted}});
  obj.emplace_back("sent", Value{Number{res.sent}});
  obj.emplace_back("failed", Value{Number{res.failures.size()}});
  return Value::object(std::move(obj));
}

Value make_simple_ack_json(const MpPartyRuntime &runtime, std::string_view cmd_name,
                           std::optional<mp::DeviceId> target_device = std::nullopt) {
  Value::Object obj;
  obj.emplace_back("type", Value{"ack"});
  obj.emplace_back("cmd", Value{std::string{cmd_name}});
  obj.emplace_back("party_id", Value{Number{runtime.party_id().value()}});
  obj.emplace_back("party_epoch", Value{Number{runtime.party_epoch()}});
  if (target_device.has_value()) {
    obj.emplace_back("device_id", Value{Number{target_device->value()}});
    obj.emplace_back("sent", Value{Number{std::uint64_t{1U}}});
  }
  return Value::object(std::move(obj));
}

Value make_roster_event_json(const MpPartyRuntime &runtime,
                             const MpPeerMetadataMap *peer_metadata) {
  Value::Object obj;
  obj.emplace_back("type", Value{"roster"});
  obj.emplace_back("party_id", Value{Number{runtime.party_id().value()}});
  obj.emplace_back("party_epoch", Value{Number{runtime.party_epoch()}});
  obj.emplace_back("peer_count", Value{Number{runtime.peer_count()}});
  obj.emplace_back("peers", mp_runtime_roster_to_json(runtime, peer_metadata));
  return Value::object(std::move(obj));
}

std::string format_roster_human(const MpPartyRuntime &runtime,
                                const MpPeerMetadataMap *peer_metadata) {
  const auto peers = runtime.roster();
  std::string out = "[roster] party #" + runtime.party_id().to_decimal() + " epoch " +
                    std::to_string(runtime.party_epoch()) + " (" +
                    std::to_string(peers.size()) + " peers)";
  for (const auto &peer : peers) {
    out += " | #" + peer.device_id.to_decimal();
    if (peer_metadata != nullptr) {
      if (const auto it = peer_metadata->find(peer.device_id.value());
          it != peer_metadata->end() && !it->second.handle.empty()) {
        out += " @" + party_chat_sanitize(it->second.handle, 64U);
      }
    }
    const bool is_leader = runtime.leader_device_id().has_value() &&
                           *runtime.leader_device_id() == peer.device_id;
    if (is_leader) {
      out += " [leader]";
    }
    out += " (" + std::string{peer_connection_state_name(peer.connection_state)} + ")";
  }
  return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Name & parse helpers
// ---------------------------------------------------------------------------

std::string_view mp_party_bridge_error_name(MpPartyBridgeError detail) noexcept {
  switch (detail) {
  case MpPartyBridgeError::none:
    return "none";
  case MpPartyBridgeError::line_too_large:
    return "line_too_large";
  case MpPartyBridgeError::invalid_utf8:
    return "invalid_utf8";
  case MpPartyBridgeError::invalid_json:
    return "invalid_json";
  case MpPartyBridgeError::not_json_object:
    return "not_json_object";
  case MpPartyBridgeError::missing_command:
    return "missing_command";
  case MpPartyBridgeError::unknown_command:
    return "unknown_command";
  case MpPartyBridgeError::invalid_field:
    return "invalid_field";
  case MpPartyBridgeError::field_too_large:
    return "field_too_large";
  case MpPartyBridgeError::invalid_enum:
    return "invalid_enum";
  case MpPartyBridgeError::invalid_device_id:
    return "invalid_device_id";
  case MpPartyBridgeError::invalid_config:
    return "invalid_config";
  case MpPartyBridgeError::io_error:
    return "io_error";
  }
  return "unknown";
}

std::string_view mp_attach_mode_name(MpAttachMode mode) noexcept {
  switch (mode) {
  case MpAttachMode::jsonl:
    return "jsonl";
  case MpAttachMode::plain:
    return "plain";
  }
  return "unknown";
}

Result<MpAttachMode> parse_mp_attach_mode(std::string_view text) noexcept {
  if (text == "jsonl") {
    return Result<MpAttachMode>::success(MpAttachMode::jsonl);
  }
  if (text == "plain") {
    return Result<MpAttachMode>::success(MpAttachMode::plain);
  }
  return fail<MpAttachMode>(ErrorCode::invalid_range, MpPartyBridgeError::invalid_enum);
}

std::string_view p2p_party_activity_state_name(P2pPartyActivityState state) noexcept {
  switch (state) {
  case P2pPartyActivityState::offline:
    return "offline";
  case P2pPartyActivityState::online:
    return "online";
  case P2pPartyActivityState::working:
    return "working";
  case P2pPartyActivityState::idle:
    return "idle";
  case P2pPartyActivityState::typing:
    return "typing";
  }
  return "unknown";
}

Result<P2pPartyActivityState>
parse_p2p_party_activity_state(std::string_view text) noexcept {
  if (text == "offline") {
    return Result<P2pPartyActivityState>::success(P2pPartyActivityState::offline);
  }
  if (text == "online") {
    return Result<P2pPartyActivityState>::success(P2pPartyActivityState::online);
  }
  if (text == "working") {
    return Result<P2pPartyActivityState>::success(P2pPartyActivityState::working);
  }
  if (text == "idle") {
    return Result<P2pPartyActivityState>::success(P2pPartyActivityState::idle);
  }
  if (text == "typing") {
    return Result<P2pPartyActivityState>::success(P2pPartyActivityState::typing);
  }
  return fail<P2pPartyActivityState>(ErrorCode::invalid_range,
                                     MpPartyBridgeError::invalid_enum);
}

std::string_view
p2p_party_control_notice_kind_name(P2pPartyControlNoticeKind kind) noexcept {
  switch (kind) {
  case P2pPartyControlNoticeKind::sync_ack:
    return "sync_ack";
  case P2pPartyControlNoticeKind::scope_changed:
    return "scope_changed";
  case P2pPartyControlNoticeKind::status:
    return "status";
  }
  return "unknown";
}

Result<P2pPartyControlNoticeKind>
parse_p2p_party_control_notice_kind(std::string_view text) noexcept {
  if (text == "sync_ack") {
    return Result<P2pPartyControlNoticeKind>::success(
        P2pPartyControlNoticeKind::sync_ack);
  }
  if (text == "scope_changed") {
    return Result<P2pPartyControlNoticeKind>::success(
        P2pPartyControlNoticeKind::scope_changed);
  }
  if (text == "status") {
    return Result<P2pPartyControlNoticeKind>::success(
        P2pPartyControlNoticeKind::status);
  }
  return fail<P2pPartyControlNoticeKind>(ErrorCode::invalid_range,
                                         MpPartyBridgeError::invalid_enum);
}

std::string_view mp_attach_command_kind_name(MpAttachCommandKind kind) noexcept {
  switch (kind) {
  case MpAttachCommandKind::say:
    return "say";
  case MpAttachCommandKind::pulse:
    return "pulse";
  case MpAttachCommandKind::notice:
    return "notice";
  case MpAttachCommandKind::roster:
    return "roster";
  case MpAttachCommandKind::ping:
    return "ping";
  case MpAttachCommandKind::quit:
    return "quit";
  }
  return "unknown";
}

std::string_view mp_runtime_event_json_type(MpRuntimeEventKind kind) noexcept {
  switch (kind) {
  case MpRuntimeEventKind::chat_received:
    return "chat";
  case MpRuntimeEventKind::bridge_envelope_received:
    return "bridge_envelope";
  case MpRuntimeEventKind::control_notice_received:
    return "notice";
  case MpRuntimeEventKind::ephemeral_pulse_received:
    return "pulse";
  default:
    return mp_runtime_event_kind_name(kind);
  }
}

// ---------------------------------------------------------------------------
// Strict JSONL & plain-line command parsers
// ---------------------------------------------------------------------------

Result<MpAttachCommand> parse_mp_attach_command(std::string_view line) {
  if (line.size() > kMpAttachMaxCommandBytes) {
    return fail<MpAttachCommand>(ErrorCode::capacity,
                                 MpPartyBridgeError::line_too_large);
  }
  if (!is_valid_utf8_strict(line)) {
    return fail<MpAttachCommand>(ErrorCode::corrupt, MpPartyBridgeError::invalid_utf8);
  }
  const std::string_view trimmed = trim_ascii_whitespace(line);
  if (trimmed.empty()) {
    return fail<MpAttachCommand>(ErrorCode::corrupt, MpPartyBridgeError::invalid_json);
  }

  const auto parsed = parse_json(
      trimmed,
      ValueLimits{.bytes = kMpAttachMaxCommandBytes, .nodes = 1024U, .depth = 16U});
  if (!parsed.has_value()) {
    return fail<MpAttachCommand>(ErrorCode::corrupt, MpPartyBridgeError::invalid_json);
  }
  const auto *entries = std::get_if<Value::Object>(&parsed.value().value());
  if (entries == nullptr) {
    return fail<MpAttachCommand>(ErrorCode::corrupt,
                                 MpPartyBridgeError::not_json_object);
  }
  if (has_duplicate_keys(*entries)) {
    return fail<MpAttachCommand>(ErrorCode::corrupt, MpPartyBridgeError::invalid_json);
  }

  const Value *cmd_val = parsed.value().find("cmd");
  if (cmd_val == nullptr) {
    return fail<MpAttachCommand>(ErrorCode::corrupt,
                                 MpPartyBridgeError::missing_command);
  }
  const auto *cmd_str = std::get_if<std::string>(&cmd_val->value());
  if (cmd_str == nullptr || cmd_str->empty()) {
    return fail<MpAttachCommand>(ErrorCode::corrupt,
                                 MpPartyBridgeError::missing_command);
  }

  if (*cmd_str == "say") {
    auto body = extract_string_field(
        parsed.value(),
        JsonStringFieldSpec{"body", kP2pPartyMaxChatBodyBytes, true, false, ""});
    if (!body.has_value()) {
      return Result<MpAttachCommand>::failure(body.error());
    }
    auto room_scope = extract_string_field(
        parsed.value(), JsonStringFieldSpec{"room_scope", kP2pPartyMaxRoomScopeBytes,
                                            false, false, kMpAttachDefaultRoomScope});
    if (!room_scope.has_value()) {
      return Result<MpAttachCommand>::failure(room_scope.error());
    }
    auto target = extract_string_field(
        parsed.value(), JsonStringFieldSpec{"target", kP2pPartyMaxTargetSelectorBytes,
                                            false, false, kMpAttachDefaultTarget});
    if (!target.has_value()) {
      return Result<MpAttachCommand>::failure(target.error());
    }
    std::optional<mp::DeviceId> device_id;
    if (const Value *dev_val = parsed.value().find("device_id");
        dev_val != nullptr &&
        !std::holds_alternative<std::nullptr_t>(dev_val->value())) {
      const auto raw_id = parse_u64_number(*dev_val);
      if (!raw_id.has_value()) {
        return Result<MpAttachCommand>::failure(raw_id.error());
      }
      const auto checked = mp::DeviceId::create(raw_id.value());
      if (!checked.has_value()) {
        return fail<MpAttachCommand>(ErrorCode::invalid_range,
                                     MpPartyBridgeError::invalid_device_id);
      }
      device_id = checked.value();
    }

    MpAttachSayCommand say_cmd{};
    say_cmd.body = std::move(body).value();
    say_cmd.room_scope = std::move(room_scope).value();
    say_cmd.target = std::move(target).value();
    say_cmd.device_id = device_id;
    return Result<MpAttachCommand>::success(
        MpAttachCommand{MpAttachCommandKind::say, std::move(say_cmd)});
  }

  if (*cmd_str == "pulse") {
    const auto state_str = extract_string_field(
        parsed.value(), JsonStringFieldSpec{"state", 32U, true, false, ""});
    if (!state_str.has_value()) {
      return Result<MpAttachCommand>::failure(state_str.error());
    }
    const auto state = parse_p2p_party_activity_state(state_str.value());
    if (!state.has_value()) {
      return Result<MpAttachCommand>::failure(state.error());
    }
    auto status = extract_string_field(
        parsed.value(), JsonStringFieldSpec{"status", kP2pPartyMaxEphemeralStatusBytes,
                                            false, true, ""});
    if (!status.has_value()) {
      return Result<MpAttachCommand>::failure(status.error());
    }
    MpAttachPulseCommand pulse_cmd{};
    pulse_cmd.state = state.value();
    pulse_cmd.status = std::move(status).value();
    return Result<MpAttachCommand>::success(
        MpAttachCommand{MpAttachCommandKind::pulse, std::move(pulse_cmd)});
  }

  if (*cmd_str == "notice") {
    const auto kind_str = extract_string_field(
        parsed.value(), JsonStringFieldSpec{"notice_kind", 32U, true, false, ""});
    if (!kind_str.has_value()) {
      return Result<MpAttachCommand>::failure(kind_str.error());
    }
    const auto notice_kind = parse_p2p_party_control_notice_kind(kind_str.value());
    if (!notice_kind.has_value()) {
      return Result<MpAttachCommand>::failure(notice_kind.error());
    }
    auto text = extract_string_field(
        parsed.value(),
        JsonStringFieldSpec{"text", kP2pPartyMaxControlNoticeBytes, false, true, ""});
    if (!text.has_value()) {
      return Result<MpAttachCommand>::failure(text.error());
    }
    MpAttachNoticeCommand notice_cmd{};
    notice_cmd.notice_kind = notice_kind.value();
    notice_cmd.text = std::move(text).value();
    return Result<MpAttachCommand>::success(
        MpAttachCommand{MpAttachCommandKind::notice, std::move(notice_cmd)});
  }

  if (*cmd_str == "roster") {
    return Result<MpAttachCommand>::success(
        MpAttachCommand{MpAttachCommandKind::roster, MpAttachRosterCommand{}});
  }
  if (*cmd_str == "ping") {
    return Result<MpAttachCommand>::success(
        MpAttachCommand{MpAttachCommandKind::ping, MpAttachPingCommand{}});
  }
  if (*cmd_str == "quit") {
    return Result<MpAttachCommand>::success(
        MpAttachCommand{MpAttachCommandKind::quit, MpAttachQuitCommand{}});
  }

  return fail<MpAttachCommand>(ErrorCode::invalid_range,
                               MpPartyBridgeError::unknown_command);
}

Result<std::optional<MpAttachCommand>>
parse_mp_attach_plain_line(std::string_view line,
                           MpAttachRoomScopeRef default_room_scope) {
  if (line.size() > kMpAttachMaxCommandBytes) {
    return fail<std::optional<MpAttachCommand>>(ErrorCode::capacity,
                                                MpPartyBridgeError::line_too_large);
  }
  if (!is_valid_utf8_strict(line)) {
    return fail<std::optional<MpAttachCommand>>(ErrorCode::corrupt,
                                                MpPartyBridgeError::invalid_utf8);
  }
  const std::string_view effective_scope = default_room_scope.value.empty()
                                               ? kMpAttachDefaultRoomScope
                                               : default_room_scope.value;
  if (const auto scope_ok =
          validate_text_cap(effective_scope, kP2pPartyMaxRoomScopeBytes, false);
      !scope_ok.has_value()) {
    return Result<std::optional<MpAttachCommand>>::failure(scope_ok.error());
  }

  const std::string_view trimmed = trim_ascii_whitespace(line);
  if (trimmed.empty()) {
    return Result<std::optional<MpAttachCommand>>::success(std::nullopt);
  }

  if (trimmed == "/quit" || trimmed == "/exit") {
    return Result<std::optional<MpAttachCommand>>::success(
        MpAttachCommand{MpAttachCommandKind::quit, MpAttachQuitCommand{}});
  }
  if (trimmed == "/roster") {
    return Result<std::optional<MpAttachCommand>>::success(
        MpAttachCommand{MpAttachCommandKind::roster, MpAttachRosterCommand{}});
  }
  if (trimmed == "/ping") {
    return Result<std::optional<MpAttachCommand>>::success(
        MpAttachCommand{MpAttachCommandKind::ping, MpAttachPingCommand{}});
  }
  if (trimmed == "/status" || trimmed.starts_with("/status ") ||
      trimmed.starts_with("/status\t")) {
    std::string_view rest = trimmed.substr(std::string_view{"/status"}.size());
    rest = trim_ascii_whitespace(rest);
    if (rest.empty()) {
      return fail<std::optional<MpAttachCommand>>(ErrorCode::invalid_range,
                                                  MpPartyBridgeError::invalid_field);
    }
    const std::size_t sep = rest.find_first_of(" \t");
    const std::string_view state_tok =
        (sep == std::string_view::npos) ? rest : rest.substr(0U, sep);
    const auto state = parse_p2p_party_activity_state(state_tok);
    if (!state.has_value()) {
      return Result<std::optional<MpAttachCommand>>::failure(state.error());
    }
    std::string_view status_text;
    if (sep != std::string_view::npos) {
      status_text = trim_ascii_whitespace(rest.substr(sep + 1U));
    }
    if (const auto st_ok =
            validate_text_cap(status_text, kP2pPartyMaxEphemeralStatusBytes, true);
        !st_ok.has_value()) {
      return Result<std::optional<MpAttachCommand>>::failure(st_ok.error());
    }
    MpAttachPulseCommand pulse_cmd{};
    pulse_cmd.state = state.value();
    pulse_cmd.status = std::string{status_text};
    return Result<std::optional<MpAttachCommand>>::success(
        MpAttachCommand{MpAttachCommandKind::pulse, std::move(pulse_cmd)});
  }

  const std::string_view body = strip_trailing_eol(line);
  if (const auto body_ok = validate_text_cap(body, kP2pPartyMaxChatBodyBytes, false);
      !body_ok.has_value()) {
    return Result<std::optional<MpAttachCommand>>::failure(body_ok.error());
  }
  MpAttachSayCommand say_cmd{};
  say_cmd.body = std::string{body};
  say_cmd.room_scope = std::string{effective_scope};
  say_cmd.target = std::string{kMpAttachDefaultTarget};
  return Result<std::optional<MpAttachCommand>>::success(
      MpAttachCommand{MpAttachCommandKind::say, std::move(say_cmd)});
}

// ---------------------------------------------------------------------------
// Typed Event Serialization & Display Formatting
// ---------------------------------------------------------------------------

Value mp_runtime_roster_to_json(const MpPartyRuntime &runtime,
                                const MpPeerMetadataMap *peer_metadata) {
  const auto peers = runtime.roster();
  const auto leader_dev = runtime.leader_device_id();
  Value::Array list;
  list.reserve(peers.size());

  for (const auto &peer : peers) {
    Value::Object item;
    item.emplace_back("device_id", Value{Number{peer.device_id.value()}});
    item.emplace_back("account_id", Value{Number{peer.account_id.value()}});
    std::string handle;
    std::string device_label;
    if (peer_metadata != nullptr) {
      if (const auto it = peer_metadata->find(peer.device_id.value());
          it != peer_metadata->end()) {
        handle = it->second.handle;
        device_label = it->second.device_label;
      }
    }
    item.emplace_back("handle", Value{std::move(handle)});
    item.emplace_back("device_label", Value{std::move(device_label)});
    item.emplace_back("pubkey_b64", Value{base64_encode(peer.device_pubkey)});
    const bool is_leader = leader_dev.has_value() && *leader_dev == peer.device_id;
    item.emplace_back("is_leader", Value{is_leader});
    const bool p2p_connected =
        peer.connection_state == P2pPeerConnectionState::connected;
    item.emplace_back("connected", Value{p2p_connected});
    item.emplace_back("control_plane_connected", Value{peer.control_plane_connected});
    item.emplace_back(
        "connection_state",
        Value{std::string{peer_connection_state_name(peer.connection_state)}});
    if (const auto sn = mp::compute_safety_number(peer.account_id, peer.root_pubkey);
        sn.has_value()) {
      item.emplace_back("safety_number", Value{sn.value()});
    }
    list.push_back(Value::object(std::move(item)));
  }

  return Value{std::move(list)};
}

Value mp_runtime_event_to_json(const MpRuntimeEvent &event,
                               const MpPartyRuntime &runtime,
                               const MpPeerMetadataMap *peer_metadata) {
  Value::Object obj;
  obj.emplace_back("type", Value{std::string{mp_runtime_event_json_type(event.kind)}});
  obj.emplace_back("party_id", Value{Number{runtime.party_id().value()}});
  const std::uint64_t effective_epoch =
      event.party_epoch != 0U ? event.party_epoch : runtime.party_epoch();
  obj.emplace_back("party_epoch", Value{Number{effective_epoch}});

  switch (event.kind) {
  case MpRuntimeEventKind::hello_acked:
    if (event.session_id.has_value()) {
      obj.emplace_back("session_id", Value{Number{event.session_id->value()}});
    }
    obj.emplace_back("ping_interval_ms", Value{Number{runtime.ping_interval_ms()}});
    obj.emplace_back("clock_skew_s", Value{Number{runtime.clock_skew_seconds()}});
    break;

  case MpRuntimeEventKind::snapshot_applied:
    if (event.snapshot_result.has_value()) {
      const auto &rep = *event.snapshot_result;
      obj.emplace_back("admitted_count", Value{Number{rep.admitted_peers.size()}});
      obj.emplace_back("revoked_count", Value{Number{rep.revoked_peers.size()}});
      obj.emplace_back("rejected_count", Value{Number{rep.rejected_members.size()}});
      obj.emplace_back("dial_failure_count", Value{Number{rep.dial_failures.size()}});
    }
    obj.emplace_back("peer_count", Value{Number{runtime.peer_count()}});
    if (const auto ld = runtime.leader_device_id(); ld.has_value()) {
      obj.emplace_back("leader_device_id", Value{Number{ld->value()}});
    }
    if (const auto la = runtime.leader_account_id(); la.has_value()) {
      obj.emplace_back("leader_account_id", Value{Number{la->value()}});
    }
    break;

  case MpRuntimeEventKind::member_joined:
    if (event.device_id.has_value()) {
      obj.emplace_back("device_id", Value{Number{event.device_id->value()}});
    }
    if (event.account_id.has_value()) {
      obj.emplace_back("account_id", Value{Number{event.account_id->value()}});
    }
    break;

  case MpRuntimeEventKind::member_updated:
    if (event.device_id.has_value()) {
      obj.emplace_back("device_id", Value{Number{event.device_id->value()}});
    }
    break;

  case MpRuntimeEventKind::member_left:
    if (event.device_id.has_value()) {
      obj.emplace_back("device_id", Value{Number{event.device_id->value()}});
    }
    if (event.account_id.has_value()) {
      obj.emplace_back("account_id", Value{Number{event.account_id->value()}});
    }
    if (event.leave_reason.has_value()) {
      obj.emplace_back(
          "reason", Value{std::string{member_leave_reason_name(*event.leave_reason)}});
    }
    break;

  case MpRuntimeEventKind::leader_changed:
    if (event.device_id.has_value()) {
      obj.emplace_back("leader_device_id", Value{Number{event.device_id->value()}});
    }
    if (event.account_id.has_value()) {
      obj.emplace_back("leader_account_id", Value{Number{event.account_id->value()}});
    }
    if (event.leader_change_reason.has_value()) {
      obj.emplace_back(
          "reason",
          Value{std::string{leader_change_reason_name(*event.leader_change_reason)}});
    }
    break;

  case MpRuntimeEventKind::party_disbanded:
    if (event.disband_reason.has_value()) {
      obj.emplace_back(
          "reason",
          Value{std::string{party_disband_reason_name(*event.disband_reason)}});
    }
    break;

  case MpRuntimeEventKind::kicked_or_revoked:
    obj.emplace_back("ws_close_code", Value{Number{event.ws_close_code}});
    obj.emplace_back("reason", Value{event.ws_close_code == kMpWsCloseDeviceRevoked
                                         ? "device_revoked"
                                         : "kicked_or_banned"});
    break;

  case MpRuntimeEventKind::control_disconnected:
    obj.emplace_back("ws_close_code", Value{Number{event.ws_close_code}});
    if (event.error.has_value()) {
      obj.emplace_back("error_code", Value{error_name(event.error->code)});
      obj.emplace_back("error_detail", Value{Number{event.error->detail}});
    }
    break;

  case MpRuntimeEventKind::control_reconnected:
    obj.emplace_back("state",
                     Value{std::string{mp_runtime_state_name(runtime.state())}});
    break;

  case MpRuntimeEventKind::control_error:
    if (event.device_id.has_value()) {
      obj.emplace_back("device_id", Value{Number{event.device_id->value()}});
    }
    if (event.account_id.has_value()) {
      obj.emplace_back("account_id", Value{Number{event.account_id->value()}});
    }
    if (event.server_error.has_value()) {
      obj.emplace_back("ref_seq", Value{Number{event.server_error->ref_seq}});
      obj.emplace_back("server_error_code", Value{Number{event.server_error->code}});
      obj.emplace_back("retry_after_ms",
                       Value{Number{event.server_error->retry_after_ms}});
    }
    if (event.error.has_value()) {
      obj.emplace_back("error_code", Value{error_name(event.error->code)});
      obj.emplace_back("error_detail", Value{Number{event.error->detail}});
    }
    break;

  case MpRuntimeEventKind::join_request_received:
    if (event.join_request.has_value()) {
      const auto &jr = *event.join_request;
      obj.emplace_back("request_id", Value{Number{jr.request_id.value()}});
      obj.emplace_back("account_id", Value{Number{jr.account_id.value()}});
      obj.emplace_back("device_id", Value{Number{jr.device_id.value()}});
      obj.emplace_back("root_pubkey_b64", Value{base64_encode(jr.root_pubkey)});
      obj.emplace_back("device_pubkey_b64", Value{base64_encode(jr.device_pubkey)});
      if (const auto sn = mp::compute_safety_number(jr.account_id, jr.root_pubkey);
          sn.has_value()) {
        obj.emplace_back("safety_number", Value{sn.value()});
      }
    }
    break;

  case MpRuntimeEventKind::peer_connected:
    if (event.sender_device_id.has_value()) {
      obj.emplace_back("device_id", Value{Number{event.sender_device_id->value()}});
    }
    if (event.sender_account_id.has_value()) {
      obj.emplace_back("account_id", Value{Number{event.sender_account_id->value()}});
    }
    obj.emplace_back("pubkey_b64", Value{base64_encode(event.peer_pubkey)});
    break;

  case MpRuntimeEventKind::peer_disconnected:
  case MpRuntimeEventKind::peer_evicted:
    if (event.sender_device_id.has_value()) {
      obj.emplace_back("device_id", Value{Number{event.sender_device_id->value()}});
    } else if (event.device_id.has_value()) {
      obj.emplace_back("device_id", Value{Number{event.device_id->value()}});
    }
    if (event.sender_account_id.has_value()) {
      obj.emplace_back("account_id", Value{Number{event.sender_account_id->value()}});
    } else if (event.account_id.has_value()) {
      obj.emplace_back("account_id", Value{Number{event.account_id->value()}});
    }
    obj.emplace_back("pubkey_b64", Value{base64_encode(event.peer_pubkey)});
    obj.emplace_back("reason_code", Value{Number{event.reason_code}});
    break;

  case MpRuntimeEventKind::chat_received:
    if (event.sender_device_id.has_value()) {
      obj.emplace_back("sender_device_id",
                       Value{Number{event.sender_device_id->value()}});
    }
    if (event.sender_account_id.has_value()) {
      obj.emplace_back("sender_account_id",
                       Value{Number{event.sender_account_id->value()}});
    }
    obj.emplace_back("sender_pubkey_b64", Value{base64_encode(event.peer_pubkey)});
    obj.emplace_back("sender_handle",
                     Value{resolve_chat_sender_handle(event, runtime, peer_metadata)});
    if (event.chat.has_value()) {
      obj.emplace_back("room_scope", Value{event.chat->room_scope});
      obj.emplace_back("target", Value{event.chat->target_selector});
      obj.emplace_back("body", Value{event.chat->body});
      obj.emplace_back(
          "sanitized_body",
          Value{party_chat_sanitize(event.chat->body, kP2pPartyMaxChatBodyBytes)});
      obj.emplace_back("timestamp_ns", Value{Number{event.chat->timestamp_ns}});
    }
    break;

  case MpRuntimeEventKind::bridge_envelope_received:
    if (event.sender_device_id.has_value()) {
      obj.emplace_back("sender_device_id",
                       Value{Number{event.sender_device_id->value()}});
    }
    if (event.sender_account_id.has_value()) {
      obj.emplace_back("sender_account_id",
                       Value{Number{event.sender_account_id->value()}});
    }
    obj.emplace_back("sender_pubkey_b64", Value{base64_encode(event.peer_pubkey)});
    if (event.bridge_envelope.has_value()) {
      obj.emplace_back("room_scope", Value{event.bridge_envelope->room_scope});
      obj.emplace_back("payload_b64",
                       Value{base64_encode(event.bridge_envelope->payload)});
      obj.emplace_back("payload_bytes",
                       Value{Number{event.bridge_envelope->payload.size()}});
    }
    break;

  case MpRuntimeEventKind::control_notice_received:
    if (event.sender_device_id.has_value()) {
      obj.emplace_back("sender_device_id",
                       Value{Number{event.sender_device_id->value()}});
    }
    if (event.sender_account_id.has_value()) {
      obj.emplace_back("sender_account_id",
                       Value{Number{event.sender_account_id->value()}});
    }
    obj.emplace_back("sender_pubkey_b64", Value{base64_encode(event.peer_pubkey)});
    if (event.control_notice.has_value()) {
      obj.emplace_back("notice_kind",
                       Value{std::string{p2p_party_control_notice_kind_name(
                           event.control_notice->kind)}});
      obj.emplace_back("notice_party_epoch",
                       Value{Number{event.control_notice->party_epoch}});
      obj.emplace_back("text", Value{event.control_notice->text});
      obj.emplace_back("sanitized_text",
                       Value{party_chat_sanitize(event.control_notice->text,
                                                 kP2pPartyMaxControlNoticeBytes)});
    }
    break;

  case MpRuntimeEventKind::ephemeral_pulse_received:
    if (event.sender_device_id.has_value()) {
      obj.emplace_back("sender_device_id",
                       Value{Number{event.sender_device_id->value()}});
    }
    if (event.sender_account_id.has_value()) {
      obj.emplace_back("sender_account_id",
                       Value{Number{event.sender_account_id->value()}});
    }
    obj.emplace_back("sender_pubkey_b64", Value{base64_encode(event.peer_pubkey)});
    if (event.ephemeral_pulse.has_value()) {
      obj.emplace_back("state", Value{std::string{p2p_party_activity_state_name(
                                    event.ephemeral_pulse->activity_state)}});
      obj.emplace_back("status", Value{event.ephemeral_pulse->status});
      obj.emplace_back("sanitized_status",
                       Value{party_chat_sanitize(event.ephemeral_pulse->status,
                                                 kP2pPartyMaxEphemeralStatusBytes)});
      obj.emplace_back("timestamp_ns",
                       Value{Number{event.ephemeral_pulse->timestamp_ns}});
    }
    break;

  case MpRuntimeEventKind::frame_dropped:
    obj.emplace_back("lane", Value{std::string{p2p_lane_name(event.lane)}});
    if (event.sender_device_id.has_value()) {
      obj.emplace_back("sender_device_id",
                       Value{Number{event.sender_device_id->value()}});
    }
    obj.emplace_back("pubkey_b64", Value{base64_encode(event.peer_pubkey)});
    if (event.error.has_value()) {
      obj.emplace_back("error_code", Value{error_name(event.error->code)});
      obj.emplace_back("error_detail", Value{Number{event.error->detail}});
    }
    break;
  }

  return Value::object(std::move(obj));
}

std::string format_mp_runtime_event_human(const MpRuntimeEvent &event,
                                          const MpPartyRuntime &runtime,
                                          const MpPeerMetadataMap *peer_metadata) {
  const auto dev_label = [](std::optional<mp::DeviceId> id) -> std::string {
    return id.has_value() ? ("#" + id->to_decimal()) : "#?";
  };
  const auto acct_label = [](std::optional<mp::AccountId> id) -> std::string {
    return id.has_value() ? ("#" + id->to_decimal()) : "#?";
  };

  switch (event.kind) {
  case MpRuntimeEventKind::hello_acked:
    return "[control] connected party=#" + runtime.party_id().to_decimal() +
           " session=" +
           (event.session_id.has_value() ? event.session_id->to_decimal() : "?") +
           " ping=" + std::to_string(runtime.ping_interval_ms()) + "ms";

  case MpRuntimeEventKind::snapshot_applied: {
    std::size_t admitted = 0U;
    std::size_t rejected = 0U;
    if (event.snapshot_result.has_value()) {
      admitted = event.snapshot_result->admitted_peers.size();
      rejected = event.snapshot_result->rejected_members.size();
    }
    return "[party] snapshot epoch=" +
           std::to_string(event.party_epoch != 0U ? event.party_epoch
                                                  : runtime.party_epoch()) +
           " peers=" + std::to_string(runtime.peer_count()) +
           " admitted=" + std::to_string(admitted) +
           " rejected=" + std::to_string(rejected);
  }

  case MpRuntimeEventKind::member_joined:
    return "[party] member joined account=" + acct_label(event.account_id) +
           " device=" + dev_label(event.device_id);

  case MpRuntimeEventKind::member_updated:
    return "[party] member updated device=" + dev_label(event.device_id);

  case MpRuntimeEventKind::member_left:
    return "[party] member left account=" + acct_label(event.account_id) +
           " device=" + dev_label(event.device_id) + " reason=" +
           std::string{event.leave_reason.has_value()
                           ? member_leave_reason_name(*event.leave_reason)
                           : "unknown"};

  case MpRuntimeEventKind::leader_changed:
    return "[party] leader changed account=" + acct_label(event.account_id) +
           " device=" + dev_label(event.device_id) + " reason=" +
           std::string{event.leader_change_reason.has_value()
                           ? leader_change_reason_name(*event.leader_change_reason)
                           : "unknown"};

  case MpRuntimeEventKind::party_disbanded:
    return "[party] disbanded reason=" +
           std::string{event.disband_reason.has_value()
                           ? party_disband_reason_name(*event.disband_reason)
                           : "unknown"};

  case MpRuntimeEventKind::kicked_or_revoked:
    return "[party] kicked or revoked close_code=" +
           std::to_string(event.ws_close_code);

  case MpRuntimeEventKind::control_disconnected:
    return "[control] disconnected close_code=" + std::to_string(event.ws_close_code);

  case MpRuntimeEventKind::control_reconnected:
    return "[control] reconnected epoch=" + std::to_string(runtime.party_epoch());

  case MpRuntimeEventKind::control_error: {
    std::string out = "[control] error";
    if (event.server_error.has_value()) {
      out += " server_code=" + std::to_string(event.server_error->code);
    }
    if (event.error.has_value()) {
      out += " code=" + std::string{error_name(event.error->code)} +
             " detail=" + std::to_string(event.error->detail);
    }
    return out;
  }

  case MpRuntimeEventKind::join_request_received:
    return "[party] join request id=" +
           (event.join_request.has_value() ? event.join_request->request_id.to_decimal()
                                           : "?") +
           " account=" + acct_label(event.account_id) +
           " device=" + dev_label(event.device_id);

  case MpRuntimeEventKind::peer_connected:
    return "[p2p] peer connected device=" + dev_label(event.sender_device_id) +
           " account=" + acct_label(event.sender_account_id);

  case MpRuntimeEventKind::peer_disconnected:
    return "[p2p] peer disconnected device=" +
           dev_label(event.sender_device_id.has_value() ? event.sender_device_id
                                                        : event.device_id) +
           " reason_code=" + std::to_string(event.reason_code);

  case MpRuntimeEventKind::peer_evicted:
    return "[p2p] peer evicted device=" +
           dev_label(event.sender_device_id.has_value() ? event.sender_device_id
                                                        : event.device_id) +
           " reason_code=" + std::to_string(event.reason_code);

  case MpRuntimeEventKind::chat_received: {
    const std::string raw_handle =
        resolve_chat_sender_handle(event, runtime, peer_metadata);
    const std::string safe_handle =
        party_chat_sanitize(raw_handle, kP2pPartyMaxSenderHandleBytes * 4U);
    if (!event.chat.has_value()) {
      return "[chat] " + safe_handle + "(" + dev_label(event.sender_device_id) + ")";
    }
    const std::string safe_scope =
        party_chat_sanitize(event.chat->room_scope, kP2pPartyMaxRoomScopeBytes * 4U);
    const std::string safe_target = party_chat_sanitize(
        event.chat->target_selector, kP2pPartyMaxTargetSelectorBytes * 4U);
    const std::string safe_body =
        party_chat_sanitize(event.chat->body, kP2pPartyMaxChatBodyBytes);
    return "[" + safe_scope + "] " + safe_handle + "(" +
           dev_label(event.sender_device_id) + ") -> " + safe_target + ": " + safe_body;
  }

  case MpRuntimeEventKind::bridge_envelope_received: {
    const std::string safe_scope =
        event.bridge_envelope.has_value()
            ? party_chat_sanitize(event.bridge_envelope->room_scope,
                                  kP2pPartyMaxRoomScopeBytes * 4U)
            : "unknown";
    const std::size_t payload_bytes =
        event.bridge_envelope.has_value() ? event.bridge_envelope->payload.size() : 0U;
    return "[bridge:" + safe_scope + "] device=" + dev_label(event.sender_device_id) +
           " bytes=" + std::to_string(payload_bytes);
  }

  case MpRuntimeEventKind::control_notice_received: {
    if (!event.control_notice.has_value()) {
      return "[notice] device=" + dev_label(event.sender_device_id);
    }
    const std::string safe_text = party_chat_sanitize(
        event.control_notice->text, kP2pPartyMaxControlNoticeBytes * 4U);
    return "[notice:" +
           std::string{p2p_party_control_notice_kind_name(event.control_notice->kind)} +
           "] device=" + dev_label(event.sender_device_id) +
           " epoch=" + std::to_string(event.control_notice->party_epoch) +
           (safe_text.empty() ? "" : (": " + safe_text));
  }

  case MpRuntimeEventKind::ephemeral_pulse_received: {
    if (!event.ephemeral_pulse.has_value()) {
      return "[pulse] device=" + dev_label(event.sender_device_id);
    }
    const std::string safe_status = party_chat_sanitize(
        event.ephemeral_pulse->status, kP2pPartyMaxEphemeralStatusBytes * 4U);
    return "[pulse] device=" + dev_label(event.sender_device_id) + " " +
           std::string{
               p2p_party_activity_state_name(event.ephemeral_pulse->activity_state)} +
           (safe_status.empty() ? "" : (": " + safe_status));
  }

  case MpRuntimeEventKind::frame_dropped:
    return "[p2p] frame dropped lane=" + std::string{p2p_lane_name(event.lane)};
  }

  return "[event] unknown";
}

// ---------------------------------------------------------------------------
// MpPartyAttachRunner & run_mp_party_attach_loop
// ---------------------------------------------------------------------------

std::function<void(std::string_view)>
make_mp_attach_ostream_emitter(std::ostream &out) {
  return [&out](std::string_view line) {
    out.write(line.data(), static_cast<std::streamsize>(line.size()));
    out.put('\n');
    out.flush();
  };
}

MpPartyAttachRunner::MpPartyAttachRunner(MpPartyRuntime &runtime, MpAttachConfig config)
    : runtime_(runtime), config_(std::move(config)) {}

Result<MpAttachSummary> MpPartyAttachRunner::run() {
  const std::string_view effective_scope =
      config_.default_room_scope.empty() ? kMpAttachDefaultRoomScope
                                         : std::string_view{config_.default_room_scope};
  if (const auto scope_ok =
          validate_text_cap(effective_scope, kP2pPartyMaxRoomScopeBytes, false);
      !scope_ok.has_value()) {
    return fail<MpAttachSummary>(ErrorCode::invalid_range,
                                 MpPartyBridgeError::invalid_config);
  }
  if (config_.local_sender_handle.has_value()) {
    if (const auto handle_ok = validate_text_cap(*config_.local_sender_handle,
                                                 kP2pPartyMaxSenderHandleBytes, false);
        !handle_ok.has_value()) {
      return fail<MpAttachSummary>(ErrorCode::invalid_range,
                                   MpPartyBridgeError::invalid_config);
    }
  }
  if (config_.local_party_room_id.has_value() &&
      !config_.local_party_room_id->empty() &&
      !valid_party_room_id(*config_.local_party_room_id)) {
    return fail<MpAttachSummary>(ErrorCode::invalid_range,
                                 MpPartyBridgeError::invalid_config);
  }

  const std::uint32_t tick_ms =
      config_.tick_ms == 0U
          ? kMpAttachDefaultTickMs
          : std::min<std::uint32_t>(config_.tick_ms, kMpAttachMaxTickMs);
  const std::string local_handle = resolve_local_sender_handle(runtime_, config_);
  const MpPeerMetadataMap *meta_ptr =
      config_.peer_metadata.empty() ? nullptr : &config_.peer_metadata;

  MpAttachSummary summary{};
  std::optional<PartyLobbyClient> lobby_client;
  const bool lobby_enabled =
      config_.local_party_socket.has_value() && !config_.local_party_socket->empty() &&
      config_.local_party_room_id.has_value() && !config_.local_party_room_id->empty();

  auto emit = [&](std::string_view line) {
    if (config_.emit_line) {
      config_.emit_line(line);
    }
    ++summary.events_emitted;
  };

  auto emit_json = [&](const Value &val) { emit(serialize_json_line(val)); };

  auto emit_cmd_error = [&](std::string_view cmd_name, const Error &err) {
    ++summary.command_errors;
    if (config_.mode == MpAttachMode::jsonl) {
      emit_json(make_command_error_json(runtime_, cmd_name, err));
    } else {
      emit("[error] " + std::string{cmd_name.empty() ? "command" : cmd_name} + ": " +
           error_name(err.code) + " (" + std::to_string(err.detail) + ")");
    }
  };

  auto forward_chat_to_lobby = [&](const MpRuntimeEvent &event) {
    if (!lobby_enabled || !event.chat.has_value()) {
      return;
    }
    // Derive lobby sender alias EXCLUSIVELY from authenticated/trusted metadata
    // for the verified TLS 1.3 Mutual RPK sender_device_id (never untrusted wire
    // chat->sender_handle, which could impersonate a local PartyLobbyServer lease).
    std::string trusted_handle;
    if (event.sender_device_id.has_value() && meta_ptr != nullptr) {
      if (const auto it = meta_ptr->find(event.sender_device_id->value());
          it != meta_ptr->end() && !it->second.handle.empty()) {
        trusted_handle = it->second.handle;
      }
    }
    const std::string alias =
        sanitize_lobby_alias(trusted_handle, event.sender_device_id);
    const std::string safe_target =
        event.chat->target_selector.empty()
            ? std::string{kMpAttachDefaultTarget}
            : party_chat_sanitize(event.chat->target_selector,
                                  kP2pPartyMaxTargetSelectorBytes);
    // Reserve 3 bytes for party_chat_sanitize()'s "..." truncation suffix so the
    // sanitized message always stays <= kPartyMaxMessageBytes.
    constexpr std::size_t kLobbySanitizeCap = kPartyMaxMessageBytes - 3U;
    const std::string safe_body =
        party_chat_sanitize(event.chat->body, kLobbySanitizeCap);
    if (trim_ascii_whitespace(safe_body).empty()) {
      ++summary.lobby_forwards_failed;
      return;
    }

    auto try_post = [&]() -> bool {
      if (!lobby_client.has_value() || !lobby_client->connected()) {
        PartyLobbyClientConfig lcfg{};
        lcfg.io_timeout_ms = 500;
        auto conn = PartyLobbyClient::connect(*config_.local_party_socket, lcfg);
        if (!conn.has_value()) {
          return false;
        }
        lobby_client.emplace(std::move(conn).value());
      }
      const auto posted =
          lobby_client->post_message(*config_.local_party_room_id, alias, safe_target,
                                     safe_body, PartyMessageKind::chat);
      if (posted.has_value()) {
        return true;
      }
      lobby_client->close();
      lobby_client.reset();
      return false;
    };

    const bool reused_conn = lobby_client.has_value() && lobby_client->connected();
    bool forwarded = try_post();
    if (!forwarded && reused_conn) {
      forwarded = try_post();
    }
    if (forwarded) {
      ++summary.lobby_forwards_succeeded;
    } else {
      ++summary.lobby_forwards_failed;
    }
  };

  // 1. Emit initial `ready` event before entering the pump loop.
  if (config_.mode == MpAttachMode::jsonl) {
    emit_json(make_ready_event_json(runtime_, config_.mode, local_handle));
  } else {
    emit("[ready] party #" + runtime_.party_id().to_decimal() +
         " state=" + std::string{mp_runtime_state_name(runtime_.state())} + " handle=" +
         party_chat_sanitize(local_handle, kP2pPartyMaxSenderHandleBytes * 4U));
  }

  bool quit_requested = false;
  bool stop_loop = false;
  std::string close_reason;

  auto execute_command = [&](const MpAttachCommand &cmd) {
    switch (cmd.kind) {
    case MpAttachCommandKind::say: {
      const auto &say = std::get<MpAttachSayCommand>(cmd.payload);
      P2pPartyChatMessage msg{};
      msg.room_scope = say.room_scope;
      msg.target_selector = say.target;
      msg.sender_handle = local_handle;
      msg.timestamp_ns = current_unix_ns();
      msg.body = say.body;
      if (say.device_id.has_value()) {
        const auto sent = runtime_.send_chat_to(*say.device_id, msg);
        if (!sent.has_value()) {
          emit_cmd_error("say", sent.error());
          return;
        }
        ++summary.commands_processed;
        if (config_.mode == MpAttachMode::jsonl) {
          emit_json(make_simple_ack_json(runtime_, "say", say.device_id));
        }
      } else {
        const auto sent = runtime_.broadcast_chat(msg);
        if (!sent.has_value()) {
          emit_cmd_error("say", sent.error());
          return;
        }
        ++summary.commands_processed;
        if (config_.mode == MpAttachMode::jsonl) {
          emit_json(make_broadcast_ack_json(runtime_, "say", sent.value()));
        }
      }
      return;
    }

    case MpAttachCommandKind::pulse: {
      const auto &pulse_cmd = std::get<MpAttachPulseCommand>(cmd.payload);
      P2pPartyEphemeralPulse pulse{};
      pulse.activity_state = pulse_cmd.state;
      pulse.timestamp_ns = current_unix_ns();
      pulse.status = pulse_cmd.status;
      const auto sent = runtime_.broadcast_ephemeral_pulse(pulse);
      if (!sent.has_value()) {
        emit_cmd_error("pulse", sent.error());
        return;
      }
      ++summary.commands_processed;
      if (config_.mode == MpAttachMode::jsonl) {
        emit_json(make_broadcast_ack_json(runtime_, "pulse", sent.value()));
      }
      return;
    }

    case MpAttachCommandKind::notice: {
      const auto &notice_cmd = std::get<MpAttachNoticeCommand>(cmd.payload);
      P2pPartyControlNotice notice{};
      notice.kind = notice_cmd.notice_kind;
      notice.party_epoch = runtime_.party_epoch();
      notice.text = notice_cmd.text;
      const auto sent = runtime_.broadcast_control_notice(notice);
      if (!sent.has_value()) {
        emit_cmd_error("notice", sent.error());
        return;
      }
      ++summary.commands_processed;
      if (config_.mode == MpAttachMode::jsonl) {
        emit_json(make_broadcast_ack_json(runtime_, "notice", sent.value()));
      }
      return;
    }

    case MpAttachCommandKind::roster:
      ++summary.commands_processed;
      if (config_.mode == MpAttachMode::jsonl) {
        emit_json(make_roster_event_json(runtime_, meta_ptr));
      } else {
        emit(format_roster_human(runtime_, meta_ptr));
      }
      return;

    case MpAttachCommandKind::ping: {
      const auto sent = runtime_.send_heartbeat_ping();
      if (!sent.has_value()) {
        emit_cmd_error("ping", sent.error());
        return;
      }
      ++summary.commands_processed;
      if (config_.mode == MpAttachMode::jsonl) {
        emit_json(make_simple_ack_json(runtime_, "ping"));
      } else {
        emit("[control] ping sent");
      }
      return;
    }

    case MpAttachCommandKind::quit:
      ++summary.commands_processed;
      quit_requested = true;
      close_reason = "quit";
      return;
    }
  };

  auto dispatch_line = [&](std::string_view line) {
    if (config_.mode == MpAttachMode::jsonl) {
      if (trim_ascii_whitespace(line).empty()) {
        return;
      }
      const auto parsed = parse_mp_attach_command(line);
      if (!parsed.has_value()) {
        emit_cmd_error("", parsed.error());
        return;
      }
      execute_command(parsed.value());
    } else {
      const auto parsed = parse_mp_attach_plain_line(line, effective_scope);
      if (!parsed.has_value()) {
        emit_cmd_error("", parsed.error());
        return;
      }
      if (parsed.value().has_value()) {
        execute_command(*parsed.value());
      }
    }
  };

  auto drain_runtime_events = [&]() {
    const auto events = runtime_.drain_events();
    for (const auto &ev : events) {
      if (config_.mode == MpAttachMode::jsonl) {
        emit_json(mp_runtime_event_to_json(ev, runtime_, meta_ptr));
      } else {
        emit(format_mp_runtime_event_human(ev, runtime_, meta_ptr));
      }
      if (ev.kind == MpRuntimeEventKind::chat_received) {
        forward_chat_to_lobby(ev);
      } else if (ev.kind == MpRuntimeEventKind::party_disbanded) {
        stop_loop = true;
        close_reason = "party_disbanded";
      } else if (ev.kind == MpRuntimeEventKind::kicked_or_revoked) {
        stop_loop = true;
        close_reason = "kicked_or_revoked";
      }
    }
  };

  bool input_active = (config_.input_fd >= 0);
  std::string line_buf;
  bool discarding_oversized_line = false;

  auto ingest_chunk = [&](std::string_view chunk) {
    std::size_t pos = 0U;
    while (pos < chunk.size() && !quit_requested) {
      const std::size_t nl = chunk.find('\n', pos);
      const bool has_nl = (nl != std::string_view::npos);
      const std::size_t seg_end = has_nl ? nl : chunk.size();
      const std::string_view seg = chunk.substr(pos, seg_end - pos);

      if (discarding_oversized_line) {
        if (has_nl) {
          discarding_oversized_line = false;
          line_buf.clear();
          emit_cmd_error(
              "", Error{ErrorCode::capacity,
                        static_cast<std::int64_t>(MpPartyBridgeError::line_too_large)});
        }
        pos = has_nl ? (nl + 1U) : chunk.size();
        continue;
      }

      if (line_buf.size() + seg.size() > kMpAttachMaxCommandBytes) {
        line_buf.clear();
        if (has_nl) {
          emit_cmd_error(
              "", Error{ErrorCode::capacity,
                        static_cast<std::int64_t>(MpPartyBridgeError::line_too_large)});
        } else {
          discarding_oversized_line = true;
        }
        pos = has_nl ? (nl + 1U) : chunk.size();
        continue;
      }

      line_buf.append(seg.data(), seg.size());
      if (has_nl) {
        if (!line_buf.empty() && line_buf.back() == '\r') {
          line_buf.pop_back();
        }
        dispatch_line(line_buf);
        line_buf.clear();
      }
      pos = has_nl ? (nl + 1U) : chunk.size();
    }
  };

  auto check_stop_flag = [&]() -> bool {
    if (config_.stop_flag != nullptr &&
        config_.stop_flag->load(std::memory_order_acquire)) {
      stop_loop = true;
      close_reason = "signal_stop";
      return true;
    }
    return false;
  };

  // 2. Main bounded poll + pump loop.
  while (!quit_requested && !stop_loop) {
    if (check_stop_flag()) {
      break;
    }

    // Drain any events already queued on the runtime before waiting.
    drain_runtime_events();
    if (stop_loop) {
      break;
    }
    if (runtime_.is_terminated()) {
      close_reason = (runtime_.state() == MpRuntimeState::disbanded)
                         ? "party_disbanded"
                         : "runtime_terminated";
      break;
    }

    // Poll input_fd with a short bounded slice so runtime.pump_once() is never
    // starved or blocked.
    if (input_active) {
      const int first_poll_ms = std::max<int>(
          1, static_cast<int>(std::min<std::uint32_t>(tick_ms / 2U, 25U)));
      constexpr std::size_t kMaxReadChunksPerTick = 16U;
      for (std::size_t chunk_idx = 0U;
           chunk_idx < kMaxReadChunksPerTick && input_active && !quit_requested;
           ++chunk_idx) {
        if (check_stop_flag()) {
          break;
        }
        pollfd pfd{};
        pfd.fd = config_.input_fd;
        pfd.events = POLLIN;
        const int slice_ms = (chunk_idx == 0U) ? first_poll_ms : 0;
        const int prc = ::poll(&pfd, 1U, slice_ms);
        if (prc < 0) {
          if (errno == EINTR) {
            break;
          }
          emit_cmd_error("", Error{ErrorCode::io, static_cast<std::int64_t>(
                                                      MpPartyBridgeError::io_error)});
          input_active = false;
          if (config_.exit_on_eof) {
            stop_loop = true;
            close_reason = "io_error";
          }
          break;
        }
        if (prc == 0) {
          break;
        }
        if ((pfd.revents & POLLNVAL) != 0) {
          emit_cmd_error("", Error{ErrorCode::io, static_cast<std::int64_t>(
                                                      MpPartyBridgeError::io_error)});
          input_active = false;
          if (config_.exit_on_eof) {
            stop_loop = true;
            close_reason = "io_error";
          }
          break;
        }
        if ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
          break;
        }

        std::array<char, 4096> rbuf{};
        const ssize_t n = ::read(config_.input_fd, rbuf.data(), rbuf.size());
        if (n > 0) {
          ingest_chunk(std::string_view{rbuf.data(), static_cast<std::size_t>(n)});
          continue;
        }
        if (n == 0) {
          input_active = false;
          if (discarding_oversized_line) {
            discarding_oversized_line = false;
            line_buf.clear();
            emit_cmd_error("", Error{ErrorCode::capacity,
                                     static_cast<std::int64_t>(
                                         MpPartyBridgeError::line_too_large)});
          } else if (!line_buf.empty()) {
            if (line_buf.back() == '\r') {
              line_buf.pop_back();
            }
            dispatch_line(line_buf);
            line_buf.clear();
          }
          if (!quit_requested && config_.exit_on_eof) {
            stop_loop = true;
            close_reason = "eof";
          }
          break;
        }
        if (errno == EINTR) {
          break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        emit_cmd_error("", Error{ErrorCode::io, static_cast<std::int64_t>(
                                                    MpPartyBridgeError::io_error)});
        input_active = false;
        if (config_.exit_on_eof) {
          stop_loop = true;
          close_reason = "io_error";
        }
        break;
      }
    }

    if (quit_requested || stop_loop || check_stop_flag()) {
      break;
    }

    const std::uint32_t pump_slice_ms =
        input_active ? std::max<std::uint32_t>(1U, tick_ms / 2U) : tick_ms;
    const auto pumped = runtime_.pump_once(pump_slice_ms, config_.now_s_override);
    if (!pumped.has_value()) {
      emit_cmd_error("pump", pumped.error());
    }

    drain_runtime_events();
    if (stop_loop) {
      break;
    }
    if (runtime_.is_terminated()) {
      close_reason = (runtime_.state() == MpRuntimeState::disbanded)
                         ? "party_disbanded"
                         : "runtime_terminated";
      break;
    }
  }

  // 3. Clean idempotent runtime shutdown + final `closed` event.
  if (lobby_client.has_value()) {
    lobby_client->close();
    lobby_client.reset();
  }
  runtime_.shutdown();

  if (close_reason.empty()) {
    close_reason = (runtime_.state() == MpRuntimeState::disbanded) ? "party_disbanded"
                                                                   : "terminated";
  }

  summary.final_state = runtime_.state();
  summary.close_reason = close_reason;

  if (config_.mode == MpAttachMode::jsonl) {
    emit_json(make_closed_event_json(runtime_, close_reason));
  } else {
    emit("[closed] party #" + runtime_.party_id().to_decimal() +
         " state=" + std::string{mp_runtime_state_name(summary.final_state)} +
         " reason=" + close_reason);
  }

  return Result<MpAttachSummary>::success(std::move(summary));
}

Result<MpAttachSummary> run_mp_party_attach_loop(MpPartyRuntime &runtime,
                                                 MpAttachConfig config) {
  MpPartyAttachRunner runner{runtime, std::move(config)};
  return runner.run();
}

} // namespace blackbird
