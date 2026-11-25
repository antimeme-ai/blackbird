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
constexpr std::size_t kMaxMentionAlerts = 64U;

template <typename T> Result<T> fail(ErrorCode code, MpRoomV2Error detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_void(ErrorCode code, MpRoomV2Error detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

char ascii_lower(char ch) noexcept {
  return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
}

bool ascii_is_alnum(char ch) noexcept {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
         (ch >= '0' && ch <= '9');
}

bool is_handle_word_char(char ch) noexcept {
  return ascii_is_alnum(ch) || ch == '_' || ch == '-';
}

bool is_mention_prefix_blocker(char ch) noexcept {
  return ascii_is_alnum(ch) || ch == '_' || ch == '-' || ch == '.';
}

bool ascii_iequals(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) {
    return false;
  }
  for (std::size_t i = 0U; i < a.size(); ++i) {
    if (ascii_lower(a[i]) != ascii_lower(b[i])) {
      return false;
    }
  }
  return true;
}

bool ascii_istarts_with(std::string_view text, std::string_view prefix) noexcept {
  if (text.size() < prefix.size()) {
    return false;
  }
  return ascii_iequals(text.substr(0U, prefix.size()), prefix);
}

std::string_view trim_ascii_ws(std::string_view text) noexcept {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t' ||
                           text.front() == '\r' || text.front() == '\n')) {
    text.remove_prefix(1U);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t' ||
                           text.back() == '\r' || text.back() == '\n')) {
    text.remove_suffix(1U);
  }
  return text;
}

// Consumes a CSI parameter/intermediate sequence through its final byte (0x40..0x7E).
void consume_csi_tail(std::string_view raw, std::size_t &i) noexcept {
  while (i < raw.size()) {
    const auto c = static_cast<unsigned char>(raw[i++]);
    if (c >= 0x40U && c <= 0x7eU) {
      break;
    }
  }
}

// Consumes an OSC/DCS/SOS/PM/APC string payload through BEL (0x07), ESC \,
// bare C1 ST (0x9C), or UTF-8 C1 ST (0xC2 0x9C).
void consume_st_tail(std::string_view raw, std::size_t &i) noexcept {
  while (i < raw.size()) {
    const auto c = static_cast<unsigned char>(raw[i++]);
    if (c == 0x07U || c == 0x9cU) {
      break;
    }
    if (c == 0x1bU && i < raw.size() && raw[i] == '\\') {
      ++i;
      break;
    }
    if (c == 0xc2U && i < raw.size() && static_cast<unsigned char>(raw[i]) == 0x9cU) {
      ++i;
      break;
    }
  }
}

// Strips ANSI CSI/OSC/DCS/SOS/PM/APC (both 7-bit ESC and 8-bit/UTF-8 C1),
// C0/DEL/C1/BiDi/zero-width/line-separator/Unicode-Tag controls, and invalid
// UTF-8 bytes so outbound agent_card JSON stays strictly printable UTF-8.
std::string scrub_agent_card_text(std::string_view raw, std::size_t max_bytes) {
  std::string out;
  out.reserve(std::min(raw.size(), max_bytes));
  std::size_t i = 0U;
  auto push_space_collapsed = [&]() {
    if (!out.empty() && out.back() != ' ' && out.size() < max_bytes) {
      out.push_back(' ');
    }
  };
  while (i < raw.size() && out.size() < max_bytes) {
    const auto b0 = static_cast<unsigned char>(raw[i]);
    if (b0 == 0x1bU) {
      ++i;
      if (i < raw.size()) {
        const char next = raw[i++];
        if (next == '[') {
          consume_csi_tail(raw, i);
        } else if (next == ']' || next == 'P' || next == 'X' || next == '^' ||
                   next == '_') {
          consume_st_tail(raw, i);
        }
      }
      continue;
    }
    if (b0 == '\r' || b0 == '\n' || b0 == '\t') {
      push_space_collapsed();
      ++i;
      continue;
    }
    if (b0 < 0x20U || b0 == 0x7fU) {
      ++i;
      continue;
    }
    if (b0 < 0x80U) {
      out.push_back(static_cast<char>(b0));
      ++i;
      continue;
    }
    // Bare single-byte C1 controls (0x80..0x9F), including CSI/OSC/DCS/SOS/PM/APC.
    if (b0 <= 0x9fU) {
      ++i;
      if (b0 == 0x9bU) {
        consume_csi_tail(raw, i);
      } else if (b0 == 0x9dU || b0 == 0x90U || b0 == 0x98U || b0 == 0x9eU ||
                 b0 == 0x9fU) {
        consume_st_tail(raw, i);
      }
      continue;
    }
    // Validate UTF-8 multibyte sequence and reject C1/BiDi/zero-width/Tag controls.
    if ((b0 & 0xe0U) == 0xc0U) {
      if (b0 < 0xc2U || i + 1U >= raw.size()) {
        ++i;
        continue;
      }
      const auto b1 = static_cast<unsigned char>(raw[i + 1U]);
      if ((b1 & 0xc0U) != 0x80U) {
        ++i;
        continue;
      }
      const char32_t cp =
          (static_cast<char32_t>(b0 & 0x1fU) << 6U) | static_cast<char32_t>(b1 & 0x3fU);
      if (cp <= 0x9fU) {
        i += 2U;
        if (cp == 0x9bU) {
          consume_csi_tail(raw, i);
        } else if (cp == 0x9dU || cp == 0x90U || cp == 0x98U || cp == 0x9eU ||
                   cp == 0x9fU) {
          consume_st_tail(raw, i);
        }
        continue;
      }
      if (cp == 0x061cU) {
        i += 2U;
        continue;
      }
      if (out.size() + 2U > max_bytes) {
        break;
      }
      out.append(raw.data() + i, 2U);
      i += 2U;
      continue;
    }
    if ((b0 & 0xf0U) == 0xe0U) {
      if (i + 2U >= raw.size()) {
        ++i;
        continue;
      }
      const auto b1 = static_cast<unsigned char>(raw[i + 1U]);
      const auto b2 = static_cast<unsigned char>(raw[i + 2U]);
      if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U ||
          (b0 == 0xe0U && b1 < 0xa0U) || (b0 == 0xedU && b1 >= 0xa0U)) {
        ++i;
        continue;
      }
      const char32_t cp = (static_cast<char32_t>(b0 & 0x0fU) << 12U) |
                          (static_cast<char32_t>(b1 & 0x3fU) << 6U) |
                          static_cast<char32_t>(b2 & 0x3fU);
      if (cp == 0x2028U || cp == 0x2029U) {
        push_space_collapsed();
        i += 3U;
        continue;
      }
      if ((cp >= 0x200bU && cp <= 0x200fU) || (cp >= 0x202aU && cp <= 0x202eU) ||
          (cp >= 0x2066U && cp <= 0x2069U) || cp == 0xfeffU) {
        i += 3U;
        continue;
      }
      if (out.size() + 3U > max_bytes) {
        break;
      }
      out.append(raw.data() + i, 3U);
      i += 3U;
      continue;
    }
    if ((b0 & 0xf8U) == 0xf0U) {
      if (b0 > 0xf4U || i + 3U >= raw.size()) {
        ++i;
        continue;
      }
      const auto b1 = static_cast<unsigned char>(raw[i + 1U]);
      const auto b2 = static_cast<unsigned char>(raw[i + 2U]);
      const auto b3 = static_cast<unsigned char>(raw[i + 3U]);
      if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U || (b3 & 0xc0U) != 0x80U ||
          (b0 == 0xf0U && b1 < 0x90U) || (b0 == 0xf4U && b1 >= 0x90U)) {
        ++i;
        continue;
      }
      const char32_t cp = (static_cast<char32_t>(b0 & 0x07U) << 18U) |
                          (static_cast<char32_t>(b1 & 0x3fU) << 12U) |
                          (static_cast<char32_t>(b2 & 0x3fU) << 6U) |
                          static_cast<char32_t>(b3 & 0x3fU);
      if (cp >= 0xe0000U && cp <= 0xe007fU) {
        i += 4U;
        continue;
      }
      if (out.size() + 4U > max_bytes) {
        break;
      }
      out.append(raw.data() + i, 4U);
      i += 4U;
      continue;
    }
    ++i;
  }
  while (!out.empty() && out.back() == ' ') {
    out.pop_back();
  }
  std::size_t lead = 0U;
  while (lead < out.size() && out[lead] == ' ') {
    ++lead;
  }
  if (lead > 0U) {
    out.erase(0U, lead);
  }
  return out;
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
  const auto parsed_card = parse_mp_room_v2_agent_card(body);
  if (!parsed_card.has_value()) {
    return party_chat_sanitize(body, 2048U);
  }
  const auto &c = *parsed_card;
  const std::string title = c.title.empty() ? std::string{"Agent update"}
                                            : party_chat_sanitize(c.title, 160U);
  std::string out = "[agent] " + title;
  if (!c.status.empty() && c.status != "done") {
    out += " [" + party_chat_sanitize(c.status, 24U) + "]";
  }
  if (!c.summary.empty()) {
    out += " — " + party_chat_sanitize(c.summary, 512U);
  }
  if (c.diff_stat.has_value() && !c.diff_stat->empty()) {
    out += " (" + party_chat_sanitize(*c.diff_stat, 48U) + ")";
  }
  if (!c.files.empty()) {
    out += " [";
    const std::size_t shown = std::min<std::size_t>(c.files.size(), 6U);
    for (std::size_t i = 0U; i < shown; ++i) {
      if (i > 0U) {
        out += ", ";
      }
      out += party_chat_sanitize(c.files[i], 96U);
    }
    if (c.files.size() > shown) {
      out += ", +" + std::to_string(c.files.size() - shown);
    }
    out += "]";
  }
  return out;
}

std::string format_member_display_name(const MpRoomV2Member &m) {
  const std::string handle = party_chat_sanitize(strip_at(m.handle), 64U);
  std::string out =
      m.is_guest ? ((handle.empty() ? std::string{"guest"} : handle) + " [guest]")
                 : ("@" + (handle.empty() ? std::string{"member"} : handle));
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

std::optional<mp::AccountId> json_optional_account_id(const Value &obj,
                                                      std::string_view key) {
  const auto raw = json_u64_or_decimal(obj, key);
  if (!raw.has_value() || *raw == 0U) {
    return std::nullopt;
  }
  const auto id = mp::AccountId::create(*raw);
  if (!id.has_value()) {
    return std::nullopt;
  }
  return id.value();
}

bool json_opt_bool(const Value &obj, std::string_view key) noexcept {
  const Value *f = obj.find(key);
  if (f == nullptr) {
    return false;
  }
  if (const auto *b = std::get_if<bool>(&f->value())) {
    return *b;
  }
  return false;
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
    const auto acct_id = json_optional_account_id(item, "account_id");
    const bool is_guest = !acct_id.has_value() || json_opt_bool(item, "is_guest");
    const std::string raw_handle = json_opt_string(item, "handle").value_or("");
    const std::string clean_handle = party_chat_sanitize(strip_at(raw_handle), 64U);
    if (clean_handle.empty()) {
      continue;
    }
    MpRoomV2Member m{};
    m.account_id = acct_id;
    m.is_guest = is_guest;
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
    m.is_self = !m.is_guest && self_account_id.has_value() &&
                m.account_id.has_value() && *m.account_id == *self_account_id;
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

brakes::EffectivePolicy load_effective_brakes_policy_or_default() {
  if (auto loaded = brakes::load_effective_policy(); loaded.has_value()) {
    return std::move(loaded).value();
  }
  return brakes::EffectivePolicy{};
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
  case MpRoomV2Error::secret_rejected:
    return "secret_rejected";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Agent Card validation, scrubbing, serialization & `@agent` mention detection
// ---------------------------------------------------------------------------

bool mp_room_v2_contains_secret_token(std::string_view text) noexcept {
  if (text.empty()) {
    return false;
  }
  static constexpr std::array<std::string_view, 14> kMarkers{
      "mprk1_",      "mpinv1_", "mppi1_", "mpcs1_",      "mpguest1_",
      "mpdl1_",      "sk-ant-", "sk-or-", "sk-proj-",    "ghp_",
      "github_pat_", "xoxb-",   "xoxp-",  "-----begin ",
  };
  for (std::size_t i = 0U; i < text.size(); ++i) {
    const std::string_view tail = text.substr(i);
    for (const std::string_view marker : kMarkers) {
      if (ascii_istarts_with(tail, marker)) {
        return true;
      }
    }
  }
  return false;
}

bool mp_room_v2_valid_agent_card_status(std::string_view status) noexcept {
  return status == "done" || status == "working" || status == "testing" ||
         status == "blocked" || status == "error";
}

Result<std::string>
serialize_mp_room_v2_agent_card(const MpRoomV2AgentCard &card,
                                std::string_view default_agent_name) {
  const std::string status_raw = card.status.empty()
                                     ? std::string{"done"}
                                     : std::string{trim_ascii_ws(card.status)};
  if (!mp_room_v2_valid_agent_card_status(status_raw)) {
    return fail<std::string>(ErrorCode::invalid_range, MpRoomV2Error::invalid_field);
  }

  auto check_secret = [](std::string_view raw, std::string_view scrubbed) noexcept {
    return mp_room_v2_contains_secret_token(raw) ||
           mp_room_v2_contains_secret_token(scrubbed);
  };

  const std::string title = scrub_agent_card_text(card.title, 256U);
  const std::string summary = scrub_agent_card_text(card.summary, 1024U);
  const std::string_view raw_agent =
      card.agent_name.empty() ? default_agent_name : std::string_view{card.agent_name};
  const std::string agent_name = scrub_agent_card_text(raw_agent, 64U);
  std::string diff_stat;
  if (card.diff_stat.has_value()) {
    diff_stat = scrub_agent_card_text(*card.diff_stat, 64U);
    if (check_secret(*card.diff_stat, diff_stat)) {
      return fail<std::string>(ErrorCode::invalid_range,
                               MpRoomV2Error::secret_rejected);
    }
  }

  if (check_secret(card.title, title) || check_secret(card.summary, summary) ||
      check_secret(raw_agent, agent_name)) {
    return fail<std::string>(ErrorCode::invalid_range, MpRoomV2Error::secret_rejected);
  }
  if (title.empty() && summary.empty()) {
    return fail<std::string>(ErrorCode::invalid_range, MpRoomV2Error::invalid_field);
  }

  std::vector<std::string> clean_files;
  clean_files.reserve(std::min(card.files.size(), kMpRoomV2MaxAgentCardFiles));
  for (const auto &raw_path : card.files) {
    const std::string scrubbed = scrub_agent_card_text(raw_path, 160U);
    if (check_secret(raw_path, scrubbed)) {
      return fail<std::string>(ErrorCode::invalid_range,
                               MpRoomV2Error::secret_rejected);
    }
    if (scrubbed.empty()) {
      continue;
    }
    if (std::find(clean_files.begin(), clean_files.end(), scrubbed) !=
        clean_files.end()) {
      continue;
    }
    if (clean_files.size() >= kMpRoomV2MaxAgentCardFiles) {
      break;
    }
    clean_files.push_back(scrubbed);
  }

  Value::Object card_obj;
  card_obj.emplace_back("title", Value{title});
  card_obj.emplace_back("summary", Value{summary});
  card_obj.emplace_back("status", Value{status_raw});
  if (!agent_name.empty()) {
    card_obj.emplace_back("agent_name", Value{agent_name});
  }
  if (!diff_stat.empty()) {
    card_obj.emplace_back("diff_stat", Value{diff_stat});
  }
  if (!clean_files.empty()) {
    Value::Array files_arr;
    files_arr.reserve(clean_files.size());
    for (auto &f : clean_files) {
      files_arr.emplace_back(std::move(f));
    }
    card_obj.emplace_back("files", Value{std::move(files_arr)});
  }

  auto json_res = dump_json(Value::object(std::move(card_obj)));
  if (!json_res.has_value()) {
    return fail<std::string>(ErrorCode::corrupt, MpRoomV2Error::invalid_field);
  }
  std::string body = std::move(json_res).value();
  if (body.size() > kMpRoomV2MaxAgentCardBytes) {
    return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::field_too_large);
  }
  return Result<std::string>::success(std::move(body));
}

std::optional<MpRoomV2AgentCard> parse_mp_room_v2_agent_card(std::string_view body) {
  ValueLimits limits{};
  limits.bytes = mp::kMaxMp2BodyBytes;
  limits.nodes = 2048U;
  limits.depth = 16U;
  const auto parsed = parse_json(body, limits);
  if (!parsed.has_value() ||
      !std::holds_alternative<Value::Object>(parsed.value().value())) {
    return std::nullopt;
  }
  const Value &obj = parsed.value();
  MpRoomV2AgentCard card{};
  card.title = party_chat_sanitize(json_opt_string(obj, "title").value_or(""), 160U);
  card.summary =
      party_chat_sanitize(json_opt_string(obj, "summary").value_or(""), 512U);
  if (card.title.empty() && card.summary.empty()) {
    return std::nullopt;
  }
  const std::string raw_status = json_opt_string(obj, "status").value_or("done");
  card.status = mp_room_v2_valid_agent_card_status(raw_status) ? raw_status : "done";
  card.agent_name =
      party_chat_sanitize(json_opt_string(obj, "agent_name").value_or(""), 48U);
  if (const auto ds = json_opt_string(obj, "diff_stat"); ds.has_value()) {
    const std::string clean_ds = party_chat_sanitize(*ds, 64U);
    if (!clean_ds.empty()) {
      card.diff_stat = clean_ds;
    }
  }
  if (const Value *files_field = obj.find("files"); files_field != nullptr) {
    if (const auto *arr = std::get_if<Value::Array>(&files_field->value());
        arr != nullptr) {
      const std::size_t cap =
          std::min<std::size_t>(arr->size(), kMpRoomV2MaxAgentCardFiles);
      card.files.reserve(cap);
      for (std::size_t i = 0U; i < cap; ++i) {
        if (const auto *s = std::get_if<std::string>(&(*arr)[i].value())) {
          const std::string clean_path = party_chat_sanitize(*s, 160U);
          if (!clean_path.empty()) {
            card.files.push_back(clean_path);
          }
        }
      }
    }
  }
  return card;
}

bool detect_self_agent_mention(std::string_view body,
                               std::string_view self_handle) noexcept {
  while (!self_handle.empty() && self_handle.front() == '@') {
    self_handle.remove_prefix(1U);
  }
  if (self_handle.empty() || body.size() < self_handle.size() + 1U) {
    return false;
  }

  for (std::size_t pos = 0U; pos < body.size(); ++pos) {
    if (body[pos] != '@') {
      continue;
    }
    if (pos > 0U && is_mention_prefix_blocker(body[pos - 1U])) {
      continue;
    }
    const std::size_t hstart = pos + 1U;
    if (hstart + self_handle.size() > body.size()) {
      break;
    }
    if (!ascii_iequals(body.substr(hstart, self_handle.size()), self_handle)) {
      continue;
    }

    const std::size_t after = hstart + self_handle.size();
    if (after == body.size()) {
      return true;
    }

    const std::string_view rest = body.substr(after);
    // Explicit `@handle:agent` form.
    if (ascii_istarts_with(rest, ":agent")) {
      const std::size_t end = after + 6U;
      if (end == body.size() || !is_handle_word_char(body[end])) {
        return true;
      }
      continue;
    }

    // Explicit `@handle's agent` (ASCII apostrophe or UTF-8 U+2019 right single quote).
    std::size_t apos_len = 0U;
    if (rest.front() == '\'') {
      apos_len = 1U;
    } else if (rest.size() >= 3U && static_cast<unsigned char>(rest[0]) == 0xe2U &&
               static_cast<unsigned char>(rest[1]) == 0x80U &&
               static_cast<unsigned char>(rest[2]) == 0x99U) {
      apos_len = 3U;
    }
    if (apos_len > 0U && rest.size() > apos_len && ascii_lower(rest[apos_len]) == 's') {
      std::size_t sp = apos_len + 1U;
      std::size_t spaces = 0U;
      while (sp < rest.size() && (rest[sp] == ' ' || rest[sp] == '\t')) {
        ++sp;
        ++spaces;
      }
      if (spaces > 0U && ascii_istarts_with(rest.substr(sp), "agent")) {
        const std::size_t end = after + sp + 5U;
        if (end == body.size() || !is_handle_word_char(body[end])) {
          return true;
        }
      }
      continue;
    }

    // Reject email/domain like `@handle.com` (dot immediately followed by alnum).
    if (rest.front() == '.' && rest.size() > 1U && ascii_is_alnum(rest[1])) {
      continue;
    }

    // Reject unknown colon-tag like `@handle:other`, while allowing `@handle: hi`.
    if (rest.front() == ':' && rest.size() > 1U && is_handle_word_char(rest[1])) {
      continue;
    }

    // Reject prefix collisions like `@handle2`, `@handle_bot`, `@handle-x`.
    if (is_handle_word_char(rest.front())) {
      continue;
    }

    return true;
  }
  return false;
}

std::string build_mp_room_v2_respond_prompt(const MpRoomV2PendingMention &mention,
                                            std::string_view extra_guidance) {
  const std::string sender =
      mention.sender_handle.empty()
          ? std::string{"@peer"}
          : ("@" + party_chat_sanitize(strip_at(mention.sender_handle), 64U));
  const std::string scope = mention.room_scope.empty()
                                ? std::string{"party/live"}
                                : party_chat_sanitize(mention.room_scope, 64U);
  std::string out = "The local operator explicitly asked you to review and respond to "
                    "a peer mention from " +
                    sender + " in " + scope + ".\n" + mention.fenced_envelope;
  const std::string_view trimmed_guidance = trim_ascii_ws(extra_guidance);
  if (!trimmed_guidance.empty()) {
    out += "\n\nOperator guidance: ";
    out.append(trimmed_guidance);
  }
  return out;
}

brakes::BrakesDecision
evaluate_mp_room_v2_respond_effect(const brakes::BrakesGate &gate,
                                   std::string_view op_name, const Value &op_input,
                                   const std::filesystem::path &workspace_root) {
  // The operator explicitly triggered `/respond`: allow the turn's own primary
  // LLM provider invocation so the model can actually read & answer the mention,
  // while routing every tool call strictly through BrakesGate.
  if (op_name == "provider") {
    return brakes::BrakesDecision::make_allow("respond turn model invocation");
  }
  brakes::ToolCallRequest req{};
  req.tool_name = std::string{op_name};
  if (const auto *p = op_input.find("path");
      p != nullptr && std::holds_alternative<std::string>(p->value())) {
    req.target_path = std::filesystem::path{p->string()};
  }
  req.workspace_root = workspace_root;
  return gate.evaluate_tool_call(req);
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
      brakes_gate_(load_effective_brakes_policy_or_default()),
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
    m.is_guest = im.is_guest || !im.account_id.has_value();
    m.handle = clean_h;
    m.client = party_chat_sanitize(im.client, 32U);
    m.agent_name = party_chat_sanitize(im.agent_name, 48U);
    m.agent_state = party_chat_sanitize(im.agent_state, 32U);
    m.agent_summary = party_chat_sanitize(im.agent_summary, 128U);
    m.status =
        im.status.empty() ? std::string{"live"} : party_chat_sanitize(im.status, 24U);
    m.is_self = !m.is_guest && local_account_id_.has_value() &&
                m.account_id.has_value() && *m.account_id == *local_account_id_;
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
  if (target.value.empty()) {
    target.value = "@all";
  }
  if (target.value.size() > kMaxRoomTargetBytes) {
    return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::field_too_large);
  }

  auto json_res = serialize_mp_room_v2_agent_card(card, agent_name_);
  if (!json_res.has_value()) {
    return Result<std::string>::failure(json_res.error());
  }
  std::string body = std::move(json_res).value();
  auto parsed_card = parse_mp_room_v2_agent_card(body);

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
    optimistic.parsed_agent_card = std::move(parsed_card);
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

std::string MpRoomV2Session::local_handle() const {
  std::lock_guard<std::mutex> lock(state_mu_);
  return local_handle_;
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

std::optional<MpRoomV2PendingMention> MpRoomV2Session::pending_agent_mention() const {
  std::lock_guard<std::mutex> lock(state_mu_);
  return pending_agent_mention_;
}

std::optional<MpRoomV2PendingMention> MpRoomV2Session::consume_pending_agent_mention() {
  std::optional<MpRoomV2PendingMention> out;
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    out = std::move(pending_agent_mention_);
    pending_agent_mention_.reset();
  }
  if (out.has_value()) {
    signal_wake();
  }
  return out;
}

brakes::TurnTaintState MpRoomV2Session::turn_taint_snapshot() const {
  std::lock_guard<std::mutex> lock(state_mu_);
  return brakes_gate_.taint();
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
  snap.mention_alerts.assign(mention_alerts_.begin(), mention_alerts_.end());
  mention_alerts_.clear();
  snap.pending_agent_mention = pending_agent_mention_;
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
    if (m.parsed_agent_card.has_value()) {
      PartyAgentCard pc{};
      pc.title = m.parsed_agent_card->title;
      pc.summary = m.parsed_agent_card->summary;
      pc.files = m.parsed_agent_card->files;
      pc.status = m.parsed_agent_card->status;
      pc.agent_name = !m.parsed_agent_card->agent_name.empty()
                          ? m.parsed_agent_card->agent_name
                          : m.sender_agent_name;
      pc.diff_stat = m.parsed_agent_card->diff_stat;
      pm.agent_card = std::move(pc);
    }
    snap.messages.push_back(std::move(pm));
  }
  if (pending_agent_mention_.has_value()) {
    snap.pending_mention = PartyPendingMention{
        pending_agent_mention_->sender_handle,
        pending_agent_mention_->sanitized_preview,
    };
  }
  return snap;
}

// ---------------------------------------------------------------------------
// Internal state helpers
// ---------------------------------------------------------------------------

void MpRoomV2Session::remember_seen_seq_locked(std::uint64_t seq) {
  if (seq == 0U) {
    return;
  }
  const auto [it, inserted] = seen_seqs_.insert(seq);
  (void)it;
  if (!inserted) {
    return;
  }
  seen_seq_order_.push_back(seq);
  const std::size_t cap = std::max<std::size_t>(max_retained_messages_ * 4U, 2048U);
  while (seen_seq_order_.size() > cap) {
    seen_seqs_.erase(seen_seq_order_.front());
    seen_seq_order_.pop_front();
  }
}

void MpRoomV2Session::remember_seen_client_msg_id_locked(
    const std::string &client_msg_id) {
  if (client_msg_id.empty()) {
    return;
  }
  const auto [it, inserted] = seen_client_msg_ids_.insert(client_msg_id);
  (void)it;
  if (!inserted) {
    return;
  }
  seen_client_msg_id_order_.push_back(client_msg_id);
  const std::size_t cap = std::max<std::size_t>(max_retained_messages_ * 4U, 2048U);
  while (seen_client_msg_id_order_.size() > cap) {
    seen_client_msg_ids_.erase(seen_client_msg_id_order_.front());
    seen_client_msg_id_order_.pop_front();
  }
}

void MpRoomV2Session::apply_members_locked(const std::vector<MpRoomV2Member> &members) {
  members_ = members;
  bool has_self = false;
  for (auto &m : members_) {
    if (!m.is_guest && local_account_id_.has_value() && m.account_id.has_value() &&
        *m.account_id == *local_account_id_) {
      m.is_self = true;
      has_self = true;
    } else {
      m.is_self = false;
    }
  }
  if (!has_self && local_account_id_.has_value()) {
    MpRoomV2Member self{};
    self.account_id = *local_account_id_;
    self.is_guest = false;
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
          remember_seen_seq_locked(msg.seq);
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
    remember_seen_client_msg_id_locked(msg.client_msg_id);
  }

  if (msg.seq > 0U) {
    remember_seen_seq_locked(msg.seq);
    if (msg.seq > latest_seq_) {
      latest_seq_ = msg.seq;
      latest_seq_atomic_.store(latest_seq_, std::memory_order_release);
    }
    // Preserve ascending `seq` ordering when resume backfills gaps before newer
    // `hello.history` entries, keeping pending `seq == 0` optimistic items at the tail.
    auto insert_pos = messages_.end();
    while (insert_pos != messages_.begin()) {
      const auto prev = std::prev(insert_pos);
      if (prev->seq == 0U || prev->seq > msg.seq) {
        insert_pos = prev;
      } else {
        break;
      }
    }
    messages_.insert(insert_pos, std::move(msg));
  } else {
    messages_.push_back(std::move(msg));
  }
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
  const std::uint64_t prev_latest_seq = latest_seq_;
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
          handle_event_locked(ev, true);
        }
      }
    }
  }

  const std::uint64_t server_latest =
      json_u64_or_decimal(obj, "latest_seq").value_or(0U);
  if (connected_once_ && prev_latest_seq > 0U) {
    action.need_send_resume = true;
    action.resume_seq = prev_latest_seq;
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

void MpRoomV2Session::handle_event_locked(const Value &obj, bool is_history) {
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

  const bool already_seen =
      (seq > 0U && seen_seqs_.contains(seq)) ||
      (!cmsg_id.empty() && seen_client_msg_ids_.contains(cmsg_id));

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
        acct_raw.has_value() && *acct_raw != 0U) {
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
  const bool matched_outbox =
      !cmsg_id.empty() &&
      std::any_of(outbox_.begin(), outbox_.end(), [&](const OutboundMessage &pending) {
        return pending.client_msg_id == cmsg_id;
      });
  msg.local_self = matched_outbox || (local_account_id_.has_value() &&
                                      msg.sender_account_id.has_value() &&
                                      *msg.sender_account_id == *local_account_id_);

  if (msg.kind == "agent_card" && msg.body_encoding == "utf8") {
    msg.parsed_agent_card = parse_mp_room_v2_agent_card(msg.body);
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

  // Detect incoming remote `@<self_handle>` / `@<self_handle>:agent` /
  // `@<self_handle>'s agent` mentions in both chat messages and `agent_card`
  // events, and isolate through Brakes Stage 1. Never triggers on self-sent
  // echoes, encrypted opaque frames, or duplicates.
  bool mentions_self = false;
  std::string_view mention_payload;
  if (!is_history && !already_seen && !msg.local_self && msg.body_encoding == "utf8") {
    if (msg.kind == "chat") {
      mentions_self = detect_self_agent_mention(msg.body, local_handle_) ||
                      detect_self_agent_mention(msg.target, local_handle_);
      mention_payload = msg.body;
    } else if (msg.kind == "agent_card") {
      mentions_self =
          detect_self_agent_mention(msg.target, local_handle_) ||
          (msg.parsed_agent_card.has_value() &&
           (detect_self_agent_mention(msg.parsed_agent_card->title, local_handle_) ||
            detect_self_agent_mention(msg.parsed_agent_card->summary, local_handle_)));
      mention_payload = msg.rendered_body;
    }
  }
  if (mentions_self) {
    const bool sender_is_guest = !msg.sender_account_id.has_value();
    const std::string room_scope =
        !room_code_.empty() ? ("room/" + room_code_) : std::string{"party/live"};
    const std::string sender_handle =
        msg.sender_handle.empty() ? std::string{"peer"} : msg.sender_handle;

    brakes::PeerProvenance prov{};
    prov.origin = brakes::PeerOriginKind::online_peer;
    prov.account_id =
        msg.sender_account_id.has_value() ? msg.sender_account_id->value() : 0U;
    prov.is_external_guest = sender_is_guest;
    prov.safety_number = msg.sender_account_id.has_value()
                             ? ("mp2-acct-" + msg.sender_account_id->to_decimal())
                             : std::string{"mp2-guest"};
    prov.effective_trust =
        std::min(brakes::PartyTrustProfile::advisory,
                 brakes_gate_.policy().party_trust.max_default_profile);

    const brakes::PartyTrustProfile clamped_trust = brakes_gate_.ingest_peer(prov);
    prov.effective_trust = clamped_trust;

    const auto wrapped = brakes::format_untrusted_peer_envelope(
        prov, brakes::RoomScopeRef{room_scope}, brakes::SenderRef{"@" + sender_handle},
        brakes::MessageBodyRef{mention_payload});
    if (wrapped.has_value()) {
      MpRoomV2PendingMention pending{};
      pending.seq = msg.seq;
      pending.ts_ms = msg.ts_ms;
      pending.sender_account_id = msg.sender_account_id;
      pending.sender_is_guest = sender_is_guest;
      pending.sender_handle = sender_handle;
      pending.sender_client = msg.sender_client;
      pending.sender_agent_name = msg.sender_agent_name;
      pending.room_scope = room_scope;
      pending.raw_body = std::string{mention_payload};
      pending.sanitized_preview = party_chat_sanitize(mention_payload, 140U);
      pending.fenced_envelope = wrapped.value();
      pending.provenance = std::move(prov);
      pending.effective_trust = clamped_trust;

      pending_agent_mention_ = pending;
      mention_alerts_.push_back(std::move(pending));
      while (mention_alerts_.size() > kMaxMentionAlerts) {
        mention_alerts_.pop_front();
      }
    }
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
          remember_seen_seq_locked(seq);
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
  if (retry_ms > 0U || code == "rate_limited") {
    action.retry_backoff_ms = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(retry_ms > 0U ? retry_ms : 1000U, 30000U));
    for (auto &pending : outbox_) {
      pending.sent_on_current_socket = false;
    }
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
