#include "blackbird/mp_room_v2.hpp"

#include "blackbird/json.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <optional>
#include <span>
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

PartyParticipantState map_member_state(const MpRoomV2Member &m) noexcept {
  if (m.status == "offline" || m.status == "away") {
    return PartyParticipantState::offline;
  }
  if (m.agent_state == "working" || m.agent_state == "busy" ||
      m.agent_state == "running") {
    return PartyParticipantState::working;
  }
  return PartyParticipantState::online;
}

PartyMessageKind map_message_kind(std::string_view kind) noexcept {
  if (kind == "agent_card") {
    return PartyMessageKind::leader_update;
  }
  if (kind == "irc_action") {
    return PartyMessageKind::irc_action;
  }
  if (kind == "irc_notice") {
    return PartyMessageKind::irc_notice;
  }
  if (kind == "system") {
    return PartyMessageKind::system;
  }
  return PartyMessageKind::chat;
}

std::optional<mp::DeviceId> json_optional_device_id(const Value &obj,
                                                    std::string_view key) {
  const auto raw = json_u64_or_decimal(obj, key);
  if (!raw.has_value() || *raw == 0U) {
    return std::nullopt;
  }
  const auto id = mp::DeviceId::create(*raw);
  if (!id.has_value()) {
    return std::nullopt;
  }
  return id.value();
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
parse_members_array(const Value &obj, std::optional<mp::AccountId> self_account_id,
                    std::optional<mp::DeviceId> self_device_id) {
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
    const auto dev_id = json_optional_device_id(item, "device_id");
    const bool is_guest = !acct_id.has_value() || json_opt_bool(item, "is_guest");
    const std::string raw_handle = json_opt_string(item, "handle").value_or("");
    const std::string clean_handle = party_chat_sanitize(strip_at(raw_handle), 64U);
    if (clean_handle.empty()) {
      continue;
    }
    MpRoomV2Member m{};
    m.account_id = acct_id;
    m.device_id = dev_id;
    m.is_guest = is_guest;
    m.handle = clean_handle;
    if (const auto raw_nick = json_opt_string(item, "nick");
        raw_nick.has_value() && !raw_nick->empty()) {
      if (const auto valid_nick = validate_irc_nick(*raw_nick);
          valid_nick.has_value()) {
        m.nick = valid_nick.value();
      }
    }
    m.client = party_chat_sanitize(json_opt_string(item, "client").value_or(""), 32U);
    m.is_browser =
        json_opt_bool(item, "is_browser") || mp_room_v2_is_browser_client(m.client);
    m.agent_name =
        party_chat_sanitize(json_opt_string(item, "agent_name").value_or(""), 48U);
    m.agent_state =
        party_chat_sanitize(json_opt_string(item, "agent_state").value_or(""), 32U);
    m.agent_summary =
        party_chat_sanitize(json_opt_string(item, "agent_summary").value_or(""), 128U);
    m.status =
        party_chat_sanitize(json_opt_string(item, "status").value_or("live"), 24U);
    const bool same_account = !m.is_guest && !m.is_browser &&
                              self_account_id.has_value() && m.account_id.has_value() &&
                              *m.account_id == *self_account_id;
    const bool is_sibling_dev = same_account && m.device_id.has_value() &&
                                self_device_id.has_value() &&
                                *m.device_id != *self_device_id;
    m.is_self = same_account && !is_sibling_dev;
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

brakes::PeerProvenance make_mp2_peer_provenance(std::optional<mp::AccountId> acct_id,
                                                bool is_guest, bool is_browser,
                                                const brakes::EffectivePolicy &policy) {
  brakes::PeerProvenance prov{};
  prov.origin = brakes::PeerOriginKind::online_peer;
  prov.account_id = acct_id.has_value() ? acct_id->value() : 0U;
  prov.is_external_guest = is_guest || is_browser;
  if (is_browser) {
    prov.safety_number = acct_id.has_value()
                             ? ("mp2-browser-acct-" + acct_id->to_decimal())
                             : std::string{"mp2-browser"};
  } else if (acct_id.has_value()) {
    prov.safety_number = "mp2-acct-" + acct_id->to_decimal();
  } else {
    prov.safety_number = "mp2-guest";
  }
  prov.effective_trust = std::min(brakes::PartyTrustProfile::advisory,
                                  policy.party_trust.max_default_profile);
  return prov;
}

std::string room_b64_encode(std::span<const std::uint8_t> bytes) {
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

std::optional<std::vector<std::uint8_t>> room_b64_decode(std::string_view text) {
  if (text.empty() || (text.size() % 4U) != 0U) {
    return std::nullopt;
  }
  auto val = [](char ch) noexcept -> int {
    if (ch >= 'A' && ch <= 'Z')
      return ch - 'A';
    if (ch >= 'a' && ch <= 'z')
      return 26 + (ch - 'a');
    if (ch >= '0' && ch <= '9')
      return 52 + (ch - '0');
    if (ch == '+')
      return 62;
    if (ch == '/')
      return 63;
    return -1;
  };
  std::vector<std::uint8_t> out;
  out.reserve((text.size() / 4U) * 3U);
  for (std::size_t i = 0U; i < text.size(); i += 4U) {
    const bool pad2 = (text[i + 2U] == '=');
    const bool pad3 = (text[i + 3U] == '=');
    if ((pad2 || pad3) && (i + 4U != text.size())) {
      return std::nullopt;
    }
    if (pad2 && !pad3) {
      return std::nullopt;
    }
    const int v0 = val(text[i]);
    const int v1 = val(text[i + 1U]);
    const int v2 = pad2 ? 0 : val(text[i + 2U]);
    const int v3 = pad3 ? 0 : val(text[i + 3U]);
    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
      return std::nullopt;
    }
    const std::uint32_t t = (static_cast<std::uint32_t>(v0) << 18U) |
                            (static_cast<std::uint32_t>(v1) << 12U) |
                            (static_cast<std::uint32_t>(v2) << 6U) |
                            static_cast<std::uint32_t>(v3);
    out.push_back(static_cast<std::uint8_t>((t >> 16U) & 0xffU));
    if (!pad2) {
      out.push_back(static_cast<std::uint8_t>((t >> 8U) & 0xffU));
    }
    if (!pad3) {
      out.push_back(static_cast<std::uint8_t>(t & 0xffU));
    }
  }
  return out;
}

// Canonical binary inner routed payload (zero JSON internals):
// "\x01MP2I"(5) || target_len(u16 BE) || target || body
std::vector<std::uint8_t> encode_inner_routed_payload(std::string_view target,
                                                      std::string_view body) {
  static constexpr std::array<std::uint8_t, 5> kMagic = {0x01U, 'M', 'P', '2', 'I'};
  const std::uint16_t tlen = static_cast<std::uint16_t>(
      std::min<std::size_t>(target.size(), kMaxRoomTargetBytes));
  std::vector<std::uint8_t> out;
  out.reserve(kMagic.size() + 2U + tlen + body.size());
  out.insert(out.end(), kMagic.begin(), kMagic.end());
  out.push_back(static_cast<std::uint8_t>((tlen >> 8U) & 0xffU));
  out.push_back(static_cast<std::uint8_t>(tlen & 0xffU));
  out.insert(out.end(), target.begin(),
             target.begin() + static_cast<std::ptrdiff_t>(tlen));
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

void decode_inner_routed_payload(std::span<const std::uint8_t> raw,
                                 std::string &out_target, std::string &out_body) {
  static constexpr std::array<std::uint8_t, 5> kMagic = {0x01U, 'M', 'P', '2', 'I'};
  if (raw.size() >= kMagic.size() + 2U &&
      std::memcmp(raw.data(), kMagic.data(), kMagic.size()) == 0) {
    const std::size_t tlen =
        (static_cast<std::size_t>(raw[5]) << 8U) | static_cast<std::size_t>(raw[6]);
    if (kMagic.size() + 2U + tlen <= raw.size()) {
      out_target.assign(reinterpret_cast<const char *>(raw.data() + 7U), tlen);
      const std::size_t bstart = 7U + tlen;
      out_body.assign(reinterpret_cast<const char *>(raw.data() + bstart),
                      raw.size() - bstart);
      if (out_target.empty()) {
        out_target = "@all";
      }
      return;
    }
  }
  out_target = "@all";
  out_body.assign(reinterpret_cast<const char *>(raw.data()), raw.size());
}

// Canonical binary inner ephemeral status payload (zero JSON internals):
// "\x01MP2S"(5) || len16(client) || len16(agent_name) || len16(agent_state) ||
// len16(agent_summary)
std::vector<std::uint8_t>
encode_inner_ephemeral_status(const MpRoomV2StatusUpdate &st) {
  static constexpr std::array<std::uint8_t, 5> kMagic = {0x01U, 'M', 'P', '2', 'S'};
  std::vector<std::uint8_t> out(kMagic.begin(), kMagic.end());
  auto append_str = [&](std::string_view s, std::size_t cap) {
    const std::uint16_t n =
        static_cast<std::uint16_t>(std::min<std::size_t>(s.size(), cap));
    out.push_back(static_cast<std::uint8_t>((n >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(n & 0xffU));
    out.insert(out.end(), s.begin(), s.begin() + static_cast<std::ptrdiff_t>(n));
  };
  append_str(st.client, 32U);
  append_str(st.agent_name, 48U);
  append_str(st.agent_state, 32U);
  append_str(st.agent_summary, 128U);
  return out;
}

std::optional<MpRoomV2StatusUpdate>
decode_inner_ephemeral_status(std::span<const std::uint8_t> raw) {
  static constexpr std::array<std::uint8_t, 5> kMagic = {0x01U, 'M', 'P', '2', 'S'};
  if (raw.size() < kMagic.size() + 8U ||
      std::memcmp(raw.data(), kMagic.data(), kMagic.size()) != 0) {
    return std::nullopt;
  }
  std::size_t pos = kMagic.size();
  auto read_str = [&](std::size_t cap) -> std::optional<std::string> {
    if (pos + 2U > raw.size()) {
      return std::nullopt;
    }
    const std::size_t n = (static_cast<std::size_t>(raw[pos]) << 8U) |
                          static_cast<std::size_t>(raw[pos + 1U]);
    pos += 2U;
    if (n > cap || pos + n > raw.size()) {
      return std::nullopt;
    }
    std::string s(reinterpret_cast<const char *>(raw.data() + pos), n);
    pos += n;
    return s;
  };
  const auto client = read_str(32U);
  const auto agent_name = read_str(48U);
  const auto agent_state = read_str(32U);
  const auto agent_summary = read_str(128U);
  if (!client.has_value() || !agent_name.has_value() || !agent_state.has_value() ||
      !agent_summary.has_value() || pos != raw.size()) {
    return std::nullopt;
  }
  return MpRoomV2StatusUpdate{*client, *agent_name, *agent_state, *agent_summary};
}

// Shared E2EE IRC JSON convention inside encrypted `e2ee_app` routed payloads
// (never visible to server, interoperable across Blackbird / Outpost / Web):
//   {"mp_irc":1,"t":"me","text":"..."}
//   {"mp_irc":1,"t":"nick","nick":"..."}
//   {"mp_irc":1,"t":"topic","topic":"..."}
std::vector<std::uint8_t> encode_e2ee_irc_action(std::string_view target,
                                                 std::string_view action) {
  Value::Object obj;
  obj.emplace_back("mp_irc", Value{Number{std::uint64_t{1U}}});
  obj.emplace_back("t", Value{"me"});
  obj.emplace_back("text", Value{std::string{action}});
  const auto dumped = dump_json(Value::object(std::move(obj)));
  return encode_inner_routed_payload(target, dumped.has_value() ? dumped.value()
                                                                : std::string{action});
}

std::vector<std::uint8_t> encode_e2ee_irc_nick(std::string_view nick) {
  Value::Object obj;
  obj.emplace_back("mp_irc", Value{Number{std::uint64_t{1U}}});
  obj.emplace_back("t", Value{"nick"});
  obj.emplace_back("nick", Value{std::string{nick}});
  const auto dumped = dump_json(Value::object(std::move(obj)));
  return encode_inner_routed_payload("@all", dumped.has_value() ? dumped.value()
                                                                : std::string{});
}

std::vector<std::uint8_t> encode_e2ee_irc_topic(std::string_view topic) {
  Value::Object obj;
  obj.emplace_back("mp_irc", Value{Number{std::uint64_t{1U}}});
  obj.emplace_back("t", Value{"topic"});
  obj.emplace_back("topic", Value{std::string{topic}});
  const auto dumped = dump_json(Value::object(std::move(obj)));
  return encode_inner_routed_payload("@all", dumped.has_value() ? dumped.value()
                                                                : std::string{});
}

enum class InnerIrcKind : std::uint8_t {
  chat = 0,
  irc_action = 1,
  irc_nick = 2,
  irc_topic = 3,
};

struct DecodedInnerPayload {
  InnerIrcKind kind = InnerIrcKind::chat;
  std::string target = "@all";
  std::string body;
};

DecodedInnerPayload decode_inner_chat_or_irc(std::span<const std::uint8_t> raw) {
  static constexpr std::array<std::uint8_t, 5> kActionMagic = {0x01U, 'M', 'P', '2',
                                                               'A'};
  static constexpr std::array<std::uint8_t, 5> kNickMagic = {0x01U, 'M', 'P', '2', 'N'};
  static constexpr std::array<std::uint8_t, 5> kTopicMagic = {0x01U, 'M', 'P', '2',
                                                              'T'};
  if (raw.size() >= 7U &&
      std::memcmp(raw.data(), kActionMagic.data(), kActionMagic.size()) == 0) {
    const std::size_t tlen =
        (static_cast<std::size_t>(raw[5]) << 8U) | static_cast<std::size_t>(raw[6]);
    if (7U + tlen <= raw.size()) {
      DecodedInnerPayload out{};
      out.kind = InnerIrcKind::irc_action;
      out.target.assign(reinterpret_cast<const char *>(raw.data() + 7U), tlen);
      if (out.target.empty()) {
        out.target = "@all";
      }
      out.body.assign(reinterpret_cast<const char *>(raw.data() + 7U + tlen),
                      raw.size() - (7U + tlen));
      return out;
    }
  }
  if (raw.size() >= 7U &&
      std::memcmp(raw.data(), kNickMagic.data(), kNickMagic.size()) == 0) {
    const std::size_t nlen =
        (static_cast<std::size_t>(raw[5]) << 8U) | static_cast<std::size_t>(raw[6]);
    if (7U + nlen <= raw.size()) {
      DecodedInnerPayload out{};
      out.kind = InnerIrcKind::irc_nick;
      out.body.assign(reinterpret_cast<const char *>(raw.data() + 7U), nlen);
      return out;
    }
  }
  if (raw.size() >= 7U &&
      std::memcmp(raw.data(), kTopicMagic.data(), kTopicMagic.size()) == 0) {
    const std::size_t tlen =
        (static_cast<std::size_t>(raw[5]) << 8U) | static_cast<std::size_t>(raw[6]);
    if (7U + tlen <= raw.size()) {
      DecodedInnerPayload out{};
      out.kind = InnerIrcKind::irc_topic;
      out.body.assign(reinterpret_cast<const char *>(raw.data() + 7U), tlen);
      return out;
    }
  }
  DecodedInnerPayload out{};
  decode_inner_routed_payload(raw, out.target, out.body);
  const std::string_view trimmed = trim_ascii_ws(out.body);
  if (trimmed.size() >= 12U && trimmed.front() == '{' && trimmed.back() == '}') {
    ValueLimits limits{};
    limits.bytes = mp::kMaxMp2BodyBytes;
    limits.nodes = 128U;
    limits.depth = 8U;
    if (const auto parsed = parse_json(trimmed, limits);
        parsed.has_value() &&
        std::holds_alternative<Value::Object>(parsed.value().value())) {
      const Value &obj = parsed.value();
      if (json_u64_or_decimal(obj, "mp_irc").value_or(0U) == 1U) {
        const auto t = json_opt_string(obj, "t");
        if (t.has_value()) {
          if (*t == "nick") {
            if (const auto n = json_opt_string(obj, "nick"); n.has_value()) {
              out.kind = InnerIrcKind::irc_nick;
              out.body = *n;
              return out;
            }
          } else if (*t == "me") {
            if (const auto txt = json_opt_string(obj, "text"); txt.has_value()) {
              out.kind = InnerIrcKind::irc_action;
              out.body = *txt;
              return out;
            }
          } else if (*t == "topic") {
            if (const auto top = json_opt_string(obj, "topic"); top.has_value()) {
              out.kind = InnerIrcKind::irc_topic;
              out.body = *top;
              return out;
            }
          }
        }
      }
    }
  }
  // Also render plain decrypted `/me <action>` text cleanly as an IRC action.
  if (trimmed.size() > 4U && trimmed.starts_with("/me ")) {
    out.kind = InnerIrcKind::irc_action;
    out.body = std::string{trim_ascii_ws(trimmed.substr(4U))};
  }
  return out;
}

std::string member_identity_key(const MpRoomV2Member &m) {
  auto lower = [](std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
      out.push_back(ascii_lower(ch));
    }
    return out;
  };
  if (!m.is_guest && m.account_id.has_value()) {
    if (m.device_id.has_value()) {
      return "dev:" + std::to_string(m.account_id->value()) + ":" +
             std::to_string(m.device_id->value());
    }
    if (!m.client.empty()) {
      return "acct:" + std::to_string(m.account_id->value()) + ":" + lower(m.client);
    }
    return "acct:" + std::to_string(m.account_id->value());
  }
  return "guest:" + lower(strip_at(m.handle));
}

std::string format_irc_joinline(const MpRoomV2Member &m) {
  const std::string clean_handle = party_chat_sanitize(strip_at(m.handle), 64U);
  const std::string nick =
      !m.nick.empty() ? party_chat_sanitize(m.nick, 32U) : clean_handle;
  const std::string client =
      m.client.empty() ? std::string{"blackbird"} : party_chat_sanitize(m.client, 32U);
  return "--> " + nick + " (@" + clean_handle + " · " + client + ") has joined";
}

std::string format_irc_partline(const MpRoomV2Member &m) {
  const std::string clean_handle = party_chat_sanitize(strip_at(m.handle), 64U);
  const std::string nick =
      !m.nick.empty() ? party_chat_sanitize(m.nick, 32U) : clean_handle;
  return "<-- " + nick + " (@" + clean_handle + ") has left";
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
  case MpRoomV2Error::mls_unavailable:
    return "mls_unavailable";
  case MpRoomV2Error::mls_encrypt_failed:
    return "mls_encrypt_failed";
  case MpRoomV2Error::mls_send_blocked:
    return "mls_send_blocked";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Agent Card validation, scrubbing, serialization & `@agent` mention detection
// ---------------------------------------------------------------------------

bool mp_room_v2_is_browser_client(std::string_view client) noexcept {
  const std::string_view trimmed = trim_ascii_ws(client);
  return ascii_iequals(trimmed, "web") || ascii_iequals(trimmed, "browser");
}

bool mp_room_v2_contains_secret_token(std::string_view text) noexcept {
  if (text.empty()) {
    return false;
  }
  static constexpr std::array<std::string_view, 15> kMarkers{
      "mprk1_", "mpinv1_",     "mppi1_",  "mpcs1_", "mpguest1_",
      "mpws1_", "mpdl1_",      "sk-ant-", "sk-or-", "sk-proj-",
      "ghp_",   "github_pat_", "xoxb-",   "xoxp-",  "-----begin ",
  };
  for (std::size_t i = 0U; i < text.size(); ++i) {
    const std::string_view tail = text.substr(i);
    for (const std::string_view marker : kMarkers) {
      if (ascii_istarts_with(tail, marker)) {
        return true;
      }
    }
  }
  // Also reject canonical `#<secret>` fragment invite URLs
  // (`multiplayer.tech/p/i/...#...` or `clank.party/i/...#...`).
  static constexpr std::array<std::string_view, 2> kInvitePaths{
      "multiplayer.tech/p/i/",
      "clank.party/i/",
  };
  for (std::size_t i = 0U; i < text.size(); ++i) {
    const std::string_view tail = text.substr(i);
    for (const std::string_view prefix : kInvitePaths) {
      if (!ascii_istarts_with(tail, prefix)) {
        continue;
      }
      const std::string_view rest = tail.substr(prefix.size());
      const std::size_t hash = rest.find('#');
      if (hash != std::string_view::npos && hash + 1U < rest.size()) {
        const char next = rest[hash + 1U];
        if (next != ' ' && next != '\t' && next != '\r' && next != '\n' &&
            next != '[') {
          return true;
        }
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
  if (op_name == "party_chat") {
    std::string_view action;
    if (const auto *a = op_input.find("action");
        a != nullptr && std::holds_alternative<std::string>(a->value())) {
      action = a->string();
    }
    if (action == "read" || action == "status") {
      req.effect_class = brakes::ToolEffectClass::read_only;
    } else {
      req.requires_network = true;
      req.effect_class = brakes::ToolEffectClass::outbound_network;
    }
  }
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
// MLS Engine bootstrap helper & session lifecycle
// ---------------------------------------------------------------------------

Result<std::shared_ptr<MpMlsEngine>> open_mp_mls_engine_for_identity(
    const std::filesystem::path &state_dir, const mp::MpIdentityState &identity,
    mp::MpControlClient *client, std::uint8_t client_class, bool agent_capable) {
  if (!mp_mls_compiled_in()) {
    return fail<std::shared_ptr<MpMlsEngine>>(ErrorCode::unsupported,
                                              MpRoomV2Error::mls_unavailable);
  }
  if (state_dir.empty() || !identity.account_id.has_value() ||
      !identity.device_id.has_value() || identity.device_id->value() == 0U) {
    return fail<std::shared_ptr<MpMlsEngine>>(ErrorCode::invalid_identity,
                                              MpRoomV2Error::mls_unavailable);
  }
  const auto dev_sk = mp::Ed25519SigningKey::from_seed(identity.device_seed.bytes());
  if (!dev_sk.has_value()) {
    return fail<std::shared_ptr<MpMlsEngine>>(ErrorCode::invalid_identity,
                                              MpRoomV2Error::mls_unavailable);
  }
  std::vector<std::uint8_t> key_preimage;
  static constexpr std::string_view kStoreKeyDomain = "bb-mls-store-key-v1:";
  key_preimage.insert(key_preimage.end(), kStoreKeyDomain.begin(),
                      kStoreKeyDomain.end());
  key_preimage.insert(key_preimage.end(), identity.device_seed.bytes().begin(),
                      identity.device_seed.bytes().end());
  const auto key_hash = mp::sha256(key_preimage);
  if (!key_hash.has_value()) {
    return Result<std::shared_ptr<MpMlsEngine>>::failure(key_hash.error());
  }

  const std::uint64_t now_s = wall_now_ms() / 1000U;
  const std::uint64_t iat_s = now_s > 60ULL ? (now_s - 60ULL) : 1ULL;
  const std::uint64_t ttl_s =
      (client_class == 3U) ? (7ULL * 86400ULL - 120ULL) : (30ULL * 86400ULL - 120ULL);

  MpMlsEngineConfig mcfg{};
  mcfg.state_dir = state_dir;
  mcfg.account_id = *identity.account_id;
  mcfg.device_id = *identity.device_id;
  mcfg.client_class = client_class;
  mcfg.agent_capable = agent_capable;
  mcfg.mls_sig_seed = identity.device_seed.bytes();
  mcfg.store_enc_key = key_hash.value();

  if (identity.root_seed.has_value()) {
    // Self-custody path (`custody_mode = 1`): sign binding + device list locally.
    const auto binding = mp_mls_sign_device_binding(
        *identity.account_id, 1U, *identity.device_id, 1U, client_class, agent_capable,
        1U, iat_s, now_s + ttl_s, identity.root_seed->bytes(),
        identity.device_seed.bytes());
    if (!binding.has_value()) {
      return Result<std::shared_ptr<MpMlsEngine>>::failure(binding.error());
    }
    const std::array<MpMlsActiveDeviceEntry, 1> dev_entries{
        MpMlsActiveDeviceEntry{identity.device_id->value(), 1U,
                               dev_sk.value().public_key()},
    };
    const auto dlist = mp_mls_sign_device_list(
        *identity.account_id, 1U, 1U, iat_s, now_s + (30ULL * 86400ULL - 120ULL),
        dev_entries, identity.root_seed->bytes());
    if (!dlist.has_value()) {
      return Result<std::shared_ptr<MpMlsEngine>>::failure(dlist.error());
    }
    mcfg.root_gen = 1U;
    mcfg.device_gen = 1U;
    mcfg.custody_mode = 1U;
    mcfg.device_binding = binding.value();
    mcfg.device_list_bytes = dlist.value();
  } else if (client != nullptr) {
    // Cloud-managed path (`custody_mode = 0`, e.g. `blackbird login`):
    // 2-step Spec v3.1 cloud-managed MLS device binding via
    // `POST /v1/accounts/me/mls/cloud-bind`.
    // Step 1: request deterministic `body[108]` + `root_sig[64]` + `pop_message[50]`.
    // Step 2: verify `pop_message == "mp-mls-dev-pop-v1:" || SHA-256(body ||
    // root_sig)`, sign with local device MLS signing key, and submit `device_sig_b64`.
    const auto dev_pk = dev_sk.value().public_key();
    mp::MlsCloudBindRequest step1_req{};
    step1_req.mls_sig_pubkey = dev_pk;
    step1_req.client_class = client_class;
    step1_req.agent_capable = agent_capable;
    const auto step1_res = client->mls_cloud_bind(step1_req);
    if (!step1_res.has_value()) {
      return Result<std::shared_ptr<MpMlsEngine>>::failure(step1_res.error());
    }

    mp::MlsCloudBindResponse bound_res = step1_res.value();
    if (bound_res.step == "sign_pop") {
      if (bound_res.body_bytes.size() != 108U ||
          bound_res.root_sig_bytes.size() != 64U ||
          bound_res.pop_message_bytes.size() != 50U) {
        return fail<std::shared_ptr<MpMlsEngine>>(ErrorCode::corrupt,
                                                  MpRoomV2Error::protocol_error);
      }
      std::vector<std::uint8_t> hash_input;
      hash_input.reserve(172U);
      hash_input.insert(hash_input.end(), bound_res.body_bytes.begin(),
                        bound_res.body_bytes.end());
      hash_input.insert(hash_input.end(), bound_res.root_sig_bytes.begin(),
                        bound_res.root_sig_bytes.end());
      const auto pop_digest = mp::sha256(hash_input);
      if (!pop_digest.has_value()) {
        return Result<std::shared_ptr<MpMlsEngine>>::failure(pop_digest.error());
      }
      static constexpr std::string_view kPopDomain = "mp-mls-dev-pop-v1:";
      std::vector<std::uint8_t> expected_pop;
      expected_pop.reserve(kPopDomain.size() + 32U);
      expected_pop.insert(expected_pop.end(), kPopDomain.begin(), kPopDomain.end());
      expected_pop.insert(expected_pop.end(), pop_digest.value().begin(),
                          pop_digest.value().end());
      if (expected_pop != bound_res.pop_message_bytes) {
        return fail<std::shared_ptr<MpMlsEngine>>(ErrorCode::corrupt,
                                                  MpRoomV2Error::protocol_error);
      }
      const auto pop_sig = dev_sk.value().sign(expected_pop);
      if (!pop_sig.has_value()) {
        return Result<std::shared_ptr<MpMlsEngine>>::failure(pop_sig.error());
      }

      mp::MlsCloudBindRequest step2_req{};
      step2_req.mls_sig_pubkey = dev_pk;
      step2_req.client_class = client_class;
      step2_req.agent_capable = agent_capable;
      step2_req.iat_s = bound_res.iat_s;
      step2_req.exp_s = bound_res.exp_s;
      step2_req.device_sig.assign(pop_sig.value().begin(), pop_sig.value().end());
      const auto step2_res = client->mls_cloud_bind(step2_req);
      if (!step2_res.has_value()) {
        return Result<std::shared_ptr<MpMlsEngine>>::failure(step2_res.error());
      }
      if (step2_res.value().step != "bound") {
        return fail<std::shared_ptr<MpMlsEngine>>(ErrorCode::corrupt,
                                                  MpRoomV2Error::protocol_error);
      }
      bound_res = step2_res.value();
    }

    if (const auto chk = mp_mls_verify_device_binding(bound_res.device_binding);
        !chk.has_value()) {
      return Result<std::shared_ptr<MpMlsEngine>>::failure(chk.error());
    }
    mcfg.root_gen = bound_res.root_gen;
    mcfg.device_gen = bound_res.device_gen;
    mcfg.custody_mode = bound_res.custody_mode;
    mcfg.device_binding = bound_res.device_binding;
    mcfg.device_list_bytes = bound_res.device_list_bytes;
  } else {
    return fail<std::shared_ptr<MpMlsEngine>>(ErrorCode::invalid_identity,
                                              MpRoomV2Error::mls_unavailable);
  }

  auto opened = MpMlsEngine::open(mcfg);
  if (!opened.has_value()) {
    return Result<std::shared_ptr<MpMlsEngine>>::failure(opened.error());
  }
  return Result<std::shared_ptr<MpMlsEngine>>::success(
      std::make_shared<MpMlsEngine>(std::move(opened).value()));
}

Result<std::unique_ptr<MpRoomV2Session>> MpRoomV2Session::start(MpRoomV2Config config) {
  if (!config.identity.account_id.has_value() ||
      !config.identity.device_id.has_value() ||
      config.identity.device_id->value() == 0U) {
    return fail<std::unique_ptr<MpRoomV2Session>>(ErrorCode::provider_auth,
                                                  MpRoomV2Error::invalid_config);
  }
  // Fail closed when e2ee_mode == 1 without a valid MpMlsEngine!
  if (config.e2ee_mode == 1U) {
    if (!config.mls_engine || !config.mls_engine->valid()) {
      return fail<std::unique_ptr<MpRoomV2Session>>(ErrorCode::invalid_identity,
                                                    MpRoomV2Error::mls_unavailable);
    }
    if (config.mls_group_id.has_value() &&
        !config.mls_engine->room_status(*config.mls_group_id).has_value()) {
      return fail<std::unique_ptr<MpRoomV2Session>>(ErrorCode::invalid_identity,
                                                    MpRoomV2Error::mls_unavailable);
    }
  } else if (config.e2ee_mode > 1U) {
    return fail<std::unique_ptr<MpRoomV2Session>>(ErrorCode::invalid_range,
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

  // Creator bootstrap BEFORE connecting WebSocket when party_ds_pubkey is already
  // known: creates the epoch-0 MLS group and POSTs /v1/parties/:id/mls/init so `hello`
  // arrives with an already-live E2EE group!
  if (config.e2ee_mode == 1U && config.mls_engine && config.mls_engine->valid() &&
      !config.mls_group_id.has_value() && config.is_room_creator &&
      config.party_ds_pubkey.has_value()) {
    MpMlsRoomPolicy pol{};
    pol.party_id = config.party_id;
    pol.require_self_custody = false;
    pol.allow_browser_devices = true;
    pol.host_account_ids = {config.identity.account_id->value()};
    const auto created = config.mls_engine->create_group(pol, *config.party_ds_pubkey);
    if (created.has_value()) {
      const auto init_res = client.mls_init_party(mp::MlsInitPartyRequest{
          config.party_id,
          created.value().group_id,
          created.value().group_info_bytes,
      });
      if (init_res.has_value()) {
        config.mls_group_id = created.value().group_id;
      }
      // On 409 (mls_already_initialized) or transient error, fall through to WS connect
      // where handle_hello_locked + worker pumps will complete bootstrap or
      // Welcome-join!
    }
  }

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
      local_device_id_(params.config.identity.device_id),
      mls_engine_(std::move(params.config.mls_engine)),
      ws_path_(std::move(params.ws_path)),
      local_handle_(std::move(params.local_handle)),
      client_name_(params.config.client_name.empty() ? std::string{"blackbird"}
                                                     : params.config.client_name),
      agent_name_(params.config.agent_name.empty() ? std::string{"Blackbird"}
                                                   : params.config.agent_name),
      max_retained_messages_(std::clamp<std::size_t>(
          params.config.max_retained_messages, 1U, kMpRoomV2MaxRetainedMessagesCap)),
      room_code_(party_chat_sanitize(params.config.room_code, 32U)),
      room_name_(party_chat_sanitize(params.config.room_name, 128U)),
      share_url_(mp::is_usable_room_share_url(params.config.share_url)
                     ? party_chat_sanitize(params.config.share_url, 256U)
                     : std::string{}),
      brakes_gate_(load_effective_brakes_policy_or_default()),
      party_ds_pubkey_(params.config.party_ds_pubkey),
      mls_invite_fragment_(std::move(params.config.mls_invite_fragment)),
      poll_interval_ms_(
          std::clamp<std::uint32_t>(params.config.poll_interval_ms, 5U, 250U)),
      ping_interval_ms_(
          std::clamp<std::uint32_t>(params.config.ping_interval_ms, 1000U, 60000U)),
      reconnect_base_ms_(std::max<std::uint32_t>(params.config.reconnect_base_ms, 50U)),
      reconnect_max_ms_(
          std::max<std::uint32_t>(params.config.reconnect_max_ms, reconnect_base_ms_)),
      wake_read_fd_(params.wake_read_fd), wake_write_fd_(params.wake_write_fd),
      e2ee_mode_(params.config.e2ee_mode), state_(MpRoomV2State::connecting),
      mls_joining_(params.config.e2ee_mode == 1U &&
                   !params.config.mls_group_id.has_value()),
      mls_group_id_(params.config.mls_group_id) {
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
    m.is_browser = im.is_browser || mp_room_v2_is_browser_client(m.client);
    m.agent_name = party_chat_sanitize(im.agent_name, 48U);
    m.agent_state = party_chat_sanitize(im.agent_state, 32U);
    m.agent_summary = party_chat_sanitize(im.agent_summary, 128U);
    m.status =
        im.status.empty() ? std::string{"live"} : party_chat_sanitize(im.status, 24U);
    m.is_self = !m.is_guest && !m.is_browser && local_account_id_.has_value() &&
                m.account_id.has_value() && *m.account_id == *local_account_id_;
    initial.push_back(std::move(m));
  }
  apply_members_locked(initial);
  refresh_mls_status_locked();
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

    if (e2ee_mode_ == 1U) {
      if (!mls_engine_ || !mls_group_id_.has_value()) {
        return fail<std::string>(ErrorCode::invalid_identity,
                                 MpRoomV2Error::mls_unavailable);
      }
      MlsInnerMsgId inner_id{};
      if (const auto rnd = mp::random_bytes(inner_id); !rnd.has_value()) {
        return fail<std::string>(ErrorCode::external_unknown,
                                 MpRoomV2Error::mls_encrypt_failed);
      }
      auto inner_bytes = encode_inner_routed_payload(target.value, body);
      auto enc = mls_engine_->encrypt_app(*mls_group_id_, inner_id, MpMlsMsgClass::chat,
                                          inner_bytes, wall_now_ms() / 1000U);
      if (!enc.has_value()) {
        refresh_mls_status_locked();
        const auto mls_err = mp_mls_error_of(enc.error());
        if (mls_err == MpMlsError::self_clone_detected ||
            mls_err == MpMlsError::pending_removal ||
            mls_err == MpMlsError::frame_cap) {
          return fail<std::string>(ErrorCode::conflict,
                                   MpRoomV2Error::mls_send_blocked);
        }
        return fail<std::string>(enc.error().code, MpRoomV2Error::mls_encrypt_failed);
      }

      MpRoomV2Message optimistic{};
      optimistic.seq = 0U;
      optimistic.ts_ms = wall_now_ms();
      optimistic.client_msg_id = msg_id;
      optimistic.sender_account_id = local_account_id_;
      optimistic.sender_device_id = local_device_id_;
      optimistic.sender_handle = local_handle_;
      optimistic.sender_nick = local_nick_;
      optimistic.sender_client = client_name_;
      optimistic.sender_agent_name = agent_name_;
      optimistic.target = party_chat_sanitize(target.value, kMaxRoomTargetBytes);
      optimistic.kind = "chat";
      optimistic.body_encoding = "opaque_b64";
      optimistic.body = body;
      optimistic.rendered_body = party_chat_sanitize(body, 2048U);
      optimistic.delivered = false;
      optimistic.local_self = true;
      upsert_message_locked(std::move(optimistic));

      OutboundMessage ob{};
      ob.client_msg_id = msg_id;
      ob.kind = "e2ee_app";
      ob.target = "*";
      ob.body_encoding = "opaque_b64";
      ob.body = room_b64_encode(enc.value().wire_bytes);
      ob.sent_on_current_socket = false;
      ob.is_e2ee = true;
      ob.inner_msg_id = inner_id;
      ob.mls_msg_class = MpMlsMsgClass::chat;
      ob.plaintext_inner = std::move(inner_bytes);
      ob.sent_epoch = enc.value().mls_epoch;
      outbox_.push_back(std::move(ob));
      refresh_mls_status_locked();
    } else {
      MpRoomV2Message optimistic{};
      optimistic.seq = 0U;
      optimistic.ts_ms = wall_now_ms();
      optimistic.client_msg_id = msg_id;
      optimistic.sender_account_id = local_account_id_;
      optimistic.sender_device_id = local_device_id_;
      optimistic.sender_handle = local_handle_;
      optimistic.sender_nick = local_nick_;
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

      OutboundMessage ob{};
      ob.client_msg_id = msg_id;
      ob.kind = "chat";
      ob.target = std::move(target.value);
      ob.body_encoding = "utf8";
      ob.body = std::move(body);
      ob.sent_on_current_socket = false;
      outbox_.push_back(std::move(ob));
    }
    rebuild_status_summary_locked();
  }
  signal_wake();
  return Result<std::string>::success(std::move(msg_id));
}

Result<std::string> MpRoomV2Session::send_action(const std::string &action,
                                                 MpRoomV2Target target) {
  if (stop_requested_.load(std::memory_order_acquire) ||
      stopped_.load(std::memory_order_acquire)) {
    return fail<std::string>(ErrorCode::stale_handle, MpRoomV2Error::session_stopped);
  }
  const std::string_view trimmed = trim_ascii_ws(action);
  if (trimmed.empty()) {
    return fail<std::string>(ErrorCode::invalid_range, MpRoomV2Error::invalid_field);
  }
  if (trimmed.size() > mp::kMaxMp2BodyBytes) {
    return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::field_too_large);
  }
  if (target.value.empty()) {
    target.value = "@all";
  }
  if (target.value.size() > kMaxRoomTargetBytes) {
    return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::field_too_large);
  }
  const std::string clean_action = party_chat_sanitize(trimmed, 2048U);
  if (clean_action.empty()) {
    return fail<std::string>(ErrorCode::invalid_range, MpRoomV2Error::invalid_field);
  }

  std::string msg_id;
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (outbox_.size() >= kMpRoomV2MaxPendingOutbox) {
      return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::queue_full);
    }
    ++local_msg_counter_;
    msg_id = generate_client_msg_id(local_msg_counter_);

    if (e2ee_mode_ == 1U) {
      if (!mls_engine_ || !mls_group_id_.has_value()) {
        return fail<std::string>(ErrorCode::invalid_identity,
                                 MpRoomV2Error::mls_unavailable);
      }
      MlsInnerMsgId inner_id{};
      if (const auto rnd = mp::random_bytes(inner_id); !rnd.has_value()) {
        return fail<std::string>(ErrorCode::external_unknown,
                                 MpRoomV2Error::mls_encrypt_failed);
      }
      auto inner_bytes = encode_e2ee_irc_action(target.value, clean_action);
      auto enc = mls_engine_->encrypt_app(*mls_group_id_, inner_id, MpMlsMsgClass::chat,
                                          inner_bytes, wall_now_ms() / 1000U);
      if (!enc.has_value()) {
        refresh_mls_status_locked();
        const auto mls_err = mp_mls_error_of(enc.error());
        if (mls_err == MpMlsError::self_clone_detected ||
            mls_err == MpMlsError::pending_removal ||
            mls_err == MpMlsError::frame_cap) {
          return fail<std::string>(ErrorCode::conflict,
                                   MpRoomV2Error::mls_send_blocked);
        }
        return fail<std::string>(enc.error().code, MpRoomV2Error::mls_encrypt_failed);
      }

      MpRoomV2Message optimistic{};
      optimistic.seq = 0U;
      optimistic.ts_ms = wall_now_ms();
      optimistic.client_msg_id = msg_id;
      optimistic.sender_account_id = local_account_id_;
      optimistic.sender_device_id = local_device_id_;
      optimistic.sender_handle = local_handle_;
      optimistic.sender_nick = local_nick_;
      optimistic.sender_client = client_name_;
      optimistic.sender_agent_name = agent_name_;
      optimistic.target = party_chat_sanitize(target.value, kMaxRoomTargetBytes);
      optimistic.kind = "irc_action";
      optimistic.body_encoding = "opaque_b64";
      optimistic.body = clean_action;
      optimistic.rendered_body = clean_action;
      optimistic.delivered = false;
      optimistic.local_self = true;
      upsert_message_locked(std::move(optimistic));

      OutboundMessage ob{};
      ob.client_msg_id = msg_id;
      ob.kind = "e2ee_app";
      ob.target = "*";
      ob.body_encoding = "opaque_b64";
      ob.body = room_b64_encode(enc.value().wire_bytes);
      ob.sent_on_current_socket = false;
      ob.is_e2ee = true;
      ob.inner_msg_id = inner_id;
      ob.mls_msg_class = MpMlsMsgClass::chat;
      ob.plaintext_inner = std::move(inner_bytes);
      ob.sent_epoch = enc.value().mls_epoch;
      outbox_.push_back(std::move(ob));
      refresh_mls_status_locked();
    } else {
      MpRoomV2Message optimistic{};
      optimistic.seq = 0U;
      optimistic.ts_ms = wall_now_ms();
      optimistic.client_msg_id = msg_id;
      optimistic.sender_account_id = local_account_id_;
      optimistic.sender_device_id = local_device_id_;
      optimistic.sender_handle = local_handle_;
      optimistic.sender_nick = local_nick_;
      optimistic.sender_client = client_name_;
      optimistic.sender_agent_name = agent_name_;
      optimistic.target = party_chat_sanitize(target.value, kMaxRoomTargetBytes);
      optimistic.kind = "irc_action";
      optimistic.body_encoding = "utf8";
      optimistic.body = clean_action;
      optimistic.rendered_body = clean_action;
      optimistic.delivered = false;
      optimistic.local_self = true;
      upsert_message_locked(std::move(optimistic));

      OutboundMessage ob{};
      ob.client_msg_id = msg_id;
      ob.kind = "chat";
      ob.target = std::move(target.value);
      ob.body_encoding = "utf8";
      ob.body = "/me " + clean_action;
      ob.sent_on_current_socket = false;
      outbox_.push_back(std::move(ob));
    }
    rebuild_status_summary_locked();
  }
  signal_wake();
  return Result<std::string>::success(std::move(msg_id));
}

Result<std::string> MpRoomV2Session::set_nick(std::string_view nick) {
  if (stop_requested_.load(std::memory_order_acquire) ||
      stopped_.load(std::memory_order_acquire)) {
    return fail<std::string>(ErrorCode::stale_handle, MpRoomV2Error::session_stopped);
  }
  const auto valid = validate_irc_nick(nick);
  if (!valid.has_value()) {
    return fail<std::string>(valid.error().code, MpRoomV2Error::invalid_field);
  }
  const std::string &clean_nick = valid.value();

  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (outbox_.size() >= kMpRoomV2MaxPendingOutbox) {
      return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::queue_full);
    }
    ++local_msg_counter_;
    const std::string msg_id = generate_client_msg_id(local_msg_counter_);

    if (e2ee_mode_ == 1U) {
      if (!mls_engine_ || !mls_group_id_.has_value()) {
        return fail<std::string>(ErrorCode::invalid_identity,
                                 MpRoomV2Error::mls_unavailable);
      }
      const MlsGroupId gid = *mls_group_id_;
      MlsInnerMsgId inner_id{};
      if (const auto rnd = mp::random_bytes(inner_id); !rnd.has_value()) {
        return fail<std::string>(ErrorCode::external_unknown,
                                 MpRoomV2Error::mls_encrypt_failed);
      }
      auto inner_bytes = encode_e2ee_irc_nick(clean_nick);
      auto enc = mls_engine_->encrypt_app(gid, inner_id, MpMlsMsgClass::chat,
                                          inner_bytes, wall_now_ms() / 1000U);
      if (!enc.has_value()) {
        refresh_mls_status_locked();
        const auto mls_err = mp_mls_error_of(enc.error());
        if (mls_err == MpMlsError::self_clone_detected ||
            mls_err == MpMlsError::pending_removal ||
            mls_err == MpMlsError::frame_cap) {
          return fail<std::string>(ErrorCode::conflict,
                                   MpRoomV2Error::mls_send_blocked);
        }
        return fail<std::string>(enc.error().code, MpRoomV2Error::mls_encrypt_failed);
      }
      OutboundMessage ob{};
      ob.client_msg_id = msg_id;
      ob.kind = "e2ee_app";
      ob.target = "*";
      ob.body_encoding = "opaque_b64";
      ob.body = room_b64_encode(enc.value().wire_bytes);
      ob.sent_on_current_socket = false;
      ob.is_e2ee = true;
      ob.inner_msg_id = inner_id;
      ob.mls_msg_class = MpMlsMsgClass::chat;
      ob.plaintext_inner = std::move(inner_bytes);
      ob.sent_epoch = enc.value().mls_epoch;
      outbox_.push_back(std::move(ob));
      refresh_mls_status_locked();
    } else {
      Value::Object frame;
      frame.emplace_back("v", Value{Number{std::uint64_t{2U}}});
      frame.emplace_back("t", Value{"nick"});
      frame.emplace_back("nick", Value{clean_nick});
      if (const auto dumped = dump_json(Value::object(std::move(frame)));
          dumped.has_value()) {
        control_outbox_.push_back(PendingControlFrame{dumped.value()});
      }
    }

    local_nick_ = clean_nick;
    set_member_nick_locked(MemberNickUpdate{local_account_id_, local_device_id_,
                                            local_handle_, clean_nick});
    append_irc_notice_locked("* @" + local_handle_ + " is now known as " + clean_nick);
    rebuild_status_summary_locked();
  }
  signal_wake();
  return Result<std::string>::success(clean_nick);
}

Result<std::string> MpRoomV2Session::set_topic(std::string_view topic) {
  if (stop_requested_.load(std::memory_order_acquire) ||
      stopped_.load(std::memory_order_acquire)) {
    return fail<std::string>(ErrorCode::stale_handle, MpRoomV2Error::session_stopped);
  }
  const std::string_view trimmed = trim_ascii_ws(topic);
  if (trimmed.empty()) {
    return fail<std::string>(ErrorCode::invalid_range, MpRoomV2Error::invalid_field);
  }
  const std::string clean_topic = scrub_agent_card_text(trimmed, 160U);
  if (clean_topic.empty()) {
    return fail<std::string>(ErrorCode::invalid_range, MpRoomV2Error::invalid_field);
  }
  if (mp_room_v2_contains_secret_token(trimmed) ||
      mp_room_v2_contains_secret_token(clean_topic)) {
    return fail<std::string>(ErrorCode::invalid_range, MpRoomV2Error::secret_rejected);
  }

  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (outbox_.size() >= kMpRoomV2MaxPendingOutbox) {
      return fail<std::string>(ErrorCode::capacity, MpRoomV2Error::queue_full);
    }
    ++local_msg_counter_;
    const std::string msg_id = generate_client_msg_id(local_msg_counter_);

    if (e2ee_mode_ == 1U) {
      if (!mls_engine_ || !mls_group_id_.has_value()) {
        return fail<std::string>(ErrorCode::invalid_identity,
                                 MpRoomV2Error::mls_unavailable);
      }
      const MlsGroupId gid = *mls_group_id_;
      MlsInnerMsgId inner_id{};
      if (const auto rnd = mp::random_bytes(inner_id); !rnd.has_value()) {
        return fail<std::string>(ErrorCode::external_unknown,
                                 MpRoomV2Error::mls_encrypt_failed);
      }
      auto inner_bytes = encode_e2ee_irc_topic(clean_topic);
      auto enc = mls_engine_->encrypt_app(gid, inner_id, MpMlsMsgClass::chat,
                                          inner_bytes, wall_now_ms() / 1000U);
      if (!enc.has_value()) {
        refresh_mls_status_locked();
        const auto mls_err = mp_mls_error_of(enc.error());
        if (mls_err == MpMlsError::self_clone_detected ||
            mls_err == MpMlsError::pending_removal ||
            mls_err == MpMlsError::frame_cap) {
          return fail<std::string>(ErrorCode::conflict,
                                   MpRoomV2Error::mls_send_blocked);
        }
        return fail<std::string>(enc.error().code, MpRoomV2Error::mls_encrypt_failed);
      }
      OutboundMessage ob{};
      ob.client_msg_id = msg_id;
      ob.kind = "e2ee_app";
      ob.target = "*";
      ob.body_encoding = "opaque_b64";
      ob.body = room_b64_encode(enc.value().wire_bytes);
      ob.sent_on_current_socket = false;
      ob.is_e2ee = true;
      ob.inner_msg_id = inner_id;
      ob.mls_msg_class = MpMlsMsgClass::chat;
      ob.plaintext_inner = std::move(inner_bytes);
      ob.sent_epoch = enc.value().mls_epoch;
      outbox_.push_back(std::move(ob));
      refresh_mls_status_locked();
    } else {
      Value::Object frame;
      frame.emplace_back("v", Value{Number{std::uint64_t{2U}}});
      frame.emplace_back("t", Value{"topic"});
      frame.emplace_back("topic", Value{clean_topic});
      if (const auto dumped = dump_json(Value::object(std::move(frame)));
          dumped.has_value()) {
        control_outbox_.push_back(PendingControlFrame{dumped.value()});
      }
    }

    topic_ = clean_topic;
    const std::string actor =
        format_irc_display_name(IrcDisplayNameInput{local_nick_, local_handle_});
    append_irc_notice_locked("* " + actor + " changed the topic to: " + clean_topic);
    rebuild_status_summary_locked();
  }
  signal_wake();
  return Result<std::string>::success(clean_topic);
}

std::string MpRoomV2Session::topic() const {
  std::lock_guard<std::mutex> lock(state_mu_);
  return topic_;
}

std::string MpRoomV2Session::local_nick() const {
  std::lock_guard<std::mutex> lock(state_mu_);
  return local_nick_;
}

std::string MpRoomV2Session::format_names_line() const {
  std::lock_guard<std::mutex> lock(state_mu_);
  std::string out = "[Users: ";
  for (std::size_t i = 0U; i < members_.size(); ++i) {
    if (i > 0U) {
      out += ", ";
    }
    const auto &m = members_[i];
    const std::string clean_handle = party_chat_sanitize(strip_at(m.handle), 64U);
    const std::string nick =
        !m.nick.empty() ? party_chat_sanitize(m.nick, 32U) : clean_handle;
    const std::string client = m.client.empty() ? std::string{"blackbird"}
                                                : party_chat_sanitize(m.client, 32U);
    const std::string st = (m.status == "offline" || m.status == "away")
                               ? std::string{"away"}
                               : std::string{"live"};
    out += nick + " (@" + clean_handle + " · " + client + " · " + st + ")";
  }
  if (members_.empty()) {
    out += "(none)";
  }
  out += "]";
  return out;
}

std::string MpRoomV2Session::post_local_names_notice() {
  const std::string line = format_names_line();
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    append_irc_notice_locked(line);
  }
  signal_wake();
  return line;
}

void MpRoomV2Session::post_local_topic_notice() {
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (topic_.empty()) {
      append_irc_notice_locked("* No topic is set.");
    } else {
      append_irc_notice_locked("* Topic: " + topic_);
    }
  }
  signal_wake();
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

    if (e2ee_mode_ == 1U) {
      if (!mls_engine_ || !mls_group_id_.has_value()) {
        return fail<std::string>(ErrorCode::invalid_identity,
                                 MpRoomV2Error::mls_unavailable);
      }
      MlsInnerMsgId inner_id{};
      if (const auto rnd = mp::random_bytes(inner_id); !rnd.has_value()) {
        return fail<std::string>(ErrorCode::external_unknown,
                                 MpRoomV2Error::mls_encrypt_failed);
      }
      auto inner_bytes = encode_inner_routed_payload(target.value, body);
      auto enc =
          mls_engine_->encrypt_app(*mls_group_id_, inner_id, MpMlsMsgClass::agent_card,
                                   inner_bytes, wall_now_ms() / 1000U);
      if (!enc.has_value()) {
        refresh_mls_status_locked();
        const auto mls_err = mp_mls_error_of(enc.error());
        if (mls_err == MpMlsError::self_clone_detected ||
            mls_err == MpMlsError::pending_removal ||
            mls_err == MpMlsError::frame_cap) {
          return fail<std::string>(ErrorCode::conflict,
                                   MpRoomV2Error::mls_send_blocked);
        }
        return fail<std::string>(enc.error().code, MpRoomV2Error::mls_encrypt_failed);
      }

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
      optimistic.body_encoding = "opaque_b64";
      optimistic.body = body;
      optimistic.rendered_body = render_agent_card_body(body);
      optimistic.parsed_agent_card = std::move(parsed_card);
      optimistic.delivered = false;
      optimistic.local_self = true;
      upsert_message_locked(std::move(optimistic));

      OutboundMessage ob{};
      ob.client_msg_id = msg_id;
      ob.kind = "e2ee_app";
      ob.target = "*";
      ob.body_encoding = "opaque_b64";
      ob.body = room_b64_encode(enc.value().wire_bytes);
      ob.sent_on_current_socket = false;
      ob.is_e2ee = true;
      ob.inner_msg_id = inner_id;
      ob.mls_msg_class = MpMlsMsgClass::agent_card;
      ob.plaintext_inner = std::move(inner_bytes);
      ob.sent_epoch = enc.value().mls_epoch;
      outbox_.push_back(std::move(ob));
      refresh_mls_status_locked();
    } else {
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

      OutboundMessage ob{};
      ob.client_msg_id = msg_id;
      ob.kind = "agent_card";
      ob.target = std::move(target.value);
      ob.body_encoding = "utf8";
      ob.body = std::move(body);
      ob.sent_on_current_socket = false;
      outbox_.push_back(std::move(ob));
    }
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
    if (e2ee_mode_ == 1U) {
      if (!mls_engine_ || !mls_group_id_.has_value()) {
        return fail_void(ErrorCode::invalid_identity, MpRoomV2Error::mls_unavailable);
      }
      MlsInnerMsgId inner_id{};
      if (const auto rnd = mp::random_bytes(inner_id); !rnd.has_value()) {
        return fail_void(ErrorCode::external_unknown,
                         MpRoomV2Error::mls_encrypt_failed);
      }
      auto inner_bytes = encode_inner_ephemeral_status(status);
      auto enc = mls_engine_->encrypt_app(*mls_group_id_, inner_id,
                                          MpMlsMsgClass::ephemeral_status, inner_bytes,
                                          wall_now_ms() / 1000U);
      if (!enc.has_value()) {
        refresh_mls_status_locked();
        const auto mls_err = mp_mls_error_of(enc.error());
        if (mls_err == MpMlsError::self_clone_detected ||
            mls_err == MpMlsError::pending_removal ||
            mls_err == MpMlsError::frame_cap) {
          return fail_void(ErrorCode::conflict, MpRoomV2Error::mls_send_blocked);
        }
        return fail_void(enc.error().code, MpRoomV2Error::mls_encrypt_failed);
      }
      // Replace any unsent queued ephemeral status to bound outbox size.
      std::erase_if(outbox_, [](const OutboundMessage &pending) {
        return !pending.sent_on_current_socket && pending.kind == "e2ee_ephemeral";
      });
      ++local_msg_counter_;
      OutboundMessage ob{};
      ob.client_msg_id = generate_client_msg_id(local_msg_counter_);
      ob.kind = "e2ee_ephemeral";
      ob.target = "*";
      ob.body_encoding = "opaque_b64";
      ob.body = room_b64_encode(enc.value().wire_bytes);
      ob.sent_on_current_socket = false;
      ob.is_e2ee = true;
      ob.inner_msg_id = inner_id;
      ob.mls_msg_class = MpMlsMsgClass::ephemeral_status;
      ob.plaintext_inner = std::move(inner_bytes);
      ob.sent_epoch = enc.value().mls_epoch;
      outbox_.push_back(std::move(ob));
      refresh_mls_status_locked();
    } else {
      pending_status_ = std::move(status);
    }
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
  snap.e2ee_mode = e2ee_mode_;
  if (e2ee_mode_ == 1U && mls_engine_ && mls_group_id_.has_value()) {
    if (const auto st = mls_engine_->room_status(*mls_group_id_, wall_now_ms() / 1000U);
        st.has_value()) {
      mls_status_ = st.value();
    }
  }
  snap.mls_status = mls_status_;
  snap.topic = topic_;
  snap.local_nick = local_nick_;
  snap.mls_joining = mls_joining_;
  return snap;
}

PartySnapshot MpRoomV2Session::to_party_snapshot() const {
  std::lock_guard<std::mutex> lock(state_mu_);
  PartySnapshot snap{};
  snap.room_scope = !room_code_.empty() ? ("room/" + room_code_)
                                        : ("party #" + party_id_.to_decimal());
  snap.room_topic = topic_;
  snap.mode_override = PartyModeOverride::auto_detect;
  snap.compact_room_presentation = true;

  auto state_priority = [](PartyParticipantState st) noexcept -> int {
    switch (st) {
    case PartyParticipantState::working:
      return 3;
    case PartyParticipantState::online:
      return 2;
    case PartyParticipantState::idle:
      return 1;
    case PartyParticipantState::offline:
      return 0;
    }
    return 0;
  };
  auto lower_ascii = [](std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
      out.push_back((ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch);
    }
    return out;
  };

  struct MergedMember {
    std::string key;
    std::string handle;
    std::string nick;
    bool is_guest = false;
    bool is_self = false;
    PartyParticipantState state = PartyParticipantState::offline;
    std::vector<std::string> clients;
    std::string agent_name;
  };
  std::vector<MergedMember> merged;
  merged.reserve(members_.size());
  for (const auto &m : members_) {
    const std::string key =
        (!m.is_guest && m.account_id.has_value())
            ? ((!m.is_browser && m.device_id.has_value())
                   ? ("dev:" + std::to_string(m.account_id->value()) + ":" +
                      std::to_string(m.device_id->value()))
                   : ("acct:" + std::to_string(m.account_id->value())))
            : ("guest:" + lower_ascii(strip_at(m.handle)));
    auto it = std::find_if(merged.begin(), merged.end(),
                           [&](const MergedMember &e) { return e.key == key; });
    const PartyParticipantState st = map_member_state(m);
    const std::string clean_client = party_chat_sanitize(m.client, 24U);
    const std::string clean_agent = party_chat_sanitize(m.agent_name, 32U);
    auto add_client = [&](MergedMember &entry) {
      if (!clean_client.empty() && std::find(entry.clients.begin(), entry.clients.end(),
                                             clean_client) == entry.clients.end()) {
        if (clean_client != "web" && !entry.clients.empty() &&
            entry.clients.front() == "web") {
          entry.clients.insert(entry.clients.begin(), clean_client);
        } else {
          entry.clients.push_back(clean_client);
        }
      }
      if (!clean_agent.empty() && lower_ascii(clean_agent) != "blackbird" &&
          lower_ascii(clean_agent) != lower_ascii(clean_client) &&
          entry.agent_name.empty()) {
        entry.agent_name = clean_agent;
      }
      if (entry.nick.empty() && !m.nick.empty()) {
        entry.nick = m.nick;
      }
    };
    if (it == merged.end()) {
      MergedMember entry{};
      entry.key = key;
      entry.handle = party_chat_sanitize(strip_at(m.handle), 64U);
      entry.nick = m.nick;
      entry.is_guest = m.is_guest;
      entry.is_self = m.is_self;
      entry.state = st;
      add_client(entry);
      merged.push_back(std::move(entry));
    } else {
      it->is_self = it->is_self || m.is_self;
      it->is_guest = it->is_guest && m.is_guest;
      if (state_priority(st) > state_priority(it->state)) {
        it->state = st;
      }
      add_client(*it);
    }
  }

  snap.mode =
      merged.size() > 1U ? PartyMode::multi_operator : PartyMode::single_operator;
  snap.participants.reserve(merged.size());
  for (const auto &entry : merged) {
    PartyParticipant p{};
    p.id = entry.handle;
    p.nick = entry.nick;
    std::string clients_joined;
    for (std::size_t i = 0; i < entry.clients.size(); ++i) {
      if (i > 0)
        clients_joined += " + ";
      clients_joined += entry.clients[i];
    }
    std::string disp =
        entry.is_guest
            ? (entry.handle + " [guest]")
            : format_irc_display_name(IrcDisplayNameInput{entry.nick, entry.handle});
    if (!clients_joined.empty() && !entry.agent_name.empty()) {
      disp += " (" + clients_joined + " · " + entry.agent_name + ")";
    } else if (!clients_joined.empty()) {
      disp += " (" + clients_joined + ")";
    } else if (!entry.agent_name.empty()) {
      disp += " (" + entry.agent_name + ")";
    }
    p.display_name = std::move(disp);
    p.role = PartyMemberRole::operator_human;
    p.host = std::move(clients_joined);
    p.model = entry.agent_name;
    p.state = entry.state;
    p.local_self = entry.is_self;
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
    pm.sender_nick = m.sender_nick;
    pm.sender_role = m.kind == "agent_card" ? PartyMemberRole::platoon_leader
                                            : PartyMemberRole::operator_human;
    pm.sender_host = m.sender_client;
    pm.sender_model = m.kind == "agent_card" ? m.sender_agent_name : std::string{};
    pm.verified_peer = !m.sender_is_guest && !m.sender_is_browser;
    pm.target = m.target.empty() ? std::string{"@all"} : m.target;
    pm.kind = map_message_kind(m.kind);
    std::string body_out = m.rendered_body;
    if (m.local_self && (m.kind == "chat" || m.kind == "irc_action")) {
      body_out += m.delivered ? " ✓" : " …";
    }
    pm.body = std::move(body_out);
    pm.untrusted_remote = (m.sender_is_guest || m.sender_is_browser) && !m.local_self;
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
  if (e2ee_mode_ == 1U) {
    std::optional<MpMlsRoomStatus> st = mls_status_;
    if (mls_engine_ && mls_group_id_.has_value()) {
      if (const auto live_st =
              mls_engine_->room_status(*mls_group_id_, wall_now_ms() / 1000U);
          live_st.has_value()) {
        st = live_st.value();
      }
    }
    if (st.has_value()) {
      PartyMlsStatus pms{};
      pms.mls_epoch = st->mls_epoch;
      pms.trust_tier = static_cast<std::uint32_t>(st->trust_tier);
      pms.has_declared_agent = st->has_declared_agent;
      pms.has_pending_removals = st->has_pending_removals;
      pms.clone_detected = st->clone_detected;
      pms.epoch_authenticator = st->epoch_authenticator_code;
      snap.mls_status = std::move(pms);
    }
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

void MpRoomV2Session::append_irc_notice_locked(const std::string &text) {
  const std::string clean = party_chat_sanitize(text, 512U);
  if (clean.empty()) {
    return;
  }
  ++local_msg_counter_;
  MpRoomV2Message notice{};
  notice.seq = 0U;
  notice.ts_ms = wall_now_ms();
  notice.client_msg_id = "irc-" + std::to_string(local_msg_counter_);
  notice.sender_handle = "system";
  notice.target = "@all";
  notice.kind = "irc_notice";
  notice.body_encoding = "utf8";
  notice.body = clean;
  notice.rendered_body = clean;
  notice.delivered = true;
  notice.local_self = false;
  upsert_message_locked(std::move(notice));
}

std::string
MpRoomV2Session::lookup_member_nick_locked(std::optional<mp::AccountId> acct_id,
                                           std::optional<mp::DeviceId> dev_id,
                                           std::string_view handle) const {
  if (dev_id.has_value() && local_device_id_.has_value() &&
      *dev_id == *local_device_id_ && !local_nick_.empty()) {
    return local_nick_;
  }
  if (acct_id.has_value() && dev_id.has_value()) {
    const std::string k = "dev:" + std::to_string(acct_id->value()) + ":" +
                          std::to_string(dev_id->value());
    for (const auto &[ek, ev] : member_nicks_) {
      if (ek == k) {
        return ev;
      }
    }
  }
  if (acct_id.has_value()) {
    const std::string k = "acct:" + std::to_string(acct_id->value());
    for (const auto &[ek, ev] : member_nicks_) {
      if (ek == k) {
        return ev;
      }
    }
  }
  if (!handle.empty()) {
    std::string low;
    const std::string stripped = strip_at(handle);
    low.reserve(stripped.size());
    for (char ch : stripped) {
      low.push_back(ascii_lower(ch));
    }
    const std::string k = "handle:" + low;
    for (const auto &[ek, ev] : member_nicks_) {
      if (ek == k) {
        return ev;
      }
    }
  }
  return {};
}

void MpRoomV2Session::set_member_nick_locked(const MemberNickUpdate &update) {
  auto put_key = [&](std::string key) {
    for (auto &[ek, ev] : member_nicks_) {
      if (ek == key) {
        ev = std::string{update.nick};
        return;
      }
    }
    if (member_nicks_.size() < 256U) {
      member_nicks_.emplace_back(std::move(key), std::string{update.nick});
    }
  };
  if (update.acct_id.has_value() && update.dev_id.has_value()) {
    put_key("dev:" + std::to_string(update.acct_id->value()) + ":" +
            std::to_string(update.dev_id->value()));
  } else if (update.acct_id.has_value()) {
    put_key("acct:" + std::to_string(update.acct_id->value()));
  }
  if (!update.handle.empty() && !update.dev_id.has_value()) {
    std::string low;
    const std::string stripped = strip_at(update.handle);
    low.reserve(stripped.size());
    for (char ch : stripped) {
      low.push_back(ascii_lower(ch));
    }
    put_key("handle:" + low);
  }
  for (auto &m : members_) {
    const bool dev_match = update.dev_id.has_value() && m.device_id.has_value() &&
                           *m.device_id == *update.dev_id;
    const bool acct_match = !update.dev_id.has_value() && update.acct_id.has_value() &&
                            m.account_id.has_value() &&
                            *m.account_id == *update.acct_id &&
                            !m.device_id.has_value();
    const bool self_match = update.dev_id.has_value() && local_device_id_.has_value() &&
                            *update.dev_id == *local_device_id_ && m.is_self;
    if (dev_match || acct_match || self_match) {
      m.nick = std::string{update.nick};
    }
  }
}

void MpRoomV2Session::apply_members_locked(const std::vector<MpRoomV2Member> &members,
                                           bool emit_irc_notices) {
  const std::vector<MpRoomV2Member> prev_members = members_;
  members_ = members;
  bool has_self = false;
  for (auto &m : members_) {
    m.is_browser = m.is_browser || mp_room_v2_is_browser_client(m.client);
    const bool same_acct = !m.is_guest && !m.is_browser &&
                           local_account_id_.has_value() && m.account_id.has_value() &&
                           *m.account_id == *local_account_id_;
    const bool is_sibling_dev = same_acct && m.device_id.has_value() &&
                                local_device_id_.has_value() &&
                                *m.device_id != *local_device_id_;
    if (same_acct && !is_sibling_dev) {
      m.is_self = true;
      has_self = true;
      if (!m.device_id.has_value()) {
        m.device_id = local_device_id_;
      }
      if (!local_nick_.empty()) {
        m.nick = local_nick_;
      }
    } else {
      m.is_self = false;
      if (m.nick.empty()) {
        m.nick = lookup_member_nick_locked(m.account_id, m.device_id, m.handle);
      }
      // Latch remote taint immediately for ANY multi-account party (including
      // personal parties with >1 account) or ANY browser participant (even
      // matching the local operator's own account/@handle). Taint is monotonic
      // and NEVER cleared if the peer or browser participant later leaves.
      if (!same_acct || m.is_browser || m.is_guest) {
        const auto prov = make_mp2_peer_provenance(m.account_id, m.is_guest,
                                                   m.is_browser, brakes_gate_.policy());
        (void)brakes_gate_.ingest_peer(prov);
      }
    }
  }
  if (!has_self && local_account_id_.has_value()) {
    MpRoomV2Member self{};
    self.account_id = *local_account_id_;
    self.device_id = local_device_id_;
    self.is_guest = false;
    self.is_browser = false;
    self.handle = local_handle_;
    self.nick = local_nick_;
    self.client = client_name_;
    self.agent_name = agent_name_;
    self.agent_state = "idle";
    self.status = "live";
    self.is_self = true;
    members_.insert(members_.begin(), std::move(self));
  }

  if (emit_irc_notices) {
    auto is_online = [](const MpRoomV2Member &m) noexcept {
      return m.status != "offline" && m.status != "away";
    };
    auto find_by_key = [](const std::vector<MpRoomV2Member> &list,
                          const std::string &key) -> const MpRoomV2Member * {
      for (const auto &item : list) {
        if (member_identity_key(item) == key) {
          return &item;
        }
      }
      return nullptr;
    };
    for (const auto &cur : members_) {
      if (cur.is_self || !is_online(cur)) {
        continue;
      }
      const std::string key = member_identity_key(cur);
      const auto *prev = find_by_key(prev_members, key);
      if (prev == nullptr || !is_online(*prev)) {
        append_irc_notice_locked(format_irc_joinline(cur));
      }
    }
    for (const auto &prev : prev_members) {
      if (prev.is_self || !is_online(prev)) {
        continue;
      }
      const std::string key = member_identity_key(prev);
      const auto *cur = find_by_key(members_, key);
      if (cur == nullptr || !is_online(*cur)) {
        append_irc_notice_locked(format_irc_partline(prev));
      }
    }
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
    if (e2ee_mode_ == 1U && (!mls_group_id_.has_value() || mls_joining_)) {
      status_summary_ = "◐ Joining E2EE group…";
      return;
    }
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
      status_summary_ = "● Live — party #" + party_id_.to_decimal();
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
  const std::uint64_t server_e2ee =
      json_u64_or_decimal(obj, "e2ee_mode")
          .value_or(json_opt_bool(obj, "e2ee_mode") ? 1U : 0U);
  if (server_e2ee == 1U) {
    // Always fail closed if no live MpMlsEngine is attached — never downgrade to
    // plaintext!
    if (!mls_engine_ || !mls_engine_->valid()) {
      state_ = MpRoomV2State::disconnected;
      push_notice_locked("Refused E2EE room without active MLS engine (fail-closed).");
      rebuild_status_summary_locked();
      action.force_disconnect = true;
      return;
    }
    e2ee_mode_ = 1U;
    if (const auto ds_b64 = json_opt_string(obj, "party_ds_pubkey_b64");
        ds_b64.has_value() && !ds_b64->empty()) {
      if (const auto ds_bytes = room_b64_decode(*ds_b64);
          ds_bytes.has_value() && ds_bytes->size() == 32U) {
        mp::Ed25519PubKey pk{};
        std::memcpy(pk.data(), ds_bytes->data(), 32U);
        party_ds_pubkey_ = pk;
      }
    }
    if (const auto gid_b64 = json_opt_string(obj, "group_id_b64");
        gid_b64.has_value() && !gid_b64->empty()) {
      if (const auto gid_bytes = room_b64_decode(*gid_b64);
          gid_bytes.has_value() && gid_bytes->size() == kMlsGroupIdBytes) {
        MlsGroupId gid{};
        std::memcpy(gid.data(), gid_bytes->data(), kMlsGroupIdBytes);
        server_mls_group_id_ = gid;
      }
    }

    if (!mls_group_id_.has_value()) {
      if (server_mls_group_id_.has_value() &&
          mls_engine_->room_status(*server_mls_group_id_).has_value()) {
        mls_group_id_ = *server_mls_group_id_;
        mls_joining_ = false;
      } else if (!server_mls_group_id_.has_value() && party_ds_pubkey_.has_value()) {
        // Group not yet bootstrapped on server — creator bootstraps seamlessly!
        mls_joining_ = true;
        action.need_mls_bootstrap = true;
      } else {
        // Existing E2EE group — hold sends fail-closed & run KP/Welcome join pump
        // WITHOUT disconnecting the WebSocket!
        mls_joining_ = true;
        action.need_mls_join_pump = true;
      }
    } else {
      mls_joining_ = false;
    }

    if (mls_group_id_.has_value()) {
      refresh_mls_status_locked();
      const std::uint64_t server_mls_epoch =
          json_u64_or_decimal(obj, "mls_epoch").value_or(0U);
      const std::uint64_t local_epoch =
          mls_status_.has_value() ? mls_status_->mls_epoch : 0U;
      if (server_mls_epoch > local_epoch) {
        action.need_mls_catchup = true;
        action.catchup_from_epoch = local_epoch + 1U;
      }
    }
  }
  if (const auto rc = json_opt_string(obj, "room_code");
      rc.has_value() && !rc->empty()) {
    room_code_ = party_chat_sanitize(*rc, 32U);
  }
  if (const auto rn = json_opt_string(obj, "name"); rn.has_value() && !rn->empty()) {
    room_name_ = party_chat_sanitize(*rn, 128U);
  }
  if (e2ee_mode_ == 0U) {
    if (const auto ht = json_opt_string(obj, "topic"); ht.has_value() && !ht->empty()) {
      const std::string clean_topic = scrub_agent_card_text(*ht, 160U);
      if (!clean_topic.empty() && !mp_room_v2_contains_secret_token(clean_topic)) {
        topic_ = clean_topic;
      }
    }
  }
  if (const Value *self_field = obj.find("self");
      self_field != nullptr &&
      std::holds_alternative<Value::Object>(self_field->value())) {
    if (const auto sh = json_opt_string(*self_field, "handle");
        sh.has_value() && !sh->empty()) {
      local_handle_ = party_chat_sanitize(strip_at(*sh), 64U);
    }
  }

  const auto parsed_members =
      parse_members_array(obj, local_account_id_, local_device_id_);
  if (!parsed_members.empty()) {
    apply_members_locked(parsed_members, false);
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
    push_notice_locked("Reconnected to party" +
                       (!room_code_.empty() ? (" (" + room_code_ + ")")
                                            : (" (#" + party_id_.to_decimal() + ")")));
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

  std::optional<std::uint64_t> outer_sender_device_id;
  if (const Value *sender_field = obj.find("sender");
      sender_field != nullptr &&
      std::holds_alternative<Value::Object>(sender_field->value())) {
    if (const auto acct_raw = json_u64_or_decimal(*sender_field, "account_id");
        acct_raw.has_value() && *acct_raw != 0U) {
      if (const auto aid = mp::AccountId::create(*acct_raw); aid.has_value()) {
        msg.sender_account_id = aid.value();
      }
    }
    outer_sender_device_id = json_u64_or_decimal(*sender_field, "device_id");
    if (outer_sender_device_id.has_value() && *outer_sender_device_id != 0U) {
      if (const auto did = mp::DeviceId::create(*outer_sender_device_id);
          did.has_value()) {
        msg.sender_device_id = did.value();
      }
    }
    msg.sender_handle = party_chat_sanitize(
        strip_at(json_opt_string(*sender_field, "handle").value_or("")), 64U);
    msg.sender_client =
        party_chat_sanitize(json_opt_string(*sender_field, "client").value_or(""), 32U);
    msg.sender_agent_name = party_chat_sanitize(
        json_opt_string(*sender_field, "agent_name").value_or(""), 48U);
    msg.sender_is_guest =
        !msg.sender_account_id.has_value() || json_opt_bool(*sender_field, "is_guest");
    msg.sender_is_browser = json_opt_bool(*sender_field, "is_browser") ||
                            mp_room_v2_is_browser_client(msg.sender_client);
  } else {
    msg.sender_is_guest = true;
  }

  auto matched_outbox_it = outbox_.end();
  if (!cmsg_id.empty()) {
    matched_outbox_it = std::find_if(outbox_.begin(), outbox_.end(),
                                     [&](const OutboundMessage &pending) {
                                       return pending.client_msg_id == cmsg_id;
                                     });
  }
  const bool matched_outbox = (matched_outbox_it != outbox_.end());

  bool decrypted_is_historical_catchup = is_history;
  bool decrypted_from_mls = false;

  if (e2ee_mode_ == 1U) {
    if (msg.kind == "system") {
      msg.rendered_body = party_chat_sanitize(msg.body, 2048U);
      upsert_message_locked(std::move(msg));
      rebuild_status_summary_locked();
      return;
    }
    // Strict downgrade protection: NEVER render or trigger on non-opaque_b64 member
    // frames inside an e2ee_mode == 1 room!
    if (msg.body_encoding != "opaque_b64") {
      push_notice_locked("Rejected unencrypted member frame in E2EE room.");
      return;
    }
    if (!mls_engine_ || !mls_group_id_.has_value()) {
      push_notice_locked("MLS engine unavailable; dropped encrypted frame.");
      return;
    }

    // Own echoed outbox frame: OpenMLS cannot decrypt its own sender ratchet.
    // Verify exact ciphertext bytes match what we sent so a hostile server cannot
    // substitute content under our client_msg_id!
    if (matched_outbox && matched_outbox_it->is_e2ee) {
      if (matched_outbox_it->body != body) {
        push_notice_locked("Rejected tampered self-echo ciphertext in E2EE room.");
        return;
      }
      const bool is_ephemeral_echo = (matched_outbox_it->kind == "e2ee_ephemeral");
      outbox_.erase(matched_outbox_it);
      if (!is_ephemeral_echo) {
        if (seq > 0U) {
          remember_seen_seq_locked(seq);
          if (seq > latest_seq_) {
            latest_seq_ = seq;
            latest_seq_atomic_.store(latest_seq_, std::memory_order_release);
          }
        }
        for (auto &existing : messages_) {
          if (existing.client_msg_id == cmsg_id) {
            existing.delivered = true;
            if (seq > 0U) {
              existing.seq = seq;
            }
            if (ts_ms > 0U) {
              existing.ts_ms = ts_ms;
            }
            break;
          }
        }
      }
      rebuild_status_summary_locked();
      return;
    }

    const auto wire_opt = room_b64_decode(body);
    if (!wire_opt.has_value()) {
      push_notice_locked("Rejected malformed base64 E2EE frame.");
      return;
    }
    const auto dec_res =
        mls_engine_->decrypt_app(*mls_group_id_, *wire_opt, is_history);
    if (!dec_res.has_value()) {
      const auto mls_err = mp_mls_error_of(dec_res.error());
      if (mls_err == MpMlsError::duplicate_msg) {
        return;
      }
      if (mls_err == MpMlsError::self_clone_detected) {
        refresh_mls_status_locked();
        push_notice_locked(
            "SECURITY ALERT: Cloned device key suspected — outbound sends frozen.");
        return;
      }
      push_notice_locked("Failed to verify/decrypt E2EE frame (" +
                         std::string{mp_mls_error_name(mls_err)} + ").");
      return;
    }

    const auto &dec = dec_res.value();
    // Assert authenticated MLS sender leaf matches outer server metadata when present!
    if (msg.sender_account_id.has_value() &&
        msg.sender_account_id->value() != dec.auth_account_id) {
      push_notice_locked(
          "Rejected E2EE frame: outer account_id disagrees with MLS leaf.");
      return;
    }
    if (outer_sender_device_id.has_value() && *outer_sender_device_id != 0U &&
        *outer_sender_device_id != dec.auth_device_id) {
      push_notice_locked(
          "Rejected E2EE frame: outer device_id disagrees with MLS leaf.");
      return;
    }

    const auto auth_acct = mp::AccountId::create(dec.auth_account_id);
    if (!auth_acct.has_value()) {
      return;
    }
    // Derive sender identity & browser taint strictly from authenticated MLS leaf!
    msg.sender_account_id = auth_acct.value();
    if (const auto auth_dev = mp::DeviceId::create(dec.auth_device_id);
        auth_dev.has_value()) {
      msg.sender_device_id = auth_dev.value();
    }
    msg.sender_is_guest = false;
    msg.sender_is_browser = (dec.sender_client_class == 3U);
    if (msg.sender_is_browser && msg.sender_client.empty()) {
      msg.sender_client = "browser";
    }
    msg.local_self = false;
    decrypted_is_historical_catchup = is_history || dec.is_historical_catchup;
    decrypted_from_mls = true;

    // Pass authenticated sender_client_class == 3 & auth_account_id into BrakesGate!
    const auto ev_prov = make_mp2_peer_provenance(
        msg.sender_account_id, false, msg.sender_is_browser, brakes_gate_.policy());
    (void)brakes_gate_.ingest_peer(ev_prov);

    if (dec.msg_class == MpMlsMsgClass::ephemeral_status) {
      if (const auto st = decode_inner_ephemeral_status(dec.plaintext);
          st.has_value()) {
        for (auto &m : members_) {
          if (m.account_id.has_value() && *m.account_id == auth_acct.value() &&
              m.is_browser == msg.sender_is_browser) {
            m.agent_name = party_chat_sanitize(st->agent_name, 48U);
            m.agent_state = party_chat_sanitize(st->agent_state, 32U);
            m.agent_summary = party_chat_sanitize(st->agent_summary, 128U);
            break;
          }
        }
        rebuild_status_summary_locked();
      }
      return;
    }
    if (dec.msg_class == MpMlsMsgClass::invite_control) {
      (void)mls_engine_->register_invite_record(*mls_group_id_, dec.plaintext);
      return;
    }

    if (dec.msg_class == MpMlsMsgClass::agent_card) {
      std::string inner_target;
      std::string inner_body;
      decode_inner_routed_payload(dec.plaintext, inner_target, inner_body);
      msg.target = party_chat_sanitize(inner_target, kMaxRoomTargetBytes);
      msg.body = std::move(inner_body);
      msg.kind = "agent_card";
      msg.parsed_agent_card = parse_mp_room_v2_agent_card(msg.body);
      msg.rendered_body = render_agent_card_body(msg.body);
      msg.sender_nick = lookup_member_nick_locked(
          msg.sender_account_id, msg.sender_device_id, msg.sender_handle);
    } else {
      const auto decoded = decode_inner_chat_or_irc(dec.plaintext);
      if (decoded.kind == InnerIrcKind::irc_nick) {
        if (const auto valid_nick = validate_irc_nick(decoded.body);
            valid_nick.has_value()) {
          set_member_nick_locked(
              MemberNickUpdate{msg.sender_account_id, msg.sender_device_id,
                               msg.sender_handle, valid_nick.value()});
          const std::string handle_badge = msg.sender_handle.empty()
                                               ? std::string{"@peer"}
                                               : ("@" + strip_at(msg.sender_handle));
          msg.kind = "irc_notice";
          msg.target = "@all";
          msg.body = "* " + handle_badge + " is now known as " + valid_nick.value();
          msg.rendered_body = msg.body;
          upsert_message_locked(std::move(msg));
          refresh_mls_status_locked();
          rebuild_status_summary_locked();
        }
        return;
      }
      if (decoded.kind == InnerIrcKind::irc_topic) {
        const std::string clean_topic = scrub_agent_card_text(decoded.body, 160U);
        if (!clean_topic.empty() && !mp_room_v2_contains_secret_token(clean_topic)) {
          topic_ = clean_topic;
          const std::string peer_nick = lookup_member_nick_locked(
              msg.sender_account_id, msg.sender_device_id, msg.sender_handle);
          const std::string actor = format_irc_display_name(
              IrcDisplayNameInput{peer_nick, msg.sender_handle});
          msg.kind = "irc_notice";
          msg.target = "@all";
          msg.body = "* " + actor + " changed the topic to: " + clean_topic;
          msg.rendered_body = msg.body;
          upsert_message_locked(std::move(msg));
          refresh_mls_status_locked();
          rebuild_status_summary_locked();
        }
        return;
      }
      msg.target = party_chat_sanitize(decoded.target, kMaxRoomTargetBytes);
      msg.body = decoded.body;
      msg.sender_nick = lookup_member_nick_locked(
          msg.sender_account_id, msg.sender_device_id, msg.sender_handle);
      if (decoded.kind == InnerIrcKind::irc_action) {
        msg.kind = "irc_action";
        msg.rendered_body = party_chat_sanitize(msg.body, 2048U);
      } else {
        msg.kind = "chat";
        msg.rendered_body = party_chat_sanitize(msg.body, 2048U);
      }
    }
    refresh_mls_status_locked();
  } else {
    // Browser-authored messages (sender.is_browser == true or sender.client == "web"),
    // guest messages, and sibling devices (same account_id, distinct device_id) are
    // NEVER collapsed into local_self!
    const bool is_sibling_device = outer_sender_device_id.has_value() &&
                                   local_device_id_.has_value() &&
                                   *outer_sender_device_id != local_device_id_->value();
    msg.local_self = !msg.sender_is_browser && !msg.sender_is_guest &&
                     !is_sibling_device &&
                     (matched_outbox || (local_account_id_.has_value() &&
                                         msg.sender_account_id.has_value() &&
                                         *msg.sender_account_id == *local_account_id_));

    if (!msg.local_self) {
      const auto ev_prov =
          make_mp2_peer_provenance(msg.sender_account_id, msg.sender_is_guest,
                                   msg.sender_is_browser, brakes_gate_.policy());
      (void)brakes_gate_.ingest_peer(ev_prov);
    }

    if (msg.kind == "chat" && msg.body_encoding == "utf8") {
      if (msg.body.starts_with("/nick ")) {
        const std::string_view raw_nick =
            trim_ascii_ws(std::string_view{msg.body}.substr(6U));
        if (matched_outbox) {
          outbox_.erase(matched_outbox_it);
          if (seq > latest_seq_) {
            latest_seq_ = seq;
            latest_seq_atomic_.store(latest_seq_, std::memory_order_release);
          }
          remember_seen_seq_locked(seq);
          rebuild_status_summary_locked();
          return;
        }
        if (const auto valid_nick = validate_irc_nick(raw_nick);
            valid_nick.has_value()) {
          set_member_nick_locked(
              MemberNickUpdate{msg.sender_account_id, msg.sender_device_id,
                               msg.sender_handle, valid_nick.value()});
          const std::string handle_badge = msg.sender_handle.empty()
                                               ? std::string{"@peer"}
                                               : ("@" + strip_at(msg.sender_handle));
          msg.kind = "irc_notice";
          msg.body = "* " + handle_badge + " is now known as " + valid_nick.value();
          msg.rendered_body = msg.body;
          upsert_message_locked(std::move(msg));
          rebuild_status_summary_locked();
          return;
        }
      } else if (msg.body.starts_with("/topic ")) {
        const std::string_view raw_topic =
            trim_ascii_ws(std::string_view{msg.body}.substr(7U));
        if (matched_outbox) {
          outbox_.erase(matched_outbox_it);
          if (seq > latest_seq_) {
            latest_seq_ = seq;
            latest_seq_atomic_.store(latest_seq_, std::memory_order_release);
          }
          remember_seen_seq_locked(seq);
          rebuild_status_summary_locked();
          return;
        }
        const std::string clean_topic = scrub_agent_card_text(raw_topic, 160U);
        if (!clean_topic.empty() && !mp_room_v2_contains_secret_token(clean_topic)) {
          topic_ = clean_topic;
          const std::string peer_nick = lookup_member_nick_locked(
              msg.sender_account_id, msg.sender_device_id, msg.sender_handle);
          const std::string actor = format_irc_display_name(
              IrcDisplayNameInput{peer_nick, msg.sender_handle});
          msg.kind = "irc_notice";
          msg.body = "* " + actor + " changed the topic to: " + clean_topic;
          msg.rendered_body = msg.body;
          upsert_message_locked(std::move(msg));
          rebuild_status_summary_locked();
          return;
        }
      } else if (msg.body.starts_with("/me ")) {
        msg.kind = "irc_action";
        msg.body = std::string{trim_ascii_ws(std::string_view{msg.body}.substr(4U))};
        msg.rendered_body = party_chat_sanitize(msg.body, 2048U);
      } else {
        msg.rendered_body = party_chat_sanitize(msg.body, 2048U);
      }
      msg.sender_nick = lookup_member_nick_locked(
          msg.sender_account_id, msg.sender_device_id, msg.sender_handle);
    } else if (msg.kind == "agent_card" && msg.body_encoding == "utf8") {
      msg.parsed_agent_card = parse_mp_room_v2_agent_card(msg.body);
      msg.rendered_body = render_agent_card_body(msg.body);
      msg.sender_nick = lookup_member_nick_locked(
          msg.sender_account_id, msg.sender_device_id, msg.sender_handle);
    } else if (msg.body_encoding == "opaque_b64") {
      msg.rendered_body = "[encrypted message]";
    } else {
      msg.rendered_body = party_chat_sanitize(msg.body, 2048U);
    }
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
  // echoes, historical catch-up (`is_history` or `dec.is_historical_catchup`),
  // undecrypted opaque frames, or duplicates!
  bool mentions_self = false;
  std::string_view mention_payload;
  const bool eligible_body =
      (e2ee_mode_ == 1U) ? decrypted_from_mls : (msg.body_encoding == "utf8");
  if (!is_history && !decrypted_is_historical_catchup && !already_seen &&
      !msg.local_self && eligible_body) {
    if (msg.kind == "chat" || msg.kind == "irc_action") {
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
    const bool sender_is_guest = msg.sender_is_guest;
    const bool sender_is_browser = msg.sender_is_browser;
    const std::string room_scope = !room_code_.empty()
                                       ? ("room/" + room_code_)
                                       : ("party #" + party_id_.to_decimal());
    const std::string sender_handle =
        msg.sender_handle.empty() ? std::string{"peer"} : msg.sender_handle;

    brakes::PeerProvenance prov =
        make_mp2_peer_provenance(msg.sender_account_id, sender_is_guest,
                                 sender_is_browser, brakes_gate_.policy());

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
      pending.sender_is_browser = sender_is_browser;
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
  const auto parsed_members =
      parse_members_array(obj, local_account_id_, local_device_id_);
  apply_members_locked(parsed_members, connected_once_);
  rebuild_status_summary_locked();
}

void MpRoomV2Session::handle_irc_nick_frame_locked(const Value &obj) {
  if (e2ee_mode_ == 1U) {
    return;
  }
  const auto raw_nick = json_opt_string(obj, "nick");
  if (!raw_nick.has_value()) {
    return;
  }
  const auto valid_nick = validate_irc_nick(*raw_nick);
  if (!valid_nick.has_value()) {
    return;
  }
  const auto acct_id = json_optional_account_id(obj, "account_id");
  const auto dev_id = json_optional_device_id(obj, "device_id");
  const std::string handle =
      party_chat_sanitize(strip_at(json_opt_string(obj, "handle").value_or("")), 64U);
  if (dev_id.has_value() && local_device_id_.has_value() &&
      *dev_id == *local_device_id_) {
    return;
  }
  set_member_nick_locked(MemberNickUpdate{acct_id, dev_id, handle, valid_nick.value()});
  const std::string badge = handle.empty() ? std::string{"@peer"} : ("@" + handle);
  append_irc_notice_locked("* " + badge + " is now known as " + valid_nick.value());
}

void MpRoomV2Session::handle_irc_topic_frame_locked(const Value &obj) {
  if (e2ee_mode_ == 1U) {
    return;
  }
  const auto raw_topic = json_opt_string(obj, "topic");
  if (!raw_topic.has_value()) {
    return;
  }
  const std::string clean_topic = scrub_agent_card_text(*raw_topic, 160U);
  if (clean_topic.empty() || mp_room_v2_contains_secret_token(clean_topic)) {
    return;
  }
  const auto acct_id = json_optional_account_id(obj, "account_id");
  const auto dev_id = json_optional_device_id(obj, "device_id");
  const std::string handle =
      party_chat_sanitize(strip_at(json_opt_string(obj, "handle").value_or("")), 64U);
  if (dev_id.has_value() && local_device_id_.has_value() &&
      *dev_id == *local_device_id_) {
    return;
  }
  topic_ = clean_topic;
  const std::string nick = lookup_member_nick_locked(acct_id, dev_id, handle);
  const std::string actor = format_irc_display_name(IrcDisplayNameInput{nick, handle});
  append_irc_notice_locked("* " + actor + " changed the topic to: " + clean_topic);
}

void MpRoomV2Session::handle_error_locked(const Value &obj, FrameAction &action) {
  const std::string message =
      party_chat_sanitize(json_opt_string(obj, "message").value_or(""), 200U);
  const std::string code =
      party_chat_sanitize(json_opt_string(obj, "code").value_or("error"), 48U);
  const std::uint64_t retry_ms = json_u64_or_decimal(obj, "retry_ms").value_or(0U);
  if (code == "mls_epoch_stale" && e2ee_mode_ == 1U) {
    requeue_stale_e2ee_outbox_locked(action);
  } else if (code == "device_seq_rollback" && e2ee_mode_ == 1U && mls_engine_ &&
             mls_group_id_.has_value()) {
    (void)mls_engine_->mark_clone_detected(*mls_group_id_);
    refresh_mls_status_locked();
    push_notice_locked(
        "SECURITY ALERT: Server reported device_seq_rollback — outbound sends frozen.");
    return;
  } else if (retry_ms > 0U || code == "rate_limited") {
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

void MpRoomV2Session::refresh_mls_status_locked() {
  if (e2ee_mode_ == 1U && mls_engine_ && mls_group_id_.has_value()) {
    if (const auto st = mls_engine_->room_status(*mls_group_id_, wall_now_ms() / 1000U);
        st.has_value()) {
      mls_status_ = st.value();
    }
  }
}

void MpRoomV2Session::requeue_stale_e2ee_outbox_locked(FrameAction &action) {
  if (e2ee_mode_ != 1U || !mls_engine_ || !mls_group_id_.has_value()) {
    return;
  }
  const std::uint64_t now_s = wall_now_ms() / 1000U;
  const auto st = mls_engine_->room_status(*mls_group_id_, now_s);
  if (!st.has_value()) {
    return;
  }
  const std::uint64_t current_epoch = st.value().mls_epoch;
  bool any_requeued = false;
  for (auto &pending : outbox_) {
    if (!pending.is_e2ee) {
      continue;
    }
    if (pending.sent_epoch < current_epoch) {
      // Re-encrypt in the advanced epoch preserving the EXACT `inner_msg_id[16]`
      // (§7.2)!
      auto enc = mls_engine_->encrypt_app(*mls_group_id_, pending.inner_msg_id,
                                          pending.mls_msg_class,
                                          pending.plaintext_inner, now_s);
      if (enc.has_value()) {
        pending.body = room_b64_encode(enc.value().wire_bytes);
        pending.sent_epoch = enc.value().mls_epoch;
        pending.sent_on_current_socket = false;
        any_requeued = true;
      }
    } else {
      pending.sent_on_current_socket = false;
      any_requeued = true;
    }
  }
  refresh_mls_status_locked();
  if (any_requeued) {
    action.need_flush_outbox = true;
  }
}

void MpRoomV2Session::handle_mls_join_request_locked(const Value &obj,
                                                     FrameAction &action) {
  if (e2ee_mode_ != 1U || !mls_engine_ || !mls_group_id_.has_value()) {
    return;
  }
  const auto acct_id = json_u64_or_decimal(obj, "account_id");
  const auto dev_id = json_u64_or_decimal(obj, "device_id");
  if (!acct_id.has_value() || *acct_id == 0U || !dev_id.has_value() || *dev_id == 0U) {
    return;
  }
  // Ignore our own device's KeyPackage, but NEVER ignore a sibling device of our own
  // account (`account_id == local_account_id` with `device_id != local_device_id`)!
  if (local_device_id_.has_value() && *dev_id == local_device_id_->value()) {
    return;
  }
  auto kp_b64 = json_opt_string(obj, "kp_blob_b64");
  if (!kp_b64.has_value() || kp_b64->empty()) {
    kp_b64 = json_opt_string(obj, "kp_b64");
  }
  const auto kpref_b64 = json_opt_string(obj, "kp_ref_b64");
  if (!kp_b64.has_value() || kp_b64->empty() || !kpref_b64.has_value() ||
      kpref_b64->empty()) {
    return;
  }
  const auto kp_bytes = room_b64_decode(*kp_b64);
  const auto kpref_bytes = room_b64_decode(*kpref_b64);
  if (!kp_bytes.has_value() || kp_bytes->empty() || !kpref_bytes.has_value() ||
      kpref_bytes->size() != kMlsHashBytes) {
    return;
  }
  PendingJoinRequest req{};
  req.account_id = *acct_id;
  req.device_id = *dev_id;
  req.invite_id = json_u64_or_decimal(obj, "invite_id").value_or(0U);
  std::memcpy(req.kp_ref.data(), kpref_bytes->data(), kMlsHashBytes);
  req.kp_bytes = std::move(*kp_bytes);
  if (const auto jp_b64 = json_opt_string(obj, "join_proof_b64");
      jp_b64.has_value() && !jp_b64->empty()) {
    if (const auto jp_bytes = room_b64_decode(*jp_b64);
        jp_bytes.has_value() && jp_bytes->size() == kMlsHashBytes) {
      MlsHash32 jp{};
      std::memcpy(jp.data(), jp_bytes->data(), kMlsHashBytes);
      req.join_proof = jp;
    }
  }
  action.pending_join_requests.push_back(std::move(req));
}

void MpRoomV2Session::handle_mls_commit_tentative_locked(const Value &obj,
                                                         FrameAction &action) {
  if (e2ee_mode_ != 1U || !mls_engine_ || !mls_group_id_.has_value()) {
    return;
  }
  const Value *pf = obj.find("proposals_b64");
  if (pf == nullptr) {
    pf = obj.find("proposals");
  }
  if (pf != nullptr) {
    if (const auto *arr = std::get_if<Value::Array>(&pf->value())) {
      for (const auto &item : *arr) {
        if (const auto *ps = std::get_if<std::string>(&item.value())) {
          if (const auto pbytes = room_b64_decode(*ps); pbytes.has_value()) {
            (void)mls_engine_->apply_proposal(*mls_group_id_, *pbytes);
          }
        }
      }
    }
  }
  auto cb64 = json_opt_string(obj, "commit_blob_b64");
  if (!cb64.has_value() || cb64->empty()) {
    cb64 = json_opt_string(obj, "commit_b64");
  }
  if (!cb64.has_value() || cb64->empty()) {
    return;
  }
  const auto cbytes = room_b64_decode(*cb64);
  if (!cbytes.has_value()) {
    return;
  }
  const std::uint64_t parent_epoch =
      json_u64_or_decimal(obj, "parent_epoch")
          .value_or(mls_status_.has_value() ? mls_status_->mls_epoch : 0U);
  const std::uint64_t target_epoch =
      json_u64_or_decimal(obj, "target_epoch").value_or(parent_epoch + 1U);

  const auto ack_res = mls_engine_->stage_tentative_commit(*mls_group_id_, *cbytes);
  if (!ack_res.has_value()) {
    if (mp_mls_error_of(ack_res.error()) == MpMlsError::epoch_stale) {
      const std::uint64_t local_ep =
          mls_status_.has_value() ? mls_status_->mls_epoch : 0U;
      action.need_mls_catchup = true;
      action.catchup_from_epoch = local_ep + 1U;
    }
    return;
  }
  action.pending_commit_ack = PendingCommitAck{
      parent_epoch,
      target_epoch,
      ack_res.value().status,
      ack_res.value().ack_bytes,
  };
}

void MpRoomV2Session::handle_mls_commit_finalized_locked(const Value &obj,
                                                         FrameAction &action) {
  if (e2ee_mode_ != 1U || !mls_engine_) {
    return;
  }
  if (!mls_group_id_.has_value()) {
    if (mls_joining_) {
      action.need_mls_poll_welcome = true;
    }
    return;
  }
  const Value *pf = obj.find("proposals_b64");
  if (pf == nullptr) {
    pf = obj.find("proposals");
  }
  if (pf != nullptr) {
    if (const auto *arr = std::get_if<Value::Array>(&pf->value())) {
      for (const auto &item : *arr) {
        if (const auto *ps = std::get_if<std::string>(&item.value())) {
          if (const auto pbytes = room_b64_decode(*ps); pbytes.has_value()) {
            (void)mls_engine_->apply_proposal(*mls_group_id_, *pbytes);
          }
        }
      }
    }
  }
  auto cb64 = json_opt_string(obj, "commit_blob_b64");
  if (!cb64.has_value() || cb64->empty()) {
    cb64 = json_opt_string(obj, "commit_b64");
  }
  if (!cb64.has_value() || cb64->empty()) {
    return;
  }
  const auto cbytes = room_b64_decode(*cb64);
  if (!cbytes.has_value()) {
    return;
  }
  const std::uint64_t now_s = wall_now_ms() / 1000U;
  const auto fin = mls_engine_->finalize_commit(*mls_group_id_, *cbytes, now_s);
  if (!fin.has_value()) {
    const auto mls_err = mp_mls_error_of(fin.error());
    if (mls_err == MpMlsError::self_clone_detected) {
      refresh_mls_status_locked();
      push_notice_locked(
          "SECURITY ALERT: Unauthored commit from own device_id — clone suspected!");
      return;
    }
    // If our local epoch lagged behind the finalized commit, trigger HTTP commit
    // catch-up instead of stalling!
    const std::uint64_t local_ep =
        mls_status_.has_value() ? mls_status_->mls_epoch : 0U;
    action.need_mls_catchup = true;
    action.catchup_from_epoch = local_ep + 1U;
    return;
  }
  (void)mls_engine_->prune_past_epochs(*mls_group_id_, now_s);
  refresh_mls_status_locked();
  requeue_stale_e2ee_outbox_locked(action);
  rebuild_status_summary_locked();
}

void MpRoomV2Session::handle_mls_commit_discarded_locked() {
  if (e2ee_mode_ == 1U && mls_engine_ && mls_group_id_.has_value()) {
    (void)mls_engine_->discard_tentative(*mls_group_id_);
  }
}

void MpRoomV2Session::handle_mls_rekey_needed_locked(const Value &obj,
                                                     FrameAction &action) {
  if (e2ee_mode_ != 1U || !mls_engine_ || !mls_group_id_.has_value()) {
    return;
  }
  bool applied_proposals = false;
  const Value *pf = obj.find("proposals_b64");
  if (pf == nullptr) {
    pf = obj.find("proposals");
  }
  if (pf != nullptr) {
    if (const auto *arr = std::get_if<Value::Array>(&pf->value())) {
      for (const auto &item : *arr) {
        if (const auto *ps = std::get_if<std::string>(&item.value())) {
          if (const auto pbytes = room_b64_decode(*ps); pbytes.has_value()) {
            if (mls_engine_->apply_proposal(*mls_group_id_, *pbytes).has_value()) {
              applied_proposals = true;
            }
          }
        }
      }
    }
  }
  if (json_opt_bool(obj, "is_elected_committer")) {
    if (auto c = mls_engine_->commit_pending_or_self_update(*mls_group_id_,
                                                            applied_proposals);
        c.has_value()) {
      action.pending_rekey_commit = std::move(c).value();
    }
  }
  refresh_mls_status_locked();
  push_notice_locked("MLS rekey required for room.");
}

void MpRoomV2Session::handle_mls_welcome_ready_locked(const Value &obj,
                                                      FrameAction &action) {
  (void)obj;
  if (e2ee_mode_ == 1U && mls_engine_ && !mls_group_id_.has_value()) {
    action.need_mls_poll_welcome = true;
  }
  push_notice_locked("MLS Welcome ready for room.");
}

void MpRoomV2Session::pump_mls_bootstrap() {
  std::shared_ptr<MpMlsEngine> engine;
  std::optional<mp::Ed25519PubKey> ds_pk;
  std::optional<mp::AccountId> acct_id;
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (e2ee_mode_ != 1U || !mls_engine_ || !mls_engine_->valid() ||
        mls_group_id_.has_value() || !party_ds_pubkey_.has_value() ||
        !local_account_id_.has_value()) {
      return;
    }
    engine = mls_engine_;
    ds_pk = party_ds_pubkey_;
    acct_id = local_account_id_;
  }

  MpMlsRoomPolicy pol{};
  pol.party_id = party_id_;
  pol.require_self_custody = false;
  pol.allow_browser_devices = true;
  pol.host_account_ids = {acct_id->value()};
  const auto created = engine->create_group(pol, *ds_pk);
  if (!created.has_value()) {
    return;
  }
  const auto init_res = client_.mls_init_party(mp::MlsInitPartyRequest{
      party_id_,
      created.value().group_id,
      created.value().group_info_bytes,
  });
  if (init_res.has_value()) {
    std::lock_guard<std::mutex> lock(state_mu_);
    mls_group_id_ = created.value().group_id;
    server_mls_group_id_ = created.value().group_id;
    mls_joining_ = false;
    refresh_mls_status_locked();
    rebuild_status_summary_locked();
    push_notice_locked("E2EE group ready (epoch 0).");
  } else if (mp::mp_client_error_of(init_res.error()) ==
             mp::MpClientError::http_conflict) {
    // Another device already initialized the group — switch to Welcome-join pump!
    pump_mls_join_and_welcome(true);
  }
}

void MpRoomV2Session::pump_mls_join_and_welcome(bool allow_kp_upload) {
  std::shared_ptr<MpMlsEngine> engine;
  std::optional<mp::Ed25519PubKey> ds_pk;
  std::optional<MlsGroupId> srv_gid;
  std::optional<std::string> invite_frag;
  bool already_uploaded = false;
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (e2ee_mode_ != 1U || !mls_engine_ || !mls_engine_->valid() ||
        mls_group_id_.has_value()) {
      return;
    }
    engine = mls_engine_;
    ds_pk = party_ds_pubkey_;
    srv_gid = server_mls_group_id_;
    invite_frag = mls_invite_fragment_;
    already_uploaded = mls_kp_uploaded_;
  }

  // 1. Check if a Welcome is already queued for our device_id.
  const auto w_res = client_.mls_fetch_welcome(party_id_);
  if (w_res.has_value() && w_res.value().available) {
    const auto &w = w_res.value();
    const mp::Ed25519PubKey expected_ds = ds_pk.value_or(w.ds_pubkey);
    const auto joined = engine->process_welcome(party_id_, expected_ds, w.welcome_bytes,
                                                w.welcome_auth_bytes);
    if (joined.has_value()) {
      (void)client_.mls_ack_welcome(party_id_, w.target_epoch);
      std::uint64_t next_catchup_epoch = 0U;
      {
        std::lock_guard<std::mutex> lock(state_mu_);
        mls_group_id_ = joined.value();
        mls_joining_ = false;
        refresh_mls_status_locked();
        rebuild_status_summary_locked();
        const std::uint64_t ep = mls_status_.has_value() ? mls_status_->mls_epoch : 0U;
        next_catchup_epoch = ep + 1U;
        push_notice_locked("Joined E2EE group (epoch " + std::to_string(ep) + ").");
      }
      pump_mls_catchup(next_catchup_epoch);
      return;
    }
  }

  // 2. If no Welcome yet and we haven't uploaded our KeyPackage yet, prepare & upload!
  if (!allow_kp_upload || already_uploaded) {
    return;
  }
  if (invite_frag.has_value() && !invite_frag->empty()) {
    const auto prep = engine->prepare_join(*invite_frag);
    if (prep.has_value()) {
      const auto join_res = client_.mls_join_party(mp::MlsJoinPartyRequest{
          party_id_,
          prep.value().invite_id,
          prep.value().server_invite_token,
          prep.value().kp_ref,
          prep.value().kp_bytes,
          prep.value().join_proof,
      });
      if (join_res.has_value() || mp::mp_client_error_of(join_res.error()) ==
                                      mp::MpClientError::http_conflict) {
        std::lock_guard<std::mutex> lock(state_mu_);
        mls_kp_uploaded_ = true;
      }
    }
  } else if (srv_gid.has_value()) {
    const auto prep = engine->prepare_direct_join(*srv_gid);
    if (prep.has_value()) {
      const auto join_res = client_.mls_join_party(mp::MlsJoinPartyRequest{
          party_id_,
          0U,
          std::nullopt,
          prep.value().kp_ref,
          prep.value().kp_bytes,
          std::nullopt,
      });
      if (join_res.has_value() || mp::mp_client_error_of(join_res.error()) ==
                                      mp::MpClientError::http_conflict) {
        std::lock_guard<std::mutex> lock(state_mu_);
        mls_kp_uploaded_ = true;
      }
    }
  }
}

void MpRoomV2Session::pump_mls_catchup(std::uint64_t from_epoch) {
  std::shared_ptr<MpMlsEngine> engine;
  std::optional<MlsGroupId> gid;
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (e2ee_mode_ != 1U || !mls_engine_ || !mls_group_id_.has_value()) {
      return;
    }
    engine = mls_engine_;
    gid = mls_group_id_;
  }

  std::uint64_t cursor = std::max<std::uint64_t>(from_epoch, 1U);
  for (int page = 0; page < 8; ++page) {
    const auto res =
        client_.mls_fetch_commits(mp::MlsFetchCommitsRequest{party_id_, cursor, 32U});
    if (!res.has_value() || res.value().commits.empty()) {
      break;
    }
    const std::uint64_t now_s = wall_now_ms() / 1000U;
    std::uint64_t last_ep = cursor;
    bool applied_any = false;
    {
      std::lock_guard<std::mutex> lock(state_mu_);
      for (const auto &rec : res.value().commits) {
        for (const auto &prop : rec.referenced_proposals) {
          (void)engine->apply_proposal(*gid, prop);
        }
        const auto fin = engine->finalize_commit(*gid, rec.commit_bytes, now_s);
        if (fin.has_value()) {
          applied_any = true;
          last_ep = std::max(last_ep, rec.epoch);
        }
      }
      if (applied_any) {
        (void)engine->prune_past_epochs(*gid, now_s);
        refresh_mls_status_locked();
        FrameAction dummy{};
        requeue_stale_e2ee_outbox_locked(dummy);
        rebuild_status_summary_locked();
      }
    }
    if (!applied_any || res.value().commits.size() < 32U ||
        last_ep >= res.value().head_epoch) {
      break;
    }
    cursor = last_ep + 1U;
  }
}

void MpRoomV2Session::pump_mls_pending_joiners(
    const std::vector<PendingJoinRequest> &requests) {
  if (requests.empty()) {
    return;
  }
  for (const auto &req : requests) {
    std::shared_ptr<MpMlsEngine> engine;
    std::optional<MlsGroupId> gid;
    std::optional<mp::AccountId> local_acct;
    std::uint64_t parent_epoch = 0U;
    {
      std::lock_guard<std::mutex> lock(state_mu_);
      if (e2ee_mode_ != 1U || !mls_engine_ || !mls_group_id_.has_value()) {
        return;
      }
      engine = mls_engine_;
      gid = mls_group_id_;
      local_acct = local_account_id_;
      if (const auto st = engine->room_status(*gid, wall_now_ms() / 1000U);
          st.has_value()) {
        parent_epoch = st.value().mls_epoch;
      }
    }

    const std::uint64_t now_s = wall_now_ms() / 1000U;
    Result<MpMlsAddCommit> add_res = fail<MpMlsAddCommit>(
        ErrorCode::invalid_identity, MpRoomV2Error::mls_unavailable);
    if (req.invite_id > 0U && req.join_proof.has_value()) {
      add_res = engine->commit_add_invitee(*gid, req.invite_id, req.kp_bytes,
                                           *req.join_proof, now_s, false);
    } else if (local_acct.has_value() && req.account_id == local_acct->value()) {
      add_res = engine->commit_add_sibling(*gid, req.kp_bytes, now_s);
    }
    if (!add_res.has_value()) {
      continue;
    }
    const auto target_dev = mp::DeviceId::create(req.device_id);
    if (!target_dev.has_value()) {
      (void)engine->discard_tentative(*gid);
      continue;
    }
    const auto submit_res = client_.mls_submit_commit(mp::MlsSubmitCommitRequest{
        party_id_,
        parent_epoch,
        add_res.value().commit_bytes,
        add_res.value().welcome_bytes,
        add_res.value().welcome_auth_bytes,
        target_dev.value(),
        req.kp_ref,
    });
    if (!submit_res.has_value()) {
      (void)engine->discard_tentative(*gid);
      continue;
    }
    if (submit_res.value().finalized) {
      std::lock_guard<std::mutex> lock(state_mu_);
      if (engine->finalize_commit(*gid, add_res.value().commit_bytes, now_s)
              .has_value()) {
        (void)engine->prune_past_epochs(*gid, now_s);
        refresh_mls_status_locked();
        rebuild_status_summary_locked();
      }
    }
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
  } else if (*type == "nick") {
    handle_irc_nick_frame_locked(obj);
  } else if (*type == "topic") {
    handle_irc_topic_frame_locked(obj);
  } else if (*type == "error") {
    handle_error_locked(obj, action);
  } else if (*type == "mls_join_request" || *type == "mls_key_package_available") {
    handle_mls_join_request_locked(obj, action);
  } else if (*type == "mls_commit_tentative") {
    handle_mls_commit_tentative_locked(obj, action);
  } else if (*type == "mls_commit_finalized") {
    handle_mls_commit_finalized_locked(obj, action);
  } else if (*type == "mls_commit_discarded") {
    handle_mls_commit_discarded_locked();
  } else if (*type == "mls_rekey_needed") {
    handle_mls_rekey_needed_locked(obj, action);
  } else if (*type == "mls_welcome_ready") {
    handle_mls_welcome_ready_locked(obj, action);
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

bool MpRoomV2Session::flush_pending_control_frames(mp::MpControlSocket &sock) {
  std::deque<PendingControlFrame> batch;
  {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (control_outbox_.empty()) {
      return true;
    }
    batch.swap(control_outbox_);
  }
  while (!batch.empty()) {
    const auto &front = batch.front();
    if (!sock.send_text(front.payload).has_value()) {
      std::lock_guard<std::mutex> lock(state_mu_);
      while (!batch.empty()) {
        control_outbox_.push_front(std::move(batch.back()));
        batch.pop_back();
      }
      return false;
    }
    batch.pop_front();
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
  auto last_welcome_poll = SteadyClock::now();
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

    // 2. Flush outbound messages & status when live and not rate-limited, and poll
    //    Welcome periodically while joining an E2EE group.
    bool can_send = false;
    bool need_periodic_welcome = false;
    {
      std::lock_guard<std::mutex> lock(state_mu_);
      can_send = (state_ == MpRoomV2State::live);
      need_periodic_welcome =
          can_send && e2ee_mode_ == 1U && mls_joining_ && !mls_group_id_.has_value() &&
          std::chrono::duration_cast<std::chrono::milliseconds>(now - last_welcome_poll)
                  .count() >= 500;
    }
    if (need_periodic_welcome) {
      last_welcome_poll = now;
      pump_mls_join_and_welcome(true);
      signal_wake();
    }
    if (can_send && now >= rate_limit_until) {
      if (!flush_outbox(active_sock) || !flush_pending_status(active_sock) ||
          !flush_pending_control_frames(active_sock)) {
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
      if (action.force_disconnect) {
        (void)active_sock.close(1008U);
        socket_.reset();
        signal_wake();
        break;
      }
      if (action.need_mls_bootstrap) {
        pump_mls_bootstrap();
      }
      if (action.need_mls_join_pump) {
        last_welcome_poll = SteadyClock::now();
        pump_mls_join_and_welcome(true);
      } else if (action.need_mls_poll_welcome) {
        last_welcome_poll = SteadyClock::now();
        pump_mls_join_and_welcome(false);
      }
      if (action.need_mls_catchup) {
        pump_mls_catchup(action.catchup_from_epoch);
      }
      if (!action.pending_join_requests.empty()) {
        pump_mls_pending_joiners(action.pending_join_requests);
      }
      if (action.pending_commit_ack.has_value()) {
        const auto &ack = *action.pending_commit_ack;
        const auto http_ack =
            client_.mls_submit_commit_ack(mp::MlsSubmitCommitAckRequest{
                party_id_,
                ack.parent_epoch,
                ack.target_epoch,
                ack.status,
                ack.ack_bytes,
            });
        if (!http_ack.has_value()) {
          // Fallback for WS-only loopback test harnesses that do not serve HTTP REST.
          Value::Object ack_frame;
          ack_frame.emplace_back("v", Value{Number{std::uint64_t{2U}}});
          ack_frame.emplace_back("t", Value{"mls_commit_ack"});
          ack_frame.emplace_back("parent_epoch", Value{Number{ack.parent_epoch}});
          ack_frame.emplace_back("target_epoch", Value{Number{ack.target_epoch}});
          ack_frame.emplace_back("status",
                                 Value{Number{static_cast<std::uint64_t>(ack.status)}});
          ack_frame.emplace_back("ack_b64", Value{room_b64_encode(ack.ack_bytes)});
          if (const auto dumped = dump_json(Value::object(std::move(ack_frame)));
              dumped.has_value()) {
            (void)active_sock.send_text(dumped.value());
          }
        }
      }
      if (action.pending_rekey_commit.has_value()) {
        std::uint64_t parent_ep = 0U;
        {
          std::lock_guard<std::mutex> lock(state_mu_);
          if (mls_status_.has_value()) {
            parent_ep = mls_status_->mls_epoch;
          }
        }
        const auto http_commit = client_.mls_submit_commit(mp::MlsSubmitCommitRequest{
            party_id_,
            parent_ep,
            *action.pending_rekey_commit,
            std::nullopt,
            std::nullopt,
            std::nullopt,
            std::nullopt,
        });
        if (http_commit.has_value()) {
          if (http_commit.value().finalized) {
            std::lock_guard<std::mutex> lock(state_mu_);
            if (mls_engine_ && mls_group_id_.has_value()) {
              const std::uint64_t now_s = wall_now_ms() / 1000U;
              (void)mls_engine_->finalize_commit(*mls_group_id_,
                                                 *action.pending_rekey_commit, now_s);
              (void)mls_engine_->prune_past_epochs(*mls_group_id_, now_s);
              refresh_mls_status_locked();
              rebuild_status_summary_locked();
            }
          }
        } else {
          Value::Object cframe;
          cframe.emplace_back("v", Value{Number{std::uint64_t{2U}}});
          cframe.emplace_back("t", Value{"mls_commit"});
          cframe.emplace_back("commit_b64",
                              Value{room_b64_encode(*action.pending_rekey_commit)});
          if (const auto dumped = dump_json(Value::object(std::move(cframe)));
              dumped.has_value()) {
            (void)active_sock.send_text(dumped.value());
          }
        }
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
