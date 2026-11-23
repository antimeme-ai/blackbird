#include "blackbird/p2p_party_session.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace blackbird {

namespace {

template <typename T> Result<T> fail(ErrorCode code, P2pPartyError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_void(ErrorCode code, P2pPartyError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> validate_party_epoch(std::uint64_t epoch) {
  if (epoch == 0U || epoch > mp::kMaxSafeId) {
    return fail_void(ErrorCode::invalid_range, P2pPartyError::invalid_party_epoch);
  }
  return Result<void>::success();
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

bool is_valid_utf8(std::span<const std::uint8_t> bytes) noexcept {
  std::size_t i = 0U;
  while (i < bytes.size()) {
    const std::uint8_t b0 = bytes[i];
    if (b0 <= 0x7fU) {
      ++i;
      continue;
    }
    if (b0 >= 0xc2U && b0 <= 0xdfU) {
      if (i + 1U >= bytes.size()) {
        return false;
      }
      const std::uint8_t b1 = bytes[i + 1U];
      if ((b1 & 0xc0U) != 0x80U) {
        return false;
      }
      i += 2U;
      continue;
    }
    if (b0 >= 0xe0U && b0 <= 0xefU) {
      if (i + 2U >= bytes.size()) {
        return false;
      }
      const std::uint8_t b1 = bytes[i + 1U];
      const std::uint8_t b2 = bytes[i + 2U];
      if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U) {
        return false;
      }
      if (b0 == 0xe0U && b1 < 0xa0U) {
        return false;
      }
      if (b0 == 0xedU && b1 >= 0xa0U) {
        return false; // UTF-16 surrogates
      }
      i += 3U;
      continue;
    }
    if (b0 >= 0xf0U && b0 <= 0xf4U) {
      if (i + 3U >= bytes.size()) {
        return false;
      }
      const std::uint8_t b1 = bytes[i + 1U];
      const std::uint8_t b2 = bytes[i + 2U];
      const std::uint8_t b3 = bytes[i + 3U];
      if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U || (b3 & 0xc0U) != 0x80U) {
        return false;
      }
      if (b0 == 0xf0U && b1 < 0x90U) {
        return false;
      }
      if (b0 == 0xf4U && b1 > 0x8fU) {
        return false;
      }
      i += 4U;
      continue;
    }
    return false;
  }
  return true;
}

bool is_valid_utf8_text(std::string_view text) noexcept {
  const auto *ptr = reinterpret_cast<const std::uint8_t *>(text.data());
  return is_valid_utf8(std::span<const std::uint8_t>{ptr, text.size()});
}

bool is_loopback_direct_addr(const mp::DirectAddr &addr) noexcept {
  if (const auto *v4 = std::get_if<mp::DirectAddrV4>(&addr)) {
    return v4->ip[0] == 127U;
  }
  const auto &v6 = std::get<mp::DirectAddrV6>(addr);
  const bool prefix15_zero =
      std::all_of(v6.ip.begin(), v6.ip.begin() + 15,
                  [](std::uint8_t b) noexcept { return b == 0U; });
  return prefix15_zero && v6.ip[15] == 1U;
}

std::uint16_t mp_direct_addr_port(const mp::DirectAddr &addr) noexcept {
  return std::visit([](const auto &a) noexcept { return a.port; }, addr);
}

std::size_t mp_direct_addr_encoded_len(const mp::DirectAddr &addr) noexcept {
  return std::holds_alternative<mp::DirectAddrV4>(addr) ? 7U : 19U;
}

void append_u16_le(std::vector<std::uint8_t> &out, std::uint16_t val) {
  out.push_back(static_cast<std::uint8_t>(val & 0xffU));
  out.push_back(static_cast<std::uint8_t>((val >> 8U) & 0xffU));
}

void append_u32_le(std::vector<std::uint8_t> &out, std::uint32_t val) {
  for (std::size_t i = 0U; i < 4U; ++i) {
    out.push_back(static_cast<std::uint8_t>((val >> (i * 8U)) & 0xffU));
  }
}

void append_u64_le(std::vector<std::uint8_t> &out, std::uint64_t val) {
  for (std::size_t i = 0U; i < 8U; ++i) {
    out.push_back(static_cast<std::uint8_t>((val >> (i * 8U)) & 0xffU));
  }
}

void append_i64_le(std::vector<std::uint8_t> &out, std::int64_t val) {
  append_u64_le(out, std::bit_cast<std::uint64_t>(val));
}

void append_text_u16(std::vector<std::uint8_t> &out, std::string_view text) {
  append_u16_le(out, static_cast<std::uint16_t>(text.size()));
  for (const char ch : text) {
    out.push_back(static_cast<std::uint8_t>(ch));
  }
}

void append_text_u32(std::vector<std::uint8_t> &out, std::string_view text) {
  append_u32_le(out, static_cast<std::uint32_t>(text.size()));
  for (const char ch : text) {
    out.push_back(static_cast<std::uint8_t>(ch));
  }
}

void append_bytes_u32(std::vector<std::uint8_t> &out,
                      std::span<const std::uint8_t> bytes) {
  append_u32_le(out, static_cast<std::uint32_t>(bytes.size()));
  out.insert(out.end(), bytes.begin(), bytes.end());
}

Result<void> validate_text_field(std::string_view text, std::size_t max_bytes) {
  if (text.size() > max_bytes) {
    return fail_void(ErrorCode::capacity, P2pPartyError::frame_field_too_large);
  }
  if (!is_valid_utf8_text(text)) {
    return fail_void(ErrorCode::corrupt, P2pPartyError::frame_invalid_utf8);
  }
  return Result<void>::success();
}

Result<P2pPartyFrameKind> frame_kind_from_u8(std::uint8_t raw) {
  switch (raw) {
  case 1U:
    return Result<P2pPartyFrameKind>::success(P2pPartyFrameKind::chat_message);
  case 2U:
    return Result<P2pPartyFrameKind>::success(P2pPartyFrameKind::bridge_envelope);
  case 3U:
    return Result<P2pPartyFrameKind>::success(P2pPartyFrameKind::control_notice);
  case 4U:
    return Result<P2pPartyFrameKind>::success(P2pPartyFrameKind::ephemeral_pulse);
  default:
    return fail<P2pPartyFrameKind>(ErrorCode::corrupt,
                                   P2pPartyError::frame_unknown_kind);
  }
}

Result<P2pPartyControlNoticeKind> control_notice_kind_from_u8(std::uint8_t raw) {
  switch (raw) {
  case 0U:
    return Result<P2pPartyControlNoticeKind>::success(
        P2pPartyControlNoticeKind::sync_ack);
  case 1U:
    return Result<P2pPartyControlNoticeKind>::success(
        P2pPartyControlNoticeKind::scope_changed);
  case 2U:
    return Result<P2pPartyControlNoticeKind>::success(
        P2pPartyControlNoticeKind::status);
  default:
    return fail<P2pPartyControlNoticeKind>(ErrorCode::corrupt,
                                           P2pPartyError::frame_invalid_enum);
  }
}

Result<P2pPartyActivityState> activity_state_from_u8(std::uint8_t raw) {
  switch (raw) {
  case 0U:
    return Result<P2pPartyActivityState>::success(P2pPartyActivityState::offline);
  case 1U:
    return Result<P2pPartyActivityState>::success(P2pPartyActivityState::online);
  case 2U:
    return Result<P2pPartyActivityState>::success(P2pPartyActivityState::working);
  case 3U:
    return Result<P2pPartyActivityState>::success(P2pPartyActivityState::idle);
  case 4U:
    return Result<P2pPartyActivityState>::success(P2pPartyActivityState::typing);
  default:
    return fail<P2pPartyActivityState>(ErrorCode::corrupt,
                                       P2pPartyError::frame_invalid_enum);
  }
}

class FrameReader {
public:
  explicit FrameReader(std::span<const std::uint8_t> bytes) noexcept : bytes_(bytes) {}

  Result<std::span<const std::uint8_t>> take(std::size_t count) {
    if (count > bytes_.size() - pos_) {
      return fail<std::span<const std::uint8_t>>(ErrorCode::corrupt,
                                                 P2pPartyError::frame_truncated);
    }
    const auto out = bytes_.subspan(pos_, count);
    pos_ += count;
    return Result<std::span<const std::uint8_t>>::success(out);
  }

  Result<std::uint8_t> read_u8() {
    const auto s = take(1U);
    if (!s.has_value()) {
      return Result<std::uint8_t>::failure(s.error());
    }
    return Result<std::uint8_t>::success(s.value()[0]);
  }

  Result<std::uint16_t> read_u16() {
    const auto s = take(2U);
    if (!s.has_value()) {
      return Result<std::uint16_t>::failure(s.error());
    }
    const auto v =
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(s.value()[0]) |
                                   (static_cast<std::uint16_t>(s.value()[1]) << 8U));
    return Result<std::uint16_t>::success(v);
  }

  Result<std::uint32_t> read_u32() {
    const auto s = take(4U);
    if (!s.has_value()) {
      return Result<std::uint32_t>::failure(s.error());
    }
    std::uint32_t v = 0U;
    for (std::size_t i = 0U; i < 4U; ++i) {
      v |= static_cast<std::uint32_t>(s.value()[i]) << (i * 8U);
    }
    return Result<std::uint32_t>::success(v);
  }

  Result<std::uint64_t> read_u64() {
    const auto s = take(8U);
    if (!s.has_value()) {
      return Result<std::uint64_t>::failure(s.error());
    }
    std::uint64_t v = 0U;
    for (std::size_t i = 0U; i < 8U; ++i) {
      v |= static_cast<std::uint64_t>(s.value()[i]) << (i * 8U);
    }
    return Result<std::uint64_t>::success(v);
  }

  Result<std::int64_t> read_i64() {
    const auto raw = read_u64();
    if (!raw.has_value()) {
      return Result<std::int64_t>::failure(raw.error());
    }
    return Result<std::int64_t>::success(std::bit_cast<std::int64_t>(raw.value()));
  }

  Result<std::string> read_text_u16(std::size_t max_bytes) {
    const auto len = read_u16();
    if (!len.has_value()) {
      return Result<std::string>::failure(len.error());
    }
    if (static_cast<std::size_t>(len.value()) > max_bytes) {
      return fail<std::string>(ErrorCode::capacity,
                               P2pPartyError::frame_field_too_large);
    }
    const auto slice = take(static_cast<std::size_t>(len.value()));
    if (!slice.has_value()) {
      return Result<std::string>::failure(slice.error());
    }
    if (!is_valid_utf8(slice.value())) {
      return fail<std::string>(ErrorCode::corrupt, P2pPartyError::frame_invalid_utf8);
    }
    std::string out;
    out.reserve(slice.value().size());
    for (const std::uint8_t b : slice.value()) {
      out.push_back(static_cast<char>(b));
    }
    return Result<std::string>::success(std::move(out));
  }

  Result<std::string> read_text_u32(std::size_t max_bytes) {
    const auto len = read_u32();
    if (!len.has_value()) {
      return Result<std::string>::failure(len.error());
    }
    if (static_cast<std::size_t>(len.value()) > max_bytes) {
      return fail<std::string>(ErrorCode::capacity,
                               P2pPartyError::frame_field_too_large);
    }
    const auto slice = take(static_cast<std::size_t>(len.value()));
    if (!slice.has_value()) {
      return Result<std::string>::failure(slice.error());
    }
    if (!is_valid_utf8(slice.value())) {
      return fail<std::string>(ErrorCode::corrupt, P2pPartyError::frame_invalid_utf8);
    }
    std::string out;
    out.reserve(slice.value().size());
    for (const std::uint8_t b : slice.value()) {
      out.push_back(static_cast<char>(b));
    }
    return Result<std::string>::success(std::move(out));
  }

  Result<std::vector<std::uint8_t>> read_bytes_u32(std::size_t max_bytes) {
    const auto len = read_u32();
    if (!len.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(len.error());
    }
    if (static_cast<std::size_t>(len.value()) > max_bytes) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::capacity,
                                             P2pPartyError::frame_field_too_large);
    }
    const auto slice = take(static_cast<std::size_t>(len.value()));
    if (!slice.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(slice.error());
    }
    return Result<std::vector<std::uint8_t>>::success(
        std::vector<std::uint8_t>(slice.value().begin(), slice.value().end()));
  }

  bool at_end() const noexcept { return pos_ == bytes_.size(); }

private:
  std::span<const std::uint8_t> bytes_;
  std::size_t pos_ = 0U;
};

} // namespace

// ---------------------------------------------------------------------------
// Name helpers
// ---------------------------------------------------------------------------

std::string_view p2p_party_error_name(P2pPartyError detail) noexcept {
  switch (detail) {
  case P2pPartyError::none:
    return "none";
  case P2pPartyError::session_disbanded:
    return "session_disbanded";
  case P2pPartyError::no_active_party:
    return "no_active_party";
  case P2pPartyError::stale_party_epoch:
    return "stale_party_epoch";
  case P2pPartyError::relay_policy_mismatch:
    return "relay_policy_mismatch";
  case P2pPartyError::duplicate_device_id:
    return "duplicate_device_id";
  case P2pPartyError::duplicate_device_pubkey:
    return "duplicate_device_pubkey";
  case P2pPartyError::peer_not_found:
    return "peer_not_found";
  case P2pPartyError::self_target_disallowed:
    return "self_target_disallowed";
  case P2pPartyError::endpoint_unavailable:
    return "endpoint_unavailable";
  case P2pPartyError::frame_truncated:
    return "frame_truncated";
  case P2pPartyError::frame_trailing_bytes:
    return "frame_trailing_bytes";
  case P2pPartyError::frame_unsupported_version:
    return "frame_unsupported_version";
  case P2pPartyError::frame_unknown_kind:
    return "frame_unknown_kind";
  case P2pPartyError::frame_lane_mismatch:
    return "frame_lane_mismatch";
  case P2pPartyError::frame_field_too_large:
    return "frame_field_too_large";
  case P2pPartyError::frame_invalid_utf8:
    return "frame_invalid_utf8";
  case P2pPartyError::frame_invalid_enum:
    return "frame_invalid_enum";
  case P2pPartyError::frame_non_zero_reserved:
    return "frame_non_zero_reserved";
  case P2pPartyError::frame_unverified_sender:
    return "frame_unverified_sender";
  case P2pPartyError::local_pubkey_mismatch:
    return "local_pubkey_mismatch";
  case P2pPartyError::invalid_party_member_count:
    return "invalid_party_member_count";
  case P2pPartyError::peer_lease_expired:
    return "peer_lease_expired";
  case P2pPartyError::frame_oversized:
    return "frame_oversized";
  case P2pPartyError::party_id_mismatch:
    return "party_id_mismatch";
  case P2pPartyError::invalid_party_epoch:
    return "invalid_party_epoch";
  }
  return "unknown";
}

std::string_view p2p_party_frame_kind_name(P2pPartyFrameKind kind) noexcept {
  switch (kind) {
  case P2pPartyFrameKind::chat_message:
    return "chat_message";
  case P2pPartyFrameKind::bridge_envelope:
    return "bridge_envelope";
  case P2pPartyFrameKind::control_notice:
    return "control_notice";
  case P2pPartyFrameKind::ephemeral_pulse:
    return "ephemeral_pulse";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// EndpointDescriptor -> P2pPeerTarget conversion
// ---------------------------------------------------------------------------

P2pDirectAddr mp_direct_addr_to_p2p(const mp::DirectAddr &addr) noexcept {
  if (const auto *v4 = std::get_if<mp::DirectAddrV4>(&addr)) {
    return P2pDirectAddr::ipv4(v4->ip, v4->port);
  }
  const auto &v6 = std::get<mp::DirectAddrV6>(addr);
  return P2pDirectAddr::ipv6(v6.ip, v6.port);
}

Result<mp::DirectAddr> p2p_direct_addr_to_mp(const P2pDirectAddr &addr) {
  if (addr.port == 0U) {
    return Result<mp::DirectAddr>::failure(
        {ErrorCode::invalid_range,
         static_cast<std::int64_t>(mp::MpError::invalid_port)});
  }
  if (addr.family == 4U) {
    for (std::size_t i = 4U; i < addr.ip.size(); ++i) {
      if (addr.ip[i] != 0U) {
        return Result<mp::DirectAddr>::failure(
            {ErrorCode::invalid_range,
             static_cast<std::int64_t>(mp::MpError::invalid_addr_family)});
      }
    }
    mp::DirectAddrV4 v4{};
    v4.ip = {addr.ip[0], addr.ip[1], addr.ip[2], addr.ip[3]};
    v4.port = addr.port;
    return Result<mp::DirectAddr>::success(mp::DirectAddr{v4});
  }
  if (addr.family == 6U) {
    mp::DirectAddrV6 v6{};
    v6.ip = addr.ip;
    v6.port = addr.port;
    return Result<mp::DirectAddr>::success(mp::DirectAddr{v6});
  }
  return Result<mp::DirectAddr>::failure(
      {ErrorCode::invalid_range,
       static_cast<std::int64_t>(mp::MpError::invalid_addr_family)});
}

Result<P2pPeerTarget>
endpoint_descriptor_to_p2p_target(const mp::PartyMemberRecord &member,
                                  mp::RelayPolicy party_relay_policy,
                                  std::uint32_t connect_timeout_ms) {
  if (member.endpoint.relay_url.size() > kP2pMaxRelayUrlBytes) {
    return Result<P2pPeerTarget>::failure(
        {ErrorCode::invalid_range,
         static_cast<std::int64_t>(mp::MpError::invalid_relay_url)});
  }
  if (member.endpoint.direct_addrs.size() > kP2pMaxDirectAddrs) {
    return Result<P2pPeerTarget>::failure(
        {ErrorCode::invalid_range,
         static_cast<std::int64_t>(mp::MpError::too_many_direct_addrs)});
  }

  P2pPeerTarget target{};
  target.pubkey = member.device_pubkey;
  target.remote_relay_policy = to_p2p_relay_policy(party_relay_policy);
  target.connect_timeout_ms =
      connect_timeout_ms == 0U ? kP2pPartyDefaultConnectTimeoutMs : connect_timeout_ms;

  switch (party_relay_policy) {
  case mp::RelayPolicy::force_relays:
    if (member.endpoint.relay_url.empty()) {
      return Result<P2pPeerTarget>::failure(
          {ErrorCode::invalid_range,
           static_cast<std::int64_t>(mp::MpError::force_relays_violation)});
    }
    if (const auto url_ok = mp::validate_relay_url(member.endpoint.relay_url);
        !url_ok.has_value()) {
      return Result<P2pPeerTarget>::failure(url_ok.error());
    }
    // Defense in depth: force_relays ALWAYS drops direct IP addresses.
    target.relay_url = member.endpoint.relay_url;
    target.direct_addrs.clear();
    return Result<P2pPeerTarget>::success(std::move(target));
  case mp::RelayPolicy::no_relays:
    target.relay_url.clear();
    break;
  case mp::RelayPolicy::allow_relays:
    if (const auto url_ok = mp::validate_relay_url(member.endpoint.relay_url);
        !url_ok.has_value()) {
      return Result<P2pPeerTarget>::failure(url_ok.error());
    }
    target.relay_url = member.endpoint.relay_url;
    break;
  }

  try {
    target.direct_addrs.reserve(member.endpoint.direct_addrs.size());
    for (const auto &addr : member.endpoint.direct_addrs) {
      if (mp_direct_addr_port(addr) == 0U) {
        return Result<P2pPeerTarget>::failure(
            {ErrorCode::invalid_range,
             static_cast<std::int64_t>(mp::MpError::invalid_port)});
      }
      target.direct_addrs.push_back(mp_direct_addr_to_p2p(addr));
    }
  } catch (const std::bad_alloc &) {
    return Result<P2pPeerTarget>::failure({ErrorCode::allocation});
  }
  return Result<P2pPeerTarget>::success(std::move(target));
}

// ---------------------------------------------------------------------------
// Typed Party Data-Plane Wire Codec
// Exact little-endian byte offsets are documented in p2p_party_session.hpp:
//   Header [0..3]: version(0x01), kind(1..4), flags(0x00), reserved(0x00).
//   chat_message    (Lane 1): [4..11] i64 ts_ns, u16 scope, u16 target, u16 handle,
//                             u32 body.
//   bridge_envelope (Lane 1): [4..] u16 scope, u32 payload.
//   control_notice  (Lane 0): [4] u8 kind, [5] u8 rsv(0), [6..13] u64 epoch, u16 text.
//   ephemeral_pulse (Lane 2): [4] u8 state, [5] u8 rsv(0), [6..13] i64 ts_ns, u16
//   status.
// ---------------------------------------------------------------------------

P2pPartyFrameKind p2p_party_frame_kind(const P2pPartyFrame &frame) noexcept {
  if (std::holds_alternative<P2pPartyChatMessage>(frame)) {
    return P2pPartyFrameKind::chat_message;
  }
  if (std::holds_alternative<P2pPartyBridgeEnvelope>(frame)) {
    return P2pPartyFrameKind::bridge_envelope;
  }
  if (std::holds_alternative<P2pPartyControlNotice>(frame)) {
    return P2pPartyFrameKind::control_notice;
  }
  return P2pPartyFrameKind::ephemeral_pulse;
}

Result<std::vector<std::uint8_t>> encode_p2p_party_frame(const P2pPartyFrame &frame) {
  const P2pPartyFrameKind kind = p2p_party_frame_kind(frame);
  const P2pLane lane = p2p_party_frame_lane(kind);
  try {
    std::vector<std::uint8_t> out;
    out.push_back(kP2pPartyFrameVersion);
    out.push_back(static_cast<std::uint8_t>(kind));
    out.push_back(0U); // flags
    out.push_back(0U); // reserved

    if (const auto *chat = std::get_if<P2pPartyChatMessage>(&frame)) {
      if (const auto ok =
              validate_text_field(chat->room_scope, kP2pPartyMaxRoomScopeBytes);
          !ok.has_value()) {
        return Result<std::vector<std::uint8_t>>::failure(ok.error());
      }
      if (const auto ok = validate_text_field(chat->target_selector,
                                              kP2pPartyMaxTargetSelectorBytes);
          !ok.has_value()) {
        return Result<std::vector<std::uint8_t>>::failure(ok.error());
      }
      if (const auto ok =
              validate_text_field(chat->sender_handle, kP2pPartyMaxSenderHandleBytes);
          !ok.has_value()) {
        return Result<std::vector<std::uint8_t>>::failure(ok.error());
      }
      if (const auto ok = validate_text_field(chat->body, kP2pPartyMaxChatBodyBytes);
          !ok.has_value()) {
        return Result<std::vector<std::uint8_t>>::failure(ok.error());
      }
      out.reserve(4U + 8U + 2U + chat->room_scope.size() + 2U +
                  chat->target_selector.size() + 2U + chat->sender_handle.size() + 4U +
                  chat->body.size());
      append_i64_le(out, chat->timestamp_ns);
      append_text_u16(out, chat->room_scope);
      append_text_u16(out, chat->target_selector);
      append_text_u16(out, chat->sender_handle);
      append_text_u32(out, chat->body);
    } else if (const auto *bridge = std::get_if<P2pPartyBridgeEnvelope>(&frame)) {
      if (const auto ok =
              validate_text_field(bridge->room_scope, kP2pPartyMaxRoomScopeBytes);
          !ok.has_value()) {
        return Result<std::vector<std::uint8_t>>::failure(ok.error());
      }
      if (bridge->payload.size() > kP2pPartyMaxBridgePayloadBytes) {
        return fail<std::vector<std::uint8_t>>(ErrorCode::capacity,
                                               P2pPartyError::frame_field_too_large);
      }
      out.reserve(4U + 2U + bridge->room_scope.size() + 4U + bridge->payload.size());
      append_text_u16(out, bridge->room_scope);
      append_bytes_u32(out, bridge->payload);
    } else if (const auto *notice = std::get_if<P2pPartyControlNotice>(&frame)) {
      const auto raw_kind = static_cast<std::uint8_t>(notice->kind);
      if (!control_notice_kind_from_u8(raw_kind).has_value()) {
        return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_range,
                                               P2pPartyError::frame_invalid_enum);
      }
      if (const auto ok =
              validate_text_field(notice->text, kP2pPartyMaxControlNoticeBytes);
          !ok.has_value()) {
        return Result<std::vector<std::uint8_t>>::failure(ok.error());
      }
      out.reserve(4U + 2U + 8U + 2U + notice->text.size());
      out.push_back(raw_kind);
      out.push_back(0U); // reserved
      append_u64_le(out, notice->party_epoch);
      append_text_u16(out, notice->text);
    } else if (const auto *pulse = std::get_if<P2pPartyEphemeralPulse>(&frame)) {
      const auto raw_state = static_cast<std::uint8_t>(pulse->activity_state);
      if (!activity_state_from_u8(raw_state).has_value()) {
        return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_range,
                                               P2pPartyError::frame_invalid_enum);
      }
      if (const auto ok =
              validate_text_field(pulse->status, kP2pPartyMaxEphemeralStatusBytes);
          !ok.has_value()) {
        return Result<std::vector<std::uint8_t>>::failure(ok.error());
      }
      out.reserve(4U + 2U + 8U + 2U + pulse->status.size());
      out.push_back(raw_state);
      out.push_back(0U); // reserved
      append_i64_le(out, pulse->timestamp_ns);
      append_text_u16(out, pulse->status);
    }

    if (out.size() > p2p_lane_max_frame_bytes(lane)) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::capacity,
                                             P2pPartyError::frame_oversized);
    }
    return Result<std::vector<std::uint8_t>>::success(std::move(out));
  } catch (const std::bad_alloc &) {
    return Result<std::vector<std::uint8_t>>::failure({ErrorCode::allocation});
  }
}

Result<P2pPartyFrame> decode_p2p_party_frame(P2pLane expected_lane,
                                             std::span<const std::uint8_t> bytes) {
  if (bytes.size() > p2p_lane_max_frame_bytes(expected_lane)) {
    return fail<P2pPartyFrame>(ErrorCode::capacity, P2pPartyError::frame_oversized);
  }
  FrameReader reader{bytes};
  const auto version = reader.read_u8();
  if (!version.has_value()) {
    return Result<P2pPartyFrame>::failure(version.error());
  }
  if (version.value() != kP2pPartyFrameVersion) {
    return fail<P2pPartyFrame>(ErrorCode::corrupt,
                               P2pPartyError::frame_unsupported_version);
  }
  const auto kind_raw = reader.read_u8();
  if (!kind_raw.has_value()) {
    return Result<P2pPartyFrame>::failure(kind_raw.error());
  }
  const auto kind = frame_kind_from_u8(kind_raw.value());
  if (!kind.has_value()) {
    return Result<P2pPartyFrame>::failure(kind.error());
  }
  const auto flags = reader.read_u8();
  if (!flags.has_value()) {
    return Result<P2pPartyFrame>::failure(flags.error());
  }
  const auto reserved = reader.read_u8();
  if (!reserved.has_value()) {
    return Result<P2pPartyFrame>::failure(reserved.error());
  }
  if (flags.value() != 0U || reserved.value() != 0U) {
    return fail<P2pPartyFrame>(ErrorCode::corrupt,
                               P2pPartyError::frame_non_zero_reserved);
  }
  if (p2p_party_frame_lane(kind.value()) != expected_lane) {
    return fail<P2pPartyFrame>(ErrorCode::corrupt, P2pPartyError::frame_lane_mismatch);
  }

  try {
    switch (kind.value()) {
    case P2pPartyFrameKind::chat_message: {
      const auto ts = reader.read_i64();
      if (!ts.has_value()) {
        return Result<P2pPartyFrame>::failure(ts.error());
      }
      auto room_scope = reader.read_text_u16(kP2pPartyMaxRoomScopeBytes);
      if (!room_scope.has_value()) {
        return Result<P2pPartyFrame>::failure(room_scope.error());
      }
      auto target_selector = reader.read_text_u16(kP2pPartyMaxTargetSelectorBytes);
      if (!target_selector.has_value()) {
        return Result<P2pPartyFrame>::failure(target_selector.error());
      }
      auto sender_handle = reader.read_text_u16(kP2pPartyMaxSenderHandleBytes);
      if (!sender_handle.has_value()) {
        return Result<P2pPartyFrame>::failure(sender_handle.error());
      }
      auto body = reader.read_text_u32(kP2pPartyMaxChatBodyBytes);
      if (!body.has_value()) {
        return Result<P2pPartyFrame>::failure(body.error());
      }
      if (!reader.at_end()) {
        return fail<P2pPartyFrame>(ErrorCode::corrupt,
                                   P2pPartyError::frame_trailing_bytes);
      }
      return Result<P2pPartyFrame>::success(P2pPartyChatMessage{
          std::move(room_scope).value(),
          std::move(target_selector).value(),
          std::move(sender_handle).value(),
          ts.value(),
          std::move(body).value(),
      });
    }
    case P2pPartyFrameKind::bridge_envelope: {
      auto room_scope = reader.read_text_u16(kP2pPartyMaxRoomScopeBytes);
      if (!room_scope.has_value()) {
        return Result<P2pPartyFrame>::failure(room_scope.error());
      }
      auto payload = reader.read_bytes_u32(kP2pPartyMaxBridgePayloadBytes);
      if (!payload.has_value()) {
        return Result<P2pPartyFrame>::failure(payload.error());
      }
      if (!reader.at_end()) {
        return fail<P2pPartyFrame>(ErrorCode::corrupt,
                                   P2pPartyError::frame_trailing_bytes);
      }
      return Result<P2pPartyFrame>::success(P2pPartyBridgeEnvelope{
          std::move(room_scope).value(),
          std::move(payload).value(),
      });
    }
    case P2pPartyFrameKind::control_notice: {
      const auto raw_notice_kind = reader.read_u8();
      if (!raw_notice_kind.has_value()) {
        return Result<P2pPartyFrame>::failure(raw_notice_kind.error());
      }
      const auto notice_kind = control_notice_kind_from_u8(raw_notice_kind.value());
      if (!notice_kind.has_value()) {
        return Result<P2pPartyFrame>::failure(notice_kind.error());
      }
      const auto body_reserved = reader.read_u8();
      if (!body_reserved.has_value()) {
        return Result<P2pPartyFrame>::failure(body_reserved.error());
      }
      if (body_reserved.value() != 0U) {
        return fail<P2pPartyFrame>(ErrorCode::corrupt,
                                   P2pPartyError::frame_non_zero_reserved);
      }
      const auto epoch = reader.read_u64();
      if (!epoch.has_value()) {
        return Result<P2pPartyFrame>::failure(epoch.error());
      }
      auto text = reader.read_text_u16(kP2pPartyMaxControlNoticeBytes);
      if (!text.has_value()) {
        return Result<P2pPartyFrame>::failure(text.error());
      }
      if (!reader.at_end()) {
        return fail<P2pPartyFrame>(ErrorCode::corrupt,
                                   P2pPartyError::frame_trailing_bytes);
      }
      return Result<P2pPartyFrame>::success(P2pPartyControlNotice{
          notice_kind.value(),
          epoch.value(),
          std::move(text).value(),
      });
    }
    case P2pPartyFrameKind::ephemeral_pulse: {
      const auto raw_state = reader.read_u8();
      if (!raw_state.has_value()) {
        return Result<P2pPartyFrame>::failure(raw_state.error());
      }
      const auto state = activity_state_from_u8(raw_state.value());
      if (!state.has_value()) {
        return Result<P2pPartyFrame>::failure(state.error());
      }
      const auto body_reserved = reader.read_u8();
      if (!body_reserved.has_value()) {
        return Result<P2pPartyFrame>::failure(body_reserved.error());
      }
      if (body_reserved.value() != 0U) {
        return fail<P2pPartyFrame>(ErrorCode::corrupt,
                                   P2pPartyError::frame_non_zero_reserved);
      }
      const auto ts = reader.read_i64();
      if (!ts.has_value()) {
        return Result<P2pPartyFrame>::failure(ts.error());
      }
      auto status = reader.read_text_u16(kP2pPartyMaxEphemeralStatusBytes);
      if (!status.has_value()) {
        return Result<P2pPartyFrame>::failure(status.error());
      }
      if (!reader.at_end()) {
        return fail<P2pPartyFrame>(ErrorCode::corrupt,
                                   P2pPartyError::frame_trailing_bytes);
      }
      return Result<P2pPartyFrame>::success(P2pPartyEphemeralPulse{
          state.value(),
          ts.value(),
          std::move(status).value(),
      });
    }
    }
  } catch (const std::bad_alloc &) {
    return Result<P2pPartyFrame>::failure({ErrorCode::allocation});
  }
  return fail<P2pPartyFrame>(ErrorCode::corrupt, P2pPartyError::frame_unknown_kind);
}

// ---------------------------------------------------------------------------
// P2pPartySession lifecycle & construction
// ---------------------------------------------------------------------------

P2pPartySession::P2pPartySession(P2pPartySessionConfig config,
                                 std::optional<P2pEndpoint> endpoint,
                                 std::optional<P2pPubkey> local_pubkey) noexcept
    : config_(std::move(config)), endpoint_(std::move(endpoint)),
      local_pubkey_(local_pubkey) {}

Result<P2pPartySession> P2pPartySession::create(P2pPartySessionConfig config,
                                                P2pEndpoint endpoint) {
  if (config.max_lease_ttl_s.has_value() && *config.max_lease_ttl_s <= 0) {
    return Result<P2pPartySession>::failure({ErrorCode::invalid_range});
  }
  if (!endpoint.valid()) {
    return fail<P2pPartySession>(ErrorCode::stale_handle,
                                 P2pPartyError::endpoint_unavailable);
  }
  if (endpoint.relay_policy() != config.local_relay_policy) {
    return fail<P2pPartySession>(ErrorCode::conflict,
                                 P2pPartyError::relay_policy_mismatch);
  }
  const auto ep_pk = endpoint.local_pubkey();
  if (!ep_pk.has_value()) {
    return Result<P2pPartySession>::failure(ep_pk.error());
  }
  if (config.local_pubkey.has_value() && *config.local_pubkey != ep_pk.value()) {
    return fail<P2pPartySession>(ErrorCode::invalid_identity,
                                 P2pPartyError::local_pubkey_mismatch);
  }
  // Ensure fail-closed empty allowlist on the live endpoint immediately.
  if (const auto clear_ok = endpoint.set_allowed_peers({}); !clear_ok.has_value()) {
    return Result<P2pPartySession>::failure(clear_ok.error());
  }
  return Result<P2pPartySession>::success(
      P2pPartySession{std::move(config), std::move(endpoint), ep_pk.value()});
}

Result<P2pPartySession> P2pPartySession::create_detached(P2pPartySessionConfig config) {
  if (config.max_lease_ttl_s.has_value() && *config.max_lease_ttl_s <= 0) {
    return Result<P2pPartySession>::failure({ErrorCode::invalid_range});
  }
  const std::optional<P2pPubkey> pk = config.local_pubkey;
  return Result<P2pPartySession>::success(
      P2pPartySession{std::move(config), std::nullopt, pk});
}

void P2pPartySession::close() noexcept {
  if (endpoint_.has_value()) {
    endpoint_->close();
    endpoint_.reset();
  }
}

Result<std::vector<P2pDirectAddr>> P2pPartySession::local_direct_addrs() const {
  if (!endpoint_.has_value() || !endpoint_->valid()) {
    return fail<std::vector<P2pDirectAddr>>(ErrorCode::unsupported,
                                            P2pPartyError::endpoint_unavailable);
  }
  return endpoint_->local_direct_addrs();
}

std::optional<P2pPartyPeer> P2pPartySession::find_peer(mp::DeviceId device_id) const {
  const auto it = peers_by_device_.find(device_id);
  if (it == peers_by_device_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<P2pPartyPeer>
P2pPartySession::find_peer_by_pubkey(const P2pPubkey &pubkey) const {
  const auto idx = device_by_pubkey_.find(pubkey);
  if (idx == device_by_pubkey_.end()) {
    return std::nullopt;
  }
  return find_peer(idx->second);
}

std::vector<P2pPartyPeer> P2pPartySession::peers() const {
  std::vector<P2pPartyPeer> out;
  out.reserve(peers_by_device_.size());
  for (const auto &[id, peer] : peers_by_device_) {
    (void)id;
    out.push_back(peer);
  }
  return out;
}

std::vector<P2pPubkey> P2pPartySession::allowed_pubkeys() const {
  std::vector<P2pPubkey> out;
  out.reserve(peers_by_device_.size());
  for (const auto &[id, peer] : peers_by_device_) {
    (void)id;
    out.push_back(peer.device_pubkey);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Internal policy, allowlist, dial, and expiry helpers
// ---------------------------------------------------------------------------

Result<void> P2pPartySession::validate_endpoint_for_session(
    const mp::EndpointDescriptor &endpoint, mp::RelayPolicy policy,
    std::string_view pinned_relay_url) const {
  if (!config_.allow_loopback_direct_addrs || policy != mp::RelayPolicy::no_relays) {
    return endpoint.validate_against_policy(policy, pinned_relay_url);
  }
  // Loopback-enabled test harness under RelayPolicy::no_relays only:
  // still enforces every control-plane policy check and rejects all non-loopback
  // disallowed addresses (0.0.0.0, multicast, broadcast, ::, v4-mapped).
  if (const auto ok = mp::validate_pinned_relay_url(policy, pinned_relay_url);
      !ok.has_value()) {
    return ok;
  }
  if (!endpoint.relay_url.empty()) {
    return Result<void>::failure(
        {ErrorCode::invalid_range,
         static_cast<std::int64_t>(mp::MpError::no_relays_violation)});
  }
  if (endpoint.direct_addrs.size() > mp::kMaxDirectAddrs) {
    return Result<void>::failure(
        {ErrorCode::invalid_range,
         static_cast<std::int64_t>(mp::MpError::too_many_direct_addrs)});
  }
  std::size_t total = 1U + 2U + 1U;
  mp::EndpointDescriptor non_loopback{};
  non_loopback.transport_kind = endpoint.transport_kind;
  for (const auto &addr : endpoint.direct_addrs) {
    if (mp_direct_addr_port(addr) == 0U) {
      return Result<void>::failure(
          {ErrorCode::invalid_range,
           static_cast<std::int64_t>(mp::MpError::invalid_port)});
    }
    total += mp_direct_addr_encoded_len(addr);
    if (!is_loopback_direct_addr(addr)) {
      non_loopback.direct_addrs.push_back(addr);
    }
  }
  if (total > mp::kMaxEndpointDescriptorBytes) {
    return Result<void>::failure(
        {ErrorCode::capacity,
         static_cast<std::int64_t>(mp::MpError::endpoint_too_large)});
  }
  return non_loopback.validate_against_policy(policy, pinned_relay_url);
}

Result<void> P2pPartySession::sync_allowlist_to_endpoint() {
  if (!endpoint_.has_value() || !endpoint_->valid()) {
    return Result<void>::success();
  }
  const std::vector<P2pPubkey> keys = allowed_pubkeys();
  return endpoint_->set_allowed_peers(keys);
}

Result<void> P2pPartySession::dial_peer_record(P2pPartyPeer &peer) {
  if (!peer.we_dial) {
    return Result<void>::success();
  }
  if (!endpoint_.has_value() || !endpoint_->valid()) {
    peer.connection_state = P2pPeerConnectionState::dial_pending;
    return fail_void(ErrorCode::unsupported, P2pPartyError::endpoint_unavailable);
  }
  mp::PartyMemberRecord member{
      peer.device_id,
      peer.account_id,
      peer.root_pubkey,
      peer.device_pubkey,
      {},
      peer.endpoint,
      peer.joined_seq,
      peer.control_plane_connected,
  };
  const auto target = endpoint_descriptor_to_p2p_target(member, relay_policy_,
                                                        config_.connect_timeout_ms);
  if (!target.has_value()) {
    peer.connection_state = P2pPeerConnectionState::dial_pending;
    return Result<void>::failure(target.error());
  }
  const auto conn = endpoint_->connect_peer(target.value());
  if (!conn.has_value()) {
    peer.connection_state = P2pPeerConnectionState::dial_pending;
    return conn;
  }
  peer.connection_state = P2pPeerConnectionState::connected;
  return Result<void>::success();
}

bool P2pPartySession::is_peer_expired(const P2pPartyPeer &peer,
                                      std::int64_t now_s) const noexcept {
  if (now_s >= peer.cwt_exp_s) {
    return true;
  }
  if (config_.max_lease_ttl_s.has_value()) {
    const std::int64_t lease_deadline =
        saturating_add_i64(peer.last_confirmed_s, *config_.max_lease_ttl_s);
    if (now_s > lease_deadline) {
      return true;
    }
  }
  return false;
}

void P2pPartySession::revoke_all_and_disband() noexcept {
  disbanded_ = true;
  std::vector<P2pPubkey> pubkeys;
  pubkeys.reserve(peers_by_device_.size());
  for (const auto &[id, peer] : peers_by_device_) {
    (void)id;
    pubkeys.push_back(peer.device_pubkey);
  }
  peers_by_device_.clear();
  device_by_pubkey_.clear();
  if (endpoint_.has_value() && endpoint_->valid()) {
    for (const auto &pk : pubkeys) {
      (void)endpoint_->revoke_peer(pk);
    }
    (void)endpoint_->set_allowed_peers({});
  }
}

// ---------------------------------------------------------------------------
// Control-plane lifecycle handlers
// ---------------------------------------------------------------------------

Result<P2pPartySnapshotResult>
P2pPartySession::apply_snapshot(const mp::PartySnapshotMessage &snapshot,
                                std::int64_t now_s) {
  if (disbanded_) {
    return fail<P2pPartySnapshotResult>(ErrorCode::conflict,
                                        P2pPartyError::session_disbanded);
  }
  if (const auto epoch_ok = validate_party_epoch(snapshot.party_epoch);
      !epoch_ok.has_value()) {
    return Result<P2pPartySnapshotResult>::failure(epoch_ok.error());
  }
  if (snapshot.max_members < 2U || snapshot.max_members > mp::kMaxPartyMembers) {
    return fail<P2pPartySnapshotResult>(ErrorCode::invalid_range,
                                        P2pPartyError::invalid_party_member_count);
  }
  if (party_id_.has_value()) {
    if (snapshot.party_id != *party_id_) {
      return fail<P2pPartySnapshotResult>(ErrorCode::conflict,
                                          P2pPartyError::party_id_mismatch);
    }
    if (snapshot.party_epoch < party_epoch_) {
      return fail<P2pPartySnapshotResult>(ErrorCode::conflict,
                                          P2pPartyError::stale_party_epoch);
    }
    if (snapshot.relay_policy != relay_policy_ ||
        snapshot.pinned_relay_url != pinned_relay_url_) {
      return fail<P2pPartySnapshotResult>(ErrorCode::conflict,
                                          P2pPartyError::relay_policy_mismatch);
    }
    if (snapshot.max_members != max_members_) {
      return fail<P2pPartySnapshotResult>(ErrorCode::conflict,
                                          P2pPartyError::invalid_party_member_count);
    }
  }
  if (snapshot.members.size() > snapshot.max_members) {
    return fail<P2pPartySnapshotResult>(ErrorCode::capacity,
                                        P2pPartyError::invalid_party_member_count);
  }
  if (const auto pin_ok = mp::validate_pinned_relay_url(snapshot.relay_policy,
                                                        snapshot.pinned_relay_url);
      !pin_ok.has_value()) {
    return Result<P2pPartySnapshotResult>::failure(pin_ok.error());
  }
  if (!relay_policy_compatible(
          LocalRelayPolicy{config_.local_relay_policy},
          RemoteRelayPolicy{to_p2p_relay_policy(snapshot.relay_policy)})) {
    return fail<P2pPartySnapshotResult>(ErrorCode::conflict,
                                        P2pPartyError::relay_policy_mismatch);
  }

  P2pPartySnapshotResult report{};
  std::map<mp::DeviceId, P2pPartyPeer> next_peers;
  std::map<P2pPubkey, mp::DeviceId> next_by_pubkey;
  std::set<mp::DeviceId> seen_remote_ids;
  std::vector<mp::DeviceId> need_dial;

  for (const auto &member : snapshot.members) {
    if (member.device_id == config_.local_device_id) {
      continue;
    }
    if (next_peers.size() + 1U >= snapshot.max_members) {
      report.rejected_members.push_back(P2pPartyPeerFailure{
          member.device_id,
          {ErrorCode::capacity,
           static_cast<std::int64_t>(P2pPartyError::invalid_party_member_count)},
      });
      continue;
    }
    if (!seen_remote_ids.insert(member.device_id).second) {
      report.rejected_members.push_back(P2pPartyPeerFailure{
          member.device_id,
          {ErrorCode::conflict,
           static_cast<std::int64_t>(P2pPartyError::duplicate_device_id)},
      });
      continue;
    }
    if (local_pubkey_.has_value() && member.device_pubkey == *local_pubkey_) {
      report.rejected_members.push_back(P2pPartyPeerFailure{
          member.device_id,
          {ErrorCode::conflict,
           static_cast<std::int64_t>(P2pPartyError::duplicate_device_pubkey)},
      });
      continue;
    }
    if (next_by_pubkey.contains(member.device_pubkey)) {
      report.rejected_members.push_back(P2pPartyPeerFailure{
          member.device_id,
          {ErrorCode::conflict,
           static_cast<std::int64_t>(P2pPartyError::duplicate_device_pubkey)},
      });
      continue;
    }
    const auto claims = mp::verify_party_member_cwt(member, now_s);
    if (!claims.has_value()) {
      report.rejected_members.push_back(
          P2pPartyPeerFailure{member.device_id, claims.error()});
      continue;
    }
    const auto ep_ok = validate_endpoint_for_session(
        member.endpoint, snapshot.relay_policy, snapshot.pinned_relay_url);
    if (!ep_ok.has_value()) {
      report.rejected_members.push_back(
          P2pPartyPeerFailure{member.device_id, ep_ok.error()});
      continue;
    }
    const auto target_ok = endpoint_descriptor_to_p2p_target(
        member, snapshot.relay_policy, config_.connect_timeout_ms);
    if (!target_ok.has_value()) {
      report.rejected_members.push_back(
          P2pPartyPeerFailure{member.device_id, target_ok.error()});
      continue;
    }

    const bool we_dial =
        should_dial_peer(LocalDeviceId{config_.local_device_id.value()},
                         PeerDeviceId{member.device_id.value()});
    P2pPeerConnectionState conn_state = we_dial ? P2pPeerConnectionState::dial_pending
                                                : P2pPeerConnectionState::admitted;
    bool should_trigger_dial = we_dial;

    if (const auto old_it = peers_by_device_.find(member.device_id);
        old_it != peers_by_device_.end() &&
        old_it->second.device_pubkey == member.device_pubkey &&
        old_it->second.account_id == member.account_id &&
        old_it->second.root_pubkey == member.root_pubkey) {
      if (old_it->second.connection_state == P2pPeerConnectionState::connected &&
          old_it->second.endpoint == member.endpoint) {
        conn_state = P2pPeerConnectionState::connected;
        should_trigger_dial = false;
      }
    }

    P2pPartyPeer peer{
        member.device_id,
        member.account_id,
        member.root_pubkey,
        member.device_pubkey,
        member.endpoint,
        member.joined_seq,
        member.connected,
        claims.value().iat,
        claims.value().exp,
        now_s,
        we_dial,
        conn_state,
    };
    next_peers.emplace(member.device_id, std::move(peer));
    next_by_pubkey.emplace(member.device_pubkey, member.device_id);
    report.admitted_peers.push_back(member.device_id);
    if (should_trigger_dial) {
      need_dial.push_back(member.device_id);
    }
  }

  // Compute pubkeys that are no longer admitted OR whose identity binding
  // (device_id, account_id, or root_pubkey) changed, so existing QUIC
  // connections are always severed with 4403.
  std::vector<std::pair<mp::DeviceId, P2pPubkey>> to_revoke_removed;
  std::vector<std::pair<mp::DeviceId, P2pPubkey>> to_revoke_rebound;
  for (const auto &[old_id, old_peer] : peers_by_device_) {
    const auto next_pk_it = next_by_pubkey.find(old_peer.device_pubkey);
    if (next_pk_it == next_by_pubkey.end()) {
      to_revoke_removed.emplace_back(old_id, old_peer.device_pubkey);
      continue;
    }
    const auto next_peer_it = next_peers.find(next_pk_it->second);
    if (next_peer_it == next_peers.end() || next_peer_it->first != old_id ||
        next_peer_it->second.account_id != old_peer.account_id ||
        next_peer_it->second.root_pubkey != old_peer.root_pubkey) {
      to_revoke_rebound.emplace_back(old_id, old_peer.device_pubkey);
    }
  }

  // Sync new allowlist into the live iroh endpoint BEFORE committing state so a
  // transport allowlist failure leaves prior state untouched. Rebound pubkeys
  // are revoked first (closing their old QUIC connection with 4403) and then
  // re-allowlisted via set_allowed_peers so a fresh handshake is forced.
  if (endpoint_.has_value() && endpoint_->valid()) {
    std::vector<P2pPubkey> next_allowed;
    next_allowed.reserve(next_peers.size());
    for (const auto &[id, peer] : next_peers) {
      (void)id;
      next_allowed.push_back(peer.device_pubkey);
    }
    for (const auto &[old_id, old_pk] : to_revoke_rebound) {
      (void)endpoint_->revoke_peer(old_pk);
      report.revoked_peers.push_back(old_id);
    }
    if (const auto sync_ok = endpoint_->set_allowed_peers(next_allowed);
        !sync_ok.has_value()) {
      return Result<P2pPartySnapshotResult>::failure(sync_ok.error());
    }
    for (const auto &[old_id, old_pk] : to_revoke_removed) {
      (void)endpoint_->revoke_peer(old_pk);
      report.revoked_peers.push_back(old_id);
    }
  } else {
    for (const auto &[old_id, old_pk] : to_revoke_rebound) {
      (void)old_pk;
      report.revoked_peers.push_back(old_id);
    }
    for (const auto &[old_id, old_pk] : to_revoke_removed) {
      (void)old_pk;
      report.revoked_peers.push_back(old_id);
    }
  }

  party_id_ = snapshot.party_id;
  party_epoch_ = snapshot.party_epoch;
  leader_account_id_ = snapshot.leader_account_id;
  leader_device_id_ = snapshot.leader_device_id;
  relay_policy_ = snapshot.relay_policy;
  max_members_ = snapshot.max_members;
  pinned_relay_url_ = snapshot.pinned_relay_url;
  peers_by_device_ = std::move(next_peers);
  device_by_pubkey_ = std::move(next_by_pubkey);

  if (config_.auto_dial && endpoint_.has_value() && endpoint_->valid()) {
    for (const auto dev_id : need_dial) {
      auto it = peers_by_device_.find(dev_id);
      if (it == peers_by_device_.end()) {
        continue;
      }
      if (const auto dial_ok = dial_peer_record(it->second); !dial_ok.has_value()) {
        report.dial_failures.push_back(P2pPartyPeerFailure{dev_id, dial_ok.error()});
      }
    }
  }

  return Result<P2pPartySnapshotResult>::success(std::move(report));
}

Result<void>
P2pPartySession::apply_member_joined(const mp::PartyMemberJoinedMessage &message,
                                     std::int64_t now_s) {
  if (disbanded_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::session_disbanded);
  }
  if (!party_id_.has_value()) {
    return fail_void(ErrorCode::conflict, P2pPartyError::no_active_party);
  }
  if (const auto epoch_ok = validate_party_epoch(message.party_epoch);
      !epoch_ok.has_value()) {
    return epoch_ok;
  }
  if (message.party_epoch < party_epoch_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::stale_party_epoch);
  }
  if (!relay_policy_compatible(LocalRelayPolicy{config_.local_relay_policy},
                               RemoteRelayPolicy{to_p2p_relay_policy(relay_policy_)})) {
    return fail_void(ErrorCode::conflict, P2pPartyError::relay_policy_mismatch);
  }

  const auto &member = message.member;
  if (member.device_id == config_.local_device_id) {
    party_epoch_ = message.party_epoch;
    return Result<void>::success();
  }

  const bool is_new_device = !peers_by_device_.contains(member.device_id);
  if (is_new_device && peers_by_device_.size() + 1U >= max_members_) {
    return fail_void(ErrorCode::capacity, P2pPartyError::invalid_party_member_count);
  }
  if (local_pubkey_.has_value() && member.device_pubkey == *local_pubkey_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::duplicate_device_pubkey);
  }
  if (const auto pk_it = device_by_pubkey_.find(member.device_pubkey);
      pk_it != device_by_pubkey_.end() && pk_it->second != member.device_id) {
    return fail_void(ErrorCode::conflict, P2pPartyError::duplicate_device_pubkey);
  }

  const auto claims = mp::verify_party_member_cwt(member, now_s);
  if (!claims.has_value()) {
    return Result<void>::failure(claims.error());
  }
  if (const auto ep_ok = validate_endpoint_for_session(member.endpoint, relay_policy_,
                                                       pinned_relay_url_);
      !ep_ok.has_value()) {
    return ep_ok;
  }
  if (const auto tgt_ok = endpoint_descriptor_to_p2p_target(member, relay_policy_,
                                                            config_.connect_timeout_ms);
      !tgt_ok.has_value()) {
    return Result<void>::failure(tgt_ok.error());
  }

  const bool we_dial = should_dial_peer(LocalDeviceId{config_.local_device_id.value()},
                                        PeerDeviceId{member.device_id.value()});
  P2pPeerConnectionState conn_state =
      we_dial ? P2pPeerConnectionState::dial_pending : P2pPeerConnectionState::admitted;
  std::optional<P2pPubkey> replaced_old_pk;
  std::optional<P2pPubkey> rebound_same_pk;
  bool should_dial = we_dial;

  if (const auto old_it = peers_by_device_.find(member.device_id);
      old_it != peers_by_device_.end()) {
    if (old_it->second.device_pubkey != member.device_pubkey) {
      replaced_old_pk = old_it->second.device_pubkey;
    } else if (old_it->second.account_id != member.account_id ||
               old_it->second.root_pubkey != member.root_pubkey) {
      rebound_same_pk = member.device_pubkey;
    } else if (old_it->second.connection_state == P2pPeerConnectionState::connected &&
               old_it->second.endpoint == member.endpoint) {
      conn_state = P2pPeerConnectionState::connected;
      should_dial = false;
    }
  }

  // Build candidate allowlist and sync to endpoint before committing state.
  // If an existing device_pubkey changed account_id/root_pubkey, revoke first to
  // sever the live QUIC connection with 4403, then re-allowlist for a fresh handshake.
  if (endpoint_.has_value() && endpoint_->valid()) {
    std::vector<P2pPubkey> next_allowed;
    next_allowed.reserve(peers_by_device_.size() + 1U);
    for (const auto &[id, existing] : peers_by_device_) {
      if (id == member.device_id) {
        continue;
      }
      next_allowed.push_back(existing.device_pubkey);
    }
    next_allowed.push_back(member.device_pubkey);
    if (rebound_same_pk.has_value()) {
      (void)endpoint_->revoke_peer(*rebound_same_pk);
    }
    if (const auto sync_ok = endpoint_->set_allowed_peers(next_allowed);
        !sync_ok.has_value()) {
      return sync_ok;
    }
    if (replaced_old_pk.has_value()) {
      (void)endpoint_->revoke_peer(*replaced_old_pk);
    }
  }

  if (replaced_old_pk.has_value()) {
    device_by_pubkey_.erase(*replaced_old_pk);
  }

  P2pPartyPeer peer{
      member.device_id,
      member.account_id,
      member.root_pubkey,
      member.device_pubkey,
      member.endpoint,
      member.joined_seq,
      member.connected,
      claims.value().iat,
      claims.value().exp,
      now_s,
      we_dial,
      conn_state,
  };
  peers_by_device_.insert_or_assign(member.device_id, std::move(peer));
  device_by_pubkey_.insert_or_assign(member.device_pubkey, member.device_id);
  party_epoch_ = message.party_epoch;

  if (should_dial && config_.auto_dial && endpoint_.has_value() && endpoint_->valid()) {
    auto it = peers_by_device_.find(member.device_id);
    if (it != peers_by_device_.end()) {
      (void)dial_peer_record(it->second);
    }
  }

  return Result<void>::success();
}

Result<void>
P2pPartySession::apply_member_updated(const mp::PartyMemberUpdatedMessage &message,
                                      std::int64_t now_s) {
  if (disbanded_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::session_disbanded);
  }
  if (!party_id_.has_value()) {
    return fail_void(ErrorCode::conflict, P2pPartyError::no_active_party);
  }
  if (const auto epoch_ok = validate_party_epoch(message.party_epoch);
      !epoch_ok.has_value()) {
    return epoch_ok;
  }
  if (message.party_epoch < party_epoch_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::stale_party_epoch);
  }
  if (message.device_id == config_.local_device_id) {
    party_epoch_ = message.party_epoch;
    return Result<void>::success();
  }

  auto it = peers_by_device_.find(message.device_id);
  if (it == peers_by_device_.end()) {
    return fail_void(ErrorCode::invalid_identity, P2pPartyError::peer_not_found);
  }

  if (const auto ep_ok = validate_endpoint_for_session(message.endpoint, relay_policy_,
                                                       pinned_relay_url_);
      !ep_ok.has_value()) {
    return ep_ok;
  }

  mp::PartyMemberRecord candidate{
      it->second.device_id,     it->second.account_id, it->second.root_pubkey,
      it->second.device_pubkey, message.device_cwt,    message.endpoint,
      it->second.joined_seq,    message.connected,
  };
  if (const auto tgt_ok = endpoint_descriptor_to_p2p_target(candidate, relay_policy_,
                                                            config_.connect_timeout_ms);
      !tgt_ok.has_value()) {
    return Result<void>::failure(tgt_ok.error());
  }

  std::int64_t next_iat_s = it->second.cwt_iat_s;
  std::int64_t next_exp_s = it->second.cwt_exp_s;
  if (!message.device_cwt.empty()) {
    const auto claims = mp::verify_party_member_cwt(candidate, now_s);
    if (!claims.has_value()) {
      return Result<void>::failure(claims.error());
    }
    next_iat_s = claims.value().iat;
    next_exp_s = claims.value().exp;
  } else if (now_s >= it->second.cwt_exp_s) {
    return Result<void>::failure({ErrorCode::provider_auth,
                                  static_cast<std::int64_t>(mp::MpError::cwt_expired)});
  }

  const bool endpoint_changed = (it->second.endpoint != message.endpoint);
  it->second.endpoint = message.endpoint;
  it->second.control_plane_connected = message.connected;
  it->second.cwt_iat_s = next_iat_s;
  it->second.cwt_exp_s = next_exp_s;
  it->second.last_confirmed_s = now_s;
  party_epoch_ = message.party_epoch;

  if (it->second.we_dial &&
      (endpoint_changed ||
       it->second.connection_state != P2pPeerConnectionState::connected)) {
    if (it->second.connection_state != P2pPeerConnectionState::connected) {
      it->second.connection_state = P2pPeerConnectionState::dial_pending;
    }
    if (config_.auto_dial && endpoint_.has_value() && endpoint_->valid()) {
      (void)dial_peer_record(it->second);
    }
  }

  return Result<void>::success();
}

Result<void>
P2pPartySession::apply_member_left(const mp::PartyMemberLeftMessage &message) {
  if (disbanded_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::session_disbanded);
  }
  if (!party_id_.has_value()) {
    return fail_void(ErrorCode::conflict, P2pPartyError::no_active_party);
  }
  if (const auto epoch_ok = validate_party_epoch(message.party_epoch);
      !epoch_ok.has_value()) {
    return epoch_ok;
  }
  if (message.party_epoch < party_epoch_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::stale_party_epoch);
  }
  party_epoch_ = message.party_epoch;

  if (message.device_id == config_.local_device_id) {
    revoke_all_and_disband();
    return Result<void>::success();
  }

  const auto it = peers_by_device_.find(message.device_id);
  if (it == peers_by_device_.end()) {
    return Result<void>::success();
  }
  const P2pPubkey pubkey = it->second.device_pubkey;
  device_by_pubkey_.erase(pubkey);
  peers_by_device_.erase(it);

  if (endpoint_.has_value() && endpoint_->valid()) {
    const auto sync_res = sync_allowlist_to_endpoint();
    Result<void> revoke_res = Result<void>::success();
    if (endpoint_.has_value() && endpoint_->valid()) {
      revoke_res = endpoint_->revoke_peer(pubkey);
    }
    if (!revoke_res.has_value()) {
      return revoke_res;
    }
    if (!sync_res.has_value()) {
      return sync_res;
    }
  }

  return Result<void>::success();
}

Result<void>
P2pPartySession::apply_leader_changed(const mp::PartyLeaderChangedMessage &message) {
  if (disbanded_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::session_disbanded);
  }
  if (!party_id_.has_value()) {
    return fail_void(ErrorCode::conflict, P2pPartyError::no_active_party);
  }
  if (const auto epoch_ok = validate_party_epoch(message.party_epoch);
      !epoch_ok.has_value()) {
    return epoch_ok;
  }
  if (message.party_epoch < party_epoch_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::stale_party_epoch);
  }
  party_epoch_ = message.party_epoch;
  leader_account_id_ = message.new_leader_account_id;
  leader_device_id_ = message.new_leader_device_id;
  return Result<void>::success();
}

Result<void>
P2pPartySession::apply_disbanded(const mp::PartyDisbandedMessage &message) {
  if (!party_id_.has_value()) {
    return fail_void(ErrorCode::conflict, P2pPartyError::no_active_party);
  }
  if (const auto epoch_ok = validate_party_epoch(message.party_epoch);
      !epoch_ok.has_value()) {
    return epoch_ok;
  }
  if (message.party_epoch < party_epoch_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::stale_party_epoch);
  }
  party_epoch_ = message.party_epoch;
  revoke_all_and_disband();
  return Result<void>::success();
}

// ---------------------------------------------------------------------------
// Lease-TTL & CWT expiry eviction
// ---------------------------------------------------------------------------

Result<std::vector<mp::DeviceId>>
P2pPartySession::evict_expired_peers(std::int64_t now_s) {
  std::vector<mp::DeviceId> evicted_ids;
  std::vector<P2pPubkey> evicted_pubkeys;

  for (const auto &[id, peer] : peers_by_device_) {
    if (is_peer_expired(peer, now_s)) {
      evicted_ids.push_back(id);
      evicted_pubkeys.push_back(peer.device_pubkey);
    }
  }
  if (evicted_ids.empty()) {
    return Result<std::vector<mp::DeviceId>>::success(std::move(evicted_ids));
  }

  for (std::size_t i = 0U; i < evicted_ids.size(); ++i) {
    peers_by_device_.erase(evicted_ids[i]);
    device_by_pubkey_.erase(evicted_pubkeys[i]);
  }

  if (endpoint_.has_value() && endpoint_->valid()) {
    std::optional<Error> first_err;
    for (const auto &pk : evicted_pubkeys) {
      if (const auto rev_ok = endpoint_->revoke_peer(pk);
          !rev_ok.has_value() && !first_err.has_value()) {
        first_err = rev_ok.error();
      }
    }
    if (const auto sync_ok = sync_allowlist_to_endpoint();
        !sync_ok.has_value() && !first_err.has_value()) {
      first_err = sync_ok.error();
    }
    if (first_err.has_value()) {
      return Result<std::vector<mp::DeviceId>>::failure(*first_err);
    }
  }

  return Result<std::vector<mp::DeviceId>>::success(std::move(evicted_ids));
}

Result<void> P2pPartySession::refresh_all_leases(std::int64_t now_s) {
  if (disbanded_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::session_disbanded);
  }
  if (!party_id_.has_value()) {
    return fail_void(ErrorCode::conflict, P2pPartyError::no_active_party);
  }
  for (auto &[id, peer] : peers_by_device_) {
    (void)id;
    if (now_s > peer.last_confirmed_s) {
      peer.last_confirmed_s = now_s;
    }
  }
  return Result<void>::success();
}

// ---------------------------------------------------------------------------
// Deterministic dialer helper
// ---------------------------------------------------------------------------

Result<P2pPartyConnectResult> P2pPartySession::connect_pending_peers() {
  if (disbanded_) {
    return fail<P2pPartyConnectResult>(ErrorCode::conflict,
                                       P2pPartyError::session_disbanded);
  }
  if (!party_id_.has_value()) {
    return fail<P2pPartyConnectResult>(ErrorCode::conflict,
                                       P2pPartyError::no_active_party);
  }
  if (!endpoint_.has_value() || !endpoint_->valid()) {
    return fail<P2pPartyConnectResult>(ErrorCode::unsupported,
                                       P2pPartyError::endpoint_unavailable);
  }

  P2pPartyConnectResult result{};
  for (auto &[id, peer] : peers_by_device_) {
    if (!peer.we_dial || peer.connection_state == P2pPeerConnectionState::connected) {
      continue;
    }
    ++result.attempted;
    if (const auto dial_ok = dial_peer_record(peer); dial_ok.has_value()) {
      ++result.connected;
    } else {
      result.failures.push_back(P2pPartyPeerFailure{id, dial_ok.error()});
    }
  }
  return Result<P2pPartyConnectResult>::success(std::move(result));
}

// ---------------------------------------------------------------------------
// Typed data-plane senders
// ---------------------------------------------------------------------------

Result<void> P2pPartySession::send_frame_to_device(mp::DeviceId device_id,
                                                   const P2pPartyFrame &frame) {
  if (disbanded_) {
    return fail_void(ErrorCode::conflict, P2pPartyError::session_disbanded);
  }
  if (!party_id_.has_value()) {
    return fail_void(ErrorCode::conflict, P2pPartyError::no_active_party);
  }
  if (device_id == config_.local_device_id) {
    return fail_void(ErrorCode::invalid_range, P2pPartyError::self_target_disallowed);
  }
  const auto encoded = encode_p2p_party_frame(frame);
  if (!encoded.has_value()) {
    return Result<void>::failure(encoded.error());
  }
  const auto it = peers_by_device_.find(device_id);
  if (it == peers_by_device_.end()) {
    return fail_void(ErrorCode::invalid_identity, P2pPartyError::peer_not_found);
  }
  if (!endpoint_.has_value() || !endpoint_->valid()) {
    return fail_void(ErrorCode::unsupported, P2pPartyError::endpoint_unavailable);
  }
  const P2pLane lane = p2p_party_frame_lane(p2p_party_frame_kind(frame));
  return endpoint_->send_frame(it->second.device_pubkey, lane, encoded.value());
}

Result<P2pPartyBroadcastResult>
P2pPartySession::broadcast_frame(const P2pPartyFrame &frame) {
  if (disbanded_) {
    return fail<P2pPartyBroadcastResult>(ErrorCode::conflict,
                                         P2pPartyError::session_disbanded);
  }
  if (!party_id_.has_value()) {
    return fail<P2pPartyBroadcastResult>(ErrorCode::conflict,
                                         P2pPartyError::no_active_party);
  }
  const auto encoded = encode_p2p_party_frame(frame);
  if (!encoded.has_value()) {
    return Result<P2pPartyBroadcastResult>::failure(encoded.error());
  }
  if (!endpoint_.has_value() || !endpoint_->valid()) {
    return fail<P2pPartyBroadcastResult>(ErrorCode::unsupported,
                                         P2pPartyError::endpoint_unavailable);
  }
  const P2pLane lane = p2p_party_frame_lane(p2p_party_frame_kind(frame));
  P2pPartyBroadcastResult out{};
  for (const auto &[id, peer] : peers_by_device_) {
    ++out.attempted;
    if (const auto ok =
            endpoint_->send_frame(peer.device_pubkey, lane, encoded.value());
        ok.has_value()) {
      ++out.sent;
    } else {
      out.failures.push_back(P2pPartyPeerFailure{id, ok.error()});
    }
  }
  return Result<P2pPartyBroadcastResult>::success(std::move(out));
}

Result<P2pPartyBroadcastResult>
P2pPartySession::broadcast_chat(const P2pPartyChatMessage &message) {
  return broadcast_frame(P2pPartyFrame{message});
}

Result<void> P2pPartySession::send_chat_to(mp::DeviceId device_id,
                                           const P2pPartyChatMessage &message) {
  return send_frame_to_device(device_id, P2pPartyFrame{message});
}

Result<P2pPartyBroadcastResult>
P2pPartySession::broadcast_bridge_envelope(const P2pPartyBridgeEnvelope &envelope) {
  return broadcast_frame(P2pPartyFrame{envelope});
}

Result<void>
P2pPartySession::send_bridge_envelope_to(mp::DeviceId device_id,
                                         const P2pPartyBridgeEnvelope &envelope) {
  return send_frame_to_device(device_id, P2pPartyFrame{envelope});
}

Result<P2pPartyBroadcastResult>
P2pPartySession::broadcast_control_notice(const P2pPartyControlNotice &notice) {
  return broadcast_frame(P2pPartyFrame{notice});
}

Result<void>
P2pPartySession::send_control_notice_to(mp::DeviceId device_id,
                                        const P2pPartyControlNotice &notice) {
  return send_frame_to_device(device_id, P2pPartyFrame{notice});
}

Result<P2pPartyBroadcastResult>
P2pPartySession::broadcast_ephemeral_pulse(const P2pPartyEphemeralPulse &pulse) {
  return broadcast_frame(P2pPartyFrame{pulse});
}

Result<void>
P2pPartySession::send_ephemeral_pulse_to(mp::DeviceId device_id,
                                         const P2pPartyEphemeralPulse &pulse) {
  return send_frame_to_device(device_id, P2pPartyFrame{pulse});
}

// ---------------------------------------------------------------------------
// Inbound event polling & strict anti-spoofing attribution
// ---------------------------------------------------------------------------

Result<std::optional<P2pPartyEvent>>
P2pPartySession::poll_event(PollTimeoutMs timeout_ms, PartyNowSeconds now_s) {
  if (!endpoint_.has_value() || !endpoint_->valid()) {
    return fail<std::optional<P2pPartyEvent>>(ErrorCode::unsupported,
                                              P2pPartyError::endpoint_unavailable);
  }
  if (const auto evict_ok = evict_expired_peers(now_s.value); !evict_ok.has_value()) {
    return Result<std::optional<P2pPartyEvent>>::failure(evict_ok.error());
  }
  if (!endpoint_.has_value() || !endpoint_->valid()) {
    return fail<std::optional<P2pPartyEvent>>(ErrorCode::unsupported,
                                              P2pPartyError::endpoint_unavailable);
  }
  auto polled = endpoint_->poll_event(timeout_ms.value);
  if (!polled.has_value()) {
    return Result<std::optional<P2pPartyEvent>>::failure(polled.error());
  }
  const auto &raw_event = polled.value();
  if (!raw_event.has_value()) {
    return Result<std::optional<P2pPartyEvent>>::success(std::nullopt);
  }
  return Result<std::optional<P2pPartyEvent>>::success(
      ingest_transport_event(*raw_event, now_s.value));
}

P2pPartyEvent P2pPartySession::ingest_transport_event(const P2pEvent &event,
                                                      std::int64_t now_s) {
  P2pPartyEvent out{};
  out.lane = event.lane;
  out.peer_pubkey = event.peer_pubkey;
  out.reason_code = event.reason_code;

  const auto pk_it = device_by_pubkey_.find(event.peer_pubkey);
  const bool in_roster = (pk_it != device_by_pubkey_.end());

  if (event.kind == P2pEventKind::peer_disconnected) {
    out.kind = P2pPartyEventKind::peer_disconnected;
    if (in_roster) {
      auto peer_it = peers_by_device_.find(pk_it->second);
      if (peer_it != peers_by_device_.end()) {
        peer_it->second.connection_state = P2pPeerConnectionState::disconnected;
        out.sender_device_id = peer_it->second.device_id;
        out.sender_account_id = peer_it->second.account_id;
      }
    }
    return out;
  }

  if (!in_roster) {
    out.kind = P2pPartyEventKind::frame_dropped;
    out.drop_error =
        Error{ErrorCode::invalid_identity,
              static_cast<std::int64_t>(P2pPartyError::frame_unverified_sender)};
    if (event.kind == P2pEventKind::peer_connected && endpoint_.has_value() &&
        endpoint_->valid()) {
      (void)endpoint_->revoke_peer(event.peer_pubkey);
    }
    return out;
  }

  auto peer_it = peers_by_device_.find(pk_it->second);
  if (peer_it == peers_by_device_.end()) {
    out.kind = P2pPartyEventKind::frame_dropped;
    out.drop_error =
        Error{ErrorCode::invalid_identity,
              static_cast<std::int64_t>(P2pPartyError::frame_unverified_sender)};
    return out;
  }

  const mp::DeviceId auth_device_id = peer_it->second.device_id;
  const mp::AccountId auth_account_id = peer_it->second.account_id;

  if (is_peer_expired(peer_it->second, now_s)) {
    const P2pPubkey expired_pk = peer_it->second.device_pubkey;
    peers_by_device_.erase(peer_it);
    device_by_pubkey_.erase(expired_pk);
    if (endpoint_.has_value() && endpoint_->valid()) {
      (void)endpoint_->revoke_peer(expired_pk);
      (void)sync_allowlist_to_endpoint();
    }
    out.kind = P2pPartyEventKind::frame_dropped;
    out.sender_device_id = auth_device_id;
    out.sender_account_id = auth_account_id;
    out.drop_error =
        Error{ErrorCode::provider_auth,
              static_cast<std::int64_t>(P2pPartyError::peer_lease_expired)};
    return out;
  }

  if (event.kind == P2pEventKind::peer_connected) {
    peer_it->second.connection_state = P2pPeerConnectionState::connected;
    out.kind = P2pPartyEventKind::peer_connected;
    out.sender_device_id = auth_device_id;
    out.sender_account_id = auth_account_id;
    return out;
  }

  if (event.kind == P2pEventKind::frame_received) {
    auto decoded = decode_p2p_party_frame(event.lane, event.payload);
    out.sender_device_id = auth_device_id;
    out.sender_account_id = auth_account_id;
    if (!decoded.has_value()) {
      out.kind = P2pPartyEventKind::frame_dropped;
      out.drop_error = decoded.error();
      return out;
    }
    out.kind = P2pPartyEventKind::frame_received;
    out.frame = std::move(decoded).value();
    return out;
  }

  out.kind = P2pPartyEventKind::frame_dropped;
  out.drop_error = Error{ErrorCode::corrupt,
                         static_cast<std::int64_t>(P2pPartyError::frame_unknown_kind)};
  return out;
}

} // namespace blackbird
