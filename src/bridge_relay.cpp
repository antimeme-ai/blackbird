#include "blackbird/bridge_relay.hpp"

#include "blackbird/json.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <limits>
#include <ranges>
#include <set>
#include <utility>

namespace blackbird {
namespace {

constexpr std::size_t kMaxActorIdBytes = 128;
constexpr std::size_t kMaxRoomIdBytes = 128;
constexpr std::size_t kMaxUntrustedSourceBytes = 512;

std::int64_t wall_now_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return ns <= 0 ? 1 : static_cast<std::int64_t>(ns);
}

bool valid_safe_token(std::string_view value, std::size_t max_len) noexcept {
  if (value.empty() || value.size() > max_len)
    return false;
  for (const char ch : value) {
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' ||
                    ch == ':';
    if (!ok)
      return false;
  }
  return true;
}

bool valid_utf8_no_ctrl(std::string_view value, std::size_t max_len,
                        bool allow_empty) noexcept {
  if (value.empty())
    return allow_empty;
  if (value.size() > max_len || !valid_utf8(value))
    return false;
  for (const char ch : value) {
    const auto u = static_cast<unsigned char>(ch);
    if (u < 0x20 || u == 0x7f)
      return false;
  }
  return true;
}

bool valid_relay_lane(RelayLane lane) noexcept {
  return lane == RelayLane::control || lane == RelayLane::causal ||
         lane == RelayLane::presence;
}

bool valid_base64_or_url_syntax(std::string_view input, std::size_t max_len) noexcept {
  if (input.empty() || input.size() > max_len)
    return false;
  bool saw_std = false;
  bool saw_url = false;
  bool saw_pad = false;
  std::size_t pad_count = 0;
  for (const char ch : input) {
    if (ch == '=') {
      saw_pad = true;
      ++pad_count;
      if (pad_count > 2)
        return false;
      continue;
    }
    if (saw_pad)
      return false;
    const bool alnum = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                       (ch >= '0' && ch <= '9');
    if (alnum)
      continue;
    if (ch == '+' || ch == '/') {
      saw_std = true;
      continue;
    }
    if (ch == '-' || ch == '_') {
      saw_url = true;
      continue;
    }
    return false;
  }
  if (saw_std && saw_url)
    return false;
  if (saw_pad) {
    if ((input.size() % 4) != 0)
      return false;
  } else {
    if ((input.size() % 4) == 1)
      return false;
  }
  return true;
}

std::string base64url_encode(std::string_view bytes) {
  static constexpr std::string_view kAlphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve(((bytes.size() + 2) / 3) * 4);
  std::size_t i = 0;
  while (i + 3 <= bytes.size()) {
    const auto b0 = static_cast<unsigned char>(bytes[i]);
    const auto b1 = static_cast<unsigned char>(bytes[i + 1]);
    const auto b2 = static_cast<unsigned char>(bytes[i + 2]);
    const auto triple = (static_cast<std::uint32_t>(b0) << 16U) |
                        (static_cast<std::uint32_t>(b1) << 8U) |
                        static_cast<std::uint32_t>(b2);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
    out.push_back(kAlphabet[triple & 0x3fU]);
    i += 3;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1) {
    const auto b0 = static_cast<unsigned char>(bytes[i]);
    const auto triple = static_cast<std::uint32_t>(b0) << 16U;
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
  } else if (rem == 2) {
    const auto b0 = static_cast<unsigned char>(bytes[i]);
    const auto b1 = static_cast<unsigned char>(bytes[i + 1]);
    const auto triple = (static_cast<std::uint32_t>(b0) << 16U) |
                        (static_cast<std::uint32_t>(b1) << 8U);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
  }
  return out;
}

Result<std::string> base64url_decode_strict(std::string_view input) {
  if (input.empty() || (input.size() % 4) == 1)
    return Result<std::string>::failure({ErrorCode::corrupt});

  auto decode_char = [](char ch) noexcept -> int {
    if (ch >= 'A' && ch <= 'Z')
      return ch - 'A';
    if (ch >= 'a' && ch <= 'z')
      return 26 + (ch - 'a');
    if (ch >= '0' && ch <= '9')
      return 52 + (ch - '0');
    if (ch == '-')
      return 62;
    if (ch == '_')
      return 63;
    return -1;
  };

  std::string out;
  out.reserve((input.size() / 4) * 3 + 2);
  std::size_t i = 0;
  while (i + 4 <= input.size()) {
    const int a = decode_char(input[i]);
    const int b = decode_char(input[i + 1]);
    const int c = decode_char(input[i + 2]);
    const int d = decode_char(input[i + 3]);
    if (a < 0 || b < 0 || c < 0 || d < 0)
      return Result<std::string>::failure({ErrorCode::corrupt});
    const auto triple = (static_cast<std::uint32_t>(a) << 18U) |
                        (static_cast<std::uint32_t>(b) << 12U) |
                        (static_cast<std::uint32_t>(c) << 6U) |
                        static_cast<std::uint32_t>(d);
    out.push_back(static_cast<char>((triple >> 16U) & 0xffU));
    out.push_back(static_cast<char>((triple >> 8U) & 0xffU));
    out.push_back(static_cast<char>(triple & 0xffU));
    i += 4;
  }

  const std::size_t rem = input.size() - i;
  if (rem == 2) {
    const int a = decode_char(input[i]);
    const int b = decode_char(input[i + 1]);
    if (a < 0 || b < 0 || (b & 0x0f) != 0)
      return Result<std::string>::failure({ErrorCode::corrupt});
    const auto triple =
        (static_cast<std::uint32_t>(a) << 18U) | (static_cast<std::uint32_t>(b) << 12U);
    out.push_back(static_cast<char>((triple >> 16U) & 0xffU));
  } else if (rem == 3) {
    const int a = decode_char(input[i]);
    const int b = decode_char(input[i + 1]);
    const int c = decode_char(input[i + 2]);
    if (a < 0 || b < 0 || c < 0 || (c & 0x03) != 0)
      return Result<std::string>::failure({ErrorCode::corrupt});
    const auto triple = (static_cast<std::uint32_t>(a) << 18U) |
                        (static_cast<std::uint32_t>(b) << 12U) |
                        (static_cast<std::uint32_t>(c) << 6U);
    out.push_back(static_cast<char>((triple >> 16U) & 0xffU));
    out.push_back(static_cast<char>((triple >> 8U) & 0xffU));
  }
  return Result<std::string>::success(std::move(out));
}

Result<void> validate_strict_object_keys(const Value::Object &obj,
                                         std::span<const std::string_view> expected) {
  if (obj.size() != expected.size())
    return Result<void>::failure({ErrorCode::corrupt});
  std::set<std::string_view> seen;
  for (const auto &[key, ignored] : obj) {
    (void)ignored;
    if (!std::ranges::contains(expected, std::string_view{key}))
      return Result<void>::failure({ErrorCode::corrupt});
    if (!seen.insert(key).second)
      return Result<void>::failure({ErrorCode::corrupt});
  }
  return Result<void>::success();
}

std::optional<std::string> parse_string_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return std::nullopt;
  const auto *str = std::get_if<std::string>(&field->value());
  if (!str)
    return std::nullopt;
  return *str;
}

std::optional<std::uint64_t> parse_uint64_field(const Value &obj,
                                                std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return std::nullopt;
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return std::nullopt;
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage()))
    return *u;
  if (const auto *s = std::get_if<std::int64_t>(&num->storage())) {
    if (*s >= 0)
      return static_cast<std::uint64_t>(*s);
  }
  return std::nullopt;
}

std::optional<std::int64_t> parse_int64_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return std::nullopt;
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return std::nullopt;
  if (const auto *s = std::get_if<std::int64_t>(&num->storage()))
    return *s;
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage())) {
    if (*u <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
      return static_cast<std::int64_t>(*u);
  }
  return std::nullopt;
}

std::optional<std::uint64_t> parse_uint64_value(const Value &field) {
  const auto *num = std::get_if<Number>(&field.value());
  if (!num)
    return std::nullopt;
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage()))
    return *u;
  if (const auto *s = std::get_if<std::int64_t>(&num->storage())) {
    if (*s >= 0)
      return static_cast<std::uint64_t>(*s);
  }
  return std::nullopt;
}

Result<void> validate_mux_config(const BridgeMuxConfig &config) noexcept {
  if (config.max_control_queue == 0 || config.max_causal_queue == 0 ||
      config.max_presence_queue == 0) {
    return Result<void>::failure({ErrorCode::invalid_range});
  }
  if (config.control_max_bytes == 0 ||
      config.control_max_bytes > kRelayControlMaxBytes ||
      config.causal_max_bytes == 0 || config.causal_max_bytes > kRelayCausalMaxBytes ||
      config.presence_max_bytes == 0 ||
      config.presence_max_bytes > kRelayPresenceMaxBytes) {
    return Result<void>::failure({ErrorCode::invalid_range});
  }
  return Result<void>::success();
}

Result<void> validate_checkpoint_fields(const BridgeCheckpoint &checkpoint,
                                        bool require_signature) {
  if (checkpoint.version != kBridgeCheckpointVersion)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_safe_token(checkpoint.room_id, kMaxRoomIdBytes))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (checkpoint.created_ns <= 0)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_peer_fingerprint(checkpoint.signer_fingerprint))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (checkpoint.actor_watermarks.size() > kCheckpointMaxEntries ||
      checkpoint.causal_frontier_hashes.size() > kCheckpointMaxEntries ||
      checkpoint.revoked_grant_ids.size() > kCheckpointMaxEntries ||
      checkpoint.lease_epochs.size() > kCheckpointMaxEntries) {
    return Result<void>::failure({ErrorCode::capacity});
  }
  for (const auto &[actor_id, seq] : checkpoint.actor_watermarks) {
    (void)seq;
    if (!valid_utf8_no_ctrl(actor_id, kMaxActorIdBytes, false))
      return Result<void>::failure({ErrorCode::invalid_range});
  }
  {
    std::set<std::string_view> seen_hashes;
    for (const auto &hash : checkpoint.causal_frontier_hashes) {
      if (!valid_sha256_hex(hash))
        return Result<void>::failure({ErrorCode::invalid_range});
      if (!seen_hashes.insert(hash).second)
        return Result<void>::failure({ErrorCode::corrupt});
    }
  }
  {
    std::set<std::string_view> seen_grants;
    for (const auto &grant_id : checkpoint.revoked_grant_ids) {
      if (!valid_safe_token(grant_id, kPeerMaxIdLength))
        return Result<void>::failure({ErrorCode::invalid_range});
      if (!seen_grants.insert(grant_id).second)
        return Result<void>::failure({ErrorCode::corrupt});
    }
  }
  for (const auto &[scope, epoch] : checkpoint.lease_epochs) {
    (void)epoch;
    if (!valid_utf8_no_ctrl(scope, kBoardBridgeMaxScopeBytes, false))
      return Result<void>::failure({ErrorCode::invalid_range});
  }
  if (require_signature) {
    if (checkpoint.signature.empty() ||
        checkpoint.signature.size() > kPeerMaxSignatureBytes ||
        !valid_utf8(checkpoint.signature) ||
        checkpoint.signature.find('\0') != std::string::npos) {
      return Result<void>::failure({ErrorCode::invalid_identity});
    }
  }
  return Result<void>::success();
}

Result<void> validate_relay_url(std::string_view url) noexcept {
  if (url.empty() || url.size() > kRoomInviteMaxUrlBytes || !valid_utf8(url))
    return Result<void>::failure({ErrorCode::invalid_range});
  std::string_view rest;
  if (url.starts_with("wss://")) {
    rest = url.substr(6);
  } else if (url.starts_with("https://")) {
    rest = url.substr(8);
  } else if (url.starts_with("quic://")) {
    rest = url.substr(7);
  } else {
    return Result<void>::failure({ErrorCode::invalid_range});
  }
  if (rest.empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  for (const char ch : url) {
    const auto u = static_cast<unsigned char>(ch);
    if (u <= 0x20 || u == 0x7f)
      return Result<void>::failure({ErrorCode::invalid_range});
    // Zero secrets in invite URLs: forbid embedded userinfo, queries, and fragments.
    if (ch == '@' || ch == '?' || ch == '#')
      return Result<void>::failure({ErrorCode::invalid_range});
  }
  const std::size_t slash = rest.find('/');
  const std::string_view authority =
      slash == std::string_view::npos ? rest : rest.substr(0, slash);
  if (authority.empty() || authority.front() == ':' || authority.back() == ':')
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

Result<RoomInvite> validate_and_canonicalize_invite(const RoomInvite &invite) {
  if (!valid_safe_token(invite.room_id, kMaxRoomIdBytes))
    return Result<RoomInvite>::failure({ErrorCode::invalid_range});
  auto url_ok = validate_relay_url(invite.relay_url);
  if (!url_ok.has_value())
    return Result<RoomInvite>::failure(url_ok.error());
  if (!valid_peer_fingerprint(invite.creator_fingerprint))
    return Result<RoomInvite>::failure({ErrorCode::invalid_identity});
  auto canonical_pub = canonicalize_ed25519_public_key(invite.creator_public_key);
  if (!canonical_pub.has_value())
    return Result<RoomInvite>::failure({ErrorCode::invalid_identity});
  auto derived_fp = peer_fingerprint_from_public_key(canonical_pub.value());
  if (!derived_fp.has_value() || derived_fp.value() != invite.creator_fingerprint)
    return Result<RoomInvite>::failure({ErrorCode::invalid_identity});
  if (!valid_safe_token(invite.invite_code, kRoomInviteMaxCodeBytes))
    return Result<RoomInvite>::failure({ErrorCode::invalid_range});
  if (invite.expires_ns <= 0)
    return Result<RoomInvite>::failure({ErrorCode::invalid_range});

  return Result<RoomInvite>::success(RoomInvite{
      invite.room_id,
      invite.relay_url,
      invite.creator_fingerprint,
      std::move(canonical_pub).value(),
      invite.invite_code,
      invite.expires_ns,
  });
}

Result<void> validate_blind_relay_frame(const BlindRelayFrame &frame,
                                        const BridgeMuxConfig &mux_cfg) noexcept {
  if (!valid_relay_lane(frame.lane))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_safe_token(frame.room_id, kMaxRoomIdBytes))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_peer_fingerprint(frame.sender_fingerprint))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (!valid_safe_token(frame.frame_id, kRelayMaxFrameIdBytes))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (frame.timestamp_ns <= 0)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_sha256_hex(frame.aad_hash))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_utf8_no_ctrl(frame.routing_scope, kBoardBridgeMaxScopeBytes, true))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_base64_or_url_syntax(frame.nonce_b64, kRelayMaxNonceB64Bytes))
    return Result<void>::failure({ErrorCode::invalid_range});

  std::size_t cap = relay_lane_max_bytes(frame.lane);
  switch (frame.lane) {
  case RelayLane::control:
    cap = std::min(cap, mux_cfg.control_max_bytes);
    break;
  case RelayLane::causal:
    cap = std::min(cap, mux_cfg.causal_max_bytes);
    break;
  case RelayLane::presence:
    cap = std::min(cap, mux_cfg.presence_max_bytes);
    break;
  }
  if (frame.ciphertext_b64.size() > cap)
    return Result<void>::failure({ErrorCode::capacity});
  if (!valid_base64_or_url_syntax(frame.ciphertext_b64, cap))
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

struct ScopeMatchQuery {
  std::string_view subscription;
  std::string_view frame_scope;
};

bool scope_matches(ScopeMatchQuery query) noexcept {
  if (query.subscription == "*")
    return true;
  if (query.subscription == query.frame_scope)
    return true;
  if (query.subscription.size() >= 2 && query.subscription.back() == '*') {
    const std::string_view prefix =
        query.subscription.substr(0, query.subscription.size() - 1);
    return query.frame_scope.starts_with(prefix);
  }
  if (query.frame_scope.size() > query.subscription.size() &&
      query.frame_scope.starts_with(query.subscription)) {
    const char next = query.frame_scope[query.subscription.size()];
    return next == '/' || next == ':';
  }
  return false;
}

bool session_interested_in_frame(const std::vector<std::string> &subscribed_scopes,
                                 const BlindRelayFrame &frame) noexcept {
  // Control lane frames (recalls, revocations, fencing epochs) are always relevant
  // to every participant in the room.
  if (frame.lane == RelayLane::control)
    return true;
  if (subscribed_scopes.empty() || frame.routing_scope.empty())
    return true;
  for (const auto &sub : subscribed_scopes) {
    if (scope_matches({sub, frame.routing_scope}))
      return true;
  }
  return false;
}

Result<void> validate_rate_limit_policy(const RelayRateLimitPolicy &policy) noexcept {
  if (!std::isfinite(policy.frames_per_sec) || policy.frames_per_sec <= 0.0 ||
      !std::isfinite(policy.burst_frames) || policy.burst_frames < 1.0 ||
      !std::isfinite(policy.bytes_per_sec) || policy.bytes_per_sec <= 0.0 ||
      !std::isfinite(policy.burst_bytes) || policy.burst_bytes < 1.0) {
    return Result<void>::failure({ErrorCode::invalid_range});
  }
  return Result<void>::success();
}

struct PresenceFreshnessCheck {
  std::int64_t incoming_ts_ns;
  std::uint64_t incoming_seq;
  std::int64_t existing_ts_ns;
  std::uint64_t existing_seq;
};

bool presence_is_stale(PresenceFreshnessCheck check) noexcept {
  if (check.incoming_ts_ns != check.existing_ts_ns)
    return check.incoming_ts_ns < check.existing_ts_ns;
  if (check.incoming_seq != check.existing_seq)
    return check.incoming_seq < check.existing_seq;
  return false;
}

std::vector<std::string> effective_hop_chain(const TaintedProvenance &provenance) {
  if (provenance.hop_chain.empty() && provenance.hop_count == 0)
    return {provenance.origin_fingerprint};
  return provenance.hop_chain;
}

} // namespace

// ---------------------------------------------------------------------------
// 1. 3-Lane Priority Multiplexer
// ---------------------------------------------------------------------------

std::string_view relay_lane_name(RelayLane lane) noexcept {
  switch (lane) {
  case RelayLane::control:
    return "control";
  case RelayLane::causal:
    return "causal";
  case RelayLane::presence:
    return "presence";
  }
  return {};
}

Result<RelayLane> parse_relay_lane(std::string_view name) noexcept {
  if (name == "control")
    return Result<RelayLane>::success(RelayLane::control);
  if (name == "causal")
    return Result<RelayLane>::success(RelayLane::causal);
  if (name == "presence")
    return Result<RelayLane>::success(RelayLane::presence);
  return Result<RelayLane>::failure({ErrorCode::invalid_range});
}

std::size_t relay_lane_max_bytes(RelayLane lane) noexcept {
  switch (lane) {
  case RelayLane::control:
    return kRelayControlMaxBytes;
  case RelayLane::causal:
    return kRelayCausalMaxBytes;
  case RelayLane::presence:
    return kRelayPresenceMaxBytes;
  }
  return 0;
}

std::size_t
BridgeMux::PresenceKeyHash::operator()(const PresenceKey &key) const noexcept {
  const std::size_t h1 = std::hash<std::string>{}(key.actor_id);
  const std::size_t h2 = std::hash<std::string>{}(key.scope);
  return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6U) + (h1 >> 2U));
}

Result<BridgeMux> BridgeMux::create(BridgeMuxConfig config) {
  auto valid = validate_mux_config(config);
  if (!valid.has_value())
    return Result<BridgeMux>::failure(valid.error());
  return Result<BridgeMux>::success(BridgeMux{config});
}

BridgeMuxStats BridgeMux::stats() const noexcept {
  return BridgeMuxStats{
      control_queue_.size(),    causal_queue_.size(),    presence_list_.size(),
      enqueued_total_,          dequeued_total_,         presence_coalesced_,
      presence_dropped_oldest_, presence_stale_ignored_, rejected_oversize_,
      rejected_queue_full_,
  };
}

Result<BridgeMuxEnqueueStatus> BridgeMux::enqueue(RelayPacket packet) {
  if (!valid_relay_lane(packet.lane))
    return Result<BridgeMuxEnqueueStatus>::failure({ErrorCode::invalid_range});
  if (packet.timestamp_ns < 0)
    return Result<BridgeMuxEnqueueStatus>::failure({ErrorCode::invalid_range});

  std::size_t max_bytes = 0;
  switch (packet.lane) {
  case RelayLane::control:
    max_bytes = std::min(config_.control_max_bytes, kRelayControlMaxBytes);
    break;
  case RelayLane::causal:
    max_bytes = std::min(config_.causal_max_bytes, kRelayCausalMaxBytes);
    break;
  case RelayLane::presence:
    max_bytes = std::min(config_.presence_max_bytes, kRelayPresenceMaxBytes);
    break;
  }
  if (packet.payload.size() > max_bytes) {
    ++rejected_oversize_;
    return Result<BridgeMuxEnqueueStatus>::failure({ErrorCode::capacity});
  }

  try {
    if (packet.lane == RelayLane::control) {
      if (control_queue_.size() >= config_.max_control_queue) {
        ++rejected_queue_full_;
        return Result<BridgeMuxEnqueueStatus>::failure({ErrorCode::capacity});
      }
      control_queue_.push_back(std::move(packet));
      ++enqueued_total_;
      return Result<BridgeMuxEnqueueStatus>::success(BridgeMuxEnqueueStatus::queued);
    }

    if (packet.lane == RelayLane::causal) {
      if (causal_queue_.size() >= config_.max_causal_queue) {
        ++rejected_queue_full_;
        return Result<BridgeMuxEnqueueStatus>::failure({ErrorCode::capacity});
      }
      causal_queue_.push_back(std::move(packet));
      ++enqueued_total_;
      return Result<BridgeMuxEnqueueStatus>::success(BridgeMuxEnqueueStatus::queued);
    }

    // Lane 2 (presence): unreliable latest-wins MRS coalesced by (actor_id, scope).
    if (packet.actor_id.empty())
      return Result<BridgeMuxEnqueueStatus>::failure({ErrorCode::invalid_range});

    PresenceKey key{packet.actor_id, packet.scope};
    const auto seen_it = last_seen_presence_.find(key);
    if (seen_it != last_seen_presence_.end()) {
      if (presence_is_stale({packet.timestamp_ns, packet.sequence,
                             seen_it->second.timestamp_ns, seen_it->second.sequence})) {
        ++presence_stale_ignored_;
        return Result<BridgeMuxEnqueueStatus>::success(
            BridgeMuxEnqueueStatus::ignored_stale);
      }
    }

    auto record_seen = [&](const PresenceKey &seen_key, std::int64_t ts,
                           std::uint64_t seq) {
      auto [it, inserted] =
          last_seen_presence_.insert_or_assign(seen_key, PresenceWater{ts, seq});
      (void)it;
      if (inserted) {
        last_seen_order_.push_back(seen_key);
        const std::size_t cap =
            std::max<std::size_t>(config_.max_presence_queue * 4, 64);
        while (last_seen_order_.size() > cap) {
          const PresenceKey oldest = std::move(last_seen_order_.front());
          last_seen_order_.pop_front();
          if (!presence_index_.contains(oldest))
            last_seen_presence_.erase(oldest);
        }
      }
    };

    const auto existing = presence_index_.find(key);
    if (existing != presence_index_.end()) {
      auto it = existing->second;
      it->packet = std::move(packet);
      record_seen(key, it->packet.timestamp_ns, it->packet.sequence);
      presence_list_.splice(presence_list_.end(), presence_list_, it);
      ++presence_coalesced_;
      ++enqueued_total_;
      return Result<BridgeMuxEnqueueStatus>::success(BridgeMuxEnqueueStatus::coalesced);
    }

    bool dropped = false;
    if (presence_list_.size() >= config_.max_presence_queue) {
      const auto oldest_it = presence_list_.begin();
      presence_index_.erase(oldest_it->key);
      presence_list_.erase(oldest_it);
      ++presence_dropped_oldest_;
      dropped = true;
    }

    const std::int64_t ts = packet.timestamp_ns;
    const std::uint64_t seq = packet.sequence;
    presence_list_.push_back(PresenceEntry{key, std::move(packet)});
    auto back_it = std::prev(presence_list_.end());
    presence_index_.emplace(key, back_it);
    record_seen(key, ts, seq);
    ++enqueued_total_;
    return Result<BridgeMuxEnqueueStatus>::success(
        dropped ? BridgeMuxEnqueueStatus::dropped_oldest_and_queued
                : BridgeMuxEnqueueStatus::queued);
  } catch (const std::bad_alloc &) {
    return Result<BridgeMuxEnqueueStatus>::failure({ErrorCode::allocation});
  }
}

std::optional<RelayPacket> BridgeMux::dequeue_next() {
  if (!control_queue_.empty()) {
    RelayPacket out = std::move(control_queue_.front());
    control_queue_.pop_front();
    ++dequeued_total_;
    return out;
  }
  if (!causal_queue_.empty()) {
    RelayPacket out = std::move(causal_queue_.front());
    causal_queue_.pop_front();
    ++dequeued_total_;
    return out;
  }
  if (!presence_list_.empty()) {
    auto it = presence_list_.begin();
    RelayPacket out = std::move(it->packet);
    presence_index_.erase(it->key);
    presence_list_.erase(it);
    ++dequeued_total_;
    return out;
  }
  return std::nullopt;
}

bool BridgeMux::empty() const noexcept {
  return control_queue_.empty() && causal_queue_.empty() && presence_list_.empty();
}

std::size_t BridgeMux::size() const noexcept {
  return control_queue_.size() + causal_queue_.size() + presence_list_.size();
}

std::size_t BridgeMux::lane_size(RelayLane lane) const noexcept {
  switch (lane) {
  case RelayLane::control:
    return control_queue_.size();
  case RelayLane::causal:
    return causal_queue_.size();
  case RelayLane::presence:
    return presence_list_.size();
  }
  return 0;
}

void BridgeMux::clear_presence() noexcept {
  presence_index_.clear();
  presence_list_.clear();
}

// ---------------------------------------------------------------------------
// 2. Signed Late-Join Checkpoints
// ---------------------------------------------------------------------------

Result<std::string> canonical_checkpoint_payload(const BridgeCheckpoint &checkpoint) {
  auto valid = validate_checkpoint_fields(checkpoint, false);
  if (!valid.has_value())
    return Result<std::string>::failure(valid.error());

  Value::Object watermarks_obj;
  watermarks_obj.reserve(checkpoint.actor_watermarks.size());
  for (const auto &[actor_id, seq] : checkpoint.actor_watermarks)
    watermarks_obj.emplace_back(actor_id, Value{Number{seq}});

  Value::Array frontier_arr;
  frontier_arr.reserve(checkpoint.causal_frontier_hashes.size());
  for (const auto &hash : checkpoint.causal_frontier_hashes)
    frontier_arr.emplace_back(hash);

  Value::Object epochs_obj;
  epochs_obj.reserve(checkpoint.lease_epochs.size());
  for (const auto &[scope, epoch] : checkpoint.lease_epochs)
    epochs_obj.emplace_back(scope, Value{Number{epoch}});

  Value::Array revoked_arr;
  revoked_arr.reserve(checkpoint.revoked_grant_ids.size());
  for (const auto &grant_id : checkpoint.revoked_grant_ids)
    revoked_arr.emplace_back(grant_id);

  // Keys strictly sorted lexicographically for deterministic canonical JSON.
  const Value signing_doc = Value::object({
      {"actor_watermarks", Value::object(std::move(watermarks_obj))},
      {"causal_frontier_hashes", Value{std::move(frontier_arr)}},
      {"checkpoint_seq", Value{Number{checkpoint.checkpoint_seq}}},
      {"created_ns", Value{Number{checkpoint.created_ns}}},
      {"lease_epochs", Value::object(std::move(epochs_obj))},
      {"revoked_grant_ids", Value{std::move(revoked_arr)}},
      {"room_id", Value{checkpoint.room_id}},
      {"signer_fingerprint", Value{checkpoint.signer_fingerprint}},
      {"type", Value{std::string{kBridgeCheckpointSigningType}}},
      {"version", Value{Number{checkpoint.version}}},
  });
  return dump_json(signing_doc, {kPeerMaxPayloadBytes, 500000, 128});
}

Value checkpoint_to_value(const BridgeCheckpoint &checkpoint) {
  Value::Object watermarks_obj;
  watermarks_obj.reserve(checkpoint.actor_watermarks.size());
  for (const auto &[actor_id, seq] : checkpoint.actor_watermarks)
    watermarks_obj.emplace_back(actor_id, Value{Number{seq}});

  Value::Array frontier_arr;
  frontier_arr.reserve(checkpoint.causal_frontier_hashes.size());
  for (const auto &hash : checkpoint.causal_frontier_hashes)
    frontier_arr.emplace_back(hash);

  Value::Array revoked_arr;
  revoked_arr.reserve(checkpoint.revoked_grant_ids.size());
  for (const auto &grant_id : checkpoint.revoked_grant_ids)
    revoked_arr.emplace_back(grant_id);

  Value::Object epochs_obj;
  epochs_obj.reserve(checkpoint.lease_epochs.size());
  for (const auto &[scope, epoch] : checkpoint.lease_epochs)
    epochs_obj.emplace_back(scope, Value{Number{epoch}});

  return Value::object({
      {"version", Value{Number{checkpoint.version}}},
      {"room_id", Value{checkpoint.room_id}},
      {"checkpoint_seq", Value{Number{checkpoint.checkpoint_seq}}},
      {"created_ns", Value{Number{checkpoint.created_ns}}},
      {"actor_watermarks", Value::object(std::move(watermarks_obj))},
      {"causal_frontier_hashes", Value{std::move(frontier_arr)}},
      {"revoked_grant_ids", Value{std::move(revoked_arr)}},
      {"lease_epochs", Value::object(std::move(epochs_obj))},
      {"signer_fingerprint", Value{checkpoint.signer_fingerprint}},
      {"signature", Value{checkpoint.signature}},
  });
}

Result<BridgeCheckpoint> checkpoint_from_value(const Value &value) {
  const auto *obj = std::get_if<Value::Object>(&value.value());
  if (!obj)
    return Result<BridgeCheckpoint>::failure({ErrorCode::corrupt});
  static constexpr std::array<std::string_view, 10> kKeys{
      "version",           "room_id",          "checkpoint_seq",
      "created_ns",        "actor_watermarks", "causal_frontier_hashes",
      "revoked_grant_ids", "lease_epochs",     "signer_fingerprint",
      "signature",
  };
  auto keys_ok = validate_strict_object_keys(*obj, kKeys);
  if (!keys_ok.has_value())
    return Result<BridgeCheckpoint>::failure(keys_ok.error());

  auto version = parse_uint64_field(value, "version");
  auto room_id = parse_string_field(value, "room_id");
  auto checkpoint_seq = parse_uint64_field(value, "checkpoint_seq");
  auto created_ns = parse_int64_field(value, "created_ns");
  auto signer_fp = parse_string_field(value, "signer_fingerprint");
  auto signature = parse_string_field(value, "signature");
  if (!version.has_value() ||
      version.value() > std::numeric_limits<std::uint32_t>::max() ||
      !room_id.has_value() || !checkpoint_seq.has_value() || !created_ns.has_value() ||
      !signer_fp.has_value() || !signature.has_value()) {
    return Result<BridgeCheckpoint>::failure({ErrorCode::corrupt});
  }

  auto parse_u64_map =
      [&](std::string_view key) -> Result<std::map<std::string, std::uint64_t>> {
    const Value *field = value.find(key);
    if (!field)
      return Result<std::map<std::string, std::uint64_t>>::failure(
          {ErrorCode::corrupt});
    const auto *map_obj = std::get_if<Value::Object>(&field->value());
    if (!map_obj || map_obj->size() > kCheckpointMaxEntries)
      return Result<std::map<std::string, std::uint64_t>>::failure(
          {ErrorCode::corrupt});
    std::map<std::string, std::uint64_t> out;
    for (const auto &[k, v] : *map_obj) {
      auto parsed = parse_uint64_value(v);
      if (!parsed.has_value()) {
        return Result<std::map<std::string, std::uint64_t>>::failure(
            {ErrorCode::corrupt});
      }
      if (!out.emplace(k, parsed.value()).second) {
        return Result<std::map<std::string, std::uint64_t>>::failure(
            {ErrorCode::corrupt});
      }
    }
    return Result<std::map<std::string, std::uint64_t>>::success(std::move(out));
  };

  auto parse_str_array = [&](std::string_view key) -> Result<std::vector<std::string>> {
    const Value *field = value.find(key);
    if (!field)
      return Result<std::vector<std::string>>::failure({ErrorCode::corrupt});
    const auto *arr = std::get_if<Value::Array>(&field->value());
    if (!arr || arr->size() > kCheckpointMaxEntries)
      return Result<std::vector<std::string>>::failure({ErrorCode::corrupt});
    std::vector<std::string> out;
    out.reserve(arr->size());
    for (const auto &entry : *arr) {
      const auto *s = std::get_if<std::string>(&entry.value());
      if (!s)
        return Result<std::vector<std::string>>::failure({ErrorCode::corrupt});
      out.push_back(*s);
    }
    return Result<std::vector<std::string>>::success(std::move(out));
  };

  auto watermarks = parse_u64_map("actor_watermarks");
  if (!watermarks.has_value())
    return Result<BridgeCheckpoint>::failure(watermarks.error());
  auto frontier = parse_str_array("causal_frontier_hashes");
  if (!frontier.has_value())
    return Result<BridgeCheckpoint>::failure(frontier.error());
  auto revoked = parse_str_array("revoked_grant_ids");
  if (!revoked.has_value())
    return Result<BridgeCheckpoint>::failure(revoked.error());
  auto epochs = parse_u64_map("lease_epochs");
  if (!epochs.has_value())
    return Result<BridgeCheckpoint>::failure(epochs.error());

  BridgeCheckpoint cp{
      static_cast<std::uint32_t>(version.value()),
      std::move(room_id).value(),
      checkpoint_seq.value(),
      created_ns.value(),
      std::move(watermarks).value(),
      std::move(frontier).value(),
      std::move(revoked).value(),
      std::move(epochs).value(),
      std::move(signer_fp).value(),
      std::move(signature).value(),
  };
  auto valid = validate_checkpoint_fields(cp, true);
  if (!valid.has_value())
    return Result<BridgeCheckpoint>::failure(valid.error());
  return Result<BridgeCheckpoint>::success(std::move(cp));
}

Result<BridgeCheckpoint> sign_checkpoint(const PeerIdentityStore &identity,
                                         BridgeCheckpointDraft draft) {
  try {
    if (draft.created_ns == 0)
      draft.created_ns = wall_now_ns();

    std::ranges::sort(draft.causal_frontier_hashes);
    const auto frontier_dup = std::ranges::unique(draft.causal_frontier_hashes);
    draft.causal_frontier_hashes.erase(frontier_dup.begin(), frontier_dup.end());

    std::ranges::sort(draft.revoked_grant_ids);
    const auto grant_dup = std::ranges::unique(draft.revoked_grant_ids);
    draft.revoked_grant_ids.erase(grant_dup.begin(), grant_dup.end());

    BridgeCheckpoint checkpoint{
        kBridgeCheckpointVersion,
        std::move(draft.room_id),
        draft.checkpoint_seq,
        draft.created_ns,
        std::move(draft.actor_watermarks),
        std::move(draft.causal_frontier_hashes),
        std::move(draft.revoked_grant_ids),
        std::move(draft.lease_epochs),
        identity.identity().fingerprint,
        {},
    };

    auto canonical = canonical_checkpoint_payload(checkpoint);
    if (!canonical.has_value())
      return Result<BridgeCheckpoint>::failure(canonical.error());
    auto sig = identity.sign_bytes(canonical.value());
    if (!sig.has_value())
      return Result<BridgeCheckpoint>::failure(sig.error());
    checkpoint.signature = std::move(sig).value();
    return Result<BridgeCheckpoint>::success(std::move(checkpoint));
  } catch (const std::bad_alloc &) {
    return Result<BridgeCheckpoint>::failure({ErrorCode::allocation});
  }
}

Result<void> verify_checkpoint(const KnownPeersStore &known_peers,
                               const BridgeCheckpoint &checkpoint,
                               const PeerIdentityConfig &config) {
  auto valid = validate_checkpoint_fields(checkpoint, true);
  if (!valid.has_value())
    return valid;

  auto lookup_signer = [&]() -> Result<std::string> {
    auto found = known_peers.find_by_fingerprint(checkpoint.signer_fingerprint);
    if (!found.has_value())
      return Result<std::string>::failure(found.error());
    const auto &maybe_peer = found.value();
    if (!maybe_peer.has_value())
      return Result<std::string>::failure({ErrorCode::invalid_identity});
    if (maybe_peer->revoked)
      return Result<std::string>::failure({ErrorCode::conflict});
    return Result<std::string>::success(maybe_peer->public_key);
  };

  auto signer_public_key = lookup_signer();
  if (!signer_public_key.has_value())
    return Result<void>::failure(signer_public_key.error());

  auto canonical = canonical_checkpoint_payload(checkpoint);
  if (!canonical.has_value())
    return Result<void>::failure(canonical.error());

  auto verified = verify_detached_signature(
      DetachedSignatureVerification{
          checkpoint.signer_fingerprint,
          signer_public_key.value(),
          canonical.value(),
          checkpoint.signature,
      },
      config);
  if (!verified.has_value())
    return verified;

  // Close concurrent peer-revocation vs ssh-keygen verification TOCTOU window.
  auto rechecked = lookup_signer();
  if (!rechecked.has_value())
    return Result<void>::failure(rechecked.error());
  if (rechecked.value() != signer_public_key.value())
    return Result<void>::failure({ErrorCode::conflict});
  return Result<void>::success();
}

std::map<std::string, std::uint64_t>
compute_actor_watermarks(const std::vector<CausalEvent> &events) {
  std::map<std::string, std::uint64_t> watermarks;
  for (const auto &ev : events) {
    auto [it, inserted] = watermarks.emplace(ev.actor_id, ev.actor_seq);
    if (!inserted && ev.actor_seq > it->second)
      it->second = ev.actor_seq;
  }
  return watermarks;
}

std::vector<std::string>
compute_causal_frontier(const std::vector<CausalEvent> &events) {
  std::set<std::string_view> referenced_parents;
  for (const auto &ev : events) {
    for (const auto &parent : ev.causal_parents)
      referenced_parents.insert(parent);
  }
  std::set<std::string> frontier;
  for (const auto &ev : events) {
    if (!ev.event_hash.empty() && !referenced_parents.contains(ev.event_hash))
      frontier.insert(ev.event_hash);
  }
  return {frontier.begin(), frontier.end()};
}

std::vector<CausalEvent>
filter_delta_after_checkpoint(const std::vector<CausalEvent> &events,
                              const BridgeCheckpoint &checkpoint) {
  std::vector<CausalEvent> delta;
  for (const auto &ev : events) {
    const auto it = checkpoint.actor_watermarks.find(ev.actor_id);
    if (it == checkpoint.actor_watermarks.end() || ev.actor_seq > it->second)
      delta.push_back(ev);
  }
  return delta;
}

// ---------------------------------------------------------------------------
// 3. Room Invite URI (bbjoin1:...) & Content-Blind Relay Router
// ---------------------------------------------------------------------------

Result<std::string> encode_room_invite(const RoomInvite &invite) {
  auto validated = validate_and_canonicalize_invite(invite);
  if (!validated.has_value())
    return Result<std::string>::failure(validated.error());
  const RoomInvite &clean = validated.value();

  // Canonical sorted-key JSON with zero embedded secrets.
  const Value doc = Value::object({
      {"creator_fingerprint", Value{clean.creator_fingerprint}},
      {"creator_public_key", Value{clean.creator_public_key}},
      {"expires_ns", Value{Number{clean.expires_ns}}},
      {"invite_code", Value{clean.invite_code}},
      {"relay_url", Value{clean.relay_url}},
      {"room_id", Value{clean.room_id}},
  });
  auto json = dump_json(doc, {kRoomInviteMaxUriBytes, 64, 8});
  if (!json.has_value())
    return Result<std::string>::failure(json.error());

  try {
    std::string uri{kRoomInvitePrefix};
    uri += base64url_encode(json.value());
    if (uri.size() > kRoomInviteMaxUriBytes)
      return Result<std::string>::failure({ErrorCode::capacity});
    return Result<std::string>::success(std::move(uri));
  } catch (const std::bad_alloc &) {
    return Result<std::string>::failure({ErrorCode::allocation});
  }
}

Result<RoomInvite> parse_room_invite(std::string_view uri) {
  if (uri.empty())
    return Result<RoomInvite>::failure({ErrorCode::corrupt});
  if (uri.size() > kRoomInviteMaxUriBytes)
    return Result<RoomInvite>::failure({ErrorCode::capacity});
  if (!uri.starts_with(kRoomInvitePrefix))
    return Result<RoomInvite>::failure({ErrorCode::corrupt});

  const std::string_view encoded = uri.substr(kRoomInvitePrefix.size());
  auto decoded = base64url_decode_strict(encoded);
  if (!decoded.has_value())
    return Result<RoomInvite>::failure(decoded.error());

  auto parsed = parse_json(decoded.value(), {kRoomInviteMaxUriBytes, 64, 8});
  if (!parsed.has_value())
    return Result<RoomInvite>::failure({ErrorCode::corrupt});
  const Value &root = parsed.value();
  const auto *obj = std::get_if<Value::Object>(&root.value());
  if (!obj)
    return Result<RoomInvite>::failure({ErrorCode::corrupt});

  static constexpr std::array<std::string_view, 6> kInviteKeys{
      "room_id",     "relay_url",  "creator_fingerprint", "creator_public_key",
      "invite_code", "expires_ns",
  };
  auto keys_ok = validate_strict_object_keys(*obj, kInviteKeys);
  if (!keys_ok.has_value())
    return Result<RoomInvite>::failure(keys_ok.error());

  auto room_id = parse_string_field(root, "room_id");
  auto relay_url = parse_string_field(root, "relay_url");
  auto creator_fp = parse_string_field(root, "creator_fingerprint");
  auto creator_pub = parse_string_field(root, "creator_public_key");
  auto invite_code = parse_string_field(root, "invite_code");
  auto expires_ns = parse_int64_field(root, "expires_ns");
  if (!room_id.has_value() || !relay_url.has_value() || !creator_fp.has_value() ||
      !creator_pub.has_value() || !invite_code.has_value() || !expires_ns.has_value()) {
    return Result<RoomInvite>::failure({ErrorCode::corrupt});
  }

  return validate_and_canonicalize_invite(RoomInvite{
      std::move(room_id).value(),
      std::move(relay_url).value(),
      std::move(creator_fp).value(),
      std::move(creator_pub).value(),
      std::move(invite_code).value(),
      expires_ns.value(),
  });
}

Value blind_relay_frame_to_value(const BlindRelayFrame &frame) {
  return Value::object({
      {"room_id", Value{frame.room_id}},
      {"sender_fingerprint", Value{frame.sender_fingerprint}},
      {"lane", Value{std::string{relay_lane_name(frame.lane)}}},
      {"frame_id", Value{frame.frame_id}},
      {"epoch", Value{Number{frame.epoch}}},
      {"ciphertext_b64", Value{frame.ciphertext_b64}},
      {"nonce_b64", Value{frame.nonce_b64}},
      {"aad_hash", Value{frame.aad_hash}},
      {"timestamp_ns", Value{Number{frame.timestamp_ns}}},
      {"routing_scope", Value{frame.routing_scope}},
  });
}

Result<BlindRelayFrame> blind_relay_frame_from_value(const Value &value) {
  const auto *obj = std::get_if<Value::Object>(&value.value());
  if (!obj)
    return Result<BlindRelayFrame>::failure({ErrorCode::corrupt});
  static constexpr std::array<std::string_view, 10> kFrameKeys{
      "room_id",      "sender_fingerprint", "lane",      "frame_id",
      "epoch",        "ciphertext_b64",     "nonce_b64", "aad_hash",
      "timestamp_ns", "routing_scope",
  };
  auto keys_ok = validate_strict_object_keys(*obj, kFrameKeys);
  if (!keys_ok.has_value())
    return Result<BlindRelayFrame>::failure(keys_ok.error());

  auto room_id = parse_string_field(value, "room_id");
  auto sender_fp = parse_string_field(value, "sender_fingerprint");
  auto lane_str = parse_string_field(value, "lane");
  auto frame_id = parse_string_field(value, "frame_id");
  auto epoch = parse_uint64_field(value, "epoch");
  auto ciphertext_b64 = parse_string_field(value, "ciphertext_b64");
  auto nonce_b64 = parse_string_field(value, "nonce_b64");
  auto aad_hash = parse_string_field(value, "aad_hash");
  auto timestamp_ns = parse_int64_field(value, "timestamp_ns");
  auto routing_scope = parse_string_field(value, "routing_scope");
  if (!room_id.has_value() || !sender_fp.has_value() || !lane_str.has_value() ||
      !frame_id.has_value() || !epoch.has_value() || !ciphertext_b64.has_value() ||
      !nonce_b64.has_value() || !aad_hash.has_value() || !timestamp_ns.has_value() ||
      !routing_scope.has_value()) {
    return Result<BlindRelayFrame>::failure({ErrorCode::corrupt});
  }
  auto lane = parse_relay_lane(lane_str.value());
  if (!lane.has_value())
    return Result<BlindRelayFrame>::failure({ErrorCode::corrupt});

  BlindRelayFrame frame{
      std::move(room_id).value(),
      std::move(sender_fp).value(),
      lane.value(),
      std::move(frame_id).value(),
      epoch.value(),
      std::move(ciphertext_b64).value(),
      std::move(nonce_b64).value(),
      std::move(aad_hash).value(),
      timestamp_ns.value(),
      std::move(routing_scope).value(),
  };
  auto valid = validate_blind_relay_frame(frame, BridgeMuxConfig{});
  if (!valid.has_value())
    return Result<BlindRelayFrame>::failure(valid.error());
  return Result<BlindRelayFrame>::success(std::move(frame));
}

Result<BlindRelayRouter> BlindRelayRouter::create(BlindRelayConfig config) {
  auto rl_ok = validate_rate_limit_policy(config.rate_limit);
  if (!rl_ok.has_value())
    return Result<BlindRelayRouter>::failure(rl_ok.error());
  auto mux_ok = validate_mux_config(config.session_mux);
  if (!mux_ok.has_value())
    return Result<BlindRelayRouter>::failure(mux_ok.error());
  if (config.max_room_history == 0 || config.max_seen_frame_ids == 0 ||
      config.max_sessions_per_room == 0) {
    return Result<BlindRelayRouter>::failure({ErrorCode::invalid_range});
  }
  return Result<BlindRelayRouter>::success(BlindRelayRouter{config});
}

BlindRelayStats BlindRelayRouter::stats() const noexcept {
  std::size_t connected = 0;
  for (const auto &[id, session] : sessions_) {
    (void)id;
    if (session.handle.connected)
      ++connected;
  }
  return BlindRelayStats{
      rooms_.size(),
      sessions_.size(),
      connected,
      published_frames_,
      duplicate_frames_,
      rate_limited_frames_,
      rejected_oversize_frames_,
      session_roams_,
  };
}

Result<RelaySessionHandle> BlindRelayRouter::register_session(RelaySessionSpec spec) {
  if (!valid_safe_token(spec.room_id, kMaxRoomIdBytes))
    return Result<RelaySessionHandle>::failure({ErrorCode::invalid_range});
  if (!valid_peer_fingerprint(spec.peer_fingerprint))
    return Result<RelaySessionHandle>::failure({ErrorCode::invalid_identity});
  if (spec.role != RelayParticipantRole::peer &&
      spec.role != RelayParticipantRole::spectator) {
    return Result<RelaySessionHandle>::failure({ErrorCode::invalid_range});
  }
  if (!valid_utf8_no_ctrl(spec.remote_endpoint, kRelayMaxEndpointBytes, false))
    return Result<RelaySessionHandle>::failure({ErrorCode::invalid_range});
  if (spec.subscribed_scopes.size() > kRelayMaxSubscriptions)
    return Result<RelaySessionHandle>::failure({ErrorCode::capacity});
  for (const auto &scope : spec.subscribed_scopes) {
    if (!valid_utf8_no_ctrl(scope, kBoardBridgeMaxScopeBytes, false))
      return Result<RelaySessionHandle>::failure({ErrorCode::invalid_range});
  }

  auto mux = BridgeMux::create(config_.session_mux);
  if (!mux.has_value())
    return Result<RelaySessionHandle>::failure(mux.error());

  try {
    auto &room = rooms_[spec.room_id];
    if (room.session_ids.size() >= config_.max_sessions_per_room)
      return Result<RelaySessionHandle>::failure({ErrorCode::capacity});

    const std::uint64_t seq = next_id_counter_++;
    std::string session_id = "sess-" + std::to_string(seq);
    std::string connection_id = "conn-" + std::to_string(seq);

    RelaySessionHandle handle{
        session_id,
        std::move(connection_id),
        spec.room_id,
        std::move(spec.peer_fingerprint),
        spec.role,
        std::move(spec.remote_endpoint),
        true,
        0,
        0,
    };

    SessionState state{
        handle,
        std::move(spec.subscribed_scopes),
        std::move(mux).value(),
        {},
        {},
        {},
        1,
        0,
    };
    sessions_.emplace(session_id, std::move(state));
    room.session_ids.push_back(std::move(session_id));
    return Result<RelaySessionHandle>::success(std::move(handle));
  } catch (const std::bad_alloc &) {
    return Result<RelaySessionHandle>::failure({ErrorCode::allocation});
  }
}

Result<void> BlindRelayRouter::disconnect_session(std::string_view session_id) {
  const auto it = sessions_.find(std::string{session_id});
  if (it == sessions_.end())
    return Result<void>::failure({ErrorCode::stale_handle});
  it->second.handle.connected = false;
  // Drop ephemeral Lane 2 presence on disconnect; never replay stale presence.
  it->second.outbound_mux.clear_presence();
  it->second.presence_ticket_order.clear();
  it->second.presence_ticket_pos.clear();
  std::erase_if(it->second.pending_frames, [](const auto &entry) {
    return entry.second.frame.lane == RelayLane::presence;
  });
  return Result<void>::success();
}

Result<void> BlindRelayRouter::enqueue_for_session(SessionState &session,
                                                   const RoutedRelayFrame &routed,
                                                   bool &coalesced) {
  coalesced = false;
  std::string ticket;
  if (routed.frame.lane == RelayLane::presence) {
    ticket = "p:" + routed.frame.sender_fingerprint + ":" + routed.frame.routing_scope;
  } else {
    ticket = "r:" + std::to_string(session.next_ticket++);
  }

  RelayPacket packet{
      routed.frame.lane,
      ticket,
      routed.frame.sender_fingerprint,
      routed.frame.routing_scope,
      routed.relay_seq,
      routed.frame.timestamp_ns,
      {}, // Content-blind router keeps opaque ciphertext in pending_frames without
          // duplicating multi-MiB payloads inside the mux queue.
  };

  auto enq = session.outbound_mux.enqueue(std::move(packet));
  if (!enq.has_value())
    return Result<void>::failure(enq.error());

  if (enq.value() == BridgeMuxEnqueueStatus::ignored_stale)
    return Result<void>::success();
  if (enq.value() == BridgeMuxEnqueueStatus::coalesced)
    coalesced = true;

  session.pending_frames.insert_or_assign(ticket, routed);
  if (routed.frame.lane == RelayLane::presence) {
    if (enq.value() == BridgeMuxEnqueueStatus::coalesced) {
      if (const auto pos = session.presence_ticket_pos.find(ticket);
          pos != session.presence_ticket_pos.end()) {
        session.presence_ticket_order.splice(session.presence_ticket_order.end(),
                                             session.presence_ticket_order,
                                             pos->second);
      }
    } else {
      if (enq.value() == BridgeMuxEnqueueStatus::dropped_oldest_and_queued &&
          !session.presence_ticket_order.empty()) {
        const std::string evicted = std::move(session.presence_ticket_order.front());
        session.presence_ticket_order.pop_front();
        session.presence_ticket_pos.erase(evicted);
        session.pending_frames.erase(evicted);
      }
      session.presence_ticket_order.push_back(ticket);
      session.presence_ticket_pos.insert_or_assign(
          ticket, std::prev(session.presence_ticket_order.end()));
    }
  }
  if (routed.relay_seq > session.last_enqueued_relay_seq)
    session.last_enqueued_relay_seq = routed.relay_seq;
  return Result<void>::success();
}

Result<RelayResumeResult> BlindRelayRouter::resume_session(RelayResumeRequest request) {
  if (request.session_id.empty())
    return Result<RelayResumeResult>::failure({ErrorCode::invalid_range});
  if (!valid_peer_fingerprint(request.peer_fingerprint))
    return Result<RelayResumeResult>::failure({ErrorCode::invalid_identity});
  if (!valid_utf8_no_ctrl(request.new_remote_endpoint, kRelayMaxEndpointBytes, false))
    return Result<RelayResumeResult>::failure({ErrorCode::invalid_range});

  const auto it = sessions_.find(request.session_id);
  if (it == sessions_.end())
    return Result<RelayResumeResult>::failure({ErrorCode::stale_handle});

  SessionState &session = it->second;
  if (session.handle.peer_fingerprint != request.peer_fingerprint)
    return Result<RelayResumeResult>::failure({ErrorCode::invalid_identity});

  const auto room_it = rooms_.find(session.handle.room_id);
  if (room_it == rooms_.end())
    return Result<RelayResumeResult>::failure({ErrorCode::stale_handle});

  auto fresh_mux = BridgeMux::create(config_.session_mux);
  if (!fresh_mux.has_value())
    return Result<RelayResumeResult>::failure(fresh_mux.error());

  try {
    // Rotate connection ID on network/IP roam (RFC 9000 style path migration).
    session.handle.connection_id = "conn-" + std::to_string(next_id_counter_++);
    session.handle.remote_endpoint = std::move(request.new_remote_endpoint);
    session.handle.connected = true;
    ++session.handle.roam_count;
    ++session_roams_;
    session.handle.last_acked_relay_seq = request.last_acked_relay_seq;

    // Reset outbound queue and replay ONLY missed reliable frames (Lane 0 & 1)
    // strictly newer than last_acked_relay_seq. Never replay stale Lane 2 presence.
    session.outbound_mux = std::move(fresh_mux).value();
    session.pending_frames.clear();
    session.presence_ticket_order.clear();
    session.presence_ticket_pos.clear();
    session.last_enqueued_relay_seq = request.last_acked_relay_seq;

    const RoomState &room = room_it->second;
    bool history_truncated = false;
    if (!room.reliable_history.empty() &&
        request.last_acked_relay_seq + 1 < room.reliable_history.front().relay_seq) {
      history_truncated = true;
    }

    std::size_t replayed = 0;
    for (const auto &entry : room.reliable_history) {
      if (entry.relay_seq <= request.last_acked_relay_seq)
        continue;
      if (entry.frame.sender_fingerprint == session.handle.peer_fingerprint)
        continue;
      if (!session_interested_in_frame(session.subscribed_scopes, entry.frame))
        continue;
      bool coalesced = false;
      auto enq = enqueue_for_session(session, entry, coalesced);
      if (!enq.has_value())
        return Result<RelayResumeResult>::failure(enq.error());
      ++replayed;
    }

    return Result<RelayResumeResult>::success(
        RelayResumeResult{session.handle, replayed, history_truncated});
  } catch (const std::bad_alloc &) {
    return Result<RelayResumeResult>::failure({ErrorCode::allocation});
  }
}

Result<RelayPublishReport> BlindRelayRouter::publish(const BlindRelayFrame &frame,
                                                     std::int64_t now_ns) {
  if (now_ns <= 0)
    return Result<RelayPublishReport>::failure({ErrorCode::invalid_range});

  auto valid = validate_blind_relay_frame(frame, config_.session_mux);
  if (!valid.has_value()) {
    if (valid.error().code == ErrorCode::capacity)
      ++rejected_oversize_frames_;
    return Result<RelayPublishReport>::failure(valid.error());
  }

  const auto room_it = rooms_.find(frame.room_id);
  if (room_it == rooms_.end())
    return Result<RelayPublishReport>::failure({ErrorCode::invalid_identity});
  RoomState &room = room_it->second;

  // Verify sender holds an active peer (non-spectator) session in this room.
  bool found_sender = false;
  bool sender_is_peer = false;
  for (const auto &sid : room.session_ids) {
    const auto sit = sessions_.find(sid);
    if (sit == sessions_.end())
      continue;
    if (sit->second.handle.peer_fingerprint == frame.sender_fingerprint) {
      found_sender = true;
      if (sit->second.handle.role == RelayParticipantRole::peer &&
          sit->second.handle.connected) {
        sender_is_peer = true;
        break;
      }
    }
  }
  if (!found_sender)
    return Result<RelayPublishReport>::failure({ErrorCode::invalid_identity});
  if (!sender_is_peer)
    return Result<RelayPublishReport>::failure({ErrorCode::conflict});

  // Per-sender token bucket (net_chan_limit style): isolates runaway senders
  // without impacting other peers in the room.
  auto &bucket = sender_buckets_[frame.sender_fingerprint];
  if (!bucket.initialized) {
    bucket.frame_tokens = config_.rate_limit.burst_frames;
    bucket.byte_tokens = config_.rate_limit.burst_bytes;
    bucket.last_refill_ns = now_ns;
    bucket.initialized = true;
  } else if (now_ns > bucket.last_refill_ns) {
    const double elapsed_sec =
        static_cast<double>(now_ns - bucket.last_refill_ns) / 1.0e9;
    bucket.frame_tokens = std::min(
        config_.rate_limit.burst_frames,
        bucket.frame_tokens + (elapsed_sec * config_.rate_limit.frames_per_sec));
    bucket.byte_tokens =
        std::min(config_.rate_limit.burst_bytes,
                 bucket.byte_tokens + (elapsed_sec * config_.rate_limit.bytes_per_sec));
    bucket.last_refill_ns = now_ns;
  }

  const double frame_bytes = static_cast<double>(
      frame.ciphertext_b64.size() + frame.nonce_b64.size() + frame.aad_hash.size());
  if (bucket.frame_tokens < 1.0 || bucket.byte_tokens < frame_bytes) {
    ++rate_limited_frames_;
    return Result<RelayPublishReport>::failure({ErrorCode::busy});
  }
  bucket.frame_tokens -= 1.0;
  bucket.byte_tokens -= frame_bytes;

  // Deduplicate by (sender_fingerprint, frame_id) within room so a peer cannot
  // pre-squat another peer's frame_id namespace.
  std::string dedupe_key;
  dedupe_key.reserve(frame.sender_fingerprint.size() + 1U + frame.frame_id.size());
  dedupe_key.append(frame.sender_fingerprint);
  dedupe_key.push_back('\0');
  dedupe_key.append(frame.frame_id);
  if (room.seen_frame_ids.contains(dedupe_key)) {
    ++duplicate_frames_;
    return Result<RelayPublishReport>::success(RelayPublishReport{0, 0, 0, true});
  }

  try {
    room.seen_frame_ids.insert(dedupe_key);
    room.seen_frame_order.push_back(std::move(dedupe_key));
    while (room.seen_frame_order.size() > config_.max_seen_frame_ids) {
      room.seen_frame_ids.erase(room.seen_frame_order.front());
      room.seen_frame_order.pop_front();
    }

    std::uint64_t relay_seq = 0;
    if (frame.lane != RelayLane::presence) {
      relay_seq = room.next_relay_seq++;
      room.reliable_history.push_back(RoutedRelayFrame{relay_seq, frame});
      while (room.reliable_history.size() > config_.max_room_history)
        room.reliable_history.pop_front();
    }

    const RoutedRelayFrame routed{relay_seq, frame};
    std::size_t delivered = 0;
    std::size_t coalesced = 0;
    for (const auto &sid : room.session_ids) {
      const auto sit = sessions_.find(sid);
      if (sit == sessions_.end())
        continue;
      SessionState &target = sit->second;
      if (!target.handle.connected)
        continue;
      if (target.handle.peer_fingerprint == frame.sender_fingerprint)
        continue;
      if (!session_interested_in_frame(target.subscribed_scopes, frame))
        continue;
      bool was_coalesced = false;
      auto enq = enqueue_for_session(target, routed, was_coalesced);
      if (!enq.has_value()) {
        // Backpressure on one slow receiver does not tear down other peers.
        continue;
      }
      if (was_coalesced)
        ++coalesced;
      else
        ++delivered;
    }

    ++published_frames_;
    return Result<RelayPublishReport>::success(
        RelayPublishReport{relay_seq, delivered, coalesced, false});
  } catch (const std::bad_alloc &) {
    return Result<RelayPublishReport>::failure({ErrorCode::allocation});
  }
}

Result<std::optional<RoutedRelayFrame>>
BlindRelayRouter::poll_outbound(std::string_view session_id) {
  const auto it = sessions_.find(std::string{session_id});
  if (it == sessions_.end())
    return Result<std::optional<RoutedRelayFrame>>::failure({ErrorCode::stale_handle});
  SessionState &session = it->second;
  if (!session.handle.connected)
    return Result<std::optional<RoutedRelayFrame>>::failure({ErrorCode::stale_handle});

  auto next = session.outbound_mux.dequeue_next();
  if (!next.has_value())
    return Result<std::optional<RoutedRelayFrame>>::success(std::nullopt);

  const auto frame_it = session.pending_frames.find(next->packet_id);
  if (frame_it == session.pending_frames.end())
    return Result<std::optional<RoutedRelayFrame>>::failure({ErrorCode::corrupt});
  RoutedRelayFrame out = std::move(frame_it->second);
  session.pending_frames.erase(frame_it);
  if (out.frame.lane == RelayLane::presence) {
    if (const auto pos = session.presence_ticket_pos.find(next->packet_id);
        pos != session.presence_ticket_pos.end()) {
      session.presence_ticket_order.erase(pos->second);
      session.presence_ticket_pos.erase(pos);
    }
  }
  return Result<std::optional<RoutedRelayFrame>>::success(std::move(out));
}

Result<void> BlindRelayRouter::ack_relay_seq(std::string_view session_id,
                                             std::uint64_t relay_seq) {
  const auto it = sessions_.find(std::string{session_id});
  if (it == sessions_.end())
    return Result<void>::failure({ErrorCode::stale_handle});
  if (relay_seq > it->second.handle.last_acked_relay_seq)
    it->second.handle.last_acked_relay_seq = relay_seq;
  return Result<void>::success();
}

Result<RelaySessionHandle>
BlindRelayRouter::session_info(std::string_view session_id) const {
  const auto it = sessions_.find(std::string{session_id});
  if (it == sessions_.end())
    return Result<RelaySessionHandle>::failure({ErrorCode::stale_handle});
  return Result<RelaySessionHandle>::success(it->second.handle);
}

// ---------------------------------------------------------------------------
// 4. Transitive Multi-Hop PeerProvenance Taint Propagation
// ---------------------------------------------------------------------------

Result<void> validate_tainted_provenance(const TaintedProvenance &provenance) {
  if (!valid_peer_fingerprint(provenance.origin_fingerprint))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (provenance.max_hops == 0 || provenance.max_hops > kHardMaxProvenanceHops)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (provenance.hop_count > provenance.max_hops)
    return Result<void>::failure({ErrorCode::capacity});

  if (!provenance.hop_chain.empty()) {
    if (provenance.hop_chain.front() != provenance.origin_fingerprint)
      return Result<void>::failure({ErrorCode::corrupt});
    if (provenance.hop_chain.size() !=
        static_cast<std::size_t>(provenance.hop_count) + 1U) {
      return Result<void>::failure({ErrorCode::corrupt});
    }
    std::set<std::string_view> seen_hops;
    for (const auto &hop : provenance.hop_chain) {
      if (!valid_utf8_no_ctrl(hop, kMaxActorIdBytes, false))
        return Result<void>::failure({ErrorCode::invalid_range});
      if (!seen_hops.insert(hop).second)
        return Result<void>::failure({ErrorCode::conflict});
    }
  } else if (provenance.hop_count != 0) {
    return Result<void>::failure({ErrorCode::corrupt});
  }

  if (provenance.untrusted_sources.size() > kMaxProvenanceUntrustedSources)
    return Result<void>::failure({ErrorCode::capacity});
  for (const auto &src : provenance.untrusted_sources) {
    if (!valid_utf8_no_ctrl(src, kMaxUntrustedSourceBytes, false))
      return Result<void>::failure({ErrorCode::invalid_range});
  }
  return Result<void>::success();
}

Result<TaintedProvenance>
propagate_taint(const TaintedProvenance &parent, std::string_view next_actor,
                const std::vector<std::string> &added_untrusted_sources) {
  auto parent_ok = validate_tainted_provenance(parent);
  if (!parent_ok.has_value())
    return Result<TaintedProvenance>::failure(parent_ok.error());
  if (!valid_utf8_no_ctrl(next_actor, kMaxActorIdBytes, false))
    return Result<TaintedProvenance>::failure({ErrorCode::invalid_range});
  if (parent.hop_count >= parent.max_hops)
    return Result<TaintedProvenance>::failure({ErrorCode::capacity});

  try {
    std::vector<std::string> chain = effective_hop_chain(parent);
    for (const auto &hop : chain) {
      if (hop == next_actor)
        return Result<TaintedProvenance>::failure({ErrorCode::conflict});
    }
    chain.emplace_back(next_actor);

    // Monotonic union: upstream untrusted sources can NEVER be stripped downstream.
    std::set<std::string> merged_sources;
    for (const auto &src : parent.untrusted_sources)
      merged_sources.insert(src);
    for (const auto &src : added_untrusted_sources) {
      if (!valid_utf8_no_ctrl(src, kMaxUntrustedSourceBytes, false))
        return Result<TaintedProvenance>::failure({ErrorCode::invalid_range});
      merged_sources.insert(src);
    }
    if (merged_sources.size() > kMaxProvenanceUntrustedSources)
      return Result<TaintedProvenance>::failure({ErrorCode::capacity});

    TaintedProvenance child{
        parent.origin_fingerprint,
        std::move(chain),
        std::vector<std::string>{merged_sources.begin(), merged_sources.end()},
        parent.hop_count + 1U,
        parent.max_hops,
    };
    return Result<TaintedProvenance>::success(std::move(child));
  } catch (const std::bad_alloc &) {
    return Result<TaintedProvenance>::failure({ErrorCode::allocation});
  }
}

Result<void> verify_taint_monotonicity(const TaintTransitionCheck &transition) {
  auto parent_ok = validate_tainted_provenance(transition.parent);
  if (!parent_ok.has_value())
    return parent_ok;
  auto child_ok = validate_tainted_provenance(transition.child);
  if (!child_ok.has_value())
    return child_ok;

  if (transition.child.origin_fingerprint != transition.parent.origin_fingerprint)
    return Result<void>::failure({ErrorCode::conflict});
  if (transition.child.max_hops > transition.parent.max_hops)
    return Result<void>::failure({ErrorCode::conflict});
  if (transition.child.hop_count <= transition.parent.hop_count)
    return Result<void>::failure({ErrorCode::conflict});

  const std::vector<std::string> parent_chain = effective_hop_chain(transition.parent);
  const std::vector<std::string> child_chain = effective_hop_chain(transition.child);
  if (child_chain.size() <= parent_chain.size())
    return Result<void>::failure({ErrorCode::conflict});
  for (std::size_t i = 0; i < parent_chain.size(); ++i) {
    if (child_chain[i] != parent_chain[i])
      return Result<void>::failure({ErrorCode::conflict});
  }

  std::set<std::string_view> child_sources;
  for (const auto &src : transition.child.untrusted_sources)
    child_sources.insert(src);
  for (const auto &upstream : transition.parent.untrusted_sources) {
    if (!child_sources.contains(upstream))
      return Result<void>::failure({ErrorCode::conflict});
  }
  return Result<void>::success();
}

bool is_provenance_tainted(const TaintedProvenance &provenance) noexcept {
  return !provenance.untrusted_sources.empty();
}

Value tainted_provenance_to_value(const TaintedProvenance &provenance) {
  Value::Array hops;
  hops.reserve(provenance.hop_chain.size());
  for (const auto &hop : provenance.hop_chain)
    hops.emplace_back(hop);

  Value::Array sources;
  sources.reserve(provenance.untrusted_sources.size());
  for (const auto &src : provenance.untrusted_sources)
    sources.emplace_back(src);

  return Value::object({
      {"origin_fingerprint", Value{provenance.origin_fingerprint}},
      {"hop_chain", Value{std::move(hops)}},
      {"untrusted_sources", Value{std::move(sources)}},
      {"hop_count", Value{Number{provenance.hop_count}}},
      {"max_hops", Value{Number{provenance.max_hops}}},
  });
}

Result<TaintedProvenance> tainted_provenance_from_value(const Value &value) {
  const auto *obj = std::get_if<Value::Object>(&value.value());
  if (!obj)
    return Result<TaintedProvenance>::failure({ErrorCode::corrupt});
  static constexpr std::array<std::string_view, 5> kKeys{
      "origin_fingerprint", "hop_chain", "untrusted_sources", "hop_count", "max_hops",
  };
  auto keys_ok = validate_strict_object_keys(*obj, kKeys);
  if (!keys_ok.has_value())
    return Result<TaintedProvenance>::failure(keys_ok.error());

  auto origin_fp = parse_string_field(value, "origin_fingerprint");
  auto hop_count = parse_uint64_field(value, "hop_count");
  auto max_hops = parse_uint64_field(value, "max_hops");
  if (!origin_fp.has_value() || !hop_count.has_value() || !max_hops.has_value() ||
      hop_count.value() > std::numeric_limits<std::uint32_t>::max() ||
      max_hops.value() > std::numeric_limits<std::uint32_t>::max()) {
    return Result<TaintedProvenance>::failure({ErrorCode::corrupt});
  }

  auto parse_str_arr = [&](std::string_view key,
                           std::size_t max_items) -> Result<std::vector<std::string>> {
    const Value *field = value.find(key);
    if (!field)
      return Result<std::vector<std::string>>::failure({ErrorCode::corrupt});
    const auto *arr = std::get_if<Value::Array>(&field->value());
    if (!arr || arr->size() > max_items)
      return Result<std::vector<std::string>>::failure({ErrorCode::corrupt});
    std::vector<std::string> out;
    out.reserve(arr->size());
    for (const auto &entry : *arr) {
      const auto *s = std::get_if<std::string>(&entry.value());
      if (!s)
        return Result<std::vector<std::string>>::failure({ErrorCode::corrupt});
      out.push_back(*s);
    }
    return Result<std::vector<std::string>>::success(std::move(out));
  };

  auto hops =
      parse_str_arr("hop_chain", static_cast<std::size_t>(kHardMaxProvenanceHops) + 1U);
  if (!hops.has_value())
    return Result<TaintedProvenance>::failure(hops.error());
  auto sources = parse_str_arr("untrusted_sources", kMaxProvenanceUntrustedSources);
  if (!sources.has_value())
    return Result<TaintedProvenance>::failure(sources.error());

  TaintedProvenance prov{
      std::move(origin_fp).value(),
      std::move(hops).value(),
      std::move(sources).value(),
      static_cast<std::uint32_t>(hop_count.value()),
      static_cast<std::uint32_t>(max_hops.value()),
  };
  auto valid = validate_tainted_provenance(prov);
  if (!valid.has_value())
    return Result<TaintedProvenance>::failure(valid.error());
  return Result<TaintedProvenance>::success(std::move(prov));
}

Result<PeerProvenance> merge_taint_into_peer_provenance(const TaintedProvenance &taint,
                                                        PeerProvenance destination) {
  auto valid = validate_tainted_provenance(taint);
  if (!valid.has_value())
    return Result<PeerProvenance>::failure(valid.error());
  try {
    std::set<std::string> merged;
    for (const auto &src : destination.untrusted_sources)
      merged.insert(src);
    for (const auto &src : taint.untrusted_sources)
      merged.insert(src);
    if (merged.size() > kBoardBridgeMaxUntrustedSources)
      return Result<PeerProvenance>::failure({ErrorCode::capacity});
    destination.untrusted_sources.assign(merged.begin(), merged.end());
    return Result<PeerProvenance>::success(std::move(destination));
  } catch (const std::bad_alloc &) {
    return Result<PeerProvenance>::failure({ErrorCode::allocation});
  }
}

} // namespace blackbird
