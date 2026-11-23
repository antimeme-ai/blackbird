#pragma once

#include "blackbird/foundation.hpp"

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace blackbird::mp {

// ---------------------------------------------------------------------------
// Error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

enum class MpError : std::int64_t {
  none = 0,

  // 52/53-bit safe integer IDs
  id_zero = 100,
  id_exceeds_safe_int = 101,
  id_invalid_decimal = 102,

  // Cryptography & handles
  invalid_public_key = 200,
  weak_public_key = 201,
  invalid_signature = 202,
  invalid_handle = 203,
  reserved_handle = 204,
  crypto_internal = 205,

  // EndpointDescriptor
  endpoint_too_large = 300,
  endpoint_truncated = 301,
  endpoint_trailing_bytes = 302,
  invalid_transport_kind = 303,
  invalid_relay_policy = 304,
  invalid_relay_url = 305,
  too_many_direct_addrs = 306,
  invalid_addr_family = 307,
  invalid_port = 308,
  disallowed_direct_addr = 309,
  force_relays_violation = 310,
  no_relays_violation = 311,

  // CBOR / COSE_Sign1 / CWT
  cwt_too_large = 400,
  cwt_invalid_cbor = 401,
  cwt_invalid_envelope_shape = 402,
  cwt_invalid_protected_header = 403,
  cwt_non_empty_unprotected_header = 404,
  cwt_invalid_signature_length = 405,
  cwt_invalid_claims = 406,
  cwt_issuer_mismatch = 407,
  cwt_device_key_mismatch = 408,
  cwt_future_issued_at = 409,
  cwt_expired = 410,
  cwt_ttl_exceeded = 411,

  // RFC 9421 + RFC 9530
  rfc9421_unsupported_method = 500,
  rfc9421_invalid_authority = 501,
  rfc9421_invalid_path = 502,
  rfc9421_query_not_allowed = 503,
  rfc9421_unexpected_body_on_get = 504,
  rfc9421_content_encoding_forbidden = 505,
  rfc9421_missing_content_type = 506,
  rfc9421_invalid_content_digest = 507,
  rfc9421_content_digest_mismatch = 508,
  rfc9421_invalid_signature_input = 509,
  rfc9421_invalid_covered_components = 510,
  rfc9421_invalid_algorithm = 511,
  rfc9421_invalid_tag = 512,
  rfc9421_invalid_key_id = 513,
  rfc9421_invalid_nonce = 514,
  rfc9421_invalid_window = 515,
  rfc9421_clock_skew = 516,
  rfc9421_expired = 517,
  rfc9421_invalid_signature_header = 518,

  // MP1 binary framing
  mp1_frame_too_large = 600,
  mp1_truncated = 601,
  mp1_trailing_bytes = 602,
  mp1_unsupported_version = 603,
  mp1_non_zero_flags = 604,
  mp1_non_zero_reserved = 605,
  mp1_unknown_opcode = 606,
  mp1_length_mismatch = 607,
  mp1_invalid_enum_value = 608,
  mp1_invalid_bool = 609,
  mp1_invalid_count = 610,
  mp1_safe_int_exceeded = 611,
  mp1_invalid_cwt_length = 612,
};

constexpr MpError mp_error_of(const Error &error) noexcept {
  return static_cast<MpError>(error.detail);
}

const char *mp_error_name(MpError detail) noexcept;

// ---------------------------------------------------------------------------
// 1. Strongly-typed 52/53-bit safe positive integer IDs
// ---------------------------------------------------------------------------

inline constexpr std::uint64_t kMaxSafeId = (std::uint64_t{1} << 53U) - 1U;
inline constexpr std::uint64_t kMaxRandomGlobalId = (std::uint64_t{1} << 52U) - 1U;

Result<std::uint64_t> parse_safe_decimal_id(std::string_view text);
Result<std::uint64_t> generate_random_global_id();

template <typename Tag> class SafeId {
public:
  static constexpr Result<SafeId> create(std::uint64_t raw) {
    if (raw == 0U) {
      return Result<SafeId>::failure(
          {ErrorCode::invalid_range, static_cast<std::int64_t>(MpError::id_zero)});
    }
    if (raw > kMaxSafeId) {
      return Result<SafeId>::failure(
          {ErrorCode::invalid_range,
           static_cast<std::int64_t>(MpError::id_exceeds_safe_int)});
    }
    return Result<SafeId>::success(SafeId{raw});
  }

  static Result<SafeId> parse_decimal(std::string_view text) {
    const auto parsed = parse_safe_decimal_id(text);
    if (!parsed.has_value()) {
      return Result<SafeId>::failure(parsed.error());
    }
    return create(parsed.value());
  }

  static constexpr Result<SafeId>
  from_le_bytes(std::span<const std::uint8_t, 8> bytes) {
    std::uint64_t raw = 0U;
    for (std::size_t i = 0; i < 8U; ++i) {
      raw |= static_cast<std::uint64_t>(bytes[i]) << (i * 8U);
    }
    return create(raw);
  }

  constexpr std::array<std::uint8_t, 8> to_le_bytes() const noexcept {
    std::array<std::uint8_t, 8> out{};
    for (std::size_t i = 0; i < 8U; ++i) {
      out[i] = static_cast<std::uint8_t>((value_ >> (i * 8U)) & 0xffU);
    }
    return out;
  }

  constexpr std::uint64_t value() const noexcept { return value_; }
  std::string to_decimal() const { return std::to_string(value_); }

  auto operator<=>(const SafeId &) const = default;

private:
  constexpr explicit SafeId(std::uint64_t value) noexcept : value_(value) {}
  std::uint64_t value_;
};

struct AccountIdTag;
struct DeviceIdTag;
struct PartyIdTag;
struct InviteIdTag;
struct PartyInviteIdTag;
struct SessionIdTag;
struct RequestIdTag;

using AccountId = SafeId<AccountIdTag>;
using DeviceId = SafeId<DeviceIdTag>;
using PartyId = SafeId<PartyIdTag>;
using InviteId = SafeId<InviteIdTag>;
using PartyInviteId = SafeId<PartyInviteIdTag>;
using SessionId = SafeId<SessionIdTag>;
using RequestId = SafeId<RequestIdTag>;

// ---------------------------------------------------------------------------
// 2. OpenSSL 3 cryptography primitives & mutable handle validation
// ---------------------------------------------------------------------------

using Ed25519PubKey = std::array<std::uint8_t, 32>;
using Ed25519Seed = std::array<std::uint8_t, 32>;
using Ed25519Sig = std::array<std::uint8_t, 64>;
using Sha256Digest = std::array<std::uint8_t, 32>;

struct ConstantTimeCompare {
  std::span<const std::uint8_t> lhs;
  std::span<const std::uint8_t> rhs;
};

struct Ed25519VerifyInput {
  Ed25519PubKey pubkey{};
  std::span<const std::uint8_t> message;
  Ed25519Sig signature{};
};

class Ed25519SigningKey {
public:
  static Result<Ed25519SigningKey> generate();
  static Result<Ed25519SigningKey> from_seed(const Ed25519Seed &seed);

  Ed25519SigningKey(const Ed25519SigningKey &) = delete;
  Ed25519SigningKey &operator=(const Ed25519SigningKey &) = delete;
  Ed25519SigningKey(Ed25519SigningKey &&other) noexcept;
  Ed25519SigningKey &operator=(Ed25519SigningKey &&other) noexcept;
  ~Ed25519SigningKey();

  bool valid() const noexcept { return valid_; }
  const Ed25519PubKey &public_key() const noexcept { return public_key_; }
  Result<Ed25519Sig> sign(std::span<const std::uint8_t> message) const;

private:
  struct KeyMaterial {
    Ed25519Seed seed{};
    Ed25519PubKey public_key{};
  };
  explicit Ed25519SigningKey(const KeyMaterial &material) noexcept
      : seed_(material.seed), public_key_(material.public_key), valid_(true) {}
  void cleanse() noexcept;

  Ed25519Seed seed_{};
  Ed25519PubKey public_key_{};
  bool valid_ = false;
};

Result<Sha256Digest> sha256(std::span<const std::uint8_t> data);
std::string hex_lower(std::span<const std::uint8_t> bytes);
Result<void> random_bytes(std::span<std::uint8_t> out);
Result<std::string> generate_nonce_b64url(std::size_t raw_bytes = 24U);
bool constant_time_equal(const ConstantTimeCompare &cmp) noexcept;

Result<void> validate_ed25519_pubkey_strict(const Ed25519PubKey &pubkey);
Result<void> verify_ed25519_strict(const Ed25519VerifyInput &input);

Result<Sha256Digest>
hash_account_invite_secret(std::span<const std::uint8_t, 32> raw_secret);
Result<Sha256Digest>
hash_party_invite_secret(PartyId party_id,
                         std::span<const std::uint8_t, 32> raw_secret);

class AccountHandle {
public:
  static Result<AccountHandle> parse(std::string_view raw);

  std::string_view display() const noexcept { return display_; }
  std::string_view normalized() const noexcept { return normalized_; }

  bool operator==(const AccountHandle &) const = default;

private:
  AccountHandle(std::string display, std::string normalized)
      : display_(std::move(display)), normalized_(std::move(normalized)) {}
  std::string display_;
  std::string normalized_;
};

// ---------------------------------------------------------------------------
// 3. Strictly parsed EndpointDescriptor binary codec (<= 256 B)
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMaxEndpointDescriptorBytes = 256U;
inline constexpr std::size_t kMaxRelayUrlBytes = 100U;
inline constexpr std::size_t kMaxDirectAddrs = 8U;

enum class TransportKind : std::uint8_t {
  iroh_quic = 1,
  direct_quic = 2,
};

enum class RelayPolicy : std::uint8_t {
  allow_relays = 0,
  force_relays = 1,
  no_relays = 2,
};

struct DirectAddrV4 {
  std::array<std::uint8_t, 4> ip{};
  std::uint16_t port = 0U;
  bool operator==(const DirectAddrV4 &) const = default;
};

struct DirectAddrV6 {
  std::array<std::uint8_t, 16> ip{};
  std::uint16_t port = 0U;
  bool operator==(const DirectAddrV6 &) const = default;
};

using DirectAddr = std::variant<DirectAddrV4, DirectAddrV6>;

Result<void> validate_relay_url(std::string_view url);
Result<void> validate_pinned_relay_url(RelayPolicy policy,
                                       std::string_view pinned_relay_url);

struct EndpointDescriptor {
  TransportKind transport_kind = TransportKind::iroh_quic;
  std::string relay_url;
  std::vector<DirectAddr> direct_addrs;

  Result<void> validate() const;
  Result<void> validate_against_policy(RelayPolicy policy,
                                       std::string_view pinned_relay_url) const;
  Result<std::vector<std::uint8_t>> encode() const;
  static Result<EndpointDescriptor> decode(std::span<const std::uint8_t> bytes);

  bool operator==(const EndpointDescriptor &) const = default;
};

// ---------------------------------------------------------------------------
// 4. MP1 16-byte LE binary control-plane WebSocket wire codec
// ---------------------------------------------------------------------------

inline constexpr std::uint8_t kMp1Version = 1U;
inline constexpr std::size_t kMp1HeaderBytes = 16U;
inline constexpr std::size_t kMaxMp1FrameBytes = 8192U;
inline constexpr std::size_t kMaxPartyMembers = 12U;
inline constexpr std::size_t kMaxPresenceEntries = 256U;

enum class Opcode : std::uint16_t {
  hello_ack = 0x0001,
  error = 0x0002,
  presence_set = 0x0101,
  presence_snapshot = 0x0102,
  presence_delta = 0x0103,
  social_event = 0x0104,
  party_invite_notify = 0x0105,
  party_snapshot = 0x0201,
  party_member_joined = 0x0202,
  party_endpoint_update = 0x0203,
  party_member_updated = 0x0204,
  party_member_left = 0x0205,
  party_leader_changed = 0x0206,
  party_join_request_event = 0x0207,
  party_disbanded = 0x0208,
};

enum class SocketRole : std::uint8_t {
  account = 1,
  party = 2,
};

constexpr bool opcode_allowed_from_client(Opcode opcode, SocketRole role) noexcept {
  switch (role) {
  case SocketRole::account:
    return opcode == Opcode::presence_set;
  case SocketRole::party:
    return opcode == Opcode::party_endpoint_update;
  }
  return false;
}

enum class PresenceVisibility : std::uint8_t {
  invisible = 0,
  online = 1,
  idle = 2,
  busy = 3,
};

enum class SocialEventKind : std::uint8_t {
  friend_request = 1,
  friend_accepted = 2,
  unfriended = 3,
};

enum class PartyVisibility : std::uint8_t {
  private_party = 0,
  friends = 1,
};

enum class PartyJoinMode : std::uint8_t {
  invite_only = 0,
  approval_required = 1,
};

enum class MemberLeaveReason : std::uint8_t {
  left = 0,
  kicked = 1,
  disconnected_timeout = 2,
  device_revoked = 3,
  connect_timeout = 4,
};

enum class PartyLeaderChangeReason : std::uint8_t {
  promoted = 0,
  auto_migrated = 1,
};

enum class PartyDisbandReason : std::uint8_t {
  leader_disbanded = 0,
  empty_timeout = 1,
};

struct FrameHeader {
  Opcode opcode = Opcode::hello_ack;
  std::uint32_t seq = 0U;
  std::uint32_t payload_len = 0U;
  bool operator==(const FrameHeader &) const = default;
};

struct HelloAckMessage {
  SessionId session_id;
  std::uint64_t server_now_ms = 0U;
  std::uint32_t ping_interval_ms = 0U;
  bool operator==(const HelloAckMessage &) const = default;
};

struct ErrorMessage {
  std::uint32_t ref_seq = 0U;
  std::uint16_t code = 0U;
  std::uint32_t retry_after_ms = 0U;
  bool operator==(const ErrorMessage &) const = default;
};

struct PresenceSetMessage {
  PresenceVisibility visibility = PresenceVisibility::invisible;
  bool share_party = false;
  bool operator==(const PresenceSetMessage &) const = default;
};

struct PresenceEntry {
  AccountId account_id;
  PresenceVisibility status = PresenceVisibility::invisible;
  std::optional<PartyId> joinable_party_id;
  std::uint64_t updated_ms = 0U;
  bool operator==(const PresenceEntry &) const = default;
};

struct PresenceSnapshotMessage {
  std::vector<PresenceEntry> entries;
  bool operator==(const PresenceSnapshotMessage &) const = default;
};

struct PresenceDeltaMessage {
  PresenceEntry entry;
  bool operator==(const PresenceDeltaMessage &) const = default;
};

struct SocialEventMessage {
  SocialEventKind kind = SocialEventKind::friend_request;
  AccountId peer_account_id;
  bool operator==(const SocialEventMessage &) const = default;
};

struct PartyInviteNotifyMessage {
  PartyInviteId party_invite_id;
  PartyId party_id;
  AccountId from_account_id;
  std::uint64_t expires_at_ms = 0U;
  bool operator==(const PartyInviteNotifyMessage &) const = default;
};

struct PartyMemberRecord {
  DeviceId device_id;
  AccountId account_id;
  Ed25519PubKey root_pubkey{};
  Ed25519PubKey device_pubkey{};
  std::vector<std::uint8_t> device_cwt;
  EndpointDescriptor endpoint;
  std::uint64_t joined_seq = 0U;
  bool connected = false;
  bool operator==(const PartyMemberRecord &) const = default;
};

struct PartySnapshotMessage {
  PartyId party_id;
  std::uint64_t party_epoch = 0U;
  AccountId leader_account_id;
  DeviceId leader_device_id;
  PartyVisibility visibility = PartyVisibility::private_party;
  PartyJoinMode join_mode = PartyJoinMode::invite_only;
  RelayPolicy relay_policy = RelayPolicy::allow_relays;
  std::uint8_t max_members = 2U;
  std::string pinned_relay_url;
  std::vector<PartyMemberRecord> members;
  bool operator==(const PartySnapshotMessage &) const = default;
};

struct PartyMemberJoinedMessage {
  std::uint64_t party_epoch = 0U;
  PartyMemberRecord member;
  bool operator==(const PartyMemberJoinedMessage &) const = default;
};

struct PartyEndpointUpdateMessage {
  EndpointDescriptor endpoint;
  bool operator==(const PartyEndpointUpdateMessage &) const = default;
};

struct PartyMemberUpdatedMessage {
  std::uint64_t party_epoch = 0U;
  DeviceId device_id;
  bool connected = false;
  std::vector<std::uint8_t> device_cwt;
  EndpointDescriptor endpoint;
  bool operator==(const PartyMemberUpdatedMessage &) const = default;
};

struct PartyMemberLeftMessage {
  std::uint64_t party_epoch = 0U;
  DeviceId device_id;
  AccountId account_id;
  MemberLeaveReason reason = MemberLeaveReason::left;
  bool operator==(const PartyMemberLeftMessage &) const = default;
};

struct PartyLeaderChangedMessage {
  std::uint64_t party_epoch = 0U;
  AccountId new_leader_account_id;
  DeviceId new_leader_device_id;
  PartyLeaderChangeReason reason = PartyLeaderChangeReason::promoted;
  bool operator==(const PartyLeaderChangedMessage &) const = default;
};

struct PartyJoinRequestEventMessage {
  RequestId request_id;
  AccountId account_id;
  DeviceId device_id;
  Ed25519PubKey root_pubkey{};
  Ed25519PubKey device_pubkey{};
  bool operator==(const PartyJoinRequestEventMessage &) const = default;
};

struct PartyDisbandedMessage {
  std::uint64_t party_epoch = 0U;
  PartyDisbandReason reason = PartyDisbandReason::leader_disbanded;
  bool operator==(const PartyDisbandedMessage &) const = default;
};

using Mp1Message = std::variant<
    HelloAckMessage, ErrorMessage, PresenceSetMessage, PresenceSnapshotMessage,
    PresenceDeltaMessage, SocialEventMessage, PartyInviteNotifyMessage,
    PartySnapshotMessage, PartyMemberJoinedMessage, PartyEndpointUpdateMessage,
    PartyMemberUpdatedMessage, PartyMemberLeftMessage, PartyLeaderChangedMessage,
    PartyJoinRequestEventMessage, PartyDisbandedMessage>;

Opcode opcode_of(const Mp1Message &message) noexcept;

struct DecodedFrame {
  FrameHeader header;
  Mp1Message message;
  bool operator==(const DecodedFrame &) const = default;
};

Result<std::vector<std::uint8_t>> encode_frame(std::uint32_t seq,
                                               const Mp1Message &message);
Result<DecodedFrame> decode_frame(std::span<const std::uint8_t> bytes);

// ---------------------------------------------------------------------------
// 5. Strict RFC 9421 (tag="mp1", alg="ed25519") + RFC 9530 HTTP auth
// ---------------------------------------------------------------------------

inline constexpr std::int64_t kMaxClockSkewSecs = 60;
inline constexpr std::int64_t kMaxSignatureWindowSecs = 120;
inline constexpr std::int64_t kNonceRetentionSlackMs = 5000;
inline constexpr std::size_t kMinNonceLen = 22U;
inline constexpr std::size_t kMaxNonceLen = 64U;

enum class HttpMethod : std::uint8_t {
  get,
  post,
  put,
  patch,
  del,
};

constexpr std::string_view http_method_name(HttpMethod method) noexcept {
  switch (method) {
  case HttpMethod::get:
    return "GET";
  case HttpMethod::post:
    return "POST";
  case HttpMethod::put:
    return "PUT";
  case HttpMethod::patch:
    return "PATCH";
  case HttpMethod::del:
    return "DELETE";
  }
  return "";
}

constexpr bool method_requires_body_headers(HttpMethod method) noexcept {
  return method != HttpMethod::get;
}

Result<HttpMethod> parse_http_method(std::string_view name);

struct DeviceKeyId {
  AccountId account_id;
  DeviceId device_id;
  bool operator==(const DeviceKeyId &) const = default;
};

struct RootKeyId {
  AccountId account_id;
  bool operator==(const RootKeyId &) const = default;
};

struct RegistrationKeyId {
  std::array<std::uint8_t, 16> root_pubkey_sha256_prefix{};
  bool operator==(const RegistrationKeyId &) const = default;
};

using KeyId = std::variant<DeviceKeyId, RootKeyId, RegistrationKeyId>;

Result<KeyId> parse_key_id(std::string_view raw);
std::string format_key_id(const KeyId &key_id);
Result<RegistrationKeyId> registration_key_id_for_pubkey(const Ed25519PubKey &pubkey);

Result<std::string> compute_content_digest(std::span<const std::uint8_t> body);

struct HttpTarget {
  HttpMethod method = HttpMethod::get;
  std::string_view path;
  std::string_view query;
};

Result<void> validate_path_and_query(const HttpTarget &target);

struct ParsedSignatureInput {
  std::vector<std::string> components;
  std::string canonical_params;
  std::int64_t created = 0;
  std::int64_t expires = 0;
  std::string nonce;
  std::string keyid_raw;
  KeyId keyid = RegistrationKeyId{};
  bool operator==(const ParsedSignatureInput &) const = default;
};

Result<ParsedSignatureInput> parse_signature_input(std::string_view header);
Result<Ed25519Sig> parse_signature_header(std::string_view header);

struct Rfc9421Request {
  HttpMethod method = HttpMethod::get;
  std::string_view authority;
  std::string_view path;
  // Per RFC 9421 section 2.2.7: always starts with '?' ("?" when empty).
  std::string_view query;
  std::optional<std::string_view> content_type;
  std::optional<std::string_view> content_digest;
  bool has_content_encoding = false;
  std::span<const std::uint8_t> body;
  std::string_view signature_input;
  std::string_view signature;
};

struct Rfc9421SignRequest {
  HttpMethod method = HttpMethod::get;
  std::string_view authority;
  std::string_view path;
  std::string_view query;
  std::optional<std::string_view> content_type;
  std::span<const std::uint8_t> body;
  KeyId keyid = RegistrationKeyId{};
  std::int64_t created = 0;
  std::int64_t expires = 0;
  // Optional: if empty, a fresh 24-byte (32 base64url char) CSPRNG nonce is generated.
  std::string_view nonce;
};

struct SignedRfc9421Headers {
  std::string signature_input;
  std::string signature;
  std::optional<std::string> content_digest;
  std::string nonce;
  std::vector<std::uint8_t> signature_base;
};

struct Rfc9421VerifyInput {
  Rfc9421Request request;
  std::string_view expected_authority;
  Ed25519PubKey pubkey{};
  std::int64_t now_s = 0;
};

struct VerifiedSignature {
  KeyId keyid = RegistrationKeyId{};
  std::string nonce;
  std::int64_t created = 0;
  std::int64_t expires = 0;
  std::int64_t retain_until_ms = 0;
  bool operator==(const VerifiedSignature &) const = default;
};

Result<std::vector<std::uint8_t>>
build_signature_base(const Rfc9421Request &request, const ParsedSignatureInput &parsed);
Result<SignedRfc9421Headers> sign_rfc9421_request(const Ed25519SigningKey &signing_key,
                                                  const Rfc9421SignRequest &request);
Result<VerifiedSignature> verify_rfc9421_request(const Rfc9421VerifyInput &input);

// ---------------------------------------------------------------------------
// 6. RFC 8949 Deterministic CBOR + RFC 9052 COSE_Sign1 (Ed25519 = -19) +
//    RFC 8392/8747 Device CWT
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMaxCwtBytes = 256U;
inline constexpr std::int64_t kMaxCwtTtlSecs = 30 * 24 * 60 * 60;
inline constexpr std::int64_t kMaxCwtIatSkewSecs = 60;
inline constexpr std::array<std::uint8_t, 3> kProtectedHeaderEd25519 = {0xa1U, 0x01U,
                                                                        0x32U};

struct CwtClaims {
  std::string iss;
  std::int64_t iat = 0;
  std::int64_t exp = 0;
  Ed25519PubKey device_pubkey{};
  bool operator==(const CwtClaims &) const = default;
};

struct DeviceCwtMintRequest {
  Ed25519PubKey device_pubkey{};
  std::int64_t issued_at_s = 0;
  std::int64_t expires_at_s = 0;
};

struct DeviceCwtVerifyRequest {
  std::span<const std::uint8_t> cwt_bytes;
  Ed25519PubKey expected_root_pubkey{};
  std::optional<Ed25519PubKey> expected_device_pubkey;
  std::int64_t now_s = 0;
};

Result<std::vector<std::uint8_t>>
encode_device_cwt(const Ed25519SigningKey &root_signing_key,
                  const DeviceCwtMintRequest &request);
Result<CwtClaims> verify_device_cwt(const DeviceCwtVerifyRequest &request);

// Zero-RTT peer verification helper confirming member.device_cwt validly delegates
// member.device_pubkey under member.root_pubkey and is unexpired at now_s.
Result<CwtClaims> verify_party_member_cwt(const PartyMemberRecord &member,
                                          std::int64_t now_s);

} // namespace blackbird::mp
