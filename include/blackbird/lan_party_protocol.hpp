#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/mp_client.hpp"
#include "blackbird/mp_protocol.hpp"
#include "blackbird/p2p_transport.hpp"

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace blackbird::lan {

// ---------------------------------------------------------------------------
// Error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

enum class LanError : std::int64_t {
  none = 0,

  // Cryptography & PIN proofs
  invalid_pin = 2000,
  invalid_lan_party_id = 2001,
  invalid_pubkey = 2002,
  pin_proof_mismatch = 2003,
  crypto_internal = 2004,

  // Policy engine (Mandates #1, #2, #3, #6)
  lan_disabled = 2100,
  policy_parse_error = 2101,
  policy_insecure_file = 2102,
  policy_symlink_rejected = 2103,
  policy_io_failed = 2104,

  // Local LAN identity & Safety Number
  invalid_display_name = 2200,
  identity_insecure_permissions = 2201,
  identity_symlink_rejected = 2202,
  identity_corrupt = 2203,
  identity_io_failed = 2204,

  // Local OS presence guard (Mandate #6)
  local_auth_denied = 2300,
  local_auth_unavailable = 2301,
  local_auth_failed = 2302,

  // In-TLS Lane-0 handshake framing
  frame_too_large = 2400,
  frame_truncated = 2401,
  frame_unsupported_version = 2402,
  frame_unknown_kind = 2403,
  frame_non_zero_reserved = 2404,
  frame_lane_mismatch = 2405,
  frame_invalid_utf8 = 2406,
  frame_invalid_json = 2407,
  frame_invalid_field = 2408,
  frame_too_many_members = 2409,

  // PIN brute-force rate limiting
  pin_peer_locked = 2500,
  pin_lobby_locked = 2501,
};

constexpr LanError lan_error_of(const Error &error) noexcept {
  return static_cast<LanError>(error.detail);
}

std::string_view lan_error_name(LanError detail) noexcept;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

inline constexpr std::string_view kLanPinDeriveContext = "mp1-lan-pin-v1";
inline constexpr std::string_view kLanJoinProofDomain = "mp1-lan-join";
inline constexpr std::size_t kLanPinMaxBytes = 64U;
inline constexpr std::size_t kLanPartyIdBytes = 8U;
inline constexpr std::size_t kLanPartyIdHexLen = 16U;
inline constexpr std::size_t kLanNonceBytes = 32U;
inline constexpr std::size_t kLanPinProofBytes = 32U;

inline constexpr std::uint32_t kDefaultLanIdleTimeoutSec = 300U;
inline constexpr std::uint32_t kMaxLanIdleTimeoutSec = 1800U;
inline constexpr std::uint32_t kDefaultLanScanTimeoutSec = 15U;
inline constexpr std::uint32_t kMaxLanScanTimeoutSec = 60U;
inline constexpr std::string_view kDefaultSystemLanPolicyPath =
    "/etc/multiplayer/lan.toml";
inline constexpr std::size_t kMaxLanPolicyFileBytes = 16U * 1024U;

inline constexpr std::uint8_t kLanHandshakeVersion = 1U;
inline constexpr std::size_t kLanHandshakeHeaderBytes = 4U;
inline constexpr std::size_t kLanHandshakeMaxFrameBytes = kP2pMaxControlFrameBytes;
inline constexpr std::size_t kLanMaxNameBytes = 32U;
inline constexpr std::size_t kLanMaxMembers = 12U;
inline constexpr std::size_t kLanMaxRejectReasonBytes = 128U;

inline constexpr std::uint32_t kLanPinMaxPeerFailures = 5U;
inline constexpr std::uint32_t kLanPinMaxLobbyFailures = 15U;

using Blake3Digest = std::array<std::uint8_t, 32>;
using Blake3Key = std::array<std::uint8_t, 32>;
using LanPartyId = std::array<std::uint8_t, kLanPartyIdBytes>;
using LanNonce = std::array<std::uint8_t, kLanNonceBytes>;
using LanPinProof = std::array<std::uint8_t, kLanPinProofBytes>;

// ---------------------------------------------------------------------------
// 1. Owned C++23 BLAKE3 & mp1-lan/1 PIN challenge-response
// ---------------------------------------------------------------------------

Blake3Digest blake3_hash(std::span<const std::uint8_t> input) noexcept;
Blake3Digest blake3_keyed_hash(const Blake3Key &key,
                               std::span<const std::uint8_t> input) noexcept;
Blake3Digest blake3_derive_key(std::string_view context,
                               std::span<const std::uint8_t> key_material) noexcept;

// Fixed-capacity PIN buffer cleansed with OPENSSL_cleanse on destruction/move.
// Avoids std::string SSO leaks for short PINs.
class CleansedPin {
public:
  CleansedPin() noexcept = default;
  CleansedPin(const CleansedPin &other) noexcept;
  CleansedPin &operator=(const CleansedPin &other) noexcept;
  CleansedPin(CleansedPin &&other) noexcept;
  CleansedPin &operator=(CleansedPin &&other) noexcept;
  ~CleansedPin();

  static Result<CleansedPin> create(std::string_view raw);

  std::string_view view() const noexcept {
    return std::string_view{reinterpret_cast<const char *>(bytes_.data()), len_};
  }
  std::span<const std::uint8_t> bytes() const noexcept {
    return std::span<const std::uint8_t>{bytes_.data(), len_};
  }
  std::size_t size() const noexcept { return len_; }
  bool empty() const noexcept { return len_ == 0U; }
  void cleanse() noexcept;

private:
  std::array<std::uint8_t, kLanPinMaxBytes> bytes_{};
  std::size_t len_ = 0U;
};

// Validates a PIN for mp1-lan/1: 1..64 UTF-8 bytes, no ASCII/C1 control characters
// or BiDi formatting overrides. Callers supplying non-ASCII Unicode should provide
// NFC-normalized UTF-8 (all printable ASCII is already NFC).
Result<void> validate_lan_pin(std::string_view pin);

Result<LanPartyId> parse_lan_party_id_hex(std::string_view hex);
std::string format_lan_party_id_hex(const LanPartyId &id);

struct LanPinProofInput {
  std::string_view pin;
  std::string_view lan_party_id_hex;
  mp::Ed25519PubKey host_pubkey{};
  mp::Ed25519PubKey joiner_pubkey{};
  LanNonce host_nonce{};
};

// Computes:
//   key = blake3_derive_key("mp1-lan-pin-v1", pin_utf8_bytes)
//   msg = "mp1-lan-join" (12B) || lan_party_id_bytes (8B) || host_pubkey (32B) ||
//         joiner_pubkey (32B) || host_nonce (32B)
//   proof = blake3_keyed_hash(key, msg)
Result<LanPinProof> compute_lan_pin_proof(const LanPinProofInput &input);

// Constant-time verification via CRYPTO_memcmp, cleansing derived key & expected
// proof on scope exit.
Result<bool> verify_lan_pin_proof(const LanPinProofInput &input,
                                  const LanPinProof &provided_proof);

// ---------------------------------------------------------------------------
// 2. Mandates #1, #2, #3, #6 Policy Engine (system non-overridable floor)
// ---------------------------------------------------------------------------

using EnvLookupFn = std::function<std::optional<std::string>(std::string_view)>;

struct LanPolicyConfig {
  bool disabled = false;
  bool require_pin = false;
  bool require_local_auth = false;
  std::uint32_t idle_timeout_sec = kDefaultLanIdleTimeoutSec;
  std::uint32_t scan_timeout_sec = kDefaultLanScanTimeoutSec;

  bool operator==(const LanPolicyConfig &) const = default;
};

struct LanPolicyPaths {
  std::filesystem::path system_policy_path = std::string{kDefaultSystemLanPolicyPath};
  // When unset, resolved from XDG_CONFIG_HOME/blackbird/lan.toml or
  // HOME/.config/blackbird/lan.toml.
  std::optional<std::filesystem::path> user_policy_path = std::nullopt;
  // Expected owner UID of system_policy_path (defaults to root = 0; overridable
  // in unit tests).
  std::uint32_t expected_system_uid = 0U;
  // Expected owner UID of user_policy_path (defaults to geteuid() when unset).
  std::optional<std::uint32_t> expected_user_uid = std::nullopt;
};

// Strict minimal TOML parser for the [lan] section. Fails closed on unknown keys,
// unknown sections, duplicate keys, malformed lines, or invalid types/ranges.
Result<LanPolicyConfig> parse_lan_policy_toml(std::string_view text);

// Loads optional system and user LAN policy files plus MP_DISABLE_LAN /
// BLACKBIRD_DISABLE_LAN kill-switches, enforcing the system policy as a
// non-overridable floor and failing closed on tampered/symlink/malformed files.
Result<LanPolicyConfig> load_effective_lan_policy(const LanPolicyPaths &paths = {},
                                                  const EnvLookupFn &env_lookup = {});

// ---------------------------------------------------------------------------
// 3. Local-only LAN Identity & Canonical Safety Number
// ---------------------------------------------------------------------------

bool is_valid_lan_name(std::string_view name) noexcept;
std::string sanitize_lan_display_name(std::string_view raw);

// Computes the canonical 39-character Crockford Base32 Safety Number
// (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX).
// Delegates directly to mp::compute_safety_number when account_id > 0, and uses the
// exact same SHA-256("mp-safety-v1:" || u64_le(0) || pubkey) formula for
// unregistered local-only LAN identities (account_id == 0).
Result<std::string> compute_lan_safety_number(std::uint64_t account_id,
                                              const mp::Ed25519PubKey &pubkey);

struct LanIdentity {
  std::uint64_t account_id = 0U;
  bool is_online_identity = false;
  std::string display_name;
  mp::Ed25519PubKey public_key{};
  mp::CleansedSeed signing_seed;
  std::string safety_number;

  Result<mp::Ed25519SigningKey> signing_key() const;
  bool operator==(const LanIdentity &) const = default;
};

struct LanIdentityRequest {
  std::optional<std::filesystem::path> online_state_dir = std::nullopt;
  std::filesystem::path lan_state_dir;
  std::string preferred_display_name;
};

// If an online MpIdentityStore exists in online_state_dir with an account_id,
// derives LanIdentity from its Ed25519 root (or device) key + handle + account_id.
// Otherwise loads or creates a 0600 (O_NOFOLLOW, atomic rename) local-only Ed25519
// seed file at lan_state_dir / "identity.json" with account_id = 0.
Result<LanIdentity> load_or_create_lan_identity(const LanIdentityRequest &request);

// ---------------------------------------------------------------------------
// 4. Mandate #6 Local OS Presence Guard
// ---------------------------------------------------------------------------

using LocalAuthPromptFn = std::function<Result<void>(std::string_view reason)>;

struct LocalAuthOptions {
  std::string_view reason = "Authorize Blackbird LAN Party action";
  LocalAuthPromptFn prompt_override = {};
  EnvLookupFn env_lookup = {};
  bool allow_sudo_fallback = true;
};

// Verifies live local operator presence before LAN host/join/pin when
// lan.require_local_auth is enabled:
// - macOS: dynamic LocalAuthentication.framework LAContext
//   (LAPolicyDeviceOwnerAuthentication = 2), falling back to `posix_spawn`
//   `/usr/bin/sudo -k` then `/usr/bin/sudo -v` on headless SSH sessions.
// - Linux: `posix_spawn` `/usr/bin/sudo -k` then `/usr/bin/sudo -v`.
Result<void> verify_local_os_presence(const LocalAuthOptions &options = {});

// ---------------------------------------------------------------------------
// 5. In-TLS Lane-0 Handshake Framing & PIN Brute-Force Lockout
//
// Wire format on P2pLane::control (total frame <= 64 KiB):
//   [0]    u8  version  = 0x01
//   [1]    u8  kind     = 0x10 lan_hello
//                       | 0x11 lan_join
//                       | 0x12 lan_welcome
//                       | 0x13 lan_roster
//   [2]    u8  flags    = 0x00 (must be 0)
//   [3]    u8  reserved = 0x00 (must be 0)
//   [4..]  strict UTF-8 JSON object payload
// ---------------------------------------------------------------------------

enum class LanHandshakeKind : std::uint8_t {
  lan_hello = 0x10,
  lan_join = 0x11,
  lan_welcome = 0x12,
  lan_roster = 0x13,
};

std::string_view lan_handshake_kind_name(LanHandshakeKind kind) noexcept;

struct LanMemberInfo {
  std::uint64_t account_id = 0U;
  std::string display_name;
  mp::Ed25519PubKey pubkey{};
  bool is_host = false;

  bool operator==(const LanMemberInfo &) const = default;
};

struct LanHelloMessage {
  std::string lan_party_id;
  std::string lobby_name;
  std::string host_name;
  std::uint64_t host_account_id = 0U;
  mp::Ed25519PubKey host_pubkey{};
  bool require_pin = false;
  LanNonce host_nonce{};
  std::uint8_t max_members = static_cast<std::uint8_t>(kLanMaxMembers);

  bool operator==(const LanHelloMessage &) const = default;
};

struct LanJoinMessage {
  std::string lan_party_id;
  std::string display_name;
  std::uint64_t account_id = 0U;
  std::optional<LanPinProof> pin_proof = std::nullopt;

  bool operator==(const LanJoinMessage &) const = default;
};

struct LanWelcomeMessage {
  std::string lan_party_id;
  bool accepted = false;
  std::string reason;
  std::uint64_t roster_epoch = 0U;
  std::vector<LanMemberInfo> members;

  bool operator==(const LanWelcomeMessage &) const = default;
};

struct LanRosterMessage {
  std::string lan_party_id;
  std::uint64_t roster_epoch = 0U;
  bool locked = false;
  std::vector<LanMemberInfo> members;

  bool operator==(const LanRosterMessage &) const = default;
};

using LanHandshakeMessage =
    std::variant<LanHelloMessage, LanJoinMessage, LanWelcomeMessage, LanRosterMessage>;

LanHandshakeKind lan_handshake_kind(const LanHandshakeMessage &message) noexcept;

bool is_lan_handshake_frame(std::span<const std::uint8_t> bytes) noexcept;

Result<std::vector<std::uint8_t>>
encode_lan_handshake_frame(const LanHandshakeMessage &message);

Result<LanHandshakeMessage>
decode_lan_handshake_frame(P2pLane expected_lane, std::span<const std::uint8_t> bytes);

// Tracks failed PIN attempts per (joiner_pubkey, source_ip) and per lobby.
struct LanPinPeerKey {
  mp::Ed25519PubKey joiner_pubkey{};
  std::string source_ip;

  auto operator<=>(const LanPinPeerKey &) const = default;
};

enum class LanPinLockoutStatus : std::uint8_t {
  allowed = 0,
  peer_locked = 1,
  lobby_locked = 2,
};

struct LanPinRateLimitConfig {
  std::uint32_t max_peer_failures = kLanPinMaxPeerFailures;
  std::uint32_t max_lobby_failures = kLanPinMaxLobbyFailures;
};

class LanPinRateLimiter {
public:
  explicit LanPinRateLimiter(LanPinRateLimitConfig config = {}) noexcept;

  LanPinLockoutStatus check(const LanPinPeerKey &peer) const noexcept;
  LanPinLockoutStatus record_failure(const LanPinPeerKey &peer);
  void record_success(const LanPinPeerKey &peer) noexcept;

  std::uint32_t peer_failures(const LanPinPeerKey &peer) const noexcept;
  std::uint32_t total_failures() const noexcept { return total_failures_; }
  bool is_peer_locked(const LanPinPeerKey &peer) const noexcept;
  bool is_lobby_locked() const noexcept {
    return total_failures_ >= config_.max_lobby_failures;
  }
  void reset() noexcept;

private:
  LanPinRateLimitConfig config_;
  std::uint32_t total_failures_ = 0U;
  std::map<LanPinPeerKey, std::uint32_t> peer_failures_;
};

} // namespace blackbird::lan
