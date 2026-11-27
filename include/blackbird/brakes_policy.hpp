#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/lan_party_protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace blackbird::brakes {

// ---------------------------------------------------------------------------
// Error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

enum class BrakesError : std::int64_t {
  none = 0,

  // Profile & enum parsing
  invalid_profile = 3000,
  invalid_trust_profile = 3001,

  // Policy engine & system floor
  policy_parse_error = 3100,
  policy_insecure_file = 3101,
  policy_symlink_rejected = 3102,
  policy_io_failed = 3103,
  policy_floor_violation = 3104,
  invalid_env_override = 3105,

  // Provenance / framing / crypto
  crypto_internal = 3200,
  invalid_utf8 = 3201,

  // Path containment
  invalid_path = 3300,
  path_denied = 3301,
  path_symlink_escape = 3302,
};

constexpr BrakesError brakes_error_of(const Error &error) noexcept {
  return static_cast<BrakesError>(error.detail);
}

std::string_view brakes_error_name(BrakesError detail) noexcept;

// ---------------------------------------------------------------------------
// 1. Profiles & Monotonic Ordering
// ---------------------------------------------------------------------------

// Strictly ordered: higher numeric value = stricter containment.
enum class BrakesProfile : std::uint8_t {
  black_flag = 0,
  guarded = 1,
  sandboxed = 2,
  airgap = 3,
};

// Strictly ordered: lower numeric value = stricter peer trust restriction.
enum class PartyTrustProfile : std::uint8_t {
  advisory = 0,
  human_gated = 1,
  peer_trusted = 2,
  black_flag = 3,
};

std::string_view brakes_profile_name(BrakesProfile profile) noexcept;
Result<BrakesProfile> parse_brakes_profile(std::string_view text) noexcept;

std::string_view party_trust_profile_name(PartyTrustProfile profile) noexcept;
Result<PartyTrustProfile> parse_party_trust_profile(std::string_view text) noexcept;

constexpr bool is_contained_profile(BrakesProfile profile) noexcept {
  return profile > BrakesProfile::black_flag;
}

constexpr bool is_restricted_peer_trust(PartyTrustProfile profile) noexcept {
  return profile < PartyTrustProfile::black_flag;
}

// ---------------------------------------------------------------------------
// 2. Unified Monotonic Policy Engine
// ---------------------------------------------------------------------------

inline constexpr std::string_view kDefaultSystemPolicyPath =
    "/etc/multiplayer/policy.toml";
inline constexpr std::string_view kDefaultLegacySystemLanPolicyPath =
    lan::kDefaultSystemLanPolicyPath;
inline constexpr std::size_t kMaxPolicyFileBytes = 16U * 1024U;
inline constexpr std::size_t kMaxPolicyArrayEntries = 64U;
inline constexpr std::size_t kMaxPolicyStringBytes = 512U;
inline constexpr std::uint32_t kDefaultMaxTurnsPerPeer = 32U;
inline constexpr double kDefaultMaxCostUsdPerPeer = 2.0;

struct BrakesSectionPolicy {
  BrakesProfile min_profile = BrakesProfile::black_flag;
  BrakesProfile default_profile = BrakesProfile::black_flag;
  bool allow_escalation = true;
  bool require_local_auth_for_escalation = false;
  std::vector<std::string> extra_denied_paths;
  bool fail_closed_on_missing_sandbox = true;

  bool operator==(const BrakesSectionPolicy &) const = default;
};

struct PartyTrustSectionPolicy {
  PartyTrustProfile max_default_profile = PartyTrustProfile::black_flag;
  PartyTrustProfile max_peer_override = PartyTrustProfile::black_flag;
  PartyTrustProfile max_external_guest_profile = PartyTrustProfile::advisory;
  std::uint32_t max_turns_per_peer = kDefaultMaxTurnsPerPeer;
  double max_cost_usd_per_peer = kDefaultMaxCostUsdPerPeer;

  bool operator==(const PartyTrustSectionPolicy &) const = default;
};

struct OnlineSectionPolicy {
  bool disabled = false;
  bool require_force_relays = false;
  std::vector<std::string> allowed_authorities;
  std::vector<std::string> allowed_org_slugs;
  bool allow_personal_parties = true;

  bool operator==(const OnlineSectionPolicy &) const = default;
};

struct EffectivePolicy {
  BrakesProfile effective_profile = BrakesProfile::black_flag;
  BrakesSectionPolicy brakes{};
  PartyTrustSectionPolicy party_trust{};
  lan::LanPolicyConfig lan{};
  OnlineSectionPolicy online{};

  bool system_policy_loaded = false;
  bool legacy_lan_policy_loaded = false;
  bool user_policy_loaded = false;
  bool clamped_to_system_floor = false;

  bool operator==(const EffectivePolicy &) const = default;
};

struct PolicyLoadOptions {
  std::filesystem::path system_policy_path = std::string{kDefaultSystemPolicyPath};
  std::filesystem::path legacy_system_lan_policy_path =
      std::string{kDefaultLegacySystemLanPolicyPath};
  // When unset, resolved from XDG_CONFIG_HOME/blackbird/policy.toml or
  // HOME/.config/blackbird/policy.toml. Pass an empty path to disable.
  std::optional<std::filesystem::path> user_policy_path = std::nullopt;
  // When unset, resolved from XDG_CONFIG_HOME/blackbird/lan.toml or
  // HOME/.config/blackbird/lan.toml. Pass an empty path to disable.
  std::optional<std::filesystem::path> legacy_user_lan_policy_path = std::nullopt;
  // Expected owner UID of system policy files (defaults to root = 0; overridable
  // in unit tests).
  std::uint32_t expected_system_uid = 0U;
  // Expected owner UID of user policy files (defaults to geteuid() when unset).
  std::optional<std::uint32_t> expected_user_uid = std::nullopt;
  lan::EnvLookupFn env_lookup = {};
  std::optional<BrakesProfile> cli_brakes_override = std::nullopt;
};

// Strict TOML parser for a standalone policy.toml document supporting [brakes],
// [party_trust], [lan], and [online]. Fails closed on unknown/duplicate sections,
// unknown/duplicate keys, invalid types/ranges, or malformed syntax.
Result<EffectivePolicy> parse_policy_toml(std::string_view text);

// Loads optional system policy.toml + legacy lan.toml + user policy.toml/lan.toml
// + BLACKBIRD_BRAKES/MP_BRAKES/LAN kill-switch env vars + optional CLI override.
// Enforces system floor monotonically and fails closed on tampered/symlink/malformed
// files or explicit CLI overrides weaker than system.min_profile.
Result<EffectivePolicy> load_effective_policy(const PolicyLoadOptions &options = {});

// ---------------------------------------------------------------------------
// 3. Peer Provenance Framing & Immutable C++ Taint Gate
// ---------------------------------------------------------------------------

enum class PeerOriginKind : std::uint8_t {
  local_operator = 0,
  online_peer = 1,
  lan_peer = 2,
  ssh_peer = 3,
  external_mcp = 4,
};

std::string_view peer_origin_kind_name(PeerOriginKind origin) noexcept;

struct PeerProvenance {
  PeerOriginKind origin = PeerOriginKind::online_peer;
  std::string peer_pubkey_b64;
  std::string safety_number;
  std::uint64_t account_id = 0U;
  std::optional<std::uint64_t> org_id = std::nullopt;
  bool is_external_guest = false;
  PartyTrustProfile effective_trust = PartyTrustProfile::advisory;

  bool operator==(const PeerProvenance &) const = default;
};

// Distinct non-mutually-convertible string view wrappers to prevent accidental
// argument transposition in format_untrusted_peer_envelope.
struct RoomScopeRef {
  std::string_view value;
  constexpr RoomScopeRef(std::string_view v) noexcept : value(v) {}
  constexpr RoomScopeRef(const char *v) noexcept : value(v ? v : "") {}
  RoomScopeRef(const std::string &v) noexcept : value(v) {}
};

struct SenderRef {
  std::string_view value;
  constexpr SenderRef(std::string_view v) noexcept : value(v) {}
  constexpr SenderRef(const char *v) noexcept : value(v ? v : "") {}
  SenderRef(const std::string &v) noexcept : value(v) {}
};

struct MessageBodyRef {
  std::string_view value;
  constexpr MessageBodyRef(std::string_view v) noexcept : value(v) {}
  constexpr MessageBodyRef(const char *v) noexcept : value(v ? v : "") {}
  MessageBodyRef(const std::string &v) noexcept : value(v) {}
};

// Generates a 16-hex CSPRNG nonce via OpenSSL RAND_bytes, escapes JSON angle
// brackets plus control & Unicode BiDi characters, and wraps the payload in:
//   [UNTRUSTED_PEER_DATA nonce=... origin=... safety_number=... trust=...]
//   ...
//   [/UNTRUSTED_PEER_DATA nonce=...]
Result<std::string> format_untrusted_peer_envelope(const PeerProvenance &provenance,
                                                   RoomScopeRef room_scope,
                                                   SenderRef sender,
                                                   MessageBodyRef body);

// Immutable-to-Lua C++ turn taint latch. Latches the strictest (minimum)
// PartyTrustProfile across all ingested peer/external-MCP items, clamps external
// org guests to max_external_guest_profile, and clears only on explicit operator
// action.
class TurnTaintState {
public:
  TurnTaintState() noexcept = default;

  PartyTrustProfile ingest(const PeerProvenance &provenance,
                           const PartyTrustSectionPolicy &policy);
  PartyTrustProfile ingest(const PeerProvenance &provenance,
                           const EffectivePolicy &policy);

  // Monotonically latches taint from another TurnTaintState (never clears or
  // weakens existing taint).
  PartyTrustProfile latch_from(const TurnTaintState &other,
                               const PartyTrustSectionPolicy &policy) noexcept;
  PartyTrustProfile latch_from(const TurnTaintState &other,
                               const EffectivePolicy &policy) noexcept;

  void reset_by_operator() noexcept;

  bool is_tainted() const noexcept {
    return peer_ingested_ && effective_trust_ < PartyTrustProfile::black_flag;
  }
  bool has_peer_data() const noexcept { return peer_ingested_; }
  PartyTrustProfile effective_trust() const noexcept { return effective_trust_; }
  bool external_guest_seen() const noexcept { return external_guest_seen_; }
  std::size_t ingested_count() const noexcept { return ingested_count_; }
  PeerOriginKind last_origin() const noexcept { return last_origin_; }
  const std::string &last_safety_number() const noexcept { return last_safety_number_; }

private:
  bool peer_ingested_ = false;
  bool external_guest_seen_ = false;
  PartyTrustProfile effective_trust_ = PartyTrustProfile::black_flag;
  std::size_t ingested_count_ = 0U;
  PeerOriginKind last_origin_ = PeerOriginKind::local_operator;
  std::string last_safety_number_;
};

enum class BrakesVerdict : std::uint8_t {
  allow = 0,
  escalate = 1,
  deny = 2,
};

struct BrakesDecision {
  bool allow = false;
  bool escalate = false;
  bool deny = true;
  std::string reason;
  bool policy_locked = false;
  BrakesVerdict verdict = BrakesVerdict::deny;

  static BrakesDecision make_allow(std::string reason_text = {});
  static BrakesDecision make_escalate(std::string reason_text);
  static BrakesDecision make_deny(std::string reason_text, bool locked = true);

  bool operator==(const BrakesDecision &) const = default;
};

enum class ToolEffectClass : std::uint8_t {
  auto_classify = 0,
  read_only = 1,
  workspace_write = 2,
  exec = 3,
  outbound_network = 4,
  peer_spawn = 5,
  self_modify = 6,
};

struct ToolCallRequest {
  std::string tool_name;
  std::string tool_op;
  ToolEffectClass effect_class = ToolEffectClass::auto_classify;
  std::optional<std::filesystem::path> target_path = std::nullopt;
  bool targets_known_peers = false;
  bool requires_network = false;
  bool sandbox_active = false;
  std::uint32_t peer_turns_used = 0U;
  double peer_cost_usd_used = 0.0;
  double projected_cost_usd = 0.0;
  std::filesystem::path workspace_root;
  std::filesystem::path tmp_dir;
  lan::EnvLookupFn env_lookup = {};
};

class BrakesGate {
public:
  explicit BrakesGate(EffectivePolicy policy = {}, TurnTaintState taint = {}) noexcept
      : policy_(std::move(policy)), taint_(std::move(taint)) {}

  const EffectivePolicy &policy() const noexcept { return policy_; }
  const TurnTaintState &taint() const noexcept { return taint_; }
  TurnTaintState &mutable_taint() noexcept { return taint_; }

  PartyTrustProfile ingest_peer(const PeerProvenance &provenance) {
    return taint_.ingest(provenance, policy_.party_trust);
  }
  PartyTrustProfile latch_taint_from(const TurnTaintState &other) noexcept {
    return taint_.latch_from(other, policy_.party_trust);
  }
  void reset_taint_by_operator() noexcept { taint_.reset_by_operator(); }

  BrakesDecision evaluate_tool_call(const ToolCallRequest &req) const;

private:
  EffectivePolicy policy_{};
  TurnTaintState taint_{};
};

// ---------------------------------------------------------------------------
// 4. In-Process PathContainmentGuard & Scrubbed Child envp
// ---------------------------------------------------------------------------

enum class PathAccessKind : std::uint8_t {
  read = 0,
  write = 1,
};

struct WorkspaceRootPath {
  std::filesystem::path value;
  WorkspaceRootPath() = default;
  WorkspaceRootPath(std::filesystem::path p) : value(std::move(p)) {}
  WorkspaceRootPath(std::string_view p) : value(p) {}
  WorkspaceRootPath(const char *p) : value(p ? p : "") {}
};

struct TmpDirPath {
  std::filesystem::path value;
  TmpDirPath() = default;
  TmpDirPath(std::filesystem::path p) : value(std::move(p)) {}
  TmpDirPath(std::string_view p) : value(p) {}
  TmpDirPath(const char *p) : value(p ? p : "") {}
};

struct TargetPath {
  std::filesystem::path value;
  TargetPath() = default;
  TargetPath(std::filesystem::path p) : value(std::move(p)) {}
  TargetPath(std::string_view p) : value(p) {}
  TargetPath(const char *p) : value(p ? p : "") {}
};

struct PathGuardOptions {
  lan::EnvLookupFn env_lookup = {};
  std::vector<std::filesystem::path> extra_read_only_dirs;
  std::optional<BrakesProfile> profile_override = std::nullopt;
};

struct PathAccessDecision {
  bool allowed = false;
  bool policy_locked = false;
  bool is_secret_store = false;
  bool is_protected_write = false;
  bool outside_workspace = false;
  bool symlink_escaped = false;
  std::filesystem::path canonical_path;
  std::string reason;

  bool operator==(const PathAccessDecision &) const = default;
};

PathAccessDecision check_path_access(const EffectivePolicy &policy,
                                     const WorkspaceRootPath &workspace_root,
                                     const TmpDirPath &tmp_dir,
                                     const TargetPath &target_path, PathAccessKind kind,
                                     const PathGuardOptions &options = {});

// Returns true if the environment variable key should be scrubbed from child
// processes under guarded / sandboxed / airgap profiles.
bool is_scrubbed_env_key(std::string_view key) noexcept;

// Under black_flag, passes parent_env through verbatim. Under guarded+, strips
// provider/cloud/auth secrets and loader/shell injection variables while
// preserving safe runtime vars (PATH, LANG, TERM, HOME, etc.).
std::vector<std::string>
build_scrubbed_child_env(BrakesProfile profile,
                         const std::vector<std::string> &parent_env);

} // namespace blackbird::brakes
