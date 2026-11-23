#pragma once

#include "blackbird/brakes_policy.hpp"
#include "blackbird/context.hpp"
#include "blackbird/context_hygiene.hpp"
#include "blackbird/foundation.hpp"
#include "blackbird/value.hpp"

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

// Strongly-typed integer primary key for loaded SaaS integration packs (zero
// string primary keys internally; service names are indexed properties).
struct SaasPackId {
  std::uint64_t value = 0;
  constexpr explicit operator bool() const noexcept { return value != 0; }
  auto operator<=>(const SaasPackId &) const = default;
};

inline constexpr std::size_t kSaasPackMaxSourceBytes = 256U * 1024U;
inline constexpr std::size_t kSaasPackMaxHeapBytes = 8U * 1024U * 1024U;
inline constexpr std::uint64_t kSaasPackMaxLuaInstructions = 2'000'000U;
inline constexpr std::size_t kSaasPackMaxHttpRequestsPerCall = 16U;

enum class SaasEffectClass : std::uint8_t {
  read = 0,
  write = 1,
  send = 2,
  del = 3,
};

std::string_view saas_effect_class_name(SaasEffectClass effect) noexcept;
Result<SaasEffectClass> parse_saas_effect_class(std::string_view name) noexcept;

// Service-pinned HTTP request passed from C++ to the injectable PinnedHttpFn.
// SECURITY INVARIANTS:
// - Host is ALWAYS pinned by C++ against the pack's authoritative allowed_hosts.
// - Path is strictly relative (starts with '/', rejects scheme/host/userinfo/..).
// - Lua NEVER supplies or receives Authorization/Cookie/Proxy-Authorization
//   headers; C++ / IntegrationVault injects credentials strictly outside Lua.
struct PinnedHttpRequest {
  SaasPackId pack_id{};
  std::string service;
  std::string account;
  std::string method; // GET, POST, PUT, PATCH, DELETE
  std::string host;   // C++-verified pinned HTTPS host
  std::string path;   // strictly relative path
  std::string url;    // C++-assembled https://<host><path>[?<query>]
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
  SaasEffectClass effect = SaasEffectClass::write;
  std::chrono::milliseconds timeout{15000};
};

struct PinnedHttpResponse {
  int status_code = 0;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
};

using PinnedHttpFn =
    std::function<Result<PinnedHttpResponse>(const PinnedHttpRequest &)>;

struct SaasOperationPolicy {
  std::string name;
  SaasEffectClass effect = SaasEffectClass::write;
};

struct SaasPackManifest {
  std::string service;
  std::string display_name;
  std::vector<std::string> allowed_hosts;
  std::vector<std::pair<std::string, std::string>> default_headers;
  std::vector<SaasOperationPolicy> operations;
  bool is_open_world = false;
  brakes::PartyTrustProfile trust_profile = brakes::PartyTrustProfile::human_gated;
  std::string safety_number;
};

struct SaasPackInfo {
  SaasPackId pack_id{};
  std::string service;
  std::string display_name;
  std::vector<std::string> allowed_hosts;
  std::vector<std::string> operation_names;
  bool is_open_world = false;
};

struct SaasInvokeParams {
  std::string service;
  std::string operation;
  Value arguments = Value::object({});
  std::string account;
  std::optional<ToolProjectionPolicy> projection_policy;
};

struct SaasInvokeOutcome {
  SaasPackId pack_id{};
  std::string service;
  std::string operation;
  bool blocked_by_brakes = false;
  bool blocked_by_host_pin = false;
  brakes::BrakesDecision brakes_decision = brakes::BrakesDecision::make_allow();
  // CSPRNG nonce-framed, context-hygiene-projected output safe for model context.
  std::string framed_output;
  ToolProjectionResult projection{};
  // Full unframed Markdown/text output returned by the Lua pack.
  std::string raw_output;
  // Redacted raw HTTP response bodies captured across the call.
  std::vector<std::string> raw_http_bodies;
  std::string audit_ref;
  std::string error_detail;
};

struct SaasHostConfig {
  PinnedHttpFn http_transport;
  brakes::EffectivePolicy brakes_policy{};
  ToolProjectionPolicy default_projection{};
  AuditLog *audit_log = nullptr;
  std::size_t max_lua_heap_bytes = kSaasPackMaxHeapBytes;
  std::uint64_t max_lua_instructions = kSaasPackMaxLuaInstructions;
};

// Built-in authoritative manifests for the 7 first-party SaaS integration packs
// (linear, slack, gmail, gcal, notion, github, discord).
const std::vector<SaasPackManifest> &builtin_saas_pack_manifests();
std::optional<SaasPackManifest>
find_builtin_saas_pack_manifest(std::string_view service);

// Pure helper: validates a relative path and constructs a pinned https:// URL
// while rejecting scheme overrides, host/userinfo injection, traversal, and
// control bytes.
struct PinnedUrlInput {
  const std::vector<std::string> &allowed_hosts;
  std::string_view requested_host;
  std::string_view relative_path;
  std::string_view query_string;
};
Result<std::string> build_pinned_https_url(const PinnedUrlInput &input,
                                           std::string *resolved_host_out = nullptr);

// Owned sandboxed Lua 5.5.1 runtime hosting service-pinned SaaS Integration
// Packs with unbypassable C++ host pinning, zero secret exposure to Lua,
// BrakesGate enforcement, ContextHygiene projection, and CSPRNG taint framing.
class SaasPackHost {
public:
  explicit SaasPackHost(SaasHostConfig config);
  SaasPackHost(const SaasPackHost &) = delete;
  SaasPackHost &operator=(const SaasPackHost &) = delete;
  SaasPackHost(SaasPackHost &&) noexcept;
  SaasPackHost &operator=(SaasPackHost &&) noexcept;
  ~SaasPackHost();

  // Registers a pack from Lua 5.5.1 source under an authoritative C++ manifest.
  Result<SaasPackId> register_pack_source(SaasPackManifest manifest,
                                          std::string_view lua_source);

  // Loads a pack .lua file from disk under an authoritative C++ manifest.
  Result<SaasPackId> load_pack_file(SaasPackManifest manifest,
                                    const std::filesystem::path &lua_path);

  // Loads all 7 builtin packs (<service>.lua) from integrations_dir.
  Result<std::vector<SaasPackId>>
  load_builtin_packs(const std::filesystem::path &integrations_dir);

  std::optional<SaasPackId> find_pack_id(std::string_view service) const;
  std::vector<SaasPackInfo> list_packs() const;

  // Executes pack.operations[operation](arguments) inside a fresh sandboxed Lua
  // 5.5.1 VM with service-pinned blackbird.http.request(op).
  Result<SaasInvokeOutcome> invoke(const SaasInvokeParams &params);

  const brakes::BrakesGate &brakes_gate() const noexcept;
  brakes::BrakesGate &mutable_brakes_gate() noexcept;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace blackbird
