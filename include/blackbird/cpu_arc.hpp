#pragma once

#include "blackbird/brakes_policy.hpp"
#include "blackbird/foundation.hpp"
#include "blackbird/value.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird::arc {

// ---------------------------------------------------------------------------
// 1. Error Model (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

enum class ArcError : std::int64_t {
  none = 0,
  invalid_id = 6000,
  invalid_lua = 6001,
  sandbox_violation = 6002,
  memory_limit_exceeded = 6003,
  instruction_limit_exceeded = 6004,
  timeout = 6005,
  recursion_limit_exceeded = 6006,
  step_limit_exceeded = 6007,
  function_not_found = 6008,
  entry_not_found = 6009,
  load_not_found = 6010,
  type_conversion_failed = 6011,
  lm_unavailable = 6012,
  tool_unavailable = 6013,
  compile_cycle_detected = 6014,
  compile_unresolved_call = 6015,
  sqlite_failed = 6016,
  io_failed = 6017,
  insecure_path = 6018,
};

constexpr ArcError arc_error_of(const Error &error) noexcept {
  return static_cast<ArcError>(error.detail);
}

std::string_view arc_error_name(ArcError detail) noexcept;

// Valid function / entry ID: 1..64 characters, strictly [A-Za-z0-9_-].
bool valid_arc_id(std::string_view id) noexcept;

// Computes lowercase 64-hex SHA-256 digest using OpenSSL EVP.
std::string compute_trace_hash(std::string_view text);

// ---------------------------------------------------------------------------
// 2. Semantic Function & Registry Data Model
// ---------------------------------------------------------------------------

enum class ArcGranularity : std::uint8_t {
  fine = 0,
  medium = 1,
  coarse = 2,
};

std::string_view arc_granularity_name(ArcGranularity granularity) noexcept;
Result<ArcGranularity> parse_arc_granularity(std::string_view text) noexcept;

enum class ArcPerturbationMode : std::uint8_t {
  golden = 0,
  phrasal = 1,
  parametric = 2,
  combined = 3,
};

std::string_view arc_perturbation_mode_name(ArcPerturbationMode mode) noexcept;

inline constexpr std::size_t kMaxArcIdLength = 64U;
inline constexpr std::size_t kDefaultMaxLuaMemoryBytes = 16U * 1024U * 1024U;
inline constexpr std::uint64_t kDefaultMaxLuaInstructions = 2000000U;
inline constexpr std::uint32_t kDefaultTimeoutMs = 5000U;
inline constexpr std::uint32_t kDefaultBusyTimeoutMs = 5000U;
inline constexpr std::uint32_t kDefaultMaxCallDepth = 16U;
inline constexpr std::uint32_t kDefaultMaxDoCalls = 64U;
inline constexpr std::uint32_t kDefaultMaxLmCalls = 32U;
inline constexpr std::uint32_t kDefaultMaxToolCalls = 32U;
inline constexpr std::size_t kDefaultMaxNarrationEntries = 512U;

struct ArcCapabilities {
  bool available = true;
  std::string lua_version;
  std::string sqlite_version;
  bool supports_fts5 = false;
  bool supports_wal = true;
  bool supports_nofollow = true;
  bool supports_compiled_execution = true;
  std::size_t default_lua_memory_bytes = kDefaultMaxLuaMemoryBytes;
  std::uint64_t default_lua_instructions = kDefaultMaxLuaInstructions;
};

// Passive capability probe (zero disk writes).
ArcCapabilities probe_cpu_arc_capabilities();

struct ArcParamSpec {
  std::string name;
  std::string description;
  std::string d_type = "any";
  std::string example;
  bool required = true;

  bool operator==(const ArcParamSpec &) const = default;
};

struct ArcFunctionRecord {
  std::string id;
  std::string description;
  std::vector<ArcParamSpec> params;
  std::vector<std::string> return_keys;
  std::string lua_source;
  std::string provenance_trace_hash;
  ArcGranularity granularity = ArcGranularity::medium;
  bool is_root = false;
  std::optional<std::string> compiled_lua = std::nullopt;
  // Optional entry-point templates / examples registered atomically with this function.
  std::vector<std::string> entry_templates;

  // Persisted telemetry & cost accumulators.
  std::uint64_t invocation_count = 0U;
  std::uint64_t success_count = 0U;
  std::uint64_t failure_count = 0U;
  std::uint64_t fallback_count = 0U;
  double total_source_cost_usd = 0.0;
  double total_builder_cost_usd = 0.0;
  double total_target_cost_usd = 0.0;
};

struct ArcEntryPointRecord {
  std::string entry_id;
  std::string function_id;
  std::string template_text;
  bool is_template = true;
};

struct ArcSearchMatch {
  std::string id;
  std::string function_id;
  std::string matched_text;
  double score = 0.0;
  double bm25_score = 0.0;
  double lexical_score = 0.0;
  double dense_score = 0.0;
};

struct ArcRegistryStats {
  std::size_t function_count = 0U;
  std::size_t root_function_count = 0U;
  std::size_t compiled_function_count = 0U;
  std::size_t entry_point_count = 0U;
  std::uint64_t total_invocations = 0U;
  std::uint64_t total_successes = 0U;
  std::uint64_t total_failures = 0U;
  std::uint64_t total_fallbacks = 0U;
  double total_source_cost_usd = 0.0;
  double total_builder_cost_usd = 0.0;
  double total_target_cost_usd = 0.0;
};

struct ArcCostSample {
  double source_cost_usd = 0.0;
  double builder_cost_usd = 0.0;
  double target_cost_usd = 0.0;
};

// ---------------------------------------------------------------------------
// 3. Callbacks, Configuration, Limits, and Execution Results
// ---------------------------------------------------------------------------

using ArcEmbedCallback =
    std::function<Result<std::vector<float>>(std::string_view text)>;
using ArcLmCallback = std::function<Result<std::string>(std::string_view prompt,
                                                        std::string_view purpose)>;
using ArcToolCallback =
    std::function<Result<Value>(std::string_view name, const Value &args)>;
using ArcSourceFallbackCallback =
    std::function<Result<Value>(std::string_view raw_request)>;
using ArcJudgeCallback = std::function<Result<bool>(
    const Value &actual, const Value &expected, std::string_view context_note)>;

struct ArcRegistryConfig {
  std::uint32_t busy_timeout_ms = kDefaultBusyTimeoutMs;
  ArcEmbedCallback embed_callback = {};
  double bm25_weight = 0.35;
  double lexical_weight = 0.65;
  double dense_weight = 0.50;
  double min_do_score = 0.15;
  double min_load_score = 0.10;
};

struct ArcRuntimeCallbacks {
  ArcLmCallback lm = {};
  ArcToolCallback tool = {};
  ArcSourceFallbackCallback source_fallback = {};
  brakes::TurnTaintState *turn_taint = nullptr;
  brakes::PartyTrustSectionPolicy party_trust_policy{};
};

struct ArcExecutionLimits {
  std::size_t max_lua_memory_bytes = kDefaultMaxLuaMemoryBytes;
  std::uint64_t max_lua_instructions = kDefaultMaxLuaInstructions;
  std::uint32_t timeout_ms = kDefaultTimeoutMs;
  std::uint32_t max_call_depth = kDefaultMaxCallDepth;
  std::uint32_t max_do_calls = kDefaultMaxDoCalls;
  std::uint32_t max_lm_calls = kDefaultMaxLmCalls;
  std::uint32_t max_tool_calls = kDefaultMaxToolCalls;
  std::size_t max_narration_entries = kDefaultMaxNarrationEntries;
  double min_entry_score = 0.25;
  double min_do_score = 0.15;
  double min_load_score = 0.10;
  bool prefer_compiled = true;
};

struct ArcNarrationEntry {
  std::uint32_t depth = 0U;
  std::string function_id;
  std::string message;

  bool operator==(const ArcNarrationEntry &) const = default;
};

std::string format_narration_trace(const std::vector<ArcNarrationEntry> &entries);

struct ArcExecutionResult {
  Value output;
  std::vector<ArcNarrationEntry> narrations;
  std::string narration_trace;
  std::string root_function_id;
  bool cache_hit = false;
  bool used_compiled = false;
  bool fell_back_to_source = false;
  std::string fallback_reason;
  double entry_score = 0.0;
  std::uint64_t search_calls = 0U;
  std::uint64_t load_search_calls = 0U;
  std::uint32_t do_calls = 0U;
  std::uint32_t lm_calls = 0U;
  std::uint32_t tool_calls = 0U;
  std::uint64_t lua_instructions = 0U;
  std::size_t peak_lua_memory_bytes = 0U;
  std::int64_t duration_ns = 0;
  bool turn_tainted = false;
};

// ---------------------------------------------------------------------------
// 4. Static Analysis & Static Compilation (CPU-ARC Section 2.2.3)
// ---------------------------------------------------------------------------

struct ArcCallSite {
  std::string primitive; // "do_" or "load"
  std::string target_expr;
  std::string query_literal;
  std::optional<std::string> d_type_literal;
  std::string payloads_expr;
  std::size_t start_offset = 0U;
  std::size_t end_offset = 0U;
};

struct ArcStaticAnalysis {
  bool syntax_valid = false;
  bool defines_semantic_function = false;
  std::size_t narration_count = 0U;
  std::size_t control_flow_complexity = 1U;
  bool narration_commensurate = false;
  std::vector<ArcCallSite> do_calls;
  std::vector<ArcCallSite> load_calls;
  std::string diagnostic;
};

Result<ArcStaticAnalysis> analyze_lua_source(std::string_view lua_source);

struct ArcCompiledModule {
  std::string root_function_id;
  std::string lua_source;
  std::vector<std::string> included_function_ids;
  std::size_t resolved_do_sites = 0U;
  std::size_t resolved_load_sites = 0U;
};

// ---------------------------------------------------------------------------
// 5. Perturbation & Equivalence Verification (CPU-ARC Section 3.1 / 3.2)
// ---------------------------------------------------------------------------

struct ArcVerificationCase {
  std::string case_id;
  ArcPerturbationMode mode = ArcPerturbationMode::golden;
  std::string raw_request;
  Value explicit_payloads;
  Value expected_output;
  std::optional<std::string> output_key = std::nullopt;
  double numeric_tolerance = 1e-3;
  double source_cost_usd = 0.0;
  double target_cost_usd = 0.0;
};

struct ArcCaseResult {
  std::string case_id;
  ArcPerturbationMode mode = ArcPerturbationMode::golden;
  bool passed = false;
  bool cache_hit = false;
  bool fell_back_to_source = false;
  std::int64_t duration_ns = 0;
  std::string detail;
};

struct ArcModeSummary {
  std::size_t total = 0U;
  std::size_t passed = 0U;
  double pass_rate = 0.0;
};

struct ArcVerificationReport {
  std::size_t total_cases = 0U;
  std::size_t passed_cases = 0U;
  double overall_pass_rate = 0.0;
  ArcModeSummary golden{};
  ArcModeSummary phrasal{};
  ArcModeSummary parametric{};
  ArcModeSummary combined{};
  std::int64_t min_latency_ns = 0;
  std::int64_t median_latency_ns = 0;
  std::int64_t max_latency_ns = 0;
  double total_source_cost_usd = 0.0;
  double total_target_cost_usd = 0.0;
  double cost_ratio = 0.0;
  double savings_multiplier = 0.0;
  std::vector<ArcCaseResult> case_results;
};

struct ArcVerifyOptions {
  ArcExecutionLimits limits{};
  ArcJudgeCallback judge = {};
  bool require_cache_hit = true;
};

// ---------------------------------------------------------------------------
// 6. Persistent / In-Memory CPU-ARC Registry & Execution Engine
// ---------------------------------------------------------------------------

class ArcRegistry {
public:
  static Result<ArcRegistry> open(const std::filesystem::path &db_path,
                                  ArcRegistryConfig config = {});
  static Result<ArcRegistry> open_in_memory(ArcRegistryConfig config = {});

  ~ArcRegistry();
  ArcRegistry(const ArcRegistry &) = delete;
  ArcRegistry &operator=(const ArcRegistry &) = delete;
  ArcRegistry(ArcRegistry &&other) noexcept;
  ArcRegistry &operator=(ArcRegistry &&other) noexcept;

  // Registry CRUD + hybrid semantic search (FTS5 BM25 + lexical + optional dense).
  Result<void> register_function(const ArcFunctionRecord &record);
  Result<void> register_entry_point(const ArcEntryPointRecord &entry);
  Result<ArcFunctionRecord> get_function(std::string_view id) const;
  Result<std::vector<ArcFunctionRecord>> list_functions() const;
  Result<void> remove_function(std::string_view id);

  Result<std::vector<ArcSearchMatch>> search_functions(std::string_view query,
                                                       std::size_t limit = 5U) const;
  Result<std::vector<ArcSearchMatch>> search_entry_points(std::string_view query,
                                                          std::size_t limit = 5U) const;

  Result<ArcRegistryStats> stats() const;
  Result<void> record_cost(std::string_view function_id, const ArcCostSample &cost);

  // Sandboxed Lua 5.5.1 execution (dynamic semantic dispatch & compiled zero-search).
  Result<ArcExecutionResult> invoke_function(std::string_view function_id,
                                             const Value &payloads,
                                             const ArcRuntimeCallbacks &callbacks = {},
                                             const ArcExecutionLimits &limits = {});

  Result<ArcExecutionResult> invoke_compiled(std::string_view function_id,
                                             const Value &payloads,
                                             const ArcRuntimeCallbacks &callbacks = {},
                                             const ArcExecutionLimits &limits = {});

  Result<ArcExecutionResult>
  invoke_compiled_module(const ArcCompiledModule &module, const Value &payloads,
                         const ArcRuntimeCallbacks &callbacks = {},
                         const ArcExecutionLimits &limits = {});

  // Gated CPU-ARC Figure 1 serving (IS1 -> IS2 -> IS3 -> IS4 + fallback to S).
  Result<ArcExecutionResult> serve(std::string_view raw_request,
                                   const Value &explicit_payloads,
                                   const ArcRuntimeCallbacks &callbacks = {},
                                   const ArcExecutionLimits &limits = {});

  // Section 2.2.3 static DAG compiler.
  Result<ArcCompiledModule> compile_network(std::string_view root_function_id,
                                            bool save_to_registry = true);

  // Section 3.1 / 3.2 perturbation & equivalence verifier.
  Result<ArcVerificationReport>
  verify_candidate(const std::vector<ArcVerificationCase> &cases,
                   const ArcRuntimeCallbacks &callbacks = {},
                   const ArcVerifyOptions &options = {});

private:
  struct Impl;
  explicit ArcRegistry(std::unique_ptr<Impl> impl) noexcept;
  std::unique_ptr<Impl> impl_;
};

} // namespace blackbird::arc
