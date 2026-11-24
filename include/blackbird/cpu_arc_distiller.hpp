#pragma once

#include "blackbird/context.hpp"
#include "blackbird/cpu_arc.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird::arc {

// ---------------------------------------------------------------------------
// 1. Error Model (carried in blackbird::Error::detail, starting at 6100)
// ---------------------------------------------------------------------------

enum class ArcDistillerError : std::int64_t {
  none = 0,
  invalid_trace = 6100,
  builder_unavailable = 6101,
  target_unavailable = 6102,
  judge_unavailable = 6103,
  phase_failed = 6104,
  parse_failed = 6105,
  validation_failed = 6106,
  extraction_robustness_failed = 6107,
  budget_exceeded = 6108,
  registry_failed = 6109,
  compile_failed = 6110,
};

constexpr ArcDistillerError arc_distiller_error_of(const Error &error) noexcept {
  return static_cast<ArcDistillerError>(error.detail);
}

std::string_view arc_distiller_error_name(ArcDistillerError detail) noexcept;

// ---------------------------------------------------------------------------
// 2. Lossless Trace Extraction & Equirational Candidate Clustering
// ---------------------------------------------------------------------------

inline constexpr std::size_t kDefaultMaxJsonlBytes = 4U * 1024U * 1024U;
inline constexpr std::size_t kDefaultMaxJsonlLines = 10000U;
inline constexpr std::size_t kDefaultMaxPlanNodes = 32U;

struct ArcSourceTrace {
  std::string trace_id;
  std::string user_query;
  std::string source_transcript;
  std::string final_answer;
  std::vector<std::string> tools_used;
  std::string provenance_hash;
  double source_cost_usd = 0.0;
  std::uint64_t block_id = 0U;

  bool operator==(const ArcSourceTrace &) const = default;
};

struct ArcDistillCandidateCluster {
  std::string canonical_template;
  std::string representative_trace_id;
  std::vector<std::string> member_trace_ids;
  std::size_t occurrence_count = 0U;
  double total_source_cost_usd = 0.0;
  double average_similarity = 1.0;

  bool operator==(const ArcDistillCandidateCluster &) const = default;
};

// Reads completed instruction + closed exchange block pairs losslessly without
// mutating ContextStore or AuditLog originals.
std::vector<ArcSourceTrace> extract_distillable_traces(const ContextStore &store);

// Parses exported JSONL turn transcripts safely under strict byte and line bounds.
Result<std::vector<ArcSourceTrace>>
extract_distillable_traces_from_jsonl(std::string_view jsonl,
                                      std::size_t max_bytes = kDefaultMaxJsonlBytes);

// Groups equirational/recurring traces by normalized lexical template similarity,
// sorted descending by occurrence_count then total_source_cost_usd.
std::vector<ArcDistillCandidateCluster>
cluster_recurring_traces(const std::vector<ArcSourceTrace> &traces,
                         double min_similarity = 0.45);

// ---------------------------------------------------------------------------
// 3. 5-Phase CPU-ARC Construction State Machine (Section 2.2.1)
// ---------------------------------------------------------------------------

struct ArcJudgeVerdict {
  bool passed = false;
  std::string critique;

  bool operator==(const ArcJudgeVerdict &) const = default;
};

using ArcBuilderCallback =
    std::function<Result<std::string>(std::string_view prompt, std::string_view phase)>;
using ArcDistillJudgeCallback = std::function<Result<ArcJudgeVerdict>(
    std::string_view expected, const Value &actual, std::string_view context_note)>;

struct ArcDistillerCallbacks {
  ArcBuilderCallback builder = {};
  ArcLmCallback target_lm = {};
  ArcDistillJudgeCallback judge = {};
  ArcToolCallback tool = {};
  brakes::TurnTaintState *turn_taint = nullptr;
  brakes::PartyTrustSectionPolicy party_trust_policy{};
};

struct ArcDistillOptions {
  ArcGranularity granularity = ArcGranularity::medium;
  std::uint32_t max_node_retries = 3U;
  std::uint32_t extraction_round_trips = 3U;
  bool auto_compile = true;
  bool require_narration_commensurate = true;
  double numeric_tolerance = 1e-3;
  double builder_cost_usd = 0.0;
  std::size_t max_plan_nodes = kDefaultMaxPlanNodes;
  ArcExecutionLimits exec_limits{};
};

enum class ArcPhaseStatus : std::uint8_t {
  not_run = 0,
  succeeded = 1,
  failed = 2,
  skipped = 3,
};

std::string_view arc_phase_status_name(ArcPhaseStatus status) noexcept;

struct ArcPhaseRecord {
  std::string phase_name;
  ArcPhaseStatus status = ArcPhaseStatus::not_run;
  std::uint32_t attempts = 0U;
  std::int64_t duration_ns = 0;
  std::string detail;
};

struct ArcDecompositionStep {
  std::string id;
  std::string description;
  std::vector<std::string> inputs;
  bool reusable = false;
};

struct ArcRecognizedParam {
  std::string name;
  std::string description;
  std::string d_type = "any";
  std::string example;
  std::string validity_range;
  Value original_value;
  bool required = true;
};

struct ArcPlanNode {
  std::string id;
  std::string description;
  std::vector<std::string> depends_on;
  std::vector<ArcParamSpec> params;
  std::vector<std::string> return_keys;
  bool is_root = false;
  Value test_payloads;
  std::string expected_output;
};

struct ArcNodeDistillSummary {
  std::string node_id;
  std::string registered_function_id;
  bool reused_existing = false;
  std::uint32_t attempts = 0U;
  std::uint32_t retries = 0U;
  bool passed = false;
  std::string last_feedback;
};

struct ArcDistillReport {
  bool succeeded = false;
  std::string trace_id;
  std::string provenance_hash;

  std::string isolated_user_input;
  std::string isolated_expected_output;
  std::vector<ArcDecompositionStep> decomposition_steps;
  std::string generic_template;
  std::vector<ArcRecognizedParam> recognized_params;
  std::vector<ArcPlanNode> plan_nodes;
  std::vector<std::string> topological_order;

  std::string root_function_id;
  std::vector<std::string> reused_function_ids;
  std::vector<std::string> registered_function_ids;
  std::vector<std::string> registered_entry_ids;
  std::vector<ArcNodeDistillSummary> node_summaries;

  bool stage1_correctness_passed = false;
  std::uint32_t stage2_trials_run = 0U;
  std::uint32_t stage2_trials_passed = 0U;
  double extraction_pass_rate = 0.0;
  bool compiled = false;

  std::vector<ArcPhaseRecord> phases;
  std::uint32_t total_retries = 0U;
  double source_cost_usd = 0.0;
  double builder_cost_usd = 0.0;
  std::int64_t total_duration_ns = 0;
  std::string diagnostic;
};

class ArcDistiller {
public:
  ArcDistiller() = default;

  Result<ArcDistillReport> distill(ArcRegistry &registry, const ArcSourceTrace &trace,
                                   const ArcDistillerCallbacks &callbacks,
                                   const ArcDistillOptions &options = {});

  // Diagnostic report from the most recent distill() call (populated on both
  // success and failure).
  const ArcDistillReport &last_report() const noexcept { return last_report_; }

private:
  ArcDistillReport last_report_{};
};

// ---------------------------------------------------------------------------
// 4. Gated Turn Interceptor (CPU-ARC Figure 1)
// ---------------------------------------------------------------------------

struct ArcTurnGateConfig {
  bool enabled = true;
  ArcExecutionLimits exec_limits{};
  std::size_t max_queued_misses = 256U;
  std::size_t auto_distill_threshold = 2U;
  double cluster_min_similarity = 0.45;
};

struct ArcTurnCostEstimate {
  double source_cost_usd = 0.0;
  double target_cost_usd = 0.0;
};

struct ArcTurnGateTelemetry {
  std::uint64_t total_turns = 0U;
  std::uint64_t cache_hits = 0U;
  std::uint64_t cache_misses = 0U;
  std::uint64_t error_fallbacks = 0U;
  double hit_rate = 0.0;
  double estimated_saved_usd = 0.0;
  double total_source_cost_usd = 0.0;
  double total_actual_cost_usd = 0.0;
  double cost_savings_multiplier = 1.0;
  std::size_t queued_miss_count = 0U;
  std::size_t ready_candidate_count = 0U;
};

class ArcTurnGate {
public:
  explicit ArcTurnGate(ArcRegistry &registry, ArcTurnGateConfig config = {}) noexcept;

  const ArcTurnGateConfig &config() const noexcept { return config_; }
  void set_config(ArcTurnGateConfig config) noexcept { config_ = std::move(config); }

  Result<ArcExecutionResult> handle_turn(std::string_view raw_request,
                                         const Value &explicit_payloads,
                                         const ArcRuntimeCallbacks &callbacks = {},
                                         ArcTurnCostEstimate cost_estimate = {});

  void record_miss(ArcSourceTrace trace);
  std::vector<ArcSourceTrace> queued_misses() const;
  std::vector<ArcDistillCandidateCluster> pending_candidates() const;
  std::size_t consume_cluster(const ArcDistillCandidateCluster &cluster);
  void clear_misses() noexcept;

  ArcTurnGateTelemetry telemetry() const;

private:
  void enqueue_miss(ArcSourceTrace trace);

  ArcRegistry *registry_ = nullptr;
  ArcTurnGateConfig config_{};
  std::deque<ArcSourceTrace> missed_traces_;
  std::uint64_t miss_sequence_ = 0U;
  std::uint64_t total_turns_ = 0U;
  std::uint64_t cache_hits_ = 0U;
  std::uint64_t cache_misses_ = 0U;
  std::uint64_t error_fallbacks_ = 0U;
  double estimated_saved_usd_ = 0.0;
  double total_source_cost_usd_ = 0.0;
  double total_actual_cost_usd_ = 0.0;
};

} // namespace blackbird::arc
