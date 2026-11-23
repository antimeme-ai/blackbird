#pragma once

#include "blackbird/brakes_policy.hpp"
#include "blackbird/foundation.hpp"
#include "blackbird/os_sandbox.hpp"
#include "blackbird/value.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird::measure {

// ---------------------------------------------------------------------------
// Error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

enum class MeasureError : std::int64_t {
  none = 0,
  empty_argv = 4000,
  invalid_spec = 4001,
  pipe_failed = 4002,
  fork_failed = 4003,
  wait_failed = 4004,
  clock_failed = 4005,
  sandbox_failed = 4006,
  chdir_failed = 4007,
  exec_failed = 4008,
  invalid_json = 4009,
  invalid_journal_entry = 4010,
  capacity_exceeded = 4011,
};

constexpr MeasureError measure_error_of(const Error &error) noexcept {
  return static_cast<MeasureError>(error.detail);
}

std::string_view measure_error_name(MeasureError detail) noexcept;

// ---------------------------------------------------------------------------
// Bounds & defaults
// ---------------------------------------------------------------------------

inline constexpr std::size_t kDefaultMaxTailBytes = 16U * 1024U;
inline constexpr std::size_t kMaxTailBytesLimit = 1024U * 1024U;
inline constexpr std::uint32_t kMaxTotalTrials = 10000U;
inline constexpr std::size_t kMaxCustomMetricsPerTrial = 1024U;
inline constexpr std::size_t kMaxMetricKeyLength = 64U;
inline constexpr std::size_t kMaxMetricLineBytes = 4096U;
inline constexpr std::uint64_t kDefaultTimeoutMs = 30000U;
inline constexpr std::uint64_t kDefaultKillGraceMs = 200U;
inline constexpr std::size_t kMaxJournalIterations = 10000U;

// ---------------------------------------------------------------------------
// 1. High-Precision Raw Trial Capture (Zero Writer-Side Filtering/Aggregation)
// ---------------------------------------------------------------------------

enum class RusageMemoryUnit : std::uint8_t {
  bytes = 0,     // macOS / Darwin ru_maxrss
  kibibytes = 1, // Linux ru_maxrss
};

// Normalizes rusage.ru_maxrss to bytes with negative clamping and overflow saturation.
constexpr std::uint64_t normalize_rusage_maxrss_bytes(std::int64_t raw_ru_maxrss,
                                                      RusageMemoryUnit unit) noexcept {
  if (raw_ru_maxrss <= 0) {
    return 0U;
  }
  const auto magnitude = static_cast<std::uint64_t>(raw_ru_maxrss);
  if (unit == RusageMemoryUnit::bytes) {
    return magnitude;
  }
  constexpr std::uint64_t kKib = 1024ULL;
  if (magnitude > std::numeric_limits<std::uint64_t>::max() / kKib) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return magnitude * kKib;
}

struct CustomMetricSample {
  std::string key;
  double value = 0.0;

  bool operator==(const CustomMetricSample &) const = default;
};

// Validates a BLACKBIRD_METRIC key: [A-Za-z_][A-Za-z0-9_.-]{0,63}.
bool is_valid_metric_key(std::string_view key) noexcept;

// Parses a single stdout line matching `BLACKBIRD_METRIC <key>=<finite_double>`.
// Returns std::nullopt for non-matching lines, invalid keys, or non-finite numbers.
std::optional<CustomMetricSample> parse_blackbird_metric_line(std::string_view line);

// Raw per-trial observation emitted losslessly without writer-side filtering or
// aggregation. Warmup and failed trials are marked raw and preserved intact.
struct RawTrialRecord {
  std::uint32_t trial_index = 0U;
  bool is_warmup = false;

  std::uint64_t wall_ns = 0U;
  std::uint64_t user_us = 0U;
  std::uint64_t sys_us = 0U;
  std::uint64_t max_rss_bytes = 0U;
  std::uint64_t minflt = 0U;
  std::uint64_t majflt = 0U;
  std::uint64_t nvcsw = 0U;
  std::uint64_t nivcsw = 0U;

  int exit_code = -1;
  int term_signal = 0;
  bool timed_out = false;
  bool sandbox_apply_failed = false;
  sandbox::SandboxError sandbox_error = sandbox::SandboxError::none;
  int exec_errno = 0;

  std::uint64_t stdout_bytes = 0U;
  std::uint64_t stderr_bytes = 0U;
  std::string stdout_tail;
  std::string stderr_tail;
  std::vector<CustomMetricSample> custom_metrics;

  [[nodiscard]] bool succeeded() const noexcept {
    return !timed_out && !sandbox_apply_failed && exec_errno == 0 && term_signal == 0 &&
           exit_code == 0;
  }

  [[nodiscard]] std::uint64_t cpu_us() const noexcept {
    if (std::numeric_limits<std::uint64_t>::max() - user_us < sys_us) {
      return std::numeric_limits<std::uint64_t>::max();
    }
    return user_us + sys_us;
  }

  bool operator==(const RawTrialRecord &) const = default;
};

struct TrialTag {
  std::uint32_t trial_index = 0U;
  bool is_warmup = false;
};

// Direct subprocess specification (zero shell: executed via fork + execvp).
struct CommandRunSpec {
  std::vector<std::string> argv;
  std::optional<std::filesystem::path> cwd = std::nullopt;
  // Additional "KEY=VALUE" entries merged over parent/override environment.
  std::vector<std::string> extra_env;
  // Explicit base "KEY=VALUE" environment; when unset, inherits parent environ.
  std::optional<std::vector<std::string>> env_override = std::nullopt;
  std::uint64_t timeout_ms = kDefaultTimeoutMs;
  std::uint64_t kill_grace_ms = kDefaultKillGraceMs;
  std::size_t max_tail_bytes = kDefaultMaxTailBytes;
  // Optional Brakes containment profile. Under black_flag (or std::nullopt) with no
  // custom env, incurs zero env-copy or scrubbing overhead. Under guarded/sandboxed/
  // airgap, scrubs child env via brakes::build_scrubbed_child_env.
  std::optional<brakes::BrakesProfile> brakes_profile = std::nullopt;
  // Optional OS kernel sandbox applied irrevocably in the child before execvp.
  // Fails closed on error; never silently executes unsandboxed.
  std::optional<sandbox::SandboxSpec> sandbox_spec = std::nullopt;
};

struct MeasurementPlan {
  CommandRunSpec command;
  std::uint32_t warmup_trials = 0U;
  std::uint32_t measured_trials = 5U;
  // Optional correctness oracle executed BEFORE measured trials (fail-fast gate).
  std::optional<CommandRunSpec> oracle = std::nullopt;
};

struct MeasurementRunResult {
  bool oracle_ran = false;
  bool oracle_passed = true;
  std::optional<RawTrialRecord> oracle_record = std::nullopt;
  // Every emitted raw trial (including warmup and failed trials) in execution order.
  std::vector<RawTrialRecord> raw_trials;
};

using RawTrialCallback = std::function<void(const RawTrialRecord &)>;

// Executes a single command trial in its own process group (setpgid(0, 0)), measures
// CLOCK_MONOTONIC_RAW (fallback CLOCK_MONOTONIC) wall time and wait4() rusage,
// captures bounded stdout/stderr tails, extracts BLACKBIRD_METRIC lines, and tears
// down the entire process group via SIGTERM -> SIGKILL on timeout.
Result<RawTrialRecord> run_single_trial(const CommandRunSpec &spec, TrialTag tag = {});

// Executes optional fail-fast correctness oracle followed by warmup + measured raw
// trials, emitting every raw trial unconditionally to on_raw_trial (when set) and
// returning all raw records intact.
Result<MeasurementRunResult>
run_measurement_plan(const MeasurementPlan &plan,
                     const RawTrialCallback &on_raw_trial = {});

// ---------------------------------------------------------------------------
// 2. Separate Pure Tertiary Analysis (docs/INSTRUMENTATION.md)
// ---------------------------------------------------------------------------

// Summary distribution computed strictly on the tertiary consumer side.
// Quantiles use standard linear interpolation (R-7: pos = p * (n - 1)).
// stddev is Bessel-corrected sample standard deviation (n - 1; 0.0 for n <= 1).
struct MetricDistribution {
  std::size_t count = 0U;
  double min = 0.0;
  double q25 = 0.0;
  double median = 0.0;
  double q75 = 0.0;
  double p95 = 0.0;
  double max = 0.0;
  double iqr = 0.0;
  double mean = 0.0;
  double stddev = 0.0;
  double cv = 0.0;

  bool operator==(const MetricDistribution &) const = default;
};

struct TrialSummaryStats {
  std::size_t total_count = 0U;
  std::size_t warmup_count = 0U;
  std::size_t warmup_failed_count = 0U;
  std::size_t valid_count = 0U;
  std::size_t failed_count = 0U;

  MetricDistribution wall_ns{};
  MetricDistribution cpu_us{};
  MetricDistribution max_rss_bytes{};
  std::map<std::string, MetricDistribution> custom_metrics;

  bool operator==(const TrialSummaryStats &) const = default;
};

// Pure tertiary statistical reduction over finite samples.
MetricDistribution compute_metric_distribution(std::span<const double> samples);

// Pure tertiary consumer: filters warmup and failed trials ONLY here, producing
// distributions for wall_ns, cpu_us, max_rss_bytes, and custom metrics.
TrialSummaryStats
analyze_measurement_trials(std::span<const RawTrialRecord> raw_trials);

enum class ComparisonVerdict : std::uint8_t {
  invalid = 0,
  improved = 1,
  regressed = 2,
  inconclusive = 3,
};

std::string_view comparison_verdict_name(ComparisonVerdict verdict) noexcept;
std::optional<ComparisonVerdict>
parse_comparison_verdict(std::string_view text) noexcept;

struct ComparisonPolicy {
  // Minimum relative wall-time median shift required (e.g. 0.02 = 2%) to declare
  // improved or regressed.
  double min_effect_ratio = 0.02;
  // Require non-overlapping [q25, q75] wall-time IQRs before declaring improved or
  // regressed.
  bool require_non_overlapping_iqr = true;

  bool operator==(const ComparisonPolicy &) const = default;
};

struct MeasurementComparison {
  double speedup_ratio = 0.0; // baseline.wall_ns.median / candidate.wall_ns.median
  double delta_pct = 0.0;     // ((candidate - baseline) / baseline) * 100.0
  std::int64_t memory_delta_bytes = 0;
  bool iqr_overlaps = true;
  ComparisonVerdict verdict = ComparisonVerdict::invalid;
  std::string reason;

  bool operator==(const MeasurementComparison &) const = default;
};

// Distinct non-mutually-convertible wrappers preventing accidental argument swap.
struct BaselineStatsRef {
  const TrialSummaryStats &stats;
  constexpr BaselineStatsRef(const TrialSummaryStats &s) noexcept : stats(s) {}
};

struct CandidateStatsRef {
  const TrialSummaryStats &stats;
  constexpr CandidateStatsRef(const TrialSummaryStats &s) noexcept : stats(s) {}
};

MeasurementComparison compare_measurements(BaselineStatsRef baseline,
                                           CandidateStatsRef candidate,
                                           const ComparisonPolicy &policy = {});

// ---------------------------------------------------------------------------
// 3. Correctness Oracle Gate + TuningJournal (Closed-Loop Retry Valve)
// ---------------------------------------------------------------------------

struct IterationMetadata {
  std::string label;
  std::string snapshot_ref;
};

struct CandidateSubmission {
  std::string label;
  std::string snapshot_ref;
  bool oracle_passed = true;
  TrialSummaryStats summary{};
};

struct TuningIteration {
  std::uint64_t id = 0U; // 0 = baseline, 1..N = numbered candidates
  bool is_baseline = false;
  std::string label;
  std::string snapshot_ref;
  bool oracle_passed = true;
  TrialSummaryStats summary{};
  std::optional<MeasurementComparison> comparison = std::nullopt;
  bool accepted = false;
  bool rollback_recommended = false;
  std::string reason;

  bool operator==(const TuningIteration &) const = default;
};

struct RollbackRecommendation {
  bool should_rollback = false;
  std::uint64_t target_iteration_id = 0U;
  std::string target_snapshot_ref;
  std::string reason;

  bool operator==(const RollbackRecommendation &) const = default;
};

class TuningJournal {
public:
  explicit TuningJournal(ComparisonPolicy policy = {}) noexcept;

  const ComparisonPolicy &policy() const noexcept { return policy_; }
  bool has_baseline() const noexcept { return !iterations_.empty(); }
  const std::vector<TuningIteration> &iterations() const noexcept {
    return iterations_;
  }

  // Records iteration 0 (baseline). Fails with conflict if baseline is already set.
  Result<TuningIteration> record_baseline(CandidateSubmission baseline);

  // Records a numbered candidate iteration (1..N), comparing against the current best
  // accepted iteration. Rejects and recommends rollback on oracle failure, invalid
  // measurement, or regression.
  Result<TuningIteration> record_candidate(CandidateSubmission candidate);

  // End-to-end closed-loop helpers: run plan (fail-fast oracle + raw trial capture),
  // run pure tertiary analysis, and record into the journal.
  Result<TuningIteration>
  run_and_record_baseline(IterationMetadata meta, const MeasurementPlan &plan,
                          const RawTrialCallback &on_raw_trial = {});

  Result<TuningIteration>
  run_and_record_candidate(IterationMetadata meta, const MeasurementPlan &plan,
                           const RawTrialCallback &on_raw_trial = {});

  // Returns the accepted iteration with the lowest median wall_ns (or std::nullopt).
  std::optional<TuningIteration> best_iteration() const;

  // Returns rollback guidance for the most recent iteration, targeting
  // best_iteration().
  RollbackRecommendation latest_rollback_recommendation() const;

  // Structured serialization via blackbird::Value and JSON adapter.
  Value to_value() const;
  static Result<TuningJournal> from_value(const Value &value);
  Result<std::string> to_json() const;
  static Result<TuningJournal> from_json(std::string_view json_text);

  bool operator==(const TuningJournal &) const = default;

private:
  ComparisonPolicy policy_{};
  std::vector<TuningIteration> iterations_;
  std::uint64_t next_id_ = 1U;
};

// Convenience blackbird::Value encoders for standalone inspection/logging.
Value to_value(const MetricDistribution &dist);
Value to_value(const TrialSummaryStats &summary);
Value to_value(const MeasurementComparison &comparison);

} // namespace blackbird::measure
