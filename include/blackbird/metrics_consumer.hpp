#pragma once

#include "blackbird/context.hpp"
#include "blackbird/foundation.hpp"
#include "blackbird/token_usage.hpp"
#include "blackbird/value.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace blackbird {

inline constexpr std::size_t kMetricsDefaultSeriesCapacity = 512;
inline constexpr std::size_t kMetricsMaxSeriesCapacity = 65536;
inline constexpr std::size_t kMetricsDefaultMaxJsonlBytes = 64 * 1024 * 1024;
inline constexpr std::size_t kMetricsDefaultMaxRecords = 200000;
inline constexpr std::size_t kMetricsMaxCoverageNotes = 128;

// Unit 6 invariant: explicitly distinguish observed zero, partial known subtotal,
// complete known total, and unknown (never coerced to 0).
enum class TriMetricState : std::uint8_t {
  unknown = 0,
  zero = 1,
  known_subtotal = 2,
  complete = 3,
};

std::string_view tri_metric_state_name(TriMetricState state) noexcept;

enum class MetricsClockDomain : std::uint8_t {
  unknown = 0,
  utc_ns = 1,
  monotonic_ns = 2,
};

std::string_view metrics_clock_domain_name(MetricsClockDomain domain) noexcept;
std::optional<MetricsClockDomain>
parse_metrics_clock_domain(std::string_view name) noexcept;

enum class MetricsSampleKind : std::uint8_t {
  provider_response = 0,
  tool_execution = 1,
  context_snapshot = 2,
  decision_batch = 3,
  operation_event = 4,
};

std::string_view metrics_sample_kind_name(MetricsSampleKind kind) noexcept;
std::optional<MetricsSampleKind>
parse_metrics_sample_kind(std::string_view name) noexcept;

template <typename T> struct TriMetric {
  static_assert(std::is_same_v<T, std::uint64_t> || std::is_same_v<T, double>,
                "TriMetric supports uint64_t and double");

  TriMetricState state = TriMetricState::unknown;
  std::optional<T> value;
  std::uint64_t known_count = 0;
  std::uint64_t missing_count = 0;
  bool overflow = false;

  static TriMetric unknown() noexcept { return TriMetric{}; }

  static TriMetric from_known(T sample_value) noexcept {
    TriMetric metric;
    metric.record_known(sample_value);
    return metric;
  }

  void record_known(T sample_value) noexcept {
    if constexpr (std::is_same_v<T, double>) {
      if (!std::isfinite(sample_value) || sample_value < 0.0) {
        record_missing();
        return;
      }
      if (sample_value == 0.0)
        sample_value = 0.0; // Normalize -0.0.
      if (!value.has_value()) {
        value = sample_value;
      } else {
        const double sum = *value + sample_value;
        if (!std::isfinite(sum)) {
          overflow = true;
          value = std::numeric_limits<double>::max();
        } else {
          value = sum;
        }
      }
    } else {
      if (!value.has_value()) {
        value = sample_value;
      } else if (std::numeric_limits<std::uint64_t>::max() - *value < sample_value) {
        overflow = true;
        value = std::numeric_limits<std::uint64_t>::max();
      } else {
        value = *value + sample_value;
      }
    }
    ++known_count;
    recompute_state();
  }

  void set_observed_gauge(T sample_value) noexcept {
    if constexpr (std::is_same_v<T, double>) {
      if (!std::isfinite(sample_value) || sample_value < 0.0) {
        record_missing();
        return;
      }
      if (sample_value == 0.0)
        sample_value = 0.0;
    }
    value = sample_value;
    ++known_count;
    recompute_state();
  }

  void record_max(T sample_value) noexcept {
    if constexpr (std::is_same_v<T, double>) {
      if (!std::isfinite(sample_value) || sample_value < 0.0) {
        record_missing();
        return;
      }
      if (sample_value == 0.0)
        sample_value = 0.0;
    }
    if (!value.has_value() || sample_value > *value)
      value = sample_value;
    ++known_count;
    recompute_state();
  }

  void record_missing() noexcept {
    ++missing_count;
    recompute_state();
  }

  void merge(const TriMetric<T> &other) noexcept {
    if (other.known_count > 0 && other.value.has_value()) {
      if (!value.has_value()) {
        value = *other.value;
      } else if constexpr (std::is_same_v<T, double>) {
        const double sum = *value + *other.value;
        if (!std::isfinite(sum)) {
          overflow = true;
          value = std::numeric_limits<double>::max();
        } else {
          value = sum;
        }
      } else {
        if (std::numeric_limits<std::uint64_t>::max() - *value < *other.value) {
          overflow = true;
          value = std::numeric_limits<std::uint64_t>::max();
        } else {
          value = *value + *other.value;
        }
      }
    }
    known_count += other.known_count;
    missing_count += other.missing_count;
    overflow = overflow || other.overflow;
    recompute_state();
  }

  bool is_unknown() const noexcept { return state == TriMetricState::unknown; }
  bool is_zero() const noexcept { return state == TriMetricState::zero; }
  bool is_known_subtotal() const noexcept {
    return state == TriMetricState::known_subtotal;
  }
  bool is_complete() const noexcept { return state == TriMetricState::complete; }
  bool has_value() const noexcept { return value.has_value(); }

  bool operator==(const TriMetric &) const = default;

private:
  void recompute_state() noexcept {
    if (known_count == 0 || !value.has_value()) {
      state = TriMetricState::unknown;
      value.reset();
      return;
    }
    if (missing_count > 0 || overflow) {
      state = TriMetricState::known_subtotal;
      return;
    }
    if (*value == T{0}) {
      state = TriMetricState::zero;
      return;
    }
    state = TriMetricState::complete;
  }
};

struct MetricsPoint {
  std::int64_t timestamp_ns = 0;
  double value = 0.0;
  std::string source_record_id;
  std::string source_label;
  std::string clock_id;
  std::string unit;
  std::string request_id;
  std::string provider;
  MetricsClockDomain clock_domain = MetricsClockDomain::unknown;
  bool operator==(const MetricsPoint &) const = default;
};

struct MetricsSourceRecord {
  std::int64_t timestamp_ns = 0;
  std::string source_record_id;
  std::string source_label;
  std::string source_locator;
  std::string clock_id;
  std::string request_id;
  std::string capture_key;
  std::string provider;
  std::string model;
  Value metadata;
  MetricsSampleKind kind = MetricsSampleKind::provider_response;
  MetricsClockDomain clock_domain = MetricsClockDomain::unknown;
  bool operator==(const MetricsSourceRecord &) const = default;
};

struct MetricsSeries {
  std::string name;
  std::string unit;
  std::size_t capacity = kMetricsDefaultSeriesCapacity;
  std::uint64_t dropped_oldest = 0;
  std::vector<MetricsPoint> points;

  void push(MetricsPoint point);
  std::vector<double> values() const;
  bool operator==(const MetricsSeries &) const = default;
};

struct MetricsSparkline {
  std::string glyphs;
  std::optional<double> min_value;
  std::optional<double> max_value;
  std::size_t input_count = 0;
  std::size_t finite_count = 0;
  std::size_t ignored_non_finite = 0;
  std::size_t glyph_count = 0;
  bool operator==(const MetricsSparkline &) const = default;
};

// Pure bounded Unicode sparkline projection (▁▂▃▄▅▆▇█), ignoring NaN/Inf cleanly.
MetricsSparkline metrics_sparkline(std::span<const double> values, std::size_t width);
MetricsSparkline metrics_sparkline(const MetricsSeries &series, std::size_t width);

struct LatencyStats {
  TriMetric<double> total_ms;
  std::optional<double> min_ms;
  std::optional<double> max_ms;
  std::optional<double> mean_ms;
  std::optional<double> p50_ms;
  std::optional<double> p95_ms;
  bool operator==(const LatencyStats &) const = default;
};

struct OperationsSummary {
  TriMetric<std::uint64_t> provider_requests;
  TriMetric<std::uint64_t> tool_executions;
  TriMetric<std::uint64_t> tool_failures;
  TriMetric<std::uint64_t> error_count;
  TriMetric<std::uint64_t> retry_count;
  LatencyStats ttft_stats;
  LatencyStats total_latency_stats;
  LatencyStats tool_duration_stats;
  MetricsSeries ttft_ms;
  MetricsSeries total_latency_ms;
  MetricsSeries tool_duration_ms;
  MetricsSeries points;
  bool operator==(const OperationsSummary &) const = default;
};

struct VersionedCostEstimate {
  std::string pricing_version;
  TriMetric<double> estimated_cost_usd;
  bool operator==(const VersionedCostEstimate &) const = default;
};

struct ProviderUsageSummary {
  std::string provider;
  std::uint64_t observation_count = 0;
  TriMetric<std::uint64_t> input_tokens;
  TriMetric<std::uint64_t> cached_tokens;
  TriMetric<std::uint64_t> cache_write_tokens;
  TriMetric<std::uint64_t> reasoning_tokens;
  TriMetric<std::uint64_t> output_tokens;
  TriMetric<double> cache_hit_ratio;
  TriMetric<double> observed_charge_usd;
  TriMetric<double> estimated_cost_usd;
  std::string pricing_version;
  bool mixed_pricing_versions = false;
  std::vector<VersionedCostEstimate> estimates_by_version;
  bool operator==(const ProviderUsageSummary &) const = default;
};

struct UsageSummary {
  std::uint64_t observation_count = 0;
  TriMetric<std::uint64_t> total_input_tokens;
  TriMetric<std::uint64_t> total_cached_tokens;
  TriMetric<std::uint64_t> total_cache_write_tokens;
  TriMetric<std::uint64_t> total_reasoning_tokens;
  TriMetric<std::uint64_t> total_output_tokens;
  TriMetric<double> cache_hit_ratio;
  TriMetric<double> observed_charge_usd;
  TriMetric<double> estimated_cost_usd;
  std::string pricing_version;
  bool mixed_pricing_versions = false;
  std::vector<VersionedCostEstimate> estimates_by_version;
  std::vector<ProviderUsageSummary> by_provider;
  MetricsSeries token_spend_series;
  MetricsSeries charge_usd_series;
  MetricsSeries estimated_usd_series;
  bool operator==(const UsageSummary &) const = default;
};

struct ContextSummary {
  std::uint64_t observation_count = 0;
  TriMetric<std::uint64_t> latest_live_bytes;
  TriMetric<std::uint64_t> latest_archived_bytes;
  TriMetric<std::uint64_t> peak_live_bytes;
  TriMetric<std::uint64_t> upstream_cache_epoch_jumps;
  TriMetric<std::uint64_t> compaction_events;
  TriMetric<std::uint64_t> compaction_bytes_reclaimed;
  std::optional<std::string> last_cache_epoch;
  MetricsSeries live_bytes_series;
  MetricsSeries archived_bytes_series;
  MetricsSeries cache_epoch_jumps_series;
  MetricsSeries compaction_series;
  bool operator==(const ContextSummary &) const = default;
};

struct DecisionCompanionSummary {
  TriMetric<std::uint64_t> batch_count;
  TriMetric<std::uint64_t> failure_count;
  LatencyStats latency_stats;
  TriMetric<std::uint64_t> input_tokens;
  TriMetric<std::uint64_t> output_tokens;
  TriMetric<std::uint64_t> total_tokens;
  TriMetric<double> observed_charge_usd;
  TriMetric<double> estimated_cost_usd;
  std::string pricing_version;
  bool mixed_pricing_versions = false;
  std::vector<VersionedCostEstimate> estimates_by_version;
  MetricsSeries latency_ms;
  MetricsSeries token_spend_series;
  bool operator==(const DecisionCompanionSummary &) const = default;
};

struct MetricsCoverage {
  std::uint64_t records_ingested = 0;
  std::uint64_t records_skipped_corrupt = 0;
  std::uint64_t duplicate_captures_deduped = 0;
  std::uint64_t conflicting_captures = 0;
  std::uint64_t missing_field_observations = 0;
  bool has_utc_clock = false;
  bool has_monotonic_clock = false;
  bool has_unknown_clock = false;
  std::vector<std::string> clock_ids;
  std::vector<std::string> notes;
  // Preserved raw/observation scans never claim a complete session ledger.
  bool complete_session_ledger = false;
  bool operator==(const MetricsCoverage &) const = default;
};

struct MetricsSample {
  std::int64_t timestamp_ns = 0;

  std::optional<double> ttft_ms;
  std::optional<double> total_latency_ms;
  std::optional<double> tool_duration_ms;
  std::optional<std::uint64_t> retries;

  std::optional<std::uint64_t> input_tokens;
  std::optional<std::uint64_t> cached_tokens;
  std::optional<std::uint64_t> cache_write_tokens;
  std::optional<std::uint64_t> reasoning_tokens;
  std::optional<std::uint64_t> output_tokens;

  std::optional<double> observed_charge_usd;
  std::optional<double> estimated_usd;

  std::optional<std::uint64_t> live_bytes;
  std::optional<std::uint64_t> archived_bytes;
  std::optional<std::uint64_t> compaction_bytes_before;
  std::optional<std::uint64_t> compaction_bytes_after;

  std::string source_record_id;
  std::string source_label;
  std::string source_locator;
  std::string clock_id;
  std::string request_id;
  std::string capture_key;
  std::string provider;
  std::string model;
  std::string service_tier;
  std::string tool_name;
  std::string pricing_version;
  Value raw_metadata;
  std::optional<std::string> cache_epoch;

  MetricsSampleKind kind = MetricsSampleKind::provider_response;
  MetricsClockDomain clock_domain = MetricsClockDomain::unknown;
  bool input_includes_cache = true;
  bool cache_epoch_jump = false;
  bool compaction_event = false;
  std::optional<bool> succeeded;
};

struct MetricsSnapshot {
  std::uint64_t generation = 0;
  std::optional<Error> last_refresh_error;
  std::string stale_reason;
  std::string source_description;
  MetricsCoverage coverage;
  OperationsSummary operations;
  UsageSummary usage;
  ContextSummary context;
  DecisionCompanionSummary decision_companion;
  std::vector<MetricsSourceRecord> source_records;
  bool has_data = false;
  bool stale = false;

  const MetricsSourceRecord *
  find_source(std::string_view source_record_id) const noexcept;
};

struct MetricsConsumerConfig {
  std::size_t series_capacity = kMetricsDefaultSeriesCapacity;
  std::size_t max_jsonl_bytes = kMetricsDefaultMaxJsonlBytes;
  std::size_t max_records = kMetricsDefaultMaxRecords;
  std::string default_pricing_version;
  std::vector<UsagePrice> pricing_rules;
};

// Strictly read-only tertiary metrics & telemetry consumer (Unit 6).
// Never touches producer hot paths or raw emitters; retains last-good snapshots
// marked stale when upstream sources fail or corrupt on refresh().
class MetricsConsumer {
public:
  using SampleSource = std::function<Result<std::vector<MetricsSample>>()>;

  explicit MetricsConsumer(MetricsConsumerConfig config = {});

  static MetricsConsumer from_jsonl_file(std::filesystem::path path,
                                         MetricsConsumerConfig config = {});
  static MetricsConsumer from_audit_log(AuditLog &log,
                                        MetricsConsumerConfig config = {});
  static MetricsConsumer
  from_token_usage_directory(std::filesystem::path session_directory,
                             MetricsConsumerConfig config = {});
  static MetricsConsumer from_sample_source(SampleSource source,
                                            std::string source_description = "custom",
                                            MetricsConsumerConfig config = {});

  MetricsConsumer(const MetricsConsumer &) = delete;
  MetricsConsumer &operator=(const MetricsConsumer &) = delete;
  MetricsConsumer(MetricsConsumer &&) noexcept;
  MetricsConsumer &operator=(MetricsConsumer &&) noexcept;
  ~MetricsConsumer();

  Result<void> refresh();
  Result<void> ingest(const MetricsSample &sample);
  Result<void> ingest_batch(std::span<const MetricsSample> samples);
  Result<void> ingest_jsonl_file(const std::filesystem::path &path);
  Result<void> ingest_audit_log(AuditLog &log);
  Result<void> ingest_token_usage(const TokenUsageReport &report);

  void clear();
  void mark_stale(std::string reason, std::optional<Error> error = std::nullopt);

  const MetricsSnapshot &snapshot() const noexcept { return snapshot_; }
  const MetricsSourceRecord *
  find_source(std::string_view source_record_id) const noexcept {
    return snapshot_.find_source(source_record_id);
  }

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  MetricsSnapshot snapshot_;
};

Result<MetricsSample> parse_metrics_sample(const Value &value);
Result<MetricsSample> parse_metrics_sample_json(std::string_view json_line);

Value to_value(const MetricsSample &sample);
Value to_value(const TriMetric<std::uint64_t> &metric);
Value to_value(const TriMetric<double> &metric);
Value to_value(const MetricsPoint &point);
Value to_value(const MetricsSeries &series);
Value to_value(const MetricsSparkline &sparkline);
Value to_value(const LatencyStats &stats);
Value to_value(const VersionedCostEstimate &estimate);
Value to_value(const OperationsSummary &summary);
Value to_value(const ProviderUsageSummary &summary);
Value to_value(const UsageSummary &summary);
Value to_value(const ContextSummary &summary);
Value to_value(const DecisionCompanionSummary &summary);
Value to_value(const MetricsCoverage &coverage);
Value to_value(const MetricsSourceRecord &record);
Value to_value(const MetricsSnapshot &snapshot);

Result<std::string> to_json(const MetricsSample &sample);
Result<std::string> to_json(const TriMetric<std::uint64_t> &metric);
Result<std::string> to_json(const TriMetric<double> &metric);
Result<std::string> to_json(const MetricsPoint &point);
Result<std::string> to_json(const MetricsSeries &series);
Result<std::string> to_json(const MetricsSparkline &sparkline);
Result<std::string> to_json(const OperationsSummary &summary);
Result<std::string> to_json(const UsageSummary &summary);
Result<std::string> to_json(const ContextSummary &summary);
Result<std::string> to_json(const DecisionCompanionSummary &summary);
Result<std::string> to_json(const MetricsSnapshot &snapshot);

} // namespace blackbird
