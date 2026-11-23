#include "blackbird/metrics_consumer.hpp"
#include "blackbird/json.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <deque>
#include <fcntl.h>
#include <limits>
#include <map>
#include <set>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>
#include <utility>

namespace blackbird {
namespace {

constexpr std::array<std::string_view, 8> kSparklineGlyphs = {
    "\xE2\x96\x81", // ▁
    "\xE2\x96\x82", // ▂
    "\xE2\x96\x83", // ▃
    "\xE2\x96\x84", // ▄
    "\xE2\x96\x85", // ▅
    "\xE2\x96\x86", // ▆
    "\xE2\x96\x87", // ▇
    "\xE2\x96\x88", // █
};

constexpr std::size_t kConstantSparklineLevel = 3; // ▄
constexpr std::size_t kReadChunkBytes = 64 * 1024;
constexpr std::size_t kMaxSparklineWidth = 4096;

class ScopedFd {
public:
  explicit ScopedFd(int fd = -1) noexcept : fd_(fd) {}
  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;
  ScopedFd(ScopedFd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  ScopedFd &operator=(ScopedFd &&other) noexcept {
    if (this != &other) {
      reset();
      fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
  }
  ~ScopedFd() { reset(); }

  int get() const noexcept { return fd_; }
  void reset(int next = -1) noexcept {
    if (fd_ >= 0)
      (void)::close(fd_);
    fd_ = next;
  }

private:
  int fd_ = -1;
};

std::size_t clamp_series_capacity(std::size_t requested) noexcept {
  if (requested == 0)
    return 1;
  return std::min(requested, kMetricsMaxSeriesCapacity);
}

Value finite_double_value(double v) {
  if (!std::isfinite(v))
    return Value{};
  if (v == 0.0)
    v = 0.0;
  return Value{Number{v}};
}

std::optional<double> parse_finite_double(const Value *field) {
  if (!field)
    return std::nullopt;
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return std::nullopt;
  const std::string text = num->text();
  double parsed = 0.0;
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (ec != std::errc{} || ptr != text.data() + text.size() || !std::isfinite(parsed))
    return std::nullopt;
  if (parsed == 0.0)
    parsed = 0.0;
  return parsed;
}

std::optional<double> parse_non_negative_double(const Value *field) {
  const auto parsed = parse_finite_double(field);
  if (!parsed.has_value() || *parsed < 0.0)
    return std::nullopt;
  return parsed;
}

std::optional<std::uint64_t> parse_uint64(const Value *field) {
  if (!field)
    return std::nullopt;
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return std::nullopt;
  const std::string text = num->text();
  std::uint64_t parsed = 0;
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (ec != std::errc{} || ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

std::optional<std::int64_t> parse_int64(const Value *field) {
  if (!field)
    return std::nullopt;
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return std::nullopt;
  const std::string text = num->text();
  std::int64_t parsed = 0;
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (ec != std::errc{} || ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

std::optional<bool> parse_bool(const Value *field) {
  if (!field)
    return std::nullopt;
  if (const auto *b = std::get_if<bool>(&field->value()))
    return *b;
  return std::nullopt;
}

std::optional<std::string> parse_string(const Value *field) {
  if (!field)
    return std::nullopt;
  if (const auto *s = std::get_if<std::string>(&field->value()))
    return *s;
  return std::nullopt;
}

Result<std::string> read_file_bounded(const std::filesystem::path &path,
                                      std::size_t max_bytes) {
  if (path.empty())
    return Result<std::string>::failure({ErrorCode::invalid_range});
  int fd = -1;
  do {
    fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0)
    return Result<std::string>::failure({ErrorCode::io, errno});
  ScopedFd owned{fd};

  struct stat st{};
  if (::fstat(owned.get(), &st) != 0)
    return Result<std::string>::failure({ErrorCode::io, errno});
  if (!S_ISREG(st.st_mode))
    return Result<std::string>::failure({ErrorCode::io, EINVAL});
  if (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) > max_bytes)
    return Result<std::string>::failure({ErrorCode::capacity});

  std::string out;
  out.reserve(static_cast<std::size_t>(st.st_size));
  std::array<char, kReadChunkBytes> buffer{};
  for (;;) {
    const ssize_t count = ::read(owned.get(), buffer.data(), buffer.size());
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return Result<std::string>::failure({ErrorCode::io, errno});
    }
    if (count == 0)
      break;
    const auto chunk = static_cast<std::size_t>(count);
    if (chunk > max_bytes - out.size())
      return Result<std::string>::failure({ErrorCode::capacity});
    out.append(buffer.data(), chunk);
  }
  return Result<std::string>::success(std::move(out));
}

bool is_whitespace_only(std::string_view line) noexcept {
  return std::all_of(line.begin(), line.end(), [](unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  });
}

std::optional<double> parse_number_double(const Number &num) {
  const std::string text = num.text();
  double out = 0.0;
  const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), out);
  if (ec != std::errc{} || ptr != text.data() + text.size() || !std::isfinite(out) ||
      out < 0.0)
    return std::nullopt;
  if (out == 0.0)
    out = 0.0;
  return out;
}

struct DedupKey {
  MetricsSampleKind kind = MetricsSampleKind::provider_response;
  std::string request_id;
  std::string capture_key;
  auto operator<=>(const DedupKey &) const = default;
};

struct CaptureFingerprint {
  std::optional<std::uint64_t> input_tokens;
  std::optional<std::uint64_t> cached_tokens;
  std::optional<std::uint64_t> cache_write_tokens;
  std::optional<std::uint64_t> reasoning_tokens;
  std::optional<std::uint64_t> output_tokens;
  std::optional<double> observed_charge_usd;
  std::optional<double> estimated_usd;
  std::string pricing_version;
  bool operator==(const CaptureFingerprint &) const = default;
};

CaptureFingerprint fingerprint_for(const MetricsSample &sample) {
  return CaptureFingerprint{
      sample.input_tokens,     sample.cached_tokens,   sample.cache_write_tokens,
      sample.reasoning_tokens, sample.output_tokens,   sample.observed_charge_usd,
      sample.estimated_usd,    sample.pricing_version,
  };
}

struct SeriesBuilder {
  std::string name;
  std::string unit;
  std::size_t capacity = kMetricsDefaultSeriesCapacity;
  std::uint64_t dropped_oldest = 0;
  std::deque<MetricsPoint> points;

  void push(MetricsPoint point) {
    const std::size_t cap = clamp_series_capacity(capacity);
    if (points.size() >= cap) {
      points.pop_front();
      ++dropped_oldest;
    }
    points.push_back(std::move(point));
  }

  MetricsSeries materialize() const {
    MetricsSeries out;
    out.name = name;
    out.unit = unit;
    out.capacity = clamp_series_capacity(capacity);
    out.dropped_oldest = dropped_oldest;
    out.points.assign(points.begin(), points.end());
    return out;
  }
};

struct LatencyAccumulator {
  TriMetric<double> total_ms;
  std::optional<double> min_ms;
  std::optional<double> max_ms;
  std::deque<double> retained_samples;
  std::size_t capacity = kMetricsDefaultSeriesCapacity;

  void record(std::optional<double> sample_ms) {
    if (!sample_ms.has_value() || !std::isfinite(*sample_ms) || *sample_ms < 0.0) {
      total_ms.record_missing();
      return;
    }
    const double val = *sample_ms == 0.0 ? 0.0 : *sample_ms;
    total_ms.record_known(val);
    if (!min_ms.has_value() || val < *min_ms)
      min_ms = val;
    if (!max_ms.has_value() || val > *max_ms)
      max_ms = val;
    const std::size_t cap = clamp_series_capacity(capacity);
    if (retained_samples.size() >= cap)
      retained_samples.pop_front();
    retained_samples.push_back(val);
  }

  LatencyStats materialize() const {
    LatencyStats out;
    out.total_ms = total_ms;
    out.min_ms = min_ms;
    out.max_ms = max_ms;
    if (total_ms.known_count > 0 && total_ms.value.has_value() && !total_ms.overflow) {
      out.mean_ms = *total_ms.value / static_cast<double>(total_ms.known_count);
    }
    if (!retained_samples.empty()) {
      std::vector<double> sorted(retained_samples.begin(), retained_samples.end());
      std::sort(sorted.begin(), sorted.end());
      const auto quantile = [&](double q) -> double {
        const double pos = q * static_cast<double>(sorted.size() - 1);
        const auto idx = static_cast<std::size_t>(std::llround(pos));
        return sorted[std::min(idx, sorted.size() - 1)];
      };
      out.p50_ms = quantile(0.50);
      out.p95_ms = quantile(0.95);
    }
    return out;
  }
};

struct EstimateAccumulator {
  TriMetric<double> total;
  std::map<std::string, TriMetric<double>> by_version;
  std::string primary_version;
  bool mixed_versions = false;

  void record(std::optional<double> estimated_usd, std::string_view version,
              MetricsCoverage *coverage) {
    if (!estimated_usd.has_value()) {
      total.record_missing();
      return;
    }
    if (version.empty()) {
      total.record_missing();
      if (coverage) {
        ++coverage->missing_field_observations;
        if (coverage->notes.size() < kMetricsMaxCoverageNotes)
          coverage->notes.emplace_back("estimated_usd missing pricing_version");
      }
      return;
    }
    if (!std::isfinite(*estimated_usd) || *estimated_usd < 0.0) {
      total.record_missing();
      return;
    }
    if (primary_version.empty()) {
      primary_version = std::string{version};
    } else if (primary_version != version) {
      mixed_versions = true;
    }
    total.record_known(*estimated_usd);
    by_version[std::string{version}].record_known(*estimated_usd);
  }

  void apply_to(TriMetric<double> &target_total, std::string &target_version,
                bool &target_mixed,
                std::vector<VersionedCostEstimate> &target_by_version) const {
    target_total = total;
    target_version = primary_version;
    target_mixed = mixed_versions;
    target_by_version.clear();
    target_by_version.reserve(by_version.size());
    for (const auto &[ver, metric] : by_version) {
      target_by_version.push_back(VersionedCostEstimate{ver, metric});
    }
  }
};

struct ProviderUsageAccumulator {
  std::string provider;
  std::uint64_t observation_count = 0;
  TriMetric<std::uint64_t> input_tokens;
  TriMetric<std::uint64_t> cached_tokens;
  TriMetric<std::uint64_t> cache_write_tokens;
  TriMetric<std::uint64_t> reasoning_tokens;
  TriMetric<std::uint64_t> output_tokens;
  // Denominator tracking for cache_hit_ratio: sums effective prompt input per obs.
  TriMetric<std::uint64_t> cache_denominator_tokens;
  TriMetric<double> observed_charge_usd;
  EstimateAccumulator estimates;

  static TriMetric<double>
  compute_cache_hit_ratio(const TriMetric<std::uint64_t> &cached,
                          const TriMetric<std::uint64_t> &denominator) noexcept {
    TriMetric<double> ratio;
    if (!denominator.value.has_value() || *denominator.value == 0 ||
        !cached.value.has_value() || cached.known_count == 0) {
      return ratio; // unknown — never fabricate 0 without denominator > 0!
    }
    const double denom = static_cast<double>(*denominator.value);
    const double numer = static_cast<double>(*cached.value);
    const double raw = std::clamp(numer / denom, 0.0, 1.0);
    ratio.value = raw == 0.0 ? 0.0 : raw;
    ratio.known_count = std::min(cached.known_count, denominator.known_count);
    ratio.missing_count = cached.missing_count + denominator.missing_count;
    ratio.overflow = cached.overflow || denominator.overflow;
    if (ratio.missing_count > 0 || ratio.overflow) {
      ratio.state = TriMetricState::known_subtotal;
    } else if (*ratio.value == 0.0) {
      ratio.state = TriMetricState::zero;
    } else {
      ratio.state = TriMetricState::complete;
    }
    return ratio;
  }

  ProviderUsageSummary materialize() const {
    ProviderUsageSummary out;
    out.provider = provider;
    out.observation_count = observation_count;
    out.input_tokens = input_tokens;
    out.cached_tokens = cached_tokens;
    out.cache_write_tokens = cache_write_tokens;
    out.reasoning_tokens = reasoning_tokens;
    out.output_tokens = output_tokens;
    out.cache_hit_ratio =
        compute_cache_hit_ratio(cached_tokens, cache_denominator_tokens);
    out.observed_charge_usd = observed_charge_usd;
    estimates.apply_to(out.estimated_cost_usd, out.pricing_version,
                       out.mixed_pricing_versions, out.estimates_by_version);
    return out;
  }
};

struct ConsumerState {
  explicit ConsumerState(MetricsConsumerConfig cfg)
      : config(std::move(cfg)),
        series_cap(clamp_series_capacity(config.series_capacity)) {
    ttft_ms = {"operations.ttft_ms", "ms", series_cap, 0, {}};
    total_latency_ms = {"operations.total_latency_ms", "ms", series_cap, 0, {}};
    tool_duration_ms = {"operations.tool_duration_ms", "ms", series_cap, 0, {}};
    op_points = {"operations.points", "mixed", series_cap, 0, {}};
    token_spend_series = {"usage.tokens", "tokens", series_cap, 0, {}};
    charge_usd_series = {"usage.observed_charge_usd", "usd", series_cap, 0, {}};
    estimated_usd_series = {"usage.estimated_cost_usd", "usd", series_cap, 0, {}};
    live_bytes_series = {"context.live_bytes", "bytes", series_cap, 0, {}};
    archived_bytes_series = {"context.archived_bytes", "bytes", series_cap, 0, {}};
    cache_epoch_jumps_series = {
        "context.cache_epoch_jumps", "count", series_cap, 0, {}};
    compaction_series = {"context.compactions", "count", series_cap, 0, {}};
    decision_latency_ms = {"decision.latency_ms", "ms", series_cap, 0, {}};
    decision_token_spend = {"decision.tokens", "tokens", series_cap, 0, {}};
    ttft_stats.capacity = series_cap;
    total_latency_stats.capacity = series_cap;
    tool_duration_stats.capacity = series_cap;
    decision_latency_stats.capacity = series_cap;
  }

  MetricsConsumerConfig config;
  std::size_t series_cap = kMetricsDefaultSeriesCapacity;
  std::uint64_t synthetic_id_counter = 0;

  MetricsCoverage coverage;
  std::set<std::string> clock_id_set;
  std::map<DedupKey, CaptureFingerprint> seen_captures;
  std::map<std::string, MetricsSourceRecord> source_index;

  // Operations
  TriMetric<std::uint64_t> provider_requests;
  TriMetric<std::uint64_t> tool_executions;
  TriMetric<std::uint64_t> tool_failures;
  TriMetric<std::uint64_t> error_count;
  TriMetric<std::uint64_t> retry_count;
  LatencyAccumulator ttft_stats;
  LatencyAccumulator total_latency_stats;
  LatencyAccumulator tool_duration_stats;
  SeriesBuilder ttft_ms;
  SeriesBuilder total_latency_ms;
  SeriesBuilder tool_duration_ms;
  SeriesBuilder op_points;

  // Usage
  std::uint64_t usage_observations = 0;
  TriMetric<std::uint64_t> total_input_tokens;
  TriMetric<std::uint64_t> total_cached_tokens;
  TriMetric<std::uint64_t> total_cache_write_tokens;
  TriMetric<std::uint64_t> total_reasoning_tokens;
  TriMetric<std::uint64_t> total_output_tokens;
  TriMetric<std::uint64_t> total_cache_denominator;
  TriMetric<double> total_observed_charge_usd;
  EstimateAccumulator total_estimates;
  std::map<std::string, ProviderUsageAccumulator> by_provider;
  SeriesBuilder token_spend_series;
  SeriesBuilder charge_usd_series;
  SeriesBuilder estimated_usd_series;

  // Context
  std::uint64_t context_observations = 0;
  TriMetric<std::uint64_t> latest_live_bytes;
  TriMetric<std::uint64_t> latest_archived_bytes;
  TriMetric<std::uint64_t> peak_live_bytes;
  TriMetric<std::uint64_t> upstream_cache_epoch_jumps;
  TriMetric<std::uint64_t> compaction_events;
  TriMetric<std::uint64_t> compaction_bytes_reclaimed;
  std::optional<std::string> last_cache_epoch;
  SeriesBuilder live_bytes_series;
  SeriesBuilder archived_bytes_series;
  SeriesBuilder cache_epoch_jumps_series;
  SeriesBuilder compaction_series;

  // Decision companion (Jev/Clef)
  TriMetric<std::uint64_t> decision_batches;
  TriMetric<std::uint64_t> decision_failures;
  LatencyAccumulator decision_latency_stats;
  TriMetric<std::uint64_t> decision_input_tokens;
  TriMetric<std::uint64_t> decision_output_tokens;
  TriMetric<std::uint64_t> decision_total_tokens;
  TriMetric<double> decision_observed_charge_usd;
  EstimateAccumulator decision_estimates;
  SeriesBuilder decision_latency_ms;
  SeriesBuilder decision_token_spend;

  void add_note(std::string note) {
    if (coverage.notes.size() < kMetricsMaxCoverageNotes)
      coverage.notes.push_back(std::move(note));
  }

  std::string resolve_source_id(const MetricsSample &sample) {
    if (!sample.source_record_id.empty())
      return sample.source_record_id;
    return "sample:" + std::to_string(++synthetic_id_counter);
  }

  MetricsPoint make_point(const MetricsSample &sample,
                          const std::string &resolved_source_id, std::string_view unit,
                          double point_value) const {
    MetricsPoint point;
    point.source_record_id = resolved_source_id;
    point.source_label = sample.source_label.empty()
                             ? std::string{metrics_sample_kind_name(sample.kind)}
                             : sample.source_label;
    point.clock_domain = sample.clock_domain;
    point.clock_id = sample.clock_id;
    point.timestamp_ns = sample.timestamp_ns;
    point.value = point_value == 0.0 ? 0.0 : point_value;
    point.unit = std::string{unit};
    point.request_id = sample.request_id;
    point.provider = sample.provider;
    return point;
  }

  void record_clock(const MetricsSample &sample) {
    if (sample.clock_domain == MetricsClockDomain::utc_ns)
      coverage.has_utc_clock = true;
    else if (sample.clock_domain == MetricsClockDomain::monotonic_ns)
      coverage.has_monotonic_clock = true;
    else
      coverage.has_unknown_clock = true;
    if (!sample.clock_id.empty())
      clock_id_set.insert(sample.clock_id);
  }

  void record_source(const MetricsSample &sample,
                     const std::string &resolved_source_id) {
    MetricsSourceRecord record;
    record.source_record_id = resolved_source_id;
    record.source_label = sample.source_label.empty()
                              ? std::string{metrics_sample_kind_name(sample.kind)}
                              : sample.source_label;
    record.source_locator = sample.source_locator;
    record.kind = sample.kind;
    record.clock_domain = sample.clock_domain;
    record.clock_id = sample.clock_id;
    record.timestamp_ns = sample.timestamp_ns;
    record.request_id = sample.request_id;
    record.capture_key = sample.capture_key;
    record.provider = sample.provider;
    record.model = sample.model;
    record.metadata = sample.raw_metadata;
    source_index.insert_or_assign(resolved_source_id, std::move(record));
  }

  void compute_pricing_estimate(const MetricsSample &sample,
                                std::optional<double> &out_estimated_usd,
                                std::string &out_version) const {
    if (sample.estimated_usd.has_value()) {
      out_estimated_usd = sample.estimated_usd;
      out_version = sample.pricing_version;
      return;
    }
    if (config.pricing_rules.empty() || !sample.input_tokens.has_value() ||
        !sample.output_tokens.has_value())
      return;
    for (const auto &rule : config.pricing_rules) {
      if (!rule.provider.empty() && rule.provider != sample.provider)
        continue;
      if (!rule.model.empty() && rule.model != sample.model)
        continue;
      if (!rule.service_tier.empty() && rule.service_tier != sample.service_tier)
        continue;
      const std::uint64_t raw_in = *sample.input_tokens;
      const std::uint64_t cached = sample.cached_tokens.value_or(0);
      const std::uint64_t cache_write = sample.cache_write_tokens.value_or(0);
      if (sample.input_includes_cache && cached > raw_in)
        continue;
      const std::uint64_t non_cached_in =
          sample.input_includes_cache ? (raw_in - cached) : raw_in;
      double total =
          (static_cast<double>(non_cached_in) * rule.input_per_million +
           static_cast<double>(*sample.output_tokens) * rule.output_per_million) /
          1000000.0;
      if (cached > 0) {
        if (!rule.cache_read_per_million.has_value())
          continue;
        total +=
            static_cast<double>(cached) * (*rule.cache_read_per_million) / 1000000.0;
      }
      if (cache_write > 0) {
        if (!rule.cache_write_per_million.has_value())
          continue;
        total += static_cast<double>(cache_write) * (*rule.cache_write_per_million) /
                 1000000.0;
      }
      if (std::isfinite(total) && total >= 0.0) {
        out_estimated_usd = total;
        out_version = !rule.date.empty() ? rule.date : config.default_pricing_version;
        return;
      }
    }
  }

  void ingest_sample(const MetricsSample &sample) {
    if (coverage.records_ingested >= config.max_records) {
      add_note("record ingestion limit reached");
      return;
    }

    // Deduplicate repeated response captures by (kind, request_id, capture_key).
    if (!sample.request_id.empty() || !sample.capture_key.empty()) {
      const DedupKey key{sample.kind, sample.request_id, sample.capture_key};
      const auto existing = seen_captures.find(key);
      if (existing != seen_captures.end()) {
        ++coverage.duplicate_captures_deduped;
        if (existing->second != fingerprint_for(sample)) {
          ++coverage.conflicting_captures;
          add_note("conflicting duplicate capture for request_id=" + sample.request_id);
        }
        return;
      }
      if (seen_captures.size() < config.max_records)
        seen_captures.emplace(key, fingerprint_for(sample));
    }

    ++coverage.records_ingested;
    record_clock(sample);
    const std::string resolved_id = resolve_source_id(sample);
    bool point_recorded = false;

    const auto record_optional_u64 = [](TriMetric<std::uint64_t> &target,
                                        const std::optional<std::uint64_t> &val) {
      if (val.has_value())
        target.record_known(*val);
      else
        target.record_missing();
    };

    const auto record_optional_double = [](TriMetric<double> &target,
                                           const std::optional<double> &val) {
      if (val.has_value())
        target.record_known(*val);
      else
        target.record_missing();
    };

    if (sample.kind == MetricsSampleKind::provider_response) {
      provider_requests.record_known(1);
      if (sample.succeeded.has_value())
        error_count.record_known(*sample.succeeded ? 0 : 1);
      else
        error_count.record_missing();
      record_optional_u64(retry_count, sample.retries);

      ttft_stats.record(sample.ttft_ms);
      if (sample.ttft_ms.has_value() && std::isfinite(*sample.ttft_ms) &&
          *sample.ttft_ms >= 0.0) {
        auto pt = make_point(sample, resolved_id, "ms", *sample.ttft_ms);
        ttft_ms.push(pt);
        op_points.push(std::move(pt));
        point_recorded = true;
      }

      total_latency_stats.record(sample.total_latency_ms);
      if (sample.total_latency_ms.has_value() &&
          std::isfinite(*sample.total_latency_ms) && *sample.total_latency_ms >= 0.0) {
        auto pt = make_point(sample, resolved_id, "ms", *sample.total_latency_ms);
        total_latency_ms.push(pt);
        op_points.push(std::move(pt));
        point_recorded = true;
      }

      // Usage & cost accounting (strictly separate observed charge vs versioned
      // estimate).
      ++usage_observations;
      const std::string provider_key =
          sample.provider.empty() ? std::string{"unknown"} : sample.provider;
      auto &prov = by_provider[provider_key];
      prov.provider = provider_key;
      ++prov.observation_count;

      record_optional_u64(total_input_tokens, sample.input_tokens);
      record_optional_u64(total_cached_tokens, sample.cached_tokens);
      record_optional_u64(total_cache_write_tokens, sample.cache_write_tokens);
      record_optional_u64(total_reasoning_tokens, sample.reasoning_tokens);
      record_optional_u64(total_output_tokens, sample.output_tokens);

      record_optional_u64(prov.input_tokens, sample.input_tokens);
      record_optional_u64(prov.cached_tokens, sample.cached_tokens);
      record_optional_u64(prov.cache_write_tokens, sample.cache_write_tokens);
      record_optional_u64(prov.reasoning_tokens, sample.reasoning_tokens);
      record_optional_u64(prov.output_tokens, sample.output_tokens);

      // Compute cache hit ratio denominator honestly.
      std::optional<std::uint64_t> effective_input;
      if (sample.input_tokens.has_value()) {
        if (sample.input_includes_cache) {
          effective_input = *sample.input_tokens;
        } else {
          std::uint64_t denom = *sample.input_tokens;
          if (sample.cached_tokens.has_value()) {
            if (std::numeric_limits<std::uint64_t>::max() - denom >=
                *sample.cached_tokens)
              denom += *sample.cached_tokens;
            else
              denom = std::numeric_limits<std::uint64_t>::max();
          }
          if (sample.cache_write_tokens.has_value()) {
            if (std::numeric_limits<std::uint64_t>::max() - denom >=
                *sample.cache_write_tokens)
              denom += *sample.cache_write_tokens;
            else
              denom = std::numeric_limits<std::uint64_t>::max();
          }
          effective_input = denom;
        }
      }
      record_optional_u64(total_cache_denominator, effective_input);
      record_optional_u64(prov.cache_denominator_tokens, effective_input);

      record_optional_double(total_observed_charge_usd, sample.observed_charge_usd);
      record_optional_double(prov.observed_charge_usd, sample.observed_charge_usd);

      std::optional<double> est_usd;
      std::string est_version;
      compute_pricing_estimate(sample, est_usd, est_version);
      total_estimates.record(est_usd, est_version, &coverage);
      prov.estimates.record(est_usd, est_version, nullptr);

      if (sample.input_tokens.has_value() || sample.output_tokens.has_value()) {
        const double total_tok = static_cast<double>(sample.input_tokens.value_or(0)) +
                                 static_cast<double>(sample.output_tokens.value_or(0));
        token_spend_series.push(make_point(sample, resolved_id, "tokens", total_tok));
        point_recorded = true;
      }
      if (sample.observed_charge_usd.has_value() &&
          std::isfinite(*sample.observed_charge_usd) &&
          *sample.observed_charge_usd >= 0.0) {
        charge_usd_series.push(
            make_point(sample, resolved_id, "usd", *sample.observed_charge_usd));
        point_recorded = true;
      }
      if (est_usd.has_value() && !est_version.empty() && std::isfinite(*est_usd) &&
          *est_usd >= 0.0) {
        estimated_usd_series.push(make_point(sample, resolved_id, "usd", *est_usd));
        point_recorded = true;
      }
    } else if (sample.kind == MetricsSampleKind::tool_execution) {
      tool_executions.record_known(1);
      if (sample.succeeded.has_value()) {
        const std::uint64_t fail = *sample.succeeded ? 0 : 1;
        tool_failures.record_known(fail);
        error_count.record_known(fail);
      } else {
        tool_failures.record_missing();
        error_count.record_missing();
      }
      record_optional_u64(retry_count, sample.retries);
      tool_duration_stats.record(sample.tool_duration_ms);
      if (sample.tool_duration_ms.has_value() &&
          std::isfinite(*sample.tool_duration_ms) && *sample.tool_duration_ms >= 0.0) {
        auto pt = make_point(sample, resolved_id, "ms", *sample.tool_duration_ms);
        tool_duration_ms.push(pt);
        op_points.push(std::move(pt));
        point_recorded = true;
      }
    } else if (sample.kind == MetricsSampleKind::context_snapshot) {
      ++context_observations;
      if (sample.live_bytes.has_value()) {
        latest_live_bytes.set_observed_gauge(*sample.live_bytes);
        peak_live_bytes.record_max(*sample.live_bytes);
        live_bytes_series.push(make_point(sample, resolved_id, "bytes",
                                          static_cast<double>(*sample.live_bytes)));
        point_recorded = true;
      } else {
        latest_live_bytes.record_missing();
        peak_live_bytes.record_missing();
      }

      if (sample.archived_bytes.has_value()) {
        latest_archived_bytes.set_observed_gauge(*sample.archived_bytes);
        archived_bytes_series.push(make_point(
            sample, resolved_id, "bytes", static_cast<double>(*sample.archived_bytes)));
        point_recorded = true;
      } else {
        latest_archived_bytes.record_missing();
      }

      bool jump_detected = sample.cache_epoch_jump;
      if (sample.cache_epoch.has_value() && !sample.cache_epoch->empty()) {
        if (last_cache_epoch.has_value() && *last_cache_epoch != *sample.cache_epoch)
          jump_detected = true;
        last_cache_epoch = *sample.cache_epoch;
      }
      if (jump_detected) {
        upstream_cache_epoch_jumps.record_known(1);
        cache_epoch_jumps_series.push(make_point(sample, resolved_id, "count", 1.0));
        point_recorded = true;
      } else if (sample.cache_epoch.has_value()) {
        upstream_cache_epoch_jumps.record_known(0);
      }

      if (sample.compaction_event) {
        compaction_events.record_known(1);
        double reclaimed_val = 0.0;
        if (sample.compaction_bytes_before.has_value() &&
            sample.compaction_bytes_after.has_value() &&
            *sample.compaction_bytes_before >= *sample.compaction_bytes_after) {
          const std::uint64_t reclaimed =
              *sample.compaction_bytes_before - *sample.compaction_bytes_after;
          compaction_bytes_reclaimed.record_known(reclaimed);
          reclaimed_val = static_cast<double>(reclaimed);
        } else {
          compaction_bytes_reclaimed.record_missing();
        }
        compaction_series.push(make_point(sample, resolved_id, "bytes", reclaimed_val));
        point_recorded = true;
      } else {
        compaction_events.record_known(0);
      }
    } else if (sample.kind == MetricsSampleKind::decision_batch) {
      decision_batches.record_known(1);
      if (sample.succeeded.has_value()) {
        const std::uint64_t fail = *sample.succeeded ? 0 : 1;
        decision_failures.record_known(fail);
        error_count.record_known(fail);
      } else {
        decision_failures.record_missing();
        error_count.record_missing();
      }
      decision_latency_stats.record(sample.total_latency_ms);
      if (sample.total_latency_ms.has_value() &&
          std::isfinite(*sample.total_latency_ms) && *sample.total_latency_ms >= 0.0) {
        decision_latency_ms.push(
            make_point(sample, resolved_id, "ms", *sample.total_latency_ms));
        point_recorded = true;
      }

      record_optional_u64(decision_input_tokens, sample.input_tokens);
      record_optional_u64(decision_output_tokens, sample.output_tokens);
      if (sample.input_tokens.has_value() && sample.output_tokens.has_value()) {
        const std::uint64_t sum =
            std::numeric_limits<std::uint64_t>::max() - *sample.input_tokens <
                    *sample.output_tokens
                ? std::numeric_limits<std::uint64_t>::max()
                : *sample.input_tokens + *sample.output_tokens;
        decision_total_tokens.record_known(sum);
        decision_token_spend.push(
            make_point(sample, resolved_id, "tokens", static_cast<double>(sum)));
        point_recorded = true;
      } else {
        decision_total_tokens.record_missing();
      }

      record_optional_double(decision_observed_charge_usd, sample.observed_charge_usd);
      std::optional<double> est_usd;
      std::string est_version;
      compute_pricing_estimate(sample, est_usd, est_version);
      decision_estimates.record(est_usd, est_version, &coverage);
    } else if (sample.kind == MetricsSampleKind::operation_event) {
      if (sample.succeeded.has_value())
        error_count.record_known(*sample.succeeded ? 0 : 1);
      else
        error_count.record_missing();
      record_optional_u64(retry_count, sample.retries);
      if (sample.total_latency_ms.has_value() &&
          std::isfinite(*sample.total_latency_ms) && *sample.total_latency_ms >= 0.0) {
        total_latency_stats.record(sample.total_latency_ms);
        auto pt = make_point(sample, resolved_id, "ms", *sample.total_latency_ms);
        total_latency_ms.push(pt);
        op_points.push(std::move(pt));
        point_recorded = true;
      }
    }

    if (point_recorded || !sample.source_record_id.empty())
      record_source(sample, resolved_id);
  }

  void collect_referenced_ids(const SeriesBuilder &series,
                              std::set<std::string> &referenced) const {
    for (const auto &pt : series.points)
      referenced.insert(pt.source_record_id);
  }

  MetricsSnapshot materialize(std::uint64_t generation,
                              std::string source_description) const {
    MetricsSnapshot snap;
    snap.generation = generation;
    snap.has_data = coverage.records_ingested > 0;
    snap.stale = false;
    snap.source_description = std::move(source_description);

    snap.coverage = coverage;
    snap.coverage.clock_ids.assign(clock_id_set.begin(), clock_id_set.end());
    snap.coverage.complete_session_ledger = false;

    // Operations
    snap.operations.provider_requests = provider_requests;
    snap.operations.tool_executions = tool_executions;
    snap.operations.tool_failures = tool_failures;
    snap.operations.error_count = error_count;
    snap.operations.retry_count = retry_count;
    snap.operations.ttft_stats = ttft_stats.materialize();
    snap.operations.total_latency_stats = total_latency_stats.materialize();
    snap.operations.tool_duration_stats = tool_duration_stats.materialize();
    snap.operations.ttft_ms = ttft_ms.materialize();
    snap.operations.total_latency_ms = total_latency_ms.materialize();
    snap.operations.tool_duration_ms = tool_duration_ms.materialize();
    snap.operations.points = op_points.materialize();

    // Usage
    snap.usage.observation_count = usage_observations;
    snap.usage.total_input_tokens = total_input_tokens;
    snap.usage.total_cached_tokens = total_cached_tokens;
    snap.usage.total_cache_write_tokens = total_cache_write_tokens;
    snap.usage.total_reasoning_tokens = total_reasoning_tokens;
    snap.usage.total_output_tokens = total_output_tokens;
    snap.usage.cache_hit_ratio = ProviderUsageAccumulator::compute_cache_hit_ratio(
        total_cached_tokens, total_cache_denominator);
    snap.usage.observed_charge_usd = total_observed_charge_usd;
    total_estimates.apply_to(snap.usage.estimated_cost_usd, snap.usage.pricing_version,
                             snap.usage.mixed_pricing_versions,
                             snap.usage.estimates_by_version);
    snap.usage.by_provider.reserve(by_provider.size());
    for (const auto &[name, acc] : by_provider) {
      (void)name;
      snap.usage.by_provider.push_back(acc.materialize());
    }
    snap.usage.token_spend_series = token_spend_series.materialize();
    snap.usage.charge_usd_series = charge_usd_series.materialize();
    snap.usage.estimated_usd_series = estimated_usd_series.materialize();

    // Context
    snap.context.observation_count = context_observations;
    snap.context.latest_live_bytes = latest_live_bytes;
    snap.context.latest_archived_bytes = latest_archived_bytes;
    snap.context.peak_live_bytes = peak_live_bytes;
    snap.context.upstream_cache_epoch_jumps = upstream_cache_epoch_jumps;
    snap.context.compaction_events = compaction_events;
    snap.context.compaction_bytes_reclaimed = compaction_bytes_reclaimed;
    snap.context.last_cache_epoch = last_cache_epoch;
    snap.context.live_bytes_series = live_bytes_series.materialize();
    snap.context.archived_bytes_series = archived_bytes_series.materialize();
    snap.context.cache_epoch_jumps_series = cache_epoch_jumps_series.materialize();
    snap.context.compaction_series = compaction_series.materialize();

    // Decision companion
    snap.decision_companion.batch_count = decision_batches;
    snap.decision_companion.failure_count = decision_failures;
    snap.decision_companion.latency_stats = decision_latency_stats.materialize();
    snap.decision_companion.input_tokens = decision_input_tokens;
    snap.decision_companion.output_tokens = decision_output_tokens;
    snap.decision_companion.total_tokens = decision_total_tokens;
    snap.decision_companion.observed_charge_usd = decision_observed_charge_usd;
    decision_estimates.apply_to(snap.decision_companion.estimated_cost_usd,
                                snap.decision_companion.pricing_version,
                                snap.decision_companion.mixed_pricing_versions,
                                snap.decision_companion.estimates_by_version);
    snap.decision_companion.latency_ms = decision_latency_ms.materialize();
    snap.decision_companion.token_spend_series = decision_token_spend.materialize();

    // Retain all source records referenced by active series points plus up to a
    // bounded cap of non-plotted records so every plotted point recovers its source.
    std::set<std::string> referenced;
    collect_referenced_ids(ttft_ms, referenced);
    collect_referenced_ids(total_latency_ms, referenced);
    collect_referenced_ids(tool_duration_ms, referenced);
    collect_referenced_ids(op_points, referenced);
    collect_referenced_ids(token_spend_series, referenced);
    collect_referenced_ids(charge_usd_series, referenced);
    collect_referenced_ids(estimated_usd_series, referenced);
    collect_referenced_ids(live_bytes_series, referenced);
    collect_referenced_ids(archived_bytes_series, referenced);
    collect_referenced_ids(cache_epoch_jumps_series, referenced);
    collect_referenced_ids(compaction_series, referenced);
    collect_referenced_ids(decision_latency_ms, referenced);
    collect_referenced_ids(decision_token_spend, referenced);

    std::size_t extra_kept = 0;
    const std::size_t extra_cap = series_cap * 4;
    snap.source_records.reserve(referenced.size() +
                                std::min(extra_cap, source_index.size()));
    for (const auto &[id, rec] : source_index) {
      if (referenced.contains(id)) {
        snap.source_records.push_back(rec);
      } else if (extra_kept < extra_cap) {
        snap.source_records.push_back(rec);
        ++extra_kept;
      }
    }
    return snap;
  }
};

Result<void> parse_jsonl_into(const std::filesystem::path &path, std::size_t max_bytes,
                              ConsumerState &state, std::string &error_detail) {
  auto content = read_file_bounded(path, max_bytes);
  if (!content.has_value()) {
    error_detail = std::string{"source unavailable ("} +
                   error_name(content.error().code) + "): " + path.string();
    return Result<void>::failure(content.error());
  }
  const std::string_view text = content.value();
  std::size_t pos = 0;
  std::size_t line_no = 0;
  while (pos < text.size()) {
    ++line_no;
    const std::size_t nl = text.find('\n', pos);
    const std::string_view line =
        nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
    pos = nl == std::string_view::npos ? text.size() : nl + 1;
    if (is_whitespace_only(line))
      continue;
    auto parsed = parse_metrics_sample_json(line);
    if (!parsed.has_value()) {
      error_detail = "corrupt JSONL record at line " + std::to_string(line_no) +
                     " in " + path.string();
      return Result<void>::failure(parsed.error());
    }
    auto sample = std::move(parsed).value();
    if (sample.source_locator.empty())
      sample.source_locator = path.string() + ":" + std::to_string(line_no);
    if (sample.source_record_id.empty())
      sample.source_record_id =
          path.filename().string() + ":" + std::to_string(line_no);
    state.ingest_sample(sample);
  }
  return Result<void>::success();
}

Result<void> ingest_audit_into(AuditLog &log, ConsumerState &state,
                               std::string &error_detail) {
  const RetainedState &retained = log.root();
  const auto history = retained.history_snapshot();
  const std::size_t limit = std::min(history.count, state.config.max_records);
  for (std::size_t i = 0; i < limit; ++i) {
    auto fact_res = history.read(i);
    if (!fact_res.has_value()) {
      error_detail = std::string{"audit read failed at fact "} + std::to_string(i) +
                     ": " + error_name(fact_res.error().code);
      return Result<void>::failure(fact_res.error());
    }
    const auto &fact = fact_res.value();
    const std::string record_id = hex_identity(fact.record.journal.bytes()) + ":" +
                                  std::to_string(fact.record.sequence);
    if (const auto *app = std::get_if<ApplicationRecordEvent>(&fact.event.body)) {
      if (app->channel != ApplicationChannel::log || app->payload.size() > 65536)
        continue;
      auto decoded = read_application_packet(*app);
      if (!decoded.has_value())
        continue;
      const Value &packet = decoded.value();
      const auto label = parse_string(packet.find("label")).value_or(std::string{});
      if (label == "metrics.sample" ||
          parse_metrics_sample_kind(
              parse_string(packet.find("kind")).value_or(std::string{}))
              .has_value()) {
        auto parsed = parse_metrics_sample(packet);
        if (parsed.has_value()) {
          auto sample = std::move(parsed).value();
          if (sample.source_record_id.empty())
            sample.source_record_id = record_id;
          if (sample.source_locator.empty())
            sample.source_locator = "audit:" + record_id;
          state.ingest_sample(sample);
        } else {
          ++state.coverage.records_skipped_corrupt;
        }
      } else if (label == "variable.sample") {
        const auto var_name = parse_string(packet.find("variable"));
        if (!var_name.has_value())
          continue;
        MetricsSample sample;
        sample.source_record_id = record_id;
        sample.source_label = "variable." + *var_name;
        sample.source_locator = "audit:" + record_id;
        if (const auto *t = packet.find("time")) {
          if (const auto cid = parse_string(t->find("clock_id")))
            sample.clock_id = *cid;
          if (const auto utc = parse_int64(t->find("utc_ns"))) {
            sample.clock_domain = MetricsClockDomain::utc_ns;
            sample.timestamp_ns = *utc;
          } else if (const auto mono = parse_int64(t->find("monotonic_ns"))) {
            sample.clock_domain = MetricsClockDomain::monotonic_ns;
            sample.timestamp_ns = *mono;
          }
        }
        const auto *val = packet.find("value");
        sample.raw_metadata = packet;
        if (*var_name == "context.live_bytes") {
          sample.kind = MetricsSampleKind::context_snapshot;
          sample.live_bytes = parse_uint64(val);
          state.ingest_sample(sample);
        } else if (*var_name == "context.archived_bytes") {
          sample.kind = MetricsSampleKind::context_snapshot;
          sample.archived_bytes = parse_uint64(val);
          state.ingest_sample(sample);
        } else if (*var_name == "provider.ttft_ms") {
          sample.kind = MetricsSampleKind::provider_response;
          sample.ttft_ms = parse_non_negative_double(val);
          state.ingest_sample(sample);
        } else if (*var_name == "tool.duration_ms") {
          sample.kind = MetricsSampleKind::tool_execution;
          sample.tool_duration_ms = parse_non_negative_double(val);
          state.ingest_sample(sample);
        } else if (*var_name == "jev.latency_ms" || *var_name == "clef.latency_ms") {
          sample.kind = MetricsSampleKind::decision_batch;
          sample.provider = *var_name == "clef.latency_ms" ? "clef" : "jev";
          sample.total_latency_ms = parse_non_negative_double(val);
          state.ingest_sample(sample);
        }
      }
    } else if (const auto *obs =
                   std::get_if<AttemptObservationEvent>(&fact.event.body)) {
      MetricsSample sample;
      sample.kind = MetricsSampleKind::operation_event;
      sample.source_record_id = record_id;
      sample.source_label = "attempt.observation";
      sample.source_locator = "audit:" + record_id;
      sample.request_id = hex_identity(obs->attempt.bytes());
      if (obs->disposition == AttemptDisposition::success)
        sample.succeeded = true;
      else if (obs->disposition == AttemptDisposition::failure ||
               obs->disposition == AttemptDisposition::cancellation)
        sample.succeeded = false;
      state.ingest_sample(sample);
    }
  }
  return Result<void>::success();
}

void ingest_token_usage_into(const TokenUsageReport &report, ConsumerState &state) {
  for (const auto &issue : report.issues) {
    state.add_note("token_usage: " + issue.reason);
  }
  for (const auto &obs : report.observations) {
    if (obs.scope == UsageScope::model_alternative)
      continue;
    MetricsSample sample;
    sample.kind = obs.actor == UsageActor::decision
                      ? MetricsSampleKind::decision_batch
                      : MetricsSampleKind::provider_response;
    sample.request_id =
        hex_identity(obs.request.lane) + ":" + std::to_string(obs.request.ordinal);
    if (!obs.sources.empty()) {
      const auto &src = obs.sources.front();
      sample.source_record_id =
          hex_identity(src.event.lane) + ":" + std::to_string(src.event.ordinal);
      sample.source_locator = src.run_directory + "#" + sample.source_record_id;
    } else {
      sample.source_record_id = sample.request_id;
    }
    sample.source_label = obs.actor == UsageActor::decision ? "token_usage.decision"
                                                            : "token_usage.provider";
    sample.provider = !obs.provider.empty()
                          ? obs.provider
                          : (!obs.reported_provider.empty() ? obs.reported_provider
                                                            : std::string{"unknown"});
    sample.model = !obs.actual_model.empty() ? obs.actual_model : obs.requested_model;
    sample.service_tier = obs.service_tier;
    sample.input_includes_cache = obs.counters.input_includes_cache;

    if (!obs.malformed && !obs.conflicting) {
      sample.input_tokens = obs.counters.input;
      sample.output_tokens = obs.counters.output;
      sample.cached_tokens = obs.counters.cache_read;
      sample.cache_write_tokens = obs.counters.cache_write;
      sample.reasoning_tokens = obs.counters.reasoning;
    }

    if (!obs.malformed_cost && !obs.conflicting_cost) {
      if (obs.observed_cost_usd.has_value()) {
        sample.observed_charge_usd = parse_number_double(*obs.observed_cost_usd);
      } else if (obs.reported_cost.has_value() && obs.reported_cost_explicit_usd) {
        sample.observed_charge_usd = parse_number_double(*obs.reported_cost);
      }
    }

    if (obs.http_status.has_value()) {
      sample.succeeded = (*obs.http_status >= 200 && *obs.http_status < 300);
    }

    state.ingest_sample(sample);
  }
}

enum class UpstreamKind : std::uint8_t {
  none = 0,
  jsonl_file = 1,
  audit_log = 2,
  token_usage_directory = 3,
  sample_source = 4,
};

} // namespace

struct MetricsConsumer::Impl {
  explicit Impl(MetricsConsumerConfig cfg) : state(std::move(cfg)) {}

  ConsumerState state;
  UpstreamKind upstream_kind = UpstreamKind::none;
  std::filesystem::path path;
  AuditLog *audit_log = nullptr;
  SampleSource sample_source;
  std::string source_description = "direct";
  std::uint64_t generation = 0;
};

std::string_view tri_metric_state_name(TriMetricState state) noexcept {
  switch (state) {
  case TriMetricState::unknown:
    return "unknown";
  case TriMetricState::zero:
    return "zero";
  case TriMetricState::known_subtotal:
    return "known_subtotal";
  case TriMetricState::complete:
    return "complete";
  }
  return "unknown";
}

std::string_view metrics_clock_domain_name(MetricsClockDomain domain) noexcept {
  switch (domain) {
  case MetricsClockDomain::unknown:
    return "unknown";
  case MetricsClockDomain::utc_ns:
    return "utc_ns";
  case MetricsClockDomain::monotonic_ns:
    return "monotonic_ns";
  }
  return "unknown";
}

std::optional<MetricsClockDomain>
parse_metrics_clock_domain(std::string_view name) noexcept {
  if (name == "utc_ns")
    return MetricsClockDomain::utc_ns;
  if (name == "monotonic_ns")
    return MetricsClockDomain::monotonic_ns;
  if (name == "unknown")
    return MetricsClockDomain::unknown;
  return std::nullopt;
}

std::string_view metrics_sample_kind_name(MetricsSampleKind kind) noexcept {
  switch (kind) {
  case MetricsSampleKind::provider_response:
    return "provider_response";
  case MetricsSampleKind::tool_execution:
    return "tool_execution";
  case MetricsSampleKind::context_snapshot:
    return "context_snapshot";
  case MetricsSampleKind::decision_batch:
    return "decision_batch";
  case MetricsSampleKind::operation_event:
    return "operation_event";
  }
  return "provider_response";
}

std::optional<MetricsSampleKind>
parse_metrics_sample_kind(std::string_view name) noexcept {
  if (name == "provider_response")
    return MetricsSampleKind::provider_response;
  if (name == "tool_execution")
    return MetricsSampleKind::tool_execution;
  if (name == "context_snapshot")
    return MetricsSampleKind::context_snapshot;
  if (name == "decision_batch")
    return MetricsSampleKind::decision_batch;
  if (name == "operation_event")
    return MetricsSampleKind::operation_event;
  return std::nullopt;
}

void MetricsSeries::push(MetricsPoint point) {
  const std::size_t cap = clamp_series_capacity(capacity);
  capacity = cap;
  if (points.size() >= cap) {
    points.erase(points.begin());
    ++dropped_oldest;
  }
  points.push_back(std::move(point));
}

std::vector<double> MetricsSeries::values() const {
  std::vector<double> out;
  out.reserve(points.size());
  for (const auto &pt : points)
    out.push_back(pt.value);
  return out;
}

MetricsSparkline metrics_sparkline(std::span<const double> values, std::size_t width) {
  MetricsSparkline result;
  result.input_count = values.size();

  std::vector<double> finite;
  finite.reserve(values.size());
  for (const double v : values) {
    if (!std::isfinite(v)) {
      ++result.ignored_non_finite;
      continue;
    }
    const double normalized = v == 0.0 ? 0.0 : v;
    finite.push_back(normalized);
    if (!result.min_value.has_value() || normalized < *result.min_value)
      result.min_value = normalized;
    if (!result.max_value.has_value() || normalized > *result.max_value)
      result.max_value = normalized;
  }
  result.finite_count = finite.size();
  if (finite.empty() || width == 0 || !result.min_value.has_value() ||
      !result.max_value.has_value()) {
    return result;
  }

  const std::size_t bounded_width = std::min(width, kMaxSparklineWidth);
  const std::size_t bucket_count = std::min(finite.size(), bounded_width);
  result.glyphs.reserve(bucket_count * 3);

  const double min_v = *result.min_value;
  const double max_v = *result.max_value;
  const long double span =
      static_cast<long double>(max_v) - static_cast<long double>(min_v);

  for (std::size_t i = 0; i < bucket_count; ++i) {
    const std::size_t begin = (i * finite.size()) / bucket_count;
    const std::size_t end = ((i + 1) * finite.size()) / bucket_count;
    long double bucket_val = 0.0L;
    if (end > begin) {
      long double sum = 0.0L;
      for (std::size_t j = begin; j < end; ++j)
        sum += static_cast<long double>(finite[j]);
      bucket_val = sum / static_cast<long double>(end - begin);
    } else {
      bucket_val = static_cast<long double>(finite[begin]);
    }

    std::size_t level = kConstantSparklineLevel;
    if (span > 0.0L && std::isfinite(static_cast<double>(span))) {
      const long double frac =
          std::clamp((bucket_val - static_cast<long double>(min_v)) / span, 0.0L, 1.0L);
      level = static_cast<std::size_t>(std::llround(frac * 7.0L));
      level = std::min<std::size_t>(level, 7);
    } else if (span > 0.0L) {
      // Extreme finite range where (max - min) overflows double; scale by 0.5.
      const long double half_min = static_cast<long double>(min_v) * 0.5L;
      const long double half_span = static_cast<long double>(max_v) * 0.5L - half_min;
      const long double frac =
          half_span > 0.0L
              ? std::clamp((bucket_val * 0.5L - half_min) / half_span, 0.0L, 1.0L)
              : 0.5L;
      level = static_cast<std::size_t>(std::llround(frac * 7.0L));
      level = std::min<std::size_t>(level, 7);
    }
    result.glyphs.append(kSparklineGlyphs[level]);
    ++result.glyph_count;
  }
  return result;
}

MetricsSparkline metrics_sparkline(const MetricsSeries &series, std::size_t width) {
  const auto vals = series.values();
  return metrics_sparkline(vals, width);
}

const MetricsSourceRecord *
MetricsSnapshot::find_source(std::string_view source_record_id) const noexcept {
  if (source_record_id.empty())
    return nullptr;
  const auto it =
      std::lower_bound(source_records.begin(), source_records.end(), source_record_id,
                       [](const MetricsSourceRecord &rec, std::string_view target) {
                         return rec.source_record_id < target;
                       });
  if (it != source_records.end() && it->source_record_id == source_record_id)
    return &(*it);
  return nullptr;
}

MetricsConsumer::MetricsConsumer(MetricsConsumerConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))),
      snapshot_(impl_->state.materialize(0, impl_->source_description)) {}

MetricsConsumer::MetricsConsumer(MetricsConsumer &&) noexcept = default;
MetricsConsumer &MetricsConsumer::operator=(MetricsConsumer &&) noexcept = default;
MetricsConsumer::~MetricsConsumer() = default;

MetricsConsumer MetricsConsumer::from_jsonl_file(std::filesystem::path path,
                                                 MetricsConsumerConfig config) {
  MetricsConsumer consumer(std::move(config));
  consumer.impl_->upstream_kind = UpstreamKind::jsonl_file;
  consumer.impl_->source_description = "jsonl:" + path.string();
  consumer.impl_->path = std::move(path);
  consumer.snapshot_.source_description = consumer.impl_->source_description;
  return consumer;
}

MetricsConsumer MetricsConsumer::from_audit_log(AuditLog &log,
                                                MetricsConsumerConfig config) {
  MetricsConsumer consumer(std::move(config));
  consumer.impl_->upstream_kind = UpstreamKind::audit_log;
  consumer.impl_->audit_log = &log;
  consumer.impl_->source_description = "audit_log";
  consumer.snapshot_.source_description = consumer.impl_->source_description;
  return consumer;
}

MetricsConsumer
MetricsConsumer::from_token_usage_directory(std::filesystem::path session_directory,
                                            MetricsConsumerConfig config) {
  MetricsConsumer consumer(std::move(config));
  consumer.impl_->upstream_kind = UpstreamKind::token_usage_directory;
  consumer.impl_->source_description = "token_usage:" + session_directory.string();
  consumer.impl_->path = std::move(session_directory);
  consumer.snapshot_.source_description = consumer.impl_->source_description;
  return consumer;
}

MetricsConsumer MetricsConsumer::from_sample_source(SampleSource source,
                                                    std::string source_description,
                                                    MetricsConsumerConfig config) {
  MetricsConsumer consumer(std::move(config));
  consumer.impl_->upstream_kind = UpstreamKind::sample_source;
  consumer.impl_->sample_source = std::move(source);
  consumer.impl_->source_description = source_description.empty()
                                           ? std::string{"custom"}
                                           : std::move(source_description);
  consumer.snapshot_.source_description = consumer.impl_->source_description;
  return consumer;
}

Result<void> MetricsConsumer::refresh() {
  if (impl_->upstream_kind == UpstreamKind::none) {
    snapshot_ =
        impl_->state.materialize(++impl_->generation, impl_->source_description);
    return Result<void>::success();
  }

  // Build candidate state independently so any failure retains last-good snapshot.
  ConsumerState candidate(impl_->state.config);
  std::string error_detail;
  Result<void> load_result = Result<void>::success();

  if (impl_->upstream_kind == UpstreamKind::jsonl_file) {
    load_result = parse_jsonl_into(impl_->path, candidate.config.max_jsonl_bytes,
                                   candidate, error_detail);
  } else if (impl_->upstream_kind == UpstreamKind::audit_log) {
    if (!impl_->audit_log) {
      error_detail = "audit_log source is null";
      load_result = Result<void>::failure({ErrorCode::audit_unavailable});
    } else {
      load_result = ingest_audit_into(*impl_->audit_log, candidate, error_detail);
    }
  } else if (impl_->upstream_kind == UpstreamKind::token_usage_directory) {
    auto report = read_token_usage(impl_->path.string());
    if (!report.has_value()) {
      error_detail = std::string{"token_usage directory unavailable ("} +
                     error_name(report.error().code) + "): " + impl_->path.string();
      load_result = Result<void>::failure(report.error());
    } else {
      ingest_token_usage_into(report.value(), candidate);
    }
  } else if (impl_->upstream_kind == UpstreamKind::sample_source) {
    if (!impl_->sample_source) {
      error_detail = "sample source callback is empty";
      load_result = Result<void>::failure({ErrorCode::unsupported});
    } else {
      auto samples = impl_->sample_source();
      if (!samples.has_value()) {
        error_detail = std::string{"sample source failed ("} +
                       error_name(samples.error().code) + ")";
        load_result = Result<void>::failure(samples.error());
      } else {
        for (const auto &sample : samples.value())
          candidate.ingest_sample(sample);
      }
    }
  }

  if (!load_result.has_value()) {
    // Preserve last-good snapshot intact; mark stale with explicit reason.
    snapshot_.stale = true;
    snapshot_.stale_reason = error_detail.empty()
                                 ? std::string{error_name(load_result.error().code)}
                                 : std::move(error_detail);
    snapshot_.last_refresh_error = load_result.error();
    return load_result;
  }

  impl_->state = std::move(candidate);
  snapshot_ = impl_->state.materialize(++impl_->generation, impl_->source_description);
  return Result<void>::success();
}

Result<void> MetricsConsumer::ingest(const MetricsSample &sample) {
  impl_->state.ingest_sample(sample);
  snapshot_ = impl_->state.materialize(++impl_->generation, impl_->source_description);
  return Result<void>::success();
}

Result<void> MetricsConsumer::ingest_batch(std::span<const MetricsSample> samples) {
  for (const auto &sample : samples)
    impl_->state.ingest_sample(sample);
  snapshot_ = impl_->state.materialize(++impl_->generation, impl_->source_description);
  return Result<void>::success();
}

Result<void> MetricsConsumer::ingest_jsonl_file(const std::filesystem::path &path) {
  ConsumerState candidate = impl_->state;
  std::string error_detail;
  auto res =
      parse_jsonl_into(path, candidate.config.max_jsonl_bytes, candidate, error_detail);
  if (!res.has_value()) {
    snapshot_.stale = true;
    snapshot_.stale_reason = std::move(error_detail);
    snapshot_.last_refresh_error = res.error();
    return res;
  }
  impl_->state = std::move(candidate);
  snapshot_ = impl_->state.materialize(++impl_->generation, impl_->source_description);
  return Result<void>::success();
}

Result<void> MetricsConsumer::ingest_audit_log(AuditLog &log) {
  ConsumerState candidate = impl_->state;
  std::string error_detail;
  auto res = ingest_audit_into(log, candidate, error_detail);
  if (!res.has_value()) {
    snapshot_.stale = true;
    snapshot_.stale_reason = std::move(error_detail);
    snapshot_.last_refresh_error = res.error();
    return res;
  }
  impl_->state = std::move(candidate);
  snapshot_ = impl_->state.materialize(++impl_->generation, impl_->source_description);
  return Result<void>::success();
}

Result<void> MetricsConsumer::ingest_token_usage(const TokenUsageReport &report) {
  ingest_token_usage_into(report, impl_->state);
  snapshot_ = impl_->state.materialize(++impl_->generation, impl_->source_description);
  return Result<void>::success();
}

void MetricsConsumer::clear() {
  const auto cfg = impl_->state.config;
  impl_->state = ConsumerState(cfg);
  snapshot_ = impl_->state.materialize(++impl_->generation, impl_->source_description);
}

void MetricsConsumer::mark_stale(std::string reason, std::optional<Error> error) {
  snapshot_.stale = true;
  snapshot_.stale_reason = std::move(reason);
  snapshot_.last_refresh_error = error;
}

Result<MetricsSample> parse_metrics_sample(const Value &value) {
  if (!std::holds_alternative<Value::Object>(value.value()))
    return Result<MetricsSample>::failure({ErrorCode::corrupt});

  MetricsSample sample;
  if (const auto kind_str = parse_string(value.find("kind"))) {
    const auto parsed_kind = parse_metrics_sample_kind(*kind_str);
    if (!parsed_kind.has_value())
      return Result<MetricsSample>::failure({ErrorCode::corrupt});
    sample.kind = *parsed_kind;
  } else if (value.find("kind") != nullptr) {
    return Result<MetricsSample>::failure({ErrorCode::corrupt});
  }

  const auto read_opt_str = [&](std::string_view key,
                                std::string &target) -> Result<void> {
    const Value *f = value.find(key);
    if (!f || std::holds_alternative<std::nullptr_t>(f->value()))
      return Result<void>::success();
    const auto s = parse_string(f);
    if (!s.has_value())
      return Result<void>::failure({ErrorCode::corrupt});
    target = *s;
    return Result<void>::success();
  };

  for (auto &[key, target] :
       std::array<std::pair<std::string_view, std::string *>, 11>{{
           {"source_record_id", &sample.source_record_id},
           {"source_label", &sample.source_label},
           {"source_locator", &sample.source_locator},
           {"clock_id", &sample.clock_id},
           {"request_id", &sample.request_id},
           {"capture_key", &sample.capture_key},
           {"provider", &sample.provider},
           {"model", &sample.model},
           {"service_tier", &sample.service_tier},
           {"tool_name", &sample.tool_name},
           {"pricing_version", &sample.pricing_version},
       }}) {
    auto ok = read_opt_str(key, *target);
    if (!ok.has_value())
      return Result<MetricsSample>::failure(ok.error());
  }

  if (const auto *cd = value.find("clock_domain");
      cd && !std::holds_alternative<std::nullptr_t>(cd->value())) {
    const auto cd_str = parse_string(cd);
    if (!cd_str.has_value())
      return Result<MetricsSample>::failure({ErrorCode::corrupt});
    const auto parsed_cd = parse_metrics_clock_domain(*cd_str);
    if (!parsed_cd.has_value())
      return Result<MetricsSample>::failure({ErrorCode::corrupt});
    sample.clock_domain = *parsed_cd;
  }

  if (const auto *ts = value.find("timestamp_ns");
      ts && !std::holds_alternative<std::nullptr_t>(ts->value())) {
    const auto parsed_ts = parse_int64(ts);
    if (!parsed_ts.has_value())
      return Result<MetricsSample>::failure({ErrorCode::corrupt});
    sample.timestamp_ns = *parsed_ts;
  } else if (const auto *t = value.find("time");
             t && std::holds_alternative<Value::Object>(t->value())) {
    if (sample.clock_id.empty()) {
      if (const auto cid = parse_string(t->find("clock_id")))
        sample.clock_id = *cid;
    }
    if (const auto utc = parse_int64(t->find("utc_ns"))) {
      sample.clock_domain = MetricsClockDomain::utc_ns;
      sample.timestamp_ns = *utc;
    } else if (const auto mono = parse_int64(t->find("monotonic_ns"))) {
      sample.clock_domain = MetricsClockDomain::monotonic_ns;
      sample.timestamp_ns = *mono;
    }
  }

  const auto read_opt_double = [&](std::string_view key,
                                   std::optional<double> &target) -> Result<void> {
    const Value *f = value.find(key);
    if (!f || std::holds_alternative<std::nullptr_t>(f->value()))
      return Result<void>::success();
    const auto parsed = parse_non_negative_double(f);
    if (!parsed.has_value())
      return Result<void>::failure({ErrorCode::corrupt});
    target = *parsed;
    return Result<void>::success();
  };

  const auto read_opt_u64 = [&](std::string_view key,
                                std::optional<std::uint64_t> &target) -> Result<void> {
    const Value *f = value.find(key);
    if (!f || std::holds_alternative<std::nullptr_t>(f->value()))
      return Result<void>::success();
    const auto parsed = parse_uint64(f);
    if (!parsed.has_value())
      return Result<void>::failure({ErrorCode::corrupt});
    target = *parsed;
    return Result<void>::success();
  };

  for (auto &[key, target] :
       std::array<std::pair<std::string_view, std::optional<double> *>, 5>{{
           {"ttft_ms", &sample.ttft_ms},
           {"total_latency_ms", &sample.total_latency_ms},
           {"tool_duration_ms", &sample.tool_duration_ms},
           {"observed_charge_usd", &sample.observed_charge_usd},
           {"estimated_usd", &sample.estimated_usd},
       }}) {
    auto ok = read_opt_double(key, *target);
    if (!ok.has_value())
      return Result<MetricsSample>::failure(ok.error());
  }
  if (!sample.observed_charge_usd.has_value()) {
    auto ok = read_opt_double("charge_usd", sample.observed_charge_usd);
    if (!ok.has_value())
      return Result<MetricsSample>::failure(ok.error());
  }

  for (auto &[key, target] :
       std::array<std::pair<std::string_view, std::optional<std::uint64_t> *>, 10>{{
           {"retries", &sample.retries},
           {"input_tokens", &sample.input_tokens},
           {"cached_tokens", &sample.cached_tokens},
           {"cache_write_tokens", &sample.cache_write_tokens},
           {"reasoning_tokens", &sample.reasoning_tokens},
           {"output_tokens", &sample.output_tokens},
           {"live_bytes", &sample.live_bytes},
           {"archived_bytes", &sample.archived_bytes},
           {"compaction_bytes_before", &sample.compaction_bytes_before},
           {"compaction_bytes_after", &sample.compaction_bytes_after},
       }}) {
    auto ok = read_opt_u64(key, *target);
    if (!ok.has_value())
      return Result<MetricsSample>::failure(ok.error());
  }

  if (const auto *f = value.find("succeeded");
      f && !std::holds_alternative<std::nullptr_t>(f->value())) {
    const auto b = parse_bool(f);
    if (!b.has_value())
      return Result<MetricsSample>::failure({ErrorCode::corrupt});
    sample.succeeded = *b;
  }
  if (const auto *f = value.find("input_includes_cache");
      f && !std::holds_alternative<std::nullptr_t>(f->value())) {
    const auto b = parse_bool(f);
    if (!b.has_value())
      return Result<MetricsSample>::failure({ErrorCode::corrupt});
    sample.input_includes_cache = *b;
  }
  if (const auto *f = value.find("cache_epoch");
      f && !std::holds_alternative<std::nullptr_t>(f->value())) {
    const auto s = parse_string(f);
    if (!s.has_value())
      return Result<MetricsSample>::failure({ErrorCode::corrupt});
    sample.cache_epoch = *s;
  }
  if (const auto *f = value.find("cache_epoch_jump");
      f && !std::holds_alternative<std::nullptr_t>(f->value())) {
    const auto b = parse_bool(f);
    if (!b.has_value())
      return Result<MetricsSample>::failure({ErrorCode::corrupt});
    sample.cache_epoch_jump = *b;
  }
  if (const auto *f = value.find("compaction_event");
      f && !std::holds_alternative<std::nullptr_t>(f->value())) {
    const auto b = parse_bool(f);
    if (!b.has_value())
      return Result<MetricsSample>::failure({ErrorCode::corrupt});
    sample.compaction_event = *b;
  }
  if (const auto *f = value.find("raw_metadata"))
    sample.raw_metadata = *f;

  return Result<MetricsSample>::success(std::move(sample));
}

Result<MetricsSample> parse_metrics_sample_json(std::string_view json_line) {
  auto parsed = parse_json(json_line);
  if (!parsed.has_value())
    return Result<MetricsSample>::failure(parsed.error());
  return parse_metrics_sample(parsed.value());
}

Value to_value(const MetricsSample &sample) {
  Value::Object obj;
  obj.emplace_back("kind", Value{std::string{metrics_sample_kind_name(sample.kind)}});
  if (!sample.source_record_id.empty())
    obj.emplace_back("source_record_id", Value{sample.source_record_id});
  if (!sample.source_label.empty())
    obj.emplace_back("source_label", Value{sample.source_label});
  if (!sample.source_locator.empty())
    obj.emplace_back("source_locator", Value{sample.source_locator});
  obj.emplace_back("clock_domain",
                   Value{std::string{metrics_clock_domain_name(sample.clock_domain)}});
  if (!sample.clock_id.empty())
    obj.emplace_back("clock_id", Value{sample.clock_id});
  obj.emplace_back("timestamp_ns", Value{Number{sample.timestamp_ns}});
  if (!sample.request_id.empty())
    obj.emplace_back("request_id", Value{sample.request_id});
  if (!sample.capture_key.empty())
    obj.emplace_back("capture_key", Value{sample.capture_key});
  if (!sample.provider.empty())
    obj.emplace_back("provider", Value{sample.provider});
  if (!sample.model.empty())
    obj.emplace_back("model", Value{sample.model});
  if (!sample.service_tier.empty())
    obj.emplace_back("service_tier", Value{sample.service_tier});
  if (!sample.tool_name.empty())
    obj.emplace_back("tool_name", Value{sample.tool_name});
  if (sample.ttft_ms.has_value())
    obj.emplace_back("ttft_ms", finite_double_value(*sample.ttft_ms));
  if (sample.total_latency_ms.has_value())
    obj.emplace_back("total_latency_ms", finite_double_value(*sample.total_latency_ms));
  if (sample.tool_duration_ms.has_value())
    obj.emplace_back("tool_duration_ms", finite_double_value(*sample.tool_duration_ms));
  if (sample.succeeded.has_value())
    obj.emplace_back("succeeded", Value{*sample.succeeded});
  if (sample.retries.has_value())
    obj.emplace_back("retries", Value{Number{*sample.retries}});
  if (sample.input_tokens.has_value())
    obj.emplace_back("input_tokens", Value{Number{*sample.input_tokens}});
  if (sample.cached_tokens.has_value())
    obj.emplace_back("cached_tokens", Value{Number{*sample.cached_tokens}});
  if (sample.cache_write_tokens.has_value())
    obj.emplace_back("cache_write_tokens", Value{Number{*sample.cache_write_tokens}});
  if (sample.reasoning_tokens.has_value())
    obj.emplace_back("reasoning_tokens", Value{Number{*sample.reasoning_tokens}});
  if (sample.output_tokens.has_value())
    obj.emplace_back("output_tokens", Value{Number{*sample.output_tokens}});
  obj.emplace_back("input_includes_cache", Value{sample.input_includes_cache});
  if (sample.observed_charge_usd.has_value())
    obj.emplace_back("observed_charge_usd",
                     finite_double_value(*sample.observed_charge_usd));
  if (sample.estimated_usd.has_value())
    obj.emplace_back("estimated_usd", finite_double_value(*sample.estimated_usd));
  if (!sample.pricing_version.empty())
    obj.emplace_back("pricing_version", Value{sample.pricing_version});
  if (sample.live_bytes.has_value())
    obj.emplace_back("live_bytes", Value{Number{*sample.live_bytes}});
  if (sample.archived_bytes.has_value())
    obj.emplace_back("archived_bytes", Value{Number{*sample.archived_bytes}});
  if (sample.cache_epoch.has_value())
    obj.emplace_back("cache_epoch", Value{*sample.cache_epoch});
  if (sample.cache_epoch_jump)
    obj.emplace_back("cache_epoch_jump", Value{true});
  if (sample.compaction_event)
    obj.emplace_back("compaction_event", Value{true});
  if (sample.compaction_bytes_before.has_value())
    obj.emplace_back("compaction_bytes_before",
                     Value{Number{*sample.compaction_bytes_before}});
  if (sample.compaction_bytes_after.has_value())
    obj.emplace_back("compaction_bytes_after",
                     Value{Number{*sample.compaction_bytes_after}});
  if (!std::holds_alternative<std::nullptr_t>(sample.raw_metadata.value()))
    obj.emplace_back("raw_metadata", sample.raw_metadata);
  return Value::object(std::move(obj));
}

Value to_value(const TriMetric<std::uint64_t> &metric) {
  Value::Object obj;
  obj.emplace_back("state", Value{std::string{tri_metric_state_name(metric.state)}});
  obj.emplace_back("value",
                   metric.value.has_value() ? Value{Number{*metric.value}} : Value{});
  obj.emplace_back("known_count", Value{Number{metric.known_count}});
  obj.emplace_back("missing_count", Value{Number{metric.missing_count}});
  obj.emplace_back("overflow", Value{metric.overflow});
  return Value::object(std::move(obj));
}

Value to_value(const TriMetric<double> &metric) {
  Value::Object obj;
  obj.emplace_back("state", Value{std::string{tri_metric_state_name(metric.state)}});
  obj.emplace_back(
      "value", metric.value.has_value() ? finite_double_value(*metric.value) : Value{});
  obj.emplace_back("known_count", Value{Number{metric.known_count}});
  obj.emplace_back("missing_count", Value{Number{metric.missing_count}});
  obj.emplace_back("overflow", Value{metric.overflow});
  return Value::object(std::move(obj));
}

Value to_value(const MetricsPoint &point) {
  Value::Object obj;
  obj.emplace_back("source_record_id", Value{point.source_record_id});
  obj.emplace_back("source_label", Value{point.source_label});
  obj.emplace_back("clock_domain",
                   Value{std::string{metrics_clock_domain_name(point.clock_domain)}});
  if (!point.clock_id.empty())
    obj.emplace_back("clock_id", Value{point.clock_id});
  obj.emplace_back("timestamp_ns", Value{Number{point.timestamp_ns}});
  obj.emplace_back("value", finite_double_value(point.value));
  obj.emplace_back("unit", Value{point.unit});
  if (!point.request_id.empty())
    obj.emplace_back("request_id", Value{point.request_id});
  if (!point.provider.empty())
    obj.emplace_back("provider", Value{point.provider});
  return Value::object(std::move(obj));
}

Value to_value(const MetricsSeries &series) {
  Value::Array pts;
  pts.reserve(series.points.size());
  for (const auto &pt : series.points)
    pts.push_back(to_value(pt));
  return Value::object({
      {"name", Value{series.name}},
      {"unit", Value{series.unit}},
      {"capacity", Value{Number{series.capacity}}},
      {"dropped_oldest", Value{Number{series.dropped_oldest}}},
      {"points", Value{std::move(pts)}},
  });
}

Value to_value(const MetricsSparkline &sparkline) {
  return Value::object({
      {"glyphs", Value{sparkline.glyphs}},
      {"min_value", sparkline.min_value.has_value()
                        ? finite_double_value(*sparkline.min_value)
                        : Value{}},
      {"max_value", sparkline.max_value.has_value()
                        ? finite_double_value(*sparkline.max_value)
                        : Value{}},
      {"input_count", Value{Number{sparkline.input_count}}},
      {"finite_count", Value{Number{sparkline.finite_count}}},
      {"ignored_non_finite", Value{Number{sparkline.ignored_non_finite}}},
      {"glyph_count", Value{Number{sparkline.glyph_count}}},
  });
}

Value to_value(const LatencyStats &stats) {
  return Value::object({
      {"total_ms", to_value(stats.total_ms)},
      {"min_ms",
       stats.min_ms.has_value() ? finite_double_value(*stats.min_ms) : Value{}},
      {"max_ms",
       stats.max_ms.has_value() ? finite_double_value(*stats.max_ms) : Value{}},
      {"mean_ms",
       stats.mean_ms.has_value() ? finite_double_value(*stats.mean_ms) : Value{}},
      {"p50_ms",
       stats.p50_ms.has_value() ? finite_double_value(*stats.p50_ms) : Value{}},
      {"p95_ms",
       stats.p95_ms.has_value() ? finite_double_value(*stats.p95_ms) : Value{}},
  });
}

Value to_value(const VersionedCostEstimate &estimate) {
  return Value::object({
      {"pricing_version", Value{estimate.pricing_version}},
      {"estimated_cost_usd", to_value(estimate.estimated_cost_usd)},
  });
}

Value to_value(const OperationsSummary &summary) {
  return Value::object({
      {"provider_requests", to_value(summary.provider_requests)},
      {"tool_executions", to_value(summary.tool_executions)},
      {"tool_failures", to_value(summary.tool_failures)},
      {"error_count", to_value(summary.error_count)},
      {"retry_count", to_value(summary.retry_count)},
      {"ttft_stats", to_value(summary.ttft_stats)},
      {"total_latency_stats", to_value(summary.total_latency_stats)},
      {"tool_duration_stats", to_value(summary.tool_duration_stats)},
      {"ttft_ms", to_value(summary.ttft_ms)},
      {"total_latency_ms", to_value(summary.total_latency_ms)},
      {"tool_duration_ms", to_value(summary.tool_duration_ms)},
      {"points", to_value(summary.points)},
  });
}

Value to_value(const ProviderUsageSummary &summary) {
  Value::Array estimates;
  estimates.reserve(summary.estimates_by_version.size());
  for (const auto &est : summary.estimates_by_version)
    estimates.push_back(to_value(est));
  return Value::object({
      {"provider", Value{summary.provider}},
      {"observation_count", Value{Number{summary.observation_count}}},
      {"input_tokens", to_value(summary.input_tokens)},
      {"cached_tokens", to_value(summary.cached_tokens)},
      {"cache_write_tokens", to_value(summary.cache_write_tokens)},
      {"reasoning_tokens", to_value(summary.reasoning_tokens)},
      {"output_tokens", to_value(summary.output_tokens)},
      {"cache_hit_ratio", to_value(summary.cache_hit_ratio)},
      {"observed_charge_usd", to_value(summary.observed_charge_usd)},
      {"estimated_cost_usd", to_value(summary.estimated_cost_usd)},
      {"pricing_version", Value{summary.pricing_version}},
      {"mixed_pricing_versions", Value{summary.mixed_pricing_versions}},
      {"estimates_by_version", Value{std::move(estimates)}},
  });
}

Value to_value(const UsageSummary &summary) {
  Value::Array providers;
  providers.reserve(summary.by_provider.size());
  for (const auto &prov : summary.by_provider)
    providers.push_back(to_value(prov));
  Value::Array estimates;
  estimates.reserve(summary.estimates_by_version.size());
  for (const auto &est : summary.estimates_by_version)
    estimates.push_back(to_value(est));
  return Value::object({
      {"observation_count", Value{Number{summary.observation_count}}},
      {"total_input_tokens", to_value(summary.total_input_tokens)},
      {"total_cached_tokens", to_value(summary.total_cached_tokens)},
      {"total_cache_write_tokens", to_value(summary.total_cache_write_tokens)},
      {"total_reasoning_tokens", to_value(summary.total_reasoning_tokens)},
      {"total_output_tokens", to_value(summary.total_output_tokens)},
      {"cache_hit_ratio", to_value(summary.cache_hit_ratio)},
      {"observed_charge_usd", to_value(summary.observed_charge_usd)},
      {"estimated_cost_usd", to_value(summary.estimated_cost_usd)},
      {"pricing_version", Value{summary.pricing_version}},
      {"mixed_pricing_versions", Value{summary.mixed_pricing_versions}},
      {"estimates_by_version", Value{std::move(estimates)}},
      {"by_provider", Value{std::move(providers)}},
      {"token_spend_series", to_value(summary.token_spend_series)},
      {"charge_usd_series", to_value(summary.charge_usd_series)},
      {"estimated_usd_series", to_value(summary.estimated_usd_series)},
  });
}

Value to_value(const ContextSummary &summary) {
  return Value::object({
      {"observation_count", Value{Number{summary.observation_count}}},
      {"latest_live_bytes", to_value(summary.latest_live_bytes)},
      {"latest_archived_bytes", to_value(summary.latest_archived_bytes)},
      {"peak_live_bytes", to_value(summary.peak_live_bytes)},
      {"upstream_cache_epoch_jumps", to_value(summary.upstream_cache_epoch_jumps)},
      {"compaction_events", to_value(summary.compaction_events)},
      {"compaction_bytes_reclaimed", to_value(summary.compaction_bytes_reclaimed)},
      {"last_cache_epoch", summary.last_cache_epoch.has_value()
                               ? Value{*summary.last_cache_epoch}
                               : Value{}},
      {"live_bytes_series", to_value(summary.live_bytes_series)},
      {"archived_bytes_series", to_value(summary.archived_bytes_series)},
      {"cache_epoch_jumps_series", to_value(summary.cache_epoch_jumps_series)},
      {"compaction_series", to_value(summary.compaction_series)},
  });
}

Value to_value(const DecisionCompanionSummary &summary) {
  Value::Array estimates;
  estimates.reserve(summary.estimates_by_version.size());
  for (const auto &est : summary.estimates_by_version)
    estimates.push_back(to_value(est));
  return Value::object({
      {"batch_count", to_value(summary.batch_count)},
      {"failure_count", to_value(summary.failure_count)},
      {"latency_stats", to_value(summary.latency_stats)},
      {"input_tokens", to_value(summary.input_tokens)},
      {"output_tokens", to_value(summary.output_tokens)},
      {"total_tokens", to_value(summary.total_tokens)},
      {"observed_charge_usd", to_value(summary.observed_charge_usd)},
      {"estimated_cost_usd", to_value(summary.estimated_cost_usd)},
      {"pricing_version", Value{summary.pricing_version}},
      {"mixed_pricing_versions", Value{summary.mixed_pricing_versions}},
      {"estimates_by_version", Value{std::move(estimates)}},
      {"latency_ms", to_value(summary.latency_ms)},
      {"token_spend_series", to_value(summary.token_spend_series)},
  });
}

Value to_value(const MetricsCoverage &coverage) {
  Value::Array clocks;
  clocks.reserve(coverage.clock_ids.size());
  for (const auto &c : coverage.clock_ids)
    clocks.emplace_back(c);
  Value::Array notes;
  notes.reserve(coverage.notes.size());
  for (const auto &n : coverage.notes)
    notes.emplace_back(n);
  return Value::object({
      {"records_ingested", Value{Number{coverage.records_ingested}}},
      {"records_skipped_corrupt", Value{Number{coverage.records_skipped_corrupt}}},
      {"duplicate_captures_deduped",
       Value{Number{coverage.duplicate_captures_deduped}}},
      {"conflicting_captures", Value{Number{coverage.conflicting_captures}}},
      {"missing_field_observations",
       Value{Number{coverage.missing_field_observations}}},
      {"has_utc_clock", Value{coverage.has_utc_clock}},
      {"has_monotonic_clock", Value{coverage.has_monotonic_clock}},
      {"has_unknown_clock", Value{coverage.has_unknown_clock}},
      {"clock_ids", Value{std::move(clocks)}},
      {"notes", Value{std::move(notes)}},
      {"complete_session_ledger", Value{coverage.complete_session_ledger}},
  });
}

Value to_value(const MetricsSourceRecord &record) {
  return Value::object({
      {"source_record_id", Value{record.source_record_id}},
      {"source_label", Value{record.source_label}},
      {"source_locator", Value{record.source_locator}},
      {"kind", Value{std::string{metrics_sample_kind_name(record.kind)}}},
      {"clock_domain",
       Value{std::string{metrics_clock_domain_name(record.clock_domain)}}},
      {"clock_id", Value{record.clock_id}},
      {"timestamp_ns", Value{Number{record.timestamp_ns}}},
      {"request_id", Value{record.request_id}},
      {"capture_key", Value{record.capture_key}},
      {"provider", Value{record.provider}},
      {"model", Value{record.model}},
      {"metadata", record.metadata},
  });
}

Value to_value(const MetricsSnapshot &snapshot) {
  Value::Array sources;
  sources.reserve(snapshot.source_records.size());
  for (const auto &rec : snapshot.source_records)
    sources.push_back(to_value(rec));
  return Value::object({
      {"generation", Value{Number{snapshot.generation}}},
      {"has_data", Value{snapshot.has_data}},
      {"stale", Value{snapshot.stale}},
      {"stale_reason", Value{snapshot.stale_reason}},
      {"last_refresh_error",
       snapshot.last_refresh_error.has_value()
           ? Value{std::string{error_name(snapshot.last_refresh_error->code)}}
           : Value{}},
      {"source_description", Value{snapshot.source_description}},
      {"coverage", to_value(snapshot.coverage)},
      {"operations", to_value(snapshot.operations)},
      {"usage", to_value(snapshot.usage)},
      {"context", to_value(snapshot.context)},
      {"decision_companion", to_value(snapshot.decision_companion)},
      {"source_records", Value{std::move(sources)}},
  });
}

Result<std::string> to_json(const MetricsSample &sample) {
  return dump_json(to_value(sample));
}
Result<std::string> to_json(const TriMetric<std::uint64_t> &metric) {
  return dump_json(to_value(metric));
}
Result<std::string> to_json(const TriMetric<double> &metric) {
  return dump_json(to_value(metric));
}
Result<std::string> to_json(const MetricsPoint &point) {
  return dump_json(to_value(point));
}
Result<std::string> to_json(const MetricsSeries &series) {
  return dump_json(to_value(series));
}
Result<std::string> to_json(const MetricsSparkline &sparkline) {
  return dump_json(to_value(sparkline));
}
Result<std::string> to_json(const OperationsSummary &summary) {
  return dump_json(to_value(summary));
}
Result<std::string> to_json(const UsageSummary &summary) {
  return dump_json(to_value(summary));
}
Result<std::string> to_json(const ContextSummary &summary) {
  return dump_json(to_value(summary));
}
Result<std::string> to_json(const DecisionCompanionSummary &summary) {
  return dump_json(to_value(summary));
}
Result<std::string> to_json(const MetricsSnapshot &snapshot) {
  return dump_json(to_value(snapshot));
}

} // namespace blackbird
