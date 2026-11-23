#include "blackbird/json.hpp"
#include "blackbird/metrics_consumer.hpp"
#include "blackbird/observations.hpp"

#include <array>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

const char *g_stage = "startup";

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

template <class T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{context} + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
  return std::move(result).value();
}

void must_ok(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{context} + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
}

bool near(double actual, double expected, double eps = 1e-9) {
  return std::fabs(actual - expected) <= eps;
}

void write_text_file(const std::filesystem::path &path, std::string_view content) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  check(static_cast<bool>(out), "failed to open file for writing");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  out.flush();
  check(static_cast<bool>(out), "failed to write file");
}

void test_tri_metric_states() {
  g_stage = "tri_metric_states";

  // 1. Unknown: never coerced to 0.
  TriMetric<std::uint64_t> u_unknown;
  check(u_unknown.is_unknown(), "default TriMetric must be unknown");
  check(!u_unknown.has_value(), "unknown TriMetric must have nullopt value");
  check(!u_unknown.is_zero(), "unknown must not equal zero");
  check(tri_metric_state_name(u_unknown.state) == "unknown", "state name unknown");

  // Missing observations alone remain unknown, never 0.
  u_unknown.record_missing();
  u_unknown.record_missing();
  check(u_unknown.is_unknown(), "missing-only metric must stay unknown");
  check(!u_unknown.has_value(), "missing-only metric must not coerce to 0");
  check(u_unknown.missing_count == 2, "missing_count mismatch");

  // 2. Observed zero: strictly distinct from unknown.
  TriMetric<std::uint64_t> u_zero;
  u_zero.record_known(0);
  check(u_zero.is_zero(), "observed 0 must be zero state");
  check(u_zero.value.has_value() && *u_zero.value == 0, "observed 0 value mismatch");
  check(u_zero.known_count == 1 && u_zero.missing_count == 0, "zero counts mismatch");
  u_zero.record_known(0);
  check(u_zero.is_zero() && u_zero.known_count == 2, "two zeros stay zero");

  // 3. Complete: all observations known and non-zero.
  TriMetric<std::uint64_t> u_complete;
  u_complete.record_known(120);
  u_complete.record_known(80);
  check(u_complete.is_complete(), "all-known non-zero must be complete");
  check(u_complete.value.has_value() && *u_complete.value == 200,
        "complete total mismatch");

  // 4. Known subtotal: some observations known, some missing (even if subtotal is 0!).
  TriMetric<std::uint64_t> u_sub = u_zero;
  u_sub.record_missing();
  check(u_sub.is_known_subtotal(),
        "0 known + missing must be known_subtotal, not zero");
  check(u_sub.value.has_value() && *u_sub.value == 0, "subtotal value mismatch");
  check(u_sub.known_count == 2 && u_sub.missing_count == 1, "subtotal counts mismatch");

  u_sub.record_known(45);
  check(u_sub.is_known_subtotal(), "subtotal + known remains known_subtotal");
  check(u_sub.value.has_value() && *u_sub.value == 45, "subtotal sum mismatch");

  // Floating-point TriMetric rejects NaN/Inf/negative into missing rather than
  // poisoning.
  TriMetric<double> d_metric;
  d_metric.record_known(std::numeric_limits<double>::quiet_NaN());
  d_metric.record_known(std::numeric_limits<double>::infinity());
  d_metric.record_known(-1.0);
  check(d_metric.is_unknown() && !d_metric.has_value() && d_metric.missing_count == 3,
        "non-finite/negative double samples must stay unknown");
  d_metric.record_known(0.25);
  check(d_metric.is_known_subtotal() && d_metric.value.has_value() &&
            near(*d_metric.value, 0.25),
        "finite double after missing must be known_subtotal");

  // Integer overflow degrades cleanly to known_subtotal with overflow=true.
  TriMetric<std::uint64_t> u_ovf;
  u_ovf.record_known(std::numeric_limits<std::uint64_t>::max() - 5);
  u_ovf.record_known(10);
  check(u_ovf.overflow && u_ovf.is_known_subtotal(),
        "uint64 overflow must flag overflow and known_subtotal");

  // End-to-end TriMetric verification through MetricsConsumer UsageSummary.
  MetricsConsumer consumer;
  MetricsSample s1;
  s1.kind = MetricsSampleKind::provider_response;
  s1.source_record_id = "rec-tri-1";
  s1.provider = "openai";
  s1.input_tokens = 1000;
  s1.cached_tokens = 0; // Explicitly observed zero cache hits.
  s1.output_tokens = 250;
  // reasoning_tokens left absent (unknown).
  s1.succeeded = true;
  must_ok(consumer.ingest(s1), "ingest s1");

  const auto &snap1 = consumer.snapshot();
  check(snap1.usage.total_input_tokens.is_complete() &&
            snap1.usage.total_input_tokens.value == 1000,
        "s1 input complete");
  check(snap1.usage.total_cached_tokens.is_zero() &&
            snap1.usage.total_cached_tokens.value == 0,
        "s1 cached zero");
  check(snap1.usage.cache_hit_ratio.is_zero() &&
            snap1.usage.cache_hit_ratio.value.has_value() &&
            near(*snap1.usage.cache_hit_ratio.value, 0.0),
        "s1 cache_hit_ratio zero when input > 0 and cached == 0");
  check(snap1.usage.total_reasoning_tokens.is_unknown() &&
            !snap1.usage.total_reasoning_tokens.has_value(),
        "s1 reasoning must remain unknown");
  check(snap1.operations.error_count.is_zero() &&
            snap1.operations.error_count.value == 0,
        "s1 error_count observed zero");

  // Add second sample with missing output_tokens & missing cached_tokens.
  MetricsSample s2;
  s2.kind = MetricsSampleKind::provider_response;
  s2.source_record_id = "rec-tri-2";
  s2.provider = "openai";
  s2.input_tokens = 500;
  // cached_tokens and output_tokens absent!
  must_ok(consumer.ingest(s2), "ingest s2");

  const auto &snap2 = consumer.snapshot();
  check(snap2.usage.total_input_tokens.is_complete() &&
            snap2.usage.total_input_tokens.value == 1500,
        "s2 input remains complete");
  check(snap2.usage.total_output_tokens.is_known_subtotal() &&
            snap2.usage.total_output_tokens.value == 250 &&
            snap2.usage.total_output_tokens.missing_count == 1,
        "s2 output becomes known_subtotal");
  check(snap2.usage.total_cached_tokens.is_known_subtotal() &&
            snap2.usage.total_cached_tokens.value == 0,
        "s2 cached becomes known_subtotal");
  check(snap2.usage.cache_hit_ratio.is_known_subtotal(),
        "s2 cache_hit_ratio becomes known_subtotal");
  check(snap2.usage.total_reasoning_tokens.is_unknown(),
        "s2 reasoning remains unknown");
}

void test_duplicate_capture_dedup() {
  g_stage = "duplicate_capture_dedup";

  MetricsConsumer consumer;

  MetricsSample resp;
  resp.kind = MetricsSampleKind::provider_response;
  resp.source_record_id = "cap-1";
  resp.source_label = "provider.response";
  resp.clock_domain = MetricsClockDomain::utc_ns;
  resp.timestamp_ns = 1700000001000000000LL;
  resp.request_id = "req-dup-42";
  resp.capture_key = "http-body-v1";
  resp.provider = "anthropic";
  resp.model = "claude-sonnet";
  resp.ttft_ms = 125.0;
  resp.total_latency_ms = 640.0;
  resp.succeeded = true;
  resp.input_tokens = 2000;
  resp.cached_tokens = 1500;
  resp.output_tokens = 400;
  resp.input_includes_cache = false;
  resp.observed_charge_usd = 0.0125;
  resp.estimated_usd = 0.0130;
  resp.pricing_version = "2026-10-15-list";

  must_ok(consumer.ingest(resp), "ingest first capture");

  // Feed identical (request_id, capture_key) again with a different source_record_id.
  MetricsSample dup = resp;
  dup.source_record_id = "cap-2-retry-read";
  must_ok(consumer.ingest(dup), "ingest duplicate capture");

  // Feed conflicting duplicate capture for same (request_id, capture_key).
  MetricsSample conflict = resp;
  conflict.source_record_id = "cap-3-conflict";
  conflict.input_tokens = 9999;
  must_ok(consumer.ingest(conflict), "ingest conflicting duplicate capture");

  // Feed another capture with same request_id but empty capture_key twice.
  MetricsSample empty_key = resp;
  empty_key.source_record_id = "cap-4";
  empty_key.request_id = "req-dup-99";
  empty_key.capture_key = "";
  empty_key.input_tokens = 500;
  empty_key.cached_tokens = 0;
  empty_key.output_tokens = 100;
  empty_key.input_includes_cache = true;
  empty_key.observed_charge_usd = 0.0025;
  empty_key.estimated_usd = 0.0030;
  must_ok(consumer.ingest(empty_key), "ingest req-dup-99 first");
  empty_key.source_record_id = "cap-5";
  must_ok(consumer.ingest(empty_key), "ingest req-dup-99 duplicate");

  const auto &snap = consumer.snapshot();
  check(snap.usage.observation_count == 2,
        "duplicate captures must not increment observation_count");
  check(snap.operations.provider_requests.value == 2,
        "duplicate captures must not double-count provider_requests");
  check(snap.usage.total_input_tokens.is_complete() &&
            snap.usage.total_input_tokens.value == 2500,
        "tokens must be counted once per (request_id, capture_key)");
  check(snap.usage.total_output_tokens.is_complete() &&
            snap.usage.total_output_tokens.value == 500,
        "output tokens must be counted once");
  check(snap.usage.observed_charge_usd.value.has_value() &&
            near(*snap.usage.observed_charge_usd.value, 0.0150),
        "observed charge must not be double-counted");
  check(snap.usage.estimated_cost_usd.value.has_value() &&
            near(*snap.usage.estimated_cost_usd.value, 0.0160),
        "estimated cost must not be double-counted");
  check(snap.coverage.duplicate_captures_deduped == 3,
        "expected 3 deduped duplicate captures");
  check(snap.coverage.conflicting_captures == 1,
        "expected 1 conflicting capture flagged");
}

void test_charge_vs_versioned_estimate() {
  g_stage = "charge_vs_versioned_estimate";

  MetricsConsumerConfig cfg;
  cfg.default_pricing_version = "2026-10-15-v1";
  cfg.pricing_rules.push_back(UsagePrice{
      "2026-10-15-v1",
      "openai",
      "gpt-5",
      "",
      2.0,  // $2 / 1M input
      10.0, // $10 / 1M output
      0.5,  // $0.5 / 1M cached read
      std::nullopt,
  });

  MetricsConsumer consumer(cfg);

  // Sample 1: observed provider charge ONLY (no estimate supplied, provider not in
  // rules).
  MetricsSample s1;
  s1.kind = MetricsSampleKind::provider_response;
  s1.source_record_id = "cost-1";
  s1.request_id = "req-cost-1";
  s1.provider = "openrouter";
  s1.model = "claude-opus";
  s1.input_tokens = 1000;
  s1.output_tokens = 500;
  s1.observed_charge_usd = 0.042;
  must_ok(consumer.ingest(s1), "ingest charge-only sample");

  // Sample 2: versioned estimate ONLY (computed from pricing_rules, no observed
  // charge).
  MetricsSample s2;
  s2.kind = MetricsSampleKind::provider_response;
  s2.source_record_id = "cost-2";
  s2.request_id = "req-cost-2";
  s2.provider = "openai";
  s2.model = "gpt-5";
  s2.input_tokens = 1000000; // 500k non-cached ($1.00) + 500k cached ($0.25)
  s2.cached_tokens = 500000;
  s2.output_tokens = 100000; // $1.00 -> total estimate = $2.25
  s2.input_includes_cache = true;
  must_ok(consumer.ingest(s2), "ingest estimate-only sample");

  // Sample 3: explicit untagged estimate (missing pricing_version) must NOT pollute
  // estimate.
  MetricsSample s3;
  s3.kind = MetricsSampleKind::provider_response;
  s3.source_record_id = "cost-3";
  s3.request_id = "req-cost-3";
  s3.provider = "anthropic";
  s3.model = "claude-sonnet";
  s3.estimated_usd = 0.99; // pricing_version intentionally empty!
  must_ok(consumer.ingest(s3), "ingest untagged estimate sample");

  const auto &snap = consumer.snapshot();
  check(snap.usage.observed_charge_usd.is_known_subtotal(),
        "observed charge must be known_subtotal (1 known, 2 missing)");
  check(snap.usage.observed_charge_usd.value.has_value() &&
            near(*snap.usage.observed_charge_usd.value, 0.042),
        "observed charge must never include estimates");

  check(
      snap.usage.estimated_cost_usd.is_known_subtotal(),
      "estimated cost must be known_subtotal (1 valid versioned, 2 missing/untagged)");
  check(snap.usage.estimated_cost_usd.value.has_value() &&
            near(*snap.usage.estimated_cost_usd.value, 2.25),
        "estimated cost calculation mismatch");
  check(snap.usage.pricing_version == "2026-10-15-v1", "pricing_version mismatch");
  check(snap.usage.estimates_by_version.size() == 1 &&
            snap.usage.estimates_by_version[0].pricing_version == "2026-10-15-v1",
        "estimates_by_version mismatch");
  check(snap.coverage.missing_field_observations == 1,
        "untagged estimate must record missing_field_observations");

  // Per-provider breakdown stays strictly separated too.
  check(snap.usage.by_provider.size() == 3, "expected 3 providers");
  for (const auto &prov : snap.usage.by_provider) {
    if (prov.provider == "openrouter") {
      check(prov.observed_charge_usd.is_complete() &&
                prov.observed_charge_usd.value.has_value() &&
                near(*prov.observed_charge_usd.value, 0.042),
            "openrouter observed_charge_usd mismatch");
      check(prov.estimated_cost_usd.is_unknown(),
            "openrouter estimated_cost_usd must stay unknown");
    } else if (prov.provider == "openai") {
      check(prov.observed_charge_usd.is_unknown(),
            "openai observed_charge_usd must stay unknown");
      check(prov.estimated_cost_usd.is_complete() &&
                prov.estimated_cost_usd.value.has_value() &&
                near(*prov.estimated_cost_usd.value, 2.25) &&
                prov.pricing_version == "2026-10-15-v1",
            "openai estimated_cost_usd mismatch");
      check(prov.cache_hit_ratio.is_complete() &&
                prov.cache_hit_ratio.value.has_value() &&
                near(*prov.cache_hit_ratio.value, 0.5),
            "openai cache_hit_ratio must be 0.5");
    }
  }
}

void test_clock_domain_and_source_linkage() {
  g_stage = "clock_domain_and_source_linkage";

  MetricsConsumerConfig cfg;
  cfg.series_capacity = 3; // Exercise bounded ring eviction too!
  MetricsConsumer consumer(cfg);

  // Mix UTC and monotonic clock domains across all 4 summary families.
  MetricsSample op1;
  op1.kind = MetricsSampleKind::provider_response;
  op1.source_record_id = "journalA:10";
  op1.source_label = "provider.ttft";
  op1.source_locator = "run-1#journalA:10";
  op1.clock_domain = MetricsClockDomain::monotonic_ns;
  op1.clock_id = "clk-host-a";
  op1.timestamp_ns = 1000000;
  op1.request_id = "req-clk-1";
  op1.provider = "openai";
  op1.model = "gpt-5";
  op1.ttft_ms = 42.5;
  op1.total_latency_ms = 310.0;
  op1.succeeded = true;
  op1.retries = 0;
  op1.raw_metadata = Value::object({{"route", Value{"responses"}}});
  must_ok(consumer.ingest(op1), "ingest op1");

  MetricsSample tool1;
  tool1.kind = MetricsSampleKind::tool_execution;
  tool1.source_record_id = "journalA:11";
  tool1.source_label = "tool.exec";
  tool1.source_locator = "run-1#journalA:11";
  tool1.clock_domain = MetricsClockDomain::utc_ns;
  tool1.clock_id = "clk-host-b";
  tool1.timestamp_ns = 1760000000000000000LL;
  tool1.tool_name = "read_file";
  tool1.tool_duration_ms = 14.2;
  tool1.succeeded = true;
  must_ok(consumer.ingest(tool1), "ingest tool1");

  MetricsSample ctx1;
  ctx1.kind = MetricsSampleKind::context_snapshot;
  ctx1.source_record_id = "journalA:12";
  ctx1.source_label = "context.state";
  ctx1.clock_domain = MetricsClockDomain::utc_ns;
  ctx1.clock_id = "clk-host-b";
  ctx1.timestamp_ns = 1760000001000000000LL;
  ctx1.live_bytes = 64000;
  ctx1.archived_bytes = 12000;
  ctx1.cache_epoch = "epoch-1";
  must_ok(consumer.ingest(ctx1), "ingest ctx1");

  MetricsSample ctx2;
  ctx2.kind = MetricsSampleKind::context_snapshot;
  ctx2.source_record_id = "journalA:13";
  ctx2.source_label = "context.compact";
  ctx2.clock_domain = MetricsClockDomain::utc_ns;
  ctx2.clock_id = "clk-host-b";
  ctx2.timestamp_ns = 1760000002000000000LL;
  ctx2.live_bytes = 32000;
  ctx2.archived_bytes = 44000;
  ctx2.cache_epoch = "epoch-2"; // Automatic cache epoch jump detection!
  ctx2.compaction_event = true;
  ctx2.compaction_bytes_before = 64000;
  ctx2.compaction_bytes_after = 32000;
  must_ok(consumer.ingest(ctx2), "ingest ctx2");

  MetricsSample dec1;
  dec1.kind = MetricsSampleKind::decision_batch;
  dec1.source_record_id = "journalA:14";
  dec1.source_label = "jev.batch";
  dec1.clock_domain = MetricsClockDomain::monotonic_ns;
  dec1.clock_id = "clk-host-a";
  dec1.timestamp_ns = 2500000;
  dec1.request_id = "jev-batch-1";
  dec1.provider = "jev";
  dec1.total_latency_ms = 88.0;
  dec1.input_tokens = 300;
  dec1.output_tokens = 40;
  dec1.succeeded = false;
  must_ok(consumer.ingest(dec1), "ingest dec1");

  const auto &snap = consumer.snapshot();
  check(snap.coverage.has_utc_clock && snap.coverage.has_monotonic_clock &&
            !snap.coverage.has_unknown_clock,
        "clock domain flags mismatch");
  check(snap.coverage.clock_ids.size() == 2, "expected 2 distinct clock_ids");

  // Verify selecting points recovers exact source records and preserves clock domains.
  check(snap.operations.ttft_ms.points.size() == 1, "expected 1 ttft point");
  const auto &ttft_pt = snap.operations.ttft_ms.points[0];
  check(ttft_pt.clock_domain == MetricsClockDomain::monotonic_ns &&
            ttft_pt.timestamp_ns == 1000000 &&
            ttft_pt.source_record_id == "journalA:10",
        "ttft point clock/source linkage mismatch");
  const auto *ttft_src = snap.find_source(ttft_pt.source_record_id);
  check(ttft_src != nullptr && ttft_src->source_locator == "run-1#journalA:10" &&
            ttft_src->request_id == "req-clk-1" && ttft_src->model == "gpt-5",
        "failed to recover exact source record from ttft point");

  check(snap.operations.tool_duration_ms.points.size() == 1, "expected 1 tool point");
  const auto &tool_pt = snap.operations.tool_duration_ms.points[0];
  check(tool_pt.clock_domain == MetricsClockDomain::utc_ns &&
            tool_pt.timestamp_ns == 1760000000000000000LL,
        "tool point clock domain mismatch");
  const auto *tool_src = consumer.find_source(tool_pt.source_record_id);
  check(tool_src != nullptr && tool_src->source_label == "tool.exec",
        "failed to recover tool source record");

  // Verify ContextSummary fields & source recovery.
  check(snap.context.latest_live_bytes.is_complete() &&
            snap.context.latest_live_bytes.value == 32000,
        "latest_live_bytes mismatch");
  check(snap.context.peak_live_bytes.is_complete() &&
            snap.context.peak_live_bytes.value == 64000,
        "peak_live_bytes mismatch");
  check(snap.context.upstream_cache_epoch_jumps.is_complete() &&
            snap.context.upstream_cache_epoch_jumps.value == 1,
        "expected 1 upstream cache epoch jump");
  check(snap.context.compaction_events.is_complete() &&
            snap.context.compaction_events.value == 1,
        "expected 1 compaction event");
  check(snap.context.compaction_bytes_reclaimed.is_complete() &&
            snap.context.compaction_bytes_reclaimed.value == 32000,
        "compaction reclaimed bytes mismatch");
  check(snap.context.compaction_series.points.size() == 1,
        "expected 1 compaction series point");
  check(snap.find_source(snap.context.compaction_series.points[0].source_record_id) !=
            nullptr,
        "compaction point must recover source");

  // Verify DecisionCompanionSummary fields & source recovery.
  check(snap.decision_companion.batch_count.is_complete() &&
            snap.decision_companion.batch_count.value == 1,
        "decision batch_count mismatch");
  check(snap.decision_companion.failure_count.is_complete() &&
            snap.decision_companion.failure_count.value == 1,
        "decision failure_count mismatch");
  check(snap.decision_companion.total_tokens.is_complete() &&
            snap.decision_companion.total_tokens.value == 340,
        "decision total_tokens mismatch");
  check(snap.decision_companion.latency_ms.points.size() == 1,
        "expected 1 decision latency point");
  const auto *dec_src =
      snap.find_source(snap.decision_companion.latency_ms.points[0].source_record_id);
  check(dec_src != nullptr && dec_src->provider == "jev" &&
            dec_src->clock_domain == MetricsClockDomain::monotonic_ns,
        "decision point must recover exact source");

  // Verify bounded ring eviction (series_capacity == 3).
  for (int i = 0; i < 4; ++i) {
    MetricsSample extra;
    extra.kind = MetricsSampleKind::tool_execution;
    extra.source_record_id = "ring-" + std::to_string(i);
    extra.tool_duration_ms = static_cast<double>(10 + i);
    extra.succeeded = true;
    must_ok(consumer.ingest(extra), "ingest ring sample");
  }
  const auto &ring_snap = consumer.snapshot();
  check(ring_snap.operations.tool_duration_ms.points.size() == 3,
        "bounded series exceeded capacity");
  check(ring_snap.operations.tool_duration_ms.dropped_oldest == 2,
        "bounded series dropped_oldest count mismatch");
  check(ring_snap.operations.tool_duration_ms.points.front().source_record_id ==
                "ring-1" &&
            ring_snap.operations.tool_duration_ms.points.back().source_record_id ==
                "ring-3",
        "bounded series did not evict oldest FIFO");
  for (const auto &pt : ring_snap.operations.tool_duration_ms.points) {
    check(ring_snap.find_source(pt.source_record_id) != nullptr,
          "every retained ring point must recover its source");
  }
}

void test_stale_last_good_retention(const std::filesystem::path &base) {
  g_stage = "stale_last_good_retention";

  const auto jsonl_path = base / "telemetry.jsonl";
  MetricsSample s1;
  s1.kind = MetricsSampleKind::provider_response;
  s1.source_record_id = "file-rec-1";
  s1.source_label = "provider.response";
  s1.clock_domain = MetricsClockDomain::utc_ns;
  s1.timestamp_ns = 1760000100000000000LL;
  s1.request_id = "req-stale-1";
  s1.provider = "anthropic";
  s1.ttft_ms = 55.0;
  s1.total_latency_ms = 220.0;
  s1.input_tokens = 1200;
  s1.cached_tokens = 600;
  s1.output_tokens = 300;
  s1.observed_charge_usd = 0.008;
  s1.succeeded = true;

  const std::string line1 = must(to_json(s1), "serialize s1");
  write_text_file(jsonl_path, line1 + "\n");

  auto consumer = MetricsConsumer::from_jsonl_file(jsonl_path);
  must_ok(consumer.refresh(), "initial valid refresh");

  const auto good_gen = consumer.snapshot().generation;
  check(!consumer.snapshot().stale, "initial snapshot must not be stale");
  check(consumer.snapshot().stale_reason.empty(), "initial stale_reason must be empty");
  check(consumer.snapshot().has_data, "initial snapshot must have data");
  check(consumer.snapshot().operations.ttft_ms.points.size() == 1,
        "initial ttft series missing");
  check(consumer.snapshot().usage.total_input_tokens.value == 1200,
        "initial token count mismatch");

  // 1. Corrupt the JSONL source and refresh -> previous snapshot stays intact,
  // stale=true.
  write_text_file(jsonl_path, line1 + "\n{corrupt_json_truncated\n");
  const auto corrupt_res = consumer.refresh();
  check(!corrupt_res.has_value() && corrupt_res.error().code == ErrorCode::corrupt,
        "corrupt source refresh must fail with corrupt");
  check(consumer.snapshot().stale, "corrupt refresh must flip stale=true");
  check(!consumer.snapshot().stale_reason.empty(),
        "corrupt refresh must set explicit stale_reason");
  check(consumer.snapshot().generation == good_gen,
        "stale retention must keep last good generation");
  check(consumer.snapshot().operations.ttft_ms.points.size() == 1 &&
            near(consumer.snapshot().operations.ttft_ms.points[0].value, 55.0),
        "stale retention must preserve previous series points");
  check(consumer.snapshot().usage.total_input_tokens.value == 1200,
        "stale retention must preserve previous summaries");
  check(consumer.find_source("file-rec-1") != nullptr,
        "stale retention must preserve source linkage");

  // 2. Remove the file completely and refresh -> previous snapshot STILL intact,
  // stale=true.
  std::filesystem::remove(jsonl_path);
  const auto missing_res = consumer.refresh();
  check(!missing_res.has_value() && missing_res.error().code == ErrorCode::io,
        "missing source refresh must fail with io");
  check(consumer.snapshot().stale, "missing refresh must remain stale=true");
  check(consumer.snapshot().last_refresh_error.has_value() &&
            consumer.snapshot().last_refresh_error->code == ErrorCode::io,
        "missing refresh error mismatch");
  check(consumer.snapshot().operations.ttft_ms.points.size() == 1,
        "missing source must not blank view");

  // 3. Reject symlink source cleanly while keeping stale last-good snapshot intact.
  const auto symlink_path = base / "symlink.jsonl";
  const auto target_path = base / "target.jsonl";
  write_text_file(target_path, line1 + "\n");
  check(::symlink(target_path.c_str(), symlink_path.c_str()) == 0,
        "failed to create symlink");
  auto sym_consumer = MetricsConsumer::from_jsonl_file(symlink_path);
  const auto sym_res = sym_consumer.refresh();
  check(!sym_res.has_value() && sym_res.error().code == ErrorCode::io,
        "symlink JSONL source must be rejected");
  check(sym_consumer.snapshot().stale, "failed symlink refresh must mark stale");

  // 4. Restore valid source with an additional sample -> recovers cleanly, stale=false!
  MetricsSample s2 = s1;
  s2.source_record_id = "file-rec-2";
  s2.request_id = "req-stale-2";
  s2.ttft_ms = 65.0;
  s2.input_tokens = 800;
  const std::string line2 = must(to_json(s2), "serialize s2");
  write_text_file(jsonl_path, line1 + "\n" + line2 + "\n");

  must_ok(consumer.refresh(), "recovery refresh");
  check(!consumer.snapshot().stale, "recovered snapshot must clear stale flag");
  check(consumer.snapshot().stale_reason.empty(),
        "recovered snapshot must clear stale_reason");
  check(consumer.snapshot().generation > good_gen,
        "recovered snapshot must advance generation");
  check(consumer.snapshot().operations.ttft_ms.points.size() == 2,
        "recovered snapshot must have 2 points");
  check(consumer.snapshot().usage.total_input_tokens.value == 2000,
        "recovered token total mismatch");
}

template <class T> T make_test_id(unsigned char n) {
  IdentityBytes b{};
  b[0] = std::byte{n};
  return unwrap(T::from_bytes(b));
}

void test_audit_log_readonly_and_sample_source(const std::filesystem::path &base) {
  g_stage = "audit_log_readonly_and_sample_source";

  const auto audit_dir = base / "audit";
  std::error_code ec;
  std::filesystem::create_directories(audit_dir, ec);
  check(::chmod(audit_dir.c_str(), mode_t{0700}) == 0, "chmod audit_dir 0700");

  JournalHeader header{make_test_id<EnvironmentId>(1),
                       make_test_id<AuditStreamId>(2),
                       3,
                       {1024 * 1024, 4 * 1024 * 1024},
                       std::nullopt};
  JournalCapacity capacity{32 * 1024 * 1024, 4096};

  auto root = unwrap(
      RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                NativeJournalDirectory::open(audit_dir.string()))),
                            "metrics-audit", header, capacity));
  AuditLog log{*root};

  // Record a structured metrics.sample and an Observations variable.sample.
  MetricsSample sample;
  sample.kind = MetricsSampleKind::provider_response;
  sample.request_id = "audit-req-1";
  sample.provider = "openai";
  sample.model = "gpt-5";
  sample.clock_domain = MetricsClockDomain::utc_ns;
  sample.timestamp_ns = 1760000200000000000LL;
  sample.ttft_ms = 33.0;
  sample.total_latency_ms = 140.0;
  sample.input_tokens = 900;
  sample.output_tokens = 100;
  sample.observed_charge_usd = 0.004;
  sample.succeeded = true;
  Value packet = to_value(sample);
  packet.object().emplace_back("label", Value{"metrics.sample"});
  log.record(ApplicationChannel::log, packet);

  Observations obs(
      log, [] { return ObservationTime{1760000205000000000LL, 55000000LL, 100}; });
  obs.sample("context.live_bytes", Value{Number{std::uint64_t{48000}}},
             Value::object({{"kind", Value{"context_store"}}}));

  const std::size_t facts_before = root->fact_count();
  auto consumer = MetricsConsumer::from_audit_log(log);
  must_ok(consumer.refresh(), "refresh from audit log");
  // Strict read-only invariant: consuming AuditLog must never append facts.
  check(root->fact_count() == facts_before,
        "MetricsConsumer must not write facts to AuditLog");

  const auto &snap = consumer.snapshot();
  check(!snap.stale && snap.has_data, "audit snapshot must have fresh data");
  check(snap.operations.provider_requests.value == 1,
        "audit provider_requests mismatch");
  check(snap.usage.total_input_tokens.value == 900, "audit input_tokens mismatch");
  check(snap.context.latest_live_bytes.is_complete() &&
            snap.context.latest_live_bytes.value == 48000,
        "audit variable.sample context.live_bytes mismatch");
  check(snap.context.live_bytes_series.points.size() == 1,
        "audit context point missing");
  const auto &ctx_pt = snap.context.live_bytes_series.points[0];
  check(ctx_pt.clock_domain == MetricsClockDomain::utc_ns &&
            ctx_pt.timestamp_ns == 1760000205000000000LL,
        "audit variable.sample clock domain mismatch");
  check(snap.find_source(ctx_pt.source_record_id) != nullptr,
        "audit point must recover source record");

  // Also test custom sample_source stale retention on transient callback failure.
  bool fail_next = false;
  auto custom = MetricsConsumer::from_sample_source(
      [&]() -> Result<std::vector<MetricsSample>> {
        if (fail_next)
          return Result<std::vector<MetricsSample>>::failure(
              {ErrorCode::audit_unavailable});
        return Result<std::vector<MetricsSample>>::success({sample});
      },
      "in-memory-test");
  must_ok(custom.refresh(), "custom initial refresh");
  check(!custom.snapshot().stale &&
            custom.snapshot().usage.total_input_tokens.value == 900,
        "custom refresh value mismatch");
  fail_next = true;
  const auto failed = custom.refresh();
  check(!failed.has_value() && failed.error().code == ErrorCode::audit_unavailable,
        "custom failure error mismatch");
  check(custom.snapshot().stale &&
            custom.snapshot().usage.total_input_tokens.value == 900,
        "custom failure must retain last-good snapshot marked stale");
}

void test_sparkline_edge_cases() {
  g_stage = "sparkline_edge_cases";

  // 1. Empty input.
  {
    const std::vector<double> empty;
    const auto sp = metrics_sparkline(empty, 8);
    check(sp.glyphs.empty() && sp.glyph_count == 0, "empty sparkline must be empty");
    check(!sp.min_value.has_value() && !sp.max_value.has_value(),
          "empty sparkline min/max must be nullopt");
    check(sp.input_count == 0 && sp.finite_count == 0 && sp.ignored_non_finite == 0,
          "empty sparkline counts mismatch");
  }

  // 2. Constant values.
  {
    const std::array<double, 4> constant = {42.0, 42.0, 42.0, 42.0};
    const auto sp = metrics_sparkline(constant, 8);
    check(sp.glyph_count == 4, "constant sparkline glyph count mismatch");
    check(sp.glyphs == "\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84",
          "constant sparkline must emit uniform middle bars");
    check(sp.min_value.has_value() && near(*sp.min_value, 42.0) &&
              sp.max_value.has_value() && near(*sp.max_value, 42.0),
          "constant sparkline min/max mismatch");
  }

  // 3. Monotonic ramp 0..7 -> exact 8 Unicode levels ▁▂▃▄▅▆▇█.
  {
    const std::array<double, 8> ramp = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};
    const auto sp = metrics_sparkline(ramp, 8);
    check(sp.glyph_count == 8, "ramp glyph_count mismatch");
    check(sp.glyphs == "\xE2\x96\x81\xE2\x96\x82\xE2\x96\x83\xE2\x96\x84"
                       "\xE2\x96\x85\xE2\x96\x86\xE2\x96\x87\xE2\x96\x88",
          "monotonic ramp glyphs mismatch");
    check(sp.min_value.has_value() && near(*sp.min_value, 0.0) &&
              sp.max_value.has_value() && near(*sp.max_value, 7.0),
          "ramp min/max mismatch");

    // Downsampling to width 4 keeps exact min/max metadata and bounds glyph count.
    const auto narrow = metrics_sparkline(ramp, 4);
    check(narrow.glyph_count == 4 && narrow.glyphs.size() == 12,
          "downsampled sparkline width mismatch");
    check(narrow.min_value.has_value() && near(*narrow.min_value, 0.0) &&
              narrow.max_value.has_value() && near(*narrow.max_value, 7.0),
          "downsampled sparkline min/max mismatch");
  }

  // 4. NaN / +Inf / -Inf ignored cleanly.
  {
    const double nan = std::numeric_limits<double>::quiet_NaN();
    const double inf = std::numeric_limits<double>::infinity();
    const std::array<double, 6> dirty = {nan, 10.0, inf, 20.0, -inf, 30.0};
    const auto sp = metrics_sparkline(dirty, 8);
    check(sp.input_count == 6 && sp.finite_count == 3 && sp.ignored_non_finite == 3,
          "non-finite counts mismatch");
    check(sp.glyph_count == 3, "non-finite glyph count mismatch");
    check(sp.min_value.has_value() && near(*sp.min_value, 10.0) &&
              sp.max_value.has_value() && near(*sp.max_value, 30.0),
          "non-finite min/max mismatch");
    check(sp.glyphs == "\xE2\x96\x81\xE2\x96\x85\xE2\x96\x88" ||
              sp.glyphs == "\xE2\x96\x81\xE2\x96\x84\xE2\x96\x88",
          "non-finite ramp glyphs mismatch");

    // All non-finite -> empty glyphs, nullopt min/max.
    const std::array<double, 3> all_bad = {nan, inf, -inf};
    const auto bad_sp = metrics_sparkline(all_bad, 8);
    check(bad_sp.glyphs.empty() && bad_sp.glyph_count == 0 &&
              bad_sp.ignored_non_finite == 3 && !bad_sp.min_value.has_value() &&
              !bad_sp.max_value.has_value(),
          "all non-finite sparkline must produce empty glyphs and nullopt min/max");
  }

  // 5. Width == 0 preserves min/max metadata with empty glyphs.
  {
    const std::array<double, 2> vals = {3.0, 9.0};
    const auto sp = metrics_sparkline(vals, 0);
    check(sp.glyphs.empty() && sp.glyph_count == 0 && sp.finite_count == 2 &&
              sp.min_value.has_value() && near(*sp.min_value, 3.0) &&
              sp.max_value.has_value() && near(*sp.max_value, 9.0),
          "width=0 sparkline metadata mismatch");
  }
}

void test_json_export_and_token_usage_adapter() {
  g_stage = "json_export_and_token_usage_adapter";

  TokenUsageReport report;
  UsageObservation obs;
  obs.actor = UsageActor::main;
  obs.scope = UsageScope::aggregate;
  obs.request.lane[0] = std::byte{0xAB};
  obs.request.ordinal = 7;
  obs.provider = "anthropic";
  obs.actual_model = "claude-sonnet";
  obs.counters.input = 400;
  obs.counters.output = 100;
  obs.counters.cache_read = 600;
  obs.counters.input_includes_cache = false;
  obs.observed_cost_usd = Number{"0.0055"};
  obs.http_status = 200;
  report.observations.push_back(obs);

  // Model-alternative scope must be excluded from aggregate totals!
  UsageObservation alt = obs;
  alt.scope = UsageScope::model_alternative;
  alt.counters.input = 99999;
  report.observations.push_back(alt);

  MetricsConsumer consumer;
  must_ok(consumer.ingest_token_usage(report), "ingest token usage report");
  const auto &snap = consumer.snapshot();
  check(snap.usage.observation_count == 1,
        "model_alternative scope must not be added to aggregate totals");
  check(snap.usage.total_input_tokens.is_complete() &&
            snap.usage.total_input_tokens.value == 400,
        "token_usage input mismatch");
  check(snap.usage.cache_hit_ratio.is_complete() &&
            snap.usage.cache_hit_ratio.value.has_value() &&
            near(*snap.usage.cache_hit_ratio.value, 0.6),
        "anthropic cache_hit_ratio must use (input + cached) denominator");
  check(snap.usage.observed_charge_usd.is_complete() &&
            snap.usage.observed_charge_usd.value.has_value() &&
            near(*snap.usage.observed_charge_usd.value, 0.0055),
        "token_usage observed_charge_usd mismatch");
  check(snap.usage.estimated_cost_usd.is_unknown(),
        "token_usage without pricing rules must leave estimate unknown");

  // Full JSON round-trip check on snapshot & sparkline.
  const std::string snap_json = must(to_json(snap), "snapshot to_json");
  const Value parsed = must(parse_json(snap_json), "parse snapshot json");
  check(parsed.find("stale") != nullptr && parsed.find("operations") != nullptr &&
            parsed.find("usage") != nullptr && parsed.find("context") != nullptr &&
            parsed.find("decision_companion") != nullptr &&
            parsed.find("source_records") != nullptr,
        "snapshot JSON missing required top-level fields");

  const auto sp = metrics_sparkline(snap.usage.token_spend_series, 8);
  const std::string sp_json = must(to_json(sp), "sparkline to_json");
  const Value parsed_sp = must(parse_json(sp_json), "parse sparkline json");
  check(parsed_sp.find("glyphs") != nullptr && parsed_sp.find("min_value") != nullptr &&
            parsed_sp.find("max_value") != nullptr,
        "sparkline JSON missing required fields");
}

} // namespace

int main() {
  const std::filesystem::path temp_dir =
      std::filesystem::temp_directory_path() /
      ("blackbird_metrics_consumer_test_" + std::to_string(::getpid()));
  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  std::filesystem::create_directories(temp_dir, ec);

  try {
    test_tri_metric_states();
    test_duplicate_capture_dedup();
    test_charge_vs_versioned_estimate();
    test_clock_domain_and_source_linkage();
    test_stale_last_good_retention(temp_dir);
    test_audit_log_readonly_and_sample_source(temp_dir);
    test_sparkline_edge_cases();
    test_json_export_and_token_usage_adapter();
  } catch (const Error &err) {
    std::cerr << "metrics_consumer_test failed at stage [" << g_stage
              << "] with Error: " << error_name(err.code) << " (" << err.detail
              << ")\n";
    std::filesystem::remove_all(temp_dir, ec);
    return 1;
  } catch (const std::exception &ex) {
    std::cerr << "metrics_consumer_test failed at stage [" << g_stage
              << "]: " << ex.what() << "\n";
    std::filesystem::remove_all(temp_dir, ec);
    return 1;
  }

  std::filesystem::remove_all(temp_dir, ec);
  std::cout << "metrics_consumer_test: all checks passed\n";
  return 0;
}
