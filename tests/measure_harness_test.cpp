#include "blackbird/measure_harness.hpp"

#include "blackbird/json.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <signal.h>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

using namespace blackbird::measure;

void require(bool condition, std::string_view claim,
             std::source_location loc = std::source_location::current()) {
  if (!condition) {
    throw std::runtime_error(std::string{loc.file_name()} + ":" +
                             std::to_string(loc.line()) + " (" + loc.function_name() +
                             "): " + std::string{claim});
  }
}

template <typename T>
const T &require_opt(const std::optional<T> &opt, std::string_view claim,
                     std::source_location loc = std::source_location::current()) {
  if (!opt.has_value()) {
    throw std::runtime_error(std::string{loc.file_name()} + ":" +
                             std::to_string(loc.line()) + " (" + loc.function_name() +
                             "): " + std::string{claim});
  }
  return *opt;
}

bool approx_eq(double actual, double expected, double eps = 1e-6) noexcept {
  return std::abs(actual - expected) <= eps;
}

int count_open_fds() noexcept {
  int count = 0;
  for (int fd = 0; fd < 256; ++fd) {
    if (::fcntl(fd, F_GETFD) != -1) {
      ++count;
    }
  }
  return count;
}

bool has_any_unreaped_child() noexcept {
  int status = 0;
  const pid_t rc = ::waitpid(-1, &status, WNOHANG);
  return rc > 0;
}

struct TempDir {
  std::filesystem::path root;

  TempDir() {
    std::string tmpl =
        (std::filesystem::temp_directory_path() / "bb-measure-test-XXXXXX").string();
    char *created = ::mkdtemp(tmpl.data());
    require(created != nullptr, "mkdtemp for measure_harness_test");
    root = std::filesystem::canonical(created);
  }

  ~TempDir() {
    if (std::uncaught_exceptions() != 0) {
      std::cerr << "retained failed measure fixture: " << root << '\n';
      return;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
  }
};

void write_text_file(const std::filesystem::path &path, std::string_view content) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream out{path, std::ios::binary | std::ios::trunc};
  require(out.good(), "open fixture file for write");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  require(out.good(), "write fixture file");
}

std::string read_text_file(const std::filesystem::path &path) {
  std::ifstream in{path, std::ios::binary};
  require(in.good(), "open fixture file for read");
  return std::string{std::istreambuf_iterator<char>{in},
                     std::istreambuf_iterator<char>{}};
}

// ---------------------------------------------------------------------------
// Self-contained child worker modes (invoked via self_exe --child-...)
// ---------------------------------------------------------------------------

struct ChildWorkArgs {
  int sleep_ms = 0;
  std::size_t extra_junk_bytes = 0U;
};

int child_work_and_metrics(ChildWorkArgs args) {
  // Touch a small heap buffer so kernel records non-zero RSS and CPU activity.
  volatile std::uint64_t sink = 0U;
  std::vector<std::uint8_t> buf(256U * 1024U, 1U);
  for (std::size_t i = 0U; i < buf.size(); i += 64U) {
    sink += buf[i];
  }
  if (args.sleep_ms > 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds{args.sleep_ms});
  }
  if (args.extra_junk_bytes > 0U) {
    std::string junk(args.extra_junk_bytes, 'x');
    std::cout << junk << '\n';
  }
  std::cout << "normal output line\n";
  std::cout << "BLACKBIRD_METRIC throughput=1234.5\n";
  std::cout << "BLACKBIRD_METRIC latency_ms=12.25\r\n";
  std::cout << "BLACKBIRD_METRIC bad_nan=NaN\n";
  std::cout << "BLACKBIRD_METRIC bad_inf=inf\n";
  std::cout << "BLACKBIRD_METRIC bad_neg_inf=-Infinity\n";
  std::cout << "BLACKBIRD_METRIC 9badkey=42\n";
  std::cout << "BLACKBIRD_METRIC bad key=42\n";
  std::cout << "BLACKBIRD_METRIC bad_plus=+42\n";
  std::cout << "BLACKBIRD_METRIC neg_zero=-0.0\n";
  std::cout << "TAIL_SENTINEL_STDOUT\n";
  std::cerr << "STDERR_LINE_ONE\nTAIL_SENTINEL_STDERR\n";
  (void)sink;
  return 0;
}

int child_spawn_grandchild_and_hang(const std::string &pid_file_path) {
  // Ignore SIGTERM in BOTH child and grandchild to exercise full SIGTERM -> SIGKILL
  // process-group teardown!
  (void)::signal(SIGTERM, SIG_IGN);
  const pid_t gc = ::fork();
  if (gc == 0) {
    (void)::signal(SIGTERM, SIG_IGN);
    // Keep stdout/stderr open and sleep indefinitely.
    for (;;) {
      ::pause();
    }
  }
  if (gc > 0) {
    std::ofstream out{pid_file_path, std::ios::binary | std::ios::trunc};
    out << gc << '\n';
    out.flush();
    for (;;) {
      ::pause();
    }
  }
  return 2;
}

int child_dump_env_keys() {
  const auto emit = [](const char *key) {
    const char *val = std::getenv(key);
    std::cout << key << "=" << (val != nullptr ? val : "<UNSET>") << '\n';
  };
  emit("OPENAI_API_KEY");
  emit("MY_CUSTOM_SECRET_TOKEN");
  emit("BLACKBIRD_BENCH_SAFE_VAR");
  emit("PATH");
  return 0;
}

int child_read_file(const std::string &target_path) {
  std::ifstream in{target_path, std::ios::binary};
  if (!in.good()) {
    std::cerr << "open_denied\n";
    return 10;
  }
  std::string content{std::istreambuf_iterator<char>{in},
                      std::istreambuf_iterator<char>{}};
  std::cout << content;
  return 0;
}

// ---------------------------------------------------------------------------
// Direct Test Cases
// ---------------------------------------------------------------------------

void test_platform_maxrss_and_metric_parser() {
  // Unit normalization: macOS bytes vs Linux KiB + negative/overflow safety.
  require(normalize_rusage_maxrss_bytes(0, RusageMemoryUnit::bytes) == 0U,
          "0 bytes -> 0");
  require(normalize_rusage_maxrss_bytes(-42, RusageMemoryUnit::kibibytes) == 0U,
          "negative ru_maxrss clamped to 0");
  require(normalize_rusage_maxrss_bytes(4096, RusageMemoryUnit::bytes) == 4096U,
          "macOS bytes unchanged");
  require(normalize_rusage_maxrss_bytes(4096, RusageMemoryUnit::kibibytes) ==
              4096ULL * 1024ULL,
          "Linux KiB multiplied by 1024");
  require(normalize_rusage_maxrss_bytes(std::numeric_limits<std::int64_t>::max(),
                                        RusageMemoryUnit::kibibytes) ==
              std::numeric_limits<std::uint64_t>::max(),
          "Linux KiB overflow saturates");

  // Strict BLACKBIRD_METRIC parser checks.
  {
    const auto parsed =
        parse_blackbird_metric_line("BLACKBIRD_METRIC ops_per_sec=9876.5");
    const auto &ok = require_opt(parsed, "valid metric line parsed");
    require(ok.key == "ops_per_sec", "parsed key");
    require(approx_eq(ok.value, 9876.5), "parsed value");
  }
  {
    const auto parsed =
        parse_blackbird_metric_line("BLACKBIRD_METRIC cpu.p99-ms=-1.5e-2");
    const auto &ok =
        require_opt(parsed, "valid key with dot/dash and scientific notation");
    require(approx_eq(ok.value, -0.015), "parsed scientific value");
  }
  {
    const auto parsed = parse_blackbird_metric_line("BLACKBIRD_METRIC z=-0.0");
    const auto &ok = require_opt(parsed, "negative zero accepted");
    require(ok.value == 0.0 && !std::signbit(ok.value), "negative zero normalized");
  }

  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC x=nan").has_value(),
          "reject nan");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC x=NaN").has_value(),
          "reject NaN");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC x=inf").has_value(),
          "reject inf");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC x=-inf").has_value(),
          "reject -inf");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC x=1e500").has_value(),
          "reject overflow to inf");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC x=+1.0").has_value(),
          "reject leading plus");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC x= 1.0").has_value(),
          "reject leading space in value");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC x=1.0 trailing").has_value(),
          "reject trailing junk");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC 1bad=1.0").has_value(),
          "reject digit-leading key");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC bad/key=1.0").has_value(),
          "reject slash in key");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC =1.0").has_value(),
          "reject empty key");
  require(!parse_blackbird_metric_line("BLACKBIRD_METRIC x=").has_value(),
          "reject empty value");
  require(!parse_blackbird_metric_line("  BLACKBIRD_METRIC x=1.0").has_value(),
          "reject leading whitespace before prefix");
  require(
      !parse_blackbird_metric_line("BLACKBIRD_METRIC " + std::string(65U, 'a') + "=1.0")
           .has_value(),
      "reject key longer than 64 chars");
}

void test_real_subprocess_trials_and_raw_emission(
    const std::filesystem::path &self_exe) {
  MeasurementPlan plan{};
  plan.command.argv = {self_exe.string(), "--child-work", "15", "2048"};
  plan.command.max_tail_bytes = 256U;
  plan.warmup_trials = 2U;
  plan.measured_trials = 3U;

  std::vector<RawTrialRecord> emitted;
  auto run_res = run_measurement_plan(
      plan, [&](const RawTrialRecord &rec) { emitted.push_back(rec); });
  require(run_res.has_value(), "run_measurement_plan succeeded");
  const auto &res = run_res.value();
  require(!res.oracle_ran && res.oracle_passed, "no oracle configured");
  require(res.raw_trials.size() == 5U,
          "all 2 warmup + 3 measured raw trials preserved");
  require(emitted.size() == 5U, "callback received every single raw trial");

  for (std::uint32_t i = 0U; i < 5U; ++i) {
    const auto &t = res.raw_trials[i];
    require(t.trial_index == i, "sequential trial_index");
    require(t.is_warmup == (i < 2U), "warmup flag preserved raw");
    require(t.succeeded(), "trial succeeded");
    require(t.wall_ns > 0U, "monotonic wall_ns > 0");
    require(t.wall_ns >= 10'000'000ULL, "wall_ns reflects >= 10ms real sleep");
    require(t.max_rss_bytes > 0U, "max_rss_bytes > 0");
    require(t.stdout_bytes > 2048U, "full stdout_bytes counted even past tail cap");
    require(t.stdout_tail.size() <= 256U, "stdout_tail strictly bounded");
    require(t.stdout_tail.find("TAIL_SENTINEL_STDOUT") != std::string::npos,
            "stdout_tail retains actual tail");
    require(t.stderr_tail.find("TAIL_SENTINEL_STDERR") != std::string::npos,
            "stderr_tail retains actual tail");
    require(t.custom_metrics.size() == 3U,
            "only the 3 valid finite BLACKBIRD_METRIC lines parsed");
    require(t.custom_metrics[0].key == "throughput" &&
                approx_eq(t.custom_metrics[0].value, 1234.5),
            "throughput metric exact");
    require(t.custom_metrics[1].key == "latency_ms" &&
                approx_eq(t.custom_metrics[1].value, 12.25),
            "latency_ms metric with CRLF exact");
    require(t.custom_metrics[2].key == "neg_zero" && t.custom_metrics[2].value == 0.0 &&
                !std::signbit(t.custom_metrics[2].value),
            "neg_zero normalized");
  }

  // Tertiary analysis filters warmup ONLY here.
  const auto summary = analyze_measurement_trials(res.raw_trials);
  require(summary.total_count == 5U, "total_count = 5");
  require(summary.warmup_count == 2U, "warmup_count = 2");
  require(summary.valid_count == 3U, "valid_count = 3");
  require(summary.failed_count == 0U, "failed_count = 0");
  require(summary.wall_ns.count == 3U, "wall_ns distribution count = 3");
  require(summary.wall_ns.median > 0.0, "wall_ns median > 0");
  require(summary.max_rss_bytes.median > 0.0, "max_rss_bytes median > 0");
  require(summary.custom_metrics.contains("throughput"), "custom metric aggregated");
  require(approx_eq(summary.custom_metrics.at("throughput").median, 1234.5),
          "custom metric median exact");
}

void test_correctness_oracle_pass_and_fail_fast(const std::filesystem::path &self_exe) {
  TempDir fx;
  const auto marker = fx.root / "should_not_run.marker";

  // 1. Failing oracle: fail-fast BEFORE running any measured trials.
  {
    MeasurementPlan plan{};
    CommandRunSpec oracle{};
    oracle.argv = {self_exe.string(), "--child-exit", "7"};
    plan.oracle = oracle;
    plan.command.argv = {self_exe.string(), "--child-touch", marker.string()};
    plan.warmup_trials = 1U;
    plan.measured_trials = 3U;

    std::size_t callback_count = 0U;
    auto run_res =
        run_measurement_plan(plan, [&](const RawTrialRecord &) { ++callback_count; });
    require(run_res.has_value(), "fail-fast oracle plan returns cleanly");
    require(run_res.value().oracle_ran, "oracle_ran == true");
    require(!run_res.value().oracle_passed, "oracle_passed == false");
    const auto &oracle_rec =
        require_opt(run_res.value().oracle_record, "oracle record captured");
    require(oracle_rec.exit_code == 7, "oracle exit code captured");
    require(run_res.value().raw_trials.empty(),
            "zero measured trials run after oracle failure");
    require(callback_count == 0U, "zero callbacks emitted after oracle failure");
    require(!std::filesystem::exists(marker),
            "target command NEVER executed when oracle failed");
  }

  // 2. Passing oracle: proceeds to run trials normally.
  {
    MeasurementPlan plan{};
    CommandRunSpec oracle{};
    oracle.argv = {self_exe.string(), "--child-exit", "0"};
    plan.oracle = oracle;
    plan.command.argv = {self_exe.string(), "--child-touch", marker.string()};
    plan.warmup_trials = 0U;
    plan.measured_trials = 2U;

    auto run_res = run_measurement_plan(plan);
    require(run_res.has_value(), "passing oracle plan returns cleanly");
    require(run_res.value().oracle_ran && run_res.value().oracle_passed,
            "oracle passed");
    require(run_res.value().raw_trials.size() == 2U, "both measured trials executed");
    require(std::filesystem::exists(marker),
            "target command executed after oracle pass");
  }
}

void test_timeout_process_group_kill_with_grandchild(
    const std::filesystem::path &self_exe) {
  TempDir fx;
  const auto pid_file = fx.root / "grandchild.pid";

  CommandRunSpec spec{};
  spec.argv = {self_exe.string(), "--child-spawn-gc", pid_file.string()};
  spec.timeout_ms = 200U;
  spec.kill_grace_ms = 100U;

  const int fds_before = count_open_fds();
  auto res = run_single_trial(spec, TrialTag{0U, false});
  const int fds_after = count_open_fds();

  require(res.has_value(), "timed-out trial returns structured RawTrialRecord");
  require(res.value().timed_out, "timed_out == true");
  require(!res.value().succeeded(), "timed-out trial did not succeed");
  require(res.value().term_signal == SIGKILL,
          "SIGTERM-ignoring child+grandchild escalated to SIGKILL");
  require(fds_after == fds_before, "zero FD leaks after timeout teardown");
  require(!has_any_unreaped_child(), "zero zombies after timeout teardown");

  // Verify the grandchild PID recorded by the child is ALSO dead (ESRCH)!
  require(std::filesystem::exists(pid_file),
          "child wrote grandchild PID before timeout");
  const std::string pid_text = read_text_file(pid_file);
  const long gc_pid_long = std::strtol(pid_text.c_str(), nullptr, 10);
  require(gc_pid_long > 1L, "parsed valid grandchild PID");
  const auto gc_pid = static_cast<pid_t>(gc_pid_long);

  bool gc_dead = false;
  for (int i = 0; i < 40; ++i) {
    if (::kill(gc_pid, 0) != 0 && errno == ESRCH) {
      gc_dead = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  require(gc_dead, "grandchild in process group MUST be dead after SIGKILL teardown");
}

void test_tertiary_stats_and_comparison_exact_math() {
  struct SyntheticTrialSpec {
    std::uint32_t idx = 0U;
    bool warmup = false;
    int exit_code = 0;
    std::uint64_t wall_ns = 0U;
    std::uint64_t user_us = 0U;
    std::uint64_t sys_us = 0U;
    std::uint64_t rss = 0U;
    double custom_val = 0.0;
  };
  auto make_trial = [](const SyntheticTrialSpec &s) {
    RawTrialRecord r{};
    r.trial_index = s.idx;
    r.is_warmup = s.warmup;
    r.exit_code = s.exit_code;
    r.wall_ns = s.wall_ns;
    r.user_us = s.user_us;
    r.sys_us = s.sys_us;
    r.max_rss_bytes = s.rss;
    r.custom_metrics.push_back(CustomMetricSample{"score", s.custom_val});
    return r;
  };

  // Valid wall_ns values: [100, 120, 140, 160, 180]
  //   min = 100, q25 = 120, median = 140, q75 = 160, iqr = 40
  //   p95: pos = 0.95 * 4 = 3.8 => 160 + 0.8 * 20 = 176
  //   max = 180, mean = 140
  //   sample variance = ((40^2 + 20^2 + 0 + 20^2 + 40^2) / 4) = 4000 / 4 = 1000
  //   stddev = sqrt(1000) = 31.622776601683793
  //   cv = stddev / 140 = 0.2258769757263128
  std::vector<RawTrialRecord> baseline_raw = {
      make_trial({0U, true, 0, 999999U, 500U, 500U, 999999U, 9999.0}), // warmup
      make_trial({1U, true, 1, 888888U, 500U, 500U, 888888U, 8888.0}), // failed warmup
      make_trial(
          {2U, false, 1, 777777U, 500U, 500U, 777777U, 7777.0}), // failed measured
      make_trial({3U, false, 0, 180U, 60U, 30U, 2000U, 18.0}),
      make_trial({4U, false, 0, 100U, 40U, 10U, 1000U, 10.0}),
      make_trial({5U, false, 0, 140U, 50U, 20U, 1500U, 14.0}),
      make_trial({6U, false, 0, 160U, 55U, 25U, 1750U, 16.0}),
      make_trial({7U, false, 0, 120U, 45U, 15U, 1250U, 12.0}),
  };

  const auto base_stats = analyze_measurement_trials(baseline_raw);
  require(base_stats.total_count == 8U, "total_count == 8");
  require(base_stats.warmup_count == 2U, "warmup_count == 2");
  require(base_stats.warmup_failed_count == 1U, "warmup_failed_count == 1");
  require(base_stats.valid_count == 5U, "valid_count == 5");
  require(base_stats.failed_count == 1U, "failed_count == 1");

  require(approx_eq(base_stats.wall_ns.min, 100.0), "wall min");
  require(approx_eq(base_stats.wall_ns.q25, 120.0), "wall q25");
  require(approx_eq(base_stats.wall_ns.median, 140.0), "wall median");
  require(approx_eq(base_stats.wall_ns.q75, 160.0), "wall q75");
  require(approx_eq(base_stats.wall_ns.p95, 176.0), "wall p95");
  require(approx_eq(base_stats.wall_ns.max, 180.0), "wall max");
  require(approx_eq(base_stats.wall_ns.iqr, 40.0), "wall iqr");
  require(approx_eq(base_stats.wall_ns.mean, 140.0), "wall mean");
  require(approx_eq(base_stats.wall_ns.stddev, std::sqrt(1000.0)), "wall stddev");
  require(approx_eq(base_stats.wall_ns.cv, std::sqrt(1000.0) / 140.0), "wall cv");
  require(approx_eq(base_stats.cpu_us.median, 70.0), "cpu_us median = 50 + 20");
  require(approx_eq(base_stats.max_rss_bytes.median, 1500.0), "rss median = 1500");
  require(approx_eq(base_stats.custom_metrics.at("score").median, 14.0),
          "custom metric score median = 14");

  // Improved candidate: wall_ns [60, 65, 70, 75, 80] -> median 70 (2.0x speedup, -50%)
  // IQR [65, 75] does NOT overlap baseline [120, 160].
  std::vector<RawTrialRecord> faster_raw = {
      make_trial({0U, false, 0, 60U, 20U, 10U, 1200U, 20.0}),
      make_trial({1U, false, 0, 65U, 22U, 10U, 1250U, 21.0}),
      make_trial({2U, false, 0, 70U, 25U, 10U, 1300U, 22.0}),
      make_trial({3U, false, 0, 75U, 28U, 10U, 1350U, 23.0}),
      make_trial({4U, false, 0, 80U, 30U, 10U, 1400U, 24.0}),
  };
  const auto faster_stats = analyze_measurement_trials(faster_raw);
  const auto cmp_fast = compare_measurements(base_stats, faster_stats);
  require(cmp_fast.verdict == ComparisonVerdict::improved, "faster verdict improved");
  require(!cmp_fast.iqr_overlaps, "non-overlapping IQRs");
  require(approx_eq(cmp_fast.speedup_ratio, 2.0), "speedup_ratio == 2.0");
  require(approx_eq(cmp_fast.delta_pct, -50.0), "delta_pct == -50.0");
  require(cmp_fast.memory_delta_bytes == -200, "memory_delta_bytes == -200");

  // Regressed candidate: wall_ns [260, 270, 280, 290, 300] -> median 280 (0.5x, +100%)
  std::vector<RawTrialRecord> slower_raw = {
      make_trial({0U, false, 0, 260U, 90U, 20U, 2000U, 5.0}),
      make_trial({1U, false, 0, 270U, 95U, 20U, 2100U, 5.0}),
      make_trial({2U, false, 0, 280U, 100U, 20U, 2200U, 5.0}),
      make_trial({3U, false, 0, 290U, 105U, 20U, 2300U, 5.0}),
      make_trial({4U, false, 0, 300U, 110U, 20U, 2400U, 5.0}),
  };
  const auto slower_stats = analyze_measurement_trials(slower_raw);
  const auto cmp_slow = compare_measurements(base_stats, slower_stats);
  require(cmp_slow.verdict == ComparisonVerdict::regressed, "slower verdict regressed");
  require(!cmp_slow.iqr_overlaps, "non-overlapping IQRs on regression");
  require(approx_eq(cmp_slow.speedup_ratio, 0.5), "speedup_ratio == 0.5");
  require(approx_eq(cmp_slow.delta_pct, 100.0), "delta_pct == +100.0");
  require(cmp_slow.memory_delta_bytes == 700, "memory_delta_bytes == +700");

  // Overlapping IQRs -> inconclusive even with lower median.
  std::vector<RawTrialRecord> noisy_raw = {
      make_trial({0U, false, 0, 100U, 40U, 10U, 1500U, 14.0}),
      make_trial({1U, false, 0, 110U, 40U, 10U, 1500U, 14.0}),
      make_trial({2U, false, 0, 125U, 40U, 10U, 1500U, 14.0}),
      make_trial({3U, false, 0, 140U, 40U, 10U, 1500U, 14.0}),
      make_trial({4U, false, 0, 150U, 40U, 10U, 1500U, 14.0}),
  };
  const auto noisy_stats = analyze_measurement_trials(noisy_raw);
  const auto cmp_noisy = compare_measurements(base_stats, noisy_stats);
  require(cmp_noisy.iqr_overlaps, "overlapping IQRs detected");
  require(cmp_noisy.verdict == ComparisonVerdict::inconclusive,
          "overlapping IQRs -> inconclusive");

  // Empty candidate -> invalid.
  const TrialSummaryStats empty_stats{};
  const auto cmp_invalid = compare_measurements(base_stats, empty_stats);
  require(cmp_invalid.verdict == ComparisonVerdict::invalid, "empty candidate invalid");
}

void test_brakes_scrubbed_env_and_os_sandbox(const std::filesystem::path &self_exe) {
  // 1. Env scrubbing under guarded vs verbatim pass-through under black_flag.
  CommandRunSpec base_env_spec{};
  base_env_spec.argv = {self_exe.string(), "--child-dump-env"};
  base_env_spec.extra_env = {
      "OPENAI_API_KEY=sk-secret-value-123",
      "MY_CUSTOM_SECRET_TOKEN=tok-secret-456",
      "BLACKBIRD_BENCH_SAFE_VAR=keep-me-789",
  };

  {
    CommandRunSpec bf = base_env_spec;
    bf.brakes_profile = blackbird::brakes::BrakesProfile::black_flag;
    auto res = run_single_trial(bf);
    require(res.has_value() && res.value().succeeded(), "black_flag env trial ok");
    require(res.value().stdout_tail.find("OPENAI_API_KEY=sk-secret-value-123") !=
                std::string::npos,
            "black_flag preserves OPENAI_API_KEY");
    require(res.value().stdout_tail.find("MY_CUSTOM_SECRET_TOKEN=tok-secret-456") !=
                std::string::npos,
            "black_flag preserves MY_CUSTOM_SECRET_TOKEN");
    require(res.value().stdout_tail.find("BLACKBIRD_BENCH_SAFE_VAR=keep-me-789") !=
                std::string::npos,
            "black_flag preserves safe var");
  }

  {
    CommandRunSpec guarded = base_env_spec;
    guarded.brakes_profile = blackbird::brakes::BrakesProfile::guarded;
    auto res = run_single_trial(guarded);
    require(res.has_value() && res.value().succeeded(), "guarded env trial ok");
    require(res.value().stdout_tail.find("OPENAI_API_KEY=<UNSET>") != std::string::npos,
            "guarded MUST scrub OPENAI_API_KEY");
    require(res.value().stdout_tail.find("sk-secret-value-123") == std::string::npos,
            "OPENAI_API_KEY secret never leaked");
    require(res.value().stdout_tail.find("MY_CUSTOM_SECRET_TOKEN=<UNSET>") !=
                std::string::npos,
            "guarded MUST scrub MY_CUSTOM_SECRET_TOKEN");
    require(res.value().stdout_tail.find("BLACKBIRD_BENCH_SAFE_VAR=keep-me-789") !=
                std::string::npos,
            "guarded preserves safe runtime var");
    require(res.value().stdout_tail.find("PATH=<UNSET>") == std::string::npos,
            "guarded preserves PATH");
  }

  // 2. OS sandbox integration (when kernel sandbox is available on host).
  const auto caps = blackbird::sandbox::probe_os_sandbox_capabilities();
  if (caps.available) {
    TempDir fx;
    const auto ws = fx.root / "ws";
    const auto tmp = fx.root / "tmp";
    const auto home = fx.root / "home";
    const auto secret_dir = fx.root / "secret_dir";
    std::filesystem::create_directories(ws);
    std::filesystem::create_directories(tmp);
    std::filesystem::create_directories(home);
    std::filesystem::create_directories(secret_dir);
    write_text_file(ws / "allowed.txt", "workspace-readable");
    write_text_file(secret_dir / "secret.txt", "TOP-SECRET-DATA");

    blackbird::sandbox::SandboxSpec sbox{};
    sbox.profile = blackbird::sandbox::SandboxProfile::guarded;
    sbox.workspace_root = ws;
    sbox.tmp_dir = tmp;
    sbox.home_dir = home;
    sbox.denied_paths = {secret_dir};
    sbox.extra_read_paths = {self_exe.parent_path()};

    // Allowed workspace read succeeds inside sandboxed measurement.
    {
      CommandRunSpec ok_spec{};
      ok_spec.argv = {self_exe.string(), "--child-read", (ws / "allowed.txt").string()};
      ok_spec.brakes_profile = blackbird::brakes::BrakesProfile::guarded;
      ok_spec.sandbox_spec = sbox;
      auto res = run_single_trial(ok_spec);
      require(res.has_value() && !res.value().sandbox_apply_failed,
              "guarded sandbox applied cleanly");
      require(res.value().succeeded(), "workspace read succeeds under guarded sandbox");
      require(res.value().stdout_tail == "workspace-readable", "read workspace data");
    }

    // Denied secret read fails at kernel boundary.
    {
      CommandRunSpec deny_spec{};
      deny_spec.argv = {self_exe.string(), "--child-read",
                        (secret_dir / "secret.txt").string()};
      deny_spec.brakes_profile = blackbird::brakes::BrakesProfile::guarded;
      deny_spec.sandbox_spec = sbox;
      auto res = run_single_trial(deny_spec);
      require(res.has_value() && !res.value().sandbox_apply_failed,
              "guarded sandbox applied for secret deny check");
      require(!res.value().succeeded(), "secret_dir read blocked by kernel sandbox");
      require(res.value().stdout_tail.find("TOP-SECRET-DATA") == std::string::npos,
              "secret contents never leaked");
    }

    // Fail-closed: broken SandboxSpec reports sandbox_apply_failed and NEVER executes.
    {
      blackbird::sandbox::SandboxSpec broken = sbox;
      broken.workspace_root = fx.root / "nonexistent_dir";
      CommandRunSpec bad_spec{};
      bad_spec.argv = {self_exe.string(), "--child-read",
                       (secret_dir / "secret.txt").string()};
      bad_spec.sandbox_spec = broken;
      auto res = run_single_trial(bad_spec);
      require(res.has_value(), "broken sandbox spec returns RawTrialRecord");
      require(res.value().sandbox_apply_failed, "sandbox_apply_failed == true");
      require(!res.value().succeeded(), "broken sandbox trial rejected");
      require(res.value().stdout_tail.find("TOP-SECRET-DATA") == std::string::npos,
              "child never ran unsandboxed");
    }
  }
}

void test_tuning_journal_accept_reject_rollback_and_json_roundtrip(
    const std::filesystem::path &self_exe) {
  struct SyntheticStatsSpec {
    double median_wall = 0.0;
    double spread = 0.0;
    double rss_median = 0.0;
  };
  auto make_stats = [](const SyntheticStatsSpec &s) {
    std::vector<RawTrialRecord> raw;
    const std::array<double, 5> offsets = {-s.spread, -s.spread * 0.5, 0.0,
                                           s.spread * 0.5, s.spread};
    for (std::uint32_t i = 0U; i < 5U; ++i) {
      RawTrialRecord r{};
      r.trial_index = i;
      r.exit_code = 0;
      r.wall_ns = static_cast<std::uint64_t>(s.median_wall + offsets[i]);
      r.user_us = 100U;
      r.sys_us = 20U;
      r.max_rss_bytes = static_cast<std::uint64_t>(s.rss_median);
      r.custom_metrics.push_back(
          CustomMetricSample{"ops_s", 1e9 / (s.median_wall + offsets[i])});
      raw.push_back(std::move(r));
    }
    return analyze_measurement_trials(raw);
  };

  TuningJournal journal{ComparisonPolicy{0.05, true}};

  // Candidate before baseline fails cleanly.
  {
    CandidateSubmission premature{};
    premature.label = "too-early";
    premature.snapshot_ref = "git:deadbeef";
    premature.summary = make_stats({1000.0, 20.0, 4096.0});
    auto rc = journal.record_candidate(std::move(premature));
    require(!rc.has_value(), "candidate before baseline rejected");
    require(measure_error_of(rc.error()) == MeasureError::invalid_journal_entry,
            "error detail is invalid_journal_entry");
  }

  // Baseline (id 0): 1000 ns
  {
    CandidateSubmission base{};
    base.label = "baseline";
    base.snapshot_ref = "snap-0";
    base.oracle_passed = true;
    base.summary = make_stats({1000.0, 20.0, 8192.0});
    auto r = journal.record_baseline(std::move(base));
    require(r.has_value(), "record_baseline succeeded");
    require(r.value().id == 0U && r.value().is_baseline && r.value().accepted,
            "baseline accepted with id 0");
  }

  // Duplicate baseline rejected.
  {
    CandidateSubmission dup{};
    dup.label = "dup";
    dup.snapshot_ref = "snap-dup";
    dup.summary = make_stats({900.0, 20.0, 8192.0});
    auto r = journal.record_baseline(std::move(dup));
    require(!r.has_value(), "duplicate baseline rejected");
  }

  // Candidate 1: clear improvement (700 ns) -> accepted, new best!
  {
    CandidateSubmission c1{};
    c1.label = "opt-loop-unroll";
    c1.snapshot_ref = "snap-1";
    c1.oracle_passed = true;
    c1.summary = make_stats({700.0, 20.0, 7168.0});
    auto r = journal.record_candidate(std::move(c1));
    require(r.has_value(), "record candidate 1 succeeded");
    require(r.value().id == 1U && r.value().accepted && !r.value().rollback_recommended,
            "candidate 1 accepted");
    const auto &cmp1 = require_opt(r.value().comparison, "candidate 1 comparison");
    require(cmp1.verdict == ComparisonVerdict::improved,
            "candidate 1 verdict improved");
    const auto best_opt = journal.best_iteration();
    const auto &best = require_opt(best_opt, "best_iteration exists");
    require(best.id == 1U && best.snapshot_ref == "snap-1",
            "best_iteration advanced to snap-1");
    require(!journal.latest_rollback_recommendation().should_rollback,
            "no rollback after accepted improvement");
  }

  // Candidate 2: regression vs snap-1 (900 ns > 700 ns) -> rejected + rollback to
  // snap-1!
  {
    CandidateSubmission c2{};
    c2.label = "bad-cache-thrash";
    c2.snapshot_ref = "snap-2";
    c2.oracle_passed = true;
    c2.summary = make_stats({900.0, 20.0, 9000.0});
    auto r = journal.record_candidate(std::move(c2));
    require(r.has_value(), "record candidate 2 succeeded");
    require(r.value().id == 2U && !r.value().accepted && r.value().rollback_recommended,
            "candidate 2 rejected with rollback_recommended");
    const auto &cmp2 = require_opt(r.value().comparison, "candidate 2 comparison");
    require(cmp2.verdict == ComparisonVerdict::regressed,
            "candidate 2 verdict regressed");
    const auto rb = journal.latest_rollback_recommendation();
    require(rb.should_rollback && rb.target_iteration_id == 1U &&
                rb.target_snapshot_ref == "snap-1",
            "rollback targets best iteration snap-1");
  }

  // Candidate 3: oracle failure (even if summary were fast) -> rejected + rollback to
  // snap-1!
  {
    CandidateSubmission c3{};
    c3.label = "unsafe-shortcut";
    c3.snapshot_ref = "snap-3";
    c3.oracle_passed = false;
    c3.summary = make_stats({100.0, 5.0, 4096.0});
    auto r = journal.record_candidate(std::move(c3));
    require(r.has_value(), "record candidate 3 succeeded");
    require(r.value().id == 3U && !r.value().oracle_passed && !r.value().accepted &&
                r.value().rollback_recommended,
            "oracle failure rejected with rollback");
    const auto rb = journal.latest_rollback_recommendation();
    require(rb.should_rollback && rb.target_iteration_id == 1U &&
                rb.target_snapshot_ref == "snap-1",
            "oracle failure recommends rollback to snap-1");
  }

  // Candidate 4: inconclusive noisy overlap (695 ns with wide spread) -> rejected, no
  // rollback.
  {
    CandidateSubmission c4{};
    c4.label = "noisy-tweak";
    c4.snapshot_ref = "snap-4";
    c4.oracle_passed = true;
    c4.summary = make_stats({695.0, 40.0, 7168.0});
    auto r = journal.record_candidate(std::move(c4));
    require(r.has_value(), "record candidate 4 succeeded");
    require(r.value().id == 4U && !r.value().accepted &&
                !r.value().rollback_recommended,
            "inconclusive rejected without forced rollback");
    const auto &cmp4 = require_opt(r.value().comparison, "candidate 4 comparison");
    require(cmp4.verdict == ComparisonVerdict::inconclusive, "verdict inconclusive");
  }

  // JSON export / import round-trip via blackbird::Value.
  const auto json_res = journal.to_json();
  require(json_res.has_value(), "journal.to_json succeeded");
  const auto parsed_res = TuningJournal::from_json(json_res.value());
  require(parsed_res.has_value(), "TuningJournal::from_json succeeded");
  const auto &roundtripped = parsed_res.value();

  require(roundtripped.policy() == journal.policy(), "policy preserved");
  require(roundtripped.iterations().size() == journal.iterations().size(),
          "iteration count preserved");
  for (std::size_t i = 0U; i < journal.iterations().size(); ++i) {
    const auto &a = journal.iterations()[i];
    const auto &b = roundtripped.iterations()[i];
    require(a.id == b.id && a.is_baseline == b.is_baseline && a.label == b.label &&
                a.snapshot_ref == b.snapshot_ref &&
                a.oracle_passed == b.oracle_passed && a.accepted == b.accepted &&
                a.rollback_recommended == b.rollback_recommended &&
                a.reason == b.reason,
            "iteration metadata preserved through JSON round-trip");
    require(approx_eq(a.summary.wall_ns.median, b.summary.wall_ns.median, 1e-4),
            "summary wall_ns median preserved");
    require(a.comparison.has_value() == b.comparison.has_value(),
            "comparison presence preserved");
    if (a.comparison.has_value()) {
      const auto &ca = require_opt(a.comparison, "a comparison present");
      const auto &cb = require_opt(b.comparison, "b comparison present");
      require(ca.verdict == cb.verdict &&
                  approx_eq(ca.speedup_ratio, cb.speedup_ratio, 1e-4) &&
                  ca.memory_delta_bytes == cb.memory_delta_bytes,
              "comparison values preserved");
    }
  }
  const auto rt_best_opt = roundtripped.best_iteration();
  const auto &rt_best = require_opt(rt_best_opt, "roundtrip best_iteration exists");
  require(rt_best.id == 1U && rt_best.snapshot_ref == "snap-1",
          "best_iteration preserved after JSON import");

  // Malformed JSON / wrong schema rejected cleanly.
  require(!TuningJournal::from_json("{not json").has_value(),
          "malformed JSON rejected");
  require(
      !TuningJournal::from_json(R"({"schema_version":99,"policy":{},"iterations":[]})")
           .has_value(),
      "unknown schema_version rejected");

  // Live closed-loop run_and_record_baseline + run_and_record_candidate (oracle
  // failure).
  {
    TuningJournal live_journal{};
    MeasurementPlan base_plan{};
    base_plan.command.argv = {self_exe.string(), "--child-work", "10", "0"};
    base_plan.warmup_trials = 1U;
    base_plan.measured_trials = 2U;
    auto b_res =
        live_journal.run_and_record_baseline({"live-base", "rev-0"}, base_plan);
    require(b_res.has_value() && b_res.value().accepted, "live baseline accepted");

    MeasurementPlan broken_cand{};
    CommandRunSpec bad_oracle{};
    bad_oracle.argv = {self_exe.string(), "--child-exit", "1"};
    broken_cand.oracle = bad_oracle;
    broken_cand.command.argv = {self_exe.string(), "--child-work", "1", "0"};
    broken_cand.measured_trials = 2U;
    auto c_res =
        live_journal.run_and_record_candidate({"broken-cand", "rev-1"}, broken_cand);
    require(c_res.has_value() && !c_res.value().oracle_passed &&
                !c_res.value().accepted && c_res.value().rollback_recommended,
            "live oracle-failing candidate rejected with rollback");
    const auto rb = live_journal.latest_rollback_recommendation();
    require(rb.should_rollback && rb.target_snapshot_ref == "rev-0",
            "live rollback targets rev-0");
  }
}

void test_input_validation_guards() {
  {
    CommandRunSpec empty{};
    auto res = run_single_trial(empty);
    require(!res.has_value(), "empty argv rejected");
    require(measure_error_of(res.error()) == MeasureError::empty_argv,
            "empty_argv error detail");
  }
  {
    CommandRunSpec zero_timeout{};
    zero_timeout.argv = {"/bin/echo", "hi"};
    zero_timeout.timeout_ms = 0U;
    auto res = run_single_trial(zero_timeout);
    require(!res.has_value(), "zero timeout rejected");
    require(measure_error_of(res.error()) == MeasureError::invalid_spec,
            "invalid_spec error detail");
  }
  {
    CommandRunSpec bad_env{};
    bad_env.argv = {"/bin/echo", "hi"};
    bad_env.extra_env = {"NO_EQUALS_SIGN"};
    auto res = run_single_trial(bad_env);
    require(!res.has_value(), "malformed env entry rejected");
    require(measure_error_of(res.error()) == MeasureError::invalid_spec,
            "invalid_spec for bad env");
  }
  {
    CommandRunSpec nul_arg{};
    std::string bad{"hello"};
    bad.push_back('\0');
    bad.append("world");
    nul_arg.argv = {"/bin/echo", bad};
    auto res = run_single_trial(nul_arg);
    require(!res.has_value(), "embedded NUL in argv rejected");
    require(measure_error_of(res.error()) == MeasureError::invalid_spec,
            "invalid_spec for embedded NUL");
  }
}

} // namespace

int main(int argc, char **argv) {
  if (argc >= 2) {
    const std::string_view mode{argv[1]};
    if (mode == "--child-work" && argc == 4) {
      const int sleep_ms = std::atoi(argv[2]);
      const auto junk = static_cast<std::size_t>(std::strtoull(argv[3], nullptr, 10));
      return child_work_and_metrics(ChildWorkArgs{sleep_ms, junk});
    }
    if (mode == "--child-exit" && argc == 3) {
      return std::atoi(argv[2]);
    }
    if (mode == "--child-touch" && argc == 3) {
      std::ofstream out{argv[2], std::ios::binary | std::ios::trunc};
      out << "ran\n";
      return out.good() ? 0 : 1;
    }
    if (mode == "--child-spawn-gc" && argc == 3) {
      return child_spawn_grandchild_and_hang(argv[2]);
    }
    if (mode == "--child-dump-env" && argc == 2) {
      return child_dump_env_keys();
    }
    if (mode == "--child-read" && argc == 3) {
      return child_read_file(argv[2]);
    }
  }

  try {
    const std::filesystem::path self_exe = std::filesystem::canonical(argv[0]);
    const int fds_before = count_open_fds();

    test_platform_maxrss_and_metric_parser();
    test_input_validation_guards();
    test_real_subprocess_trials_and_raw_emission(self_exe);
    test_correctness_oracle_pass_and_fail_fast(self_exe);
    test_timeout_process_group_kill_with_grandchild(self_exe);
    test_tertiary_stats_and_comparison_exact_math();
    test_brakes_scrubbed_env_and_os_sandbox(self_exe);
    test_tuning_journal_accept_reject_rollback_and_json_roundtrip(self_exe);

    const int fds_after = count_open_fds();
    require(fds_after == fds_before,
            "zero FD leaks across entire measure_harness_test suite (before=" +
                std::to_string(fds_before) + ", after=" + std::to_string(fds_after) +
                ")");
    require(!has_any_unreaped_child(), "zero zombies after entire test suite");

    std::cout << "measure_harness_test: ALL PASSED (0 FD leaks, 0 zombies)\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "measure_harness_test FAILED: " << ex.what() << '\n';
    return 1;
  }
}
