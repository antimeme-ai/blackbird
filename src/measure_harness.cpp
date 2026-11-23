#include "blackbird/measure_harness.hpp"

#include "blackbird/json.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <signal.h>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#if defined(__APPLE__)
#include <crt_externs.h>
#else
extern char **environ;
#endif

namespace blackbird::measure {

namespace {

Error make_error(ErrorCode code, MeasureError detail) noexcept {
  return Error{code, static_cast<std::int64_t>(detail)};
}

char **&process_environ() noexcept {
#if defined(__APPLE__)
  return *::_NSGetEnviron();
#else
  return environ;
#endif
}

struct ScopedFd {
  int fd = -1;

  ScopedFd() = default;
  explicit ScopedFd(int value) noexcept : fd(value) {}
  ~ScopedFd() { reset(); }

  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;
  ScopedFd(ScopedFd &&other) noexcept : fd(std::exchange(other.fd, -1)) {}
  ScopedFd &operator=(ScopedFd &&other) noexcept {
    if (this != &other) {
      reset();
      fd = std::exchange(other.fd, -1);
    }
    return *this;
  }

  void reset(int next = -1) noexcept {
    if (fd >= 0) {
      (void)::close(fd);
    }
    fd = next;
  }

  [[nodiscard]] bool valid() const noexcept { return fd >= 0; }
};

// Ensures child process group is killed and reaped on any early/exceptional exit.
struct ScopedChildReaper {
  pid_t pid = -1;
  bool reaped = false;

  explicit ScopedChildReaper(pid_t child_pid) noexcept : pid(child_pid) {}

  ~ScopedChildReaper() {
    if (pid > 0 && !reaped) {
      (void)::kill(-pid, SIGKILL);
      int status = 0;
      pid_t rc = -1;
      do {
        rc = ::waitpid(pid, &status, 0);
      } while (rc < 0 && errno == EINTR);
      reaped = true;
    }
  }

  ScopedChildReaper(const ScopedChildReaper &) = delete;
  ScopedChildReaper &operator=(const ScopedChildReaper &) = delete;
};

bool create_cloexec_pipe(std::array<ScopedFd, 2> &out) noexcept {
  std::array<int, 2> raw{-1, -1};
#if defined(__linux__)
  if (::pipe2(raw.data(), O_CLOEXEC) != 0) {
    return false;
  }
#else
  if (::pipe(raw.data()) != 0) {
    return false;
  }
  for (const int fd : raw) {
    const int flags = ::fcntl(fd, F_GETFD);
    if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
      (void)::close(raw[0]);
      (void)::close(raw[1]);
      return false;
    }
  }
#endif
  out[0].reset(raw[0]);
  out[1].reset(raw[1]);
  return true;
}

bool set_nonblocking(int fd) noexcept {
  const int flags = ::fcntl(fd, F_GETFL);
  if (flags < 0) {
    return false;
  }
  return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool write_all_fd(int fd, const void *data, std::size_t size) noexcept {
  const auto *ptr = static_cast<const std::uint8_t *>(data);
  std::size_t written = 0U;
  while (written < size) {
    const ssize_t n = ::write(fd, ptr + written, size - written);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (n == 0) {
      return false;
    }
    written += static_cast<std::size_t>(n);
  }
  return true;
}

struct ChildFailurePacket {
  std::int64_t sandbox_error = 0;
  int err_no = 0;
  std::uint32_t stage = 0U; // 1 = sandbox, 2 = chdir, 3 = exec, 4 = stdin
};

Result<std::uint64_t> read_monotonic_raw_ns() noexcept {
  struct timespec ts{};
#if defined(CLOCK_MONOTONIC_RAW)
  if (::clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
    if (ts.tv_sec < 0 || ts.tv_nsec < 0) {
      return Result<std::uint64_t>::failure(
          make_error(ErrorCode::clock_regressed, MeasureError::clock_failed));
    }
    return Result<std::uint64_t>::success(static_cast<std::uint64_t>(ts.tv_sec) *
                                              1'000'000'000ULL +
                                          static_cast<std::uint64_t>(ts.tv_nsec));
  }
#endif
  if (::clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
    if (ts.tv_sec < 0 || ts.tv_nsec < 0) {
      return Result<std::uint64_t>::failure(
          make_error(ErrorCode::clock_regressed, MeasureError::clock_failed));
    }
    return Result<std::uint64_t>::success(static_cast<std::uint64_t>(ts.tv_sec) *
                                              1'000'000'000ULL +
                                          static_cast<std::uint64_t>(ts.tv_nsec));
  }
  return Result<std::uint64_t>::failure(
      make_error(ErrorCode::io, MeasureError::clock_failed));
}

std::uint64_t timeval_to_us(const struct timeval &tv) noexcept {
  if (tv.tv_sec < 0 || tv.tv_usec < 0) {
    return 0U;
  }
  constexpr std::uint64_t kMicrosPerSec = 1'000'000ULL;
  const auto sec = static_cast<std::uint64_t>(tv.tv_sec);
  const auto usec = static_cast<std::uint64_t>(tv.tv_usec);
  if (sec > (std::numeric_limits<std::uint64_t>::max() - usec) / kMicrosPerSec) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return sec * kMicrosPerSec + usec;
}

std::uint64_t clamp_nonneg_long(long value) noexcept {
  return value > 0L ? static_cast<std::uint64_t>(value) : 0U;
}

std::uint64_t normalize_platform_maxrss_bytes(long raw_ru_maxrss) noexcept {
#if defined(__APPLE__)
  return normalize_rusage_maxrss_bytes(static_cast<std::int64_t>(raw_ru_maxrss),
                                       RusageMemoryUnit::bytes);
#else
  return normalize_rusage_maxrss_bytes(static_cast<std::int64_t>(raw_ru_maxrss),
                                       RusageMemoryUnit::kibibytes);
#endif
}

std::uint64_t saturating_ms_to_ns(std::uint64_t ms) noexcept {
  constexpr std::uint64_t kNsPerMs = 1'000'000ULL;
  if (ms > std::numeric_limits<std::uint64_t>::max() / kNsPerMs) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return ms * kNsPerMs;
}

std::uint64_t saturating_add_u64(std::uint64_t lhs, std::uint64_t rhs) noexcept {
  if (std::numeric_limits<std::uint64_t>::max() - lhs < rhs) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return lhs + rhs;
}

// Ring buffer preserving the exact last `capacity` bytes written.
class BoundedTailBuffer {
public:
  explicit BoundedTailBuffer(std::size_t capacity) : capacity_(capacity) {}

  void append(std::string_view chunk) {
    if (capacity_ == 0U || chunk.empty()) {
      return;
    }
    if (chunk.size() >= capacity_) {
      buf_.assign(chunk.data() + (chunk.size() - capacity_), capacity_);
      write_pos_ = 0U;
      wrapped_ = true;
      return;
    }
    if (!wrapped_ && buf_.size() + chunk.size() <= capacity_) {
      buf_.append(chunk.data(), chunk.size());
      if (buf_.size() == capacity_) {
        write_pos_ = 0U;
        wrapped_ = true;
      }
      return;
    }
    if (!wrapped_) {
      const std::size_t avail = capacity_ - buf_.size();
      buf_.append(chunk.data(), avail);
      chunk.remove_prefix(avail);
      write_pos_ = 0U;
      wrapped_ = true;
    }
    while (!chunk.empty()) {
      const std::size_t space = capacity_ - write_pos_;
      const std::size_t take = std::min(space, chunk.size());
      std::memcpy(buf_.data() + write_pos_, chunk.data(), take);
      write_pos_ = (write_pos_ + take) % capacity_;
      chunk.remove_prefix(take);
    }
  }

  [[nodiscard]] std::string finalize() const {
    if (!wrapped_ || write_pos_ == 0U) {
      return buf_;
    }
    std::string out;
    out.reserve(buf_.size());
    out.append(buf_.data() + write_pos_, buf_.size() - write_pos_);
    out.append(buf_.data(), write_pos_);
    return out;
  }

private:
  std::size_t capacity_ = 0U;
  std::string buf_;
  std::size_t write_pos_ = 0U;
  bool wrapped_ = false;
};

// Streaming stdout line parser extracting BLACKBIRD_METRIC lines across read chunks.
class MetricLineStreamParser {
public:
  void feed(std::string_view chunk, std::vector<CustomMetricSample> &out) {
    for (const char ch : chunk) {
      if (ch == '\n') {
        flush_line(out);
        continue;
      }
      if (overflowed_) {
        continue;
      }
      if (line_.size() >= kMaxMetricLineBytes) {
        overflowed_ = true;
        line_.clear();
        continue;
      }
      line_.push_back(ch);
    }
  }

  void finish(std::vector<CustomMetricSample> &out) {
    if (!line_.empty() && !overflowed_) {
      flush_line(out);
    }
    line_.clear();
    overflowed_ = false;
  }

private:
  void flush_line(std::vector<CustomMetricSample> &out) {
    if (!overflowed_ && out.size() < kMaxCustomMetricsPerTrial) {
      std::string_view view{line_};
      if (!view.empty() && view.back() == '\r') {
        view.remove_suffix(1U);
      }
      if (auto parsed = parse_blackbird_metric_line(view); parsed.has_value()) {
        out.push_back(std::move(*parsed));
      }
    }
    line_.clear();
    overflowed_ = false;
  }

  std::string line_;
  bool overflowed_ = false;
};

bool has_embedded_nul(std::string_view text) noexcept {
  return text.find('\0') != std::string_view::npos;
}

bool valid_env_entry(std::string_view entry) noexcept {
  if (entry.empty() || has_embedded_nul(entry)) {
    return false;
  }
  const std::size_t eq = entry.find('=');
  return eq != std::string_view::npos && eq > 0U;
}

Result<void> validate_command_spec(const CommandRunSpec &spec) noexcept {
  if (spec.argv.empty() || spec.argv.front().empty()) {
    return Result<void>::failure(
        make_error(ErrorCode::invalid_range, MeasureError::empty_argv));
  }
  for (const auto &arg : spec.argv) {
    if (has_embedded_nul(arg)) {
      return Result<void>::failure(
          make_error(ErrorCode::invalid_range, MeasureError::invalid_spec));
    }
  }
  if (spec.cwd.has_value()) {
    const std::string cwd_str = spec.cwd->string();
    if (has_embedded_nul(cwd_str)) {
      return Result<void>::failure(
          make_error(ErrorCode::invalid_range, MeasureError::invalid_spec));
    }
  }
  if (spec.timeout_ms == 0U || spec.max_tail_bytes > kMaxTailBytesLimit) {
    return Result<void>::failure(
        make_error(ErrorCode::invalid_range, MeasureError::invalid_spec));
  }
  if (spec.env_override.has_value()) {
    for (const auto &entry : *spec.env_override) {
      if (!valid_env_entry(entry)) {
        return Result<void>::failure(
            make_error(ErrorCode::invalid_range, MeasureError::invalid_spec));
      }
    }
  }
  for (const auto &entry : spec.extra_env) {
    if (!valid_env_entry(entry)) {
      return Result<void>::failure(
          make_error(ErrorCode::invalid_range, MeasureError::invalid_spec));
    }
  }
  return Result<void>::success();
}

std::vector<std::string> snapshot_parent_env() {
  std::vector<std::string> out;
  char **envp = process_environ();
  if (envp == nullptr) {
    return out;
  }
  for (std::size_t i = 0U; envp[i] != nullptr; ++i) {
    out.emplace_back(envp[i]);
  }
  return out;
}

void merge_env_entries(std::vector<std::string> &base,
                       const std::vector<std::string> &overrides) {
  for (const auto &entry : overrides) {
    const std::size_t eq = entry.find('=');
    if (eq == std::string::npos || eq == 0U) {
      continue;
    }
    const std::string_view key{entry.data(), eq};
    bool replaced = false;
    for (auto &existing : base) {
      const std::size_t existing_eq = existing.find('=');
      if (existing_eq == eq && std::string_view{existing.data(), existing_eq} == key) {
        existing = entry;
        replaced = true;
        break;
      }
    }
    if (!replaced) {
      base.push_back(entry);
    }
  }
}

struct PreparedChildEnv {
  bool use_custom_env = false;
  std::vector<std::string> storage;
  std::vector<char *> envp;
};

PreparedChildEnv prepare_child_env(const CommandRunSpec &spec) {
  PreparedChildEnv prepared;
  const bool scrub_required = spec.brakes_profile.has_value() &&
                              brakes::is_contained_profile(*spec.brakes_profile);
  const bool has_custom = spec.env_override.has_value() || !spec.extra_env.empty();

  // black_flag (or unset) with no custom env: zero allocation / zero scrubbing
  // overhead.
  if (!scrub_required && !has_custom) {
    return prepared;
  }

  std::vector<std::string> merged =
      spec.env_override.has_value() ? *spec.env_override : snapshot_parent_env();
  if (!spec.extra_env.empty()) {
    merge_env_entries(merged, spec.extra_env);
  }
  if (scrub_required) {
    prepared.storage = brakes::build_scrubbed_child_env(*spec.brakes_profile, merged);
  } else {
    prepared.storage = std::move(merged);
  }

  prepared.envp.reserve(prepared.storage.size() + 1U);
  for (auto &entry : prepared.storage) {
    prepared.envp.push_back(entry.data());
  }
  prepared.envp.push_back(nullptr);
  prepared.use_custom_env = true;
  return prepared;
}

struct PipeDrainState {
  ScopedFd stdout_fd;
  ScopedFd stderr_fd;
  BoundedTailBuffer stdout_tail;
  BoundedTailBuffer stderr_tail;
  MetricLineStreamParser metric_parser;
  std::uint64_t stdout_bytes = 0U;
  std::uint64_t stderr_bytes = 0U;
  bool stdout_open = true;
  bool stderr_open = true;

  PipeDrainState(ScopedFd out_fd, ScopedFd err_fd, std::size_t tail_cap)
      : stdout_fd(std::move(out_fd)), stderr_fd(std::move(err_fd)),
        stdout_tail(tail_cap), stderr_tail(tail_cap) {}

  [[nodiscard]] bool any_open() const noexcept { return stdout_open || stderr_open; }
};

struct StreamDrainTarget {
  int fd = -1;
  bool *is_open = nullptr;
  std::uint64_t *byte_counter = nullptr;
  BoundedTailBuffer *tail = nullptr;
  MetricLineStreamParser *metric_parser = nullptr;
  std::vector<CustomMetricSample> *metrics = nullptr;
};

void drain_nonblocking_fd(StreamDrainTarget target) {
  std::array<char, 8192> buf{};
  for (;;) {
    const ssize_t n = ::read(target.fd, buf.data(), buf.size());
    if (n > 0) {
      const auto count = static_cast<std::size_t>(n);
      const std::string_view chunk{buf.data(), count};
      *target.byte_counter =
          saturating_add_u64(*target.byte_counter, static_cast<std::uint64_t>(count));
      target.tail->append(chunk);
      if (target.metric_parser != nullptr && target.metrics != nullptr) {
        target.metric_parser->feed(chunk, *target.metrics);
      }
      continue;
    }
    if (n == 0) {
      *target.is_open = false;
      return;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return;
    }
    *target.is_open = false;
    return;
  }
}

void poll_and_drain_once(PipeDrainState &state, int timeout_ms,
                         std::vector<CustomMetricSample> &metrics) {
  std::array<pollfd, 2> pfds{};
  nfds_t nfds = 0U;
  int stdout_idx = -1;
  int stderr_idx = -1;

  if (state.stdout_open && state.stdout_fd.valid()) {
    stdout_idx = static_cast<int>(nfds);
    pfds[nfds].fd = state.stdout_fd.fd;
    pfds[nfds].events = POLLIN;
    ++nfds;
  }
  if (state.stderr_open && state.stderr_fd.valid()) {
    stderr_idx = static_cast<int>(nfds);
    pfds[nfds].fd = state.stderr_fd.fd;
    pfds[nfds].events = POLLIN;
    ++nfds;
  }
  if (nfds == 0U) {
    return;
  }

  int rc = 0;
  do {
    rc = ::poll(pfds.data(), nfds, timeout_ms);
  } while (rc < 0 && errno == EINTR);

  if (rc <= 0) {
    return;
  }
  if (stdout_idx >= 0 && (pfds[static_cast<std::size_t>(stdout_idx)].revents &
                          (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
    drain_nonblocking_fd(StreamDrainTarget{state.stdout_fd.fd, &state.stdout_open,
                                           &state.stdout_bytes, &state.stdout_tail,
                                           &state.metric_parser, &metrics});
    if (!state.stdout_open) {
      state.stdout_fd.reset();
    }
  }
  if (stderr_idx >= 0 && (pfds[static_cast<std::size_t>(stderr_idx)].revents &
                          (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
    drain_nonblocking_fd(StreamDrainTarget{state.stderr_fd.fd, &state.stderr_open,
                                           &state.stderr_bytes, &state.stderr_tail,
                                           nullptr, nullptr});
    if (!state.stderr_open) {
      state.stderr_fd.reset();
    }
  }
}

bool child_has_exited_without_reaping(pid_t pid) noexcept {
  siginfo_t info{};
  info.si_pid = 0;
  int rc = -1;
  do {
    rc = ::waitid(P_PID, static_cast<id_t>(pid), &info, WEXITED | WNOHANG | WNOWAIT);
  } while (rc < 0 && errno == EINTR);
  return rc == 0 && info.si_pid == pid;
}

double quantile_sorted(std::span<const double> sorted, double probability) noexcept {
  if (sorted.empty()) {
    return 0.0;
  }
  if (sorted.size() == 1U) {
    return sorted.front();
  }
  const double pos = probability * static_cast<double>(sorted.size() - 1U);
  const auto lo = static_cast<std::size_t>(std::floor(pos));
  const auto hi = static_cast<std::size_t>(std::ceil(pos));
  const double frac = pos - static_cast<double>(lo);
  return sorted[lo] + frac * (sorted[hi] - sorted[lo]);
}

double normalize_zero(double value) noexcept {
  if (!std::isfinite(value)) {
    return 0.0;
  }
  return value == 0.0 ? 0.0 : value;
}

Value finite_number_value(double value) { return Value{Number{normalize_zero(value)}}; }

Result<double> extract_double(const Value &value) {
  const auto *num = std::get_if<Number>(&value.value());
  if (num == nullptr) {
    return Result<double>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  double out = 0.0;
  bool ok = true;
  std::visit(
      [&](const auto &n) {
        using T = std::decay_t<decltype(n)>;
        if constexpr (std::is_same_v<T, double>) {
          out = n;
          ok = std::isfinite(out);
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
          out = static_cast<double>(n);
        } else if constexpr (std::is_same_v<T, std::uint64_t>) {
          out = static_cast<double>(n);
        } else {
          const std::string txt = num->text();
          double parsed = 0.0;
          const auto ec = parse_decimal_double(txt, parsed);
          ok = (ec == std::errc{}) && std::isfinite(parsed);
          out = parsed;
        }
      },
      num->storage());
  if (!ok || !std::isfinite(out)) {
    return Result<double>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  return Result<double>::success(normalize_zero(out));
}

Result<std::uint64_t> extract_uint64(const Value &value) {
  const auto *num = std::get_if<Number>(&value.value());
  if (num == nullptr) {
    return Result<std::uint64_t>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage())) {
    return Result<std::uint64_t>::success(*u);
  }
  if (const auto *i = std::get_if<std::int64_t>(&num->storage())) {
    if (*i >= 0) {
      return Result<std::uint64_t>::success(static_cast<std::uint64_t>(*i));
    }
  }
  return Result<std::uint64_t>::failure(
      make_error(ErrorCode::corrupt, MeasureError::invalid_json));
}

Result<std::int64_t> extract_int64(const Value &value) {
  const auto *num = std::get_if<Number>(&value.value());
  if (num == nullptr) {
    return Result<std::int64_t>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  if (const auto *i = std::get_if<std::int64_t>(&num->storage())) {
    return Result<std::int64_t>::success(*i);
  }
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage())) {
    if (*u <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return Result<std::int64_t>::success(static_cast<std::int64_t>(*u));
    }
  }
  return Result<std::int64_t>::failure(
      make_error(ErrorCode::corrupt, MeasureError::invalid_json));
}

Result<bool> extract_bool(const Value &value) {
  const auto *b = std::get_if<bool>(&value.value());
  if (b == nullptr) {
    return Result<bool>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  return Result<bool>::success(*b);
}

Result<std::string> extract_string(const Value &value) {
  const auto *s = std::get_if<std::string>(&value.value());
  if (s == nullptr) {
    return Result<std::string>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  return Result<std::string>::success(*s);
}

const Value *require_field(const Value &obj, std::string_view key) noexcept {
  return obj.find(key);
}

Result<MetricDistribution> parse_distribution_value(const Value &obj) {
  if (!std::holds_alternative<Value::Object>(obj.value())) {
    return Result<MetricDistribution>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  MetricDistribution dist{};
  const auto read_u64 = [&](std::string_view key, std::size_t &dst) -> bool {
    const Value *f = require_field(obj, key);
    if (f == nullptr) {
      return false;
    }
    auto parsed = extract_uint64(*f);
    if (!parsed.has_value()) {
      return false;
    }
    dst = static_cast<std::size_t>(parsed.value());
    return true;
  };
  const auto read_f64 = [&](std::string_view key, double &dst) -> bool {
    const Value *f = require_field(obj, key);
    if (f == nullptr) {
      return false;
    }
    auto parsed = extract_double(*f);
    if (!parsed.has_value()) {
      return false;
    }
    dst = parsed.value();
    return true;
  };

  if (!read_u64("count", dist.count) || !read_f64("min", dist.min) ||
      !read_f64("q25", dist.q25) || !read_f64("median", dist.median) ||
      !read_f64("q75", dist.q75) || !read_f64("p95", dist.p95) ||
      !read_f64("max", dist.max) || !read_f64("iqr", dist.iqr) ||
      !read_f64("mean", dist.mean) || !read_f64("stddev", dist.stddev) ||
      !read_f64("cv", dist.cv)) {
    return Result<MetricDistribution>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  return Result<MetricDistribution>::success(dist);
}

Result<TrialSummaryStats> parse_summary_value(const Value &obj) {
  if (!std::holds_alternative<Value::Object>(obj.value())) {
    return Result<TrialSummaryStats>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  TrialSummaryStats stats{};
  const auto read_count = [&](std::string_view key, std::size_t &dst) -> bool {
    const Value *f = require_field(obj, key);
    if (f == nullptr) {
      return false;
    }
    auto parsed = extract_uint64(*f);
    if (!parsed.has_value()) {
      return false;
    }
    dst = static_cast<std::size_t>(parsed.value());
    return true;
  };
  if (!read_count("total_count", stats.total_count) ||
      !read_count("warmup_count", stats.warmup_count) ||
      !read_count("warmup_failed_count", stats.warmup_failed_count) ||
      !read_count("valid_count", stats.valid_count) ||
      !read_count("failed_count", stats.failed_count)) {
    return Result<TrialSummaryStats>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }

  const auto read_dist = [&](std::string_view key, MetricDistribution &dst) -> bool {
    const Value *f = require_field(obj, key);
    if (f == nullptr) {
      return false;
    }
    auto parsed = parse_distribution_value(*f);
    if (!parsed.has_value()) {
      return false;
    }
    dst = parsed.value();
    return true;
  };
  if (!read_dist("wall_ns", stats.wall_ns) || !read_dist("cpu_us", stats.cpu_us) ||
      !read_dist("max_rss_bytes", stats.max_rss_bytes)) {
    return Result<TrialSummaryStats>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }

  const Value *custom_field = require_field(obj, "custom_metrics");
  if (custom_field == nullptr ||
      !std::holds_alternative<Value::Object>(custom_field->value())) {
    return Result<TrialSummaryStats>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  for (const auto &[key, val] : custom_field->object()) {
    if (!is_valid_metric_key(key)) {
      return Result<TrialSummaryStats>::failure(
          make_error(ErrorCode::corrupt, MeasureError::invalid_json));
    }
    auto parsed = parse_distribution_value(val);
    if (!parsed.has_value()) {
      return Result<TrialSummaryStats>::failure(parsed.error());
    }
    stats.custom_metrics.emplace(key, parsed.value());
  }
  return Result<TrialSummaryStats>::success(std::move(stats));
}

Result<MeasurementComparison> parse_comparison_value(const Value &obj) {
  if (!std::holds_alternative<Value::Object>(obj.value())) {
    return Result<MeasurementComparison>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  const Value *speedup_f = require_field(obj, "speedup_ratio");
  const Value *delta_f = require_field(obj, "delta_pct");
  const Value *mem_f = require_field(obj, "memory_delta_bytes");
  const Value *iqr_f = require_field(obj, "iqr_overlaps");
  const Value *verdict_f = require_field(obj, "verdict");
  const Value *reason_f = require_field(obj, "reason");
  if (speedup_f == nullptr || delta_f == nullptr || mem_f == nullptr ||
      iqr_f == nullptr || verdict_f == nullptr || reason_f == nullptr) {
    return Result<MeasurementComparison>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  auto speedup = extract_double(*speedup_f);
  auto delta = extract_double(*delta_f);
  auto mem = extract_int64(*mem_f);
  auto iqr = extract_bool(*iqr_f);
  auto verdict_str = extract_string(*verdict_f);
  auto reason = extract_string(*reason_f);
  if (!speedup.has_value() || !delta.has_value() || !mem.has_value() ||
      !iqr.has_value() || !verdict_str.has_value() || !reason.has_value()) {
    return Result<MeasurementComparison>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  auto parsed_verdict = parse_comparison_verdict(verdict_str.value());
  if (!parsed_verdict.has_value()) {
    return Result<MeasurementComparison>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  MeasurementComparison out{};
  out.speedup_ratio = speedup.value();
  out.delta_pct = delta.value();
  out.memory_delta_bytes = mem.value();
  out.iqr_overlaps = iqr.value();
  out.verdict = *parsed_verdict;
  out.reason = std::move(reason).value();
  return Result<MeasurementComparison>::success(std::move(out));
}

Result<TuningIteration> parse_iteration_value(const Value &obj) {
  if (!std::holds_alternative<Value::Object>(obj.value())) {
    return Result<TuningIteration>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  const Value *id_f = require_field(obj, "id");
  const Value *base_f = require_field(obj, "is_baseline");
  const Value *label_f = require_field(obj, "label");
  const Value *snap_f = require_field(obj, "snapshot_ref");
  const Value *oracle_f = require_field(obj, "oracle_passed");
  const Value *summary_f = require_field(obj, "summary");
  const Value *comp_f = require_field(obj, "comparison");
  const Value *accepted_f = require_field(obj, "accepted");
  const Value *rollback_f = require_field(obj, "rollback_recommended");
  const Value *reason_f = require_field(obj, "reason");
  if (id_f == nullptr || base_f == nullptr || label_f == nullptr || snap_f == nullptr ||
      oracle_f == nullptr || summary_f == nullptr || comp_f == nullptr ||
      accepted_f == nullptr || rollback_f == nullptr || reason_f == nullptr) {
    return Result<TuningIteration>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }

  auto id = extract_uint64(*id_f);
  auto is_base = extract_bool(*base_f);
  auto label = extract_string(*label_f);
  auto snap = extract_string(*snap_f);
  auto oracle = extract_bool(*oracle_f);
  auto summary = parse_summary_value(*summary_f);
  auto accepted = extract_bool(*accepted_f);
  auto rollback = extract_bool(*rollback_f);
  auto reason = extract_string(*reason_f);
  if (!id.has_value() || !is_base.has_value() || !label.has_value() ||
      !snap.has_value() || !oracle.has_value() || !summary.has_value() ||
      !accepted.has_value() || !rollback.has_value() || !reason.has_value()) {
    return Result<TuningIteration>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }

  std::optional<MeasurementComparison> comp = std::nullopt;
  if (!std::holds_alternative<std::nullptr_t>(comp_f->value())) {
    auto parsed_comp = parse_comparison_value(*comp_f);
    if (!parsed_comp.has_value()) {
      return Result<TuningIteration>::failure(parsed_comp.error());
    }
    comp = std::move(parsed_comp).value();
  }

  TuningIteration out{};
  out.id = id.value();
  out.is_baseline = is_base.value();
  out.label = std::move(label).value();
  out.snapshot_ref = std::move(snap).value();
  out.oracle_passed = oracle.value();
  out.summary = std::move(summary).value();
  out.comparison = std::move(comp);
  out.accepted = accepted.value();
  out.rollback_recommended = rollback.value();
  out.reason = std::move(reason).value();
  return Result<TuningIteration>::success(std::move(out));
}

} // namespace

// ---------------------------------------------------------------------------
// Error & enum names
// ---------------------------------------------------------------------------

std::string_view measure_error_name(MeasureError detail) noexcept {
  switch (detail) {
  case MeasureError::none:
    return "none";
  case MeasureError::empty_argv:
    return "empty_argv";
  case MeasureError::invalid_spec:
    return "invalid_spec";
  case MeasureError::pipe_failed:
    return "pipe_failed";
  case MeasureError::fork_failed:
    return "fork_failed";
  case MeasureError::wait_failed:
    return "wait_failed";
  case MeasureError::clock_failed:
    return "clock_failed";
  case MeasureError::sandbox_failed:
    return "sandbox_failed";
  case MeasureError::chdir_failed:
    return "chdir_failed";
  case MeasureError::exec_failed:
    return "exec_failed";
  case MeasureError::invalid_json:
    return "invalid_json";
  case MeasureError::invalid_journal_entry:
    return "invalid_journal_entry";
  case MeasureError::capacity_exceeded:
    return "capacity_exceeded";
  }
  return "unknown";
}

std::string_view comparison_verdict_name(ComparisonVerdict verdict) noexcept {
  switch (verdict) {
  case ComparisonVerdict::invalid:
    return "invalid";
  case ComparisonVerdict::improved:
    return "improved";
  case ComparisonVerdict::regressed:
    return "regressed";
  case ComparisonVerdict::inconclusive:
    return "inconclusive";
  }
  return "invalid";
}

std::optional<ComparisonVerdict>
parse_comparison_verdict(std::string_view text) noexcept {
  if (text == "invalid") {
    return ComparisonVerdict::invalid;
  }
  if (text == "improved") {
    return ComparisonVerdict::improved;
  }
  if (text == "regressed") {
    return ComparisonVerdict::regressed;
  }
  if (text == "inconclusive") {
    return ComparisonVerdict::inconclusive;
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// 1. Custom Metric Parsing & Raw Subprocess Trial Execution
// ---------------------------------------------------------------------------

bool is_valid_metric_key(std::string_view key) noexcept {
  if (key.empty() || key.size() > kMaxMetricKeyLength) {
    return false;
  }
  const auto is_alpha = [](char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  };
  const auto is_digit = [](char c) noexcept { return c >= '0' && c <= '9'; };
  if (!is_alpha(key.front()) && key.front() != '_') {
    return false;
  }
  for (std::size_t i = 1U; i < key.size(); ++i) {
    const char c = key[i];
    if (!is_alpha(c) && !is_digit(c) && c != '_' && c != '.' && c != '-') {
      return false;
    }
  }
  return true;
}

std::optional<CustomMetricSample> parse_blackbird_metric_line(std::string_view line) {
  constexpr std::string_view kPrefix = "BLACKBIRD_METRIC ";
  if (!line.starts_with(kPrefix)) {
    return std::nullopt;
  }
  const std::string_view rest = line.substr(kPrefix.size());
  const std::size_t eq = rest.find('=');
  if (eq == std::string_view::npos) {
    return std::nullopt;
  }
  const std::string_view key = rest.substr(0U, eq);
  const std::string_view val_text = rest.substr(eq + 1U);
  if (!is_valid_metric_key(key) || val_text.empty()) {
    return std::nullopt;
  }
  // Reject leading '+' or whitespace explicitly across all platforms (including Linux
  // std::from_chars) and rely on parse_decimal_double for finite decimal parsing.
  if (val_text.front() == '+' || val_text.front() == ' ' || val_text.front() == '\t') {
    return std::nullopt;
  }
  double parsed = 0.0;
  const std::errc ec = parse_decimal_double(val_text, parsed);
  if (ec != std::errc{} || !std::isfinite(parsed)) {
    return std::nullopt;
  }
  return CustomMetricSample{std::string{key}, normalize_zero(parsed)};
}

Result<RawTrialRecord> run_single_trial(const CommandRunSpec &spec, TrialTag tag) {
  if (const auto valid = validate_command_spec(spec); !valid.has_value()) {
    return Result<RawTrialRecord>::failure(valid.error());
  }

  std::array<ScopedFd, 2> stdout_pipe;
  std::array<ScopedFd, 2> stderr_pipe;
  std::array<ScopedFd, 2> err_pipe;
  if (!create_cloexec_pipe(stdout_pipe) || !create_cloexec_pipe(stderr_pipe) ||
      !create_cloexec_pipe(err_pipe)) {
    return Result<RawTrialRecord>::failure(
        make_error(ErrorCode::io, MeasureError::pipe_failed));
  }

  // Prepare argv, cwd, and optional scrubbed/custom env BEFORE fork() to minimize
  // post-fork work in the child.
  std::vector<std::string> owned_argv = spec.argv;
  std::vector<char *> exec_argv;
  exec_argv.reserve(owned_argv.size() + 1U);
  for (auto &arg : owned_argv) {
    exec_argv.push_back(arg.data());
  }
  exec_argv.push_back(nullptr);

  std::string cwd_str;
  if (spec.cwd.has_value() && !spec.cwd->empty()) {
    cwd_str = spec.cwd->string();
  }

  PreparedChildEnv child_env = prepare_child_env(spec);
  const bool apply_sandbox =
      spec.sandbox_spec.has_value() &&
      spec.sandbox_spec->profile != sandbox::SandboxProfile::none;

  const auto start_ns_res = read_monotonic_raw_ns();
  if (!start_ns_res.has_value()) {
    return Result<RawTrialRecord>::failure(start_ns_res.error());
  }
  const std::uint64_t start_ns = start_ns_res.value();

  const pid_t pid = ::fork();
  if (pid < 0) {
    return Result<RawTrialRecord>::failure(
        make_error(ErrorCode::io, MeasureError::fork_failed));
  }

  if (pid == 0) {
    // Isolate child in its own process group for clean SIGTERM -> SIGKILL teardown.
    (void)::setpgid(0, 0);

    stdout_pipe[0].reset();
    stderr_pipe[0].reset();
    err_pipe[0].reset();

    const int devnull = ::open("/dev/null", O_RDONLY);
    if (devnull < 0) {
      const ChildFailurePacket pkt{0, errno, 4U};
      (void)write_all_fd(err_pipe[1].fd, &pkt, sizeof(pkt));
      ::_exit(127);
    }
    if (devnull != STDIN_FILENO) {
      if (::dup2(devnull, STDIN_FILENO) < 0) {
        const ChildFailurePacket pkt{0, errno, 4U};
        (void)write_all_fd(err_pipe[1].fd, &pkt, sizeof(pkt));
        ::_exit(127);
      }
      (void)::close(devnull);
    }

    if (::dup2(stdout_pipe[1].fd, STDOUT_FILENO) < 0 ||
        ::dup2(stderr_pipe[1].fd, STDERR_FILENO) < 0) {
      const ChildFailurePacket pkt{0, errno, 3U};
      (void)write_all_fd(err_pipe[1].fd, &pkt, sizeof(pkt));
      ::_exit(127);
    }
    stdout_pipe[1].reset();
    stderr_pipe[1].reset();

    if (!cwd_str.empty() && ::chdir(cwd_str.c_str()) != 0) {
      const ChildFailurePacket pkt{0, errno, 2U};
      (void)write_all_fd(err_pipe[1].fd, &pkt, sizeof(pkt));
      ::_exit(127);
    }

    if (apply_sandbox) {
      const auto sandbox_res =
          sandbox::apply_os_sandbox_to_current_process(*spec.sandbox_spec);
      if (!sandbox_res.has_value()) {
        const ChildFailurePacket pkt{sandbox_res.error().detail, errno, 1U};
        (void)write_all_fd(err_pipe[1].fd, &pkt, sizeof(pkt));
        ::_exit(126);
      }
    }

    if (child_env.use_custom_env) {
      process_environ() = child_env.envp.data();
    }

    ::execvp(exec_argv.front(), exec_argv.data());
    const ChildFailurePacket pkt{0, errno, 3U};
    (void)write_all_fd(err_pipe[1].fd, &pkt, sizeof(pkt));
    ::_exit(127);
  }

  // Parent process: close child write ends and establish process group immediately to
  // close any race before timeout signaling.
  ScopedChildReaper reaper{pid};
  (void)::setpgid(pid, pid);

  stdout_pipe[1].reset();
  stderr_pipe[1].reset();
  err_pipe[1].reset();

  if (!set_nonblocking(stdout_pipe[0].fd) || !set_nonblocking(stderr_pipe[0].fd)) {
    return Result<RawTrialRecord>::failure(
        make_error(ErrorCode::io, MeasureError::pipe_failed));
  }

  RawTrialRecord record{};
  record.trial_index = tag.trial_index;
  record.is_warmup = tag.is_warmup;

  PipeDrainState drain{std::move(stdout_pipe[0]), std::move(stderr_pipe[0]),
                       spec.max_tail_bytes};

  const std::uint64_t timeout_ns = saturating_ms_to_ns(spec.timeout_ms);
  const std::uint64_t deadline_ns = saturating_add_u64(start_ns, timeout_ns);

  // Drain stdout/stderr until EOF or timeout deadline.
  while (drain.any_open()) {
    const auto now_res = read_monotonic_raw_ns();
    if (!now_res.has_value()) {
      return Result<RawTrialRecord>::failure(now_res.error());
    }
    const std::uint64_t now_ns = now_res.value();
    if (now_ns >= deadline_ns) {
      record.timed_out = true;
      break;
    }
    const std::uint64_t rem_ns = deadline_ns - now_ns;
    const std::uint64_t rem_ms =
        std::max<std::uint64_t>(1U, (rem_ns + 999'999ULL) / 1'000'000ULL);
    const int poll_ms = static_cast<int>(std::min<std::uint64_t>(rem_ms, 10000ULL));
    poll_and_drain_once(drain, poll_ms, record.custom_metrics);
  }

  // If pipes closed before child finished, check deadline while waiting for exit.
  if (!record.timed_out) {
    while (!child_has_exited_without_reaping(pid)) {
      const auto now_res = read_monotonic_raw_ns();
      if (!now_res.has_value()) {
        return Result<RawTrialRecord>::failure(now_res.error());
      }
      const std::uint64_t now_ns = now_res.value();
      if (now_ns >= deadline_ns) {
        record.timed_out = true;
        break;
      }
      const std::uint64_t rem_ns = deadline_ns - now_ns;
      const std::uint64_t sleep_ms = std::min<std::uint64_t>(
          5U, std::max<std::uint64_t>(1U, rem_ns / 1'000'000ULL));
      (void)::poll(nullptr, 0U, static_cast<int>(sleep_ms));
    }
  }

  if (record.timed_out) {
    // Process-group teardown while `pid` is still unreaped (immune to PID recycling).
    (void)::kill(-pid, SIGTERM);
    const auto term_now = read_monotonic_raw_ns();
    const std::uint64_t grace_start =
        term_now.has_value() ? term_now.value() : deadline_ns;
    const std::uint64_t grace_deadline =
        saturating_add_u64(grace_start, saturating_ms_to_ns(spec.kill_grace_ms));

    for (;;) {
      if (drain.any_open()) {
        poll_and_drain_once(drain, 5, record.custom_metrics);
      }
      // If both pipes hit EOF AND child has exited, no process-group member holds our
      // pipes; check if grace elapsed or exit early if clean.
      const bool child_done = child_has_exited_without_reaping(pid);
      if (child_done && !drain.any_open()) {
        break;
      }
      const auto now_res = read_monotonic_raw_ns();
      const std::uint64_t now_ns =
          now_res.has_value() ? now_res.value() : grace_deadline;
      if (now_ns >= grace_deadline) {
        break;
      }
      if (!drain.any_open()) {
        (void)::poll(nullptr, 0U, 5);
      }
    }

    // Escalate to SIGKILL for the entire process group (child + all grandchildren).
    (void)::kill(-pid, SIGKILL);
  }

  // Reap direct child and capture kernel rusage via wait4().
  int status = 0;
  struct rusage ru{};
  pid_t waited = -1;
  do {
    waited = ::wait4(pid, &status, 0, &ru);
  } while (waited < 0 && errno == EINTR);

  if (waited < 0) {
    return Result<RawTrialRecord>::failure(
        make_error(ErrorCode::io, MeasureError::wait_failed));
  }
  reaper.reaped = true;

  const auto end_ns_res = read_monotonic_raw_ns();
  if (!end_ns_res.has_value()) {
    return Result<RawTrialRecord>::failure(end_ns_res.error());
  }
  const std::uint64_t end_ns = end_ns_res.value();
  record.wall_ns = end_ns >= start_ns ? (end_ns - start_ns) : 0U;

  // Bounded post-reap drain to collect any remaining buffered bytes without hanging.
  if (drain.any_open()) {
    for (int attempt = 0; attempt < 5 && drain.any_open(); ++attempt) {
      poll_and_drain_once(drain, 5, record.custom_metrics);
    }
  }
  drain.stdout_fd.reset();
  drain.stderr_fd.reset();
  drain.metric_parser.finish(record.custom_metrics);

  record.stdout_bytes = drain.stdout_bytes;
  record.stderr_bytes = drain.stderr_bytes;
  record.stdout_tail = drain.stdout_tail.finalize();
  record.stderr_tail = drain.stderr_tail.finalize();

  // Read optional pre-exec child failure packet.
  ChildFailurePacket failure_pkt{};
  std::size_t failure_bytes = 0U;
  auto *pkt_dst = reinterpret_cast<std::uint8_t *>(&failure_pkt);
  while (failure_bytes < sizeof(failure_pkt)) {
    const ssize_t n = ::read(err_pipe[0].fd, pkt_dst + failure_bytes,
                             sizeof(failure_pkt) - failure_bytes);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (n == 0) {
      break;
    }
    failure_bytes += static_cast<std::size_t>(n);
  }
  err_pipe[0].reset();

  record.user_us = timeval_to_us(ru.ru_utime);
  record.sys_us = timeval_to_us(ru.ru_stime);
  record.max_rss_bytes = normalize_platform_maxrss_bytes(ru.ru_maxrss);
  record.minflt = clamp_nonneg_long(ru.ru_minflt);
  record.majflt = clamp_nonneg_long(ru.ru_majflt);
  record.nvcsw = clamp_nonneg_long(ru.ru_nvcsw);
  record.nivcsw = clamp_nonneg_long(ru.ru_nivcsw);

  if (WIFEXITED(status)) {
    record.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    record.term_signal = WTERMSIG(status);
    record.exit_code = 128 + record.term_signal;
  }

  if (failure_bytes == sizeof(failure_pkt)) {
    if (failure_pkt.stage == 1U) {
      record.sandbox_apply_failed = true;
      record.sandbox_error =
          static_cast<sandbox::SandboxError>(failure_pkt.sandbox_error);
      record.exec_errno = failure_pkt.err_no;
    } else if (failure_pkt.stage == 2U || failure_pkt.stage == 3U ||
               failure_pkt.stage == 4U) {
      record.exec_errno = failure_pkt.err_no != 0 ? failure_pkt.err_no : EIO;
    }
  }

  return Result<RawTrialRecord>::success(std::move(record));
}

Result<MeasurementRunResult>
run_measurement_plan(const MeasurementPlan &plan,
                     const RawTrialCallback &on_raw_trial) {
  if (const auto valid = validate_command_spec(plan.command); !valid.has_value()) {
    return Result<MeasurementRunResult>::failure(valid.error());
  }
  if (plan.measured_trials == 0U) {
    return Result<MeasurementRunResult>::failure(
        make_error(ErrorCode::invalid_range, MeasureError::invalid_spec));
  }
  const std::uint64_t total_trials = static_cast<std::uint64_t>(plan.warmup_trials) +
                                     static_cast<std::uint64_t>(plan.measured_trials);
  if (total_trials > kMaxTotalTrials) {
    return Result<MeasurementRunResult>::failure(
        make_error(ErrorCode::capacity, MeasureError::capacity_exceeded));
  }
  if (plan.oracle.has_value()) {
    if (const auto oracle_valid = validate_command_spec(*plan.oracle);
        !oracle_valid.has_value()) {
      return Result<MeasurementRunResult>::failure(oracle_valid.error());
    }
  }

  MeasurementRunResult result{};

  // Correctness oracle fail-fast gate BEFORE measured trials.
  if (plan.oracle.has_value()) {
    auto oracle_res = run_single_trial(*plan.oracle, TrialTag{0U, false});
    if (!oracle_res.has_value()) {
      return Result<MeasurementRunResult>::failure(oracle_res.error());
    }
    result.oracle_ran = true;
    result.oracle_passed = oracle_res.value().succeeded();
    result.oracle_record = std::move(oracle_res).value();
    if (!result.oracle_passed) {
      return Result<MeasurementRunResult>::success(std::move(result));
    }
  }

  result.raw_trials.reserve(static_cast<std::size_t>(total_trials));
  for (std::uint32_t i = 0U; i < static_cast<std::uint32_t>(total_trials); ++i) {
    const bool is_warmup = i < plan.warmup_trials;
    auto trial_res = run_single_trial(plan.command, TrialTag{i, is_warmup});
    if (!trial_res.has_value()) {
      return Result<MeasurementRunResult>::failure(trial_res.error());
    }
    if (on_raw_trial) {
      on_raw_trial(trial_res.value());
    }
    result.raw_trials.push_back(std::move(trial_res).value());
  }

  return Result<MeasurementRunResult>::success(std::move(result));
}

// ---------------------------------------------------------------------------
// 2. Pure Tertiary Analysis (docs/INSTRUMENTATION.md)
// ---------------------------------------------------------------------------

MetricDistribution compute_metric_distribution(std::span<const double> samples) {
  std::vector<double> finite;
  finite.reserve(samples.size());
  for (const double value : samples) {
    if (std::isfinite(value)) {
      finite.push_back(normalize_zero(value));
    }
  }
  MetricDistribution dist{};
  if (finite.empty()) {
    return dist;
  }

  std::sort(finite.begin(), finite.end());
  dist.count = finite.size();
  dist.min = finite.front();
  dist.q25 = normalize_zero(quantile_sorted(finite, 0.25));
  dist.median = normalize_zero(quantile_sorted(finite, 0.50));
  dist.q75 = normalize_zero(quantile_sorted(finite, 0.75));
  dist.p95 = normalize_zero(quantile_sorted(finite, 0.95));
  dist.max = finite.back();
  dist.iqr = normalize_zero(dist.q75 - dist.q25);

  // Welford's online algorithm for numerically stable mean and sample variance.
  double mean = 0.0;
  double m2 = 0.0;
  for (std::size_t i = 0U; i < finite.size(); ++i) {
    const double x = finite[i];
    const double delta = x - mean;
    mean += delta / static_cast<double>(i + 1U);
    const double delta2 = x - mean;
    m2 += delta * delta2;
  }
  dist.mean = normalize_zero(mean);
  if (finite.size() >= 2U) {
    const double variance = std::max(0.0, m2 / static_cast<double>(finite.size() - 1U));
    dist.stddev = normalize_zero(std::sqrt(variance));
  } else {
    dist.stddev = 0.0;
  }
  if (dist.mean != 0.0) {
    dist.cv = normalize_zero(dist.stddev / std::abs(dist.mean));
  } else {
    dist.cv = 0.0;
  }
  return dist;
}

TrialSummaryStats
analyze_measurement_trials(std::span<const RawTrialRecord> raw_trials) {
  TrialSummaryStats stats{};
  stats.total_count = raw_trials.size();

  std::vector<double> walls;
  std::vector<double> cpus;
  std::vector<double> rss;
  std::map<std::string, std::vector<double>> custom_buckets;

  walls.reserve(raw_trials.size());
  cpus.reserve(raw_trials.size());
  rss.reserve(raw_trials.size());

  for (const auto &trial : raw_trials) {
    if (trial.is_warmup) {
      ++stats.warmup_count;
      if (!trial.succeeded()) {
        ++stats.warmup_failed_count;
      }
      continue;
    }
    if (!trial.succeeded()) {
      ++stats.failed_count;
      continue;
    }
    ++stats.valid_count;
    walls.push_back(static_cast<double>(trial.wall_ns));
    cpus.push_back(static_cast<double>(trial.cpu_us()));
    rss.push_back(static_cast<double>(trial.max_rss_bytes));
    for (const auto &metric : trial.custom_metrics) {
      if (is_valid_metric_key(metric.key) && std::isfinite(metric.value)) {
        custom_buckets[metric.key].push_back(normalize_zero(metric.value));
      }
    }
  }

  stats.wall_ns = compute_metric_distribution(walls);
  stats.cpu_us = compute_metric_distribution(cpus);
  stats.max_rss_bytes = compute_metric_distribution(rss);
  for (const auto &[key, values] : custom_buckets) {
    stats.custom_metrics.emplace(key, compute_metric_distribution(values));
  }
  return stats;
}

MeasurementComparison compare_measurements(BaselineStatsRef baseline,
                                           CandidateStatsRef candidate,
                                           const ComparisonPolicy &policy) {
  MeasurementComparison cmp{};
  const TrialSummaryStats &base = baseline.stats;
  const TrialSummaryStats &cand = candidate.stats;

  if (base.valid_count == 0U || base.wall_ns.count == 0U ||
      !std::isfinite(base.wall_ns.median) || base.wall_ns.median <= 0.0) {
    cmp.verdict = ComparisonVerdict::invalid;
    cmp.reason = "baseline has no valid positive wall_ns measurements";
    return cmp;
  }
  if (cand.valid_count == 0U || cand.wall_ns.count == 0U ||
      !std::isfinite(cand.wall_ns.median) || cand.wall_ns.median <= 0.0) {
    cmp.verdict = ComparisonVerdict::invalid;
    cmp.reason = "candidate has no valid positive wall_ns measurements";
    return cmp;
  }

  const double base_med = base.wall_ns.median;
  const double cand_med = cand.wall_ns.median;
  cmp.speedup_ratio = normalize_zero(base_med / cand_med);
  const double rel_change = (cand_med - base_med) / base_med;
  cmp.delta_pct = normalize_zero(rel_change * 100.0);

  if (base.max_rss_bytes.count > 0U && cand.max_rss_bytes.count > 0U &&
      std::isfinite(base.max_rss_bytes.median) &&
      std::isfinite(cand.max_rss_bytes.median)) {
    const double diff = cand.max_rss_bytes.median - base.max_rss_bytes.median;
    if (diff >= static_cast<double>(std::numeric_limits<std::int64_t>::max())) {
      cmp.memory_delta_bytes = std::numeric_limits<std::int64_t>::max();
    } else if (diff <= static_cast<double>(std::numeric_limits<std::int64_t>::min())) {
      cmp.memory_delta_bytes = std::numeric_limits<std::int64_t>::min();
    } else {
      cmp.memory_delta_bytes = static_cast<std::int64_t>(std::llround(diff));
    }
  }

  const double b_lo = base.wall_ns.q25;
  const double b_hi = base.wall_ns.q75;
  const double c_lo = cand.wall_ns.q25;
  const double c_hi = cand.wall_ns.q75;
  cmp.iqr_overlaps = (b_lo <= c_hi) && (c_lo <= b_hi);

  const double min_eff =
      (std::isfinite(policy.min_effect_ratio) && policy.min_effect_ratio >= 0.0)
          ? policy.min_effect_ratio
          : 0.0;

  if (policy.require_non_overlapping_iqr && cmp.iqr_overlaps) {
    cmp.verdict = ComparisonVerdict::inconclusive;
    cmp.reason = "wall_ns IQR intervals overlap";
    return cmp;
  }
  if (cand_med < base_med && -rel_change >= min_eff) {
    cmp.verdict = ComparisonVerdict::improved;
    cmp.reason = "candidate wall_ns median improved beyond threshold";
    return cmp;
  }
  if (cand_med > base_med && rel_change >= min_eff) {
    cmp.verdict = ComparisonVerdict::regressed;
    cmp.reason = "candidate wall_ns median regressed beyond threshold";
    return cmp;
  }

  cmp.verdict = ComparisonVerdict::inconclusive;
  cmp.reason = "wall_ns change within minimum effect threshold";
  return cmp;
}

// ---------------------------------------------------------------------------
// 3. TuningJournal (Oracle Gate, Accept/Reject, Rollback, Value/JSON)
// ---------------------------------------------------------------------------

TuningJournal::TuningJournal(ComparisonPolicy policy) noexcept : policy_(policy) {}

Result<TuningIteration> TuningJournal::record_baseline(CandidateSubmission baseline) {
  if (!iterations_.empty()) {
    return Result<TuningIteration>::failure(
        make_error(ErrorCode::conflict, MeasureError::invalid_journal_entry));
  }
  TuningIteration entry{};
  entry.id = 0U;
  entry.is_baseline = true;
  entry.label = std::move(baseline.label);
  entry.snapshot_ref = std::move(baseline.snapshot_ref);
  entry.oracle_passed = baseline.oracle_passed;
  entry.summary = std::move(baseline.summary);
  entry.comparison = std::nullopt;

  if (!entry.oracle_passed) {
    entry.accepted = false;
    entry.rollback_recommended = false;
    entry.reason = "baseline oracle gate failed";
  } else if (entry.summary.valid_count == 0U || entry.summary.wall_ns.count == 0U ||
             !std::isfinite(entry.summary.wall_ns.median) ||
             entry.summary.wall_ns.median <= 0.0) {
    entry.accepted = false;
    entry.rollback_recommended = false;
    entry.reason = "baseline has no valid positive measurements";
  } else {
    entry.accepted = true;
    entry.rollback_recommended = false;
    entry.reason = "baseline established";
  }

  iterations_.push_back(entry);
  next_id_ = 1U;
  return Result<TuningIteration>::success(std::move(entry));
}

Result<TuningIteration> TuningJournal::record_candidate(CandidateSubmission candidate) {
  if (iterations_.empty()) {
    return Result<TuningIteration>::failure(
        make_error(ErrorCode::conflict, MeasureError::invalid_journal_entry));
  }
  if (iterations_.size() >= kMaxJournalIterations) {
    return Result<TuningIteration>::failure(
        make_error(ErrorCode::capacity, MeasureError::capacity_exceeded));
  }

  TuningIteration entry{};
  entry.id = next_id_++;
  entry.is_baseline = false;
  entry.label = std::move(candidate.label);
  entry.snapshot_ref = std::move(candidate.snapshot_ref);
  entry.oracle_passed = candidate.oracle_passed;
  entry.summary = std::move(candidate.summary);

  const auto incumbent = best_iteration();
  if (!entry.oracle_passed) {
    entry.accepted = false;
    entry.rollback_recommended = incumbent.has_value();
    entry.reason = "oracle gate failed; candidate rejected";
    iterations_.push_back(entry);
    return Result<TuningIteration>::success(std::move(entry));
  }

  if (!incumbent.has_value()) {
    if (entry.summary.valid_count > 0U && entry.summary.wall_ns.count > 0U &&
        std::isfinite(entry.summary.wall_ns.median) &&
        entry.summary.wall_ns.median > 0.0) {
      entry.accepted = true;
      entry.rollback_recommended = false;
      entry.reason = "accepted as first valid incumbent";
    } else {
      entry.accepted = false;
      entry.rollback_recommended = false;
      entry.reason =
          "candidate has no valid measurements and no prior incumbent exists";
    }
    iterations_.push_back(entry);
    return Result<TuningIteration>::success(std::move(entry));
  }

  const MeasurementComparison cmp =
      compare_measurements(incumbent->summary, entry.summary, policy_);
  entry.comparison = cmp;

  switch (cmp.verdict) {
  case ComparisonVerdict::improved:
    entry.accepted = true;
    entry.rollback_recommended = false;
    entry.reason = "accepted: " + cmp.reason;
    break;
  case ComparisonVerdict::regressed:
    entry.accepted = false;
    entry.rollback_recommended = true;
    entry.reason = "rejected (regression): " + cmp.reason;
    break;
  case ComparisonVerdict::invalid:
    entry.accepted = false;
    entry.rollback_recommended = true;
    entry.reason = "rejected (invalid measurement): " + cmp.reason;
    break;
  case ComparisonVerdict::inconclusive:
    entry.accepted = false;
    entry.rollback_recommended = false;
    entry.reason = "rejected (inconclusive): " + cmp.reason;
    break;
  }

  iterations_.push_back(entry);
  return Result<TuningIteration>::success(std::move(entry));
}

Result<TuningIteration>
TuningJournal::run_and_record_baseline(IterationMetadata meta,
                                       const MeasurementPlan &plan,
                                       const RawTrialCallback &on_raw_trial) {
  auto run_res = run_measurement_plan(plan, on_raw_trial);
  if (!run_res.has_value()) {
    return Result<TuningIteration>::failure(run_res.error());
  }
  CandidateSubmission sub{};
  sub.label = std::move(meta.label);
  sub.snapshot_ref = std::move(meta.snapshot_ref);
  sub.oracle_passed = run_res.value().oracle_passed;
  sub.summary = analyze_measurement_trials(run_res.value().raw_trials);
  return record_baseline(std::move(sub));
}

Result<TuningIteration>
TuningJournal::run_and_record_candidate(IterationMetadata meta,
                                        const MeasurementPlan &plan,
                                        const RawTrialCallback &on_raw_trial) {
  auto run_res = run_measurement_plan(plan, on_raw_trial);
  if (!run_res.has_value()) {
    return Result<TuningIteration>::failure(run_res.error());
  }
  CandidateSubmission sub{};
  sub.label = std::move(meta.label);
  sub.snapshot_ref = std::move(meta.snapshot_ref);
  sub.oracle_passed = run_res.value().oracle_passed;
  sub.summary = analyze_measurement_trials(run_res.value().raw_trials);
  return record_candidate(std::move(sub));
}

std::optional<TuningIteration> TuningJournal::best_iteration() const {
  const TuningIteration *best = nullptr;
  for (const auto &iter : iterations_) {
    if (!iter.accepted || !iter.oracle_passed || iter.summary.valid_count == 0U ||
        iter.summary.wall_ns.count == 0U ||
        !std::isfinite(iter.summary.wall_ns.median) ||
        iter.summary.wall_ns.median <= 0.0) {
      continue;
    }
    if (best == nullptr || iter.summary.wall_ns.median < best->summary.wall_ns.median) {
      best = &iter;
    }
  }
  if (best == nullptr) {
    return std::nullopt;
  }
  return *best;
}

RollbackRecommendation TuningJournal::latest_rollback_recommendation() const {
  RollbackRecommendation rec{};
  if (iterations_.empty()) {
    rec.reason = "journal is empty";
    return rec;
  }
  const auto &latest = iterations_.back();
  if (!latest.rollback_recommended) {
    rec.reason = "no rollback required";
    return rec;
  }
  const auto best = best_iteration();
  if (!best.has_value()) {
    rec.reason = "rollback requested but no accepted target iteration exists";
    return rec;
  }
  rec.should_rollback = true;
  rec.target_iteration_id = best->id;
  rec.target_snapshot_ref = best->snapshot_ref;
  rec.reason = latest.reason;
  return rec;
}

Value to_value(const MetricDistribution &dist) {
  Value::Object obj;
  obj.reserve(11U);
  obj.emplace_back("count", Value{Number{static_cast<std::uint64_t>(dist.count)}});
  obj.emplace_back("min", finite_number_value(dist.min));
  obj.emplace_back("q25", finite_number_value(dist.q25));
  obj.emplace_back("median", finite_number_value(dist.median));
  obj.emplace_back("q75", finite_number_value(dist.q75));
  obj.emplace_back("p95", finite_number_value(dist.p95));
  obj.emplace_back("max", finite_number_value(dist.max));
  obj.emplace_back("iqr", finite_number_value(dist.iqr));
  obj.emplace_back("mean", finite_number_value(dist.mean));
  obj.emplace_back("stddev", finite_number_value(dist.stddev));
  obj.emplace_back("cv", finite_number_value(dist.cv));
  return Value::object(std::move(obj));
}

Value to_value(const TrialSummaryStats &summary) {
  Value::Object custom_obj;
  custom_obj.reserve(summary.custom_metrics.size());
  for (const auto &[key, dist] : summary.custom_metrics) {
    custom_obj.emplace_back(key, to_value(dist));
  }

  Value::Object obj;
  obj.reserve(9U);
  obj.emplace_back("total_count",
                   Value{Number{static_cast<std::uint64_t>(summary.total_count)}});
  obj.emplace_back("warmup_count",
                   Value{Number{static_cast<std::uint64_t>(summary.warmup_count)}});
  obj.emplace_back(
      "warmup_failed_count",
      Value{Number{static_cast<std::uint64_t>(summary.warmup_failed_count)}});
  obj.emplace_back("valid_count",
                   Value{Number{static_cast<std::uint64_t>(summary.valid_count)}});
  obj.emplace_back("failed_count",
                   Value{Number{static_cast<std::uint64_t>(summary.failed_count)}});
  obj.emplace_back("wall_ns", to_value(summary.wall_ns));
  obj.emplace_back("cpu_us", to_value(summary.cpu_us));
  obj.emplace_back("max_rss_bytes", to_value(summary.max_rss_bytes));
  obj.emplace_back("custom_metrics", Value::object(std::move(custom_obj)));
  return Value::object(std::move(obj));
}

Value to_value(const MeasurementComparison &comparison) {
  Value::Object obj;
  obj.reserve(6U);
  obj.emplace_back("speedup_ratio", finite_number_value(comparison.speedup_ratio));
  obj.emplace_back("delta_pct", finite_number_value(comparison.delta_pct));
  obj.emplace_back("memory_delta_bytes", Value{Number{comparison.memory_delta_bytes}});
  obj.emplace_back("iqr_overlaps", Value{comparison.iqr_overlaps});
  obj.emplace_back("verdict",
                   Value{std::string{comparison_verdict_name(comparison.verdict)}});
  obj.emplace_back("reason", Value{comparison.reason});
  return Value::object(std::move(obj));
}

Value TuningJournal::to_value() const {
  Value::Object policy_obj;
  policy_obj.reserve(2U);
  policy_obj.emplace_back("min_effect_ratio",
                          finite_number_value(policy_.min_effect_ratio));
  policy_obj.emplace_back("require_non_overlapping_iqr",
                          Value{policy_.require_non_overlapping_iqr});

  Value::Array iters_arr;
  iters_arr.reserve(iterations_.size());
  for (const auto &iter : iterations_) {
    Value::Object item;
    item.reserve(10U);
    item.emplace_back("id", Value{Number{iter.id}});
    item.emplace_back("is_baseline", Value{iter.is_baseline});
    item.emplace_back("label", Value{iter.label});
    item.emplace_back("snapshot_ref", Value{iter.snapshot_ref});
    item.emplace_back("oracle_passed", Value{iter.oracle_passed});
    item.emplace_back("summary", blackbird::measure::to_value(iter.summary));
    item.emplace_back("comparison", iter.comparison.has_value()
                                        ? blackbird::measure::to_value(*iter.comparison)
                                        : Value{nullptr});
    item.emplace_back("accepted", Value{iter.accepted});
    item.emplace_back("rollback_recommended", Value{iter.rollback_recommended});
    item.emplace_back("reason", Value{iter.reason});
    iters_arr.push_back(Value::object(std::move(item)));
  }

  Value::Object root;
  root.reserve(3U);
  root.emplace_back("schema_version", Value{Number{std::uint64_t{1U}}});
  root.emplace_back("policy", Value::object(std::move(policy_obj)));
  root.emplace_back("iterations", Value{std::move(iters_arr)});
  return Value::object(std::move(root));
}

Result<TuningJournal> TuningJournal::from_value(const Value &value) {
  if (!std::holds_alternative<Value::Object>(value.value())) {
    return Result<TuningJournal>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  const Value *version_f = require_field(value, "schema_version");
  const Value *policy_f = require_field(value, "policy");
  const Value *iters_f = require_field(value, "iterations");
  if (version_f == nullptr || policy_f == nullptr || iters_f == nullptr) {
    return Result<TuningJournal>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  auto version = extract_uint64(*version_f);
  if (!version.has_value() || version.value() != 1U) {
    return Result<TuningJournal>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }

  if (!std::holds_alternative<Value::Object>(policy_f->value()) ||
      !std::holds_alternative<Value::Array>(iters_f->value())) {
    return Result<TuningJournal>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  const Value *min_eff_f = require_field(*policy_f, "min_effect_ratio");
  const Value *req_iqr_f = require_field(*policy_f, "require_non_overlapping_iqr");
  if (min_eff_f == nullptr || req_iqr_f == nullptr) {
    return Result<TuningJournal>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }
  auto min_eff = extract_double(*min_eff_f);
  auto req_iqr = extract_bool(*req_iqr_f);
  if (!min_eff.has_value() || !req_iqr.has_value() || min_eff.value() < 0.0) {
    return Result<TuningJournal>::failure(
        make_error(ErrorCode::corrupt, MeasureError::invalid_json));
  }

  const auto &raw_iters = iters_f->array();
  if (raw_iters.size() > kMaxJournalIterations) {
    return Result<TuningJournal>::failure(
        make_error(ErrorCode::capacity, MeasureError::capacity_exceeded));
  }

  TuningJournal journal{ComparisonPolicy{min_eff.value(), req_iqr.value()}};
  journal.iterations_.reserve(raw_iters.size());
  std::uint64_t max_id = 0U;
  for (std::size_t idx = 0U; idx < raw_iters.size(); ++idx) {
    auto parsed = parse_iteration_value(raw_iters[idx]);
    if (!parsed.has_value()) {
      return Result<TuningJournal>::failure(parsed.error());
    }
    if (idx == 0U && (!parsed.value().is_baseline || parsed.value().id != 0U)) {
      return Result<TuningJournal>::failure(
          make_error(ErrorCode::corrupt, MeasureError::invalid_journal_entry));
    }
    if (idx > 0U && (parsed.value().is_baseline || parsed.value().id <= max_id)) {
      return Result<TuningJournal>::failure(
          make_error(ErrorCode::corrupt, MeasureError::invalid_journal_entry));
    }
    max_id = parsed.value().id;
    journal.iterations_.push_back(std::move(parsed).value());
  }
  journal.next_id_ = journal.iterations_.empty() ? 1U : (max_id + 1U);
  return Result<TuningJournal>::success(std::move(journal));
}

Result<std::string> TuningJournal::to_json() const { return dump_json(to_value()); }

Result<TuningJournal> TuningJournal::from_json(std::string_view json_text) {
  auto parsed = parse_json(json_text);
  if (!parsed.has_value()) {
    return Result<TuningJournal>::failure(
        make_error(parsed.error().code, MeasureError::invalid_json));
  }
  return from_value(parsed.value());
}

} // namespace blackbird::measure
