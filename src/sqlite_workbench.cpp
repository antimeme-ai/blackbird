#include "blackbird/sqlite_workbench.hpp"
#include "blackbird/sqlite_embedded.hpp"

#include "blackbird/json.hpp"
#include "blackbird/project_memory.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <random>
#include <signal.h>
#include <spawn.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

#ifndef F_SETNOSIGPIPE
#include <pthread.h>
#endif

namespace blackbird::sqlite {
namespace {

namespace fs = std::filesystem;
using SteadyClock = std::chrono::steady_clock;

constexpr std::string_view kTaintRegistryTable = "_blackbird_taint_registry";
constexpr std::string_view kDbWideTaintKey = "__db__";
constexpr std::size_t kMaxInsertBatchRows = 100U;
constexpr std::size_t kMaxProbeOutputBytes = 64U * 1024U;

template <typename T> Result<T> fail(ErrorCode code, SqliteError detail) {
  return Result<T>::failure(Error{code, static_cast<std::int64_t>(detail)});
}

class ScopedFd {
public:
  ScopedFd() noexcept = default;
  explicit ScopedFd(int fd) noexcept : fd_(fd) {}
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
  explicit operator bool() const noexcept { return fd_ >= 0; }
  void reset(int next = -1) noexcept {
    if (fd_ >= 0) {
      while (::close(fd_) != 0 && errno == EINTR) {
      }
    }
    fd_ = next;
  }

private:
  int fd_ = -1;
};

#ifndef F_SETNOSIGPIPE
class PipeSignalGuard {
public:
  PipeSignalGuard() noexcept {
    sigemptyset(&blocked_);
    sigaddset(&blocked_, SIGPIPE);
    active_ = (::pthread_sigmask(SIG_BLOCK, &blocked_, &previous_) == 0);
    if (active_) {
      sigset_t pending{};
      if (::sigpending(&pending) == 0) {
        was_pending_ = (sigismember(&pending, SIGPIPE) == 1);
      }
    }
  }
  PipeSignalGuard(const PipeSignalGuard &) = delete;
  PipeSignalGuard &operator=(const PipeSignalGuard &) = delete;
  ~PipeSignalGuard() {
    if (!active_) {
      return;
    }
    if (!was_pending_) {
      timespec zero{};
      while (::sigtimedwait(&blocked_, nullptr, &zero) < 0 && errno == EINTR) {
      }
    }
    (void)::pthread_sigmask(SIG_SETMASK, &previous_, nullptr);
  }

private:
  sigset_t blocked_{};
  sigset_t previous_{};
  bool active_ = false;
  bool was_pending_ = false;
};
#endif

std::string ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return out;
}

bool has_control_or_nul(std::string_view text) noexcept {
  for (const char ch : text) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7FU) {
      return true;
    }
  }
  return false;
}

std::optional<std::string> lookup_env(const lan::EnvLookupFn &env_lookup,
                                      std::string_view name) {
  if (env_lookup) {
    return env_lookup(name);
  }
  const std::string key{name};
  const char *val = std::getenv(key.c_str());
  if (val == nullptr) {
    return std::nullopt;
  }
  return std::string{val};
}

std::string random_hex_16() {
  std::array<unsigned char, 8> bytes{};
  bool filled = false;
  int fd = -1;
  do {
    fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd >= 0) {
    ScopedFd urandom{fd};
    std::size_t got = 0U;
    while (got < bytes.size()) {
      const ssize_t n = ::read(urandom.get(), bytes.data() + got, bytes.size() - got);
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        break;
      }
      if (n == 0) {
        break;
      }
      got += static_cast<std::size_t>(n);
    }
    filled = (got == bytes.size());
  }
  if (!filled) {
    std::random_device rd;
    for (unsigned char &b : bytes) {
      b = static_cast<unsigned char>(rd() & 0xFFU);
    }
  }
  static constexpr std::string_view kHex = "0123456789abcdef";
  std::string out;
  out.reserve(16U);
  for (const unsigned char b : bytes) {
    out.push_back(kHex[(b >> 4U) & 0x0FU]);
    out.push_back(kHex[b & 0x0FU]);
  }
  return out;
}

std::string encode_hex_upper(std::string_view bytes) {
  static constexpr std::string_view kHex = "0123456789ABCDEF";
  std::string out;
  out.reserve(bytes.size() * 2U);
  for (const char ch : bytes) {
    const auto b = static_cast<unsigned char>(ch);
    out.push_back(kHex[(b >> 4U) & 0x0FU]);
    out.push_back(kHex[b & 0x0FU]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Secure Filesystem Helpers (O_NOFOLLOW, 0700/0600, UID checks)
// ---------------------------------------------------------------------------

Result<ScopedFd> open_verified_dir_nofollow(const fs::path &dir_path,
                                            bool require_owner_only) {
  if (dir_path.empty()) {
    return fail<ScopedFd>(ErrorCode::invalid_range, SqliteError::invalid_path);
  }
  const std::string raw = dir_path.string();
  if (has_control_or_nul(raw)) {
    return fail<ScopedFd>(ErrorCode::invalid_range, SqliteError::invalid_path);
  }
  struct stat lst{};
  if (::lstat(raw.c_str(), &lst) != 0) {
    if (errno == ENOENT) {
      return fail<ScopedFd>(ErrorCode::io, SqliteError::invalid_path);
    }
    return fail<ScopedFd>(ErrorCode::io, SqliteError::io_failed);
  }
  if (S_ISLNK(lst.st_mode)) {
    return fail<ScopedFd>(ErrorCode::io, SqliteError::symlink_rejected);
  }
  if (!S_ISDIR(lst.st_mode)) {
    return fail<ScopedFd>(ErrorCode::io, SqliteError::invalid_path);
  }

  int fd = -1;
  do {
    fd = ::open(raw.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ELOOP) {
      return fail<ScopedFd>(ErrorCode::io, SqliteError::symlink_rejected);
    }
    return fail<ScopedFd>(ErrorCode::io, SqliteError::io_failed);
  }
  ScopedFd owned{fd};

  struct stat fst{};
  if (::fstat(owned.get(), &fst) != 0) {
    return fail<ScopedFd>(ErrorCode::io, SqliteError::io_failed);
  }
  if (!S_ISDIR(fst.st_mode) || fst.st_dev != lst.st_dev || fst.st_ino != lst.st_ino) {
    return fail<ScopedFd>(ErrorCode::io, SqliteError::symlink_rejected);
  }
  if (require_owner_only) {
    if (fst.st_uid != ::geteuid() || (fst.st_mode & mode_t{0077}) != 0) {
      return fail<ScopedFd>(ErrorCode::io, SqliteError::insecure_permissions);
    }
  }
  return Result<ScopedFd>::success(std::move(owned));
}

Result<ScopedFd> ensure_restricted_dir(const fs::path &dir_path) {
  if (dir_path.empty()) {
    return fail<ScopedFd>(ErrorCode::invalid_range, SqliteError::invalid_path);
  }
  const std::string raw = dir_path.string();
  if (has_control_or_nul(raw)) {
    return fail<ScopedFd>(ErrorCode::invalid_range, SqliteError::invalid_path);
  }

  struct stat st{};
  if (::lstat(raw.c_str(), &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      return fail<ScopedFd>(ErrorCode::io, SqliteError::symlink_rejected);
    }
    if (!S_ISDIR(st.st_mode)) {
      return fail<ScopedFd>(ErrorCode::io, SqliteError::invalid_path);
    }
    return open_verified_dir_nofollow(dir_path, /*require_owner_only=*/true);
  }
  if (errno != ENOENT) {
    return fail<ScopedFd>(ErrorCode::io, SqliteError::io_failed);
  }

  // Create missing directory chain component-by-component with 0700.
  const fs::path normalized = dir_path.lexically_normal();
  std::vector<fs::path> missing;
  fs::path probe = normalized;
  while (!probe.empty()) {
    struct stat probe_st{};
    const std::string probe_str = probe.string();
    if (::lstat(probe_str.c_str(), &probe_st) == 0) {
      if (S_ISLNK(probe_st.st_mode)) {
        // Allow OS root symlinks like /tmp or /var on macOS only if they are
        // top-level directories, never arbitrary user leaf symlinks.
        const bool is_root_level = (probe.parent_path() == probe.root_path());
        if (!is_root_level) {
          return fail<ScopedFd>(ErrorCode::io, SqliteError::symlink_rejected);
        }
      } else if (!S_ISDIR(probe_st.st_mode)) {
        return fail<ScopedFd>(ErrorCode::io, SqliteError::invalid_path);
      }
      break;
    }
    if (errno != ENOENT) {
      return fail<ScopedFd>(ErrorCode::io, SqliteError::io_failed);
    }
    missing.push_back(probe);
    const fs::path parent = probe.parent_path();
    if (parent == probe) {
      break;
    }
    probe = parent;
  }

  for (auto it = missing.rbegin(); it != missing.rend(); ++it) {
    const std::string step = it->string();
    if (::mkdir(step.c_str(), mode_t{0700}) != 0) {
      if (errno == EEXIST) {
        struct stat existing{};
        if (::lstat(step.c_str(), &existing) != 0) {
          return fail<ScopedFd>(ErrorCode::io, SqliteError::io_failed);
        }
        if (S_ISLNK(existing.st_mode)) {
          return fail<ScopedFd>(ErrorCode::io, SqliteError::symlink_rejected);
        }
        if (!S_ISDIR(existing.st_mode)) {
          return fail<ScopedFd>(ErrorCode::io, SqliteError::invalid_path);
        }
      } else {
        return fail<ScopedFd>(ErrorCode::io, SqliteError::io_failed);
      }
    } else {
      // Tighten explicitly in case umask was unusual (0700 is already strict).
      (void)::chmod(step.c_str(), mode_t{0700});
    }
  }

  return open_verified_dir_nofollow(dir_path, /*require_owner_only=*/true);
}

Result<void> ensure_restricted_db_file(int dir_fd, const std::string &filename) {
  for (int attempt = 0; attempt < 16; ++attempt) {
    int fd = -1;
    do {
      fd = ::openat(dir_fd, filename.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      ScopedFd owned{fd};
      struct stat st{};
      if (::fstat(owned.get(), &st) != 0) {
        return fail<void>(ErrorCode::io, SqliteError::io_failed);
      }
      if (!S_ISREG(st.st_mode)) {
        return fail<void>(ErrorCode::io, SqliteError::invalid_path);
      }
      if (st.st_uid != ::geteuid() || (st.st_mode & mode_t{0077}) != 0) {
        return fail<void>(ErrorCode::io, SqliteError::insecure_permissions);
      }
      return Result<void>::success();
    }
    if (errno == ELOOP) {
      return fail<void>(ErrorCode::io, SqliteError::symlink_rejected);
    }
    if (errno != ENOENT) {
      return fail<void>(ErrorCode::io, SqliteError::io_failed);
    }

    do {
      fd = ::openat(dir_fd, filename.c_str(),
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t{0600});
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      ScopedFd owned{fd};
      struct stat st{};
      if (::fstat(owned.get(), &st) != 0) {
        return fail<void>(ErrorCode::io, SqliteError::io_failed);
      }
      if (!S_ISREG(st.st_mode)) {
        return fail<void>(ErrorCode::io, SqliteError::invalid_path);
      }
      if (st.st_uid != ::geteuid() || (st.st_mode & mode_t{0077}) != 0) {
        return fail<void>(ErrorCode::io, SqliteError::insecure_permissions);
      }
      return Result<void>::success();
    }
    if (errno == ELOOP) {
      return fail<void>(ErrorCode::io, SqliteError::symlink_rejected);
    }
    if (errno != EEXIST && errno != ENOENT) {
      return fail<void>(ErrorCode::io, SqliteError::io_failed);
    }
  }
  return fail<void>(ErrorCode::busy, SqliteError::io_failed);
}

Result<void> verify_sidecars_safe(int dir_fd, const std::string &filename) {
  static constexpr std::array<std::string_view, 3> kSuffixes = {"-wal", "-shm",
                                                                "-journal"};
  for (const std::string_view suffix : kSuffixes) {
    const std::string sidecar = filename + std::string{suffix};
    struct stat st{};
    if (::fstatat(dir_fd, sidecar.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno == ENOENT) {
        continue;
      }
      return fail<void>(ErrorCode::io, SqliteError::io_failed);
    }
    if (S_ISLNK(st.st_mode)) {
      return fail<void>(ErrorCode::io, SqliteError::symlink_rejected);
    }
    if (!S_ISREG(st.st_mode)) {
      return fail<void>(ErrorCode::io, SqliteError::invalid_path);
    }
    if (st.st_uid != ::geteuid()) {
      return fail<void>(ErrorCode::io, SqliteError::insecure_permissions);
    }
  }
  return Result<void>::success();
}

void tighten_sidecars_in_dir(int dir_fd, const std::string &filename) noexcept {
  static constexpr std::array<std::string_view, 3> kSuffixes = {"-wal", "-shm",
                                                                "-journal"};
  for (const std::string_view suffix : kSuffixes) {
    const std::string sidecar = filename + std::string{suffix};
    int fd = -1;
    do {
      fd = ::openat(dir_fd, sidecar.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
      continue;
    }
    ScopedFd owned{fd};
    struct stat st{};
    if (::fstat(owned.get(), &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == ::geteuid() && (st.st_mode & mode_t{0077}) != 0) {
      (void)::fchmod(owned.get(), mode_t{0600});
    }
  }
}

std::string strip_trailing_slashes(std::string path) {
  while (path.size() > 1U && path.back() == '/') {
    path.pop_back();
  }
  return path;
}

fs::path canonicalize_lenient(const fs::path &input) {
  std::array<char, PATH_MAX> resolved{};
  const std::string raw = input.string();
  if (!raw.empty() && ::realpath(raw.c_str(), resolved.data()) != nullptr) {
    return fs::path{strip_trailing_slashes(std::string{resolved.data()})};
  }
  fs::path probe = input.lexically_normal();
  std::vector<fs::path> tail;
  while (!probe.empty()) {
    const std::string probe_str = probe.string();
    if (::realpath(probe_str.c_str(), resolved.data()) != nullptr) {
      fs::path out{resolved.data()};
      for (auto it = tail.rbegin(); it != tail.rend(); ++it) {
        out /= *it;
      }
      return fs::path{strip_trailing_slashes(out.lexically_normal().string())};
    }
    const fs::path parent = probe.parent_path();
    if (parent == probe) {
      break;
    }
    const fs::path name = probe.filename();
    if (!name.empty() && name != ".") {
      tail.push_back(name);
    }
    probe = parent;
  }
  return fs::path{strip_trailing_slashes(input.lexically_normal().string())};
}

bool paths_overlap(const fs::path &lhs, const fs::path &rhs) {
  const std::string a = canonicalize_lenient(lhs).string();
  const std::string b = canonicalize_lenient(rhs).string();
  if (a.empty() || b.empty()) {
    return false;
  }
  if (a == b) {
    return true;
  }
  if (a.size() < b.size() && b.compare(0U, a.size(), a) == 0 &&
      (a.back() == '/' || b[a.size()] == '/')) {
    return true;
  }
  if (b.size() < a.size() && a.compare(0U, b.size(), b) == 0 &&
      (b.back() == '/' || a[b.size()] == '/')) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// SQLite Binary Resolution & Minimal Child Environment
// ---------------------------------------------------------------------------

bool is_executable_file(const fs::path &path) {
  const std::string raw = path.string();
  if (raw.empty() || has_control_or_nul(raw)) {
    return false;
  }
  struct stat st{};
  if (::stat(raw.c_str(), &st) != 0) {
    return false;
  }
  if (!S_ISREG(st.st_mode)) {
    return false;
  }
  return ::access(raw.c_str(), X_OK) == 0;
}

Result<fs::path> resolve_sqlite3_binary(const std::optional<fs::path> &binary_override,
                                        const lan::EnvLookupFn &env_lookup) {
  if (binary_override.has_value()) {
    const fs::path &candidate = *binary_override;
    if (candidate.empty() || !candidate.is_absolute() ||
        has_control_or_nul(candidate.string())) {
      return fail<fs::path>(ErrorCode::invalid_range, SqliteError::invalid_path);
    }
    if (!is_executable_file(candidate)) {
      return fail<fs::path>(ErrorCode::unsupported, SqliteError::binary_not_found);
    }
    return Result<fs::path>::success(candidate);
  }

  // Prefer system /usr/bin/sqlite3 first (macOS 3.51.0 with -safe, -nofollow, FTS5).
  const fs::path system_sqlite{"/usr/bin/sqlite3"};
  if (is_executable_file(system_sqlite)) {
    return Result<fs::path>::success(system_sqlite);
  }

  const auto path_env = lookup_env(env_lookup, "PATH");
  if (path_env.has_value()) {
    std::string_view remaining{*path_env};
    while (!remaining.empty()) {
      const std::size_t sep = remaining.find(':');
      const std::string_view dir =
          (sep == std::string_view::npos) ? remaining : remaining.substr(0U, sep);
      if (!dir.empty() && dir.front() == '/' && !has_control_or_nul(dir)) {
        const fs::path candidate = fs::path{dir} / "sqlite3";
        if (is_executable_file(candidate)) {
          return Result<fs::path>::success(candidate);
        }
      }
      if (sep == std::string_view::npos) {
        break;
      }
      remaining.remove_prefix(sep + 1U);
    }
  }

  return fail<fs::path>(ErrorCode::unsupported, SqliteError::binary_not_found);
}

// Build a minimal clean child environment: no provider/auth secrets and NO HOME
// so sqlite3 never reads ~/.sqliterc or ~/.sqlite_history.
std::vector<std::string> build_minimal_sqlite_env(const lan::EnvLookupFn &env_lookup) {
  std::vector<std::string> env;
  env.reserve(6U);
  static constexpr std::array<std::string_view, 5> kSafeKeys = {
      "PATH", "TMPDIR", "LANG", "LC_ALL", "TZ",
  };
  for (const std::string_view key : kSafeKeys) {
    const auto val = lookup_env(env_lookup, key);
    if (val.has_value() && !has_control_or_nul(*val)) {
      env.push_back(std::string{key} + "=" + *val);
    }
  }
  return env;
}

// ---------------------------------------------------------------------------
// Subprocess Runner (posix_spawn, O_CLOEXEC, non-blocking poll, pgroup kill)
// ---------------------------------------------------------------------------

struct SubprocessLimits {
  std::uint32_t timeout_ms = kDefaultTimeoutMs;
  std::size_t max_stdout_bytes = kDefaultMaxOutputBytes;
  std::size_t max_stderr_bytes = kMaxStderrBytes;
};

struct SubprocessResult {
  int exit_code = -1;
  bool exited_normally = false;
  bool timed_out = false;
  bool stdout_truncated = false;
  std::string stdout_bytes;
  std::string stderr_bytes;
  std::int64_t duration_ns = 0;
};

Result<std::pair<ScopedFd, ScopedFd>> make_cloexec_pipe() {
  int raw[2]{-1, -1};
  if (::pipe(raw) != 0) {
    return fail<std::pair<ScopedFd, ScopedFd>>(ErrorCode::io,
                                               SqliteError::spawn_failed);
  }
  ScopedFd r0{raw[0]};
  ScopedFd w0{raw[1]};
  const int r_dup = ::fcntl(r0.get(), F_DUPFD_CLOEXEC, 3);
  if (r_dup < 0) {
    return fail<std::pair<ScopedFd, ScopedFd>>(ErrorCode::io,
                                               SqliteError::spawn_failed);
  }
  ScopedFd r_owned{r_dup};
  const int w_dup = ::fcntl(w0.get(), F_DUPFD_CLOEXEC, 3);
  if (w_dup < 0) {
    return fail<std::pair<ScopedFd, ScopedFd>>(ErrorCode::io,
                                               SqliteError::spawn_failed);
  }
  ScopedFd w_owned{w_dup};
  return Result<std::pair<ScopedFd, ScopedFd>>::success(
      std::make_pair(std::move(r_owned), std::move(w_owned)));
}

class ChildProcessGuard {
public:
  ChildProcessGuard() noexcept = default;
  explicit ChildProcessGuard(pid_t pid) noexcept : pid_(pid) {}
  ChildProcessGuard(const ChildProcessGuard &) = delete;
  ChildProcessGuard &operator=(const ChildProcessGuard &) = delete;
  ~ChildProcessGuard() { terminate_and_reap(); }

  pid_t pid() const noexcept { return pid_; }
  bool unreaped() const noexcept { return pid_ > 0; }

  bool poll_reap(int &status_out) noexcept {
    if (pid_ <= 0) {
      return true;
    }
    for (;;) {
      const pid_t rc = ::waitpid(pid_, &status_out, WNOHANG);
      if (rc == pid_) {
        pid_ = -1;
        return true;
      }
      if (rc == 0) {
        return false;
      }
      if (errno == EINTR) {
        continue;
      }
      pid_ = -1;
      return true;
    }
  }

  void terminate_and_reap() noexcept {
    if (pid_ <= 0) {
      return;
    }
    const pid_t target = pid_;
    (void)::kill(-target, SIGTERM);
    const auto grace_deadline = SteadyClock::now() + std::chrono::milliseconds(50);
    int status = 0;
    while (SteadyClock::now() < grace_deadline) {
      const pid_t rc = ::waitpid(target, &status, WNOHANG);
      if (rc == target || (rc < 0 && errno != EINTR)) {
        pid_ = -1;
        return;
      }
      (void)::poll(nullptr, 0, 5);
    }
    (void)::kill(-target, SIGKILL);
    for (;;) {
      const pid_t rc = ::waitpid(target, &status, 0);
      if (rc == target || (rc < 0 && errno != EINTR)) {
        break;
      }
    }
    pid_ = -1;
  }

private:
  pid_t pid_ = -1;
};

Result<SubprocessResult> run_sqlite_subprocess(const fs::path &binary_path,
                                               const std::vector<std::string> &args,
                                               std::string_view stdin_payload,
                                               const std::vector<std::string> &env_vars,
                                               SubprocessLimits limits) {
  const auto start_time = SteadyClock::now();

  auto in_pipe = make_cloexec_pipe();
  if (!in_pipe.has_value()) {
    return Result<SubprocessResult>::failure(in_pipe.error());
  }
  auto out_pipe = make_cloexec_pipe();
  if (!out_pipe.has_value()) {
    return Result<SubprocessResult>::failure(out_pipe.error());
  }
  auto err_pipe = make_cloexec_pipe();
  if (!err_pipe.has_value()) {
    return Result<SubprocessResult>::failure(err_pipe.error());
  }

  ScopedFd in_read = std::move(in_pipe.value().first);
  ScopedFd in_write = std::move(in_pipe.value().second);
  ScopedFd out_read = std::move(out_pipe.value().first);
  ScopedFd out_write = std::move(out_pipe.value().second);
  ScopedFd err_read = std::move(err_pipe.value().first);
  ScopedFd err_write = std::move(err_pipe.value().second);

  std::vector<std::string> argv_storage = args;
  std::vector<char *> argv;
  argv.reserve(argv_storage.size() + 1U);
  for (std::string &arg : argv_storage) {
    argv.push_back(arg.data());
  }
  argv.push_back(nullptr);

  std::vector<std::string> env_storage = env_vars;
  std::vector<char *> envp;
  envp.reserve(env_storage.size() + 1U);
  for (std::string &entry : env_storage) {
    envp.push_back(entry.data());
  }
  envp.push_back(nullptr);

  posix_spawn_file_actions_t actions{};
  posix_spawnattr_t attr{};
  pid_t child_pid = -1;

  int spawn_rc = ::posix_spawn_file_actions_init(&actions);
  if (spawn_rc == 0) {
    spawn_rc = ::posix_spawnattr_init(&attr);
    if (spawn_rc == 0) {
      if (spawn_rc == 0) {
        spawn_rc =
            ::posix_spawn_file_actions_adddup2(&actions, in_read.get(), STDIN_FILENO);
      }
      if (spawn_rc == 0) {
        spawn_rc = ::posix_spawn_file_actions_adddup2(&actions, out_write.get(),
                                                      STDOUT_FILENO);
      }
      if (spawn_rc == 0) {
        spawn_rc = ::posix_spawn_file_actions_adddup2(&actions, err_write.get(),
                                                      STDERR_FILENO);
      }
      if (spawn_rc == 0) {
        spawn_rc = ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP |
                                                         POSIX_SPAWN_SETSIGMASK);
      }
      if (spawn_rc == 0) {
        spawn_rc = ::posix_spawnattr_setpgroup(&attr, 0);
      }
      if (spawn_rc == 0) {
        sigset_t empty_mask{};
        sigemptyset(&empty_mask);
        spawn_rc = ::posix_spawnattr_setsigmask(&attr, &empty_mask);
      }
      if (spawn_rc == 0) {
        // Strict posix_spawn (never posix_spawnp, never shell): exact absolute path.
        spawn_rc = ::posix_spawn(&child_pid, binary_path.c_str(), &actions, &attr,
                                 argv.data(), envp.data());
      }
      (void)::posix_spawnattr_destroy(&attr);
    }
    (void)::posix_spawn_file_actions_destroy(&actions);
  }

  // Close child ends immediately in parent.
  in_read.reset();
  out_write.reset();
  err_write.reset();

  if (spawn_rc != 0 || child_pid <= 0) {
    return fail<SubprocessResult>(ErrorCode::io, SqliteError::spawn_failed);
  }

  ChildProcessGuard child{child_pid};

#ifdef F_SETNOSIGPIPE
  (void)::fcntl(in_write.get(), F_SETNOSIGPIPE, 1);
#else
  PipeSignalGuard sigpipe_guard;
#endif
  if (::fcntl(in_write.get(), F_SETFL, O_NONBLOCK) < 0 ||
      ::fcntl(out_read.get(), F_SETFL, O_NONBLOCK) < 0 ||
      ::fcntl(err_read.get(), F_SETFL, O_NONBLOCK) < 0) {
    return fail<SubprocessResult>(ErrorCode::io, SqliteError::io_failed);
  }

  if (stdin_payload.empty()) {
    in_write.reset();
  }

  SubprocessResult result{};
  std::size_t stdin_offset = 0U;
  const std::uint32_t effective_timeout_ms =
      limits.timeout_ms == 0U ? kDefaultTimeoutMs : limits.timeout_ms;
  const auto deadline = start_time + std::chrono::milliseconds(effective_timeout_ms);

  std::array<char, 8192> chunk{};
  while (in_write || out_read || err_read) {
    const auto now = SteadyClock::now();
    if (now >= deadline) {
      result.timed_out = true;
      break;
    }
    const auto remaining_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    const int poll_timeout =
        static_cast<int>(std::clamp<std::int64_t>(remaining_ms, 1, 50));

    std::array<pollfd, 3> pfds{};
    nfds_t nfds = 0U;
    int idx_in = -1;
    int idx_out = -1;
    int idx_err = -1;

    if (in_write) {
      idx_in = static_cast<int>(nfds);
      pfds[nfds++] = pollfd{in_write.get(), POLLOUT, 0};
    }
    if (out_read) {
      idx_out = static_cast<int>(nfds);
      pfds[nfds++] = pollfd{out_read.get(), POLLIN, 0};
    }
    if (err_read) {
      idx_err = static_cast<int>(nfds);
      pfds[nfds++] = pollfd{err_read.get(), POLLIN, 0};
    }

    const int rc = ::poll(pfds.data(), nfds, poll_timeout);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      return fail<SubprocessResult>(ErrorCode::io, SqliteError::io_failed);
    }
    if (rc == 0) {
      continue;
    }

    if (idx_in >= 0 && (pfds[static_cast<std::size_t>(idx_in)].revents &
                        (POLLOUT | POLLERR | POLLHUP)) != 0) {
      const std::size_t left = stdin_payload.size() - stdin_offset;
      const ssize_t written =
          ::write(in_write.get(), stdin_payload.data() + stdin_offset, left);
      if (written > 0) {
        stdin_offset += static_cast<std::size_t>(written);
        if (stdin_offset >= stdin_payload.size()) {
          in_write.reset();
        }
      } else if (written < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
          // Child closed stdin early (e.g., syntax error); stop writing and drain
          // out/err.
          in_write.reset();
        }
      }
    }

    if (idx_out >= 0 && (pfds[static_cast<std::size_t>(idx_out)].revents &
                         (POLLIN | POLLHUP | POLLERR)) != 0) {
      for (;;) {
        const ssize_t n = ::read(out_read.get(), chunk.data(), chunk.size());
        if (n > 0) {
          const auto count = static_cast<std::size_t>(n);
          if (result.stdout_bytes.size() + count > limits.max_stdout_bytes) {
            const std::size_t room =
                limits.max_stdout_bytes > result.stdout_bytes.size()
                    ? limits.max_stdout_bytes - result.stdout_bytes.size()
                    : 0U;
            if (room > 0U) {
              result.stdout_bytes.append(chunk.data(), room);
            }
            result.stdout_truncated = true;
            in_write.reset();
            out_read.reset();
            err_read.reset();
            break;
          }
          result.stdout_bytes.append(chunk.data(), count);
        } else if (n == 0) {
          out_read.reset();
          break;
        } else {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
          }
          if (errno == EINTR) {
            continue;
          }
          out_read.reset();
          break;
        }
      }
    }

    if (idx_err >= 0 && err_read &&
        (pfds[static_cast<std::size_t>(idx_err)].revents &
         (POLLIN | POLLHUP | POLLERR)) != 0) {
      for (;;) {
        const ssize_t n = ::read(err_read.get(), chunk.data(), chunk.size());
        if (n > 0) {
          const auto count = static_cast<std::size_t>(n);
          if (result.stderr_bytes.size() < limits.max_stderr_bytes) {
            const std::size_t take =
                std::min(count, limits.max_stderr_bytes - result.stderr_bytes.size());
            result.stderr_bytes.append(chunk.data(), take);
          }
        } else if (n == 0) {
          err_read.reset();
          break;
        } else {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
          }
          if (errno == EINTR) {
            continue;
          }
          err_read.reset();
          break;
        }
      }
    }
  }

  in_write.reset();
  out_read.reset();
  err_read.reset();

  if (result.timed_out) {
    child.terminate_and_reap();
    result.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             SteadyClock::now() - start_time)
                             .count();
    return Result<SubprocessResult>::success(std::move(result));
  }

  if (result.stdout_truncated) {
    child.terminate_and_reap();
    result.exited_normally = true;
    result.exit_code = 0;
    result.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             SteadyClock::now() - start_time)
                             .count();
    return Result<SubprocessResult>::success(std::move(result));
  }

  int status = 0;
  while (child.unreaped()) {
    if (child.poll_reap(status)) {
      break;
    }
    if (SteadyClock::now() >= deadline) {
      result.timed_out = true;
      child.terminate_and_reap();
      break;
    }
    (void)::poll(nullptr, 0, 5);
  }

  if (!result.timed_out) {
    if (WIFEXITED(status)) {
      result.exited_normally = true;
      result.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      result.exited_normally = false;
      result.exit_code = 128 + WTERMSIG(status);
    }
  }

  result.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           SteadyClock::now() - start_time)
                           .count();
  return Result<SubprocessResult>::success(std::move(result));
}

// ---------------------------------------------------------------------------
// JSON Output Decoding (Handles empty, single array, multi-array, & truncated)
// ---------------------------------------------------------------------------

struct ParsedJsonRows {
  Value::Array rows;
  std::vector<std::string> columns;
  std::size_t total_rows_seen = 0U;
  bool truncated_rows = false;
};

void record_columns_from_object(const Value::Object &obj,
                                std::vector<std::string> &columns,
                                std::set<std::string> &seen) {
  for (const auto &entry : obj) {
    if (seen.insert(entry.first).second) {
      columns.push_back(entry.first);
    }
  }
}

Result<ParsedJsonRows> parse_complete_sqlite_json(std::string_view output,
                                                  std::size_t max_rows) {
  ParsedJsonRows parsed{};
  std::set<std::string> seen_cols;
  std::size_t pos = 0U;
  while (pos < output.size()) {
    while (pos < output.size() &&
           std::isspace(static_cast<unsigned char>(output[pos])) != 0) {
      ++pos;
    }
    if (pos >= output.size()) {
      break;
    }
    if (output[pos] != '[') {
      return fail<ParsedJsonRows>(ErrorCode::corrupt, SqliteError::json_parse_failed);
    }
    // Find matching closing ']' for this top-level JSON array.
    const std::size_t start = pos;
    std::size_t depth = 0U;
    bool in_str = false;
    bool escaped = false;
    std::size_t end = std::string_view::npos;
    for (std::size_t i = pos; i < output.size(); ++i) {
      const char ch = output[i];
      if (in_str) {
        if (escaped) {
          escaped = false;
        } else if (ch == '\\') {
          escaped = true;
        } else if (ch == '"') {
          in_str = false;
        }
        continue;
      }
      if (ch == '"') {
        in_str = true;
      } else if (ch == '[') {
        ++depth;
      } else if (ch == ']') {
        if (depth == 0U) {
          return fail<ParsedJsonRows>(ErrorCode::corrupt,
                                      SqliteError::json_parse_failed);
        }
        --depth;
        if (depth == 0U) {
          end = i + 1U;
          break;
        }
      }
    }
    if (end == std::string_view::npos) {
      return fail<ParsedJsonRows>(ErrorCode::corrupt, SqliteError::json_parse_failed);
    }
    auto arr_val = parse_json(output.substr(start, end - start));
    if (!arr_val.has_value() ||
        !std::holds_alternative<Value::Array>(arr_val.value().value())) {
      return fail<ParsedJsonRows>(ErrorCode::corrupt, SqliteError::json_parse_failed);
    }
    const Value::Array &arr = arr_val.value().array();
    for (const Value &row : arr) {
      ++parsed.total_rows_seen;
      if (parsed.rows.size() < max_rows) {
        if (std::holds_alternative<Value::Object>(row.value())) {
          record_columns_from_object(row.object(), parsed.columns, seen_cols);
        }
        parsed.rows.push_back(row);
      } else {
        parsed.truncated_rows = true;
      }
    }
    pos = end;
  }
  return Result<ParsedJsonRows>::success(std::move(parsed));
}

ParsedJsonRows parse_truncated_sqlite_json_prefix(std::string_view prefix,
                                                  std::size_t max_rows) {
  ParsedJsonRows parsed{};
  std::set<std::string> seen_cols;
  bool in_str = false;
  bool escaped = false;
  std::size_t brace_depth = 0U;
  std::size_t obj_start = std::string_view::npos;

  for (std::size_t i = 0U; i < prefix.size(); ++i) {
    const char ch = prefix[i];
    if (in_str) {
      if (escaped) {
        escaped = false;
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == '"') {
        in_str = false;
      }
      continue;
    }
    if (ch == '"') {
      in_str = true;
    } else if (ch == '{') {
      if (brace_depth == 0U) {
        obj_start = i;
      }
      ++brace_depth;
    } else if (ch == '}' && brace_depth > 0U) {
      --brace_depth;
      if (brace_depth == 0U && obj_start != std::string_view::npos) {
        auto row_val = parse_json(prefix.substr(obj_start, i - obj_start + 1U));
        obj_start = std::string_view::npos;
        if (row_val.has_value() &&
            std::holds_alternative<Value::Object>(row_val.value().value())) {
          ++parsed.total_rows_seen;
          if (parsed.rows.size() < max_rows) {
            record_columns_from_object(row_val.value().object(), parsed.columns,
                                       seen_cols);
            parsed.rows.push_back(std::move(row_val).value());
          } else {
            parsed.truncated_rows = true;
          }
        }
      }
    }
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// SQL Lexer & Guardrails
// ---------------------------------------------------------------------------

enum class SqlTokenKind : std::uint8_t {
  ident,
  quoted_ident,
  string_literal,
  blob_literal,
  number,
  punct,
};

struct SqlToken {
  SqlTokenKind kind = SqlTokenKind::punct;
  std::string text; // Unquoted content for ident / quoted_ident
};

bool is_ident_start(unsigned char ch) noexcept {
  return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_' ||
         ch >= 0x80U;
}

bool is_ident_body(unsigned char ch) noexcept {
  return is_ident_start(ch) || (ch >= '0' && ch <= '9') || ch == '$';
}

Result<std::vector<SqlToken>> lex_sql(std::string_view sql) {
  std::vector<SqlToken> tokens;
  std::size_t i = 0U;
  bool at_line_start = true;

  while (i < sql.size()) {
    const unsigned char ch = static_cast<unsigned char>(sql[i]);
    if (ch == '\0') {
      return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                         SqliteError::invalid_sql);
    }

    // Newlines reset line-start detection for sqlite3 dot-command refusal.
    if (ch == '\n' || ch == '\r') {
      at_line_start = true;
      ++i;
      continue;
    }

    // Horizontal whitespace preserves at_line_start.
    if (ch == ' ' || ch == '\t' || ch == '\v' || ch == '\f') {
      ++i;
      continue;
    }

    // Dot-command check: any line starting with '.' outside strings/comments is
    // rejected so sqlite3 CLI can never execute .shell/.system/.import/.load/etc.
    if (at_line_start && ch == '.') {
      return fail<std::vector<SqlToken>>(ErrorCode::unsupported,
                                         SqliteError::dot_command_rejected);
    }

    // Line comment: -- ... \n
    if (ch == '-' && i + 1U < sql.size() && sql[i + 1U] == '-') {
      i += 2U;
      while (i < sql.size() && sql[i] != '\n' && sql[i] != '\r') {
        if (sql[i] == '\0') {
          return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                             SqliteError::invalid_sql);
        }
        ++i;
      }
      continue;
    }

    // Block comment: /* ... */
    if (ch == '/' && i + 1U < sql.size() && sql[i + 1U] == '*') {
      i += 2U;
      bool closed = false;
      while (i + 1U < sql.size()) {
        if (sql[i] == '\0') {
          return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                             SqliteError::invalid_sql);
        }
        if (sql[i] == '*' && sql[i + 1U] == '/') {
          i += 2U;
          closed = true;
          break;
        }
        ++i;
      }
      if (!closed) {
        return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                           SqliteError::invalid_sql);
      }
      // Block comment does not count as horizontal whitespace before a dot-command
      // on the same line, so only reset if it wasn't at line start (Wait: on the
      // next line, '\n' sets at_line_start = true). Keep at_line_start = false here.
      at_line_start = false;
      continue;
    }

    at_line_start = false;

    // Hex blob literal: X'...' or x'...'
    if ((ch == 'X' || ch == 'x') && i + 1U < sql.size() && sql[i + 1U] == '\'') {
      i += 2U;
      bool closed = false;
      while (i < sql.size()) {
        if (sql[i] == '\0') {
          return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                             SqliteError::invalid_sql);
        }
        if (sql[i] == '\'') {
          ++i;
          closed = true;
          break;
        }
        ++i;
      }
      if (!closed) {
        return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                           SqliteError::invalid_sql);
      }
      tokens.push_back(SqlToken{SqlTokenKind::blob_literal, {}});
      continue;
    }

    // Single-quoted string literal: '...' with '' escape. Preserve unescaped
    // content because SQLite accepts single-quoted names in table/schema/PRAGMA
    // positions.
    if (ch == '\'') {
      ++i;
      std::string content;
      bool closed = false;
      while (i < sql.size()) {
        if (sql[i] == '\0') {
          return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                             SqliteError::invalid_sql);
        }
        if (sql[i] == '\'') {
          if (i + 1U < sql.size() && sql[i + 1U] == '\'') {
            content.push_back('\'');
            i += 2U;
            continue;
          }
          ++i;
          closed = true;
          break;
        }
        content.push_back(sql[i]);
        ++i;
      }
      if (!closed) {
        return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                           SqliteError::invalid_sql);
      }
      tokens.push_back(SqlToken{SqlTokenKind::string_literal, std::move(content)});
      continue;
    }

    // Double-quoted or backtick-quoted identifier: "..." or `...`
    if (ch == '"' || ch == '`') {
      const char quote = static_cast<char>(ch);
      ++i;
      std::string content;
      bool closed = false;
      while (i < sql.size()) {
        if (sql[i] == '\0') {
          return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                             SqliteError::invalid_sql);
        }
        if (sql[i] == quote) {
          if (i + 1U < sql.size() && sql[i + 1U] == quote) {
            content.push_back(quote);
            i += 2U;
            continue;
          }
          ++i;
          closed = true;
          break;
        }
        content.push_back(sql[i]);
        ++i;
      }
      if (!closed) {
        return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                           SqliteError::invalid_sql);
      }
      tokens.push_back(SqlToken{SqlTokenKind::quoted_ident, std::move(content)});
      continue;
    }

    // Bracket-quoted identifier: [...]
    if (ch == '[') {
      ++i;
      std::string content;
      bool closed = false;
      while (i < sql.size()) {
        if (sql[i] == '\0') {
          return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                             SqliteError::invalid_sql);
        }
        if (sql[i] == ']') {
          ++i;
          closed = true;
          break;
        }
        content.push_back(sql[i]);
        ++i;
      }
      if (!closed) {
        return fail<std::vector<SqlToken>>(ErrorCode::invalid_range,
                                           SqliteError::invalid_sql);
      }
      tokens.push_back(SqlToken{SqlTokenKind::quoted_ident, std::move(content)});
      continue;
    }

    // Unquoted identifier or keyword
    if (is_ident_start(ch)) {
      const std::size_t start = i;
      ++i;
      while (i < sql.size() && is_ident_body(static_cast<unsigned char>(sql[i]))) {
        ++i;
      }
      tokens.push_back(
          SqlToken{SqlTokenKind::ident, std::string{sql.substr(start, i - start)}});
      continue;
    }

    // Numeric literal
    if (ch >= '0' && ch <= '9') {
      const std::size_t start = i;
      ++i;
      while (i < sql.size() &&
             (std::isalnum(static_cast<unsigned char>(sql[i])) != 0 || sql[i] == '.')) {
        ++i;
      }
      tokens.push_back(
          SqlToken{SqlTokenKind::number, std::string{sql.substr(start, i - start)}});
      continue;
    }

    // Punctuation / operator
    tokens.push_back(SqlToken{SqlTokenKind::punct, std::string(1U, sql[i])});
    ++i;
  }

  return Result<std::vector<SqlToken>>::success(std::move(tokens));
}

bool is_ident_or_quoted(const SqlToken &tok) noexcept {
  return tok.kind == SqlTokenKind::ident || tok.kind == SqlTokenKind::quoted_ident;
}

// SQLite accepts single-quoted literals in table, schema, and PRAGMA name
// positions, so table/PRAGMA/taint analysis must inspect string_literal too.
bool is_name_token(const SqlToken &tok) noexcept {
  return is_ident_or_quoted(tok) || tok.kind == SqlTokenKind::string_literal;
}

bool token_eq_ci(const SqlToken &tok, std::string_view lower_expected) {
  return tok.kind == SqlTokenKind::ident && ascii_lower(tok.text) == lower_expected;
}

// ---------------------------------------------------------------------------
// SQL Literal & Identifier Formatting (Zero SQL Injection)
// ---------------------------------------------------------------------------

std::string sql_quote_ident(std::string_view ident) {
  std::string out;
  out.reserve(ident.size() + 2U);
  out.push_back('"');
  for (const char ch : ident) {
    if (ch == '"') {
      out.push_back('"');
    }
    out.push_back(ch);
  }
  out.push_back('"');
  return out;
}

std::string sql_literal_text(std::string_view text) {
  // Any control char (<0x20, including \0, \r, \n, \t) or DEL (0x7F) uses
  // CAST(X'...' AS TEXT) so sqlite3 CLI never strips \r or truncates at \0.
  if (has_control_or_nul(text)) {
    return "CAST(X'" + encode_hex_upper(text) + "' AS TEXT)";
  }
  std::string out;
  out.reserve(text.size() + 2U);
  out.push_back('\'');
  for (const char ch : text) {
    if (ch == '\'') {
      out.push_back('\'');
    }
    out.push_back(ch);
  }
  out.push_back('\'');
  return out;
}

Result<std::string> sql_literal_value(const Value &val) {
  const auto &storage = val.value();
  if (std::holds_alternative<std::nullptr_t>(storage)) {
    return Result<std::string>::success("NULL");
  }
  if (std::holds_alternative<bool>(storage)) {
    return Result<std::string>::success(std::get<bool>(storage) ? "1" : "0");
  }
  if (std::holds_alternative<Number>(storage)) {
    const Number &num = std::get<Number>(storage);
    const auto &nst = num.storage();
    if (std::holds_alternative<std::int64_t>(nst)) {
      return Result<std::string>::success(std::to_string(std::get<std::int64_t>(nst)));
    }
    if (std::holds_alternative<std::uint64_t>(nst)) {
      const std::uint64_t u = std::get<std::uint64_t>(nst);
      if (u <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return Result<std::string>::success(std::to_string(u));
      }
      return Result<std::string>::success(sql_literal_text(std::to_string(u)));
    }
    if (std::holds_alternative<double>(nst)) {
      const double d = std::get<double>(nst);
      if (!std::isfinite(d)) {
        return Result<std::string>::success("NULL");
      }
      return Result<std::string>::success(num.text());
    }
    // Exact Decimal representation
    return Result<std::string>::success(num.text());
  }
  if (std::holds_alternative<std::string>(storage)) {
    return Result<std::string>::success(
        sql_literal_text(std::get<std::string>(storage)));
  }
  // Nested Array / Object serialized to JSON text (queryable with JSON1).
  auto dumped = dump_json(val);
  if (!dumped.has_value()) {
    return fail<std::string>(ErrorCode::corrupt, SqliteError::ingest_parse_failed);
  }
  return Result<std::string>::success(sql_literal_text(dumped.value()));
}

std::string sanitize_column_name(std::string_view raw,
                                 std::set<std::string> &used_lower) {
  std::string cleaned;
  cleaned.reserve(std::min<std::size_t>(raw.size() + 8U, kMaxIdentifierLength));
  for (const char ch : raw) {
    const auto u = static_cast<unsigned char>(ch);
    if ((u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z') || (u >= '0' && u <= '9') ||
        u == '_') {
      cleaned.push_back(ch);
    } else {
      cleaned.push_back('_');
    }
    if (cleaned.size() >= kMaxIdentifierLength - 6U) {
      break;
    }
  }
  if (cleaned.empty() || (static_cast<unsigned char>(cleaned.front()) >= '0' &&
                          static_cast<unsigned char>(cleaned.front()) <= '9')) {
    cleaned.insert(0U, "col_");
  }
  const std::string low_prefix = ascii_lower(cleaned);
  if (low_prefix.starts_with("sqlite_") || low_prefix == kTaintRegistryTable) {
    cleaned.insert(0U, "c_");
  }
  if (cleaned.size() > kMaxIdentifierLength - 6U) {
    cleaned.resize(kMaxIdentifierLength - 6U);
  }

  std::string candidate = cleaned;
  std::size_t suffix = 2U;
  while (!used_lower.insert(ascii_lower(candidate)).second) {
    candidate = cleaned + "_" + std::to_string(suffix++);
  }
  return candidate;
}

enum class InferredColType : std::uint8_t {
  unknown = 0,
  integer = 1,
  real = 2,
  text = 3,
};

InferredColType merge_col_type(InferredColType current, const Value &val) noexcept {
  const auto &st = val.value();
  if (std::holds_alternative<std::nullptr_t>(st)) {
    return current;
  }
  InferredColType incoming = InferredColType::text;
  if (std::holds_alternative<bool>(st)) {
    incoming = InferredColType::integer;
  } else if (std::holds_alternative<Number>(st)) {
    const auto &nst = std::get<Number>(st).storage();
    if (std::holds_alternative<std::int64_t>(nst) ||
        std::holds_alternative<std::uint64_t>(nst)) {
      incoming = InferredColType::integer;
    } else {
      incoming = InferredColType::real;
    }
  }
  if (current == InferredColType::unknown) {
    return incoming;
  }
  if (current == incoming) {
    return current;
  }
  if ((current == InferredColType::integer && incoming == InferredColType::real) ||
      (current == InferredColType::real && incoming == InferredColType::integer)) {
    return InferredColType::real;
  }
  return InferredColType::text;
}

std::string_view col_type_sql(InferredColType type) noexcept {
  switch (type) {
  case InferredColType::integer:
    return "INTEGER";
  case InferredColType::real:
    return "REAL";
  case InferredColType::unknown:
  case InferredColType::text:
    return "TEXT";
  }
  return "TEXT";
}

// ---------------------------------------------------------------------------
// Pure C++ RFC 4180 CSV Parser (Preserves quotes, commas, newlines, NULs)
// ---------------------------------------------------------------------------

Result<std::vector<std::vector<std::string>>> parse_csv_rows(std::string_view csv) {
  // Strip UTF-8 BOM if present.
  if (csv.size() >= 3U && static_cast<unsigned char>(csv[0]) == 0xEFU &&
      static_cast<unsigned char>(csv[1]) == 0xBBU &&
      static_cast<unsigned char>(csv[2]) == 0xBFU) {
    csv.remove_prefix(3U);
  }
  if (csv.empty()) {
    return fail<std::vector<std::vector<std::string>>>(
        ErrorCode::invalid_range, SqliteError::ingest_parse_failed);
  }

  std::vector<std::vector<std::string>> rows;
  std::size_t i = 0U;
  while (i < csv.size()) {
    std::vector<std::string> row;
    for (;;) {
      std::string field;
      if (i < csv.size() && csv[i] == '"') {
        ++i;
        bool closed = false;
        while (i < csv.size()) {
          if (csv[i] == '"') {
            if (i + 1U < csv.size() && csv[i + 1U] == '"') {
              field.push_back('"');
              i += 2U;
              continue;
            }
            ++i;
            closed = true;
            break;
          }
          field.push_back(csv[i]);
          ++i;
        }
        if (!closed) {
          return fail<std::vector<std::vector<std::string>>>(
              ErrorCode::invalid_range, SqliteError::ingest_parse_failed);
        }
        row.push_back(std::move(field));
        if (i >= csv.size()) {
          break;
        }
        if (csv[i] == ',') {
          ++i;
          continue;
        }
        if (csv[i] == '\r') {
          ++i;
          if (i < csv.size() && csv[i] == '\n') {
            ++i;
          }
          break;
        }
        if (csv[i] == '\n') {
          ++i;
          break;
        }
        return fail<std::vector<std::vector<std::string>>>(
            ErrorCode::invalid_range, SqliteError::ingest_parse_failed);
      }

      // Unquoted field
      const std::size_t start = i;
      while (i < csv.size() && csv[i] != ',' && csv[i] != '\n' && csv[i] != '\r') {
        if (csv[i] == '"') {
          return fail<std::vector<std::vector<std::string>>>(
              ErrorCode::invalid_range, SqliteError::ingest_parse_failed);
        }
        ++i;
      }
      field.assign(csv.substr(start, i - start));
      row.push_back(std::move(field));

      if (i >= csv.size()) {
        break;
      }
      if (csv[i] == ',') {
        ++i;
        continue;
      }
      if (csv[i] == '\r') {
        ++i;
        if (i < csv.size() && csv[i] == '\n') {
          ++i;
        }
        break;
      }
      if (csv[i] == '\n') {
        ++i;
        break;
      }
    }
    rows.push_back(std::move(row));
  }

  return Result<std::vector<std::vector<std::string>>>::success(std::move(rows));
}

} // namespace

// ---------------------------------------------------------------------------
// Public Error Names & Validators
// ---------------------------------------------------------------------------

std::string_view sqlite_error_name(SqliteError detail) noexcept {
  switch (detail) {
  case SqliteError::none:
    return "none";
  case SqliteError::invalid_db_name:
    return "invalid_db_name";
  case SqliteError::invalid_table_name:
    return "invalid_table_name";
  case SqliteError::invalid_column_name:
    return "invalid_column_name";
  case SqliteError::invalid_sql:
    return "invalid_sql";
  case SqliteError::dot_command_rejected:
    return "dot_command_rejected";
  case SqliteError::forbidden_sql_rejected:
    return "forbidden_sql_rejected";
  case SqliteError::invalid_path:
    return "invalid_path";
  case SqliteError::symlink_rejected:
    return "symlink_rejected";
  case SqliteError::insecure_permissions:
    return "insecure_permissions";
  case SqliteError::binary_not_found:
    return "binary_not_found";
  case SqliteError::spawn_failed:
    return "spawn_failed";
  case SqliteError::timeout:
    return "timeout";
  case SqliteError::output_limit_exceeded:
    return "output_limit_exceeded";
  case SqliteError::sql_execution_failed:
    return "sql_execution_failed";
  case SqliteError::json_parse_failed:
    return "json_parse_failed";
  case SqliteError::ingest_parse_failed:
    return "ingest_parse_failed";
  case SqliteError::db_not_found:
    return "db_not_found";
  case SqliteError::db_already_exists:
    return "db_already_exists";
  case SqliteError::io_failed:
    return "io_failed";
  case SqliteError::invalid_config:
    return "invalid_config";
  case SqliteError::safe_mode_unsupported:
    return "safe_mode_unsupported";
  }
  return "unknown";
}

bool valid_db_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > kMaxDbNameLength) {
    return false;
  }
  for (const char ch : name) {
    const auto u = static_cast<unsigned char>(ch);
    const bool ok = (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z') ||
                    (u >= '0' && u <= '9') || u == '_' || u == '-';
    if (!ok) {
      return false;
    }
  }
  return true;
}

bool valid_sql_identifier(std::string_view name) noexcept {
  if (name.empty() || name.size() > kMaxIdentifierLength) {
    return false;
  }
  const auto first = static_cast<unsigned char>(name.front());
  if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ||
        first == '_')) {
    return false;
  }
  for (const char ch : name) {
    const auto u = static_cast<unsigned char>(ch);
    const bool ok = (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z') ||
                    (u >= '0' && u <= '9') || u == '_';
    if (!ok) {
      return false;
    }
  }
  const std::string lower = ascii_lower(name);
  if (lower.starts_with("sqlite_") || lower == kTaintRegistryTable) {
    return false;
  }
  return true;
}

Result<SqlAnalysis> validate_and_analyze_sql(std::string_view sql) {
  auto lexed = lex_sql(sql);
  if (!lexed.has_value()) {
    return Result<SqlAnalysis>::failure(lexed.error());
  }
  const std::vector<SqlToken> &tokens = lexed.value();
  if (tokens.empty()) {
    return fail<SqlAnalysis>(ErrorCode::invalid_range, SqliteError::invalid_sql);
  }

  SqlAnalysis analysis{};
  const std::size_t n = tokens.size();

  for (std::size_t i = 0U; i < n; ++i) {
    const SqlToken &tok = tokens[i];
    if (is_name_token(tok)) {
      const std::string lower = ascii_lower(tok.text);
      analysis.referenced_identifiers.insert(lower);

      if (tok.kind == SqlTokenKind::ident) {
        if (lower == "attach" || lower == "detach" || lower == "load_extension") {
          return fail<SqlAnalysis>(ErrorCode::unsupported,
                                   SqliteError::forbidden_sql_rejected);
        }
        // Reject VACUUM [schema] INTO '<file>' (arbitrary file write).
        if (lower == "vacuum") {
          std::size_t j = i + 1U;
          if (j < n && is_name_token(tokens[j]) &&
              ascii_lower(tokens[j].text) != "into") {
            ++j;
          }
          if (j < n && token_eq_ci(tokens[j], "into")) {
            return fail<SqlAnalysis>(ErrorCode::unsupported,
                                     SqliteError::forbidden_sql_rejected);
          }
        }
        // Reject dangerous PRAGMAs (even with schema prefix or single/double quotes).
        if (lower == "pragma") {
          std::size_t j = i + 1U;
          if (j + 2U < n && is_name_token(tokens[j]) &&
              tokens[j + 1U].kind == SqlTokenKind::punct &&
              tokens[j + 1U].text == ".") {
            j += 2U;
          }
          if (j < n && is_name_token(tokens[j])) {
            const std::string pragma_name = ascii_lower(tokens[j].text);
            if (pragma_name == "writable_schema" || pragma_name == "trusted_schema" ||
                pragma_name == "temp_store_directory" ||
                pragma_name == "data_store_directory") {
              return fail<SqlAnalysis>(ErrorCode::unsupported,
                                       SqliteError::forbidden_sql_rejected);
            }
          }
        }
      } else if (tok.kind == SqlTokenKind::quoted_ident) {
        // SQLite allows quoted function calls like "load_extension"('x') or
        // [load_extension]('x').
        if (lower == "load_extension" && i + 1U < n &&
            tokens[i + 1U].kind == SqlTokenKind::punct && tokens[i + 1U].text == "(") {
          return fail<SqlAnalysis>(ErrorCode::unsupported,
                                   SqliteError::forbidden_sql_rejected);
        }
      }

      // Track write targets for transitive taint propagation & registry protection.
      if (tok.kind == SqlTokenKind::ident) {
        if (lower == "insert" || lower == "replace" || lower == "update" ||
            lower == "delete" || lower == "drop" || lower == "alter" ||
            lower == "create") {
          analysis.has_write = true;
        }
        // INSERT [OR ...] INTO [schema.]<target> / REPLACE INTO [schema.]<target>
        if (lower == "into" && i + 1U < n) {
          std::size_t j = i + 1U;
          if (j + 2U < n && is_name_token(tokens[j]) &&
              tokens[j + 1U].kind == SqlTokenKind::punct &&
              tokens[j + 1U].text == ".") {
            j += 2U;
          }
          if (j < n && is_name_token(tokens[j])) {
            analysis.write_targets.insert(ascii_lower(tokens[j].text));
          }
        }
        // CREATE [TEMP|TEMPORARY] [VIRTUAL] (TABLE|VIEW) [IF NOT EXISTS]
        // [schema.]<target>
        if (lower == "create") {
          std::size_t j = i + 1U;
          while (j < n && tokens[j].kind == SqlTokenKind::ident) {
            const std::string kw = ascii_lower(tokens[j].text);
            if (kw == "temp" || kw == "temporary" || kw == "virtual" ||
                kw == "unique") {
              ++j;
              continue;
            }
            break;
          }
          if (j < n && tokens[j].kind == SqlTokenKind::ident) {
            const std::string obj_kind = ascii_lower(tokens[j].text);
            if (obj_kind == "table" || obj_kind == "view") {
              ++j;
              if (j + 2U < n && token_eq_ci(tokens[j], "if") &&
                  token_eq_ci(tokens[j + 1U], "not") &&
                  token_eq_ci(tokens[j + 2U], "exists")) {
                j += 3U;
              }
              if (j + 2U < n && is_name_token(tokens[j]) &&
                  tokens[j + 1U].kind == SqlTokenKind::punct &&
                  tokens[j + 1U].text == ".") {
                j += 2U;
              }
              if (j < n && is_name_token(tokens[j])) {
                analysis.write_targets.insert(ascii_lower(tokens[j].text));
              }
            }
          }
        }
        // UPDATE [OR ...] <target> / DELETE FROM <target> / DROP (TABLE|VIEW) [IF
        // EXISTS] <target> / ALTER TABLE <src> [RENAME TO <dst>]
        if (lower == "update" || lower == "delete" || lower == "drop" ||
            lower == "alter") {
          std::size_t j = i + 1U;
          if (lower == "update" && j + 1U < n && token_eq_ci(tokens[j], "or")) {
            j += 2U;
          } else if (lower == "delete" && j < n && token_eq_ci(tokens[j], "from")) {
            ++j;
          } else if (lower == "drop" && j < n &&
                     (token_eq_ci(tokens[j], "table") ||
                      token_eq_ci(tokens[j], "view"))) {
            ++j;
            if (j + 1U < n && token_eq_ci(tokens[j], "if") &&
                token_eq_ci(tokens[j + 1U], "exists")) {
              j += 2U;
            }
          } else if (lower == "alter" && j < n && token_eq_ci(tokens[j], "table")) {
            ++j;
          }
          if (j + 2U < n && is_name_token(tokens[j]) &&
              tokens[j + 1U].kind == SqlTokenKind::punct &&
              tokens[j + 1U].text == ".") {
            j += 2U;
          }
          if (j < n && is_name_token(tokens[j])) {
            analysis.write_targets.insert(ascii_lower(tokens[j].text));
            ++j;
          }
          // Capture ALTER TABLE <src> RENAME TO <dst> so taint cannot be
          // laundered by renaming a tainted table.
          if (lower == "alter") {
            for (std::size_t k = j; k < n; ++k) {
              if (tokens[k].kind == SqlTokenKind::punct && tokens[k].text == ";") {
                break;
              }
              if (token_eq_ci(tokens[k], "rename") && k + 2U < n &&
                  token_eq_ci(tokens[k + 1U], "to") && is_name_token(tokens[k + 2U])) {
                analysis.write_targets.insert(ascii_lower(tokens[k + 2U].text));
                break;
              }
            }
          }
        }
      }
    }
  }

  // Never allow user SQL to drop, delete, update, rename, or overwrite the taint
  // registry (regardless of unquoted, double-quoted, or single-quoted naming).
  const std::string taint_reg{kTaintRegistryTable};
  if (analysis.write_targets.contains(taint_reg) ||
      (analysis.has_write && analysis.referenced_identifiers.contains(taint_reg))) {
    return fail<SqlAnalysis>(ErrorCode::unsupported,
                             SqliteError::forbidden_sql_rejected);
  }

  return Result<SqlAnalysis>::success(std::move(analysis));
}

std::string compute_project_db_hash(const fs::path &project_root) {
  const fs::path canonical = canonicalize_lenient(project_root);
  return memory_sha256_hex(canonical.string());
}

Result<fs::path> resolve_default_model_state_dir(const lan::EnvLookupFn &env_lookup) {
  const auto xdg_data = lookup_env(env_lookup, "XDG_DATA_HOME");
  if (xdg_data.has_value() && !xdg_data->empty()) {
    const fs::path base{*xdg_data};
    if (base.is_absolute() && !has_control_or_nul(*xdg_data)) {
      return Result<fs::path>::success(base / "blackbird" / "model_memory");
    }
  }
  const auto home = lookup_env(env_lookup, "HOME");
  if (!home.has_value() || home->empty() || has_control_or_nul(*home)) {
    return fail<fs::path>(ErrorCode::invalid_range, SqliteError::invalid_path);
  }
  const fs::path home_path{*home};
  if (!home_path.is_absolute()) {
    return fail<fs::path>(ErrorCode::invalid_range, SqliteError::invalid_path);
  }
  return Result<fs::path>::success(home_path / ".local" / "share" / "blackbird" /
                                   "model_memory");
}

// ---------------------------------------------------------------------------
// Passive Capability Probe & CliSqliteBackend
// ---------------------------------------------------------------------------

Result<SqliteCapabilities>
probe_sqlite_capabilities(const std::optional<fs::path> &binary_override,
                          const lan::EnvLookupFn &env_lookup) {
#if defined(BLACKBIRD_HAS_EMBEDDED_SQLITE3) && BLACKBIRD_HAS_EMBEDDED_SQLITE3
  if (!binary_override.has_value() && !env_lookup) {
    return Result<SqliteCapabilities>::success(probe_embedded_sqlite_capabilities());
  }
#endif
  auto resolved = resolve_sqlite3_binary(binary_override, env_lookup);
  if (!resolved.has_value()) {
    return Result<SqliteCapabilities>::failure(resolved.error());
  }
  const fs::path &binary = resolved.value();
  const std::vector<std::string> env = build_minimal_sqlite_env(env_lookup);

  SqliteCapabilities caps{};
  caps.binary_path = binary;

  SubprocessLimits probe_limits{};
  probe_limits.timeout_ms = 3000U;
  probe_limits.max_stdout_bytes = kMaxProbeOutputBytes;

  // 1. Version probe
  auto ver_res = run_sqlite_subprocess(binary, {binary.string(), "--version"}, "", env,
                                       probe_limits);
  if (!ver_res.has_value() || ver_res.value().timed_out ||
      !ver_res.value().exited_normally || ver_res.value().exit_code != 0) {
    return fail<SqliteCapabilities>(ErrorCode::unsupported,
                                    SqliteError::binary_not_found);
  }
  {
    std::string_view out{ver_res.value().stdout_bytes};
    while (!out.empty() && std::isspace(static_cast<unsigned char>(out.front())) != 0) {
      out.remove_prefix(1U);
    }
    const std::size_t sp = out.find_first_of(" \t\r\n");
    caps.version = std::string{sp == std::string_view::npos ? out : out.substr(0U, sp)};
  }
  caps.available = true;

  // 2. -safe flag probe (passive against :memory:)
  {
    auto safe_res = run_sqlite_subprocess(
        binary, {binary.string(), "-safe", "-batch", "-bail", "-json", ":memory:"},
        "SELECT 1 AS ok;\n", env, probe_limits);
    caps.supports_safe_flag = safe_res.has_value() && !safe_res.value().timed_out &&
                              safe_res.value().exited_normally &&
                              safe_res.value().exit_code == 0;
  }

  // 3. -nofollow flag probe
  {
    std::vector<std::string> args = {binary.string()};
    if (caps.supports_safe_flag) {
      args.emplace_back("-safe");
    }
    args.emplace_back("-nofollow");
    args.emplace_back("-batch");
    args.emplace_back("-bail");
    args.emplace_back("-json");
    args.emplace_back(":memory:");
    auto nf_res =
        run_sqlite_subprocess(binary, args, "SELECT 1 AS ok;\n", env, probe_limits);
    caps.supports_nofollow_flag = nf_res.has_value() && !nf_res.value().timed_out &&
                                  nf_res.value().exited_normally &&
                                  nf_res.value().exit_code == 0;
  }

  // 4. Compile options probe (PRAGMA compile_options)
  {
    std::vector<std::string> args = {binary.string()};
    if (caps.supports_safe_flag) {
      args.emplace_back("-safe");
    }
    args.emplace_back("-batch");
    args.emplace_back("-bail");
    args.emplace_back("-json");
    args.emplace_back(":memory:");

    auto opt_res = run_sqlite_subprocess(binary, args, "PRAGMA compile_options;\n", env,
                                         probe_limits);
    if (opt_res.has_value() && !opt_res.value().timed_out &&
        opt_res.value().exited_normally && opt_res.value().exit_code == 0) {
      auto parsed = parse_complete_sqlite_json(opt_res.value().stdout_bytes, 512U);
      if (parsed.has_value()) {
        for (const Value &row : parsed.value().rows) {
          if (std::holds_alternative<Value::Object>(row.value())) {
            const Value *col = row.find("compile_options");
            if (col != nullptr && std::holds_alternative<std::string>(col->value())) {
              const std::string &opt = col->string();
              caps.compile_options.push_back(opt);
              if (opt == "ENABLE_FTS5") {
                caps.supports_fts5 = true;
              }
              if (opt == "ENABLE_JSON1") {
                caps.supports_json1 = true;
              }
            }
          }
        }
      }
    }

    // Direct functional probe for FTS5 & JSON1 in :memory: (SQLite 3.38+ enables
    // JSON1 by default without listing ENABLE_JSON1 in compile_options).
    if (!caps.supports_fts5) {
      auto fts_res = run_sqlite_subprocess(
          binary, args, "CREATE VIRTUAL TABLE _bb_fts_probe USING fts5(body);\n", env,
          probe_limits);
      caps.supports_fts5 = fts_res.has_value() && !fts_res.value().timed_out &&
                           fts_res.value().exited_normally &&
                           fts_res.value().exit_code == 0;
    }
    if (!caps.supports_json1) {
      auto json_res = run_sqlite_subprocess(
          binary, args, "SELECT json_extract('{\"a\":1}', '$.a') AS j;\n", env,
          probe_limits);
      caps.supports_json1 =
          json_res.has_value() && !json_res.value().timed_out &&
          json_res.value().exited_normally && json_res.value().exit_code == 0 &&
          json_res.value().stdout_bytes.find('1') != std::string::npos;
    }
  }

  return Result<SqliteCapabilities>::success(std::move(caps));
}

CliSqliteBackend::CliSqliteBackend(CliSqliteBackendConfig config)
    : config_(std::move(config)) {}

Result<SqliteCapabilities> CliSqliteBackend::probe() const {
  return probe_sqlite_capabilities(config_.binary_override, config_.env_lookup);
}

Result<SqliteCapabilities> CliSqliteBackend::ensure_probed() {
  if (cached_capabilities_.has_value()) {
    return Result<SqliteCapabilities>::success(*cached_capabilities_);
  }
  auto probed = probe();
  if (!probed.has_value()) {
    return Result<SqliteCapabilities>::failure(probed.error());
  }
  cached_capabilities_ = probed.value();
  return Result<SqliteCapabilities>::success(*cached_capabilities_);
}

Result<SqliteBackendResponse>
CliSqliteBackend::execute(const SqliteBackendRequest &request) {
  if (request.db_path.empty() || has_control_or_nul(request.db_path.string())) {
    return fail<SqliteBackendResponse>(ErrorCode::invalid_range,
                                       SqliteError::invalid_path);
  }
  auto probed = ensure_probed();
  if (!probed.has_value()) {
    return Result<SqliteBackendResponse>::failure(probed.error());
  }
  const SqliteCapabilities &caps = probed.value();
  if (config_.require_safe_mode && !caps.supports_safe_flag) {
    return fail<SqliteBackendResponse>(ErrorCode::unsupported,
                                       SqliteError::safe_mode_unsupported);
  }

  std::vector<std::string> args;
  args.reserve(12U);
  args.push_back(caps.binary_path.string());
  if (caps.supports_safe_flag) {
    args.emplace_back("-safe");
  }
  args.emplace_back("-batch");
  args.emplace_back("-bail");
  args.emplace_back("-json");
  if (caps.supports_nofollow_flag) {
    args.emplace_back("-nofollow");
  }
  if (request.limits.read_only) {
    args.emplace_back("-readonly");
  }
  args.emplace_back("-cmd");
  args.push_back(".timeout " + std::to_string(request.limits.busy_timeout_ms));
  args.emplace_back("--");
  args.push_back(request.db_path.string());

  std::string payload = request.sql;
  if (payload.empty() || payload.back() != '\n') {
    payload.push_back('\n');
  }

  SubprocessLimits proc_limits{};
  proc_limits.timeout_ms = request.limits.timeout_ms;
  proc_limits.max_stdout_bytes = request.limits.max_output_bytes == 0U
                                     ? kDefaultMaxOutputBytes
                                     : request.limits.max_output_bytes;
  proc_limits.max_stderr_bytes = kMaxStderrBytes;

  const std::vector<std::string> env = build_minimal_sqlite_env(config_.env_lookup);
  auto proc = run_sqlite_subprocess(caps.binary_path, args, payload, env, proc_limits);
  if (!proc.has_value()) {
    return Result<SqliteBackendResponse>::failure(proc.error());
  }

  const SubprocessResult &sub = proc.value();
  if (sub.timed_out) {
    return fail<SqliteBackendResponse>(ErrorCode::io, SqliteError::timeout);
  }
  if (!sub.exited_normally || sub.exit_code != 0) {
    return fail<SqliteBackendResponse>(ErrorCode::io,
                                       SqliteError::sql_execution_failed);
  }

  SqliteBackendResponse response{};
  response.output_bytes = sub.stdout_bytes.size();
  response.truncated_bytes = sub.stdout_truncated;
  response.stderr_text = sub.stderr_bytes;
  response.duration_ns = sub.duration_ns;

  if (!sub.stdout_bytes.empty()) {
    const std::size_t row_cap =
        request.limits.max_rows == 0U ? kDefaultMaxRows : request.limits.max_rows;
    if (sub.stdout_truncated) {
      ParsedJsonRows partial =
          parse_truncated_sqlite_json_prefix(sub.stdout_bytes, row_cap);
      response.rows = std::move(partial.rows);
      response.columns = std::move(partial.columns);
      response.total_rows_seen = partial.total_rows_seen;
      response.truncated_rows = partial.truncated_rows;
    } else {
      auto parsed = parse_complete_sqlite_json(sub.stdout_bytes, row_cap);
      if (!parsed.has_value()) {
        return Result<SqliteBackendResponse>::failure(parsed.error());
      }
      response.rows = std::move(parsed.value().rows);
      response.columns = std::move(parsed.value().columns);
      response.total_rows_seen = parsed.value().total_rows_seen;
      response.truncated_rows = parsed.value().truncated_rows;
    }
  }

  return Result<SqliteBackendResponse>::success(std::move(response));
}

// ---------------------------------------------------------------------------
// SqliteWorkbench Implementation
// ---------------------------------------------------------------------------

SqliteWorkbench::SqliteWorkbench(SqliteWorkbenchConfig config,
                                 std::unique_ptr<ISqliteBackend> backend)
    : config_(std::move(config)), backend_(std::move(backend)) {
  if (!backend_) {
#if defined(BLACKBIRD_HAS_EMBEDDED_SQLITE3) && BLACKBIRD_HAS_EMBEDDED_SQLITE3
    if (!config_.sqlite_binary_override.has_value()) {
      backend_ = std::make_unique<EmbeddedSqliteBackend>();
      return;
    }
#endif
    CliSqliteBackendConfig cli_cfg{};
    cli_cfg.binary_override = config_.sqlite_binary_override;
    cli_cfg.env_lookup = config_.env_lookup;
    backend_ = std::make_unique<CliSqliteBackend>(std::move(cli_cfg));
  }
}

SqliteWorkbench::~SqliteWorkbench() { destroy_all_scratch(); }

SqliteWorkbench::SqliteWorkbench(SqliteWorkbench &&other) noexcept
    : config_(std::move(other.config_)), backend_(std::move(other.backend_)),
      scratch_session_dir_(std::exchange(other.scratch_session_dir_, std::nullopt)),
      scratch_dir_dev_(std::exchange(other.scratch_dir_dev_, 0U)),
      scratch_dir_ino_(std::exchange(other.scratch_dir_ino_, 0U)),
      scratch_dbs_(std::move(other.scratch_dbs_)),
      model_dbs_(std::move(other.model_dbs_)) {
  other.scratch_dbs_.clear();
  other.model_dbs_.clear();
}

SqliteWorkbench &SqliteWorkbench::operator=(SqliteWorkbench &&other) noexcept {
  if (this != &other) {
    destroy_all_scratch();
    config_ = std::move(other.config_);
    backend_ = std::move(other.backend_);
    scratch_session_dir_ = std::exchange(other.scratch_session_dir_, std::nullopt);
    scratch_dir_dev_ = std::exchange(other.scratch_dir_dev_, 0U);
    scratch_dir_ino_ = std::exchange(other.scratch_dir_ino_, 0U);
    scratch_dbs_ = std::move(other.scratch_dbs_);
    model_dbs_ = std::move(other.model_dbs_);
    other.scratch_dbs_.clear();
    other.model_dbs_.clear();
  }
  return *this;
}

Result<SqliteCapabilities> SqliteWorkbench::probe_capabilities() const {
  if (!backend_) {
    return fail<SqliteCapabilities>(ErrorCode::unsupported,
                                    SqliteError::invalid_config);
  }
  return backend_->probe();
}

std::optional<fs::path> SqliteWorkbench::scratch_session_dir() const {
  return scratch_session_dir_;
}

Result<void> SqliteWorkbench::ensure_scratch_session_dir() {
  if (scratch_session_dir_.has_value()) {
    auto dir_fd = open_verified_dir_nofollow(*scratch_session_dir_,
                                             /*require_owner_only=*/true);
    if (!dir_fd.has_value()) {
      return Result<void>::failure(dir_fd.error());
    }
    struct stat st{};
    if (::fstat(dir_fd.value().get(), &st) != 0 ||
        static_cast<std::uint64_t>(st.st_dev) != scratch_dir_dev_ ||
        static_cast<std::uint64_t>(st.st_ino) != scratch_dir_ino_) {
      return fail<void>(ErrorCode::io, SqliteError::symlink_rejected);
    }
    return Result<void>::success();
  }

  fs::path parent;
  if (config_.scratch_parent_dir.has_value()) {
    parent = *config_.scratch_parent_dir;
    if (parent.empty() || has_control_or_nul(parent.string())) {
      return fail<void>(ErrorCode::invalid_range, SqliteError::invalid_path);
    }
    struct stat pst{};
    if (::lstat(parent.c_str(), &pst) == 0 && S_ISLNK(pst.st_mode)) {
      return fail<void>(ErrorCode::io, SqliteError::symlink_rejected);
    }
  } else {
    std::error_code ec;
    parent = fs::temp_directory_path(ec);
    if (ec || parent.empty()) {
      return fail<void>(ErrorCode::io, SqliteError::invalid_path);
    }
  }

  for (int attempt = 0; attempt < 16; ++attempt) {
    const std::string dirname = "blackbird-scratch-" +
                                std::to_string(static_cast<std::uint64_t>(::getpid())) +
                                "-" + random_hex_16();
    const fs::path candidate = parent / dirname;
    if (::mkdir(candidate.c_str(), mode_t{0700}) == 0) {
      (void)::chmod(candidate.c_str(), mode_t{0700});
      auto dir_fd = open_verified_dir_nofollow(candidate, /*require_owner_only=*/true);
      if (!dir_fd.has_value()) {
        (void)::rmdir(candidate.c_str());
        return Result<void>::failure(dir_fd.error());
      }
      struct stat st{};
      if (::fstat(dir_fd.value().get(), &st) != 0) {
        (void)::rmdir(candidate.c_str());
        return fail<void>(ErrorCode::io, SqliteError::io_failed);
      }
      // Resolve OS mount symlinks (e.g. /var -> /private/var on macOS) after
      // O_NOFOLLOW verification so sqlite3 -nofollow accepts the canonical path.
      const fs::path canonical_dir = canonicalize_lenient(candidate);
      scratch_session_dir_ = canonical_dir;
      scratch_dir_dev_ = static_cast<std::uint64_t>(st.st_dev);
      scratch_dir_ino_ = static_cast<std::uint64_t>(st.st_ino);
      return Result<void>::success();
    }
    if (errno != EEXIST) {
      return fail<void>(ErrorCode::io, SqliteError::io_failed);
    }
  }
  return fail<void>(ErrorCode::busy, SqliteError::io_failed);
}

void SqliteWorkbench::destroy_all_scratch() noexcept {
  if (!scratch_session_dir_.has_value()) {
    scratch_dbs_.clear();
    return;
  }
  const fs::path dir = *scratch_session_dir_;
  auto dir_fd = open_verified_dir_nofollow(dir, /*require_owner_only=*/true);
  if (dir_fd.has_value()) {
    struct stat st{};
    const bool identity_ok =
        (::fstat(dir_fd.value().get(), &st) == 0 &&
         static_cast<std::uint64_t>(st.st_dev) == scratch_dir_dev_ &&
         static_cast<std::uint64_t>(st.st_ino) == scratch_dir_ino_);
    if (identity_ok) {
      static constexpr std::array<std::string_view, 4> kSuffixes = {"", "-wal", "-shm",
                                                                    "-journal"};
      for (const auto &[key, entry] : scratch_dbs_) {
        (void)key;
        for (const std::string_view suffix : kSuffixes) {
          const std::string fname = entry.filename + std::string{suffix};
          (void)::unlinkat(dir_fd.value().get(), fname.c_str(), 0);
        }
      }
    }
  }
  scratch_dbs_.clear();
  (void)::rmdir(dir.c_str());
  scratch_session_dir_.reset();
  scratch_dir_dev_ = 0U;
  scratch_dir_ino_ = 0U;
}

Result<SqliteDbHandle> SqliteWorkbench::open_scratch(std::string_view name) {
  if (!valid_db_name(name)) {
    return fail<SqliteDbHandle>(ErrorCode::invalid_range, SqliteError::invalid_db_name);
  }
  auto dir_ok = ensure_scratch_session_dir();
  if (!dir_ok.has_value()) {
    return Result<SqliteDbHandle>::failure(dir_ok.error());
  }
  if (!scratch_session_dir_.has_value()) {
    return fail<SqliteDbHandle>(ErrorCode::io, SqliteError::io_failed);
  }
  const fs::path &session_dir = *scratch_session_dir_;
  auto dir_fd = open_verified_dir_nofollow(session_dir, /*require_owner_only=*/true);
  if (!dir_fd.has_value()) {
    return Result<SqliteDbHandle>::failure(dir_fd.error());
  }

  const std::string key{name};
  const std::string filename = key + ".db";
  auto file_ok = ensure_restricted_db_file(dir_fd.value().get(), filename);
  if (!file_ok.has_value()) {
    return Result<SqliteDbHandle>::failure(file_ok.error());
  }
  auto sidecar_ok = verify_sidecars_safe(dir_fd.value().get(), filename);
  if (!sidecar_ok.has_value()) {
    return Result<SqliteDbHandle>::failure(sidecar_ok.error());
  }

  const fs::path db_path = session_dir / filename;
  SqliteDbHandle handle{SqliteDbScope::scratch, key, db_path};

  auto it = scratch_dbs_.find(key);
  if (it == scratch_dbs_.end()) {
    DbEntry entry{};
    entry.handle = handle;
    entry.parent_dir = session_dir;
    entry.filename = filename;
    entry.parent_dev = scratch_dir_dev_;
    entry.parent_ino = scratch_dir_ino_;
    scratch_dbs_.emplace(key, std::move(entry));
  }

  // Initialize foreign_keys pragma to verify DB is writable & valid.
  SqliteBackendRequest init_req{};
  init_req.db_path = db_path;
  init_req.sql = "PRAGMA foreign_keys = ON;";
  init_req.limits = config_.default_limits;
  init_req.expect_rows = false;
  auto init_res = backend_->execute(init_req);
  if (!init_res.has_value()) {
    return Result<SqliteDbHandle>::failure(init_res.error());
  }
  tighten_sidecars_in_dir(dir_fd.value().get(), filename);

  return Result<SqliteDbHandle>::success(std::move(handle));
}

Result<void> SqliteWorkbench::close_scratch(std::string_view name) {
  if (!valid_db_name(name)) {
    return fail<void>(ErrorCode::invalid_range, SqliteError::invalid_db_name);
  }
  const std::string key{name};
  auto it = scratch_dbs_.find(key);
  if (it == scratch_dbs_.end()) {
    return fail<void>(ErrorCode::invalid_identity, SqliteError::db_not_found);
  }
  if (!scratch_session_dir_.has_value()) {
    scratch_dbs_.erase(it);
    return Result<void>::success();
  }
  auto dir_fd = open_verified_dir_nofollow(*scratch_session_dir_,
                                           /*require_owner_only=*/true);
  if (!dir_fd.has_value()) {
    return Result<void>::failure(dir_fd.error());
  }
  struct stat st{};
  if (::fstat(dir_fd.value().get(), &st) != 0 ||
      static_cast<std::uint64_t>(st.st_dev) != scratch_dir_dev_ ||
      static_cast<std::uint64_t>(st.st_ino) != scratch_dir_ino_) {
    return fail<void>(ErrorCode::io, SqliteError::symlink_rejected);
  }

  static constexpr std::array<std::string_view, 4> kSuffixes = {"", "-wal", "-shm",
                                                                "-journal"};
  for (const std::string_view suffix : kSuffixes) {
    const std::string fname = it->second.filename + std::string{suffix};
    if (::unlinkat(dir_fd.value().get(), fname.c_str(), 0) != 0 && errno != ENOENT) {
      return fail<void>(ErrorCode::io, SqliteError::io_failed);
    }
  }
  scratch_dbs_.erase(it);
  return Result<void>::success();
}

Result<SqliteDbHandle>
SqliteWorkbench::open_model_db(const std::optional<fs::path> &project_root_override) {
  fs::path state_dir;
  if (config_.model_state_dir.has_value()) {
    state_dir = *config_.model_state_dir;
  } else {
    auto resolved = resolve_default_model_state_dir(config_.env_lookup);
    if (!resolved.has_value()) {
      return Result<SqliteDbHandle>::failure(resolved.error());
    }
    state_dir = std::move(resolved).value();
  }

  if (state_dir.empty() || has_control_or_nul(state_dir.string())) {
    return fail<SqliteDbHandle>(ErrorCode::invalid_range, SqliteError::invalid_path);
  }

  const std::optional<fs::path> project_root =
      project_root_override.has_value() ? project_root_override : config_.project_root;
  if (!project_root.has_value() || project_root->empty() ||
      has_control_or_nul(project_root->string())) {
    return fail<SqliteDbHandle>(ErrorCode::invalid_range, SqliteError::invalid_path);
  }

  // Enforce strict isolation from project workspace and authoritative
  // Journal/Originals.
  if (paths_overlap(state_dir, *project_root)) {
    return fail<SqliteDbHandle>(ErrorCode::invalid_range, SqliteError::invalid_path);
  }
  for (const fs::path &forbidden : config_.forbidden_journal_dirs) {
    if (!forbidden.empty() && paths_overlap(state_dir, forbidden)) {
      return fail<SqliteDbHandle>(ErrorCode::invalid_range, SqliteError::invalid_path);
    }
  }

  auto dir_fd = ensure_restricted_dir(state_dir);
  if (!dir_fd.has_value()) {
    return Result<SqliteDbHandle>::failure(dir_fd.error());
  }
  struct stat dir_st{};
  if (::fstat(dir_fd.value().get(), &dir_st) != 0) {
    return fail<SqliteDbHandle>(ErrorCode::io, SqliteError::io_failed);
  }
  // Canonicalize after O_NOFOLLOW verification so OS mount symlinks (/var ->
  // /private/var on macOS) do not trip sqlite3 -nofollow.
  const fs::path canonical_state_dir = canonicalize_lenient(state_dir);

  const std::string hash = compute_project_db_hash(*project_root);
  const std::string filename = hash + ".db";

  auto file_ok = ensure_restricted_db_file(dir_fd.value().get(), filename);
  if (!file_ok.has_value()) {
    return Result<SqliteDbHandle>::failure(file_ok.error());
  }
  auto sidecar_ok = verify_sidecars_safe(dir_fd.value().get(), filename);
  if (!sidecar_ok.has_value()) {
    return Result<SqliteDbHandle>::failure(sidecar_ok.error());
  }

  const fs::path db_path = canonical_state_dir / filename;
  SqliteDbHandle handle{SqliteDbScope::model_private, hash, db_path};

  // Configure WAL mode + NORMAL sync + foreign_keys.
  SqliteBackendRequest wal_req{};
  wal_req.db_path = db_path;
  wal_req.sql = "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA "
                "foreign_keys = ON;";
  wal_req.limits = config_.default_limits;
  wal_req.expect_rows = true;
  auto wal_res = backend_->execute(wal_req);
  if (!wal_res.has_value()) {
    return Result<SqliteDbHandle>::failure(wal_res.error());
  }

  // Confirm WAL mode succeeded.
  bool wal_confirmed = false;
  for (const Value &row : wal_res.value().rows) {
    if (std::holds_alternative<Value::Object>(row.value())) {
      const Value *jm = row.find("journal_mode");
      if (jm != nullptr && std::holds_alternative<std::string>(jm->value()) &&
          ascii_lower(jm->string()) == "wal") {
        wal_confirmed = true;
        break;
      }
    }
  }
  if (!wal_confirmed) {
    return fail<SqliteDbHandle>(ErrorCode::io, SqliteError::sql_execution_failed);
  }

  tighten_sidecars_in_dir(dir_fd.value().get(), filename);

  auto [it, inserted] = model_dbs_.try_emplace(hash);
  DbEntry &entry = it->second;
  entry.handle = handle;
  entry.parent_dir = canonical_state_dir;
  entry.filename = filename;
  entry.parent_dev = static_cast<std::uint64_t>(dir_st.st_dev);
  entry.parent_ino = static_cast<std::uint64_t>(dir_st.st_ino);
  if (inserted) {
    load_persisted_taint(entry);
  }

  return Result<SqliteDbHandle>::success(std::move(handle));
}

Result<SqliteWorkbench::DbEntry *>
SqliteWorkbench::lookup_and_verify_db(const SqliteDbHandle &db) {
  auto &table = (db.scope == SqliteDbScope::scratch) ? scratch_dbs_ : model_dbs_;
  auto it = table.find(db.name);
  if (it == table.end() || it->second.handle.path != db.path) {
    return fail<DbEntry *>(ErrorCode::invalid_identity, SqliteError::db_not_found);
  }
  DbEntry &entry = it->second;

  auto dir_fd = open_verified_dir_nofollow(entry.parent_dir,
                                           /*require_owner_only=*/true);
  if (!dir_fd.has_value()) {
    return Result<DbEntry *>::failure(dir_fd.error());
  }
  struct stat dir_st{};
  if (::fstat(dir_fd.value().get(), &dir_st) != 0 ||
      static_cast<std::uint64_t>(dir_st.st_dev) != entry.parent_dev ||
      static_cast<std::uint64_t>(dir_st.st_ino) != entry.parent_ino) {
    return fail<DbEntry *>(ErrorCode::io, SqliteError::symlink_rejected);
  }

  auto file_ok = ensure_restricted_db_file(dir_fd.value().get(), entry.filename);
  if (!file_ok.has_value()) {
    return Result<DbEntry *>::failure(file_ok.error());
  }
  auto sidecar_ok = verify_sidecars_safe(dir_fd.value().get(), entry.filename);
  if (!sidecar_ok.has_value()) {
    return Result<DbEntry *>::failure(sidecar_ok.error());
  }

  return Result<DbEntry *>::success(&entry);
}

const SqliteWorkbench::DbEntry *
SqliteWorkbench::find_db_const(const SqliteDbHandle &db) const {
  const auto &table = (db.scope == SqliteDbScope::scratch) ? scratch_dbs_ : model_dbs_;
  const auto it = table.find(db.name);
  if (it == table.end() || it->second.handle.path != db.path) {
    return nullptr;
  }
  return &it->second;
}

void SqliteWorkbench::tighten_sidecars_locked(const DbEntry &entry) const noexcept {
  auto dir_fd = open_verified_dir_nofollow(entry.parent_dir,
                                           /*require_owner_only=*/true);
  if (dir_fd.has_value()) {
    tighten_sidecars_in_dir(dir_fd.value().get(), entry.filename);
  }
}

Result<void> SqliteWorkbench::persist_taint_entry(DbEntry &entry,
                                                  std::string_view scope_key,
                                                  bool is_db_wide) {
  if (entry.handle.scope != SqliteDbScope::model_private) {
    return Result<void>::success();
  }
  const std::string sql =
      "BEGIN IMMEDIATE; "
      "CREATE TABLE IF NOT EXISTS " +
      sql_quote_ident(kTaintRegistryTable) +
      " (\"scope_key\" TEXT PRIMARY KEY, \"is_db_wide\" INTEGER NOT NULL); "
      "INSERT OR REPLACE INTO " +
      sql_quote_ident(kTaintRegistryTable) +
      " (\"scope_key\", \"is_db_wide\") VALUES (" + sql_literal_text(scope_key) + ", " +
      (is_db_wide ? "1" : "0") + "); COMMIT;";
  SqliteBackendRequest req{};
  req.db_path = entry.handle.path;
  req.sql = sql;
  req.limits = config_.default_limits;
  req.expect_rows = false;
  req.internal_taint_registry_write = true;
  auto res = backend_->execute(req);
  tighten_sidecars_locked(entry);
  if (!res.has_value()) {
    return Result<void>::failure(res.error());
  }
  return Result<void>::success();
}

void SqliteWorkbench::load_persisted_taint(DbEntry &entry) {
  if (entry.handle.scope != SqliteDbScope::model_private) {
    return;
  }
  SqliteBackendRequest check_req{};
  check_req.db_path = entry.handle.path;
  check_req.sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=" +
                  sql_literal_text(kTaintRegistryTable) + ";";
  check_req.limits = config_.default_limits;
  check_req.expect_rows = true;
  auto check_res = backend_->execute(check_req);
  if (!check_res.has_value() || check_res.value().rows.empty()) {
    return;
  }

  SqliteBackendRequest load_req{};
  load_req.db_path = entry.handle.path;
  load_req.sql = "SELECT \"scope_key\", \"is_db_wide\" FROM " +
                 sql_quote_ident(kTaintRegistryTable) + ";";
  load_req.limits = config_.default_limits;
  load_req.limits.max_rows = 4096U;
  load_req.expect_rows = true;
  auto load_res = backend_->execute(load_req);
  if (!load_res.has_value()) {
    return;
  }
  for (const Value &row : load_res.value().rows) {
    if (!std::holds_alternative<Value::Object>(row.value())) {
      continue;
    }
    const Value *key_val = row.find("scope_key");
    const Value *wide_val = row.find("is_db_wide");
    if (key_val == nullptr || !std::holds_alternative<std::string>(key_val->value())) {
      continue;
    }
    const std::string &scope_key = key_val->string();
    bool is_wide = false;
    if (wide_val != nullptr && std::holds_alternative<Number>(wide_val->value())) {
      const auto &nst = wide_val->number().storage();
      if (std::holds_alternative<std::int64_t>(nst)) {
        is_wide = (std::get<std::int64_t>(nst) != 0);
      } else if (std::holds_alternative<std::uint64_t>(nst)) {
        is_wide = (std::get<std::uint64_t>(nst) != 0U);
      }
    }
    if (is_wide || scope_key == kDbWideTaintKey) {
      entry.db_tainted = true;
    } else {
      entry.tainted_tables.insert(ascii_lower(scope_key));
    }
  }
}

bool SqliteWorkbench::is_turn_tainted() const noexcept {
  return config_.turn_taint != nullptr && config_.turn_taint->is_tainted();
}

void SqliteWorkbench::latch_turn_taint_on_read() noexcept {
  if (config_.turn_taint == nullptr) {
    return;
  }
  brakes::PeerProvenance provenance{};
  provenance.origin = brakes::PeerOriginKind::external_mcp;
  provenance.effective_trust = brakes::PartyTrustProfile::advisory;
  (void)config_.turn_taint->ingest(provenance, config_.party_trust_policy);
}

Result<SqliteQueryResult>
SqliteWorkbench::run_guarded_sql(const SqliteDbHandle &db, std::string_view sql,
                                 std::optional<SqliteExecLimits> limits,
                                 bool expect_rows) {
  auto analysis = validate_and_analyze_sql(sql);
  if (!analysis.has_value()) {
    return Result<SqliteQueryResult>::failure(analysis.error());
  }
  auto entry_res = lookup_and_verify_db(db);
  if (!entry_res.has_value()) {
    return Result<SqliteQueryResult>::failure(entry_res.error());
  }
  DbEntry *entry = entry_res.value();

  // Check if SQL touches any tainted DB or table.
  bool touches_tainted = entry->db_tainted;
  if (!touches_tainted) {
    for (const std::string &ident : analysis.value().referenced_identifiers) {
      if (entry->tainted_tables.contains(ident)) {
        touches_tainted = true;
        break;
      }
    }
  }

  SqliteBackendRequest req{};
  req.db_path = entry->handle.path;
  req.sql = std::string{sql};
  req.limits = limits.value_or(config_.default_limits);
  req.expect_rows = expect_rows;

  auto exec_res = backend_->execute(req);
  tighten_sidecars_locked(*entry);
  if (!exec_res.has_value()) {
    return Result<SqliteQueryResult>::failure(exec_res.error());
  }

  // Transitive taint propagation: if a write statement read tainted data OR executed
  // while TurnTaintState is tainted, taint all write targets (or the DB if targets
  // could not be statically extracted).
  const bool taint_propagates_to_writes =
      analysis.value().has_write && (touches_tainted || is_turn_tainted());
  if (taint_propagates_to_writes) {
    if (analysis.value().write_targets.empty()) {
      entry->db_tainted = true;
      auto persisted =
          persist_taint_entry(*entry, kDbWideTaintKey, /*is_db_wide=*/true);
      if (!persisted.has_value()) {
        return Result<SqliteQueryResult>::failure(persisted.error());
      }
    } else {
      for (const std::string &target : analysis.value().write_targets) {
        entry->tainted_tables.insert(target);
        auto persisted = persist_taint_entry(*entry, target, /*is_db_wide=*/false);
        if (!persisted.has_value()) {
          return Result<SqliteQueryResult>::failure(persisted.error());
        }
      }
    }
  }

  SqliteQueryResult out{};
  out.rows = std::move(exec_res.value().rows);
  out.columns = std::move(exec_res.value().columns);
  out.total_rows_seen = exec_res.value().total_rows_seen;
  out.output_bytes = exec_res.value().output_bytes;
  out.truncated_rows = exec_res.value().truncated_rows;
  out.truncated_bytes = exec_res.value().truncated_bytes;
  out.contains_tainted_data = touches_tainted;
  out.stderr_text = std::move(exec_res.value().stderr_text);
  out.duration_ns = exec_res.value().duration_ns;

  if (out.contains_tainted_data) {
    latch_turn_taint_on_read();
  }

  return Result<SqliteQueryResult>::success(std::move(out));
}

Result<SqliteQueryResult>
SqliteWorkbench::exec(const SqliteDbHandle &db, std::string_view sql,
                      std::optional<SqliteExecLimits> limits) {
  return run_guarded_sql(db, sql, limits, /*expect_rows=*/false);
}

Result<SqliteQueryResult>
SqliteWorkbench::query(const SqliteDbHandle &db, std::string_view sql,
                       std::optional<SqliteExecLimits> limits) {
  return run_guarded_sql(db, sql, limits, /*expect_rows=*/true);
}

Result<void> SqliteWorkbench::mark_db_tainted(const SqliteDbHandle &db) {
  auto entry_res = lookup_and_verify_db(db);
  if (!entry_res.has_value()) {
    return Result<void>::failure(entry_res.error());
  }
  DbEntry *entry = entry_res.value();
  entry->db_tainted = true;
  return persist_taint_entry(*entry, kDbWideTaintKey, /*is_db_wide=*/true);
}

Result<void> SqliteWorkbench::mark_table_tainted(const SqliteDbHandle &db,
                                                 TableName table) {
  if (!valid_sql_identifier(table.value)) {
    return fail<void>(ErrorCode::invalid_range, SqliteError::invalid_table_name);
  }
  auto entry_res = lookup_and_verify_db(db);
  if (!entry_res.has_value()) {
    return Result<void>::failure(entry_res.error());
  }
  DbEntry *entry = entry_res.value();
  const std::string lower = ascii_lower(table.value);
  entry->tainted_tables.insert(lower);
  return persist_taint_entry(*entry, lower, /*is_db_wide=*/false);
}

bool SqliteWorkbench::is_db_tainted(const SqliteDbHandle &db) const {
  const DbEntry *entry = find_db_const(db);
  return entry != nullptr && entry->db_tainted;
}

bool SqliteWorkbench::is_table_tainted(const SqliteDbHandle &db,
                                       TableName table) const {
  const DbEntry *entry = find_db_const(db);
  if (entry == nullptr) {
    return false;
  }
  if (entry->db_tainted) {
    return true;
  }
  return entry->tainted_tables.contains(ascii_lower(table.value));
}

// ---------------------------------------------------------------------------
// Structural Bulk Ingestors (Pure C++ -> Escaped Transactional INSERTs)
// ---------------------------------------------------------------------------

Result<SqliteIngestResult> SqliteWorkbench::ingest_records(const SqliteDbHandle &db,
                                                           TableName table,
                                                           const Value::Array &records,
                                                           bool tainted) {
  if (!valid_sql_identifier(table.value)) {
    return fail<SqliteIngestResult>(ErrorCode::invalid_range,
                                    SqliteError::invalid_table_name);
  }
  auto entry_res = lookup_and_verify_db(db);
  if (!entry_res.has_value()) {
    return Result<SqliteIngestResult>::failure(entry_res.error());
  }
  DbEntry *entry = entry_res.value();
  const bool effective_tainted = tainted || is_turn_tainted();

  // Discover union of keys and infer column types.
  std::vector<std::string> raw_keys;
  std::unordered_map<std::string, std::size_t> key_index;
  std::vector<InferredColType> col_types;

  for (const Value &rec : records) {
    if (!std::holds_alternative<Value::Object>(rec.value())) {
      return fail<SqliteIngestResult>(ErrorCode::invalid_range,
                                      SqliteError::ingest_parse_failed);
    }
    for (const auto &[key, val] : rec.object()) {
      auto it = key_index.find(key);
      if (it == key_index.end()) {
        const std::size_t idx = raw_keys.size();
        key_index.emplace(key, idx);
        raw_keys.push_back(key);
        col_types.push_back(merge_col_type(InferredColType::unknown, val));
      } else {
        col_types[it->second] = merge_col_type(col_types[it->second], val);
      }
    }
  }

  std::set<std::string> used_lower;
  std::vector<std::string> col_names;
  col_names.reserve(raw_keys.size());
  for (const std::string &raw_key : raw_keys) {
    col_names.push_back(sanitize_column_name(raw_key, used_lower));
  }

  SqliteIngestResult result{};
  result.table_name = std::string{table.value};
  result.columns = col_names;
  result.rows_ingested = records.size();
  result.tainted = effective_tainted;

  if (records.empty()) {
    if (effective_tainted) {
      const std::string lower = ascii_lower(table.value);
      entry->tainted_tables.insert(lower);
      auto persisted = persist_taint_entry(*entry, lower, /*is_db_wide=*/false);
      if (!persisted.has_value()) {
        return Result<SqliteIngestResult>::failure(persisted.error());
      }
    }
    return Result<SqliteIngestResult>::success(std::move(result));
  }

  if (col_names.empty()) {
    return fail<SqliteIngestResult>(ErrorCode::invalid_range,
                                    SqliteError::ingest_parse_failed);
  }

  const std::string quoted_table = sql_quote_ident(table.value);
  std::string sql;
  sql.reserve(256U + records.size() * 64U);
  sql += "BEGIN IMMEDIATE;\nCREATE TABLE IF NOT EXISTS ";
  sql += quoted_table;
  sql += " (";
  for (std::size_t c = 0U; c < col_names.size(); ++c) {
    if (c > 0U) {
      sql += ", ";
    }
    sql += sql_quote_ident(col_names[c]);
    sql += ' ';
    sql += col_type_sql(col_types[c]);
  }
  sql += ");\n";

  std::string col_list;
  for (std::size_t c = 0U; c < col_names.size(); ++c) {
    if (c > 0U) {
      col_list += ", ";
    }
    col_list += sql_quote_ident(col_names[c]);
  }

  std::size_t row_idx = 0U;
  while (row_idx < records.size()) {
    const std::size_t batch_end =
        std::min(records.size(), row_idx + kMaxInsertBatchRows);
    sql += "INSERT INTO ";
    sql += quoted_table;
    sql += " (";
    sql += col_list;
    sql += ") VALUES ";
    for (std::size_t r = row_idx; r < batch_end; ++r) {
      if (r > row_idx) {
        sql += ", ";
      }
      sql += '(';
      const Value &rec = records[r];
      for (std::size_t c = 0U; c < raw_keys.size(); ++c) {
        if (c > 0U) {
          sql += ", ";
        }
        const Value *field = rec.find(raw_keys[c]);
        if (field == nullptr) {
          sql += "NULL";
        } else {
          auto lit = sql_literal_value(*field);
          if (!lit.has_value()) {
            return Result<SqliteIngestResult>::failure(lit.error());
          }
          sql += lit.value();
        }
      }
      sql += ')';
    }
    sql += ";\n";
    row_idx = batch_end;
  }
  sql += "COMMIT;\n";

  SqliteBackendRequest req{};
  req.db_path = entry->handle.path;
  req.sql = std::move(sql);
  req.limits = config_.default_limits;
  req.expect_rows = false;

  auto exec_res = backend_->execute(req);
  tighten_sidecars_locked(*entry);
  if (!exec_res.has_value()) {
    return Result<SqliteIngestResult>::failure(exec_res.error());
  }

  if (effective_tainted) {
    const std::string lower = ascii_lower(table.value);
    entry->tainted_tables.insert(lower);
    auto persisted = persist_taint_entry(*entry, lower, /*is_db_wide=*/false);
    if (!persisted.has_value()) {
      return Result<SqliteIngestResult>::failure(persisted.error());
    }
  }

  result.duration_ns = exec_res.value().duration_ns;
  return Result<SqliteIngestResult>::success(std::move(result));
}

Result<SqliteIngestResult> SqliteWorkbench::ingest_jsonl(const SqliteDbHandle &db,
                                                         TableName table,
                                                         std::string_view jsonl_text,
                                                         bool tainted) {
  if (!valid_sql_identifier(table.value)) {
    return fail<SqliteIngestResult>(ErrorCode::invalid_range,
                                    SqliteError::invalid_table_name);
  }
  auto entry_res = lookup_and_verify_db(db);
  if (!entry_res.has_value()) {
    return Result<SqliteIngestResult>::failure(entry_res.error());
  }
  DbEntry *entry = entry_res.value();
  const bool effective_tainted = tainted || is_turn_tainted();

  struct ParsedLine {
    std::int64_t line_no = 0;
    std::string raw_line;
    Value parsed;
  };
  std::vector<ParsedLine> lines;
  bool all_objects = true;
  std::int64_t line_no = 0;

  std::size_t pos = 0U;
  while (pos < jsonl_text.size()) {
    const std::size_t nl = jsonl_text.find('\n', pos);
    std::string_view line = (nl == std::string_view::npos)
                                ? jsonl_text.substr(pos)
                                : jsonl_text.substr(pos, nl - pos);
    pos = (nl == std::string_view::npos) ? jsonl_text.size() : (nl + 1U);
    ++line_no;
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1U);
    }
    // Trim whitespace to skip blank lines.
    std::string_view trimmed = line;
    while (!trimmed.empty() &&
           std::isspace(static_cast<unsigned char>(trimmed.front())) != 0) {
      trimmed.remove_prefix(1U);
    }
    while (!trimmed.empty() &&
           std::isspace(static_cast<unsigned char>(trimmed.back())) != 0) {
      trimmed.remove_suffix(1U);
    }
    if (trimmed.empty()) {
      continue;
    }

    auto parsed = parse_json(trimmed);
    if (!parsed.has_value()) {
      return fail<SqliteIngestResult>(ErrorCode::invalid_range,
                                      SqliteError::ingest_parse_failed);
    }
    if (!std::holds_alternative<Value::Object>(parsed.value().value())) {
      all_objects = false;
    }
    lines.push_back(
        ParsedLine{line_no, std::string{trimmed}, std::move(parsed).value()});
  }

  // Build schema: if all lines are JSON objects, infer columns + _raw (for JSON1).
  std::vector<std::string> raw_keys;
  std::unordered_map<std::string, std::size_t> key_index;
  std::vector<InferredColType> col_types;
  if (all_objects) {
    for (const ParsedLine &item : lines) {
      for (const auto &[key, val] : item.parsed.object()) {
        auto it = key_index.find(key);
        if (it == key_index.end()) {
          const std::size_t idx = raw_keys.size();
          key_index.emplace(key, idx);
          raw_keys.push_back(key);
          col_types.push_back(merge_col_type(InferredColType::unknown, val));
        } else {
          col_types[it->second] = merge_col_type(col_types[it->second], val);
        }
      }
    }
  }

  std::set<std::string> used_lower;
  std::vector<std::string> col_names;
  col_names.reserve(raw_keys.size() + 2U);
  for (const std::string &rk : raw_keys) {
    col_names.push_back(sanitize_column_name(rk, used_lower));
  }
  const std::string raw_col =
      sanitize_column_name(all_objects ? "_raw" : "raw", used_lower);
  const std::string line_no_col = sanitize_column_name("_line_no", used_lower);

  const std::string quoted_table = sql_quote_ident(table.value);
  std::string sql;
  sql.reserve(256U + lines.size() * 96U);
  sql += "BEGIN IMMEDIATE;\nCREATE TABLE IF NOT EXISTS ";
  sql += quoted_table;
  sql += " (";
  sql += sql_quote_ident(line_no_col);
  sql += " INTEGER PRIMARY KEY";
  for (std::size_t c = 0U; c < col_names.size(); ++c) {
    sql += ", ";
    sql += sql_quote_ident(col_names[c]);
    sql += ' ';
    sql += col_type_sql(col_types[c]);
  }
  sql += ", ";
  sql += sql_quote_ident(raw_col);
  sql += " TEXT);\n";

  std::string col_list = sql_quote_ident(line_no_col);
  for (const std::string &cn : col_names) {
    col_list += ", ";
    col_list += sql_quote_ident(cn);
  }
  col_list += ", ";
  col_list += sql_quote_ident(raw_col);

  std::size_t idx = 0U;
  while (idx < lines.size()) {
    const std::size_t batch_end = std::min(lines.size(), idx + kMaxInsertBatchRows);
    sql += "INSERT INTO ";
    sql += quoted_table;
    sql += " (";
    sql += col_list;
    sql += ") VALUES ";
    for (std::size_t r = idx; r < batch_end; ++r) {
      if (r > idx) {
        sql += ", ";
      }
      const ParsedLine &item = lines[r];
      sql += '(';
      sql += std::to_string(item.line_no);
      for (const std::string &rk : raw_keys) {
        sql += ", ";
        const Value *field = item.parsed.find(rk);
        if (field == nullptr) {
          sql += "NULL";
        } else {
          auto lit = sql_literal_value(*field);
          if (!lit.has_value()) {
            return Result<SqliteIngestResult>::failure(lit.error());
          }
          sql += lit.value();
        }
      }
      sql += ", ";
      sql += sql_literal_text(item.raw_line);
      sql += ')';
    }
    sql += ";\n";
    idx = batch_end;
  }
  sql += "COMMIT;\n";

  SqliteBackendRequest req{};
  req.db_path = entry->handle.path;
  req.sql = std::move(sql);
  req.limits = config_.default_limits;
  req.expect_rows = false;

  auto exec_res = backend_->execute(req);
  tighten_sidecars_locked(*entry);
  if (!exec_res.has_value()) {
    return Result<SqliteIngestResult>::failure(exec_res.error());
  }

  if (effective_tainted) {
    const std::string lower = ascii_lower(table.value);
    entry->tainted_tables.insert(lower);
    auto persisted = persist_taint_entry(*entry, lower, /*is_db_wide=*/false);
    if (!persisted.has_value()) {
      return Result<SqliteIngestResult>::failure(persisted.error());
    }
  }

  SqliteIngestResult out{};
  out.table_name = std::string{table.value};
  out.columns.push_back(line_no_col);
  for (const std::string &cn : col_names) {
    out.columns.push_back(cn);
  }
  out.columns.push_back(raw_col);
  out.rows_ingested = lines.size();
  out.tainted = effective_tainted;
  out.duration_ns = exec_res.value().duration_ns;
  return Result<SqliteIngestResult>::success(std::move(out));
}

Result<SqliteIngestResult> SqliteWorkbench::ingest_csv(const SqliteDbHandle &db,
                                                       TableName table,
                                                       std::string_view csv_text,
                                                       bool tainted) {
  if (!valid_sql_identifier(table.value)) {
    return fail<SqliteIngestResult>(ErrorCode::invalid_range,
                                    SqliteError::invalid_table_name);
  }
  auto entry_res = lookup_and_verify_db(db);
  if (!entry_res.has_value()) {
    return Result<SqliteIngestResult>::failure(entry_res.error());
  }
  DbEntry *entry = entry_res.value();
  const bool effective_tainted = tainted || is_turn_tainted();

  auto parsed_rows = parse_csv_rows(csv_text);
  if (!parsed_rows.has_value() || parsed_rows.value().empty() ||
      parsed_rows.value()[0].empty()) {
    return fail<SqliteIngestResult>(ErrorCode::invalid_range,
                                    SqliteError::ingest_parse_failed);
  }

  const auto &all_rows = parsed_rows.value();
  const auto &header = all_rows[0];
  std::set<std::string> used_lower;
  std::vector<std::string> col_names;
  col_names.reserve(header.size());
  for (const std::string &h : header) {
    col_names.push_back(sanitize_column_name(h, used_lower));
  }

  for (std::size_t r = 1U; r < all_rows.size(); ++r) {
    if (all_rows[r].size() > col_names.size()) {
      return fail<SqliteIngestResult>(ErrorCode::invalid_range,
                                      SqliteError::ingest_parse_failed);
    }
  }

  const std::string quoted_table = sql_quote_ident(table.value);
  std::string sql;
  sql.reserve(256U + all_rows.size() * 64U);
  sql += "BEGIN IMMEDIATE;\nCREATE TABLE IF NOT EXISTS ";
  sql += quoted_table;
  sql += " (";
  for (std::size_t c = 0U; c < col_names.size(); ++c) {
    if (c > 0U) {
      sql += ", ";
    }
    sql += sql_quote_ident(col_names[c]);
    sql += " TEXT";
  }
  sql += ");\n";

  std::string col_list;
  for (std::size_t c = 0U; c < col_names.size(); ++c) {
    if (c > 0U) {
      col_list += ", ";
    }
    col_list += sql_quote_ident(col_names[c]);
  }

  std::size_t idx = 1U;
  while (idx < all_rows.size()) {
    const std::size_t batch_end = std::min(all_rows.size(), idx + kMaxInsertBatchRows);
    sql += "INSERT INTO ";
    sql += quoted_table;
    sql += " (";
    sql += col_list;
    sql += ") VALUES ";
    for (std::size_t r = idx; r < batch_end; ++r) {
      if (r > idx) {
        sql += ", ";
      }
      sql += '(';
      const auto &row = all_rows[r];
      for (std::size_t c = 0U; c < col_names.size(); ++c) {
        if (c > 0U) {
          sql += ", ";
        }
        if (c < row.size()) {
          sql += sql_literal_text(row[c]);
        } else {
          sql += "NULL";
        }
      }
      sql += ')';
    }
    sql += ";\n";
    idx = batch_end;
  }
  sql += "COMMIT;\n";

  SqliteBackendRequest req{};
  req.db_path = entry->handle.path;
  req.sql = std::move(sql);
  req.limits = config_.default_limits;
  req.expect_rows = false;

  auto exec_res = backend_->execute(req);
  tighten_sidecars_locked(*entry);
  if (!exec_res.has_value()) {
    return Result<SqliteIngestResult>::failure(exec_res.error());
  }

  if (effective_tainted) {
    const std::string lower = ascii_lower(table.value);
    entry->tainted_tables.insert(lower);
    auto persisted = persist_taint_entry(*entry, lower, /*is_db_wide=*/false);
    if (!persisted.has_value()) {
      return Result<SqliteIngestResult>::failure(persisted.error());
    }
  }

  SqliteIngestResult out{};
  out.table_name = std::string{table.value};
  out.columns = std::move(col_names);
  out.rows_ingested = all_rows.size() - 1U;
  out.tainted = effective_tainted;
  out.duration_ns = exec_res.value().duration_ns;
  return Result<SqliteIngestResult>::success(std::move(out));
}

Result<SqliteIngestResult> SqliteWorkbench::ingest_lines(const SqliteDbHandle &db,
                                                         TableName table,
                                                         std::string_view text,
                                                         bool tainted) {
  if (!valid_sql_identifier(table.value)) {
    return fail<SqliteIngestResult>(ErrorCode::invalid_range,
                                    SqliteError::invalid_table_name);
  }
  auto entry_res = lookup_and_verify_db(db);
  if (!entry_res.has_value()) {
    return Result<SqliteIngestResult>::failure(entry_res.error());
  }
  DbEntry *entry = entry_res.value();
  const bool effective_tainted = tainted || is_turn_tainted();

  std::vector<std::string_view> lines;
  std::size_t pos = 0U;
  while (pos < text.size()) {
    const std::size_t nl = text.find('\n', pos);
    std::string_view line =
        (nl == std::string_view::npos) ? text.substr(pos) : text.substr(pos, nl - pos);
    if (nl != std::string_view::npos && !line.empty() && line.back() == '\r') {
      line.remove_suffix(1U);
    }
    lines.push_back(line);
    if (nl == std::string_view::npos) {
      break;
    }
    pos = nl + 1U;
  }

  const std::string quoted_table = sql_quote_ident(table.value);
  std::string sql;
  sql.reserve(256U + lines.size() * 48U);
  sql += "BEGIN IMMEDIATE;\nCREATE TABLE IF NOT EXISTS ";
  sql += quoted_table;
  sql += " (\"line_no\" INTEGER PRIMARY KEY, \"text\" TEXT);\n";

  std::size_t idx = 0U;
  while (idx < lines.size()) {
    const std::size_t batch_end = std::min(lines.size(), idx + kMaxInsertBatchRows);
    sql += "INSERT INTO ";
    sql += quoted_table;
    sql += " (\"line_no\", \"text\") VALUES ";
    for (std::size_t r = idx; r < batch_end; ++r) {
      if (r > idx) {
        sql += ", ";
      }
      sql += '(';
      sql += std::to_string(r + 1U);
      sql += ", ";
      sql += sql_literal_text(lines[r]);
      sql += ')';
    }
    sql += ";\n";
    idx = batch_end;
  }
  sql += "COMMIT;\n";

  SqliteBackendRequest req{};
  req.db_path = entry->handle.path;
  req.sql = std::move(sql);
  req.limits = config_.default_limits;
  req.expect_rows = false;

  auto exec_res = backend_->execute(req);
  tighten_sidecars_locked(*entry);
  if (!exec_res.has_value()) {
    return Result<SqliteIngestResult>::failure(exec_res.error());
  }

  if (effective_tainted) {
    const std::string lower = ascii_lower(table.value);
    entry->tainted_tables.insert(lower);
    auto persisted = persist_taint_entry(*entry, lower, /*is_db_wide=*/false);
    if (!persisted.has_value()) {
      return Result<SqliteIngestResult>::failure(persisted.error());
    }
  }

  SqliteIngestResult out{};
  out.table_name = std::string{table.value};
  out.columns = {"line_no", "text"};
  out.rows_ingested = lines.size();
  out.tainted = effective_tainted;
  out.duration_ns = exec_res.value().duration_ns;
  return Result<SqliteIngestResult>::success(std::move(out));
}

} // namespace blackbird::sqlite
