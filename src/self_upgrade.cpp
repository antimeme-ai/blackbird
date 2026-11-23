#include "blackbird/self_upgrade.hpp"

#include "blackbird/json.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <optional>
#include <poll.h>
#include <spawn.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace blackbird {
namespace {

constexpr std::uint8_t kTotalSteps = 6;
constexpr std::size_t kMaxMetadataBytes = 1024U * 1024U;
constexpr std::uint64_t kMaxTarballBytes = 1024ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaxProcessOutputBytes = 4U * 1024U * 1024U;
constexpr std::size_t kCopyChunkBytes = 64U * 1024U;
constexpr int kCurlTimeoutSeconds = 120;
constexpr int kTarTimeoutSeconds = 120;
constexpr int kSmokeTimeoutSeconds = 20;
constexpr int kPollIntervalMs = 80;

constexpr std::string_view kDefaultReleaseLatestBase =
    "https://github.com/antimemeai/blackbird/releases/latest/download";
constexpr std::string_view kDefaultReleaseTagPrefix =
    "https://github.com/antimemeai/blackbird/releases/download/";

struct UniqueFd {
  int fd = -1;

  UniqueFd() = default;
  explicit UniqueFd(int raw) noexcept : fd(raw) {}
  UniqueFd(const UniqueFd &) = delete;
  UniqueFd &operator=(const UniqueFd &) = delete;
  UniqueFd(UniqueFd &&other) noexcept : fd(std::exchange(other.fd, -1)) {}
  UniqueFd &operator=(UniqueFd &&other) noexcept {
    if (this != &other) {
      close();
      fd = std::exchange(other.fd, -1);
    }
    return *this;
  }
  ~UniqueFd() { close(); }

  void close() noexcept {
    if (fd >= 0) {
      (void)::close(fd);
      fd = -1;
    }
  }
  bool valid() const noexcept { return fd >= 0; }
};

struct TempDirGuard {
  std::filesystem::path path;
  bool keep = false;

  ~TempDirGuard() {
    if (!keep && !path.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(path, ec);
    }
  }
};

struct TempFileGuard {
  std::filesystem::path path;
  bool keep = false;

  ~TempFileGuard() {
    if (!keep && !path.empty()) {
      std::error_code ec;
      std::filesystem::remove(path, ec);
    }
  }
};

struct EvpMdCtxDeleter {
  void operator()(EVP_MD_CTX *ctx) const noexcept {
    if (ctx != nullptr) {
      EVP_MD_CTX_free(ctx);
    }
  }
};

using UniqueEvpMdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

bool is_ascii_control(char ch) noexcept {
  const auto byte = static_cast<unsigned char>(ch);
  return byte < 0x20U || byte == 0x7FU;
}

bool is_ascii_whitespace(char ch) noexcept {
  return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' ||
         ch == '\f';
}

bool has_control_chars(std::string_view text) noexcept {
  for (const char ch : text) {
    if (is_ascii_control(ch)) {
      return true;
    }
  }
  return false;
}

bool has_control_or_whitespace(std::string_view text) noexcept {
  for (const char ch : text) {
    if (is_ascii_control(ch) || is_ascii_whitespace(ch)) {
      return true;
    }
  }
  return false;
}

bool is_hex_digit(char ch) noexcept {
  return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
         (ch >= 'A' && ch <= 'F');
}

bool is_hex64(std::string_view text) noexcept {
  if (text.size() != 64U) {
    return false;
  }
  for (const char ch : text) {
    if (!is_hex_digit(ch)) {
      return false;
    }
  }
  return true;
}

std::string to_lower_ascii(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    if (ch >= 'A' && ch <= 'Z') {
      out.push_back(static_cast<char>(ch - 'A' + 'a'));
    } else {
      out.push_back(ch);
    }
  }
  return out;
}

std::string trim_ascii(std::string_view text) {
  std::size_t start = 0;
  while (start < text.size() && is_ascii_whitespace(text[start])) {
    ++start;
  }
  std::size_t end = text.size();
  while (end > start && is_ascii_whitespace(text[end - 1U])) {
    --end;
  }
  return std::string{text.substr(start, end - start)};
}

std::string sanitize_terminal_text(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (std::size_t i = 0; i < text.size(); ++i) {
    const unsigned char byte = static_cast<unsigned char>(text[i]);
    if (byte == 0x1BU) {
      // Strip ANSI CSI/OSC escape sequences if present.
      if (i + 1U < text.size() && text[i + 1U] == '[') {
        i += 2U;
        while (i < text.size()) {
          const unsigned char c = static_cast<unsigned char>(text[i]);
          if (c >= 0x40U && c <= 0x7EU) {
            break;
          }
          ++i;
        }
      } else if (i + 1U < text.size() && text[i + 1U] == ']') {
        i += 2U;
        while (i < text.size()) {
          const unsigned char c = static_cast<unsigned char>(text[i]);
          if (c == 0x07U) {
            break;
          }
          if (c == 0x1BU && i + 1U < text.size() && text[i + 1U] == '\\') {
            ++i;
            break;
          }
          ++i;
        }
      }
      continue;
    }
    if (byte < 0x20U || byte == 0x7FU) {
      if (byte == '\t') {
        out.push_back(' ');
      }
      continue;
    }
    out.push_back(text[i]);
  }
  return out;
}

void emit_progress(const UpgradeProgressCallback &cb, const UpgradeProgress &p) {
  if (cb) {
    cb(p);
  }
}

bool has_dotdot_segment(std::string_view path) noexcept {
  std::size_t pos = 0;
  while (pos <= path.size()) {
    const std::size_t slash = path.find('/', pos);
    const std::string_view seg = (slash == std::string_view::npos)
                                     ? path.substr(pos)
                                     : path.substr(pos, slash - pos);
    if (seg == "..") {
      return true;
    }
    if (slash == std::string_view::npos) {
      break;
    }
    pos = slash + 1U;
  }
  return false;
}

bool is_safe_asset_filename(std::string_view name) noexcept {
  if (name.empty() || name.size() > 255U || name == "." || name == "..") {
    return false;
  }
  if (has_control_or_whitespace(name)) {
    return false;
  }
  if (name.find('/') != std::string_view::npos ||
      name.find('\\') != std::string_view::npos ||
      name.find("..") != std::string_view::npos) {
    return false;
  }
  return true;
}

Result<std::filesystem::path> resolve_prefix(const UpgradeConfig &cfg) {
  std::filesystem::path prefix = cfg.prefix;
  if (prefix.empty()) {
    const char *home = std::getenv("HOME");
    if (home == nullptr || home[0] == '\0') {
      return Result<std::filesystem::path>::failure({ErrorCode::invalid_range});
    }
    prefix = std::filesystem::path{home} / ".local";
  }
  const std::string raw = prefix.string();
  if (raw.empty() || has_control_chars(raw)) {
    return Result<std::filesystem::path>::failure({ErrorCode::invalid_range});
  }
  return Result<std::filesystem::path>::success(std::move(prefix));
}

Result<std::filesystem::path> parse_file_url_path(std::string_view url) {
  constexpr std::string_view kScheme = "file://";
  if (!url.starts_with(kScheme)) {
    return Result<std::filesystem::path>::failure({ErrorCode::invalid_range});
  }
  if (has_control_or_whitespace(url)) {
    return Result<std::filesystem::path>::failure({ErrorCode::invalid_range});
  }
  const std::string_view rest = url.substr(kScheme.size());
  if (rest.empty() || rest.front() != '/' || has_dotdot_segment(rest)) {
    return Result<std::filesystem::path>::failure({ErrorCode::invalid_range});
  }
  return Result<std::filesystem::path>::success(
      std::filesystem::path{std::string{rest}});
}

Result<std::filesystem::path> create_private_temp_dir(std::string_view label) {
  std::filesystem::path base;
  const char *tmpdir = std::getenv("TMPDIR");
  if (tmpdir != nullptr && tmpdir[0] != '\0' && !has_control_chars(tmpdir)) {
    base = std::filesystem::path{tmpdir};
  } else {
    base = std::filesystem::path{"/tmp"};
  }
  std::error_code ec;
  std::filesystem::create_directories(base, ec);
  std::string tmpl = (base / (std::string{label} + "-XXXXXX")).string();
  char *created = ::mkdtemp(tmpl.data());
  if (created == nullptr) {
    return Result<std::filesystem::path>::failure({ErrorCode::io, errno});
  }
  if (::chmod(created, 0700) != 0) {
    std::filesystem::remove_all(created, ec);
    return Result<std::filesystem::path>::failure({ErrorCode::io, errno});
  }
  return Result<std::filesystem::path>::success(std::filesystem::path{created});
}

Result<std::filesystem::path>
create_generation_dir(const std::filesystem::path &releases_dir) {
  std::string tmpl = (releases_dir / "generation-XXXXXXXX").string();
  char *created = ::mkdtemp(tmpl.data());
  if (created == nullptr) {
    return Result<std::filesystem::path>::failure({ErrorCode::io, errno});
  }
  if (::chmod(created, 0755) != 0) {
    std::error_code ec;
    std::filesystem::remove_all(created, ec);
    return Result<std::filesystem::path>::failure({ErrorCode::io, errno});
  }
  return Result<std::filesystem::path>::success(std::filesystem::path{created});
}

Result<std::string> read_regular_file_bounded(const std::filesystem::path &path,
                                              std::size_t max_bytes) {
  UniqueFd fd{::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
  if (!fd.valid()) {
    return Result<std::string>::failure({ErrorCode::io, errno});
  }
  struct stat st{};
  if (::fstat(fd.fd, &st) != 0) {
    return Result<std::string>::failure({ErrorCode::io, errno});
  }
  if (!S_ISREG(st.st_mode)) {
    return Result<std::string>::failure({ErrorCode::corrupt});
  }
  if (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) > max_bytes) {
    return Result<std::string>::failure({ErrorCode::capacity});
  }
  std::string out;
  out.reserve(static_cast<std::size_t>(st.st_size));
  std::array<char, 8192> buf{};
  for (;;) {
    const ssize_t n = ::read(fd.fd, buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Result<std::string>::failure({ErrorCode::io, errno});
    }
    if (n == 0) {
      break;
    }
    const auto chunk = static_cast<std::size_t>(n);
    if (out.size() + chunk > max_bytes) {
      return Result<std::string>::failure({ErrorCode::capacity});
    }
    out.append(buf.data(), chunk);
  }
  return Result<std::string>::success(std::move(out));
}

Result<void> write_all_fd(int fd, std::string_view data) {
  std::size_t offset = 0;
  while (offset < data.size()) {
    const ssize_t written = ::write(fd, data.data() + offset, data.size() - offset);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Result<void>::failure({ErrorCode::io, errno});
    }
    offset += static_cast<std::size_t>(written);
  }
  return Result<void>::success();
}

Result<void> atomic_write_file(const std::filesystem::path &dest,
                               std::string_view content, mode_t mode) {
  std::string tmpl =
      (dest.parent_path() / (".tmp-" + dest.filename().string() + "-XXXXXX")).string();
  UniqueFd fd{::mkstemp(tmpl.data())};
  if (!fd.valid()) {
    return Result<void>::failure({ErrorCode::io, errno});
  }
  TempFileGuard tmp_guard{std::filesystem::path{tmpl}, false};
  (void)::fcntl(fd.fd, F_SETFD, FD_CLOEXEC);
  const auto wr = write_all_fd(fd.fd, content);
  if (!wr.has_value()) {
    return wr;
  }
  if (::fchmod(fd.fd, mode) != 0) {
    return Result<void>::failure({ErrorCode::io, errno});
  }
  fd.close();
  if (::rename(tmp_guard.path.c_str(), dest.c_str()) != 0) {
    return Result<void>::failure({ErrorCode::io, errno});
  }
  tmp_guard.keep = true;
  return Result<void>::success();
}

std::optional<std::string> find_executable_in_path(std::string_view name) {
  if (name.empty() || name.find('/') != std::string_view::npos) {
    return std::nullopt;
  }
  const char *path_env = std::getenv("PATH");
  const std::string_view search_path =
      (path_env != nullptr && path_env[0] != '\0')
          ? std::string_view{path_env}
          : std::string_view{"/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"};
  std::size_t pos = 0;
  while (pos <= search_path.size()) {
    const std::size_t colon = search_path.find(':', pos);
    const std::string_view dir = (colon == std::string_view::npos)
                                     ? search_path.substr(pos)
                                     : search_path.substr(pos, colon - pos);
    if (!dir.empty() && dir.front() == '/' && !has_control_chars(dir)) {
      const std::filesystem::path candidate =
          std::filesystem::path{std::string{dir}} / std::string{name};
      struct stat st{};
      if (::stat(candidate.c_str(), &st) == 0 && S_ISREG(st.st_mode) &&
          ::access(candidate.c_str(), X_OK) == 0) {
        return candidate.string();
      }
    }
    if (colon == std::string_view::npos) {
      break;
    }
    pos = colon + 1U;
  }
  return std::nullopt;
}

std::vector<std::string> build_filtered_env(bool allow_proxy) {
  std::vector<std::string> env;
  auto add_if_set = [&](const char *key) {
    const char *val = std::getenv(key);
    if (val != nullptr && !has_control_chars(val)) {
      env.push_back(std::string{key} + "=" + val);
    }
  };
  const char *path_env = std::getenv("PATH");
  if (path_env != nullptr && path_env[0] != '\0' && !has_control_chars(path_env)) {
    env.push_back(std::string{"PATH="} + path_env);
  } else {
    env.emplace_back("PATH=/usr/bin:/bin");
  }
  add_if_set("HOME");
  add_if_set("TMPDIR");
  env.emplace_back("LC_ALL=C");
  if (allow_proxy) {
    add_if_set("HTTPS_PROXY");
    add_if_set("https_proxy");
    add_if_set("ALL_PROXY");
    add_if_set("all_proxy");
    add_if_set("NO_PROXY");
    add_if_set("no_proxy");
    add_if_set("SSL_CERT_FILE");
    add_if_set("SSL_CERT_DIR");
    add_if_set("CURL_CA_BUNDLE");
  }
  return env;
}

struct ProcessRequest {
  std::string executable;
  std::vector<std::string> args;
  std::vector<std::string> env;
  int timeout_seconds = 60;
  // Returns false to abort the subprocess immediately (reported as capacity).
  std::function<bool()> on_poll_tick;
};

struct ProcessOutcome {
  int exit_code = -1;
  std::string stdout_data;
  std::string stderr_data;
};

void terminate_and_reap(pid_t pid) noexcept {
  if (pid <= 0) {
    return;
  }
  int status = 0;
  if (::waitpid(pid, &status, WNOHANG) == pid) {
    return;
  }
  (void)::kill(-pid, SIGTERM);
  (void)::kill(pid, SIGTERM);
  for (int i = 0; i < 10; ++i) {
    if (::waitpid(pid, &status, WNOHANG) == pid) {
      return;
    }
    ::usleep(10000);
  }
  (void)::kill(-pid, SIGKILL);
  (void)::kill(pid, SIGKILL);
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
}

Result<ProcessOutcome> run_subprocess(const ProcessRequest &req) {
  if (req.executable.empty() || req.executable.front() != '/' ||
      has_control_chars(req.executable)) {
    return Result<ProcessOutcome>::failure({ErrorCode::invalid_range});
  }

  int out_fds[2] = {-1, -1};
  int err_fds[2] = {-1, -1};
  if (::pipe(out_fds) != 0) {
    return Result<ProcessOutcome>::failure({ErrorCode::io, errno});
  }
  UniqueFd out_read{out_fds[0]};
  UniqueFd out_write{out_fds[1]};
  if (::pipe(err_fds) != 0) {
    return Result<ProcessOutcome>::failure({ErrorCode::io, errno});
  }
  UniqueFd err_read{err_fds[0]};
  UniqueFd err_write{err_fds[1]};

  (void)::fcntl(out_read.fd, F_SETFD, FD_CLOEXEC);
  (void)::fcntl(out_write.fd, F_SETFD, FD_CLOEXEC);
  (void)::fcntl(err_read.fd, F_SETFD, FD_CLOEXEC);
  (void)::fcntl(err_write.fd, F_SETFD, FD_CLOEXEC);

  const int out_flags = ::fcntl(out_read.fd, F_GETFL, 0);
  if (out_flags >= 0) {
    (void)::fcntl(out_read.fd, F_SETFL, out_flags | O_NONBLOCK);
  }
  const int err_flags = ::fcntl(err_read.fd, F_GETFL, 0);
  if (err_flags >= 0) {
    (void)::fcntl(err_read.fd, F_SETFL, err_flags | O_NONBLOCK);
  }

  std::vector<std::string> argv_storage;
  argv_storage.reserve(req.args.size() + 1U);
  argv_storage.push_back(req.executable);
  for (const auto &arg : req.args) {
    argv_storage.push_back(arg);
  }
  std::vector<char *> argv;
  argv.reserve(argv_storage.size() + 1U);
  for (auto &s : argv_storage) {
    argv.push_back(s.data());
  }
  argv.push_back(nullptr);

  std::vector<std::string> env_storage = req.env;
  std::vector<char *> envp;
  envp.reserve(env_storage.size() + 1U);
  for (auto &e : env_storage) {
    envp.push_back(e.data());
  }
  envp.push_back(nullptr);

  posix_spawn_file_actions_t actions{};
  posix_spawnattr_t attr{};
  int rc = ::posix_spawn_file_actions_init(&actions);
  if (rc != 0) {
    return Result<ProcessOutcome>::failure({ErrorCode::io, rc});
  }
  rc = ::posix_spawnattr_init(&attr);
  if (rc != 0) {
    (void)::posix_spawn_file_actions_destroy(&actions);
    return Result<ProcessOutcome>::failure({ErrorCode::io, rc});
  }

  pid_t child_pid = -1;
  if (rc == 0) {
    rc = ::posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null",
                                            O_RDONLY, 0);
  }
  if (rc == 0) {
    rc = ::posix_spawn_file_actions_adddup2(&actions, out_write.fd, STDOUT_FILENO);
  }
  if (rc == 0) {
    rc = ::posix_spawn_file_actions_adddup2(&actions, err_write.fd, STDERR_FILENO);
  }
  if (rc == 0) {
    rc = ::posix_spawnattr_setflags(
        &attr, static_cast<short>(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK));
  }
  if (rc == 0) {
    rc = ::posix_spawnattr_setpgroup(&attr, 0);
  }
  if (rc == 0) {
    sigset_t empty_mask{};
    sigemptyset(&empty_mask);
    rc = ::posix_spawnattr_setsigmask(&attr, &empty_mask);
  }
  if (rc == 0) {
    rc = ::posix_spawn(&child_pid, req.executable.c_str(), &actions, &attr, argv.data(),
                       envp.data());
  }
  (void)::posix_spawnattr_destroy(&attr);
  (void)::posix_spawn_file_actions_destroy(&actions);

  out_write.close();
  err_write.close();

  if (rc != 0 || child_pid <= 0) {
    return Result<ProcessOutcome>::failure({ErrorCode::io, rc});
  }

  struct ChildGuard {
    pid_t pid = -1;
    bool reaped = false;
    ~ChildGuard() {
      if (!reaped) {
        terminate_and_reap(pid);
      }
    }
  } child_guard{child_pid, false};

  ProcessOutcome outcome;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds{req.timeout_seconds};
  bool out_open = true;
  bool err_open = true;
  bool child_done = false;
  int child_status = 0;
  std::array<char, 8192> buf{};

  auto drain_fd = [&](int fd, std::string &target, bool &is_open) -> bool {
    for (;;) {
      const ssize_t n = ::read(fd, buf.data(), buf.size());
      if (n > 0) {
        const auto chunk = static_cast<std::size_t>(n);
        if (target.size() + chunk <= kMaxProcessOutputBytes) {
          target.append(buf.data(), chunk);
        } else if (target.size() < kMaxProcessOutputBytes) {
          target.append(buf.data(), kMaxProcessOutputBytes - target.size());
        }
      } else if (n == 0) {
        is_open = false;
        return true;
      } else if (errno == EINTR) {
        continue;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return true;
      } else {
        is_open = false;
        return false;
      }
    }
  };

  while (out_open || err_open || !child_done) {
    if (std::chrono::steady_clock::now() >= deadline) {
      return Result<ProcessOutcome>::failure({ErrorCode::interrupted});
    }
    if (!child_done) {
      const pid_t w = ::waitpid(child_pid, &child_status, WNOHANG);
      if (w == child_pid) {
        child_done = true;
        child_guard.reaped = true;
      }
    }

    std::array<pollfd, 2> pfds{};
    nfds_t nfds = 0;
    if (out_open) {
      pfds[nfds++] = pollfd{out_read.fd, POLLIN, 0};
    }
    if (err_open) {
      pfds[nfds++] = pollfd{err_read.fd, POLLIN, 0};
    }

    if (nfds > 0) {
      const int pr = ::poll(pfds.data(), nfds, kPollIntervalMs);
      if (pr > 0) {
        for (nfds_t i = 0; i < nfds; ++i) {
          if ((pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            if (pfds[i].fd == out_read.fd) {
              (void)drain_fd(out_read.fd, outcome.stdout_data, out_open);
            } else if (pfds[i].fd == err_read.fd) {
              (void)drain_fd(err_read.fd, outcome.stderr_data, err_open);
            }
          }
        }
      }
    } else if (!child_done) {
      ::usleep(20000);
    }

    if (req.on_poll_tick && !req.on_poll_tick()) {
      return Result<ProcessOutcome>::failure({ErrorCode::capacity});
    }
  }

  if (WIFEXITED(child_status)) {
    outcome.exit_code = WEXITSTATUS(child_status);
  } else {
    outcome.exit_code = -1;
  }
  return Result<ProcessOutcome>::success(std::move(outcome));
}

struct FetchToFileRequest {
  std::string url;
  std::filesystem::path dest;
  std::uint64_t expected_total_bytes = 0;
  std::uint64_t max_bytes = kMaxTarballBytes;
  std::function<void(std::uint64_t, std::uint64_t)> on_bytes;
};

Result<std::uint64_t> fetch_file_url_to_dest(const FetchToFileRequest &req) {
  const auto src_res = parse_file_url_path(req.url);
  if (!src_res.has_value()) {
    return Result<std::uint64_t>::failure(src_res.error());
  }
  UniqueFd src_fd{::open(src_res.value().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
  if (!src_fd.valid()) {
    return Result<std::uint64_t>::failure({ErrorCode::io, errno});
  }
  struct stat st{};
  if (::fstat(src_fd.fd, &st) != 0) {
    return Result<std::uint64_t>::failure({ErrorCode::io, errno});
  }
  if (!S_ISREG(st.st_mode)) {
    return Result<std::uint64_t>::failure({ErrorCode::corrupt});
  }
  if (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) > req.max_bytes) {
    return Result<std::uint64_t>::failure({ErrorCode::capacity});
  }
  const auto total_bytes = req.expected_total_bytes > 0
                               ? req.expected_total_bytes
                               : static_cast<std::uint64_t>(st.st_size);

  UniqueFd dst_fd{::open(req.dest.c_str(),
                         O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600)};
  if (!dst_fd.valid()) {
    return Result<std::uint64_t>::failure({ErrorCode::io, errno});
  }

  std::vector<char> chunk(kCopyChunkBytes);
  std::uint64_t copied = 0;
  if (req.on_bytes) {
    req.on_bytes(0, total_bytes);
  }
  for (;;) {
    const ssize_t n = ::read(src_fd.fd, chunk.data(), chunk.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Result<std::uint64_t>::failure({ErrorCode::io, errno});
    }
    if (n == 0) {
      break;
    }
    const auto count = static_cast<std::size_t>(n);
    if (copied + count > req.max_bytes) {
      return Result<std::uint64_t>::failure({ErrorCode::capacity});
    }
    const auto wr = write_all_fd(dst_fd.fd, std::string_view{chunk.data(), count});
    if (!wr.has_value()) {
      return Result<std::uint64_t>::failure(wr.error());
    }
    copied += count;
    if (req.on_bytes) {
      req.on_bytes(copied, total_bytes);
    }
  }
  return Result<std::uint64_t>::success(copied);
}

Result<std::uint64_t> fetch_https_url_to_dest(const FetchToFileRequest &req) {
  if (!req.url.starts_with("https://") || req.url.size() <= 8U ||
      has_control_or_whitespace(req.url)) {
    return Result<std::uint64_t>::failure({ErrorCode::invalid_range});
  }
  const auto curl_bin = find_executable_in_path("curl");
  if (!curl_bin.has_value()) {
    return Result<std::uint64_t>::failure({ErrorCode::unsupported});
  }

  std::uint64_t last_reported = 0;
  if (req.on_bytes) {
    req.on_bytes(0, req.expected_total_bytes);
  }

  ProcessRequest proc;
  proc.executable = *curl_bin;
  proc.args = {
      "--proto",
      "=https",
      "--proto-redir",
      "=https",
      "--tlsv1.2",
      "--fail",
      "--silent",
      "--show-error",
      "--location",
      "--max-time",
      std::to_string(kCurlTimeoutSeconds),
      "--max-filesize",
      std::to_string(req.max_bytes),
      "--output",
      req.dest.string(),
      "--",
      req.url,
  };
  proc.env = build_filtered_env(true);
  proc.timeout_seconds = kCurlTimeoutSeconds + 10;
  proc.on_poll_tick = [&]() -> bool {
    struct stat st{};
    if (::stat(req.dest.c_str(), &st) == 0 && st.st_size >= 0) {
      const auto current = static_cast<std::uint64_t>(st.st_size);
      if (current > req.max_bytes) {
        return false;
      }
      if (req.on_bytes && current != last_reported) {
        last_reported = current;
        req.on_bytes(current, req.expected_total_bytes);
      }
    }
    return true;
  };

  const auto outcome = run_subprocess(proc);
  if (!outcome.has_value()) {
    return Result<std::uint64_t>::failure(outcome.error());
  }
  if (outcome.value().exit_code != 0) {
    return Result<std::uint64_t>::failure(
        {ErrorCode::provider_transport, outcome.value().exit_code});
  }

  struct stat st{};
  if (::lstat(req.dest.c_str(), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
    return Result<std::uint64_t>::failure({ErrorCode::io});
  }
  const auto final_size = static_cast<std::uint64_t>(st.st_size);
  if (final_size > req.max_bytes) {
    return Result<std::uint64_t>::failure({ErrorCode::capacity});
  }
  if (req.on_bytes) {
    req.on_bytes(final_size,
                 req.expected_total_bytes > 0 ? req.expected_total_bytes : final_size);
  }
  return Result<std::uint64_t>::success(final_size);
}

Result<std::uint64_t> fetch_url_to_file(const FetchToFileRequest &req) {
  if (req.url.starts_with("file://")) {
    return fetch_file_url_to_dest(req);
  }
  if (req.url.starts_with("https://")) {
    return fetch_https_url_to_dest(req);
  }
  return Result<std::uint64_t>::failure({ErrorCode::invalid_range});
}

Result<std::string> fetch_url_to_string(std::string_view url, std::size_t max_bytes) {
  if (url.starts_with("file://")) {
    const auto path_res = parse_file_url_path(url);
    if (!path_res.has_value()) {
      return Result<std::string>::failure(path_res.error());
    }
    return read_regular_file_bounded(path_res.value(), max_bytes);
  }
  if (!url.starts_with("https://")) {
    return Result<std::string>::failure({ErrorCode::invalid_range});
  }
  const auto tmp_dir = create_private_temp_dir("blackbird-upgrade-meta");
  if (!tmp_dir.has_value()) {
    return Result<std::string>::failure(tmp_dir.error());
  }
  TempDirGuard guard{tmp_dir.value(), false};
  const std::filesystem::path dest = tmp_dir.value() / "payload";
  FetchToFileRequest req;
  req.url = std::string{url};
  req.dest = dest;
  req.max_bytes = max_bytes;
  const auto fetched = fetch_https_url_to_dest(req);
  if (!fetched.has_value()) {
    return Result<std::string>::failure(fetched.error());
  }
  return read_regular_file_bounded(dest, max_bytes);
}

Result<std::string> compute_file_sha256_hex(const std::filesystem::path &path) {
  UniqueFd fd{::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
  if (!fd.valid()) {
    return Result<std::string>::failure({ErrorCode::io, errno});
  }
  struct stat st{};
  if (::fstat(fd.fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    return Result<std::string>::failure({ErrorCode::corrupt});
  }

  UniqueEvpMdCtx ctx{EVP_MD_CTX_new()};
  if (!ctx) {
    return Result<std::string>::failure({ErrorCode::allocation});
  }
  if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
    return Result<std::string>::failure({ErrorCode::io});
  }

  std::vector<unsigned char> buf(kCopyChunkBytes);
  for (;;) {
    const ssize_t n = ::read(fd.fd, buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Result<std::string>::failure({ErrorCode::io, errno});
    }
    if (n == 0) {
      break;
    }
    if (EVP_DigestUpdate(ctx.get(), buf.data(), static_cast<std::size_t>(n)) != 1) {
      return Result<std::string>::failure({ErrorCode::io});
    }
  }

  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int digest_len = 0;
  if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_len) != 1 ||
      digest_len != 32U) {
    return Result<std::string>::failure({ErrorCode::io});
  }

  static constexpr char kHex[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(64U);
  for (std::size_t i = 0; i < 32U; ++i) {
    const unsigned char b = digest[i];
    hex.push_back(kHex[(b >> 4U) & 0x0FU]);
    hex.push_back(kHex[b & 0x0FU]);
  }
  return Result<std::string>::success(std::move(hex));
}

struct HexDigestPair {
  std::string_view expected;
  std::string_view actual;
};

bool constant_time_equal_hex64(const HexDigestPair &pair) noexcept {
  if (pair.expected.size() != 64U || pair.actual.size() != 64U) {
    return false;
  }
  return CRYPTO_memcmp(pair.expected.data(), pair.actual.data(), 64U) == 0;
}

struct ParsedManifest {
  std::string version;
  std::string commit;
  std::string filename;
  std::string sha256;
  std::uint64_t size_bytes = 0;
};

struct ManifestParseParams {
  std::string_view json_text;
  std::string_view expected_version;
  std::string_view target_triplet;
};

Result<ParsedManifest> parse_release_manifest(const ManifestParseParams &params) {
  const auto parsed = parse_json(params.json_text);
  if (!parsed.has_value()) {
    return Result<ParsedManifest>::failure({ErrorCode::corrupt});
  }
  const Value &root = parsed.value();
  if (!std::holds_alternative<Value::Object>(root.value())) {
    return Result<ParsedManifest>::failure({ErrorCode::corrupt});
  }

  const Value *ver_val = root.find("version");
  if (ver_val == nullptr || !std::holds_alternative<std::string>(ver_val->value())) {
    return Result<ParsedManifest>::failure({ErrorCode::corrupt});
  }
  const std::string &manifest_version = ver_val->string();
  const auto ver_ok = valid_upgrade_version(manifest_version);
  if (!ver_ok.has_value() || !ver_ok.value() || manifest_version == "latest") {
    return Result<ParsedManifest>::failure({ErrorCode::corrupt});
  }
  if (params.expected_version != "latest" &&
      manifest_version != params.expected_version) {
    return Result<ParsedManifest>::failure({ErrorCode::corrupt});
  }

  std::string manifest_commit;
  if (const Value *commit_val = root.find("commit"); commit_val != nullptr) {
    if (!std::holds_alternative<std::string>(commit_val->value())) {
      return Result<ParsedManifest>::failure({ErrorCode::corrupt});
    }
    if (commit_val->string().size() > 128U || has_control_chars(commit_val->string())) {
      return Result<ParsedManifest>::failure({ErrorCode::corrupt});
    }
    manifest_commit = commit_val->string();
  }

  const Value *assets_val = root.find("assets");
  if (assets_val == nullptr ||
      !std::holds_alternative<Value::Array>(assets_val->value())) {
    return Result<ParsedManifest>::failure({ErrorCode::corrupt});
  }

  std::size_t matches = 0;
  ParsedManifest out;
  out.version = manifest_version;
  out.commit = std::move(manifest_commit);

  for (const Value &item : assets_val->array()) {
    if (!std::holds_alternative<Value::Object>(item.value())) {
      return Result<ParsedManifest>::failure({ErrorCode::corrupt});
    }
    const Value *t_val = item.find("target");
    if (t_val == nullptr || !std::holds_alternative<std::string>(t_val->value())) {
      continue;
    }
    if (t_val->string() != params.target_triplet) {
      continue;
    }
    ++matches;
    if (matches > 1U) {
      return Result<ParsedManifest>::failure({ErrorCode::corrupt});
    }

    const Value *fn_val = item.find("filename");
    const Value *sha_val = item.find("sha256");
    if (fn_val == nullptr || !std::holds_alternative<std::string>(fn_val->value()) ||
        sha_val == nullptr || !std::holds_alternative<std::string>(sha_val->value())) {
      return Result<ParsedManifest>::failure({ErrorCode::corrupt});
    }
    const std::string &filename = fn_val->string();
    const std::string &sha_raw = sha_val->string();
    if (!is_safe_asset_filename(filename) || !is_hex64(sha_raw)) {
      return Result<ParsedManifest>::failure({ErrorCode::corrupt});
    }
    const std::string expected_name = "blackbird-" + manifest_version + "-" +
                                      std::string{params.target_triplet} + ".tar.gz";
    if (filename != expected_name) {
      return Result<ParsedManifest>::failure({ErrorCode::corrupt});
    }

    std::uint64_t size_bytes = 0;
    if (const Value *sz_val = item.find("size_bytes"); sz_val != nullptr) {
      if (!std::holds_alternative<Number>(sz_val->value())) {
        return Result<ParsedManifest>::failure({ErrorCode::corrupt});
      }
      const auto &storage = sz_val->number().storage();
      if (const auto *u = std::get_if<std::uint64_t>(&storage)) {
        size_bytes = *u;
      } else if (const auto *i = std::get_if<std::int64_t>(&storage);
                 i != nullptr && *i >= 0) {
        size_bytes = static_cast<std::uint64_t>(*i);
      } else {
        return Result<ParsedManifest>::failure({ErrorCode::corrupt});
      }
      if (size_bytes > kMaxTarballBytes) {
        return Result<ParsedManifest>::failure({ErrorCode::capacity});
      }
    }

    out.filename = filename;
    out.sha256 = to_lower_ascii(sha_raw);
    out.size_bytes = size_bytes;
  }

  if (matches != 1U) {
    return Result<ParsedManifest>::failure({ErrorCode::unsupported});
  }
  return Result<ParsedManifest>::success(std::move(out));
}

struct Sha256SumsLookup {
  std::string_view sums_text;
  std::string_view asset_filename;
};

Result<std::string> lookup_sha256sums_entry(const Sha256SumsLookup &lookup) {
  std::size_t matches = 0;
  std::string found_hash;

  std::size_t pos = 0;
  while (pos < lookup.sums_text.size()) {
    const std::size_t nl = lookup.sums_text.find('\n', pos);
    std::string_view line = (nl == std::string_view::npos)
                                ? lookup.sums_text.substr(pos)
                                : lookup.sums_text.substr(pos, nl - pos);
    pos = (nl == std::string_view::npos) ? lookup.sums_text.size() : nl + 1U;
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1U);
    }
    if (line.empty()) {
      continue;
    }

    const std::size_t sep = line.find_first_of(" \t");
    if (sep == std::string_view::npos) {
      continue;
    }
    const std::string_view hash_part = line.substr(0, sep);
    std::string_view rest = line.substr(sep);
    while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) {
      rest.remove_prefix(1U);
    }
    if (!rest.empty() && rest.front() == '*') {
      rest.remove_prefix(1U);
    }
    if (!is_hex64(hash_part) || !is_safe_asset_filename(rest)) {
      continue;
    }
    if (rest == lookup.asset_filename) {
      ++matches;
      if (matches > 1U) {
        return Result<std::string>::failure({ErrorCode::corrupt});
      }
      found_hash = to_lower_ascii(hash_part);
    }
  }

  if (matches != 1U) {
    return Result<std::string>::failure({ErrorCode::corrupt});
  }
  return Result<std::string>::success(std::move(found_hash));
}

struct InstalledVersionInfo {
  std::string version;
  std::string commit;
};

InstalledVersionInfo detect_installed_version(const std::filesystem::path &prefix,
                                              std::string_view current_version_string) {
  InstalledVersionInfo info;
  const std::filesystem::path current_dir = prefix / "lib" / "blackbird" / "current";

  // 1. Prefer <prefix>/lib/blackbird/current/release-manifest.json
  const std::filesystem::path manifest_json = current_dir / "release-manifest.json";
  if (const auto text = read_regular_file_bounded(manifest_json, kMaxMetadataBytes);
      text.has_value()) {
    if (const auto parsed = parse_json(text.value());
        parsed.has_value() &&
        std::holds_alternative<Value::Object>(parsed.value().value())) {
      if (const Value *v = parsed.value().find("version");
          v != nullptr && std::holds_alternative<std::string>(v->value()) &&
          !has_control_chars(v->string())) {
        info.version = v->string();
      }
      if (const Value *c = parsed.value().find("commit");
          c != nullptr && std::holds_alternative<std::string>(c->value()) &&
          !has_control_chars(c->string())) {
        info.commit = c->string();
      }
    }
  }

  // 2. Fallback to <prefix>/lib/blackbird/current/MANIFEST (key=value lines)
  if (info.version.empty() || info.commit.empty()) {
    const std::filesystem::path manifest_kv = current_dir / "MANIFEST";
    if (const auto text = read_regular_file_bounded(manifest_kv, kMaxMetadataBytes);
        text.has_value()) {
      std::size_t pos = 0;
      const std::string_view body = text.value();
      while (pos < body.size()) {
        const std::size_t nl = body.find('\n', pos);
        std::string_view line = (nl == std::string_view::npos)
                                    ? body.substr(pos)
                                    : body.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? body.size() : nl + 1U;
        if (!line.empty() && line.back() == '\r') {
          line.remove_suffix(1U);
        }
        if (info.version.empty() && line.starts_with("tag=")) {
          const auto tag = trim_ascii(line.substr(4U));
          if (!tag.empty() && !has_control_chars(tag)) {
            info.version = tag;
          }
        } else if (info.commit.empty() && line.starts_with("commit=")) {
          const auto commit = trim_ascii(line.substr(7U));
          if (!commit.empty() && !has_control_chars(commit)) {
            info.commit = commit;
          }
        }
      }
    }
  }

  // 3. Fallback to cfg.current_version_string (e.g. "blackbird 3dd0b0e005dd (...)")
  if ((info.version.empty() || info.commit.empty()) &&
      !current_version_string.empty()) {
    const std::string trimmed =
        trim_ascii(sanitize_terminal_text(current_version_string));
    if (trimmed.starts_with("blackbird ")) {
      std::string_view rest = std::string_view{trimmed}.substr(10U);
      const std::size_t sp = rest.find(' ');
      const std::string_view tok =
          (sp == std::string_view::npos) ? rest : rest.substr(0, sp);
      if (!tok.empty()) {
        const auto is_tag = valid_upgrade_version(tok);
        if (is_tag.has_value() && is_tag.value() && tok != "latest") {
          if (info.version.empty()) {
            info.version = std::string{tok};
          }
        } else if (info.commit.empty()) {
          info.commit = std::string{tok};
        }
      }
    } else if (!trimmed.empty()) {
      const auto is_tag = valid_upgrade_version(trimmed);
      if (is_tag.has_value() && is_tag.value() && trimmed != "latest") {
        if (info.version.empty()) {
          info.version = trimmed;
        }
      } else if (info.commit.empty() && !has_control_or_whitespace(trimmed)) {
        info.commit = trimmed;
      }
    }
  }

  return info;
}

bool compute_update_available(const InstalledVersionInfo &installed,
                              const ParsedManifest &latest) noexcept {
  if (installed.version.empty() && installed.commit.empty()) {
    return true;
  }
  if (!installed.version.empty() && !latest.version.empty()) {
    if (installed.version != latest.version) {
      return true;
    }
    if (!installed.commit.empty() && !latest.commit.empty()) {
      return installed.commit != latest.commit;
    }
    return false;
  }
  if (!installed.commit.empty() && !latest.commit.empty()) {
    return installed.commit != latest.commit;
  }
  return true;
}

std::vector<std::string_view> split_lines_lf_nonempty(std::string_view text) {
  std::vector<std::string_view> lines;
  std::size_t pos = 0;
  while (pos < text.size()) {
    const std::size_t nl = text.find('\n', pos);
    const std::string_view line =
        (nl == std::string_view::npos) ? text.substr(pos) : text.substr(pos, nl - pos);
    pos = (nl == std::string_view::npos) ? text.size() : nl + 1U;
    if (!line.empty()) {
      lines.push_back(line);
    }
  }
  return lines;
}

bool is_safe_single_component(std::string_view comp) noexcept {
  if (comp.empty() || comp == "." || comp == ".." || has_control_chars(comp)) {
    return false;
  }
  if (comp.find('/') != std::string_view::npos ||
      comp.find("..") != std::string_view::npos) {
    return false;
  }
  return true;
}

std::optional<std::string> read_symlink_target_raw(const std::filesystem::path &path) {
  std::array<char, 4096> buf{};
  const ssize_t n = ::readlink(path.c_str(), buf.data(), buf.size() - 1U);
  if (n <= 0) {
    return std::nullopt;
  }
  return std::string{buf.data(), static_cast<std::size_t>(n)};
}

struct TarInspectSpec {
  std::filesystem::path tarball;
  std::string tar_bin;
  std::string expected_stem;
};

Result<void> inspect_tarball_before_extract(const TarInspectSpec &spec) {
  // 1. tar -tzf <tarball>
  ProcessRequest list_req;
  list_req.executable = spec.tar_bin;
  list_req.args = {"-tzf", spec.tarball.string()};
  list_req.env = build_filtered_env(false);
  list_req.timeout_seconds = kTarTimeoutSeconds;
  const auto list_res = run_subprocess(list_req);
  if (!list_res.has_value()) {
    return Result<void>::failure(list_res.error());
  }
  if (list_res.value().exit_code != 0) {
    return Result<void>::failure({ErrorCode::corrupt});
  }

  // 2. tar -tvzf <tarball>
  ProcessRequest vlist_req;
  vlist_req.executable = spec.tar_bin;
  vlist_req.args = {"-tvzf", spec.tarball.string()};
  vlist_req.env = build_filtered_env(false);
  vlist_req.timeout_seconds = kTarTimeoutSeconds;
  const auto vlist_res = run_subprocess(vlist_req);
  if (!vlist_res.has_value()) {
    return Result<void>::failure(vlist_res.error());
  }
  if (vlist_res.value().exit_code != 0) {
    return Result<void>::failure({ErrorCode::corrupt});
  }

  // Reject any CR bytes in raw tar output BEFORE line splitting.
  if (list_res.value().stdout_data.find('\r') != std::string::npos ||
      vlist_res.value().stdout_data.find('\r') != std::string::npos) {
    return Result<void>::failure({ErrorCode::corrupt});
  }

  const auto names = split_lines_lf_nonempty(list_res.value().stdout_data);
  const auto verbose = split_lines_lf_nonempty(vlist_res.value().stdout_data);
  if (names.empty() || verbose.empty() || names.size() != verbose.size()) {
    return Result<void>::failure({ErrorCode::corrupt});
  }

  const std::string stem_prefix = spec.expected_stem + "/";
  const std::string lib_prefix = stem_prefix + "lib/";

  for (std::size_t idx = 0; idx < names.size(); ++idx) {
    const std::string_view entry = names[idx];
    const std::string_view vline = verbose[idx];

    if (entry.empty() || entry.front() == '/' || has_control_chars(entry) ||
        has_dotdot_segment(entry)) {
      return Result<void>::failure({ErrorCode::corrupt});
    }
    if (entry != spec.expected_stem && !entry.starts_with(stem_prefix)) {
      return Result<void>::failure({ErrorCode::corrupt});
    }
    if (vline.empty() || has_control_chars(vline)) {
      return Result<void>::failure({ErrorCode::corrupt});
    }

    const char type_ch = vline.front();
    if (type_ch == '-' || type_ch == 'd') {
      if (vline.find(" -> ") != std::string_view::npos ||
          vline.find(" link to ") != std::string_view::npos) {
        return Result<void>::failure({ErrorCode::corrupt});
      }
      continue;
    }

    if (type_ch == 'l') {
      // Match scripts/install-release.sh: allow ONLY intra-directory relative symlinks
      // directly inside <expected_stem>/lib/<name> -> <target> (Linux SONAME libs).
      if (!entry.starts_with(lib_prefix)) {
        return Result<void>::failure({ErrorCode::corrupt});
      }
      const std::string_view sym_rel = entry.substr(lib_prefix.size());
      if (!is_safe_single_component(sym_rel)) {
        return Result<void>::failure({ErrorCode::corrupt});
      }
      const std::size_t arrow = vline.find(" -> ");
      if (arrow == std::string_view::npos ||
          vline.find(" -> ", arrow + 4U) != std::string_view::npos) {
        return Result<void>::failure({ErrorCode::corrupt});
      }
      const std::string_view before_arrow = vline.substr(0, arrow);
      const std::string_view sym_target = vline.substr(arrow + 4U);
      const std::string expected_suffix = " " + std::string{entry};
      if (!before_arrow.ends_with(expected_suffix) ||
          !is_safe_single_component(sym_target)) {
        return Result<void>::failure({ErrorCode::corrupt});
      }
      continue;
    }

    // Reject hardlinks ('h'), devices ('b'/'c'), FIFOs ('p'), and any other type.
    return Result<void>::failure({ErrorCode::corrupt});
  }

  return Result<void>::success();
}

struct ExtractedTreeSpec {
  std::filesystem::path extract_dir;
  std::string expected_stem;
};

Result<void> verify_extracted_tree_safe(const ExtractedTreeSpec &spec) {
  std::error_code ec;
  const auto root_status = std::filesystem::symlink_status(spec.extract_dir, ec);
  if (ec || !std::filesystem::is_directory(root_status) ||
      std::filesystem::is_symlink(root_status)) {
    return Result<void>::failure({ErrorCode::corrupt});
  }
  const std::filesystem::path expected_lib_rel =
      std::filesystem::path{spec.expected_stem} / "lib";

  for (std::filesystem::recursive_directory_iterator
           it{spec.extract_dir, std::filesystem::directory_options::none, ec},
       end;
       it != end; it.increment(ec)) {
    if (ec) {
      return Result<void>::failure({ErrorCode::io});
    }
    const auto st = it->symlink_status(ec);
    if (ec) {
      return Result<void>::failure({ErrorCode::io});
    }
    if (std::filesystem::is_regular_file(st) || std::filesystem::is_directory(st)) {
      continue;
    }
    if (std::filesystem::is_symlink(st)) {
      const auto rel = it->path().lexically_relative(spec.extract_dir);
      if (rel.empty() || has_dotdot_segment(rel.string()) ||
          rel.parent_path() != expected_lib_rel ||
          !is_safe_single_component(rel.filename().string())) {
        return Result<void>::failure({ErrorCode::corrupt});
      }
      const auto target = read_symlink_target_raw(it->path());
      if (!target.has_value() || !is_safe_single_component(*target)) {
        return Result<void>::failure({ErrorCode::corrupt});
      }
      const std::filesystem::path sibling = it->path().parent_path() / *target;
      struct stat sib_st{};
      if (::lstat(sibling.c_str(), &sib_st) != 0 || !S_ISREG(sib_st.st_mode)) {
        return Result<void>::failure({ErrorCode::corrupt});
      }
      continue;
    }
    return Result<void>::failure({ErrorCode::corrupt});
  }
  return Result<void>::success();
}

struct TreeCopySpec {
  std::filesystem::path src_root;
  std::filesystem::path dst_root;
};

Result<void> copy_tree_regular(const TreeCopySpec &spec) {
  std::error_code ec;
  struct PendingLibSymlink {
    std::filesystem::path dst_link;
    std::string target;
  };
  std::vector<PendingLibSymlink> pending_links;

  for (std::filesystem::recursive_directory_iterator
           it{spec.src_root, std::filesystem::directory_options::none, ec},
       end;
       it != end; it.increment(ec)) {
    if (ec) {
      return Result<void>::failure({ErrorCode::io});
    }
    const auto rel = it->path().lexically_relative(spec.src_root);
    if (rel.empty() || has_dotdot_segment(rel.string())) {
      return Result<void>::failure({ErrorCode::corrupt});
    }
    const std::filesystem::path target = spec.dst_root / rel;
    const auto st = it->symlink_status(ec);
    if (ec) {
      return Result<void>::failure({ErrorCode::io});
    }
    if (std::filesystem::is_directory(st)) {
      std::filesystem::create_directories(target, ec);
      if (ec) {
        return Result<void>::failure({ErrorCode::io});
      }
    } else if (std::filesystem::is_regular_file(st)) {
      std::filesystem::create_directories(target.parent_path(), ec);
      if (ec) {
        return Result<void>::failure({ErrorCode::io});
      }
      std::filesystem::copy_file(it->path(), target,
                                 std::filesystem::copy_options::overwrite_existing, ec);
      if (ec) {
        return Result<void>::failure({ErrorCode::io});
      }
      struct stat src_st{};
      if (::lstat(it->path().c_str(), &src_st) == 0) {
        (void)::chmod(target.c_str(), src_st.st_mode & 0777U);
      }
    } else if (std::filesystem::is_symlink(st)) {
      if (rel.parent_path() != std::filesystem::path{"lib"} ||
          !is_safe_single_component(rel.filename().string())) {
        return Result<void>::failure({ErrorCode::corrupt});
      }
      const auto link_target = read_symlink_target_raw(it->path());
      if (!link_target.has_value() || !is_safe_single_component(*link_target)) {
        return Result<void>::failure({ErrorCode::corrupt});
      }
      pending_links.push_back(PendingLibSymlink{target, *link_target});
    } else {
      return Result<void>::failure({ErrorCode::corrupt});
    }
  }

  for (const auto &link : pending_links) {
    const std::filesystem::path sibling = link.dst_link.parent_path() / link.target;
    struct stat sib_st{};
    if (::lstat(sibling.c_str(), &sib_st) != 0 || !S_ISREG(sib_st.st_mode)) {
      return Result<void>::failure({ErrorCode::corrupt});
    }
    std::filesystem::create_directories(link.dst_link.parent_path(), ec);
    if (ec) {
      return Result<void>::failure({ErrorCode::io});
    }
    if (::symlink(link.target.c_str(), link.dst_link.c_str()) != 0) {
      return Result<void>::failure({ErrorCode::io, errno});
    }
  }

  return Result<void>::success();
}

struct SmokeCheckSpec {
  std::filesystem::path gen_dir;
  std::filesystem::path scratch_dir;
};

Result<std::string> run_binary_smoke_check(const SmokeCheckSpec &spec) {
  const std::filesystem::path binary = spec.gen_dir / "bin" / "blackbird";
  struct stat st{};
  if (::lstat(binary.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
    return Result<std::string>::failure({ErrorCode::corrupt});
  }
  if (::chmod(binary.c_str(), 0755) != 0) {
    return Result<std::string>::failure({ErrorCode::io, errno});
  }

  const std::filesystem::path smoke_home = spec.scratch_dir / "smoke-home";
  const std::filesystem::path smoke_auth = spec.scratch_dir / "smoke-auth";
  std::error_code ec;
  std::filesystem::create_directories(smoke_home, ec);
  std::filesystem::create_directories(smoke_auth, ec);
  if (ec) {
    return Result<std::string>::failure({ErrorCode::io});
  }
  (void)::chmod(smoke_home.c_str(), 0700);
  (void)::chmod(smoke_auth.c_str(), 0700);

  ProcessRequest req;
  req.executable = binary.string();
  req.args = {"--version"};
  req.timeout_seconds = kSmokeTimeoutSeconds;
  const char *path_env = std::getenv("PATH");
  req.env = {
      std::string{"PATH="} +
          ((path_env != nullptr && path_env[0] != '\0' && !has_control_chars(path_env))
               ? std::string{path_env}
               : std::string{"/usr/bin:/bin"}),
      "HOME=" + smoke_home.string(),
      "TMPDIR=" + smoke_home.string(),
      "BLACKBIRD_AUTH_HOME=" + smoke_auth.string(),
      "LC_ALL=C",
  };

  const auto outcome = run_subprocess(req);
  if (!outcome.has_value()) {
    return Result<std::string>::failure(outcome.error());
  }
  if (outcome.value().exit_code != 0) {
    return Result<std::string>::failure(
        {ErrorCode::corrupt, outcome.value().exit_code});
  }
  const std::string output =
      trim_ascii(sanitize_terminal_text(outcome.value().stdout_data));
  if (output.empty() || output.find("blackbird") == std::string::npos) {
    return Result<std::string>::failure({ErrorCode::corrupt});
  }
  return Result<std::string>::success(output);
}

struct AtomicSymlinkSwap {
  std::filesystem::path link_path;
  std::string target;
};

Result<void> atomic_swap_symlink(const AtomicSymlinkSwap &swap) {
  const std::filesystem::path parent = swap.link_path.parent_path();
  const std::string base = "." + swap.link_path.filename().string() + ".tmp";

  std::filesystem::path tmp_link;
  const auto pid_str = std::to_string(static_cast<long>(::getpid()));
  bool created = false;
  for (int attempt = 0; attempt < 64; ++attempt) {
    tmp_link = parent / (base + "." + pid_str + "." + std::to_string(attempt));
    if (::symlink(swap.target.c_str(), tmp_link.c_str()) == 0) {
      created = true;
      break;
    }
    if (errno != EEXIST) {
      return Result<void>::failure({ErrorCode::io, errno});
    }
  }
  if (!created) {
    return Result<void>::failure({ErrorCode::io, EEXIST});
  }

  TempFileGuard tmp_guard{tmp_link, false};
  if (::rename(tmp_link.c_str(), swap.link_path.c_str()) != 0) {
    return Result<void>::failure({ErrorCode::io, errno});
  }
  tmp_guard.keep = true;
  return Result<void>::success();
}

std::optional<std::string> read_symlink_target(const std::filesystem::path &path) {
  std::array<char, 4096> buf{};
  const ssize_t n = ::readlink(path.c_str(), buf.data(), buf.size() - 1U);
  if (n <= 0) {
    return std::nullopt;
  }
  return std::string{buf.data(), static_cast<std::size_t>(n)};
}

std::string format_human_bytes(std::uint64_t bytes) {
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(1);
  if (bytes >= 1024ULL * 1024ULL * 1024ULL) {
    oss << (static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0)) << " GB";
  } else if (bytes >= 1024ULL * 1024ULL) {
    oss << (static_cast<double>(bytes) / (1024.0 * 1024.0)) << " MB";
  } else if (bytes >= 1024ULL) {
    oss << (static_cast<double>(bytes) / 1024.0) << " KB";
  } else {
    return std::to_string(bytes) + " B";
  }
  return oss.str();
}

} // namespace

Result<UpgradeTarget> detect_upgrade_target() {
  struct utsname uts{};
  if (::uname(&uts) != 0) {
    return Result<UpgradeTarget>::failure({ErrorCode::io, errno});
  }
  const std::string_view sysname{uts.sysname};
  const std::string_view machine{uts.machine};

  std::string os_slug;
  if (sysname == "Darwin") {
    os_slug = "darwin";
  } else if (sysname == "Linux") {
    os_slug = "linux";
  } else {
    return Result<UpgradeTarget>::failure({ErrorCode::unsupported});
  }

  std::string arch_slug;
  if (machine == "arm64" || machine == "aarch64") {
    arch_slug = "arm64";
  } else if (machine == "x86_64" || machine == "amd64") {
    arch_slug = "x86_64";
  } else {
    return Result<UpgradeTarget>::failure({ErrorCode::unsupported});
  }

  const std::string triplet = os_slug + "-" + arch_slug;
  if (triplet != "darwin-arm64" && triplet != "linux-x86_64") {
    return Result<UpgradeTarget>::failure({ErrorCode::unsupported});
  }

  return Result<UpgradeTarget>::success(
      UpgradeTarget{std::move(os_slug), std::move(arch_slug), triplet});
}

Result<bool> valid_upgrade_version(std::string_view version) noexcept {
  if (version == "latest") {
    return Result<bool>::success(true);
  }
  if (version.size() < 2U || version.size() > 128U || version.front() != 'v') {
    return Result<bool>::success(false);
  }
  if (version.find("..") != std::string_view::npos ||
      version.find('/') != std::string_view::npos) {
    return Result<bool>::success(false);
  }
  for (std::size_t i = 1U; i < version.size(); ++i) {
    const char ch = version[i];
    const bool ok = (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= 'a' && ch <= 'z') || ch == '.' || ch == '_' || ch == '-';
    if (!ok) {
      return Result<bool>::success(false);
    }
  }
  return Result<bool>::success(true);
}

Result<std::string> resolve_upgrade_base_url(const UpgradeConfig &cfg) {
  const auto ver_ok = valid_upgrade_version(cfg.version);
  if (!ver_ok.has_value() || !ver_ok.value()) {
    return Result<std::string>::failure({ErrorCode::invalid_range});
  }

  std::string url = cfg.base_url;
  if (url.empty()) {
    if (cfg.version == "latest") {
      url = std::string{kDefaultReleaseLatestBase};
    } else {
      url = std::string{kDefaultReleaseTagPrefix} + cfg.version;
    }
  }

  while (!url.empty() && url.back() == '/') {
    url.pop_back();
  }

  if (url.empty() || has_control_or_whitespace(url)) {
    return Result<std::string>::failure({ErrorCode::invalid_range});
  }

  if (url.starts_with("https://")) {
    const std::string_view rest = std::string_view{url}.substr(8U);
    if (rest.empty() || rest.front() == '/' || rest.front() == ':' ||
        rest.find('?') != std::string_view::npos ||
        rest.find('#') != std::string_view::npos ||
        rest.find('@') != std::string_view::npos || has_dotdot_segment(rest)) {
      return Result<std::string>::failure({ErrorCode::invalid_range});
    }
    return Result<std::string>::success(std::move(url));
  }

  if (url.starts_with("file://")) {
    const auto parsed = parse_file_url_path(url);
    if (!parsed.has_value()) {
      return Result<std::string>::failure(parsed.error());
    }
    return Result<std::string>::success(std::move(url));
  }

  return Result<std::string>::failure({ErrorCode::invalid_range});
}

namespace {

struct UpgradeCheckWithRaw {
  UpgradeCheckResult check;
  std::string raw_manifest_json;
};

Result<UpgradeCheckWithRaw>
check_for_upgrade_with_raw(const UpgradeConfig &cfg,
                           const UpgradeProgressCallback &on_progress) {
  emit_progress(on_progress, UpgradeProgress{UpgradeStage::checking, 1, kTotalSteps,
                                             "Checking release metadata...", 0, 0});

  const auto target_res = detect_upgrade_target();
  if (!target_res.has_value()) {
    return Result<UpgradeCheckWithRaw>::failure(target_res.error());
  }
  const auto prefix_res = resolve_prefix(cfg);
  if (!prefix_res.has_value()) {
    return Result<UpgradeCheckWithRaw>::failure(prefix_res.error());
  }
  const auto base_url_res = resolve_upgrade_base_url(cfg);
  if (!base_url_res.has_value()) {
    return Result<UpgradeCheckWithRaw>::failure(base_url_res.error());
  }

  const std::string &base_url = base_url_res.value();
  const auto manifest_text =
      fetch_url_to_string(base_url + "/release-manifest.json", kMaxMetadataBytes);
  if (!manifest_text.has_value()) {
    return Result<UpgradeCheckWithRaw>::failure(manifest_text.error());
  }
  const auto sums_text =
      fetch_url_to_string(base_url + "/SHA256SUMS.txt", kMaxMetadataBytes);
  if (!sums_text.has_value()) {
    return Result<UpgradeCheckWithRaw>::failure(sums_text.error());
  }

  const auto manifest_res = parse_release_manifest(ManifestParseParams{
      manifest_text.value(), cfg.version, target_res.value().triplet});
  if (!manifest_res.has_value()) {
    return Result<UpgradeCheckWithRaw>::failure(manifest_res.error());
  }
  const ParsedManifest &manifest = manifest_res.value();

  const auto sums_sha_res =
      lookup_sha256sums_entry(Sha256SumsLookup{sums_text.value(), manifest.filename});
  if (!sums_sha_res.has_value()) {
    return Result<UpgradeCheckWithRaw>::failure(sums_sha_res.error());
  }

  // Dual-source cross-verification BEFORE downloading anything.
  if (!constant_time_equal_hex64(
          HexDigestPair{manifest.sha256, sums_sha_res.value()})) {
    return Result<UpgradeCheckWithRaw>::failure({ErrorCode::corrupt});
  }

  const InstalledVersionInfo installed =
      detect_installed_version(prefix_res.value(), cfg.current_version_string);

  UpgradeCheckWithRaw out;
  out.check.target = target_res.value().triplet;
  out.check.current_version = installed.version;
  out.check.current_commit = installed.commit;
  out.check.latest_version = manifest.version;
  out.check.latest_commit = manifest.commit;
  out.check.asset_name = manifest.filename;
  out.check.expected_sha256 = manifest.sha256;
  out.check.expected_size_bytes = manifest.size_bytes;
  out.check.update_available = compute_update_available(installed, manifest);
  out.check.download_url = base_url + "/" + manifest.filename;
  out.raw_manifest_json = manifest_text.value();

  return Result<UpgradeCheckWithRaw>::success(std::move(out));
}

} // namespace

Result<UpgradeCheckResult>
check_for_upgrade(const UpgradeConfig &cfg,
                  const UpgradeProgressCallback &on_progress) {
  auto res = check_for_upgrade_with_raw(cfg, on_progress);
  if (!res.has_value()) {
    return Result<UpgradeCheckResult>::failure(res.error());
  }
  return Result<UpgradeCheckResult>::success(std::move(res).value().check);
}

Result<UpgradeResult> perform_upgrade(const UpgradeConfig &cfg,
                                      const UpgradeProgressCallback &on_progress,
                                      const UpgradeConfirmCallback &confirm) {
  const auto prefix_res = resolve_prefix(cfg);
  if (!prefix_res.has_value()) {
    return Result<UpgradeResult>::failure(prefix_res.error());
  }
  const std::filesystem::path &prefix = prefix_res.value();

  const auto check_res = check_for_upgrade_with_raw(cfg, on_progress);
  if (!check_res.has_value()) {
    return Result<UpgradeResult>::failure(check_res.error());
  }
  const std::string &verified_manifest_json = check_res.value().raw_manifest_json;

  UpgradeResult result;
  result.check = check_res.value().check;
  result.installed_binary = prefix / "bin" / "blackbird";

  if (cfg.check_only) {
    result.already_up_to_date = !result.check.update_available;
    return Result<UpgradeResult>::success(std::move(result));
  }

  if (!cfg.force && !result.check.update_available) {
    result.already_up_to_date = true;
    return Result<UpgradeResult>::success(std::move(result));
  }

  // Permission gate: never download or touch <prefix> if not confirmed.
  if (!cfg.no_ask) {
    emit_progress(on_progress,
                  UpgradeProgress{UpgradeStage::prompt, 1, kTotalSteps,
                                  "Awaiting upgrade confirmation...", 0, 0});
    if (!confirm || !confirm(result.check)) {
      result.cancelled_by_user = true;
      return Result<UpgradeResult>::success(std::move(result));
    }
  }

  const auto tar_bin = find_executable_in_path("tar");
  if (!tar_bin.has_value()) {
    return Result<UpgradeResult>::failure({ErrorCode::unsupported});
  }

  const auto scratch_res = create_private_temp_dir("blackbird-upgrade");
  if (!scratch_res.has_value()) {
    return Result<UpgradeResult>::failure(scratch_res.error());
  }
  TempDirGuard scratch_guard{scratch_res.value(), false};

  // Step 2/6: Download tarball with progress callbacks.
  const std::filesystem::path tarball_path =
      scratch_res.value() / result.check.asset_name;
  FetchToFileRequest dl_req;
  dl_req.url = result.check.download_url;
  dl_req.dest = tarball_path;
  dl_req.expected_total_bytes = result.check.expected_size_bytes;
  dl_req.max_bytes = kMaxTarballBytes;
  dl_req.on_bytes = [&](std::uint64_t done, std::uint64_t total) {
    emit_progress(on_progress,
                  UpgradeProgress{UpgradeStage::downloading, 2, kTotalSteps,
                                  "Downloading " + result.check.asset_name, done,
                                  total});
  };

  const auto dl_size = fetch_url_to_file(dl_req);
  if (!dl_size.has_value()) {
    return Result<UpgradeResult>::failure(dl_size.error());
  }

  // Step 3/6: Verify downloaded size and SHA-256 via OpenSSL 3 EVP.
  emit_progress(on_progress, UpgradeProgress{UpgradeStage::verifying, 3, kTotalSteps,
                                             "Verifying SHA-256 digest...",
                                             dl_size.value(), dl_size.value()});
  if (result.check.expected_size_bytes > 0 &&
      dl_size.value() != result.check.expected_size_bytes) {
    return Result<UpgradeResult>::failure({ErrorCode::corrupt});
  }
  const auto actual_sha = compute_file_sha256_hex(tarball_path);
  if (!actual_sha.has_value()) {
    return Result<UpgradeResult>::failure(actual_sha.error());
  }
  if (!constant_time_equal_hex64(
          HexDigestPair{result.check.expected_sha256, actual_sha.value()})) {
    return Result<UpgradeResult>::failure({ErrorCode::corrupt});
  }

  // Step 4/6: Hardened archive inspection BEFORE extraction, then extract.
  const std::string stem =
      "blackbird-" + result.check.latest_version + "-" + result.check.target;
  emit_progress(on_progress,
                UpgradeProgress{UpgradeStage::extracting, 4, kTotalSteps,
                                "Inspecting and extracting archive...", 0, 0});
  const auto inspect_res =
      inspect_tarball_before_extract(TarInspectSpec{tarball_path, *tar_bin, stem});
  if (!inspect_res.has_value()) {
    return Result<UpgradeResult>::failure(inspect_res.error());
  }

  const std::filesystem::path extract_dir = scratch_res.value() / "extract";
  std::error_code ec;
  std::filesystem::create_directories(extract_dir, ec);
  if (ec) {
    return Result<UpgradeResult>::failure({ErrorCode::io});
  }

  ProcessRequest extract_req;
  extract_req.executable = *tar_bin;
  extract_req.args = {"-xzf", tarball_path.string(), "-C", extract_dir.string()};
  extract_req.env = build_filtered_env(false);
  extract_req.timeout_seconds = kTarTimeoutSeconds;
  const auto extract_out = run_subprocess(extract_req);
  if (!extract_out.has_value()) {
    return Result<UpgradeResult>::failure(extract_out.error());
  }
  if (extract_out.value().exit_code != 0) {
    return Result<UpgradeResult>::failure({ErrorCode::corrupt});
  }

  const auto tree_ok = verify_extracted_tree_safe(ExtractedTreeSpec{extract_dir, stem});
  if (!tree_ok.has_value()) {
    return Result<UpgradeResult>::failure(tree_ok.error());
  }

  const std::filesystem::path payload_root = extract_dir / stem;
  struct stat payload_bin_st{};
  if (::lstat((payload_root / "bin" / "blackbird").c_str(), &payload_bin_st) != 0 ||
      !S_ISREG(payload_bin_st.st_mode)) {
    return Result<UpgradeResult>::failure({ErrorCode::corrupt});
  }

  // Prepare <prefix>/lib/blackbird and acquire install.lock via flock.
  const std::filesystem::path bb_home = prefix / "lib" / "blackbird";
  const std::filesystem::path releases_dir = bb_home / "releases";
  const std::filesystem::path bin_dir = prefix / "bin";
  std::filesystem::create_directories(releases_dir, ec);
  if (ec) {
    return Result<UpgradeResult>::failure({ErrorCode::io});
  }
  std::filesystem::create_directories(bin_dir, ec);
  if (ec) {
    return Result<UpgradeResult>::failure({ErrorCode::io});
  }

  const std::filesystem::path lock_path = bb_home / "install.lock";
  UniqueFd lock_fd{
      ::open(lock_path.c_str(), O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600)};
  if (!lock_fd.valid()) {
    return Result<UpgradeResult>::failure({ErrorCode::io, errno});
  }
  if (::flock(lock_fd.fd, LOCK_EX | LOCK_NB) != 0) {
    return Result<UpgradeResult>::failure(
        {errno == EWOULDBLOCK ? ErrorCode::busy : ErrorCode::io, errno});
  }

  const std::filesystem::path current_link = bb_home / "current";
  struct stat cur_st{};
  if (::lstat(current_link.c_str(), &cur_st) == 0 && !S_ISLNK(cur_st.st_mode)) {
    return Result<UpgradeResult>::failure({ErrorCode::conflict});
  }
  struct stat bin_st{};
  if (::lstat(result.installed_binary.c_str(), &bin_st) == 0 &&
      S_ISDIR(bin_st.st_mode)) {
    return Result<UpgradeResult>::failure({ErrorCode::conflict});
  }

  const auto gen_res = create_generation_dir(releases_dir);
  if (!gen_res.has_value()) {
    return Result<UpgradeResult>::failure(gen_res.error());
  }
  TempDirGuard gen_guard{gen_res.value(), false};

  const auto copied = copy_tree_regular(TreeCopySpec{payload_root, gen_res.value()});
  if (!copied.has_value()) {
    return Result<UpgradeResult>::failure(copied.error());
  }

  const std::filesystem::path gen_manifest = gen_res.value() / "release-manifest.json";
  if (!std::filesystem::exists(gen_manifest, ec)) {
    const auto wrote = atomic_write_file(gen_manifest, verified_manifest_json, 0644);
    if (!wrote.has_value()) {
      return Result<UpgradeResult>::failure(wrote.error());
    }
  }

  // Step 5/6: Offline smoke check BEFORE swapping symlinks.
  emit_progress(on_progress,
                UpgradeProgress{UpgradeStage::smoke_testing, 5, kTotalSteps,
                                "Running smoke check on staged binary...", 0, 0});
  const auto smoke_res =
      run_binary_smoke_check(SmokeCheckSpec{gen_res.value(), scratch_res.value()});
  if (!smoke_res.has_value()) {
    return Result<UpgradeResult>::failure(smoke_res.error());
  }

  // Step 6/6: Atomic generation swap (<prefix>/lib/blackbird/current &
  // <prefix>/bin/blackbird).
  emit_progress(on_progress,
                UpgradeProgress{UpgradeStage::installing, 6, kTotalSteps,
                                "Activating verified generation atomically...", 0, 0});

  const std::optional<std::string> prev_current = read_symlink_target(current_link);
  const std::string rel_gen_target = "releases/" + gen_res.value().filename().string();
  const auto swap_current =
      atomic_swap_symlink(AtomicSymlinkSwap{current_link, rel_gen_target});
  if (!swap_current.has_value()) {
    return Result<UpgradeResult>::failure(swap_current.error());
  }

  const auto swap_bin = atomic_swap_symlink(AtomicSymlinkSwap{
      result.installed_binary, "../lib/blackbird/current/bin/blackbird"});
  if (!swap_bin.has_value()) {
    // Roll back current symlink cleanly if bin/blackbird swap failed.
    if (prev_current.has_value()) {
      (void)atomic_swap_symlink(AtomicSymlinkSwap{current_link, *prev_current});
    } else {
      (void)::unlink(current_link.c_str());
    }
    return Result<UpgradeResult>::failure(swap_bin.error());
  }

  gen_guard.keep = true;
  result.upgraded = true;
  result.generation_dir = gen_res.value();
  result.installed_version_output = smoke_res.value();

  emit_progress(on_progress,
                UpgradeProgress{UpgradeStage::complete, kTotalSteps, kTotalSteps,
                                "Upgraded to " + result.check.latest_version,
                                result.check.expected_size_bytes,
                                result.check.expected_size_bytes});

  return Result<UpgradeResult>::success(std::move(result));
}

std::string format_upgrade_progress_line(const UpgradeProgress &p) {
  std::ostringstream oss;
  if (p.step_total > 0U) {
    oss << "[" << static_cast<unsigned>(p.step_index) << "/"
        << static_cast<unsigned>(p.step_total) << "] ";
  }
  if (p.bytes_total > 0U) {
    const std::uint64_t clamped = std::min(p.bytes_done, p.bytes_total);
    const std::uint64_t pct =
        (clamped <= (std::numeric_limits<std::uint64_t>::max() / 100ULL))
            ? ((clamped * 100ULL) / p.bytes_total)
            : std::min<std::uint64_t>(100ULL, clamped / (p.bytes_total / 100ULL));
    constexpr std::size_t kBarWidth = 16U;
    const std::size_t filled = static_cast<std::size_t>((pct * kBarWidth) / 100ULL);
    oss << "[";
    for (std::size_t i = 0; i < kBarWidth; ++i) {
      oss << (i < filled ? "\xE2\x96\x88" : "\xE2\x96\x91");
    }
    oss << "] " << pct << "% (" << format_human_bytes(clamped) << " / "
        << format_human_bytes(p.bytes_total) << ") ";
  }
  oss << sanitize_terminal_text(p.message);
  return oss.str();
}

std::string format_upgrade_prompt_summary(const UpgradeCheckResult &check,
                                          const std::filesystem::path &prefix) {
  std::ostringstream oss;
  oss << "Blackbird Upgrade Available\n";
  oss << "  Target:   " << sanitize_terminal_text(check.target) << "\n";
  oss << "  Current:  "
      << (check.current_version.empty()
              ? std::string{"(not installed)"}
              : sanitize_terminal_text(check.current_version));
  if (!check.current_commit.empty()) {
    oss << " (" << sanitize_terminal_text(check.current_commit) << ")";
  }
  oss << "\n";
  oss << "  Latest:   " << sanitize_terminal_text(check.latest_version);
  if (!check.latest_commit.empty()) {
    oss << " (" << sanitize_terminal_text(check.latest_commit) << ")";
  }
  oss << "\n";
  oss << "  Asset:    " << sanitize_terminal_text(check.asset_name);
  if (check.expected_size_bytes > 0U) {
    oss << " (" << format_human_bytes(check.expected_size_bytes) << ")";
  }
  oss << "\n";
  oss << "  SHA-256:  " << sanitize_terminal_text(check.expected_sha256) << "\n";
  oss << "  Source:   " << sanitize_terminal_text(check.download_url) << "\n";
  oss << "  Prefix:   " << sanitize_terminal_text(prefix.string()) << "\n";
  oss << "Proceed with SHA-256 verified upgrade? [y/N]";
  return oss.str();
}

} // namespace blackbird
