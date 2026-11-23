#include "blackbird/platoon_runner.hpp"
#include "blackbird/json.hpp"
#include "blackbird/process_lifetime.hpp"
#include "blackbird/value.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <poll.h>
#include <set>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

extern char **environ;

namespace blackbird {
namespace {

using SteadyClock = std::chrono::steady_clock;
using WallClock = std::chrono::system_clock;

constexpr std::size_t max_peer_id_bytes = 48;
constexpr std::size_t max_role_bytes = 128;
constexpr std::size_t max_provider_bytes = 64;
constexpr std::size_t max_model_bytes = 128;
constexpr std::size_t max_effort_bytes = 32;
constexpr std::size_t max_c2_id_bytes = 64;
constexpr std::size_t max_tool_allowlist_bytes = 1024;
constexpr std::size_t max_prompt_bytes = 256U * 1024U;
constexpr std::size_t max_env_key_bytes = 128;
constexpr std::size_t max_env_value_bytes = 16U * 1024U;
constexpr std::size_t max_acp_line_bytes = 1024U * 1024U;
constexpr std::size_t max_retained_settled_peers = 256;
constexpr int max_grace_ms = 60000;
constexpr int destructor_grace_ms = 250;
constexpr int drain_grace_ms = 200;
constexpr int poll_interval_ms = 25;

std::int64_t wall_now_ns() noexcept {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             WallClock::now().time_since_epoch())
      .count();
}

struct OwnedFd {
  int fd = -1;
  OwnedFd() = default;
  explicit OwnedFd(int descriptor) noexcept : fd(descriptor) {}
  ~OwnedFd() { close(); }
  OwnedFd(const OwnedFd &) = delete;
  OwnedFd &operator=(const OwnedFd &) = delete;
  OwnedFd(OwnedFd &&other) noexcept : fd(std::exchange(other.fd, -1)) {}
  OwnedFd &operator=(OwnedFd &&other) noexcept {
    if (this != &other) {
      close();
      fd = std::exchange(other.fd, -1);
    }
    return *this;
  }
  int release() noexcept { return std::exchange(fd, -1); }
  void close() noexcept {
    if (fd >= 0) {
      (void)::close(std::exchange(fd, -1));
    }
  }
};

struct PipePair {
  OwnedFd read_end;
  OwnedFd write_end;
};

Result<PipePair> create_cloexec_pipe() {
  int raw[2]{-1, -1};
  if (::pipe(raw) != 0)
    return Result<PipePair>::failure({ErrorCode::io, errno});
  OwnedFd raw_read{raw[0]};
  OwnedFd raw_write{raw[1]};

  const int normalized_read = ::fcntl(raw_read.fd, F_DUPFD_CLOEXEC, 3);
  if (normalized_read < 0)
    return Result<PipePair>::failure({ErrorCode::io, errno});
  OwnedFd read_fd{normalized_read};

  const int normalized_write = ::fcntl(raw_write.fd, F_DUPFD_CLOEXEC, 3);
  if (normalized_write < 0)
    return Result<PipePair>::failure({ErrorCode::io, errno});
  OwnedFd write_fd{normalized_write};

  return Result<PipePair>::success(PipePair{std::move(read_fd), std::move(write_fd)});
}

Result<void> set_nonblocking(int fd) {
  const int flags = ::fcntl(fd, F_GETFL);
  if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return Result<void>::failure({ErrorCode::io, errno});
  return Result<void>::success();
}

Result<std::filesystem::path> current_executable_path() {
#ifdef __APPLE__
  std::uint32_t length = 0;
  (void)::_NSGetExecutablePath(nullptr, &length);
  if (length == 0)
    return Result<std::filesystem::path>::failure({ErrorCode::io, EINVAL});
  std::string buffer(length, '\0');
  if (::_NSGetExecutablePath(buffer.data(), &length) != 0)
    return Result<std::filesystem::path>::failure({ErrorCode::io, errno});
  std::error_code ec;
  auto resolved = std::filesystem::canonical(buffer.c_str(), ec);
  if (ec)
    return Result<std::filesystem::path>::failure({ErrorCode::io, ec.value()});
  return Result<std::filesystem::path>::success(std::move(resolved));
#else
  std::string buffer(256, '\0');
  for (;;) {
    const auto count = ::readlink("/proc/self/exe", buffer.data(), buffer.size());
    if (count < 0)
      return Result<std::filesystem::path>::failure({ErrorCode::io, errno});
    if (static_cast<std::size_t>(count) < buffer.size()) {
      buffer.resize(static_cast<std::size_t>(count));
      std::error_code ec;
      auto resolved = std::filesystem::canonical(buffer, ec);
      if (ec)
        return Result<std::filesystem::path>::failure({ErrorCode::io, ec.value()});
      return Result<std::filesystem::path>::success(std::move(resolved));
    }
    if (buffer.size() > buffer.max_size() / 2U)
      return Result<std::filesystem::path>::failure({ErrorCode::invalid_range});
    buffer.resize(buffer.size() * 2U);
  }
#endif
}

Result<std::filesystem::path> resolve_path_executable(std::string_view binary) {
  const char *env = std::getenv("PATH");
  if (env == nullptr || *env == '\0')
    return Result<std::filesystem::path>::failure({ErrorCode::io, ENOENT});
  std::string_view paths{env};
  while (!paths.empty()) {
    const auto end = paths.find(':');
    const auto dir = paths.substr(0, end);
    if (!dir.empty() && dir.front() == '/') {
      std::error_code ec;
      auto candidate = std::filesystem::path{dir} / binary;
      const auto st = std::filesystem::status(candidate, ec);
      if (!ec && std::filesystem::exists(st) && std::filesystem::is_regular_file(st) &&
          ::access(candidate.c_str(), X_OK) == 0) {
        return Result<std::filesystem::path>::success(std::move(candidate));
      }
    }
    if (end == std::string_view::npos)
      break;
    paths.remove_prefix(end + 1);
  }
  return Result<std::filesystem::path>::failure({ErrorCode::io, ENOENT});
}

bool has_nul_or_control(std::string_view text) noexcept {
  for (const char ch : text) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7fU)
      return true;
  }
  return false;
}

bool valid_token_identifier(std::string_view value, std::size_t max_len) noexcept {
  if (value.empty() || value.size() > max_len || value.front() == '-' ||
      !valid_utf8(value))
    return false;
  for (const char ch : value) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte <= 0x20U || byte >= 0x7fU)
      return false;
  }
  return true;
}

bool valid_effort(std::string_view value) noexcept {
  if (value.empty() || value.size() > max_effort_bytes || value.front() == '-')
    return false;
  for (const char ch : value) {
    const bool ok =
        (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
    if (!ok)
      return false;
  }
  return true;
}

bool valid_c2_identifier(std::string_view value) noexcept {
  if (value.empty() || value.size() > max_c2_id_bytes)
    return false;
  if (value.front() == '-' || value.front() == '.')
    return false;
  if (value.find("..") != std::string_view::npos)
    return false;
  for (const char ch : value) {
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == ':' ||
                    ch == '@' || ch == '-';
    if (!ok)
      return false;
  }
  return true;
}

bool valid_tool_allowlist(std::string_view value) noexcept {
  if (value.empty() || value.size() > max_tool_allowlist_bytes)
    return false;
  if (value.front() == '-' || value.front() == ',' || value.back() == ',')
    return false;
  bool at_token_start = true;
  for (const char ch : value) {
    if (ch == ',') {
      if (at_token_start)
        return false;
      at_token_start = true;
      continue;
    }
    if (at_token_start && ch == '-')
      return false;
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '_' || ch == '*' || ch == '+' ||
                    ch == '-';
    if (!ok)
      return false;
    at_token_start = false;
  }
  return !at_token_start;
}

std::string ascii_upper(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
  }
  return out;
}

bool is_ambient_secret_env_key(std::string_view key) {
  const std::string upper = ascii_upper(key);
  if (upper == "KEY" || upper.ends_with("_KEY"))
    return true;
  constexpr std::array<std::string_view, 7> secret_markers = {
      "API_KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY", "BEARER"};
  for (const auto marker : secret_markers) {
    if (upper.find(marker) != std::string::npos)
      return true;
  }
  return false;
}

bool is_disallowed_extra_env_key(std::string_view key) {
  const std::string upper = ascii_upper(key);
  if (upper.starts_with("LD_") || upper.starts_with("DYLD_") || upper == "IFS" ||
      upper == "BASH_ENV" || upper == "ENV" || upper == "PROMPT_COMMAND")
    return true;
  return is_ambient_secret_env_key(key);
}

bool is_allowlisted_external_env_key(std::string_view key) {
  if (key.empty() || is_ambient_secret_env_key(key))
    return false;
  constexpr std::array<std::string_view, 16> exact_allowed = {
      "HOME",        "USER",          "LOGNAME",      "PATH",          "TMPDIR",
      "TERM",        "COLORTERM",     "NO_COLOR",     "LANG",          "TZ",
      "SHELL",       "SSH_AUTH_SOCK", "ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS",
      "TSAN_OPTIONS"};
  for (const auto allowed : exact_allowed) {
    if (key == allowed)
      return true;
  }
  return key.starts_with("LC_") || key.starts_with("XDG_") ||
         key.starts_with("BLACKBIRD_PLATOON_");
}

std::vector<std::string>
build_spawn_env(PlatoonPeerDriver driver,
                const std::vector<std::pair<std::string, std::string>> &extra_env) {
  std::vector<std::string> env_storage;
  std::map<std::string, std::string, std::less<>> overrides;
  for (const auto &[key, value] : extra_env)
    overrides.emplace(key, value);

  const bool external_driver = (driver != PlatoonPeerDriver::blackbird);
  if (environ != nullptr) {
    for (char **entry = environ; *entry != nullptr; ++entry) {
      const std::string_view item{*entry};
      const auto eq = item.find('=');
      if (eq == std::string_view::npos)
        continue;
      const std::string_view key = item.substr(0, eq);
      if (overrides.contains(key))
        continue;
      if (external_driver && !is_allowlisted_external_env_key(key))
        continue;
      env_storage.emplace_back(item);
    }
  }
  for (const auto &[key, value] : extra_env)
    env_storage.push_back(key + "=" + value);
  return env_storage;
}

bool valid_env_key(std::string_view key) noexcept {
  if (key.empty() || key.size() > max_env_key_bytes)
    return false;
  for (std::size_t i = 0; i < key.size(); ++i) {
    const char ch = key[i];
    const bool alpha =
        (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_';
    const bool digit = ch >= '0' && ch <= '9';
    if (i == 0 ? !alpha : !(alpha || digit))
      return false;
  }
  return true;
}

bool valid_absolute_path(const std::filesystem::path &path) {
  const std::string native = path.string();
  if (native.empty() || native.find('\0') != std::string::npos || !valid_utf8(native))
    return false;
  return path.is_absolute();
}

// Ring buffer preserving the exact last `capacity` bytes in O(N) total time.
class TailRing {
public:
  explicit TailRing(std::size_t capacity) : buffer_(capacity) {}

  void append(std::string_view chunk) {
    total_bytes_ += chunk.size();
    const std::size_t cap = buffer_.size();
    if (cap == 0 || chunk.empty())
      return;
    if (chunk.size() >= cap) {
      const char *tail_src = chunk.data() + (chunk.size() - cap);
      std::memcpy(buffer_.data(), tail_src, cap);
      head_ = 0;
      size_ = cap;
      return;
    }
    const std::size_t write_pos = (head_ + size_) % cap;
    const std::size_t first_part = std::min(chunk.size(), cap - write_pos);
    std::memcpy(buffer_.data() + write_pos, chunk.data(), first_part);
    const std::size_t second_part = chunk.size() - first_part;
    if (second_part > 0)
      std::memcpy(buffer_.data(), chunk.data() + first_part, second_part);
    if (size_ + chunk.size() > cap) {
      const std::size_t dropped = (size_ + chunk.size()) - cap;
      head_ = (head_ + dropped) % cap;
      size_ = cap;
    } else {
      size_ += chunk.size();
    }
  }

  std::size_t total_bytes() const noexcept { return total_bytes_; }

  std::string utf8_tail() const {
    if (size_ == 0)
      return {};
    std::string raw;
    raw.resize(size_);
    const std::size_t cap = buffer_.size();
    const std::size_t first_part = std::min(size_, cap - head_);
    std::memcpy(raw.data(), buffer_.data() + head_, first_part);
    const std::size_t second_part = size_ - first_part;
    if (second_part > 0)
      std::memcpy(raw.data() + first_part, buffer_.data(), second_part);

    std::size_t start = 0;
    if (total_bytes_ > size_) {
      // Skip up to 3 orphaned leading UTF-8 continuation bytes after wraparound.
      std::size_t skipped = 0;
      while (start < raw.size() && skipped < 3U &&
             (static_cast<unsigned char>(raw[start]) & 0xc0U) == 0x80U) {
        ++start;
        ++skipped;
      }
    }
    const std::string_view slice{raw.data() + start, raw.size() - start};
    if (valid_utf8(slice))
      return std::string{slice};

    // Sanitize any invalid UTF-8 bytes without exceeding max_output_bytes.
    std::string sanitized;
    sanitized.reserve(slice.size());
    std::size_t i = 0;
    while (i < slice.size()) {
      const auto lead = static_cast<unsigned char>(slice[i]);
      std::size_t seq_len = 0;
      if (lead < 0x80U)
        seq_len = 1;
      else if ((lead & 0xe0U) == 0xc0U)
        seq_len = 2;
      else if ((lead & 0xf0U) == 0xe0U)
        seq_len = 3;
      else if ((lead & 0xf8U) == 0xf0U)
        seq_len = 4;

      if (seq_len > 0 && i + seq_len <= slice.size() &&
          valid_utf8(slice.substr(i, seq_len))) {
        sanitized.append(slice.substr(i, seq_len));
        i += seq_len;
      } else {
        sanitized.push_back('?');
        ++i;
      }
    }
    return sanitized;
  }

private:
  std::vector<char> buffer_;
  std::size_t head_ = 0;
  std::size_t size_ = 0;
  std::size_t total_bytes_ = 0;
};

struct SignalRequest {
  pid_t leader_pid;
  int signal_number;
};

void signal_peer_group(SignalRequest request) noexcept {
  if (request.leader_pid <= 0)
    return;
  const int group_rc = ::kill(-request.leader_pid, request.signal_number);
  const pid_t observed_pgid = ::getpgid(request.leader_pid);
  if (group_rc != 0 || observed_pgid != request.leader_pid) {
    (void)::kill(request.leader_pid, request.signal_number);
  }
}

void wake_reader_locked(int wake_write_fd) noexcept {
  if (wake_write_fd < 0)
    return;
  const char byte = 1;
  (void)::write(wake_write_fd, &byte, 1);
}

struct ValidatedSpec {
  PlatoonPeerDriver driver = PlatoonPeerDriver::blackbird;
  std::string owner_actor;
  std::string command_room;
  std::string tool_allowlist;
  std::filesystem::path executable;
  std::filesystem::path working_dir;
  std::filesystem::path session_dir;
  std::vector<std::string> argv;
  std::string prompt;
};

bool valid_driver_enum(PlatoonPeerDriver driver) noexcept {
  switch (driver) {
  case PlatoonPeerDriver::blackbird:
  case PlatoonPeerDriver::claude_code:
  case PlatoonPeerDriver::codex:
  case PlatoonPeerDriver::pi:
  case PlatoonPeerDriver::antigravity:
  case PlatoonPeerDriver::acp:
    return true;
  }
  return false;
}

Result<ValidatedSpec> validate_spec(const PlatoonPeerSpec &spec) {
  if (!valid_driver_enum(spec.driver))
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  if (!valid_platoon_peer_id(spec.peer_id))
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  if (spec.role.empty() || spec.role.size() > max_role_bytes ||
      has_nul_or_control(spec.role) || !valid_utf8(spec.role))
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});

  const bool is_blackbird = (spec.driver == PlatoonPeerDriver::blackbird);
  if (is_blackbird || !spec.provider.empty()) {
    if (!valid_token_identifier(spec.provider, max_provider_bytes))
      return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  }
  if (is_blackbird || !spec.model.empty()) {
    if (!valid_token_identifier(spec.model, max_model_bytes))
      return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  }
  if (spec.effort.has_value() && !valid_effort(*spec.effort))
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  if (spec.workflow.has_value() && !valid_absolute_path(*spec.workflow))
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  if (!valid_absolute_path(spec.working_dir))
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  if (is_blackbird || !spec.session_dir.empty()) {
    if (!valid_absolute_path(spec.session_dir))
      return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  }
  if (spec.prompt.empty() || spec.prompt.size() > max_prompt_bytes ||
      spec.prompt.find('\0') != std::string::npos || !valid_utf8(spec.prompt))
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  if (spec.max_output_bytes == 0 ||
      spec.max_output_bytes > PlatoonRunner::max_output_bytes_limit)
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});

  std::string normalized_owner = spec.owner_actor.empty() ? "local" : spec.owner_actor;
  if (!valid_c2_identifier(normalized_owner))
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  if (!spec.command_room.empty() && !valid_c2_identifier(spec.command_room))
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  if (!spec.tool_allowlist.empty() && !valid_tool_allowlist(spec.tool_allowlist))
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  if (spec.extra_args.size() > PlatoonRunner::max_extra_args)
    return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  for (const auto &arg : spec.extra_args) {
    if (arg.size() > PlatoonRunner::max_extra_arg_bytes ||
        arg.find('\0') != std::string::npos || !valid_utf8(arg))
      return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  }

  std::set<std::string, std::less<>> seen_env;
  for (const auto &[key, value] : spec.extra_env) {
    if (!valid_env_key(key) || is_disallowed_extra_env_key(key))
      return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
    if (value.size() > max_env_value_bytes || value.find('\0') != std::string::npos ||
        !valid_utf8(value))
      return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
    if (!seen_env.insert(key).second)
      return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
  }

  std::error_code ec;
  const auto work_status = std::filesystem::status(spec.working_dir, ec);
  if (ec || !std::filesystem::exists(work_status))
    return Result<ValidatedSpec>::failure({ErrorCode::io, ENOENT});
  if (!std::filesystem::is_directory(work_status))
    return Result<ValidatedSpec>::failure({ErrorCode::io, ENOTDIR});

  if (!spec.session_dir.empty()) {
    ec.clear();
    const auto session_status = std::filesystem::status(spec.session_dir, ec);
    if (!ec && std::filesystem::exists(session_status) &&
        !std::filesystem::is_directory(session_status))
      return Result<ValidatedSpec>::failure({ErrorCode::io, ENOTDIR});
  }

  std::filesystem::path exe;
  if (spec.executable.empty()) {
    Result<std::filesystem::path> resolved =
        Result<std::filesystem::path>::failure({ErrorCode::invalid_range});
    switch (spec.driver) {
    case PlatoonPeerDriver::blackbird:
      resolved = current_executable_path();
      break;
    case PlatoonPeerDriver::claude_code:
      resolved = resolve_path_executable("claude");
      break;
    case PlatoonPeerDriver::codex:
      resolved = resolve_path_executable("codex");
      break;
    case PlatoonPeerDriver::pi:
      resolved = resolve_path_executable("pi");
      break;
    case PlatoonPeerDriver::antigravity:
      resolved = resolve_path_executable("agy");
      break;
    case PlatoonPeerDriver::acp:
      return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
    }
    if (!resolved.has_value())
      return Result<ValidatedSpec>::failure(resolved.error());
    exe = std::move(resolved).value();
  } else {
    if (!valid_absolute_path(spec.executable))
      return Result<ValidatedSpec>::failure({ErrorCode::invalid_range});
    exe = spec.executable;
  }

  ec.clear();
  const auto exe_status = std::filesystem::status(exe, ec);
  if (ec || !std::filesystem::exists(exe_status))
    return Result<ValidatedSpec>::failure({ErrorCode::io, ENOENT});
  if (!std::filesystem::is_regular_file(exe_status))
    return Result<ValidatedSpec>::failure({ErrorCode::io, EACCES});
  if (::access(exe.c_str(), X_OK) != 0)
    return Result<ValidatedSpec>::failure({ErrorCode::io, errno});

  ValidatedSpec out;
  out.driver = spec.driver;
  out.owner_actor = std::move(normalized_owner);
  out.command_room = spec.command_room;
  out.tool_allowlist = spec.tool_allowlist;
  out.executable = std::move(exe);
  out.working_dir = spec.working_dir;
  out.session_dir = spec.session_dir;
  out.prompt = spec.prompt;

  out.argv.reserve(16U + spec.extra_args.size());
  out.argv.push_back(out.executable.string());
  switch (spec.driver) {
  case PlatoonPeerDriver::blackbird:
    out.argv.emplace_back("--session");
    out.argv.push_back(out.session_dir.string());
    out.argv.emplace_back("--provider");
    out.argv.push_back(spec.provider);
    out.argv.emplace_back("--model");
    out.argv.push_back(spec.model);
    if (spec.effort.has_value()) {
      out.argv.emplace_back("--effort");
      out.argv.push_back(*spec.effort);
    }
    if (spec.workflow.has_value()) {
      out.argv.emplace_back("--workflow");
      out.argv.push_back(spec.workflow->string());
    }
    for (const auto &arg : spec.extra_args)
      out.argv.push_back(arg);
    out.argv.emplace_back("--plain");
    out.argv.emplace_back("--once");
    out.argv.push_back(spec.prompt);
    break;
  case PlatoonPeerDriver::claude_code:
    out.argv.emplace_back("-p");
    out.argv.push_back(spec.prompt);
    out.argv.emplace_back("--output-format");
    out.argv.emplace_back("stream-json");
    out.argv.emplace_back("--verbose");
    if (!spec.model.empty()) {
      out.argv.emplace_back("--model");
      out.argv.push_back(spec.model);
    }
    for (const auto &arg : spec.extra_args)
      out.argv.push_back(arg);
    break;
  case PlatoonPeerDriver::codex:
    out.argv.emplace_back("exec");
    out.argv.emplace_back("--json");
    if (!spec.model.empty()) {
      out.argv.emplace_back("-m");
      out.argv.push_back(spec.model);
    }
    for (const auto &arg : spec.extra_args)
      out.argv.push_back(arg);
    out.argv.push_back(spec.prompt);
    break;
  case PlatoonPeerDriver::pi:
    out.argv.emplace_back("--mode");
    out.argv.emplace_back("json");
    out.argv.emplace_back("-p");
    if (!spec.provider.empty()) {
      out.argv.emplace_back("--provider");
      out.argv.push_back(spec.provider);
    }
    if (!spec.model.empty()) {
      out.argv.emplace_back("--model");
      out.argv.push_back(spec.model);
    }
    if (!spec.session_dir.empty()) {
      out.argv.emplace_back("--session-dir");
      out.argv.push_back(spec.session_dir.string());
    }
    if (!spec.tool_allowlist.empty()) {
      out.argv.emplace_back("--tools");
      out.argv.push_back(spec.tool_allowlist);
    }
    for (const auto &arg : spec.extra_args)
      out.argv.push_back(arg);
    out.argv.push_back(spec.prompt);
    break;
  case PlatoonPeerDriver::antigravity:
    out.argv.emplace_back("--non-interactive");
    if (!spec.model.empty()) {
      out.argv.emplace_back("--model");
      out.argv.push_back(spec.model);
    }
    for (const auto &arg : spec.extra_args)
      out.argv.push_back(arg);
    out.argv.push_back(spec.prompt);
    break;
  case PlatoonPeerDriver::acp:
    for (const auto &arg : spec.extra_args)
      out.argv.push_back(arg);
    break;
  }
  return Result<ValidatedSpec>::success(std::move(out));
}

struct SpawnedProcess {
  pid_t pid = -1;
  OwnedFd stdin_write;
  OwnedFd output_read;
  OwnedFd stderr_read;
  OwnedFd wake_read;
  OwnedFd wake_write;
};

struct SpawnInput {
  const ValidatedSpec &validated;
  const std::vector<std::pair<std::string, std::string>> &extra_env;
};

Result<SpawnedProcess> spawn_peer_process(SpawnInput input) {
  const std::lock_guard spawn_lock{detail::process_spawn_mutex};

  struct sigaction child_policy{};
  if (::sigaction(SIGCHLD, nullptr, &child_policy) != 0)
    return Result<SpawnedProcess>::failure({ErrorCode::io, errno});
  if (child_policy.sa_handler == SIG_IGN || (child_policy.sa_flags & SA_NOCLDWAIT) != 0)
    return Result<SpawnedProcess>::failure({ErrorCode::unsupported, SIGCHLD});

  const bool acp_mode = (input.validated.driver == PlatoonPeerDriver::acp);

  auto output_pipe = create_cloexec_pipe();
  if (!output_pipe.has_value())
    return Result<SpawnedProcess>::failure(output_pipe.error());
  auto wake_pipe = create_cloexec_pipe();
  if (!wake_pipe.has_value())
    return Result<SpawnedProcess>::failure(wake_pipe.error());

  std::optional<PipePair> stdin_pipe;
  std::optional<PipePair> stderr_pipe;
  if (acp_mode) {
    auto sp = create_cloexec_pipe();
    if (!sp.has_value())
      return Result<SpawnedProcess>::failure(sp.error());
    stdin_pipe = std::move(sp).value();
    auto ep = create_cloexec_pipe();
    if (!ep.has_value())
      return Result<SpawnedProcess>::failure(ep.error());
    stderr_pipe = std::move(ep).value();
  }

  if (const auto r = set_nonblocking(output_pipe.value().read_end.fd); !r.has_value())
    return Result<SpawnedProcess>::failure(r.error());
  if (const auto r = set_nonblocking(wake_pipe.value().read_end.fd); !r.has_value())
    return Result<SpawnedProcess>::failure(r.error());
  if (const auto r = set_nonblocking(wake_pipe.value().write_end.fd); !r.has_value())
    return Result<SpawnedProcess>::failure(r.error());
#ifdef F_SETNOSIGPIPE
  if (::fcntl(wake_pipe.value().write_end.fd, F_SETNOSIGPIPE, 1) < 0)
    return Result<SpawnedProcess>::failure({ErrorCode::io, errno});
#endif
  if (stdin_pipe.has_value()) {
    if (const auto r = set_nonblocking(stdin_pipe->write_end.fd); !r.has_value())
      return Result<SpawnedProcess>::failure(r.error());
#ifdef F_SETNOSIGPIPE
    if (::fcntl(stdin_pipe->write_end.fd, F_SETNOSIGPIPE, 1) < 0)
      return Result<SpawnedProcess>::failure({ErrorCode::io, errno});
#endif
  }
  if (stderr_pipe.has_value()) {
    if (const auto r = set_nonblocking(stderr_pipe->read_end.fd); !r.has_value())
      return Result<SpawnedProcess>::failure(r.error());
  }

  posix_spawn_file_actions_t actions{};
  int rc = ::posix_spawn_file_actions_init(&actions);
  if (rc != 0)
    return Result<SpawnedProcess>::failure({ErrorCode::io, rc});
  struct ActionsGuard {
    posix_spawn_file_actions_t &value;
    ~ActionsGuard() { (void)::posix_spawn_file_actions_destroy(&value); }
  } actions_guard{actions};

  posix_spawnattr_t attributes{};
  rc = ::posix_spawnattr_init(&attributes);
  if (rc != 0)
    return Result<SpawnedProcess>::failure({ErrorCode::io, rc});
  struct AttrsGuard {
    posix_spawnattr_t &value;
    ~AttrsGuard() { (void)::posix_spawnattr_destroy(&value); }
  } attrs_guard{attributes};

  if (stdin_pipe.has_value()) {
    rc = ::posix_spawn_file_actions_adddup2(&actions, stdin_pipe->read_end.fd,
                                            STDIN_FILENO);
  } else {
    rc = ::posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null",
                                            O_RDONLY, 0);
  }
  if (rc == 0)
    rc = ::posix_spawn_file_actions_adddup2(&actions, output_pipe.value().write_end.fd,
                                            STDOUT_FILENO);
  if (rc == 0) {
    const int err_target = stderr_pipe.has_value() ? stderr_pipe->write_end.fd
                                                   : output_pipe.value().write_end.fd;
    rc = ::posix_spawn_file_actions_adddup2(&actions, err_target, STDERR_FILENO);
  }
  if (rc == 0) {
#ifdef __APPLE__
    rc = ::posix_spawn_file_actions_addchdir(&actions,
                                             input.validated.working_dir.c_str());
#else
    rc = ::posix_spawn_file_actions_addchdir_np(&actions,
                                                input.validated.working_dir.c_str());
#endif
  }

  sigset_t empty_mask{};
  sigemptyset(&empty_mask);
  sigset_t default_signals{};
  sigemptyset(&default_signals);
  for (const int sig : {SIGINT, SIGQUIT, SIGTERM, SIGHUP, SIGPIPE, SIGCHLD, SIGTSTP,
                        SIGTTIN, SIGTTOU, SIGUSR1, SIGUSR2, SIGWINCH}) {
    sigaddset(&default_signals, sig);
  }
  if (rc == 0)
    rc = ::posix_spawnattr_setsigmask(&attributes, &empty_mask);
  if (rc == 0)
    rc = ::posix_spawnattr_setsigdefault(&attributes, &default_signals);
  if (rc == 0)
    rc = ::posix_spawnattr_setpgroup(&attributes, 0);
  if (rc == 0) {
    const short flags = static_cast<short>(
        POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    rc = ::posix_spawnattr_setflags(&attributes, flags);
  }
  if (rc != 0)
    return Result<SpawnedProcess>::failure({ErrorCode::io, rc});

  std::vector<std::string> argv_storage = input.validated.argv;
  std::vector<char *> argv_ptrs;
  argv_ptrs.reserve(argv_storage.size() + 1U);
  for (auto &arg : argv_storage)
    argv_ptrs.push_back(arg.data());
  argv_ptrs.push_back(nullptr);

  std::vector<std::string> env_storage =
      build_spawn_env(input.validated.driver, input.extra_env);

  std::vector<char *> envp_ptrs;
  envp_ptrs.reserve(env_storage.size() + 1U);
  for (auto &entry : env_storage)
    envp_ptrs.push_back(entry.data());
  envp_ptrs.push_back(nullptr);

  pid_t child_pid = -1;
  rc = ::posix_spawn(&child_pid, input.validated.executable.c_str(), &actions,
                     &attributes, argv_ptrs.data(), envp_ptrs.data());
  // Parent closes child's pipe ends immediately regardless of spawn outcome.
  output_pipe.value().write_end.close();
  if (stdin_pipe.has_value())
    stdin_pipe->read_end.close();
  if (stderr_pipe.has_value())
    stderr_pipe->write_end.close();
  if (rc != 0)
    return Result<SpawnedProcess>::failure({ErrorCode::io, rc});

  ++detail::owned_children;
  SpawnedProcess proc;
  proc.pid = child_pid;
  if (stdin_pipe.has_value())
    proc.stdin_write = std::move(stdin_pipe->write_end);
  proc.output_read = std::move(output_pipe.value().read_end);
  if (stderr_pipe.has_value())
    proc.stderr_read = std::move(stderr_pipe->read_end);
  proc.wake_read = std::move(wake_pipe.value().read_end);
  proc.wake_write = std::move(wake_pipe.value().write_end);
  return Result<SpawnedProcess>::success(std::move(proc));
}

bool jsonrpc_id_matches(const Value *id_val, std::uint64_t expected) noexcept {
  if (id_val == nullptr)
    return false;
  const auto *num = std::get_if<Number>(&id_val->value());
  if (num == nullptr)
    return false;
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage()))
    return *u == expected;
  if (const auto *s = std::get_if<std::int64_t>(&num->storage()))
    return *s >= 0 && static_cast<std::uint64_t>(*s) == expected;
  return false;
}

Result<std::string> dump_json_line(const Value &value) {
  auto dumped = dump_json(value);
  if (!dumped.has_value())
    return dumped;
  dumped.value().push_back('\n');
  return dumped;
}

Result<std::string> build_acp_initialize_line() {
  return dump_json_line(Value::object(
      {{"jsonrpc", Value{"2.0"}},
       {"id", Value{Number{std::uint64_t{1}}}},
       {"method", Value{"initialize"}},
       {"params", Value::object({{"protocolVersion", Value{Number{std::uint64_t{1}}}},
                                 {"clientCapabilities", Value::object({})},
                                 {"clientInfo",
                                  Value::object({{"name", Value{"blackbird"}},
                                                 {"version", Value{"0.1.0"}}})}})}}));
}

Result<std::string>
build_acp_session_new_line(const std::filesystem::path &working_dir) {
  return dump_json_line(Value::object(
      {{"jsonrpc", Value{"2.0"}},
       {"id", Value{Number{std::uint64_t{2}}}},
       {"method", Value{"session/new"}},
       {"params", Value::object({{"cwd", Value{working_dir.string()}},
                                 {"mcpServers", Value{Value::Array{}}}})}}));
}

struct AcpPromptPayload {
  std::string_view session_id;
  std::string_view prompt;
};

Result<std::string> build_acp_session_prompt_line(AcpPromptPayload payload) {
  return dump_json_line(Value::object(
      {{"jsonrpc", Value{"2.0"}},
       {"id", Value{Number{std::uint64_t{3}}}},
       {"method", Value{"session/prompt"}},
       {"params",
        Value::object(
            {{"sessionId", Value{std::string{payload.session_id}}},
             {"prompt", Value{Value::Array{Value::object(
                            {{"type", Value{"text"}},
                             {"text", Value{std::string{payload.prompt}}}})}}}})}}));
}

enum class AcpStage : std::uint8_t {
  inactive,
  awaiting_initialize,
  awaiting_session_new,
  awaiting_prompt,
  done,
};

struct AcpClientSession {
  AcpStage stage = AcpStage::inactive;
  bool failed = false;
  bool line_overflow = false;
  std::filesystem::path working_dir;
  std::string prompt;
  std::string write_buf;
  std::size_t write_offset = 0;
  std::string line_buf;

  void start(const std::filesystem::path &cwd, std::string prompt_text,
             OwnedFd &stdin_write) noexcept {
    working_dir = cwd;
    prompt = std::move(prompt_text);
    try {
      auto init = build_acp_initialize_line();
      if (!init.has_value()) {
        fail(stdin_write);
        return;
      }
      enqueue(std::move(init).value());
      stage = AcpStage::awaiting_initialize;
    } catch (...) {
      fail(stdin_write);
    }
  }

  void fail(OwnedFd &stdin_write) noexcept {
    failed = true;
    stage = AcpStage::done;
    write_buf.clear();
    write_offset = 0;
    stdin_write.close();
  }

  void finish(OwnedFd &stdin_write) noexcept {
    stage = AcpStage::done;
    write_buf.clear();
    write_offset = 0;
    stdin_write.close();
  }

  void enqueue(std::string_view line) {
    if (write_offset == write_buf.size()) {
      write_buf.clear();
      write_offset = 0;
    }
    write_buf.append(line);
  }

  bool has_pending_write() const noexcept { return write_offset < write_buf.size(); }

  void flush_stdin(OwnedFd &stdin_write) noexcept {
    while (stdin_write.fd >= 0 && write_offset < write_buf.size()) {
      const ssize_t n = ::write(stdin_write.fd, write_buf.data() + write_offset,
                                write_buf.size() - write_offset);
      if (n > 0) {
        write_offset += static_cast<std::size_t>(n);
        if (write_offset == write_buf.size()) {
          write_buf.clear();
          write_offset = 0;
        }
      } else if (n < 0 && errno == EINTR) {
        continue;
      } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      } else {
        if (stage != AcpStage::done && stage != AcpStage::inactive)
          fail(stdin_write);
        else
          stdin_write.close();
        break;
      }
    }
  }

  void handle_line(std::string_view line, OwnedFd &stdin_write) noexcept {
    if (stage == AcpStage::inactive || stage == AcpStage::done)
      return;
    if (!line.empty() && line.back() == '\r')
      line.remove_suffix(1);
    const auto first = line.find_first_not_of(" \t");
    if (first == std::string_view::npos)
      return;
    line.remove_prefix(first);
    if (line.empty() || line.front() != '{')
      return;

    try {
      const auto parsed = parse_json(line);
      if (!parsed.has_value())
        return;
      const Value &msg = parsed.value();
      if (!std::holds_alternative<Value::Object>(msg.value()))
        return;
      // Ignore notifications and agent->client requests.
      if (msg.find("method") != nullptr)
        return;
      const Value *id_val = msg.find("id");
      if (id_val == nullptr)
        return;

      const Value *err_val = msg.find("error");
      const bool has_error =
          (err_val != nullptr &&
           !std::holds_alternative<std::nullptr_t>(err_val->value()));
      const Value *res_val = msg.find("result");

      if (stage == AcpStage::awaiting_initialize && jsonrpc_id_matches(id_val, 1U)) {
        if (has_error || res_val == nullptr) {
          fail(stdin_write);
          return;
        }
        auto next = build_acp_session_new_line(working_dir);
        if (!next.has_value()) {
          fail(stdin_write);
          return;
        }
        enqueue(std::move(next).value());
        stage = AcpStage::awaiting_session_new;
      } else if (stage == AcpStage::awaiting_session_new &&
                 jsonrpc_id_matches(id_val, 2U)) {
        if (has_error || res_val == nullptr ||
            !std::holds_alternative<Value::Object>(res_val->value())) {
          fail(stdin_write);
          return;
        }
        const Value *sid = res_val->find("sessionId");
        if (sid == nullptr)
          sid = res_val->find("session_id");
        if (sid == nullptr || !std::holds_alternative<std::string>(sid->value()) ||
            sid->string().empty()) {
          fail(stdin_write);
          return;
        }
        auto next = build_acp_session_prompt_line({sid->string(), prompt});
        if (!next.has_value()) {
          fail(stdin_write);
          return;
        }
        enqueue(std::move(next).value());
        stage = AcpStage::awaiting_prompt;
      } else if (stage == AcpStage::awaiting_prompt && jsonrpc_id_matches(id_val, 3U)) {
        if (has_error || res_val == nullptr) {
          fail(stdin_write);
          return;
        }
        finish(stdin_write);
      }
    } catch (...) {
      fail(stdin_write);
    }
  }

  void feed_stdout(std::string_view chunk, OwnedFd &stdin_write) noexcept {
    if (stage == AcpStage::inactive || stage == AcpStage::done)
      return;
    std::size_t pos = 0;
    while (pos < chunk.size() && stage != AcpStage::done) {
      const auto nl = chunk.find('\n', pos);
      const auto piece = (nl == std::string_view::npos) ? chunk.substr(pos)
                                                        : chunk.substr(pos, nl - pos);
      if (!line_overflow) {
        if (line_buf.size() + piece.size() > max_acp_line_bytes) {
          line_buf.clear();
          line_overflow = true;
        } else {
          try {
            line_buf.append(piece);
          } catch (...) {
            fail(stdin_write);
            return;
          }
        }
      }
      if (nl == std::string_view::npos)
        break;
      if (!line_overflow)
        handle_line(line_buf, stdin_write);
      line_buf.clear();
      line_overflow = false;
      pos = nl + 1;
    }
  }

  void on_stdout_eof(OwnedFd &stdin_write) noexcept {
    if (stage == AcpStage::inactive || stage == AcpStage::done)
      return;
    if (!line_overflow && !line_buf.empty())
      handle_line(line_buf, stdin_write);
    line_buf.clear();
    line_overflow = false;
    if (stage != AcpStage::done)
      fail(stdin_write);
  }
};

} // namespace

const char *platoon_peer_state_name(PlatoonPeerState state) noexcept {
  switch (state) {
  case PlatoonPeerState::running:
    return "running";
  case PlatoonPeerState::completed:
    return "completed";
  case PlatoonPeerState::failed:
    return "failed";
  case PlatoonPeerState::stopped:
    return "stopped";
  }
  return "unknown";
}

const char *platoon_driver_name(PlatoonPeerDriver driver) noexcept {
  switch (driver) {
  case PlatoonPeerDriver::blackbird:
    return "blackbird";
  case PlatoonPeerDriver::claude_code:
    return "claude_code";
  case PlatoonPeerDriver::codex:
    return "codex";
  case PlatoonPeerDriver::pi:
    return "pi";
  case PlatoonPeerDriver::antigravity:
    return "antigravity";
  case PlatoonPeerDriver::acp:
    return "acp";
  }
  return "unknown";
}

Result<PlatoonPeerDriver> parse_platoon_driver(std::string_view name) noexcept {
  if (name == "blackbird")
    return Result<PlatoonPeerDriver>::success(PlatoonPeerDriver::blackbird);
  if (name == "claude_code" || name == "claude-code")
    return Result<PlatoonPeerDriver>::success(PlatoonPeerDriver::claude_code);
  if (name == "codex")
    return Result<PlatoonPeerDriver>::success(PlatoonPeerDriver::codex);
  if (name == "pi")
    return Result<PlatoonPeerDriver>::success(PlatoonPeerDriver::pi);
  if (name == "antigravity")
    return Result<PlatoonPeerDriver>::success(PlatoonPeerDriver::antigravity);
  if (name == "acp")
    return Result<PlatoonPeerDriver>::success(PlatoonPeerDriver::acp);
  return Result<PlatoonPeerDriver>::failure({ErrorCode::invalid_range});
}

bool valid_platoon_peer_id(std::string_view id) noexcept {
  if (id.empty() || id.size() > max_peer_id_bytes || id.front() == '-')
    return false;
  for (const char ch : id) {
    const bool ok =
        (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
    if (!ok)
      return false;
  }
  return true;
}

Value to_value(const PlatoonPeerSnapshot &snapshot) {
  Value::Object obj;
  obj.reserve(17);
  obj.emplace_back("peer_id", Value{snapshot.peer_id});
  obj.emplace_back("driver", Value{platoon_driver_name(snapshot.driver)});
  obj.emplace_back("role", Value{snapshot.role});
  obj.emplace_back("provider", Value{snapshot.provider});
  obj.emplace_back("model", Value{snapshot.model});
  obj.emplace_back("owner_actor", Value{snapshot.owner_actor});
  obj.emplace_back("command_room", Value{snapshot.command_room});
  obj.emplace_back("tool_allowlist", Value{snapshot.tool_allowlist});
  obj.emplace_back("working_dir", Value{snapshot.working_dir.string()});
  obj.emplace_back("session_dir", Value{snapshot.session_dir.string()});
  obj.emplace_back("state", Value{platoon_peer_state_name(snapshot.state)});
  obj.emplace_back("pid", Value{Number{snapshot.pid}});
  if (snapshot.exit_code.has_value()) {
    obj.emplace_back("exit_code",
                     Value{Number{static_cast<std::int64_t>(*snapshot.exit_code)}});
  } else {
    obj.emplace_back("exit_code", Value{nullptr});
  }
  obj.emplace_back("output_tail", Value{snapshot.output_tail});
  obj.emplace_back("output_bytes",
                   Value{Number{static_cast<std::uint64_t>(snapshot.output_bytes)}});
  obj.emplace_back("started_ns", Value{Number{snapshot.started_ns}});
  obj.emplace_back("finished_ns", Value{Number{snapshot.finished_ns}});
  return Value{std::move(obj)};
}

struct PlatoonRunner::Impl {
  struct ReaderHandles {
    OwnedFd stdin_write;
    OwnedFd output_read;
    OwnedFd stderr_read;
    OwnedFd wake_read;
    std::string acp_prompt;
  };

  struct Peer {
    std::string peer_id;
    PlatoonPeerDriver driver = PlatoonPeerDriver::blackbird;
    std::string role;
    std::string provider;
    std::string model;
    std::string owner_actor;
    std::string command_room;
    std::string tool_allowlist;
    std::filesystem::path working_dir;
    std::filesystem::path session_dir;

    PlatoonPeerState state = PlatoonPeerState::running;
    pid_t pid = -1;
    std::optional<int> exit_code;
    TailRing output_ring;
    std::int64_t started_ns = 0;
    std::int64_t finished_ns = 0;
    std::uint64_t order = 0;

    bool launched = false;
    bool counted = false;
    bool stop_requested = false;
    int stop_grace_ms = 1500;
    bool settled = false;
    OwnedFd wake_write;
    std::thread reader;

    Peer(const PlatoonPeerSpec &spec, const ValidatedSpec &validated,
         std::uint64_t seq_order)
        : peer_id(spec.peer_id), driver(validated.driver), role(spec.role),
          provider(spec.provider), model(spec.model),
          owner_actor(validated.owner_actor), command_room(validated.command_room),
          tool_allowlist(validated.tool_allowlist), working_dir(validated.working_dir),
          session_dir(validated.session_dir), output_ring(spec.max_output_bytes),
          order(seq_order) {}

    ~Peer() {
      if (reader.joinable())
        reader.join();
    }
  };

  mutable std::mutex mutex;
  std::condition_variable cv;
  std::size_t max_peers = default_max_peers;
  std::uint64_t next_order = 1;
  bool shutting_down = false;
  std::map<std::string, std::shared_ptr<Peer>, std::less<>> peers;

  explicit Impl(std::size_t limit) : max_peers(limit) {}

  PlatoonPeerSnapshot make_snapshot_locked(const Peer &peer) const {
    PlatoonPeerSnapshot snap;
    snap.peer_id = peer.peer_id;
    snap.driver = peer.driver;
    snap.role = peer.role;
    snap.provider = peer.provider;
    snap.model = peer.model;
    snap.owner_actor = peer.owner_actor;
    snap.command_room = peer.command_room;
    snap.tool_allowlist = peer.tool_allowlist;
    snap.working_dir = peer.working_dir;
    snap.session_dir = peer.session_dir;
    snap.state = peer.state;
    snap.pid = static_cast<std::int64_t>(peer.pid);
    snap.exit_code = peer.exit_code;
    snap.output_tail = peer.output_ring.utf8_tail();
    snap.output_bytes = peer.output_ring.total_bytes();
    snap.started_ns = peer.started_ns;
    snap.finished_ns = peer.finished_ns;
    return snap;
  }

  std::size_t active_count_locked() const noexcept {
    std::size_t count = 0;
    for (const auto &[id, peer] : peers) {
      (void)id;
      if (!peer->settled)
        ++count;
    }
    return count;
  }

  void collect_settled_for_join_locked(std::vector<std::shared_ptr<Peer>> &to_join) {
    // Enforce bounded retention of historical settled peers.
    std::size_t settled_count = 0;
    for (const auto &[id, peer] : peers) {
      (void)id;
      if (peer->settled)
        ++settled_count;
    }
    while (settled_count > max_retained_settled_peers) {
      auto oldest = peers.end();
      for (auto cursor = peers.begin(); cursor != peers.end(); ++cursor) {
        if (!cursor->second->settled)
          continue;
        if (oldest == peers.end() || cursor->second->order < oldest->second->order)
          oldest = cursor;
      }
      if (oldest == peers.end())
        break;
      to_join.push_back(std::move(oldest->second));
      peers.erase(oldest);
      --settled_count;
    }
  }

  static void join_peers(std::vector<std::shared_ptr<Peer>> &to_join) noexcept {
    for (auto &peer : to_join) {
      if (peer && peer->reader.joinable())
        peer->reader.join();
    }
  }

  void reader_loop(const std::shared_ptr<Peer> &peer, ReaderHandles handles) noexcept {
    const pid_t pid = peer->pid;
    const bool acp_mode = (peer->driver == PlatoonPeerDriver::acp);
    OwnedFd stdin_write = std::move(handles.stdin_write);
    OwnedFd output_read = std::move(handles.output_read);
    OwnedFd stderr_read = std::move(handles.stderr_read);
    OwnedFd wake_read = std::move(handles.wake_read);

    if (acp_mode) {
      sigset_t pipe_mask{};
      sigemptyset(&pipe_mask);
      sigaddset(&pipe_mask, SIGPIPE);
      (void)::pthread_sigmask(SIG_BLOCK, &pipe_mask, nullptr);
    }

    AcpClientSession acp;
    if (acp_mode) {
      acp.start(peer->working_dir, std::move(handles.acp_prompt), stdin_write);
    }

    bool stdout_closed = (output_read.fd < 0);
    bool stderr_closed = (stderr_read.fd < 0);
    bool leader_exited = false;
    bool reaped = false;
    bool status_observed = false;
    bool term_sent = false;
    bool kill_sent = false;
    bool stopped_by_request = false;
    bool normal_exit = false;
    int observed_exit_code = 0;
    std::optional<SteadyClock::time_point> kill_deadline;
    std::optional<SteadyClock::time_point> drain_deadline;

    auto drain_stdout = [&](std::size_t max_bytes_per_pass) {
      if (stdout_closed)
        return;
      std::size_t total_read = 0;
      std::array<char, 8192> buf{};
      while (total_read < max_bytes_per_pass) {
        const ssize_t n = ::read(output_read.fd, buf.data(), buf.size());
        if (n > 0) {
          const auto count = static_cast<std::size_t>(n);
          const std::string_view chunk{buf.data(), count};
          total_read += count;
          {
            const std::lock_guard lock{mutex};
            peer->output_ring.append(chunk);
          }
          if (acp_mode)
            acp.feed_stdout(chunk, stdin_write);
        } else if (n == 0) {
          output_read.close();
          stdout_closed = true;
          if (acp_mode)
            acp.on_stdout_eof(stdin_write);
          break;
        } else {
          if (errno == EINTR)
            continue;
          if (errno == EAGAIN)
            break;
          output_read.close();
          stdout_closed = true;
          if (acp_mode)
            acp.on_stdout_eof(stdin_write);
          break;
        }
      }
    };

    auto drain_stderr = [&](std::size_t max_bytes_per_pass) {
      if (stderr_closed)
        return;
      std::size_t total_read = 0;
      std::array<char, 8192> buf{};
      while (total_read < max_bytes_per_pass) {
        const ssize_t n = ::read(stderr_read.fd, buf.data(), buf.size());
        if (n > 0) {
          const auto count = static_cast<std::size_t>(n);
          total_read += count;
          const std::lock_guard lock{mutex};
          peer->output_ring.append(std::string_view{buf.data(), count});
        } else if (n == 0) {
          stderr_read.close();
          stderr_closed = true;
          break;
        } else {
          if (errno == EINTR)
            continue;
          if (errno == EAGAIN)
            break;
          stderr_read.close();
          stderr_closed = true;
          break;
        }
      }
    };

    auto drain_wake = [&]() {
      std::array<char, 64> discard{};
      for (;;) {
        const ssize_t n = ::read(wake_read.fd, discard.data(), discard.size());
        if (n > 0)
          continue;
        if (n < 0 && errno == EINTR)
          continue;
        break;
      }
    };

    for (;;) {
      drain_wake();

      bool stop_requested = false;
      int grace_ms = 1500;
      {
        const std::lock_guard lock{mutex};
        stop_requested = peer->stop_requested;
        grace_ms = peer->stop_grace_ms;
      }

      const auto now = SteadyClock::now();
      if (stop_requested && !term_sent && !leader_exited) {
        stopped_by_request = true;
        term_sent = true;
        stdin_write.close();
        if (grace_ms <= 0) {
          signal_peer_group({pid, SIGKILL});
          kill_sent = true;
          drain_deadline = now + std::chrono::milliseconds{drain_grace_ms};
        } else {
          signal_peer_group({pid, SIGTERM});
          kill_deadline = now + std::chrono::milliseconds{grace_ms};
        }
      } else if (stop_requested && term_sent && !kill_sent && !leader_exited &&
                 kill_deadline.has_value()) {
        // Honour a tighter grace period (e.g. destructor interrupting a longer stop()).
        const auto tightened = now + std::chrono::milliseconds{std::max(0, grace_ms)};
        if (tightened < *kill_deadline)
          kill_deadline = tightened;
      }

      if (term_sent && !kill_sent && !leader_exited && kill_deadline.has_value() &&
          now >= *kill_deadline) {
        signal_peer_group({pid, SIGKILL});
        kill_sent = true;
        drain_deadline = now + std::chrono::milliseconds{drain_grace_ms};
      }

      if (acp_mode)
        acp.flush_stdin(stdin_write);
      drain_stdout(64U * 1024U);
      if (acp_mode)
        acp.flush_stdin(stdin_write);
      drain_stderr(64U * 1024U);

      if (!leader_exited) {
        siginfo_t info{};
        const int rc =
            ::waitid(P_PID, static_cast<id_t>(pid), &info, WEXITED | WNOHANG | WNOWAIT);
        if (rc == 0 && info.si_pid == pid &&
            (info.si_code == CLD_EXITED || info.si_code == CLD_KILLED ||
             info.si_code == CLD_DUMPED)) {
          leader_exited = true;
          status_observed = true;
          normal_exit = (info.si_code == CLD_EXITED);
          observed_exit_code = normal_exit ? info.si_status : 128 + info.si_status;
          stdin_write.close();
          drain_deadline =
              SteadyClock::now() + std::chrono::milliseconds{drain_grace_ms};
          // Final non-blocking drain pass to capture bytes flushed right before exit.
          drain_stdout(256U * 1024U);
          drain_stderr(256U * 1024U);
        } else if (rc < 0 && errno == ECHILD) {
          leader_exited = true;
          reaped = true;
          stdin_write.close();
          detail::uncontained_exec.store(true);
          drain_deadline = SteadyClock::now() + std::chrono::milliseconds{50};
        }
      }

      const bool pipes_closed = stdout_closed && stderr_closed;
      if (leader_exited && !pipes_closed && drain_deadline.has_value() &&
          SteadyClock::now() >= *drain_deadline) {
        // Leader is a zombie pinning the PGID: sweep any grandchild holding the pipe.
        if (!reaped)
          signal_peer_group({pid, SIGKILL});
        drain_stdout(64U * 1024U);
        drain_stderr(64U * 1024U);
        output_read.close();
        stderr_read.close();
        stdout_closed = true;
        stderr_closed = true;
      }

      if (leader_exited && stdout_closed && stderr_closed)
        break;

      int timeout_ms = poll_interval_ms;
      const auto poll_now = SteadyClock::now();
      auto clamp_timeout = [&](const std::optional<SteadyClock::time_point> &deadline) {
        if (!deadline.has_value())
          return;
        if (*deadline <= poll_now) {
          timeout_ms = 0;
          return;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(*deadline - poll_now)
                .count();
        const int clamped =
            static_cast<int>(std::min<std::int64_t>(remaining, poll_interval_ms));
        timeout_ms = std::min(timeout_ms, std::max(1, clamped));
      };
      if (term_sent && !kill_sent && !leader_exited)
        clamp_timeout(kill_deadline);
      if (leader_exited && !(stdout_closed && stderr_closed))
        clamp_timeout(drain_deadline);

      std::array<pollfd, 4> fds{
          pollfd{stdout_closed ? -1 : output_read.fd, POLLIN, 0},
          pollfd{wake_read.fd, POLLIN, 0},
          pollfd{stderr_closed ? -1 : stderr_read.fd, POLLIN, 0},
          pollfd{(stdin_write.fd >= 0 && acp.has_pending_write()) ? stdin_write.fd : -1,
                 POLLOUT, 0}};
      (void)::poll(fds.data(), fds.size(), timeout_ms);
    }

    stdin_write.close();
    output_read.close();
    stderr_read.close();
    if (acp_mode && acp.stage != AcpStage::done)
      acp.failed = true;

    if (!reaped) {
      // Zombie leader still pins PGID `-pid`: sweep any remaining process-group
      // members.
      signal_peer_group({pid, SIGKILL});
      int status = 0;
      pid_t waited = -1;
      do {
        waited = ::waitpid(pid, &status, 0);
      } while (waited < 0 && errno == EINTR);
      if (waited == pid) {
        if (!status_observed) {
          if (WIFEXITED(status)) {
            status_observed = true;
            normal_exit = true;
            observed_exit_code = WEXITSTATUS(status);
          } else if (WIFSIGNALED(status)) {
            status_observed = true;
            normal_exit = false;
            observed_exit_code = 128 + WTERMSIG(status);
          }
        }
      } else if (waited < 0 && errno == ECHILD) {
        detail::uncontained_exec.store(true);
      }
    }

    {
      const std::lock_guard lock{mutex};
      // Close wake_write while holding mutex BEFORE wake_read closes so stop()
      // can never write to a broken pipe.
      peer->wake_write.close();
      if (peer->counted) {
        --detail::owned_children;
        peer->counted = false;
      }
      peer->finished_ns = wall_now_ns();
      if (status_observed)
        peer->exit_code = observed_exit_code;
      if (stopped_by_request)
        peer->state = PlatoonPeerState::stopped;
      else if (status_observed && normal_exit && observed_exit_code == 0 && !acp.failed)
        peer->state = PlatoonPeerState::completed;
      else
        peer->state = PlatoonPeerState::failed;
      peer->settled = true;
      cv.notify_all();
    }

    wake_read.close();
  }
};

PlatoonRunner::PlatoonRunner(std::size_t max_peers) {
  if (max_peers == 0 || max_peers > max_peers_limit)
    throw Error{ErrorCode::invalid_range};
  impl_ = std::make_unique<Impl>(max_peers);
}

PlatoonRunner::~PlatoonRunner() {
  if (!impl_)
    return;
  std::vector<std::shared_ptr<Impl::Peer>> all_peers;
  {
    const std::lock_guard lock{impl_->mutex};
    impl_->shutting_down = true;
    all_peers.reserve(impl_->peers.size());
    for (auto &[id, peer] : impl_->peers) {
      (void)id;
      if (!peer->settled) {
        peer->stop_requested = true;
        peer->stop_grace_ms = std::min(peer->stop_grace_ms, destructor_grace_ms);
        wake_reader_locked(peer->wake_write.fd);
      }
      all_peers.push_back(peer);
    }
    impl_->peers.clear();
  }
  Impl::join_peers(all_peers);
}

Result<PlatoonPeerSnapshot> PlatoonRunner::spawn(const PlatoonPeerSpec &spec) {
  auto validated = validate_spec(spec);
  if (!validated.has_value())
    return Result<PlatoonPeerSnapshot>::failure(validated.error());

  std::shared_ptr<Impl::Peer> peer;
  std::vector<std::shared_ptr<Impl::Peer>> to_join;
  {
    const std::lock_guard lock{impl_->mutex};
    if (impl_->shutting_down)
      return Result<PlatoonPeerSnapshot>::failure({ErrorCode::busy});

    const auto existing = impl_->peers.find(spec.peer_id);
    if (existing != impl_->peers.end() && !existing->second->settled)
      return Result<PlatoonPeerSnapshot>::failure({ErrorCode::conflict});

    if (impl_->active_count_locked() >= impl_->max_peers)
      return Result<PlatoonPeerSnapshot>::failure({ErrorCode::capacity});

    if (existing != impl_->peers.end()) {
      to_join.push_back(std::move(existing->second));
      impl_->peers.erase(existing);
    }
    impl_->collect_settled_for_join_locked(to_join);

    peer = std::make_shared<Impl::Peer>(spec, validated.value(), impl_->next_order++);
    impl_->peers.emplace(spec.peer_id, peer);
  }

  Impl::join_peers(to_join);

  auto spawned = spawn_peer_process({validated.value(), spec.extra_env});
  if (!spawned.has_value()) {
    const std::lock_guard lock{impl_->mutex};
    peer->settled = true;
    const auto it = impl_->peers.find(spec.peer_id);
    if (it != impl_->peers.end() && it->second == peer)
      impl_->peers.erase(it);
    impl_->cv.notify_all();
    return Result<PlatoonPeerSnapshot>::failure(spawned.error());
  }

  const auto started = wall_now_ns();
  auto proc = std::move(spawned).value();
  std::string acp_prompt;
  if (validated.value().driver == PlatoonPeerDriver::acp)
    acp_prompt = std::move(validated.value().prompt);
  {
    const std::lock_guard lock{impl_->mutex};
    peer->pid = proc.pid;
    peer->started_ns = started;
    peer->counted = true;
    peer->launched = true;
    peer->wake_write = std::move(proc.wake_write);
    Impl::ReaderHandles handles{
        std::move(proc.stdin_write), std::move(proc.output_read),
        std::move(proc.stderr_read), std::move(proc.wake_read), std::move(acp_prompt)};
    try {
      peer->reader = std::thread(
          [impl = impl_.get(), peer, handles = std::move(handles)]() mutable {
            impl->reader_loop(peer, std::move(handles));
          });
    } catch (...) {
      peer->wake_write.close();
      signal_peer_group({proc.pid, SIGKILL});
      int status = 0;
      pid_t waited = -1;
      do {
        waited = ::waitpid(proc.pid, &status, 0);
      } while (waited < 0 && errno == EINTR);
      if (peer->counted) {
        --detail::owned_children;
        peer->counted = false;
      }
      peer->settled = true;
      const auto it = impl_->peers.find(spec.peer_id);
      if (it != impl_->peers.end() && it->second == peer)
        impl_->peers.erase(it);
      impl_->cv.notify_all();
      return Result<PlatoonPeerSnapshot>::failure({ErrorCode::io, EAGAIN});
    }
    if (peer->stop_requested)
      wake_reader_locked(peer->wake_write.fd);
    return Result<PlatoonPeerSnapshot>::success(impl_->make_snapshot_locked(*peer));
  }
}

std::vector<PlatoonPeerSnapshot> PlatoonRunner::list() const {
  const std::lock_guard lock{impl_->mutex};
  std::vector<PlatoonPeerSnapshot> snapshots;
  snapshots.reserve(impl_->peers.size());
  for (const auto &[id, peer] : impl_->peers) {
    (void)id;
    if (peer->launched)
      snapshots.push_back(impl_->make_snapshot_locked(*peer));
  }
  return snapshots;
}

Result<PlatoonPeerSnapshot> PlatoonRunner::snapshot(std::string_view peer_id) const {
  const std::lock_guard lock{impl_->mutex};
  const auto it = impl_->peers.find(peer_id);
  if (it == impl_->peers.end() || !it->second->launched)
    return Result<PlatoonPeerSnapshot>::failure({ErrorCode::invalid_range});
  return Result<PlatoonPeerSnapshot>::success(impl_->make_snapshot_locked(*it->second));
}

std::size_t PlatoonRunner::active_count() const {
  const std::lock_guard lock{impl_->mutex};
  return impl_->active_count_locked();
}

std::size_t PlatoonRunner::max_peers() const noexcept { return impl_->max_peers; }

Result<PlatoonPeerSnapshot> PlatoonRunner::stop(std::string_view peer_id,
                                                int grace_ms) {
  if (grace_ms < 0 || grace_ms > max_grace_ms)
    return Result<PlatoonPeerSnapshot>::failure({ErrorCode::invalid_range});

  std::unique_lock lock{impl_->mutex};
  const auto it = impl_->peers.find(peer_id);
  if (it == impl_->peers.end() || !it->second->launched)
    return Result<PlatoonPeerSnapshot>::failure({ErrorCode::invalid_range});
  const auto peer = it->second;

  if (!peer->settled) {
    if (!peer->stop_requested) {
      peer->stop_requested = true;
      peer->stop_grace_ms = grace_ms;
    } else {
      peer->stop_grace_ms = std::min(peer->stop_grace_ms, grace_ms);
    }
    wake_reader_locked(peer->wake_write.fd);
    impl_->cv.wait(lock, [&] { return peer->settled; });
  }
  return Result<PlatoonPeerSnapshot>::success(impl_->make_snapshot_locked(*peer));
}

Result<PlatoonPeerSnapshot> PlatoonRunner::wait(std::string_view peer_id,
                                                int timeout_ms) {
  if (timeout_ms < 0)
    return Result<PlatoonPeerSnapshot>::failure({ErrorCode::invalid_range});

  std::unique_lock lock{impl_->mutex};
  const auto it = impl_->peers.find(peer_id);
  if (it == impl_->peers.end() || !it->second->launched)
    return Result<PlatoonPeerSnapshot>::failure({ErrorCode::invalid_range});
  const auto peer = it->second;

  if (!peer->settled && timeout_ms > 0) {
    const auto deadline = SteadyClock::now() + std::chrono::milliseconds{timeout_ms};
    (void)impl_->cv.wait_until(lock, deadline, [&] { return peer->settled; });
  }
  return Result<PlatoonPeerSnapshot>::success(impl_->make_snapshot_locked(*peer));
}

} // namespace blackbird
