#include "blackbird/party_dispatch.hpp"

#include "blackbird/json.hpp"
#include "blackbird/process_lifetime.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <spawn.h>
#include <sstream>
#include <string>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace blackbird {
namespace {

namespace fs = std::filesystem;
using SteadyClock = std::chrono::steady_clock;

constexpr std::size_t kPipeReadChunkBytes = 8192U;
constexpr std::size_t kMaxErrorSnippetBytes = 1024U;
constexpr std::size_t kMaxRemotePathBytes = 1024U;
constexpr int kMaxPollStepMs = 100;
constexpr int kSigtermGraceMs = 150;

enum class PathProbe : std::uint8_t {
  missing,
  regular_file,
  directory,
  symlink,
  other,
};

PathProbe probe_path_nofollow(const fs::path &path) noexcept {
  if (path.empty())
    return PathProbe::missing;
  std::error_code ec;
  const fs::file_status st = fs::symlink_status(path, ec);
  if (ec) {
    if (ec == std::errc::no_such_file_or_directory || ec == std::errc::not_a_directory)
      return PathProbe::missing;
    return PathProbe::other;
  }
  if (fs::is_symlink(st))
    return PathProbe::symlink;
  if (!fs::exists(st))
    return PathProbe::missing;
  if (fs::is_directory(st))
    return PathProbe::directory;
  if (fs::is_regular_file(st))
    return PathProbe::regular_file;
  return PathProbe::other;
}

bool path_or_parent_is_symlink(const fs::path &path) noexcept {
  if (path.empty())
    return false;
  if (probe_path_nofollow(path) == PathProbe::symlink)
    return true;
  const fs::path parent = path.parent_path();
  return !parent.empty() && probe_path_nofollow(parent) == PathProbe::symlink;
}

bool has_control_or_nul(std::string_view text) noexcept {
  for (const char ch : text) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7fU)
      return true;
  }
  return false;
}

bool is_ascii_space(char ch) noexcept {
  return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\v' ||
         ch == '\f';
}

bool has_whitespace_or_control(std::string_view text) noexcept {
  for (const char ch : text) {
    if (is_ascii_space(ch))
      return true;
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7fU)
      return true;
  }
  return false;
}

char lower_ascii(char ch) noexcept {
  return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
}

bool equals_ci(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size())
    return false;
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    if (lower_ascii(lhs[i]) != lower_ascii(rhs[i]))
      return false;
  }
  return true;
}

std::string trim_trailing_newlines(std::string text) {
  while (!text.empty() && (text.back() == '\n' || text.back() == '\r'))
    text.pop_back();
  return text;
}

std::string truncate_utf8_bytes(std::string_view text, std::size_t max_bytes) {
  if (text.size() <= max_bytes)
    return std::string{text};
  std::size_t cut = max_bytes;
  while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xc0U) == 0x80U)
    --cut;
  return std::string{text.substr(0, cut)};
}

std::string sanitize_platoon_sender_id(std::string_view raw) {
  if (valid_platoon_member_id(raw))
    return std::string{raw};
  std::string out;
  out.reserve(std::min(raw.size(), kPlatoonMaxIdLength));
  for (const char ch : raw) {
    if (out.size() >= kPlatoonMaxIdLength)
      break;
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
    if (ok) {
      if (out.empty() && (ch == '-' || ch == '.'))
        continue;
      out.push_back(ch);
    } else if (!out.empty() && out.back() != '_') {
      out.push_back('_');
    }
  }
  if (!valid_platoon_member_id(out))
    return "remote_peer";
  return out;
}

std::string sanitize_envelope_thread_id(std::string_view raw) {
  std::string out;
  out.reserve(std::min(raw.size(), kPeerMaxIdLength));
  for (const char ch : raw) {
    if (out.size() >= kPeerMaxIdLength)
      break;
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' ||
                    ch == ':';
    out.push_back(ok ? ch : ':');
  }
  if (out.empty())
    return "party";
  return out;
}

std::string make_room_recipient(std::string_view scope) {
  std::string alias;
  alias.reserve(std::min(scope.size(), kPeerMaxAliasLength));
  for (const char ch : scope) {
    if (alias.size() >= kPeerMaxAliasLength)
      break;
    const bool alnum = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                       (ch >= '0' && ch <= '9');
    const bool extra = ch == '-' || ch == '_' || ch == '.';
    if (alias.empty()) {
      if (alnum)
        alias.push_back(ch);
    } else if (alnum || extra) {
      alias.push_back(ch);
    } else if (alias.back() != '.') {
      alias.push_back('.');
    }
  }
  if (!valid_peer_alias(alias))
    alias = "party";
  return "room:" + alias;
}

Result<std::string> random_prefixed_id(std::string_view prefix) {
  std::array<unsigned char, 12> bytes{};
  if (::getentropy(bytes.data(), bytes.size()) != 0)
    return Result<std::string>::failure({ErrorCode::io, errno});
  static constexpr std::string_view kHex = "0123456789abcdef";
  std::string out{prefix};
  out.reserve(out.size() + bytes.size() * 2U);
  for (const unsigned char byte : bytes) {
    out.push_back(kHex[(byte >> 4U) & 0x0fU]);
    out.push_back(kHex[byte & 0x0fU]);
  }
  return Result<std::string>::success(std::move(out));
}

Result<void> validate_absolute_executable_path(std::string_view path_str) noexcept {
  if (path_str.empty() || path_str.size() > kMaxRemotePathBytes ||
      has_control_or_nul(path_str) || !valid_utf8(path_str)) {
    return Result<void>::failure({ErrorCode::invalid_range});
  }
  if (path_str.front() != '/')
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

Result<void> validate_remote_blackbird_path(std::string_view path_str) noexcept {
  if (path_str.empty() || path_str.size() > kMaxRemotePathBytes ||
      has_control_or_nul(path_str) || !valid_utf8(path_str) ||
      path_str.front() == '-') {
    return Result<void>::failure({ErrorCode::invalid_range});
  }
  if (path_str == "~" || path_str == "~/")
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

Result<void> validate_ssh_target(std::string_view target) noexcept {
  if (target.empty() || target.size() > 256U || has_whitespace_or_control(target) ||
      !valid_utf8(target) || target.front() == '-') {
    return Result<void>::failure({ErrorCode::invalid_range});
  }
  const std::size_t at = target.find('@');
  if (at != std::string_view::npos) {
    if (at == 0 || at + 1U >= target.size())
      return Result<void>::failure({ErrorCode::invalid_range});
    if (target.find('@', at + 1U) != std::string_view::npos)
      return Result<void>::failure({ErrorCode::invalid_range});
    if (target[at + 1U] == '-')
      return Result<void>::failure({ErrorCode::invalid_range});
  }
  return Result<void>::success();
}

Result<void> probe_existing_identity_files(const fs::path &peers_dir) noexcept {
  for (const char *filename : {"id_ed25519", "id_ed25519.pub"}) {
    const PathProbe probe = probe_path_nofollow(peers_dir / filename);
    if (probe == PathProbe::symlink)
      return Result<void>::failure({ErrorCode::io, ELOOP});
    if (probe == PathProbe::missing)
      return Result<void>::failure({ErrorCode::io, ENOENT});
    if (probe != PathProbe::regular_file)
      return Result<void>::failure({ErrorCode::io, EINVAL});
  }
  return Result<void>::success();
}

Result<void> validate_dispatch_config(const PartyDispatchConfig &cfg) {
  if (cfg.platoon_dir.empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (path_or_parent_is_symlink(cfg.platoon_dir))
    return Result<void>::failure({ErrorCode::io, ELOOP});
  if (!cfg.bridge_dir.empty() && path_or_parent_is_symlink(cfg.bridge_dir))
    return Result<void>::failure({ErrorCode::io, ELOOP});
  if (!cfg.peers_dir.empty() && path_or_parent_is_symlink(cfg.peers_dir))
    return Result<void>::failure({ErrorCode::io, ELOOP});
  if (!cfg.party_config_path.empty() &&
      path_or_parent_is_symlink(cfg.party_config_path))
    return Result<void>::failure({ErrorCode::io, ELOOP});
  if (!valid_platoon_member_id(cfg.local_actor))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (cfg.timeout_ms <= 0 || cfg.timeout_ms > kPartyDispatchMaxTimeoutMs)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (cfg.max_output_bytes == 0 || cfg.max_output_bytes > kPartyDispatchMaxOutputBytes)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (cfg.max_concurrency == 0)
    return Result<void>::failure({ErrorCode::invalid_range});
  auto ssh_ok = validate_absolute_executable_path(cfg.ssh_binary);
  if (!ssh_ok.has_value())
    return ssh_ok;
  auto remote_ok = validate_remote_blackbird_path(cfg.remote_blackbird_path);
  if (!remote_ok.has_value())
    return remote_ok;
  return Result<void>::success();
}

class OwnedFd {
public:
  OwnedFd() = default;
  explicit OwnedFd(int fd) noexcept : fd_(fd) {}
  OwnedFd(const OwnedFd &) = delete;
  OwnedFd &operator=(const OwnedFd &) = delete;
  OwnedFd(OwnedFd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  OwnedFd &operator=(OwnedFd &&other) noexcept {
    if (this != &other) {
      close();
      fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
  }
  ~OwnedFd() { close(); }

  int get() const noexcept { return fd_; }
  explicit operator bool() const noexcept { return fd_ >= 0; }
  void close() noexcept {
    if (fd_ >= 0)
      (void)::close(std::exchange(fd_, -1));
  }

private:
  int fd_ = -1;
};

struct PipePair {
  OwnedFd read_end;
  OwnedFd write_end;
};

Result<PipePair> create_cloexec_pipe() noexcept {
  int raw[2]{-1, -1};
  if (::pipe(raw) != 0)
    return Result<PipePair>::failure({ErrorCode::io, errno});
  OwnedFd raw_read{raw[0]};
  OwnedFd raw_write{raw[1]};

  const int norm_read = ::fcntl(raw_read.get(), F_DUPFD_CLOEXEC, 3);
  if (norm_read < 0)
    return Result<PipePair>::failure({ErrorCode::io, errno});
  OwnedFd read_fd{norm_read};

  const int norm_write = ::fcntl(raw_write.get(), F_DUPFD_CLOEXEC, 3);
  if (norm_write < 0)
    return Result<PipePair>::failure({ErrorCode::io, errno});
  OwnedFd write_fd{norm_write};

  return Result<PipePair>::success(PipePair{std::move(read_fd), std::move(write_fd)});
}

Result<void> set_nonblocking(int fd) noexcept {
  const int flags = ::fcntl(fd, F_GETFL);
  if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return Result<void>::failure({ErrorCode::io, errno});
  return Result<void>::success();
}

void terminate_and_reap_group(pid_t &pid) noexcept {
  if (pid <= 0)
    return;

  auto already_exited = [](pid_t target) noexcept -> bool {
    siginfo_t info{};
    const int rc =
        ::waitid(P_PID, static_cast<id_t>(target), &info, WEXITED | WNOHANG | WNOWAIT);
    if (rc < 0 && errno == ECHILD)
      return true;
    return rc == 0 && info.si_pid == target &&
           (info.si_code == CLD_EXITED || info.si_code == CLD_KILLED ||
            info.si_code == CLD_DUMPED);
  };

  if (!already_exited(pid)) {
    (void)::kill(-pid, SIGTERM);
    const auto grace_deadline =
        SteadyClock::now() + std::chrono::milliseconds{kSigtermGraceMs};
    while (!already_exited(pid) && SteadyClock::now() < grace_deadline)
      (void)::poll(nullptr, 0, 15);
    if (!already_exited(pid))
      (void)::kill(-pid, SIGKILL);
  }

  int status = 0;
  pid_t rc = -1;
  do {
    rc = ::waitpid(pid, &status, 0);
  } while (rc < 0 && errno == EINTR);
  pid = -1;
}

std::string build_party_prompt(std::string_view local_actor,
                               std::string_view room_scope, std::string_view body) {
  std::string out;
  out.reserve(local_actor.size() + room_scope.size() + body.size() + 32U);
  out += "[party ";
  out += room_scope;
  out += " from ";
  out += local_actor;
  out += "] ";
  out += body;
  return out;
}

OnboardLeaderDispatchResult
execute_onboard_via_runner(PlatoonRunner &runner, const PartyDispatchConfig &cfg,
                           const OnboardLeaderDispatchRequest &req) {
  OnboardLeaderDispatchResult res{};
  const fs::path work_dir =
      cfg.working_dir.empty() ? fs::current_path() : cfg.working_dir;
  const fs::path base_sessions =
      cfg.sessions_dir.empty() ? (cfg.platoon_dir / "sessions") : cfg.sessions_dir;

  PlatoonPeerSpec spec{};
  spec.peer_id = sanitize_platoon_sender_id(req.target.id);
  spec.role = std::string{party_member_role_name(req.target.role)};
  spec.provider = req.target.provider.value_or(std::string{"openai"});
  spec.model = req.target.model.empty()
                   ? req.target.remote_model.value_or(std::string{"gpt-5"})
                   : req.target.model;
  spec.working_dir = work_dir;
  spec.session_dir = base_sessions / spec.peer_id;
  spec.prompt = req.prompt;
  spec.owner_actor = req.local_actor;
  spec.command_room = req.room_scope;
  spec.max_output_bytes =
      std::min(cfg.max_output_bytes, PlatoonRunner::max_output_bytes_limit);

  auto spawned = runner.spawn(spec);
  if (!spawned.has_value()) {
    res.status = PartyDeliveryStatus::error;
    res.error_detail =
        std::string{"platoon runner spawn failed: "} + error_name(spawned.error().code);
    return res;
  }

  auto waited = runner.wait(spec.peer_id, req.timeout_ms);
  if (!waited.has_value()) {
    res.status = PartyDeliveryStatus::error;
    res.error_detail =
        std::string{"platoon runner wait failed: "} + error_name(waited.error().code);
    return res;
  }

  const PlatoonPeerSnapshot &snap = waited.value();
  if (snap.state == PlatoonPeerState::running) {
    (void)runner.stop(spec.peer_id, 500);
    res.status = PartyDeliveryStatus::timeout;
    res.error_detail = "onboard platoon leader timed out";
    return res;
  }
  if (snap.state == PlatoonPeerState::completed) {
    std::string reply = trim_trailing_newlines(snap.output_tail);
    if (!reply.empty()) {
      res.status = PartyDeliveryStatus::replied;
      res.reply_text = std::move(reply);
    } else {
      res.status = PartyDeliveryStatus::delivered;
    }
    return res;
  }

  res.status = PartyDeliveryStatus::error;
  res.error_detail = std::string{"onboard platoon leader ended in state "} +
                     platoon_peer_state_name(snap.state);
  return res;
}

bool is_passive_event_kind(std::string_view kind) noexcept {
  return kind == "receipt" || kind == "presence" || kind == "heartbeat" ||
         kind == "observation";
}

std::optional<std::string> opt_string_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return std::nullopt;
  const auto *s = std::get_if<std::string>(&field->value());
  if (!s)
    return std::nullopt;
  return *s;
}

std::optional<std::string> envelope_causal_event_hash(const PeerEnvelope &env) {
  if (!std::holds_alternative<Value::Object>(env.payload.value()))
    return std::nullopt;
  const Value *ce = env.payload.find("causal_event");
  if (!ce || !std::holds_alternative<Value::Object>(ce->value()))
    return std::nullopt;
  return opt_string_field(*ce, "event_hash");
}

} // namespace

// ---------------------------------------------------------------------------
// Public utilities
// ---------------------------------------------------------------------------

std::string_view party_delivery_status_name(PartyDeliveryStatus status) noexcept {
  switch (status) {
  case PartyDeliveryStatus::delivered:
    return "delivered";
  case PartyDeliveryStatus::replied:
    return "replied";
  case PartyDeliveryStatus::timeout:
    return "timeout";
  case PartyDeliveryStatus::error:
    return "error";
  }
  return "error";
}

std::string posix_shell_quote(std::string_view arg) {
  std::string out;
  out.reserve(arg.size() + 2U);
  out.push_back('\'');
  for (const char ch : arg) {
    if (ch == '\'') {
      out.append("'\\''");
    } else {
      out.push_back(ch);
    }
  }
  out.push_back('\'');
  return out;
}

std::vector<std::string> build_sanitized_ssh_env() {
  std::vector<std::string> env;
  static constexpr std::array<const char *, 6> kAllowedKeys{
      "PATH", "HOME", "USER", "LANG", "SSH_AUTH_SOCK", "TERM",
  };
  env.reserve(kAllowedKeys.size());
  bool has_path = false;
  for (const char *key : kAllowedKeys) {
    if (const char *val = std::getenv(key); val != nullptr && val[0] != '\0') {
      if (std::string_view{key} == "PATH")
        has_path = true;
      env.emplace_back(std::string{key} + "=" + val);
    }
  }
  if (!has_path)
    env.emplace_back("PATH=/usr/bin:/bin");
  return env;
}

Result<std::string>
build_remote_blackbird_command(const RemotePeerDispatchRequest &request) {
  auto path_ok = validate_remote_blackbird_path(request.remote_blackbird_path);
  if (!path_ok.has_value())
    return Result<std::string>::failure(path_ok.error());
  if (request.prompt.empty() || request.prompt.find('\0') != std::string::npos ||
      !valid_utf8(request.prompt)) {
    return Result<std::string>::failure({ErrorCode::invalid_range});
  }

  auto validate_opt_arg = [](const std::optional<std::string> &opt,
                             bool forbid_ws) noexcept -> Result<void> {
    if (!opt.has_value() || opt->empty())
      return Result<void>::success();
    if (opt->size() > kPartyMaxFieldBytes || !valid_utf8(*opt) || opt->front() == '-') {
      return Result<void>::failure({ErrorCode::invalid_range});
    }
    if (forbid_ws ? has_whitespace_or_control(*opt) : has_control_or_nul(*opt))
      return Result<void>::failure({ErrorCode::invalid_range});
    return Result<void>::success();
  };

  if (auto ok = validate_opt_arg(request.target.provider, true); !ok.has_value())
    return Result<std::string>::failure(ok.error());
  if (auto ok = validate_opt_arg(request.target.remote_session, false); !ok.has_value())
    return Result<std::string>::failure(ok.error());

  std::optional<std::string> chosen_model;
  if (request.target.remote_model.has_value() && !request.target.remote_model->empty())
    chosen_model = request.target.remote_model;
  else if (!request.target.model.empty())
    chosen_model = request.target.model;
  if (auto ok = validate_opt_arg(chosen_model, true); !ok.has_value())
    return Result<std::string>::failure(ok.error());

  try {
    std::string cmd;
    const std::string_view bin = request.remote_blackbird_path;
    if (bin.starts_with("~/")) {
      cmd = "\"$HOME\"/" + posix_shell_quote(bin.substr(2));
    } else {
      cmd = posix_shell_quote(bin);
    }

    if (request.target.remote_session.has_value() &&
        !request.target.remote_session->empty()) {
      cmd += " --session ";
      cmd += posix_shell_quote(*request.target.remote_session);
    }
    if (request.target.provider.has_value() && !request.target.provider->empty()) {
      cmd += " --provider ";
      cmd += posix_shell_quote(*request.target.provider);
    }
    if (chosen_model.has_value() && !chosen_model->empty()) {
      cmd += " --model ";
      cmd += posix_shell_quote(*chosen_model);
    }
    cmd += " --plain --once ";
    cmd += posix_shell_quote(request.prompt);
    return Result<std::string>::success(std::move(cmd));
  } catch (const std::bad_alloc &) {
    return Result<std::string>::failure({ErrorCode::allocation});
  }
}

RemotePeerDispatchResult
execute_remote_peer_ssh(const RemotePeerDispatchRequest &request,
                        const std::function<bool()> &cancelled) {
  RemotePeerDispatchResult result{};

  if (auto ok = validate_absolute_executable_path(request.ssh_binary);
      !ok.has_value()) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "ssh_binary must be a valid absolute path";
    return result;
  }
  if (!request.target.ssh_target.has_value()) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "missing ssh_target";
    return result;
  }
  const std::string &ssh_target = *request.target.ssh_target;
  if (auto ok = validate_ssh_target(ssh_target); !ok.has_value()) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "invalid ssh_target";
    return result;
  }
  if (request.timeout_ms <= 0 || request.timeout_ms > kPartyDispatchMaxTimeoutMs) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "invalid timeout_ms";
    return result;
  }
  if (request.max_output_bytes == 0 ||
      request.max_output_bytes > kPartyDispatchMaxOutputBytes) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "invalid max_output_bytes";
    return result;
  }
  std::error_code ec;
  const fs::file_status bin_st = fs::status(request.ssh_binary, ec);
  if (ec || !fs::exists(bin_st) || !fs::is_regular_file(bin_st) ||
      ::access(request.ssh_binary.c_str(), X_OK) != 0) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "ssh_binary is not an executable regular file";
    return result;
  }

  auto remote_cmd = build_remote_blackbird_command(request);
  if (!remote_cmd.has_value()) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "failed to build remote command";
    return result;
  }

  auto out_pipe = create_cloexec_pipe();
  if (!out_pipe.has_value()) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "failed to create stdout pipe";
    return result;
  }
  auto err_pipe = create_cloexec_pipe();
  if (!err_pipe.has_value()) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "failed to create stderr pipe";
    return result;
  }

  std::vector<std::string> argv_storage{
      request.ssh_binary,
      "-T",
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=10",
      "--",
      ssh_target,
      std::move(remote_cmd).value(),
  };
  std::vector<char *> argv;
  argv.reserve(argv_storage.size() + 1U);
  for (auto &arg : argv_storage)
    argv.push_back(arg.data());
  argv.push_back(nullptr);

  std::vector<std::string> env_storage = build_sanitized_ssh_env();
  std::vector<char *> envp;
  envp.reserve(env_storage.size() + 1U);
  for (auto &entry : env_storage)
    envp.push_back(entry.data());
  envp.push_back(nullptr);

  pid_t child_pid = -1;
  int spawn_rc = 0;
  {
    const std::lock_guard spawn_lock{detail::process_spawn_mutex};
    posix_spawn_file_actions_t actions{};
    posix_spawnattr_t attr{};
    spawn_rc = ::posix_spawn_file_actions_init(&actions);
    if (spawn_rc == 0) {
      spawn_rc = ::posix_spawnattr_init(&attr);
      if (spawn_rc == 0) {
        if (spawn_rc == 0) {
          spawn_rc = ::posix_spawn_file_actions_addopen(&actions, STDIN_FILENO,
                                                        "/dev/null", O_RDONLY, 0);
        }
        if (spawn_rc == 0) {
          spawn_rc = ::posix_spawn_file_actions_adddup2(
              &actions, out_pipe.value().write_end.get(), STDOUT_FILENO);
        }
        if (spawn_rc == 0) {
          spawn_rc = ::posix_spawn_file_actions_adddup2(
              &actions, err_pipe.value().write_end.get(), STDERR_FILENO);
        }
        if (spawn_rc == 0) {
          spawn_rc = ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP |
                                                           POSIX_SPAWN_SETSIGMASK);
        }
        if (spawn_rc == 0)
          spawn_rc = ::posix_spawnattr_setpgroup(&attr, 0);
        if (spawn_rc == 0) {
          sigset_t empty_mask{};
          sigemptyset(&empty_mask);
          spawn_rc = ::posix_spawnattr_setsigmask(&attr, &empty_mask);
        }
        if (spawn_rc == 0) {
          // Strict posix_spawn (never posix_spawnp): exact absolute path only.
          spawn_rc = ::posix_spawn(&child_pid, request.ssh_binary.c_str(), &actions,
                                   &attr, argv.data(), envp.data());
        }
        (void)::posix_spawnattr_destroy(&attr);
      }
      (void)::posix_spawn_file_actions_destroy(&actions);
    }
  }

  out_pipe.value().write_end.close();
  err_pipe.value().write_end.close();

  if (spawn_rc != 0 || child_pid <= 0) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail =
        "posix_spawn failed for ssh_binary (rc=" + std::to_string(spawn_rc) + ")";
    return result;
  }

  struct ChildGuard {
    pid_t pid = -1;
    ~ChildGuard() { terminate_and_reap_group(pid); }
  } guard{child_pid};

  if (!set_nonblocking(out_pipe.value().read_end.get()).has_value() ||
      !set_nonblocking(err_pipe.value().read_end.get()).has_value()) {
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "failed to configure non-blocking ssh pipes";
    return result;
  }

  const auto deadline =
      SteadyClock::now() + std::chrono::milliseconds{request.timeout_ms};
  std::string stdout_bytes;
  std::string stderr_bytes;
  bool stdout_open = true;
  bool stderr_open = true;
  bool output_overflow = false;
  bool timed_out = false;
  bool was_cancelled = false;

  std::array<char, kPipeReadChunkBytes> buf{};
  while (stdout_open || stderr_open) {
    if (cancelled && cancelled()) {
      was_cancelled = true;
      break;
    }
    const auto now = SteadyClock::now();
    if (now >= deadline) {
      timed_out = true;
      break;
    }
    const auto remaining_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    const int wait_ms =
        static_cast<int>(std::clamp<std::int64_t>(remaining_ms, 1, kMaxPollStepMs));

    std::array<pollfd, 2> pfds{};
    nfds_t nfds = 0;
    int out_slot = -1;
    int err_slot = -1;
    if (stdout_open) {
      out_slot = static_cast<int>(nfds);
      pfds[nfds++] = pollfd{out_pipe.value().read_end.get(), POLLIN, 0};
    }
    if (stderr_open) {
      err_slot = static_cast<int>(nfds);
      pfds[nfds++] = pollfd{err_pipe.value().read_end.get(), POLLIN, 0};
    }

    const int prc = ::poll(pfds.data(), nfds, wait_ms);
    if (prc < 0) {
      if (errno == EINTR)
        continue;
      result.status = PartyDeliveryStatus::error;
      result.error_detail = "poll failed reading ssh output";
      return result;
    }
    if (prc == 0)
      continue;

    auto drain_fd = [&](int fd, std::string &dst, bool &is_open, bool enforce_cap) {
      for (;;) {
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n > 0) {
          const auto got = static_cast<std::size_t>(n);
          if (enforce_cap) {
            if (got > request.max_output_bytes - dst.size()) {
              output_overflow = true;
              is_open = false;
              return;
            }
            dst.append(buf.data(), got);
          } else {
            if (dst.size() < request.max_output_bytes) {
              const std::size_t take =
                  std::min(got, request.max_output_bytes - dst.size());
              dst.append(buf.data(), take);
            }
          }
          continue;
        }
        if (n == 0) {
          is_open = false;
          return;
        }
        if (errno == EINTR)
          continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          return;
        is_open = false;
        return;
      }
    };

    if (out_slot >= 0 && (pfds[static_cast<std::size_t>(out_slot)].revents &
                          (POLLIN | POLLHUP | POLLERR)) != 0) {
      drain_fd(out_pipe.value().read_end.get(), stdout_bytes, stdout_open, true);
      if (output_overflow)
        break;
    }
    if (err_slot >= 0 && (pfds[static_cast<std::size_t>(err_slot)].revents &
                          (POLLIN | POLLHUP | POLLERR)) != 0) {
      drain_fd(err_pipe.value().read_end.get(), stderr_bytes, stderr_open, false);
    }
  }

  out_pipe.value().read_end.close();
  err_pipe.value().read_end.close();

  if (was_cancelled) {
    terminate_and_reap_group(guard.pid);
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "remote ssh dispatch cancelled";
    return result;
  }
  if (timed_out) {
    terminate_and_reap_group(guard.pid);
    result.status = PartyDeliveryStatus::timeout;
    result.error_detail = "remote ssh dispatch timed out";
    return result;
  }
  if (output_overflow) {
    terminate_and_reap_group(guard.pid);
    result.status = PartyDeliveryStatus::error;
    result.error_detail = "remote ssh output exceeded bounded cap";
    return result;
  }

  // Wait for process exit up to remaining deadline.
  int status = 0;
  for (;;) {
    if (cancelled && cancelled()) {
      terminate_and_reap_group(guard.pid);
      result.status = PartyDeliveryStatus::error;
      result.error_detail = "remote ssh dispatch cancelled";
      return result;
    }
    const pid_t wrc = ::waitpid(guard.pid, &status, WNOHANG);
    if (wrc == guard.pid) {
      guard.pid = -1;
      break;
    }
    if (wrc < 0) {
      if (errno == EINTR)
        continue;
      guard.pid = -1;
      result.status = PartyDeliveryStatus::error;
      result.error_detail = "waitpid failed for ssh child";
      return result;
    }
    if (SteadyClock::now() >= deadline) {
      terminate_and_reap_group(guard.pid);
      result.status = PartyDeliveryStatus::timeout;
      result.error_detail = "remote ssh dispatch timed out waiting for exit";
      return result;
    }
    (void)::poll(nullptr, 0, 15);
  }

  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    result.exit_code = 128 + WTERMSIG(status);
  }

  if (WIFEXITED(status) && result.exit_code == 0) {
    std::string reply = trim_trailing_newlines(std::move(stdout_bytes));
    if (!reply.empty()) {
      result.status = PartyDeliveryStatus::replied;
      result.reply_text = std::move(reply);
    } else {
      result.status = PartyDeliveryStatus::delivered;
    }
    return result;
  }

  result.status = PartyDeliveryStatus::error;
  std::string err_snip =
      trim_trailing_newlines(truncate_utf8_bytes(stderr_bytes, kMaxErrorSnippetBytes));
  if (err_snip.empty()) {
    result.error_detail = "ssh exited with status " + std::to_string(result.exit_code);
  } else {
    result.error_detail = party_chat_sanitize(err_snip, kMaxErrorSnippetBytes);
  }
  return result;
}

// ---------------------------------------------------------------------------
// PartyDispatchConfig & PartyDispatchReport
// ---------------------------------------------------------------------------

PartyDispatchConfig PartyDispatchConfig::for_project(const fs::path &project_root) {
  PartyDispatchConfig cfg{};
  cfg.platoon_dir = project_root / ".blackbird" / "platoon";
  cfg.bridge_dir = project_root / ".blackbird" / "bridge";
  cfg.party_config_path = project_root / ".blackbird" / "party.json";
  cfg.working_dir = project_root;
  cfg.sessions_dir = project_root / ".blackbird" / "platoon" / "sessions";
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0')
    cfg.peers_dir = fs::path{home} / ".local" / "share" / "blackbird" / "peers";
  return cfg;
}

std::size_t PartyDispatchReport::replied_count() const noexcept {
  std::size_t count = 0;
  for (const auto &o : outcomes) {
    if (o.status == PartyDeliveryStatus::replied)
      ++count;
  }
  return count;
}

std::size_t PartyDispatchReport::delivered_count() const noexcept {
  std::size_t count = 0;
  for (const auto &o : outcomes) {
    if (o.status == PartyDeliveryStatus::delivered ||
        o.status == PartyDeliveryStatus::replied) {
      ++count;
    }
  }
  return count;
}

std::size_t PartyDispatchReport::failed_count() const noexcept {
  std::size_t count = 0;
  for (const auto &o : outcomes) {
    if (o.status == PartyDeliveryStatus::timeout ||
        o.status == PartyDeliveryStatus::error) {
      ++count;
    }
  }
  return count;
}

// ---------------------------------------------------------------------------
// Unified Party Fan-Out Dispatcher
// ---------------------------------------------------------------------------

Result<PartyDispatchReport>
PartyDispatcher::dispatch(std::string_view raw_input) const {
  return dispatch_party_message(raw_input, config_);
}

Result<PartyDispatchReport>
PartyDispatcher::dispatch_party_message(std::string_view raw_input,
                                        const PartyDispatchConfig &cfg) {
  return blackbird::dispatch_party_message(raw_input, cfg);
}

Result<PartyDispatchReport> dispatch_party_message(std::string_view raw_input,
                                                   const PartyDispatchConfig &cfg) {
  try {
    auto cfg_ok = validate_dispatch_config(cfg);
    if (!cfg_ok.has_value())
      return Result<PartyDispatchReport>::failure(cfg_ok.error());

    if (raw_input.empty() || raw_input.find('\0') != std::string_view::npos ||
        !valid_utf8(raw_input)) {
      return Result<PartyDispatchReport>::failure({ErrorCode::invalid_range});
    }
    if (raw_input.size() > kPartyMaxMessageBytes)
      return Result<PartyDispatchReport>::failure({ErrorCode::capacity});

    // Open existing peer identity passively if peers_dir already exists AND
    // contains identity key files; NEVER create peers_dir, lock files, or keys.
    std::optional<PeerIdentityStore> local_identity;
    std::optional<KnownPeersStore> known_peers;
    if (!cfg.peers_dir.empty()) {
      const PathProbe peers_probe = probe_path_nofollow(cfg.peers_dir);
      if (peers_probe == PathProbe::symlink)
        return Result<PartyDispatchReport>::failure({ErrorCode::io, ELOOP});
      if (peers_probe == PathProbe::directory) {
        const auto files_probe = probe_existing_identity_files(cfg.peers_dir);
        if (!files_probe.has_value()) {
          if (files_probe.error().code == ErrorCode::io &&
              files_probe.error().detail == ELOOP) {
            return Result<PartyDispatchReport>::failure(files_probe.error());
          }
        } else {
          auto id_res =
              PeerIdentityStore::open_existing(cfg.peers_dir, cfg.peer_identity_config);
          if (id_res.has_value()) {
            local_identity.emplace(std::move(id_res).value());
            auto kp_res =
                KnownPeersStore::open(cfg.peers_dir, cfg.peer_identity_config);
            if (kp_res.has_value())
              known_peers.emplace(std::move(kp_res).value());
          }
        }
      }
    }

    // 1. Load passive PartySnapshot and route message.
    PartyConfig party_cfg{};
    party_cfg.platoon_dir = cfg.platoon_dir;
    party_cfg.bridge_dir = cfg.bridge_dir;
    party_cfg.party_config_path = cfg.party_config_path;
    party_cfg.known_peers_dir = cfg.peers_dir;
    party_cfg.room_scope = cfg.room_scope;
    party_cfg.local_operator_id = cfg.local_actor;
    if (local_identity.has_value())
      party_cfg.local_actor_fp = local_identity->identity().fingerprint;

    auto snap_res = load_party_snapshot(party_cfg);
    if (!snap_res.has_value())
      return Result<PartyDispatchReport>::failure(snap_res.error());
    const PartySnapshot &snap = snap_res.value();

    auto routed_res = parse_party_input(raw_input, snap);
    if (!routed_res.has_value())
      return Result<PartyDispatchReport>::failure(routed_res.error());
    const ParsedPartyInput &routed = routed_res.value();

    const std::string effective_scope =
        !cfg.room_scope.empty()
            ? cfg.room_scope
            : (!snap.room_scope.empty() ? snap.room_scope
                                        : std::string{kPartyDefaultScope});

    // 2. Append operator message to PlatoonBoard.
    auto board_res = PlatoonBoard::open(cfg.platoon_dir);
    if (!board_res.has_value())
      return Result<PartyDispatchReport>::failure(board_res.error());
    PlatoonBoard board = std::move(board_res).value();

    std::string post_to = "all";
    if (!routed.broadcast && routed.resolved_targets.size() == 1U &&
        valid_platoon_member_id(routed.resolved_targets.front())) {
      post_to = routed.resolved_targets.front();
    }

    auto posted_res = board.post(PlatoonPost{
        cfg.local_actor,
        std::move(post_to),
        PlatoonMessageKind::message,
        routed.body,
        {"party_scope:" + effective_scope, "target_label:" + routed.target_label},
    });
    if (!posted_res.has_value())
      return Result<PartyDispatchReport>::failure(posted_res.error());

    PartyDispatchReport report{};
    report.mode = routed.mode;
    report.room_scope = effective_scope;
    report.target_label = routed.target_label;
    report.body = routed.body;
    report.operator_board_seq = posted_res.value().seq;
    report.local_identity_available = local_identity.has_value();
    report.unknown_targets = routed.unknown_targets;

    // Resolve addressed participants from snapshot (excluding local_self).
    std::vector<PartyParticipant> targets;
    targets.reserve(routed.resolved_targets.size());
    for (const auto &target_id : routed.resolved_targets) {
      for (const auto &participant : snap.participants) {
        if (equals_ci(participant.id, target_id)) {
          if (!participant.local_self)
            targets.push_back(participant);
          break;
        }
      }
    }

    if (targets.empty())
      return Result<PartyDispatchReport>::success(std::move(report));

    // Open BoardBridge only if we have a remote target and either local identity
    // (for signing outbound envelopes) or an already-existing bridge_dir.
    const bool has_remote_target =
        std::any_of(targets.begin(), targets.end(), [](const PartyParticipant &p) {
          return p.ssh_target.has_value() && !p.ssh_target->empty();
        });

    std::optional<BoardBridge> bridge;
    if (has_remote_target && !cfg.bridge_dir.empty()) {
      const PathProbe bridge_probe = probe_path_nofollow(cfg.bridge_dir);
      if (bridge_probe == PathProbe::symlink)
        return Result<PartyDispatchReport>::failure({ErrorCode::io, ELOOP});
      if (local_identity.has_value() || bridge_probe == PathProbe::directory) {
        auto opened_bridge = BoardBridge::open(cfg.bridge_dir);
        if (!opened_bridge.has_value())
          return Result<PartyDispatchReport>::failure(opened_bridge.error());
        bridge.emplace(std::move(opened_bridge).value());
      }
    }

    // Prepare per-target dispatch tasks (signing outbound envelopes sequentially
    // before spawning concurrent workers so BoardBridge actor_seq ordering is crisp).
    struct WorkItem {
      PartyParticipant target;
      bool remote = false;
      std::string prompt;
      std::optional<PeerEnvelope> signed_outbound;
    };

    const std::string prompt_text =
        build_party_prompt(cfg.local_actor, effective_scope, routed.body);

    std::vector<WorkItem> items;
    items.reserve(targets.size());
    for (auto &target : targets) {
      const bool is_remote =
          target.ssh_target.has_value() && !target.ssh_target->empty();
      std::optional<PeerEnvelope> signed_outbound;
      if (is_remote && local_identity.has_value() && bridge.has_value()) {
        const std::string &local_fp = local_identity->identity().fingerprint;
        const std::string to_fp = valid_peer_fingerprint(target.fingerprint)
                                      ? target.fingerprint
                                      : make_room_recipient(effective_scope);

        auto ev_res = bridge->emit_causal_event(CausalEventDraft{
            local_fp,
            0,
            {},
            0,
            effective_scope,
            "chat",
            Value::object({
                {"body", Value{routed.body}},
                {"to", Value{target.id}},
                {"sender_id", Value{cfg.local_actor}},
                {"target_label", Value{routed.target_label}},
            }),
        });
        if (ev_res.has_value()) {
          auto env_id = random_prefixed_id("party-out-");
          if (env_id.has_value()) {
            const PeerEnvelopeMeta meta{
                std::move(env_id).value(),
                to_fp,
                sanitize_envelope_thread_id(effective_scope),
                PeerEnvelopeKind::mail,
                0,
            };
            auto env_res = BoardBridge::sign_causal_event_envelope(
                *local_identity, ev_res.value(), meta);
            if (env_res.has_value()) {
              std::ostringstream sink;
              auto sent = bridge->send_envelope(sink, env_res.value());
              if (sent.has_value())
                signed_outbound = std::move(env_res).value();
            }
          }
        }
      }

      items.push_back(WorkItem{
          std::move(target),
          is_remote,
          prompt_text,
          std::move(signed_outbound),
      });
    }

    // 3. Execute addressed targets concurrently with bounded pool (<= 8 workers).
    report.outcomes.resize(items.size());
    std::mutex store_mutex;
    std::atomic<std::size_t> next_index{0};

    auto run_one = [&](std::size_t idx) noexcept {
      const WorkItem &item = items[idx];
      const auto started = SteadyClock::now();

      PartyTargetOutcome outcome{};
      try {
        outcome.target_id = item.target.id;
        outcome.remote = item.remote;
        if (item.signed_outbound.has_value())
          outcome.signed_outbound_envelope_id = item.signed_outbound->envelope_id;

        if (item.remote) {
          RemotePeerDispatchRequest req{};
          req.target = item.target;
          req.prompt = item.prompt;
          req.raw_body = routed.body;
          req.room_scope = effective_scope;
          req.local_actor = cfg.local_actor;
          req.signed_envelope = item.signed_outbound;
          req.ssh_binary = cfg.ssh_binary;
          req.remote_blackbird_path = cfg.remote_blackbird_path;
          req.timeout_ms = cfg.timeout_ms;
          req.max_output_bytes = cfg.max_output_bytes;

          RemotePeerDispatchResult remote_res =
              cfg.remote_executor ? cfg.remote_executor(req)
                                  : execute_remote_peer_ssh(req, cfg.cancelled);

          outcome.status = remote_res.status;
          outcome.reply_text = std::move(remote_res.reply_text);
          outcome.error_detail = std::move(remote_res.error_detail);
          outcome.untrusted_remote = true;

          // Deliver remote reply back into local BoardBridge & PlatoonBoard with
          // untrusted-peer provenance metadata.
          if (outcome.status == PartyDeliveryStatus::replied &&
              !outcome.reply_text.empty()) {
            const std::lock_guard lock{store_mutex};

            if (remote_res.reply_envelope.has_value() && bridge.has_value() &&
                known_peers.has_value()) {
              auto ingested =
                  bridge->receive_envelope(*remote_res.reply_envelope, *known_peers);
              if (ingested.has_value())
                outcome.reply_verified = true;
            } else if (bridge.has_value() && local_identity.has_value()) {
              const std::string &local_fp = local_identity->identity().fingerprint;
              const std::string ssh_src =
                  item.target.ssh_target.has_value() ? *item.target.ssh_target : "";
              (void)bridge->emit_causal_event(CausalEventDraft{
                  local_fp,
                  0,
                  {},
                  0,
                  effective_scope,
                  "observation",
                  Value::object({
                      {"body", Value{truncate_utf8_bytes(outcome.reply_text,
                                                         kPlatoonMaxMessageBytes)}},
                      {"reply_from", Value{item.target.id}},
                      {"to", Value{cfg.local_actor}},
                      {"untrusted_remote", Value{true}},
                      {"provenance_source", Value{"ssh:" + ssh_src}},
                  }),
              });
            }

            std::vector<std::string> refs;
            refs.emplace_back("untrusted_remote:true");
            refs.emplace_back(
                truncate_utf8_bytes("peer:" + item.target.id, kPlatoonMaxRefBytes));
            if (item.target.ssh_target.has_value() &&
                !item.target.ssh_target->empty()) {
              refs.emplace_back(truncate_utf8_bytes(
                  "provenance:ssh:" + *item.target.ssh_target, kPlatoonMaxRefBytes));
            }
            if (!item.target.fingerprint.empty()) {
              refs.emplace_back(truncate_utf8_bytes(
                  "fingerprint:" + item.target.fingerprint, kPlatoonMaxRefBytes));
            }
            refs.emplace_back(outcome.reply_verified ? "verified_peer:true"
                                                     : "verified_peer:false");

            auto reply_post = board.post(PlatoonPost{
                sanitize_platoon_sender_id(item.target.id),
                cfg.local_actor,
                PlatoonMessageKind::message,
                truncate_utf8_bytes(outcome.reply_text, kPlatoonMaxMessageBytes),
                std::move(refs),
            });
            if (reply_post.has_value())
              outcome.reply_board_seq = reply_post.value().seq;
          }
        } else {
          OnboardLeaderDispatchRequest req{};
          req.target = item.target;
          req.prompt = item.prompt;
          req.raw_body = routed.body;
          req.room_scope = effective_scope;
          req.local_actor = cfg.local_actor;
          req.board_seq = report.operator_board_seq;
          req.timeout_ms = cfg.timeout_ms;

          OnboardLeaderDispatchResult local_res{};
          if (cfg.onboard_executor) {
            local_res = cfg.onboard_executor(req);
          } else if (cfg.platoon_runner != nullptr) {
            local_res = execute_onboard_via_runner(*cfg.platoon_runner, cfg, req);
          } else {
            // No live runner handle attached: operator board mention is cleanly
            // recorded.
            local_res.status = PartyDeliveryStatus::delivered;
          }

          outcome.status = local_res.status;
          outcome.reply_text = std::move(local_res.reply_text);
          outcome.error_detail = std::move(local_res.error_detail);
          outcome.untrusted_remote = false;
          outcome.reply_verified = true;

          if (outcome.status == PartyDeliveryStatus::replied &&
              !outcome.reply_text.empty()) {
            const std::lock_guard lock{store_mutex};
            auto reply_post = board.post(PlatoonPost{
                sanitize_platoon_sender_id(item.target.id),
                cfg.local_actor,
                PlatoonMessageKind::message,
                truncate_utf8_bytes(outcome.reply_text, kPlatoonMaxMessageBytes),
                {"party_scope:" + effective_scope, "onboard_leader:true"},
            });
            if (reply_post.has_value())
              outcome.reply_board_seq = reply_post.value().seq;
          }
        }
      } catch (const std::exception &ex) {
        outcome.status = PartyDeliveryStatus::error;
        outcome.reply_text.clear();
        try {
          outcome.error_detail = party_chat_sanitize(ex.what(), kMaxErrorSnippetBytes);
        } catch (...) {
          outcome.error_detail.clear();
        }
      } catch (...) {
        outcome.status = PartyDeliveryStatus::error;
        outcome.reply_text.clear();
        try {
          outcome.error_detail = "unexpected non-standard exception during dispatch";
        } catch (...) {
          outcome.error_detail.clear();
        }
      }

      const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               SteadyClock::now() - started)
                               .count();
      outcome.elapsed_ms = elapsed < 0 ? 0 : static_cast<std::int64_t>(elapsed);
      report.outcomes[idx] = std::move(outcome);
    };

    const std::size_t capped_concurrency =
        std::min<std::size_t>(cfg.max_concurrency, kPartyDispatchMaxConcurrency);
    const std::size_t worker_count = std::min(items.size(), capped_concurrency);

    auto drain_work = [&]() noexcept {
      for (;;) {
        const std::size_t idx = next_index.fetch_add(1U, std::memory_order_relaxed);
        if (idx >= items.size())
          break;
        run_one(idx);
      }
    };

    if (worker_count <= 1U) {
      drain_work();
    } else {
      std::vector<std::thread> workers;
      workers.reserve(worker_count);
      struct ThreadJoinGuard {
        std::vector<std::thread> &threads;
        ~ThreadJoinGuard() {
          for (auto &t : threads) {
            if (t.joinable())
              t.join();
          }
        }
      } join_guard{workers};

      for (std::size_t w = 0; w < worker_count; ++w) {
        try {
          workers.emplace_back(drain_work);
        } catch (...) {
          // Fall back to draining remaining targets on the calling thread while
          // join_guard guarantees all already-started workers are joined safely.
          drain_work();
          break;
        }
      }
    }

    return Result<PartyDispatchReport>::success(std::move(report));
  } catch (const std::bad_alloc &) {
    return Result<PartyDispatchReport>::failure({ErrorCode::allocation});
  }
}

// ---------------------------------------------------------------------------
// Live Bridge Auto-Responder (`PartyBridgeWatcher`)
// ---------------------------------------------------------------------------

Result<PartyWatchCycleReport>
PartyBridgeWatcher::poll_and_respond_once(const PartyWatcherConfig &cfg,
                                          const WatcherResponder &responder) {
  try {
    if (!responder)
      return Result<PartyWatchCycleReport>::failure({ErrorCode::invalid_range});
    if (cfg.scope.empty() || cfg.scope.size() > kBoardBridgeMaxScopeBytes ||
        cfg.scope.find('\0') != std::string::npos || !valid_utf8(cfg.scope)) {
      return Result<PartyWatchCycleReport>::failure({ErrorCode::invalid_range});
    }
    if (cfg.max_replies_per_cycle == 0 ||
        cfg.max_replies_per_cycle > kPartyWatcherHardMaxReplies) {
      return Result<PartyWatchCycleReport>::failure({ErrorCode::invalid_range});
    }
    if (cfg.peers_dir.empty() || cfg.bridge_dir.empty())
      return Result<PartyWatchCycleReport>::failure({ErrorCode::invalid_range});

    // Fail closed WITHOUT creating any directories or keys if peers_dir or
    // bridge_dir is missing or a symlink.
    if (path_or_parent_is_symlink(cfg.peers_dir))
      return Result<PartyWatchCycleReport>::failure({ErrorCode::io, ELOOP});
    const PathProbe peers_probe = probe_path_nofollow(cfg.peers_dir);
    if (peers_probe == PathProbe::symlink)
      return Result<PartyWatchCycleReport>::failure({ErrorCode::io, ELOOP});
    if (peers_probe == PathProbe::missing)
      return Result<PartyWatchCycleReport>::failure({ErrorCode::io, ENOENT});
    if (peers_probe != PathProbe::directory)
      return Result<PartyWatchCycleReport>::failure({ErrorCode::io, ENOTDIR});
    // Probe key files BEFORE opening PeerIdentityStore so an existing empty
    // peers_dir stays completely untouched (zero identity.lock created).
    if (auto key_files = probe_existing_identity_files(cfg.peers_dir);
        !key_files.has_value()) {
      return Result<PartyWatchCycleReport>::failure(key_files.error());
    }

    if (path_or_parent_is_symlink(cfg.bridge_dir))
      return Result<PartyWatchCycleReport>::failure({ErrorCode::io, ELOOP});
    const PathProbe bridge_probe = probe_path_nofollow(cfg.bridge_dir);
    if (bridge_probe == PathProbe::symlink)
      return Result<PartyWatchCycleReport>::failure({ErrorCode::io, ELOOP});
    if (bridge_probe == PathProbe::missing)
      return Result<PartyWatchCycleReport>::failure({ErrorCode::io, ENOENT});
    if (bridge_probe != PathProbe::directory)
      return Result<PartyWatchCycleReport>::failure({ErrorCode::io, ENOTDIR});

    auto identity_res =
        PeerIdentityStore::open_existing(cfg.peers_dir, cfg.peer_identity_config);
    if (!identity_res.has_value())
      return Result<PartyWatchCycleReport>::failure(identity_res.error());
    const PeerIdentityStore identity = std::move(identity_res).value();
    const std::string &local_fp = identity.identity().fingerprint;

    auto known_res = KnownPeersStore::open(cfg.peers_dir, cfg.peer_identity_config);
    if (!known_res.has_value())
      return Result<PartyWatchCycleReport>::failure(known_res.error());
    const KnownPeersStore known_peers = std::move(known_res).value();

    auto bridge_res = BoardBridge::open(cfg.bridge_dir);
    if (!bridge_res.has_value())
      return Result<PartyWatchCycleReport>::failure(bridge_res.error());
    BoardBridge bridge = std::move(bridge_res).value();

    PartyWatchCycleReport report{};
    report.scope = cfg.scope;
    report.local_fingerprint = local_fp;

    // Query unread foreign events targeting cfg.scope via
    // BoardBridge::check_action_guard.
    auto guard_res = bridge.check_action_guard(local_fp, cfg.scope);
    if (!guard_res.has_value())
      return Result<PartyWatchCycleReport>::failure(guard_res.error());

    auto events_res = bridge.events();
    if (!events_res.has_value())
      return Result<PartyWatchCycleReport>::failure(events_res.error());
    const auto &all_events = events_res.value();

    auto receipts_res = bridge.receipts();
    if (!receipts_res.has_value())
      return Result<PartyWatchCycleReport>::failure(receipts_res.error());

    std::unordered_set<std::string_view> durably_handled;
    for (const auto &rcpt : receipts_res.value()) {
      if (rcpt.recipient_actor == local_fp &&
          (receipt_stage_is_cognitive_inclusion(rcpt.stage) ||
           rcpt.stage == ReceiptStage::acted)) {
        durably_handled.insert(rcpt.event_hash);
      }
    }

    // Also count own events in scope for observability, while strictly ignoring them.
    for (const auto &ev : all_events) {
      if (ev.actor_id == local_fp && !is_passive_event_kind(ev.kind) &&
          (ev.resource_scope == cfg.scope || ev.resource_scope.empty() ||
           ev.resource_scope == "*" || cfg.scope == "*")) {
        ++report.skipped_own;
      }
    }

    if (guard_res.value().allowed || guard_res.value().blocking_event_hashes.empty())
      return Result<PartyWatchCycleReport>::success(std::move(report));

    std::unordered_set<std::string_view> blocking_set;
    blocking_set.reserve(guard_res.value().blocking_event_hashes.size());
    for (const auto &h : guard_res.value().blocking_event_hashes)
      blocking_set.insert(h);

    auto envelopes_res = bridge.envelopes();
    if (!envelopes_res.has_value())
      return Result<PartyWatchCycleReport>::failure(envelopes_res.error());

    std::unordered_map<std::string, const PeerEnvelope *> envelope_by_event_hash;
    envelope_by_event_hash.reserve(envelopes_res.value().size());
    for (const auto &env : envelopes_res.value()) {
      if (auto ev_hash = envelope_causal_event_hash(env); ev_hash.has_value()) {
        if (env.from_fingerprint != local_fp)
          envelope_by_event_hash.try_emplace(*ev_hash, &env);
      }
    }

    const std::size_t reply_cap =
        std::min<std::size_t>(cfg.max_replies_per_cycle, kPartyWatcherHardMaxReplies);

    // Iterate in causal/log order across blocking unread events.
    for (const auto &ev : all_events) {
      if (!blocking_set.contains(ev.event_hash))
        continue;
      ++report.inspected;

      // Belt-and-suspenders: never respond to own events or passive kinds.
      if (ev.actor_id == local_fp || is_passive_event_kind(ev.kind)) {
        ++report.skipped_own;
        continue;
      }

      // Skip already-handled events (in-memory or durable receipts across restarts).
      if (seen_event_hashes_.contains(ev.event_hash) ||
          durably_handled.contains(ev.event_hash)) {
        ++report.skipped_already_seen;
        continue;
      }

      // Enforce anti-loop per-cycle reply cap.
      if (report.answered >= reply_cap) {
        report.capped_by_limit = true;
        break;
      }

      // Verify peer is pinned and non-revoked in KnownPeersStore.
      auto peer_res = known_peers.find_by_fingerprint(ev.actor_id);
      if (!peer_res.has_value())
        return Result<PartyWatchCycleReport>::failure(peer_res.error());
      const auto &maybe_peer = peer_res.value();
      if (!maybe_peer.has_value() || maybe_peer->revoked) {
        ++report.skipped_unverified;
        continue;
      }
      const PinnedPeer &pinned = *maybe_peer;
      const std::string peer_alias =
          pinned.alias.empty() ? pinned.fingerprint : pinned.alias;

      // Locate & cryptographically verify the signed PeerEnvelope for this event.
      std::optional<PeerEnvelope> envelope_for_frame;
      if (const auto env_it = envelope_by_event_hash.find(ev.event_hash);
          env_it != envelope_by_event_hash.end()) {
        const PeerEnvelope &candidate_env = *env_it->second;
        if (candidate_env.from_fingerprint != ev.actor_id) {
          ++report.skipped_unverified;
          continue;
        }
        auto verified = known_peers.verify_envelope(candidate_env);
        if (!verified.has_value()) {
          ++report.skipped_unverified;
          continue;
        }
        envelope_for_frame = candidate_env;
      } else if (cfg.require_signed_envelope) {
        ++report.skipped_unverified;
        continue;
      } else {
        PeerEnvelope synthetic{};
        synthetic.envelope_id = "event-" + ev.event_hash.substr(0, 16);
        synthetic.from_fingerprint = ev.actor_id;
        synthetic.to_fingerprint = local_fp;
        synthetic.thread_id = ev.resource_scope.empty() ? cfg.scope : ev.resource_scope;
        synthetic.kind = PeerEnvelopeKind::mail;
        synthetic.timestamp_ns = ev.timestamp_ns;
        synthetic.payload = ev.payload;
        envelope_for_frame = std::move(synthetic);
      }

      if (!envelope_for_frame.has_value()) {
        ++report.skipped_unverified;
        continue;
      }

      // Wrap incoming peer data in strict <<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN>>>
      // provenance fencing before passing to responder.
      PeerProvenance provenance{};
      provenance.owner_actor = local_fp;
      provenance.requested_by_actor = ev.actor_id;
      provenance.untrusted_sources = {
          "peer:" + ev.actor_id,
          "scope:" + (ev.resource_scope.empty() ? cfg.scope : ev.resource_scope),
      };
      provenance.trust_note =
          "Verified pinned peer '" + peer_alias + "' (untrusted peer data only)";

      auto framed_res = format_quoted_peer_frame(*envelope_for_frame, provenance);
      if (!framed_res.has_value())
        return Result<PartyWatchCycleReport>::failure(framed_res.error());

      auto reply_res =
          responder(WatchPeerAlias{peer_alias}, WatchFencedPrompt{framed_res.value()});
      if (!reply_res.has_value()) {
        ++report.responder_errors;
        continue;
      }

      const std::string reply_text = std::move(reply_res).value();
      const std::string reply_scope =
          ev.resource_scope.empty() ? cfg.scope : ev.resource_scope;

      // 1. Emit causal reply event linked to incoming event_hash.
      auto reply_event_res = bridge.emit_causal_event(CausalEventDraft{
          local_fp,
          0,
          {ev.event_hash},
          0,
          reply_scope,
          "chat",
          Value::object({
              {"body", Value{reply_text}},
              {"in_reply_to", Value{ev.event_hash}},
              {"to", Value{peer_alias}},
              {"sender_id", Value{local_fp}},
          }),
      });
      if (!reply_event_res.has_value())
        return Result<PartyWatchCycleReport>::failure(reply_event_res.error());
      const CausalEvent &reply_event = reply_event_res.value();

      // 2. Sign & record outbound reply PeerEnvelope in BoardBridge.
      auto reply_env_id = random_prefixed_id("watch-reply-");
      if (!reply_env_id.has_value())
        return Result<PartyWatchCycleReport>::failure(reply_env_id.error());

      const std::string reply_thread =
          envelope_for_frame->thread_id.empty()
              ? sanitize_envelope_thread_id(reply_scope)
              : sanitize_envelope_thread_id(envelope_for_frame->thread_id);
      const PeerEnvelopeMeta reply_meta{
          std::move(reply_env_id).value(), ev.actor_id, reply_thread,
          PeerEnvelopeKind::mail,          0,
      };
      auto reply_env_res =
          BoardBridge::sign_causal_event_envelope(identity, reply_event, reply_meta);
      if (!reply_env_res.has_value())
        return Result<PartyWatchCycleReport>::failure(reply_env_res.error());

      std::ostringstream reply_wire;
      auto sent_reply = bridge.send_envelope(reply_wire, reply_env_res.value());
      if (!sent_reply.has_value())
        return Result<PartyWatchCycleReport>::failure(sent_reply.error());

      // 3. Record durable ReadReceipt + signed receipt PeerEnvelope bound to incoming
      //    event_hash so the message is never answered twice across restarts.
      MessageReceipt receipt{};
      receipt.event_hash = ev.event_hash;
      receipt.recipient_actor = local_fp;
      receipt.stage = ReceiptStage::acknowledged;
      receipt.timestamp_ns = 0;
      receipt.request_hash = reply_event.event_hash;
      receipt.action_ref = reply_env_res.value().envelope_id;

      auto recorded_rcpt = bridge.record_receipt(receipt);
      if (!recorded_rcpt.has_value())
        return Result<PartyWatchCycleReport>::failure(recorded_rcpt.error());

      auto rcpt_env_id = random_prefixed_id("watch-rcpt-");
      if (!rcpt_env_id.has_value())
        return Result<PartyWatchCycleReport>::failure(rcpt_env_id.error());

      const PeerEnvelopeMeta rcpt_meta{
          std::move(rcpt_env_id).value(), ev.actor_id, reply_thread,
          PeerEnvelopeKind::mail,         0,
      };
      auto rcpt_env_res = BoardBridge::sign_receipt_envelope(
          identity, recorded_rcpt.value(), rcpt_meta);
      if (!rcpt_env_res.has_value())
        return Result<PartyWatchCycleReport>::failure(rcpt_env_res.error());

      std::ostringstream rcpt_wire;
      auto sent_rcpt = bridge.send_envelope(rcpt_wire, rcpt_env_res.value());
      if (!sent_rcpt.has_value())
        return Result<PartyWatchCycleReport>::failure(sent_rcpt.error());

      seen_event_hashes_.insert(ev.event_hash);
      ++report.answered;
      report.replies.push_back(PartyWatchReplyRecord{
          ev.event_hash,
          peer_alias,
          ev.actor_id,
          reply_event.event_hash,
          reply_env_res.value().envelope_id,
          rcpt_env_res.value().envelope_id,
          reply_text,
      });
      report.outbound_envelopes.push_back(std::move(reply_env_res).value());
      report.outbound_envelopes.push_back(std::move(rcpt_env_res).value());
    }

    return Result<PartyWatchCycleReport>::success(std::move(report));
  } catch (const std::bad_alloc &) {
    return Result<PartyWatchCycleReport>::failure({ErrorCode::allocation});
  }
}

} // namespace blackbird
