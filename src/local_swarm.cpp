#include "blackbird/local_swarm.hpp"
#include "blackbird/json.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <utility>

#ifdef __APPLE__
#include <sys/event.h>
#include <sys/time.h>
#elif defined(__linux__)
#include <sys/inotify.h>
#endif

namespace blackbird {
namespace {

#if defined(__APPLE__)
constexpr const char *kBoardFileName = "board.jsonl";
constexpr std::uintptr_t kWakeEventIdent = 1;
#endif
constexpr const char *kSwarmStateFile = "local_swarm.json";
constexpr const char *kSwarmStateLockFile = "local_swarm.lock";
constexpr std::uint64_t kSwarmStateSchemaVersion = 1;
constexpr std::size_t kMaxSwarmStateBytes = 16 * 1024 * 1024;
constexpr std::size_t kReadChunkBytes = 64 * 1024;
constexpr std::int64_t kCancelSliceMs = 15;
constexpr std::int64_t kMissingDirPollMs = 25;
constexpr std::int64_t kMaxBoundedWaitTimeoutMs = 365LL * 24LL * 60LL * 60LL * 1000LL;

std::atomic<std::uint64_t> g_swarm_tmp_counter{0};

using SteadyClock = std::chrono::steady_clock;

enum class EmptyPolicy : std::uint8_t { allow, forbid };
enum class PathKind : std::uint8_t { regular, directory };

Error native_error(int err) noexcept {
  if (err == EINTR)
    return {ErrorCode::interrupted, err};
  if (err == ENOTSUP)
    return {ErrorCode::unsupported, err};
  return {ErrorCode::io, err};
}

std::int64_t wall_now_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return ns < 0 ? 0 : static_cast<std::int64_t>(ns);
}

class ScopedFd {
public:
  ScopedFd() = default;
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
  int release() noexcept { return std::exchange(fd_, -1); }
  void reset(int next = -1) noexcept {
    if (fd_ >= 0)
      (void)::close(fd_);
    fd_ = next;
  }

private:
  int fd_ = -1;
};

Result<void> check_restricted(int fd, PathKind kind) noexcept {
  struct stat st{};
  if (::fstat(fd, &st) != 0)
    return Result<void>::failure(native_error(errno));
  const bool kind_ok =
      kind == PathKind::directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode);
  if (!kind_ok || st.st_uid != ::geteuid() || (st.st_mode & 0077) != 0)
    return Result<void>::failure({ErrorCode::io, EPERM});
  return Result<void>::success();
}

Result<void> fsync_fd(int fd) noexcept {
  while (::fsync(fd) != 0) {
    if (errno == EINTR)
      continue;
    return Result<void>::failure(native_error(errno));
  }
  return Result<void>::success();
}

Result<void> write_all_fd(int fd, std::string_view data) noexcept {
  std::size_t offset = 0;
  while (offset < data.size()) {
    const ssize_t written = ::write(fd, data.data() + offset, data.size() - offset);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      return Result<void>::failure(native_error(errno));
    }
    if (written == 0)
      return Result<void>::failure({ErrorCode::io, EIO});
    offset += static_cast<std::size_t>(written);
  }
  return Result<void>::success();
}

Result<ScopedFd> open_or_create_restricted(int dir_fd, const char *name) noexcept {
  for (int attempt = 0; attempt < 32; ++attempt) {
    int fd = -1;
    do {
      fd = ::openat(dir_fd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      ScopedFd owned{fd};
      auto checked = check_restricted(owned.get(), PathKind::regular);
      if (!checked.has_value())
        return Result<ScopedFd>::failure(checked.error());
      return Result<ScopedFd>::success(std::move(owned));
    }
    if (errno != ENOENT)
      return Result<ScopedFd>::failure(native_error(errno));

    do {
      fd = ::openat(dir_fd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    mode_t{0600});
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      ScopedFd owned{fd};
      auto checked = check_restricted(owned.get(), PathKind::regular);
      if (!checked.has_value())
        return Result<ScopedFd>::failure(checked.error());
      return Result<ScopedFd>::success(std::move(owned));
    }
    if (errno != EEXIST && errno != ENOENT)
      return Result<ScopedFd>::failure(native_error(errno));
  }
  return Result<ScopedFd>::failure({ErrorCode::busy, EEXIST});
}

class ScopedFlock {
public:
  enum class Mode : std::uint8_t { shared, exclusive };

  static Result<ScopedFlock> acquire(int dir_fd, const char *lock_name,
                                     Mode mode) noexcept {
    auto opened = open_or_create_restricted(dir_fd, lock_name);
    if (!opened.has_value())
      return Result<ScopedFlock>::failure(opened.error());
    ScopedFd owned = std::move(opened).value();
    const int op = mode == Mode::shared ? LOCK_SH : LOCK_EX;
    while (::flock(owned.get(), op) != 0) {
      if (errno == EINTR)
        continue;
      return Result<ScopedFlock>::failure(native_error(errno));
    }
    return Result<ScopedFlock>::success(ScopedFlock{std::move(owned)});
  }

  ScopedFlock(const ScopedFlock &) = delete;
  ScopedFlock &operator=(const ScopedFlock &) = delete;
  ScopedFlock(ScopedFlock &&other) noexcept = default;
  ScopedFlock &operator=(ScopedFlock &&other) noexcept = default;
  ~ScopedFlock() {
    if (fd_) {
      while (::flock(fd_.get(), LOCK_UN) != 0 && errno == EINTR) {
      }
    }
  }

private:
  explicit ScopedFlock(ScopedFd fd) noexcept : fd_(std::move(fd)) {}
  ScopedFd fd_;
};

Result<void> validate_text(std::string_view value, std::size_t max_bytes,
                           EmptyPolicy policy) noexcept {
  if (policy == EmptyPolicy::forbid && value.empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (value.size() > max_bytes)
    return Result<void>::failure({ErrorCode::capacity});
  if (value.find('\0') != std::string_view::npos)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_utf8(value))
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

bool is_ascii_alnum(char ch) noexcept {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
         (ch >= '0' && ch <= '9');
}

bool is_mention_prefix_blocker(char ch) noexcept {
  return is_ascii_alnum(ch) || ch == '_' || ch == '-' || ch == '.';
}

bool is_mention_suffix_blocker(char ch) noexcept {
  return is_ascii_alnum(ch) || ch == '_' || ch == '-';
}

struct MentionLookup {
  std::string_view text;
  std::string_view target;
};

bool text_contains_mention(MentionLookup lookup) noexcept {
  if (lookup.target.empty() || lookup.text.size() < lookup.target.size() + 1U)
    return false;
  std::size_t pos = 0;
  while (pos < lookup.text.size()) {
    const std::size_t at = lookup.text.find('@', pos);
    if (at == std::string_view::npos)
      return false;
    const bool before_ok = (at == 0) || !is_mention_prefix_blocker(lookup.text[at - 1]);
    const std::size_t name_start = at + 1;
    const std::size_t name_end = name_start + lookup.target.size();
    if (before_ok && name_end <= lookup.text.size() &&
        lookup.text.compare(name_start, lookup.target.size(), lookup.target) == 0) {
      const bool after_ok = (name_end == lookup.text.size()) ||
                            !is_mention_suffix_blocker(lookup.text[name_end]);
      if (after_ok)
        return true;
    }
    pos = at + 1;
  }
  return false;
}

struct NormalizedPathResult {
  std::string normalized;
  std::string error_reason;
  bool ok = false;
};

NormalizedPathResult normalize_relative_repo_path(std::string_view raw) {
  if (raw.empty())
    return {{}, "empty path", false};
  if (raw.size() > kSwarmMaxOwnedPathBytes)
    return {{}, "path exceeds length limit", false};
  if (raw.find('\0') != std::string_view::npos)
    return {{}, "path contains NUL byte", false};
  if (!valid_utf8(raw))
    return {{}, "path is not valid UTF-8", false};
  for (const char ch : raw) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7fU)
      return {{}, "path contains control character", false};
    if (ch == '\\')
      return {{}, "path contains backslash", false};
  }
  if (raw.front() == '/')
    return {{}, "absolute path is not allowed", false};

  std::vector<std::string_view> components;
  std::size_t start = 0;
  while (start <= raw.size()) {
    const std::size_t slash = raw.find('/', start);
    const std::size_t end = slash == std::string_view::npos ? raw.size() : slash;
    const std::string_view segment = raw.substr(start, end - start);
    if (segment == "..")
      return {{}, "path traversal '..' is not allowed", false};
    if (!segment.empty() && segment != ".")
      components.push_back(segment);
    if (slash == std::string_view::npos)
      break;
    start = slash + 1;
  }
  if (components.empty())
    return {{}, "path resolves to empty relative path", false};

  std::string joined;
  joined.reserve(raw.size());
  for (std::size_t i = 0; i < components.size(); ++i) {
    if (i > 0)
      joined.push_back('/');
    joined.append(components[i]);
  }
  return {std::move(joined), {}, true};
}

struct PathPair {
  std::string_view owner_path;
  std::string_view candidate_path;
};

bool path_covers_candidate(PathPair pair) noexcept {
  if (pair.owner_path == pair.candidate_path)
    return true;
  if (pair.candidate_path.size() > pair.owner_path.size() &&
      pair.candidate_path.starts_with(pair.owner_path) &&
      pair.candidate_path[pair.owner_path.size()] == '/') {
    return true;
  }
  return false;
}

bool paths_overlap(PathPair pair) noexcept {
  return path_covers_candidate(pair) ||
         path_covers_candidate(PathPair{pair.candidate_path, pair.owner_path});
}

PlatoonMemberState to_platoon_state(SwarmWorkerState state) noexcept {
  switch (state) {
  case SwarmWorkerState::working:
    return PlatoonMemberState::working;
  case SwarmWorkerState::waiting:
    return PlatoonMemberState::waiting;
  case SwarmWorkerState::stopped:
  case SwarmWorkerState::killed:
    return PlatoonMemberState::stopped;
  }
  return PlatoonMemberState::stopped;
}

struct BriefFormatInput {
  std::string_view worker_name;
  std::string_view raw_brief;
};

std::string format_directed_brief(BriefFormatInput input) {
  const std::string mention = "@" + std::string{input.worker_name};
  if (input.raw_brief.starts_with(mention) &&
      (input.raw_brief.size() == mention.size() ||
       !is_mention_suffix_blocker(input.raw_brief[mention.size()]))) {
    return std::string{input.raw_brief};
  }
  std::string out;
  out.reserve(mention.size() + 1U + input.raw_brief.size());
  out.append(mention);
  out.push_back(' ');
  out.append(input.raw_brief);
  return out;
}

struct SliceBriefInput {
  std::size_t one_based_index = 1;
  std::size_t total_slices = 1;
  std::string_view target;
  std::string_view shared_brief;
};

std::string format_slice_brief(SliceBriefInput input) {
  std::string out = "[slice " + std::to_string(input.one_based_index) + "/" +
                    std::to_string(input.total_slices) + ": " +
                    std::string{input.target} + "]";
  if (!input.shared_brief.empty()) {
    out.push_back(' ');
    out.append(input.shared_brief);
  }
  return out;
}

std::string build_dentist_brief(const std::vector<std::string> &repo_checks) {
  std::string brief =
      "[dentist-verifier] Read-only adversarial verifier operating in inherit "
      "workspace. NEVER edit production files (owned_files is empty). Inspect "
      "worker worktrees and verify: formatting (clang-format), clean build with "
      "warnings-as-errors, targeted regression & sanitizer tests, static analysis "
      "(clang-tidy), and security invariants (path traversal, owned_files scope, "
      "resource/error safety). Report defects to the owning worker by @name.";
  if (!repo_checks.empty()) {
    brief.append(" Required repo checks:");
    for (const auto &item : repo_checks) {
      brief.append(" [");
      brief.append(item);
      brief.push_back(']');
    }
  }
  return brief;
}

struct ModelHandoffTextInput {
  std::string_view worker_name;
  std::string_view old_provider;
  std::string_view old_model;
  std::string_view new_provider;
  std::string_view new_model;
  std::string_view session_id;
  std::string_view reason;
};

std::string format_model_handoff_text(ModelHandoffTextInput input) {
  std::string text = "@" + std::string{input.worker_name} + " [model-handoff] ";
  if (!input.old_provider.empty()) {
    text.append(input.old_provider);
    text.push_back('/');
  }
  text.append(input.old_model.empty() ? "<unset>" : input.old_model);
  text.append(" -> ");
  if (!input.new_provider.empty()) {
    text.append(input.new_provider);
    text.push_back('/');
  }
  text.append(input.new_model);
  text.append(" (session=");
  text.append(input.session_id);
  if (!input.reason.empty()) {
    text.append(", reason=");
    text.append(input.reason);
  }
  text.push_back(')');
  return text;
}

Result<std::uint64_t> parse_uint64_field(const Value &object, std::string_view key) {
  const auto *field = object.find(key);
  if (!field)
    return Result<std::uint64_t>::failure({ErrorCode::corrupt});
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return Result<std::uint64_t>::failure({ErrorCode::corrupt});
  const std::string text = num->text();
  std::uint64_t parsed = 0;
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (ec != std::errc{} || ptr != text.data() + text.size())
    return Result<std::uint64_t>::failure({ErrorCode::corrupt});
  return Result<std::uint64_t>::success(parsed);
}

Result<std::int64_t> parse_int64_field(const Value &object, std::string_view key) {
  const auto *field = object.find(key);
  if (!field)
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  const std::string text = num->text();
  std::int64_t parsed = 0;
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (ec != std::errc{} || ptr != text.data() + text.size())
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  return Result<std::int64_t>::success(parsed);
}

Result<std::string> parse_string_field(const Value &object, std::string_view key) {
  const auto *field = object.find(key);
  if (!field)
    return Result<std::string>::failure({ErrorCode::corrupt});
  const auto *str = std::get_if<std::string>(&field->value());
  if (!str)
    return Result<std::string>::failure({ErrorCode::corrupt});
  return Result<std::string>::success(*str);
}

Result<bool> parse_bool_field(const Value &object, std::string_view key) {
  const auto *field = object.find(key);
  if (!field)
    return Result<bool>::failure({ErrorCode::corrupt});
  const auto *flag = std::get_if<bool>(&field->value());
  if (!flag)
    return Result<bool>::failure({ErrorCode::corrupt});
  return Result<bool>::success(*flag);
}

Value worker_to_value(const SwarmWorkerRecord &record) {
  Value::Array owned_array;
  owned_array.reserve(record.owned_files.size());
  for (const auto &path : record.owned_files)
    owned_array.emplace_back(path);

  Value::Object fields{
      {"name", Value{record.name}},
      {"role", Value{record.role}},
      {"provider", Value{record.provider}},
      {"model", Value{record.model}},
      {"workspace_mode",
       Value{std::string{swarm_workspace_mode_name(record.workspace_mode)}}},
      {"state", Value{std::string{swarm_worker_state_name(record.state)}}},
      {"owned_files", Value{std::move(owned_array)}},
      {"brief", Value{record.brief}},
      {"session_id", Value{record.session_id}},
      {"workspace_path", Value{record.workspace_path.string()}},
      {"lease_id", Value{record.lease_id}},
      {"branch", Value{record.branch}},
      {"brief_seq", Value{Number{record.brief_seq}}},
      {"created_ns", Value{Number{record.created_ns}}},
      {"updated_ns", Value{Number{record.updated_ns}}},
      {"read_only", Value{record.read_only}},
  };
  if (record.fork_from_session_dir.has_value()) {
    fields.emplace_back("fork_from_session_dir",
                        Value{record.fork_from_session_dir->string()});
  }
  return Value::object(std::move(fields));
}

Result<SwarmWorkerRecord> worker_from_value(const Value &value) {
  if (!std::holds_alternative<Value::Object>(value.value()))
    return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});

  auto name = parse_string_field(value, "name");
  auto role = parse_string_field(value, "role");
  auto provider = parse_string_field(value, "provider");
  auto model = parse_string_field(value, "model");
  auto ws_mode_str = parse_string_field(value, "workspace_mode");
  auto state_str = parse_string_field(value, "state");
  auto brief = parse_string_field(value, "brief");
  auto session_id = parse_string_field(value, "session_id");
  auto workspace_path = parse_string_field(value, "workspace_path");
  auto lease_id = parse_string_field(value, "lease_id");
  auto branch = parse_string_field(value, "branch");
  auto brief_seq = parse_uint64_field(value, "brief_seq");
  auto created_ns = parse_int64_field(value, "created_ns");
  auto updated_ns = parse_int64_field(value, "updated_ns");
  auto read_only = parse_bool_field(value, "read_only");
  if (!name.has_value() || !role.has_value() || !provider.has_value() ||
      !model.has_value() || !ws_mode_str.has_value() || !state_str.has_value() ||
      !brief.has_value() || !session_id.has_value() || !workspace_path.has_value() ||
      !lease_id.has_value() || !branch.has_value() || !brief_seq.has_value() ||
      !created_ns.has_value() || !updated_ns.has_value() || !read_only.has_value()) {
    return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
  }

  if (!valid_swarm_worker_name(name.value()))
    return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
  if (created_ns.value() < 0 || updated_ns.value() < 0)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
  auto ws_mode = parse_swarm_workspace_mode(ws_mode_str.value());
  auto state = parse_swarm_worker_state(state_str.value());
  if (!ws_mode.has_value() || !state.has_value())
    return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
  for (const std::string_view field :
       {std::string_view{role.value()}, std::string_view{provider.value()},
        std::string_view{model.value()}, std::string_view{session_id.value()},
        std::string_view{workspace_path.value()}, std::string_view{lease_id.value()},
        std::string_view{branch.value()}}) {
    if (!validate_text(field, kPlatoonMaxFieldBytes, EmptyPolicy::allow).has_value())
      return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
  }
  if (!validate_text(brief.value(), kPlatoonMaxBriefBytes, EmptyPolicy::forbid)
           .has_value()) {
    return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
  }

  const auto *owned_field = value.find("owned_files");
  if (!owned_field)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
  const auto *owned_array = std::get_if<Value::Array>(&owned_field->value());
  if (!owned_array || owned_array->size() > kSwarmMaxOwnedFilesPerWorker)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
  if (read_only.value() && !owned_array->empty())
    return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});

  std::vector<std::string> owned_files;
  owned_files.reserve(owned_array->size());
  for (const auto &entry : *owned_array) {
    const auto *path_str = std::get_if<std::string>(&entry.value());
    if (!path_str)
      return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
    auto norm = normalize_relative_repo_path(*path_str);
    if (!norm.ok)
      return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
    owned_files.push_back(std::move(norm.normalized));
  }
  std::sort(owned_files.begin(), owned_files.end());
  for (std::size_t i = 1; i < owned_files.size(); ++i) {
    if (owned_files[i - 1] == owned_files[i])
      return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
  }

  std::optional<std::filesystem::path> fork_dir;
  if (const auto *fork_field = value.find("fork_from_session_dir")) {
    const auto *fork_str = std::get_if<std::string>(&fork_field->value());
    if (!fork_str ||
        !validate_text(*fork_str, kPlatoonMaxFieldBytes, EmptyPolicy::forbid)
             .has_value()) {
      return Result<SwarmWorkerRecord>::failure({ErrorCode::corrupt});
    }
    fork_dir = std::filesystem::path{*fork_str};
  }

  SwarmWorkerRecord record;
  record.name = std::move(name).value();
  record.role = std::move(role).value();
  record.provider = std::move(provider).value();
  record.model = std::move(model).value();
  record.workspace_mode = ws_mode.value();
  record.state = state.value();
  record.owned_files = std::move(owned_files);
  record.brief = std::move(brief).value();
  record.session_id = std::move(session_id).value();
  record.fork_from_session_dir = std::move(fork_dir);
  record.workspace_path = std::filesystem::path{std::move(workspace_path).value()};
  record.lease_id = std::move(lease_id).value();
  record.branch = std::move(branch).value();
  record.brief_seq = brief_seq.value();
  record.created_ns = created_ns.value();
  record.updated_ns = updated_ns.value();
  record.read_only = read_only.value();
  return Result<SwarmWorkerRecord>::success(std::move(record));
}

Result<std::string> read_regular_file_bounded(int dir_fd, const char *name,
                                              std::size_t max_bytes, bool &exists) {
  exists = false;
  int fd = -1;
  do {
    fd = ::openat(dir_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ENOENT)
      return Result<std::string>::success(std::string{});
    return Result<std::string>::failure(native_error(errno));
  }
  ScopedFd owned{fd};
  auto checked = check_restricted(owned.get(), PathKind::regular);
  if (!checked.has_value())
    return Result<std::string>::failure(checked.error());
  exists = true;

  std::string content;
  std::array<char, kReadChunkBytes> buffer{};
  for (;;) {
    const ssize_t count = ::read(owned.get(), buffer.data(), buffer.size());
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return Result<std::string>::failure(native_error(errno));
    }
    if (count == 0)
      break;
    const auto bytes = static_cast<std::size_t>(count);
    if (bytes > max_bytes - content.size())
      return Result<std::string>::failure({ErrorCode::capacity});
    content.append(buffer.data(), bytes);
  }
  return Result<std::string>::success(std::move(content));
}

Result<void> write_file_atomic_locked(int dir_fd, const char *target_name,
                                      std::string_view payload) {
  const auto pid = static_cast<unsigned long long>(::getpid());
  std::string tmp_name;
  ScopedFd tmp_fd;
  for (int attempt = 0; attempt < 64; ++attempt) {
    const auto seq = g_swarm_tmp_counter.fetch_add(1, std::memory_order_relaxed);
    tmp_name = "local_swarm.tmp." + std::to_string(pid) + "." + std::to_string(seq);
    int fd = -1;
    do {
      fd = ::openat(dir_fd, tmp_name.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t{0600});
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      tmp_fd.reset(fd);
      break;
    }
    if (errno != EEXIST)
      return Result<void>::failure(native_error(errno));
  }
  if (!tmp_fd)
    return Result<void>::failure({ErrorCode::conflict, EEXIST});

  class TempFileGuard {
  public:
    TempFileGuard(int parent_fd, std::string name) noexcept
        : parent_fd_(parent_fd), name_(std::move(name)) {}
    TempFileGuard(const TempFileGuard &) = delete;
    TempFileGuard &operator=(const TempFileGuard &) = delete;
    ~TempFileGuard() {
      if (active_)
        (void)::unlinkat(parent_fd_, name_.c_str(), 0);
    }
    void dismiss() noexcept { active_ = false; }
    const char *c_str() const noexcept { return name_.c_str(); }

  private:
    int parent_fd_;
    std::string name_;
    bool active_ = true;
  } cleanup{dir_fd, std::move(tmp_name)};

  auto written = write_all_fd(tmp_fd.get(), payload);
  if (!written.has_value())
    return written;
  auto synced = fsync_fd(tmp_fd.get());
  if (!synced.has_value())
    return synced;
  const int raw_fd = tmp_fd.release();
  if (::close(raw_fd) != 0)
    return Result<void>::failure(native_error(errno));

  if (::renameat(dir_fd, cleanup.c_str(), dir_fd, target_name) != 0)
    return Result<void>::failure(native_error(errno));
  cleanup.dismiss();
  return fsync_fd(dir_fd);
}

struct UnreadScanResult {
  bool triggered = false;
  std::uint64_t latest_seq = 0;
  std::vector<PlatoonMessage> window;
};

Result<UnreadScanResult> scan_unread_for_wake(const PlatoonBoard &board,
                                              const SwarmBoardWaitOptions &options) {
  UnreadScanResult out;
  out.latest_seq = options.since_seq;

  std::deque<PlatoonMessage> window;
  std::uint64_t cursor = options.since_seq;
  const std::size_t page_size = std::clamp<std::size_t>(
      options.max_messages, kPlatoonDefaultReadLimit, std::size_t{1024});

  for (;;) {
    auto page_res = board.read_since(cursor, page_size);
    if (!page_res.has_value())
      return Result<UnreadScanResult>::failure(page_res.error());
    auto page = std::move(page_res).value();
    if (page.empty())
      break;
    const std::uint64_t page_last_seq = page.back().seq;

    for (auto &msg : page) {
      const bool is_trigger = !options.mentions_only ||
                              swarm_message_mentions_agent(msg, options.agent_name);
      out.latest_seq = msg.seq;
      if (window.size() == options.max_messages)
        window.pop_front();
      window.push_back(std::move(msg));
      if (is_trigger)
        out.triggered = true;
      if (out.triggered && window.size() == options.max_messages) {
        out.window.reserve(window.size());
        for (auto &entry : window)
          out.window.push_back(std::move(entry));
        return Result<UnreadScanResult>::success(std::move(out));
      }
    }

    if (page.size() < page_size || page_last_seq <= cursor)
      break;
    cursor = page_last_seq;
  }

  if (out.triggered) {
    out.window.reserve(window.size());
    for (auto &entry : window)
      out.window.push_back(std::move(entry));
  }
  return Result<UnreadScanResult>::success(std::move(out));
}

} // namespace

// ---------------------------------------------------------------------------
// Public enum / validation helpers
// ---------------------------------------------------------------------------

std::string_view swarm_workspace_mode_name(SwarmWorkspaceMode mode) noexcept {
  switch (mode) {
  case SwarmWorkspaceMode::inherit:
    return "inherit";
  case SwarmWorkspaceMode::share:
    return "share";
  case SwarmWorkspaceMode::branch:
    return "branch";
  }
  return {};
}

Result<SwarmWorkspaceMode> parse_swarm_workspace_mode(std::string_view name) noexcept {
  if (name == "inherit")
    return Result<SwarmWorkspaceMode>::success(SwarmWorkspaceMode::inherit);
  if (name == "share")
    return Result<SwarmWorkspaceMode>::success(SwarmWorkspaceMode::share);
  if (name == "branch")
    return Result<SwarmWorkspaceMode>::success(SwarmWorkspaceMode::branch);
  return Result<SwarmWorkspaceMode>::failure({ErrorCode::invalid_range});
}

std::string_view swarm_worker_state_name(SwarmWorkerState state) noexcept {
  switch (state) {
  case SwarmWorkerState::working:
    return "working";
  case SwarmWorkerState::waiting:
    return "waiting";
  case SwarmWorkerState::stopped:
    return "stopped";
  case SwarmWorkerState::killed:
    return "killed";
  }
  return {};
}

Result<SwarmWorkerState> parse_swarm_worker_state(std::string_view name) noexcept {
  if (name == "working")
    return Result<SwarmWorkerState>::success(SwarmWorkerState::working);
  if (name == "waiting")
    return Result<SwarmWorkerState>::success(SwarmWorkerState::waiting);
  if (name == "stopped")
    return Result<SwarmWorkerState>::success(SwarmWorkerState::stopped);
  if (name == "killed")
    return Result<SwarmWorkerState>::success(SwarmWorkerState::killed);
  return Result<SwarmWorkerState>::failure({ErrorCode::invalid_range});
}

bool valid_swarm_worker_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > kSwarmMaxWorkerNameLength)
    return false;
  if (name == "all" || name == "coordinator" || name.starts_with("coordinator-"))
    return false;
  const char first = name.front();
  if (!((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')))
    return false;
  for (const char ch : name) {
    const bool ok =
        (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
    if (!ok)
      return false;
  }
  return true;
}

bool swarm_message_mentions_agent(const PlatoonMessage &message,
                                  std::string_view agent_name) noexcept {
  if (agent_name.empty())
    return false;
  if (message.to == agent_name || message.to == "all")
    return true;
  if (text_contains_mention(MentionLookup{message.text, agent_name}))
    return true;
  return text_contains_mention(MentionLookup{message.text, "all"});
}

// ---------------------------------------------------------------------------
// Zero-Token Reactive SwarmBoardWaiter (kqueue on macOS, inotify on Linux)
// ---------------------------------------------------------------------------

struct SwarmBoardWaiter::WatcherState {
#ifdef __APPLE__
  ScopedFd kq_fd;
  ScopedFd dir_fd;
  ScopedFd board_fd;
  bool dir_watched = false;
  bool board_watched = false;

  Result<void> init() noexcept {
    const int kq = ::kqueue();
    if (kq < 0)
      return Result<void>::failure(native_error(errno));
    kq_fd.reset(kq);
    if (::fcntl(kq_fd.get(), F_SETFD, FD_CLOEXEC) != 0)
      return Result<void>::failure(native_error(errno));

    struct kevent user_ev{};
    user_ev.ident = kWakeEventIdent;
    user_ev.filter = EVFILT_USER;
    user_ev.flags = EV_ADD | EV_CLEAR;
    user_ev.fflags = 0;
    user_ev.data = 0;
    user_ev.udata = nullptr;
    if (::kevent(kq_fd.get(), &user_ev, 1, nullptr, 0, nullptr) != 0)
      return Result<void>::failure(native_error(errno));
    return Result<void>::success();
  }

  void close_board_watch() noexcept {
    board_fd.reset();
    board_watched = false;
  }

  void close_dir_watch() noexcept {
    dir_fd.reset();
    dir_watched = false;
  }

  // Arms the OS watcher BEFORE reading board.jsonl so writes occurring during
  // or after the read latch an edge in kqueue and are never slept through.
  bool arm(const std::filesystem::path &board_root) noexcept {
    if (!board_fd) {
      const std::filesystem::path board_path = board_root / kBoardFileName;
      int fd = -1;
      do {
        fd = ::open(board_path.c_str(), O_EVTONLY | O_NOFOLLOW | O_CLOEXEC);
      } while (fd < 0 && errno == EINTR);
      if (fd >= 0) {
        board_fd.reset(fd);
        board_watched = false;
      }
    }

    if (board_fd && !board_watched) {
      struct kevent ev{};
      ev.ident = static_cast<std::uintptr_t>(board_fd.get());
      ev.filter = EVFILT_VNODE;
      ev.flags = EV_ADD | EV_CLEAR;
      ev.fflags = NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_DELETE | NOTE_RENAME |
                  NOTE_REVOKE;
      ev.data = 0;
      ev.udata = nullptr;
      if (::kevent(kq_fd.get(), &ev, 1, nullptr, 0, nullptr) == 0) {
        board_watched = true;
        // Once board.jsonl is watched directly, stop watching the directory so
        // unrelated roster.json / lock updates do not wake the waiter.
        close_dir_watch();
      } else {
        close_board_watch();
      }
    }

    if (board_watched)
      return true;

    if (!dir_fd) {
      int fd = -1;
      do {
        fd = ::open(board_root.c_str(),
                    O_EVTONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      } while (fd < 0 && errno == EINTR);
      if (fd >= 0) {
        dir_fd.reset(fd);
        dir_watched = false;
      }
    }

    if (dir_fd && !dir_watched) {
      struct kevent ev{};
      ev.ident = static_cast<std::uintptr_t>(dir_fd.get());
      ev.filter = EVFILT_VNODE;
      ev.flags = EV_ADD | EV_CLEAR;
      ev.fflags = NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK | NOTE_DELETE |
                  NOTE_RENAME | NOTE_REVOKE;
      ev.data = 0;
      ev.udata = nullptr;
      if (::kevent(kq_fd.get(), &ev, 1, nullptr, 0, nullptr) == 0) {
        dir_watched = true;
      } else {
        close_dir_watch();
      }
    }

    return dir_watched;
  }

  Result<void> wait_once(std::optional<std::chrono::nanoseconds> timeout) noexcept {
    struct timespec ts{};
    const struct timespec *ts_ptr = nullptr;
    if (timeout.has_value()) {
      const auto clamped =
          timeout.value().count() < 0 ? std::chrono::nanoseconds{0} : timeout.value();
      const auto secs = std::chrono::duration_cast<std::chrono::seconds>(clamped);
      const auto nsecs = clamped - secs;
      ts.tv_sec = static_cast<time_t>(secs.count());
      ts.tv_nsec = static_cast<long>(nsecs.count());
      ts_ptr = &ts;
    }

    std::array<struct kevent, 8> events{};
    const int rc = ::kevent(kq_fd.get(), nullptr, 0, events.data(),
                            static_cast<int>(events.size()), ts_ptr);
    if (rc < 0) {
      if (errno == EINTR)
        return Result<void>::success();
      return Result<void>::failure(native_error(errno));
    }

    for (int i = 0; i < rc; ++i) {
      const auto &ev = events[static_cast<std::size_t>(i)];
      if (ev.filter == EVFILT_VNODE &&
          (ev.fflags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE)) != 0U) {
        if (board_fd && ev.ident == static_cast<std::uintptr_t>(board_fd.get()))
          close_board_watch();
        if (dir_fd && ev.ident == static_cast<std::uintptr_t>(dir_fd.get()))
          close_dir_watch();
      }
    }
    return Result<void>::success();
  }

  void wake() noexcept {
    if (!kq_fd)
      return;
    struct kevent trigger{};
    trigger.ident = kWakeEventIdent;
    trigger.filter = EVFILT_USER;
    trigger.flags = 0;
    trigger.fflags = NOTE_TRIGGER;
    trigger.data = 0;
    trigger.udata = nullptr;
    (void)::kevent(kq_fd.get(), &trigger, 1, nullptr, 0, nullptr);
  }
#elif defined(__linux__)
  ScopedFd inotify_fd;
  ScopedFd wake_read_fd;
  ScopedFd wake_write_fd;
  int watch_desc = -1;

  Result<void> init() noexcept {
    const int ifd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0)
      return Result<void>::failure(native_error(errno));
    inotify_fd.reset(ifd);

    int pipe_fds[2]{-1, -1};
    if (::pipe2(pipe_fds, O_NONBLOCK | O_CLOEXEC) != 0)
      return Result<void>::failure(native_error(errno));
    wake_read_fd.reset(pipe_fds[0]);
    wake_write_fd.reset(pipe_fds[1]);
    return Result<void>::success();
  }

  bool arm(const std::filesystem::path &board_root) noexcept {
    if (watch_desc >= 0)
      return true;
    const int wd =
        ::inotify_add_watch(inotify_fd.get(), board_root.c_str(),
                            IN_MODIFY | IN_MOVED_TO | IN_CREATE | IN_CLOSE_WRITE |
                                IN_DELETE_SELF | IN_MOVE_SELF);
    if (wd < 0)
      return false;
    watch_desc = wd;
    return true;
  }

  void drain_inotify() noexcept {
    alignas(struct inotify_event) std::array<char, 4096> buf{};
    for (;;) {
      const ssize_t n = ::read(inotify_fd.get(), buf.data(), buf.size());
      if (n <= 0)
        break;
      std::size_t offset = 0;
      const auto total = static_cast<std::size_t>(n);
      while (offset + sizeof(struct inotify_event) <= total) {
        struct inotify_event ev{};
        std::memcpy(&ev, buf.data() + offset, sizeof(ev));
        if ((ev.mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED)) != 0U)
          watch_desc = -1;
        offset += sizeof(struct inotify_event) + static_cast<std::size_t>(ev.len);
      }
    }
  }

  void drain_wake_pipe() noexcept {
    std::array<char, 64> drain{};
    while (::read(wake_read_fd.get(), drain.data(), drain.size()) > 0) {
    }
  }

  Result<void> wait_once(std::optional<std::chrono::nanoseconds> timeout) noexcept {
    int poll_ms = -1;
    if (timeout.has_value()) {
      const auto clamped =
          timeout.value().count() < 0 ? std::chrono::nanoseconds{0} : timeout.value();
      const auto ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(clamped).count();
      if (ms > std::numeric_limits<int>::max()) {
        poll_ms = std::numeric_limits<int>::max();
      } else if (ms == 0 && clamped.count() > 0) {
        poll_ms = 1;
      } else {
        poll_ms = static_cast<int>(ms);
      }
    }

    std::array<struct pollfd, 2> pfds{};
    pfds[0].fd = inotify_fd.get();
    pfds[0].events = POLLIN;
    pfds[1].fd = wake_read_fd.get();
    pfds[1].events = POLLIN;

    const int rc = ::poll(pfds.data(), static_cast<nfds_t>(pfds.size()), poll_ms);
    if (rc < 0) {
      if (errno == EINTR)
        return Result<void>::success();
      return Result<void>::failure(native_error(errno));
    }
    if ((pfds[0].revents & POLLIN) != 0)
      drain_inotify();
    if ((pfds[1].revents & POLLIN) != 0)
      drain_wake_pipe();
    return Result<void>::success();
  }

  void wake() noexcept {
    if (!wake_write_fd)
      return;
    const char byte = 1;
    (void)::write(wake_write_fd.get(), &byte, 1);
  }
#else
  std::atomic_bool wake_flag{false};

  Result<void> init() noexcept { return Result<void>::success(); }
  bool arm(const std::filesystem::path &) noexcept { return false; }

  Result<void> wait_once(std::optional<std::chrono::nanoseconds> timeout) noexcept {
    if (wake_flag.exchange(false, std::memory_order_acq_rel))
      return Result<void>::success();
    const auto slice =
        timeout.has_value()
            ? std::min(timeout.value(),
                       std::chrono::nanoseconds{
                           std::chrono::milliseconds{kMissingDirPollMs}})
            : std::chrono::nanoseconds{std::chrono::milliseconds{kMissingDirPollMs}};
    if (slice.count() > 0)
      std::this_thread::sleep_for(slice);
    return Result<void>::success();
  }

  void wake() noexcept { wake_flag.store(true, std::memory_order_release); }
#endif
};

SwarmBoardWaiter::SwarmBoardWaiter(std::filesystem::path board_root,
                                   std::unique_ptr<WatcherState> state) noexcept
    : board_root_(std::move(board_root)), state_(std::move(state)) {}

SwarmBoardWaiter::SwarmBoardWaiter(SwarmBoardWaiter &&other) noexcept = default;
SwarmBoardWaiter &
SwarmBoardWaiter::operator=(SwarmBoardWaiter &&other) noexcept = default;
SwarmBoardWaiter::~SwarmBoardWaiter() = default;

Result<SwarmBoardWaiter>
SwarmBoardWaiter::open(const std::filesystem::path &board_root) {
  if (board_root.empty())
    return Result<SwarmBoardWaiter>::failure({ErrorCode::invalid_range});
  const std::string raw = board_root.string();
  if (raw.find('\0') != std::string::npos)
    return Result<SwarmBoardWaiter>::failure({ErrorCode::invalid_range});
  try {
    auto state = std::make_unique<WatcherState>();
    auto init_res = state->init();
    if (!init_res.has_value())
      return Result<SwarmBoardWaiter>::failure(init_res.error());
    return Result<SwarmBoardWaiter>::success(
        SwarmBoardWaiter{board_root, std::move(state)});
  } catch (const std::bad_alloc &) {
    return Result<SwarmBoardWaiter>::failure({ErrorCode::allocation});
  }
}

void SwarmBoardWaiter::wake() noexcept {
  if (state_)
    state_->wake();
}

Result<SwarmBoardWaitResult>
SwarmBoardWaiter::wait(const SwarmBoardWaitOptions &options) {
  auto board = PlatoonBoard::open(board_root_);
  if (!board.has_value())
    return Result<SwarmBoardWaitResult>::failure(board.error());
  return wait(board.value(), options);
}

Result<SwarmBoardWaitResult>
SwarmBoardWaiter::wait(const PlatoonBoard &board,
                       const SwarmBoardWaitOptions &options) {
  if (!state_)
    return Result<SwarmBoardWaitResult>::failure({ErrorCode::stale_handle});
  if (board.root() != board_root_)
    return Result<SwarmBoardWaitResult>::failure({ErrorCode::wrong_environment});
  if (options.max_messages == 0)
    return Result<SwarmBoardWaitResult>::failure({ErrorCode::invalid_range});
  if (options.mentions_only && options.agent_name.empty())
    return Result<SwarmBoardWaitResult>::failure({ErrorCode::invalid_identity});
  if (!options.agent_name.empty() && !valid_platoon_member_id(options.agent_name))
    return Result<SwarmBoardWaitResult>::failure({ErrorCode::invalid_identity});

  const bool has_deadline = options.timeout_ms > 0;
  const std::int64_t clamped_timeout_ms =
      has_deadline ? std::min(options.timeout_ms, kMaxBoundedWaitTimeoutMs) : 0;
  const auto deadline =
      has_deadline ? SteadyClock::now() + std::chrono::milliseconds{clamped_timeout_ms}
                   : SteadyClock::time_point{};

  std::uint64_t last_seen_seq = options.since_seq;

  for (;;) {
    if (options.cancel != nullptr && options.cancel->load(std::memory_order_acquire)) {
      return Result<SwarmBoardWaitResult>::success(
          SwarmBoardWaitResult{false, false, true, last_seen_seq, {}});
    }

    // Arm OS watcher BEFORE reading board.jsonl so concurrent writes cannot be
    // missed between read_since() and kevent()/poll().
    const bool watched = state_->arm(board.root());

    auto scanned = scan_unread_for_wake(board, options);
    if (!scanned.has_value())
      return Result<SwarmBoardWaitResult>::failure(scanned.error());

    last_seen_seq = scanned.value().latest_seq;
    if (scanned.value().triggered) {
      return Result<SwarmBoardWaitResult>::success(SwarmBoardWaitResult{
          true, false, false, last_seen_seq, std::move(scanned.value().window)});
    }

    if (options.timeout_ms == 0) {
      return Result<SwarmBoardWaitResult>::success(
          SwarmBoardWaitResult{false, true, false, last_seen_seq, {}});
    }

    std::optional<std::chrono::nanoseconds> wait_slice;
    if (has_deadline) {
      const auto now = SteadyClock::now();
      if (now >= deadline) {
        return Result<SwarmBoardWaitResult>::success(
            SwarmBoardWaitResult{false, true, false, last_seen_seq, {}});
      }
      wait_slice = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now);
    }

    if (options.cancel != nullptr) {
      const auto cancel_cap =
          std::chrono::nanoseconds{std::chrono::milliseconds{kCancelSliceMs}};
      wait_slice =
          wait_slice.has_value() ? std::min(*wait_slice, cancel_cap) : cancel_cap;
    }

    if (!watched) {
      const auto fallback_cap =
          std::chrono::nanoseconds{std::chrono::milliseconds{kMissingDirPollMs}};
      wait_slice =
          wait_slice.has_value() ? std::min(*wait_slice, fallback_cap) : fallback_cap;
    }

    if (options.cancel != nullptr && options.cancel->load(std::memory_order_acquire)) {
      return Result<SwarmBoardWaitResult>::success(
          SwarmBoardWaitResult{false, false, true, last_seen_seq, {}});
    }

    auto waited = state_->wait_once(wait_slice);
    if (!waited.has_value())
      return Result<SwarmBoardWaitResult>::failure(waited.error());
  }
}

Result<SwarmBoardWaitResult>
wait_for_board_mention(const PlatoonBoard &board,
                       const SwarmBoardWaitOptions &options) {
  auto waiter = SwarmBoardWaiter::open(board.root());
  if (!waiter.has_value())
    return Result<SwarmBoardWaitResult>::failure(waiter.error());
  return waiter.value().wait(board, options);
}

// ---------------------------------------------------------------------------
// LocalSwarmCoordinator
// ---------------------------------------------------------------------------

LocalSwarmCoordinator::LocalSwarmCoordinator(
    LocalSwarmConfig config, PlatoonBoard board,
    std::optional<WorktreeLeaseManager> worktree_manager, int dir_fd) noexcept
    : config_(std::move(config)), board_(std::move(board)),
      worktree_manager_(std::move(worktree_manager)), dir_fd_(dir_fd) {}

LocalSwarmCoordinator::LocalSwarmCoordinator(LocalSwarmCoordinator &&other) noexcept
    : config_(std::move(other.config_)), board_(std::move(other.board_)),
      worktree_manager_(std::move(other.worktree_manager_)),
      dir_fd_(std::exchange(other.dir_fd_, -1)),
      session_counter_(other.session_counter_), workers_(std::move(other.workers_)) {}

LocalSwarmCoordinator &
LocalSwarmCoordinator::operator=(LocalSwarmCoordinator &&other) noexcept {
  if (this != &other) {
    if (dir_fd_ >= 0)
      (void)::close(dir_fd_);
    config_ = std::move(other.config_);
    board_ = std::move(other.board_);
    worktree_manager_ = std::move(other.worktree_manager_);
    dir_fd_ = std::exchange(other.dir_fd_, -1);
    session_counter_ = other.session_counter_;
    workers_ = std::move(other.workers_);
  }
  return *this;
}

LocalSwarmCoordinator::~LocalSwarmCoordinator() {
  if (dir_fd_ >= 0)
    (void)::close(dir_fd_);
}

Result<LocalSwarmCoordinator> LocalSwarmCoordinator::open(LocalSwarmConfig config) {
  if (!valid_platoon_member_id(config.coordinator_name))
    return Result<LocalSwarmCoordinator>::failure({ErrorCode::invalid_identity});
  if (config.max_workers == 0 || config.max_workers > kPlatoonMaxRosterMembers)
    return Result<LocalSwarmCoordinator>::failure({ErrorCode::invalid_range});
  auto title_ok =
      validate_text(config.swarm_title, kPlatoonMaxFieldBytes, EmptyPolicy::allow);
  if (!title_ok.has_value())
    return Result<LocalSwarmCoordinator>::failure(title_ok.error());

  auto board = PlatoonBoard::open(config.board_root);
  if (!board.has_value())
    return Result<LocalSwarmCoordinator>::failure(board.error());

  std::optional<WorktreeLeaseManager> worktree_manager;
  if (config.worktree_config.has_value()) {
    auto wt = WorktreeLeaseManager::open(*config.worktree_config);
    if (!wt.has_value())
      return Result<LocalSwarmCoordinator>::failure(wt.error());
    worktree_manager.emplace(std::move(wt).value());
  }

  int raw_dir_fd = -1;
  do {
    raw_dir_fd = ::open(board.value().root().c_str(),
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (raw_dir_fd < 0 && errno == EINTR);
  if (raw_dir_fd < 0)
    return Result<LocalSwarmCoordinator>::failure(native_error(errno));
  ScopedFd owned_dir{raw_dir_fd};
  auto dir_checked = check_restricted(owned_dir.get(), PathKind::directory);
  if (!dir_checked.has_value())
    return Result<LocalSwarmCoordinator>::failure(dir_checked.error());

  LocalSwarmCoordinator coordinator{std::move(config), std::move(board).value(),
                                    std::move(worktree_manager), owned_dir.release()};
  auto loaded = coordinator.load_state_locked();
  if (!loaded.has_value())
    return Result<LocalSwarmCoordinator>::failure(loaded.error());
  return Result<LocalSwarmCoordinator>::success(std::move(coordinator));
}

std::string LocalSwarmCoordinator::title() const {
  std::lock_guard<std::mutex> guard{mutex_};
  return config_.swarm_title;
}

Result<void> LocalSwarmCoordinator::set_title(std::string title) {
  auto ok = validate_text(title, kPlatoonMaxFieldBytes, EmptyPolicy::allow);
  if (!ok.has_value())
    return ok;
  std::lock_guard<std::mutex> guard{mutex_};
  if (dir_fd_ < 0)
    return Result<void>::failure({ErrorCode::stale_handle});
  std::string previous = std::move(config_.swarm_title);
  config_.swarm_title = std::move(title);
  auto saved = persist_state_locked();
  if (!saved.has_value()) {
    config_.swarm_title = std::move(previous);
    return saved;
  }
  return Result<void>::success();
}

Result<SwarmWorkerRecord>
LocalSwarmCoordinator::add_worker(const SwarmWorkerSpec &spec) {
  std::lock_guard<std::mutex> guard{mutex_};
  return add_worker_locked(spec, SwarmWorkerState::working);
}

Result<std::vector<SwarmWorkerRecord>> LocalSwarmCoordinator::add_sharded_group(
    std::string_view base_name, const std::vector<std::string> &tasks,
    std::string_view shared_brief, const SwarmWorkerSpec &spec_template,
    std::size_t max_concurrency) {
  if (tasks.empty())
    return Result<std::vector<SwarmWorkerRecord>>::failure({ErrorCode::invalid_range});
  if (tasks.size() > kSwarmMaxShardedTasks)
    return Result<std::vector<SwarmWorkerRecord>>::failure({ErrorCode::capacity});
  if (max_concurrency == 0 || max_concurrency > kSwarmMaxShardedTasks)
    return Result<std::vector<SwarmWorkerRecord>>::failure({ErrorCode::invalid_range});

  auto brief_ok =
      validate_text(shared_brief, kPlatoonMaxBriefBytes, EmptyPolicy::allow);
  if (!brief_ok.has_value())
    return Result<std::vector<SwarmWorkerRecord>>::failure(brief_ok.error());

  if (!spec_template.owned_files.empty() && tasks.size() > 1U)
    return Result<std::vector<SwarmWorkerRecord>>::failure({ErrorCode::conflict});

  std::lock_guard<std::mutex> guard{mutex_};
  if (dir_fd_ < 0)
    return Result<std::vector<SwarmWorkerRecord>>::failure({ErrorCode::stale_handle});
  if (workers_.size() + tasks.size() > config_.max_workers)
    return Result<std::vector<SwarmWorkerRecord>>::failure({ErrorCode::capacity});

  // Pre-validate template fields and every sharded worker spec before mutating state.
  if (swarm_workspace_mode_name(spec_template.workspace_mode).empty())
    return Result<std::vector<SwarmWorkerRecord>>::failure({ErrorCode::invalid_range});
  if (spec_template.read_only && !spec_template.owned_files.empty())
    return Result<std::vector<SwarmWorkerRecord>>::failure({ErrorCode::invalid_range});
  for (const std::string_view field :
       {std::string_view{spec_template.role}, std::string_view{spec_template.provider},
        std::string_view{spec_template.model},
        std::string_view{spec_template.base_ref}}) {
    auto ok = validate_text(field, kPlatoonMaxFieldBytes, EmptyPolicy::allow);
    if (!ok.has_value())
      return Result<std::vector<SwarmWorkerRecord>>::failure(ok.error());
  }
  if (spec_template.fork_from_session_dir.has_value()) {
    const std::string fork_str = spec_template.fork_from_session_dir->string();
    auto fork_ok = validate_text(fork_str, kPlatoonMaxFieldBytes, EmptyPolicy::forbid);
    if (!fork_ok.has_value())
      return Result<std::vector<SwarmWorkerRecord>>::failure(fork_ok.error());
  }

  std::vector<SwarmWorkerSpec> planned;
  planned.reserve(tasks.size());
  for (std::size_t i = 0; i < tasks.size(); ++i) {
    auto task_ok = validate_text(tasks[i], kPlatoonMaxFieldBytes, EmptyPolicy::forbid);
    if (!task_ok.has_value())
      return Result<std::vector<SwarmWorkerRecord>>::failure(task_ok.error());

    const std::string worker_name =
        std::string{base_name} + "-" + std::to_string(i + 1U);
    if (!valid_swarm_worker_name(worker_name)) {
      return Result<std::vector<SwarmWorkerRecord>>::failure(
          {ErrorCode::invalid_identity});
    }
    const auto dup = std::find_if(
        workers_.begin(), workers_.end(),
        [&](const SwarmWorkerRecord &entry) { return entry.name == worker_name; });
    if (dup != workers_.end())
      return Result<std::vector<SwarmWorkerRecord>>::failure({ErrorCode::conflict});

    SwarmWorkerSpec slice_spec = spec_template;
    slice_spec.name = worker_name;
    slice_spec.session_id.clear();
    slice_spec.brief = format_slice_brief(
        SliceBriefInput{i + 1U, tasks.size(), tasks[i], shared_brief});
    auto combined_ok =
        validate_text(slice_spec.brief, kPlatoonMaxBriefBytes, EmptyPolicy::forbid);
    if (!combined_ok.has_value())
      return Result<std::vector<SwarmWorkerRecord>>::failure(combined_ok.error());
    const std::string directed =
        format_directed_brief(BriefFormatInput{slice_spec.name, slice_spec.brief});
    if (directed.size() > kPlatoonMaxMessageBytes)
      return Result<std::vector<SwarmWorkerRecord>>::failure({ErrorCode::capacity});
    planned.push_back(std::move(slice_spec));
  }

  const std::uint64_t previous_counter = session_counter_;
  const std::vector<SwarmWorkerRecord> previous_workers = workers_;

  std::vector<SwarmWorkerRecord> spawned;
  spawned.reserve(planned.size());
  for (std::size_t i = 0; i < planned.size(); ++i) {
    const SwarmWorkerState initial_state =
        i < max_concurrency ? SwarmWorkerState::working : SwarmWorkerState::waiting;
    auto created = add_worker_locked(planned[i], initial_state);
    if (!created.has_value()) {
      for (const auto &prior : spawned) {
        if (worktree_manager_.has_value() && !prior.lease_id.empty())
          (void)worktree_manager_->release(prior.lease_id, true);
      }
      workers_ = previous_workers;
      session_counter_ = previous_counter;
      (void)persist_state_locked();
      return Result<std::vector<SwarmWorkerRecord>>::failure(created.error());
    }
    spawned.push_back(std::move(created).value());
  }
  return Result<std::vector<SwarmWorkerRecord>>::success(std::move(spawned));
}

Result<SwarmWorkerRecord>
LocalSwarmCoordinator::add_dentist_verifier(std::string_view name,
                                            const std::vector<std::string> &repo_checks,
                                            const SwarmDentistOptions &options) {
  for (const auto &check_item : repo_checks) {
    auto ok = validate_text(check_item, kPlatoonMaxFieldBytes, EmptyPolicy::forbid);
    if (!ok.has_value())
      return Result<SwarmWorkerRecord>::failure(ok.error());
  }

  SwarmWorkerSpec spec;
  spec.name = std::string{name};
  spec.role = "dentist";
  spec.provider = options.provider;
  spec.model = options.model;
  spec.workspace_mode = SwarmWorkspaceMode::inherit;
  spec.owned_files.clear();
  spec.brief = build_dentist_brief(repo_checks);
  spec.fork_from_session_dir = options.fork_from_session_dir;
  spec.read_only = true;

  std::lock_guard<std::mutex> guard{mutex_};
  return add_worker_locked(spec, SwarmWorkerState::working);
}

Result<SwarmWorkerRecord>
LocalSwarmCoordinator::switch_worker_model(const SwarmModelSwitchRequest &request) {
  if (!valid_swarm_worker_name(request.worker_name))
    return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_identity});
  auto prov_ok =
      validate_text(request.new_provider, kPlatoonMaxFieldBytes, EmptyPolicy::allow);
  if (!prov_ok.has_value())
    return Result<SwarmWorkerRecord>::failure(prov_ok.error());
  auto model_ok =
      validate_text(request.new_model, kPlatoonMaxFieldBytes, EmptyPolicy::forbid);
  if (!model_ok.has_value())
    return Result<SwarmWorkerRecord>::failure(model_ok.error());
  auto reason_ok =
      validate_text(request.reason, kPlatoonMaxFieldBytes, EmptyPolicy::allow);
  if (!reason_ok.has_value())
    return Result<SwarmWorkerRecord>::failure(reason_ok.error());

  std::lock_guard<std::mutex> guard{mutex_};
  if (dir_fd_ < 0)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::stale_handle});

  auto it = std::find_if(workers_.begin(), workers_.end(),
                         [&](const SwarmWorkerRecord &entry) {
                           return entry.name == request.worker_name;
                         });
  if (it == workers_.end())
    return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_identity});
  if (it->state != SwarmWorkerState::waiting)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::conflict});

  SwarmWorkerRecord updated = *it;
  const std::string old_provider = updated.provider;
  const std::string old_model = updated.model;
  updated.provider = request.new_provider;
  updated.model = request.new_model;
  updated.updated_ns = wall_now_ns();

  const std::string handoff_text = format_model_handoff_text(ModelHandoffTextInput{
      updated.name,
      old_provider,
      old_model,
      updated.provider,
      updated.model,
      updated.session_id,
      request.reason,
  });
  if (handoff_text.size() > kPlatoonMaxMessageBytes)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::capacity});

  auto synced = sync_platoon_member_locked(updated);
  if (!synced.has_value())
    return Result<SwarmWorkerRecord>::failure(synced.error());

  auto posted = board_.post(PlatoonPost{
      config_.coordinator_name,
      updated.name,
      PlatoonMessageKind::handoff,
      handoff_text,
      {},
  });
  if (!posted.has_value())
    return Result<SwarmWorkerRecord>::failure(posted.error());

  SwarmWorkerRecord previous = *it;
  *it = updated;
  auto saved = persist_state_locked();
  if (!saved.has_value()) {
    *it = std::move(previous);
    return Result<SwarmWorkerRecord>::failure(saved.error());
  }
  return Result<SwarmWorkerRecord>::success(std::move(updated));
}

Result<SwarmWorkerRecord>
LocalSwarmCoordinator::set_worker_state(std::string_view name,
                                        SwarmWorkerState new_state) {
  if (!valid_swarm_worker_name(name))
    return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_identity});
  if (swarm_worker_state_name(new_state).empty())
    return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_range});

  std::lock_guard<std::mutex> guard{mutex_};
  if (dir_fd_ < 0)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::stale_handle});

  if (new_state == SwarmWorkerState::killed)
    return kill_worker_locked(name);

  auto it =
      std::find_if(workers_.begin(), workers_.end(),
                   [&](const SwarmWorkerRecord &entry) { return entry.name == name; });
  if (it == workers_.end())
    return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_identity});
  if (it->state == SwarmWorkerState::killed)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::conflict});

  SwarmWorkerRecord updated = *it;
  updated.state = new_state;
  updated.updated_ns = wall_now_ns();
  auto synced = sync_platoon_member_locked(updated);
  if (!synced.has_value())
    return Result<SwarmWorkerRecord>::failure(synced.error());

  SwarmWorkerRecord previous = *it;
  *it = updated;
  auto saved = persist_state_locked();
  if (!saved.has_value()) {
    *it = std::move(previous);
    return Result<SwarmWorkerRecord>::failure(saved.error());
  }
  return Result<SwarmWorkerRecord>::success(std::move(updated));
}

Result<SwarmWorkerRecord> LocalSwarmCoordinator::kill_worker(std::string_view name) {
  if (!valid_swarm_worker_name(name))
    return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_identity});
  std::lock_guard<std::mutex> guard{mutex_};
  return kill_worker_locked(name);
}

std::vector<SwarmWorkerRecord> LocalSwarmCoordinator::status() const {
  std::lock_guard<std::mutex> guard{mutex_};
  return workers_;
}

Result<std::optional<SwarmWorkerRecord>>
LocalSwarmCoordinator::worker(std::string_view name) const {
  if (!valid_swarm_worker_name(name))
    return Result<std::optional<SwarmWorkerRecord>>::failure(
        {ErrorCode::invalid_identity});
  std::lock_guard<std::mutex> guard{mutex_};
  auto it =
      std::find_if(workers_.begin(), workers_.end(),
                   [&](const SwarmWorkerRecord &entry) { return entry.name == name; });
  if (it == workers_.end())
    return Result<std::optional<SwarmWorkerRecord>>::success(std::nullopt);
  return Result<std::optional<SwarmWorkerRecord>>::success(*it);
}

Result<SwarmScopeCheckResult> LocalSwarmCoordinator::verify_owned_files_scope(
    std::string_view worker_name,
    const std::vector<std::string> &modified_paths) const {
  if (!valid_swarm_worker_name(worker_name))
    return Result<SwarmScopeCheckResult>::failure({ErrorCode::invalid_identity});

  std::lock_guard<std::mutex> guard{mutex_};
  auto it = std::find_if(
      workers_.begin(), workers_.end(),
      [&](const SwarmWorkerRecord &entry) { return entry.name == worker_name; });
  if (it == workers_.end())
    return Result<SwarmScopeCheckResult>::failure({ErrorCode::invalid_identity});

  SwarmScopeCheckResult result;
  result.verified_paths.reserve(modified_paths.size());
  for (const auto &raw_path : modified_paths) {
    auto normalized = normalize_relative_repo_path(raw_path);
    if (!normalized.ok) {
      result.violations.push_back(
          SwarmScopeViolation{raw_path, std::move(normalized.error_reason)});
      continue;
    }

    bool allowed = false;
    for (const auto &owned : it->owned_files) {
      if (path_covers_candidate(PathPair{owned, normalized.normalized})) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      result.violations.push_back(SwarmScopeViolation{
          raw_path, it->read_only ? "read-only worker has no owned files"
                                  : "path is outside worker owned_files"});
      continue;
    }
    result.verified_paths.push_back(std::move(normalized.normalized));
  }
  result.ok = result.violations.empty();
  return Result<SwarmScopeCheckResult>::success(std::move(result));
}

Result<SwarmBoardWaitResult>
LocalSwarmCoordinator::wait_for_mention(const SwarmBoardWaitOptions &options) const {
  return wait_for_board_mention(board_, options);
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

Result<SwarmWorkerRecord>
LocalSwarmCoordinator::add_worker_locked(const SwarmWorkerSpec &spec,
                                         SwarmWorkerState initial_state) {
  if (dir_fd_ < 0)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::stale_handle});
  if (!valid_swarm_worker_name(spec.name))
    return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_identity});
  if (swarm_workspace_mode_name(spec.workspace_mode).empty())
    return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_range});
  if (workers_.size() >= config_.max_workers)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::capacity});

  for (const auto &existing : workers_) {
    if (existing.name == spec.name)
      return Result<SwarmWorkerRecord>::failure({ErrorCode::conflict});
  }

  for (const std::string_view field :
       {std::string_view{spec.role}, std::string_view{spec.provider},
        std::string_view{spec.model}, std::string_view{spec.session_id},
        std::string_view{spec.base_ref}}) {
    auto ok = validate_text(field, kPlatoonMaxFieldBytes, EmptyPolicy::allow);
    if (!ok.has_value())
      return Result<SwarmWorkerRecord>::failure(ok.error());
  }
  auto brief_ok = validate_text(spec.brief, kPlatoonMaxBriefBytes, EmptyPolicy::forbid);
  if (!brief_ok.has_value())
    return Result<SwarmWorkerRecord>::failure(brief_ok.error());
  const std::string directed_brief =
      format_directed_brief(BriefFormatInput{spec.name, spec.brief});
  if (directed_brief.size() > kPlatoonMaxMessageBytes)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::capacity});
  if (spec.session_id.empty() &&
      session_counter_ == std::numeric_limits<std::uint64_t>::max()) {
    return Result<SwarmWorkerRecord>::failure({ErrorCode::overflow});
  }

  if (spec.fork_from_session_dir.has_value()) {
    const std::string fork_str = spec.fork_from_session_dir->string();
    auto fork_ok = validate_text(fork_str, kPlatoonMaxFieldBytes, EmptyPolicy::forbid);
    if (!fork_ok.has_value())
      return Result<SwarmWorkerRecord>::failure(fork_ok.error());
  }

  if (spec.read_only && !spec.owned_files.empty())
    return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_range});
  if (spec.owned_files.size() > kSwarmMaxOwnedFilesPerWorker)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::capacity});

  std::vector<std::string> normalized_owned;
  normalized_owned.reserve(spec.owned_files.size());
  for (const auto &raw_path : spec.owned_files) {
    auto norm = normalize_relative_repo_path(raw_path);
    if (!norm.ok)
      return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_range});
    normalized_owned.push_back(std::move(norm.normalized));
  }
  std::sort(normalized_owned.begin(), normalized_owned.end());
  normalized_owned.erase(std::unique(normalized_owned.begin(), normalized_owned.end()),
                         normalized_owned.end());

  // Enforce disjoint owned_files across all active non-killed workers.
  for (const auto &existing : workers_) {
    if (existing.state == SwarmWorkerState::killed)
      continue;
    for (const auto &existing_path : existing.owned_files) {
      for (const auto &candidate_path : normalized_owned) {
        if (paths_overlap(PathPair{existing_path, candidate_path}))
          return Result<SwarmWorkerRecord>::failure({ErrorCode::conflict});
      }
    }
  }

  std::filesystem::path workspace_path;
  std::string lease_id;
  std::string branch;
  bool acquired_lease = false;

  if (spec.workspace_mode == SwarmWorkspaceMode::inherit) {
    if (worktree_manager_.has_value())
      workspace_path = worktree_manager_->repo_root();
  } else if (worktree_manager_.has_value()) {
    WorktreeLeaseRequest req;
    req.lease_id = "swarm-" + spec.name;
    req.branch = "swarm/" + spec.name;
    req.base_ref = spec.base_ref.empty() ? "HEAD" : spec.base_ref;
    req.owner_id = spec.name;
    req.owner_pid = static_cast<std::int64_t>(::getpid());
    auto lease = worktree_manager_->acquire(req);
    if (!lease.has_value())
      return Result<SwarmWorkerRecord>::failure(lease.error());
    workspace_path = lease.value().path;
    lease_id = lease.value().lease_id;
    branch = lease.value().branch;
    acquired_lease = true;
  }

  auto rollback_lease = [&]() noexcept {
    if (acquired_lease && worktree_manager_.has_value() && !lease_id.empty())
      (void)worktree_manager_->release(lease_id, true);
  };

  const std::int64_t now_ns = wall_now_ns();
  std::string session_id = spec.session_id;
  if (session_id.empty()) {
    session_id =
        "swarm-sess-" + spec.name + "-" + std::to_string(session_counter_ + 1U);
  }

  SwarmWorkerRecord record;
  record.name = spec.name;
  record.role = spec.role.empty() ? "builder" : spec.role;
  record.provider = spec.provider;
  record.model = spec.model;
  record.workspace_mode = spec.workspace_mode;
  record.state = initial_state;
  record.owned_files = std::move(normalized_owned);
  record.brief = spec.brief;
  record.session_id = std::move(session_id);
  record.fork_from_session_dir = spec.fork_from_session_dir;
  record.workspace_path = std::move(workspace_path);
  record.lease_id = std::move(lease_id);
  record.branch = std::move(branch);
  record.created_ns = now_ns;
  record.updated_ns = now_ns;
  record.read_only = spec.read_only;

  auto synced = sync_platoon_member_locked(record);
  if (!synced.has_value()) {
    rollback_lease();
    return Result<SwarmWorkerRecord>::failure(synced.error());
  }

  std::vector<std::string> refs;
  const std::size_t ref_count = std::min(record.owned_files.size(), kPlatoonMaxRefs);
  refs.reserve(ref_count);
  for (std::size_t i = 0; i < ref_count; ++i)
    refs.push_back(record.owned_files[i]);

  auto posted = board_.post(PlatoonPost{
      config_.coordinator_name,
      record.name,
      PlatoonMessageKind::brief,
      directed_brief,
      std::move(refs),
  });
  if (!posted.has_value()) {
    rollback_lease();
    return Result<SwarmWorkerRecord>::failure(posted.error());
  }
  record.brief_seq = posted.value().seq;

  const std::uint64_t previous_counter = session_counter_;
  std::vector<SwarmWorkerRecord> previous_workers = workers_;
  if (spec.session_id.empty())
    ++session_counter_;
  workers_.push_back(record);
  std::sort(workers_.begin(), workers_.end(),
            [](const SwarmWorkerRecord &lhs, const SwarmWorkerRecord &rhs) {
              return lhs.name < rhs.name;
            });

  auto saved = persist_state_locked();
  if (!saved.has_value()) {
    session_counter_ = previous_counter;
    workers_ = std::move(previous_workers);
    rollback_lease();
    return Result<SwarmWorkerRecord>::failure(saved.error());
  }

  return Result<SwarmWorkerRecord>::success(std::move(record));
}

Result<SwarmWorkerRecord>
LocalSwarmCoordinator::kill_worker_locked(std::string_view name) {
  if (dir_fd_ < 0)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::stale_handle});

  auto it =
      std::find_if(workers_.begin(), workers_.end(),
                   [&](const SwarmWorkerRecord &entry) { return entry.name == name; });
  if (it == workers_.end())
    return Result<SwarmWorkerRecord>::failure({ErrorCode::invalid_identity});
  if (it->state == SwarmWorkerState::killed)
    return Result<SwarmWorkerRecord>::failure({ErrorCode::conflict});

  if (worktree_manager_.has_value() && !it->lease_id.empty()) {
    auto released = worktree_manager_->release(it->lease_id, true);
    if (!released.has_value())
      return Result<SwarmWorkerRecord>::failure(released.error());
  }

  SwarmWorkerRecord updated = *it;
  updated.state = SwarmWorkerState::killed;
  updated.lease_id.clear();
  updated.updated_ns = wall_now_ns();

  auto synced = sync_platoon_member_locked(updated);
  if (!synced.has_value())
    return Result<SwarmWorkerRecord>::failure(synced.error());

  auto posted = board_.post(PlatoonPost{
      config_.coordinator_name,
      updated.name,
      PlatoonMessageKind::status,
      "@" + updated.name + " [killed] worker terminated permanently",
      {},
  });
  if (!posted.has_value())
    return Result<SwarmWorkerRecord>::failure(posted.error());

  *it = updated;
  auto saved = persist_state_locked();
  if (!saved.has_value())
    return Result<SwarmWorkerRecord>::failure(saved.error());
  return Result<SwarmWorkerRecord>::success(std::move(updated));
}

Result<void>
LocalSwarmCoordinator::sync_platoon_member_locked(const SwarmWorkerRecord &record) {
  PlatoonMember member;
  member.id = record.name;
  member.role = record.role;
  member.provider = record.provider;
  member.model = record.model;
  member.workspace = record.workspace_path.string();
  member.branch = record.branch;
  member.state = to_platoon_state(record.state);
  member.pid = static_cast<std::int64_t>(::getpid());
  member.updated_ns = record.updated_ns;
  member.brief = record.brief;
  auto upserted = board_.upsert_member(member);
  if (!upserted.has_value())
    return Result<void>::failure(upserted.error());
  return Result<void>::success();
}

Result<void> LocalSwarmCoordinator::persist_state_locked() const {
  if (dir_fd_ < 0)
    return Result<void>::failure({ErrorCode::stale_handle});
  try {
    auto lock = ScopedFlock::acquire(dir_fd_, kSwarmStateLockFile,
                                     ScopedFlock::Mode::exclusive);
    if (!lock.has_value())
      return Result<void>::failure(lock.error());

    Value::Array encoded;
    encoded.reserve(workers_.size());
    for (const auto &entry : workers_)
      encoded.push_back(worker_to_value(entry));

    const Value document = Value::object({
        {"version", Value{Number{kSwarmStateSchemaVersion}}},
        {"title", Value{config_.swarm_title}},
        {"session_counter", Value{Number{session_counter_}}},
        {"workers", Value{std::move(encoded)}},
    });
    auto json = dump_json(document);
    if (!json.has_value())
      return Result<void>::failure(json.error());
    std::string payload = std::move(json).value();
    payload.push_back('\n');
    return write_file_atomic_locked(dir_fd_, kSwarmStateFile, payload);
  } catch (const std::bad_alloc &) {
    return Result<void>::failure({ErrorCode::allocation});
  }
}

Result<void> LocalSwarmCoordinator::load_state_locked() {
  if (dir_fd_ < 0)
    return Result<void>::failure({ErrorCode::stale_handle});
  try {
    auto lock =
        ScopedFlock::acquire(dir_fd_, kSwarmStateLockFile, ScopedFlock::Mode::shared);
    if (!lock.has_value())
      return Result<void>::failure(lock.error());

    bool exists = false;
    auto raw = read_regular_file_bounded(dir_fd_, kSwarmStateFile, kMaxSwarmStateBytes,
                                         exists);
    if (!raw.has_value())
      return Result<void>::failure(raw.error());
    if (!exists)
      return Result<void>::success();
    if (raw.value().empty())
      return Result<void>::failure({ErrorCode::corrupt});

    auto parsed = parse_json(raw.value());
    if (!parsed.has_value())
      return Result<void>::failure({ErrorCode::corrupt});
    const Value &root = parsed.value();
    if (!std::holds_alternative<Value::Object>(root.value()))
      return Result<void>::failure({ErrorCode::corrupt});

    auto version = parse_uint64_field(root, "version");
    if (!version.has_value() || version.value() != kSwarmStateSchemaVersion)
      return Result<void>::failure({ErrorCode::corrupt});
    auto stored_title = parse_string_field(root, "title");
    auto stored_counter = parse_uint64_field(root, "session_counter");
    if (!stored_title.has_value() || !stored_counter.has_value())
      return Result<void>::failure({ErrorCode::corrupt});
    if (!validate_text(stored_title.value(), kPlatoonMaxFieldBytes, EmptyPolicy::allow)
             .has_value()) {
      return Result<void>::failure({ErrorCode::corrupt});
    }

    const auto *workers_field = root.find("workers");
    if (!workers_field)
      return Result<void>::failure({ErrorCode::corrupt});
    const auto *array = std::get_if<Value::Array>(&workers_field->value());
    if (!array || array->size() > kPlatoonMaxRosterMembers ||
        array->size() > config_.max_workers) {
      return Result<void>::failure({ErrorCode::corrupt});
    }

    std::vector<SwarmWorkerRecord> loaded;
    loaded.reserve(array->size());
    for (const auto &entry : *array) {
      auto rec = worker_from_value(entry);
      if (!rec.has_value())
        return Result<void>::failure(rec.error());
      loaded.push_back(std::move(rec).value());
    }
    std::sort(loaded.begin(), loaded.end(),
              [](const SwarmWorkerRecord &lhs, const SwarmWorkerRecord &rhs) {
                return lhs.name < rhs.name;
              });
    for (std::size_t i = 1; i < loaded.size(); ++i) {
      if (loaded[i - 1].name == loaded[i].name)
        return Result<void>::failure({ErrorCode::corrupt});
    }
    for (std::size_t i = 0; i < loaded.size(); ++i) {
      if (loaded[i].state == SwarmWorkerState::killed)
        continue;
      for (std::size_t j = i + 1; j < loaded.size(); ++j) {
        if (loaded[j].state == SwarmWorkerState::killed)
          continue;
        for (const auto &lhs_path : loaded[i].owned_files) {
          for (const auto &rhs_path : loaded[j].owned_files) {
            if (paths_overlap(PathPair{lhs_path, rhs_path}))
              return Result<void>::failure({ErrorCode::corrupt});
          }
        }
      }
    }

    if (config_.swarm_title.empty())
      config_.swarm_title = std::move(stored_title).value();
    session_counter_ = stored_counter.value();
    workers_ = std::move(loaded);
    return Result<void>::success();
  } catch (const std::bad_alloc &) {
    return Result<void>::failure({ErrorCode::allocation});
  }
}

} // namespace blackbird
