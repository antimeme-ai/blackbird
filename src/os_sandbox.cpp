#include "blackbird/os_sandbox.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <signal.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#if defined(__APPLE__)
#include <dlfcn.h>
#endif

#if defined(__linux__)
#include <dirent.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#endif
#endif

namespace blackbird::sandbox {

namespace {

Error make_error(ErrorCode code, SandboxError detail) noexcept {
  return Error{code, static_cast<std::int64_t>(detail)};
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

bool has_control_or_nul(std::string_view text) noexcept {
  for (const char ch : text) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7FU) {
      return true;
    }
  }
  return false;
}

std::string strip_trailing_slashes(std::string path) {
  while (path.size() > 1U && path.back() == '/') {
    path.pop_back();
  }
  return path;
}

// Strictly canonicalizes an existing path using realpath().
Result<std::filesystem::path>
canonicalize_existing_dir(const std::filesystem::path &input) {
  if (input.empty()) {
    return Result<std::filesystem::path>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::invalid_path));
  }
  const std::string raw = input.string();
  if (has_control_or_nul(raw)) {
    return Result<std::filesystem::path>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::control_char_in_path));
  }
  std::array<char, PATH_MAX> resolved{};
  if (::realpath(raw.c_str(), resolved.data()) == nullptr) {
    return Result<std::filesystem::path>::failure(
        make_error(ErrorCode::io, SandboxError::canonicalize_failed));
  }
  struct stat st{};
  if (::stat(resolved.data(), &st) != 0 || !S_ISDIR(st.st_mode)) {
    return Result<std::filesystem::path>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::invalid_path));
  }
  return Result<std::filesystem::path>::success(
      std::filesystem::path{strip_trailing_slashes(std::string{resolved.data()})});
}

// Canonicalizes an existing path or, if the target does not exist yet, resolves the
// deepest existing ancestor with realpath() and joins the normalized remaining tail.
Result<std::filesystem::path>
canonicalize_path_lenient(const std::filesystem::path &input) {
  if (input.empty()) {
    return Result<std::filesystem::path>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::invalid_path));
  }
  const std::string raw = input.string();
  if (has_control_or_nul(raw)) {
    return Result<std::filesystem::path>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::control_char_in_path));
  }
  std::array<char, PATH_MAX> resolved{};
  if (::realpath(raw.c_str(), resolved.data()) != nullptr) {
    return Result<std::filesystem::path>::success(
        std::filesystem::path{strip_trailing_slashes(std::string{resolved.data()})});
  }

  std::filesystem::path probe = input.lexically_normal();
  std::vector<std::filesystem::path> tail;
  while (!probe.empty()) {
    const std::string probe_str = probe.string();
    if (::realpath(probe_str.c_str(), resolved.data()) != nullptr) {
      std::filesystem::path result{resolved.data()};
      for (auto it = tail.rbegin(); it != tail.rend(); ++it) {
        result /= *it;
      }
      return Result<std::filesystem::path>::success(std::filesystem::path{
          strip_trailing_slashes(result.lexically_normal().string())});
    }
    const std::filesystem::path parent = probe.parent_path();
    if (parent == probe) {
      break;
    }
    const std::filesystem::path name = probe.filename();
    if (!name.empty() && name != ".") {
      if (name == "..") {
        return Result<std::filesystem::path>::failure(
            make_error(ErrorCode::invalid_range, SandboxError::invalid_path));
      }
      tail.push_back(name);
    }
    probe = parent;
  }

  const std::string fallback =
      strip_trailing_slashes(input.lexically_normal().string());
  if (fallback.empty() || fallback.front() != '/') {
    return Result<std::filesystem::path>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::canonicalize_failed));
  }
  return Result<std::filesystem::path>::success(std::filesystem::path{fallback});
}

std::filesystem::path resolve_default_tmp_dir() {
  if (const char *env_tmp = std::getenv("TMPDIR");
      env_tmp != nullptr && *env_tmp != '\0') {
    return std::filesystem::path{env_tmp};
  }
  return std::filesystem::path{"/tmp"};
}

std::filesystem::path resolve_default_home_dir() {
  if (const char *env_home = std::getenv("HOME");
      env_home != nullptr && *env_home != '\0') {
    return std::filesystem::path{env_home};
  }
  return {};
}

void push_unique_path(std::vector<std::filesystem::path> &out,
                      const std::filesystem::path &candidate) {
  if (candidate.empty()) {
    return;
  }
  if (std::find(out.begin(), out.end(), candidate) == out.end()) {
    out.push_back(candidate);
  }
}

struct ResolvedSpec {
  SandboxProfile profile = SandboxProfile::none;
  std::filesystem::path workspace_root;
  std::filesystem::path tmp_dir;
  std::filesystem::path home_dir;
  std::vector<std::filesystem::path> denied_paths;
  std::vector<std::filesystem::path> extra_read_paths;
  bool deny_workspace_dotenv = true;
};

Result<ResolvedSpec> resolve_sandbox_spec(const SandboxSpec &spec) {
  ResolvedSpec resolved;
  resolved.profile = spec.profile;
  resolved.deny_workspace_dotenv = spec.deny_workspace_dotenv;

  auto ws = canonicalize_existing_dir(spec.workspace_root);
  if (!ws.has_value()) {
    return Result<ResolvedSpec>::failure(ws.error());
  }
  if (ws.value() == "/") {
    return Result<ResolvedSpec>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::invalid_spec));
  }
  resolved.workspace_root = std::move(ws).value();

  const std::filesystem::path tmp_input =
      spec.tmp_dir.empty() ? resolve_default_tmp_dir() : spec.tmp_dir;
  auto tmp = canonicalize_existing_dir(tmp_input);
  if (!tmp.has_value()) {
    return Result<ResolvedSpec>::failure(tmp.error());
  }
  if (tmp.value() == "/") {
    return Result<ResolvedSpec>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::invalid_spec));
  }
  resolved.tmp_dir = std::move(tmp).value();

  const bool explicit_home = !spec.home_dir.empty();
  const std::filesystem::path home_input =
      explicit_home ? spec.home_dir : resolve_default_home_dir();
  if (!home_input.empty()) {
    auto home = canonicalize_path_lenient(home_input);
    if (!home.has_value()) {
      return Result<ResolvedSpec>::failure(home.error());
    }
    if (home.value() == "/") {
      if (explicit_home) {
        return Result<ResolvedSpec>::failure(
            make_error(ErrorCode::invalid_range, SandboxError::invalid_spec));
      }
      // Inherited HOME="/" (e.g. minimal container env): omit home_dir rather than
      // ever enumerating or exposing root.
    } else {
      resolved.home_dir = std::move(home).value();
    }
  }

  auto add_denied = [&](const std::filesystem::path &raw_path) -> Result<void> {
    if (raw_path.empty()) {
      return Result<void>::failure(
          make_error(ErrorCode::invalid_range, SandboxError::invalid_path));
    }
    auto canon = canonicalize_path_lenient(raw_path);
    if (!canon.has_value()) {
      return Result<void>::failure(canon.error());
    }
    push_unique_path(resolved.denied_paths, canon.value());
    // If raw_path itself was a symlink whose parent canonicalizes differently from
    // realpath(raw_path), also block the symlink location under its canonical parent.
    const std::filesystem::path parent = raw_path.parent_path();
    const std::filesystem::path leaf = raw_path.filename();
    if (!parent.empty() && !leaf.empty() && leaf != "." && leaf != "..") {
      auto canon_parent = canonicalize_path_lenient(parent);
      if (canon_parent.has_value()) {
        push_unique_path(resolved.denied_paths, canon_parent.value() / leaf);
      }
    }
    return Result<void>::success();
  };

  for (const auto &denied : spec.denied_paths) {
    auto rc = add_denied(denied);
    if (!rc.has_value()) {
      return Result<ResolvedSpec>::failure(rc.error());
    }
  }

  if (spec.include_default_denied_paths) {
    for (const auto &def_path : default_denied_paths(resolved.home_dir)) {
      auto rc = add_denied(def_path);
      if (!rc.has_value()) {
        return Result<ResolvedSpec>::failure(rc.error());
      }
    }
  }

  for (const auto &extra : spec.extra_read_paths) {
    if (extra.empty()) {
      return Result<ResolvedSpec>::failure(
          make_error(ErrorCode::invalid_range, SandboxError::invalid_path));
    }
    auto canon = canonicalize_path_lenient(extra);
    if (!canon.has_value()) {
      return Result<ResolvedSpec>::failure(canon.error());
    }
    if (canon.value() == "/") {
      return Result<ResolvedSpec>::failure(
          make_error(ErrorCode::invalid_range, SandboxError::invalid_spec));
    }
    push_unique_path(resolved.extra_read_paths, canon.value());
  }

  return Result<ResolvedSpec>::success(std::move(resolved));
}

// Escapes regex metacharacters AND SBPL string characters for #"..." literals.
Result<std::string> escape_sbpl_regex_literal(std::string_view input) {
  if (has_control_or_nul(input)) {
    return Result<std::string>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::control_char_in_path));
  }
  std::string out;
  out.reserve(input.size() * 2U);
  for (const char ch : input) {
    switch (ch) {
    case '\\':
    case '"':
    case '.':
    case '+':
    case '*':
    case '?':
    case '^':
    case '$':
    case '(':
    case ')':
    case '[':
    case ']':
    case '{':
    case '}':
    case '|':
      out.push_back('\\');
      out.push_back(ch);
      break;
    default:
      out.push_back(ch);
      break;
    }
  }
  return Result<std::string>::success(std::move(out));
}

Result<void> append_sbpl_quoted(std::string &out, std::string_view raw) {
  auto escaped = escape_sbpl_string(raw);
  if (!escaped.has_value()) {
    return Result<void>::failure(escaped.error());
  }
  out.push_back('"');
  out.append(escaped.value());
  out.push_back('"');
  return Result<void>::success();
}

Result<void> append_sbpl_subpath(std::string &out, const std::filesystem::path &path) {
  out.append("(subpath ");
  auto rc = append_sbpl_quoted(out, path.string());
  if (!rc.has_value()) {
    return rc;
  }
  out.push_back(')');
  return Result<void>::success();
}

Result<void> append_sbpl_literal(std::string &out, const std::filesystem::path &path) {
  out.append("(literal ");
  auto rc = append_sbpl_quoted(out, path.string());
  if (!rc.has_value()) {
    return rc;
  }
  out.push_back(')');
  return Result<void>::success();
}

#if defined(__APPLE__)
using SandboxInitFn = int (*)(const char *profile, std::uint64_t flags,
                              char **errorbuf);
using SandboxFreeErrorFn = void (*)(char *errorbuf);

template <typename FnPtr> FnPtr load_symbol(const char *symbol_name) noexcept {
  void *raw = ::dlsym(RTLD_DEFAULT, symbol_name);
  FnPtr fn = nullptr;
  static_assert(sizeof(fn) == sizeof(raw));
  std::memcpy(&fn, &raw, sizeof(fn));
  return fn;
}

Result<void> apply_macos_seatbelt(const SandboxSpec &spec) {
  const auto init_fn = load_symbol<SandboxInitFn>("sandbox_init");
  const auto free_fn = load_symbol<SandboxFreeErrorFn>("sandbox_free_error");
  if (init_fn == nullptr || free_fn == nullptr) {
    return Result<void>::failure(
        make_error(ErrorCode::unsupported, SandboxError::backend_unavailable));
  }
  auto profile = build_macos_seatbelt_profile(spec);
  if (!profile.has_value()) {
    return Result<void>::failure(profile.error());
  }
  char *error_buf = nullptr;
  const int rc = init_fn(profile.value().c_str(), 0U, &error_buf);
  if (error_buf != nullptr) {
    free_fn(error_buf);
  }
  if (rc != 0) {
    return Result<void>::failure(
        make_error(ErrorCode::io, SandboxError::seatbelt_init_failed));
  }
  return Result<void>::success();
}
#endif

#if defined(__linux__)
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
              "Linux seccomp-bpf filter assumes little-endian architecture");

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

inline constexpr std::uint32_t kLandlockCreateRulesetVersion = 1U << 0U;
inline constexpr std::uint32_t kLandlockRulePathBeneath = 1U;

inline constexpr std::uint64_t kLandlockFsExecute = 1ULL << 0U;
inline constexpr std::uint64_t kLandlockFsWriteFile = 1ULL << 1U;
inline constexpr std::uint64_t kLandlockFsReadFile = 1ULL << 2U;
inline constexpr std::uint64_t kLandlockFsReadDir = 1ULL << 3U;
inline constexpr std::uint64_t kLandlockFsRemoveDir = 1ULL << 4U;
inline constexpr std::uint64_t kLandlockFsRemoveFile = 1ULL << 5U;
inline constexpr std::uint64_t kLandlockFsMakeChar = 1ULL << 6U;
inline constexpr std::uint64_t kLandlockFsMakeDir = 1ULL << 7U;
inline constexpr std::uint64_t kLandlockFsMakeReg = 1ULL << 8U;
inline constexpr std::uint64_t kLandlockFsMakeSock = 1ULL << 9U;
inline constexpr std::uint64_t kLandlockFsMakeFifo = 1ULL << 10U;
inline constexpr std::uint64_t kLandlockFsMakeBlock = 1ULL << 11U;
inline constexpr std::uint64_t kLandlockFsMakeSym = 1ULL << 12U;
inline constexpr std::uint64_t kLandlockFsRefer = 1ULL << 13U;
inline constexpr std::uint64_t kLandlockFsTruncate = 1ULL << 14U;
inline constexpr std::uint64_t kLandlockFsIoctlDev = 1ULL << 15U;

inline constexpr std::uint64_t kLandlockNetBindTcp = 1ULL << 0U;
inline constexpr std::uint64_t kLandlockNetConnectTcp = 1ULL << 1U;

inline constexpr std::uint64_t kLandlockScopeAbstractUnix = 1ULL << 0U;
inline constexpr std::uint64_t kLandlockScopeSignal = 1ULL << 1U;

struct LandlockRulesetAttrV6 {
  std::uint64_t handled_access_fs = 0U;
  std::uint64_t handled_access_net = 0U;
  std::uint64_t scoped = 0U;
};

struct LandlockPathBeneathAttr {
  std::uint64_t allowed_access = 0U;
  std::int32_t parent_fd = -1;
} __attribute__((packed));

int probe_landlock_abi_version() noexcept {
  const long rc =
      ::syscall(__NR_landlock_create_ruleset, nullptr, static_cast<std::size_t>(0U),
                kLandlockCreateRulesetVersion);
  if (rc < 1L || rc > static_cast<long>(INT_MAX)) {
    return 0;
  }
  return static_cast<int>(rc);
}

struct RulesetFd {
  int fd = -1;
};

struct PathPrefixCheck {
  const std::filesystem::path &prefix;
  const std::filesystem::path &target;
};

bool path_equals_or_is_prefix(PathPrefixCheck check) {
  const std::string p = strip_trailing_slashes(check.prefix.string());
  const std::string t = strip_trailing_slashes(check.target.string());
  if (p == t) {
    return true;
  }
  if (p == "/") {
    return !t.empty() && t.front() == '/';
  }
  return t.size() > p.size() && t.compare(0U, p.size(), p) == 0 && t[p.size()] == '/';
}

bool is_denied_or_ancestor(const std::filesystem::path &candidate,
                           const std::vector<std::filesystem::path> &denied_paths) {
  for (const auto &denied : denied_paths) {
    if (path_equals_or_is_prefix({denied, candidate}) ||
        path_equals_or_is_prefix({candidate, denied})) {
      return true;
    }
  }
  return false;
}

bool is_path_denied(const std::filesystem::path &candidate,
                    const std::vector<std::filesystem::path> &denied_paths) {
  for (const auto &denied : denied_paths) {
    if (path_equals_or_is_prefix({denied, candidate})) {
      return true;
    }
  }
  return false;
}

enum class LandlockAccessKind : std::uint8_t { read_only, read_write, device_rw };

std::uint64_t compute_landlock_rights(LandlockAccessKind kind, bool is_directory,
                                      std::uint64_t handled_fs) noexcept {
  constexpr std::uint64_t kFileRead = kLandlockFsExecute | kLandlockFsReadFile;
  constexpr std::uint64_t kDirRead = kFileRead | kLandlockFsReadDir;
  constexpr std::uint64_t kFileWrite =
      kFileRead | kLandlockFsWriteFile | kLandlockFsTruncate;
  constexpr std::uint64_t kDirWrite =
      kDirRead | kLandlockFsWriteFile | kLandlockFsRemoveDir | kLandlockFsRemoveFile |
      kLandlockFsMakeDir | kLandlockFsMakeReg | kLandlockFsMakeSock |
      kLandlockFsMakeFifo | kLandlockFsMakeSym | kLandlockFsRefer | kLandlockFsTruncate;
  constexpr std::uint64_t kDeviceFileWrite = kFileWrite | kLandlockFsIoctlDev;
  constexpr std::uint64_t kDeviceDirWrite = kDirWrite | kLandlockFsIoctlDev;

  std::uint64_t rights = 0U;
  switch (kind) {
  case LandlockAccessKind::read_only:
    rights = is_directory ? kDirRead : kFileRead;
    break;
  case LandlockAccessKind::read_write:
    rights = is_directory ? kDirWrite : kFileWrite;
    break;
  case LandlockAccessKind::device_rw:
    rights = is_directory ? kDeviceDirWrite : kDeviceFileWrite;
    break;
  }
  return rights & handled_fs;
}

Result<void> add_landlock_fd_rule(RulesetFd ruleset, int target_fd,
                                  LandlockAccessKind kind, std::uint64_t handled_fs) {
  struct stat st{};
  if (::fstat(target_fd, &st) != 0) {
    return Result<void>::failure(
        make_error(ErrorCode::io, SandboxError::landlock_rule_failed));
  }
  const bool is_dir = S_ISDIR(st.st_mode);
  const std::uint64_t rights = compute_landlock_rights(kind, is_dir, handled_fs);
  if (rights == 0U) {
    return Result<void>::success();
  }
  LandlockPathBeneathAttr attr{};
  attr.allowed_access = rights;
  attr.parent_fd = target_fd;
  const long rc =
      ::syscall(__NR_landlock_add_rule, ruleset.fd, kLandlockRulePathBeneath, &attr,
                static_cast<std::uint32_t>(0U));
  if (rc != 0L) {
    return Result<void>::failure(
        make_error(ErrorCode::io, SandboxError::landlock_rule_failed));
  }
  return Result<void>::success();
}

Result<void> add_landlock_path_if_exists(RulesetFd ruleset,
                                         const std::filesystem::path &path,
                                         LandlockAccessKind kind,
                                         std::uint64_t handled_fs, bool required) {
  const int raw_fd = ::open(path.c_str(), O_PATH | O_CLOEXEC);
  if (raw_fd < 0) {
    if (!required && (errno == ENOENT || errno == ENOTDIR || errno == EACCES)) {
      return Result<void>::success();
    }
    return Result<void>::failure(
        make_error(ErrorCode::io, SandboxError::landlock_rule_failed));
  }
  ScopedFd fd{raw_fd};
  return add_landlock_fd_rule(ruleset, fd.fd, kind, handled_fs);
}

enum class HomeEnumLevel : std::uint8_t { home_root, dot_local, leaf_only };

// Enumerates immediate entries of dir_path via opendir + openat(O_PATH|O_NOFOLLOW),
// adding safe siblings read-only while omitting denied paths and ancestors of denied
// paths. NEVER adds dir_path itself as a Landlock rule.
Result<void>
add_safe_directory_children_ro(RulesetFd ruleset, const std::filesystem::path &dir_path,
                               const std::vector<std::filesystem::path> &denied_paths,
                               std::uint64_t handled_fs, HomeEnumLevel level) {
  const int raw_dir_fd =
      ::open(dir_path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (raw_dir_fd < 0) {
    return Result<void>::success();
  }
  ScopedFd dir_fd{raw_dir_fd};
  const int dup_fd = ::fcntl(dir_fd.fd, F_DUPFD_CLOEXEC, 0);
  if (dup_fd < 0) {
    return Result<void>::failure(
        make_error(ErrorCode::io, SandboxError::landlock_rule_failed));
  }
  DIR *dir = ::fdopendir(dup_fd);
  if (dir == nullptr) {
    (void)::close(dup_fd);
    return Result<void>::failure(
        make_error(ErrorCode::io, SandboxError::landlock_rule_failed));
  }

  Result<void> status = Result<void>::success();
  while (const struct dirent *ent = ::readdir(dir)) {
    const std::string_view name{ent->d_name};
    if (name == "." || name == "..") {
      continue;
    }
    const std::filesystem::path child_path = dir_path / name;

    // Descend one level into ~/.config, ~/.local, and ~/.local/share without ever
    // adding those container directories themselves as Landlock allow rules.
    if (level == HomeEnumLevel::home_root && name == ".config") {
      if (!is_path_denied(child_path, denied_paths)) {
        const auto sub = add_safe_directory_children_ro(
            ruleset, child_path, denied_paths, handled_fs, HomeEnumLevel::leaf_only);
        if (!sub.has_value()) {
          status = sub;
          break;
        }
      }
      continue;
    }
    if (level == HomeEnumLevel::home_root && name == ".local") {
      if (!is_path_denied(child_path, denied_paths)) {
        const auto sub = add_safe_directory_children_ro(
            ruleset, child_path, denied_paths, handled_fs, HomeEnumLevel::dot_local);
        if (!sub.has_value()) {
          status = sub;
          break;
        }
      }
      continue;
    }
    if (level == HomeEnumLevel::dot_local && name == "share") {
      if (!is_path_denied(child_path, denied_paths)) {
        const auto sub = add_safe_directory_children_ro(
            ruleset, child_path, denied_paths, handled_fs, HomeEnumLevel::leaf_only);
        if (!sub.has_value()) {
          status = sub;
          break;
        }
      }
      continue;
    }

    if (is_denied_or_ancestor(child_path, denied_paths)) {
      continue;
    }

    const int raw_entry_fd =
        ::openat(dir_fd.fd, ent->d_name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (raw_entry_fd < 0) {
      continue;
    }
    ScopedFd entry_fd{raw_entry_fd};
    struct stat st{};
    if (::fstat(entry_fd.fd, &st) != 0) {
      continue;
    }
    if (S_ISLNK(st.st_mode)) {
      auto resolved_target = canonicalize_path_lenient(child_path);
      if (!resolved_target.has_value() ||
          is_denied_or_ancestor(resolved_target.value(), denied_paths)) {
        continue;
      }
      auto rc =
          add_landlock_path_if_exists(ruleset, resolved_target.value(),
                                      LandlockAccessKind::read_only, handled_fs, false);
      if (!rc.has_value()) {
        status = rc;
        break;
      }
      continue;
    }

    auto rc = add_landlock_fd_rule(ruleset, entry_fd.fd, LandlockAccessKind::read_only,
                                   handled_fs);
    if (!rc.has_value()) {
      status = rc;
      break;
    }
  }
  (void)::closedir(dir);
  return status;
}

struct BpfJumpTargets {
  std::uint8_t jt = 0U;
  std::uint8_t jf = 0U;
};

constexpr sock_filter bpf_stmt(std::uint16_t code, std::uint32_t k) noexcept {
  return sock_filter{code, 0U, 0U, k};
}

constexpr sock_filter bpf_jump(std::uint16_t code, std::uint32_t k,
                               BpfJumpTargets targets) noexcept {
  return sock_filter{code, targets.jt, targets.jf, k};
}

Result<void> install_linux_seccomp_filter(SandboxProfile profile) {
#if defined(__x86_64__)
  constexpr std::uint32_t kExpectedArch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
  constexpr std::uint32_t kExpectedArch = AUDIT_ARCH_AARCH64;
#else
  (void)profile;
  return Result<void>::failure(
      make_error(ErrorCode::unsupported, SandboxError::seccomp_arch_unsupported));
#endif

  constexpr std::uint16_t kLdW = static_cast<std::uint16_t>(BPF_LD | BPF_W | BPF_ABS);
  constexpr std::uint16_t kJmpEq =
      static_cast<std::uint16_t>(BPF_JMP | BPF_JEQ | BPF_K);
  constexpr std::uint16_t kRetK = static_cast<std::uint16_t>(BPF_RET | BPF_K);
  constexpr std::uint32_t kOffsetArch =
      static_cast<std::uint32_t>(offsetof(struct seccomp_data, arch));
  constexpr std::uint32_t kOffsetNr =
      static_cast<std::uint32_t>(offsetof(struct seccomp_data, nr));
  constexpr std::uint32_t kOffsetArg0 =
      static_cast<std::uint32_t>(offsetof(struct seccomp_data, args[0]));
  constexpr std::uint32_t kRetKill = static_cast<std::uint32_t>(SECCOMP_RET_KILL);
  constexpr std::uint32_t kRetAllow = static_cast<std::uint32_t>(SECCOMP_RET_ALLOW);
  constexpr std::uint32_t kRetEperm = static_cast<std::uint32_t>(SECCOMP_RET_ERRNO) |
                                      (static_cast<std::uint32_t>(EPERM) &
                                       static_cast<std::uint32_t>(SECCOMP_RET_DATA));

  constexpr std::array<std::uint32_t, 11> kBlockedSyscalls = {
      static_cast<std::uint32_t>(__NR_ptrace),
      static_cast<std::uint32_t>(__NR_process_vm_readv),
      static_cast<std::uint32_t>(__NR_process_vm_writev),
      static_cast<std::uint32_t>(__NR_io_uring_setup),
      static_cast<std::uint32_t>(__NR_bpf),
      static_cast<std::uint32_t>(__NR_keyctl),
      static_cast<std::uint32_t>(__NR_add_key),
      static_cast<std::uint32_t>(__NR_request_key),
      static_cast<std::uint32_t>(__NR_unshare),
      static_cast<std::uint32_t>(__NR_mount),
      static_cast<std::uint32_t>(__NR_pivot_root),
  };

  std::vector<sock_filter> prog;
  prog.reserve(32U);
  std::vector<std::size_t> patch_jt_eperm;
  std::vector<std::size_t> patch_jf_allow;

  // 1. Verify syscall architecture (fail closed via SECCOMP_RET_KILL).
  prog.push_back(bpf_stmt(kLdW, kOffsetArch));
  prog.push_back(bpf_jump(kJmpEq, kExpectedArch, {1U, 0U}));
  prog.push_back(bpf_stmt(kRetK, kRetKill));

  // 2. Load syscall number.
  prog.push_back(bpf_stmt(kLdW, kOffsetNr));

  // 3. Block dangerous inspection/escape/keyring syscalls with EPERM.
  for (const std::uint32_t nr : kBlockedSyscalls) {
    patch_jt_eperm.push_back(prog.size());
    prog.push_back(bpf_jump(kJmpEq, nr, {0U, 0U}));
  }

  // 4. Under sandboxed and airgap, block socket(AF_INET|AF_INET6|AF_PACKET|AF_NETLINK)
  //    so TCP, UDP, DNS, and raw sockets are blocked at the kernel boundary (matching
  //    macOS sandboxed/airgap parity even on Landlock ABI >= 4 where Landlock covers
  //    TCP only).
  const bool block_inet_sockets =
      profile == SandboxProfile::sandboxed || profile == SandboxProfile::airgap;
  if (block_inet_sockets) {
    patch_jf_allow.push_back(prog.size());
    prog.push_back(bpf_jump(kJmpEq, static_cast<std::uint32_t>(__NR_socket), {0U, 0U}));
    prog.push_back(bpf_stmt(kLdW, kOffsetArg0));
    constexpr std::array<std::uint32_t, 4> kBlockedFamilies = {
        static_cast<std::uint32_t>(AF_INET),
        static_cast<std::uint32_t>(AF_INET6),
        static_cast<std::uint32_t>(AF_PACKET),
        static_cast<std::uint32_t>(AF_NETLINK),
    };
    for (const std::uint32_t family : kBlockedFamilies) {
      patch_jt_eperm.push_back(prog.size());
      prog.push_back(bpf_jump(kJmpEq, family, {0U, 0U}));
    }
  }

  const std::size_t allow_idx = prog.size();
  prog.push_back(bpf_stmt(kRetK, kRetAllow));
  const std::size_t eperm_idx = prog.size();
  prog.push_back(bpf_stmt(kRetK, kRetEperm));

  for (const std::size_t idx : patch_jt_eperm) {
    const std::size_t dist = eperm_idx - (idx + 1U);
    if (dist > std::numeric_limits<std::uint8_t>::max()) {
      return Result<void>::failure(
          make_error(ErrorCode::overflow, SandboxError::seccomp_install_failed));
    }
    prog[idx].jt = static_cast<std::uint8_t>(dist);
  }
  for (const std::size_t idx : patch_jf_allow) {
    const std::size_t dist = allow_idx - (idx + 1U);
    if (dist > std::numeric_limits<std::uint8_t>::max()) {
      return Result<void>::failure(
          make_error(ErrorCode::overflow, SandboxError::seccomp_install_failed));
    }
    prog[idx].jf = static_cast<std::uint8_t>(dist);
  }

  sock_fprog fprog{};
  fprog.len = static_cast<unsigned short>(prog.size());
  fprog.filter = prog.data();
  if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) != 0) {
    return Result<void>::failure(
        make_error(ErrorCode::io, SandboxError::seccomp_install_failed));
  }
  return Result<void>::success();
}

Result<void> apply_linux_landlock_and_seccomp(const SandboxSpec &spec) {
  auto resolved_res = resolve_sandbox_spec(spec);
  if (!resolved_res.has_value()) {
    return Result<void>::failure(resolved_res.error());
  }
  const ResolvedSpec &resolved = resolved_res.value();

  const int abi = probe_landlock_abi_version();
  if (abi < 1) {
    return Result<void>::failure(
        make_error(ErrorCode::unsupported, SandboxError::landlock_unavailable));
  }

  if (::prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) {
    return Result<void>::failure(
        make_error(ErrorCode::io, SandboxError::no_new_privs_failed));
  }

  std::uint64_t handled_fs =
      kLandlockFsExecute | kLandlockFsWriteFile | kLandlockFsReadFile |
      kLandlockFsReadDir | kLandlockFsRemoveDir | kLandlockFsRemoveFile |
      kLandlockFsMakeChar | kLandlockFsMakeDir | kLandlockFsMakeReg |
      kLandlockFsMakeSock | kLandlockFsMakeFifo | kLandlockFsMakeBlock |
      kLandlockFsMakeSym;
  if (abi >= 2) {
    handled_fs |= kLandlockFsRefer;
  }
  if (abi >= 3) {
    handled_fs |= kLandlockFsTruncate;
  }
  if (abi >= 5) {
    handled_fs |= kLandlockFsIoctlDev;
  }

  LandlockRulesetAttrV6 attr{};
  attr.handled_access_fs = handled_fs;
  if (abi >= 4 && (resolved.profile == SandboxProfile::airgap ||
                   resolved.profile == SandboxProfile::sandboxed)) {
    attr.handled_access_net = resolved.profile == SandboxProfile::airgap
                                  ? (kLandlockNetBindTcp | kLandlockNetConnectTcp)
                                  : kLandlockNetConnectTcp;
  }
  if (abi >= 6 && (resolved.profile == SandboxProfile::airgap ||
                   resolved.profile == SandboxProfile::sandboxed)) {
    attr.scoped = kLandlockScopeAbstractUnix | kLandlockScopeSignal;
  }

  std::size_t attr_size = sizeof(std::uint64_t);
  if (abi >= 6) {
    attr_size = sizeof(LandlockRulesetAttrV6);
  } else if (abi >= 4) {
    attr_size = sizeof(std::uint64_t) * 2U;
  }

  const long raw_ruleset = ::syscall(__NR_landlock_create_ruleset, &attr, attr_size,
                                     static_cast<std::uint32_t>(0U));
  if (raw_ruleset < 0L) {
    return Result<void>::failure(
        make_error(ErrorCode::io, SandboxError::landlock_ruleset_failed));
  }
  ScopedFd ruleset_fd{static_cast<int>(raw_ruleset)};
  const RulesetFd ruleset{ruleset_fd.fd};

  // Allow-list-only FS construction (NEVER add "/" or "$HOME" directly!).
  constexpr std::array<std::string_view, 9> kSystemReadOnlyPrefixes = {
      "/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt", "/etc", "/proc/self", "/dev",
  };
  for (const std::string_view prefix : kSystemReadOnlyPrefixes) {
    auto rc =
        add_landlock_path_if_exists(ruleset, std::filesystem::path{prefix},
                                    LandlockAccessKind::read_only, handled_fs, false);
    if (!rc.has_value()) {
      return rc;
    }
  }

  // Allow write/ioctl on essential pseudo-devices (/dev/null, /dev/tty, /dev/pts).
  constexpr std::array<std::string_view, 3> kDeviceRwPaths = {
      "/dev/null",
      "/dev/tty",
      "/dev/pts",
  };
  for (const std::string_view dev_path : kDeviceRwPaths) {
    auto rc =
        add_landlock_path_if_exists(ruleset, std::filesystem::path{dev_path},
                                    LandlockAccessKind::device_rw, handled_fs, false);
    if (!rc.has_value()) {
      return rc;
    }
  }

  // Canonical workspace_root and tmp_dir are read-write.
  {
    auto rc =
        add_landlock_path_if_exists(ruleset, resolved.workspace_root,
                                    LandlockAccessKind::read_write, handled_fs, true);
    if (!rc.has_value()) {
      return rc;
    }
  }
  {
    auto rc = add_landlock_path_if_exists(
        ruleset, resolved.tmp_dir, LandlockAccessKind::read_write, handled_fs, true);
    if (!rc.has_value()) {
      return rc;
    }
  }

  // Extra read-only paths (never allowing a denied path or ancestor of a denied path).
  for (const auto &extra : resolved.extra_read_paths) {
    if (is_denied_or_ancestor(extra, resolved.denied_paths)) {
      continue;
    }
    auto rc = add_landlock_path_if_exists(ruleset, extra, LandlockAccessKind::read_only,
                                          handled_fs, false);
    if (!rc.has_value()) {
      return rc;
    }
  }

  // Under guarded only: enumerate immediate entries of home_dir (and one level under
  // .config and .local/share), adding safe siblings RO while omitting denied_paths.
  if (resolved.profile == SandboxProfile::guarded && !resolved.home_dir.empty() &&
      resolved.home_dir != "/") {
    auto rc = add_safe_directory_children_ro(ruleset, resolved.home_dir,
                                             resolved.denied_paths, handled_fs,
                                             HomeEnumLevel::home_root);
    if (!rc.has_value()) {
      return rc;
    }
  }

  if (::syscall(__NR_landlock_restrict_self, ruleset_fd.fd,
                static_cast<std::uint32_t>(0U)) != 0L) {
    return Result<void>::failure(
        make_error(ErrorCode::io, SandboxError::landlock_restrict_failed));
  }

  return install_linux_seccomp_filter(resolved.profile);
}
#endif

struct ChildFailurePacket {
  std::int64_t sandbox_error = 0;
  std::int32_t err_no = 0;
  std::uint32_t stage = 0U; // 1 = sandbox apply, 2 = chdir, 3 = execvp
};
static_assert(sizeof(ChildFailurePacket) == 16U);

bool write_all_fd(int fd, const void *data, std::size_t len) noexcept {
  const auto *ptr = static_cast<const std::uint8_t *>(data);
  std::size_t remaining = len;
  while (remaining > 0U) {
    const ssize_t written = ::write(fd, ptr, remaining);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    ptr += static_cast<std::size_t>(written);
    remaining -= static_cast<std::size_t>(written);
  }
  return true;
}

bool create_cloexec_pipe(std::array<ScopedFd, 2> &out) noexcept {
  int fds[2] = {-1, -1};
  if (::pipe(fds) != 0) {
    return false;
  }
  out[0].reset(fds[0]);
  out[1].reset(fds[1]);
  if (::fcntl(out[0].fd, F_SETFD, FD_CLOEXEC) != 0 ||
      ::fcntl(out[1].fd, F_SETFD, FD_CLOEXEC) != 0) {
    out[0].reset();
    out[1].reset();
    return false;
  }
  return true;
}

} // namespace

std::string_view sandbox_error_name(SandboxError detail) noexcept {
  switch (detail) {
  case SandboxError::none:
    return "none";
  case SandboxError::invalid_spec:
    return "invalid_spec";
  case SandboxError::invalid_path:
    return "invalid_path";
  case SandboxError::control_char_in_path:
    return "control_char_in_path";
  case SandboxError::canonicalize_failed:
    return "canonicalize_failed";
  case SandboxError::unsupported_platform:
    return "unsupported_platform";
  case SandboxError::backend_unavailable:
    return "backend_unavailable";
  case SandboxError::seatbelt_init_failed:
    return "seatbelt_init_failed";
  case SandboxError::no_new_privs_failed:
    return "no_new_privs_failed";
  case SandboxError::landlock_unavailable:
    return "landlock_unavailable";
  case SandboxError::landlock_ruleset_failed:
    return "landlock_ruleset_failed";
  case SandboxError::landlock_rule_failed:
    return "landlock_rule_failed";
  case SandboxError::landlock_restrict_failed:
    return "landlock_restrict_failed";
  case SandboxError::seccomp_arch_unsupported:
    return "seccomp_arch_unsupported";
  case SandboxError::seccomp_install_failed:
    return "seccomp_install_failed";
  case SandboxError::fork_failed:
    return "fork_failed";
  case SandboxError::pipe_failed:
    return "pipe_failed";
  case SandboxError::waitpid_failed:
    return "waitpid_failed";
  case SandboxError::empty_argv:
    return "empty_argv";
  }
  return "unknown";
}

std::string_view sandbox_profile_name(SandboxProfile profile) noexcept {
  switch (profile) {
  case SandboxProfile::none:
    return "black-flag";
  case SandboxProfile::guarded:
    return "guarded";
  case SandboxProfile::sandboxed:
    return "sandboxed";
  case SandboxProfile::airgap:
    return "airgap";
  }
  return "unknown";
}

std::optional<SandboxProfile> parse_sandbox_profile(std::string_view text) noexcept {
  if (text == "none" || text == "black-flag" || text == "black_flag") {
    return SandboxProfile::none;
  }
  if (text == "guarded") {
    return SandboxProfile::guarded;
  }
  if (text == "sandboxed") {
    return SandboxProfile::sandboxed;
  }
  if (text == "airgap") {
    return SandboxProfile::airgap;
  }
  return std::nullopt;
}

SandboxCapabilities probe_os_sandbox_capabilities() {
  SandboxCapabilities caps;
#if defined(__APPLE__)
  caps.platform = "macos";
  const auto init_fn = load_symbol<SandboxInitFn>("sandbox_init");
  const auto free_fn = load_symbol<SandboxFreeErrorFn>("sandbox_free_error");
  if (init_fn != nullptr && free_fn != nullptr) {
    caps.available = true;
    caps.backend_name = "seatbelt";
    caps.landlock_abi_version = 0;
    caps.supports_network_airgap = true;
    caps.caveats = {
        "macOS Seatbelt (sandbox_init) is deprecated by Apple; initialization fails "
        "closed if unavailable.",
        "Under guarded mode, allow-default permits unspecified Mach/XPC services "
        "except "
        "explicitly denied LaunchServices and Pasteboard.",
        "Workspace .env denial uses SBPL path regex; hardlinks or renamed copies "
        "inside "
        "workspace remain readable.",
    };
  } else {
    caps.available = false;
    caps.backend_name = "none";
    caps.supports_network_airgap = false;
    caps.caveats = {
        "sandbox_init symbol unavailable in libSystem; OS sandboxing cannot be "
        "enforced.",
    };
  }
#elif defined(__linux__)
  caps.platform = "linux";
  const int abi = probe_landlock_abi_version();
  caps.landlock_abi_version = abi;
#if defined(__x86_64__) || defined(__aarch64__)
  constexpr bool kSeccompArchSupported = true;
#else
  constexpr bool kSeccompArchSupported = false;
#endif
  if (abi >= 1 && kSeccompArchSupported) {
    caps.available = true;
    caps.backend_name = "landlock+seccomp";
    caps.supports_network_airgap = true;
    caps.caveats.push_back(
        "Landlock is allow-list only and cannot carve workspace .env or .git/hooks out "
        "of a readable/writable workspace without a Stage 2 mount namespace (bwrap).");
    if (abi < 4) {
      caps.caveats.push_back(
          "Linux kernel Landlock ABI < 4 lacks TCP port rules; sandboxed and airgap "
          "block AF_INET/AF_INET6/AF_PACKET/AF_NETLINK sockets via seccomp-bpf.");
    }
    if (abi < 6) {
      caps.caveats.push_back(
          "Linux kernel Landlock ABI < 6 lacks abstract Unix socket and signal "
          "scoping.");
    }
  } else {
    caps.available = false;
    caps.backend_name = "none";
    caps.supports_network_airgap = false;
    if (abi < 1) {
      caps.caveats.push_back(
          "Linux Landlock LSM is unavailable or disabled in this kernel.");
    }
    if (!kSeccompArchSupported) {
      caps.caveats.push_back(
          "Current Linux CPU architecture is not supported by the built-in seccomp-bpf "
          "filter.");
    }
  }
#else
  caps.platform = "unsupported";
  caps.available = false;
  caps.backend_name = "none";
  caps.landlock_abi_version = 0;
  caps.supports_network_airgap = false;
  caps.caveats = {
      "No native OS kernel sandbox backend is implemented for this platform.",
  };
#endif
  return caps;
}

std::vector<std::filesystem::path>
default_denied_paths(const std::filesystem::path &home_dir) {
  std::vector<std::filesystem::path> out;
  if (const char *auth_home = std::getenv("BLACKBIRD_AUTH_HOME");
      auth_home != nullptr && *auth_home != '\0') {
    push_unique_path(out, std::filesystem::path{auth_home});
  }
  if (const char *online_dir = std::getenv("BLACKBIRD_ONLINE_DIR");
      online_dir != nullptr && *online_dir != '\0') {
    push_unique_path(out, std::filesystem::path{online_dir});
  }
  if (home_dir.empty()) {
    return out;
  }
  constexpr std::array<std::string_view, 20> kHomeSecretRelPaths = {
      ".local/share/blackbird/auth",
      ".local/share/blackbird/peers",
      ".config/blackbird/online",
      ".config/blackbird/lan",
      ".config/blackbird/known_peers.json",
      ".config/mp-outpost",
      ".ssh",
      ".aws",
      ".gnupg",
      ".kube",
      ".docker",
      ".config/gh",
      ".config/gcloud",
      ".azure",
      ".codex",
      ".netrc",
      ".npmrc",
      ".pypirc",
      ".git-credentials",
      "Library/Keychains",
  };
  for (const std::string_view rel : kHomeSecretRelPaths) {
    push_unique_path(out, home_dir / rel);
  }
  return out;
}

Result<std::string> escape_sbpl_string(std::string_view input) {
  if (has_control_or_nul(input)) {
    return Result<std::string>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::control_char_in_path));
  }
  std::string out;
  out.reserve(input.size() + 8U);
  for (const char ch : input) {
    if (ch == '\\' || ch == '"') {
      out.push_back('\\');
    }
    out.push_back(ch);
  }
  return Result<std::string>::success(std::move(out));
}

Result<std::string> build_macos_seatbelt_profile(const SandboxSpec &spec) {
  if (spec.profile == SandboxProfile::none) {
    return Result<std::string>::success("(version 1)\n(allow default)\n");
  }

  auto resolved_res = resolve_sandbox_spec(spec);
  if (!resolved_res.has_value()) {
    return Result<std::string>::failure(resolved_res.error());
  }
  const ResolvedSpec &resolved = resolved_res.value();

  std::string out;
  out.reserve(2048U);
  out.append("(version 1)\n");

  if (resolved.profile == SandboxProfile::guarded) {
    out.append("(allow default)\n");
    out.append("(deny file-write* (subpath \"/\"))\n");
    out.append("(allow file-write*\n  ");
    if (auto rc = append_sbpl_subpath(out, resolved.workspace_root); !rc.has_value()) {
      return Result<std::string>::failure(rc.error());
    }
    out.append("\n  ");
    if (auto rc = append_sbpl_subpath(out, resolved.tmp_dir); !rc.has_value()) {
      return Result<std::string>::failure(rc.error());
    }
    out.append("\n  (literal \"/dev/null\")\n"
               "  (literal \"/dev/tty\")\n"
               "  (literal \"/dev/dtracehelper\")\n"
               "  (regex #\"^/dev/ttys[0-9]+$\"))\n");
    out.append("(deny mach-lookup\n"
               "  (global-name \"com.apple.coreservices.launchservicesd\")\n"
               "  (global-name \"com.apple.pasteboard.1\"))\n");
  } else {
    // sandboxed & airgap: strict deny-default baseline.
    out.append("(deny default)\n");
    out.append("(allow process-exec*)\n");
    out.append("(allow process-fork)\n");
    out.append("(allow signal (target self))\n");
    out.append("(allow sysctl-read)\n");
    out.append("(allow file-read-metadata)\n");
    out.append("(allow file-read-data (literal \"/\"))\n");
    out.append("(allow process-info-pidinfo (target self))\n");
    out.append("(allow file-ioctl\n"
               "  (literal \"/dev/tty\")\n"
               "  (literal \"/dev/null\")\n"
               "  (regex #\"^/dev/ttys[0-9]+$\"))\n");

    constexpr std::array<std::string_view, 10> kSystemReadOnlyPrefixes = {
        "/usr",          "/System",      "/Library",
        "/opt/homebrew", "/usr/local",   "/bin",
        "/sbin",         "/private/etc", "/private/var/db/timezone",
        "/dev",
    };

    out.append("(allow file-read*\n");
    for (const std::string_view prefix : kSystemReadOnlyPrefixes) {
      out.append("  ");
      if (auto rc = append_sbpl_subpath(out, std::filesystem::path{prefix});
          !rc.has_value()) {
        return Result<std::string>::failure(rc.error());
      }
      out.push_back('\n');
    }
    out.append("  ");
    if (auto rc = append_sbpl_subpath(out, resolved.workspace_root); !rc.has_value()) {
      return Result<std::string>::failure(rc.error());
    }
    out.append("\n  ");
    if (auto rc = append_sbpl_subpath(out, resolved.tmp_dir); !rc.has_value()) {
      return Result<std::string>::failure(rc.error());
    }
    for (const auto &extra : resolved.extra_read_paths) {
      out.append("\n  ");
      if (auto rc = append_sbpl_subpath(out, extra); !rc.has_value()) {
        return Result<std::string>::failure(rc.error());
      }
      out.append("\n  ");
      if (auto rc = append_sbpl_literal(out, extra); !rc.has_value()) {
        return Result<std::string>::failure(rc.error());
      }
    }
    out.append(")\n");

    out.append("(allow file-map-executable\n");
    constexpr std::array<std::string_view, 7> kExecPrefixes = {
        "/usr", "/System", "/Library", "/opt/homebrew", "/usr/local", "/bin", "/sbin",
    };
    for (const std::string_view prefix : kExecPrefixes) {
      out.append("  ");
      if (auto rc = append_sbpl_subpath(out, std::filesystem::path{prefix});
          !rc.has_value()) {
        return Result<std::string>::failure(rc.error());
      }
      out.push_back('\n');
    }
    out.append("  ");
    if (auto rc = append_sbpl_subpath(out, resolved.workspace_root); !rc.has_value()) {
      return Result<std::string>::failure(rc.error());
    }
    out.append("\n  ");
    if (auto rc = append_sbpl_subpath(out, resolved.tmp_dir); !rc.has_value()) {
      return Result<std::string>::failure(rc.error());
    }
    for (const auto &extra : resolved.extra_read_paths) {
      out.append("\n  ");
      if (auto rc = append_sbpl_subpath(out, extra); !rc.has_value()) {
        return Result<std::string>::failure(rc.error());
      }
    }
    out.append(")\n");

    out.append("(allow file-write*\n  ");
    if (auto rc = append_sbpl_subpath(out, resolved.workspace_root); !rc.has_value()) {
      return Result<std::string>::failure(rc.error());
    }
    out.append("\n  ");
    if (auto rc = append_sbpl_subpath(out, resolved.tmp_dir); !rc.has_value()) {
      return Result<std::string>::failure(rc.error());
    }
    out.append("\n  (literal \"/dev/null\")\n"
               "  (literal \"/dev/tty\")\n"
               "  (literal \"/dev/dtracehelper\")\n"
               "  (regex #\"^/dev/ttys[0-9]+$\"))\n");

    if (resolved.profile == SandboxProfile::airgap) {
      out.append("(deny network*)\n");
    } else {
      out.append("(deny network-outbound)\n");
    }
  }

  // Workspace .env deny (emitted before explicit denied_paths so denied_paths always
  // takes last-match-wins precedence even over .env.example).
  if (resolved.deny_workspace_dotenv) {
    auto ws_regex = escape_sbpl_regex_literal(resolved.workspace_root.string());
    if (!ws_regex.has_value()) {
      return Result<std::string>::failure(ws_regex.error());
    }
    out.append("(deny file-read* file-write* (regex #\"^");
    out.append(ws_regex.value());
    out.append("(/.*)?/\\.env(\\.[^/]+)?$\"))\n");
    out.append("(allow file-read* (regex #\"^");
    out.append(ws_regex.value());
    out.append("(/.*)?/\\.env\\.(example|sample|template)$\"))\n");
  }

  // Last-match-wins hard denies apply to guarded, sandboxed, and airgap alike.
  out.append("(deny file-write*\n  ");
  if (auto rc = append_sbpl_subpath(out, resolved.workspace_root / ".git" / "hooks");
      !rc.has_value()) {
    return Result<std::string>::failure(rc.error());
  }
  out.append("\n  ");
  if (auto rc = append_sbpl_literal(out, resolved.workspace_root / ".git" / "config");
      !rc.has_value()) {
    return Result<std::string>::failure(rc.error());
  }
  out.append(")\n");

  if (!resolved.denied_paths.empty()) {
    out.append("(deny file-read* file-write*\n");
    for (const auto &denied : resolved.denied_paths) {
      out.append("  ");
      if (auto rc = append_sbpl_subpath(out, denied); !rc.has_value()) {
        return Result<std::string>::failure(rc.error());
      }
      out.append("\n  ");
      if (auto rc = append_sbpl_literal(out, denied); !rc.has_value()) {
        return Result<std::string>::failure(rc.error());
      }
      out.push_back('\n');
    }
    out.append(")\n");
  }

  return Result<std::string>::success(std::move(out));
}

Result<void> apply_os_sandbox_to_current_process(const SandboxSpec &spec) {
  if (spec.profile == SandboxProfile::none) {
    return Result<void>::success();
  }
#if defined(__APPLE__)
  return apply_macos_seatbelt(spec);
#elif defined(__linux__)
  return apply_linux_landlock_and_seccomp(spec);
#else
  return Result<void>::failure(
      make_error(ErrorCode::unsupported, SandboxError::unsupported_platform));
#endif
}

Result<SandboxProbeResult>
run_sandboxed_child_probe(const SandboxSpec &spec, const std::vector<std::string> &argv,
                          const std::optional<std::filesystem::path> &cwd) {
  if (argv.empty() || argv.front().empty()) {
    return Result<SandboxProbeResult>::failure(
        make_error(ErrorCode::invalid_range, SandboxError::empty_argv));
  }

  std::array<ScopedFd, 2> output_pipe;
  std::array<ScopedFd, 2> err_pipe;
  if (!create_cloexec_pipe(output_pipe) || !create_cloexec_pipe(err_pipe)) {
    return Result<SandboxProbeResult>::failure(
        make_error(ErrorCode::io, SandboxError::pipe_failed));
  }

  std::vector<std::string> owned_args = argv;
  std::vector<char *> exec_argv;
  exec_argv.reserve(owned_args.size() + 1U);
  for (auto &arg : owned_args) {
    exec_argv.push_back(arg.data());
  }
  exec_argv.push_back(nullptr);

  std::string cwd_str;
  if (cwd.has_value() && !cwd->empty()) {
    cwd_str = cwd->string();
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    return Result<SandboxProbeResult>::failure(
        make_error(ErrorCode::io, SandboxError::fork_failed));
  }

  if (pid == 0) {
    output_pipe[0].reset();
    err_pipe[0].reset();

    (void)::dup2(output_pipe[1].fd, STDOUT_FILENO);
    (void)::dup2(output_pipe[1].fd, STDERR_FILENO);
    output_pipe[1].reset();

    if (!cwd_str.empty() && ::chdir(cwd_str.c_str()) != 0) {
      const ChildFailurePacket pkt{0, errno, 2U};
      (void)write_all_fd(err_pipe[1].fd, &pkt, sizeof(pkt));
      ::_exit(127);
    }

    const auto apply_res = apply_os_sandbox_to_current_process(spec);
    if (!apply_res.has_value()) {
      const ChildFailurePacket pkt{apply_res.error().detail, errno, 1U};
      (void)write_all_fd(err_pipe[1].fd, &pkt, sizeof(pkt));
      ::_exit(126);
    }

    ::execvp(exec_argv.front(), exec_argv.data());
    const ChildFailurePacket pkt{0, errno, 3U};
    (void)write_all_fd(err_pipe[1].fd, &pkt, sizeof(pkt));
    ::_exit(127);
  }

  output_pipe[1].reset();
  err_pipe[1].reset();

  SandboxProbeResult result;
  constexpr std::size_t kMaxCaptureBytes = 1024U * 1024U;
  std::array<char, 4096> buf{};
  for (;;) {
    const ssize_t n = ::read(output_pipe[0].fd, buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (n == 0) {
      break;
    }
    const auto count = static_cast<std::size_t>(n);
    if (result.output.size() < kMaxCaptureBytes) {
      const std::size_t take = std::min(count, kMaxCaptureBytes - result.output.size());
      result.output.append(buf.data(), take);
    }
  }
  output_pipe[0].reset();

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

  int status = 0;
  pid_t waited = -1;
  do {
    waited = ::waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);

  if (waited < 0) {
    return Result<SandboxProbeResult>::failure(
        make_error(ErrorCode::io, SandboxError::waitpid_failed));
  }

  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    result.term_signal = WTERMSIG(status);
    result.exit_code = 128 + result.term_signal;
  }

  if (failure_bytes == sizeof(failure_pkt) && failure_pkt.stage == 1U) {
    result.sandbox_apply_failed = true;
    result.sandbox_error = static_cast<SandboxError>(failure_pkt.sandbox_error);
  }

  return Result<SandboxProbeResult>::success(std::move(result));
}

} // namespace blackbird::sandbox
