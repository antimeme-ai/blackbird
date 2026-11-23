#include "blackbird/worktree_lease.hpp"
#include "blackbird/json.hpp"
#include "native_process.hpp"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <limits>
#include <signal.h>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace blackbird {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kMaxBaseRefLength = 256;
constexpr std::size_t kMaxOwnerIdLength = 128;
constexpr std::size_t kMaxMetadataBytes = 64 * 1024;
constexpr std::size_t kMaxGitOutputBytes = 4 * 1024 * 1024;
constexpr auto kGitCommandTimeout = std::chrono::seconds{60};
constexpr std::int64_t kMetadataVersion = 1;

struct LeaseRecord {
  std::string lease_id;
  std::string branch;
  std::string base_ref;
  std::string base_sha;
  std::string owner_id;
  std::int64_t owner_pid = 0;
  std::int64_t created_ns = 0;
};

struct GitOutput {
  int exit_code = 0;
  std::string stdout_bytes;
};

struct PathRelation {
  const fs::path &parent;
  const fs::path &candidate;
};

struct LeaseRoots {
  const fs::path &repo_root;
  const fs::path &lease_root;
};

struct RecordParseInput {
  std::string_view json_text;
  std::string_view expected_lease_id;
};

struct WorktreeLookup {
  const fs::path &repo_root;
  const fs::path &worktree_dir;
};

struct RepoPaths {
  fs::path repo_root;
  fs::path git_dir;
  fs::path git_common_dir;
};

bool is_valid_lease_id(std::string_view id) noexcept {
  if (id.empty() || id.size() > kMaxWorktreeLeaseIdLength)
    return false;
  if (id.front() == '-')
    return false;
  return std::all_of(id.begin(), id.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
  });
}

bool has_forbidden_ref_chars(std::string_view text, bool allow_rev_ops) noexcept {
  for (const char c : text) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte < 0x20U || byte == 0x7fU || c == ' ' || c == '?' || c == '*' || c == '[' ||
        c == '\\' || c == ':')
      return true;
    if (!allow_rev_ops && (c == '~' || c == '^'))
      return true;
  }
  return false;
}

bool is_valid_branch_name(std::string_view branch) noexcept {
  if (branch.empty() || branch.size() > kMaxWorktreeBranchLength)
    return false;
  if (!valid_utf8(branch))
    return false;
  if (branch == "HEAD" || branch == "@")
    return false;
  if (branch.front() == '-' || branch.front() == '/' || branch.front() == '.' ||
      branch.back() == '/' || branch.back() == '.')
    return false;
  if (branch.find("..") != std::string_view::npos ||
      branch.find("//") != std::string_view::npos ||
      branch.find("@{") != std::string_view::npos)
    return false;
  if (has_forbidden_ref_chars(branch, false))
    return false;

  std::size_t start = 0;
  while (start <= branch.size()) {
    const std::size_t slash = branch.find('/', start);
    const std::size_t end = slash == std::string_view::npos ? branch.size() : slash;
    const std::string_view component = branch.substr(start, end - start);
    if (component.empty() || component.front() == '.' || component.ends_with(".lock"))
      return false;
    if (slash == std::string_view::npos)
      break;
    start = slash + 1;
  }
  return true;
}

bool is_valid_base_ref(std::string_view ref) noexcept {
  if (ref.empty() || ref.size() > kMaxBaseRefLength)
    return false;
  if (!valid_utf8(ref))
    return false;
  if (ref == "@")
    return false;
  if (ref.front() == '-' || ref.front() == '/' || ref.front() == '.' ||
      ref.back() == '/' || ref.back() == '.')
    return false;
  if (ref.find("..") != std::string_view::npos ||
      ref.find("//") != std::string_view::npos ||
      ref.find("@{") != std::string_view::npos || ref.ends_with(".lock"))
    return false;
  return !has_forbidden_ref_chars(ref, true);
}

bool is_valid_owner_id(std::string_view owner_id) noexcept {
  if (owner_id.size() > kMaxOwnerIdLength)
    return false;
  if (!valid_utf8(owner_id))
    return false;
  for (const char c : owner_id) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte < 0x20U || byte == 0x7fU)
      return false;
  }
  return true;
}

bool is_valid_oid(std::string_view text) noexcept {
  if (text.size() != 40 && text.size() != 64)
    return false;
  return std::all_of(text.begin(), text.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  });
}

bool is_valid_owner_pid(std::int64_t pid) noexcept {
  return pid >= 0 &&
         pid <= static_cast<std::int64_t>(std::numeric_limits<pid_t>::max());
}

std::string trim_trailing_newlines(std::string text) {
  while (!text.empty() && (text.back() == '\n' || text.back() == '\r'))
    text.pop_back();
  return text;
}

bool is_path_same_or_descendant(const PathRelation &relation) {
  const fs::path parent = relation.parent.lexically_normal();
  const fs::path candidate = relation.candidate.lexically_normal();
  auto pit = parent.begin();
  auto cit = candidate.begin();
  for (; pit != parent.end(); ++pit, ++cit) {
    if (cit == candidate.end() || *pit != *cit)
      return false;
  }
  return true;
}

std::int64_t now_utc_ns() noexcept {
  const auto now = std::chrono::system_clock::now();
  return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch())
      .count();
}

enum class ProcessLiveness : std::uint8_t {
  no_pid,
  alive,
  dead,
};

ProcessLiveness check_process_liveness(std::int64_t owner_pid) noexcept {
  if (owner_pid <= 0)
    return ProcessLiveness::no_pid;
  if (owner_pid > static_cast<std::int64_t>(std::numeric_limits<pid_t>::max()))
    return ProcessLiveness::dead;
  const int rc = ::kill(static_cast<pid_t>(owner_pid), 0);
  if (rc == 0)
    return ProcessLiveness::alive;
  if (errno == ESRCH)
    return ProcessLiveness::dead;
  // EPERM or other non-ESRCH error: conservatively treat as alive so we never reap.
  return ProcessLiveness::alive;
}

class FileLock {
public:
  static Result<FileLock> acquire(const fs::path &path, int mode) {
    const int fd =
        ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
      const int err = errno;
      return Result<FileLock>::failure(
          {err == ELOOP ? ErrorCode::conflict : ErrorCode::io, err});
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
      const int err = errno;
      (void)::close(fd);
      return Result<FileLock>::failure({ErrorCode::io, err});
    }
    if (!S_ISREG(st.st_mode)) {
      (void)::close(fd);
      return Result<FileLock>::failure({ErrorCode::conflict});
    }
    while (::flock(fd, mode) != 0) {
      const int err = errno;
      if (err == EINTR)
        continue;
      (void)::close(fd);
      return Result<FileLock>::failure({ErrorCode::io, err});
    }
    return Result<FileLock>::success(FileLock{fd});
  }

  FileLock(const FileLock &) = delete;
  FileLock &operator=(const FileLock &) = delete;
  FileLock(FileLock &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  FileLock &operator=(FileLock &&other) noexcept {
    if (this != &other) {
      release();
      fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
  }
  ~FileLock() { release(); }

private:
  explicit FileLock(int fd) noexcept : fd_(fd) {}
  void release() noexcept {
    if (fd_ >= 0) {
      while (::flock(fd_, LOCK_UN) != 0 && errno == EINTR) {
      }
      (void)::close(fd_);
      fd_ = -1;
    }
  }
  int fd_ = -1;
};

Result<void> ensure_private_directory(const fs::path &dir) {
  std::error_code ec;
  const fs::file_status st = fs::symlink_status(dir, ec);
  if (ec && ec != std::errc::no_such_file_or_directory)
    return Result<void>::failure({ErrorCode::io, ec.value()});
  if (!ec) {
    if (fs::is_symlink(st) || !fs::is_directory(st))
      return Result<void>::failure({ErrorCode::conflict});
  } else {
    if (::mkdir(dir.c_str(), 0700) != 0) {
      const int err = errno;
      if (err != EEXIST)
        return Result<void>::failure({ErrorCode::io, err});
      const fs::file_status recheck = fs::symlink_status(dir, ec);
      if (ec || fs::is_symlink(recheck) || !fs::is_directory(recheck))
        return Result<void>::failure({ErrorCode::conflict});
    }
  }
  if (::chmod(dir.c_str(), 0700) != 0)
    return Result<void>::failure({ErrorCode::io, errno});
  return Result<void>::success();
}

Result<void> sync_directory(const fs::path &dir) {
  const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return Result<void>::failure({ErrorCode::io, errno});
  int rc = 0;
  while ((rc = ::fsync(fd)) != 0 && errno == EINTR) {
  }
  const int sync_err = errno;
  (void)::close(fd);
  if (rc != 0)
    return Result<void>::failure({ErrorCode::io, sync_err});
  return Result<void>::success();
}

Result<std::string> read_regular_file(const fs::path &path) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    const int err = errno;
    if (err == ENOENT)
      return Result<std::string>::failure({ErrorCode::stale_handle, err});
    if (err == ELOOP)
      return Result<std::string>::failure({ErrorCode::conflict, err});
    return Result<std::string>::failure({ErrorCode::io, err});
  }
  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    const int err = errno;
    (void)::close(fd);
    return Result<std::string>::failure({ErrorCode::io, err});
  }
  if (!S_ISREG(st.st_mode)) {
    (void)::close(fd);
    return Result<std::string>::failure({ErrorCode::conflict});
  }
  std::string content;
  char buffer[4096];
  while (true) {
    const ssize_t n = ::read(fd, buffer, sizeof(buffer));
    if (n == 0)
      break;
    if (n < 0) {
      if (errno == EINTR)
        continue;
      const int err = errno;
      (void)::close(fd);
      return Result<std::string>::failure({ErrorCode::io, err});
    }
    const auto count = static_cast<std::size_t>(n);
    if (content.size() > kMaxMetadataBytes ||
        count > kMaxMetadataBytes - content.size()) {
      (void)::close(fd);
      return Result<std::string>::failure({ErrorCode::corrupt});
    }
    content.append(buffer, count);
  }
  (void)::close(fd);
  return Result<std::string>::success(std::move(content));
}

Result<void> write_file_atomic(const fs::path &destination, std::string_view bytes) {
  const fs::path parent = destination.parent_path();
  static std::atomic<std::uint64_t> temp_counter{0};
  const auto pid = static_cast<std::uint64_t>(::getpid());

  int fd = -1;
  fs::path temp_path;
  for (int attempt = 0; attempt < 64; ++attempt) {
    const std::uint64_t seq = temp_counter.fetch_add(1, std::memory_order_relaxed);
    temp_path =
        parent / (".tmp-lease-" + std::to_string(pid) + "-" + std::to_string(seq));
    fd = ::open(temp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0600);
    if (fd >= 0)
      break;
    if (errno == EEXIST)
      continue;
    return Result<void>::failure({ErrorCode::io, errno});
  }
  if (fd < 0)
    return Result<void>::failure({ErrorCode::io, EEXIST});

  auto cleanup_temp = [&]() noexcept { (void)::unlink(temp_path.c_str()); };

  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t written = ::write(fd, bytes.data() + offset, bytes.size() - offset);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      const int err = errno;
      (void)::close(fd);
      cleanup_temp();
      return Result<void>::failure({ErrorCode::io, err});
    }
    if (written == 0) {
      (void)::close(fd);
      cleanup_temp();
      return Result<void>::failure({ErrorCode::io, EIO});
    }
    offset += static_cast<std::size_t>(written);
  }

  int sync_rc = 0;
  while ((sync_rc = ::fsync(fd)) != 0 && errno == EINTR) {
  }
  if (sync_rc != 0) {
    const int err = errno;
    (void)::close(fd);
    cleanup_temp();
    return Result<void>::failure({ErrorCode::io, err});
  }
  if (::close(fd) != 0) {
    const int err = errno;
    cleanup_temp();
    return Result<void>::failure({ErrorCode::io, err});
  }
  if (::rename(temp_path.c_str(), destination.c_str()) != 0) {
    const int err = errno;
    cleanup_temp();
    return Result<void>::failure({ErrorCode::io, err});
  }
  return sync_directory(parent);
}

Result<GitOutput> run_git(const fs::path &directory, std::vector<std::string> subargs,
                          bool read_only) {
  try {
    std::vector<std::string> argv;
    argv.reserve(subargs.size() + 3);
    argv.emplace_back("git");
    argv.emplace_back("-C");
    argv.emplace_back(directory.string());
    for (auto &arg : subargs)
      argv.emplace_back(std::move(arg));

    detail::Child child;
    for (char **entry = environ; entry != nullptr && *entry != nullptr; ++entry) {
      if (!std::string_view{*entry}.starts_with("GIT_"))
        child.child_environment.emplace_back(*entry);
    }
    child.child_environment.emplace_back("GIT_TERMINAL_PROMPT=0");
    if (read_only)
      child.child_environment.emplace_back("GIT_OPTIONAL_LOCKS=0");

    child.start(std::move(argv), {}, false);
    child.close_input();
    int exit_code = 0;
    std::string output = child.collect(detail::Clock::now() + kGitCommandTimeout,
                                       kMaxGitOutputBytes, &exit_code);
    return Result<GitOutput>::success(GitOutput{exit_code, std::move(output)});
  } catch (const Error &error) {
    return Result<GitOutput>::failure(error);
  } catch (const std::bad_alloc &) {
    return Result<GitOutput>::failure({ErrorCode::allocation});
  }
}

Result<std::int64_t> read_int64_field(const Value &object, std::string_view key) {
  const Value *field = object.find(key);
  if (field == nullptr)
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  const auto *number = std::get_if<Number>(&field->value());
  if (number == nullptr)
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  const std::string digits = number->text();
  std::int64_t parsed = 0;
  const auto [ptr, ec] =
      std::from_chars(digits.data(), digits.data() + digits.size(), parsed);
  if (ec != std::errc{} || ptr != digits.data() + digits.size())
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  return Result<std::int64_t>::success(parsed);
}

Result<std::string> read_string_field(const Value &object, std::string_view key) {
  const Value *field = object.find(key);
  if (field == nullptr)
    return Result<std::string>::failure({ErrorCode::corrupt});
  const auto *text = std::get_if<std::string>(&field->value());
  if (text == nullptr)
    return Result<std::string>::failure({ErrorCode::corrupt});
  return Result<std::string>::success(*text);
}

Result<std::string> serialize_record(const LeaseRecord &record) {
  const Value object = Value::object({
      {"version", Value{Number{kMetadataVersion}}},
      {"lease_id", Value{record.lease_id}},
      {"branch", Value{record.branch}},
      {"base_ref", Value{record.base_ref}},
      {"base_sha", Value{record.base_sha}},
      {"owner_id", Value{record.owner_id}},
      {"owner_pid", Value{Number{record.owner_pid}}},
      {"created_ns", Value{Number{record.created_ns}}},
  });
  auto dumped = dump_json(object);
  if (!dumped.has_value())
    return Result<std::string>::failure(dumped.error());
  dumped.value().push_back('\n');
  return dumped;
}

Result<LeaseRecord> parse_record(const RecordParseInput &input) {
  auto parsed = parse_json(input.json_text);
  if (!parsed.has_value())
    return Result<LeaseRecord>::failure({ErrorCode::corrupt});
  const Value &root = parsed.value();
  if (!std::holds_alternative<Value::Object>(root.value()))
    return Result<LeaseRecord>::failure({ErrorCode::corrupt});

  const auto version = read_int64_field(root, "version");
  if (!version.has_value() || version.value() != kMetadataVersion)
    return Result<LeaseRecord>::failure({ErrorCode::corrupt});

  auto lease_id = read_string_field(root, "lease_id");
  auto branch = read_string_field(root, "branch");
  auto base_ref = read_string_field(root, "base_ref");
  auto base_sha = read_string_field(root, "base_sha");
  auto owner_id = read_string_field(root, "owner_id");
  const auto owner_pid = read_int64_field(root, "owner_pid");
  const auto created_ns = read_int64_field(root, "created_ns");

  if (!lease_id.has_value() || !branch.has_value() || !base_ref.has_value() ||
      !base_sha.has_value() || !owner_id.has_value() || !owner_pid.has_value() ||
      !created_ns.has_value())
    return Result<LeaseRecord>::failure({ErrorCode::corrupt});

  if (lease_id.value() != input.expected_lease_id ||
      !is_valid_lease_id(lease_id.value()) || !is_valid_branch_name(branch.value()) ||
      !is_valid_base_ref(base_ref.value()) || !is_valid_oid(base_sha.value()) ||
      !is_valid_owner_id(owner_id.value()) || !is_valid_owner_pid(owner_pid.value()) ||
      created_ns.value() < 0)
    return Result<LeaseRecord>::failure({ErrorCode::corrupt});

  return Result<LeaseRecord>::success(LeaseRecord{
      std::move(lease_id).value(),
      std::move(branch).value(),
      std::move(base_ref).value(),
      std::move(base_sha).value(),
      std::move(owner_id).value(),
      owner_pid.value(),
      created_ns.value(),
  });
}

Result<LeaseRecord> load_lease_record(const fs::path &leases_dir,
                                      std::string_view lease_id) {
  const fs::path file = leases_dir / (std::string{lease_id} + ".json");
  auto bytes = read_regular_file(file);
  if (!bytes.has_value())
    return Result<LeaseRecord>::failure(bytes.error());
  return parse_record({bytes.value(), lease_id});
}

Result<std::vector<LeaseRecord>> load_all_records(const fs::path &leases_dir) {
  std::vector<LeaseRecord> records;
  std::error_code ec;
  fs::directory_iterator it{leases_dir, ec};
  if (ec)
    return Result<std::vector<LeaseRecord>>::failure({ErrorCode::io, ec.value()});

  for (const auto &entry : it) {
    const fs::path &entry_path = entry.path();
    const std::string filename = entry_path.filename().string();
    if (filename == "leases.lock" || filename.starts_with(".tmp-"))
      continue;
    if (!filename.ends_with(".json"))
      continue;
    const std::string_view stem{filename.data(), filename.size() - 5};
    if (!is_valid_lease_id(stem))
      return Result<std::vector<LeaseRecord>>::failure({ErrorCode::corrupt});
    auto record = load_lease_record(leases_dir, stem);
    if (!record.has_value())
      return Result<std::vector<LeaseRecord>>::failure(record.error());
    records.push_back(std::move(record).value());
  }

  std::sort(records.begin(), records.end(),
            [](const LeaseRecord &lhs, const LeaseRecord &rhs) {
              if (lhs.created_ns != rhs.created_ns)
                return lhs.created_ns < rhs.created_ns;
              return lhs.lease_id < rhs.lease_id;
            });
  return Result<std::vector<LeaseRecord>>::success(std::move(records));
}

Result<bool> branch_exists(const fs::path &repo_root, std::string_view branch) {
  auto output = run_git(
      repo_root,
      {"show-ref", "--verify", "--quiet", "refs/heads/" + std::string{branch}}, true);
  if (!output.has_value())
    return Result<bool>::failure(output.error());
  return Result<bool>::success(output.value().exit_code == 0);
}

Result<bool> branch_checked_out_anywhere(const fs::path &repo_root,
                                         std::string_view branch) {
  auto output = run_git(repo_root, {"worktree", "list", "--porcelain"}, true);
  if (!output.has_value())
    return Result<bool>::failure(output.error());
  if (output.value().exit_code != 0)
    return Result<bool>::failure({ErrorCode::io, output.value().exit_code});
  const std::string needle = "\nbranch refs/heads/" + std::string{branch} + "\n";
  const std::string haystack = "\n" + output.value().stdout_bytes + "\n";
  return Result<bool>::success(haystack.find(needle) != std::string::npos);
}

Result<bool> is_registered_worktree(const WorktreeLookup &lookup) {
  auto output = run_git(lookup.repo_root, {"worktree", "list", "--porcelain"}, true);
  if (!output.has_value())
    return Result<bool>::failure(output.error());
  if (output.value().exit_code != 0)
    return Result<bool>::failure({ErrorCode::io, output.value().exit_code});
  std::error_code ec;
  const fs::path canonical_wt = fs::canonical(lookup.worktree_dir, ec);
  const std::string path_str =
      ec ? lookup.worktree_dir.string() : canonical_wt.string();
  const std::string needle = "\nworktree " + path_str + "\n";
  const std::string haystack = "\n" + output.value().stdout_bytes + "\n";
  return Result<bool>::success(haystack.find(needle) != std::string::npos);
}

Result<bool> is_own_git_toplevel(const fs::path &canonical_wt) {
  auto top_res = run_git(canonical_wt, {"rev-parse", "--show-toplevel"}, true);
  if (!top_res.has_value())
    return Result<bool>::failure(top_res.error());
  if (top_res.value().exit_code != 0)
    return Result<bool>::success(false);
  const std::string toplevel_str =
      trim_trailing_newlines(std::move(top_res).value().stdout_bytes);
  if (toplevel_str.empty())
    return Result<bool>::success(false);
  std::error_code ec;
  const fs::path canonical_top = fs::canonical(fs::path{toplevel_str}, ec);
  if (ec)
    return Result<bool>::success(false);
  return Result<bool>::success(canonical_top == canonical_wt);
}

bool lease_root_conflicts_with_repo(const fs::path &candidate_lease,
                                    const RepoPaths &repo_paths) {
  return candidate_lease == repo_paths.repo_root ||
         is_path_same_or_descendant({candidate_lease, repo_paths.repo_root}) ||
         is_path_same_or_descendant({repo_paths.git_dir, candidate_lease}) ||
         is_path_same_or_descendant({repo_paths.git_common_dir, candidate_lease}) ||
         is_path_same_or_descendant({candidate_lease, repo_paths.git_dir}) ||
         is_path_same_or_descendant({candidate_lease, repo_paths.git_common_dir});
}

Result<fs::path> resolve_git_dir_arg(const fs::path &repo_input,
                                     std::string_view flag) {
  auto res = run_git(repo_input, {"rev-parse", std::string{flag}}, true);
  if (!res.has_value())
    return Result<fs::path>::failure(res.error());
  if (res.value().exit_code != 0)
    return Result<fs::path>::failure({ErrorCode::invalid_range, res.value().exit_code});
  const std::string raw = trim_trailing_newlines(std::move(res).value().stdout_bytes);
  if (raw.empty())
    return Result<fs::path>::failure({ErrorCode::invalid_range});
  fs::path p{raw};
  if (p.is_relative())
    p = repo_input / p;
  std::error_code ec;
  const fs::path canonical_p = fs::canonical(p, ec);
  if (ec)
    return Result<fs::path>::failure({ErrorCode::io, ec.value()});
  return Result<fs::path>::success(canonical_p);
}

Result<WorktreeLeaseInfo> inspect_lease(const LeaseRecord &record,
                                        const LeaseRoots &roots) {
  WorktreeLeaseInfo info;
  info.lease_id = record.lease_id;
  info.branch = record.branch;
  info.base_ref = record.base_ref;
  info.base_sha = record.base_sha;
  info.owner_id = record.owner_id;
  info.owner_pid = record.owner_pid;
  info.created_ns = record.created_ns;
  info.path = roots.lease_root / record.lease_id;
  info.owner_alive = check_process_liveness(record.owner_pid) == ProcessLiveness::alive;

  std::error_code ec;
  const fs::file_status st = fs::symlink_status(info.path, ec);
  if (ec && ec != std::errc::no_such_file_or_directory)
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::io, ec.value()});
  if (ec) {
    info.worktree_present = false;
    return Result<WorktreeLeaseInfo>::success(std::move(info));
  }
  if (fs::is_symlink(st) || !fs::is_directory(st))
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::conflict});

  const fs::path canonical_wt = fs::canonical(info.path, ec);
  if (ec || canonical_wt == roots.repo_root ||
      !is_path_same_or_descendant({roots.lease_root, canonical_wt}))
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::conflict});

  info.worktree_present = true;

  // Verify the directory is actually a registered linked worktree whose git toplevel
  // is itself before querying git status/HEAD; otherwise git would walk up to an
  // enclosing parent repository if .git were missing or corrupt.
  auto registered = is_registered_worktree({roots.repo_root, canonical_wt});
  if (!registered.has_value())
    return Result<WorktreeLeaseInfo>::failure(registered.error());
  auto own_top = is_own_git_toplevel(canonical_wt);
  if (!own_top.has_value())
    return Result<WorktreeLeaseInfo>::failure(own_top.error());
  if (!registered.value() || !own_top.value()) {
    info.dirty = true;
    return Result<WorktreeLeaseInfo>::success(std::move(info));
  }

  auto head_res = run_git(info.path, {"rev-parse", "--verify", "HEAD"}, true);
  if (!head_res.has_value())
    return Result<WorktreeLeaseInfo>::failure(head_res.error());
  if (head_res.value().exit_code == 0) {
    const std::string sha =
        trim_trailing_newlines(std::move(head_res).value().stdout_bytes);
    if (is_valid_oid(sha))
      info.head_sha = sha;
  }

  auto status_res = run_git(info.path, {"status", "--porcelain"}, true);
  if (!status_res.has_value())
    return Result<WorktreeLeaseInfo>::failure(status_res.error());
  if (status_res.value().exit_code != 0) {
    // Conservatively mark dirty if git status fails so work is never silently
    // destroyed.
    info.dirty = true;
  } else {
    info.dirty = !status_res.value().stdout_bytes.empty();
  }

  if (!info.head_sha.empty()) {
    auto ahead_res =
        run_git(info.path, {"rev-list", "--count", record.base_sha + "..HEAD"}, true);
    if (!ahead_res.has_value())
      return Result<WorktreeLeaseInfo>::failure(ahead_res.error());
    if (ahead_res.value().exit_code == 0) {
      const std::string count_str =
          trim_trailing_newlines(std::move(ahead_res).value().stdout_bytes);
      std::uint64_t ahead = 0;
      const auto [ptr, parse_ec] =
          std::from_chars(count_str.data(), count_str.data() + count_str.size(), ahead);
      if (parse_ec == std::errc{} && ptr == count_str.data() + count_str.size())
        info.commits_ahead = ahead;
    }
  }

  return Result<WorktreeLeaseInfo>::success(std::move(info));
}

Result<void> remove_lease_locked(const LeaseRoots &roots, const LeaseRecord &record,
                                 bool force) {
  const fs::path leases_dir = roots.lease_root / ".leases";
  const fs::path wt_path = roots.lease_root / record.lease_id;
  if (wt_path.parent_path() != roots.lease_root ||
      wt_path.filename() != record.lease_id)
    return Result<void>::failure({ErrorCode::conflict});

  std::error_code ec;
  const fs::file_status st = fs::symlink_status(wt_path, ec);
  if (ec && ec != std::errc::no_such_file_or_directory)
    return Result<void>::failure({ErrorCode::io, ec.value()});

  if (!ec) {
    if (fs::is_symlink(st) || !fs::is_directory(st))
      return Result<void>::failure({ErrorCode::conflict});

    const fs::path canonical_wt = fs::canonical(wt_path, ec);
    if (ec || canonical_wt == roots.repo_root ||
        !is_path_same_or_descendant({roots.lease_root, canonical_wt}))
      return Result<void>::failure({ErrorCode::conflict});

    auto registered = is_registered_worktree({roots.repo_root, canonical_wt});
    if (!registered.has_value())
      return Result<void>::failure(registered.error());

    if (registered.value()) {
      if (!force) {
        auto own_top = is_own_git_toplevel(canonical_wt);
        if (!own_top.has_value())
          return Result<void>::failure(own_top.error());
        if (!own_top.value())
          return Result<void>::failure({ErrorCode::conflict});

        auto status_res = run_git(wt_path, {"status", "--porcelain"}, true);
        if (!status_res.has_value())
          return Result<void>::failure(status_res.error());
        if (status_res.value().exit_code != 0 ||
            !status_res.value().stdout_bytes.empty())
          return Result<void>::failure({ErrorCode::conflict});
      }

      std::vector<std::string> remove_args{"worktree", "remove"};
      if (force)
        remove_args.emplace_back("--force");
      remove_args.emplace_back("--");
      remove_args.emplace_back(wt_path.string());

      auto rm_res = run_git(roots.repo_root, std::move(remove_args), false);
      if (!rm_res.has_value())
        return Result<void>::failure(rm_res.error());
      if (rm_res.value().exit_code != 0)
        return Result<void>::failure({ErrorCode::io, rm_res.value().exit_code});
    } else {
      if (!force)
        return Result<void>::failure({ErrorCode::conflict});
      fs::remove_all(wt_path, ec);
      if (ec)
        return Result<void>::failure({ErrorCode::io, ec.value()});
    }
  }

  auto prune_res = run_git(roots.repo_root, {"worktree", "prune"}, false);
  if (!prune_res.has_value())
    return Result<void>::failure(prune_res.error());
  if (prune_res.value().exit_code != 0)
    return Result<void>::failure({ErrorCode::io, prune_res.value().exit_code});

  const fs::path meta_file = leases_dir / (record.lease_id + ".json");
  if (::unlink(meta_file.c_str()) != 0 && errno != ENOENT)
    return Result<void>::failure({ErrorCode::io, errno});
  return sync_directory(leases_dir);
}

} // namespace

WorktreeLeaseManager::WorktreeLeaseManager(WorktreeLeaseConfig config)
    : repo_root_(std::move(config.repo_root)),
      lease_root_(std::move(config.lease_root)), max_leases_(config.max_leases) {}

Result<WorktreeLeaseManager>
WorktreeLeaseManager::open(const WorktreeLeaseConfig &config) {
  if (config.max_leases < kMinWorktreeLeases || config.max_leases > kMaxWorktreeLeases)
    return Result<WorktreeLeaseManager>::failure({ErrorCode::invalid_range});
  if (config.repo_root.empty() || config.lease_root.empty())
    return Result<WorktreeLeaseManager>::failure({ErrorCode::invalid_range});

  std::error_code ec;
  const fs::path canonical_repo_input = fs::canonical(config.repo_root, ec);
  if (ec || !fs::is_directory(canonical_repo_input, ec))
    return Result<WorktreeLeaseManager>::failure(
        {ErrorCode::invalid_range, ec.value()});

  auto top_res = run_git(canonical_repo_input, {"rev-parse", "--show-toplevel"}, true);
  if (!top_res.has_value())
    return Result<WorktreeLeaseManager>::failure(top_res.error());
  if (top_res.value().exit_code != 0)
    return Result<WorktreeLeaseManager>::failure(
        {ErrorCode::invalid_range, top_res.value().exit_code});
  const std::string toplevel_str =
      trim_trailing_newlines(std::move(top_res).value().stdout_bytes);
  if (toplevel_str.empty())
    return Result<WorktreeLeaseManager>::failure({ErrorCode::invalid_range});

  const fs::path canonical_repo = fs::canonical(fs::path{toplevel_str}, ec);
  if (ec)
    return Result<WorktreeLeaseManager>::failure({ErrorCode::io, ec.value()});

  auto git_dir = resolve_git_dir_arg(canonical_repo_input, "--git-dir");
  if (!git_dir.has_value())
    return Result<WorktreeLeaseManager>::failure(git_dir.error());
  auto git_common_dir = resolve_git_dir_arg(canonical_repo_input, "--git-common-dir");
  if (!git_common_dir.has_value())
    return Result<WorktreeLeaseManager>::failure(git_common_dir.error());

  const RepoPaths repo_paths{canonical_repo, std::move(git_dir).value(),
                             std::move(git_common_dir).value()};

  // Validate lease_root containment BEFORE creating any directories on disk so
  // rejected configurations (such as inside .git) never mutate the filesystem.
  const fs::path abs_lease = fs::absolute(config.lease_root, ec);
  if (ec)
    return Result<WorktreeLeaseManager>::failure({ErrorCode::io, ec.value()});
  const fs::path pre_lease = fs::weakly_canonical(abs_lease, ec);
  if (ec)
    return Result<WorktreeLeaseManager>::failure({ErrorCode::io, ec.value()});
  if (lease_root_conflicts_with_repo(pre_lease, repo_paths))
    return Result<WorktreeLeaseManager>::failure({ErrorCode::conflict});

  (void)fs::symlink_status(config.lease_root, ec);
  if (ec && ec != std::errc::no_such_file_or_directory)
    return Result<WorktreeLeaseManager>::failure({ErrorCode::io, ec.value()});
  if (ec) {
    fs::create_directories(config.lease_root, ec);
    if (ec)
      return Result<WorktreeLeaseManager>::failure({ErrorCode::io, ec.value()});
    if (::chmod(config.lease_root.c_str(), 0700) != 0)
      return Result<WorktreeLeaseManager>::failure({ErrorCode::io, errno});
  } else if (!fs::is_directory(config.lease_root, ec)) {
    return Result<WorktreeLeaseManager>::failure({ErrorCode::conflict});
  }

  const fs::path canonical_lease = fs::canonical(config.lease_root, ec);
  if (ec)
    return Result<WorktreeLeaseManager>::failure({ErrorCode::io, ec.value()});

  // Re-verify after canonicalization against any concurrent symlink/path changes.
  if (lease_root_conflicts_with_repo(canonical_lease, repo_paths))
    return Result<WorktreeLeaseManager>::failure({ErrorCode::conflict});

  const fs::path leases_meta_dir = canonical_lease / ".leases";
  auto dir_ok = ensure_private_directory(leases_meta_dir);
  if (!dir_ok.has_value())
    return Result<WorktreeLeaseManager>::failure(dir_ok.error());

  return Result<WorktreeLeaseManager>::success(WorktreeLeaseManager{
      WorktreeLeaseConfig{canonical_repo, canonical_lease, config.max_leases}});
}

fs::path WorktreeLeaseManager::leases_dir() const { return lease_root_ / ".leases"; }

fs::path WorktreeLeaseManager::lock_path() const {
  return leases_dir() / "leases.lock";
}

fs::path WorktreeLeaseManager::metadata_path(std::string_view lease_id) const {
  return leases_dir() / (std::string{lease_id} + ".json");
}

fs::path WorktreeLeaseManager::worktree_path(std::string_view lease_id) const {
  return lease_root_ / std::string{lease_id};
}

Result<WorktreeLeaseInfo>
WorktreeLeaseManager::acquire(const WorktreeLeaseRequest &req) {
  if (!is_valid_lease_id(req.lease_id))
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::invalid_identity});
  if (!is_valid_branch_name(req.branch))
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::invalid_range});
  const std::string_view base_ref =
      req.base_ref.empty() ? std::string_view{"HEAD"} : std::string_view{req.base_ref};
  if (!is_valid_base_ref(base_ref))
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::invalid_range});
  if (!is_valid_owner_id(req.owner_id) || !is_valid_owner_pid(req.owner_pid))
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::invalid_range});

  auto dir_ok = ensure_private_directory(leases_dir());
  if (!dir_ok.has_value())
    return Result<WorktreeLeaseInfo>::failure(dir_ok.error());

  auto lock = FileLock::acquire(lock_path(), LOCK_EX);
  if (!lock.has_value())
    return Result<WorktreeLeaseInfo>::failure(lock.error());

  auto existing = load_all_records(leases_dir());
  if (!existing.has_value())
    return Result<WorktreeLeaseInfo>::failure(existing.error());

  for (const auto &rec : existing.value()) {
    if (rec.lease_id == req.lease_id)
      return Result<WorktreeLeaseInfo>::failure({ErrorCode::conflict});
  }
  if (existing.value().size() >= max_leases_)
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::capacity});

  const fs::path target_path = worktree_path(req.lease_id);
  if (target_path.parent_path() != lease_root_ ||
      target_path.filename() != req.lease_id)
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::invalid_identity});

  std::error_code ec;
  (void)fs::symlink_status(target_path, ec);
  if (!ec)
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::conflict});
  if (ec != std::errc::no_such_file_or_directory)
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::io, ec.value()});

  auto base_res = run_git(
      repo_root_, {"rev-parse", "--verify", std::string{base_ref} + "^{commit}"}, true);
  if (!base_res.has_value())
    return Result<WorktreeLeaseInfo>::failure(base_res.error());
  if (base_res.value().exit_code != 0)
    return Result<WorktreeLeaseInfo>::failure(
        {ErrorCode::invalid_range, base_res.value().exit_code});
  const std::string base_sha =
      trim_trailing_newlines(std::move(base_res).value().stdout_bytes);
  if (!is_valid_oid(base_sha))
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::invalid_range});

  auto has_branch = branch_exists(repo_root_, req.branch);
  if (!has_branch.has_value())
    return Result<WorktreeLeaseInfo>::failure(has_branch.error());

  if (req.use_existing_branch) {
    if (!has_branch.value())
      return Result<WorktreeLeaseInfo>::failure({ErrorCode::invalid_range});
    auto checked_out = branch_checked_out_anywhere(repo_root_, req.branch);
    if (!checked_out.has_value())
      return Result<WorktreeLeaseInfo>::failure(checked_out.error());
    if (checked_out.value())
      return Result<WorktreeLeaseInfo>::failure({ErrorCode::conflict});
  } else if (has_branch.value()) {
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::conflict});
  }

  std::vector<std::string> add_args;
  if (req.use_existing_branch) {
    add_args = {"worktree", "add", "--", target_path.string(), req.branch};
  } else {
    add_args = {"worktree",           "add",   "-b", req.branch, "--",
                target_path.string(), base_sha};
  }

  auto add_res = run_git(repo_root_, std::move(add_args), false);
  if (!add_res.has_value())
    return Result<WorktreeLeaseInfo>::failure(add_res.error());
  if (add_res.value().exit_code != 0)
    return Result<WorktreeLeaseInfo>::failure(
        {ErrorCode::io, add_res.value().exit_code});

  LeaseRecord record{
      req.lease_id, req.branch,    std::string{base_ref}, base_sha,
      req.owner_id, req.owner_pid, now_utc_ns(),
  };

  auto json = serialize_record(record);
  auto write_res = json.has_value()
                       ? write_file_atomic(metadata_path(req.lease_id), json.value())
                       : Result<void>::failure(json.error());
  if (!write_res.has_value()) {
    // Roll back the created worktree (and newly created branch) on metadata failure.
    (void)run_git(repo_root_,
                  {"worktree", "remove", "--force", "--", target_path.string()}, false);
    (void)run_git(repo_root_, {"worktree", "prune"}, false);
    if (!req.use_existing_branch)
      (void)run_git(repo_root_, {"branch", "-D", "--", req.branch}, false);
    return Result<WorktreeLeaseInfo>::failure(write_res.error());
  }

  return inspect_lease(record, {repo_root_, lease_root_});
}

Result<std::vector<WorktreeLeaseInfo>> WorktreeLeaseManager::list() const {
  auto lock = FileLock::acquire(lock_path(), LOCK_SH);
  if (!lock.has_value())
    return Result<std::vector<WorktreeLeaseInfo>>::failure(lock.error());

  auto records = load_all_records(leases_dir());
  if (!records.has_value())
    return Result<std::vector<WorktreeLeaseInfo>>::failure(records.error());

  std::vector<WorktreeLeaseInfo> result;
  result.reserve(records.value().size());
  for (const auto &record : records.value()) {
    auto info = inspect_lease(record, {repo_root_, lease_root_});
    if (!info.has_value())
      return Result<std::vector<WorktreeLeaseInfo>>::failure(info.error());
    result.push_back(std::move(info).value());
  }
  return Result<std::vector<WorktreeLeaseInfo>>::success(std::move(result));
}

Result<WorktreeLeaseInfo>
WorktreeLeaseManager::status(std::string_view lease_id) const {
  if (!is_valid_lease_id(lease_id))
    return Result<WorktreeLeaseInfo>::failure({ErrorCode::invalid_identity});

  auto lock = FileLock::acquire(lock_path(), LOCK_SH);
  if (!lock.has_value())
    return Result<WorktreeLeaseInfo>::failure(lock.error());

  auto record = load_lease_record(leases_dir(), lease_id);
  if (!record.has_value())
    return Result<WorktreeLeaseInfo>::failure(record.error());

  return inspect_lease(record.value(), {repo_root_, lease_root_});
}

Result<void> WorktreeLeaseManager::release(std::string_view lease_id, bool force) {
  if (!is_valid_lease_id(lease_id))
    return Result<void>::failure({ErrorCode::invalid_identity});

  auto lock = FileLock::acquire(lock_path(), LOCK_EX);
  if (!lock.has_value())
    return Result<void>::failure(lock.error());

  auto record = load_lease_record(leases_dir(), lease_id);
  if (!record.has_value())
    return Result<void>::failure(record.error());

  return remove_lease_locked({repo_root_, lease_root_}, record.value(), force);
}

Result<WorktreeReclaimReport> WorktreeLeaseManager::reclaim_stale() {
  auto lock = FileLock::acquire(lock_path(), LOCK_EX);
  if (!lock.has_value())
    return Result<WorktreeReclaimReport>::failure(lock.error());

  auto records = load_all_records(leases_dir());
  if (!records.has_value())
    return Result<WorktreeReclaimReport>::failure(records.error());

  WorktreeReclaimReport report;
  for (const auto &record : records.value()) {
    if (check_process_liveness(record.owner_pid) != ProcessLiveness::dead)
      continue;

    auto info = inspect_lease(record, {repo_root_, lease_root_});
    if (!info.has_value())
      return Result<WorktreeReclaimReport>::failure(info.error());

    if (info.value().worktree_present && info.value().dirty) {
      report.orphaned_dirty.push_back(std::move(info).value());
      continue;
    }

    auto removed = remove_lease_locked({repo_root_, lease_root_}, record, false);
    if (!removed.has_value())
      return Result<WorktreeReclaimReport>::failure(removed.error());
    report.reclaimed.push_back(record.lease_id);
  }

  return Result<WorktreeReclaimReport>::success(std::move(report));
}

} // namespace blackbird
