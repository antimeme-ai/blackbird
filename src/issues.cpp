#include "blackbird/issues.hpp"
#include "blackbird/json.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <fcntl.h>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace blackbird {
namespace {

constexpr const char *kEventsFile = "events.jsonl";
constexpr const char *kLockFile = "issues.lock";
constexpr std::size_t kMaxEventLineBytes = 512 * 1024;
constexpr std::size_t kReadChunkBytes = 64 * 1024;

Error native_error(int err) noexcept {
  if (err == EINTR)
    return {ErrorCode::interrupted, err};
  if (err == ENOTSUP)
    return {ErrorCode::unsupported, err};
  return {ErrorCode::io, err};
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

// Accepts 0700/0600 (newly created) as well as Git-checked-out 0755/0644 owned
// by the current effective UID, while rejecting symlinks, non-owned paths, and
// group/world-writable modes.
Result<void> check_safe_owned(int fd, bool directory) noexcept {
  struct stat st{};
  if (::fstat(fd, &st) != 0)
    return Result<void>::failure(native_error(errno));
  const bool kind_ok = directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode);
  if (!kind_ok || st.st_uid != ::geteuid() || (st.st_mode & 0022) != 0)
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

Result<ScopedFd> open_or_create_lock_file(int dir_fd, const char *name) noexcept {
  // On Darwin/APFS, concurrent openat(..., O_CREAT | O_NOFOLLOW) on a newly
  // created file can spuriously fail with ENOENT in racing threads/processes.
  for (int attempt = 0; attempt < 32; ++attempt) {
    int fd = -1;
    do {
      fd = ::openat(dir_fd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      ScopedFd owned{fd};
      auto checked = check_safe_owned(owned.get(), false);
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
      auto checked = check_safe_owned(owned.get(), false);
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
  static Result<ScopedFlock> acquire(int dir_fd, bool shared) noexcept {
    auto opened = open_or_create_lock_file(dir_fd, kLockFile);
    if (!opened.has_value())
      return Result<ScopedFlock>::failure(opened.error());
    ScopedFd owned = std::move(opened).value();
    const int op = shared ? LOCK_SH : LOCK_EX;
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

std::int64_t wall_now_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return ns < 0 ? 0 : static_cast<std::int64_t>(ns);
}

Result<void> validate_title(std::string_view title) noexcept {
  if (title.empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (title.size() > kIssueMaxTitleBytes)
    return Result<void>::failure({ErrorCode::capacity});
  for (const char ch : title) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7FU)
      return Result<void>::failure({ErrorCode::invalid_range});
  }
  if (!valid_utf8(title))
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

Result<void> validate_text(std::string_view value, std::size_t max_bytes,
                           bool allow_empty) noexcept {
  if (!allow_empty && value.empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (value.size() > max_bytes)
    return Result<void>::failure({ErrorCode::capacity});
  if (value.find('\0') != std::string_view::npos)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_utf8(value))
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

Result<void> validate_priority(std::uint8_t priority) noexcept {
  if (priority > kIssueMaxPriority)
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

Result<std::vector<std::string>>
validate_and_normalize_labels(const std::vector<std::string> &labels) {
  if (labels.size() > kIssueMaxLabels)
    return Result<std::vector<std::string>>::failure({ErrorCode::capacity});
  std::vector<std::string> out;
  out.reserve(labels.size());
  for (const auto &label : labels) {
    if (!valid_issue_label(label))
      return Result<std::vector<std::string>>::failure({ErrorCode::invalid_range});
    out.push_back(label);
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return Result<std::vector<std::string>>::success(std::move(out));
}

bool issue_id_less(std::string_view lhs, std::string_view rhs) noexcept {
  const auto a = parse_issue_number(lhs);
  const auto b = parse_issue_number(rhs);
  if (a.has_value() && b.has_value())
    return a.value() < b.value();
  return lhs < rhs;
}

Result<std::vector<std::string>>
validate_and_normalize_depends_on(const std::vector<std::string> &deps) {
  if (deps.size() > kIssueMaxDependsOn)
    return Result<std::vector<std::string>>::failure({ErrorCode::capacity});
  std::vector<std::string> out;
  out.reserve(deps.size());
  for (const auto &dep : deps) {
    if (!valid_issue_id(dep))
      return Result<std::vector<std::string>>::failure({ErrorCode::invalid_identity});
    out.push_back(dep);
  }
  std::sort(out.begin(), out.end(), [](const std::string &a, const std::string &b) {
    return issue_id_less(a, b);
  });
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return Result<std::vector<std::string>>::success(std::move(out));
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

Result<std::vector<std::string>> parse_string_array(const Value &field) {
  const auto *array = std::get_if<Value::Array>(&field.value());
  if (!array)
    return Result<std::vector<std::string>>::failure({ErrorCode::corrupt});
  std::vector<std::string> out;
  out.reserve(array->size());
  for (const auto &entry : *array) {
    const auto *str = std::get_if<std::string>(&entry.value());
    if (!str)
      return Result<std::vector<std::string>>::failure({ErrorCode::corrupt});
    out.push_back(*str);
  }
  return Result<std::vector<std::string>>::success(std::move(out));
}

Value string_array_to_value(const std::vector<std::string> &items) {
  Value::Array arr;
  arr.reserve(items.size());
  for (const auto &item : items)
    arr.emplace_back(item);
  return Value{std::move(arr)};
}

struct ReplayedState {
  std::map<std::uint64_t, IssueRecord> issues;
  std::uint64_t max_issue_num = 0;
  std::uint64_t last_event_seq = 0;
  bool empty = true;
  bool ends_with_newline = true;
};

void apply_event_line(std::string_view line, ReplayedState &state) {
  ValueLimits limits{};
  limits.bytes = kMaxEventLineBytes;
  limits.nodes = 4096;
  limits.depth = 16;
  auto parsed = parse_json(line, limits);
  if (!parsed.has_value())
    return;
  const Value &obj = parsed.value();
  if (!std::holds_alternative<Value::Object>(obj.value()))
    return;

  auto op = parse_string_field(obj, "op");
  auto id = parse_string_field(obj, "id");
  auto ts = parse_int64_field(obj, "timestamp_ns");
  if (!op.has_value() || !id.has_value() || !ts.has_value() || ts.value() < 0)
    return;
  auto num = parse_issue_number(id.value());
  if (!num.has_value())
    return;

  if (const auto seq = parse_uint64_field(obj, "seq");
      seq.has_value() && seq.value() > state.last_event_seq) {
    state.last_event_seq = seq.value();
  }

  const std::string_view op_name = op.value();
  if (op_name == "create") {
    auto title = parse_string_field(obj, "title");
    auto body = parse_string_field(obj, "body");
    auto kind_str = parse_string_field(obj, "kind");
    auto priority = parse_uint64_field(obj, "priority");
    if (!title.has_value() || !body.has_value() || !kind_str.has_value() ||
        !priority.has_value() || priority.value() > kIssueMaxPriority) {
      return;
    }
    auto kind = parse_issue_kind(kind_str.value());
    if (!kind.has_value())
      return;
    if (!validate_title(title.value()).has_value() ||
        !validate_text(body.value(), kIssueMaxBodyBytes, true).has_value()) {
      return;
    }

    std::optional<std::string> assignee;
    if (const auto *assignee_field = obj.find("assignee")) {
      if (!std::holds_alternative<std::nullptr_t>(assignee_field->value())) {
        const auto *str = std::get_if<std::string>(&assignee_field->value());
        if (!str || !valid_issue_actor_id(*str))
          return;
        assignee = *str;
      }
    }

    std::vector<std::string> labels;
    if (const auto *labels_field = obj.find("labels")) {
      auto raw_labels = parse_string_array(*labels_field);
      if (!raw_labels.has_value())
        return;
      auto normalized = validate_and_normalize_labels(raw_labels.value());
      if (!normalized.has_value())
        return;
      labels = std::move(normalized).value();
    }

    std::vector<std::string> depends_on;
    if (const auto *deps_field = obj.find("depends_on")) {
      auto raw_deps = parse_string_array(*deps_field);
      if (!raw_deps.has_value())
        return;
      auto normalized = validate_and_normalize_depends_on(raw_deps.value());
      if (!normalized.has_value())
        return;
      depends_on = std::move(normalized).value();
    }

    IssueRecord record;
    record.id = std::move(id).value();
    record.title = std::move(title).value();
    record.body = std::move(body).value();
    record.kind = kind.value();
    record.status = IssueStatus::open;
    record.priority = static_cast<std::uint8_t>(priority.value());
    record.assignee = std::move(assignee);
    record.labels = std::move(labels);
    record.depends_on = std::move(depends_on);
    record.revision = 1;
    record.created_ns = ts.value();
    record.updated_ns = ts.value();

    state.issues[num.value()] = std::move(record);
    if (num.value() > state.max_issue_num)
      state.max_issue_num = num.value();
    return;
  }

  auto it = state.issues.find(num.value());
  if (it == state.issues.end())
    return;
  IssueRecord &rec = it->second;

  if (op_name == "update") {
    IssueRecord next = rec;
    if (const auto *field = obj.find("title")) {
      const auto *str = std::get_if<std::string>(&field->value());
      if (!str || !validate_title(*str).has_value())
        return;
      next.title = *str;
    }
    if (const auto *field = obj.find("body")) {
      const auto *str = std::get_if<std::string>(&field->value());
      if (!str || !validate_text(*str, kIssueMaxBodyBytes, true).has_value())
        return;
      next.body = *str;
    }
    if (const auto *field = obj.find("kind")) {
      const auto *str = std::get_if<std::string>(&field->value());
      if (!str)
        return;
      auto kind = parse_issue_kind(*str);
      if (!kind.has_value())
        return;
      next.kind = kind.value();
    }
    bool status_changed = false;
    if (const auto *field = obj.find("status")) {
      const auto *str = std::get_if<std::string>(&field->value());
      if (!str)
        return;
      auto status = parse_issue_status(*str);
      if (!status.has_value())
        return;
      next.status = status.value();
      status_changed = true;
    }
    if (obj.find("priority") != nullptr) {
      auto prio = parse_uint64_field(obj, "priority");
      if (!prio.has_value() || prio.value() > kIssueMaxPriority)
        return;
      next.priority = static_cast<std::uint8_t>(prio.value());
    }
    if (const auto *field = obj.find("assignee")) {
      if (std::holds_alternative<std::nullptr_t>(field->value())) {
        next.assignee.reset();
      } else {
        const auto *str = std::get_if<std::string>(&field->value());
        if (!str || !valid_issue_actor_id(*str))
          return;
        next.assignee = *str;
      }
    }
    if (const auto *field = obj.find("labels")) {
      auto raw_labels = parse_string_array(*field);
      if (!raw_labels.has_value())
        return;
      auto normalized = validate_and_normalize_labels(raw_labels.value());
      if (!normalized.has_value())
        return;
      next.labels = std::move(normalized).value();
    }
    if (const auto *field = obj.find("close_reason")) {
      const auto *str = std::get_if<std::string>(&field->value());
      if (!str || !validate_text(*str, kIssueMaxCloseReasonBytes, true).has_value())
        return;
      next.close_reason = *str;
    } else if (status_changed && next.status != IssueStatus::closed) {
      next.close_reason.clear();
    }
    if (auto rev = parse_uint64_field(obj, "revision");
        rev.has_value() && rev.value() > 0)
      next.revision = rev.value();
    else if (next.revision < std::numeric_limits<std::uint64_t>::max())
      ++next.revision;
    next.updated_ns = ts.value();
    rec = std::move(next);
    return;
  }

  if (op_name == "claim") {
    auto actor = parse_string_field(obj, "actor");
    if (!actor.has_value() || !valid_issue_actor_id(actor.value()))
      return;
    rec.assignee = std::move(actor).value();
    rec.status = IssueStatus::in_progress;
    if (auto rev = parse_uint64_field(obj, "revision");
        rev.has_value() && rev.value() > 0)
      rec.revision = rev.value();
    else if (rec.revision < std::numeric_limits<std::uint64_t>::max())
      ++rec.revision;
    rec.updated_ns = ts.value();
    return;
  }

  if (op_name == "close") {
    auto reason = parse_string_field(obj, "reason");
    if (!reason.has_value() ||
        !validate_text(reason.value(), kIssueMaxCloseReasonBytes, true).has_value()) {
      return;
    }
    rec.status = IssueStatus::closed;
    rec.close_reason = std::move(reason).value();
    if (auto rev = parse_uint64_field(obj, "revision");
        rev.has_value() && rev.value() > 0)
      rec.revision = rev.value();
    else if (rec.revision < std::numeric_limits<std::uint64_t>::max())
      ++rec.revision;
    rec.updated_ns = ts.value();
    return;
  }

  if (op_name == "add_dependency") {
    auto blocker = parse_string_field(obj, "blocker_id");
    if (!blocker.has_value() || !valid_issue_id(blocker.value()) ||
        blocker.value() == rec.id) {
      return;
    }
    if (std::find(rec.depends_on.begin(), rec.depends_on.end(), blocker.value()) ==
        rec.depends_on.end()) {
      if (rec.depends_on.size() >= kIssueMaxDependsOn)
        return;
      rec.depends_on.push_back(std::move(blocker).value());
      std::sort(rec.depends_on.begin(), rec.depends_on.end(),
                [](const std::string &a, const std::string &b) {
                  return issue_id_less(a, b);
                });
    }
    if (auto rev = parse_uint64_field(obj, "revision");
        rev.has_value() && rev.value() > 0)
      rec.revision = rev.value();
    else if (rec.revision < std::numeric_limits<std::uint64_t>::max())
      ++rec.revision;
    rec.updated_ns = ts.value();
    return;
  }

  if (op_name == "add_comment") {
    auto author = parse_string_field(obj, "author");
    auto text = parse_string_field(obj, "text");
    if (!author.has_value() || !valid_issue_actor_id(author.value()) ||
        !text.has_value() ||
        !validate_text(text.value(), kIssueMaxCommentBytes, false).has_value()) {
      return;
    }
    rec.comments.push_back(
        IssueComment{std::move(author).value(), ts.value(), std::move(text).value()});
    if (auto rev = parse_uint64_field(obj, "revision");
        rev.has_value() && rev.value() > 0)
      rec.revision = rev.value();
    else if (rec.revision < std::numeric_limits<std::uint64_t>::max())
      ++rec.revision;
    rec.updated_ns = ts.value();
  }
}

Result<ReplayedState> scan_events_fd(int fd) {
  ReplayedState state{};
  std::array<char, kReadChunkBytes> chunk{};
  std::string line;
  bool line_overflowed = false;
  off_t offset = 0;

  for (;;) {
    const ssize_t count = ::pread(fd, chunk.data(), chunk.size(), offset);
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return Result<ReplayedState>::failure(native_error(errno));
    }
    if (count == 0)
      break;
    const auto bytes = static_cast<std::size_t>(count);
    offset += static_cast<off_t>(bytes);
    state.empty = false;
    state.ends_with_newline = (chunk[bytes - 1] == '\n');

    std::size_t cursor = 0;
    while (cursor < bytes) {
      const std::string_view remaining{chunk.data() + cursor, bytes - cursor};
      const std::size_t nl = remaining.find('\n');
      if (nl == std::string_view::npos) {
        if (!line_overflowed) {
          if (remaining.size() > kMaxEventLineBytes - line.size()) {
            line.clear();
            line_overflowed = true;
          } else {
            line.append(remaining.data(), remaining.size());
          }
        }
        break;
      }

      if (!line_overflowed) {
        if (nl > kMaxEventLineBytes - line.size()) {
          line.clear();
          line_overflowed = true;
        } else {
          line.append(remaining.data(), nl);
        }
      }

      if (!line_overflowed) {
        std::string_view view{line};
        if (!view.empty() && view.back() == '\r')
          view.remove_suffix(1);
        if (!view.empty())
          apply_event_line(view, state);
      }
      line.clear();
      line_overflowed = false;
      cursor += nl + 1;
    }
  }
  return Result<ReplayedState>::success(std::move(state));
}

Result<ReplayedState> read_state_locked(int dir_fd) {
  int fd = -1;
  do {
    fd = ::openat(dir_fd, kEventsFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ENOENT)
      return Result<ReplayedState>::success(ReplayedState{});
    return Result<ReplayedState>::failure(native_error(errno));
  }
  ScopedFd events_fd{fd};
  auto checked = check_safe_owned(events_fd.get(), false);
  if (!checked.has_value())
    return Result<ReplayedState>::failure(checked.error());
  return scan_events_fd(events_fd.get());
}

struct OpenedEventsWrite {
  ScopedFd fd;
  bool created = false;
};

Result<OpenedEventsWrite> open_events_for_write_locked(int dir_fd) noexcept {
  bool created = false;
  int fd = -1;
  do {
    fd = ::openat(dir_fd, kEventsFile, O_RDWR | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0 && errno == ENOENT) {
    do {
      fd = ::openat(dir_fd, kEventsFile,
                    O_RDWR | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
                    mode_t{0600});
    } while (fd < 0 && errno == EINTR);
    created = (fd >= 0);
  }
  if (fd < 0)
    return Result<OpenedEventsWrite>::failure(native_error(errno));
  ScopedFd owned{fd};
  auto checked = check_safe_owned(owned.get(), false);
  if (!checked.has_value())
    return Result<OpenedEventsWrite>::failure(checked.error());
  return Result<OpenedEventsWrite>::success(
      OpenedEventsWrite{std::move(owned), created});
}

Result<void> append_event_locked(int dir_fd, const OpenedEventsWrite &target,
                                 const ReplayedState &state, const Value &event) {
  ValueLimits limits{};
  limits.bytes = kMaxEventLineBytes;
  limits.nodes = 4096;
  limits.depth = 16;
  auto json = dump_json(event, limits);
  if (!json.has_value())
    return Result<void>::failure(json.error());

  std::string payload;
  const bool needs_recovery = !state.empty && !state.ends_with_newline;
  payload.reserve(json.value().size() + (needs_recovery ? 3U : 1U));
  if (needs_recovery) {
    // Invalidate any uncommitted trailing fragment (including a complete JSON
    // line that crashed before its newline) and start the new record cleanly.
    payload.append("!\n");
  }
  payload.append(json.value());
  payload.push_back('\n');

  auto written = write_all_fd(target.fd.get(), payload);
  if (!written.has_value())
    return written;
  auto synced = fsync_fd(target.fd.get());
  if (!synced.has_value())
    return synced;
  if (target.created) {
    auto dir_synced = fsync_fd(dir_fd);
    if (!dir_synced.has_value())
      return dir_synced;
  }
  return Result<void>::success();
}

struct DependencySearch {
  std::uint64_t start_num = 0;
  std::uint64_t target_num = 0;
};

// Returns true if target_num is reachable from start_num via existing depends_on edges.
bool dependency_reaches(const std::map<std::uint64_t, IssueRecord> &issues,
                        DependencySearch search) {
  std::vector<std::uint64_t> stack;
  std::set<std::uint64_t> visited;
  stack.push_back(search.start_num);
  visited.insert(search.start_num);

  while (!stack.empty()) {
    const std::uint64_t current = stack.back();
    stack.pop_back();
    if (current == search.target_num)
      return true;
    const auto it = issues.find(current);
    if (it == issues.end())
      continue;
    for (const auto &dep_id : it->second.depends_on) {
      const auto dep_num = parse_issue_number(dep_id);
      if (!dep_num.has_value())
        continue;
      if (dep_num.value() == search.target_num)
        return true;
      if (visited.insert(dep_num.value()).second)
        stack.push_back(dep_num.value());
    }
  }
  return false;
}

} // namespace

std::string_view issue_kind_name(IssueKind kind) noexcept {
  switch (kind) {
  case IssueKind::task:
    return "task";
  case IssueKind::bug:
    return "bug";
  case IssueKind::epic:
    return "epic";
  case IssueKind::friction:
    return "friction";
  case IssueKind::research:
    return "research";
  }
  return {};
}

Result<IssueKind> parse_issue_kind(std::string_view name) noexcept {
  if (name == "task")
    return Result<IssueKind>::success(IssueKind::task);
  if (name == "bug")
    return Result<IssueKind>::success(IssueKind::bug);
  if (name == "epic")
    return Result<IssueKind>::success(IssueKind::epic);
  if (name == "friction")
    return Result<IssueKind>::success(IssueKind::friction);
  if (name == "research")
    return Result<IssueKind>::success(IssueKind::research);
  return Result<IssueKind>::failure({ErrorCode::invalid_range});
}

std::string_view issue_status_name(IssueStatus status) noexcept {
  switch (status) {
  case IssueStatus::open:
    return "open";
  case IssueStatus::in_progress:
    return "in_progress";
  case IssueStatus::blocked:
    return "blocked";
  case IssueStatus::closed:
    return "closed";
  }
  return {};
}

Result<IssueStatus> parse_issue_status(std::string_view name) noexcept {
  if (name == "open")
    return Result<IssueStatus>::success(IssueStatus::open);
  if (name == "in_progress")
    return Result<IssueStatus>::success(IssueStatus::in_progress);
  if (name == "blocked")
    return Result<IssueStatus>::success(IssueStatus::blocked);
  if (name == "closed")
    return Result<IssueStatus>::success(IssueStatus::closed);
  return Result<IssueStatus>::failure({ErrorCode::invalid_range});
}

Result<std::uint64_t> parse_issue_number(std::string_view id) noexcept {
  if (id.size() < 4 || !id.starts_with("bb-"))
    return Result<std::uint64_t>::failure({ErrorCode::invalid_identity});
  const std::string_view digits = id.substr(3);
  if (digits.empty() || digits.front() < '1' || digits.front() > '9')
    return Result<std::uint64_t>::failure({ErrorCode::invalid_identity});
  for (const char ch : digits) {
    if (ch < '0' || ch > '9')
      return Result<std::uint64_t>::failure({ErrorCode::invalid_identity});
  }
  std::uint64_t parsed = 0;
  const auto [ptr, ec] =
      std::from_chars(digits.data(), digits.data() + digits.size(), parsed);
  if (ec != std::errc{} || ptr != digits.data() + digits.size() || parsed == 0)
    return Result<std::uint64_t>::failure({ErrorCode::invalid_identity});
  return Result<std::uint64_t>::success(parsed);
}

bool valid_issue_id(std::string_view id) noexcept {
  return parse_issue_number(id).has_value();
}

bool valid_issue_actor_id(std::string_view actor) noexcept {
  if (actor.empty() || actor.size() > kIssueMaxActorLength || actor == "all")
    return false;
  const char first = actor.front();
  if (!((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')))
    return false;
  for (const char ch : actor) {
    const bool ok =
        (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
    if (!ok)
      return false;
  }
  return true;
}

bool valid_issue_label(std::string_view label) noexcept {
  if (label.empty() || label.size() > kIssueMaxLabelLength)
    return false;
  const char first = label.front();
  if (!((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')))
    return false;
  for (const char ch : label) {
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' ||
                    ch == '-' || ch == '.' || ch == ':' || ch == '/';
    if (!ok)
      return false;
  }
  return true;
}

Value to_json(const IssueComment &comment) {
  return Value::object({
      {"author", Value{comment.author}},
      {"timestamp_ns", Value{Number{comment.timestamp_ns}}},
      {"text", Value{comment.text}},
  });
}

Value to_json(const IssueRecord &record) {
  Value::Array encoded_comments;
  encoded_comments.reserve(record.comments.size());
  for (const auto &comment : record.comments)
    encoded_comments.push_back(to_json(comment));

  return Value::object({
      {"id", Value{record.id}},
      {"title", Value{record.title}},
      {"body", Value{record.body}},
      {"kind", Value{std::string{issue_kind_name(record.kind)}}},
      {"status", Value{std::string{issue_status_name(record.status)}}},
      {"priority", Value{Number{static_cast<std::uint64_t>(record.priority)}}},
      {"assignee", record.assignee.has_value() ? Value{*record.assignee} : Value{}},
      {"labels", string_array_to_value(record.labels)},
      {"depends_on", string_array_to_value(record.depends_on)},
      {"comments", Value{std::move(encoded_comments)}},
      {"revision", Value{Number{record.revision}}},
      {"created_ns", Value{Number{record.created_ns}}},
      {"updated_ns", Value{Number{record.updated_ns}}},
      {"close_reason", Value{record.close_reason}},
  });
}

Result<IssueStore> IssueStore::open(const std::filesystem::path &root) {
  try {
    std::string path_str = root.string();
    if (path_str.empty() || path_str.find('\0') != std::string::npos)
      return Result<IssueStore>::failure({ErrorCode::invalid_range});
    while (path_str.size() > 1 && path_str.back() == '/')
      path_str.pop_back();

    bool created = false;
    if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
      created = true;
    } else if (errno == ENOENT) {
      const auto parent = std::filesystem::path{path_str}.parent_path();
      if (!parent.empty()) {
        std::error_code ec;
        (void)std::filesystem::create_directories(parent, ec);
        if (ec)
          return Result<IssueStore>::failure({ErrorCode::io, ec.value()});
      }
      if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
        created = true;
      } else if (errno != EEXIST) {
        return Result<IssueStore>::failure(native_error(errno));
      }
    } else if (errno != EEXIST) {
      return Result<IssueStore>::failure(native_error(errno));
    }

    int fd = -1;
    do {
      fd = ::open(path_str.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
      return Result<IssueStore>::failure(native_error(errno));
    ScopedFd owned{fd};

    if (created && ::fchmod(owned.get(), mode_t{0700}) != 0)
      return Result<IssueStore>::failure(native_error(errno));

    auto checked = check_safe_owned(owned.get(), true);
    if (!checked.has_value())
      return Result<IssueStore>::failure(checked.error());

    return Result<IssueStore>::success(
        IssueStore{std::filesystem::path{std::move(path_str)}, owned.release()});
  } catch (const std::bad_alloc &) {
    return Result<IssueStore>::failure({ErrorCode::allocation});
  }
}

IssueStore::IssueStore(IssueStore &&other) noexcept
    : root_(std::move(other.root_)), dir_fd_(std::exchange(other.dir_fd_, -1)) {}

IssueStore &IssueStore::operator=(IssueStore &&other) noexcept {
  if (this != &other) {
    if (dir_fd_ >= 0)
      (void)::close(dir_fd_);
    root_ = std::move(other.root_);
    dir_fd_ = std::exchange(other.dir_fd_, -1);
  }
  return *this;
}

IssueStore::~IssueStore() {
  if (dir_fd_ >= 0)
    (void)::close(dir_fd_);
}

Result<IssueRecord> IssueStore::create(IssueCreateRequest request) {
  if (dir_fd_ < 0)
    return Result<IssueRecord>::failure({ErrorCode::stale_handle});
  if (auto ok = validate_title(request.title); !ok.has_value())
    return Result<IssueRecord>::failure(ok.error());
  if (auto ok = validate_text(request.body, kIssueMaxBodyBytes, true); !ok.has_value())
    return Result<IssueRecord>::failure(ok.error());
  if (issue_kind_name(request.kind).empty())
    return Result<IssueRecord>::failure({ErrorCode::invalid_range});
  if (auto ok = validate_priority(request.priority); !ok.has_value())
    return Result<IssueRecord>::failure(ok.error());
  if (request.assignee.has_value() && !valid_issue_actor_id(*request.assignee))
    return Result<IssueRecord>::failure({ErrorCode::invalid_identity});

  try {
    auto labels = validate_and_normalize_labels(request.labels);
    if (!labels.has_value())
      return Result<IssueRecord>::failure(labels.error());
    auto depends_on = validate_and_normalize_depends_on(request.depends_on);
    if (!depends_on.has_value())
      return Result<IssueRecord>::failure(depends_on.error());

    auto lock = ScopedFlock::acquire(dir_fd_, false);
    if (!lock.has_value())
      return Result<IssueRecord>::failure(lock.error());

    auto target = open_events_for_write_locked(dir_fd_);
    if (!target.has_value())
      return Result<IssueRecord>::failure(target.error());

    auto scanned = scan_events_fd(target.value().fd.get());
    if (!scanned.has_value())
      return Result<IssueRecord>::failure(scanned.error());
    const ReplayedState &state = scanned.value();

    if (state.max_issue_num == std::numeric_limits<std::uint64_t>::max() ||
        state.last_event_seq == std::numeric_limits<std::uint64_t>::max()) {
      return Result<IssueRecord>::failure({ErrorCode::overflow});
    }
    const std::uint64_t next_num = state.max_issue_num + 1;
    const std::string new_id = "bb-" + std::to_string(next_num);

    for (const auto &dep_id : depends_on.value()) {
      if (dep_id == new_id)
        return Result<IssueRecord>::failure({ErrorCode::conflict});
      const auto dep_num = parse_issue_number(dep_id);
      if (!dep_num.has_value())
        return Result<IssueRecord>::failure({ErrorCode::invalid_identity});
      if (!state.issues.contains(dep_num.value()))
        return Result<IssueRecord>::failure({ErrorCode::stale_handle, ENOENT});
    }

    const std::int64_t now_ns = wall_now_ns();
    IssueRecord created;
    created.id = new_id;
    created.title = std::move(request.title);
    created.body = std::move(request.body);
    created.kind = request.kind;
    created.status = IssueStatus::open;
    created.priority = request.priority;
    created.assignee = std::move(request.assignee);
    created.labels = std::move(labels).value();
    created.depends_on = std::move(depends_on).value();
    created.revision = 1;
    created.created_ns = now_ns;
    created.updated_ns = now_ns;

    Value::Object fields{
        {"seq", Value{Number{state.last_event_seq + 1}}},
        {"op", Value{"create"}},
        {"id", Value{created.id}},
        {"timestamp_ns", Value{Number{now_ns}}},
        {"revision", Value{Number{created.revision}}},
        {"title", Value{created.title}},
        {"body", Value{created.body}},
        {"kind", Value{std::string{issue_kind_name(created.kind)}}},
        {"priority", Value{Number{static_cast<std::uint64_t>(created.priority)}}},
        {"assignee", created.assignee.has_value() ? Value{*created.assignee} : Value{}},
        {"labels", string_array_to_value(created.labels)},
        {"depends_on", string_array_to_value(created.depends_on)},
    };
    auto appended = append_event_locked(dir_fd_, target.value(), state,
                                        Value::object(std::move(fields)));
    if (!appended.has_value())
      return Result<IssueRecord>::failure(appended.error());

    return Result<IssueRecord>::success(std::move(created));
  } catch (const std::bad_alloc &) {
    return Result<IssueRecord>::failure({ErrorCode::allocation});
  }
}

Result<IssueRecord> IssueStore::get(std::string_view id) const {
  if (dir_fd_ < 0)
    return Result<IssueRecord>::failure({ErrorCode::stale_handle});
  const auto num = parse_issue_number(id);
  if (!num.has_value())
    return Result<IssueRecord>::failure(num.error());

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, true);
    if (!lock.has_value())
      return Result<IssueRecord>::failure(lock.error());
    auto state = read_state_locked(dir_fd_);
    if (!state.has_value())
      return Result<IssueRecord>::failure(state.error());
    const auto it = state.value().issues.find(num.value());
    if (it == state.value().issues.end())
      return Result<IssueRecord>::failure({ErrorCode::stale_handle, ENOENT});
    return Result<IssueRecord>::success(it->second);
  } catch (const std::bad_alloc &) {
    return Result<IssueRecord>::failure({ErrorCode::allocation});
  }
}

Result<std::vector<IssueRecord>> IssueStore::list(IssueQuery query) const {
  if (dir_fd_ < 0)
    return Result<std::vector<IssueRecord>>::failure({ErrorCode::stale_handle});
  if (query.status.has_value() && issue_status_name(*query.status).empty())
    return Result<std::vector<IssueRecord>>::failure({ErrorCode::invalid_range});
  if (query.kind.has_value() && issue_kind_name(*query.kind).empty())
    return Result<std::vector<IssueRecord>>::failure({ErrorCode::invalid_range});
  if (query.assignee.has_value() && !valid_issue_actor_id(*query.assignee))
    return Result<std::vector<IssueRecord>>::failure({ErrorCode::invalid_identity});
  if (query.label.has_value() && !valid_issue_label(*query.label))
    return Result<std::vector<IssueRecord>>::failure({ErrorCode::invalid_range});
  if (query.limit == 0)
    return Result<std::vector<IssueRecord>>::success({});

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, true);
    if (!lock.has_value())
      return Result<std::vector<IssueRecord>>::failure(lock.error());
    auto state = read_state_locked(dir_fd_);
    if (!state.has_value())
      return Result<std::vector<IssueRecord>>::failure(state.error());

    std::vector<IssueRecord> result;
    std::size_t matched = 0;
    for (const auto &[num, rec] : state.value().issues) {
      (void)num;
      if (query.status.has_value() && rec.status != *query.status)
        continue;
      if (query.kind.has_value() && rec.kind != *query.kind)
        continue;
      if (query.assignee.has_value() &&
          (!rec.assignee.has_value() || *rec.assignee != *query.assignee)) {
        continue;
      }
      if (query.label.has_value() && std::find(rec.labels.begin(), rec.labels.end(),
                                               *query.label) == rec.labels.end()) {
        continue;
      }
      if (matched < query.offset) {
        ++matched;
        continue;
      }
      result.push_back(rec);
      ++matched;
      if (result.size() >= query.limit)
        break;
    }
    return Result<std::vector<IssueRecord>>::success(std::move(result));
  } catch (const std::bad_alloc &) {
    return Result<std::vector<IssueRecord>>::failure({ErrorCode::allocation});
  }
}

Result<std::vector<IssueRecord>> IssueStore::ready(std::size_t limit) const {
  if (dir_fd_ < 0)
    return Result<std::vector<IssueRecord>>::failure({ErrorCode::stale_handle});
  if (limit == 0)
    return Result<std::vector<IssueRecord>>::success({});

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, true);
    if (!lock.has_value())
      return Result<std::vector<IssueRecord>>::failure(lock.error());
    auto state = read_state_locked(dir_fd_);
    if (!state.has_value())
      return Result<std::vector<IssueRecord>>::failure(state.error());

    const auto &issues = state.value().issues;
    std::vector<std::pair<std::uint64_t, IssueRecord>> candidates;
    for (const auto &[num, rec] : issues) {
      if (rec.status != IssueStatus::open)
        continue;
      bool all_closed = true;
      for (const auto &dep_id : rec.depends_on) {
        const auto dep_num = parse_issue_number(dep_id);
        if (!dep_num.has_value()) {
          all_closed = false;
          break;
        }
        const auto dep_it = issues.find(dep_num.value());
        if (dep_it == issues.end() || dep_it->second.status != IssueStatus::closed) {
          all_closed = false;
          break;
        }
      }
      if (all_closed)
        candidates.emplace_back(num, rec);
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const auto &lhs, const auto &rhs) {
                if (lhs.second.priority != rhs.second.priority)
                  return lhs.second.priority < rhs.second.priority;
                return lhs.first < rhs.first;
              });

    const std::size_t count = std::min(limit, candidates.size());
    std::vector<IssueRecord> result;
    result.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
      result.push_back(std::move(candidates[i].second));
    return Result<std::vector<IssueRecord>>::success(std::move(result));
  } catch (const std::bad_alloc &) {
    return Result<std::vector<IssueRecord>>::failure({ErrorCode::allocation});
  }
}

Result<IssueRecord> IssueStore::update(IssueUpdateRequest request) {
  if (dir_fd_ < 0)
    return Result<IssueRecord>::failure({ErrorCode::stale_handle});
  const auto num = parse_issue_number(request.id);
  if (!num.has_value())
    return Result<IssueRecord>::failure(num.error());
  if (request.assignee.has_value() && request.clear_assignee)
    return Result<IssueRecord>::failure({ErrorCode::invalid_range});
  if (request.title.has_value()) {
    if (auto ok = validate_title(*request.title); !ok.has_value())
      return Result<IssueRecord>::failure(ok.error());
  }
  if (request.body.has_value()) {
    if (auto ok = validate_text(*request.body, kIssueMaxBodyBytes, true);
        !ok.has_value()) {
      return Result<IssueRecord>::failure(ok.error());
    }
  }
  if (request.kind.has_value() && issue_kind_name(*request.kind).empty())
    return Result<IssueRecord>::failure({ErrorCode::invalid_range});
  if (request.status.has_value() && issue_status_name(*request.status).empty())
    return Result<IssueRecord>::failure({ErrorCode::invalid_range});
  if (request.priority.has_value()) {
    if (auto ok = validate_priority(*request.priority); !ok.has_value())
      return Result<IssueRecord>::failure(ok.error());
  }
  if (request.assignee.has_value() && !valid_issue_actor_id(*request.assignee))
    return Result<IssueRecord>::failure({ErrorCode::invalid_identity});
  if (request.close_reason.has_value()) {
    if (auto ok = validate_text(*request.close_reason, kIssueMaxCloseReasonBytes, true);
        !ok.has_value()) {
      return Result<IssueRecord>::failure(ok.error());
    }
  }

  try {
    std::optional<std::vector<std::string>> normalized_labels;
    if (request.labels.has_value()) {
      auto labels = validate_and_normalize_labels(*request.labels);
      if (!labels.has_value())
        return Result<IssueRecord>::failure(labels.error());
      normalized_labels = std::move(labels).value();
    }

    auto lock = ScopedFlock::acquire(dir_fd_, false);
    if (!lock.has_value())
      return Result<IssueRecord>::failure(lock.error());

    auto target = open_events_for_write_locked(dir_fd_);
    if (!target.has_value())
      return Result<IssueRecord>::failure(target.error());

    auto scanned = scan_events_fd(target.value().fd.get());
    if (!scanned.has_value())
      return Result<IssueRecord>::failure(scanned.error());
    const ReplayedState &state = scanned.value();

    const auto it = state.issues.find(num.value());
    if (it == state.issues.end())
      return Result<IssueRecord>::failure({ErrorCode::stale_handle, ENOENT});

    IssueRecord next = it->second;
    if (request.expected_revision.has_value() &&
        next.revision != *request.expected_revision) {
      return Result<IssueRecord>::failure({ErrorCode::conflict});
    }
    if (next.revision == std::numeric_limits<std::uint64_t>::max() ||
        state.last_event_seq == std::numeric_limits<std::uint64_t>::max()) {
      return Result<IssueRecord>::failure({ErrorCode::overflow});
    }

    const std::int64_t now_ns = wall_now_ns();
    ++next.revision;
    next.updated_ns = now_ns;

    Value::Object fields{
        {"seq", Value{Number{state.last_event_seq + 1}}},
        {"op", Value{"update"}},
        {"id", Value{next.id}},
        {"timestamp_ns", Value{Number{now_ns}}},
        {"revision", Value{Number{next.revision}}},
    };

    if (request.title.has_value()) {
      next.title = std::move(*request.title);
      fields.emplace_back("title", Value{next.title});
    }
    if (request.body.has_value()) {
      next.body = std::move(*request.body);
      fields.emplace_back("body", Value{next.body});
    }
    if (request.kind.has_value()) {
      next.kind = *request.kind;
      fields.emplace_back("kind", Value{std::string{issue_kind_name(next.kind)}});
    }
    if (request.status.has_value()) {
      next.status = *request.status;
      fields.emplace_back("status", Value{std::string{issue_status_name(next.status)}});
      if (next.status != IssueStatus::closed && !request.close_reason.has_value())
        next.close_reason.clear();
    }
    if (request.priority.has_value()) {
      next.priority = *request.priority;
      fields.emplace_back("priority",
                          Value{Number{static_cast<std::uint64_t>(next.priority)}});
    }
    if (request.clear_assignee) {
      next.assignee.reset();
      fields.emplace_back("assignee", Value{});
    } else if (request.assignee.has_value()) {
      next.assignee = std::move(*request.assignee);
      fields.emplace_back("assignee", Value{*next.assignee});
    }
    if (normalized_labels.has_value()) {
      next.labels = std::move(*normalized_labels);
      fields.emplace_back("labels", string_array_to_value(next.labels));
    }
    if (request.close_reason.has_value()) {
      next.close_reason = std::move(*request.close_reason);
      fields.emplace_back("close_reason", Value{next.close_reason});
    }

    auto appended = append_event_locked(dir_fd_, target.value(), state,
                                        Value::object(std::move(fields)));
    if (!appended.has_value())
      return Result<IssueRecord>::failure(appended.error());

    return Result<IssueRecord>::success(std::move(next));
  } catch (const std::bad_alloc &) {
    return Result<IssueRecord>::failure({ErrorCode::allocation});
  }
}

Result<IssueRecord> IssueStore::claim(IssueIdRef id, std::string_view actor,
                                      std::optional<std::uint64_t> expected_revision) {
  if (dir_fd_ < 0)
    return Result<IssueRecord>::failure({ErrorCode::stale_handle});
  const auto num = parse_issue_number(id.value);
  if (!num.has_value())
    return Result<IssueRecord>::failure(num.error());
  if (!valid_issue_actor_id(actor))
    return Result<IssueRecord>::failure({ErrorCode::invalid_identity});

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, false);
    if (!lock.has_value())
      return Result<IssueRecord>::failure(lock.error());

    auto target = open_events_for_write_locked(dir_fd_);
    if (!target.has_value())
      return Result<IssueRecord>::failure(target.error());

    auto scanned = scan_events_fd(target.value().fd.get());
    if (!scanned.has_value())
      return Result<IssueRecord>::failure(scanned.error());
    const ReplayedState &state = scanned.value();

    const auto it = state.issues.find(num.value());
    if (it == state.issues.end())
      return Result<IssueRecord>::failure({ErrorCode::stale_handle, ENOENT});

    IssueRecord next = it->second;
    if (expected_revision.has_value() && next.revision != *expected_revision)
      return Result<IssueRecord>::failure({ErrorCode::conflict});
    if (next.status == IssueStatus::closed)
      return Result<IssueRecord>::failure({ErrorCode::conflict});
    if (next.assignee.has_value() && *next.assignee != actor)
      return Result<IssueRecord>::failure({ErrorCode::conflict});
    if (next.revision == std::numeric_limits<std::uint64_t>::max() ||
        state.last_event_seq == std::numeric_limits<std::uint64_t>::max()) {
      return Result<IssueRecord>::failure({ErrorCode::overflow});
    }

    const std::int64_t now_ns = wall_now_ns();
    next.assignee = std::string{actor};
    next.status = IssueStatus::in_progress;
    ++next.revision;
    next.updated_ns = now_ns;

    const Value event = Value::object({
        {"seq", Value{Number{state.last_event_seq + 1}}},
        {"op", Value{"claim"}},
        {"id", Value{next.id}},
        {"timestamp_ns", Value{Number{now_ns}}},
        {"revision", Value{Number{next.revision}}},
        {"actor", Value{*next.assignee}},
    });
    auto appended = append_event_locked(dir_fd_, target.value(), state, event);
    if (!appended.has_value())
      return Result<IssueRecord>::failure(appended.error());

    return Result<IssueRecord>::success(std::move(next));
  } catch (const std::bad_alloc &) {
    return Result<IssueRecord>::failure({ErrorCode::allocation});
  }
}

Result<IssueRecord> IssueStore::close(IssueIdRef id, std::string_view reason,
                                      std::optional<std::uint64_t> expected_revision) {
  if (dir_fd_ < 0)
    return Result<IssueRecord>::failure({ErrorCode::stale_handle});
  const auto num = parse_issue_number(id.value);
  if (!num.has_value())
    return Result<IssueRecord>::failure(num.error());
  if (auto ok = validate_text(reason, kIssueMaxCloseReasonBytes, true); !ok.has_value())
    return Result<IssueRecord>::failure(ok.error());

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, false);
    if (!lock.has_value())
      return Result<IssueRecord>::failure(lock.error());

    auto target = open_events_for_write_locked(dir_fd_);
    if (!target.has_value())
      return Result<IssueRecord>::failure(target.error());

    auto scanned = scan_events_fd(target.value().fd.get());
    if (!scanned.has_value())
      return Result<IssueRecord>::failure(scanned.error());
    const ReplayedState &state = scanned.value();

    const auto it = state.issues.find(num.value());
    if (it == state.issues.end())
      return Result<IssueRecord>::failure({ErrorCode::stale_handle, ENOENT});

    IssueRecord next = it->second;
    if (expected_revision.has_value() && next.revision != *expected_revision)
      return Result<IssueRecord>::failure({ErrorCode::conflict});
    if (next.status == IssueStatus::closed)
      return Result<IssueRecord>::failure({ErrorCode::conflict});
    if (next.revision == std::numeric_limits<std::uint64_t>::max() ||
        state.last_event_seq == std::numeric_limits<std::uint64_t>::max()) {
      return Result<IssueRecord>::failure({ErrorCode::overflow});
    }

    const std::int64_t now_ns = wall_now_ns();
    next.status = IssueStatus::closed;
    next.close_reason = std::string{reason};
    ++next.revision;
    next.updated_ns = now_ns;

    const Value event = Value::object({
        {"seq", Value{Number{state.last_event_seq + 1}}},
        {"op", Value{"close"}},
        {"id", Value{next.id}},
        {"timestamp_ns", Value{Number{now_ns}}},
        {"revision", Value{Number{next.revision}}},
        {"reason", Value{next.close_reason}},
    });
    auto appended = append_event_locked(dir_fd_, target.value(), state, event);
    if (!appended.has_value())
      return Result<IssueRecord>::failure(appended.error());

    return Result<IssueRecord>::success(std::move(next));
  } catch (const std::bad_alloc &) {
    return Result<IssueRecord>::failure({ErrorCode::allocation});
  }
}

Result<IssueRecord> IssueStore::add_dependency(IssueIdRef id,
                                               IssueBlockerRef blocker_id) {
  if (dir_fd_ < 0)
    return Result<IssueRecord>::failure({ErrorCode::stale_handle});
  const auto num = parse_issue_number(id.value);
  if (!num.has_value())
    return Result<IssueRecord>::failure(num.error());
  const auto blocker_num = parse_issue_number(blocker_id.value);
  if (!blocker_num.has_value())
    return Result<IssueRecord>::failure(blocker_num.error());
  if (num.value() == blocker_num.value())
    return Result<IssueRecord>::failure({ErrorCode::conflict});

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, false);
    if (!lock.has_value())
      return Result<IssueRecord>::failure(lock.error());

    auto target = open_events_for_write_locked(dir_fd_);
    if (!target.has_value())
      return Result<IssueRecord>::failure(target.error());

    auto scanned = scan_events_fd(target.value().fd.get());
    if (!scanned.has_value())
      return Result<IssueRecord>::failure(scanned.error());
    const ReplayedState &state = scanned.value();

    const auto it = state.issues.find(num.value());
    if (it == state.issues.end())
      return Result<IssueRecord>::failure({ErrorCode::stale_handle, ENOENT});
    if (!state.issues.contains(blocker_num.value()))
      return Result<IssueRecord>::failure({ErrorCode::stale_handle, ENOENT});

    IssueRecord next = it->second;
    if (std::find(next.depends_on.begin(), next.depends_on.end(), blocker_id.value) !=
        next.depends_on.end()) {
      return Result<IssueRecord>::success(std::move(next));
    }
    if (next.depends_on.size() >= kIssueMaxDependsOn)
      return Result<IssueRecord>::failure({ErrorCode::capacity});

    // Adding edge (num -> blocker_num) creates a cycle iff num is reachable from
    // blocker_num along existing depends_on edges.
    if (dependency_reaches(state.issues,
                           DependencySearch{blocker_num.value(), num.value()}))
      return Result<IssueRecord>::failure({ErrorCode::conflict});

    if (next.revision == std::numeric_limits<std::uint64_t>::max() ||
        state.last_event_seq == std::numeric_limits<std::uint64_t>::max()) {
      return Result<IssueRecord>::failure({ErrorCode::overflow});
    }

    const std::int64_t now_ns = wall_now_ns();
    next.depends_on.emplace_back(blocker_id.value);
    std::sort(
        next.depends_on.begin(), next.depends_on.end(),
        [](const std::string &a, const std::string &b) { return issue_id_less(a, b); });
    ++next.revision;
    next.updated_ns = now_ns;

    const Value event = Value::object({
        {"seq", Value{Number{state.last_event_seq + 1}}},
        {"op", Value{"add_dependency"}},
        {"id", Value{next.id}},
        {"timestamp_ns", Value{Number{now_ns}}},
        {"revision", Value{Number{next.revision}}},
        {"blocker_id", Value{std::string{blocker_id.value}}},
    });
    auto appended = append_event_locked(dir_fd_, target.value(), state, event);
    if (!appended.has_value())
      return Result<IssueRecord>::failure(appended.error());

    return Result<IssueRecord>::success(std::move(next));
  } catch (const std::bad_alloc &) {
    return Result<IssueRecord>::failure({ErrorCode::allocation});
  }
}

Result<IssueRecord> IssueStore::add_comment(IssueIdRef id, IssueActorRef author,
                                            std::string_view text) {
  if (dir_fd_ < 0)
    return Result<IssueRecord>::failure({ErrorCode::stale_handle});
  const auto num = parse_issue_number(id.value);
  if (!num.has_value())
    return Result<IssueRecord>::failure(num.error());
  if (!valid_issue_actor_id(author.value))
    return Result<IssueRecord>::failure({ErrorCode::invalid_identity});
  if (auto ok = validate_text(text, kIssueMaxCommentBytes, false); !ok.has_value())
    return Result<IssueRecord>::failure(ok.error());

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, false);
    if (!lock.has_value())
      return Result<IssueRecord>::failure(lock.error());

    auto target = open_events_for_write_locked(dir_fd_);
    if (!target.has_value())
      return Result<IssueRecord>::failure(target.error());

    auto scanned = scan_events_fd(target.value().fd.get());
    if (!scanned.has_value())
      return Result<IssueRecord>::failure(scanned.error());
    const ReplayedState &state = scanned.value();

    const auto it = state.issues.find(num.value());
    if (it == state.issues.end())
      return Result<IssueRecord>::failure({ErrorCode::stale_handle, ENOENT});

    IssueRecord next = it->second;
    if (next.revision == std::numeric_limits<std::uint64_t>::max() ||
        state.last_event_seq == std::numeric_limits<std::uint64_t>::max()) {
      return Result<IssueRecord>::failure({ErrorCode::overflow});
    }

    const std::int64_t now_ns = wall_now_ns();
    IssueComment comment{std::string{author.value}, now_ns, std::string{text}};
    next.comments.push_back(comment);
    ++next.revision;
    next.updated_ns = now_ns;

    const Value event = Value::object({
        {"seq", Value{Number{state.last_event_seq + 1}}},
        {"op", Value{"add_comment"}},
        {"id", Value{next.id}},
        {"timestamp_ns", Value{Number{now_ns}}},
        {"revision", Value{Number{next.revision}}},
        {"author", Value{comment.author}},
        {"text", Value{comment.text}},
    });
    auto appended = append_event_locked(dir_fd_, target.value(), state, event);
    if (!appended.has_value())
      return Result<IssueRecord>::failure(appended.error());

    return Result<IssueRecord>::success(std::move(next));
  } catch (const std::bad_alloc &) {
    return Result<IssueRecord>::failure({ErrorCode::allocation});
  }
}

} // namespace blackbird
