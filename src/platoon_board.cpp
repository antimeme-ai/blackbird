#include "blackbird/platoon_board.hpp"
#include "blackbird/json.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <limits>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace blackbird {
namespace {

constexpr const char *kBoardFile = "board.jsonl";
constexpr const char *kBoardLockFile = "board.lock";
constexpr const char *kRosterFile = "roster.json";
constexpr const char *kRosterLockFile = "roster.lock";
constexpr std::size_t kMaxBoardLineBytes = 1024 * 1024;
constexpr std::size_t kMaxRosterBytes = 16 * 1024 * 1024;
constexpr std::size_t kReadChunkBytes = 64 * 1024;
constexpr std::uint64_t kRosterSchemaVersion = 1;

std::atomic<std::uint64_t> g_tmp_counter{0};

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

Result<void> check_restricted(int fd, bool directory) noexcept {
  struct stat st{};
  if (::fstat(fd, &st) != 0)
    return Result<void>::failure(native_error(errno));
  const bool kind_ok = directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode);
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
  // On Darwin/APFS, concurrent openat(..., O_CREAT | O_NOFOLLOW) on a newly
  // created file can spuriously fail with ENOENT in racing threads/processes.
  // Use a bounded open-existing / create-exclusive loop instead.
  for (int attempt = 0; attempt < 32; ++attempt) {
    int fd = -1;
    do {
      fd = ::openat(dir_fd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      ScopedFd owned{fd};
      auto checked = check_restricted(owned.get(), false);
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
      auto checked = check_restricted(owned.get(), false);
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
  static Result<ScopedFlock> acquire(int dir_fd, const char *lock_name,
                                     bool shared) noexcept {
    auto opened = open_or_create_restricted(dir_fd, lock_name);
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

bool valid_recipient(std::string_view recipient) noexcept {
  return recipient == "all" || valid_platoon_member_id(recipient);
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

Result<void> validate_member(const PlatoonMember &member) noexcept {
  if (!valid_platoon_member_id(member.id))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (platoon_member_state_name(member.state).empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (member.pid < 0 || member.updated_ns < 0)
    return Result<void>::failure({ErrorCode::invalid_range});
  for (const std::string_view field :
       {std::string_view{member.role}, std::string_view{member.provider},
        std::string_view{member.model}, std::string_view{member.workspace},
        std::string_view{member.branch}}) {
    auto ok = validate_text(field, kPlatoonMaxFieldBytes, true);
    if (!ok.has_value())
      return ok;
  }
  return validate_text(member.brief, kPlatoonMaxBriefBytes, true);
}

Result<void> validate_post(const PlatoonPost &post) noexcept {
  if (!valid_platoon_member_id(post.from))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (!valid_recipient(post.to))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (platoon_message_kind_name(post.kind).empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  auto text_ok = validate_text(post.text, kPlatoonMaxMessageBytes, true);
  if (!text_ok.has_value())
    return text_ok;
  if (post.refs.size() > kPlatoonMaxRefs)
    return Result<void>::failure({ErrorCode::capacity});
  for (const auto &ref : post.refs) {
    auto ref_ok = validate_text(ref, kPlatoonMaxRefBytes, false);
    if (!ref_ok.has_value())
      return ref_ok;
  }
  return Result<void>::success();
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

Value member_to_value(const PlatoonMember &member) {
  return Value::object({
      {"id", Value{member.id}},
      {"role", Value{member.role}},
      {"provider", Value{member.provider}},
      {"model", Value{member.model}},
      {"workspace", Value{member.workspace}},
      {"branch", Value{member.branch}},
      {"state", Value{std::string{platoon_member_state_name(member.state)}}},
      {"pid", Value{Number{member.pid}}},
      {"updated_ns", Value{Number{member.updated_ns}}},
      {"brief", Value{member.brief}},
  });
}

Result<PlatoonMember> member_from_value(const Value &value) {
  if (!std::holds_alternative<Value::Object>(value.value()))
    return Result<PlatoonMember>::failure({ErrorCode::corrupt});
  auto id = parse_string_field(value, "id");
  auto role = parse_string_field(value, "role");
  auto provider = parse_string_field(value, "provider");
  auto model = parse_string_field(value, "model");
  auto workspace = parse_string_field(value, "workspace");
  auto branch = parse_string_field(value, "branch");
  auto state_str = parse_string_field(value, "state");
  auto pid = parse_int64_field(value, "pid");
  auto updated_ns = parse_int64_field(value, "updated_ns");
  auto brief = parse_string_field(value, "brief");
  if (!id.has_value() || !role.has_value() || !provider.has_value() ||
      !model.has_value() || !workspace.has_value() || !branch.has_value() ||
      !state_str.has_value() || !pid.has_value() || !updated_ns.has_value() ||
      !brief.has_value())
    return Result<PlatoonMember>::failure({ErrorCode::corrupt});
  auto state = parse_platoon_member_state(state_str.value());
  if (!state.has_value())
    return Result<PlatoonMember>::failure({ErrorCode::corrupt});
  PlatoonMember result{
      std::move(id).value(),
      std::move(role).value(),
      std::move(provider).value(),
      std::move(model).value(),
      std::move(workspace).value(),
      std::move(branch).value(),
      state.value(),
      pid.value(),
      updated_ns.value(),
      std::move(brief).value(),
  };
  if (!validate_member(result).has_value())
    return Result<PlatoonMember>::failure({ErrorCode::corrupt});
  return Result<PlatoonMember>::success(std::move(result));
}

Value message_to_value(const PlatoonMessage &message) {
  Value::Object fields{
      {"seq", Value{Number{message.seq}}},
      {"timestamp_ns", Value{Number{message.timestamp_ns}}},
      {"from", Value{message.from}},
      {"to", Value{message.to}},
      {"kind", Value{std::string{platoon_message_kind_name(message.kind)}}},
      {"text", Value{message.text}},
  };
  if (!message.refs.empty()) {
    Value::Array refs;
    refs.reserve(message.refs.size());
    for (const auto &ref : message.refs)
      refs.emplace_back(ref);
    fields.emplace_back("refs", Value{std::move(refs)});
  }
  return Value::object(std::move(fields));
}

Result<PlatoonMessage> parse_message_line(std::string_view line) {
  ValueLimits limits{};
  limits.bytes = kMaxBoardLineBytes;
  limits.nodes = 1024;
  limits.depth = 16;
  auto parsed = parse_json(line, limits);
  if (!parsed.has_value())
    return Result<PlatoonMessage>::failure({ErrorCode::corrupt});
  const Value &object = parsed.value();
  if (!std::holds_alternative<Value::Object>(object.value()))
    return Result<PlatoonMessage>::failure({ErrorCode::corrupt});
  auto seq = parse_uint64_field(object, "seq");
  auto timestamp_ns = parse_int64_field(object, "timestamp_ns");
  auto from = parse_string_field(object, "from");
  auto to = parse_string_field(object, "to");
  auto kind_str = parse_string_field(object, "kind");
  auto text = parse_string_field(object, "text");
  if (!seq.has_value() || seq.value() == 0 || !timestamp_ns.has_value() ||
      timestamp_ns.value() < 0 || !from.has_value() || !to.has_value() ||
      !kind_str.has_value() || !text.has_value())
    return Result<PlatoonMessage>::failure({ErrorCode::corrupt});
  auto kind = parse_platoon_message_kind(kind_str.value());
  if (!kind.has_value())
    return Result<PlatoonMessage>::failure({ErrorCode::corrupt});
  if (!valid_platoon_member_id(from.value()) || !valid_recipient(to.value()))
    return Result<PlatoonMessage>::failure({ErrorCode::corrupt});
  if (!validate_text(text.value(), kPlatoonMaxMessageBytes, true).has_value())
    return Result<PlatoonMessage>::failure({ErrorCode::corrupt});

  std::vector<std::string> refs;
  if (const auto *refs_field = object.find("refs")) {
    const auto *array = std::get_if<Value::Array>(&refs_field->value());
    if (!array || array->size() > kPlatoonMaxRefs)
      return Result<PlatoonMessage>::failure({ErrorCode::corrupt});
    refs.reserve(array->size());
    for (const auto &entry : *array) {
      const auto *ref = std::get_if<std::string>(&entry.value());
      if (!ref || !validate_text(*ref, kPlatoonMaxRefBytes, false).has_value())
        return Result<PlatoonMessage>::failure({ErrorCode::corrupt});
      refs.push_back(*ref);
    }
  }

  return Result<PlatoonMessage>::success(PlatoonMessage{
      seq.value(),
      timestamp_ns.value(),
      std::move(from).value(),
      std::move(to).value(),
      kind.value(),
      std::move(text).value(),
      std::move(refs),
  });
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
  auto checked = check_restricted(owned.get(), false);
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

Result<std::vector<PlatoonMember>> read_roster_locked(int dir_fd) {
  bool exists = false;
  auto raw = read_regular_file_bounded(dir_fd, kRosterFile, kMaxRosterBytes, exists);
  if (!raw.has_value())
    return Result<std::vector<PlatoonMember>>::failure(raw.error());
  if (!exists)
    return Result<std::vector<PlatoonMember>>::success({});
  if (raw.value().empty())
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::corrupt});

  auto parsed = parse_json(raw.value());
  if (!parsed.has_value())
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::corrupt});
  const Value &root = parsed.value();
  if (!std::holds_alternative<Value::Object>(root.value()))
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::corrupt});
  auto version = parse_uint64_field(root, "version");
  if (!version.has_value() || version.value() != kRosterSchemaVersion)
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::corrupt});
  const auto *members_field = root.find("members");
  if (!members_field)
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::corrupt});
  const auto *array = std::get_if<Value::Array>(&members_field->value());
  if (!array)
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::corrupt});
  if (array->size() > kPlatoonMaxRosterMembers)
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::capacity});

  std::vector<PlatoonMember> result;
  result.reserve(array->size());
  for (const auto &entry : *array) {
    auto member = member_from_value(entry);
    if (!member.has_value())
      return Result<std::vector<PlatoonMember>>::failure(member.error());
    result.push_back(std::move(member).value());
  }
  std::sort(result.begin(), result.end(),
            [](const PlatoonMember &lhs, const PlatoonMember &rhs) {
              return lhs.id < rhs.id;
            });
  for (std::size_t i = 1; i < result.size(); ++i) {
    if (result[i - 1].id == result[i].id)
      return Result<std::vector<PlatoonMember>>::failure({ErrorCode::corrupt});
  }
  return Result<std::vector<PlatoonMember>>::success(std::move(result));
}

Result<void> write_roster_atomic_locked(int dir_fd,
                                        const std::vector<PlatoonMember> &list) {
  Value::Array encoded_members;
  encoded_members.reserve(list.size());
  for (const auto &entry : list)
    encoded_members.push_back(member_to_value(entry));
  const Value document = Value::object({
      {"version", Value{Number{kRosterSchemaVersion}}},
      {"members", Value{std::move(encoded_members)}},
  });
  auto json = dump_json(document);
  if (!json.has_value())
    return Result<void>::failure(json.error());
  std::string payload = std::move(json).value();
  payload.push_back('\n');

  const auto pid = static_cast<unsigned long long>(::getpid());
  std::string tmp_name;
  ScopedFd tmp_fd;
  for (int attempt = 0; attempt < 64; ++attempt) {
    const auto seq = g_tmp_counter.fetch_add(1, std::memory_order_relaxed);
    tmp_name = "roster.tmp." + std::to_string(pid) + "." + std::to_string(seq);
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

  if (::renameat(dir_fd, cleanup.c_str(), dir_fd, kRosterFile) != 0)
    return Result<void>::failure(native_error(errno));
  cleanup.dismiss();
  return fsync_fd(dir_fd);
}

Result<void> quarantine_roster_locked(int dir_fd) {
  const auto pid = static_cast<unsigned long long>(::getpid());
  const auto ns = static_cast<unsigned long long>(wall_now_ns());
  const std::string base =
      "roster.corrupt." + std::to_string(pid) + "." + std::to_string(ns);
  std::string target = base;
  for (int attempt = 0; attempt < 64; ++attempt) {
    if (::faccessat(dir_fd, target.c_str(), F_OK, AT_SYMLINK_NOFOLLOW) != 0 &&
        errno == ENOENT) {
      break;
    }
    const auto seq = g_tmp_counter.fetch_add(1, std::memory_order_relaxed);
    target = base + "." + std::to_string(seq);
  }
  if (::renameat(dir_fd, kRosterFile, dir_fd, target.c_str()) != 0) {
    if (errno == ENOENT)
      return Result<void>::success();
    return Result<void>::failure(native_error(errno));
  }
  return fsync_fd(dir_fd);
}

Result<ScopedFd> open_or_create_board(int dir_fd, bool &created) noexcept {
  created = false;
  for (int attempt = 0; attempt < 32; ++attempt) {
    int fd = -1;
    do {
      fd = ::openat(dir_fd, kBoardFile, O_RDWR | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      ScopedFd owned{fd};
      auto checked = check_restricted(owned.get(), false);
      if (!checked.has_value())
        return Result<ScopedFd>::failure(checked.error());
      return Result<ScopedFd>::success(std::move(owned));
    }
    if (errno != ENOENT)
      return Result<ScopedFd>::failure(native_error(errno));

    do {
      fd = ::openat(dir_fd, kBoardFile,
                    O_RDWR | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
                    mode_t{0600});
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      created = true;
      ScopedFd owned{fd};
      auto checked = check_restricted(owned.get(), false);
      if (!checked.has_value())
        return Result<ScopedFd>::failure(checked.error());
      return Result<ScopedFd>::success(std::move(owned));
    }
    if (errno != EEXIST && errno != ENOENT)
      return Result<ScopedFd>::failure(native_error(errno));
  }
  return Result<ScopedFd>::failure({ErrorCode::busy, EEXIST});
}

struct BoardScanSummary {
  std::uint64_t last_seq = 0;
  bool empty = true;
  bool ends_with_newline = true;
};

template <class OnMessage>
Result<BoardScanSummary> scan_board_fd(int fd, OnMessage &&on_message) {
  BoardScanSummary summary{};
  std::array<char, kReadChunkBytes> chunk{};
  std::string line;
  bool line_overflowed = false;
  off_t offset = 0;
  bool keep_reading = true;

  while (keep_reading) {
    const ssize_t count = ::pread(fd, chunk.data(), chunk.size(), offset);
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return Result<BoardScanSummary>::failure(native_error(errno));
    }
    if (count == 0)
      break;
    const auto bytes = static_cast<std::size_t>(count);
    offset += static_cast<off_t>(bytes);
    summary.empty = false;
    summary.ends_with_newline = (chunk[bytes - 1] == '\n');

    std::size_t cursor = 0;
    while (cursor < bytes) {
      const std::string_view remaining{chunk.data() + cursor, bytes - cursor};
      const std::size_t nl = remaining.find('\n');
      if (nl == std::string_view::npos) {
        if (!line_overflowed) {
          if (remaining.size() > kMaxBoardLineBytes - line.size()) {
            line.clear();
            line_overflowed = true;
          } else {
            line.append(remaining.data(), remaining.size());
          }
        }
        break;
      }

      if (!line_overflowed) {
        if (nl > kMaxBoardLineBytes - line.size()) {
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
        if (!view.empty()) {
          auto parsed = parse_message_line(view);
          if (parsed.has_value() && parsed.value().seq > summary.last_seq) {
            summary.last_seq = parsed.value().seq;
            if (!on_message(std::move(parsed).value())) {
              keep_reading = false;
              break;
            }
          }
        }
      }
      line.clear();
      line_overflowed = false;
      cursor += nl + 1;
    }
  }
  return Result<BoardScanSummary>::success(summary);
}

} // namespace

std::string_view platoon_message_kind_name(PlatoonMessageKind kind) noexcept {
  switch (kind) {
  case PlatoonMessageKind::brief:
    return "brief";
  case PlatoonMessageKind::message:
    return "message";
  case PlatoonMessageKind::handoff:
    return "handoff";
  case PlatoonMessageKind::blocker:
    return "blocker";
  case PlatoonMessageKind::decision:
    return "decision";
  case PlatoonMessageKind::artifact:
    return "artifact";
  case PlatoonMessageKind::review:
    return "review";
  case PlatoonMessageKind::status:
    return "status";
  }
  return {};
}

Result<PlatoonMessageKind> parse_platoon_message_kind(std::string_view name) noexcept {
  if (name == "brief")
    return Result<PlatoonMessageKind>::success(PlatoonMessageKind::brief);
  if (name == "message")
    return Result<PlatoonMessageKind>::success(PlatoonMessageKind::message);
  if (name == "handoff")
    return Result<PlatoonMessageKind>::success(PlatoonMessageKind::handoff);
  if (name == "blocker")
    return Result<PlatoonMessageKind>::success(PlatoonMessageKind::blocker);
  if (name == "decision")
    return Result<PlatoonMessageKind>::success(PlatoonMessageKind::decision);
  if (name == "artifact")
    return Result<PlatoonMessageKind>::success(PlatoonMessageKind::artifact);
  if (name == "review")
    return Result<PlatoonMessageKind>::success(PlatoonMessageKind::review);
  if (name == "status")
    return Result<PlatoonMessageKind>::success(PlatoonMessageKind::status);
  return Result<PlatoonMessageKind>::failure({ErrorCode::invalid_range});
}

std::string_view platoon_member_state_name(PlatoonMemberState state) noexcept {
  switch (state) {
  case PlatoonMemberState::starting:
    return "starting";
  case PlatoonMemberState::working:
    return "working";
  case PlatoonMemberState::waiting:
    return "waiting";
  case PlatoonMemberState::completed:
    return "completed";
  case PlatoonMemberState::failed:
    return "failed";
  case PlatoonMemberState::stopped:
    return "stopped";
  }
  return {};
}

Result<PlatoonMemberState> parse_platoon_member_state(std::string_view name) noexcept {
  if (name == "starting")
    return Result<PlatoonMemberState>::success(PlatoonMemberState::starting);
  if (name == "working")
    return Result<PlatoonMemberState>::success(PlatoonMemberState::working);
  if (name == "waiting")
    return Result<PlatoonMemberState>::success(PlatoonMemberState::waiting);
  if (name == "completed")
    return Result<PlatoonMemberState>::success(PlatoonMemberState::completed);
  if (name == "failed")
    return Result<PlatoonMemberState>::success(PlatoonMemberState::failed);
  if (name == "stopped")
    return Result<PlatoonMemberState>::success(PlatoonMemberState::stopped);
  return Result<PlatoonMemberState>::failure({ErrorCode::invalid_range});
}

bool valid_platoon_member_id(std::string_view id) noexcept {
  if (id.empty() || id.size() > kPlatoonMaxIdLength || id == "all")
    return false;
  for (const char ch : id) {
    const bool ok =
        (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
    if (!ok)
      return false;
  }
  return true;
}

Result<PlatoonBoard> PlatoonBoard::open(const std::filesystem::path &root) {
  try {
    std::string path_str = root.string();
    if (path_str.empty() || path_str.find('\0') != std::string::npos)
      return Result<PlatoonBoard>::failure({ErrorCode::invalid_range});
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
          return Result<PlatoonBoard>::failure({ErrorCode::io, ec.value()});
      }
      if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
        created = true;
      } else if (errno != EEXIST) {
        return Result<PlatoonBoard>::failure(native_error(errno));
      }
    } else if (errno != EEXIST) {
      return Result<PlatoonBoard>::failure(native_error(errno));
    }

    int fd = -1;
    do {
      fd = ::open(path_str.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
      return Result<PlatoonBoard>::failure(native_error(errno));
    ScopedFd owned{fd};

    if (created && ::fchmod(owned.get(), mode_t{0700}) != 0)
      return Result<PlatoonBoard>::failure(native_error(errno));

    auto checked = check_restricted(owned.get(), true);
    if (!checked.has_value())
      return Result<PlatoonBoard>::failure(checked.error());

    return Result<PlatoonBoard>::success(
        PlatoonBoard{std::filesystem::path{std::move(path_str)}, owned.release()});
  } catch (const std::bad_alloc &) {
    return Result<PlatoonBoard>::failure({ErrorCode::allocation});
  }
}

PlatoonBoard::PlatoonBoard(PlatoonBoard &&other) noexcept
    : root_(std::move(other.root_)), dir_fd_(std::exchange(other.dir_fd_, -1)) {}

PlatoonBoard &PlatoonBoard::operator=(PlatoonBoard &&other) noexcept {
  if (this != &other) {
    if (dir_fd_ >= 0)
      (void)::close(dir_fd_);
    root_ = std::move(other.root_);
    dir_fd_ = std::exchange(other.dir_fd_, -1);
  }
  return *this;
}

PlatoonBoard::~PlatoonBoard() {
  if (dir_fd_ >= 0)
    (void)::close(dir_fd_);
}

Result<PlatoonMember> PlatoonBoard::upsert_member(const PlatoonMember &member) {
  if (dir_fd_ < 0)
    return Result<PlatoonMember>::failure({ErrorCode::stale_handle});
  auto valid = validate_member(member);
  if (!valid.has_value())
    return Result<PlatoonMember>::failure(valid.error());

  try {
    PlatoonMember stored = member;
    if (stored.updated_ns == 0)
      stored.updated_ns = wall_now_ns();

    auto lock = ScopedFlock::acquire(dir_fd_, kRosterLockFile, false);
    if (!lock.has_value())
      return Result<PlatoonMember>::failure(lock.error());

    std::vector<PlatoonMember> list;
    auto existing = read_roster_locked(dir_fd_);
    if (existing.has_value()) {
      list = std::move(existing).value();
    } else if (existing.error().code == ErrorCode::corrupt ||
               existing.error().code == ErrorCode::capacity) {
      auto quarantined = quarantine_roster_locked(dir_fd_);
      if (!quarantined.has_value())
        return Result<PlatoonMember>::failure(quarantined.error());
    } else {
      return Result<PlatoonMember>::failure(existing.error());
    }

    auto found =
        std::find_if(list.begin(), list.end(),
                     [&](const PlatoonMember &entry) { return entry.id == stored.id; });
    if (found != list.end()) {
      *found = stored;
    } else {
      if (list.size() >= kPlatoonMaxRosterMembers)
        return Result<PlatoonMember>::failure({ErrorCode::capacity});
      list.push_back(stored);
      std::sort(list.begin(), list.end(),
                [](const PlatoonMember &lhs, const PlatoonMember &rhs) {
                  return lhs.id < rhs.id;
                });
    }

    auto written = write_roster_atomic_locked(dir_fd_, list);
    if (!written.has_value())
      return Result<PlatoonMember>::failure(written.error());

    return Result<PlatoonMember>::success(std::move(stored));
  } catch (const std::bad_alloc &) {
    return Result<PlatoonMember>::failure({ErrorCode::allocation});
  }
}

Result<std::vector<PlatoonMember>> PlatoonBoard::members() const {
  if (dir_fd_ < 0)
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::stale_handle});
  try {
    auto lock = ScopedFlock::acquire(dir_fd_, kRosterLockFile, true);
    if (!lock.has_value())
      return Result<std::vector<PlatoonMember>>::failure(lock.error());
    return read_roster_locked(dir_fd_);
  } catch (const std::bad_alloc &) {
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::allocation});
  }
}

Result<std::optional<PlatoonMember>> PlatoonBoard::member(std::string_view id) const {
  if (dir_fd_ < 0)
    return Result<std::optional<PlatoonMember>>::failure({ErrorCode::stale_handle});
  if (!valid_platoon_member_id(id))
    return Result<std::optional<PlatoonMember>>::failure({ErrorCode::invalid_identity});
  auto all = members();
  if (!all.has_value())
    return Result<std::optional<PlatoonMember>>::failure(all.error());
  for (auto &entry : all.value()) {
    if (entry.id == id)
      return Result<std::optional<PlatoonMember>>::success(std::move(entry));
  }
  return Result<std::optional<PlatoonMember>>::success(std::nullopt);
}

Result<PlatoonMessage> PlatoonBoard::post(PlatoonPost message) {
  if (dir_fd_ < 0)
    return Result<PlatoonMessage>::failure({ErrorCode::stale_handle});
  auto valid = validate_post(message);
  if (!valid.has_value())
    return Result<PlatoonMessage>::failure(valid.error());

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, kBoardLockFile, false);
    if (!lock.has_value())
      return Result<PlatoonMessage>::failure(lock.error());

    bool created = false;
    auto opened_board = open_or_create_board(dir_fd_, created);
    if (!opened_board.has_value())
      return Result<PlatoonMessage>::failure(opened_board.error());
    ScopedFd board_fd = std::move(opened_board).value();

    auto scanned =
        scan_board_fd(board_fd.get(), [](PlatoonMessage &&) { return true; });
    if (!scanned.has_value())
      return Result<PlatoonMessage>::failure(scanned.error());
    const BoardScanSummary summary = scanned.value();
    if (summary.last_seq == std::numeric_limits<std::uint64_t>::max())
      return Result<PlatoonMessage>::failure({ErrorCode::overflow});

    PlatoonMessage committed{
        summary.last_seq + 1,    wall_now_ns(), std::move(message.from),
        std::move(message.to),   message.kind,  std::move(message.text),
        std::move(message.refs),
    };

    ValueLimits limits{};
    limits.bytes = kMaxBoardLineBytes;
    auto json = dump_json(message_to_value(committed), limits);
    if (!json.has_value())
      return Result<PlatoonMessage>::failure(json.error());

    std::string record;
    const bool needs_recovery_newline = !summary.empty && !summary.ends_with_newline;
    record.reserve(json.value().size() + (needs_recovery_newline ? 3U : 1U));
    if (needs_recovery_newline) {
      // Terminate and invalidate any uncommitted trailing fragment (even one
      // that crashed immediately before its trailing newline) before writing
      // the new record on a fresh line.
      record.append("!\n");
    }
    record.append(json.value());
    record.push_back('\n');

    auto written = write_all_fd(board_fd.get(), record);
    if (!written.has_value())
      return Result<PlatoonMessage>::failure(written.error());
    auto synced = fsync_fd(board_fd.get());
    if (!synced.has_value())
      return Result<PlatoonMessage>::failure(synced.error());
    if (created) {
      auto dir_synced = fsync_fd(dir_fd_);
      if (!dir_synced.has_value())
        return Result<PlatoonMessage>::failure(dir_synced.error());
    }
    return Result<PlatoonMessage>::success(std::move(committed));
  } catch (const std::bad_alloc &) {
    return Result<PlatoonMessage>::failure({ErrorCode::allocation});
  }
}

Result<std::vector<PlatoonMessage>> PlatoonBoard::read(PlatoonReadQuery query) const {
  if (dir_fd_ < 0)
    return Result<std::vector<PlatoonMessage>>::failure({ErrorCode::stale_handle});
  if (!query.recipient_filter.empty() && !valid_recipient(query.recipient_filter))
    return Result<std::vector<PlatoonMessage>>::failure({ErrorCode::invalid_identity});
  if (query.limit == 0)
    return Result<std::vector<PlatoonMessage>>::success({});

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, kBoardLockFile, true);
    if (!lock.has_value())
      return Result<std::vector<PlatoonMessage>>::failure(lock.error());

    int fd = -1;
    do {
      fd = ::openat(dir_fd_, kBoardFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
      if (errno == ENOENT)
        return Result<std::vector<PlatoonMessage>>::success({});
      return Result<std::vector<PlatoonMessage>>::failure(native_error(errno));
    }
    ScopedFd board_fd{fd};
    auto checked = check_restricted(board_fd.get(), false);
    if (!checked.has_value())
      return Result<std::vector<PlatoonMessage>>::failure(checked.error());

    std::vector<PlatoonMessage> result;
    auto scanned = scan_board_fd(board_fd.get(), [&](PlatoonMessage &&msg) {
      if (msg.seq <= query.after_seq)
        return true;
      if (!query.recipient_filter.empty() && msg.to != "all" &&
          msg.to != query.recipient_filter && msg.from != query.recipient_filter)
        return true;
      result.push_back(std::move(msg));
      return result.size() < query.limit;
    });
    if (!scanned.has_value())
      return Result<std::vector<PlatoonMessage>>::failure(scanned.error());
    return Result<std::vector<PlatoonMessage>>::success(std::move(result));
  } catch (const std::bad_alloc &) {
    return Result<std::vector<PlatoonMessage>>::failure({ErrorCode::allocation});
  }
}

Result<std::vector<PlatoonMessage>>
PlatoonBoard::read_since(std::uint64_t after_seq, std::size_t limit,
                         std::string_view recipient_filter) const {
  return read(PlatoonReadQuery{after_seq, limit, recipient_filter});
}

Result<std::uint64_t> PlatoonBoard::latest_seq() const {
  if (dir_fd_ < 0)
    return Result<std::uint64_t>::failure({ErrorCode::stale_handle});
  try {
    auto lock = ScopedFlock::acquire(dir_fd_, kBoardLockFile, true);
    if (!lock.has_value())
      return Result<std::uint64_t>::failure(lock.error());

    int fd = -1;
    do {
      fd = ::openat(dir_fd_, kBoardFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
      if (errno == ENOENT)
        return Result<std::uint64_t>::success(0);
      return Result<std::uint64_t>::failure(native_error(errno));
    }
    ScopedFd board_fd{fd};
    auto checked = check_restricted(board_fd.get(), false);
    if (!checked.has_value())
      return Result<std::uint64_t>::failure(checked.error());

    auto scanned =
        scan_board_fd(board_fd.get(), [](PlatoonMessage &&) { return true; });
    if (!scanned.has_value())
      return Result<std::uint64_t>::failure(scanned.error());
    return Result<std::uint64_t>::success(scanned.value().last_seq);
  } catch (const std::bad_alloc &) {
    return Result<std::uint64_t>::failure({ErrorCode::allocation});
  }
}

} // namespace blackbird
