#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/value.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::size_t kIssueMaxTitleBytes = 256;
inline constexpr std::size_t kIssueMaxBodyBytes = 32 * 1024;
inline constexpr std::size_t kIssueMaxCommentBytes = 32 * 1024;
inline constexpr std::size_t kIssueMaxCloseReasonBytes = 4096;
inline constexpr std::size_t kIssueMaxActorLength = 48;
inline constexpr std::size_t kIssueMaxLabelLength = 48;
inline constexpr std::size_t kIssueMaxLabels = 32;
inline constexpr std::size_t kIssueMaxDependsOn = 64;
inline constexpr std::uint8_t kIssueDefaultPriority = 2;
inline constexpr std::uint8_t kIssueMaxPriority = 3;
inline constexpr std::size_t kIssueDefaultReadyLimit = 64;
inline constexpr std::size_t kIssueDefaultListLimit = 256;

enum class IssueKind : std::uint8_t {
  task,
  bug,
  epic,
  friction,
  research,
};

enum class IssueStatus : std::uint8_t {
  open,
  in_progress,
  blocked,
  closed,
};

std::string_view issue_kind_name(IssueKind kind) noexcept;
Result<IssueKind> parse_issue_kind(std::string_view name) noexcept;

std::string_view issue_status_name(IssueStatus status) noexcept;
Result<IssueStatus> parse_issue_status(std::string_view name) noexcept;

bool valid_issue_id(std::string_view id) noexcept;
Result<std::uint64_t> parse_issue_number(std::string_view id) noexcept;
bool valid_issue_actor_id(std::string_view actor) noexcept;
bool valid_issue_label(std::string_view label) noexcept;

// Distinct non-mutually-convertible view wrappers for multi-string APIs so
// callers can pass string literals, std::string, or std::string_view directly
// without adjacent swappable parameters.
struct IssueIdRef {
  std::string_view value;
  constexpr IssueIdRef(std::string_view id) noexcept : value(id) {}
  constexpr IssueIdRef(const char *id) noexcept : value(id ? id : "") {}
  IssueIdRef(const std::string &id) noexcept : value(id) {}
};

struct IssueBlockerRef {
  std::string_view value;
  constexpr IssueBlockerRef(std::string_view blocker) noexcept : value(blocker) {}
  constexpr IssueBlockerRef(const char *blocker) noexcept
      : value(blocker ? blocker : "") {}
  IssueBlockerRef(const std::string &blocker) noexcept : value(blocker) {}
};

struct IssueActorRef {
  std::string_view value;
  constexpr IssueActorRef(std::string_view actor) noexcept : value(actor) {}
  constexpr IssueActorRef(const char *actor) noexcept : value(actor ? actor : "") {}
  IssueActorRef(const std::string &actor) noexcept : value(actor) {}
};

struct IssueComment {
  std::string author;
  std::int64_t timestamp_ns = 0;
  std::string text;
  bool operator==(const IssueComment &) const = default;
};

struct IssueRecord {
  std::string id;
  std::string title;
  std::string body;
  IssueKind kind = IssueKind::task;
  IssueStatus status = IssueStatus::open;
  std::uint8_t priority = kIssueDefaultPriority;
  std::optional<std::string> assignee;
  std::vector<std::string> labels;
  std::vector<std::string> depends_on;
  std::vector<IssueComment> comments;
  std::uint64_t revision = 1;
  std::int64_t created_ns = 0;
  std::int64_t updated_ns = 0;
  std::string close_reason;
  bool operator==(const IssueRecord &) const = default;
};

struct IssueCreateRequest {
  std::string title;
  std::string body;
  IssueKind kind = IssueKind::task;
  std::uint8_t priority = kIssueDefaultPriority;
  std::optional<std::string> assignee;
  std::vector<std::string> labels;
  std::vector<std::string> depends_on;
};

struct IssueUpdateRequest {
  std::string id;
  std::optional<std::uint64_t> expected_revision;
  std::optional<std::string> title;
  std::optional<std::string> body;
  std::optional<IssueKind> kind;
  std::optional<IssueStatus> status;
  std::optional<std::uint8_t> priority;
  std::optional<std::string> assignee;
  bool clear_assignee = false;
  std::optional<std::vector<std::string>> labels;
  std::optional<std::string> close_reason;
};

struct IssueQuery {
  std::optional<IssueStatus> status;
  std::optional<IssueKind> kind;
  std::optional<std::string> assignee;
  std::optional<std::string> label;
  std::size_t limit = kIssueDefaultListLimit;
  std::size_t offset = 0;
};

Value to_json(const IssueComment &comment);
Value to_json(const IssueRecord &record);

// Zero-daemon, worktree-safe, Git-friendly local issue tracker backed by an
// flock-guarded append-only JSONL event log (<root>/events.jsonl).
class IssueStore {
public:
  static Result<IssueStore> open(const std::filesystem::path &root);

  IssueStore(const IssueStore &) = delete;
  IssueStore &operator=(const IssueStore &) = delete;
  IssueStore(IssueStore &&other) noexcept;
  IssueStore &operator=(IssueStore &&other) noexcept;
  ~IssueStore();

  const std::filesystem::path &root() const noexcept { return root_; }

  Result<IssueRecord> create(IssueCreateRequest request);
  Result<IssueRecord> get(std::string_view id) const;
  Result<std::vector<IssueRecord>> list(IssueQuery query = {}) const;
  Result<std::vector<IssueRecord>>
  ready(std::size_t limit = kIssueDefaultReadyLimit) const;
  Result<IssueRecord> update(IssueUpdateRequest request);
  Result<IssueRecord> claim(IssueIdRef id, std::string_view actor,
                            std::optional<std::uint64_t> expected_revision = {});
  Result<IssueRecord> close(IssueIdRef id, std::string_view reason,
                            std::optional<std::uint64_t> expected_revision = {});
  Result<IssueRecord> add_dependency(IssueIdRef id, IssueBlockerRef blocker_id);
  Result<IssueRecord> add_comment(IssueIdRef id, IssueActorRef author,
                                  std::string_view text);

private:
  IssueStore(std::filesystem::path root, int dir_fd) noexcept
      : root_(std::move(root)), dir_fd_(dir_fd) {}

  std::filesystem::path root_;
  int dir_fd_ = -1;
};

} // namespace blackbird
