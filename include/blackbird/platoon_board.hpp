#pragma once

#include "blackbird/foundation.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::size_t kPlatoonMaxIdLength = 48;
inline constexpr std::size_t kPlatoonMaxMessageBytes = 64 * 1024;
inline constexpr std::size_t kPlatoonMaxBriefBytes = 64 * 1024;
inline constexpr std::size_t kPlatoonMaxFieldBytes = 4096;
inline constexpr std::size_t kPlatoonMaxRefs = 64;
inline constexpr std::size_t kPlatoonMaxRefBytes = 1024;
inline constexpr std::size_t kPlatoonMaxRosterMembers = 512;
inline constexpr std::size_t kPlatoonDefaultReadLimit = 64;

enum class PlatoonMessageKind : std::uint8_t {
  brief,
  message,
  handoff,
  blocker,
  decision,
  artifact,
  review,
  status,
};

enum class PlatoonMemberState : std::uint8_t {
  starting,
  working,
  waiting,
  completed,
  failed,
  stopped,
};

std::string_view platoon_message_kind_name(PlatoonMessageKind kind) noexcept;
Result<PlatoonMessageKind> parse_platoon_message_kind(std::string_view name) noexcept;

std::string_view platoon_member_state_name(PlatoonMemberState state) noexcept;
Result<PlatoonMemberState> parse_platoon_member_state(std::string_view name) noexcept;

bool valid_platoon_member_id(std::string_view id) noexcept;

struct PlatoonMember {
  std::string id;
  std::string role;
  std::string provider;
  std::string model;
  std::string workspace;
  std::string branch;
  PlatoonMemberState state = PlatoonMemberState::starting;
  std::int64_t pid = 0;
  std::int64_t updated_ns = 0;
  std::string brief;
  bool operator==(const PlatoonMember &) const = default;
};

struct PlatoonPost {
  std::string from;
  std::string to = "all";
  PlatoonMessageKind kind = PlatoonMessageKind::message;
  std::string text;
  std::vector<std::string> refs;
};

struct PlatoonMessage {
  std::uint64_t seq = 0;
  std::int64_t timestamp_ns = 0;
  std::string from;
  std::string to;
  PlatoonMessageKind kind = PlatoonMessageKind::message;
  std::string text;
  std::vector<std::string> refs;
  bool operator==(const PlatoonMessage &) const = default;
};

struct PlatoonReadQuery {
  std::uint64_t after_seq = 0;
  std::size_t limit = kPlatoonDefaultReadLimit;
  std::string_view recipient_filter;
};

// Durable, zero-daemon, multi-process-safe message board and member roster
// backed by flock-guarded append-only board.jsonl and atomic-rename roster.json.
class PlatoonBoard {
public:
  static Result<PlatoonBoard> open(const std::filesystem::path &root);

  PlatoonBoard(const PlatoonBoard &) = delete;
  PlatoonBoard &operator=(const PlatoonBoard &) = delete;
  PlatoonBoard(PlatoonBoard &&other) noexcept;
  PlatoonBoard &operator=(PlatoonBoard &&other) noexcept;
  ~PlatoonBoard();

  const std::filesystem::path &root() const noexcept { return root_; }

  Result<PlatoonMember> upsert_member(const PlatoonMember &member);
  Result<std::vector<PlatoonMember>> members() const;
  Result<std::optional<PlatoonMember>> member(std::string_view id) const;

  Result<PlatoonMessage> post(PlatoonPost message);
  Result<std::vector<PlatoonMessage>> read(PlatoonReadQuery query) const;
  Result<std::vector<PlatoonMessage>>
  read_since(std::uint64_t after_seq, std::size_t limit = kPlatoonDefaultReadLimit,
             std::string_view recipient_filter = {}) const;
  Result<std::uint64_t> latest_seq() const;

private:
  PlatoonBoard(std::filesystem::path root, int dir_fd) noexcept
      : root_(std::move(root)), dir_fd_(dir_fd) {}

  std::filesystem::path root_;
  int dir_fd_ = -1;
};

} // namespace blackbird
