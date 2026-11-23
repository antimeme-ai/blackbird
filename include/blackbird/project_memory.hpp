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

inline constexpr std::size_t kMemoryMaxTitleBytes = 256;
inline constexpr std::size_t kMemoryMaxBodyBytes = 32 * 1024;
inline constexpr std::size_t kMemoryMaxActorLength = 64;
inline constexpr std::size_t kMemoryMaxSessionIdLength = 128;
inline constexpr std::size_t kMemoryMaxTags = 32;
inline constexpr std::size_t kMemoryMaxTagBytes = 64;
inline constexpr std::size_t kMemoryMaxSources = 32;
inline constexpr std::size_t kMemoryMaxPathBytes = 4096;
inline constexpr std::size_t kMemoryDefaultLimit = 16;
inline constexpr std::size_t kMemoryMaxLimit = 64;

enum class MemoryKind : std::uint8_t {
  decision,
  invariant,
  handoff,
  finding,
  friction,
  preference,
};

enum class MemoryFreshness : std::uint8_t {
  unchecked,
  unpinned,
  fresh,
  stale,
  missing_source,
};

std::string_view memory_kind_name(MemoryKind kind) noexcept;
Result<MemoryKind> parse_memory_kind(std::string_view name) noexcept;

std::string_view memory_freshness_name(MemoryFreshness freshness) noexcept;
Result<MemoryFreshness> parse_memory_freshness(std::string_view name) noexcept;

// Valid entry ID: "mem-N" where N is a canonical positive decimal uint64.
bool valid_memory_id(std::string_view id) noexcept;
Result<std::uint64_t> parse_memory_id_number(std::string_view id) noexcept;

// Valid actor ID: [a-z0-9_-], length 1..64, leading char in [a-z0-9].
bool valid_memory_actor(std::string_view actor) noexcept;

// Valid SHA-256 hex digest: 64 lowercase hexadecimal chars [0-9a-f].
bool valid_memory_sha256(std::string_view sha256) noexcept;

// Computes lowercase 64-char FIPS 180-4 SHA-256 of arbitrary bytes.
std::string memory_sha256_hex(std::string_view bytes);

// Computes live SHA-256 of a regular file contained strictly inside root using
// component-wise O_RDONLY | O_NOFOLLOW | O_CLOEXEC traversal. Rejects '..',
// absolute paths outside root, symlinks, and non-regular files.
Result<std::string> hash_memory_source_file(const std::filesystem::path &root,
                                            std::string_view source_path);

// Default project memory directory helper: <project_root>/.blackbird/memory.
std::filesystem::path
default_project_memory_dir(const std::filesystem::path &project_root);

struct MemorySourcePin {
  std::string path;
  std::string sha256;
  bool operator==(const MemorySourcePin &) const = default;
};

struct MemoryEntry {
  std::string id;
  MemoryKind kind = MemoryKind::finding;
  std::string title;
  std::string body;
  std::vector<std::string> tags;
  std::string actor;
  std::optional<std::string> session_id;
  std::vector<MemorySourcePin> sources;
  std::optional<std::string> supersedes;
  std::optional<std::string> superseded_by;
  std::int64_t created_ns = 0;
  bool operator==(const MemoryEntry &) const = default;
};

struct MemoryRecordRequest {
  MemoryKind kind = MemoryKind::finding;
  std::string title;
  std::string body;
  std::vector<std::string> tags;
  std::string actor;
  std::optional<std::string> session_id;
  std::vector<MemorySourcePin> sources;
  std::optional<std::string> supersedes;
  std::optional<std::filesystem::path> repo_root;
  std::int64_t created_ns = 0;
};

struct MemoryRecallQuery {
  std::string query;
  std::optional<MemoryKind> kind;
  std::optional<std::string> tag;
  bool include_superseded = false;
  std::size_t limit = kMemoryDefaultLimit;
  std::optional<std::filesystem::path> verify_root;
};

struct MemoryRecallHit {
  MemoryEntry entry;
  std::uint64_t score = 0;
  MemoryFreshness freshness = MemoryFreshness::unpinned;
  bool operator==(const MemoryRecallHit &) const = default;
};

// Re-hashes every pinned source of entry strictly inside verify_root.
// Rejects '..', absolute paths outside verify_root, and symlink escapes.
Result<MemoryFreshness>
verify_memory_freshness(const MemoryEntry &entry,
                        const std::filesystem::path &verify_root);

// Native Value and JSON interchange helpers for CLI, model tools, Lua and TUI.
Value to_value(const MemorySourcePin &pin);
Value to_value(const MemoryEntry &entry);
Value to_value(const MemoryRecallHit &hit);
Value to_value(const std::vector<MemoryEntry> &entries);
Value to_value(const std::vector<MemoryRecallHit> &hits);

Result<std::string> to_json(const MemorySourcePin &pin);
Result<std::string> to_json(const MemoryEntry &entry);
Result<std::string> to_json(const MemoryRecallHit &hit);
Result<std::string> to_json(const std::vector<MemoryEntry> &entries);
Result<std::string> to_json(const std::vector<MemoryRecallHit> &hits);

// Durable, zero-daemon, multi-process-safe cross-session project memory and
// superseding lineage store backed by a 0700 pinned directory, flock on
// memory.lock, and crash-safe append-only entries.jsonl.
class ProjectMemoryStore {
public:
  static Result<ProjectMemoryStore> open(const std::filesystem::path &root);

  ProjectMemoryStore(const ProjectMemoryStore &) = delete;
  ProjectMemoryStore &operator=(const ProjectMemoryStore &) = delete;
  ProjectMemoryStore(ProjectMemoryStore &&other) noexcept;
  ProjectMemoryStore &operator=(ProjectMemoryStore &&other) noexcept;
  ~ProjectMemoryStore();

  const std::filesystem::path &root() const noexcept { return root_; }

  Result<MemoryEntry> record(MemoryRecordRequest request);
  Result<std::optional<MemoryEntry>> get(std::string_view id) const;
  Result<std::vector<MemoryRecallHit>> recall(const MemoryRecallQuery &query) const;
  Result<std::vector<MemoryEntry>> recent(std::size_t limit = kMemoryDefaultLimit,
                                          bool include_superseded = false) const;

private:
  ProjectMemoryStore(std::filesystem::path root, int dir_fd) noexcept
      : root_(std::move(root)), dir_fd_(dir_fd) {}

  std::filesystem::path root_;
  int dir_fd_ = -1;
};

} // namespace blackbird
