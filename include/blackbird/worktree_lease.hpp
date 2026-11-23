#pragma once

#include "blackbird/foundation.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::size_t kDefaultMaxWorktreeLeases = 8;
inline constexpr std::size_t kMinWorktreeLeases = 1;
inline constexpr std::size_t kMaxWorktreeLeases = 32;
inline constexpr std::size_t kMaxWorktreeLeaseIdLength = 48;
inline constexpr std::size_t kMaxWorktreeBranchLength = 128;

struct WorktreeLeaseConfig {
  std::filesystem::path repo_root;
  std::filesystem::path lease_root;
  std::size_t max_leases = kDefaultMaxWorktreeLeases;
  // Optional absolute git executable override; empty resolves absolute git once at
  // open().
  std::filesystem::path git_executable = {};
};

struct WorktreeLeaseRequest {
  std::string lease_id;
  std::string branch;
  std::string base_ref = "HEAD";
  std::string owner_id;
  std::int64_t owner_pid = 0;
  bool use_existing_branch = false;
};

struct WorktreeLeaseInfo {
  std::string lease_id;
  std::string branch;
  std::string base_ref;
  std::string base_sha;
  std::string owner_id;
  std::int64_t owner_pid = 0;
  std::int64_t created_ns = 0;
  std::filesystem::path path;
  std::string head_sha;
  bool dirty = false;
  std::uint64_t commits_ahead = 0;
  bool owner_alive = false;
  bool worktree_present = false;
};

struct WorktreeReclaimReport {
  std::vector<std::string> reclaimed;
  std::vector<WorktreeLeaseInfo> orphaned_dirty;
};

// Bounded, flock-guarded isolated git worktree lease manager.
// All git invocations pass explicit argv vectors directly without a shell.
// Metadata persists atomically under <lease_root>/.leases/<lease_id>.json (0700 dir).
class WorktreeLeaseManager {
public:
  static Result<WorktreeLeaseManager> open(const WorktreeLeaseConfig &config);

  Result<WorktreeLeaseInfo> acquire(const WorktreeLeaseRequest &req);
  Result<std::vector<WorktreeLeaseInfo>> list() const;
  Result<WorktreeLeaseInfo> status(std::string_view lease_id) const;
  Result<void> release(std::string_view lease_id, bool force = false);
  Result<WorktreeReclaimReport> reclaim_stale();

  const std::filesystem::path &repo_root() const noexcept { return repo_root_; }
  const std::filesystem::path &lease_root() const noexcept { return lease_root_; }
  std::size_t max_leases() const noexcept { return max_leases_; }
  const std::filesystem::path &git_executable() const noexcept {
    return git_executable_;
  }

private:
  explicit WorktreeLeaseManager(WorktreeLeaseConfig config);

  std::filesystem::path leases_dir() const;
  std::filesystem::path lock_path() const;
  std::filesystem::path metadata_path(std::string_view lease_id) const;
  std::filesystem::path worktree_path(std::string_view lease_id) const;

  std::filesystem::path repo_root_;
  std::filesystem::path lease_root_;
  std::size_t max_leases_;
  std::filesystem::path git_executable_;
};

} // namespace blackbird
