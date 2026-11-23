#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/worktree_lease.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::size_t kSwarmMaxWorkerNameLength = 24;
inline constexpr std::size_t kSwarmMaxShardedTasks = 32;
inline constexpr std::size_t kSwarmDefaultShardedConcurrency = 8;
inline constexpr std::size_t kSwarmDefaultMaxWorkers = 64;
inline constexpr std::int64_t kSwarmDefaultWaitTimeoutMs = 30000;
inline constexpr std::size_t kSwarmDefaultWaitMaxMessages = 1024;
inline constexpr std::size_t kSwarmMaxOwnedFilesPerWorker = 256;
inline constexpr std::size_t kSwarmMaxOwnedPathBytes = 1024;

enum class SwarmWorkspaceMode : std::uint8_t {
  inherit,
  share,
  branch,
};

enum class SwarmWorkerState : std::uint8_t {
  working,
  waiting,
  stopped,
  killed,
};

std::string_view swarm_workspace_mode_name(SwarmWorkspaceMode mode) noexcept;
Result<SwarmWorkspaceMode> parse_swarm_workspace_mode(std::string_view name) noexcept;

std::string_view swarm_worker_state_name(SwarmWorkerState state) noexcept;
Result<SwarmWorkerState> parse_swarm_worker_state(std::string_view name) noexcept;

// Validates lowercase roster names matching ^[a-z0-9][a-z0-9_-]{0,23}$,
// rejecting reserved identities: "all", "coordinator", and "coordinator-*".
bool valid_swarm_worker_name(std::string_view name) noexcept;

// Returns true if message targets agent_name directly (to == agent_name or
// to == "all") or mentions @<agent_name> or @all on word boundaries in text.
bool swarm_message_mentions_agent(const PlatoonMessage &message,
                                  std::string_view agent_name) noexcept;

struct SwarmBoardWaitOptions {
  std::string agent_name = {};
  std::uint64_t since_seq = 0;
  bool mentions_only = true;
  // > 0: bounded wait in milliseconds; 0: immediate check; < 0: wait until
  // woken or cancelled.
  std::int64_t timeout_ms = kSwarmDefaultWaitTimeoutMs;
  std::atomic_bool *cancel = nullptr;
  std::size_t max_messages = kSwarmDefaultWaitMaxMessages;
};

struct SwarmBoardWaitResult {
  bool woken = false;
  bool timed_out = false;
  bool cancelled = false;
  std::uint64_t latest_seq = 0;
  std::vector<PlatoonMessage> messages;
};

// Zero-token reactive watcher over PlatoonBoard (board.jsonl) backed by
// kqueue EVFILT_VNODE on macOS and inotify on Linux. Checks unread messages
// immediately after arming the OS watcher so concurrent posts are never missed.
class SwarmBoardWaiter {
public:
  static Result<SwarmBoardWaiter> open(const std::filesystem::path &board_root);

  SwarmBoardWaiter(const SwarmBoardWaiter &) = delete;
  SwarmBoardWaiter &operator=(const SwarmBoardWaiter &) = delete;
  SwarmBoardWaiter(SwarmBoardWaiter &&other) noexcept;
  SwarmBoardWaiter &operator=(SwarmBoardWaiter &&other) noexcept;
  ~SwarmBoardWaiter();

  const std::filesystem::path &board_root() const noexcept { return board_root_; }

  Result<SwarmBoardWaitResult> wait(const PlatoonBoard &board,
                                    const SwarmBoardWaitOptions &options);
  Result<SwarmBoardWaitResult> wait(const SwarmBoardWaitOptions &options);

  // Immediately wakes a blocked wait() call from another thread.
  void wake() noexcept;

private:
  struct WatcherState;

  SwarmBoardWaiter(std::filesystem::path board_root,
                   std::unique_ptr<WatcherState> state) noexcept;

  std::filesystem::path board_root_;
  std::unique_ptr<WatcherState> state_;
};

// Convenience reactive wait helper using SwarmBoardWaiter over an open board.
Result<SwarmBoardWaitResult>
wait_for_board_mention(const PlatoonBoard &board, const SwarmBoardWaitOptions &options);

struct SwarmWorkerSpec {
  std::string name = {};
  std::string role = "builder";
  std::string provider = {};
  std::string model = {};
  SwarmWorkspaceMode workspace_mode = SwarmWorkspaceMode::inherit;
  std::vector<std::string> owned_files = {};
  std::string brief = {};
  std::optional<std::filesystem::path> fork_from_session_dir = std::nullopt;
  std::string base_ref = "HEAD";
  std::string session_id = {};
  bool read_only = false;
};

struct SwarmWorkerRecord {
  std::string name;
  std::string role;
  std::string provider;
  std::string model;
  SwarmWorkspaceMode workspace_mode = SwarmWorkspaceMode::inherit;
  SwarmWorkerState state = SwarmWorkerState::working;
  std::vector<std::string> owned_files;
  std::string brief;
  std::string session_id;
  std::optional<std::filesystem::path> fork_from_session_dir = std::nullopt;
  std::filesystem::path workspace_path;
  std::string lease_id;
  std::string branch;
  std::uint64_t brief_seq = 0;
  std::int64_t created_ns = 0;
  std::int64_t updated_ns = 0;
  bool read_only = false;
  bool operator==(const SwarmWorkerRecord &) const = default;
};

struct SwarmDentistOptions {
  std::string provider = {};
  std::string model = {};
  std::optional<std::filesystem::path> fork_from_session_dir = std::nullopt;
};

struct SwarmModelSwitchRequest {
  std::string worker_name = {};
  std::string new_provider = {};
  std::string new_model = {};
  std::string reason = {};
};

struct SwarmScopeViolation {
  std::string path;
  std::string reason;
  bool operator==(const SwarmScopeViolation &) const = default;
};

struct SwarmScopeCheckResult {
  bool ok = false;
  std::vector<std::string> verified_paths;
  std::vector<SwarmScopeViolation> violations;
};

struct LocalSwarmConfig {
  std::filesystem::path board_root = {};
  std::string coordinator_name = "coordinator";
  std::optional<WorktreeLeaseConfig> worktree_config = std::nullopt;
  std::string swarm_title = {};
  std::size_t max_workers = kSwarmDefaultMaxWorkers;
};

// Native single-player swarm coordinator layered cleanly over PlatoonBoard and
// optional WorktreeLeaseManager. Enforces disjoint owned_files across active
// non-killed workers, Kimi-style sharded fan-out, read-only @dentist verifier
// presets, in-place waiting model handoffs, and safe-landing scope checks.
class LocalSwarmCoordinator {
public:
  static Result<LocalSwarmCoordinator> open(LocalSwarmConfig config);

  LocalSwarmCoordinator(const LocalSwarmCoordinator &) = delete;
  LocalSwarmCoordinator &operator=(const LocalSwarmCoordinator &) = delete;
  LocalSwarmCoordinator(LocalSwarmCoordinator &&other) noexcept;
  LocalSwarmCoordinator &operator=(LocalSwarmCoordinator &&other) noexcept;
  ~LocalSwarmCoordinator();

  const PlatoonBoard &board() const noexcept { return board_; }
  PlatoonBoard &board() noexcept { return board_; }

  std::string title() const;
  Result<void> set_title(std::string title);

  Result<SwarmWorkerRecord> add_worker(const SwarmWorkerSpec &spec);

  Result<std::vector<SwarmWorkerRecord>>
  add_sharded_group(std::string_view base_name, const std::vector<std::string> &tasks,
                    std::string_view shared_brief, const SwarmWorkerSpec &spec_template,
                    std::size_t max_concurrency = kSwarmDefaultShardedConcurrency);

  Result<SwarmWorkerRecord>
  add_dentist_verifier(std::string_view name,
                       const std::vector<std::string> &repo_checks = {},
                       const SwarmDentistOptions &options = {});

  Result<SwarmWorkerRecord> switch_worker_model(const SwarmModelSwitchRequest &request);

  Result<SwarmWorkerRecord> set_worker_state(std::string_view name,
                                             SwarmWorkerState new_state);

  Result<SwarmWorkerRecord> kill_worker(std::string_view name);

  std::vector<SwarmWorkerRecord> status() const;
  Result<std::optional<SwarmWorkerRecord>> worker(std::string_view name) const;

  Result<SwarmScopeCheckResult>
  verify_owned_files_scope(std::string_view worker_name,
                           const std::vector<std::string> &modified_paths) const;

  Result<SwarmBoardWaitResult>
  wait_for_mention(const SwarmBoardWaitOptions &options) const;

private:
  LocalSwarmCoordinator(LocalSwarmConfig config, PlatoonBoard board,
                        std::optional<WorktreeLeaseManager> worktree_manager,
                        int dir_fd) noexcept;

  Result<SwarmWorkerRecord> add_worker_locked(const SwarmWorkerSpec &spec,
                                              SwarmWorkerState initial_state);
  Result<SwarmWorkerRecord> kill_worker_locked(std::string_view name);
  Result<void> sync_platoon_member_locked(const SwarmWorkerRecord &record);
  Result<void> persist_state_locked() const;
  Result<void> load_state_locked();

  mutable std::mutex mutex_;
  LocalSwarmConfig config_;
  PlatoonBoard board_;
  std::optional<WorktreeLeaseManager> worktree_manager_;
  int dir_fd_ = -1;
  std::uint64_t session_counter_ = 0;
  std::vector<SwarmWorkerRecord> workers_;
};

} // namespace blackbird
