#pragma once

#include "blackbird/board_bridge.hpp"
#include "blackbird/foundation.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

enum class PeerRosterState : std::uint8_t {
  working,
  waiting,
  stopped,
  failed,
};

std::string_view peer_roster_state_name(PeerRosterState state) noexcept;

struct PeerRosterRow {
  std::string peer_id;
  std::string role;
  std::string driver;
  std::string owner_actor;
  PeerRosterState state = PeerRosterState::waiting;
  std::uint64_t last_seq = 0;
  std::string lease_branch;
  std::int64_t updated_ns = 0;
  bool operator==(const PeerRosterRow &) const = default;
};

enum class SwarmboardMessageSource : std::uint8_t {
  platoon,
  bridge,
};

std::string_view
swarmboard_message_source_name(SwarmboardMessageSource source) noexcept;

struct SwarmboardMessageRow {
  SwarmboardMessageSource source = SwarmboardMessageSource::platoon;
  std::string seq_or_hash;
  std::string from;
  std::string to;
  std::string kind;
  std::string resource_scope;
  std::vector<std::string> tags;
  std::string text;
  std::int64_t timestamp_ns = 0;
  bool operator==(const SwarmboardMessageRow &) const = default;
};

struct WatcherRow {
  std::string display_name;
  std::string actor_id;
  std::string watching_scope;
  std::string status;
  bool operator==(const WatcherRow &) const = default;
};

enum class SwarmboardFilter : std::uint8_t {
  all,
  mentions,
  conflicts,
  watchers,
};

std::string_view swarmboard_filter_name(SwarmboardFilter filter) noexcept;

// Distinct non-mutually-convertible viewport dimension wrappers so callers can
// pass integer columns/rows directly (`render(80, 24)`) without swappable params.
struct SwarmboardWidth {
  std::size_t value = 80;
  constexpr SwarmboardWidth(std::size_t cols) noexcept : value(cols) {}
};

struct SwarmboardHeight {
  std::size_t value = 24;
  constexpr SwarmboardHeight(std::size_t rows) noexcept : value(rows) {}
};

// Source paths and optional actor/scope filters for passive read-only loading.
struct SwarmboardConfig {
  std::filesystem::path platoon_dir;
  std::filesystem::path leases_dir;
  std::filesystem::path bridge_dir;
  std::optional<std::string> local_actor_fp;
  std::optional<std::string> local_actor_id;
  std::string scope;
  std::string room_label;
  // 0 => use current system wall clock nanoseconds for watcher TTL checks.
  std::int64_t now_ns = 0;

  static SwarmboardConfig for_project(const std::filesystem::path &project_root);
};

// Immutable passive read-only snapshot of platoon, worktree lease, and bridge state.
struct SwarmboardSnapshot {
  std::string room_label;
  std::string scope;
  std::optional<std::string> local_actor_fp;
  std::optional<std::string> local_actor_id;
  std::vector<PeerRosterRow> roster;
  std::vector<SwarmboardMessageRow> messages;
  std::vector<WatcherRow> watchers;
  ActionGuardVerdict guard_verdict{true, {}, "clear"};
  bool guard_checked = false;
  std::vector<ConcurrentClaimConflict> concurrent_conflicts;
  bool platoon_present = false;
  bool leases_present = false;
  bool bridge_present = false;

  std::size_t working_peers() const noexcept;
  std::size_t waiting_peers() const noexcept;
  std::size_t stopped_peers() const noexcept;
  std::size_t failed_peers() const noexcept;
  std::size_t conflict_count() const noexcept { return concurrent_conflicts.size(); }

  bool operator==(const SwarmboardSnapshot &) const = default;
};

// Strict terminal sanitization escaping all C0 (<0x20), DEL (0x7F), bare C1
// (0x80..0x9F, incl. 0x9B CSI), UTF-8 C1 (0xC2 0x80..0x9F), Unicode bidi
// override controls, and invalid UTF-8 bytes while preserving valid UTF-8.
std::string swarmboard_sanitize_inline(std::string_view text,
                                       std::size_t max_bytes = 256);

// Single-pass strict sanitization wrapped in explicit double quotes for untrusted
// peer text (escaping `\` and `"` without double-escaping control hex escapes).
std::string swarmboard_quote_untrusted(std::string_view text,
                                       std::size_t max_bytes = 512);

// Passive read-only loader. Never creates directories/lock files, never mutates
// PlatoonBoard / BoardBridge / WorktreeLeaseManager, and never advances any
// MessageReceipt stage.
Result<SwarmboardSnapshot> load_swarmboard_snapshot(const SwarmboardConfig &config);

// Dense, terminal-safe split-pane Live Swarmboard view (roster + scrollable
// filterable @mention board / conflicts / watchers).
class SwarmboardView {
public:
  SwarmboardView() = default;
  explicit SwarmboardView(SwarmboardSnapshot snapshot);

  Result<void> reload(const SwarmboardConfig &config);
  void update(SwarmboardSnapshot snapshot);

  const SwarmboardSnapshot &snapshot() const noexcept { return snapshot_; }

  SwarmboardFilter filter() const noexcept { return filter_; }
  void set_filter(SwarmboardFilter filter) noexcept;

  std::size_t scroll_offset() const noexcept { return scroll_offset_; }
  void scroll_up(std::size_t lines = 1) noexcept;
  void scroll_down(std::size_t lines = 1) noexcept;
  void page_up(std::size_t page_lines = 10) noexcept;
  void page_down(std::size_t page_lines = 10) noexcept;
  void scroll_to_top() noexcept { scroll_offset_ = 0; }
  void scroll_to_bottom() noexcept;

  std::vector<SwarmboardMessageRow> filtered_messages() const;

  std::vector<std::string> render_lines(SwarmboardWidth width,
                                        SwarmboardHeight height) const;
  std::string render(SwarmboardWidth width, SwarmboardHeight height) const;

private:
  std::size_t lower_item_count() const noexcept;
  void clamp_scroll() noexcept;

  SwarmboardSnapshot snapshot_{};
  SwarmboardFilter filter_ = SwarmboardFilter::all;
  std::size_t scroll_offset_ = 0;
};

} // namespace blackbird
