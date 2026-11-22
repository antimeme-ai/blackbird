#pragma once

#include "blackbird/tui_inspector.hpp"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

struct ContextDetailSlice {
  std::string content;
  std::uint64_t total_bytes = 0;
  std::uint64_t offset = 0;
  bool truncated = false;
  bool archived = false;
};

using ContextDetailReader = std::function<std::optional<ContextDetailSlice>(
    std::uint64_t id, std::size_t offset, std::size_t limit)>;

struct ContextWorkbenchBlock {
  std::uint64_t id = 0;
  std::string kind;
  std::string label;
  std::string preview;
  std::uint64_t bytes = 0;
  std::size_t items = 0;
  std::vector<std::uint64_t> replaces;
  bool pinned = false;
  bool open = false;
  bool archived = false;
};

struct ContextWorkbenchSnapshot {
  std::uint64_t revision = 0;
  std::uint64_t upstream_epoch = 0;
  std::uint64_t total_bytes = 0;
  std::uint64_t live_blocks = 0;
  std::uint64_t archived_blocks = 0;
  std::uint64_t pending_compactions = 0;
  std::optional<std::uint64_t> context_window_tokens;
  std::vector<ContextWorkbenchBlock> blocks;
};

struct ContextWorkbenchAction {
  std::string command;
  std::string notice;
};

// Local TUI view adapter for live and archived context blocks. Owns only local
// presentation state; mutations return explicit audited slash commands for the
// session worker rather than mutating ContextStore directly.
class ContextWorkbench {
public:
  ContextWorkbench();
  ContextWorkbench(const ContextWorkbench &) = delete;
  ContextWorkbench &operator=(const ContextWorkbench &) = delete;

  void toggle(RawEventRef origin = {});
  void first_page(RawEventRef origin = {});
  bool open() const noexcept { return open_; }
  bool focused() const noexcept { return focused_; }
  void focus_editor() noexcept { focused_ = false; }
  void focus_view() noexcept { focused_ = open_; }
  bool needs_refresh() const noexcept { return refresh_; }
  bool showing_archived() const noexcept { return show_archived_; }

  void update(ContextWorkbenchSnapshot snapshot);
  void toggle_archived();
  void page(bool forward);
  Result<void> act(tui::InspectorAction action);
  bool refresh(const ContextDetailReader &reader);
  Result<tui::InspectorLayout> render(ChatGrid &grid, tui::Rect bounds);

  std::optional<ContextWorkbenchBlock> selected_block() const;
  ContextWorkbenchAction action_command(std::string_view verb);
  std::string caption() const;
  std::string_view notice() const noexcept { return notice_; }
  const tui::SceneHost &host() const noexcept { return host_; }

private:
  tui::SceneHost host_;
  tui::CollectionInspector controls_;
  ContextWorkbenchSnapshot snapshot_;
  std::optional<std::uint64_t> selected_id_;
  std::size_t detail_offset_ = 0;
  std::uint64_t detail_total_ = 0;
  bool detail_truncated_ = false;
  bool open_ = false;
  bool focused_ = false;
  bool refresh_ = true;
  bool show_archived_ = true;
  std::string notice_;
};

} // namespace blackbird
