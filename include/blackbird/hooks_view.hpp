#pragma once

#include "blackbird/hooks.hpp"
#include "blackbird/tui_inspector.hpp"
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

struct HooksViewSnapshot {
  std::string revision;
  std::string pending_revision;
  std::vector<HookDefinition> hooks;
  std::vector<HookDefinition> pending_hooks;
  std::vector<HookDispatchRecord> history;
};

struct HooksViewAction {
  std::string command;
  std::string notice;
};

// Interactive Hooks & Action Fabric view (TUI Unit 4).
// Owns only local selection and display mode; mutating toggles emit audited
// /hooks commands through the worker queue (never mutating engine state directly).
class HooksView {
public:
  HooksView();
  HooksView(const HooksView &) = delete;
  HooksView &operator=(const HooksView &) = delete;

  void update(HooksViewSnapshot snapshot);
  void toggle(RawEventRef origin = {});
  void first_page(RawEventRef origin = {});
  void close() noexcept {
    open_ = false;
    focused_ = false;
  }
  bool open() const noexcept { return open_; }
  bool focused() const noexcept { return focused_; }
  void focus_editor() noexcept { focused_ = false; }
  void focus_view() noexcept { focused_ = open_; }
  bool needs_refresh() const noexcept { return refresh_; }
  bool showing_history() const noexcept { return show_history_; }
  void toggle_history() noexcept;
  std::string_view notice() const noexcept { return notice_; }

  Result<void> act(tui::InspectorAction action);
  std::optional<HookDefinition> selected_hook() const;
  std::optional<HookDispatchRecord> selected_dispatch() const;
  HooksViewAction action_command(std::string_view verb);

  bool refresh();
  Result<tui::InspectorLayout> render(ChatGrid &grid, tui::Rect bounds);
  std::string caption() const;

private:
  tui::SceneHost host_;
  tui::CollectionInspector controls_;
  HooksViewSnapshot snapshot_;
  std::optional<std::string> selected_hook_;
  std::optional<std::uint64_t> selected_dispatch_;
  bool open_ = false;
  bool focused_ = false;
  bool refresh_ = true;
  bool show_history_ = false;
  std::string notice_;
};

} // namespace blackbird
