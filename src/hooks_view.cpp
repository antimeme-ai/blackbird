#include "blackbird/hooks_view.hpp"
#include "blackbird/display_text.hpp"
#include "blackbird/terminal.hpp"
#include <algorithm>
#include <atomic>
#include <charconv>
#include <limits>

namespace blackbird {
namespace {

constexpr std::string_view collection_key = "hooks", detail_key = "hook_detail";

std::string hook_item_key(std::string_view name) { return "h:" + std::string{name}; }

std::string dispatch_item_key(std::uint64_t seq) { return "d:" + std::to_string(seq); }

std::optional<std::uint64_t> parse_dispatch_key(std::string_view key) noexcept {
  if (!key.starts_with("d:") || key.size() < 3)
    return std::nullopt;
  std::uint64_t seq = 0;
  const auto res = std::from_chars(key.data() + 2, key.data() + key.size(), seq);
  if (res.ec != std::errc{} || res.ptr != key.data() + key.size() || seq == 0)
    return std::nullopt;
  return seq;
}

tui::TargetRef hook_target(std::string_view key) {
  return {"hooks-fabric", "hook", std::string{key}, 1};
}

tui::SceneCandidate base_candidate(tui::ViewIdentity view, std::uint64_t revision) {
  tui::SceneCandidate result;
  result.view = view;
  result.base_revision = revision;
  result.nodes = {{std::string{collection_key}, {}, tui::NodeKind::collection, true},
                  {std::string{detail_key}, {}, tui::NodeKind::inspector, true}};
  result.collections = {{std::string{collection_key}, {}, "HOOKS & FABRIC", {}}};
  result.inspectors = {{std::string{detail_key}, "HOOK DETAIL", {}, {}, {}, 0}};
  return result;
}

tui::SceneHost initial_hooks_host() {
  static std::atomic<std::uint64_t> next{1};
  const auto incarnation = next.fetch_add(1, std::memory_order_relaxed);
  const tui::ViewIdentity view{4, incarnation};
  auto host = unwrap(tui::SceneHost::create(view, {4, 16384, 131072}));
  unwrap(host.publish(base_candidate(view, 0)));
  return host;
}

std::string sanitize_single_line(std::string_view text, std::size_t max_bytes) {
  std::string joined;
  for (const auto &line :
       terminal_lines(text, std::numeric_limits<std::size_t>::max())) {
    if (!joined.empty())
      joined += ' ';
    joined += line;
    if (joined.size() > max_bytes)
      break;
  }
  std::string out;
  std::string_view rem = joined;
  while (!rem.empty()) {
    const auto sc = display_scalar(rem);
    if (sc.bytes == 0 || sc.cells < 0 || sc.scalar < 32 || sc.scalar == 127) {
      rem.remove_prefix(std::max<std::size_t>(1, sc.bytes));
      continue;
    }
    if (out.size() + sc.bytes > max_bytes)
      break;
    out.append(rem.data(), sc.bytes);
    rem.remove_prefix(sc.bytes);
  }
  return out;
}

void append_text_lines(std::vector<ChatRow> &rows, std::string_view text,
                       std::size_t max_lines, Ink ink = Ink::normal) {
  for (auto &line : terminal_lines(text, 240)) {
    if (rows.size() >= max_lines)
      break;
    rows.push_back({{std::move(line), ink}});
  }
}

std::string short_revision(std::string_view rev) {
  if (rev.empty())
    return "none";
  if (rev.size() <= 16)
    return std::string{rev};
  return std::string{rev.substr(0, 12)} + "..";
}

} // namespace

HooksView::HooksView()
    : host_(initial_hooks_host()),
      controls_(
          unwrap(tui::CollectionInspector::create(host_, collection_key, detail_key))) {
}

void HooksView::update(HooksViewSnapshot snapshot) {
  snapshot_ = std::move(snapshot);
  refresh_ = true;
}

void HooksView::toggle(RawEventRef origin) {
  (void)origin;
  open_ = !open_;
  focused_ = open_;
  if (open_)
    refresh_ = true;
}

void HooksView::first_page(RawEventRef origin) {
  (void)origin;
  open_ = true;
  focused_ = true;
  refresh_ = true;
}

void HooksView::toggle_history() noexcept {
  show_history_ = !show_history_;
  notice_ = show_history_ ? "Showing dispatch history" : "Showing hook definitions";
  refresh_ = true;
}

Result<void> HooksView::act(tui::InspectorAction action) {
  const auto res = controls_.act(action);
  if (!res.has_value())
    return res;
  const auto state = controls_.state();
  const auto key = state.has_value() ? state.value().selected : std::nullopt;
  if (key) {
    if (show_history_) {
      if (const auto seq = parse_dispatch_key(*key);
          seq && (!selected_dispatch_ || *selected_dispatch_ != *seq)) {
        selected_dispatch_ = *seq;
        refresh_ = true;
      }
    } else if (key->starts_with("h:")) {
      const auto name = key->substr(2);
      if (!selected_hook_ || *selected_hook_ != name) {
        selected_hook_ = name;
        refresh_ = true;
      }
    }
  }
  return res;
}

std::optional<HookDefinition> HooksView::selected_hook() const {
  if (!selected_hook_)
    return std::nullopt;
  for (const auto &hook : snapshot_.hooks) {
    if (hook.name == *selected_hook_)
      return hook;
  }
  return std::nullopt;
}

std::optional<HookDispatchRecord> HooksView::selected_dispatch() const {
  if (!selected_dispatch_)
    return std::nullopt;
  for (const auto &rec : snapshot_.history) {
    if (rec.sequence == *selected_dispatch_)
      return rec;
  }
  return std::nullopt;
}

HooksViewAction HooksView::action_command(std::string_view verb) {
  if (verb == "toggle_enabled") {
    if (show_history_) {
      notice_ = "Switch to Definitions (F9) to toggle a hook";
      return {{}, notice_};
    }
    const auto hook = selected_hook();
    if (!hook) {
      notice_ = "No hook selected";
      return {{}, notice_};
    }
    const std::string op = hook->enabled ? "disable" : "enable";
    notice_ = (hook->enabled ? "Disabling hook " : "Enabling hook ") + hook->name;
    return {"/hooks " + op + " " + hook->name, notice_};
  }
  return {};
}

bool HooksView::refresh() {
  refresh_ = false;
  const auto current = host_.snapshot();
  auto scene = base_candidate(current->view, current->revision);
  auto &list = scene.collections.front();
  auto &detail = scene.inspectors.front();

  std::optional<std::string> selected_key;

  if (!show_history_) {
    list.title = "HOOK DEFINITIONS (" + std::to_string(snapshot_.hooks.size()) + ")";
    for (const auto &hook : snapshot_.hooks) {
      std::string label = (hook.enabled ? "[ON]  " : "[OFF] ") + hook.name + " | " +
                          std::string{hook_event_name(hook.event)} + " | " +
                          std::string{hook_kind_name(hook.kind)};
      if (hook.order != 0)
        label += " | ord " + std::to_string(hook.order);
      const auto key = hook_item_key(hook.name);
      list.items.push_back({key, sanitize_single_line(label, 96), hook_target(key)});
    }
    if (snapshot_.hooks.empty()) {
      list.notice = {tui::NoticeKind::none,
                     "No hooks registered (configure via program_config.hooks)"};
      selected_hook_.reset();
    } else {
      const HookDefinition *chosen = nullptr;
      if (selected_hook_) {
        for (const auto &hook : snapshot_.hooks) {
          if (hook.name == *selected_hook_) {
            chosen = &hook;
            break;
          }
        }
      }
      if (!chosen) {
        chosen = &snapshot_.hooks.front();
        selected_hook_ = chosen->name;
      }
      selected_key = hook_item_key(chosen->name);
      detail.title = "HOOK " + chosen->name + (chosen->enabled ? " (ON)" : " (OFF)");
      detail.target = hook_target(*selected_key);

      std::string header = "Event: " + std::string{hook_event_name(chosen->event)} +
                           " | Kind: " + std::string{hook_kind_name(chosen->kind)} +
                           " | Order: " + std::to_string(chosen->order);
      detail.lines.push_back({{std::move(header), Ink::heading}});
      detail.lines.push_back(
          {{"Revision: " + short_revision(snapshot_.revision) +
                (snapshot_.pending_revision.empty()
                     ? ""
                     : " | Pending: " + short_revision(snapshot_.pending_revision)),
            Ink::muted}});
      if (!chosen->description.empty()) {
        detail.lines.push_back(
            {{"Description: " + sanitize_single_line(chosen->description, 200),
              Ink::normal}});
      }
      if (!chosen->match.tool.empty() || !chosen->match.prompt_prefix.empty()) {
        std::string match = "Match:";
        if (!chosen->match.tool.empty())
          match += " tool=" + sanitize_single_line(chosen->match.tool, 64);
        if (!chosen->match.prompt_prefix.empty())
          match +=
              " prompt_prefix=" + sanitize_single_line(chosen->match.prompt_prefix, 64);
        detail.lines.push_back({{std::move(match), Ink::keyword}});
      } else {
        detail.lines.push_back({{"Match: all events of this type", Ink::muted}});
      }

      const HookDispatchRecord *latest = nullptr;
      for (auto it = snapshot_.history.rbegin(); it != snapshot_.history.rend(); ++it) {
        if (it->hook_name == chosen->name) {
          latest = &*it;
          break;
        }
      }
      if (latest) {
        std::string last = "Last dispatch #" + std::to_string(latest->sequence) + ": " +
                           std::string{hook_outcome_name(latest->outcome)} + " (" +
                           std::to_string(latest->duration_ms) + "ms)";
        if (!latest->detail.empty())
          last += " | " + sanitize_single_line(latest->detail, 120);
        const Ink ink = latest->outcome == HookOutcome::matched_ok ? Ink::success
                        : latest->outcome == HookOutcome::skipped  ? Ink::muted
                                                                   : Ink::failure;
        detail.lines.push_back({{std::move(last), ink}});
      } else {
        detail.lines.push_back(
            {{"Last dispatch: never fired in this session", Ink::muted}});
      }
      detail.lines.push_back({{"", Ink::normal}});
      detail.lines.push_back({{"Lua source (function(event) ... end):", Ink::heading}});
      append_text_lines(detail.lines, chosen->source, 160, Ink::code);
    }
  } else {
    list.title = "DISPATCH HISTORY (" + std::to_string(snapshot_.history.size()) + ")";
    // Newest first in history view.
    for (auto it = snapshot_.history.rbegin(); it != snapshot_.history.rend(); ++it) {
      const auto &rec = *it;
      std::string label = "#" + std::to_string(rec.sequence) + " " + rec.hook_name +
                          " | " + std::string{hook_event_name(rec.event)} + " | " +
                          std::string{hook_outcome_name(rec.outcome)} + " (" +
                          std::to_string(rec.duration_ms) + "ms)";
      const auto key = dispatch_item_key(rec.sequence);
      list.items.push_back({key, sanitize_single_line(label, 96), hook_target(key)});
    }
    if (snapshot_.history.empty()) {
      list.notice = {tui::NoticeKind::none, "No hook dispatches recorded yet"};
      selected_dispatch_.reset();
    } else {
      const HookDispatchRecord *chosen = nullptr;
      if (selected_dispatch_) {
        for (const auto &rec : snapshot_.history) {
          if (rec.sequence == *selected_dispatch_) {
            chosen = &rec;
            break;
          }
        }
      }
      if (!chosen) {
        chosen = &snapshot_.history.back();
        selected_dispatch_ = chosen->sequence;
      }
      selected_key = dispatch_item_key(chosen->sequence);
      detail.title =
          "DISPATCH #" + std::to_string(chosen->sequence) + " | " + chosen->hook_name;
      detail.target = hook_target(*selected_key);
      detail.lines.push_back(
          {{"Outcome: " + std::string{hook_outcome_name(chosen->outcome)} + " | " +
                std::to_string(chosen->duration_ms) + "ms",
            chosen->outcome == HookOutcome::matched_ok ? Ink::success
            : chosen->outcome == HookOutcome::skipped  ? Ink::muted
                                                       : Ink::failure}});
      detail.lines.push_back(
          {{"Event: " + std::string{hook_event_name(chosen->event)} +
                " | Kind: " + std::string{hook_kind_name(chosen->kind)},
            Ink::heading}});
      detail.lines.push_back(
          {{"Revision: " + short_revision(chosen->revision), Ink::muted}});
      detail.lines.push_back({{"", Ink::normal}});
      if (!chosen->detail.empty()) {
        detail.lines.push_back({{"Detail:", Ink::heading}});
        append_text_lines(detail.lines, chosen->detail, 120, Ink::normal);
      } else {
        detail.lines.push_back({{"No additional detail recorded.", Ink::muted}});
      }
    }
  }

  const auto published = host_.publish(scene);
  if (!published.has_value()) {
    notice_ =
        "Hooks publish failed: " + std::string{error_name(published.error().code)};
    return false;
  }
  if (selected_key) {
    if (const auto handle = host_.handle(collection_key); handle.has_value())
      (void)host_.select(handle.value(), *selected_key);
  }
  return true;
}

Result<tui::InspectorLayout> HooksView::render(ChatGrid &grid, tui::Rect bounds) {
  return controls_.render(grid, bounds);
}

std::string HooksView::caption() const {
  std::size_t enabled_count = 0;
  for (const auto &hook : snapshot_.hooks) {
    if (hook.enabled)
      ++enabled_count;
  }
  std::string out = "HOOKS & FABRIC | ";
  out += show_history_ ? "history" : "definitions";
  out += " | " + std::to_string(enabled_count) + "/" +
         std::to_string(snapshot_.hooks.size()) + " enabled";
  out += " | " + std::to_string(snapshot_.history.size()) + " dispatches";
  if (!snapshot_.pending_revision.empty())
    out += " | pending rev";
  if (!notice_.empty())
    out += " | " + notice_;
  return out;
}

} // namespace blackbird
