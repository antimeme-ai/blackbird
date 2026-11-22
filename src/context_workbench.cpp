#include "blackbird/context_workbench.hpp"
#include "blackbird/display_text.hpp"
#include "blackbird/terminal.hpp"
#include <algorithm>
#include <atomic>
#include <charconv>
#include <iomanip>
#include <limits>
#include <sstream>

namespace blackbird {
namespace {

constexpr std::string_view collection_key = "blocks", detail_key = "block_detail";
constexpr std::size_t detail_page_bytes = 8192;

std::string format_bytes(std::uint64_t bytes) {
  std::ostringstream out;
  if (bytes < 1024) {
    out << bytes << " B";
  } else if (bytes < 1024ULL * 1024ULL) {
    out << std::fixed << std::setprecision(1) << (static_cast<double>(bytes) / 1024.0)
        << " KiB";
  } else {
    out << std::fixed << std::setprecision(1)
        << (static_cast<double>(bytes) / (1024.0 * 1024.0)) << " MiB";
  }
  return out.str();
}

std::string short_kind(std::string_view kind) {
  if (kind == "instruction")
    return "instr";
  if (kind == "exchange")
    return "exch";
  if (kind == "note")
    return "note";
  return std::string{kind};
}

std::string block_key(std::uint64_t id) { return "b" + std::to_string(id); }

std::optional<std::uint64_t> parse_block_key(std::string_view key) noexcept {
  if (key.size() < 2 || key.front() != 'b')
    return std::nullopt;
  std::uint64_t id = 0;
  const auto res = std::from_chars(key.data() + 1, key.data() + key.size(), id);
  if (res.ec != std::errc{} || res.ptr != key.data() + key.size() || id == 0)
    return std::nullopt;
  return id;
}

tui::TargetRef block_target(std::uint64_t id) {
  return {"context-store", "block", block_key(id), 1};
}

tui::SceneCandidate base_candidate(tui::ViewIdentity view, std::uint64_t revision) {
  tui::SceneCandidate result;
  result.view = view;
  result.base_revision = revision;
  result.nodes = {{std::string{collection_key}, {}, tui::NodeKind::collection, true},
                  {std::string{detail_key}, {}, tui::NodeKind::inspector, true}};
  result.collections = {{std::string{collection_key}, {}, "CONTEXT BLOCKS", {}}};
  result.inspectors = {{std::string{detail_key}, "BLOCK DETAIL", {}, {}, {}, 0}};
  return result;
}

tui::SceneHost initial_workbench_host() {
  static std::atomic<std::uint64_t> next{1};
  const auto incarnation = next.fetch_add(1, std::memory_order_relaxed);
  const tui::ViewIdentity view{3, incarnation};
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
                       std::size_t max_lines) {
  for (auto &line : terminal_lines(text, 240)) {
    if (rows.size() >= max_lines)
      break;
    rows.push_back({{std::move(line), Ink::normal}});
  }
}

} // namespace

ContextWorkbench::ContextWorkbench()
    : host_(initial_workbench_host()),
      controls_(
          unwrap(tui::CollectionInspector::create(host_, collection_key, detail_key))) {
}

void ContextWorkbench::toggle(RawEventRef) {
  open_ = !open_;
  focused_ = open_;
  if (open_) {
    refresh_ = true;
    notice_.clear();
  }
}

void ContextWorkbench::first_page(RawEventRef) {
  open_ = true;
  focused_ = true;
  detail_offset_ = 0;
  refresh_ = true;
  notice_.clear();
}

void ContextWorkbench::update(ContextWorkbenchSnapshot snapshot) {
  snapshot_ = std::move(snapshot);
  refresh_ = true;
}

void ContextWorkbench::toggle_archived() {
  show_archived_ = !show_archived_;
  detail_offset_ = 0;
  refresh_ = true;
  notice_ = show_archived_ ? "Showing live + archived" : "Showing live only";
}

void ContextWorkbench::page(bool forward) {
  if (forward) {
    if (!detail_truncated_)
      return;
    detail_offset_ += detail_page_bytes;
  } else {
    if (detail_offset_ == 0)
      return;
    detail_offset_ =
        detail_offset_ > detail_page_bytes ? detail_offset_ - detail_page_bytes : 0;
  }
  refresh_ = true;
}

Result<void> ContextWorkbench::act(tui::InspectorAction action) {
  const auto before = controls_.state();
  const auto before_key = before.has_value() ? before.value().selected : std::nullopt;
  auto result = controls_.act(action);
  if (!result.has_value())
    return result;
  const auto after = controls_.state();
  const auto after_key = after.has_value() ? after.value().selected : std::nullopt;
  if (after_key != before_key) {
    selected_id_ = after_key ? parse_block_key(*after_key) : std::nullopt;
    detail_offset_ = 0;
    notice_.clear();
    refresh_ = true;
  }
  return result;
}

std::optional<ContextWorkbenchBlock> ContextWorkbench::selected_block() const {
  std::optional<std::uint64_t> id = selected_id_;
  if (const auto state = controls_.state(); state.has_value() && state.value().selected)
    id = parse_block_key(*state.value().selected);
  if (!id)
    return std::nullopt;
  for (const auto &block : snapshot_.blocks) {
    if (block.id == *id && (show_archived_ || !block.archived))
      return block;
  }
  return std::nullopt;
}

ContextWorkbenchAction ContextWorkbench::action_command(std::string_view verb) {
  if (verb == "flush") {
    if (snapshot_.pending_compactions == 0) {
      notice_ = "No pending deferred compactions";
      return {{}, notice_};
    }
    notice_ = "Flushing pending compactions";
    return {"/compact {\"op\":\"flush\"}", notice_};
  }
  const auto selected = selected_block();
  if (!selected) {
    notice_ = "No block selected";
    return {{}, notice_};
  }
  if (verb == "pin") {
    if (selected->archived) {
      notice_ = "Archived blocks cannot be pinned; F7 restores";
      return {{}, notice_};
    }
    const std::string op = selected->pinned ? "unpin" : "pin";
    notice_ =
        (selected->pinned ? "Unpinning #" : "Pinning #") + std::to_string(selected->id);
    return {"/compact {\"op\":\"" + op + "\",\"ids\":[" + std::to_string(selected->id) +
                "]}",
            notice_};
  }
  if (verb == "drop_or_restore") {
    if (selected->archived) {
      notice_ = "Restoring archived block #" + std::to_string(selected->id);
      return {"/restore " + std::to_string(selected->id), notice_};
    }
    if (selected->kind == "instruction") {
      notice_ = "Instruction blocks are protected from drop";
      return {{}, notice_};
    }
    if (selected->open) {
      notice_ = "Open exchange block cannot be dropped mid-call";
      return {{}, notice_};
    }
    if (selected->pinned) {
      notice_ =
          "Block #" + std::to_string(selected->id) + " is pinned; F6 unpins first";
      return {{}, notice_};
    }
    notice_ = "Dropping block #" + std::to_string(selected->id) + " now";
    return {"/compact {\"op\":\"drop\",\"ids\":[" + std::to_string(selected->id) +
                "],\"apply\":\"now\"}",
            notice_};
  }
  return {};
}

bool ContextWorkbench::refresh(const ContextDetailReader &reader) {
  refresh_ = false;
  const auto current = host_.snapshot();
  auto scene = base_candidate(current->view, current->revision);
  auto &list = scene.collections.front();
  list.title = show_archived_ ? "BLOCKS (live + archived)" : "BLOCKS (live only)";

  std::vector<const ContextWorkbenchBlock *> visible;
  visible.reserve(snapshot_.blocks.size());
  for (const auto &block : snapshot_.blocks) {
    if (!show_archived_ && block.archived)
      continue;
    visible.push_back(&block);
    std::string flags;
    if (block.archived)
      flags += " [A]";
    if (block.pinned)
      flags += " [P]";
    if (block.open)
      flags += " [O]";
    const auto preview = sanitize_single_line(block.preview, 44);
    std::string label = "#" + std::to_string(block.id) + " " + short_kind(block.kind) +
                        flags + " " + format_bytes(block.bytes);
    if (!preview.empty())
      label += " | " + preview;
    list.items.push_back(
        {block_key(block.id), std::move(label), block_target(block.id)});
  }

  if (visible.empty())
    list.notice = {tui::NoticeKind::none, "No context blocks yet"};

  // Keep selected block anchored by ID across snapshots.
  const ContextWorkbenchBlock *chosen = nullptr;
  if (selected_id_) {
    for (const auto *b : visible) {
      if (b->id == *selected_id_) {
        chosen = b;
        break;
      }
    }
  }
  if (!chosen && !visible.empty()) {
    chosen = visible.front();
    selected_id_ = chosen->id;
    detail_offset_ = 0;
  }
  if (!chosen)
    selected_id_.reset();

  auto &detail = scene.inspectors.front();
  detail_total_ = 0;
  detail_truncated_ = false;
  if (!chosen) {
    detail.title = "BLOCK DETAIL";
    detail.notice = {tui::NoticeKind::none, "Select a block to inspect"};
  } else {
    detail.title = "BLOCK #" + std::to_string(chosen->id) + " | " + chosen->kind +
                   (chosen->archived ? " (archived)" : " (live)");
    detail.target = block_target(chosen->id);
    detail.content_offset = detail_offset_;

    std::string meta = "Status: " + std::string{chosen->archived ? "archived" : "live"};
    if (chosen->pinned)
      meta += " | pinned";
    if (chosen->open)
      meta += " | open";
    meta += " | " + format_bytes(chosen->bytes) + " | " +
            std::to_string(chosen->items) + " item(s)";
    detail.lines.push_back({{std::move(meta), Ink::heading}});
    if (!chosen->label.empty())
      detail.lines.push_back(
          {{"Label: " + sanitize_single_line(chosen->label, 200), Ink::muted}});
    if (!chosen->replaces.empty()) {
      std::string rep = "Replaces blocks: ";
      for (std::size_t i = 0; i < chosen->replaces.size(); ++i) {
        if (i > 0)
          rep += ", ";
        rep += "#" + std::to_string(chosen->replaces[i]);
      }
      detail.lines.push_back({{std::move(rep), Ink::muted}});
    }
    detail.lines.push_back({{"", Ink::normal}});

    std::optional<ContextDetailSlice> slice;
    if (reader)
      slice = reader(chosen->id, detail_offset_, detail_page_bytes);
    if (slice) {
      detail_total_ = slice->total_bytes;
      detail_truncated_ = slice->truncated;
      std::string range = "Original JSON: bytes " + std::to_string(slice->offset) +
                          "-" + std::to_string(slice->offset + slice->content.size()) +
                          " of " + std::to_string(slice->total_bytes);
      if (slice->truncated || slice->offset > 0)
        range += " | Ctrl-Left/Right page";
      detail.lines.push_back({{std::move(range), Ink::muted}});
      detail.lines.push_back({{"", Ink::normal}});
      append_text_lines(detail.lines, slice->content, 160);
    } else {
      detail.lines.push_back(
          {{"Preview: " + sanitize_single_line(chosen->preview, 240), Ink::normal}});
      detail.notice = {tui::NoticeKind::loading,
                       "Original detail loads when session is idle"};
    }
  }

  const auto published = host_.publish(scene);
  if (!published.has_value()) {
    notice_ =
        "Workbench publish failed: " + std::string{error_name(published.error().code)};
    return false;
  }
  if (chosen) {
    if (const auto handle = host_.handle(collection_key); handle.has_value())
      (void)host_.select(handle.value(), block_key(chosen->id));
  }
  return true;
}

Result<tui::InspectorLayout> ContextWorkbench::render(ChatGrid &grid,
                                                      tui::Rect bounds) {
  return controls_.render(grid, bounds);
}

std::string ContextWorkbench::caption() const {
  std::string out = "CONTEXT WORKBENCH · e" + std::to_string(snapshot_.upstream_epoch) +
                    " · " + std::to_string(snapshot_.live_blocks) + " live";
  if (snapshot_.archived_blocks > 0)
    out += " · " + std::to_string(snapshot_.archived_blocks) + " arch";
  out += " · " + format_bytes(snapshot_.total_bytes);
  if (snapshot_.pending_compactions > 0)
    out += " · " + std::to_string(snapshot_.pending_compactions) + " pending";
  if (!notice_.empty())
    out += " · " + notice_;
  return out;
}

} // namespace blackbird
