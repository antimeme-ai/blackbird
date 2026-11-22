#include "blackbird/coding.hpp"
#include "blackbird/context_workbench.hpp"
#include "blackbird/json.hpp"
#include "blackbird/terminal.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

using namespace blackbird;

namespace {

void require(bool condition, const char *why) {
  if (!condition)
    throw std::runtime_error(why);
}

template <class T> T make_id(unsigned char n) {
  IdentityBytes bytes{};
  bytes[0] = std::byte{n};
  return unwrap(T::from_bytes(bytes));
}

void append_utf8(std::string &out, char32_t cp) {
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xc0U | (cp >> 6U));
    out += static_cast<char>(0x80U | (cp & 0x3fU));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xe0U | (cp >> 12U));
    out += static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU));
    out += static_cast<char>(0x80U | (cp & 0x3fU));
  } else {
    out += static_cast<char>(0xf0U | (cp >> 18U));
    out += static_cast<char>(0x80U | ((cp >> 12U) & 0x3fU));
    out += static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU));
    out += static_cast<char>(0x80U | (cp & 0x3fU));
  }
}

std::string render_text(const ChatGrid &grid) {
  std::string out;
  for (std::size_t row = 0; row < grid.height; ++row) {
    for (std::size_t col = 0; col < grid.width; ++col) {
      const auto &cell = grid.cells[row * grid.width + col];
      if (cell.width == 0)
        continue;
      append_utf8(out, cell.scalar);
      if (cell.length != 0)
        out.append(grid.tails, cell.tail, cell.length);
    }
    out += '\n';
  }
  return out;
}

struct SnapshotMeta {
  std::uint64_t epoch = 0;
  std::uint64_t pending = 0;
};

ContextWorkbenchSnapshot build_snapshot(const ContextStore &context,
                                        SnapshotMeta meta) {
  ContextWorkbenchSnapshot snap;
  snap.upstream_epoch = meta.epoch;
  snap.total_bytes = context.total_bytes();
  snap.live_blocks = context.blocks().size();
  snap.archived_blocks = context.archived().size();
  snap.pending_compactions = meta.pending;
  const auto listing = context.list(true);
  for (const auto &entry : field(listing, "blocks").array()) {
    ContextWorkbenchBlock b;
    b.id = std::stoull(field(entry, "id").number().text());
    b.kind = string_field(entry, "kind");
    b.preview = string_field(entry, "preview");
    b.bytes = std::stoull(field(entry, "bytes").number().text());
    b.items = std::stoull(field(entry, "items").number().text());
    b.pinned = std::get<bool>(field(entry, "pinned").value());
    b.open = std::get<bool>(field(entry, "open").value());
    b.archived = false;
    if (const auto *rep = entry.find("replaces")) {
      for (const auto &r : rep->array())
        b.replaces.push_back(std::stoull(r.number().text()));
    }
    snap.blocks.push_back(std::move(b));
  }
  if (const auto *arch = listing.find("archived")) {
    for (const auto &entry : arch->array()) {
      ContextWorkbenchBlock b;
      b.id = std::stoull(field(entry, "id").number().text());
      b.kind = string_field(entry, "kind");
      b.preview = string_field(entry, "preview");
      b.bytes = std::stoull(field(entry, "bytes").number().text());
      b.archived = true;
      snap.blocks.push_back(std::move(b));
    }
  }
  return snap;
}

void test_workbench_navigation_and_actions() {
  char pattern[] = "/tmp/blackbird-workbench-XXXXXX";
  const auto *path = ::mkdtemp(pattern);
  require(path != nullptr, "mkdtemp failed");
  struct Cleanup {
    std::filesystem::path dir;
    ~Cleanup() {
      std::error_code ignored;
      std::filesystem::remove_all(dir, ignored);
    }
  } cleanup{path};

  auto root =
      unwrap(RetainedState::create(std::make_unique<NativeJournalDirectory>(
                                       unwrap(NativeJournalDirectory::open(path))),
                                   "audit",
                                   {make_id<EnvironmentId>(1),
                                    make_id<AuditStreamId>(2),
                                    3,
                                    {1024 * 1024, 4 * 1024 * 1024},
                                    std::nullopt},
                                   {64 * 1024 * 1024, 10000}));
  AuditLog log{*root};
  ContextStore context{log};

  const auto id1 = context.append(
      {Value::object({{"role", Value{"user"}}, {"content", Value{"Operator prompt"}}})},
      "operator", BlockKind::instruction);
  const auto id2 =
      context.append({Value::object({{"type", Value{"function_call"}},
                                     {"call_id", Value{"c1"}},
                                     {"name", Value{"read_file"}},
                                     {"arguments", Value{"{\"path\":\"alpha.txt\"}"}}}),
                      Value::object({{"type", Value{"function_call_output"}},
                                     {"call_id", Value{"c1"}},
                                     {"output", Value{std::string(10000, 'X')}}})},
                     "provider.branch:test", BlockKind::exchange);
  const auto id3 =
      context.append({Value::object({{"role", Value{"assistant"}},
                                     {"content", Value{"Second exchange reply"}}})},
                     "provider.branch:test", BlockKind::exchange);

  // Archive id3 so we test live + archived together.
  CompactRequest drop3;
  drop3.op = CompactOp::drop;
  drop3.ids = {id3};
  (void)context.compact(drop3);

  ContextDetailReader reader =
      [&](std::uint64_t id, std::size_t offset,
          std::size_t limit) -> std::optional<ContextDetailSlice> {
    try {
      const auto res = context.read_block(id, {.offset = offset, .limit = limit});
      return ContextDetailSlice{
          .content = string_field(res, "content"),
          .total_bytes = std::stoull(field(res, "total_bytes").number().text()),
          .offset = std::stoull(field(res, "offset").number().text()),
          .truncated = std::get<bool>(field(res, "truncated").value()),
          .archived = std::get<bool>(field(res, "archived").value())};
    } catch (...) {
      return std::nullopt;
    }
  };

  ContextWorkbench wb;
  wb.update(build_snapshot(context, {.epoch = 2, .pending = 1}));
  wb.first_page();
  require(wb.open() && wb.focused(), "workbench opens focused");
  require(wb.refresh(reader), "initial refresh succeeds");

  // Block #1 (instruction) is selected first and protected from drop.
  auto sel = wb.selected_block();
  require(sel && sel->id == id1 && sel->kind == "instruction",
          "first block selected is instruction #1");
  const auto drop_instr = wb.action_command("drop_or_restore");
  require(drop_instr.command.empty() &&
              drop_instr.notice.find("protected") != std::string::npos,
          "instruction block cannot be dropped from workbench");

  // Flush pending generates audited /compact flush command.
  const auto flush = wb.action_command("flush");
  require(flush.command == "/compact {\"op\":\"flush\"}",
          "flush generates /compact flush command");

  // Move to block #2 (large exchange) and verify detail paging + pin/drop commands.
  unwrap(wb.act(tui::InspectorAction::next));
  require(wb.refresh(reader), "refresh after selecting #2");
  sel = wb.selected_block();
  require(sel && sel->id == id2 && !sel->archived, "selected block #2");

  ChatGrid grid;
  grid.reset(100, 24);
  const auto layout = unwrap(wb.render(grid, {0, 2, 100, 20}));
  require(layout.split, "wide workbench uses split collection + detail layout");
  const auto screen1 = render_text(grid);
  require(screen1.find("#2 exch") != std::string::npos &&
              screen1.find("Original JSON: bytes 0") != std::string::npos,
          "screen shows #2 row and first byte page");

  wb.page(true);
  require(wb.refresh(reader), "page forward loads next 8KiB slice");
  grid.reset(100, 24);
  (void)unwrap(wb.render(grid, {0, 2, 100, 20}));
  const auto screen2 = render_text(grid);
  require(screen2.find("Original JSON: bytes 8192") != std::string::npos,
          "paged detail shows offset 8192");

  const auto pin_cmd = wb.action_command("pin");
  require(pin_cmd.command ==
              "/compact {\"op\":\"pin\",\"ids\":[" + std::to_string(id2) + "]}",
          "F6 pin emits exact audited command");
  const auto drop_cmd = wb.action_command("drop_or_restore");
  require(drop_cmd.command == "/compact {\"op\":\"drop\",\"ids\":[" +
                                  std::to_string(id2) + "],\"apply\":\"now\"}",
          "F7 drop emits exact audited immediate drop command");

  // Move to archived block #3 and check restore + toggle_archived filter.
  unwrap(wb.act(tui::InspectorAction::next));
  require(wb.refresh(reader), "refresh after selecting archived #3");
  sel = wb.selected_block();
  require(sel && sel->id == id3 && sel->archived, "selected archived block #3");
  const auto restore_cmd = wb.action_command("drop_or_restore");
  require(restore_cmd.command == "/restore " + std::to_string(id3),
          "F7 on archived block emits /restore command");

  // Toggle archived off: #3 disappears and selection falls back cleanly.
  wb.toggle_archived();
  require(!wb.showing_archived(), "archived filter toggled off");
  require(wb.refresh(reader), "refresh with live-only filter");
  sel = wb.selected_block();
  require(sel && !sel->archived, "live-only filter hides archived blocks");

  // Caption reports epoch, live/archived counts, bytes, and pending count.
  const auto cap = wb.caption();
  require(cap.find("CONTEXT WORKBENCH") != std::string::npos &&
              cap.find("e2") != std::string::npos &&
              cap.find("2 live") != std::string::npos &&
              cap.find("1 arch") != std::string::npos &&
              cap.find("1 pending") != std::string::npos,
          "caption reflects epoch, live/archived counts, and pending count");

  // View picker exposes view.context-workbench and preserves draft.
  Composer composer;
  composer.draft("keep my draft");
  composer.views(tui::ViewRoute::conversation);
  for (const char ch : std::string_view{"view.context-workbench"})
    (void)composer.feed(ch);
  const auto chosen = composer.feed('\r');
  require(chosen.action == InputAction::select_view &&
              chosen.view == tui::ViewRoute::context_workbench &&
              composer.text() == "keep my draft",
          "view picker selects context_workbench while preserving draft");
}

} // namespace

int main() {
  try {
    test_workbench_navigation_and_actions();
    std::cout << "Context workbench unit tests passed.\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "context_workbench_test failed: " << e.what() << '\n';
    return 1;
  } catch (const Error &e) {
    std::cerr << "context_workbench_test error: " << error_name(e.code) << ':'
              << e.detail << '\n';
    return 1;
  }
}
