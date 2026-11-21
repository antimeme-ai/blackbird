#include "blackbird/chat_view.hpp"
#include "blackbird/coding.hpp"
#include "blackbird/command_inspector.hpp"
#include "blackbird/command_jobs.hpp"
#include "blackbird/context.hpp"
#include "blackbird/json.hpp"
#include "blackbird/terminal.hpp"
#include <chrono>
#include <clocale>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

using namespace blackbird;
namespace {
void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
template <class T> T make_id(unsigned char n) {
  IdentityBytes bytes{};
  bytes[0] = std::byte{n};
  return unwrap(T::from_bytes(bytes));
}
struct TempDir {
  std::filesystem::path path;
  explicit TempDir(const char *prefix) {
    std::string pattern = std::string{"/tmp/"} + prefix + "-XXXXXX";
    char *created = ::mkdtemp(pattern.data());
    require(created != nullptr, "mkdtemp failed");
    path = created;
  }
  ~TempDir() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};
std::string render_plain(ChatView &view, std::size_t width = 80) {
  std::string out;
  for (const auto &row : view.rows(width)) {
    out += chat_plain(row);
    out += '\n';
  }
  return out;
}

void test_paste_crlf_normalization() {
  Composer composer;
  const std::string pasted = "\x1b[200~line1\r\nline2\rline3\nline4\x1b"
                             "x\r\nline5\x1b[201~";
  for (const char byte : pasted)
    (void)composer.feed(byte);
  require(!composer.pasted(), "paste ended cleanly");
  require(composer.text() == "line1\nline2\nline3\nline4\x1bx\nline5",
          "RED: CRLF bracketed paste doubled newlines");
}

void test_osc52_and_last_text() {
  require(terminal_osc52_copy("hello world") == "\x1b]52;c;aGVsbG8gd29ybGQ=\x07",
          "OSC 52 base64 exact for 11 bytes");
  require(terminal_osc52_copy("a") == "\x1b]52;c;YQ==\x07",
          "OSC 52 base64 padding for 1 byte");
  require(terminal_osc52_copy("ab") == "\x1b]52;c;YWI=\x07",
          "OSC 52 base64 padding for 2 bytes");
  ChatView view;
  view.append(ChatKind::user, "first question");
  view.append(ChatKind::assistant, "first answer");
  view.append(ChatKind::assistant, "second answer");
  require(view.last_text(ChatKind::assistant) == "second answer",
          "last_text returns most recent assistant message");
  require(view.last_text(ChatKind::user) == "first question",
          "last_text returns most recent user message");
  require(view.plain_transcript().find("second answer") != std::string::npos,
          "plain_transcript includes conversation text");
}

void test_single_tool_card_and_fold() {
  ChatView view;
  view.tool_start("▸ read_file · sample.txt");
  view.tool_output("[read 3 lines · 17 B]\n");
  view.tool_complete("read_file completed · 4ms", Ink::success);
  // A second outer completion after tool_end must NOT mutate the inner card header.
  view.tool_complete("lua completed · 20ms", Ink::success);
  const auto plain = render_plain(view);
  require(plain.find("✓ read_file · sample.txt · 4ms") != std::string::npos,
          "tool header updates in place with check and duration");
  require(plain.find("4ms · 20ms") == std::string::npos,
          "nested outer completion must not double-mutate inner tool header");
  require(plain.find("[read 3 lines · 17 B]") != std::string::npos,
          "file preview stays inside single tool card");

  // Unknown/stopped outcome must use neutral bullet, never a false checkmark.
  ChatView unknown;
  unknown.tool_start("▸ exec · sleep 30");
  unknown.tool_complete("exec stopped; outcome unknown · 50ms", Ink::muted);
  const auto uplain = render_plain(unknown);
  require(uplain.find("• exec · sleep 30") != std::string::npos &&
              uplain.find("✓ exec") == std::string::npos,
          "unknown outcome uses bullet, never a false checkmark");

  // Long exec tool folds head+tail cleanly and keeps single card on completion.
  ChatView folded;
  folded.tool_start("▸ exec · seq 1 40");
  for (int i = 1; i <= 40; ++i)
    folded.tool_output("TOOL_" + std::to_string(i) + "\n");
  folded.tool_output("\n[exit 0]\n");
  folded.tool_complete("exec completed · 12ms", Ink::success);
  const auto fplain = render_plain(folded);
  std::size_t folded_cards = 0;
  for (std::size_t pos = 0; (pos = fplain.find("ACTIVITY", pos)) != std::string::npos;
       pos += 8)
    ++folded_cards;
  require(folded_cards == 1, "single tool call renders ONE ACTIVITY card, not two");
  require(fplain.find("✓ exec · seq 1 40 · 12ms") != std::string::npos,
          "folded exec header updates in place");
  require(fplain.find("┆ 35 more lines · Ctrl-O inspects") != std::string::npos,
          "folded exec preserves exact fold count");
  require(fplain.find("TOOL_39") != std::string::npos &&
              fplain.find("TOOL_40") != std::string::npos &&
              fplain.find("[exit 0]") != std::string::npos,
          "folded exec preserves exact tail lines");
}

void test_scroll_preserved_on_trim() {
  ChatView view;
  const auto before_clear = view.cleared_generation();
  const auto before_gen = view.generation();
  const std::string chunk(1024, 'x');
  for (int i = 0; i < 90; ++i)
    view.append(ChatKind::assistant, chunk + "\n");
  require(view.generation() > before_gen, "ring trim incremented generation");
  require(view.cleared_generation() == before_clear,
          "ring trim must not increment cleared_generation");
  view.clear();
  require(view.cleared_generation() == before_clear + 1,
          "explicit clear increments cleared_generation");
}

void test_bare_escape_dispatch() {
  using Clock = std::chrono::steady_clock;
  Composer idle;
  (void)idle.feed('\x1b');
  const auto bare = terminal_input_dispatch(idle, Clock::time_point::max(),
                                            Clock::time_point::min(), 0);
  require(bare.redraw && bare.bare_escape, "bare Esc sets bare_escape");

  Composer palette;
  (void)palette.feed(0); // open palette
  (void)palette.feed('\x1b');
  const auto dismissed = terminal_input_dispatch(palette, Clock::time_point::max(),
                                                 Clock::time_point::min(), 0);
  require(dismissed.redraw && !dismissed.bare_escape && !palette.palette_open(),
          "palette Esc dismissal does not fire bare_escape");

  Composer partial_sgr;
  for (const char ch : std::string_view{"\x1b[<64;5"})
    (void)partial_sgr.feed(ch);
  const auto sgr = terminal_input_dispatch(partial_sgr, Clock::time_point::max(),
                                           Clock::time_point::min(), 0);
  require(sgr.redraw && !sgr.bare_escape,
          "expired partial SGR mouse report does not fire bare_escape");
}

void test_file_tool_previews() {
  TempDir dir{"bb-ux-tools"};
  const JournalHeader header{make_id<EnvironmentId>(11),
                             make_id<AuditStreamId>(12),
                             1,
                             {8 * 1024 * 1024, 24 * 1024 * 1024},
                             std::nullopt};
  auto root = unwrap(
      RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                NativeJournalDirectory::open(dir.path.string()))),
                            "audit", header, {64 * 1024 * 1024, 10000}));
  AuditLog log{*root};
  ContextStore context{log};
  struct DummyProvider final : public CodingProvider {
    Value respond(const Value &,
                  const std::function<void(std::string_view)> &) override {
      throw std::runtime_error("unexpected provider call");
    }
  } provider;
  CodingEngine engine{log, context, provider, "test-model"};
  std::string captured;
  engine.process_output = [&](std::string_view text) { captured.append(text); };

  const auto file = (dir.path / "sample.txt").string();
  (void)engine.operator_call(
      "write_file", Value::object({{"path", Value{file}},
                                   {"content", Value{"alpha\nbeta\ngamma\n"}}}));
  require(captured.find("wrote") != std::string::npos ||
              captured.find("lines") != std::string::npos,
          "RED: write_file emitted no preview output");

  captured.clear();
  (void)engine.operator_call("read_file", Value::object({{"path", Value{file}}}));
  require(captured.find("read") != std::string::npos &&
              captured.find("3 lines") != std::string::npos,
          "RED: read_file emitted no preview output");

  captured.clear();
  (void)engine.operator_call("edit_file",
                             Value::object({{"path", Value{file}},
                                            {"old", Value{"beta"}},
                                            {"new", Value{"BETA_UPDATED"}}}));
  require(captured.find("- beta") != std::string::npos &&
              captured.find("+ BETA_UPDATED") != std::string::npos,
          "RED: edit_file emitted no diff preview");
}

void test_command_inspector_label() {
  CommandJobs jobs;
  const std::string id(32, 'a');
  jobs.start(id,
             Value::object({{"argv", Value{Value::Array{Value{"/bin/sh"}, Value{"-c"},
                                                        Value{"printf INSPECT_LBL"}}}},
                            {"timeout_seconds", Value{Number{10}}}}));
  const auto pump = [&] {
    for (const auto &event : jobs.drain())
      if (event.bytes)
        jobs.retained(event.job_id, event.offset + event.bytes->size());
      else
        jobs.settled(event.job_id, event.result);
  };
  (void)jobs.wait(id, {5000, 4096, false}, pump, [] { return false; });
  pump();

  CommandInspector inspector;
  inspector.toggle();
  (void)inspector.refresh(&jobs, false);
  const auto scene = inspector.host().snapshot();
  require(scene && scene->collections.size() == 1 &&
              scene->collections.front().items.size() == 1 &&
              scene->collections.front().items.front().label.find(
                  "printf INSPECT_LBL") != std::string::npos,
          "CommandInspector collection item includes human-readable command label");
  ChatGrid grid;
  grid.reset(120, 20);
  (void)unwrap(inspector.render(grid, {0, 0, 120, 20}));
  std::string rendered;
  for (std::size_t r = 0; r < grid.height; ++r) {
    for (std::size_t c = 0; c < grid.width; ++c)
      rendered.push_back(static_cast<char>(grid.cells[r * grid.width + c].scalar));
    rendered.push_back('\n');
  }
  require(rendered.find("printf INSPECT") != std::string::npos,
          "RED: CommandInspector listed command only by opaque 8-hex ID");
  // Non-truncated UTF-8 command label must stay intact (not lose its last byte).
  const std::string utf8_id(32, 'b');
  jobs.start(utf8_id,
             Value::object({{"argv", Value{Value::Array{Value{"/bin/sh"}, Value{"-c"},
                                                        Value{"echo café"}}}},
                            {"timeout_seconds", Value{Number{10}}}}));
  (void)jobs.wait(utf8_id, {5000, 4096, false}, pump, [] { return false; });
  pump();
  const auto obs = jobs.try_observe({});
  require(obs.status == CommandObservationStatus::ready && obs.row_count == 2 &&
              obs.rows[1].command_label_view() == "echo café",
          "UTF-8 command_label preserved without corruption");
  jobs.shutdown();
  pump();
}
} // namespace

int main(int argc, char **argv) {
  (void)std::setlocale(LC_CTYPE, "");
  const std::string_view selected = argc >= 2 ? std::string_view{argv[1]} : "all";
  const std::pair<std::string_view, void (*)()> cases[]{
      {"paste_crlf", test_paste_crlf_normalization},
      {"osc52_and_last_text", test_osc52_and_last_text},
      {"single_tool_card_and_fold", test_single_tool_card_and_fold},
      {"scroll_preserved_on_trim", test_scroll_preserved_on_trim},
      {"bare_escape_dispatch", test_bare_escape_dispatch},
      {"file_tool_previews", test_file_tool_previews},
      {"command_inspector_label", test_command_inspector_label},
  };
  bool failed = false;
  for (const auto &[name, fn] : cases) {
    if (selected != "all" && selected != name)
      continue;
    try {
      fn();
      std::cout << "PASS " << name << '\n';
    } catch (const std::exception &error) {
      std::cerr << "FAIL " << name << ": " << error.what() << '\n';
      failed = true;
    }
  }
  return failed ? 1 : 0;
}
