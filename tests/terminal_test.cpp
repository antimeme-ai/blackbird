#include "blackbird/json.hpp"
#include "blackbird/terminal.hpp"
#include "blackbird/tools.hpp"
#include <chrono>
#include <clocale>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <source_location>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
using namespace blackbird;
void check(bool good, std::source_location where = std::source_location::current()) {
  if (!good)
    throw std::runtime_error("terminal contract at line " +
                             std::to_string(where.line()));
}
void require(bool condition, std::string_view message) {
  if (!condition)
    throw std::runtime_error(std::string{message});
}
InputResult feed(Composer &c, std::string_view bytes) {
  InputResult result;
  for (char byte : bytes) {
    auto r = c.feed(byte);
    if (r.action != InputAction::none)
      result = std::move(r);
  }
  return result;
}
int main() {
  {
    Composer picker;
    picker.draft("unsent draft");
    picker.choices({{"/resume /tmp/a", "", "/tmp/a", "Session", "Alpha"},
                    {"/resume /tmp/b", "", "/tmp/b", "Session", "Beta"}},
                   "Sessions");
    check(picker.palette_lines(8)[0].starts_with("Sessions"));
    check(feed(picker, "\x1b[B\r").text == "/resume /tmp/b");
    check(picker.text() == "unsent draft");
    picker.choices({{"/resume /tmp/a", "", "/tmp/a", "Session", "Alpha"},
                    {"/resume /tmp/b", "", "/tmp/b", "Session", "Beta"}},
                   "Sessions");
    check(feed(picker, "\x1b[<65;1;1M\r").text == "/resume /tmp/b"); // Wheel selects.
    check(picker.text() == "unsent draft");
    picker.choices({{"/resume /tmp/a", "", "/tmp/a", "Session", "Alpha"}}, "Sessions");
    feed(picker, "\x1b");
    check(picker.flush_escape() && picker.text() == "unsent draft");
    Composer question;
    question.draft("EFFORT_DRAFT");
    feed(question, "\x1b[D");
    const auto caret = question.cursor();
    question.choices(
        {{"/effort low", "", "Use low effort", "Effort", "low", {}, true},
         {"/effort high", "", "Use high effort", "Effort", "high", {}, true}},
        "What level of effort did you intend?");
    check(question.palette_lines(6)[0].starts_with("What level of effort"));
    check(question.palette_lines(6)[3].find("Enter answers") != std::string::npos);
    const auto answered = feed(question, "\x1b[B\r");
    check(answered.action == InputAction::answer_question &&
          answered.text == "/effort high" && question.text() == "EFFORT_DRAFT" &&
          question.cursor() == caret);
    Composer views;
    views.draft("VIEW_DRAFT_SENTRY");
    feed(views, "\x1b[D\x1b[D");
    const auto view_cursor = views.cursor();
    const auto open_views = feed(views, "\x1c");
    check(open_views.action == InputAction::select_view &&
          open_views.text == "view.picker");
    views.views(tui::ViewRoute::conversation);
    check(views.palette_open());
    check(views.palette_lines(8)[0].starts_with("Views"));
    feed(views, "command runs");
    const auto view_choice = feed(views, "\r");
    check(view_choice.view == tui::ViewRoute::command_runs);
    check(view_choice.text == "view.command-runs" &&
          view_choice.action != InputAction::choose_command &&
          view_choice.action != InputAction::submit);
    check(views.text() == "VIEW_DRAFT_SENTRY" && views.cursor() == view_cursor);
    views.views(tui::ViewRoute::command_center);
    const auto inspecting_feed = [&](std::string_view bytes) {
      InputResult result;
      for (const auto byte : bytes) {
        auto next = views.feed(byte, nullptr, true);
        check(next.action != InputAction::instrument_action &&
              next.action != InputAction::inspect_next);
        if (next.action != InputAction::none)
          result = std::move(next);
      }
      return result;
    };
    inspecting_feed("\x1b[19~\x1b[B");
    const auto modal_choice = inspecting_feed("\r");
    check(modal_choice.view == tui::ViewRoute::command_runs);
    check(views.text() == "VIEW_DRAFT_SENTRY" && views.cursor() == view_cursor);
    views.views(tui::ViewRoute::result_comparison);
    inspecting_feed("\x1b");
    const auto dismissal =
        terminal_input_dispatch(views, std::chrono::steady_clock::time_point::max(),
                                std::chrono::steady_clock::time_point::min(), 0);
    check(dismissal.redraw && !dismissal.focus_editor && !views.palette_open());
    check(views.text() == "VIEW_DRAFT_SENTRY" && views.cursor() == view_cursor);
    Composer literal_view_key;
    feed(literal_view_key, "\x1b[200~\x1c\x1b[201~");
    check(literal_view_key.text() == "\x1c" && !literal_view_key.palette_open());
    Composer optional;
    check(feed(optional, "/runs\r").text == "/runs");
    Composer slash;
    feed(slash, "/");
    check(!slash.palette_lines(8).empty());
    feed(slash, "stats");
    check(slash.palette_lines(8)[1].find("/stats") != std::string::npos);
    check(feed(slash, "\r").text == "/stats");
    feed(slash, "/ne\t");
    check(slash.text() == "/new");
    check(feed(slash, "\r").text == "/new");
    feed(slash, "/mod\t");
    check(slash.text() == "/model ");
    check(slash.palette_lines(8).empty());
    slash.draft("");
    feed(slash, "/\x1b[B\t");
    check(slash.text() == "/keys");
    slash.draft("");
    feed(slash, "/\x1b");
    check(slash.flush_escape());
    check(slash.text() == "/" && slash.palette_lines(8).empty());
    slash.draft("");
    feed(slash, "\x1b[200~/stats\x1b[201~");
    check(slash.text() == "/stats" && slash.palette_lines(8).empty());
    slash.draft("/stats");
    check(slash.palette_lines(8).empty());
    slash.draft("");
    feed(slash, "/");
    check(feed(slash, "\x03").action == InputAction::cancel);
    slash.draft("");
    feed(slash, "/model\r");
    check(slash.text() == "/model ");
    feed(slash, "custom");
    check(feed(slash, "\r").text == "/model custom");
    feed(slash, "/statx\x7f");
    check(slash.palette_lines(8)[1].find("/stats") != std::string::npos);
    slash.draft("");
    feed(slash, "/tmp/file");
    check(slash.palette_lines(8).empty());
    slash.draft("");
    feed(slash, "/zzzz");
    check(feed(slash, "\r").text == "/zzzz");
  }
  try {
    (void)std::setlocale(LC_CTYPE, "en_US.UTF-8");
    for (const auto prefix : {std::string_view{"\x1b"}, std::string_view{"\x1b["},
                              std::string_view{"\x1b[1;"}, std::string_view{"\x1bO"}}) {
      using Clock = std::chrono::steady_clock;
      const auto deadline = Clock::time_point{std::chrono::milliseconds{50}};
      for (const short events :
           {short{0}, short{POLLIN}, short{POLLHUP}, short{POLLERR}}) {
        Composer polled;
        polled.draft("draft");
        feed(polled, prefix);
        const auto early = terminal_input_dispatch(
            polled, deadline - std::chrono::milliseconds{1}, deadline, events);
        check(early.read_input == (events != 0) && !early.redraw &&
              polled.escape_pending());
        const auto due = terminal_input_dispatch(polled, deadline, deadline, events);
        check(due.read_input == (events != 0) && due.redraw &&
              !polled.escape_pending());
        feed(polled, "x");
        check(polled.text() == "draftx");
      }
      Composer expired;
      expired.draft("draft");
      feed(expired, "\x1b[D");
      feed(expired, prefix);
      check(expired.escape_pending());
      check(expired.flush_escape()); // The owner has observed the deadline.
      check(!expired.escape_pending() && !expired.flush_escape());
      check(expired.text() == "draft" && expired.cursor() == 4);
      feed(expired, "X");
      check(expired.text() == "drafXt" && expired.cursor() == 5);
      check(feed(expired, "\x03").action == InputAction::cancel);
    }
    Composer fragmented;
    fragmented.draft("one two");
    for (const char byte : std::string_view{"\x1b[1;5D"})
      check(fragmented.feed(byte).action == InputAction::none);
    check(!fragmented.escape_pending() && fragmented.cursor() == 4);
    for (const char byte : std::string_view{"\x1bOH"})
      check(fragmented.feed(byte).action == InputAction::none);
    check(!fragmented.escape_pending() && fragmented.cursor() == 0);
    feed(fragmented, "\x1b[1;3C");
    check(fragmented.cursor() == 3);
    check(feed(fragmented, "\x1b[6~").action == InputAction::page_down);
    Composer paste_timeout;
    feed(paste_timeout, "\x1b[200~/stats\r\x03");
    check(paste_timeout.pasted() && paste_timeout.text() == "/stats\n\x03");
    // Fragmented paste termination stays recognized even when deadline service
    // occurs between its bytes. Pasted controls remain literal until termination.
    for (const char byte : std::string_view{"\x1b[201~"}) {
      check(paste_timeout.feed(byte).action == InputAction::none);
      check(!paste_timeout.flush_escape());
    }
    check(!paste_timeout.pasted() && !paste_timeout.escape_pending());
    check(feed(paste_timeout, "\r").text == "/stats\n\x03");
    Composer palette_key;
    palette_key.draft("unsent draft");
    feed(palette_key, std::string_view{"\0stats", 6});
    check(palette_key.text() == "unsent draft"); // Search never edits the hidden draft.
    check(palette_key.palette_open());
    check(palette_key.palette_lines(4)[1].starts_with("> /stats"));
    const auto selected = feed(palette_key, "\r");
    check(selected.action == InputAction::choose_command && selected.text == "/stats");
    check(!palette_key.palette_open() && palette_key.text() == "unsent draft");
    feed(palette_key, "\x14SESSION");
    check(palette_key.palette_lines(4)[1].find("/session") != std::string::npos);
    feed(palette_key, "\x1b");
    check(palette_key.flush_escape() && !palette_key.palette_open());
    check(palette_key.text() == "unsent draft" && palette_key.cursor() == 12);
    feed(palette_key, std::string_view{"\0zzzz", 5});
    check(palette_key.palette_lines(4)[1].find("No matching") != std::string::npos);
    check(feed(palette_key, "\r").action == InputAction::none &&
          palette_key.palette_open());
    feed(palette_key, "\x03");
    feed(palette_key, "\x14\x1b[200~stats\r\x07\x1b[201~");
    check(palette_key.palette_open() && palette_key.text() == "unsent draft");
    check(palette_key.palette_lines(1).size() == 1 &&
          palette_key.palette_lines(2).size() == 2);
    feed(palette_key, "\x14\x14"); // Close, reopen full catalog.
    feed(palette_key, "\x1b[B\x1b[B");
    const auto moved = palette_key.palette_lines(4);
    check(moved[2].starts_with("> /commands"));
    feed(palette_key, "\x14");
    check(!palette_key.palette_open() && palette_key.text() == "unsent draft");
    Composer editor_key;
    feed(editor_key, "draft");
    check(feed(editor_key, "\x07").action != InputAction::none &&
          editor_key.text() == "draft");
    Composer completion;
    feed(completion, "/hel\t");
    check(completion.text() == "/help" && completion.cursor() == 5);
    feed(completion, "\x15/mod\t");
    check(completion.text() == "/model ");
    feed(completion, "gpt-example\t");
    check(completion.text() == "/model gpt-example");
    feed(completion, "\x15/dra\t");
    check(completion.text() == "/drafts"); // Tab fills the visible selected row.
    feed(completion, "\x15/draft");
    feed(completion, "\t");
    check(completion.text() == "/draft ");
    feed(completion, "\x15/co\t");
    check(completion.text() == "/commands"); // Selection is shown before filling.
    feed(completion, "\x15/unknown\t");
    check(completion.text() == "/unknown");
    feed(completion, "\x15/hel\x1b[D\t");
    check(completion.text() == "/hel" && completion.cursor() == 3);
    feed(completion, "\x15\x1b[200~/hel\t\x1b[201~");
    check(completion.text() == "/hel\t"); // Paste is literal, never completion.
    check(terminal_command_hint("/co").find("/compact") != std::string::npos);
    check(terminal_command_hint("/co").find("/context") != std::string::npos);
    check(terminal_command_hint("/model foo").find("NAME") != std::string::npos);
    check(terminal_command_hint("/unknown").starts_with("Unknown command"));
    check(terminal_command_hint("ordinary draft").empty());
    check(terminal_command_hint("/lua\ncode").empty());
    check(terminal_help().find("/sessions") != std::string::npos);
    check(terminal_help().find("not model context") != std::string::npos);
    check(terminal_key_help().find("keep unsent draft") != std::string::npos);
    // Queued process output joins only within one stream (rhi.8 attribution).
    check(terminal_process_join({.queued = "FG_1\n", .next = "FG_2\n"}) ==
          std::optional<std::string_view>{"FG_2\n"});
    check(terminal_process_join(
              {.queued = "\n[command J]\nBG_1\n", .next = "\n[command J]\nBG_2\n"}) ==
          std::optional<std::string_view>{"BG_2\n"});
    check(
        !terminal_process_join({.queued = "\n[command J]\nBG_1\n", .next = "FG_2\n"}));
    check(!terminal_process_join(
        {.queued = "\n[command J]\nBG_1\n", .next = "\n[command K]\nBG_1\n"}));
    check(
        !terminal_process_join({.queued = "FG_1\n", .next = "\n[command J]\nBG_1\n"}));
    check(!terminal_process_join({.queued = "TOOL_40\n", .next = "\n[exit 0]\n"}));
    check(terminal_process_join({.queued = "\n[exit 0]\n", .next = "more\n"}) ==
          std::optional<std::string_view>{"more\n"});
    check(terminal_context_badge("compacted", 10000, 50) ==
          "◆ CONTEXT compacted −10 KiB");
    check(terminal_context_badge("restored", 50, 1000) == "◆ CONTEXT restored +950 B");
    check(terminal_context_badge("edited", 7, 7) == "◆ CONTEXT edited ±0 B");
    check(terminal_context_badge("compacted", std::nullopt, 10) ==
          "◆ CONTEXT compacted");
    Composer multiline;
    feed(multiline, "history\r");
    multiline.draft("abcd\nx\n12345");
    feed(multiline, "\x1b[A");
    check(multiline.text() == "abcd\nx\n12345" && multiline.cursor() == 6);
    feed(multiline, "\x1b[A");
    check(multiline.cursor() == 4); // Sticky column survives the short middle line.
    feed(multiline, "\x1b[B\x1b[B");
    check(multiline.cursor() == 12);
    feed(multiline, "\x1b[1;5H");
    check(multiline.cursor() == 0);
    feed(multiline, "\x10"); // Explicit history, even for multiline drafts.
    check(multiline.text() == "history");
    feed(multiline, "\x0e");
    check(multiline.text() == "abcd\nx\n12345" && multiline.cursor() == 0);
    feed(multiline, "\x1b[B\x05");
    check(multiline.cursor() == 6); // Ctrl-E ends this line, not the whole draft.
    feed(multiline, "\x01");
    check(multiline.cursor() == 5);
    Composer words;
    words.draft("one é界 two");
    feed(words, "\x1b"
                "b");
    check(words.cursor() == 10);
    feed(words, "\x17");
    check(words.text() == "one two" && words.cursor() == 4);
    feed(words, "\x19");
    check(words.text() == "one é界 two" && words.cursor() == 10);
    feed(words, "\x1b[1;5H\x1b[1;5C");
    check(words.cursor() == 3);
    feed(words, "\x1b"
                "d");
    check(words.text() == "one two");
    words.draft("first\nsecond");
    feed(words, "\x1b[1;5H\x05\x0b"); // At line end, kill the newline.
    check(words.text() == "firstsecond");
    feed(words, "\x19");
    check(words.text() == "first\nsecond");
    Composer columns;
    columns.draft("a界z\nx\n1234");
    feed(columns, "\x1b[A\x1b[A");
    check(columns.cursor() == 5); // Four terminal cells, not four UTF-8 bytes.
    feed(columns, "\x1b[D\x1b[B\x1b[B");
    check(columns.cursor() ==
          columns.text().size() - 1); // Horizontal motion resets goal.
    columns.draft("a\n\nb");
    feed(columns, "\x1b[A");
    check(columns.cursor() == 2);
    feed(columns, "\x1b[A");
    check(columns.cursor() == 1);
    columns.draft("abc\ndef");
    feed(columns, "\x01\x1b[A");
    check(columns.cursor() == 0);
    feed(columns, "\x0b");
    check(columns.text() == "\ndef");
    feed(columns, "\x19");
    check(columns.text() == "abc\ndef" && columns.cursor() == 3);
    feed(columns, "\x15\x19");
    check(columns.text() == "abc\ndef");
    columns.draft("界\nx");
    feed(columns, "\x1b[A");
    check(columns.cursor() == 0); // Can't place the cursor inside a wide glyph.
    feed(columns, "\x1b[B");
    check(columns.cursor() == columns.text().size());
    columns.draft("a\tb\n123");
    feed(columns, "\x1b[A");
    check(columns.cursor() == 2); // Pasted tab has the renderer's two-cell width.
    columns.draft("éx\nab");
    feed(columns, "\x1b[A");
    check(columns.cursor() == 4); // Combining mark contributes no extra cell.
    columns.draft(std::string{"\xff\nabcd", 6});
    feed(columns, "\x1b[A");
    check(columns.cursor() == 1); // Invalid byte is displayed as four escaped cells.
    columns.restore({"", 0, {}, {}});
    feed(columns, "\x19");
    check(columns.text().empty()); // Restore does not inherit a prior kill buffer.
    Composer full;
    full.draft(std::string(1024 * 1024, 'a'));
    feed(full, "\x17");
    check(full.text().empty());
    full.draft("b");
    feed(full, "\x19");
    check(full.text() == "b" && full.cursor() == 1); // Oversized yank is atomic/no-op.
    Composer literal;
    feed(literal, "\x1b[200~a\x17\x0b\x19\x10\x0e\x1b[201~");
    check(literal.text() == "a\x17\x0b\x19\x10\x0e");
    Composer c;
    feed(c, "aéz");
    feed(c, "\x1b[D\x7f");
    check(c.text() == "az" && c.cursor() == 1);
    feed(c, "b");
    check(feed(c, "\r").text == "abz");
    feed(c, "draft\x1b[A");
    check(c.text() == "abz");
    feed(c, "\x1b[B");
    check(c.text() == "draft");
    check(feed(c, "\x03").action == InputAction::cancel && c.text() == "draft");
    feed(c, "\x15");
    feed(c, "\x1b[200~one\ntwo\rthree\x1b[201~");
    check(c.text() == "one\ntwo\nthree");
    check(feed(c, "\r").text == "one\ntwo\nthree");
    feed(c, "x\x1b\ry");
    check(c.text() == "x\ny");
    feed(c, "\x15");
    // Shift, Alt and Ctrl Enter in Ghostty's default and kitty's CSI-u forms.
    for (const std::string_view enter : {"\x1b[27;2;13~", "\x1b[13;2u", "\x1b[27;3;13~",
                                         "\x1b[13;3u", "\x1b[27;5;13~", "\x1b[13;5u"}) {
      feed(c, "\x15");
      check(feed(c, std::string{"x"} + std::string{enter} + "y").action ==
            InputAction::none);
      check(c.text() == "x\ny" && c.cursor() == 3);
    }
    check(feed(c, "\r").text == "x\ny");
    // An SGR wheel report scrolls; it never moves the caret or recalls history.
    feed(c, "wheel draft");
    check(feed(c, "\x1b[<64;10;5M").action == InputAction::scroll_up);
    check(feed(c, "\x1b[<65;10;5M").action == InputAction::scroll_down);
    check(feed(c, "\x1b[<68;1;1M").action == InputAction::scroll_up); // Shift held.
    check(c.text() == "wheel draft" && c.cursor() == 11);
    // SGR button press/drag/release emit native chat-selection events;
    // right-click and other non-left buttons are ignored without leaking into the
    // draft.
    const auto press = feed(c, "\x1b[<0;3;4M");
    check(press.action == InputAction::mouse_press && press.mouse_col == 2 &&
          press.mouse_row == 3);
    const auto drag = feed(c, "\x1b[<32;7;4M");
    check(drag.action == InputAction::mouse_drag && drag.mouse_col == 6 &&
          drag.mouse_row == 3);
    const auto rel = feed(c, "\x1b[<0;7;4m");
    check(rel.action == InputAction::mouse_release && rel.mouse_col == 6 &&
          rel.mouse_row == 3);
    check(feed(c, "\x1b[<2;3;4M").action == InputAction::none);
    check(c.text() == "wheel draft" && c.cursor() == 11 && !c.escape_pending());
    // X10 reports from terminals that ignore ?1006: raw coordinate bytes,
    // including parameter-range and final-looking ones, never reach the draft.
    check(feed(c, "\x1b[M`!!").action == InputAction::scroll_up);
    check(feed(c, "\x1b[Ma!!").action == InputAction::scroll_down);
    check(feed(c, "\x1b[M`5m").action == InputAction::scroll_up);
    check(feed(c, "\x1b[M 55\x1b[M#5m").action == InputAction::none);
    feed(c, "k");
    check(c.text() == "wheel draftk" && c.cursor() == 12);
    // A report split across reads past the escape deadline drops its tail.
    feed(c, "\x1b[<64;5");
    check(c.flush_escape());
    feed(c, ";5M");
    feed(c, "\x1b[M`");
    check(c.flush_escape());
    feed(c, "!!z");
    check(c.text() == "wheel draftkz" && c.cursor() == 13);
    // A bare CSI M (also SCO F1) that expires arms no tail; ESC aborts X10.
    feed(c, "\x1b[M");
    check(c.flush_escape());
    feed(c, "12\x1b[M`\x1b[D");
    check(c.text() == "wheel draftkz12" && c.cursor() == 14);
    // An input-owner handoff forgets a partial escape without arming a tail,
    // or skips the rest of a report the PTY child was holding.
    feed(c, "\x1b[<64;5");
    c.reset_escape();
    feed(c, "34");
    check(c.text() == "wheel draftkz1342" && !c.escape_pending());
    c.reset_escape(true);
    feed(c, ";5Mq");
    check(c.text() == "wheel draftkz134q2"); // The cursor sits before the final 2.
    feed(c, "\x15");
    // Down past the newest entry restores the draft and its cursor (2bj).
    feed(c, "draft\x1b[D\x1b[D\x1b[A");
    check(c.text() == "x\ny");
    feed(c, "\x1b[B");
    check(c.text() == "draft" && c.cursor() == 3);
    feed(c, "\x15");
    check(feed(c, "\x04").action == InputAction::quit);
    check(terminal_lines("é界x", 3) == std::vector<std::string>{"é界", "x"});
    check(terminal_lines("x\x1b[31m", 20)[0] == "x\\x1b[31m");
    check(terminal_lines("a\nb", 20) == std::vector<std::string>{"a", "b"});
    // Old end=90 (100-10). Append20, trim10: same content end is80,
    // so new110 lines require scroll30, NOT net-growth scroll20.
    check(terminal_scroll_after_output({.scroll = 10,
                                        .previous = 100,
                                        .before_trim = 120,
                                        .after_trim = 110,
                                        .height = 10}) == 30);
    check(terminal_scroll_after_output({.scroll = 0,
                                        .previous = 100,
                                        .before_trim = 120,
                                        .after_trim = 110,
                                        .height = 10}) == 0);
    check(terminal_scroll_after_output({.scroll = 80,
                                        .previous = 100,
                                        .before_trim = 120,
                                        .after_trim = 70,
                                        .height = 10}) == 60);
    check(terminal_scroll_after_output({.scroll = 10,
                                        .previous = 100,
                                        .before_trim = 120,
                                        .after_trim = 120,
                                        .height = 10}) == 30);
    std::string long_line(2 * 1024 * 1024, 'x');
    long_line += "éEND\n";
    trim_terminal_transcript(long_line);
    check(long_line.size() <= 1024 * 1024 && long_line.ends_with("éEND\n") &&
          long_line.starts_with("[Older display trimmed"));
    std::string unicode_line;
    for (std::size_t n = 0; n < 600000; ++n)
      unicode_line += "é";
    trim_terminal_transcript(unicode_line);
    check(unicode_line.size() <= 1024 * 1024 &&
          dump_json(Value{unicode_line}).has_value());
    const char *old_visual = std::getenv("VISUAL");
    const char *old_editor = std::getenv("EDITOR");
    const std::optional<std::string> visual =
        old_visual ? std::optional<std::string>{old_visual} : std::nullopt;
    const std::optional<std::string> editor =
        old_editor ? std::optional<std::string>{old_editor} : std::nullopt;
    check(setenv("VISUAL", "sh -c 'printf edited > \"$1\"' --", 1) == 0);
    auto result = edit_terminal_draft("original");
    check(result.accepted && result.text == "edited");
    check(setenv("VISUAL", "sh -c 'printf bad > \"$1\"; exit 7' --", 1) == 0);
    check(!edit_terminal_draft("original").accepted);
    check(setenv("VISUAL", "no-such-arco-editor-123", 1) == 0);
    check(!edit_terminal_draft("original").accepted);
    check(setenv("VISUAL", "sh -c 'rm \"$1\"; ln -s /dev/null \"$1\"' --", 1) == 0);
    check(!edit_terminal_draft("original").accepted);
    check(setenv("VISUAL", "sh -c 'rm \"$1\"; mkfifo \"$1\"' --", 1) == 0);
    check(!edit_terminal_draft("original").accepted);
    check(setenv("VISUAL",
                 "sh -c 'dd if=/dev/zero of=\"$1\" bs=1024 count=1025 2>/dev/null' --",
                 1) == 0);
    check(!edit_terminal_draft("original").accepted);
    check(setenv("VISUAL", "", 1) == 0);
    check(setenv("EDITOR", "sh -c 'printf fallback > \"$1\"' --", 1) == 0);
    check(edit_terminal_draft("original").text == "fallback");
    if (visual)
      check(setenv("VISUAL", visual->c_str(), 1) == 0);
    else
      check(unsetenv("VISUAL") == 0);
    if (editor)
      check(setenv("EDITOR", editor->c_str(), 1) == 0);
    else
      check(unsetenv("EDITOR") == 0);
    char path[] = "/tmp/arco-ui-state-XXXXXX";
    const auto dir = mkdtemp(path);
    check(dir != nullptr);
    const auto file = std::filesystem::path{dir} / "ui-state.bbm";
    TerminalState state{std::string{"x\xff\0", 3}, 1, {"sent"}, {"queued"}};
    save_terminal_state(file, state);
    const auto loaded = load_terminal_state(file);
    check(loaded.draft == state.draft && loaded.cursor == 1 &&
          loaded.history == state.history && loaded.queued == state.queued);
    Composer restored;
    restored.restore(loaded);
    feed(restored, "Z");
    check(restored.text() == std::string{"xZ\xff\0", 4});
    save_terminal_state(file, {"é", 1, {}, {}});
    check(load_terminal_state(file).cursor == 0);
    save_terminal_state(file, state);
    auto too_big = state;
    too_big.queued.resize(129);
    bool rejected = false;
    try {
      save_terminal_state(file, too_big);
    } catch (const Error &e) {
      rejected = e.code == ErrorCode::capacity;
    }
    check(rejected && load_terminal_state(file).queued == state.queued);
    too_big = state;
    too_big.history = {std::string(1024 * 1024, 'a'), "b"};
    rejected = false;
    try {
      save_terminal_state(file, too_big);
    } catch (const Error &e) {
      rejected = e.code == ErrorCode::capacity;
    }
    check(rejected);
    write_file(file, "broken");
    rejected = false;
    try {
      (void)load_terminal_state(file);
    } catch (const Error &) {
      rejected = true;
    }
    check(rejected);
    Composer inspection;
    inspection.draft("kept draft");
    feed(inspection, "\x1b[D");
    const auto kept_cursor = inspection.cursor();
    check(inspection.feed('\x18').action == InputAction::center_toggle);
    check(inspection.text() == "kept draft" && inspection.cursor() == kept_cursor);
    check(inspection.feed('\x18', nullptr, true).action == InputAction::center_toggle);
    check(inspection.feed('\x0f').action == InputAction::inspect_toggle);
    check(inspection.text() == "kept draft" && inspection.cursor() == kept_cursor);
    InputResult navigation;
    for (const auto byte : std::string_view{"\x1b[A"})
      navigation = inspection.feed(byte, nullptr, true);
    check(navigation.action == InputAction::inspect_previous);
    check(inspection.text() == "kept draft" && inspection.cursor() == kept_cursor);
    const auto inspect_feed = [&](std::string_view bytes) {
      InputResult last;
      for (const auto byte : bytes)
        if (auto next = inspection.feed(byte, nullptr, true);
            next.action != InputAction::none)
          last = std::move(next);
      return last.action;
    };
    check(inspect_feed("\x1b[<64;2;2M") == InputAction::inspect_previous);
    check(inspect_feed("\x1b[<65;2;2M") == InputAction::inspect_next);
    // A click keeps inspector focus instead of returning to the draft.
    check(inspect_feed("\x1b[<0;2;2M\x1b[<0;2;2m") == InputAction::none);
    check(inspection.text() == "kept draft" && inspection.cursor() == kept_cursor);
    {
      // With the slash menu open, the wheel follows the arrows to the inspector.
      Composer slash_inspect;
      feed(slash_inspect, "/");
      InputResult arrow, wheel;
      for (const auto byte : std::string_view{"\x1b[A"})
        arrow = slash_inspect.feed(byte, nullptr, true);
      for (const auto byte : std::string_view{"\x1b[<64;1;1M"})
        wheel = slash_inspect.feed(byte, nullptr, true);
      check(arrow.action == InputAction::inspect_previous &&
            wheel.action == InputAction::inspect_previous);
    }
    check(inspection.feed('\t', nullptr, true).action ==
          InputAction::inspect_toggle_focus);
    check(inspection.feed('X', nullptr, true).action ==
          InputAction::inspect_focus_editor);
    check(inspection.text() == "kept drafXt");
    inspection.draft("");
    for (const auto byte : std::string_view{"\x1b[200~"})
      navigation = inspection.feed(byte, nullptr, true);
    check(navigation.action == InputAction::inspect_focus_editor &&
          inspection.pasted());
    check(inspection.feed('\x0f').action == InputAction::none);
    check(inspection.feed('\x03').action == InputAction::none);
    check(inspection.feed('\x18').action == InputAction::none);
    feed(inspection, "\x1b[201~");
    check(inspection.text() == std::string{"\x0f\x03\x18", 3});
    TerminalUI task_ui{"Task observation fixture"};
    TaskState source_tasks;
    check(task_ui.try_observe_tasks({}).publication ==
          TaskPublicationStatus::uninitialized);
    task_ui.tasks(source_tasks.snapshot(), {2, {}, {}, source_tasks.revision()});
    check(task_ui.try_observe_tasks({}).publication == TaskPublicationStatus::ready);
    auto publish_add = [&] {
      auto prepared = source_tasks.prepare(unwrap(parse_json(
          R"({"op_id":"publication)" + std::to_string(source_tasks.revision()) +
          R"(","base":)" + std::to_string(source_tasks.revision()) +
          R"(,"ops":[{"op":"add","title":"Actual task"}]})")));
      auto packet = prepared.packet;
      source_tasks.commit(std::move(prepared));
      return packet;
    };
    auto delta = publish_add();
    task_ui.tasks(delta, {3, {}, {}, source_tasks.revision()});
    const auto accepted = task_ui.try_observe_tasks({});
    check(accepted.publication == TaskPublicationStatus::ready &&
          accepted.value.revision == 1 && accepted.value.row_count == 1 &&
          accepted.origin.revision == std::optional<std::uint64_t>{1});
    auto missed = publish_add();
    auto gap = publish_add();
    bool publication_rejected = false;
    try {
      task_ui.tasks(gap, {3, {}, {}, source_tasks.revision()});
    } catch (const Error &) {
      publication_rejected = true;
    }
    const auto stale = task_ui.try_observe_tasks({});
    check(publication_rejected && stale.publication == TaskPublicationStatus::stale &&
          stale.value.revision == 1 &&
          stale.origin.revision == std::optional<std::uint64_t>{1});
    task_ui.tasks(missed, {3, {}, {}, 2});
    check(task_ui.try_observe_tasks({}).publication == TaskPublicationStatus::stale);
    task_ui.tasks(source_tasks.snapshot(), {2, {}, {}, source_tasks.revision()});
    const auto repaired = task_ui.try_observe_tasks({});
    check(repaired.publication == TaskPublicationStatus::ready &&
          repaired.value.revision == 3 && repaired.value.row_count == 3);

    // Wave 7B-1: Party Chat Alt+P / Esc / Alt+Shift+P decoding, docked vs overlay
    // rendering, ambient status pill, help mentions, and !cmd shell escape.
    {
      check(terminal_help().find("/party") != std::string::npos);
      check(terminal_help().find("Alt+P party") != std::string::npos);
      check(terminal_help().find("!cmd shell") != std::string::npos);
      check(terminal_key_help().find("Alt+P party") != std::string::npos);
      check(terminal_key_help().find("!cmd shell") != std::string::npos);

      Composer party_keys;
      party_keys.draft("preserved draft");
      feed(party_keys, "\x1b[D\x1b[D");
      const auto saved_cursor = party_keys.cursor();
      check(feed(party_keys, "\x1b"
                             "p")
                .action == InputAction::party_toggle);
      check(party_keys.text() == "preserved draft" &&
            party_keys.cursor() == saved_cursor);
      check(feed(party_keys, "\x1b[112;3u").action == InputAction::party_toggle);
      check(feed(party_keys, "\x1b"
                             "P")
                .action == InputAction::party_hide);
      check(feed(party_keys, "\x1b[80;3u").action == InputAction::party_hide);
      check(party_keys.text() == "preserved draft" &&
            party_keys.cursor() == saved_cursor);
      // Bare Esc decodes cleanly via escape deadline without touching draft.
      feed(party_keys, "\x1b");
      const auto esc = terminal_input_dispatch(
          party_keys, std::chrono::steady_clock::time_point::max(),
          std::chrono::steady_clock::time_point::min(), 0);
      check(esc.bare_escape && party_keys.text() == "preserved draft" &&
            party_keys.cursor() == saved_cursor);

      // Docked (>= 120 cols) vs overlay (< 120 cols) PartyChatPane layout & grid
      // render.
      PartySnapshot snap;
      snap.room_scope = "ops/alpha";
      snap.party_config_present = true;
      PartyParticipant op;
      op.id = "patrick";
      op.role = PartyMemberRole::operator_human;
      op.state = PartyParticipantState::online;
      op.local_self = true;
      PartyParticipant wm;
      wm.id = "wintermute";
      wm.role = PartyMemberRole::platoon_leader;
      wm.state = PartyParticipantState::working;
      wm.model = "deepseek-chat";
      snap.participants = {op, wm};
      PartyMessage msg;
      msg.id = "m1";
      msg.sender_id = "wintermute";
      msg.sender_role = PartyMemberRole::platoon_leader;
      msg.target = "@all";
      msg.body = "docked split ready";
      snap.messages = {msg};

      PartyChatPane pane{snap};
      pane.set_open(true);
      pane.set_focused(true);

      auto grid_plain = [](const ChatGrid &g) {
        std::string out;
        for (const auto &cell : g.cells) {
          if (cell.width == 0)
            continue;
          if (cell.scalar < 0x80)
            out.push_back(static_cast<char>(cell.scalar));
          else if (cell.scalar == U'│')
            out += "│";
          else if (cell.scalar == U'╭')
            out += "╭";
          else if (cell.scalar == U'╰')
            out += "╰";
        }
        return out;
      };

      const auto wide_layout = terminal_party_pane_layout({136, 28});
      check(wide_layout.docked && wide_layout.width >= 42 && wide_layout.width <= 48 &&
            wide_layout.main_width + wide_layout.width + 2 == 136 &&
            wide_layout.col == wide_layout.main_width + 2);
      ChatGrid wide_grid;
      wide_grid.reset(136, 28);
      terminal_render_party_pane(wide_grid, pane, wide_layout);
      const std::string wide_text = grid_plain(wide_grid);
      check(wide_text.find("PARTY CHAT") != std::string::npos &&
            wide_text.find("docked") != std::string::npos &&
            wide_text.find("split") != std::string::npos &&
            wide_text.find("ready") != std::string::npos &&
            wide_grid.cells[wide_layout.main_width].scalar == U'│');

      const auto narrow_layout = terminal_party_pane_layout({92, 24});
      check(!narrow_layout.docked && narrow_layout.main_width == 92 &&
            narrow_layout.width < 92 && narrow_layout.height < 24);
      ChatGrid narrow_grid;
      narrow_grid.reset(92, 24);
      terminal_render_party_pane(narrow_grid, pane, narrow_layout);
      const std::string narrow_text = grid_plain(narrow_grid);
      check(narrow_text.find("PARTY CHAT") != std::string::npos &&
            narrow_text.find("Party Chat") != std::string::npos &&
            narrow_text.find("docked split ready") != std::string::npos &&
            narrow_text.find("╭") != std::string::npos &&
            narrow_text.find("╰") != std::string::npos);

      // Ambient Party status badge: active (closed, with & without unread) vs
      // solo/empty.
      PartyChatPane closed_active{snap};
      check(terminal_party_is_active(snap));
      const std::string active_pill = terminal_party_status_pill(closed_active, false);
      check(active_pill == "● PARTY ops/alpha · 2 online · Alt+P");
      PartyMessage msg2 = msg;
      msg2.id = "m2";
      closed_active.push_message(msg2);
      const std::string unread_pill = terminal_party_status_pill(closed_active, false);
      check(unread_pill == "● PARTY ops/alpha · 2 online (1 unread) · Alt+P");

      PartyChatPane empty_pane;
      check(!terminal_party_is_active(empty_pane.snapshot()));
      check(terminal_party_status_pill(empty_pane, false).empty());
      check(terminal_party_status_pill(empty_pane, true) == "Alt+P party");

      PartySnapshot solo_snap;
      solo_snap.room_scope = "solo";
      solo_snap.party_config_present = true;
      solo_snap.participants = {op};
      PartyChatPane solo_pane{solo_snap};
      check(!terminal_party_is_active(solo_snap));
      check(terminal_party_status_pill(solo_pane, false).empty());

      // Wave 9B-2: Alt+F Hero v24 Flight Deck toggle decoding, /cwd & /resume
      // palette registration, and configured-leader ambient status pill.
      {
        Composer fd_keys;
        fd_keys.draft("cockpit draft");
        feed(fd_keys, "\x1b[D\x1b[D");
        const auto saved_fd_cursor = fd_keys.cursor();
        check(feed(fd_keys, "\x1b"
                            "f")
                  .action == InputAction::flightdeck_toggle);
        check(fd_keys.text() == "cockpit draft" && fd_keys.cursor() == saved_fd_cursor);
        check(feed(fd_keys, "\x1b[102;3u").action == InputAction::flightdeck_toggle);
        check(fd_keys.text() == "cockpit draft" && fd_keys.cursor() == saved_fd_cursor);

        // /cwd and /resume are registered in builtin_commands for help, hints,
        // Tab-completion, and searchable palette.
        check(terminal_help().find("/cwd") != std::string::npos);
        check(terminal_help().find("/resume") != std::string::npos);
        check(terminal_help().find("Alt+F cockpit") != std::string::npos);
        check(terminal_key_help().find("Alt+F") != std::string::npos);
        check(terminal_command_hint("/cwd").starts_with("/cwd"));
        check(terminal_command_hint("/resume").starts_with("/resume"));

        Composer cwd_palette;
        for (const char ch : std::string_view{"\0cwd", 4})
          (void)cwd_palette.feed(ch);
        const auto cwd_lines = cwd_palette.palette_lines(6);
        check(cwd_lines.size() >= 2 && cwd_lines[1].find("/cwd") != std::string::npos);

        Composer resume_palette;
        for (const char ch : std::string_view{"\0resume", 7})
          (void)resume_palette.feed(ch);
        const auto resume_lines = resume_palette.palette_lines(6);
        check(resume_lines.size() >= 2 &&
              resume_lines[1].find("/resume") != std::string::npos);

        Composer cwd_tab;
        feed(cwd_tab, "/cw\t");
        check(cwd_tab.text() == "/cwd ");

        // Ambient status pill counts configured leaders clearly before first
        // presence heartbeat (never misleading "0 online").
        PartySnapshot offline_leaders;
        offline_leaders.room_scope = "ops/alpha";
        offline_leaders.party_config_present = true;
        PartyParticipant l1;
        l1.id = "wintermute";
        l1.role = PartyMemberRole::platoon_leader;
        l1.state = PartyParticipantState::offline;
        PartyParticipant l2;
        l2.id = "neuromancer";
        l2.role = PartyMemberRole::platoon_leader;
        l2.state = PartyParticipantState::offline;
        offline_leaders.participants = {l1, l2};
        PartyChatPane offline_pane{offline_leaders};
        check(terminal_party_status_pill(offline_pane, false) ==
              "● PARTY ops/alpha · 2 leaders · Alt+P");

        // Even when local_self is online while configured leaders haven't
        // heartbeated yet, show configured leaders clearly.
        offline_leaders.participants.insert(offline_leaders.participants.begin(), op);
        PartyChatPane self_plus_offline_pane{offline_leaders};
        check(terminal_party_status_pill(self_plus_offline_pane, false) ==
              "● PARTY ops/alpha · 2 leaders · Alt+P");
      }

      // TerminalUI::party_chat queues snapshot cleanly.
      task_ui.party_chat(snap);

      // !cmd interactive shell escape helpers & POSIX fork/exec exit codes.
      check(terminal_is_bang_shell_command("!blackbird auth key jev"));
      check(terminal_bang_shell_body("!blackbird auth key jev") ==
            "blackbird auth key jev");
      check(terminal_is_bang_shell_command("!  ls -la "));
      check(terminal_bang_shell_body("!  ls -la ") == "ls -la");
      check(terminal_is_bang_shell_command("!"));
      check(terminal_bang_shell_body("!").empty());
      check(terminal_bang_shell_body("!   ").empty());
      check(!terminal_is_bang_shell_command("hello!"));
      check(!terminal_is_bang_shell_command(""));
      check(terminal_bang_shell_body("hello").empty());

      check(run_interactive_bang_shell("exit 0") == 0);
      check(run_interactive_bang_shell("exit 7") == 7);
      check(run_interactive_bang_shell("") == 2);
      check(run_interactive_bang_shell(std::string_view{"exit 0\0; exit 9", 15}) == 2);
    }

    // Neon TUI polish: sacred native text selection, compact 1-line Party Strip,
    // and OSC 9/777/99 desktop notifications.
    {
      // 1. Default mouse reporting is OFF unless BLACKBIRD_MOUSE=1; alt-scroll
      //    constants are exact DECSET/DECRST 1007 sequences.
      require(!terminal_default_mouse_wanted(nullptr),
              "mouse reporting must default OFF when BLACKBIRD_MOUSE is unset");
      require(!terminal_default_mouse_wanted(""),
              "mouse reporting must default OFF when BLACKBIRD_MOUSE is empty");
      require(!terminal_default_mouse_wanted("0"),
              "mouse reporting must be OFF when BLACKBIRD_MOUSE=0");
      require(!terminal_default_mouse_wanted("true"),
              "mouse reporting must stay OFF unless BLACKBIRD_MOUSE is literally 1");
      require(terminal_default_mouse_wanted("1"),
              "mouse reporting opts ON when BLACKBIRD_MOUSE=1");
      require(kTerminalAltScrollOn == "\x1b[?1007h",
              "alternate-scroll enter sequence must be DECSET 1007");
      require(kTerminalAltScrollOff == "\x1b[?1007l",
              "alternate-scroll exit sequence must be DECRST 1007");
      require(terminal_key_help().find("Native terminal drag-select") !=
                  std::string::npos,
              "key help must document native drag-select default");
      require(terminal_key_help().find("alternate scroll") != std::string::npos,
              "key help must document alternate-scroll wheel support");

      // 2. Always-visible compact 1-line Party Strip at any width + strict
      // sanitization.
      auto assert_no_control_or_bidi = [](std::string_view text, const char *label) {
        for (std::size_t i = 0; i < text.size(); ++i) {
          const auto b = static_cast<unsigned char>(text[i]);
          require(b >= 0x20U && b != 0x7FU,
                  std::string{label} + ": contains C0 or DEL byte");
          if (b == 0xC2U && i + 1U < text.size()) {
            const auto b1 = static_cast<unsigned char>(text[i + 1U]);
            require(b1 < 0x80U || b1 > 0x9FU,
                    std::string{label} + ": contains UTF-8 C1 control");
          }
          if (b == 0xE2U && i + 2U < text.size()) {
            const auto b1 = static_cast<unsigned char>(text[i + 1U]);
            const auto b2 = static_cast<unsigned char>(text[i + 2U]);
            const bool is_bidi_202x = (b1 == 0x80U && b2 >= 0xAAU && b2 <= 0xAEU);
            const bool is_bidi_206x = (b1 == 0x81U && b2 >= 0xA6U && b2 <= 0xA9U);
            const bool is_lrm_rlm = (b1 == 0x80U && (b2 == 0x8EU || b2 == 0x8FU));
            require(!is_bidi_202x && !is_bidi_206x && !is_lrm_rlm,
                    std::string{label} + ": contains BiDi control");
          }
        }
        require(text.find('\x1b') == std::string_view::npos,
                std::string{label} + ": contains ESC");
        require(text.find('\x07') == std::string_view::npos,
                std::string{label} + ": contains BEL");
      };

      PartyChatPane inactive_pane;
      require(terminal_party_strip(inactive_pane, 80U).empty(),
              "inactive party must render no party strip");

      PartySnapshot live_snap;
      live_snap.room_scope = "ops/neon";
      live_snap.party_config_present = true;
      PartyParticipant self_p;
      self_p.id = "antimeme";
      self_p.display_name = "antimeme";
      self_p.role = PartyMemberRole::operator_human;
      self_p.provider = "Blackbird";
      self_p.state = PartyParticipantState::online;
      self_p.local_self = true;

      PartyParticipant phall_p;
      phall_p.id = "phall";
      phall_p.display_name = "@phall";
      phall_p.role = PartyMemberRole::operator_human;
      phall_p.provider = "Outpost";
      phall_p.state = PartyParticipantState::online;
      phall_p.local_self = false;
      live_snap.participants = {self_p, phall_p};

      PartyChatPane live_pane{live_snap};
      const ChatRow strip_80 = terminal_party_strip(live_pane, 80U);
      const std::string plain_80 = chat_plain(strip_80);
      require(
          plain_80 ==
              "● Party: you (Blackbird) · ● @phall (Outpost) · 2 live  [Alt+P chat]",
          "80-col party strip must match expected crisp format, got: " + plain_80);
      require(display_cells(plain_80).value <= 80U,
              "80-col party strip must fit within 80 cells");
      assert_no_control_or_bidi(plain_80, "live 80-col strip");

      for (const std::size_t narrow_w : {60U, 44U, 30U, 18U}) {
        const ChatRow narrow_strip = terminal_party_strip(live_pane, narrow_w);
        const std::string narrow_plain = chat_plain(narrow_strip);
        require(!narrow_plain.empty(), "narrow party strip must remain visible");
        require(display_cells(narrow_plain).value <= narrow_w,
                "narrow party strip must never overflow width " +
                    std::to_string(narrow_w));
        require(narrow_plain.find("●") != std::string::npos,
                "narrow party strip must retain shape glyph");
        assert_no_control_or_bidi(narrow_plain, "narrow strip");
      }

      // Unread messages appear in the strip hint.
      PartyMessage incoming;
      incoming.id = "party-msg-1";
      incoming.sender_id = "phall";
      incoming.body = "ready to pair";
      live_pane.push_message(incoming);
      const std::string unread_strip =
          chat_plain(terminal_party_strip(live_pane, 100U));
      require(unread_strip.find("1 unread") != std::string::npos,
              "party strip must surface unread count");

      // Reconnecting (◐) and away (○) states always carry shape + word.
      PartySnapshot reconn_snap = live_snap;
      reconn_snap.participants[0].state = PartyParticipantState::idle;
      reconn_snap.participants[1].state = PartyParticipantState::idle;
      const std::string reconn_plain =
          chat_plain(terminal_party_strip(PartyChatPane{reconn_snap}, 90U));
      require(reconn_plain.find("◐") != std::string::npos &&
                  reconn_plain.find("reconnecting") != std::string::npos,
              "reconnecting strip must show shape ◐ and word reconnecting");

      PartySnapshot away_snap = live_snap;
      away_snap.participants[0].state = PartyParticipantState::offline;
      away_snap.participants[1].state = PartyParticipantState::offline;
      const std::string away_plain =
          chat_plain(terminal_party_strip(PartyChatPane{away_snap}, 90U));
      require(away_plain.find("○") != std::string::npos &&
                  away_plain.find("away") != std::string::npos,
              "away strip must show shape ○ and word away");

      PartySnapshot mixed_snap = live_snap;
      mixed_snap.participants[1].state = PartyParticipantState::idle;
      const std::string mixed_plain =
          chat_plain(terminal_party_strip(PartyChatPane{mixed_snap}, 110U));
      require(mixed_plain.find("●") != std::string::npos &&
                  mixed_plain.find("live") != std::string::npos &&
                  mixed_plain.find("◐") != std::string::npos &&
                  mixed_plain.find("reconnecting") != std::string::npos,
              "mixed strip must show both live and reconnecting shapes+words");

      // Hostile remote handle and client injection must be completely stripped.
      PartySnapshot hostile_snap = live_snap;
      hostile_snap.participants[1].display_name =
          std::string{"\x1b[31m\x1b]0;pwn\x07\xC2\x9B"
                      "2J\xE2\x80\xAE@evil\x00\x07\x7F\n\r",
                      34U};
      hostile_snap.participants[1].provider =
          std::string{"\x1b]52;c;AAAA\x1b\\Out\xE2\x81\xA6post\x1b[0m", 32U};
      const std::string hostile_plain =
          chat_plain(terminal_party_strip(PartyChatPane{hostile_snap}, 120U));
      assert_no_control_or_bidi(hostile_plain, "hostile party strip");
      require(hostile_plain.find("@evil") != std::string::npos &&
                  hostile_plain.find("Outpost") != std::string::npos,
              "hostile sanitizer must preserve safe handle/client text: " +
                  hostile_plain);
      require(hostile_plain.find("pwn") == std::string::npos &&
                  hostile_plain.find("AAAA") == std::string::npos,
              "hostile OSC payloads must be stripped, not leaked: " + hostile_plain);

      // 3. TerminalNotifyLimiter: sanitization, bounding, OSC framing, rate limit.
      TerminalNotifyLimiter limiter{std::chrono::milliseconds{1000}};
      const auto t0 = std::chrono::steady_clock::now();
      const TerminalNotifyTarget ghostty_target{TerminalNotifyProtocol::osc777, false};
      const TerminalNotifyTarget iterm_target{TerminalNotifyProtocol::osc9, false};
      const TerminalNotifyTarget none_target{TerminalNotifyProtocol::none, false};

      // Unsupported target and empty/control-only inputs never consume rate budget.
      require(limiter.format_if_allowed(none_target, {"Title", "Body", 0U}, t0).empty(),
              "none protocol must emit nothing");
      require(limiter
                  .format_if_allowed(
                      ghostty_target,
                      {"\x1b[31m\x07\x00", "\x1b]0;x\x07\xE2\x80\xAE", 0U}, t0)
                  .empty(),
              "control-only notification must emit nothing");

      const std::string osc777 = limiter.format_if_allowed(
          ghostty_target,
          {"\x1b[31mParty;Invite\x07",
           "\x1b]9;spoof\x1b\\\xE2\x80\xAE@phall joined\nnow\x07", 0U},
          t0);
      require(osc777 == "\x1b]777;notify;Party:Invite;@phall joined now\x1b\\",
              "OSC 777 notification must sanitize and frame safely, got: " + osc777);
      require(osc777.find('\x07') == std::string::npos,
              "OSC 777 packet must contain no BEL");

      // Immediate second notification is rate-limited.
      require(limiter
                  .format_if_allowed(ghostty_target, {"Second", "Spam", 0U},
                                     t0 + std::chrono::milliseconds{500})
                  .empty(),
              "notification inside min_interval must be rate-limited");

      // After min_interval elapses, oversized body is bounded and emitted cleanly.
      const std::string long_body(1024U, 'A');
      const std::string osc9 = limiter.format_if_allowed(
          iterm_target, {"Alert", long_body, 0U}, t0 + std::chrono::milliseconds{1000});
      require(osc9.starts_with("\x1b]9;Alert: ") && osc9.ends_with("\x1b\\"),
              "OSC 9 notification must emit after rate limit window");
      require(osc9.size() <= 16U + kTerminalDesktopNotifyMaxBytes,
              "notification body must be strictly bounded");

      // TerminalUI::desktop_notify safely queues without throwing (accepts
      // string literals, std::string_view, and std::string cleanly).
      task_ui.desktop_notify("Party", "@phall joined");
      task_ui.desktop_notify(std::string_view{"Party"}, std::string_view{"sv body"});
      task_ui.desktop_notify("\x1b[31m\x07", "");

      // 4. End-to-end 80x24 PTY check: default mouse OFF, alt-scroll ON/OFF,
      //    80-col Party Strip visible, /mouse on/off toggle, OSC 777 delivery.
      int master = ::posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
      require(master >= 0 && ::grantpt(master) == 0 && ::unlockpt(master) == 0,
              "PTY master setup");
      const char *slave_name = ::ptsname(master);
      require(slave_name != nullptr, "PTY slave name");
      const int slave = ::open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
      require(slave >= 0, "PTY slave open");
      winsize ws{};
      ws.ws_row = 24;
      ws.ws_col = 80;
      require(::ioctl(slave, TIOCSWINSZ, &ws) == 0, "PTY 80x24 winsize");
      const pid_t child = ::fork();
      require(child >= 0, "PTY fork");
      if (child == 0) {
        ::close(master);
        if (::dup2(slave, STDIN_FILENO) < 0 || ::dup2(slave, STDOUT_FILENO) < 0)
          ::_exit(90);
        ::close(slave);
        ::unsetenv("BLACKBIRD_MOUSE");
        ::setenv("BLACKBIRD_MASCOT", "0", 1);
        ::setenv("TERM_PROGRAM", "ghostty", 1);
        ::setenv("TERM", "xterm-ghostty", 1);
        try {
          TerminalUI pty_ui{"neon-pty"};
          pty_ui.party_chat(live_snap);
          pty_ui.desktop_notify("Party invite", "@phall invited you");
          pty_ui.desktop_notify("Burst", "should be rate-limited");
          std::atomic_bool cancelled{false};
          pty_ui.run([](std::string_view) {}, cancelled);
          ::_exit(0);
        } catch (...) {
          ::_exit(91);
        }
      }
      ::close(slave);
      auto drain_pty = [&](std::string &buf, std::string_view needle, int timeout_ms) {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
        char chunk[4096];
        while (std::chrono::steady_clock::now() < deadline) {
          if (!needle.empty() && buf.find(needle) != std::string::npos)
            return true;
          pollfd pfd{master, POLLIN, 0};
          const int rc = ::poll(&pfd, 1, 25);
          if (rc > 0 && (pfd.revents & POLLIN)) {
            const ssize_t n = ::read(master, chunk, sizeof(chunk));
            if (n > 0)
              buf.append(chunk, static_cast<std::size_t>(n));
            else if (n == 0)
              break;
          } else if (rc > 0 && (pfd.revents & POLLHUP)) {
            break;
          }
        }
        return !needle.empty() && buf.find(needle) != std::string::npos;
      };
      auto send_pty = [&](std::string_view bytes) {
        require(::write(master, bytes.data(), bytes.size()) ==
                    static_cast<ssize_t>(bytes.size()),
                "write to PTY master");
      };

      std::string initial_out;
      require(drain_pty(initial_out,
                        "\x1b]777;notify;Party invite;@phall invited you\x1b\\", 3000),
              "PTY initial frame must emit OSC 777 notification");
      require(initial_out.find("\x1b[?1007h") != std::string::npos,
              "PTY enter must enable alternate-scroll (?1007h)");
      require(initial_out.find("\x1b[?1000h") == std::string::npos,
              "PTY default must NOT enable SGR mouse reporting (?1000h)");
      require(initial_out.find("Party: ") != std::string::npos &&
                  initial_out.find("@phall") != std::string::npos &&
                  initial_out.find("2 live") != std::string::npos &&
                  initial_out.find("[Alt+P chat]") != std::string::npos,
              "80-col PTY must render always-visible 1-line Party Strip");
      require(initial_out.find("should be rate-limited") == std::string::npos,
              "immediate duplicate desktop_notify must be coalesced/rate-limited");

      // Toggle /mouse on -> enables SGR reporting + prints hint.
      std::string mouse_on_out;
      send_pty("/mouse on\r");
      require(drain_pty(mouse_on_out, "\x1b[?1000h\x1b[?1002h\x1b[?1006h", 3000),
              "/mouse on must enable SGR mouse reporting");
      require(mouse_on_out.find("hold Shift/Option to drag-select") !=
                  std::string::npos,
              "/mouse on must display Shift/Option drag-select hint");

      // Toggle /mouse off -> disables SGR reporting.
      std::string mouse_off_out;
      send_pty("/mouse off\r");
      require(drain_pty(mouse_off_out, "\x1b[?1006l\x1b[?1002l\x1b[?1000l", 3000),
              "/mouse off must disable SGR mouse reporting");

      // Exit via /quit -> disables alternate-scroll (?1007l).
      std::string exit_out;
      send_pty("/quit\r");
      (void)drain_pty(exit_out, "\x1b[?1007l", 3000);
      require(exit_out.find("\x1b[?1007l") != std::string::npos,
              "PTY exit must disable alternate-scroll (?1007l)");
      int wstatus = 0;
      require(::waitpid(child, &wstatus, 0) == child && WIFEXITED(wstatus) &&
                  WEXITSTATUS(wstatus) == 0,
              "PTY child must exit cleanly with code 0");
      ::close(master);
    }

    std::filesystem::remove_all(dir);

  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
