#include "blackbird/chat_view.hpp"
#include "blackbird/display_text.hpp"
#include "blackbird/sprite.hpp"
#include "blackbird/terminal.hpp"
#include <cerrno>
#include <chrono>
#include <clocale>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <type_traits>
#include <unistd.h>
using namespace blackbird;
void require(bool yes, const char *why) {
  if (!yes)
    throw std::runtime_error(why);
}
std::string plain(const std::vector<ChatRow> &rows) {
  std::string s;
  for (const auto &r : rows)
    s += chat_plain(r) + "\n";
  return s;
}
std::string hex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  for (const char byte : bytes) {
    const auto c = static_cast<unsigned char>(byte);
    result += digits[c >> 4];
    result += digits[c & 15];
  }
  return result;
}
void presenter_pipe() {
  static_assert(!std::is_move_constructible_v<ChatPresenter>);
  int descriptors[2];
  require(::pipe(descriptors) == 0, "presenter pipe setup");
  (void)::fcntl(descriptors[0], F_SETFL, O_NONBLOCK);
  {
    ChatPresenter presenter;
    presenter.attach(descriptors[1]);
    auto &grid = presenter.grid();
    grid.reset(20, 4);
    grid.line(0, {{"A", Ink::normal}});
    const auto initial = presenter.prepare(2, 3);
    presenter.start();
    require(presenter.flush() && !presenter.flush(), "completion consumed once");
    require(presenter.geometry().rows == 4 && presenter.geometry().cursor_column == 3,
            "completed normal geometry");
    std::string received;
    char data[16384];
    auto count = ::read(descriptors[0], data, sizeof(data));
    require(count > 0, "initial presenter bytes");
    received.append(data, static_cast<std::size_t>(count));
    require(received == initial, "initial exact packet");
    presenter.grid().reset(20, 4);
    presenter.grid().line(0, {{"B", Ink::normal}});
    auto &packet = presenter.prepare(1, 8);
    packet.append(256 * 1024, 'q'); // Final graphics-like augmentation is owned.
    const auto expected = packet;
    presenter.start();
    require(!presenter.flush() && presenter.pending(), "owned backpressure");
    require(presenter.geometry().cursor_column == 3,
            "partial output does not publish cursor");
    bool refused = false;
    try {
      (void)presenter.prepare_tiny(2, 8, 0, 1);
    } catch (const std::logic_error &) {
      refused = true;
    }
    require(refused, "inflight frame cannot be replaced");
    received.clear();
    unsigned completions = 0;
    for (unsigned round = 0;
         round < 1000 && (presenter.pending() || received.size() < expected.size());
         ++round) {
      count = ::read(descriptors[0], data, sizeof(data));
      if (count > 0)
        received.append(data, static_cast<std::size_t>(count));
      completions += presenter.flush() ? 1U : 0U;
    }
    require(received == expected && completions == 1 &&
                presenter.geometry().cursor_column == 8,
            "owned exact suffix and matching completion");
    auto &tiny = presenter.prepare_tiny(2, 8, 0, 1);
    tiny = "x"; // Short string storage must remain inside the immovable owner.
    presenter.start();
    require(presenter.flush() && presenter.geometry().tiny,
            "tiny completion is explicit");
    require(::read(descriptors[0], data, sizeof(data)) == 1 && data[0] == 'x',
            "short owned packet");
    presenter.grid().reset(20, 4);
    require(!presenter.prepare(1, 8).empty(), "tiny invalidates normal baseline");
    presenter.abandon();
  }
  require((::fcntl(descriptors[1], F_GETFL) & O_NONBLOCK) == 0,
          "presenter restores descriptor flags");
  ::close(descriptors[0]);
  ::close(descriptors[1]);
}
void test_rich_markdown_and_compact_tools() {
  // 1. Headings hierarchy (H1 underline, H2 clean heading, H3 accent) + inline code.
  {
    ChatView view;
    view.append(ChatKind::assistant, "# Main `API`\n## Overview\n### Details\n");
    const auto &rows = view.rows(60);
    const auto text = plain(rows);
    require(text.find("# ") == std::string::npos &&
                text.find("## ") == std::string::npos &&
                text.find("### ") == std::string::npos,
            "raw heading hashes must be stripped");
    require(text.find("  │ Main API\n  │ ────────\n") != std::string::npos,
            "H1 must render title followed by width-matched underline");
    require(text.find("  │ Overview\n") != std::string::npos,
            "H2 must render clean heading");
    require(text.find("  │ › Details\n") != std::string::npos,
            "H3 must render subtle accent heading");
    bool h1_code_ink = false, h2_heading_ink = false, h3_heading_ink = false;
    for (const auto &row : rows) {
      for (const auto &span : row) {
        if (span.text == "API" && span.ink == Ink::code)
          h1_code_ink = true;
        if (span.text == "Overview" && span.ink == Ink::heading)
          h2_heading_ink = true;
        if (span.text == "Details" && span.ink == Ink::heading)
          h3_heading_ink = true;
      }
    }
    require(h1_code_ink && h2_heading_ink && h3_heading_ink,
            "headings preserve Ink::heading and inline Ink::code");
  }

  // 2. Hanging-indent bullet (-, *, +) and numbered lists (1., 12.) at narrow width=24.
  {
    ChatView view;
    view.append(ChatKind::assistant, "- Alpha **bold** item wraps cleanly here\n"
                                     "* Second bullet with `code`\n"
                                     "+ Third bullet\n"
                                     "1. Numbered item wraps nicely on narrow width\n"
                                     "12. Double digit item also indents properly\n");
    const auto &rows = view.rows(24);
    for (const auto &row : rows)
      require(display_cells(chat_plain(row)).value <= 24,
              "list row exceeded narrow viewport width 24");
    const auto text = plain(rows);
    require(text.find("  │   • Alpha bold item ") != std::string::npos &&
                text.find("  │     wraps cleanly he") != std::string::npos,
            "bullet list must use hanging indent (4 spaces under text)");
    require(text.find("  │   • Second bullet wi") != std::string::npos &&
                text.find("  │   • Third bullet\n") != std::string::npos,
            "* and + bullets must normalize to •");
    require(text.find("  │   1. Numbered item w") != std::string::npos &&
                text.find("  │      raps nicely on ") != std::string::npos,
            "single-digit numbered list must align continuation under text");
    require(text.find("  │   12. Double digit i") != std::string::npos &&
                text.find("  │       tem also inden") != std::string::npos,
            "two-digit numbered list must align continuation under text");
  }

  // 3. Bordered fenced code blocks with language pill + narrow clamping.
  {
    ChatView view;
    view.append(ChatKind::assistant, "```cpp\nauto answer = \"café\";\n```\n"
                                     "```\nplain line\n```\n");
    const auto &wide = view.rows(52);
    const auto wtext = plain(wide);
    require(wtext.find("```") == std::string::npos,
            "raw backtick fences must not clutter rendered output");
    require(
        wtext.find("  │ ╭─ cpp ─") != std::string::npos &&
            wtext.find("  │ │ auto answer = \"café\";\n") != std::string::npos &&
            wtext.find("  │ ╰───") != std::string::npos,
        "fenced code block renders top border + language pill, │ bar, bottom border");
    require(wtext.find("  │ ╭───") != std::string::npos &&
                wtext.find("  │ │ plain line\n") != std::string::npos,
            "unlabelled code fence renders clean border without language pill");
    bool pill_code_ink = false, bar_code_ink = false, kw_ink = false;
    for (const auto &row : wide) {
      for (const auto &span : row) {
        if (span.text == "cpp" && span.ink == Ink::code)
          pill_code_ink = true;
        if (span.text == "│ " && span.ink == Ink::code)
          bar_code_ink = true;
        if (span.text == "auto" && span.ink == Ink::keyword)
          kw_ink = true;
      }
    }
    require(pill_code_ink && bar_code_ink && kw_ink,
            "fenced code block uses Ink::code pill/bar and syntax highlighting");
    const auto &narrow = view.rows(24);
    for (const auto &row : narrow)
      require(display_cells(chat_plain(row)).value <= 24,
              "fenced code row exceeded narrow width 24");
  }

  // 4. Aligned box-drawn Markdown tables (UTF-8, inline formatting, alignment, narrow).
  {
    ChatView view;
    view.append(ChatKind::assistant, "| Name | `Code` | Count |\n"
                                     "|:-----|:------:|------:|\n"
                                     "| **界** | `a|b` | 7 |\n"
                                     "| café \\| tea | ok | 1234 |\n");
    const auto &wide = view.rows(60);
    const auto wtext = plain(wide);
    require(wtext.find("╭") != std::string::npos &&
                wtext.find("├") != std::string::npos &&
                wtext.find("┼") != std::string::npos &&
                wtext.find("╰") != std::string::npos,
            "table must render aligned box-drawing borders");
    require(wtext.find("a|b") != std::string::npos &&
                wtext.find("café | tea") != std::string::npos,
            "pipes inside inline code and escaped pipes must not split columns");
    std::size_t table_width = 0;
    for (const auto &row : wide) {
      const auto line = chat_plain(row);
      const auto cells = display_cells(line).value;
      require(cells <= 60, "table row exceeded width 60");
      if (line.find("╭") != std::string::npos || line.find("├") != std::string::npos ||
          line.find("╰") != std::string::npos ||
          (line.starts_with("  │ │") && line.ends_with("│"))) {
        if (table_width == 0)
          table_width = cells;
        require(cells == table_width,
                "every box-drawn table row must align identically");
      }
    }
    require(table_width > 0, "expected box-drawn table rows");
    // Narrow width=24 must clamp & wrap cleanly with every row <= 24 cells.
    const auto &narrow = view.rows(24);
    std::size_t narrow_table_width = 0;
    for (const auto &row : narrow) {
      const auto line = chat_plain(row);
      const auto cells = display_cells(line).value;
      require(cells <= 24, "narrow table row exceeded width 24");
      if (line.find("╭") != std::string::npos || line.find("├") != std::string::npos ||
          line.find("╰") != std::string::npos ||
          (line.starts_with("  │ │") && line.ends_with("│"))) {
        if (narrow_table_width == 0)
          narrow_table_width = cells;
        require(cells == narrow_table_width,
                "narrow wrapped table rows must stay column-aligned");
      }
    }
    require(narrow_table_width > 0 && narrow_table_width <= 24,
            "narrow table must fit within 24 columns");
    // Extreme width=8 with 3 columns falls back without crash or overflow.
    const auto &tiny = view.rows(8);
    for (std::size_t idx = 1; idx < tiny.size(); ++idx)
      require(display_cells(chat_plain(tiny[idx])).value <= 8,
              "tiny table fallback exceeded width 8");
  }

  // 5. Blockquotes and horizontal rules (---, ***, ___).
  {
    ChatView view;
    view.append(ChatKind::assistant,
                "> Quoted **bold** and `code` wrapping nicely here\n"
                "---\n"
                "***\n"
                "___\n"
                "- - -\n");
    const auto &rows = view.rows(24);
    const auto text = plain(rows);
    for (const auto &row : rows)
      require(display_cells(chat_plain(row)).value <= 24,
              "blockquote/hr row exceeded narrow width 24");
    require(text.find("  │ ▎ Quoted bold and co") != std::string::npos &&
                text.find("  │ ▎ de wrapping nicely") != std::string::npos,
            "blockquote must render continuous ▎ left accent bar on wrapped lines");
    std::size_t hr_count = 0;
    const std::string expected_hr = "  │ ────────────────────";
    for (const auto &row : rows)
      if (chat_plain(row) == expected_hr)
        ++hr_count;
    require(hr_count == 4,
            "all four horizontal rule forms must render bounded divider");
  }

  // 6. Full rich Markdown 1-byte stream vs cold parity (including tables & lists).
  {
    const std::string doc = "# Title\n## Sub\n### Leaf\n"
                            "> Quote with `x`\n"
                            "---\n"
                            "- first **item**\n"
                            "1. step one\n"
                            "| A | B |\n"
                            "|---|---:|\n"
                            "foo | 42\n"
                            "| bar | 99 |\n"
                            "```lua\nlocal x = \"ok\"\n```\n"
                            "End.\n";
    ChatView stream, cold;
    stream.begin(ChatKind::assistant);
    for (const char ch : doc) {
      stream.stream(std::string_view{&ch, 1});
      cold.clear();
      cold.append(ChatKind::assistant, doc.substr(0, stream.size()));
      const auto &a = stream.rows(36);
      const auto &b = cold.rows(36);
      require(a.size() == b.size(), "rich stream/cold row count diverged");
      for (std::size_t r = 0; r < a.size(); ++r) {
        require(a[r].size() == b[r].size(), "rich stream/cold span count diverged");
        for (std::size_t s = 0; s < a[r].size(); ++s)
          require(a[r][s].text == b[r][s].text && a[r][s].ink == b[r][s].ink,
                  "rich stream/cold span diverged");
      }
    }
  }

  // 7. Selection extraction compatibility & hostile ESC / control-char neutralization.
  {
    ChatView hostile;
    static constexpr char raw_payload[] =
        "# \x1b[2JEvil\n- item \x1b]52;c;YQ==\x07ok\n"
        "> \xc2\x9b"
        "31mquoted\n"
        "| col\x1b[31m | val |\n|---|---|\n| a\0b | café |\n"
        "```cpp\nauto x = \"\x1b[2J\";\n```\n";
    hostile.append(ChatKind::assistant,
                   std::string_view{raw_payload, sizeof(raw_payload) - 1});
    const auto &rows = hostile.rows(48);
    const auto rendered = plain(rows);
    require(rendered.find('\x1b') == std::string::npos &&
                rendered.find('\0') == std::string::npos,
            "hostile ESC or NUL escaped rich Markdown renderer");
    const auto selected =
        terminal_extract_chat_selection(rows, {1, 0, rows.size() - 1, 40});
    require(selected.find("Evil") != std::string::npos &&
                selected.find("café") != std::string::npos,
            "selection extraction works cleanly across rich Markdown rows");
  }

  // 8. Compact semantic tool headers + single card folding & JSON ESC defense.
  {
    require(format_compact_tool_header("▸ read_file · sample.txt") ==
                "▸ read_file · sample.txt",
            "plain tool header must stay unchanged");
    require(format_compact_tool_header("▸ exec seq") == "▸ exec seq",
            "simple exec header without separator must stay unchanged");
    require(format_compact_tool_header("▸ read_file · \"src/chat_view.cpp\"") ==
                "▸ read_file · src/chat_view.cpp",
            "JSON-quoted path must unwrap cleanly");
    require(format_compact_tool_header(
                "▸ exec · [\"/bin/sh\",\"-c\",\"cmake --build build/debug\"]") ==
                "▸ exec · cmake --build build/debug",
            "shell argv array must extract inner command");
    require(format_compact_tool_header(
                "▸ exec · [\"/usr/bin/env\",\"bash\",\"-lc\",\"git status -s\"]") ==
                "▸ exec · git status -s",
            "env shell argv array must extract inner command");
    require(format_compact_tool_header("▸ exec · [\"git\",\"diff\",\"--stat\"]") ==
                "▸ exec · git diff --stat",
            "plain argv array must join with spaces");
    require(format_compact_tool_header(
                "▸ edit_file · "
                "{\"path\":\"src/chat_view.cpp\",\"old\":\"a\",\"new\":\"b\"}") ==
                "▸ edit_file · src/chat_view.cpp",
            "JSON object header must extract primary semantic key");
    const auto safe_hdr = format_compact_tool_header(
        "▸ exec · \"echo "
        "\\u001b[2Jhi\\nnext\\u009b31m\\ud800\\u001b]52;c;YQ==\\u0007café\"");
    require(safe_hdr.find('\x1b') == std::string::npos &&
                safe_hdr.find('\n') == std::string::npos &&
                safe_hdr.find("\xc2\x9b") == std::string::npos &&
                safe_hdr.find("[2J") == std::string::npos &&
                safe_hdr.find("31m") == std::string::npos &&
                safe_hdr.find("52;c;") == std::string::npos &&
                safe_hdr.find("echo") != std::string::npos &&
                safe_hdr.find("hi") != std::string::npos &&
                safe_hdr.find("café") != std::string::npos,
            "compact tool header strips JSON-encoded ESC/OSC/C1 payloads while "
            "preserving UTF-8");
    const auto raw_c1_hdr = format_compact_tool_header("▸ exec · \"foo\x9b"
                                                       "31mbar\xc2\x9d"
                                                       "52;c;YQ==\xc2\x9c"
                                                       "baz\x1b^pm\x1b\\\\qux\x1b"
                                                       "cend界\"");
    require(raw_c1_hdr.find('\x9b') == std::string::npos &&
                raw_c1_hdr.find("31m") == std::string::npos &&
                raw_c1_hdr.find("52;c;") == std::string::npos &&
                raw_c1_hdr.find("pm") == std::string::npos &&
                raw_c1_hdr == "▸ exec · foobarbazquxend界",
            "compact tool header strips raw 8-bit C1, UTF-8 C1 OSC, ESC^, and 2-byte "
            "ESC while preserving CJK");
    const std::string trailing_junk = "▸ exec · {\"path\":\"a.cpp\"} junk {}";
    require(format_compact_tool_header(trailing_junk) == trailing_junk,
            "malformed JSON object with trailing junk must not be silently truncated");
    const std::string trailing_empty = "▸ exec · {} junk {}";
    require(format_compact_tool_header(trailing_empty) == trailing_empty,
            "empty JSON object with trailing junk must be rejected");
    const auto long_hdr =
        format_compact_tool_header("▸ exec · \"" + std::string(300, 'z') + "\"");
    require(display_cells(long_hdr).value <= 140 && long_hdr.ends_with("…"),
            "verbose JSON tool header is bounded with ellipsis");

    ChatView card;
    card.tool_start("▸ exec · [\"/bin/sh\",\"-c\",\"seq 1 40\"]");
    for (int i = 1; i <= 40; ++i)
      card.tool_output("L" + std::to_string(i) + "\n");
    card.tool_complete("exec completed · 9ms", Ink::success);
    const auto card_text = plain(card.rows(80));
    require(card_text.find("✓ exec · seq 1 40 · 9ms") != std::string::npos &&
                card_text.find("┆ 34 more lines · Ctrl-O inspects") !=
                    std::string::npos &&
                card_text.find("L38") != std::string::npos &&
                card_text.find("L40") != std::string::npos,
            "compact tool card preserves in-place completion and middle fold");
  }
}
int main(int argc, char **) {
  try {
    (void)std::setlocale(LC_CTYPE, "en_US.UTF-8");
    if (argc > 1) {
      int descriptors[2];
      require(::pipe(descriptors) == 0, "oracle presenter pipe");
      ChatPresenter presenter;
      presenter.attach(descriptors[1]);
      for (int i = 0; i < 9; ++i) {
        if (i == 6) {
          auto &tiny = presenter.prepare_tiny(2, 8, 0, 1);
          tiny = "\x1b[?2026h\x1b[H\x1b[2Jx\x1b[1;2H\x1b[?2026l";
          const auto expected = tiny;
          presenter.start();
          require(presenter.flush(), "tiny oracle completion");
          char data[4096];
          const auto count = ::read(descriptors[0], data, sizeof(data));
          require(count > 0, "tiny oracle bytes");
          std::cout << "8 2\n"
                    << hex(std::string_view{data, static_cast<std::size_t>(count)})
                    << "\n"
                    << hex(expected) << "\n";
          continue;
        }
        auto &frame = presenter.grid();
        frame.reset(i == 4 ? 12 : 20, 4);
        frame.line(0, {{i == 0   ? "hello long"
                        : i == 1 ? "界éx"
                        : i == 2 ? "h"
                        : i == 8 ? "A\u200dB\u200dCx"
                                 : "👩‍💻🇺🇸",
                        Ink::assistant}});
        frame.line(1, {{"keyword", Ink::keyword}, {" string", Ink::string}});
        ChatPainter full;
        (void)presenter.prepare(3, 2);
        const auto cold = full.prepare(frame, 3, 2);
        const auto width = frame.width, height = frame.height;
        presenter.start();
        require(presenter.flush(), "oracle presenter completion");
        char data[4096];
        const auto count = ::read(descriptors[0], data, sizeof(data));
        require(count > 0, "oracle presenter bytes");
        const std::string_view packet{data, static_cast<std::size_t>(count)};
        std::cout << width << " " << height << "\n"
                  << hex(packet) << "\n"
                  << hex(cold) << "\n";
      }
      presenter.detach();
      ::close(descriptors[0]);
      ::close(descriptors[1]);
      return 0;
    }
    presenter_pipe();
    test_rich_markdown_and_compact_tools();
    const auto &idle_sprite = blackbird_sprite(false, 0);
    require(&idle_sprite == &blackbird_sprite(false, 999), "idle mascot animates");
    require(blackbird_sprite(true, 0) != blackbird_sprite(true, 1),
            "busy exhaust static");
    ChatGrid sprite_grid;
    sprite_grid.reset(40, blackbird_sprite_height);
    sprite_grid.line(0, {{"HEADER", Ink::normal}});
    for (std::size_t y = 0; y < idle_sprite.size(); ++y)
      sprite_grid.line(y, {{idle_sprite[y], Ink::assistant}}, 22);
    require(sprite_grid.cells[0].scalar == U'H' && sprite_grid.cells[5].scalar == U'R',
            "sprite blit overwrites header");
    sprite_grid.line(0, {{idle_sprite[0], Ink::assistant}}, 40);
    require(sprite_grid.cells[0].scalar == U'H', "offscreen sprite corrupts cells");
    sprite_grid.reset(40, blackbird_sprite_height);
    sprite_grid.line(0, {{"界x", Ink::normal}});
    sprite_grid.line(0, {{"h", Ink::normal}}, 1);
    require(sprite_grid.cells[0].scalar == U' ' && sprite_grid.cells[0].width == 1 &&
                sprite_grid.cells[1].scalar == U'h' &&
                sprite_grid.cells[2].scalar == U'x',
            "offset blit leaves wide-cell leader");
    sprite_grid.line(0, {{"界", Ink::normal}}, 2);
    sprite_grid.line(0, {{"界", Ink::normal}}, 1);
    require(sprite_grid.cells[1].width == 2 && sprite_grid.cells[2].width == 0 &&
                sprite_grid.cells[3].width == 1,
            "overlapping wide-cell blit leaves stale continuation");
    for (const auto &[width, height] :
         std::array<std::pair<std::size_t, std::size_t>, 4>{
             {{40, 12}, {80, 18}, {80, 30}, {120, 20}}}) {
      const auto startup = blackbird_startup(width, height);
      require(startup.size() <= height, "startup art exceeds viewport height");
      for (const auto &line : startup)
        require(terminal_lines(line, width) == std::vector<std::string>{line},
                "startup art exceeds terminal cell width");
    }
    require(blackbird_startup(80, 30, false).size() == 6,
            "startup wordmark must have six rows");
    ChatView view;
    view.append(ChatKind::user, "hola");
    view.begin(ChatKind::assistant);
    view.stream("¡Hola! ¿En qué te ayudo?");
    auto text = plain(view.rows(80));
    require(text.find("YOU") != std::string::npos &&
                text.find("BLACKBIRD") != std::string::npos,
            "typed roles missing");
    require(text.find("JSON bytes") == std::string::npos, "diagnostics leak");
    const auto count = view.reflows();
    for (int i = 0; i < 100; ++i)
      (void)view.rows(80);
    require(view.reflows() == count, "idle/cache causes reflow");
    ChatView stream, cold;
    std::string markdown =
        "# Heading\n\n**bold** and `code`\n```cpp\nauto value = \"yes\";\n```\nDone.\n";
    stream.begin(ChatKind::assistant);
    for (char c : markdown) {
      stream.stream(std::string_view{&c, 1});
      cold.clear();
      cold.append(ChatKind::assistant, markdown.substr(0, stream.size()));
      const auto &a = stream.rows(40), &b = cold.rows(40);
      require(plain(a) == plain(b), "stream/cold diverge");
      require(a.size() == b.size(), "styled row count differs");
      for (std::size_t row = 0; row < a.size(); ++row) {
        require(a[row].size() == b[row].size(), "styled span count differs");
        for (std::size_t span = 0; span < a[row].size(); ++span)
          require(a[row][span].text == b[row][span].text &&
                      a[row][span].ink == b[row][span].ink,
                  "stream/cold styles diverge");
      }
    }
    ChatGrid grid;
    grid.reset(20, 4);
    grid.line(0, {{"hello", Ink::assistant}});
    ChatPainter painter;
    auto initial = painter.prepare(grid, 3, 2);
    require(!initial.empty(), "first paint missing");
    painter.commit(grid);
    require(painter.prepare(grid, 3, 2).empty(), "unchanged frame emitted");
    grid.line(0, {{"j", Ink::assistant}});
    auto delta = painter.prepare(grid, 3, 2);
    require(delta.find("hello") == std::string::npos && painter.touched() == 1,
            "damage not bounded");
    painter.commit(grid);
    require(painter.prepare(grid, 3, 2).empty(), "committed frame repeats");
    grid.reset(20, 4);
    grid.line(0, {{"界x", Ink::normal}});
    require(grid.cells[0].width == 2 && grid.cells[1].width == 0 &&
                grid.cells[2].scalar == U'x',
            "CJK cells");
    grid.reset(20, 4);
    grid.line(0, {{"éx", Ink::normal}});
    require(grid.cells[0].length == 2 && grid.cells[1].scalar == U'x',
            "combining cluster");
    grid.reset(20, 4);
    grid.line(0, {{"👩‍💻x", Ink::normal}});
    require(grid.cells[0].width == 2 && grid.cells[2].scalar == U'x', "ZWJ cluster");
    grid.reset(20, 4);
    grid.line(0, {{" \u200d \u200d X", Ink::normal}});
    require(grid.cells[0].width == 1 && grid.cells[1].width == 1 &&
                grid.cells[2].width == 1 && grid.cells[3].scalar == U'X',
            "plain-text joiners collapse spacing cells");
    grid.reset(20, 4);
    grid.line(0, {{"A\u200dB\u200dCx", Ink::normal}});
    require(grid.cells[0].width == 1 && grid.cells[1].scalar == U'B' &&
                grid.cells[2].scalar == U'C' && grid.cells[3].scalar == U'x',
            "plain-text joiners collapse letter cells");
    grid.reset(20, 4);
    grid.line(0, {{"\u200dA", Ink::normal}});
    require(grid.cells[0].scalar == U'A' && grid.cells[1].scalar == U' ',
            "leading joiner consumes a spacing cell or next letter");
    grid.reset(20, 4);
    grid.line(0, {{"\u200d\u200dA", Ink::normal}});
    require(grid.cells[0].scalar == U'A' && grid.cells[1].scalar == U' ',
            "repeated leading joiners fail to advance input");
    grid.reset(20, 4);
    grid.line(0, {{"👩́\u200d💻x", Ink::normal}});
    require(grid.cells[0].width == 2 && grid.cells[2].scalar == U'x',
            "pictograph Extend ZWJ sequence split");
    grid.reset(20, 4);
    grid.line(0, {{"👩🏽\u200d💻x", Ink::normal}});
    require(grid.cells[0].width == 2 && grid.cells[2].scalar == U'x',
            "modified pictograph ZWJ sequence split");
    for (const auto barrier_text :
         {"👩\u200b\u200d💻x", "👩\u200e\u200d💻x", "👩\u200d́💻x"}) {
      grid.reset(20, 4);
      grid.line(0, {{barrier_text, Ink::normal}});
      require(grid.cells[0].width == 2 && grid.cells[2].scalar == U'💻' &&
                  grid.cells[4].scalar == U'x',
              "non-Extend barrier or post-ZWJ Extend joins pictographs");
    }
    grid.reset(20, 4);
    grid.line(0, {{"👨\u200d👩\u200d👧\u200d👦x", Ink::normal}});
    require(grid.cells[0].width == 2 && grid.cells[2].scalar == U'x',
            "family pictograph ZWJ sequence split");
    ChatView plain_joiners;
    plain_joiners.append(ChatKind::assistant, " \u200d \u200d XZ");
    const auto &joined_rows = plain_joiners.rows(8);
    require(joined_rows.size() == 3 &&
                chat_plain(joined_rows[1]) == "  │  \u200d \u200d X" &&
                chat_plain(joined_rows[2]) == "  │ Z",
            "plain joiners change wrap boundary");
    grid.reset(20, 4);
    grid.line(0, {{"🇺🇸x", Ink::normal}});
    require(grid.cells[0].width == 2 && grid.cells[2].scalar == U'x', "flag cluster");
    painter.prepare(grid, 3, 2);
    painter.commit(grid);
    grid.reset(10, 3);
    require(!painter.prepare(grid, 2, 0).empty(), "resize did not repaint");
    ChatView control;
    control.append(ChatKind::assistant, "evil\x1b[2J");
    require(plain(control.rows(80)).find('\x1b') == std::string::npos,
            "untrusted control escaped renderer");
    ChatView large;
    large.append(ChatKind::tool, std::string(2 * 1024 * 1024, 'a'));
    require(large.size() <= 1024 * 1024, "display source unbounded");
    {
      // A tool block folds to its header, first 3 and last 3 lines (rhi.8).
      std::string lines;
      for (int n = 1; n <= 40; ++n)
        lines += std::to_string(n) + "\n";
      const std::string folded = "  ACTIVITY\n"
                                 "  │ ▸ exec seq 1 40\n"
                                 "  │ 1\n  │ 2\n  │ 3\n"
                                 "  │ ┆ 34 more lines · Ctrl-O inspects\n"
                                 "  │ 38\n  │ 39\n  │ 40\n";
      ChatView whole;
      whole.append(ChatKind::tool, "▸ exec seq 1 40\n");
      whole.append(ChatKind::tool, lines, true);
      require(plain(whole.rows(80)) == folded, "tool output not folded");
      ChatView streamed;
      streamed.append(ChatKind::tool, "▸ exec seq 1 40\n");
      for (int n = 1; n <= 40; ++n) {
        streamed.append(ChatKind::tool, std::to_string(n) + "\n", true);
        (void)streamed.rows(80);
      }
      require(plain(streamed.rows(80)) == folded, "streamed tool output folds alike");
      require(streamed.size() < 64, "folded display keeps only head and tail");
      streamed.append(ChatKind::tool, "4", true);
      streamed.append(ChatKind::tool, "1", true);
      require(plain(streamed.rows(80))
                  .ends_with("  │ ┆ 34 more lines · Ctrl-O inspects\n"
                             "  │ 38\n  │ 39\n  │ 40\n  │ 41\n"),
              "unfinished tail line not shown live");
      streamed.append(ChatKind::tool, "\n", true);
      require(plain(streamed.rows(80))
                  .ends_with("  │ ┆ 35 more lines · Ctrl-O inspects\n"
                             "  │ 39\n  │ 40\n  │ 41\n"),
              "completed tail line not folded");
      require(plain(streamed.rows(30)).find("┆ 35 more lines") != std::string::npos,
              "fold lost on width change");
      for (const auto [body_lines, fold] : {std::pair{7, false}, std::pair{8, true}}) {
        ChatView small;
        std::string body = "▸ h\n";
        for (int n = 1; n <= body_lines; ++n)
          body += "s" + std::to_string(n) + "\n";
        small.append(ChatKind::tool, body);
        const auto shown = plain(small.rows(80));
        require((shown.find("┆") != std::string::npos) == fold &&
                    (shown.find("s4") != std::string::npos) == !fold,
                "fold needs at least two hidden lines");
      }
      ChatView prose;
      prose.append(ChatKind::assistant, lines);
      require(plain(prose.rows(80)).find("  │ 20\n") != std::string::npos,
              "non-tool block folded");
      ChatView conversation;
      conversation.append(ChatKind::user, "KEEP_PROMPT");
      conversation.append(ChatKind::tool, "▸ exec big\n");
      for (int n = 0; n < 10000; ++n)
        conversation.append(ChatKind::tool, "line " + std::to_string(n) + "\n", true);
      const auto kept = plain(conversation.rows(80));
      require(kept.find("KEEP_PROMPT") != std::string::npos &&
                  kept.find("┆ 9994 more lines") != std::string::npos &&
                  kept.find("Display clipped") == std::string::npos,
              "tool output evicted the conversation");
    }
    {
      // Command presentation: the exit marker takes one tail line, background
      // output keeps its own attributed block, and foreground output after it
      // repeats its header.
      ChatView commands;
      commands.tool_start("▸ exec seq");
      for (int n = 1; n <= 40; ++n)
        commands.tool_output(std::to_string(n) + "\n");
      commands.tool_output("\n[exit 0]\n");
      require(plain(commands.rows(80))
                  .ends_with("  │ ┆ 35 more lines · Ctrl-O inspects\n"
                             "  │ 39\n  │ 40\n  │ [exit 0]\n"),
              "exit marker spends an extra tail line");
      ChatView mixed;
      mixed.tool_start("▸ exec fg");
      mixed.tool_output("FG_1\n");
      mixed.tool_output("\n[command J1]\nBG_1\n");
      mixed.tool_output("\n[command J1]\nBG_2\n");
      mixed.tool_output("FG_2\n");
      require(plain(mixed.rows(80)) ==
                  "  ACTIVITY\n  │ ▸ exec fg\n  │ FG_1\n\n"
                  "  ACTIVITY\n  │ [command J1]\n  │ BG_1\n  │ BG_2\n\n"
                  "  ACTIVITY\n  │ ▸ exec fg\n  │ FG_2\n",
              "background output not attributed");
      ChatView ended;
      ended.tool_start("▸ exec e");
      ended.tool_output("E_1\n");
      ended.tool_end();
      ended.append(ChatKind::tool, "✓ exec completed");
      ended.tool_output("\n[exec: capacity]\n");
      require(plain(ended.rows(80)).find("▸ exec e") ==
                  plain(ended.rows(80)).rfind("▸ exec e"),
              "finished command header reopened for later output");
      ChatView partial;
      partial.tool_start("▸ exec p");
      partial.tool_output("no newline");
      partial.tool_output("\n[exit 1]\n");
      require(plain(partial.rows(80)).ends_with("  │ no newline\n  │ [exit 1]\n"),
              "marker lost its separating newline");
      // A fence opened in the head and closed in the hidden middle leaves the
      // tail as prose; one opened in the middle leaves it as code.
      for (const auto [close, code] :
           {std::pair{true, false}, std::pair{false, true}}) {
        ChatView fenced;
        fenced.tool_start("▸ cat");
        std::string body = close ? "a\n```\nb\n" : "a\nb\nc\n";
        for (int n = 0; n < 6; ++n)
          body += n == 2 ? "```\n" : "m\n";
        body += "y\nz\nif q\n"; // Only code mode highlights the keyword.
        fenced.tool_output(body);
        const auto &last = fenced.rows(80).back();
        require(std::any_of(last.begin(), last.end(),
                            [](const ChatSpan &span) {
                              return span.ink == Ink::keyword;
                            }) == code,
                "fence state lost across the fold");
      }
      // A fold followed by a new block before rows() renders both in order.
      ChatView ordered;
      ordered.tool_start("▸ exec o");
      for (int n = 1; n <= 20; ++n)
        ordered.tool_output("o" + std::to_string(n) + "\n");
      ordered.append(ChatKind::assistant, "AFTER");
      const auto ordered_text = plain(ordered.rows(80));
      require(ordered_text.find("┆ 14 more lines") < ordered_text.find("  │ o20\n") &&
                  ordered_text.find("  │ o20\n") < ordered_text.find("AFTER"),
              "fold and later block out of order");
      // A clipped over-long line inside the folded middle still folds cleanly.
      ChatView clipped;
      clipped.tool_start("▸ exec long");
      clipped.tool_output("c1\nc2\nc3\n" + std::string(4096, 'x') +
                          "\nc5\nc6\nc7\nc8\n");
      const auto clipped_text = plain(clipped.rows(80));
      require(clipped_text.find("┆ 2 more lines") != std::string::npos &&
                  clipped_text.find("xxxx") == std::string::npos,
              "clipped line broke the fold");
    }
    ChatView narrow;
    narrow.append(ChatKind::assistant, "aa👩‍💻x\n```cpp\n// 界\n```");
    const auto narrow_text = plain(narrow.rows(8));
    require(narrow_text.find("👩‍💻") != std::string::npos &&
                narrow_text.find("界") != std::string::npos,
            "wrapping splits Unicode clusters");
    grid.reset(20, 4);
    grid.line(0, {{"é", Ink::normal}});
    grid.line(0, {{"h", Ink::normal}});
    require(grid.cells[0].length == 0, "overwrite preserves old cluster tail");
    std::string cluster = "e";
    for (int i = 0; i < 3000; ++i)
      cluster += "́";
    grid.line(0, {{cluster, Ink::normal}});
    require(grid.cells[0].scalar == U'�', "oversized cluster has no bounded fallback");
    ChatView newlines;
    newlines.append(ChatKind::tool, std::string(1024 * 1024, '\n'));
    require(newlines.rows(8).size() < 4096, "derived rows unbounded");
    ChatView unfinished;
    unfinished.begin(ChatKind::tool);
    for (int i = 0; i < 256; ++i) {
      unfinished.stream(std::string(1024, 'a'));
      require(unfinished.rows(80).size() < 64, "unfinished line work unbounded");
    }
    int descriptors[2];
    require(::pipe(descriptors) == 0, "pipe setup");
    (void)::fcntl(descriptors[0], F_SETFL, O_NONBLOCK);
    std::string payload(256 * 1024, 'q'), received;
    {
      ChatOutput output;
      output.attach(descriptors[1]);
      output.start(payload);
      require(!output.flush() && output.pending(),
              "backpressure did not remain pending");
      for (unsigned round = 0;
           round < 1000 && (output.pending() || received.size() < payload.size());
           ++round) {
        char data[16384];
        const auto n = ::read(descriptors[0], data, sizeof(data));
        if (n > 0)
          received.append(data, static_cast<std::size_t>(n));
        if (output.pending())
          (void)output.flush();
      }
      require(!output.pending() && received == payload,
              "partial writes corrupted bytes");
    }
    require((::fcntl(descriptors[1], F_GETFL) & O_NONBLOCK) == 0,
            "output flags not restored");
    ::close(descriptors[0]);
    ::close(descriptors[1]);
    const auto start = std::chrono::steady_clock::now();
    std::size_t bytes = 0;
    ChatGrid motion;
    motion.reset(120, 40);
    ChatPainter paint;
    motion.line(0, {{"activity 0", Ink::assistant}});
    paint.prepare(motion, 38, 3);
    paint.commit(motion);
    for (int i = 0; i < 1000; ++i) {
      motion.line(0, {{"activity " + std::to_string(i % 10), Ink::assistant}});
      bytes += paint.prepare(motion, 38, 3).size();
      paint.commit(motion);
    }
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - start)
                        .count();
    require(bytes < 100000, "motion writes excessive bytes");
    std::cout << "1000 120x40 motion updates: " << us << "us, " << bytes
              << " bytes; sizeof(cell)=" << sizeof(ChatCell) << "\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
