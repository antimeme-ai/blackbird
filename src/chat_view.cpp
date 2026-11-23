#include "blackbird/chat_view.hpp"
#include "blackbird/display_text.hpp"
#include "blackbird/terminal.hpp"
#include "blackbird/workflows.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <clocale>
#include <fcntl.h>
#include <limits>
#include <stdexcept>
#include <unistd.h>

namespace blackbird {
namespace {
constexpr std::size_t display_limit = 64 * 1024;
constexpr std::size_t line_limit = 2048;
std::string_view color(Ink ink) {
  constexpr std::array colors{"\x1b[0m",
                              "\x1b[0;38;2;160;173;188m",
                              "\x1b[1;38;2;222;179;113m",
                              "\x1b[1;38;2;114;215;211m",
                              "\x1b[1;38;2;232;227;217m",
                              "\x1b[0;38;2;188;168;239;48;2;37;40;51m",
                              "\x1b[1;38;2;188;168;239;48;2;37;40;51m",
                              "\x1b[0;38;2;155;213;172;48;2;37;40;51m",
                              "\x1b[0;38;2;155;213;172m",
                              "\x1b[1;38;2;242;137;137m",
                              "\x1b[0;1;38;2;114;215;211m",
                              "\x1b[0;38;2;85;142;151m",
                              "\x1b[0;38;2;20;24;32;48;2;114;215;211m"};
  return colors[static_cast<std::size_t>(ink)];
}
void utf8(std::string &out, char32_t cp) {
  if (cp < 0x80)
    out += static_cast<char>(cp);
  else if (cp < 0x800) {
    out += static_cast<char>(0xc0 | (cp >> 6));
    out += static_cast<char>(0x80 | (cp & 63));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xe0 | (cp >> 12));
    out += static_cast<char>(0x80 | ((cp >> 6) & 63));
    out += static_cast<char>(0x80 | (cp & 63));
  } else {
    out += static_cast<char>(0xf0 | (cp >> 18));
    out += static_cast<char>(0x80 | ((cp >> 12) & 63));
    out += static_cast<char>(0x80 | ((cp >> 6) & 63));
    out += static_cast<char>(0x80 | (cp & 63));
  }
}
ChatRow inline_text(std::string_view text, Ink base) {
  ChatRow out;
  std::string pending;
  Ink current = base;
  auto flush = [&] {
    if (!pending.empty()) {
      out.push_back({std::move(pending), current});
      pending.clear();
    }
  };
  bool bold = false, code = false;
  while (!text.empty()) {
    if (text.starts_with("**") && !code) {
      flush();
      bold = !bold;
      current = bold ? Ink::heading : base;
      text.remove_prefix(2);
    } else if (text.front() == '`') {
      flush();
      code = !code;
      current = code ? Ink::code : (bold ? Ink::heading : base);
      text.remove_prefix(1);
    } else {
      pending += text.front();
      text.remove_prefix(1);
    }
  }
  flush();
  return out;
}
ChatRow syntax(std::string_view text) {
  ChatRow out;
  std::size_t pos = 0;
  constexpr std::array words{"auto", "const", "return", "if",       "else",
                             "for",  "while", "class",  "struct",   "void",
                             "int",  "bool",  "local",  "function", "end",
                             "true", "false", "nil",    "nullptr"};
  while (pos < text.size()) {
    const auto begin = pos;
    Ink ink = Ink::code;
    if (text[pos] == '"' || text[pos] == '\'') {
      const auto quote = text[pos++];
      while (pos < text.size()) {
        const auto c = text[pos++];
        if (c == '\\' && pos < text.size())
          ++pos;
        else if (c == quote)
          break;
      }
      ink = Ink::string;
    } else if ((text[pos] >= 'a' && text[pos] <= 'z') ||
               (text[pos] >= 'A' && text[pos] <= 'Z') || text[pos] == '_') {
      do {
        ++pos;
      } while (pos < text.size() &&
               ((text[pos] >= 'a' && text[pos] <= 'z') ||
                (text[pos] >= 'A' && text[pos] <= 'Z') ||
                (text[pos] >= '0' && text[pos] <= '9') || text[pos] == '_'));
      const auto word = text.substr(begin, pos - begin);
      if (std::find(words.begin(), words.end(), word) != words.end())
        ink = Ink::keyword;
    } else
      pos += display_scalar(text.substr(pos)).bytes;
    if (!out.empty() && out.back().ink == ink)
      out.back().text.append(text.substr(begin, pos - begin));
    else
      out.push_back({std::string{text.substr(begin, pos - begin)}, ink});
  }
  return out;
}
struct WrapPrefix {
  ChatRow first;
  ChatRow continuation;
};
std::size_t row_cells(const ChatRow &content) {
  DisplayCursor cursor{content};
  DisplayCluster cluster;
  std::size_t cells = 0;
  while (cursor.next(cluster))
    cells += cluster.cells.value;
  return cells;
}
std::string repeat_str(std::string_view unit, std::size_t count) {
  std::string out;
  out.reserve(unit.size() * count);
  for (std::size_t i = 0; i < count; ++i)
    out += unit;
  return out;
}
std::string clip_display_cells(std::string_view text, CellCount max_cells,
                               std::size_t *out_cells = nullptr) {
  std::string out;
  DisplayCursor cursor{text};
  DisplayCluster cluster;
  std::size_t used = 0;
  while (cursor.next(cluster)) {
    if (!cluster.cells.value)
      continue;
    if (used + cluster.cells.value > max_cells.value)
      break;
    cursor.append(out, cluster);
    used += cluster.cells.value;
  }
  if (out_cells)
    *out_cells = used;
  return out;
}
std::string_view trim_ascii_spaces(std::string_view text) {
  while (!text.empty() && text.front() == ' ')
    text.remove_prefix(1);
  while (!text.empty() && text.back() == ' ')
    text.remove_suffix(1);
  return text;
}
void wrap_prefixed(std::vector<ChatRow> &rows, const ChatRow &content, CellCount width,
                   Ink rail, const WrapPrefix &prefix = {}) {
  const std::size_t first_prefix_cells = row_cells(prefix.first);
  const std::size_t cont_prefix_cells = row_cells(prefix.continuation);
  const std::size_t first_budget =
      width.value > first_prefix_cells ? width.value - first_prefix_cells : 1;
  const std::size_t cont_budget =
      width.value > cont_prefix_cells ? width.value - cont_prefix_cells : 1;
  auto make_row = [&](const ChatRow &lead) {
    ChatRow row{{"  │ ", rail}};
    row.insert(row.end(), lead.begin(), lead.end());
    return row;
  };
  ChatRow row = make_row(prefix.first);
  std::size_t budget = first_budget;
  std::size_t cells = 0;
  std::string pending;
  Ink previous = Ink::normal;
  auto flush = [&] {
    if (!pending.empty()) {
      row.push_back({std::move(pending), previous});
      pending.clear();
    }
  };
  DisplayCursor cursor{content};
  DisplayCluster cluster;
  while (cursor.next(cluster)) {
    if (!cluster.cells.value)
      continue;
    if (cluster.ink != previous) {
      flush();
      previous = cluster.ink;
    }
    if (cells && cells + cluster.cells.value > budget) {
      flush();
      rows.push_back(std::move(row));
      row = make_row(prefix.continuation);
      budget = cont_budget;
      cells = 0;
    }
    display_fit(cluster, {budget});
    cursor.append(pending, cluster);
    cells += cluster.cells.value;
  }
  flush();
  rows.push_back(std::move(row));
}
void wrap(std::vector<ChatRow> &rows, const ChatRow &content, std::size_t width,
          Ink rail) {
  wrap_prefixed(rows, content, {width}, rail);
}
bool is_horizontal_rule(std::string_view line) {
  std::size_t indent = 0;
  while (indent < line.size() && indent < 3 && line[indent] == ' ')
    ++indent;
  line.remove_prefix(indent);
  if (line.empty())
    return false;
  const char marker = line.front();
  if (marker != '-' && marker != '*' && marker != '_')
    return false;
  std::size_t count = 0;
  for (const char c : line) {
    if (c == marker)
      ++count;
    else if (c != ' ')
      return false;
  }
  return count >= 3;
}
struct HeadingMatch {
  std::size_t level = 0;
  std::string_view title;
};
std::optional<HeadingMatch> parse_heading(std::string_view line) {
  std::size_t indent = 0;
  while (indent < line.size() && indent < 3 && line[indent] == ' ')
    ++indent;
  line.remove_prefix(indent);
  std::size_t hashes = 0;
  while (hashes < line.size() && hashes < 6 && line[hashes] == '#')
    ++hashes;
  if (hashes == 0)
    return std::nullopt;
  if (hashes < line.size() && line[hashes] != ' ')
    return std::nullopt;
  auto title = line.substr(hashes);
  while (!title.empty() && title.front() == ' ')
    title.remove_prefix(1);
  while (!title.empty() && title.back() == ' ')
    title.remove_suffix(1);
  // Strip optional CommonMark closing `#` sequence preceded by space.
  std::size_t end = title.size();
  while (end > 0 && title[end - 1] == '#')
    --end;
  if (end < title.size() && (end == 0 || title[end - 1] == ' ')) {
    title = title.substr(0, end);
    while (!title.empty() && title.back() == ' ')
      title.remove_suffix(1);
  }
  return HeadingMatch{hashes, title};
}
struct FenceOpenMatch {
  std::string_view lang;
};
std::optional<FenceOpenMatch> parse_fence_open(std::string_view line) {
  std::size_t indent = 0;
  while (indent < line.size() && indent < 3 && line[indent] == ' ')
    ++indent;
  line.remove_prefix(indent);
  std::size_t ticks = 0;
  while (ticks < line.size() && line[ticks] == '`')
    ++ticks;
  if (ticks < 3)
    return std::nullopt;
  const auto info = trim_ascii_spaces(line.substr(ticks));
  if (info.find('`') != std::string_view::npos)
    return std::nullopt;
  return FenceOpenMatch{info};
}
bool is_fence_close(std::string_view line) {
  std::size_t indent = 0;
  while (indent < line.size() && indent < 3 && line[indent] == ' ')
    ++indent;
  line.remove_prefix(indent);
  std::size_t ticks = 0;
  while (ticks < line.size() && line[ticks] == '`')
    ++ticks;
  if (ticks < 3)
    return false;
  return trim_ascii_spaces(line.substr(ticks)).empty();
}
struct BlockquoteMatch {
  std::size_t depth = 0;
  std::string_view body;
};
std::optional<BlockquoteMatch> parse_blockquote(std::string_view line) {
  std::size_t depth = 0;
  while (depth < 3) {
    std::size_t spaces = 0;
    while (spaces < line.size() && spaces < 3 && line[spaces] == ' ')
      ++spaces;
    if (spaces >= line.size() || line[spaces] != '>')
      break;
    line.remove_prefix(spaces + 1);
    if (!line.empty() && line.front() == ' ')
      line.remove_prefix(1);
    ++depth;
  }
  if (depth == 0)
    return std::nullopt;
  return BlockquoteMatch{depth, line};
}
struct ListItemMatch {
  std::size_t indent = 0;
  std::string marker;
  std::string_view body;
};
std::optional<ListItemMatch> parse_list_item(std::string_view line) {
  std::size_t indent = 0;
  while (indent < line.size() && line[indent] == ' ')
    ++indent;
  const auto rest = line.substr(indent);
  if (rest.size() >= 2 && (rest[0] == '-' || rest[0] == '*' || rest[0] == '+') &&
      rest[1] == ' ') {
    return ListItemMatch{indent, "• ", rest.substr(2)};
  }
  std::size_t digits = 0;
  while (digits < rest.size() && digits < 6 && rest[digits] >= '0' &&
         rest[digits] <= '9')
    ++digits;
  if (digits > 0 && digits + 1 < rest.size() && rest[digits] == '.' &&
      rest[digits + 1] == ' ') {
    return ListItemMatch{indent, std::string{rest.substr(0, digits)} + ". ",
                         rest.substr(digits + 2)};
  }
  return std::nullopt;
}
enum class TableAlign : std::uint8_t { left, center, right };
constexpr std::size_t max_table_cols = 32;
constexpr std::size_t max_table_rows = 256;
std::vector<std::string> split_table_cells(std::string_view line) {
  line = trim_ascii_spaces(line);
  if (!line.empty() && line.front() == '|')
    line.remove_prefix(1);
  if (!line.empty() && line.back() == '|') {
    std::size_t slashes = 0;
    for (std::size_t i = line.size() - 1; i > 0 && line[i - 1] == '\\'; --i)
      ++slashes;
    if ((slashes & 1U) == 0)
      line.remove_suffix(1);
  }
  std::vector<std::string> cells;
  std::string current;
  bool in_code = false;
  for (std::size_t i = 0; i < line.size(); ++i) {
    const char c = line[i];
    if (c == '\\' && i + 1 < line.size() && line[i + 1] == '|') {
      current += '|';
      ++i;
      continue;
    }
    if (c == '`') {
      in_code = !in_code;
      current += c;
      continue;
    }
    if (c == '|' && !in_code && cells.size() + 1 < max_table_cols) {
      cells.emplace_back(trim_ascii_spaces(current));
      current.clear();
      continue;
    }
    current += c;
  }
  cells.emplace_back(trim_ascii_spaces(current));
  return cells;
}
std::optional<std::vector<TableAlign>> parse_table_separator(std::string_view line) {
  const auto trimmed = trim_ascii_spaces(line);
  if (trimmed.find('|') == std::string_view::npos)
    return std::nullopt;
  const bool edge_pipe = trimmed.front() == '|' || trimmed.back() == '|';
  auto stripped = trimmed;
  if (!stripped.empty() && stripped.front() == '|')
    stripped.remove_prefix(1);
  if (!stripped.empty() && stripped.back() == '|')
    stripped.remove_suffix(1);
  std::vector<TableAlign> aligns;
  std::size_t pos = 0;
  while (pos <= stripped.size()) {
    const auto bar = stripped.find('|', pos);
    const auto raw_cell = bar == std::string_view::npos
                              ? stripped.substr(pos)
                              : stripped.substr(pos, bar - pos);
    const auto cell = trim_ascii_spaces(raw_cell);
    if (cell.empty())
      return std::nullopt;
    const bool lead_colon = cell.front() == ':';
    const bool trail_colon = cell.size() > 1 && cell.back() == ':';
    const std::size_t dash_begin = lead_colon ? 1 : 0;
    const std::size_t dash_end = trail_colon ? cell.size() - 1 : cell.size();
    if (dash_begin >= dash_end)
      return std::nullopt;
    for (std::size_t i = dash_begin; i < dash_end; ++i)
      if (cell[i] != '-')
        return std::nullopt;
    if (aligns.size() < max_table_cols)
      aligns.push_back(lead_colon && trail_colon ? TableAlign::center
                       : trail_colon             ? TableAlign::right
                                                 : TableAlign::left);
    if (bar == std::string_view::npos)
      break;
    pos = bar + 1;
  }
  if (aligns.empty() || (aligns.size() == 1 && !edge_pipe))
    return std::nullopt;
  return aligns;
}
bool could_be_table_separator_prefix(std::string_view line) {
  if (line.empty())
    return false;
  for (const char c : line)
    if (c != ' ' && c != '|' && c != '-' && c != ':')
      return false;
  return true;
}
bool looks_like_table_row(std::string_view line) {
  const auto trimmed = trim_ascii_spaces(line);
  if (trimmed.empty() || trimmed.find('|') == std::string_view::npos)
    return false;
  if (parse_fence_open(line) || parse_heading(line) || is_horizontal_rule(line))
    return false;
  return true;
}
struct WrappedCellLine {
  ChatRow spans;
  std::size_t cells = 0;
};
std::vector<WrappedCellLine> wrap_cell(const ChatRow &content, CellCount col_width) {
  const std::size_t limit = std::max<std::size_t>(1, col_width.value);
  std::vector<WrappedCellLine> lines;
  WrappedCellLine current;
  std::string pending;
  Ink previous = Ink::normal;
  auto flush = [&] {
    if (!pending.empty()) {
      current.spans.push_back({std::move(pending), previous});
      pending.clear();
    }
  };
  DisplayCursor cursor{content};
  DisplayCluster cluster;
  while (cursor.next(cluster)) {
    if (!cluster.cells.value)
      continue;
    if (cluster.ink != previous) {
      flush();
      previous = cluster.ink;
    }
    if (current.cells && current.cells + cluster.cells.value > limit) {
      flush();
      lines.push_back(std::move(current));
      current = {};
    }
    display_fit(cluster, {limit});
    cursor.append(pending, cluster);
    current.cells += cluster.cells.value;
  }
  flush();
  lines.push_back(std::move(current));
  return lines;
}
struct TableBorderGlyphs {
  std::string_view left;
  std::string_view cross;
  std::string_view right;
};
void push_table_border(std::vector<ChatRow> &rows,
                       const std::vector<std::size_t> &widths, bool padded, Ink rail,
                       TableBorderGlyphs glyphs) {
  std::string line{glyphs.left};
  for (std::size_t c = 0; c < widths.size(); ++c) {
    if (c > 0)
      line += glyphs.cross;
    line += repeat_str("─", widths[c] + (padded ? 2U : 0U));
  }
  line += glyphs.right;
  rows.push_back({{"  │ ", rail}, {std::move(line), Ink::border}});
}
void render_markdown_table(std::vector<ChatRow> &rows,
                           const std::vector<std::string> &table_lines,
                           const std::vector<TableAlign> &raw_aligns, CellCount avail,
                           Ink rail) {
  // table_lines[0] is header, table_lines[1] is separator, table_lines[2..] are body.
  std::vector<std::vector<ChatRow>> grid;
  std::size_t cols = raw_aligns.size();
  grid.reserve(table_lines.size() - 1);
  for (std::size_t r = 0; r < table_lines.size(); ++r) {
    if (r == 1)
      continue;
    const auto raw_cells = split_table_cells(table_lines[r]);
    cols = std::max(cols, raw_cells.size());
    std::vector<ChatRow> styled_row;
    styled_row.reserve(raw_cells.size());
    const Ink base = r == 0 ? Ink::heading : Ink::normal;
    for (const auto &cell : raw_cells)
      styled_row.push_back(inline_text(cell, base));
    grid.push_back(std::move(styled_row));
  }
  cols = std::clamp<std::size_t>(cols, 1, max_table_cols);
  const bool padded = avail.value >= 4 * cols + 1;
  const std::size_t overhead = padded ? 3 * cols + 1 : cols + 1;
  if (avail.value < overhead + cols) {
    for (const auto &line : table_lines)
      wrap_prefixed(rows, inline_text(line, Ink::normal), avail, rail);
    return;
  }
  std::vector<TableAlign> aligns = raw_aligns;
  aligns.resize(cols, TableAlign::left);
  std::vector<std::size_t> nat(cols, 1);
  for (const auto &row : grid) {
    for (std::size_t c = 0; c < std::min(row.size(), cols); ++c)
      nat[c] = std::max(nat[c], row_cells(row[c]));
  }
  const std::size_t budget = avail.value - overhead;
  std::vector<std::size_t> widths = nat;
  std::size_t total = 0;
  for (const auto w : widths)
    total += w;
  if (total > budget) {
    const std::size_t extra = budget - cols;
    std::vector<std::size_t> capped(cols, 1);
    std::size_t excess_total = 0;
    for (std::size_t c = 0; c < cols; ++c) {
      capped[c] = std::min(nat[c], budget);
      excess_total += capped[c] - 1;
    }
    std::size_t assigned = 0;
    for (std::size_t c = 0; c < cols; ++c) {
      const std::size_t share =
          excess_total ? ((capped[c] - 1) * extra) / excess_total : 0;
      widths[c] = 1 + share;
      assigned += widths[c];
    }
    for (std::size_t c = 0; c < cols && assigned < budget; ++c) {
      if (widths[c] < nat[c]) {
        ++widths[c];
        ++assigned;
      }
    }
  }
  push_table_border(rows, widths, padded, rail, {"╭", "┬", "╮"});
  for (std::size_t r = 0; r < grid.size(); ++r) {
    std::vector<std::vector<WrappedCellLine>> wrapped(cols);
    std::size_t row_height = 1;
    for (std::size_t c = 0; c < cols; ++c) {
      if (c < grid[r].size())
        wrapped[c] = wrap_cell(grid[r][c], {widths[c]});
      else
        wrapped[c].push_back({});
      row_height = std::max(row_height, wrapped[c].size());
    }
    for (std::size_t y = 0; y < row_height; ++y) {
      ChatRow out{{"  │ ", rail}};
      auto append_span = [&](std::string text, Ink ink) {
        if (text.empty())
          return;
        if (!out.empty() && out.back().ink == ink)
          out.back().text += text;
        else
          out.push_back({std::move(text), ink});
      };
      for (std::size_t c = 0; c < cols; ++c) {
        append_span("│", Ink::border);
        if (padded)
          append_span(" ", Ink::normal);
        const WrappedCellLine empty_cell;
        const auto &cell_line = y < wrapped[c].size() ? wrapped[c][y] : empty_cell;
        const std::size_t pad =
            widths[c] > cell_line.cells ? widths[c] - cell_line.cells : 0;
        const std::size_t left_pad = aligns[c] == TableAlign::right    ? pad
                                     : aligns[c] == TableAlign::center ? pad / 2
                                                                       : 0;
        const std::size_t right_pad = pad - left_pad;
        if (left_pad)
          append_span(std::string(left_pad, ' '), Ink::normal);
        for (const auto &span : cell_line.spans)
          append_span(span.text, span.ink);
        if (right_pad)
          append_span(std::string(right_pad, ' '), Ink::normal);
        if (padded)
          append_span(" ", Ink::normal);
      }
      append_span("│", Ink::border);
      rows.push_back(std::move(out));
    }
    if (r == 0)
      push_table_border(rows, widths, padded, rail, {"├", "┼", "┤"});
  }
  push_table_border(rows, widths, padded, rail, {"╰", "┴", "╯"});
}
void render_assistant_line(std::vector<ChatRow> &rows, std::string_view safe,
                           std::size_t width, Ink rail, bool &code) {
  const std::size_t content_width = width - 4;
  const std::size_t prose_width = std::min<std::size_t>(content_width, 92);
  const std::size_t box_width = prose_width;
  if (code) {
    if (is_fence_close(safe)) {
      const std::size_t fill = box_width > 1 ? box_width - 1 : 0;
      rows.push_back({{"  │ ", rail}, {"╰" + repeat_str("─", fill), Ink::border}});
      code = false;
      return;
    }
    WrapPrefix prefix{{{"│ ", Ink::code}}, {{"│ ", Ink::code}}};
    wrap_prefixed(rows, syntax(safe), {content_width}, rail, prefix);
    return;
  }
  if (const auto open = parse_fence_open(safe)) {
    if (!open->lang.empty() && box_width >= 6) {
      std::size_t lang_cells = 0;
      auto lang = clip_display_cells(open->lang, {box_width - 5}, &lang_cells);
      if (!lang.empty()) {
        const std::size_t fill =
            box_width > 4 + lang_cells ? box_width - 4 - lang_cells : 1;
        rows.push_back({{"  │ ", rail},
                        {"╭─ ", Ink::border},
                        {std::move(lang), Ink::code},
                        {" " + repeat_str("─", fill), Ink::border}});
      } else {
        const std::size_t fill = box_width > 1 ? box_width - 1 : 0;
        rows.push_back({{"  │ ", rail}, {"╭" + repeat_str("─", fill), Ink::border}});
      }
    } else {
      const std::size_t fill = box_width > 1 ? box_width - 1 : 0;
      rows.push_back({{"  │ ", rail}, {"╭" + repeat_str("─", fill), Ink::border}});
    }
    code = true;
    return;
  }
  if (const auto heading = parse_heading(safe)) {
    const auto styled = inline_text(heading->title, Ink::heading);
    if (heading->level == 1) {
      wrap_prefixed(rows, styled, {prose_width}, rail);
      const std::size_t cells = row_cells(styled);
      if (cells > 0) {
        rows.push_back({{"  │ ", rail},
                        {repeat_str("─", std::min(cells, prose_width)), Ink::border}});
      }
    } else if (heading->level == 2 || prose_width < 4) {
      wrap_prefixed(rows, styled, {prose_width}, rail);
    } else {
      WrapPrefix prefix{{{"› ", Ink::border}}, {{"  ", Ink::normal}}};
      wrap_prefixed(rows, styled, {prose_width}, rail, prefix);
    }
    return;
  }
  if (is_horizontal_rule(safe)) {
    rows.push_back({{"  │ ", rail}, {repeat_str("─", prose_width), Ink::border}});
    return;
  }
  if (const auto quote = parse_blockquote(safe)) {
    const std::size_t max_depth = prose_width > 2 ? (prose_width - 2) / 2 : 0;
    const std::size_t depth = std::min(quote->depth, max_depth);
    ChatRow bar;
    if (depth > 0)
      bar.push_back({repeat_str("▎ ", depth), Ink::border});
    WrapPrefix prefix{bar, bar};
    wrap_prefixed(rows, inline_text(quote->body, Ink::muted), {prose_width}, rail,
                  prefix);
    return;
  }
  if (const auto item = parse_list_item(safe)) {
    const std::size_t marker_cells = display_cells(item->marker).value;
    WrapPrefix prefix;
    if (prose_width >= marker_cells + 4) {
      const std::size_t base_cells = marker_cells + 2;
      const std::size_t max_nest =
          prose_width > base_cells + 4
              ? std::min<std::size_t>(prose_width - base_cells - 4, 12)
              : 0;
      const std::size_t nest = std::min(item->indent, max_nest);
      prefix.first.push_back({std::string(nest + 2, ' '), Ink::normal});
      prefix.first.push_back({item->marker, Ink::assistant});
      prefix.continuation.push_back({std::string(nest + base_cells, ' '), Ink::normal});
    } else if (prose_width >= marker_cells + 2) {
      prefix.first.push_back({item->marker, Ink::assistant});
      prefix.continuation.push_back({std::string(marker_cells, ' '), Ink::normal});
    } else {
      wrap_prefixed(rows, inline_text(safe, Ink::normal), {prose_width}, rail);
      return;
    }
    wrap_prefixed(rows, inline_text(item->body, Ink::normal), {prose_width}, rail,
                  prefix);
    return;
  }
  wrap_prefixed(rows, inline_text(safe, Ink::normal), {prose_width}, rail);
}
ChatRow style_tool_header_line(std::string_view safe) {
  struct Badge {
    std::string_view prefix;
    Ink ink;
  };
  constexpr std::array badges{
      Badge{"▸ ", Ink::assistant},
      Badge{"✓ ", Ink::success},
      Badge{"✗ ", Ink::failure},
      Badge{"• ", Ink::muted},
  };
  for (const auto &badge : badges) {
    if (!safe.starts_with(badge.prefix))
      continue;
    ChatRow out;
    out.push_back({std::string{badge.prefix}, badge.ink});
    const auto rest = safe.substr(badge.prefix.size());
    constexpr std::string_view sep = " · ";
    const auto first_sep = rest.find(sep);
    if (first_sep == std::string_view::npos) {
      if (!rest.empty())
        out.push_back({std::string{rest},
                       badge.ink == Ink::failure ? Ink::failure : Ink::heading});
      return out;
    }
    const auto name = rest.substr(0, first_sep);
    const auto tail = rest.substr(first_sep + sep.size());
    if (!name.empty())
      out.push_back(
          {std::string{name}, badge.ink == Ink::failure ? Ink::failure : Ink::heading});
    out.push_back({std::string{sep}, Ink::muted});
    const auto last_sep = tail.rfind(sep);
    if (last_sep != std::string_view::npos) {
      const auto arg = tail.substr(0, last_sep);
      const auto suffix = tail.substr(last_sep);
      if (!arg.empty())
        out.push_back({std::string{arg}, Ink::normal});
      out.push_back({std::string{suffix}, Ink::muted});
    } else if (!tail.empty()) {
      out.push_back({std::string{tail}, Ink::normal});
    }
    return out;
  }
  return {};
}
std::size_t valid_utf8_len(std::string_view text, std::size_t pos) {
  const auto b0 = static_cast<unsigned char>(text[pos]);
  auto is_cont = [&](std::size_t idx) {
    return idx < text.size() &&
           (static_cast<unsigned char>(text[idx]) & 0xc0U) == 0x80U;
  };
  if (b0 >= 0xc2 && b0 <= 0xdf)
    return is_cont(pos + 1) ? 2U : 0U;
  if (b0 >= 0xe0 && b0 <= 0xef) {
    if (!is_cont(pos + 1) || !is_cont(pos + 2))
      return 0U;
    const auto b1 = static_cast<unsigned char>(text[pos + 1]);
    if (b0 == 0xe0 && b1 < 0xa0)
      return 0U;
    if (b0 == 0xed && b1 >= 0xa0)
      return 0U;
    return 3U;
  }
  if (b0 >= 0xf0 && b0 <= 0xf4) {
    if (!is_cont(pos + 1) || !is_cont(pos + 2) || !is_cont(pos + 3))
      return 0U;
    const auto b1 = static_cast<unsigned char>(text[pos + 1]);
    if (b0 == 0xf0 && b1 < 0x90)
      return 0U;
    if (b0 == 0xf4 && b1 >= 0x90)
      return 0U;
    return 4U;
  }
  return 0U;
}
void skip_csi_payload(std::string_view text, std::size_t &i) {
  while (i < text.size()) {
    const auto c = static_cast<unsigned char>(text[i]);
    if (c >= 0x40 && c <= 0x7e)
      return;
    ++i;
  }
}
void skip_st_string_payload(std::string_view text, std::size_t &i) {
  while (i < text.size()) {
    const auto c = static_cast<unsigned char>(text[i]);
    if (c == 0x07 || c == 0x9c)
      return;
    if (c == 0x1b && i + 1 < text.size() && text[i + 1] == '\\') {
      ++i;
      return;
    }
    if (c == 0xc2 && i + 1 < text.size() &&
        static_cast<unsigned char>(text[i + 1]) == 0x9c) {
      ++i;
      return;
    }
    ++i;
  }
}
void skip_c1_control(std::string_view text, unsigned char code, std::size_t &i) {
  if (code == 0x9b) {
    ++i;
    skip_csi_payload(text, i);
  } else if (code == 0x9d || code == 0x9f || code == 0x90 || code == 0x9e ||
             code == 0x98) {
    ++i;
    skip_st_string_payload(text, i);
  }
}
std::string collapse_single_line(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  bool prev_space = true;
  for (std::size_t i = 0; i < text.size(); ++i) {
    const auto byte = static_cast<unsigned char>(text[i]);
    if (byte == '\n' || byte == '\r' || byte == '\t' || byte == ' ') {
      if (!prev_space) {
        out += ' ';
        prev_space = true;
      }
      continue;
    }
    if (byte < 0x20 || byte == 0x7f) {
      if (byte == 0x1b && i + 1 < text.size()) {
        const auto intro = static_cast<unsigned char>(text[i + 1]);
        if (intro == '[') {
          i += 2;
          skip_csi_payload(text, i);
        } else if (intro == ']' || intro == '_' || intro == 'P' || intro == '^' ||
                   intro == 'X') {
          i += 2;
          skip_st_string_payload(text, i);
        } else if (intro >= 0x20 && intro <= 0x7e) {
          ++i;
          while (i < text.size()) {
            const auto c = static_cast<unsigned char>(text[i]);
            if (c >= 0x20 && c <= 0x2f) {
              ++i;
              continue;
            }
            if (c >= 0x30 && c <= 0x7e)
              break;
            --i;
            break;
          }
        }
      }
      continue;
    }
    if (byte >= 0x80 && byte <= 0x9f) {
      skip_c1_control(text, byte, i);
      continue;
    }
    if (byte >= 0xc2 && byte <= 0xf4) {
      if (const std::size_t len = valid_utf8_len(text, i); len > 0) {
        if (len == 2 && byte == 0xc2) {
          const auto next = static_cast<unsigned char>(text[i + 1]);
          if (next >= 0x80 && next <= 0x9f) {
            ++i;
            skip_c1_control(text, next, i);
            continue;
          }
        }
        out.append(text.substr(i, len));
        i += len - 1;
        prev_space = false;
        continue;
      }
    }
    out += static_cast<char>(byte);
    prev_space = false;
  }
  while (!out.empty() && out.back() == ' ')
    out.pop_back();
  return out;
}
std::optional<std::string> parse_json_string_at(std::string_view src,
                                                std::size_t &pos) {
  if (pos >= src.size() || src[pos] != '"')
    return std::nullopt;
  ++pos;
  std::string out;
  while (pos < src.size()) {
    const char c = src[pos++];
    if (c == '"')
      return out;
    if (c == '\\') {
      if (pos >= src.size())
        return std::nullopt;
      const char esc = src[pos++];
      switch (esc) {
      case '"':
      case '\\':
      case '/':
        out += esc;
        break;
      case 'n':
      case 'r':
      case 't':
      case 'b':
      case 'f':
        out += ' ';
        break;
      case 'u': {
        if (pos + 4 > src.size())
          return std::nullopt;
        unsigned code = 0;
        for (std::size_t k = 0; k < 4; ++k) {
          const char h = src[pos + k];
          code <<= 4U;
          if (h >= '0' && h <= '9')
            code |= static_cast<unsigned>(h - '0');
          else if (h >= 'a' && h <= 'f')
            code |= static_cast<unsigned>(10 + h - 'a');
          else if (h >= 'A' && h <= 'F')
            code |= static_cast<unsigned>(10 + h - 'A');
          else
            return std::nullopt;
        }
        pos += 4;
        if (code == 0x1b || code == 0x07)
          out += static_cast<char>(code);
        else if (code >= 0x20 && code < 0x7f)
          out += static_cast<char>(code);
        else if (code < 0x20 || code == 0x7f)
          out += ' ';
        else if (code >= 0xd800 && code <= 0xdfff)
          utf8(out, U'\ufffd');
        else
          utf8(out, static_cast<char32_t>(code));
        break;
      }
      default:
        out += esc;
        break;
      }
    } else {
      out += c;
    }
  }
  return std::nullopt;
}
void skip_json_ws(std::string_view src, std::size_t &pos) {
  while (pos < src.size() &&
         (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\n' || src[pos] == '\r'))
    ++pos;
}
std::optional<std::vector<std::string>> parse_json_string_array(std::string_view src) {
  std::size_t pos = 0;
  skip_json_ws(src, pos);
  if (pos >= src.size() || src[pos] != '[')
    return std::nullopt;
  ++pos;
  std::vector<std::string> items;
  skip_json_ws(src, pos);
  if (pos < src.size() && src[pos] == ']') {
    ++pos;
    skip_json_ws(src, pos);
    return pos == src.size() ? std::optional{items} : std::nullopt;
  }
  while (pos < src.size()) {
    skip_json_ws(src, pos);
    auto item = parse_json_string_at(src, pos);
    if (!item)
      return std::nullopt;
    items.push_back(std::move(*item));
    skip_json_ws(src, pos);
    if (pos < src.size() && src[pos] == ',') {
      ++pos;
      continue;
    }
    if (pos < src.size() && src[pos] == ']') {
      ++pos;
      skip_json_ws(src, pos);
      return pos == src.size() ? std::optional{items} : std::nullopt;
    }
    return std::nullopt;
  }
  return std::nullopt;
}
bool is_shell_binary(std::string_view arg) {
  const auto slash = arg.rfind('/');
  const auto base = slash == std::string_view::npos ? arg : arg.substr(slash + 1);
  return base == "sh" || base == "bash" || base == "zsh" || base == "dash" ||
         base == "fish";
}
std::string compact_argv_items(const std::vector<std::string> &items) {
  if (items.empty())
    return {};
  if (items.size() == 3 && is_shell_binary(items[0]) &&
      (items[1] == "-c" || items[1] == "-lc"))
    return items[2];
  if (items.size() == 4 && (items[0] == "env" || items[0].ends_with("/env")) &&
      is_shell_binary(items[1]) && (items[2] == "-c" || items[2] == "-lc"))
    return items[3];
  std::string joined;
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i > 0)
      joined += ' ';
    joined += items[i];
  }
  return joined;
}
std::optional<std::string> skip_json_value_range(std::string_view src,
                                                 std::size_t &pos) {
  skip_json_ws(src, pos);
  if (pos >= src.size())
    return std::nullopt;
  const std::size_t start = pos;
  if (src[pos] == '"') {
    if (!parse_json_string_at(src, pos))
      return std::nullopt;
    return std::string{src.substr(start, pos - start)};
  }
  if (src[pos] == '[' || src[pos] == '{') {
    int depth = 0;
    while (pos < src.size()) {
      const char c = src[pos];
      if (c == '"') {
        if (!parse_json_string_at(src, pos))
          return std::nullopt;
        continue;
      }
      if (c == '[' || c == '{')
        ++depth;
      else if (c == ']' || c == '}') {
        --depth;
        ++pos;
        if (depth == 0)
          return std::string{src.substr(start, pos - start)};
        continue;
      }
      ++pos;
    }
    return std::nullopt;
  }
  while (pos < src.size() && src[pos] != ',' && src[pos] != '}' && src[pos] != ']' &&
         src[pos] != ' ' && src[pos] != '\t' && src[pos] != '\n' && src[pos] != '\r')
    ++pos;
  return std::string{src.substr(start, pos - start)};
}
std::optional<std::string> compact_json_object(std::string_view src) {
  std::size_t pos = 0;
  skip_json_ws(src, pos);
  if (pos >= src.size() || src[pos] != '{')
    return std::nullopt;
  ++pos;
  std::vector<std::pair<std::string, std::string>> entries;
  skip_json_ws(src, pos);
  if (pos < src.size() && src[pos] == '}') {
    ++pos;
    skip_json_ws(src, pos);
    return pos == src.size() ? std::optional{std::string{}} : std::nullopt;
  }
  bool closed = false;
  while (pos < src.size()) {
    skip_json_ws(src, pos);
    auto key = parse_json_string_at(src, pos);
    if (!key)
      return std::nullopt;
    skip_json_ws(src, pos);
    if (pos >= src.size() || src[pos] != ':')
      return std::nullopt;
    ++pos;
    auto val = skip_json_value_range(src, pos);
    if (!val)
      return std::nullopt;
    entries.emplace_back(std::move(*key), std::move(*val));
    skip_json_ws(src, pos);
    if (pos < src.size() && src[pos] == ',') {
      ++pos;
      continue;
    }
    if (pos < src.size() && src[pos] == '}') {
      ++pos;
      skip_json_ws(src, pos);
      if (pos != src.size())
        return std::nullopt;
      closed = true;
      break;
    }
    return std::nullopt;
  }
  if (!closed)
    return std::nullopt;
  constexpr std::array priority{"path",    "file", "command", "cmd",  "argv", "query",
                                "pattern", "url",  "id",      "name", "title"};
  for (const auto wanted : priority) {
    for (const auto &[k, raw_v] : entries) {
      if (k != wanted)
        continue;
      if (raw_v.starts_with("\"")) {
        std::size_t vpos = 0;
        if (auto s = parse_json_string_at(raw_v, vpos); s && vpos == raw_v.size())
          return *s;
      }
      if (raw_v.starts_with("[")) {
        if (auto arr = parse_json_string_array(raw_v))
          return compact_argv_items(*arr);
      }
      return raw_v;
    }
  }
  std::string summary;
  for (std::size_t i = 0; i < std::min<std::size_t>(entries.size(), 2); ++i) {
    if (i > 0)
      summary += ", ";
    std::string val = entries[i].second;
    if (val.starts_with("\"")) {
      std::size_t vpos = 0;
      if (auto s = parse_json_string_at(val, vpos); s && vpos == val.size())
        val = std::move(*s);
    }
    summary += entries[i].first + "=" + val;
  }
  return summary;
}
std::string truncate_compact_arg(std::string_view text) {
  constexpr std::size_t max_arg_cells = 120;
  const auto clean = collapse_single_line(text);
  if (display_cells(clean).value <= max_arg_cells)
    return clean;
  return clip_display_cells(clean, {max_arg_cells - 1}) + "…";
}
bool equal(const ChatGrid &a, const ChatGrid &b, std::size_t i) {
  const auto &x = a.cells[i], &y = b.cells[i];
  return x.scalar == y.scalar && x.ink == y.ink && x.width == y.width &&
         std::string_view{a.tails}.substr(x.tail, x.length) ==
             std::string_view{b.tails}.substr(y.tail, y.length);
}
} // namespace
std::string chat_plain(const ChatRow &row) {
  std::string text;
  for (const auto &s : row)
    text += s.text;
  return text;
}
std::string format_compact_tool_header(std::string_view raw_header) {
  constexpr std::string_view sep = " · ";
  std::string_view prefix;
  std::string_view arg;
  bool found = false;
  if (const auto sep_pos = raw_header.find(sep); sep_pos != std::string_view::npos) {
    prefix = raw_header.substr(0, sep_pos);
    arg = trim_ascii_spaces(raw_header.substr(sep_pos + sep.size()));
    found = true;
  } else {
    const auto brace = raw_header.find(" {");
    const auto bracket = raw_header.find(" [");
    const auto arg_pos = std::min(brace, bracket);
    if (arg_pos != std::string_view::npos) {
      prefix = raw_header.substr(0, arg_pos);
      arg = trim_ascii_spaces(raw_header.substr(arg_pos + 1));
      found = true;
    }
  }
  if (!found || arg.empty())
    return std::string{raw_header};
  std::optional<std::string> compact;
  if (arg.starts_with("\"") && arg.ends_with("\"")) {
    std::size_t pos = 0;
    if (auto s = parse_json_string_at(arg, pos); s && pos == arg.size())
      compact = std::move(*s);
  } else if (arg.starts_with("[") && arg.ends_with("]")) {
    if (auto items = parse_json_string_array(arg))
      compact = compact_argv_items(*items);
  } else if (arg.starts_with("{") && arg.ends_with("}")) {
    compact = compact_json_object(arg);
  }
  if (!compact)
    return std::string{raw_header};
  const auto clean_arg = truncate_compact_arg(*compact);
  if (clean_arg.empty())
    return std::string{prefix};
  return std::string{prefix} + std::string{sep} + clean_arg;
}
void ChatView::trim(RawControlToken *credit) {
  auto retire = [&](const Block &block, std::uint8_t reason, std::size_t offset,
                    std::size_t length) {
    (void)raw_ui_link(4032, block.identity,
                      std::array{detail::raw_native_field(reason),
                                 detail::raw_native_field(offset),
                                 detail::raw_native_field(length),
                                 detail::raw_native_field(generation_)},
                      credit);
  };
  // A front cut removes the head a fold measured from; display restarts plain.
  auto forget_fold = [](Block &block) {
    block.head_end = block.hidden = block.folded_bytes = 0;
    block.fence_parity = false;
  };
  bool removed = false;
  if (newlines_ > 2048 && !blocks_.empty()) {
    while (blocks_.size() > 1 && newlines_ > 1536) {
      newlines_ -= static_cast<std::size_t>(
          std::count(blocks_.front().text.begin(), blocks_.front().text.end(), '\n'));
      bytes_ -= blocks_.front().text.size();
      retire(blocks_.front(), 1, 0, blocks_.front().text.size());
      blocks_.pop_front();
      removed = true;
    }
    if (newlines_ > 2048) {
      auto &text = blocks_.front().text;
      std::size_t cut = 0;
      while (newlines_ > 1536) {
        cut = text.find('\n', cut) + 1;
        --newlines_;
      }
      retire(blocks_.front(), 2, 0, cut);
      text.erase(0, cut);
      forget_fold(blocks_.front());
      bytes_ = text.size();
      removed = true;
    }
  }
  while (blocks_.size() > 1 && (bytes_ > display_limit || blocks_.size() > 1024)) {
    bytes_ -= blocks_.front().text.size();
    newlines_ -= static_cast<std::size_t>(
        std::count(blocks_.front().text.begin(), blocks_.front().text.end(), '\n'));
    retire(blocks_.front(), 1, 0, blocks_.front().text.size());
    blocks_.pop_front();
    removed = true;
  }
  if (bytes_ > display_limit && !blocks_.empty()) {
    auto &s = blocks_.front().text;
    auto cut = s.size() - display_limit * 3 / 4;
    while (cut < s.size() && (static_cast<unsigned char>(s[cut]) & 0xc0) == 0x80)
      ++cut;
    newlines_ -= static_cast<std::size_t>(
        std::count(s.begin(), s.begin() + static_cast<std::ptrdiff_t>(cut), '\n'));
    retire(blocks_.front(), 2, 0, cut);
    s.erase(0, cut);
    forget_fold(blocks_.front());
    bytes_ = s.size();
    removed = true;
  }
  if (removed) {
    width_ = 0;
    ++generation_;
    clipped_ = true;
    dirty_ = true;
  }
}
void ChatView::append(ChatKind kind, std::string_view text, bool merge,
                      RawEventRef source) {
  const auto size = text.size();
  const auto ranges = raw_ui_add(1027, size / line_limit);
  // Ranges: 1025 block retirements, one prefix cut, line skips and one fold.
  const auto credit =
      raw_ui_add(raw_ui_multiply(raw_ui_add(ranges, 1), 65), raw_ui_error_bytes + 72);
  RawUiTrace trace{
      raw_capture_,
      {4030, 4033},
      std::array{detail::raw_native_field(kind), detail::raw_native_field(merge),
                 ByteView{source.lane}, detail::raw_native_field(source.ordinal),
                 detail::raw_native_field(size), detail::raw_string_field(text)},
      credit,
      true};
  trace.run([&] {
    try {
      if (!merge || blocks_.empty() || blocks_.back().kind != kind) {
        blocks_.push_back({kind, {}, true, 0, 0, 0, false, false, trace.reference()});
        ++serial_;
      }
      auto &block = blocks_.back();
      bool changed = block.dirty;
      std::optional<std::size_t> skipped;
      auto close_skip = [&](std::size_t end) {
        if (!skipped)
          return;
        const std::uint8_t reason = 4;
        const auto length = end - *skipped;
        (void)raw_ui_link(4032, trace.reference(),
                          std::array{detail::raw_native_field(reason),
                                     detail::raw_native_field(*skipped),
                                     detail::raw_native_field(length),
                                     detail::raw_native_field(generation_)},
                          trace.credit());
        skipped.reset();
      };
      for (std::size_t index = 0; index < text.size(); ++index) {
        const char c = text[index];
        if (c == '\n') {
          close_skip(index);
          block.text += c;
          ++bytes_;
          block.line_bytes = 0;
          ++newlines_;
          changed = true;
        } else if (block.line_bytes < line_limit ||
                   (block.line_bytes < line_limit + 4 &&
                    (static_cast<unsigned char>(c) & 0xc0) == 0x80)) {
          close_skip(index);
          block.text += c;
          ++bytes_;
          ++block.line_bytes;
          changed = true;
        } else {
          if (!skipped)
            skipped = index;
          if (!clipped_) {
            clipped_ = true;
            width_ = 0;
            changed = true;
          }
        }
      }
      close_skip(text.size());
      block.dirty = block.dirty || changed;
      dirty_ = dirty_ || changed;
      if (block.kind == ChatKind::tool && changed)
        fold(block, trace.credit());
      const auto identity = block.identity;
      const auto current = block.text.size();
      (void)trace.event(4031, std::array{ByteView{identity.lane},
                                         detail::raw_native_field(identity.ordinal),
                                         detail::raw_native_field(current)});
      trim(trace.credit());
      trace.close();
    } catch (...) {
      const auto count = blocks_.size();
      (void)trace.event(4073, std::array{detail::raw_native_field(count),
                                         detail::raw_native_field(bytes_),
                                         detail::raw_native_field(newlines_),
                                         detail::raw_native_field(generation_)});
      throw;
    }
  });
}
void ChatView::fold(Block &block, RawControlToken *credit) {
  constexpr std::size_t head_lines = 4, tail_lines = 3; // Header + 3, and 3.
  const std::string_view text{block.text};
  if (!block.head_end) {
    std::size_t end = 0;
    for (std::size_t n = 0; n < head_lines; ++n) {
      const auto lf = text.find('\n', end);
      if (lf == std::string_view::npos)
        return;
      end = lf + 1;
    }
    block.head_end = end;
  }
  // The tail is the last complete lines plus any unfinished one: it starts after
  // the (tail_lines + 1)th newline from the end. Only those bytes are scanned.
  std::size_t tail = text.size();
  for (std::size_t n = 0; n <= tail_lines; ++n) {
    if (tail <= block.head_end)
      return;
    const auto lf = text.rfind('\n', tail - 1);
    if (lf == std::string_view::npos || lf < block.head_end)
      return;
    tail = lf;
  }
  ++tail;
  const auto middle = text.substr(block.head_end, tail - block.head_end);
  const auto lines =
      static_cast<std::size_t>(std::count(middle.begin(), middle.end(), '\n'));
  // The elision row must stand for at least two lines the first time.
  if (lines < (block.hidden ? 1U : 2U))
    return;
  // Fences hidden in the middle still toggle code state for the tail.
  for (std::size_t at = 0; at < middle.size();) {
    if (middle.substr(at).starts_with("```"))
      block.fence_parity = !block.fence_parity;
    const auto lf = middle.find('\n', at);
    if (lf == std::string_view::npos)
      break;
    at = lf + 1;
  }
  // Coordinates are the block's display stream: bytes that entered block.text
  // (line-clipped bytes never do), with earlier folded ranges still counted.
  const std::uint8_t reason = 5;
  const auto offset = block.head_end + block.folded_bytes, length = middle.size();
  (void)raw_ui_link(4032, block.identity,
                    std::array{detail::raw_native_field(reason),
                               detail::raw_native_field(offset),
                               detail::raw_native_field(length),
                               detail::raw_native_field(generation_)},
                    credit);
  block.text.erase(block.head_end, length);
  block.hidden += lines;
  block.folded_bytes += length;
  bytes_ -= length;
  newlines_ -= lines;
  block.restart = block.dirty = dirty_ = true;
}
void ChatView::tool_start(std::string_view header, RawEventRef source) {
  const auto compact = format_compact_tool_header(header);
  append(ChatKind::tool, compact + "\n", false, source);
  tool_header_ = compact;
  tool_block_ = serial_;
}
void ChatView::tool_output(std::string_view text, RawEventRef source) {
  constexpr std::string_view background = "\n[command ";
  if (const auto close = text.find("]\n");
      text.starts_with(background) && close != std::string_view::npos) {
    const auto job = text.substr(background.size(), close - background.size());
    const auto body = text.substr(close + 2);
    if (!blocks_.empty() && serial_ == background_block_ && job == background_job_) {
      append(ChatKind::tool, body, true, source);
      return;
    }
    append(ChatKind::tool, "[command " + std::string{job} + "]\n" + std::string{body},
           false, source);
    background_job_ = job;
    background_block_ = serial_;
    return;
  }
  const auto marker = text.starts_with("\n[") ? text.substr(1) : text;
  if ((blocks_.empty() || serial_ != tool_block_) && !tool_header_.empty()) {
    append(ChatKind::tool, tool_header_ + "\n" + std::string{marker}, false, source);
    tool_block_ = serial_;
    return;
  }
  const bool line_start = blocks_.empty() || blocks_.back().text.empty() ||
                          blocks_.back().text.back() == '\n';
  append(ChatKind::tool, line_start ? marker : text, true, source);
}
void ChatView::tool_complete(std::string_view summary, Ink outcome,
                             RawEventRef source) {
  const bool failed = outcome == Ink::failure;
  if (!failed && tool_block_ != 0 && !blocks_.empty() && serial_ == tool_block_ &&
      blocks_.back().kind == ChatKind::tool && blocks_.back().text.starts_with("▸ ")) {
    auto &block = blocks_.back();
    const auto lf = block.text.find('\n');
    const auto header_end = lf == std::string::npos ? block.text.size() : lf;
    auto header = block.text.substr(0, header_end);
    constexpr std::string_view running_prefix = "▸ ";
    header.replace(0, running_prefix.size(), outcome == Ink::success ? "✓ " : "• ");
    std::string suffix;
    constexpr std::string_view dot_sep = " · ";
    if (const auto sep = summary.rfind(dot_sep); sep != std::string_view::npos) {
      const auto head = summary.substr(0, sep);
      const auto duration = summary.substr(sep + dot_sep.size());
      if (head.ends_with(" completed"))
        suffix = " · " + std::string{duration};
      else {
        const auto space = head.find(' ');
        const auto status =
            space == std::string_view::npos ? head : head.substr(space + 1);
        suffix = " · " + std::string{status} + " · " + std::string{duration};
      }
    } else if (!summary.empty()) {
      suffix = " · " + std::string{summary};
    }
    if (header.size() + suffix.size() <= line_limit)
      header += suffix;
    const auto old_len = header_end;
    const auto new_len = header.size();
    const bool fits_display =
        new_len <= old_len || bytes_ + (new_len - old_len) <= display_limit;
    if (fits_display) {
      block.text.replace(0, old_len, header);
      bytes_ = bytes_ - old_len + new_len;
      if (block.head_end)
        block.head_end = block.head_end - old_len + new_len;
      block.restart = block.dirty = dirty_ = true;
      tool_end();
      return;
    }
  }
  tool_end();
  append(failed ? ChatKind::error : ChatKind::tool,
         std::string{failed                    ? "✗ "
                     : outcome == Ink::success ? "✓ "
                                               : "• "} +
             std::string{summary},
         false, source);
}
std::string ChatView::last_text(ChatKind kind) const {
  for (auto it = blocks_.rbegin(); it != blocks_.rend(); ++it)
    if (it->kind == kind && !it->text.empty())
      return it->text;
  return {};
}
std::string ChatView::plain_transcript() const {
  std::string out;
  for (const auto &block : blocks_) {
    if (block.text.empty())
      continue;
    if (!out.empty() && out.back() != '\n')
      out += '\n';
    out += block.text;
  }
  return out;
}
void ChatView::begin(ChatKind kind) {
  stream_kind_ = kind;
  append(kind, {});
}
void ChatView::stream(std::string_view text) { append(stream_kind_, text, true); }
ChatView &ChatView::operator+=(std::string_view notice) {
  append(ChatKind::notice, notice, true);
  return *this;
}
void ChatView::clear() {
  const auto count = blocks_.size();
  RawUiTrace trace{raw_capture_,
                   {4034, 4033},
                   std::array{detail::raw_native_field(count),
                              detail::raw_native_field(bytes_),
                              detail::raw_native_field(generation_)},
                   raw_ui_add(raw_ui_multiply(count, 65), 40 + raw_ui_error_bytes)};
  const std::uint8_t reason = 3;
  const std::size_t offset = 0;
  for (const auto &block : blocks_) {
    const auto size = block.text.size();
    (void)raw_ui_link(4032, block.identity,
                      std::array{detail::raw_native_field(reason),
                                 detail::raw_native_field(offset),
                                 detail::raw_native_field(size),
                                 detail::raw_native_field(generation_)},
                      trace.credit());
  }
  blocks_.clear();
  rows_.clear();
  bytes_ = 0;
  newlines_ = 0;
  clipped_ = false;
  ++generation_;
  ++cleared_generation_;
  width_ = 0;
  dirty_ = true;
  trace.finish();
}
const std::vector<ChatRow> &ChatView::rows(std::size_t width) {
  width = std::max<std::size_t>(width, 8);
  if (width != width_) {
    rows_.clear();
    if (clipped_)
      rows_.push_back(
          {{"  Display clipped; full content remains in audit.", Ink::muted}});
    for (auto &b : blocks_) {
      b.dirty = true;
      b.initialized = false;
      b.committed = 0;
      b.in_code = false;
    }
    width_ = width;
    dirty_ = true;
  }
  if (!dirty_)
    return rows_;
  for (auto &b : blocks_) {
    if (!b.dirty)
      continue;
    ++reflows_;
    const auto rail = b.kind == ChatKind::user        ? Ink::user
                      : b.kind == ChatKind::error     ? Ink::failure
                      : b.kind == ChatKind::assistant ? Ink::assistant
                                                      : Ink::muted;
    // A fold changed text before the committed offset: redraw this (last) block.
    if (b.restart && b.initialized) {
      rows_.resize(b.first_row);
      b.initialized = b.in_code = false;
      b.committed = 0;
    }
    b.restart = false;
    if (!b.initialized) {
      b.first_row = rows_.size();
      if (!rows_.empty())
        rows_.push_back({});
      const auto label = b.kind == ChatKind::user        ? "YOU"
                         : b.kind == ChatKind::assistant ? "BLACKBIRD"
                         : b.kind == ChatKind::tool      ? "ACTIVITY"
                         : b.kind == ChatKind::error     ? "ERROR"
                         : b.kind == ChatKind::summary   ? "TURN"
                                                         : "";
      if (label[0])
        rows_.push_back({{"  " + std::string{label}, rail}});
      b.stable_rows = rows_.size();
      b.initialized = true;
    }
    rows_.resize(b.stable_rows);
    auto remaining = std::string_view{b.text}.substr(b.committed);
    while (!remaining.empty()) {
      const auto lf = remaining.find('\n');
      const auto length = lf == std::string_view::npos ? remaining.size() : lf;
      const auto raw = remaining.substr(0, length);
      const auto safe = terminal_lines(raw, display_limit).front();
      bool code = b.in_code;
      const auto registry = displayed_workflows();
      if (b.kind == ChatKind::assistant) {
        if (!code && looks_like_table_row(safe)) {
          if (lf == std::string_view::npos) {
            render_assistant_line(rows_, safe, width, rail, code);
            break;
          }
          const auto after_first = remaining.substr(length + 1);
          const auto lf2 = after_first.find('\n');
          const auto len2 = lf2 == std::string_view::npos ? after_first.size() : lf2;
          const auto safe2 =
              terminal_lines(after_first.substr(0, len2), display_limit).front();
          if (const auto aligns = parse_table_separator(safe2)) {
            std::vector<std::string> table_lines;
            table_lines.push_back(safe);
            table_lines.push_back(safe2);
            std::size_t consumed =
                length + 1 + len2 + (lf2 == std::string_view::npos ? 0U : 1U);
            bool finalized = false;
            std::optional<std::string> trailing_unfinished;
            if (lf2 != std::string_view::npos) {
              auto scan = after_first.substr(len2 + 1);
              bool last_had_lf = true;
              while (!scan.empty() && table_lines.size() < max_table_rows) {
                const auto nlf = scan.find('\n');
                const auto nlen = nlf == std::string_view::npos ? scan.size() : nlf;
                const auto nsafe =
                    terminal_lines(scan.substr(0, nlen), display_limit).front();
                if (!looks_like_table_row(nsafe)) {
                  if (nlf != std::string_view::npos)
                    finalized = true;
                  else
                    trailing_unfinished = nsafe;
                  break;
                }
                table_lines.push_back(nsafe);
                if (nlf == std::string_view::npos) {
                  consumed += nlen;
                  last_had_lf = false;
                  break;
                }
                consumed += nlen + 1;
                scan.remove_prefix(nlen + 1);
                last_had_lf = true;
              }
              if (table_lines.size() >= max_table_rows && last_had_lf)
                finalized = true;
            }
            render_markdown_table(rows_, table_lines, *aligns, {width - 4}, rail);
            if (!finalized) {
              if (trailing_unfinished)
                render_assistant_line(rows_, *trailing_unfinished, width, rail, code);
              break;
            }
            b.committed += consumed;
            b.stable_rows = rows_.size();
            b.in_code = code;
            remaining.remove_prefix(consumed);
            continue;
          }
          if (lf2 == std::string_view::npos &&
              (safe2.empty() || could_be_table_separator_prefix(safe2))) {
            render_assistant_line(rows_, safe, width, rail, code);
            if (!after_first.empty())
              render_assistant_line(rows_, safe2, width, rail, code);
            break;
          }
        }
        render_assistant_line(rows_, safe, width, rail, code);
      } else if (b.kind == ChatKind::user && registry) {
        wrap(rows_, terminal_powerword_lines(raw, display_limit).front(), width - 4,
             rail);
      } else if (safe.starts_with("```")) {
        if (!code)
          wrap(rows_, {{"─ " + safe.substr(3) + " ─", Ink::code}}, width - 4, rail);
        code = !code;
      } else if (code)
        wrap(rows_, syntax(safe), width - 4, rail);
      else if (safe.starts_with("#")) {
        const auto start = safe.find_first_not_of("# ");
        wrap(rows_,
             {{start == std::string::npos ? "" : safe.substr(start), Ink::heading}},
             std::min<std::size_t>(width - 4, 92), rail);
      } else if (b.kind == ChatKind::tool) {
        if (const auto styled_tool = style_tool_header_line(safe); !styled_tool.empty())
          wrap(rows_, styled_tool, std::min<std::size_t>(width - 4, 92), rail);
        else
          wrap(rows_, inline_text(safe, Ink::normal),
               std::min<std::size_t>(width - 4, 92), rail);
      } else
        wrap(rows_,
             inline_text(safe, b.kind == ChatKind::summary ? Ink::muted
                               : b.kind == ChatKind::error ? Ink::failure
                                                           : Ink::normal),
             std::min<std::size_t>(width - 4, 92), rail);
      if (lf == std::string_view::npos)
        break;
      b.committed += length + 1;
      if (b.hidden && b.committed == b.head_end) {
        wrap(rows_,
             {{"┆ " + std::to_string(b.hidden) + " more lines · Ctrl-O inspects",
               Ink::muted}},
             width - 4, rail);
        code = code != b.fence_parity;
      }
      b.stable_rows = rows_.size();
      b.in_code = code;
      remaining.remove_prefix(length + 1);
    }
    b.dirty = false;
  }
  dirty_ = false;
  return rows_;
}
void ChatGrid::reset(std::size_t columns, std::size_t rows) {
  if (!columns || !rows || columns > 4096 || rows > 4096 ||
      rows > 1024 * 1024 / columns)
    throw std::length_error("terminal geometry exceeds bounded grid");
  width = columns;
  height = rows;
  cells.resize(width * height);
  std::fill(cells.begin(), cells.end(), ChatCell{});
  tails.clear();
}
void ChatGrid::line(std::size_t row, const ChatRow &content, std::size_t column) {
  if (row >= height || column >= width)
    return;
  DisplayCursor cursor{content};
  DisplayCluster cluster;
  while (cursor.next(cluster)) {
    const auto cells_used = cluster.cells.value;
    if (!cells_used)
      continue;
    if (column + cells_used > width)
      return;
    const auto erase_footprint = [&](std::size_t x) {
      auto &old = cells[row * width + x];
      if (old.width == 0 && x > 0)
        cells[row * width + x - 1] = ChatCell{};
      if (old.width == 2 && x + 1 < width)
        cells[row * width + x + 1] = ChatCell{};
      old = ChatCell{};
    };
    erase_footprint(column);
    if (cells_used == 2)
      erase_footprint(column + 1);
    auto &cell = cells[row * width + column];
    cell.scalar = cluster.scalar;
    cell.ink = cluster.ink;
    cell.width = static_cast<std::uint8_t>(cells_used);
    cell.tail = static_cast<std::uint32_t>(tails.size());
    cursor.append(tails, cluster, true);
    cell.length = static_cast<std::uint16_t>(tails.size() - cell.tail);
    column += cells_used;
    if (cells_used == 2) {
      cells[row * width + column - 1] = ChatCell{};
      cells[row * width + column - 1].width = 0;
    }
  }
}
std::uint64_t raw_ui_owned_grid_bound(const ChatGrid &grid) {
  constexpr std::uint64_t max_color =
      sizeof("\x1b[0;38;2;188;168;239;48;2;37;40;51m") - 1;
  constexpr std::uint64_t digits = std::numeric_limits<std::size_t>::digits10 + 1;
  constexpr std::uint64_t mode_bytes =
      sizeof("\x1b[?2026h\x1b[?25l\x1b[0m\x1b[;H\x1b[?25h\x1b[?2026l") - 1;
  return raw_ui_add(
      raw_ui_add(raw_ui_multiply(grid.cells.size(), 4 + max_color), grid.tails.size()),
      raw_ui_add(raw_ui_multiply(grid.height, 4 + 2 * digits),
                 mode_bytes + 2 * digits + sizeof("\x1b[?7l\x1b[?7h\x1b[0m\x1b[2J") -
                     1));
}
const std::string &ChatPainter::prepare(const ChatGrid &next, std::size_t cursor_row,
                                        std::size_t cursor_column, bool full,
                                        ChatPaintPolicy policy) {
  if (!next.width || !next.height)
    throw std::logic_error("cannot paint an empty grid");
  packet_.clear();
  touched_ = 0;
  cursor_row = std::min(cursor_row, next.height - 1);
  cursor_column = std::min(cursor_column, next.width - 1);
  const bool all = full || policy == ChatPaintPolicy::full || !valid_ ||
                   previous_.width != next.width || previous_.height != next.height;
  for (std::size_t y = 0; y < next.height; ++y) {
    std::size_t first = next.width, last = 0;
    for (std::size_t x = 0; x < next.width; ++x)
      if (all || !equal(next, previous_, y * next.width + x)) {
        first = std::min(first, x);
        last = x + 1;
      }
    if (first == next.width)
      continue;
    if (first && (next.cells[y * next.width + first].width == 0 ||
                  (!all && previous_.cells[y * next.width + first].width == 0)))
      --first;
    if (last < next.width &&
        (next.cells[y * next.width + last].width == 0 ||
         (!all && previous_.cells[y * next.width + last].width == 0)))
      ++last;
    if (packet_.empty()) {
      packet_ = "\x1b[?2026h\x1b[?25l";
      if (policy == ChatPaintPolicy::full)
        packet_ += "\x1b[0m\x1b[2J";
    }
    std::size_t erase_from = next.width;
    if (policy == ChatPaintPolicy::erase) {
      auto tail = next.width;
      while (tail) {
        const auto &cell = next.cells[y * next.width + tail - 1];
        if (cell.scalar != U' ' || cell.length || cell.width != 1 ||
            cell.ink != Ink::normal)
          break;
        --tail;
      }
      if (last > tail)
        erase_from = std::max(first, tail);
    }
    packet_ += "\x1b[" + std::to_string(y + 1) + ";" + std::to_string(first + 1) + "H";
    Ink active = Ink::normal;
    bool styled = false;
    for (auto x = first; x < std::min(last, erase_from); ++x) {
      const auto &cell = next.cells[y * next.width + x];
      ++touched_;
      if (!cell.width)
        continue;
      if (!styled || active != cell.ink) {
        styled = true;
        packet_ += color(cell.ink);
        active = cell.ink;
      }
      const bool corner = policy == ChatPaintPolicy::corner && y + 1 == next.height &&
                          x + cell.width == next.width;
      if (corner)
        packet_ += "\x1b[?7l";
      utf8(packet_, cell.scalar);
      packet_.append(next.tails, cell.tail, cell.length);
      if (corner)
        packet_ += "\x1b[?7h";
    }
    if (erase_from < next.width) {
      packet_ += color(Ink::normal);
      packet_ += "\x1b[" + std::to_string(y + 1) + ";" +
                 std::to_string(erase_from + 1) + "H\x1b[K";
      touched_ += next.width - erase_from;
    }
  }
  if (!packet_.empty() || !valid_ || cursor_row != cursor_row_ ||
      cursor_column != cursor_column_) {
    if (packet_.empty())
      packet_ = "\x1b[?2026h";
    packet_ += "\x1b[0m\x1b[" + std::to_string(cursor_row + 1) + ";" +
               std::to_string(cursor_column + 1) + "H\x1b[?25h\x1b[?2026l";
  }
  prepared_row_ = cursor_row;
  prepared_column_ = cursor_column;
  return packet_;
}
void ChatPainter::commit(const ChatGrid &next) {
  previous_ = next;
  cursor_row_ = prepared_row_;
  cursor_column_ = prepared_column_;
  valid_ = true;
}
void ChatPainter::commit_swap(ChatGrid &next) noexcept {
  using std::swap;
  swap(previous_, next);
  cursor_row_ = prepared_row_;
  cursor_column_ = prepared_column_;
  valid_ = true;
}
ChatOutput::~ChatOutput() {
  owner_.require_cleanup_thread();
  detach();
}
void ChatOutput::detach() {
  RawUiOwnerBinding binding{owner_};
  if (raw_.terminal) {
    RawUiOwnerBinding packet_binding{raw_.owner};
    const std::uint8_t branch = 4;
    (void)raw_ui_link(
        4042, raw_.frame,
        std::array{detail::raw_native_field(branch), detail::raw_native_field(offset_)},
        &*raw_.terminal);
    raw_.terminal.reset();
  }
  if (descriptor_ >= 0) {
    const auto request = raw_ui_link(4047, attach_,
                                     std::array{detail::raw_native_field(descriptor_),
                                                detail::raw_native_field(flags_),
                                                detail::raw_native_field(offset_)},
                                     cleanup_ ? &*cleanup_ : nullptr);
    const int result = ::fcntl(descriptor_, F_SETFL, flags_);
    const int error = errno;
    const bool failed = result < 0;
    if (failed)
      (void)raw_ui_link(4061, request,
                        std::array{detail::raw_native_field(result),
                                   detail::raw_native_field(failed),
                                   detail::raw_native_field(error)},
                        cleanup_ ? &*cleanup_ : nullptr);
    else
      (void)raw_ui_link(4061, request,
                        std::array{detail::raw_native_field(result),
                                   detail::raw_native_field(failed)},
                        cleanup_ ? &*cleanup_ : nullptr);
    errno = error;
  }
  cleanup_.reset();
  descriptor_ = -1;
  packet_ = {};
  offset_ = 0;
}
void ChatOutput::attach(int descriptor) {
  if (descriptor_ >= 0)
    throw std::logic_error("output already attached");
  auto owner = RawUiOwner{raw_capture_};
  RawUiOwnerBinding binding{owner};
  RawUiTrace trace{raw_capture_,
                   {4046, 4062},
                   std::array{detail::raw_native_field(descriptor)},
                   378};
  trace.run([&] {
    auto native_flags = [&](int operation, int argument) {
      const auto request =
          trace.event(4060, std::array{detail::raw_native_field(descriptor),
                                       detail::raw_native_field(operation),
                                       detail::raw_native_field(argument)});
      const int result = ::fcntl(descriptor, operation, argument);
      const int error = errno;
      const bool failed = result < 0;
      if (failed)
        (void)raw_ui_link(4061, request,
                          std::array{detail::raw_native_field(result),
                                     detail::raw_native_field(failed),
                                     detail::raw_native_field(error)},
                          trace.credit());
      else
        (void)raw_ui_link(4061, request,
                          std::array{detail::raw_native_field(result),
                                     detail::raw_native_field(failed)},
                          trace.credit());
      errno = error;
      return result;
    };
    const int flags = native_flags(F_GETFL, 0);
    if (flags < 0 || native_flags(F_SETFL, flags | O_NONBLOCK) < 0)
      throw std::runtime_error("cannot configure terminal output");
    auto cleanup = trace.split(105);
    owner_ = std::move(owner);
    descriptor_ = descriptor;
    flags_ = flags;
    attach_ = trace.reference();
    cleanup_ = std::move(cleanup);
    trace.finish();
  });
}
void ChatOutput::start(std::string_view packet, RawUiPacket raw) {
  owner_.require_thread();
  RawUiOwnerBinding binding{raw.owner};
  if (pending())
    throw std::logic_error("cannot replace an in-flight terminal packet");
  if ((owner_.selected() || (raw_capture_ && raw_enabled())) && !raw.terminal)
    throw Error{ErrorCode::invalid_identity};
  packet_ = packet;
  offset_ = 0;
  raw_ = std::move(raw);
  if (raw_.terminal) {
    const std::uint8_t branch = 2;
    (void)raw_ui_link(
        4042, raw_.frame,
        std::array{detail::raw_native_field(branch), detail::raw_native_field(offset_)},
        &*raw_.terminal);
  }
}
bool ChatOutput::flush() {
  owner_.require_thread();
  RawUiOwnerBinding binding{raw_.owner};
  for (unsigned call = 0; pending() && call < 8; ++call) {
    auto credit = raw_ui_control(raw_capture_, 113);
    const auto requested = std::min<std::size_t>(packet_.size() - offset_, 8192);
    const auto request = raw_ui_link(4044, raw_.frame,
                                     std::array{detail::raw_native_field(descriptor_),
                                                detail::raw_native_field(offset_),
                                                detail::raw_native_field(requested)},
                                     credit ? &*credit : nullptr);
    const auto count = ::write(descriptor_, packet_.data() + offset_, requested);
    const int error = errno;
    const bool failed = count < 0;
    if (failed)
      (void)raw_ui_link(4045, request,
                        std::array{detail::raw_native_field(count),
                                   detail::raw_native_field(failed),
                                   detail::raw_native_field(error)},
                        credit ? &*credit : nullptr);
    else
      (void)raw_ui_link(
          4045, request,
          std::array{detail::raw_native_field(count), detail::raw_native_field(failed)},
          credit ? &*credit : nullptr);
    errno = error;
    if (count > 0)
      offset_ += static_cast<std::size_t>(count);
    else if (count < 0 && error == EINTR)
      continue;
    else if (count < 0 && (error == EAGAIN || error == EWOULDBLOCK))
      return false;
    else
      throw std::runtime_error("terminal output transport failed");
  }
  const bool complete = !pending();
  if (complete && raw_.terminal) {
    const std::uint8_t branch = 3;
    (void)raw_ui_link(
        4042, raw_.frame,
        std::array{detail::raw_native_field(branch), detail::raw_native_field(offset_)},
        &*raw_.terminal);
    raw_.terminal.reset();
  }
  return complete;
}
void ChatPresenter::require_idle() const {
  if (state_ != State::idle)
    throw std::logic_error("cannot replace a prepared or writing terminal frame");
}
ChatGrid &ChatPresenter::grid() {
  require_idle();
  return grid_;
}
std::string &ChatPresenter::prepare(std::size_t cursor_row, std::size_t cursor_column,
                                    bool full, ChatPaintPolicy policy) {
  require_idle();
  // Return the previous packet's capacity before constructing the next delta.
  packet_.swap(painter_.packet_);
  (void)painter_.prepare(grid_, cursor_row, cursor_column, full, policy);
  packet_.swap(painter_.packet_);
  staged_ = {grid_.height, grid_.width, std::min(cursor_row, grid_.height - 1),
             std::min(cursor_column, grid_.width - 1), false};
  state_ = State::prepared;
  return packet_;
}
std::string &ChatPresenter::prepare_tiny(std::size_t rows, std::size_t columns,
                                         std::size_t cursor_row,
                                         std::size_t cursor_column) {
  require_idle();
  if (!rows || !columns || cursor_row >= rows || cursor_column >= columns)
    throw std::logic_error("invalid tiny terminal geometry");
  packet_.clear();
  staged_ = {rows, columns, cursor_row, cursor_column, true};
  state_ = State::prepared;
  return packet_;
}
void ChatPresenter::start(RawUiPacket raw) {
  if (state_ != State::prepared || packet_.empty())
    throw std::logic_error("terminal frame is not prepared for output");
  output_.start(packet_, std::move(raw));
  state_ = State::writing;
}
bool ChatPresenter::flush() {
  if (state_ != State::writing)
    return false;
  try {
    if (!output_.flush())
      return false;
  } catch (...) {
    detach();
    throw;
  }
  if (staged_.tiny)
    painter_.invalidate();
  else
    painter_.commit_swap(grid_);
  committed_ = staged_;
  state_ = State::idle;
  return true;
}
void ChatPresenter::detach() {
  output_.detach();
  painter_.invalidate();
  committed_ = {};
  state_ = State::idle;
}
void ChatPresenter::abandon() {
  if (state_ == State::writing)
    detach();
  else
    state_ = State::idle;
}
} // namespace blackbird
