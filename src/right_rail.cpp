#include "blackbird/right_rail.hpp"

#include "blackbird/party_chat.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace blackbird {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kTabCount = 6;
constexpr std::size_t kMaxDocsDirEntries = 512;
constexpr std::size_t kSanitizeLimit = 512;

struct DecodedUtf8 {
  char32_t scalar = 0;
  std::size_t length = 0;
};

DecodedUtf8 decode_utf8_at(std::string_view text, std::size_t offset) noexcept {
  if (offset >= text.size())
    return {};
  const auto b0 = static_cast<unsigned char>(text[offset]);
  if (b0 < 0x80U)
    return {static_cast<char32_t>(b0), 1};
  if ((b0 & 0xe0U) == 0xc0U) {
    if (b0 < 0xc2U || offset + 1 >= text.size())
      return {};
    const auto b1 = static_cast<unsigned char>(text[offset + 1]);
    if ((b1 & 0xc0U) != 0x80U)
      return {};
    const char32_t cp =
        (static_cast<char32_t>(b0 & 0x1fU) << 6U) | static_cast<char32_t>(b1 & 0x3fU);
    return {cp, 2};
  }
  if ((b0 & 0xf0U) == 0xe0U) {
    if (offset + 2 >= text.size())
      return {};
    const auto b1 = static_cast<unsigned char>(text[offset + 1]);
    const auto b2 = static_cast<unsigned char>(text[offset + 2]);
    if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U)
      return {};
    if (b0 == 0xe0U && b1 < 0xa0U)
      return {};
    if (b0 == 0xedU && b1 >= 0xa0U)
      return {};
    const char32_t cp = (static_cast<char32_t>(b0 & 0x0fU) << 12U) |
                        (static_cast<char32_t>(b1 & 0x3fU) << 6U) |
                        static_cast<char32_t>(b2 & 0x3fU);
    return {cp, 3};
  }
  if ((b0 & 0xf8U) == 0xf0U) {
    if (b0 > 0xf4U || offset + 3 >= text.size())
      return {};
    const auto b1 = static_cast<unsigned char>(text[offset + 1]);
    const auto b2 = static_cast<unsigned char>(text[offset + 2]);
    const auto b3 = static_cast<unsigned char>(text[offset + 3]);
    if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U || (b3 & 0xc0U) != 0x80U)
      return {};
    if (b0 == 0xf0U && b1 < 0x90U)
      return {};
    if (b0 == 0xf4U && b1 >= 0x90U)
      return {};
    const char32_t cp = (static_cast<char32_t>(b0 & 0x07U) << 18U) |
                        (static_cast<char32_t>(b1 & 0x3fU) << 12U) |
                        (static_cast<char32_t>(b2 & 0x3fU) << 6U) |
                        static_cast<char32_t>(b3 & 0x3fU);
    return {cp, 4};
  }
  return {};
}

std::size_t scalar_cell_width(char32_t cp) noexcept {
  if (cp < 0x20U || (cp >= 0x7fU && cp <= 0x9fU))
    return 0;
  if ((cp >= 0x0300U && cp <= 0x036fU) || (cp >= 0x1ab0U && cp <= 0x1affU) ||
      (cp >= 0x1dc0U && cp <= 0x1dffU) || (cp >= 0x20d0U && cp <= 0x20ffU) ||
      (cp >= 0xfe00U && cp <= 0xfe0fU) || (cp >= 0xfe20U && cp <= 0xfe2fU) ||
      cp == 0x200bU || cp == 0x200cU || cp == 0x200dU) {
    return 0;
  }
  if ((cp >= 0x1100U && cp <= 0x115fU) || cp == 0x2329U || cp == 0x232aU ||
      (cp >= 0x2e80U && cp <= 0xa4cfU && cp != 0x303fU) ||
      (cp >= 0xac00U && cp <= 0xd7a3U) || (cp >= 0xf900U && cp <= 0xfaffU) ||
      (cp >= 0xfe10U && cp <= 0xfe19U) || (cp >= 0xfe30U && cp <= 0xfe6fU) ||
      (cp >= 0xff00U && cp <= 0xff60U) || (cp >= 0xffe0U && cp <= 0xffe6U) ||
      (cp >= 0x1f300U && cp <= 0x1faffU) || (cp >= 0x20000U && cp <= 0x3fffdU)) {
    return 2;
  }
  return 1;
}

std::size_t utf8_display_cells(std::string_view text) noexcept {
  std::size_t cells = 0;
  std::size_t i = 0;
  while (i < text.size()) {
    const DecodedUtf8 dec = decode_utf8_at(text, i);
    if (dec.length == 0) {
      ++i;
      continue;
    }
    cells += scalar_cell_width(dec.scalar);
    i += dec.length;
  }
  return cells;
}

std::string clip_to_cells(std::string_view sanitized, std::size_t max_cols) {
  if (max_cols == 0)
    return {};
  if (utf8_display_cells(sanitized) <= max_cols)
    return std::string{sanitized};

  const bool use_ellipsis = max_cols >= 4;
  const std::size_t budget = use_ellipsis ? (max_cols - 3) : max_cols;
  std::string out;
  out.reserve(std::min(sanitized.size(), max_cols + 4));
  std::size_t used = 0;
  std::size_t i = 0;
  while (i < sanitized.size()) {
    const DecodedUtf8 dec = decode_utf8_at(sanitized, i);
    if (dec.length == 0) {
      ++i;
      continue;
    }
    const std::size_t w = scalar_cell_width(dec.scalar);
    if (used + w > budget)
      break;
    out.append(sanitized.data() + i, dec.length);
    used += w;
    i += dec.length;
  }
  if (use_ellipsis)
    out += "...";
  return out;
}

std::string pad_to_cells(std::string_view sanitized, std::size_t width) {
  std::string out = clip_to_cells(sanitized, width);
  const std::size_t used = utf8_display_cells(out);
  if (used < width)
    out.append(width - used, ' ');
  return out;
}

std::string repeat_utf8(std::string_view glyph, std::size_t count) {
  std::string out;
  out.reserve(glyph.size() * count);
  for (std::size_t i = 0; i < count; ++i)
    out.append(glyph);
  return out;
}

std::string sanitize_field(std::string_view text) {
  return party_chat_sanitize(text, kSanitizeLimit);
}

char lower_ascii(char ch) noexcept {
  return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
}

std::string to_lower_ascii(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  for (const char ch : input)
    out.push_back(lower_ascii(ch));
  return out;
}

bool is_policy_locked_safe_action(std::string_view action) {
  const std::string lower = to_lower_ascii(action);
  static constexpr std::array<std::string_view, 10> kDisallowedKeywords{
      "allow", "approve", "grant", "permit",   "accept",
      "trust", "bypass",  "yes",   "escalate", "[y]",
  };
  for (const std::string_view kw : kDisallowedKeywords) {
    if (lower.find(kw) != std::string::npos)
      return false;
  }
  static constexpr std::array<std::string_view, 10> kAllowedDismissKeywords{
      "deny",    "dismiss", "close", "ack", "cancel",
      "decline", "reject",  "[d]",   "[n]", "[esc]",
  };
  for (const std::string_view kw : kAllowedDismissKeywords) {
    if (lower.find(kw) != std::string::npos)
      return true;
  }
  return false;
}

std::string format_compact_count(std::uint64_t count) {
  char buf[32]{};
  if (count >= 1'000'000'000ULL) {
    std::snprintf(buf, sizeof(buf), "%.1fB",
                  static_cast<double>(count) / 1'000'000'000.0);
    return std::string{buf};
  }
  if (count >= 1'000'000ULL) {
    std::snprintf(buf, sizeof(buf), "%.1fM", static_cast<double>(count) / 1'000'000.0);
    return std::string{buf};
  }
  if (count >= 1'000ULL) {
    std::snprintf(buf, sizeof(buf), "%.1fk", static_cast<double>(count) / 1'000.0);
    return std::string{buf};
  }
  return std::to_string(count);
}

std::string format_tok_per_sec(double rate) {
  if (!std::isfinite(rate) || rate < 0.0)
    return "--";
  char buf[32]{};
  if (rate >= 1000.0) {
    std::snprintf(buf, sizeof(buf), "%.0f", rate);
  } else {
    std::snprintf(buf, sizeof(buf), "%.1f", rate);
  }
  return std::string{buf};
}

std::string format_bytes_short(std::uint64_t bytes) {
  char buf[32]{};
  if (bytes >= 1024ULL * 1024ULL) {
    std::snprintf(buf, sizeof(buf), "%.1fM",
                  static_cast<double>(bytes) / (1024.0 * 1024.0));
    return std::string{buf};
  }
  if (bytes >= 1024ULL) {
    std::snprintf(buf, sizeof(buf), "%.1fK", static_cast<double>(bytes) / 1024.0);
    return std::string{buf};
  }
  return std::to_string(bytes) + "B";
}

std::string section_rule(std::string_view title, std::size_t width) {
  if (width == 0)
    return {};
  const std::string clean = sanitize_field(title);
  if (width <= 6)
    return clip_to_cells(clean, width);
  const std::string prefix = "── " + clean + " ";
  const std::size_t prefix_cells = utf8_display_cells(prefix);
  if (prefix_cells >= width)
    return clip_to_cells(prefix, width);
  return prefix + repeat_utf8("─", width - prefix_cells);
}

std::string framed_top(std::string_view title, std::size_t width) {
  if (width == 0)
    return {};
  if (width < 4)
    return repeat_utf8("━", width);
  const std::string clean = sanitize_field(title);
  const std::string label = " " + clean + " ";
  const std::size_t inner_max = width - 2;
  const std::string clipped = clip_to_cells(label, inner_max);
  const std::size_t used = utf8_display_cells(clipped);
  std::string out = "┏";
  if (used + 1 <= inner_max) {
    out += "━";
    out += clipped;
    out += repeat_utf8("━", inner_max - used - 1);
  } else {
    out += clipped;
    if (used < inner_max)
      out += repeat_utf8("━", inner_max - used);
  }
  out += "┓";
  return clip_to_cells(out, width);
}

std::string framed_row(std::string_view sanitized_text, std::size_t width) {
  if (width == 0)
    return {};
  if (width < 5)
    return clip_to_cells(sanitized_text, width);
  const std::size_t inner = width - 4;
  return "┃ " + pad_to_cells(sanitized_text, inner) + " ┃";
}

std::string framed_bottom(std::size_t width) {
  if (width == 0)
    return {};
  if (width < 2)
    return repeat_utf8("━", width);
  return "┗" + repeat_utf8("━", width - 2) + "┛";
}

std::vector<std::string> wrap_sanitized_words(std::string_view sanitized,
                                              std::size_t max_cols) {
  std::vector<std::string> out;
  if (max_cols == 0)
    return out;
  if (sanitized.empty()) {
    out.emplace_back();
    return out;
  }

  std::string cur;
  std::size_t cur_cells = 0;

  auto flush = [&]() {
    out.push_back(std::move(cur));
    cur.clear();
    cur_cells = 0;
  };

  auto push_long = [&](std::string_view token) {
    std::size_t pos = 0;
    while (pos < token.size()) {
      const DecodedUtf8 dec = decode_utf8_at(token, pos);
      if (dec.length == 0) {
        ++pos;
        continue;
      }
      const std::size_t w = scalar_cell_width(dec.scalar);
      if (w > max_cols && cur_cells == 0) {
        pos += dec.length;
        continue;
      }
      if (cur_cells + w > max_cols)
        flush();
      cur.append(token.data() + pos, dec.length);
      cur_cells += w;
      pos += dec.length;
    }
  };

  std::size_t i = 0;
  while (i < sanitized.size()) {
    while (i < sanitized.size() && sanitized[i] == ' ')
      ++i;
    if (i >= sanitized.size())
      break;
    const std::size_t start = i;
    while (i < sanitized.size() && sanitized[i] != ' ')
      ++i;
    const std::string_view word = sanitized.substr(start, i - start);
    const std::size_t w_cells = utf8_display_cells(word);
    if (cur_cells == 0) {
      if (w_cells <= max_cols) {
        cur.append(word);
        cur_cells = w_cells;
      } else {
        push_long(word);
      }
    } else if (cur_cells + 1 + w_cells <= max_cols) {
      cur.push_back(' ');
      cur.append(word);
      cur_cells += 1 + w_cells;
    } else {
      flush();
      if (w_cells <= max_cols) {
        cur.append(word);
        cur_cells = w_cells;
      } else {
        push_long(word);
      }
    }
  }
  if (!cur.empty() || out.empty())
    out.push_back(std::move(cur));
  return out;
}

bool lstat_regular_nofollow(const fs::path &path, std::uint64_t &size_out) noexcept {
  struct stat st{};
  if (::lstat(path.c_str(), &st) != 0)
    return false;
  if (S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode))
    return false;
  size_out = st.st_size > 0 ? static_cast<std::uint64_t>(st.st_size) : 0U;
  return true;
}

bool is_spec_markdown_name(std::string_view filename) {
  if (filename.size() < 4)
    return false;
  const std::string lower = to_lower_ascii(filename);
  if (!lower.ends_with(".md"))
    return false;
  return lower.find("spec") != std::string::npos;
}

struct ScopedDir {
  DIR *dir = nullptr;
  explicit ScopedDir(DIR *d) noexcept : dir(d) {}
  ScopedDir(const ScopedDir &) = delete;
  ScopedDir &operator=(const ScopedDir &) = delete;
  ~ScopedDir() {
    if (dir != nullptr)
      (void)::closedir(dir);
  }
};

std::string_view escalation_short_tag(RightRailEscalationKind kind) noexcept {
  switch (kind) {
  case RightRailEscalationKind::brakes_escalation:
    return "BRAKES";
  case RightRailEscalationKind::user_question:
    return "QUESTION";
  case RightRailEscalationKind::friend_request:
    return "FRIEND";
  case RightRailEscalationKind::lan_safety_number:
    return "LAN SAFETY";
  case RightRailEscalationKind::agent_escalation:
    return "AGENT";
  }
  return "ALERT";
}

void append_escalation_cards(std::vector<std::string> &body,
                             const std::vector<RightRailEscalation> &escalations,
                             std::size_t width) {
  if (escalations.empty()) {
    body.push_back(section_rule("ESCALATIONS", width));
    body.push_back(clip_to_cells("  (no pending escalations)", width));
    return;
  }

  for (std::size_t idx = 0; idx < escalations.size(); ++idx) {
    const auto &esc = escalations[idx];
    std::string top_title = "! ";
    top_title += escalation_short_tag(esc.kind);
    if (escalations.size() > 1) {
      top_title += " ";
      top_title += std::to_string(idx + 1);
      top_title += "/";
      top_title += std::to_string(escalations.size());
    }
    body.push_back(framed_top(top_title, width));

    const std::string title_clean = sanitize_field(esc.title);
    const std::size_t inner_w = width >= 5 ? (width - 4) : width;
    const auto title_lines = wrap_sanitized_words(
        title_clean.empty() ? std::string_view{"(untitled escalation)"}
                            : std::string_view{title_clean},
        inner_w);
    const std::size_t max_title_rows = std::min<std::size_t>(title_lines.size(), 2);
    for (std::size_t t = 0; t < max_title_rows; ++t)
      body.push_back(framed_row(title_lines[t], width));

    const std::string src_clean = sanitize_field(esc.source_label);
    const std::string id_clean = sanitize_field(esc.id);
    if (!src_clean.empty() || !id_clean.empty()) {
      std::string meta;
      if (!src_clean.empty())
        meta += src_clean;
      if (!id_clean.empty()) {
        if (!meta.empty())
          meta += " · ";
        meta += "#";
        meta += id_clean;
      }
      body.push_back(framed_row(meta, width));
    }

    const std::size_t detail_count =
        std::min(esc.detail_lines.size(), kRightRailMaxEscalationDetailLines);
    for (std::size_t d = 0; d < detail_count; ++d) {
      const std::string clean_detail = sanitize_field(esc.detail_lines[d]);
      body.push_back(framed_row(clean_detail, width));
    }

    if (esc.policy_locked) {
      body.push_back(framed_row("LOCKED: non-escalatable", width));
      std::string safe_actions;
      for (const auto &raw_act : esc.actions) {
        const std::string act = sanitize_field(raw_act);
        if (act.empty() || !is_policy_locked_safe_action(act))
          continue;
        if (!safe_actions.empty())
          safe_actions += "  ";
        safe_actions += act;
      }
      if (!safe_actions.empty()) {
        const auto act_lines = wrap_sanitized_words(safe_actions, inner_w);
        for (const auto &al : act_lines)
          body.push_back(framed_row(al, width));
      } else {
        body.push_back(framed_row("Policy denied (no allow)", width));
      }
    } else if (!esc.actions.empty()) {
      std::string joined;
      for (const auto &raw_act : esc.actions) {
        const std::string act = sanitize_field(raw_act);
        if (act.empty())
          continue;
        if (!joined.empty())
          joined += "  ";
        joined += act;
      }
      if (!joined.empty()) {
        const auto act_lines = wrap_sanitized_words(joined, inner_w);
        for (const auto &al : act_lines)
          body.push_back(framed_row(al, width));
      }
    }

    body.push_back(framed_bottom(width));
  }
}

void append_tokenomics_card(std::vector<std::string> &body,
                            const RightRailTokenomics &tok, std::size_t width) {
  const std::string badge = format_right_rail_brakes_badge(tok.brakes_profile);
  body.push_back(section_rule("TOKENOMICS", width));
  body.push_back(clip_to_cells("Brakes: [" + badge + "]", width));

  const std::string prov = sanitize_field(tok.provider);
  const std::string mod = sanitize_field(tok.model);
  const std::string eff = sanitize_field(tok.effort);
  if (!prov.empty() || !mod.empty() || !eff.empty()) {
    std::string identity;
    if (!prov.empty())
      identity += prov;
    if (!mod.empty()) {
      if (!identity.empty())
        identity += "/";
      identity += mod;
    }
    if (!eff.empty()) {
      if (!identity.empty())
        identity += " ";
      identity += "(" + eff + ")";
    }
    body.push_back(clip_to_cells(identity, width));
  }

  if (!tok.available) {
    body.push_back(clip_to_cells("Telemetry: unavailable", width));
    return;
  }

  const std::string spark =
      format_right_rail_sparkline(tok.throughput_samples, kRightRailSparklineSamples);
  const std::string rate_str =
      "Rate: " + format_tok_per_sec(tok.tok_per_sec) + " tok/s";
  const std::string combined_rate = rate_str + "  " + spark;
  if (utf8_display_cells(combined_rate) <= width) {
    body.push_back(combined_rate);
  } else {
    body.push_back(clip_to_cells(rate_str, width));
    body.push_back(clip_to_cells("Spark: " + spark, width));
  }

  const std::size_t bar_cells = width >= 26 ? 8U : 6U;
  body.push_back(clip_to_cells(
      "Cache: " + format_right_rail_bar(tok.cache_hit_ratio, bar_cells), width));
  body.push_back(clip_to_cells(
      "Ctx:   " + format_right_rail_bar(tok.context_fill_ratio, bar_cells), width));

  const std::string in_hit = "In " + format_compact_count(tok.input_tokens) +
                             " · Cache " + format_compact_count(tok.cached_tokens);
  const std::string out_rsn = "Out " + format_compact_count(tok.output_tokens) +
                              " · Rsn " + format_compact_count(tok.reasoning_tokens);
  body.push_back(clip_to_cells(in_hit, width));
  body.push_back(clip_to_cells(out_rsn, width));
}

void append_tasks_card(std::vector<std::string> &body,
                       const std::vector<RightRailTaskItem> &tasks, std::size_t width) {
  body.push_back(section_rule("TASKS (" + std::to_string(tasks.size()) + ")", width));
  if (tasks.empty()) {
    body.push_back(clip_to_cells("  (no tracked tasks)", width));
    return;
  }

  std::size_t active_n = 0;
  std::size_t open_n = 0;
  std::size_t blocked_n = 0;
  std::size_t done_n = 0;
  for (const auto &t : tasks) {
    switch (t.status) {
    case RightRailTaskStatus::active:
      ++active_n;
      break;
    case RightRailTaskStatus::open:
      ++open_n;
      break;
    case RightRailTaskStatus::done:
      ++done_n;
      break;
    case RightRailTaskStatus::blocked:
      ++blocked_n;
      break;
    }
  }
  const std::string counts =
      std::to_string(active_n) + " act · " + std::to_string(open_n) + " open · " +
      std::to_string(blocked_n) + " blk · " + std::to_string(done_n) + " done";
  body.push_back(clip_to_cells(counts, width));

  for (const auto &t : tasks) {
    std::string row;
    row += right_rail_task_status_glyph(t.status);
    row.push_back(' ');
    row += right_rail_task_source_badge(t.source);
    row.push_back(' ');
    const std::string title = sanitize_field(t.title);
    row += title.empty() ? "(untitled)" : title;
    const std::string owner = sanitize_field(t.owner);
    if (!owner.empty()) {
      row += " @";
      row += owner;
    }
    body.push_back(clip_to_cells(row, width));
  }
}

void append_anchors_card(std::vector<std::string> &body,
                         const std::vector<RightRailAnchor> &anchors,
                         std::size_t width) {
  body.push_back(
      section_rule("ANCHORS (" + std::to_string(anchors.size()) + ")", width));
  if (anchors.empty()) {
    body.push_back(clip_to_cells("  (no governing docs)", width));
    return;
  }

  static constexpr std::array<RightRailAnchorCategory, 4> kOrder{
      RightRailAnchorCategory::doctrine,
      RightRailAnchorCategory::design,
      RightRailAnchorCategory::plan,
      RightRailAnchorCategory::spec,
  };
  for (const RightRailAnchorCategory cat : kOrder) {
    bool emitted_heading = false;
    for (const auto &a : anchors) {
      if (a.category != cat)
        continue;
      if (!emitted_heading) {
        body.push_back(clip_to_cells(
            std::string{right_rail_anchor_category_name(cat)} + ":", width));
        emitted_heading = true;
      }
      const std::string path_clean = sanitize_field(a.rel_path);
      const std::string title_clean = sanitize_field(a.title);
      std::string line = "  ";
      line += !path_clean.empty() ? path_clean : title_clean;
      if (a.size_bytes > 0) {
        const std::string with_size =
            line + " (" + format_bytes_short(a.size_bytes) + ")";
        if (utf8_display_cells(with_size) <= width)
          line = with_size;
      }
      body.push_back(clip_to_cells(line, width));
    }
  }
}

void append_multiplayer_card(std::vector<std::string> &body,
                             const RightRailMultiplayer &mp, std::size_t width) {
  body.push_back(section_rule("PARTY & SWARM", width));

  std::string status_line = "Party: ";
  status_line += right_rail_party_transport_name(mp.transport);
  const std::string custom_status = sanitize_field(mp.party_status);
  if (!custom_status.empty()) {
    status_line += " (" + custom_status + ")";
  }
  const std::string scope = sanitize_field(mp.room_scope);
  if (!scope.empty()) {
    status_line += " · " + scope;
  }
  body.push_back(clip_to_cells(status_line, width));

  const std::string_view sn_badge = right_rail_safety_badge(mp.safety_status);
  const std::string sn_clean = sanitize_field(mp.safety_number);
  if (!sn_badge.empty() || !sn_clean.empty()) {
    std::string trust = "Trust: ";
    if (!sn_badge.empty())
      trust += sn_badge;
    if (!sn_clean.empty()) {
      if (!sn_badge.empty())
        trust.push_back(' ');
      trust += sn_clean;
    }
    body.push_back(clip_to_cells(trust, width));
  }

  std::string social = "Peers: " + std::to_string(mp.peer_count) +
                       " · Friends: " + std::to_string(mp.friends_online) + " on";
  if (mp.pending_friend_requests > 0) {
    social += " · " + std::to_string(mp.pending_friend_requests) + " req";
  }
  body.push_back(clip_to_cells(social, width));

  std::size_t working_n = 0;
  std::size_t waiting_n = 0;
  std::size_t stopped_n = 0;
  for (const auto &w : mp.swarm_workers) {
    switch (w.state) {
    case RightRailWorkerState::working:
      ++working_n;
      break;
    case RightRailWorkerState::waiting:
      ++waiting_n;
      break;
    case RightRailWorkerState::stopped:
      ++stopped_n;
      break;
    }
  }
  std::string swarm_summary = "Swarm: " + std::to_string(working_n) + " working · " +
                              std::to_string(waiting_n) + " waiting";
  if (stopped_n > 0)
    swarm_summary += " · " + std::to_string(stopped_n) + " stopped";
  body.push_back(clip_to_cells(swarm_summary, width));

  for (const auto &w : mp.swarm_workers) {
    std::string glyph = "·";
    if (w.state == RightRailWorkerState::working)
      glyph = "●";
    else if (w.state == RightRailWorkerState::waiting)
      glyph = "○";
    const std::string name = sanitize_field(w.name);
    const std::string task = sanitize_field(w.task_summary);
    std::string row = "  " + glyph + " " + (name.empty() ? "(worker)" : name) + " [" +
                      std::string{right_rail_worker_state_name(w.state)} + "]";
    if (!task.empty())
      row += " " + task;
    body.push_back(clip_to_cells(row, width));
  }

  const std::size_t conflict_total =
      std::max(mp.lease_conflicts, mp.lease_conflict_labels.size());
  if (conflict_total > 0) {
    body.push_back(
        clip_to_cells("! Lease conflicts: " + std::to_string(conflict_total), width));
    const std::size_t shown = std::min<std::size_t>(mp.lease_conflict_labels.size(), 4);
    for (std::size_t i = 0; i < shown; ++i) {
      body.push_back(
          clip_to_cells("  ! " + sanitize_field(mp.lease_conflict_labels[i]), width));
    }
  }
}

struct ChromeContext {
  RightRailTab active_tab = RightRailTab::auto_context;
  std::size_t esc_count = 0;
  std::size_t width = 0;
};

std::string build_tab_strip(ChromeContext ctx) {
  struct TabLabel {
    RightRailTab tab;
    std::string_view label;
  };
  static constexpr std::array<TabLabel, kTabCount> kTabs{{
      {RightRailTab::auto_context, "Auto"},
      {RightRailTab::escalations, "Esc"},
      {RightRailTab::tokenomics, "Tok"},
      {RightRailTab::tasks, "Tsk"},
      {RightRailTab::anchors, "Doc"},
      {RightRailTab::multiplayer, "MP"},
  }};

  std::string strip;
  for (std::size_t i = 0; i < kTabs.size(); ++i) {
    if (i > 0)
      strip.push_back(' ');
    std::string item{kTabs[i].label};
    if (kTabs[i].tab == RightRailTab::escalations && ctx.esc_count > 0)
      item += "!";
    if (kTabs[i].tab == ctx.active_tab) {
      strip += "[" + item + "]";
    } else {
      strip += item;
    }
  }
  return clip_to_cells(strip, ctx.width);
}

std::string build_header(ChromeContext ctx) {
  std::string out = "RAIL · ";
  if (ctx.active_tab == RightRailTab::auto_context) {
    if (ctx.esc_count > 0) {
      out += "! ESCALATION (" + std::to_string(ctx.esc_count) + ") · AUTO";
    } else {
      out += "AUTO";
    }
  } else if (ctx.active_tab == RightRailTab::escalations) {
    out += "ESCALATIONS (" + std::to_string(ctx.esc_count) + ")";
  } else if (ctx.active_tab == RightRailTab::tokenomics) {
    out += "TOKENOMICS";
    if (ctx.esc_count > 0)
      out += " [!" + std::to_string(ctx.esc_count) + "]";
  } else if (ctx.active_tab == RightRailTab::tasks) {
    out += "TASKS";
    if (ctx.esc_count > 0)
      out += " [!" + std::to_string(ctx.esc_count) + "]";
  } else if (ctx.active_tab == RightRailTab::anchors) {
    out += "ANCHORS";
    if (ctx.esc_count > 0)
      out += " [!" + std::to_string(ctx.esc_count) + "]";
  } else {
    out += "PARTY/SWARM";
    if (ctx.esc_count > 0)
      out += " [!" + std::to_string(ctx.esc_count) + "]";
  }
  return clip_to_cells(out, ctx.width);
}

} // namespace

// ---------------------------------------------------------------------------
// Name & badge helpers
// ---------------------------------------------------------------------------

std::string_view right_rail_tab_name(RightRailTab tab) noexcept {
  switch (tab) {
  case RightRailTab::auto_context:
    return "auto_context";
  case RightRailTab::escalations:
    return "escalations";
  case RightRailTab::tokenomics:
    return "tokenomics";
  case RightRailTab::tasks:
    return "tasks";
  case RightRailTab::anchors:
    return "anchors";
  case RightRailTab::multiplayer:
    return "multiplayer";
  }
  return "auto_context";
}

std::string_view right_rail_mode_name(RightRailMode mode) noexcept {
  switch (mode) {
  case RightRailMode::hidden:
    return "hidden";
  case RightRailMode::docked:
    return "docked";
  case RightRailMode::overlay:
    return "overlay";
  }
  return "hidden";
}

std::string_view
right_rail_escalation_kind_name(RightRailEscalationKind kind) noexcept {
  switch (kind) {
  case RightRailEscalationKind::brakes_escalation:
    return "brakes_escalation";
  case RightRailEscalationKind::user_question:
    return "user_question";
  case RightRailEscalationKind::friend_request:
    return "friend_request";
  case RightRailEscalationKind::lan_safety_number:
    return "lan_safety_number";
  case RightRailEscalationKind::agent_escalation:
    return "agent_escalation";
  }
  return "brakes_escalation";
}

std::string_view right_rail_brakes_badge(RightRailBrakesProfile profile) noexcept {
  switch (profile) {
  case RightRailBrakesProfile::black_flag:
    return "BLACK FLAG";
  case RightRailBrakesProfile::guarded:
    return "GUARDED";
  case RightRailBrakesProfile::sandboxed:
    return "SANDBOXED";
  case RightRailBrakesProfile::airgap:
    return "AIRGAP";
  }
  return "GUARDED";
}

std::string format_right_rail_brakes_badge(std::string_view profile) {
  const std::string clean = sanitize_field(profile);
  if (clean.empty())
    return "GUARDED";
  const std::string lower = to_lower_ascii(clean);
  if (lower == "black_flag" || lower == "black-flag" || lower == "black flag" ||
      lower == "blackflag" || lower == "none") {
    return "BLACK FLAG";
  }
  if (lower == "guarded")
    return "GUARDED";
  if (lower == "sandboxed" || lower == "sandbox")
    return "SANDBOXED";
  if (lower == "airgap" || lower == "air-gap" || lower == "air_gap" ||
      lower == "air gap") {
    return "AIRGAP";
  }
  return clean;
}

std::string_view right_rail_task_source_badge(RightRailTaskSource source) noexcept {
  switch (source) {
  case RightRailTaskSource::builtin:
    return "[BB]";
  case RightRailTaskSource::beads:
    return "[BD]";
  case RightRailTaskSource::issue:
    return "[IS]";
  case RightRailTaskSource::swarm:
    return "[SW]";
  case RightRailTaskSource::external:
    return "[EXT]";
  }
  return "[BB]";
}

std::string_view right_rail_task_status_glyph(RightRailTaskStatus status) noexcept {
  switch (status) {
  case RightRailTaskStatus::active:
    return "●";
  case RightRailTaskStatus::open:
    return "○";
  case RightRailTaskStatus::done:
    return "✓";
  case RightRailTaskStatus::blocked:
    return "!";
  }
  return "○";
}

std::string_view right_rail_anchor_category_name(RightRailAnchorCategory cat) noexcept {
  switch (cat) {
  case RightRailAnchorCategory::doctrine:
    return "doctrine";
  case RightRailAnchorCategory::design:
    return "design";
  case RightRailAnchorCategory::plan:
    return "plan";
  case RightRailAnchorCategory::spec:
    return "spec";
  }
  return "doctrine";
}

std::string_view
right_rail_party_transport_name(RightRailPartyTransport transport) noexcept {
  switch (transport) {
  case RightRailPartyTransport::offline:
    return "OFFLINE";
  case RightRailPartyTransport::lan:
    return "LAN";
  case RightRailPartyTransport::online:
    return "ONLINE";
  }
  return "OFFLINE";
}

std::string_view right_rail_safety_badge(RightRailSafetyStatus status) noexcept {
  switch (status) {
  case RightRailSafetyStatus::none:
    return "";
  case RightRailSafetyStatus::unverified:
    return "[SN UNVERIFIED]";
  case RightRailSafetyStatus::verified:
    return "[SN VERIFIED]";
  case RightRailSafetyStatus::mismatch:
    return "[SN MISMATCH!]";
  }
  return "";
}

std::string_view right_rail_worker_state_name(RightRailWorkerState state) noexcept {
  switch (state) {
  case RightRailWorkerState::working:
    return "working";
  case RightRailWorkerState::waiting:
    return "waiting";
  case RightRailWorkerState::stopped:
    return "stopped";
  }
  return "waiting";
}

// ---------------------------------------------------------------------------
// Auto-docking layout helper
// ---------------------------------------------------------------------------

RightRailLayout
compute_right_rail_layout(RightRailCols cols_arg, RightRailRows rows_arg,
                          RightRailUserOpen user_open_arg,
                          RightRailUserDismissed user_dismissed_arg) noexcept {
  const std::size_t cols = cols_arg.value;
  const std::size_t rows = rows_arg.value;
  const bool user_open = user_open_arg.value;
  const bool user_dismissed = user_dismissed_arg.value;

  RightRailLayout layout{};
  if (cols == 0 || rows == 0)
    return layout;

  if (cols >= kRightRailDockedMinCols) {
    if (user_dismissed) {
      layout.mode = RightRailMode::hidden;
      layout.main_width = cols;
      return layout;
    }
    const std::size_t scaled = (cols * 28U) / 100U;
    const std::size_t pane_w = std::clamp<std::size_t>(scaled, kRightRailDockedMinWidth,
                                                       kRightRailDockedMaxWidth);
    layout.mode = RightRailMode::docked;
    layout.visible = true;
    layout.docked = true;
    layout.overlay = false;
    layout.main_width = cols - pane_w - 2U;
    layout.col = layout.main_width + 2U;
    layout.row = 0;
    layout.width = pane_w;
    layout.height = rows;
    return layout;
  }

  if (!user_open) {
    layout.mode = RightRailMode::hidden;
    layout.main_width = cols;
    return layout;
  }

  const std::size_t margin_x = cols >= 24U ? 2U : 0U;
  const std::size_t margin_y = rows >= 12U ? 2U : (rows >= 8U ? 1U : 0U);
  const std::size_t avail_w = cols > 2U * margin_x ? cols - 2U * margin_x : cols;
  const std::size_t avail_h = rows > 2U * margin_y ? rows - 2U * margin_y : rows;
  const std::size_t pane_w =
      avail_w > kRightRailDockedMaxWidth ? kRightRailDockedMaxWidth : avail_w;

  layout.mode = RightRailMode::overlay;
  layout.visible = true;
  layout.docked = false;
  layout.overlay = true;
  layout.main_width = cols;
  layout.width = pane_w;
  layout.height = avail_h;
  layout.col = cols > pane_w + margin_x ? (cols - pane_w - margin_x)
                                        : (cols > pane_w ? cols - pane_w : 0U);
  layout.row = margin_y;
  return layout;
}

// ---------------------------------------------------------------------------
// Formatting helpers (bars & sparklines)
// ---------------------------------------------------------------------------

std::string format_right_rail_bar(double ratio, RightRailBarCells cells) {
  const std::size_t width = std::clamp<std::size_t>(cells.value, 1U, 32U);
  if (!std::isfinite(ratio))
    return "[" + repeat_utf8("░", width) + "] --%";
  const double clamped = std::clamp(ratio, 0.0, 1.0);
  const auto pct = static_cast<int>(std::lround(clamped * 100.0));
  const auto filled = std::min<std::size_t>(
      width,
      static_cast<std::size_t>(std::lround(clamped * static_cast<double>(width))));
  return "[" + repeat_utf8("█", filled) + repeat_utf8("░", width - filled) + "] " +
         std::to_string(pct) + "%";
}

std::string format_right_rail_sparkline(std::span<const double> samples,
                                        std::size_t width) {
  if (width == 0)
    return {};
  const std::size_t cap = std::min<std::size_t>(width, 64U);

  std::vector<double> finite;
  finite.reserve(std::min(samples.size(), cap));
  for (const double v : samples) {
    if (std::isfinite(v))
      finite.push_back(std::max(0.0, v));
  }

  if (finite.empty())
    return repeat_utf8("·", cap);

  const std::size_t start = finite.size() > cap ? (finite.size() - cap) : 0U;
  const std::span<const double> window{finite.data() + start, finite.size() - start};

  double min_v = window[0];
  double max_v = window[0];
  for (const double v : window) {
    min_v = std::min(min_v, v);
    max_v = std::max(max_v, v);
  }

  static constexpr std::array<std::string_view, 8> kGlyphs{
      "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█",
  };

  std::string out;
  out.reserve(cap * 3U);
  if (window.size() < cap)
    out += repeat_utf8("·", cap - window.size());

  const double span = max_v - min_v;
  for (const double v : window) {
    std::size_t idx = 0;
    if (span <= 1e-12) {
      idx = max_v > 0.0 ? 4U : 0U;
    } else {
      const double norm = std::clamp((v - min_v) / span, 0.0, 1.0);
      idx =
          std::min<std::size_t>(7U, static_cast<std::size_t>(std::lround(norm * 7.0)));
    }
    out += kGlyphs[idx];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Passive read-only repo anchor discovery
// ---------------------------------------------------------------------------

std::vector<RightRailAnchor> discover_repo_anchors(const fs::path &root) {
  std::vector<RightRailAnchor> anchors;
  if (root.empty())
    return anchors;

  struct stat root_st{};
  if (::lstat(root.c_str(), &root_st) != 0)
    return anchors;
  if (S_ISLNK(root_st.st_mode) || !S_ISDIR(root_st.st_mode))
    return anchors;

  auto try_add = [&](RightRailAnchorCategory cat, const fs::path &full_path,
                     std::string rel_path, std::string title) {
    std::uint64_t size = 0;
    if (!lstat_regular_nofollow(full_path, size))
      return;
    for (const auto &existing : anchors) {
      if (existing.rel_path == rel_path)
        return;
    }
    anchors.push_back(RightRailAnchor{
        .category = cat,
        .rel_path = std::move(rel_path),
        .title = std::move(title),
        .size_bytes = size,
    });
  };

  // Root-level doctrine files.
  static constexpr std::array<std::string_view, 3> kDoctrineFiles{
      "BLACKBIRD.md",
      "AGENTS.md",
      "CLAUDE.md",
  };
  for (const std::string_view name : kDoctrineFiles) {
    try_add(RightRailAnchorCategory::doctrine, root / name, std::string{name},
            std::string{name});
  }

  // Bounded immediate docs/ inspection (rejecting symlinked docs/ directory).
  const fs::path docs_dir = root / "docs";
  struct stat docs_st{};
  if (::lstat(docs_dir.c_str(), &docs_st) != 0)
    return anchors;
  if (S_ISLNK(docs_st.st_mode) || !S_ISDIR(docs_st.st_mode))
    return anchors;

  static constexpr std::array<std::string_view, 3> kDesignFiles{
      "CORE_DESIGN.md",
      "TUI_DOCTRINE.md",
      "INTERACTION_THEORY.md",
  };
  for (const std::string_view name : kDesignFiles) {
    try_add(RightRailAnchorCategory::design, docs_dir / name,
            "docs/" + std::string{name}, std::string{name});
  }

  static constexpr std::array<std::string_view, 3> kPlanFiles{
      "IMPLEMENTATION_PLAN.md",
      "TESTING_PLAN.md",
      "TUI_IMPLEMENTATION_PLAN.md",
  };
  for (const std::string_view name : kPlanFiles) {
    try_add(RightRailAnchorCategory::plan, docs_dir / name, "docs/" + std::string{name},
            std::string{name});
  }

  // Always probe canonical LAN_PARTY_SPEC.md directly in case docs/ exceeds scan cap.
  try_add(RightRailAnchorCategory::spec, docs_dir / "LAN_PARTY_SPEC.md",
          "docs/LAN_PARTY_SPEC.md", "LAN_PARTY_SPEC.md");

  // Discover immediate docs/*SPEC*.md (including docs/LAN_PARTY_SPEC.md) with
  // O_NOFOLLOW + fstatat(AT_SYMLINK_NOFOLLOW) so symlinks are never traversed.
  const int docs_fd =
      ::open(docs_dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (docs_fd < 0)
    return anchors;
  DIR *raw_dir = ::fdopendir(docs_fd);
  if (raw_dir == nullptr) {
    (void)::close(docs_fd);
    return anchors;
  }
  ScopedDir owned_dir{raw_dir};

  std::vector<std::pair<std::string, std::uint64_t>> spec_files;
  std::size_t scanned = 0;
  while (scanned < kMaxDocsDirEntries) {
    const struct dirent *ent = ::readdir(owned_dir.dir);
    if (ent == nullptr)
      break;
    ++scanned;
    const std::string_view name{ent->d_name};
    if (name == "." || name == "..")
      continue;
    if (!is_spec_markdown_name(name))
      continue;
    struct stat entry_st{};
    if (::fstatat(docs_fd, ent->d_name, &entry_st, AT_SYMLINK_NOFOLLOW) != 0)
      continue;
    if (S_ISLNK(entry_st.st_mode) || !S_ISREG(entry_st.st_mode))
      continue;
    const std::uint64_t sz =
        entry_st.st_size > 0 ? static_cast<std::uint64_t>(entry_st.st_size) : 0U;
    spec_files.emplace_back(std::string{name}, sz);
  }

  std::sort(spec_files.begin(), spec_files.end(),
            [](const auto &lhs, const auto &rhs) { return lhs.first < rhs.first; });
  for (const auto &[name, sz] : spec_files) {
    const std::string rel = "docs/" + name;
    bool dup = false;
    for (const auto &existing : anchors) {
      if (existing.rel_path == rel) {
        dup = true;
        break;
      }
    }
    if (!dup) {
      anchors.push_back(RightRailAnchor{
          .category = RightRailAnchorCategory::spec,
          .rel_path = rel,
          .title = name,
          .size_bytes = sz,
      });
    }
  }

  return anchors;
}

// ---------------------------------------------------------------------------
// RightRailMultiplayer / RightRailRenderFrame / RightRailPane
// ---------------------------------------------------------------------------

bool RightRailMultiplayer::is_active() const noexcept {
  return transport != RightRailPartyTransport::offline || !party_status.empty() ||
         !room_scope.empty() || safety_status != RightRailSafetyStatus::none ||
         !safety_number.empty() || peer_count > 0 || friends_online > 0 ||
         pending_friend_requests > 0 || !swarm_workers.empty() || lease_conflicts > 0 ||
         !lease_conflict_labels.empty();
}

std::string RightRailRenderFrame::text() const {
  std::string out;
  for (const auto &line : lines) {
    out += line;
    out.push_back('\n');
  }
  return out;
}

RightRailPane::RightRailPane(RightRailSnapshot snapshot)
    : snapshot_(std::move(snapshot)) {}

void RightRailPane::update(RightRailSnapshot snapshot) {
  snapshot_ = std::move(snapshot);
}

void RightRailPane::set_open(bool open) noexcept {
  open_ = open;
  dismissed_ = !open;
}

void RightRailPane::dismiss() noexcept {
  open_ = false;
  dismissed_ = true;
}

void RightRailPane::toggle() noexcept {
  if (open_) {
    open_ = false;
    dismissed_ = true;
  } else {
    open_ = true;
    dismissed_ = false;
  }
}

void RightRailPane::toggle_for_viewport(std::size_t cols) noexcept {
  const bool currently_visible = cols >= kRightRailDockedMinCols ? !dismissed_ : open_;
  if (currently_visible) {
    open_ = false;
    dismissed_ = true;
  } else {
    open_ = true;
    dismissed_ = false;
  }
}

void RightRailPane::pin_tab(RightRailTab tab) noexcept {
  pinned_tab_ = tab;
  scroll_offset_ = 0;
}

void RightRailPane::cycle_tab(int delta) noexcept {
  if (delta == 0)
    return;
  const int cur = static_cast<int>(pinned_tab_);
  const int count = static_cast<int>(kTabCount);
  int next = (cur + (delta % count) + count) % count;
  pinned_tab_ = static_cast<RightRailTab>(next);
  scroll_offset_ = 0;
}

void RightRailPane::scroll_up(std::size_t lines) noexcept {
  scroll_offset_ = lines >= scroll_offset_ ? 0U : (scroll_offset_ - lines);
}

void RightRailPane::scroll_down(std::size_t lines) noexcept {
  const std::size_t max_val = std::numeric_limits<std::size_t>::max();
  scroll_offset_ =
      lines > max_val - scroll_offset_ ? max_val : (scroll_offset_ + lines);
}

RightRailLayout RightRailPane::layout(RightRailCols cols,
                                      RightRailRows rows) const noexcept {
  return compute_right_rail_layout(cols, rows, open_, dismissed_);
}

RightRailRenderFrame RightRailPane::render(RightRailWidth width_arg,
                                           RightRailHeight height_arg) const {
  RightRailRenderFrame frame{};
  frame.active_tab = pinned_tab_;
  frame.has_priority_escalation = !snapshot_.escalations.empty();

  if (width_arg.value <= 0 || height_arg.value <= 0)
    return frame;

  const auto width = static_cast<std::size_t>(width_arg.value);
  const auto height = static_cast<std::size_t>(height_arg.value);
  const std::size_t esc_count = snapshot_.escalations.size();

  const ChromeContext chrome{
      .active_tab = pinned_tab_,
      .esc_count = esc_count,
      .width = width,
  };
  frame.header = build_header(chrome);

  std::vector<std::string> body;
  switch (pinned_tab_) {
  case RightRailTab::auto_context:
    if (!snapshot_.escalations.empty()) {
      append_escalation_cards(body, snapshot_.escalations, width);
    }
    append_tokenomics_card(body, snapshot_.tokenomics, width);
    append_tasks_card(body, snapshot_.tasks, width);
    if (snapshot_.multiplayer.is_active()) {
      append_multiplayer_card(body, snapshot_.multiplayer, width);
    }
    if (!snapshot_.anchors.empty()) {
      append_anchors_card(body, snapshot_.anchors, width);
    }
    break;
  case RightRailTab::escalations:
    append_escalation_cards(body, snapshot_.escalations, width);
    break;
  case RightRailTab::tokenomics:
    append_tokenomics_card(body, snapshot_.tokenomics, width);
    break;
  case RightRailTab::tasks:
    append_tasks_card(body, snapshot_.tasks, width);
    break;
  case RightRailTab::anchors:
    append_anchors_card(body, snapshot_.anchors, width);
    break;
  case RightRailTab::multiplayer:
    append_multiplayer_card(body, snapshot_.multiplayer, width);
    break;
  }

  frame.lines.reserve(height);
  frame.lines.push_back(pad_to_cells(frame.header, width));
  if (height == 1)
    return frame;

  if (height >= 3) {
    frame.lines.push_back(pad_to_cells(build_tab_strip(chrome), width));
  }
  if (height >= 4) {
    frame.lines.push_back(repeat_utf8("─", width));
  }

  const bool has_footer = height >= 5;
  const std::size_t chrome_rows = frame.lines.size() + (has_footer ? 1U : 0U);
  const std::size_t body_budget = height > chrome_rows ? (height - chrome_rows) : 0U;

  const std::size_t max_scroll =
      body.size() > body_budget ? (body.size() - body_budget) : 0U;
  const std::size_t effective_scroll = std::min(scroll_offset_, max_scroll);

  for (std::size_t r = 0; r < body_budget; ++r) {
    const std::size_t src_idx = effective_scroll + r;
    if (src_idx < body.size()) {
      frame.lines.push_back(pad_to_cells(body[src_idx], width));
    } else {
      frame.lines.emplace_back(width, ' ');
    }
  }

  if (has_footer) {
    std::string footer;
    if (max_scroll > 0) {
      footer = "↑↓ " + std::to_string(effective_scroll + 1) + "-" +
               std::to_string(std::min(body.size(), effective_scroll + body_budget)) +
               "/" + std::to_string(body.size()) + " · Tab:next";
    } else {
      footer = "Tab:cycle · Esc:close";
    }
    frame.lines.push_back(pad_to_cells(footer, width));
  }

  return frame;
}

} // namespace blackbird
