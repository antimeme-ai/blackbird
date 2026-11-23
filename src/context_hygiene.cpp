#include "blackbird/context_hygiene.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {
namespace {

constexpr std::size_t kMaxStubPreviewBytes = 120;
constexpr std::size_t kMaxIdentifierBytes = 64;

struct LineSpan {
  std::size_t offset = 0;
  std::size_t length = 0;
};

struct FooterMetrics {
  std::size_t omitted_lines = 0;
  std::size_t omitted_bytes = 0;
  std::size_t total_bytes = 0;
};

struct ByteSliceSpec {
  std::size_t budget = 0;
  bool from_tail = false;
};

bool is_utf8_continuation(unsigned char byte) noexcept {
  return (byte & 0xC0U) == 0x80U;
}

// Validates a single UTF-8 codepoint beginning at text[pos].
// Returns its byte length (1..4) if valid, or 0 if invalid.
std::size_t utf8_codepoint_length(std::string_view text, std::size_t pos) noexcept {
  if (pos >= text.size())
    return 0;
  const auto b0 = static_cast<unsigned char>(text[pos]);
  if (b0 <= 0x7FU)
    return 1;
  if (b0 >= 0xC2U && b0 <= 0xDFU) {
    if (pos + 1 >= text.size())
      return 0;
    const auto b1 = static_cast<unsigned char>(text[pos + 1]);
    return is_utf8_continuation(b1) ? 2 : 0;
  }
  if (b0 >= 0xE0U && b0 <= 0xEFU) {
    if (pos + 2 >= text.size())
      return 0;
    const auto b1 = static_cast<unsigned char>(text[pos + 1]);
    const auto b2 = static_cast<unsigned char>(text[pos + 2]);
    if (!is_utf8_continuation(b1) || !is_utf8_continuation(b2))
      return 0;
    if (b0 == 0xE0U && b1 < 0xA0U)
      return 0; // overlong
    if (b0 == 0xEDU && b1 >= 0xA0U)
      return 0; // UTF-16 surrogate
    return 3;
  }
  if (b0 >= 0xF0U && b0 <= 0xF4U) {
    if (pos + 3 >= text.size())
      return 0;
    const auto b1 = static_cast<unsigned char>(text[pos + 1]);
    const auto b2 = static_cast<unsigned char>(text[pos + 2]);
    const auto b3 = static_cast<unsigned char>(text[pos + 3]);
    if (!is_utf8_continuation(b1) || !is_utf8_continuation(b2) ||
        !is_utf8_continuation(b3))
      return 0;
    if (b0 == 0xF0U && b1 < 0x90U)
      return 0; // overlong
    if (b0 == 0xF4U && b1 > 0x8FU)
      return 0; // > U+10FFFF
    return 4;
  }
  return 0;
}

// Largest byte offset <= min(limit, text.size()) that never splits a valid
// UTF-8 codepoint.
std::size_t utf8_floor_boundary(std::string_view text, std::size_t limit) noexcept {
  const std::size_t clamped = std::min(limit, text.size());
  if (clamped == 0 || clamped == text.size())
    return clamped;
  if (!is_utf8_continuation(static_cast<unsigned char>(text[clamped])))
    return clamped;
  std::size_t lead = clamped;
  std::size_t back = 0;
  while (lead > 0 && back < 3 &&
         is_utf8_continuation(static_cast<unsigned char>(text[lead]))) {
    --lead;
    ++back;
  }
  const std::size_t cp_len = utf8_codepoint_length(text, lead);
  if (cp_len > 0 && lead + cp_len > clamped)
    return lead;
  return clamped;
}

// Smallest byte offset >= min(start, text.size()) that never starts inside a
// valid UTF-8 codepoint.
std::size_t utf8_ceil_boundary(std::string_view text, std::size_t start) noexcept {
  const std::size_t clamped = std::min(start, text.size());
  if (clamped == 0 || clamped == text.size())
    return clamped;
  if (!is_utf8_continuation(static_cast<unsigned char>(text[clamped])))
    return clamped;
  std::size_t lead = clamped;
  std::size_t back = 0;
  while (lead > 0 && back < 3 &&
         is_utf8_continuation(static_cast<unsigned char>(text[lead]))) {
    --lead;
    ++back;
  }
  const std::size_t cp_len = utf8_codepoint_length(text, lead);
  if (cp_len > 0 && lead + cp_len > clamped)
    return lead + cp_len;
  return clamped;
}

std::string_view slice_utf8_bounded(std::string_view text,
                                    ByteSliceSpec spec) noexcept {
  if (spec.budget >= text.size())
    return text;
  if (spec.budget == 0)
    return {};
  if (!spec.from_tail) {
    return text.substr(0, utf8_floor_boundary(text, spec.budget));
  }
  const std::size_t raw_start = text.size() - spec.budget;
  const std::size_t safe_start = utf8_ceil_boundary(text, raw_start);
  return text.substr(safe_start);
}

std::vector<LineSpan> split_lines(std::string_view text) {
  std::vector<LineSpan> lines;
  std::size_t pos = 0;
  while (pos < text.size()) {
    const std::size_t lf = text.find('\n', pos);
    if (lf == std::string_view::npos) {
      lines.push_back({pos, text.size() - pos});
      break;
    }
    lines.push_back({pos, lf - pos});
    pos = lf + 1;
  }
  return lines;
}

std::string_view line_text(std::string_view raw, LineSpan span) noexcept {
  return raw.substr(span.offset, span.length);
}

enum class DiagnosticTier : std::uint8_t { none = 0, warning = 1, error = 2 };

DiagnosticTier classify_diagnostic_line(std::string_view line) noexcept {
  static constexpr std::array<std::string_view, 10> kErrorPatterns = {
      "error:",
      "ERROR",
      "FAILED",
      "***Failed",
      "AssertionError",
      "AddressSanitizer",
      "UndefinedBehaviorSanitizer",
      "fatal:",
      "panic:",
      "Segmentation fault",
  };
  for (const auto pattern : kErrorPatterns) {
    if (line.find(pattern) != std::string_view::npos)
      return DiagnosticTier::error;
  }
  if (line.find("warning:") != std::string_view::npos)
    return DiagnosticTier::warning;
  return DiagnosticTier::none;
}

std::string format_projection_footer(FooterMetrics metrics,
                                     std::optional<std::uint64_t> audit_entry_id) {
  std::string footer;
  footer.reserve(160);
  footer += "[... omitted ";
  footer += std::to_string(metrics.omitted_lines);
  footer += " lines (";
  footer += std::to_string(metrics.omitted_bytes);
  footer += " bytes); full ";
  footer += std::to_string(metrics.total_bytes);
  footer += " bytes retained in audit";
  if (audit_entry_id.has_value()) {
    const std::string id_str = std::to_string(*audit_entry_id);
    footer += " #";
    footer += id_str;
    footer += " \xe2\x80\x94 use /restore ";
    footer += id_str;
    footer += " or audit_inspect for verbatim ...]";
  } else {
    footer += " \xe2\x80\x94 use audit_inspect for verbatim ...]";
  }
  return footer;
}

// Formats a single line to fit within max_bytes on a valid UTF-8 boundary.
std::string truncate_line_utf8(std::string_view line, std::size_t max_bytes) {
  if (line.size() <= max_bytes)
    return std::string{line};
  if (max_bytes <= 3)
    return std::string{
        slice_utf8_bounded(line, {.budget = max_bytes, .from_tail = false})};
  const std::string_view prefix =
      slice_utf8_bounded(line, {.budget = max_bytes - 3, .from_tail = false});
  std::string out;
  out.reserve(prefix.size() + 3);
  out.append(prefix);
  out.append("...");
  return out;
}

std::string truncate_tail_line_utf8(std::string_view line, std::size_t max_bytes) {
  if (line.size() <= max_bytes)
    return std::string{line};
  if (max_bytes <= 3)
    return std::string{
        slice_utf8_bounded(line, {.budget = max_bytes, .from_tail = true})};
  const std::string_view suffix =
      slice_utf8_bounded(line, {.budget = max_bytes - 3, .from_tail = true});
  std::string out;
  out.reserve(suffix.size() + 3);
  out.append("...");
  out.append(suffix);
  return out;
}

struct RenderedSection {
  std::vector<std::string> lines;
  std::size_t total_bytes = 0; // bytes including '\n' separators between lines
  std::size_t source_bytes = 0;
};

RenderedSection collect_forward_lines(std::string_view raw,
                                      const std::vector<LineSpan> &all_lines,
                                      const std::vector<std::size_t> &indices,
                                      std::size_t budget) {
  RenderedSection section;
  if (indices.empty() || budget == 0)
    return section;

  for (std::size_t idx_pos = 0; idx_pos < indices.size(); ++idx_pos) {
    const std::string_view line = line_text(raw, all_lines[indices[idx_pos]]);
    const std::size_t sep = section.lines.empty() ? 0 : 1;
    if (section.total_bytes + sep + line.size() <= budget) {
      section.lines.emplace_back(line);
      section.total_bytes += sep + line.size();
      section.source_bytes += line.size();
      continue;
    }
    const std::size_t remaining_budget =
        budget > section.total_bytes + sep ? budget - section.total_bytes - sep : 0;
    if (remaining_budget == 0)
      break;
    // Always preserve at least a bounded prefix of the first line in the section
    // or a per-slot slice when a single oversized line would otherwise drop entries.
    if (section.lines.empty() || remaining_budget >= 32) {
      const std::size_t remaining_count = indices.size() - idx_pos;
      const std::size_t slot =
          remaining_count > 1
              ? std::max<std::size_t>(32, remaining_budget / remaining_count)
              : remaining_budget;
      const std::size_t cap = std::min(remaining_budget, slot);
      std::string piece = truncate_line_utf8(line, cap);
      if (!piece.empty()) {
        section.total_bytes += sep + piece.size();
        section.source_bytes += std::min(line.size(), piece.size());
        section.lines.push_back(std::move(piece));
      }
    } else {
      break;
    }
  }
  return section;
}

RenderedSection collect_tail_lines(std::string_view raw,
                                   const std::vector<LineSpan> &all_lines,
                                   const std::vector<std::size_t> &indices,
                                   std::size_t budget) {
  RenderedSection section;
  if (indices.empty() || budget == 0)
    return section;

  for (std::size_t rev = indices.size(); rev > 0; --rev) {
    const std::string_view line = line_text(raw, all_lines[indices[rev - 1]]);
    const std::size_t sep = section.lines.empty() ? 0 : 1;
    if (section.total_bytes + sep + line.size() <= budget) {
      section.lines.emplace_back(line);
      section.total_bytes += sep + line.size();
      section.source_bytes += line.size();
      continue;
    }
    if (section.lines.empty()) {
      std::string piece = truncate_tail_line_utf8(line, budget);
      if (!piece.empty()) {
        section.total_bytes += piece.size();
        section.source_bytes += std::min(line.size(), piece.size());
        section.lines.push_back(std::move(piece));
      }
    }
    break;
  }
  std::reverse(section.lines.begin(), section.lines.end());
  return section;
}

std::size_t measure_indices_bytes(const std::vector<LineSpan> &all_lines,
                                  const std::vector<std::size_t> &indices) noexcept {
  std::size_t total = 0;
  for (std::size_t i = 0; i < indices.size(); ++i) {
    if (i > 0)
      ++total;
    total += all_lines[indices[i]].length;
  }
  return total;
}

struct ScaledUnit {
  std::uint64_t bytes = 0;
  std::uint64_t unit = 1;
  std::string_view suffix;
};

struct PercentArg {
  std::size_t value = 0;
  std::size_t pct = 0;
};

std::size_t percent_of(PercentArg arg) noexcept {
  return (arg.value / 100U) * arg.pct + ((arg.value % 100U) * arg.pct) / 100U;
}

std::string format_scaled_unit(ScaledUnit spec) {
  const std::uint64_t whole = spec.bytes / spec.unit;
  const std::uint64_t rem = spec.bytes % spec.unit;
  const std::uint64_t extra_tenths = (rem * 10ULL + spec.unit / 2ULL) / spec.unit;
  const std::uint64_t carry = extra_tenths / 10ULL;
  const std::uint64_t frac = extra_tenths % 10ULL;
  return std::to_string(whole + carry) + "." + std::to_string(frac) + " " +
         std::string{spec.suffix};
}

// Formats byte counts deterministically without locale dependencies or overflow.
std::string format_human_bytes(std::size_t bytes) {
  const auto n = static_cast<std::uint64_t>(bytes);
  constexpr std::uint64_t kKiB = 1024ULL;
  constexpr std::uint64_t kMiB = 1024ULL * 1024ULL;
  constexpr std::uint64_t kGiB = 1024ULL * 1024ULL * 1024ULL;
  if (n < kKiB)
    return std::to_string(n) + " B";
  if (n < kMiB)
    return format_scaled_unit({.bytes = n, .unit = kKiB, .suffix = "KiB"});
  if (n < kGiB)
    return format_scaled_unit({.bytes = n, .unit = kMiB, .suffix = "MiB"});
  return format_scaled_unit({.bytes = n, .unit = kGiB, .suffix = "GiB"});
}

// Advances past a CSI parameter/intermediate body through its final byte (0x40..0x7E).
std::size_t skip_csi_body(std::string_view text, std::size_t pos) noexcept {
  while (pos < text.size()) {
    const auto c = static_cast<unsigned char>(text[pos]);
    ++pos;
    if (c >= 0x40U && c <= 0x7EU)
      break;
  }
  return pos;
}

// Advances past an OSC/APC/DCS/PM/SOS payload terminated by BEL, 7-bit ST (ESC \),
// 8-bit ST (0x9C), or UTF-8 ST (0xC2 0x9C).
std::size_t skip_st_string_body(std::string_view text, std::size_t pos) noexcept {
  while (pos < text.size()) {
    const auto c = static_cast<unsigned char>(text[pos]);
    if (c == 0x07U || c == 0x9CU) {
      return pos + 1;
    }
    if (c == 0x1BU && pos + 1 < text.size() && text[pos + 1] == '\\') {
      return pos + 2;
    }
    if (c == 0xC2U && pos + 1 < text.size() &&
        static_cast<unsigned char>(text[pos + 1]) == 0x9CU) {
      return pos + 2;
    }
    ++pos;
  }
  return pos;
}

std::uint32_t decode_utf8_scalar(std::string_view text, std::size_t pos) noexcept {
  const std::size_t len = utf8_codepoint_length(text, pos);
  if (len == 1)
    return static_cast<unsigned char>(text[pos]);
  if (len == 2) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(text[pos]) & 0x1FU)
            << 6U) |
           static_cast<std::uint32_t>(static_cast<unsigned char>(text[pos + 1]) &
                                      0x3FU);
  }
  if (len == 3) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(text[pos]) & 0x0FU)
            << 12U) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(text[pos + 1]) &
                                       0x3FU)
            << 6U) |
           static_cast<std::uint32_t>(static_cast<unsigned char>(text[pos + 2]) &
                                      0x3FU);
  }
  if (len == 4) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(text[pos]) & 0x07U)
            << 18U) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(text[pos + 1]) &
                                       0x3FU)
            << 12U) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(text[pos + 2]) &
                                       0x3FU)
            << 6U) |
           static_cast<std::uint32_t>(static_cast<unsigned char>(text[pos + 3]) &
                                      0x3FU);
  }
  return 0;
}

bool is_disallowed_bidi_or_format(std::uint32_t cp) noexcept {
  return cp == 0x061CU || cp == 0x200EU || cp == 0x200FU ||
         (cp >= 0x202AU && cp <= 0x202EU) || (cp >= 0x2066U && cp <= 0x2069U) ||
         cp == 0xFEFFU;
}

// Strips 7-bit ESC/CSI/OSC/APC/DCS/PM/SOS, 8-bit C1, UTF-8 C1, C0/DEL control
// characters, and Unicode BiDi overrides/isolates while collapsing whitespace
// to single spaces and preserving valid UTF-8 codepoints.
std::string sanitize_one_line(std::string_view text, std::size_t max_bytes) {
  std::string out;
  out.reserve(std::min(text.size(), max_bytes + 3));
  bool prev_space = false;
  bool truncated = false;

  std::size_t i = 0;
  while (i < text.size()) {
    const auto b = static_cast<unsigned char>(text[i]);

    // 7-bit ESC sequences.
    if (b == 0x1BU) {
      ++i;
      if (i >= text.size())
        break;
      const char next = text[i];
      if (next == '[') {
        i = skip_csi_body(text, i + 1);
      } else if (next == ']' || next == '_' || next == 'P' || next == '^' ||
                 next == 'X') {
        i = skip_st_string_body(text, i + 1);
      } else {
        // 2-byte or nF escape sequence (intermediate 0x20..0x2F, final 0x30..0x7E).
        while (i < text.size()) {
          const auto c = static_cast<unsigned char>(text[i]);
          ++i;
          if (c < 0x20U || c > 0x2FU)
            break;
        }
      }
      continue;
    }

    // 8-bit C1 control sequences (CSI, OSC, APC, DCS, PM, SOS, or other C1).
    if (b >= 0x80U && b <= 0x9FU) {
      if (b == 0x9BU) {
        i = skip_csi_body(text, i + 1);
      } else if (b == 0x9DU || b == 0x9FU || b == 0x90U || b == 0x9EU || b == 0x98U) {
        i = skip_st_string_body(text, i + 1);
      } else {
        ++i;
      }
      continue;
    }

    if (b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' || b == '\v') {
      if (!prev_space && !out.empty()) {
        if (out.size() + 1 > max_bytes) {
          truncated = true;
          break;
        }
        out.push_back(' ');
      }
      prev_space = true;
      ++i;
      continue;
    }

    if (b < 0x20U || b == 0x7FU) {
      ++i;
      continue;
    }

    const std::size_t cp_len = utf8_codepoint_length(text, i);
    if (cp_len == 0) {
      // Skip invalid UTF-8 byte.
      ++i;
      continue;
    }

    // UTF-8 encoded C1 controls U+0080..U+009F (0xC2 0x80..0x9F).
    if (cp_len == 2 && b == 0xC2U) {
      const auto c1 = static_cast<unsigned char>(text[i + 1]);
      if (c1 <= 0x9FU) {
        if (c1 == 0x9BU) {
          i = skip_csi_body(text, i + 2);
        } else if (c1 == 0x9DU || c1 == 0x9FU || c1 == 0x90U || c1 == 0x9EU ||
                   c1 == 0x98U) {
          i = skip_st_string_body(text, i + 2);
        } else {
          i += 2;
        }
        continue;
      }
    }

    if (cp_len >= 2 && is_disallowed_bidi_or_format(decode_utf8_scalar(text, i))) {
      i += cp_len;
      continue;
    }

    if (out.size() + cp_len > max_bytes) {
      truncated = true;
      break;
    }
    out.append(text.data() + i, cp_len);
    prev_space = false;
    i += cp_len;
  }

  while (!out.empty() && out.back() == ' ')
    out.pop_back();

  if (truncated && max_bytes >= 3) {
    if (out.size() + 3 > max_bytes) {
      const std::size_t cut = utf8_floor_boundary(out, max_bytes - 3);
      out.resize(cut);
      while (!out.empty() && out.back() == ' ')
        out.pop_back();
    }
    out.append("...");
  }
  return out;
}

bool is_tool_result_kind(std::string_view kind) noexcept {
  return kind == "tool_result" || kind == "function_call_output";
}

// Parses a positive uint64_t block ID from entry_id (accepts "42", "#42", or "b42").
std::optional<std::uint64_t>
parse_context_block_id(std::string_view entry_id) noexcept {
  if (entry_id.empty())
    return std::nullopt;
  if (entry_id.front() == '#' || entry_id.front() == 'b')
    entry_id.remove_prefix(1);
  if (entry_id.empty())
    return std::nullopt;
  std::uint64_t id = 0;
  const auto *begin = entry_id.data();
  const auto *end = entry_id.data() + entry_id.size();
  const auto res = std::from_chars(begin, end, id);
  if (res.ec != std::errc{} || res.ptr != end || id == 0)
    return std::nullopt;
  return id;
}

} // namespace

ToolProjectionResult
project_tool_output_for_context(const ToolProjectionInput &input,
                                const ToolProjectionPolicy &policy) {
  const std::string_view raw = input.raw_output;
  const std::vector<LineSpan> lines = split_lines(raw);

  ToolProjectionResult result;
  result.original_bytes = raw.size();
  result.original_lines = lines.size();

  if (raw.size() <= policy.max_inline_bytes &&
      lines.size() <= policy.max_inline_lines) {
    result.projected_text = input.raw_output;
    result.was_compacted = false;
    result.projected_bytes = result.projected_text.size();
    result.diagnostic_lines_extracted = 0;
    return result;
  }

  result.was_compacted = true;
  const std::size_t hard_ceiling =
      policy.max_inline_bytes > std::numeric_limits<std::size_t>::max() -
                                    kToolProjectionFooterHeadroomBytes
          ? std::numeric_limits<std::size_t>::max()
          : policy.max_inline_bytes + kToolProjectionFooterHeadroomBytes;

  // Single-line huge blob (e.g. minified JSON): UTF-8-safe head + tail byte slicing.
  if (lines.size() <= 1) {
    const std::size_t payload_budget = policy.max_inline_bytes;
    const std::size_t head_budget = payload_budget / 2;
    const std::size_t tail_budget = payload_budget - head_budget;

    const std::size_t head_end = utf8_floor_boundary(raw, head_budget);
    const std::size_t raw_tail_start =
        raw.size() > tail_budget ? raw.size() - tail_budget : 0;
    const std::size_t tail_start =
        std::max(head_end, utf8_ceil_boundary(raw, raw_tail_start));

    const std::string_view head_slice = raw.substr(0, head_end);
    const std::string_view tail_slice = raw.substr(tail_start);
    const std::size_t omitted_bytes = tail_start > head_end ? tail_start - head_end : 0;

    const std::string footer = format_projection_footer(
        {.omitted_lines = 0, .omitted_bytes = omitted_bytes, .total_bytes = raw.size()},
        input.audit_entry_id);

    std::string out;
    out.reserve(head_slice.size() + tail_slice.size() + footer.size() + 2);
    if (!head_slice.empty()) {
      out.append(head_slice);
      out.push_back('\n');
    }
    out.append(footer);
    if (!tail_slice.empty()) {
      out.push_back('\n');
      out.append(tail_slice);
    }
    if (out.size() > hard_ceiling)
      out.resize(utf8_floor_boundary(out, hard_ceiling));

    result.projected_text = std::move(out);
    result.projected_bytes = result.projected_text.size();
    result.diagnostic_lines_extracted = 0;
    return result;
  }

  // Multi-line output: select disjoint head, middle diagnostic, and tail indices.
  const std::size_t total_lines = lines.size();
  const std::size_t head_end = std::min(policy.head_lines, total_lines);
  const std::size_t raw_tail_start =
      total_lines > policy.tail_lines ? total_lines - policy.tail_lines : 0;
  const std::size_t tail_start = std::max(head_end, raw_tail_start);

  std::vector<std::size_t> head_indices;
  head_indices.reserve(head_end);
  for (std::size_t i = 0; i < head_end; ++i)
    head_indices.push_back(i);

  std::vector<std::size_t> tail_indices;
  tail_indices.reserve(total_lines - tail_start);
  for (std::size_t i = tail_start; i < total_lines; ++i)
    tail_indices.push_back(i);

  // Extract deduplicated middle diagnostics: prioritize errors/failures over warnings.
  std::vector<std::size_t> diag_indices;
  if (policy.max_diagnostic_lines > 0 && head_end < tail_start) {
    std::vector<std::size_t> warning_candidates;
    for (std::size_t i = head_end; i < tail_start; ++i) {
      const DiagnosticTier tier = classify_diagnostic_line(line_text(raw, lines[i]));
      if (tier == DiagnosticTier::error) {
        if (diag_indices.size() < policy.max_diagnostic_lines)
          diag_indices.push_back(i);
      } else if (tier == DiagnosticTier::warning) {
        if (warning_candidates.size() < policy.max_diagnostic_lines)
          warning_candidates.push_back(i);
      }
    }
    for (const std::size_t warn_idx : warning_candidates) {
      if (diag_indices.size() >= policy.max_diagnostic_lines)
        break;
      diag_indices.push_back(warn_idx);
    }
    std::sort(diag_indices.begin(), diag_indices.end());
  }

  // Budget allocation across head, diagnostics, and tail so payload <=
  // max_inline_bytes.
  const std::size_t payload_budget = policy.max_inline_bytes;
  const std::size_t head_need = measure_indices_bytes(lines, head_indices);
  const std::size_t diag_need = measure_indices_bytes(lines, diag_indices);
  const std::size_t tail_need = measure_indices_bytes(lines, tail_indices);

  std::size_t head_budget = head_need;
  std::size_t diag_budget = diag_need;
  std::size_t tail_budget = tail_need;

  if (head_need + diag_need + tail_need > payload_budget) {
    std::size_t remaining = payload_budget;
    if (!diag_indices.empty()) {
      const std::size_t diag_share = percent_of({.value = payload_budget, .pct = 35U});
      diag_budget = std::min(diag_need, diag_share);
      remaining -= diag_budget;
    } else {
      diag_budget = 0;
    }

    const std::size_t head_share = percent_of({.value = remaining, .pct = 37U});
    const std::size_t tail_share = remaining - head_share;

    head_budget = std::min(head_need, head_share);
    tail_budget = std::min(tail_need, tail_share);
    std::size_t surplus = remaining - head_budget - tail_budget;

    if (surplus > 0 && tail_budget < tail_need) {
      const std::size_t add = std::min(surplus, tail_need - tail_budget);
      tail_budget += add;
      surplus -= add;
    }
    if (surplus > 0 && head_budget < head_need) {
      const std::size_t add = std::min(surplus, head_need - head_budget);
      head_budget += add;
      surplus -= add;
    }
    if (surplus > 0 && diag_budget < diag_need) {
      const std::size_t add = std::min(surplus, diag_need - diag_budget);
      diag_budget += add;
    }
  }

  const RenderedSection head_sec =
      collect_forward_lines(raw, lines, head_indices, head_budget);
  const RenderedSection diag_sec =
      collect_forward_lines(raw, lines, diag_indices, diag_budget);
  const RenderedSection tail_sec =
      collect_tail_lines(raw, lines, tail_indices, tail_budget);

  const std::size_t emitted_lines =
      head_sec.lines.size() + diag_sec.lines.size() + tail_sec.lines.size();
  const std::size_t emitted_source_bytes =
      head_sec.source_bytes + diag_sec.source_bytes + tail_sec.source_bytes;

  const std::size_t omitted_lines =
      total_lines > emitted_lines ? total_lines - emitted_lines : 0;
  const std::size_t omitted_bytes =
      raw.size() > emitted_source_bytes ? raw.size() - emitted_source_bytes : 0;

  const std::string footer = format_projection_footer({.omitted_lines = omitted_lines,
                                                       .omitted_bytes = omitted_bytes,
                                                       .total_bytes = raw.size()},
                                                      input.audit_entry_id);

  std::string out;
  out.reserve(head_sec.total_bytes + diag_sec.total_bytes + tail_sec.total_bytes +
              footer.size() + 64);

  auto append_section = [&out](const RenderedSection &sec) {
    for (std::size_t i = 0; i < sec.lines.size(); ++i) {
      if (i > 0)
        out.push_back('\n');
      out.append(sec.lines[i]);
    }
  };

  if (!head_sec.lines.empty())
    append_section(head_sec);

  if (!diag_sec.lines.empty()) {
    if (!out.empty())
      out.append("\n[... diagnostics ...]\n");
    append_section(diag_sec);
  }

  if (!tail_sec.lines.empty()) {
    if (!out.empty())
      out.append("\n[... tail ...]\n");
    append_section(tail_sec);
  }

  if (!out.empty())
    out.push_back('\n');
  out.append(footer);

  if (out.size() > hard_ceiling)
    out.resize(utf8_floor_boundary(out, hard_ceiling));

  result.projected_text = std::move(out);
  result.projected_bytes = result.projected_text.size();
  result.diagnostic_lines_extracted = diag_sec.lines.size();
  return result;
}

std::vector<CompactRequest> ToolAgingPlan::compact_requests() const {
  std::vector<CompactRequest> out;
  out.reserve(actions.size());
  for (const auto &action : actions) {
    if (!action.request.ids.empty() || action.request.from.has_value() ||
        action.request.to.has_value()) {
      out.push_back(action.request);
    }
  }
  return out;
}

bool is_aged_tool_stub(std::string_view text) noexcept {
  return text.starts_with(kAgedToolStubPrefix);
}

ToolAgingPlan plan_tool_result_aging(const std::vector<ContextEntryView> &entries,
                                     std::uint64_t current_turn,
                                     const ToolAgingPolicy &policy) {
  ToolAgingPlan plan;

  for (const auto &entry : entries) {
    if (!is_tool_result_kind(entry.kind))
      continue;
    if (entry.already_stubbed || is_aged_tool_stub(entry.preview))
      continue;
    if (entry.pinned) {
      ++plan.entries_skipped_pinned;
      continue;
    }

    const std::uint64_t age =
        current_turn > entry.turn_index ? current_turn - entry.turn_index : 0;
    const std::uint64_t keep_turns =
        entry.failed ? policy.preserve_errors_for_turns : policy.keep_recent_turns;
    if (age <= keep_turns) {
      ++plan.entries_skipped_recent;
      continue;
    }

    if (entry.bytes < policy.min_bytes_to_age)
      continue;

    if (plan.entries_aged >= policy.max_compactions_per_pass)
      continue;

    const auto parsed_id = parse_context_block_id(entry.entry_id);
    std::string safe_id;
    if (parsed_id.has_value()) {
      safe_id = std::to_string(*parsed_id);
    } else {
      safe_id = sanitize_one_line(entry.entry_id, kMaxIdentifierBytes);
      while (!safe_id.empty() && safe_id.front() == '#')
        safe_id.erase(safe_id.begin());
      std::erase(safe_id, ' ');
      if (safe_id.empty())
        safe_id = "unknown";
    }
    std::string safe_tool = sanitize_one_line(entry.tool_name, kMaxIdentifierBytes);
    if (safe_tool.empty())
      safe_tool = "tool";
    std::string safe_preview = sanitize_one_line(entry.preview, kMaxStubPreviewBytes);
    if (safe_preview.empty())
      safe_preview = "(no preview)";

    std::string stub;
    stub.reserve(safe_id.size() * 2 + safe_tool.size() + safe_preview.size() + 80);
    stub += "[aged tool #";
    stub += safe_id;
    stub += ' ';
    stub += safe_tool;
    stub += " (";
    stub += format_human_bytes(entry.bytes);
    stub += ") \xe2\x80\x94 ";
    stub += safe_preview;
    stub += "; /restore ";
    stub += safe_id;
    stub += " for verbatim original]";

    if (stub.size() >= entry.bytes)
      continue;

    const std::size_t reclaimed = entry.bytes - stub.size();

    CompactRequest req;
    req.op = CompactOp::summarize;
    req.summary = stub;
    if (parsed_id.has_value()) {
      req.ids.push_back(*parsed_id);
    }

    AgedToolAction action;
    action.entry_id = entry.entry_id;
    action.stub = std::move(stub);
    action.original_bytes = entry.bytes;
    action.stub_bytes = action.stub.size();
    action.bytes_reclaimed = reclaimed;
    action.request = std::move(req);

    plan.total_bytes_reclaimed += reclaimed;
    ++plan.entries_aged;
    plan.actions.push_back(std::move(action));
  }

  return plan;
}

} // namespace blackbird
