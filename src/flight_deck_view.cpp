#include "blackbird/flight_deck_view.hpp"
#include "blackbird/sprite.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {
namespace {

enum class DeckInk : std::uint8_t {
  normal = 0,
  border,
  header,
  muted,
  sr71,
  contrail_hot,
  contrail_cool,
  lane_input,
  lane_cached,
  lane_reasoning,
  lane_output,
  good,
  warn,
  alert,
  peer_active,
  peer_wait,
  watcher,
  spark_tokens,
  spark_ttft,
};

// Palette inspired by Blackbird's instrument-panel themes (hero-flight-v24 /
// hero-sr71-v15 / hero-fountain-v8): distinct semantic hues per token class and
// flight telemetry surface.
std::string_view ansi_sgr_for(DeckInk ink) noexcept {
  constexpr std::array<std::string_view, 19> kSgr{
      "\x1b[0m",                  // normal
      "\x1b[0;38;2;86;95;137m",   // border
      "\x1b[1;38;2;232;227;217m", // header
      "\x1b[0;38;2;122;134;156m", // muted
      "\x1b[1;38;2;125;207;255m", // sr71
      "\x1b[1;38;2;255;200;140m", // contrail_hot
      "\x1b[0;38;2;5;217;232m",   // contrail_cool
      "\x1b[0;38;2;122;162;247m", // lane_input
      "\x1b[0;38;2;80;247;212m",  // lane_cached
      "\x1b[1;38;2;187;154;247m", // lane_reasoning
      "\x1b[1;38;2;255;158;100m", // lane_output
      "\x1b[1;38;2;158;206;106m", // good
      "\x1b[1;38;2;224;175;104m", // warn
      "\x1b[1;38;2;247;118;142m", // alert
      "\x1b[1;38;2;90;255;170m",  // peer_active
      "\x1b[0;38;2;224;175;104m", // peer_wait
      "\x1b[0;38;2;185;103;255m", // watcher
      "\x1b[0;38;2;5;217;232m",   // spark_tokens
      "\x1b[0;38;2;255;158;100m", // spark_ttft
  };
  return kSgr[static_cast<std::size_t>(ink)];
}

bool env_no_color_set() noexcept {
  const char *val = std::getenv("NO_COLOR");
  return val != nullptr && val[0] != '\0';
}

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

bool is_bidi_or_format_control(char32_t cp) noexcept {
  return (cp >= 0x202aU && cp <= 0x202eU) || (cp >= 0x2066U && cp <= 0x2069U) ||
         cp == 0x200eU || cp == 0x200fU || cp == 0x061cU || cp == 0xfeffU;
}

// Locale-independent display width for terminal cells.
std::size_t scalar_cell_width(char32_t cp) noexcept {
  if (cp < 0x20U || (cp >= 0x7fU && cp <= 0x9fU))
    return 0;
  if ((cp >= 0x0300U && cp <= 0x036fU) || (cp >= 0x1ab0U && cp <= 0x1affU) ||
      (cp >= 0x1dc0U && cp <= 0x1dffU) || (cp >= 0x20d0U && cp <= 0x20ffU) ||
      (cp >= 0xfe00U && cp <= 0xfe0fU) || (cp >= 0xfe20U && cp <= 0xfe2fU) ||
      cp == 0x200bU || cp == 0x200cU || cp == 0x200dU) {
    return 0;
  }
  // Common East Asian Wide / Fullwidth / Emoji blocks.
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

std::string hex_escape_byte(unsigned char byte) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out = "\\x";
  out += kHex[byte >> 4U];
  out += kHex[byte & 0x0fU];
  return out;
}

struct CellCoord {
  std::size_t row = 0;
  std::size_t col = 0;
};

struct TextSpanSpec {
  std::size_t row = 0;
  std::size_t col = 0;
  std::size_t max_cols = 0;
  DeckInk ink = DeckInk::normal;
};

struct HLineSpec {
  std::size_t row = 0;
  std::size_t col_begin = 0;
  std::size_t length = 0;
  std::string_view glyph = "─";
  DeckInk ink = DeckInk::border;
};

struct VLineSpec {
  std::size_t col = 0;
  std::size_t row_begin = 0;
  std::size_t length = 0;
  std::string_view glyph = "│";
  DeckInk ink = DeckInk::border;
};

struct CanvasCell {
  std::string glyph = " ";
  DeckInk ink = DeckInk::normal;
  bool continuation = false;
};

class DeckCanvas {
public:
  explicit DeckCanvas(const FlightDeckRenderOptions &options)
      : width_(options.width), height_(options.height),
        cells_(options.width * options.height) {}

  std::size_t width() const noexcept { return width_; }
  std::size_t height() const noexcept { return height_; }

  void put_glyph(CellCoord pos, std::string_view glyph, DeckInk ink = DeckInk::normal) {
    if (pos.row >= height_ || pos.col >= width_)
      return;
    const std::size_t idx = pos.row * width_ + pos.col;
    if (cells_[idx].continuation && pos.col > 0) {
      cells_[idx - 1].glyph = " ";
      cells_[idx - 1].continuation = false;
    }
    if (pos.col + 1 < width_ && cells_[idx + 1].continuation) {
      cells_[idx + 1].glyph = " ";
      cells_[idx + 1].continuation = false;
    }
    cells_[idx].glyph.assign(glyph);
    cells_[idx].ink = ink;
    cells_[idx].continuation = false;
  }

  std::size_t put_text(const TextSpanSpec &spec, std::string_view text) {
    if (spec.row >= height_ || spec.col >= width_ || spec.max_cols == 0)
      return 0;
    const std::size_t col_limit = std::min(width_, spec.col + spec.max_cols);
    std::size_t cur = spec.col;
    std::size_t i = 0;
    while (i < text.size() && cur < col_limit) {
      const DecodedUtf8 dec = decode_utf8_at(text, i);
      if (dec.length == 0) {
        ++i;
        continue;
      }
      const std::size_t w = scalar_cell_width(dec.scalar);
      if (w == 0) {
        i += dec.length;
        continue;
      }
      if (cur + w > col_limit)
        break;
      const std::string_view slice = text.substr(i, dec.length);
      put_glyph({spec.row, cur}, slice, spec.ink);
      if (w == 2) {
        const std::size_t next_idx = spec.row * width_ + cur + 1;
        cells_[next_idx].glyph.clear();
        cells_[next_idx].ink = spec.ink;
        cells_[next_idx].continuation = true;
      }
      cur += w;
      i += dec.length;
    }
    return cur - spec.col;
  }

  void hline(const HLineSpec &spec) {
    if (spec.row >= height_ || spec.col_begin >= width_)
      return;
    const std::size_t end = std::min(width_, spec.col_begin + spec.length);
    for (std::size_t c = spec.col_begin; c < end; ++c)
      put_glyph({spec.row, c}, spec.glyph, spec.ink);
  }

  void vline(const VLineSpec &spec) {
    if (spec.col >= width_ || spec.row_begin >= height_)
      return;
    const std::size_t end = std::min(height_, spec.row_begin + spec.length);
    for (std::size_t r = spec.row_begin; r < end; ++r)
      put_glyph({r, spec.col}, spec.glyph, spec.ink);
  }

  void draw_outer_frame() {
    if (width_ < 2 || height_ < 2)
      return;
    put_glyph({0, 0}, "╭", DeckInk::border);
    put_glyph({0, width_ - 1}, "╮", DeckInk::border);
    put_glyph({height_ - 1, 0}, "╰", DeckInk::border);
    put_glyph({height_ - 1, width_ - 1}, "╯", DeckInk::border);
    hline({0, 1, width_ - 2, "─", DeckInk::border});
    hline({height_ - 1, 1, width_ - 2, "─", DeckInk::border});
    vline({0, 1, height_ - 2, "│", DeckInk::border});
    vline({width_ - 1, 1, height_ - 2, "│", DeckInk::border});
  }

  std::vector<std::string> serialize(bool color_enabled) const {
    std::vector<std::string> out;
    out.reserve(height_);
    for (std::size_t r = 0; r < height_; ++r) {
      std::string line;
      line.reserve(width_ * (color_enabled ? 4U : 2U));
      DeckInk active_ink = DeckInk::normal;
      for (std::size_t c = 0; c < width_; ++c) {
        const CanvasCell &cell = cells_[r * width_ + c];
        if (cell.continuation)
          continue;
        if (color_enabled && cell.ink != active_ink) {
          line.append(ansi_sgr_for(cell.ink));
          active_ink = cell.ink;
        }
        line.append(cell.glyph);
      }
      if (color_enabled && active_ink != DeckInk::normal)
        line.append(ansi_sgr_for(DeckInk::normal));
      out.push_back(std::move(line));
    }
    return out;
  }

private:
  std::size_t width_ = 0;
  std::size_t height_ = 0;
  std::vector<CanvasCell> cells_;
};

std::string format_fixed(double value, int precision) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(precision) << value;
  return out.str();
}

std::string format_compact_count(std::uint64_t value) {
  if (value < 1000ULL)
    return std::to_string(value);
  if (value < 1000000ULL)
    return format_fixed(static_cast<double>(value) / 1000.0, 1) + "k";
  if (value < 1000000000ULL)
    return format_fixed(static_cast<double>(value) / 1000000.0, 1) + "M";
  return format_fixed(static_cast<double>(value) / 1000000000.0, 1) + "B";
}

std::string format_bytes_compact(std::uint64_t bytes) {
  if (bytes < 1024ULL)
    return std::to_string(bytes) + "B";
  if (bytes < 1024ULL * 1024ULL)
    return format_fixed(static_cast<double>(bytes) / 1024.0, 1) + "KiB";
  if (bytes < 1024ULL * 1024ULL * 1024ULL)
    return format_fixed(static_cast<double>(bytes) / (1024.0 * 1024.0), 1) + "MiB";
  return format_fixed(static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0), 1) +
         "GiB";
}

std::string format_tri_count(const TriMetric<std::uint64_t> &metric) {
  if (metric.is_unknown() || !metric.value.has_value())
    return "UNKNOWN";
  if (metric.is_zero())
    return "0";
  std::string out = format_compact_count(*metric.value);
  if (metric.is_known_subtotal())
    out += "+";
  return out;
}

std::string format_tri_bytes(const TriMetric<std::uint64_t> &metric) {
  if (metric.is_unknown() || !metric.value.has_value())
    return "UNKNOWN";
  if (metric.is_zero())
    return "0B";
  std::string out = format_bytes_compact(*metric.value);
  if (metric.is_known_subtotal())
    out += "+";
  return out;
}

std::string format_tri_percent(const TriMetric<double> &metric) {
  if (metric.is_unknown() || !metric.value.has_value())
    return "UNKNOWN";
  const double pct = std::clamp(*metric.value * 100.0, 0.0, 100.0);
  std::string out = format_fixed(pct, 1) + "%";
  if (metric.is_known_subtotal())
    out += "+";
  return out;
}

std::string format_tri_usd(const TriMetric<double> &metric) {
  if (metric.is_unknown() || !metric.value.has_value())
    return "UNKNOWN";
  std::string out = "$" + format_fixed(*metric.value, 4);
  if (metric.is_known_subtotal())
    out += "+";
  return out;
}

std::string format_latency_compact(const LatencyStats &stats) {
  if (stats.p50_ms.has_value() && stats.p95_ms.has_value()) {
    return "p50=" + format_fixed(*stats.p50_ms, 0) +
           "ms p95=" + format_fixed(*stats.p95_ms, 0) + "ms";
  }
  if (stats.p50_ms.has_value())
    return "p50=" + format_fixed(*stats.p50_ms, 0) + "ms";
  if (stats.mean_ms.has_value())
    return "avg=" + format_fixed(*stats.mean_ms, 0) + "ms";
  if (stats.total_ms.is_zero())
    return "0ms";
  if (!stats.total_ms.is_unknown() && stats.total_ms.value.has_value())
    return format_fixed(*stats.total_ms.value, 0) + "ms";
  return "UNKNOWN";
}

std::string format_latency_short(const LatencyStats &stats) {
  if (stats.p50_ms.has_value())
    return format_fixed(*stats.p50_ms, 0) + "ms";
  if (stats.mean_ms.has_value())
    return format_fixed(*stats.mean_ms, 0) + "ms";
  if (stats.total_ms.is_zero())
    return "0ms";
  if (!stats.total_ms.is_unknown() && stats.total_ms.value.has_value())
    return format_fixed(*stats.total_ms.value, 0) + "ms";
  return "UNKNOWN";
}

bool is_flight_active(const FlightDeckTelemetry &telemetry) noexcept {
  if (telemetry.active_peers.has_value() && *telemetry.active_peers > 0)
    return true;
  const auto &u = telemetry.snapshot.usage;
  const auto has_pos = [](const TriMetric<std::uint64_t> &m) noexcept {
    return !m.is_unknown() && m.value.has_value() && *m.value > 0;
  };
  if (has_pos(u.total_input_tokens) || has_pos(u.total_cached_tokens) ||
      has_pos(u.total_reasoning_tokens) || has_pos(u.total_output_tokens)) {
    return true;
  }
  if (has_pos(telemetry.snapshot.operations.provider_requests))
    return true;
  if (!u.token_spend_series.points.empty())
    return true;
  return false;
}

struct GaugeBarSpec {
  double fraction = 0.0;
  std::size_t width = 0;
};

std::string render_gauge_bar(GaugeBarSpec spec) {
  if (spec.width == 0)
    return {};
  const double clamped = std::clamp(spec.fraction, 0.0, 1.0);
  const auto filled =
      static_cast<std::size_t>(std::llround(clamped * static_cast<double>(spec.width)));
  std::string out;
  out.reserve(spec.width * 3U);
  for (std::size_t i = 0; i < spec.width; ++i)
    out.append(i < filled ? "█" : "░");
  return out;
}

std::string compute_mach_label(const FlightDeckTelemetry &telemetry, bool active) {
  if (!active)
    return "IDLE";
  const auto &hit = telemetry.snapshot.usage.cache_hit_ratio;
  if (!hit.is_unknown() && hit.value.has_value()) {
    // Mach 1.2 .. Mach 3.3 mapped deterministically from observed cache efficiency.
    const double mach = 1.2 + std::clamp(*hit.value, 0.0, 1.0) * 2.1;
    return "M" + format_fixed(mach, 1);
  }
  if (telemetry.snapshot.has_data)
    return "M2.0";
  return "M1.5";
}

struct SpriteDrawSpec {
  std::size_t row = 0;
  std::size_t col = 0;
  std::size_t max_width = 0;
  std::size_t sprite_row_begin = 0;
  std::size_t sprite_row_end = blackbird_sprite_height;
  bool active = false;
  std::uint64_t tick = 0;
};

void draw_sr71_and_contrail(DeckCanvas &canvas, const SpriteDrawSpec &spec) {
  const std::size_t phase = static_cast<std::size_t>(spec.tick % 3ULL);
  const auto &sprite = blackbird_sprite(spec.active, phase);
  const std::size_t sprite_cols =
      std::min<std::size_t>(blackbird_sprite_width, spec.max_width);
  const std::size_t trail_start = spec.col + sprite_cols;
  const std::size_t trail_len =
      spec.max_width > sprite_cols ? spec.max_width - sprite_cols : 0;

  constexpr std::array<std::string_view, 4> kHotJet{"◈", "═", "≡", "─"};
  constexpr std::array<std::string_view, 8> kCoolTrail{"⣿", "⣶", "⣤", "⣀",
                                                       "⠒", "⠤", "⠂", "·"};
  constexpr std::array<std::string_view, 6> kIdleWake{"·", " ", " ", "·", " ", " "};

  for (std::size_t sr = spec.sprite_row_begin;
       sr < spec.sprite_row_end && sr < blackbird_sprite_height; ++sr) {
    const std::size_t out_row = spec.row + (sr - spec.sprite_row_begin);
    canvas.put_text({out_row, spec.col, sprite_cols, DeckInk::sr71}, sprite[sr]);

    if (trail_len == 0)
      continue;

    // Engine exhaust trails align with sprite rows 1 and 2 (twin J58 nacelles).
    const bool is_engine_row = (sr == 1 || sr == 2);
    const bool is_wake_row = (sr == 3);
    for (std::size_t i = 0; i < trail_len; ++i) {
      const std::size_t col = trail_start + i;
      if (spec.active && is_engine_row) {
        const std::uint64_t shift = (spec.tick + (sr == 2 ? 2ULL : 0ULL));
        if (i < 4) {
          const std::size_t idx =
              static_cast<std::size_t>((i + 4ULL - (shift % 4ULL)) % 4ULL);
          canvas.put_glyph({out_row, col}, kHotJet[idx], DeckInk::contrail_hot);
        } else {
          const std::size_t dist = i - 4;
          const std::size_t idx =
              static_cast<std::size_t>((dist + 8ULL - (shift % 8ULL)) % 8ULL);
          const std::size_t faded = std::min<std::size_t>(
              7, idx / 2 + (dist * 4) / std::max<std::size_t>(1, trail_len));
          canvas.put_glyph({out_row, col}, kCoolTrail[faded], DeckInk::contrail_cool);
        }
      } else if (spec.active && is_wake_row) {
        const std::size_t wave =
            static_cast<std::size_t>((i + 6ULL - (spec.tick % 6ULL)) % 6ULL);
        if (wave == 0)
          canvas.put_glyph({out_row, col}, "⠁", DeckInk::muted);
        else if (wave == 3)
          canvas.put_glyph({out_row, col}, "·", DeckInk::muted);
      } else if (!spec.active && is_engine_row) {
        const std::size_t idx = (i + (sr == 2 ? 3U : 0U)) % kIdleWake.size();
        if (kIdleWake[idx] != " ")
          canvas.put_glyph({out_row, col}, kIdleWake[idx], DeckInk::muted);
      } else if (spec.active && sr == 0 && trail_len >= 6) {
        // Subtle high-altitude sky parallax dots advancing with tick.
        const std::size_t sky = static_cast<std::size_t>((i + spec.tick * 2ULL) % 9ULL);
        if (sky == 0)
          canvas.put_glyph({out_row, col}, "·", DeckInk::muted);
      }
    }
  }
}

struct TokenLaneInfo {
  std::string_view full_name;
  std::string_view short_name;
  TriMetric<std::uint64_t> metric;
  DeckInk ink;
};

struct ShowerBoxSpec {
  std::size_t row = 0;
  std::size_t col = 0;
  std::size_t width = 0;
  std::size_t height = 0;
  std::uint64_t tick = 0;
  bool stale = false;
  bool compact = false;
};

void draw_token_shower_panel(DeckCanvas &canvas, const UsageSummary &usage,
                             const ShowerBoxSpec &box) {
  if (box.width < 8 || box.height < 3)
    return;

  const std::array<TokenLaneInfo, 4> lanes{{
      {"INPUT", "IN", usage.total_input_tokens, DeckInk::lane_input},
      {"CACHED", "CA", usage.total_cached_tokens, DeckInk::lane_cached},
      {"REASON", "RS", usage.total_reasoning_tokens, DeckInk::lane_reasoning},
      {"OUTPUT", "OU", usage.total_output_tokens, DeckInk::lane_output},
  }};

  std::uint64_t max_known = 0;
  bool any_known = false;
  for (const auto &lane : lanes) {
    if (!lane.metric.is_unknown() && lane.metric.value.has_value()) {
      any_known = true;
      max_known = std::max(max_known, *lane.metric.value);
    }
  }

  // Reserve bottom 2 rows for lane names + values (or 1 row in ultra-compact mode).
  const std::size_t footer_rows = box.compact ? 1 : 2;
  const std::size_t fountain_rows =
      box.height > footer_rows ? box.height - footer_rows : 1;
  const std::size_t lane_width = std::max<std::size_t>(2, box.width / 4);

  constexpr std::array<std::string_view, 8> kBars{"▁", "▂", "▃", "▄",
                                                  "▅", "▆", "▇", "█"};
  constexpr std::array<std::string_view, 5> kDrops{"·", "◦", "▫", "▪", "•"};

  for (std::size_t idx = 0; idx < lanes.size(); ++idx) {
    const auto &lane = lanes[idx];
    const std::size_t lx = box.col + idx * lane_width;
    const std::size_t lw =
        (idx == 3 && box.width > idx * lane_width)
            ? std::min(lane_width, box.width - idx * lane_width)
            : std::min(lane_width,
                       box.col + box.width > lx ? box.col + box.width - lx : 0);
    if (lw == 0)
      continue;

    const std::size_t bar_cols = lw >= 5 ? 3 : (lw >= 3 ? 2 : 1);
    const std::size_t bar_pad = (lw > bar_cols) ? (lw - bar_cols) / 2 : 0;

    if (lane.metric.is_unknown() || !lane.metric.value.has_value()) {
      const std::size_t mid_row = box.row + fountain_rows / 2;
      const std::string_view tag = lw >= 7 ? "UNKNOWN" : (lw >= 3 ? "UNK" : "?");
      const std::size_t pad = lw > tag.size() ? (lw - tag.size()) / 2 : 0;
      canvas.put_text({mid_row, lx + pad, lw - pad, DeckInk::muted}, tag);
    } else if (lane.metric.is_zero() || *lane.metric.value == 0) {
      const std::size_t base_row = box.row + fountain_rows - 1;
      for (std::size_t c = 0; c < bar_cols; ++c)
        canvas.put_glyph({base_row, lx + bar_pad + c}, "▁", DeckInk::muted);
    } else {
      const double frac = max_known > 0 ? static_cast<double>(*lane.metric.value) /
                                              static_cast<double>(max_known)
                                        : 0.0;
      const std::size_t max_bar_rows =
          fountain_rows > 2 ? fountain_rows - 2 : (fountain_rows > 1 ? 1 : 1);
      const std::uint64_t total_eighths = std::max<std::uint64_t>(
          1ULL, static_cast<std::uint64_t>(
                    std::llround(frac * static_cast<double>(max_bar_rows * 8))));
      const std::size_t full_rows = static_cast<std::size_t>(total_eighths / 8ULL);
      const std::size_t rem_eighths = static_cast<std::size_t>(total_eighths % 8ULL);
      const std::size_t occupied_rows =
          std::min(fountain_rows, full_rows + (rem_eighths > 0 ? 1U : 0U));

      // Draw rising proportional bar from bottom of fountain area.
      for (std::size_t offset = 0; offset < occupied_rows; ++offset) {
        const std::size_t r = box.row + fountain_rows - 1 - offset;
        std::string_view glyph = "█";
        if (offset == full_rows && rem_eighths > 0)
          glyph = kBars[rem_eighths - 1];
        for (std::size_t c = 0; c < bar_cols; ++c)
          canvas.put_glyph({r, lx + bar_pad + c}, glyph, lane.ink);
      }

      // Draw deterministic falling token shower drops above the bar.
      const std::size_t sky_rows = fountain_rows - occupied_rows;
      const std::uint64_t density_mod =
          frac >= 0.65 ? 2ULL : (frac >= 0.25 ? 3ULL : 4ULL);
      for (std::size_t sr = 0; sr < sky_rows; ++sr) {
        for (std::size_t c = 0; c < bar_cols; ++c) {
          const std::uint64_t seed = (static_cast<std::uint64_t>(idx + 1) * 13ULL) +
                                     (static_cast<std::uint64_t>(c) * 7ULL);
          const std::uint64_t phase =
              (static_cast<std::uint64_t>(sr) + 1024ULL - (box.tick % 1024ULL) + seed);
          if (phase % density_mod == 0) {
            const std::size_t drop_idx = static_cast<std::size_t>(
                (phase / density_mod + c + idx) % kDrops.size());
            canvas.put_glyph({box.row + sr, lx + bar_pad + c}, kDrops[drop_idx],
                             lane.ink);
          }
        }
      }
    }

    // Footer label & value.
    const std::size_t label_row = box.row + fountain_rows;
    const std::string_view name =
        lw >= lane.full_name.size() + 1 ? lane.full_name : lane.short_name;
    const std::size_t name_pad = lw > name.size() ? (lw - name.size()) / 2 : 0;
    canvas.put_text({label_row, lx + name_pad, lw - name_pad, lane.ink}, name);

    if (!box.compact && label_row + 1 < box.row + box.height) {
      std::string val = format_tri_count(lane.metric);
      if (val == "UNKNOWN" && lw < 7)
        val = "UNK";
      const std::size_t val_pad = lw > val.size() ? (lw - val.size()) / 2 : 0;
      const DeckInk val_ink =
          lane.metric.is_unknown() ? DeckInk::muted : DeckInk::header;
      canvas.put_text({label_row + 1, lx + val_pad, lw - val_pad, val_ink}, val);
    }
  }

  // When all 4 lanes are unknown and narrow lanes abbreviated to UNK, ensure
  // explicit "UNKNOWN" appears cleanly inside the shower box.
  if (!any_known && lane_width < 7 && fountain_rows >= 1) {
    const std::string_view banner = "TOKENS: UNKNOWN";
    const std::size_t pad =
        box.width > banner.size() ? (box.width - banner.size()) / 2 : 0;
    canvas.put_text({box.row, box.col + pad, box.width - pad, DeckInk::muted}, banner);
  }
}

void draw_standard_layout(DeckCanvas &canvas, const FlightDeckTelemetry &telemetry) {
  const std::size_t W = canvas.width();
  const std::size_t H = canvas.height();
  const auto &snap = telemetry.snapshot;
  const bool active = is_flight_active(telemetry);

  canvas.draw_outer_frame();

  // --- Split Geometry ---
  // Bottom Panel 3 needs 6..7 inner rows (plus divider row + bottom border).
  const std::size_t p3_inner_rows = H >= 28 ? 7 : 6;
  const std::size_t divider_row = H - 2 - p3_inner_rows;
  const std::size_t split_col = (W * 54) / 100; // ~43 cols left, ~36 cols right on 80w

  // Dividers (drawn before header rail labels so `┬` never collides with text).
  canvas.put_glyph({0, split_col}, "┬", DeckInk::border);
  canvas.vline({split_col, 1, divider_row - 1, "│", DeckInk::border});
  canvas.put_glyph({divider_row, 0}, "├", DeckInk::border);
  canvas.hline({divider_row, 1, W - 2, "─", DeckInk::border});
  canvas.put_glyph({divider_row, split_col}, "┴", DeckInk::border);
  canvas.put_glyph({divider_row, W - 1}, "┤", DeckInk::border);

  // --- Top Header Bar (row 0, cleanly split across left & right top rails) ---
  {
    const std::string status =
        snap.stale ? "[STALE]"
                   : (telemetry.guard_blocked ? "[GUARD BLOCKED]"
                                              : (active ? "[ACTIVE]" : "[IDLE]"));
    const DeckInk status_ink =
        snap.stale
            ? DeckInk::alert
            : (telemetry.guard_blocked ? DeckInk::alert
                                       : (active ? DeckInk::good : DeckInk::muted));
    const std::size_t left_end = split_col > 1 ? split_col - 1 : 1;
    std::size_t lcol = 2;
    if (lcol < left_end) {
      lcol += canvas.put_text({0, lcol, left_end - lcol, DeckInk::header},
                              " SR-71 FLIGHT DECK ");
    }
    if (lcol < left_end) {
      canvas.put_text({0, lcol, left_end - lcol, status_ink}, status + " ");
    }

    const std::string tick_str = " T:" + std::to_string(telemetry.tick) + " ";
    const std::size_t right_begin = split_col + 2;
    const std::size_t right_end = W > 2 ? W - 2 : W;
    std::size_t meta_end = right_end;
    if (right_end > right_begin + tick_str.size()) {
      meta_end = right_end - tick_str.size();
      canvas.put_text({0, meta_end, tick_str.size(), DeckInk::muted}, tick_str);
    }
    std::size_t rcol = right_begin;
    const bool has_room = !telemetry.room_label.empty();
    const bool has_model = !telemetry.model_label.empty();
    const std::size_t avail = meta_end > rcol ? meta_end - rcol : 0;
    const std::size_t per_label =
        (has_room && has_model) ? std::max<std::size_t>(8, avail / 2) : avail;
    if (has_room && rcol < meta_end) {
      const std::size_t budget =
          std::min(per_label > 4 ? per_label - 4 : 4, std::size_t{28});
      const std::string safe_room =
          sanitize_flight_deck_label(telemetry.room_label, budget);
      rcol += canvas.put_text({0, rcol, meta_end - rcol, DeckInk::contrail_cool},
                              " RM:" + safe_room + " ");
    }
    if (has_model && rcol < meta_end) {
      const std::size_t rem = meta_end - rcol;
      const std::size_t budget = std::min(rem > 4 ? rem - 4 : 4, std::size_t{28});
      const std::string safe_model =
          sanitize_flight_deck_label(telemetry.model_label, budget);
      canvas.put_text({0, rcol, meta_end - rcol, DeckInk::lane_reasoning},
                      "MD:" + safe_model + " ");
    }
  }

  // --- Panel 1: SR-71 Flight Deck Canvas (rows 1..divider_row-1, cols 1..split_col-1)
  // ---
  const std::size_t p1_x = 2;
  const std::size_t p1_w = split_col > 3 ? split_col - 3 : 0;
  const std::size_t p1_rows = divider_row > 1 ? divider_row - 1 : 0;

  if (p1_w >= 12 && p1_rows >= 8) {
    const std::string mach = compute_mach_label(telemetry, active);
    const std::string p1_hdr =
        "FLIGHT DECK [" + mach + (active ? " AFTERBURNER" : " CRUISE") + "]";
    canvas.put_text({1, p1_x, p1_w, DeckInk::header}, p1_hdr);

    // Draw SR-71 + contrail (6 rows if tall enough, else 4 core rows).
    const bool full_sprite = p1_rows >= 13;
    const std::size_t sprite_rows = full_sprite ? blackbird_sprite_height : 4;
    draw_sr71_and_contrail(canvas, {2, p1_x, p1_w, full_sprite ? 0U : 1U,
                                    full_sprite ? blackbird_sprite_height : 5U, active,
                                    telemetry.tick});

    std::size_t row = 2 + sprite_rows;
    // Gauge 1: Mach / Cache-Hit
    if (row < divider_row) {
      const auto &hit = snap.usage.cache_hit_ratio;
      std::string line = "CACHE ";
      if (hit.is_unknown() || !hit.value.has_value()) {
        line += "UNKNOWN";
      } else {
        const std::size_t gw = p1_w >= 34 ? 10 : 6;
        line +=
            "[" + render_gauge_bar({*hit.value, gw}) + "] " + format_tri_percent(hit);
      }
      canvas.put_text(
          {row, p1_x, p1_w, hit.is_unknown() ? DeckInk::muted : DeckInk::lane_cached},
          line);
      ++row;
    }

    // Gauge 2: TTFT / Latency & Requests
    if (row < divider_row) {
      const std::string ttft = format_latency_compact(snap.operations.ttft_stats);
      std::string line = "TTFT  " + ttft;
      if (p1_w >= 36 && !snap.operations.provider_requests.is_unknown()) {
        line += "  REQ:" + format_tri_count(snap.operations.provider_requests);
      }
      canvas.put_text(
          {row, p1_x, p1_w, ttft == "UNKNOWN" ? DeckInk::muted : DeckInk::spark_ttft},
          line);
      ++row;
    }

    // Gauge 3: Context Altitude (`live_bytes`)
    if (row < divider_row) {
      const auto &live = snap.context.latest_live_bytes;
      std::string line = "ALT   ";
      if (live.is_unknown() || !live.value.has_value()) {
        line += "UNKNOWN";
      } else {
        std::uint64_t ceiling = 256ULL * 1024ULL;
        if (!snap.context.peak_live_bytes.is_unknown() &&
            snap.context.peak_live_bytes.value.has_value() &&
            *snap.context.peak_live_bytes.value > ceiling) {
          ceiling = *snap.context.peak_live_bytes.value;
        }
        const double frac =
            static_cast<double>(*live.value) / static_cast<double>(ceiling);
        const std::size_t gw = p1_w >= 34 ? 10 : 6;
        line += "[" + render_gauge_bar({frac, gw}) + "] " + format_tri_bytes(live);
      }
      canvas.put_text({row, p1_x, p1_w,
                       live.is_unknown() ? DeckInk::muted : DeckInk::contrail_cool},
                      line);
      ++row;
    }

    // Gauge 4: Platoon Wingman Pips & Watchers
    if (row < divider_row) {
      std::size_t col = p1_x;
      const std::size_t end_col = p1_x + p1_w;
      col += canvas.put_text({row, col, end_col - col, DeckInk::header}, "WING ");
      if (!telemetry.active_peers.has_value() && !telemetry.waiting_peers.has_value()) {
        col += canvas.put_text({row, col, end_col - col, DeckInk::muted}, "UNKNOWN");
      } else {
        const std::size_t act = telemetry.active_peers.value_or(0);
        const std::size_t wait = telemetry.waiting_peers.value_or(0);
        const std::size_t shown_act = std::min<std::size_t>(act, 6);
        std::string pips;
        for (std::size_t i = 0; i < shown_act; ++i)
          pips += "▲";
        if (act > shown_act)
          pips += "+" + std::to_string(act - shown_act);
        if (!pips.empty())
          col += canvas.put_text({row, col, end_col - col, DeckInk::peer_active},
                                 pips + " ");
        const std::size_t shown_wait = std::min<std::size_t>(wait, 4);
        std::string wpips;
        for (std::size_t i = 0; i < shown_wait; ++i)
          wpips += "△";
        if (wait > shown_wait)
          wpips += "+" + std::to_string(wait - shown_wait);
        if (!wpips.empty() && col < end_col)
          col += canvas.put_text({row, col, end_col - col, DeckInk::peer_wait},
                                 wpips + " ");
        if (col < end_col) {
          col += canvas.put_text({row, col, end_col - col, DeckInk::normal},
                                 "A:" + std::to_string(act) +
                                     " W:" + std::to_string(wait));
        }
      }
      if (telemetry.active_watchers.has_value() && col + 6 < end_col) {
        canvas.put_text({row, col, end_col - col, DeckInk::watcher},
                        " ◎" + std::to_string(*telemetry.active_watchers));
      }
      ++row;
    }

    // Extra row if space permits: Guard / Error status
    if (row < divider_row) {
      if (telemetry.guard_blocked) {
        canvas.put_text({row, p1_x, p1_w, DeckInk::alert},
                        "GUARD: BLOCKED (policy active)");
      } else {
        const std::string errs = format_tri_count(snap.operations.error_count);
        const std::string tools = format_tri_count(snap.operations.tool_executions);
        canvas.put_text({row, p1_x, p1_w, DeckInk::muted},
                        "TOOLS:" + tools + "  ERR:" + errs);
      }
    }
  }

  // --- Panel 2: Live Token Shower / Fountain (rows 1..divider_row-1, cols
  // split_col+1..W-2) ---
  const std::size_t p2_x = split_col + 2;
  const std::size_t p2_w = W > split_col + 3 ? W - split_col - 3 : 0;
  if (p2_w >= 8 && p1_rows >= 5) {
    std::size_t hcol = p2_x;
    hcol += canvas.put_text({1, hcol, p2_w, DeckInk::header}, "TOKEN SHOWER ");
    if (snap.stale && hcol < p2_x + p2_w) {
      canvas.put_text({1, hcol, p2_x + p2_w - hcol, DeckInk::alert}, "[STALE]");
    } else if (hcol < p2_x + p2_w) {
      const std::string obs = "OBS:" + std::to_string(snap.usage.observation_count);
      canvas.put_text({1, hcol, p2_x + p2_w - hcol, DeckInk::muted}, obs);
    }

    const std::size_t shower_h = divider_row > 2 ? divider_row - 2 : 0;
    draw_token_shower_panel(
        canvas, snap.usage,
        {2, p2_x, p2_w, shower_h, telemetry.tick, snap.stale, false});
  }

  // --- Panel 3: Sparkline & Telemetry Strip (rows divider_row+1..H-2) ---
  const std::size_t p3_x = 2;
  const std::size_t p3_w = W > 4 ? W - 4 : 0;
  std::size_t r = divider_row + 1;

  if (r < H - 1) {
    std::size_t col = p3_x;
    col += canvas.put_text({r, col, p3_w, DeckInk::header}, "TELEMETRY & SPARKLINES");
    if (snap.stale && col + 8 < p3_x + p3_w) {
      std::string stale_note = "  [STALE";
      if (!snap.stale_reason.empty()) {
        stale_note += ": " + sanitize_flight_deck_label(snap.stale_reason, 36);
      }
      stale_note += "]";
      canvas.put_text({r, col, p3_x + p3_w - col, DeckInk::alert}, stale_note);
    }
    ++r;
  }

  // Row: Token Spend Sparkline
  if (r < H - 1) {
    const std::size_t spark_w = std::clamp<std::size_t>(p3_w / 3, 12, 32);
    const MetricsSparkline spark =
        metrics_sparkline(snap.usage.token_spend_series, spark_w);
    std::size_t col = p3_x;
    col += canvas.put_text({r, col, p3_w, DeckInk::header}, "TOKENS : ");
    if (spark.finite_count == 0 || spark.glyphs.empty()) {
      canvas.put_text({r, col, p3_x + p3_w - col, DeckInk::muted},
                      "UNKNOWN (no samples)");
    } else {
      col += canvas.put_text({r, col, p3_x + p3_w - col, DeckInk::spark_tokens},
                             spark.glyphs);
      if (spark.min_value.has_value() && spark.max_value.has_value() &&
          col + 4 < p3_x + p3_w) {
        std::string range = " [" + format_fixed(*spark.min_value, 0) + ".." +
                            format_fixed(*spark.max_value, 0) +
                            " tok, n=" + std::to_string(spark.finite_count) + "]";
        canvas.put_text({r, col, p3_x + p3_w - col, DeckInk::muted}, range);
      }
    }
    ++r;
  }

  // Row: TTFT Sparkline
  if (r < H - 1) {
    const std::size_t spark_w = std::clamp<std::size_t>(p3_w / 3, 12, 32);
    const MetricsSparkline spark = metrics_sparkline(snap.operations.ttft_ms, spark_w);
    std::size_t col = p3_x;
    col += canvas.put_text({r, col, p3_w, DeckInk::header}, "TTFT   : ");
    if (spark.finite_count == 0 || spark.glyphs.empty()) {
      canvas.put_text({r, col, p3_x + p3_w - col, DeckInk::muted},
                      "UNKNOWN (no samples)");
    } else {
      col += canvas.put_text({r, col, p3_x + p3_w - col, DeckInk::spark_ttft},
                             spark.glyphs);
      if (spark.min_value.has_value() && spark.max_value.has_value() &&
          col + 4 < p3_x + p3_w) {
        std::string range = " [" + format_fixed(*spark.min_value, 1) + ".." +
                            format_fixed(*spark.max_value, 1) +
                            " ms, n=" + std::to_string(spark.finite_count) + "]";
        canvas.put_text({r, col, p3_x + p3_w - col, DeckInk::muted}, range);
      }
    }
    ++r;
  }

  // Row: Decision Companion
  if (r < H - 1) {
    const auto &dc = snap.decision_companion;
    std::string line = "COMPANION: calls=" + format_tri_count(dc.batch_count) +
                       " fail=" + format_tri_count(dc.failure_count) +
                       " tok=" + format_tri_count(dc.total_tokens) +
                       " lat=" + format_latency_short(dc.latency_stats);
    canvas.put_text(
        {r, p3_x, p3_w, dc.batch_count.is_unknown() ? DeckInk::muted : DeckInk::normal},
        line);
    ++r;
  }

  // Row: Strictly separated Observed vs Estimated Cost
  if (r < H - 1) {
    std::size_t col = p3_x;
    col += canvas.put_text({r, col, p3_w, DeckInk::header}, "COST   : ");
    const std::string obs_str = format_tri_usd(snap.usage.observed_charge_usd);
    const std::string est_str = format_tri_usd(snap.usage.estimated_cost_usd);
    col += canvas.put_text(
        {r, col, p3_x + p3_w - col,
         snap.usage.observed_charge_usd.is_unknown() ? DeckInk::muted : DeckInk::good},
        "OBSERVED=" + obs_str);
    if (col + 4 < p3_x + p3_w) {
      col += canvas.put_text({r, col, p3_x + p3_w - col, DeckInk::border}, "  |  ");
    }
    if (col < p3_x + p3_w) {
      std::string est_full = "ESTIMATED=" + est_str;
      if (snap.usage.mixed_pricing_versions) {
        est_full += " [mixed]";
      } else if (!snap.usage.pricing_version.empty()) {
        est_full +=
            " [" + sanitize_flight_deck_label(snap.usage.pricing_version, 16) + "]";
      }
      canvas.put_text(
          {r, col, p3_x + p3_w - col,
           snap.usage.estimated_cost_usd.is_unknown() ? DeckInk::muted : DeckInk::warn},
          est_full);
    }
    ++r;
  }

  // Row: Context & Coverage summary
  if (r < H - 1) {
    const auto &ctx = snap.context;
    std::string line = "CONTEXT: live=" + format_tri_bytes(ctx.latest_live_bytes) +
                       " peak=" + format_tri_bytes(ctx.peak_live_bytes) +
                       " arch=" + format_tri_bytes(ctx.latest_archived_bytes) +
                       " cmp=" + format_tri_count(ctx.compaction_events);
    canvas.put_text({r, p3_x, p3_w, DeckInk::muted}, line);
    ++r;
  }

  // Optional extra row for taller viewports (>= 28 rows): Coverage & Companion Cost
  if (r < H - 1) {
    const auto &cov = snap.coverage;
    const auto &dc = snap.decision_companion;
    std::string line = "COVERAGE: ingested=" + std::to_string(cov.records_ingested) +
                       " corrupt=" + std::to_string(cov.records_skipped_corrupt) +
                       " missing=" + std::to_string(cov.missing_field_observations) +
                       "  |  DC_OBS=" + format_tri_usd(dc.observed_charge_usd) +
                       " DC_EST=" + format_tri_usd(dc.estimated_cost_usd);
    canvas.put_text({r, p3_x, p3_w, DeckInk::muted}, line);
  }
}

void draw_narrow_layout(DeckCanvas &canvas, const FlightDeckTelemetry &telemetry) {
  const std::size_t W = canvas.width();
  const std::size_t H = canvas.height();
  const auto &snap = telemetry.snapshot;
  const bool active = is_flight_active(telemetry);

  // Ultra-tiny fallback (< 16 cols or < 8 rows): plain clipped lines without box.
  if (W < 16 || H < 8) {
    std::size_t r = 0;
    if (r < H) {
      std::string hdr = "SR-71 ";
      hdr += snap.stale ? "STALE" : (active ? "ACT" : "IDLE");
      canvas.put_text({r++, 0, W, snap.stale ? DeckInk::alert : DeckInk::header}, hdr);
    }
    if (r < H) {
      canvas.put_text({r++, 0, W, DeckInk::lane_input},
                      "IN:" + format_tri_count(snap.usage.total_input_tokens));
    }
    if (r < H) {
      canvas.put_text({r++, 0, W, DeckInk::lane_output},
                      "OU:" + format_tri_count(snap.usage.total_output_tokens));
    }
    if (r < H) {
      canvas.put_text({r++, 0, W, DeckInk::warn},
                      "OBS:" + format_tri_usd(snap.usage.observed_charge_usd));
    }
    return;
  }

  canvas.draw_outer_frame();
  const std::size_t inner_x = 2;
  const std::size_t inner_w = W > 4 ? W - 4 : 0;

  // Row 0: Compact Header
  {
    std::size_t col = 2;
    col += canvas.put_text({0, col, W - 4, DeckInk::header}, " SR-71 ");
    const std::string badge =
        snap.stale
            ? "[STALE]"
            : (telemetry.guard_blocked ? "[GUARD]" : (active ? "[ACT]" : "[IDLE]"));
    const DeckInk bink = snap.stale ? DeckInk::alert
                                    : (telemetry.guard_blocked
                                           ? DeckInk::alert
                                           : (active ? DeckInk::good : DeckInk::muted));
    col += canvas.put_text({0, col, W - col - 2, bink}, badge + " ");
    const std::string t = "T:" + std::to_string(telemetry.tick) + " ";
    if (W > col + t.size() + 2) {
      canvas.put_text({0, W - 2 - t.size(), t.size(), DeckInk::muted}, t);
    }
  }

  std::size_t r = 1;
  // Row 1: Room & Model labels (sanitized)
  if (r < H - 1) {
    std::string meta;
    if (!telemetry.room_label.empty())
      meta += "RM:" + sanitize_flight_deck_label(telemetry.room_label, 14);
    if (!telemetry.model_label.empty()) {
      if (!meta.empty())
        meta += " ";
      meta += "MD:" + sanitize_flight_deck_label(telemetry.model_label, 14);
    }
    if (meta.empty())
      meta = "FLIGHT DECK " + compute_mach_label(telemetry, active);
    canvas.put_text({r++, inner_x, inner_w, DeckInk::contrail_cool}, meta);
  }

  // Rows 2..5: Core 4 rows of SR-71 sprite + contrail
  if (r + 4 <= H - 1) {
    draw_sr71_and_contrail(canvas,
                           {r, inner_x, inner_w, 1U, 5U, active, telemetry.tick});
    r += 4;
  }

  // Row 6: Cache & TTFT
  if (r < H - 1) {
    std::string line = "CA:" + format_tri_percent(snap.usage.cache_hit_ratio) +
                       " TTFT:" + format_latency_short(snap.operations.ttft_stats);
    canvas.put_text({r++, inner_x, inner_w, DeckInk::lane_cached}, line);
  }

  // Row 7: Context Altitude & Wingmen
  if (r < H - 1) {
    std::string line = "ALT:" + format_tri_bytes(snap.context.latest_live_bytes);
    if (telemetry.active_peers.has_value() || telemetry.waiting_peers.has_value()) {
      line += " P:" + std::to_string(telemetry.active_peers.value_or(0)) + "/" +
              std::to_string(telemetry.waiting_peers.value_or(0));
    } else {
      line += " P:UNK";
    }
    if (telemetry.active_watchers.has_value())
      line += " W:" + std::to_string(*telemetry.active_watchers);
    canvas.put_text({r++, inner_x, inner_w, DeckInk::peer_active}, line);
  }

  // Divider before compact token shower + sparklines
  if (r < H - 4) {
    canvas.put_glyph({r, 0}, "├", DeckInk::border);
    canvas.hline({r, 1, W - 2, "─", DeckInk::border});
    canvas.put_glyph({r, W - 1}, "┤", DeckInk::border);
    canvas.put_text({r, 2, inner_w, DeckInk::header}, " SHOWER ");
    ++r;
  }

  // Compact 4-lane token shower (3 rows if available, leaving 3 rows for spark/cost)
  const std::size_t bottom_needed = 3;
  if (r + bottom_needed + 2 <= H - 1) {
    const std::size_t shower_h = (H - 1 - bottom_needed) - r;
    draw_token_shower_panel(
        canvas, snap.usage,
        {r, inner_x, inner_w, shower_h, telemetry.tick, snap.stale, true});
    r += shower_h;
  }

  // Token Sparkline
  if (r < H - 1) {
    const std::size_t sw = inner_w > 10 ? std::min<std::size_t>(inner_w - 6, 18) : 6;
    const auto sp = metrics_sparkline(snap.usage.token_spend_series, sw);
    const std::string s = (sp.finite_count == 0 || sp.glyphs.empty())
                              ? "TOK: UNKNOWN"
                              : ("TOK: " + sp.glyphs);
    canvas.put_text({r++, inner_x, inner_w,
                     sp.finite_count == 0 ? DeckInk::muted : DeckInk::spark_tokens},
                    s);
  }

  // TTFT Sparkline & Companion calls
  if (r < H - 1) {
    const std::size_t sw = inner_w > 16 ? std::min<std::size_t>(inner_w - 14, 12) : 5;
    const auto sp = metrics_sparkline(snap.operations.ttft_ms, sw);
    std::string s =
        (sp.finite_count == 0 || sp.glyphs.empty()) ? "LAT:UNK" : ("LAT:" + sp.glyphs);
    s += " DC:" + format_tri_count(snap.decision_companion.batch_count);
    canvas.put_text({r++, inner_x, inner_w, DeckInk::spark_ttft}, s);
  }

  // Observed vs Estimated Cost (strictly separated)
  if (r < H - 1) {
    std::string s = "OBS:" + format_tri_usd(snap.usage.observed_charge_usd) +
                    " EST:" + format_tri_usd(snap.usage.estimated_cost_usd);
    canvas.put_text({r++, inner_x, inner_w, DeckInk::warn}, s);
  }
}

} // namespace

std::string FlightDeckFrame::text() const {
  std::string out;
  std::size_t total = 0;
  for (const auto &line : lines)
    total += line.size() + 1;
  out.reserve(total);
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (i > 0)
      out += '\n';
    out += lines[i];
  }
  return out;
}

std::string sanitize_flight_deck_label(std::string_view text, std::size_t max_bytes) {
  std::string out;
  out.reserve(std::min(text.size(), max_bytes));
  std::size_t emitted = 0;
  bool truncated = false;

  for (std::size_t i = 0; i < text.size();) {
    const auto b = static_cast<unsigned char>(text[i]);
    std::string chunk;
    std::size_t step = 1;

    if (b == '\r') {
      chunk = "\\r";
    } else if (b == '\n') {
      chunk = "\\n";
    } else if (b == '\t') {
      chunk = "\\t";
    } else if (b < 0x20U || b == 0x7fU || (b >= 0x80U && b <= 0x9fU)) {
      chunk = hex_escape_byte(b);
    } else {
      const DecodedUtf8 dec = decode_utf8_at(text, i);
      if (dec.length == 0) {
        chunk = hex_escape_byte(b);
      } else if ((dec.scalar >= 0x80U && dec.scalar <= 0x9fU) ||
                 is_bidi_or_format_control(dec.scalar)) {
        for (std::size_t k = 0; k < dec.length; ++k)
          chunk += hex_escape_byte(static_cast<unsigned char>(text[i + k]));
        step = dec.length;
      } else {
        chunk.assign(text.data() + i, dec.length);
        step = dec.length;
      }
    }

    if (emitted + chunk.size() > max_bytes) {
      truncated = true;
      break;
    }
    out += chunk;
    emitted += chunk.size();
    i += step;
  }

  if (truncated && max_bytes >= 3) {
    while (out.size() + 3 > max_bytes && !out.empty()) {
      // Remove complete UTF-8 scalar or byte cleanly.
      const auto back = static_cast<unsigned char>(out.back());
      out.pop_back();
      if ((back & 0xc0U) == 0x80U) {
        while (!out.empty() &&
               (static_cast<unsigned char>(out.back()) & 0xc0U) == 0x80U) {
          out.pop_back();
        }
        if (!out.empty())
          out.pop_back();
      }
    }
    out += "...";
  }
  return out;
}

FlightDeckFrame FlightDeckView::render(const FlightDeckTelemetry &telemetry,
                                       const FlightDeckRenderOptions &options) const {
  FlightDeckFrame frame;
  if (options.width == 0 || options.height == 0)
    return frame;

  const bool color_enabled =
      options.color && !(options.honor_no_color_env && env_no_color_set());
  const bool narrow = options.width < 60 || options.height < 20;

  DeckCanvas canvas{options};
  if (narrow)
    draw_narrow_layout(canvas, telemetry);
  else
    draw_standard_layout(canvas, telemetry);

  frame.lines = canvas.serialize(color_enabled);
  frame.width = options.width;
  frame.height = options.height;
  frame.color_enabled = color_enabled;
  frame.stale = telemetry.snapshot.stale;
  frame.narrow_mode = narrow;
  return frame;
}

std::string FlightDeckView::render_text(const FlightDeckTelemetry &telemetry,
                                        const FlightDeckRenderOptions &options) const {
  return render(telemetry, options).text();
}

} // namespace blackbird
