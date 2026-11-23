#include "blackbird/flight_deck_hero.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <numbers>
#include <span>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace blackbird {
namespace {

constexpr HeroRgb rgb_hex(std::uint32_t hex) noexcept {
  return HeroRgb{
      .r = static_cast<std::uint8_t>((hex >> 16U) & 0xFFU),
      .g = static_cast<std::uint8_t>((hex >> 8U) & 0xFFU),
      .b = static_cast<std::uint8_t>(hex & 0xFFU),
  };
}

constexpr std::array<HeroTheme, hero_theme_count> kThemes = {{
    // 0: synthwave
    HeroTheme{
        .id = HeroThemeId::synthwave,
        .key = "synthwave",
        .display_name = "synthwave",
        .sky = {rgb_hex(0x0b0120), rgb_hex(0x1c0640), rgb_hex(0x3a0b5e),
                rgb_hex(0x7a1670), rgb_hex(0xff4f8b)},
        .horizon = 0.80F,
        .sun = true,
        .sun_cols = {rgb_hex(0xfff27a), rgb_hex(0xff9a3c), rgb_hex(0xff2f8e)},
        .sun_halo = rgb_hex(0xff50a0),
        .grid = rgb_hex(0xff2fd0),
        .scan = 0.07F,
        .bloom = 0.45F,
        .rim = rgb_hex(0xff2fd0),
        .rim2 = rgb_hex(0x05d9e8),
        .burn = {rgb_hex(0xffc88c), rgb_hex(0x05d9e8), rgb_hex(0xff2fd0)},
        .cls = {HeroRgb{110, 90, 230}, HeroRgb{255, 42, 180}, HeroRgb{255, 123, 41},
                HeroRgb{185, 103, 255}, HeroRgb{5, 217, 232}, HeroRgb{255, 251, 150}},
        .team = {HeroRgb{255, 106, 213}, HeroRgb{160, 120, 255}, HeroRgb{255, 160, 90},
                 HeroRgb{90, 255, 170}, HeroRgb{90, 170, 255}, HeroRgb{255, 80, 120},
                 HeroRgb{255, 251, 150}},
        .label = rgb_hex(0xff9de2),
        .dim = rgb_hex(0x7a5a9a),
        .scene = HeroSceneKind::none,
        .ground = HeroGroundKind::grid,
        .cr_style = HeroCacheReadStyle::fog,
    },
    // 1: tokyonight
    HeroTheme{
        .id = HeroThemeId::tokyonight,
        .key = "tokyonight",
        .display_name = "tokyo night",
        .sky = {rgb_hex(0x0f0f17), rgb_hex(0x16161e), rgb_hex(0x1a1b26),
                rgb_hex(0x24283b), rgb_hex(0x414868)},
        .horizon = 0.82F,
        .sun = false,
        .sun_cols = {rgb_hex(0xfff27a), rgb_hex(0xff9a3c), rgb_hex(0xff2f8e)},
        .sun_halo = rgb_hex(0xf7768e),
        .grid = rgb_hex(0x3b4261),
        .scan = 0.0F,
        .bloom = 0.25F,
        .rim = rgb_hex(0x7aa2f7),
        .rim2 = rgb_hex(0x7dcfff),
        .burn = {rgb_hex(0xe0af68), rgb_hex(0x7dcfff), rgb_hex(0xbb9af7)},
        .cls = {HeroRgb{61, 89, 161}, HeroRgb{187, 154, 247}, HeroRgb{255, 158, 100},
                HeroRgb{247, 118, 142}, HeroRgb{192, 202, 245}, HeroRgb{125, 207, 255}},
        .team = {HeroRgb{255, 158, 100}, HeroRgb{187, 154, 247}, HeroRgb{224, 175, 104},
                 HeroRgb{158, 206, 106}, HeroRgb{122, 162, 247}, HeroRgb{247, 118, 142},
                 HeroRgb{125, 207, 255}},
        .label = rgb_hex(0xc0caf5),
        .dim = rgb_hex(0x565f89),
        .scene = HeroSceneKind::skyline,
        .ground = HeroGroundKind::grid,
        .cr_style = HeroCacheReadStyle::fog,
        .sky_back = rgb_hex(0x232842),
        .sky_front = rgb_hex(0x0d0e16),
        .tower = rgb_hex(0xf7768e),
        .window = rgb_hex(0xe0af68),
    },
    // 2: gotham
    HeroTheme{
        .id = HeroThemeId::gotham,
        .key = "gotham",
        .display_name = "gotham",
        .sky = {rgb_hex(0x030303), rgb_hex(0x070707), rgb_hex(0x0c0c0c),
                rgb_hex(0x151413), rgb_hex(0x221a14)},
        .horizon = 0.82F,
        .sun = false,
        .sun_cols = {rgb_hex(0xffd2a0), rgb_hex(0xffb070), rgb_hex(0xff6a2a)},
        .sun_halo = rgb_hex(0xff8c3c),
        .grid = rgb_hex(0x262626),
        .scan = 0.0F,
        .bloom = 0.15F,
        .rim = rgb_hex(0x9a9a9a),
        .rim2 = rgb_hex(0xff8c3c),
        .burn = {rgb_hex(0xffd2a0), rgb_hex(0xffb070), rgb_hex(0xff6a2a)},
        .cls = {HeroRgb{150, 158, 170}, HeroRgb{160, 150, 175}, HeroRgb{200, 185, 165},
                HeroRgb{190, 190, 190}, HeroRgb{255, 140, 60}, HeroRgb{255, 200, 120}},
        .team = {rgb_hex(0xff8c3c), rgb_hex(0x8a7cff), rgb_hex(0xd9785a),
                 rgb_hex(0x6fbf73), rgb_hex(0x5fa8ff), rgb_hex(0xd45a8a),
                 rgb_hex(0xffd27a)},
        .label = rgb_hex(0xd0d0d0),
        .dim = rgb_hex(0x555555),
        .scene = HeroSceneKind::gotham,
        .ground = HeroGroundKind::grid,
        .cr_style = HeroCacheReadStyle::rain,
        .sky_back = rgb_hex(0x171717),
        .sky_front = rgb_hex(0x050505),
        .tower = rgb_hex(0xff8c3c),
        .window = rgb_hex(0xffb070),
    },
    // 3: kanagawa
    HeroTheme{
        .id = HeroThemeId::kanagawa,
        .key = "kanagawa",
        .display_name = "kanagawa",
        .sky = {rgb_hex(0x111116), rgb_hex(0x17171e), rgb_hex(0x1f1f28),
                rgb_hex(0x223249), rgb_hex(0x2d4f67)},
        .horizon = 0.80F,
        .sun = false,
        .sun_cols = {rgb_hex(0xe6c384), rgb_hex(0x7fb4ca), rgb_hex(0x957fb8)},
        .sun_halo = rgb_hex(0xc8c093),
        .grid = rgb_hex(0x363646),
        .scan = 0.0F,
        .bloom = 0.20F,
        .rim = rgb_hex(0xdcd7ba),
        .rim2 = rgb_hex(0x7fb4ca),
        .burn = {rgb_hex(0xe6c384), rgb_hex(0x7fb4ca), rgb_hex(0x957fb8)},
        .cls = {rgb_hex(0x938aa9), rgb_hex(0x957fb8), rgb_hex(0xc17158),
                rgb_hex(0xc34043), rgb_hex(0xdcd7ba), rgb_hex(0x7aa89f)},
        .team = {rgb_hex(0xe6c384), rgb_hex(0x957fb8), rgb_hex(0xc17158),
                 rgb_hex(0x98bb6c), rgb_hex(0x7fb4ca), rgb_hex(0xe82424),
                 rgb_hex(0x7aa89f)},
        .label = rgb_hex(0xdcd7ba),
        .dim = rgb_hex(0x727169),
        .scene = HeroSceneKind::fuji,
        .ground = HeroGroundKind::grid,
        .cr_style = HeroCacheReadStyle::petal,
    },
    // 4: nord
    HeroTheme{
        .id = HeroThemeId::nord,
        .key = "nord",
        .display_name = "nord",
        .sky = {rgb_hex(0x191c23), rgb_hex(0x222730), rgb_hex(0x2e3440),
                rgb_hex(0x3b4252), rgb_hex(0x4c566a)},
        .horizon = 0.80F,
        .sun = false,
        .sun_cols = {rgb_hex(0xebcb8b), rgb_hex(0x88c0d0), rgb_hex(0x5e81ac)},
        .sun_halo = rgb_hex(0x88c0d0),
        .grid = rgb_hex(0x434c5e),
        .scan = 0.0F,
        .bloom = 0.20F,
        .rim = rgb_hex(0xd8dee9),
        .rim2 = rgb_hex(0x88c0d0),
        .burn = {rgb_hex(0xebcb8b), rgb_hex(0x88c0d0), rgb_hex(0x5e81ac)},
        .cls = {rgb_hex(0xd8dee9), rgb_hex(0xb48ead), rgb_hex(0xd5967a),
                rgb_hex(0xbf616a), rgb_hex(0xebcb8b), rgb_hex(0x8fbcbb)},
        .team = {rgb_hex(0x88c0d0), rgb_hex(0xb48ead), rgb_hex(0xd5967a),
                 rgb_hex(0xa3be8c), rgb_hex(0x81a1c1), rgb_hex(0xbf616a),
                 rgb_hex(0x8fbcbb)},
        .label = rgb_hex(0xd8dee9),
        .dim = rgb_hex(0x667080),
        .scene = HeroSceneKind::aurora,
        .ground = HeroGroundKind::grid,
        .cr_style = HeroCacheReadStyle::snow,
    },
    // 5: hackerman
    HeroTheme{
        .id = HeroThemeId::hackerman,
        .key = "hackerman",
        .display_name = "hackerman",
        .sky = {rgb_hex(0x06060c), rgb_hex(0x080910), rgb_hex(0x0b0c16),
                rgb_hex(0x0b0c16), rgb_hex(0x151828)},
        .horizon = 0.80F,
        .sun = false,
        .sun_cols = {rgb_hex(0xd1fffe), rgb_hex(0x7cf8f7), rgb_hex(0x4fe88f)},
        .sun_halo = rgb_hex(0x4fe88f),
        .grid = rgb_hex(0x287b51),
        .scan = 0.08F,
        .bloom = 0.35F,
        .rim = rgb_hex(0x82fb9c),
        .rim2 = rgb_hex(0x7cf8f7),
        .burn = {rgb_hex(0xd1fffe), rgb_hex(0x7cf8f7), rgb_hex(0x4fe88f)},
        .cls = {rgb_hex(0x4fe88f), rgb_hex(0x829dd4), rgb_hex(0x50f7d4),
                rgb_hex(0x86a7df), rgb_hex(0xd1fffe), rgb_hex(0x82fb9c)},
        .team = {rgb_hex(0x82fb9c), rgb_hex(0x829dd4), rgb_hex(0x50f7a3),
                 rgb_hex(0x7cf8f7), rgb_hex(0x86a7df), rgb_hex(0x50f872),
                 rgb_hex(0xa4ffec)},
        .label = rgb_hex(0xddf7ff),
        .dim = rgb_hex(0x6a6e95),
        .scene = HeroSceneKind::wire,
        .ground = HeroGroundKind::grid,
        .cr_style = HeroCacheReadStyle::code,
    },
    // 6: retro82
    HeroTheme{
        .id = HeroThemeId::retro82,
        .key = "retro82",
        .display_name = "retro-82",
        .sky = {rgb_hex(0x020c17), rgb_hex(0x05182e), rgb_hex(0x0a2540),
                rgb_hex(0x743d1e), rgb_hex(0xe97b3c)},
        .horizon = 0.78F,
        .sun = true,
        .sun_cols = {rgb_hex(0xf6dcac), rgb_hex(0xfaa968), rgb_hex(0xf85525)},
        .sun_halo = rgb_hex(0xf85525),
        .grid = rgb_hex(0x2a6b78),
        .scan = 0.04F,
        .bloom = 0.35F,
        .rim = rgb_hex(0xfaa968),
        .rim2 = rgb_hex(0x8cbfb8),
        .burn = {rgb_hex(0xf6dcac), rgb_hex(0xfaa968), rgb_hex(0xf85525)},
        .cls = {rgb_hex(0x3f8f8a), rgb_hex(0x8cbfb8), rgb_hex(0xe97b3c),
                rgb_hex(0xf85525), rgb_hex(0xf6dcac), rgb_hex(0xa7c9c6)},
        .team = {rgb_hex(0xfaa968), rgb_hex(0x8cbfb8), rgb_hex(0xe97b3c),
                 rgb_hex(0x028391), rgb_hex(0x3f8f8a), rgb_hex(0xf85525),
                 rgb_hex(0xa7c9c6)},
        .label = rgb_hex(0xf6dcac),
        .dim = rgb_hex(0x3f8f8a),
        .scene = HeroSceneKind::palms,
        .ground = HeroGroundKind::ocean,
        .cr_style = HeroCacheReadStyle::fog,
    },
    // 7: dyingearth
    HeroTheme{
        .id = HeroThemeId::dyingearth,
        .key = "dyingearth",
        .display_name = "dying earth",
        .sky = {rgb_hex(0x041413), rgb_hex(0x08201f), rgb_hex(0x0f3b3a),
                rgb_hex(0x0f3b3a), rgb_hex(0x155352)},
        .horizon = 0.80F,
        .sun = false,
        .sun_cols = {rgb_hex(0xffffff), rgb_hex(0xcfc041), rgb_hex(0xf15f22)},
        .sun_halo = rgb_hex(0xcfc041),
        .grid = rgb_hex(0x155352),
        .scan = 0.05F,
        .bloom = 0.30F,
        .rim = rgb_hex(0xb1c9c3),
        .rim2 = rgb_hex(0x77bfcf),
        .burn = {rgb_hex(0xffffff), rgb_hex(0xcfc041), rgb_hex(0xf15f22)},
        .cls = {rgb_hex(0x40a4b9), rgb_hex(0xb154cf), rgb_hex(0xe99f10),
                rgb_hex(0xda5bd6), rgb_hex(0xcfc041), rgb_hex(0x00c420)},
        .team = {rgb_hex(0xf15f22), rgb_hex(0x0096ff), rgb_hex(0x00c420),
                 rgb_hex(0xa64a2e), rgb_hex(0x77bfcf), rgb_hex(0xda5bd6),
                 rgb_hex(0xcfc041)},
        .label = rgb_hex(0xb1c9c3),
        .dim = rgb_hex(0x40a4b9),
        .scene = HeroSceneKind::qud,
        .ground = HeroGroundKind::glyph,
        .cr_style = HeroCacheReadStyle::fog,
    },
}};

struct Vec2 {
  float x = 0.0F;
  float y = 0.0F;
};

struct Vec3 {
  float x = 0.0F;
  float y = 0.0F;
  float z = 0.0F;
};

struct PixelPos {
  int x = 0;
  int y = 0;
};

struct ColorA {
  HeroRgb rgb{};
  float alpha = 1.0F;
};

struct RectF {
  float x = 0.0F;
  float y = 0.0F;
  float w = 0.0F;
  float h = 0.0F;
};

struct LineSeg {
  Vec2 a{};
  Vec2 b{};
};

struct CircleSpec {
  Vec2 center{};
  float radius = 0.0F;
};

struct EllipseSpec {
  Vec2 center{};
  Vec2 radii{};
};

struct ArcSpec {
  Vec2 center{};
  Vec2 radii{};
  float start_rad = 0.0F;
  float end_rad = 0.0F;
  float thickness = 2.0F;
};

struct VGrad {
  HeroRgb top{};
  HeroRgb bottom{};
  float top_alpha = 1.0F;
  float bottom_alpha = 1.0F;
  bool additive = false;
};

struct RadialGrad {
  Vec2 center{};
  float inner_r = 0.0F;
  float outer_r = 1.0F;
  ColorA inner{};
  ColorA outer{};
  int clip_y_max = -1;
  bool additive = true;
};

struct TextStyle {
  ColorA color{};
  int scale = 1;
  bool center = false;
  bool right = false;
  bool additive = false;
};

struct CanvasView {
  std::uint8_t *rgba = nullptr;
  int width = 0;
  int height = 0;
};

struct SeededRng {
  std::uint32_t state = 11;

  float next() noexcept {
    state = (state ^ (state >> 15U)) * (1U | state) + 0x6D2B79F5U;
    return static_cast<float>(state) / 4294967296.0F;
  }

  float range(float lo, float hi) noexcept { return lo + next() * (hi - lo); }
};

struct RangeF {
  float lo = 0.0F;
  float hi = 1.0F;
};

float rng_range(SeededRng &rng, RangeF bounds) noexcept {
  return bounds.lo + rng.next() * (bounds.hi - bounds.lo);
}

HeroSize clamp_hero_size(HeroSize size) noexcept {
  return HeroSize{
      .width = std::clamp(size.width, hero_min_width, hero_max_width),
      .height = std::clamp(size.height, hero_min_height, hero_max_height),
  };
}

std::uint8_t clamp_u8(float value) noexcept {
  if (!(value > 0.0F)) {
    return 0;
  }
  if (!(value < 255.0F)) {
    return 255;
  }
  return static_cast<std::uint8_t>(value + 0.5F);
}

double sanitize_rate(double value) noexcept {
  if (!std::isfinite(value) || value <= 0.0) {
    return 0.0;
  }
  return std::min(value, 1e9);
}

double sanitize_cache_hit(double value) noexcept {
  if (!std::isfinite(value)) {
    return 0.85;
  }
  return std::clamp(value, 0.0, 1.0);
}

double sanitize_context_fill(double value) noexcept {
  if (!std::isfinite(value)) {
    return 0.35;
  }
  return std::clamp(value, 0.08, 1.0);
}

float sanitize_stick(float value) noexcept {
  if (!std::isfinite(value)) {
    return 0.0F;
  }
  return std::clamp(value, -1.0F, 1.0F);
}

std::optional<std::size_t> checked_rgba_bytes(HeroSize size) noexcept {
  if (size.width == 0 || size.height == 0) {
    return std::nullopt;
  }
  const auto sw = static_cast<std::size_t>(size.width);
  const auto sh = static_cast<std::size_t>(size.height);
  constexpr auto kMax = std::numeric_limits<std::size_t>::max();
  if (sw > kMax / sh) {
    return std::nullopt;
  }
  const std::size_t pixels = sw * sh;
  if (pixels > kMax / 4U) {
    return std::nullopt;
  }
  return pixels * 4U;
}

HeroRgb lerp_rgb(HeroRgb a, HeroRgb b, float t) noexcept {
  const float u = std::clamp(t, 0.0F, 1.0F);
  return HeroRgb{
      .r = clamp_u8(static_cast<float>(a.r) +
                    (static_cast<float>(b.r) - static_cast<float>(a.r)) * u),
      .g = clamp_u8(static_cast<float>(a.g) +
                    (static_cast<float>(b.g) - static_cast<float>(a.g)) * u),
      .b = clamp_u8(static_cast<float>(a.b) +
                    (static_cast<float>(b.b) - static_cast<float>(a.b)) * u),
  };
}

HeroRgb sample_sky(const std::array<HeroRgb, 5> &stops, float t) noexcept {
  const float u = std::clamp(t, 0.0F, 1.0F) * 4.0F;
  const auto idx = static_cast<std::size_t>(std::clamp(std::floor(u), 0.0F, 3.0F));
  const float frac = u - static_cast<float>(idx);
  return lerp_rgb(stops[idx], stops[idx + 1], frac);
}

void blend_pixel(CanvasView cv, PixelPos pos, ColorA col, bool additive) noexcept {
  if (pos.x < 0 || pos.x >= cv.width || pos.y < 0 || pos.y >= cv.height ||
      col.alpha <= 0.001F) {
    return;
  }
  const float a = std::clamp(col.alpha, 0.0F, 1.0F);
  const auto offset =
      (static_cast<std::size_t>(pos.y) * static_cast<std::size_t>(cv.width) +
       static_cast<std::size_t>(pos.x)) *
      4U;
  std::uint8_t *dst = cv.rgba + offset;
  if (additive) {
    dst[0] = clamp_u8(static_cast<float>(dst[0]) + static_cast<float>(col.rgb.r) * a);
    dst[1] = clamp_u8(static_cast<float>(dst[1]) + static_cast<float>(col.rgb.g) * a);
    dst[2] = clamp_u8(static_cast<float>(dst[2]) + static_cast<float>(col.rgb.b) * a);
    dst[3] = 255;
    return;
  }
  if (a >= 0.999F) {
    dst[0] = col.rgb.r;
    dst[1] = col.rgb.g;
    dst[2] = col.rgb.b;
    dst[3] = 255;
    return;
  }
  const float inv = 1.0F - a;
  dst[0] =
      clamp_u8(static_cast<float>(dst[0]) * inv + static_cast<float>(col.rgb.r) * a);
  dst[1] =
      clamp_u8(static_cast<float>(dst[1]) * inv + static_cast<float>(col.rgb.g) * a);
  dst[2] =
      clamp_u8(static_cast<float>(dst[2]) * inv + static_cast<float>(col.rgb.b) * a);
  dst[3] = 255;
}

void blend_span(std::uint8_t *dst, int count, ColorA col, bool additive) noexcept {
  if (count <= 0 || col.alpha <= 0.001F) {
    return;
  }
  const float a = std::clamp(col.alpha, 0.0F, 1.0F);
  if (additive) {
    const int dr = static_cast<int>(static_cast<float>(col.rgb.r) * a + 0.5F);
    const int dg = static_cast<int>(static_cast<float>(col.rgb.g) * a + 0.5F);
    const int db = static_cast<int>(static_cast<float>(col.rgb.b) * a + 0.5F);
    if (dr == 0 && dg == 0 && db == 0) {
      return;
    }
    for (int i = 0; i < count; ++i) {
      dst[0] = static_cast<std::uint8_t>(std::min(255, static_cast<int>(dst[0]) + dr));
      dst[1] = static_cast<std::uint8_t>(std::min(255, static_cast<int>(dst[1]) + dg));
      dst[2] = static_cast<std::uint8_t>(std::min(255, static_cast<int>(dst[2]) + db));
      dst[3] = 255;
      dst += 4;
    }
    return;
  }
  if (a >= 0.999F) {
    const std::uint8_t r = col.rgb.r;
    const std::uint8_t g = col.rgb.g;
    const std::uint8_t b = col.rgb.b;
    for (int i = 0; i < count; ++i) {
      dst[0] = r;
      dst[1] = g;
      dst[2] = b;
      dst[3] = 255;
      dst += 4;
    }
    return;
  }
  const float inv = 1.0F - a;
  const float sr = static_cast<float>(col.rgb.r) * a;
  const float sg = static_cast<float>(col.rgb.g) * a;
  const float sb = static_cast<float>(col.rgb.b) * a;
  for (int i = 0; i < count; ++i) {
    dst[0] = clamp_u8(static_cast<float>(dst[0]) * inv + sr);
    dst[1] = clamp_u8(static_cast<float>(dst[1]) * inv + sg);
    dst[2] = clamp_u8(static_cast<float>(dst[2]) * inv + sb);
    dst[3] = 255;
    dst += 4;
  }
}

void fill_rect(CanvasView cv, RectF rect, ColorA col, bool additive = false) noexcept {
  if (col.alpha <= 0.001F || rect.w <= 0.0F || rect.h <= 0.0F) {
    return;
  }
  const int x0 = std::max(0, static_cast<int>(std::floor(rect.x)));
  const int y0 = std::max(0, static_cast<int>(std::floor(rect.y)));
  const int x1 = std::min(cv.width, static_cast<int>(std::ceil(rect.x + rect.w)));
  const int y1 = std::min(cv.height, static_cast<int>(std::ceil(rect.y + rect.h)));
  if (x0 >= x1 || y0 >= y1) {
    return;
  }
  const int span = x1 - x0;
  for (int y = y0; y < y1; ++y) {
    std::uint8_t *row =
        cv.rgba + (static_cast<std::size_t>(y) * static_cast<std::size_t>(cv.width) +
                   static_cast<std::size_t>(x0)) *
                      4U;
    blend_span(row, span, col, additive);
  }
}

void fill_vgrad_rect(CanvasView cv, RectF rect, VGrad grad) noexcept {
  if (rect.w <= 0.0F || rect.h <= 0.0F) {
    return;
  }
  const int x0 = std::max(0, static_cast<int>(std::floor(rect.x)));
  const int y0 = std::max(0, static_cast<int>(std::floor(rect.y)));
  const int x1 = std::min(cv.width, static_cast<int>(std::ceil(rect.x + rect.w)));
  const int y1 = std::min(cv.height, static_cast<int>(std::ceil(rect.y + rect.h)));
  if (x0 >= x1 || y0 >= y1) {
    return;
  }
  const int span = x1 - x0;
  const float inv_h = 1.0F / std::max(1.0F, rect.h);
  for (int y = y0; y < y1; ++y) {
    const float t = std::clamp((static_cast<float>(y) - rect.y) * inv_h, 0.0F, 1.0F);
    const ColorA col{
        .rgb = lerp_rgb(grad.top, grad.bottom, t),
        .alpha = grad.top_alpha + (grad.bottom_alpha - grad.top_alpha) * t,
    };
    if (col.alpha <= 0.001F) {
      continue;
    }
    std::uint8_t *row =
        cv.rgba + (static_cast<std::size_t>(y) * static_cast<std::size_t>(cv.width) +
                   static_cast<std::size_t>(x0)) *
                      4U;
    blend_span(row, span, col, grad.additive);
  }
}

void stroke_rect(CanvasView cv, RectF rect, ColorA col,
                 bool additive = false) noexcept {
  fill_rect(cv, RectF{.x = rect.x, .y = rect.y, .w = rect.w, .h = 1.0F}, col, additive);
  fill_rect(cv, RectF{.x = rect.x, .y = rect.y + rect.h - 1.0F, .w = rect.w, .h = 1.0F},
            col, additive);
  fill_rect(cv, RectF{.x = rect.x, .y = rect.y, .w = 1.0F, .h = rect.h}, col, additive);
  fill_rect(cv, RectF{.x = rect.x + rect.w - 1.0F, .y = rect.y, .w = 1.0F, .h = rect.h},
            col, additive);
}

void draw_aa_line(CanvasView cv, LineSeg seg, ColorA col, float thickness = 1.0F,
                  bool additive = false) noexcept {
  if (col.alpha <= 0.001F) {
    return;
  }
  const float dx = seg.b.x - seg.a.x;
  const float dy = seg.b.y - seg.a.y;
  const float len2 = dx * dx + dy * dy;
  if (len2 < 1e-6F) {
    blend_pixel(cv,
                PixelPos{.x = static_cast<int>(std::lround(seg.a.x)),
                         .y = static_cast<int>(std::lround(seg.a.y))},
                col, additive);
    return;
  }
  if (thickness <= 1.25F) {
    // Crisp antialiased Xiaolin Wu-style coverage along the dominant axis.
    const bool steep = std::abs(dy) > std::abs(dx);
    float x0 = steep ? seg.a.y : seg.a.x;
    float y0 = steep ? seg.a.x : seg.a.y;
    float x1 = steep ? seg.b.y : seg.b.x;
    float y1 = steep ? seg.b.x : seg.b.y;
    if (x0 > x1) {
      std::swap(x0, x1);
      std::swap(y0, y1);
    }
    const float span = std::max(0.001F, x1 - x0);
    const float grad = (y1 - y0) / span;
    const int ix0 = std::max(0, static_cast<int>(std::floor(x0)));
    const int ix1 =
        std::min((steep ? cv.height : cv.width) - 1, static_cast<int>(std::ceil(x1)));
    for (int ix = ix0; ix <= ix1; ++ix) {
      const float fy = y0 + grad * (static_cast<float>(ix) - x0);
      const int iy = static_cast<int>(std::floor(fy));
      const float frac = fy - static_cast<float>(iy);
      const float a0 = col.alpha * (1.0F - frac);
      const float a1 = col.alpha * frac;
      if (steep) {
        blend_pixel(cv, PixelPos{.x = iy, .y = ix}, ColorA{.rgb = col.rgb, .alpha = a0},
                    additive);
        blend_pixel(cv, PixelPos{.x = iy + 1, .y = ix},
                    ColorA{.rgb = col.rgb, .alpha = a1}, additive);
      } else {
        blend_pixel(cv, PixelPos{.x = ix, .y = iy}, ColorA{.rgb = col.rgb, .alpha = a0},
                    additive);
        blend_pixel(cv, PixelPos{.x = ix, .y = iy + 1},
                    ColorA{.rgb = col.rgb, .alpha = a1}, additive);
      }
    }
    return;
  }
  // Smooth SDF capsule for thick / glowing strokes with squared-distance reject.
  const float half_w = thickness * 0.5F;
  const float reach = half_w + 0.75F;
  const float reach2 = reach * reach;
  const int min_x = std::max(
      0, static_cast<int>(std::floor(std::min(seg.a.x, seg.b.x) - half_w - 1)));
  const int max_x =
      std::min(cv.width - 1,
               static_cast<int>(std::ceil(std::max(seg.a.x, seg.b.x) + half_w + 1)));
  const int min_y = std::max(
      0, static_cast<int>(std::floor(std::min(seg.a.y, seg.b.y) - half_w - 1)));
  const int max_y =
      std::min(cv.height - 1,
               static_cast<int>(std::ceil(std::max(seg.a.y, seg.b.y) + half_w + 1)));
  const float inv_len2 = 1.0F / len2;
  for (int y = min_y; y <= max_y; ++y) {
    const float py = static_cast<float>(y) - seg.a.y;
    for (int x = min_x; x <= max_x; ++x) {
      const float px = static_cast<float>(x) - seg.a.x;
      const float proj = std::clamp((px * dx + py * dy) * inv_len2, 0.0F, 1.0F);
      const float rx = px - proj * dx;
      const float ry = py - proj * dy;
      const float dist2 = rx * rx + ry * ry;
      if (dist2 >= reach2) {
        continue;
      }
      const float dist = std::sqrt(dist2);
      const float cov = std::clamp(reach - dist, 0.0F, 1.0F);
      if (cov > 0.01F) {
        blend_pixel(cv, PixelPos{.x = x, .y = y},
                    ColorA{.rgb = col.rgb, .alpha = col.alpha * cov}, additive);
      }
    }
  }
}

void draw_glow_line(CanvasView cv, LineSeg seg, ColorA col,
                    float glow_radius = 3.2F) noexcept {
  draw_aa_line(cv, seg, ColorA{.rgb = col.rgb, .alpha = col.alpha * 0.24F}, glow_radius,
               true);
  draw_aa_line(cv, seg, col, 1.1F, false);
}

void fill_circle(CanvasView cv, CircleSpec spec, ColorA col,
                 bool additive = false) noexcept {
  if (spec.radius <= 0.0F || col.alpha <= 0.001F) {
    return;
  }
  const float outer = spec.radius + 0.5F;
  const float outer2 = outer * outer;
  const float inner = std::max(0.0F, spec.radius - 0.5F);
  const float inner2 = inner * inner;
  const int min_x =
      std::max(0, static_cast<int>(std::floor(spec.center.x - spec.radius - 1.0F)));
  const int max_x = std::min(
      cv.width - 1, static_cast<int>(std::ceil(spec.center.x + spec.radius + 1.0F)));
  const int min_y =
      std::max(0, static_cast<int>(std::floor(spec.center.y - spec.radius - 1.0F)));
  const int max_y = std::min(
      cv.height - 1, static_cast<int>(std::ceil(spec.center.y + spec.radius + 1.0F)));
  for (int y = min_y; y <= max_y; ++y) {
    const float dy = static_cast<float>(y) - spec.center.y;
    const float dy2 = dy * dy;
    if (dy2 >= outer2) {
      continue;
    }
    for (int x = min_x; x <= max_x; ++x) {
      const float dx = static_cast<float>(x) - spec.center.x;
      const float d2 = dx * dx + dy2;
      if (d2 >= outer2) {
        continue;
      }
      const float cov =
          (d2 <= inner2) ? 1.0F : std::clamp(outer - std::sqrt(d2), 0.0F, 1.0F);
      if (cov > 0.01F) {
        blend_pixel(cv, PixelPos{.x = x, .y = y},
                    ColorA{.rgb = col.rgb, .alpha = col.alpha * cov}, additive);
      }
    }
  }
}

void stroke_circle(CanvasView cv, CircleSpec spec, ColorA col, float thickness = 1.2F,
                   bool additive = false) noexcept {
  if (spec.radius <= 0.0F || col.alpha <= 0.001F) {
    return;
  }
  const float half_w = thickness * 0.5F;
  const float band = half_w + 0.6F;
  const float outer = spec.radius + band;
  const float outer2 = outer * outer;
  const float inner = std::max(0.0F, spec.radius - band);
  const float inner2 = inner * inner;
  const int min_x =
      std::max(0, static_cast<int>(std::floor(spec.center.x - outer - 1.0F)));
  const int max_x =
      std::min(cv.width - 1, static_cast<int>(std::ceil(spec.center.x + outer + 1.0F)));
  const int min_y =
      std::max(0, static_cast<int>(std::floor(spec.center.y - outer - 1.0F)));
  const int max_y = std::min(cv.height - 1,
                             static_cast<int>(std::ceil(spec.center.y + outer + 1.0F)));
  for (int y = min_y; y <= max_y; ++y) {
    const float dy = static_cast<float>(y) - spec.center.y;
    const float dy2 = dy * dy;
    if (dy2 >= outer2) {
      continue;
    }
    for (int x = min_x; x <= max_x; ++x) {
      const float dx = static_cast<float>(x) - spec.center.x;
      const float d2 = dx * dx + dy2;
      if (d2 >= outer2 || d2 <= inner2) {
        continue;
      }
      const float dist = std::abs(std::sqrt(d2) - spec.radius);
      const float cov = std::clamp(band - dist, 0.0F, 1.0F);
      if (cov > 0.01F) {
        blend_pixel(cv, PixelPos{.x = x, .y = y},
                    ColorA{.rgb = col.rgb, .alpha = col.alpha * cov}, additive);
      }
    }
  }
}

void fill_radial_halo(CanvasView cv, RadialGrad grad) noexcept {
  if (grad.outer_r <= grad.inner_r) {
    return;
  }
  const int min_x =
      std::max(0, static_cast<int>(std::floor(grad.center.x - grad.outer_r)));
  const int max_x =
      std::min(cv.width - 1, static_cast<int>(std::ceil(grad.center.x + grad.outer_r)));
  const int min_y =
      std::max(0, static_cast<int>(std::floor(grad.center.y - grad.outer_r)));
  int max_y = std::min(cv.height - 1,
                       static_cast<int>(std::ceil(grad.center.y + grad.outer_r)));
  if (grad.clip_y_max >= 0) {
    max_y = std::min(max_y, grad.clip_y_max);
  }
  const float span = grad.outer_r - grad.inner_r;
  const float outer_r2 = grad.outer_r * grad.outer_r;
  for (int y = min_y; y <= max_y; ++y) {
    const float dy = static_cast<float>(y) - grad.center.y;
    const float dy2 = dy * dy;
    for (int x = min_x; x <= max_x; ++x) {
      const float dx = static_cast<float>(x) - grad.center.x;
      const float d2 = dx * dx + dy2;
      if (d2 >= outer_r2) {
        continue;
      }
      const float d = std::sqrt(d2);
      const float t = std::clamp((d - grad.inner_r) / span, 0.0F, 1.0F);
      const float smooth = (1.0F - t) * (1.0F - t);
      const float a = grad.outer.alpha + (grad.inner.alpha - grad.outer.alpha) * smooth;
      if (a <= 0.002F) {
        continue;
      }
      const HeroRgb rgb = lerp_rgb(grad.inner.rgb, grad.outer.rgb, t);
      blend_pixel(cv, PixelPos{.x = x, .y = y}, ColorA{.rgb = rgb, .alpha = a},
                  grad.additive);
    }
  }
}

void stroke_ellipse_arc(CanvasView cv, ArcSpec spec, ColorA col,
                        bool additive = false) noexcept {
  if (spec.radii.x <= 0.5F || spec.radii.y <= 0.5F || col.alpha <= 0.001F) {
    return;
  }
  const float sweep = spec.end_rad - spec.start_rad;
  if (std::abs(sweep) <= 0.001F) {
    return;
  }
  const int segments =
      std::clamp(static_cast<int>(std::ceil(std::abs(sweep) * 18.0F)), 6, 96);
  Vec2 prev{
      .x = spec.center.x + std::cos(spec.start_rad) * spec.radii.x,
      .y = spec.center.y + std::sin(spec.start_rad) * spec.radii.y,
  };
  for (int i = 1; i <= segments; ++i) {
    const float t = static_cast<float>(i) / static_cast<float>(segments);
    const float ang = spec.start_rad + sweep * t;
    const Vec2 cur{
        .x = spec.center.x + std::cos(ang) * spec.radii.x,
        .y = spec.center.y + std::sin(ang) * spec.radii.y,
    };
    draw_aa_line(cv, LineSeg{.a = prev, .b = cur}, col, spec.thickness, additive);
    prev = cur;
  }
}

void stroke_ellipse(CanvasView cv, EllipseSpec spec, ColorA col, float thickness = 1.5F,
                    bool additive = false) noexcept {
  stroke_ellipse_arc(cv,
                     ArcSpec{.center = spec.center,
                             .radii = spec.radii,
                             .start_rad = 0.0F,
                             .end_rad = std::numbers::pi_v<float> * 2.0F,
                             .thickness = thickness},
                     col, additive);
}

void fill_polygon(CanvasView cv, std::span<const Vec2> pts, ColorA col,
                  bool additive = false) {
  if (pts.size() < 3 || col.alpha <= 0.001F) {
    return;
  }
  float min_yf = pts[0].y;
  float max_yf = pts[0].y;
  for (const auto &p : pts) {
    min_yf = std::min(min_yf, p.y);
    max_yf = std::max(max_yf, p.y);
  }
  const int y0 = std::max(0, static_cast<int>(std::floor(min_yf)));
  const int y1 = std::min(cv.height - 1, static_cast<int>(std::ceil(max_yf)));
  if (y0 > y1) {
    return;
  }
  std::array<float, 64> stack_nodes{};
  std::vector<float> heap_nodes;
  float *nodes = stack_nodes.data();
  if (pts.size() > stack_nodes.size()) {
    heap_nodes.resize(pts.size());
    nodes = heap_nodes.data();
  }
  for (int y = y0; y <= y1; ++y) {
    const float scan_y = static_cast<float>(y) + 0.5F;
    std::size_t node_count = 0;
    std::size_t j = pts.size() - 1;
    for (std::size_t i = 0; i < pts.size(); ++i) {
      const float yi = pts[i].y;
      const float yj = pts[j].y;
      if ((yi < scan_y && yj >= scan_y) || (yj < scan_y && yi >= scan_y)) {
        const float xi = pts[i].x;
        const float xj = pts[j].x;
        nodes[node_count++] = xi + (scan_y - yi) / (yj - yi) * (xj - xi);
      }
      j = i;
    }
    if (node_count < 2U) {
      continue;
    }
    std::sort(nodes, nodes + node_count);
    std::uint8_t *row_base =
        cv.rgba + static_cast<std::size_t>(y) * static_cast<std::size_t>(cv.width) * 4U;
    for (std::size_t i = 0; i + 1 < node_count; i += 2) {
      const int x0 = std::max(0, static_cast<int>(std::floor(nodes[i])));
      const int x1 = std::min(cv.width - 1, static_cast<int>(std::ceil(nodes[i + 1])));
      if (x0 <= x1) {
        blend_span(row_base + static_cast<std::size_t>(x0) * 4U, x1 - x0 + 1, col,
                   additive);
      }
    }
  }
}

void fill_polygon_vgrad(CanvasView cv, std::span<const Vec2> pts, VGrad grad) {
  if (pts.size() < 3) {
    return;
  }
  float min_yf = pts[0].y;
  float max_yf = pts[0].y;
  for (const auto &p : pts) {
    min_yf = std::min(min_yf, p.y);
    max_yf = std::max(max_yf, p.y);
  }
  const int y0 = std::max(0, static_cast<int>(std::floor(min_yf)));
  const int y1 = std::min(cv.height - 1, static_cast<int>(std::ceil(max_yf)));
  if (y0 > y1) {
    return;
  }
  const float inv_span = 1.0F / std::max(1.0F, max_yf - min_yf);
  std::array<float, 64> stack_nodes{};
  std::vector<float> heap_nodes;
  float *nodes = stack_nodes.data();
  if (pts.size() > stack_nodes.size()) {
    heap_nodes.resize(pts.size());
    nodes = heap_nodes.data();
  }
  for (int y = y0; y <= y1; ++y) {
    const float scan_y = static_cast<float>(y) + 0.5F;
    const float t = std::clamp((scan_y - min_yf) * inv_span, 0.0F, 1.0F);
    const ColorA col{
        .rgb = lerp_rgb(grad.top, grad.bottom, t),
        .alpha = grad.top_alpha + (grad.bottom_alpha - grad.top_alpha) * t,
    };
    if (col.alpha <= 0.001F) {
      continue;
    }
    std::size_t node_count = 0;
    std::size_t j = pts.size() - 1;
    for (std::size_t i = 0; i < pts.size(); ++i) {
      const float yi = pts[i].y;
      const float yj = pts[j].y;
      if ((yi < scan_y && yj >= scan_y) || (yj < scan_y && yi >= scan_y)) {
        const float xi = pts[i].x;
        const float xj = pts[j].x;
        nodes[node_count++] = xi + (scan_y - yi) / (yj - yi) * (xj - xi);
      }
      j = i;
    }
    if (node_count < 2U) {
      continue;
    }
    std::sort(nodes, nodes + node_count);
    std::uint8_t *row_base =
        cv.rgba + static_cast<std::size_t>(y) * static_cast<std::size_t>(cv.width) * 4U;
    for (std::size_t i = 0; i + 1 < node_count; i += 2) {
      const int x0 = std::max(0, static_cast<int>(std::floor(nodes[i])));
      const int x1 = std::min(cv.width - 1, static_cast<int>(std::ceil(nodes[i + 1])));
      if (x0 <= x1) {
        blend_span(row_base + static_cast<std::size_t>(x0) * 4U, x1 - x0 + 1, col,
                   grad.additive);
      }
    }
  }
}

void stroke_polygon(CanvasView cv, std::span<const Vec2> pts, ColorA col,
                    bool glow = false) noexcept {
  if (pts.size() < 2) {
    return;
  }
  for (std::size_t i = 0; i < pts.size(); ++i) {
    const Vec2 a = pts[i];
    const Vec2 b = pts[(i + 1) % pts.size()];
    if (glow) {
      draw_glow_line(cv, LineSeg{.a = a, .b = b}, col, 3.0F);
    } else {
      draw_aa_line(cv, LineSeg{.a = a, .b = b}, col, 1.0F, false);
    }
  }
}

// Compact crisp 5x7 uppercase + digit + symbol pixel font (7 rows, low 5 bits).
std::array<std::uint8_t, 7> glyph_5x7(char raw_ch) noexcept {
  const auto ch = static_cast<char>(std::toupper(static_cast<unsigned char>(raw_ch)));
  switch (ch) {
  case 'A':
    return {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11};
  case 'B':
    return {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E};
  case 'C':
    return {0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E};
  case 'D':
    return {0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E};
  case 'E':
    return {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F};
  case 'F':
    return {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10};
  case 'G':
    return {0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0E};
  case 'H':
    return {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11};
  case 'I':
    return {0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E};
  case 'J':
    return {0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0C};
  case 'K':
    return {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11};
  case 'L':
    return {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F};
  case 'M':
    return {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11};
  case 'N':
    return {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11};
  case 'O':
    return {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E};
  case 'P':
    return {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10};
  case 'Q':
    return {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D};
  case 'R':
    return {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11};
  case 'S':
    return {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E};
  case 'T':
    return {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
  case 'U':
    return {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E};
  case 'V':
    return {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04};
  case 'W':
    return {0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11};
  case 'X':
    return {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11};
  case 'Y':
    return {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04};
  case 'Z':
    return {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F};
  case '0':
    return {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E};
  case '1':
    return {0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E};
  case '2':
    return {0x0E, 0x11, 0x01, 0x06, 0x08, 0x10, 0x1F};
  case '3':
    return {0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E};
  case '4':
    return {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02};
  case '5':
    return {0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E};
  case '6':
    return {0x0E, 0x10, 0x10, 0x1E, 0x11, 0x11, 0x0E};
  case '7':
    return {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08};
  case '8':
    return {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E};
  case '9':
    return {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x01, 0x0E};
  case '.':
    return {0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x06};
  case ',':
    return {0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x08};
  case ':':
    return {0x00, 0x06, 0x06, 0x00, 0x06, 0x06, 0x00};
  case ';':
    return {0x00, 0x06, 0x06, 0x00, 0x06, 0x04, 0x08};
  case '!':
    return {0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04};
  case '?':
    return {0x0E, 0x11, 0x01, 0x06, 0x04, 0x00, 0x04};
  case '-':
    return {0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00};
  case '+':
    return {0x00, 0x04, 0x04, 0x1F, 0x04, 0x04, 0x00};
  case '/':
    return {0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10};
  case '_':
    return {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F};
  case '%':
    return {0x19, 0x19, 0x02, 0x04, 0x08, 0x13, 0x13};
  case '[':
    return {0x0E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0E};
  case ']':
    return {0x0E, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0E};
  case '(':
    return {0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02};
  case ')':
    return {0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08};
  case '*':
    return {0x00, 0x15, 0x0E, 0x1F, 0x0E, 0x15, 0x00};
  case '>':
    return {0x10, 0x08, 0x04, 0x02, 0x04, 0x08, 0x10};
  case '<':
    return {0x02, 0x04, 0x08, 0x10, 0x08, 0x04, 0x02};
  case '=':
    return {0x00, 0x00, 0x1F, 0x00, 0x1F, 0x00, 0x00};
  case '#':
    return {0x0A, 0x0A, 0x1F, 0x0A, 0x1F, 0x0A, 0x0A};
  case '|':
    return {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
  case '~':
    return {0x00, 0x08, 0x15, 0x02, 0x00, 0x00, 0x00};
  case '^':
    return {0x04, 0x0A, 0x11, 0x00, 0x00, 0x00, 0x00};
  case '"':
    return {0x0A, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00};
  case '\'':
    return {0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00};
  default:
    return {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  }
}

int measure_text_5x7(std::string_view text, int scale = 1) noexcept {
  if (text.empty()) {
    return 0;
  }
  const int s = std::max(1, scale);
  return static_cast<int>(text.size()) * 6 * s - s;
}

void draw_text_5x7(CanvasView cv, Vec2 pos, std::string_view text,
                   TextStyle style) noexcept {
  if (text.empty() || style.color.alpha <= 0.001F) {
    return;
  }
  const int s = std::max(1, style.scale);
  const int total_w = measure_text_5x7(text, s);
  int cursor_x = static_cast<int>(std::lround(pos.x));
  if (style.center) {
    cursor_x -= total_w / 2;
  } else if (style.right) {
    cursor_x -= total_w;
  }
  const int base_y = static_cast<int>(std::lround(pos.y));
  for (const char ch : text) {
    const auto rows = glyph_5x7(ch);
    for (int ry = 0; ry < 7; ++ry) {
      const std::uint8_t bits = rows[static_cast<std::size_t>(ry)];
      for (int rx = 0; rx < 5; ++rx) {
        if ((bits & (1U << static_cast<unsigned>(4 - rx))) == 0U) {
          continue;
        }
        for (int sy = 0; sy < s; ++sy) {
          for (int sx = 0; sx < s; ++sx) {
            blend_pixel(
                cv, PixelPos{.x = cursor_x + rx * s + sx, .y = base_y + ry * s + sy},
                style.color, style.additive);
          }
        }
      }
    }
    cursor_x += 6 * s;
  }
}

std::string format_compact_tokens(std::uint64_t count) {
  char buf[32]{};
  if (count >= 1'000'000ULL) {
    std::snprintf(buf, sizeof(buf), "%.2fM", static_cast<double>(count) / 1e6);
  } else if (count >= 1'000ULL) {
    std::snprintf(buf, sizeof(buf), "%.1fK", static_cast<double>(count) / 1e3);
  } else {
    std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(count));
  }
  return std::string{buf};
}

std::string format_rate_k(float rate) {
  char buf[32]{};
  std::snprintf(buf, sizeof(buf), "%.1fK", static_cast<double>(rate) / 1000.0);
  return std::string{buf};
}

std::string format_u64(std::uint64_t value) { return std::to_string(value); }

std::string format_int(int value) {
  char buf[32]{};
  std::snprintf(buf, sizeof(buf), "%d", value);
  return std::string{buf};
}

std::string_view env_view(const char *name) noexcept {
  const char *val = std::getenv(name);
  return val ? std::string_view{val} : std::string_view{};
}

// Fast 1D separable 3-tap blur on a low-res RGB float buffer using caller scratch.
struct LowResBuf {
  std::vector<float> *rgb = nullptr;
  std::vector<float> *tmp = nullptr;
  int width = 0;
  int height = 0;
};

void blur_lowres_rgb(LowResBuf buf) noexcept {
  if (buf.width < 3 || buf.height < 3 || buf.rgb == nullptr || buf.tmp == nullptr) {
    return;
  }
  const auto count =
      static_cast<std::size_t>(buf.width) * static_cast<std::size_t>(buf.height) * 3U;
  if (buf.rgb->size() < count || buf.tmp->size() < count) {
    return;
  }
  float *tmp = buf.tmp->data();
  const float *src = buf.rgb->data();
  const auto stride = static_cast<std::size_t>(buf.width) * 3U;
  // Horizontal pass [0.25, 0.5, 0.25]
  for (int y = 0; y < buf.height; ++y) {
    const float *srow = src + static_cast<std::size_t>(y) * stride;
    float *trow = tmp + static_cast<std::size_t>(y) * stride;
    // Left edge (x = 0)
    for (std::size_t c = 0; c < 3; ++c) {
      trow[c] = srow[c] * 0.75F + srow[3U + c] * 0.25F;
    }
    // Interior
    for (int x = 1; x < buf.width - 1; ++x) {
      const auto o = static_cast<std::size_t>(x) * 3U;
      trow[o] = srow[o - 3U] * 0.25F + srow[o] * 0.50F + srow[o + 3U] * 0.25F;
      trow[o + 1U] = srow[o - 2U] * 0.25F + srow[o + 1U] * 0.50F + srow[o + 4U] * 0.25F;
      trow[o + 2U] = srow[o - 1U] * 0.25F + srow[o + 2U] * 0.50F + srow[o + 5U] * 0.25F;
    }
    // Right edge (x = width - 1)
    const auto last = static_cast<std::size_t>(buf.width - 1) * 3U;
    for (std::size_t c = 0; c < 3; ++c) {
      trow[last + c] = srow[last - 3U + c] * 0.25F + srow[last + c] * 0.75F;
    }
  }
  // Vertical pass [0.25, 0.5, 0.25]
  float *dst = buf.rgb->data();
  for (int y = 0; y < buf.height; ++y) {
    const int yu = std::max(0, y - 1);
    const int yd = std::min(buf.height - 1, y + 1);
    float *drow = dst + static_cast<std::size_t>(y) * stride;
    const float *tu = tmp + static_cast<std::size_t>(yu) * stride;
    const float *tc = tmp + static_cast<std::size_t>(y) * stride;
    const float *td = tmp + static_cast<std::size_t>(yd) * stride;
    for (std::size_t k = 0; k < stride; ++k) {
      drow[k] = tu[k] * 0.25F + tc[k] * 0.50F + td[k] * 0.25F;
    }
  }
}

struct UpsampleSpec {
  const std::vector<float> *src = nullptr;
  int src_w = 0;
  int src_h = 0;
  float gain = 1.0F;
};

void upsample_additive(CanvasView cv, UpsampleSpec spec) noexcept {
  if (spec.src == nullptr || spec.src_w < 2 || spec.src_h < 2 || spec.gain <= 0.001F ||
      cv.width <= 0 || cv.height <= 0 || cv.width > static_cast<int>(hero_max_width) ||
      spec.src_h > 256) {
    return;
  }
  const float *s = spec.src->data();
  const auto src_stride = static_cast<std::size_t>(spec.src_w) * 3U;

  // Compute compact per-source-row activity mask so empty rows skip 100% of output
  // work.
  std::array<bool, 256> row_active{};
  bool any_active = false;
  for (int sy = 0; sy < spec.src_h; ++sy) {
    const float *row = s + static_cast<std::size_t>(sy) * src_stride;
    bool active = false;
    for (std::size_t k = 0; k < src_stride; ++k) {
      if (row[k] > 0.05F) {
        active = true;
        break;
      }
    }
    row_active[static_cast<std::size_t>(sy)] = active;
    any_active = any_active || active;
  }
  if (!any_active) {
    return;
  }

  // Precompute horizontal sample offsets and interpolation weights once per call.
  const float sx_scale = static_cast<float>(spec.src_w - 1) /
                         static_cast<float>(std::max(1, cv.width - 1));
  const float sy_scale = static_cast<float>(spec.src_h - 1) /
                         static_cast<float>(std::max(1, cv.height - 1));
  std::array<std::uint16_t, hero_max_width> x0_off{};
  std::array<std::uint16_t, hero_max_width> x1_off{};
  std::array<float, hero_max_width> wx_arr{};
  for (int x = 0; x < cv.width; ++x) {
    const float fx = static_cast<float>(x) * sx_scale;
    const int x0 = static_cast<int>(fx);
    const int x1 = std::min(spec.src_w - 1, x0 + 1);
    const auto ux = static_cast<std::size_t>(x);
    x0_off[ux] = static_cast<std::uint16_t>(x0 * 3);
    x1_off[ux] = static_cast<std::uint16_t>(x1 * 3);
    wx_arr[ux] = fx - static_cast<float>(x0);
  }

  for (int y = 0; y < cv.height; ++y) {
    const float fy = static_cast<float>(y) * sy_scale;
    const int y0 = static_cast<int>(fy);
    const int y1 = std::min(spec.src_h - 1, y0 + 1);
    if (!row_active[static_cast<std::size_t>(y0)] &&
        !row_active[static_cast<std::size_t>(y1)]) {
      continue;
    }
    const float wy = fy - static_cast<float>(y0);
    const float wy0 = (1.0F - wy) * spec.gain;
    const float wy1 = wy * spec.gain;
    const float *s0 = s + static_cast<std::size_t>(y0) * src_stride;
    const float *s1 = s + static_cast<std::size_t>(y1) * src_stride;
    std::uint8_t *dst_row =
        cv.rgba + static_cast<std::size_t>(y) * static_cast<std::size_t>(cv.width) * 4U;
    for (int x = 0; x < cv.width; ++x) {
      const auto ux = static_cast<std::size_t>(x);
      const std::size_t o0 = x0_off[ux];
      const std::size_t o1 = x1_off[ux];
      const float wx = wx_arr[ux];
      const float w1m = 1.0F - wx;
      const float w00 = w1m * wy0;
      const float w10 = wx * wy0;
      const float w01 = w1m * wy1;
      const float w11 = wx * wy1;
      const float r = s0[o0] * w00 + s0[o1] * w10 + s1[o0] * w01 + s1[o1] * w11;
      const float g =
          s0[o0 + 1U] * w00 + s0[o1 + 1U] * w10 + s1[o0 + 1U] * w01 + s1[o1 + 1U] * w11;
      const float b =
          s0[o0 + 2U] * w00 + s0[o1 + 2U] * w10 + s1[o0 + 2U] * w01 + s1[o1 + 2U] * w11;
      if (r > 0.25F || g > 0.25F || b > 0.25F) {
        std::uint8_t *px = dst_row + ux * 4U;
        px[0] = clamp_u8(static_cast<float>(px[0]) + r);
        px[1] = clamp_u8(static_cast<float>(px[1]) + g);
        px[2] = clamp_u8(static_cast<float>(px[2]) + b);
        px[3] = 255;
      }
    }
  }
}

// 3x5 mini code glyphs for Hackerman matrix rain.
constexpr std::array<std::uint16_t, 8> kCodeGlyphs = {
    0b111101101101111U, 0b010110010010111U, 0b111001111100111U, 0b111001011001111U,
    0b101101111001001U, 0b110101110101110U, 0b011100100100011U, 0b010111010111010U,
};

// Exact SR-71 half-planform coordinates (feet) from hero-flight-v24.html:442.
constexpr std::array<Vec2, 14> kSrHalf = {{
    {0.0F, 107.0F},
    {1.2F, 98.0F},
    {2.6F, 88.0F},
    {4.4F, 76.0F},
    {6.2F, 63.0F},
    {7.8F, 50.0F},
    {8.6F, 44.0F},
    {27.8F, 12.5F},
    {27.8F, 10.5F},
    {16.5F, 7.5F},
    {8.4F, 8.5F},
    {3.0F, 5.0F},
    {1.4F, 2.0F},
    {0.0F, -3.0F},
}};

// Per token class flow index: 0 cascade, 1 sweep, 2 fog/atmosphere.
constexpr std::array<std::uint8_t, 6> kClassFlow = {2, 1, 1, 0, 0, 1};

constexpr std::size_t kMaxParticles = 600;
constexpr float kEnergyThreshold = 0.005F;
constexpr float kStaleIdleSeconds = 1.5F;
constexpr float kIdleAmbientTotalRate = 45.0F;
constexpr float kBusyAmbientTotalRate = 320.0F;
constexpr float kIdleAmbientOutRate = 12.0F;
constexpr float kBusyAmbientOutRate = 120.0F;

void append_base64(std::string &out, std::span<const std::uint8_t> bytes) {
  if (bytes.empty()) {
    return;
  }
  constexpr std::string_view kAlpha =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const std::size_t groups = (bytes.size() - 1U) / 3U + 1U;
  const std::size_t old_size = out.size();
  out.resize(old_size + groups * 4U);
  char *dst = out.data() + old_size;
  const std::size_t full_end = (bytes.size() / 3U) * 3U;
  std::size_t i = 0;
  for (; i < full_end; i += 3) {
    const auto a = static_cast<unsigned>(bytes[i]);
    const auto b = static_cast<unsigned>(bytes[i + 1]);
    const auto c = static_cast<unsigned>(bytes[i + 2]);
    dst[0] = kAlpha[a >> 2U];
    dst[1] = kAlpha[((a & 3U) << 4U) | (b >> 4U)];
    dst[2] = kAlpha[((b & 15U) << 2U) | (c >> 6U)];
    dst[3] = kAlpha[c & 63U];
    dst += 4;
  }
  if (i < bytes.size()) {
    const auto a = static_cast<unsigned>(bytes[i]);
    const bool has_b = (i + 1 < bytes.size());
    const auto b = has_b ? static_cast<unsigned>(bytes[i + 1]) : 0U;
    dst[0] = kAlpha[a >> 2U];
    dst[1] = kAlpha[((a & 3U) << 4U) | (b >> 4U)];
    dst[2] = has_b ? kAlpha[(b & 15U) << 2U] : '=';
    dst[3] = '=';
  }
}

void append_u8_dec(std::string &out, std::uint8_t val) {
  if (val >= 100) {
    out += static_cast<char>('0' + (val / 100));
    out += static_cast<char>('0' + ((val / 10) % 10));
    out += static_cast<char>('0' + (val % 10));
  } else if (val >= 10) {
    out += static_cast<char>('0' + (val / 10));
    out += static_cast<char>('0' + (val % 10));
  } else {
    out += static_cast<char>('0' + val);
  }
}

struct RidgeSpec {
  int horizon_y = 0;
  float base = 10.0F;
  float amp = 40.0F;
  float step = 24.0F;
  std::uint32_t seed = 5;
  int width = 480;
};

std::vector<Vec2> build_ridge(RidgeSpec spec) {
  SeededRng rng{.state = spec.seed};
  std::vector<Vec2> pts;
  const float step = std::max(4.0F, spec.step);
  const float span = static_cast<float>(spec.width) + 32.0F;
  const int count = static_cast<int>(std::floor(span / step));
  pts.reserve(static_cast<std::size_t>(count + 1));
  for (int i = 0; i <= count; ++i) {
    const float x = -16.0F + static_cast<float>(i) * step;
    pts.push_back(Vec2{.x = x,
                       .y = static_cast<float>(spec.horizon_y) - spec.base -
                            rng.next() * spec.amp});
  }
  return pts;
}

} // namespace

// ---- Theme API ----

std::string_view hero_theme_name(HeroThemeId theme) noexcept {
  return hero_theme_spec(theme).key;
}

std::optional<HeroThemeId> parse_hero_theme(std::string_view name) noexcept {
  std::array<char, 16> buf{};
  std::size_t len = 0;
  for (const char ch : name) {
    const auto uch = static_cast<unsigned char>(ch);
    if (std::isalnum(uch) != 0) {
      if (len >= 12) {
        return std::nullopt;
      }
      buf[len++] = static_cast<char>(std::tolower(uch));
    }
  }
  const std::string_view norm{buf.data(), len};
  if (norm == "synthwave" || norm == "synth") {
    return HeroThemeId::synthwave;
  }
  if (norm == "tokyonight" || norm == "tokyo") {
    return HeroThemeId::tokyonight;
  }
  if (norm == "gotham") {
    return HeroThemeId::gotham;
  }
  if (norm == "kanagawa" || norm == "fuji") {
    return HeroThemeId::kanagawa;
  }
  if (norm == "nord" || norm == "aurora") {
    return HeroThemeId::nord;
  }
  if (norm == "hackerman" || norm == "matrix" || norm == "wire") {
    return HeroThemeId::hackerman;
  }
  if (norm == "retro82" || norm == "retro") {
    return HeroThemeId::retro82;
  }
  if (norm == "dyingearth" || norm == "qud") {
    return HeroThemeId::dyingearth;
  }
  return std::nullopt;
}

HeroThemeId next_hero_theme(HeroThemeId theme) noexcept {
  const auto idx = static_cast<std::size_t>(theme);
  return static_cast<HeroThemeId>((idx + 1U) % hero_theme_count);
}

const HeroTheme &hero_theme_spec(HeroThemeId theme) noexcept {
  const auto idx = static_cast<std::size_t>(theme);
  if (idx < kThemes.size()) {
    return kThemes[idx];
  }
  return kThemes[0];
}

std::string sanitize_hero_text(std::string_view text, std::size_t max_bytes) {
  const auto skip_csi = [&](std::size_t idx) -> std::size_t {
    while (idx < text.size()) {
      const auto c = static_cast<unsigned char>(text[idx]);
      if (c >= 0x40U && c <= 0x7EU) {
        return idx;
      }
      ++idx;
    }
    return text.size();
  };
  const auto skip_string_seq = [&](std::size_t idx) -> std::size_t {
    while (idx < text.size()) {
      const auto c = static_cast<unsigned char>(text[idx]);
      if (c == 0x07U || c == 0x9CU) {
        return idx;
      }
      if (c == 0x1BU && idx + 1 < text.size() && text[idx + 1] == '\\') {
        return idx + 1;
      }
      if (c == 0xC2U && idx + 1 < text.size() &&
          static_cast<unsigned char>(text[idx + 1]) == 0x9CU) {
        return idx + 1;
      }
      ++idx;
    }
    return text.size();
  };

  std::string out;
  out.reserve(std::min(text.size(), max_bytes));
  for (std::size_t i = 0; i < text.size() && out.size() < max_bytes; ++i) {
    const auto b = static_cast<unsigned char>(text[i]);
    // Strip 7-bit ESC sequences (CSI, OSC, APC, DCS, PM, SOS).
    if (b == 0x1BU) {
      if (i + 1 < text.size()) {
        const char next = text[i + 1];
        if (next == '[') {
          i = skip_csi(i + 2);
        } else if (next == ']' || next == '_' || next == 'P' || next == '^' ||
                   next == 'X') {
          i = skip_string_seq(i + 2);
        } else {
          ++i;
        }
      }
      continue;
    }
    // Strip 8-bit C1 CSI / OSC / APC / DCS / PM / SOS control sequences.
    if (b == 0x9BU) {
      i = skip_csi(i + 1);
      continue;
    }
    if (b == 0x9DU || b == 0x9FU || b == 0x90U || b == 0x9EU || b == 0x98U) {
      i = skip_string_seq(i + 1);
      continue;
    }
    // Strip UTF-8 encoded C1 (U+0080..U+009F) including CSI/OSC/APC/DCS payloads.
    if (b == 0xC2U && i + 1 < text.size()) {
      const auto b2 = static_cast<unsigned char>(text[i + 1]);
      if (b2 == 0x9BU) {
        i = skip_csi(i + 2);
        continue;
      }
      if (b2 == 0x9DU || b2 == 0x9FU || b2 == 0x90U || b2 == 0x9EU || b2 == 0x98U) {
        i = skip_string_seq(i + 2);
        continue;
      }
      if (b2 == 0xB7U) {
        out.push_back('.');
        ++i;
        continue;
      }
      if (b2 >= 0x80U && b2 <= 0x9FU) {
        ++i;
        continue;
      }
    }
    if (b < 0x20U || b == 0x7FU) {
      if (b == '\t' || b == '\n' || b == '\r') {
        if (!out.empty() && out.back() != ' ') {
          out.push_back(' ');
        }
      }
      continue;
    }
    if (b >= 0x80U) {
      continue;
    }
    out.push_back(static_cast<char>(b));
  }
  while (!out.empty() && out.back() == ' ') {
    out.pop_back();
  }
  return out;
}

// ---- HeroParticleSystem ----

HeroParticleSystem::HeroParticleSystem() { reset(HeroSize{}, 11U); }

bool HeroParticleSystem::buffers_valid() const noexcept {
  if (width_ == 0 || height_ == 0 || glow_w_ == 0 || glow_h_ == 0) {
    return false;
  }
  const std::size_t expected_acc =
      static_cast<std::size_t>(width_) * static_cast<std::size_t>(height_) * 3U;
  const std::size_t expected_low =
      static_cast<std::size_t>(glow_w_) * static_cast<std::size_t>(glow_h_) * 3U;
  const std::size_t expected_mat =
      static_cast<std::size_t>(matrix_cols_) * static_cast<std::size_t>(matrix_rows_);
  return acc_.size() == expected_acc && glow_buf_.size() == expected_low &&
         fog_buf_.size() == expected_low && fog_blur_.size() == expected_low &&
         glow_blur_.size() == expected_low && blur_tmp_.size() == expected_low &&
         matrix_bright_.size() == expected_mat && matrix_glyph_.size() == expected_mat;
}

void HeroParticleSystem::reset(HeroSize size, std::uint32_t seed) {
  const auto clamped = clamp_hero_size(size);
  width_ = clamped.width;
  height_ = clamped.height;
  glow_w_ = std::max<std::uint32_t>(16, width_ / 4);
  glow_h_ = std::max<std::uint32_t>(16, height_ / 4);
  rng_state_ = seed == 0 ? 11U : seed;
  sim_t_ = 0.0F;
  idle_stale_seconds_ = 0.0F;
  eff_total_rate_ = kIdleAmbientTotalRate;
  eff_out_rate_ = kIdleAmbientOutRate;
  has_prev_counters_ = false;
  prev_input_ = 0;
  prev_cached_ = 0;
  prev_reasoning_ = 0;
  prev_output_ = 0;
  prev_jev_ = 0;
  burst_backlog_.fill(0.0F);
  owe_.fill(0.0F);
  particles_.clear();
  particles_.reserve(kMaxParticles);
  acc_.assign(static_cast<std::size_t>(width_) * static_cast<std::size_t>(height_) * 3U,
              0.0F);
  const auto low_count =
      static_cast<std::size_t>(glow_w_) * static_cast<std::size_t>(glow_h_) * 3U;
  glow_buf_.assign(low_count, 0.0F);
  fog_buf_.assign(low_count, 0.0F);
  fog_blur_.assign(low_count, 0.0F);
  glow_blur_.assign(low_count, 0.0F);
  blur_tmp_.assign(low_count, 0.0F);
  acc_energy_ = 0.0F;
  glow_energy_ = 0.0F;
  fog_energy_ = 0.0F;
  matrix_energy_ = 0.0F;
  matrix_cols_ = std::max<std::uint32_t>(8, (width_ + 8) / 9);
  matrix_rows_ = std::max<std::uint32_t>(8, (height_ + 10) / 11);
  matrix_bright_.assign(static_cast<std::size_t>(matrix_cols_) *
                            static_cast<std::size_t>(matrix_rows_),
                        0.0F);
  matrix_glyph_.assign(static_cast<std::size_t>(matrix_cols_) *
                           static_cast<std::size_t>(matrix_rows_),
                       0);
}

float HeroParticleSystem::next_random() noexcept {
  rng_state_ = (rng_state_ ^ (rng_state_ >> 15U)) * (1U | rng_state_) + 0x6D2B79F5U;
  return static_cast<float>(rng_state_) / 4294967296.0F;
}

float HeroParticleSystem::next_gauss() noexcept {
  return (next_random() + next_random() + next_random() + next_random() - 2.0F) / 1.15F;
}

void HeroParticleSystem::write_matrix_cell(CellPoint point) {
  if (matrix_cols_ == 0 || matrix_rows_ == 0) {
    return;
  }
  const int c = static_cast<int>(point.x / 9.0F);
  const int r = static_cast<int>(point.y / 11.0F);
  if (c < 0 || c >= static_cast<int>(matrix_cols_) || r < 0 ||
      r >= static_cast<int>(matrix_rows_)) {
    return;
  }
  const auto k = static_cast<std::size_t>(r) * static_cast<std::size_t>(matrix_cols_) +
                 static_cast<std::size_t>(c);
  if (matrix_bright_[k] < 0.6F) {
    matrix_glyph_[k] = static_cast<std::uint8_t>(
        next_random() * static_cast<float>(kCodeGlyphs.size()));
  }
  matrix_bright_[k] = 1.25F;
  matrix_energy_ = std::max(matrix_energy_, 1.25F);
}

void HeroParticleSystem::spawn_particle(SpawnSpec spec, const HeroTheme &theme) {
  if (particles_.size() >= kMaxParticles) {
    return;
  }
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const float floor_y = h * theme.horizon + h * 0.04F;
  const float head_y = 6.0F;
  const float gravity = 18.0F * (h / 300.0F);
  const std::uint8_t cls = std::min<std::uint8_t>(spec.token_class, 5);
  const std::uint8_t flow = kClassFlow[cls];
  const std::uint8_t src = static_cast<std::uint8_t>(spec.source % 7U);

  Particle p{};
  p.source = src;
  p.token_class = cls;
  p.flow = flow;

  if (flow == 0) {
    // Cascade from upper-left arcing across the flight deck.
    const float nx = w * 0.032F;
    const float ny = h * 0.06F;
    const float vy0 = -9.0F * (h / 300.0F);
    const float tf =
        (-vy0 + std::sqrt(vy0 * vy0 + 2.0F * gravity * std::max(10.0F, floor_y - ny))) /
        gravity;
    const float target_x = w * (0.18F + static_cast<float>(src) * 0.115F);
    const float base_vx = (target_x - nx) / std::max(0.5F, tf);
    const float cls_bias = (cls == 4) ? 0.04F : -0.04F;
    p.x = nx + next_gauss() * (w * 0.012F);
    p.y = ny + next_gauss() * (h * 0.028F);
    p.vx = base_vx * (1.0F + cls_bias + next_gauss() * 0.12F);
    p.vy = vy0 + next_gauss() * (h * 0.025F);
  } else if (flow == 1) {
    // Sweep up from lower-left rising toward upper sky.
    const float sx = w * 0.02F;
    const float sy = floor_y - h * 0.05F;
    const float svy0 = 1.5F * (h / 300.0F);
    const float tr = (svy0 + std::sqrt(svy0 * svy0 +
                                       2.0F * gravity * std::max(10.0F, sy - head_y))) /
                     gravity;
    const float target_x = w * (0.42F + static_cast<float>(src) * 0.088F);
    const float base_vx = (target_x - sx) / std::max(0.5F, tr);
    const float cls_bias = (cls == 1) ? -0.05F : (cls == 5 ? 0.0F : 0.03F);
    p.x = sx + next_gauss() * (w * 0.009F);
    p.y = sy + next_gauss() * (h * 0.022F);
    p.vx = base_vx * (1.0F + cls_bias + next_gauss() * 0.10F);
    p.vy = svy0 + next_gauss() * (h * 0.015F);
  } else {
    // Sky atmosphere (cache read): fog / rain / snow / petal / code.
    switch (theme.cr_style) {
    case HeroCacheReadStyle::rain:
      p.x = next_random() * (w + w * 0.22F);
      p.y = head_y + next_random() * 18.0F;
      p.vx = -34.0F * (w / 480.0F);
      p.vy = (165.0F + next_random() * 65.0F) * (h / 300.0F);
      break;
    case HeroCacheReadStyle::snow:
      p.x = next_random() * w;
      p.y = head_y + next_random() * 18.0F;
      p.vx = next_gauss() * 4.0F;
      p.vy = (16.0F + next_random() * 14.0F) * (h / 300.0F);
      break;
    case HeroCacheReadStyle::petal:
      p.x = next_random() * w - 24.0F;
      p.y = head_y + next_random() * 18.0F;
      p.vx = (10.0F + next_random() * 16.0F) * (w / 480.0F);
      p.vy = (18.0F + next_random() * 16.0F) * (h / 300.0F);
      break;
    case HeroCacheReadStyle::code:
      p.x = std::floor(next_random() * static_cast<float>(matrix_cols_)) * 9.0F + 2.0F;
      p.y = head_y + next_random() * 16.0F;
      p.vx = 0.0F;
      p.vy = (70.0F + next_random() * 55.0F) * (h / 300.0F);
      break;
    case HeroCacheReadStyle::fog:
      p.x = next_random() * w;
      p.y = head_y + next_random() * 18.0F;
      p.vx = next_gauss() * 3.0F;
      p.vy = (32.0F + next_random() * 24.0F) * (h / 300.0F);
      break;
    }
  }
  particles_.push_back(p);
}

void HeroParticleSystem::emit_from_telemetry(const HeroTelemetryInput &telemetry,
                                             const HeroTheme &theme, float dt_seconds) {
  if (!buffers_valid() || !std::isfinite(dt_seconds) || dt_seconds <= 0.0F) {
    return;
  }
  const float dt = std::min(dt_seconds, 0.1F);
  const float hit = static_cast<float>(sanitize_cache_hit(telemetry.cache_hit_ratio));
  const float miss = 1.0F - hit;

  // Token quanta per particle (cache read uses coarser quantum so sky stays balanced).
  constexpr std::array<float, 6> kQuanta = {110.0F, 28.0F, 28.0F, 22.0F, 22.0F, 45.0F};

  // Detect monotonic counter movement and stage bounded bursts into a smooth ~0.5s
  // backlog so large counter jumps never dump 288 particles in a single frame spike.
  bool counters_advanced = false;
  if (has_prev_counters_) {
    if (telemetry.cached_tokens > prev_cached_) {
      counters_advanced = true;
      const float d = static_cast<float>(
          std::min<std::uint64_t>(telemetry.cached_tokens - prev_cached_, 50000));
      burst_backlog_[0] = std::min(burst_backlog_[0] + d, kQuanta[0] * 48.0F);
    }
    if (telemetry.input_tokens > prev_input_) {
      counters_advanced = true;
      const float d_in = static_cast<float>(
          std::min<std::uint64_t>(telemetry.input_tokens - prev_input_, 50000));
      burst_backlog_[1] = std::min(burst_backlog_[1] + d_in * 0.2F, kQuanta[1] * 48.0F);
      burst_backlog_[2] = std::min(burst_backlog_[2] + d_in * 0.8F, kQuanta[2] * 48.0F);
    }
    if (telemetry.reasoning_tokens > prev_reasoning_) {
      counters_advanced = true;
      const float d = static_cast<float>(
          std::min<std::uint64_t>(telemetry.reasoning_tokens - prev_reasoning_, 20000));
      burst_backlog_[3] = std::min(burst_backlog_[3] + d, kQuanta[3] * 48.0F);
    }
    if (telemetry.output_tokens > prev_output_) {
      counters_advanced = true;
      const float d = static_cast<float>(
          std::min<std::uint64_t>(telemetry.output_tokens - prev_output_, 20000));
      burst_backlog_[4] = std::min(burst_backlog_[4] + d, kQuanta[4] * 48.0F);
    }
    if (telemetry.jev_calls > prev_jev_) {
      counters_advanced = true;
      const float d = static_cast<float>(
          std::min<std::uint64_t>(telemetry.jev_calls - prev_jev_, 20) * 600ULL);
      burst_backlog_[5] = std::min(burst_backlog_[5] + d, kQuanta[5] * 48.0F);
    }
  }
  has_prev_counters_ = true;
  prev_input_ = telemetry.input_tokens;
  prev_cached_ = telemetry.cached_tokens;
  prev_reasoning_ = telemetry.reasoning_tokens;
  prev_output_ = telemetry.output_tokens;
  prev_jev_ = telemetry.jev_calls;

  // Track staleness when !busy and counters are stationary for > 1.5s: treat stale
  // non-zero incoming rates as zero and smoothly decay down to a crisp ambient cruise.
  if (telemetry.busy || counters_advanced) {
    idle_stale_seconds_ = 0.0F;
  } else {
    idle_stale_seconds_ = std::min(idle_stale_seconds_ + dt, 60.0F);
  }
  const bool stale_idle =
      (!telemetry.busy) && (idle_stale_seconds_ > kStaleIdleSeconds);
  const float live_rate =
      stale_idle ? 0.0F
                 : static_cast<float>(sanitize_rate(telemetry.total_tok_per_sec));
  const float live_out =
      stale_idle ? 0.0F
                 : static_cast<float>(sanitize_rate(telemetry.out_rsn_tok_per_sec));
  const float ambient_base =
      telemetry.busy ? kBusyAmbientTotalRate : kIdleAmbientTotalRate;
  const float out_base = telemetry.busy ? kBusyAmbientOutRate : kIdleAmbientOutRate;
  const float target_total = std::max(ambient_base, live_rate);
  const float target_out = std::max(out_base, live_out);

  // Ramp up immediately for responsive live streaming; decay smoothly when going idle.
  const float decay_alpha = 1.0F - std::exp(-dt * 3.0F);
  if (target_total >= eff_total_rate_) {
    eff_total_rate_ = target_total;
  } else {
    eff_total_rate_ += (target_total - eff_total_rate_) * decay_alpha;
  }
  if (target_out >= eff_out_rate_) {
    eff_out_rate_ = target_out;
  } else {
    eff_out_rate_ += (target_out - eff_out_rate_) * decay_alpha;
  }

  std::array<float, 6> class_tokens{};
  class_tokens[0] = eff_total_rate_ * hit * dt;
  class_tokens[1] = eff_total_rate_ * miss * 0.25F * dt;
  class_tokens[2] = eff_total_rate_ * miss * 0.75F * dt;
  class_tokens[3] = eff_out_rate_ * 0.35F * dt;
  class_tokens[4] = eff_out_rate_ * 0.65F * dt;
  class_tokens[5] = telemetry.busy ? 18.0F * dt : 2.5F * dt;

  // Spread any counter-delta backlog smoothly over ~0.5s.
  const float burst_drain_frac = std::min(1.0F, dt * 2.0F);
  for (std::size_t c = 0; c < 6; ++c) {
    if (burst_backlog_[c] > 0.0F) {
      const float take = (burst_backlog_[c] < 1.0F)
                             ? burst_backlog_[c]
                             : (burst_backlog_[c] * burst_drain_frac);
      burst_backlog_[c] = std::max(0.0F, burst_backlog_[c] - take);
      class_tokens[c] += take;
    }
  }

  const std::size_t active_sources =
      std::clamp<std::size_t>(std::max<std::size_t>(1, telemetry.total_agents), 1, 6);

  for (std::uint8_t c = 0; c < 6; ++c) {
    const float next_owe = std::isfinite(owe_[c]) ? owe_[c] : 0.0F;
    const float add = (std::isfinite(class_tokens[c]) && class_tokens[c] > 0.0F)
                          ? class_tokens[c]
                          : 0.0F;
    owe_[c] = std::min(next_owe + add, kQuanta[c] * 16.0F);
    const int spawn_count =
        std::min(8, static_cast<int>(std::floor(owe_[c] / kQuanta[c])));
    if (spawn_count <= 0) {
      continue;
    }
    owe_[c] = std::max(0.0F, owe_[c] - static_cast<float>(spawn_count) * kQuanta[c]);
    for (int k = 0; k < spawn_count; ++k) {
      const auto src =
          (c == 5) ? static_cast<std::uint8_t>(6)
                   : static_cast<std::uint8_t>(
                         static_cast<std::size_t>(next_random() *
                                                  static_cast<float>(active_sources)) %
                         active_sources);
      spawn_particle(SpawnSpec{.source = src, .token_class = c}, theme);
    }
  }
}

void HeroParticleSystem::step(const HeroTheme &theme, float dt_seconds) {
  if (!buffers_valid() || !std::isfinite(dt_seconds) || dt_seconds <= 0.0F) {
    return;
  }
  const float dt = std::min(dt_seconds, 0.1F);
  sim_t_ += dt;

  // Exponential decay scaled to frame dt (30 fps reference), energy-gated so empty
  // buffers cost zero memory bandwidth.
  const float ticks = dt * 30.0F;
  if (acc_energy_ >= kEnergyThreshold) {
    const float acc_decay = std::pow(0.84F, ticks);
    acc_energy_ *= acc_decay;
    if (acc_energy_ < kEnergyThreshold) {
      std::fill(acc_.begin(), acc_.end(), 0.0F);
      acc_energy_ = 0.0F;
    } else {
      float *p = acc_.data();
      const std::size_t n = acc_.size();
      for (std::size_t idx = 0; idx < n; ++idx) {
        p[idx] *= acc_decay;
      }
    }
  }
  if (glow_energy_ >= kEnergyThreshold) {
    const float glow_decay = std::pow(0.945F, ticks);
    glow_energy_ *= glow_decay;
    if (glow_energy_ < kEnergyThreshold) {
      std::fill(glow_buf_.begin(), glow_buf_.end(), 0.0F);
      glow_energy_ = 0.0F;
    } else {
      float *p = glow_buf_.data();
      const std::size_t n = glow_buf_.size();
      for (std::size_t idx = 0; idx < n; ++idx) {
        p[idx] *= glow_decay;
      }
    }
  }
  if (fog_energy_ >= kEnergyThreshold) {
    const float fog_decay = std::pow(0.925F, ticks);
    fog_energy_ *= fog_decay;
    if (fog_energy_ < kEnergyThreshold) {
      std::fill(fog_buf_.begin(), fog_buf_.end(), 0.0F);
      fog_energy_ = 0.0F;
    } else {
      float *p = fog_buf_.data();
      const std::size_t n = fog_buf_.size();
      for (std::size_t idx = 0; idx < n; ++idx) {
        p[idx] *= fog_decay;
      }
    }
  }
  if (theme.cr_style == HeroCacheReadStyle::code &&
      matrix_energy_ >= kEnergyThreshold) {
    const float mat_decay = std::pow(0.935F, ticks);
    float peak_mat = 0.0F;
    for (std::size_t k = 0; k < matrix_bright_.size(); ++k) {
      if (matrix_bright_[k] < 0.03F) {
        matrix_bright_[k] = 0.0F;
        continue;
      }
      matrix_bright_[k] *= mat_decay;
      peak_mat = std::max(peak_mat, matrix_bright_[k]);
      if (next_random() < 0.004F) {
        matrix_glyph_[k] = static_cast<std::uint8_t>(
            next_random() * static_cast<float>(kCodeGlyphs.size()));
      }
    }
    matrix_energy_ = peak_mat;
  }

  const auto w = static_cast<int>(width_);
  const auto h = static_cast<int>(height_);
  const float floor_y =
      static_cast<float>(h) * theme.horizon + static_cast<float>(h) * 0.04F;
  const float gravity = 18.0F * (static_cast<float>(h) / 300.0F);
  const float drag = std::max(0.0F, 1.0F - 0.02F * dt);
  float *acc_data = acc_.data();
  float *glow_data = glow_buf_.data();
  float *fog_data = fog_buf_.data();

  std::size_t i = particles_.size();
  while (i > 0) {
    --i;
    Particle &p = particles_[i];
    if (p.flow == 0) {
      p.vy += gravity * dt;
    } else if (p.flow == 1) {
      p.vy -= gravity * dt;
    } else {
      if (theme.cr_style == HeroCacheReadStyle::snow ||
          theme.cr_style == HeroCacheReadStyle::petal) {
        p.vy += gravity * 0.02F * dt;
      } else if (theme.cr_style == HeroCacheReadStyle::fog) {
        p.vy += gravity * 0.05F * dt;
      }
    }
    p.vx *= drag;
    float sway = 0.0F;
    if (p.flow == 2) {
      if (theme.cr_style == HeroCacheReadStyle::petal) {
        sway = std::sin(p.y * 0.05F + static_cast<float>(i)) * 0.55F;
      } else if (theme.cr_style == HeroCacheReadStyle::snow) {
        sway = std::sin(p.y * 0.03F + static_cast<float>(i) * 0.7F) * 0.35F;
      } else if (theme.cr_style == HeroCacheReadStyle::fog) {
        sway = std::sin(p.y * 0.02F + static_cast<float>(i) * 0.7F) * 0.22F;
      }
    } else {
      sway = std::sin(p.y * 0.03F + static_cast<float>(i)) * 0.08F;
    }
    p.x += p.vx * dt + sway;
    p.y += p.vy * dt;

    const int xi = static_cast<int>(p.x);
    const int yi = static_cast<int>(p.y);
    if (xi < 0 || xi >= w || p.y >= floor_y - 1.0F || p.y < 1.0F) {
      particles_[i] = particles_.back();
      particles_.pop_back();
      continue;
    }

    const HeroRgb col = theme.cls[p.token_class];
    const auto gx =
        std::min<std::uint32_t>(glow_w_ - 1, static_cast<std::uint32_t>(xi) >> 2U);
    const auto gy =
        std::min<std::uint32_t>(glow_h_ - 1, static_cast<std::uint32_t>(yi) >> 2U);
    const auto go = (static_cast<std::size_t>(gy) * static_cast<std::size_t>(glow_w_) +
                     static_cast<std::size_t>(gx)) *
                    3U;

    if (p.flow == 2) {
      switch (theme.cr_style) {
      case HeroCacheReadStyle::snow: {
        const float dr = static_cast<float>(col.r) * 0.42F;
        const float dg = static_cast<float>(col.g) * 0.42F;
        const float db = static_cast<float>(col.b) * 0.42F;
        for (int dy = 0; dy < 3; ++dy) {
          const int yy = yi + dy;
          if (yy >= h) {
            break;
          }
          for (int dx = 0; dx < 3; ++dx) {
            if ((dx == 0 || dx == 2) && (dy == 0 || dy == 2)) {
              continue;
            }
            const int xx = xi + dx;
            if (xx < w) {
              const auto o =
                  (static_cast<std::size_t>(yy) * static_cast<std::size_t>(w) +
                   static_cast<std::size_t>(xx)) *
                  3U;
              acc_data[o] += dr;
              acc_data[o + 1] += dg;
              acc_data[o + 2] += db;
              acc_energy_ = std::max(
                  {acc_energy_, acc_data[o], acc_data[o + 1], acc_data[o + 2]});
            }
          }
        }
        break;
      }
      case HeroCacheReadStyle::petal: {
        const bool flip =
            ((static_cast<int>(p.y * 0.08F) + static_cast<int>(i)) & 1) != 0;
        const int pw = flip ? 4 : 2;
        const int ph = flip ? 2 : 4;
        const float dr = static_cast<float>(col.r) * 0.48F;
        const float dg = static_cast<float>(col.g) * 0.48F;
        const float db = static_cast<float>(col.b) * 0.48F;
        for (int dy = 0; dy < ph; ++dy) {
          const int yy = yi + dy;
          if (yy >= h) {
            break;
          }
          for (int dx = 0; dx < pw; ++dx) {
            const int xx = xi + dx;
            if (xx < w) {
              const auto o =
                  (static_cast<std::size_t>(yy) * static_cast<std::size_t>(w) +
                   static_cast<std::size_t>(xx)) *
                  3U;
              acc_data[o] += dr;
              acc_data[o + 1] += dg;
              acc_data[o + 2] += db;
              acc_energy_ = std::max(
                  {acc_energy_, acc_data[o], acc_data[o + 1], acc_data[o + 2]});
            }
          }
        }
        break;
      }
      case HeroCacheReadStyle::code: {
        write_matrix_cell(CellPoint{.x = p.x, .y = p.y});
        break;
      }
      case HeroCacheReadStyle::rain: {
        const float dr = static_cast<float>(col.r) * 0.22F;
        const float dg = static_cast<float>(col.g) * 0.22F;
        const float db = static_cast<float>(col.b) * 0.22F;
        for (int k = 0; k < 10; ++k) {
          const int xx = xi + static_cast<int>(static_cast<float>(k) * 0.14F);
          const int yy = yi - k;
          if (yy < 0 || xx < 0 || xx >= w) {
            break;
          }
          const auto o = (static_cast<std::size_t>(yy) * static_cast<std::size_t>(w) +
                          static_cast<std::size_t>(xx)) *
                         3U;
          acc_data[o] += dr;
          acc_data[o + 1] += dg;
          acc_data[o + 2] += db;
          acc_energy_ =
              std::max({acc_energy_, acc_data[o], acc_data[o + 1], acc_data[o + 2]});
        }
        break;
      }
      case HeroCacheReadStyle::fog: {
        constexpr float kFogAlpha = 0.09F;
        fog_data[go] += static_cast<float>(col.r) * kFogAlpha;
        fog_data[go + 1] += static_cast<float>(col.g) * kFogAlpha;
        fog_data[go + 2] += static_cast<float>(col.b) * kFogAlpha;
        fog_energy_ =
            std::max({fog_energy_, fog_data[go], fog_data[go + 1], fog_data[go + 2]});
        break;
      }
      }
      continue;
    }

    // Flow 0 & 1: team-colored low-res additive glow + crisp 2x2 token core.
    const HeroRgb tm = theme.team[p.source];
    glow_data[go] += static_cast<float>(tm.r) * 0.11F;
    glow_data[go + 1] += static_cast<float>(tm.g) * 0.11F;
    glow_data[go + 2] += static_cast<float>(tm.b) * 0.11F;
    glow_energy_ =
        std::max({glow_energy_, glow_data[go], glow_data[go + 1], glow_data[go + 2]});

    constexpr float kCoreAlpha = 0.52F;
    const float cr = static_cast<float>(col.r) * kCoreAlpha;
    const float cg = static_cast<float>(col.g) * kCoreAlpha;
    const float cb = static_cast<float>(col.b) * kCoreAlpha;
    for (int dy = 0; dy < 2; ++dy) {
      const int yy = yi + dy;
      if (yy >= h) {
        break;
      }
      for (int dx = 0; dx < 2; ++dx) {
        const int xx = xi + dx;
        if (xx < w) {
          const auto o = (static_cast<std::size_t>(yy) * static_cast<std::size_t>(w) +
                          static_cast<std::size_t>(xx)) *
                         3U;
          acc_data[o] += cr;
          acc_data[o + 1] += cg;
          acc_data[o + 2] += cb;
          acc_energy_ =
              std::max({acc_energy_, acc_data[o], acc_data[o + 1], acc_data[o + 2]});
        }
      }
    }
  }
}

void HeroParticleSystem::composite(std::vector<std::uint8_t> &rgba,
                                   const HeroTheme &theme) const {
  const auto expected_rgba =
      checked_rgba_bytes(HeroSize{.width = width_, .height = height_});
  if (!buffers_valid() || !expected_rgba.has_value() || rgba.size() != *expected_rgba) {
    return;
  }
  CanvasView cv{
      .rgba = rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  // Energy-gated blurred additive fog + team glow upsampled from W/4 x H/4 using
  // preallocated scratch buffers; skip completely when peak energy < 0.005F.
  const int gw = static_cast<int>(glow_w_);
  const int gh = static_cast<int>(glow_h_);
  if (fog_energy_ >= kEnergyThreshold) {
    std::memcpy(fog_blur_.data(), fog_buf_.data(), fog_buf_.size() * sizeof(float));
    blur_lowres_rgb(
        LowResBuf{.rgb = &fog_blur_, .tmp = &blur_tmp_, .width = gw, .height = gh});
    upsample_additive(
        cv, UpsampleSpec{.src = &fog_blur_, .src_w = gw, .src_h = gh, .gain = 0.90F});
  }
  if (glow_energy_ >= kEnergyThreshold) {
    std::memcpy(glow_blur_.data(), glow_buf_.data(), glow_buf_.size() * sizeof(float));
    blur_lowres_rgb(
        LowResBuf{.rgb = &glow_blur_, .tmp = &blur_tmp_, .width = gw, .height = gh});
    blur_lowres_rgb(
        LowResBuf{.rgb = &glow_blur_, .tmp = &blur_tmp_, .width = gw, .height = gh});
    upsample_additive(cv, UpsampleSpec{.src = &glow_blur_,
                                       .src_w = gw,
                                       .src_h = gh,
                                       .gain = 0.65F + theme.bloom * 0.55F});
  }

  // Hackerman matrix glyph overlay (energy-gated).
  if (theme.cr_style == HeroCacheReadStyle::code &&
      matrix_energy_ >= kEnergyThreshold && matrix_cols_ > 0 && matrix_rows_ > 0) {
    const HeroRgb head_col = rgb_hex(0xe8fff0);
    const HeroRgb tail_col = theme.cls[0];
    for (std::uint32_t r = 0; r < matrix_rows_; ++r) {
      for (std::uint32_t c = 0; c < matrix_cols_; ++c) {
        const auto k =
            static_cast<std::size_t>(r) * static_cast<std::size_t>(matrix_cols_) +
            static_cast<std::size_t>(c);
        const float b = matrix_bright_[k];
        if (b < 0.04F) {
          continue;
        }
        const bool is_head = b > 1.05F;
        const ColorA col{
            .rgb = is_head ? head_col : tail_col,
            .alpha = std::min(1.0F, is_head ? 1.0F : b * 0.85F),
        };
        const std::uint16_t bits =
            kCodeGlyphs[static_cast<std::size_t>(matrix_glyph_[k]) %
                        kCodeGlyphs.size()];
        const int bx = static_cast<int>(c * 9U + 2U);
        const int by = static_cast<int>(r * 11U + 2U);
        for (int bit = 0; bit < 15; ++bit) {
          if (((bits >> static_cast<unsigned>(bit)) & 1U) == 0U) {
            continue;
          }
          const int dx = (bit % 3) * 2;
          const int dy = (bit / 3) * 2;
          blend_pixel(cv, PixelPos{.x = bx + dx, .y = by + dy}, col, true);
          blend_pixel(cv, PixelPos{.x = bx + dx + 1, .y = by + dy}, col, true);
        }
      }
    }
  }

  // Composite full-resolution particle trail buffer (energy-gated).
  if (acc_energy_ < 1.0F) {
    return;
  }
  const std::size_t total_px =
      static_cast<std::size_t>(width_) * static_cast<std::size_t>(height_);
  const float bloom_boost = 1.0F + theme.bloom * 0.45F;
  constexpr float kInv255 = 1.0F / 255.0F;
  const float *acc_ptr = acc_.data();
  std::uint8_t *dst = rgba.data();
  for (std::size_t p = 0; p < total_px; ++p) {
    const float r = acc_ptr[0];
    const float g = acc_ptr[1];
    const float b = acc_ptr[2];
    acc_ptr += 3;
    const float m = std::max({r, g, b});
    if (m >= 1.0F) {
      const float k = 255.0F / std::max(m, 255.0F);
      const float a = std::min(235.0F, m * 1.1F) * kInv255;
      const float inv = 1.0F - a * 0.55F;
      const float scale = k * a * bloom_boost;
      dst[0] = clamp_u8(static_cast<float>(dst[0]) * inv + r * scale);
      dst[1] = clamp_u8(static_cast<float>(dst[1]) * inv + g * scale);
      dst[2] = clamp_u8(static_cast<float>(dst[2]) * inv + b * scale);
      dst[3] = 255;
    }
    dst += 4;
  }
}

// ---- HeroFlightDeckEngine ----

HeroFlightDeckEngine::HeroFlightDeckEngine(HeroCanvasConfig config)
    : theme_(config.theme), seed_(config.seed == 0 ? 11U : config.seed),
      visual_rng_(seed_) {
  const auto clamped = clamp_hero_size(config.size);
  width_ = clamped.width;
  height_ = clamped.height;
  frame_.width = width_;
  frame_.height = height_;
  frame_.rgba.assign(
      static_cast<std::size_t>(width_) * static_cast<std::size_t>(height_) * 4U, 255);
  reset(seed_);
}

void HeroFlightDeckEngine::reset(std::uint32_t seed) {
  seed_ = seed == 0 ? 11U : seed;
  visual_rng_ = seed_;
  static_bg_valid_ = false;
  sim_t_ = 0.0F;
  grid_off_ = 0.0F;
  grid_n_ = 0;
  has_prev_engine_counters_ = false;
  prev_eng_input_ = 0;
  prev_eng_cached_ = 0;
  prev_eng_reasoning_ = 0;
  prev_eng_output_ = 0;
  prev_eng_jev_ = 0;
  engine_idle_stale_seconds_ = 0.0F;
  smooth_rate_ = kIdleAmbientTotalRate;
  prev_rate_ = kIdleAmbientTotalRate;
  smooth_out_rate_ = kIdleAmbientOutRate;
  smooth_miss_ = 0.15F;
  stx_ = 0.0F;
  sty_ = 0.0F;
  svx_ = 0.0F;
  svy_ = 0.0F;
  bank_rad_ = 0.0F;
  jev_seen_ = telemetry_.jev_calls;
  beacon_flash_ = 0.0F;
  searchlight_phase_ = {0.0F, 1.3F, 2.6F, 3.9F, 5.2F, 6.5F};
  particles_.reset(HeroSize{.width = width_, .height = height_}, seed_);
  // Warm up a tiny deterministic stream so frame 0 already feels alive.
  const HeroTheme &spec = hero_theme_spec(theme_);
  for (int i = 0; i < 8; ++i) {
    particles_.emit_from_telemetry(telemetry_, spec, 1.0F / 30.0F);
    particles_.step(spec, 1.0F / 30.0F);
  }
}

void HeroFlightDeckEngine::resize(HeroSize size) {
  const auto clamped = clamp_hero_size(size);
  if (clamped.width == width_ && clamped.height == height_) {
    return;
  }
  width_ = clamped.width;
  height_ = clamped.height;
  static_bg_valid_ = false;
  frame_.width = width_;
  frame_.height = height_;
  frame_.rgba.assign(
      static_cast<std::size_t>(width_) * static_cast<std::size_t>(height_) * 4U, 255);
  particles_.reset(clamped, seed_);
  rebuild_gate_layout();
}

void HeroFlightDeckEngine::set_theme(HeroThemeId theme) {
  if (theme_ != theme) {
    theme_ = theme;
    static_bg_valid_ = false;
  }
}

void HeroFlightDeckEngine::cycle_theme() {
  theme_ = next_hero_theme(theme_);
  static_bg_valid_ = false;
}

void HeroFlightDeckEngine::set_telemetry(const HeroTelemetryInput &telemetry) {
  telemetry_ = telemetry;
}

void HeroFlightDeckEngine::steer_input(const HeroControlInput &input) {
  control_ = input;
}

void HeroFlightDeckEngine::set_question(std::optional<HeroQuestion> question) {
  if (!question.has_value() || question->options.empty()) {
    question_.reset();
    gates_.clear();
    return;
  }
  ActiveQuestion active{};
  active.from = sanitize_hero_text(question->from, 20);
  if (active.from.empty()) {
    active.from = "main";
  }
  active.text = sanitize_hero_text(question->text, 44);
  active.detail = sanitize_hero_text(question->detail, 54);
  const std::size_t opt_count = std::min<std::size_t>(3, question->options.size());
  active.options.reserve(opt_count);
  for (std::size_t i = 0; i < opt_count; ++i) {
    auto label = sanitize_hero_text(question->options[i], 18);
    if (label.empty()) {
      label = "OPT " + format_int(static_cast<int>(i + 1));
    }
    active.options.push_back(std::move(label));
  }
  answered_index_.reset();
  question_ = std::move(active);
  rebuild_gate_layout();
}

void HeroFlightDeckEngine::rebuild_gate_layout() {
  gates_.clear();
  if (!question_.has_value()) {
    return;
  }
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const float radius = std::clamp(std::min(w, h) * 0.115F, 18.0F, 44.0F);
  const std::size_t n = question_->options.size();
  std::array<Vec2, 3> coords{};
  if (n == 1) {
    coords[0] = Vec2{.x = w * 0.50F, .y = h * 0.68F};
  } else if (n == 2) {
    coords[0] = Vec2{.x = w * 0.20F, .y = h * 0.30F};
    coords[1] = Vec2{.x = w * 0.80F, .y = h * 0.30F};
  } else {
    coords[0] = Vec2{.x = w * 0.18F, .y = h * 0.30F};
    coords[1] = Vec2{.x = w * 0.82F, .y = h * 0.30F};
    coords[2] = Vec2{.x = w * 0.50F, .y = h * 0.68F};
  }
  gates_.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    gates_.push_back(HeroGateState{
        .label = question_->options[i],
        .x = coords[i].x,
        .y = coords[i].y,
        .radius = radius,
        .dwell_seconds = 0.0F,
    });
  }
}

void HeroFlightDeckEngine::finish_question(std::size_t option_index,
                                           std::string_view how) {
  if (!question_.has_value() || question_->done ||
      option_index >= question_->options.size()) {
    return;
  }
  question_->done = true;
  question_->pick = option_index;
  question_->flash = 1.0F;
  answered_index_ = option_index;
  std::string entry = question_->from + ": " + question_->text + " -> " +
                      question_->options[option_index] + " (" + std::string{how} + ")";
  answer_log_.insert(answer_log_.begin(), sanitize_hero_text(entry, 64));
  if (answer_log_.size() > 3) {
    answer_log_.resize(3);
  }
}

bool HeroFlightDeckEngine::answer_by_key(std::size_t option_index) {
  if (!question_.has_value() || question_->done ||
      option_index >= question_->options.size()) {
    return false;
  }
  finish_question(option_index, "key");
  return true;
}

std::optional<std::size_t> HeroFlightDeckEngine::take_answered_index() noexcept {
  auto out = answered_index_;
  answered_index_.reset();
  return out;
}

HeroPlaneState HeroFlightDeckEngine::plane_state() const noexcept {
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const float cx = w * 0.52F + std::sin(sim_t_ * 0.11F) * (w * 0.015F) + stx_;
  const float cy = h * 0.48F + std::sin(sim_t_ * 0.60F) * (h * 0.008F) + sty_;
  return HeroPlaneState{
      .x = cx,
      .y = cy,
      .offset_x = stx_,
      .offset_y = sty_,
      .vx = svx_,
      .vy = svy_,
      .bank_rad = bank_rad_,
  };
}

void HeroFlightDeckEngine::step(float dt_seconds) {
  if (!std::isfinite(dt_seconds) || dt_seconds <= 0.0F) {
    return;
  }
  // Sub-step large deltas so critically damped spring and 1.5s dwell stay accurate.
  float remaining = std::min(dt_seconds, 5.0F);
  constexpr float kMaxStep = 1.0F / 30.0F;
  while (remaining > 0.0001F) {
    const float sub = std::min(remaining, kMaxStep);
    step_substep(sub);
    remaining -= sub;
  }
}

void HeroFlightDeckEngine::step_substep(float dt_seconds) {
  if (!std::isfinite(dt_seconds) || dt_seconds <= 0.0F) {
    return;
  }
  sim_t_ += dt_seconds;

  // Track counter staleness when idle so stale non-zero rates smoothly decay down
  // to a crisp ambient cruise instead of driving maxed ground speed and afterburners.
  bool eng_counters_advanced = false;
  if (has_prev_engine_counters_) {
    eng_counters_advanced = (telemetry_.input_tokens > prev_eng_input_) ||
                            (telemetry_.cached_tokens > prev_eng_cached_) ||
                            (telemetry_.reasoning_tokens > prev_eng_reasoning_) ||
                            (telemetry_.output_tokens > prev_eng_output_) ||
                            (telemetry_.jev_calls > prev_eng_jev_);
  }
  has_prev_engine_counters_ = true;
  prev_eng_input_ = telemetry_.input_tokens;
  prev_eng_cached_ = telemetry_.cached_tokens;
  prev_eng_reasoning_ = telemetry_.reasoning_tokens;
  prev_eng_output_ = telemetry_.output_tokens;
  prev_eng_jev_ = telemetry_.jev_calls;

  if (telemetry_.busy || eng_counters_advanced) {
    engine_idle_stale_seconds_ = 0.0F;
  } else {
    engine_idle_stale_seconds_ =
        std::min(engine_idle_stale_seconds_ + dt_seconds, 60.0F);
  }
  const bool eng_stale_idle =
      (!telemetry_.busy) && (engine_idle_stale_seconds_ > kStaleIdleSeconds);

  // Smooth telemetry signals.
  const float raw_rate =
      eng_stale_idle ? 0.0F
                     : static_cast<float>(sanitize_rate(telemetry_.total_tok_per_sec));
  const float raw_out =
      eng_stale_idle
          ? 0.0F
          : static_cast<float>(sanitize_rate(telemetry_.out_rsn_tok_per_sec));
  const float target_rate = std::max(
      telemetry_.busy ? kBusyAmbientTotalRate : kIdleAmbientTotalRate, raw_rate);
  const float target_out =
      std::max(telemetry_.busy ? kBusyAmbientOutRate : kIdleAmbientOutRate, raw_out);
  const float target_miss =
      1.0F - static_cast<float>(sanitize_cache_hit(telemetry_.cache_hit_ratio));
  const float rate_alpha = std::min(1.0F, dt_seconds * 4.0F);
  prev_rate_ = smooth_rate_;
  smooth_rate_ += (target_rate - smooth_rate_) * rate_alpha;
  smooth_out_rate_ += (target_out - smooth_out_rate_) * rate_alpha;
  smooth_miss_ += (target_miss - smooth_miss_) * rate_alpha;

  // Perspective grid scrolling driven by total token rate.
  grid_off_ += dt_seconds * std::min(6.0F, 0.15F + smooth_rate_ / 9000.0F);
  while (grid_off_ >= 1.0F) {
    grid_off_ -= 1.0F;
    ++grid_n_;
  }

  // Jev beacon pulse.
  if (telemetry_.jev_calls != jev_seen_) {
    jev_seen_ = telemetry_.jev_calls;
    beacon_flash_ = 1.0F;
  } else {
    beacon_flash_ = std::max(0.0F, beacon_flash_ - dt_seconds * 0.65F);
  }

  // Gotham searchlight sweep phases.
  const float sweep_speed = 0.12F + std::min(1.5F, smooth_rate_ / 15000.0F);
  for (std::size_t i = 0; i < searchlight_phase_.size(); ++i) {
    searchlight_phase_[i] +=
        dt_seconds * sweep_speed * (0.85F + 0.07F * static_cast<float>(i));
  }

  // Flight controls: critically damped spring return to cruise when released.
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  float ax = 0.0F;
  float ay = 0.0F;
  if (control_.left) {
    ax -= 1.0F;
  }
  if (control_.right) {
    ax += 1.0F;
  }
  if (control_.up) {
    ay -= 1.0F;
  }
  if (control_.down) {
    ay += 1.0F;
  }
  const float stick_x = sanitize_stick(control_.stick_x);
  const float stick_y = sanitize_stick(control_.stick_y);
  if (std::abs(stick_x) >= 0.15F) {
    ax += stick_x;
  }
  if (std::abs(stick_y) >= 0.15F) {
    ay += stick_y;
  }
  ax = std::clamp(ax, -1.0F, 1.0F);
  ay = std::clamp(ay, -1.0F, 1.0F);

  const bool held = (std::abs(ax) > 0.001F) || (std::abs(ay) > 0.001F);
  const float speed_x = w * 0.54F;
  const float speed_y = h * 0.54F;
  if (held) {
    const float blend = std::min(1.0F, dt_seconds * 6.0F);
    svx_ += (ax * speed_x - svx_) * blend;
    svy_ += (ay * speed_y - svy_) * blend;
  } else {
    constexpr float kSpring = 28.0F;
    const float damping = 2.0F * std::sqrt(kSpring);
    svx_ += (-kSpring * stx_ - damping * svx_) * dt_seconds;
    svy_ += (-kSpring * sty_ - damping * svy_) * dt_seconds;
  }
  stx_ = std::clamp(stx_ + svx_ * dt_seconds, -w * 0.44F, w * 0.42F);
  sty_ = std::clamp(sty_ + svy_ * dt_seconds, -h * 0.38F, h * 0.34F);

  // Live roll bank responding to steering velocity + throughput delta.
  const float d_rate = smooth_rate_ - prev_rate_;
  const float target_bank = std::clamp(-d_rate / 3500.0F, -0.22F, 0.22F) +
                            std::clamp(svx_ / std::max(1.0F, w * 0.80F), -0.60F, 0.60F);
  bank_rad_ = bank_rad_ * 0.90F + target_bank * 0.10F;

  // Update active question dwell & confirmation flash.
  if (question_.has_value()) {
    question_->elapsed += dt_seconds;
    if (!question_->done) {
      const auto plane = plane_state();
      for (std::size_t i = 0; i < gates_.size(); ++i) {
        HeroGateState &gt = gates_[i];
        const float dist = std::hypot(plane.x - gt.x, plane.y - gt.y);
        if (dist < gt.radius) {
          gt.dwell_seconds += dt_seconds;
          if (gt.dwell_seconds >= hero_gate_dwell_seconds) {
            finish_question(i, "flight");
            break;
          }
        } else {
          gt.dwell_seconds = std::max(0.0F, gt.dwell_seconds - dt_seconds * 2.5F);
        }
      }
    } else {
      question_->flash = std::max(0.0F, question_->flash - dt_seconds * 0.8F);
      if (question_->flash <= 0.0F) {
        question_.reset();
        gates_.clear();
      }
    }
  }

  // Particle token shower physics.
  const HeroTheme &spec = hero_theme_spec(theme_);
  particles_.emit_from_telemetry(telemetry_, spec, dt_seconds);
  particles_.step(spec, dt_seconds);
}

void HeroFlightDeckEngine::draw_sun_static(std::uint8_t *rgba, const HeroTheme &spec,
                                           int horizon_y) const {
  CanvasView cv{
      .rgba = rgba,
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const float cx = w * 0.64F;
  const float cy = static_cast<float>(horizon_y) - 3.0F;
  const float r = std::min(w, h) * 0.24F;

  // Additive radial halo behind sun (100% static).
  fill_radial_halo(cv, RadialGrad{.center = Vec2{.x = cx, .y = cy},
                                  .inner_r = r * 0.55F,
                                  .outer_r = r * 2.1F,
                                  .inner = ColorA{.rgb = spec.sun_halo, .alpha = 0.28F},
                                  .outer = ColorA{.rgb = spec.sun_halo, .alpha = 0.0F},
                                  .clip_y_max = horizon_y,
                                  .additive = true});

  // Upper unstriped semicircle band (above cy - r * 0.52F, never touched by stripes).
  const float stripe_band = r * 0.52F;
  const int min_y = std::max(0, static_cast<int>(std::floor(cy - r - 1.0F)));
  const int stripe_top_y = std::min(
      horizon_y + 1, std::max(min_y, static_cast<int>(std::floor(cy - stripe_band))));
  const float r_outer = r + 0.5F;
  const float r_outer2 = r_outer * r_outer;
  const float r_inner = std::max(0.0F, r - 0.5F);
  const float r_inner2 = r_inner * r_inner;

  for (int y = min_y; y < stripe_top_y; ++y) {
    const float fy = static_cast<float>(y);
    const float dy = fy - cy;
    const float dy2 = dy * dy;
    if (dy2 >= r_outer2) {
      continue;
    }
    const float half_x = std::sqrt(r_outer2 - dy2);
    const int x0 = std::max(0, static_cast<int>(std::floor(cx - half_x)));
    const int x1 = std::min(cv.width - 1, static_cast<int>(std::ceil(cx + half_x)));
    const float t = std::clamp((fy - (cy - r)) / std::max(1.0F, r), 0.0F, 1.0F);
    const HeroRgb sun_rgb =
        (t < 0.55F) ? lerp_rgb(spec.sun_cols[0], spec.sun_cols[1], t / 0.55F)
                    : lerp_rgb(spec.sun_cols[1], spec.sun_cols[2], (t - 0.55F) / 0.45F);
    for (int x = x0; x <= x1; ++x) {
      const float dx = static_cast<float>(x) - cx;
      const float d2 = dx * dx + dy2;
      if (d2 >= r_outer2) {
        continue;
      }
      const float cov =
          (d2 <= r_inner2) ? 1.0F : std::clamp(r_outer - std::sqrt(d2), 0.0F, 1.0F);
      if (cov > 0.01F) {
        blend_pixel(cv, PixelPos{.x = x, .y = y}, ColorA{.rgb = sun_rgb, .alpha = cov},
                    false);
      }
    }
  }
}

void HeroFlightDeckEngine::draw_sun_dynamic(const HeroTheme &spec, int horizon_y) {
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const float cx = w * 0.64F;
  const float cy = static_cast<float>(horizon_y) - 3.0F;
  const float r = std::min(w, h) * 0.24F;

  // Lower semicircle with animated cache-miss stripe cutouts.
  const float stripe_band = r * 0.52F;
  const float stripe_step = stripe_band / 7.0F;
  const float stripe_shift = std::fmod(sim_t_ * 3.0F, stripe_step);
  const float gap_max =
      std::max(1.2F, r * 0.115F * std::min(1.0F, smooth_miss_ * 4.0F));

  const int min_y = std::max(0, static_cast<int>(std::floor(cy - r - 1.0F)));
  const int stripe_top_y =
      std::max(min_y, static_cast<int>(std::floor(cy - stripe_band)));
  const int max_y = std::min(horizon_y, static_cast<int>(std::ceil(cy)));
  const float r_outer = r + 0.5F;
  const float r_outer2 = r_outer * r_outer;
  const float r_inner = std::max(0.0F, r - 0.5F);
  const float r_inner2 = r_inner * r_inner;

  for (int y = stripe_top_y; y <= max_y; ++y) {
    const float fy = static_cast<float>(y);
    const float dy = fy - cy;
    const float dy2 = dy * dy;
    if (dy2 >= r_outer2) {
      continue;
    }
    bool in_stripe = false;
    for (int k = 0; k < 7; ++k) {
      const float sy =
          cy - stripe_band + static_cast<float>(k) * stripe_step + stripe_shift;
      const float sh =
          std::max(0.75F, gap_max * (0.25F + static_cast<float>(k) * 0.14F));
      if (fy >= sy && fy < sy + sh) {
        in_stripe = true;
        break;
      }
    }
    const float half_x = std::sqrt(r_outer2 - dy2);
    const int x0 = std::max(0, static_cast<int>(std::floor(cx - half_x)));
    const int x1 = std::min(cv.width - 1, static_cast<int>(std::ceil(cx + half_x)));
    const float t = std::clamp((fy - (cy - r)) / std::max(1.0F, r), 0.0F, 1.0F);
    const HeroRgb sun_rgb =
        (t < 0.55F) ? lerp_rgb(spec.sun_cols[0], spec.sun_cols[1], t / 0.55F)
                    : lerp_rgb(spec.sun_cols[1], spec.sun_cols[2], (t - 0.55F) / 0.45F);
    const HeroRgb row_rgb = in_stripe ? spec.sky[3] : sun_rgb;
    const float row_alpha_scale = in_stripe ? 0.85F : 1.0F;

    if (dy2 < r_inner2) {
      const float inner_half = std::sqrt(r_inner2 - dy2);
      const int ix0 = std::max(x0, static_cast<int>(std::ceil(cx - inner_half)));
      const int ix1 = std::min(x1, static_cast<int>(std::floor(cx + inner_half)));
      // Left AA edge
      for (int x = x0; x < ix0; ++x) {
        const float dx = static_cast<float>(x) - cx;
        const float d2 = dx * dx + dy2;
        if (d2 < r_outer2) {
          const float cov = std::clamp(r_outer - std::sqrt(d2), 0.0F, 1.0F);
          if (cov > 0.01F) {
            blend_pixel(cv, PixelPos{.x = x, .y = y},
                        ColorA{.rgb = row_rgb, .alpha = cov * row_alpha_scale}, false);
          }
        }
      }
      // Fast interior span (cov == 1.0F)
      if (ix0 <= ix1) {
        std::uint8_t *row_ptr = cv.rgba + (static_cast<std::size_t>(y) *
                                               static_cast<std::size_t>(cv.width) +
                                           static_cast<std::size_t>(ix0)) *
                                              4U;
        blend_span(row_ptr, ix1 - ix0 + 1,
                   ColorA{.rgb = row_rgb, .alpha = row_alpha_scale}, false);
      }
      // Right AA edge
      for (int x = ix1 + 1; x <= x1; ++x) {
        const float dx = static_cast<float>(x) - cx;
        const float d2 = dx * dx + dy2;
        if (d2 < r_outer2) {
          const float cov = std::clamp(r_outer - std::sqrt(d2), 0.0F, 1.0F);
          if (cov > 0.01F) {
            blend_pixel(cv, PixelPos{.x = x, .y = y},
                        ColorA{.rgb = row_rgb, .alpha = cov * row_alpha_scale}, false);
          }
        }
      }
    } else {
      for (int x = x0; x <= x1; ++x) {
        const float dx = static_cast<float>(x) - cx;
        const float d2 = dx * dx + dy2;
        if (d2 < r_outer2) {
          const float cov = std::clamp(r_outer - std::sqrt(d2), 0.0F, 1.0F);
          if (cov > 0.01F) {
            blend_pixel(cv, PixelPos{.x = x, .y = y},
                        ColorA{.rgb = row_rgb, .alpha = cov * row_alpha_scale}, false);
          }
        }
      }
    }
  }
}

void HeroFlightDeckEngine::draw_skyline_static(std::uint8_t *rgba,
                                               const HeroTheme &spec, int horizon_y) {
  CanvasView cv{
      .rgba = rgba,
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 320.0F;

  // Horizon city glow.
  fill_vgrad_rect(cv, RectF{.x = 0.0F, .y = fh - 110.0F * sy, .w = w, .h = 110.0F * sy},
                  VGrad{.top = spec.tower,
                        .bottom = spec.tower,
                        .top_alpha = 0.0F,
                        .bottom_alpha = 0.22F,
                        .additive = true});

  SeededRng rng{.state = 97};
  // Back hazy skyline layer.
  for (float x = -6.0F; x < w;) {
    const float bw = rng_range(rng, RangeF{.lo = 12.0F, .hi = 36.0F});
    const float bh = rng_range(rng, RangeF{.lo = 18.0F, .hi = 68.0F}) * sy;
    fill_rect(cv, RectF{.x = x, .y = fh - bh, .w = bw, .h = bh},
              ColorA{.rgb = spec.sky_back, .alpha = 1.0F});
    x += bw + rng.next() * 3.0F;
  }

  // Front dark stepped buildings + record window slots and beacon positions.
  std::size_t bldg_idx = 0;
  for (float x = -4.0F; x < w;) {
    const float bw = rng_range(rng, RangeF{.lo = 16.0F, .hi = 40.0F});
    const float bh = (28.0F + std::pow(rng.next(), 1.6F) * 115.0F) * sy;
    fill_rect(cv, RectF{.x = x, .y = fh - bh, .w = bw, .h = bh},
              ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
    if (rng.next() < 0.45F) {
      fill_rect(cv,
                RectF{.x = x + bw * 0.16F,
                      .y = fh - bh - 8.0F * sy,
                      .w = bw * 0.68F,
                      .h = 8.0F * sy},
                ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
    }
    if (rng.next() < 0.38F) {
      const float mast_h = 22.0F * sy;
      fill_rect(
          cv, RectF{.x = x + bw * 0.5F, .y = fh - bh - mast_h, .w = 1.5F, .h = mast_h},
          ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
      cached_beacons_.push_back(
          CachedBeacon{.x = x + bw * 0.5F, .y = fh - bh - mast_h - 1.0F});
    }
    if (rng.next() < 0.28F && bh > 40.0F * sy) {
      fill_rect(cv, RectF{.x = x, .y = fh - bh, .w = bw, .h = 1.5F},
                ColorA{.rgb = spec.tower, .alpha = 0.60F}, true);
    }
    const float wy0 = fh - bh + 5.0F;
    const int w_rows =
        std::max(0, static_cast<int>(std::ceil((fh - 4.0F - wy0) / 5.0F)));
    const int w_cols = std::max(0, static_cast<int>(std::ceil((bw - 6.0F) / 4.5F)));
    for (int r = 0; r < w_rows; ++r) {
      const float wy = wy0 + static_cast<float>(r) * 5.0F;
      for (int c = 0; c < w_cols; ++c) {
        const float wx = x + 3.0F + static_cast<float>(c) * 4.5F;
        const float th = rng.next();
        cached_windows_.push_back(CachedWindow{
            .x = wx,
            .y = wy,
            .w = 2.0F,
            .h = 2.5F,
            .thresh = th,
            .alpha = 0.35F + 0.50F * std::fmod(th * 97.0F, 1.0F),
        });
      }
    }
    // Vertical neon accent bar on select buildings.
    if (rng.next() < 0.32F && bh > 52.0F * sy) {
      const HeroRgb sign_col = spec.cls[bldg_idx % 5U + 1U];
      const float sx = x + bw * 0.5F;
      fill_rect(cv,
                RectF{.x = sx - 2.0F, .y = fh - bh + 8.0F, .w = 4.0F, .h = bh * 0.42F},
                ColorA{.rgb = sign_col, .alpha = 0.65F}, true);
    }
    ++bldg_idx;
    x += bw + 1.5F + rng.next() * 3.0F;
  }

  // Stepped pyramid arcology on right.
  const float ax = w * 0.88F;
  const float ah = 135.0F * sy;
  for (int k = 0; k < 7; ++k) {
    const float ww = (96.0F - static_cast<float>(k) * 12.0F) * (w / 480.0F);
    const float step_h = ah / 7.0F + 1.0F;
    const float y = fh - ah * static_cast<float>(k + 1) / 7.0F;
    fill_rect(cv, RectF{.x = ax - ww * 0.5F, .y = y, .w = ww, .h = step_h},
              ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
  }
  fill_rect(
      cv, RectF{.x = ax - 0.5F, .y = fh - ah - 24.0F * sy, .w = 1.5F, .h = 24.0F * sy},
      ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
  cached_beacons_.push_back(CachedBeacon{.x = ax, .y = fh - ah - 25.0F * sy});

  // Tokyo lattice tower at W * 0.62.
  const float tx = w * 0.62F;
  const float th_tower = 175.0F * sy;
  const auto leg = [&](float y) -> Vec2 {
    const float u = std::clamp(1.0F - (fh - y) / th_tower, 0.0F, 1.0F);
    const float spread = 24.0F * std::pow(u, 1.6F) + 1.0F;
    return Vec2{.x = tx - spread, .y = tx + spread};
  };
  const ColorA tower_col{.rgb = spec.tower, .alpha = 0.90F};
  Vec2 prev_leg = leg(fh);
  const float lattice_step = std::max(2.0F, 10.0F * sy);
  const int lattice_count =
      std::max(0, static_cast<int>(std::floor((th_tower - 20.0F * sy) / lattice_step)));
  for (int i = 1; i <= lattice_count; ++i) {
    const float y = fh - static_cast<float>(i) * lattice_step;
    const Vec2 cur = leg(y);
    draw_aa_line(cv,
                 LineSeg{.a = Vec2{.x = prev_leg.x, .y = y + lattice_step},
                         .b = Vec2{.x = cur.y, .y = y}},
                 tower_col, 1.0F);
    draw_aa_line(cv,
                 LineSeg{.a = Vec2{.x = prev_leg.y, .y = y + lattice_step},
                         .b = Vec2{.x = cur.x, .y = y}},
                 tower_col, 1.0F);
    draw_aa_line(cv,
                 LineSeg{.a = Vec2{.x = prev_leg.x, .y = y + lattice_step},
                         .b = Vec2{.x = cur.x, .y = y}},
                 tower_col, 1.1F);
    draw_aa_line(cv,
                 LineSeg{.a = Vec2{.x = prev_leg.y, .y = y + lattice_step},
                         .b = Vec2{.x = cur.y, .y = y}},
                 tower_col, 1.1F);
    prev_leg = cur;
  }
  fill_rect(cv,
            RectF{.x = tx - 11.0F, .y = fh - th_tower * 0.42F, .w = 22.0F, .h = 4.0F},
            ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
  fill_rect(cv,
            RectF{.x = tx - 7.0F, .y = fh - th_tower * 0.70F, .w = 14.0F, .h = 3.5F},
            ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
  fill_rect(
      cv,
      RectF{
          .x = tx - 0.5F, .y = fh - th_tower - 16.0F * sy, .w = 1.5F, .h = 16.0F * sy},
      ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
  cached_beacons_.push_back(CachedBeacon{.x = tx, .y = fh - th_tower - 17.0F * sy});
}

void HeroFlightDeckEngine::draw_skyline_dynamic(const HeroTheme &spec) {
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float busy_ratio =
      telemetry_.total_agents > 0
          ? std::clamp(static_cast<float>(telemetry_.active_agents) /
                           static_cast<float>(telemetry_.total_agents),
                       0.0F, 1.0F)
          : (telemetry_.busy ? 0.8F : 0.25F);
  const float lit_thresh = 0.08F + 0.80F * busy_ratio;
  for (const auto &win : cached_windows_) {
    if (win.thresh < lit_thresh) {
      fill_rect(cv, RectF{.x = win.x, .y = win.y, .w = win.w, .h = win.h},
                ColorA{.rgb = spec.window, .alpha = win.alpha});
    }
  }
  // Flashing red Jev beacons.
  const float ba = 0.30F + 0.70F * beacon_flash_;
  const HeroRgb red = rgb_hex(0xff3c50);
  for (const auto &b : cached_beacons_) {
    const Vec2 pt{.x = b.x, .y = b.y};
    fill_radial_halo(cv, RadialGrad{.center = pt,
                                    .inner_r = 0.0F,
                                    .outer_r = 4.0F + beacon_flash_ * 6.0F,
                                    .inner = ColorA{.rgb = red, .alpha = ba * 0.8F},
                                    .outer = ColorA{.rgb = red, .alpha = 0.0F},
                                    .additive = true});
    fill_circle(cv, CircleSpec{.center = pt, .radius = 1.3F + beacon_flash_ * 0.9F},
                ColorA{.rgb = red, .alpha = ba}, true);
  }
}

void HeroFlightDeckEngine::draw_gotham_static(std::uint8_t *rgba, const HeroTheme &spec,
                                              int horizon_y) {
  CanvasView cv{
      .rgba = rgba,
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 320.0F;

  // Warm gothic horizon haze.
  fill_vgrad_rect(cv, RectF{.x = 0.0F, .y = fh - 95.0F * sy, .w = w, .h = 95.0F * sy},
                  VGrad{.top = rgb_hex(0xff8c3c),
                        .bottom = rgb_hex(0xff8c3c),
                        .top_alpha = 0.0F,
                        .bottom_alpha = 0.14F,
                        .additive = true});

  // Art-deco towers + Empire State + Chrysler silhouettes (cached static geometry).
  SeededRng rng{.state = 31};
  for (float x = -6.0F; x < w;) {
    const float bw = rng_range(rng, RangeF{.lo = 14.0F, .hi = 30.0F});
    const float bh = rng_range(rng, RangeF{.lo = 26.0F, .hi = 70.0F}) * sy;
    fill_rect(cv, RectF{.x = x, .y = fh - bh, .w = bw, .h = bh},
              ColorA{.rgb = spec.sky_back, .alpha = 1.0F});
    x += bw + 2.0F;
  }

  for (float x = -4.0F; x < w;) {
    const float bw = rng_range(rng, RangeF{.lo = 18.0F, .hi = 36.0F});
    const float bh = (32.0F + std::pow(rng.next(), 1.5F) * 100.0F) * sy;
    fill_rect(cv, RectF{.x = x, .y = fh - bh, .w = bw, .h = bh},
              ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
    const float wy0 = fh - bh + 5.0F;
    const int w_rows =
        std::max(0, static_cast<int>(std::ceil((fh - 4.0F - wy0) / 5.0F)));
    const int w_cols = std::max(0, static_cast<int>(std::ceil((bw - 6.0F) / 4.0F)));
    for (int r = 0; r < w_rows; ++r) {
      const float wy = wy0 + static_cast<float>(r) * 5.0F;
      for (int c = 0; c < w_cols; ++c) {
        const float wx = x + 3.0F + static_cast<float>(c) * 4.0F;
        const float th = rng.next();
        cached_windows_.push_back(CachedWindow{
            .x = wx,
            .y = wy,
            .w = 1.5F,
            .h = 2.0F,
            .thresh = th,
            .alpha = 0.28F + 0.42F * std::fmod(th * 97.0F, 1.0F),
        });
      }
    }
    x += bw + 2.0F;
  }

  // Empire State setbacks at W * 0.64.
  const float ex = w * 0.64F;
  float ey = fh;
  constexpr std::array<Vec2, 4> kEmpTiers = {
      {{54.0F, 92.0F}, {38.0F, 36.0F}, {24.0F, 22.0F}, {12.0F, 14.0F}}};
  for (const auto &tier : kEmpTiers) {
    const float tw = tier.x * (w / 480.0F);
    const float th_t = tier.y * sy;
    fill_rect(cv, RectF{.x = ex - tw * 0.5F, .y = ey - th_t, .w = tw, .h = th_t},
              ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
    ey -= th_t;
  }
  fill_rect(cv, RectF{.x = ex - 1.0F, .y = ey - 28.0F * sy, .w = 2.0F, .h = 28.0F * sy},
            ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
  cached_beacons_.push_back(CachedBeacon{.x = ex, .y = ey - 29.0F * sy});

  // Chrysler crown at W * 0.88.
  const float kx = w * 0.88F;
  const float kh = 128.0F * sy;
  fill_rect(cv, RectF{.x = kx - 18.0F, .y = fh - kh, .w = 36.0F, .h = kh},
            ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
  float ky = fh - kh;
  for (int k = 0; k < 4; ++k) {
    const float rr = 16.0F - static_cast<float>(k) * 3.2F;
    fill_circle(cv, CircleSpec{.center = Vec2{.x = kx, .y = ky}, .radius = rr},
                ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
    stroke_ellipse_arc(cv,
                       ArcSpec{.center = Vec2{.x = kx, .y = ky},
                               .radii = Vec2{.x = rr * 0.72F, .y = rr * 0.72F},
                               .start_rad = std::numbers::pi_v<float>,
                               .end_rad = std::numbers::pi_v<float> * 2.0F,
                               .thickness = 1.2F},
                       ColorA{.rgb = rgb_hex(0xffaa5a), .alpha = 0.65F}, true);
    ky -= rr * 0.72F;
  }
  fill_rect(cv, RectF{.x = kx - 1.0F, .y = ky - 26.0F * sy, .w = 2.0F, .h = 26.0F * sy},
            ColorA{.rgb = spec.sky_front, .alpha = 1.0F});
  cached_beacons_.push_back(CachedBeacon{.x = kx, .y = ky - 27.0F * sy});
}

void HeroFlightDeckEngine::draw_gotham_dynamic(const HeroTheme &spec, int horizon_y) {
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 320.0F;

  // Dynamic lit windows on cached buildings.
  const float busy_ratio =
      telemetry_.total_agents > 0
          ? std::clamp(static_cast<float>(telemetry_.active_agents) /
                           static_cast<float>(telemetry_.total_agents),
                       0.0F, 1.0F)
          : (telemetry_.busy ? 0.8F : 0.25F);
  const float lit_thresh = 0.08F + 0.78F * busy_ratio;
  for (const auto &win : cached_windows_) {
    if (win.thresh < lit_thresh) {
      fill_rect(cv, RectF{.x = win.x, .y = win.y, .w = win.w, .h = win.h},
                ColorA{.rgb = spec.window, .alpha = win.alpha});
    }
  }

  // Sweeping searchlight cones (one per active agent, up to 6).
  const std::size_t lights_n =
      std::clamp<std::size_t>(std::max<std::size_t>(2, telemetry_.active_agents), 2, 6);
  for (std::size_t i = 0; i < lights_n; ++i) {
    const float lx = w * (0.10F + 0.16F * static_cast<float>(i));
    const float ly = fh - 42.0F * sy;
    const float ang =
        -std::numbers::pi_v<float> * 0.5F + std::sin(searchlight_phase_[i]) * 0.52F;
    const float beam_len = fh * 1.1F;
    const float spread = 0.055F;
    const std::array<Vec2, 3> cone = {{
        Vec2{.x = lx, .y = ly},
        Vec2{.x = lx + std::cos(ang - spread) * beam_len,
             .y = ly + std::sin(ang - spread) * beam_len},
        Vec2{.x = lx + std::cos(ang + spread) * beam_len,
             .y = ly + std::sin(ang + spread) * beam_len},
    }};
    fill_polygon(cv, cone, ColorA{.rgb = rgb_hex(0xebebe1), .alpha = 0.085F}, true);
  }

  // The Blackbird-Signal spotlight driven by cache-miss share.
  const float sgl = std::min(1.0F, 0.22F + smooth_miss_ * 4.5F);
  const Vec2 sig{.x = w * 0.70F, .y = fh * 0.30F};
  const Vec2 emp{.x = w * 0.64F, .y = fh - 175.0F * sy};
  const std::array<Vec2, 3> sig_beam = {{
      Vec2{.x = emp.x, .y = emp.y},
      Vec2{.x = sig.x - 28.0F, .y = sig.y + 4.0F},
      Vec2{.x = sig.x + 28.0F, .y = sig.y - 4.0F},
  }};
  fill_polygon(cv, sig_beam, ColorA{.rgb = rgb_hex(0xffdca8), .alpha = 0.11F * sgl},
               true);
  fill_radial_halo(
      cv, RadialGrad{.center = sig,
                     .inner_r = 0.0F,
                     .outer_r = 30.0F,
                     .inner = ColorA{.rgb = rgb_hex(0xffe1b4), .alpha = 0.55F * sgl},
                     .outer = ColorA{.rgb = rgb_hex(0xffc88c), .alpha = 0.0F},
                     .additive = true});
  // Dark SR-71 top silhouette inside signal (stack array, zero heap alloc).
  std::array<Vec2, kSrHalf.size() * 2U> sig_plane{};
  std::size_t sp_idx = 0;
  for (const auto &pt : kSrHalf) {
    sig_plane[sp_idx++] =
        Vec2{.x = sig.x + pt.x * 0.42F, .y = sig.y - (pt.y - 52.0F) * 0.18F};
  }
  for (std::size_t idx = kSrHalf.size(); idx > 0; --idx) {
    const auto &pt = kSrHalf[idx - 1];
    sig_plane[sp_idx++] =
        Vec2{.x = sig.x - pt.x * 0.42F, .y = sig.y - (pt.y - 52.0F) * 0.18F};
  }
  fill_polygon(cv, sig_plane,
               ColorA{.rgb = rgb_hex(0x0c0c0c), .alpha = 0.55F + 0.35F * sgl}, false);

  const float ba = 0.28F + 0.72F * beacon_flash_;
  const HeroRgb red = rgb_hex(0xff3c3c);
  for (const auto &b : cached_beacons_) {
    fill_circle(cv,
                CircleSpec{.center = Vec2{.x = b.x, .y = b.y},
                           .radius = 1.4F + beacon_flash_ * 1.1F},
                ColorA{.rgb = red, .alpha = ba}, true);
  }
}

void HeroFlightDeckEngine::draw_fuji_static(std::uint8_t *rgba, const HeroTheme &spec,
                                            int horizon_y) const {
  (void)spec;
  CanvasView cv{
      .rgba = rgba,
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 240.0F;

  // Pale parchment moon.
  const Vec2 moon{.x = w * 0.26F, .y = fh * 0.28F};
  fill_radial_halo(cv,
                   RadialGrad{.center = moon,
                              .inner_r = 8.0F,
                              .outer_r = 48.0F,
                              .inner = ColorA{.rgb = rgb_hex(0xc8c093), .alpha = 0.28F},
                              .outer = ColorA{.rgb = rgb_hex(0xc8c093), .alpha = 0.0F},
                              .additive = true});
  fill_circle(cv, CircleSpec{.center = moon, .radius = 18.0F * sy},
              ColorA{.rgb = rgb_hex(0xc8c093), .alpha = 0.88F});

  // Distant ridge.
  auto ridge = build_ridge(RidgeSpec{.horizon_y = horizon_y,
                                     .base = 8.0F * sy,
                                     .amp = 28.0F * sy,
                                     .step = 26.0F,
                                     .seed = 5,
                                     .width = cv.width});
  ridge.insert(ridge.begin(), Vec2{.x = -16.0F, .y = fh});
  ridge.push_back(Vec2{.x = w + 16.0F, .y = fh});
  fill_polygon(cv, ridge, ColorA{.rgb = rgb_hex(0x17171e), .alpha = 1.0F});

  // Mount Fuji cone.
  const float px = w * 0.50F;
  const float top = fh - 118.0F * sy;
  const std::array<Vec2, 8> fuji = {{
      Vec2{.x = w * 0.06F, .y = fh},
      Vec2{.x = px - 72.0F * (w / 480.0F), .y = fh - 48.0F * sy},
      Vec2{.x = px - 30.0F * (w / 480.0F), .y = fh - 90.0F * sy},
      Vec2{.x = px - 12.0F, .y = top},
      Vec2{.x = px + 12.0F, .y = top},
      Vec2{.x = px + 30.0F * (w / 480.0F), .y = fh - 90.0F * sy},
      Vec2{.x = px + 72.0F * (w / 480.0F), .y = fh - 48.0F * sy},
      Vec2{.x = w * 0.94F, .y = fh},
  }};
  fill_polygon(cv, fuji, ColorA{.rgb = rgb_hex(0x223249), .alpha = 1.0F});

  // Jagged Fuji snowcap.
  const std::array<Vec2, 9> snow = {{
      Vec2{.x = px - 12.0F, .y = top},
      Vec2{.x = px + 12.0F, .y = top},
      Vec2{.x = px + 32.0F, .y = top + 34.0F * sy},
      Vec2{.x = px + 20.0F, .y = top + 40.0F * sy},
      Vec2{.x = px + 10.0F, .y = top + 31.0F * sy},
      Vec2{.x = px + 0.0F, .y = top + 42.0F * sy},
      Vec2{.x = px - 12.0F, .y = top + 30.0F * sy},
      Vec2{.x = px - 22.0F, .y = top + 39.0F * sy},
      Vec2{.x = px - 32.0F, .y = top + 33.0F * sy},
  }};
  fill_polygon(cv, snow, ColorA{.rgb = rgb_hex(0xdcd7ba), .alpha = 1.0F});
}

void HeroFlightDeckEngine::draw_fuji_dynamic(const HeroTheme &spec, int horizon_y) {
  (void)spec;
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 240.0F;

  // Hokusai curling wave on the right (crest height = output + reasoning rate).
  const float thr = std::min(1.6F, smooth_out_rate_ / 2500.0F);
  const float hc = (20.0F + thr * 52.0F) * sy;
  const float sway = std::sin(sim_t_ * 0.9F) * 3.0F;
  const std::array<Vec2, 8> wave = {{
      Vec2{.x = w + 10.0F, .y = fh + 2.0F},
      Vec2{.x = w - 60.0F, .y = fh - hc * 0.35F},
      Vec2{.x = w - 122.0F + sway, .y = fh - hc},
      Vec2{.x = w - 165.0F + sway, .y = fh - hc * 0.85F},
      Vec2{.x = w - 155.0F + sway, .y = fh - hc * 0.55F},
      Vec2{.x = w - 135.0F, .y = fh - hc * 0.65F},
      Vec2{.x = w - 140.0F, .y = fh - hc * 0.25F},
      Vec2{.x = w - 190.0F, .y = fh + 2.0F},
  }};
  fill_polygon(cv, wave, ColorA{.rgb = rgb_hex(0x2d4f67), .alpha = 1.0F});
  stroke_polygon(cv, wave, ColorA{.rgb = rgb_hex(0xdcd7ba), .alpha = 0.85F}, false);
}

void HeroFlightDeckEngine::draw_aurora_static(std::uint8_t *rgba, const HeroTheme &spec,
                                              int horizon_y) {
  (void)spec;
  CanvasView cv{
      .rgba = rgba,
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 240.0F;

  cached_aurora_clip_y_.assign(static_cast<std::size_t>(width_), horizon_y);

  // Two snow-capped Nordic mountain ridges (100% static).
  struct Layer {
    float base;
    float amp;
    float step;
    HeroRgb col;
    std::uint32_t seed;
  };
  const std::array<Layer, 2> layers = {{
      {.base = 34.0F * sy,
       .amp = 68.0F * sy,
       .step = 24.0F,
       .col = rgb_hex(0x3b4252),
       .seed = 11},
      {.base = 12.0F * sy,
       .amp = 42.0F * sy,
       .step = 18.0F,
       .col = rgb_hex(0x2e3440),
       .seed = 23},
  }};
  for (const auto &l : layers) {
    auto pts = build_ridge(RidgeSpec{.horizon_y = horizon_y,
                                     .base = l.base,
                                     .amp = l.amp,
                                     .step = l.step,
                                     .seed = l.seed,
                                     .width = cv.width});
    // Record upper ridge silhouette per column so dynamic aurora clips cleanly behind
    // it.
    for (std::size_t i = 0; i + 1 < pts.size(); ++i) {
      const Vec2 a = pts[i];
      const Vec2 b = pts[i + 1];
      const int x0 = std::max(0, static_cast<int>(std::floor(std::min(a.x, b.x))));
      const int x1 =
          std::min(cv.width - 1, static_cast<int>(std::ceil(std::max(a.x, b.x))));
      const float dx = b.x - a.x;
      for (int x = x0; x <= x1; ++x) {
        const float t = (std::abs(dx) > 0.001F)
                            ? std::clamp((static_cast<float>(x) - a.x) / dx, 0.0F, 1.0F)
                            : 0.0F;
        const int ridge_y = static_cast<int>(std::floor(a.y + (b.y - a.y) * t));
        const auto ux = static_cast<std::size_t>(x);
        cached_aurora_clip_y_[ux] = std::min(cached_aurora_clip_y_[ux], ridge_y);
      }
    }
    std::vector<Vec2> poly;
    poly.reserve(pts.size() + 2);
    poly.push_back(Vec2{.x = -16.0F, .y = fh});
    poly.insert(poly.end(), pts.begin(), pts.end());
    poly.push_back(Vec2{.x = w + 16.0F, .y = fh});
    fill_polygon(cv, poly, ColorA{.rgb = l.col, .alpha = 1.0F});
    for (std::size_t i = 1; i + 1 < pts.size(); ++i) {
      if (pts[i].y < fh - l.base - l.amp * 0.52F) {
        const std::array<Vec2, 3> cap = {{
            pts[i],
            Vec2{.x = pts[i].x - 6.0F, .y = pts[i].y + 8.0F * sy},
            Vec2{.x = pts[i].x + 6.0F, .y = pts[i].y + 8.0F * sy},
        }};
        fill_polygon(cv, cap, ColorA{.rgb = rgb_hex(0xd8dee9), .alpha = 0.85F});
      }
    }
  }
}

void HeroFlightDeckEngine::draw_aurora_dynamic(const HeroTheme &spec, int horizon_y) {
  (void)spec;
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 240.0F;
  const float hit = 1.0F - smooth_miss_;
  const float k = std::clamp((hit - 0.35F) / 0.60F, 0.18F, 1.0F);
  const HeroRgb top_col = rgb_hex(0xb48ead);
  const HeroRgb mid_col = rgb_hex(0x88c0d0);
  const HeroRgb bot_col = rgb_hex(0xa3be8c);

  // Rippling additive aurora curtains clipped cleanly behind cached Nordic peaks.
  for (int x = 0; x < cv.width; x += 3) {
    const float fx = static_cast<float>(x);
    const float y0 = (36.0F + 22.0F * std::sin(fx * 0.015F + sim_t_ * 0.28F) +
                      10.0F * std::sin(fx * 0.040F - sim_t_ * 0.42F)) *
                     sy;
    const float ah = (54.0F + 26.0F * std::sin(fx * 0.025F + sim_t_ * 0.32F)) * sy;
    const float half_h = ah * 0.5F;
    const int span_w = std::min(3, cv.width - x);
    int clip_y = horizon_y;
    for (int dx = 0; dx < span_w; ++dx) {
      const auto ux = static_cast<std::size_t>(x + dx);
      if (ux < cached_aurora_clip_y_.size()) {
        clip_y = std::min(clip_y, cached_aurora_clip_y_[ux]);
      }
    }
    const float max_h1 = static_cast<float>(clip_y) - y0;
    if (max_h1 > 0.0F) {
      fill_vgrad_rect(cv,
                      RectF{.x = fx,
                            .y = y0,
                            .w = static_cast<float>(span_w),
                            .h = std::min(half_h, max_h1)},
                      VGrad{.top = top_col,
                            .bottom = mid_col,
                            .top_alpha = 0.0F,
                            .bottom_alpha = 0.16F * k,
                            .additive = true});
    }
    const float y_mid = y0 + half_h;
    const float max_h2 = static_cast<float>(clip_y) - y_mid;
    if (max_h2 > 0.0F) {
      fill_vgrad_rect(cv,
                      RectF{.x = fx,
                            .y = y_mid,
                            .w = static_cast<float>(span_w),
                            .h = std::min(half_h, max_h2)},
                      VGrad{.top = mid_col,
                            .bottom = bot_col,
                            .top_alpha = 0.24F * k,
                            .bottom_alpha = 0.0F,
                            .additive = true});
    }
  }
}

void HeroFlightDeckEngine::draw_wire_static(std::uint8_t *rgba, const HeroTheme &spec,
                                            int horizon_y) const {
  (void)spec;
  CanvasView cv{
      .rgba = rgba,
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 240.0F;
  constexpr float kBaseAlpha = 0.55F;
  const ColorA col{.rgb = rgb_hex(0x4fe88f), .alpha = kBaseAlpha};
  auto pts = build_ridge(RidgeSpec{.horizon_y = horizon_y,
                                   .base = 4.0F * sy,
                                   .amp = 78.0F * sy,
                                   .step = 32.0F,
                                   .seed = 41,
                                   .width = cv.width});
  for (std::size_t i = 0; i + 1 < pts.size(); ++i) {
    draw_glow_line(cv, LineSeg{.a = pts[i], .b = pts[i + 1]}, col, 2.8F);
    if ((i & 1U) != 0U) {
      draw_aa_line(
          cv,
          LineSeg{.a = pts[i],
                  .b = Vec2{.x = pts[i].x + (pts[i].x - w * 0.64F) * 0.08F, .y = fh}},
          ColorA{.rgb = col.rgb, .alpha = kBaseAlpha * 0.65F}, 1.0F, true);
    }
  }
  // Wireframe crescent moon.
  const Vec2 moon{.x = w * 0.25F, .y = fh * 0.28F};
  stroke_ellipse_arc(cv,
                     ArcSpec{.center = moon,
                             .radii = Vec2{.x = 18.0F * sy, .y = 18.0F * sy},
                             .start_rad = -1.9F,
                             .end_rad = 1.9F,
                             .thickness = 1.2F},
                     ColorA{.rgb = rgb_hex(0x4fe88f), .alpha = 0.65F}, true);
  stroke_ellipse_arc(cv,
                     ArcSpec{.center = Vec2{.x = moon.x + 7.0F * sy, .y = moon.y},
                             .radii = Vec2{.x = 15.5F * sy, .y = 15.5F * sy},
                             .start_rad = -1.75F,
                             .end_rad = 1.75F,
                             .thickness = 1.1F},
                     ColorA{.rgb = rgb_hex(0x4fe88f), .alpha = 0.55F}, true);
}

void HeroFlightDeckEngine::draw_wire_dynamic(const HeroTheme &spec, int horizon_y) {
  (void)spec;
  if (beacon_flash_ <= 0.01F) {
    return;
  }
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 240.0F;
  const ColorA pulse_col{.rgb = rgb_hex(0x4fe88f), .alpha = 0.45F * beacon_flash_};
  auto pts = build_ridge(RidgeSpec{.horizon_y = horizon_y,
                                   .base = 4.0F * sy,
                                   .amp = 78.0F * sy,
                                   .step = 32.0F,
                                   .seed = 41,
                                   .width = cv.width});
  for (std::size_t i = 0; i + 1 < pts.size(); ++i) {
    draw_aa_line(cv, LineSeg{.a = pts[i], .b = pts[i + 1]}, pulse_col,
                 2.8F + beacon_flash_ * 2.0F, true);
  }
}

void HeroFlightDeckEngine::draw_palms_static(std::uint8_t *rgba, const HeroTheme &spec,
                                             int horizon_y) const {
  (void)spec;
  (void)horizon_y;
  CanvasView cv{
      .rgba = rgba,
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const ColorA dark{.rgb = rgb_hex(0x020c17), .alpha = 1.0F};

  struct PalmSpec {
    float bx;
    float hgt;
    float lean;
    float sz;
  };
  const std::array<PalmSpec, 3> palms = {{
      {.bx = w * 0.03F, .hgt = h * 0.42F, .lean = w * 0.06F, .sz = h * 0.16F},
      {.bx = w * 0.12F, .hgt = h * 0.30F, .lean = w * 0.04F, .sz = h * 0.12F},
      {.bx = w * 0.97F, .hgt = h * 0.38F, .lean = -w * 0.06F, .sz = h * 0.14F},
  }};
  for (const auto &pl : palms) {
    const Vec2 base{.x = pl.bx, .y = h + 4.0F};
    const Vec2 mid{.x = pl.bx + pl.lean * 0.25F, .y = h - pl.hgt * 0.55F};
    const Vec2 top{.x = pl.bx + pl.lean, .y = h - pl.hgt};
    draw_aa_line(cv, LineSeg{.a = base, .b = mid}, dark, std::max(2.5F, pl.sz * 0.10F));
    draw_aa_line(cv, LineSeg{.a = mid, .b = top}, dark, std::max(2.0F, pl.sz * 0.075F));
    fill_circle(cv, CircleSpec{.center = top, .radius = pl.sz * 0.08F}, dark);
  }
}

void HeroFlightDeckEngine::draw_palms_dynamic(const HeroTheme &spec, int horizon_y) {
  (void)spec;
  (void)horizon_y;
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const ColorA dark{.rgb = rgb_hex(0x020c17), .alpha = 1.0F};

  struct PalmSpec {
    float bx;
    float hgt;
    float lean;
    float sz;
  };
  const std::array<PalmSpec, 3> palms = {{
      {.bx = w * 0.03F, .hgt = h * 0.42F, .lean = w * 0.06F, .sz = h * 0.16F},
      {.bx = w * 0.12F, .hgt = h * 0.30F, .lean = w * 0.04F, .sz = h * 0.12F},
      {.bx = w * 0.97F, .hgt = h * 0.38F, .lean = -w * 0.06F, .sz = h * 0.14F},
  }};
  for (const auto &pl : palms) {
    const Vec2 top{.x = pl.bx + pl.lean, .y = h - pl.hgt};
    for (int k = 0; k < 9; ++k) {
      const float a = std::numbers::pi_v<float> +
                      static_cast<float>(k) * (std::numbers::pi_v<float> / 8.0F) +
                      std::sin(sim_t_ * 0.5F + static_cast<float>(k)) * 0.04F;
      const float len =
          pl.sz * (0.75F + 0.25F * std::sin(static_cast<float>(k) * 2.1F));
      const float dx = std::cos(a);
      const float dy = std::sin(a);
      const Vec2 tip{.x = top.x + dx * len,
                     .y = top.y + dy * len * 0.35F +
                          len * 0.40F * (1.0F - std::abs(dy) * 0.4F)};
      const Vec2 ctrl{.x = top.x + dx * len * 0.50F,
                      .y = top.y + dy * len * 0.50F - len * 0.15F};
      draw_aa_line(cv, LineSeg{.a = top, .b = ctrl}, dark, 2.2F);
      draw_aa_line(cv, LineSeg{.a = ctrl, .b = tip}, dark, 1.5F);
    }
  }
}

void HeroFlightDeckEngine::draw_qud_static(std::uint8_t *rgba, const HeroTheme &spec,
                                           int horizon_y) const {
  (void)spec;
  CanvasView cv{
      .rgba = rgba,
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 240.0F;

  // Starfield.
  SeededRng rng{.state = 77};
  constexpr std::array<HeroRgb, 3> kStarCols = {rgb_hex(0xb1c9c3), rgb_hex(0x77bfcf),
                                                rgb_hex(0xcfc041)};
  for (int i = 0; i < 65; ++i) {
    const int sx = static_cast<int>(rng.next() * w);
    const int sy_px = static_cast<int>(rng.next() * (fh * 0.72F));
    const float alpha = 0.25F + rng.next() * 0.45F;
    blend_pixel(
        cv, PixelPos{.x = sx, .y = sy_px},
        ColorA{.rgb = kStarCols[static_cast<std::size_t>(i) % 3U], .alpha = alpha},
        true);
  }

  // Canyon mesa ridge.
  auto ridge = build_ridge(RidgeSpec{.horizon_y = horizon_y,
                                     .base = 5.0F * sy,
                                     .amp = 22.0F * sy,
                                     .step = 20.0F,
                                     .seed = 9,
                                     .width = cv.width});
  ridge.insert(ridge.begin(), Vec2{.x = -16.0F, .y = fh});
  ridge.push_back(Vec2{.x = w + 16.0F, .y = fh});
  fill_polygon(cv, ridge, ColorA{.rgb = rgb_hex(0x08201f), .alpha = 1.0F});

  // Ruined arcology monoliths.
  struct Monolith {
    float x;
    float h;
    float w;
  };
  const std::array<Monolith, 3> monos = {{
      {.x = w * 0.12F, .h = 34.0F * sy, .w = 15.0F},
      {.x = w * 0.30F, .h = 24.0F * sy, .w = 22.0F},
      {.x = w * 0.90F, .h = 44.0F * sy, .w = 16.0F},
  }};
  for (const auto &m : monos) {
    fill_rect(cv, RectF{.x = m.x, .y = fh - m.h, .w = m.w, .h = m.h},
              ColorA{.rgb = rgb_hex(0x0a2726), .alpha = 1.0F});
    fill_rect(cv,
              RectF{.x = m.x + m.w * 0.2F,
                    .y = fh - m.h - 10.0F * sy,
                    .w = 2.5F,
                    .h = 10.0F * sy},
              ColorA{.rgb = rgb_hex(0x0a2726), .alpha = 1.0F});
  }

  // The Spindle body & outline at W * 0.74.
  const float sx = w * 0.74F;
  const std::array<Vec2, 4> spindle = {{
      Vec2{.x = sx - 6.0F, .y = fh},
      Vec2{.x = sx - 1.5F, .y = 0.0F},
      Vec2{.x = sx + 1.5F, .y = 0.0F},
      Vec2{.x = sx + 6.0F, .y = fh},
  }};
  fill_polygon(cv, spindle, ColorA{.rgb = rgb_hex(0x155352), .alpha = 1.0F});
  stroke_polygon(cv, spindle, ColorA{.rgb = rgb_hex(0x40a4b9), .alpha = 0.65F}, false);
}

void HeroFlightDeckEngine::draw_qud_dynamic(const HeroTheme &spec, int horizon_y) {
  (void)spec;
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float fh = static_cast<float>(horizon_y);
  const float sy = fh / 240.0F;
  const float sx = w * 0.74F;

  const float fill =
      static_cast<float>(sanitize_context_fill(telemetry_.main_context_fill));
  const float lh = fh * fill;
  fill_vgrad_rect(cv, RectF{.x = sx - 1.5F, .y = fh - lh, .w = 3.0F, .h = lh},
                  VGrad{.top = rgb_hex(0xcfc041),
                        .bottom = rgb_hex(0xcfc041),
                        .top_alpha = 0.25F,
                        .bottom_alpha = 0.92F,
                        .additive = true});
  const float rung_step = std::max(4.0F, 16.0F * sy);
  const int rung_count =
      std::max(0, static_cast<int>(std::floor((lh - 8.0F) / rung_step)));
  for (int i = 0; i <= rung_count; ++i) {
    const float y = fh - 8.0F - static_cast<float>(i) * rung_step;
    if (y <= fh - lh) {
      break;
    }
    fill_rect(cv, RectF{.x = sx - 3.5F, .y = y, .w = 7.0F, .h = 1.5F},
              ColorA{.rgb = rgb_hex(0xcfc041), .alpha = 0.75F}, true);
  }
}

void HeroFlightDeckEngine::draw_ocean_dynamic(const HeroTheme &spec, int horizon_y) {
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const float fh = static_cast<float>(horizon_y);
  const float depth = std::max(1.0F, h - fh);
  const float cx = w * 0.64F;
  constexpr int kLines = 22;
  for (int k = 0; k < kLines; ++k) {
    // Scroll smoothly DOWN toward the camera as grid_off_ increases.
    const float z = (static_cast<float>(k) + grid_off_) / static_cast<float>(kLines);
    const float y = fh + depth * z * z;
    const float rw = (w * 0.19F - z * w * 0.08F) *
                     (0.60F + 0.40F * std::sin(static_cast<float>(k) * 2.3F + sim_t_));
    const float rx = cx - rw * 0.5F + std::sin(static_cast<float>(k) + sim_t_) * 4.5F;
    fill_rect(cv, RectF{.x = rx, .y = y, .w = rw, .h = 1.0F + z * 2.0F},
              ColorA{.rgb = spec.sun_cols[static_cast<std::size_t>(k) % 3U],
                     .alpha = 0.52F * (1.0F - z) + 0.12F},
              true);
  }
}

void HeroFlightDeckEngine::draw_glyph_ground(const HeroTheme &spec, int horizon_y) {
  (void)spec;
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const float fh = static_cast<float>(horizon_y);
  const float depth = std::max(1.0F, h - fh);
  struct GlyphCol {
    char ch;
    HeroRgb rgb;
  };
  constexpr std::array<GlyphCol, 8> kGlyphs = {{
      {'.', rgb_hex(0xb1c9c3)},
      {',', rgb_hex(0x009403)},
      {'"', rgb_hex(0x00c420)},
      {'~', rgb_hex(0x40a4b9)},
      {'=', rgb_hex(0x0096ff)},
      {'*', rgb_hex(0x98875f)},
      {'^', rgb_hex(0x98875f)},
      {'.', rgb_hex(0x155352)},
  }};
  constexpr int kRows = 12;
  for (int k = 0; k < kRows; ++k) {
    // Scroll smoothly DOWN toward the camera as grid_off_ increases.
    const float z = (static_cast<float>(k) + grid_off_) / static_cast<float>(kRows);
    const float y = fh + depth * z * z;
    const float alpha = 0.25F + 0.70F * z;
    const std::uint32_t row_id =
        (grid_n_ - static_cast<std::uint32_t>(k) + 100000U) * 2654435761U;
    SeededRng rng{.state = row_id == 0 ? 1U : row_id};
    const float sp = 7.0F + z * 11.0F;
    const float off = rng.next() * sp;
    const int cols = static_cast<int>(std::ceil((w + off) / sp));
    for (int col = 0; col < cols; ++col) {
      const float x = -off + static_cast<float>(col) * sp;
      const float v = rng.next();
      if (v < 0.35F) {
        continue;
      }
      const auto &gc =
          kGlyphs[static_cast<std::size_t>(v * static_cast<float>(kGlyphs.size())) %
                  kGlyphs.size()];
      const char str[2] = {gc.ch, '\0'};
      draw_text_5x7(cv, Vec2{.x = x, .y = y - 3.0F}, std::string_view{str, 1},
                    TextStyle{.color = ColorA{.rgb = gc.rgb, .alpha = alpha}});
    }
  }
}

void HeroFlightDeckEngine::draw_grid(const HeroTheme &spec, int horizon_y) {
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const float fh = static_cast<float>(horizon_y);
  const float depth = std::max(1.0F, h - fh);
  const float dim = (spec.ground == HeroGroundKind::ocean) ? 0.35F : 1.0F;

  // Fast direct horizontal glowing horizon line (exact SDF equivalence, zero hypot).
  const float horiz_alpha = 0.90F * dim;
  const float glow_reach = 2.6F * 0.5F + 0.75F;
  const int hy0 = std::max(0, horizon_y - 2);
  const int hy1 = std::min(cv.height - 1, horizon_y + 2);
  for (int y = hy0; y <= hy1; ++y) {
    const float dist = std::abs(static_cast<float>(y) - fh);
    const float cov = std::clamp(glow_reach - dist, 0.0F, 1.0F);
    if (cov > 0.01F) {
      std::uint8_t *row = cv.rgba + static_cast<std::size_t>(y) *
                                        static_cast<std::size_t>(cv.width) * 4U;
      blend_span(row, cv.width,
                 ColorA{.rgb = spec.grid, .alpha = horiz_alpha * 0.24F * cov}, true);
    }
  }
  if (horizon_y >= 0 && horizon_y < cv.height) {
    std::uint8_t *row = cv.rgba + static_cast<std::size_t>(horizon_y) *
                                      static_cast<std::size_t>(cv.width) * 4U;
    blend_span(row, cv.width, ColorA{.rgb = spec.grid, .alpha = horiz_alpha}, false);
  }

  // Diverging rays from vanishing point (W * 0.64, horizon_y).
  const float vpx = w * 0.64F;
  for (int k = -14; k <= 14; ++k) {
    const float fk = static_cast<float>(k);
    const Vec2 a{.x = vpx + fk * (w * 0.026F), .y = fh};
    const Vec2 b{.x = vpx + fk * (w * 0.28F), .y = h};
    draw_aa_line(cv, LineSeg{.a = a, .b = b},
                 ColorA{.rgb = spec.grid, .alpha = 0.55F * dim}, 1.0F, true);
  }

  // Depth-squared forward-scrolling horizontal lines moving DOWN toward the camera.
  constexpr int kLines = 14;
  for (int k = 0; k < kLines; ++k) {
    const float z = (static_cast<float>(k) + grid_off_) / static_cast<float>(kLines);
    const float y = fh + depth * z * z;
    const float alpha = (0.25F + 0.60F * z) * dim;
    const int iy = static_cast<int>(std::floor(y));
    const float frac = y - static_cast<float>(iy);
    if (iy >= 0 && iy < cv.height) {
      std::uint8_t *row0 = cv.rgba + static_cast<std::size_t>(iy) *
                                         static_cast<std::size_t>(cv.width) * 4U;
      blend_span(row0, cv.width,
                 ColorA{.rgb = spec.grid, .alpha = alpha * (1.0F - frac)}, true);
    }
    if (iy + 1 >= 0 && iy + 1 < cv.height) {
      std::uint8_t *row1 = cv.rgba + static_cast<std::size_t>(iy + 1) *
                                         static_cast<std::size_t>(cv.width) * 4U;
      blend_span(row1, cv.width, ColorA{.rgb = spec.grid, .alpha = alpha * frac}, true);
    }
  }
}

void HeroFlightDeckEngine::ensure_static_background(const HeroTheme &spec,
                                                    int horizon_y) {
  const std::size_t expected_bytes =
      static_cast<std::size_t>(width_) * static_cast<std::size_t>(height_) * 4U;
  if (static_bg_valid_ && static_bg_width_ == width_ && static_bg_height_ == height_ &&
      static_bg_theme_ == theme_ && static_bg_rgba_.size() == expected_bytes) {
    return;
  }

  static_bg_rgba_.assign(expected_bytes, 255);
  cached_windows_.clear();
  cached_beacons_.clear();
  cached_aurora_clip_y_.clear();

  CanvasView cv{
      .rgba = static_bg_rgba_.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };

  // Multi-stop sky gradient.
  const float inv_sky = 1.0F / static_cast<float>(std::max(1, horizon_y - 1));
  for (int y = 0; y < horizon_y; ++y) {
    const HeroRgb rgb = sample_sky(spec.sky, static_cast<float>(y) * inv_sky);
    std::uint8_t *row =
        cv.rgba + static_cast<std::size_t>(y) * static_cast<std::size_t>(cv.width) * 4U;
    for (int x = 0; x < cv.width; ++x) {
      row[0] = rgb.r;
      row[1] = rgb.g;
      row[2] = rgb.b;
      row[3] = 255;
      row += 4;
    }
  }

  // Deep horizon ground fill.
  fill_rect(
      cv,
      RectF{.x = 0.0F,
            .y = static_cast<float>(horizon_y),
            .w = static_cast<float>(width_),
            .h = static_cast<float>(height_ - static_cast<std::uint32_t>(horizon_y))},
      ColorA{.rgb = spec.sky[0], .alpha = 1.0F});

  if (spec.sun) {
    draw_sun_static(static_bg_rgba_.data(), spec, horizon_y);
  }
  switch (spec.scene) {
  case HeroSceneKind::skyline:
    draw_skyline_static(static_bg_rgba_.data(), spec, horizon_y);
    break;
  case HeroSceneKind::gotham:
    draw_gotham_static(static_bg_rgba_.data(), spec, horizon_y);
    break;
  case HeroSceneKind::fuji:
    draw_fuji_static(static_bg_rgba_.data(), spec, horizon_y);
    break;
  case HeroSceneKind::aurora:
    draw_aurora_static(static_bg_rgba_.data(), spec, horizon_y);
    break;
  case HeroSceneKind::wire:
    draw_wire_static(static_bg_rgba_.data(), spec, horizon_y);
    break;
  case HeroSceneKind::palms:
    draw_palms_static(static_bg_rgba_.data(), spec, horizon_y);
    break;
  case HeroSceneKind::qud:
    draw_qud_static(static_bg_rgba_.data(), spec, horizon_y);
    break;
  case HeroSceneKind::none:
    break;
  }

  // Static ocean gradient base (drawn after palms so trunks clip cleanly at horizon).
  if (spec.ground == HeroGroundKind::ocean) {
    const float fh = static_cast<float>(horizon_y);
    const float depth = std::max(1.0F, static_cast<float>(height_) - fh);
    fill_vgrad_rect(
        cv, RectF{.x = 0.0F, .y = fh, .w = static_cast<float>(width_), .h = depth},
        VGrad{.top = rgb_hex(0x0a2540), .bottom = rgb_hex(0x020c17)});
  }

  static_bg_width_ = width_;
  static_bg_height_ = height_;
  static_bg_theme_ = theme_;
  static_bg_valid_ = true;
}

void HeroFlightDeckEngine::draw_background(const HeroTheme &spec) {
  const int horizon_y = std::clamp(
      static_cast<int>(std::lround(static_cast<float>(height_) * spec.horizon)), 16,
      static_cast<int>(height_) - 8);

  // Steady-state frame: single memcpy of cached static sky + sun + scene geometry.
  ensure_static_background(spec, horizon_y);
  std::memcpy(frame_.rgba.data(), static_bg_rgba_.data(), frame_.rgba.size());

  // Dynamic overlays on top of static background cache.
  if (spec.sun) {
    draw_sun_dynamic(spec, horizon_y);
  }
  switch (spec.scene) {
  case HeroSceneKind::skyline:
    draw_skyline_dynamic(spec);
    break;
  case HeroSceneKind::gotham:
    draw_gotham_dynamic(spec, horizon_y);
    break;
  case HeroSceneKind::fuji:
    draw_fuji_dynamic(spec, horizon_y);
    break;
  case HeroSceneKind::aurora:
    draw_aurora_dynamic(spec, horizon_y);
    break;
  case HeroSceneKind::wire:
    draw_wire_dynamic(spec, horizon_y);
    break;
  case HeroSceneKind::palms:
    draw_palms_dynamic(spec, horizon_y);
    break;
  case HeroSceneKind::qud:
    draw_qud_dynamic(spec, horizon_y);
    break;
  case HeroSceneKind::none:
    break;
  }

  if (spec.ground == HeroGroundKind::glyph) {
    draw_glyph_ground(spec, horizon_y);
  } else {
    if (spec.ground == HeroGroundKind::ocean) {
      draw_ocean_dynamic(spec, horizon_y);
    }
    draw_grid(spec, horizon_y);
  }
}

void HeroFlightDeckEngine::draw_question_overlay(const HeroTheme &spec) {
  if (!question_.has_value()) {
    return;
  }
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  const HeroRgb gate_col = spec.rim2;
  const HeroRgb ok_col = spec.cls[4];

  // Top-center translucent question card.
  const std::string title = question_->from + " ASKS: " + question_->text;
  const int title_w = measure_text_5x7(title, 1);
  const int detail_w = measure_text_5x7(question_->detail, 1);
  const float card_w =
      std::min(w - 16.0F, static_cast<float>(std::max(title_w, detail_w)) + 20.0F);
  const float card_h = question_->detail.empty() ? 22.0F : 32.0F;
  const float card_x = (w - card_w) * 0.5F;
  const float card_y = std::max(8.0F, h * 0.05F);
  fill_rect(cv, RectF{.x = card_x, .y = card_y, .w = card_w, .h = card_h},
            ColorA{.rgb = rgb_hex(0x05030b), .alpha = 0.74F});
  stroke_rect(cv, RectF{.x = card_x, .y = card_y, .w = card_w, .h = card_h},
              ColorA{.rgb = gate_col, .alpha = 0.92F}, true);
  draw_text_5x7(
      cv, Vec2{.x = w * 0.5F, .y = card_y + 6.0F}, title,
      TextStyle{.color = ColorA{.rgb = gate_col, .alpha = 1.0F}, .center = true});
  if (!question_->detail.empty()) {
    draw_text_5x7(
        cv, Vec2{.x = w * 0.5F, .y = card_y + 18.0F}, question_->detail,
        TextStyle{.color = ColorA{.rgb = spec.label, .alpha = 0.92F}, .center = true});
  }

  // Pulsing holographic elliptical answer gates.
  for (std::size_t i = 0; i < gates_.size(); ++i) {
    const HeroGateState &gt = gates_[i];
    const bool picked = question_->done && question_->pick == i;
    const bool dim = question_->done && !picked;
    const float alpha = dim ? 0.25F : 1.0F;
    const float pulse =
        1.0F + 0.06F * std::sin(question_->elapsed * 4.0F + static_cast<float>(i));
    const HeroRgb col = picked ? ok_col : gate_col;
    const Vec2 center{.x = gt.x, .y = gt.y};
    const Vec2 radii{.x = gt.radius * pulse, .y = gt.radius * 0.62F * pulse};

    // Outer glow ring + crisp holographic ellipse + inner ring.
    stroke_ellipse(cv, EllipseSpec{.center = center, .radii = radii},
                   ColorA{.rgb = col, .alpha = alpha * 0.30F}, 4.5F, true);
    stroke_ellipse(cv, EllipseSpec{.center = center, .radii = radii},
                   ColorA{.rgb = col, .alpha = alpha}, 1.6F, true);
    stroke_ellipse(
        cv,
        EllipseSpec{.center = center,
                    .radii = Vec2{.x = radii.x * 0.78F, .y = radii.y * 0.78F}},
        ColorA{.rgb = col, .alpha = alpha * 0.45F}, 1.0F, true);

    // Radial dwell progress arc (1.5s dwell).
    if (gt.dwell_seconds > 0.0F && !question_->done) {
      const float frac =
          std::clamp(gt.dwell_seconds / hero_gate_dwell_seconds, 0.0F, 1.0F);
      const float start = -std::numbers::pi_v<float> * 0.5F;
      const float end = start + std::numbers::pi_v<float> * 2.0F * frac;
      stroke_ellipse_arc(
          cv,
          ArcSpec{.center = center,
                  .radii = Vec2{.x = gt.radius + 4.5F, .y = gt.radius * 0.62F + 4.5F},
                  .start_rad = start,
                  .end_rad = end,
                  .thickness = 3.0F},
          ColorA{.rgb = ok_col, .alpha = 0.95F}, true);
    }

    draw_text_5x7(
        cv, Vec2{.x = gt.x, .y = gt.y - 5.0F}, gt.label,
        TextStyle{.color = ColorA{.rgb = spec.label, .alpha = alpha}, .center = true});
    const std::string key_hint = "[" + format_int(static_cast<int>(i + 1)) + "]";
    draw_text_5x7(
        cv, Vec2{.x = gt.x, .y = gt.y + 6.0F}, key_hint,
        TextStyle{.color = ColorA{.rgb = spec.dim, .alpha = alpha}, .center = true});
  }

  // Additive confirmation flash on answer.
  if (question_->done && question_->flash > 0.01F) {
    fill_rect(cv, RectF{.x = 0.0F, .y = 0.0F, .w = w, .h = h},
              ColorA{.rgb = HeroRgb{255, 255, 255}, .alpha = question_->flash * 0.14F},
              true);
  }
}

void HeroFlightDeckEngine::draw_sr71(const HeroTheme &spec) {
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const auto plane = plane_state();
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);
  constexpr float kCamH = 22.0F;
  constexpr float kCamD = 175.0F;
  const float foc = std::min(w * 1.35F, h * 2.10F);
  const float cb = std::cos(plane.bank_rad);
  const float sb = std::sin(plane.bank_rad);

  struct Projected {
    Vec2 pt{};
    float depth = 1.0F;
  };
  const auto project = [&](Vec3 p) -> Projected {
    const float rx = p.x * cb - p.y * sb;
    const float ry = p.x * sb + p.y * cb;
    const float d = std::max(12.0F, p.z + kCamD);
    return Projected{
        .pt = Vec2{.x = plane.x + foc * rx / d, .y = plane.y + foc * (kCamH - ry) / d},
        .depth = d,
    };
  };

  // Full 26-vertex planform outline (stack array, zero heap alloc).
  std::array<Vec2, kSrHalf.size() * 2U - 2U> outline{};
  std::size_t out_idx = 0;
  for (const auto &pt : kSrHalf) {
    outline[out_idx++] = project(Vec3{.x = pt.x, .y = 0.0F, .z = pt.y}).pt;
  }
  for (std::size_t i = kSrHalf.size() - 2; i >= 1; --i) {
    const auto &pt = kSrHalf[i];
    outline[out_idx++] = project(Vec3{.x = -pt.x, .y = 0.0F, .z = pt.y}).pt;
  }
  fill_polygon_vgrad(cv, outline,
                     VGrad{.top = rgb_hex(0x1a1430), .bottom = rgb_hex(0x07050d)});

  // Glowing neon leading-edge rim from left wingtip through nose to right wingtip.
  constexpr std::array<Vec2, 15> kLeadingEdge = {{
      {-27.8F, 12.5F},
      {-8.6F, 44.0F},
      {-7.8F, 50.0F},
      {-6.2F, 63.0F},
      {-4.4F, 76.0F},
      {-2.6F, 88.0F},
      {-1.2F, 98.0F},
      {0.0F, 107.0F},
      {1.2F, 98.0F},
      {2.6F, 88.0F},
      {4.4F, 76.0F},
      {6.2F, 63.0F},
      {7.8F, 50.0F},
      {8.6F, 44.0F},
      {27.8F, 12.5F},
  }};
  for (std::size_t i = 0; i + 1 < kLeadingEdge.size(); ++i) {
    const Vec2 a =
        project(Vec3{.x = kLeadingEdge[i].x, .y = 0.0F, .z = kLeadingEdge[i].y}).pt;
    const Vec2 b =
        project(Vec3{.x = kLeadingEdge[i + 1].x, .y = 0.0F, .z = kLeadingEdge[i + 1].y})
            .pt;
    draw_glow_line(cv, LineSeg{.a = a, .b = b}, ColorA{.rgb = spec.rim, .alpha = 0.92F},
                   3.8F);
  }

  // Fuselage spine, dorsal ridge, and canopy hump (rim2 cyan glint).
  const auto draw_poly3 = [&](std::initializer_list<Vec3> pts3, HeroRgb fill_rgb,
                              std::optional<HeroRgb> stroke_rgb, bool glow) {
    std::array<Vec2, 8> pts2{};
    std::size_t count = 0;
    for (const auto &p : pts3) {
      if (count < pts2.size()) {
        pts2[count++] = project(p).pt;
      }
    }
    const std::span<const Vec2> poly_span{pts2.data(), count};
    fill_polygon(cv, poly_span, ColorA{.rgb = fill_rgb, .alpha = 1.0F});
    if (stroke_rgb.has_value()) {
      stroke_polygon(cv, poly_span, ColorA{.rgb = *stroke_rgb, .alpha = 0.90F}, glow);
    }
  };
  draw_poly3({{-3.2F, 0.0F, 30.0F},
              {0.0F, 3.6F, 40.0F},
              {3.2F, 0.0F, 30.0F},
              {0.0F, 1.2F, 2.0F}},
             rgb_hex(0x0c0916), std::nullopt, false);
  draw_poly3({{-2.4F, 0.0F, 62.0F},
              {0.0F, 4.6F, 72.0F},
              {2.4F, 0.0F, 62.0F},
              {0.0F, 3.4F, 48.0F}},
             rgb_hex(0x110d1f), spec.rim, true);
  draw_poly3({{-1.6F, 1.5F, 74.0F}, {0.0F, 4.4F, 78.0F}, {1.6F, 1.5F, 74.0F}},
             rgb_hex(0x2a2448), spec.rim2, true);

  // Twin engine nacelles + glowing inlet spikes.
  for (const float nx : {-11.3F, 11.3F}) {
    const auto near_p = project(Vec3{.x = nx, .y = 0.0F, .z = -1.5F});
    const auto far_p = project(Vec3{.x = nx, .y = 0.0F, .z = 58.0F});
    const float rn = foc * 2.9F / near_p.depth;
    const float rf = foc * 2.9F / far_p.depth;
    const std::array<Vec2, 4> body = {{
        Vec2{.x = far_p.pt.x - rf, .y = far_p.pt.y},
        Vec2{.x = near_p.pt.x - rn, .y = near_p.pt.y},
        Vec2{.x = near_p.pt.x + rn, .y = near_p.pt.y},
        Vec2{.x = far_p.pt.x + rf, .y = far_p.pt.y},
    }};
    fill_polygon(cv, body, ColorA{.rgb = rgb_hex(0x0a0714), .alpha = 1.0F});
    fill_circle(cv, CircleSpec{.center = near_p.pt, .radius = rn},
                ColorA{.rgb = rgb_hex(0x0a0714), .alpha = 1.0F});
    fill_circle(cv, CircleSpec{.center = far_p.pt, .radius = rf},
                ColorA{.rgb = rgb_hex(0x0a0714), .alpha = 1.0F});
    draw_aa_line(cv, LineSeg{.a = body[0], .b = body[1]},
                 ColorA{.rgb = spec.rim, .alpha = 0.58F}, 1.0F);
    draw_aa_line(cv, LineSeg{.a = body[3], .b = body[2]},
                 ColorA{.rgb = spec.rim, .alpha = 0.58F}, 1.0F);
    const auto spike = project(Vec3{.x = nx, .y = 0.0F, .z = 66.0F});
    fill_circle(cv, CircleSpec{.center = spike.pt, .radius = 1.4F},
                ColorA{.rgb = spec.rim, .alpha = 0.70F}, true);
  }

  // Twin canted vertical tails (~15 deg inward).
  for (const float sd : {-1.0F, 1.0F}) {
    const float nx = sd * 11.3F;
    draw_poly3({{nx, 2.6F, 3.0F},
                {nx, 2.6F, 17.0F},
                {nx - sd * 2.3F, 11.0F, 12.5F},
                {nx - sd * 2.6F, 12.2F, 6.5F}},
               rgb_hex(0x0d0a18), spec.rim, true);
  }

  // Ejector nozzles + glowing afterburner cores + animated Mach shock-diamond plumes.
  const float thrust = std::clamp(smooth_out_rate_ / 2500.0F, 0.14F, 1.60F);
  for (const float nx : {-11.3F, 11.3F}) {
    const auto nozzle = project(Vec3{.x = nx, .y = 0.0F, .z = -1.5F});
    const float rr = foc * 3.0F / nozzle.depth;
    fill_circle(cv, CircleSpec{.center = nozzle.pt, .radius = rr},
                ColorA{.rgb = rgb_hex(0x05030a), .alpha = 1.0F});
    stroke_circle(cv, CircleSpec{.center = nozzle.pt, .radius = rr * 0.92F},
                  ColorA{.rgb = rgb_hex(0x3a3350), .alpha = 1.0F}, 1.2F);
    // Additive outer flame halo + hot core.
    fill_radial_halo(cv, RadialGrad{.center = nozzle.pt,
                                    .inner_r = 0.0F,
                                    .outer_r = rr * (1.8F + thrust * 0.75F),
                                    .inner = ColorA{.rgb = spec.burn[1],
                                                    .alpha = 0.55F + thrust * 0.20F},
                                    .outer = ColorA{.rgb = spec.burn[2], .alpha = 0.0F},
                                    .additive = true});
    fill_circle(cv, CircleSpec{.center = nozzle.pt, .radius = rr * 0.72F},
                ColorA{.rgb = spec.burn[0], .alpha = 0.85F}, true);
    fill_circle(cv, CircleSpec{.center = nozzle.pt, .radius = rr * 0.36F},
                ColorA{.rgb = HeroRgb{255, 255, 255}, .alpha = 0.95F}, true);

    // Tapered afterburner plume extending toward camera (negative z).
    const float plume_len = 8.0F + thrust * 52.0F;
    const auto tail = project(Vec3{.x = nx, .y = 0.0F, .z = -1.5F - plume_len});
    const float r0 = foc * 2.4F / nozzle.depth;
    const float r1 = foc * (0.9F + thrust * 0.8F) / tail.depth;
    const std::array<Vec2, 4> plume = {{
        Vec2{.x = nozzle.pt.x - r0, .y = nozzle.pt.y},
        Vec2{.x = tail.pt.x - r1, .y = tail.pt.y},
        Vec2{.x = tail.pt.x + r1, .y = tail.pt.y},
        Vec2{.x = nozzle.pt.x + r0, .y = nozzle.pt.y},
    }};
    fill_polygon_vgrad(cv, plume,
                       VGrad{.top = spec.burn[1],
                             .bottom = spec.burn[2],
                             .top_alpha = 0.58F,
                             .bottom_alpha = 0.04F,
                             .additive = true});

    // 5 flickering Mach shock diamonds inside the plume.
    constexpr int kSteps = 5;
    for (int k = kSteps; k >= 1; --k) {
      visual_rng_ =
          (visual_rng_ ^ (visual_rng_ >> 15U)) * (1U | visual_rng_) + 0x6D2B79F5U;
      const float flicker =
          0.80F + 0.20F * (static_cast<float>(visual_rng_) / 4294967296.0F);
      const float z =
          -1.5F - static_cast<float>(k) * plume_len / static_cast<float>(kSteps);
      const auto dp = project(Vec3{.x = nx, .y = 0.0F, .z = z});
      const float dr =
          foc * (2.2F - static_cast<float>(k) * 0.18F + thrust * 0.5F) / dp.depth;
      const float alpha =
          std::max(0.0F, (0.78F - static_cast<float>(k) * 0.12F) * flicker);
      const std::array<Vec2, 4> diamond = {{
          Vec2{.x = dp.pt.x, .y = dp.pt.y - dr * 0.72F},
          Vec2{.x = dp.pt.x + dr * 0.48F, .y = dp.pt.y},
          Vec2{.x = dp.pt.x, .y = dp.pt.y + dr * 0.72F},
          Vec2{.x = dp.pt.x - dr * 0.48F, .y = dp.pt.y},
      }};
      fill_polygon(cv, diamond, ColorA{.rgb = HeroRgb{255, 235, 250}, .alpha = alpha},
                   true);
    }
  }
}

void HeroFlightDeckEngine::draw_scanlines(const HeroTheme &spec) {
  if (spec.scan <= 0.001F) {
    return;
  }
  const float keep = std::clamp(1.0F - spec.scan, 0.0F, 1.0F);
  const auto keep_u16 = static_cast<std::uint16_t>(std::lround(keep * 256.0F));
  for (std::uint32_t y = 0; y < height_; y += 3) {
    std::uint8_t *row = frame_.rgba.data() + static_cast<std::size_t>(y) *
                                                 static_cast<std::size_t>(width_) * 4U;
    for (std::uint32_t x = 0; x < width_; ++x) {
      row[0] = static_cast<std::uint8_t>(
          (static_cast<std::uint32_t>(row[0]) * keep_u16) >> 8U);
      row[1] = static_cast<std::uint8_t>(
          (static_cast<std::uint32_t>(row[1]) * keep_u16) >> 8U);
      row[2] = static_cast<std::uint8_t>(
          (static_cast<std::uint32_t>(row[2]) * keep_u16) >> 8U);
      row += 4;
    }
  }
}

void HeroFlightDeckEngine::draw_hud(const HeroTheme &spec) {
  CanvasView cv{
      .rgba = frame_.rgba.data(),
      .width = static_cast<int>(width_),
      .height = static_cast<int>(height_),
  };
  const float w = static_cast<float>(width_);
  const float h = static_cast<float>(height_);

  // Top-right translucent roster pill (when canvas wide enough).
  if (width_ >= 240) {
    std::array<HeroPeerEntry, 3> fallback_roster{};
    std::size_t fallback_count = 0;
    std::span<const HeroPeerEntry> roster = telemetry_.peers;
    if (roster.empty()) {
      const std::uint64_t total_tok =
          telemetry_.input_tokens + telemetry_.cached_tokens +
          telemetry_.reasoning_tokens + telemetry_.output_tokens;
      fallback_roster[fallback_count++] = HeroPeerEntry{
          .name = telemetry_.room_label.empty()
                      ? "main"
                      : sanitize_hero_text(telemetry_.room_label, 12),
          .tokens = total_tok,
          .active = telemetry_.busy,
      };
      if (telemetry_.total_agents > 1) {
        fallback_roster[fallback_count++] = HeroPeerEntry{
            .name = "agents " + format_u64(telemetry_.active_agents) + "/" +
                    format_u64(telemetry_.total_agents),
            .tokens = telemetry_.output_tokens + telemetry_.reasoning_tokens,
            .active = telemetry_.active_agents > 0,
        };
      }
      if (telemetry_.jev_calls > 0) {
        fallback_roster[fallback_count++] = HeroPeerEntry{
            .name = "jev",
            .jev_calls = telemetry_.jev_calls,
            .active = true,
            .is_jev = true,
        };
      }
      roster = std::span<const HeroPeerEntry>{fallback_roster.data(), fallback_count};
    }
    const std::size_t rows = std::min<std::size_t>(7, roster.size());
    const float pill_w = std::min(156.0F, w * 0.36F);
    const float pill_h = 14.0F + static_cast<float>(rows) * 11.0F;
    const float pill_x = w - pill_w - 6.0F;
    const float pill_y = 6.0F;
    fill_rect(cv, RectF{.x = pill_x, .y = pill_y, .w = pill_w, .h = pill_h},
              ColorA{.rgb = rgb_hex(0x060210), .alpha = 0.72F});
    stroke_rect(cv, RectF{.x = pill_x, .y = pill_y, .w = pill_w, .h = pill_h},
                ColorA{.rgb = spec.dim, .alpha = 0.45F});
    draw_text_5x7(cv, Vec2{.x = pill_x + 5.0F, .y = pill_y + 3.0F}, "SOURCE",
                  TextStyle{.color = ColorA{.rgb = spec.dim, .alpha = 0.90F}});
    draw_text_5x7(
        cv, Vec2{.x = pill_x + pill_w - 5.0F, .y = pill_y + 3.0F}, "TOK",
        TextStyle{.color = ColorA{.rgb = spec.dim, .alpha = 0.90F}, .right = true});
    for (std::size_t i = 0; i < rows; ++i) {
      const auto &peer = roster[i];
      const float ry = pill_y + 13.0F + static_cast<float>(i) * 11.0F;
      const HeroRgb tm = spec.team[i % spec.team.size()];
      fill_rect(cv, RectF{.x = pill_x + 5.0F, .y = ry + 1.0F, .w = 5.0F, .h = 5.0F},
                ColorA{.rgb = tm, .alpha = 1.0F});
      const HeroRgb name_col = peer.silent ? rgb_hex(0xff4d6d) : spec.label;
      std::string name = sanitize_hero_text(peer.name, 12);
      if (peer.tool_busy && name.size() < 11) {
        name += "*";
      }
      draw_text_5x7(cv, Vec2{.x = pill_x + 13.0F, .y = ry}, name,
                    TextStyle{.color = ColorA{.rgb = name_col, .alpha = 0.95F}});
      const std::string val = peer.is_jev ? (format_u64(peer.jev_calls) + "C")
                                          : format_compact_tokens(peer.tokens);
      draw_text_5x7(
          cv, Vec2{.x = pill_x + pill_w - 5.0F, .y = ry}, val,
          TextStyle{.color = ColorA{.rgb = name_col, .alpha = 0.78F}, .right = true});
    }
  }

  // Recent answer confirmations just above bottom-left telemetry.
  for (std::size_t i = 0; i < answer_log_.size(); ++i) {
    const float ly = h - 34.0F - static_cast<float>(i) * 10.0F;
    if (ly < 10.0F) {
      break;
    }
    const float alpha = std::max(0.25F, 1.0F - static_cast<float>(i) * 0.30F);
    draw_text_5x7(cv, Vec2{.x = 8.0F, .y = ly}, "+ " + answer_log_[i],
                  TextStyle{.color = ColorA{.rgb = spec.label, .alpha = alpha}});
  }

  // Bottom-left telemetry strip.
  const float safe_miss =
      std::isfinite(smooth_miss_) ? std::clamp(smooth_miss_, 0.0F, 1.0F) : 0.15F;
  const float safe_rate =
      std::isfinite(smooth_rate_) ? std::clamp(smooth_rate_, 0.0F, 1e9F) : 0.0F;
  const float safe_out =
      std::isfinite(smooth_out_rate_) ? std::clamp(smooth_out_rate_, 0.0F, 1e9F) : 0.0F;
  const int cache_pct = static_cast<int>(std::lround((1.0F - safe_miss) * 100.0F));
  const auto thrust_u64 = static_cast<std::uint64_t>(std::llround(safe_out));
  const std::string line1 = "GROUND " + format_rate_k(safe_rate) + " TOK/S  CACHE " +
                            format_int(cache_pct) + "%";
  const std::string line2 = "THRUST " + format_u64(thrust_u64) + " OUT+RSN TOK/S";
  draw_text_5x7(cv, Vec2{.x = 8.0F, .y = h - 20.0F}, line1,
                TextStyle{.color = ColorA{.rgb = spec.label, .alpha = 0.95F}});
  draw_text_5x7(cv, Vec2{.x = 8.0F, .y = h - 10.0F}, line2,
                TextStyle{.color = ColorA{.rgb = spec.dim, .alpha = 0.95F}});

  // Bottom-right theme badge & key hints.
  const std::string badge = "[" + std::string{spec.display_name} + "]";
  draw_text_5x7(
      cv, Vec2{.x = w - 8.0F, .y = h - 20.0F}, badge,
      TextStyle{.color = ColorA{.rgb = spec.rim, .alpha = 0.95F}, .right = true});
  if (width_ >= 340) {
    draw_text_5x7(
        cv, Vec2{.x = w - 8.0F, .y = h - 10.0F},
        "WASD FLY . T THEME . 1-3 ANS . ESC EXIT",
        TextStyle{.color = ColorA{.rgb = spec.dim, .alpha = 0.90F}, .right = true});
  }
}

const HeroFrame &HeroFlightDeckEngine::render() {
  const HeroTheme &spec = hero_theme_spec(theme_);
  draw_background(spec);
  particles_.composite(frame_.rgba, spec);
  draw_question_overlay(spec);
  draw_sr71(spec);
  draw_scanlines(spec);
  draw_hud(spec);
  return frame_;
}

const HeroFrame &HeroFlightDeckEngine::step_and_render(float dt_seconds) {
  step(dt_seconds);
  return render();
}

// ---- Terminal Graphics Encoders ----

namespace {

bool kitty_graphics_capable_impl() noexcept {
  const auto mode = env_view("BLACKBIRD_GRAPHICS");
  if (mode == "off") {
    return false;
  }
  if (mode == "kitty") {
    return true;
  }
  if (!mode.empty() || !env_view("SSH_CONNECTION").empty() ||
      !env_view("TMUX").empty() || !env_view("STY").empty()) {
    return false;
  }
  const auto term_program = env_view("TERM_PROGRAM");
  const auto term = env_view("TERM");
  return term_program == "ghostty" || term_program == "WezTerm" ||
         term == "xterm-ghostty" || term == "xterm-kitty";
}

} // namespace

bool kitty_graphics_capable() { return kitty_graphics_capable_impl(); }

bool kitty_shm_capable() noexcept {
  if (!kitty_graphics_capable_impl()) {
    return false;
  }
  return env_view("SSH_CONNECTION").empty() && env_view("SSH_TTY").empty() &&
         env_view("SSH_CLIENT").empty() && env_view("TMUX").empty() &&
         env_view("STY").empty();
}

std::string encode_kitty_rgba_frame(const HeroFrame &frame,
                                    const HeroKittyPlacement &placement) {
  const auto expected_opt =
      checked_rgba_bytes(HeroSize{.width = frame.width, .height = frame.height});
  constexpr auto kMaxSize = std::numeric_limits<std::size_t>::max();
  if (!expected_opt.has_value() || frame.rgba.size() != *expected_opt ||
      placement.columns == 0 || placement.rows == 0 || placement.row == kMaxSize ||
      placement.column == kMaxSize) {
    return {};
  }
  const std::size_t expected = *expected_opt;

  // 3072 raw bytes -> exactly 4096 base64 characters per Kitty chunk.
  constexpr std::size_t kRawChunkBytes = 3072;
  const std::size_t b64_groups = (expected - 1U) / 3U + 1U;
  const std::size_t num_chunks = (expected - 1U) / kRawChunkBytes + 1U;
  std::string out;
  if (b64_groups <= (kMaxSize - 96U) / 4U &&
      num_chunks <= (kMaxSize - b64_groups * 4U - 96U) / 24U) {
    out.reserve(b64_groups * 4U + num_chunks * 24U + 96U);
  }

  // Anchor at (row, column) with DECSC/DECRC cursor save/restore.
  out += "\x1b"
         "7\x1b[";
  out += std::to_string(placement.row + 1);
  out += ';';
  out += std::to_string(placement.column + 1);
  out += 'H';

  std::size_t offset = 0;
  std::size_t chunk_idx = 0;
  while (offset < expected) {
    const std::size_t take = std::min(kRawChunkBytes, expected - offset);
    const bool is_first = (chunk_idx == 0);
    const bool is_last = (offset + take >= expected);
    if (is_first) {
      out += "\x1b_Ga=T,f=32,s=";
      out += std::to_string(frame.width);
      out += ",v=";
      out += std::to_string(frame.height);
      out += ",i=";
      out += std::to_string(placement.image_id);
      out += ",p=";
      out += std::to_string(placement.placement_id);
      out += ",q=2,C=1,c=";
      out += std::to_string(placement.columns);
      out += ",r=";
      out += std::to_string(placement.rows);
      out += is_last ? ",m=0;" : ",m=1;";
    } else {
      out += is_last ? "\x1b_Gm=0;" : "\x1b_Gm=1;";
    }
    append_base64(out, std::span<const std::uint8_t>{frame.rgba.data() + offset, take});
    out += "\x1b\\";
    offset += take;
    ++chunk_idx;
  }

  out += "\x1b"
         "8";
  return out;
}

std::string encode_kitty_rgb_frame(const HeroFrame &frame,
                                   const HeroKittyPlacement &placement) {
  const auto expected_opt =
      checked_rgba_bytes(HeroSize{.width = frame.width, .height = frame.height});
  constexpr auto kMaxSize = std::numeric_limits<std::size_t>::max();
  if (!expected_opt.has_value() || frame.rgba.size() != *expected_opt ||
      placement.columns == 0 || placement.rows == 0 || placement.row == kMaxSize ||
      placement.column == kMaxSize) {
    return {};
  }
  const std::size_t pixels = *expected_opt / 4U;
  const std::size_t rgb_bytes = pixels * 3U;

  // 1024 pixels = 3072 RGB bytes -> exactly 4096 base64 characters per Kitty chunk.
  constexpr std::size_t kChunkPixels = 1024;
  constexpr std::size_t kRawChunkBytes = kChunkPixels * 3U;
  const std::size_t b64_groups = (rgb_bytes - 1U) / 3U + 1U;
  const std::size_t num_chunks = (rgb_bytes - 1U) / kRawChunkBytes + 1U;
  std::string out;
  if (b64_groups <= (kMaxSize - 96U) / 4U &&
      num_chunks <= (kMaxSize - b64_groups * 4U - 96U) / 24U) {
    out.reserve(b64_groups * 4U + num_chunks * 24U + 96U);
  }

  // Anchor at (row, column) with DECSC/DECRC cursor save/restore.
  out += "\x1b"
         "7\x1b[";
  out += std::to_string(placement.row + 1);
  out += ';';
  out += std::to_string(placement.column + 1);
  out += 'H';

  std::array<std::uint8_t, kRawChunkBytes> chunk_rgb{};
  std::size_t pixel_offset = 0;
  std::size_t chunk_idx = 0;
  while (pixel_offset < pixels) {
    const std::size_t take_pixels = std::min(kChunkPixels, pixels - pixel_offset);
    const bool is_first = (chunk_idx == 0);
    const bool is_last = (pixel_offset + take_pixels >= pixels);
    if (is_first) {
      out += "\x1b_Ga=T,f=24,s=";
      out += std::to_string(frame.width);
      out += ",v=";
      out += std::to_string(frame.height);
      out += ",i=";
      out += std::to_string(placement.image_id);
      out += ",p=";
      out += std::to_string(placement.placement_id);
      out += ",q=2,C=1,c=";
      out += std::to_string(placement.columns);
      out += ",r=";
      out += std::to_string(placement.rows);
      out += is_last ? ",m=0;" : ",m=1;";
    } else {
      out += is_last ? "\x1b_Gm=0;" : "\x1b_Gm=1;";
    }
    const std::uint8_t *src = frame.rgba.data() + pixel_offset * 4U;
    std::uint8_t *dst = chunk_rgb.data();
    for (std::size_t p = 0; p < take_pixels; ++p) {
      dst[0] = src[0];
      dst[1] = src[1];
      dst[2] = src[2];
      src += 4;
      dst += 3;
    }
    append_base64(out,
                  std::span<const std::uint8_t>{chunk_rgb.data(), take_pixels * 3U});
    out += "\x1b\\";
    pixel_offset += take_pixels;
    ++chunk_idx;
  }

  out += "\x1b"
         "8";
  return out;
}

std::string encode_kitty_shm_rgb_frame(const HeroFrame &frame,
                                       const HeroKittyPlacement &placement) {
  const auto expected_opt =
      checked_rgba_bytes(HeroSize{.width = frame.width, .height = frame.height});
  constexpr auto kMaxSize = std::numeric_limits<std::size_t>::max();
  if (!expected_opt.has_value() || frame.rgba.size() != *expected_opt ||
      placement.columns == 0 || placement.rows == 0 || placement.row == kMaxSize ||
      placement.column == kMaxSize) {
    return {};
  }
  const std::size_t pixels = *expected_opt / 4U;
  const std::size_t rgb_bytes = pixels * 3U;
  if (rgb_bytes == 0U ||
      rgb_bytes > static_cast<std::size_t>(std::numeric_limits<off_t>::max())) {
    return encode_kitty_rgb_frame(frame, placement);
  }

  // Unique POSIX shared memory name <= 30 chars (macOS PSHMNAMLEN = 31).
  static std::atomic<std::uint64_t> g_shm_seq{1U};
  const unsigned pid_part = static_cast<unsigned>(::getpid()) % 100000000U;
  std::array<char, 31> shm_name{};
  int fd = -1;
  int name_len = 0;
  for (int attempt = 0; attempt < 8; ++attempt) {
    const unsigned seq_part =
        static_cast<unsigned>(g_shm_seq.fetch_add(1U, std::memory_order_relaxed)) %
        100000000U;
    name_len = std::snprintf(shm_name.data(), shm_name.size(), "/bb-fd-%u-%u", pid_part,
                             seq_part);
    if (name_len <= 0 || static_cast<std::size_t>(name_len) >= shm_name.size()) {
      return encode_kitty_rgb_frame(frame, placement);
    }
    fd = ::shm_open(shm_name.data(), O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd >= 0) {
      break;
    }
    if (errno != EEXIST) {
      return encode_kitty_rgb_frame(frame, placement);
    }
  }
  if (fd < 0) {
    return encode_kitty_rgb_frame(frame, placement);
  }

  int trunc_rc = 0;
  do {
    trunc_rc = ::ftruncate(fd, static_cast<off_t>(rgb_bytes));
  } while (trunc_rc != 0 && errno == EINTR);
  if (trunc_rc != 0) {
    ::close(fd);
    ::shm_unlink(shm_name.data());
    return encode_kitty_rgb_frame(frame, placement);
  }

  void *mapped = ::mmap(nullptr, rgb_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mapped == MAP_FAILED) {
    ::close(fd);
    ::shm_unlink(shm_name.data());
    return encode_kitty_rgb_frame(frame, placement);
  }

  // Pack tight 24-bit RGB directly into shared memory (zero base64 on pixel bytes).
  const std::uint8_t *src = frame.rgba.data();
  auto *dst = static_cast<std::uint8_t *>(mapped);
  for (std::size_t p = 0; p < pixels; ++p) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    src += 4;
    dst += 3;
  }

  ::munmap(mapped, rgb_bytes);
  ::close(fd);

  // Per Kitty t=s spec, the terminal opens and unlinks shm_name after reading it.
  std::string out;
  out.reserve(128U);
  out += "\x1b"
         "7\x1b[";
  out += std::to_string(placement.row + 1U);
  out += ';';
  out += std::to_string(placement.column + 1U);
  out += "H\x1b_Ga=T,f=24,t=s,s=";
  out += std::to_string(frame.width);
  out += ",v=";
  out += std::to_string(frame.height);
  out += ",i=";
  out += std::to_string(placement.image_id);
  out += ",p=";
  out += std::to_string(placement.placement_id);
  out += ",q=2,C=1,c=";
  out += std::to_string(placement.columns);
  out += ",r=";
  out += std::to_string(placement.rows);
  out += ';';
  append_base64(out, std::span<const std::uint8_t>{
                         reinterpret_cast<const std::uint8_t *>(shm_name.data()),
                         static_cast<std::size_t>(name_len)});
  out += "\x1b\\\x1b"
         "8";
  return out;
}

std::string encode_kitty_erase(std::uint32_t image_id) {
  return "\x1b_Ga=d,d=I,i=" + std::to_string(image_id) + ",q=2;\x1b\\";
}

std::vector<std::string>
encode_truecolor_halfblock_frame(const HeroFrame &frame,
                                 const HeroHalfBlockOptions &options) {
  constexpr auto kMaxSize = std::numeric_limits<std::size_t>::max();
  if (options.columns == 0 || options.rows == 0 || options.rows > kMaxSize / 2U) {
    return {};
  }
  const auto expected_opt =
      checked_rgba_bytes(HeroSize{.width = frame.width, .height = frame.height});
  const bool valid_frame =
      expected_opt.has_value() && frame.rgba.size() == *expected_opt;

  std::vector<std::string> lines;
  lines.reserve(options.rows);
  if (!valid_frame) {
    std::string blank_row;
    blank_row.reserve(options.columns + 20U);
    blank_row += "\x1b[48;2;0;0;0m";
    blank_row.append(options.columns, ' ');
    blank_row += "\x1b[0m";
    lines.assign(options.rows, blank_row);
    return lines;
  }

  const auto scale_index = [](std::size_t idx, std::size_t num,
                              std::size_t den) noexcept -> std::size_t {
    if (idx >= den) {
      return num;
    }
    // Overflow-safe floor(idx * num / den) via quotient + remainder split.
    const std::size_t q = num / den;
    const std::size_t rem = num % den;
    const auto scaled_rem =
        static_cast<std::size_t>((static_cast<double>(idx) * static_cast<double>(rem)) /
                                 static_cast<double>(den));
    return std::min(num, idx * q + scaled_rem);
  };

  struct SpanRange {
    std::size_t start = 0;
    std::size_t end = 0;
  };
  struct BoxSpan {
    SpanRange x{};
    SpanRange y{};
  };

  const std::size_t fw = frame.width;
  const std::size_t fh = frame.height;
  const std::size_t target_h = options.rows * 2U;

  // Precompute integer source spans once per frame (zero double math in inner loop).
  std::vector<SpanRange> x_spans(options.columns);
  for (std::size_t c = 0; c < options.columns; ++c) {
    const std::size_t x0 = std::min(fw - 1U, scale_index(c, fw, options.columns));
    const std::size_t xe =
        std::min(fw, std::max(x0 + 1U, scale_index(c + 1U, fw, options.columns)));
    x_spans[c] = SpanRange{.start = x0, .end = xe};
  }
  std::vector<SpanRange> y_spans(target_h);
  for (std::size_t ys = 0; ys < target_h; ++ys) {
    const std::size_t y0 = std::min(fh - 1U, scale_index(ys, fh, target_h));
    const std::size_t ye =
        std::min(fh, std::max(y0 + 1U, scale_index(ys + 1U, fh, target_h)));
    y_spans[ys] = SpanRange{.start = y0, .end = ye};
  }

  const std::uint8_t *rgba_ptr = frame.rgba.data();
  const auto sample_span = [rgba_ptr, fw](BoxSpan box) noexcept -> HeroRgb {
    if (box.x.end - box.x.start == 1U && box.y.end - box.y.start == 1U) {
      const std::size_t off = (box.y.start * fw + box.x.start) * 4U;
      return HeroRgb{
          .r = rgba_ptr[off],
          .g = rgba_ptr[off + 1U],
          .b = rgba_ptr[off + 2U],
      };
    }
    std::uint64_t sr = 0;
    std::uint64_t sg = 0;
    std::uint64_t sb = 0;
    const std::uint64_t count =
        static_cast<std::uint64_t>(box.y.end - box.y.start) * (box.x.end - box.x.start);
    for (std::size_t y = box.y.start; y < box.y.end; ++y) {
      const std::uint8_t *px = rgba_ptr + (y * fw + box.x.start) * 4U;
      for (std::size_t x = box.x.start; x < box.x.end; ++x) {
        sr += px[0];
        sg += px[1];
        sb += px[2];
        px += 4;
      }
    }
    return HeroRgb{
        .r = static_cast<std::uint8_t>(sr / count),
        .g = static_cast<std::uint8_t>(sg / count),
        .b = static_cast<std::uint8_t>(sb / count),
    };
  };

  for (std::size_t r = 0; r < options.rows; ++r) {
    std::string line;
    line.reserve(options.columns * 24U);
    std::optional<HeroRgb> prev_fg;
    std::optional<HeroRgb> prev_bg;
    const SpanRange y_top = y_spans[r * 2U];
    const SpanRange y_bot = y_spans[r * 2U + 1U];
    for (std::size_t c = 0; c < options.columns; ++c) {
      const SpanRange xs = x_spans[c];
      const HeroRgb top = sample_span(BoxSpan{.x = xs, .y = y_top});
      const HeroRgb bot = sample_span(BoxSpan{.x = xs, .y = y_bot});
      if (top == bot) {
        // Coalesce identical top/bottom pixels into a single ASCII space using
        // only background SGR, preserving prev_fg for subsequent half-block cells.
        if (!prev_bg.has_value() || *prev_bg != bot) {
          line += "\x1b[48;2;";
          append_u8_dec(line, bot.r);
          line += ';';
          append_u8_dec(line, bot.g);
          line += ';';
          append_u8_dec(line, bot.b);
          line += 'm';
          prev_bg = bot;
        }
        line += ' ';
        continue;
      }
      if (!prev_fg.has_value() || *prev_fg != top) {
        line += "\x1b[38;2;";
        append_u8_dec(line, top.r);
        line += ';';
        append_u8_dec(line, top.g);
        line += ';';
        append_u8_dec(line, top.b);
        line += 'm';
        prev_fg = top;
      }
      if (!prev_bg.has_value() || *prev_bg != bot) {
        line += "\x1b[48;2;";
        append_u8_dec(line, bot.r);
        line += ';';
        append_u8_dec(line, bot.g);
        line += ';';
        append_u8_dec(line, bot.b);
        line += 'm';
        prev_bg = bot;
      }
      // U+2580 UPPER HALF BLOCK ("▀"): fg = top pixel, bg = bottom pixel.
      line += "\xE2\x96\x80";
    }
    line += "\x1b[0m";
    lines.push_back(std::move(line));
  }
  return lines;
}

std::string encode_halfblock_diff(const HeroHalfBlockDiff &diff) {
  const bool emit_all =
      diff.full_redraw || diff.prev_rows.size() != diff.curr_rows.size();
  std::size_t bytes = 0;
  for (std::size_t r = 0; r < diff.curr_rows.size(); ++r) {
    if (emit_all || diff.curr_rows[r] != diff.prev_rows[r]) {
      bytes += diff.curr_rows[r].size() + 16U;
    }
  }
  if (bytes == 0U) {
    return {};
  }
  std::string out;
  out.reserve(bytes);
  for (std::size_t r = 0; r < diff.curr_rows.size(); ++r) {
    if (emit_all || diff.curr_rows[r] != diff.prev_rows[r]) {
      out += "\x1b[";
      out += std::to_string(r + 1U);
      out += ";1H";
      out += diff.curr_rows[r];
    }
  }
  return out;
}

} // namespace blackbird
