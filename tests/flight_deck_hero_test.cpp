#include "blackbird/flight_deck_hero.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <numeric>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

int g_failures = 0;

void check(bool cond, std::string_view msg) {
  if (!cond) {
    std::cerr << "FAIL: " << msg << "\n";
    ++g_failures;
  }
}

void require(bool cond, std::string_view msg) { check(cond, msg); }

std::vector<std::uint8_t> decode_base64(std::string_view b64) {
  std::array<int, 256> lut{};
  lut.fill(-1);
  for (int i = 0; i < 26; ++i) {
    lut[static_cast<std::size_t>('A' + i)] = i;
    lut[static_cast<std::size_t>('a' + i)] = i + 26;
  }
  for (int i = 0; i < 10; ++i) {
    lut[static_cast<std::size_t>('0' + i)] = i + 52;
  }
  lut[static_cast<std::size_t>('+')] = 62;
  lut[static_cast<std::size_t>('/')] = 63;

  std::vector<std::uint8_t> out;
  out.reserve((b64.size() / 4U) * 3U);
  int val = 0;
  int valb = -8;
  for (const char ch : b64) {
    if (ch == '=') {
      break;
    }
    const int d = lut[static_cast<unsigned char>(ch)];
    if (d < 0) {
      continue;
    }
    val = (val << 6) + d;
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<std::uint8_t>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

std::uint64_t frame_signature(const blackbird::HeroFrame &frame) {
  std::uint64_t h = 1469598103934665603ULL;
  for (std::size_t i = 0; i < frame.rgba.size(); i += 17) {
    h ^= static_cast<std::uint64_t>(frame.rgba[i]);
    h *= 1099511628211ULL;
  }
  return h;
}

void test_themes_and_rendering() {
  using namespace blackbird;

  HeroTelemetryInput tel{};
  tel.total_tok_per_sec = 4200.0;
  tel.out_rsn_tok_per_sec = 1100.0;
  tel.cache_hit_ratio = 0.78;
  tel.input_tokens = 25000;
  tel.cached_tokens = 90000;
  tel.reasoning_tokens = 3200;
  tel.output_tokens = 5400;
  tel.jev_calls = 3;
  tel.active_agents = 4;
  tel.total_agents = 6;
  tel.busy = true;
  tel.main_context_fill = 0.72;

  std::array<std::uint64_t, hero_theme_count> sigs{};
  HeroThemeId cur = HeroThemeId::synthwave;
  for (std::size_t i = 0; i < hero_theme_count; ++i) {
    const auto name = hero_theme_name(cur);
    const auto parsed = parse_hero_theme(name);
    check(parsed.has_value() && *parsed == cur, "theme round-trip name/parse");

    HeroFlightDeckEngine engine(HeroCanvasConfig{
        .size = HeroSize{.width = 320, .height = 200},
        .theme = cur,
        .seed = 42,
    });
    engine.set_telemetry(tel);
    const auto &frame = engine.step_and_render(0.05F);
    check(frame.width == 320 && frame.height == 200, "exact frame dimensions");
    check(frame.rgba.size() == 320U * 200U * 4U, "exact RGBA buffer size");

    bool all_alpha_255 = true;
    std::uint64_t sum_rgb = 0;
    for (std::size_t p = 0; p < frame.rgba.size(); p += 4) {
      sum_rgb += frame.rgba[p] + frame.rgba[p + 1] + frame.rgba[p + 2];
      if (frame.rgba[p + 3] != 255) {
        all_alpha_255 = false;
        break;
      }
    }
    check(all_alpha_255, "all alpha bytes == 255");
    check(sum_rgb > 100000ULL, "theme renders non-black vivid pixels");
    sigs[i] = frame_signature(frame);

    cur = next_hero_theme(cur);
  }
  check(cur == HeroThemeId::synthwave, "next_hero_theme wraps cleanly after 8 themes");
  check(parse_hero_theme("TOKYO NIGHT") == HeroThemeId::tokyonight,
        "parse display name tokyo night");
  check(parse_hero_theme("retro-82") == HeroThemeId::retro82,
        "parse display name retro-82");
  check(parse_hero_theme("Dying Earth") == HeroThemeId::dyingearth,
        "parse display name dying earth");
  check(!parse_hero_theme("nonexistent").has_value(), "unknown theme returns nullopt");

  for (std::size_t i = 0; i < hero_theme_count; ++i) {
    for (std::size_t j = i + 1; j < hero_theme_count; ++j) {
      check(sigs[i] != sigs[j], "all 8 themes render distinct palettes");
    }
  }
}

void test_steering_and_spring_return() {
  using namespace blackbird;

  HeroFlightDeckEngine engine(HeroCanvasConfig{
      .size = HeroSize{.width = 480, .height = 300},
      .theme = HeroThemeId::synthwave,
      .seed = 11,
  });
  const auto p0 = engine.plane_state();

  // Steer left + up.
  engine.steer_input(HeroControlInput{.left = true, .up = true});
  for (int i = 0; i < 20; ++i) {
    engine.step(0.03F);
  }
  const auto p_left_up = engine.plane_state();
  check(p_left_up.offset_x < -40.0F, "left steering shifts plane left");
  check(p_left_up.offset_y < -20.0F, "up steering shifts plane up");
  check(p_left_up.x < p0.x - 30.0F, "screen x moves left");
  check(p_left_up.y < p0.y - 15.0F, "screen y moves up");

  // Release -> critically damped spring returns toward cruise (0, 0).
  engine.steer_input(HeroControlInput{});
  for (int i = 0; i < 60; ++i) {
    engine.step(0.03F);
  }
  const auto p_returned = engine.plane_state();
  check(std::abs(p_returned.offset_x) < 2.0F, "spring returns offset_x toward cruise");
  check(std::abs(p_returned.offset_y) < 2.0F, "spring returns offset_y toward cruise");

  // Steer right + down.
  engine.steer_input(HeroControlInput{.right = true, .down = true});
  for (int i = 0; i < 20; ++i) {
    engine.step(0.03F);
  }
  const auto p_right_down = engine.plane_state();
  check(p_right_down.offset_x > 40.0F, "right steering shifts plane right");
  check(p_right_down.offset_y > 20.0F, "down steering shifts plane down");
}

void test_fly_to_answer_and_key_answer() {
  using namespace blackbird;

  // 1) Fly-to-answer dwell (1.5s inside gate 0).
  HeroFlightDeckEngine engine(HeroCanvasConfig{
      .size = HeroSize{.width = 480, .height = 300},
      .theme = HeroThemeId::synthwave,
      .seed = 11,
  });
  engine.set_question(HeroQuestion{
      .from = "main",
      .text = "run build?",
      .detail = "ninja -C build/debug",
      .options = {"approve", "deny", "always"},
  });
  check(engine.has_question(), "question active");
  check(engine.gates().size() == 3, "three gates created");
  check(!engine.answered_index().has_value(), "no answer yet");

  // Fly smoothly into gate 0 using proportional stick input targeting gate 0.
  for (int i = 0; i < 180 && !engine.answered_index().has_value(); ++i) {
    const auto p = engine.plane_state();
    const auto &g0 = engine.gates()[0];
    const float dx = g0.x - p.x;
    const float dy = g0.y - p.y;
    engine.steer_input(HeroControlInput{
        .stick_x = std::clamp(dx / 25.0F, -1.0F, 1.0F),
        .stick_y = std::clamp(dy / 25.0F, -1.0F, 1.0F),
    });
    engine.step(0.03F);
  }
  check(engine.answered_index().has_value() && *engine.answered_index() == 0U,
        "1.5s dwell inside gate 0 triggers answered_index == 0");
  check(!engine.answer_log().empty(), "answer logged");
  const auto taken = engine.take_answered_index();
  check(taken.has_value() && *taken == 0U, "take_answered_index returns 0");
  check(!engine.answered_index().has_value(), "take_answered_index consumes result");

  // 2) Instant answer_by_key(1).
  engine.set_question(HeroQuestion{
      .from = "claude",
      .text = "keep recorder separate?",
      .detail = "raw recorder vs station",
      .options = {"separate", "fold in", "discuss"},
  });
  check(engine.answer_by_key(1), "answer_by_key(1) succeeds");
  check(!engine.answer_by_key(2), "duplicate answer_by_key rejected");
  check(engine.answered_index().has_value() && *engine.answered_index() == 1U,
        "answer_by_key(1) sets answered_index == 1");
  const auto &flash_frame = engine.render();
  check(flash_frame.rgba.size() == 480U * 300U * 4U, "render during flash valid");
}

void test_kitty_encoder_roundtrip_and_erase() {
  using namespace blackbird;

  HeroFlightDeckEngine engine(HeroCanvasConfig{
      .size = HeroSize{.width = 160, .height = 100},
      .theme = HeroThemeId::hackerman,
      .seed = 7,
  });
  const auto &frame = engine.step_and_render(0.05F);
  const std::string encoded =
      encode_kitty_rgba_frame(frame, HeroKittyPlacement{.row = 2,
                                                        .column = 4,
                                                        .columns = 60,
                                                        .rows = 20,
                                                        .image_id = 72172,
                                                        .placement_id = 1});

  check(encoded.starts_with(
            "\x1b"
            "7\x1b[3;5H\x1b_Ga=T,f=32,s=160,v=100,i=72172,p=1,q=2,C=1,c=60,r=20,m=1;"),
        "kitty prefix header matches exact spec");
  check(encoded.ends_with("\x1b\\"
                          "\x1b"
                          "8"),
        "kitty trailer ends with ST + DECRC");

  // Parse every APC chunk and verify chunk size <= 4096, m=1..m=0, and exact RGBA
  // decode.
  std::size_t pos = encoded.find("\x1b_G");
  std::string all_b64;
  std::size_t chunk_count = 0;
  bool saw_final_m0 = false;
  while (pos != std::string::npos) {
    const std::size_t semi = encoded.find(';', pos);
    const std::size_t st = encoded.find("\x1b\\", semi);
    check(semi != std::string::npos && st != std::string::npos, "valid APC framing");
    if (semi == std::string::npos || st == std::string::npos) {
      break;
    }
    const std::string_view header(encoded.data() + pos + 3, semi - (pos + 3));
    const std::string_view payload(encoded.data() + semi + 1, st - (semi + 1));
    check(payload.size() <= 4096U, "base64 chunk <= 4096 bytes");
    const bool is_m0 = header.find("m=0") != std::string_view::npos;
    const bool is_m1 = header.find("m=1") != std::string_view::npos;
    check(is_m0 != is_m1, "chunk specifies exactly one of m=0 or m=1");
    if (is_m0) {
      saw_final_m0 = true;
    } else {
      check(payload.size() == 4096U, "non-final chunk is full 4096 base64 bytes");
    }
    all_b64.append(payload);
    ++chunk_count;
    pos = encoded.find("\x1b_G", st + 2);
  }
  check(chunk_count > 1, "160x100 RGBA splits into multiple Kitty chunks");
  check(saw_final_m0, "final chunk ends with m=0");

  const auto decoded = decode_base64(all_b64);
  check(decoded == frame.rgba, "base64 chunks decode back to exact RGBA bytes");

  const std::string erase = encode_kitty_erase(72172);
  check(erase == "\x1b_Ga=d,d=I,i=72172,q=2;\x1b\\", "exact kitty erase sequence");

  // Single-chunk small frame test (<= 3072 raw bytes -> m=0 in single chunk).
  HeroFrame tiny{
      .width = 8, .height = 8, .rgba = std::vector<std::uint8_t>(8 * 8 * 4, 128)};
  const std::string tiny_enc = encode_kitty_rgba_frame(
      tiny, HeroKittyPlacement{.row = 0, .column = 0, .columns = 4, .rows = 2});
  check(tiny_enc.find("m=0;") != std::string::npos &&
            tiny_enc.find("m=1;") == std::string::npos,
        "small frame emits single m=0 chunk");
}

void test_kitty_rgb_encoder_roundtrip() {
  using namespace blackbird;

  HeroFlightDeckEngine engine(HeroCanvasConfig{
      .size = HeroSize{.width = 160, .height = 100},
      .theme = HeroThemeId::hackerman,
      .seed = 7,
  });
  const auto &frame = engine.step_and_render(0.05F);
  const HeroKittyPlacement placement{.row = 2,
                                     .column = 4,
                                     .columns = 60,
                                     .rows = 20,
                                     .image_id = 72172,
                                     .placement_id = 1};
  const std::string rgba_enc = encode_kitty_rgba_frame(frame, placement);
  const std::string rgb_enc = encode_kitty_rgb_frame(frame, placement);

  check(rgb_enc.starts_with(
            "\x1b"
            "7\x1b[3;5H\x1b_Ga=T,f=24,s=160,v=100,i=72172,p=1,q=2,C=1,c=60,r=20,m=1;"),
        "kitty rgb prefix header uses f=24");
  check(rgb_enc.ends_with("\x1b\\"
                          "\x1b"
                          "8"),
        "kitty rgb trailer ends with ST + DECRC");
  check(rgb_enc.size() * 100U < rgba_enc.size() * 78U,
        "kitty f=24 RGB payload is ~25% smaller than f=32 RGBA");

  std::size_t pos = rgb_enc.find("\x1b_G");
  std::string all_b64;
  std::size_t chunk_count = 0;
  bool saw_final_m0 = false;
  while (pos != std::string::npos) {
    const std::size_t semi = rgb_enc.find(';', pos);
    const std::size_t st = rgb_enc.find("\x1b\\", semi);
    check(semi != std::string::npos && st != std::string::npos,
          "valid RGB APC framing");
    if (semi == std::string::npos || st == std::string::npos) {
      break;
    }
    const std::string_view header(rgb_enc.data() + pos + 3, semi - (pos + 3));
    const std::string_view payload(rgb_enc.data() + semi + 1, st - (semi + 1));
    check(payload.size() <= 4096U, "RGB base64 chunk <= 4096 bytes");
    const bool is_m0 = header.find("m=0") != std::string_view::npos;
    const bool is_m1 = header.find("m=1") != std::string_view::npos;
    check(is_m0 != is_m1, "RGB chunk specifies exactly one of m=0 or m=1");
    if (is_m0) {
      saw_final_m0 = true;
    } else {
      check(payload.size() == 4096U, "non-final RGB chunk is full 4096 base64 bytes");
    }
    all_b64.append(payload);
    ++chunk_count;
    pos = rgb_enc.find("\x1b_G", st + 2);
  }
  check(chunk_count > 1U, "160x100 RGB splits into multiple Kitty chunks");
  check(saw_final_m0, "final RGB chunk ends with m=0");

  const auto decoded = decode_base64(all_b64);
  const std::size_t expected_rgb_bytes = static_cast<std::size_t>(frame.width) *
                                         static_cast<std::size_t>(frame.height) * 3U;
  check(decoded.size() == expected_rgb_bytes,
        "kitty rgb decoded byte count == width * height * 3");
  bool pixels_match = decoded.size() == expected_rgb_bytes;
  for (std::size_t p = 0; pixels_match && p < expected_rgb_bytes / 3U; ++p) {
    if (decoded[p * 3U] != frame.rgba[p * 4U] ||
        decoded[p * 3U + 1U] != frame.rgba[p * 4U + 1U] ||
        decoded[p * 3U + 2U] != frame.rgba[p * 4U + 2U]) {
      pixels_match = false;
    }
  }
  check(pixels_match, "kitty rgb decoded bytes match frame RGBA with alpha stripped");

  // Single-chunk tiny RGB frame (8x8x3 = 192 bytes -> m=0).
  HeroFrame tiny{
      .width = 8, .height = 8, .rgba = std::vector<std::uint8_t>(8 * 8 * 4, 200)};
  const std::string tiny_rgb = encode_kitty_rgb_frame(
      tiny, HeroKittyPlacement{.row = 0, .column = 0, .columns = 4, .rows = 2});
  check(tiny_rgb.find("f=24,") != std::string::npos &&
            tiny_rgb.find("m=0;") != std::string::npos &&
            tiny_rgb.find("m=1;") == std::string::npos,
        "small RGB frame emits single m=0 chunk");
}

void test_halfblock_coalescing_and_diff() {
  using namespace blackbird;

  // 1) Solid frame coalesces identical top == bot cells to ASCII spaces with bg only.
  HeroFrame solid{
      .width = 16, .height = 8, .rgba = std::vector<std::uint8_t>(16 * 8 * 4)};
  for (std::size_t p = 0; p < 16U * 8U; ++p) {
    solid.rgba[p * 4U] = 12;
    solid.rgba[p * 4U + 1U] = 34;
    solid.rgba[p * 4U + 2U] = 56;
    solid.rgba[p * 4U + 3U] = 255;
  }
  const auto solid_rows = encode_truecolor_halfblock_frame(
      solid, HeroHalfBlockOptions{.columns = 8, .rows = 4});
  check(solid_rows.size() == 4U, "solid halfblock produces exact row count");
  for (const auto &row : solid_rows) {
    check(row == "\x1b[48;2;12;34;56m        \x1b[0m",
          "solid row coalesces to single bg SGR + ASCII spaces without half-block");
    check(row.find("\xE2\x96\x80") == std::string::npos, "solid row omits half-block");
    check(row.find("\x1b[38;2;") == std::string::npos, "solid row omits fg SGR");
  }

  // 2) Mixed top/bot frame preserves exact RGB colors and keeps prev_fg across spaces.
  HeroFrame mixed{
      .width = 4, .height = 2, .rgba = std::vector<std::uint8_t>(4 * 2 * 4, 255)};
  auto set_px = [&](std::size_t x, std::size_t y, HeroRgb rgb) {
    const std::size_t off = (y * 4U + x) * 4U;
    mixed.rgba[off] = rgb.r;
    mixed.rgba[off + 1U] = rgb.g;
    mixed.rgba[off + 2U] = rgb.b;
    mixed.rgba[off + 3U] = 255;
  };
  set_px(0, 0, HeroRgb{10, 20, 30});
  set_px(0, 1, HeroRgb{40, 50, 60});
  set_px(1, 0, HeroRgb{40, 50, 60});
  set_px(1, 1, HeroRgb{40, 50, 60});
  set_px(2, 0, HeroRgb{10, 20, 30});
  set_px(2, 1, HeroRgb{40, 50, 60});
  set_px(3, 0, HeroRgb{70, 80, 90});
  set_px(3, 1, HeroRgb{40, 50, 60});
  const auto mixed_rows = encode_truecolor_halfblock_frame(
      mixed, HeroHalfBlockOptions{.columns = 4, .rows = 1});
  check(mixed_rows.size() == 1U, "mixed halfblock produces 1 row");
  const std::string expected_mixed =
      "\x1b[38;2;10;20;30m\x1b[48;2;40;50;60m\xE2\x96\x80 \xE2\x96\x80"
      "\x1b[38;2;70;80;90m\xE2\x96\x80\x1b[0m";
  check(mixed_rows[0] == expected_mixed,
        "mixed halfblock preserves exact RGB and elides redundant fg/bg across spaces");

  // 3) Row diffing: full redraw, identical 0-byte frame, single-row diff, size
  // mismatch.
  const std::vector<std::string> prev = {"row0", "row1", "row2", "row3"};
  const std::string full = encode_halfblock_diff(
      HeroHalfBlockDiff{.prev_rows = prev, .curr_rows = prev, .full_redraw = true});
  check(full == "\x1b[1;1Hrow0\x1b[2;1Hrow1\x1b[3;1Hrow2\x1b[4;1Hrow3",
        "full_redraw emits every row");

  const std::string same = encode_halfblock_diff(
      HeroHalfBlockDiff{.prev_rows = prev, .curr_rows = prev, .full_redraw = false});
  check(same.empty(), "identical frame diff emits 0 bytes");

  std::vector<std::string> one_changed = prev;
  one_changed[2] = "row2_updated";
  const std::string single = encode_halfblock_diff(HeroHalfBlockDiff{
      .prev_rows = prev, .curr_rows = one_changed, .full_redraw = false});
  check(single == "\x1b[3;1Hrow2_updated", "single changed row emits only that row");

  const std::vector<std::string> shorter = {"row0", "row1"};
  const std::string resized = encode_halfblock_diff(
      HeroHalfBlockDiff{.prev_rows = shorter, .curr_rows = prev, .full_redraw = false});
  check(resized == full, "row count mismatch emits all rows");
}

void test_halfblock_and_hostile_labels() {
  using namespace blackbird;

  HeroFlightDeckEngine engine(HeroCanvasConfig{
      .size = HeroSize{.width = 480, .height = 300},
      .theme = HeroThemeId::tokyonight,
      .seed = 19,
  });
  HeroTelemetryInput tel{};
  tel.room_label = "bad\x1b[31mroom\x07\x9b"
                   "2J";
  tel.peers.push_back(HeroPeerEntry{
      .name = "evil\x1b]52;c;YQ==\x07peer",
      .tokens = 123456,
      .active = true,
  });
  engine.set_telemetry(tel);
  engine.set_question(HeroQuestion{
      .from = "\x1b[2Jmain\x00",
      .text = "deploy\x1b[31m?\x07",
      .detail = "\x1b_Ga=d;\x1b\\cmd\r\nnext",
      .options = {"\x1b[1myes\x07", "no\x1b[0m", "hold\x7f"},
  });

  // Verify sanitize_hero_text strips all raw control chars / CSI escapes.
  const std::string clean = sanitize_hero_text("abc\x1b[31mDEF\x07\x9b"
                                               "2J\x7f");
  check(clean.find('\x1b') == std::string::npos, "sanitized text has no ESC");
  check(clean.find('\x07') == std::string::npos, "sanitized text has no BEL");
  check(clean.find('\x7f') == std::string::npos, "sanitized text has no DEL");

  const auto &frame = engine.step_and_render(0.05F);
  const auto lines = encode_truecolor_halfblock_frame(
      frame, HeroHalfBlockOptions{.columns = 80, .rows = 24});
  check(lines.size() == 24U, "halfblock produces exact rows lines");

  std::size_t rows_with_halfblock = 0;
  for (const auto &line : lines) {
    check(line.find("\x1b[48;2;") != std::string::npos, "line has 24-bit bg ANSI");
    const bool has_halfblock = line.find("\xE2\x96\x80") != std::string::npos;
    if (has_halfblock) {
      ++rows_with_halfblock;
      check(line.find("\x1b[38;2;") != std::string::npos,
            "half-block row has 24-bit fg ANSI");
    } else {
      check(line.find(' ') != std::string::npos, "coalesced row emits ASCII spaces");
    }
    check(line.ends_with("\x1b[0m"), "line resets SGR");
    // Ensure zero raw C0/BEL/DEL/OSC/APC control bytes anywhere in encoded output.
    for (std::size_t i = 0; i < line.size(); ++i) {
      const auto b = static_cast<unsigned char>(line[i]);
      if (b == 0x1BU) {
        check(i + 1 < line.size() && line[i + 1] == '[',
              "only CSI SGR escapes allowed in halfblock output");
        continue;
      }
      check(b >= 0x20U && b != 0x7FU, "zero raw control chars in halfblock output");
    }
  }
  check(rows_with_halfblock >= 16U, "rendered scene contains half-block rows");
}

void test_determinism_and_performance() {
  using namespace blackbird;

  HeroCanvasConfig cfg{
      .size = HeroSize{.width = 480, .height = 300},
      .theme = HeroThemeId::synthwave,
      .seed = 12345,
  };
  HeroFlightDeckEngine e1(cfg);
  HeroFlightDeckEngine e2(cfg);
  const auto &f1 = e1.step_and_render(1.0F / 30.0F);
  const auto &f2 = e2.step_and_render(1.0F / 30.0F);
  check(f1.rgba == f2.rgba, "deterministic seed produces bit-identical RGBA frames");

  // Benchmark 10 frames at default 480x300.
  const auto t0 = std::chrono::steady_clock::now();
  for (int i = 0; i < 10; ++i) {
    (void)e1.step_and_render(1.0F / 30.0F);
  }
  const auto t1 = std::chrono::steady_clock::now();
  const double ms_per_frame =
      std::chrono::duration<double, std::milli>(t1 - t0).count() / 10.0;
  std::cout << "hero_flightdeck_480x300_ms_per_frame=" << ms_per_frame << "\n";
  // Generous ceiling so unoptimized debug+ASan builds still pass comfortably.
  check(ms_per_frame < 250.0, "render performance within budget");

  // Measure Kitty RGBA vs RGB payload sizes (480x300 and smart 384x240) and
  // half-block full vs steady-state diff bytes at 180x50.
  const HeroKittyPlacement kitty_place{
      .row = 0, .column = 0, .columns = 128, .rows = 40};
  const std::string kitty_480_rgba = encode_kitty_rgba_frame(e1.frame(), kitty_place);
  const std::string kitty_480_rgb = encode_kitty_rgb_frame(e1.frame(), kitty_place);
  HeroFlightDeckEngine e_kitty(HeroCanvasConfig{
      .size = HeroSize{.width = 384, .height = 240},
      .theme = HeroThemeId::synthwave,
      .seed = 12345,
  });
  const auto &fk = e_kitty.step_and_render(1.0F / 30.0F);
  const std::string kitty_384_rgb = encode_kitty_rgb_frame(fk, kitty_place);
  const std::string kitty_480_shm = encode_kitty_shm_rgb_frame(e1.frame(), kitty_place);
  const std::size_t shm_apc = kitty_480_shm.find("\x1b_G");
  const std::size_t shm_semi = (shm_apc != std::string::npos)
                                   ? kitty_480_shm.find(';', shm_apc)
                                   : std::string::npos;
  const std::size_t shm_st = (shm_semi != std::string::npos)
                                 ? kitty_480_shm.find("\x1b\\", shm_semi)
                                 : std::string::npos;
  if (shm_semi != std::string::npos && shm_st != std::string::npos &&
      shm_st > shm_semi + 1U) {
    const auto name_bytes = decode_base64(std::string_view(
        kitty_480_shm.data() + shm_semi + 1U, shm_st - (shm_semi + 1U)));
    const std::string shm_name(reinterpret_cast<const char *>(name_bytes.data()),
                               name_bytes.size());
    (void)::shm_unlink(shm_name.c_str());
  }
  std::cout << "hero_kitty_480x300_rgba_bytes=" << kitty_480_rgba.size() << "\n";
  std::cout << "hero_kitty_480x300_rgb_bytes=" << kitty_480_rgb.size() << "\n";
  std::cout << "hero_kitty_384x240_rgb_bytes=" << kitty_384_rgb.size() << "\n";
  std::cout << "hero_kitty_480x300_shm_bytes=" << kitty_480_shm.size() << "\n";

  HeroFlightDeckEngine e_hb(HeroCanvasConfig{
      .size = HeroSize{.width = 180, .height = 100},
      .theme = HeroThemeId::synthwave,
      .seed = 12345,
  });
  const HeroHalfBlockOptions hb_opts{.columns = 180, .rows = 50};
  auto prev_hb =
      encode_truecolor_halfblock_frame(e_hb.step_and_render(1.0F / 30.0F), hb_opts);
  const std::string full_hb = encode_halfblock_diff(
      HeroHalfBlockDiff{.prev_rows = {}, .curr_rows = prev_hb, .full_redraw = true});
  std::size_t diff_hb_total = 0;
  for (int i = 0; i < 10; ++i) {
    auto curr_hb =
        encode_truecolor_halfblock_frame(e_hb.step_and_render(1.0F / 30.0F), hb_opts);
    diff_hb_total += encode_halfblock_diff(HeroHalfBlockDiff{.prev_rows = prev_hb,
                                                             .curr_rows = curr_hb,
                                                             .full_redraw = false})
                         .size();
    prev_hb = std::move(curr_hb);
  }
  std::cout << "hero_halfblock_180x50_full_bytes=" << full_hb.size() << "\n";
  std::cout << "hero_halfblock_180x50_steady_diff_bytes=" << (diff_hb_total / 10U)
            << "\n";
}

void test_kitty_capability_env() {
  using namespace blackbird;

  ::setenv("BLACKBIRD_GRAPHICS", "kitty", 1);
  check(kitty_graphics_capable(), "BLACKBIRD_GRAPHICS=kitty enables Kitty mode");
  ::setenv("BLACKBIRD_GRAPHICS", "off", 1);
  check(!kitty_graphics_capable(), "BLACKBIRD_GRAPHICS=off disables Kitty mode");
  ::unsetenv("BLACKBIRD_GRAPHICS");
  ::unsetenv("SSH_CONNECTION");
  ::unsetenv("TMUX");
  ::unsetenv("STY");
  ::setenv("TERM_PROGRAM", "ghostty", 1);
  ::setenv("TERM", "xterm-256color", 1);
  check(kitty_graphics_capable(), "TERM_PROGRAM=ghostty enables Kitty mode");
  ::setenv("TERM_PROGRAM", "iTerm2", 1);
  ::setenv("TERM", "xterm-kitty", 1);
  check(kitty_graphics_capable(), "TERM=xterm-kitty enables Kitty mode");
  ::setenv("TERM", "xterm-256color", 1);
  check(!kitty_graphics_capable(), "plain xterm-256color disables Kitty mode");
}

void test_size_clamping() {
  using namespace blackbird;

  HeroFlightDeckEngine tiny(HeroCanvasConfig{
      .size = HeroSize{.width = 20, .height = 10},
      .theme = HeroThemeId::nord,
      .seed = 1,
  });
  check(tiny.width() == hero_min_width && tiny.height() == hero_min_height,
        "clamps small dimensions to [160, 100]");

  tiny.resize(HeroSize{.width = 2000, .height = 2000});
  check(tiny.width() == hero_max_width && tiny.height() == hero_max_height,
        "clamps large dimensions to [640, 480]");
}

void test_safety_hardening_regressions() {
  using namespace blackbird;

  // 1) Default-constructed HeroParticleSystem + undersized rgba buffer guard.
  HeroParticleSystem ps;
  HeroTelemetryInput tel{};
  tel.total_tok_per_sec = 5000.0;
  tel.out_rsn_tok_per_sec = 1200.0;
  const auto &synth = hero_theme_spec(HeroThemeId::synthwave);
  ps.emit_from_telemetry(tel, synth, 0.05F);
  ps.step(synth, 0.05F);
  std::vector<std::uint8_t> undersized(16, 42);
  ps.composite(undersized, synth);
  check(undersized.size() == 16U && undersized[0] == 42U,
        "undersized rgba buffer ignored safely without OOB write");
  std::vector<std::uint8_t> exact_rgba(static_cast<std::size_t>(ps.width()) *
                                           static_cast<std::size_t>(ps.height()) * 4U,
                                       0);
  ps.composite(exact_rgba, synth);
  check(ps.live_count() > 0U, "default-constructed HeroParticleSystem is operational");

  // 2) 64-bit integer wraparound HeroFrame (0x80000000 x 0x80000000) in both encoders.
  HeroFrame wrap_frame{
      .width = 0x80000000U,
      .height = 0x80000000U,
      .rgba = {},
  };
  const std::string kitty_wrap = encode_kitty_rgba_frame(wrap_frame);
  check(kitty_wrap.empty(), "kitty encoder rejects 64-bit overflow dimensions");
  check(encode_kitty_rgb_frame(wrap_frame).empty(),
        "kitty rgb encoder rejects 64-bit overflow dimensions");
  const auto hb_wrap = encode_truecolor_halfblock_frame(
      wrap_frame, HeroHalfBlockOptions{.columns = 8, .rows = 4});
  check(hb_wrap.size() == 4U, "halfblock encoder safely handles overflow dimensions");
  check(
      encode_kitty_rgba_frame(
          HeroFrame{.width = 4, .height = 4, .rgba = std::vector<std::uint8_t>(64, 1)},
          HeroKittyPlacement{.row = std::numeric_limits<std::size_t>::max(),
                             .column = 0,
                             .columns = 4,
                             .rows = 2})
          .empty(),
      "kitty encoder rejects max row overflow");
  check(
      encode_kitty_rgb_frame(
          HeroFrame{.width = 4, .height = 4, .rgba = std::vector<std::uint8_t>(64, 1)},
          HeroKittyPlacement{.row = std::numeric_limits<std::size_t>::max(),
                             .column = 0,
                             .columns = 4,
                             .rows = 2})
          .empty(),
      "kitty rgb encoder rejects max row overflow");
  check(
      encode_truecolor_halfblock_frame(
          HeroFrame{.width = 4, .height = 4, .rgba = std::vector<std::uint8_t>(64, 1)},
          HeroHalfBlockOptions{.columns = 4,
                               .rows = std::numeric_limits<std::size_t>::max()})
          .empty(),
      "halfblock encoder rejects rows*2 overflow");

  // 3) NaN / +Inf / huge telemetry, stick inputs, and dt must never poison state or UB.
  const double nan_d = std::numeric_limits<double>::quiet_NaN();
  const double inf_d = std::numeric_limits<double>::infinity();
  const float nan_f = std::numeric_limits<float>::quiet_NaN();
  const float inf_f = std::numeric_limits<float>::infinity();
  HeroFlightDeckEngine engine(HeroCanvasConfig{
      .size = HeroSize{.width = 320, .height = 200},
      .theme = HeroThemeId::dyingearth,
      .seed = 9,
  });
  HeroTelemetryInput hostile_tel{};
  hostile_tel.total_tok_per_sec = inf_d;
  hostile_tel.out_rsn_tok_per_sec = 1e30;
  hostile_tel.cache_hit_ratio = nan_d;
  hostile_tel.main_context_fill = nan_d;
  hostile_tel.jev_calls = 4000000000ULL;
  hostile_tel.active_agents = 3000000000ULL;
  hostile_tel.total_agents = 4000000000ULL;
  engine.set_telemetry(hostile_tel);
  engine.steer_input(HeroControlInput{.stick_x = nan_f, .stick_y = inf_f});
  engine.step(nan_f);
  engine.step(-inf_f);
  engine.step(inf_f);
  const auto &frame = engine.step_and_render(0.05F);
  const auto ps_state = engine.plane_state();
  check(std::isfinite(ps_state.x) && std::isfinite(ps_state.y) &&
            std::isfinite(ps_state.bank_rad),
        "plane state stays finite under NaN/Inf telemetry and dt");
  check(frame.rgba.size() == 320U * 200U * 4U, "frame valid under NaN/Inf telemetry");

  // 4) OSC, APC, DCS, and 8-bit/UTF-8 C1 payload stripping in sanitize_hero_text.
  check(sanitize_hero_text("pre\x1b]52;c;YQ==\x07post") == "prepost",
        "sanitize_hero_text strips OSC BEL payload");
  check(sanitize_hero_text("pre\x1b_Ga=d,i=1;\x1b\\post") == "prepost",
        "sanitize_hero_text strips APC ST payload");
  check(sanitize_hero_text("pre\x1bP+q544e\x1b\\post") == "prepost",
        "sanitize_hero_text strips DCS ST payload");
  check(sanitize_hero_text("pre\x9b"
                           "2Jpost") == "prepost",
        "sanitize_hero_text strips 8-bit C1 CSI payload");
  check(sanitize_hero_text("pre\x9d"
                           "0;title\x9cpost") == "prepost",
        "sanitize_hero_text strips 8-bit C1 OSC ST payload");
  check(sanitize_hero_text("pre\xc2\x9b"
                           "31mpost") == "prepost",
        "sanitize_hero_text strips UTF-8 C1 CSI payload");

  // 5) parse_hero_theme zero-alloc overlong input rejection.
  const std::string huge(1024, 'a');
  check(!parse_hero_theme(huge).has_value(), "parse_hero_theme rejects overlong input");
}

void test_stale_idle_burst_and_rate_limiting() {
  using namespace blackbird;

  const auto &synth = hero_theme_spec(HeroThemeId::synthwave);

  // 1) Stale high rate while !busy and counters stationary must decay after > 1.5s.
  HeroParticleSystem ps;
  ps.reset(HeroSize{.width = 480, .height = 300}, 42);
  HeroTelemetryInput stale_tel{};
  stale_tel.total_tok_per_sec = 50000.0;
  stale_tel.out_rsn_tok_per_sec = 12000.0;
  stale_tel.cached_tokens = 10000;
  stale_tel.input_tokens = 2000;
  stale_tel.output_tokens = 500;
  stale_tel.busy = false;

  // First 0.5s: still fresh -> responsive emission.
  for (int i = 0; i < 15; ++i) {
    ps.emit_from_telemetry(stale_tel, synth, 1.0F / 30.0F);
    ps.step(synth, 1.0F / 30.0F);
  }
  require(ps.effective_total_rate() > 10000.0F,
          "fresh telemetry responds immediately before 1.5s staleness window");

  // Advance another 8.0s with !busy and stationary counters so stale rate decays
  // after 1.5s and previously spawned slow fog particles finish drifting out.
  for (int i = 0; i < 240; ++i) {
    ps.emit_from_telemetry(stale_tel, synth, 1.0F / 30.0F);
    ps.step(synth, 1.0F / 30.0F);
  }
  require(ps.effective_total_rate() < 55.0F,
          "stale idle total rate decays smoothly toward 45 tok/s ambient cruise");
  require(ps.live_count() <= 40U,
          "stale idle telemetry settles to light ambient cruise without flooding");

  // 2) Single huge counter jump must be rate-limited (<= 8 per class = <= 48 per frame)
  //    and spread smoothly over ~0.5s, never exceeding kMaxParticles (600).
  HeroParticleSystem burst_ps;
  burst_ps.reset(HeroSize{.width = 480, .height = 300}, 7);
  HeroTelemetryInput jump_tel{};
  jump_tel.busy = true;
  jump_tel.total_tok_per_sec = 100.0;
  jump_tel.out_rsn_tok_per_sec = 50.0;
  burst_ps.emit_from_telemetry(jump_tel, synth, 1.0F / 30.0F);
  const std::size_t before_jump = burst_ps.live_count();

  jump_tel.cached_tokens += 50000;
  jump_tel.input_tokens += 50000;
  jump_tel.reasoning_tokens += 20000;
  jump_tel.output_tokens += 20000;
  jump_tel.jev_calls += 20;
  burst_ps.emit_from_telemetry(jump_tel, synth, 1.0F / 30.0F);
  const std::size_t spawned_in_one_frame = burst_ps.live_count() - before_jump;
  require(spawned_in_one_frame > 0U && spawned_in_one_frame <= 48U,
          "huge counter jump caps single-frame spawns to <= 8 per class (<= 48 total)");

  // Keep stepping with massive repeated jumps -> never exceeds kMaxParticles (600).
  for (int i = 0; i < 40; ++i) {
    jump_tel.cached_tokens += 50000;
    jump_tel.input_tokens += 50000;
    jump_tel.output_tokens += 20000;
    burst_ps.emit_from_telemetry(jump_tel, synth, 1.0F / 30.0F);
    burst_ps.step(synth, 1.0F / 30.0F);
    require(burst_ps.live_count() <= 600U, "live particle count capped at 600");
  }

  // 3) Live busy streaming remains responsive even when counters pause briefly.
  HeroTelemetryInput busy_tel{};
  busy_tel.busy = true;
  busy_tel.total_tok_per_sec = 8000.0;
  busy_tel.out_rsn_tok_per_sec = 1500.0;
  for (int i = 0; i < 90; ++i) {
    ps.emit_from_telemetry(busy_tel, synth, 1.0F / 30.0F);
    ps.step(synth, 1.0F / 30.0F);
  }
  require(ps.effective_total_rate() >= 8000.0F,
          "busy telemetry stays responsive without staleness decay");

  // 4) Energy-gated composite skips empty buffers completely (no pixel mutations).
  HeroParticleSystem empty_ps;
  empty_ps.reset(HeroSize{.width = 160, .height = 100}, 1);
  empty_ps.step(synth, 1.0F / 30.0F);
  require(empty_ps.acc_energy() < 0.005F && empty_ps.glow_energy() < 0.005F &&
              empty_ps.fog_energy() < 0.005F,
          "empty particle system has sub-threshold energies");
  std::vector<std::uint8_t> canvas(160U * 100U * 4U, 42U);
  const auto snapshot = canvas;
  empty_ps.composite(canvas, synth);
  require(canvas == snapshot,
          "energy-gated composite leaves canvas untouched when empty");
}

void test_forward_ground_scroll() {
  using namespace blackbird;

  // Verify ALL 3 ground renderers (grid via synthwave/tokyonight, ocean via retro82,
  // glyph via dyingearth) scroll strictly DOWNWARD toward the camera as time advances.
  const std::array<HeroThemeId, 4> ground_themes = {
      HeroThemeId::synthwave,
      HeroThemeId::tokyonight,
      HeroThemeId::retro82,
      HeroThemeId::dyingearth,
  };
  for (const HeroThemeId tid : ground_themes) {
    HeroFlightDeckEngine engine(HeroCanvasConfig{
        .size = HeroSize{.width = 480, .height = 300},
        .theme = tid,
        .seed = 11,
    });
    HeroTelemetryInput tel{};
    tel.busy = true;
    tel.total_tok_per_sec = 9000.0;
    engine.set_telemetry(tel);

    const std::vector<std::uint8_t> snap1 = engine.step_and_render(0.05F).rgba;
    const std::vector<std::uint8_t> snap2 = engine.step_and_render(0.30F).rgba;

    const auto &spec = hero_theme_spec(tid);
    const int horizon_y = static_cast<int>(std::lround(300.0F * spec.horizon));
    const int x0 = (tid == HeroThemeId::retro82) ? 295 : 160;
    const int x1 = 320;
    auto row_luma = [&](const std::vector<std::uint8_t> &rgba, int y) -> double {
      double sum = 0.0;
      for (int x = x0; x < x1; ++x) {
        const std::size_t off =
            (static_cast<std::size_t>(y) * 480U + static_cast<std::size_t>(x)) * 4U;
        sum += static_cast<double>(rgba[off]) + static_cast<double>(rgba[off + 1]) +
               static_cast<double>(rgba[off + 2]);
      }
      return sum;
    };

    // High-pass vertical cross-correlation over [-6, +6] excluding dy=0 finds the exact
    // pixel displacement of horizontal ground lines, ocean bars, and glyph rows.
    int best_dy = 0;
    double best_score = -1e18;
    for (int dy = -6; dy <= 6; ++dy) {
      if (dy == 0) {
        continue;
      }
      double score = 0.0;
      for (int y = horizon_y + 14; y < 270; ++y) {
        const double v1 = row_luma(snap1, y) -
                          0.5 * (row_luma(snap1, y - 1) + row_luma(snap1, y + 1));
        const double v2 = row_luma(snap2, y + dy) - 0.5 * (row_luma(snap2, y + dy - 1) +
                                                           row_luma(snap2, y + dy + 1));
        score += v1 * v2;
      }
      if (score > best_score) {
        best_score = score;
        best_dy = dy;
      }
    }
    require(best_dy > 0, "ground renderer scrolls strictly downward toward camera");
  }
}

void test_static_bg_cache_equivalence_and_invalidation() {
  using namespace blackbird;

  HeroTelemetryInput tel{};
  tel.total_tok_per_sec = 2400.0;
  tel.out_rsn_tok_per_sec = 600.0;
  tel.active_agents = 3;
  tel.total_agents = 5;
  tel.busy = true;
  tel.main_context_fill = 0.64;

  HeroThemeId cur = HeroThemeId::synthwave;
  for (std::size_t i = 0; i < hero_theme_count; ++i) {
    const HeroCanvasConfig cfg{
        .size = HeroSize{.width = 320, .height = 200},
        .theme = cur,
        .seed = 99,
    };
    HeroFlightDeckEngine cached_eng(cfg);
    HeroFlightDeckEngine fresh_eng(cfg);
    cached_eng.set_telemetry(tel);
    fresh_eng.set_telemetry(tel);

    // Frame 1 populates the static background cache in both engines.
    (void)cached_eng.step_and_render(1.0F / 30.0F);
    (void)fresh_eng.step_and_render(1.0F / 30.0F);

    // Invalidate fresh_eng's static background cache by toggling theme away and back
    // without touching particles or visual_rng_.
    fresh_eng.set_theme(next_hero_theme(cur));
    fresh_eng.set_theme(cur);

    // Frame 2: cached_eng reuses static_bg_rgba_ via memcpy; fresh_eng rebuilds it.
    const auto &f_cached = cached_eng.step_and_render(1.0F / 30.0F);
    const auto &f_fresh = fresh_eng.step_and_render(1.0F / 30.0F);
    require(f_cached.rgba == f_fresh.rgba,
            "cached static background render matches fresh render bit-for-bit");

    cur = next_hero_theme(cur);
  }

  // Verify theme change invalidation and resize invalidation produce valid distinct
  // frames.
  HeroFlightDeckEngine eng(HeroCanvasConfig{
      .size = HeroSize{.width = 320, .height = 200},
      .theme = HeroThemeId::synthwave,
      .seed = 21,
  });
  const std::vector<std::uint8_t> synth_px = eng.render().rgba;
  eng.cycle_theme();
  const std::vector<std::uint8_t> tokyo_px = eng.render().rgba;
  require(synth_px != tokyo_px, "cycle_theme invalidates static background cache");

  eng.resize(HeroSize{.width = 240, .height = 160});
  const auto &resized_frame = eng.render();
  require(resized_frame.width == 240U && resized_frame.height == 160U &&
              resized_frame.rgba.size() == 240U * 160U * 4U,
          "resize invalidates and rebuilds static background cache at new dimensions");
}

void test_kitty_shm_encoder_and_capability() {
  using namespace blackbird;

  // 1) Capability gating for kitty_shm_capable().
  ::unsetenv("BLACKBIRD_GRAPHICS");
  ::unsetenv("SSH_CONNECTION");
  ::unsetenv("SSH_TTY");
  ::unsetenv("SSH_CLIENT");
  ::unsetenv("TMUX");
  ::unsetenv("STY");
  ::setenv("TERM_PROGRAM", "ghostty", 1);
  ::setenv("TERM", "xterm-256color", 1);
  require(kitty_shm_capable(), "local Ghostty enables kitty_shm_capable");

  ::setenv("TERM_PROGRAM", "WezTerm", 1);
  require(kitty_shm_capable(), "local WezTerm enables kitty_shm_capable");

  ::setenv("SSH_CONNECTION", "1.2.3.4 1234 5.6.7.8 22", 1);
  require(!kitty_shm_capable(), "SSH_CONNECTION disables kitty_shm_capable");
  ::unsetenv("SSH_CONNECTION");

  ::setenv("SSH_TTY", "/dev/pts/1", 1);
  require(!kitty_shm_capable(), "SSH_TTY disables kitty_shm_capable");
  ::unsetenv("SSH_TTY");

  ::setenv("SSH_CLIENT", "1.2.3.4 1234 22", 1);
  require(!kitty_shm_capable(), "SSH_CLIENT disables kitty_shm_capable");
  ::unsetenv("SSH_CLIENT");

  ::setenv("TMUX", "/tmp/tmux-1000/default,123,0", 1);
  require(!kitty_shm_capable(), "TMUX disables kitty_shm_capable");
  ::unsetenv("TMUX");

  ::setenv("STY", "12345.pts-0.host", 1);
  require(!kitty_shm_capable(), "STY disables kitty_shm_capable");
  ::unsetenv("STY");

  ::setenv("BLACKBIRD_GRAPHICS", "kitty", 1);
  ::setenv("SSH_TTY", "/dev/pts/1", 1);
  require(
      !kitty_shm_capable(),
      "SSH_TTY still disables kitty_shm_capable even with BLACKBIRD_GRAPHICS=kitty");
  ::unsetenv("SSH_TTY");
  require(kitty_shm_capable(),
          "local BLACKBIRD_GRAPHICS=kitty enables kitty_shm_capable");
  ::setenv("BLACKBIRD_GRAPHICS", "off", 1);
  require(!kitty_shm_capable(), "BLACKBIRD_GRAPHICS=off disables kitty_shm_capable");
  ::unsetenv("BLACKBIRD_GRAPHICS");

  // 2) Full t=s shared-memory round-trip + exact RGB24 byte check + zero-leak cleanup.
  HeroFlightDeckEngine engine(HeroCanvasConfig{
      .size = HeroSize{.width = 160, .height = 100},
      .theme = HeroThemeId::synthwave,
      .seed = 77,
  });
  const auto &frame = engine.step_and_render(0.05F);
  const HeroKittyPlacement placement{.row = 2,
                                     .column = 4,
                                     .columns = 60,
                                     .rows = 20,
                                     .image_id = 72172,
                                     .placement_id = 1};
  const std::string shm_enc = encode_kitty_shm_rgb_frame(frame, placement);
  require(
      shm_enc.starts_with(
          "\x1b"
          "7\x1b[3;5H\x1b_Ga=T,f=24,t=s,s=160,v=100,i=72172,p=1,q=2,C=1,c=60,r=20;"),
      "kitty shm prefix header matches exact t=s spec");
  require(shm_enc.ends_with("\x1b\\"
                            "\x1b"
                            "8"),
          "kitty shm trailer ends with ST + DECRC");
  require(shm_enc.size() < 120U,
          "kitty shm encoded frame is compact (~85 bytes, not hundreds of KB)");

  const std::size_t apc = shm_enc.find("\x1b_G");
  const std::size_t semi =
      (apc != std::string::npos) ? shm_enc.find(';', apc) : std::string::npos;
  const std::size_t st =
      (semi != std::string::npos) ? shm_enc.find("\x1b\\", semi) : std::string::npos;
  require(semi != std::string::npos && st != std::string::npos && st > semi + 1U,
          "kitty shm sequence contains base64 shm_name payload");
  if (semi != std::string::npos && st != std::string::npos && st > semi + 1U) {
    const std::string_view b64_name(shm_enc.data() + semi + 1U, st - (semi + 1U));
    const auto name_bytes = decode_base64(b64_name);
    const std::string shm_name(reinterpret_cast<const char *>(name_bytes.data()),
                               name_bytes.size());
    require(shm_name.starts_with("/bb-fd-"), "shm_name uses /bb-fd- prefix");
    require(shm_name.size() <= 30U, "shm_name fits within macOS PSHMNAMLEN=31 limit");

    const int fd = ::shm_open(shm_name.c_str(), O_RDONLY, 0);
    require(fd >= 0, "shm_open opens created shared memory object");
    if (fd >= 0) {
      struct stat sb{};
      const int stat_rc = ::fstat(fd, &sb);
      const std::size_t expected_rgb_bytes = 160U * 100U * 3U;
      // macOS rounds POSIX shm ftruncate size up to the VM page size; Linux is exact.
      require(stat_rc == 0 &&
                  static_cast<std::size_t>(sb.st_size) >= expected_rgb_bytes,
              "shm object size covers width * height * 3");
      void *mapped = ::mmap(nullptr, expected_rgb_bytes, PROT_READ, MAP_SHARED, fd, 0);
      require(mapped != MAP_FAILED, "mmap maps shared memory object for verification");
      if (mapped != MAP_FAILED) {
        const auto *rgb = static_cast<const std::uint8_t *>(mapped);
        bool all_match = true;
        for (std::size_t p = 0; p < 160U * 100U; ++p) {
          if (rgb[p * 3U] != frame.rgba[p * 4U] ||
              rgb[p * 3U + 1U] != frame.rgba[p * 4U + 1U] ||
              rgb[p * 3U + 2U] != frame.rgba[p * 4U + 2U]) {
            all_match = false;
            break;
          }
        }
        require(all_match, "shm RGB24 bytes match rendered frame RGBA bit-for-bit");
        ::munmap(mapped, expected_rgb_bytes);
      }
      ::close(fd);
    }
    // Always unlink so tests NEVER leak shared memory entries.
    const int unlink_rc = ::shm_unlink(shm_name.c_str());
    require(unlink_rc == 0, "shm_unlink cleanly removes test shared memory object");
    const int after_fd = ::shm_open(shm_name.c_str(), O_RDONLY, 0);
    require(after_fd < 0, "unlinked shm object is no longer openable (zero leak)");
    if (after_fd >= 0) {
      ::close(after_fd);
    }
  }

  // 3) Invalid/overflow frames rejected cleanly without creating shm objects.
  HeroFrame wrap_frame{
      .width = 0x80000000U,
      .height = 0x80000000U,
      .rgba = {},
  };
  require(encode_kitty_shm_rgb_frame(wrap_frame).empty(),
          "kitty shm encoder rejects 64-bit overflow dimensions");
}

} // namespace

int main() {
  test_themes_and_rendering();
  test_steering_and_spring_return();
  test_fly_to_answer_and_key_answer();
  test_kitty_encoder_roundtrip_and_erase();
  test_kitty_rgb_encoder_roundtrip();
  test_halfblock_coalescing_and_diff();
  test_halfblock_and_hostile_labels();
  test_determinism_and_performance();
  test_kitty_capability_env();
  test_size_clamping();
  test_safety_hardening_regressions();
  test_stale_idle_burst_and_rate_limiting();
  test_forward_ground_scroll();
  test_static_bg_cache_equivalence_and_invalidation();
  test_kitty_shm_encoder_and_capability();

  if (g_failures != 0) {
    std::cerr << "TOTAL FAILURES: " << g_failures << "\n";
    return 1;
  }
  std::cout << "ALL FLIGHT_DECK_HERO TESTS PASSED\n";
  return 0;
}
