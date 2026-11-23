#include "blackbird/flight_deck_hero.hpp"

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <numeric>
#include <string>
#include <string_view>
#include <vector>

namespace {

int g_failures = 0;

void check(bool cond, std::string_view msg) {
  if (!cond) {
    std::cerr << "FAIL: " << msg << "\n";
    ++g_failures;
  }
}

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
  std::cout << "hero_kitty_480x300_rgba_bytes=" << kitty_480_rgba.size() << "\n";
  std::cout << "hero_kitty_480x300_rgb_bytes=" << kitty_480_rgb.size() << "\n";
  std::cout << "hero_kitty_384x240_rgb_bytes=" << kitty_384_rgb.size() << "\n";

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

  if (g_failures != 0) {
    std::cerr << "TOTAL FAILURES: " << g_failures << "\n";
    return 1;
  }
  std::cout << "ALL FLIGHT_DECK_HERO TESTS PASSED\n";
  return 0;
}
