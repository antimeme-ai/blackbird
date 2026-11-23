#include "blackbird/flight_deck_view.hpp"
#include "blackbird/metrics_consumer.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace blackbird;

namespace {

void require(bool condition, const char *why) {
  if (!condition)
    throw std::runtime_error(why);
}

// Locale-independent UTF-8 visible cell counter (stripping CSI SGR when requested).
std::size_t visible_cells(std::string_view line, bool strip_sgr) {
  std::size_t cells = 0;
  std::size_t i = 0;
  while (i < line.size()) {
    const auto b = static_cast<unsigned char>(line[i]);
    if (strip_sgr && b == 0x1bU && i + 1 < line.size() && line[i + 1] == '[') {
      i += 2;
      while (i < line.size() && line[i] != 'm')
        ++i;
      if (i < line.size())
        ++i;
      continue;
    }
    if (b < 0x80U) {
      ++cells;
      ++i;
    } else if ((b & 0xe0U) == 0xc0U) {
      ++cells;
      i += 2;
    } else if ((b & 0xf0U) == 0xe0U) {
      ++cells;
      i += 3;
    } else if ((b & 0xf8U) == 0xf0U) {
      cells += 2;
      i += 4;
    } else {
      ++cells;
      ++i;
    }
  }
  return cells;
}

bool contains_raw_control_or_c1(std::string_view text) {
  for (std::size_t i = 0; i < text.size(); ++i) {
    const auto b = static_cast<unsigned char>(text[i]);
    if (b == '\n')
      continue;
    if (b < 0x20U || b == 0x7fU)
      return true;
    // Raw single-byte C1 (0x80..0x9f) that is not a UTF-8 continuation byte.
    // Check UTF-8 lead vs bare C1 by decoding valid UTF-8 sequences.
    if (b >= 0x80U && b <= 0x9fU)
      return true;
    if (b == 0xc2U && i + 1 < text.size()) {
      const auto next = static_cast<unsigned char>(text[i + 1]);
      if (next >= 0x80U && next <= 0x9fU)
        return true;
      ++i;
      continue;
    }
    if ((b & 0xe0U) == 0xc0U && i + 1 < text.size()) {
      i += 1;
    } else if ((b & 0xf0U) == 0xe0U && i + 2 < text.size()) {
      i += 2;
    } else if ((b & 0xf8U) == 0xf0U && i + 3 < text.size()) {
      i += 3;
    }
  }
  return false;
}

MetricsSnapshot build_populated_snapshot(bool mark_stale) {
  MetricsConsumer consumer;

  MetricsSample s1;
  s1.kind = MetricsSampleKind::provider_response;
  s1.source_record_id = "req-1";
  s1.provider = "anthropic";
  s1.model = "claude-opus-4-6";
  s1.input_tokens = 12000;
  s1.cached_tokens = 9000;
  s1.reasoning_tokens = 2400;
  s1.output_tokens = 1800;
  s1.ttft_ms = 140.0;
  s1.total_latency_ms = 920.0;
  s1.observed_charge_usd = 0.0412;
  s1.estimated_usd = 0.0435;
  s1.pricing_version = "v2026-11";
  s1.succeeded = true;
  require(consumer.ingest(s1).has_value(), "ingest s1");

  MetricsSample s2;
  s2.kind = MetricsSampleKind::provider_response;
  s2.source_record_id = "req-2";
  s2.provider = "anthropic";
  s2.model = "claude-opus-4-6";
  s2.input_tokens = 18000;
  s2.cached_tokens = 15000;
  s2.reasoning_tokens = 4200;
  s2.output_tokens = 3200;
  s2.ttft_ms = 210.0;
  s2.total_latency_ms = 1150.0;
  s2.observed_charge_usd = 0.0588;
  s2.estimated_usd = 0.0610;
  s2.pricing_version = "v2026-11";
  s2.succeeded = true;
  require(consumer.ingest(s2).has_value(), "ingest s2");

  MetricsSample s3;
  s3.kind = MetricsSampleKind::provider_response;
  s3.source_record_id = "req-3";
  s3.provider = "anthropic";
  s3.model = "claude-opus-4-6";
  s3.input_tokens = 9000;
  s3.cached_tokens = 7200;
  s3.reasoning_tokens = 1600;
  s3.output_tokens = 1100;
  s3.ttft_ms = 95.0;
  s3.total_latency_ms = 640.0;
  s3.observed_charge_usd = 0.0250;
  s3.estimated_usd = 0.0265;
  s3.pricing_version = "v2026-11";
  s3.succeeded = true;
  require(consumer.ingest(s3).has_value(), "ingest s3");

  MetricsSample ctx;
  ctx.kind = MetricsSampleKind::context_snapshot;
  ctx.source_record_id = "ctx-1";
  ctx.live_bytes = 96ULL * 1024ULL;
  ctx.archived_bytes = 320ULL * 1024ULL;
  ctx.compaction_event = true;
  require(consumer.ingest(ctx).has_value(), "ingest ctx");

  MetricsSample dc;
  dc.kind = MetricsSampleKind::decision_batch;
  dc.source_record_id = "dc-1";
  dc.input_tokens = 600;
  dc.output_tokens = 180;
  dc.total_latency_ms = 85.0;
  dc.observed_charge_usd = 0.0015;
  dc.estimated_usd = 0.0018;
  dc.succeeded = true;
  require(consumer.ingest(dc).has_value(), "ingest dc");

  if (mark_stale)
    consumer.mark_stale("upstream metrics reader offline");

  return consumer.snapshot();
}

struct ExpectedBounds {
  std::size_t width = 0;
  std::size_t height = 0;
};

void assert_frame_bounds(const FlightDeckFrame &frame, ExpectedBounds bounds) {
  require(frame.width == bounds.width, "frame width metadata mismatch");
  require(frame.height == bounds.height, "frame height metadata mismatch");
  require(frame.lines.size() == bounds.height, "frame line count mismatch");
  for (const auto &line : frame.lines) {
    const std::size_t cells = visible_cells(line, frame.color_enabled);
    require(cells <= bounds.width, "line exceeded viewport width");
  }
}

void test_unknown_empty_snapshot() {
  FlightDeckView view;
  FlightDeckTelemetry telemetry;
  telemetry.room_label = "ops-alpha";
  telemetry.model_label = "unselected";
  telemetry.tick = 0;

  const auto frame = view.render(telemetry, {80, 24, false, true});
  assert_frame_bounds(frame, {80, 24});
  require(!frame.narrow_mode, "80x24 must use standard layout");
  require(!frame.stale, "fresh empty snapshot must not be stale");
  require(!frame.color_enabled, "color=false must keep color disabled");

  const std::string rendered = frame.text();
  require(!contains_raw_control_or_c1(rendered),
          "plain render must have no raw escapes");
  require(rendered.find("UNKNOWN") != std::string::npos,
          "empty snapshot must render UNKNOWN");
  require(rendered.find("IDLE") != std::string::npos, "empty snapshot must show IDLE");
  require(rendered.find("OBSERVED=UNKNOWN") != std::string::npos,
          "observed cost must be UNKNOWN, never 0");
  require(rendered.find("ESTIMATED=UNKNOWN") != std::string::npos,
          "estimated cost must be UNKNOWN, never 0");
  require(rendered.find("CACHE UNKNOWN") != std::string::npos,
          "cache hit ratio must be UNKNOWN, never 0%");
  require(rendered.find("ALT   UNKNOWN") != std::string::npos,
          "context live_bytes must be UNKNOWN, never 0B");
  require(rendered.find("STALE") == std::string::npos,
          "non-stale snapshot must not show STALE");

  // Determinism check: identical inputs produce byte-identical frames.
  const auto frame2 = view.render(telemetry, {80, 24, false, true});
  require(frame.lines == frame2.lines, "render must be strictly deterministic");
}

void test_populated_telemetry_and_animation() {
  FlightDeckView view;
  FlightDeckTelemetry telemetry;
  telemetry.snapshot = build_populated_snapshot(false);
  telemetry.active_peers = 3;
  telemetry.waiting_peers = 1;
  telemetry.active_watchers = 2;
  telemetry.room_label = "command-post";
  telemetry.model_label = "claude-opus-4-6";

  telemetry.tick = 0;
  const auto f0 = view.render(telemetry, {80, 24, false, true});
  telemetry.tick = 1;
  const auto f1 = view.render(telemetry, {80, 24, false, true});
  telemetry.tick = 2;
  const auto f2 = view.render(telemetry, {80, 24, false, true});

  assert_frame_bounds(f0, {80, 24});
  assert_frame_bounds(f1, {80, 24});
  assert_frame_bounds(f2, {80, 24});

  const std::string t0 = f0.text();
  const std::string t1 = f1.text();
  const std::string t2 = f2.text();

  // Advancing contrail and falling shower must produce distinct frames for tick 0,
  // 1, 2.
  require(
      t0 != t1 && t1 != t2 && t0 != t2,
      "tick 0, 1, 2 must advance SR-71 contrail and token shower deterministically");

  // Verify Panel 1 telemetry elements.
  require(t0.find("SR-71 FLIGHT DECK") != std::string::npos, "missing title");
  require(t0.find("[ACTIVE]") != std::string::npos,
          "populated snapshot must be ACTIVE");
  require(t0.find("AFTERBURNER") != std::string::npos,
          "active flight deck afterburner");
  require(t0.find("CACHE [") != std::string::npos, "cache gauge missing");
  require(t0.find("TTFT  p50=") != std::string::npos, "TTFT p50 readout missing");
  require(t0.find("ALT   [") != std::string::npos, "context altitude gauge missing");
  require(t0.find("96.0KiB") != std::string::npos, "context live_bytes missing");
  require(t0.find("▲▲▲") != std::string::npos, "active wingman pips missing");
  require(t0.find("△") != std::string::npos, "waiting wingman pip missing");
  require(t0.find("◎2") != std::string::npos, "watcher count missing");

  // Verify Panel 2 proportional 4-lane token shower.
  require(t0.find("TOKEN SHOWER") != std::string::npos, "token shower title missing");
  require(t0.find("INPUT") != std::string::npos, "INPUT lane missing");
  require(t0.find("CACHED") != std::string::npos, "CACHED lane missing");
  require(t0.find("REASON") != std::string::npos, "REASON lane missing");
  require(t0.find("OUTPUT") != std::string::npos, "OUTPUT lane missing");
  require(t0.find("█") != std::string::npos, "proportional bar blocks missing");
  require(t0.find("39.0k") != std::string::npos, "input token total mismatch");
  require(t0.find("31.2k") != std::string::npos, "cached token total mismatch");
  require(t0.find("8.2k") != std::string::npos, "reasoning token total mismatch");
  require(t0.find("6.1k") != std::string::npos, "output token total mismatch");

  // Verify Panel 3 sparklines, companion, and strictly separated costs.
  require(t0.find("TOKENS : ") != std::string::npos, "tokens sparkline missing");
  require(t0.find("TTFT   : ") != std::string::npos, "ttft sparkline missing");
  require(t0.find("COMPANION: calls=1") != std::string::npos,
          "decision companion batch count missing");
  require(t0.find("OBSERVED=$0.1250") != std::string::npos,
          "observed charge must match exact observed sum");
  require(t0.find("ESTIMATED=$0.1310") != std::string::npos,
          "estimated cost must remain strictly separated from observed charge");
  require(t0.find("[v2026-11]") != std::string::npos, "pricing version missing");

  // Verify STALE warning and guard_blocked flag.
  telemetry.snapshot = build_populated_snapshot(true);
  telemetry.guard_blocked = true;
  const auto f_stale = view.render(telemetry, {80, 24, false, true});
  assert_frame_bounds(f_stale, {80, 24});
  require(f_stale.stale, "stale frame flag must be true");
  const std::string t_stale = f_stale.text();
  require(t_stale.find("[STALE]") != std::string::npos, "STALE badge missing");
  require(t_stale.find("upstream metrics reader offline") != std::string::npos,
          "stale reason missing");
  require(t_stale.find("GUARD: BLOCKED") != std::string::npos,
          "guard blocked status missing");
}

void test_tri_state_partial_honesty() {
  // Explicitly verify mixed observed zero + unknown + known_subtotal lanes.
  MetricsConsumer consumer;
  MetricsSample s;
  s.kind = MetricsSampleKind::provider_response;
  s.source_record_id = "mix-1";
  s.input_tokens = 4000;
  s.cached_tokens = 0; // Explicitly observed zero.
  // reasoning_tokens left unset -> unknown!
  s.output_tokens = 500;
  require(consumer.ingest(s).has_value(), "ingest mix-1");

  FlightDeckTelemetry telemetry;
  telemetry.snapshot = consumer.snapshot();
  telemetry.tick = 1;

  FlightDeckView view;
  const auto frame = view.render(telemetry, {100, 30, false, true});
  assert_frame_bounds(frame, {100, 30});
  const std::string text = frame.text();
  require(text.find("4.0k") != std::string::npos, "input 4.0k missing");
  require(text.find("0.0%") != std::string::npos, "observed 0% cache hit missing");
  require(text.find("UNKNOWN") != std::string::npos,
          "missing reasoning lane must remain UNKNOWN");

  // Add a second sample with missing input_tokens so input becomes known_subtotal (+).
  MetricsSample s2;
  s2.kind = MetricsSampleKind::provider_response;
  s2.source_record_id = "mix-2";
  s2.output_tokens = 500;
  require(consumer.ingest(s2).has_value(), "ingest mix-2");
  telemetry.snapshot = consumer.snapshot();
  const auto sub_frame = view.render(telemetry, {100, 30, false, true});
  assert_frame_bounds(sub_frame, {100, 30});
  require(sub_frame.text().find("4.0k+") != std::string::npos,
          "known_subtotal must display + marker");
}

void test_viewports_and_clipping() {
  FlightDeckView view;
  FlightDeckTelemetry telemetry;
  telemetry.snapshot = build_populated_snapshot(true);
  telemetry.active_peers = 9;
  telemetry.waiting_peers = 5;
  telemetry.active_watchers = 4;
  telemetry.room_label = "very-long-platoon-command-room-name-exceeding-normal-width";
  telemetry.model_label = "very-long-model-identifier-for-boundary-clipping-tests";
  telemetry.tick = 42;

  // Narrow viewport 40x16.
  const auto narrow = view.render(telemetry, {40, 16, false, true});
  assert_frame_bounds(narrow, {40, 16});
  require(narrow.narrow_mode, "40x16 must enter narrow_mode");
  const std::string narrow_text = narrow.text();
  require(!contains_raw_control_or_c1(narrow_text), "narrow render has raw escapes");
  require(narrow_text.find("[STALE]") != std::string::npos, "narrow STALE missing");
  require(narrow_text.find("SR-71") != std::string::npos,
          "narrow SR-71 header missing");

  // 100x30 viewport.
  const auto mid = view.render(telemetry, {100, 30, false, true});
  assert_frame_bounds(mid, {100, 30});
  require(!mid.narrow_mode, "100x30 must use standard mode");

  // Wide viewport 120x36.
  const auto wide = view.render(telemetry, {120, 36, false, true});
  assert_frame_bounds(wide, {120, 36});
  require(!wide.narrow_mode, "120x36 must use standard mode");
  require(wide.text().find("COVERAGE:") != std::string::npos,
          "wide viewport should display extra coverage strip");

  // Edge tiny and zero viewports.
  const auto tiny = view.render(telemetry, {12, 6, false, true});
  assert_frame_bounds(tiny, {12, 6});
  const auto empty = view.render(telemetry, {0, 0, false, true});
  require(empty.lines.empty() && empty.width == 0 && empty.height == 0,
          "0x0 viewport must return empty frame");
}

void test_hostile_label_escaping_and_color_modes() {
  FlightDeckView view;
  FlightDeckTelemetry telemetry;
  telemetry.snapshot = build_populated_snapshot(true);
  telemetry.room_label = std::string{"ops\x1b[31mred\x9b"
                                     "6n\r\n",
                                     17};
  telemetry.room_label.push_back('\0');
  telemetry.room_label += "end";
  telemetry.model_label = std::string{"m\x1b]0;evil\x07\x9b"
                                      "2J\r",
                                      15};
  telemetry.model_label.push_back('\0');
  telemetry.snapshot.stale_reason = std::string{"bad\x1b[32m\x9b"
                                                "6n\r",
                                                13};
  telemetry.snapshot.stale_reason.push_back('\0');

  // Verify direct sanitizer output including UTF-8 C1, bidi override, and invalid
  // UTF-8.
  const std::string san_room = sanitize_flight_deck_label(telemetry.room_label, 128);
  require(!contains_raw_control_or_c1(san_room),
          "sanitized room must have zero raw ctrl");
  require(san_room.find("\\x1b[31m") != std::string::npos, "ESC must be hex-escaped");
  require(san_room.find("\\x9b6n") != std::string::npos, "C1 0x9b must be hex-escaped");
  require(san_room.find("\\r") != std::string::npos, "CR must be escaped");
  require(san_room.find("\\x00") != std::string::npos, "NUL must be hex-escaped");

  const std::string san_extra =
      sanitize_flight_deck_label("a\xc2\x9b\xe2\x80\xae\xffz", 128);
  require(!contains_raw_control_or_c1(san_extra), "UTF-8 C1/bidi/bad bytes escaped");
  require(san_extra.find("\\xc2\\x9b") != std::string::npos, "UTF-8 C1 escaped");
  require(san_extra.find("\\xe2\\x80\\xae") != std::string::npos, "RLO bidi escaped");
  require(san_extra.find("\\xff") != std::string::npos, "invalid UTF-8 byte escaped");

  // Plain mode (color = false): ZERO raw escape or C1 bytes anywhere.
  const auto plain = view.render(telemetry, {120, 36, false, true});
  assert_frame_bounds(plain, {120, 36});
  const std::string plain_text = plain.text();
  require(plain_text.find('\x1b') == std::string::npos,
          "color=false must emit zero ESC bytes");
  require(!contains_raw_control_or_c1(plain_text),
          "color=false must emit zero raw control/C1 bytes");
  require(plain_text.find("\\x1b") != std::string::npos,
          "escaped label text should be visibly rendered");

  // Color mode (color = true, ignoring NO_COLOR for explicit color verification).
  const auto colored = view.render(telemetry, {80, 24, true, false});
  assert_frame_bounds(colored, {80, 24});
  require(colored.color_enabled,
          "color=true with honor_no_color_env=false must enable");
  const std::string colored_text = colored.text();
  require(colored_text.find("\x1b[") != std::string::npos,
          "color=true must emit ANSI SGR codes");
  require(colored_text.find("\x1b[31m") == std::string::npos,
          "hostile user SGR must never leak raw even in color=true mode");
  require(colored_text.find('\x9b') == std::string::npos,
          "hostile C1 0x9b must never leak raw even in color=true mode");
  require(colored_text.find('\0') == std::string::npos,
          "hostile NUL must never leak raw even in color=true mode");

  // NO_COLOR environment variable honors disabling ANSI color when requested.
  const char *prev_no_color = std::getenv("NO_COLOR");
  const std::string saved_no_color = prev_no_color ? std::string{prev_no_color} : "";
  const bool had_no_color = prev_no_color != nullptr;

  require(::setenv("NO_COLOR", "1", 1) == 0, "setenv NO_COLOR");
  const auto honored = view.render(telemetry, {80, 24, true, true});
  if (had_no_color)
    (void)::setenv("NO_COLOR", saved_no_color.c_str(), 1);
  else
    (void)::unsetenv("NO_COLOR");

  assert_frame_bounds(honored, {80, 24});
  require(!honored.color_enabled, "NO_COLOR=1 must disable ANSI color");
  require(honored.text().find('\x1b') == std::string::npos,
          "NO_COLOR=1 output must have zero ESC bytes");
}

} // namespace

int main() {
  try {
    test_unknown_empty_snapshot();
    test_populated_telemetry_and_animation();
    test_tri_state_partial_honesty();
    test_viewports_and_clipping();
    test_hostile_label_escaping_and_color_modes();
    std::cout << "flight_deck_view_test: ok\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "flight_deck_view_test failed: " << ex.what() << "\n";
    return 1;
  }
}
