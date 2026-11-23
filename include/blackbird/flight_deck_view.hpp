#pragma once

#include "blackbird/metrics_consumer.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

// Strictly read-only telemetry input for the SR-71 Flight-Deck & Token-Shower
// visualizer. All animation is driven exclusively by the caller-supplied `tick`
// counter (zero wall-clock nondeterminism).
struct FlightDeckTelemetry {
  MetricsSnapshot snapshot;
  std::optional<std::size_t> active_peers;
  std::optional<std::size_t> waiting_peers;
  std::optional<std::size_t> active_watchers;
  bool guard_blocked = false;
  std::string room_label;
  std::string model_label;
  std::uint64_t tick = 0;
};

struct FlightDeckRenderOptions {
  std::size_t width = 80;
  std::size_t height = 24;
  bool color = false;
  bool honor_no_color_env = true;
};

struct FlightDeckFrame {
  std::vector<std::string> lines;
  std::size_t width = 0;
  std::size_t height = 0;
  bool color_enabled = false;
  bool stale = false;
  bool narrow_mode = false;

  std::string text() const;
};

// Pure label sanitizer for untrusted room/model/reason strings: escapes C0/DEL,
// raw C1 (0x80..0x9F including 0x9B CSI), UTF-8 C1 (U+0080..U+009F), bidi
// override scalars, and invalid UTF-8 sequences while preserving valid printable
// UTF-8 within `max_bytes`.
std::string sanitize_flight_deck_label(std::string_view text,
                                       std::size_t max_bytes = 64);

// Strictly read-only tertiary terminal visualizer combining Blackbird's SR-71
// flight telemetry canvas, 4-lane proportional token-shower fountain, and
// sparkline/companion/cost telemetry strip.
class FlightDeckView {
public:
  FlightDeckView() = default;

  FlightDeckFrame render(const FlightDeckTelemetry &telemetry,
                         const FlightDeckRenderOptions &options = {}) const;

  std::string render_text(const FlightDeckTelemetry &telemetry,
                          const FlightDeckRenderOptions &options = {}) const;
};

} // namespace blackbird
