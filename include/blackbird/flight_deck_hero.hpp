#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

enum class HeroThemeId : std::uint8_t {
  synthwave = 0,
  tokyonight,
  gotham,
  kanagawa,
  nord,
  hackerman,
  retro82,
  dyingearth,
};

inline constexpr std::size_t hero_theme_count = 8;

inline constexpr std::uint32_t hero_min_width = 160;
inline constexpr std::uint32_t hero_max_width = 640;
inline constexpr std::uint32_t hero_min_height = 100;
inline constexpr std::uint32_t hero_max_height = 480;
inline constexpr std::uint32_t hero_default_width = 480;
inline constexpr std::uint32_t hero_default_height = 300;
inline constexpr std::uint32_t hero_default_kitty_image_id = 72172;
inline constexpr float hero_gate_dwell_seconds = 1.5F;

struct HeroRgb {
  std::uint8_t r = 0;
  std::uint8_t g = 0;
  std::uint8_t b = 0;

  constexpr bool operator==(const HeroRgb &) const noexcept = default;
};

enum class HeroSceneKind : std::uint8_t {
  none = 0,
  skyline,
  gotham,
  fuji,
  aurora,
  wire,
  palms,
  qud,
};

enum class HeroGroundKind : std::uint8_t {
  grid = 0,
  ocean,
  glyph,
};

enum class HeroCacheReadStyle : std::uint8_t {
  fog = 0,
  rain,
  petal,
  snow,
  code,
};

struct HeroTheme {
  HeroThemeId id = HeroThemeId::synthwave;
  std::string_view key;
  std::string_view display_name;
  std::array<HeroRgb, 5> sky{};
  float horizon = 0.80F;
  bool sun = false;
  std::array<HeroRgb, 3> sun_cols{};
  HeroRgb sun_halo{};
  HeroRgb grid{};
  float scan = 0.0F;
  float bloom = 0.0F;
  HeroRgb rim{};
  HeroRgb rim2{};
  std::array<HeroRgb, 3> burn{};
  // Token classes: 0 cache_read, 1 cache_write, 2 uncached_input,
  // 3 reasoning, 4 output, 5 jev.
  std::array<HeroRgb, 6> cls{};
  std::array<HeroRgb, 7> team{};
  HeroRgb label{};
  HeroRgb dim{};
  HeroSceneKind scene = HeroSceneKind::none;
  HeroGroundKind ground = HeroGroundKind::grid;
  HeroCacheReadStyle cr_style = HeroCacheReadStyle::fog;
  HeroRgb sky_back{};
  HeroRgb sky_front{};
  HeroRgb tower{};
  HeroRgb window{};
};

std::string_view hero_theme_name(HeroThemeId theme) noexcept;
std::optional<HeroThemeId> parse_hero_theme(std::string_view name) noexcept;
HeroThemeId next_hero_theme(HeroThemeId theme) noexcept;
const HeroTheme &hero_theme_spec(HeroThemeId theme) noexcept;

// Sanitize untrusted HUD text (question/room/peer labels) by stripping/replacing
// C0/DEL/C1 control bytes and truncating safely within max_bytes.
std::string sanitize_hero_text(std::string_view text, std::size_t max_bytes = 64);

struct HeroSize {
  std::uint32_t width = hero_default_width;
  std::uint32_t height = hero_default_height;
};

struct HeroCanvasConfig {
  HeroSize size{};
  HeroThemeId theme = HeroThemeId::synthwave;
  std::uint32_t seed = 11;
};

struct HeroPeerEntry {
  std::string name;
  std::uint64_t tokens = 0;
  std::uint64_t jev_calls = 0;
  bool active = false;
  bool tool_busy = false;
  bool is_jev = false;
  bool silent = false;
};

struct HeroTelemetryInput {
  double total_tok_per_sec = 0.0;
  double out_rsn_tok_per_sec = 0.0;
  double cache_hit_ratio = 0.85;
  std::uint64_t input_tokens = 0;
  std::uint64_t cached_tokens = 0;
  std::uint64_t reasoning_tokens = 0;
  std::uint64_t output_tokens = 0;
  std::uint64_t jev_calls = 0;
  std::size_t active_agents = 1;
  std::size_t total_agents = 1;
  bool busy = false;
  double main_context_fill = 0.35;
  std::string room_label;
  std::vector<HeroPeerEntry> peers;
};

struct HeroControlInput {
  bool left = false;
  bool right = false;
  bool up = false;
  bool down = false;
  float stick_x = 0.0F;
  float stick_y = 0.0F;
};

struct HeroQuestion {
  std::string from;
  std::string text;
  std::string detail;
  std::vector<std::string> options;
};

struct HeroGateState {
  std::string label;
  float x = 0.0F;
  float y = 0.0F;
  float radius = 0.0F;
  float dwell_seconds = 0.0F;
};

struct HeroPlaneState {
  float x = 0.0F;
  float y = 0.0F;
  float offset_x = 0.0F;
  float offset_y = 0.0F;
  float vx = 0.0F;
  float vy = 0.0F;
  float bank_rad = 0.0F;
};

struct HeroFrame {
  std::uint32_t width = 0;
  std::uint32_t height = 0;
  std::vector<std::uint8_t> rgba;
};

struct HeroKittyPlacement {
  std::size_t row = 0;
  std::size_t column = 0;
  std::size_t columns = 80;
  std::size_t rows = 24;
  std::uint32_t image_id = hero_default_kitty_image_id;
  std::uint32_t placement_id = 1;
};

struct HeroHalfBlockOptions {
  std::size_t columns = 80;
  std::size_t rows = 24;
};

struct HeroHalfBlockDiff {
  std::span<const std::string> prev_rows{};
  std::span<const std::string> curr_rows{};
  bool full_redraw = false;
};

// Zero-dependency physics particle token shower + additive glow/fog buffers.
class HeroParticleSystem {
public:
  HeroParticleSystem();

  void reset(HeroSize size, std::uint32_t seed);
  void emit_from_telemetry(const HeroTelemetryInput &telemetry, const HeroTheme &theme,
                           float dt_seconds);
  void step(const HeroTheme &theme, float dt_seconds);
  void composite(std::vector<std::uint8_t> &rgba, const HeroTheme &theme) const;

  std::size_t live_count() const noexcept { return particles_.size(); }
  std::uint32_t width() const noexcept { return width_; }
  std::uint32_t height() const noexcept { return height_; }
  float effective_total_rate() const noexcept { return eff_total_rate_; }
  float acc_energy() const noexcept { return acc_energy_; }
  float glow_energy() const noexcept { return glow_energy_; }
  float fog_energy() const noexcept { return fog_energy_; }

private:
  struct Particle {
    float x = 0.0F;
    float y = 0.0F;
    float vx = 0.0F;
    float vy = 0.0F;
    std::uint8_t source = 0;
    std::uint8_t token_class = 0;
    std::uint8_t flow = 0;
  };

  struct SpawnSpec {
    std::uint8_t source = 0;
    std::uint8_t token_class = 0;
  };
  struct CellPoint {
    float x = 0.0F;
    float y = 0.0F;
  };

  bool buffers_valid() const noexcept;
  float next_random() noexcept;
  float next_gauss() noexcept;
  void spawn_particle(SpawnSpec spec, const HeroTheme &theme);
  void write_matrix_cell(CellPoint point);

  std::uint32_t width_ = hero_default_width;
  std::uint32_t height_ = hero_default_height;
  std::uint32_t glow_w_ = hero_default_width / 4;
  std::uint32_t glow_h_ = hero_default_height / 4;
  std::uint32_t rng_state_ = 11;
  float sim_t_ = 0.0F;
  float idle_stale_seconds_ = 0.0F;
  float eff_total_rate_ = 45.0F;
  float eff_out_rate_ = 12.0F;
  bool has_prev_counters_ = false;
  std::uint64_t prev_input_ = 0;
  std::uint64_t prev_cached_ = 0;
  std::uint64_t prev_reasoning_ = 0;
  std::uint64_t prev_output_ = 0;
  std::uint64_t prev_jev_ = 0;
  std::array<float, 6> burst_backlog_{};
  std::array<float, 6> owe_{};
  std::vector<Particle> particles_;
  std::vector<float> acc_;
  std::vector<float> glow_buf_;
  std::vector<float> fog_buf_;
  mutable std::vector<float> fog_blur_;
  mutable std::vector<float> glow_blur_;
  mutable std::vector<float> blur_tmp_;
  float acc_energy_ = 0.0F;
  float glow_energy_ = 0.0F;
  float fog_energy_ = 0.0F;
  float matrix_energy_ = 0.0F;
  std::uint32_t matrix_cols_ = 0;
  std::uint32_t matrix_rows_ = 0;
  std::vector<float> matrix_bright_;
  std::vector<std::uint8_t> matrix_glyph_;
};

// Real-time zero-dependency RGBA8888 Hero v24 Flight Deck rasterizer.
class HeroFlightDeckEngine {
public:
  explicit HeroFlightDeckEngine(HeroCanvasConfig config = {});

  void reset(std::uint32_t seed = 11);
  void resize(HeroSize size);

  std::uint32_t width() const noexcept { return width_; }
  std::uint32_t height() const noexcept { return height_; }

  void set_theme(HeroThemeId theme);
  HeroThemeId theme() const noexcept { return theme_; }
  void cycle_theme();

  void set_telemetry(const HeroTelemetryInput &telemetry);
  void steer_input(const HeroControlInput &input);

  void set_question(std::optional<HeroQuestion> question);
  bool has_question() const noexcept { return question_.has_value(); }
  bool answer_by_key(std::size_t option_index);
  std::optional<std::size_t> answered_index() const noexcept { return answered_index_; }
  std::optional<std::size_t> take_answered_index() noexcept;
  const std::vector<std::string> &answer_log() const noexcept { return answer_log_; }
  const std::vector<HeroGateState> &gates() const noexcept { return gates_; }

  HeroPlaneState plane_state() const noexcept;
  std::size_t live_particles() const noexcept { return particles_.live_count(); }

  void step(float dt_seconds);
  const HeroFrame &render();
  const HeroFrame &step_and_render(float dt_seconds);
  const HeroFrame &frame() const noexcept { return frame_; }

private:
  struct ActiveQuestion {
    std::string from;
    std::string text;
    std::string detail;
    std::vector<std::string> options;
    float elapsed = 0.0F;
    bool done = false;
    std::size_t pick = 0;
    float flash = 0.0F;
  };

  struct CachedWindow {
    float x = 0.0F;
    float y = 0.0F;
    float w = 0.0F;
    float h = 0.0F;
    float thresh = 0.0F;
    float alpha = 0.0F;
  };

  struct CachedBeacon {
    float x = 0.0F;
    float y = 0.0F;
  };

  void step_substep(float dt_seconds);
  void rebuild_gate_layout();
  void finish_question(std::size_t option_index, std::string_view how);
  void ensure_static_background(const HeroTheme &spec, int horizon_y);
  void draw_background(const HeroTheme &spec);
  void draw_sun_static(std::uint8_t *rgba, const HeroTheme &spec, int horizon_y) const;
  void draw_sun_dynamic(const HeroTheme &spec, int horizon_y);
  void draw_skyline_static(std::uint8_t *rgba, const HeroTheme &spec, int horizon_y);
  void draw_skyline_dynamic(const HeroTheme &spec);
  void draw_gotham_static(std::uint8_t *rgba, const HeroTheme &spec, int horizon_y);
  void draw_gotham_dynamic(const HeroTheme &spec, int horizon_y);
  void draw_fuji_static(std::uint8_t *rgba, const HeroTheme &spec, int horizon_y) const;
  void draw_fuji_dynamic(const HeroTheme &spec, int horizon_y);
  void draw_aurora_static(std::uint8_t *rgba, const HeroTheme &spec, int horizon_y);
  void draw_aurora_dynamic(const HeroTheme &spec, int horizon_y);
  void draw_wire_static(std::uint8_t *rgba, const HeroTheme &spec, int horizon_y) const;
  void draw_wire_dynamic(const HeroTheme &spec, int horizon_y);
  void draw_palms_static(std::uint8_t *rgba, const HeroTheme &spec,
                         int horizon_y) const;
  void draw_palms_dynamic(const HeroTheme &spec, int horizon_y);
  void draw_qud_static(std::uint8_t *rgba, const HeroTheme &spec, int horizon_y) const;
  void draw_qud_dynamic(const HeroTheme &spec, int horizon_y);
  void draw_ocean_dynamic(const HeroTheme &spec, int horizon_y);
  void draw_glyph_ground(const HeroTheme &spec, int horizon_y);
  void draw_grid(const HeroTheme &spec, int horizon_y);
  void draw_question_overlay(const HeroTheme &spec);
  void draw_sr71(const HeroTheme &spec);
  void draw_scanlines(const HeroTheme &spec);
  void draw_hud(const HeroTheme &spec);

  std::uint32_t width_ = hero_default_width;
  std::uint32_t height_ = hero_default_height;
  HeroThemeId theme_ = HeroThemeId::synthwave;
  std::uint32_t seed_ = 11;
  std::uint32_t visual_rng_ = 11;

  HeroTelemetryInput telemetry_{};
  HeroControlInput control_{};
  HeroParticleSystem particles_{};
  HeroFrame frame_{};

  std::vector<std::uint8_t> static_bg_rgba_;
  std::uint32_t static_bg_width_ = 0;
  std::uint32_t static_bg_height_ = 0;
  HeroThemeId static_bg_theme_ = HeroThemeId::synthwave;
  bool static_bg_valid_ = false;
  std::vector<CachedWindow> cached_windows_;
  std::vector<CachedBeacon> cached_beacons_;
  std::vector<int> cached_aurora_clip_y_;

  float sim_t_ = 0.0F;
  float grid_off_ = 0.0F;
  std::uint32_t grid_n_ = 0;

  bool has_prev_engine_counters_ = false;
  std::uint64_t prev_eng_input_ = 0;
  std::uint64_t prev_eng_cached_ = 0;
  std::uint64_t prev_eng_reasoning_ = 0;
  std::uint64_t prev_eng_output_ = 0;
  std::uint64_t prev_eng_jev_ = 0;
  float engine_idle_stale_seconds_ = 0.0F;

  float smooth_rate_ = 45.0F;
  float prev_rate_ = 45.0F;
  float smooth_out_rate_ = 12.0F;
  float smooth_miss_ = 0.15F;

  float stx_ = 0.0F;
  float sty_ = 0.0F;
  float svx_ = 0.0F;
  float svy_ = 0.0F;
  float bank_rad_ = 0.0F;

  std::uint64_t jev_seen_ = 0;
  float beacon_flash_ = 0.0F;
  std::array<float, 6> searchlight_phase_{0.0F, 1.3F, 2.6F, 3.9F, 5.2F, 6.5F};

  std::optional<ActiveQuestion> question_;
  std::vector<HeroGateState> gates_;
  std::optional<std::size_t> answered_index_;
  std::vector<std::string> answer_log_;
};

// Returns true when the terminal supports in-memory Kitty Graphics Protocol
// transmission (Ghostty, Kitty, WezTerm, or BLACKBIRD_GRAPHICS=kitty override).
bool kitty_graphics_capable();

// Returns true when local POSIX shared-memory Kitty graphics (t=s) is safe
// to use: kitty_graphics_capable() is true and no SSH/tmux/screen session is active.
bool kitty_shm_capable() noexcept;

// Encodes an RGBA8888 HeroFrame into standard 4096-byte base64-chunked Kitty
// APC sequences anchored at (placement.row, placement.column).
std::string encode_kitty_rgba_frame(const HeroFrame &frame,
                                    const HeroKittyPlacement &placement = {});

// Encodes an RGBA8888 HeroFrame as 24-bit RGB (f=24, stripping opaque alpha)
// into 4096-byte base64-chunked Kitty APC sequences anchored at
// (placement.row, placement.column).
std::string encode_kitty_rgb_frame(const HeroFrame &frame,
                                   const HeroKittyPlacement &placement = {});

// Encodes an RGBA8888 HeroFrame as 24-bit RGB (f=24) using local POSIX shared
// memory (t=s), emitting a compact ~85-byte Kitty APC sequence carrying only
// the base64-encoded shm object name. Falls back transparently to
// encode_kitty_rgb_frame() if POSIX shm creation or mapping fails.
std::string encode_kitty_shm_rgb_frame(const HeroFrame &frame,
                                       const HeroKittyPlacement &placement = {});

// Deletes the uploaded Kitty graphics image and its placements.
std::string encode_kitty_erase(std::uint32_t image_id = hero_default_kitty_image_id);

// Encodes an RGBA8888 HeroFrame into 24-bit truecolor half-block ("▀") rows
// with per-row run-length color deduplication and same-color space coalescing
// for non-Kitty terminals.
std::vector<std::string>
encode_truecolor_halfblock_frame(const HeroFrame &frame,
                                 const HeroHalfBlockOptions &options = {});

// Emits cursor-addressed ANSI updates for changed half-block rows only
// (or all rows when diff.full_redraw is true or row counts differ).
std::string encode_halfblock_diff(const HeroHalfBlockDiff &diff);

} // namespace blackbird
