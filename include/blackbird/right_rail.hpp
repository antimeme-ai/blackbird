#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::size_t kRightRailDockedMinCols = 136;
inline constexpr std::size_t kRightRailDockedMinWidth = 38;
inline constexpr std::size_t kRightRailDockedMaxWidth = 48;
inline constexpr std::size_t kRightRailMaxEscalationDetailLines = 4;
inline constexpr std::size_t kRightRailSparklineSamples = 12;

enum class RightRailTab : std::uint8_t {
  auto_context,
  escalations,
  tokenomics,
  tasks,
  anchors,
  multiplayer,
};

enum class RightRailMode : std::uint8_t {
  hidden,
  docked,
  overlay,
};

enum class RightRailEscalationKind : std::uint8_t {
  brakes_escalation,
  user_question,
  friend_request,
  lan_safety_number,
  agent_escalation,
};

enum class RightRailBrakesProfile : std::uint8_t {
  black_flag,
  guarded,
  sandboxed,
  airgap,
};

enum class RightRailTaskSource : std::uint8_t {
  builtin,
  beads,
  issue,
  swarm,
  external,
};

enum class RightRailTaskStatus : std::uint8_t {
  active,
  open,
  done,
  blocked,
};

enum class RightRailAnchorCategory : std::uint8_t {
  doctrine,
  design,
  plan,
  spec,
};

enum class RightRailPartyTransport : std::uint8_t {
  offline,
  lan,
  online,
};

enum class RightRailSafetyStatus : std::uint8_t {
  none,
  unverified,
  verified,
  mismatch,
};

enum class RightRailWorkerState : std::uint8_t {
  working,
  waiting,
  stopped,
};

std::string_view right_rail_tab_name(RightRailTab tab) noexcept;
std::string_view right_rail_mode_name(RightRailMode mode) noexcept;
std::string_view right_rail_escalation_kind_name(RightRailEscalationKind kind) noexcept;
std::string_view right_rail_brakes_badge(RightRailBrakesProfile profile) noexcept;
std::string format_right_rail_brakes_badge(std::string_view profile);
std::string_view right_rail_task_source_badge(RightRailTaskSource source) noexcept;
std::string_view right_rail_task_status_glyph(RightRailTaskStatus status) noexcept;
std::string_view right_rail_anchor_category_name(RightRailAnchorCategory cat) noexcept;
std::string_view
right_rail_party_transport_name(RightRailPartyTransport transport) noexcept;
std::string_view right_rail_safety_badge(RightRailSafetyStatus status) noexcept;
std::string_view right_rail_worker_state_name(RightRailWorkerState state) noexcept;

// Distinct non-mutually-convertible parameter wrappers so callers can pass raw
// dimensions/flags (`compute_right_rail_layout(160, 45, false, false)`,
// `pane.render(42, 30)`) cleanly without triggering swappable-parameter lint.
struct RightRailCols {
  std::size_t value = 0;
  constexpr RightRailCols(std::size_t cols) noexcept : value(cols) {}
};

struct RightRailRows {
  std::size_t value = 0;
  constexpr RightRailRows(std::size_t rows) noexcept : value(rows) {}
};

struct RightRailUserOpen {
  bool value = false;
  constexpr RightRailUserOpen(bool open) noexcept : value(open) {}
};

struct RightRailUserDismissed {
  bool value = false;
  constexpr RightRailUserDismissed(bool dismissed) noexcept : value(dismissed) {}
};

struct RightRailWidth {
  int value = 42;
  constexpr RightRailWidth(int cols) noexcept : value(cols) {}
};

struct RightRailHeight {
  int value = 24;
  constexpr RightRailHeight(int rows) noexcept : value(rows) {}
};

struct RightRailLayout {
  RightRailMode mode = RightRailMode::hidden;
  bool visible = false;
  bool docked = false;
  bool overlay = false;
  std::size_t col = 0;
  std::size_t row = 0;
  std::size_t width = 0;
  std::size_t height = 0;
  std::size_t main_width = 0;

  bool operator==(const RightRailLayout &) const = default;
};

// Auto-docking layout helper:
// - Wide terminals (cols >= 136 when !user_dismissed): auto-docks on the right,
//   reserving 38..48 cols with main_width = cols - pane_w - 2, col = main_width + 2.
// - Narrower terminals (cols < 136): hidden by default unless explicitly toggled
//   open (user_open == true), in which case renders in overlay mode.
RightRailLayout
compute_right_rail_layout(RightRailCols cols, RightRailRows rows,
                          RightRailUserOpen user_open,
                          RightRailUserDismissed user_dismissed) noexcept;

struct RightRailEscalation {
  RightRailEscalationKind kind = RightRailEscalationKind::brakes_escalation;
  std::string id;
  std::string title;
  std::string source_label;
  std::vector<std::string> detail_lines; // at most 4 displayed
  std::vector<std::string> actions;
  bool policy_locked = false;

  bool operator==(const RightRailEscalation &) const = default;
};

struct RightRailAnchor {
  RightRailAnchorCategory category = RightRailAnchorCategory::doctrine;
  std::string rel_path;
  std::string title;
  std::uint64_t size_bytes = 0;

  bool operator==(const RightRailAnchor &) const = default;
};

struct RightRailTaskItem {
  std::string id;
  RightRailTaskSource source = RightRailTaskSource::builtin;
  RightRailTaskStatus status = RightRailTaskStatus::open;
  std::string title;
  std::string owner;

  bool operator==(const RightRailTaskItem &) const = default;
};

struct RightRailTokenomics {
  std::string provider;
  std::string model;
  std::string effort;
  double tok_per_sec = 0.0;
  double cache_hit_ratio = 0.0;
  double context_fill_ratio = 0.0;
  std::uint64_t input_tokens = 0;
  std::uint64_t cached_tokens = 0;
  std::uint64_t output_tokens = 0;
  std::uint64_t reasoning_tokens = 0;
  std::string brakes_profile = "GUARDED";
  std::vector<double> throughput_samples;
  bool available = true;

  bool operator==(const RightRailTokenomics &) const = default;
};

struct RightRailSwarmWorker {
  std::string name;
  std::string model;
  RightRailWorkerState state = RightRailWorkerState::waiting;
  std::string task_summary;

  bool operator==(const RightRailSwarmWorker &) const = default;
};

struct RightRailMultiplayer {
  RightRailPartyTransport transport = RightRailPartyTransport::offline;
  std::string party_status;
  std::string room_scope;
  RightRailSafetyStatus safety_status = RightRailSafetyStatus::none;
  std::string safety_number;
  std::size_t peer_count = 0;
  std::size_t friends_online = 0;
  std::size_t pending_friend_requests = 0;
  std::vector<RightRailSwarmWorker> swarm_workers;
  std::size_t lease_conflicts = 0;
  std::vector<std::string> lease_conflict_labels;

  bool is_active() const noexcept;
  bool operator==(const RightRailMultiplayer &) const = default;
};

struct RightRailSnapshot {
  std::vector<RightRailEscalation> escalations;
  RightRailTokenomics tokenomics;
  std::vector<RightRailTaskItem> tasks;
  std::vector<RightRailAnchor> anchors;
  RightRailMultiplayer multiplayer;

  const std::vector<RightRailEscalation> &active_escalations() const noexcept {
    return escalations;
  }
  bool has_escalations() const noexcept { return !escalations.empty(); }
  bool operator==(const RightRailSnapshot &) const = default;
};

// 100% passive read-only governing-document discovery.
// Uses lstat()/fstatat(AT_SYMLINK_NOFOLLOW), rejects symlinks on root, docs/,
// and every candidate file, never creates directories or files, and scans only
// immediate files in root and docs/.
std::vector<RightRailAnchor> discover_repo_anchors(const std::filesystem::path &root);

struct RightRailBarCells {
  std::size_t value = 8;
  constexpr RightRailBarCells(std::size_t count) noexcept : value(count) {}
};

// Compact ratio bar `[████░░░░] 42%` (non-finite ratios render `[░░░░░░░░] --%`).
std::string format_right_rail_bar(double ratio,
                                  RightRailBarCells cells = RightRailBarCells{8});

// Compact 12-sample Unicode sparkline (`▁▂▃▄▅▆▇█`, `·` for missing slots).
std::string format_right_rail_sparkline(std::span<const double> samples,
                                        std::size_t width = kRightRailSparklineSamples);

struct RightRailRenderFrame {
  std::vector<std::string> lines;
  std::string header;
  RightRailTab active_tab = RightRailTab::auto_context;
  bool has_priority_escalation = false;

  std::string text() const;
  bool operator==(const RightRailRenderFrame &) const = default;
};

class RightRailPane {
public:
  RightRailPane() = default;
  explicit RightRailPane(RightRailSnapshot snapshot);

  void update(RightRailSnapshot snapshot);
  const RightRailSnapshot &snapshot() const noexcept { return snapshot_; }
  const std::vector<RightRailEscalation> &active_escalations() const noexcept {
    return snapshot_.escalations;
  }

  bool is_open() const noexcept { return open_; }
  bool is_dismissed() const noexcept { return dismissed_; }
  void set_open(bool open) noexcept;
  void dismiss() noexcept;
  void toggle() noexcept;
  void toggle_for_viewport(std::size_t cols) noexcept;

  RightRailTab pinned_tab() const noexcept { return pinned_tab_; }
  void pin_tab(RightRailTab tab) noexcept;
  void cycle_tab(int delta) noexcept;

  std::size_t scroll_offset() const noexcept { return scroll_offset_; }
  void set_scroll_offset(std::size_t offset) noexcept { scroll_offset_ = offset; }
  void scroll_up(std::size_t lines = 1) noexcept;
  void scroll_down(std::size_t lines = 1) noexcept;
  void reset_scroll() noexcept { scroll_offset_ = 0; }

  RightRailLayout layout(RightRailCols cols, RightRailRows rows) const noexcept;
  RightRailRenderFrame render(RightRailWidth width, RightRailHeight height) const;

private:
  RightRailSnapshot snapshot_{};
  bool open_ = false;
  bool dismissed_ = false;
  RightRailTab pinned_tab_ = RightRailTab::auto_context;
  std::size_t scroll_offset_ = 0;
};

} // namespace blackbird
