#include "blackbird/right_rail.hpp"

#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

namespace fs = std::filesystem;

void require(bool condition, const char *why) {
  if (!condition)
    throw std::runtime_error(why);
}

struct TempDir {
  fs::path path;
  explicit TempDir(const char *prefix) {
    std::string pattern = std::string{"/tmp/"} + prefix + "-XXXXXX";
    auto *created = ::mkdtemp(pattern.data());
    require(created != nullptr, "mkdtemp failed");
    path = created;
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;
};

struct StatRecord {
  off_t size = 0;
  std::int64_t mtime_sec = 0;
  std::int64_t mtime_nsec = 0;
  bool operator==(const StatRecord &) const = default;
};

std::map<std::string, StatRecord> snapshot_tree_stats(const fs::path &root) {
  std::map<std::string, StatRecord> out;
  auto record_one = [&](const fs::path &p) {
    struct stat st{};
    require(::lstat(p.c_str(), &st) == 0, "lstat failed");
#ifdef __APPLE__
    const auto sec = static_cast<std::int64_t>(st.st_mtimespec.tv_sec);
    const auto nsec = static_cast<std::int64_t>(st.st_mtimespec.tv_nsec);
#else
    const auto sec = static_cast<std::int64_t>(st.st_mtim.tv_sec);
    const auto nsec = static_cast<std::int64_t>(st.st_mtim.tv_nsec);
#endif
    out.emplace(p.string(), StatRecord{st.st_size, sec, nsec});
  };
  record_one(root);
  for (const auto &entry : fs::recursive_directory_iterator(root))
    record_one(entry.path());
  return out;
}

void write_raw_file(const fs::path &path, std::string_view content) {
  fs::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  require(static_cast<bool>(out), "open raw file for write");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  out.flush();
  require(static_cast<bool>(out), "flush raw file");
}

std::size_t test_utf8_cells_and_zero_controls(std::string_view line) {
  std::size_t cells = 0;
  std::size_t i = 0;
  while (i < line.size()) {
    const auto b0 = static_cast<unsigned char>(line[i]);
    if (b0 < 0x80U) {
      require(b0 >= 0x20U && b0 != 0x7fU,
              "raw C0/ESC/DEL byte leaked into rendered line");
      ++cells;
      ++i;
      continue;
    }
    char32_t cp = 0;
    std::size_t len = 0;
    if ((b0 & 0xe0U) == 0xc0U) {
      require(b0 >= 0xc2U && i + 1 < line.size(), "invalid 2-byte UTF-8 / bare C1");
      const auto b1 = static_cast<unsigned char>(line[i + 1]);
      require((b1 & 0xc0U) == 0x80U, "invalid 2-byte UTF-8 continuation");
      cp =
          (static_cast<char32_t>(b0 & 0x1fU) << 6U) | static_cast<char32_t>(b1 & 0x3fU);
      len = 2;
    } else if ((b0 & 0xf0U) == 0xe0U) {
      require(i + 2 < line.size(), "truncated 3-byte UTF-8");
      const auto b1 = static_cast<unsigned char>(line[i + 1]);
      const auto b2 = static_cast<unsigned char>(line[i + 2]);
      require((b1 & 0xc0U) == 0x80U && (b2 & 0xc0U) == 0x80U,
              "invalid 3-byte UTF-8 continuation");
      cp = (static_cast<char32_t>(b0 & 0x0fU) << 12U) |
           (static_cast<char32_t>(b1 & 0x3fU) << 6U) |
           static_cast<char32_t>(b2 & 0x3fU);
      len = 3;
    } else if ((b0 & 0xf8U) == 0xf0U) {
      require(b0 <= 0xf4U && i + 3 < line.size(), "invalid 4-byte UTF-8");
      const auto b1 = static_cast<unsigned char>(line[i + 1]);
      const auto b2 = static_cast<unsigned char>(line[i + 2]);
      const auto b3 = static_cast<unsigned char>(line[i + 3]);
      require((b1 & 0xc0U) == 0x80U && (b2 & 0xc0U) == 0x80U && (b3 & 0xc0U) == 0x80U,
              "invalid 4-byte UTF-8 continuation");
      cp = (static_cast<char32_t>(b0 & 0x07U) << 18U) |
           (static_cast<char32_t>(b1 & 0x3fU) << 12U) |
           (static_cast<char32_t>(b2 & 0x3fU) << 6U) |
           static_cast<char32_t>(b3 & 0x3fU);
      len = 4;
    } else {
      require(false, "bare C1 or invalid UTF-8 lead byte leaked");
    }
    require(!(cp >= 0x80U && cp <= 0x9fU), "UTF-8 C1 control leaked");
    require(cp != 0x061cU && cp != 0x200eU && cp != 0x200fU && cp != 0xfeffU &&
                !(cp >= 0x202aU && cp <= 0x202eU) && !(cp >= 0x2066U && cp <= 0x2069U),
            "Unicode bidi or BOM control leaked");

    const bool zero_w =
        (cp >= 0x0300U && cp <= 0x036fU) || (cp >= 0x1ab0U && cp <= 0x1affU) ||
        (cp >= 0x1dc0U && cp <= 0x1dffU) || (cp >= 0x20d0U && cp <= 0x20ffU) ||
        (cp >= 0xfe00U && cp <= 0xfe0fU) || (cp >= 0xfe20U && cp <= 0xfe2fU) ||
        cp == 0x200bU || cp == 0x200cU || cp == 0x200dU;
    const bool wide =
        (cp >= 0x1100U && cp <= 0x115fU) || cp == 0x2329U || cp == 0x232aU ||
        (cp >= 0x2e80U && cp <= 0xa4cfU && cp != 0x303fU) ||
        (cp >= 0xac00U && cp <= 0xd7a3U) || (cp >= 0xf900U && cp <= 0xfaffU) ||
        (cp >= 0xfe10U && cp <= 0xfe19U) || (cp >= 0xfe30U && cp <= 0xfe6fU) ||
        (cp >= 0xff00U && cp <= 0xff60U) || (cp >= 0xffe0U && cp <= 0xffe6U) ||
        (cp >= 0x1f300U && cp <= 0x1faffU) || (cp >= 0x20000U && cp <= 0x3fffdU);
    cells += zero_w ? 0U : (wide ? 2U : 1U);
    i += len;
  }
  return cells;
}

void verify_frame_bounds(const RightRailRenderFrame &frame, RightRailWidth width,
                         RightRailHeight height) {
  const auto w = static_cast<std::size_t>(width.value);
  const auto h = static_cast<std::size_t>(height.value);
  require(frame.lines.size() == h, "frame line count matches height");
  require(test_utf8_cells_and_zero_controls(frame.header) <= w,
          "header exceeds width or contains controls");
  for (const auto &line : frame.lines) {
    const std::size_t cells = test_utf8_cells_and_zero_controls(line);
    require(cells <= w, "rendered line exceeds width");
  }
}

void test_layout_auto_dock_and_overlay() {
  // Wide terminal (160x45): auto-docks by default (!user_dismissed).
  const auto wide = compute_right_rail_layout(160, 45, false, false);
  require(wide.mode == RightRailMode::docked, "160x45 auto-docks");
  require(wide.visible && wide.docked && !wide.overlay, "wide flags");
  require(wide.width >= kRightRailDockedMinWidth &&
              wide.width <= kRightRailDockedMaxWidth,
          "docked width in 38..48");
  require(wide.main_width == 160U - wide.width - 2U, "main_width = cols - pane_w - 2");
  require(wide.col == wide.main_width + 2U, "col = main_width + 2");
  require(wide.row == 0 && wide.height == 45U, "docked full height");

  // Exact threshold cols == 136 auto-docks; cols == 135 stays hidden.
  const auto edge_dock = compute_right_rail_layout(136, 40, false, false);
  require(edge_dock.mode == RightRailMode::docked && edge_dock.docked,
          "136 cols docks");
  require(edge_dock.width >= 38U && edge_dock.width <= 48U, "136 width in 38..48");
  const auto edge_narrow = compute_right_rail_layout(135, 40, false, false);
  require(edge_narrow.mode == RightRailMode::hidden && !edge_narrow.visible,
          "135 cols hidden by default");
  require(edge_narrow.main_width == 135U, "hidden preserves full main_width");

  // Wide terminal dismissed by user: stays hidden.
  const auto wide_dismissed = compute_right_rail_layout(160, 45, false, true);
  require(wide_dismissed.mode == RightRailMode::hidden && !wide_dismissed.visible,
          "dismissed wide rail hidden");
  require(wide_dismissed.main_width == 160U, "dismissed wide preserves main_width");

  // Laptop terminal (100x30): hidden by default.
  const auto laptop_default = compute_right_rail_layout(100, 30, false, false);
  require(laptop_default.mode == RightRailMode::hidden && !laptop_default.visible,
          "100x30 hidden by default");
  require(laptop_default.main_width == 100U, "laptop hidden main_width");

  // Laptop terminal (100x30) manually toggled open: overlay mode.
  const auto laptop_overlay = compute_right_rail_layout(100, 30, true, false);
  require(laptop_overlay.mode == RightRailMode::overlay, "100x30 user_open overlay");
  require(laptop_overlay.visible && laptop_overlay.overlay && !laptop_overlay.docked,
          "overlay flags");
  require(laptop_overlay.main_width == 100U, "overlay does not shrink main_width");
  require(laptop_overlay.width > 0 && laptop_overlay.col + laptop_overlay.width <= 100U,
          "overlay fits horizontally");
  require(laptop_overlay.height > 0 &&
              laptop_overlay.row + laptop_overlay.height <= 30U,
          "overlay fits vertically");

  // Zero dimensions fail cleanly.
  const auto zero = compute_right_rail_layout(0, 0, true, false);
  require(zero.mode == RightRailMode::hidden && !zero.visible, "zero viewport hidden");

  // Pane state transitions: toggle / dismiss / toggle_for_viewport.
  RightRailPane pane;
  require(!pane.is_open() && !pane.is_dismissed(), "initial pane state");
  require(pane.layout(160, 45).docked, "pane auto-docks on wide");
  require(!pane.layout(100, 30).visible, "pane hidden on laptop");
  pane.toggle();
  require(pane.is_open() && !pane.is_dismissed(), "toggle opens");
  require(pane.layout(100, 30).overlay, "toggled pane overlays on laptop");
  pane.toggle();
  require(!pane.is_open() && pane.is_dismissed(), "second toggle dismisses");
  require(!pane.layout(160, 45).visible, "dismissed pane hidden even on wide");
  pane.toggle_for_viewport(160);
  require(pane.layout(160, 45).docked, "toggle_for_viewport re-docks on wide");
  pane.toggle_for_viewport(160);
  require(!pane.layout(160, 45).visible, "toggle_for_viewport hides docked wide");
}

void test_priority_takeover_and_policy_locked() {
  RightRailSnapshot snap{};
  snap.tokenomics.provider = "anthropic";
  snap.tokenomics.model = "claude-opus-4";
  snap.tokenomics.effort = "high";
  snap.tokenomics.tok_per_sec = 92.4;
  snap.tokenomics.cache_hit_ratio = 0.82;
  snap.tokenomics.context_fill_ratio = 0.42;
  snap.tokenomics.brakes_profile = "SANDBOXED";
  snap.tasks.push_back(RightRailTaskItem{
      .id = "t-1",
      .source = RightRailTaskSource::swarm,
      .status = RightRailTaskStatus::active,
      .title = "Implement right rail",
      .owner = "adaptive_right_rail",
  });

  // Escalation 1: actionable brakes escalation.
  snap.escalations.push_back(RightRailEscalation{
      .kind = RightRailEscalationKind::brakes_escalation,
      .id = "brk-42",
      .title = "Outbound curl to example.com",
      .source_label = "brakes:guarded",
      .detail_lines = {"cmd: curl https://example.com", "rule: network-egress", "line3",
                       "line4", "line5-should-be-dropped"},
      .actions = {"[a] Allow once", "[s] Allow turn", "[d] Deny"},
      .policy_locked = false,
  });

  RightRailPane pane(snap);
  require(pane.pinned_tab() == RightRailTab::auto_context, "default auto_context");
  const auto frame = pane.render(44, 34);
  verify_frame_bounds(frame, 44, 34);
  require(frame.active_tab == RightRailTab::auto_context, "auto_context active");
  require(frame.has_priority_escalation, "priority escalation flagged");

  const std::string text = frame.text();
  const auto pos_esc = text.find("BRAKES");
  const auto pos_tok = text.find("TOKENOMICS");
  const auto pos_tsk = text.find("TASKS");
  require(pos_esc != std::string::npos, "escalation rendered");
  require(pos_tok != std::string::npos, "tokenomics rendered");
  require(pos_tsk != std::string::npos, "tasks rendered");
  require(pos_esc < pos_tok && pos_tok < pos_tsk,
          "escalation jumps above tokenomics and tasks in auto_context");
  require(text.find("Allow once") != std::string::npos,
          "actionable escalation shows Allow once");
  require(text.find("line4") != std::string::npos, "4th detail line rendered");
  require(text.find("line5-should-be-dropped") == std::string::npos,
          "detail lines strictly capped at 4");

  // Policy-locked escalation MUST NOT render allow buttons even if passed in actions.
  RightRailSnapshot locked_snap{};
  locked_snap.escalations.push_back(RightRailEscalation{
      .kind = RightRailEscalationKind::brakes_escalation,
      .id = "brk-99",
      .title = "Read ~/.ssh/id_ed25519 blocked",
      .source_label = "brakes:airgap",
      .detail_lines = {"target: ~/.ssh/id_ed25519", "immutable credential fence"},
      .actions = {"[a] Allow once", "[s] Allow turn", "[y] Approve", "[1] Bypass",
                  "[t] Trust", "[d] Deny"},
      .policy_locked = true,
  });
  pane.update(locked_snap);
  const auto locked_frame = pane.render(44, 24);
  verify_frame_bounds(locked_frame, 44, 24);
  const std::string locked_text = locked_frame.text();
  require(locked_text.find("LOCKED: non-escalatable") != std::string::npos,
          "policy_locked shows non-escalatable notice");
  require(locked_text.find("Allow") == std::string::npos,
          "policy_locked hides Allow actions");
  require(locked_text.find("Approve") == std::string::npos,
          "policy_locked hides Approve actions");
  require(locked_text.find("Bypass") == std::string::npos,
          "policy_locked hides unknown/bypass actions fail-closed");
  require(locked_text.find("Trust") == std::string::npos,
          "policy_locked hides Trust actions fail-closed");
  require(locked_text.find("[d] Deny") != std::string::npos,
          "policy_locked retains non-allow Deny action");

  // Also test all 5 escalation kinds render cleanly.
  RightRailSnapshot all_kinds{};
  all_kinds.escalations = {
      {.kind = RightRailEscalationKind::brakes_escalation,
       .id = "e1",
       .title = "B",
       .source_label = "brakes",
       .detail_lines = {},
       .actions = {},
       .policy_locked = false},
      {.kind = RightRailEscalationKind::user_question,
       .id = "e2",
       .title = "Pick build profile",
       .source_label = "question",
       .detail_lines = {},
       .actions = {"[1] Debug", "[2] Release", "[3] ASan"},
       .policy_locked = false},
      {.kind = RightRailEscalationKind::friend_request,
       .id = "e3",
       .title = "Invite from alice",
       .source_label = "social",
       .detail_lines = {},
       .actions = {"[y] Accept", "[n] Decline"},
       .policy_locked = false},
      {.kind = RightRailEscalationKind::lan_safety_number,
       .id = "e4",
       .title = "Verify 12345-67890",
       .source_label = "lan",
       .detail_lines = {},
       .actions = {"[y] Trust", "[n] Reject"},
       .policy_locked = false},
      {.kind = RightRailEscalationKind::agent_escalation,
       .id = "e5",
       .title = "Worker needs rebase",
       .source_label = "swarm",
       .detail_lines = {},
       .actions = {},
       .policy_locked = false},
  };
  pane.update(all_kinds);
  pane.pin_tab(RightRailTab::escalations);
  const auto kinds_frame = pane.render(44, 48);
  verify_frame_bounds(kinds_frame, 44, 48);
  const std::string kinds_text = kinds_frame.text();
  require(kinds_text.find("BRAKES") != std::string::npos, "brakes tag");
  require(kinds_text.find("QUESTION") != std::string::npos, "question tag");
  require(kinds_text.find("FRIEND") != std::string::npos, "friend tag");
  require(kinds_text.find("LAN SAFETY") != std::string::npos, "lan safety tag");
  require(kinds_text.find("AGENT") != std::string::npos, "agent tag");
}

void test_all_four_cards_and_tab_cycling() {
  // Verify bar & sparkline helpers directly.
  const std::string bar42 = format_right_rail_bar(0.42, 8);
  require(bar42.find("42%") != std::string::npos, "42% bar percentage");
  require(bar42.find('[') == 0 && bar42.find(']') != std::string::npos, "bar brackets");
  const std::string bar_nan =
      format_right_rail_bar(std::numeric_limits<double>::quiet_NaN(), 8);
  require(bar_nan.find("--%") != std::string::npos, "NaN bar shows unavailable");

  const std::vector<double> samples{10.0, 20.0, 35.0, 50.0, 80.0, 120.0,
                                    90.0, 75.0, 60.0, 40.0, 95.0, 110.0};
  const std::string spark = format_right_rail_sparkline(samples, 12);
  require(test_utf8_cells_and_zero_controls(spark) == 12U,
          "12-sample sparkline is exactly 12 cells");
  require(spark.find("▁") != std::string::npos && spark.find("█") != std::string::npos,
          "sparkline spans low to high glyphs");

  // Full snapshot covering all 4 cards.
  RightRailSnapshot snap{};
  snap.tokenomics = RightRailTokenomics{
      .provider = "openai",
      .model = "gpt-5.4",
      .effort = "xhigh",
      .tok_per_sec = 112.6,
      .cache_hit_ratio = 0.75,
      .context_fill_ratio = 0.42,
      .input_tokens = 42'500,
      .cached_tokens = 31'800,
      .output_tokens = 4'200,
      .reasoning_tokens = 1'900,
      .brakes_profile = "black_flag",
      .throughput_samples = samples,
      .available = true,
  };
  snap.tasks = {
      {.id = "1",
       .source = RightRailTaskSource::builtin,
       .status = RightRailTaskStatus::active,
       .title = "Core loop",
       .owner = "pat"},
      {.id = "2",
       .source = RightRailTaskSource::beads,
       .status = RightRailTaskStatus::open,
       .title = "Old bead",
       .owner = "lead"},
      {.id = "3",
       .source = RightRailTaskSource::issue,
       .status = RightRailTaskStatus::blocked,
       .title = "Linux test",
       .owner = "ci"},
      {.id = "4",
       .source = RightRailTaskSource::swarm,
       .status = RightRailTaskStatus::done,
       .title = "Wave 17",
       .owner = "swarm-1"},
      {.id = "5",
       .source = RightRailTaskSource::external,
       .status = RightRailTaskStatus::open,
       .title = "Ext hook",
       .owner = ""},
  };
  snap.anchors = {
      {.category = RightRailAnchorCategory::doctrine,
       .rel_path = "BLACKBIRD.md",
       .title = "BLACKBIRD.md",
       .size_bytes = 2048},
      {.category = RightRailAnchorCategory::design,
       .rel_path = "docs/CORE_DESIGN.md",
       .title = "CORE_DESIGN.md",
       .size_bytes = 25000},
      {.category = RightRailAnchorCategory::plan,
       .rel_path = "docs/IMPLEMENTATION_PLAN.md",
       .title = "IMPLEMENTATION_PLAN.md",
       .size_bytes = 15000},
      {.category = RightRailAnchorCategory::spec,
       .rel_path = "docs/LAN_PARTY_SPEC.md",
       .title = "LAN_PARTY_SPEC.md",
       .size_bytes = 9000},
  };
  snap.multiplayer = RightRailMultiplayer{
      .transport = RightRailPartyTransport::lan,
      .party_status = "host",
      .room_scope = "party/rollcall",
      .safety_status = RightRailSafetyStatus::verified,
      .safety_number = "12345-67890",
      .peer_count = 3,
      .friends_online = 2,
      .pending_friend_requests = 1,
      .swarm_workers =
          {
              {.name = "right_rail",
               .model = "opus",
               .state = RightRailWorkerState::working,
               .task_summary = "Wave 18A"},
              {.name = "dentist-2",
               .model = "sonnet",
               .state = RightRailWorkerState::waiting,
               .task_summary = "review"},
          },
      .lease_conflicts = 1,
      .lease_conflict_labels = {"src/terminal.cpp"},
  };

  RightRailPane pane(snap);

  // Tokenomics tab.
  pane.pin_tab(RightRailTab::tokenomics);
  const auto tok_frame = pane.render(44, 18);
  verify_frame_bounds(tok_frame, 44, 18);
  const std::string tok_txt = tok_frame.text();
  require(tok_txt.find("[BLACK FLAG]") != std::string::npos, "BLACK FLAG badge");
  require(tok_txt.find("openai/gpt-5.4 (xhigh)") != std::string::npos,
          "provider/model/effort");
  require(tok_txt.find("112.6 tok/s") != std::string::npos, "tok/s rate");
  require(tok_txt.find("75%") != std::string::npos, "cache hit pct");
  require(tok_txt.find("42%") != std::string::npos, "context fill pct");
  require(tok_txt.find("42.5k") != std::string::npos, "input tokens");
  require(tok_txt.find("31.8k") != std::string::npos, "cached tokens");
  require(tok_txt.find("4.2k") != std::string::npos, "output tokens");
  require(tok_txt.find("1.9k") != std::string::npos, "reasoning tokens");
  require(tok_txt.find(spark) != std::string::npos, "12-sample sparkline rendered");

  // Brakes profile badges normalization.
  require(format_right_rail_brakes_badge("guarded") == "GUARDED", "GUARDED badge");
  require(format_right_rail_brakes_badge("sandboxed") == "SANDBOXED",
          "SANDBOXED badge");
  require(format_right_rail_brakes_badge("air-gap") == "AIRGAP", "AIRGAP badge");

  // Tasks tab: all 5 sources & all 4 status glyphs.
  pane.pin_tab(RightRailTab::tasks);
  const auto tsk_frame = pane.render(44, 18);
  verify_frame_bounds(tsk_frame, 44, 18);
  const std::string tsk_txt = tsk_frame.text();
  require(tsk_txt.find("● [BB]") != std::string::npos, "active builtin task");
  require(tsk_txt.find("○ [BD]") != std::string::npos, "open beads task");
  require(tsk_txt.find("! [IS]") != std::string::npos, "blocked issue task");
  require(tsk_txt.find("✓ [SW]") != std::string::npos, "done swarm task");
  require(tsk_txt.find("○ [EXT]") != std::string::npos, "open external task");

  // Anchors tab.
  pane.pin_tab(RightRailTab::anchors);
  const auto anc_frame = pane.render(44, 18);
  verify_frame_bounds(anc_frame, 44, 18);
  const std::string anc_txt = anc_frame.text();
  require(anc_txt.find("doctrine:") != std::string::npos &&
              anc_txt.find("BLACKBIRD.md") != std::string::npos,
          "doctrine anchor");
  require(anc_txt.find("design:") != std::string::npos &&
              anc_txt.find("docs/CORE_DESIGN.md") != std::string::npos,
          "design anchor");
  require(anc_txt.find("plan:") != std::string::npos &&
              anc_txt.find("docs/IMPLEMENTATION_PLAN.md") != std::string::npos,
          "plan anchor");
  require(anc_txt.find("spec:") != std::string::npos &&
              anc_txt.find("docs/LAN_PARTY_SPEC.md") != std::string::npos,
          "spec anchor");

  // Multiplayer / Swarm tab.
  pane.pin_tab(RightRailTab::multiplayer);
  const auto mp_frame = pane.render(44, 22);
  verify_frame_bounds(mp_frame, 44, 22);
  const std::string mp_txt = mp_frame.text();
  require(mp_txt.find("LAN (host) · party/rollcall") != std::string::npos,
          "party transport + scope");
  require(mp_txt.find("[SN VERIFIED]") != std::string::npos, "safety number badge");
  require(mp_txt.find("Peers: 3 · Friends: 2 on · 1 req") != std::string::npos,
          "peers/friends/requests");
  require(mp_txt.find("Swarm: 1 working · 1 waiting") != std::string::npos,
          "swarm worker counts");
  require(mp_txt.find("! Lease conflicts: 1") != std::string::npos,
          "lease conflict count");
  require(mp_txt.find("src/terminal.cpp") != std::string::npos, "lease conflict label");

  // Tab cycling wraps forward and backward.
  pane.pin_tab(RightRailTab::auto_context);
  pane.cycle_tab(1);
  require(pane.pinned_tab() == RightRailTab::escalations, "cycle +1 -> escalations");
  pane.cycle_tab(-2);
  require(pane.pinned_tab() == RightRailTab::multiplayer, "cycle -2 wraps to mp");
  pane.cycle_tab(1);
  require(pane.pinned_tab() == RightRailTab::auto_context, "cycle +1 wraps to auto");
}

void test_discover_repo_anchors_passive_and_symlink_safe() {
  TempDir repo("bb-rail-anchors");
  TempDir outside("bb-rail-outside");

  write_raw_file(outside.path / "secret.md", "top secret");

  // Legitimate files across all 4 categories.
  write_raw_file(repo.path / "BLACKBIRD.md", "# Doctrine\n");
  write_raw_file(repo.path / "AGENTS.md", "# Agents\n");
  write_raw_file(repo.path / "docs" / "CORE_DESIGN.md", "# Design\n");
  write_raw_file(repo.path / "docs" / "TUI_DOCTRINE.md", "# TUI Doctrine\n");
  write_raw_file(repo.path / "docs" / "IMPLEMENTATION_PLAN.md", "# Plan\n");
  write_raw_file(repo.path / "docs" / "LAN_PARTY_SPEC.md", "# LAN Spec\n");
  write_raw_file(repo.path / "docs" / "CUSTOM_SPEC_V2.md", "# Custom Spec\n");
  // Nested file outside root + docs/ must NOT be discovered.
  write_raw_file(repo.path / "docs" / "nested" / "DEEP_SPEC.md", "# Deep\n");
  write_raw_file(repo.path / "docs" / "README.md", "# Regular doc\n");

  // Symlink traps MUST be rejected.
  fs::create_symlink(outside.path / "secret.md", repo.path / "CLAUDE.md");
  fs::create_symlink(outside.path / "secret.md",
                     repo.path / "docs" / "INTERACTION_THEORY.md");
  fs::create_symlink(outside.path / "secret.md",
                     repo.path / "docs" / "TESTING_PLAN.md");
  fs::create_symlink(outside.path / "secret.md", repo.path / "docs" / "EVIL_SPEC.md");

  const auto before_stats = snapshot_tree_stats(repo.path);
  const auto anchors = discover_repo_anchors(repo.path);
  const auto after_stats = snapshot_tree_stats(repo.path);
  require(before_stats == after_stats,
          "discover_repo_anchors must be 100% passive read-only");

  auto has_anchor = [&](std::string_view rel, RightRailAnchorCategory cat) {
    for (const auto &a : anchors) {
      if (a.rel_path == rel && a.category == cat)
        return true;
    }
    return false;
  };
  auto has_path = [&](std::string_view rel) {
    for (const auto &a : anchors) {
      if (a.rel_path == rel)
        return true;
    }
    return false;
  };

  require(has_anchor("BLACKBIRD.md", RightRailAnchorCategory::doctrine),
          "BLACKBIRD.md detected");
  require(has_anchor("AGENTS.md", RightRailAnchorCategory::doctrine),
          "AGENTS.md detected");
  require(has_anchor("docs/CORE_DESIGN.md", RightRailAnchorCategory::design),
          "CORE_DESIGN.md detected");
  require(has_anchor("docs/TUI_DOCTRINE.md", RightRailAnchorCategory::design),
          "TUI_DOCTRINE.md detected");
  require(has_anchor("docs/IMPLEMENTATION_PLAN.md", RightRailAnchorCategory::plan),
          "IMPLEMENTATION_PLAN.md detected");
  require(has_anchor("docs/LAN_PARTY_SPEC.md", RightRailAnchorCategory::spec),
          "LAN_PARTY_SPEC.md detected");
  require(has_anchor("docs/CUSTOM_SPEC_V2.md", RightRailAnchorCategory::spec),
          "CUSTOM_SPEC_V2.md detected");

  // Symlinks & nested/unrelated files excluded.
  require(!has_path("CLAUDE.md"), "symlink CLAUDE.md rejected");
  require(!has_path("docs/INTERACTION_THEORY.md"),
          "symlink INTERACTION_THEORY.md rejected");
  require(!has_path("docs/TESTING_PLAN.md"), "symlink TESTING_PLAN.md rejected");
  require(!has_path("docs/EVIL_SPEC.md"), "symlink EVIL_SPEC.md rejected");
  require(!has_path("docs/nested/DEEP_SPEC.md"), "nested spec excluded");
  require(!has_path("docs/README.md"), "non-spec README excluded");

  // Symlinked docs/ directory rejected entirely.
  TempDir sym_docs_repo("bb-rail-symdocs");
  write_raw_file(sym_docs_repo.path / "BLACKBIRD.md", "# OK\n");
  fs::create_symlink(repo.path / "docs", sym_docs_repo.path / "docs");
  const auto sym_docs_anchors = discover_repo_anchors(sym_docs_repo.path);
  require(sym_docs_anchors.size() == 1 &&
              sym_docs_anchors[0].rel_path == "BLACKBIRD.md",
          "symlinked docs/ directory ignored");

  // Symlinked root rejected entirely.
  TempDir sym_root_parent("bb-rail-symroot");
  const fs::path sym_root = sym_root_parent.path / "link_root";
  fs::create_symlink(repo.path, sym_root);
  require(discover_repo_anchors(sym_root).empty(), "symlinked root rejected");

  // Nonexistent root returns empty and creates nothing.
  const fs::path missing = sym_root_parent.path / "does-not-exist";
  require(discover_repo_anchors(missing).empty(), "missing root returns empty");
  require(!fs::exists(missing), "missing root never created");
}

void test_hostile_sanitization_and_sweep_bounds() {
  const std::string hostile = std::string{"evil\x1b[31mRED\x1b]52;c;cHdu\x07\x9b"} +
                              "2J" + "\xc2\x9b" + "0m" + "\xe2\x80\xae" + "spoof" +
                              "\xe2\x81\xa6" + "iso" + "\xef\xbb\xbf" +
                              "line\nbreak\r\x7f" + "漢字🚀";

  RightRailSnapshot snap{};
  snap.escalations.push_back(RightRailEscalation{
      .kind = RightRailEscalationKind::lan_safety_number,
      .id = hostile,
      .title = hostile,
      .source_label = hostile,
      .detail_lines = {hostile, hostile, hostile, hostile},
      .actions = {hostile, "[d] Deny"},
      .policy_locked = false,
  });
  snap.tokenomics = RightRailTokenomics{
      .provider = hostile,
      .model = hostile,
      .effort = hostile,
      .tok_per_sec = std::numeric_limits<double>::infinity(),
      .cache_hit_ratio = 1.7,
      .context_fill_ratio = -0.3,
      .input_tokens = 1234567890ULL,
      .cached_tokens = 98765432ULL,
      .output_tokens = 54321ULL,
      .reasoning_tokens = 999ULL,
      .brakes_profile = hostile,
      .throughput_samples = {std::numeric_limits<double>::quiet_NaN(), 5.0, 25.0,
                             std::numeric_limits<double>::infinity(), 40.0},
      .available = true,
  };
  snap.tasks.push_back(RightRailTaskItem{
      .id = hostile,
      .source = RightRailTaskSource::external,
      .status = RightRailTaskStatus::blocked,
      .title = hostile,
      .owner = hostile,
  });
  snap.anchors.push_back(RightRailAnchor{
      .category = RightRailAnchorCategory::spec,
      .rel_path = hostile,
      .title = hostile,
      .size_bytes = 4096,
  });
  snap.multiplayer = RightRailMultiplayer{
      .transport = RightRailPartyTransport::online,
      .party_status = hostile,
      .room_scope = hostile,
      .safety_status = RightRailSafetyStatus::mismatch,
      .safety_number = hostile,
      .peer_count = 7,
      .friends_online = 4,
      .pending_friend_requests = 2,
      .swarm_workers = {{.name = hostile,
                         .model = hostile,
                         .state = RightRailWorkerState::working,
                         .task_summary = hostile}},
      .lease_conflicts = 2,
      .lease_conflict_labels = {hostile},
  };

  RightRailPane pane(snap);
  static constexpr RightRailTab kAllTabs[] = {
      RightRailTab::auto_context, RightRailTab::escalations, RightRailTab::tokenomics,
      RightRailTab::tasks,        RightRailTab::anchors,     RightRailTab::multiplayer,
  };

  for (const RightRailTab tab : kAllTabs) {
    pane.pin_tab(tab);
    for (int w = 24; w <= 60; w += 6) {
      for (int h = 8; h <= 50; h += 7) {
        const auto frame = pane.render(w, h);
        verify_frame_bounds(frame, w, h);
        require(frame.active_tab == tab, "active_tab matches pinned");
      }
    }
    // Also test exact boundary widths 24, 38, 48, 60 and heights 8, 50.
    for (const int w : {24, 38, 48, 60}) {
      for (const int h : {8, 50}) {
        const auto frame = pane.render(w, h);
        verify_frame_bounds(frame, w, h);
      }
    }
  }

  // Degenerate / tiny viewports never crash or violate cell bounds.
  const auto zero_frame = pane.render(0, 0);
  require(zero_frame.lines.empty(), "0x0 render returns empty lines");
  for (const int w : {1, 4, 10}) {
    for (const int h : {1, 2, 3, 4}) {
      const auto tiny = pane.render(w, h);
      verify_frame_bounds(tiny, w, h);
    }
  }

  // Scroll clamping under extreme scroll_offset never crashes or violates bounds.
  pane.pin_tab(RightRailTab::auto_context);
  pane.scroll_down(10000);
  const auto scrolled = pane.render(38, 12);
  verify_frame_bounds(scrolled, 38, 12);
  pane.scroll_up(10000);
  require(pane.scroll_offset() == 0, "scroll_up saturates at 0");
}

} // namespace

int main() {
  test_layout_auto_dock_and_overlay();
  test_priority_takeover_and_policy_locked();
  test_all_four_cards_and_tab_cycling();
  test_discover_repo_anchors_passive_and_symlink_safe();
  test_hostile_sanitization_and_sweep_bounds();
  std::cout << "right_rail_test: all checks passed\n";
  return 0;
}
