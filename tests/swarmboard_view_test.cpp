#include "blackbird/swarmboard_view.hpp"

#include "blackbird/board_bridge.hpp"
#include "blackbird/display_text.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/platoon_board.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
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

template <class T> T must(Result<T> res, const char *ctx) {
  if (!res.has_value()) {
    throw std::runtime_error(std::string{ctx} + ": " + error_name(res.error().code));
  }
  return std::move(res).value();
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

void write_text_file(const fs::path &path, std::string_view content) {
  fs::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  require(static_cast<bool>(out), "open temp file for write");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  out.flush();
  require(static_cast<bool>(out), "flush temp file");
}

void assert_lines_fit_width(const std::vector<std::string> &lines,
                            SwarmboardWidth width, SwarmboardHeight height) {
  require(lines.size() == height.value,
          "rendered line count must match viewport height");
  for (const auto &line : lines) {
    const std::size_t cells = display_cells(line).value;
    require(cells <= width.value, "rendered line exceeded viewport width");
    for (const char ch : line) {
      const auto b = static_cast<unsigned char>(ch);
      require(b >= 0x20U && b != 0x7fU, "raw C0 or DEL control leaked into output");
    }
  }
}

void test_empty_workspace_graceful_no_dirs_created() {
  TempDir dir("bb-swarmboard-empty");
  const auto cfg = SwarmboardConfig::for_project(dir.path);

  SwarmboardView view;
  const auto res = view.reload(cfg);
  require(res.has_value(), "reload on empty workspace must succeed");

  require(!fs::exists(dir.path / ".blackbird"),
          "passive swarmboard load must NOT create .blackbird directory");
  require(!view.snapshot().platoon_present, "platoon_present must be false");
  require(!view.snapshot().leases_present, "leases_present must be false");
  require(!view.snapshot().bridge_present, "bridge_present must be false");
  require(view.snapshot().roster.empty(), "empty roster");
  require(view.snapshot().messages.empty(), "empty messages");
  require(view.snapshot().watchers.empty(), "empty watchers");
  require(view.snapshot().guard_verdict.allowed, "empty guard is clear");
  require(view.snapshot().conflict_count() == 0, "empty conflict count is 0");

  const auto lines80 = view.render_lines(80, 24);
  assert_lines_fit_width(lines80, 80, 24);
  const std::string rendered = view.render(80, 24);
  require(rendered.find("GUARD: CLEAR") != std::string::npos,
          "header shows GUARD: CLEAR");
  require(rendered.find("Watchers: 0") != std::string::npos,
          "header shows Watchers: 0");
  require(rendered.find("(no peers registered)") != std::string::npos,
          "empty roster placeholder shown");
  require(rendered.find("(board empty)") != std::string::npos,
          "empty board placeholder shown");

  // Also ensure switching filters on empty view renders gracefully.
  view.set_filter(SwarmboardFilter::watchers);
  require(view.render(80, 24).find("(no active watchers)") != std::string::npos,
          "empty watchers filter renders cleanly");
  view.set_filter(SwarmboardFilter::conflicts);
  require(view.render(80, 24).find("(no conflicts or blocked items)") !=
              std::string::npos,
          "empty conflicts filter renders cleanly");
  view.set_filter(SwarmboardFilter::mentions);
  require(view.render(80, 24).find("(no matching @mentions)") != std::string::npos,
          "empty mentions filter renders cleanly");
  require(!fs::exists(dir.path / ".blackbird"),
          "rendering must never create workspace directories");
}

void test_populated_platoon_bridge_filters_scroll_and_readonly_invariant() {
  TempDir dir("bb-swarmboard-full");
  const fs::path platoon_dir = dir.path / ".blackbird" / "platoon";
  const fs::path leases_dir = dir.path / ".blackbird" / "worktrees" / ".leases";
  const fs::path bridge_dir = dir.path / ".blackbird" / "bridge";

  // 1. Populate heterogeneous platoon roster + board messages.
  auto platoon = must(PlatoonBoard::open(platoon_dir), "open platoon");
  {
    PlatoonMember m1;
    m1.id = "coder-alpha";
    m1.role = "implementer";
    m1.provider = "claude_code";
    m1.model = "sonnet";
    m1.state = PlatoonMemberState::working;
    m1.updated_ns = 1000;
    must(platoon.upsert_member(m1), "upsert coder-alpha");

    PlatoonMember m2;
    m2.id = "verifier-beta";
    m2.role = "reviewer";
    m2.provider = "codex";
    m2.model = "o3";
    m2.branch = "feat/verify";
    m2.state = PlatoonMemberState::waiting;
    m2.updated_ns = 2000;
    must(platoon.upsert_member(m2), "upsert verifier-beta");

    PlatoonMember m3;
    m3.id = "scout-gamma";
    m3.role = "research";
    m3.provider = "blackbird";
    m3.model = "opus";
    m3.state = PlatoonMemberState::stopped;
    m3.updated_ns = 3000;
    must(platoon.upsert_member(m3), "upsert scout-gamma");

    PlatoonMember m4;
    m4.id = "fuzz-delta";
    m4.role = "fuzzer";
    m4.provider = "acp";
    m4.state = PlatoonMemberState::failed;
    m4.updated_ns = 4000;
    must(platoon.upsert_member(m4), "upsert fuzz-delta");
  }

  // Write a read-only lease metadata file matching coder-alpha.
  write_text_file(
      leases_dir / "lease-alpha.json",
      "{\"version\":1,\"lease_id\":\"lease-alpha\","
      "\"branch\":\"swarm/coder-alpha\",\"base_ref\":\"HEAD\","
      "\"base_sha\":\"0123456789abcdef0123456789abcdef01234567\","
      "\"owner_id\":\"coder-alpha\",\"owner_pid\":1234,\"created_ns\":1000}\n");

  for (int i = 1; i <= 12; ++i) {
    PlatoonPost post;
    post.from = (i % 2 == 0) ? "verifier-beta" : "coder-alpha";
    post.to = (i == 3 || i == 7) ? "coder-alpha" : "all";
    post.kind = (i == 5) ? PlatoonMessageKind::blocker : PlatoonMessageKind::message;
    if (i == 3)
      post.text = "@coder-alpha [done] finished parser slice";
    else if (i == 5)
      post.text = "waiting on schema lock [blocked]";
    else if (i == 7)
      post.text = "@coder-alpha please review diff";
    else
      post.text = "status update #" + std::to_string(i);
    must(platoon.post(std::move(post)), "post platoon msg");
  }

  // 2. Populate BoardBridge with Alice + Bob identities, concurrent claims on
  // `src/parser.cpp`, receipts (one included_in_request, one acted, one unread
  // foreign event to trip check_action_guard!), and active watchers.
  auto alice_id =
      must(PeerIdentityStore::open_or_create(dir.path / "id-alice"), "alice id");
  auto bob_id = must(PeerIdentityStore::open_or_create(dir.path / "id-bob"), "bob id");
  const std::string alice_fp = alice_id.identity().fingerprint;
  const std::string bob_fp = bob_id.identity().fingerprint;

  auto bridge = must(BoardBridge::open(bridge_dir), "open bridge");
  constexpr std::int64_t kNowNs = 1'700'000'100'000'000'000LL;
  constexpr std::int64_t kTtlNs = 300'000'000'000LL;

  // Alice claims src/parser.cpp (no parent)
  const auto ev_alice =
      must(bridge.emit_causal_event(CausalEventDraft{
               alice_fp,
               0,
               {},
               kNowNs - 50'000'000'000LL,
               "src/parser.cpp",
               "claim",
               Value::object({{"text", Value{"Alice claiming src/parser.cpp"}}}),
           }),
           "emit alice claim");

  // Bob concurrently claims src/parser.cpp (no parent -> ConcurrentClaimConflict!)
  // AND Bob's event is UNREAD by Alice -> check_action_guard blocks Alice!
  const auto ev_bob_conflict = must(
      bridge.emit_causal_event(CausalEventDraft{
          bob_fp,
          0,
          {},
          kNowNs - 40'000'000'000LL,
          "src/parser.cpp",
          "claim",
          Value::object({{"text", Value{"Bob concurrent claim on src/parser.cpp"}}}),
      }),
      "emit bob concurrent claim");

  // Bob emits a second event on src/parser.cpp that Alice HAS included & acted on.
  const auto ev_bob_acked =
      must(bridge.emit_causal_event(CausalEventDraft{
               bob_fp,
               0,
               {ev_bob_conflict.event_hash},
               kNowNs - 30'000'000'000LL,
               "src/other.cpp",
               "handoff",
               Value::object({{"text", Value{"Bob handoff [done]"}}}),
           }),
           "emit bob handoff");

  const std::string req_hash = board_bridge_sha256_hex("llm-req-1");
  must(bridge.record_receipt(MessageReceipt{
           ev_bob_acked.event_hash,
           alice_fp,
           ReceiptStage::included_in_request,
           kNowNs - 20'000'000'000LL,
           req_hash,
           std::nullopt,
           std::nullopt,
       }),
       "record included receipt");
  must(bridge.record_receipt(MessageReceipt{
           ev_bob_acked.event_hash,
           alice_fp,
           ReceiptStage::acted,
           kNowNs - 10'000'000'000LL,
           std::nullopt,
           std::nullopt,
           std::string{"commit:abc123"},
       }),
       "record acted receipt");

  // Active watchers: 2 active (1 exact scope, 1 wildcard), 1 expired.
  must(bridge.record_presence(PresenceRecord{
           bob_fp,
           "Bob Reviewer",
           "src/parser.cpp",
           "inspecting diff",
           kNowNs - 5'000'000'000LL,
           kTtlNs,
       }),
       "record bob watcher");
  must(bridge.record_presence(PresenceRecord{
           alice_fp,
           "Alice Lead",
           "*",
           "coordinating",
           kNowNs - 2'000'000'000LL,
           kTtlNs,
       }),
       "record alice watcher");
  must(bridge.record_presence(PresenceRecord{
           bob_fp,
           "Bob Stale",
           "src/old.cpp",
           "gone",
           kNowNs - 900'000'000'000LL,
           kTtlNs,
       }),
       "record expired watcher");

  // Capture exact disk stats and receipt state BEFORE loading/rendering Swarmboard.
  const auto receipts_before = must(bridge.receipts(), "receipts before");
  const auto guard_before =
      must(bridge.check_action_guard(alice_fp, "src/parser.cpp"), "guard before");
  require(!guard_before.allowed && guard_before.blocking_event_hashes.size() == 1,
          "guard must initially block on Bob's unread claim");

  const auto stats_before = snapshot_tree_stats(dir.path / ".blackbird");

  // 3. Load and render Swarmboard across both 80x24 and 120x40 viewports and all
  // filters.
  SwarmboardConfig cfg = SwarmboardConfig::for_project(dir.path);
  cfg.local_actor_fp = alice_fp;
  cfg.local_actor_id = "coder-alpha";
  cfg.scope = "src/parser.cpp";
  cfg.now_ns = kNowNs;

  SwarmboardView view;
  require(view.reload(cfg).has_value(), "reload populated swarmboard");

  const auto &snap = view.snapshot();
  require(snap.roster.size() == 4, "expected 4 roster rows");
  require(snap.working_peers() == 1 && snap.waiting_peers() == 1 &&
              snap.stopped_peers() == 1 && snap.failed_peers() == 1,
          "peer state counts must match 1 working / 1 waiting / 1 stopped / 1 failed");
  require(snap.watchers.size() == 2, "expected 2 active watchers (expired excluded)");
  require(snap.conflict_count() == 1, "expected 1 concurrent claim conflict");
  require(!snap.guard_verdict.allowed &&
              snap.guard_verdict.blocking_event_hashes.size() == 1 &&
              snap.guard_verdict.blocking_event_hashes[0] == ev_bob_conflict.event_hash,
          "guard verdict must report Bob's unread claim");

  // Verify lease enrichment on coder-alpha.
  bool found_alpha = false;
  for (const auto &row : snap.roster) {
    if (row.peer_id == "coder-alpha") {
      found_alpha = true;
      require(row.driver == "claude_code/sonnet", "driver combines provider/model");
      require(row.lease_branch == "swarm/coder-alpha",
              "lease branch loaded read-only from .leases");
      require(row.last_seq > 0, "last_seq populated from platoon board");
    }
  }
  require(found_alpha, "coder-alpha present in roster");
  (void)ev_alice;

  // Verify 120x40 render contents.
  const auto lines120 = view.render_lines(120, 40);
  assert_lines_fit_width(lines120, 120, 40);
  const std::string out120 = view.render(120, 40);
  require(out120.find("Watchers: 2") != std::string::npos, "header shows Watchers: 2");
  require(out120.find("GUARD: BLOCKED(1)") != std::string::npos,
          "header shows GUARD: BLOCKED(1)");
  require(out120.find("Conflicts: 1") != std::string::npos,
          "header shows Conflicts: 1");
  require(out120.find("working=1 waiting=1 stopped=1 failed=1") != std::string::npos,
          "header shows peer state breakdown");
  require(out120.find("PEER") != std::string::npos &&
              out120.find("DRIVER") != std::string::npos &&
              out120.find("SEQ/LEASE") != std::string::npos,
          "roster header columns present");
  require(out120.find("coder-alpha") != std::string::npos &&
              out120.find("swarm/coder-alpha") != std::string::npos,
          "roster shows coder-alpha lease branch");
  require(out120.find("[done]") != std::string::npos, "done badge rendered");
  require(out120.find("[blocked]") != std::string::npos, "blocked badge rendered");
  require(out120.find("[conflict]") != std::string::npos, "conflict badge rendered");
  require(out120.find("[receipt:included]") != std::string::npos,
          "receipt:included badge rendered");
  require(out120.find("[receipt:acted]") != std::string::npos,
          "receipt:acted badge rendered");

  // Verify 80x24 clipping and scrolling.
  // The 3 bridge events have earlier timestamps than the 12 platoon posts, so
  // index 0..2 are bridge events and index 3..14 are platoon #1..#12.
  const auto lines80_top = view.render_lines(80, 24);
  assert_lines_fit_width(lines80_top, 80, 24);
  const std::string top_render = view.render(80, 24);
  require(top_render.find(ev_alice.event_hash.substr(0, 10)) != std::string::npos,
          "top scroll includes earliest bridge claim");
  require(top_render.find("#1 [platoon/message]") != std::string::npos,
          "top scroll includes platoon #1");

  view.scroll_down(4);
  require(view.scroll_offset() == 4, "scroll_down advances offset");
  const std::string scrolled_render = view.render(80, 24);
  require(scrolled_render != top_render, "scrolling changes rendered lower pane");
  require(scrolled_render.find(ev_alice.event_hash.substr(0, 10)) == std::string::npos,
          "scrolled view omits earliest bridge claim");
  require(scrolled_render.find("#1 [platoon/message]") == std::string::npos,
          "scrolled view omits #1");
  require(scrolled_render.find("#2 [platoon/message]") != std::string::npos,
          "scrolled view shows #2");

  view.page_down(5);
  require(view.scroll_offset() == 9, "page_down advances offset");
  view.page_up(4);
  require(view.scroll_offset() == 5, "page_up rewinds offset");
  view.scroll_up(100);
  require(view.scroll_offset() == 0, "scroll_up clamps at 0");

  // Verify filter switching: mentions, conflicts, watchers, all.
  view.set_filter(SwarmboardFilter::mentions);
  const auto mentions = view.filtered_messages();
  require(mentions.size() == 2, "mentions filter isolates @coder-alpha messages");
  const std::string mentions_out80 = view.render(80, 24);
  const std::string mentions_out120 = view.render(120, 40);
  require(mentions_out80.find("Filter: mentions") != std::string::npos &&
              mentions_out80.find("@coder-alpha [done]") != std::string::npos &&
              mentions_out80.find("status update #1\"") == std::string::npos &&
              mentions_out120.find("finished parser slice") != std::string::npos,
          "mentions render shows only matching mentions");

  view.set_filter(SwarmboardFilter::conflicts);
  const auto conflicts = view.filtered_messages();
  require(conflicts.size() >= 3,
          "conflicts filter includes platoon blocker + conflicting bridge claims");
  const std::string conflicts_out = view.render(80, 24);
  require(conflicts_out.find("[conflict]") != std::string::npos &&
              conflicts_out.find("[blocked]") != std::string::npos,
          "conflicts render displays conflict and blocked items");

  view.set_filter(SwarmboardFilter::watchers);
  const std::string watchers_out = view.render(80, 24);
  require(watchers_out.find("Bob Reviewer") != std::string::npos &&
              watchers_out.find("Alice Lead") != std::string::npos &&
              watchers_out.find("Bob Stale") == std::string::npos,
          "watchers filter displays active watchers only");

  // 4. CRITICAL PASSIVE READ-ONLY INVARIANT CHECK:
  // Assert zero disk mtime/size changes, zero created files, and identical
  // BoardBridge receipts & action guard verdict!
  const auto stats_after = snapshot_tree_stats(dir.path / ".blackbird");
  require(stats_before == stats_after,
          "CRITICAL: loading/rendering Swarmboard mutated disk mtime, size, or files!");

  const auto receipts_after = must(bridge.receipts(), "receipts after");
  require(receipts_before == receipts_after,
          "CRITICAL: loading/rendering Swarmboard mutated MessageReceipts!");

  const auto guard_after =
      must(bridge.check_action_guard(alice_fp, "src/parser.cpp"), "guard after");
  require(guard_before == guard_after,
          "CRITICAL: loading/rendering Swarmboard disarmed ActionGuardVerdict!");
}

void test_hostile_terminal_escape_and_c1_injection_sanitization() {
  SwarmboardSnapshot snap{};
  snap.room_label = "room\x1b[31mred\x9b"
                    "6n\r\n";
  snap.guard_verdict = {false, {"deadbeef"}, "reason\x1b]0;pwned\x07\r\x7f"};

  PeerRosterRow peer{};
  peer.peer_id = "peer\x1b[2J";
  peer.role = "role\r\nfake";
  peer.driver = "drv\xc2\x9b"
                "6n";
  peer.owner_actor = "own\x7f"
                     "del";
  peer.state = PeerRosterState::working;
  peer.last_seq = 9;
  peer.lease_branch = "br\x9b"
                      "31m";
  snap.roster.push_back(peer);

  SwarmboardMessageRow msg1{};
  msg1.source = SwarmboardMessageSource::platoon;
  msg1.seq_or_hash = "#9";
  msg1.from = "evil\x1b[31m";
  msg1.to = "victim\x9b"
            "6n";
  msg1.kind = "message";
  msg1.tags = {"[done]"};
  // ANSI ESC, bare C1 0x9B CSI, UTF-8 C1 (0xC2 0x9B), CR, LF, DEL.
  msg1.text = "\x1b[31mRED\x1b[0m \x9b"
              "6n \xc2\x9b"
              "32m \r\n\x7f";
  snap.messages.push_back(msg1);

  SwarmboardMessageRow msg2{};
  msg2.source = SwarmboardMessageSource::platoon;
  msg2.seq_or_hash = "#10";
  msg2.from = "peer-utf8";
  msg2.to = "all";
  msg2.kind = "message";
  // Valid UTF-8 ("café"), quotes, Unicode bidi RLO (U+202E = E2 80 AE), and NUL.
  msg2.text = "\"quoted\" caf\xc3\xa9 \xe2\x80\xae"
              "spoof";
  msg2.text.push_back('\0');
  msg2.text += "tail";
  snap.messages.push_back(msg2);

  WatcherRow watcher{};
  watcher.display_name = "Watch\x1b[31m\x9b"
                         "6n";
  watcher.actor_id = "actor\r\x7f";
  watcher.watching_scope = "src/\xc2\x85"
                           "nel";
  watcher.status = "ok\x07"
                   "bell";
  snap.watchers.push_back(watcher);

  SwarmboardView view{std::move(snap)};
  for (const auto filter : {SwarmboardFilter::all, SwarmboardFilter::watchers}) {
    view.set_filter(filter);
    const auto lines = view.render_lines(120, 40);
    assert_lines_fit_width(lines, 120, 40);
    const std::string rendered = view.render(120, 40);

    // Ensure zero raw ESC, bare C1 (0x80..0x9F when standalone), UTF-8 C1, CR,
    // DEL, BEL, or NUL bytes exist anywhere in rendered output.
    for (std::size_t i = 0; i < rendered.size(); ++i) {
      const auto b = static_cast<unsigned char>(rendered[i]);
      if (b == '\n')
        continue;
      require(b >= 0x20U && b != 0x7fU, "C0 or DEL leaked into rendered output");
      if (b == 0xc2U && i + 1 < rendered.size()) {
        const auto next = static_cast<unsigned char>(rendered[i + 1]);
        require(next < 0x80U || next > 0x9fU, "UTF-8 C1 control leaked into output");
      }
      if (b == 0xe2U && i + 2 < rendered.size() &&
          static_cast<unsigned char>(rendered[i + 1]) == 0x80U &&
          static_cast<unsigned char>(rendered[i + 2]) == 0xaeU) {
        require(false, "Unicode bidi override U+202E leaked into output");
      }
    }
    require(valid_utf8(rendered), "rendered output must be strictly valid UTF-8");
    require(rendered.find("\\x1b[31m") != std::string::npos,
            "ANSI escape must be visible as hex escape");
    require(rendered.find("\\x9b6n") != std::string::npos,
            "bare C1 0x9B CSI must be visible as hex escape");
    require(rendered.find("\\r") != std::string::npos,
            "CR must be visible as \\r escape");
  }

  // Verify valid UTF-8 ("café") is preserved while controls are escaped.
  view.set_filter(SwarmboardFilter::all);
  const std::string msg_out = view.render(120, 40);
  require(msg_out.find("caf\xc3\xa9") != std::string::npos,
          "valid UTF-8 text preserved");
  require(msg_out.find("\\xc2\\x9b32m") != std::string::npos,
          "UTF-8 C1 0xC2 0x9B hex-escaped");
  require(msg_out.find("\\x00tail") != std::string::npos,
          "embedded NUL byte hex-escaped");
  require(msg_out.find("\\xe2\\x80\\xae") != std::string::npos,
          "Unicode bidi override hex-escaped");
}

} // namespace

int main() {
  try {
    test_empty_workspace_graceful_no_dirs_created();
    test_populated_platoon_bridge_filters_scroll_and_readonly_invariant();
    test_hostile_terminal_escape_and_c1_injection_sanitization();
    std::cout << "swarmboard_view_test: ok\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "swarmboard_view_test failed: " << ex.what() << '\n';
    return 1;
  }
}
