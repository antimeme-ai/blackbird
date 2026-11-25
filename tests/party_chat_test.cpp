#include "blackbird/party_chat.hpp"

#include "blackbird/board_bridge.hpp"
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

void write_raw_file(const fs::path &path, std::string_view content) {
  fs::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  require(static_cast<bool>(out), "open raw file for write");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  out.flush();
  require(static_cast<bool>(out), "flush raw file");
}

void assert_zero_raw_controls(std::string_view line) {
  std::size_t i = 0;
  while (i < line.size()) {
    const auto b0 = static_cast<unsigned char>(line[i]);
    if (b0 < 0x80U) {
      require(b0 >= 0x20U && b0 != 0x7fU,
              "raw C0/ESC/DEL byte leaked into rendered line");
      ++i;
      continue;
    }
    // Any non-ASCII byte must begin a valid multi-byte UTF-8 sequence (rejects bare C1
    // 0x80..0x9F and stray continuation bytes).
    char32_t cp = 0;
    std::size_t len = 0;
    if ((b0 & 0xe0U) == 0xc0U) {
      require(b0 >= 0xc2U && i + 1 < line.size(), "invalid 2-byte UTF-8 / bare C1");
      const auto b1 = static_cast<unsigned char>(line[i + 1]);
      require((b1 & 0xc0U) == 0x80U, "invalid UTF-8 continuation");
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
      require(false, "bare C1 or invalid UTF-8 lead byte leaked into rendered line");
    }
    require(!(cp >= 0x80U && cp <= 0x9fU),
            "UTF-8 C1 control leaked into rendered line");
    require(cp != 0x061cU && cp != 0x200eU && cp != 0x200fU &&
                !(cp >= 0x202aU && cp <= 0x202eU) && !(cp >= 0x2066U && cp <= 0x2069U),
            "Unicode bidi override/isolate control leaked into rendered line");
    i += len;
  }
}

void test_absent_workspace_creates_zero_dirs() {
  TempDir dir("bb-party-empty");
  TempDir fake_home("bb-party-home");

  PartyConfig cfg = PartyConfig::for_project(dir.path);
  cfg.known_peers_dir = fake_home.path / ".local" / "share" / "blackbird" / "peers";

  const auto snap = must(load_party_snapshot(cfg), "load empty snapshot");
  require(!fs::exists(dir.path / ".blackbird"),
          "load_party_snapshot must NOT create .blackbird");
  require(!fs::exists(fake_home.path / ".local"),
          "load_party_snapshot must NOT create ~/.local");
  require(!snap.party_config_present, "party_config_present false");
  require(!snap.platoon_present, "platoon_present false");
  require(!snap.bridge_present, "bridge_present false");
  require(!snap.known_peers_present, "known_peers_present false");
  require(snap.room_scope == kPartyDefaultScope, "default room scope");
  require(snap.mode == PartyMode::single_operator, "default single_operator mode");
  require(snap.participants.empty(), "empty participants");
  require(snap.messages.empty(), "empty messages");

  PartyChatPane pane(snap);
  const auto frame = pane.render_frame(80, 20, false);
  require(frame.lines.size() == 20, "exact 20 lines rendered");
  for (const auto &line : frame.lines)
    assert_zero_raw_controls(line);
  const std::string rendered = frame.text();
  require(rendered.find("PARTY CHAT") != std::string::npos, "header title present");
  require(rendered.find("[SINGLE-OP · ALL LEADERS]") != std::string::npos,
          "single-op mode badge present");
  require(rendered.find("no party messages yet") != std::string::npos,
          "clean empty state shown");
  require(!fs::exists(dir.path / ".blackbird"), "rendering must NOT create .blackbird");
}

void test_single_operator_auto_mode_routing_and_target_cycle() {
  PartySnapshot snap{};
  snap.room_scope = "party/rollcall";

  PartyParticipant p_op{};
  p_op.id = "patrick";
  p_op.display_name = "Patrick";
  p_op.role = PartyMemberRole::operator_human;
  p_op.host = "laptop";
  p_op.state = PartyParticipantState::online;
  p_op.local_self = true;

  PartyParticipant p_laptop{};
  p_laptop.id = "laptop";
  p_laptop.display_name = "laptop";
  p_laptop.role = PartyMemberRole::platoon_leader;
  p_laptop.host = "laptop";
  p_laptop.model = "claude-opus-4";
  p_laptop.state = PartyParticipantState::working;

  PartyParticipant p_wm{};
  p_wm.id = "wintermute";
  p_wm.display_name = "wintermute";
  p_wm.role = PartyMemberRole::platoon_leader;
  p_wm.host = "wintermute";
  p_wm.model = "deepseek-chat";
  p_wm.state = PartyParticipantState::online;
  p_wm.ssh_target = std::string{"patrick@wintermute"};
  p_wm.provider = std::string{"deepseek"};
  p_wm.remote_model = std::string{"deepseek-chat"};

  PartyParticipant p_nm{};
  p_nm.id = "neuromancer";
  p_nm.display_name = "neuromancer";
  p_nm.role = PartyMemberRole::platoon_leader;
  p_nm.host = "neuromancer";
  p_nm.model = "glm-5";
  p_nm.state = PartyParticipantState::idle;

  snap.participants = {p_op, p_laptop, p_wm, p_nm};
  snap.mode = detect_party_mode(snap.participants);
  require(snap.mode == PartyMode::single_operator,
          "1 operator + 3 leaders => single_operator");

  // Routing: plain text & @all broadcast to all 3 active leaders.
  const auto plain = must(parse_party_input("Roll call status?", snap), "parse plain");
  require(plain.broadcast && !plain.explicit_all, "plain text is implicit broadcast");
  require(plain.target_label == "@all", "target label is @all");
  require(plain.resolved_targets.size() == 3, "broadcast resolves all 3 leaders");
  require(plain.body == "Roll call status?", "body preserved");
  require(!plain.has_unknown_targets(), "no unknown targets");

  const auto explicit_all =
      must(parse_party_input("@all sync up on Wave 7", snap), "parse @all");
  require(explicit_all.broadcast && explicit_all.explicit_all, "@all explicit");
  require(explicit_all.resolved_targets.size() == 3, "@all targets all 3 leaders");
  require(explicit_all.body == "sync up on Wave 7", "@all strips mention");

  // Targeted @wintermute
  const auto single =
      must(parse_party_input("@wintermute run tests now", snap), "parse @wintermute");
  require(!single.broadcast, "targeted message is not broadcast");
  require(single.resolved_targets.size() == 1 &&
              single.resolved_targets[0] == "wintermute",
          "routes to wintermute");
  require(single.target_label == "@wintermute", "target label @wintermute");
  require(single.body == "run tests now", "targeted body");

  // Multi-mention + unknown target flagged cleanly without crash
  const auto multi =
      must(parse_party_input("@wintermute @neuromancer @ghost check logs", snap),
           "parse multi");
  require(multi.resolved_targets.size() == 2, "resolved 2 known leaders");
  require(multi.unknown_targets.size() == 1 && multi.unknown_targets[0] == "ghost",
          "flagged unknown @ghost cleanly");
  require(multi.body == "check logs", "multi body");

  // Reject empty / whitespace / mention-only inputs
  require(!parse_party_input("", snap).has_value(), "reject empty");
  require(!parse_party_input("   \t\n  ", snap).has_value(), "reject whitespace");
  require(!parse_party_input("@wintermute   ", snap).has_value(),
          "reject mention-only without body");

  // Target cycling & unread tracking on PartyChatPane
  PartyChatPane pane(snap);
  require(pane.mode() == PartyMode::single_operator, "pane single_operator");
  require(pane.selected_target() == "@all", "default target @all");
  pane.cycle_target();
  require(pane.selected_target() == "@laptop", "cycle -> @laptop");
  pane.cycle_target();
  require(pane.selected_target() == "@wintermute", "cycle -> @wintermute");
  pane.cycle_target();
  require(pane.selected_target() == "@neuromancer", "cycle -> @neuromancer");
  pane.cycle_target();
  require(pane.selected_target() == "@all", "cycle wraps -> @all");

  // Composer respects selected target when user omits @mention.
  pane.set_selected_target("wintermute");
  pane.set_composer_text("ping from cockpit");
  const auto parsed_comp = must(pane.parse_composer(), "parse composer");
  require(!parsed_comp.broadcast && parsed_comp.resolved_targets.size() == 1 &&
              parsed_comp.resolved_targets[0] == "wintermute",
          "composer routes to selected target");

  // Unread increments while pane is closed, clears on focus.
  require(!pane.is_open(), "pane starts closed");
  PartyMessage m1{};
  m1.id = "m1";
  m1.timestamp_ns = 100;
  m1.sender_id = "wintermute";
  m1.sender_role = PartyMemberRole::platoon_leader;
  m1.sender_model = "deepseek-chat";
  m1.verified_peer = true;
  m1.target = "@all";
  m1.kind = PartyMessageKind::leader_update;
  m1.body = "Build green on wintermute";
  pane.push_message(m1);
  require(pane.unread_count() == 1, "unread incremented while closed");

  const std::string wide_out = pane.render(120, 30, false);
  require(wide_out.find("[SINGLE-OP · ALL LEADERS]") != std::string::npos,
          "wide render shows SINGLE-OP badge");
  require(wide_out.find("[+1 unread]") != std::string::npos,
          "wide render shows unread indicator");
  require(wide_out.find("1 op · 3 leaders") != std::string::npos,
          "wide render shows online counts");
  require(wide_out.find("To: @wintermute") != std::string::npos,
          "wide render shows selected target pill");

  pane.set_open(true);
  pane.set_focused(true);
  require(pane.unread_count() == 0, "focus clears unread");

  // Scrolled up also increments unread on incoming messages, scroll_to_bottom clears
  // it.
  pane.scroll_up(2);
  PartyMessage m2{};
  m2.id = "m2";
  m2.timestamp_ns = 200;
  m2.sender_id = "neuromancer";
  m2.sender_role = PartyMemberRole::platoon_leader;
  m2.verified_peer = true;
  m2.target = "@all";
  m2.kind = PartyMessageKind::leader_update;
  m2.body = "Tests green on neuromancer";
  pane.push_message(m2);
  require(pane.unread_count() == 1, "unread incremented while scrolled up");
  pane.scroll_to_bottom();
  require(pane.scroll_offset() == 0 && pane.unread_count() == 0,
          "scroll_to_bottom resets offset and clears unread");
}

void test_multi_operator_auto_mode_and_filters() {
  PartySnapshot snap{};
  snap.room_scope = "party/ops-room";

  PartyParticipant p1{};
  p1.id = "patrick";
  p1.display_name = "Patrick";
  p1.role = PartyMemberRole::operator_human;
  p1.host = "macbook";
  p1.fingerprint = "bb1-11111111111111111111111111111111";
  p1.state = PartyParticipantState::online;
  p1.local_self = true;

  PartyParticipant p2{};
  p2.id = "phall";
  p2.display_name = "PHall";
  p2.role = PartyMemberRole::operator_human;
  p2.host = "rig-east";
  p2.fingerprint = "bb1-22222222222222222222222222222222";
  p2.state = PartyParticipantState::online;

  PartyParticipant l1{};
  l1.id = "wintermute";
  l1.display_name = "wintermute";
  l1.role = PartyMemberRole::platoon_leader;
  l1.host = "wintermute";
  l1.model = "deepseek-chat";
  l1.state = PartyParticipantState::working;

  PartyParticipant l2{};
  l2.id = "neuromancer";
  l2.display_name = "neuromancer";
  l2.role = PartyMemberRole::platoon_leader;
  l2.host = "neuromancer";
  l2.model = "claude-sonnet";
  l2.state = PartyParticipantState::idle;

  snap.participants = {p1, p2, l1, l2};
  snap.mode = detect_party_mode(snap.participants);
  require(snap.mode == PartyMode::multi_operator,
          "2 operators + 2 leaders => multi_operator");

  PartyMessage msg1{};
  msg1.id = "1";
  msg1.timestamp_ns = 1'700'000'001'000'000'000LL;
  msg1.sender_id = "patrick";
  msg1.sender_role = PartyMemberRole::operator_human;
  msg1.verified_peer = true;
  msg1.target = "@all";
  msg1.kind = PartyMessageKind::chat;
  msg1.body = "PHall, ready to cut Wave 7?";

  PartyMessage msg2{};
  msg2.id = "2";
  msg2.timestamp_ns = 1'700'000'002'000'000'000LL;
  msg2.sender_id = "phall";
  msg2.sender_role = PartyMemberRole::operator_human;
  msg2.verified_peer = true;
  msg2.target = "@patrick";
  msg2.kind = PartyMessageKind::chat;
  msg2.body = "Yes, waiting on wintermute build.";

  PartyMessage msg3{};
  msg3.id = "3";
  msg3.timestamp_ns = 1'700'000'003'000'000'000LL;
  msg3.sender_id = "wintermute";
  msg3.sender_role = PartyMemberRole::platoon_leader;
  msg3.sender_model = "deepseek-chat";
  msg3.verified_peer = true;
  msg3.target = "@all";
  msg3.kind = PartyMessageKind::leader_update;
  msg3.body = "Wave 7A unit tests passing 100%.";

  PartyMessage msg4{};
  msg4.id = "4";
  msg4.timestamp_ns = 1'700'000'004'000'000'000LL;
  msg4.sender_id = "bridge";
  msg4.sender_role = PartyMemberRole::bridge_peer;
  msg4.verified_peer = true;
  msg4.target = "@all";
  msg4.kind = PartyMessageKind::conflict;
  msg4.body = "Concurrent claim on src/parser.cpp: patrick vs phall";

  PartyMessage msg5{};
  msg5.id = "5";
  msg5.timestamp_ns = 1'700'000'005'000'000'000LL;
  msg5.sender_id = "rogue-node";
  msg5.sender_role = PartyMemberRole::bridge_peer;
  msg5.verified_peer = false;
  msg5.target = "@all";
  msg5.kind = PartyMessageKind::chat;
  msg5.body = "Unverified remote message";
  msg5.untrusted_remote = true;

  snap.messages = {msg1, msg2, msg3, msg4, msg5};

  // Multi-op broadcast includes other operator + both leaders.
  const auto bcast = must(parse_party_input("Status all?", snap), "multi broadcast");
  require(bcast.broadcast, "multi broadcast flag");
  require(bcast.resolved_targets.size() == 3,
          "multi broadcast reaches phall + 2 leaders");

  PartyChatPane pane(snap);
  pane.set_open(true);
  pane.set_focused(true);

  const std::string all_view = pane.render(120, 30, false);
  require(all_view.find("[MULTI-OP]") != std::string::npos, "renders [MULTI-OP]");
  require(all_view.find("2 ops · 2 leaders") != std::string::npos,
          "renders 2 ops · 2 leaders");
  require(all_view.find("[OP]") != std::string::npos, "renders [OP] badge");
  require(all_view.find("[LEADER]") != std::string::npos, "renders [LEADER] badge");
  require(all_view.find("[CONFLICT]") != std::string::npos, "renders [CONFLICT] badge");
  require(all_view.find("[PEER:UNTRUSTED]") != std::string::npos,
          "renders [PEER:UNTRUSTED] badge");

  pane.set_filter(PartyMessageFilter::operators);
  require(pane.filtered_messages().size() == 2, "operators filter keeps 2 op msgs");
  pane.set_filter(PartyMessageFilter::leaders);
  require(pane.filtered_messages().size() == 1, "leaders filter keeps 1 leader update");
  pane.set_filter(PartyMessageFilter::conflicts);
  require(pane.filtered_messages().size() == 1, "conflicts filter keeps 1 conflict");
  pane.set_filter(PartyMessageFilter::all);
  require(pane.filtered_messages().size() == 5, "all filter restores all 5 msgs");
}

void test_passive_readonly_invariant_on_populated_platoon_and_bridge() {
  TempDir dir("bb-party-ro");
  const fs::path platoon_dir = dir.path / ".blackbird" / "platoon";
  const fs::path bridge_dir = dir.path / ".blackbird" / "bridge";
  const fs::path peers_dir = dir.path / "peers";

  // Populate PlatoonBoard with 1 operator + 1 leader + status message.
  {
    auto platoon = must(PlatoonBoard::open(platoon_dir), "open platoon");
    PlatoonMember op{};
    op.id = "patrick";
    op.role = "operator";
    op.state = PlatoonMemberState::working;
    op.updated_ns = 1'700'000'010'000'000'000LL;
    must(platoon.upsert_member(op), "upsert op");

    PlatoonMember l1{};
    l1.id = "wintermute";
    l1.role = "platoon_leader";
    l1.provider = "deepseek";
    l1.model = "deepseek-chat";
    l1.state = PlatoonMemberState::working;
    l1.updated_ns = 1'700'000'011'000'000'000LL;
    must(platoon.upsert_member(l1), "upsert l1");

    PlatoonPost p1{};
    p1.from = "wintermute";
    p1.to = "all";
    p1.kind = PlatoonMessageKind::status;
    p1.text = "Leader milestone reached";
    must(platoon.post(std::move(p1)), "post platoon status");
  }

  // Populate BoardBridge with Alice + Bob identities, concurrent claims, presence,
  // and an unread foreign event that blocks Alice's action guard.
  auto alice_id =
      must(PeerIdentityStore::open_or_create(dir.path / "id-alice"), "alice id");
  auto bob_id = must(PeerIdentityStore::open_or_create(dir.path / "id-bob"), "bob id");
  const std::string alice_fp = alice_id.identity().fingerprint;
  const std::string bob_fp = bob_id.identity().fingerprint;

  {
    auto known = must(KnownPeersStore::open(peers_dir), "open known peers");
    must(known.pin_peer(
             PinPeerRequest{"phall", bob_id.identity().public_key, "remote operator"}),
         "pin bob");
  }

  constexpr std::int64_t kNowNs = 1'700'000'100'000'000'000LL;
  {
    auto bridge = must(BoardBridge::open(bridge_dir), "open bridge");

    CausalEventDraft alice_draft{};
    alice_draft.actor_id = alice_fp;
    alice_draft.timestamp_ns = kNowNs - 30'000'000'000LL;
    alice_draft.resource_scope = "src/party_chat.cpp";
    alice_draft.kind = "chat";
    alice_draft.payload = Value::object({
        {"text", Value{"Alice starting party chat"}},
        {"role", Value{"operator_human"}},
    });
    const auto ev_alice =
        must(bridge.emit_causal_event(std::move(alice_draft)), "emit alice");
    (void)ev_alice;

    CausalEventDraft bob_draft{};
    bob_draft.actor_id = bob_fp;
    bob_draft.timestamp_ns = kNowNs - 20'000'000'000LL;
    bob_draft.resource_scope = "src/party_chat.cpp";
    bob_draft.kind = "chat";
    bob_draft.payload = Value::object({
        {"text", Value{"Bob concurrently claiming party_chat.cpp"}},
        {"role", Value{"operator_human"}},
    });
    const auto ev_bob =
        must(bridge.emit_causal_event(std::move(bob_draft)), "emit bob");
    (void)ev_bob;

    PresenceRecord bob_pres{};
    bob_pres.actor_id = bob_fp;
    bob_pres.display_name = "PHall";
    bob_pres.watching_scope = "party/rollcall";
    bob_pres.status = "working";
    bob_pres.updated_ns = kNowNs - 5'000'000'000LL;
    bob_pres.ttl_ns = 300'000'000'000LL;
    must(bridge.record_presence(std::move(bob_pres)), "record bob presence");
  }

  // Snapshot stats and bridge receipts/guard BEFORE passive party load.
  const auto before_platoon_stats = snapshot_tree_stats(platoon_dir);
  const auto before_peers_stats = snapshot_tree_stats(peers_dir);

  std::size_t before_receipt_count = 0;
  ActionGuardVerdict before_guard{};
  {
    auto bridge = must(BoardBridge::open(bridge_dir), "open bridge verify before");
    before_receipt_count = must(bridge.receipts(), "receipts before").size();
    before_guard =
        must(bridge.check_action_guard(alice_fp, "src/party_chat.cpp"), "guard before");
    require(!before_guard.allowed, "alice guard should be blocked by unread bob event");
  }
  const auto before_bridge_stats = snapshot_tree_stats(bridge_dir);

  // Execute passive read-only load_party_snapshot.
  PartyConfig cfg = PartyConfig::for_project(dir.path);
  cfg.known_peers_dir = peers_dir;
  cfg.local_operator_id = "patrick";
  cfg.local_actor_fp = alice_fp;
  cfg.local_host = "macbook";
  cfg.now_ns = kNowNs;

  const auto snap = must(load_party_snapshot(cfg), "load passive snapshot");
  require(snap.platoon_present, "platoon detected");
  require(snap.bridge_present, "bridge detected");
  require(snap.known_peers_present, "known peers detected");
  require(snap.mode == PartyMode::multi_operator,
          "auto-detected multi_operator from patrick + phall");
  require(snap.conflict_count() == 1, "detected 1 concurrent claim conflict");
  require(snap.messages.size() >= 4, "merged platoon + bridge events + conflict alert");

  // Verify ZERO filesystem mutation (sizes and mtimes identical down to nanoseconds).
  require(snapshot_tree_stats(platoon_dir) == before_platoon_stats,
          "platoon_dir mtimes/sizes untouched");
  require(snapshot_tree_stats(bridge_dir) == before_bridge_stats,
          "bridge_dir mtimes/sizes untouched");
  require(snapshot_tree_stats(peers_dir) == before_peers_stats,
          "known_peers_dir mtimes/sizes untouched");

  // Verify BoardBridge receipts & action guard untouched.
  {
    auto bridge = must(BoardBridge::open(bridge_dir), "open bridge verify after");
    const auto after_receipts = must(bridge.receipts(), "receipts after");
    require(after_receipts.size() == before_receipt_count,
            "receipts count completely untouched");
    const auto after_guard =
        must(bridge.check_action_guard(alice_fp, "src/party_chat.cpp"), "guard after");
    require(after_guard == before_guard, "action guard verdict untouched");
  }
}

void test_party_json_roundtrip_and_security_rejections() {
  TempDir dir("bb-party-cfg");
  const fs::path cfg_path = dir.path / ".blackbird" / "party.json";

  PartyRosterPeerConfig peer1{};
  peer1.alias = "wintermute";
  peer1.role = PartyMemberRole::platoon_leader;
  peer1.host = "wintermute.local";
  peer1.ssh_target = std::string{"patrick@wintermute"};
  peer1.provider = std::string{"deepseek"};
  peer1.model = std::string{"deepseek-chat"};
  peer1.remote_session = std::string{"/home/patrick/.blackbird/sessions/wm.json"};
  peer1.display_name = std::string{"Wintermute"};

  PartyRosterPeerConfig peer2{};
  peer2.alias = "neuromancer";
  peer2.role = PartyMemberRole::platoon_leader;
  peer2.host = "neuromancer.local";
  peer2.ssh_target = std::string{"patrick@neuromancer"};
  peer2.provider = std::string{"anthropic"};
  peer2.model = std::string{"claude-opus-4"};

  PartyRosterConfig cfg{};
  cfg.room_scope = "party/alpha-squad";
  cfg.mode_override = PartyModeOverride::single_operator;
  cfg.peers = {peer1, peer2};

  must(save_party_roster_config(cfg_path, cfg), "save party.json");

  struct stat st{};
  require(::lstat(cfg_path.c_str(), &st) == 0, "lstat party.json");
  require((st.st_mode & 0777) == 0600, "party.json saved with 0600 permissions");

  const auto loaded = must(load_party_roster_config(cfg_path), "load party.json");
  require(loaded == cfg, "party.json round-trip exact match");

  // Corrupt JSON rejected
  const fs::path corrupt_path = dir.path / "corrupt.json";
  write_raw_file(corrupt_path, "{not valid json");
  require(!load_party_roster_config(corrupt_path).has_value(), "corrupt json rejected");

  // Unknown / secret key rejected
  const fs::path secret_key_path = dir.path / "secret_key.json";
  write_raw_file(
      secret_key_path,
      R"({"version":1,"room_scope":"party/rollcall","mode":"auto","api_key":"sk-123456","peers":[]})");
  require(!load_party_roster_config(secret_key_path).has_value(),
          "unknown/secret key rejected");

  // Secret-looking value in model field rejected on save
  PartyRosterConfig secret_cfg = cfg;
  secret_cfg.peers[0].model = "sk-ant-secret-token";
  require(
      !save_party_roster_config(dir.path / "secret_val.json", secret_cfg).has_value(),
      "secret-looking value rejected on save");

  // Oversized (> 256 KiB) rejected
  const fs::path oversize_path = dir.path / "oversize.json";
  std::string huge(kPartyConfigMaxBytes + 64, ' ');
  huge[0] = '{';
  huge.back() = '}';
  write_raw_file(oversize_path, huge);
  const auto oversize_res = load_party_roster_config(oversize_path);
  require(!oversize_res.has_value() && oversize_res.error().code == ErrorCode::capacity,
          "oversized party.json rejected with capacity error");

  // Symlink rejected on both load_party_roster_config and load_party_snapshot
  const fs::path link_path = dir.path / "symlink-party.json";
  fs::create_symlink(cfg_path, link_path);
  const auto sym_res = load_party_roster_config(link_path);
  require(!sym_res.has_value() && sym_res.error().code == ErrorCode::io,
          "symlink party.json rejected");

  PartyConfig sym_snap_cfg = PartyConfig::for_project(dir.path);
  sym_snap_cfg.party_config_path = link_path;
  require(!load_party_snapshot(sym_snap_cfg).has_value(),
          "load_party_snapshot rejects symlink party.json");
}

void test_hostile_escape_sanitization_and_responsive_rendering() {
  PartySnapshot snap{};
  snap.room_scope = "room\x1b[31mRED\x07\x7f\x9b"
                    "2J\xc2\x9b"
                    "31m\xe2\x80\xae"
                    "evil";

  PartyParticipant op{};
  op.id = std::string{"op\x1b[2J\x00one", 11};
  op.display_name = "Op\r\nOne";
  op.role = PartyMemberRole::operator_human;
  op.host = "host\x9b"
            "1m\xd8\x9c"
            "h";
  op.model = "mod\xe2\x81\xa6"
             "rtl\xe2\x81\xa9";
  op.state = PartyParticipantState::online;
  op.local_self = true;

  PartyParticipant lead{};
  lead.id = "lead\x07\x7f"
            "1";
  lead.display_name = "Leader1";
  lead.role = PartyMemberRole::platoon_leader;
  lead.host = "wm\x1b]0;pwned\x07";
  lead.model = "deepseek\xc2\x85"
               "chat";
  lead.state = PartyParticipantState::working;

  snap.participants = {op, lead};

  PartyMessage evil_msg{};
  evil_msg.id = "evil-1";
  evil_msg.timestamp_ns = 1000;
  evil_msg.sender_id = "lead\x1b[31m1";
  evil_msg.sender_role = PartyMemberRole::platoon_leader;
  evil_msg.sender_host = "wm\x9b"
                         "0m";
  evil_msg.sender_model = "m\x01\x02";
  evil_msg.verified_peer = false;
  evil_msg.target = "@all";
  evil_msg.kind = PartyMessageKind::chat;
  constexpr char kEvilBody[] = "hello\x1b[31m\x07\x7f\x9b"
                               "2J\xc2\x9b"
                               "32m\xe2\x80\xae"
                               "spoof\xe2\x80\x8e\xe2\x80\x8f\xd8\x9c\xe2\x81\xa6"
                               "iso\x00end";
  evil_msg.body = std::string{kEvilBody, sizeof(kEvilBody) - 1};
  evil_msg.untrusted_remote = true;

  snap.messages = {evil_msg};
  snap.mode = detect_party_mode(snap.participants);

  PartyChatPane pane(snap);
  pane.set_open(true);
  pane.set_focused(true);
  pane.set_composer_text("draft\x1b[31m\x9b"
                         "0m\xe2\x80\xae"
                         "text");

  // Narrow (60x18) responsive rendering
  const auto narrow = pane.render_frame(60, 18, false);
  require(!narrow.split_layout, "60x18 uses compact non-split layout");
  require(narrow.lines.size() == 18, "60x18 exact height");
  for (const auto &line : narrow.lines)
    assert_zero_raw_controls(line);
  require(narrow.text().find("[PEER:UNTRUSTED]") != std::string::npos,
          "narrow shows untrusted badge");
  require(narrow.text().find("Tab target") != std::string::npos,
          "narrow shows key hints");

  // Wide (120x30) responsive rendering
  const auto wide = pane.render_frame(120, 30, false);
  require(wide.split_layout, "120x30 uses split layout");
  require(wide.lines.size() == 30, "120x30 exact height");
  for (const auto &line : wide.lines)
    assert_zero_raw_controls(line);
  require(wide.text().find("│") != std::string::npos,
          "wide render draws split roster divider");

  // Color mode renders ANSI SGR without crashing and still escapes hostile data
  const auto colored = pane.render_frame(120, 30, true);
  require(colored.lines.size() == 30, "colored 120x30 exact height");
  require(colored.text().find("\\x1b") != std::string::npos,
          "hostile ESC still escaped even when color=true");
  require(colored.text().find("\\x9b") != std::string::npos,
          "hostile bare 0x9B CSI still escaped");
  require(colored.text().find("\\xc2\\x9b") != std::string::npos,
          "hostile UTF-8 C1 still escaped");
  require(colored.text().find("\\xe2\\x80\\xae") != std::string::npos,
          "hostile U+202E bidi override still escaped");

  // Tiny degenerate viewports never crash
  require(pane.render_frame(0, 0, false).lines.empty(), "0x0 returns empty");
  require(pane.render_frame(-5, 10, false).lines.empty(), "negative width safe");
  require(pane.render_frame(10, 3, false).lines.size() == 3, "10x3 exact height");
}

void test_unverified_and_revoked_bridge_peer_cannot_impersonate_or_escalate() {
  TempDir dir("bb-party-spoof");
  const fs::path bridge_dir = dir.path / ".blackbird" / "bridge";
  const fs::path peers_dir = dir.path / "peers";

  auto local_id =
      must(PeerIdentityStore::open_or_create(dir.path / "id-local"), "local id");
  auto unverified_id =
      must(PeerIdentityStore::open_or_create(dir.path / "id-rogue"), "rogue id");
  auto revoked_id =
      must(PeerIdentityStore::open_or_create(dir.path / "id-revoked"), "revoked id");

  const std::string local_fp = local_id.identity().fingerprint;
  const std::string rogue_fp = unverified_id.identity().fingerprint;
  const std::string revoked_fp = revoked_id.identity().fingerprint;

  // Pin then revoke `revoked_id`; leave `unverified_id` completely unpinned.
  {
    auto known = must(KnownPeersStore::open(peers_dir), "open known peers");
    must(known.pin_peer(
             PinPeerRequest{"old-op", revoked_id.identity().public_key, "ex-op"}),
         "pin revoked peer");
    must(known.revoke_peer(PeerRevocationRequest{revoked_fp, "compromised key"}),
         "revoke peer");
  }

  constexpr std::int64_t kNowNs = 1'700'000'200'000'000'000LL;
  {
    auto bridge = must(BoardBridge::open(bridge_dir), "open bridge");

    // 1. Unverified peer attempts presence role escalation ("operator") and
    //    display_name spoofing ("Patrick").
    PresenceRecord rogue_pres{};
    rogue_pres.actor_id = rogue_fp;
    rogue_pres.display_name = "Patrick";
    rogue_pres.watching_scope = "party/rollcall";
    rogue_pres.status = "operator";
    rogue_pres.updated_ns = kNowNs - 5'000'000'000LL;
    rogue_pres.ttl_ns = 300'000'000'000LL;
    must(bridge.record_presence(std::move(rogue_pres)), "record rogue presence");

    // 2. Unverified peer attempts sender_id + role impersonation of local operator
    //    "patrick" via causal event payload.
    CausalEventDraft rogue_ev{};
    rogue_ev.actor_id = rogue_fp;
    rogue_ev.timestamp_ns = kNowNs - 3'000'000'000LL;
    rogue_ev.resource_scope = "party/rollcall";
    rogue_ev.kind = "chat";
    rogue_ev.payload = Value::object({
        {"sender_id", Value{"patrick"}},
        {"role", Value{"operator_human"}},
        {"text", Value{"spoofed from unverified peer"}},
    });
    must(bridge.emit_causal_event(std::move(rogue_ev)), "emit rogue event");

    // 3. Revoked peer attempts presence role escalation and sender_id spoofing.
    PresenceRecord rev_pres{};
    rev_pres.actor_id = revoked_fp;
    rev_pres.display_name = "patrick";
    rev_pres.watching_scope = "party/rollcall";
    rev_pres.status = "operator";
    rev_pres.updated_ns = kNowNs - 4'000'000'000LL;
    rev_pres.ttl_ns = 300'000'000'000LL;
    must(bridge.record_presence(std::move(rev_pres)), "record revoked presence");

    CausalEventDraft rev_ev{};
    rev_ev.actor_id = revoked_fp;
    rev_ev.timestamp_ns = kNowNs - 2'000'000'000LL;
    rev_ev.resource_scope = "party/rollcall";
    rev_ev.kind = "chat";
    rev_ev.payload = Value::object({
        {"sender_id", Value{"patrick"}},
        {"role", Value{"operator_human"}},
        {"text", Value{"spoofed from revoked peer"}},
    });
    must(bridge.emit_causal_event(std::move(rev_ev)), "emit revoked event");
  }

  PartyConfig cfg = PartyConfig::for_project(dir.path);
  cfg.known_peers_dir = peers_dir;
  cfg.local_operator_id = "patrick";
  cfg.local_operator_display_name = "Patrick Real";
  cfg.local_actor_fp = local_fp;
  cfg.local_host = "macbook";
  cfg.now_ns = kNowNs;

  const auto snap = must(load_party_snapshot(cfg), "load spoof test snapshot");

  // Mode MUST remain single_operator (only 1 genuine operator: patrick).
  require(snap.mode == PartyMode::single_operator,
          "unverified/revoked peers must NOT flip single_operator to multi_operator");
  require(snap.operator_count() == 1, "operator_count must stay 1");

  // Local operator participant row must remain completely intact.
  const PartyParticipant *patrick = nullptr;
  const PartyParticipant *rogue = nullptr;
  const PartyParticipant *revoked = nullptr;
  for (const auto &p : snap.participants) {
    if (p.id == "patrick")
      patrick = &p;
    if (p.fingerprint == rogue_fp)
      rogue = &p;
    if (p.fingerprint == revoked_fp)
      revoked = &p;
  }
  require(patrick != nullptr, "patrick participant present");
  require(patrick->local_self, "patrick remains local_self");
  require(patrick->fingerprint == local_fp, "patrick fingerprint untouched");
  require(patrick->display_name == "Patrick Real", "patrick display_name untouched");
  require(patrick->role == PartyMemberRole::operator_human, "patrick remains operator");

  require(rogue != nullptr, "rogue participant tracked separately");
  require(rogue->id == rogue_fp, "rogue id stays fingerprint, not patrick");
  require(rogue->role == PartyMemberRole::bridge_peer, "rogue pinned to bridge_peer");
  require(!rogue->local_self, "rogue is not local_self");

  require(revoked != nullptr, "revoked participant tracked separately");
  require(revoked->id == revoked_fp, "revoked id stays fingerprint, not alias");
  require(revoked->role == PartyMemberRole::bridge_peer,
          "revoked peer pinned to bridge_peer");

  // Both spoofed chat messages must be tagged untrusted_remote + bridge_peer, never
  // patrick.
  std::size_t spoof_chat_count = 0;
  for (const auto &m : snap.messages) {
    if (m.kind == PartyMessageKind::conflict)
      continue;
    ++spoof_chat_count;
    require(m.sender_id != "patrick",
            "spoofed message must NOT show sender_id patrick");
    require(m.sender_role == PartyMemberRole::bridge_peer,
            "spoofed message must stay bridge_peer role");
    require(!m.verified_peer, "spoofed message verified_peer must be false");
    require(m.untrusted_remote, "spoofed message untrusted_remote must be true");
  }
  require(spoof_chat_count == 2, "2 spoofed bridge chat messages loaded");

  PartyChatPane pane(snap);
  const std::string rendered = pane.render(120, 30, false);
  require(rendered.find("[SINGLE-OP · ALL LEADERS]") != std::string::npos,
          "pane renders SINGLE-OP badge despite spoof attempts");
  require(rendered.find("[PEER:UNTRUSTED]") != std::string::npos,
          "pane renders [PEER:UNTRUSTED] badge for spoofed messages");
}

void test_structured_agent_card_rendering_and_hostile_sanitization() {
  PartySnapshot snap{};
  snap.room_scope = "room/KAIH";
  snap.mode = PartyMode::multi_operator;

  PartyParticipant self_p{};
  self_p.id = "antimeme";
  self_p.display_name = "@antimeme (blackbird)";
  self_p.role = PartyMemberRole::operator_human;
  self_p.state = PartyParticipantState::online;
  self_p.local_self = true;

  PartyParticipant phall_p{};
  phall_p.id = "phall";
  phall_p.display_name = "@phall (outpost · Claude Code)";
  phall_p.role = PartyMemberRole::operator_human;
  phall_p.state = PartyParticipantState::working;
  snap.participants = {self_p, phall_p};

  PartyMessage card_msg{};
  card_msg.id = "card-1";
  card_msg.timestamp_ns = 1'700'000'500'000'000'000LL;
  card_msg.sender_id = "@phall";
  card_msg.sender_role = PartyMemberRole::platoon_leader;
  card_msg.sender_model = "Claude Code";
  card_msg.verified_peer = true;
  card_msg.untrusted_remote = true;
  card_msg.target = "@all";
  card_msg.kind = PartyMessageKind::leader_update;
  card_msg.body = "[agent] Fixed auth test — 2 files changed";
  PartyAgentCard card{};
  card.title = "Fixed auth test";
  card.summary = "Updated token validation and added regression coverage";
  card.status = "done";
  card.agent_name = "Claude Code";
  card.diff_stat = "+42 -7";
  card.files = {"src/auth.cpp", "tests/auth_test.cpp", "src/a.cpp", "src/b.cpp",
                "src/c.cpp",    "src/d.cpp",           "src/e.cpp"};
  card_msg.agent_card = card;

  // Also test hostile ANSI/OSC/BiDi inside a blocked card.
  PartyMessage hostile_card_msg{};
  hostile_card_msg.id = "card-2";
  hostile_card_msg.timestamp_ns = 1'700'000'510'000'000'000LL;
  hostile_card_msg.sender_id = "@phall";
  hostile_card_msg.sender_role = PartyMemberRole::platoon_leader;
  hostile_card_msg.untrusted_remote = true;
  hostile_card_msg.kind = PartyMessageKind::leader_update;
  PartyAgentCard hostile_card{};
  hostile_card.title = "\x1b[31mBlocked\x1b]0;pwn\x07\xE2\x80\xAE task";
  hostile_card.summary = "Waiting on \xC2\x9B"
                         "2J review";
  hostile_card.status = "blocked";
  hostile_card.agent_name = "Bot\x07";
  hostile_card.files = {"src/secret\x1b[0m.cpp"};
  hostile_card_msg.agent_card = hostile_card;

  snap.messages = {card_msg, hostile_card_msg};

  PartyChatPane pane{snap};
  const PartyChatFrame frame = pane.render_frame(120, 28, false);
  const std::string plain = frame.text();
  require(plain.find("┌─ [DONE] Claude Code · Fixed auth test (+42 -7)") !=
              std::string::npos,
          "Party Chat pane must render structured DONE agent card header");
  require(plain.find("Updated token validation") != std::string::npos,
          "Party Chat pane must render agent card summary");
  require(plain.find("└─ files: src/auth.cpp, tests/auth_test.cpp") !=
              std::string::npos,
          "Party Chat pane must render agent card file list footer");
  require(plain.find("+1") != std::string::npos,
          "Party Chat pane must summarize overflow file count beyond 6");
  require(plain.find("[BLOCKED]") != std::string::npos,
          "Party Chat pane must render BLOCKED status badge");

  for (const auto &line : frame.lines) {
    assert_zero_raw_controls(line);
  }

  // Color mode must also render cleanly without throwing or emptying.
  const PartyChatFrame color_frame = pane.render_frame(100, 24, true);
  require(color_frame.lines.size() == 24U, "color card render preserves height");
  require(color_frame.text().find("[DONE]") != std::string::npos,
          "color card render includes status badge");
}

void test_compact_room_presentation_rendering() {
  PartySnapshot snap{};
  snap.room_scope = "room/335K";
  snap.mode = PartyMode::multi_operator;
  snap.compact_room_presentation = true;

  PartyParticipant me{};
  me.id = "antimeme";
  me.display_name = "@antimeme";
  me.role = PartyMemberRole::operator_human;
  me.host = "blackbird + web";
  me.state = PartyParticipantState::online;
  me.local_self = true;

  PartyParticipant peer{};
  peer.id = "spongebob";
  peer.display_name = "@spongebob";
  peer.role = PartyMemberRole::operator_human;
  peer.host = "blackbird";
  peer.state = PartyParticipantState::online;
  snap.participants = {me, peer};

  PartyMessage peer_chat{};
  peer_chat.id = "m1";
  peer_chat.timestamp_ns = 1795587256000000000LL;
  peer_chat.sender_id = "@spongebob";
  peer_chat.sender_role = PartyMemberRole::operator_human;
  peer_chat.target = "@all";
  peer_chat.kind = PartyMessageKind::chat;
  peer_chat.body = "hello from spongebob";
  peer_chat.untrusted_remote = false;

  PartyMessage direct_msg{};
  direct_msg.id = "m2";
  direct_msg.timestamp_ns = 1795587262000000000LL;
  direct_msg.sender_id = "@antimeme";
  direct_msg.sender_role = PartyMemberRole::operator_human;
  direct_msg.target = "@spongebob";
  direct_msg.kind = PartyMessageKind::chat;
  direct_msg.body = "pinging you directly ✓";

  PartyMessage guest_msg{};
  guest_msg.id = "m3";
  guest_msg.timestamp_ns = 1795587270000000000LL;
  guest_msg.sender_id = "@visitor";
  guest_msg.sender_role = PartyMemberRole::operator_human;
  guest_msg.target = "@all";
  guest_msg.kind = PartyMessageKind::chat;
  guest_msg.body = "hi";
  guest_msg.untrusted_remote = true;

  snap.messages = {peer_chat, direct_msg, guest_msg};

  PartyChatPane pane{snap};
  const PartyChatFrame frame = pane.render_frame(110, 20, false);
  const std::string plain = frame.text();

  require(plain.find("PARTY · room/335K · 2 online") != std::string::npos,
          "compact room header must show clean room code and online count");
  require(plain.find("0 leaders") == std::string::npos,
          "compact room header must omit 0 leaders noise");
  require(plain.find("[MULTI-OP]") == std::string::npos,
          "compact room header must omit [MULTI-OP] noise");
  require(plain.find("ROSTER (2)") != std::string::npos,
          "compact roster must show deduplicated participant count");
  require(plain.find("@antimeme (you)") != std::string::npos,
          "compact roster must render handle cleanly without [OP]");
  require(plain.find("blackbird + web") != std::string::npos,
          "compact roster must render merged client list");
  require(plain.find("[OP]") == std::string::npos,
          "compact room presentation must omit [OP] tags");
  require(plain.find("[PEER:UNTRUSTED]") == std::string::npos,
          "compact room presentation must not stamp [PEER:UNTRUSTED] on authenticated "
          "friends");
  require(plain.find("@spongebob: hello from spongebob") != std::string::npos,
          "compact broadcast chat must omit -> @all noise");
  require(plain.find("@antimeme → @spongebob: pinging you directly") !=
              std::string::npos,
          "compact direct chat must preserve target mention");
  require(plain.find("[GUEST] @visitor: hi") != std::string::npos,
          "compact chat must label unauthenticated guests with [GUEST]");
}

} // namespace

int main() {
  try {
    test_absent_workspace_creates_zero_dirs();
    test_single_operator_auto_mode_routing_and_target_cycle();
    test_multi_operator_auto_mode_and_filters();
    test_passive_readonly_invariant_on_populated_platoon_and_bridge();
    test_party_json_roundtrip_and_security_rejections();
    test_hostile_escape_sanitization_and_responsive_rendering();
    test_unverified_and_revoked_bridge_peer_cannot_impersonate_or_escalate();
    test_structured_agent_card_rendering_and_hostile_sanitization();
    test_compact_room_presentation_rendering();
    std::cout << "party_chat_test: all checks passed\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "party_chat_test FAILED: " << ex.what() << '\n';
    return 1;
  }
}
