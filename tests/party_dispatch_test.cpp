#include "blackbird/party_dispatch.hpp"

#include "blackbird/board_bridge.hpp"
#include "blackbird/party_chat.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/platoon_board.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <thread>
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
    throw std::runtime_error(std::string{ctx} + ": " + error_name(res.error().code) +
                             " (" + std::to_string(res.error().detail) + ")");
  }
  return std::move(res).value();
}

void must_void(Result<void> res, const char *ctx) {
  if (!res.has_value()) {
    throw std::runtime_error(std::string{ctx} + ": " + error_name(res.error().code) +
                             " (" + std::to_string(res.error().detail) + ")");
  }
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

void write_executable_script(const fs::path &path, std::string_view content) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  require(static_cast<bool>(out), "open script failed");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  out.flush();
  require(static_cast<bool>(out), "flush script failed");
  require(::chmod(path.c_str(), mode_t{0700}) == 0, "chmod script failed");
}

void seed_standard_party(const fs::path &root) {
  PartyRosterConfig roster{};
  roster.room_scope = "party/rollcall";
  roster.peers = {
      PartyRosterPeerConfig{
          "wintermute",
          PartyMemberRole::platoon_leader,
          "wintermute.local",
          std::string{"patrick@wintermute"},
          std::string{"deepseek"},
          std::string{"deepseek-chat"},
          std::string{"/srv/wintermute/session"},
          std::string{"Wintermute"},
          std::nullopt,
      },
      PartyRosterPeerConfig{
          "neuromancer",
          PartyMemberRole::platoon_leader,
          "neuromancer.local",
          std::string{"patrick@neuromancer"},
          std::string{"anthropic"},
          std::string{"claude-sonnet-4"},
          std::nullopt,
          std::string{"Neuromancer"},
          std::nullopt,
      },
      PartyRosterPeerConfig{
          "builder",
          PartyMemberRole::platoon_leader,
          "local",
          std::nullopt,
          std::string{"openai"},
          std::string{"gpt-5"},
          std::nullopt,
          std::string{"Builder"},
          std::nullopt,
      },
  };
  must_void(save_party_roster_config(root / ".blackbird" / "party.json", roster),
            "save party roster");

  auto board =
      must(PlatoonBoard::open(root / ".blackbird" / "platoon"), "open platoon board");
  must(board.upsert_member(PlatoonMember{
           "builder",
           "platoon_leader",
           "openai",
           "gpt-5",
           root.string(),
           "main",
           PlatoonMemberState::working,
           1234,
           1000,
           "local builder leader",
       }),
       "upsert builder");
}

void test_all_fanout_concurrent_and_board_recording() {
  TempDir tmp{"bb-party-fanout"};
  seed_standard_party(tmp.path);

  const fs::path peers_dir = tmp.path / "peers";
  auto local_id = must(PeerIdentityStore::open_or_create(peers_dir), "create local id");
  require(!local_id.identity().fingerprint.empty(), "local fp empty");

  PartyDispatchConfig cfg = PartyDispatchConfig::for_project(tmp.path);
  cfg.peers_dir = peers_dir;
  cfg.local_actor = "operator";

  std::atomic<int> in_flight{0};
  std::atomic<int> max_in_flight{0};
  std::mutex seen_mu;
  std::set<std::string> remote_called;
  std::set<std::string> onboard_called;
  std::atomic<bool> saw_signed_envelope{false};

  auto bump_inflight = [&]() {
    const int cur = in_flight.fetch_add(1) + 1;
    int prev = max_in_flight.load();
    while (cur > prev && !max_in_flight.compare_exchange_weak(prev, cur)) {
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{120});
    in_flight.fetch_sub(1);
  };

  cfg.remote_executor = [&](const RemotePeerDispatchRequest &req) {
    if (req.signed_envelope.has_value())
      saw_signed_envelope.store(true);
    {
      const std::lock_guard lk{seen_mu};
      remote_called.insert(req.target.id);
    }
    bump_inflight();
    return RemotePeerDispatchResult{
        PartyDeliveryStatus::replied,
        "ack from " + req.target.id + ": " + req.raw_body,
        {},
        0,
        std::nullopt,
    };
  };

  cfg.onboard_executor = [&](const OnboardLeaderDispatchRequest &req) {
    {
      const std::lock_guard lk{seen_mu};
      onboard_called.insert(req.target.id);
    }
    bump_inflight();
    return OnboardLeaderDispatchResult{
        PartyDeliveryStatus::replied,
        "local ack from " + req.target.id,
        {},
    };
  };

  // Mark remote leaders active via snapshot fallback (builder is active; explicit
  // `@all` or all-leader broadcast): let's also register wintermute & neuromancer
  // as online via party roster + presence so `@all` hits all 3 leaders!
  auto bridge = must(BoardBridge::open(cfg.bridge_dir), "open bridge");
  auto wm_id = must(PeerIdentityStore::open_or_create(tmp.path / "wm-id"), "wm id");
  auto nm_id = must(PeerIdentityStore::open_or_create(tmp.path / "nm-id"), "nm id");
  auto kp = must(KnownPeersStore::open(peers_dir), "open kp");
  must(kp.pin_peer({"wintermute", wm_id.identity().public_key, "wm"}), "pin wm");
  must(kp.pin_peer({"neuromancer", nm_id.identity().public_key, "nm"}), "pin nm");
  must(bridge.record_presence(PresenceRecord{
           wm_id.identity().fingerprint,
           "Wintermute",
           "party/rollcall",
           "online",
           0,
           60LL * 1'000'000'000LL,
       }),
       "wm presence");
  must(bridge.record_presence(PresenceRecord{
           nm_id.identity().fingerprint,
           "Neuromancer",
           "party/rollcall",
           "online",
           0,
           60LL * 1'000'000'000LL,
       }),
       "nm presence");

  const auto report =
      must(dispatch_party_message("@all status rollcall", cfg), "dispatch @all");

  require(report.operator_board_seq > 0, "operator message not posted to PlatoonBoard");
  require(report.unknown_targets.empty(), "unexpected unknown targets");
  require(report.outcomes.size() == 3U, "expected 3 outcomes for @all");
  require(report.replied_count() == 3U, "expected 3 replies");
  require(report.failed_count() == 0U, "expected 0 failures");
  require(max_in_flight.load() >= 2, "targets did not execute concurrently");
  require(saw_signed_envelope.load(), "expected signed outbound envelope");
  require(remote_called.contains("wintermute") && remote_called.contains("neuromancer"),
          "missing remote leader call");
  require(onboard_called.contains("builder"), "missing onboard leader call");

  // Verify PlatoonBoard recorded operator message + untrusted-remote provenance on
  // replies.
  auto board = must(PlatoonBoard::open(cfg.platoon_dir), "reopen board");
  const auto msgs = must(board.read_since(0, 32), "read board");
  require(msgs.size() >= 4U, "expected operator post + 3 replies on PlatoonBoard");
  require(msgs.front().from == "operator" && msgs.front().text == "status rollcall",
          "operator post mismatch");

  bool saw_untrusted_ref = false;
  for (const auto &m : msgs) {
    if (m.from == "wintermute") {
      for (const auto &r : m.refs) {
        if (r == "untrusted_remote:true")
          saw_untrusted_ref = true;
      }
    }
  }
  require(saw_untrusted_ref, "remote reply missing untrusted_remote provenance ref");
}

void test_targeted_dispatch_and_unknown_target() {
  TempDir tmp{"bb-party-target"};
  seed_standard_party(tmp.path);

  PartyDispatchConfig cfg = PartyDispatchConfig::for_project(tmp.path);
  cfg.peers_dir = tmp.path / "absent-peers"; // Deliberately absent!

  std::vector<std::string> called_remote;
  cfg.remote_executor = [&](const RemotePeerDispatchRequest &req) {
    called_remote.push_back(req.target.id);
    require(!req.signed_envelope.has_value(),
            "should not sign envelope when peers_dir absent");
    return RemotePeerDispatchResult{
        PartyDeliveryStatus::replied, "pong from " + req.target.id, {}, 0, std::nullopt,
    };
  };

  // Targeted `@wintermute ping` must dispatch ONLY to wintermute.
  const auto rep =
      must(dispatch_party_message("@wintermute ping", cfg), "dispatch @wintermute");
  require(called_remote.size() == 1U && called_remote.front() == "wintermute",
          "targeted dispatch hit wrong targets");
  require(rep.outcomes.size() == 1U && rep.outcomes.front().target_id == "wintermute" &&
              rep.outcomes.front().status == PartyDeliveryStatus::replied &&
              rep.outcomes.front().reply_text == "pong from wintermute",
          "unexpected targeted outcome");
  require(!rep.local_identity_available,
          "absent peers_dir reported identity available");
  require(!fs::exists(cfg.peers_dir), "dispatch created absent peers_dir");

  // Unknown target `@ghost hi` reports unknown target cleanly without crashing.
  called_remote.clear();
  const auto ghost_rep =
      must(dispatch_party_message("@ghost hi", cfg), "dispatch @ghost");
  require(called_remote.empty(), "unknown target dispatched remote call");
  require(ghost_rep.outcomes.empty(), "unknown target produced delivery outcome");
  require(ghost_rep.has_unknown_targets() && ghost_rep.unknown_targets.size() == 1U &&
              ghost_rep.unknown_targets.front() == "ghost",
          "unknown target not reported");
  require(!fs::exists(cfg.peers_dir),
          "unknown target dispatch created absent peers_dir");

  // Empty/invalid inputs fail with ErrorCode::invalid_range.
  const auto empty_res = dispatch_party_message("   \t\n ", cfg);
  require(!empty_res.has_value() && empty_res.error().code == ErrorCode::invalid_range,
          "empty input not rejected with invalid_range");
  const auto bodyless_res = dispatch_party_message("@wintermute", cfg);
  require(!bodyless_res.has_value() &&
              bodyless_res.error().code == ErrorCode::invalid_range,
          "bodyless mention not rejected with invalid_range");
}

void test_posix_shell_quote_and_ssh_runner() {
  // Hostile shell injection payloads.
  const std::string hostile = "'; rm -rf /; $(whoami) `id` \n";
  const std::string quoted = posix_shell_quote(hostile);
  require(quoted == "''\\''; rm -rf /; $(whoami) `id` \n'",
          "posix_shell_quote output mismatch for hostile payload");

  // Verify build_remote_blackbird_command handles ~/ and quotes hostile prompt.
  RemotePeerDispatchRequest req{};
  req.target.id = "wintermute";
  req.target.ssh_target = "patrick@wintermute";
  req.target.provider = "deepseek";
  req.target.remote_model = "deepseek-chat";
  req.target.remote_session = "/tmp/my session's dir";
  req.prompt = hostile;
  req.remote_blackbird_path = "~/.local/bin/blackbird";
  const std::string cmd = must(build_remote_blackbird_command(req), "build remote cmd");
  require(cmd.starts_with("\"$HOME\"/'.local/bin/blackbird'"),
          "remote ~/ expansion quoting mismatch");
  require(cmd.find(quoted) != std::string::npos,
          "hostile prompt not single-quoted in remote command");

  // Relative ssh_binary must be rejected.
  RemotePeerDispatchRequest bad_bin = req;
  bad_bin.ssh_binary = "ssh";
  const auto bad_bin_res = execute_remote_peer_ssh(bad_bin);
  require(bad_bin_res.status == PartyDeliveryStatus::error,
          "relative ssh_binary was not rejected");

  // Option-injection and malformed ssh_targets must be rejected.
  for (const std::string_view bad :
       {"-oProxyCommand=evil", "patrick@-oProxyCommand=evil", "@host", "user@",
        "a@b@c"}) {
    RemotePeerDispatchRequest bad_target = req;
    bad_target.target.ssh_target = std::string{bad};
    const auto bad_target_res = execute_remote_peer_ssh(bad_target);
    require(bad_target_res.status == PartyDeliveryStatus::error,
            "malformed/option-injection ssh_target was not rejected");
  }

  // Real offline subprocess check with fake local ssh binary: verifies sanitized env
  // (zero secret leakage), exact SSH flags, shell-safe payload, timeout, and output
  // cap.
  TempDir tmp{"bb-party-ssh"};
  const fs::path fake_ssh = tmp.path / "fake-ssh";
  write_executable_script(fake_ssh,
                          "#!/bin/sh\n"
                          "if [ -n \"$BLACKBIRD_TEST_SECRET_API_KEY\" ]; then\n"
                          "  echo LEAKED_SECRET >&2\n"
                          "  exit 9\n"
                          "fi\n"
                          "printf 'ARGS:%s|%s|%s|%s|%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" "
                          "\"$4\" \"$5\" \"$6\" \"$7\"\n");
  require(::setenv("BLACKBIRD_TEST_SECRET_API_KEY", "sk-secret-do-not-leak", 1) == 0,
          "setenv secret failed");

  RemotePeerDispatchRequest ok_req = req;
  ok_req.ssh_binary = fake_ssh.string();
  ok_req.timeout_ms = 5000;
  const auto ok_res = execute_remote_peer_ssh(ok_req);
  require(ok_res.status == PartyDeliveryStatus::replied, "fake ssh did not reply");
  require(ok_res.reply_text.find("ARGS:-T|-o|BatchMode=yes|-o|ConnectTimeout=10|--|"
                                 "patrick@wintermute") != std::string::npos,
          "unexpected ssh argv passed to ssh_binary");

  // Timeout check with sleeping fake ssh.
  const fs::path slow_ssh = tmp.path / "slow-ssh";
  write_executable_script(slow_ssh, "#!/bin/sh\nsleep 5\n");
  RemotePeerDispatchRequest slow_req = ok_req;
  slow_req.ssh_binary = slow_ssh.string();
  slow_req.timeout_ms = 150;
  const auto timeout_res = execute_remote_peer_ssh(slow_req);
  require(timeout_res.status == PartyDeliveryStatus::timeout,
          "slow ssh did not hit hard timeout");

  // Bounded output cap check.
  const fs::path flood_ssh = tmp.path / "flood-ssh";
  write_executable_script(flood_ssh,
                          "#!/bin/sh\ndd if=/dev/zero bs=1024 count=32 2>/dev/null | "
                          "tr '\\0' 'A'\n");
  RemotePeerDispatchRequest cap_req = ok_req;
  cap_req.ssh_binary = flood_ssh.string();
  cap_req.max_output_bytes = 4096U;
  const auto cap_res = execute_remote_peer_ssh(cap_req);
  require(cap_res.status == PartyDeliveryStatus::error,
          "output overflow did not fail cleanly");

  (void)::unsetenv("BLACKBIRD_TEST_SECRET_API_KEY");
}

void test_bridge_watcher_lifecycle_and_fail_closed() {
  TempDir tmp{"bb-party-watch"};

  // 1. Fail-closed when peers_dir is absent (creates ZERO directories or keys!).
  {
    const fs::path absent_peers = tmp.path / "no-such-peers";
    const fs::path bridge_dir = tmp.path / "bridge-existing";
    auto br = must(BoardBridge::open(bridge_dir), "open existing bridge");
    (void)br;

    PartyWatcherConfig bad_cfg{};
    bad_cfg.bridge_dir = bridge_dir;
    bad_cfg.peers_dir = absent_peers;
    bad_cfg.scope = "party/rollcall";

    PartyBridgeWatcher watcher;
    const auto res =
        watcher.poll_and_respond_once(bad_cfg, [](WatchPeerAlias, WatchFencedPrompt) {
          return Result<std::string>::success("should-not-run");
        });
    require(!res.has_value() && res.error().code == ErrorCode::io,
            "watcher did not fail closed on absent peers_dir");
    require(!fs::exists(absent_peers), "watcher created absent peers_dir!");

    // 1b. Fail-closed on an existing EMPTY peers_dir (must NOT create identity.lock!).
    const fs::path empty_peers = tmp.path / "empty-peers";
    require(::mkdir(empty_peers.c_str(), mode_t{0700}) == 0, "mkdir empty_peers");
    PartyWatcherConfig empty_cfg = bad_cfg;
    empty_cfg.peers_dir = empty_peers;
    const auto empty_res =
        watcher.poll_and_respond_once(empty_cfg, [](WatchPeerAlias, WatchFencedPrompt) {
          return Result<std::string>::success("should-not-run");
        });
    require(!empty_res.has_value() && empty_res.error().code == ErrorCode::io,
            "watcher did not fail closed on empty peers_dir");
    require(fs::is_empty(empty_peers),
            "watcher mutated existing empty peers_dir (e.g. created identity.lock)");
  }

  // 2. Full end-to-end auto-responder cycle:
  //    - Answers verified unread peer message once with provenance fencing
  //    - Records signed outbound reply envelope & signed ReadReceipt
  //    - Ignores own events & revoked/unverified peers
  //    - Second poll (even with fresh watcher instance simulating restart) is no-op!
  const fs::path local_peers = tmp.path / "local-peers";
  const fs::path remote_peers = tmp.path / "remote-peers";
  const fs::path revoked_peers = tmp.path / "revoked-peers";
  const fs::path bridge_dir = tmp.path / "live-bridge";

  auto local_id = must(PeerIdentityStore::open_or_create(local_peers), "local id");
  auto remote_id = must(PeerIdentityStore::open_or_create(remote_peers), "remote id");
  auto revoked_id =
      must(PeerIdentityStore::open_or_create(revoked_peers), "revoked id");

  auto local_kp = must(KnownPeersStore::open(local_peers), "open local kp");
  must(local_kp.pin_peer({"wintermute", remote_id.identity().public_key, "trusted"}),
       "pin wintermute");
  must(local_kp.pin_peer({"rogue", revoked_id.identity().public_key, "soon revoked"}),
       "pin rogue");

  auto bridge = must(BoardBridge::open(bridge_dir), "open live bridge");

  // Own message on the same scope (must be ignored!).
  must(bridge.emit_causal_event(CausalEventDraft{
           local_id.identity().fingerprint,
           0,
           {},
           1000,
           "party/rollcall",
           "chat",
           Value::object({{"body", Value{"my own message"}}}),
       }),
       "emit own event");

  // Verified peer message from wintermute (must be answered once!).
  const auto wm_event =
      must(make_causal_event(CausalEventDraft{
               remote_id.identity().fingerprint,
               1,
               {},
               2000,
               "party/rollcall",
               "chat",
               Value::object({{"body", Value{"hello from wintermute"}}}),
           }),
           "make wm event");
  const auto wm_env =
      must(BoardBridge::sign_causal_event_envelope(
               remote_id, wm_event,
               PeerEnvelopeMeta{"env-wm-1", local_id.identity().fingerprint,
                                "party:rollcall", PeerEnvelopeKind::mail, 2000}),
           "sign wm env");
  must(bridge.receive_envelope(wm_env, local_kp), "ingest wm env");

  // Event from rogue peer that gets revoked before polling (must be ignored!).
  const auto rogue_event =
      must(make_causal_event(CausalEventDraft{
               revoked_id.identity().fingerprint,
               1,
               {},
               3000,
               "party/rollcall",
               "chat",
               Value::object({{"body", Value{"compromised prompt"}}}),
           }),
           "make rogue event");
  const auto rogue_env =
      must(BoardBridge::sign_causal_event_envelope(
               revoked_id, rogue_event,
               PeerEnvelopeMeta{"env-rogue-1", local_id.identity().fingerprint,
                                "party:rollcall", PeerEnvelopeKind::mail, 3000}),
           "sign rogue env");
  must(bridge.receive_envelope(rogue_env, local_kp), "ingest rogue env");
  must(local_kp.revoke_peer({revoked_id.identity().fingerprint, "revoked in test"}),
       "revoke rogue");

  // Unverified peer event injected without pinning (must be ignored!).
  auto stranger_id = must(
      PeerIdentityStore::open_or_create(tmp.path / "stranger-peers"), "stranger id");
  const auto stranger_event =
      must(make_causal_event(CausalEventDraft{
               stranger_id.identity().fingerprint,
               1,
               {},
               4000,
               "party/rollcall",
               "chat",
               Value::object({{"body", Value{"stranger danger"}}}),
           }),
           "make stranger event");
  must(bridge.record_causal_event(stranger_event), "record stranger event");

  PartyWatcherConfig wcfg{};
  wcfg.bridge_dir = bridge_dir;
  wcfg.peers_dir = local_peers;
  wcfg.scope = "party/rollcall";
  wcfg.max_replies_per_cycle = 8U;

  std::vector<std::string> seen_aliases;
  std::vector<std::string> seen_prompts;

  auto responder = [&](WatchPeerAlias alias, WatchFencedPrompt fenced) {
    seen_aliases.emplace_back(alias.value);
    seen_prompts.emplace_back(fenced.value);
    return Result<std::string>::success("copy that, " + std::string{alias.value});
  };

  PartyBridgeWatcher watcher;
  const auto cycle1 =
      must(watcher.poll_and_respond_once(wcfg, responder), "watch cycle 1");

  require(cycle1.answered == 1U, "expected exactly 1 answered peer message");
  require(cycle1.skipped_own >= 1U, "expected own message skipped");
  require(cycle1.skipped_unverified == 2U,
          "expected revoked + unverified peer messages skipped");
  require(seen_aliases.size() == 1U && seen_aliases.front() == "wintermute",
          "responder called for wrong peer");
  require(seen_prompts.front().find("<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN>>>") !=
              std::string::npos,
          "responder prompt missing untrusted provenance begin delimiter");
  require(seen_prompts.front().find("<<<BLACKBIRD_UNTRUSTED_PEER_DATA_END>>>") !=
              std::string::npos,
          "responder prompt missing untrusted provenance end delimiter");
  require(seen_prompts.front().find("hello from wintermute") != std::string::npos,
          "responder prompt missing peer payload");
  require(cycle1.outbound_envelopes.size() == 2U,
          "expected signed reply envelope + signed receipt envelope");

  // Verify durable acknowledged receipt bound to incoming event_hash.
  const auto rcpts = must(bridge.receipts_for_event(wm_event.event_hash), "read rcpts");
  require(!rcpts.empty() && rcpts.front().stage == ReceiptStage::acknowledged &&
              rcpts.front().recipient_actor == local_id.identity().fingerprint,
          "missing acknowledged ReadReceipt bound to incoming event_hash");

  // Verify the signed outbound reply & receipt envelopes verify cryptographically!
  auto remote_kp = must(KnownPeersStore::open(remote_peers), "open remote kp");
  must(remote_kp.pin_peer({"local", local_id.identity().public_key, "local host"}),
       "pin local on remote");
  for (const auto &env : cycle1.outbound_envelopes)
    must_void(remote_kp.verify_envelope(env), "verify outbound envelope signature");

  // Second poll with a BRAND NEW PartyBridgeWatcher instance (simulating process
  // restart): must be a clean no-op (`answered == 0`)!
  seen_aliases.clear();
  PartyBridgeWatcher restarted_watcher;
  const auto cycle2 =
      must(restarted_watcher.poll_and_respond_once(wcfg, responder), "watch cycle 2");
  require(cycle2.answered == 0U, "restarted watcher answered same message twice!");
  require(seen_aliases.empty(), "responder invoked on already-answered message!");

  // 3. Anti-loop cap: enqueue 3 new verified messages with max_replies_per_cycle = 2.
  for (std::uint64_t seq = 2; seq <= 4; ++seq) {
    const auto ev =
        must(make_causal_event(CausalEventDraft{
                 remote_id.identity().fingerprint,
                 seq,
                 {},
                 5000 + static_cast<std::int64_t>(seq),
                 "party/rollcall",
                 "chat",
                 Value::object({{"body", Value{"msg " + std::to_string(seq)}}}),
             }),
             "make burst event");
    const auto env = must(BoardBridge::sign_causal_event_envelope(
                              remote_id, ev,
                              PeerEnvelopeMeta{"env-wm-" + std::to_string(seq),
                                               local_id.identity().fingerprint,
                                               "party:rollcall", PeerEnvelopeKind::mail,
                                               5000 + static_cast<std::int64_t>(seq)}),
                          "sign burst env");
    must(bridge.receive_envelope(env, local_kp), "ingest burst env");
  }

  PartyWatcherConfig capped_cfg = wcfg;
  capped_cfg.max_replies_per_cycle = 2U;
  const auto burst1 = must(
      restarted_watcher.poll_and_respond_once(capped_cfg, responder), "burst cycle 1");
  require(burst1.answered == 2U && burst1.capped_by_limit,
          "anti-loop max_replies_per_cycle cap did not trigger at 2");
  const auto burst2 = must(
      restarted_watcher.poll_and_respond_once(capped_cfg, responder), "burst cycle 2");
  require(burst2.answered == 1U && !burst2.capped_by_limit,
          "remaining 1 message was not drained cleanly on next cycle");
  const auto burst3 = must(
      restarted_watcher.poll_and_respond_once(capped_cfg, responder), "burst cycle 3");
  require(burst3.answered == 0U, "third cycle should be a clean no-op");
}

void test_concurrency_hard_cap_at_8() {
  TempDir tmp{"bb-party-cap8"};
  PartyRosterConfig roster{};
  roster.room_scope = "party/rollcall";
  for (int i = 1; i <= 12; ++i) {
    roster.peers.push_back(PartyRosterPeerConfig{
        "node" + std::to_string(i),
        PartyMemberRole::platoon_leader,
        "node" + std::to_string(i) + ".local",
        "op@node" + std::to_string(i),
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
    });
  }
  must_void(save_party_roster_config(tmp.path / ".blackbird" / "party.json", roster),
            "save 12-node roster");

  PartyDispatchConfig cfg = PartyDispatchConfig::for_project(tmp.path);
  cfg.peers_dir = tmp.path / "absent-peers";
  cfg.max_concurrency = 32U; // Must still be hard-capped at <= 8!

  std::atomic<int> in_flight{0};
  std::atomic<int> max_in_flight{0};
  cfg.remote_executor = [&](const RemotePeerDispatchRequest &req) {
    const int cur = in_flight.fetch_add(1) + 1;
    int prev = max_in_flight.load();
    while (cur > prev && !max_in_flight.compare_exchange_weak(prev, cur)) {
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{40});
    in_flight.fetch_sub(1);
    return RemotePeerDispatchResult{
        PartyDeliveryStatus::replied, "ok " + req.target.id, {}, 0, std::nullopt,
    };
  };

  const auto report =
      must(dispatch_party_message("@all rollout check", cfg), "dispatch 12 nodes");
  require(report.outcomes.size() == 12U && report.replied_count() == 12U,
          "expected all 12 remote peers to reply");
  require(max_in_flight.load() >= 2 &&
              max_in_flight.load() <= static_cast<int>(kPartyDispatchMaxConcurrency),
          "concurrency must be parallel and hard-capped at <= 8");
  require(!fs::exists(cfg.peers_dir), "12-node dispatch created absent peers_dir");
}

void test_worker_exception_isolation_and_empty_peers_dir() {
  TempDir tmp{"bb-party-exc"};
  seed_standard_party(tmp.path);

  // Existing empty peers_dir must stay untouched during dispatch (no identity.lock).
  const fs::path empty_peers = tmp.path / "empty-peers";
  require(::mkdir(empty_peers.c_str(), mode_t{0700}) == 0, "mkdir empty_peers");

  PartyDispatchConfig cfg = PartyDispatchConfig::for_project(tmp.path);
  cfg.peers_dir = empty_peers;

  cfg.remote_executor = [&](const RemotePeerDispatchRequest &req) {
    if (req.target.id == "wintermute")
      throw std::runtime_error("simulated transport failure");
    return RemotePeerDispatchResult{
        PartyDeliveryStatus::replied,
        "healthy sibling reply from " + req.target.id,
        {},
        0,
        std::nullopt,
    };
  };

  const auto report =
      must(dispatch_party_message("@wintermute @neuromancer check", cfg),
           "dispatch with throwing worker");
  require(report.outcomes.size() == 2U, "expected 2 outcomes");
  require(report.outcomes[0].target_id == "wintermute" &&
              report.outcomes[0].status == PartyDeliveryStatus::error &&
              report.outcomes[0].error_detail.find("simulated transport failure") !=
                  std::string::npos,
          "throwing worker did not record PartyDeliveryStatus::error");
  require(report.outcomes[1].target_id == "neuromancer" &&
              report.outcomes[1].status == PartyDeliveryStatus::replied &&
              report.outcomes[1].reply_text == "healthy sibling reply from neuromancer",
          "healthy sibling failed when peer worker threw");
  require(fs::is_empty(empty_peers),
          "dispatch mutated existing empty peers_dir (e.g. created identity.lock)");
}

} // namespace

int main() {
  try {
    test_all_fanout_concurrent_and_board_recording();
    test_targeted_dispatch_and_unknown_target();
    test_posix_shell_quote_and_ssh_runner();
    test_bridge_watcher_lifecycle_and_fail_closed();
    test_concurrency_hard_cap_at_8();
    test_worker_exception_isolation_and_empty_peers_dir();
    std::cout << "party_dispatch_test: PASS\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "party_dispatch_test: FAIL: " << ex.what() << '\n';
    return 1;
  }
}
