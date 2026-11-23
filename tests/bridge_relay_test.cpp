#include "blackbird/bridge_relay.hpp"

#include "blackbird/json.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

const char *g_stage = "startup";

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

template <class T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{context} + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
  return std::move(result).value();
}

void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{context} + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
}

std::filesystem::path make_temp_dir() {
  const char *env_tmp = std::getenv("TMPDIR");
  std::string base =
      (env_tmp != nullptr && env_tmp[0] != '\0') ? std::string{env_tmp} : "/tmp";
  while (base.size() > 1 && base.back() == '/')
    base.pop_back();
  std::string tmpl = base + "/blackbird-bridge-relay-test-XXXXXX";
  char *created = ::mkdtemp(tmpl.data());
  if (!created)
    throw std::runtime_error("mkdtemp failed");
  return std::filesystem::path{created};
}

// ---------------------------------------------------------------------------
// 1. 3-Lane Priority Multiplexer Tests
// ---------------------------------------------------------------------------

void test_three_lane_mux_preemption_and_coalescing() {
  g_stage = "three_lane_mux";

  check(relay_lane_name(RelayLane::control) == "control", "control name");
  check(relay_lane_name(RelayLane::causal) == "causal", "causal name");
  check(relay_lane_name(RelayLane::presence) == "presence", "presence name");
  check(must(parse_relay_lane("control"), "parse control") == RelayLane::control,
        "parse control mismatch");
  check(!parse_relay_lane("unknown").has_value(), "unknown lane accepted");
  check(relay_lane_max_bytes(RelayLane::control) == 16 * 1024, "control max bytes");
  check(relay_lane_max_bytes(RelayLane::presence) == 4 * 1024, "presence max bytes");
  check(relay_lane_max_bytes(RelayLane::causal) == 4 * 1024 * 1024, "causal max bytes");

  // Reject invalid mux configs (exceeding hard 16 KiB control cap or zero depth).
  {
    BridgeMuxConfig bad_cfg{};
    bad_cfg.control_max_bytes = kRelayControlMaxBytes + 1;
    check(!BridgeMux::create(bad_cfg).has_value(),
          "BridgeMux accepted control_max_bytes > 16 KiB");
    BridgeMuxConfig zero_cfg{};
    zero_cfg.max_causal_queue = 0;
    check(!BridgeMux::create(zero_cfg).has_value(),
          "BridgeMux accepted zero queue cap");
  }

  auto mux = must(BridgeMux::create(BridgeMuxConfig{
                      .max_control_queue = 16,
                      .max_causal_queue = 32,
                      .max_presence_queue = 4,
                  }),
                  "create BridgeMux");

  // Flood Lane 1 (causal) with 10 work orders.
  for (std::uint64_t i = 1; i <= 10; ++i) {
    const auto st = must(mux.enqueue(RelayPacket{
                             RelayLane::causal,
                             "causal-" + std::to_string(i),
                             "alice",
                             "src/engine.cpp",
                             i,
                             static_cast<std::int64_t>(1000 + i),
                             "work-order-" + std::to_string(i),
                         }),
                         "enqueue causal");
    check(st == BridgeMuxEnqueueStatus::queued, "causal should be queued");
  }

  // Flood Lane 2 (presence) with 50 heartbeats for the SAME (actor, scope).
  for (std::uint64_t i = 1; i <= 50; ++i) {
    const auto st = must(mux.enqueue(RelayPacket{
                             RelayLane::presence,
                             "hb-" + std::to_string(i),
                             "bob",
                             "src/engine.cpp",
                             i,
                             static_cast<std::int64_t>(2000 + i),
                             "watching-step-" + std::to_string(i),
                         }),
                         "enqueue presence");
    if (i == 1)
      check(st == BridgeMuxEnqueueStatus::queued, "first heartbeat queued");
    else
      check(st == BridgeMuxEnqueueStatus::coalesced, "subsequent heartbeat coalesced");
  }

  // Must coalesce 50 heartbeats down to exactly 1 latest packet!
  check(mux.lane_size(RelayLane::presence) == 1,
        "50 presence heartbeats did not coalesce to 1");
  check(mux.stats().presence_coalesced == 49, "expected 49 coalesced heartbeats");

  // Delayed/stale older heartbeat for same (actor, scope) must be ignored.
  const auto stale_st = must(mux.enqueue(RelayPacket{
                                 RelayLane::presence,
                                 "hb-stale",
                                 "bob",
                                 "src/engine.cpp",
                                 10,
                                 2010,
                                 "stale-payload",
                             }),
                             "enqueue stale presence");
  check(stale_st == BridgeMuxEnqueueStatus::ignored_stale,
        "stale heartbeat was not ignored");
  check(mux.stats().presence_stale_ignored == 1, "stale counter mismatch");

  // Now enqueue a Lane 0 control recall AFTER flooding Lane 1 and Lane 2.
  const auto ctrl_st = must(mux.enqueue(RelayPacket{
                                RelayLane::control,
                                "recall-1",
                                "coordinator",
                                "room:alpha",
                                99,
                                5000,
                                "{\"kind\":\"recall\"}",
                            }),
                            "enqueue control recall");
  check(ctrl_st == BridgeMuxEnqueueStatus::queued, "control recall not queued");

  // Control payload > 16 KiB must be rejected with ErrorCode::capacity.
  const auto oversize = mux.enqueue(RelayPacket{
      RelayLane::control,
      "ctrl-big",
      "coordinator",
      "room:alpha",
      100,
      5001,
      std::string(kRelayControlMaxBytes + 1, 'x'),
  });
  check(!oversize.has_value() && oversize.error().code == ErrorCode::capacity,
        "oversize control packet was not rejected");

  // Dequeue order: Lane 0 FIRST, then all 10 Lane 1 packets in FIFO order, then Lane 2.
  const auto first = mux.dequeue_next();
  check(first.has_value() && first->lane == RelayLane::control &&
            first->packet_id == "recall-1",
        "Lane 0 recall did not preempt Lane 1 and Lane 2");

  for (std::uint64_t i = 1; i <= 10; ++i) {
    const auto next = mux.dequeue_next();
    check(next.has_value() && next->lane == RelayLane::causal &&
              next->packet_id == "causal-" + std::to_string(i),
          "Lane 1 FIFO order broken");
  }

  const auto last = mux.dequeue_next();
  check(last.has_value() && last->lane == RelayLane::presence &&
            last->packet_id == "hb-50" && last->payload == "watching-step-50",
        "Lane 2 did not deliver latest coalesced heartbeat #50");
  check(!mux.dequeue_next().has_value() && mux.empty(), "mux not empty after drain");

  // Even AFTER dequeue, a delayed older heartbeat for ("bob", "src/engine.cpp")
  // must NOT be replayed.
  const auto post_drain_stale = must(mux.enqueue(RelayPacket{
                                         RelayLane::presence,
                                         "hb-late-stale",
                                         "bob",
                                         "src/engine.cpp",
                                         49,
                                         2049,
                                         "old-state",
                                     }),
                                     "enqueue post-drain stale presence");
  check(post_drain_stale == BridgeMuxEnqueueStatus::ignored_stale && mux.empty(),
        "stale presence replayed after drain");

  // Bounded Lane 2 drop-oldest across distinct (actor, scope) watchers (cap = 4).
  for (int i = 1; i <= 6; ++i) {
    const auto st = must(mux.enqueue(RelayPacket{
                             RelayLane::presence,
                             "w-" + std::to_string(i),
                             "watcher-" + std::to_string(i),
                             "room:alpha",
                             1,
                             static_cast<std::int64_t>(6000 + i),
                             "alive",
                         }),
                         "enqueue distinct watcher");
    if (i <= 4)
      check(st == BridgeMuxEnqueueStatus::queued, "watcher within cap queued");
    else
      check(st == BridgeMuxEnqueueStatus::dropped_oldest_and_queued,
            "watcher beyond cap should drop oldest");
  }
  check(mux.lane_size(RelayLane::presence) == 4, "presence cap not enforced");
  check(mux.stats().presence_dropped_oldest == 2, "expected 2 dropped oldest presence");
  // Oldest watchers 1 and 2 dropped; remaining should be 3, 4, 5, 6.
  for (int i = 3; i <= 6; ++i) {
    const auto p = mux.dequeue_next();
    check(p.has_value() && p->actor_id == "watcher-" + std::to_string(i),
          "unexpected watcher after drop-oldest");
  }
}

// ---------------------------------------------------------------------------
// 2. Signed Late-Join Checkpoints & O(delta) Filtering
// ---------------------------------------------------------------------------

void test_signed_checkpoint_and_delta_filter(const std::filesystem::path &base) {
  g_stage = "signed_checkpoint_and_delta_filter";

  auto alice_id =
      must(PeerIdentityStore::open_or_create(base / "cp-alice"), "create alice id");
  auto bob_id =
      must(PeerIdentityStore::open_or_create(base / "cp-bob"), "create bob id");
  auto charlie_id =
      must(PeerIdentityStore::open_or_create(base / "cp-charlie"), "create charlie id");
  auto known = must(KnownPeersStore::open(base / "cp-known"), "open known peers");
  (void)must(known.pin_peer({"alice", alice_id.identity().public_key, "lead"}),
             "pin alice");

  // Build causal event history spanning pre-checkpoint and post-checkpoint events.
  const auto ev_a1 = must(make_causal_event({
                              alice_id.identity().fingerprint,
                              1,
                              {},
                              1000,
                              "src/a.cpp",
                              "claim",
                              Value::object({{"step", Value{Number{1}}}}),
                          }),
                          "make ev_a1");
  const auto ev_a2 = must(make_causal_event({
                              alice_id.identity().fingerprint,
                              2,
                              {ev_a1.event_hash},
                              1100,
                              "src/a.cpp",
                              "patch",
                              Value::object({{"step", Value{Number{2}}}}),
                          }),
                          "make ev_a2");
  const auto ev_b1 = must(make_causal_event({
                              bob_id.identity().fingerprint,
                              1,
                              {ev_a1.event_hash},
                              1200,
                              "src/b.cpp",
                              "claim",
                              Value::object({{"step", Value{Number{1}}}}),
                          }),
                          "make ev_b1");

  const std::vector<CausalEvent> pre_events{ev_a1, ev_a2, ev_b1};
  const auto watermarks = compute_actor_watermarks(pre_events);
  const auto frontier = compute_causal_frontier(pre_events);
  check(watermarks.at(alice_id.identity().fingerprint) == 2, "alice watermark != 2");
  check(watermarks.at(bob_id.identity().fingerprint) == 1, "bob watermark != 1");
  check(frontier.size() == 2, "expected 2 frontier leaves (ev_a2, ev_b1)");

  BridgeCheckpointDraft draft{};
  draft.room_id = "room:falcon";
  draft.checkpoint_seq = 7;
  draft.created_ns = 1500;
  draft.actor_watermarks = watermarks;
  draft.causal_frontier_hashes = frontier;
  draft.revoked_grant_ids = {"grant-revoked-2", "grant-revoked-1", "grant-revoked-2"};
  draft.lease_epochs = {{"src/a.cpp", 4}, {"src/b.cpp", 2}};

  const auto checkpoint =
      must(sign_checkpoint(alice_id, std::move(draft)), "sign checkpoint");
  check(checkpoint.signer_fingerprint == alice_id.identity().fingerprint,
        "checkpoint signer mismatch");
  check(checkpoint.revoked_grant_ids.size() == 2 &&
            checkpoint.revoked_grant_ids[0] == "grant-revoked-1" &&
            checkpoint.revoked_grant_ids[1] == "grant-revoked-2",
        "revoked_grant_ids not sorted/deduplicated");

  // Verify canonical payload embeds blackbird.bridge_checkpoint type tag.
  const auto canonical =
      must(canonical_checkpoint_payload(checkpoint), "canonical checkpoint payload");
  check(canonical.find("\"type\":\"blackbird.bridge_checkpoint\"") != std::string::npos,
        "missing blackbird.bridge_checkpoint type tag");

  // Verify valid checkpoint succeeds (both 2-arg and 3-arg PeerIdentityConfig
  // overloads).
  must_void(verify_checkpoint(known, checkpoint), "verify valid checkpoint");
  must_void(verify_checkpoint(known, checkpoint, PeerIdentityConfig{}),
            "verify valid checkpoint with config");

  // Checkpoint anti-rollback, room binding, freshness, and signer authority checks.
  {
    CheckpointVerifyOptions strict_ok{};
    strict_ok.expected_room_id = "room:falcon";
    strict_ok.min_checkpoint_seq = 7;
    strict_ok.max_age_ns = 1000;
    strict_ok.now_ns = 2000; // age = 500 <= 1000
    strict_ok.max_future_skew_ns = 100;
    strict_ok.allowed_signers = {alice_id.identity().fingerprint};
    must_void(verify_checkpoint(known, checkpoint, strict_ok),
              "verify valid checkpoint with strict options");

    // Room mismatch rejected.
    CheckpointVerifyOptions wrong_room = strict_ok;
    wrong_room.expected_room_id = "room:other";
    const auto room_res = verify_checkpoint(known, checkpoint, wrong_room);
    check(!room_res.has_value() && room_res.error().code == ErrorCode::conflict,
          "wrong-room checkpoint accepted");

    // Sequence rollback rejected.
    CheckpointVerifyOptions rollback = strict_ok;
    rollback.min_checkpoint_seq = 8;
    const auto seq_res = verify_checkpoint(known, checkpoint, rollback);
    check(!seq_res.has_value() && seq_res.error().code == ErrorCode::conflict,
          "rolled-back checkpoint_seq accepted");

    // Stale checkpoint rejected.
    CheckpointVerifyOptions stale = strict_ok;
    stale.now_ns = 2501; // age = 1001 > 1000
    const auto stale_res = verify_checkpoint(known, checkpoint, stale);
    check(!stale_res.has_value() && stale_res.error().code == ErrorCode::stale_handle,
          "stale checkpoint accepted");

    // Excessively future-dated checkpoint rejected.
    CheckpointVerifyOptions future_skew = strict_ok;
    future_skew.now_ns = 1000; // created_ns 1500 is 500ns ahead > 100ns skew
    const auto skew_res = verify_checkpoint(known, checkpoint, future_skew);
    check(!skew_res.has_value() && skew_res.error().code == ErrorCode::clock_regressed,
          "future-skewed checkpoint accepted");

    // Unauthorized signer rejected even when cryptographically valid & pinned.
    CheckpointVerifyOptions unauth_signer = strict_ok;
    unauth_signer.allowed_signers = {bob_id.identity().fingerprint};
    const auto auth_res = verify_checkpoint(known, checkpoint, unauth_signer);
    check(!auth_res.has_value() && auth_res.error().code == ErrorCode::invalid_identity,
          "unauthorized checkpoint signer accepted");
  }

  // Round-trip through Value/JSON and re-verify.
  const auto cp_json = must(dump_json(checkpoint_to_value(checkpoint)), "dump cp json");
  const auto cp_val = must(parse_json(cp_json), "parse cp json");
  const auto cp_rt = must(checkpoint_from_value(cp_val), "checkpoint_from_value");
  check(cp_rt == checkpoint, "checkpoint JSON round-trip mismatch");
  must_void(verify_checkpoint(known, cp_rt), "verify round-tripped checkpoint");

  // Tamper tests: mutating lease_epochs, watermarks, or revoked_grant_ids MUST fail.
  {
    BridgeCheckpoint tampered = checkpoint;
    tampered.lease_epochs["src/a.cpp"] = 999;
    check(!verify_checkpoint(known, tampered).has_value(),
          "tampered lease_epochs accepted");

    BridgeCheckpoint tampered_wm = checkpoint;
    tampered_wm.actor_watermarks[alice_id.identity().fingerprint] = 1;
    check(!verify_checkpoint(known, tampered_wm).has_value(),
          "tampered actor_watermarks accepted");

    BridgeCheckpoint tampered_grants = checkpoint;
    tampered_grants.revoked_grant_ids.pop_back();
    check(!verify_checkpoint(known, tampered_grants).has_value(),
          "tampered revoked_grant_ids accepted");

    // Unknown signer rejected.
    const auto bob_cp = must(sign_checkpoint(bob_id,
                                             BridgeCheckpointDraft{
                                                 "room:falcon",
                                                 8,
                                                 1600,
                                                 watermarks,
                                                 frontier,
                                                 {},
                                                 {},
                                             }),
                             "sign bob checkpoint");
    const auto unknown_res = verify_checkpoint(known, bob_cp);
    check(!unknown_res.has_value() &&
              unknown_res.error().code == ErrorCode::invalid_identity,
          "unpinned signer checkpoint accepted");
  }

  // Late-join delta filter: add post-checkpoint events for alice (seq 3), bob (seq 2),
  // and a brand-new actor charlie (seq 1).
  const auto ev_a3 = must(make_causal_event({
                              alice_id.identity().fingerprint,
                              3,
                              {ev_a2.event_hash},
                              2000,
                              "src/a.cpp",
                              "review",
                              Value::object({{"step", Value{Number{3}}}}),
                          }),
                          "make ev_a3");
  const auto ev_b2 = must(make_causal_event({
                              bob_id.identity().fingerprint,
                              2,
                              {ev_b1.event_hash},
                              2100,
                              "src/b.cpp",
                              "done",
                              Value::object({{"step", Value{Number{2}}}}),
                          }),
                          "make ev_b2");
  const auto ev_c1 = must(make_causal_event({
                              charlie_id.identity().fingerprint,
                              1,
                              {ev_a2.event_hash, ev_b1.event_hash},
                              2200,
                              "src/c.cpp",
                              "join",
                              Value::object({{"step", Value{Number{1}}}}),
                          }),
                          "make ev_c1");

  const std::vector<CausalEvent> full_log{ev_a1, ev_a2, ev_b1, ev_a3, ev_b2, ev_c1};
  const auto delta = filter_delta_after_checkpoint(full_log, checkpoint);
  check(delta.size() == 3,
        "delta filter did not return exactly 3 post-watermark events");
  check(delta[0] == ev_a3 && delta[1] == ev_b2 && delta[2] == ev_c1,
        "delta filter returned wrong events");

  // Revoking alice in KnownPeersStore immediately rejects alice's checkpoint.
  (void)must(known.revoke_peer({alice_id.identity().fingerprint, "rotated"}),
             "revoke alice");
  const auto revoked_res = verify_checkpoint(known, checkpoint);
  check(!revoked_res.has_value() && revoked_res.error().code == ErrorCode::conflict,
        "revoked peer checkpoint was accepted");
}

// ---------------------------------------------------------------------------
// 3. Room Invite URI (bbjoin1:...) Tests
// ---------------------------------------------------------------------------

void test_room_invite_uri(const std::filesystem::path &base) {
  g_stage = "room_invite_uri";

  auto alice =
      must(PeerIdentityStore::open_or_create(base / "inv-alice"), "create inv alice");
  auto mallory = must(PeerIdentityStore::open_or_create(base / "inv-mallory"),
                      "create inv mallory");

  const RoomInvite invite{
      "room:apollo-7",
      "wss://relay.blackbird.example:443/v1",
      alice.identity().fingerprint,
      alice.identity().public_key,
      "INV-9988-ALPHA",
      999999999999LL,
  };
  const auto uri = must(encode_room_invite(invite), "encode room invite");
  check(uri.starts_with("bbjoin1:"), "invite URI missing bbjoin1: prefix");
  check(uri.find('=') == std::string::npos, "base64url should not include '=' padding");
  check(uri.find('+') == std::string::npos && uri.find('/') == std::string::npos,
        "base64url contains non-url chars");

  const auto parsed = must(parse_room_invite(uri), "parse room invite");
  check(parsed == invite, "room invite round-trip mismatch");

  // Invite freshness and expiration enforcement.
  check(!parsed.is_expired(invite.expires_ns - 1), "fresh invite marked expired");
  check(parsed.is_expired(invite.expires_ns), "boundary-expired invite marked fresh");
  check(parsed.is_expired(invite.expires_ns + 1), "expired invite marked fresh");
  must_void(validate_room_invite_freshness(parsed, invite.expires_ns - 1),
            "validate fresh invite");
  const auto exp_chk = validate_room_invite_freshness(parsed, invite.expires_ns);
  check(!exp_chk.has_value() && exp_chk.error().code == ErrorCode::stale_handle,
        "expired invite passed freshness check");
  const auto parsed_fresh =
      must(parse_room_invite(uri, invite.expires_ns - 1), "parse fresh invite");
  check(parsed_fresh == invite, "fresh parsed invite mismatch");
  const auto parsed_expired = parse_room_invite(uri, invite.expires_ns);
  check(!parsed_expired.has_value() &&
            parsed_expired.error().code == ErrorCode::stale_handle,
        "parse_room_invite accepted expired invite when now_ns was supplied");
  const auto parsed_bad_now = parse_room_invite(uri, 0);
  check(!parsed_bad_now.has_value() &&
            parsed_bad_now.error().code == ErrorCode::invalid_range,
        "parse_room_invite accepted non-positive now_ns");

  // Mismatched fingerprint vs public key MUST be rejected (MITM pinning defense).
  {
    RoomInvite spoofed = invite;
    spoofed.creator_public_key = mallory.identity().public_key;
    const auto enc_bad = encode_room_invite(spoofed);
    check(!enc_bad.has_value() && enc_bad.error().code == ErrorCode::invalid_identity,
          "encode accepted mismatched fingerprint/public_key");
  }

  // Test parser rejecting manually tampered payload with mismatched fingerprint/key.
  {
    // Swap creator_fingerprint in a JSON payload encoded via RFC 4648 base64url.
    auto b64url = [](std::string_view in) {
      static constexpr std::string_view kAlpha =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      std::string out;
      std::size_t i = 0;
      while (i + 3 <= in.size()) {
        const auto t =
            (static_cast<std::uint32_t>(static_cast<unsigned char>(in[i])) << 16U) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(in[i + 1])) << 8U) |
            static_cast<std::uint32_t>(static_cast<unsigned char>(in[i + 2]));
        out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
        out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
        out.push_back(kAlpha[(t >> 6U) & 0x3fU]);
        out.push_back(kAlpha[t & 0x3fU]);
        i += 3;
      }
      if (in.size() - i == 1) {
        const auto t = static_cast<std::uint32_t>(static_cast<unsigned char>(in[i]))
                       << 16U;
        out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
        out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
      } else if (in.size() - i == 2) {
        const auto t =
            (static_cast<std::uint32_t>(static_cast<unsigned char>(in[i])) << 16U) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(in[i + 1])) << 8U);
        out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
        out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
        out.push_back(kAlpha[(t >> 6U) & 0x3fU]);
      }
      return out;
    };

    const Value mismatch_doc = Value::object({
        {"creator_fingerprint", Value{alice.identity().fingerprint}},
        {"creator_public_key", Value{mallory.identity().public_key}},
        {"expires_ns", Value{Number{invite.expires_ns}}},
        {"invite_code", Value{invite.invite_code}},
        {"relay_url", Value{invite.relay_url}},
        {"room_id", Value{invite.room_id}},
    });
    const std::string mismatch_uri =
        "bbjoin1:" + b64url(must(dump_json(mismatch_doc), "dump mismatch"));
    const auto res = parse_room_invite(mismatch_uri);
    check(!res.has_value() && res.error().code == ErrorCode::invalid_identity,
          "parse_room_invite accepted mismatched key/fingerprint");

    // Smuggled secret field in JSON MUST be rejected.
    const Value smuggled_doc = Value::object({
        {"creator_fingerprint", Value{alice.identity().fingerprint}},
        {"creator_public_key", Value{alice.identity().public_key}},
        {"expires_ns", Value{Number{invite.expires_ns}}},
        {"invite_code", Value{invite.invite_code}},
        {"relay_url", Value{invite.relay_url}},
        {"room_id", Value{invite.room_id}},
        {"room_secret", Value{"super-secret-leak"}},
    });
    const std::string smuggled_uri =
        "bbjoin1:" + b64url(must(dump_json(smuggled_doc), "dump smuggled"));
    check(!parse_room_invite(smuggled_uri).has_value(),
          "parse_room_invite accepted unknown/smuggled field");
  }

  // Reject credential-bearing or insecure relay URLs.
  {
    RoomInvite bad_url = invite;
    bad_url.relay_url = "ws://insecure.example/relay";
    check(!encode_room_invite(bad_url).has_value(), "insecure ws:// accepted");
    bad_url.relay_url = "wss://user:secret@relay.example/v1";
    check(!encode_room_invite(bad_url).has_value(), "userinfo in URL accepted");
    bad_url.relay_url = "wss://relay.example/v1?token=secret";
    check(!encode_room_invite(bad_url).has_value(), "query secret in URL accepted");
  }

  // Reject oversized and malformed URIs.
  check(!parse_room_invite("").has_value(), "empty URI accepted");
  check(!parse_room_invite("bbjoin2:abc").has_value(), "wrong prefix accepted");
  check(!parse_room_invite("bbjoin1:%%%not-base64%%%").has_value(),
        "malformed base64url accepted");
  check(!parse_room_invite("bbjoin1:" + std::string(kRoomInviteMaxUriBytes + 10, 'A'))
             .has_value(),
        "oversized invite URI accepted");
}

// ---------------------------------------------------------------------------
// 4. Content-Blind Relay Router Tests
// ---------------------------------------------------------------------------

void test_blind_relay_router(const std::filesystem::path &base) {
  g_stage = "blind_relay_router";

  auto alice =
      must(PeerIdentityStore::open_or_create(base / "rel-alice"), "create rel alice");
  auto bob =
      must(PeerIdentityStore::open_or_create(base / "rel-bob"), "create rel bob");
  auto spec =
      must(PeerIdentityStore::open_or_create(base / "rel-spec"), "create rel spec");
  auto outsider = must(PeerIdentityStore::open_or_create(base / "rel-outsider"),
                       "create rel outsider");

  BlindRelayConfig cfg{};
  cfg.rate_limit.frames_per_sec = 5.0;
  cfg.rate_limit.burst_frames = 3.0;
  cfg.rate_limit.bytes_per_sec = 1024.0 * 1024.0;
  cfg.rate_limit.burst_bytes = 1024.0 * 1024.0;

  auto router = must(BlindRelayRouter::create(cfg), "create BlindRelayRouter");

  // Register two peers + one read-only spectator in room:ops, plus one peer in
  // room:other.
  const auto s_alice = must(router.register_session({
                                "room:ops",
                                alice.identity().fingerprint,
                                RelayParticipantRole::peer,
                                "192.168.1.10:5000",
                                {},
                            }),
                            "register alice");
  const auto s_bob = must(router.register_session({
                              "room:ops",
                              bob.identity().fingerprint,
                              RelayParticipantRole::peer,
                              "192.168.1.11:5000",
                              {"src/core/*"},
                          }),
                          "register bob");
  const auto s_spec = must(router.register_session({
                               "room:ops",
                               spec.identity().fingerprint,
                               RelayParticipantRole::spectator,
                               "192.168.1.12:5000",
                               {},
                           }),
                           "register spectator");
  const auto s_other = must(router.register_session({
                                "room:other",
                                outsider.identity().fingerprint,
                                RelayParticipantRole::peer,
                                "10.0.0.5:5000",
                                {},
                            }),
                            "register outsider");

  const std::string aad = board_bridge_sha256_hex("room:ops|epoch=1");
  // Arbitrary opaque base64 ciphertext (non-UTF8 binary bytes encoded in base64;
  // relay must NEVER attempt to parse or decrypt it).
  const std::string opaque_ct = "//+A/wABAgMEBQYHCAkKCwwNDg8=";
  const std::string nonce = "QUJDREVGR0hJSktM";

  // 1) Publish matching-scope frame from Alice -> reaches Bob and Spectator, NOT other
  // room.
  const BlindRelayFrame f1{
      "room:ops",
      alice.identity().fingerprint,
      RelayLane::causal,
      "f-1",
      1,
      opaque_ct,
      nonce,
      aad,
      1'000'000'000LL,
      "src/core/mux.cpp",
  };
  const auto pub1 =
      must(router.publish(s_alice.session_id, f1, 1'000'000'000LL), "publish f1");
  check(pub1.relay_seq == 1 && pub1.delivered_sessions == 2 && !pub1.duplicate,
        "f1 delivery count mismatch");

  // Duplicate frame_id is suppressed without re-broadcast.
  const auto pub1_dup =
      must(router.publish(s_alice.session_id, f1, 1'000'000'100LL), "publish dup f1");
  check(pub1_dup.duplicate && pub1_dup.delivered_sessions == 0,
        "duplicate frame was not suppressed");

  // Bob receives byte-identical opaque ciphertext and acks seq 1.
  const auto bob_f1 = must(router.poll_outbound(s_bob.session_id), "bob poll f1");
  check(bob_f1.has_value() && bob_f1->relay_seq == 1 &&
            bob_f1->frame.ciphertext_b64 == opaque_ct,
        "bob did not receive intact opaque ciphertext f1");
  must_void(router.ack_relay_seq(s_bob.session_id, 1), "bob ack 1");

  // Spectator also receives f1; outsider in room:other receives NOTHING.
  const auto spec_f1 = must(router.poll_outbound(s_spec.session_id), "spec poll f1");
  check(spec_f1.has_value() && spec_f1->frame.frame_id == "f-1", "spectator missed f1");
  check(!must(router.poll_outbound(s_other.session_id), "outsider poll").has_value(),
        "room isolation violated");

  // Spectator cannot publish frames.
  const BlindRelayFrame spec_try{
      "room:ops",
      spec.identity().fingerprint,
      RelayLane::causal,
      "f-spec-bad",
      1,
      opaque_ct,
      nonce,
      aad,
      1'000'000'200LL,
      "src/core/mux.cpp",
  };
  const auto spec_pub = router.publish(s_spec.session_id, spec_try, 1'000'000'200LL);
  check(!spec_pub.has_value() && spec_pub.error().code == ErrorCode::conflict,
        "spectator was allowed to publish");

  // 2) Interest filtering: frame in "docs/notes.md" reaches Spectator (wildcard)
  //    but is filtered out for Bob (subscribed to "src/core/*").
  const BlindRelayFrame f2_out_of_scope{
      "room:ops",
      alice.identity().fingerprint,
      RelayLane::causal,
      "f-2-docs",
      1,
      opaque_ct,
      nonce,
      aad,
      1'000'000'300LL,
      "docs/notes.md",
  };
  const auto pub2 =
      must(router.publish(s_alice.session_id, f2_out_of_scope, 1'000'000'300LL),
           "publish f2");
  check(pub2.relay_seq == 2 && pub2.delivered_sessions == 1,
        "interest filtering did not exclude Bob");
  check(!must(router.poll_outbound(s_bob.session_id), "bob poll filtered").has_value(),
        "Bob received out-of-scope frame");
  const auto spec_f2 = must(router.poll_outbound(s_spec.session_id), "spec poll f2");
  check(spec_f2.has_value() && spec_f2->frame.frame_id == "f-2-docs",
        "spectator missed f2");

  // 3) Per-sender token-bucket rate limit enforcement without tearing down other peers.
  // Alice already consumed 3 tokens (f1, dup f1 check, f2) in burst_frames=3.
  // Next immediate publish from Alice at same timestamp MUST be rate-limited (busy).
  const BlindRelayFrame f_rate_limited{
      "room:ops",
      alice.identity().fingerprint,
      RelayLane::causal,
      "f-3-rl",
      1,
      opaque_ct,
      nonce,
      aad,
      1'000'000'400LL,
      "src/core/mux.cpp",
  };
  const auto rl_res =
      router.publish(s_alice.session_id, f_rate_limited, 1'000'000'400LL);
  check(!rl_res.has_value() && rl_res.error().code == ErrorCode::busy,
        "Alice burst was not rate-limited");
  check(router.stats().rate_limited_frames == 1, "rate_limited_frames stat mismatch");

  // Meanwhile Bob's independent bucket is completely unaffected, AND Bob can reuse
  // frame_id "f-1" without Alice pre-squatting Bob's frame_id namespace!
  const BlindRelayFrame f_bob_ok{
      "room:ops",
      bob.identity().fingerprint,
      RelayLane::causal,
      "f-1",
      1,
      opaque_ct,
      nonce,
      aad,
      1'000'000'500LL,
      "src/core/mux.cpp",
  };
  const auto bob_pub = must(router.publish(s_bob.session_id, f_bob_ok, 1'000'000'500LL),
                            "bob publish ok");
  check(bob_pub.relay_seq == 3 && bob_pub.delivered_sessions == 2 && !bob_pub.duplicate,
        "Bob was affected by Alice rate limit or frame_id pre-squatting");
  const auto alice_got_bob =
      must(router.poll_outbound(s_alice.session_id), "alice poll bob frame");
  check(alice_got_bob.has_value() && alice_got_bob->frame.frame_id == "f-1" &&
            alice_got_bob->frame.sender_fingerprint == bob.identity().fingerprint,
        "Alice did not receive Bob frame with independent frame_id");

  // 4) Per-lane size cap rejection (control > 16 KiB and presence > 4 KiB).
  const BlindRelayFrame oversized_ctrl{
      "room:ops",
      alice.identity().fingerprint,
      RelayLane::control,
      "f-ctrl-huge",
      1,
      std::string(kRelayControlMaxBytes + 4, 'A'),
      nonce,
      aad,
      3'000'000'000LL,
      {},
  };
  const auto ctrl_bad =
      router.publish(s_alice.session_id, oversized_ctrl, 3'000'000'000LL);
  check(!ctrl_bad.has_value() && ctrl_bad.error().code == ErrorCode::capacity,
        "oversized control frame was not rejected");

  const BlindRelayFrame oversized_pres{
      "room:ops",
      alice.identity().fingerprint,
      RelayLane::presence,
      "f-pres-huge",
      1,
      std::string(kRelayPresenceMaxBytes + 4, 'A'),
      nonce,
      aad,
      3'000'000'100LL,
      "src/core/mux.cpp",
  };
  const auto pres_bad =
      router.publish(s_alice.session_id, oversized_pres, 3'000'000'100LL);
  check(!pres_bad.has_value() && pres_bad.error().code == ErrorCode::capacity,
        "oversized presence frame was not rejected");
  check(router.stats().rejected_oversize_frames == 2, "oversize stat mismatch");

  // 5) Wi-Fi roam disconnect -> missed frames -> reconnect from new IP with delta
  // resume.
  must_void(router.disconnect_session(s_bob.session_id), "disconnect bob");

  // While Bob is offline on Wi-Fi drop, Alice sends:
  // - causal f-4 in Bob's scope (relay_seq 4)
  // - ephemeral presence heartbeat (NOT replayed on resume!)
  // - control recall f-5 (relay_seq 5, preempts causal on resume!)
  const auto pub4 = must(router.publish(s_alice.session_id,
                                        BlindRelayFrame{
                                            "room:ops",
                                            alice.identity().fingerprint,
                                            RelayLane::causal,
                                            "f-4-missed",
                                            1,
                                            opaque_ct,
                                            nonce,
                                            aad,
                                            5'000'000'000LL,
                                            "src/core/net.cpp",
                                        },
                                        5'000'000'000LL),
                         "publish missed causal");
  check(pub4.relay_seq == 4, "expected relay_seq 4");

  (void)must(router.publish(s_alice.session_id,
                            BlindRelayFrame{
                                "room:ops",
                                alice.identity().fingerprint,
                                RelayLane::presence,
                                "f-pres-offline",
                                1,
                                opaque_ct,
                                nonce,
                                aad,
                                5'100'000'000LL,
                                "src/core/net.cpp",
                            },
                            5'100'000'000LL),
             "publish offline presence");

  const auto pub5 = must(router.publish(s_alice.session_id,
                                        BlindRelayFrame{
                                            "room:ops",
                                            alice.identity().fingerprint,
                                            RelayLane::control,
                                            "f-5-recall",
                                            2,
                                            opaque_ct,
                                            nonce,
                                            aad,
                                            5'200'000'000LL,
                                            {},
                                        },
                                        5'200'000'000LL),
                         "publish missed control");
  check(pub5.relay_seq == 5, "expected relay_seq 5");

  // Hijack attempt with wrong fingerprint MUST fail.
  const auto hijack = router.resume_session({
      s_bob.session_id,
      outsider.identity().fingerprint,
      "203.0.113.99:4444",
      1,
      s_bob.resume_token,
      "room:ops",
  });
  check(!hijack.has_value() && hijack.error().code == ErrorCode::invalid_identity,
        "session resume allowed wrong peer fingerprint");

  // Bob roams to LTE IP and resumes from last_acked_relay_seq = 1.
  const auto resumed = must(router.resume_session({
                                s_bob.session_id,
                                bob.identity().fingerprint,
                                "100.64.9.42:61234",
                                1,
                                s_bob.resume_token,
                                "room:ops",
                            }),
                            "bob roam resume");
  check(resumed.session.connected, "resumed session not connected");
  check(resumed.session.remote_endpoint == "100.64.9.42:61234", "endpoint not updated");
  check(resumed.session.connection_id != s_bob.connection_id,
        "connection_id did not rotate on roam");
  check(resumed.session.resume_token != s_bob.resume_token,
        "resume_token did not rotate on roam");
  check(resumed.session.roam_count == 1, "roam_count != 1");
  // Missed relevant reliable frames after seq 1: f-4-missed (seq 4) and f-5-recall (seq
  // 5). (f-1 was acked, f-2 was out of scope, f-bob-1 was Bob's own, f-pres-offline was
  // Lane 2).
  check(resumed.replayed_frames == 2 && !resumed.history_truncated,
        "unexpected delta replay count on roam");

  // Lane 0 recall (f-5-recall) preempts Lane 1 causal (f-4-missed) on drain!
  const auto r1 = must(router.poll_outbound(s_bob.session_id), "bob poll roam 1");
  const auto r2 = must(router.poll_outbound(s_bob.session_id), "bob poll roam 2");
  const auto r3 = must(router.poll_outbound(s_bob.session_id), "bob poll roam 3");
  check(r1.has_value() && r1->frame.frame_id == "f-5-recall" && r1->relay_seq == 5,
        "roam drain did not prioritize Lane 0 recall");
  check(r2.has_value() && r2->frame.frame_id == "f-4-missed" && r2->relay_seq == 4,
        "roam drain did not deliver missed causal frame");
  check(!r3.has_value(), "unexpected extra/stale frame replayed on roam");
}

bool is_random_hex_token(std::string_view token, std::string_view prefix) {
  if (!token.starts_with(prefix))
    return false;
  const std::string_view hex = token.substr(prefix.size());
  if (hex.size() != 32)
    return false;
  for (const char ch : hex) {
    const bool ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    if (!ok)
      return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// 4b. Wave 5 Opus Hardening Regression Tests (Atomic Rollback, Zero Loss,
//     Auth/Anti-Takeover, Zero-Copy Shared Storage, Byte Cap, Session Reaping)
// ---------------------------------------------------------------------------

void test_relay_atomic_resume_rollback(const std::filesystem::path &base) {
  g_stage = "relay_atomic_resume_rollback";

  auto alice = must(PeerIdentityStore::open_or_create(base / "rb-alice"), "rb alice");
  auto bob = must(PeerIdentityStore::open_or_create(base / "rb-bob"), "rb bob");

  BlindRelayConfig cfg{};
  cfg.session_mux.max_causal_queue = 2;
  cfg.session_mux.max_control_queue = 2;
  cfg.max_room_history = 16;
  cfg.rate_limit.frames_per_sec = 1000.0;
  cfg.rate_limit.burst_frames = 100.0;

  auto router = must(BlindRelayRouter::create(cfg), "create rollback router");
  const auto s_alice = must(router.register_session({
                                "room:rb",
                                alice.identity().fingerprint,
                                RelayParticipantRole::peer,
                                "10.0.0.1:5000",
                                {},
                            }),
                            "reg rb alice");
  const auto s_bob = must(router.register_session({
                              "room:rb",
                              bob.identity().fingerprint,
                              RelayParticipantRole::peer,
                              "10.0.0.2:5000",
                              {},
                          }),
                          "reg rb bob");

  const std::string aad = board_bridge_sha256_hex("room:rb|epoch=1");
  const std::string ct = "YWJjZGVmZ2g=";
  const std::string nonce = "QUJDREVGR0hJSktM";

  // Put 1 frame into Bob's queue while connected, then disconnect Bob so Bob
  // retains his pre-existing pending state before an overflowing resume.
  (void)must(router.publish(s_alice.session_id,
                            BlindRelayFrame{
                                "room:rb",
                                alice.identity().fingerprint,
                                RelayLane::causal,
                                "rb-1",
                                1,
                                ct,
                                nonce,
                                aad,
                                1'000'000'000LL,
                                {},
                            },
                            1'000'000'000LL),
             "publish rb-1");
  must_void(router.disconnect_session(s_bob.session_id, 1'500'000'000LL),
            "disconnect rb bob");

  // Alice publishes 3 more frames (total 4 reliable frames > max_causal_queue = 2).
  for (int i = 2; i <= 4; ++i) {
    (void)must(
        router.publish(s_alice.session_id,
                       BlindRelayFrame{
                           "room:rb",
                           alice.identity().fingerprint,
                           RelayLane::causal,
                           "rb-" + std::to_string(i),
                           1,
                           ct,
                           nonce,
                           aad,
                           static_cast<std::int64_t>(2'000'000'000LL + i * 1000LL),
                           {},
                       },
                       static_cast<std::int64_t>(2'000'000'000LL + i * 1000LL)),
        "publish rb frame");
  }

  const auto before_info = must(router.session_info(s_bob.session_id), "before info");
  check(!before_info.connected, "bob should be disconnected before failed resume");

  // Resume from seq 0 requires replaying 4 causal frames into a 2-slot queue -> MUST
  // fail with capacity AND leave Bob's session state completely untouched!
  const auto failed_resume = router.resume_session({
      s_bob.session_id,
      bob.identity().fingerprint,
      "10.9.9.9:9999",
      0,
      s_bob.resume_token,
      "room:rb",
  });
  check(!failed_resume.has_value() && failed_resume.error().code == ErrorCode::capacity,
        "overflowing resume did not fail with capacity");

  const auto after_info = must(router.session_info(s_bob.session_id), "after info");
  check(after_info == before_info,
        "failed resume mutated session handle (not atomic rollback)");
  check(!after_info.connected, "failed resume left session connected");
  check(after_info.connection_id == s_bob.connection_id,
        "failed resume rotated connection_id");
  check(after_info.resume_token == s_bob.resume_token,
        "failed resume rotated resume_token");
  check(after_info.remote_endpoint == "10.0.0.2:5000",
        "failed resume mutated remote_endpoint");
  check(after_info.roam_count == 0 && router.stats().session_roams == 0,
        "failed resume incremented roam counters");

  // Also test atomic rollback while connected with an existing queued frame.
  const auto ok_resume = must(router.resume_session({
                                  s_bob.session_id,
                                  bob.identity().fingerprint,
                                  "10.0.0.20:5000",
                                  2, // replays frames 3 and 4 (fits in 2-slot queue)
                                  s_bob.resume_token,
                                  "room:rb",
                              }),
                              "valid resume after rollback");
  check(ok_resume.replayed_frames == 2, "expected 2 replayed frames");
  const auto connected_before =
      must(router.session_info(s_bob.session_id), "connected before");
  const auto second_fail = router.resume_session({
      s_bob.session_id,
      bob.identity().fingerprint,
      "10.8.8.8:8888",
      0,
      ok_resume.session.resume_token,
      "room:rb",
  });
  check(!second_fail.has_value() && second_fail.error().code == ErrorCode::capacity,
        "second overflowing resume did not fail");
  check(must(router.session_info(s_bob.session_id), "connected after") ==
            connected_before,
        "failed resume while connected mutated session");
  // Existing queued frames 3 and 4 must still be intact and pollable!
  const auto p3 = must(router.poll_outbound(s_bob.session_id), "poll intact 3");
  const auto p4 = must(router.poll_outbound(s_bob.session_id), "poll intact 4");
  check(p3.has_value() && p3->relay_seq == 3 && p4.has_value() && p4->relay_seq == 4,
        "failed resume wiped pre-existing pending frames");
}

void test_relay_zero_silent_frame_loss(const std::filesystem::path &base) {
  g_stage = "relay_zero_silent_frame_loss";

  auto alice = must(PeerIdentityStore::open_or_create(base / "zfl-alice"), "zfl alice");
  auto bob = must(PeerIdentityStore::open_or_create(base / "zfl-bob"), "zfl bob");
  auto charlie =
      must(PeerIdentityStore::open_or_create(base / "zfl-charlie"), "zfl charlie");

  BlindRelayConfig cfg{};
  cfg.session_mux.max_causal_queue = 2;
  cfg.session_mux.max_control_queue = 2;
  cfg.max_room_history = 32;
  cfg.rate_limit.frames_per_sec = 1000.0;
  cfg.rate_limit.burst_frames = 100.0;

  auto router = must(BlindRelayRouter::create(cfg), "create zfl router");
  const auto s_alice = must(router.register_session({
                                "room:zfl",
                                alice.identity().fingerprint,
                                RelayParticipantRole::peer,
                                "10.0.1.1:5000",
                                {},
                            }),
                            "reg zfl alice");
  const auto s_bob = must(router.register_session({
                              "room:zfl",
                              bob.identity().fingerprint,
                              RelayParticipantRole::peer,
                              "10.0.1.2:5000",
                              {},
                          }),
                          "reg zfl bob");
  const auto s_charlie = must(router.register_session({
                                  "room:zfl",
                                  charlie.identity().fingerprint,
                                  RelayParticipantRole::peer,
                                  "10.0.1.3:5000",
                                  {},
                              }),
                              "reg zfl charlie");

  const std::string aad = board_bridge_sha256_hex("room:zfl|epoch=1");
  const std::string ct = "YWJjZGVmZ2g=";
  const std::string nonce = "QUJDREVGR0hJSktM";

  auto send_frame = [&](int idx, RelayLane lane) {
    return must(
        router.publish(s_alice.session_id,
                       BlindRelayFrame{
                           "room:zfl",
                           alice.identity().fingerprint,
                           lane,
                           "zfl-" + std::to_string(idx),
                           1,
                           ct,
                           nonce,
                           aad,
                           static_cast<std::int64_t>(1'000'000'000LL + idx * 100LL),
                           {},
                       },
                       static_cast<std::int64_t>(1'000'000'000LL + idx * 100LL)),
        "publish zfl frame");
  };

  // Frames 1..4 fill and drain cleanly for Charlie; for Bob, frames 1..2 fill his
  // 2-slot causal queue, then frame 3 overflows.
  const auto r1 = send_frame(1, RelayLane::causal);
  const auto r2 = send_frame(2, RelayLane::causal);
  check(r1.relay_seq == 1 && r2.relay_seq == 2 && r2.overflowed_sessions == 0,
        "frames 1-2 should enqueue cleanly");

  // Charlie drains frames 1 and 2 so Charlie never overflows.
  check(must(router.poll_outbound(s_charlie.session_id), "c poll 1").has_value(),
        "charlie missed 1");
  check(must(router.poll_outbound(s_charlie.session_id), "c poll 2").has_value(),
        "charlie missed 2");

  // Frame 3 overflows Bob's full causal queue (Opus #3: frame 5 scenario).
  const auto r3 = send_frame(3, RelayLane::causal);
  check(r3.relay_seq == 3 && r3.delivered_sessions == 1 && r3.overflowed_sessions == 1,
        "frame 3 should deliver to Charlie and latch overflow on Bob");
  check(must(router.session_info(s_bob.session_id), "bob overflow info").needs_resync,
        "bob needs_resync flag not set on reliable overflow");
  check(router.stats().reliable_overflow_events == 1,
        "reliable_overflow_events mismatch");

  // Bob polls frame 1, freeing a slot in his causal queue!
  const auto b1 = must(router.poll_outbound(s_bob.session_id), "bob poll 1");
  check(b1.has_value() && b1->relay_seq == 1, "bob poll 1 mismatch");

  // Frame 4 (causal) and Frame 5 (control) arrive after Bob freed a slot!
  // Neither may be enqueued for Bob while needs_resync is latched (prevents skipping
  // 3).
  const auto r4 = send_frame(4, RelayLane::causal);
  const auto r5 = send_frame(5, RelayLane::control);
  check(r4.overflowed_sessions == 1 && r5.overflowed_sessions == 1,
        "post-overflow reliable frames were enqueued past gap");

  // Attempting to ack seq 2 BEFORE polling frame 2 must fail (unpolled reliable frame).
  const auto ack2_early = router.ack_relay_seq(s_bob.session_id, 2);
  check(!ack2_early.has_value() && ack2_early.error().code == ErrorCode::conflict,
        "ack_relay_seq allowed skipping unpolled frame 2");
  must_void(router.ack_relay_seq(s_bob.session_id, 1), "bob ack 1");

  // Bob polls frame 2; queue is now empty (frames 4 & 5 were NOT enqueued past gap 3).
  const auto b2 = must(router.poll_outbound(s_bob.session_id), "bob poll 2");
  check(b2.has_value() && b2->relay_seq == 2, "bob poll 2 mismatch");
  check(!must(router.poll_outbound(s_bob.session_id), "bob poll gap").has_value(),
        "bob received frame 4 or 5 past dropped frame 3");

  must_void(router.ack_relay_seq(s_bob.session_id, 2), "bob ack 2");

  // Attempting to ack seq 3, 4, or 5 MUST fail (zero silent frame loss).
  for (std::uint64_t bad_seq : {3ULL, 4ULL, 5ULL}) {
    const auto bad_ack = router.ack_relay_seq(s_bob.session_id, bad_seq);
    check(!bad_ack.has_value() && bad_ack.error().code == ErrorCode::conflict,
          "ack_relay_seq advanced past dropped reliable frame");
  }
  check(
      must(router.session_info(s_bob.session_id), "bob ack seq").last_acked_relay_seq ==
          2,
      "bob last_acked_relay_seq advanced past 2");

  // Bob resyncs via resume_session from last_acked_relay_seq = 2 and receives
  // ALL three missed frames (3, 4, 5) with zero loss!
  const auto resync = must(router.resume_session({
                               s_bob.session_id,
                               bob.identity().fingerprint,
                               "10.0.1.2:5001",
                               2,
                               s_bob.resume_token,
                               "room:zfl",
                           }),
                           "bob resync resume");
  check(!resync.session.needs_resync && resync.replayed_frames == 3 &&
            !resync.history_truncated,
        "bob resync did not cleanly replay frames 3, 4, 5");

  // Control frame 5 preempts causal frames 3 and 4; cumulative ACK 5 MUST fail
  // until 3 and 4 are also polled!
  const auto p5 = must(router.poll_outbound(s_bob.session_id), "bob poll resync 5");
  check(p5.has_value() && p5->relay_seq == 5, "control frame 5 did not preempt");
  const auto ack5_premature = router.ack_relay_seq(s_bob.session_id, 5);
  check(!ack5_premature.has_value() &&
            ack5_premature.error().code == ErrorCode::conflict,
        "ack_relay_seq(5) succeeded while causal frames 3 & 4 were still unpolled");

  const auto p3 = must(router.poll_outbound(s_bob.session_id), "bob poll resync 3");
  const auto p4 = must(router.poll_outbound(s_bob.session_id), "bob poll resync 4");
  check(p3.has_value() && p3->relay_seq == 3 && p4.has_value() && p4->relay_seq == 4,
        "resync lost frame 3 or 4");
  must_void(router.ack_relay_seq(s_bob.session_id, 5), "bob ack 5 after full drain");
}

void test_relay_auth_and_unpredictable_tokens(const std::filesystem::path &base) {
  g_stage = "relay_auth_and_unpredictable_tokens";

  auto alice =
      must(PeerIdentityStore::open_or_create(base / "auth-alice"), "auth alice");
  auto bob = must(PeerIdentityStore::open_or_create(base / "auth-bob"), "auth bob");
  auto mallory =
      must(PeerIdentityStore::open_or_create(base / "auth-mallory"), "auth mallory");

  auto router =
      must(BlindRelayRouter::create(BlindRelayConfig{}), "create auth router");
  const auto s_alice = must(router.register_session({
                                "room:auth",
                                alice.identity().fingerprint,
                                RelayParticipantRole::peer,
                                "10.0.2.1:5000",
                                {},
                            }),
                            "reg auth alice");
  const auto s_bob = must(router.register_session({
                              "room:auth",
                              bob.identity().fingerprint,
                              RelayParticipantRole::peer,
                              "10.0.2.2:5000",
                              {},
                          }),
                          "reg auth bob");
  const auto s_mallory = must(router.register_session({
                                  "room:other",
                                  mallory.identity().fingerprint,
                                  RelayParticipantRole::peer,
                                  "10.0.2.3:5000",
                                  {},
                              }),
                              "reg auth mallory");

  // 128-bit random hex tokens (NEVER predictable sequential sess-1 / conn-1).
  check(is_random_hex_token(s_alice.session_id, "sess-"),
        "alice session_id is not 128-bit random hex");
  check(is_random_hex_token(s_alice.connection_id, "conn-"),
        "alice connection_id is not 128-bit random hex");
  check(is_random_hex_token(s_alice.resume_token, "rtok-"),
        "alice resume_token is not 128-bit random hex");
  check(is_random_hex_token(s_bob.session_id, "sess-"),
        "bob session_id is not 128-bit random hex");
  check(s_alice.session_id != s_bob.session_id &&
            s_alice.resume_token != s_bob.resume_token &&
            s_alice.connection_id != s_bob.connection_id,
        "random session tokens collided");

  const std::string aad = board_bridge_sha256_hex("room:auth|epoch=1");
  const BlindRelayFrame alice_frame{
      "room:auth",
      alice.identity().fingerprint,
      RelayLane::causal,
      "auth-f1",
      1,
      "YWJjZGVmZ2g=",
      "QUJDREVGR0hJSktM",
      aad,
      1'000'000'000LL,
      {},
  };

  // Spoof attempt 1: unknown/guessed sequential session_id.
  const auto pub_unknown = router.publish("sess-1", alice_frame, 1'000'000'000LL);
  check(!pub_unknown.has_value() &&
            pub_unknown.error().code == ErrorCode::invalid_identity,
        "publish accepted unknown session_id");

  // Spoof attempt 2: Bob uses his own valid session_id to spoof Alice's fingerprint.
  const auto pub_spoof = router.publish(s_bob.session_id, alice_frame, 1'000'000'000LL);
  check(!pub_spoof.has_value() && pub_spoof.error().code == ErrorCode::invalid_identity,
        "publish allowed Bob's session to spoof Alice's sender_fingerprint");

  // Spoof attempt 3: Mallory uses session in room:other to publish into room:auth.
  BlindRelayFrame cross_room = alice_frame;
  cross_room.sender_fingerprint = mallory.identity().fingerprint;
  const auto pub_xroom =
      router.publish(s_mallory.session_id, cross_room, 1'000'000'000LL);
  check(!pub_xroom.has_value() && pub_xroom.error().code == ErrorCode::invalid_identity,
        "publish allowed cross-room session injection");

  // Spoof attempt 4: Disconnected session cannot publish.
  must_void(router.disconnect_session(s_alice.session_id, 1'000'000'000LL),
            "disconnect auth alice");
  const auto pub_disc =
      router.publish(s_alice.session_id, alice_frame, 1'000'000'100LL);
  check(!pub_disc.has_value() && pub_disc.error().code == ErrorCode::stale_handle,
        "disconnected session was allowed to publish");

  // Resume hijack attempt 1: attacker knows session_id + public fingerprint but NOT
  // resume_token.
  const auto hijack_no_tok = router.resume_session({
      s_alice.session_id,
      alice.identity().fingerprint,
      "203.0.113.55:4444",
      0,
      "",
      "room:auth",
  });
  check(!hijack_no_tok.has_value() &&
            hijack_no_tok.error().code == ErrorCode::invalid_identity,
        "resume succeeded without resume_token");

  const auto hijack_wrong_tok = router.resume_session({
      s_alice.session_id,
      alice.identity().fingerprint,
      "203.0.113.55:4444",
      0,
      s_bob.resume_token,
      "room:auth",
  });
  check(!hijack_wrong_tok.has_value() &&
            hijack_wrong_tok.error().code == ErrorCode::invalid_identity,
        "resume succeeded with wrong resume_token");

  // Resume hijack attempt 2: wrong room_id rejected even with valid token.
  const auto hijack_wrong_room = router.resume_session({
      s_alice.session_id,
      alice.identity().fingerprint,
      "10.0.2.1:5001",
      0,
      s_alice.resume_token,
      "room:other",
  });
  check(!hijack_wrong_room.has_value() &&
            hijack_wrong_room.error().code == ErrorCode::invalid_identity,
        "resume succeeded with wrong room_id");

  // Legitimate resume succeeds and rotates resume_token; replaying old token fails!
  const auto resumed = must(router.resume_session({
                                s_alice.session_id,
                                alice.identity().fingerprint,
                                "10.0.2.1:5001",
                                0,
                                s_alice.resume_token,
                                "room:auth",
                            }),
                            "legit auth resume");
  check(is_random_hex_token(resumed.session.resume_token, "rtok-") &&
            resumed.session.resume_token != s_alice.resume_token,
        "resume_token did not rotate to new 128-bit random token");

  const auto replay_old_tok = router.resume_session({
      s_alice.session_id,
      alice.identity().fingerprint,
      "203.0.113.55:4444",
      0,
      s_alice.resume_token,
      "room:auth",
  });
  check(!replay_old_tok.has_value() &&
            replay_old_tok.error().code == ErrorCode::invalid_identity,
        "replaying rotated-out resume_token succeeded");
}

void test_relay_memory_and_session_bounds(const std::filesystem::path &base) {
  g_stage = "relay_memory_and_session_bounds";

  auto alice = must(PeerIdentityStore::open_or_create(base / "mem-alice"), "mem alice");
  auto bob = must(PeerIdentityStore::open_or_create(base / "mem-bob"), "mem bob");
  auto charlie =
      must(PeerIdentityStore::open_or_create(base / "mem-charlie"), "mem charlie");

  // 1) shared_ptr zero-copy + byte-bounded history eviction.
  {
    BlindRelayConfig cfg{};
    cfg.max_room_history = 100;
    cfg.max_room_history_bytes = 2200; // Fits at most ~2 frames of ~900 bytes each.
    cfg.rate_limit.frames_per_sec = 1000.0;
    cfg.rate_limit.burst_frames = 100.0;

    auto router = must(BlindRelayRouter::create(cfg), "create mem router");
    const auto s_alice = must(router.register_session({
                                  "room:mem",
                                  alice.identity().fingerprint,
                                  RelayParticipantRole::peer,
                                  "10.0.3.1:5000",
                                  {},
                              }),
                              "reg mem alice");
    const auto s_bob = must(router.register_session({
                                "room:mem",
                                bob.identity().fingerprint,
                                RelayParticipantRole::peer,
                                "10.0.3.2:5000",
                                {},
                            }),
                            "reg mem bob");
    const auto s_charlie = must(router.register_session({
                                    "room:mem",
                                    charlie.identity().fingerprint,
                                    RelayParticipantRole::peer,
                                    "10.0.3.3:5000",
                                    {},
                                }),
                                "reg mem charlie");

    const std::string aad = board_bridge_sha256_hex("room:mem|epoch=1");
    const std::string payload_512(512, 'A');
    const std::string nonce = "QUJDREVGR0hJSktM";

    (void)must(router.publish(s_alice.session_id,
                              BlindRelayFrame{
                                  "room:mem",
                                  alice.identity().fingerprint,
                                  RelayLane::causal,
                                  "mem-1",
                                  1,
                                  payload_512,
                                  nonce,
                                  aad,
                                  1'000'000'000LL,
                                  {},
                              },
                              1'000'000'000LL),
               "publish mem-1");

    // Zero-copy verification: Bob and Charlie receive pointers to the EXACT same
    // immutable RoutedRelayFrame object shared with room history!
    const auto bob_shared =
        must(router.poll_outbound_shared(s_bob.session_id), "bob poll shared");
    const auto charlie_shared =
        must(router.poll_outbound_shared(s_charlie.session_id), "charlie poll shared");
    check(bob_shared.has_value() && charlie_shared.has_value(),
          "missing shared frame for recipients");
    check(bob_shared.has_value() && charlie_shared.has_value() &&
              bob_shared->get() == charlie_shared->get(),
          "ciphertext was duplicated instead of shared via shared_ptr");
    check(bob_shared.has_value() && bob_shared->use_count() >= 3,
          "expected shared_ptr shared across bob, charlie, and room history");

    // Publish 4 more 512-byte frames -> byte cap (2200) must evict oldest frames even
    // though max_room_history frame count is 100!
    for (int i = 2; i <= 5; ++i) {
      (void)must(
          router.publish(s_alice.session_id,
                         BlindRelayFrame{
                             "room:mem",
                             alice.identity().fingerprint,
                             RelayLane::causal,
                             "mem-" + std::to_string(i),
                             1,
                             payload_512,
                             nonce,
                             aad,
                             static_cast<std::int64_t>(1'000'000'000LL + i * 100LL),
                             {},
                         },
                         static_cast<std::int64_t>(1'000'000'000LL + i * 100LL)),
          "publish mem frame");
    }
    const auto st = router.stats();
    check(st.retained_history_bytes <= cfg.max_room_history_bytes,
          "room reliable history exceeded max_room_history_bytes");
    check(st.retained_history_frames < 5 && st.retained_history_frames >= 1,
          "byte cap did not evict oldest frames");

    // Resuming from seq 0 must flag history_truncated because seq 1 was byte-evicted.
    const auto resumed = must(router.resume_session({
                                  s_bob.session_id,
                                  bob.identity().fingerprint,
                                  "10.0.3.2:5001",
                                  0,
                                  s_bob.resume_token,
                                  "room:mem",
                              }),
                              "resume after byte eviction");
    check(resumed.history_truncated,
          "resume did not report history_truncated after byte-cap eviction");
    check(resumed.replayed_frames == st.retained_history_frames,
          "replayed frame count did not match retained byte-bounded history");
  }

  // 2) Stale disconnected session reaping & automatic eviction under room session cap.
  {
    BlindRelayConfig cfg{};
    cfg.max_sessions_per_room = 2;
    cfg.disconnected_session_ttl_ns = 1'000'000'000LL; // 1s TTL

    auto router = must(BlindRelayRouter::create(cfg), "create cap router");
    const auto s1 = must(router.register_session({
                             "room:cap",
                             alice.identity().fingerprint,
                             RelayParticipantRole::peer,
                             "10.0.4.1:5000",
                             {},
                         }),
                         "reg s1");
    const auto s2 = must(router.register_session({
                             "room:cap",
                             bob.identity().fingerprint,
                             RelayParticipantRole::peer,
                             "10.0.4.2:5000",
                             {},
                         }),
                         "reg s2");

    // Both connected -> 3rd session MUST be rejected with capacity.
    const auto full_rej = router.register_session({
        "room:cap",
        charlie.identity().fingerprint,
        RelayParticipantRole::peer,
        "10.0.4.3:5000",
        {},
    });
    check(!full_rej.has_value() && full_rej.error().code == ErrorCode::capacity,
          "room exceeded max_sessions_per_room while all sessions connected");

    // Disconnect s1 (older) then s2 (newer).
    must_void(router.disconnect_session(s1.session_id, 1'000'000'000LL), "disc s1");
    must_void(router.disconnect_session(s2.session_id, 2'000'000'000LL), "disc s2");

    // Registering s3 must automatically evict oldest disconnected session (s1),
    // preventing dead sessions from permanently DoS'ing the room cap!
    const auto s3 = must(router.register_session({
                             "room:cap",
                             charlie.identity().fingerprint,
                             RelayParticipantRole::peer,
                             "10.0.4.3:5000",
                             {},
                         }),
                         "reg s3 after evicting s1");
    check(!router.session_info(s1.session_id).has_value(),
          "oldest disconnected session s1 was not evicted");
    check(router.session_info(s2.session_id).has_value(),
          "newer disconnected session s2 should still exist");
    check(router.stats().evicted_sessions == 1, "evicted_sessions != 1");

    // Explicit evict_disconnected_before reaps s2 (disconnected at 2s) while keeping
    // connected s3 alive.
    check(router.evict_disconnected_before(1'500'000'000LL) == 0,
          "evicted session disconnected after cutoff");
    check(router.evict_disconnected_before(2'500'000'000LL) == 1,
          "failed to evict stale disconnected session s2");
    check(!router.session_info(s2.session_id).has_value(),
          "s2 still present after evict_disconnected_before");
    check(router.session_info(s3.session_id).has_value(),
          "connected s3 was wrongly evicted");

    // TTL reaping via evict_stale_sessions cleans up disconnected s3 and empty room.
    must_void(router.disconnect_session(s3.session_id, 3'000'000'000LL), "disc s3");
    check(router.evict_stale_sessions(3'500'000'000LL) == 0,
          "evicted s3 before TTL elapsed");
    check(router.evict_stale_sessions(4'100'000'000LL) == 1,
          "did not evict s3 after TTL elapsed");
    check(router.stats().registered_sessions == 0 && router.stats().active_rooms == 0,
          "empty room/sessions not cleaned up after reaping");
  }
}

// ---------------------------------------------------------------------------
// 5. Transitive Multi-Hop PeerProvenance Taint Propagation Tests
// ---------------------------------------------------------------------------

void test_transitive_taint_propagation(const std::filesystem::path &base) {
  g_stage = "transitive_taint_propagation";

  auto origin =
      must(PeerIdentityStore::open_or_create(base / "taint-origin"), "create origin");
  const std::string fp_a = origin.identity().fingerprint;

  // Root provenance with upstream untrusted web source.
  const TaintedProvenance hop0{
      fp_a, {fp_a}, {"web:https://untrusted.example/spec"}, 0,
      3, // Small max_hops=3 to test 3 valid hops + 4th-hop overflow cleanly.
  };
  must_void(validate_tainted_provenance(hop0), "validate hop0");
  check(is_provenance_tainted(hop0), "hop0 should be tainted");

  // Hop 1: peer-b adds a local untrusted fixture.
  const auto hop1 =
      must(propagate_taint(hop0, "peer-b", {"file:third_party/readme.md"}), "hop1");
  check(hop1.hop_count == 1 && hop1.hop_chain.size() == 2 &&
            hop1.hop_chain[0] == fp_a && hop1.hop_chain[1] == "peer-b",
        "hop1 chain/count mismatch");
  check(hop1.untrusted_sources.size() == 2, "hop1 did not union untrusted sources");

  // Hop 2: peer-c adds NO new untrusted sources -> upstream taint MUST remain intact!
  const auto hop2 = must(propagate_taint(hop1, "peer-c", {}), "hop2");
  check(hop2.hop_count == 2 && hop2.untrusted_sources == hop1.untrusted_sources,
        "hop2 lost upstream taint");

  // Hop 3: peer-d adds an issue comment source -> all 3 sources preserved.
  const auto hop3 = must(propagate_taint(hop2, "peer-d", {"issue:ext-42"}), "hop3");
  check(hop3.hop_count == 3 && hop3.hop_chain.size() == 4, "hop3 chain/count mismatch");
  check(hop3.untrusted_sources.size() == 3, "hop3 missing upstream sources");
  check(std::ranges::contains(hop3.untrusted_sources,
                              std::string{"web:https://untrusted.example/spec"}),
        "hop3 stripped origin untrusted source");
  must_void(verify_taint_monotonicity({hop0, hop3}), "monotonicity hop0->hop3");
  must_void(verify_taint_monotonicity({hop2, hop3}), "monotonicity hop2->hop3");

  // Hop 4: exceeds max_hops=3 -> MUST be rejected with ErrorCode::capacity.
  const auto hop4 = propagate_taint(hop3, "peer-e", {});
  check(!hop4.has_value() && hop4.error().code == ErrorCode::capacity,
        "hop-limit overflow was not rejected");

  // Cycle detection: propagating back to an earlier actor in hop_chain MUST fail.
  const auto cycle = propagate_taint(hop2, "peer-b", {});
  check(!cycle.has_value() && cycle.error().code == ErrorCode::conflict,
        "cycle in hop_chain was not rejected");
  const auto origin_cycle = propagate_taint(hop1, fp_a, {});
  check(!origin_cycle.has_value() && origin_cycle.error().code == ErrorCode::conflict,
        "cycle back to origin was not rejected");

  // Downstream taint stripping attempt MUST be caught by verify_taint_monotonicity.
  {
    TaintedProvenance stripped = hop2;
    stripped.untrusted_sources.clear();
    const auto res = verify_taint_monotonicity({hop1, stripped});
    check(!res.has_value() && res.error().code == ErrorCode::conflict,
          "taint stripping was not caught");

    TaintedProvenance inflated_cap = hop2;
    inflated_cap.max_hops = 8;
    check(!verify_taint_monotonicity({hop1, inflated_cap}).has_value(),
          "downstream max_hops inflation was not caught");
  }

  // Round-trip serialization & merge into Stage 0 PeerProvenance.
  const auto prov_val = tainted_provenance_to_value(hop3);
  const auto prov_rt = must(tainted_provenance_from_value(prov_val), "prov roundtrip");
  check(prov_rt == hop3, "tainted provenance round-trip mismatch");

  const PeerProvenance base_peer_prov{
      "owner-local",
      "peer-d",
      {"local:diff"},
      "quoted peer handoff",
  };
  const auto merged =
      must(merge_taint_into_peer_provenance(hop3, base_peer_prov), "merge peer prov");
  check(merged.untrusted_sources.size() == 4,
        "merged PeerProvenance missing transitive untrusted sources");

  // Receiver-side invariant: peer-supplied "clean" provenance MUST NEVER override
  // local taint!
  auto forwarder = must(PeerIdentityStore::open_or_create(base / "taint-forwarder"),
                        "create forwarder");
  const std::string fp_fwd = forwarder.identity().fingerprint;
  const BlindRelayFrame foreign_frame{
      "room:taint",
      fp_a,
      RelayLane::causal,
      "f-clean-claim",
      1,
      "YWJjZGVmZ2g=",
      "QUJDREVGR0hJSktM",
      board_bridge_sha256_hex("room:taint"),
      1'000'000'000LL,
      {},
  };

  // Case 1: Foreign peer attaches a self-reported "clean" provenance (empty
  // untrusted_sources).
  const TaintedProvenance self_reported_clean{
      fp_a, {fp_a}, {}, 0, kDefaultMaxProvenanceHops,
  };
  check(!is_provenance_tainted(self_reported_clean),
        "self-reported clean fixture should start clean");
  const auto derived_clean_override =
      must(derive_local_taint_for_peer_frame(foreign_frame, "local-worker",
                                             self_reported_clean),
           "derive local taint overriding clean peer report");
  check(is_provenance_tainted(derived_clean_override),
        "receiver trusted peer-supplied clean provenance");
  check(std::ranges::contains(derived_clean_override.untrusted_sources,
                              std::string{"peer:" + fp_a}),
        "receiver missing peer:<sender_fingerprint> taint marker");
  must_void(verify_taint_monotonicity({self_reported_clean, derived_clean_override}),
            "derived taint violated monotonicity");

  // Case 2: Foreign peer omits provenance entirely -> still locally tainted.
  const auto derived_no_prov =
      must(derive_local_taint_for_peer_frame(foreign_frame, "local-worker"),
           "derive local taint with omitted peer provenance");
  check(is_provenance_tainted(derived_no_prov) &&
            std::ranges::contains(derived_no_prov.untrusted_sources,
                                  std::string{"peer:" + fp_a}),
        "omitted peer provenance was not locally tainted");

  // Case 3: Forwarding peer omits itself from hop_chain -> receiver inserts both
  // forwarder and local actor while preserving upstream untrusted sources.
  BlindRelayFrame forwarded_frame = foreign_frame;
  forwarded_frame.sender_fingerprint = fp_fwd;
  const auto derived_forwarded =
      must(derive_local_taint_for_peer_frame(forwarded_frame, "local-worker", hop0),
           "derive local taint for forwarded frame");
  check(derived_forwarded.hop_count == 2 && derived_forwarded.hop_chain.size() == 3 &&
            derived_forwarded.hop_chain[0] == fp_a &&
            derived_forwarded.hop_chain[1] == fp_fwd &&
            derived_forwarded.hop_chain[2] == "local-worker",
        "forwarded hop chain missing forwarder or local actor");
  check(std::ranges::contains(derived_forwarded.untrusted_sources,
                              std::string{"web:https://untrusted.example/spec"}) &&
            std::ranges::contains(derived_forwarded.untrusted_sources,
                                  std::string{"peer:" + fp_fwd}),
        "forwarded taint missing upstream or forwarder source");
  must_void(verify_taint_monotonicity({hop0, derived_forwarded}),
            "forwarded taint violated monotonicity");

  // Case 4: Hop-cap overflow on receive is rejected (fail-closed).
  const auto derived_overflow =
      derive_local_taint_for_peer_frame(foreign_frame, "local-worker", hop3);
  check(!derived_overflow.has_value() &&
            derived_overflow.error().code == ErrorCode::capacity,
        "receiver failed to reject hop-cap overflow");
}

} // namespace

int main() {
  const auto temp_dir = make_temp_dir();
  int exit_code = 0;
  try {
    test_three_lane_mux_preemption_and_coalescing();
    test_signed_checkpoint_and_delta_filter(temp_dir);
    test_room_invite_uri(temp_dir);
    test_blind_relay_router(temp_dir);
    test_relay_atomic_resume_rollback(temp_dir);
    test_relay_zero_silent_frame_loss(temp_dir);
    test_relay_auth_and_unpredictable_tokens(temp_dir);
    test_relay_memory_and_session_bounds(temp_dir);
    test_transitive_taint_propagation(temp_dir);
    std::cout << "bridge_relay_test: all checks passed\n";
  } catch (const std::exception &ex) {
    std::cerr << "bridge_relay_test FAILED at stage [" << g_stage << "]: " << ex.what()
              << '\n';
    exit_code = 1;
  }
  std::error_code ec;
  (void)std::filesystem::remove_all(temp_dir, ec);
  return exit_code;
}
