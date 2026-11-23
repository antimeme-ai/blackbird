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

  // Verify valid checkpoint succeeds.
  must_void(verify_checkpoint(known, checkpoint), "verify valid checkpoint");

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
  const auto pub1 = must(router.publish(f1, 1'000'000'000LL), "publish f1");
  check(pub1.relay_seq == 1 && pub1.delivered_sessions == 2 && !pub1.duplicate,
        "f1 delivery count mismatch");

  // Duplicate frame_id is suppressed without re-broadcast.
  const auto pub1_dup = must(router.publish(f1, 1'000'000'100LL), "publish dup f1");
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
  const auto spec_pub = router.publish(spec_try, 1'000'000'200LL);
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
      must(router.publish(f2_out_of_scope, 1'000'000'300LL), "publish f2");
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
  const auto rl_res = router.publish(f_rate_limited, 1'000'000'400LL);
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
  const auto bob_pub =
      must(router.publish(f_bob_ok, 1'000'000'500LL), "bob publish ok");
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
  const auto ctrl_bad = router.publish(oversized_ctrl, 3'000'000'000LL);
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
  const auto pres_bad = router.publish(oversized_pres, 3'000'000'100LL);
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
  const auto pub4 = must(router.publish(
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

  (void)must(router.publish(
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

  const auto pub5 = must(router.publish(
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
  });
  check(!hijack.has_value() && hijack.error().code == ErrorCode::invalid_identity,
        "session resume allowed wrong peer fingerprint");

  // Bob roams to LTE IP and resumes from last_acked_relay_seq = 1.
  const auto resumed = must(router.resume_session({
                                s_bob.session_id,
                                bob.identity().fingerprint,
                                "100.64.9.42:61234",
                                1,
                            }),
                            "bob roam resume");
  check(resumed.session.connected, "resumed session not connected");
  check(resumed.session.remote_endpoint == "100.64.9.42:61234", "endpoint not updated");
  check(resumed.session.connection_id != s_bob.connection_id,
        "connection_id did not rotate on roam");
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
