#include "blackbird/p2p_transport.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace blackbird;

namespace {

const char *g_stage = "startup";

void require(bool condition, const char *message) {
  if (!condition) {
    throw std::runtime_error(std::string{g_stage} + ": " + message);
  }
}

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH

template <typename T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context + "]: code=" +
                             std::to_string(static_cast<int>(result.error().code)) +
                             " detail=" + std::to_string(result.error().detail));
  }
  return std::move(result).value();
}

void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context + "]: code=" +
                             std::to_string(static_cast<int>(result.error().code)) +
                             " detail=" + std::to_string(result.error().detail));
  }
}

P2pEvent wait_for_event(P2pEndpoint &endpoint, P2pEventKind expected_kind,
                        int max_wait_ms = 5000) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(max_wait_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    auto polled = must(endpoint.poll_event(200), "poll_event");
    if (!polled.has_value()) {
      continue;
    }
    if (polled->kind == expected_kind) {
      return std::move(*polled);
    }
  }
  throw std::runtime_error(std::string{g_stage} + ": timed out waiting for event");
}

std::string bytes_to_string(const std::vector<std::uint8_t> &bytes) {
  return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
}

#endif

void test_deterministic_dialer_and_policy_helpers() {
  g_stage = "deterministic_dialer_and_policy_helpers";

  // Strictly smaller positive device_id dials first.
  require(should_dial_peer(1001, 2002), "smaller device_id must dial");
  require(!should_dial_peer(2002, 1001), "larger device_id must not dial");
  require(!should_dial_peer(1001, 1001), "equal device_ids must not dial");
  require(!should_dial_peer(0, 1001), "zero local device_id must not dial");
  require(!should_dial_peer(1001, 0), "zero peer device_id must not dial");

  // Non-downgradeable relay policy matrix.
  require(
      !relay_policy_compatible(P2pRelayPolicy::force_relays, P2pRelayPolicy::no_relays),
      "force_relays must reject no_relays");
  require(
      !relay_policy_compatible(P2pRelayPolicy::no_relays, P2pRelayPolicy::force_relays),
      "no_relays must reject force_relays");
  require(!relay_policy_compatible(P2pRelayPolicy::allow_relays,
                                   P2pRelayPolicy::force_relays),
          "allow_relays must reject force_relays downgrade");
  require(relay_policy_compatible(P2pRelayPolicy::force_relays,
                                  P2pRelayPolicy::force_relays),
          "force_relays + force_relays must be compatible");
  require(relay_policy_compatible(P2pRelayPolicy::force_relays,
                                  P2pRelayPolicy::allow_relays),
          "force_relays + allow_relays must be compatible");
  require(relay_policy_compatible(P2pRelayPolicy::no_relays, P2pRelayPolicy::no_relays),
          "no_relays + no_relays must be compatible");

  // Lane max frame sizes.
  require(p2p_lane_max_frame_bytes(P2pLane::control) == 64U * 1024U,
          "control lane limit must be 64 KiB");
  require(p2p_lane_max_frame_bytes(P2pLane::causal) == 4U * 1024U * 1024U,
          "causal lane limit must be 4 MiB");
  require(p2p_lane_max_frame_bytes(P2pLane::ephemeral) == 1200U,
          "ephemeral lane limit must be 1200 B");
}

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH

void test_force_relays_policy_and_zero_direct_sockets() {
  g_stage = "force_relays_policy_and_zero_direct_sockets";

  // Missing relay URL under force_relays must fail closed.
  P2pEndpointConfig missing_url{};
  missing_url.relay_policy = P2pRelayPolicy::force_relays;
  auto missing_res = P2pEndpoint::create(missing_url);
  require(!missing_res.has_value(), "force_relays without relay_url must fail");

  // Non-HTTPS or query/userinfo relay URLs must fail closed.
  for (const char *bad_url :
       {"http://relay.multiplayer.tech", "https://user:pass@relay.multiplayer.tech",
        "https://relay.multiplayer.tech/?x=1",
        "https://relay.multiplayer.tech/#frag"}) {
    P2pEndpointConfig bad_cfg{};
    bad_cfg.relay_policy = P2pRelayPolicy::force_relays;
    bad_cfg.relay_url = bad_url;
    auto bad_res = P2pEndpoint::create(bad_cfg);
    require(!bad_res.has_value(), "malformed relay_url must fail closed");
  }

  // Valid pinned HTTPS relay URL creates true IP-hiding endpoint with 0 UDP sockets.
  P2pEndpointConfig force_cfg{};
  force_cfg.relay_policy = P2pRelayPolicy::force_relays;
  force_cfg.relay_url = "https://relay.multiplayer.tech";
  auto hidden = must(P2pEndpoint::create(force_cfg), "create force_relays");
  require(hidden.valid(), "force_relays endpoint must be valid");
  require(hidden.relay_policy() == P2pRelayPolicy::force_relays,
          "relay_policy accessor mismatch");

  auto addrs = must(hidden.local_direct_addrs(), "local_direct_addrs");
  require(addrs.empty(), "force_relays must bind ZERO direct IP sockets");

  // Create a no_relays peer just to obtain a valid Ed25519 pubkey.
  P2pEndpointConfig direct_cfg{};
  direct_cfg.relay_policy = P2pRelayPolicy::no_relays;
  auto peer = must(P2pEndpoint::create(direct_cfg), "create no_relays peer");
  auto peer_pk = must(peer.local_pubkey(), "peer local_pubkey");
  auto peer_addrs = must(peer.local_direct_addrs(), "peer local_direct_addrs");
  require(!peer_addrs.empty(), "no_relays peer must have local direct addrs");

  const std::array<P2pPubkey, 1> allowed = {peer_pk};
  must_void(hidden.set_allowed_peers(allowed), "allow peer on hidden");

  // force_relays rejects no_relays mismatch cleanly.
  P2pPeerTarget mismatch{};
  mismatch.pubkey = peer_pk;
  mismatch.remote_relay_policy = P2pRelayPolicy::no_relays;
  mismatch.direct_addrs = peer_addrs;
  auto mismatch_res = hidden.connect_peer(mismatch);
  require(!mismatch_res.has_value(), "force_relays must reject no_relays target");
  require(mismatch_res.error().code == ErrorCode::conflict,
          "policy mismatch must report ErrorCode::conflict");

  // force_relays also rejects direct IP addresses even if remote policy says
  // force_relays.
  P2pPeerTarget direct_leak{};
  direct_leak.pubkey = peer_pk;
  direct_leak.remote_relay_policy = P2pRelayPolicy::force_relays;
  direct_leak.relay_url = "https://relay.multiplayer.tech";
  direct_leak.direct_addrs = peer_addrs;
  auto leak_res = hidden.connect_peer(direct_leak);
  require(!leak_res.has_value(), "force_relays must reject direct IP target");
  require(leak_res.error().code == ErrorCode::conflict,
          "direct IP leak attempt must report ErrorCode::conflict");

  // Move semantics and explicit close preserve RAII lifecycle cleanly.
  P2pEndpoint moved = std::move(hidden);
  require(moved.valid(), "moved endpoint must be valid");
  const auto moved_pk = must(moved.local_pubkey(), "moved local_pubkey");
  require(moved_pk != peer_pk, "moved endpoint pubkey must be valid and distinct");
  moved.close();
  require(!moved.valid(), "closed endpoint must be invalid");
  auto closed_res = moved.local_pubkey();
  require(!closed_res.has_value() && closed_res.error().code == ErrorCode::stale_handle,
          "closed endpoint must fail with stale_handle");

  P2pEndpoint empty{};
  require(!empty.valid(), "default-constructed endpoint must be invalid");
  auto empty_res = empty.local_pubkey();
  require(!empty_res.has_value() && empty_res.error().code == ErrorCode::stale_handle,
          "default-constructed endpoint must fail with stale_handle");

  // Deterministic 32-byte Ed25519 seed yields identical local_pubkey.
  P2pEndpointConfig seeded_cfg{};
  seeded_cfg.relay_policy = P2pRelayPolicy::no_relays;
  seeded_cfg.secret_key = P2pSecretKey{};
  seeded_cfg.secret_key->fill(0x2AU);
  auto seeded_a = must(P2pEndpoint::create(seeded_cfg), "create seeded_a");
  auto seeded_b = must(P2pEndpoint::create(seeded_cfg), "create seeded_b");
  require(must(seeded_a.local_pubkey(), "seeded_a pk") ==
              must(seeded_b.local_pubkey(), "seeded_b pk"),
          "identical secret_key seeds must derive identical Ed25519 pubkey");
}

void test_live_loopback_quic_tls13_rpk_end_to_end() {
  g_stage = "live_loopback_quic_tls13_rpk_end_to_end";

  P2pEndpointConfig offline_cfg{};
  offline_cfg.relay_policy = P2pRelayPolicy::no_relays;

  auto alice = must(P2pEndpoint::create(offline_cfg), "create alice");
  auto bob = must(P2pEndpoint::create(offline_cfg), "create bob");
  auto mallory = must(P2pEndpoint::create(offline_cfg), "create mallory");

  const auto alice_pk = must(alice.local_pubkey(), "alice pubkey");
  const auto bob_pk = must(bob.local_pubkey(), "bob pubkey");
  const auto mallory_pk = must(mallory.local_pubkey(), "mallory pubkey");
  require(alice_pk != bob_pk && alice_pk != mallory_pk && bob_pk != mallory_pk,
          "ephemeral Ed25519 keys must be distinct");

  const auto alice_addrs = must(alice.local_direct_addrs(), "alice direct addrs");
  require(!alice_addrs.empty(), "alice must expose loopback direct address");

  // 1. Unallowed peer mallory attempting real QUIC+TLS1.3-RPK connect to alice is
  //    immediately rejected before any application bytes pass.
  const std::array<P2pPubkey, 1> mallory_allows_alice = {alice_pk};
  must_void(mallory.set_allowed_peers(mallory_allows_alice), "mallory allow alice");

  P2pPeerTarget alice_target{};
  alice_target.pubkey = alice_pk;
  alice_target.remote_relay_policy = P2pRelayPolicy::no_relays;
  alice_target.direct_addrs = alice_addrs;
  alice_target.connect_timeout_ms = 5000;

  auto mallory_conn = mallory.connect_peer(alice_target);
  require(!mallory_conn.has_value(), "mallory connect to alice must fail");
  require(mallory_conn.error().code == ErrorCode::invalid_identity,
          "unallowed mallory must receive invalid_identity rejection");

  auto alice_unexpected = must(alice.poll_event(150), "alice poll after mallory");
  require(!alice_unexpected.has_value(),
          "alice must receive ZERO events from unallowed mallory");

  // Local outbound guard: bob cannot dial alice before allowlisting alice.
  auto unallowed_outbound = bob.connect_peer(alice_target);
  require(!unallowed_outbound.has_value() &&
              unallowed_outbound.error().code == ErrorCode::invalid_identity,
          "bob must refuse dialing unallowed peer");

  // Unspecified, multicast, and broadcast direct addresses must fail closed.
  const std::array<P2pDirectAddr, 5> bad_direct_addrs = {
      P2pDirectAddr::ipv4({0, 0, 0, 0}, 4433),
      P2pDirectAddr::ipv4({224, 0, 0, 1}, 4433),
      P2pDirectAddr::ipv4({255, 255, 255, 255}, 4433),
      P2pDirectAddr::ipv6({}, 4433),
      P2pDirectAddr::ipv6({0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 4433),
  };
  for (const auto &bad_addr : bad_direct_addrs) {
    P2pPeerTarget bad_target{};
    bad_target.pubkey = alice_pk;
    bad_target.remote_relay_policy = P2pRelayPolicy::no_relays;
    bad_target.direct_addrs = {bad_addr};
    auto bad_res = bob.connect_peer(bad_target);
    require(!bad_res.has_value() && bad_res.error().code == ErrorCode::invalid_range,
            "unspecified/multicast/broadcast direct addr must fail with invalid_range");
  }

  // 2. Mutual allowlist between alice and bob -> real QUIC + TLS 1.3 RPK handshake.
  const std::array<P2pPubkey, 1> alice_allows_bob = {bob_pk};
  const std::array<P2pPubkey, 1> bob_allows_alice = {alice_pk};
  must_void(alice.set_allowed_peers(alice_allows_bob), "alice allow bob");
  must_void(bob.set_allowed_peers(bob_allows_alice), "bob allow alice");

  // Deterministic dialer: suppose bob has smaller device_id (10 < 20) -> bob dials
  // alice.
  require(should_dial_peer(10, 20), "bob (10) dials alice (20)");
  must_void(bob.connect_peer(alice_target), "bob connect to alice");

  const auto bob_conn_ev = wait_for_event(bob, P2pEventKind::peer_connected);
  require(bob_conn_ev.peer_pubkey == alice_pk, "bob connected pubkey mismatch");

  const auto alice_conn_ev = wait_for_event(alice, P2pEventKind::peer_connected);
  require(alice_conn_ev.peer_pubkey == bob_pk, "alice connected pubkey mismatch");

  // 3. Exchange frames across Lane 0 (Control), Lane 1 (Causal), Lane 2 (RFC 9221
  // Datagram)
  //    in BOTH directions and verify exact byte & lane fidelity.
  const std::string ctrl_a2b = "ctrl:grant:epoch=7:action_guard=ok";
  const std::vector<std::uint8_t> causal_a2b(96U * 1024U,
                                             0x3CU); // 96 KiB (> 64 KiB control max)
  const std::string eph_a2b = "dgram:presence:alice:online:flightdeck";

  // Lane size guards fail closed before hitting wire.
  auto over_ctrl = alice.send_frame(bob_pk, P2pLane::control, causal_a2b);
  require(!over_ctrl.has_value() && over_ctrl.error().code == ErrorCode::capacity,
          "control frame > 64 KiB must fail with capacity");
  const std::vector<std::uint8_t> over_dgram(kP2pMaxEphemeralFrameBytes + 1U, 0xEEU);
  auto over_eph = alice.send_frame(bob_pk, P2pLane::ephemeral, over_dgram);
  require(!over_eph.has_value() && over_eph.error().code == ErrorCode::capacity,
          "ephemeral datagram > 1200 B must fail with capacity");

  // Alice -> Bob
  must_void(alice.send_frame(bob_pk, P2pLane::control, ctrl_a2b), "alice send control");
  const auto got_ctrl_b = wait_for_event(bob, P2pEventKind::frame_received);
  require(got_ctrl_b.peer_pubkey == alice_pk, "bob control sender mismatch");
  require(got_ctrl_b.lane == P2pLane::control, "bob control lane mismatch");
  require(bytes_to_string(got_ctrl_b.payload) == ctrl_a2b,
          "bob control payload mismatch");

  must_void(alice.send_frame(bob_pk, P2pLane::causal, causal_a2b), "alice send causal");
  const auto got_causal_b = wait_for_event(bob, P2pEventKind::frame_received);
  require(got_causal_b.peer_pubkey == alice_pk, "bob causal sender mismatch");
  require(got_causal_b.lane == P2pLane::causal, "bob causal lane mismatch");
  require(got_causal_b.payload == causal_a2b, "bob causal payload mismatch");

  must_void(alice.send_frame(bob_pk, P2pLane::ephemeral, eph_a2b),
            "alice send ephemeral");
  const auto got_eph_b = wait_for_event(bob, P2pEventKind::frame_received);
  require(got_eph_b.peer_pubkey == alice_pk, "bob ephemeral sender mismatch");
  require(got_eph_b.lane == P2pLane::ephemeral, "bob ephemeral lane mismatch");
  require(bytes_to_string(got_eph_b.payload) == eph_a2b,
          "bob ephemeral payload mismatch");

  // Bob -> Alice
  const std::string ctrl_b2a = "ctrl:ack:epoch=7";
  const std::string causal_b2a = "causal:board_bridge:receipt=6/6";
  const std::string eph_b2a = "dgram:typing:bob";

  must_void(bob.send_frame(alice_pk, P2pLane::control, ctrl_b2a), "bob send control");
  const auto got_ctrl_a = wait_for_event(alice, P2pEventKind::frame_received);
  require(got_ctrl_a.peer_pubkey == bob_pk && got_ctrl_a.lane == P2pLane::control &&
              bytes_to_string(got_ctrl_a.payload) == ctrl_b2a,
          "alice control recv mismatch");

  must_void(bob.send_frame(alice_pk, P2pLane::causal, causal_b2a), "bob send causal");
  const auto got_causal_a = wait_for_event(alice, P2pEventKind::frame_received);
  require(got_causal_a.peer_pubkey == bob_pk && got_causal_a.lane == P2pLane::causal &&
              bytes_to_string(got_causal_a.payload) == causal_b2a,
          "alice causal recv mismatch");

  must_void(bob.send_frame(alice_pk, P2pLane::ephemeral, eph_b2a),
            "bob send ephemeral");
  const auto got_eph_a = wait_for_event(alice, P2pEventKind::frame_received);
  require(got_eph_a.peer_pubkey == bob_pk && got_eph_a.lane == P2pLane::ephemeral &&
              bytes_to_string(got_eph_a.payload) == eph_b2a,
          "alice ephemeral recv mismatch");

  // 4. alice.revoke_peer(bob_pk) immediately severs the active QUIC connection and
  //    rejects subsequent sends.
  must_void(alice.revoke_peer(bob_pk), "alice revoke bob");

  const auto alice_disc_ev = wait_for_event(alice, P2pEventKind::peer_disconnected);
  require(alice_disc_ev.peer_pubkey == bob_pk, "alice disconnect pubkey mismatch");
  require(alice_disc_ev.reason_code == 4403U, "alice disconnect reason must be 4403");

  auto send_after_revoke = alice.send_frame(bob_pk, P2pLane::control, "after-revoke");
  require(!send_after_revoke.has_value() &&
              send_after_revoke.error().code == ErrorCode::invalid_identity,
          "send after revoke must fail with invalid_identity");

  const auto bob_disc_ev = wait_for_event(bob, P2pEventKind::peer_disconnected);
  require(bob_disc_ev.peer_pubkey == alice_pk, "bob disconnect pubkey mismatch");
  require(bob_disc_ev.reason_code == 4403U,
          "bob must observe immediate QUIC close code 4403 on revoke");

  // Re-dial from revoked bob to alice must also be rejected!
  auto redial_res = bob.connect_peer(alice_target);
  require(!redial_res.has_value() &&
              redial_res.error().code == ErrorCode::invalid_identity,
          "revoked bob re-dialing alice must be immediately rejected");
}

void test_lan_open_admission_fail_closed_on_online_policies() {
  g_stage = "lan_open_admission_fail_closed_on_online_policies";

  // allow_relays endpoint MUST fail closed with ErrorCode::conflict.
  P2pEndpointConfig allow_cfg{};
  allow_cfg.relay_policy = P2pRelayPolicy::allow_relays;
  allow_cfg.relay_url = "https://relay.multiplayer.tech";
  auto allow_ep = must(P2pEndpoint::create(allow_cfg), "create allow_relays");
  auto allow_on = allow_ep.set_lan_open_admission(true);
  require(!allow_on.has_value() && allow_on.error().code == ErrorCode::conflict,
          "allow_relays must reject set_lan_open_admission(true) with conflict");
  auto allow_off = allow_ep.set_lan_open_admission(false);
  require(!allow_off.has_value() && allow_off.error().code == ErrorCode::conflict,
          "allow_relays must reject set_lan_open_admission(false) with conflict");

  // force_relays endpoint MUST fail closed with ErrorCode::conflict.
  P2pEndpointConfig force_cfg{};
  force_cfg.relay_policy = P2pRelayPolicy::force_relays;
  force_cfg.relay_url = "https://relay.multiplayer.tech";
  auto force_ep = must(P2pEndpoint::create(force_cfg), "create force_relays");
  auto force_on = force_ep.set_lan_open_admission(true);
  require(!force_on.has_value() && force_on.error().code == ErrorCode::conflict,
          "force_relays must reject set_lan_open_admission(true) with conflict");
  auto force_off = force_ep.set_lan_open_admission(false);
  require(!force_off.has_value() && force_off.error().code == ErrorCode::conflict,
          "force_relays must reject set_lan_open_admission(false) with conflict");

  // Default-constructed / closed endpoints fail with stale_handle.
  P2pEndpoint empty{};
  auto empty_open = empty.set_lan_open_admission(true);
  require(!empty_open.has_value() && empty_open.error().code == ErrorCode::stale_handle,
          "invalid endpoint set_lan_open_admission must fail with stale_handle");
  const P2pPubkey dummy_pk{};
  auto empty_allow = empty.allow_peer(dummy_pk);
  require(!empty_allow.has_value() &&
              empty_allow.error().code == ErrorCode::stale_handle,
          "invalid endpoint allow_peer must fail with stale_handle");
}

void test_lan_open_admission_live_handshake_promotion_and_lock() {
  g_stage = "lan_open_admission_live_handshake_promotion_and_lock";

  P2pEndpointConfig lan_cfg{};
  lan_cfg.relay_policy = P2pRelayPolicy::no_relays;

  auto host = must(P2pEndpoint::create(lan_cfg), "create lan host");
  auto joiner = must(P2pEndpoint::create(lan_cfg), "create lan joiner");
  auto rogue = must(P2pEndpoint::create(lan_cfg), "create lan rogue");
  auto latecomer = must(P2pEndpoint::create(lan_cfg), "create lan latecomer");

  const auto host_pk = must(host.local_pubkey(), "host pubkey");
  const auto joiner_pk = must(joiner.local_pubkey(), "joiner pubkey");
  const auto rogue_pk = must(rogue.local_pubkey(), "rogue pubkey");
  const auto host_addrs = must(host.local_direct_addrs(), "host direct addrs");
  require(!host_addrs.empty(), "lan host must bind loopback direct addr");

  const std::array<P2pPubkey, 1> allow_host = {host_pk};
  must_void(joiner.set_allowed_peers(allow_host), "joiner allow host");
  must_void(rogue.set_allowed_peers(allow_host), "rogue allow host");
  must_void(latecomer.set_allowed_peers(allow_host), "latecomer allow host");

  P2pPeerTarget host_target{};
  host_target.pubkey = host_pk;
  host_target.remote_relay_policy = P2pRelayPolicy::no_relays;
  host_target.direct_addrs = host_addrs;
  host_target.connect_timeout_ms = 5000;

  // 1. Default no_relays host rejects un-allowlisted joiner.
  auto before_open = joiner.connect_peer(host_target);
  require(!before_open.has_value() &&
              before_open.error().code == ErrorCode::invalid_identity,
          "no_relays default must reject un-allowlisted joiner");

  // 2. Host enables opt-in open LAN admission -> un-allowlisted joiner connects.
  must_void(host.set_lan_open_admission(true), "host enable lan open admission");
  must_void(joiner.connect_peer(host_target), "un-allowlisted joiner dials lan host");

  const auto host_saw_joiner = wait_for_event(host, P2pEventKind::peer_connected);
  require(host_saw_joiner.peer_pubkey == joiner_pk,
          "host must observe pending joiner peer_connected");

  // Host cannot send Lane 1 (causal) to un-allowlisted pending joiner before promotion.
  auto pre_promote_causal =
      host.send_frame(joiner_pk, P2pLane::causal, "blocked-causal-before-allow");
  require(!pre_promote_causal.has_value() &&
              pre_promote_causal.error().code == ErrorCode::invalid_identity,
          "host must not send causal frames to pending un-allowlisted peer");

  // Exchange Lane 0 (control) LAN handshake frames while joiner is pending.
  const std::string lan_hello = "LAN_HELLO:nonce=feedface";
  must_void(host.send_frame(joiner_pk, P2pLane::control, lan_hello),
            "host send LAN_HELLO");
  const auto got_hello = wait_for_event(joiner, P2pEventKind::frame_received);
  require(got_hello.peer_pubkey == host_pk && got_hello.lane == P2pLane::control &&
              bytes_to_string(got_hello.payload) == lan_hello,
          "joiner LAN_HELLO control recv mismatch");

  const std::string lan_join = "LAN_JOIN:pin_proof=verified";
  must_void(joiner.send_frame(host_pk, P2pLane::control, lan_join),
            "joiner send LAN_JOIN");
  const auto got_join = wait_for_event(host, P2pEventKind::frame_received);
  require(got_join.peer_pubkey == joiner_pk && got_join.lane == P2pLane::control &&
              bytes_to_string(got_join.payload) == lan_join,
          "host LAN_JOIN control recv mismatch");

  // 3. Rogue pending peer sending Lane 1 (causal) before promotion is closed with 4400.
  must_void(rogue.connect_peer(host_target), "rogue connects pending");
  const auto host_saw_rogue = wait_for_event(host, P2pEventKind::peer_connected);
  require(host_saw_rogue.peer_pubkey == rogue_pk,
          "host must observe pending rogue peer_connected");
  must_void(rogue.send_frame(host_pk, P2pLane::causal, "rogue-causal-violation"),
            "rogue sends forbidden causal frame");

  const auto rogue_host_disc = wait_for_event(host, P2pEventKind::peer_disconnected);
  require(
      rogue_host_disc.peer_pubkey == rogue_pk && rogue_host_disc.reason_code == 4400U,
      "host must disconnect rogue pending peer with CLOSE_PROTOCOL_VIOLATION (4400)");
  const auto rogue_disc = wait_for_event(rogue, P2pEventKind::peer_disconnected);
  require(rogue_disc.peer_pubkey == host_pk && rogue_disc.reason_code == 4400U,
          "rogue must observe CLOSE_PROTOCOL_VIOLATION (4400)");

  // 4. Host promotes joiner via allow_peer -> both exchange Lane 1 (causal) cleanly.
  must_void(host.allow_peer(joiner_pk), "host promote joiner");
  const std::string lan_welcome = "LAN_WELCOME:admitted=1";
  must_void(host.send_frame(joiner_pk, P2pLane::control, lan_welcome),
            "host send LAN_WELCOME");
  const auto got_welcome = wait_for_event(joiner, P2pEventKind::frame_received);
  require(got_welcome.peer_pubkey == host_pk && got_welcome.lane == P2pLane::control &&
              bytes_to_string(got_welcome.payload) == lan_welcome,
          "joiner LAN_WELCOME recv mismatch");

  const std::string causal_j2h = "lan-causal:joiner-to-host";
  must_void(joiner.send_frame(host_pk, P2pLane::causal, causal_j2h),
            "promoted joiner send causal");
  const auto got_causal_h = wait_for_event(host, P2pEventKind::frame_received);
  require(got_causal_h.peer_pubkey == joiner_pk &&
              got_causal_h.lane == P2pLane::causal &&
              bytes_to_string(got_causal_h.payload) == causal_j2h,
          "host causal recv from promoted joiner mismatch");

  const std::string causal_h2j = "lan-causal:host-to-joiner";
  must_void(host.send_frame(joiner_pk, P2pLane::causal, causal_h2j),
            "host send causal to promoted joiner");
  const auto got_causal_j = wait_for_event(joiner, P2pEventKind::frame_received);
  require(got_causal_j.peer_pubkey == host_pk && got_causal_j.lane == P2pLane::causal &&
              bytes_to_string(got_causal_j.payload) == causal_h2j,
          "joiner causal recv from host mismatch");

  // 5. Locking lobby (set_lan_open_admission(false)) blocks third un-allowlisted peer
  //    while keeping admitted joiner connected!
  must_void(host.set_lan_open_admission(false), "host lock lan lobby");

  auto late_res = latecomer.connect_peer(host_target);
  require(!late_res.has_value() && late_res.error().code == ErrorCode::invalid_identity,
          "locked lan lobby must reject un-allowlisted third peer");

  const std::string post_lock_causal = "lan-causal:after-lobby-lock";
  must_void(joiner.send_frame(host_pk, P2pLane::causal, post_lock_causal),
            "admitted joiner send causal after lobby lock");
  const auto got_post_lock = wait_for_event(host, P2pEventKind::frame_received);
  require(got_post_lock.peer_pubkey == joiner_pk &&
              got_post_lock.lane == P2pLane::causal &&
              bytes_to_string(got_post_lock.payload) == post_lock_causal,
          "admitted joiner must remain connected after lobby lock");
}

#else

void test_without_iroh_returns_unsupported() {
  g_stage = "without_iroh_returns_unsupported";
  require(!p2p_iroh_compiled_in(), "p2p_iroh_compiled_in must be false without flag");
  auto res = P2pEndpoint::create();
  require(!res.has_value() && res.error().code == ErrorCode::unsupported,
          "P2pEndpoint::create without iroh must return ErrorCode::unsupported");
  P2pEndpoint ep{};
  auto open_res = ep.set_lan_open_admission(true);
  require(!open_res.has_value() && open_res.error().code == ErrorCode::unsupported,
          "set_lan_open_admission without iroh must return ErrorCode::unsupported");
  const P2pPubkey pk{};
  auto allow_res = ep.allow_peer(pk);
  require(!allow_res.has_value() && allow_res.error().code == ErrorCode::unsupported,
          "allow_peer without iroh must return ErrorCode::unsupported");
}

#endif

} // namespace

int main() {
  try {
    test_deterministic_dialer_and_policy_helpers();
#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
    require(p2p_iroh_compiled_in(), "p2p_iroh_compiled_in must be true with flag");
    test_force_relays_policy_and_zero_direct_sockets();
    test_live_loopback_quic_tls13_rpk_end_to_end();
    test_lan_open_admission_fail_closed_on_online_policies();
    test_lan_open_admission_live_handshake_promotion_and_lock();
#else
    test_without_iroh_returns_unsupported();
#endif
    std::cout << "p2p_transport_test: ALL PASSED\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "FAIL: " << ex.what() << "\n";
    return 1;
  }
}
