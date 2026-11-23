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

#else

void test_without_iroh_returns_unsupported() {
  g_stage = "without_iroh_returns_unsupported";
  require(!p2p_iroh_compiled_in(), "p2p_iroh_compiled_in must be false without flag");
  auto res = P2pEndpoint::create();
  require(!res.has_value() && res.error().code == ErrorCode::unsupported,
          "P2pEndpoint::create without iroh must return ErrorCode::unsupported");
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
