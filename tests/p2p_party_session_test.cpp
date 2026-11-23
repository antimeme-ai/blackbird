#include "blackbird/p2p_party_session.hpp"

#include <array>
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

template <typename T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: code=" + error_name(result.error().code) +
                             " detail=" + std::to_string(result.error().detail));
  }
  return std::move(result).value();
}

void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: code=" + error_name(result.error().code) +
                             " detail=" + std::to_string(result.error().detail));
  }
}

mp::Ed25519SigningKey make_key(std::uint8_t seed_byte) {
  mp::Ed25519Seed seed{};
  seed.fill(seed_byte);
  return must(mp::Ed25519SigningKey::from_seed(seed), "make_key");
}

struct MintMemberSpec {
  std::uint64_t device_id = 0U;
  std::uint64_t account_id = 0U;
  mp::Ed25519PubKey device_pubkey{};
  mp::EndpointDescriptor endpoint;
  std::int64_t iat_s = 1000;
  std::int64_t exp_s = 2000;
  std::uint64_t joined_seq = 1U;
  bool connected = true;
};

mp::PartyMemberRecord mint_member(const mp::Ed25519SigningKey &root_key,
                                  const MintMemberSpec &spec) {
  const auto cwt = must(
      mp::encode_device_cwt(root_key, mp::DeviceCwtMintRequest{spec.device_pubkey,
                                                               spec.iat_s, spec.exp_s}),
      "encode_device_cwt");
  return mp::PartyMemberRecord{
      must(mp::DeviceId::create(spec.device_id), "device_id"),
      must(mp::AccountId::create(spec.account_id), "account_id"),
      root_key.public_key(),
      spec.device_pubkey,
      cwt,
      spec.endpoint,
      spec.joined_seq,
      spec.connected,
  };
}

mp::EndpointDescriptor make_public_endpoint(std::uint16_t port,
                                            std::string relay_url = {}) {
  mp::EndpointDescriptor ep{};
  ep.transport_kind = mp::TransportKind::iroh_quic;
  ep.relay_url = std::move(relay_url);
  ep.direct_addrs.push_back(mp::DirectAddrV4{{203U, 0U, 113U, 10U}, port});
  return ep;
}

mp::EndpointDescriptor make_lan_endpoint(std::uint16_t port) {
  mp::EndpointDescriptor ep{};
  ep.transport_kind = mp::TransportKind::iroh_quic;
  ep.direct_addrs.push_back(mp::DirectAddrV4{{192U, 168U, 1U, 42U}, port});
  return ep;
}

mp::EndpointDescriptor make_force_relay_endpoint(std::string relay_url) {
  mp::EndpointDescriptor ep{};
  ep.transport_kind = mp::TransportKind::iroh_quic;
  ep.relay_url = std::move(relay_url);
  return ep;
}

void test_golden_wire_hex_vectors() {
  g_stage = "golden_wire_hex_vectors";

  // 1. chat_message (kind 0x01, Lane 1 causal)
  const P2pPartyChatMessage chat{
      "party/main", "@all", "alice", 0x0102030405060708LL, "hi",
  };
  constexpr std::string_view kExpectedChatHex = "01010000"
                                                "0807060504030201"
                                                "0a0070617274792f6d61696e"
                                                "040040616c6c"
                                                "0500616c696365"
                                                "020000006869";
  const auto chat_bytes = must(encode_p2p_party_frame(chat), "golden encode chat");
  require(mp::hex_lower(chat_bytes) == kExpectedChatHex,
          "chat_message golden hex mismatch");
  const auto chat_dec =
      must(decode_p2p_party_frame(P2pLane::causal, chat_bytes), "golden decode chat");
  require(std::get<P2pPartyChatMessage>(chat_dec) == chat,
          "chat_message golden decode mismatch");

  // 2. bridge_envelope (kind 0x02, Lane 1 causal)
  const P2pPartyBridgeEnvelope bridge{
      "party/ops",
      std::vector<std::uint8_t>{0xdeU, 0xadU, 0xbeU, 0xefU},
  };
  constexpr std::string_view kExpectedBridgeHex = "01020000"
                                                  "090070617274792f6f7073"
                                                  "04000000deadbeef";
  const auto bridge_bytes =
      must(encode_p2p_party_frame(bridge), "golden encode bridge");
  require(mp::hex_lower(bridge_bytes) == kExpectedBridgeHex,
          "bridge_envelope golden hex mismatch");
  const auto bridge_dec = must(decode_p2p_party_frame(P2pLane::causal, bridge_bytes),
                               "golden decode bridge");
  require(std::get<P2pPartyBridgeEnvelope>(bridge_dec) == bridge,
          "bridge_envelope golden decode mismatch");

  // 3. control_notice (kind 0x03, Lane 0 control)
  const P2pPartyControlNotice notice{
      P2pPartyControlNoticeKind::sync_ack,
      7U,
      "ok",
  };
  constexpr std::string_view kExpectedNoticeHex = "01030000"
                                                  "0000"
                                                  "0700000000000000"
                                                  "02006f6b";
  const auto notice_bytes =
      must(encode_p2p_party_frame(notice), "golden encode notice");
  require(mp::hex_lower(notice_bytes) == kExpectedNoticeHex,
          "control_notice golden hex mismatch");
  const auto notice_dec = must(decode_p2p_party_frame(P2pLane::control, notice_bytes),
                               "golden decode notice");
  require(std::get<P2pPartyControlNotice>(notice_dec) == notice,
          "control_notice golden decode mismatch");

  // 4. ephemeral_pulse (kind 0x04, Lane 2 ephemeral)
  const P2pPartyEphemeralPulse pulse{
      P2pPartyActivityState::working,
      0x0000000011223344LL,
      "run",
  };
  constexpr std::string_view kExpectedPulseHex = "01040000"
                                                 "0200"
                                                 "4433221100000000"
                                                 "030072756e";
  const auto pulse_bytes = must(encode_p2p_party_frame(pulse), "golden encode pulse");
  require(mp::hex_lower(pulse_bytes) == kExpectedPulseHex,
          "ephemeral_pulse golden hex mismatch");
  const auto pulse_dec = must(decode_p2p_party_frame(P2pLane::ephemeral, pulse_bytes),
                              "golden decode pulse");
  require(std::get<P2pPartyEphemeralPulse>(pulse_dec) == pulse,
          "ephemeral_pulse golden decode mismatch");
}

void test_frame_codec_roundtrip_and_bounds() {
  g_stage = "frame_codec_roundtrip_and_bounds";

  // 1. chat_message (Lane 1 causal)
  const P2pPartyChatMessage chat{
      "party/flight-deck",
      "@all",
      "alice",
      1763900000123456789LL,
      "cleared for takeoff across lane 1",
  };
  const auto chat_bytes = must(encode_p2p_party_frame(chat), "encode chat");
  const auto chat_decoded =
      must(decode_p2p_party_frame(P2pLane::causal, chat_bytes), "decode chat");
  require(std::holds_alternative<P2pPartyChatMessage>(chat_decoded),
          "decoded frame must be chat_message");
  require(std::get<P2pPartyChatMessage>(chat_decoded) == chat,
          "chat roundtrip mismatch");

  // Wrong lane rejection (chat_message on control or ephemeral must fail).
  const auto wrong_lane = decode_p2p_party_frame(P2pLane::control, chat_bytes);
  require(!wrong_lane.has_value() && p2p_party_error_of(wrong_lane.error()) ==
                                         P2pPartyError::frame_lane_mismatch,
          "chat_message on control lane must fail with frame_lane_mismatch");

  // 2. bridge_envelope (Lane 1 causal)
  const P2pPartyBridgeEnvelope bridge{
      "party/bridge",
      std::vector<std::uint8_t>{0x01U, 0x02U, 0x7bU, 0x7dU, 0xffU},
  };
  const auto bridge_bytes = must(encode_p2p_party_frame(bridge), "encode bridge");
  const auto bridge_decoded =
      must(decode_p2p_party_frame(P2pLane::causal, bridge_bytes), "decode bridge");
  require(std::get<P2pPartyBridgeEnvelope>(bridge_decoded) == bridge,
          "bridge_envelope roundtrip mismatch");

  // 3. control_notice (Lane 0 control)
  const P2pPartyControlNotice notice{
      P2pPartyControlNoticeKind::scope_changed,
      42U,
      "scope=party/tactical",
  };
  const auto notice_bytes = must(encode_p2p_party_frame(notice), "encode notice");
  const auto notice_decoded =
      must(decode_p2p_party_frame(P2pLane::control, notice_bytes), "decode notice");
  require(std::get<P2pPartyControlNotice>(notice_decoded) == notice,
          "control_notice roundtrip mismatch");

  // 4. ephemeral_pulse (Lane 2 ephemeral, <= 1200 B)
  const P2pPartyEphemeralPulse pulse{
      P2pPartyActivityState::typing,
      1763900000999999999LL,
      "drafting maneuver",
  };
  const auto pulse_bytes = must(encode_p2p_party_frame(pulse), "encode pulse");
  require(pulse_bytes.size() <= kP2pMaxEphemeralFrameBytes,
          "ephemeral_pulse must fit inside 1200 B datagram budget");
  const auto pulse_decoded =
      must(decode_p2p_party_frame(P2pLane::ephemeral, pulse_bytes), "decode pulse");
  require(std::get<P2pPartyEphemeralPulse>(pulse_decoded) == pulse,
          "ephemeral_pulse roundtrip mismatch");

  // 5. Reject malformed frames: bad version, non-zero reserved, trailing bytes,
  //    truncated payload, oversized fields, invalid UTF-8.
  auto bad_ver = notice_bytes;
  bad_ver[0] = 2U;
  auto res = decode_p2p_party_frame(P2pLane::control, bad_ver);
  require(!res.has_value() && p2p_party_error_of(res.error()) ==
                                  P2pPartyError::frame_unsupported_version,
          "version != 1 must fail");

  auto bad_flags = notice_bytes;
  bad_flags[2] = 1U;
  res = decode_p2p_party_frame(P2pLane::control, bad_flags);
  require(!res.has_value() &&
              p2p_party_error_of(res.error()) == P2pPartyError::frame_non_zero_reserved,
          "non-zero flags must fail");

  auto trailing = notice_bytes;
  trailing.push_back(0x00U);
  res = decode_p2p_party_frame(P2pLane::control, trailing);
  require(!res.has_value() &&
              p2p_party_error_of(res.error()) == P2pPartyError::frame_trailing_bytes,
          "trailing bytes must fail");

  auto truncated = notice_bytes;
  truncated.pop_back();
  res = decode_p2p_party_frame(P2pLane::control, truncated);
  require(!res.has_value() &&
              p2p_party_error_of(res.error()) == P2pPartyError::frame_truncated,
          "truncated frame must fail");

  P2pPartyChatMessage oversized_scope = chat;
  oversized_scope.room_scope.assign(kP2pPartyMaxRoomScopeBytes + 1U, 'x');
  auto over_res = encode_p2p_party_frame(oversized_scope);
  require(!over_res.has_value() && p2p_party_error_of(over_res.error()) ==
                                       P2pPartyError::frame_field_too_large,
          "room_scope > 128 B must fail");

  P2pPartyChatMessage bad_utf8 = chat;
  bad_utf8.body = std::string{"\xff\xfe", 2U};
  over_res = encode_p2p_party_frame(bad_utf8);
  require(!over_res.has_value() &&
              p2p_party_error_of(over_res.error()) == P2pPartyError::frame_invalid_utf8,
          "invalid UTF-8 body must fail");

  P2pPartyEphemeralPulse oversized_status = pulse;
  oversized_status.status.assign(kP2pPartyMaxEphemeralStatusBytes + 1U, 'a');
  over_res = encode_p2p_party_frame(oversized_status);
  require(!over_res.has_value() && p2p_party_error_of(over_res.error()) ==
                                       P2pPartyError::frame_field_too_large,
          "ephemeral status > 256 B must fail");
}

void test_endpoint_descriptor_conversion_and_policy() {
  g_stage = "endpoint_descriptor_conversion_and_policy";

  const auto root = make_key(0x11U);
  const auto dev = make_key(0x12U);

  mp::EndpointDescriptor mixed{};
  mixed.transport_kind = mp::TransportKind::iroh_quic;
  mixed.relay_url = "https://relay.multiplayer.tech";
  mixed.direct_addrs.push_back(mp::DirectAddrV4{{203U, 0U, 113U, 5U}, 4433U});
  mixed.direct_addrs.push_back(mp::DirectAddrV6{
      {0x20U, 0x01U, 0x0dU, 0xb8U, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1U}, 5544U});

  const auto member = mint_member(
      root, MintMemberSpec{200U, 20U, dev.public_key(), mixed, 1000, 2000, 1U, true});

  // force_relays MUST force 0 direct_addrs even if caller passed some.
  const auto forced = must(
      endpoint_descriptor_to_p2p_target(member, mp::RelayPolicy::force_relays, 7500U),
      "force_relays target");
  require(forced.direct_addrs.empty(), "force_relays must strip all direct_addrs");
  require(forced.relay_url == "https://relay.multiplayer.tech",
          "force_relays must preserve relay_url");
  require(forced.remote_relay_policy == P2pRelayPolicy::force_relays,
          "remote_relay_policy mismatch");
  require(forced.connect_timeout_ms == 7500U, "connect_timeout_ms mismatch");

  // no_relays strips relay_url and converts v4 + v6 addrs accurately.
  const auto direct =
      must(endpoint_descriptor_to_p2p_target(member, mp::RelayPolicy::no_relays, 4000U),
           "no_relays target");
  require(direct.relay_url.empty(), "no_relays must strip relay_url");
  require(direct.direct_addrs.size() == 2U, "no_relays must keep v4+v6 addrs");
  require(direct.direct_addrs[0] == P2pDirectAddr::ipv4({203U, 0U, 113U, 5U}, 4433U),
          "IPv4 conversion mismatch");
  require(
      direct.direct_addrs[1] ==
          P2pDirectAddr::ipv6(
              {0x20U, 0x01U, 0x0dU, 0xb8U, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1U}, 5544U),
      "IPv6 conversion mismatch");

  // Finding 4 regressions: endpoint_descriptor_to_p2p_target must reject empty/invalid
  // relay_url under force_relays and invalid relay_url under allow_relays.
  auto empty_relay_member = member;
  empty_relay_member.endpoint.relay_url.clear();
  const auto force_empty = endpoint_descriptor_to_p2p_target(
      empty_relay_member, mp::RelayPolicy::force_relays, 4000U);
  require(!force_empty.has_value() && mp::mp_error_of(force_empty.error()) ==
                                          mp::MpError::force_relays_violation,
          "force_relays with empty relay_url must fail closed");

  // allow_relays with empty relay_url is valid.
  const auto allow_empty =
      must(endpoint_descriptor_to_p2p_target(empty_relay_member,
                                             mp::RelayPolicy::allow_relays, 4000U),
           "allow_relays with empty relay_url");
  require(allow_empty.relay_url.empty() && allow_empty.direct_addrs.size() == 2U,
          "allow_relays with empty relay_url must succeed");

  auto bad_http_member = member;
  bad_http_member.endpoint.relay_url = "http://relay.multiplayer.tech";
  const auto force_http = endpoint_descriptor_to_p2p_target(
      bad_http_member, mp::RelayPolicy::force_relays, 4000U);
  require(!force_http.has_value() &&
              mp::mp_error_of(force_http.error()) == mp::MpError::invalid_relay_url,
          "force_relays with non-HTTPS relay_url must fail closed");

  auto bad_query_member = member;
  bad_query_member.endpoint.relay_url = "https://relay.multiplayer.tech/?x=1";
  const auto allow_query = endpoint_descriptor_to_p2p_target(
      bad_query_member, mp::RelayPolicy::allow_relays, 4000U);
  require(!allow_query.has_value() &&
              mp::mp_error_of(allow_query.error()) == mp::MpError::invalid_relay_url,
          "allow_relays with malformed relay_url must fail closed");
}

void test_policy_immutability_epoch_bounds_max_members_and_rebind() {
  g_stage = "policy_immutability_epoch_bounds_max_members_and_rebind";

  const auto alice_acct = must(mp::AccountId::create(10U), "alice_acct");
  const auto alice_id = must(mp::DeviceId::create(100U), "alice_id");
  const auto bob_acct = must(mp::AccountId::create(20U), "bob_acct");
  const auto bob_id = must(mp::DeviceId::create(200U), "bob_id");
  const auto party_id = must(mp::PartyId::create(8008U), "party_id");

  const auto alice_dev = make_key(0x81U);
  const auto bob_root = make_key(0x82U);
  const auto bob_root2 = make_key(0x83U);
  const auto bob_dev = make_key(0x84U);
  const auto carol_root = make_key(0x85U);
  const auto carol_dev = make_key(0x86U);

  // 1. Finding 1: relay_policy and pinned_relay_url are immutable across snapshots.
  P2pPartySessionConfig force_cfg{alice_acct, alice_id};
  force_cfg.local_relay_policy = P2pRelayPolicy::force_relays;
  force_cfg.local_pubkey = alice_dev.public_key();
  auto force_sess = must(P2pPartySession::create_detached(force_cfg), "force_sess");

  const auto bob_force = mint_member(
      bob_root,
      MintMemberSpec{200U, 20U, bob_dev.public_key(),
                     make_force_relay_endpoint("https://relay.multiplayer.tech"), 900,
                     2000, 1U, true});
  mp::PartySnapshotMessage force_snap{
      party_id,
      1U,
      alice_acct,
      alice_id,
      mp::PartyVisibility::private_party,
      mp::PartyJoinMode::invite_only,
      mp::RelayPolicy::force_relays,
      2U,
      "https://relay.multiplayer.tech",
      {bob_force},
  };
  (void)must(force_sess.apply_snapshot(force_snap, 1000), "initial force snapshot");
  require(force_sess.max_members() == 2U, "max_members stored");

  // Mutating pinned_relay_url on subsequent snapshot must fail closed.
  auto redirect_snap = force_snap;
  redirect_snap.party_epoch = 2U;
  redirect_snap.pinned_relay_url = "https://relay2.multiplayer.tech";
  const auto redir_res = force_sess.apply_snapshot(redirect_snap, 1000);
  require(!redir_res.has_value() && p2p_party_error_of(redir_res.error()) ==
                                        P2pPartyError::relay_policy_mismatch,
          "subsequent snapshot changing pinned_relay_url must be rejected");
  require(force_sess.pinned_relay_url() == "https://relay.multiplayer.tech",
          "pinned_relay_url must remain unchanged after rejected snapshot");

  // Downgrading relay_policy on subsequent snapshot must fail closed.
  auto downgrade_snap = force_snap;
  downgrade_snap.party_epoch = 2U;
  downgrade_snap.relay_policy = mp::RelayPolicy::allow_relays;
  const auto down_res = force_sess.apply_snapshot(downgrade_snap, 1000);
  require(!down_res.has_value() && p2p_party_error_of(down_res.error()) ==
                                       P2pPartyError::relay_policy_mismatch,
          "subsequent snapshot changing relay_policy must be rejected");
  require(force_sess.relay_policy() == mp::RelayPolicy::force_relays,
          "relay_policy must remain unchanged after rejected snapshot");

  // Mutating max_members on subsequent snapshot must fail closed.
  auto resize_snap = force_snap;
  resize_snap.party_epoch = 2U;
  resize_snap.max_members = 4U;
  const auto resize_res = force_sess.apply_snapshot(resize_snap, 1000);
  require(!resize_res.has_value() && p2p_party_error_of(resize_res.error()) ==
                                         P2pPartyError::invalid_party_member_count,
          "subsequent snapshot changing max_members must be rejected");

  // 2. Finding 2: party_epoch safe-positive bounds (1..=kMaxSafeId) and max_members cap
  //    accounting for local self (no 13-member or max_members+1 overflow).
  P2pPartySessionConfig fresh_cfg{alice_acct, alice_id};
  fresh_cfg.local_relay_policy = P2pRelayPolicy::no_relays;
  fresh_cfg.local_pubkey = alice_dev.public_key();
  auto fresh_sess = must(P2pPartySession::create_detached(fresh_cfg), "fresh_sess");

  const auto bob_lan = mint_member(
      bob_root, MintMemberSpec{200U, 20U, bob_dev.public_key(),
                               make_lan_endpoint(4200U), 900, 2000, 1U, true});
  const auto carol_lan = mint_member(
      carol_root, MintMemberSpec{300U, 30U, carol_dev.public_key(),
                                 make_lan_endpoint(4300U), 900, 2000, 2U, true});

  mp::PartySnapshotMessage bad_epoch0{
      party_id,
      0U,
      alice_acct,
      alice_id,
      mp::PartyVisibility::private_party,
      mp::PartyJoinMode::invite_only,
      mp::RelayPolicy::no_relays,
      2U,
      "",
      {bob_lan},
  };
  auto err_res = fresh_sess.apply_snapshot(bad_epoch0, 1000);
  require(!err_res.has_value() &&
              p2p_party_error_of(err_res.error()) == P2pPartyError::invalid_party_epoch,
          "party_epoch == 0 must be rejected on first snapshot");

  auto bad_epoch_hi = bad_epoch0;
  bad_epoch_hi.party_epoch = mp::kMaxSafeId + 1U;
  err_res = fresh_sess.apply_snapshot(bad_epoch_hi, 1000);
  require(!err_res.has_value() &&
              p2p_party_error_of(err_res.error()) == P2pPartyError::invalid_party_epoch,
          "party_epoch > kMaxSafeId must be rejected on snapshot");

  auto bad_max1 = bad_epoch0;
  bad_max1.party_epoch = 1U;
  bad_max1.max_members = 1U;
  err_res = fresh_sess.apply_snapshot(bad_max1, 1000);
  require(!err_res.has_value() && p2p_party_error_of(err_res.error()) ==
                                      P2pPartyError::invalid_party_member_count,
          "max_members < 2 must be rejected");

  auto bad_max13 = bad_max1;
  bad_max13.max_members = 13U;
  err_res = fresh_sess.apply_snapshot(bad_max13, 1000);
  require(!err_res.has_value() && p2p_party_error_of(err_res.error()) ==
                                      P2pPartyError::invalid_party_member_count,
          "max_members > 12 must be rejected");

  // Snapshot with max_members=2 and 2 remote members (omitting self) must admit at most
  // 1 remote member (self + 1 remote = 2) and reject the overflow member.
  mp::PartySnapshotMessage two_cap_snap{
      party_id,
      1U,
      alice_acct,
      alice_id,
      mp::PartyVisibility::private_party,
      mp::PartyJoinMode::invite_only,
      mp::RelayPolicy::no_relays,
      2U,
      "",
      {bob_lan, carol_lan},
  };
  const auto two_cap_report =
      must(fresh_sess.apply_snapshot(two_cap_snap, 1000), "apply two_cap_snap");
  require(two_cap_report.admitted_peers.size() == 1U &&
              two_cap_report.admitted_peers[0] == bob_id,
          "max_members=2 must admit only 1 remote peer alongside local self");
  require(two_cap_report.rejected_members.size() == 1U &&
              p2p_party_error_of(two_cap_report.rejected_members[0].error) ==
                  P2pPartyError::invalid_party_member_count,
          "2nd remote peer in max_members=2 snapshot must be rejected");

  // Joining a 2nd remote peer into max_members=2 party must fail closed!
  const auto over_join =
      fresh_sess.apply_member_joined(mp::PartyMemberJoinedMessage{2U, carol_lan}, 1000);
  require(!over_join.has_value() && p2p_party_error_of(over_join.error()) ==
                                        P2pPartyError::invalid_party_member_count,
          "join exceeding max_members (including local self) must fail closed");

  // All lifecycle handlers reject party_epoch == 0 and > kMaxSafeId.
  for (const std::uint64_t bad_ep : {std::uint64_t{0U}, mp::kMaxSafeId + 1U}) {
    auto r1 = fresh_sess.apply_member_joined(
        mp::PartyMemberJoinedMessage{bad_ep, bob_lan}, 1000);
    require(!r1.has_value() &&
                p2p_party_error_of(r1.error()) == P2pPartyError::invalid_party_epoch,
            "join bad epoch");
    auto r2 = fresh_sess.apply_member_updated(
        mp::PartyMemberUpdatedMessage{bad_ep, bob_id, true, bob_lan.device_cwt,
                                      bob_lan.endpoint},
        1000);
    require(!r2.has_value() &&
                p2p_party_error_of(r2.error()) == P2pPartyError::invalid_party_epoch,
            "update bad epoch");
    auto r3 = fresh_sess.apply_member_left(mp::PartyMemberLeftMessage{
        bad_ep, bob_id, bob_acct, mp::MemberLeaveReason::left});
    require(!r3.has_value() &&
                p2p_party_error_of(r3.error()) == P2pPartyError::invalid_party_epoch,
            "left bad epoch");
    auto r4 = fresh_sess.apply_leader_changed(mp::PartyLeaderChangedMessage{
        bad_ep, bob_acct, bob_id, mp::PartyLeaderChangeReason::promoted});
    require(!r4.has_value() &&
                p2p_party_error_of(r4.error()) == P2pPartyError::invalid_party_epoch,
            "leader_changed bad epoch");
    auto r5 = fresh_sess.apply_disbanded(
        mp::PartyDisbandedMessage{bad_ep, mp::PartyDisbandReason::leader_disbanded});
    require(!r5.has_value() &&
                p2p_party_error_of(r5.error()) == P2pPartyError::invalid_party_epoch,
            "disbanded bad epoch");
  }

  // 3. Finding 3 (detached): Rebinding bob's device_pubkey to a different device_id or
  //    account_id/root_pubkey revokes the prior binding and resets connected state.
  (void)fresh_sess.ingest_transport_event(
      P2pEvent{
          P2pEventKind::peer_connected, P2pLane::control, bob_dev.public_key(), {}, 0U},
      1005);
  const auto before_rebind = fresh_sess.find_peer(bob_id);
  require(before_rebind.has_value() &&
              before_rebind->connection_state == P2pPeerConnectionState::connected,
          "bob connected before rebind");

  // Rebind same device_pubkey to a new device_id=250 via snapshot.
  const auto bob_rebound_dev = mint_member(
      bob_root, MintMemberSpec{250U, 20U, bob_dev.public_key(),
                               make_lan_endpoint(4200U), 900, 2000, 3U, true});
  auto rebind_snap = two_cap_snap;
  rebind_snap.party_epoch = 2U;
  rebind_snap.members = {bob_rebound_dev};
  const auto rebind_report =
      must(fresh_sess.apply_snapshot(rebind_snap, 1010), "rebind device_id snapshot");
  require(rebind_report.revoked_peers.size() == 1U &&
              rebind_report.revoked_peers[0] == bob_id,
          "rebinding device_pubkey to new device_id must revoke prior peer");
  const auto dev250 = must(mp::DeviceId::create(250U), "dev250");
  const auto after_dev_rebind = fresh_sess.find_peer(dev250);
  require(after_dev_rebind.has_value() && after_dev_rebind->connection_state ==
                                              P2pPeerConnectionState::dial_pending,
          "rebound device must reset connection_state to dial_pending");

  // Mark dev250 connected, then rebind same device_id+device_pubkey to a new
  // root_pubkey via apply_member_joined -> must reset connection_state from connected
  // to dial_pending.
  (void)fresh_sess.ingest_transport_event(
      P2pEvent{
          P2pEventKind::peer_connected, P2pLane::control, bob_dev.public_key(), {}, 0U},
      1015);
  const auto dev250_new_root = mint_member(
      bob_root2, MintMemberSpec{250U, 25U, bob_dev.public_key(),
                                make_lan_endpoint(4200U), 900, 2000, 4U, true});
  must_void(fresh_sess.apply_member_joined(
                mp::PartyMemberJoinedMessage{3U, dev250_new_root}, 1020),
            "rebind account_id/root_pubkey on join");
  const auto after_root_rebind = fresh_sess.find_peer(dev250);
  require(after_root_rebind.has_value() &&
              after_root_rebind->connection_state ==
                  P2pPeerConnectionState::dial_pending &&
              after_root_rebind->root_pubkey == bob_root2.public_key(),
          "rebinding account_id/root_pubkey on join must reset connected state");
}

void test_detached_cwt_policy_epoch_anti_spoofing_and_eviction() {
  g_stage = "detached_cwt_policy_epoch_anti_spoofing_and_eviction";

  const auto alice_root = make_key(0x21U);
  const auto alice_dev = make_key(0x22U);
  const auto bob_root = make_key(0x31U);
  const auto bob_dev = make_key(0x32U);
  const auto mallory_root = make_key(0x41U);
  const auto mallory_dev = make_key(0x42U);
  const auto wrong_root = make_key(0x51U);
  const auto carol_root = make_key(0x61U);
  const auto carol_dev = make_key(0x62U);

  const auto party_id = must(mp::PartyId::create(9001U), "party_id");
  const auto alice_acct = must(mp::AccountId::create(10U), "alice_acct");
  const auto alice_id = must(mp::DeviceId::create(100U), "alice_id");
  const auto bob_acct = must(mp::AccountId::create(20U), "bob_acct");
  const auto bob_id = must(mp::DeviceId::create(200U), "bob_id");
  const auto mallory_id = must(mp::DeviceId::create(300U), "mallory_id");
  const auto carol_id = must(mp::DeviceId::create(400U), "carol_id");

  P2pPartySessionConfig cfg{alice_acct, alice_id};
  cfg.local_relay_policy = P2pRelayPolicy::no_relays;
  cfg.local_pubkey = alice_dev.public_key();
  cfg.max_lease_ttl_s = 60;
  cfg.auto_dial = false;
  cfg.allow_loopback_direct_addrs = false; // Strict production validation

  auto session = must(P2pPartySession::create_detached(cfg), "create_detached");

  // 1. Relay policy mismatch: no_relays local session rejects force_relays party.
  mp::PartySnapshotMessage force_snap{
      party_id,
      1U,
      alice_acct,
      alice_id,
      mp::PartyVisibility::private_party,
      mp::PartyJoinMode::invite_only,
      mp::RelayPolicy::force_relays,
      4U,
      "https://relay.multiplayer.tech",
      {},
  };
  const auto mismatch = session.apply_snapshot(force_snap, 1000);
  require(!mismatch.has_value() && p2p_party_error_of(mismatch.error()) ==
                                       P2pPartyError::relay_policy_mismatch,
          "no_relays local must reject force_relays party snapshot");

  // 2. force_relays session rejects direct addrs in member endpoint.
  P2pPartySessionConfig force_cfg{alice_acct, alice_id};
  force_cfg.local_relay_policy = P2pRelayPolicy::force_relays;
  force_cfg.local_pubkey = alice_dev.public_key();
  auto force_session =
      must(P2pPartySession::create_detached(force_cfg), "create force_relays detached");
  const auto bad_force_member = mint_member(
      bob_root,
      MintMemberSpec{200U, 20U, bob_dev.public_key(),
                     make_public_endpoint(4433U, "https://relay.multiplayer.tech"), 900,
                     2000, 1U, true});
  force_snap.members = {bad_force_member};
  const auto force_report = must(force_session.apply_snapshot(force_snap, 1000),
                                 "force_relays snapshot with bad member");
  require(force_report.admitted_peers.empty(),
          "force_relays must not admit peer with direct_addrs");
  require(force_report.rejected_members.size() == 1U &&
              mp::mp_error_of(force_report.rejected_members[0].error) ==
                  mp::MpError::force_relays_violation,
          "force_relays violation must be reported");

  // Also valid force_relays member IS admitted cleanly.
  const auto good_force_member = mint_member(
      bob_root,
      MintMemberSpec{200U, 20U, bob_dev.public_key(),
                     make_force_relay_endpoint("https://relay.multiplayer.tech"), 900,
                     2000, 1U, true});
  must_void(force_session.apply_member_joined(
                mp::PartyMemberJoinedMessage{2U, good_force_member}, 1000),
            "admit valid force_relays member");
  require(force_session.peer_count() == 1U, "valid force_relays peer admitted");

  // 3. Production default strictly rejects 127.0.0.1 loopback in EndpointDescriptor.
  mp::EndpointDescriptor loopback_ep{};
  loopback_ep.transport_kind = mp::TransportKind::iroh_quic;
  loopback_ep.direct_addrs.push_back(mp::DirectAddrV4{{127U, 0U, 0U, 1U}, 4433U});

  const auto alice_rec = mint_member(
      alice_root, MintMemberSpec{100U, 10U, alice_dev.public_key(),
                                 make_lan_endpoint(4100U), 900, 2000, 1U, true});
  const auto bob_rec = mint_member(
      bob_root, MintMemberSpec{200U, 20U, bob_dev.public_key(),
                               make_lan_endpoint(4200U), 900, 2000, 2U, true});

  // Mallory with forged signature.
  auto mallory_forged = mint_member(
      mallory_root, MintMemberSpec{300U, 30U, mallory_dev.public_key(),
                                   make_lan_endpoint(4300U), 900, 2000, 3U, true});
  mallory_forged.device_cwt.back() ^= 0x55U;

  // Carol with duplicate pubkey (claiming Bob's device_pubkey under device_id=400).
  const auto carol_dup_pk = mint_member(
      carol_root, MintMemberSpec{400U, 40U, bob_dev.public_key(),
                                 make_lan_endpoint(4400U), 900, 2000, 4U, true});

  // Device 500 with loopback direct addr (must be rejected when allow_loopback=false).
  const auto loopback_dev = make_key(0x72U);
  const auto loopback_rec =
      mint_member(carol_root, MintMemberSpec{500U, 50U, loopback_dev.public_key(),
                                             loopback_ep, 900, 2000, 5U, true});

  mp::PartySnapshotMessage snap{
      party_id,
      5U,
      alice_acct,
      alice_id,
      mp::PartyVisibility::private_party,
      mp::PartyJoinMode::invite_only,
      mp::RelayPolicy::no_relays,
      8U,
      "",
      {alice_rec, bob_rec, mallory_forged, carol_dup_pk, loopback_rec},
  };
  const auto report = must(session.apply_snapshot(snap, 1000), "apply_snapshot");
  require(report.admitted_peers.size() == 1U && report.admitted_peers[0] == bob_id,
          "only Bob must be admitted (self skipped, bad peers rejected)");
  require(report.rejected_members.size() == 3U,
          "forged CWT, duplicate pubkey, and loopback addr must all be rejected");
  require(session.peer_count() == 1U, "roster must contain only Bob");
  const auto bob_peer = session.find_peer(bob_id);
  require(bob_peer.has_value() && bob_peer->we_dial && bob_peer->cwt_exp_s == 2000,
          "Alice (100) must have we_dial=true for Bob (200) with cwt_exp_s=2000");

  // 4. Reject wrong-root, future-iat, and expired CWTs on apply_member_joined.
  auto mallory_wrong_root = mint_member(
      wrong_root, MintMemberSpec{300U, 30U, mallory_dev.public_key(),
                                 make_lan_endpoint(4300U), 900, 2000, 6U, true});
  mallory_wrong_root.root_pubkey = mallory_root.public_key();
  auto join_res = session.apply_member_joined(
      mp::PartyMemberJoinedMessage{6U, mallory_wrong_root}, 1000);
  require(!join_res.has_value(), "wrong-root CWT must be rejected");

  const auto mallory_future = mint_member(
      mallory_root, MintMemberSpec{300U, 30U, mallory_dev.public_key(),
                                   make_lan_endpoint(4300U), 1200, 2000, 6U, true});
  join_res = session.apply_member_joined(
      mp::PartyMemberJoinedMessage{6U, mallory_future}, 1000);
  require(!join_res.has_value() &&
              mp::mp_error_of(join_res.error()) == mp::MpError::cwt_future_issued_at,
          "future-iat CWT must be rejected");

  const auto mallory_expired = mint_member(
      mallory_root, MintMemberSpec{300U, 30U, mallory_dev.public_key(),
                                   make_lan_endpoint(4300U), 800, 1000, 6U, true});
  join_res = session.apply_member_joined(
      mp::PartyMemberJoinedMessage{6U, mallory_expired}, 1000);
  require(!join_res.has_value() &&
              mp::mp_error_of(join_res.error()) == mp::MpError::cwt_expired,
          "expired CWT must be rejected");

  // Duplicate pubkey on join must fail closed.
  join_res =
      session.apply_member_joined(mp::PartyMemberJoinedMessage{6U, carol_dup_pk}, 1000);
  require(!join_res.has_value() && p2p_party_error_of(join_res.error()) ==
                                       P2pPartyError::duplicate_device_pubkey,
          "duplicate pubkey on join must fail closed");

  // 5. Monotonic party_epoch enforcement (stale replay rejected).
  auto stale_snap = snap;
  stale_snap.party_epoch = 4U;
  const auto stale_res = session.apply_snapshot(stale_snap, 1000);
  require(!stale_res.has_value() &&
              p2p_party_error_of(stale_res.error()) == P2pPartyError::stale_party_epoch,
          "stale snapshot party_epoch must be rejected");

  const auto stale_leader = session.apply_leader_changed(mp::PartyLeaderChangedMessage{
      4U, bob_acct, bob_id, mp::PartyLeaderChangeReason::promoted});
  require(!stale_leader.has_value() && p2p_party_error_of(stale_leader.error()) ==
                                           P2pPartyError::stale_party_epoch,
          "stale leader_changed must be rejected");

  // Valid leader change advances epoch & leader.
  must_void(session.apply_leader_changed(mp::PartyLeaderChangedMessage{
                6U, bob_acct, bob_id, mp::PartyLeaderChangeReason::promoted}),
            "apply_leader_changed");
  require(session.party_epoch() == 6U && session.leader_device_id() == bob_id &&
              session.leader_account_id() == bob_acct,
          "leader_changed must update epoch and leader");

  // 6. Strict anti-spoofing attribution via ingest_transport_event.
  //    Bob sends a chat claiming sender_handle="alice-impersonator", but event MUST
  //    attribute sender_device_id=200 & sender_account_id=20 from Bob's RPK pubkey!
  const P2pPartyChatMessage spoof_attempt{
      "party/main", "@all", "alice-impersonator", 123456789LL, "pretending to be alice",
  };
  const auto spoof_wire = must(encode_p2p_party_frame(spoof_attempt), "encode spoof");
  const P2pEvent bob_wire_ev{
      P2pEventKind::frame_received,
      P2pLane::causal,
      bob_dev.public_key(),
      spoof_wire,
      0U,
  };
  const auto attributed = session.ingest_transport_event(bob_wire_ev, 1010);
  require(attributed.kind == P2pPartyEventKind::frame_received,
          "verified peer frame must be delivered");
  require(attributed.sender_device_id == bob_id &&
              attributed.sender_account_id == bob_acct,
          "sender attribution must come exclusively from verified RPK pubkey");

  // Frame from unknown pubkey (Mallory) MUST be dropped.
  const P2pEvent mallory_wire_ev{
      P2pEventKind::frame_received,
      P2pLane::causal,
      mallory_dev.public_key(),
      spoof_wire,
      0U,
  };
  const auto dropped_unknown = session.ingest_transport_event(mallory_wire_ev, 1010);
  require(dropped_unknown.kind == P2pPartyEventKind::frame_dropped &&
              !dropped_unknown.sender_device_id.has_value() &&
              dropped_unknown.drop_error.has_value() &&
              p2p_party_error_of(*dropped_unknown.drop_error) ==
                  P2pPartyError::frame_unverified_sender,
          "frame from unverified pubkey must be dropped");

  // 7. Lease-TTL eviction (60s since confirmation at t=1000 -> evicted at t=1061).
  require(must(session.evict_expired_peers(1060), "evict at 1060").empty(),
          "peer within 60s lease TTL must remain");
  const auto evicted = must(session.evict_expired_peers(1061), "evict at 1061");
  require(evicted.size() == 1U && evicted[0] == bob_id,
          "peer past 60s lease TTL must be evicted");
  require(session.peer_count() == 0U, "roster must be empty after lease eviction");

  // Re-admit Carol with fresh CWT, then disband and verify subsequent joins fail
  // closed.
  const auto carol_valid = mint_member(
      carol_root, MintMemberSpec{400U, 40U, carol_dev.public_key(),
                                 make_lan_endpoint(4400U), 1050, 1500, 7U, true});
  must_void(
      session.apply_member_joined(mp::PartyMemberJoinedMessage{7U, carol_valid}, 1070),
      "join carol");
  require(session.peer_count() == 1U, "carol admitted");
  must_void(session.apply_disbanded(mp::PartyDisbandedMessage{
                8U, mp::PartyDisbandReason::leader_disbanded}),
            "apply_disbanded");
  require(session.disbanded() && session.peer_count() == 0U,
          "disbanded session must clear roster");
  const auto after_disband_join =
      session.apply_member_joined(mp::PartyMemberJoinedMessage{9U, carol_valid}, 1075);
  require(!after_disband_join.has_value() &&
              p2p_party_error_of(after_disband_join.error()) ==
                  P2pPartyError::session_disbanded,
          "joins after disband must fail closed");
  const auto after_disband_send = session.broadcast_chat(spoof_attempt);
  require(!after_disband_send.has_value() &&
              p2p_party_error_of(after_disband_send.error()) ==
                  P2pPartyError::session_disbanded,
          "sends after disband must fail closed");
  (void)mallory_id;
  (void)carol_id;
}

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH

mp::EndpointDescriptor
endpoint_from_p2p_addrs(const std::vector<P2pDirectAddr> &addrs) {
  mp::EndpointDescriptor ep{};
  ep.transport_kind = mp::TransportKind::iroh_quic;
  for (const auto &a : addrs) {
    ep.direct_addrs.push_back(must(p2p_direct_addr_to_mp(a), "p2p_direct_addr_to_mp"));
  }
  return ep;
}

P2pPartyEvent wait_for_party_event(P2pPartySession &session,
                                   P2pPartyEventKind expected_kind,
                                   PartyNowSeconds now_s,
                                   PollTimeoutMs max_wait_ms = PollTimeoutMs{5000U}) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(max_wait_ms.value);
  while (std::chrono::steady_clock::now() < deadline) {
    auto polled = must(session.poll_event(PollTimeoutMs{200U}, now_s), "poll");
    if (!polled.has_value()) {
      continue;
    }
    if (polled->kind == expected_kind) {
      return std::move(*polled);
    }
  }
  throw std::runtime_error(std::string{g_stage} +
                           ": timed out waiting for party event");
}

void test_live_iroh_party_mesh_end_to_end() {
  g_stage = "live_iroh_party_mesh_end_to_end";

  const std::int64_t t0 = 10000;
  const std::int64_t cwt_exp = t0 + 120;

  const auto party_id = must(mp::PartyId::create(7777U), "party_id");
  const auto alice_acct = must(mp::AccountId::create(1001U), "alice_acct");
  const auto alice_id = must(mp::DeviceId::create(100U), "alice_id");
  const auto bob_acct = must(mp::AccountId::create(2002U), "bob_acct");
  const auto bob_id = must(mp::DeviceId::create(200U), "bob_id");
  const auto mallory_acct = must(mp::AccountId::create(3003U), "mallory_acct");
  const auto mallory_id = must(mp::DeviceId::create(300U), "mallory_id");

  const auto alice_root = make_key(0xA1U);
  const auto bob_root = make_key(0xB1U);
  const auto mallory_root = make_key(0xC1U);

  P2pEndpointConfig ep_cfg{};
  ep_cfg.relay_policy = P2pRelayPolicy::no_relays;

  auto alice_ep = must(P2pEndpoint::create(ep_cfg), "create alice endpoint");
  auto bob_ep = must(P2pEndpoint::create(ep_cfg), "create bob endpoint");
  auto mallory_ep = must(P2pEndpoint::create(ep_cfg), "create mallory endpoint");

  const auto alice_pk = must(alice_ep.local_pubkey(), "alice pk");
  const auto bob_pk = must(bob_ep.local_pubkey(), "bob pk");
  const auto mallory_pk = must(mallory_ep.local_pubkey(), "mallory pk");

  const auto alice_addrs = must(alice_ep.local_direct_addrs(), "alice addrs");
  const auto bob_addrs = must(bob_ep.local_direct_addrs(), "bob addrs");
  const auto mallory_addrs = must(mallory_ep.local_direct_addrs(), "mallory addrs");
  require(!alice_addrs.empty() && !bob_addrs.empty() && !mallory_addrs.empty(),
          "live endpoints must expose local direct addrs");

  P2pPartySessionConfig alice_cfg{alice_acct, alice_id};
  alice_cfg.local_relay_policy = P2pRelayPolicy::no_relays;
  alice_cfg.local_pubkey = alice_pk;
  alice_cfg.max_lease_ttl_s = std::nullopt; // Test explicit CWT exp eviction cleanly
  alice_cfg.auto_dial = false;              // Exercise explicit connect_pending_peers()
  alice_cfg.allow_loopback_direct_addrs = true;

  P2pPartySessionConfig bob_cfg{bob_acct, bob_id};
  bob_cfg.local_relay_policy = P2pRelayPolicy::no_relays;
  bob_cfg.local_pubkey = bob_pk;
  bob_cfg.max_lease_ttl_s = std::nullopt;
  bob_cfg.auto_dial = true;
  bob_cfg.allow_loopback_direct_addrs = true;

  auto alice = must(P2pPartySession::create(alice_cfg, std::move(alice_ep)),
                    "create alice session");
  auto bob =
      must(P2pPartySession::create(bob_cfg, std::move(bob_ep)), "create bob session");

  const auto alice_rec =
      mint_member(alice_root, MintMemberSpec{100U, 1001U, alice_pk,
                                             endpoint_from_p2p_addrs(alice_addrs),
                                             t0 - 10, cwt_exp, 1U, true});
  const auto bob_rec = mint_member(
      bob_root, MintMemberSpec{200U, 2002U, bob_pk, endpoint_from_p2p_addrs(bob_addrs),
                               t0 - 10, cwt_exp, 2U, true});

  // Mallory has a forged CWT signature -> rejected before iroh allowlist admission!
  auto mallory_forged =
      mint_member(mallory_root, MintMemberSpec{300U, 3003U, mallory_pk,
                                               endpoint_from_p2p_addrs(mallory_addrs),
                                               t0 - 10, cwt_exp, 3U, true});
  mallory_forged.device_cwt[mallory_forged.device_cwt.size() - 1U] ^= 0xAAU;

  mp::PartySnapshotMessage snapshot{
      party_id,
      1U,
      alice_acct,
      alice_id,
      mp::PartyVisibility::private_party,
      mp::PartyJoinMode::invite_only,
      mp::RelayPolicy::no_relays,
      4U,
      "",
      {alice_rec, bob_rec, mallory_forged},
  };

  // Bob (device_id=200 > 100) applies snapshot first: allowlists Alice, rejects
  // Mallory, does NOT dial (higher device_id accepts).
  const auto bob_snap_res =
      must(bob.apply_snapshot(snapshot, t0), "bob apply_snapshot");
  require(bob_snap_res.admitted_peers.size() == 1U &&
              bob_snap_res.admitted_peers[0] == alice_id,
          "bob must admit only alice");
  require(bob_snap_res.rejected_members.size() == 1U &&
              bob_snap_res.rejected_members[0].device_id == mallory_id,
          "bob must reject mallory forged CWT");
  const auto bob_view_of_alice = bob.find_peer(alice_id);
  require(bob_view_of_alice.has_value() && !bob_view_of_alice->we_dial,
          "bob (200) must NOT dial alice (100)");

  // Mallory attempts live QUIC connect to Bob -> MUST fail at iroh EndpointHooks!
  const std::array<P2pPubkey, 1> mallory_allows_bob = {bob_pk};
  must_void(mallory_ep.set_allowed_peers(mallory_allows_bob), "mallory allow bob");
  const auto bob_target = must(
      endpoint_descriptor_to_p2p_target(bob_rec, mp::RelayPolicy::no_relays, 3000U),
      "bob target");
  const auto mallory_dial = mallory_ep.connect_peer(bob_target);
  require(!mallory_dial.has_value() &&
              mallory_dial.error().code == ErrorCode::invalid_identity,
          "rejected mallory must be blocked by iroh allowlist");

  // Alice (device_id=100 < 200) applies snapshot with auto_dial=false: allowlists Bob,
  // rejects Mallory, marks Bob dial_pending, then connect_pending_peers() dials Bob!
  const auto alice_snap_res =
      must(alice.apply_snapshot(snapshot, t0), "alice apply_snapshot");
  require(alice_snap_res.admitted_peers.size() == 1U &&
              alice_snap_res.admitted_peers[0] == bob_id,
          "alice must admit only bob");
  require(alice_snap_res.rejected_members.size() == 1U &&
              alice_snap_res.rejected_members[0].device_id == mallory_id,
          "alice must reject mallory forged CWT");
  const auto alice_view_of_bob = alice.find_peer(bob_id);
  require(alice_view_of_bob.has_value() && alice_view_of_bob->we_dial &&
              alice_view_of_bob->connection_state ==
                  P2pPeerConnectionState::dial_pending,
          "alice must mark bob dial_pending before connect_pending_peers");
  const auto conn_res =
      must(alice.connect_pending_peers(), "alice connect_pending_peers");
  require(conn_res.attempted == 1U && conn_res.connected == 1U &&
              conn_res.failures.empty(),
          "alice connect_pending_peers must connect bob");
  // Bob calling connect_pending_peers must attempt 0 (higher device_id never dials).
  const auto bob_conn_res =
      must(bob.connect_pending_peers(), "bob connect_pending_peers");
  require(bob_conn_res.attempted == 0U && bob_conn_res.connected == 0U,
          "bob (200) must never initiate outbound dial to alice (100)");

  const auto alice_conn =
      wait_for_party_event(alice, P2pPartyEventKind::peer_connected, t0);
  require(alice_conn.sender_device_id == bob_id &&
              alice_conn.sender_account_id == bob_acct &&
              alice_conn.peer_pubkey == bob_pk,
          "alice peer_connected attribution mismatch");

  const auto bob_conn =
      wait_for_party_event(bob, P2pPartyEventKind::peer_connected, t0);
  require(bob_conn.sender_device_id == alice_id &&
              bob_conn.sender_account_id == alice_acct &&
              bob_conn.peer_pubkey == alice_pk,
          "bob peer_connected attribution mismatch");

  // Exchange all 4 typed frame kinds across Lanes 0, 1, 2 in both directions.
  const P2pPartyChatMessage a_chat{"party/flight-deck", "@bob", "alice-handle",
                                   100001LL, "hello bob on reliable causal lane 1"};
  const auto a_chat_res = must(alice.broadcast_chat(a_chat), "alice broadcast_chat");
  require(a_chat_res.sent == 1U && a_chat_res.failures.empty(), "alice chat sent=1");

  const auto b_got_chat =
      wait_for_party_event(bob, P2pPartyEventKind::frame_received, t0);
  require(
      b_got_chat.lane == P2pLane::causal && b_got_chat.sender_device_id == alice_id &&
          b_got_chat.sender_account_id == alice_acct && b_got_chat.frame.has_value() &&
          std::get<P2pPartyChatMessage>(*b_got_chat.frame) == a_chat,
      "bob received chat mismatch or bad attribution");

  const P2pPartyBridgeEnvelope b_bridge{"party/board",
                                        std::vector<std::uint8_t>(48U * 1024U, 0x5AU)};
  must_void(bob.send_bridge_envelope_to(alice_id, b_bridge),
            "bob send_bridge_envelope");
  const auto a_got_bridge =
      wait_for_party_event(alice, P2pPartyEventKind::frame_received, t0);
  require(a_got_bridge.lane == P2pLane::causal &&
              a_got_bridge.sender_device_id == bob_id &&
              a_got_bridge.sender_account_id == bob_acct &&
              a_got_bridge.frame.has_value() &&
              std::get<P2pPartyBridgeEnvelope>(*a_got_bridge.frame) == b_bridge,
          "alice received bridge_envelope mismatch");

  const P2pPartyControlNotice a_notice{P2pPartyControlNoticeKind::sync_ack, 1U,
                                       "epoch-1-synced"};
  const auto a_notice_res =
      must(alice.broadcast_control_notice(a_notice), "alice broadcast_control_notice");
  require(a_notice_res.sent == 1U, "control_notice sent=1");
  const auto b_got_notice =
      wait_for_party_event(bob, P2pPartyEventKind::frame_received, t0);
  require(b_got_notice.lane == P2pLane::control &&
              b_got_notice.sender_device_id == alice_id &&
              b_got_notice.sender_account_id == alice_acct &&
              b_got_notice.frame.has_value() &&
              std::get<P2pPartyControlNotice>(*b_got_notice.frame) == a_notice,
          "bob received control_notice mismatch");

  const P2pPartyEphemeralPulse b_pulse{P2pPartyActivityState::working, 200002LL,
                                       "compiling wave 11b"};
  const auto b_pulse_res =
      must(bob.broadcast_ephemeral_pulse(b_pulse), "bob broadcast_ephemeral_pulse");
  require(b_pulse_res.sent == 1U, "ephemeral_pulse sent=1");
  const auto a_got_pulse =
      wait_for_party_event(alice, P2pPartyEventKind::frame_received, t0);
  require(a_got_pulse.lane == P2pLane::ephemeral &&
              a_got_pulse.sender_device_id == bob_id &&
              a_got_pulse.sender_account_id == bob_acct &&
              a_got_pulse.frame.has_value() &&
              std::get<P2pPartyEphemeralPulse>(*a_got_pulse.frame) == b_pulse,
          "alice received ephemeral_pulse mismatch");

  // 2. apply_member_left(device_revoked) on Alice IMMEDIATELY tears down Bob's QUIC
  //    connection with close code 4403 and subsequent sends fail closed.
  must_void(alice.apply_member_left(mp::PartyMemberLeftMessage{
                2U, bob_id, bob_acct, mp::MemberLeaveReason::device_revoked}),
            "alice apply_member_left(device_revoked)");
  require(alice.peer_count() == 0U, "alice roster must remove revoked bob");

  const auto alice_disc =
      wait_for_party_event(alice, P2pPartyEventKind::peer_disconnected, t0);
  require(alice_disc.peer_pubkey == bob_pk && alice_disc.reason_code == 4403U,
          "alice must observe 4403 disconnect for revoked bob");

  const auto bob_disc =
      wait_for_party_event(bob, P2pPartyEventKind::peer_disconnected, t0);
  require(bob_disc.peer_pubkey == alice_pk && bob_disc.reason_code == 4403U,
          "bob must immediately observe QUIC close code 4403 on revoke");

  const auto fail_send_alice = alice.send_chat_to(bob_id, a_chat);
  require(!fail_send_alice.has_value() && p2p_party_error_of(fail_send_alice.error()) ==
                                              P2pPartyError::peer_not_found,
          "alice send to revoked bob must fail closed");

  // 3. Re-admit Bob via apply_member_joined, verify reconnection, then test
  //    evict_expired_peers(cwt_exp + 1) tearing down the live QUIC connection!
  must_void(alice.apply_member_joined(mp::PartyMemberJoinedMessage{3U, bob_rec}, t0),
            "alice re-admit bob");
  const auto reconn_res =
      must(alice.connect_pending_peers(), "alice connect_pending_peers reconnect");
  require(reconn_res.attempted == 1U && reconn_res.connected == 1U,
          "alice reconnect must succeed");
  const auto alice_reconn =
      wait_for_party_event(alice, P2pPartyEventKind::peer_connected, t0);
  require(alice_reconn.sender_device_id == bob_id, "alice reconnected to bob");
  const auto bob_reconn =
      wait_for_party_event(bob, P2pPartyEventKind::peer_connected, t0);
  require(bob_reconn.sender_device_id == alice_id, "bob accepted alice reconnect");

  const auto evicted =
      must(alice.evict_expired_peers(cwt_exp + 1), "evict_expired_peers(exp+1)");
  require(evicted.size() == 1U && evicted[0] == bob_id,
          "evict_expired_peers must evict bob past cwt_exp");
  require(alice.peer_count() == 0U, "alice roster empty after CWT eviction");

  const auto alice_evict_disc =
      wait_for_party_event(alice, P2pPartyEventKind::peer_disconnected, cwt_exp + 1);
  require(alice_evict_disc.peer_pubkey == bob_pk &&
              alice_evict_disc.reason_code == 4403U,
          "CWT eviction must tear down QUIC with 4403 on alice");
  const auto bob_evict_disc =
      wait_for_party_event(bob, P2pPartyEventKind::peer_disconnected, t0);
  require(bob_evict_disc.peer_pubkey == alice_pk && bob_evict_disc.reason_code == 4403U,
          "CWT eviction must tear down QUIC with 4403 on bob");

  // 4. Finding 3 live iroh regression: Mint longer-lived CWTs, reconnect, then rebind
  //    bob_pk to a new account_id/root_pubkey via apply_snapshot -> MUST immediately
  //    revoke the live QUIC connection with close code 4403!
  const std::int64_t t1 = cwt_exp + 10;
  const std::int64_t cwt_exp2 = t1 + 300;
  const auto bob_rec2 = mint_member(
      bob_root, MintMemberSpec{200U, 2002U, bob_pk, endpoint_from_p2p_addrs(bob_addrs),
                               t1 - 5, cwt_exp2, 4U, true});
  const auto alice_rec2 =
      mint_member(alice_root, MintMemberSpec{100U, 1001U, alice_pk,
                                             endpoint_from_p2p_addrs(alice_addrs),
                                             t1 - 5, cwt_exp2, 4U, true});
  must_void(bob.apply_member_updated(
                mp::PartyMemberUpdatedMessage{4U, alice_id, true, alice_rec2.device_cwt,
                                              alice_rec2.endpoint},
                t1),
            "bob update alice CWT");
  must_void(alice.apply_member_joined(mp::PartyMemberJoinedMessage{4U, bob_rec2}, t1),
            "alice re-join bob with fresh CWT");
  const auto reconn2_res =
      must(alice.connect_pending_peers(), "alice connect_pending_peers reconnect 2");
  require(reconn2_res.attempted == 1U && reconn2_res.connected == 1U,
          "alice reconnect 2 must succeed");
  (void)wait_for_party_event(alice, P2pPartyEventKind::peer_connected, t1);
  (void)wait_for_party_event(bob, P2pPartyEventKind::peer_connected, t1);

  const auto bob_alt_root = make_key(0xD1U);
  const auto bob_rebound_rec =
      mint_member(bob_alt_root, MintMemberSpec{200U, 2999U, bob_pk,
                                               endpoint_from_p2p_addrs(bob_addrs),
                                               t1 - 5, cwt_exp2, 5U, true});
  auto rebound_snap = snapshot;
  rebound_snap.party_epoch = 5U;
  rebound_snap.members = {alice_rec2, bob_rebound_rec};
  const auto rebound_snap_res =
      must(alice.apply_snapshot(rebound_snap, t1), "alice apply rebound snapshot");
  require(rebound_snap_res.revoked_peers.size() == 1U &&
              rebound_snap_res.revoked_peers[0] == bob_id,
          "live snapshot rebinding account/root must report revoked peer");
  const auto alice_rebind_disc =
      wait_for_party_event(alice, P2pPartyEventKind::peer_disconnected, t1);
  require(alice_rebind_disc.peer_pubkey == bob_pk &&
              alice_rebind_disc.reason_code == 4403U,
          "alice must tear down live QUIC with 4403 on identity rebind");
  const auto bob_rebind_disc =
      wait_for_party_event(bob, P2pPartyEventKind::peer_disconnected, t1);
  require(bob_rebind_disc.peer_pubkey == alice_pk &&
              bob_rebind_disc.reason_code == 4403U,
          "bob must observe immediate 4403 on identity rebind");

  // Reconnect after rebind, then verify apply_disbanded tears down the mesh and rejects
  // further joins/sends.
  const auto reconn3_res =
      must(alice.connect_pending_peers(), "alice connect_pending_peers after rebind");
  require(reconn3_res.attempted == 1U && reconn3_res.connected == 1U,
          "alice reconnect after rebind must succeed");
  (void)wait_for_party_event(alice, P2pPartyEventKind::peer_connected, t1);
  (void)wait_for_party_event(bob, P2pPartyEventKind::peer_connected, t1);

  must_void(alice.apply_disbanded(mp::PartyDisbandedMessage{
                6U, mp::PartyDisbandReason::leader_disbanded}),
            "alice apply_disbanded");
  require(alice.disbanded() && alice.peer_count() == 0U, "alice disbanded cleanly");
  const auto bob_disband_disc =
      wait_for_party_event(bob, P2pPartyEventKind::peer_disconnected, t1);
  require(bob_disband_disc.peer_pubkey == alice_pk &&
              bob_disband_disc.reason_code == 4403U,
          "disband must sever bob QUIC connection with 4403");

  const auto join_after_disband =
      alice.apply_member_joined(mp::PartyMemberJoinedMessage{7U, bob_rec2}, t1);
  require(!join_after_disband.has_value() &&
              p2p_party_error_of(join_after_disband.error()) ==
                  P2pPartyError::session_disbanded,
          "join after disband must fail closed");
  const auto send_after_disband = alice.broadcast_chat(a_chat);
  require(!send_after_disband.has_value() &&
              p2p_party_error_of(send_after_disband.error()) ==
                  P2pPartyError::session_disbanded,
          "send after disband must fail closed");

  (void)mallory_acct;
}

#else

void test_without_iroh_detached_endpoints_fail_closed() {
  g_stage = "without_iroh_detached_endpoints_fail_closed";
  require(!p2p_iroh_compiled_in(), "p2p_iroh_compiled_in must be false");

  const auto alice_acct = must(mp::AccountId::create(10U), "alice_acct");
  const auto alice_id = must(mp::DeviceId::create(100U), "alice_id");
  const auto party_id = must(mp::PartyId::create(55U), "party_id");

  P2pPartySessionConfig cfg{alice_acct, alice_id};
  cfg.local_relay_policy = P2pRelayPolicy::no_relays;
  auto session = must(P2pPartySession::create_detached(cfg), "detached session");

  mp::PartySnapshotMessage snap{
      party_id,
      1U,
      alice_acct,
      alice_id,
      mp::PartyVisibility::private_party,
      mp::PartyJoinMode::invite_only,
      mp::RelayPolicy::no_relays,
      4U,
      "",
      {},
  };
  (void)must(session.apply_snapshot(snap, 1000), "apply_snapshot detached");

  const auto poll_res = session.poll_event(PollTimeoutMs{10U}, PartyNowSeconds{1000});
  require(!poll_res.has_value() && poll_res.error().code == ErrorCode::unsupported,
          "poll_event without endpoint must return unsupported");

  const auto send_res = session.broadcast_control_notice(
      P2pPartyControlNotice{P2pPartyControlNoticeKind::status, 1U, "hi"});
  require(!send_res.has_value() && send_res.error().code == ErrorCode::unsupported,
          "broadcast without endpoint must return unsupported");
}

#endif

} // namespace

int main() {
  try {
    test_golden_wire_hex_vectors();
    test_frame_codec_roundtrip_and_bounds();
    test_endpoint_descriptor_conversion_and_policy();
    test_policy_immutability_epoch_bounds_max_members_and_rebind();
    test_detached_cwt_policy_epoch_anti_spoofing_and_eviction();
#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
    require(p2p_iroh_compiled_in(), "p2p_iroh_compiled_in must be true");
    test_live_iroh_party_mesh_end_to_end();
#else
    test_without_iroh_detached_endpoints_fail_closed();
#endif
    std::cout << "p2p_party_session_test: ALL PASSED\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "FAIL: " << ex.what() << "\n";
    return 1;
  }
}
