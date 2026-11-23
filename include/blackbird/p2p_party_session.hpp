#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/mp_protocol.hpp"
#include "blackbird/p2p_transport.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace blackbird {

// ---------------------------------------------------------------------------
// Constants & error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

inline constexpr std::uint8_t kP2pPartyFrameVersion = 1U;
inline constexpr std::size_t kP2pPartyMaxRoomScopeBytes = 128U;
inline constexpr std::size_t kP2pPartyMaxTargetSelectorBytes = 64U;
inline constexpr std::size_t kP2pPartyMaxSenderHandleBytes = 64U;
inline constexpr std::size_t kP2pPartyMaxChatBodyBytes = 256U * 1024U;
inline constexpr std::size_t kP2pPartyMaxBridgePayloadBytes = 1024U * 1024U;
inline constexpr std::size_t kP2pPartyMaxControlNoticeBytes = 4U * 1024U;
inline constexpr std::size_t kP2pPartyMaxEphemeralStatusBytes = 256U;
inline constexpr std::int64_t kP2pPartyDefaultMaxLeaseTtlSecs = 60;
inline constexpr std::uint32_t kP2pPartyDefaultConnectTimeoutMs = 10000U;

enum class P2pPartyError : std::int64_t {
  none = 0,
  session_disbanded = 1000,
  no_active_party = 1001,
  stale_party_epoch = 1002,
  relay_policy_mismatch = 1003,
  duplicate_device_id = 1004,
  duplicate_device_pubkey = 1005,
  peer_not_found = 1006,
  self_target_disallowed = 1007,
  endpoint_unavailable = 1008,
  frame_truncated = 1009,
  frame_trailing_bytes = 1010,
  frame_unsupported_version = 1011,
  frame_unknown_kind = 1012,
  frame_lane_mismatch = 1013,
  frame_field_too_large = 1014,
  frame_invalid_utf8 = 1015,
  frame_invalid_enum = 1016,
  frame_non_zero_reserved = 1017,
  frame_unverified_sender = 1018,
  local_pubkey_mismatch = 1019,
  invalid_party_member_count = 1020,
  peer_lease_expired = 1021,
  frame_oversized = 1022,
  party_id_mismatch = 1023,
  invalid_party_epoch = 1024,
};

constexpr P2pPartyError p2p_party_error_of(const Error &error) noexcept {
  return static_cast<P2pPartyError>(error.detail);
}

std::string_view p2p_party_error_name(P2pPartyError detail) noexcept;

// ---------------------------------------------------------------------------
// Policy & EndpointDescriptor -> P2pPeerTarget conversion
// ---------------------------------------------------------------------------

constexpr P2pRelayPolicy to_p2p_relay_policy(mp::RelayPolicy policy) noexcept {
  switch (policy) {
  case mp::RelayPolicy::allow_relays:
    return P2pRelayPolicy::allow_relays;
  case mp::RelayPolicy::force_relays:
    return P2pRelayPolicy::force_relays;
  case mp::RelayPolicy::no_relays:
    return P2pRelayPolicy::no_relays;
  }
  return P2pRelayPolicy::allow_relays;
}

constexpr mp::RelayPolicy to_mp_relay_policy(P2pRelayPolicy policy) noexcept {
  switch (policy) {
  case P2pRelayPolicy::allow_relays:
    return mp::RelayPolicy::allow_relays;
  case P2pRelayPolicy::force_relays:
    return mp::RelayPolicy::force_relays;
  case P2pRelayPolicy::no_relays:
    return mp::RelayPolicy::no_relays;
  }
  return mp::RelayPolicy::allow_relays;
}

P2pDirectAddr mp_direct_addr_to_p2p(const mp::DirectAddr &addr) noexcept;
Result<mp::DirectAddr> p2p_direct_addr_to_mp(const P2pDirectAddr &addr);

// Maps a verified mp::PartyMemberRecord onto an iroh P2pPeerTarget.
// Forces 0 direct_addrs when party_relay_policy == mp::RelayPolicy::force_relays,
// and forces empty relay_url when party_relay_policy == mp::RelayPolicy::no_relays.
Result<P2pPeerTarget> endpoint_descriptor_to_p2p_target(
    const mp::PartyMemberRecord &member, mp::RelayPolicy party_relay_policy,
    std::uint32_t connect_timeout_ms = kP2pPartyDefaultConnectTimeoutMs);

// ---------------------------------------------------------------------------
// Typed Party Data-Plane Wire Envelopes (3 QUIC lanes, LE binary, version 1)
//
// Cross-repo wire specification (ALPN "blackbird-mp/1", Blackbird <-> Outpost):
// All multi-byte integers are little-endian. All text fields are strict UTF-8.
// Trailing bytes or non-zero flags/reserved bytes MUST be rejected.
//
// Common 4-byte header (offsets 0..3):
//   [0]    u8  version   = 0x01
//   [1]    u8  kind      = 0x01 chat_message    (Lane 1: causal)
//                        | 0x02 bridge_envelope (Lane 1: causal)
//                        | 0x03 control_notice  (Lane 0: control)
//                        | 0x04 ephemeral_pulse (Lane 2: ephemeral)
//   [2]    u8  flags     = 0x00 (must be 0)
//   [3]    u8  reserved  = 0x00 (must be 0)
//
// Kind 0x01 chat_message (Lane 1 causal):
//   [4..11]  i64 LE  timestamp_ns
//   [12..]   u16 LE  room_scope_len (<= 128)        + UTF-8 bytes
//            u16 LE  target_selector_len (<= 64)    + UTF-8 bytes
//            u16 LE  sender_handle_len (<= 64)      + UTF-8 bytes
//            u32 LE  body_len (<= 262144)           + UTF-8 bytes
//
// Kind 0x02 bridge_envelope (Lane 1 causal):
//   [4..]    u16 LE  room_scope_len (<= 128)        + UTF-8 bytes
//            u32 LE  payload_len (<= 1048576)       + raw payload bytes
//
// Kind 0x03 control_notice (Lane 0 control):
//   [4]      u8      notice_kind (0=sync_ack, 1=scope_changed, 2=status)
//   [5]      u8      reserved    = 0x00 (must be 0)
//   [6..13]  u64 LE  party_epoch
//   [14..]   u16 LE  text_len (<= 4096)             + UTF-8 bytes
//
// Kind 0x04 ephemeral_pulse (Lane 2 ephemeral, total frame <= 1200 B):
//   [4]      u8      activity_state (0=offline, 1=online, 2=working, 3=idle, 4=typing)
//   [5]      u8      reserved    = 0x00 (must be 0)
//   [6..13]  i64 LE  timestamp_ns
//   [14..]   u16 LE  status_len (<= 256)            + UTF-8 bytes
// ---------------------------------------------------------------------------

enum class P2pPartyFrameKind : std::uint8_t {
  chat_message = 1,
  bridge_envelope = 2,
  control_notice = 3,
  ephemeral_pulse = 4,
};

enum class P2pPartyControlNoticeKind : std::uint8_t {
  sync_ack = 0,
  scope_changed = 1,
  status = 2,
};

enum class P2pPartyActivityState : std::uint8_t {
  offline = 0,
  online = 1,
  working = 2,
  idle = 3,
  typing = 4,
};

constexpr P2pLane p2p_party_frame_lane(P2pPartyFrameKind kind) noexcept {
  switch (kind) {
  case P2pPartyFrameKind::chat_message:
  case P2pPartyFrameKind::bridge_envelope:
    return P2pLane::causal;
  case P2pPartyFrameKind::control_notice:
    return P2pLane::control;
  case P2pPartyFrameKind::ephemeral_pulse:
    return P2pLane::ephemeral;
  }
  return P2pLane::control;
}

std::string_view p2p_party_frame_kind_name(P2pPartyFrameKind kind) noexcept;

struct P2pPartyChatMessage {
  std::string room_scope;
  std::string target_selector;
  std::string sender_handle;
  std::int64_t timestamp_ns = 0;
  std::string body;

  bool operator==(const P2pPartyChatMessage &) const = default;
};

struct P2pPartyBridgeEnvelope {
  std::string room_scope;
  std::vector<std::uint8_t> payload;

  bool operator==(const P2pPartyBridgeEnvelope &) const = default;
};

struct P2pPartyControlNotice {
  P2pPartyControlNoticeKind kind = P2pPartyControlNoticeKind::status;
  std::uint64_t party_epoch = 0U;
  std::string text;

  bool operator==(const P2pPartyControlNotice &) const = default;
};

struct P2pPartyEphemeralPulse {
  P2pPartyActivityState activity_state = P2pPartyActivityState::online;
  std::int64_t timestamp_ns = 0;
  std::string status;

  bool operator==(const P2pPartyEphemeralPulse &) const = default;
};

using P2pPartyFrame = std::variant<P2pPartyChatMessage, P2pPartyBridgeEnvelope,
                                   P2pPartyControlNotice, P2pPartyEphemeralPulse>;

P2pPartyFrameKind p2p_party_frame_kind(const P2pPartyFrame &frame) noexcept;

Result<std::vector<std::uint8_t>> encode_p2p_party_frame(const P2pPartyFrame &frame);
Result<P2pPartyFrame> decode_p2p_party_frame(P2pLane expected_lane,
                                             std::span<const std::uint8_t> bytes);

// ---------------------------------------------------------------------------
// Session configuration, peer roster, events, and operation reports
// ---------------------------------------------------------------------------

// Distinct non-mutually-convertible parameter wrappers for poll_event(timeout_ms,
// now_s).
struct PollTimeoutMs {
  std::uint32_t value = 0U;
  constexpr PollTimeoutMs(std::uint32_t ms) noexcept : value(ms) {}
};

struct PartyNowSeconds {
  std::int64_t value = 0;
  constexpr PartyNowSeconds(std::int64_t secs) noexcept : value(secs) {}
};

enum class P2pPeerConnectionState : std::uint8_t {
  admitted = 0,
  dial_pending = 1,
  connected = 2,
  disconnected = 3,
};

struct P2pPartyPeer {
  mp::DeviceId device_id;
  mp::AccountId account_id;
  mp::Ed25519PubKey root_pubkey{};
  P2pPubkey device_pubkey{};
  mp::EndpointDescriptor endpoint;
  std::uint64_t joined_seq = 0U;
  bool control_plane_connected = false;
  std::int64_t cwt_iat_s = 0;
  std::int64_t cwt_exp_s = 0;
  std::int64_t last_confirmed_s = 0;
  bool we_dial = false;
  P2pPeerConnectionState connection_state = P2pPeerConnectionState::admitted;

  bool operator==(const P2pPartyPeer &) const = default;
};

struct P2pPartyPeerFailure {
  mp::DeviceId device_id;
  Error error;

  bool operator==(const P2pPartyPeerFailure &) const = default;
};

struct P2pPartySnapshotResult {
  std::vector<mp::DeviceId> admitted_peers;
  std::vector<mp::DeviceId> revoked_peers;
  std::vector<P2pPartyPeerFailure> rejected_members;
  std::vector<P2pPartyPeerFailure> dial_failures;

  bool operator==(const P2pPartySnapshotResult &) const = default;
};

struct P2pPartyConnectResult {
  std::size_t attempted = 0U;
  std::size_t connected = 0U;
  std::vector<P2pPartyPeerFailure> failures;

  bool operator==(const P2pPartyConnectResult &) const = default;
};

struct P2pPartyBroadcastResult {
  std::size_t attempted = 0U;
  std::size_t sent = 0U;
  std::vector<P2pPartyPeerFailure> failures;

  bool operator==(const P2pPartyBroadcastResult &) const = default;
};

enum class P2pPartyEventKind : std::uint8_t {
  peer_connected = 1,
  peer_disconnected = 2,
  frame_received = 3,
  frame_dropped = 4,
};

struct P2pPartyEvent {
  P2pPartyEventKind kind = P2pPartyEventKind::frame_dropped;
  P2pLane lane = P2pLane::control;
  P2pPubkey peer_pubkey{};
  // Attributed EXCLUSIVELY from the authenticated TLS 1.3 Mutual RPK peer_pubkey
  // looked up in the CWT-verified roster; never taken from payload bytes.
  std::optional<mp::DeviceId> sender_device_id = std::nullopt;
  std::optional<mp::AccountId> sender_account_id = std::nullopt;
  std::optional<P2pPartyFrame> frame = std::nullopt;
  std::uint32_t reason_code = 0U;
  std::optional<Error> drop_error = std::nullopt;

  bool operator==(const P2pPartyEvent &) const = default;
};

struct P2pPartySessionConfig {
  mp::AccountId local_account_id;
  mp::DeviceId local_device_id;
  P2pRelayPolicy local_relay_policy = P2pRelayPolicy::allow_relays;
  std::optional<P2pPubkey> local_pubkey = std::nullopt;
  std::uint32_t connect_timeout_ms = kP2pPartyDefaultConnectTimeoutMs;
  // Optional lease-TTL ceiling since last control-plane confirmation (default 60s).
  // Set to std::nullopt to enforce CWT exp only.
  std::optional<std::int64_t> max_lease_ttl_s = kP2pPartyDefaultMaxLeaseTtlSecs;
  // When true, newly admitted/updated peers with should_dial_peer(...) == true are
  // dialed immediately if a live P2pEndpoint is attached.
  bool auto_dial = true;
  // Explicitly opt-in for local loopback tests under RelayPolicy::no_relays only.
  // Production sessions must leave this false.
  bool allow_loopback_direct_addrs = false;
};

// ---------------------------------------------------------------------------
// Control-Plane <-> iroh P2P Data-Plane Orchestrator
// ---------------------------------------------------------------------------

class P2pPartySession {
public:
  // Creates a session attached to a live iroh P2pEndpoint (fail-closed initial
  // allowlist).
  static Result<P2pPartySession> create(P2pPartySessionConfig config,
                                        P2pEndpoint endpoint);

  // Creates a session without an attached iroh P2pEndpoint (for pure state/CWT/
  // policy/codec/anti-spoofing operation and BLACKBIRD_HAS_IROH=0 builds).
  static Result<P2pPartySession> create_detached(P2pPartySessionConfig config);

  P2pPartySession(const P2pPartySession &) = delete;
  P2pPartySession &operator=(const P2pPartySession &) = delete;
  P2pPartySession(P2pPartySession &&) noexcept = default;
  P2pPartySession &operator=(P2pPartySession &&) noexcept = default;
  ~P2pPartySession() = default;

  // Control-plane lifecycle handlers.
  Result<P2pPartySnapshotResult>
  apply_snapshot(const mp::PartySnapshotMessage &snapshot, std::int64_t now_s);
  Result<void> apply_member_joined(const mp::PartyMemberJoinedMessage &message,
                                   std::int64_t now_s);
  Result<void> apply_member_updated(const mp::PartyMemberUpdatedMessage &message,
                                    std::int64_t now_s);
  Result<void> apply_member_left(const mp::PartyMemberLeftMessage &message);
  Result<void> apply_leader_changed(const mp::PartyLeaderChangedMessage &message);
  Result<void> apply_disbanded(const mp::PartyDisbandedMessage &message);

  // Lease-TTL & CWT expiry enforcement.
  Result<std::vector<mp::DeviceId>> evict_expired_peers(std::int64_t now_s);
  Result<void> refresh_all_leases(std::int64_t now_s);

  // Deterministic outbound connection driver (dials peers where we_dial == true).
  Result<P2pPartyConnectResult> connect_pending_peers();

  // Typed party data-plane senders across the 3 QUIC lanes.
  Result<P2pPartyBroadcastResult> broadcast_chat(const P2pPartyChatMessage &message);
  Result<void> send_chat_to(mp::DeviceId device_id, const P2pPartyChatMessage &message);

  Result<P2pPartyBroadcastResult>
  broadcast_bridge_envelope(const P2pPartyBridgeEnvelope &envelope);
  Result<void> send_bridge_envelope_to(mp::DeviceId device_id,
                                       const P2pPartyBridgeEnvelope &envelope);

  Result<P2pPartyBroadcastResult>
  broadcast_control_notice(const P2pPartyControlNotice &notice);
  Result<void> send_control_notice_to(mp::DeviceId device_id,
                                      const P2pPartyControlNotice &notice);

  Result<P2pPartyBroadcastResult>
  broadcast_ephemeral_pulse(const P2pPartyEphemeralPulse &pulse);
  Result<void> send_ephemeral_pulse_to(mp::DeviceId device_id,
                                       const P2pPartyEphemeralPulse &pulse);

  // Inbound event polling & anti-spoofing attribution.
  Result<std::optional<P2pPartyEvent>> poll_event(PollTimeoutMs timeout_ms,
                                                  PartyNowSeconds now_s);
  P2pPartyEvent ingest_transport_event(const P2pEvent &event, std::int64_t now_s);

  // Inspection accessors.
  const P2pPartySessionConfig &config() const noexcept { return config_; }
  bool has_endpoint() const noexcept {
    return endpoint_.has_value() && endpoint_->valid();
  }
  bool has_active_party() const noexcept { return party_id_.has_value(); }
  bool disbanded() const noexcept { return disbanded_; }
  std::optional<mp::PartyId> party_id() const noexcept { return party_id_; }
  std::uint64_t party_epoch() const noexcept { return party_epoch_; }
  std::optional<mp::AccountId> leader_account_id() const noexcept {
    return leader_account_id_;
  }
  std::optional<mp::DeviceId> leader_device_id() const noexcept {
    return leader_device_id_;
  }
  mp::RelayPolicy relay_policy() const noexcept { return relay_policy_; }
  std::uint8_t max_members() const noexcept { return max_members_; }
  std::string_view pinned_relay_url() const noexcept { return pinned_relay_url_; }
  std::optional<P2pPubkey> local_pubkey() const noexcept { return local_pubkey_; }
  Result<std::vector<P2pDirectAddr>> local_direct_addrs() const;

  std::size_t peer_count() const noexcept { return peers_by_device_.size(); }
  std::optional<P2pPartyPeer> find_peer(mp::DeviceId device_id) const;
  std::optional<P2pPartyPeer> find_peer_by_pubkey(const P2pPubkey &pubkey) const;
  std::vector<P2pPartyPeer> peers() const;
  std::vector<P2pPubkey> allowed_pubkeys() const;

  void close() noexcept;

private:
  P2pPartySession(P2pPartySessionConfig config, std::optional<P2pEndpoint> endpoint,
                  std::optional<P2pPubkey> local_pubkey) noexcept;

  Result<void> validate_endpoint_for_session(const mp::EndpointDescriptor &endpoint,
                                             mp::RelayPolicy policy,
                                             std::string_view pinned_relay_url) const;
  Result<void> sync_allowlist_to_endpoint();
  Result<void> dial_peer_record(P2pPartyPeer &peer);
  Result<void> send_frame_to_device(mp::DeviceId device_id, const P2pPartyFrame &frame);
  Result<P2pPartyBroadcastResult> broadcast_frame(const P2pPartyFrame &frame);
  bool is_peer_expired(const P2pPartyPeer &peer, std::int64_t now_s) const noexcept;
  void revoke_all_and_disband() noexcept;

  P2pPartySessionConfig config_;
  std::optional<P2pEndpoint> endpoint_;
  std::optional<P2pPubkey> local_pubkey_;

  std::optional<mp::PartyId> party_id_;
  std::uint64_t party_epoch_ = 0U;
  std::optional<mp::AccountId> leader_account_id_;
  std::optional<mp::DeviceId> leader_device_id_;
  mp::RelayPolicy relay_policy_ = mp::RelayPolicy::allow_relays;
  std::uint8_t max_members_ = 0U;
  std::string pinned_relay_url_;
  bool disbanded_ = false;

  std::map<mp::DeviceId, P2pPartyPeer> peers_by_device_;
  std::map<P2pPubkey, mp::DeviceId> device_by_pubkey_;
};

} // namespace blackbird
