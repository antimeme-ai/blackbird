#pragma once

#include "blackbird/board_bridge.hpp"
#include "blackbird/foundation.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/value.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace blackbird {

// Stage 1 -> Stage 2 Three-Lane Multiplexing, Signed Late-Join Checkpoints,
// Content-Blind Relay Routing, and Transitive Multi-Hop Taint Propagation.

inline constexpr std::uint32_t kBridgeCheckpointVersion = 1;
inline constexpr std::string_view kBridgeCheckpointSigningType =
    "blackbird.bridge_checkpoint";

inline constexpr std::size_t kRelayControlMaxBytes = 16 * 1024;      // 16 KiB hard cap
inline constexpr std::size_t kRelayPresenceMaxBytes = 4 * 1024;      // 4 KiB hard cap
inline constexpr std::size_t kRelayCausalMaxBytes = 4 * 1024 * 1024; // 4 MiB hard cap

inline constexpr std::string_view kRoomInvitePrefix = "bbjoin1:";
inline constexpr std::size_t kRoomInviteMaxUriBytes = 4096;
inline constexpr std::size_t kRoomInviteMaxUrlBytes = 512;
inline constexpr std::size_t kRoomInviteMaxCodeBytes = 128;

inline constexpr std::size_t kRelayMaxFrameIdBytes = 128;
inline constexpr std::size_t kRelayMaxNonceB64Bytes = 128;
inline constexpr std::size_t kRelayMaxEndpointBytes = 256;
inline constexpr std::size_t kRelayMaxSubscriptions = 256;
inline constexpr std::size_t kRelayDefaultMaxRoomHistoryBytes =
    16 * 1024 * 1024; // 16 MiB default byte cap on retained room history
inline constexpr std::size_t kCheckpointMaxEntries = 4096;

inline constexpr std::uint32_t kDefaultMaxProvenanceHops = 8;
inline constexpr std::uint32_t kHardMaxProvenanceHops = 32;
inline constexpr std::size_t kMaxProvenanceUntrustedSources = 128;

// ---------------------------------------------------------------------------
// 1. 3-Lane Priority Multiplexer (Tribes MRS + Valve Connection Lanes)
// ---------------------------------------------------------------------------

enum class RelayLane : std::uint8_t {
  control = 0,  // Preemptive: recall, CapabilityGrant, revocations, lease epochs
  causal = 1,   // Reliable ordered: work orders, CausalEvents, receipts, artifacts
  presence = 2, // Unreliable latest-wins MRS heartbeats, coalesced by (actor, scope)
};

std::string_view relay_lane_name(RelayLane lane) noexcept;
Result<RelayLane> parse_relay_lane(std::string_view name) noexcept;
std::size_t relay_lane_max_bytes(RelayLane lane) noexcept;

struct RelayPacket {
  RelayLane lane = RelayLane::causal;
  std::string packet_id;
  std::string actor_id;
  std::string scope; // watching_scope (Lane 2) or resource_scope (Lane 0/1)
  std::uint64_t sequence = 0;
  std::int64_t timestamp_ns = 0;
  std::string payload;
  bool operator==(const RelayPacket &) const = default;
};

struct BridgeMuxConfig {
  std::size_t max_control_queue = 256;
  std::size_t max_causal_queue = 1024;
  std::size_t max_presence_queue = 256;
  std::size_t control_max_bytes = kRelayControlMaxBytes;
  std::size_t causal_max_bytes = kRelayCausalMaxBytes;
  std::size_t presence_max_bytes = kRelayPresenceMaxBytes;
  bool operator==(const BridgeMuxConfig &) const = default;
};

enum class BridgeMuxEnqueueStatus : std::uint8_t {
  queued,
  coalesced,
  dropped_oldest_and_queued,
  ignored_stale,
};

struct BridgeMuxStats {
  std::size_t control_depth = 0;
  std::size_t causal_depth = 0;
  std::size_t presence_depth = 0;
  std::uint64_t enqueued_total = 0;
  std::uint64_t dequeued_total = 0;
  std::uint64_t presence_coalesced = 0;
  std::uint64_t presence_dropped_oldest = 0;
  std::uint64_t presence_stale_ignored = 0;
  std::uint64_t rejected_oversize = 0;
  std::uint64_t rejected_queue_full = 0;
  bool operator==(const BridgeMuxStats &) const = default;
};

class BridgeMux {
public:
  BridgeMux() = default;
  static Result<BridgeMux> create(BridgeMuxConfig config);

  const BridgeMuxConfig &config() const noexcept { return config_; }
  BridgeMuxStats stats() const noexcept;

  Result<BridgeMuxEnqueueStatus> enqueue(RelayPacket packet);
  std::optional<RelayPacket> dequeue_next();

  bool empty() const noexcept;
  std::size_t size() const noexcept;
  std::size_t lane_size(RelayLane lane) const noexcept;
  void clear_presence() noexcept;

private:
  struct PresenceKey {
    std::string actor_id;
    std::string scope;
    bool operator==(const PresenceKey &) const = default;
  };

  struct PresenceKeyHash {
    std::size_t operator()(const PresenceKey &key) const noexcept;
  };

  struct PresenceWater {
    std::int64_t timestamp_ns = 0;
    std::uint64_t sequence = 0;
  };

  struct PresenceEntry {
    PresenceKey key;
    RelayPacket packet;
  };

  explicit BridgeMux(BridgeMuxConfig config) noexcept : config_(config) {}

  BridgeMuxConfig config_{};
  std::deque<RelayPacket> control_queue_;
  std::deque<RelayPacket> causal_queue_;
  std::list<PresenceEntry> presence_list_;
  std::unordered_map<PresenceKey, std::list<PresenceEntry>::iterator, PresenceKeyHash>
      presence_index_;
  std::unordered_map<PresenceKey, PresenceWater, PresenceKeyHash> last_seen_presence_;
  std::deque<PresenceKey> last_seen_order_;

  std::uint64_t enqueued_total_ = 0;
  std::uint64_t dequeued_total_ = 0;
  std::uint64_t presence_coalesced_ = 0;
  std::uint64_t presence_dropped_oldest_ = 0;
  std::uint64_t presence_stale_ignored_ = 0;
  std::uint64_t rejected_oversize_ = 0;
  std::uint64_t rejected_queue_full_ = 0;
};

// ---------------------------------------------------------------------------
// 2. Signed Late-Join Checkpoints (Quake III / Factorio Snapshot + Delta Tail)
// ---------------------------------------------------------------------------

struct BridgeCheckpointDraft {
  std::string room_id;
  std::uint64_t checkpoint_seq = 0;
  std::int64_t created_ns = 0; // 0 => current wall clock ns on sign
  std::map<std::string, std::uint64_t> actor_watermarks;
  std::vector<std::string> causal_frontier_hashes;
  std::vector<std::string> revoked_grant_ids;
  std::map<std::string, std::uint64_t> lease_epochs;
};

struct BridgeCheckpoint {
  std::uint32_t version = kBridgeCheckpointVersion;
  std::string room_id;
  std::uint64_t checkpoint_seq = 0;
  std::int64_t created_ns = 0;
  std::map<std::string, std::uint64_t> actor_watermarks;
  std::vector<std::string> causal_frontier_hashes;
  std::vector<std::string> revoked_grant_ids;
  std::map<std::string, std::uint64_t> lease_epochs;
  std::string signer_fingerprint;
  std::string signature;
  bool operator==(const BridgeCheckpoint &) const = default;
};

Result<std::string> canonical_checkpoint_payload(const BridgeCheckpoint &checkpoint);
Value checkpoint_to_value(const BridgeCheckpoint &checkpoint);
Result<BridgeCheckpoint> checkpoint_from_value(const Value &value);

struct CheckpointVerifyOptions {
  std::optional<std::string> expected_room_id;
  std::optional<std::uint64_t> min_checkpoint_seq;
  std::optional<std::int64_t> max_age_ns;
  std::optional<std::int64_t> now_ns;
  std::optional<std::int64_t> max_future_skew_ns;
  // When non-empty, checkpoint.signer_fingerprint must appear in allowed_signers.
  std::vector<std::string> allowed_signers;
  bool operator==(const CheckpointVerifyOptions &) const = default;
};

Result<BridgeCheckpoint> sign_checkpoint(const PeerIdentityStore &identity,
                                         BridgeCheckpointDraft draft);
Result<void> verify_checkpoint(const KnownPeersStore &known_peers,
                               const BridgeCheckpoint &checkpoint,
                               const PeerIdentityConfig &config = {});
Result<void> verify_checkpoint(const KnownPeersStore &known_peers,
                               const BridgeCheckpoint &checkpoint,
                               const CheckpointVerifyOptions &options,
                               const PeerIdentityConfig &config = {});

std::map<std::string, std::uint64_t>
compute_actor_watermarks(const std::vector<CausalEvent> &events);
std::vector<std::string>
compute_causal_frontier(const std::vector<CausalEvent> &events);
std::vector<CausalEvent>
filter_delta_after_checkpoint(const std::vector<CausalEvent> &events,
                              const BridgeCheckpoint &checkpoint);

// ---------------------------------------------------------------------------
// 3. Room Invite URI (bbjoin1:...) & Content-Blind Relay Router (SDR / DERP)
// ---------------------------------------------------------------------------

// Unsigned room join metadata. `invite_code` IS a room-join bearer credential
// and MUST be handled as sensitive material over a confidential channel; the
// URI does not carry private identity keys or E2EE room keys, and `relay_url`
// forbids embedded userinfo, query parameters, and fragments.
struct RoomInvite {
  std::string room_id;
  std::string relay_url;
  std::string creator_fingerprint;
  std::string creator_public_key;
  std::string invite_code;
  std::int64_t expires_ns = 0;

  bool is_expired(std::int64_t now_ns) const noexcept {
    return expires_ns <= 0 || now_ns >= expires_ns;
  }

  bool operator==(const RoomInvite &) const = default;
};

Result<void> validate_room_invite_freshness(const RoomInvite &invite,
                                            std::int64_t now_ns) noexcept;
Result<std::string> encode_room_invite(const RoomInvite &invite);
Result<RoomInvite> parse_room_invite(std::string_view uri,
                                     std::optional<std::int64_t> now_ns = std::nullopt);

struct BlindRelayFrame {
  std::string room_id;
  std::string sender_fingerprint;
  RelayLane lane = RelayLane::causal;
  std::string frame_id;
  std::uint64_t epoch = 0;
  std::string ciphertext_b64;
  std::string nonce_b64;
  std::string aad_hash;
  std::int64_t timestamp_ns = 0;
  // Optional opaque routing scope hint for interest filtering; empty => room-wide.
  std::string routing_scope;
  bool operator==(const BlindRelayFrame &) const = default;
};

Value blind_relay_frame_to_value(const BlindRelayFrame &frame);
Result<BlindRelayFrame> blind_relay_frame_from_value(const Value &value);

enum class RelayParticipantRole : std::uint8_t {
  peer,
  spectator,
};

struct RelayRateLimitPolicy {
  double frames_per_sec = 25.0;
  double burst_frames = 25.0;
  double bytes_per_sec = 8.0 * 1024.0 * 1024.0;
  double burst_bytes = 8.0 * 1024.0 * 1024.0;
  bool operator==(const RelayRateLimitPolicy &) const = default;
};

struct BlindRelayConfig {
  RelayRateLimitPolicy rate_limit{};
  BridgeMuxConfig session_mux{};
  std::size_t max_room_history = 4096;
  std::size_t max_room_history_bytes = kRelayDefaultMaxRoomHistoryBytes;
  std::size_t max_seen_frame_ids = 8192;
  std::size_t max_sessions_per_room = 512;
  // Optional TTL for reaping disconnected sessions via evict_stale_sessions() /
  // publish(). 0 disables automatic clock-based reaping (capacity-triggered eviction of
  // oldest disconnected sessions and explicit evict_disconnected_before() remain
  // active).
  std::int64_t disconnected_session_ttl_ns = 0;
  bool operator==(const BlindRelayConfig &) const = default;
};

struct RelaySessionSpec {
  std::string room_id;
  std::string peer_fingerprint;
  RelayParticipantRole role = RelayParticipantRole::peer;
  std::string remote_endpoint;
  std::vector<std::string> subscribed_scopes; // empty => all scopes in room
};

struct RelaySessionHandle {
  std::string session_id;
  std::string connection_id;
  std::string resume_token;
  std::string room_id;
  std::string peer_fingerprint;
  RelayParticipantRole role = RelayParticipantRole::peer;
  std::string remote_endpoint;
  bool connected = false;
  bool needs_resync = false;
  std::uint64_t roam_count = 0;
  std::uint64_t last_acked_relay_seq = 0;
  bool operator==(const RelaySessionHandle &) const = default;
};

struct RelayResumeRequest {
  std::string session_id;
  std::string peer_fingerprint;
  std::string new_remote_endpoint;
  std::uint64_t last_acked_relay_seq = 0;
  std::string resume_token;
  std::string
      room_id; // Optional; if non-empty, must match session's registered room_id.
};

struct RelayResumeResult {
  RelaySessionHandle session;
  std::size_t replayed_frames = 0;
  bool history_truncated = false;
  bool operator==(const RelayResumeResult &) const = default;
};

struct RelayPublishReport {
  std::uint64_t relay_seq = 0;
  std::size_t delivered_sessions = 0;
  std::size_t coalesced_sessions = 0;
  std::size_t overflowed_sessions = 0;
  bool duplicate = false;
  bool operator==(const RelayPublishReport &) const = default;
};

struct RoutedRelayFrame {
  std::uint64_t relay_seq = 0;
  BlindRelayFrame frame;
  bool operator==(const RoutedRelayFrame &) const = default;
};

struct BlindRelayStats {
  std::size_t active_rooms = 0;
  std::size_t registered_sessions = 0;
  std::size_t connected_sessions = 0;
  std::size_t retained_history_frames = 0;
  std::size_t retained_history_bytes = 0;
  std::uint64_t published_frames = 0;
  std::uint64_t duplicate_frames = 0;
  std::uint64_t rate_limited_frames = 0;
  std::uint64_t rejected_oversize_frames = 0;
  std::uint64_t reliable_overflow_events = 0;
  std::uint64_t evicted_sessions = 0;
  std::uint64_t session_roams = 0;
  bool operator==(const BlindRelayStats &) const = default;
};

// Content-blind in-process room router: routes opaque AEAD ciphertext frames by
// room_id and routing_scope, enforces per-sender token-bucket rate limits and
// per-lane size caps, supports read-only spectators, and resumes sessions across
// IP/network roaming with cryptographic token rotation and atomic O(delta) replay.
//
// Reliable delivery invariant (zero silent loss):
//   Every session tracks `contiguous_enqueued_relay_seq` and `needs_resync`.
//   If any relevant reliable (control/causal) frame fails to enqueue due to
//   queue backpressure, `needs_resync` becomes true and NO newer reliable frames
//   are enqueued for that session until `resume_session` replays contiguously
//   from `last_acked_relay_seq`. `ack_relay_seq` rejects any sequence above
//   `contiguous_enqueued_relay_seq` or any sequence that would skip unpolled
//   reliable frames still queued for that session.
class BlindRelayRouter {
public:
  BlindRelayRouter() = default;
  static Result<BlindRelayRouter> create(BlindRelayConfig config);

  const BlindRelayConfig &config() const noexcept { return config_; }
  BlindRelayStats stats() const noexcept;

  Result<RelaySessionHandle> register_session(RelaySessionSpec spec);
  Result<void> disconnect_session(std::string_view session_id, std::int64_t now_ns = 0);
  std::size_t evict_disconnected_before(std::int64_t cutoff_ns);
  std::size_t evict_stale_sessions(std::int64_t now_ns);
  Result<RelayResumeResult> resume_session(RelayResumeRequest request);
  Result<RelayPublishReport> publish(std::string_view session_id,
                                     const BlindRelayFrame &frame, std::int64_t now_ns);
  Result<std::optional<std::shared_ptr<const RoutedRelayFrame>>>
  poll_outbound_shared(std::string_view session_id);
  Result<std::optional<RoutedRelayFrame>> poll_outbound(std::string_view session_id);
  Result<void> ack_relay_seq(std::string_view session_id, std::uint64_t relay_seq);
  Result<RelaySessionHandle> session_info(std::string_view session_id) const;

private:
  struct SenderBucket {
    double frame_tokens = 0.0;
    double byte_tokens = 0.0;
    std::int64_t last_refill_ns = 0;
    bool initialized = false;
  };

  struct SessionState {
    RelaySessionHandle handle;
    std::vector<std::string> subscribed_scopes;
    BridgeMux outbound_mux;
    std::unordered_map<std::string, std::shared_ptr<const RoutedRelayFrame>>
        pending_frames;
    std::list<std::string> presence_ticket_order;
    std::unordered_map<std::string, std::list<std::string>::iterator>
        presence_ticket_pos;
    std::uint64_t next_ticket = 1;
    std::uint64_t last_enqueued_relay_seq = 0;
    std::uint64_t contiguous_enqueued_relay_seq = 0;
    std::uint64_t first_dropped_relay_seq = 0;
    std::int64_t disconnected_at_ns = 0;
    std::uint64_t disconnect_order = 0;
  };

  struct RoomState {
    std::uint64_t next_relay_seq = 1;
    std::uint64_t evicted_through_seq = 0;
    std::size_t reliable_history_bytes = 0;
    std::deque<std::shared_ptr<const RoutedRelayFrame>> reliable_history;
    std::unordered_set<std::string> seen_frame_ids;
    std::deque<std::string> seen_frame_order;
    std::vector<std::string> session_ids;
  };

  explicit BlindRelayRouter(BlindRelayConfig config) noexcept : config_(config) {}

  Result<void>
  enqueue_for_session(SessionState &session,
                      const std::shared_ptr<const RoutedRelayFrame> &routed,
                      bool &coalesced);
  bool evict_oldest_disconnected_in_room(RoomState &room);

  BlindRelayConfig config_{};
  std::unordered_map<std::string, RoomState> rooms_;
  std::unordered_map<std::string, SessionState> sessions_;
  std::unordered_map<std::string, SenderBucket> sender_buckets_;
  std::uint64_t disconnect_seq_ = 0;

  std::uint64_t published_frames_ = 0;
  std::uint64_t duplicate_frames_ = 0;
  std::uint64_t rate_limited_frames_ = 0;
  std::uint64_t rejected_oversize_frames_ = 0;
  std::uint64_t reliable_overflow_events_ = 0;
  std::uint64_t evicted_sessions_ = 0;
  std::uint64_t session_roams_ = 0;
};

// ---------------------------------------------------------------------------
// 4. Transitive Multi-Hop PeerProvenance Taint Propagation (Can CaMeLs Talk?)
// ---------------------------------------------------------------------------

struct TaintedProvenance {
  std::string origin_fingerprint;
  std::vector<std::string> hop_chain;
  std::vector<std::string> untrusted_sources;
  std::uint32_t hop_count = 0;
  std::uint32_t max_hops = kDefaultMaxProvenanceHops;
  bool operator==(const TaintedProvenance &) const = default;
};

struct TaintTransitionCheck {
  const TaintedProvenance &parent;
  const TaintedProvenance &child;
};

struct PeerFrameTaintInput {
  std::string sender_fingerprint;
  std::string local_actor_id;
  std::string room_id;
  std::string frame_id;
  std::optional<TaintedProvenance> peer_reported_provenance;
  std::vector<std::string> local_untrusted_sources;
  std::uint32_t max_hops = kDefaultMaxProvenanceHops;
};

Result<void> validate_tainted_provenance(const TaintedProvenance &provenance);
Result<TaintedProvenance>
propagate_taint(const TaintedProvenance &parent, std::string_view next_actor,
                const std::vector<std::string> &added_untrusted_sources = {});
Result<void> verify_taint_monotonicity(const TaintTransitionCheck &transition);
bool is_provenance_tainted(const TaintedProvenance &provenance) noexcept;

// Receiver-side taint invariant: foreign peer frames are ALWAYS marked tainted
// with `peer:<sender_fingerprint>` regardless of any self-reported clean
// provenance sent by a remote peer.
Result<TaintedProvenance>
derive_local_taint_for_peer_frame(const PeerFrameTaintInput &input);
Result<TaintedProvenance> derive_local_taint_for_peer_frame(
    const BlindRelayFrame &frame, std::string_view local_actor_id,
    const std::optional<TaintedProvenance> &peer_reported = std::nullopt,
    const std::vector<std::string> &local_untrusted_sources = {});

Value tainted_provenance_to_value(const TaintedProvenance &provenance);
Result<TaintedProvenance> tainted_provenance_from_value(const Value &value);
Result<PeerProvenance> merge_taint_into_peer_provenance(const TaintedProvenance &taint,
                                                        PeerProvenance destination);

} // namespace blackbird
