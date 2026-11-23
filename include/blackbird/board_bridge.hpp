#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/value.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::uint32_t kBoardBridgeSchemaVersion = 1;
inline constexpr std::size_t kBoardBridgeMaxScopeBytes = 1024;
inline constexpr std::size_t kBoardBridgeMaxKindBytes = 64;
inline constexpr std::size_t kBoardBridgeMaxRefBytes = 256;
inline constexpr std::size_t kBoardBridgeMaxStatusBytes = 256;
inline constexpr std::size_t kBoardBridgeMaxDisplayNameBytes = 128;
inline constexpr std::size_t kBoardBridgeMaxCausalParents = 64;
inline constexpr std::size_t kBoardBridgeMaxUntrustedSources = 64;
inline constexpr std::size_t kBoardBridgeMaxLineBytes = 4 * 1024 * 1024;
inline constexpr std::int64_t kBoardBridgeMaxTtlNs = 24LL * 60LL * 60LL * 1000000000LL;

// Distinct non-mutually-convertible view wrappers for multi-string APIs so
// callers can pass string literals, std::string, or std::string_view directly
// without adjacent swappable parameters.
struct ActorIdRef {
  std::string_view value;
  constexpr ActorIdRef(std::string_view actor) noexcept : value(actor) {}
  constexpr ActorIdRef(const char *actor) noexcept : value(actor ? actor : "") {}
  ActorIdRef(const std::string &actor) noexcept : value(actor) {}
};

struct ResourceScopeRef {
  std::string_view value;
  constexpr ResourceScopeRef(std::string_view scope) noexcept : value(scope) {}
  constexpr ResourceScopeRef(const char *scope) noexcept : value(scope ? scope : "") {}
  ResourceScopeRef(const std::string &scope) noexcept : value(scope) {}
};

struct CausalOrderQuery {
  std::string_view ancestor_hash;
  std::string_view descendant_hash;
};

// Validates a lowercase 64-character hexadecimal SHA-256 digest.
bool valid_sha256_hex(std::string_view hex) noexcept;

// Computes lowercase 64-character FIPS 180-4 SHA-256 hex digest of arbitrary bytes.
std::string board_bridge_sha256_hex(std::string_view bytes);

// 1. Distributed Causal Event Identity (N4)
struct CausalEventDraft {
  std::string actor_id;
  std::uint64_t actor_seq = 0; // 0 => auto-increment monotonic per-actor seq on emit
  std::vector<std::string> causal_parents;
  std::int64_t timestamp_ns = 0; // 0 => current wall clock ns on emit
  std::string resource_scope;
  std::string kind;
  Value payload = Value::object({});
};

struct CausalEvent {
  std::string actor_id;
  std::uint64_t actor_seq = 0;
  std::string event_hash;
  std::vector<std::string> causal_parents;
  std::int64_t timestamp_ns = 0;
  std::string resource_scope;
  std::string kind;
  Value payload = Value::object({});
  bool operator==(const CausalEvent &) const = default;
};

struct ConcurrentClaimConflict {
  std::string resource_scope;
  std::string first_event_hash;
  std::string second_event_hash;
  std::string first_actor_id;
  std::string second_actor_id;
  bool operator==(const ConcurrentClaimConflict &) const = default;
};

Result<std::string> compute_causal_event_hash(const CausalEvent &event);
Result<CausalEvent> make_causal_event(CausalEventDraft draft);
Value causal_event_to_value(const CausalEvent &event);
Result<CausalEvent> causal_event_from_value(const Value &value);

bool causally_precedes(const std::vector<CausalEvent> &events, CausalOrderQuery query);
Result<std::vector<ConcurrentClaimConflict>>
detect_concurrent_claims(const std::vector<CausalEvent> &events,
                         std::string_view resource_scope = {});

// 2. Executable 4-Stage Receipt Lifecycle (N1 — Worse Together)
enum class ReceiptStage : std::uint8_t {
  transmitted,
  available,
  opened_by_application,
  included_in_request,
  acknowledged,
  acted,
};

std::string_view receipt_stage_name(ReceiptStage stage) noexcept;
Result<ReceiptStage> parse_receipt_stage(std::string_view name) noexcept;
bool receipt_stage_is_cognitive_inclusion(ReceiptStage stage) noexcept;

struct MessageReceipt {
  std::string event_hash;
  std::string recipient_actor;
  ReceiptStage stage = ReceiptStage::transmitted;
  std::int64_t timestamp_ns = 0;
  std::optional<std::string> request_hash;  // Required for included_in_request
  std::optional<std::string> brief_version; // Optional for acknowledged
  std::optional<std::string> action_ref;    // Required for acted
  bool operator==(const MessageReceipt &) const = default;
};

Value receipt_to_value(const MessageReceipt &receipt);
Result<MessageReceipt> receipt_from_value(const Value &value);

// 3. Scoped Action-Time Unread-Message Guard (N1)
struct ActionGuardVerdict {
  bool allowed = false;
  std::vector<std::string> blocking_event_hashes;
  std::string reason;
  bool operator==(const ActionGuardVerdict &) const = default;
};

// 4. Data-Only Quoted Peer Framing (N4 + Opus §5)
struct PeerProvenance {
  std::string owner_actor;
  std::string requested_by_actor;
  std::vector<std::string> untrusted_sources;
  std::string trust_note;
  bool operator==(const PeerProvenance &) const = default;
};

Result<std::string> format_quoted_peer_frame(const PeerEnvelope &envelope,
                                             const PeerProvenance &provenance);

// 5. Attribution, Spend Ceilings & Local Tool-Time Grant Re-Verification
struct SpendPolicy {
  std::uint32_t max_turns_per_peer = 32;
  double max_cost_usd_per_peer = 2.0;
  double max_cost_usd_per_platoon = 10.0;
  bool operator==(const SpendPolicy &) const = default;
};

struct TurnAttribution {
  std::string owner_actor;
  std::string requested_by_actor;
  std::string grant_id;
  std::uint64_t input_tokens = 0;
  std::uint64_t output_tokens = 0;
  double cost_usd = 0.0;
  bool operator==(const TurnAttribution &) const = default;
};

class SpendLedger {
public:
  explicit SpendLedger(SpendPolicy policy = {}) noexcept : policy_(policy) {}

  const SpendPolicy &policy() const noexcept { return policy_; }
  Result<void> set_policy(SpendPolicy policy) noexcept;

  Result<void> record_turn(TurnAttribution attribution);

  const std::vector<TurnAttribution> &entries() const noexcept { return entries_; }
  std::uint32_t turns_for_peer(std::string_view peer_actor) const noexcept;
  std::uint32_t turns_for_grant(std::string_view grant_id) const noexcept;
  std::uint64_t tokens_for_grant(std::string_view grant_id) const noexcept;
  double cost_usd_for_peer(std::string_view peer_actor) const noexcept;
  double total_cost_usd() const noexcept;

private:
  SpendPolicy policy_{};
  std::vector<TurnAttribution> entries_;
};

struct ToolAuthorization {
  bool allowed = false;
  std::optional<ErrorCode> denial_code;
  std::string reason;
  bool operator==(const ToolAuthorization &) const = default;
};

Result<ToolAuthorization>
authorize_tool_call(const KnownPeersStore &known_peers, const CapabilityGrant &grant,
                    std::string_view tool_name, std::int64_t now_ns,
                    const SpendLedger &ledger, double projected_cost_usd);

// 6. Live Watcher Presence Heartbeats (Grok #5)
struct PresenceRecord {
  std::string actor_id;
  std::string display_name;
  std::string watching_scope;
  std::string status;
  std::int64_t updated_ns = 0;
  std::int64_t ttl_ns = 0;
  bool operator==(const PresenceRecord &) const = default;
};

Value presence_to_value(const PresenceRecord &record);
Result<PresenceRecord> presence_from_value(const Value &value);

// 7. Bidirectional NDJSON Pipe/SSH Transport & Durable Storage
struct PeerEnvelopeMeta {
  std::string envelope_id;
  std::string to_fingerprint;
  std::string thread_id;
  PeerEnvelopeKind kind = PeerEnvelopeKind::mail;
  std::int64_t timestamp_ns = 0;
};

enum class EnvelopeIngestStatus : std::uint8_t {
  accepted,
  duplicate,
};

struct EnvelopeIngestResult {
  EnvelopeIngestStatus status = EnvelopeIngestStatus::accepted;
  std::string envelope_id;
  std::string from_fingerprint;
  std::optional<std::string> causal_event_hash;
  bool operator==(const EnvelopeIngestResult &) const = default;
};

struct BridgePumpReport {
  std::size_t accepted = 0;
  std::size_t duplicates = 0;
  std::size_t rejected = 0;
  bool incomplete_trailing_frame = false;
  std::vector<std::string> accepted_envelope_ids;
  std::vector<std::string> accepted_event_hashes;
  bool operator==(const BridgePumpReport &) const = default;
};

// Stage 0 multiplayer BoardBridge: owns a pinned 0700 durable directory with
// flock + fsync append-only NDJSON storage for verified signed PeerEnvelopes,
// distributed CausalEvents, 4-stage MessageReceipts, scoped action-time unread
// message guards, live watcher PresenceRecords, and bidirectional NDJSON
// pipe/SSH transport with replay deduplication and reconnect recovery.
class BoardBridge {
public:
  static Result<BoardBridge> open(const std::filesystem::path &root);

  BoardBridge(const BoardBridge &) = delete;
  BoardBridge &operator=(const BoardBridge &) = delete;
  BoardBridge(BoardBridge &&other) noexcept;
  BoardBridge &operator=(BoardBridge &&other) noexcept;
  ~BoardBridge();

  const std::filesystem::path &root() const noexcept { return root_; }

  // Distributed causal events (N4).
  Result<CausalEvent> emit_causal_event(CausalEventDraft draft);
  Result<bool> record_causal_event(const CausalEvent &event);
  Result<std::vector<CausalEvent>> events() const;
  Result<std::optional<CausalEvent>> find_event(std::string_view event_hash) const;
  Result<std::uint64_t> latest_actor_seq(std::string_view actor_id) const;
  Result<std::vector<ConcurrentClaimConflict>>
  detect_concurrent_conflicts(std::string_view resource_scope = {}) const;

  // 4-stage receipt lifecycle (N1).
  Result<MessageReceipt> record_receipt(MessageReceipt receipt);
  Result<std::vector<MessageReceipt>> receipts() const;
  Result<std::vector<MessageReceipt>>
  receipts_for_event(std::string_view event_hash) const;

  // Scoped action-time unread-message guard (N1).
  Result<ActionGuardVerdict> check_action_guard(ActorIdRef actor_id,
                                                ResourceScopeRef resource_scope) const;

  // Live watcher presence heartbeats (Grok #5).
  Result<PresenceRecord> record_presence(PresenceRecord record);
  Result<std::vector<PresenceRecord>> active_watchers(std::string_view scope,
                                                      std::int64_t now_ns) const;

  // Bidirectional NDJSON pipe/SSH transport over signed PeerEnvelopes.
  Result<void> send_envelope(std::ostream &out, const PeerEnvelope &envelope);
  Result<std::size_t> replay_outbound(std::ostream &out) const;
  Result<EnvelopeIngestResult> receive_envelope(const PeerEnvelope &envelope,
                                                const KnownPeersStore &known_peers);
  Result<BridgePumpReport> pump_inbound(std::istream &in,
                                        const KnownPeersStore &known_peers);
  Result<std::vector<PeerEnvelope>> envelopes() const;

  // Helpers to package typed Stage 0 payloads into signed PeerEnvelopes.
  static Result<PeerEnvelope>
  sign_causal_event_envelope(const PeerIdentityStore &identity,
                             const CausalEvent &event, const PeerEnvelopeMeta &meta,
                             const Value &extra_payload = Value::object({}));
  static Result<PeerEnvelope> sign_receipt_envelope(const PeerIdentityStore &identity,
                                                    const MessageReceipt &receipt,
                                                    const PeerEnvelopeMeta &meta);
  static Result<PeerEnvelope> sign_presence_envelope(const PeerIdentityStore &identity,
                                                     const PresenceRecord &presence,
                                                     const PeerEnvelopeMeta &meta);

private:
  BoardBridge(std::filesystem::path root, int dir_fd) noexcept
      : root_(std::move(root)), dir_fd_(dir_fd) {}

  std::filesystem::path root_;
  int dir_fd_ = -1;
};

} // namespace blackbird
