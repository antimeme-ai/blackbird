#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/value.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::uint32_t kPeerEnvelopeVersion = 1;
inline constexpr std::uint32_t kCapabilityGrantVersion = 1;
inline constexpr std::size_t kPeerFingerprintLength = 36;
inline constexpr std::size_t kPeerMaxAliasLength = 64;
inline constexpr std::size_t kPeerMaxIdLength = 128;
inline constexpr std::size_t kPeerMaxPublicKeyBytes = 2048;
inline constexpr std::size_t kPeerMaxTrustNoteBytes = 4096;
inline constexpr std::size_t kPeerMaxReasonBytes = 1024;
inline constexpr std::size_t kPeerMaxSignatureBytes = 16 * 1024;
inline constexpr std::size_t kPeerMaxPayloadBytes = 4 * 1024 * 1024;
inline constexpr std::size_t kPeerMaxAllowedTools = 128;
inline constexpr std::uint32_t kPeerMaxGrantTurns = 10000;
inline constexpr std::uint64_t kPeerMaxGrantTokens = 100000000;

enum class PeerEnvelopeKind : std::uint8_t {
  mail,
  brief,
  handoff,
  decision,
  artifact,
  review,
  recall,
};

enum class CapabilityGrantMode : std::uint8_t {
  direct_support,
  temporary_attachment,
};

std::string_view peer_envelope_kind_name(PeerEnvelopeKind kind) noexcept;
Result<PeerEnvelopeKind> parse_peer_envelope_kind(std::string_view name) noexcept;

std::string_view capability_grant_mode_name(CapabilityGrantMode mode) noexcept;
Result<CapabilityGrantMode> parse_capability_grant_mode(std::string_view name) noexcept;

bool valid_peer_alias(std::string_view alias) noexcept;
bool valid_peer_fingerprint(std::string_view fingerprint) noexcept;
bool valid_peer_recipient(std::string_view recipient) noexcept;

Result<std::string> canonicalize_ed25519_public_key(std::string_view public_key);
Result<std::string> peer_fingerprint_from_public_key(std::string_view public_key);

struct PeerIdentityConfig {
  std::string ssh_keygen_executable = "/usr/bin/ssh-keygen";
  std::string signature_namespace = "blackbird";
  int process_timeout_seconds = 15;
  std::function<bool()> cancelled;
};

struct PeerIdentity {
  std::string fingerprint;
  std::string public_key;
  bool operator==(const PeerIdentity &) const = default;
};

struct PinnedPeer {
  std::string alias;
  std::string fingerprint;
  std::string public_key;
  std::string trust_note;
  std::int64_t pinned_at_ns = 0;
  bool revoked = false;
  std::int64_t revoked_at_ns = 0;
  std::string revocation_reason;
  bool operator==(const PinnedPeer &) const = default;
};

struct PinPeerRequest {
  std::string alias;
  std::string public_key;
  std::string trust_note;
};

struct PeerRevocationRequest {
  std::string fingerprint;
  std::string reason;
};

struct RevokedGrantRecord {
  std::string grant_id;
  std::int64_t revoked_at_ns = 0;
  std::string reason;
  bool operator==(const RevokedGrantRecord &) const = default;
};

struct GrantRevocationRequest {
  std::string grant_id;
  std::string reason;
};

struct PeerEnvelopeDraft {
  std::string envelope_id;
  std::string to_fingerprint;
  std::string thread_id;
  PeerEnvelopeKind kind = PeerEnvelopeKind::mail;
  std::int64_t timestamp_ns = 0;
  Value payload = Value::object({});
};

struct PeerEnvelope {
  std::uint32_t version = kPeerEnvelopeVersion;
  std::string envelope_id;
  std::string from_fingerprint;
  std::string to_fingerprint;
  std::string thread_id;
  PeerEnvelopeKind kind = PeerEnvelopeKind::mail;
  std::int64_t timestamp_ns = 0;
  Value payload = Value::object({});
  std::string signature;
  bool operator==(const PeerEnvelope &) const = default;
};

struct CapabilityGrantDraft {
  std::string grant_id;
  CapabilityGrantMode mode = CapabilityGrantMode::direct_support;
  std::string grantee_fingerprint;
  std::string target_peer;
  std::optional<std::string> command_room;
  std::uint32_t max_turns = 1;
  std::uint64_t max_tokens = 1;
  std::vector<std::string> allowed_tools;
  std::int64_t issued_at_ns = 0;
  std::int64_t expires_at_ns = 0;
  bool revocable = true;
};

struct CapabilityGrant {
  std::uint32_t version = kCapabilityGrantVersion;
  std::string grant_id;
  CapabilityGrantMode mode = CapabilityGrantMode::direct_support;
  std::string grantor_fingerprint;
  std::string grantee_fingerprint;
  std::string target_peer;
  std::optional<std::string> command_room;
  std::uint32_t max_turns = 0;
  std::uint64_t max_tokens = 0;
  std::vector<std::string> allowed_tools;
  std::int64_t issued_at_ns = 0;
  std::int64_t expires_at_ns = 0;
  bool revocable = true;
  std::string signature;
  bool operator==(const CapabilityGrant &) const = default;
};

struct DetachedSignatureVerification {
  std::string_view expected_fingerprint;
  std::string_view public_key;
  std::string_view payload;
  std::string_view signature;
};

Value peer_to_value(const PinnedPeer &peer);
Value envelope_to_value(const PeerEnvelope &envelope);
Result<PeerEnvelope> envelope_from_value(const Value &value);
Value grant_to_value(const CapabilityGrant &grant);
Result<CapabilityGrant> grant_from_value(const Value &value);

Result<std::string> canonical_envelope_payload(const PeerEnvelope &envelope);
Result<std::string> canonical_grant_payload(const CapabilityGrant &grant);
Result<void> verify_detached_signature(const DetachedSignatureVerification &input,
                                       const PeerIdentityConfig &config = {});

// Owns a pinned 0700 operator identity directory containing a 0600 OpenSSH
// Ed25519 keypair and provides deterministic self-certifying fingerprinting
// and ssh-keygen -Y signing for PeerEnvelope and CapabilityGrant objects.
class PeerIdentityStore {
public:
  static Result<PeerIdentityStore> open_or_create(const std::filesystem::path &root,
                                                  PeerIdentityConfig config = {});
  static Result<PeerIdentityStore> open_existing(const std::filesystem::path &root,
                                                 PeerIdentityConfig config = {});

  PeerIdentityStore(const PeerIdentityStore &) = delete;
  PeerIdentityStore &operator=(const PeerIdentityStore &) = delete;
  PeerIdentityStore(PeerIdentityStore &&other) noexcept;
  PeerIdentityStore &operator=(PeerIdentityStore &&other) noexcept;
  ~PeerIdentityStore();

  const std::filesystem::path &root() const noexcept { return root_; }
  const PeerIdentity &identity() const noexcept { return identity_; }

  Result<std::string> sign_bytes(std::string_view payload) const;
  Result<PeerEnvelope> sign_envelope(PeerEnvelopeDraft draft) const;
  Result<CapabilityGrant> sign_grant(CapabilityGrantDraft draft) const;

private:
  PeerIdentityStore(std::filesystem::path root, int dir_fd, PeerIdentity identity,
                    PeerIdentityConfig config) noexcept
      : root_(std::move(root)), dir_fd_(dir_fd), identity_(std::move(identity)),
        config_(std::move(config)) {}

  std::filesystem::path root_;
  int dir_fd_ = -1;
  PeerIdentity identity_;
  PeerIdentityConfig config_;
};

// Zero-fortress peer trust store with explicit key-pinning protection against
// silent key swaps, peer revocation, local grant kill-switch revocation, and
// cryptographic verification of PeerEnvelope and CapabilityGrant objects.
class KnownPeersStore {
public:
  static Result<KnownPeersStore> open(const std::filesystem::path &root,
                                      PeerIdentityConfig config = {});

  KnownPeersStore(const KnownPeersStore &) = delete;
  KnownPeersStore &operator=(const KnownPeersStore &) = delete;
  KnownPeersStore(KnownPeersStore &&other) noexcept;
  KnownPeersStore &operator=(KnownPeersStore &&other) noexcept;
  ~KnownPeersStore();

  const std::filesystem::path &root() const noexcept { return root_; }

  // Pins alias -> ssh-ed25519 public key atomically in known_peers.json.
  // Rejects silent key swap for an existing alias with ErrorCode::conflict.
  Result<PinnedPeer> pin_peer(const PinPeerRequest &request);
  Result<PinnedPeer> revoke_peer(const PeerRevocationRequest &request);
  Result<std::vector<PinnedPeer>> list_peers() const;
  Result<std::optional<PinnedPeer>>
  find_by_fingerprint(std::string_view fingerprint) const;
  Result<std::optional<PinnedPeer>> find_by_alias(std::string_view alias) const;

  Result<RevokedGrantRecord> revoke_grant(const GrantRevocationRequest &request);
  Result<bool> is_grant_revoked(std::string_view grant_id) const;
  Result<std::vector<RevokedGrantRecord>> list_revoked_grants() const;

  // Verifies sender is pinned and non-revoked, and signature is valid over
  // exact canonical JSON bytes.
  Result<void> verify_envelope(const PeerEnvelope &envelope) const;

  // Verifies grantor is pinned and non-revoked, grant is not locally revoked,
  // issued_at_ns <= now_ns < expires_at_ns, and signature is valid over exact
  // canonical JSON bytes.
  Result<void> verify_grant(const CapabilityGrant &grant, std::int64_t now_ns) const;

private:
  KnownPeersStore(std::filesystem::path root, int dir_fd,
                  PeerIdentityConfig config) noexcept
      : root_(std::move(root)), dir_fd_(dir_fd), config_(std::move(config)) {}

  std::filesystem::path root_;
  int dir_fd_ = -1;
  PeerIdentityConfig config_;
};

} // namespace blackbird
