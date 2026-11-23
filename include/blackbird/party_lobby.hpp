#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/party_chat.hpp"
#include "blackbird/peer_identity.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace blackbird {

inline constexpr std::uint32_t kPartyLobbyProtocolVersion = 1;
inline constexpr std::int64_t kPartyLobbyDefaultTtlNs = 300LL * 1000000000LL;
inline constexpr std::int64_t kPartyLobbyMaxTtlNs = 3600LL * 1000000000LL;
inline constexpr std::int64_t kPartyLobbyMaxFutureSkewNs = 60LL * 1000000000LL;

inline constexpr std::size_t kPartyLobbyMaxRooms = 64U;
inline constexpr std::size_t kPartyLobbyMaxMembersPerRoom = 64U;
inline constexpr std::size_t kPartyLobbyMaxMessagesPerRoom = 1024U;
inline constexpr std::size_t kPartyLobbyMaxClients = 32U;
inline constexpr std::size_t kPartyLobbyMaxLineBytes = 256U * 1024U;
inline constexpr std::size_t kPartyLobbyMaxRoomIdBytes = 128U;
inline constexpr std::size_t kPartyLobbyMaxSignatureB64Bytes = 24U * 1024U;
inline constexpr int kPartyLobbyDefaultIoTimeoutMs = 5000;

// Distinct non-mutually-convertible string view wrappers so callers can pass
// literals, std::string, or std::string_view directly without swappable-parameter
// ambiguity.
struct LobbyRoomRef {
  std::string_view value;
  constexpr LobbyRoomRef(std::string_view room) noexcept : value(room) {}
  constexpr LobbyRoomRef(const char *room) noexcept : value(room ? room : "") {}
  LobbyRoomRef(const std::string &room) noexcept : value(room) {}
};

struct LobbyActorFingerprintRef {
  std::string_view value;
  constexpr LobbyActorFingerprintRef(std::string_view fp) noexcept : value(fp) {}
  constexpr LobbyActorFingerprintRef(const char *fp) noexcept : value(fp ? fp : "") {}
  LobbyActorFingerprintRef(const std::string &fp) noexcept : value(fp) {}
};

struct LobbyAliasRef {
  std::string_view value;
  constexpr LobbyAliasRef(std::string_view alias) noexcept : value(alias) {}
  constexpr LobbyAliasRef(const char *alias) noexcept : value(alias ? alias : "") {}
  LobbyAliasRef(const std::string &alias) noexcept : value(alias) {}
};

struct LobbyTargetRef {
  std::string_view value;
  constexpr LobbyTargetRef(std::string_view target) noexcept : value(target) {}
  constexpr LobbyTargetRef(const char *target) noexcept : value(target ? target : "") {}
  LobbyTargetRef(const std::string &target) noexcept : value(target) {}
};

struct LobbyBodyRef {
  std::string_view value;
  constexpr LobbyBodyRef(std::string_view body) noexcept : value(body) {}
  constexpr LobbyBodyRef(const char *body) noexcept : value(body ? body : "") {}
  LobbyBodyRef(const std::string &body) noexcept : value(body) {}
};

// User-scoped Unix-domain socket path for the pure in-RAM Party Lobby daemon:
// `$XDG_RUNTIME_DIR/blackbird/party.sock` if set and valid, else
// `/tmp/blackbird-<uid>/party.sock`.
std::filesystem::path default_party_socket_path();
std::filesystem::path
resolve_party_socket_path(std::optional<std::string_view> xdg_runtime_dir,
                          std::uint64_t uid);

bool valid_party_room_id(std::string_view room_id) noexcept;

// Signed ephemeral lease for live membership in the in-RAM Party Lobby.
// `ssh_target` is local transport metadata ONLY populated server-side from
// local operator configuration or verified KnownPeersStore entries; any wire
// `ssh_target` value is always ignored/stripped.
struct PartyLease {
  std::string room_id;
  std::string actor_fingerprint;
  std::string alias;
  PartyMemberRole role = PartyMemberRole::worker;
  std::string host;
  std::string model;
  std::optional<std::string> ssh_target;
  std::int64_t issued_ns = 0;
  std::int64_t expires_ns = 0;
  std::uint64_t lease_seq = 1;
  std::uint64_t revocation_epoch = 0;
  std::string signature_b64;

  bool operator==(const PartyLease &) const = default;
};

struct PartyLobbyPing {
  bool ok = false;
  std::uint32_t protocol_version = kPartyLobbyProtocolVersion;
  std::uint64_t revocation_epoch = 0;
  std::optional<std::string> active_room_id;
  std::size_t room_count = 0;
  std::int64_t server_pid = 0;

  bool operator==(const PartyLobbyPing &) const = default;
};

// Deterministic canonical JSON signing payloads and Ed25519 signing helpers
// backed by PeerIdentityStore (Base64-encoded SSHSIG detached signature).
Result<std::string> canonical_party_lease_payload(const PartyLease &lease);
Result<std::string> canonical_party_heartbeat_payload(
    LobbyRoomRef room_id, LobbyActorFingerprintRef actor_fingerprint,
    std::int64_t new_expires_ns, std::uint64_t revocation_epoch);

Result<PartyLease> sign_party_lease(const PeerIdentityStore &identity,
                                    PartyLease lease);
Result<std::string> sign_party_heartbeat(const PeerIdentityStore &identity,
                                         LobbyRoomRef room_id,
                                         std::int64_t new_expires_ns,
                                         std::uint64_t revocation_epoch = 0);

// Deterministic revocation epoch derived solely from KnownPeersStore's revoked
// peers and revoked grants (0 when nothing is revoked; strictly monotonic as
// revocations accumulate).
std::uint64_t
compute_party_revocation_epoch(const std::vector<PinnedPeer> &peers,
                               const std::vector<RevokedGrantRecord> &revoked_grants);

struct PartyLobbyServerConfig {
  std::filesystem::path socket_path;
  std::filesystem::path local_identity_dir;
  std::optional<PeerIdentity> local_identity;
  std::filesystem::path known_peers_dir;
  PeerIdentityConfig peer_identity_config{};
  std::optional<std::string> local_ssh_target;
  std::unordered_map<std::string, std::string> trusted_peer_ssh_targets;
  std::function<std::int64_t()> clock_now_ns;
  int io_timeout_ms = kPartyLobbyDefaultIoTimeoutMs;
  std::size_t max_rooms = kPartyLobbyMaxRooms;
  std::size_t max_members_per_room = kPartyLobbyMaxMembersPerRoom;
  std::size_t max_messages_per_room = kPartyLobbyMaxMessagesPerRoom;
  std::size_t max_clients = kPartyLobbyMaxClients;
  std::size_t max_line_bytes = kPartyLobbyMaxLineBytes;
};

// Ephemeral in-RAM Party Lobby daemon serving authenticated same-UID Unix
// socket clients over newline-delimited JSON frames. Never reads or writes any
// `party.json` file on disk.
class PartyLobbyServer {
public:
  static Result<std::unique_ptr<PartyLobbyServer>>
  start(PartyLobbyServerConfig config = {});

  PartyLobbyServer(const PartyLobbyServer &) = delete;
  PartyLobbyServer &operator=(const PartyLobbyServer &) = delete;
  PartyLobbyServer(PartyLobbyServer &&) = delete;
  PartyLobbyServer &operator=(PartyLobbyServer &&) = delete;
  ~PartyLobbyServer();

  const std::filesystem::path &socket_path() const noexcept;
  bool running() const noexcept;

  // Deterministic lifecycle hooks (safe to call from any thread).
  std::size_t reap_expired(std::int64_t now_ns);
  Result<std::uint64_t> refresh_revocations();
  std::uint64_t revocation_epoch() const noexcept;
  PartySnapshot snapshot(std::optional<std::string_view> room_id = std::nullopt) const;

  void stop();

private:
  struct Impl;
  explicit PartyLobbyServer(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

struct PartyLobbyClientConfig {
  int io_timeout_ms = kPartyLobbyDefaultIoTimeoutMs;
  std::size_t max_line_bytes = kPartyLobbyMaxLineBytes;
};

// Fortress-ready client talking to the local in-RAM PartyLobbyServer over a
// user-scoped Unix-domain socket (kernel peer-credential verified).
class PartyLobbyClient {
public:
  static Result<PartyLobbyClient>
  connect(const std::filesystem::path &socket_path = default_party_socket_path(),
          PartyLobbyClientConfig config = {});

  PartyLobbyClient() = default;
  PartyLobbyClient(const PartyLobbyClient &) = delete;
  PartyLobbyClient &operator=(const PartyLobbyClient &) = delete;
  PartyLobbyClient(PartyLobbyClient &&other) noexcept;
  PartyLobbyClient &operator=(PartyLobbyClient &&other) noexcept;
  ~PartyLobbyClient();

  bool connected() const noexcept { return fd_ >= 0; }
  void close() noexcept;

  Result<PartyLobbyPing> ping() const;
  Result<void> shutdown();

  Result<PartySnapshot> create_room(LobbyRoomRef room_id, const PartyLease &host_lease);
  Result<PartySnapshot> join_room(LobbyRoomRef room_id, const PartyLease &lease);
  Result<PartyLease> heartbeat(LobbyRoomRef room_id,
                               LobbyActorFingerprintRef actor_fingerprint,
                               std::int64_t new_expires_ns,
                               std::string_view signature_b64);
  Result<void> leave_room(LobbyRoomRef room_id,
                          LobbyActorFingerprintRef actor_fingerprint);
  Result<PartyParticipant> invite_friend(LobbyRoomRef room_id,
                                         LobbyAliasRef friend_alias);
  Result<void> kick_member(LobbyRoomRef room_id, LobbyAliasRef alias);
  Result<std::uint64_t> post_message(LobbyRoomRef room_id, LobbyAliasRef sender_alias,
                                     LobbyTargetRef target, LobbyBodyRef body,
                                     PartyMessageKind kind = PartyMessageKind::chat);
  Result<PartySnapshot>
  snapshot(std::optional<std::string_view> room_id = std::nullopt) const;
  Result<std::vector<PinnedPeer>> list_friends() const;
  Result<std::size_t> reap_expired(std::optional<std::int64_t> now_ns = std::nullopt);
  Result<std::uint64_t> refresh_revocations();

private:
  PartyLobbyClient(int fd, PartyLobbyClientConfig config) noexcept
      : fd_(fd), config_(config) {}

  Result<Value> invoke_rpc(std::string_view op, Value params) const;
  void invalidate_connection() const noexcept;

  mutable int fd_ = -1;
  PartyLobbyClientConfig config_{};
  mutable std::string read_buffer_;
};

} // namespace blackbird
