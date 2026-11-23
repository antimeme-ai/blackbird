#pragma once

#include "blackbird/mp_protocol.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace blackbird::mp {

// ---------------------------------------------------------------------------
// Control client error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

enum class MpClientError : std::int64_t {
  none = 0,

  // Transport & TLS 1.3
  invalid_config = 1000,
  dns_failed = 1001,
  connect_failed = 1002,
  timeout = 1003,
  tls_init_failed = 1004,
  tls_ca_load_failed = 1005,
  tls_handshake_failed = 1006,
  tls_verify_failed = 1007,
  tls_alpn_mismatch = 1008,
  tls_io_failed = 1009,
  tls_closed = 1010,

  // HTTP/1.1 REST client
  http_header_too_large = 1100,
  http_body_too_large = 1101,
  http_malformed_response = 1102,
  http_chunked_malformed = 1103,
  http_status_error = 1104,
  http_unauthorized = 1105,
  http_forbidden = 1106,
  http_not_found = 1107,
  http_conflict = 1108,
  http_rate_limited = 1109,
  http_server_error = 1110,
  http_clock_skew = 1111,
  http_json_invalid = 1112,
  http_response_schema = 1113,
  http_bad_request = 1114,
  http_gone = 1115,

  // Local keystore
  keystore_invalid_path = 1200,
  keystore_not_found = 1201,
  keystore_insecure_permissions = 1202,
  keystore_symlink_rejected = 1203,
  keystore_corrupt = 1204,
  keystore_io_failed = 1205,

  // RFC 6455 WebSocket client
  ws_upgrade_rejected = 1300,
  ws_accept_mismatch = 1301,
  ws_subprotocol_mismatch = 1302,
  ws_protocol_error = 1303,
  ws_masked_server_frame = 1304,
  ws_frame_too_large = 1305,
  ws_unexpected_text_frame = 1306,
  ws_closed = 1307,
  ws_not_open = 1308,

  // Caller identity state
  missing_root_key = 1400,
  missing_device_key = 1401,
  missing_account_identity = 1402,
};

constexpr MpClientError mp_client_error_of(const Error &error) noexcept {
  return static_cast<MpClientError>(error.detail);
}

const char *mp_client_error_name(MpClientError detail) noexcept;

// ---------------------------------------------------------------------------
// Wire & client limits
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMaxHttpHeaderBytes = 16U * 1024U;
inline constexpr std::size_t kMaxHttpBodyBytes = 256U * 1024U;
inline constexpr std::string_view kDefaultMpAuthority = "api.multiplayer.tech";
inline constexpr std::uint16_t kDefaultMpPort = 443U;
inline constexpr std::string_view kMp1HeartbeatPing = "MP1:PING";
inline constexpr std::string_view kMp1HeartbeatPong = "MP1:PONG";

// ---------------------------------------------------------------------------
// 1. Local device identity store (0700 dir, 0600 files, RAII OPENSSL_cleanse)
// ---------------------------------------------------------------------------

class CleansedSeed {
public:
  CleansedSeed() noexcept = default;
  explicit CleansedSeed(const Ed25519Seed &seed) noexcept : seed_(seed) {}
  CleansedSeed(const CleansedSeed &other) noexcept : seed_(other.seed_) {}
  CleansedSeed &operator=(const CleansedSeed &other) noexcept;
  CleansedSeed(CleansedSeed &&other) noexcept;
  CleansedSeed &operator=(CleansedSeed &&other) noexcept;
  ~CleansedSeed();

  static Result<CleansedSeed> generate();

  const Ed25519Seed &bytes() const noexcept { return seed_; }
  Ed25519Seed &mutable_bytes() noexcept { return seed_; }
  void cleanse() noexcept;

  bool operator==(const CleansedSeed &other) const noexcept;

private:
  Ed25519Seed seed_{};
};

struct MpIdentityState {
  std::optional<CleansedSeed> root_seed;
  CleansedSeed device_seed;
  std::optional<AccountId> account_id;
  std::optional<DeviceId> device_id;
  std::string handle;
  std::string authority = std::string{kDefaultMpAuthority};
  std::vector<std::uint8_t> device_cwt;

  bool operator==(const MpIdentityState &) const = default;
};

struct InstallDeviceCwtRequest {
  AccountId account_id;
  DeviceId device_id;
  std::string handle;
  std::vector<std::uint8_t> device_cwt;
  std::optional<std::string> authority;
  std::optional<Ed25519PubKey> expected_root_pubkey;
  std::optional<std::int64_t> now_s;
};

class MpIdentityStore {
public:
  // Fails closed without creating directories or files.
  static Result<MpIdentityStore> open_existing(const std::filesystem::path &dir);

  // Opens an existing keystore if present, or initializes a new device-only keystore
  // (no root_seed, no account_id/device_id, empty device_cwt) with 0700/0600 perms.
  // Fails closed on symlinks, insecure permissions, or corrupt files.
  static Result<MpIdentityStore>
  open_or_init_device(const std::filesystem::path &dir,
                      std::string_view authority = kDefaultMpAuthority);

  // Creates directory with 0700 and writes files atomically with 0600,
  // cleansing temporary buffers.
  static Result<MpIdentityStore> save(const std::filesystem::path &dir,
                                      const MpIdentityState &state);

  MpIdentityStore(const MpIdentityStore &) = delete;
  MpIdentityStore &operator=(const MpIdentityStore &) = delete;
  MpIdentityStore(MpIdentityStore &&other) noexcept;
  MpIdentityStore &operator=(MpIdentityStore &&other) noexcept;
  ~MpIdentityStore();

  const std::filesystem::path &directory() const noexcept { return dir_; }
  const MpIdentityState &state() const noexcept { return state_; }

  Result<void> update(const MpIdentityState &state);
  // Validates account/device/handle and confirms the CWT's embedded cnf device_pubkey
  // matches this store's device key (plus full Ed25519 signature + expiry verification
  // when expected_root_pubkey is provided) before atomically updating disk.
  Result<void> install_cwt(const InstallDeviceCwtRequest &request);
  Result<Ed25519SigningKey> device_signing_key() const;
  Result<Ed25519SigningKey> root_signing_key() const;

private:
  MpIdentityStore(std::filesystem::path dir, int dir_fd, MpIdentityState state) noexcept
      : dir_(std::move(dir)), dir_fd_(dir_fd), state_(std::move(state)) {}

  std::filesystem::path dir_;
  int dir_fd_ = -1;
  MpIdentityState state_;
};

// ---------------------------------------------------------------------------
// 2. TLS 1.3 + HTTP/1.1 client configuration & REST DTOs
// ---------------------------------------------------------------------------

struct MpClientConfig {
  std::string authority = std::string{kDefaultMpAuthority};
  // Optional TCP target override (e.g. "127.0.0.1" for loopback TLS tests).
  // TLS SNI, X.509 hostname verification, HTTP Host, and RFC 9421 @authority
  // always derive from `authority`.
  std::string connect_host;
  std::uint16_t port = kDefaultMpPort;
  std::optional<std::filesystem::path> ca_bundle_path;
  int connect_timeout_ms = 5000;
  int io_timeout_ms = 10000;
};

struct HealthResponse {
  bool ok = false;
  std::uint64_t server_now_ms = 0U;
  bool operator==(const HealthResponse &) const = default;
};

struct RelayProbeResponse {
  bool ok = false;
  int http_status = 0;
  std::uint64_t rtt_ms = 0U;
  std::string url;
  bool operator==(const RelayProbeResponse &) const = default;
};

struct RegisterAccountRequest {
  std::string invite_secret;
  std::string handle;
  Ed25519PubKey device_pubkey{};
  std::string device_label;
  std::vector<std::uint8_t> device_cwt;
  // Optional 16..64 char Idempotency-Key; generated from CSPRNG if empty.
  std::string idempotency_key;
};

struct RegisterAccountResponse {
  AccountId account_id;
  DeviceId device_id;
  std::string handle;
  bool operator==(const RegisterAccountResponse &) const = default;
};

struct DeviceInfo {
  DeviceId device_id;
  Ed25519PubKey pubkey{};
  std::string label;
  std::uint64_t cwt_expires_ms = 0U;
  std::uint64_t generation = 0U;
  bool pop_verified = false;
  std::uint64_t created_at_ms = 0U;
  std::optional<std::uint64_t> revoked_at_ms;
  bool operator==(const DeviceInfo &) const = default;
};

struct WhoamiResponse {
  AccountId account_id;
  std::string handle;
  Ed25519PubKey root_pubkey{};
  std::vector<DeviceInfo> devices;
  std::vector<PartyId> active_party_ids;
  bool operator==(const WhoamiResponse &) const = default;
};

struct ResolvedAccount {
  AccountId account_id;
  std::string handle;
  Ed25519PubKey root_pubkey{};
  bool operator==(const ResolvedAccount &) const = default;
};

struct EnrollDeviceRequest {
  Ed25519PubKey device_pubkey{};
  std::string device_label;
  std::vector<std::uint8_t> device_cwt;
};

struct EnrollDeviceResponse {
  DeviceId device_id;
  std::uint64_t cwt_expires_ms = 0U;
  bool operator==(const EnrollDeviceResponse &) const = default;
};

struct RevokeDeviceResponse {
  bool revoked = false;
  std::vector<PartyId> evicted_parties;
  std::uint64_t pending_retries = 0U;
  bool operator==(const RevokeDeviceResponse &) const = default;
};

// Strict Crockford Base32 web-session user code normalizer (accepts XXXXXXXX or
// XXXX-XXXX in uppercase/lowercase, rejects I/L/O/U and controls, returns XXXX-XXXX).
Result<std::string> normalize_web_user_code(std::string_view user_code);

// Crockford Base32 device-link code normalizer (accepts XXXXXXXX or XXXX-XXXX in
// uppercase/lowercase plus Crockford typo aliases O->0 and I/L->1, rejects U and
// controls, returns canonical uppercase XXXX-XXXX).
Result<std::string> normalize_device_link_code(std::string_view link_code);

struct RecoverLookupResponse {
  AccountId account_id;
  std::string handle;
  Ed25519PubKey root_pubkey{};
  std::string safety_number;
  std::vector<DeviceInfo> devices;
  bool operator==(const RecoverLookupResponse &) const = default;
};

struct CreateDeviceLinkResponse {
  std::string link_code;
  std::uint64_t expires_at_ms = 0U;
  bool operator==(const CreateDeviceLinkResponse &) const = default;
};

struct ClaimDeviceLinkResponse {
  std::string poll_token;
  std::string server_device_fingerprint;
  std::string local_device_fingerprint;
  std::uint64_t expires_at_ms = 0U;
  bool operator==(const ClaimDeviceLinkResponse &) const = default;
};

enum class DeviceLinkState : std::uint8_t {
  waiting_for_device = 0,
  pending_approval = 1,
};

struct InspectDeviceLinkResponse {
  DeviceLinkState state = DeviceLinkState::waiting_for_device;
  std::optional<std::string> suggested_label;
  std::optional<Ed25519PubKey> device_pubkey;
  std::optional<std::string> server_device_fingerprint;
  std::optional<std::string> local_device_fingerprint;
  std::optional<std::string> device_label;
  std::optional<std::string> requester_country;
  std::uint64_t created_at_ms = 0U;
  std::uint64_t expires_at_ms = 0U;
  bool operator==(const InspectDeviceLinkResponse &) const = default;
};

struct ApproveDeviceLinkRequest {
  std::string link_code;
  Ed25519PubKey device_pubkey{};
  std::vector<std::uint8_t> device_cwt;
  std::string device_label;
};

struct ApproveDeviceLinkResponse {
  bool approved = false;
  AccountId account_id;
  DeviceId device_id;
  std::string device_label;
  std::string device_fingerprint;
  std::uint64_t cwt_expires_ms = 0U;
  bool operator==(const ApproveDeviceLinkResponse &) const = default;
};

struct PollDeviceLinkRequest {
  std::string link_code;
  std::string poll_token;
};

struct PollDeviceLinkResponse {
  bool pending = false;
  bool approved = false;
  std::optional<std::uint64_t> expires_at_ms;
  std::optional<AccountId> account_id;
  std::optional<std::string> handle;
  std::optional<DeviceId> device_id;
  std::optional<Ed25519PubKey> root_pubkey;
  std::vector<std::uint8_t> device_cwt;
  std::optional<std::uint64_t> cwt_expires_ms;
  std::optional<std::string> safety_number;
  bool operator==(const PollDeviceLinkResponse &) const = default;
};

struct WebSessionApproveResponse {
  bool approved = false;
  std::string scope;
  std::optional<std::uint64_t> expires_at_ms;
  bool operator==(const WebSessionApproveResponse &) const = default;
};

using PresenceStatus = PresenceVisibility;

enum class FriendEdgeState : std::uint8_t {
  friend_edge = 0,
  invite_sent = 1,
  invite_received = 2,
  blocked = 3,
};

struct FriendEdge {
  AccountId peer_account_id;
  FriendEdgeState state = FriendEdgeState::friend_edge;
  std::uint64_t updated_at_ms = 0U;
  std::optional<std::string> handle = std::nullopt;
  std::optional<Ed25519PubKey> root_pubkey = std::nullopt;
  std::optional<std::string> safety_number = std::nullopt;
  bool operator==(const FriendEdge &) const = default;
};

struct FriendRequestResponse {
  AccountId target_account_id;
  FriendEdgeState state = FriendEdgeState::invite_sent;
  int http_status = 0;
  bool operator==(const FriendRequestResponse &) const = default;
};

struct CreatePartyRequest {
  PartyVisibility visibility = PartyVisibility::private_party;
  PartyJoinMode join_mode = PartyJoinMode::invite_only;
  RelayPolicy relay_policy = RelayPolicy::allow_relays;
  std::uint8_t max_members = 12U;
  EndpointDescriptor endpoint;
  std::string relay_url;
};

struct CreatePartyResponse {
  PartyId party_id;
  std::uint64_t party_epoch = 0U;
  std::string pinned_relay_url;
  bool operator==(const CreatePartyResponse &) const = default;
};

struct PartySummary {
  PartyId party_id;
  std::uint64_t party_epoch = 0U;
  AccountId leader_account_id;
  DeviceId leader_device_id;
  PartyVisibility visibility = PartyVisibility::private_party;
  PartyJoinMode join_mode = PartyJoinMode::invite_only;
  RelayPolicy relay_policy = RelayPolicy::allow_relays;
  std::string pinned_relay_url;
  std::uint8_t max_members = 2U;
  std::uint8_t member_count = 0U;
  bool operator==(const PartySummary &) const = default;
};

struct CreatePartyInviteRequest {
  PartyId party_id;
  std::optional<AccountId> target_account_id;
  std::uint8_t max_uses = 1U;
  std::uint32_t ttl_sec = 3600U;
};

struct CreatePartyInviteResponse {
  PartyInviteId party_invite_id;
  std::uint64_t expires_at_ms = 0U;
  std::optional<std::string> invite_link;
  bool operator==(const CreatePartyInviteResponse &) const = default;
};

struct JoinPartyRequest {
  PartyId party_id;
  EndpointDescriptor endpoint;
  std::optional<std::string> invite_link;
};

struct JoinPartyResponse {
  bool pending_approval = false;
  std::uint64_t party_epoch = 0U;
  std::optional<RequestId> request_id;
  bool operator==(const JoinPartyResponse &) const = default;
};

struct KickMemberRequest {
  PartyId party_id;
  AccountId target_account_id;
  std::uint64_t expected_party_epoch = 0U;
};

struct DisbandPartyRequest {
  PartyId party_id;
  std::uint64_t expected_party_epoch = 0U;
};

struct PartyMutationResponse {
  std::uint64_t party_epoch = 0U;
  bool operator==(const PartyMutationResponse &) const = default;
};

// ---------------------------------------------------------------------------
// 3. Live RFC 6455 WebSocket Client over TLS 1.3 + HTTP/1.1 ALPN
// ---------------------------------------------------------------------------

struct MpWsMp1Frame {
  DecodedFrame frame;
  bool operator==(const MpWsMp1Frame &) const = default;
};

struct MpWsPong {
  bool operator==(const MpWsPong &) const = default;
};

struct MpWsClosed {
  std::uint16_t code = 1000U;
  bool operator==(const MpWsClosed &) const = default;
};

using MpWsEvent = std::variant<MpWsMp1Frame, MpWsPong, MpWsClosed>;

struct MpSocketConnectRequest {
  MpClientConfig config;
  std::string path;
  AccountId account_id;
  DeviceId device_id;
  std::int64_t clock_offset_s = 0;
};

class MpControlSocket {
public:
  static Result<MpControlSocket> connect(const MpSocketConnectRequest &request,
                                         const Ed25519SigningKey &device_key);

  MpControlSocket(const MpControlSocket &) = delete;
  MpControlSocket &operator=(const MpControlSocket &) = delete;
  MpControlSocket(MpControlSocket &&other) noexcept;
  MpControlSocket &operator=(MpControlSocket &&other) noexcept;
  ~MpControlSocket();

  bool is_open() const noexcept;
  Result<void> send_mp1(std::uint32_t seq, const Mp1Message &message);
  Result<void> send_ping();
  // Returns std::nullopt when timeout_ms elapses with no complete event.
  Result<std::optional<MpWsEvent>> poll_event(int timeout_ms);
  Result<void> close(std::uint16_t code = 1000U);

private:
  struct Impl;
  explicit MpControlSocket(std::unique_ptr<Impl> impl) noexcept;
  std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// 4. Signed Control-Plane REST + WebSocket Client
// ---------------------------------------------------------------------------

class MpControlClient {
public:
  explicit MpControlClient(MpClientConfig config);
  MpControlClient(MpClientConfig config, MpIdentityState identity);

  MpControlClient(const MpControlClient &) = delete;
  MpControlClient &operator=(const MpControlClient &) = delete;
  MpControlClient(MpControlClient &&other) noexcept = default;
  MpControlClient &operator=(MpControlClient &&other) noexcept = default;
  ~MpControlClient() = default;

  const MpClientConfig &config() const noexcept { return config_; }
  const std::optional<MpIdentityState> &identity() const noexcept { return identity_; }
  void set_identity(MpIdentityState identity) { identity_ = std::move(identity); }

  std::int64_t clock_offset_seconds() const noexcept { return clock_offset_s_; }
  void set_clock_offset_seconds(std::int64_t offset_s) noexcept {
    clock_offset_s_ = offset_s;
  }

  // Unauthenticated liveness & clock sync
  Result<HealthResponse> health();

  // Unauthenticated TLS 1.3 relay liveness probe (GET <path>/ping)
  Result<RelayProbeResponse>
  probe_relay(std::string_view relay_url,
              std::optional<std::string_view> connect_host_override = std::nullopt,
              std::optional<std::uint16_t> port_override = std::nullopt) const;

  // Account onboarding (reg.<hex16> signed by root_signing_key)
  Result<RegisterAccountResponse>
  register_account(const Ed25519SigningKey &root_signing_key,
                   const RegisterAccountRequest &request);

  // Account & device management
  Result<WhoamiResponse> whoami();
  Result<ResolvedAccount> resolve_handle(std::string_view handle);
  Result<EnrollDeviceResponse> enroll_device(const EnrollDeviceRequest &request);
  Result<RevokeDeviceResponse> revoke_device(DeviceId device_id);

  // Identity Portability v1: recovery lookup (rec.<hex32> signed by root_signing_key)
  Result<RecoverLookupResponse>
  recover_account_lookup(const Ed25519SigningKey &root_signing_key);

  // Identity Portability v1: Primary-Initiated Device Linking
  Result<CreateDeviceLinkResponse>
  create_device_link(const std::optional<std::string> &device_label = std::nullopt);
  Result<ClaimDeviceLinkResponse>
  claim_device_link(std::string_view link_code,
                    const Ed25519SigningKey &device_signing_key,
                    std::string_view device_label);
  Result<InspectDeviceLinkResponse> inspect_device_link(std::string_view link_code);
  Result<ApproveDeviceLinkResponse>
  approve_device_link(const ApproveDeviceLinkRequest &request);
  Result<PollDeviceLinkResponse>
  poll_device_link(const Ed25519SigningKey &device_signing_key,
                   const PollDeviceLinkRequest &request);

  // Web account portal approval (device-key signed POST /v1/web-sessions/approve)
  Result<WebSessionApproveResponse> approve_web_session(std::string_view user_code);

  // Social graph (friends & blocks)
  Result<std::vector<FriendEdge>> list_friends();
  Result<FriendRequestResponse> send_or_accept_friend(AccountId target_account_id);
  Result<void> remove_friend(AccountId target_account_id);
  Result<void> block_account(AccountId target_account_id);

  // Parties
  Result<CreatePartyResponse> create_party(const CreatePartyRequest &request);
  Result<PartySummary> get_party(PartyId party_id);
  Result<CreatePartyInviteResponse>
  create_party_invite(const CreatePartyInviteRequest &request);
  Result<void> revoke_party_invite(PartyId party_id, PartyInviteId invite_id);
  Result<JoinPartyResponse> join_party(const JoinPartyRequest &request);
  Result<PartyMutationResponse> kick_member(const KickMemberRequest &request);
  Result<PartyMutationResponse> leave_party(PartyId party_id);
  Result<PartyMutationResponse> disband_party(const DisbandPartyRequest &request);

  // Live RFC 6455 WebSockets (automatically retry once on clock_skew)
  Result<MpControlSocket> connect_account_socket();
  Result<MpControlSocket> connect_social_ws();
  Result<MpControlSocket> connect_party_socket(PartyId party_id);

private:
  MpClientConfig config_;
  std::optional<MpIdentityState> identity_;
  std::int64_t clock_offset_s_ = 0;
};

} // namespace blackbird::mp
