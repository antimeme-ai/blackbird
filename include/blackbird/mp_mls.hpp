#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/mp_protocol.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct BbMlsEngine;

namespace blackbird {

inline constexpr std::size_t kMlsGroupIdBytes = 24U;
inline constexpr std::size_t kMlsHashBytes = 32U;
inline constexpr std::size_t kMlsMsgIdBytes = 16U;
inline constexpr std::size_t kMlsDeviceBindingBytes = 236U;
inline constexpr std::size_t kMlsLeafCredBytes = 276U;
inline constexpr std::size_t kMlsRootRotationBytes = 219U;
inline constexpr std::size_t kMlsInviteFragmentBytes = 114U;
inline constexpr std::size_t kMlsInviteRecordBytes = 93U;
inline constexpr std::size_t kMlsWelcomeAuthBytes = 177U;
inline constexpr std::size_t kMlsSafetyNumberV2Len = 39U;
inline constexpr std::size_t kMlsEpochAuthCodeLen = 29U;
inline constexpr std::size_t kMlsMaxAppWireBytes = 24000U;
inline constexpr std::uint64_t kMlsMaxFramesPerEpoch = 900U;

using MlsGroupId = std::array<std::uint8_t, kMlsGroupIdBytes>;
using MlsHash32 = std::array<std::uint8_t, kMlsHashBytes>;
using MlsInnerMsgId = std::array<std::uint8_t, kMlsMsgIdBytes>;
using MlsDeviceBinding = std::array<std::uint8_t, kMlsDeviceBindingBytes>;
using MlsRootRotationStmt = std::array<std::uint8_t, kMlsRootRotationBytes>;

enum class MpMlsError : std::int64_t {
  none = 0,
  null_pointer = 1,
  invalid_arg = 2,
  policy_violation = 3,
  credential_invalid = 4,
  equivocation = 5,
  pending_removal = 6,
  epoch_stale = 7,
  duplicate_msg = 8,
  self_clone_detected = 9,
  bucket_overflow = 10,
  storage = 11,
  panic = 12,
  bad_confirmation = 13,
  frame_cap = 14,
  not_found = 15,
  unsupported = 16,
};

constexpr MpMlsError mp_mls_error_of(const Error &error) noexcept {
  return static_cast<MpMlsError>(error.detail);
}

std::string_view mp_mls_error_name(MpMlsError detail) noexcept;

enum class MpMlsMsgClass : std::uint32_t {
  chat = 1U,
  agent_card = 2U,
  ephemeral_status = 3U,
  invite_control = 4U,
};

enum class MpMlsTrustTier : std::uint32_t {
  tier0_unverified = 0U,
  tier1_cloud_or_browser = 1U,
  tier2_self_custody_tofu = 2U,
  tier3_self_custody_verified = 3U,
};

std::string_view mp_mls_trust_tier_label(MpMlsTrustTier tier) noexcept;

bool mp_mls_compiled_in() noexcept;

struct MpMlsActiveDeviceEntry {
  std::uint64_t device_id = 0U;
  std::uint32_t device_gen = 1U;
  mp::Ed25519PubKey mls_sig_pubkey{};

  bool operator==(const MpMlsActiveDeviceEntry &) const = default;
};

struct MpMlsEngineConfig {
  std::filesystem::path state_dir;
  mp::AccountId account_id = mp::AccountId::create(1U).value();
  mp::DeviceId device_id = mp::DeviceId::create(1U).value();
  std::uint32_t root_gen = 1U;
  std::uint32_t device_gen = 1U;
  std::uint8_t client_class = 1U; // 1=blackbird, 2=outpost, 3=browser
  bool agent_capable = true;
  std::uint8_t custody_mode = 1U; // 0=cloud-managed, 1=self-custody
  mp::Ed25519Seed mls_sig_seed{};
  std::array<std::uint8_t, 32> store_enc_key{};
  MlsDeviceBinding device_binding{};
  std::vector<std::uint8_t> device_list_bytes;
};

struct MpMlsRoomPolicy {
  mp::PartyId party_id = mp::PartyId::create(1U).value();
  bool require_self_custody = false;
  bool allow_browser_devices = true;
  std::uint64_t org_id = 0U;
  std::vector<std::uint64_t> host_account_ids;
};

struct MpMlsCreatedGroup {
  MlsGroupId group_id{};
  std::vector<std::uint8_t> group_info_bytes;
};

struct MpMlsMintedInvite {
  std::string fragment_b64url;
  MlsHash32 server_invite_token{};
  MlsHash32 server_token_hash{};
  std::vector<std::uint8_t> invite_record_bytes;
};

struct MpMlsPreparedJoin {
  MlsGroupId group_id{};
  std::uint64_t invite_id = 0U;
  std::uint64_t invite_epoch = 0U;
  std::uint64_t expires_at_s = 0U;
  std::uint8_t policy_bits = 0U;
  mp::Ed25519PubKey inviter_root_pk{};
  MlsHash32 server_invite_token{};
  MlsHash32 kp_ref{};
  MlsHash32 join_proof{};
  std::vector<std::uint8_t> kp_bytes;
};

struct MpMlsPreparedDirectJoin {
  MlsGroupId group_id{};
  MlsHash32 kp_ref{};
  std::vector<std::uint8_t> kp_bytes;
};

struct MpMlsAddCommit {
  std::vector<std::uint8_t> commit_bytes;
  std::vector<std::uint8_t> welcome_bytes;
  std::vector<std::uint8_t> welcome_auth_bytes;
};

struct MpMlsTentativeAck {
  std::uint8_t status = 0U; // 1=OK, 2=REJECT
  std::vector<std::uint8_t> ack_bytes;
};

struct MpMlsEncryptedApp {
  std::uint64_t mls_epoch = 0U;
  std::uint64_t device_epoch_seq = 0U;
  std::uint64_t total_sent_in_epoch = 0U;
  bool needs_pcs_self_update = false;
  std::vector<std::uint8_t> wire_bytes;
};

struct MpMlsDecryptedApp {
  std::uint64_t mls_epoch = 0U;
  std::uint64_t auth_account_id = 0U;
  std::uint64_t auth_device_id = 0U;
  std::uint64_t device_epoch_seq = 0U;
  MpMlsMsgClass msg_class = MpMlsMsgClass::chat;
  MlsInnerMsgId inner_msg_id{};
  std::uint8_t sender_client_class = 0U;
  std::uint8_t sender_custody_mode = 0U;
  bool sender_agent_capable = false;
  bool is_historical_catchup = false;
  std::vector<std::uint8_t> plaintext;
};

struct MpMlsRoomStatus {
  MlsGroupId group_id{};
  std::uint64_t mls_epoch = 0U;
  MlsHash32 epoch_authenticator{};
  std::string epoch_authenticator_code;
  MpMlsTrustTier trust_tier = MpMlsTrustTier::tier0_unverified;
  bool has_declared_agent = false;
  bool has_pending_removals = false;
  bool clone_detected = false;
  bool needs_pcs_self_update = false;
  bool inviter_unconfirmed = false;
  std::uint32_t occupied_leaf_count = 0U;

  bool operator==(const MpMlsRoomStatus &) const = default;
};

// Stateless canonical binary identity helpers delegating to `bb_mls_*`.
Result<MlsDeviceBinding> mp_mls_sign_device_binding(
    mp::AccountId account_id, std::uint32_t root_gen, mp::DeviceId device_id,
    std::uint32_t device_gen, std::uint8_t client_class, bool agent_capable,
    std::uint8_t custody_mode, std::uint64_t iat_s, std::uint64_t exp_s,
    const mp::Ed25519Seed &root_seed, const mp::Ed25519Seed &device_seed);

Result<void>
mp_mls_verify_device_binding(std::span<const std::uint8_t> binding_bytes,
                             std::optional<std::uint64_t> now_s = std::nullopt);

Result<std::vector<std::uint8_t>> mp_mls_sign_device_list(
    mp::AccountId account_id, std::uint32_t root_gen, std::uint64_t list_version,
    std::uint64_t iat_s, std::uint64_t exp_s,
    std::span<const MpMlsActiveDeviceEntry> entries, const mp::Ed25519Seed &root_seed);

Result<void> mp_mls_verify_device_list(std::span<const std::uint8_t> list_bytes,
                                       const mp::Ed25519PubKey &expected_root_pk);

Result<MlsRootRotationStmt>
mp_mls_sign_root_rotation(mp::AccountId account_id, std::uint32_t old_root_gen,
                          std::uint32_t new_root_gen, std::uint8_t old_custody_mode,
                          std::uint8_t new_custody_mode, std::uint64_t rotated_at_s,
                          const mp::Ed25519Seed &old_root_seed,
                          const mp::Ed25519Seed &new_root_seed);

Result<void> mp_mls_verify_root_rotation(std::span<const std::uint8_t> stmt_bytes);

Result<std::string>
mp_mls_format_epoch_authenticator(std::span<const std::uint8_t> auth_bytes);

// Zero-leak C++23 RAII wrapper over `BbMlsEngine*` (unified `libblackbird_p2p.a`).
class MpMlsEngine {
public:
  static Result<MpMlsEngine> open(const MpMlsEngineConfig &config);

  MpMlsEngine() noexcept = default;
  MpMlsEngine(const MpMlsEngine &) = delete;
  MpMlsEngine &operator=(const MpMlsEngine &) = delete;
  MpMlsEngine(MpMlsEngine &&other) noexcept;
  MpMlsEngine &operator=(MpMlsEngine &&other) noexcept;
  ~MpMlsEngine();

  bool valid() const noexcept { return handle_ != nullptr; }
  void close() noexcept;

  Result<MpMlsCreatedGroup> create_group(
      const MpMlsRoomPolicy &policy, const mp::Ed25519PubKey &ds_pubkey,
      std::optional<std::array<std::uint8_t, 8>> incarnation_nonce = std::nullopt);

  Result<MpMlsMintedInvite> mint_invite(const MlsGroupId &group_id,
                                        std::uint64_t invite_id, std::uint32_t max_uses,
                                        std::uint64_t expires_at_s);

  Result<void>
  register_invite_record(const MlsGroupId &group_id,
                         std::span<const std::uint8_t> invite_record_bytes);

  Result<MpMlsPreparedJoin> prepare_join(std::string_view fragment_b64url);

  Result<MpMlsPreparedDirectJoin> prepare_direct_join(const MlsGroupId &group_id);

  Result<MlsGroupId> process_welcome(mp::PartyId expected_party_id,
                                     const mp::Ed25519PubKey &expected_ds_pubkey,
                                     std::span<const std::uint8_t> welcome_bytes,
                                     std::span<const std::uint8_t> welcome_auth_bytes);

  Result<MpMlsAddCommit> commit_add_invitee(const MlsGroupId &group_id,
                                            std::uint64_t invite_id,
                                            std::span<const std::uint8_t> kp_bytes,
                                            const MlsHash32 &join_proof,
                                            std::uint64_t now_s,
                                            bool allow_delegated = false);

  Result<MpMlsAddCommit> commit_add_sibling(const MlsGroupId &group_id,
                                            std::span<const std::uint8_t> kp_bytes,
                                            std::uint64_t now_s = 0U);

  Result<void> apply_proposal(const MlsGroupId &group_id,
                              std::span<const std::uint8_t> proposal_bytes);

  Result<std::vector<std::uint8_t>>
  commit_pending_or_self_update(const MlsGroupId &group_id, bool has_pending_proposals);

  Result<MpMlsTentativeAck>
  stage_tentative_commit(const MlsGroupId &group_id,
                         std::span<const std::uint8_t> commit_bytes);

  Result<void> finalize_commit(const MlsGroupId &group_id,
                               std::span<const std::uint8_t> commit_bytes,
                               std::uint64_t now_s = 0U);

  Result<void> discard_tentative(const MlsGroupId &group_id);

  Result<MpMlsEncryptedApp> encrypt_app(const MlsGroupId &group_id,
                                        const MlsInnerMsgId &inner_msg_id,
                                        MpMlsMsgClass msg_class,
                                        std::span<const std::uint8_t> plaintext,
                                        std::uint64_t now_s = 0U);

  Result<MpMlsDecryptedApp> decrypt_app(const MlsGroupId &group_id,
                                        std::span<const std::uint8_t> wire_bytes,
                                        bool is_catchup_hint = false);

  Result<void> observe_device_list(const MlsGroupId &group_id,
                                   std::span<const std::uint8_t> list_bytes,
                                   std::uint64_t now_s = 0U);

  Result<void> apply_root_rotation(const MlsGroupId &group_id,
                                   std::span<const std::uint8_t> stmt_bytes);

  Result<std::uint32_t> prune_past_epochs(const MlsGroupId &group_id,
                                          std::uint64_t now_s = 0U);

  Result<MpMlsRoomStatus> room_status(const MlsGroupId &group_id,
                                      std::uint64_t now_s = 0U) const;

  Result<void> mark_peer_verified_oob(const MlsGroupId &group_id,
                                      mp::AccountId peer_account_id);

  Result<void> mark_clone_detected(const MlsGroupId &group_id);

private:
  explicit MpMlsEngine(BbMlsEngine *handle) noexcept : handle_(handle) {}

  BbMlsEngine *handle_ = nullptr;
};

} // namespace blackbird
