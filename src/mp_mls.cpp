#include "blackbird/mp_mls.hpp"

#include <cstring>
#include <utility>

#if defined(BLACKBIRD_HAS_MLS) && BLACKBIRD_HAS_MLS
#include "blackbird_mls_abi.h"
#endif

namespace blackbird {

bool mp_mls_compiled_in() noexcept {
#if defined(BLACKBIRD_HAS_MLS) && BLACKBIRD_HAS_MLS
  return true;
#else
  return false;
#endif
}

std::string_view mp_mls_error_name(MpMlsError detail) noexcept {
  switch (detail) {
  case MpMlsError::none:
    return "none";
  case MpMlsError::null_pointer:
    return "null_pointer";
  case MpMlsError::invalid_arg:
    return "invalid_arg";
  case MpMlsError::policy_violation:
    return "policy_violation";
  case MpMlsError::credential_invalid:
    return "credential_invalid";
  case MpMlsError::equivocation:
    return "equivocation";
  case MpMlsError::pending_removal:
    return "pending_removal";
  case MpMlsError::epoch_stale:
    return "epoch_stale";
  case MpMlsError::duplicate_msg:
    return "duplicate_msg";
  case MpMlsError::self_clone_detected:
    return "self_clone_detected";
  case MpMlsError::bucket_overflow:
    return "bucket_overflow";
  case MpMlsError::storage:
    return "storage";
  case MpMlsError::panic:
    return "panic";
  case MpMlsError::bad_confirmation:
    return "bad_confirmation";
  case MpMlsError::frame_cap:
    return "frame_cap";
  case MpMlsError::not_found:
    return "not_found";
  case MpMlsError::unsupported:
    return "unsupported";
  }
  return "unknown";
}

std::string_view mp_mls_trust_tier_label(MpMlsTrustTier tier) noexcept {
  switch (tier) {
  case MpMlsTrustTier::tier0_unverified:
    return "Tier 0 — Unverified / Pending Re-Verification";
  case MpMlsTrustTier::tier1_cloud_or_browser:
    return "Tier 1 — Cloud-Assisted or Browser Present";
  case MpMlsTrustTier::tier2_self_custody_tofu:
    return "Tier 2 — Self-Custody Native (Peers Unverified)";
  case MpMlsTrustTier::tier3_self_custody_verified:
    return "Tier 3 — Self-Custody Native (All Peers Verified)";
  }
  return "Tier 0 — Unverified";
}

#if defined(BLACKBIRD_HAS_MLS) && BLACKBIRD_HAS_MLS

namespace {

Error map_mls_status(BbMlsStatus st) noexcept {
  const auto detail = static_cast<std::int64_t>(st);
  switch (st) {
  case BB_MLS_OK:
    return {ErrorCode::external_unknown, 0};
  case BB_MLS_ERR_NULL_POINTER:
  case BB_MLS_ERR_INVALID_ARG:
    return {ErrorCode::invalid_range, detail};
  case BB_MLS_ERR_POLICY_VIOLATION:
  case BB_MLS_ERR_PENDING_REMOVAL:
  case BB_MLS_ERR_EPOCH_STALE:
  case BB_MLS_ERR_FRAME_CAP:
    return {ErrorCode::conflict, detail};
  case BB_MLS_ERR_CREDENTIAL_INVALID:
  case BB_MLS_ERR_EQUIVOCATION:
  case BB_MLS_ERR_SELF_CLONE_DETECTED:
  case BB_MLS_ERR_BAD_CONFIRMATION:
    return {ErrorCode::invalid_identity, detail};
  case BB_MLS_ERR_DUPLICATE_MSG:
    return {ErrorCode::conflict, detail};
  case BB_MLS_ERR_BUCKET_OVERFLOW:
    return {ErrorCode::capacity, detail};
  case BB_MLS_ERR_STORAGE:
    return {ErrorCode::io, detail};
  case BB_MLS_ERR_NOT_FOUND:
    return {ErrorCode::stale_handle, detail};
  case BB_MLS_ERR_UNSUPPORTED:
    return {ErrorCode::unsupported, detail};
  case BB_MLS_ERR_PANIC:
    return {ErrorCode::external_unknown, detail};
  }
  return {ErrorCode::external_unknown, detail};
}

struct MlsBufGuard {
  BbMlsByteBuf buf{nullptr, 0U};

  ~MlsBufGuard() {
    if (buf.ptr != nullptr && buf.len > 0U) {
      bb_mls_free_bytes(buf.ptr, buf.len);
    }
  }

  std::vector<std::uint8_t> take_vec() const {
    if (buf.ptr == nullptr || buf.len == 0U) {
      return {};
    }
    return std::vector<std::uint8_t>(buf.ptr, buf.ptr + buf.len);
  }

  std::string take_string() const {
    if (buf.ptr == nullptr || buf.len == 0U) {
      return {};
    }
    return std::string(reinterpret_cast<const char *>(buf.ptr), buf.len);
  }
};

} // namespace

Result<MlsDeviceBinding> mp_mls_sign_device_binding(
    mp::AccountId account_id, std::uint32_t root_gen, mp::DeviceId device_id,
    std::uint32_t device_gen, std::uint8_t client_class, bool agent_capable,
    std::uint8_t custody_mode, std::uint64_t iat_s, std::uint64_t exp_s,
    const mp::Ed25519Seed &root_seed, const mp::Ed25519Seed &device_seed) {
  MlsDeviceBinding out{};
  const BbMlsStatus st = bb_mls_sign_device_binding(
      account_id.value(), root_gen, device_id.value(), device_gen, client_class,
      agent_capable ? 1U : 0U, custody_mode, iat_s, exp_s, root_seed.data(),
      device_seed.data(), out.data());
  if (st != BB_MLS_OK) {
    return Result<MlsDeviceBinding>::failure(map_mls_status(st));
  }
  return Result<MlsDeviceBinding>::success(out);
}

Result<void> mp_mls_verify_device_binding(std::span<const std::uint8_t> binding_bytes,
                                          std::optional<std::uint64_t> now_s) {
  const BbMlsStatus st =
      bb_mls_verify_device_binding(binding_bytes.data(), binding_bytes.size(),
                                   now_s.value_or(0U), now_s.has_value() ? 1U : 0U);
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

Result<std::vector<std::uint8_t>> mp_mls_sign_device_list(
    mp::AccountId account_id, std::uint32_t root_gen, std::uint64_t list_version,
    std::uint64_t iat_s, std::uint64_t exp_s,
    std::span<const MpMlsActiveDeviceEntry> entries, const mp::Ed25519Seed &root_seed) {
  std::vector<BbMlsActiveDeviceEntry> abi_entries;
  abi_entries.reserve(entries.size());
  for (const auto &e : entries) {
    BbMlsActiveDeviceEntry ae{};
    ae.device_id = e.device_id;
    ae.device_gen = e.device_gen;
    std::memcpy(ae.mls_sig_pubkey, e.mls_sig_pubkey.data(), sizeof(ae.mls_sig_pubkey));
    abi_entries.push_back(ae);
  }
  MlsBufGuard guard{};
  const BbMlsStatus st =
      bb_mls_sign_device_list(account_id.value(), root_gen, list_version, iat_s, exp_s,
                              abi_entries.empty() ? nullptr : abi_entries.data(),
                              abi_entries.size(), root_seed.data(), &guard.buf);
  if (st != BB_MLS_OK) {
    return Result<std::vector<std::uint8_t>>::failure(map_mls_status(st));
  }
  return Result<std::vector<std::uint8_t>>::success(guard.take_vec());
}

Result<void> mp_mls_verify_device_list(std::span<const std::uint8_t> list_bytes,
                                       const mp::Ed25519PubKey &expected_root_pk) {
  const BbMlsStatus st = bb_mls_verify_device_list(list_bytes.data(), list_bytes.size(),
                                                   expected_root_pk.data());
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

Result<MlsRootRotationStmt>
mp_mls_sign_root_rotation(mp::AccountId account_id, std::uint32_t old_root_gen,
                          std::uint32_t new_root_gen, std::uint8_t old_custody_mode,
                          std::uint8_t new_custody_mode, std::uint64_t rotated_at_s,
                          const mp::Ed25519Seed &old_root_seed,
                          const mp::Ed25519Seed &new_root_seed) {
  MlsRootRotationStmt out{};
  const BbMlsStatus st =
      bb_mls_sign_root_rotation(account_id.value(), old_root_gen, new_root_gen,
                                old_custody_mode, new_custody_mode, rotated_at_s,
                                old_root_seed.data(), new_root_seed.data(), out.data());
  if (st != BB_MLS_OK) {
    return Result<MlsRootRotationStmt>::failure(map_mls_status(st));
  }
  return Result<MlsRootRotationStmt>::success(out);
}

Result<void> mp_mls_verify_root_rotation(std::span<const std::uint8_t> stmt_bytes) {
  const BbMlsStatus st =
      bb_mls_verify_root_rotation(stmt_bytes.data(), stmt_bytes.size());
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

Result<std::string>
mp_mls_format_epoch_authenticator(std::span<const std::uint8_t> auth_bytes) {
  char buf[BB_MLS_EPOCH_AUTH_CODE_LEN + 1U]{};
  const BbMlsStatus st =
      bb_mls_format_epoch_authenticator(auth_bytes.data(), auth_bytes.size(), buf);
  if (st != BB_MLS_OK) {
    return Result<std::string>::failure(map_mls_status(st));
  }
  return Result<std::string>::success(std::string{buf});
}

MpMlsEngine::MpMlsEngine(MpMlsEngine &&other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)) {}

MpMlsEngine &MpMlsEngine::operator=(MpMlsEngine &&other) noexcept {
  if (this != &other) {
    close();
    handle_ = std::exchange(other.handle_, nullptr);
  }
  return *this;
}

MpMlsEngine::~MpMlsEngine() { close(); }

void MpMlsEngine::close() noexcept {
  if (handle_ != nullptr) {
    BbMlsEngine *h = std::exchange(handle_, nullptr);
    bb_mls_close(h);
  }
}

Result<MpMlsEngine> MpMlsEngine::open(const MpMlsEngineConfig &config) {
  const std::string dir_str = config.state_dir.string();
  if (dir_str.empty() || config.device_list_bytes.empty()) {
    return Result<MpMlsEngine>::failure(
        {ErrorCode::invalid_range, static_cast<std::int64_t>(MpMlsError::invalid_arg)});
  }

  BbMlsEngineConfig abi_cfg{};
  abi_cfg.abi_version = BB_MLS_ABI_VERSION;
  abi_cfg.state_dir = dir_str.data();
  abi_cfg.state_dir_len = dir_str.size();
  abi_cfg.account_id = config.account_id.value();
  abi_cfg.device_id = config.device_id.value();
  abi_cfg.root_gen = config.root_gen;
  abi_cfg.device_gen = config.device_gen;
  abi_cfg.client_class = config.client_class;
  abi_cfg.agent_capable = config.agent_capable ? 1U : 0U;
  abi_cfg.custody_mode = config.custody_mode;
  abi_cfg.mls_sig_seed = config.mls_sig_seed.data();
  abi_cfg.store_enc_key = config.store_enc_key.data();
  abi_cfg.device_binding_236b = config.device_binding.data();
  abi_cfg.device_list_bytes = config.device_list_bytes.data();
  abi_cfg.device_list_len = config.device_list_bytes.size();

  BbMlsEngine *raw = nullptr;
  const BbMlsStatus st = bb_mls_open(&abi_cfg, &raw);
  if (st != BB_MLS_OK || raw == nullptr) {
    return Result<MpMlsEngine>::failure(map_mls_status(st));
  }
  return Result<MpMlsEngine>::success(MpMlsEngine{raw});
}

Result<MpMlsCreatedGroup> MpMlsEngine::create_group(
    const MpMlsRoomPolicy &policy, const mp::Ed25519PubKey &ds_pubkey,
    std::optional<std::array<std::uint8_t, 8>> incarnation_nonce) {
  if (handle_ == nullptr) {
    return Result<MpMlsCreatedGroup>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  BbMlsRoomPolicyConfig pcfg{};
  pcfg.party_id = policy.party_id.value();
  pcfg.require_self_custody = policy.require_self_custody ? 1U : 0U;
  pcfg.allow_browser_devices = policy.allow_browser_devices ? 1U : 0U;
  pcfg.org_id = policy.org_id;
  pcfg.host_account_ids =
      policy.host_account_ids.empty() ? nullptr : policy.host_account_ids.data();
  pcfg.host_account_count = policy.host_account_ids.size();

  MlsGroupId gid{};
  MlsBufGuard gi_guard{};
  const BbMlsStatus st = bb_mls_create_group(
      handle_, &pcfg, ds_pubkey.data(),
      incarnation_nonce.has_value() ? incarnation_nonce->data() : nullptr, gid.data(),
      &gi_guard.buf);
  if (st != BB_MLS_OK) {
    return Result<MpMlsCreatedGroup>::failure(map_mls_status(st));
  }
  return Result<MpMlsCreatedGroup>::success(
      MpMlsCreatedGroup{gid, gi_guard.take_vec()});
}

Result<MpMlsMintedInvite> MpMlsEngine::mint_invite(const MlsGroupId &group_id,
                                                   std::uint64_t invite_id,
                                                   std::uint32_t max_uses,
                                                   std::uint64_t expires_at_s) {
  if (handle_ == nullptr) {
    return Result<MpMlsMintedInvite>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  BbMlsInviteMintOut raw{};
  const BbMlsStatus st = bb_mls_mint_invite(handle_, group_id.data(), invite_id,
                                            max_uses, expires_at_s, &raw);
  MlsBufGuard frag_guard{raw.fragment_b64url};
  MlsBufGuard rec_guard{raw.invite_record_bytes};
  if (st != BB_MLS_OK) {
    return Result<MpMlsMintedInvite>::failure(map_mls_status(st));
  }
  MpMlsMintedInvite out{};
  out.fragment_b64url = frag_guard.take_string();
  std::memcpy(out.server_invite_token.data(), raw.server_invite_token,
              out.server_invite_token.size());
  std::memcpy(out.server_token_hash.data(), raw.server_token_hash,
              out.server_token_hash.size());
  out.invite_record_bytes = rec_guard.take_vec();
  return Result<MpMlsMintedInvite>::success(std::move(out));
}

Result<void>
MpMlsEngine::register_invite_record(const MlsGroupId &group_id,
                                    std::span<const std::uint8_t> invite_record_bytes) {
  if (handle_ == nullptr) {
    return Result<void>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  const BbMlsStatus st = bb_mls_register_invite_record(
      handle_, group_id.data(), invite_record_bytes.data(), invite_record_bytes.size());
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

Result<MpMlsPreparedJoin> MpMlsEngine::prepare_join(std::string_view fragment_b64url) {
  if (handle_ == nullptr) {
    return Result<MpMlsPreparedJoin>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  BbMlsPrepareJoinOut raw{};
  const BbMlsStatus st = bb_mls_prepare_join(handle_, fragment_b64url.data(),
                                             fragment_b64url.size(), &raw);
  MlsBufGuard kp_guard{raw.kp_bytes};
  if (st != BB_MLS_OK) {
    return Result<MpMlsPreparedJoin>::failure(map_mls_status(st));
  }
  MpMlsPreparedJoin out{};
  std::memcpy(out.group_id.data(), raw.group_id, out.group_id.size());
  out.invite_id = raw.invite_id;
  out.invite_epoch = raw.invite_epoch;
  out.expires_at_s = raw.expires_at_s;
  out.policy_bits = raw.policy_bits;
  std::memcpy(out.inviter_root_pk.data(), raw.inviter_root_pk,
              out.inviter_root_pk.size());
  std::memcpy(out.server_invite_token.data(), raw.server_invite_token,
              out.server_invite_token.size());
  std::memcpy(out.kp_ref.data(), raw.kp_ref, out.kp_ref.size());
  std::memcpy(out.join_proof.data(), raw.join_proof, out.join_proof.size());
  out.kp_bytes = kp_guard.take_vec();
  return Result<MpMlsPreparedJoin>::success(std::move(out));
}

Result<MlsGroupId>
MpMlsEngine::process_welcome(mp::PartyId expected_party_id,
                             const mp::Ed25519PubKey &expected_ds_pubkey,
                             std::span<const std::uint8_t> welcome_bytes,
                             std::span<const std::uint8_t> welcome_auth_bytes) {
  if (handle_ == nullptr) {
    return Result<MlsGroupId>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  MlsGroupId gid{};
  const BbMlsStatus st = bb_mls_process_welcome(
      handle_, expected_party_id.value(), expected_ds_pubkey.data(),
      welcome_bytes.data(), welcome_bytes.size(), welcome_auth_bytes.data(),
      welcome_auth_bytes.size(), gid.data());
  if (st != BB_MLS_OK) {
    return Result<MlsGroupId>::failure(map_mls_status(st));
  }
  return Result<MlsGroupId>::success(gid);
}

Result<MpMlsAddCommit>
MpMlsEngine::commit_add_invitee(const MlsGroupId &group_id, std::uint64_t invite_id,
                                std::span<const std::uint8_t> kp_bytes,
                                const MlsHash32 &join_proof, std::uint64_t now_s,
                                bool allow_delegated) {
  if (handle_ == nullptr) {
    return Result<MpMlsAddCommit>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  BbMlsAddCommitOut raw{};
  const BbMlsStatus st = bb_mls_commit_add_invitee(
      handle_, group_id.data(), invite_id, kp_bytes.data(), kp_bytes.size(),
      join_proof.data(), now_s, allow_delegated ? 1U : 0U, &raw);
  MlsBufGuard c_guard{raw.commit_bytes};
  MlsBufGuard w_guard{raw.welcome_bytes};
  MlsBufGuard wa_guard{raw.welcome_auth_bytes};
  if (st != BB_MLS_OK) {
    return Result<MpMlsAddCommit>::failure(map_mls_status(st));
  }
  return Result<MpMlsAddCommit>::success(
      MpMlsAddCommit{c_guard.take_vec(), w_guard.take_vec(), wa_guard.take_vec()});
}

Result<void> MpMlsEngine::apply_proposal(const MlsGroupId &group_id,
                                         std::span<const std::uint8_t> proposal_bytes) {
  if (handle_ == nullptr) {
    return Result<void>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  const BbMlsStatus st = bb_mls_apply_proposal(
      handle_, group_id.data(), proposal_bytes.data(), proposal_bytes.size());
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

Result<std::vector<std::uint8_t>>
MpMlsEngine::commit_pending_or_self_update(const MlsGroupId &group_id,
                                           bool has_pending_proposals) {
  if (handle_ == nullptr) {
    return Result<std::vector<std::uint8_t>>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  MlsBufGuard c_guard{};
  const BbMlsStatus st = bb_mls_commit_pending_or_self_update(
      handle_, group_id.data(), has_pending_proposals ? 1U : 0U, &c_guard.buf);
  if (st != BB_MLS_OK) {
    return Result<std::vector<std::uint8_t>>::failure(map_mls_status(st));
  }
  return Result<std::vector<std::uint8_t>>::success(c_guard.take_vec());
}

Result<MpMlsTentativeAck>
MpMlsEngine::stage_tentative_commit(const MlsGroupId &group_id,
                                    std::span<const std::uint8_t> commit_bytes) {
  if (handle_ == nullptr) {
    return Result<MpMlsTentativeAck>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  std::uint8_t ack_status = 0U;
  MlsBufGuard ack_guard{};
  const BbMlsStatus st =
      bb_mls_stage_tentative_commit(handle_, group_id.data(), commit_bytes.data(),
                                    commit_bytes.size(), &ack_status, &ack_guard.buf);
  if (st != BB_MLS_OK) {
    return Result<MpMlsTentativeAck>::failure(map_mls_status(st));
  }
  return Result<MpMlsTentativeAck>::success(
      MpMlsTentativeAck{ack_status, ack_guard.take_vec()});
}

Result<void> MpMlsEngine::finalize_commit(const MlsGroupId &group_id,
                                          std::span<const std::uint8_t> commit_bytes,
                                          std::uint64_t now_s) {
  if (handle_ == nullptr) {
    return Result<void>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  const BbMlsStatus st = bb_mls_finalize_commit(
      handle_, group_id.data(), commit_bytes.data(), commit_bytes.size(), now_s);
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

Result<void> MpMlsEngine::discard_tentative(const MlsGroupId &group_id) {
  if (handle_ == nullptr) {
    return Result<void>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  const BbMlsStatus st = bb_mls_discard_tentative(handle_, group_id.data());
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

Result<MpMlsEncryptedApp>
MpMlsEngine::encrypt_app(const MlsGroupId &group_id, const MlsInnerMsgId &inner_msg_id,
                         MpMlsMsgClass msg_class,
                         std::span<const std::uint8_t> plaintext, std::uint64_t now_s) {
  if (handle_ == nullptr) {
    return Result<MpMlsEncryptedApp>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  BbMlsEncryptOut raw{};
  const BbMlsStatus st = bb_mls_encrypt_app(
      handle_, group_id.data(), inner_msg_id.data(),
      static_cast<std::uint32_t>(msg_class),
      plaintext.empty() ? nullptr : plaintext.data(), plaintext.size(), now_s, &raw);
  MlsBufGuard w_guard{raw.wire_bytes};
  if (st != BB_MLS_OK) {
    return Result<MpMlsEncryptedApp>::failure(map_mls_status(st));
  }
  MpMlsEncryptedApp out{};
  out.mls_epoch = raw.mls_epoch;
  out.device_epoch_seq = raw.device_epoch_seq;
  out.total_sent_in_epoch = raw.total_sent_in_epoch;
  out.needs_pcs_self_update = raw.needs_pcs_self_update != 0U;
  out.wire_bytes = w_guard.take_vec();
  return Result<MpMlsEncryptedApp>::success(std::move(out));
}

Result<MpMlsDecryptedApp>
MpMlsEngine::decrypt_app(const MlsGroupId &group_id,
                         std::span<const std::uint8_t> wire_bytes,
                         bool is_catchup_hint) {
  if (handle_ == nullptr) {
    return Result<MpMlsDecryptedApp>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  BbMlsDecryptedApp raw{};
  const BbMlsStatus st =
      bb_mls_decrypt_app(handle_, group_id.data(), wire_bytes.data(), wire_bytes.size(),
                         is_catchup_hint ? 1U : 0U, &raw);
  struct DecGuard {
    BbMlsDecryptedApp *ptr = nullptr;
    ~DecGuard() {
      if (ptr != nullptr) {
        bb_mls_free_decrypted_app(ptr);
      }
    }
  } dec_guard{&raw};
  if (st != BB_MLS_OK) {
    return Result<MpMlsDecryptedApp>::failure(map_mls_status(st));
  }
  MpMlsDecryptedApp out{};
  out.mls_epoch = raw.mls_epoch;
  out.auth_account_id = raw.auth_account_id;
  out.auth_device_id = raw.auth_device_id;
  out.device_epoch_seq = raw.device_epoch_seq;
  out.msg_class = static_cast<MpMlsMsgClass>(raw.msg_class);
  std::memcpy(out.inner_msg_id.data(), raw.inner_msg_id, out.inner_msg_id.size());
  out.sender_client_class = raw.sender_client_class;
  out.sender_custody_mode = raw.sender_custody_mode;
  out.sender_agent_capable = raw.sender_agent_capable != 0U;
  out.is_historical_catchup = raw.is_historical_catchup != 0U;
  if (raw.plaintext.ptr != nullptr && raw.plaintext.len > 0U) {
    out.plaintext.assign(raw.plaintext.ptr, raw.plaintext.ptr + raw.plaintext.len);
  }
  return Result<MpMlsDecryptedApp>::success(std::move(out));
}

Result<void> MpMlsEngine::observe_device_list(const MlsGroupId &group_id,
                                              std::span<const std::uint8_t> list_bytes,
                                              std::uint64_t now_s) {
  if (handle_ == nullptr) {
    return Result<void>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  const BbMlsStatus st = bb_mls_observe_device_list(
      handle_, group_id.data(), list_bytes.data(), list_bytes.size(), now_s);
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

Result<void>
MpMlsEngine::apply_root_rotation(const MlsGroupId &group_id,
                                 std::span<const std::uint8_t> stmt_bytes) {
  if (handle_ == nullptr) {
    return Result<void>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  const BbMlsStatus st = bb_mls_apply_root_rotation(
      handle_, group_id.data(), stmt_bytes.data(), stmt_bytes.size());
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

Result<std::uint32_t> MpMlsEngine::prune_past_epochs(const MlsGroupId &group_id,
                                                     std::uint64_t now_s) {
  if (handle_ == nullptr) {
    return Result<std::uint32_t>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  std::uint32_t pruned = 0U;
  const BbMlsStatus st =
      bb_mls_prune_past_epochs(handle_, group_id.data(), now_s, &pruned);
  if (st != BB_MLS_OK) {
    return Result<std::uint32_t>::failure(map_mls_status(st));
  }
  return Result<std::uint32_t>::success(pruned);
}

Result<MpMlsRoomStatus> MpMlsEngine::room_status(const MlsGroupId &group_id,
                                                 std::uint64_t now_s) const {
  if (handle_ == nullptr) {
    return Result<MpMlsRoomStatus>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  BbMlsRoomStatus raw{};
  const BbMlsStatus st = bb_mls_room_status(handle_, group_id.data(), now_s, &raw);
  if (st != BB_MLS_OK) {
    return Result<MpMlsRoomStatus>::failure(map_mls_status(st));
  }
  MpMlsRoomStatus out{};
  std::memcpy(out.group_id.data(), raw.group_id, out.group_id.size());
  out.mls_epoch = raw.mls_epoch;
  std::memcpy(out.epoch_authenticator.data(), raw.epoch_authenticator,
              out.epoch_authenticator.size());
  out.epoch_authenticator_code = std::string{raw.epoch_authenticator_code};
  out.trust_tier = static_cast<MpMlsTrustTier>(raw.trust_tier);
  out.has_declared_agent = raw.has_declared_agent != 0U;
  out.has_pending_removals = raw.has_pending_removals != 0U;
  out.clone_detected = raw.clone_detected != 0U;
  out.needs_pcs_self_update = raw.needs_pcs_self_update != 0U;
  out.inviter_unconfirmed = raw.inviter_unconfirmed != 0U;
  out.occupied_leaf_count = raw.occupied_leaf_count;
  return Result<MpMlsRoomStatus>::success(std::move(out));
}

Result<void> MpMlsEngine::mark_peer_verified_oob(const MlsGroupId &group_id,
                                                 mp::AccountId peer_account_id) {
  if (handle_ == nullptr) {
    return Result<void>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  const BbMlsStatus st =
      bb_mls_mark_peer_verified_oob(handle_, group_id.data(), peer_account_id.value());
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

Result<void> MpMlsEngine::mark_clone_detected(const MlsGroupId &group_id) {
  if (handle_ == nullptr) {
    return Result<void>::failure(
        {ErrorCode::stale_handle, static_cast<std::int64_t>(MpMlsError::null_pointer)});
  }
  const BbMlsStatus st = bb_mls_mark_clone_detected(handle_, group_id.data());
  if (st != BB_MLS_OK) {
    return Result<void>::failure(map_mls_status(st));
  }
  return Result<void>::success();
}

#else // !(BLACKBIRD_HAS_MLS)

namespace {
template <typename T> Result<T> mls_unsupported() {
  return Result<T>::failure(
      {ErrorCode::unsupported, static_cast<std::int64_t>(MpMlsError::unsupported)});
}
} // namespace

Result<MlsDeviceBinding> mp_mls_sign_device_binding(mp::AccountId, std::uint32_t,
                                                    mp::DeviceId, std::uint32_t,
                                                    std::uint8_t, bool, std::uint8_t,
                                                    std::uint64_t, std::uint64_t,
                                                    const mp::Ed25519Seed &,
                                                    const mp::Ed25519Seed &) {
  return mls_unsupported<MlsDeviceBinding>();
}
Result<void> mp_mls_verify_device_binding(std::span<const std::uint8_t>,
                                          std::optional<std::uint64_t>) {
  return mls_unsupported<void>();
}
Result<std::vector<std::uint8_t>>
mp_mls_sign_device_list(mp::AccountId, std::uint32_t, std::uint64_t, std::uint64_t,
                        std::uint64_t, std::span<const MpMlsActiveDeviceEntry>,
                        const mp::Ed25519Seed &) {
  return mls_unsupported<std::vector<std::uint8_t>>();
}
Result<void> mp_mls_verify_device_list(std::span<const std::uint8_t>,
                                       const mp::Ed25519PubKey &) {
  return mls_unsupported<void>();
}
Result<MlsRootRotationStmt> mp_mls_sign_root_rotation(mp::AccountId, std::uint32_t,
                                                      std::uint32_t, std::uint8_t,
                                                      std::uint8_t, std::uint64_t,
                                                      const mp::Ed25519Seed &,
                                                      const mp::Ed25519Seed &) {
  return mls_unsupported<MlsRootRotationStmt>();
}
Result<void> mp_mls_verify_root_rotation(std::span<const std::uint8_t>) {
  return mls_unsupported<void>();
}
Result<std::string> mp_mls_format_epoch_authenticator(std::span<const std::uint8_t>) {
  return mls_unsupported<std::string>();
}

MpMlsEngine::MpMlsEngine(MpMlsEngine &&) noexcept = default;
MpMlsEngine &MpMlsEngine::operator=(MpMlsEngine &&) noexcept = default;
MpMlsEngine::~MpMlsEngine() = default;
void MpMlsEngine::close() noexcept { handle_ = nullptr; }

Result<MpMlsEngine> MpMlsEngine::open(const MpMlsEngineConfig &) {
  return mls_unsupported<MpMlsEngine>();
}
Result<MpMlsCreatedGroup>
MpMlsEngine::create_group(const MpMlsRoomPolicy &, const mp::Ed25519PubKey &,
                          std::optional<std::array<std::uint8_t, 8>>) {
  return mls_unsupported<MpMlsCreatedGroup>();
}
Result<MpMlsMintedInvite> MpMlsEngine::mint_invite(const MlsGroupId &, std::uint64_t,
                                                   std::uint32_t, std::uint64_t) {
  return mls_unsupported<MpMlsMintedInvite>();
}
Result<void> MpMlsEngine::register_invite_record(const MlsGroupId &,
                                                 std::span<const std::uint8_t>) {
  return mls_unsupported<void>();
}
Result<MpMlsPreparedJoin> MpMlsEngine::prepare_join(std::string_view) {
  return mls_unsupported<MpMlsPreparedJoin>();
}
Result<MlsGroupId> MpMlsEngine::process_welcome(mp::PartyId, const mp::Ed25519PubKey &,
                                                std::span<const std::uint8_t>,
                                                std::span<const std::uint8_t>) {
  return mls_unsupported<MlsGroupId>();
}
Result<MpMlsAddCommit> MpMlsEngine::commit_add_invitee(const MlsGroupId &,
                                                       std::uint64_t,
                                                       std::span<const std::uint8_t>,
                                                       const MlsHash32 &, std::uint64_t,
                                                       bool) {
  return mls_unsupported<MpMlsAddCommit>();
}
Result<void> MpMlsEngine::apply_proposal(const MlsGroupId &,
                                         std::span<const std::uint8_t>) {
  return mls_unsupported<void>();
}
Result<std::vector<std::uint8_t>>
MpMlsEngine::commit_pending_or_self_update(const MlsGroupId &, bool) {
  return mls_unsupported<std::vector<std::uint8_t>>();
}
Result<MpMlsTentativeAck>
MpMlsEngine::stage_tentative_commit(const MlsGroupId &, std::span<const std::uint8_t>) {
  return mls_unsupported<MpMlsTentativeAck>();
}
Result<void> MpMlsEngine::finalize_commit(const MlsGroupId &,
                                          std::span<const std::uint8_t>,
                                          std::uint64_t) {
  return mls_unsupported<void>();
}
Result<void> MpMlsEngine::discard_tentative(const MlsGroupId &) {
  return mls_unsupported<void>();
}
Result<MpMlsEncryptedApp> MpMlsEngine::encrypt_app(const MlsGroupId &,
                                                   const MlsInnerMsgId &, MpMlsMsgClass,
                                                   std::span<const std::uint8_t>,
                                                   std::uint64_t) {
  return mls_unsupported<MpMlsEncryptedApp>();
}
Result<MpMlsDecryptedApp>
MpMlsEngine::decrypt_app(const MlsGroupId &, std::span<const std::uint8_t>, bool) {
  return mls_unsupported<MpMlsDecryptedApp>();
}
Result<void> MpMlsEngine::observe_device_list(const MlsGroupId &,
                                              std::span<const std::uint8_t>,
                                              std::uint64_t) {
  return mls_unsupported<void>();
}
Result<void> MpMlsEngine::apply_root_rotation(const MlsGroupId &,
                                              std::span<const std::uint8_t>) {
  return mls_unsupported<void>();
}
Result<std::uint32_t> MpMlsEngine::prune_past_epochs(const MlsGroupId &,
                                                     std::uint64_t) {
  return mls_unsupported<std::uint32_t>();
}
Result<MpMlsRoomStatus> MpMlsEngine::room_status(const MlsGroupId &,
                                                 std::uint64_t) const {
  return mls_unsupported<MpMlsRoomStatus>();
}
Result<void> MpMlsEngine::mark_peer_verified_oob(const MlsGroupId &, mp::AccountId) {
  return mls_unsupported<void>();
}
Result<void> MpMlsEngine::mark_clone_detected(const MlsGroupId &) {
  return mls_unsupported<void>();
}

#endif // BLACKBIRD_HAS_MLS

} // namespace blackbird
