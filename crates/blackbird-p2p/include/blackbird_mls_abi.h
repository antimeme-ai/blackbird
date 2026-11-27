#ifndef BLACKBIRD_MLS_ABI_H
#define BLACKBIRD_MLS_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BB_MLS_ABI_VERSION 1U
#define BB_MLS_PUBKEY_LEN 32U
#define BB_MLS_SEED_LEN 32U
#define BB_MLS_GROUP_ID_LEN 24U
#define BB_MLS_HASH_LEN 32U
#define BB_MLS_MSG_ID_LEN 16U
#define BB_MLS_DEVICE_BINDING_LEN 236U
#define BB_MLS_LEAF_CRED_LEN 276U
#define BB_MLS_ROOT_ROTATION_LEN 219U
#define BB_MLS_INVITE_FRAGMENT_LEN 114U
#define BB_MLS_INVITE_RECORD_LEN 93U
#define BB_MLS_WELCOME_AUTH_LEN 177U
#define BB_MLS_SAFETY_NUMBER_V2_LEN 39U
#define BB_MLS_EPOCH_AUTH_CODE_LEN 29U
#define BB_MLS_MAX_APP_WIRE_BYTES 24000U
#define BB_MLS_MAX_CTRL_BLOB_BYTES (256U * 1024U)
#define BB_MLS_MAX_FRAMES_PER_EPOCH 900U

typedef struct BbMlsEngine BbMlsEngine;

typedef enum BbMlsStatus {
  BB_MLS_OK = 0,
  BB_MLS_ERR_NULL_POINTER = 1,
  BB_MLS_ERR_INVALID_ARG = 2,
  BB_MLS_ERR_POLICY_VIOLATION = 3,
  BB_MLS_ERR_CREDENTIAL_INVALID = 4,
  BB_MLS_ERR_EQUIVOCATION = 5,
  BB_MLS_ERR_PENDING_REMOVAL = 6,
  BB_MLS_ERR_EPOCH_STALE = 7,
  BB_MLS_ERR_DUPLICATE_MSG = 8,
  BB_MLS_ERR_SELF_CLONE_DETECTED = 9,
  BB_MLS_ERR_BUCKET_OVERFLOW = 10,
  BB_MLS_ERR_STORAGE = 11,
  BB_MLS_ERR_PANIC = 12,
  BB_MLS_ERR_BAD_CONFIRMATION = 13,
  BB_MLS_ERR_FRAME_CAP = 14,
  BB_MLS_ERR_NOT_FOUND = 15,
  BB_MLS_ERR_UNSUPPORTED = 16
} BbMlsStatus;

typedef enum BbMlsMsgClass {
  BB_MLS_CLASS_CHAT = 1,
  BB_MLS_CLASS_AGENT_CARD = 2,
  BB_MLS_CLASS_EPHEMERAL_STATUS = 3,
  BB_MLS_CLASS_INVITE_CONTROL = 4
} BbMlsMsgClass;

typedef enum BbMlsTrustTier {
  BB_MLS_TIER_0_UNVERIFIED = 0,
  BB_MLS_TIER_1_CLOUD_OR_BROWSER = 1,
  BB_MLS_TIER_2_SELF_CUSTODY_TOFU = 2,
  BB_MLS_TIER_3_SELF_CUSTODY_VERIFIED = 3
} BbMlsTrustTier;

typedef struct BbMlsByteBuf {
  uint8_t *ptr;
  size_t len;
} BbMlsByteBuf;

typedef struct BbMlsActiveDeviceEntry {
  uint64_t device_id;
  uint32_t device_gen;
  uint8_t mls_sig_pubkey[BB_MLS_PUBKEY_LEN];
} BbMlsActiveDeviceEntry;

typedef struct BbMlsEngineConfig {
  uint32_t abi_version;  /* MUST equal BB_MLS_ABI_VERSION */
  const char *state_dir; /* UTF-8 base state dir (store lives in state_dir/mls/) */
  size_t state_dir_len;
  uint64_t account_id;         /* 1..=MAX_SAFE_ID */
  uint64_t device_id;          /* 1..=MAX_SAFE_ID (0 rejected!) */
  uint32_t root_gen;           /* >= 1 */
  uint32_t device_gen;         /* >= 1 */
  uint8_t client_class;        /* 1=blackbird, 2=outpost, 3=browser */
  uint8_t agent_capable;       /* 0=no, 1=yes */
  uint8_t custody_mode;        /* 0=cloud-managed, 1=self-custody */
  const uint8_t *mls_sig_seed; /* 32B Ed25519 device signing seed */
  const uint8_t
      *store_enc_key; /* 32B AES-256-GCM key for encrypted atomic state files */
  const uint8_t *device_binding_236b; /* 236B canonical MpMlsDeviceBindingV1 */
  const uint8_t *device_list_bytes;   /* canonical AccountDeviceListV1 */
  size_t device_list_len;
} BbMlsEngineConfig;

typedef struct BbMlsRoomPolicyConfig {
  uint64_t party_id;
  uint8_t require_self_custody;  /* 0 | 1 */
  uint8_t allow_browser_devices; /* 0 | 1 */
  uint64_t org_id;               /* 0 if personal */
  const uint64_t *host_account_ids;
  size_t host_account_count; /* 1..=12 */
} BbMlsRoomPolicyConfig;

typedef struct BbMlsInviteMintOut {
  BbMlsByteBuf fragment_b64url;     /* URL-safe no-pad InviteFragmentV2 UTF-8 bytes */
  uint8_t server_invite_token[32];  /* sent to PartyDO (never raw invite_seed) */
  uint8_t server_token_hash[32];    /* SHA-256(server_invite_token) */
  BbMlsByteBuf invite_record_bytes; /* 93B InviteRecordV1 for in-group sync */
} BbMlsInviteMintOut;

typedef struct BbMlsPrepareJoinOut {
  uint8_t group_id[BB_MLS_GROUP_ID_LEN];
  uint64_t invite_id;
  uint64_t invite_epoch;
  uint64_t expires_at_s;
  uint8_t policy_bits;
  uint8_t inviter_root_pk[BB_MLS_PUBKEY_LEN];
  uint8_t server_invite_token[32];
  uint8_t kp_ref[BB_MLS_HASH_LEN];
  uint8_t join_proof[BB_MLS_HASH_LEN];
  BbMlsByteBuf kp_bytes;
} BbMlsPrepareJoinOut;

typedef struct BbMlsAddCommitOut {
  BbMlsByteBuf commit_bytes;
  BbMlsByteBuf welcome_bytes;
  BbMlsByteBuf welcome_auth_bytes;
} BbMlsAddCommitOut;

typedef struct BbMlsEncryptOut {
  uint64_t mls_epoch;
  uint64_t device_epoch_seq;
  uint64_t total_sent_in_epoch;
  uint8_t needs_pcs_self_update;
  BbMlsByteBuf wire_bytes; /* exact 512 | 2048 | 8192 | 24000 bytes */
} BbMlsEncryptOut;

typedef struct BbMlsDecryptedApp {
  uint64_t mls_epoch;
  uint64_t auth_account_id;
  uint64_t auth_device_id;
  uint64_t device_epoch_seq;
  uint32_t msg_class;
  uint8_t inner_msg_id[BB_MLS_MSG_ID_LEN];
  uint8_t sender_client_class;   /* 1=blackbird, 2=outpost, 3=browser */
  uint8_t sender_custody_mode;   /* 0=cloud, 1=self-custody */
  uint8_t sender_agent_capable;  /* 0=no, 1=yes */
  uint8_t is_historical_catchup; /* 1 if decrypted from past epoch or catch-up mode */
  BbMlsByteBuf plaintext;
} BbMlsDecryptedApp;

typedef struct BbMlsRoomStatus {
  uint8_t group_id[BB_MLS_GROUP_ID_LEN];
  uint64_t mls_epoch;
  uint8_t epoch_authenticator[BB_MLS_HASH_LEN];
  char epoch_authenticator_code[BB_MLS_EPOCH_AUTH_CODE_LEN + 1U];
  uint32_t trust_tier; /* BbMlsTrustTier */
  uint8_t has_declared_agent;
  uint8_t has_pending_removals;
  uint8_t clone_detected;
  uint8_t needs_pcs_self_update;
  uint8_t inviter_unconfirmed;
  uint32_t occupied_leaf_count;
} BbMlsRoomStatus;

/* Memory management */
void bb_mls_free_bytes(uint8_t *ptr, size_t len);
void bb_mls_free_decrypted_app(BbMlsDecryptedApp *app);

/* Engine lifecycle (encrypted atomic store under <state_dir>/mls/) */
BbMlsStatus bb_mls_open(const BbMlsEngineConfig *config, BbMlsEngine **out_engine);
void bb_mls_close(BbMlsEngine *engine);

/* Identity / AS canonical binary codecs & Safety Number v2 */
BbMlsStatus bb_mls_sign_device_binding(uint64_t account_id, uint32_t root_gen,
                                       uint64_t device_id, uint32_t device_gen,
                                       uint8_t client_class, uint8_t agent_capable,
                                       uint8_t custody_mode, uint64_t iat_s,
                                       uint64_t exp_s,
                                       const uint8_t root_seed[BB_MLS_SEED_LEN],
                                       const uint8_t device_seed[BB_MLS_SEED_LEN],
                                       uint8_t out_binding[BB_MLS_DEVICE_BINDING_LEN]);

BbMlsStatus bb_mls_verify_device_binding(const uint8_t *binding_bytes,
                                         size_t binding_len, uint64_t now_s,
                                         uint8_t check_wall_clock);

BbMlsStatus bb_mls_sign_device_list(
    uint64_t account_id, uint32_t root_gen, uint64_t list_version, uint64_t iat_s,
    uint64_t exp_s, const BbMlsActiveDeviceEntry *entries, size_t entry_count,
    const uint8_t root_seed[BB_MLS_SEED_LEN], BbMlsByteBuf *out_list_bytes);

BbMlsStatus
bb_mls_verify_device_list(const uint8_t *list_bytes, size_t list_len,
                          const uint8_t expected_root_pk[BB_MLS_PUBKEY_LEN]);

BbMlsStatus bb_mls_observe_device_list(BbMlsEngine *engine,
                                       const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                                       const uint8_t *list_bytes, size_t list_len,
                                       uint64_t now_s);

BbMlsStatus bb_mls_sign_root_rotation(uint64_t account_id, uint32_t old_root_gen,
                                      uint32_t new_root_gen, uint8_t old_custody_mode,
                                      uint8_t new_custody_mode, uint64_t rotated_at_s,
                                      const uint8_t old_root_seed[BB_MLS_SEED_LEN],
                                      const uint8_t new_root_seed[BB_MLS_SEED_LEN],
                                      uint8_t out_stmt[BB_MLS_ROOT_ROTATION_LEN]);

BbMlsStatus bb_mls_verify_root_rotation(const uint8_t *stmt_bytes, size_t stmt_len);

BbMlsStatus bb_mls_apply_root_rotation(BbMlsEngine *engine,
                                       const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                                       const uint8_t *stmt_bytes, size_t stmt_len);

BbMlsStatus bb_mls_safety_number_v2(uint64_t account_id,
                                    const uint8_t root_pubkey[BB_MLS_PUBKEY_LEN],
                                    uint8_t custody_mode,
                                    char out_code[BB_MLS_SAFETY_NUMBER_V2_LEN + 1U]);

BbMlsStatus
bb_mls_format_epoch_authenticator(const uint8_t *auth_bytes, size_t auth_len,
                                  char out_code[BB_MLS_EPOCH_AUTH_CODE_LEN + 1U]);

/* Group lifecycle, invites & Welcome */
BbMlsStatus bb_mls_create_group(
    BbMlsEngine *engine, const BbMlsRoomPolicyConfig *policy,
    const uint8_t ds_pubkey[BB_MLS_PUBKEY_LEN],
    const uint8_t *incarnation_nonce_8b, /* optional 8B nonce; NULL = CSPRNG */
    uint8_t out_group_id[BB_MLS_GROUP_ID_LEN], BbMlsByteBuf *out_group_info);

BbMlsStatus bb_mls_mint_invite(BbMlsEngine *engine,
                               const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                               uint64_t invite_id, uint32_t max_uses,
                               uint64_t expires_at_s, BbMlsInviteMintOut *out_invite);

BbMlsStatus bb_mls_register_invite_record(BbMlsEngine *engine,
                                          const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                                          const uint8_t *invite_record_bytes,
                                          size_t invite_record_len);

BbMlsStatus bb_mls_prepare_join(BbMlsEngine *engine, const char *fragment_b64url,
                                size_t fragment_b64url_len,
                                BbMlsPrepareJoinOut *out_join);

BbMlsStatus bb_mls_process_welcome(BbMlsEngine *engine, uint64_t expected_party_id,
                                   const uint8_t expected_ds_pubkey[BB_MLS_PUBKEY_LEN],
                                   const uint8_t *welcome_bytes, size_t welcome_len,
                                   const uint8_t *welcome_auth_bytes,
                                   size_t welcome_auth_len,
                                   uint8_t out_group_id[BB_MLS_GROUP_ID_LEN]);

/* Commits, proposals & tentative staging */
BbMlsStatus bb_mls_commit_add_invitee(BbMlsEngine *engine,
                                      const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                                      uint64_t invite_id, const uint8_t *kp_bytes,
                                      size_t kp_len,
                                      const uint8_t join_proof[BB_MLS_HASH_LEN],
                                      uint64_t now_s, uint8_t allow_delegated,
                                      BbMlsAddCommitOut *out_commit);

BbMlsStatus bb_mls_apply_proposal(BbMlsEngine *engine,
                                  const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                                  const uint8_t *proposal_bytes, size_t proposal_len);

BbMlsStatus bb_mls_commit_pending_or_self_update(
    BbMlsEngine *engine, const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
    uint8_t has_pending_proposals, BbMlsByteBuf *out_commit_bytes);

BbMlsStatus bb_mls_stage_tentative_commit(BbMlsEngine *engine,
                                          const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                                          const uint8_t *commit_bytes,
                                          size_t commit_len,
                                          uint8_t *out_ack_status, /* 1=OK, 2=REJECT */
                                          BbMlsByteBuf *out_ack_bytes);

BbMlsStatus bb_mls_finalize_commit(BbMlsEngine *engine,
                                   const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                                   const uint8_t *commit_bytes, size_t commit_len,
                                   uint64_t now_s);

BbMlsStatus bb_mls_discard_tentative(BbMlsEngine *engine,
                                     const uint8_t group_id[BB_MLS_GROUP_ID_LEN]);

/* Application encryption / decryption */
BbMlsStatus bb_mls_encrypt_app(BbMlsEngine *engine,
                               const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                               const uint8_t inner_msg_id[BB_MLS_MSG_ID_LEN],
                               uint32_t msg_class, const uint8_t *plaintext,
                               size_t plaintext_len, uint64_t now_s,
                               BbMlsEncryptOut *out_encrypted);

BbMlsStatus bb_mls_decrypt_app(BbMlsEngine *engine,
                               const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                               const uint8_t *wire_bytes, size_t wire_len,
                               uint8_t is_catchup_hint,
                               BbMlsDecryptedApp *out_decrypted);

/* Status, pruning, trust verification & clone freeze */
BbMlsStatus bb_mls_prune_past_epochs(BbMlsEngine *engine,
                                     const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                                     uint64_t now_s, uint32_t *out_pruned_count);
BbMlsStatus bb_mls_room_status(const BbMlsEngine *engine,
                               const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                               uint64_t now_s, BbMlsRoomStatus *out_status);

BbMlsStatus bb_mls_mark_peer_verified_oob(BbMlsEngine *engine,
                                          const uint8_t group_id[BB_MLS_GROUP_ID_LEN],
                                          uint64_t peer_account_id);

BbMlsStatus bb_mls_mark_clone_detected(BbMlsEngine *engine,
                                       const uint8_t group_id[BB_MLS_GROUP_ID_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* BLACKBIRD_MLS_ABI_H */
