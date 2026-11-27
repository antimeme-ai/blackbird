//! Panic-safe C-ABI MLS FFI (`bb_mls_*`) exported from the unified `blackbird-p2p`
//! Rust staticlib (`libblackbird_p2p.a`) so Rust `std` is linked exactly once into
//! `blackbird` (Spec v3, Fable R9).
//!
//! Security & storage invariants:
//! - `#![deny(unsafe_op_in_unsafe_fn)]` enforced at crate root.
//! - Every `extern "C"` entrypoint is wrapped in `catch_unwind(AssertUnwindSafe(...))`
//!   returning `BB_MLS_ERR_PANIC` on any panic.
//! - Encrypted atomic binary state store under `<state_dir>/mls/state.enc` using
//!   AES-256-GCM (`openmls_traits::types::AeadType::Aes256Gcm`) with 12-byte CSPRNG
//!   nonce, AAD `"bb-mls-store-v1"`, `0700` dir, `0600` temp-fsync-rename, and OS
//!   backup exclusion (macOS `com.apple.metadata:com_apple_backup_excludeItem`,
//!   Linux `0600` `.nobackup` + `CACHEDIR.TAG`).
//! - Zero JSON in internals.

use std::collections::HashMap;
use std::ffi::c_char;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use mp_mls::{
    compute_join_proof, compute_safety_number_v2, derive_sibling_welcome_mac_key,
    format_epoch_authenticator, generate_single_use_key_package, AccountDeviceListV1, AckStatus,
    ActiveDeviceEntryV1, ClientClass, CommitAckV1, CustodyMode, DeviceIdentity, InviteFragmentV2,
    InviteRecordV1, InviteSecrets, MpCryptoProvider, MpMlsClient, MpMlsDeviceBindingBodyV1,
    MpMlsDeviceBindingV1, MpMlsError, MpMlsLeafCredV1, MpRoomPolicyExtV1, MpStrictCrypto, MsgClass,
    RoomTrustTier, RootRotationStmtV1, WelcomeAuthV1, DEVICE_BINDING_LEN, INVITE_RECORD_V1_LEN,
    MAX_DEVICES_PER_ACCOUNT, MP_GROUP_ID_LEN, ROOT_ROTATION_LEN, WELCOME_AUTH_V1_LEN,
};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::AeadType;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const BB_MLS_ABI_VERSION: u32 = 1;
pub const BB_MLS_PUBKEY_LEN: usize = 32;
pub const BB_MLS_SEED_LEN: usize = 32;
pub const BB_MLS_GROUP_ID_LEN: usize = MP_GROUP_ID_LEN;
pub const BB_MLS_HASH_LEN: usize = 32;
pub const BB_MLS_MSG_ID_LEN: usize = 16;
pub const BB_MLS_DEVICE_BINDING_LEN: usize = DEVICE_BINDING_LEN;
pub const BB_MLS_LEAF_CRED_LEN: usize = mp_mls::LEAF_CRED_LEN;
pub const BB_MLS_ROOT_ROTATION_LEN: usize = ROOT_ROTATION_LEN;
pub const BB_MLS_SAFETY_NUMBER_V2_LEN: usize = 39;
pub const BB_MLS_EPOCH_AUTH_CODE_LEN: usize = 29;
pub const BB_MLS_MAX_APP_WIRE_BYTES: usize = 24_000;
pub const BB_MLS_MAX_CTRL_BLOB_BYTES: usize = 256 * 1024;
pub const BB_MLS_MAX_FRAMES_PER_EPOCH: u64 = 900;

const STORE_MAGIC: &[u8; 8] = b"BBMLSS1\0";
const STORE_AAD: &[u8] = b"bb-mls-store-v1";
const STORE_FILE_NAME: &str = "state.enc";
const MAX_STATE_DIR_LEN: usize = 4096;

static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BbMlsStatus {
    Ok = 0,
    ErrNullPointer = 1,
    ErrInvalidArg = 2,
    ErrPolicyViolation = 3,
    ErrCredentialInvalid = 4,
    ErrEquivocation = 5,
    ErrPendingRemoval = 6,
    ErrEpochStale = 7,
    ErrDuplicateMsg = 8,
    ErrSelfCloneDetected = 9,
    ErrBucketOverflow = 10,
    ErrStorage = 11,
    ErrPanic = 12,
    ErrBadConfirmation = 13,
    ErrFrameCap = 14,
    ErrNotFound = 15,
    ErrUnsupported = 16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BbMlsByteBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

impl BbMlsByteBuf {
    const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }

    fn from_vec(mut vec: Vec<u8>) -> Self {
        if vec.is_empty() {
            return Self::empty();
        }
        vec.shrink_to_fit();
        let len = vec.len();
        let ptr = vec.as_mut_ptr();
        std::mem::forget(vec);
        Self { ptr, len }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BbMlsActiveDeviceEntry {
    pub device_id: u64,
    pub device_gen: u32,
    pub mls_sig_pubkey: [u8; BB_MLS_PUBKEY_LEN],
}

#[repr(C)]
pub struct BbMlsEngineConfig {
    pub abi_version: u32,
    pub state_dir: *const c_char,
    pub state_dir_len: usize,
    pub account_id: u64,
    pub device_id: u64,
    pub root_gen: u32,
    pub device_gen: u32,
    pub client_class: u8,
    pub agent_capable: u8,
    pub custody_mode: u8,
    pub mls_sig_seed: *const u8,
    pub store_enc_key: *const u8,
    pub device_binding_236b: *const u8,
    pub device_list_bytes: *const u8,
    pub device_list_len: usize,
}

#[repr(C)]
pub struct BbMlsRoomPolicyConfig {
    pub party_id: u64,
    pub require_self_custody: u8,
    pub allow_browser_devices: u8,
    pub org_id: u64,
    pub host_account_ids: *const u64,
    pub host_account_count: usize,
}

#[repr(C)]
pub struct BbMlsInviteMintOut {
    pub fragment_b64url: BbMlsByteBuf,
    pub server_invite_token: [u8; 32],
    pub server_token_hash: [u8; 32],
    pub invite_record_bytes: BbMlsByteBuf,
}

#[repr(C)]
pub struct BbMlsPrepareJoinOut {
    pub group_id: [u8; BB_MLS_GROUP_ID_LEN],
    pub invite_id: u64,
    pub invite_epoch: u64,
    pub expires_at_s: u64,
    pub policy_bits: u8,
    pub inviter_root_pk: [u8; BB_MLS_PUBKEY_LEN],
    pub server_invite_token: [u8; 32],
    pub kp_ref: [u8; BB_MLS_HASH_LEN],
    pub join_proof: [u8; BB_MLS_HASH_LEN],
    pub kp_bytes: BbMlsByteBuf,
}

#[repr(C)]
pub struct BbMlsAddCommitOut {
    pub commit_bytes: BbMlsByteBuf,
    pub welcome_bytes: BbMlsByteBuf,
    pub welcome_auth_bytes: BbMlsByteBuf,
}

#[repr(C)]
pub struct BbMlsEncryptOut {
    pub mls_epoch: u64,
    pub device_epoch_seq: u64,
    pub total_sent_in_epoch: u64,
    pub needs_pcs_self_update: u8,
    pub wire_bytes: BbMlsByteBuf,
}

#[repr(C)]
pub struct BbMlsDecryptedApp {
    pub mls_epoch: u64,
    pub auth_account_id: u64,
    pub auth_device_id: u64,
    pub device_epoch_seq: u64,
    pub msg_class: u32,
    pub inner_msg_id: [u8; BB_MLS_MSG_ID_LEN],
    pub sender_client_class: u8,
    pub sender_custody_mode: u8,
    pub sender_agent_capable: u8,
    pub is_historical_catchup: u8,
    pub plaintext: BbMlsByteBuf,
}

#[repr(C)]
pub struct BbMlsRoomStatus {
    pub group_id: [u8; BB_MLS_GROUP_ID_LEN],
    pub mls_epoch: u64,
    pub epoch_authenticator: [u8; BB_MLS_HASH_LEN],
    pub epoch_authenticator_code: [c_char; BB_MLS_EPOCH_AUTH_CODE_LEN + 1],
    pub trust_tier: u32,
    pub has_declared_agent: u8,
    pub has_pending_removals: u8,
    pub clone_detected: u8,
    pub needs_pcs_self_update: u8,
    pub inviter_unconfirmed: u8,
    pub occupied_leaf_count: u32,
}

#[derive(Clone, Copy)]
struct CachedLeafAttrs {
    client_class: u8,
    custody_mode: u8,
    agent_capable: u8,
}

struct PendingJoinState {
    group_id: [u8; BB_MLS_GROUP_ID_LEN],
    invite_id: u64,
    invite_epoch: u64,
    expires_at_s: u64,
    policy_bits: u8,
    inviter_root_pk: [u8; BB_MLS_PUBKEY_LEN],
    member_join_mac_key: [u8; 32],
    kp_ref: [u8; 32],
    provider: MpCryptoProvider,
}

impl Drop for PendingJoinState {
    fn drop(&mut self) {
        self.member_join_mac_key.zeroize();
    }
}

struct PersistedGroupSummary {
    group_id: [u8; BB_MLS_GROUP_ID_LEN],
    mls_epoch: u64,
    epoch_authenticator: [u8; 32],
    trust_tier: u32,
    has_declared_agent: u8,
    has_pending_removals: u8,
    clone_detected: u8,
    inviter_unconfirmed: u8,
    occupied_leaf_count: u32,
}

struct LiveGroupEntry {
    client: MpMlsClient,
    leaf_attrs: HashMap<u64, CachedLeafAttrs>,
    manual_clone_detected: bool,
}

impl LiveGroupEntry {
    fn new(client: MpMlsClient) -> Self {
        let mut entry = Self {
            client,
            leaf_attrs: HashMap::new(),
            manual_clone_detected: false,
        };
        entry.refresh_leaf_attrs();
        entry
    }

    fn refresh_leaf_attrs(&mut self) {
        if let Ok(leaves) = self.client.current_leaves_map() {
            for info in leaves.values() {
                let b = &info.cred.binding.body;
                self.leaf_attrs.insert(
                    b.device_id,
                    CachedLeafAttrs {
                        client_class: b.client_class as u8,
                        custody_mode: b.custody_mode as u8,
                        agent_capable: u8::from(b.agent_capable),
                    },
                );
            }
        }
    }

    fn is_clone_detected(&self) -> bool {
        self.manual_clone_detected || self.client.cloned_device_key_suspected()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct StoreKey([u8; 32]);

struct EngineInner {
    mls_dir: PathBuf,
    store_key: StoreKey,
    identity: DeviceIdentity,
    pending_joins: HashMap<[u8; BB_MLS_GROUP_ID_LEN], PendingJoinState>,
    groups: HashMap<[u8; BB_MLS_GROUP_ID_LEN], LiveGroupEntry>,
    persisted_summaries: HashMap<[u8; BB_MLS_GROUP_ID_LEN], PersistedGroupSummary>,
}

pub struct BbMlsEngine {
    inner: Mutex<EngineInner>,
}

fn resolve_now_s(now_s: u64) -> u64 {
    if now_s > 0 {
        return now_s;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn map_error(err: &MpMlsError) -> BbMlsStatus {
    match err {
        MpMlsError::InvalidLength { .. }
        | MpMlsError::TruncatedInput
        | MpMlsError::TrailingBytes
        | MpMlsError::UnsupportedVersion(_)
        | MpMlsError::InvalidSafeId(_)
        | MpMlsError::InvalidSafeCounter(_)
        | MpMlsError::InvalidEnumValue { .. }
        | MpMlsError::InvalidBase64
        | MpMlsError::InvalidPolicyBits(_)
        | MpMlsError::InvalidCatchupLimit(_)
        | MpMlsError::InvalidGroupId
        | MpMlsError::InvalidAppAad
        | MpMlsError::InvalidAppPayload(_)
        | MpMlsError::InvalidGeneration { .. }
        | MpMlsError::InvalidTimestampWindow { .. }
        | MpMlsError::InvalidCommitAck(_) => BbMlsStatus::ErrInvalidArg,

        MpMlsError::DuplicateOrUnsortedStorageKey | MpMlsError::SnapshotCorrupted(_) => {
            BbMlsStatus::ErrStorage
        }

        MpMlsError::InvalidPublicKey
        | MpMlsError::WeakOrTorsionPoint
        | MpMlsError::InvalidSignature
        | MpMlsError::TtlExceeded { .. }
        | MpMlsError::NotValidAtAdmissionTime { .. }
        | MpMlsError::UnsortedOrDuplicateDeviceList
        | MpMlsError::TooManyDevicesInList { .. }
        | MpMlsError::CustodyModeFlipUnderSameRoot
        | MpMlsError::PinnedRootMismatch
        | MpMlsError::RootGenMismatch
        | MpMlsError::InvalidRootRotation(_)
        | MpMlsError::LeafSignatureKeyMismatch
        | MpMlsError::MissingLeafDeviceListExtension
        | MpMlsError::InvalidLeafDeviceList(_)
        | MpMlsError::KeyPackageAdmissionRejected(_) => BbMlsStatus::ErrCredentialInvalid,

        MpMlsError::DeviceListEquivocation { .. } | MpMlsError::StaleDeviceList { .. } => {
            BbMlsStatus::ErrEquivocation
        }

        MpMlsError::InvalidMac
        | MpMlsError::WelcomeKeyPackageMismatch
        | MpMlsError::AadMismatch(_) => BbMlsStatus::ErrBadConfirmation,

        MpMlsError::PayloadExceedsMaxBucket | MpMlsError::WireBucketSizeMismatch { .. } => {
            BbMlsStatus::ErrBucketOverflow
        }

        MpMlsError::FrameLimitExceeded { .. } => BbMlsStatus::ErrFrameCap,

        MpMlsError::SendBlockedByLocalPolicy(_) => BbMlsStatus::ErrPendingRemoval,

        MpMlsError::CannotEvaluateTentativeCommit(_) => BbMlsStatus::ErrEpochStale,

        MpMlsError::ClonedDeviceKeySuspected => BbMlsStatus::ErrSelfCloneDetected,

        MpMlsError::OwnPrivateMessageEcho
        | MpMlsError::MissingRoomPolicyExtension
        | MpMlsError::InvalidRoomPolicy(_)
        | MpMlsError::ForbiddenProposal(_)
        | MpMlsError::ExtensionPolicyViolation(_)
        | MpMlsError::IdentityContinuityViolation(_)
        | MpMlsError::RoomPolicyViolation(_)
        | MpMlsError::TreeInvariantViolation(_)
        | MpMlsError::MissingUpdatePath
        | MpMlsError::InviteExhaustedOrExpired
        | MpMlsError::UnknownOrRevokedInvite(_)
        | MpMlsError::InvalidBootstrap(_)
        | MpMlsError::TentativeCommitError(_) => BbMlsStatus::ErrPolicyViolation,

        MpMlsError::HkdfError | MpMlsError::OpenMls(_) => BbMlsStatus::ErrBadConfirmation,
    }
}

fn trust_tier_to_u32(tier: RoomTrustTier) -> u32 {
    match tier {
        RoomTrustTier::Tier0UnverifiedPostWipe => 0,
        RoomTrustTier::Tier1CloudOrBrowserPresent => 1,
        RoomTrustTier::Tier2SelfCustodyNativeUnverified => 2,
        RoomTrustTier::Tier3SelfCustodyNativeAllVerified => 3,
    }
}

fn encode_commit_ack_v1(ack: &CommitAckV1) -> Result<Vec<u8>, BbMlsStatus> {
    let auth_bytes: &[u8] = match (&ack.status, &ack.epoch_auth_hash) {
        (AckStatus::Ok, Some(h)) => h.as_slice(),
        (AckStatus::Reject, None) => &[],
        _ => return Err(BbMlsStatus::ErrInvalidArg),
    };
    let auth_len = u16::try_from(auth_bytes.len()).map_err(|_| BbMlsStatus::ErrInvalidArg)?;
    let mut out =
        Vec::with_capacity(1 + BB_MLS_GROUP_ID_LEN + 8 + 8 + 32 + 8 + 8 + 1 + 2 + auth_bytes.len() + 64);
    out.push(1);
    out.extend_from_slice(&ack.group_id);
    out.extend_from_slice(&ack.parent_epoch.to_be_bytes());
    out.extend_from_slice(&ack.target_epoch.to_be_bytes());
    out.extend_from_slice(&ack.commit_sha256);
    out.extend_from_slice(&ack.account_id.to_be_bytes());
    out.extend_from_slice(&ack.device_id.to_be_bytes());
    out.push(ack.status as u8);
    out.extend_from_slice(&auth_len.to_be_bytes());
    out.extend_from_slice(auth_bytes);
    out.extend_from_slice(&ack.ack_sig);
    Ok(out)
}

#[cfg(unix)]
fn apply_dir_0700(path: &Path) -> Result<(), BbMlsStatus> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| BbMlsStatus::ErrStorage)
}

#[cfg(not(unix))]
fn apply_dir_0700(_path: &Path) -> Result<(), BbMlsStatus> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn exclude_dir_from_backup(dir: &Path) -> Result<(), BbMlsStatus> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    // Standard Apple binary plist encoding of NSString "com.apple.backupd"
    // matching Time Machine `com.apple.metadata:com_apple_backup_excludeItem`.
    const BPLIST_BACKUPD: &[u8] = &[
        0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, // "bplist00"
        0x5f, 0x10, 0x11, // ASCII string, len 17
        b'c', b'o', b'm', b'.', b'a', b'p', b'p', b'l', b'e', b'.', b'b', b'a', b'c', b'k',
        b'u', b'p', b'd', // "com.apple.backupd"
        0x08, // offset table: obj 0 at offset 8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, // trailer
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // num objects = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // top object = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, // offset table offset = 28
    ];
    unsafe extern "C" {
        fn setxattr(
            path: *const c_char,
            name: *const c_char,
            value: *const std::ffi::c_void,
            size: usize,
            position: u32,
            options: i32,
        ) -> i32;
    }
    let c_path = CString::new(dir.as_os_str().as_bytes()).map_err(|_| BbMlsStatus::ErrStorage)?;
    let c_name = CString::new("com.apple.metadata:com_apple_backup_excludeItem")
        .map_err(|_| BbMlsStatus::ErrStorage)?;
    const XATTR_NOFOLLOW: i32 = 0x0001;
    let rc = unsafe {
        setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            BPLIST_BACKUPD.as_ptr().cast(),
            BPLIST_BACKUPD.len(),
            0,
            XATTR_NOFOLLOW,
        )
    };
    if rc != 0 {
        // Best effort only if filesystem doesn't support xattrs (ENOTSUP), fail otherwise.
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(45 /* ENOTSUP */) {
            return Err(BbMlsStatus::ErrStorage);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn exclude_dir_from_backup(dir: &Path) -> Result<(), BbMlsStatus> {
    let nobackup = dir.join(".nobackup");
    if !nobackup.exists() {
        atomic_write_0600(dir, ".nobackup", b"")?;
    }
    let cachedir = dir.join("CACHEDIR.TAG");
    if !cachedir.exists() {
        const TAG: &[u8] =
            b"Signature: 8a477f597d28d172789f06886806bc55\n# Blackbird live MLS ratchet state - do not back up.\n";
        atomic_write_0600(dir, "CACHEDIR.TAG", TAG)?;
    }
    Ok(())
}

fn atomic_write_0600(dir: &Path, filename: &str, data: &[u8]) -> Result<(), BbMlsStatus> {
    let seq = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{filename}.tmp.{}.{seq}", std::process::id());
    let tmp_path = dir.join(&tmp_name);
    let final_path = dir.join(filename);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp_path).map_err(|_| BbMlsStatus::ErrStorage)?;
    if f.write_all(data).is_err() || f.sync_all().is_err() {
        drop(f);
        let _ = fs::remove_file(&tmp_path);
        return Err(BbMlsStatus::ErrStorage);
    }
    drop(f);
    if fs::rename(&tmp_path, &final_path).is_err() {
        let _ = fs::remove_file(&tmp_path);
        return Err(BbMlsStatus::ErrStorage);
    }
    if let Ok(dir_file) = fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(())
}

fn encrypt_store_blob(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, BbMlsStatus> {
    let crypto = MpStrictCrypto::default();
    let nonce: [u8; 12] = crypto
        .random_array()
        .map_err(|_| BbMlsStatus::ErrStorage)?;
    let ct = crypto
        .aead_encrypt(AeadType::Aes256Gcm, key, plaintext, &nonce, STORE_AAD)
        .map_err(|_| BbMlsStatus::ErrStorage)?;
    let mut out = Vec::with_capacity(STORE_MAGIC.len() + 12 + ct.len());
    out.extend_from_slice(STORE_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_store_blob(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, BbMlsStatus> {
    if blob.len() < STORE_MAGIC.len() + 12 + 16 || &blob[0..8] != STORE_MAGIC {
        return Err(BbMlsStatus::ErrStorage);
    }
    let nonce = &blob[8..20];
    let ct = &blob[20..];
    let crypto = MpStrictCrypto::default();
    crypto
        .aead_decrypt(AeadType::Aes256Gcm, key, ct, nonce, STORE_AAD)
        .map_err(|_| BbMlsStatus::ErrStorage)
}

impl EngineInner {
    fn persist(&self) -> Result<(), BbMlsStatus> {
        let mut buf = Vec::new();
        buf.push(2u8); // schema version 2 (Spec v3.1: invite_epoch + inviter_unconfirmed)

        // Pending joins
        let pj_count = u32::try_from(self.pending_joins.len())
            .map_err(|_| BbMlsStatus::ErrStorage)?;
        buf.extend_from_slice(&pj_count.to_be_bytes());
        for pj in self.pending_joins.values() {
            let prov_bin = pj
                .provider
                .export_storage_binary()
                .map_err(|_| BbMlsStatus::ErrStorage)?;
            let prov_len =
                u32::try_from(prov_bin.len()).map_err(|_| BbMlsStatus::ErrStorage)?;
            buf.extend_from_slice(&pj.group_id);
            buf.extend_from_slice(&pj.invite_id.to_be_bytes());
            buf.extend_from_slice(&pj.invite_epoch.to_be_bytes());
            buf.extend_from_slice(&pj.expires_at_s.to_be_bytes());
            buf.push(pj.policy_bits);
            buf.extend_from_slice(&pj.inviter_root_pk);
            buf.extend_from_slice(&pj.member_join_mac_key);
            buf.extend_from_slice(&pj.kp_ref);
            buf.extend_from_slice(&prov_len.to_be_bytes());
            buf.extend_from_slice(&prov_bin);
        }

        // Group summaries (live groups override persisted summaries)
        let mut summaries: HashMap<[u8; BB_MLS_GROUP_ID_LEN], PersistedGroupSummary> = HashMap::new();
        for (gid, s) in &self.persisted_summaries {
            summaries.insert(
                *gid,
                PersistedGroupSummary {
                    group_id: s.group_id,
                    mls_epoch: s.mls_epoch,
                    epoch_authenticator: s.epoch_authenticator,
                    trust_tier: s.trust_tier,
                    has_declared_agent: s.has_declared_agent,
                    has_pending_removals: s.has_pending_removals,
                    clone_detected: s.clone_detected,
                    inviter_unconfirmed: s.inviter_unconfirmed,
                    occupied_leaf_count: s.occupied_leaf_count,
                },
            );
        }
        for (gid, live) in &self.groups {
            let (tier, has_agent) = live
                .client
                .room_trust_tier()
                .unwrap_or((RoomTrustTier::Tier0UnverifiedPostWipe, false));
            let local_pol = live.client.evaluate_local_policy(None).unwrap_or_default();
            let auth_vec = live.client.epoch_authenticator();
            let mut auth = [0u8; 32];
            let n = auth_vec.len().min(32);
            auth[..n].copy_from_slice(&auth_vec[..n]);
            let leaf_cnt = live
                .client
                .current_leaves_map()
                .map(|m| m.len() as u32)
                .unwrap_or(0);
            summaries.insert(
                *gid,
                PersistedGroupSummary {
                    group_id: *gid,
                    mls_epoch: live.client.epoch(),
                    epoch_authenticator: auth,
                    trust_tier: trust_tier_to_u32(tier),
                    has_declared_agent: u8::from(has_agent),
                    has_pending_removals: u8::from(!local_pol.pending_removal_leaves.is_empty()),
                    clone_detected: u8::from(live.is_clone_detected()),
                    inviter_unconfirmed: u8::from(live.client.inviter_unconfirmed()),
                    occupied_leaf_count: leaf_cnt,
                },
            );
        }

        let grp_count =
            u32::try_from(summaries.len()).map_err(|_| BbMlsStatus::ErrStorage)?;
        buf.extend_from_slice(&grp_count.to_be_bytes());
        for s in summaries.values() {
            buf.extend_from_slice(&s.group_id);
            buf.extend_from_slice(&s.mls_epoch.to_be_bytes());
            buf.extend_from_slice(&s.epoch_authenticator);
            buf.extend_from_slice(&s.trust_tier.to_be_bytes());
            buf.push(s.has_declared_agent);
            buf.push(s.has_pending_removals);
            buf.push(s.clone_detected);
            buf.push(s.inviter_unconfirmed);
            buf.extend_from_slice(&s.occupied_leaf_count.to_be_bytes());
        }

        let enc = encrypt_store_blob(&self.store_key.0, &buf)?;
        buf.zeroize();
        atomic_write_0600(&self.mls_dir, STORE_FILE_NAME, &enc)
    }

    fn load_if_exists(&mut self) -> Result<(), BbMlsStatus> {
        let path = self.mls_dir.join(STORE_FILE_NAME);
        if !path.exists() {
            return Ok(());
        }
        let enc = fs::read(&path).map_err(|_| BbMlsStatus::ErrStorage)?;
        let mut pt = decrypt_store_blob(&self.store_key.0, &enc)?;
        let res = self.decode_state(&pt);
        pt.zeroize();
        res
    }

    fn decode_state(&mut self, bytes: &[u8]) -> Result<(), BbMlsStatus> {
        let mut c = bytes;
        if c.is_empty() || (c[0] != 1 && c[0] != 2) {
            return Err(BbMlsStatus::ErrStorage);
        }
        let schema_ver = c[0];
        c = &c[1..];

        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], BbMlsStatus> {
            if cur.len() < n {
                return Err(BbMlsStatus::ErrStorage);
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }

        let pj_count = u32::from_be_bytes(
            take(&mut c, 4)?
                .try_into()
                .map_err(|_| BbMlsStatus::ErrStorage)?,
        ) as usize;
        if pj_count > 1024 {
            return Err(BbMlsStatus::ErrStorage);
        }
        for _ in 0..pj_count {
            let group_id: [u8; BB_MLS_GROUP_ID_LEN] = take(&mut c, BB_MLS_GROUP_ID_LEN)?
                .try_into()
                .map_err(|_| BbMlsStatus::ErrStorage)?;
            let invite_id = u64::from_be_bytes(
                take(&mut c, 8)?
                    .try_into()
                    .map_err(|_| BbMlsStatus::ErrStorage)?,
            );
            let invite_epoch = if schema_ver >= 2 {
                u64::from_be_bytes(
                    take(&mut c, 8)?
                        .try_into()
                        .map_err(|_| BbMlsStatus::ErrStorage)?,
                )
            } else {
                0
            };
            let expires_at_s = u64::from_be_bytes(
                take(&mut c, 8)?
                    .try_into()
                    .map_err(|_| BbMlsStatus::ErrStorage)?,
            );
            let policy_bits = take(&mut c, 1)?[0];
            let inviter_root_pk: [u8; 32] = take(&mut c, 32)?
                .try_into()
                .map_err(|_| BbMlsStatus::ErrStorage)?;
            let member_join_mac_key: [u8; 32] = take(&mut c, 32)?
                .try_into()
                .map_err(|_| BbMlsStatus::ErrStorage)?;
            let kp_ref: [u8; 32] = take(&mut c, 32)?
                .try_into()
                .map_err(|_| BbMlsStatus::ErrStorage)?;
            let prov_len = u32::from_be_bytes(
                take(&mut c, 4)?
                    .try_into()
                    .map_err(|_| BbMlsStatus::ErrStorage)?,
            ) as usize;
            let prov_bytes = take(&mut c, prov_len)?;
            let provider = MpCryptoProvider::import_storage_binary(prov_bytes)
                .map_err(|_| BbMlsStatus::ErrStorage)?;
            self.pending_joins.insert(
                group_id,
                PendingJoinState {
                    group_id,
                    invite_id,
                    invite_epoch,
                    expires_at_s,
                    policy_bits,
                    inviter_root_pk,
                    member_join_mac_key,
                    kp_ref,
                    provider,
                },
            );
        }

        let grp_count = u32::from_be_bytes(
            take(&mut c, 4)?
                .try_into()
                .map_err(|_| BbMlsStatus::ErrStorage)?,
        ) as usize;
        if grp_count > 1024 {
            return Err(BbMlsStatus::ErrStorage);
        }
        for _ in 0..grp_count {
            let group_id: [u8; BB_MLS_GROUP_ID_LEN] = take(&mut c, BB_MLS_GROUP_ID_LEN)?
                .try_into()
                .map_err(|_| BbMlsStatus::ErrStorage)?;
            let mls_epoch = u64::from_be_bytes(
                take(&mut c, 8)?
                    .try_into()
                    .map_err(|_| BbMlsStatus::ErrStorage)?,
            );
            let epoch_authenticator: [u8; 32] = take(&mut c, 32)?
                .try_into()
                .map_err(|_| BbMlsStatus::ErrStorage)?;
            let trust_tier = u32::from_be_bytes(
                take(&mut c, 4)?
                    .try_into()
                    .map_err(|_| BbMlsStatus::ErrStorage)?,
            );
            let has_declared_agent = take(&mut c, 1)?[0];
            let has_pending_removals = take(&mut c, 1)?[0];
            let clone_detected = take(&mut c, 1)?[0];
            let inviter_unconfirmed = if schema_ver >= 2 {
                take(&mut c, 1)?[0]
            } else {
                0
            };
            let occupied_leaf_count = u32::from_be_bytes(
                take(&mut c, 4)?
                    .try_into()
                    .map_err(|_| BbMlsStatus::ErrStorage)?,
            );
            self.persisted_summaries.insert(
                group_id,
                PersistedGroupSummary {
                    group_id,
                    mls_epoch,
                    epoch_authenticator,
                    trust_tier,
                    has_declared_agent,
                    has_pending_removals,
                    clone_detected,
                    inviter_unconfirmed,
                    occupied_leaf_count,
                },
            );
        }

        if !c.is_empty() {
            return Err(BbMlsStatus::ErrStorage);
        }
        Ok(())
    }
}

fn catch_ffi<F: FnOnce() -> BbMlsStatus>(f: F) -> BbMlsStatus {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(BbMlsStatus::ErrPanic)
}

unsafe fn read_fixed<const N: usize>(ptr: *const u8) -> Result<[u8; N], BbMlsStatus> {
    if ptr.is_null() {
        return Err(BbMlsStatus::ErrNullPointer);
    }
    let slice = unsafe { slice::from_raw_parts(ptr, N) };
    slice.try_into().map_err(|_| BbMlsStatus::ErrInvalidArg)
}

unsafe fn read_bytes<'a>(
    ptr: *const u8,
    len: usize,
    max_len: usize,
) -> Result<&'a [u8], BbMlsStatus> {
    if len > max_len {
        return Err(BbMlsStatus::ErrInvalidArg);
    }
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(BbMlsStatus::ErrNullPointer);
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

fn write_cstr_fixed<const N: usize>(src: &str, dst: &mut [c_char; N]) -> Result<(), BbMlsStatus> {
    let bytes = src.as_bytes();
    if bytes.len() + 1 > N {
        return Err(BbMlsStatus::ErrInvalidArg);
    }
    for (i, &b) in bytes.iter().enumerate() {
        dst[i] = b as c_char;
    }
    dst[bytes.len()] = 0;
    Ok(())
}

// ---------------------------------------------------------------------------
// Exported C-ABI Functions
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_free_bytes(ptr: *mut u8, len: usize) {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        if !ptr.is_null() && len > 0 {
            let mut v = unsafe { Vec::from_raw_parts(ptr, len, len) };
            v.zeroize();
        }
    }));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_free_decrypted_app(app: *mut BbMlsDecryptedApp) {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        if !app.is_null() {
            let app_ref = unsafe { &mut *app };
            if !app_ref.plaintext.ptr.is_null() && app_ref.plaintext.len > 0 {
                unsafe { bb_mls_free_bytes(app_ref.plaintext.ptr, app_ref.plaintext.len) };
            }
            app_ref.plaintext = BbMlsByteBuf::empty();
        }
    }));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_open(
    config: *const BbMlsEngineConfig,
    out_engine: *mut *mut BbMlsEngine,
) -> BbMlsStatus {
    catch_ffi(|| {
        if config.is_null() || out_engine.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe { *out_engine = ptr::null_mut() };
        let cfg = unsafe { &*config };
        if cfg.abi_version != BB_MLS_ABI_VERSION {
            return BbMlsStatus::ErrInvalidArg;
        }
        if cfg.device_id == 0 || cfg.account_id == 0 {
            return BbMlsStatus::ErrInvalidArg;
        }
        if cfg.state_dir.is_null()
            || cfg.state_dir_len == 0
            || cfg.state_dir_len > MAX_STATE_DIR_LEN
        {
            return BbMlsStatus::ErrInvalidArg;
        }
        let dir_bytes =
            unsafe { slice::from_raw_parts(cfg.state_dir.cast::<u8>(), cfg.state_dir_len) };
        let Ok(dir_str) = std::str::from_utf8(dir_bytes) else {
            return BbMlsStatus::ErrInvalidArg;
        };
        if dir_str.contains('\0') {
            return BbMlsStatus::ErrInvalidArg;
        }

        let Ok(mut mls_seed) = (unsafe { read_fixed::<32>(cfg.mls_sig_seed) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let Ok(store_key_raw) = (unsafe { read_fixed::<32>(cfg.store_enc_key) }) else {
            mls_seed.zeroize();
            return BbMlsStatus::ErrNullPointer;
        };
        let Ok(binding_bytes) = (unsafe { read_fixed::<BB_MLS_DEVICE_BINDING_LEN>(cfg.device_binding_236b) }) else {
            mls_seed.zeroize();
            return BbMlsStatus::ErrNullPointer;
        };
        let Ok(list_bytes) =
            (unsafe { read_bytes(cfg.device_list_bytes, cfg.device_list_len, BB_MLS_MAX_CTRL_BLOB_BYTES) })
        else {
            mls_seed.zeroize();
            return BbMlsStatus::ErrInvalidArg;
        };

        let binding = match MpMlsDeviceBindingV1::decode_and_verify(&binding_bytes) {
            Ok(b) => b,
            Err(e) => {
                mls_seed.zeroize();
                return map_error(&e);
            }
        };
        let b = &binding.body;
        if b.account_id != cfg.account_id
            || b.device_id != cfg.device_id
            || b.root_gen != cfg.root_gen
            || b.device_gen != cfg.device_gen
            || (b.client_class as u8) != cfg.client_class
            || u8::from(b.agent_capable) != cfg.agent_capable
            || (b.custody_mode as u8) != cfg.custody_mode
        {
            mls_seed.zeroize();
            return BbMlsStatus::ErrCredentialInvalid;
        }

        let dev_list = match AccountDeviceListV1::decode(list_bytes) {
            Ok(l) => l,
            Err(e) => {
                mls_seed.zeroize();
                return map_error(&e);
            }
        };
        if let Err(e) = dev_list.verify(&b.root_pubkey) {
            mls_seed.zeroize();
            return map_error(&e);
        }
        if dev_list.account_id != cfg.account_id
            || dev_list.root_gen != cfg.root_gen
            || !dev_list.authorizes_leaf(b)
        {
            mls_seed.zeroize();
            return BbMlsStatus::ErrCredentialInvalid;
        }
        let Ok(list_hash) = dev_list.list_hash() else {
            mls_seed.zeroize();
            return BbMlsStatus::ErrCredentialInvalid;
        };
        let leaf_cred = match MpMlsLeafCredV1::new(binding, dev_list.list_version, list_hash) {
            Ok(c) => c,
            Err(e) => {
                mls_seed.zeroize();
                return map_error(&e);
            }
        };

        let device_sk = SigningKey::from_bytes(&mls_seed);
        mls_seed.zeroize();
        let identity = match DeviceIdentity::new(leaf_cred, dev_list, device_sk) {
            Ok(id) => id,
            Err(e) => return map_error(&e),
        };

        let mls_dir = PathBuf::from(dir_str).join("mls");
        if fs::create_dir_all(&mls_dir).is_err() {
            return BbMlsStatus::ErrStorage;
        }
        if let Err(st) = apply_dir_0700(&mls_dir) {
            return st;
        }
        if let Err(st) = exclude_dir_from_backup(&mls_dir) {
            return st;
        }

        let mut inner = EngineInner {
            mls_dir,
            store_key: StoreKey(store_key_raw),
            identity,
            pending_joins: HashMap::new(),
            groups: HashMap::new(),
            persisted_summaries: HashMap::new(),
        };
        if let Err(st) = inner.load_if_exists() {
            return st;
        }
        if let Err(st) = inner.persist() {
            return st;
        }

        let engine = Box::new(BbMlsEngine {
            inner: Mutex::new(inner),
        });
        unsafe { *out_engine = Box::into_raw(engine) };
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_close(engine: *mut BbMlsEngine) {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        if !engine.is_null() {
            let boxed = unsafe { Box::from_raw(engine) };
            if let Ok(guard) = boxed.inner.lock() {
                let _ = guard.persist();
            }
        }
    }));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_sign_device_binding(
    account_id: u64,
    root_gen: u32,
    device_id: u64,
    device_gen: u32,
    client_class: u8,
    agent_capable: u8,
    custody_mode: u8,
    iat_s: u64,
    exp_s: u64,
    root_seed: *const u8,
    device_seed: *const u8,
    out_binding: *mut u8,
) -> BbMlsStatus {
    catch_ffi(|| {
        if root_seed.is_null() || device_seed.is_null() || out_binding.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        if agent_capable > 1 {
            return BbMlsStatus::ErrInvalidArg;
        }
        let cc = match ClientClass::from_u8(client_class) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let cm = match CustodyMode::from_u8(custody_mode) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let Ok(mut r_seed) = (unsafe { read_fixed::<32>(root_seed) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let Ok(mut d_seed) = (unsafe { read_fixed::<32>(device_seed) }) else {
            r_seed.zeroize();
            return BbMlsStatus::ErrNullPointer;
        };
        let root_sk = SigningKey::from_bytes(&r_seed);
        let device_sk = SigningKey::from_bytes(&d_seed);
        r_seed.zeroize();
        d_seed.zeroize();

        let body = MpMlsDeviceBindingBodyV1 {
            version: 1,
            account_id,
            root_gen,
            device_id,
            device_gen,
            client_class: cc,
            agent_capable: agent_capable != 0,
            custody_mode: cm,
            iat_s,
            exp_s,
            root_pubkey: root_sk.verifying_key().to_bytes(),
            mls_sig_pubkey: device_sk.verifying_key().to_bytes(),
        };
        let signed = match MpMlsDeviceBindingV1::sign(body, &root_sk, &device_sk) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let encoded = match signed.encode() {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        unsafe { ptr::copy_nonoverlapping(encoded.as_ptr(), out_binding, BB_MLS_DEVICE_BINDING_LEN) };
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_verify_device_binding(
    binding_bytes: *const u8,
    binding_len: usize,
    now_s: u64,
    check_wall_clock: u8,
) -> BbMlsStatus {
    catch_ffi(|| {
        let bytes = match unsafe { read_bytes(binding_bytes, binding_len, BB_MLS_DEVICE_BINDING_LEN) } {
            Ok(b) => b,
            Err(st) => return st,
        };
        let binding = match MpMlsDeviceBindingV1::decode_and_verify(bytes) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        if check_wall_clock != 0
            && let Err(e) = binding.verify_at_admission(now_s)
        {
            return map_error(&e);
        }
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_sign_device_list(
    account_id: u64,
    root_gen: u32,
    list_version: u64,
    iat_s: u64,
    exp_s: u64,
    entries: *const BbMlsActiveDeviceEntry,
    entry_count: usize,
    root_seed: *const u8,
    out_list_bytes: *mut BbMlsByteBuf,
) -> BbMlsStatus {
    catch_ffi(|| {
        if root_seed.is_null() || out_list_bytes.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe { *out_list_bytes = BbMlsByteBuf::empty() };
        if entry_count > MAX_DEVICES_PER_ACCOUNT {
            return BbMlsStatus::ErrInvalidArg;
        }
        if entry_count > 0 && entries.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let raw_entries = if entry_count == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(entries, entry_count) }
        };
        let parsed: Vec<ActiveDeviceEntryV1> = raw_entries
            .iter()
            .map(|e| ActiveDeviceEntryV1 {
                device_id: e.device_id,
                device_gen: e.device_gen,
                mls_sig_pubkey: e.mls_sig_pubkey,
            })
            .collect();
        let Ok(mut r_seed) = (unsafe { read_fixed::<32>(root_seed) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let root_sk = SigningKey::from_bytes(&r_seed);
        r_seed.zeroize();

        let list = match AccountDeviceListV1::sign(
            account_id,
            root_gen,
            list_version,
            iat_s,
            exp_s,
            parsed,
            &root_sk,
        ) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let encoded = match list.encode() {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        unsafe { *out_list_bytes = BbMlsByteBuf::from_vec(encoded) };
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_verify_device_list(
    list_bytes: *const u8,
    list_len: usize,
    expected_root_pk: *const u8,
) -> BbMlsStatus {
    catch_ffi(|| {
        let Ok(pk) = (unsafe { read_fixed::<32>(expected_root_pk) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let bytes = match unsafe { read_bytes(list_bytes, list_len, BB_MLS_MAX_CTRL_BLOB_BYTES) } {
            Ok(b) => b,
            Err(st) => return st,
        };
        let list = match AccountDeviceListV1::decode(bytes) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        match list.verify(&pk) {
            Ok(()) => BbMlsStatus::Ok,
            Err(e) => map_error(&e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_observe_device_list(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    list_bytes: *const u8,
    list_len: usize,
    now_s: u64,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let bytes = match unsafe { read_bytes(list_bytes, list_len, BB_MLS_MAX_CTRL_BLOB_BYTES) } {
            Ok(b) => b,
            Err(st) => return st,
        };
        let list = match AccountDeviceListV1::decode(bytes) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        let now_opt = if now_s > 0 { Some(now_s) } else { None };
        match entry.client.observe_device_list(list, now_opt) {
            Ok(_) => {
                let _ = guard.persist();
                BbMlsStatus::Ok
            }
            Err(e) => map_error(&e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_sign_root_rotation(
    account_id: u64,
    old_root_gen: u32,
    new_root_gen: u32,
    old_custody_mode: u8,
    new_custody_mode: u8,
    rotated_at_s: u64,
    old_root_seed: *const u8,
    new_root_seed: *const u8,
    out_stmt: *mut u8,
) -> BbMlsStatus {
    catch_ffi(|| {
        if old_root_seed.is_null() || new_root_seed.is_null() || out_stmt.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let old_cm = match CustodyMode::from_u8(old_custody_mode) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let new_cm = match CustodyMode::from_u8(new_custody_mode) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let Ok(mut old_s) = (unsafe { read_fixed::<32>(old_root_seed) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let Ok(mut new_s) = (unsafe { read_fixed::<32>(new_root_seed) }) else {
            old_s.zeroize();
            return BbMlsStatus::ErrNullPointer;
        };
        let old_sk = SigningKey::from_bytes(&old_s);
        let new_sk = SigningKey::from_bytes(&new_s);
        old_s.zeroize();
        new_s.zeroize();

        let stmt = match RootRotationStmtV1::sign(
            account_id,
            old_root_gen,
            new_root_gen,
            old_cm,
            new_cm,
            rotated_at_s,
            &old_sk,
            &new_sk,
        ) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let encoded = match stmt.encode() {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        unsafe { ptr::copy_nonoverlapping(encoded.as_ptr(), out_stmt, BB_MLS_ROOT_ROTATION_LEN) };
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_verify_root_rotation(
    stmt_bytes: *const u8,
    stmt_len: usize,
) -> BbMlsStatus {
    catch_ffi(|| {
        let bytes = match unsafe { read_bytes(stmt_bytes, stmt_len, BB_MLS_ROOT_ROTATION_LEN) } {
            Ok(b) => b,
            Err(st) => return st,
        };
        match RootRotationStmtV1::decode_and_verify(bytes) {
            Ok(_) => BbMlsStatus::Ok,
            Err(e) => map_error(&e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_apply_root_rotation(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    stmt_bytes: *const u8,
    stmt_len: usize,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let bytes = match unsafe { read_bytes(stmt_bytes, stmt_len, BB_MLS_ROOT_ROTATION_LEN) } {
            Ok(b) => b,
            Err(st) => return st,
        };
        let stmt = match RootRotationStmtV1::decode_and_verify(bytes) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        match entry.client.apply_root_rotation(&stmt) {
            Ok(()) => {
                let _ = guard.persist();
                BbMlsStatus::Ok
            }
            Err(e) => map_error(&e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_safety_number_v2(
    account_id: u64,
    root_pubkey: *const u8,
    custody_mode: u8,
    out_code: *mut c_char,
) -> BbMlsStatus {
    catch_ffi(|| {
        if root_pubkey.is_null() || out_code.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        if let Err(e) = mp_mls::check_safe_id(account_id) {
            return map_error(&e);
        }
        let Ok(pk) = (unsafe { read_fixed::<32>(root_pubkey) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        if let Err(e) = mp_mls::validate_ed25519_pubkey_strict(&pk) {
            return map_error(&e);
        }
        let cm = match CustodyMode::from_u8(custody_mode) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let code = compute_safety_number_v2(account_id, &pk, cm);
        let dst = unsafe { &mut *(out_code as *mut [c_char; BB_MLS_SAFETY_NUMBER_V2_LEN + 1]) };
        if let Err(st) = write_cstr_fixed(&code, dst) {
            return st;
        }
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_format_epoch_authenticator(
    auth_bytes: *const u8,
    auth_len: usize,
    out_code: *mut c_char,
) -> BbMlsStatus {
    catch_ffi(|| {
        if auth_bytes.is_null() || out_code.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let bytes = match unsafe { read_bytes(auth_bytes, auth_len, 128) } {
            Ok(b) => b,
            Err(st) => return st,
        };
        let code = match format_epoch_authenticator(bytes) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let dst = unsafe { &mut *(out_code as *mut [c_char; BB_MLS_EPOCH_AUTH_CODE_LEN + 1]) };
        if let Err(st) = write_cstr_fixed(&code, dst) {
            return st;
        }
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_create_group(
    engine: *mut BbMlsEngine,
    policy: *const BbMlsRoomPolicyConfig,
    ds_pubkey: *const u8,
    incarnation_nonce_8b: *const u8,
    out_group_id: *mut u8,
    out_group_info: *mut BbMlsByteBuf,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null()
            || policy.is_null()
            || ds_pubkey.is_null()
            || out_group_id.is_null()
            || out_group_info.is_null()
        {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe { *out_group_info = BbMlsByteBuf::empty() };

        let pcfg = unsafe { &*policy };
        if pcfg.require_self_custody > 1 || pcfg.allow_browser_devices > 1 {
            return BbMlsStatus::ErrInvalidArg;
        }
        if pcfg.host_account_count == 0
            || pcfg.host_account_count > mp_mls::MAX_HOST_ACCOUNTS
            || pcfg.host_account_ids.is_null()
        {
            return BbMlsStatus::ErrInvalidArg;
        }
        let mut hosts =
            unsafe { slice::from_raw_parts(pcfg.host_account_ids, pcfg.host_account_count) }
                .to_vec();
        hosts.sort_unstable();
        hosts.dedup();

        let Ok(ds_pk) = (unsafe { read_fixed::<32>(ds_pubkey) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let nonce: [u8; 8] = if incarnation_nonce_8b.is_null() {
            match MpStrictCrypto::default().random_array() {
                Ok(n) => n,
                Err(_) => return BbMlsStatus::ErrStorage,
            }
        } else {
            match unsafe { read_fixed::<8>(incarnation_nonce_8b) } {
                Ok(n) => n,
                Err(st) => return st,
            }
        };

        let room_policy = MpRoomPolicyExtV1 {
            version: 1,
            party_id: pcfg.party_id,
            e2ee_mode: 1,
            require_self_custody: pcfg.require_self_custody != 0,
            allow_browser_devices: pcfg.allow_browser_devices != 0,
            org_id: pcfg.org_id,
            host_account_ids: hosts,
            banned_account_ids: Vec::new(),
            invite_epoch: 0,
        };

        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let (client, gi_bytes) = match MpMlsClient::create_room(
            pcfg.party_id,
            nonce,
            &ds_pk,
            room_policy,
            guard.identity.clone(),
        ) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let gid = client.group_id();
        guard.groups.insert(gid, LiveGroupEntry::new(client));
        if let Err(st) = guard.persist() {
            return st;
        }
        unsafe {
            ptr::copy_nonoverlapping(gid.as_ptr(), out_group_id, BB_MLS_GROUP_ID_LEN);
            *out_group_info = BbMlsByteBuf::from_vec(gi_bytes);
        }
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_mint_invite(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    invite_id: u64,
    max_uses: u32,
    expires_at_s: u64,
    out_invite: *mut BbMlsInviteMintOut,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || group_id.is_null() || out_invite.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe {
            (*out_invite).fragment_b64url = BbMlsByteBuf::empty();
            (*out_invite).invite_record_bytes = BbMlsByteBuf::empty();
        }
        if max_uses == 0 {
            return BbMlsStatus::ErrInvalidArg;
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };

        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let inviter_root_pk = guard.identity.cred.binding.body.root_pubkey;
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        let policy = match entry.client.room_policy() {
            Ok(p) => p,
            Err(e) => return map_error(&e),
        };
        let invite_seed: [u8; 32] = match MpStrictCrypto::default().random_array() {
            Ok(s) => s,
            Err(_) => return BbMlsStatus::ErrStorage,
        };
        let secrets = match InviteSecrets::derive(&gid, &invite_seed) {
            Ok(s) => s,
            Err(e) => return map_error(&e),
        };
        let frag = InviteFragmentV2 {
            group_id: gid,
            invite_id,
            invite_epoch: policy.invite_epoch,
            expires_at_s,
            policy_bits: policy.policy_bits(),
            inviter_root_pk,
            invite_seed,
        };
        let frag_b64 = match frag.encode_b64url() {
            Ok(s) => s,
            Err(e) => return map_error(&e),
        };
        let record = InviteRecordV1 {
            invite_id,
            invite_epoch: policy.invite_epoch,
            max_uses,
            expires_at_s,
            inviter_root_pk,
            member_join_mac_key: secrets.member_join_mac_key,
        };
        let record_bytes = match record.encode() {
            Ok(b) => b,
            Err(e) => return map_error(&e),
        };
        entry.client.register_active_invite(record);
        if let Err(st) = guard.persist() {
            return st;
        }

        let out = unsafe { &mut *out_invite };
        out.fragment_b64url = BbMlsByteBuf::from_vec(frag_b64.into_bytes());
        out.server_invite_token = secrets.server_invite_token;
        out.server_token_hash = secrets.server_token_hash;
        out.invite_record_bytes = BbMlsByteBuf::from_vec(record_bytes.to_vec());
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_register_invite_record(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    invite_record_bytes: *const u8,
    invite_record_len: usize,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let bytes =
            match unsafe { read_bytes(invite_record_bytes, invite_record_len, INVITE_RECORD_V1_LEN) } {
                Ok(b) => b,
                Err(st) => return st,
            };
        let record = match InviteRecordV1::decode(bytes) {
            Ok(r) => r,
            Err(e) => return map_error(&e),
        };
        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        entry.client.register_active_invite(record);
        let _ = guard.persist();
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_prepare_join(
    engine: *mut BbMlsEngine,
    fragment_b64url: *const c_char,
    fragment_b64url_len: usize,
    out_join: *mut BbMlsPrepareJoinOut,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || fragment_b64url.is_null() || out_join.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe { (*out_join).kp_bytes = BbMlsByteBuf::empty() };
        if fragment_b64url_len == 0 || fragment_b64url_len > 512 {
            return BbMlsStatus::ErrInvalidArg;
        }
        let raw_frag = unsafe { slice::from_raw_parts(fragment_b64url.cast::<u8>(), fragment_b64url_len) };
        let Ok(frag_str) = std::str::from_utf8(raw_frag) else {
            return BbMlsStatus::ErrInvalidArg;
        };
        let frag = match InviteFragmentV2::decode_b64url(frag_str) {
            Ok(f) => f,
            Err(e) => return map_error(&e),
        };
        let secrets = match frag.derive_secrets() {
            Ok(s) => s,
            Err(e) => return map_error(&e),
        };

        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let provider = MpCryptoProvider::new();
        let (kp_bytes, kp_ref) = match generate_single_use_key_package(&guard.identity, &provider) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let join_proof = match compute_join_proof(
            &secrets.member_join_mac_key,
            &frag.group_id,
            frag.invite_id,
            frag.invite_epoch,
            frag.expires_at_s,
            guard.identity.account_id(),
            guard.identity.device_id(),
            &kp_ref,
        ) {
            Ok(p) => p,
            Err(e) => return map_error(&e),
        };

        // Persist KeyPackage private bundle & invite secrets BEFORE returning to caller (Spec v3.1 Astra #8)!
        guard.pending_joins.insert(
            frag.group_id,
            PendingJoinState {
                group_id: frag.group_id,
                invite_id: frag.invite_id,
                invite_epoch: frag.invite_epoch,
                expires_at_s: frag.expires_at_s,
                policy_bits: frag.policy_bits,
                inviter_root_pk: frag.inviter_root_pk,
                member_join_mac_key: secrets.member_join_mac_key,
                kp_ref,
                provider,
            },
        );
        if let Err(st) = guard.persist() {
            guard.pending_joins.remove(&frag.group_id);
            return st;
        }

        let out = unsafe { &mut *out_join };
        out.group_id = frag.group_id;
        out.invite_id = frag.invite_id;
        out.invite_epoch = frag.invite_epoch;
        out.expires_at_s = frag.expires_at_s;
        out.policy_bits = frag.policy_bits;
        out.inviter_root_pk = frag.inviter_root_pk;
        out.server_invite_token = secrets.server_invite_token;
        out.kp_ref = kp_ref;
        out.join_proof = join_proof;
        out.kp_bytes = BbMlsByteBuf::from_vec(kp_bytes);
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_prepare_direct_join(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    out_kp_ref: *mut u8,
    out_kp_bytes: *mut BbMlsByteBuf,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || group_id.is_null() || out_kp_ref.is_null() || out_kp_bytes.is_null()
        {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe { *out_kp_bytes = BbMlsByteBuf::empty() };
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };

        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let own_acct = guard.identity.account_id();
        let own_root_pk = guard.identity.cred.binding.body.root_pubkey;
        let sibling_mac_key = match derive_sibling_welcome_mac_key(&gid, own_acct, &own_root_pk) {
            Ok(k) => k,
            Err(e) => return map_error(&e),
        };
        let provider = MpCryptoProvider::new();
        let (kp_bytes, kp_ref) = match generate_single_use_key_package(&guard.identity, &provider) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };

        guard.pending_joins.insert(
            gid,
            PendingJoinState {
                group_id: gid,
                invite_id: 1,
                invite_epoch: 0,
                expires_at_s: u64::MAX / 2,
                policy_bits: 0,
                inviter_root_pk: own_root_pk,
                member_join_mac_key: sibling_mac_key,
                kp_ref,
                provider,
            },
        );
        if let Err(st) = guard.persist() {
            guard.pending_joins.remove(&gid);
            return st;
        }

        unsafe {
            ptr::copy_nonoverlapping(kp_ref.as_ptr(), out_kp_ref, BB_MLS_HASH_LEN);
            *out_kp_bytes = BbMlsByteBuf::from_vec(kp_bytes);
        }
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_process_welcome(
    engine: *mut BbMlsEngine,
    expected_party_id: u64,
    expected_ds_pubkey: *const u8,
    welcome_bytes: *const u8,
    welcome_len: usize,
    welcome_auth_bytes: *const u8,
    welcome_auth_len: usize,
    out_group_id: *mut u8,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || expected_ds_pubkey.is_null() || out_group_id.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let Ok(ds_pk) = (unsafe { read_fixed::<32>(expected_ds_pubkey) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let w_bytes = match unsafe { read_bytes(welcome_bytes, welcome_len, BB_MLS_MAX_CTRL_BLOB_BYTES) } {
            Ok(b) => b,
            Err(st) => return st,
        };
        let wa_bytes =
            match unsafe { read_bytes(welcome_auth_bytes, welcome_auth_len, WELCOME_AUTH_V1_LEN) } {
                Ok(b) => b,
                Err(st) => return st,
            };
        let welcome_auth = match WelcomeAuthV1::decode(wa_bytes) {
            Ok(wa) => wa,
            Err(e) => return map_error(&e),
        };

        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let identity = guard.identity.clone();

        // Look up pending join by `welcome_auth.group_id` OR fallback to matching `joiner_kp_ref`
        // so fake-group Welcome with altered group_id is still rejected cleanly with ErrBadConfirmation
        // WITHOUT consuming the KeyPackage!
        let pending_key = if guard.pending_joins.contains_key(&welcome_auth.group_id) {
            welcome_auth.group_id
        } else if let Some((&k, _)) = guard
            .pending_joins
            .iter()
            .find(|(_, pj)| pj.kp_ref == welcome_auth.joiner_kp_ref)
        {
            k
        } else {
            return BbMlsStatus::ErrBadConfirmation;
        };

        // Run isolated snapshot Welcome processing on pending join's provider (MpMlsClient::join_from_welcome
        // forks isolated storage internally and NEVER mutates pending.provider on failure!).
        let client = {
            let Some(pending) = guard.pending_joins.get_mut(&pending_key) else {
                return BbMlsStatus::ErrNotFound;
            };
            match MpMlsClient::join_from_welcome(
                w_bytes,
                &welcome_auth,
                &pending.member_join_mac_key,
                &pending.kp_ref,
                pending.group_id,
                expected_party_id,
                &ds_pk,
                pending.policy_bits,
                pending.invite_epoch,
                &pending.inviter_root_pk,
                identity,
                &mut pending.provider,
            ) {
                Ok(c) => c,
                Err(e) => return map_error(&e),
            }
        };

        let gid = client.group_id();
        guard.pending_joins.remove(&pending_key);
        guard.groups.insert(gid, LiveGroupEntry::new(client));
        if let Err(st) = guard.persist() {
            return st;
        }
        unsafe { ptr::copy_nonoverlapping(gid.as_ptr(), out_group_id, BB_MLS_GROUP_ID_LEN) };
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_commit_add_invitee(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    invite_id: u64,
    kp_bytes: *const u8,
    kp_len: usize,
    join_proof: *const u8,
    now_s: u64,
    allow_delegated: u8,
    out_commit: *mut BbMlsAddCommitOut,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || out_commit.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe {
            (*out_commit).commit_bytes = BbMlsByteBuf::empty();
            (*out_commit).welcome_bytes = BbMlsByteBuf::empty();
            (*out_commit).welcome_auth_bytes = BbMlsByteBuf::empty();
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let Ok(jp) = (unsafe { read_fixed::<32>(join_proof) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let kp = match unsafe { read_bytes(kp_bytes, kp_len, BB_MLS_MAX_CTRL_BLOB_BYTES) } {
            Ok(b) => b,
            Err(st) => return st,
        };

        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        let add_out = match entry.client.commit_add_member_with_invite(
            kp,
            invite_id,
            &jp,
            now_s,
            allow_delegated != 0,
        ) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let wa_bytes = match add_out.welcome_auth.encode() {
            Ok(v) => v.to_vec(),
            Err(e) => return map_error(&e),
        };
        if let Err(st) = guard.persist() {
            return st;
        }

        let out = unsafe { &mut *out_commit };
        out.commit_bytes = BbMlsByteBuf::from_vec(add_out.commit_bytes);
        out.welcome_bytes = BbMlsByteBuf::from_vec(add_out.welcome_bytes);
        out.welcome_auth_bytes = BbMlsByteBuf::from_vec(wa_bytes);
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_commit_add_sibling(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    kp_bytes: *const u8,
    kp_len: usize,
    now_s: u64,
    out_commit: *mut BbMlsAddCommitOut,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || out_commit.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe {
            (*out_commit).commit_bytes = BbMlsByteBuf::empty();
            (*out_commit).welcome_bytes = BbMlsByteBuf::empty();
            (*out_commit).welcome_auth_bytes = BbMlsByteBuf::empty();
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let kp = match unsafe { read_bytes(kp_bytes, kp_len, BB_MLS_MAX_CTRL_BLOB_BYTES) } {
            Ok(b) => b,
            Err(st) => return st,
        };

        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        let add_out = match entry
            .client
            .commit_add_sibling_device(kp, resolve_now_s(now_s))
        {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let wa_bytes = match add_out.welcome_auth.encode() {
            Ok(v) => v.to_vec(),
            Err(e) => return map_error(&e),
        };
        if let Err(st) = guard.persist() {
            return st;
        }

        let out = unsafe { &mut *out_commit };
        out.commit_bytes = BbMlsByteBuf::from_vec(add_out.commit_bytes);
        out.welcome_bytes = BbMlsByteBuf::from_vec(add_out.welcome_bytes);
        out.welcome_auth_bytes = BbMlsByteBuf::from_vec(wa_bytes);
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_apply_proposal(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    proposal_bytes: *const u8,
    proposal_len: usize,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let bytes =
            match unsafe { read_bytes(proposal_bytes, proposal_len, BB_MLS_MAX_CTRL_BLOB_BYTES) } {
                Ok(b) => b,
                Err(st) => return st,
            };
        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        match entry.client.apply_proposal(bytes) {
            Ok(()) => {
                let _ = guard.persist();
                BbMlsStatus::Ok
            }
            Err(e) => map_error(&e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_commit_pending_or_self_update(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    has_pending_proposals: u8,
    out_commit_bytes: *mut BbMlsByteBuf,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || out_commit_bytes.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe { *out_commit_bytes = BbMlsByteBuf::empty() };
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        let res = if has_pending_proposals != 0 {
            entry.client.commit_pending_proposals(None)
        } else {
            entry.client.commit_self_update(None)
        };
        let commit_bytes = match res {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        if let Err(st) = guard.persist() {
            return st;
        }
        unsafe { *out_commit_bytes = BbMlsByteBuf::from_vec(commit_bytes) };
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_stage_tentative_commit(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    commit_bytes: *const u8,
    commit_len: usize,
    out_ack_status: *mut u8,
    out_ack_bytes: *mut BbMlsByteBuf,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || out_ack_status.is_null() || out_ack_bytes.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe {
            *out_ack_status = 0;
            *out_ack_bytes = BbMlsByteBuf::empty();
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let bytes =
            match unsafe { read_bytes(commit_bytes, commit_len, BB_MLS_MAX_CTRL_BLOB_BYTES) } {
                Ok(b) => b,
                Err(st) => return st,
            };

        let eng = unsafe { &*engine };
        let Ok(guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        let ack = match entry.client.validate_tentative_commit_and_sign_ack(bytes) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let encoded = match encode_commit_ack_v1(&ack) {
            Ok(v) => v,
            Err(st) => return st,
        };
        unsafe {
            *out_ack_status = ack.status as u8;
            *out_ack_bytes = BbMlsByteBuf::from_vec(encoded);
        }
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_finalize_commit(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    commit_bytes: *const u8,
    commit_len: usize,
    now_s: u64,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let bytes =
            match unsafe { read_bytes(commit_bytes, commit_len, BB_MLS_MAX_CTRL_BLOB_BYTES) } {
                Ok(b) => b,
                Err(st) => return st,
            };

        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        // Snapshot leaf attributes before advancing so past-epoch decryptions still know removed leaves.
        entry.refresh_leaf_attrs();
        let report = match entry
            .client
            .apply_finalized_commit(bytes, resolve_now_s(now_s))
        {
            Ok(r) => r,
            Err(e) => return map_error(&e),
        };
        entry.refresh_leaf_attrs();
        let _ = report;
        if let Err(st) = guard.persist() {
            return st;
        }
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_discard_tentative(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        match entry.client.discard_pending_commit() {
            Ok(()) => {
                let _ = guard.persist();
                BbMlsStatus::Ok
            }
            Err(e) => map_error(&e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_encrypt_app(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    inner_msg_id: *const u8,
    msg_class: u32,
    plaintext: *const u8,
    plaintext_len: usize,
    now_s: u64,
    out_encrypted: *mut BbMlsEncryptOut,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || out_encrypted.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe { (*out_encrypted).wire_bytes = BbMlsByteBuf::empty() };
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let Ok(mid) = (unsafe { read_fixed::<BB_MLS_MSG_ID_LEN>(inner_msg_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let cls = match MsgClass::from_u32(msg_class) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        if plaintext_len > BB_MLS_MAX_APP_WIRE_BYTES {
            return BbMlsStatus::ErrBucketOverflow;
        }
        let pt = match unsafe { read_bytes(plaintext, plaintext_len, BB_MLS_MAX_APP_WIRE_BYTES) } {
            Ok(b) => b,
            Err(st) => return st,
        };

        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };

        if entry.is_clone_detected() {
            return BbMlsStatus::ErrSelfCloneDetected;
        }
        let eff_now_s = resolve_now_s(now_s);
        // Spec v3.1 §7.2: hard-block outbound sends at 900 total frames in a single epoch
        // BEFORE advancing the OpenMLS ratchet!
        if entry.client.total_sent_frames_in_epoch() >= BB_MLS_MAX_FRAMES_PER_EPOCH {
            return BbMlsStatus::ErrFrameCap;
        }
        // Block outbound sends if local policy flags pending removals or pin violations.
        if let Ok(report) = entry.client.evaluate_local_policy(Some(eff_now_s))
            && report.should_block_send()
        {
            if !report.pin_violations.is_empty() {
                return BbMlsStatus::ErrCredentialInvalid;
            }
            return BbMlsStatus::ErrPendingRemoval;
        }

        let outbox = match entry.client.encrypt_app_message(mid, cls, pt, eff_now_s) {
            Ok(v) => v,
            Err(e) => return map_error(&e),
        };
        let total_sent = entry.client.total_sent_frames_in_epoch();
        let needs_pcs = u8::from(entry.client.needs_pcs_self_update());
        if let Err(st) = guard.persist() {
            return st;
        }

        let out = unsafe { &mut *out_encrypted };
        out.mls_epoch = outbox.sent_epoch;
        out.device_epoch_seq = outbox.device_epoch_seq;
        out.total_sent_in_epoch = total_sent;
        out.needs_pcs_self_update = needs_pcs;
        out.wire_bytes = BbMlsByteBuf::from_vec(outbox.wire_bytes);
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_decrypt_app(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    wire_bytes: *const u8,
    wire_len: usize,
    is_catchup_hint: u8,
    out_decrypted: *mut BbMlsDecryptedApp,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || out_decrypted.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        unsafe { (*out_decrypted).plaintext = BbMlsByteBuf::empty() };
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let wire = match unsafe { read_bytes(wire_bytes, wire_len, BB_MLS_MAX_APP_WIRE_BYTES) } {
            Ok(b) => b,
            Err(st) => return st,
        };

        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        let current_epoch = entry.client.epoch();
        entry.refresh_leaf_attrs();

        let dec = match entry.client.decrypt_app_message(wire) {
            Ok(v) => v,
            Err(e) => {
                if matches!(e, MpMlsError::ClonedDeviceKeySuspected) {
                    let _ = guard.persist();
                }
                return map_error(&e);
            }
        };

        if dec.is_duplicate {
            let _ = guard.persist();
            return BbMlsStatus::ErrDuplicateMsg;
        }

        // Look up authenticated leaf attributes (client_class, custody_mode, agent_capable).
        let attrs = entry
            .leaf_attrs
            .get(&dec.auth_device_id)
            .copied()
            .unwrap_or(CachedLeafAttrs {
                client_class: ClientClass::Browser as u8, // fail-safe untrusted if unknown
                custody_mode: CustodyMode::CloudManaged as u8,
                agent_capable: 0,
            });
        let historical = is_catchup_hint != 0 || dec.epoch < current_epoch;

        if let Err(st) = guard.persist() {
            return st;
        }

        let out = unsafe { &mut *out_decrypted };
        out.mls_epoch = dec.epoch;
        out.auth_account_id = dec.auth_account_id;
        out.auth_device_id = dec.auth_device_id;
        out.device_epoch_seq = dec.device_epoch_seq;
        out.msg_class = u32::from(dec.msg_class as u8);
        out.inner_msg_id = dec.inner_msg_id;
        out.sender_client_class = attrs.client_class;
        out.sender_custody_mode = attrs.custody_mode;
        out.sender_agent_capable = attrs.agent_capable;
        out.is_historical_catchup = u8::from(historical);
        out.plaintext = BbMlsByteBuf::from_vec(dec.body);
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_prune_past_epochs(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    now_s: u64,
    out_pruned_count: *mut u32,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        if !out_pruned_count.is_null() {
            unsafe { *out_pruned_count = 0 };
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        let pruned = match entry.client.prune_past_epochs(resolve_now_s(now_s)) {
            Ok(n) => n,
            Err(e) => return map_error(&e),
        };
        if !out_pruned_count.is_null() {
            unsafe { *out_pruned_count = u32::try_from(pruned).unwrap_or(u32::MAX) };
        }
        if pruned > 0 {
            let _ = guard.persist();
        }
        BbMlsStatus::Ok
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_room_status(
    engine: *const BbMlsEngine,
    group_id: *const u8,
    now_s: u64,
    out_status: *mut BbMlsRoomStatus,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() || out_status.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let eng = unsafe { &*engine };
        let Ok(guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };

        let out = unsafe { &mut *out_status };
        *out = BbMlsRoomStatus {
            group_id: gid,
            mls_epoch: 0,
            epoch_authenticator: [0u8; BB_MLS_HASH_LEN],
            epoch_authenticator_code: [0 as c_char; BB_MLS_EPOCH_AUTH_CODE_LEN + 1],
            trust_tier: 0,
            has_declared_agent: 0,
            has_pending_removals: 0,
            clone_detected: 0,
            needs_pcs_self_update: 0,
            inviter_unconfirmed: 0,
            occupied_leaf_count: 0,
        };

        if let Some(entry) = guard.groups.get(&gid) {
            let (tier, has_agent) = match entry.client.room_trust_tier() {
                Ok(v) => v,
                Err(e) => return map_error(&e),
            };
            let now_opt = if now_s > 0 { Some(now_s) } else { None };
            let local_pol = match entry.client.evaluate_local_policy(now_opt) {
                Ok(v) => v,
                Err(e) => return map_error(&e),
            };
            let auth_vec = entry.client.epoch_authenticator();
            let n = auth_vec.len().min(BB_MLS_HASH_LEN);
            out.epoch_authenticator[..n].copy_from_slice(&auth_vec[..n]);
            if let Ok(code) = format_epoch_authenticator(&out.epoch_authenticator) {
                let _ = write_cstr_fixed(&code, &mut out.epoch_authenticator_code);
            }
            out.mls_epoch = entry.client.epoch();
            out.trust_tier = trust_tier_to_u32(tier);
            out.has_declared_agent = u8::from(has_agent);
            out.has_pending_removals = u8::from(
                !local_pol.pending_removal_leaves.is_empty()
                    || !local_pol.expired_binding_leaves.is_empty(),
            );
            out.clone_detected = u8::from(entry.is_clone_detected());
            out.needs_pcs_self_update = u8::from(entry.client.needs_pcs_self_update());
            out.inviter_unconfirmed = u8::from(entry.client.inviter_unconfirmed());
            out.occupied_leaf_count = entry
                .client
                .current_leaves_map()
                .map(|m| m.len() as u32)
                .unwrap_or(0);
            return BbMlsStatus::Ok;
        }

        if let Some(summary) = guard.persisted_summaries.get(&gid) {
            out.mls_epoch = summary.mls_epoch;
            out.epoch_authenticator = summary.epoch_authenticator;
            if let Ok(code) = format_epoch_authenticator(&out.epoch_authenticator) {
                let _ = write_cstr_fixed(&code, &mut out.epoch_authenticator_code);
            }
            out.trust_tier = summary.trust_tier;
            out.has_declared_agent = summary.has_declared_agent;
            out.has_pending_removals = summary.has_pending_removals;
            out.clone_detected = summary.clone_detected;
            out.inviter_unconfirmed = summary.inviter_unconfirmed;
            out.occupied_leaf_count = summary.occupied_leaf_count;
            return BbMlsStatus::Ok;
        }

        BbMlsStatus::ErrNotFound
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_mark_peer_verified_oob(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
    peer_account_id: u64,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        match entry.client.pins_mut().mark_verified_oob(peer_account_id) {
            Ok(()) => {
                let _ = guard.persist();
                BbMlsStatus::Ok
            }
            Err(e) => map_error(&e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_mls_mark_clone_detected(
    engine: *mut BbMlsEngine,
    group_id: *const u8,
) -> BbMlsStatus {
    catch_ffi(|| {
        if engine.is_null() {
            return BbMlsStatus::ErrNullPointer;
        }
        let Ok(gid) = (unsafe { read_fixed::<BB_MLS_GROUP_ID_LEN>(group_id) }) else {
            return BbMlsStatus::ErrNullPointer;
        };
        let eng = unsafe { &*engine };
        let Ok(mut guard) = eng.inner.lock() else {
            return BbMlsStatus::ErrPanic;
        };
        let Some(entry) = guard.groups.get_mut(&gid) else {
            return BbMlsStatus::ErrNotFound;
        };
        entry.manual_clone_detected = true;
        let _ = guard.persist();
        BbMlsStatus::Ok
    })
}
