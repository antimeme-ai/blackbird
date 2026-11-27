#include "blackbird/mp_client.hpp"
#include "blackbird/mp_mls.hpp"
#include "blackbird/mp_protocol.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#if defined(__APPLE__)
#include <sys/xattr.h>
#endif
#include <unistd.h>
#include <vector>

namespace {

using namespace blackbird;
using namespace blackbird::mp;

void require_ok(bool ok, std::source_location loc = std::source_location::current()) {
  if (!ok) {
    std::cerr << "mp_mls_test FAIL at " << loc.file_name() << ":" << loc.line() << "\n";
    std::abort();
  }
}

template <typename T>
T require_val(Result<T> res,
              std::source_location loc = std::source_location::current()) {
  if (!res.has_value()) {
    std::cerr << "mp_mls_test FAIL (Result error code="
              << static_cast<int>(res.error().code) << " detail=" << res.error().detail
              << ") at " << loc.file_name() << ":" << loc.line() << "\n";
    std::abort();
  }
  return std::move(res).value();
}

struct TempDir {
  std::filesystem::path path;
  explicit TempDir(std::string_view tag) {
    static std::atomic<std::uint64_t> counter{0U};
    const auto id = counter.fetch_add(1U, std::memory_order_relaxed);
    path = std::filesystem::temp_directory_path() /
           ("bb_mp_mls_test_" + std::string{tag} + "_" +
            std::to_string(static_cast<std::uint64_t>(::getpid())) + "_" +
            std::to_string(id));
    std::filesystem::create_directories(path);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

struct TestActor {
  AccountId account_id = AccountId::create(1U).value();
  DeviceId device_id = DeviceId::create(1U).value();
  Ed25519Seed root_seed{};
  Ed25519PubKey root_pk{};
  Ed25519Seed dev_seed{};
  Ed25519PubKey dev_pk{};
  std::array<std::uint8_t, 32> store_key{};
  MlsDeviceBinding binding{};
  std::vector<std::uint8_t> device_list;
  MpMlsEngineConfig cfg{};
};

struct TestActorSpec {
  std::filesystem::path dir;
  std::uint64_t acct_num = 1U;
  std::uint64_t dev_num = 1U;
  std::uint8_t client_class = 1U;
  bool agent_capable = false;
  std::uint8_t custody_mode = 1U;
  std::uint8_t seed_tag = 0x11U;
  std::uint64_t now_s = 0U;
};

TestActor make_actor(const TestActorSpec &spec) {
  TestActor a{};
  a.account_id = AccountId::create(spec.acct_num).value();
  a.device_id = DeviceId::create(spec.dev_num).value();
  a.root_seed.fill(spec.seed_tag);
  a.dev_seed.fill(static_cast<std::uint8_t>(spec.seed_tag ^ 0x5aU));
  a.store_key.fill(static_cast<std::uint8_t>(spec.seed_tag ^ 0xa5U));

  const auto rsk = require_val(Ed25519SigningKey::from_seed(a.root_seed));
  const auto dsk = require_val(Ed25519SigningKey::from_seed(a.dev_seed));
  a.root_pk = rsk.public_key();
  a.dev_pk = dsk.public_key();

  const std::uint64_t ttl = (spec.client_class == 3U) ? (7ULL * 86400ULL - 120ULL)
                                                      : (30ULL * 86400ULL - 120ULL);
  a.binding = require_val(mp_mls_sign_device_binding(
      a.account_id, 1U, a.device_id, 1U, spec.client_class, spec.agent_capable,
      spec.custody_mode, spec.now_s - 60ULL, spec.now_s + ttl, a.root_seed,
      a.dev_seed));

  const std::array<MpMlsActiveDeviceEntry, 1> entries{
      MpMlsActiveDeviceEntry{a.device_id.value(), 1U, a.dev_pk},
  };
  a.device_list = require_val(mp_mls_sign_device_list(
      a.account_id, 1U, 1U, spec.now_s - 60ULL,
      spec.now_s + (30ULL * 86400ULL - 120ULL), entries, a.root_seed));

  a.cfg.state_dir = spec.dir;
  a.cfg.account_id = a.account_id;
  a.cfg.device_id = a.device_id;
  a.cfg.root_gen = 1U;
  a.cfg.device_gen = 1U;
  a.cfg.client_class = spec.client_class;
  a.cfg.agent_capable = spec.agent_capable;
  a.cfg.custody_mode = spec.custody_mode;
  a.cfg.mls_sig_seed = a.dev_seed;
  a.cfg.store_enc_key = a.store_key;
  a.cfg.device_binding = a.binding;
  a.cfg.device_list_bytes = a.device_list;
  return a;
}

void verify_backup_excluded(const std::filesystem::path &dir) {
#if defined(__APPLE__)
  std::array<char, 256> xbuf{};
  const ssize_t n =
      ::getxattr(dir.c_str(), "com.apple.metadata:com_apple_backup_excludeItem",
                 xbuf.data(), xbuf.size(), 0U, XATTR_NOFOLLOW);
  require_ok(n > 0);
  const std::string_view val{xbuf.data(), static_cast<std::size_t>(n)};
  require_ok(val.find("com.apple.backupd") != std::string_view::npos);
#else
  struct stat st1{};
  struct stat st2{};
  require_ok(::lstat((dir / ".nobackup").c_str(), &st1) == 0);
  require_ok((st1.st_mode & 0777U) == 0600U);
  require_ok(::lstat((dir / "CACHEDIR.TAG").c_str(), &st2) == 0);
  require_ok((st2.st_mode & 0777U) == 0600U);
#endif
}

} // namespace

int main() {
  require_ok(mp_mls_compiled_in());

  TempDir tmp{"e2e"};
  constexpr std::uint64_t kNowS = 1770000000ULL;

  // 1. Safety Number v2 (delegated to bb_mls_safety_number_v2) + custody mode
  // sensitivity.
  {
    Ed25519Seed seed{};
    seed.fill(0x11U);
    const auto rsk = require_val(Ed25519SigningKey::from_seed(seed));
    const auto acct = AccountId::create(1001U).value();

    const std::string sn_self =
        require_val(compute_safety_number_v2(acct, rsk.public_key(), 1U));
    const std::string sn_cloud =
        require_val(compute_safety_number_v2(acct, rsk.public_key(), 0U));
    require_ok(sn_self.size() == kMlsSafetyNumberV2Len);
    require_ok(sn_cloud.size() == kMlsSafetyNumberV2Len);
    require_ok(sn_self != sn_cloud);

    // Invalid custody_mode > 1 fails closed.
    require_ok(!compute_safety_number_v2(acct, rsk.public_key(), 2U).has_value());
    // Weak/all-zero pubkey fails closed.
    Ed25519PubKey zero_pk{};
    require_ok(!compute_safety_number_v2(acct, zero_pk, 1U).has_value());
  }

  // 2. Backup exclusion marker verified on BOTH MpIdentityStore (open_keystore_dir)
  //    AND MpMlsEngine (<state_dir>/mls/).
  {
    const auto ks_dir = tmp.path / "keystore";
    auto store = require_val(MpIdentityStore::open_or_init_device(ks_dir));
    verify_backup_excluded(ks_dir);
  }

  // 3. Identity codecs: device binding (236B), device list, root rotation (210B).
  const auto alice = make_actor(
      TestActorSpec{tmp.path / "alice", 101U, 1001U, 1U, true, 1U, 0x21U, kNowS});
  const auto bob = make_actor(
      TestActorSpec{tmp.path / "bob", 202U, 2002U, 1U, false, 1U, 0x33U, kNowS});
  const auto mallory = make_actor(
      TestActorSpec{tmp.path / "mallory", 666U, 6666U, 1U, false, 1U, 0x66U, kNowS});
  {
    require_ok(mp_mls_verify_device_binding(alice.binding, kNowS).has_value());
    require_ok(!mp_mls_verify_device_binding(alice.binding, kNowS + 40ULL * 86400ULL)
                    .has_value());
    auto tampered = alice.binding;
    tampered[5] ^= 0x01U;
    require_ok(!mp_mls_verify_device_binding(tampered).has_value());

    require_ok(mp_mls_verify_device_list(alice.device_list, alice.root_pk).has_value());
    require_ok(!mp_mls_verify_device_list(alice.device_list, bob.root_pk).has_value());

    Ed25519Seed new_root_seed{};
    new_root_seed.fill(0x99U);
    const auto rot = require_val(mp_mls_sign_root_rotation(
        alice.account_id, 1U, 2U, 1U, 1U, kNowS, alice.root_seed, new_root_seed));
    require_ok(mp_mls_verify_root_rotation(rot).has_value());
    auto bad_rot = rot;
    bad_rot[100] ^= 0x80U;
    require_ok(!mp_mls_verify_root_rotation(bad_rot).has_value());
  }

  // 4. Open engines, verify backup exclusion on <state_dir>/mls/ + encrypted atomic
  // store.
  auto alice_eng = require_val(MpMlsEngine::open(alice.cfg));
  auto bob_eng = require_val(MpMlsEngine::open(bob.cfg));
  auto mallory_eng = require_val(MpMlsEngine::open(mallory.cfg));

  verify_backup_excluded(tmp.path / "alice" / "mls");
  verify_backup_excluded(tmp.path / "bob" / "mls");
  {
    struct stat st{};
    require_ok(::lstat((tmp.path / "alice" / "mls" / "state.enc").c_str(), &st) == 0);
    require_ok((st.st_mode & 0777U) == 0600U);
    // Reopening with wrong encryption key MUST fail closed with MpMlsError::storage.
    MpMlsEngineConfig wrong_key_cfg = alice.cfg;
    wrong_key_cfg.store_enc_key[0] ^= 0xffU;
    const auto bad_open = MpMlsEngine::open(wrong_key_cfg);
    require_ok(!bad_open.has_value() &&
               mp_mls_error_of(bad_open.error()) == MpMlsError::storage);
  }

  // 5. End-to-end 2-party create -> mint invite -> prepare join -> crash-safe reopen
  //    -> fake-group Welcome REJECTED without consuming KeyPackage -> real Welcome
  //    succeeds!
  Ed25519Seed ds_seed{};
  ds_seed.fill(0x77U);
  const auto ds_sk = require_val(Ed25519SigningKey::from_seed(ds_seed));
  const auto party_id = PartyId::create(5001U).value();

  MpMlsRoomPolicy policy{};
  policy.party_id = party_id;
  policy.require_self_custody = true;
  policy.allow_browser_devices = false;
  policy.org_id = 0U;
  policy.host_account_ids = {alice.account_id.value()};

  const auto created = require_val(alice_eng.create_group(policy, ds_sk.public_key()));
  require_ok(!created.group_info_bytes.empty());

  const auto minted =
      require_val(alice_eng.mint_invite(created.group_id, 42U, 2U, kNowS + 3600ULL));
  require_ok(!minted.fragment_b64url.empty());
  require_ok(minted.invite_record_bytes.size() == kMlsInviteRecordBytes);

  const auto prep = require_val(bob_eng.prepare_join(minted.fragment_b64url));
  require_ok(prep.group_id == created.group_id);
  require_ok(prep.invite_id == 42U);
  require_ok(prep.invite_epoch == 0U);
  require_ok(prep.inviter_root_pk == alice.root_pk);
  require_ok(prep.server_invite_token == minted.server_invite_token);
  require_ok(!prep.kp_bytes.empty());

  // Simulate Bob restarting after prepare_join before Welcome arrives: encrypted store
  // restores KP!
  bob_eng.close();
  bob_eng = require_val(MpMlsEngine::open(bob.cfg));

  // Fake-group Welcome attack: Mallory creates a spoofed group for the same party_id,
  // mints her own invite, tries to welcome Bob with her forged WelcomeAuthV1 -> MUST
  // FAIL AND MUST NOT consume Bob's KeyPackage!
  {
    MpMlsRoomPolicy fake_pol{};
    fake_pol.party_id = party_id;
    fake_pol.require_self_custody = true;
    fake_pol.allow_browser_devices = false;
    fake_pol.host_account_ids = {mallory.account_id.value()};
    const auto fake_grp =
        require_val(mallory_eng.create_group(fake_pol, ds_sk.public_key()));
    const auto fake_inv = require_val(
        mallory_eng.mint_invite(fake_grp.group_id, 99U, 1U, kNowS + 3600ULL));
    // Craft a canonical 177-byte forged WelcomeAuthV1 with Bob's kp_ref and invalid
    // MAC.
    auto forged_wa = std::vector<std::uint8_t>(kMlsWelcomeAuthBytes, 0x00U);
    forged_wa[0] = 1U;
    std::memcpy(forged_wa.data() + 1U, created.group_id.data(), 24U);
    forged_wa[32] = 1U;  // target_epoch = 1
    forged_wa[40] = 42U; // invite_id = 42
    // invite_epoch = 0 at bytes 41..49
    std::memcpy(forged_wa.data() + 49U, prep.kp_ref.data(), 32U);
    const auto fake_res = bob_eng.process_welcome(party_id, ds_sk.public_key(),
                                                  fake_grp.group_info_bytes, forged_wa);
    require_ok(!fake_res.has_value());
    (void)fake_inv;
  }

  // Real Add Commit + Welcome succeeds right after fake-group Welcome was rejected!
  const auto add_out = require_val(alice_eng.commit_add_invitee(
      created.group_id, 42U, prep.kp_bytes, prep.join_proof, kNowS));
  require_ok(!add_out.commit_bytes.empty());
  require_ok(!add_out.welcome_bytes.empty());
  require_ok(add_out.welcome_auth_bytes.size() == kMlsWelcomeAuthBytes);

  // Tampered WelcomeAuthV1 MAC is rejected without consuming Bob's KeyPackage!
  {
    auto bad_wa = add_out.welcome_auth_bytes;
    bad_wa.back() ^= 0x01U;
    const auto rej = bob_eng.process_welcome(party_id, ds_sk.public_key(),
                                             add_out.welcome_bytes, bad_wa);
    require_ok(!rej.has_value() &&
               mp_mls_error_of(rej.error()) == MpMlsError::bad_confirmation);
  }

  // Now process genuine Welcome + finalize Commit on Alice.
  const auto bob_gid = require_val(bob_eng.process_welcome(
      party_id, ds_sk.public_key(), add_out.welcome_bytes, add_out.welcome_auth_bytes));
  require_ok(bob_gid == created.group_id);
  require_ok(alice_eng.finalize_commit(created.group_id, add_out.commit_bytes, kNowS)
                 .has_value());

  // Both parties agree on epoch 1, identical 6x4 Crockford Base32 epoch_authenticator,
  // Tier 2 -> Tier 3 OOB verification, inviter confirmed, and has_declared_agent ==
  // true!
  {
    const auto ast = require_val(alice_eng.room_status(created.group_id, kNowS));
    const auto bst = require_val(bob_eng.room_status(created.group_id, kNowS));
    require_ok(ast.mls_epoch == 1U && bst.mls_epoch == 1U);
    require_ok(ast.epoch_authenticator == bst.epoch_authenticator);
    require_ok(ast.epoch_authenticator_code == bst.epoch_authenticator_code);
    require_ok(ast.epoch_authenticator_code.size() == kMlsEpochAuthCodeLen);
    require_ok(ast.trust_tier == MpMlsTrustTier::tier2_self_custody_tofu);
    require_ok(ast.has_declared_agent && bst.has_declared_agent);
    require_ok(!ast.inviter_unconfirmed && !bst.inviter_unconfirmed);
    require_ok(ast.occupied_leaf_count == 2U && bst.occupied_leaf_count == 2U);
    require_ok(!ast.clone_detected && !bst.clone_detected);

    require_ok(
        alice_eng.mark_peer_verified_oob(created.group_id, bob.account_id).has_value());
    const auto ast_verified =
        require_val(alice_eng.room_status(created.group_id, kNowS));
    require_ok(ast_verified.trust_tier == MpMlsTrustTier::tier3_self_custody_verified);
  }

  // 6. Exact padded wire buckets (512 / 2048 / 8192 / 24000 B) + overflow before
  // ratchet advance!
  {
    struct BucketCase {
      std::size_t payload_len;
      std::size_t expected_wire_len;
    };
    const std::array<BucketCase, 4> cases{{
        {16U, 512U},
        {400U, 2048U},
        {2500U, 8192U},
        {9000U, 24000U},
    }};
    for (std::size_t idx = 0U; idx < cases.size(); ++idx) {
      std::vector<std::uint8_t> pt(cases[idx].payload_len,
                                   static_cast<std::uint8_t>('A' + idx));
      MlsInnerMsgId mid{};
      mid.fill(static_cast<std::uint8_t>(idx + 1U));
      const auto enc = require_val(
          alice_eng.encrypt_app(created.group_id, mid, MpMlsMsgClass::chat, pt, kNowS));
      require_ok(enc.mls_epoch == 1U);
      require_ok(enc.device_epoch_seq == idx);
      require_ok(enc.wire_bytes.size() == cases[idx].expected_wire_len);

      const auto dec =
          require_val(bob_eng.decrypt_app(created.group_id, enc.wire_bytes));
      require_ok(dec.mls_epoch == 1U);
      require_ok(dec.auth_account_id == alice.account_id.value());
      require_ok(dec.auth_device_id == alice.device_id.value());
      require_ok(dec.device_epoch_seq == idx);
      require_ok(dec.msg_class == MpMlsMsgClass::chat);
      require_ok(dec.inner_msg_id == mid);
      require_ok(dec.sender_client_class == 1U);
      require_ok(dec.sender_custody_mode == 1U);
      require_ok(dec.sender_agent_capable);
      require_ok(!dec.is_historical_catchup);
      require_ok(dec.plaintext == pt);
    }

    // Oversize payload (> 23776 B) rejected with bucket_overflow BEFORE advancing
    // ratchet!
    std::vector<std::uint8_t> huge(23900U, 0x58U);
    MlsInnerMsgId huge_mid{};
    huge_mid.fill(0xeeU);
    const auto ovf = alice_eng.encrypt_app(created.group_id, huge_mid,
                                           MpMlsMsgClass::chat, huge, kNowS);
    require_ok(!ovf.has_value() &&
               mp_mls_error_of(ovf.error()) == MpMlsError::bucket_overflow);

    // Next valid message MUST still have consecutive device_epoch_seq == 4 (ratchet NOT
    // advanced!).
    const std::string ok_str = "post-overflow-check";
    MlsInnerMsgId ok_mid{};
    ok_mid.fill(0x55U);
    const auto post = require_val(alice_eng.encrypt_app(
        created.group_id, ok_mid, MpMlsMsgClass::chat,
        std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t *>(ok_str.data()), ok_str.size()},
        kNowS));
    require_ok(post.device_epoch_seq == 4U);
    require_ok(post.wire_bytes.size() == 512U);
    const auto dec_post =
        require_val(bob_eng.decrypt_app(created.group_id, post.wire_bytes));
    require_ok(dec_post.device_epoch_seq == 4U);
  }

  // 7. Tentative commit staging + epoch advance + historical catch-up flag + dedup on
  // requeue
  //    + past-epoch pruning after 120s window!
  {
    // Encrypt an epoch-1 message on Alice BEFORE advancing to epoch 2 (delivered late
    // as catch-up).
    const std::string late_str = "late-epoch1-msg";
    MlsInnerMsgId late_mid{};
    late_mid.fill(0x71U);
    const auto late_enc = require_val(alice_eng.encrypt_app(
        created.group_id, late_mid, MpMlsMsgClass::chat,
        std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t *>(late_str.data()), late_str.size()},
        kNowS));

    // Alice creates PCS self-update commit (epoch 1 -> 2).
    const auto upd_commit =
        require_val(alice_eng.commit_pending_or_self_update(created.group_id, false));
    // Bob stages tentative commit and emits signed OK ack.
    const auto tack =
        require_val(bob_eng.stage_tentative_commit(created.group_id, upd_commit));
    require_ok(tack.status == 1U && !tack.ack_bytes.empty());
    // Both finalize epoch 2.
    require_ok(
        alice_eng.finalize_commit(created.group_id, upd_commit, kNowS).has_value());
    require_ok(
        bob_eng.finalize_commit(created.group_id, upd_commit, kNowS).has_value());

    // Bob decrypts the late epoch-1 message while at epoch 2 -> `is_historical_catchup
    // == true`!
    const auto dec_late =
        require_val(bob_eng.decrypt_app(created.group_id, late_enc.wire_bytes, false));
    require_ok(dec_late.mls_epoch == 1U && dec_late.is_historical_catchup);

    // Epoch-stale requeue of the exact same `inner_msg_id` in epoch 2 -> deduplicated!
    const auto requeued = require_val(alice_eng.encrypt_app(
        created.group_id, late_mid, MpMlsMsgClass::chat,
        std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t *>(late_str.data()), late_str.size()},
        kNowS));
    require_ok(requeued.mls_epoch == 2U);
    const auto dup = bob_eng.decrypt_app(created.group_id, requeued.wire_bytes, false);
    require_ok(!dup.has_value() &&
               mp_mls_error_of(dup.error()) == MpMlsError::duplicate_msg);

    // Prune past epochs after the 120s Spec v3.1 window.
    const auto pruned =
        require_val(bob_eng.prune_past_epochs(created.group_id, kNowS + 125ULL));
    require_ok(pruned >= 1U);
  }

  // 8. 900-frame hard cap per epoch (500-frame PCS self-update trigger + 901st frame
  // blocked).
  {
    const std::array<std::uint8_t, 4> tiny = {'p', 'i', 'n', 'g'};
    bool saw_pcs_trigger = false;
    // Note: 1 frame was already sent in epoch 2 above (`requeued`), so send 899 more to
    // hit 900.
    for (std::uint32_t i = 0U; i < 899U; ++i) {
      MlsInnerMsgId mid{};
      mid[0] = static_cast<std::uint8_t>(i & 0xffU);
      mid[1] = static_cast<std::uint8_t>((i >> 8U) & 0xffU);
      mid[15] = 0xcau;
      const auto e = require_val(alice_eng.encrypt_app(
          created.group_id, mid, MpMlsMsgClass::ephemeral_status, tiny, kNowS));
      if (e.total_sent_in_epoch >= 500U) {
        require_ok(e.needs_pcs_self_update);
        saw_pcs_trigger = true;
      }
    }
    require_ok(saw_pcs_trigger);
    MlsInnerMsgId cap_mid{};
    cap_mid.fill(0xffU);
    const auto blocked = alice_eng.encrypt_app(created.group_id, cap_mid,
                                               MpMlsMsgClass::chat, tiny, kNowS);
    require_ok(!blocked.has_value() &&
               mp_mls_error_of(blocked.error()) == MpMlsError::frame_cap);
  }

  std::cout << "mp_mls_test PASS\n";
  return 0;
}
