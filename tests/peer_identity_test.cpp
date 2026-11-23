#include "blackbird/peer_identity.hpp"

#include "blackbird/json.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

const char *g_stage = "startup";

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

template <class T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{context} + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
  return std::move(result).value();
}

void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{context} + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
}

void test_identity_generation_and_security(const std::filesystem::path &base) {
  g_stage = "identity_generation_and_security";
  const auto patrick_dir = base / "identities" / "patrick";
  const auto buddy_dir = base / "identities" / "buddy";

  auto patrick = must(PeerIdentityStore::open_or_create(patrick_dir), "create patrick");
  auto buddy = must(PeerIdentityStore::open_or_create(buddy_dir), "create buddy");

  check(patrick.root() == patrick_dir, "patrick root mismatch");
  check(valid_peer_fingerprint(patrick.identity().fingerprint),
        "patrick fingerprint invalid");
  check(valid_peer_fingerprint(buddy.identity().fingerprint),
        "buddy fingerprint invalid");
  check(patrick.identity().fingerprint != buddy.identity().fingerprint,
        "independent identities produced identical fingerprints");
  check(patrick.identity().public_key.starts_with("ssh-ed25519 "),
        "patrick public key missing ssh-ed25519 prefix");

  // Verify strict 0700 dir and 0600 key permissions.
  struct stat st{};
  check(::lstat(patrick_dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode) &&
            (st.st_mode & 0777) == 0700,
        "identity dir is not 0700");
  check(::lstat((patrick_dir / "id_ed25519").c_str(), &st) == 0 &&
            S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600,
        "private key is not 0600");
  check(::lstat((patrick_dir / "id_ed25519.pub").c_str(), &st) == 0 &&
            S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600,
        "public key is not 0600");

  // Fingerprint determinism: comments and surrounding whitespace do not change
  // canonical public key or fingerprint.
  const std::string with_comment = patrick.identity().public_key + " patrick@macbook\n";
  check(must(canonicalize_ed25519_public_key(with_comment), "canonicalize comment") ==
            patrick.identity().public_key,
        "canonical key did not strip comment");
  check(must(peer_fingerprint_from_public_key(with_comment), "fp with comment") ==
            patrick.identity().fingerprint,
        "fingerprint changed when comment was added");

  // Reloading existing identity preserves exact keypair and fingerprint.
  auto reopened = must(PeerIdentityStore::open_existing(patrick_dir), "open existing");
  check(reopened.identity() == patrick.identity(), "reopened identity mismatch");
  auto reopened2 =
      must(PeerIdentityStore::open_or_create(patrick_dir), "reopen or_create");
  check(reopened2.identity() == patrick.identity(), "open_or_create regenerated key");

  // Reject symlink root, permissive 0755 dir, missing open_existing, empty path.
  const auto link_dir = base / "symlink-id";
  check(::symlink(patrick_dir.c_str(), link_dir.c_str()) == 0,
        "symlink creation failed");
  check(!PeerIdentityStore::open_existing(link_dir).has_value(),
        "symlink identity dir accepted");

  const auto loose_dir = base / "loose-id";
  check(::mkdir(loose_dir.c_str(), mode_t{0755}) == 0, "mkdir 0755 failed");
  check(::chmod(loose_dir.c_str(), mode_t{0755}) == 0, "chmod 0755 failed");
  check(!PeerIdentityStore::open_or_create(loose_dir).has_value(),
        "0755 identity dir accepted");
  check(!PeerIdentityStore::open_existing(base / "does-not-exist").has_value(),
        "missing dir accepted by open_existing");
  check(!PeerIdentityStore::open_or_create(std::filesystem::path{}).has_value(),
        "empty path accepted");

  // Reject invalid public key formats.
  const std::array<std::string_view, 6> bad_keys = {
      "",
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==",
      "ssh-ed25519 not-valid-base64!!!",
      "ssh-ed25519 AAAA",
      "ssh-ed25519 "
      "AAAAC3NzaC1lZDI1NTE5AAAAIBEl3hjLIcAjxhPzp4wuuwJZhx9LlRRWc0r3RqLZUjN\n",
      "ssh-ed25519 "
      "AAAAC3NzaC1lZDI1NTE5AAAAIBEl3hjLIcAjxhPzp4wuuwJZhx9LlRRWc0r3RqLZUjNG\ninjected",
  };
  for (const auto bad : bad_keys) {
    check(!peer_fingerprint_from_public_key(bad).has_value(),
          "invalid ed25519 public key accepted");
  }

  // Move construction and assignment keep store usable.
  PeerIdentityStore moved = std::move(reopened);
  const auto sig = must(moved.sign_bytes("move-check"), "sign after move");
  must_void(verify_detached_signature({moved.identity().fingerprint,
                                       moved.identity().public_key, "move-check", sig}),
            "verify after move");
  moved = std::move(reopened2);
  check(moved.identity() == patrick.identity(), "move-assigned identity mismatch");
}

void test_known_peers_pinning_and_mitm_rejection(const std::filesystem::path &base) {
  g_stage = "known_peers_pinning_and_mitm_rejection";
  auto patrick =
      must(PeerIdentityStore::open_or_create(base / "pin-patrick"), "create patrick");
  auto buddy =
      must(PeerIdentityStore::open_or_create(base / "pin-buddy"), "create buddy");
  auto mallory =
      must(PeerIdentityStore::open_or_create(base / "pin-mallory"), "create mallory");

  auto patrick_peers =
      must(KnownPeersStore::open(base / "patrick-known-peers"), "open patrick peers");
  auto buddy_peers =
      must(KnownPeersStore::open(base / "buddy-known-peers"), "open buddy peers");

  const auto pinned_buddy = must(
      patrick_peers.pin_peer(
          {"buddy", buddy.identity().public_key + " buddy@linux", "Stage 0 friend"}),
      "pin buddy");
  check(pinned_buddy.alias == "buddy", "pinned alias mismatch");
  check(pinned_buddy.fingerprint == buddy.identity().fingerprint,
        "pinned fingerprint mismatch");
  check(pinned_buddy.public_key == buddy.identity().public_key,
        "pinned canonical pubkey mismatch");
  check(!pinned_buddy.revoked && pinned_buddy.pinned_at_ns > 0, "pinned state invalid");

  const auto pinned_patrick = must(
      buddy_peers.pin_peer({"patrick", patrick.identity().public_key, "Stage 0 lead"}),
      "pin patrick");
  check(pinned_patrick.fingerprint == patrick.identity().fingerprint,
        "cross-pinned patrick fingerprint mismatch");

  // Silent key-swap MITM attack on existing alias "buddy" MUST fail with conflict.
  const auto mitm =
      patrick_peers.pin_peer({"buddy", mallory.identity().public_key, "spoofed buddy"});
  check(!mitm.has_value() && mitm.error().code == ErrorCode::conflict,
        "silent key swap on existing alias was not rejected with ErrorCode::conflict");

  // Same key under a second alias MUST fail with conflict.
  const auto dup_fp =
      patrick_peers.pin_peer({"buddy-clone", buddy.identity().public_key, "dup"});
  check(!dup_fp.has_value() && dup_fp.error().code == ErrorCode::conflict,
        "duplicate fingerprint under new alias was accepted");

  // Idempotent re-pin of same alias + same key updates trust_note cleanly.
  const auto updated_buddy =
      must(patrick_peers.pin_peer(
               {"buddy", buddy.identity().public_key, "verified in person"}),
           "idempotent repin");
  check(updated_buddy.trust_note == "verified in person", "trust_note did not update");

  // Persistence across store reopen and lookups by alias / fingerprint.
  auto reopened =
      must(KnownPeersStore::open(base / "patrick-known-peers"), "reopen patrick peers");
  const auto by_alias = must(reopened.find_by_alias("buddy"), "find_by_alias");
  check(by_alias.has_value() && by_alias->fingerprint == buddy.identity().fingerprint &&
            by_alias->trust_note == "verified in person",
        "find_by_alias after reopen mismatch");
  const auto by_fp = must(reopened.find_by_fingerprint(buddy.identity().fingerprint),
                          "find_by_fingerprint");
  check(by_fp.has_value() && by_fp->alias == "buddy",
        "find_by_fingerprint after reopen mismatch");
  const auto missing = must(reopened.find_by_alias("nobody"), "find missing alias");
  check(!missing.has_value(), "missing alias returned a peer");
  const auto peers = must(reopened.list_peers(), "list peers");
  check(peers.size() == 1 && peers[0].alias == "buddy", "list_peers mismatch");
}

void test_signed_envelopes_and_tampering(const std::filesystem::path &base) {
  g_stage = "signed_envelopes_and_tampering";
  auto patrick =
      must(PeerIdentityStore::open_or_create(base / "env-patrick"), "create patrick");
  auto buddy =
      must(PeerIdentityStore::open_or_create(base / "env-buddy"), "create buddy");
  auto mallory =
      must(PeerIdentityStore::open_or_create(base / "env-mallory"), "create mallory");

  auto buddy_peers =
      must(KnownPeersStore::open(base / "env-buddy-peers"), "open buddy peers");
  must(buddy_peers.pin_peer({"patrick", patrick.identity().public_key, "trusted"}),
       "pin patrick");
  must(buddy_peers.pin_peer({"buddy", buddy.identity().public_key, "self"}),
       "pin self");

  // Exercise all 7 envelope kinds, direct & room recipients, and nested JSON payloads.
  const std::array<PeerEnvelopeKind, 7> kinds = {
      PeerEnvelopeKind::mail,     PeerEnvelopeKind::brief,    PeerEnvelopeKind::handoff,
      PeerEnvelopeKind::decision, PeerEnvelopeKind::artifact, PeerEnvelopeKind::review,
      PeerEnvelopeKind::recall,
  };
  for (std::size_t i = 0; i < kinds.size(); ++i) {
    PeerEnvelopeDraft draft{
        "",
        (i % 2 == 0) ? buddy.identity().fingerprint : "room:stage3-ops",
        "thread-alpha",
        kinds[i],
        1730000000000000000 + static_cast<std::int64_t>(i),
        Value::object(
            {{"z_key", Value{"last"}},
             {"a_key", Value{Number{static_cast<std::int64_t>(i)}}},
             {"nested", Value::object({{"b", Value{true}}, {"a", Value{"ok"}}})}}),
    };
    const auto env = must(patrick.sign_envelope(std::move(draft)), "sign envelope");
    check(env.version == kPeerEnvelopeVersion, "envelope version != 1");
    check(!env.envelope_id.empty(), "auto envelope_id empty");
    check(env.from_fingerprint == patrick.identity().fingerprint, "from_fp mismatch");
    must_void(buddy_peers.verify_envelope(env), "verify valid envelope");

    // Roundtrip through JSON and verify again (even with object keys reordered).
    const auto json_text =
        must(dump_json(envelope_to_value(env)), "dump envelope json");
    const auto parsed_val = must(parse_json(json_text), "parse envelope json");
    const auto roundtripped =
        must(envelope_from_value(parsed_val), "envelope_from_value");
    check(roundtripped == env, "envelope json roundtrip mismatch");
    must_void(buddy_peers.verify_envelope(roundtripped),
              "verify roundtripped envelope");
  }

  // Sign a baseline envelope for targeted 1-byte tamper tests.
  const auto baseline =
      must(patrick.sign_envelope(PeerEnvelopeDraft{
               "env-fixed-01",
               buddy.identity().fingerprint,
               "thread-01",
               PeerEnvelopeKind::mail,
               1730000000123456789,
               Value::object({{"subject", Value{"Stage 0 handshake"}},
                              {"body", Value{"Hello from Patrick!"}}}),
           }),
           "sign baseline envelope");
  must_void(buddy_peers.verify_envelope(baseline), "verify baseline");

  // Canonical key-ordering independence: reordering JSON object keys in
  // payload still verifies cleanly against the same canonical signature.
  {
    PeerEnvelope reordered = baseline;
    reordered.payload = Value::object({{"body", Value{"Hello from Patrick!"}},
                                       {"subject", Value{"Stage 0 handshake"}}});
    must_void(buddy_peers.verify_envelope(reordered),
              "reordered payload keys failed canonical verification");
  }

  // Tamper 1 byte of payload.
  {
    PeerEnvelope tampered = baseline;
    tampered.payload = Value::object({{"subject", Value{"Stage 0 handshake"}},
                                      {"body", Value{"Hello from Patrick?"}}});
    const auto res = buddy_peers.verify_envelope(tampered);
    check(!res.has_value() && res.error().code == ErrorCode::invalid_identity,
          "tampered payload passed verification");
  }

  // Tamper recipient.
  {
    PeerEnvelope tampered = baseline;
    tampered.to_fingerprint = "room:hijacked";
    const auto res = buddy_peers.verify_envelope(tampered);
    check(!res.has_value() && res.error().code == ErrorCode::invalid_identity,
          "tampered recipient passed verification");
  }

  // Tamper timestamp (+1 ns).
  {
    PeerEnvelope tampered = baseline;
    tampered.timestamp_ns += 1;
    const auto res = buddy_peers.verify_envelope(tampered);
    check(!res.has_value() && res.error().code == ErrorCode::invalid_identity,
          "tampered timestamp passed verification");
  }

  // Tamper sender fingerprint (swapped to another pinned key).
  {
    PeerEnvelope tampered = baseline;
    tampered.from_fingerprint = buddy.identity().fingerprint;
    const auto res = buddy_peers.verify_envelope(tampered);
    check(!res.has_value() && res.error().code == ErrorCode::invalid_identity,
          "tampered sender passed verification");
  }

  // Tamper kind / thread_id / envelope_id.
  {
    PeerEnvelope tampered = baseline;
    tampered.kind = PeerEnvelopeKind::recall;
    check(!buddy_peers.verify_envelope(tampered).has_value(),
          "tampered kind passed verification");
  }
  {
    PeerEnvelope tampered = baseline;
    tampered.thread_id = "thread-02";
    check(!buddy_peers.verify_envelope(tampered).has_value(),
          "tampered thread_id passed verification");
  }

  // Unpinned sender fails verification.
  {
    const auto mallory_env = must(mallory.sign_envelope(PeerEnvelopeDraft{
                                      "env-mallory",
                                      buddy.identity().fingerprint,
                                      "thread-01",
                                      PeerEnvelopeKind::mail,
                                      1730000000123456789,
                                      Value::object({{"msg", Value{"hi"}}}),
                                  }),
                                  "sign mallory envelope");
    const auto res = buddy_peers.verify_envelope(mallory_env);
    check(!res.has_value() && res.error().code == ErrorCode::invalid_identity,
          "unpinned sender envelope passed verification");
  }

  // Large payload (>256 KiB): valid signature passes, while syntactically corrupt
  // signature armor that causes ssh-keygen to exit before draining stdin MUST
  // classify as ErrorCode::invalid_identity (never ErrorCode::io / EPIPE).
  {
    const std::string large_body(256 * 1024, 'A');
    const auto large_env = must(patrick.sign_envelope(PeerEnvelopeDraft{
                                    "env-large-01",
                                    buddy.identity().fingerprint,
                                    "thread-large",
                                    PeerEnvelopeKind::artifact,
                                    1730000000999999999,
                                    Value::object({{"blob", Value{large_body}}}),
                                }),
                                "sign large envelope");
    must_void(buddy_peers.verify_envelope(large_env), "verify valid large envelope");

    PeerEnvelope corrupt_armor = large_env;
    corrupt_armor.signature = "-----BEGIN SSH SIGNATURE-----\n"
                              "!!!not-valid-base64-armor!!!\n"
                              "-----END SSH SIGNATURE-----\n";
    const auto corrupt_res = buddy_peers.verify_envelope(corrupt_armor);
    check(!corrupt_res.has_value() &&
              corrupt_res.error().code == ErrorCode::invalid_identity,
          "corrupt signature armor on large payload did not return invalid_identity");

    const auto direct_res = verify_detached_signature(DetachedSignatureVerification{
        patrick.identity().fingerprint,
        patrick.identity().public_key,
        large_body,
        corrupt_armor.signature,
    });
    check(
        !direct_res.has_value() &&
            direct_res.error().code == ErrorCode::invalid_identity,
        "verify_detached_signature corrupt armor on large payload != invalid_identity");
  }

  // Reject duplicate outer keys, unknown outer keys, and duplicate nested payload
  // keys in envelope_from_value to prevent last-key-wins smuggling.
  {
    Value dup_outer = envelope_to_value(baseline);
    dup_outer.object().emplace_back("to_fingerprint", Value{"room:smuggled"});
    const auto dup_res = envelope_from_value(dup_outer);
    check(!dup_res.has_value() && dup_res.error().code == ErrorCode::corrupt,
          "duplicate outer envelope key accepted");

    Value unknown_outer = envelope_to_value(baseline);
    unknown_outer.object().emplace_back("extra_field", Value{true});
    const auto unknown_res = envelope_from_value(unknown_outer);
    check(!unknown_res.has_value() && unknown_res.error().code == ErrorCode::corrupt,
          "unknown outer envelope key accepted");

    Value dup_payload = envelope_to_value(baseline);
    for (auto &[k, v] : dup_payload.object()) {
      if (k == "payload") {
        v = Value::object(
            {{"subject", Value{"first"}}, {"subject", Value{"smuggled"}}});
      }
    }
    const auto dup_payload_res = envelope_from_value(dup_payload);
    check(!dup_payload_res.has_value() &&
              dup_payload_res.error().code == ErrorCode::corrupt,
          "duplicate nested payload key accepted by envelope_from_value");
  }

  // Revoking peer rejects previously valid envelope.
  must(buddy_peers.revoke_peer({patrick.identity().fingerprint, "rotated"}),
       "revoke patrick");
  const auto revoked_res = buddy_peers.verify_envelope(baseline);
  check(!revoked_res.has_value() && revoked_res.error().code == ErrorCode::conflict,
        "revoked peer envelope passed verification");
}

void test_capability_grants_expiry_and_revocation(const std::filesystem::path &base) {
  g_stage = "capability_grants_expiry_and_revocation";
  auto patrick =
      must(PeerIdentityStore::open_or_create(base / "grant-patrick"), "create patrick");
  auto buddy =
      must(PeerIdentityStore::open_or_create(base / "grant-buddy"), "create buddy");

  auto buddy_peers =
      must(KnownPeersStore::open(base / "grant-buddy-peers"), "open buddy peers");
  must(buddy_peers.pin_peer({"patrick", patrick.identity().public_key, "grantor"}),
       "pin patrick");

  const std::int64_t issued_ns = 1730000000000000000;
  const std::int64_t expires_ns = issued_ns + 3600000000000LL; // +1 hour

  // Stage 2: Direct Support / Lend-Lease grant.
  const auto direct_grant = must(patrick.sign_grant(CapabilityGrantDraft{
                                     "grant-lend-lease-01",
                                     CapabilityGrantMode::direct_support,
                                     buddy.identity().fingerprint,
                                     "dentist-verifier",
                                     std::nullopt,
                                     25,
                                     250000,
                                     {"read_file", "run_tests"},
                                     issued_ns,
                                     expires_ns,
                                     true,
                                 }),
                                 "sign direct_support grant");

  // Stage 3: OPCON Temporary Attachment grant.
  const auto opcon_grant = must(patrick.sign_grant(CapabilityGrantDraft{
                                    "grant-opcon-01",
                                    CapabilityGrantMode::temporary_attachment,
                                    buddy.identity().fingerprint,
                                    "scout-analyst",
                                    std::string{"room:ops-bridge"},
                                    100,
                                    1000000,
                                    {"read_file", "post_board", "search_code"},
                                    issued_ns,
                                    expires_ns,
                                    true,
                                }),
                                "sign temporary_attachment grant");

  // Valid at issued_ns and mid-lease.
  must_void(buddy_peers.verify_grant(direct_grant, issued_ns),
            "verify direct grant at issued_ns");
  must_void(buddy_peers.verify_grant(direct_grant, issued_ns + 1000000),
            "verify direct grant mid-lease");
  must_void(buddy_peers.verify_grant(opcon_grant, issued_ns + 1000000),
            "verify opcon grant mid-lease");

  // JSON roundtrip preserves verifiable grant.
  const auto grant_json =
      must(dump_json(grant_to_value(opcon_grant)), "dump grant json");
  const auto roundtripped =
      must(grant_from_value(must(parse_json(grant_json), "parse grant json")),
           "grant_from_value");
  check(roundtripped == opcon_grant, "grant json roundtrip mismatch");
  must_void(buddy_peers.verify_grant(roundtripped, issued_ns + 1000000),
            "verify roundtripped grant");

  // Reject at exact expiry (now_ns == expires_at_ns) and after expiry.
  const auto at_expiry = buddy_peers.verify_grant(direct_grant, expires_ns);
  check(!at_expiry.has_value() && at_expiry.error().code == ErrorCode::stale_handle,
        "grant accepted at exact expires_at_ns");
  const auto past_expiry = buddy_peers.verify_grant(direct_grant, expires_ns + 1);
  check(!past_expiry.has_value() && past_expiry.error().code == ErrorCode::stale_handle,
        "grant accepted past expires_at_ns");
  const auto before_issue = buddy_peers.verify_grant(direct_grant, issued_ns - 1);
  check(!before_issue.has_value() &&
            before_issue.error().code == ErrorCode::invalid_range,
        "grant accepted before issued_at_ns");

  // Tampering any field of grant fails verification.
  {
    CapabilityGrant tampered = direct_grant;
    tampered.max_turns = 999;
    check(!buddy_peers.verify_grant(tampered, issued_ns + 1).has_value(),
          "tampered max_turns accepted");
  }
  {
    CapabilityGrant tampered = direct_grant;
    tampered.allowed_tools.emplace_back("shell_exec");
    check(!buddy_peers.verify_grant(tampered, issued_ns + 1).has_value(),
          "tampered allowed_tools accepted");
  }
  {
    CapabilityGrant tampered = opcon_grant;
    tampered.command_room = "room:other";
    check(!buddy_peers.verify_grant(tampered, issued_ns + 1).has_value(),
          "tampered command_room accepted");
  }

  // Invalid drafts rejected before signing.
  {
    CapabilityGrantDraft missing_room{
        "bad-opcon",
        CapabilityGrantMode::temporary_attachment,
        buddy.identity().fingerprint,
        "scout",
        std::nullopt,
        10,
        1000,
        {"read_file"},
        issued_ns,
        expires_ns,
        true,
    };
    check(!patrick.sign_grant(std::move(missing_room)).has_value(),
          "temporary_attachment without command_room accepted");
  }
  {
    CapabilityGrantDraft zero_turns{
        "bad-turns",
        CapabilityGrantMode::direct_support,
        buddy.identity().fingerprint,
        "scout",
        std::nullopt,
        0,
        1000,
        {"read_file"},
        issued_ns,
        expires_ns,
        true,
    };
    check(!patrick.sign_grant(std::move(zero_turns)).has_value(),
          "zero max_turns accepted");
  }

  // Reject duplicate outer keys and unknown outer keys in grant_from_value to
  // prevent last-key-wins smuggling (e.g. duplicate max_turns).
  {
    Value dup_grant = grant_to_value(direct_grant);
    dup_grant.object().emplace_back("max_turns", Value{Number{9999}});
    const auto dup_res = grant_from_value(dup_grant);
    check(!dup_res.has_value() && dup_res.error().code == ErrorCode::corrupt,
          "duplicate outer grant key accepted");

    Value unknown_grant = grant_to_value(direct_grant);
    unknown_grant.object().emplace_back("sudo", Value{true});
    const auto unknown_res = grant_from_value(unknown_grant);
    check(!unknown_res.has_value() && unknown_res.error().code == ErrorCode::corrupt,
          "unknown outer grant key accepted");
  }

  // Local kill-switch: revoke_grant immediately rejects direct_grant while leaving
  // opcon_grant valid, and persists across reopen.
  const auto rev_rec =
      must(buddy_peers.revoke_grant({direct_grant.grant_id, "operator recall"}),
           "revoke direct_grant");
  check(rev_rec.grant_id == direct_grant.grant_id &&
            rev_rec.reason == "operator recall",
        "revoked grant record mismatch");
  check(must(buddy_peers.is_grant_revoked(direct_grant.grant_id), "is_grant_revoked"),
        "revoked grant not reported as revoked");

  const auto revoked_direct = buddy_peers.verify_grant(direct_grant, issued_ns + 1000);
  check(!revoked_direct.has_value() &&
            revoked_direct.error().code == ErrorCode::conflict,
        "locally revoked grant passed verification");
  must_void(buddy_peers.verify_grant(opcon_grant, issued_ns + 1000),
            "non-revoked opcon grant failed after revoking another grant");

  auto reopened =
      must(KnownPeersStore::open(base / "grant-buddy-peers"), "reopen grant peers");
  check(must(reopened.is_grant_revoked(direct_grant.grant_id), "persisted revocation"),
        "grant revocation did not persist");
  check(!reopened.verify_grant(direct_grant, issued_ns + 1000).has_value(),
        "revoked grant accepted after reopen");

  // Peer revocation rejects all remaining grants from that grantor.
  must(reopened.revoke_peer({patrick.identity().fingerprint, "trust terminated"}),
       "revoke grantor peer");
  const auto revoked_peer_grant = reopened.verify_grant(opcon_grant, issued_ns + 1000);
  check(!revoked_peer_grant.has_value() &&
            revoked_peer_grant.error().code == ErrorCode::conflict,
        "grant from revoked peer passed verification");
}

void test_concurrent_identity_init(const std::filesystem::path &base) {
  g_stage = "concurrent_identity_init";
  const auto shared_dir = base / "concurrent-id";
  constexpr int kThreads = 4;
  std::vector<std::string> fingerprints(kThreads);
  std::atomic<int> failures{0};

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int i = 0; i < kThreads; ++i) {
    threads.emplace_back([&, i]() {
      auto store = PeerIdentityStore::open_or_create(shared_dir);
      if (!store.has_value()) {
        failures.fetch_add(1, std::memory_order_relaxed);
        return;
      }
      fingerprints[static_cast<std::size_t>(i)] = store.value().identity().fingerprint;
    });
  }
  for (auto &t : threads)
    t.join();

  check(failures.load() == 0, "concurrent open_or_create failed");
  for (std::size_t i = 1; i < fingerprints.size(); ++i) {
    check(!fingerprints[i].empty() && fingerprints[i] == fingerprints[0],
          "concurrent open_or_create produced divergent fingerprints");
  }
}

void test_kimi_review2_hardening(const std::filesystem::path &base) {
  g_stage = "kimi_review2_hardening";
  auto patrick =
      must(PeerIdentityStore::open_or_create(base / "k2-patrick"), "create patrick");
  auto buddy =
      must(PeerIdentityStore::open_or_create(base / "k2-buddy"), "create buddy");

  auto buddy_peers =
      must(KnownPeersStore::open(base / "k2-buddy-peers"), "open buddy peers");
  must(buddy_peers.pin_peer({"patrick", patrick.identity().public_key, "k2"}),
       "pin patrick");

  // 1. Mismatched signature_namespace must fail verification.
  {
    PeerIdentityConfig other_ns;
    other_ns.signature_namespace = "other-namespace";
    auto other_store =
        must(PeerIdentityStore::open_existing(base / "k2-patrick", other_ns),
             "open patrick with other namespace");
    const auto env_other_ns = must(other_store.sign_envelope(PeerEnvelopeDraft{
                                       "env-ns-01",
                                       buddy.identity().fingerprint,
                                       "thread-ns",
                                       PeerEnvelopeKind::mail,
                                       1730000001000000000,
                                       Value::object({{"k", Value{"v"}}}),
                                   }),
                                   "sign with other namespace");
    const auto bad_ns = buddy_peers.verify_envelope(env_other_ns);
    check(!bad_ns.has_value() && bad_ns.error().code == ErrorCode::invalid_identity,
          "mismatched signature_namespace was accepted");

    auto other_peers =
        must(KnownPeersStore::open(base / "k2-buddy-peers", other_ns), "open other ns");
    must_void(other_peers.verify_envelope(env_other_ns),
              "matching custom signature_namespace failed");
  }

  // 2. Trailing garbage after -----END SSH SIGNATURE----- must be rejected.
  {
    const auto valid_env = must(patrick.sign_envelope(PeerEnvelopeDraft{
                                    "env-armor-01",
                                    buddy.identity().fingerprint,
                                    "thread-armor",
                                    PeerEnvelopeKind::mail,
                                    1730000002000000000,
                                    Value::object({{"ok", Value{true}}}),
                                }),
                                "sign armor envelope");
    must_void(buddy_peers.verify_envelope(valid_env), "verify clean armor");

    PeerEnvelope garbage_sig = valid_env;
    garbage_sig.signature += "TRAILING-GARBAGE\n";
    const auto res = buddy_peers.verify_envelope(garbage_sig);
    check(!res.has_value() && res.error().code == ErrorCode::invalid_identity,
          "trailing armor garbage was accepted");

    const auto parsed_reject = envelope_from_value(envelope_to_value(garbage_sig));
    check(!parsed_reject.has_value() &&
              parsed_reject.error().code == ErrorCode::invalid_identity,
          "envelope_from_value accepted trailing armor garbage");
  }

  // 3. Numeric re-encoding equivalence: {"n":1e2} vs {"n":100} verify identically.
  {
    const auto sci_payload = must(parse_json(R"({"n":1e2})"), "parse 1e2");
    const auto int_payload = must(parse_json(R"({"n":100})"), "parse 100");
    const auto sci_env = must(patrick.sign_envelope(PeerEnvelopeDraft{
                                  "env-num-01",
                                  buddy.identity().fingerprint,
                                  "thread-num",
                                  PeerEnvelopeKind::decision,
                                  1730000003000000000,
                                  sci_payload,
                              }),
                              "sign 1e2 envelope");
    must_void(buddy_peers.verify_envelope(sci_env), "verify 1e2 envelope");

    PeerEnvelope reencoded = sci_env;
    reencoded.payload = int_payload;
    must_void(buddy_peers.verify_envelope(reencoded),
              "re-encoded numeric 1e2 -> 100 failed verification");
    check(must(canonical_envelope_payload(sci_env), "canon sci") ==
              must(canonical_envelope_payload(reencoded), "canon int"),
          "canonical payloads diverged for 1e2 vs 100");
  }

  // 4. IsolatedTempDir respects TMPDIR (L6).
  {
    const auto custom_tmp = base / "custom-tmpdir";
    check(::mkdir(custom_tmp.c_str(), mode_t{0700}) == 0, "mkdir custom tmpdir failed");
    const char *prev_raw = std::getenv("TMPDIR");
    const std::optional<std::string> prev =
        prev_raw != nullptr ? std::optional<std::string>{prev_raw} : std::nullopt;
    struct RestoreTmpdir {
      std::optional<std::string> prev_val;
      ~RestoreTmpdir() {
        if (prev_val.has_value())
          (void)::setenv("TMPDIR", prev_val->c_str(), 1);
        else
          (void)::unsetenv("TMPDIR");
      }
    } restore{prev};
    check(::setenv("TMPDIR", (custom_tmp.string() + "/").c_str(), 1) == 0,
          "setenv TMPDIR failed");

    const auto sig = must(patrick.sign_bytes("tmpdir-check"), "sign under TMPDIR");
    must_void(
        verify_detached_signature({patrick.identity().fingerprint,
                                   patrick.identity().public_key, "tmpdir-check", sig}),
        "verify under custom TMPDIR failed");
    // Temp dir must have been cleaned up after verify_detached_signature returned.
    check(std::filesystem::is_empty(custom_tmp),
          "IsolatedTempDir left stale directory in TMPDIR");
  }

  // 5. Concurrent verify_grant vs revoke_grant (L5): once revoke_grant completes,
  // no subsequent verify_grant may succeed, and concurrent threads never crash or
  // corrupt.
  {
    const std::int64_t issued_ns = 1730000000000000000;
    const std::int64_t expires_ns = issued_ns + 3600000000000LL;
    const auto grant = must(patrick.sign_grant(CapabilityGrantDraft{
                                "grant-race-01",
                                CapabilityGrantMode::direct_support,
                                buddy.identity().fingerprint,
                                "worker-race",
                                std::nullopt,
                                10,
                                10000,
                                {"read_file"},
                                issued_ns,
                                expires_ns,
                                true,
                            }),
                            "sign race grant");

    std::atomic<bool> start{false};
    std::atomic<bool> revoked_done{false};
    std::atomic<int> unexpected_errors{0};
    std::atomic<int> post_revoke_accepts{0};

    std::vector<std::thread> verifiers;
    for (int i = 0; i < 4; ++i) {
      verifiers.emplace_back([&]() {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (int iter = 0; iter < 6; ++iter) {
          const bool after_revoke = revoked_done.load(std::memory_order_acquire);
          const auto res = buddy_peers.verify_grant(grant, issued_ns + 100);
          if (res.has_value()) {
            if (after_revoke)
              post_revoke_accepts.fetch_add(1, std::memory_order_relaxed);
          } else if (res.error().code != ErrorCode::conflict) {
            unexpected_errors.fetch_add(1, std::memory_order_relaxed);
          }
        }
      });
    }

    std::thread revoker([&]() {
      while (!start.load(std::memory_order_acquire)) {
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
      auto rev = buddy_peers.revoke_grant({grant.grant_id, "concurrent kill"});
      if (!rev.has_value())
        unexpected_errors.fetch_add(1, std::memory_order_relaxed);
      revoked_done.store(true, std::memory_order_release);
    });

    start.store(true, std::memory_order_release);
    revoker.join();
    for (auto &t : verifiers)
      t.join();

    check(unexpected_errors.load() == 0,
          "concurrent verify_grant/revoke_grant hit unexpected error");
    check(post_revoke_accepts.load() == 0,
          "verify_grant succeeded after revoke_grant completed");
    const auto final_check = buddy_peers.verify_grant(grant, issued_ns + 100);
    check(!final_check.has_value() && final_check.error().code == ErrorCode::conflict,
          "final verify_grant after revoke did not fail with conflict");
  }
}

void test_glm53_ssh_keygen_absolute_and_minimal_env(const std::filesystem::path &base) {
  g_stage = "glm53_ssh_keygen_absolute_and_minimal_env";

  // M2a: Relative or bare ssh_keygen_executable MUST be rejected with invalid_range.
  for (const char *bad_exe : {"ssh-keygen", "./attacker-helper", "../ssh-keygen"}) {
    PeerIdentityConfig bad_cfg;
    bad_cfg.ssh_keygen_executable = bad_exe;

    const auto r1 = PeerIdentityStore::open_or_create(base / "m2-bad-id", bad_cfg);
    check(!r1.has_value() && r1.error().code == ErrorCode::invalid_range,
          "PeerIdentityStore::open_or_create accepted relative ssh_keygen_executable");

    const auto r2 = PeerIdentityStore::open_existing(base / "m2-bad-id", bad_cfg);
    check(!r2.has_value() && r2.error().code == ErrorCode::invalid_range,
          "PeerIdentityStore::open_existing accepted relative ssh_keygen_executable");

    const auto r3 = KnownPeersStore::open(base / "m2-bad-peers", bad_cfg);
    check(!r3.has_value() && r3.error().code == ErrorCode::invalid_range,
          "KnownPeersStore::open accepted relative ssh_keygen_executable");

    const auto r4 = verify_detached_signature({"bb1-00000000000000000000000000000000",
                                               "ssh-ed25519 invalid", "payload", "sig"},
                                              bad_cfg);
    check(!r4.has_value() && r4.error().code == ErrorCode::invalid_range,
          "verify_detached_signature accepted relative ssh_keygen_executable");
  }

  // M2b: Ambient ANTHROPIC_API_KEY / OPENAI_API_KEY MUST NOT be visible inside
  // the ssh-keygen child process.
  struct ScopedEnv {
    const char *key;
    std::optional<std::string> prev;
    ScopedEnv(const char *k, const char *val) : key(k) {
      if (const char *old = std::getenv(k); old != nullptr)
        prev = old;
      check(::setenv(k, val, 1) == 0, "setenv failed");
    }
    ScopedEnv(const ScopedEnv &) = delete;
    ScopedEnv &operator=(const ScopedEnv &) = delete;
    ~ScopedEnv() {
      if (prev.has_value())
        (void)::setenv(key, prev->c_str(), 1);
      else
        (void)::unsetenv(key);
    }
  };
  const ScopedEnv e1{"ANTHROPIC_API_KEY", "sk-ant-glm-m2-secret"};
  const ScopedEnv e2{"OPENAI_API_KEY", "sk-openai-glm-m2-secret"};

  const auto env_dump = base / "ssh-keygen-env.txt";
  const auto wrapper = base / "wrap-ssh-keygen.sh";
  {
    std::ofstream out{wrapper, std::ios::binary | std::ios::trunc};
    check(static_cast<bool>(out), "failed to create ssh-keygen wrapper");
    out << "#!/bin/sh\n/usr/bin/env > \"" << env_dump.string()
        << "\"\nexec /usr/bin/ssh-keygen \"$@\"\n";
  }
  check(::chmod(wrapper.c_str(), mode_t{0700}) == 0, "chmod ssh-keygen wrapper failed");

  PeerIdentityConfig wrap_cfg;
  wrap_cfg.ssh_keygen_executable = wrapper.string();
  auto store = must(PeerIdentityStore::open_or_create(base / "m2-wrap-id", wrap_cfg),
                    "open_or_create with wrapped ssh-keygen");
  const auto sig = must(store.sign_bytes("m2-secret-isolation"), "sign with wrapper");
  must_void(verify_detached_signature({store.identity().fingerprint,
                                       store.identity().public_key,
                                       "m2-secret-isolation", sig},
                                      wrap_cfg),
            "verify with wrapper");

  std::ifstream in{env_dump};
  check(static_cast<bool>(in), "failed to read ssh-keygen env dump");
  const std::string dumped{std::istreambuf_iterator<char>{in},
                           std::istreambuf_iterator<char>{}};
  check(dumped.find("ANTHROPIC_API_KEY") == std::string::npos &&
            dumped.find("OPENAI_API_KEY") == std::string::npos &&
            dumped.find("glm-m2-secret") == std::string::npos,
        "ambient API secrets leaked into ssh-keygen child process!");
  check(dumped.find("PATH=/usr/bin:/bin") != std::string::npos,
        "ssh-keygen child missing sanitized minimal PATH");
}

} // namespace

int main() {
  std::string tmpl = "/tmp/blackbird-peer-identity-test-XXXXXX";
  char *created = ::mkdtemp(tmpl.data());
  if (!created) {
    std::cerr << "mkdtemp failed: " << errno << '\n';
    return 1;
  }
  const std::filesystem::path base{created};
  struct Cleanup {
    std::filesystem::path dir;
    ~Cleanup() {
      std::error_code ec;
      (void)std::filesystem::remove_all(dir, ec);
    }
  } cleanup{base};

  try {
    test_identity_generation_and_security(base);
    test_known_peers_pinning_and_mitm_rejection(base);
    test_signed_envelopes_and_tampering(base);
    test_capability_grants_expiry_and_revocation(base);
    test_concurrent_identity_init(base);
    test_kimi_review2_hardening(base);
    test_glm53_ssh_keygen_absolute_and_minimal_env(base);
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "peer_identity_test failed at stage [" << g_stage << "]: " << ex.what()
              << '\n';
    return 1;
  }
}
