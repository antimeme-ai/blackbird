# Wave 11 Independent Adversarial Verification (`@dentist-2`) — 2026-11-23

**Scope:** Wave 11 (Live `https://api.multiplayer.tech` Control Client, `iroh` P2P Party Session Orchestrator, Official `TEST_VECTORS.json` Interop & Outpost Pointer)

- **Wave 11A (`@mp_control_client`):** `include/blackbird/mp_client.hpp`, `src/mp_client.cpp`, `tests/mp_client_test.cpp`
- **Wave 11B (`@p2p_party_session`):** `include/blackbird/p2p_party_session.hpp`, `src/p2p_party_session.cpp`, `tests/p2p_party_session_test.cpp`
- **Wave 11C (`@mp_vectors_interop`):** `tests/mp_protocol_test.cpp`, `docs/MULTIPLAYER_OUTPOST.md`

---

## Wave 11A — TLS 1.3 + HTTP/1.1 + RFC 6455 WebSocket Control Client & Keystore

### Initial Findings (Board `#239`, `#243`)
1. **HIGH — Chunked 401 `clock_skew` & keep-alive stall in `MpControlSocket::connect()`:** non-101 WS responses passed raw chunked framing directly to JSON parsing and could stall waiting for EOF on keep-alive connections.
2. **HIGH — Backward clock skew (`401 {"error":"expired","server_now_ms":...}`):** did not trigger self-healing retry when local clock lagged behind Cloudflare edge.
3. **HIGH — Signed integer overflow UB & untrusted `/v1/health` timestamp bounds:** unchecked clock-offset arithmetic and missing `server_now_ms` range checks.
4. **HIGH — RFC 9112 framing & RFC 6455 hardening:** missing rejections for non-`chunked`/multi-coding `Transfer-Encoding`, combined `TE`+`CL`, non-`identity` `Content-Encoding`, duplicate WS upgrade headers, unsolicited `Sec-WebSocket-Extensions`, and unbounded 0-byte continuation fragment floods.
5. **MEDIUM — Keystore authority validation & secret buffer cleansing:** `open_existing()` skipped `extract_tls_hostname(authority)` and temporary JSON/wire buffers left invite secrets uncleansed.
6. **HIGH (Recheck `#243`) — Flaky `SIGPIPE` crash (exit 141) in loopback test server & Linux `SIGPIPE` gap:** OpenSSL `SSL_set_fd` writes without `MSG_NOSIGNAL` on Linux (where `SO_NOSIGPIPE` does not exist).

### Remediation & Final Verdict (Board `#242`, `#244`, `#245` — **CLEAN**)
- Reused shared HTTP/1.1 body reader for WS 401s, added backward-skew `"expired"` self-healing (preserving genuine CWT expiry), added `checked_add_i64`/`checked_sub_i64` + sane `/v1/health` bounds, enforced strict RFC 9112 TE/CE + RFC 6455 header/extension/64-fragment caps, validated keystore `authority` + cleansed secret buffers, and added thread-scoped `ScopedSigpipeGuard` for Linux plus `SO_NOSIGPIPE`/thread-masked `SIGPIPE` in the loopback test server.
- Independently verified: `clang-format --dry-run --Werror`, Clang 23.1.2 `-Werror` + ASan/UBSan (`-fno-sanitize-recover=all`) **10/10 consecutive runs PASS**, and `clang-tidy` 0 warnings.
- **Integration Catch (macOS XZone Malloc + Guard Malloc `libgmalloc`):** `mp_client_test` caught a post-move `CleanseSpanGuard` use-after-free in `register_account()` and `join_party()` (`OPENSSL_cleanse` writing to a moved-from `std::vector` heap buffer after `RawHttpRequest req` freed it — invisible to ASan because `OPENSSL_cleanse` is uninstrumented `libcrypto` assembly). Fixed by introducing `CleanseVectorGuard` bound to `req.body` after the move; re-verified clean under `DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib` and `ctest`.

---

## Wave 11B — Control-Plane ↔ `iroh` P2P Party Session Orchestrator & Locked Wire v1

### Initial Findings (Board `#238`)
1. **HIGH — Mutable `relay_policy` & `pinned_relay_url` across subsequent `apply_snapshot()` calls.**
2. **HIGH — Missing `party_epoch` `1..=kMaxSafeId` validation, ignored `snapshot.max_members`, and off-by-one 13-member overflow (omitting local self from `max_members` count).**
3. **HIGH — Existing live QUIC connection not revoked (`4403`) when a `device_pubkey` was rebound to a different `device_id`, `account_id`, or `root_pubkey`.**
4. **MEDIUM — `endpoint_descriptor_to_p2p_target()` accepted empty/invalid `relay_url`.**

### Remediation & Final Verdict (Board `#240`, `#241` — **CLEAN**)
- Locked `relay_policy_`, `pinned_relay_url_`, and `max_members_` (`2..=12`) immutable per party; enforced `party_epoch` `1..=kMaxSafeId` across all 6 lifecycle handlers and local-self-inclusive `max_members_` cap; revoked (`4403`) live QUIC connections on any `(device_id, account_id, root_pubkey)` identity rebind; enforced `mp::validate_relay_url()` in `endpoint_descriptor_to_p2p_target()`.
- Locked 4 typed little-endian binary frames (version `0x01`) over the 3 `ALPN "blackbird-mp/1"` lanes with golden hex vectors published to Platoon 3 (`../multiplayer_outpost`) on `xplat-board` (`seq #14`).
- Independently verified: `clang-format`, Clang 23.1.2 ASan/UBSan (`HAS_IROH=1` live loopback QUIC/TLS-1.3-RPK mesh & `HAS_IROH=0` stub), and `clang-tidy` (0 warnings).

---

## Wave 11C — Official `TEST_VECTORS.json` Interop & Outpost Pointer

### Final Verdict (Board `#234`, `#235` — **CLEAN**)
- Verified 100% bit-exact parity across every field of `../multiplayer_site/docs/TEST_VECTORS.json` (`keys`, `cwt_rfc8392_8747_9052_9864`, `rfc9421_post`, `rfc9421_get_query`, `endpoint_descriptors`, all 4 `mp1_frames`, `invite_hashes`) with zero discrepancies in `src/mp_protocol.cpp`.
- Added concise cross-repo interop pointer `docs/MULTIPLAYER_OUTPOST.md` (clearly marked in-flight in sibling repo `../multiplayer_outpost`).
- Independently verified: `clang-format`, `mp_protocol` ctest (1/1), and `clang-tidy` (0 warnings).
