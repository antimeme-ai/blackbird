# Wave 10 Independent Adversarial Verification (`@dentist-2`) — 2026-11-23

**Scope:** Wave 10 ("Xbox Live for Agentics" Standards-Only Cryptography & P2P Foundation)

- **Wave 10A (`@mp1_protocol_cpp`):** `include/blackbird/mp_protocol.hpp`, `src/mp_protocol.cpp`, `tests/mp_protocol_test.cpp`
- **Wave 10B (`@iroh_p2p_bridge`):** `crates/blackbird-p2p/{Cargo.toml,Cargo.lock,src/lib.rs,include/blackbird_p2p_abi.h}`, `include/blackbird/p2p_transport.hpp`, `src/p2p_transport.cpp`, `tests/p2p_transport_test.cpp`
- **Wave 10C (`@party_sock_live_wire`):** `src/command_post_cli.cpp`, `tests/command_post_cli_test.cpp`, `src/command_post_tui.cpp`, `tests/command_post_tui_test.cpp`

---

## Wave 10A — Byte-Exact C++23 `MP1` Wire Codec, RFC 9421/9530 & RFC 8392/8747 `COSE_Sign1` (`Ed25519 = -19`)

### Initial Findings (Board `#224`)
1. **CRITICAL — Off-curve & mixed-order Ed25519 pubkey acceptance:** `EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, ...)` does not decompress or check curve membership or torsion-freeness (`y=2..20` all accepted), diverging from Rust `mp-protocol` (`08ad6c1`).
2. **CRITICAL — Unauthenticated timestamp oracle:** `verify_rfc9421_request()` checked `clock_skew`/`expired` before Ed25519 signature verification.
3. **HIGH — Missing `application/json` media-type check:** `verify_rfc9421_request()` omitted strict `ct_base == "application/json"` validation.
4. **MEDIUM — Moved-from `Ed25519SigningKey::sign()`:** signing after move passed the cleansed all-zero seed to OpenSSL.

### Remediation & Final Verdict (Board `#227`, `#228` — **CLEAN**)
- Implemented RFC 8032 §5.1.3 Edwards25519 decompression + prime-order `[L]A == O` verification (`add-2008-hwcd-3`) over scoped OpenSSL 3 `BIGNUM`, matching Rust `mp-protocol` (`08ad6c1`) across `y=2..26` (9 off-curve, 15 mixed-order, 1 prime-order) and rejecting non-canonical `-0`.
- Moved `clock_skew`/`expired` checks strictly after `verify_ed25519_strict()`, added strict `is_application_json_content_type()` in signer and verifier, and added `valid_` guard failing closed with `ErrorCode::stale_handle` on moved-from keys.
- Independently verified: 100% bit-for-bit hex parity against Rust `mp-protocol` (`08ad6c1`) golden vectors (`encode_device_cwt` 200B, `EndpointDescriptor::encode`, `PartySnapshot` frame, RFC 9530 `Content-Digest`, RFC 9421 Ed25519 signature), `clang-format --dry-run --Werror`, Clang 23.1.2 Debug+ASan/UBSan (`mp_protocol_test: ALL PASSED`), and `clang-tidy` (0 warnings).

---

## Wave 10B — `iroh` v1.5.0 Rust C-ABI Staticlib & C++23 RAII `P2pEndpoint`

### Initial Findings (Board `#219`)
1. **Control-lane drop & HoL blocking behind Causal frames + unbounded lifecycle queue:** `EventQueue::push_priority` could silently drop Control frames when saturated by Causal frames, pushed Control behind Causal, and skipped length caps when `needed == 0`.
2. **Zombie QUIC connection on Stream 0 / Stream 4 EOF or reset:** unexpected stream EOF/reset/write error returned without closing `conn`, leaking half-dead peers and never emitting `PEER_DISCONNECTED`.
3. **Lost handshake rejection error & leaked half-open connection in `bb_p2p_connect_peer()`:** `endpoint.connect()` collapsed `4401`/`4403` to `ErrTransport`, and non-timeout setup errors exited without `conn.close(...)`.
4. **Unspecified / multicast / broadcast IPs accepted in `direct_addr_to_socket_addr()`.**

### Remediation & Final Verdict (Board `#222`, `#223` — **CLEAN**)
- Split `EventQueueInner` into bounded `priority` (Control/lifecycle, async backpressure, never silently dropped) and `normal` (Causal/ephemeral) deques; closed `conn` (`CLOSE_PROTOCOL_VIOLATION = 4400`) on unexpected Stream 0 / Stream 4 EOF/reset/write failure; mapped `ConnectError` rejections to `ErrNotAllowed` and closed `conn` on all setup failure paths; rejected unspecified/multicast/broadcast IPv4, IPv6, and IPv4-mapped IPv6 direct addresses.
- Independently verified: `cargo clippy --all-targets -- -D warnings` (0 warnings), `cargo test` (7/7), `cargo build --release`, `clang-format`, Clang 23.1.2 ASan/UBSan (`BLACKBIRD_HAS_IROH=1` and `0`, `p2p_transport_test: ALL PASSED`), and `clang-tidy` (`HAS_IROH=1` and `0`, 0 warnings).

---

## Wave 10C — Live `party.sock` CLI (`party serve` / `lobby-status`) & `/party` TUI Wiring

### Initial Findings (Board `#221`)
1. **UTF-8 continuation-byte false-reject & missing BiDi check:** raw-byte `0x80..0x9F` check falsely rejected valid non-ASCII UTF-8 socket paths and missed BiDi control scalars.
2. **`/party join` bypassed live `party.sock` and wrote `party.json` on disk.**
3. **Invalid `BLACKBIRD_PARTY_SOCKET` silently fell back to disk writes instead of failing closed.**
4. **Bare `/party create` failed in workspaces with leading `.`/`-`/`_`/`:` or `..`.**

### Remediation & Final Verdict (Board `#225`, `#226` — **CLEAN**)
- Added proper UTF-8 scalar decoding + C0/DEL/C1/BiDi/BOM rejection (accepting valid UTF-8 paths like `cafÉ-日` and `r-É/p.sock`), wired both plain and `bbjoin1:` `/party join` through live `party.sock` with zero `party.json` written, added fail-closed `PartyLobbyConnectState::invalid_env`, and sanitized `default_party_room_name()`.
- Independently verified: `clang-format`, `cmake --build`, `ctest` (`command_post_cli`, `command_post_tui`, `party_lobby` 3/3), and `clang-tidy` (0 warnings).
