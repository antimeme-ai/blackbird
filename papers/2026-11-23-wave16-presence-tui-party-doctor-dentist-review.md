# Wave 16 Adversarial Review & Verification Report (`@dentist-2`)

**Date:** 2026-11-23
**Commit Scope:** Wave 16A (`mp_client`, `mp_social_runtime`), Wave 16B (`mp_tui_session`), Wave 16C (`doctor`), and Wave 16 CLI/TUI integration glue (`command_post_cli`, `command_post_tui`, `terminal`, `main`, `scripts/blackbird`, `CMakeLists.txt`).
**Reviewer:** `@dentist-2` (Gemini 4 Neon High), bounded 2-layer hardening protocol.

## 1. Wave 16C — `blackbird doctor` (`include/blackbird/doctor.hpp`, `src/doctor.cpp`, `tests/doctor_test.cpp`)
- **Initial Audit (`#302`):** Verified 100% passive read-only inspection (zero directory/file/lock creation), zero secret leakage, raw credential buffer cleansing, OpenSSL 3 TLS 1.3 `/ping` relay probe, `clang-format`, `clang-tidy`, ASan/UBSan, and 3/3 Guard Malloc. Found 1 HIGH defect:
  1. **Signed `int64_t` subtraction overflow (UB) on corrupt secondary-device CWT (`src/doctor.cpp:1235-1241`):** negative `iat` with `exp = INT64_MAX` could overflow `parsed->exp - parsed->iat`.
- **Remediation (`#305`) & Recheck (`#307` — CLEAN):**
  - Explicitly rejects `parsed->iat < 0` and `parsed->exp <= 0`, guards `exp - iat`, `now_s + kMaxCwtIatSkewSecs`, `exp - now_s`, and `clock_skew_ms` with `__builtin_{sub,add}_overflow`.
  - Added regression test Case E with crafted CBOR CWT (`iat = -1`, `exp = INT64_MAX`, valid `cnf`) confirming `DoctorStatus::fail` (`corrupt`) under UBSan (`-fsanitize=address,undefined -fno-sanitize-recover=all`), Release `-O2 -DNDEBUG` + 3/3 Guard Malloc, and `clang-tidy --warnings-as-errors='*'`.

## 2. Wave 16B — Live Non-Blocking Online Party TUI Session (`include/blackbird/mp_tui_session.hpp`, `src/mp_tui_session.cpp`, `tests/mp_tui_session_test.cpp`)
- **Initial Audit (`#306`):** Verified `BLACKBIRD_HAS_IROH=0` and `BLACKBIRD_HAS_IROH=1` builds, anti-spoofing (untrusted wire handles ignored; authenticated `device_id` + `mp::compute_device_fingerprint` enforced), hostile ANSI/C0/C1/BiDi sanitization, live 2-peer `iroh` v1.5.0 QUIC Mutual RPK E2E, `PartyChatPane::render()`, ASan/UBSan, 3/3 Guard Malloc, `clang-tidy`. Found 1 HIGH defect:
  1. **Cross-thread FD-reuse race between `signal_wake()`/`drain_wake()` and `stop()`/`close_wake_pipe()`:** unsynchronized load-then-`::write()`/`::read()` could race `::close()` and touch a reused descriptor.
- **Remediation (`#309`) & Recheck (`#310` — CLEAN):**
  - Added lock-free `wake_users_` atomic closing-bit (`1ULL << 63`) + active in-flight user refcount so every in-flight non-blocking `::read()`/`::write()` strictly happens-before `close_wake_pipe()` closes the FDs.
  - Added 5-round concurrent stress test (`test_concurrent_metadata_drain_and_stop_race`) hammering `update_peer_metadata()`, `drain_wake()`, `to_party_snapshot()`, and aggressive pipe FD reuse across `stop()`. Re-verified CLEAN under ASan/UBSan, `-DBLACKBIRD_HAS_IROH=0`, 3/3 Guard Malloc, and `clang-tidy --warnings-as-errors='*'`.

## 3. Wave 16A — Live Friends Presence, `SOCIAL_EVENT` WebSocket Runtime & Relay Probe (`mp_client.*`, `mp_social_runtime.*`, tests)
- **Initial Audit (`#308`):** Verified `MpSocialRuntime` step-driven `/v1/ws` lifecycle (`HELLO_ACK`, `PRESENCE_SNAPSHOT`, `PRESENCE_DELTA`, `SOCIAL_EVENT`, `PARTY_INVITE_NOTIFY`, `MP1:PING`/`PONG`, transient exponential-backoff reconnect, hard terminal stop on WS `4401` / HTTP `401`/`403`), `probe_relay()`, ASan/UBSan, 3/3 Guard Malloc, `clang-tidy`. Found 1 HIGH + 1 LOW defect:
  1. **HIGH — Live `GET /v1/friends` JSON key mismatch:** live `multiplayer_site/server/src/index.ts:1786-1806` emits `peer_handle` and `peer_root_pubkey_b64` (and omits `peer_root_pubkey_b64` on blocked edges `state == 3`).
  2. **LOW — Non-ASCII byte rejection in `parse_relay_probe_url()`:** tighten `byte == 0x7fU` to `byte >= 0x7fU`.
- **Remediation (`#311`) & Recheck (`#312` — CLEAN):**
  - `list_friends()` now parses canonical `peer_handle` and `peer_root_pubkey_b64` (with `handle`/`root_pubkey_b64` fallback aliases and fail-closed conflict rejection), computes `safety_number` locally via `compute_safety_number`, and supports blocked edges with `peer_handle` only.
  - Tightened `parse_relay_probe_url()` to reject all bytes `>= 0x7fU`.
  - Expanded regression tests and re-verified CLEAN under ASan/UBSan, Release + 3/3 Guard Malloc, and `clang-tidy --warnings-as-errors='*'`.
