# Wave 17 Adversarial Review & Verification Report (`@dentist-2`)

**Date:** 2026-11-23
**Commit Scope:** Wave 17A (`lan_party_protocol`), Wave 17B (`lan_mdns`), Wave 17C (`blackbird-p2p` + `p2p_transport`), Wave 17D (`flight_deck_hero` Turbo + `terminal`/`command_post_cli` wiring), Wave 17E (`lan_party_runtime`), and Wave 17 CLI/TUI `blackbird lan` & `/lan` glue.
**Reviewer:** `@dentist-2` (Gemini 4 Neon High), bounded 2-layer hardening protocol.

## 1. Wave 17C — Opt-In Open-Lobby Lane-0 Admission on `blackbird-p2p` (`#317` → `#318` CLEAN)
- **Scope:** `crates/blackbird-p2p/src/lib.rs`, `include/blackbird/p2p_transport.hpp`, `src/p2p_transport.cpp`, `tests/p2p_transport_test.cpp`.
- **Verification:** `bb_p2p_set_lan_open_admission` fails closed (`ErrPolicyViolation`) on `AllowRelays`/`ForceRelays` and defaults to `false`; 16-peer pending cap atomically enforced across `after_handshake`, RAII `InFlightPendingGuard`, and `peers.write()`; pending peers restricted to Lane 0 (`<= 64 KiB`) with pre-allocation `CLOSE_PROTOCOL_VIOLATION` (`4400`) on inbound Lane 1/2; `bb_p2p_allow_peer` idempotently promotes live pending peers; disabling open admission closes all pending un-allowlisted peers while preserving admitted peers. `cargo test` `11/11` PASS, `cargo clippy --all-targets -- -D warnings` 0 warnings, `ctest` `2/2` PASS, `-DBLACKBIRD_HAS_IROH=0` ASan/UBSan PASS, Release + 3/3 Guard Malloc PASS, `clang-tidy` 0 warnings.

## 2. Wave 17B — Zero-Dep mDNS Discovery & Direct `ip:port` Parser (`#320` → `#322` CLEAN)
- **Scope:** `include/blackbird/lan_mdns.hpp`, `src/lan_mdns.cpp`, `tests/lan_mdns_test.cpp`.
- **Verification:** Canonical 43-char base64url Ed25519 pubkey codec, `<= 256 B` strict TXT codec rejecting duplicate/unknown/secret keys and ANSI/BiDi bytes, RFC 6762/6763 DNS compression loop/jump-cap/OOB guards, opt-in `LanMdnsAdvertiser` & `LanMdnsScanner` opening zero sockets on construction with `TTL=0` goodbye and bounded auto-timeout shutoff (`[1, 1800]` / `[1, 60]`), strict IPv4/IPv6 `parse_lan_direct_target`. ASan/UBSan PASS, Release + 3/3 Guard Malloc PASS, `clang-tidy` 0 warnings.

## 3. Wave 17A — LAN Party Crypto, Policy Floor, Local Auth & Handshake Framing (`#319` → `#321` → `#323` → `#324` CLEAN)
- **Scope:** `include/blackbird/lan_party_protocol.hpp`, `src/lan_party_protocol.cpp`, `tests/lan_party_protocol_test.cpp`.
- **Initial Audit (`#321`) & Fixes (`#323` → `#324` CLEAN):**
  1. **HIGH — macOS `la_reply_invoke` stack UAF:** moved `cv->notify_one()` strictly inside `std::lock_guard` scope.
  2. **HIGH — Policy timeout default clobbering:** introduced `ParsedLanPolicyFile` (`std::optional<uint32_t>`) + `resolve_policy_timeout()` so user/system timeouts in `(300, 1800]` / `(15, 60]` are preserved while keeping system policy as a non-overridable upper bound.
  3. **MEDIUM — Uncleansed `seed_hex` in `Value` on reload:** replaced full-object `parse_json` with direct decoding from `CleanseVectorGuard`-protected file buffer into `mp::CleansedSeed`.
- **Verification:** Independent Python `blake3` verified bit-exact golden PIN proof `13615bcb4c8793ecbd26103a9abdeb767bfd40bdf73820116b0081319d2549c8`; `mp::compute_safety_number` parity verified; ASan/UBSan PASS, Release + 3/3 Guard Malloc PASS, `clang-tidy` 0 warnings.

## 4. Wave 17D — Flight Deck Turbo Overhaul (`#326` → `#327` CLEAN)
- **Scope:** `include/blackbird/flight_deck_hero.hpp`, `src/flight_deck_hero.cpp`, `tests/flight_deck_hero_test.cpp` (+ `src/terminal.cpp` & `src/command_post_cli.cpp` call-site wiring).
- **Verification:** Stale idle burst decay (`> 1.5s`, bounded `burst_backlog_`, `<= 8` spawns/class/frame, `kMaxParticles = 600`), forward ground scroll fix across all 3 ground renderers, bit-for-bit static background cache across all 8 themes (`1.169 -> 0.146 ms/frame` Release, `0.125 ms/frame` Guard Malloc), energy-gated blur/composite, and local Kitty POSIX shared-memory `t=s` transfer (`577,331 B -> 91 B`, ~6,300× smaller, automatic fallback over SSH/tmux). ASan/UBSan PASS, Release + 3/3 Guard Malloc PASS, `clang-tidy` 0 warnings.

## 5. Wave 17E — LAN Party Host + Joiner P2P Runtime (`#328` → `#329` → `#330` → `#331` CLEAN)
- **Scope:** `include/blackbird/lan_party_runtime.hpp`, `src/lan_party_runtime.cpp`, `tests/lan_party_runtime_test.cpp`.
- **Initial Audit (`#329`) & Fixes (`#330` → `#331` CLEAN):**
  1. **HIGH — Uncleansed Ed25519 seed in `ep_cfg.secret_key`:** wrapped with RAII `CleanseOptionalSecretGuard`.
  2. **MEDIUM — Client `policy_require_pin_` bypass against PIN-less host:** retained `policy_require_pin_` and failed closed in `handle_hello()` before trust callback / `LAN_JOIN`.
  3. **MEDIUM — Registered `account_id > 0` Safety Number mismatch:** propagated `join->account_id` / `hello.host_account_id` into `compute_lan_safety_number`.
  4. **LOW-MEDIUM — Pending-peer Slowloris:** added `kLanPendingHandshakeTimeoutSec = 15U` eviction in `LanPartyHost::pump_once()`.
- **Verification:** `-DBLACKBIRD_HAS_IROH=0` + `-DBLACKBIRD_HAS_IROH=1` Debug+ASan/UBSan PASS, Release + 3/3 Guard Malloc PASS (0 FD leaks), `clang-tidy` 0 warnings.
