# Wave 15A/B/C Adversarial Review Archive (`@dentist-2`) — 2026-11-23

Independent adversarial reviews conducted by `@dentist-2` across three parallel Wave 15 tracks prior to landing on `master` (Checkpoint #31 / release `v0.1.2`).

---

## 1. Wave 15A — Identity Portability v1 Cryptographic & Protocol Primitives (`@portability_crypto`)
- **Owned files:** `include/blackbird/mp_protocol.hpp`, `src/mp_protocol.cpp`, `tests/mp_protocol_test.cpp`
- **Pass 1 (`#288`): FIRST-PASS CLEAN**
  - Independent bit-exact verification against `multiplayer_site/docs/IDENTITY_PORTABILITY_SPEC.md` and `crates/mp-protocol/src/{crypto.rs,rfc9421.rs}`:
    - Canonical `mprk1_...` Root Recovery Key (`mprk1_000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FPD00`), pre-trim ASCII & `<= 128` checks, canonical 3-bit zero padding, constant-time 2-byte SHA-256 checksum, RAII `OPENSSL_cleanse`.
    - Canonical 128-bit `mpdevfp2:` device fingerprint (`ad1a8375-03ecc659-ad64922d-16cf6eb6`) + strict printable-ASCII `valid_device_label` (`0x20..0x7e`, `1..64` chars).
    - RFC 9421 `rec.<32hex>` and `link.<32hex>` key IDs with constant-time pubkey-hash binding on both sign & verify.
    - Portable `.mpkey` v1 (`MPKEY1\0\0`, OpenSSL 3.6 native Argon2id `v=0x13` `m=65536/t=3/p=1`, pre-allocation reader bounds `65536..524288`/`3..16`/`1..8`, AES-256-GCM 12B nonce / 16B tag, strict PEM & post-AEAD JSON validation, `OPENSSL_cleanse` guards).
  - Cross-verified bit-exact against Platoon 3 (`mp-outpost` v0.2.0, `xplat-board` `seq #29`) 172-byte `.mpkey` v1 golden container in BOTH encrypt and decrypt directions.
  - Checks: `clang-format`, Debug + ASan/UBSan, 3/3 Guard Malloc, `clang-tidy` (0 warnings).

---

## 2. Wave 15B — Friends Ergonomics Polish (`@friends_ux_polish`)
- **Owned files:** `src/command_post_cli.cpp`, `tests/command_post_cli_test.cpp`, `src/command_post_tui.cpp`, `tests/command_post_tui_test.cpp`
- **Pass 1 (`#285`): FIRST-PASS CLEAN**
  - Added `blackbird online friends accept|deny|decline <handle|account_id>` and upgraded `remove`/`block` to accept `<handle|account_id>` via `resolve_handle()` across both CLI and TUI (`/online friend ...`), with fail-closed validation before opening keystore/network and `sanitize_inline` escaping.
  - Added summary counts (`friend_count`, `pending_received_count`, `pending_sent_count`, `blocked_count`) to CLI `friends list` and surfaced incoming pending requests at the top of `/online friends` with an actionable accept/deny hint.
  - Checks: `clang-format`, `build/debug`, `ctest` (`command_post_cli` + `command_post_tui` 2/2), `clang-tidy` (0 warnings).

---

## 3. Wave 15C — Self-Upgrade Engine (`@self_upgrade`)
- **Owned files:** `include/blackbird/self_upgrade.hpp`, `src/self_upgrade.cpp`, `tests/self_upgrade_test.cpp`
- **Pass 1 (`#290`) — 5 concrete defects caught and fixed (`#291`):**
  1. **[HIGH] Linux release tarball SONAME symlinks:** Allowed ONLY intra-directory relative symlinks directly inside `<expected_stem>/lib/<name> -> <target>` (matching `scripts/install-release.sh:325-374`, validated both pre-extract and post-extract via `lstat`), while continuing to reject symlinks elsewhere, hardlinks, and special files.
  2. **[HIGH] Double-fetch TOCTOU on `release-manifest.json`:** Reused exact verified `raw_manifest_json` from `check_for_upgrade_with_raw()`.
  3. **[HIGH] Banner fallback `update_available` false positive:** Left `info.version` empty unless the banner token is a valid `v*` tag so commit-only `already_up_to_date` works cleanly.
  4. **[HIGH] Unbounded `curl` download & permissive `https://` base URL:** Added `--max-filesize` + poll-tick abort with `ErrorCode::capacity`, and rejected `?`, `#`, `@`, `..`, and empty/leading-`/`/`:` hosts in `https://` URLs.
  5. **[MEDIUM] Tar `\r` bypass & `uint64_t` progress overflow:** Rejected raw `\r` in `tar -tzf`/`-tvzf` stdout before line splitting and made percentage math overflow-safe for large `uint64_t` totals.
- **Final verdict (`#292`): CLEAN** — zero shell execution (`posix_spawn` only), zero C `assert()`, `clang-format`, Debug + ASan/UBSan (`-fno-sanitize-recover=all`), `-O2 -DNDEBUG` + 3/3 Guard Malloc, `clang-tidy --warnings-as-errors='*'` (0 warnings).
