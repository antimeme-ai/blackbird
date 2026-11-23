# Wave 12 Independent Adversarial Verification (`@dentist-2`) — 2026-11-23

**Scope:** Wave 12 (User-Facing `blackbird online` CLI, Interactive `/online` TUI Slash Commands & Canonical Cross-Company Safety Number)

- **Wave 12A (`@online_cli_wire`):** `src/command_post_cli.cpp`, `tests/command_post_cli_test.cpp`, `scripts/blackbird`
- **Wave 12B (`@online_tui_wire`):** `src/command_post_tui.cpp`, `tests/command_post_tui_test.cpp`
- **Wave 12C (`@safety_number_wire`):** `include/blackbird/mp_protocol.hpp`, `src/mp_protocol.cpp`, `tests/mp_protocol_test.cpp`

---

## Wave 12A — `blackbird online` CLI Subcommand

### Initial Findings (Board `#256`)
1. **HIGH — `run_online_register()` key-destruction & burned-invite hazard:** `register` called `register_account()` before verifying `state_dir` wasn't an existing keystore (`root.seed`/`device.seed`/`identity.json`), a non-directory, or an insecure-mode (`0755`) directory — risking silently clobbering an existing Ed25519 root key or burning a single-use invite before `MpIdentityStore::save()` failed.
2. **LOW — `--epoch 0` accepted in `party kick` and `party disband`.**

### Remediation & Final Verdict (Board `#257`, `#258` — **CLEAN**)
- Added `preflight_online_register_dir()` using `lstat` + `open(..., O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` + `fstat` + `fstatat(..., AT_SYMLINK_NOFOLLOW)` BEFORE keygen or network calls, failing closed on symlinks, non-directories, wrong UID/insecure perms, or existing keystore files with verified zero HTTP requests and byte-exact seed preservation.
- Rejected `--epoch 0` and `> kMaxSafeId` with exit code `2` in `party kick` and `party disband`.
- Independently verified: `clang-format --dry-run --Werror`, `command_post_cli` ctest (1.97s, full offline loopback TLS 1.3 E2E), `./scripts/blackbird online --help`, and `clang-tidy` (0 warnings).

---

## Wave 12B — Interactive `/online` & `/party online` TUI Slash Commands

### Final Verdict (Board `#254`, `#255` — **CLEAN**)
- Verified `/online` and `/party online` routing, passive `MpIdentityStore::open_existing()` (zero disk writes when unregistered or on invalid `BLACKBIRD_ONLINE_DIR`/`BLACKBIRD_ONLINE_CA_BUNDLE`/`BLACKBIRD_ONLINE_PORT`), strict UTF-8 scalar/traversal validation, `sanitize_inline()` escaping of untrusted server strings (including C1 controls), zero raw seed/join-secret leakage, and offline loopback TLS 1.3 E2E coverage.
- Coordinator added the 1-line `/online` `ChatCommand` palette entry in `src/terminal.cpp` (keeping `terminal_key_help()` untouched, verified `terminal` + `terminal_pty` PASS) and wired `mp::compute_safety_number(...)` display into `/online whoami` and `/online resolve`.
- Independently verified: `clang-format --dry-run --Werror`, `command_post_tui` ctest (PASS), and `clang-tidy` (0 warnings).

---

## Wave 12C — Canonical Cross-Company Safety Number (`mp::compute_safety_number`)

### Final Verdict (Board `#251`, `#252` — **CLEAN**)
- Exact 53-byte preimage `"mp-safety-v1:" || u64_le(account_id) || root_pubkey[32]` -> SHA-256[:20] -> 32 uppercase Crockford Base32 chars (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, zero `I/L/O/U`) in 8 groups of 4 (`XXXX-XXXX-...`, 39 chars), strictly gated by `validate_ed25519_pubkey_strict()`.
- Independently verified golden vector for `account_id = 1001` + `TEST_VECTORS.json` `root_pubkey`: `SP44-BGDF-SWJH-YXTV-ZWXT-MNGX-P342-B0TV` (published to Platoon 3 `../multiplayer_outpost` on `xplat-board` `seq #17`).
- Independently verified: `clang-format --dry-run --Werror`, `mp_protocol` ctest, and `clang-tidy` (0 warnings).
