# Wave 7B Independent Verification Report (`@dentist-2`, 2026-11-23)

- **Reviewer:** `@dentist-2` (independent read-only verification agent, `gemini-4-neon-high`)
- **Base Commit:** `1002607bc4da` (Checkpoint #20)
- **Target Integration:** Checkpoint #21 (`Alt+P` Party Chat split/overlay + ambient badge, `/party` lifecycle, `!cmd` cooked-TTY shell escape, concurrent `PartyDispatcher` + `PartyBridgeWatcher`, `blackbird party` CLI, Linux ASan fix in `tests/party_chat_test.cpp`)

## 1. Wave 7B-1 — Live `Alt+P` Party Chat Pane, Ambient Badge, `/party` Lifecycle & `!cmd` Shell Escape (`@party_tui_and_bang`) — 6 Findings Caught (`#168`), Remediated (`#169`), Re-verified `CLEAN` (`#170`)

- **Owned files:** `include/blackbird/terminal.hpp`, `src/terminal.cpp`, `src/command_post_tui.cpp`, `tests/command_post_tui_test.cpp`, `tests/terminal_test.cpp`
- **Caught & fixed before integration:**
  1. **High — Multi-target `/party say` silent drop:** Fixed so `PlatoonPost::to` only targets a single alias when `resolved_targets.size() == 1 && unknown_targets.empty()` (or single unknown mention); multi-target sends use `to = "all"` and preserve `parsed.target_label + " " + parsed.body`.
  2. **Medium — Startup/post-turn ambient Party badge staleness:** Added `refresh_party_passive()` at `TerminalUI::run()` startup and on `Kind::complete` (guarded by `!party_snapshot_external`).
  3. **Medium — Embedded NUL truncation in `run_interactive_bang_shell()`:** Rejected embedded `'\0'` with exit code `2`.
  4. **Low/Medium — Deferred `!cmd` draft loss:** Restored `composer.draft(std::move(result.text))` when `run_bang_shell()` defers while busy.
  5. **Medium — Unbounded `party_escape` CSI accumulation:** Capped CSI accumulation to `< 64` bytes with clear on overflow.
  6. **Low/Medium — Partial keypair `identity.lock` & plain-room `--alias` ignore:** Probed both `id_ed25519` and `id_ed25519.pub` via non-symlink regular-file checks before `PeerIdentityStore::open_existing()`, and rejected `--alias` on non-`bbjoin1:` `/party join <room>`.
- **Re-verification:** `clang-format`, Debug build, `clang-tidy` (0 warnings), 6/6 ctests (`terminal`, `command_post_tui`, `tui_snapshots`, `tui_components`, `terminal_pty_palette`, `terminal_pty_palette_capacity`).

## 2. Wave 7B-2 — Unified Onboard/Remote `PartyDispatcher` & `PartyBridgeWatcher` (`@party_dispatch_core`) — 3 Findings Caught (`#163`), Remediated (`#164`), Re-verified `CLEAN` (`#165`)

- **Owned files:** `include/blackbird/party_dispatch.hpp`, `src/party_dispatch.cpp`, `tests/party_dispatch_test.cpp`, `CMakeLists.txt`
- **Caught & fixed before integration:**
  1. **High — `std::terminate()` hazard in concurrent worker pool:** Wrapped `run_one()` in `try/catch` (`noexcept`) capturing per-target errors cleanly and added RAII `ThreadJoinGuard` + calling-thread fallback on thread creation failure.
  2. **Medium — Malformed `user@-...` SSH targets:** Hardened `validate_ssh_target()` to reject leading `-`, `user@-...`, `@host`, `user@`, `a@b@c`, whitespace, and control chars.
  3. **Medium — `identity.lock` creation in existing empty `peers_dir`:** Added `probe_existing_identity_files()` via `probe_path_nofollow()` before `PeerIdentityStore::open_existing()`.
- **Re-verification:** `clang-format`, Debug build, `clang-tidy` (0 warnings), `party_dispatch` ctest 1/1 passed (1.15s).

## 3. Wave 7B-3 — `blackbird party` CLI (`@party_cli_watch`) — `CLEAN` on First Pass (`#161`)

- **Owned files:** `src/command_post_cli.cpp`, `tests/command_post_cli_test.cpp`, `scripts/blackbird`
- **Verification:** `sh -n scripts/blackbird`, `scripts/blackbird party --help`, `clang-format`, Debug build, `clang-tidy` (0 warnings), `command_post_cli` ctest 1/1 passed (1.15s). Verified zero-dir-creation read-only `party roster`, `party leave`, `party remove-leader`, hostile `--ssh` / secret prefix rejection (exit `2`), and `0600` `.blackbird/party.json` persistence.

## 4. Linux ASan Catch (`tests/party_chat_test.cpp`)

- `scripts/check-linux --profiles debug release asan` on `wintermute` (`context/linux/run-758qzwe_`) passed 10/10 Debug, 10/10 Release, and 9/10 ASan, catching a hardcoded 55-byte length on a 45-byte string literal containing `\0` in `tests/party_chat_test.cpp:718`. Replaced with `sizeof(kEvilBody) - 1`.
