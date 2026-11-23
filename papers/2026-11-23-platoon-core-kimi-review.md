# Independent Cross-Model Adversarial Review — Native Platoon Core (2026-11-23)

- **Reviewer:** Kimi (`kimi-code/k3`, read-only `arconaut-reviewer` profile)
- **Run ID:** `context/kimi-review/run-904phwxi`
- **Session ID:** `session_ba1c145a-7efa-4caf-8328-9e662cb52914`
- **Scope:** `include/blackbird/{platoon_board,worktree_lease,platoon_runner}.hpp`,
  `src/{platoon_board,worktree_lease,platoon_runner}.cpp`,
  `tests/{platoon_board,worktree_lease,platoon_runner}_test.cpp`
- **Layer 1 Remediation:** All High (`H1`–`H2`), all Medium (`M1`–`M9`), and selected Low (`L5`, `L10`) findings fixed with direct regression tests.

## Severity Summary

- **Critical:** 0 confirmed.
- **High:** 2 (`H1`–`H2`) — both fixed and covered by direct regression tests.
- **Medium:** 9 (`M1`–`M9`) — all 9 fixed and covered by direct regression tests.
- **Low:** 10 (`L1`–`L10`) — `L5` and `L10` fixed now; remaining notes recorded below with disposition.

---

## Finding Dispositions

### High

| ID | Target | Mechanism | Disposition |
| --- | --- | --- | --- |
| **H1** | `src/platoon_runner.cpp`, `include/blackbird/platoon_runner.hpp` | `PlatoonRunner::spawn()` raced `~PlatoonRunner()` after dropping the mutex; destructor could destroy `unique_ptr<Impl>` before reader thread creation, causing UAF on raw `impl_.get()`. | **Fixed:** Switched `impl_` to `std::shared_ptr<Impl>`, captured `std::shared_ptr<Impl>` in `spawn()` and the reader thread lambda, tracked `active_spawns` drained by `~PlatoonRunner()` under `cv.wait`, and aborted/reaped in-flight spawns cleanly if `shutting_down` becomes true. Added deterministic `process_spawn_mutex`-gated concurrent spawn+destroy regression test. |
| **H2** | `src/platoon_runner.cpp`, `include/blackbird/platoon_runner.hpp` | `AcpClientSession` had no handshake or prompt deadline (allowing permanent `max_peers` slot exhaustion), and `jsonrpc_id_matches` rejected integral non-integer numeric storage (`double`/`Decimal`, e.g. `{"id": 1.0}`). | **Fixed:** Added configurable `acp_handshake_timeout_ms` (default 30s) and `acp_prompt_timeout_ms` (default 300s) to `PlatoonPeerSpec` with steady-clock stage deadlines in `AcpClientSession` and `reader_loop` poll clamping; timeout transitions cleanly to `failed` and SIGKILLs the process group. Extended `jsonrpc_id_matches` to handle `std::uint64_t`, `std::int64_t`, finite integral `double`, and integral `Decimal` (`parse_number("1.0")` produces `Decimal` in `src/value.cpp`). Added hanging handshake, hanging prompt, `{"id": 1.0}`, and 2 MiB line-overflow regression tests. |

### Medium

| ID | Target | Mechanism | Disposition |
| --- | --- | --- | --- |
| **M1** | `src/platoon_board.cpp` | `PlatoonBoard::post()` attempted one `O_RDWR|O_APPEND` followed by one `O_CREAT|O_EXCL`, returning spurious `{io, EEXIST}` on cross-process first-write races. | **Fixed:** Replaced with bounded 32-attempt open-existing / create-exclusive `open_or_create_board` loop matching `open_or_create_restricted`. Added 4-process fresh-board first-post race test across 4 rounds. |
| **M2** | `src/platoon_board.cpp`, `include/blackbird/platoon_board.hpp` | `upsert_member()` had no member count cap, allowing roster growth past 16 MiB (`kMaxRosterBytes`) to permanently brick all roster operations. | **Fixed:** Enforced `kPlatoonMaxRosterMembers = 512` on both new insertions in `upsert_member()` (updates to existing members at cap remain allowed) and `read_roster_locked()`. Added cap and update-at-cap regression tests. |
| **M3** | `src/platoon_board.cpp` | Corrupt or oversized `roster.json` permanently wedged `upsert_member()` with no recovery path. | **Fixed:** On `ErrorCode::corrupt` or `ErrorCode::capacity` under exclusive `roster.lock`, `upsert_member()` quarantines `roster.json` to `roster.corrupt.<pid>.<ns>` (with collision suffix), fsyncs the directory, and rebuilds cleanly. Added truncated-JSON and 17 MiB oversized-roster recovery tests plus a 2 MiB `board.jsonl` overflow-line recovery test. |
| **M4** | `src/worktree_lease.cpp` | A single stray or malformed `*.json` file in `.leases/` aborted `load_all_records()`, disabling `acquire()`, `list()`, and `reclaim_stale()`. | **Fixed:** `load_all_records()` collects filenames up front, skips invalid/corrupt entries during shared-lock `list()`, and quarantines them to `<file>.corrupt.<pid>.<seq>` under exclusive lock in `acquire()` and `reclaim_stale()` (explicit `status(id)` still fails with `corrupt` before quarantine). Added `rogue.json` + invalid-stem quarantine regression test. |
| **M5** | `src/worktree_lease.cpp` | `check_process_liveness()` treated `EPERM` (e.g. `owner_pid == 1` or foreign UID) as alive and did not detect PID reuse, allowing immortal leases. | **Fixed:** Rejected `owner_pid == 1` and foreign-UID `EPERM` as `dead` (reclaimable), checked same-UID ownership, zombie status, and process start time vs `created_ns` via `proc_pidinfo(PROC_PIDTBSDINFO)` on macOS and `/proc/<pid>/stat` + `/proc/stat` on Linux. Added `owner_pid = 1` and simulated PID-reuse reclaim regression tests. |
| **M6** | `src/worktree_lease.cpp` | `run_git()` inherited system config and could execute repo-local `.git/hooks/*` during `worktree add/remove`. | **Fixed:** Added `GIT_CONFIG_NOSYSTEM=1` and `-c core.hooksPath=/dev/null` to `run_git()`. Added executable `post-checkout` hook non-execution regression test. |
| **M7** | `src/platoon_runner.cpp` | External-driver allowlist forwarded `SSH_AUTH_SOCK` and sanitizer option variables (`ASAN_OPTIONS`, `LSAN_OPTIONS`, `UBSAN_OPTIONS`, `TSAN_OPTIONS`) by default. | **Fixed:** Removed `SSH_AUTH_SOCK` and all four sanitizer env vars from `is_allowlisted_external_env_key()`. Explicit opt-in via `spec.extra_env` remains supported for `SSH_AUTH_SOCK`. Added ambient blocking + explicit opt-in regression tests. |
| **M8** | `src/platoon_runner.cpp` | Rung 3 C2 metadata (`owner_actor`, `command_room`, `tool_allowlist`) was validated/snapshotted but not propagated into child environments, and `claude_code` ignored `tool_allowlist`. | **Fixed:** `build_spawn_env()` injects `BLACKBIRD_PLATOON_OWNER_ACTOR` (always), `BLACKBIRD_PLATOON_COMMAND_ROOM` (when non-empty), and `BLACKBIRD_PLATOON_TOOL_ALLOWLIST` (when non-empty), suppressing stale ambient room/allowlist values when empty. `claude_code` argv now passes `--allowedTools <allowlist>` when non-empty. Added direct env propagation, stale-suppression, and `claude_code` `--allowedTools` tests. |
| **M9** | `src/platoon_runner.cpp` | On `waitid` `ECHILD`, `reader_loop` set `reaped = true` and skipped the process-group SIGKILL sweep, leaving leaked grandchildren pinning pipes. | **Fixed:** In both the `ECHILD` branch and the `drain_deadline` sweep when `reaped` is true, issue `kill(-pid, SIGKILL)` guarded by `getpgid(pid) == pid`. Added grandchild pipe-pin and `stop(grace_ms = 0)` regression tests. |

### Low (Selected Fixes & Deferred Notes)

- **L5 (Fixed):** `WorktreeLeaseManager::open()` now creates missing `lease_root` directories iteratively with `mkdir(..., 0700)` followed by `O_NOFOLLOW` open + `fchmod(fd, 0700)` (`ensure_private_directory_tree` / `ensure_private_directory`), eliminating the umask world-readable window. Added `0700` `lstat` check and symlink-replaced worktree `status() -> conflict` test.
- **L10 (Fixed):** `validate_spec()` now lexically normalizes `working_dir` and `session_dir` before storing them in snapshots and passing them to `addchdir`/`--session`/`--session-dir`. Added normalization regression test.
- **Deferred Low Notes (`L1`–`L4`, `L6`–`L9`):**
  - `L1` (board parent dirfd pinning), `L2` (board corrupt-line counter), `L3` (O(N) `post()` tail-scan vs seq cache), `L4` (`recipient_filter` includes sender's own sent messages), `L6` (acquire rollback error logging), `L7` (`FileLock::acquire` owner/mode check inside `0700` `.leases`), `L8` (`signal_peer_group` fallback PID TOCTOU), `L9` (`resolve_path_executable` PATH trust boundary). Retained for future tranches as non-blocking low-severity follow-ups.

## Test Proposals Covered

All 12 concrete missing-test proposals from Kimi's review are now implemented as direct tests in `tests/platoon_board_test.cpp`, `tests/worktree_lease_test.cpp`, and `tests/platoon_runner_test.cpp`:
1. Concurrent `spawn()` + `~PlatoonRunner()` race (H1)
2. Hanging ACP handshake/prompt timeout + `{"id": 1.0}` double/Decimal ID (H2)
3. Multi-process first-`post()` race on a fresh nonexistent board root (M1)
4. Corrupt truncated + 17 MiB oversized `roster.json` quarantine/rebuild + 512-member cap (M2/M3)
5. Stray/corrupt `rogue.json` + invalid-stem `.leases` quarantine without blocking `list()`/`reclaim_stale()` (M4)
6. `owner_pid = 1` + simulated PID-reuse `created_ns` reclaim (M5)
7. 2 MiB overflow line on `board.jsonl` skipped cleanly
8. 2 MiB oversized single line on ACP stdout discarded via `line_overflow`
9. Grandchild pipe-pin swept within `drain_grace_ms` (M9)
10. `stop(grace_ms = 0)` immediate SIGKILL path
11. Symlink-replaced worktree `status() -> ErrorCode::conflict` + `0700` `lease_root` + disabled `post-checkout` hook (M6/L5)
12. `extra_env` `PATH` override dedupe + ambient `SSH_AUTH_SOCK`/sanitizer blocking + explicit `SSH_AUTH_SOCK` opt-in + C2 env & `--allowedTools` propagation (M7/M8/L10)
