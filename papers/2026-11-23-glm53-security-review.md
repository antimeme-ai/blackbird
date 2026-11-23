# Blackbird Native C++23 Multiplayer / Command Post — GLM 5.3 Independent Security Review & Dispositions

- **Reviewer model:** `opencode-go/glm-5.3`
- **Date:** 2026-11-23
- **Audit type:** Read-only adversarial security review
- **Scope:** 18 files (9 header/source pairs across `mcp_server`, `platoon_board`, `platoon_runner`, `worktree_lease`, `peer_identity`, `board_bridge`, `project_memory`, `command_post_cli`, `command_post_tui`; ~19,000 lines) plus `src/native_process.hpp`
- **Summary tally:** **0 Critical, 2 High, 3 Medium, 8 Low, 10 Informational**; **14 security properties verified solid**
- **Threat model audited:** Untrusted SSH/relay peers, external coding harnesses over MCP stdio (Claude Code, Codex, Pi, Antigravity, ACP), untrusted remote text rendered into prompts/TUI, local multi-process file custody, and ambient-credential/ceiling enforcement.

---

## High Findings & Dispositions

### H1 — Fail-open MCP `platoon_peer_spawn` workspace allowlist when `--allow-root` is omitted
- **Where:** `src/mcp_server.cpp` (`resolve_allowed_path`, `McpCommandPostServer::open`, `call_platoon_peer_spawn`).
- **Finding:** `normalized_allowed_roots` was populated only from explicit `allowed_workspace_roots`, and `working_root`/`session_root` were appended only when `normalized_allowed_roots` was already non-empty. When `normalized_allowed_roots` was empty, `resolve_allowed_path()` returned any validated absolute path unchanged, allowing an untrusted MCP client to spawn peers rooted at `/` or arbitrary filesystem paths.
- **Disposition:** **Fixed now.**
  - `McpCommandPostServer::open()` now unconditionally appends normalized `working_root` and `session_root` (when non-empty) to `normalized_allowed_roots`, regardless of whether `allowed_workspace_roots` was also passed.
  - `resolve_allowed_path()` now fails closed with `Result<fs::path>::failure({ErrorCode::invalid_range})` whenever `normalized_allowed_roots.empty()` — never resolving arbitrary unconstrained paths when `platoon_runner` is enabled without any workspace root.
- **Verification:** Added `test_glm53_fail_closed_allowlist_and_spawn_ceiling` in `tests/mcp_server_test.cpp` proving that `working_root`/`session_root` alone block `working_dir = "/"`, outside `working_dir`, and outside `workflow` with `forbidden_path`, while empty roots fail closed with `invalid_range`.

### H2 — Unbounded cumulative spawn/spend loop on MCP `platoon_peer_spawn` (and grant/spend-ledger wiring)
- **Where:** `include/blackbird/mcp_server.hpp`, `src/mcp_server.cpp`, `src/command_post_cli.cpp`.
- **Finding:** Concurrent spawns were capped (`max_peers <= 16`), but once peers settled the slots freed and an untrusted MCP client could loop spawn-settle-respawn indefinitely without hitting a cumulative ceiling. Additionally, `CapabilityGrant` / `SpendLedger` / `authorize_tool_call()` are currently only exercised in `blackbird bridge grant-check` against an in-memory ledger rather than persisted across processes on the MCP spawn surface.
- **Disposition:** **Mitigated now with hard cumulative spawn ceiling; multi-process durable spend-ledger & grant wiring tracked for Stage 1.**
  - Added `std::size_t max_total_spawns = 64` (`kMcpDefaultMaxTotalSpawns = 64`, hard upper limit `kMcpMaxTotalSpawnsLimit = 1024`, `0` rejected with `ErrorCode::invalid_range`) to `McpPlatoonPeerConfig` and `--max-total-spawns N` to `blackbird mcp`.
  - Tracked cumulative `total_spawns` under a mutex in `McpCommandPostServer::Impl`, reserving before `runner->spawn()` (rolling back on immediate spawn error) and refusing spawn `max_total_spawns + 1` with `ErrorCode::capacity` even after all prior peers settle. Exposed `total_spawns` and `max_total_spawns` in `platoon_peer_list`.
  - **Stage 1 design note (durable `SpendPolicy` / `BoardBridge` spend-ledger wiring):** In Stage 1, persist `SpendLedger` entries durably under the board/bridge root using the existing `flock` + atomic-append NDJSON machinery, and allow `McpCommandPostConfig` to attach an optional `SpendPolicy` + `KnownPeersStore`/`CapabilityGrant` verifier so `call_platoon_peer_spawn()` enforces cross-process per-peer turn/USD and platoon-wide USD ceilings via `authorize_tool_call()` at spawn time (recording turn attribution before launch). This is especially relevant alongside **I3** because Blackbird-driver peers inherit provider credentials.
- **Verification:** Added config-validation and settled-peer exhaustion regression tests in `tests/mcp_server_test.cpp` plus `--max-total-spawns` bounds tests in `tests/command_post_cli_test.cpp`.

---

## Medium Findings & Dispositions

### M1 — `WorktreeLeaseManager` resolved `git` via `PATH` and passed ambient secrets in `environ`
- **Where:** `include/blackbird/worktree_lease.hpp`, `src/worktree_lease.cpp`.
- **Finding:** `run_git()` invoked `posix_spawnp("git", ...)` and copied `environ` minus `GIT_*`, leaking ambient provider API keys and allowing a poisoned `PATH` entry to hijack `git`.
- **Disposition:** **Fixed now.**
  - `WorktreeLeaseManager::open()` resolves `git` once to a validated absolute regular executable path (checking `/usr/bin/git`, `/opt/homebrew/bin/git`, `/usr/local/bin/git`, or absolute `PATH` entries as fallback; optional host `git_executable` override also requires an absolute executable path).
  - `run_git()` now builds a minimal secret-free allowlist environment: `PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin`, `HOME`, `TMPDIR`, `TZ`, `LC_ALL`, `LANG`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0`, and `GIT_OPTIONAL_LOCKS=0` (for read-only commands). Zero ambient API keys reach `git`.
- **Verification:** Added `test_absolute_git_and_minimal_secret_free_env` in `tests/worktree_lease_test.cpp` proving relative `git_executable` rejection, absolute default resolution, and zero leakage of `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `DEEPSEEK_API_KEY` into the git child process.

### M2 — `ssh-keygen` subprocess inherited full `environ` and accepted relative executable paths
- **Where:** `src/peer_identity.cpp`.
- **Finding:** `validate_config()` allowed bare/relative `ssh_keygen_executable` values (enabling `PATH`/relative oracle substitution via `--ssh-keygen`), and `run_child_process()` left `child_environment` empty so `detail::Child::start()` passed `environ` verbatim with all ambient API keys.
- **Disposition:** **Fixed now.**
  - `validate_config()` now requires `std::filesystem::path{config.ssh_keygen_executable}.is_absolute()`, rejecting bare `ssh-keygen` or relative paths such as `./attacker-helper` with `ErrorCode::invalid_range`.
  - `run_child_process()` now passes an explicit minimal secret-free environment (`PATH=/usr/bin:/bin`, `HOME`, `TMPDIR`, `TZ`) so zero ambient credentials reach `ssh-keygen`.
- **Verification:** Added `test_glm53_ssh_keygen_absolute_and_minimal_env` in `tests/peer_identity_test.cpp` verifying relative-path rejection across all entry points and verifying `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` are absent from the `ssh-keygen` child environment.

### M3 — Inbound `BoardBridge` ingest performs full-log replay + per-envelope `ssh-keygen` under exclusive `flock`
- **Where:** `src/board_bridge.cpp` (`ingest_envelope_internal`, `replay_bridge_log_locked`), `src/peer_identity.cpp` (`verify_detached_signature`).
- **Finding:** Every accepted envelope from a pinned peer replays the entire `bridge.jsonl` under `LOCK_EX` after invoking `ssh-keygen`, creating O(N^2) work and unbounded log growth under sustained high-volume streaming.
- **Disposition:** **Tracked for Stage 1.** Acceptable at Stage 0 low-volume pinned-peer scale (unpinned senders are rejected before subprocess invocation). Stage 1 will add an incremental replay cursor (file size + offset with truncation detection), bounded per-window verification rate limiting, and log compaction/rotation.

---

## Low Findings & Dispositions

| ID | Summary | Disposition |
|----|---------|-------------|
| **L1** | `BoardBridge::record_receipt()` does not bind `recipient_actor` to local identity; action guard trusts unattested local receipts | **Tracked for Stage 1.** CLI already binds `recipient_actor` to local identity (`src/command_post_cli.cpp:3579`); Stage 1 harness integration will bind `included_in_request` receipts to attested model request hashes. |
| **L2** | Remote `causal_event.actor_seq` monotonicity not enforced on ingest | **Tracked for Stage 1.** Hash-based causal ordering (`causally_precedes`) is unaffected; Stage 1 will reject or flag non-monotonic remote `actor_seq` against `max_actor_seq`. |
| **L3** | Single corrupted mid-file newline-terminated line in `bridge.jsonl` aborts replay (fail-closed availability) | **Tracked for Stage 1.** Intentional fail-closed integrity posture for Stage 0 (tested by Kimi #3 M3); Stage 1 will add explicit quarantine/repair tooling so corrupted records never silently drop without operator visibility. |
| **L4** | `detect_concurrent_claims()` is O(E^3) worst-case on same-scope event sets | **Tracked for Stage 1.** Acceptable at Stage 0 scale; Stage 1 will memoize topological reachability and cap conflict reports. |
| **L5** | Reusing a caller-chosen `(from_fingerprint, envelope_id)` in `BoardBridge::send_envelope()` transmitted a duplicate that receivers silently dropped | **Fixed now.** `BoardBridge::send_envelope()` now checks `state.seen_outbound_envelopes.contains(key)` and returns `ErrorCode::conflict` before writing to the wire or log. Verified by direct regression test in `tests/board_bridge_test.cpp`. |
| **L6** | MCP server answers `tools/call` before `initialize` | **Tracked for Stage 1.** Protocol-strictness improvement (no integrity impact on single-client stdio); verify compatibility with MCP clients before enforcing strict handshake gating. |
| **L7** | TUI `/companion ask` catch-all echoed `sanitize_inline(ex.what(), 160)` to terminal | **Fixed now.** Masked raw `std::exception::what()` in `handle_companion()` (`unexpected transport error`) and outer `handle_command_post_slash()` (`unexpected internal error`) to match `src/mcp_server.cpp:1180-1184`. Verified by direct regression test in `tests/command_post_tui_test.cpp`. |
| **L8** | Residual microsecond PID TOCTOU between `verify_platoon_member_process()` and `::kill()` in `platoon stop` | **Tracked for Stage 1.** Fail-closed euid + zombie + start-time verification already eliminates stale-PID signaling in practice; Stage 1 will adopt `pidfd_open`/`pidfd_send_signal` on Linux and document the residual macOS POSIX window. |

---

## Informational Notes (I1–I10)

- **I1 — Spoofable local Platoon board attribution:** By design for same-uid local tools; TUI quotes all board text as untrusted peer data.
- **I2 — Three hand-rolled SHA-256 implementations** (`peer_identity.cpp`, `board_bridge.cpp`, `project_memory.cpp`): All three verified FIPS 180-4 correct by GLM 5.3; tracked for consolidation into one shared test-vector-pinned helper in Stage 1.
- **I3 — Blackbird-driver env inheritance vs. external-driver allowlist:** Intentional so Blackbird peers have provider credentials while external harnesses are isolated; documented alongside **H2** so operators understand a spawned Blackbird peer runs with host provider credentials.
- **I4 — 128-bit peer fingerprint (`bb1-` + 32 hex):** Adequate for the explicit pinned-peer trust model.
- **I5 — `blackbird platoon spawn` tears down child on CLI exit:** `PlatoonRunner` is process-scoped by design (persistent peers are managed by a long-lived `blackbird mcp` host or daemon).
- **I6 — Private key passed to `ssh-keygen` by path under 0700 dir + `identity.lock`:** Safe under the same-euid trust boundary.
- **I7 — `IsolatedTempDir` honors `TMPDIR` with `O_NOFOLLOW` + `fchmod(0700)` + `check_restricted`:** Verified safe under same-euid boundary.
- **I8 — `verify_envelope` does not filter recipient:** Intended broadcast/room semantics.
- **I9 — TUI `describe_transport_policy` is descriptive only:** Actual HTTP/TLS enforcement resides in `DecisionModels`.
- **I10 — Re-pinning same key updates `trust_note`:** Safe because fingerprint must match; audit trail for trust-note changes noted for Stage 1.

---

## Security Properties Verified Solid by GLM 5.3 (14/14)

1. **Substitution-proof signature canonicalization** (sorted-key canonical JSON, duplicate-key rejection, depth cap 128, type tags preventing cross-object replay).
2. **Key pinning & MITM defense** (silent key swap -> `conflict`, revoked peers rejected, strict 51-byte Ed25519 wire & canonical base64 parsing, injection-free `allowed_signers`).
3. **Revoke-vs-verify race closure** (pre- and post-subprocess revocation re-checks in `verify_grant` and `authorize_tool_call`).
4. **Local file custody** (0700 pinned dirs with `O_DIRECTORY|O_NOFOLLOW`, 0600 files, `st_nlink == 1` on private keys, atomic `O_EXCL` temp + fsync + rename + parent-dir fsync, `flock` serialization).
5. **Crash-safe append-only logs** (`!` recovery sentinel for partial tails, bounded line readers with overflow discard, idempotent replay dedup).
6. **Path traversal & symlink defenses** (`resolve_existing_prefix` rejecting `..` and dangling symlinks, component-wise `openat(O_NOFOLLOW)` in project memory, bidirectional repo/`.git` containment checks in `WorktreeLeaseManager`).
7. **Git invocation hardening** (no shell, explicit argv with `--`, `core.hooksPath=/dev/null`, strict branch/ref validation, OID validation, rollback on metadata write failure — now strengthened with M1).
8. **PID-recycling defenses** (fail-closed start-time + euid + zombie checks in `platoon stop` and `worktree_lease`; `WNOWAIT` zombie PGID pinning in `platoon_runner` / `native_process.hpp`).
9. **Terminal-injection neutralization** (`sanitize_bytes` hex-escaping C0, DEL, raw and UTF-8 C1 controls with UTF-8-safe 16 KiB bounding).
10. **Prompt-injection quarantining** (`format_quoted_peer_frame` escaping `<`/`>` as `\u003c`/`\u003e` and JSON-escaping all untrusted fields).
11. **MCP input discipline** (duplicate-key rejection, strict per-tool key allowlists, UTF-8/NUL checks, line/depth/node caps, silent notifications, host-managed credentials, masked exceptions).
12. **Ambient-secret isolation for external harnesses** (two-layer env filtering blocking loader/injection/secret-marker keys and `BLACKBIRD_PLATOON_*` spoofing — now closed across `git` and `ssh-keygen` via M1/M2).
13. **Bounds & memory safety in untrusted parsing** (underflow-safe size caps, ring-buffer arithmetic, strict UTF-8 validation).
14. **Bounded resource envelopes** (<=16 concurrent peers, <=64 default / <=1024 hard-capped cumulative MCP spawns, <=32 leases, <=512 roster members, 4 MiB line caps, 256 KiB prompts, bounded subprocess timeouts with group-kill teardown).
