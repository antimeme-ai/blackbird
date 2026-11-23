# Wave 18 Adversarial Review Report (`@dentist-2`): Adaptive Right Rail, Unified Brakes Policy & Taint Gate, and Native Kernel OS Containment

- **Date:** 2026-11-23
- **Reviewer:** `@dentist-2` (independent adversarial verifier on the Blackbird swarm board)
- **Swarm Board Trail:** `#337` (18A CLEAN), `#339 -> #343` (18B CLEAN), `#340 -> #344` (18C CLEAN)
- **Target Release:** `v0.4.0` (Checkpoint #35)

## Summary of Audited Units

### Wave 18A — Adaptive Context-Dependent Right Rail (`#337` CLEAN)
- **Files:** `include/blackbird/right_rail.hpp`, `src/right_rail.cpp`, `tests/right_rail_test.cpp`, `src/terminal.cpp`
- **Verified Invariants:**
  - Auto-dock layout activates cleanly on wide terminals (`>= 136 cols`, reserving `38..48` cols) while staying 100% hidden by default on narrow terminals (`< 136 cols`) so existing narrow-screen terminal expectations are unchanged.
  - Priority takeover elevates active Escalations / Confirmations / Operator Questions / Friend Requests / LAN Safety Numbers regardless of pinned tab, with `policy_locked` allowlist rendering (`[d] deny` / `[o] open` only; never offers `[a]`/`[s]` override on system-floor denials).
  - Passive `discover_repo_anchors()` uses `lstat`/`fstatat(AT_SYMLINK_NOFOLLOW)`, rejects symlinks on root, `docs/`, and candidate files, creates zero files/dirs, and scans only immediate files.
  - Compact Tokenomics bars & 12-sample sparklines handle `NaN`/`Inf`/negative ratios safely without UB.
  - All terminal text passes ANSI CSI/OSC, C0/C1/DEL, and BiDi stripping.

### Wave 18B — Unified Brakes Policy Engine & Immutable C++ Taint Gate (`#339 -> #343` CLEAN)
- **Files:** `include/blackbird/brakes_policy.hpp`, `src/brakes_policy.cpp`, `tests/brakes_policy_test.cpp`, `src/mp_tui_session.cpp`, `tests/mp_tui_session_test.cpp`
- **Findings Resolved in Recheck (`#339 -> #343`):**
  1. `human_gated` outside-workspace reads previously fell through to `ALLOW` under `sandboxed`; fixed to enforce `PathContainmentGuard` strictly before/alongside taint evaluation.
  2. Disjoint `[online]` `allowed_authorities` / `allowed_org_slugs` allowlists between system and user policies previously intersected to an empty vector (unrestricted); fixed to keep explicit restriction/fail-closed semantics on empty intersection.
  3. Protected policy files (`/etc/multiplayer/policy.toml`, `/etc/multiplayer/lan.toml`, `~/.config/blackbird/policy.toml`, `~/.config/blackbird/lan.toml`) are now unconditionally write-protected under `guarded+`.
- **Verified Invariants:**
  - `black-flag` YOLO mode remains zero-overhead default with verbatim `parent_env` passthrough.
  - Monotonic merge over `/etc/multiplayer/policy.toml` + backward-compatible `/etc/multiplayer/lan.toml` (`O_NOFOLLOW`, UID-0 ownership, mode check, fail-closed on tamper/syntax errors).
  - CSPRNG 16-hex nonce `[UNTRUSTED_PEER_DATA ...]` framing with BiDi/control/angle-bracket escaping.
  - `src/mp_tui_session.cpp` now separates `verified_peer = true` (TLS 1.3 Mutual RPK + CWT) from `untrusted_remote = true` (prompt-injection boundary).

### Wave 18C — Native Kernel OS Containment (`#340 -> #344` CLEAN)
- **Files:** `include/blackbird/os_sandbox.hpp`, `src/os_sandbox.cpp`, `tests/os_sandbox_test.cpp`
- **Findings Resolved in Recheck (`#340 -> #344`):**
  1. Root path `"/"` was previously accepted in `tmp_dir` and `extra_read_paths`; fixed to reject `"/"` across `workspace_root`, `tmp_dir`, and `extra_read_paths`.
  2. Linux `sandboxed` profile previously had a UDP/DNS network gap on Landlock ABI `>= 4` (which only filters TCP bind/connect); fixed by installing `seccomp-bpf` socket-family filtering (`AF_INET`/`AF_INET6`/`AF_PACKET`/`AF_NETLINK`) in BOTH `sandboxed` AND `airgap`.
- **Verified Invariants:**
  - macOS Seatbelt (`dlsym("sandbox_init")`, canonicalized `realpath()` SBPL, fails closed on init failure, zero leaked FDs).
  - Linux Landlock LSM raw syscalls (runtime ABI v1–v6 probe, sibling-enumerated `$HOME` omitting secret dirs) + `PR_SET_NO_NEW_PRIVS` + `seccomp-bpf` (`AUDIT_ARCH_X86_64`/`AARCH64`).
  - Real forked-child kernel escape tests verify writes outside workspace, reads of secret stores (`~/.ssh`, `credentials.bbm`, `.env`), and outbound sockets are genuinely denied by the OS kernel.
