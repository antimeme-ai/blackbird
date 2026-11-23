# Wave 19 Adversarial Review Report (`@dentist-2`): Zero-Dependency Model Superpowers (LSP, SQLite Workbench, Measure/Tuning Harness, Headless Neovim Tree-sitter)

- **Date:** 2026-11-23
- **Reviewer:** `@dentist-2` (independent adversarial verifier on the Blackbird swarm board)
- **Swarm Board Trail:** `#351` (19D CLEAN), `#354` (19C CLEAN), `#358 -> #361` (19B CLEAN), `#359 -> #364` (19A CLEAN)
- **Target Release:** `v0.4.0` (Checkpoint #36)

## Summary of Audited Units

### Wave 19A — Native C++23 JSON-RPC 2.0 LSP Client (`#359 -> #364` CLEAN)
- **Files:** `include/blackbird/lsp_client.hpp`, `src/lsp_client.cpp`, `tests/lsp_client_test.cpp`
- **Findings Resolved in Recheck (`#359 -> #363 -> #364`):**
  1. `read_frame()` now preserves `Content-Length` headers + partial payload bytes atomically in `recv_buf` across mid-payload read timeouts (`E_PARTIAL` regression verified).
  2. `initialize()` sends `processId: null` for consumer-only external daemon attachments (`attach_unix_socket`, `attach_tcp_loopback`, `attach_fds`) and `::getpid()` only for owned stdio children (`spawn_stdio`), preserving Blackbird's Service-Consumer boundary.
  3. `attach_fds()` enforces `O_NONBLOCK` on `read_fd` and `write_fd` so `write_all_with_deadline` cannot stall past request timeouts.
- **Verified Invariants:** UTF-8 / UTF-16 position encoding negotiation & exact surrogate-pair conversions, read-only `LspWorkspaceEditPlan` previews with zero direct disk writes, `file://` URI containment checks against `workspace_root`, server-initiated request non-deadlock (`-32601`), passive live `clangd` smoke (`encoding=utf-8`), ASan/UBSan + Release + `libgmalloc` + `clang-tidy` 0 warnings, 0 FD leaks.

### Wave 19B — Stage 1 Ephemeral Scratch & Permanent Model-Private SQLite Workbench (`#358 -> #361` CLEAN)
- **Files:** `include/blackbird/sqlite_workbench.hpp`, `src/sqlite_workbench.cpp`, `tests/sqlite_workbench_test.cpp`
- **Findings Resolved in Recheck (`#358 -> #360 -> #361`):**
  1. `lex_sql()` now preserves unescaped `string_literal` content and `is_name_token()` closes single-quoted SQLite identifier bypasses across taint tracking (`FROM 'peer_tbl'`, comma-joins), `_blackbird_taint_registry` write protection, and dangerous `PRAGMA` blocking (`PRAGMA 'writable_schema'`, `PRAGMA 'main'.'writable_schema'`), while keeping `SELECT 'ATTACH ...'` free of false positives.
  2. `ALTER TABLE <src> RENAME TO <dst>` now propagates transitive taint to `<dst>` and persists it across `model_db` reopen.
- **Verified Invariants:** Zero-shell `posix_spawn` driving `/usr/bin/sqlite3 -safe -batch -bail -json -nofollow` (clean env omitting `HOME`), `ISqliteBackend` seam ready for optional Stage 2 `sqlite3.c` amalgamation, ephemeral scratch DBs auto-destroyed on close/destructor, persistent `model_db` under `~/.local/share/blackbird/model_memory/<sha256>.db` (`0700`/`0600`/`O_NOFOLLOW`/WAL), pure C++ JSONL/CSV/lines/records bulk ingest, FTS5 + JSON1 verified, ASan/UBSan + Release + `libgmalloc` + `clang-tidy` 0 warnings, 0 FD leaks.

### Wave 19C — Native Script Measurement & Closed-Loop Tuning Harness (`#354` CLEAN)
- **Files:** `include/blackbird/measure_harness.hpp`, `src/measure_harness.cpp`, `tests/measure_harness_test.cpp`
- **Verified Invariants:** Process-group isolation (`setpgid`) + `SIGTERM -> SIGKILL` grandchild teardown before `wait4`, `CLOCK_MONOTONIC_RAW` + platform-normalized `ru_maxrss` (`bytes` macOS / `KiB*1024` Linux), lossless unfiltered `RawTrialRecord` emission adhering to `docs/INSTRUMENTATION.md`, separate pure tertiary R-7 quantile / Welford / IQR-overlap analysis, fail-fast correctness oracle gate, `TuningJournal` rollback guidance & JSON round-trip, optional Brakes env scrubbing + fail-closed OS sandbox (zero overhead under `black_flag`), ASan/UBSan + Release + `libgmalloc` + `clang-tidy` 0 warnings, 0 FD leaks, 0 zombies.

### Wave 19D — Owned C++23 MsgPack-RPC Headless Neovim & Embedded Tree-sitter AST Engine (`#351` CLEAN)
- **Files:** `include/blackbird/nvim_rpc.hpp`, `src/nvim_rpc.cpp`, `tests/nvim_rpc_test.cpp`
- **Verified Invariants:** Fuzz-hardened owned C++23 MsgPack codec (all wire types, `0xc1` rejection, `max_depth=32`, `max_bytes=16MiB`, `max_elements=65536`, pre-allocation bomb guards), bidirectional `poll(POLLOUT|POLLIN)` MsgPack-RPC v1 client driving `nvim --headless --embed --clean -n`, strict Ex allowlist + LuaJIT `setfenv` runtime sandbox blocking dynamic `vim['c'..'md']`/shell/file escapes, isolated `buftype=nofile` scratch buffers returning `vim.diff` with zero direct disk writes, live `NVIM v0.12.2` (`7` built-in Tree-sitter parsers) AST queries & scratch edits verified, ASan/UBSan + Release + `libgmalloc` + `clang-tidy` 0 warnings, 0 FD leaks, 0 zombies.
