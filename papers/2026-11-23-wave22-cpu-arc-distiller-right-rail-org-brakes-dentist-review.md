# Wave 22 — CPU-ARC Auto-Distiller, Right Rail Superpowers Telemetry, Org External Guest Brakes, & Platoon 4 Integrations (`@dentist-2`)

- **Date:** 2026-11-23
- **Reviewer:** `@dentist-2` (swarm board `#387`, `#388`, `#390`)
- **Authors:** `@cpu-arc-distiller` (`#385`, `#389`), `@right-rail-org-brakes` (`#386`), Platoon 4 (`origin/work/integrations-wired` @ `cacf22c`) + coordinator integration & Linux SIGPIPE fix

## Wave 22A — CPU-ARC Auto-Distiller & Gated Turn Engine (`#387` -> `#389` -> `#390` CLEAN)

- **Findings Resolved & Empirically Re-Verified under ASan+UBSan:**
  1. JSONL `block_id` parsing (`value_as_u64`) reads exact 64-bit integers directly from `Number::storage()` / `std::from_chars` without casting arbitrary `double` to `uint64_t` (zero UBSan `float-cast-overflow` on `1e30`; exact precision on `2^53 + 1`).
  2. Persistent registry rollback & zero-pollution on `auto_compile` failure: `staging.compile_network(..., false)` pre-validates before any persistent mutation, and `rollback_persistent()` restores full preexisting `ArcFunctionRecord` snapshots (zero overwritten functions, zero leaked entry points).
  3. Non-finite (`+Inf`/`NaN`/`-Inf`) cost, tolerance, and similarity guards across JSONL parsing, `cluster_recurring_traces`, `ArcDistiller::distill`, and `ArcTurnGate::handle_turn`.
- **Gates (`#390` CLEAN):** Debug, ASan+UBSan, Release + 3/3 `libgmalloc`, `clang-format --dry-run --Werror`, `clang-tidy --warnings-as-errors='*'`: 0 warnings.

## Wave 22B — Right Rail Superpowers Telemetry & Live Org External Guest Brakes (`#388` CLEAN)

- **Gates (`#388` CLEAN on first pass):**
  - Strictly owned 9 files; 0 C `assert()`, 0 `system()`/`popen()`, 0 `NOLINT`.
  - Pure snapshot rendering & NaN/Inf/ANSI/C0/C1/BiDi safety across all 7 Right Rail tabs (`RightRailTab::superpowers` + compact `auto_context` summary preserving Priority Escalation precedence).
  - Fail-closed `parse_party_summary()` for `org_id`, `group_id`, `external_guest_account_ids` and live 2-peer iroh E2E verification of `BrakesGate::ingest_peer(..., is_external_guest=true)` clamping & `[EXT-GUEST]` tagging in `MpTuiSession`.
  - Debug, ASan+UBSan, Release, 3/3 `libgmalloc`, `clang-format`, `clang-tidy --warnings-as-errors='*'`: 0 warnings.

## Wave 22C — Platoon 4 Outbound Integrations Merge (`origin/work/integrations-wired` @ `cacf22c`)

- Merged 20,196 lines (`blackbird::net`, OAuth 2.1 `IntegrationVault`, outbound `McpClient` + BM25 Lazy Tool Router `mcp_router`, 7 Lua 5.5.1 SaaS packs `saas_pack`, `blackbird --acp` agent server, OSC 9/777/99 terminal notifications, `flake.nix`) cleanly alongside Stage 2 Embedded SQLite 3.54.1 and Wave 21/22A Native CPU-ARC (**14 native model tools total**).
- Fixed Linux `SIGPIPE` in `tests/net_http_test.cpp` mock TLS server (`std::signal(SIGPIPE, SIG_IGN)` in `main()`), verified `./scripts/rigor lint` (47/47 LuaLS + clang-format + clang-tidy: 0 findings).
