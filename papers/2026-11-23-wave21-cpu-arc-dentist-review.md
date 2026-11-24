# Wave 21 — Blackbird Native CPU-ARC (`arXiv:2611.09891`) Adversarial Verification (`@dentist-2`)

- **Date:** 2026-11-23
- **Paper Grounding:** Peter Belcak, Greg Heinrich, Saurav Muralidharan, Shizhe Diao, Pavlo Molchanov (NVIDIA Research, Nov 2026), *CPU-ARC: Agentic Reasoning Caching for on-CPU Reasoning Reuse* (`arXiv:2611.09891`).
- **Reviewer:** `@dentist-2` (swarm board `#379`, `#381`)
- **Author:** `@superpower-cpu-arc` (swarm board `#378`, `#380`) + coordinator tool/CLI/TUI integration

## Initial Audit Findings (`#379`) — All Resolved (`#380`) & Re-Verified (`#381`)

1. **Formatting Gate (`clang-format --dry-run --Werror`)**:
   - Fixed formatting across `include/blackbird/cpu_arc.hpp`, `src/cpu_arc.cpp`, and `tests/cpu_arc_test.cpp`; exits `0`.
2. **Lua C-API `longjmp` across live C++ RAII frames on OOM**:
   - Empirically reproduced 10,815,360 bytes leaked across 20x 512 KB `arc.load` calls under a 256 KB Lua memory cap, plus `LayerPopGuard` bypass on `arc.do_` OOM.
   - Fixed by staging return values/strings on heap-owned `ArcRuntimeState` (`pending_value`, `pending_string`) before any allocating/throwing Lua C-API call, moving `luaL_tolstring` outside C++ RAII scopes, and wrapping root & `arc.do_` execution inside protected `lua_pcall` trampolines (`lua_root_trampoline`, `lua_arc_do_trampoline`, `lua_arc_compiled_frame`) with guaranteed layer unwind on error/OOM.
   - Empirically re-verified: **0 bytes leaked** (`before=801008 after=801008 delta=0`).
3. **Static DAG Compiler (`compile_network`, Section 2.2.3) Edge Cases**:
   - Replaced flat replacement spans with recursive top-down `rewrite_span` so nested `arc.load` inside `arc.do_` payloads compiles cleanly without overlapping-offset corruption.
   - Rewrote both `function semantic_function(p)` and `semantic_function = function(p)` forms and matched `arc.load` against the captured `ctx_param` rather than hardcoded `"ctx"`.
   - Synced C++ `st->layers` depth and `function_id` across `__arc_call` via a hidden 3rd argument (`lua_arc_compiled_frame`) for exact dynamic-vs-compiled narration trace parity.
   - Disambiguated compiled helper identifiers with unique per-node indices (`__arc_fn_<idx>_<sanitized>`), eliminating collisions such as `foo-bar` vs `foo_bar`.

## Final Verification Gates (`#381` CLEAN)

- Public header hygiene: zero `<lua.h>` or `<sqlite3.h>` leaks in `include/blackbird/cpu_arc.hpp`; zero C `assert()`, zero `system()`/`popen()`, zero `NOLINT`.
- Debug `cpu_arc_test`: **7/7 suites PASS (0 FD leaks)**.
- ASan+UBSan `cpu_arc_test` + adversarial OOM/sandbox probes: **7/7 suites PASS (0 FD leaks)**.
- Release `cpu_arc_test` + 3/3 `DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib`: **7/7 suites PASS (0 FD leaks)**.
- `clang-tidy --config-file=.clang-tidy --warnings-as-errors='*'`: **0 warnings**.
