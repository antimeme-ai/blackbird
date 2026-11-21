# Unit (3): Core Runtime & Decoupled Context Lifecycle Subplan

## Problem

Baseline audit of `master` (`da654feef05e`) and live DeepSeek v4.1-flash + Oxcart
sessions showed:

1. **Upstream sessions are tightly coupled to the durable Blackbird session**:
   - `ContextStore::pin()`, `unpin()`, `units()`, and `cut()` have zero production
     callers in `CodingEngine` (`src/coding.cpp`).
   - `context_manage` always stages proposals until workflow completion — impossible
     to shrink context mid-turn during long multi-step turns, and no concept of an
     upstream cache epoch (`prompt_cache_key` never rolls after a cut).
   - No cache-TTL / route-switch awareness: staged drops wait even when the upstream
     KV cache is already cold (e.g. 5+ minute gaps) or when switching models/providers.
   - Switching providers in a session throws `ErrorCode::unsupported` on foreign
     reasoning items (`anthropic_content` vs OpenAI `reasoning` vs `encrypted_content`).
2. **Provider error handling & streaming resilience**:
   - HTTP 400/413 context-length overflows and SSE stream errors surface as opaque
     `external_unknown` with zero recovery.
   - `response.incomplete` with `max_output_tokens` throws `ErrorCode::incomplete`
     and discards the model's partial reply.
   - Fixed 180s curl `--max-time` kills active slow-streaming reasoning models.
3. **3-body Lua ergonomics (from Oxcart traces)**:
   - Models hit sandbox errors calling `os.time()` / `os.clock()` and receive opaque
     `external_unknown (0)` instead of the actual Lua error message.

## Plan

1. **Decoupled Upstream Cache Epochs & Context Tools** (`include/blackbird/context.hpp`,
   `src/context.cpp`, `include/blackbird/coding.hpp`, `src/coding.cpp`, `src/tools.cpp`):
   - Add `ContextStore::commit_pending()` to publish a staged proposal mid-workflow
     without ending the workflow.
   - Support `apply = "now"` on `context_manage` (default remains `"staged"`), wire
     `context_pin`, `context_unpin`, and `context_units` as model tools and Lua
     `blackbird.pin/unpin/units/commit_context`.
   - Track `upstream_epoch_`, `last_provider_request_at_`, `last_provider_model_`,
     `last_provider_identity_`, and `cache_ttl_` (default 300s) on `CodingEngine`.
     Auto-flush staged context edits and roll `upstream_epoch_` for free on cold
     cache (`idle >= cache_ttl`) or route switch, updating `prompt_cache_key` to
     `<conversation>:e<epoch>` for `epoch >= 1` (keeping epoch 0 exact).
   - Project `request["input"]` per target provider identity by stripping foreign
     reasoning items without mutating `ContextStore` originals (`at_rebind = "drop_foreign"`).
2. **Typed Provider Errors, Overflow Recovery & Stream Timeout**
   (`include/blackbird/foundation.hpp`, `src/foundation.cpp`, `src/native_process.hpp`,
   `src/openai.cpp`, `src/openrouter.cpp`, `src/coding.cpp`):
   - Add `ErrorCode::provider_context_overflow`.
   - Classify HTTP 401/403 (`provider_auth`), 429 (`provider_rate_limit`), and 413 /
     overflow-body 400 (`provider_context_overflow`) in HTTP and SSE error paths.
   - On `provider_context_overflow` in `CodingEngine::request()`, commit any staged
     proposal or archive oldest unpinned non-instruction units (originals preserved),
     roll `upstream_epoch_`, rebuild wire input, and retry once.
   - Preserve valid `response.incomplete` (`incomplete_details.reason == "max_output_tokens"`
     with complete non-empty output) instead of discarding it; keep bare/corrupt
     `response.incomplete` failing with `ErrorCode::incomplete`.
   - Replace hard curl `--max-time` with `--connect-timeout 30 --speed-limit 1 --speed-time N`
     plus per-read inactivity timeout in `Child::collect()`.
3. **3-Body Lua Ergonomics** (`src/coding.cpp`):
   - Expose read-only `blackbird.now()` and safe read-only `os.time` / `os.clock` /
     `os.difftime` (zero shell/filesystem/env access).
   - Include captured Lua error message (`lua_error`) in failed `lua` tool results.

## Verification

- Direct C++ RED -> GREEN suite in `tests/context_lifecycle_unit3_test.cpp`:
  1. `mid_turn_cut_and_epoch_key`: `context_manage` with `apply="now"` commits mid-turn
     and rolls `prompt_cache_key` to `<conv>:e1`.
  2. `cold_cache_free_flush`: staged `context_manage` stays staged while cache is warm,
     and flushes automatically on cold cache (`idle >= cache_ttl`), rolling epoch.
  3. `foreign_reasoning_projection`: Anthropic and OpenAI reasoning items in the same
     `ContextStore` project cleanly to either provider without throwing, leaving originals
     intact.
  4. `overflow_recovery`: provider returning `provider_context_overflow` triggers
     automatic unpinned-unit archival + epoch rollover + successful retry, while keeping
     pinned units intact.
  5. `max_output_tokens_preserved`: OpenAI & OpenRouter SSE `response.incomplete` with
     `reason == "max_output_tokens"` preserves partial assistant message text.
  6. `lua_time_and_error_text`: `os.time()`, `os.clock()`, `blackbird.now()` work;
     `os.execute` remains `nil`; Lua runtime error returns actual error message text.
- Adversarial review + full un-bypassed pre-commit gate (`scripts/rigor check debug`).
