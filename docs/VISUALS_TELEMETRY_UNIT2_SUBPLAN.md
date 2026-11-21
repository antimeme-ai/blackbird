# Unit (2): Live Visuals & Token Telemetry Subplan

## Problem

Baseline audit of `src/coding.cpp`, `src/main.cpp`, and `src/terminal.cpp` showed:
1. **Sparse, ephemeral token telemetry**:
   - `CodingEngine` only kept the last request's `usage_` object, did not track
     cumulative session token totals, request latency (`duration_ms`), time to
     first token (`ttft_ms`), `cache_write_tokens`, or model context windows.
   - `src/main.cpp` discarded `cached_tokens`, `reasoning_tokens`, and `cost`,
     forwarding only `"N in · M out"` to `TerminalUI::usage()`.
   - `TerminalUI` cleared `observed_usage` at every turn start and only rendered it
     in the post-turn summary line — leaving the operator blind to context fullness,
     cache hit %, throughput (`tok/s`), and cumulative burn while working.
2. **No live streaming progress indicator**:
   - During active provider streaming (`busy && live_provider`), the status line
     showed only `Turn Ns · Requesting...` with no indication of streamed bytes
     arriving.

## Plan

1. **Cumulative Session Telemetry & Timing (`include/blackbird/coding.hpp`,
   `src/coding.cpp`)**:
   - Add `SessionTelemetry` and `known_context_window_tokens(std::string_view model)`
     (explicitly matched models only; returns `std::nullopt` for unknown models so
     no fake window sizes are ever invented).
   - Measure request wall duration (`last_duration_ms`) and time to first streamed
     text delta (`last_ttft_ms`), extract Responses/Anthropic/Chat-Completions usage
     fields (`input_tokens`, `output_tokens`, `cached_tokens`, `cache_write_tokens`,
     `reasoning_tokens`, optional numeric `cost`), accumulate session totals, fire
     `observed_telemetry`, and expose `session_usage` + `upstream_epoch` in
     `CodingEngine::stats()`.
2. **Avionics Telemetry Rail & Formatters (`include/blackbird/terminal.hpp`,
   `src/terminal.cpp`, `src/main.cpp`)**:
   - Add `TelemetrySnapshot`, `terminal_format_tokens()`,
     `terminal_usage_summary()`, and `terminal_avionics_rail(snapshot, max_cells)`.
   - Render the colored Avionics Telemetry Rail cleanly inside the composer's bottom
     border (`╰ ctx 42.1k/128k 33% ▓▓▓░░░░░ · cache 84% · 68 tok/s · Σ 148k/9.2k · e1 ╯`)
     with zero extra vertical rows stolen from the transcript, progressive width
     degradation on narrow terminals, and threshold color coding (green <70%, amber
     70–89%, red ≥90% context; green ≥50% cache hit).
   - Keep `live_telemetry` across turns (while resetting per-turn summary text) and
     show live streamed byte progress (`Streaming 2.4 KiB`) during active streaming.
   - Wire `engine.observed_telemetry` in `src/main.cpp` to `ui.telemetry(...)` and
     richer `ui.usage(terminal_usage_summary(...))`.

## Verification

- Direct C++ RED -> GREEN suite in `tests/visuals_telemetry_unit2_test.cpp`:
  1. `token_formatting_and_window_catalog`: `terminal_format_tokens()` and
     `known_context_window_tokens()` (known models vs. honest `nullopt` for unknown).
  2. `usage_summary_formatting`: cache %, `tok/s`, reasoning tokens, cost, zero-safe
     guards.
  3. `avionics_rail_colors_and_degradation`: healthy/warn/danger context inks,
     cache hit colors, epoch badge, and strict cell-width bounds down to narrow
     columns (36, 55, 80, 120).
  4. `engine_cumulative_telemetry_and_stats`: multi-request session accumulates
     totals across requests, records `last_duration_ms`/`last_ttft_ms`, tracks
     `upstream_epoch`, handles Anthropic/OpenAI/OpenRouter usage shapes, and exposes
     `session_usage` in `engine.stats()`.
- Adversarial review + full un-bypassed pre-commit gate (`scripts/rigor check debug`).
