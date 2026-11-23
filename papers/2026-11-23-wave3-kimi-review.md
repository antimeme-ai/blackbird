# Wave 3 Stage 0 BoardBridge, Command Post CLI & Live TUI — Kimi Adversarial Review #3 Disposition

- **Review run:** `run-hat5p5a8`
- **Reviewer model:** `kimi-code/k3`
- **Session:** `session_93b7e964-610a-41ec-a6db-eeadae979cbe`
- **Date:** 2026-11-23
- **Scope:** `include/blackbird/board_bridge.hpp`, `src/board_bridge.cpp`, `tests/board_bridge_test.cpp`, `include/blackbird/command_post_cli.hpp`, `src/command_post_cli.cpp`, `tests/command_post_cli_test.cpp`, `include/blackbird/command_post_tui.hpp`, `src/command_post_tui.cpp`, `tests/command_post_tui_test.cpp`
- **Critical findings:** None.

## Findings and Dispositions

### H1 (High) — Raw single-byte C1 (`0x80..0x9F`, incl. `0x9B` CSI) pass-through in TUI sanitization (`src/command_post_tui.cpp`)
- **Finding:** `sanitize_inline()` and `quote_untrusted_peer_text()` only hex-escaped UTF-8 C1 controls (`0xC2 0x80..0x9F`). A bare/orphan byte in `0x80..0x9F` (such as raw `0x9B` CSI) fell through the `else` branch with `seq_len = 1` and was copied verbatim to terminal output.
- **Disposition:** **Fixed.** Unified both `sanitize_inline()` and `quote_untrusted_peer_text()` onto a shared `sanitize_bytes()` helper with strict `valid_utf8_seq_len()` validation. Any ASCII control (`<0x20`), DEL (`0x7F`), bare single-byte C1 (`0x80..0x9F`), UTF-8 C1 (`0xC2 0x80..0x9F`), or invalid/truncated UTF-8 byte sequence (such as malformed lead `0xE2` preceding `0x9B`) is hex-escaped as `\xHH`, while valid multi-byte UTF-8 sequences (`▁▂█`, `é`) pass through unchanged.
- **Verification:** Direct regression test `test_c1_raw_and_utf8_sanitization_regression()` added in `tests/command_post_tui_test.cpp` verifying raw `"a\x9b""6nb"`, DEL (`0x7F`), malformed `"\xe2\x9b""6n"`, UTF-8 C1 `"\xc2\x9b"`, and valid UTF-8 `"▁▂█ café"`.

### M1 (Medium) — Action-time unread guard bypassed by empty-scope foreign events (`src/board_bridge.cpp`)
- **Finding:** `validate_causal_event_fields()` permitted empty `resource_scope`, while `scope_matches_guard()` returned `false` when `event_scope.empty()`. A foreign non-passive event (`kind="claim"`, `resource_scope=""`) could therefore be persisted without blocking `check_action_guard()`.
- **Disposition:** **Fixed.** Updated `scope_matches_guard()` to treat an empty `event_scope` as wildcard blocking whenever `!action_scope.empty()`. Passive event kinds (`receipt`, `presence`, `heartbeat`, `observation`) remain non-blocking via `is_passive_event_kind()`.
- **Verification:** Direct regression test added in `tests/board_bridge_test.cpp` confirming a signed foreign `kind="claim", resource_scope=""` event blocks `check_action_guard(bob_fp, "src/x.cpp")` until `included_in_request`, while a passive `kind="presence", resource_scope=""` event does not block.

### M2 (Medium) — Far-future presence pinning (`include/blackbird/board_bridge.hpp`, `src/board_bridge.cpp`)
- **Finding:** `presence_is_expired()` returned not-expired whenever `now_ns <= updated_ns`, allowing a peer to send `updated_ns = INT64_MAX` and pin `active_watchers()` indefinitely.
- **Disposition:** **Fixed.** Added `kBoardBridgeMaxFutureSkewNs = 60s` and `max_allowed_presence_ns()`. Clamped `updated_ns` to `wall_now_ns() + kBoardBridgeMaxFutureSkewNs` at ingest in both `BoardBridge::receive_envelope()` and `BoardBridge::record_presence()`, and updated `presence_is_expired()` to treat any record with `updated_ns < 0` or `updated_ns > now_ns + kBoardBridgeMaxFutureSkewNs` as expired (defending even against pre-existing on-disk records).
- **Verification:** Direct regression test added in `tests/board_bridge_test.cpp` with `updated_ns = INT64_MAX, ttl_ns = 1` across signed wire ingest, local `record_presence()`, and raw on-disk `bridge.jsonl` injection.

### M3 (Medium) — Corrupt `bridge.jsonl` masked as `rejected` in `pump_inbound()` (`src/board_bridge.cpp`)
- **Finding:** `pump_inbound()` propagated only `io`, `stale_handle`, and `allocation` errors from `receive_envelope()`, silently counting `ErrorCode::corrupt` from local `replay_bridge_log_locked()` as `report.rejected++`.
- **Disposition:** **Fixed.** Extracted `ingest_envelope_internal()` with explicit `IngestErrorOrigin` (`untrusted_frame` vs. `local_store`). Local store failures during `ScopedFlock::acquire`, `replay_bridge_log_locked`, or `append_records_locked` — including `ErrorCode::corrupt` — now propagate as fatal `Result<BridgePumpReport>::failure(...)` from `pump_inbound()`, while malformed incoming JSON frames, invalid signatures, and malformed embedded records still increment `report.rejected`.
- **Verification:** Direct regression test added in `tests/board_bridge_test.cpp` verifying a `\n`-terminated corrupt line in `bridge.jsonl` causes `pump_inbound()` to return `ErrorCode::corrupt`, while a bad embedded `causal_event` in an incoming signed envelope still increments `report.rejected`.

### M4 (Medium) — `authorize_tool_call` permitted unpinned grantee fingerprints (`include/blackbird/board_bridge.hpp`, `src/board_bridge.cpp`)
- **Finding:** `authorize_tool_call()` denied a grantee only if found in `known_peers` and marked revoked; an unpinned grantee fingerprint was allowed.
- **Disposition:** **Fixed.** Added optional `std::string_view local_actor_fingerprint = {}` parameter to `authorize_tool_call()`. The grantee must now be pinned and non-revoked in `known_peers`, OR (when absent from `known_peers`) equal to `local_actor_fingerprint` (allowing self-as-grantee on the local operator's machine without self-pinning). Unpinned third-party grantees are denied with `ErrorCode::conflict`.
- **Verification:** Updated `test_experiment_1_two_owner_transfer()` and added direct unpinned-grantee and unpinned-third-party-grantee denial tests in `tests/board_bridge_test.cpp`.

### M5 (Medium) — Spend ceiling attribution evasion (`include/blackbird/board_bridge.hpp`, `src/board_bridge.cpp`)
- **Finding:** `authorize_tool_call()` checked `policy.max_turns_per_peer` and `policy.max_cost_usd_per_peer` only against `turns_for_peer()`/`cost_usd_for_peer()` keyed on `requested_by_actor`, allowing callers that varied `requested_by_actor` strings under the same grant to evade per-peer policy ceilings.
- **Disposition:** **Fixed.** Added `SpendLedger::cost_usd_for_grant(grant_id)` alongside existing `turns_for_grant(grant_id)` and `tokens_for_grant(grant_id)`. `authorize_tool_call()` now enforces `policy.max_turns_per_peer` and `policy.max_cost_usd_per_peer` against BOTH per-peer attribution (`grantor_fingerprint`, `grantee_fingerprint`) AND `grant_id` totals (in addition to `grant.max_turns`, `grant.max_tokens`, and `policy.max_cost_usd_per_platoon`).
- **Verification:** Direct regression test added in `tests/board_bridge_test.cpp` recording turns with distinct spoofed `requested_by_actor` strings under one grant and verifying `ErrorCode::capacity` denial on both turn and USD ceilings.

### M6 (Medium) — `platoon stop` PID reuse and process-group blast radius (`src/command_post_cli.cpp`)
- **Finding:** `run_platoon_stop()` signaled `member.pid` (or its process group `-pid`) without checking process start-time identity, risking signaling a recycled PID or unrelated process group.
- **Disposition:** **Handled in parallel CLI slice (`@bridge_cli`).** Remediated in `src/command_post_cli.cpp` / `tests/command_post_cli_test.cpp` by checking process ownership/start-time (`proc_pidinfo` on macOS, `/proc/<pid>/stat` on Linux) before signaling and requiring explicit `--group` for process-group signals.

### M7 (Medium) — `peer verify` grant-vs-envelope type sniffing via `find("grant_id")` (`src/command_post_cli.cpp`)
- **Finding:** `run_peer_verify()` routed any JSON object containing a top-level `"grant_id"` key to grant verification, creating type confusion for envelopes carrying a spurious `"grant_id"`.
- **Disposition:** **Handled in parallel CLI slice (`@bridge_cli`).** Remediated in `src/command_post_cli.cpp` / `tests/command_post_cli_test.cpp` by requiring strict schema discrimination (`grant_from_value` only when required grant fields are present and `envelope_id` is absent).

### Additional Direct Tests Added
- **`pump_inbound()` boundary frames** (`tests/board_bridge_test.cpp`): verified exact `kBoardBridgeMaxLineBytes + '\n'` frame accepted (`accepted=1, rejected=0, incomplete_trailing_frame=false`), `kBoardBridgeMaxLineBytes + 1 + '\n'` rejected (`accepted=0, rejected=1, incomplete_trailing_frame=false`), and EOF immediately after `'\r'` (`incomplete_trailing_frame=true`, zero UB).

### Low Findings & Notes (Tracked / Deferred to Post-Stage-0)
- **L1 (O(N) full-log replay per call):** Acceptable at Stage 0 scale; log compaction/segmentation deferred to post-Stage-0 scaling tranche.
- **L2 (`detect_concurrent_claims` O(S² × V) BFS):** Acceptable at Stage 0 scale; indexed reachability deferred to post-Stage-0 scaling tranche.
- **L3 (`--prompt` 256-byte preview persisted to board roster `brief`):** Documented operational hygiene note; operators should pass secrets via environment/vault rather than `--prompt`.
- **L4 (Crash-tail record-level vs. batch-level atomicity):** Intentional append-only NDJSON design matching `PlatoonBoard` (`!` sentinel for partial trailing lines).
- **L5 (`send_envelope()` structural validation without re-verifying outbound signature):** Structural validation via `envelope_from_value()` prevents log corruption; outbound signatures are created by `PeerIdentityStore::sign_envelope()` and verified cryptographically on receive.
