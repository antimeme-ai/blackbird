# Opus Wave 5 Remediation & Wave 7A (`PartyChatPane`) Verification Report (`@dentist-2`, 2026-11-23)

- **Reviewer:** `@dentist-2` (independent read-only verification agent, `gemini-4-neon-high`)
- **Input Findings:** Opus Wave 5 audit (`context/wave5-findings-from-opus-2026-11-23.md`, evaluated at `d0e2e4b055ae`) + Wave 7A `PartyChatPane` core brief
- **Base Commit:** `785a5d6d878b` (Checkpoint #19)
- **Target Integration:** Checkpoint #20

## 1. Opus Wave 5 Remediation A — Command Post Model Tools (`@tools_opus_fix`) — `CLEAN` (`#148`)

- **Owned files:** `src/command_post_tools.cpp`, `tests/command_post_tools_test.cpp`
- **Verification:** `clang-format --dry-run --Werror` (0 diffs), Debug build (`command_post_tools_test`, `lua_tools_test`, `blackbird`, 0 warnings), `clang-tidy -p build/debug` (0 warnings), ctest `command_post_tools` + `lua_tools` 2/2 passed.
- **Confirmed remediations:**
  - **OpenAI strict-schema all-fields compatibility:** All actions across all 5 tools (`platoon_board`, `bridge_guard`, `project_issues`, `project_memory`, `companion_timing`) now accept unused schema keys sent as `null`/`""`/`0`/`false`/`[]` or schema defaults (`kind:"message"`, `from:"builder"`, etc.) while continuing to reject invalid values on used fields, negative/out-of-range limits, NUL bytes, and unknown keys.
  - **`companion_timing` safety floor:** `conflict_count > 0` forces `decision = "interrupt_room"` with `basis = "safety_floor_override"` and `safety_floor_applied = true`, preserving the companion's raw advisory suggestion in `companion_advisory` without allowing downgrade to `stay_quiet` or `post_artifact_note`.
  - **`bridge_guard` `receipt` fail-closed identity:** Removed silent `PeerIdentityStore::open_or_create()`; probes `peers_dir` and `id_ed25519` via `symlink_status` before `PeerIdentityStore::open_existing()`, returning structured `{recorded: false, error: "invalid_identity"}` with zero directories, keys, or lock files created when absent.
  - **`project_issues` & `project_memory` untrusted-store sanitization:** Escapes ESC/C0/DEL/raw-C1/UTF-8-C1/invalid-UTF-8/bidi overrides/`<`/`>` across all returned shared-store strings and attaches `quoted_frame` + `untrusted_shared_store: true` metadata.

## 2. Opus Wave 5 Remediation B — Stage 1->2 Relay & Checkpoints (`@relay_opus_fix`) — `CLEAN` (`#152`)

- **Owned files:** `include/blackbird/bridge_relay.hpp`, `src/bridge_relay.cpp`, `tests/bridge_relay_test.cpp`
- **Verification:** `clang-format --dry-run --Werror` (0 diffs), Debug build (`bridge_relay_test`, `command_post_cli_test`, `blackbird`, 0 warnings), `clang-tidy -p build/debug` (0 warnings), ctest `bridge_relay` + `command_post_cli` 2/2 passed (source compatibility preserved).
- **Confirmed remediations:**
  - **Atomic `resume_session` rollback:** Replay is staged into temporary state + pre-materialized `RelayResumeResult` before noexcept commit; overflow/failure leaves all existing session fields untouched.
  - **Zero silent reliable frame loss:** Tracks `contiguous_enqueued_relay_seq`, `first_dropped_relay_seq`, and `needs_resync`; suppresses post-gap reliable enqueue on overflow and rejects `ack_relay_seq` past unqueued or unpolled reliable frames (`ErrorCode::conflict`).
  - **Session takeover & sender spoofing prevention:** Replaced sequential `sess-N`/`conn-N` IDs with 128-bit `::getentropy` hex tokens (`sess-`, `conn-`, `rtok-`); bound `publish(session_id, frame, now_ns)` to a connected `peer` session matching room and `sender_fingerprint`; constant-time `resume_token` verification with rotation on every roam.
  - **Memory & session bounds:** Immutable `std::shared_ptr<const RoutedRelayFrame>` shared across room history and all recipient queues (zero ciphertext duplication), `max_room_history_bytes` (default 16 MiB) byte eviction alongside frame cap, oldest-disconnected eviction at room cap, TTL/explicit reaping, and empty-room cleanup.
  - **Checkpoint anti-rollback, invite honesty, receiver-side taint:** Added `CheckpointVerifyOptions` (`expected_room_id`, `min_checkpoint_seq`, overflow-safe `max_age_ns`/`max_future_skew_ns`, `allowed_signers`); corrected `bbjoin1:` docs to state honestly that `invite_code` is a room-join bearer credential + added `expires_ns` freshness helpers; added `derive_local_taint_for_peer_frame()` unconditionally tainting peer frames with `peer:<sender_fingerprint>`.

## 3. Wave 7A — Core Interactive `PartyChatPane` (`@party_chat_core`) — 3 Findings Caught (`#150`), Remediated (`#153`), Re-verified `CLEAN` (`#154`)

- **Owned files:** `include/blackbird/party_chat.hpp`, `src/party_chat.cpp`, `tests/party_chat_test.cpp`, `CMakeLists.txt`
- **Caught & fixed before integration:**
  - **High #1 (Fixed):** Unverified/revoked bridge peer events carrying `payload.sender_id` matching a local operator/leader alias fell back to alias lookup and spoofed `[OP]`/`[LEADER]` roles. Fixed via `find_bridge_participant_idx`: unverified/revoked peers match only by exact `by_fp` (never alias, never `local_self` or mismatched fingerprint) and stay pinned to `PartyMemberRole::bridge_peer` + `untrusted_remote = true`.
  - **High #2 (Fixed):** Unverified presence records ran `infer_role_from_string(pres.status)` and alias lookup, allowing role escalation to `operator_human` (flipping `single_operator` -> `multi_operator`) and roster overwrites. Fixed to pin unverified presence to `bridge_peer` and exact `by_fp` lookup only.
  - **Medium #3 (Fixed):** Simplified contradictory `untrusted_remote` branch to `!is_local && !verified` and removed dead `inbound_event_hashes`.
- **Re-verification:** `clang-format`, Debug build, `clang-tidy` (0 warnings), `party_chat` ctest 1/1 passed (0.05s), including direct impersonation/escalation regression tests, passive read-only `O_RDONLY | O_NOFOLLOW | O_CLOEXEC` zero-dir-creation tests, `0600` `.blackbird/party.json` secret/symlink/oversize rejection, and full ESC/C0/DEL/C1/UTF-8-C1/bidi escaping across narrow (`60x18`), wide (`120x30`), and degenerate viewports.
