# Wave 13A Independent Adversarial Verification (`@dentist-2`) — 2026-11-23

**Scope:** Wave 13A (`MpPartyRuntime` Live Control-Plane WS ↔ `iroh` v1.5.0 P2P Party Runtime)

- **Files:** `include/blackbird/mp_party_runtime.hpp`, `src/mp_party_runtime.cpp`, `tests/mp_party_runtime_test.cpp`

## Initial Findings (Board `#266`)
1. **HIGH — Reconnect HTTP 401 failed to hard-teardown & `reconnect_exhausted` unused:** a device revoked while WS was offline kept retrying instead of immediately tearing down live P2P QUIC sessions.
2. **HIGH — Stale `now_s` & premature `last_effective_now_s_` floor across `HelloAckMessage` clock-skew updates:** coalesced `PartySnapshotMessage` evaluated against unadjusted pre-`HelloAck` local time.
3. **MEDIUM — Already-connected `we_dial` peer endpoint roaming skipped re-dial on `PARTY_MEMBER_UPDATED`.**
4. **LOW — Unclamped `first_ws_timeout_ms` cast & missing `force_relays` `pinned_relay_url` match check.**

## Remediation & Final Verdict (Board `#267`, `#268` — **CLEAN**)
- Non-skew `ErrorCode::provider_auth` (HTTP 401) on reconnect immediately triggers `handle_hard_teardown(kMpWsCloseDeviceRevoked)` (`4403` QUIC close); transient exhaustion emits `control_error(reconnect_exhausted)`.
- `compute_effective_now_s()` recomputes server-adjusted time per WS frame and defers monotonic clamping until `session_.has_active_party()` (verified with `-600s` skewed `HelloAck` + coalesced `PartySnapshot`).
- `sess_cfg.auto_dial = true` restores immediate re-dial on `PARTY_MEMBER_UPDATED` endpoint roaming (verified with live UDP roam + chat delivery).
- Clamps `first_ws_timeout_ms` to `INT_MAX` and rejects `force_relays` `PartySnapshotMessage` with mismatched `pinned_relay_url`.
- Independently verified: `clang-format --dry-run --Werror`, Clang 23.1.2 `-Werror` + ASan/UBSan (`HAS_IROH=1` 5/5 suites, `HAS_IROH=0` 4/4 suites), `-O2 -DNDEBUG` + **5/5 consecutive Guard Malloc (`libgmalloc`) runs**, and `clang-tidy` (0 warnings under both `HAS_IROH=1` and `0`).
