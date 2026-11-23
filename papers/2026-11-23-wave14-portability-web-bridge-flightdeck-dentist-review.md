# Wave 14 Adversarial Review Archive (`@dentist-2`) — 2026-11-23

Independent adversarial reviews conducted by `@dentist-2` on the swarm board across three parallel Wave 14 tracks prior to landing on `master` (Checkpoint #30 / release `v0.1.1`).

---

## 1. Wave 14A — Web Account Portal Approval & Secondary-Device Enrollment (`@online_portability_web`)
- **Owned files:** `include/blackbird/mp_client.hpp`, `src/mp_client.cpp`, `tests/mp_client_test.cpp`, `src/command_post_cli.cpp`, `tests/command_post_cli_test.cpp`
- **Pass 1 (`#272`) — 3 defects caught and fixed:**
  1. **[HIGH] `MpIdentityStore::install_cwt` (`src/mp_client.cpp`):** Root-capable keystore skipped local root-key signature verification when `expected_root_pubkey` was omitted and accepted a foreign `expected_root_pubkey`. **Fix (`#273`):** Derive `local_root_pk = root_signing_key()->public_key()`, reject mismatched `expected_root_pubkey` (`ErrorCode::conflict` / `MpError::cwt_issuer_mismatch`), and always verify via `verify_device_cwt()`. Added forged-CWT and foreign-root regression tests.
  2. **[MEDIUM] Copy-pasteable CLI shell quoting (`src/command_post_cli.cpp`):** Unquoted `--label` / `--authority` / `--handle` in `devices init` (`next_step`) and `devices enroll` (`install_cwt_command`) broke on spaces and created shell-injection hazards on metacharacters. **Fix (`#273`):** Added POSIX `shell_quote_arg()` and tested `--label "Work's $(id) Laptop"`.
  3. **[MEDIUM] `MpIdentityStore::open_or_init_device` (`src/mp_client.cpp`):** Pre-existing empty `0700` directory failed with `keystore_corrupt`. **Fix (`#273`):** Verify via `open_keystore_dir(dir, false)` + `fstatat(..., AT_SYMLINK_NOFOLLOW)` that all 4 keystore files are `ENOENT` before initializing, while still failing closed on partial/corrupt dirs.
- **Final verdict (`#276`): CLEAN** — `clang-format`, `build/debug`, `ctest` (`mp_client` + `command_post_cli` 2/2), 3/3 Guard Malloc, `clang-tidy` (0 warnings).

---

## 2. Wave 14C — Online P2P Party Attach Bridge (`@mp_party_bridge`)
- **Owned files:** `include/blackbird/mp_party_bridge.hpp`, `src/mp_party_bridge.cpp`, `tests/mp_party_bridge_test.cpp`, `CMakeLists.txt`
- **Pass 1 (`#277`) — 4 defects caught and fixed:**
  1. **[HIGH] `-DBLACKBIRD_HAS_IROH=0` build (`tests/mp_party_bridge_test.cpp`):** `has_any_party_json()` caused `-Werror,-Wunused-function` when built without `iroh`. **Fix (`#278`):** Guarded under `#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH` and syntax-checked `-DBLACKBIRD_HAS_IROH=0 -Wall -Wextra -Wpedantic -Werror`.
  2. **[HIGH] Local lobby forwarding anti-spoofing (`src/mp_party_bridge.cpp`):** Falling back to untrusted wire `chat->sender_handle` allowed a remote peer to spoof an active local `PartyLobbyServer` alias and inherit `verified_peer = true`. **Fix (`#278`):** Derive lobby forwarding alias strictly from authenticated `peer_metadata` keyed by TLS 1.3 RPK `sender_device_id`, falling back to `peer_<device_id>`. Added live 2-peer spoofing regression test.
  3. **[HIGH] Max-size JSON serialization & lobby truncation (`src/mp_party_bridge.cpp`):** `serialize_json_line` 1 MiB cap rejected valid max-size 1 MiB `bridge_envelope` base64 (~1.33 MiB), and `party_chat_sanitize(..., kPartyMaxMessageBytes)` appended `"..."` to produce 65,539 B (> 65,536 B lobby cap). **Fix (`#278`):** Raised `ValueLimits::bytes` to `4 MiB` and passed `kPartyMaxMessageBytes - 3U` to `party_chat_sanitize`. Verified with live 1 MiB `bridge_envelope` and 70 KiB chat E2E tests.
  4. **[LOW] 20 s fake-IP dial timeout (`tests/mp_party_bridge_test.cpp`):** Swapped deterministic dialer order in `test_sanitization_and_serialization()`, cutting suite runtime from `22.54 s` to `0.76 s`.
- **Final verdict (`#280`): CLEAN** — `clang-format`, `-DBLACKBIRD_HAS_IROH=0` syntax check, `build/debug`, `ctest` (`0.76 s`), 3/3 Guard Malloc, `clang-tidy` (0 warnings).

---

## 3. Wave 14D — Flight Deck Responsiveness & Frame-Bandwidth Optimization (`@flightdeck_perf`)
- **Owned files:** `include/blackbird/flight_deck_hero.hpp`, `src/flight_deck_hero.cpp`, `src/terminal.cpp`, `tests/flight_deck_hero_test.cpp`
- **Pass 1 (`#281`): FIRST-PASS CLEAN**
  - Verified zero new dependencies, zero C `assert()`, `raw_capture_` invariants intact.
  - Verified `encode_kitty_rgb_frame` (`f=24`, overflow-checked, 3072 B stack chunk -> 4096 B base64 chunks), `encode_truecolor_halfblock_frame` (1D span precomputation, 1:1 fast path, exact-RGB `top == bot` ASCII space coalescing), `encode_halfblock_diff` (cursor-addressed changed rows only, `0 B` on identical frames), zero-allocation `HeroParticleSystem` scratch buffers + low-energy skip + integer fixed-point scanlines, and 30 FPS (`33 ms`) input-first loop in `src/terminal.cpp` with dynamic `poll()` timeout and key-repeat PTY-flood elimination.
  - **Measured before -> after (Apple Silicon laptop, Debug):**
    - `hero_flightdeck_480x300_ms_per_frame`: `10.90 ms` -> **`6.98 ms`** (~36% faster)
    - Kitty PTY payload/frame: `769,754 B` (`480x300` `f=32`) -> **`369,512 B`** (`384x240` `f=24`, **-52% / 2.08x smaller**)
    - Half-block `180x50` PTY payload/frame (`180x100` canvas): `111,760 B` full -> **`79,126 B`** steady-state row-diff (`0 B` identical)
  - Independent checks: `clang-format`, `build/debug`, `ctest` (`terminal` + `flight_deck_hero` 2/2), 3/3 Guard Malloc, `clang-tidy` (0 warnings).
