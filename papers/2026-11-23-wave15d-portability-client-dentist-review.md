# Wave 15D Adversarial Review Archive (`@dentist-2`) — 2026-11-23

Independent adversarial review of Wave 15D (`@portability_client` — Identity Portability v1 client & 1-command Device Linking / Recovery CLI) prior to landing on `master` (Checkpoint #32 / release `v0.2.0`).

- **Owned files:** `include/blackbird/mp_client.hpp`, `src/mp_client.cpp`, `tests/mp_client_test.cpp`, `src/command_post_cli.cpp`, `tests/command_post_cli_test.cpp`
- **Pass 1 (`#295`) — 2 defects caught and fixed (`#296`):**
  1. **[HIGH] Live-server HTTP `429 rate_limited` crash during 1-command `devices link create` / `join` polling (`src/command_post_cli.cpp`):** Live `api.multiplayer.tech` enforces 0.5 req/s on `/v1/device-links/inspect` and 1.0 req/s on `/v1/device-links/poll`; `1000 ms` polling aborted immediately on 429. **Fix:** Raised default poll cadence to `2500 ms` (`create`/`inspect`) and `2000 ms` (`join`/`poll`), added exponential backoff on `ErrorCode::provider_rate_limit` (clamped to `10000 ms` and remaining deadline), and added loopback TLS 1.3 E2E regression tests injecting HTTP `429` on both `/inspect` and `/poll`.
  2. **[MEDIUM] Libc++ SSO secret stack residue in `read_secret_line_bounded()` (`src/command_post_cli.cpp`):** Moving a short (`<= 22 B`) local `std::string` left inline stack residue uncleansed. **Fix:** Pre-reserve heap storage and read directly into caller-guarded `out`, cleansing prior/error/trailing-`\r` bytes with zero local SSO stack copy.
- **Final verdict (`#297`): CLEAN**
  - Cross-checked 100% wire JSON/HTTP/keyid parity against live `multiplayer_site/server/src/index.ts` across all 6 Identity Portability v1 endpoints (`recover-lookup`, `device-links/{create,claim,inspect,approve,poll}`), including local `mpdevfp2:` fingerprint & `mp-safety-v1:` safety-number recomputation, local CWT signature/pubkey verification, and zero secrets on `argv`.
  - Independent checks: `NO_C_ASSERT`, `clang-format`, Debug + ASan/UBSan, `ctest` (`command_post_cli` + `mp_client` 2/2), 3/3 Guard Malloc, `clang-tidy` (0 warnings).
