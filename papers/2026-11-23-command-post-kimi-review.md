# Command Post MCP Server & Peer Identity — Kimi Adversarial Review #2 Disposition

- **Review run:** `run-ft7h3k6q`
- **Reviewer model:** `kimi-code/k3`
- **Session:** `session_81a1b1c8-1af3-4b98-8cfb-98c7c8063905`
- **Date:** 2026-11-23
- **Scope:** `include/blackbird/mcp_server.hpp`, `src/mcp_server.cpp`, `tests/mcp_server_test.cpp`, `include/blackbird/peer_identity.hpp`, `src/peer_identity.cpp`, `tests/peer_identity_test.cpp`

## Findings and Dispositions

### M1 (Medium) — Incomplete `extra_env` denylist in `McpCommandPostServer` (`src/mcp_server.cpp`)
- **Finding:** `is_disallowed_mcp_extra_env_key` enumerated only specific `GIT_*`, `PYTHON*`, and `NODE_*` names, allowing bypasses such as `GIT_CONFIG_COUNT`, `GIT_DIR`, `HOME`, `SSH_AUTH_SOCK`, `XDG_*`, `PERL5*`, `RUBY*`, `NPM_CONFIG_*`, `JAVA_*`, `_JAVA_*`, `BASH_*`, `GNUPGHOME`, `CARGO_HOME`, `RUSTUP_HOME`, `GEM_HOME`, `GCONV_PATH`, `LOCPATH`, and `NLSPATH`.
- **Disposition:** **Fixed.** Replaced the ad-hoc exact list in `src/mcp_server.cpp` with comprehensive prefix blocking (`BLACKBIRD_PLATOON_`, `GIT_`, `LD_`, `DYLD_`, `PERL5`, `RUBY`, `NPM_CONFIG_`, `JAVA_`, `_JAVA_`, `PYTHON`, `NODE_`, `BASH_`, `XDG_`, `LUA_`), exact dangerous variable blocking (`ENV`, `BASH_ENV`, `ZDOTDIR`, `HOME`, `SSH_AUTH_SOCK`, `GNUPGHOME`, `CARGO_HOME`, `RUSTUP_HOME`, `GEM_HOME`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `IFS`, `PATH`, `CURL_HOME`, `PROMPT_COMMAND`, `SHELL`, `EDITOR`, `VISUAL`, `PAGER`, `TMPDIR`), and secret-name substring blocking (`API_KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `CREDENTIAL`, `PRIVATE_KEY`, `BEARER`).
- **Verification:** Direct tests added in `tests/mcp_server_test.cpp` asserting `invalid_arguments` rejection for `GIT_CONFIG_COUNT`, `GIT_DIR`, `GIT_WORK_TREE`, `HOME`, `SSH_AUTH_SOCK`, `XDG_CONFIG_HOME`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PERL5OPT`, `RUBYOPT`, `NPM_CONFIG_PREFIX`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `BASH_ENV`, `BASH_FUNC_x`, `ENV`, `GNUPGHOME`, `CARGO_HOME`, `RUSTUP_HOME`, `GEM_HOME`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `IFS`, and secret markers.

### L1 (Low) — Missing post-decode `extra_env` key/value syntax and NUL validation (`src/mcp_server.cpp`)
- **Finding:** Line-level UTF-8/NUL checks inspect raw JSON wire bytes before `\u0000` unescaping; decoded `extra_env` keys and values could therefore carry embedded NULs, `=`, whitespace, or control characters into `PlatoonPeerSpec::extra_env`.
- **Disposition:** **Fixed.** Added `is_valid_mcp_extra_env_key()` enforcing non-empty `^[A-Za-z_][A-Za-z0-9_]*$` (max 256 bytes) on every decoded key and `valid_utf8_no_nul()` on every decoded value in `call_platoon_peer_spawn`.
- **Verification:** Direct tests added in `tests/mcp_server_test.cpp` sending raw JSON lines containing `\u0000` in decoded `extra_env` key and value, plus empty, leading-digit, `=`, space, and newline key names, sibling prefix path `/tmp/.../peer-work2` vs `/tmp/.../peer-work`, and string JSON-RPC `id` echo.

### L5 (Low) — Concurrent `verify_grant` vs `revoke_grant` TOCTOU window (`src/peer_identity.cpp`)
- **Finding:** `KnownPeersStore::verify_grant` checked peer and local grant revocation under shared `flock`, released the lock while running `ssh-keygen -Y verify`, and returned success without re-checking revocation; a concurrent `revoke_grant` completing during verification could leave a revoked grant accepted.
- **Disposition:** **Fixed.** Extracted `check_grant_trust` in `KnownPeersStore::verify_grant` and re-acquired shared `flock` after `verify_detached_signature` succeeds to re-verify grantor existence, non-revocation, public key equality, and absence of `grant_id` from `revoked_grants`. Also tightened `validate_signature_armor` to reject any trailing garbage after `-----END SSH SIGNATURE-----`.
- **Verification:** Direct tests added in `tests/peer_identity_test.cpp` covering mismatched `signature_namespace`, trailing armor garbage, numeric re-encoding (`{"n":1e2}` vs `{"n":100}`), and concurrent multi-threaded `verify_grant`/`revoke_grant`.

### L6 (Low) — Hardcoded `/tmp/` in `IsolatedTempDir::create` (`src/peer_identity.cpp`)
- **Finding:** `IsolatedTempDir::create` hardcoded `/tmp/` instead of honoring `TMPDIR`, limiting custom isolated temp directories on macOS and sandboxed hosts.
- **Disposition:** **Fixed.** Updated `IsolatedTempDir::create` to honor non-empty `TMPDIR` (stripping trailing slashes) and fall back to `/tmp` when `TMPDIR` is unset or empty, preserving `mkdtemp` + `O_NOFOLLOW` + `fchmod(0700)` + `check_restricted`.
- **Verification:** Direct test added in `tests/peer_identity_test.cpp` setting a custom `TMPDIR` with trailing slash, verifying `sign_bytes`/`verify_detached_signature`, and asserting full RAII cleanup of the temporary directory.
