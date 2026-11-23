# Wave 20 Adversarial Review Report (`@dentist-2`): Zero-Dependency `.ipynb` Notebook Engine & Service-Consumer Jupyter Kernel Client

- **Date:** 2026-11-23
- **Reviewer:** `@dentist-2` (independent adversarial verifier on the Blackbird swarm board)
- **Swarm Board Trail:** `#368 -> #369 -> #370 -> #371` (CLEAN)
- **Target Release:** `v0.4.0` (Checkpoint #37)

## Summary of Audited Unit

- **Files:** `include/blackbird/jupyter_notebook.hpp`, `src/jupyter_notebook.cpp`, `tests/jupyter_notebook_test.cpp`
- **Findings Resolved in Recheck (`#369 -> #370 -> #371`):**
  1. `send_rest` and `execute_code` now compute `host_hdr` once and pre-reserve exact upper-bound buffer capacities before appending `api_token`, eliminating any post-token heap reallocation that could leave uncleansed token copies in freed memory prior to `CleanseStringGuard` `OPENSSL_cleanse`.
  2. `resolve_jupyter_executable()` now rejects non-absolute `PATH` entries (`dir.front() != '/'`) with a direct regression test preventing untrusted `./jupyter` execution from repo CWD, and `make_cloexec_pipe()` moves pipe ends above `STDERR_FILENO` via `F_DUPFD_CLOEXEC`.
- **Verified Invariants:**
  - Pure C++23 `.ipynb` (nbformat v4.x -> canonical v4.5) structural parser, cell editor, and serializer with zero disk writes; preserves raw outputs verbatim while stripping ANSI/control noise and summarizing large base64 image/binary MIME bundles for model context hygiene.
  - Strictly consumer-only Jupyter Server REST + RFC 6455 WebSocket v13 (`Sec-WebSocket-Accept` SHA-1 + `CRYPTO_memcmp`) client executing Jupyter wire protocol v5.3 `execute_request` over loopback HTTP or verified TLS 1.2+; refuses non-loopback plain `http://`; destructor NEVER terminates remote shared kernels.
  - Independent checks PASS: `clang-format --dry-run --Werror`, Debug+ASan/UBSan, Release `-O2 -DNDEBUG` + 3/3 `libgmalloc.dylib`, `clang-tidy --warnings-as-errors='*'` 0 warnings, 0 FD leaks.
