# Wave 13B Independent Adversarial Verification (`@dentist-2`) — 2026-11-23

**Scope:** Wave 13B (Prebuilt Release Packaging, SHA-256 Verified One-Line Installer, Offline Regression Suite & GitHub Actions Release Pipeline)

- **Files:** `scripts/package-release`, `scripts/install-release.sh`, `scripts/check-release-packaging`, `.github/workflows/release.yml`

## Initial Findings (Board `#262`)
1. **HIGH — Archive symlink/hardlink escape in `scripts/install-release.sh`:** `tar -tzf` checked member names only, not symlink/hardlink targets.
2. **HIGH — Unverified Lua 5.5.1 tarball download & missing publish-job validation / `iroh` guard in `.github/workflows/release.yml`.**
3. **HIGH — Unvalidated newlines/control chars in `--prefix` / `BLACKBIRD_PREFIX` in `scripts/install-release.sh`.**
4. **MEDIUM — macOS `otool -L` allowlist & Linux post-bundle RPATH containment verification in `scripts/package-release`.**

## Remediation & Final Verdict (Board `#263`, `#264` — **CLEAN**)
- Pre-extract `tar -tvzf` inspection in `scripts/install-release.sh` rejects hardlinks, special files, and symlinks outside `<stem>/lib/` or containing `/` or `..` (verified with 1 positive + 4 negative tests).
- `.github/workflows/release.yml` pins & verifies `lua-5.5.1.tar.gz` SHA-256 (`1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce`), puts `$HOME/.cargo/bin` ahead of Homebrew LLVM on macOS `PATH`, verifies `cargo`, and re-validates version allowlist in `publish`.
- `scripts/install-release.sh` rejects empty, newline, or `[[:cntrl:]]` `$blackbird_prefix` with exit `2` before touching disk.
- `scripts/package-release` enforces strict macOS Apple system allowlist (`/usr/lib/`, `/System/Library/`) and Linux post-bundle `ldd` containment inside `lib_dir.resolve()`.
- Independently verified: `sh -n`, `dash -n`, `py_compile`, YAML parse (`['build', 'publish']`), `--help`, and `./scripts/check-release-packaging` (`PASS`).
