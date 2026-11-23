# Full-History Git Secret Scan (2026-11-23)

- **Date:** 2026-11-23
- **Target HEAD:** `ef55070344273b07a0f6e5dd22e5027b89213311` (`master`)
- **Scanner:** Custom Python full-object stream scanner over `git rev-list --all --objects` and `git cat-file --batch` (scanning every reachable blob and every commit header/message across every local branch, remote-tracking ref, and tag).
- **Verdict:** **CLEAN — PASS (0 real secrets found across full Git history).**

---

## 1. Exact Scan Scope

| Metric | Count |
| --- | ---: |
| Git refs checked (`git show-ref`: local heads, remote-tracking refs, tags) | **117** |
| Total commits scanned (`git rev-list --all --count`) | **517** |
| Total tree objects enumerated | **2,920** |
| Total unique blob objects scanned | **6,308** |
| Total unique blob payload scanned | **742,599,782 bytes (~708.2 MiB)** |
| Tags enumerated | **3** |
| Commit header / message matches | **0** |
| Primary-pattern blob matches | **26 blobs** (0 real secrets) |
| Supplementary-pattern blob matches | **9 blobs** (0 real secrets; SSH detached-signature armor headers only) |

---

## 2. Patterns Scanned

### Primary Rule Set
- **Provider / cloud API key prefixes:**
  - `sk-[A-Za-z0-9]{20,}` (OpenAI / generic `sk-` keys)
  - `sk-ant-[A-Za-z0-9_-]*` (Anthropic)
  - `sk-proj-[A-Za-z0-9_-]*` (OpenAI project keys)
  - `sk-or-[A-Za-z0-9_-]*` (OpenRouter)
  - `(?<![A-Za-z0-9_])xai-[A-Za-z0-9_-]{8,}` (xAI / Grok)
  - `AIza[0-9A-Za-z_-]{35}` (Google API keys)
  - `ghp_[A-Za-z0-9]*` and `github_pat_[A-Za-z0-9_]*` (GitHub classic & fine-grained PATs)
  - `AKIA[0-9A-Z]{16}` (AWS Access Key IDs)
  - `xox[baprs]-[A-Za-z0-9-]*` (Slack tokens)
- **Private keys:**
  - `-----BEGIN (?:(?:RSA|EC|OPENSSH|DSA|ENCRYPTED|PGP)\s+)*PRIVATE KEY-----`
- **Embedded credentials & bearer tokens:**
  - `https?://[^\s:/@"'<>`]+:[^\s/@"'<>`]+@[^\s/"'<>`]+` (URL Basic auth `https://user:pass@host`)
  - `(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}` (HTTP `Authorization: Bearer ...` tokens)

### Supplementary Rule Set (Zero-Miss Backstop)
- `-----BEGIN [A-Z0-9 ]+-----` (any PEM/SSH armor header)
- `sk_(?:live|test)_[A-Za-z0-9]{16,}` (Stripe)
- `gsk_[A-Za-z0-9]{20,}` (Groq)
- `hf_[A-Za-z0-9]{20,}` (Hugging Face)
- `glpat-[A-Za-z0-9_-]{15,}` (GitLab PAT)
- `npm_[A-Za-z0-9]{20,}` (npm)
- `gh[ousr]_[A-Za-z0-9]{20,}` (GitHub OAuth/user/server/refresh tokens)
- `(?<![A-Za-z0-9])xai-[A-Za-z0-9_-]{4,}` (shorter `xai-` tokens)
- `eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}` (3-segment JWTs)

---

## 3. Classification Summary

| Classification | Matching Blobs | In `HEAD` | Real Secrets |
| --- | ---: | ---: | ---: |
| **Commit-hash / filename false positives** | 4 (2 unique paths) | 2 | **0** |
| **Synthetic test fixtures in `tests/`** | 20 (8 unique files) | 8 | **0** |
| **Historical prototype test/doc placeholders (deleted in `017e6718`)** | 2 (2 unique paths) | 0 | **0** |
| **PEM / OpenSSH private keys (`-----BEGIN ... PRIVATE KEY-----`)** | 0 | 0 | **0** |
| **Supplementary `-----BEGIN ...-----` (detached SSH signature armor headers)** | 9 (3 unique files) | 3 | **0** |
| **Provider/cloud keys (`AIza`, `ghp_`, `AKIA`, `xai-`, `xox*-`, `sk_live_`, `gsk_`, `hf_`, `glpat-`, `npm_`, `gh[ousr]_`, JWTs)** | 0 | 0 | **0** |
| **Total real secrets** | — | — | **0** |

---

## 4. Complete Match Ledger (All 26 Primary Blobs + 9 Supplementary Blobs)

All matched values below are redacted to short non-sensitive prefixes.

### 4.1 Commit-Hash & Filename False Positives (4 Blobs)

| # | Blob SHA | Commit (earliest) | Path | Line(s) | Pattern | Redacted Match | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `bd6f90b30eba` | `e55938506b7a` (HEAD) | `papers/2026-09-30-known-agent-acquisition.json` | 900 | `github_pat` | `github_pat...[17 chars]` | **False positive:** upstream tutorial GIF filename (`docs/public/assets/tutorial/github_pat_...gif`) in acquisition file inventory. |
| 2 | `30698ec5f2e0` | `017e67187bd3` (historical) | `papers/2026-09-30-known-agent-acquisition.json` | 900 | `github_pat` | `github_pat...[17 chars]` | **False positive:** earlier revision of the same upstream tutorial GIF filename prior to commit `e55938506b7a`. |
| 3 | `58f099b6bf23` | `e55938506b7a` (HEAD) | `papers/storage-performance-2026-10-07/references.json` | 88, 97, 102, 105 | `openai_or_generic_sk` | `sk-d84c8d9...[43 chars]` | **Commit-hash false positive:** trailing `sk-` of `bitcask-` followed by Bitcask's 40-hex Git commit SHA (`bitcask-d84c8d9...`). |
| 4 | `f370d70d0424` | `554f15ee374b` (historical) | `papers/storage-performance-2026-10-07/references.json` | 88, 97, 102, 105 | `openai_or_generic_sk` | `sk-d84c8d9...[43 chars]` | **Commit-hash false positive:** earlier revision of the same `bitcask-<40-hex-sha>` reference entry. |

### 4.2 Synthetic Test Fixtures in `tests/` (20 Blobs)

| # | Blob SHA | Commit (earliest) | Path | Line(s) | Pattern | Redacted Match | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 5 | `88bd2bf9cdab` | `cc2470220517` (HEAD) | `tests/decision_models_test.cpp` | 70 | `bearer_token` | `Bearer cus...[29 chars]` | **Synthetic test fixture:** local mock-curl assertion (`Authorization: Bearer custom-decision-...`). |
| 6 | `c36459dad6a8` | `200fc5e8c164` (HEAD) | `tests/decision_raw_test.cpp` | 44 | `bearer_token` | `Bearer raw...[36 chars]` | **Synthetic test fixture:** local mock-curl sentinel (`Authorization: Bearer raw-decision-...`). |
| 7 | `ab4ec2f6f54e` | `ef5507034427` (HEAD) | `tests/peer_identity_test.cpp` | 862 | `anthropic_sk_ant` | `sk-ant-glm...[20 chars]` | **Synthetic test fixture:** `ANTHROPIC_API_KEY` env-isolation sentinel verifying zero leak into `ssh-keygen`. |
| 8 | `1a543dca8797` | `ef5507034427` (HEAD) | `tests/worktree_lease_test.cpp` | 755 | `anthropic_sk_ant` | `sk-ant-glm...[20 chars]` | **Synthetic test fixture:** `ANTHROPIC_API_KEY` env-isolation sentinel verifying zero leak into `git`. |
| 9 | `8464feef0d0f` | `d36f489907d6` (HEAD) | `tests/platoon_runner_test.cpp` | 1256 | `anthropic_sk_ant` | `sk-ant-do-...[18 chars]` | **Synthetic test fixture:** `ANTHROPIC_API_KEY` env-isolation sentinel (`sk-ant-do-...`) verifying external-driver stripping. |
| 10 | `5b3cf563cf58` | `11679acda347` (historical) | `tests/platoon_runner_test.cpp` | 1151 | `anthropic_sk_ant` | `sk-ant-do-...[18 chars]` | **Synthetic test fixture:** earlier revision of the same env-isolation test sentinel. |
| 11 | `da8e1c20d06c` | `a54871131286` (HEAD) | `tests/provider_auth_raw_test.cpp` | 568, 600, 833 | `url_basic_auth`, `bearer_token` | `https://pr...[65 chars]`, `Bearer fre...[36 chars]`, `Bearer pri...[36 chars]` | **Synthetic test fixture:** negative URL-userinfo rejection test (`@example.com/v1`) and mock OAuth/Codex refresh sentinels. |
| 12 | `1c6c1bc7511a` | `77cb5776c42a` (historical) | `tests/provider_auth_raw_test.cpp` | 568, 600, 833 | `url_basic_auth`, `bearer_token` | `https://pr...[65 chars]`, `Bearer fre...[36 chars]`, `Bearer pri...[36 chars]` | **Synthetic test fixture:** historical revision of the same `tests/provider_auth_raw_test.cpp` sentinels. |
| 13 | `e6dcee2af901` | `496ff29020e5` (historical) | `tests/provider_auth_raw_test.cpp` | 568, 600, 834 | `url_basic_auth`, `bearer_token` | `https://pr...[65 chars]`, `Bearer fre...[36 chars]`, `Bearer pri...[36 chars]` | **Synthetic test fixture:** historical revision of the same `tests/provider_auth_raw_test.cpp` sentinels. |
| 14 | `1d5bd7c7b7a8` | `ab23278e2e11` (historical) | `tests/provider_auth_raw_test.cpp` | 568, 600, 833 | `url_basic_auth`, `bearer_token` | `https://pr...[65 chars]`, `Bearer fre...[36 chars]`, `Bearer pri...[36 chars]` | **Synthetic test fixture:** historical revision of the same `tests/provider_auth_raw_test.cpp` sentinels. |
| 15 | `f787a59cab10` | `2bda56585118` (historical) | `tests/provider_auth_raw_test.cpp` | 560, 591, 808 | `url_basic_auth`, `bearer_token` | `https://pr...[65 chars]`, `Bearer fre...[36 chars]`, `Bearer pri...[36 chars]` | **Synthetic test fixture:** earliest revision of the same `tests/provider_auth_raw_test.cpp` sentinels. |
| 16 | `55eb705a85b3` | `56b3f6297554` (HEAD) | `tests/provider_exchange_raw_test.cpp` | 298 | `bearer_token` | `Bearer pri...[28 chars]` | **Synthetic test fixture:** mock `ProviderHttpRequest` header (`Bearer private-wire-...`). |
| 17 | `f7b79ef652a9` | `496ff29020e5` (historical) | `tests/provider_exchange_raw_test.cpp` | 300 | `bearer_token` | `Bearer pri...[28 chars]` | **Synthetic test fixture:** historical revision of the same mock header sentinel. |
| 18 | `79ae23fabfe1` | `ab23278e2e11` (historical) | `tests/provider_exchange_raw_test.cpp` | 298 | `bearer_token` | `Bearer pri...[28 chars]` | **Synthetic test fixture:** earliest revision of the same mock header sentinel. |
| 19 | `41f91e22406b` | `56b3f6297554` (HEAD) | `tests/provider_raw_test.cpp` | 100 | `bearer_token` | `Bearer raw...[29 chars]` | **Synthetic test fixture:** mock-curl header check (`Bearer raw-test-...`). |
| 20 | `3c60dce65ac2` | `651e0beedbca` (historical) | `tests/provider_raw_test.cpp` | 100 | `bearer_token` | `Bearer raw...[29 chars]` | **Synthetic test fixture:** historical revision of the same mock-curl sentinel. |
| 21 | `f019248bb0dd` | `496ff29020e5` (historical) | `tests/provider_raw_test.cpp` | 100 | `bearer_token` | `Bearer raw...[29 chars]` | **Synthetic test fixture:** historical revision of the same mock-curl sentinel. |
| 22 | `40326217a9fe` | `ab23278e2e11` (historical) | `tests/provider_raw_test.cpp` | 100 | `bearer_token` | `Bearer raw...[29 chars]` | **Synthetic test fixture:** historical revision of the same mock-curl sentinel. |
| 23 | `02745b524515` | `2bda56585118` (historical) | `tests/provider_raw_test.cpp` | 101 | `bearer_token` | `Bearer raw...[29 chars]` | **Synthetic test fixture:** historical revision of the same mock-curl sentinel. |
| 24 | `3c812bcbd381` | `3561c724cc75` (historical) | `tests/provider_raw_test.cpp` | 98 | `bearer_token` | `Bearer raw...[29 chars]` | **Synthetic test fixture:** earliest revision of the same mock-curl sentinel. |

### 4.3 Historical Legacy-Prototype Placeholders (2 Blobs, Absent from `HEAD`)

| # | Blob SHA | Commit (introduced / deleted) | Path | Line(s) | Pattern | Redacted Match | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 25 | `20241820a311` | `24ec457d86bd` (2026-06-07) / deleted in `017e67187bd3` | `crates/arconaut-core/src/vars.rs` | 190, 195 | `anthropic_sk_ant` | `sk-ant...` (10 chars) | **Synthetic test fixture (legacy Rust prototype):** short literal `"sk-ant-..."` in unit test, deleted during C++/Lua reconstruction. |
| 26 | `22a2ee776667` | `24ec457d86bd` (2026-06-07) / deleted in `017e67187bd3` | `docs/phase5-subplan.md` | 88, 92, 100 | `anthropic_sk_ant`, `openai_sk_proj`, `openrouter_sk_or` | `sk-ant-api...[13 chars]`, `sk-pro...` (8 chars), `sk-or-...` (9 chars) | **Documentation placeholder (legacy prototype):** ellipsized TOML configuration examples (`"sk-ant-api03-..."`, `"sk-proj-..."`, `"sk-or-v1-..."`), deleted during reconstruction. |

### 4.4 Supplementary `-----BEGIN ...-----` Backstop (9 Blobs, 0 Private Keys)

The primary private-key pattern (`-----BEGIN ... PRIVATE KEY-----`) produced **0 matches** across all 6,308 blobs and 517 commits. The broader supplementary pattern `-----BEGIN [A-Z0-9 ]+-----` matched **9 blobs** across 3 files, every single one being the literal SSH detached-signature armor header `"-----BEGIN SSH SIGNATURE-----"` (not a private key):

- `src/peer_identity.cpp` (3 revisions: `782518398c96` in HEAD, `f729108691b0`, `2fe003ba17fc`) — armor validation constant.
- `tests/peer_identity_test.cpp` (3 revisions: `ab4ec2f6f54e` in HEAD, `a44c009e7d37`, `d69f23e3798a`) — detached signature armor unit tests.
- `tests/board_bridge_test.cpp` (3 revisions: `919cd4315681` in HEAD, `70c88b0d1c5a`, `ac77105f4156`) — signed envelope armor assertions.

---

## 5. Verdict & Launch Readiness

- **Real secrets found across all 517 commits, 6,308 unique blobs, and 117 refs:** **0**.
- **History rewrite required before public launch:** **No.** Full Git history is clean of API keys, OAuth/Bearer credentials, Basic-auth URLs, and PEM/OpenSSH private keys.
