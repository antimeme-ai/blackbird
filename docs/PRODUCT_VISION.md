# Multiplayer + Blackbird: Product Experience Vision ("Xbox Live Easy")

**Status:** Draft for Founder Review (2026-11-24)  
**Inputs:** Live two-engineer field post-mortem (`@antimeme` + `@phall`), 6-Model Product Council (`Astra`, `Fable`, `Kimi` CN mass-market, `GLM` CN mass-market, `Muse` Meta hyperscaler, `DeepSeek`), unanimous 5–0 P2P architecture vote, and 3 Business/Product Frumentarii reports (Empirical HCI & Gaming UX, Business/GTM & Unit Economics, Cross-Repo Code Audit).

---

## 1. Thesis: Winning vs. Irrelevance

Tonight, two senior engineers (18+ combined YoE at Amazon, Meta, and Dropbox), assisted by frontier AI models with direct database access, fought our own tools just to get two terminals into a single party. Yet despite the painful UX, `@phall` came away genuinely bullish on the underlying technology.

That single signal tells us everything: **people want multiplayer AI parties. Our plumbing is killing our product.**

Two laws of consumer software govern everything in this document:
- **The Slack Law:** *Slack didn't win because IRC lacked features; Slack won because it was effortless and let engineers bridge their existing tools on Day 1.*
- **The Instagram Law:** *Instagram didn't win on filter math; Instagram won because the time between tapping the button and seeing your image in lights felt like zero delay.*

Every decision in this vision obeys one rule: **there are no sacred cows, only winning vs. irrelevance.** Our audience is not cryptographers who enjoy managing `~/.config` directories — it is **gamers, students, builders, and engineers, including people who largely don't know what a filesystem is.**

### The 7 Falsifiable UX Laws (Grounded in Empirical HCI Data)
Why PGP, Keybase, XMPP, and Matrix v1 died at mass adoption while WhatsApp (3B), WeChat (1.4B), Discord (200M), Xbox Live (120M), Figma (13M), and Tailscale ($1.5B) won is not opinion — it is peer-reviewed fact:
- **90% of novice pairs fail Mailvelope PGP** (mean SUS 34.5/100 — an "F" grade; Ruoti et al., CHI 2016).
- **75% of computer science majors fail manual Signal safety-number verification** even when explicitly told to detect a MitM attack (Schröder et al., NDSS 2016).
- **Matrix 2.0 / Element X** had to ship "Invisible Encryption" (MSC4153) and OIDC/Passkeys after 48-character recovery keys caused mass "Unable to Decrypt" churn.
- **Xbox One (2013)** sparked a gamer revolt by bloating Party/Guide latency to 10–15s and splitting party invites from game invites; **NXOE (2015)** won players back by cutting latency 50% and reunifying them.

Therefore, every surface of Multiplayer + Blackbird must pass **7 hard, testable laws**:
1. **Zero Cryptographic Strings or Internal IDs in Normal UI:** Never show raw public keys, 60-digit safety numbers, 16-digit `party_id`s, `mppi1_` secrets, `device_id`s, `party_epoch`, or `relay_policy` flags. The user's vocabulary is `@username`, a link, and a 4-character room code.
2. **Zero Mandatory First-Contact Key Verification:** Joining a party or messaging a friend must *never* block on safety-number pinning. Verification lives in a hidden `Security / Verify @user` drawer and alerts *only* on unexpected mid-relationship anomalies.
3. **Instagram Speed ("Your Image in Lights"):** `< 10s` from clicking an invite link to sitting live in the room (in browser, zero install); `< 45s` from downloading the native app on a clean machine to exchanging a verified message with a friend; `< 1s` optimistic room render on join.
4. **At Most 2 Actions to Squad Up (`拉人开黑`):** Hosting, inviting, or joining takes `<= 2` actions via `@username`, a live rich share card (`mp.gg/@phall`), or a 4-character room code (`KAIH` / `8842`).
5. **Zero Filesystem or Terminal Literacy Required:** Moving or double-clicking the downloaded app from `~/Downloads` on a factory-reset machine must work 100% of the time with zero external `scripts/`, `programs/`, `profiles/`, or `$PATH` edits.
6. **Portable Cloud Accounts, Zero Device Lock-In:** Losing a laptop never loses your `@username`, friends list, or parties. Sign in on any new machine via browser in < 15 seconds.
7. **Proven, Loud, Plain-English Liveness:** Never hang silently for 20 seconds. Show unambiguous connection state (`● @phall live (Claude Code)` / `◐ Reconnecting…`) backed by real end-to-end delivery acknowledgements.

---

## 2. The Architecture Flip: Kill Mandatory P2P & Device-Bound PGP Theater

Tonight's failures were not isolated bugs — they were compounding interest on two ideological architecture bets that actively fight mass adoption: **mandatory P2P (`iroh`)** and **device-bound local root keys (`mprk1_`)**.

### Decision A: Kill Mandatory P2P (Unanimous 5–0 Council Verdict)
`Muse`, `Kimi`, `GLM`, `Astra`, and `Fable` voted **5–0 to kill mandatory P2P** for party rooms and run parties directly over **server-hosted WebSockets on Cloudflare Durable Objects (`PartyDO`)** — the exact architecture of Discord, Slack, Figma, WeChat, and modern Xbox Live Party Chat.

| Dimension | Mandatory P2P (`iroh`) Today | Server-Hosted `PartyDO` WebSockets |
|---|---|---|
| **Reliability** | NAT roulette, `relay_policy` mismatches, 20s synchronous dial blocks, asymmetric glare (`4409`), roaming drops | Single authenticated WSS connection on port `443` — works on dorm, corporate, hotel, and mobile Wi-Fi |
| **Browser Client** | Impossible (browsers cannot speak raw `iroh` QUIC UDP) | **First-class web client unlocked immediately** — same room, same protocol |
| **Room Persistence** | Rooms vanish when laptops sleep; 20s–5m connect timers | **Persistent rooms** with durable message log, sequence-number resume, and async catch-up |
| **Cross-Client Parity** | Separate C++ (`blackbird-p2p`) + Rust (`outpost-p2p`) QUIC state machines + 30 MB Rust staticlib in Blackbird | **One canonical room protocol** shared identically by Blackbird (C++ native TLS 1.3 WS), Outpost (Rust), and Web |
| **Latency & Cost** | Saves ~30–80ms on direct hits (imperceptible for chat/agents) | Cloudflare DO (`$0.00` egress, `setWebSocketAutoResponse` zero-wakeup pings) = **`~$0.01–$0.05/MAU/month`** |

**The 1M-User Safeguard Rule (Council Unanimous):**
> **`PartyDO` is an ordered, resumable opaque-envelope log — it never needs to parse payloads, and P2P is never load-bearing.**

Every party event carries plaintext routing/ordering fields (`room_id`, `seq`, `client_msg_id`, `sender_account_id`, `kind`) and an **opaque content body** (`body_bytes`). Large artifacts (diffs, screenshots, clips, files) upload via R2 presigned URLs, never clogging the socket. Because the body is opaque from Day 1:
- **Zero-migration E2EE later:** Enterprise/privacy-sensitive rooms can layer client-side MLS/envelope encryption over `body_bytes` without touching `PartyDO`.
- **Optional bulk accelerator later:** If voice, screenshare, or multi-GB sync ever justify direct P2P/WebRTC, it slots in as a strictly optional accelerator with automatic WebSocket fallback.
- **Zero lock-in:** `PartyDO` is just one room-host implementation of the ordered log; rooms can migrate or shard cleanly at 1M+ users.

### Decision B: Cloud-Portable Accounts (Not Device-Bound Key Files)
People do not think of an account as `~/.config/blackbird/online/root.seed`. They think of an account as **`@antimeme`**, accessible from any laptop, desktop, or browser.

- **Identity = `@username` anchored in `AccountDO`**, authenticated via **Passkeys** (already partially built in `multiplayer_site/server/src/webauthn.ts`!), **GitHub / Google / Discord OAuth**, or **Email Magic Code**.
- **Sign in on any new machine (`blackbird login` / `outpost login`):** Opens system browser (or displays a short code + QR on headless SSH boxes) → `"Continue as @antimeme in Blackbird?"` → 1 click → done in 5 seconds.
- **Devices are invisible, disposable sessions:** On sign-in, the client silently generates an ephemeral local key/session credential in OS Keychain, `AccountDO` issues and silently auto-renews its token/cert, and stale devices auto-evict cleanly. Users can view/revoke sessions under **Account → Devices**, never export `.mpkey` files, never run 8-character old-machine approval rituals, and never copy config folders.
- **Honest Security Trade-Off (Stated Plainly):** Moving default consumer accounts to cloud-managed identity makes `api.multiplayer.tech` the trusted identity directory — the exact trade WhatsApp, iMessage, Tailscale, Discord, and Xbox Live make by default. Transport is always TLS 1.3; optional per-room E2EE and an opt-in **Citadel / Enterprise** self-custody policy mode remain available for regulated buyers without taxing ordinary users.

---

## 3. The First 60 Seconds: Zero-to-Live-Party Funnel

**The front door is a URL pointing to a person (`multiplayer.tech/@phall` or `mp.gg/@phall`), not a GitHub README or a terminal binary.**

### New User Funnel (Gamers, Students, Non-Coders)
- **T+0s — The Share Card:** `@phall` clicks **Invite** (or types `/invite`). His client copies `mp.gg/@phall` (plus a 4-char room code like `KAIH` for voice calls or dorm tables). Pasted into Discord, iMessage, WeChat, or Slack, it unfurls as a live card:
  > **`@phall` invited you to a party**  
  > `● @phall (Claude Code) · 2 agents active`  
  > **[Join Party]**
- **T+5s — Instant Browser Room (Zero Install, Zero API Key Wall):** Clicking the link opens the **real working party in the browser** — not a marketing landing page. You immediately see who is there and what's happening.
- **T+15s — Claim a Name:** Click **Join Party** → enter as a one-tap Guest name (or sign in with Discord / Google / GitHub / Apple / Passkey) → pick `@username`. Zero profile wizards, zero API key prompts, zero credit cards.
- **T+20s — Optimistic Join ("Your Image in Lights"):** The room renders in `< 1s`. You are **already live** with `@phall`: chat works immediately, you see agent activity cards, and you can `@`-mention `@phall`'s agent right from your phone or browser. An automatic `"@you joined"` message proves liveness socially in under 2 seconds.
- **T+45s — Progressive Upgrade ("Bring Your Own Agent"):**
  - *Want Blackbird?* One-click signed installer (macOS `.dmg`, Windows MSIX/WinGet, Linux static binary) that remembers the party invite and drops you straight back into `@phall`'s party on first launch.
  - *Already use Claude Code / Cursor / Codex / OpenCode?* One-click **"Connect my coding app"** installs Outpost automatically (zero JSON editing, zero `cargo`, zero MCP jargon) and brings your existing AI subscription into the exact same room.

### Returning Terminal User Funnel (< 3 Seconds)
Open Blackbird → it is **silently online** on `/v1/ws` from boot → type `/invite @phall` (or press `Enter` on `@phall`'s incoming invite toast) → **live in under 2 seconds.**

---

## 4. The Entire User Vocabulary: Me, Friends, Party

Collapse the entire universe across Browser, Blackbird, and Outpost into **3 mental concepts** — **Me**, **Friends**, and **Party** — and **5 one-verb commands** (killing `/online party attach`, `/online party create friends force`, `/online watch start`, `/party online ...`, and legacy SSH `/party` duplication):

| You Type (or Click) | What Actually Happens |
|---|---|
| `/login` (or first launch) | Opens browser sign-in (Passkey / GitHub / Google / Discord / Email) → claims `@username` → auto-connects presence silently |
| `/add @phall` | Sends or accepts a friend request by username — zero safety numbers, zero account IDs |
| `/invite @phall` | If alone, **silently creates and enters a party**; rings `@phall` live across all his signed-in Blackbird, Outpost, and Web sessions. Bare `/invite` copies `mp.gg/@you` + 4-char code |
| `/join` · `/join @phall` · `/join KAIH` | **One universal resolver:** bare `/join` accepts your latest incoming invite; `/join @phall` hops into your friend's joinable party; also accepts any 4-char code, URL, or legacy token transparently |
| `/leave` | Leaves the current party (other members stay live; you can rejoin anytime) |
| `/friends` (or `/who`) | Live Xbox Live roster: `● @phall — in party (2) [Join]`, `● @mei — online [Invite]`, `○ @sam — offline` |

### Sacred Cows Explicitly Deleted from User UX
- **`create` vs. `attach`:** Deleted everywhere (TUI, CLI, Outpost, MCP). You are conceptually always in a party of 1; inviting someone or joining someone makes you live immediately.
- **`watch start`:** Deleted. Presence and incoming invite delivery are automatic whenever signed in.
- **Dual `/party` vs `/online party`:** Unified. One party concept everywhere; local LAN mDNS discovery (`blackbird lan` for offline hackathons) becomes an automatic fallback tab, not a separate identity universe.
- **16-digit `party_id` vs `mppi1_` split:** Deleted. One `@username`, one shareable URL (`mp.gg/@phall`), one optional 4-char room code.
- **Outpost MCP Parity:** Outpost's MCP server exposes the exact same high-level verbs (`party_invite("@phall")`, `party_join("@antimeme")`, `party_say("...")`, `party_friends()`, `party_leave()`) so a Cursor or Claude Code user can literally tell their AI *"invite @antimeme to a party"* without ever touching a CLI.

---

## 5. True Cross-Client Interop & Live Connection Honesty

Our internal code audit exposed **why Blackbird and Outpost couldn't cleanly talk tonight** even after forming a party:
1. **Outpost hard-blocked every message to Blackbird** (`app_daemon.rs:2292-2340`) until the user ran a manual 60-digit safety-number trust command (`ERR_CONFLICT`).
2. **Blackbird TUI silently discarded every Outpost `board_post`** (`mp_tui_session.cpp:1236-1238`: `case bridge_envelope_received: return;`).
3. **Blackbird TUI never resolved peer handles**, displaying `@phall` as `peer_<16-digit-device_id>` (`mp_tui_session.cpp:1355`).
4. **3 incompatible default `room_scope` strings** (`"online/<id>"`, `"party/online"`, `"party/main"`) and divergent `target_selector` formats (`"device:<did>"` vs `"@handle"`).
5. **Blackbird's 20-second synchronous blocking `iroh` dial** starved its own WebSocket heartbeat and evicted healthy peers, compounded by asymmetric glare (`4409`) and missing address-roaming watches.
6. **TUI mouse capture (`terminal.cpp:3267`) was flipped ON by default** (contradicting its own help text!), hijacking native click-and-drag text selection across the entire terminal.

### How We Fix All Six Permanently
- **One Canonical Room Protocol (Blackbird + Outpost + Web):** All three clients connect to `PartyDO` over WSS (`443`) using one shared, conformance-tested envelope schema (unified `room_scope`, unified `@handle` addressing, zero safety-number send gates, full rendering of both chat and structured agent activity/board cards).
- **Persistent Party Strip & Proven Liveness:** Always visible in one compact line (never hidden behind `Alt+P` on `< 120`-col screens, and mirrored via OSC 9/777 desktop notifications when unfocused):
  ```text
  ● you (Blackbird)   ● @phall (Claude Code · Outpost)   2 agents   [Copy Invite]
  ```
  - **Three states, shape + word (never color alone):** `● Live`, `◐ Reconnecting…`, `○ Away`.
  - **"Live" is proven by round-trip ACK, never guessed.** Chat messages render optimistically with a delivery check (`✓`) once acknowledged by `PartyDO` / peers.
  - **Plain-English self-healing errors:** Every degraded state states *what happened*, *what we're doing*, and *what you can do* (`"Connection dropped — reconnecting automatically (1 message queued)"`). Never bare `provider_transport`, `conflict detail=1003`, or silent 20s hangs.
- **Agents Are Social Citizens With Clear Ownership & Safety:**
  - Every agent appears labelled by owner (`@phall's Claude`, `Your Blackbird`).
  - **One-sentence safety rule enforced by the harness (not model judgment):** *"Your agent only acts on your machine, under your permissions."* Inbound peer messages remain untrusted data (Brakes `TurnTaintState` + automatic `guarded`/sandbox floor for non-friend/public parties), surfaced once in plain English: `This party can: Chat ✓ · See shared excerpts ✓ · Run commands on your machine ✗`.
  - **No agent-stream firehose:** Agent work renders as compact collapsible activity cards (`@phall's Claude: fixed auth test · 2 files [View diff]`) with a 1-action **Quiet agents** toggle so humans can talk.
- **Native Terminal Text Selection Sacred (`terminal.cpp`):** Flip `mouse_wanted` **OFF by default** so click-drag + `Cmd+C` works on the first drag in Ghostty, iTerm2, Terminal.app, Windows Terminal, and tmux. Keep wheel scrolling via alternate-scroll mode, keyboard OSC 52 copy for last block, and `/mouse on` as strictly opt-in.

---

## 6. Distribution for People Who Don't Know What a Filesystem Is

A downloadable executable that crashes when `programs/turn.lua` or `profiles/providers/*.lua` isn't sitting beside it in a Git checkout is a build artifact, not a product.

### Zero-"Scripts" Hermetic Single Binary (`blackbird`)
Our codebase audit confirmed the entire external Lua footprint is only **~83 KB** and the loaders (`read_profile_text`, `Script::create`, `register_pack_source`) already accept in-memory strings:
- **Embed 100% of built-in defaults inside `blackbird`** (via C++23 `#embed` / generated rodata): all 11 provider profiles (`29 KB`), `programs/turn.lua` (`1.5 KB`), `instruments/results.lua` (`567 B`), all 7 SaaS packs (`52 KB`), and compressed SR-71 asset (rendered via Kitty inline `t=d` base64 instead of file path `t=f`).
- **Fold helper binaries into multicall modes:** `blackbird-job-runner` (66 lines of POSIX) and `blackbird-archive` dispatch directly via `blackbird --internal-job-runner` / `--internal-archive` using `executable()`.
- **Portable session state:** Persist `builtin:turn.lua` instead of hardcoded absolute paths so moving binaries or upgrading never invalidates sessions. External disk scripts become a strictly optional power-user override.
- **Delete the 30 MB Rust `iroh` staticlib from Blackbird** once `PartyDO` WebSockets own the party data plane — cutting binary size dramatically, eliminating cross-compiler/macOS SDK link warnings, and unifying all builds under pure C++23 + Lua 5.5.1 + OpenSSL 3 + SQLite 3.54.1.

### Real Consumer Packaging Across Every Platform
| Platform | Target Artifact | Trust & Auto-Update | Why It Matters |
|---|---|---|---|
| **Web (Zero-Install)** | `multiplayer.tech/@handle` live party client (Cloudflare Pages) | Always current | Unlocks non-coders, mobile, and `< 10s` first join (Figma: 67% of MAU are non-designers) |
| **macOS** | Signed & notarized Universal `.app` inside `.dmg` + Homebrew Cask + `multiplayer://` deep link | Apple Developer ID + notarization + silent background update | Double-click from `Downloads` — zero Gatekeeper panic, zero `$PATH` editing |
| **Windows (Urgent P0)** | **Microsoft Store MSIX** + **WinGet** + Azure-signed `.exe`/`.msi` + Windows `mp-outpost` | Day-0 SmartScreen trust via Store MSIX + Azure Artifact Signing | **~95% of PC gamers** (Steam Hardware Survey) and most college students are on Windows |
| **Linux** | Single static executable + AppImage/Flatpak + `.deb`/`.rpm` + AUR/Nix | Silent in-band update with rollback | Covers SteamOS/Steam Deck, Ubuntu, and Arch cleanly |
| **Outpost (AI Tools)** | Signed `.mcpb` (1-click Claude Desktop) + Cursor/VS Code marketplace extension + `npx -y @multiplayer.tech/outpost` | Automatic marketplace updates + browser OAuth login | Zero `curl | sh`, zero JSON config editing, zero CLI flags |

### Non-Negotiable Release CI Gate
Before any release ships, CI copies **only the single downloaded artifact** into an empty `Downloads`-style directory on a **clean VM with zero Git checkout and zero dev tools**, renames it, launches it, signs in, and completes a live **Blackbird ↔ Outpost ↔ Web** round-trip party test (chat + agent card + reconnect). If that fails, the release is blocked.

---

## 7. Viral Loops, Business Model & Why We Beat Single-Player Harnesses

### Why Multiplayer Wins Where Solo Harnesses Commoditize
- **Solo AI harnesses are a margin-crushed commodity:** Models leapfrog every quarter, flat-rate agent loops bleed inference COGS, and 79–90% of developers multi-tool across Cursor, Claude Code, and Codex with zero switching cost.
- **Cross-harness multiplayer builds a real social graph:** `mp-outpost` is **Slack's 2014 IRC/XMPP gateway** — friends bring whatever AI tool and subscription they already pay for into one shared `multiplayer.tech` party. Replit's trajectory ($3–10M ARR under multi-cursor code editing → $500M+ ARR / $9B valuation under Replit Agent) proves the winning primitive is **not two humans fighting over one text cursor — it is an Xbox Live co-op raid lobby for humans and their autonomous AI rigs.**

### Four Built-In Viral & Retention Loops
1. **Live Watchable Parties + Party Clips / Squad Replay (`开黑回放`):** Every party can emit an opt-in, secret-scrubbed 60-second replay card (`mp.gg/c/xxxx`) or live watch link (`mp.gg/@phall`) showing humans + agents solving a bug, building a game mod, or shipping a demo — ending with **`[Join their next party]`** and **`[Try this setup]`**. Every shared artifact becomes a live product demo (the Lovable/Bolt/TikTok/Bilibili growth engine).
2. **"Bring a Second Opinion" (Contextual Invite):** Highlight a failing test or agent answer → 1 tap invites `@phall` with the exact excerpt previewed (*"@antimeme wants your take on why this auth test fails"*). Gives a friend an immediate concrete reason to click.
3. **Kill the Empty-Room Spiral:** Persistent async rooms (`Rejoin last night's squad`), 4-digit proximity PINs (`面对面开黑`) for dorms/hackathons/Discord voice, Discord Rich Presence (*"In Multiplayer Party (2/4) — [Join]"*), and opt-in GitHub/Discord friend discovery so nobody ever lands in an empty app.
4. **No Model / API-Key Wall:** Human guests can join, chat, watch, and ask a host's agent for free in browser with zero API keys; Outpost users ride their existing Claude/Cursor/ChatGPT subscriptions; optional pre-paid **Starter AI Credits** remove the Anthropic/OpenAI billing cliff for casual gamers & students without creating flat-rate COGS exposure.

### Unit Economics & Pricing Ladder
Because users bring their own LLM inference ($0 core AI COGS) and Cloudflare Durable Objects charge **$0.00 egress** with zero-wakeup WebSocket pings (`setWebSocketAutoResponse`), steady-state network COGS stay around **`~$0.01–$0.05/MAU/month`**. That funds a Discord/Tailscale-sized free tier that maximizes viral density:

- **Free ("Squad" — $0 forever):** Unlimited `@username`, friends, LAN parties, cross-harness Outpost, live parties up to 6–8 peers, persistent 7-day room history, and shareable Party Clips.
- **Pro ("Afterburner" — $9–$12/mo; $5/mo `.edu`):** Unlimited persistent room history & Replay Vault, vanity links (`mp.gg/team`), large R2 asset sync, always-on cloud room observer, and custom Flight Deck flair (Discord Nitro model: ~3% paid subsidizes 97% free).
- **Team / Org ($12–$15/user/mo) & Enterprise / Citadel ($25–$35+/user/mo):** Auto-trusted org roster, nested groups & External Guest Brakes (`0006_org_groups.sql` already built), SSO/SCIM instant eviction, opt-in E2EE / Citadel self-custody keys, BBM2 compliance audit export, and optional BYO/corporate relays (Tailscale + Figma expansion ladder).

---

## 8. Execution Blueprint for the Neon Regiment (Sequenced Waves)

Once the founder approves/edits this vision, the Neon Regiment executes across **4 parallelizable waves** spanning `blackbird`, `multiplayer_outpost`, and `multiplayer_site`:

- **Wave 1 — Stop the Bleeding & Ship the Hermetic Binary (`blackbird`):**
  1. Fix TUI text selection (`mouse_wanted = false` default + alternate-scroll wheel in `src/terminal.cpp`).
  2. Embed 100% of Lua programs (`turn.lua`, `results.lua`, 11 provider profiles, 7 SaaS packs) + inline SR-71 asset + multicall `job-runner`/`archive` so `blackbird` is one self-contained binary tested from an empty temp folder.
  3. Auto-connect `/v1/ws` silently on startup; ship 1-verb `/invite`, `/join`, `/leave`, `/friends`, `/add`; purge safety numbers, 16-digit IDs, and `relay_policy` from normal output; fix peer `@handle` resolution, always-visible party strip, and OSC 9/777 notifications.
- **Wave 2 — Kill Mandatory P2P → Unified `PartyDO` WebSocket Data Plane (`multiplayer_site` + `blackbird` + `multiplayer_outpost`):**
  1. Extend `PartyDO` into the canonical ordered opaque-envelope log (`seq`, `client_msg_id`, durable SQLite room log + resume cursor, R2 presigned blobs, friend-direct join by `@username`, 4-char room codes, persistent rooms with no 20s kill switch).
  2. Migrate Blackbird and Outpost party chat, presence, and agent cards onto the single `PartyDO` WSS protocol; remove `iroh` from Blackbird's critical path (and remove Outpost's safety-number send block); add Outpost MCP party lifecycle verbs (`party_invite`, `party_join`, `party_leave`).
  3. Ship a mandatory CI **Blackbird ↔ Outpost ↔ Web** conformance & live-round-trip test harness.
- **Wave 3 — Non-Device-Bound Cloud Accounts & Browser Front Door (`multiplayer_site` + `blackbird` + `multiplayer_outpost`):**
  1. Cloud-managed account signing key in `AccountDO` (`custody_mode = 0`, keeping `1: self_custody` opt-in) + browser login (`Passkey` + `GitHub/Google/Discord OAuth` + `Email Magic Code`) + `blackbird login` / `outpost login` loopback/device-code flow with silent auto-renewing ephemeral device sessions.
  2. Ship **`multiplayer.tech/@handle` live browser party client & rich share cards** (`< 10s` guest join, live chat + agent cards + 1-click download / Outpost connect).
- **Wave 4 — Mass-Market Distribution & Viral Ignition:**
  1. Signed/notarized macOS `.app`/`.dmg` + Homebrew Cask, **Windows MSIX/WinGet + Windows `mp-outpost`**, Linux static/AppImage, and 1-click Outpost `.mcpb`/Cursor/VS Code marketplace installs.
  2. Ship **Party Clips / Squad Replay (`mp.gg/c/xxxx`)**, **"Bring a Second Opinion"**, Discord Rich Presence, and 4-digit proximity PINs.
