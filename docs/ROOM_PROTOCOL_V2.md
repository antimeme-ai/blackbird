# Multiplayer Room Protocol v2 (`mp2`) & Cloud Auth Contract

**Status:** Frozen Regiment Contract (2026-11-24)  
**Shared Across:** `multiplayer_site` (Cloudflare Workers / `PartyDO` / `AccountDO`), `blackbird` (C++23), `multiplayer_outpost` (Rust), and Web Browser (`multiplayer.tech/@handle`).

---

## 1. Design Principles (Non-Negotiable)

1. **One canonical transport:** Server-hosted TLS 1.3 WebSockets over port `443` (`Sec-WebSocket-Protocol: mp2`). Mandatory `iroh` P2P is **removed** from the party correctness path.
2. **One protocol for all 3 clients:** Blackbird, Outpost, and Web Browser speak the exact same UTF-8 JSON frames over `mp2`.
3. **Opaque body from Day 1 (1M-user safeguard):** `PartyDO` validates size (`<= 32768` bytes), sequences, deduplicates `client_msg_id`, persists, and fans out. It **never** parses payload semantics so optional per-room E2EE (MLS/envelope encryption) can drop in later with zero server schema changes.
4. **Persistent, idempotent, resumable rooms:** No 20-second `CONNECT_DEADLINE_MS` evictions. Rooms persist across laptop sleep, keep durable ordered history (`seq`), support `resume(last_seq)`, and hibernate cleanly on Cloudflare DO at `$0` idle cost.
5. **Username-only UX:** Clients never display `party_id`, `device_id`, `party_epoch`, `relay_policy`, `mppi1_`, or 60-digit safety numbers in normal UX.

---

## 2. High-Level Room REST API (Username & 4-Char Code First)

All authenticated calls use existing device RFC 9421 signing OR cloud session bearer token (`Authorization: Bearer <token>` for browser/cloud-session clients).

### `POST /v1/rooms/invite`
Creates a room automatically if `party_id` is omitted, puts the caller in it, and optionally pushes a live invite to `@handle` over `AccountDO` `/v1/ws`.
- **Request:** `{ "handle": "phall" (optional), "party_id": 12345 (optional), "name": "Friday Build" (optional) }`
- **Response (`200`):**
  ```json
  {
    "party_id": 1234567890,
    "room_code": "KAIH",
    "share_url": "https://multiplayer.tech/p/KAIH",
    "handle_url": "https://multiplayer.tech/@antimeme",
    "ws_path": "/v1/parties/1234567890/ws",
    "invited_handle": "phall"
  }
  ```

### `POST /v1/rooms/enter`
Single universal idempotent resolver: creates/joins a party by `@handle`, 4-char `room_code`, `mp.gg/...` / `multiplayer.tech/...` URL, legacy `mppi1_...` token, numeric `party_id`, OR empty (`""` = accept caller's latest pending incoming invite!).
- **Request:** `{ "target": "@phall" | "KAIH" | "" | "https://..." | "mppi1_..." | "123456", "client": "blackbird" | "outpost" | "web", "agent_name": "Claude Code" (optional) }`
- **Resolution order:**
  1. Empty `target` → accepts caller's newest unexpired `pending_party_invites` entry.
  2. `@handle` → if caller has a pending invite from `@handle`, accept it; else if `@handle` is a mutual friend with an active joinable room, join it directly.
  3. 4-char uppercase alphanumeric `room_code` (A–Z, 2–9 excluding ambiguous `0/O/1/I/L`) → join matching active room.
  4. Full URL (`/@handle` or `/p/CODE`) → extract target and apply rules 2–3.
  5. Legacy `mppi1_<pid>_<secret>` or numeric `<pid>` → join transparently.
- **Response (`200`):**
  ```json
  {
    "party_id": 1234567890,
    "room_code": "KAIH",
    "name": "antimeme's party",
    "share_url": "https://multiplayer.tech/p/KAIH",
    "ws_path": "/v1/parties/1234567890/ws",
    "members": [
      { "account_id": 3541107795115782, "handle": "antimeme", "client": "blackbird", "agent_name": "Blackbird", "status": "live" }
    ]
  }
  ```

### `POST /v1/rooms/leave`
- **Request:** `{ "party_id": 1234567890 }`
- **Response (`200`):** `{ "left": true, "party_id": 1234567890 }`

### `GET /v1/friends/live`
Returns friends with live presence + active joinable room summary (Xbox Live friends list):
```json
{
  "friends": [
    { "account_id": 285954035275878, "handle": "phall", "state": "friend", "presence": "in_party", "client": "outpost", "party_room_code": "KAIH", "joinable": true }
  ],
  "pending_invites": [
    { "party_id": 1234567890, "room_code": "KAIH", "from_handle": "phall", "created_at_ms": 1795495422986 }
  ]
}
```

---

## 3. `mp2` WebSocket Room Protocol (`GET /v1/parties/:id/ws`)

- Client requests `Sec-WebSocket-Protocol: mp2` (legacy `mp1` continues to work unchanged for backward compatibility).
- Frames are UTF-8 JSON text frames (`<= 48 KiB` total frame cap; `body <= 32 KiB`).
- Heartbeat: client sends `{"v":2,"t":"ping"}` (or text `"MP2:PING"` handled by Cloudflare `setWebSocketAutoResponse` with `"MP2:PONG"` at `$0` DO wakeup cost).

### Server → Client Frames
1. **`hello` (sent immediately upon upgrade):**
   ```json
   {
     "v": 2,
     "t": "hello",
     "party_id": "1234567890",
     "room_code": "KAIH",
     "name": "antimeme's party",
     "self": { "account_id": "3541107795115782", "handle": "antimeme", "client": "blackbird" },
     "latest_seq": 12,
     "members": [
       { "account_id": "3541107795115782", "handle": "antimeme", "client": "blackbird", "agent_name": "Blackbird", "agent_state": "idle", "status": "live" },
       { "account_id": "285954035275878", "handle": "phall", "client": "outpost", "agent_name": "Claude Code", "agent_state": "working", "status": "live" }
     ],
     "history": []
   }
   ```
2. **`event` (authoritative sequenced room event — chat, agent card, or system notice):**
   ```json
   {
     "v": 2,
     "t": "event",
     "seq": 13,
     "ts_ms": 1795495430000,
     "client_msg_id": "c7a1f0e2-...",
     "sender": { "account_id": "285954035275878", "handle": "phall", "client": "outpost", "agent_name": "Claude Code" },
     "target": "@all",
     "kind": "chat",
     "body_encoding": "utf8",
     "body": "yo can you see this?"
   }
   ```
   - `kind`: `"chat"` | `"agent_card"` | `"system"`
   - `body_encoding`: `"utf8"` | `"opaque_b64"` (for future E2EE / structured opaque payloads)
   - For `"agent_card"` (`utf8`), clients serialize a compact JSON string inside `body` (e.g. `{"title":"Fixed auth test","summary":"2 files changed","files":["src/auth.ts"]}`) — `PartyDO` treats `body` strictly as an opaque string!
3. **`ack` (delivery proof for optimistic client UI):**
   ```json
   { "v": 2, "t": "ack", "client_msg_id": "c7a1f0e2-...", "seq": 13, "ts_ms": 1795495430000 }
   ```
4. **`presence` (ephemeral live roster & agent state update):**
   ```json
   { "v": 2, "t": "presence", "members": [ ... ] }
   ```
5. **`error` (plain-English recoverable error, never raw internal code alone):**
   ```json
   { "v": 2, "t": "error", "code": "rate_limited", "message": "Slow down — retrying in 2s", "retry_ms": 2000 }
   ```

### Client → Server Frames
1. **`send` (idempotent on `client_msg_id` — retries never duplicate!):**
   ```json
   { "v": 2, "t": "send", "client_msg_id": "c7a1f0e2-...", "kind": "chat", "target": "@all", "body_encoding": "utf8", "body": "hey!" }
   ```
2. **`resume` (catch up every event with `seq > last_seq`, up to 200 per batch):**
   ```json
   { "v": 2, "t": "resume", "last_seq": 12 }
   ```
3. **`status` (update local client/agent status pill):**
   ```json
   { "v": 2, "t": "status", "client": "blackbird", "agent_name": "Blackbird", "agent_state": "working", "agent_summary": "Running tests" }
   ```

---

## 4. Non-Device-Bound Cloud Auth Contract (`AccountDO` + Portal)

1. **`AccountDO` `custody_mode`:**
   - `0 = cloud_managed` (default for new accounts & upgraded consumer accounts): `AccountDO` stores envelope-encrypted `account_signing_seed_enc` (AES-256-GCM with Workers KEK) and publishes `root_pubkey` to `accounts_index` identically to legacy accounts.
   - `1 = self_custody` (opt-in Citadel/Enterprise): client retains `root.seed` offline.
2. **Browser-First CLI Login Flow (`blackbird login` / `mp-outpost login`):**
   - `POST /v1/auth/session/start` (unauthenticated, rate-limited):
     - Request: `{ "device_pubkey_b64": "...", "device_label": "MacBook Pro", "client": "blackbird"|"outpost" }`
     - Response: `{ "flow_id": "...", "poll_token": "...", "user_code": "ABCD-EFGH", "verify_url": "https://multiplayer.tech/login?code=ABCD-EFGH", "expires_at_ms": ... }`
   - User opens `verify_url` in browser (auto-opened by CLI on macOS/Windows/Linux, or printed with QR on SSH), signs in via **Passkey** (`webauthn.ts`), **Email Magic Code**, or **OAuth**, claims `@handle` if new, and clicks **Continue**.
   - `AccountDO` enrolls `device_pubkey` (bumping active device cap to `32` with oldest-idle LRU eviction) and server-signs a **7-day `device_cwt`** + session bearer token.
   - `POST /v1/auth/session/poll`:
     - Request: `{ "flow_id": "...", "poll_token": "..." }`
     - Response: `{ "status": "pending" }` or `{ "status": "approved", "account_id": ..., "handle": "antimeme", "device_id": ..., "root_pubkey_b64": "...", "device_cwt_b64": "...", "cwt_expires_ms": ..., "session_token": "..." }`
3. **Silent Background Auto-Renewal:**
   - `POST /v1/devices/me/renew` (RFC 9421 device-key authenticated): for `custody_mode = 0` accounts, mints a fresh 7-day `device_cwt` seamlessly whenever `< 3` days remain.
4. **Browser Live Party Front Door (`GET /@:handle` and `GET /p/:code`):**
   - Renders OpenGraph rich share card (`@phall invited you to a party · 2 live`) AND serves a self-contained single-page live web party client (zero build step needed — vanilla ES module + CSS served cleanly by Worker) supporting instant **Guest Join** (temporary display name -> short-lived guest WS token scoped strictly to that room!) or **Sign In** -> live `mp2` WSS chat + agent activity cards + 1-click download / Outpost connect!
