# Blackbird Party Lobby & P2P Wire Protocol (Draft Input for Frumentarii & Design)

**Status:** Working draft input (NOT a frozen v1 standard) — captures Blackbird's current client scaffolding as concrete input for the `multiplayer_site` / Blackbird Frumentarii research and adversarial design phase.

> **HARD CRYPTOGRAPHY DOCTRINE (Operator 2026-11-23):**
> - **No homebrew primitives:** use ONLY audited, vibrant open-source cryptographic libraries (discussed and approved with the operator before adoption).
> - **No homebrew protocols:** rolling a custom protocol is as dangerous as rolling a custom primitive. All production P2P transport, authentication, and multi-party E2EE MUST follow standardized, formally analyzed protocols implemented as the giants built them:
>   - **P2P Transport & Mutual Auth:** **TLS 1.3 / QUIC (RFC 9000 / RFC 9001)** or **Noise Protocol Framework (`Noise_XX` / `Noise_IK`, as in WireGuard/Tailscale/iroh)** — never a custom handshake or custom framing cipher.
>   - **Multi-Party Group E2EE & Membership (Join / Leave / Kick / PCS / Forward Secrecy):** **MLS (RFC 9420, TreeKEM)** — or **Keyhive / BeeKEM** if local-first partition tolerance requires it — never a homebrew group-key or ad-hoc epoch protocol.
>   - **Signed Objects:** **OpenSSH `SSHSIG`** (with strict namespace domain separation) or **COSE (RFC 9052)** / **MLS Application Messages**, never ad-hoc string concatenation.
>   - **NAT Traversal & Rendezvous:** **ICE (RFC 8445) / STUN (RFC 8489) / QUIC** + Tailscale/iroh-style authenticated rendezvous signaling.
> - Current JSON `PartyLease` / `PeerEnvelope` / `BlindRelayRouter` structures in Blackbird are **local development scaffolding** (and local loopback IPC), NOT a substitute for Noise/TLS 1.3/QUIC + MLS (RFC 9420).

**Open Design Questions for Frumentarii & Review:**
- **Standard protocol selection & reference libraries:** MLS (RFC 9420, e.g. OpenMLS / MLSpp) vs. Keyhive/BeeKEM for partition-tolerant agentic rooms; Noise (`Noise_IK`/`Noise_XX`) vs. mTLS 1.3 over QUIC (msquic / quiche / iroh) for P2P transport; candidate vibrant open-source C++ / Rust libraries to propose to the operator.
- **NAT traversal & hole-punching strategy:** ICE/STUN/QUIC vs. Tailscale/iroh-style DERP fallback; symmetric-NAT relay policy without breaking the "P2P data plane" invariant.
- **Lobby control-plane security:** standard challenge-response / WebAuthn / Noise / TLS 1.3 client auth, anti-Sybil/anti-DoS economics, invite binding, and revocation propagation.
- **Local loopback hub (`party.sock`):** kernel UID-verified (`LOCAL_PEERCRED`/`SO_PEERCRED`) IPC syncing local Blackbird windows with the standardized P2P/MLS session state.

## Core Boundary: Control Plane vs. P2P Data Plane

- **Lobby Server (Control Plane ONLY):** tracks and facilitates the **making and unmaking of parties** — Ed25519 identity/challenge verification, ephemeral signed membership leases (`CREATE`, `INVITE`, `JOIN`, `HEARTBEAT`, `LEAVE`, `KICK`, `REVOKE`), and P2P endpoint / rendezvous signaling.
- **Peer-to-Peer Mesh (Data Plane):** **all actual party bits fly P2P** directly between Blackbird peers (Tailscale / direct QUIC/UDP / SSH / `phux` tunnel) using Blackbird's Ed25519-signed `PeerEnvelope`, `BoardBridge` causal event DAG, 3-lane `BridgeMux`, and anti-rollback `BridgeCheckpoint`.
- **Zero Plaintext on the Lobby Server:** prompts, code, tool outputs, party chat bodies, and secrets **never** pass through the lobby server. Even signaling metadata is bounded and non-authoritative unless backed by a peer's Ed25519 signature.

---

## 1. Peer Identity (`include/blackbird/peer_identity.hpp`)

- **Key type:** OpenSSH Ed25519 (`ssh-ed25519`).
- **Fingerprint format:** `bb1-<32 lowercase hex chars>` = first 16 bytes (128 bits) of `SHA-256` over the canonical OpenSSH public key line (`ssh-ed25519 <base64>`).
- **Proof of possession:** Every mutating lobby action MUST be signed by the actor's Ed25519 private key (detached signature over canonical JSON or challenge nonce). The server NEVER authenticates a peer by public fingerprint or bearer token alone.
- **Durable trust book (client-side):** `~/.local/share/blackbird/peers/` (`KnownPeersStore`) is the operator's durable friends list (`alias`, `public_key`, `fingerprint`, `revoked`). Ephemeral party membership NEVER lives in static repo files.

---

## 2. Ephemeral Signed Party Leases (`PartyLease`)

Party membership is **purely ephemeral**, represented by short-TTL Ed25519-signed leases held in RAM and renewed via heartbeat:

```json
{
  "version": 1,
  "party_id": "party-9f4c2a1b",
  "room_scope": "party/rollcall",
  "actor_fingerprint": "bb1-f895ec8f54cd6a0bbb51666848252ffd",
  "actor_public_key": "ssh-ed25519 AAAA...",
  "alias": "laptop",
  "role": "operator_human",
  "host": "laptop",
  "model": "gpt-6.1-sol",
  "p2p_endpoints": [
    {"transport": "tailscale-ssh", "addr": "patrick@laptop"},
    {"transport": "quic", "addr": "100.x.y.z:8788"}
  ],
  "issued_ns": 1795434000000000000,
  "expires_ns": 1795434300000000000,
  "lease_seq": 1,
  "revocation_epoch": 0,
  "signature_b64": "<ed25519 signature over canonical lease payload>"
}
```

### Lease Invariants
- **Short TTL:** Default `300s` (max `3600s`). Clients renew via `HEARTBEAT`; crashed or disconnected nodes expire automatically with zero ghost members.
- **Monotonic `lease_seq`:** Higher `lease_seq` supersedes lower for the same `(party_id, actor_fingerprint)`.
- **Revocation epoch:** If a peer is kicked or revoked (`REVOKE` / `KICK`), `revocation_epoch` increments and any lease referencing the revoked peer or stale epoch is evicted immediately.
- **Roles:** `operator_human` | `platoon_leader` | `worker`. Auto-mode: `>1` distinct `operator_human` = `multi_operator`; `<=1` = `single_operator`.
- **Untrusted endpoint guard:** Clients MUST verify a peer's `actor_fingerprint` against local `KnownPeersStore` (or explicit operator invite acceptance) before dialing any advertised `p2p_endpoints`.

---

## 3. Lobby Control Plane Operations (Making & Unmaking Parties)

All lobby calls operate strictly on membership and P2P rendezvous:

| Operation | Direction | Purpose |
|---|---|---|
| `POST /v1/auth/challenge` | Client -> Lobby | Request short-lived random nonce for Ed25519 login/proof-of-possession. |
| `POST /v1/parties` | Host -> Lobby | Create a new ephemeral party (`party_id`, `room_scope`, host `PartyLease`). |
| `POST /v1/parties/{id}/invites` | Host -> Lobby | Mint a short-lived signed invite (`bbjoin1:...` URI + expiry TTL). |
| `POST /v1/parties/{id}/join` | Peer -> Lobby | Present invite code + signed `PartyLease` + `p2p_endpoints` to join party. |
| `POST /v1/parties/{id}/heartbeat` | Member -> Lobby | Renew `PartyLease` TTL and update advertised `p2p_endpoints` / `state` (`online`/`working`/`idle`). |
| `POST /v1/parties/{id}/leave` | Member -> Lobby | Signed voluntary departure; immediately notifies remaining members. |
| `POST /v1/parties/{id}/kick` | Host -> Lobby | Signed removal + `revocation_epoch` bump; immediately notifies remaining members. |
| `DELETE /v1/parties/{id}` | Host -> Lobby | Unmake/dissolve the party cleanly across all members. |
| `GET /v1/parties/{id}` / SSE / WS | Member <- Lobby | Live roster & `p2p_endpoints` stream (`member_joined`, `member_left`, `member_expired`, `party_dissolved`, `endpoint_updated`). |
| `POST /v1/parties/{id}/signal` | Peer <-> Peer via Lobby | Optional NAT-traversal / ICE / QUIC hole-punch signaling envelopes only (no payload bytes). |

### Local Loopback Hub (`party.sock`)
On a single operator machine, Blackbird's local `PartyLobbyServer` (`include/blackbird/party_lobby.hpp`) exposes the same membership semantics over a UID-verified Unix socket (`$XDG_RUNTIME_DIR/blackbird/party.sock` or `/tmp/blackbird-$UID/party.sock`, `0700`/`0600`, `LOCAL_PEERCRED`/`SO_PEERCRED`), syncing main Blackbird, `/cwd` moves, and detached `blackbird flightdeck` windows cleanly in RAM — and syncing upstream with the remote Lobby Server when online.

---

## 4. Invite URI Format (`bbjoin1:...`, `include/blackbird/bridge_relay.hpp`)

```text
bbjoin1:<base64url-no-pad(canonical JSON)>
```

Canonical JSON fields:
- `room_id`: string (`party_id` or room scope)
- `relay_url`: string (HTTPS/WSS URL of the Lobby Server — e.g. `https://multiplayer.tech/v1` — or direct P2P bootstrap URL)
- `creator_fingerprint`: `bb1-<32 hex>`
- `creator_public_key`: OpenSSH `ssh-ed25519 ...`
- `invite_code`: 128-bit CSPRNG room-join bearer credential (single-use or short-TTL on server)
- `expires_ns`: int64 Unix nanoseconds (clients & server both enforce `now_ns <= expires_ns`)

---

## 5. P2P Data Plane (Directly Between Blackbird Peers)

Once the Lobby Server introduces members and delivers their verified `p2p_endpoints`, all party traffic flows **directly P2P**:

1. **Signed Envelopes (`include/blackbird/peer_identity.hpp`, `board_bridge.hpp`):**
   - `PeerEnvelope`: `{version, envelope_id, from_fingerprint, to_fingerprint, kind, payload, created_ns, signature_b64}`.
   - Wrapped in `<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN>>>` / `<<<BLACKBIRD_UNTRUSTED_PEER_DATA_END>>>` provenance fences on every receiving model.
2. **Causal DAG & Conflict Detection (`BoardBridge`):**
   - Each event carries `actor_id`, `actor_seq`, `event_hash`, `causal_parents[]`, `resource_scope`, `kind`, `payload`.
   - Concurrent unlinked writes to the same `resource_scope` surface automatically as conflicts; action-time `check_action_guard()` blocks mutating actions while verified unread peer mail is pending.
   - Durable `ReadReceipt`s bind to `event_hash` + `request_hash`.
3. **3-Lane Priority Multiplexer (`BridgeMux`, `bridge_relay.hpp`):**
   - **Lane 0 (Preemptive Control):** `JOIN`, `LEAVE`, `REVOKE`, `CHECKPOINT`.
   - **Lane 1 (Causal Reliable):** party chat, leader updates, receipts, grants — sender-scoped `(sender_fingerprint, frame_id)` dedupe, contiguous ack / `needs_resync` anti-drop guarantee.
   - **Lane 2 (Latest-Wins MRS Ephemeral):** typing indicators, watcher presence, live telemetry ticks.
4. **Anti-Rollback Late-Join Sync (`BridgeCheckpoint`):**
   - Signed snapshot of `(room_id, checkpoint_seq, actor_watermarks, causal_frontier, revoked_grant_ids, created_ns, signer_fingerprint, signature_b64)` verified with `expected_room_id`, `min_checkpoint_seq`, freshness window, and `allowed_signers`.
