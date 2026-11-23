# Multiplayer Gaming Networking, Connection & Resource-Leasing Wisdom for Blackbird

**Date:** 2026-11-23  
**Scope:** Architectural synthesis of 30 years of real-time multiplayer game engineering mapped directly onto Blackbird's sovereign multi-agent Command Post (`BoardBridge`, `PeerIdentityStore`, `KnownPeersStore`, `WorktreeLeaseManager`, `PlatoonBoard`, `PlatoonRunner`, `SpendLedger`, and `authorize_tool_call`) across **Stage 0 -> Stage 2**.  
**Doctrine Note:** Study and architectural reference only. Adopting any third-party networking library remains gated on explicit operator discussion and owned-machinery tradeoffs.

---

## Executive Summary

Real-time multiplayer games solved the hardest practical problems of sovereign, multi-principal, latency-sensitive distributed collaboration decades before multi-agent coding systems existed: hostile or flaky endpoints behind home/corporate NATs, roaming laptops, strict per-client bandwidth/compute budgets, optimistic local execution against authoritative truth, lease reclamation across silent crashes, late-joining observers, and abusive peers inside long-running matches.

Mapping game netcode onto Blackbird yields a direct structural isomorphism:

| Multiplayer Gaming Primitive | Blackbird Command Post Equivalent |
| :--- | :--- |
| Game server / authoritative host | Local operator host (`KnownPeersStore`, `authorize_tool_call`, `SpendLedger`) |
| Client-side prediction buffer | Isolated `WorktreeLeaseManager` git worktree & branch |
| Bandwidth budget (bytes/sec) | Context & token budget (`SpendPolicy`, prompt window, attention economy) |
| Spatial Area of Interest (AoI) / Replication Graph | `resource_scope` & `command_room` subscription filtering |
| Reliable ordered vs unreliable MRS lanes | Control/grants/revocations vs ephemeral `PresenceRecord` heartbeats |
| Snapshot + delta tail catch-up | Signed `BoardBridge` state checkpoints + post-checkpoint `CausalEvent` tail |
| SourceTV / GOTV spectator relays | Read-only live watchers (`active_watchers`) decoupled from peer/worktree slots |
| `net_chan_limit_msec` & token buckets | Per-peer signature-verify & frame admission budgets (`BoardBridge::pump_inbound`) |

### Top 5 Immediately Actionable Lessons (Stage 0 -> Stage 2)

1. **Split the Wire into 3 Logical Lanes (Zero HoL Blocking):** Never multiplex high-priority revocations/grants, multi-megabyte diffs/artifacts, and ephemeral `PresenceRecord` heartbeats onto one FIFO stream or append-only replay log (Tribes MRS + Valve `GameNetworkingSockets` lanes).
2. **Treat Token & Context Budget as Network Bandwidth (Replication Graph + Fog of War):** Never broadcast raw peer tool output to every room; filter replication by `resource_scope` / `command_room`, keep private tool traces owner-only, and serialize/quote summaries once for fan-out (Unreal Replication Graph + *VALORANT* Fog of War).
3. **Add Monotonic Fencing Epochs + Soft/Hard Grace Windows to Every Lease:** Bare PID checks and wall-clock timestamps fail across laptop sleep, Wi-Fi blips, and clock jumps; pair `WorktreeLeaseInfo` and `CausalEvent` claims with monotonic `lease_epoch` fencing tokens and a `3H` suspect / `6H–10H` reclaim grace window (Kleppmann fencing tokens + game-server reconnect windows).
4. **Replace Full-History `replay_outbound()` with Signed Checkpoints + Delta Tail:** Replaying thousands of raw envelopes on reconnect causes late-join storms; emit periodic signed snapshots of active grants, revocations, leases, and causal frontier hashes plus only the delta tail (Quake III baseline+delta + Factorio FFF #147/#149).
5. **Enforce Per-Peer Admission & CPU Caps Before Cryptographic Verification:** Today `KnownPeersStore::verify_envelope()` shells out to `ssh-keygen -Y verify`; without per-peer token buckets, tight control-frame caps, and a `net_chan_limit_msec`-style verification budget, one runaway or prompt-injected peer can CPU-starve the entire Command Post.

---

## 1. Connections, NAT Traversal & Roaming (Leaving the Lab)

### Concrete Gaming & Transport Mechanisms
* **ICE/STUN Hole-Punching vs. Blind/Encrypted Relays:** Classical P2P traversal (ICE, [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445)) gathers host, server-reflexive (STUN), and relayed ([TURN, RFC 8656](https://www.rfc-editor.org/rfc/rfc8656)) candidates and runs connectivity checks to punch UDP holes through NATs. As documented in Tailscale's engineering deep dive [*How NAT traversal works*](https://tailscale.com/blog/how-nat-traversal-works), stateful firewalls, hard/symmetric NATs, and carrier-grade NATs (CGNAT) routinely defeat direct UDP hole-punching, especially across mobile and corporate networks.
* **Why Modern Games Default to Relay-First (or Instant Relay + Direct Upgrade):** Valve's [Steam Datagram Relay (SDR)](https://partner.steamgames.com/doc/features/multiplayer/steamdatagramrelay) and open-source [`GameNetworkingSockets`](https://github.com/ValveSoftware/GameNetworkingSockets) route traffic through authenticated, encrypted relay PoPs by default rather than exposing raw client/server IP addresses. Tailscale's **DERP** (*Designated Encrypted Relay for Packets*) starts every peer connection immediately over an outbound TLS-on-443 encrypted relay while attempting direct UDP hole-punching in parallel, seamlessly upgrading if direct succeeds and falling back without dropping packets if NAT rules shift.
* **Connection Migration Beyond the 4-Tuple:** TCP binds connection identity to `(src_ip, src_port, dst_ip, dst_port)`; switching Wi-Fi to LTE or waking a laptop breaks the socket. QUIC ([RFC 9000, Section 9](https://www.rfc-editor.org/rfc/rfc9000)) decouples session identity from IP/port using opaque **Connection IDs** rotated via `NEW_CONNECTION_ID`. Before shifting traffic to a new address, RFC 9000 Section 8.2 mandates cryptographic **Path Validation** (`PATH_CHALLENGE` / `PATH_RESPONSE`) to defeat off-path spoofing and reflection amplification, and resets path congestion control state (Section 9.4) because the new interface has different RTT and bandwidth.

### Real-World Failure Modes
* **Lab-to-WAN Cliff:** Protocols tested over localhost or LAN break immediately behind hotel Wi-Fi, CGNAT, or dual-NAT home routers when direct inbound TCP/UDP ports are unreachable.
* **Endpoint IP Exposure & Drop-Hacking:** Direct P2P leaks participant IPs to every peer in the session, enabling targeted DoS against a host or developer workstation (the primary motivation for Valve SDR).
* **Sleep/Roam Session Tears:** Long-lived SSH/TCP pipes stall silently when a laptop closes its lid or roams networks, hanging until OS TCP keepalive timeouts expire and forcing full reconnect and replay cycles.

### Blackbird Command Post Mapping (Stage 0 -> Stage 2)
* **Stage 0 (Present):** `BoardBridge` transports signed `PeerEnvelope` NDJSON frames over stdio/SSH pipes (`send_envelope`, `pump_inbound`, `replay_outbound`). Works cleanly on LAN, SSH, or private mesh overlays, with exact duplicate suppression via `envelope_id` on reconnect.
* **Stage 1 (WAN-Ready Roaming):** Decouple **peer session identity** (Ed25519 `PeerIdentity::fingerprint` + opaque `session_id`) from the underlying transport pipe. Add explicit application-level keepalive + challenge-nonce path verification (`PATH_CHALLENGE` analog) on reconnect so resumed pipes bind cleanly to the existing session cursor without full replay.
* **Stage 2 (Sovereign Blind Relay):** Introduce a minimal, zero-knowledge encrypted rendezvous relay (SDR/DERP pattern) over outbound TLS/443 or QUIC. Because `PeerEnvelope` objects are already end-to-end signed by `PeerIdentityStore` (and can carry AEAD ciphertext payloads in Stage 2), the relay never sees plaintext prompts, code, or grants, never becomes a governance authority, and enables instant connection startup with optional P2P upgrade.

---

## 2. Channel Separation (Reliable Ordered vs. Latest-Wins Unreliable)

### Concrete Gaming Mechanisms
* **TCP Head-of-Line (HoL) Blocking:** Glenn Fiedler's [*UDP vs. TCP*](https://gafferongames.com/post/udp_vs_tcp/) and [*Reliability, Ordering and Congestion Avoidance over UDP*](https://gafferongames.com/post/reliability_ordering_and_congestion_avoidance_over_udp/) demonstrate why multiplexing volatile real-time state over a single reliable ordered byte stream causes latency spikes: one dropped packet stalls delivery of every newer packet behind it until retransmission completes.
* **The Tribes 4-Tier Delivery Taxonomy:** Mark Frohnmayer and Tim Gift's [*The TRIBES Engine Networking Model*](https://www.gamedevs.org/uploads/tribes-networking-model.pdf) classified game messages into four explicit delivery semantics rather than forcing uniform reliability:
  1. **Guaranteed Ordered:** Critical state transitions and control commands.
  2. **Guaranteed Quickest:** Must arrive, but delivery is not blocked by earlier unrelated messages.
  3. **Most Recent State (MRS):** Only the latest value matters; dropped intermediate states are skipped entirely in favor of the freshest snapshot.
  4. **Non-Guaranteed:** Fire-and-forget telemetry/effects.
* **Valve Connection Lanes & Quake III Stateless Snapshots:** Valve's [`ISteamNetworkingSockets`](https://partner.steamgames.com/doc/api/ISteamNetworkingSockets) (`ConfigureConnectionLanes`, [`steamnetworkingtypes.h`](https://github.com/ValveSoftware/GameNetworkingSockets/blob/master/include/steam/steamnetworkingtypes.h)) multiplexes independent **lanes** over one connection, each with its own sequence space, numeric **priority** (strictly drained before lower-priority lanes), **bandwidth weight**, and per-message reliability flags (`k_nSteamNetworkingSend_Reliable` vs. `k_nSteamNetworkingSend_Unreliable` / `NoDelay`). Quake III ([`sv_snapshot.c`](https://github.com/id-Software/Quake-III-Arena/blob/master/code/server/sv_snapshot.c), [`net_chan.c`](https://github.com/id-Software/Quake-III-Arena/blob/master/code/qcommon/net_chan.c)) goes even further for world state: every update is delta-compressed against the client's last ACKed snapshot, eliminating separate retransmission queues for state updates entirely.

### Real-World Failure Modes
* **Kill-Switch Starvation:** A 3.5 MiB diff or artifact envelope saturates a single FIFO pipe, delaying a 300-byte `CapabilityGrant` revocation or `recall` envelope by seconds—during which a remote peer executes additional unrevoked tool calls.
* **Reconnect Presence Storms:** Persisting ephemeral heartbeats or progress updates as reliable ordered messages causes thousands of obsolete "thinking…" / "watching…" frames to replay in order after a brief disconnect, burning bandwidth, disk, and TUI render cycles.
* **Reliable Queue Memory Blowup:** Queueing ephemeral status frames on a reliable channel during a partition causes unbounded memory/disk growth for state that is already stale by the time the link recovers.

### Blackbird Command Post Mapping (Stage 0 -> Stage 2)
* **Stage 0 (Present):** `BoardBridge` frames `CausalEvent`, `MessageReceipt`, and `PresenceRecord` uniformly as signed `PeerEnvelope` NDJSON lines on one sequential stream, and `replay_outbound()` replays persisted outbound envelopes sequentially.
* **Stage 1/2 (Three-Lane Multiplexing):** Partition Blackbird traffic into explicit logical lanes with distinct persistence and delivery rules:

| Lane | Priority | Delivery Semantics | Durable Replay? | Blackbird Payloads |
| :--- | :--- | :--- | :--- | :--- |
| **Lane 0: Control** | Highest (preemptive) | Reliable, ordered, small-frame cap (e.g. <= 16 KiB) | Yes (compacted into checkpoints) | `PeerEnvelopeKind::recall`, grant/peer revocations, `CapabilityGrant`, lease fencing updates, `ActionGuard` blocks |
| **Lane 1: Work & Causal** | Normal (weighted) | Reliable, causally ordered / chunkable | Yes (DAG + checkpoint tail) | `CausalEvent` (briefs, handoffs, decisions, reviews, artifacts), `MessageReceipt` (`included_in_request`, `acted`) |
| **Lane 2: Ephemeral State** | Best-effort (coalesced) | **Most Recent State (MRS)** / latest-wins, unreliable | **No** (bounded in-memory ring / latest-map) | `PresenceRecord` heartbeats, watcher status, typing/thinking indicators, progress gauges |

* **Immediate Stage 0/1 Win:** Stop persisting `PresenceRecord` envelopes into the durable replay stream (`replay_outbound`); keep only a latest-wins map keyed by `(actor_id, watching_scope)` so reconnects transmit at most one current presence frame per active watcher.

---

## 3. Interest Management & Relevancy (Anti-Noise / Bandwidth / Token Budget)

### Concrete Gaming Mechanisms
* **Per-Connection Actor Relevancy:** Unreal Engine's [Actor Relevancy](https://dev.epicgames.com/documentation/en-us/unreal-engine/actor-relevancy-in-unreal-engine) computes a per-connection relevant set (`IsNetRelevantFor`), classifying actors into **Always Relevant** (`bAlwaysRelevant`, e.g., global match rules), **Owner-Only** (`bOnlyRelevantToOwner`, e.g., private inventory/HUD), and **Distance/Scope-Culled** entities.
* **Replication Graph & Fast Shared Path:** Evaluating every actor against every client every tick is $O(\text{Actors} \times \text{Clients})$ and collapses at scale. Epic built the [Replication Graph](https://dev.epicgames.com/documentation/en-us/unreal-engine/replication-graph-in-unreal-engine) for *Fortnite* (100 players, ~50,000 replicated actors): actors are routed on spawn/change into persistent graph nodes (spatial grid nodes like `GridSpatialization2D`, global always-relevant nodes, per-connection nodes) that cache and reuse candidate lists across frames. Its **Fast Shared Path** serializes shared actor state *once* per frame and fans out the serialized bytes to every relevant connection instead of re-serializing per client.
* **Security-Driven Relevancy (Fog of War):** In [*Demolishing Wallhacks with VALORANT's Fog of War*](https://technology.riotgames.com/news/demolishing-wallhacks-valorants-fog-war), Riot withholds opponent coordinates on the server until an enemy is near line-of-sight. Relevancy is not merely bandwidth optimization—it is an information-isolation boundary: a client cannot exploit or leak state it never received.

### Real-World Failure Modes
* **$O(N^2)$ Context & Spend Explosion:** Broadcasting every peer's raw tool outputs, compiler logs, and intermediate thoughts to all $N$ agents in a platoon turns every token into $N \times$ input token spend, fills context windows with irrelevant noise, and degrades model reasoning accuracy.
* **Cross-Agent Prompt Injection Amplification:** Without Fog-of-War isolation, an untrusted web page or test fixture read by Peer A gets broadcast verbatim to Peers B, C, and D, turning one local indirect prompt injection into a platoon-wide compromise.
* **Redundant Multi-Model Parsing:** Sending a 200 KiB build failure log to 6 peer models forces 6 separate frontier-model context ingestions to extract the same 5-line root cause.

### Blackbird Command Post Mapping (Stage 0 -> Stage 2)
* **Stage 0 (Present):** `BoardBridge` already carries `resource_scope` on `CausalEvent`, `watching_scope` on `PresenceRecord`, `command_room` on `CapabilityGrant` and `PlatoonPeerSpec`, `recipient_filter` on `PlatoonBoard::read_since`, and `format_quoted_peer_frame()` for data-only peer provenance.
* **Stage 1/2 (Scope-Indexed Replication Graph for Agents):**
  * **Always-Relevant Node (Room Control):** Revocations, recalls, room-wide architectural decisions, and `ConcurrentClaimConflict` alerts replicate to every active peer in the `command_room`.
  * **Scope-Filtered Node (`resource_scope` AoI):** Maintain a persistent index mapping hierarchical `resource_scope` prefixes (e.g., `repo:src/board_bridge.cpp`, `docs/*`) to subscribed peers and active worktree leases. A peer only receives full `CausalEvent` payloads intersecting its subscribed scopes or explicit `@mentions`; out-of-scope events arrive as compact 1-line digest headers (or not at all).
  * **Owner-Only Fog of War:** `PlatoonRunner::output_tail`, raw local tool outputs, local env/secrets, and unpromoted scratch files stay strictly `bOnlyRelevantToOwner`. Only explicitly authored, provenance-tagged `PeerEnvelope` artifacts cross host boundaries via `format_quoted_peer_frame()`.
  * **Fast Shared Path (Summarize Once, Fan Out Many):** When sharing large artifacts (test logs, diffs) across multiple peers, generate one bounded summary + content-addressed hash reference once at the producer/bridge boundary and fan out the compact summary rather than replicating raw logs into $K$ model contexts.

---

## 4. Authority, Anti-Cheat ("Never Trust the Client") & Optimistic Rollback

### Concrete Gaming Mechanisms
* **Strict Server Authority:** Valve's [*Source Multiplayer Networking*](https://developer.valvesoftware.com/wiki/Source_Multiplayer_Networking), Yahn Bernier's [*Latency Compensating Methods in Client/Server In-game Protocol Design and Optimization*](https://developer.valvesoftware.com/wiki/Latency_Compensating_Methods_in_Client/Server_In-game_Protocol_Design_and_Optimization), Tim Ford's GDC 2017 [*Overwatch Gameplay Architecture and Netcode*](https://www.gdcvault.com/play/1024001/-Overwatch-Gameplay-Architecture-and), and Riot's [*Peeking into VALORANT's Netcode*](https://technology.riotgames.com/news/peeking-valorants-netcode) enforce one iron rule: **the authoritative host never trusts client-computed outcomes.** Clients submit *intent/requests* (timestamped commands); the authority validates invariants, executes state transitions, and returns ground truth.
* **Why Deterministic Lockstep Fails for LLM Agents:** Classic RTS engines (*Age of Empires*, Paul Bettner & Mark Terrano, [*1500 Archers on a 28.8*](https://www.gamedeveloper.com/programming/1500-archers-on-a-28-8-network-programming-in-age-of-empires-and-beyond); Factorio [FFF #63](https://factorio.com/blog/post/fff-63), [FFF #188](https://factorio.com/blog/post/fff-188), [FFF #340](https://factorio.com/blog/post/fff-340), [FFF #415](https://factorio.com/blog/post/fff-415); Glenn Fiedler's [*Deterministic Lockstep*](https://gafferongames.com/post/deterministic_lockstep/)) save bandwidth by broadcasting only inputs and requiring bit-identical simulation on every node. Even minor floating-point or thread-order divergence triggers an unrecoverable desync. LLM agents are inherently **stochastic, heterogeneous, and slow-RTT**—lockstep stalls every peer to the slowest model and cannot deterministically replay model completions across hosts.
* **Optimistic Execution + Bounded Rollback & Reconciliation:** Instead of lockstep, action shooters (Source, *Overwatch*, *Halo: Reach*) and fighting games (Tony Cannon's [GGPO](https://github.com/pond3r/ggpo); [Infil's Netcode Guide](https://ki.infil.net/w02-netcode.html)) execute optimistically on local state to hide latency, maintain a **bounded history/speculation window**, and explicitly reconcile when authoritative state diverges—rolling back and re-simulating or rejecting the invalid speculative branch. *Overwatch* uses ECS specifically to keep the networked/authoritative surface tiny and auditable.

### Real-World Failure Modes
* **Confused-Deputy & Client-Trusted Accounting:** Trusting a peer's self-reported `requested_by_actor`, spend total, or tool allowlist lets a buggy or prompt-injected peer bypass spend caps or execute privileged local tools (exact class of bug caught in Blackbird Kimi Review #3 M4/M5!).
* **Silent Reconciliation Clobbering:** Naive last-writer-wins merging overwrites another peer's concurrent edits without surfacing the causal fork.
* **Unbounded Speculative Horizon ("Mega-Rollback"):** Allowing a peer to work for 2 hours in isolation without reconciling against room decisions produces massive merge conflicts and wasted compute—the agent equivalent of a 60-frame GGPO teleport.

### Blackbird Command Post Mapping (Stage 0 -> Stage 2)
* **Owner-Side Authority Invariant (Already Strong in Stage 0):** Each human operator's host is the sole authority over its own filesystem, credentials, and tool execution. `authorize_tool_call()` re-verifies `KnownPeersStore::verify_grant()` (including local revocation kill-switch + TOCTOU re-check), grantee pinning, `allowed_tools`, expiry, and grant-level `SpendLedger` ceilings *locally at every tool call*, never trusting remote peer assertions.
* **Isolated Optimistic Prediction via `WorktreeLeaseManager`:** Each peer's git worktree/branch is its speculative prediction buffer. Peers edit, compile, and run tests locally with zero cross-host lockstep stalls.
* **Visible Semantic Reconciliation (No Silent Overwrites):**
  * `BoardBridge::check_action_guard()` blocks mutating actions when an unread foreign `CausalEvent` touches the same `resource_scope`, requiring cognitive inclusion (`ReceiptStage::included_in_request`) before proceeding—preventing blind divergence.
  * `BoardBridge::detect_concurrent_claims()` detects concurrent causal forks (neither hash is an ancestor of the other) on the same `resource_scope` and surfaces explicit `ConcurrentClaimConflict` records instead of silently picking a winner.
  * **Stage 1/2 Bounded Speculation Policy:** Enforce short, bounded commit/checkpoint cadences on leased worktrees (and fast rebase/reconcile checks against `base_sha`) so speculative drift stays small and rollback/cherry-pick remains cheap.

---

## 5. Resource Leasing, Heartbeats, Soft Expiry & Grace Windows

### Concrete Gaming & Distributed Systems Mechanisms
* **Monotonic Fencing Tokens (Epochs):** In [*How to do distributed locking*](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html), Martin Kleppmann proves why time-bounded leases alone are unsafe: a process paused by GC, laptop sleep, or network partition can wake up *after* its lease expired and another peer acquired the resource, then corrupt the resource with a stale write. The fix is a **strictly monotonic fencing token (epoch)** issued on every lease acquisition and checked by the downstream resource itself—any mutation carrying `epoch < current_epoch` is unconditionally rejected.
* **Monotonic Clocks vs. Wall Clocks:** Kleppmann and game engines alike forbid using wall-clock time (`gettimeofday` / NTP-adjustable clocks) for lease expiry durations; a backward or forward NTP jump either immortalizes a dead lease or triggers simultaneous dual ownership. Lease durations must be measured on a **monotonic clock** (`CLOCK_MONOTONIC` / `std::chrono::steady_clock`), while cross-host wire timestamps are clamped against bounded clock skew.
* **Heartbeat / Soft-Expiry / Hard-Expiry Ratios & Jitter:** Game servers (Glenn Fiedler's [*Client Server Connection*](https://gafferongames.com/post/client_server_connection/), Valve `GameNetworkingSockets` keepalive/timeout, competitive match reconnect windows) separate **heartbeat cadence** ($H$), **suspect / soft-expiry** (typically $3H$: mark peer "degraded/reconnecting", pause new assignments, *do not* reclaim seat/worktree yet), and **hard-expiry / grace timeout** (typically $6H\text{--}10H$ for transport or minutes for match-seat reclaim). Adding random jitter (e.g., $\pm 15\text{--}25\%$) to heartbeat intervals prevents synchronized thundering herds across large platoons.
* **Idempotent Rejoin:** Competitive games hold a disconnected player's slot through a grace window and allow idempotent rejoin using the player's cryptographic identity + match ticket without duplicating entities or wiping player inventory.

### Real-World Failure Modes
* **PID-Reuse & Immortal Leases:** Checking only `kill(pid, 0)` breaks on PID recycling or PID 1 (`EPERM`)—already fixed in Blackbird's `WorktreeLeaseManager` via UID + process start-time verification, but still local-PID-only rather than distributed-epoch-safe.
* **Wi-Fi Blip Worktree Thrashing:** Reclaiming a remote peer's leased worktree or scope immediately on a 5-second socket drop destroys momentum and creates unnecessary `orphaned_dirty` branches.
* **Sleeping-Laptop Zombie Writes:** Peer A's laptop sleeps for 20 minutes; its lease expires and Peer B takes over `src/foo.cpp`; Peer A wakes up and pushes commits or posts `acted` receipts for the old lease, colliding with Peer B.

### Blackbird Command Post Mapping (Stage 0 -> Stage 2)
* **Stage 0 (Present):** `WorktreeLeaseManager` persists `WorktreeLeaseInfo` with `owner_pid`, `created_ns`, `base_sha`, `head_sha`, and safely preserves dirty worktrees on `reclaim_stale()` in `WorktreeReclaimReport::orphaned_dirty`. `PresenceRecord` uses `updated_ns` + `ttl_ns` (bounded by `kBoardBridgeMaxTtlNs` and 60s future-skew clamp).
* **Stage 1/2 Upgrades:**
  1. **Add Monotonic `lease_epoch` to `WorktreeLeaseInfo` & `CausalEvent`:** Increment a persisted monotonic `lease_epoch` on every lease acquisition/re-assignment. Require merge/integration gates and `BoardBridge` claim handlers to verify `incoming.lease_epoch == active.lease_epoch`, rejecting waking zombies cleanly with `ErrorCode::conflict`.
  2. **Introduce Soft-Expiry vs. Hard-Expiry Lease States:** Track lease states `active -> suspect (grace window) -> reclaimed/quarantined` using local `steady_clock` elapsed deltas (plus jittered peer heartbeats). During `suspect`, hold the worktree/scope and block new conflicting claims; allow **idempotent rejoin** if the same Ed25519 `owner_id` returns with matching `(lease_id, lease_epoch)` before hard expiry.
  3. **Separate Transport Liveness from Worktree Custody:** A dropped SSH/relay socket transitions a peer's transport to `reconnecting`, *not* immediate worktree eviction; only an explicit `release()`, operator revocation, or expired grace window triggers `reclaim_stale()` (preserving `orphaned_dirty` commits for inspection).

---

## 6. Lobbies, Spectators, Late-Join Catch-Up & Host Migration

### Concrete Gaming Mechanisms
* **Lobbies & Ready-Checks:** Valve's [Steam Matchmaking & Lobbies](https://partner.steamgames.com/doc/features/multiplayer/matchmaking) ([`ISteamMatchmaking`](https://partner.steamgames.com/doc/api/ISteamMatchmaking)) separates **pre-match lobby negotiation** (roster membership, version/map/capability checks, explicit ready-checks, lobby owner transfer) from the live simulation loop so mismatched configurations fail before burning match resources.
* **Spectators vs. Active Players (SourceTV / GOTV):** Valve's [SourceTV](https://developer.valvesoftware.com/wiki/SourceTV) isolates read-only spectators from the live game server onto dedicated relay proxies, supporting thousands of observers without consuming active player slots or affecting tick stability, and optionally adds a configurable broadcast delay (`tv_delay`) to prevent real-time information leaks.
* **Late-Join Snapshot + Delta Tail:** Factorio's multiplayer rewrite ([FFF #147](https://factorio.com/blog/post/fff-147), [FFF #149](https://factorio.com/blog/post/fff-149)) solved the classic late-join stall: instead of pausing all players or forcing a newcomer to replay 100,000 ticks from tick 0, the host saves a compressed **state snapshot** in the background while buffering live inputs; the joiner downloads the snapshot and fast-forwards only the short **delta tail** of buffered actions until caught up. Quake III ([`sv_snapshot.c`](https://github.com/id-Software/Quake-III-Arena/blob/master/code/server/sv_snapshot.c)) uses the same principle at packet granularity via a zeroed "dummy" baseline fallback when a client's ACKed snapshot ages out of the 32-slot history ring.
* **Graceful Host Migration:** In [*I Shot You First: Networking the Gameplay of HALO: REACH*](https://www.gdcvault.com/play/1014345/I-Shot-You-First-Networking) (GDC 2011), Bungie's David Aldridge detailed peer **host migration** when a console host drops: surviving peers enter a brief pause barrier, deterministically elect the best-connected successor host, converge on the latest authoritative state snapshot, and resume the match without kicking everyone back to the menu.

### Real-World Failure Modes
* **Unbounded Late-Join Replay:** Replaying every historical `PeerEnvelope` in `BoardBridge::replay_outbound()` works for 50 events in Stage 0 but causes multi-megabyte stalls and redundant signature verifications when a peer joins a multi-day platoon with 50,000 envelopes.
* **Spectator Slot & Guard Pollution:** Treating human or read-only observer dashboards as full platoon members wastes `PlatoonRunner::max_peers` / `WorktreeLeaseManager::max_leases` slots or causes passive presence/observer traffic to falsely trigger `check_action_guard()`.
* **Single-Coordinator Fragility:** If the coordinator operator's laptop disconnects or reboots, an un-migratable coordinator leaves surviving peers stranded with stale work orders and no integration path.

### Blackbird Command Post Mapping (Stage 0 -> Stage 2)
* **Pre-Flight Lobby Handshake (Stage 1):** Before spawning `PlatoonRunner` peers into a shared `command_room`, run a lightweight ready-check verifying: (1) mutually pinned Ed25519 fingerprints in `KnownPeersStore`, (2) repo `base_sha` compatibility, (3) valid `CapabilityGrant` envelopes and `SpendPolicy` limits, and (4) available `WorktreeLeaseManager` slots.
* **Formal Spectator Role (SourceTV Pattern):** Distinguish **Watchers/Spectators** (read-only TUI/dashboard observers tracked via `PresenceRecord` + `active_watchers`) from **Active Peers** (holders of `CapabilityGrant` / worktree leases). Spectators never consume peer/worktree quotas, never block `check_action_guard()`, and in Stage 2 can fan out from a read-only relay/checkpoint feed without touching the active coordinator's hot path.
* **`BoardBridge` Signed Checkpoints + Delta Tail (Stage 1):** Periodically compact `BoardBridge` state into a **signed checkpoint record** containing: active `PinnedPeer`/revocation set, active `CapabilityGrant` summaries, open `WorktreeLeaseInfo` epochs, latest `actor_seq` watermarks, and the current `CausalEvent` DAG frontier hashes. Late joiners and reconnecting peers fetch `latest_checkpoint` + only `CausalEvent`s after the checkpoint frontier (preserving the full append-only audit log on disk for offline inspection and recovery, matching Blackbird's originals-preservation doctrine).
* **Deterministic Coordinator Migration (Stage 2):** Because every `CausalEvent` is content-hashed (`event_hash`) and every `PeerEnvelope` is self-signed by its origin `PeerIdentity`, coordination state is already replicated across participating hosts. On coordinator timeout past grace window, surviving peers can deterministically elect a successor (explicit lobby succession order or lowest active pinned fingerprint), bump a monotonic `coordinator_epoch` control event, and resume coordination—while every human's **local** `authorize_tool_call` authority remains completely untouched by who holds the coordinator hat.

---

## 7. Anti-Griefing, Rate Limits & Backpressure

### Concrete Gaming Mechanisms
* **Per-Client CPU Time Budgets (`net_chan_limit_msec`):** Valve introduced `net_chan_limit_msec` in the Source Engine after application-layer packet-flood exploits allowed a single malicious client to stall the main server tick for all players inside `ProcessMessages`. The server measures wall/CPU time spent processing each client's incoming frames per tick; exceeding the threshold drops/disconnects *only* the offending client while the match continues uninterrupted.
* **Bandwidth & Update Caps:** Source servers enforce hard ceilings via `sv_maxrate` (bytes/sec) and `sv_maxupdaterate` (packets/sec), while Factorio [FFF #302](https://factorio.com/blog/post/fff-302) documents explicit packet-size budgeting and fragmentation controls to stop oversized burst traffic from wedging connections.
* **Relay-Layer Shielding & Token Buckets:** In Fletcher Dunn's GDC 2018 *Denial-of-Service Mitigation* talk and [Steam Datagram Relay](https://partner.steamgames.com/doc/features/multiplayer/steamdatagramrelay), authentication and per-sender rate-limiting happen *before* traffic reaches the core simulation process. Well-engineered game servers pair **per-client token buckets** (separate burst and sustained rates for control vs. chat vs. state) with **graduated sanctions**: silently drop excess unreliable state -> throttle/backpressure reliable traffic -> mute broadcasts -> kick/ban the offending connection without restarting the server.

### Real-World Failure Modes
* **Signature-Verification CPU Amplification (Blackbird-Specific Hazard!):** Today `KnownPeersStore::verify_envelope()` spawns `/usr/bin/ssh-keygen -Y verify` as an external subprocess for each incoming envelope. Even with `kBoardBridgeMaxLineBytes = 4 MiB`, a misbehaving or prompt-injected peer sending 200 small frames/sec over a pipe can fork-storm the receiving host's CPU inside `BoardBridge::pump_inbound()`.
* **Append-Log & Context Disk Flood:** An unthrottled peer looping on `PresenceRecord` or `CausalEvent` posts can bloat `BoardBridge` NDJSON files, blow past TUI display budgets, and spam peer context windows.
* **Blast-Radius Teardown:** Without per-peer isolation, operators are forced to kill the entire platoon when a single external harness driver (`claude_code`, `codex`, `pi`, `acp`) enters a runaway loop.

### Blackbird Command Post Mapping (Stage 0 -> Stage 2)
* **Stage 0 (Present):** Hard byte caps already exist (`kBoardBridgeMaxLineBytes = 4 MiB`, `kPlatoonMaxMessageBytes = 64 KiB`, `kPlatoonMaxRosterMembers = 512`, `PlatoonRunner::max_output_bytes = 256 KiB`), along with `SpendPolicy` (`max_turns_per_peer`, `max_cost_usd_per_peer`, `max_cost_usd_per_platoon`), local `revoke_grant()` / `revoke_peer()`, and per-peer `PlatoonRunner::stop(peer_id)`.
* **Stage 1/2 Hardening (Defense-in-Depth Admission Pipeline):**
  1. **Tight Per-Kind Size Caps:** Keep 4 MiB only for explicit Lane-1 artifacts/diffs; cap Lane-0 control frames and Lane-2 `PresenceRecord` frames at <= 16 KiB *before* JSON parsing or signature verification.
  2. **Per-Sender Token Buckets & `net_chan_limit_msec` Guard:** In `BoardBridge::pump_inbound()`, enforce per-`from_fingerprint` token buckets (e.g., separate rates for control, causal events, and presence) and a per-pump verification CPU/wall-time budget per sender *before* invoking `verify_envelope()`. (In Stage 1/2, migrating hot-path Ed25519 verification from `ssh-keygen` subprocesses to an owned/audited in-process implementation removes the fork-bomb amplification vector entirely—subject to operator library/machinery review.)
  3. **Explicit Backpressure & Graduated Sanctions:**
     * *Level 1 (Lane-2 overload):* Coalesce/drop excess `PresenceRecord` frames silently.
     * *Level 2 (Lane-1 burst):* Emit explicit backpressure notice (`throttle` / pause read on that peer's stream) while keeping Lane 0 open.
     * *Level 3 (Misbehaving / looping peer):* Locally mute peer's non-control room fan-out, trigger `KnownPeersStore::revoke_grant()` (immediate local kill-switch at `authorize_tool_call()`), and invoke `PlatoonRunner::stop(peer_id)`—leaving all other healthy peers, worktrees, and the Command Post session completely intact.

---

## Stage 0 -> Stage 2 Actionable Roadmap Synthesis

| Domain | Stage 0 (Shipped Foundation) | Stage 1 (WAN-Ready 2–8 Peer Command Post) | Stage 2 (Sovereign Relay-Backed Fleet) |
| :--- | :--- | :--- | :--- |
| **1. Connections & Roaming** | SSH / stdio NDJSON pipe (`BoardBridge::send_envelope`, `pump_inbound`, `envelope_id` dedupe) | Session ID decoupled from pipe; keepalive + challenge-nonce resume without full replay | Blind encrypted relay (SDR/DERP pattern) over TLS/QUIC + RFC 9000 `PATH_CHALLENGE` migration + optional P2P upgrade |
| **2. Channel Separation** | Single sequential NDJSON stream & append-only outbound replay | Stop durable replay of `PresenceRecord` (latest-wins map); prioritize Lane-0 revocations/recalls ahead of Lane-1 payloads | True 3-lane multiplexed framing (Control / Causal Work / Unreliable MRS Presence) with priority & weights |
| **3. Relevancy & Budget** | `resource_scope`, `command_room`, `recipient_filter`, `format_quoted_peer_frame` | Subscription-filtered fan-out by `resource_scope` prefix; owner-only Fog of War on raw tool logs | Persistent scope-indexed Replication Graph + Fast Shared Path (summarize once, broadcast compact digest) |
| **4. Authority & Rollback** | Local `authorize_tool_call`, `SpendLedger`, isolated `WorktreeLeaseManager`, `check_action_guard`, `detect_concurrent_claims` | Bounded speculative worktree horizons (periodic rebase/reconcile checks against `base_sha`) | Cross-host semantic merge queue with explicit conflict artifacts & zero silent overwrites |
| **5. Leasing & Grace Windows** | Local PID + start-time liveness (`WorktreeLeaseManager`), `orphaned_dirty` preservation, 60s skew clamp | Add monotonic `lease_epoch` fencing token to worktree leases & claims; `steady_clock` `3H` suspect / `6H–10H` grace windows + idempotent rejoin | Distributed epoch fencing enforced at bridge & merge gates across sleeping/roaming laptops |
| **6. Lobbies, Spectators & Migration** | `PlatoonBoard` roster, `active_watchers` presence, full `replay_outbound()` | Pre-flight lobby ready-check; formal non-blocking Spectator role; **signed `BoardBridge` checkpoints + delta tail** | SourceTV-style read-only spectator fan-out + deterministic `coordinator_epoch` host migration |
| **7. Anti-Griefing & Backpressure** | Wire byte caps (`4 MiB` / `64 KiB`), `SpendPolicy`, local `revoke_grant`, `PlatoonRunner::stop` | Per-sender token buckets + per-kind size caps + `net_chan_limit_msec` verify budget before `ssh-keygen` | Relay-edge auth/rate limiting + in-process Ed25519 verify + graduated throttle/mute/revoke isolation |

---

## Verified Primary Engineering Sources

All URLs below were verified live on 2026-11-23.

### Connections, Relays, NAT Traversal & QUIC Migration
* IETF, **RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport** (Section 8.2 Path Validation; Section 9 Connection Migration), 2021 — <https://www.rfc-editor.org/rfc/rfc9000>
* IETF, **RFC 8445: Interactive Connectivity Establishment (ICE)**, 2018 — <https://www.rfc-editor.org/rfc/rfc8445>
* IETF, **RFC 8656: Traversal Using Relays around NAT (TURN)**, 2020 — <https://www.rfc-editor.org/rfc/rfc8656>
* Valve Software, **Steam Datagram Relay (Steamworks Documentation)** — <https://partner.steamgames.com/doc/features/multiplayer/steamdatagramrelay>
* Valve Software, **GameNetworkingSockets (Open-Source Transport & Lanes)** — <https://github.com/ValveSoftware/GameNetworkingSockets> (see also [`README.md`](https://github.com/ValveSoftware/GameNetworkingSockets/blob/master/README.md) and [`include/steam/steamnetworkingtypes.h`](https://github.com/ValveSoftware/GameNetworkingSockets/blob/master/include/steam/steamnetworkingtypes.h))
* Valve Software, **ISteamNetworkingSockets API Documentation** — <https://partner.steamgames.com/doc/api/ISteamNetworkingSockets>
* David Anderson (Tailscale), **How NAT traversal works** (STUN, CGNAT, DERP relay-first + direct upgrade) — <https://tailscale.com/blog/how-nat-traversal-works>

### Channel Separation, Snapshots & Protocol Design
* Glenn Fiedler (*Gaffer on Games*), **Building a Game Network Protocol** (series index) — <https://gafferongames.com/categories/building-a-game-network-protocol/>
* Glenn Fiedler, **What Every Programmer Needs To Know About Game Networking** — <https://gafferongames.com/post/what_every_programmer_needs_to_know_about_game_networking/>
* Glenn Fiedler, **UDP vs. TCP** — <https://gafferongames.com/post/udp_vs_tcp/>
* Glenn Fiedler, **Reliability, Ordering and Congestion Avoidance over UDP** — <https://gafferongames.com/post/reliability_ordering_and_congestion_avoidance_over_udp/>
* Glenn Fiedler, **Reliable Ordered Messages** — <https://gafferongames.com/post/reliable_ordered_messages/>
* Glenn Fiedler, **Client Server Connection** — <https://gafferongames.com/post/client_server_connection/>
* Glenn Fiedler, **State Synchronization**, **Snapshot Interpolation**, and **Snapshot Compression** — <https://gafferongames.com/post/state_synchronization/>, <https://gafferongames.com/post/snapshot_interpolation/>, <https://gafferongames.com/post/snapshot_compression/>
* Mark Frohnmayer & Tim Gift (Dynamix), **The TRIBES Engine Networking Model** — <https://www.gamedevs.org/uploads/tribes-networking-model.pdf>
* id Software, **Quake III Arena Reference Source** (`sv_snapshot.c` delta snapshots & dummy baseline; `net_chan.c` packet channel) — <https://github.com/id-Software/Quake-III-Arena/blob/master/code/server/sv_snapshot.c> and <https://github.com/id-Software/Quake-III-Arena/blob/master/code/qcommon/net_chan.c>

### Relevancy, Interest Management & Information Isolation
* Epic Games, **Replication Graph in Unreal Engine** — <https://dev.epicgames.com/documentation/en-us/unreal-engine/replication-graph-in-unreal-engine>
* Epic Games, **Actor Relevancy in Unreal Engine** — <https://dev.epicgames.com/documentation/en-us/unreal-engine/actor-relevancy-in-unreal-engine>
* Epic Games, **Networking Overview for Unreal Engine** — <https://dev.epicgames.com/documentation/en-us/unreal-engine/networking-overview-for-unreal-engine>
* Riot Games Technology, **Demolishing Wallhacks with VALORANT's Fog of War** — <https://technology.riotgames.com/news/demolishing-wallhacks-valorants-fog-war>

### Authority, Prediction, Rollback & Lockstep Tradeoffs
* Valve Developer Community, **Source Multiplayer Networking** — <https://developer.valvesoftware.com/wiki/Source_Multiplayer_Networking>
* Yahn Bernier (Valve), **Latency Compensating Methods in Client/Server In-game Protocol Design and Optimization** — <https://developer.valvesoftware.com/wiki/Latency_Compensating_Methods_in_Client/Server_In-game_Protocol_Design_and_Optimization>
* Timothy Ford (Blizzard Entertainment), **'Overwatch' Gameplay Architecture and Netcode** (GDC 2017) — <https://www.gdcvault.com/play/1024001/-Overwatch-Gameplay-Architecture-and>
* Riot Games Technology, **Peeking into VALORANT's Netcode** — <https://technology.riotgames.com/news/peeking-valorants-netcode>
* Tony Cannon, **GGPO (Good Game Peace Out) Rollback Netcode SDK** — <https://github.com/pond3r/ggpo>
* Infil, **Explaining how fighting games use delay-based and rollback netcode** — <https://ki.infil.net/w02-netcode.html>
* Paul Bettner & Mark Terrano (Ensemble Studios), **1500 Archers on a 28.8: Network Programming in Age of Empires and Beyond** — <https://www.gamedeveloper.com/programming/1500-archers-on-a-28-8-network-programming-in-age-of-empires-and-beyond>
* Glenn Fiedler, **Deterministic Lockstep** and **Floating Point Determinism** — <https://gafferongames.com/post/deterministic_lockstep/> and <https://gafferongames.com/post/floating_point_determinism/>

### Resource Leasing, Lobbies, Spectators, Late-Join & Host Migration
* Martin Kleppmann, **How to do distributed locking** (leases, monotonic clocks, fencing tokens), 2016 — <https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html>
* David Aldridge (Bungie), **I Shot You First: Networking the Gameplay of HALO: REACH** (GDC 2011 — latency debt, flow control, host migration) — <https://www.gdcvault.com/play/1014345/I-Shot-You-First-Networking>
* Valve Software, **Steam Matchmaking & Lobbies** and **ISteamMatchmaking Interface** — <https://partner.steamgames.com/doc/features/multiplayer/matchmaking> and <https://partner.steamgames.com/doc/api/ISteamMatchmaking>
* Valve Developer Community, **SourceTV** (spectator proxy isolation & `tv_delay`) — <https://developer.valvesoftware.com/wiki/SourceTV>
* Wube Software (*Factorio* Friday Facts), **Multiplayer Lockstep, Late-Join Catch-Up, Megapacket Budgeting & Desyncs**:
  * [FFF #63 — The endless struggle](https://factorio.com/blog/post/fff-63)
  * [FFF #147 — Multiplayer rewrite](https://factorio.com/blog/post/fff-147)
  * [FFF #149 — Deep down in multiplayer](https://factorio.com/blog/post/fff-149)
  * [FFF #188 — Bug, Bug, Desync](https://factorio.com/blog/post/fff-188)
  * [FFF #302 — The multiplayer megapacket](https://factorio.com/blog/post/fff-302)
  * [FFF #340 — Deep desyncs](https://factorio.com/blog/post/fff-340)
  * [FFF #415 — Fix, Improve, Optimize](https://factorio.com/blog/post/fff-415)
