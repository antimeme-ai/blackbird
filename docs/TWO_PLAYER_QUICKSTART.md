# Two-Player Quickstart (Stage 0 `BoardBridge`)

Run a live, sovereign 2-player session between two operators (**Alice** and **Bob**) with zero central server, Ed25519 key-pinned envelopes, causal event tracking, action-time unread-message guards, and instant local capability revocation.

Default local directories:
- Peer keys & trust store: `~/.local/share/blackbird/peers` (override with `--root` on `peer`, `--peers` on `bridge`)
- Bridge journal (`bridge.jsonl`): `.blackbird/bridge` (override with `--bridge`)
- Local platoon board: `.blackbird/platoon` (override with `--board`)

## 1. Create Identities and Pin Out-of-Band

Both operators generate (or display) their local Ed25519 peer identity:

```sh
blackbird peer id
```

Exchange the `public_key` (`ssh-ed25519 ...`) and `fingerprint` (`bb1-...`) over a trusted out-of-band channel, then pin each other. Silent key swaps for an existing alias are rejected automatically.

```sh
# On Alice's machine:
blackbird peer pin --alias bob --public-key "ssh-ed25519 AAAA... bob" --trust-note "verified in call"

# On Bob's machine:
blackbird peer pin --alias alice --public-key "ssh-ed25519 AAAA... alice" --trust-note "verified in call"
```

Verify pinned peers anytime with `blackbird peer list`.

## 2. Send and Receive Signed Envelopes

`blackbird bridge send` emits **one compact signed NDJSON line** on stdout, so it composes directly over SSH, Tailscale SSH, or async file drops.

### Option A: One-Shot SSH / Tailscale SSH Pipe

```sh
# Alice sends a scoped handoff directly into Bob's bridge over SSH (or Tailscale SSH):
blackbird bridge send \
  --to bob \
  --kind handoff \
  --scope src/auth.cpp \
  --body "Auth parser fix ready on branch fix/auth-eof; please review before editing." \
  | ssh bob@<peer-host> 'cd /path/to/repo && blackbird bridge receive'
```

Bob's `bridge receive` verifies Alice's signature against Bob's `known_peers.json`, persists the causal event, and prints a JSON summary containing `accepted`, `duplicates`, `rejected`, `accepted_event_hashes`, and non-executable `quoted_frames`.

### Option B: Bidirectional Sync (`bridge serve`)

`bridge serve` replays outbound envelopes as pure NDJSON on stdout, ingests inbound envelopes from stdin, and writes its compact JSON summary to **stderr**:

```sh
# Exchange pending outbound envelopes with Bob over SSH in one pass:
blackbird bridge send --to bob --kind brief --scope src/auth.cpp --body "Syncing status." \
  | ssh bob@<peer-host> 'cd /path/to/repo && blackbird bridge serve' \
  | blackbird bridge receive
```

### Option C: Async Drop (Shared Folder, SCP, or Air-Gapped Transfer)

```sh
# Alice writes signed NDJSON frames to a drop file:
blackbird bridge send --to bob --kind decision --scope docs/api.md --body "Freeze v1 wire format." \
  >> handoff.ndjson

# Later, Bob ingests the drop file (replays are idempotent and deduplicated):
blackbird bridge receive < handoff.ndjson
```

Inspect the causal event DAG and detect concurrent conflicting claims on a scope:

```sh
blackbird bridge events --scope src/auth.cpp
```

## 3. Action-Time Unread-Message Guard & Cognitive Receipts

Before modifying a shared scope, Bob runs the unread-message guard:

```sh
blackbird bridge guard --scope src/auth.cpp
```

- **Exit code `2`** (`"allowed": false`): unread foreign peer events target `src/auth.cpp`; `blocking_event_hashes` lists every event that has not yet reached `included_in_request` or `acknowledged`.
- **Exit code `0`** (`"allowed": true`): all relevant foreign peer events are cognitively included.

Once Bob's model request includes Alice's quoted frame (with exact request hash `<REQUEST_HASH>`), Bob records a cognitive-inclusion receipt (add `--to alice` to also emit a signed NDJSON receipt back to Alice):

```sh
blackbird bridge receipt \
  --event <EVENT_HASH> \
  --stage included_in_request \
  --request-hash <REQUEST_HASH> \
  --to alice \
  | ssh alice@<peer-host> 'cd /path/to/repo && blackbird bridge receive'

# Guard now returns exit 0 ("allowed": true):
blackbird bridge guard --scope src/auth.cpp
```

Share and inspect live watcher presence heartbeats:

```sh
blackbird bridge presence --scope src/auth.cpp --status reviewing --name bob --ttl 300 --to alice \
  | ssh alice@<peer-host> 'cd /path/to/repo && blackbird bridge receive'

blackbird bridge presence --list --scope src/auth.cpp
```

## 4. Scoped Capability Grants & Instant Local Revocation

Alice issues a signed, time-bounded, tool-allowlisted capability grant to Bob:

```sh
# On Alice's machine:
blackbird bridge grant-issue \
  --to bob \
  --target-peer reviewer \
  --mode direct_support \
  --tool platoon_read \
  --tool platoon_post \
  --max-turns 8 \
  --max-tokens 50000 \
  --ttl 3600 > grant.json
```

Bob re-verifies the grant locally at tool execution time (exit `0` if allowed, exit `2` if denied):

```sh
# On Bob's machine:
blackbird bridge grant-check --grant-file grant.json --tool platoon_read
```

Local kill-switch revocation takes effect immediately without waiting for network round-trips:

```sh
# Revoke a single grant (next grant-check immediately exits 2):
blackbird peer revoke-grant --grant-id <GRANT_ID> --reason "review complete"

# Or revoke an entire peer key:
blackbird peer revoke-peer --fingerprint <PEER_FINGERPRINT> --reason "key rotated"
```

## 5. Attach Claude Code, Codex, or Pi via `blackbird mcp`

Any MCP-capable harness can join your local platoon board (`.blackbird/platoon`) and worktree leases via Blackbird's zero-dependency stdio MCP server:

```sh
blackbird mcp --board .blackbird/platoon --repo .
```

Example MCP server entry (for Claude Code `.mcp.json`, Codex MCP config, or Pi MCP config):

```json
{
  "mcpServers": {
    "blackbird-command-post": {
      "command": "blackbird",
      "args": ["mcp", "--board", ".blackbird/platoon", "--repo", "."]
    }
  }
}
```

Add `--allow-root /path/to/repo --max-peers 4` if you also want MCP clients to spawn supervised local peers through `PlatoonRunner`.
