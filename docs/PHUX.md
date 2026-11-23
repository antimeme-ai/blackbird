# phux support

[phux](https://github.com/no-phux/phux), by phall, is Blackbird's officially
supported external terminal multiplexer. It runs as a separate service;
Blackbird runs its ordinary C++ TUI inside a pane. No terminal library or phux
runtime is bundled into Blackbird's core, and ordinary launch still works
without phux.

## Install and startup service

Install the official binaries if needed:

```sh
curl -fsSL https://phux.sh/install | sh
phux --version
```

Verified locally with official macOS arm64 **phux 0.162.0** installed in
`~/.local/bin`.

To keep the local phux server running across logout and reboot (as a `launchd`
`LaunchAgent` on macOS or a systemd user unit on Linux):

```sh
phux service install            # install and load the per-user service unit
phux service install --restore  # also autosave session layout/names/cwd across restarts
phux service install --adopt    # write the unit without stopping an already-running server
phux service status             # report unit installation and server status
phux service logs               # inspect the supervised server log
phux service uninstall          # unload and remove the installed unit
```

On macOS, `phux service install` registers the `com.phux.server` `LaunchAgent`.
A restarted server does not keep running child processes alive across reboot;
`--restore` preserves session metadata so `phux restore` can relaunch panes.

## Start and return

From your project working directory:

```sh
./scripts/blackbird-phux blackbird --session context/my-blackbird
./scripts/blackbird-phux --ephemeral scratch --session context/scratch
```

- The first positional argument names the phux session; optional `--ephemeral`
  before `PHUX_SESSION` makes the phux session end automatically when Blackbird
  exits.
- Remaining arguments pass to Blackbird literally, and your current working
  directory stays the tool working directory.
- `scripts/blackbird-phux` resolves the sibling `scripts/blackbird` wrapper in a
  checkout and falls back to `blackbird` on `PATH` when installed.
- `scripts/arco-phux` remains a thin compatibility wrapper forwarding to
  `scripts/blackbird-phux`.
- The launcher creates the session atomically with `phux new --json --cwd "$PWD"
  --session NAME -- ...`, best-effort declares Blackbird's pane agent identity
  via `phux agent set --name blackbird --kind blackbird --session NAME @ID`, and
  execs `phux attach NAME`.
- Existing session names are refused (create-only); return to an existing
  session with `phux attach NAME`. `PHUX_SOCKET` is inherited, allowing the same
  launcher to target a private/local phux server.

Common session controls:

- `Ctrl-A`, then `%`: split side by side.
- `Ctrl-A`, then `d`: detach, leaving Blackbird running.
- `phux attach blackbird`: reattach to the same running pane.
- `/restart NOTE`: Blackbird's existing RRC; keeps the pane and retained
  conversation.
- `/quit` or `/exit`: quit Blackbird. Detach is how to leave it running.
- `phux kill --yes NAME`: non-interactively kill a named session (`phux kill`
  refuses with exit 2 without `--yes` when stdin is not a TTY; `phux kill
  --server` stops the server behind the selected socket).

Each concurrent Blackbird needs its own `--session` directory. Sharing a phux
server never makes sharing a writable Blackbird audit safe. Model/provider
requests and tools still belong to their harnesses, and individual Blackbird
restarts do not restart phux.

## Human and model terminal tools

```sh
phux ls --json
phux snapshot --json @1
phux paste @1 'text to insert'
phux send-keys @1 Enter
phux watch --json --timeout 30 @1
```

Select the actual target ID (`@N`, session name, or `%blackbird`) from `phux ls
--json` or `phux agent list --json` rather than assuming `@1`. `snapshot` and
`watch` observe without attaching or resizing. `paste` inserts text (honoring
bracketed paste when enabled) without submitting; `send-keys ... Enter` submits.
Ordinary audited exec/Lua workflows can call these external tools. To place
another program beside a chosen pane, use `phux spawn --target @ID --cwd PATH
-- PROGRAM`.

### Agent identity and exclusive input handoff

`phux 0.162.0` provides explicit per-pane agent records and input control
leases:

```sh
phux agent list --json
phux agent show --json @1
phux agent set --name blackbird --kind blackbird --state idle --session blackbird --json @1
phux agent wait --until idle --until blocked --until done --timeout 60 @1
phux take --ttl 30 --json @1
phux give --json @1
```

- `phux agent set` writes an explicit `phux.agent/v1` record (`--name`,
  `--kind`, `--state`, `--attention`, `--session`) and confirms read-back; phux
  assigns addressable `%blackbird` / `%blackbird-2` names automatically.
- `phux agent list` and `phux agent show` inspect declared or inferred agent
  records across panes.
- `phux agent wait` blocks on observed lifecycle state transitions (not static
  level reads) and exits `124` on `--timeout`.
- `phux take` seizes exclusive input authority over a pane (blocking other
  clients and agent `send-keys` until `phux give`, disconnect, or `--ttl`
  expiry); `phux give` releases the lease back to open input.

Screen text is observation. It is not an inference result, an audit, or proof an
effect completed. `wait --output-only` requires OSC-133 shell integration;
Blackbird's TUI does not emit shell marks, so use a distinct observed output or
explicit lifecycle integration rather than matching a word echoed from the
submitted prompt.

## Verification and scope boundary

Run the standalone qualification check against an isolated private socket:

```sh
./scripts/check-phux
```

The check skips cleanly (exit 0) when `phux` is not installed. When `phux` is
present, it dials a temporary `PHUX_SOCKET` (never touching the operator's
default phux server) and verifies:

- Launcher `--help` and argument validation for `scripts/blackbird-phux` and
  `scripts/arco-phux`.
- Atomic `phux new --json --cwd ... --session ...` creation (`schema_version: 1`,
  `terminal_id`) and duplicate-name refusal.
- `phux ls --json` session and terminal listing.
- `phux agent set --name blackbird --kind blackbird --state idle --session ...`,
  `phux agent show --json`, and `phux agent list --json` (`%blackbird`
  addressing).
- `phux snapshot --json`, `phux paste --json`, and `phux send-keys --json`
  round-trip observation.
- `phux take --ttl 5 --json` and `phux give --json` exclusive input handoff.
- `phux new --json --ephemeral` automatic session teardown on process exit.
- Non-interactive `phux kill` refusal (exit 2) without `--yes`, successful
  `phux kill --yes --json`, and clean `phux kill --server` teardown with
  `phux status --json` confirming `running: false` and no leftover socket.

Verified locally on macOS arm64 with **phux 0.162.0** on a private socket with
zero impact on the default `com.phux.server` instance. Earlier **phux 0.52.0**
manual TUI validation also exercised live detach/reattach and `/restart NOTE`
RRC keeping the same pane, wrapper PID, geometry, and retained conversation.

Native Blackbird lifecycle emission (pushing live working/idle/blocked state
updates into `phux agent`), a phux-specific fleet view, remote enrollment, and
multiplayer protocol integration remain subsequent work. phux's bounded live
record history complements Blackbird's complete retained audit. Source/fit
discussion: [papers/2026-10-07-phux-multiplexing.md](../papers/2026-10-07-phux-multiplexing.md).
