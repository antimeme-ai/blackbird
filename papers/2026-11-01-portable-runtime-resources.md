# Blackbird portable resources for the Oxcart alpha

## Exact source and fault

The selected Lua5.5.1 runtime is
`~/projects/blackbird/context/oxcart-lua55-runtime-2026-10-29`.
`SOURCE_TREE` and its retained source manifest select tree
`6992e5573005a7db7783e460c2d4a56f6dbfa9d3`, exactly commit
`b14d5f13c72173994a8a65b826013f16b397beb3` (Upgrade embedded Lua to pinned5.5.1
for Oxcart). The source archive SHA256 is
`a4a875a04902760973162b84cdea7fa4270c6beb861488c89c272ab9553f4da5`.
The active checkout is instead3559918… with unrelated dirty bead backups and
untracked artwork/research/handoff files. It must remain unchanged.

The pinned source has four concrete lookup seams:

- CMake defines `BLACKBIRD_WORKFLOW` as the absolute resource-root turn.lua;
  main reads that file before application ready. Application open validates and
  forwards model/effort only, so its caller cannot currently supply the already
  supported CLI workflow override.
- `command_jobs.cpp` prepends the absolute compiled job-runner path for PTY jobs.
- `trace_archive_worker.cpp` starts the absolute compiled archive helper. It is
  the same relocation fault, not a new archive feature.
- Sprite fallback and the result instrument use the compiled resource directory.
  The explicit `BLACKBIRD_SPRITE_ASSET` override and CLI `--workflow` remain valid.

Source contracts are Blackbird's AGENTS/BLACKBIRD, README/JOURNAL,
`docs/APPLICATION_INTERFACE.md`, `docs/COMMAND_JOBS.md`,
`docs/IMPLEMENTATION_PLAN.md`, `tooling/README.md`, installed source hook and
`scripts/install-blackbird`. The installer currently builds at its final path,
so compiled absolute paths work there but do not establish relocation.

## Bounded implementation

Create one isolated candidate worktree/branch from b14d5f13, outside the active
checkout, and a new private build/runtime. Record the active checkout inventory
before/after; never move its source, build, session or running executable. Follow
its source gate/hooks and bead backup rules. Preserve the existing Lua5.5.1
header/library pair; no dependency, provider, authentication, model behavior or
activation change.

Add one small owned executable-path/resource lookup seam, used by the existing
lookups above. On macOS obtain the actual executable through
`_NSGetExecutablePath`; on Linux use `/proc/self/exe`, without trusting cwd or a
bare argv0. A macOS bundle executable in Contents/MacOS resolves:

- default workflow/instrument/assets under Contents/Resources/Blackbird;
- job-runner/archive helpers beside the executable in Contents/MacOS.

A recognized bundle uses its own paths even if a required file is missing; it
must fail concretely rather than silently reading the developer checkout.
Outside a bundle preserve compiled development fallbacks and existing explicit
overrides. Prefer an actual sibling helper when supplied. Support the existing
installed generation's share/blackbird layout and conventional adjacent
share/blackbird resources without changing its installer/activation behavior.
Keep this path resolver small; it does not become a general plugin/runtime
registry. Missing helpers retain existing owned-job failure outcomes.

Allow optional string `workflow` in application open and forward it to the
existing CLI parser. It receives the same validation/session persistence as the
CLI and never bypasses source reads or turn ownership. Keep existing host-tool
negotiation and model/effort behavior.

Owning files: small new include/src runtime-path files, CMake target sources,
main/application open, command_jobs, trace_archive_worker and sprite; relevant
application/install docs and a direct relocated-process test. The package peer
owns copied files/dependencies/signing. Root owns the Oxcart retained-runtime
builder, which needs explicit job-runner and archive build targets.

## Package handoff

Proposed explicit inputs to the package peer:

- tested blackbird executable;
- same-build blackbird-job-runner and blackbird-archive;
- exact source/resource root containing programs and assets.

Package programs/assets unchanged at Contents/Resources/Blackbird and helpers at
Contents/MacOS. Retain exact source/commit/tree and Lua pins. The package's Mach-O
pass owns dependency relocation and signing. No package, install or live runtime
is changed by this source unit. Linux executable discovery is implemented, but
this does not claim a Linux Oxcart shell or fresh Linux run.

## Direct checks and delivery

Use a private model-free fixture with an actual executable, host-tool negotiation
and owned PTY command. Build old code against a private resource/build origin,
copy its executable/helpers/resources into a relocated bundle, then rename only
that private origin out of its compiled paths. The old application must actually
fail opening its default workflow; a separate explicit local CLI workflow must
show the real PTY helper launch failure. Missing API/schema/compile failure alone
is not the old red.

After the fix, the relocated default application must negotiate its offered host
tools and close normally. An explicit application workflow must execute an owned
PTY command through the real relocated helper, observe its exact output/exit,
then close and drain normally. It contains no provider call; auth/session roots
are private. Preserve full original outputs/protocol and source/build pins. Also
exercise explicit override and missing bundled-resource/helper behavior in the
same direct fixture, without changing the real source/runtime.

Run the Blackbird source gate through its installed hook before checkpoint and
push the isolated candidate branch, with no merge/force/hook bypass. Record any
actual tool/gate/push failure rather than weakening it. Root reviews held code;
package integration uses only the checked candidate. No browser, input,
activation, credential/login or network-model call belongs to this unit.
