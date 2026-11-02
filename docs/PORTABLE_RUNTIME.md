# Executable-owned runtime resources

A Blackbird executable placed under `Contents/MacOS` uses
`Contents/Resources/Blackbird/programs` and `assets` for its default workflow,
result instrument and sprite. It starts `blackbird-job-runner` and
`blackbird-archive` beside itself. Bundle names and the current working directory
do not select these files; the running executable's actual path does.

A missing bundled file fails at the existing read/spawn boundary. It never
silently falls back to the original source or build directory. Package both
helper binaries from the same build and the programs/assets from its exact
source pin. Their shared-library relocation/signing remains the package owner's
responsibility. This lookup support does not adopt dependencies or distribute a
new binary installer.

Outside a bundle, `../share/blackbird` or the existing installed generation's
`../../share/blackbird`, relative to the executable directory, select resources
when present. Helpers use an existing executable sibling before their compiled
development fallback. Without a recognized resource layout, development defaults
are unchanged. macOS executable discovery uses `_NSGetExecutablePath`; Linux uses
`/proc/self/exe`. This unit's actual relocated-process run is macOS, not a new Linux
runtime qualification or an Oxcart Linux shell.

Explicit CLI `--workflow`, application-open `workflow` and `BLACKBIRD_SPRITE_ASSET`
remain intentional caller choices. Stored sessions keep their saved workflow
paths; copied old sessions are not silently rewritten or classified as
"default" versus "custom". A caller can explicitly select a workflow after
moving such a session.

The model-free `scripts/check-portable-runtime BUILD/blackbird` fixture stages a
bundle and checks native BBM2 startup/host negotiation, an explicitly selected
workflow executing a real owned PTY command, exact command output/effect, normal
close, and refusal of missing bundled workflow/helper. It uses private session
and authentication roots and never requests a provider. Its optional
`--artifacts DIRECTORY` retains protocol/stdout/stderr and state. The owning
relocation study additionally builds against private resource/build origins and
moves those origins away before running the same fixture.
