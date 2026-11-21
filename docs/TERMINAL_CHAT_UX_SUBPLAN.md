# Unit (1): Terminal & Chat UX Subplan

## Problem

Honest baseline audit of `master` (`4a9ab700984a`) and live operator usage exposed
six compounding TUI/chat usability defects:

1. **Mouse capture breaks native selection**: `mouse_wanted` defaults to `true`
   (`?1000h/?1006h`), hijacking plain mouse drag-select and copy in Ghostty/Terminal.
2. **Paste friction & missing clipboard copy**:
   - Bracketed paste turns `\r\n` into two newlines (`\r` -> `\n`, then `\n` -> `\n`).
   - Every 128-byte paste read calls `persist()` (serialize + rename + `fsync`),
     stalling large pastes.
   - No OSC 52 clipboard copy or `/copy` command exists.
3. **`Esc` does not interrupt active turns or close unfocused overlays**:
   - Bare `Esc` only closes palettes or focuses the editor; it never cancels an
     active turn or closes an open inspector when focus is already in the editor.
   - `Ctrl-C` wipes queued prompts with no non-destructive interrupt shortcut.
4. **Silent queueing**: Submitting a prompt while busy clears the composer with
   zero transcript receipt (only a tiny status counter).
5. **Noisy double tool cards, blind file tools, and opaque `Ctrl-O` IDs**:
   - Every tool call emits two separate `ACTIVITY` blocks (start header + separate
     completion block).
   - `read_file`, `write_file`, and `edit_file` emit zero preview/diff lines.
   - `Ctrl-O` lists commands as opaque 8-hex IDs (`a3f8c219 settled`) instead of
     showing the actual command.
6. **Layout waste & scroll snap**:
   - Empty Tasks pane eats 28–36 columns even when there are zero tasks.
   - `ChatView::trim()` bumps `generation()`, which resets `scroll = 0` and snaps
     a scrolled-up operator back to the bottom.

## Plan

1. **Native selection, clean fast paste, and OSC 52 copy** (`src/terminal.cpp`,
   `include/blackbird/terminal.hpp`, `src/chat_view.cpp`, `include/blackbird/chat_view.hpp`):
   - Default `mouse_wanted = false` (`BLACKBIRD_MOUSE=1` or `/mouse on` opts in).
   - Normalize `\r\n` -> `\n` inside bracketed paste (`pasted_cr_` state).
   - Defer `persist()` while `composer.pasted()` is active and `STDIN_FILENO` has
     more bytes immediately ready (`poll(..., 0) > 0`), persisting once the burst
     drains.
   - Add `terminal_osc52_copy(std::string_view)` (owned base64 + `\x1b]52;c;...\x07`,
     bounded to 100 KiB) emitted through the single-writer `ChatPresenter`/`ChatOutput`
     frame packet, plus `/copy [all|user]` using `ChatView::last_text()` /
     `ChatView::plain_transcript()`.
2. **`Esc` turn interrupt (preserving queue) & overlay close** (`src/terminal.cpp`,
   `include/blackbird/terminal.hpp`):
   - Extend `TerminalInputDispatch` with `bare_escape` (true only when bare `\x1b`
     expires with no palette/slash menu open).
   - When `bare_escape` fires: if an inspection view is open and focus is in the
     inspector, focus the editor; if focus is already in the editor, close back to
     conversation; otherwise if `busy`, cancel the active turn **without** wiping
     `queued`. Keep `Ctrl-C` and `/cancel` as explicit stop + clear-queue.
3. **Immediate queue receipts** (`src/terminal.cpp`):
   - On enqueue while `busy || !queued.empty()`, immediately append a concise
     `ChatKind::notice` receipt (`Queued #N: <first-line preview>`).
4. **Single tool cards, file-tool previews, and readable `Ctrl-O` labels**
   (`src/chat_view.cpp`, `include/blackbird/chat_view.hpp`, `src/terminal.cpp`,
   `src/coding.cpp`, `include/blackbird/command_observation.hpp`,
   `src/command_jobs.cpp`, `src/command_inspector.cpp`):
   - Add `ChatView::tool_complete()` to update the active tool block's header
     in-place (`▸ ...` -> `✓ ... · Nms`) so each tool renders as ONE `ACTIVITY`
     card while preserving `fold()` head/tail rows.
   - Emit compact 1–4 line `process_output` summaries for `read_file`, `write_file`,
     and `edit_file` (including compact `-`/`+` diff preview lines for `edit_file`).
   - Add fixed-size zero-alloc `command_label` to `CommandObservationRow`, populated
     in `CommandJobs::try_observe()` from `launch.argv` (stripping `/bin/sh -c`),
     and render it in `CommandInspector`.
5. **Auto-hide empty Tasks pane & preserve scroll across ring trim**
   (`src/terminal.cpp`, `src/chat_view.cpp`, `include/blackbird/chat_view.hpp`):
   - Hide the side Tasks pane when `items.empty()` unless explicitly requested via
     `/tasks show`.
   - Add `ChatView::cleared_generation()` (bumped only by `clear()`, not `trim()`)
     so `TerminalUI` preserves the operator's scroll anchor across 64 KiB ring trims.

## Verification

- Direct C++ RED -> GREEN unit suite in `tests/terminal_chat_ux_test.cpp`
  (paste CRLF normalization, OSC 52 + `last_text`, single tool card + fold,
  scroll stability across trim, `bare_escape`, `CommandObservationRow` label &
  inspector display, file-tool previews).
- Real PTY end-to-end verification in `scripts/check-terminal-pty` (mouse off by
  default, empty Tasks pane auto-hidden, queue receipt, `Esc` stops turn while
  preserving queue, `/copy` emits OSC 52, `/mouse on|off` + `BLACKBIRD_MOUSE=1`).
- Adversarial review + full un-bypassed pre-commit gate (`scripts/rigor check debug`).
