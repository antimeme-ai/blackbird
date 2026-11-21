# Storage & Raw Amplification Fix + Unbounded Turn Loop (2026-11-21)

## Problem (observed in 85.7 GiB of live DeepSeek/Oxcart traces)

Real production runs of Blackbird generated **1.7–6.98 GB per session** and
**>14,000 files** in `raw/bb*/`:

1. **`ArchiveCatalog::publish_merge` + frequent checkpoints**: `maybe_checkpoint()`
   fires every 64 journal sequences (~4–6 tool calls). Each checkpoint re-reads
   the entire previous `audit.archive` one 96-byte `pread()` at a time
   (`previous->entry(old++)`), runs an `O(|delta| log N)` `previous->find()` pass,
   and emits per-entry `3206`/`3207`/`3208` + `3007`/`3008` raw records.
2. **`RawStorageNative::read` (`3008`) & `write` (`3009`) payload duplication**:
   Every `pread`/`pwrite` of Blackbird's own `audit`, `audit.archive`, and
   `audit.state` files copies the entire literal file payload verbatim into
   `raw/events.*` (60–70% of the 7 GB blowup), even though those bytes are
   already durably retained in their owning files.
3. **`CommandJobs` 10ms poll/waitid spin**: Worker loops poll every fixed 10ms
   and emit 6 raw events per wake (~600 events/s = 1+ GB/session on quiet commands).
4. **Per-command raw lane churn**: Every `CommandJobs::start()` creates a fresh
   `RawThreadHandle` and retires it on eviction; each retirement rotates
   `events.N -> events.N+1` with 5 new files and 2 directory `fsync`s (2,028
   segments / 14,278 files in one session).
5. **Arbitrary 64-step workflow ceiling**: Hardcoded `for step = 1, 64` limits in
   `programs/turn.lua`, `programs/useful_turn.lua`, and `src/workflows.cpp`
   (`ultracode`) abort long multi-step missions via `error()` and roll back
   staged changes.

## Plan

1. **Metadata-only `3008`/`3009` in `src/raw_storage.cpp`**: Retain exact storage
   I/O metadata (action/resource refs, method, fd, requested count, positioned
   offset, returned byte count, failed flag, errno) on the control partition
   without duplicating literal file payload bytes into `raw/events.*`. Update
   `raw_storage_loan_reservation`, `raw_storage_descriptions`, and the storage
   raw tests to match the metadata-only contract.
2. **Batched single-pass `ArchiveCatalog::publish_merge`**: Stream-read the
   previous catalog in 128-entry (12 KiB) batches, merge with `delta` in a
   single two-pointer pass (writing the final 160-byte prefix header with exact
   count + CRC32C after streaming), and drop per-entry `3206/3207/3208` storms
   during bulk publish while preserving `ContextStore::maybe_checkpoint`
   (`64 seq / 4 MiB`) cadence contracts.
3. **`CommandJobs` stop-wake `poll` + idle backoff**: Add `stop_wake->read_fd()`
   to the worker `pollfd` array for <1ms stop wakeup, and exponentially back off
   empty-timeout polls (`10 -> 20 -> 40 -> 80 -> 160 -> 250ms`, bounded by
   deadline, resetting to `10ms` on any I/O or control activity). Preserve both
   `waitid` calls so filtered-`ECHILD` custody semantics remain intact.
4. **`CommandJobs` raw lane recycling**: Pool retired `RawThreadHandle`s from
   finished, settled, non-pending jobs in `CommandJobs::Impl::free_lanes` and
   reuse them on subsequent `start()` calls.
5. **Remove 64-step hard limits**: Replace fixed `1..64` loops with unbounded
   `while true` loops (preserving `3880/3881/3882` telemetry, restart checks,
   cancellation, and `calls == 0` termination) in `programs/turn.lua`,
   `programs/useful_turn.lua`, and `src/workflows.cpp`.

## Verification Oracles (`tests/storage_amplification_test.cpp`)

All five oracles must fail RED on the old code before implementation and pass
GREEN afterwards, followed by full `scripts/rigor check debug` (CTest + owned
C++/Lua lint):

1. `raw_storage_metadata`: 64 KiB write + read emits `3009`/`3008` with exact
   count/offset and every record `<= 96` bytes (zero payload duplication).
2. `archive_catalog_merge`: 1,600-entry `publish_merge` (prepend + replace +
   append) issues `<= 64` `3007` reads and emits `< 64 KiB` of total raw bytes
   while preserving exact keys.
3. `command_idle_spin`: 1.2s quiet `sleep`, stop wakeup (`< 250ms`), and a
   1s deadline-timeout SIGTERM-ignoring child emit `<= 80` total `2046` poll
   events combined (no 10ms or 0ms poll spin).
4. `command_lane_reuse`: 12 sequential settled `exec` jobs record 12 `2002`
   launches across `<= 2` unique raw worker lanes (no per-command lane churn).
5. `unbounded_turn_steps`: `programs/turn.lua` completes 70 tool rounds + final
   reply without hitting a 64-step error.
