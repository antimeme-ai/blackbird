#pragma once
#include "blackbird/packet.hpp"
#include "blackbird/retained_state.hpp"
#include "blackbird/value.hpp"
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {
template <class T> T unwrap(Result<T> result) {
  if (!result.has_value())
    throw result.error();
  return std::move(result).value();
}
inline void unwrap(Result<void> result) {
  if (!result.has_value())
    throw result.error();
}
std::string read_text(const ImmutableBytes &bytes);
Result<Value> read_packet(const ImmutableBytes &bytes, ValueLimits limits = {});
Result<Value> read_application_packet(const ApplicationRecordEvent &record);
std::string hex_identity(const IdentityBytes &bytes);
const Value &field(const Value &value, std::string_view name);
const std::string &string_field(const Value &value, std::string_view name);

struct OriginalCapture {
  std::string_view label;
  std::string_view bytes;
  Value metadata;
};

class AuditLog {
public:
  explicit AuditLog(RetainedState &root) : root_(root) {}
  ApplicationRecordId issue() { return unwrap(root_.issue<ApplicationRecordId>()); }
  std::string record(ApplicationChannel channel, const Value &packet);
  RecordReference record(ApplicationRecordId identity, ApplicationChannel channel,
                         const Value &packet);
  std::string original(OriginalCapture capture);
  std::optional<SourceReference> original(ApplicationRecordId identity,
                                          OriginalCapture capture);
  SourceReference retain_program(std::string_view source,
                                 DefinitionGenerationId generation);
  Value inspect(const Value &query, std::optional<OperationAttemptId> attempt = {});
  Value trajectory(const Value &query, std::optional<OperationAttemptId> attempt = {});
  Value variables(const Value &query, std::optional<OperationAttemptId> attempt = {});
  RetainedState &root() noexcept { return root_; }

private:
  RetainedState &root_;
};

enum class BlockKind : std::uint8_t { instruction = 0, exchange = 1, note = 2 };
std::string_view block_kind_name(BlockKind kind) noexcept;
std::optional<BlockKind> parse_block_kind(std::string_view name) noexcept;

// One self-contained semantic unit in working context.
// - instruction: operator prompt, system/developer brief, restart note
// - exchange: one model round (reasoning + assistant text + function_calls + their
//   matching function_call_outputs grouped automatically by call_id)
// - note: summary, compaction note, or synthetic context block
struct Block {
  std::uint64_t id = 0;
  std::vector<Value> items;
  std::vector<std::uint64_t> replaces;
  std::vector<IdentityBytes> records; // journal record identities that built this block
  std::string label;
  std::uint64_t bytes = 0;
  BlockKind kind = BlockKind::note;
  bool pinned = false;
  bool open = false;
};

// Metadata for a dropped/summarized block; original payload stays on disk in the
// append-only journal and is loaded on demand for read_block() / restore.
struct ArchivedBlock {
  std::uint64_t id = 0;
  std::vector<IdentityBytes> records;
  std::string label;
  std::string preview;
  std::uint64_t bytes = 0;
  BlockKind kind = BlockKind::note;
};

enum class ContextChangeKind : std::uint8_t { edited, restored, managed };
struct ContextChange {
  std::string revision;
  std::string mode;
  std::optional<std::size_t> bytes_before;
  std::optional<std::size_t> bytes_after;
  ContextChangeKind kind = ContextChangeKind::managed;
};

enum class CompactOp : std::uint8_t { drop, summarize, restore, pin, unpin };
std::string_view compact_op_name(CompactOp op) noexcept;
std::optional<CompactOp> parse_compact_op(std::string_view name) noexcept;

struct CompactRequest {
  std::vector<std::uint64_t> ids;
  std::optional<std::uint64_t> from;
  std::optional<std::uint64_t> to;
  std::string summary;
  CompactOp op = CompactOp::drop;
};

struct ReadBlockOptions {
  std::size_t offset = 0;
  std::size_t limit = 16384;
};

struct ContextOpen {
  std::uint64_t whole_history_limit = 64ULL * 1024 * 1024;
  bool defer_checkpoint = false;
  bool whole_history = false;
  bool probe = false;
};

// Lightweight block-based working context backed by the append-only audit journal.
class ContextStore {
public:
  // Level 2: clean block-based context format.
  static constexpr std::uint64_t format_level = 2;
  static constexpr std::int64_t level_refused = 1;
  static constexpr std::int64_t whole_history_refused = 2;

  explicit ContextStore(AuditLog &log);
  ContextStore(AuditLog &log, ContextOpen open);
  ~ContextStore();
  ContextStore(const ContextStore &) = delete;
  ContextStore &operator=(const ContextStore &) = delete;

  void finish_open();
  Result<void> checkpoint();
  const std::optional<Error> &checkpoint_error() const noexcept {
    return checkpoint_error_;
  }

  const std::string &head() const noexcept { return head_; }
  std::uint64_t next_id() const noexcept { return next_id_; }
  const std::vector<Block> &blocks() const noexcept { return blocks_; }
  const std::vector<ArchivedBlock> &archived() const noexcept { return archived_; }
  std::uint64_t total_bytes() const noexcept;
  Value::Array items() const;
  bool has_open_exchanges() const noexcept;

  // Append wire items. function_call_outputs whose call_id matches an open exchange
  // automatically fold into that exchange block and close it once all calls are
  // answered. Returns the ID of the created or extended block (0 when items is empty).
  std::uint64_t append(Value::Array items, std::string_view label,
                       std::optional<BlockKind> declared = std::nullopt);

  // Close any open exchange blocks by appending synthetic function_call_output items
  // for unanswered call_ids. Returns the number of synthetic outputs appended.
  std::size_t close_open_exchanges(bool interrupted);

  // Drop, summarize, restore, pin, or unpin blocks by simple integer IDs / range.
  Value compact(const CompactRequest &request);

  // Full programmatic block replacement (Lua escape hatch).
  Value replace_blocks(const Value &blocks_value);

  // Model/UI inspection: live blocks with previews (optionally archived metadata too).
  Value list(bool include_archived = false) const;

  // Read exact original content of a live or archived block as bounded JSON UTF-8.
  Value read_block(std::uint64_t id, ReadBlockOptions options = {}) const;

  // Compact stats summary.
  Value stats() const;

  // True if a live block carries this origin label (used for restart/resume
  // idempotency).
  bool live_origin(std::string_view label) const;

  // True if a live instruction block contains an item equal to item (key order
  // ignored).
  bool live_instruction(const Value &item) const;

  // Seed a fresh successor session (backstop / --seed-session).
  static void validate_successor_seed(const Value &seed);
  void seed_successor(const Value &seed);

  // Optional callback invoked after mutating publications (compact/restore/replace).
  std::function<void(const ContextChange &)> changed;

private:
  void load_from_snapshot(const SavedState &saved);
  void replay_facts(const SavedState *restored);
  void apply_record(const ApplicationRecordEvent &record);
  std::optional<Value::Array>
  load_block_items(std::uint64_t id, const std::vector<IdentityBytes> &records) const;
  void write_format_level();
  void maybe_checkpoint();
  void notify_changed(ContextChangeKind kind, std::string_view mode,
                      std::uint64_t before_bytes, std::uint64_t after_bytes) const;

  AuditLog &log_;
  std::weak_ptr<void> root_lifetime_;
  ContextOpen open_;
  std::string head_;
  std::uint64_t next_id_ = 1;
  std::vector<Block> blocks_;
  std::vector<ArchivedBlock> archived_;
  std::optional<Error> checkpoint_error_;
  bool format_level_written_ = false;
};

} // namespace blackbird
