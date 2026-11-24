#pragma once

#include "blackbird/brakes_policy.hpp"
#include "blackbird/foundation.hpp"
#include "blackbird/lan_party_protocol.hpp"
#include "blackbird/value.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace blackbird::sqlite {

// ---------------------------------------------------------------------------
// Error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

enum class SqliteError : std::int64_t {
  none = 0,

  invalid_db_name = 4000,
  invalid_table_name = 4001,
  invalid_column_name = 4002,
  invalid_sql = 4003,
  dot_command_rejected = 4004,
  forbidden_sql_rejected = 4005,

  invalid_path = 4006,
  symlink_rejected = 4007,
  insecure_permissions = 4008,

  binary_not_found = 4009,
  spawn_failed = 4010,
  timeout = 4011,
  output_limit_exceeded = 4012,
  sql_execution_failed = 4013,
  json_parse_failed = 4014,
  ingest_parse_failed = 4015,

  db_not_found = 4016,
  db_already_exists = 4017,
  io_failed = 4018,
  invalid_config = 4019,
  safe_mode_unsupported = 4020,
};

constexpr SqliteError sqlite_error_of(const Error &error) noexcept {
  return static_cast<SqliteError>(error.detail);
}

std::string_view sqlite_error_name(SqliteError detail) noexcept;

// ---------------------------------------------------------------------------
// Defaults & Limits
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMaxDbNameLength = 64U;
inline constexpr std::size_t kMaxIdentifierLength = 64U;
inline constexpr std::size_t kDefaultMaxRows = 200U;
inline constexpr std::size_t kDefaultMaxOutputBytes = 64U * 1024U;
inline constexpr std::uint32_t kDefaultTimeoutMs = 5000U;
inline constexpr std::uint32_t kDefaultBusyTimeoutMs = 5000U;
inline constexpr std::size_t kMaxStderrBytes = 16U * 1024U;

// Distinct wrapper preventing accidental parameter transposition with SQL/data text.
struct TableName {
  std::string_view value;
  constexpr TableName(std::string_view v) noexcept : value(v) {}
  constexpr TableName(const char *v) noexcept : value(v ? v : "") {}
  TableName(const std::string &v) noexcept : value(v) {}
};

// ---------------------------------------------------------------------------
// Validation & SQL Lexer / Guardrail Analysis
// ---------------------------------------------------------------------------

// Valid DB name: 1..64 characters, strictly [A-Za-z0-9_-]. Rejects '/', '.', '..'.
bool valid_db_name(std::string_view name) noexcept;

// Valid SQL table/column identifier: 1..64 chars, leading [A-Za-z_], tail [A-Za-z0-9_],
// rejecting reserved sqlite_* prefix.
bool valid_sql_identifier(std::string_view name) noexcept;

struct SqlAnalysis {
  std::set<std::string> referenced_identifiers;
  std::set<std::string> write_targets;
  bool has_write = false;
};

// Lexes SQL with full awareness of single/double/backtick/bracket quoting and
// -- / /* */ comments. Rejects:
// - NUL bytes, unclosed strings/identifiers/block comments
// - sqlite3 CLI dot-commands (.shell, .system, .import, .output, .load, .read,
//   .open, .backup, .restore, etc.) at any line start outside strings/comments
// - ATTACH, DETACH, load_extension (unquoted or quoted function call),
//   VACUUM INTO, dangerous PRAGMAs (writable_schema, trusted_schema,
//   temp_store_directory, data_store_directory), and mutations to the internal
//   taint registry table.
Result<SqlAnalysis> validate_and_analyze_sql(std::string_view sql);

// Computes deterministic 64-char lowercase SHA-256 hex digest for a project root.
std::string compute_project_db_hash(const std::filesystem::path &project_root);

// Resolves ~/.local/share/blackbird/model_memory (or
// XDG_DATA_HOME/blackbird/model_memory).
Result<std::filesystem::path>
resolve_default_model_state_dir(const lan::EnvLookupFn &env_lookup = {});

// ---------------------------------------------------------------------------
// Capabilities & Backend Abstraction (Stage 1 CLI -> Stage 2 sqlite3.c ready)
// ---------------------------------------------------------------------------

struct SqliteCapabilities {
  bool available = false;
  std::filesystem::path binary_path;
  std::string version;
  bool supports_safe_flag = false;
  bool supports_nofollow_flag = false;
  bool supports_fts5 = false;
  bool supports_json1 = false;
  bool supports_wal = true;
  std::vector<std::string> compile_options;
};

struct SqliteExecLimits {
  std::size_t max_rows = kDefaultMaxRows;
  std::size_t max_output_bytes = kDefaultMaxOutputBytes;
  std::uint32_t timeout_ms = kDefaultTimeoutMs;
  std::uint32_t busy_timeout_ms = kDefaultBusyTimeoutMs;
  bool read_only = false;
};

struct SqliteBackendRequest {
  std::filesystem::path db_path;
  std::string sql;
  SqliteExecLimits limits{};
  bool expect_rows = true;
  bool internal_taint_registry_write = false;
};

struct SqliteBackendResponse {
  Value::Array rows;
  std::vector<std::string> columns;
  std::size_t total_rows_seen = 0U;
  std::size_t output_bytes = 0U;
  bool truncated_rows = false;
  bool truncated_bytes = false;
  std::string stderr_text;
  std::int64_t duration_ns = 0;
};

// Backend interface designed so an optional Stage 2 embedded sqlite3.c amalgamation
// can replace Stage 1 CliSqliteBackend without changing SqliteWorkbench callers.
class ISqliteBackend {
public:
  virtual ~ISqliteBackend() = default;
  virtual std::string_view backend_name() const noexcept = 0;
  virtual Result<SqliteCapabilities> probe() const = 0;
  virtual Result<SqliteBackendResponse>
  execute(const SqliteBackendRequest &request) = 0;
};

using SqliteBackend = ISqliteBackend;

struct CliSqliteBackendConfig {
  std::optional<std::filesystem::path> binary_override = std::nullopt;
  bool require_safe_mode = true;
  std::uint32_t probe_timeout_ms = 3000U;
  lan::EnvLookupFn env_lookup = {};
};

// Passively probes the system sqlite3 binary, version, -safe, -nofollow, FTS5,
// and JSON1 against :memory: without creating any files on disk.
Result<SqliteCapabilities> probe_sqlite_capabilities(
    const std::optional<std::filesystem::path> &binary_override = std::nullopt,
    const lan::EnvLookupFn &env_lookup = {});

// Stage 1 zero-dependency backend driving system sqlite3 via posix_spawn + pipes
// (ZERO shell, O_CLOEXEC, process group kill on timeout, -safe -batch -bail -json
// -cmd ".timeout <ms>").
class CliSqliteBackend final : public ISqliteBackend {
public:
  explicit CliSqliteBackend(CliSqliteBackendConfig config = {});

  std::string_view backend_name() const noexcept override { return "cli-sqlite3"; }
  Result<SqliteCapabilities> probe() const override;
  Result<SqliteBackendResponse> execute(const SqliteBackendRequest &request) override;

private:
  Result<SqliteCapabilities> ensure_probed();

  CliSqliteBackendConfig config_;
  std::optional<SqliteCapabilities> cached_capabilities_;
};

// ---------------------------------------------------------------------------
// Scoped Workbench (Ephemeral scratch_db + Permanent model_db)
// ---------------------------------------------------------------------------

enum class SqliteDbScope : std::uint8_t {
  scratch = 0,
  model_private = 1,
};

struct SqliteDbHandle {
  SqliteDbScope scope = SqliteDbScope::scratch;
  std::string name;
  std::filesystem::path path;

  bool operator==(const SqliteDbHandle &) const = default;
};

struct SqliteQueryResult {
  Value::Array rows;
  std::vector<std::string> columns;
  std::size_t total_rows_seen = 0U;
  std::size_t output_bytes = 0U;
  bool truncated_rows = false;
  bool truncated_bytes = false;
  bool contains_tainted_data = false;
  std::string stderr_text;
  std::int64_t duration_ns = 0;
};

struct SqliteIngestResult {
  std::string table_name;
  std::vector<std::string> columns;
  std::size_t rows_ingested = 0U;
  bool tainted = false;
  std::int64_t duration_ns = 0;
};

struct SqliteWorkbenchConfig {
  std::optional<std::filesystem::path> scratch_parent_dir = std::nullopt;
  std::optional<std::filesystem::path> model_state_dir = std::nullopt;
  std::optional<std::filesystem::path> project_root = std::nullopt;
  // Authoritative Journal/Originals directories that model_db must never overlap.
  std::vector<std::filesystem::path> forbidden_journal_dirs;
  std::optional<std::filesystem::path> sqlite_binary_override = std::nullopt;
  SqliteExecLimits default_limits{};
  // Optional Brakes turn taint latch. Queries reading tainted tables/DBs latch
  // this state, and writes while latched automatically taint target tables.
  brakes::TurnTaintState *turn_taint = nullptr;
  brakes::PartyTrustSectionPolicy party_trust_policy{};
  lan::EnvLookupFn env_lookup = {};
};

class SqliteWorkbench {
public:
  explicit SqliteWorkbench(SqliteWorkbenchConfig config = {},
                           std::unique_ptr<ISqliteBackend> backend = nullptr);
  ~SqliteWorkbench();

  SqliteWorkbench(const SqliteWorkbench &) = delete;
  SqliteWorkbench &operator=(const SqliteWorkbench &) = delete;
  SqliteWorkbench(SqliteWorkbench &&other) noexcept;
  SqliteWorkbench &operator=(SqliteWorkbench &&other) noexcept;

  Result<SqliteCapabilities> probe_capabilities() const;

  // Ephemeral scratch_db lifecycle (auto-destroyed on close_scratch or
  // ~SqliteWorkbench).
  Result<SqliteDbHandle> open_scratch(std::string_view name);
  Result<void> close_scratch(std::string_view name);
  std::optional<std::filesystem::path> scratch_session_dir() const;

  // Permanent model-private DB
  // (~/.local/share/blackbird/model_memory/<project-hash>.db, 0700 dir, 0600 file,
  // O_NOFOLLOW, WAL mode, strictly isolated from Journal/Originals).
  Result<SqliteDbHandle> open_model_db(
      const std::optional<std::filesystem::path> &project_root_override = std::nullopt);

  // Guarded SQL execution & querying.
  Result<SqliteQueryResult> exec(const SqliteDbHandle &db, std::string_view sql,
                                 std::optional<SqliteExecLimits> limits = std::nullopt);
  Result<SqliteQueryResult>
  query(const SqliteDbHandle &db, std::string_view sql,
        std::optional<SqliteExecLimits> limits = std::nullopt);

  // Structural bulk ingestors (pure C++ parsing -> escaped transactional INSERTs;
  // never uses sqlite3 .import).
  Result<SqliteIngestResult> ingest_jsonl(const SqliteDbHandle &db, TableName table,
                                          std::string_view jsonl_text,
                                          bool tainted = false);
  Result<SqliteIngestResult> ingest_csv(const SqliteDbHandle &db, TableName table,
                                        std::string_view csv_text,
                                        bool tainted = false);
  Result<SqliteIngestResult> ingest_lines(const SqliteDbHandle &db, TableName table,
                                          std::string_view text, bool tainted = false);
  Result<SqliteIngestResult> ingest_records(const SqliteDbHandle &db, TableName table,
                                            const Value::Array &records,
                                            bool tainted = false);

  // Per-DB / per-table Brakes taint tracking.
  Result<void> mark_db_tainted(const SqliteDbHandle &db);
  Result<void> mark_table_tainted(const SqliteDbHandle &db, TableName table);
  bool is_db_tainted(const SqliteDbHandle &db) const;
  bool is_table_tainted(const SqliteDbHandle &db, TableName table) const;

  void attach_turn_taint(brakes::TurnTaintState *state) noexcept {
    config_.turn_taint = state;
  }
  brakes::TurnTaintState *turn_taint() const noexcept { return config_.turn_taint; }

private:
  struct DbEntry {
    SqliteDbHandle handle;
    std::filesystem::path parent_dir;
    std::string filename;
    std::uint64_t parent_dev = 0U;
    std::uint64_t parent_ino = 0U;
    bool db_tainted = false;
    std::set<std::string> tainted_tables;
  };

  Result<void> ensure_scratch_session_dir();
  void destroy_all_scratch() noexcept;
  Result<DbEntry *> lookup_and_verify_db(const SqliteDbHandle &db);
  const DbEntry *find_db_const(const SqliteDbHandle &db) const;
  Result<void> persist_taint_entry(DbEntry &entry, std::string_view scope_key,
                                   bool is_db_wide);
  void load_persisted_taint(DbEntry &entry);
  void tighten_sidecars_locked(const DbEntry &entry) const noexcept;
  Result<SqliteQueryResult> run_guarded_sql(const SqliteDbHandle &db,
                                            std::string_view sql,
                                            std::optional<SqliteExecLimits> limits,
                                            bool expect_rows);
  void latch_turn_taint_on_read() noexcept;
  bool is_turn_tainted() const noexcept;

  SqliteWorkbenchConfig config_;
  std::unique_ptr<ISqliteBackend> backend_;
  std::optional<std::filesystem::path> scratch_session_dir_;
  std::uint64_t scratch_dir_dev_ = 0U;
  std::uint64_t scratch_dir_ino_ = 0U;
  std::unordered_map<std::string, DbEntry> scratch_dbs_;
  std::unordered_map<std::string, DbEntry> model_dbs_;
};

} // namespace blackbird::sqlite
