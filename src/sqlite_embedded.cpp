#include "blackbird/sqlite_embedded.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace blackbird::sqlite {
namespace {

using SteadyClock = std::chrono::steady_clock;

constexpr std::string_view kTaintRegistryTable = "_blackbird_taint_registry";

template <typename T>
Result<T> fail_sqlite(ErrorCode code, SqliteError detail) noexcept {
  return Result<T>::failure(Error{code, static_cast<std::int64_t>(detail)});
}

constexpr bool ascii_iequals(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (std::size_t i = 0U; i < lhs.size(); ++i) {
    const char a = (lhs[i] >= 'A' && lhs[i] <= 'Z')
                       ? static_cast<char>(lhs[i] - 'A' + 'a')
                       : lhs[i];
    const char b = (rhs[i] >= 'A' && rhs[i] <= 'Z')
                       ? static_cast<char>(rhs[i] - 'A' + 'a')
                       : rhs[i];
    if (a != b) {
      return false;
    }
  }
  return true;
}

constexpr bool is_dangerous_pragma(std::string_view name) noexcept {
  return ascii_iequals(name, "writable_schema") ||
         ascii_iequals(name, "trusted_schema") ||
         ascii_iequals(name, "temp_store_directory") ||
         ascii_iequals(name, "data_store_directory") ||
         ascii_iequals(name, "legacy_file_format") ||
         ascii_iequals(name, "cell_size_check") ||
         ascii_iequals(name, "ignore_check_constraints");
}

bool is_write_authorizer_action(int action_code) noexcept {
  switch (action_code) {
  case SQLITE_CREATE_INDEX:
  case SQLITE_CREATE_TABLE:
  case SQLITE_CREATE_TEMP_INDEX:
  case SQLITE_CREATE_TEMP_TABLE:
  case SQLITE_CREATE_TEMP_TRIGGER:
  case SQLITE_CREATE_TEMP_VIEW:
  case SQLITE_CREATE_TRIGGER:
  case SQLITE_CREATE_VIEW:
  case SQLITE_DELETE:
  case SQLITE_DROP_INDEX:
  case SQLITE_DROP_TABLE:
  case SQLITE_DROP_TEMP_INDEX:
  case SQLITE_DROP_TEMP_TABLE:
  case SQLITE_DROP_TEMP_TRIGGER:
  case SQLITE_DROP_TEMP_VIEW:
  case SQLITE_DROP_TRIGGER:
  case SQLITE_DROP_VIEW:
  case SQLITE_INSERT:
  case SQLITE_UPDATE:
  case SQLITE_ALTER_TABLE:
  case SQLITE_REINDEX:
  case SQLITE_ANALYZE:
  case SQLITE_CREATE_VTABLE:
  case SQLITE_DROP_VTABLE:
  case SQLITE_SAVEPOINT:
    return true;
  default:
    return false;
  }
}

struct AuthorizerContext {
  bool read_only = false;
  bool allow_taint_registry_write = false;
  bool denied_triggered = false;
  std::string_view denied_reason{};
};

int blackbird_sqlite_authorizer(void *user_data, int action_code, const char *arg1,
                                const char *arg2, const char * /*db_name*/,
                                const char * /*trigger_or_view*/) noexcept {
  auto *ctx = static_cast<AuthorizerContext *>(user_data);
  if (ctx == nullptr) {
    return SQLITE_DENY;
  }

  const std::string_view a1 =
      arg1 != nullptr ? std::string_view{arg1} : std::string_view{};
  const std::string_view a2 =
      arg2 != nullptr ? std::string_view{arg2} : std::string_view{};

  // Always forbid ATTACH / DETACH at the SQLite compiler level.
  if (action_code == SQLITE_ATTACH || action_code == SQLITE_DETACH) {
    ctx->denied_triggered = true;
    ctx->denied_reason = "ATTACH/DETACH denied by authorizer";
    return SQLITE_DENY;
  }

  // Always forbid load_extension function calls.
  if (action_code == SQLITE_FUNCTION && ascii_iequals(a2, "load_extension")) {
    ctx->denied_triggered = true;
    ctx->denied_reason = "load_extension denied by authorizer";
    return SQLITE_DENY;
  }

  // Forbid dangerous PRAGMAs (and all PRAGMA writes under read_only).
  if (action_code == SQLITE_PRAGMA) {
    if (is_dangerous_pragma(a1)) {
      ctx->denied_triggered = true;
      ctx->denied_reason = "dangerous PRAGMA denied by authorizer";
      return SQLITE_DENY;
    }
    if (ctx->read_only && !a2.empty()) {
      ctx->denied_triggered = true;
      ctx->denied_reason = "PRAGMA mutation denied in read-only mode";
      return SQLITE_DENY;
    }
  }

  // Protect internal _blackbird_taint_registry from user SQL mutations.
  if (!ctx->allow_taint_registry_write && is_write_authorizer_action(action_code)) {
    if (ascii_iequals(a1, kTaintRegistryTable) ||
        ascii_iequals(a2, kTaintRegistryTable)) {
      ctx->denied_triggered = true;
      ctx->denied_reason = "writes to _blackbird_taint_registry denied by authorizer";
      return SQLITE_DENY;
    }
  }

  // Enforce strict read-only queries.
  if (ctx->read_only && is_write_authorizer_action(action_code)) {
    ctx->denied_triggered = true;
    ctx->denied_reason = "write denied in read-only mode";
    return SQLITE_DENY;
  }

  // Prevent user SQL from creating or dropping arbitrary virtual tables.
  if (action_code == SQLITE_CREATE_VTABLE || action_code == SQLITE_DROP_VTABLE) {
    // Allow FTS5 and RTree virtual tables only when not read-only.
    if (ctx->read_only || (!ascii_iequals(a2, "fts5") && !ascii_iequals(a2, "rtree"))) {
      ctx->denied_triggered = true;
      ctx->denied_reason = "virtual table module denied by authorizer";
      return SQLITE_DENY;
    }
  }

  return SQLITE_OK;
}

struct ProgressContext {
  SteadyClock::time_point deadline;
  bool timed_out = false;
};

int blackbird_progress_handler(void *user_data) noexcept {
  auto *ctx = static_cast<ProgressContext *>(user_data);
  if (ctx == nullptr) {
    return 0;
  }
  if (SteadyClock::now() >= ctx->deadline) {
    ctx->timed_out = true;
    return 1; // Non-zero interrupts sqlite3_step with SQLITE_INTERRUPT.
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Zero-Copy Read-Only Virtual Table Module (`blackbird_vtab`)
// ---------------------------------------------------------------------------

struct VtabRegistrySnapshot {
  std::unordered_map<std::string, std::shared_ptr<const SqliteVirtualTableData>> tables;
};

struct BlackbirdVtab {
  sqlite3_vtab base{};
  std::shared_ptr<const SqliteVirtualTableData> data;
};

struct BlackbirdVtabCursor {
  sqlite3_vtab_cursor base{};
  std::size_t row_index = 0U;
};

std::string quote_sql_ident(std::string_view ident) {
  std::string out;
  out.reserve(ident.size() + 2U);
  out.push_back('"');
  for (char ch : ident) {
    if (ch == '"') {
      out.push_back('"');
    }
    out.push_back(ch);
  }
  out.push_back('"');
  return out;
}

std::string unquote_arg(std::string_view raw) {
  if (raw.size() >= 2U && ((raw.front() == '\'' && raw.back() == '\'') ||
                           (raw.front() == '"' && raw.back() == '"'))) {
    raw.remove_prefix(1U);
    raw.remove_suffix(1U);
  }
  return std::string{raw};
}

int bb_vtab_connect(sqlite3 *db, void *aux, int argc, const char *const *argv,
                    sqlite3_vtab **pp_vtab, char ** /*pz_err*/) {
  auto *registry = static_cast<const VtabRegistrySnapshot *>(aux);
  if (registry == nullptr || argc < 4 || argv[3] == nullptr) {
    return SQLITE_ERROR;
  }
  const std::string key = unquote_arg(argv[3]);
  const auto it = registry->tables.find(key);
  if (it == registry->tables.end() || !it->second || it->second->columns.empty()) {
    return SQLITE_ERROR;
  }

  std::string create_sql = "CREATE TABLE x(";
  for (std::size_t i = 0U; i < it->second->columns.size(); ++i) {
    if (i > 0U) {
      create_sql += ", ";
    }
    create_sql += quote_sql_ident(it->second->columns[i]);
  }
  create_sql += ")";

  const int rc = sqlite3_declare_vtab(db, create_sql.c_str());
  if (rc != SQLITE_OK) {
    return rc;
  }

  auto *vtab = new (std::nothrow) BlackbirdVtab{};
  if (vtab == nullptr) {
    return SQLITE_NOMEM;
  }
  vtab->data = it->second;
  *pp_vtab = &vtab->base;
  return SQLITE_OK;
}

int bb_vtab_disconnect(sqlite3_vtab *p_vtab) {
  auto *vtab = reinterpret_cast<BlackbirdVtab *>(p_vtab);
  delete vtab;
  return SQLITE_OK;
}

int bb_vtab_best_index(sqlite3_vtab *p_vtab, sqlite3_index_info *info) {
  const auto *vtab = reinterpret_cast<const BlackbirdVtab *>(p_vtab);
  const std::size_t n = (vtab != nullptr && vtab->data) ? vtab->data->rows.size() : 0U;
  info->estimatedRows = static_cast<sqlite3_int64>(n);
  info->estimatedCost = static_cast<double>(n + 1U);
  return SQLITE_OK;
}

int bb_vtab_open(sqlite3_vtab * /*p_vtab*/, sqlite3_vtab_cursor **pp_cursor) {
  auto *cur = new (std::nothrow) BlackbirdVtabCursor{};
  if (cur == nullptr) {
    return SQLITE_NOMEM;
  }
  *pp_cursor = &cur->base;
  return SQLITE_OK;
}

int bb_vtab_close(sqlite3_vtab_cursor *p_cur) {
  auto *cur = reinterpret_cast<BlackbirdVtabCursor *>(p_cur);
  delete cur;
  return SQLITE_OK;
}

int bb_vtab_filter(sqlite3_vtab_cursor *p_cur, int /*idx_num*/,
                   const char * /*idx_str*/, int /*argc*/, sqlite3_value ** /*argv*/) {
  auto *cur = reinterpret_cast<BlackbirdVtabCursor *>(p_cur);
  cur->row_index = 0U;
  return SQLITE_OK;
}

int bb_vtab_next(sqlite3_vtab_cursor *p_cur) {
  auto *cur = reinterpret_cast<BlackbirdVtabCursor *>(p_cur);
  ++cur->row_index;
  return SQLITE_OK;
}

int bb_vtab_eof(sqlite3_vtab_cursor *p_cur) {
  const auto *cur = reinterpret_cast<const BlackbirdVtabCursor *>(p_cur);
  const auto *vtab = reinterpret_cast<const BlackbirdVtab *>(p_cur->pVtab);
  if (vtab == nullptr || !vtab->data) {
    return 1;
  }
  return cur->row_index >= vtab->data->rows.size() ? 1 : 0;
}

int bb_vtab_column(sqlite3_vtab_cursor *p_cur, sqlite3_context *ctx, int col) {
  const auto *cur = reinterpret_cast<const BlackbirdVtabCursor *>(p_cur);
  const auto *vtab = reinterpret_cast<const BlackbirdVtab *>(p_cur->pVtab);
  if (vtab == nullptr || !vtab->data || cur->row_index >= vtab->data->rows.size() ||
      col < 0) {
    sqlite3_result_null(ctx);
    return SQLITE_OK;
  }
  const auto &row = vtab->data->rows[cur->row_index];
  const auto ucol = static_cast<std::size_t>(col);
  if (ucol >= row.size()) {
    sqlite3_result_null(ctx);
    return SQLITE_OK;
  }
  const auto &cell = row[ucol];
  if (std::holds_alternative<std::monostate>(cell)) {
    sqlite3_result_null(ctx);
  } else if (const auto *i = std::get_if<std::int64_t>(&cell)) {
    sqlite3_result_int64(ctx, static_cast<sqlite3_int64>(*i));
  } else if (const auto *d = std::get_if<double>(&cell)) {
    sqlite3_result_double(ctx, *d);
  } else if (const auto *s = std::get_if<std::string>(&cell)) {
    // Zero-copy: SQLITE_STATIC is valid for the duration of the query because
    // the immutable snapshot is pinned in VtabRegistrySnapshot on the stack.
    sqlite3_result_text64(ctx, s->data(), static_cast<sqlite3_uint64>(s->size()),
                          SQLITE_STATIC, SQLITE_UTF8);
  }
  return SQLITE_OK;
}

int bb_vtab_rowid(sqlite3_vtab_cursor *p_cur, sqlite3_int64 *p_rowid) {
  const auto *cur = reinterpret_cast<const BlackbirdVtabCursor *>(p_cur);
  *p_rowid = static_cast<sqlite3_int64>(cur->row_index + 1U);
  return SQLITE_OK;
}

// Read-only module: xUpdate is nullptr so SQLite refuses INSERT/UPDATE/DELETE!
const sqlite3_module kBlackbirdVtabModule = {
    0,                  // iVersion
    bb_vtab_connect,    // xCreate
    bb_vtab_connect,    // xConnect
    bb_vtab_best_index, // xBestIndex
    bb_vtab_disconnect, // xDisconnect
    bb_vtab_disconnect, // xDestroy
    bb_vtab_open,       // xOpen
    bb_vtab_close,      // xClose
    bb_vtab_filter,     // xFilter
    bb_vtab_next,       // xNext
    bb_vtab_eof,        // xEof
    bb_vtab_column,     // xColumn
    bb_vtab_rowid,      // xRowid
    nullptr,            // xUpdate (read-only!)
    nullptr,            // xBegin
    nullptr,            // xSync
    nullptr,            // xCommit
    nullptr,            // xRollback
    nullptr,            // xFindFunction
    nullptr,            // xRename
    nullptr,            // xSavepoint
    nullptr,            // xRelease
    nullptr,            // xRollbackTo
    nullptr,            // xShadowName
    nullptr,            // xIntegrity
};

struct ScopedSqliteDb {
  sqlite3 *db = nullptr;
  ScopedSqliteDb() noexcept = default;
  ~ScopedSqliteDb() {
    if (db != nullptr) {
      // Unregister callbacks before closing so SQLite never dereferences
      // stack contexts during teardown.
      sqlite3_progress_handler(db, 0, nullptr, nullptr);
      (void)sqlite3_set_authorizer(db, nullptr, nullptr);
      (void)sqlite3_close_v2(db);
      db = nullptr;
    }
  }
  ScopedSqliteDb(const ScopedSqliteDb &) = delete;
  ScopedSqliteDb &operator=(const ScopedSqliteDb &) = delete;
};

struct ScopedSqliteStmt {
  sqlite3_stmt *stmt = nullptr;
  ScopedSqliteStmt() noexcept = default;
  ~ScopedSqliteStmt() { reset(); }
  ScopedSqliteStmt(const ScopedSqliteStmt &) = delete;
  ScopedSqliteStmt &operator=(const ScopedSqliteStmt &) = delete;
  void reset() noexcept {
    if (stmt != nullptr) {
      (void)sqlite3_finalize(stmt);
      stmt = nullptr;
    }
  }
};

std::size_t estimate_value_bytes(const Value &val) noexcept {
  if (std::holds_alternative<std::nullptr_t>(val.value())) {
    return 4U;
  }
  if (std::holds_alternative<bool>(val.value())) {
    return 5U;
  }
  if (std::holds_alternative<Number>(val.value())) {
    return 12U;
  }
  if (const auto *s = std::get_if<std::string>(&val.value())) {
    return s->size() + 2U;
  }
  return 16U;
}

} // namespace

SqliteCapabilities probe_embedded_sqlite_capabilities() {
  SqliteCapabilities caps{};
  caps.available = true;
  caps.binary_path = "embedded:sqlite3";
  caps.version = sqlite3_libversion();
  caps.supports_safe_flag = true;     // Enforced via sqlite3_set_authorizer + DEFENSIVE
  caps.supports_nofollow_flag = true; // Enforced via SQLITE_OPEN_NOFOLLOW
  caps.supports_wal = true;

  for (int i = 0;; ++i) {
    const char *opt = sqlite3_compileoption_get(i);
    if (opt == nullptr) {
      break;
    }
    const std::string_view sv{opt};
    caps.compile_options.emplace_back(sv);
    if (sv == "ENABLE_FTS5") {
      caps.supports_fts5 = true;
    }
    if (sv == "ENABLE_JSON1") {
      caps.supports_json1 = true;
    }
  }
  // JSON functions are built-in by default since SQLite 3.38.0 even if
  // ENABLE_JSON1 isn't listed in compile options; verify directly.
  if (!caps.supports_json1) {
    caps.supports_json1 = (sqlite3_libversion_number() >= 3038000);
  }
  return caps;
}

EmbeddedSqliteBackend::EmbeddedSqliteBackend(EmbeddedSqliteBackendConfig config)
    : config_(config) {}

EmbeddedSqliteBackend::~EmbeddedSqliteBackend() = default;

Result<SqliteCapabilities> EmbeddedSqliteBackend::probe() const {
  return Result<SqliteCapabilities>::success(probe_embedded_sqlite_capabilities());
}

Result<void> EmbeddedSqliteBackend::register_virtual_table(
    std::shared_ptr<const SqliteVirtualTableData> snapshot) {
  if (!snapshot || !valid_sql_identifier(snapshot->table_name) ||
      snapshot->columns.empty()) {
    return fail_sqlite<void>(ErrorCode::invalid_range, SqliteError::invalid_table_name);
  }
  for (const auto &col : snapshot->columns) {
    if (!valid_sql_identifier(col)) {
      return fail_sqlite<void>(ErrorCode::invalid_range,
                               SqliteError::invalid_column_name);
    }
  }
  std::scoped_lock lock{vtab_mutex_};
  vtabs_[snapshot->table_name] = std::move(snapshot);
  return Result<void>::success();
}

bool EmbeddedSqliteBackend::unregister_virtual_table(std::string_view table_name) {
  std::scoped_lock lock{vtab_mutex_};
  return vtabs_.erase(std::string{table_name}) > 0U;
}

std::vector<std::string> EmbeddedSqliteBackend::registered_virtual_tables() const {
  std::scoped_lock lock{vtab_mutex_};
  std::vector<std::string> out;
  out.reserve(vtabs_.size());
  for (const auto &[name, _] : vtabs_) {
    out.push_back(name);
  }
  std::sort(out.begin(), out.end());
  return out;
}

Result<SqliteBackendResponse>
EmbeddedSqliteBackend::execute(const SqliteBackendRequest &request) {
  if (request.db_path.empty()) {
    return fail_sqlite<SqliteBackendResponse>(ErrorCode::invalid_range,
                                              SqliteError::invalid_path);
  }
  if (request.sql.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return fail_sqlite<SqliteBackendResponse>(ErrorCode::capacity,
                                              SqliteError::invalid_sql);
  }

  const auto start_tp = SteadyClock::now();

  // Declare all callback/module contexts BEFORE ScopedSqliteDb so they strictly
  // outlive sqlite3_close_v2() in reverse stack destruction order.
  VtabRegistrySnapshot vtab_snapshot{};
  {
    std::scoped_lock lock{vtab_mutex_};
    vtab_snapshot.tables = vtabs_;
  }

  AuthorizerContext auth_ctx{};
  auth_ctx.read_only = request.limits.read_only;
  auth_ctx.allow_taint_registry_write = config_.allow_internal_taint_registry_writes ||
                                        request.internal_taint_registry_write;

  ProgressContext prog_ctx{};
  const std::uint32_t timeout_ms =
      request.limits.timeout_ms > 0U ? request.limits.timeout_ms : kDefaultTimeoutMs;
  prog_ctx.deadline = start_tp + std::chrono::milliseconds{timeout_ms};

  ScopedSqliteDb conn{};
  const int open_flags =
      (request.limits.read_only ? SQLITE_OPEN_READONLY
                                : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)) |
      SQLITE_OPEN_NOFOLLOW;
  const int open_rc =
      sqlite3_open_v2(request.db_path.c_str(), &conn.db, open_flags, nullptr);
  if (open_rc != SQLITE_OK || conn.db == nullptr) {
    return fail_sqlite<SqliteBackendResponse>(ErrorCode::io,
                                              SqliteError::sql_execution_failed);
  }

  (void)sqlite3_db_config(conn.db, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
  (void)sqlite3_db_config(conn.db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr);
  (void)sqlite3_db_config(conn.db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr);
  (void)sqlite3_busy_timeout(conn.db, static_cast<int>(std::min<std::uint32_t>(
                                          request.limits.busy_timeout_ms, 60000U)));

  // Mount registered read-only zero-copy virtual tables into `temp` schema before
  // installing the user SQL authorizer.
  if (!vtab_snapshot.tables.empty()) {
    const int mod_rc = sqlite3_create_module_v2(
        conn.db, "blackbird_vtab", &kBlackbirdVtabModule, &vtab_snapshot, nullptr);
    if (mod_rc != SQLITE_OK) {
      return fail_sqlite<SqliteBackendResponse>(ErrorCode::io,
                                                SqliteError::sql_execution_failed);
    }
    for (const auto &[name, _] : vtab_snapshot.tables) {
      const std::string mount_sql = "CREATE VIRTUAL TABLE temp." +
                                    quote_sql_ident(name) + " USING blackbird_vtab('" +
                                    name + "');";
      char *err_msg = nullptr;
      const int exec_rc =
          sqlite3_exec(conn.db, mount_sql.c_str(), nullptr, nullptr, &err_msg);
      if (err_msg != nullptr) {
        sqlite3_free(err_msg);
      }
      if (exec_rc != SQLITE_OK) {
        return fail_sqlite<SqliteBackendResponse>(ErrorCode::io,
                                                  SqliteError::sql_execution_failed);
      }
    }
  }

  if (config_.enable_authorizer) {
    (void)sqlite3_set_authorizer(conn.db, blackbird_sqlite_authorizer, &auth_ctx);
  }

  sqlite3_progress_handler(conn.db, std::max(100, config_.progress_handler_steps),
                           blackbird_progress_handler, &prog_ctx);

  SqliteBackendResponse resp{};
  const std::size_t max_rows =
      request.limits.max_rows > 0U ? request.limits.max_rows : kDefaultMaxRows;
  const std::size_t max_bytes = request.limits.max_output_bytes > 0U
                                    ? request.limits.max_output_bytes
                                    : kDefaultMaxOutputBytes;

  const char *cursor = request.sql.c_str();
  const char *const end = cursor + request.sql.size();

  while (cursor < end) {
    ScopedSqliteStmt stmt{};
    const char *tail = nullptr;
    const int prep_rc = sqlite3_prepare_v2(
        conn.db, cursor, static_cast<int>(end - cursor), &stmt.stmt, &tail);
    if (prep_rc != SQLITE_OK) {
      if (prog_ctx.timed_out || prep_rc == SQLITE_INTERRUPT) {
        return fail_sqlite<SqliteBackendResponse>(ErrorCode::interrupted,
                                                  SqliteError::timeout);
      }
      if (auth_ctx.denied_triggered || prep_rc == SQLITE_AUTH) {
        return fail_sqlite<SqliteBackendResponse>(ErrorCode::invalid_range,
                                                  SqliteError::forbidden_sql_rejected);
      }
      return fail_sqlite<SqliteBackendResponse>(ErrorCode::invalid_range,
                                                SqliteError::sql_execution_failed);
    }
    if (stmt.stmt == nullptr) {
      if (tail == nullptr || tail <= cursor) {
        break;
      }
      cursor = tail;
      continue;
    }

    const int col_count = sqlite3_column_count(stmt.stmt);
    std::vector<std::string> stmt_cols;
    if (col_count > 0) {
      stmt_cols.reserve(static_cast<std::size_t>(col_count));
      for (int c = 0; c < col_count; ++c) {
        const char *cname = sqlite3_column_name(stmt.stmt, c);
        stmt_cols.emplace_back(cname != nullptr ? cname : "");
      }
    }

    Value::Array stmt_rows;
    std::size_t stmt_total_rows = 0U;
    std::size_t stmt_bytes = 0U;
    bool stmt_trunc_rows = false;
    bool stmt_trunc_bytes = false;

    for (;;) {
      const int step_rc = sqlite3_step(stmt.stmt);
      if (step_rc == SQLITE_DONE) {
        break;
      }
      if (step_rc == SQLITE_ROW) {
        if (!request.expect_rows || col_count <= 0) {
          continue;
        }
        ++stmt_total_rows;
        if (stmt_rows.size() >= max_rows) {
          stmt_trunc_rows = true;
          continue;
        }
        Value::Object row_obj;
        row_obj.reserve(static_cast<std::size_t>(col_count));
        std::size_t row_bytes = 2U;
        for (int c = 0; c < col_count; ++c) {
          Value cell{nullptr};
          switch (sqlite3_column_type(stmt.stmt, c)) {
          case SQLITE_INTEGER:
            cell = Value{
                Number{static_cast<std::int64_t>(sqlite3_column_int64(stmt.stmt, c))}};
            break;
          case SQLITE_FLOAT:
            cell = Value{Number{sqlite3_column_double(stmt.stmt, c)}};
            break;
          case SQLITE_TEXT: {
            const auto *txt =
                reinterpret_cast<const char *>(sqlite3_column_text(stmt.stmt, c));
            const int len = sqlite3_column_bytes(stmt.stmt, c);
            if (txt != nullptr && len >= 0) {
              cell = Value{std::string{txt, static_cast<std::size_t>(len)}};
            } else {
              cell = Value{std::string{}};
            }
            break;
          }
          case SQLITE_BLOB: {
            const int len = sqlite3_column_bytes(stmt.stmt, c);
            cell = Value{"<blob:" + std::to_string(std::max(0, len)) + "B>"};
            break;
          }
          case SQLITE_NULL:
          default:
            cell = Value{nullptr};
            break;
          }
          row_bytes += stmt_cols[static_cast<std::size_t>(c)].size() + 4U +
                       estimate_value_bytes(cell);
          row_obj.emplace_back(stmt_cols[static_cast<std::size_t>(c)], std::move(cell));
        }
        if (stmt_bytes + row_bytes > max_bytes) {
          stmt_trunc_bytes = true;
          break;
        }
        stmt_bytes += row_bytes;
        stmt_rows.push_back(Value::object(std::move(row_obj)));
        continue;
      }
      if (prog_ctx.timed_out || step_rc == SQLITE_INTERRUPT) {
        return fail_sqlite<SqliteBackendResponse>(ErrorCode::interrupted,
                                                  SqliteError::timeout);
      }
      if (auth_ctx.denied_triggered || step_rc == SQLITE_AUTH) {
        return fail_sqlite<SqliteBackendResponse>(ErrorCode::invalid_range,
                                                  SqliteError::forbidden_sql_rejected);
      }
      return fail_sqlite<SqliteBackendResponse>(ErrorCode::invalid_range,
                                                SqliteError::sql_execution_failed);
    }

    if (col_count > 0 && request.expect_rows) {
      resp.columns = std::move(stmt_cols);
      resp.rows = std::move(stmt_rows);
      resp.total_rows_seen = stmt_total_rows;
      resp.output_bytes = stmt_bytes;
      resp.truncated_rows = stmt_trunc_rows;
      resp.truncated_bytes = stmt_trunc_bytes;
    }

    if (tail == nullptr || tail <= cursor) {
      break;
    }
    cursor = tail;
  }

  resp.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         SteadyClock::now() - start_tp)
                         .count();
  return Result<SqliteBackendResponse>::success(std::move(resp));
}

} // namespace blackbird::sqlite
