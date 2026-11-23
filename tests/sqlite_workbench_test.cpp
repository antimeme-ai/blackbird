#include "blackbird/sqlite_workbench.hpp"

#include <chrono>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace blackbird;
using namespace blackbird::sqlite;

namespace {

const char *g_stage = "startup";

void require(bool condition, std::string_view message,
             std::source_location loc = std::source_location::current()) {
  if (!condition) {
    throw std::runtime_error(std::string{loc.file_name()} + ":" +
                             std::to_string(loc.line()) + " [" + std::string{g_stage} +
                             "]: " + std::string{message});
  }
}

template <typename T>
T must(Result<T> result, std::string_view context,
       std::source_location loc = std::source_location::current()) {
  if (!result.has_value()) {
    throw std::runtime_error(
        std::string{loc.file_name()} + ":" + std::to_string(loc.line()) + " [" +
        std::string{g_stage} + " / " + std::string{context} +
        "]: " + error_name(result.error().code) + " (" +
        std::string{sqlite_error_name(sqlite_error_of(result.error()))} + ")");
  }
  return std::move(result).value();
}

void must_void(const Result<void> &result, std::string_view context,
               std::source_location loc = std::source_location::current()) {
  if (!result.has_value()) {
    throw std::runtime_error(
        std::string{loc.file_name()} + ":" + std::to_string(loc.line()) + " [" +
        std::string{g_stage} + " / " + std::string{context} +
        "]: " + error_name(result.error().code) + " (" +
        std::string{sqlite_error_name(sqlite_error_of(result.error()))} + ")");
  }
}

template <typename T>
void expect_sqlite_err(const Result<T> &result, SqliteError expected,
                       std::string_view context,
                       std::source_location loc = std::source_location::current()) {
  if (result.has_value()) {
    throw std::runtime_error(
        std::string{loc.file_name()} + ":" + std::to_string(loc.line()) + " [" +
        std::string{g_stage} + " / " + std::string{context} + "]: expected error " +
        std::string{sqlite_error_name(expected)} + ", got success");
  }
  const SqliteError actual = sqlite_error_of(result.error());
  if (actual != expected) {
    throw std::runtime_error(std::string{loc.file_name()} + ":" +
                             std::to_string(loc.line()) + " [" + std::string{g_stage} +
                             " / " + std::string{context} + "]: expected error " +
                             std::string{sqlite_error_name(expected)} + ", got " +
                             std::string{sqlite_error_name(actual)});
  }
}

struct TempDir {
  std::filesystem::path path;

  explicit TempDir(std::string_view tag) {
    const auto base = std::filesystem::temp_directory_path();
    path = base / ("blackbird_sqlite_wb_test_" + std::string{tag} + "_" +
                   std::to_string(static_cast<std::uint64_t>(::getpid())));
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    std::filesystem::create_directories(path);
  }

  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;

  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

std::size_t count_open_fds() {
#if defined(__APPLE__)
  const char *fd_dir_path = "/dev/fd";
#else
  const char *fd_dir_path = "/proc/self/fd";
#endif
  DIR *dir = ::opendir(fd_dir_path);
  if (dir != nullptr) {
    std::size_t count = 0U;
    while (const dirent *ent = ::readdir(dir)) {
      const std::string_view name{ent->d_name};
      if (name != "." && name != "..") {
        ++count;
      }
    }
    (void)::closedir(dir);
    return count;
  }
  std::size_t count = 0U;
  for (int fd = 0; fd < 1024; ++fd) {
    if (::fcntl(fd, F_GETFD) != -1) {
      ++count;
    }
  }
  return count;
}

std::int64_t row_int(const Value &row, std::string_view key,
                     std::source_location loc = std::source_location::current()) {
  const Value *val = row.find(key);
  require(val != nullptr, "missing integer column", loc);
  require(std::holds_alternative<Number>(val->value()), "column is not Number", loc);
  const auto &nst = val->number().storage();
  if (std::holds_alternative<std::int64_t>(nst)) {
    return std::get<std::int64_t>(nst);
  }
  require(std::holds_alternative<std::uint64_t>(nst), "column is not integer", loc);
  return static_cast<std::int64_t>(std::get<std::uint64_t>(nst));
}

std::string row_str(const Value &row, std::string_view key,
                    std::source_location loc = std::source_location::current()) {
  const Value *val = row.find(key);
  require(val != nullptr, "missing string column", loc);
  require(std::holds_alternative<std::string>(val->value()), "column is not string",
          loc);
  return val->string();
}

// ---------------------------------------------------------------------------
// 1. Capability Probe
// ---------------------------------------------------------------------------

void test_capability_probe() {
  g_stage = "capability_probe";
  const auto caps = must(probe_sqlite_capabilities(), "probe system sqlite3");
  require(caps.available, "sqlite3 should be available");
  require(!caps.binary_path.empty(), "binary_path populated");
  require(!caps.version.empty(), "version populated");
  require(caps.supports_safe_flag, "system sqlite3 must support -safe");
  require(caps.supports_fts5, "system sqlite3 must support FTS5");
  require(caps.supports_json1, "system sqlite3 must support JSON1");

  expect_sqlite_err(probe_sqlite_capabilities(
                        std::filesystem::path{"/nonexistent/blackbird/sqlite3"}),
                    SqliteError::binary_not_found,
                    "missing binary override fails closed");
}

// ---------------------------------------------------------------------------
// 2. DB Name & Identifier Validation
// ---------------------------------------------------------------------------

void test_name_validation() {
  g_stage = "name_validation";
  require(valid_db_name("scratch_1"), "valid alphanumeric+underscore");
  require(valid_db_name("trace-analysis-2026"), "valid hyphenated");
  require(valid_db_name(std::string(64U, 'a')), "max length 64 allowed");
  require(!valid_db_name(""), "empty rejected");
  require(!valid_db_name(std::string(65U, 'a')), "length 65 rejected");
  require(!valid_db_name("../escape"), "dotdot slash rejected");
  require(!valid_db_name("a/b"), "slash rejected");
  require(!valid_db_name("a.b"), "dot rejected");
  require(!valid_db_name("a b"), "space rejected");

  require(valid_sql_identifier("events_1"), "valid table identifier");
  require(!valid_sql_identifier("sqlite_master"), "sqlite_ prefix rejected");
  require(!valid_sql_identifier("SQLITE_SEQUENCE"),
          "case-insensitive sqlite_ rejected");
  require(!valid_sql_identifier("_blackbird_taint_registry"),
          "internal table rejected");
  require(!valid_sql_identifier("1bad"), "leading digit rejected");
  require(!valid_sql_identifier("bad;drop"), "semicolon rejected");
}

// ---------------------------------------------------------------------------
// 3. Scratch DB Lifecycle (Create / Exec / Query / Close / RAII Cleanup)
// ---------------------------------------------------------------------------

void test_scratch_lifecycle_and_raii() {
  g_stage = "scratch_lifecycle";
  TempDir tmp{"scratch"};

  std::filesystem::path session_dir_path;
  std::filesystem::path db_a_path;
  std::filesystem::path db_b_path;

  {
    SqliteWorkbenchConfig cfg{};
    cfg.scratch_parent_dir = tmp.path;
    SqliteWorkbench wb{cfg};

    const auto db_a = must(wb.open_scratch("alpha_1"), "open scratch alpha_1");
    const auto db_b = must(wb.open_scratch("beta-2"), "open scratch beta-2");
    require(db_a.scope == SqliteDbScope::scratch, "scope is scratch");
    require(std::filesystem::exists(db_a.path), "alpha_1 file exists on disk");
    require(std::filesystem::exists(db_b.path), "beta-2 file exists on disk");
    db_a_path = db_a.path;
    db_b_path = db_b.path;

    const auto sdir = wb.scratch_session_dir();
    if (!sdir.has_value()) {
      require(false, "session scratch dir set");
      return;
    }
    session_dir_path = *sdir;

    struct stat dir_st{};
    require(::lstat(session_dir_path.c_str(), &dir_st) == 0, "lstat session dir");
    require(S_ISDIR(dir_st.st_mode), "session dir is directory");
    require((dir_st.st_mode & mode_t{0777}) == mode_t{0700}, "session dir is 0700");

    struct stat file_st{};
    require(::lstat(db_a_path.c_str(), &file_st) == 0, "lstat scratch db");
    require((file_st.st_mode & mode_t{0777}) == mode_t{0600}, "scratch db is 0600");

    (void)must(wb.exec(db_a, "CREATE TABLE items(id INTEGER PRIMARY KEY, label TEXT);"
                             "INSERT INTO items VALUES (1, 'one'), (2, 'two');"),
               "create and populate scratch table");
    const auto q =
        must(wb.query(db_a, "SELECT id, label FROM items ORDER BY id;"), "query items");
    require(q.rows.size() == 2U, "two rows returned");
    require(row_int(q.rows[0], "id") == 1, "first row id == 1");
    require(row_str(q.rows[1], "label") == "two", "second row label == two");

    // Explicit close_scratch removes file from disk immediately.
    must_void(wb.close_scratch("alpha_1"), "close_scratch alpha_1");
    require(!std::filesystem::exists(db_a_path), "alpha_1 removed on close_scratch");
    require(std::filesystem::exists(db_b_path), "beta-2 still alive");

    // Invalid names rejected.
    expect_sqlite_err(wb.open_scratch("../evil"), SqliteError::invalid_db_name,
                      "reject path traversal db name");
  }

  // RAII destructor removes remaining scratch DBs and session directory from disk!
  require(!std::filesystem::exists(db_b_path), "beta-2 auto-destroyed by destructor");
  require(!std::filesystem::exists(session_dir_path),
          "session scratch dir auto-removed by destructor");
}

// ---------------------------------------------------------------------------
// 4. Permanent model_db Persistence, 0700/0600 Permissions & Symlink Rejection
// ---------------------------------------------------------------------------

void test_model_db_persistence_and_security() {
  g_stage = "model_db_security";
  TempDir tmp{"model"};
  const auto project_dir = tmp.path / "project_repo";
  const auto state_dir = tmp.path / "state" / "model_memory";
  const auto journal_dir = tmp.path / "authoritative_journal";
  std::filesystem::create_directories(project_dir);
  std::filesystem::create_directories(journal_dir);

  std::filesystem::path model_path;

  // Session 1: create model_db, write row, verify 0700 dir / 0600 file / WAL mode.
  {
    SqliteWorkbenchConfig cfg{};
    cfg.scratch_parent_dir = tmp.path / "scratch";
    std::filesystem::create_directories(*cfg.scratch_parent_dir);
    cfg.model_state_dir = state_dir;
    cfg.project_root = project_dir;
    cfg.forbidden_journal_dirs = {journal_dir};

    SqliteWorkbench wb{cfg};
    const auto mdb = must(wb.open_model_db(), "open model_db session 1");
    require(mdb.scope == SqliteDbScope::model_private, "scope is model_private");
    model_path = mdb.path;

    struct stat dir_st{};
    require(::lstat(state_dir.c_str(), &dir_st) == 0, "lstat state_dir");
    require((dir_st.st_mode & mode_t{0777}) == mode_t{0700}, "state_dir is 0700");

    struct stat db_st{};
    require(::lstat(model_path.c_str(), &db_st) == 0, "lstat model_db");
    require((db_st.st_mode & mode_t{0777}) == mode_t{0600}, "model_db is 0600");

    const auto jm = must(wb.query(mdb, "PRAGMA journal_mode;"), "check WAL mode");
    require(jm.rows.size() == 1U, "journal_mode row");
    require(row_str(jm.rows[0], "journal_mode") == "wal", "model_db uses WAL mode");

    (void)must(wb.exec(mdb, "CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT);"
                            "INSERT INTO notes VALUES (1, 'remember invariant 42');"),
               "insert persistent note");
  }

  // Session 2: reopen model_db and verify persistence across workbench instances.
  {
    SqliteWorkbenchConfig cfg{};
    cfg.model_state_dir = state_dir;
    cfg.project_root = project_dir;
    cfg.forbidden_journal_dirs = {journal_dir};

    SqliteWorkbench wb{cfg};
    const auto mdb = must(wb.open_model_db(), "reopen model_db session 2");
    require(mdb.path == model_path, "deterministic project hash path");
    const auto q = must(wb.query(mdb, "SELECT body FROM notes WHERE id = 1;"),
                        "read persisted note");
    require(q.rows.size() == 1U, "persisted row present");
    require(row_str(q.rows[0], "body") == "remember invariant 42",
            "persisted content intact");
  }

  // Reject overlap with authoritative Journal/Originals store or project repo.
  {
    SqliteWorkbenchConfig bad_cfg{};
    bad_cfg.model_state_dir = journal_dir / "nested";
    bad_cfg.project_root = project_dir;
    bad_cfg.forbidden_journal_dirs = {journal_dir};
    SqliteWorkbench wb{bad_cfg};
    expect_sqlite_err(wb.open_model_db(), SqliteError::invalid_path,
                      "reject model_db overlapping journal dir");
  }
  {
    SqliteWorkbenchConfig bad_cfg{};
    bad_cfg.model_state_dir = project_dir / ".model_db";
    bad_cfg.project_root = project_dir;
    SqliteWorkbench wb{bad_cfg};
    expect_sqlite_err(wb.open_model_db(), SqliteError::invalid_path,
                      "reject model_db inside project repo");
  }

  // Reject symlinked state directory.
  {
    const auto real_dir = tmp.path / "real_target_dir";
    const auto sym_dir = tmp.path / "symlink_state_dir";
    std::filesystem::create_directories(real_dir);
    require(::chmod(real_dir.c_str(), mode_t{0700}) == 0, "chmod real_target_dir");
    std::filesystem::create_directory_symlink(real_dir, sym_dir);

    SqliteWorkbenchConfig sym_cfg{};
    sym_cfg.model_state_dir = sym_dir;
    sym_cfg.project_root = project_dir;
    SqliteWorkbench wb{sym_cfg};
    expect_sqlite_err(wb.open_model_db(), SqliteError::symlink_rejected,
                      "reject symlinked model_state_dir");
  }

  // Reject symlinked DB file inside valid 0700 state directory.
  {
    const auto sym_state = tmp.path / "state_with_sym_db";
    std::filesystem::create_directories(sym_state);
    require(::chmod(sym_state.c_str(), mode_t{0700}) == 0, "chmod sym_state");
    const auto decoy = tmp.path / "decoy.db";
    {
      std::ofstream out(decoy, std::ios::binary);
      out << "decoy";
    }
    const std::string hash = compute_project_db_hash(project_dir);
    std::filesystem::create_symlink(decoy, sym_state / (hash + ".db"));

    SqliteWorkbenchConfig sym_cfg{};
    sym_cfg.model_state_dir = sym_state;
    sym_cfg.project_root = project_dir;
    SqliteWorkbench wb{sym_cfg};
    expect_sqlite_err(wb.open_model_db(), SqliteError::symlink_rejected,
                      "reject symlinked model_db file");
  }

  // Reject symlinked -wal sidecar file.
  {
    const auto wal_state = tmp.path / "state_with_sym_wal";
    std::filesystem::create_directories(wal_state);
    require(::chmod(wal_state.c_str(), mode_t{0700}) == 0, "chmod wal_state");
    const auto decoy = tmp.path / "decoy_wal";
    {
      std::ofstream out(decoy, std::ios::binary);
      out << "decoy";
    }
    const std::string hash = compute_project_db_hash(project_dir);
    std::filesystem::create_symlink(decoy, wal_state / (hash + ".db-wal"));

    SqliteWorkbenchConfig wal_cfg{};
    wal_cfg.model_state_dir = wal_state;
    wal_cfg.project_root = project_dir;
    SqliteWorkbench wb{wal_cfg};
    expect_sqlite_err(wb.open_model_db(), SqliteError::symlink_rejected,
                      "reject symlinked -wal sidecar");
  }

  // Reject insecure permissions (0755 dir and 0644 db file).
  {
    const auto loose_dir = tmp.path / "loose_dir";
    std::filesystem::create_directories(loose_dir);
    require(::chmod(loose_dir.c_str(), mode_t{0755}) == 0, "chmod loose_dir 0755");
    SqliteWorkbenchConfig loose_cfg{};
    loose_cfg.model_state_dir = loose_dir;
    loose_cfg.project_root = project_dir;
    SqliteWorkbench wb{loose_cfg};
    expect_sqlite_err(wb.open_model_db(), SqliteError::insecure_permissions,
                      "reject 0755 model_state_dir");
  }
  {
    require(::chmod(model_path.c_str(), mode_t{0644}) == 0, "chmod model_db 0644");
    SqliteWorkbenchConfig loose_cfg{};
    loose_cfg.model_state_dir = state_dir;
    loose_cfg.project_root = project_dir;
    SqliteWorkbench wb{loose_cfg};
    expect_sqlite_err(wb.open_model_db(), SqliteError::insecure_permissions,
                      "reject 0644 model_db file");
    require(::chmod(model_path.c_str(), mode_t{0600}) == 0, "restore model_db 0600");
  }
}

// ---------------------------------------------------------------------------
// 5. FTS5 Full-Text Search & JSON1 Extraction
// ---------------------------------------------------------------------------

void test_fts5_and_json1() {
  g_stage = "fts5_and_json1";
  TempDir tmp{"fts5"};
  SqliteWorkbenchConfig cfg{};
  cfg.scratch_parent_dir = tmp.path;
  SqliteWorkbench wb{cfg};

  const auto db = must(wb.open_scratch("search_wb"), "open scratch search_wb");

  (void)must(
      wb.exec(
          db,
          "CREATE VIRTUAL TABLE docs_fts USING fts5(title, body);"
          "INSERT INTO docs_fts VALUES ('WalEngine', 'Crash safe write ahead log');"
          "INSERT INTO docs_fts VALUES ('Parser', 'Recursive descent JSON lexer');"
          "INSERT INTO docs_fts VALUES ('Sandbox', 'Seatbelt and Landlock policy');"),
      "create FTS5 table");

  const auto fts_q =
      must(wb.query(db, "SELECT title, bm25(docs_fts) AS rank FROM docs_fts "
                        "WHERE docs_fts MATCH 'write AND log' ORDER BY rank;"),
           "FTS5 MATCH query");
  require(fts_q.rows.size() == 1U, "exactly 1 FTS5 hit");
  require(row_str(fts_q.rows[0], "title") == "WalEngine", "FTS5 matched WalEngine");

  const auto j1 =
      must(wb.query(db, "SELECT json_extract('{\"meta\":{\"retries\":3,\"ok\":true}}', "
                        "'$.meta.retries') AS retries, "
                        "json_type('{\"a\":[1,2]}', '$.a') AS kind;"),
           "JSON1 extraction");
  require(j1.rows.size() == 1U, "1 JSON1 row");
  require(row_int(j1.rows[0], "retries") == 3, "json_extract retries == 3");
  require(row_str(j1.rows[0], "kind") == "array", "json_type == array");
}

// ---------------------------------------------------------------------------
// 6. Bulk Ingest: JSONL, CSV, Lines, Records (Quotes, NUL, Control, Newlines)
// ---------------------------------------------------------------------------

void test_bulk_ingestors() {
  g_stage = "bulk_ingestors";
  TempDir tmp{"ingest"};
  SqliteWorkbenchConfig cfg{};
  cfg.scratch_parent_dir = tmp.path;
  SqliteWorkbench wb{cfg};
  const auto db = must(wb.open_scratch("ingest_db"), "open scratch ingest_db");

  // 6a. JSONL with quotes, nested JSON, newlines, and control chars
  const std::string jsonl =
      "{\"id\":1,\"msg\":\"O'Brien said \\\"hi\\\"\\nline2\",\"meta\":{\"k\":7}}\n"
      "\n"
      "{\"id\":2,\"msg\":\"ctrl\\u0001\\u001fend\",\"meta\":{\"k\":9}}\n";
  const auto r_jsonl = must(
      wb.ingest_jsonl(db, "events_jsonl", jsonl, /*tainted=*/false), "ingest_jsonl");
  require(r_jsonl.rows_ingested == 2U, "jsonl ingested 2 rows");
  require(!r_jsonl.tainted, "jsonl untainted");

  const auto q_jsonl = must(
      wb.query(db, "SELECT id, msg, json_extract(meta, '$.k') AS k FROM events_jsonl "
                   "ORDER BY id;"),
      "query ingested jsonl");
  require(q_jsonl.rows.size() == 2U, "2 jsonl rows");
  require(row_str(q_jsonl.rows[0], "msg") == "O'Brien said \"hi\"\nline2",
          "jsonl preserved quotes and newline");
  require(row_int(q_jsonl.rows[0], "k") == 7, "jsonl nested JSON1 extract == 7");
  require(row_str(q_jsonl.rows[1], "msg") == std::string{"ctrl\x01\x1f"
                                                         "end"},
          "jsonl preserved control chars");

  // 6b. CSV with quoted commas, doubled quotes, embedded CRLF newlines, and NUL byte
  std::string csv = "name,note\r\n"
                    "\"Alice, Jr.\",\"she said \"\"hello\"\"\nsecond line\"\r\n"
                    "\"Bob\",\"a";
  csv.push_back('\0');
  csv += "b\x02\"\r\n";

  const auto r_csv =
      must(wb.ingest_csv(db, "people_csv", csv, /*tainted=*/false), "ingest_csv");
  require(r_csv.rows_ingested == 2U, "csv ingested 2 rows");

  const auto q_csv =
      must(wb.query(db, "SELECT name, note, hex(CAST(note AS BLOB)) AS note_hex "
                        "FROM people_csv ORDER BY rowid;"),
           "query ingested csv");
  require(q_csv.rows.size() == 2U, "2 csv rows");
  require(row_str(q_csv.rows[0], "name") == "Alice, Jr.", "csv comma inside quotes");
  require(row_str(q_csv.rows[0], "note") == "she said \"hello\"\nsecond line",
          "csv doubled quotes and embedded newline");
  // Verify exact NUL + control byte (61 00 62 02) stored intact in SQLite!
  require(row_str(q_csv.rows[1], "note_hex") == "61006202",
          "csv preserved embedded NUL and control bytes verbatim");

  // 6c. Lines ingest with single quotes, NUL byte, and control chars
  std::string lines_text = "first 'quoted' line\nsecond";
  lines_text.push_back('\0');
  lines_text += "nul\x07"
                "bell\nthird line\n";
  const auto r_lines = must(
      wb.ingest_lines(db, "raw_lines", lines_text, /*tainted=*/false), "ingest_lines");
  require(r_lines.rows_ingested == 3U, "lines ingested 3 rows");

  const auto q_lines =
      must(wb.query(db, "SELECT line_no, text, hex(CAST(text AS BLOB)) AS h "
                        "FROM raw_lines ORDER BY line_no;"),
           "query ingested lines");
  require(q_lines.rows.size() == 3U, "3 line rows");
  require(row_str(q_lines.rows[0], "text") == "first 'quoted' line",
          "lines preserved single quotes");
  // "second\0nul\x07bell" -> 7365636F6E64 00 6E756C 07 62656C6C
  require(row_str(q_lines.rows[1], "h") == "7365636F6E64006E756C0762656C6C",
          "lines preserved NUL and BEL verbatim");
  require(row_str(q_lines.rows[2], "text") == "third line", "third line intact");

  // 6d. Structured Value::Array records ingest
  Value::Array records;
  records.push_back(Value::object({
      {"id", Value{Number{std::int64_t{10}}}},
      {"active", Value{true}},
      {"tag", Value{std::string{"O'Neil\n\"alpha\""}}},
      {"extra", Value::object({{"nested", Value{Number{std::int64_t{99}}}}})},
  }));
  records.push_back(Value::object({
      {"id", Value{Number{std::int64_t{20}}}},
      {"active", Value{false}},
      {"tag", Value{std::string{"beta"}}},
  }));
  const auto r_rec =
      must(wb.ingest_records(db, "struct_records", records, /*tainted=*/false),
           "ingest_records");
  require(r_rec.rows_ingested == 2U, "records ingested 2 rows");

  const auto q_rec = must(
      wb.query(db, "SELECT id, active, tag, json_extract(extra, '$.nested') AS nested "
                   "FROM struct_records ORDER BY id;"),
      "query ingested records");
  require(q_rec.rows.size() == 2U, "2 record rows");
  require(row_int(q_rec.rows[0], "id") == 10, "record 0 id == 10");
  require(row_int(q_rec.rows[0], "active") == 1, "record 0 active == 1");
  require(row_str(q_rec.rows[0], "tag") == "O'Neil\n\"alpha\"",
          "record 0 tag preserved");
  require(row_int(q_rec.rows[0], "nested") == 99, "record 0 nested JSON == 99");
  require(std::holds_alternative<std::nullptr_t>(q_rec.rows[1].find("nested")->value()),
          "record 1 missing key became NULL");

  // Malformed JSONL & SQL-injection table name rejected cleanly.
  expect_sqlite_err(wb.ingest_jsonl(db, "bad_jsonl", "{not valid json}\n"),
                    SqliteError::ingest_parse_failed, "reject malformed JSONL");
  expect_sqlite_err(wb.ingest_lines(db, "t; DROP TABLE raw_lines; --", "x\n"),
                    SqliteError::invalid_table_name, "reject SQLi table name");
}

// ---------------------------------------------------------------------------
// 7. Security Guardrails: Dot-commands, Obfuscated ATTACH/DETACH/load_extension,
//    and Non-False-Positive String Literals
// ---------------------------------------------------------------------------

void test_sql_guardrails() {
  g_stage = "sql_guardrails";
  TempDir tmp{"guard"};
  SqliteWorkbenchConfig cfg{};
  cfg.scratch_parent_dir = tmp.path;
  SqliteWorkbench wb{cfg};
  const auto db = must(wb.open_scratch("guard_db"), "open guard_db");

  // Dot-commands refused (at start, indented, or after newline/semicolon)
  const std::vector<std::string> dot_attacks = {
      ".shell echo pwned",
      "  .system whoami",
      "SELECT 1;\n.import /etc/passwd tbl",
      "SELECT 1;\n  .output /tmp/pwn",
      ".load /tmp/evil.so",
      ".read /etc/passwd",
      ".open /tmp/other.db",
      ".backup /tmp/dump.db",
      ".restore /tmp/dump.db",
      "/* comment */\n.shell id",
  };
  for (const std::string &attack : dot_attacks) {
    expect_sqlite_err(wb.exec(db, attack), SqliteError::dot_command_rejected,
                      "reject dot-command: " + attack);
  }

  // Obfuscated ATTACH / DETACH / load_extension / VACUUM INTO / dangerous PRAGMA
  const std::vector<std::string> sql_attacks = {
      "ATTACH DATABASE '/tmp/x.db' AS ext;",
      "/*obfuscated*/ATTACH/*x*/DATABASE ':memory:' AS ext;",
      "-- comment\n  aTtAcH DATABASE ':memory:' AS ext;",
      "DETACH /*x*/ DATABASE main;",
      "SELECT /*comment*/ load_extension('/tmp/evil.so');",
      "SELECT \"load_extension\"('/tmp/evil.so');",
      "SELECT [load_extension]('/tmp/evil.so');",
      "SELECT `load_extension`('/tmp/evil.so');",
      "VACUUM INTO '/tmp/exfil.db';",
      "PRAGMA writable_schema = ON;",
      "PRAGMA 'writable_schema' = ON;",
      "PRAGMA main.'writable_schema' = ON;",
      "PRAGMA 'main'.'writable_schema' = ON;",
      "PRAGMA main.temp_store_directory = '/tmp';",
      "PRAGMA 'temp_store_directory' = '/tmp';",
  };
  for (const std::string &attack : sql_attacks) {
    expect_sqlite_err(wb.exec(db, attack), SqliteError::forbidden_sql_rejected,
                      "reject forbidden SQL: " + attack);
  }

  // Non-false-positive: string literals & comments containing ATTACH / DETACH /
  // load_extension / .shell MUST succeed!
  const auto ok_str = must(
      wb.query(db, "SELECT 'ATTACH DATABASE ''/etc/passwd'' AS x' AS s1, "
                   "'DETACH load_extension' AS s2, "
                   "'line1\n.shell echo safe' AS s3; -- ATTACH in comment is harmless"),
      "string literals containing ATTACH/load_extension/.shell must not "
      "false-positive");
  require(ok_str.rows.size() == 1U, "1 row returned");
  require(row_str(ok_str.rows[0], "s1") == "ATTACH DATABASE '/etc/passwd' AS x",
          "ATTACH string literal intact");
  require(row_str(ok_str.rows[0], "s2") == "DETACH load_extension",
          "DETACH/load_extension string literal intact");
  require(row_str(ok_str.rows[0], "s3") == "line1\n.shell echo safe",
          "multiline literal with .shell intact");
}

// ---------------------------------------------------------------------------
// 8. Brakes Taint Tracking & Transitive Propagation + Persistence
// ---------------------------------------------------------------------------

void test_taint_propagation() {
  g_stage = "taint_propagation";
  TempDir tmp{"taint"};
  const auto project_dir = tmp.path / "proj";
  const auto state_dir = tmp.path / "model_state";
  std::filesystem::create_directories(project_dir);

  brakes::TurnTaintState turn_taint{};
  require(!turn_taint.is_tainted(), "turn_taint starts clean");

  {
    SqliteWorkbenchConfig cfg{};
    cfg.scratch_parent_dir = tmp.path / "scratch";
    std::filesystem::create_directories(*cfg.scratch_parent_dir);
    cfg.model_state_dir = state_dir;
    cfg.project_root = project_dir;
    cfg.turn_taint = &turn_taint;

    SqliteWorkbench wb{cfg};
    const auto sdb = must(wb.open_scratch("taint_scratch"), "open taint_scratch");

    // Ingest one clean table and one tainted table.
    (void)must(wb.ingest_lines(sdb, "clean_tbl", "hello clean\n", /*tainted=*/false),
               "ingest clean_tbl");
    (void)must(wb.ingest_lines(sdb, "peer_tbl", "untrusted peer note\n",
                               /*tainted=*/true),
               "ingest peer_tbl");

    require(!wb.is_table_tainted(sdb, "clean_tbl"), "clean_tbl is untainted");
    require(wb.is_table_tainted(sdb, "peer_tbl"), "peer_tbl is tainted");

    // Reading clean_tbl stays untainted and does not latch TurnTaintState.
    const auto q_clean =
        must(wb.query(sdb, "SELECT text FROM clean_tbl;"), "query clean_tbl");
    require(!q_clean.contains_tainted_data, "clean_tbl query untainted");
    require(!turn_taint.is_tainted(), "TurnTaintState still clean");

    // Transitive write propagation: copying from peer_tbl into laundered_tbl taints
    // laundered_tbl!
    (void)must(wb.exec(sdb, "CREATE TABLE laundered_tbl AS SELECT * FROM peer_tbl;"),
               "copy tainted table");
    require(wb.is_table_tainted(sdb, "laundered_tbl"),
            "transitive taint marked laundered_tbl");

    // Reset turn_taint to verify querying laundered_tbl latches it again!
    turn_taint.reset_by_operator();
    require(!turn_taint.is_tainted(), "turn_taint reset by operator");

    const auto q_tainted =
        must(wb.query(sdb, "SELECT text FROM laundered_tbl;"), "query laundered_tbl");
    require(q_tainted.contains_tainted_data,
            "querying laundered_tbl reports contains_tainted_data");
    require(turn_taint.is_tainted(),
            "reading tainted table latched brakes::TurnTaintState");

    // Single-quoted table identifier & comma-join must NOT bypass taint tracking!
    turn_taint.reset_by_operator();
    const auto q_sq = must(wb.query(sdb, "SELECT text FROM 'peer_tbl';"),
                           "single-quoted tainted table query");
    require(q_sq.rows.size() == 1U, "single-quoted tainted query returned row");
    require(q_sq.contains_tainted_data,
            "single-quoted FROM 'peer_tbl' reports contains_tainted_data");
    require(turn_taint.is_tainted(),
            "single-quoted FROM 'peer_tbl' latched TurnTaintState");

    turn_taint.reset_by_operator();
    const auto q_join =
        must(wb.query(sdb, "SELECT c.text, p.text AS ptext FROM clean_tbl c, "
                           "'peer_tbl' p;"),
             "comma-join with single-quoted tainted table");
    require(q_join.contains_tainted_data,
            "comma-join with 'peer_tbl' reports contains_tainted_data");
    require(turn_taint.is_tainted(),
            "comma-join with 'peer_tbl' latched TurnTaintState");

    // ALTER TABLE ... RENAME TO ... must NOT launder table taint!
    turn_taint.reset_by_operator();
    (void)must(wb.exec(sdb, "ALTER TABLE peer_tbl RENAME TO clean_renamed;"),
               "rename tainted scratch table");
    require(wb.is_table_tainted(sdb, "clean_renamed"),
            "ALTER TABLE RENAME TO propagated taint to clean_renamed");
    const auto q_ren = must(wb.query(sdb, "SELECT text FROM clean_renamed;"),
                            "query renamed tainted table");
    require(q_ren.contains_tainted_data,
            "querying clean_renamed reports contains_tainted_data");
    require(turn_taint.is_tainted(), "querying clean_renamed latched TurnTaintState");

    // Permanent model_db taint persists across reopen (including RENAME TO) and
    // cannot be dropped or deleted via unquoted or single-quoted SQL.
    turn_taint.reset_by_operator();
    const auto mdb = must(wb.open_model_db(), "open model_db for taint");
    (void)must(wb.ingest_lines(mdb, "peer_archive", "peer msg\n", /*tainted=*/true),
               "ingest tainted into model_db");
    expect_sqlite_err(wb.exec(mdb, "DROP TABLE _blackbird_taint_registry;"),
                      SqliteError::forbidden_sql_rejected,
                      "user SQL cannot drop taint registry");
    expect_sqlite_err(wb.exec(mdb, "DROP TABLE '_blackbird_taint_registry';"),
                      SqliteError::forbidden_sql_rejected,
                      "single-quoted SQL cannot drop taint registry");
    expect_sqlite_err(wb.exec(mdb, "DELETE FROM '_blackbird_taint_registry';"),
                      SqliteError::forbidden_sql_rejected,
                      "single-quoted SQL cannot delete taint registry");
    (void)must(wb.exec(mdb, "ALTER TABLE 'peer_archive' RENAME TO 'renamed_archive';"),
               "rename tainted model_db table");
    require(wb.is_table_tainted(mdb, "renamed_archive"),
            "model_db RENAME TO propagated taint to renamed_archive");
  }

  // Reopen model_db in a fresh SqliteWorkbench and verify renamed taint survived!
  {
    brakes::TurnTaintState fresh_taint{};
    SqliteWorkbenchConfig cfg{};
    cfg.model_state_dir = state_dir;
    cfg.project_root = project_dir;
    cfg.turn_taint = &fresh_taint;

    SqliteWorkbench wb{cfg};
    const auto mdb = must(wb.open_model_db(), "reopen model_db taint check");
    require(wb.is_table_tainted(mdb, "renamed_archive"),
            "persisted renamed table taint loaded on reopen");
    const auto q = must(wb.query(mdb, "SELECT text FROM renamed_archive;"),
                        "query persisted renamed tainted table");
    require(q.contains_tainted_data, "reopened query reports contains_tainted_data");
    require(fresh_taint.is_tainted(), "reopened query latches fresh TurnTaintState");
  }
}

// ---------------------------------------------------------------------------
// 9. Query Timeout Process-Group Kill & Row/Byte Caps
// ---------------------------------------------------------------------------

void test_timeout_and_caps() {
  g_stage = "timeout_and_caps";
  TempDir tmp{"caps"};
  SqliteWorkbenchConfig cfg{};
  cfg.scratch_parent_dir = tmp.path;
  SqliteWorkbench wb{cfg};
  const auto db = must(wb.open_scratch("caps_db"), "open caps_db");

  // Populate 50 rows with substantial text for row-cap and byte-cap tests.
  (void)must(
      wb.exec(db, "CREATE TABLE big AS "
                  "WITH RECURSIVE cnt(x) AS ("
                  "  SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < 50"
                  ") "
                  "SELECT x AS id, "
                  "printf('row-%03d-%s', x, hex(zeroblob(40))) AS payload FROM cnt;"),
      "create 50-row table");

  // Row cap test
  {
    SqliteExecLimits lim{};
    lim.max_rows = 5U;
    lim.max_output_bytes = 64U * 1024U;
    const auto q = must(wb.query(db, "SELECT id, payload FROM big ORDER BY id;", lim),
                        "query with max_rows=5");
    require(q.rows.size() == 5U, "capped to 5 rows");
    require(q.total_rows_seen == 50U, "saw all 50 rows before row cap");
    require(q.truncated_rows, "truncated_rows flag set");
    require(!q.truncated_bytes, "not byte-truncated");
  }

  // Output byte cap test
  {
    SqliteExecLimits lim{};
    lim.max_rows = 200U;
    lim.max_output_bytes = 300U;
    const auto q = must(wb.query(db, "SELECT id, payload FROM big ORDER BY id;", lim),
                        "query with max_output_bytes=300");
    require(q.truncated_bytes, "truncated_bytes flag set");
    require(q.output_bytes <= 300U, "output_bytes bounded by max_output_bytes");
    require(q.rows.size() >= 1U && q.rows.size() < 50U,
            "partial complete rows parsed from bounded prefix");
  }

  // Query timeout kill test (10-billion-pair cross join killed within ~150ms)
  {
    SqliteExecLimits lim{};
    lim.timeout_ms = 150U;
    const auto t0 = std::chrono::steady_clock::now();
    const auto slow =
        wb.query(db,
                 "WITH RECURSIVE r(x) AS ("
                 "  SELECT 1 UNION ALL SELECT x + 1 FROM r WHERE x < 100000"
                 ") SELECT count(*) AS c FROM r a, r b;",
                 lim);
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();
    expect_sqlite_err(slow, SqliteError::timeout, "slow recursive CTE timed out");
    require(elapsed_ms < 4000, "timeout killed subprocess promptly");
  }
}

// ---------------------------------------------------------------------------
// 10. Zero Leaked File Descriptors
// ---------------------------------------------------------------------------

void test_zero_leaked_fds() {
  g_stage = "zero_leaked_fds";
  TempDir tmp{"fds"};
  const auto project_dir = tmp.path / "proj";
  const auto state_dir = tmp.path / "state";
  std::filesystem::create_directories(project_dir);

  const std::size_t baseline_fds = count_open_fds();

  {
    SqliteWorkbenchConfig cfg{};
    cfg.scratch_parent_dir = tmp.path;
    cfg.model_state_dir = state_dir;
    cfg.project_root = project_dir;
    SqliteWorkbench wb{cfg};

    const auto sdb = must(wb.open_scratch("fd_test"), "open scratch fd_test");
    (void)must(wb.ingest_lines(sdb, "t", "a\nb\nc\n"), "ingest lines");
    (void)must(wb.query(sdb, "SELECT * FROM t;"), "query scratch");
    expect_sqlite_err(wb.query(sdb, "SELECT * FROM nonexistent;"),
                      SqliteError::sql_execution_failed, "failing query");

    SqliteExecLimits short_lim{};
    short_lim.timeout_ms = 100U;
    expect_sqlite_err(
        wb.query(sdb,
                 "WITH RECURSIVE r(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM r WHERE "
                 "x < 100000) SELECT count(*) FROM r a, r b;",
                 short_lim),
        SqliteError::timeout, "timed-out query");

    const auto mdb = must(wb.open_model_db(), "open model_db");
    (void)must(wb.exec(mdb, "CREATE TABLE IF NOT EXISTS k(v INT);"), "exec model_db");
    must_void(wb.close_scratch("fd_test"), "close scratch");
  }

  const std::size_t after_fds = count_open_fds();
  require(after_fds == baseline_fds,
          "FD count must return to baseline (before=" + std::to_string(baseline_fds) +
              ", after=" + std::to_string(after_fds) + ")");
}

} // namespace

int main() {
  try {
    test_capability_probe();
    test_name_validation();
    test_scratch_lifecycle_and_raii();
    test_model_db_persistence_and_security();
    test_fts5_and_json1();
    test_bulk_ingestors();
    test_sql_guardrails();
    test_taint_propagation();
    test_timeout_and_caps();
    test_zero_leaked_fds();
    std::cout << "sqlite_workbench_test: ALL 10 TEST SUITES PASSED\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "FAIL: " << ex.what() << '\n';
    return 1;
  }
}
