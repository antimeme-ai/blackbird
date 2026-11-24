#include "blackbird/sqlite_embedded.hpp"

#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace {

using namespace blackbird;
using namespace blackbird::sqlite;
namespace fs = std::filesystem;

void require(bool cond, std::string_view msg,
             std::source_location loc = std::source_location::current()) {
  if (!cond) {
    throw std::runtime_error(std::string{loc.file_name()} + ":" +
                             std::to_string(loc.line()) + ": " + std::string{msg});
  }
}

struct TempDir {
  fs::path root;
  TempDir() {
    std::string tmpl =
        (fs::temp_directory_path() / "bb-sqlite-embedded-test-XXXXXX").string();
    char *created = ::mkdtemp(tmpl.data());
    require(created != nullptr, "mkdtemp failed");
    root = fs::canonical(created);
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(root, ec);
  }
};

void test_probe_and_fast_in_process_queries() {
  const auto caps = probe_embedded_sqlite_capabilities();
  require(caps.available, "embedded sqlite3 must be available");
  require(caps.version.starts_with("3.54"), "expected vendored SQLite 3.54.x");
  require(caps.supports_fts5, "FTS5 must be compiled in");
  require(caps.supports_json1, "JSON1 must be compiled in");
  require(caps.supports_safe_flag && caps.supports_nofollow_flag,
          "authorizer & nofollow flags must be supported");

  TempDir tmp;
  EmbeddedSqliteBackend backend{};
  const fs::path db_path = tmp.root / "fast.db";

  SqliteBackendRequest setup{};
  setup.db_path = db_path;
  setup.sql = "CREATE TABLE kv(k TEXT PRIMARY KEY, v INT);"
              "INSERT INTO kv VALUES('a', 1),('b', 2),('c', 3);";
  setup.expect_rows = false;
  require(backend.execute(setup).has_value(), "setup table");

  // Run 100 in-process queries and confirm sub-millisecond average latency!
  const auto t0 = std::chrono::steady_clock::now();
  for (int i = 0; i < 100; ++i) {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.sql = "SELECT SUM(v) AS total FROM kv;";
    req.limits.read_only = true;
    const auto res = backend.execute(req);
    require(res.has_value(), "in-process query succeeded");
    require(res.value().rows.size() == 1U, "expected 1 row");
    const Value *tot = res.value().rows[0].find("total");
    require(tot != nullptr &&
                std::get<std::int64_t>(std::get<Number>(tot->value()).storage()) == 6,
            "SUM(v) must be 6");
  }
  const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - t0)
                              .count();
  require(elapsed_ms < 2000, "100 embedded queries should be fast (got " +
                                 std::to_string(elapsed_ms) + "ms)");
}

void test_authorizer_blocks_attach_pragma_taint_and_readonly() {
  TempDir tmp;
  EmbeddedSqliteBackend backend{};
  const fs::path db_path = tmp.root / "auth.db";
  const fs::path other_db = tmp.root / "other.db";

  // Seed DB + _blackbird_taint_registry via unrestricted test backend first.
  {
    EmbeddedSqliteBackendConfig init_cfg{};
    init_cfg.allow_internal_taint_registry_writes = true;
    EmbeddedSqliteBackend init_backend{init_cfg};
    SqliteBackendRequest init_req{};
    init_req.db_path = db_path;
    init_req.expect_rows = false;
    init_req.sql = "CREATE TABLE notes(id INT, body TEXT);"
                   "INSERT INTO notes VALUES(1, 'hello');"
                   "CREATE TABLE _blackbird_taint_registry(scope TEXT PRIMARY KEY);";
    require(init_backend.execute(init_req).has_value(), "seed auth db");
  }

  // 1. ATTACH DATABASE blocked at SQLite bytecode authorizer level!
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.sql = "ATTACH DATABASE '" + other_db.string() + "' AS ext;";
    const auto res = backend.execute(req);
    require(!res.has_value() &&
                sqlite_error_of(res.error()) == SqliteError::forbidden_sql_rejected,
            "authorizer MUST deny ATTACH DATABASE");
  }

  // 2. Dangerous PRAGMA writable_schema blocked at authorizer level!
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.sql = "PRAGMA writable_schema = ON;";
    const auto res = backend.execute(req);
    require(!res.has_value() &&
                sqlite_error_of(res.error()) == SqliteError::forbidden_sql_rejected,
            "authorizer MUST deny PRAGMA writable_schema");
  }

  // 3. User SQL write to _blackbird_taint_registry blocked at authorizer level!
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.sql = "DELETE FROM _blackbird_taint_registry;";
    const auto res = backend.execute(req);
    require(!res.has_value() &&
                sqlite_error_of(res.error()) == SqliteError::forbidden_sql_rejected,
            "authorizer MUST deny writes to _blackbird_taint_registry");
  }

  // 4. Read-only mode blocks INSERT at authorizer level!
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.limits.read_only = true;
    req.sql = "INSERT INTO notes VALUES(2, 'nope');";
    const auto res = backend.execute(req);
    require(!res.has_value(), "read_only mode MUST block INSERT");
  }

  // 5. VACUUM INTO blocked at authorizer level (uses SQLITE_ATTACH internally)!
  {
    const fs::path exfil_db = tmp.root / "exfil.db";
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.sql = "VACUUM INTO '" + exfil_db.string() + "';";
    const auto res = backend.execute(req);
    require(!res.has_value() && !fs::exists(exfil_db),
            "authorizer MUST block VACUUM INTO");
  }

  // 6. Symlink DB rejected by SQLITE_OPEN_NOFOLLOW!
  {
    const fs::path link_db = tmp.root / "symlink_target.db";
    fs::create_symlink(db_path, link_db);
    SqliteBackendRequest req{};
    req.db_path = link_db;
    req.sql = "SELECT * FROM notes;";
    const auto res = backend.execute(req);
    require(!res.has_value(), "SQLITE_OPEN_NOFOLLOW MUST reject symlink DB");
  }
}

void test_fts5_json1_limits_and_progress_timeout() {
  TempDir tmp;
  EmbeddedSqliteBackend backend{};
  const fs::path db_path = tmp.root / "features.db";

  // FTS5 + JSON1
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.sql = "CREATE VIRTUAL TABLE docs USING fts5(title, body);"
              "INSERT INTO docs VALUES('sr71', 'mach three reconnaissance');"
              "INSERT INTO docs VALUES('sqlite', 'embedded authorizer engine');"
              "SELECT title, json_extract('{\"k\":42}', '$.k') AS jval "
              "FROM docs WHERE docs MATCH 'authorizer';";
    const auto res = backend.execute(req);
    require(res.has_value(), "FTS5 + JSON1 query must succeed");
    require(res.value().rows.size() == 1U, "FTS5 match must return 1 row");
    const Value *t = res.value().rows[0].find("title");
    require(t != nullptr && std::get<std::string>(t->value()) == "sqlite",
            "FTS5 matched wrong row");
    const Value *jv = res.value().rows[0].find("jval");
    require(jv != nullptr &&
                std::get<std::int64_t>(std::get<Number>(jv->value()).storage()) == 42,
            "json_extract must return 42");
  }

  // Row limit truncation
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.limits.max_rows = 5U;
    req.sql = "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt "
              "WHERE x < 50) SELECT x FROM cnt;";
    const auto res = backend.execute(req);
    require(res.has_value(), "bounded recursive CTE must succeed");
    require(res.value().rows.size() == 5U && res.value().truncated_rows,
            "max_rows=5 must truncate cleanly");
  }

  // Progress-handler timeout interrupts infinite recursive CTE cleanly!
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.limits.timeout_ms = 80U;
    req.sql = "WITH RECURSIVE inf(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM inf) "
              "SELECT COUNT(*) FROM inf;";
    const auto res = backend.execute(req);
    require(!res.has_value() && sqlite_error_of(res.error()) == SqliteError::timeout,
            "progress handler MUST interrupt infinite CTE with timeout");
  }
}

void test_zero_copy_virtual_tables() {
  TempDir tmp;
  EmbeddedSqliteBackend backend{};
  const fs::path db_path = tmp.root / "vtab.db";

  auto audit_snap = std::make_shared<SqliteVirtualTableData>();
  audit_snap->table_name = "blackbird_audit";
  audit_snap->columns = {"seq", "op", "status", "meta_json"};
  audit_snap->rows = {
      {std::int64_t{1}, std::string{"read_file"}, std::string{"ok"},
       std::string{R"({"bytes":1200})"}},
      {std::int64_t{2}, std::string{"write_file"}, std::string{"ok"},
       std::string{R"({"bytes":340})"}},
      {std::int64_t{3}, std::string{"exec"}, std::string{"err"},
       std::string{R"({"exit":1})"}},
  };
  require(backend.register_virtual_table(audit_snap).has_value(),
          "register blackbird_audit vtab");

  auto ctx_snap = std::make_shared<SqliteVirtualTableData>();
  ctx_snap->table_name = "blackbird_context";
  ctx_snap->columns = {"entry_id", "kind", "tokens"};
  ctx_snap->rows = {
      {std::int64_t{1}, std::string{"system"}, std::int64_t{500}},
      {std::int64_t{2}, std::string{"tool_result"}, std::int64_t{1500}},
  };
  require(backend.register_virtual_table(ctx_snap).has_value(),
          "register blackbird_context vtab");

  // Query live virtual table with WHERE + JSON1 extraction + JOIN!
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.sql = "SELECT a.op, json_extract(a.meta_json, '$.bytes') AS b, c.kind "
              "FROM blackbird_audit a "
              "JOIN blackbird_context c ON c.entry_id = a.seq "
              "WHERE a.status = 'ok' ORDER BY a.seq;";
    const auto res = backend.execute(req);
    require(res.has_value(), "virtual table JOIN + JSON1 query must succeed");
    require(res.value().rows.size() == 2U, "expected 2 joined rows");
    const Value *op0 = res.value().rows[0].find("op");
    const Value *b0 = res.value().rows[0].find("b");
    require(op0 != nullptr && std::get<std::string>(op0->value()) == "read_file",
            "row 0 op mismatch");
    require(b0 != nullptr &&
                std::get<std::int64_t>(std::get<Number>(b0->value()).storage()) == 1200,
            "row 0 json_extract bytes mismatch");
  }

  // Virtual tables are strictly read-only & cannot be dropped/recreated by user SQL!
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.sql = "DELETE FROM blackbird_audit;";
    const auto res = backend.execute(req);
    require(!res.has_value(), "DELETE on read-only virtual table MUST fail");
  }
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.sql = "DROP TABLE temp.blackbird_audit;";
    const auto res = backend.execute(req);
    require(!res.has_value() &&
                sqlite_error_of(res.error()) == SqliteError::forbidden_sql_rejected,
            "DROP of blackbird_vtab MUST be denied by authorizer");
  }
  {
    SqliteBackendRequest req{};
    req.db_path = db_path;
    req.sql = "CREATE VIRTUAL TABLE temp.evil USING blackbird_vtab('blackbird_audit');";
    const auto res = backend.execute(req);
    require(!res.has_value() &&
                sqlite_error_of(res.error()) == SqliteError::forbidden_sql_rejected,
            "CREATE of blackbird_vtab by user SQL MUST be denied by authorizer");
  }

  require(backend.unregister_virtual_table("blackbird_context"),
          "unregister virtual table");
  require(backend.registered_virtual_tables().size() == 1U,
          "one virtual table remains registered");
}

void test_workbench_with_embedded_backend() {
  TempDir tmp;
  SqliteWorkbenchConfig cfg{};
  cfg.scratch_parent_dir = tmp.root / "scratch";
  cfg.model_state_dir = tmp.root / "model";
  cfg.project_root = tmp.root / "repo";
  fs::create_directories(*cfg.scratch_parent_dir);
  fs::create_directories(*cfg.project_root);

  SqliteWorkbench wb{cfg, std::make_unique<EmbeddedSqliteBackend>()};
  const auto db = wb.open_scratch("stage2");
  require(db.has_value(), "open_scratch with embedded backend");

  const auto ing = wb.ingest_jsonl(
      db.value(), "events",
      "{\"tool\":\"lsp\",\"ms\":12}\n{\"tool\":\"nvim\",\"ms\":8}\n", false);
  require(ing.has_value() && ing.value().rows_ingested == 2U,
          "bulk JSONL ingest over embedded backend");

  const auto q = wb.query(db.value(), "SELECT tool, ms FROM events ORDER BY ms ASC;");
  require(q.has_value() && q.value().rows.size() == 2U,
          "query ingested rows over embedded backend");
  const Value *first_tool = q.value().rows[0].find("tool");
  require(first_tool != nullptr && std::get<std::string>(first_tool->value()) == "nvim",
          "lowest ms row must be nvim");
}

int count_open_fds() {
  int count = 0;
  for (int fd = 0; fd < 256; ++fd) {
    if (::fcntl(fd, F_GETFD) != -1) {
      ++count;
    }
  }
  return count;
}

} // namespace

int main() {
  try {
    const int fds_before = count_open_fds();
    test_probe_and_fast_in_process_queries();
    test_authorizer_blocks_attach_pragma_taint_and_readonly();
    test_fts5_json1_limits_and_progress_timeout();
    test_zero_copy_virtual_tables();
    test_workbench_with_embedded_backend();
    const int fds_after = count_open_fds();
    require(fds_after == fds_before,
            "zero FD leaks across sqlite_embedded_test (before=" +
                std::to_string(fds_before) + ", after=" + std::to_string(fds_after) +
                ")");
    std::cout << "sqlite_embedded_test: ALL 5 TEST SUITES PASSED (0 FD leaks)\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "sqlite_embedded_test FAILED: " << ex.what() << '\n';
    return 1;
  }
}
