#pragma once

#include "blackbird/sqlite_workbench.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace blackbird::sqlite {

// Zero-copy cell value exposed by an in-memory read-only SQLite Virtual Table.
using SqliteVtabCell = std::variant<std::monostate, std::int64_t, double, std::string>;

// Immutable in-memory snapshot mounted as a read-only SQLite Virtual Table
// (e.g., blackbird_audit, blackbird_context, blackbird_memory). Rows are read
// directly by reference during SQLite scans without serializing to disk.
struct SqliteVirtualTableData {
  std::string table_name;
  std::vector<std::string> columns;
  std::vector<std::vector<SqliteVtabCell>> rows;
};

struct EmbeddedSqliteBackendConfig {
  bool enable_authorizer = true;
  bool allow_internal_taint_registry_writes = false;
  int progress_handler_steps = 2000;
};

// Stage 2 in-process SQLite 3.54.1 backend (vendored public-domain amalgamation).
// Provides ~10-50us in-process query execution, bytecode-level sqlite3_set_authorizer
// enforcement, sqlite3_progress_handler deadline interruption, FTS5/JSON1/RTree,
// and zero-copy read-only Virtual Tables over Blackbird's live in-memory state.
class EmbeddedSqliteBackend final : public ISqliteBackend {
public:
  explicit EmbeddedSqliteBackend(EmbeddedSqliteBackendConfig config = {});
  ~EmbeddedSqliteBackend() override;

  EmbeddedSqliteBackend(const EmbeddedSqliteBackend &) = delete;
  EmbeddedSqliteBackend &operator=(const EmbeddedSqliteBackend &) = delete;

  std::string_view backend_name() const noexcept override { return "embedded-sqlite3"; }
  Result<SqliteCapabilities> probe() const override;
  Result<SqliteBackendResponse> execute(const SqliteBackendRequest &request) override;

  // Mounts an immutable in-memory snapshot as a read-only virtual table in `temp`
  // schema (accessible by its table_name in every query executed on this backend).
  Result<void>
  register_virtual_table(std::shared_ptr<const SqliteVirtualTableData> snapshot);
  bool unregister_virtual_table(std::string_view table_name);
  std::vector<std::string> registered_virtual_tables() const;

private:
  EmbeddedSqliteBackendConfig config_{};
  mutable std::mutex vtab_mutex_;
  std::unordered_map<std::string, std::shared_ptr<const SqliteVirtualTableData>> vtabs_;
};

// Returns capabilities of the compiled-in SQLite amalgamation without touching disk.
SqliteCapabilities probe_embedded_sqlite_capabilities();

} // namespace blackbird::sqlite
