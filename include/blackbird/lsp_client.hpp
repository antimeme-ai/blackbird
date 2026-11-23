#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/value.hpp"

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace blackbird {

inline constexpr std::size_t kLspDefaultMaxPayloadBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kLspMaxPayloadBytesLimit = 16U * 1024U * 1024U;
inline constexpr std::size_t kLspMaxHeaderBytes = 16U * 1024U;
inline constexpr std::int64_t kLspJsonRpcMethodNotFound = -32601;

enum class LspTransportKind : std::uint8_t {
  stdio_spawn,
  unix_socket,
  tcp_loopback,
  attached_fds,
};

enum class LspPositionEncoding : std::uint8_t {
  utf8,
  utf16,
  utf32,
};

struct LspPosition {
  std::uint32_t line = 0;
  std::uint32_t character = 0;
  auto operator<=>(const LspPosition &) const = default;
};

struct LspRange {
  LspPosition start;
  LspPosition end;
  bool operator==(const LspRange &) const = default;
};

struct LspLocation {
  std::filesystem::path path;
  std::string uri;
  LspRange range;
  bool operator==(const LspLocation &) const = default;
};

struct LspDiagnostic {
  LspRange range;
  std::uint32_t severity = 0; // 1=Error, 2=Warning, 3=Info, 4=Hint, 0=Unspecified
  std::string code;
  std::string source;
  std::string message;
  bool operator==(const LspDiagnostic &) const = default;
};

struct LspPublishedDiagnostics {
  std::filesystem::path path;
  std::string uri;
  std::optional<std::int64_t> version;
  std::vector<LspDiagnostic> diagnostics;
};

struct LspHover {
  std::string kind;
  std::string value;
  std::optional<LspRange> range;
};

struct LspDocumentSymbol {
  std::string name;
  std::string detail;
  std::uint32_t kind = 0;
  LspRange range;
  LspRange selection_range;
  std::vector<LspDocumentSymbol> children;
};

struct LspWorkspaceSymbol {
  std::string name;
  std::uint32_t kind = 0;
  std::string container_name;
  LspLocation location;
};

struct LspCallHierarchyItem {
  std::string name;
  std::uint32_t kind = 0;
  std::string detail;
  std::filesystem::path path;
  std::string uri;
  LspRange range;
  LspRange selection_range;
  std::optional<Value> data;
};

struct LspCallHierarchyIncomingCall {
  LspCallHierarchyItem from;
  std::vector<LspRange> from_ranges;
};

struct LspCallHierarchyOutgoingCall {
  LspCallHierarchyItem to;
  std::vector<LspRange> from_ranges;
};

struct LspPrepareRenameResult {
  LspRange range;
  std::string placeholder;
  bool default_behavior = false;
};

struct LspTextEdit {
  LspRange range;
  std::string new_text;
  bool operator==(const LspTextEdit &) const = default;
};

struct LspFileEditPlan {
  std::filesystem::path path;
  std::filesystem::path relative_path;
  std::string uri;
  std::vector<LspTextEdit> edits; // Sorted ascending, strictly non-overlapping.
  std::string unified_diff;
};

// Structured rename/code-edit plan. NEVER writes workspace files to disk.
struct LspWorkspaceEditPlan {
  std::vector<LspFileEditPlan> files; // Deterministically sorted by relative_path.
  std::string unified_preview;
  std::size_t total_edits = 0;
};

struct LspServerCapabilities {
  LspPositionEncoding position_encoding = LspPositionEncoding::utf16;
  bool definition_provider = false;
  bool references_provider = false;
  bool hover_provider = false;
  bool document_symbol_provider = false;
  bool workspace_symbol_provider = false;
  bool call_hierarchy_provider = false;
  bool rename_provider = false;
  bool rename_prepare_provider = false;
};

struct LspInitializeResult {
  std::string server_name;
  std::string server_version;
  LspServerCapabilities capabilities;
};

struct LspDidOpenParams {
  std::filesystem::path path;
  std::string language_id;
  std::int64_t version = 1;
  std::string text;
};

struct LspTextDocumentContentChange {
  std::optional<LspRange> range; // std::nullopt means full-document replacement.
  std::string text;
};

struct LspDidChangeParams {
  std::filesystem::path path;
  std::int64_t version = 2;
  std::vector<LspTextDocumentContentChange> changes;
};

struct LspTextDocumentPosition {
  std::filesystem::path path;
  LspPosition position;
};

struct LspReferencesParams {
  std::filesystem::path path;
  LspPosition position;
  bool include_declaration = true;
};

struct LspRenameParams {
  std::filesystem::path path;
  LspPosition position;
  std::string new_name;
};

struct LspTimeouts {
  std::chrono::milliseconds connect{3000};
  std::chrono::milliseconds request{10000};
  std::chrono::milliseconds shutdown_grace{1000};
  std::chrono::milliseconds term_grace{500};
};

struct LspStdioSpawnConfig {
  std::filesystem::path workspace_root;
  std::filesystem::path executable;
  std::vector<std::string> arguments;
  std::vector<std::string> environment; // Empty => inherit current environ.
  std::size_t max_payload_bytes = kLspDefaultMaxPayloadBytes;
  LspTimeouts timeouts{};
};

struct LspUnixSocketConfig {
  std::filesystem::path workspace_root;
  std::filesystem::path socket_path;
  std::size_t max_payload_bytes = kLspDefaultMaxPayloadBytes;
  LspTimeouts timeouts{};
};

struct LspTcpLoopbackConfig {
  std::filesystem::path workspace_root;
  std::string host = "127.0.0.1"; // Strictly loopback: 127.0.0.1, ::1, or localhost.
  std::uint16_t port = 0;
  std::size_t max_payload_bytes = kLspDefaultMaxPayloadBytes;
  LspTimeouts timeouts{};
};

struct LspAttachedFdsConfig {
  std::filesystem::path workspace_root;
  int read_fd = -1;
  int write_fd = -1;
  bool close_fds_on_destroy = true;
  bool allow_protocol_shutdown = false;
  std::size_t max_payload_bytes = kLspDefaultMaxPayloadBytes;
  LspTimeouts timeouts{};
};

struct LspRequestId {
  std::variant<std::int64_t, std::string> value{std::int64_t{0}};
  bool operator==(const LspRequestId &) const = default;
};

struct LspWorkspaceUriInput {
  std::filesystem::path workspace_root;
  std::string_view uri;
};

// Pure UTF-8 byte-offset <-> UTF-16 code-unit / LSP column conversion helpers.
Result<std::uint32_t> utf8_byte_offset_to_utf16_column(std::string_view line_utf8,
                                                       std::size_t byte_offset);
Result<std::size_t> utf16_column_to_utf8_byte_offset(std::string_view line_utf8,
                                                     std::uint32_t utf16_column);
Result<std::uint32_t> utf8_byte_offset_to_lsp_column(std::string_view line_utf8,
                                                     std::size_t byte_offset,
                                                     LspPositionEncoding encoding);
Result<std::size_t> lsp_column_to_utf8_byte_offset(std::string_view line_utf8,
                                                   std::uint32_t lsp_column,
                                                   LspPositionEncoding encoding);

// Pure URI <-> workspace path helpers (strictly validated against workspace_root).
Result<std::string> path_to_file_uri(const std::filesystem::path &absolute_path);
Result<std::filesystem::path>
resolve_workspace_file_uri(const LspWorkspaceUriInput &input);

// Zero-dependency native C++23 JSON-RPC 2.0 LSP Client.
// Consumer-only lifecycle: owns stdio-spawned children cleanly and NEVER terminates
// external Unix/TCP loopback shared daemons.
class LspClient {
public:
  static Result<LspClient> spawn_stdio(const LspStdioSpawnConfig &config);
  static Result<LspClient> attach_unix_socket(const LspUnixSocketConfig &config);
  static Result<LspClient> attach_tcp_loopback(const LspTcpLoopbackConfig &config);
  static Result<LspClient> attach_fds(const LspAttachedFdsConfig &config);

  LspClient(const LspClient &) = delete;
  LspClient &operator=(const LspClient &) = delete;
  LspClient(LspClient &&) noexcept;
  LspClient &operator=(LspClient &&) noexcept;
  ~LspClient();

  LspTransportKind transport_kind() const noexcept;
  bool owns_process() const noexcept;
  bool is_open() const noexcept;
  bool is_initialized() const noexcept;
  LspPositionEncoding position_encoding() const noexcept;
  const std::filesystem::path &workspace_root() const noexcept;
  const std::string &last_error_detail() const noexcept;
  std::size_t rejected_server_request_count() const noexcept;
  std::size_t dropped_diagnostics_count() const noexcept;

  // Core lifecycle.
  Result<LspInitializeResult> initialize();
  Result<void> shutdown();
  void disconnect() noexcept;

  // Document synchronization.
  Result<void> did_open(const LspDidOpenParams &params);
  Result<void> did_change(const LspDidChangeParams &params);
  Result<void> did_close(const std::filesystem::path &path);

  // Structural intelligence.
  Result<std::vector<LspLocation>> definition(const LspTextDocumentPosition &pos);
  Result<std::vector<LspLocation>> references(const LspReferencesParams &params);
  Result<std::optional<LspHover>> hover(const LspTextDocumentPosition &pos);
  Result<std::vector<LspDocumentSymbol>>
  document_symbols(const std::filesystem::path &path);
  Result<std::vector<LspWorkspaceSymbol>> workspace_symbols(std::string_view query);
  Result<std::vector<LspCallHierarchyItem>>
  prepare_call_hierarchy(const LspTextDocumentPosition &pos);
  Result<std::vector<LspCallHierarchyIncomingCall>>
  incoming_calls(const LspCallHierarchyItem &item);
  Result<std::vector<LspCallHierarchyOutgoingCall>>
  outgoing_calls(const LspCallHierarchyItem &item);

  // Diagnostics cache & notification pump.
  Result<std::size_t> poll_notifications(std::chrono::milliseconds timeout);
  Result<std::optional<LspPublishedDiagnostics>>
  cached_diagnostics(const std::filesystem::path &path) const;
  std::vector<LspPublishedDiagnostics> all_cached_diagnostics() const;

  // Safe read-only rename planning (NEVER writes disk).
  Result<std::optional<LspPrepareRenameResult>>
  prepare_rename(const LspTextDocumentPosition &pos);
  Result<LspWorkspaceEditPlan> rename(const LspRenameParams &params);

  // Low-level JSON-RPC 2.0 request/response correlation (supports int & string IDs,
  // pipelining, and out-of-order response resolution).
  Result<void> send_request_with_id(const LspRequestId &id, std::string_view method,
                                    Value params);
  Result<Value> wait_for_response(const LspRequestId &id);
  Result<Value> request_raw(std::string_view method, Value params);
  Result<void> notify_raw(std::string_view method, Value params);

private:
  struct Impl;
  explicit LspClient(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

} // namespace blackbird
