#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/value.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::size_t kJupyterDefaultMaxNotebookBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kJupyterDefaultMaxHttpBodyBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kJupyterDefaultMaxWsFrameBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kJupyterDefaultMaxHeaderBytes = 64U * 1024U;
inline constexpr std::size_t kJupyterDefaultMaxOutlinePreviewChars = 96U;
inline constexpr std::size_t kJupyterDefaultSummaryBinaryThresholdBytes = 256U;
inline constexpr std::int64_t kJupyterDefaultTimeoutMs = 10000;

enum class JupyterErrorDetail : std::int64_t {
  none = 0,
  invalid_json = 1,
  unsupported_nbformat = 2,
  invalid_notebook_schema = 3,
  invalid_cell_schema = 4,
  invalid_cell_index = 5,
  invalid_output_schema = 6,
  invalid_url = 7,
  non_loopback_http_refused = 8,
  invalid_token = 9,
  invalid_kernel_id = 10,
  invalid_kernel_name = 11,
  invalid_timeout = 12,
  connect_failed = 13,
  tls_failed = 14,
  http_protocol_error = 15,
  http_status_error = 16,
  auth_failed = 17,
  ws_handshake_failed = 18,
  ws_protocol_error = 19,
  ws_closed_unexpectedly = 20,
  execution_timeout = 21,
  response_too_large = 22,
  crypto_error = 23,
};

// ---------------------------------------------------------------------------
// Part 1: Pure C++23 .ipynb (nbformat v4.x) Structural Engine (zero disk I/O)
// ---------------------------------------------------------------------------

enum class NotebookCellType : std::uint8_t {
  code,
  markdown,
  raw,
};

std::string_view notebook_cell_type_name(NotebookCellType type) noexcept;
std::optional<NotebookCellType>
parse_notebook_cell_type(std::string_view name) noexcept;

enum class NotebookOutputType : std::uint8_t {
  stream,
  execute_result,
  display_data,
  error,
};

std::string_view notebook_output_type_name(NotebookOutputType type) noexcept;
std::optional<NotebookOutputType>
parse_notebook_output_type(std::string_view name) noexcept;

struct NotebookMimeEntry {
  std::string mime_type;
  // Raw JSON Value preserved verbatim for lossless nbformat round-trip serialization.
  Value data;
  bool operator==(const NotebookMimeEntry &) const = default;
};

struct NotebookOutput {
  NotebookOutputType output_type = NotebookOutputType::stream;

  // stream
  std::string stream_name;
  std::string text;

  // execute_result / display_data
  std::optional<std::int64_t> execution_count;
  std::vector<NotebookMimeEntry> data;
  Value metadata = Value::object({});

  // error
  std::string ename;
  std::string evalue;
  std::vector<std::string> traceback;

  bool operator==(const NotebookOutput &) const = default;
};

struct NotebookCell {
  std::string id;
  NotebookCellType cell_type = NotebookCellType::code;
  std::string source;
  std::optional<std::int64_t> execution_count;
  std::vector<NotebookOutput> outputs;
  Value metadata = Value::object({});
  std::optional<Value> attachments;

  bool operator==(const NotebookCell &) const = default;
};

struct NotebookKernelSpec {
  std::string name;
  std::string display_name;
  std::string language;
  Value extra = Value::object({});

  bool operator==(const NotebookKernelSpec &) const = default;
};

struct NotebookLanguageInfo {
  std::string name;
  std::string version;
  std::string mimetype;
  std::string file_extension;
  Value extra = Value::object({});

  bool operator==(const NotebookLanguageInfo &) const = default;
};

struct NotebookMetadata {
  std::optional<NotebookKernelSpec> kernelspec;
  std::optional<NotebookLanguageInfo> language_info;
  Value extra = Value::object({});

  bool operator==(const NotebookMetadata &) const = default;
};

struct NotebookDocument {
  std::int64_t nbformat = 4;
  std::int64_t nbformat_minor = 5;
  NotebookMetadata metadata;
  std::vector<NotebookCell> cells;

  bool operator==(const NotebookDocument &) const = default;
};

// Parses an nbformat v4.x JSON string into an in-memory NotebookDocument.
// Never performs disk I/O. Preserves raw output payloads verbatim.
Result<NotebookDocument> parse_ipynb(std::string_view json, ValueLimits limits = {});

// Serializes an in-memory NotebookDocument into canonical nbformat v4.5 JSON.
// Never performs disk I/O.
Result<std::string> serialize_ipynb(const NotebookDocument &doc,
                                    ValueLimits limits = {});

// Strips ANSI CSI/OSC/DCS/ESC sequences and raw control characters (preserving
// '\n', '\t', and valid UTF-8 printable text) for model-ergonomic summaries.
std::string strip_ansi_and_control_sequences(std::string_view text);

struct NotebookHygieneOptions {
  std::size_t max_text_chars = 1024U;
  std::size_t max_base64_inline_bytes = kJupyterDefaultSummaryBinaryThresholdBytes;
  std::size_t max_traceback_lines = 12U;
  bool strip_ansi = true;
};

// Produces a concise, model-ergonomic summary of a NotebookOutput without
// mutating raw output payloads. Strips ANSI/control noise and replaces binary /
// large base64 MIME payloads (e.g. image/png, image/jpeg, application/pdf) with
// MIME-type + decoded byte-size summaries.
std::string summarize_notebook_output(const NotebookOutput &output,
                                      const NotebookHygieneOptions &options = {});

// Structural in-memory cell transforms (zero disk writes).
Result<void> replace_cell_source(NotebookDocument &doc, std::size_t cell_index,
                                 std::string new_source);
Result<void> insert_cell(NotebookDocument &doc, std::size_t index, NotebookCell cell);
Result<void> delete_cell(NotebookDocument &doc, std::size_t cell_index);
Result<void>
update_cell_outputs(NotebookDocument &doc, std::size_t cell_index,
                    std::vector<NotebookOutput> outputs,
                    std::optional<std::int64_t> execution_count = std::nullopt);

struct NotebookOutlineOptions {
  std::size_t max_preview_chars = kJupyterDefaultMaxOutlinePreviewChars;
  NotebookHygieneOptions hygiene{};
};

// Produces a compact structural outline of a notebook (header + per-cell index,
// type, id, execution count, first-line preview, and hygienic output status).
std::string format_notebook_outline(const NotebookDocument &doc,
                                    const NotebookOutlineOptions &options = {});

// ---------------------------------------------------------------------------
// Part 2: Service-Consumer Jupyter Server REST + RFC 6455 WebSocket v13 Client
// ---------------------------------------------------------------------------

struct JupyterClientConfig {
  // Plain http:// is strictly limited to loopback: 127.0.0.1, localhost, [::1].
  // Non-loopback plain http:// is refused. https:// uses TLS 1.2+ verification.
  std::string base_url{};
  // Held privately inside JupyterClient, cleansed via OPENSSL_cleanse on
  // destruction, and never emitted in diagnostics or error messages.
  std::string api_token{};
  std::chrono::milliseconds connect_timeout{3000};
  std::chrono::milliseconds request_timeout{kJupyterDefaultTimeoutMs};
  std::size_t max_http_body_bytes = kJupyterDefaultMaxHttpBodyBytes;
  std::size_t max_ws_frame_bytes = kJupyterDefaultMaxWsFrameBytes;
};

struct JupyterKernelInfo {
  std::string id{};
  std::string name{};
  std::string execution_state{};
  std::string last_activity{};
  std::uint64_t connections = 0;

  bool operator==(const JupyterKernelInfo &) const = default;
};

struct JupyterExecuteRequest {
  std::string kernel_id{};
  std::string code{};
  std::chrono::milliseconds timeout{kJupyterDefaultTimeoutMs};
  bool silent = false;
  bool store_history = true;
  bool stop_on_error = true;
};

struct JupyterExecutionResult {
  std::string msg_id;
  std::string status; // "ok", "error", "abort"
  std::optional<std::int64_t> execution_count;
  std::vector<NotebookOutput> outputs;
  std::optional<std::string> error_name;
  std::optional<std::string> error_value;
  std::vector<std::string> traceback;
};

// Consumer-only Jupyter Server REST + RFC 6455 WebSocket v13 client.
// Destructor NEVER shuts down remote kernels (shared services may be consumed
// concurrently by multiple Blackbird instances). Call shutdown_kernel() explicitly
// only when terminating a kernel is intended.
class JupyterClient {
public:
  static Result<JupyterClient> create(const JupyterClientConfig &config);

  JupyterClient(const JupyterClient &) = delete;
  JupyterClient &operator=(const JupyterClient &) = delete;
  JupyterClient(JupyterClient &&) noexcept;
  JupyterClient &operator=(JupyterClient &&) noexcept;
  ~JupyterClient();

  std::string_view base_url() const noexcept;
  // Human-readable diagnostic for the most recent error; guaranteed never to
  // contain the configured API token.
  std::string_view last_error_detail() const noexcept;

  Result<std::vector<JupyterKernelInfo>> list_kernels();
  Result<JupyterKernelInfo> start_kernel(std::string_view kernel_name = {});
  Result<void> interrupt_kernel(std::string_view kernel_id);
  Result<void> shutdown_kernel(std::string_view kernel_id);

  // Executes code on an existing kernel over RFC 6455 WebSocket
  // (/api/kernels/<id>/channels) using Jupyter wire protocol v5.3.
  Result<JupyterExecutionResult> execute_code(const JupyterExecuteRequest &request);

private:
  struct Impl;
  explicit JupyterClient(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Part 3: Passive Local Jupyter Capability Discovery (never fails if absent)
// ---------------------------------------------------------------------------

struct JupyterKernelSpecInfo {
  std::string name;
  std::string display_name;
  std::string language;
  std::string resource_dir;

  bool operator==(const JupyterKernelSpecInfo &) const = default;
};

struct JupyterCapabilities {
  bool jupyter_available = false;
  std::string jupyter_path;
  std::vector<JupyterKernelSpecInfo> kernelspecs;
  std::string diagnostic;
};

struct JupyterProbeOptions {
  // Optional explicit executable path (absolute or relative) to probe instead of
  // scanning PATH; primarily for deterministic testing.
  std::string executable_override{};
  std::chrono::milliseconds timeout{3000};
  std::size_t max_output_bytes = 256U * 1024U;
};

// Safely checks for a local `jupyter` binary (zero shell, strict posix_spawn
// `jupyter kernelspec list --json` with bounded timeout and output cap).
// Never fails if `jupyter` is absent.
JupyterCapabilities probe_jupyter_capabilities(const JupyterProbeOptions &options = {});

} // namespace blackbird
