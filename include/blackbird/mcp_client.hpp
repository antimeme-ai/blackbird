#pragma once

#include "blackbird/brakes_policy.hpp"
#include "blackbird/context.hpp"
#include "blackbird/context_hygiene.hpp"
#include "blackbird/foundation.hpp"
#include "blackbird/mcp_server.hpp"
#include "blackbird/value.hpp"

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

// Strongly-typed integer primary keys (zero string PKs internally; names are
// indexed properties).
struct McpServerId {
  std::uint64_t value = 0;
  constexpr explicit operator bool() const noexcept { return value != 0; }
  auto operator<=>(const McpServerId &) const = default;
};

struct McpToolId {
  std::uint64_t value = 0;
  constexpr explicit operator bool() const noexcept { return value != 0; }
  auto operator<=>(const McpToolId &) const = default;
};

struct McpResourceId {
  std::uint64_t value = 0;
  constexpr explicit operator bool() const noexcept { return value != 0; }
  auto operator<=>(const McpResourceId &) const = default;
};

struct McpPromptId {
  std::uint64_t value = 0;
  constexpr explicit operator bool() const noexcept { return value != 0; }
  auto operator<=>(const McpPromptId &) const = default;
};

inline constexpr std::string_view kMcpClientProtocolLatest = "2025-11-25";
inline constexpr std::string_view kMcpClientProtocol20250618 = "2025-06-18";
inline constexpr std::string_view kMcpClientProtocol20250326 = "2025-03-26";
inline constexpr std::string_view kMcpClientName = "blackbird";
inline constexpr std::string_view kMcpClientVersion = "1.0.0";
inline constexpr std::size_t kMcpClientMaxPages = 128U;
inline constexpr std::size_t kMcpClientMaxStderrBytes = 64U * 1024U;
inline constexpr std::size_t kMcpClientDefaultSearchLimit = 8U;
inline constexpr std::size_t kMcpClientMaxSearchLimit = 64U;

enum class McpTransportKind : std::uint8_t {
  stdio = 0,
  streamable_http = 1,
};

struct McpTimeouts {
  std::chrono::milliseconds request{30000};
  std::chrono::milliseconds shutdown_grace{1000};
  std::chrono::milliseconds term_grace{500};
};

// Injectable Streamable HTTP transport contract (plugs directly into
// blackbird::net::HttpClient or deterministic unit-test harnesses).
struct McpHttpRequest {
  std::string method;
  std::string url;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
  std::chrono::milliseconds timeout{30000};
};

struct McpHttpResponse {
  int status_code = 0;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
};

using McpHttpTransportFn =
    std::function<Result<McpHttpResponse>(const McpHttpRequest &)>;

// Structured RFC 9728 / OAuth 2.1 WWW-Authenticate challenge extracted from
// HTTP 401/403 responses for seamless OAuth 2.1 handoff.
struct McpOAuthChallenge {
  int status_code = 0;
  std::string scheme;
  std::string realm;
  std::string resource_metadata;
  std::string scope;
  std::string error;
  std::string error_description;
  std::string raw_header;
  bool operator==(const McpOAuthChallenge &) const = default;
};

struct McpNotification {
  std::string method;
  Value params;
};

using McpNotificationFn = std::function<void(const McpNotification &)>;

struct McpStdioConfig {
  std::filesystem::path executable;
  std::vector<std::string> arguments;
  std::filesystem::path cwd;
  // Optional parent environment override for deterministic testing. When empty,
  // inherits current process environ before scrubbing.
  std::optional<std::vector<std::string>> parent_environment;
  // Explicit allowlisted "KEY=VALUE" entries appended AFTER scrubbing.
  std::vector<std::string> allowlisted_env;
  // Minimum brakes profile used for child env scrubbing. Defaults to guarded so
  // parent secrets (API keys, AWS creds, LD_/DYLD_) are always stripped unless
  // explicitly allowlisted.
  brakes::BrakesProfile env_scrub_profile = brakes::BrakesProfile::guarded;
  std::size_t max_line_bytes = kMcpDefaultMaxLineBytes;
  McpTimeouts timeouts{};
  McpNotificationFn notification_observer;
};

struct McpHttpConfig {
  std::string endpoint_url;
  std::string protocol_version = std::string{kMcpClientProtocolLatest};
  std::vector<std::pair<std::string, std::string>> default_headers;
  McpHttpTransportFn transport;
  std::size_t max_payload_bytes = kMcpMaxLineBytesLimit;
  McpTimeouts timeouts{};
  McpNotificationFn notification_observer;
};

// Untrusted server-supplied MCP ToolAnnotations (MCP 2025-06-18 / 2025-11-25).
// CRITICAL SECURITY INVARIANT: advisory hints ONLY; destructiveHint=true can
// tighten classification, while readOnlyHint=true NEVER downgrades a
// server/policy-configured write gate.
struct McpToolAnnotations {
  std::string title;
  std::optional<bool> read_only_hint;
  std::optional<bool> destructive_hint;
  std::optional<bool> idempotent_hint;
  std::optional<bool> open_world_hint;
  bool operator==(const McpToolAnnotations &) const = default;
};

struct McpToolDescriptor {
  std::string name;
  std::string title;
  std::string description;
  Value input_schema;
  std::optional<Value> output_schema;
  McpToolAnnotations annotations;
};

struct McpResourceDescriptor {
  std::string uri;
  std::string name;
  std::string title;
  std::string description;
  std::string mime_type;
};

struct McpPromptArgument {
  std::string name;
  std::string description;
  bool required = false;
  bool operator==(const McpPromptArgument &) const = default;
};

struct McpPromptDescriptor {
  std::string name;
  std::string title;
  std::string description;
  std::vector<McpPromptArgument> arguments;
};

struct McpInitializeResult {
  std::string protocol_requested;
  std::string protocol_negotiated;
  std::string server_name;
  std::string server_version;
  std::string instructions;
  std::string session_id;
  Value capabilities;
};

struct McpContentBlock {
  std::string type;
  std::string text;
  std::string mime_type;
  std::string uri;
  std::string data;
};

struct McpToolCallResult {
  bool is_error = false;
  std::vector<McpContentBlock> content;
  std::optional<Value> structured_content;
  std::string raw_wire_json;
};

struct McpResourceContent {
  std::string uri;
  std::string mime_type;
  std::string text;
  std::string blob_base64;
};

struct McpResourceReadResult {
  std::vector<McpResourceContent> contents;
  std::string raw_wire_json;
};

struct McpPromptMessage {
  std::string role;
  McpContentBlock content;
};

struct McpPromptGetResult {
  std::string description;
  std::vector<McpPromptMessage> messages;
  std::string raw_wire_json;
};

struct McpToolListPage {
  std::vector<McpToolDescriptor> tools;
  std::optional<std::string> next_cursor;
};

struct McpResourceListPage {
  std::vector<McpResourceDescriptor> resources;
  std::optional<std::string> next_cursor;
};

struct McpPromptListPage {
  std::vector<McpPromptDescriptor> prompts;
  std::optional<std::string> next_cursor;
};

// Pure helper: parses an HTTP WWW-Authenticate header (RFC 9728 / OAuth 2.1).
std::optional<McpOAuthChallenge> parse_mcp_www_authenticate(int status_code,
                                                            std::string_view header);

// Pure helper: parses a text/event-stream (SSE) body into ordered data payloads.
struct McpSseEvent {
  std::string event_type;
  std::string id;
  std::string data;
  std::optional<std::uint64_t> retry_ms;
};
Result<std::vector<McpSseEvent>>
parse_mcp_sse_stream(std::string_view body,
                     std::size_t max_bytes = kMcpMaxLineBytesLimit);

// Native C++23 MCP Client supporting both sandboxed/scrubbed Stdio and
// Streamable HTTP (2025-11-25 / 2025-06-18 / 2025-03-26 / stateless).
class McpClient {
public:
  static Result<McpClient> connect_stdio(const McpStdioConfig &config);
  static Result<McpClient> connect_http(const McpHttpConfig &config);

  McpClient(const McpClient &) = delete;
  McpClient &operator=(const McpClient &) = delete;
  McpClient(McpClient &&) noexcept;
  McpClient &operator=(McpClient &&) noexcept;
  ~McpClient();

  McpTransportKind transport_kind() const noexcept;
  bool is_open() const noexcept;
  bool is_initialized() const noexcept;
  const std::string &protocol_version() const noexcept;
  const std::string &session_id() const noexcept;
  const std::string &last_event_id() const noexcept;
  const std::string &stderr_log() const noexcept;
  const std::string &last_error_detail() const noexcept;
  const std::optional<McpOAuthChallenge> &last_oauth_challenge() const noexcept;

  // Protocol lifecycle.
  Result<McpInitializeResult> initialize();
  Result<void> close();

  // Tools.
  Result<McpToolListPage>
  list_tools(std::optional<std::string_view> cursor = std::nullopt);
  Result<std::vector<McpToolDescriptor>> list_all_tools();
  Result<McpToolCallResult> call_tool(std::string_view tool_name, Value arguments);

  // Resources.
  Result<McpResourceListPage>
  list_resources(std::optional<std::string_view> cursor = std::nullopt);
  Result<std::vector<McpResourceDescriptor>> list_all_resources();
  Result<McpResourceReadResult> read_resource(std::string_view uri);

  // Prompts.
  Result<McpPromptListPage>
  list_prompts(std::optional<std::string_view> cursor = std::nullopt);
  Result<std::vector<McpPromptDescriptor>> list_all_prompts();
  Result<McpPromptGetResult> get_prompt(std::string_view prompt_name, Value arguments);

  // Low-level JSON-RPC 2.0 request/notification.
  Result<Value> request_raw(std::string_view method, Value params,
                            std::string *raw_wire_out = nullptr);
  Result<void> notify_raw(std::string_view method, Value params);

private:
  struct Impl;
  explicit McpClient(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Built-in Official Remote MCP Presets
// ---------------------------------------------------------------------------

struct McpServerPreset {
  McpServerId preset_id{};
  std::string name;
  std::string display_name;
  std::string endpoint_url;
  std::string readonly_endpoint_url;
  std::string protocol_version = std::string{kMcpClientProtocolLatest};
  brakes::ToolEffectClass default_effect = brakes::ToolEffectClass::outbound_network;
  bool is_open_world = false;
  std::vector<std::pair<std::string, std::string>> default_headers;
  std::string description;
};

const std::vector<McpServerPreset> &builtin_mcp_presets();
std::optional<McpServerPreset> find_mcp_preset(std::string_view name);

// ---------------------------------------------------------------------------
// Brakes Classification Policy & BM25 Lazy Tool Router
// ---------------------------------------------------------------------------

// Server-side policy configured by operator/Brakes (authoritative over untrusted
// MCP ToolAnnotations).
struct McpServerPolicy {
  // Default fail-closed effect class for tools on this server.
  brakes::ToolEffectClass default_effect = brakes::ToolEffectClass::outbound_network;
  // Explicitly operator-approved read-only tool names on this server.
  std::vector<std::string> explicit_read_only_tools;
  // Open-world data provenance (e.g., public GitHub, external Slack/email).
  bool is_open_world = false;
  // Trust tier assigned to data ingested from this MCP server.
  brakes::PartyTrustProfile trust_profile = brakes::PartyTrustProfile::human_gated;
  // Safety number / provenance fingerprint override (auto-derived when empty).
  std::string safety_number;
};

struct McpToolEffectClassification {
  brakes::ToolEffectClass effect_class = brakes::ToolEffectClass::outbound_network;
  bool tightened_by_destructive_hint = false;
  bool open_world = false;
  bool operator==(const McpToolEffectClassification &) const = default;
};

// Authoritative classification enforcing the non-downgrade invariant:
// - destructiveHint=true CAN tighten classification (even above server policy).
// - readOnlyHint=true NEVER downgrades a server/policy-configured write gate.
McpToolEffectClassification
classify_mcp_tool_effect(const McpServerPolicy &server_policy,
                         std::string_view tool_name,
                         const McpToolAnnotations &annotations) noexcept;

struct McpRegisteredServerInfo {
  McpServerId server_id{};
  std::string name;
  std::string endpoint_label;
  McpTransportKind transport = McpTransportKind::stdio;
  std::size_t tool_count = 0;
  std::size_t resource_count = 0;
  std::size_t prompt_count = 0;
  McpServerPolicy policy{};
};

struct McpSearchQuery {
  std::string query;
  std::optional<std::string> server_name;
  std::size_t limit = kMcpClientDefaultSearchLimit;
};

struct McpSearchHit {
  McpServerId server_id{};
  McpToolId tool_id{};
  std::string server_name;
  std::string tool_name;
  std::string title;
  std::string description;
  double bm25_score = 0.0;
  Value input_schema;
  McpToolAnnotations annotations;
  McpToolEffectClassification effect{};
};

struct McpCallParams {
  std::string server_name;
  std::string tool_name;
  Value arguments = Value::object({});
  std::optional<ToolProjectionPolicy> projection_policy;
};

struct McpCallOutcome {
  McpServerId server_id{};
  McpToolId tool_id{};
  bool blocked_by_brakes = false;
  brakes::BrakesDecision brakes_decision = brakes::BrakesDecision::make_allow();
  bool is_error = false;
  // CSPRNG nonce-framed, context-hygiene-projected output safe for model context.
  std::string framed_output;
  // Pre-framing projected text (<= 4 KiB + headroom).
  ToolProjectionResult projection{};
  // Full verbatim raw payload (for lossless AuditLog::original() retention).
  std::string raw_payload;
  std::string audit_ref;
  McpToolEffectClassification effect{};
};

enum class McpResourceOp : std::uint8_t {
  list = 0,
  read = 1,
};

struct McpResourceParams {
  std::string server_name;
  McpResourceOp op = McpResourceOp::list;
  std::string uri;
  std::optional<ToolProjectionPolicy> projection_policy;
};

struct McpResourceOutcome {
  McpServerId server_id{};
  bool blocked_by_brakes = false;
  brakes::BrakesDecision brakes_decision = brakes::BrakesDecision::make_allow();
  std::vector<McpResourceDescriptor> resources;
  // Populated on op == read: CSPRNG nonce-framed, projected content.
  std::string framed_output;
  ToolProjectionResult projection{};
  std::string raw_payload;
  std::string audit_ref;
};

enum class McpPromptOp : std::uint8_t {
  list = 0,
  get = 1,
};

struct McpPromptParams {
  std::string server_name;
  McpPromptOp op = McpPromptOp::list;
  std::string prompt_name;
  Value arguments = Value::object({});
  std::optional<ToolProjectionPolicy> projection_policy;
};

struct McpPromptOutcome {
  McpServerId server_id{};
  bool blocked_by_brakes = false;
  brakes::BrakesDecision brakes_decision = brakes::BrakesDecision::make_allow();
  std::vector<McpPromptDescriptor> prompts;
  std::optional<McpPromptGetResult> prompt_result;
  // Populated on op == get: CSPRNG nonce-framed, projected prompt content.
  std::string framed_output;
  ToolProjectionResult projection{};
  std::string raw_payload;
  std::string audit_ref;
};

struct McpRouterConfig {
  brakes::EffectivePolicy brakes_policy{};
  ToolProjectionPolicy default_projection{};
  AuditLog *audit_log = nullptr;
};

// BM25 Lazy Tool Router managing connected MCP servers via integer ServerId /
// ToolId keys, exposing the 4 compact meta-operations (mcp_search, mcp_call,
// mcp_resource, mcp_prompt) with mandatory ContextHygiene + CSPRNG nonce
// framing + TurnTaintState latching.
class McpToolRouter {
public:
  explicit McpToolRouter(McpRouterConfig config = {});
  McpToolRouter(const McpToolRouter &) = delete;
  McpToolRouter &operator=(const McpToolRouter &) = delete;
  McpToolRouter(McpToolRouter &&) noexcept;
  McpToolRouter &operator=(McpToolRouter &&) noexcept;
  ~McpToolRouter();

  // Registers an initialized (or auto-initialized) MCP client under a logical
  // name and fetches its tools/resources/prompts catalog into the BM25 index.
  Result<McpServerId> add_server(std::string_view server_name, McpClient client,
                                 McpServerPolicy policy = {},
                                 std::string_view endpoint_label = {});

  // Registers a static/offline tool catalog entry without live transport (useful
  // for cached catalogs and deterministic router/BM25 tests).
  Result<McpServerId> add_catalog_snapshot(std::string_view server_name,
                                           const std::vector<McpToolDescriptor> &tools,
                                           McpServerPolicy policy = {},
                                           std::string_view endpoint_label = {});

  Result<void> refresh_server(McpServerId server_id);
  Result<void> remove_server(McpServerId server_id);

  std::optional<McpServerId> find_server_id(std::string_view server_name) const;
  std::optional<McpToolId> find_tool_id(McpServerId server_id,
                                        std::string_view tool_name) const;
  std::vector<McpRegisteredServerInfo> list_servers() const;

  // Compact 1-line-per-server namespace summary for prompts (avoids MCP Tax).
  std::string manifest_summary() const;

  // 4 compact meta-operations:
  std::vector<McpSearchHit> mcp_search(const McpSearchQuery &query) const;
  Result<McpCallOutcome> mcp_call(const McpCallParams &params);
  Result<McpResourceOutcome> mcp_resource(const McpResourceParams &params);
  Result<McpPromptOutcome> mcp_prompt(const McpPromptParams &params);

  // Access to the immutable-to-Lua BrakesGate and TurnTaintState.
  const brakes::BrakesGate &brakes_gate() const noexcept;
  brakes::BrakesGate &mutable_brakes_gate() noexcept;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace blackbird
