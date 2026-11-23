#pragma once

#include "blackbird/foundation.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct sockaddr;

namespace blackbird::net {

// ---------------------------------------------------------------------------
// Error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

enum class NetError : std::int64_t {
  none = 0,

  invalid_url = 5000,
  invalid_request = 5001,
  host_not_allowed = 5002,
  scheme_not_allowed = 5003,
  ssrf_blocked = 5004,
  redirect_blocked = 5005,
  too_many_redirects = 5006,

  dns_failed = 5007,
  connect_failed = 5008,
  timeout = 5009,
  cancelled = 5010,

  tls_init_failed = 5011,
  tls_ca_load_failed = 5012,
  tls_verify_failed = 5013,
  tls_handshake_failed = 5014,
  tls_io_failed = 5015,

  http_malformed_response = 5016,
  http_header_too_large = 5017,
  http_body_too_large = 5018,
  http_chunked_malformed = 5019,
  http_unsupported_encoding = 5020,

  sse_event_too_large = 5021,
  sse_aborted = 5022,
};

constexpr NetError net_error_of(const Error &error) noexcept {
  return static_cast<NetError>(error.detail);
}

std::string_view net_error_name(NetError detail) noexcept;

// ---------------------------------------------------------------------------
// Protocol constants & limits
// ---------------------------------------------------------------------------

inline constexpr std::size_t kDefaultMaxHeaderBytes = 64U * 1024U;
inline constexpr std::size_t kHardMaxHeaderBytes = 256U * 1024U;
inline constexpr std::size_t kDefaultMaxBodyBytes = 4U * 1024U * 1024U;
inline constexpr std::size_t kHardMaxBodyBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kDefaultMaxSseEventBytes = 1U * 1024U * 1024U;
inline constexpr std::size_t kDefaultMaxSseLineBytes = 256U * 1024U;
inline constexpr int kDefaultConnectTimeoutMs = 10'000;
inline constexpr int kDefaultIoTimeoutMs = 30'000;
inline constexpr int kTlsVersion12 = 0x0303;
inline constexpr int kTlsVersion13 = 0x0304;

// ---------------------------------------------------------------------------
// URL parsing & host/SSRF policy
// ---------------------------------------------------------------------------

struct ParsedUrl {
  std::string scheme; // lowercase "https" or "http"
  std::string host;   // lowercase hostname or IPv4/IPv6 literal (no brackets)
  std::uint16_t port = 0U;
  bool explicit_port = false;
  std::string path;  // always starts with '/'
  std::string query; // without leading '?'

  std::string authority() const;
  std::string request_target() const;
  std::string canonical_origin() const;
  std::string str() const;

  bool operator==(const ParsedUrl &) const = default;
};

Result<ParsedUrl> parse_url(std::string_view url);

// Resolves a Location header (absolute URL, scheme-relative, origin-relative,
// or path-relative) against a base URL.
Result<ParsedUrl> resolve_redirect_url(const ParsedUrl &base,
                                       std::string_view location);

// Returns true if host is an IPv4 or IPv6 literal.
bool is_ip_literal(std::string_view host) noexcept;

// Classifies raw socket addresses for SSRF protection.
bool is_loopback_address(const sockaddr *addr) noexcept;
bool is_private_or_special_address(const sockaddr *addr) noexcept;
bool is_loopback_ip_literal(std::string_view host) noexcept;
bool is_private_or_special_ip_literal(std::string_view host) noexcept;

// Checks whether a lowercase hostname matches a host pin (exact match or
// single-label/multi-label wildcard "*.example.com", never bare "*").
struct HostPinCheck {
  std::string_view host;
  std::string_view pin;
};
bool host_matches_pin(HostPinCheck check) noexcept;

struct RedirectTransition {
  const ParsedUrl &from;
  const ParsedUrl &to;
};

struct AllowedHostPolicy {
  // Pinned hosts (lowercase exact hostname or "*.example.com").
  std::vector<std::string> allowed_hosts;
  // When true (default), allowed_hosts must be non-empty and every target
  // hostname must match an entry. Fail-closed by default.
  bool require_pinned_host = true;
  // When true (default), only "https" is permitted.
  bool require_https = true;
  // Explicitly allow 127.0.0.0/8 and ::1 (for loopback testing only).
  // Private RFC1918 and link-local (169.254.x.x / fe80::) remain blocked.
  bool allow_loopback = false;
  // Explicitly allow RFC1918 / ULA / link-local addresses.
  bool allow_private_network = false;
  // Redirect controls.
  bool allow_redirects = true;
  std::uint8_t max_redirects = 5U;
  // When false (default), redirects to a different host are rejected even if
  // that host appears in allowed_hosts. Redirects to unpinned hosts or HTTPS ->
  // HTTP downgrades are ALWAYS rejected.
  bool allow_cross_host_redirects = false;

  static AllowedHostPolicy pinned(std::vector<std::string> hosts);
  static AllowedHostPolicy any_public_https();

  Result<void> validate_url(const ParsedUrl &url) const;
  Result<void> validate_resolved_address(const sockaddr *addr) const noexcept;
  Result<void> validate_redirect(RedirectTransition transition) const;

  bool operator==(const AllowedHostPolicy &) const = default;
};

// ---------------------------------------------------------------------------
// HTTP/1.1 types
// ---------------------------------------------------------------------------

enum class HttpMethod : std::uint8_t {
  get = 0,
  post = 1,
  put = 2,
  patch = 3,
  del = 4,
  head = 5,
};

std::string_view http_method_name(HttpMethod method) noexcept;
Result<HttpMethod> parse_http_method(std::string_view text) noexcept;

struct HttpHeader {
  std::string name;
  std::string value;

  bool operator==(const HttpHeader &) const = default;
};

struct HttpRequest {
  HttpMethod method = HttpMethod::get;
  std::string url;
  std::vector<HttpHeader> headers;
  std::vector<std::uint8_t> body;
  int connect_timeout_ms = kDefaultConnectTimeoutMs;
  int io_timeout_ms = kDefaultIoTimeoutMs;
  std::size_t max_header_bytes = kDefaultMaxHeaderBytes;
  std::size_t max_body_bytes = kDefaultMaxBodyBytes;

  void set_header(HttpHeader header);
  void add_header(HttpHeader header);
  void remove_header(std::string_view name);
  void set_body_string(std::string_view text);
  std::optional<std::string_view> find_header(std::string_view name) const noexcept;
};

struct HttpResponse {
  int status = 0;
  std::vector<HttpHeader> headers; // header names normalized to lowercase
  std::vector<std::uint8_t> body;
  std::string final_url;

  std::string body_as_string() const;
  std::optional<std::string_view> find_header(std::string_view name) const noexcept;
  std::vector<std::string_view> find_all_headers(std::string_view name) const;
};

// ---------------------------------------------------------------------------
// Incremental Server-Sent Events (SSE) parser (WHATWG HTML §9.2.6)
// ---------------------------------------------------------------------------

struct SseEvent {
  std::string event; // defaults to "message" when omitted
  std::string data;
  std::string id;
  std::optional<std::uint64_t> retry_ms;

  bool operator==(const SseEvent &) const = default;
};

struct SseParserConfig {
  std::size_t max_event_bytes = kDefaultMaxSseEventBytes;
  std::size_t max_line_bytes = kDefaultMaxSseLineBytes;
};

class SseParser {
public:
  using EventCallback = std::function<bool(SseEvent)>;

  explicit SseParser(SseParserConfig config = {}) noexcept : config_(config) {}

  Result<void> feed(std::span<const std::uint8_t> chunk, const EventCallback &on_event);
  Result<void> feed(std::string_view chunk, const EventCallback &on_event);
  Result<void> finish(const EventCallback &on_event);

  bool stopped() const noexcept { return stopped_; }
  const std::string &last_event_id() const noexcept { return last_event_id_; }
  std::optional<std::uint64_t> retry_ms() const noexcept { return last_retry_ms_; }
  void reset() noexcept;

private:
  Result<void> process_line(std::string_view line, const EventCallback &on_event);
  Result<void> dispatch_event(const EventCallback &on_event);

  SseParserConfig config_{};
  std::string line_buf_;
  std::string event_type_;
  std::string data_buf_;
  std::string last_event_id_;
  std::optional<std::uint64_t> last_retry_ms_;
  std::size_t bom_seen_ = 0U;
  bool bom_checked_ = false;
  bool pending_lf_ = false;
  bool has_data_ = false;
  bool stopped_ = false;
};

// ---------------------------------------------------------------------------
// HTTP/HTTPS client (OpenSSL 3 TLS 1.2+/1.3 + non-blocking poll() sockets)
// ---------------------------------------------------------------------------

struct HttpClientConfig {
  AllowedHostPolicy host_policy = AllowedHostPolicy::any_public_https();
  std::optional<std::filesystem::path> ca_bundle_path = std::nullopt;
  // Optional TCP dial target override (e.g. "127.0.0.1") for testing real SNI
  // and X.509 SAN verification against an in-process loopback TLS server.
  // AllowedHostPolicy still validates both the URL hostname and dialed IP.
  std::string connect_host_override;
  std::optional<std::uint16_t> connect_port_override = std::nullopt;
  // Minimum TLS protocol version (defaults to TLS 1.2, negotiates TLS 1.3).
  int min_tls_version = kTlsVersion12;
  std::function<bool()> cancelled = {};
  std::string default_user_agent = "Blackbird/1.0";
};

class HttpClient {
public:
  explicit HttpClient(HttpClientConfig config = {});

  const HttpClientConfig &config() const noexcept { return config_; }

  Result<HttpResponse> request(const HttpRequest &req) const;

  // Streams an SSE response ("text/event-stream") incrementally into on_event.
  // If the server returns a non-SSE content type (e.g. application/json or a
  // 401/403 challenge), reads the bounded body into HttpResponse::body instead.
  Result<HttpResponse> stream_sse(const HttpRequest &req,
                                  const SseParser::EventCallback &on_event,
                                  SseParserConfig sse_config = {}) const;

private:
  HttpClientConfig config_;
};

} // namespace blackbird::net
