#include "blackbird/mcp_client.hpp"
#include "blackbird/json.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <map>
#include <poll.h>
#include <set>
#include <spawn.h>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#ifndef F_SETNOSIGPIPE
#include <pthread.h>
#endif

extern char **environ;

namespace blackbird {
namespace {

using Clock = std::chrono::steady_clock;

#ifndef F_SETNOSIGPIPE
class ThreadSigpipeGuard {
public:
  ThreadSigpipeGuard() noexcept {
    sigemptyset(&blocked_);
    sigaddset(&blocked_, SIGPIPE);
    if (::pthread_sigmask(SIG_BLOCK, &blocked_, &previous_) == 0) {
      active_ = true;
      sigset_t pending{};
      if (::sigpending(&pending) == 0)
        was_pending_ = ::sigismember(&pending, SIGPIPE) == 1;
    }
  }
  ThreadSigpipeGuard(const ThreadSigpipeGuard &) = delete;
  ThreadSigpipeGuard &operator=(const ThreadSigpipeGuard &) = delete;
  ~ThreadSigpipeGuard() {
    if (!active_)
      return;
    if (!was_pending_) {
      timespec zero{};
      while (::sigtimedwait(&blocked_, nullptr, &zero) < 0 && errno == EINTR) {
      }
    }
    (void)::pthread_sigmask(SIG_SETMASK, &previous_, nullptr);
  }

private:
  sigset_t blocked_{};
  sigset_t previous_{};
  bool active_ = false;
  bool was_pending_ = false;
};
#endif

class OwnedFd {
public:
  OwnedFd() = default;
  explicit OwnedFd(int fd) noexcept : fd_(fd) {}
  OwnedFd(const OwnedFd &) = delete;
  OwnedFd &operator=(const OwnedFd &) = delete;
  OwnedFd(OwnedFd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  OwnedFd &operator=(OwnedFd &&other) noexcept {
    if (this != &other) {
      reset();
      fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
  }
  ~OwnedFd() { reset(); }

  int get() const noexcept { return fd_; }
  bool valid() const noexcept { return fd_ >= 0; }
  void reset(int new_fd = -1) noexcept {
    if (fd_ >= 0) {
      while (::close(fd_) < 0 && errno == EINTR) {
      }
    }
    fd_ = new_fd;
  }

private:
  int fd_ = -1;
};

bool is_object(const Value &v) noexcept {
  return std::holds_alternative<Value::Object>(v.value());
}
bool is_array(const Value &v) noexcept {
  return std::holds_alternative<Value::Array>(v.value());
}
bool is_string(const Value &v) noexcept {
  return std::holds_alternative<std::string>(v.value());
}
bool is_bool(const Value &v) noexcept {
  return std::holds_alternative<bool>(v.value());
}
bool is_number(const Value &v) noexcept {
  return std::holds_alternative<Number>(v.value());
}

std::string ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text)
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  return out;
}

bool ascii_iequals(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size())
    return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i])))
      return false;
  }
  return true;
}

std::string_view trim_ows(std::string_view text) noexcept {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
    text.remove_prefix(1U);
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
    text.remove_suffix(1U);
  return text;
}

std::optional<std::string_view>
find_header_value(const std::vector<std::pair<std::string, std::string>> &headers,
                  std::string_view key) noexcept {
  for (const auto &[k, v] : headers) {
    if (ascii_iequals(k, key))
      return v;
  }
  return std::nullopt;
}

bool has_header(const std::vector<std::pair<std::string, std::string>> &headers,
                std::string_view key) noexcept {
  return find_header_value(headers, key).has_value();
}

std::optional<std::int64_t> parse_int64_value(const Value &v) {
  if (!is_number(v))
    return std::nullopt;
  const auto &storage = v.number().storage();
  if (const auto *i = std::get_if<std::int64_t>(&storage))
    return *i;
  if (const auto *u = std::get_if<std::uint64_t>(&storage)) {
    if (*u <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
      return static_cast<std::int64_t>(*u);
    return std::nullopt;
  }
  const std::string text = v.number().text();
  std::int64_t parsed = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

struct DefaultStrField {
  std::string_view key;
  std::string_view fallback;
};

std::string get_string_or(const Value &obj, std::string_view key) {
  const Value *f = obj.find(key);
  if (f != nullptr && is_string(*f))
    return f->string();
  return {};
}

std::string get_string_default(const Value &obj, DefaultStrField field) {
  const Value *f = obj.find(field.key);
  if (f != nullptr && is_string(*f))
    return f->string();
  return std::string{field.fallback};
}

std::optional<bool> get_opt_bool(const Value &obj, std::string_view key) {
  const Value *f = obj.find(key);
  if (f != nullptr && is_bool(*f))
    return std::get<bool>(f->value());
  return std::nullopt;
}

// Strict RFC 9110 tchar HTTP header name validator (excludes ':', whitespace,
// quotes, slashes, and control chars).
bool valid_mcp_header_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > 128U)
    return false;
  for (const char ch : name) {
    const unsigned char c = static_cast<unsigned char>(ch);
    const bool is_alnum =
        (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    const bool is_sym = c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
                        c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
                        c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
    if (!is_alnum && !is_sym)
      return false;
  }
  return true;
}

bool is_forbidden_mcp_default_header(std::string_view name) noexcept {
  return ascii_iequals(name, "host") || ascii_iequals(name, "transfer-encoding") ||
         ascii_iequals(name, "content-length");
}

bool valid_mcp_header_token(std::string_view text, std::size_t max_len) noexcept {
  if (text.empty() || text.size() > max_len)
    return false;
  for (const char ch : text) {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (c < 0x21U || c > 0x7EU)
      return false;
  }
  return true;
}

bool valid_mcp_header_value(std::string_view text) noexcept {
  for (const char ch : text) {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (c == '\r' || c == '\n' || c == '\0')
      return false;
  }
  return true;
}

bool valid_mcp_port(std::string_view port_str) noexcept {
  if (port_str.empty() || port_str.size() > 5U)
    return false;
  for (const char ch : port_str) {
    if (ch < '0' || ch > '9')
      return false;
  }
  std::uint32_t port = 0;
  const auto res =
      std::from_chars(port_str.data(), port_str.data() + port_str.size(), port);
  return res.ec == std::errc{} && res.ptr == port_str.data() + port_str.size() &&
         port >= 1U && port <= 65535U;
}

bool valid_mcp_hostname(std::string_view host) noexcept {
  if (host.empty() || host.size() > 253U)
    return false;
  if (host.front() == '.' || host.back() == '.')
    return false;
  for (const char ch : host) {
    const unsigned char c = static_cast<unsigned char>(ch);
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '.';
    if (!ok)
      return false;
  }
  return host.find("..") == std::string_view::npos;
}

bool valid_mcp_endpoint_url(std::string_view url) noexcept {
  if (url.empty() || url.size() > 2048U)
    return false;
  for (const char ch : url) {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (c <= 0x20U || c >= 0x7FU)
      return false;
  }
  const bool is_https = url.starts_with("https://");
  const bool is_http = url.starts_with("http://");
  if (!is_https && !is_http)
    return false;

  const std::string_view rest = url.substr(is_https ? 8U : 7U);
  const std::size_t auth_end = rest.find_first_of("/?#");
  const std::string_view authority =
      auth_end == std::string_view::npos ? rest : rest.substr(0U, auth_end);
  if (authority.empty() || authority.find('@') != std::string_view::npos)
    return false;

  std::string_view host;
  if (authority.front() == '[') {
    const std::size_t close = authority.find(']');
    if (close == std::string_view::npos || close <= 1U)
      return false;
    host = authority.substr(0U, close + 1U);
    for (std::size_t i = 1U; i < close; ++i) {
      const char ch = authority[i];
      const bool ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                      (ch >= 'A' && ch <= 'F') || ch == ':' || ch == '.';
      if (!ok)
        return false;
    }
    const std::string_view after = authority.substr(close + 1U);
    if (!after.empty()) {
      if (after.front() != ':' || !valid_mcp_port(after.substr(1U)))
        return false;
    }
  } else {
    const std::size_t colon = authority.find(':');
    if (colon != std::string_view::npos) {
      if (authority.find(':', colon + 1U) != std::string_view::npos)
        return false;
      host = authority.substr(0U, colon);
      if (!valid_mcp_port(authority.substr(colon + 1U)))
        return false;
    } else {
      host = authority;
    }
    if (!valid_mcp_hostname(host))
      return false;
  }

  if (is_http) {
    return ascii_iequals(host, "localhost") || host == "127.0.0.1" || host == "[::1]";
  }
  return true;
}

bool valid_env_entry(std::string_view entry) noexcept {
  if (entry.empty() || entry.find('\0') != std::string_view::npos)
    return false;
  const std::size_t eq = entry.find('=');
  if (eq == std::string_view::npos || eq == 0U)
    return false;
  for (std::size_t i = 0; i < eq; ++i) {
    const unsigned char c = static_cast<unsigned char>(entry[i]);
    if (c <= 0x20U || c >= 0x7FU || c == '=')
      return false;
  }
  return true;
}

std::vector<std::string> build_mcp_child_env(const McpStdioConfig &config) {
  std::vector<std::string> parent;
  if (config.parent_environment.has_value()) {
    parent = *config.parent_environment;
  } else if (environ != nullptr) {
    for (char **e = environ; *e != nullptr; ++e)
      parent.emplace_back(*e);
  }

  std::vector<std::string> scrubbed =
      brakes::build_scrubbed_child_env(config.env_scrub_profile, parent);

  for (const std::string &extra : config.allowlisted_env) {
    if (!valid_env_entry(extra))
      continue;
    const std::size_t eq = extra.find('=');
    const std::string_view key{extra.data(), eq};
    bool replaced = false;
    for (std::string &existing : scrubbed) {
      const std::size_t eeq = existing.find('=');
      if (eeq != std::string::npos && std::string_view{existing.data(), eeq} == key) {
        existing = extra;
        replaced = true;
        break;
      }
    }
    if (!replaced)
      scrubbed.push_back(extra);
  }
  return scrubbed;
}

Result<void> make_cloexec_pipe(OwnedFd &read_end, OwnedFd &write_end) {
  int fds[2]{-1, -1};
  if (::pipe(fds) != 0)
    return Result<void>::failure({ErrorCode::io, errno});
  OwnedFd raw_r{fds[0]};
  OwnedFd raw_w{fds[1]};
  const int r = ::fcntl(raw_r.get(), F_DUPFD_CLOEXEC, 3);
  if (r < 0)
    return Result<void>::failure({ErrorCode::io, errno});
  const int w = ::fcntl(raw_w.get(), F_DUPFD_CLOEXEC, 3);
  if (w < 0) {
    const int err = errno;
    (void)::close(r);
    return Result<void>::failure({ErrorCode::io, err});
  }
  read_end.reset(r);
  write_end.reset(w);
  return Result<void>::success();
}

McpToolAnnotations parse_tool_annotations(const Value *v) {
  McpToolAnnotations out;
  if (v == nullptr || !is_object(*v))
    return out;
  out.title = get_string_or(*v, "title");
  out.read_only_hint = get_opt_bool(*v, "readOnlyHint");
  out.destructive_hint = get_opt_bool(*v, "destructiveHint");
  out.idempotent_hint = get_opt_bool(*v, "idempotentHint");
  out.open_world_hint = get_opt_bool(*v, "openWorldHint");
  return out;
}

McpContentBlock parse_content_block(const Value &v) {
  McpContentBlock block;
  if (!is_object(v))
    return block;
  block.type = get_string_or(v, "type");
  block.text = get_string_or(v, "text");
  block.mime_type = get_string_or(v, "mimeType");
  block.uri = get_string_or(v, "uri");
  block.data = get_string_or(v, "data");
  if (block.type == "resource") {
    if (const Value *res = v.find("resource"); res != nullptr && is_object(*res)) {
      if (block.uri.empty())
        block.uri = get_string_or(*res, "uri");
      if (block.mime_type.empty())
        block.mime_type = get_string_or(*res, "mimeType");
      if (block.text.empty())
        block.text = get_string_or(*res, "text");
      if (block.data.empty())
        block.data = get_string_or(*res, "blob");
    }
  }
  return block;
}

// Tokenizes text into lowercase search terms, splitting on non-alphanumeric
// boundaries AND camelCase transitions (e.g. "createIssue" -> "create", "issue").
std::vector<std::string> tokenize_for_bm25(std::string_view text) {
  std::vector<std::string> tokens;
  std::string current;
  auto flush = [&]() {
    if (!current.empty()) {
      tokens.push_back(std::move(current));
      current.clear();
    }
  };
  for (std::size_t i = 0; i < text.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(text[i]);
    if (std::isalnum(c) != 0) {
      if (!current.empty() && std::isupper(c) != 0 && i > 0U &&
          std::islower(static_cast<unsigned char>(text[i - 1U])) != 0) {
        flush();
      }
      current.push_back(static_cast<char>(std::tolower(c)));
    } else {
      flush();
    }
  }
  flush();
  return tokens;
}

std::string render_tool_result_text(const McpToolCallResult &res) {
  std::string out;
  for (const auto &block : res.content) {
    if (!out.empty())
      out.push_back('\n');
    if (!block.text.empty()) {
      out.append(block.text);
    } else if (!block.uri.empty()) {
      out.append("[resource: ");
      out.append(block.uri);
      out.push_back(']');
    } else if (!block.data.empty()) {
      out.append("[");
      out.append(block.type.empty() ? "binary" : block.type);
      out.append(" ");
      out.append(std::to_string(block.data.size()));
      out.append(" bytes]");
    }
  }
  if (out.empty() && res.structured_content.has_value()) {
    const auto dumped = dump_json(*res.structured_content);
    if (dumped.has_value())
      out = dumped.value();
  }
  if (out.empty())
    out = res.raw_wire_json;
  return out;
}

std::string render_resource_read_text(const McpResourceReadResult &res) {
  std::string out;
  for (const auto &item : res.contents) {
    if (!out.empty())
      out.append("\n---\n");
    if (!item.uri.empty()) {
      out.append("# ");
      out.append(item.uri);
      out.push_back('\n');
    }
    if (!item.text.empty()) {
      out.append(item.text);
    } else if (!item.blob_base64.empty()) {
      out.append("[blob base64 ");
      out.append(std::to_string(item.blob_base64.size()));
      out.append(" chars]");
    }
  }
  if (out.empty())
    out = res.raw_wire_json;
  return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Pure Helpers: WWW-Authenticate & SSE Parsing
// ---------------------------------------------------------------------------

std::optional<McpOAuthChallenge> parse_mcp_www_authenticate(int status_code,
                                                            std::string_view header) {
  const std::string_view trimmed = trim_ows(header);
  if (trimmed.empty())
    return std::nullopt;

  McpOAuthChallenge out;
  out.status_code = status_code;
  out.raw_header = std::string{trimmed};

  std::size_t pos = 0U;
  while (pos < trimmed.size() && trimmed[pos] != ' ' && trimmed[pos] != '\t' &&
         trimmed[pos] != ',') {
    ++pos;
  }
  out.scheme = std::string{trimmed.substr(0U, pos)};
  if (out.scheme.empty())
    return std::nullopt;

  while (pos < trimmed.size()) {
    while (pos < trimmed.size() &&
           (trimmed[pos] == ' ' || trimmed[pos] == '\t' || trimmed[pos] == ',')) {
      ++pos;
    }
    if (pos >= trimmed.size())
      break;
    const std::size_t key_start = pos;
    while (pos < trimmed.size() && trimmed[pos] != '=' && trimmed[pos] != ',' &&
           trimmed[pos] != ' ' && trimmed[pos] != '\t') {
      ++pos;
    }
    const std::string key = ascii_lower(trimmed.substr(key_start, pos - key_start));
    while (pos < trimmed.size() && (trimmed[pos] == ' ' || trimmed[pos] == '\t'))
      ++pos;
    if (pos >= trimmed.size() || trimmed[pos] != '=') {
      while (pos < trimmed.size() && trimmed[pos] != ',')
        ++pos;
      continue;
    }
    ++pos; // skip '='
    while (pos < trimmed.size() && (trimmed[pos] == ' ' || trimmed[pos] == '\t'))
      ++pos;

    std::string val;
    if (pos < trimmed.size() && trimmed[pos] == '"') {
      ++pos;
      while (pos < trimmed.size()) {
        if (trimmed[pos] == '\\' && pos + 1U < trimmed.size()) {
          val.push_back(trimmed[pos + 1U]);
          pos += 2U;
        } else if (trimmed[pos] == '"') {
          ++pos;
          break;
        } else {
          val.push_back(trimmed[pos]);
          ++pos;
        }
      }
    } else {
      const std::size_t val_start = pos;
      while (pos < trimmed.size() && trimmed[pos] != ',' && trimmed[pos] != ' ' &&
             trimmed[pos] != '\t') {
        ++pos;
      }
      val = std::string{trimmed.substr(val_start, pos - val_start)};
    }

    if (key == "realm")
      out.realm = std::move(val);
    else if (key == "resource_metadata")
      out.resource_metadata = std::move(val);
    else if (key == "scope")
      out.scope = std::move(val);
    else if (key == "error")
      out.error = std::move(val);
    else if (key == "error_description")
      out.error_description = std::move(val);
  }
  return out;
}

Result<std::vector<McpSseEvent>> parse_mcp_sse_stream(std::string_view body,
                                                      std::size_t max_bytes) {
  if (body.size() > max_bytes)
    return Result<std::vector<McpSseEvent>>::failure({ErrorCode::capacity});

  std::vector<McpSseEvent> events;
  McpSseEvent current;
  bool has_data = false;
  bool has_any_field = false;

  auto dispatch = [&]() {
    if (has_data || has_any_field) {
      if (has_data)
        events.push_back(std::move(current));
      current = McpSseEvent{};
      has_data = false;
      has_any_field = false;
    }
  };

  std::size_t pos = 0U;
  // Strip optional UTF-8 BOM at stream start per WHATWG EventSource spec.
  if (body.size() >= 3U && static_cast<unsigned char>(body[0]) == 0xEFU &&
      static_cast<unsigned char>(body[1]) == 0xBBU &&
      static_cast<unsigned char>(body[2]) == 0xBFU) {
    pos = 3U;
  }

  while (pos < body.size()) {
    std::size_t end = pos;
    while (end < body.size() && body[end] != '\n' && body[end] != '\r')
      ++end;
    const std::string_view line = body.substr(pos, end - pos);
    pos = end;
    if (pos < body.size()) {
      if (body[pos] == '\r' && pos + 1U < body.size() && body[pos + 1U] == '\n')
        pos += 2U;
      else
        pos += 1U;
    }

    if (line.empty()) {
      dispatch();
      continue;
    }
    if (line.front() == ':')
      continue; // SSE comment line

    const std::size_t colon = line.find(':');
    std::string_view field;
    std::string_view value;
    if (colon == std::string_view::npos) {
      field = line;
    } else {
      field = line.substr(0U, colon);
      value = line.substr(colon + 1U);
      if (!value.empty() && value.front() == ' ')
        value.remove_prefix(1U);
    }

    if (field == "event") {
      current.event_type = std::string{value};
      has_any_field = true;
    } else if (field == "data") {
      if (has_data)
        current.data.push_back('\n');
      current.data.append(value);
      has_data = true;
      has_any_field = true;
    } else if (field == "id") {
      if (value.find('\0') == std::string_view::npos) {
        current.id = std::string{value};
        has_any_field = true;
      }
    } else if (field == "retry") {
      std::uint64_t ms = 0;
      const auto res = std::from_chars(value.data(), value.data() + value.size(), ms);
      if (res.ec == std::errc{} && res.ptr == value.data() + value.size()) {
        current.retry_ms = ms;
        has_any_field = true;
      }
    }
  }
  dispatch();
  return Result<std::vector<McpSseEvent>>::success(std::move(events));
}

// ---------------------------------------------------------------------------
// McpClient Implementation
// ---------------------------------------------------------------------------

struct McpClient::Impl {
  McpTransportKind transport = McpTransportKind::stdio;
  bool open = false;
  bool initialized = false;
  std::int64_t next_request_id = 1;
  std::string protocol_requested{kMcpClientProtocolLatest};
  std::string protocol_negotiated{kMcpClientProtocolLatest};
  std::string session_id;
  std::string last_event_id;
  std::string stderr_log;
  std::string last_error_detail;
  std::optional<McpOAuthChallenge> last_oauth_challenge;
  McpTimeouts timeouts{};
  std::size_t max_payload_bytes = kMcpDefaultMaxLineBytes;
  McpNotificationFn notification_observer;

  // Stdio transport state.
  pid_t child_pid = -1;
  OwnedFd stdin_fd;
  OwnedFd stdout_fd;
  OwnedFd stderr_fd;
  std::string stdout_buffer;

  // Streamable HTTP transport state.
  std::string endpoint_url;
  std::vector<std::pair<std::string, std::string>> default_headers;
  McpHttpTransportFn http_transport;

  ~Impl() { (void)close_transport(); }

  void append_stderr(std::string_view chunk) {
    if (stderr_log.size() >= kMcpClientMaxStderrBytes)
      return;
    const std::size_t room = kMcpClientMaxStderrBytes - stderr_log.size();
    stderr_log.append(chunk.substr(0U, room));
  }

  void drain_stderr_nonblocking() {
    if (!stderr_fd.valid())
      return;
    std::array<char, 4096> buf{};
    while (true) {
      const ssize_t n = ::read(stderr_fd.get(), buf.data(), buf.size());
      if (n > 0) {
        append_stderr(std::string_view{buf.data(), static_cast<std::size_t>(n)});
        continue;
      }
      if (n == 0) {
        stderr_fd.reset();
        break;
      }
      if (errno == EINTR)
        continue;
      break;
    }
  }

  Result<void> close_transport() {
    if (!open)
      return Result<void>::success();
    open = false;

    if (transport == McpTransportKind::streamable_http) {
      if (!session_id.empty() && http_transport) {
        McpHttpRequest del_req;
        del_req.method = "DELETE";
        del_req.url = endpoint_url;
        del_req.timeout = timeouts.shutdown_grace;
        del_req.headers.emplace_back("MCP-Protocol-Version", protocol_negotiated);
        del_req.headers.emplace_back("Mcp-Session-Id", session_id);
        for (const auto &[k, v] : default_headers) {
          if (!has_header(del_req.headers, k))
            del_req.headers.emplace_back(k, v);
        }
        (void)http_transport(del_req);
      }
      session_id.clear();
      return Result<void>::success();
    }

    // Stdio clean process-group shutdown.
    stdin_fd.reset();
    drain_stderr_nonblocking();

    if (child_pid > 0) {
      auto wait_reap = [&](std::chrono::milliseconds grace) -> bool {
        const auto deadline = Clock::now() + grace;
        while (true) {
          int status = 0;
          const pid_t rc = ::waitpid(child_pid, &status, WNOHANG);
          if (rc == child_pid || (rc < 0 && errno == ECHILD)) {
            child_pid = -1;
            return true;
          }
          drain_stderr_nonblocking();
          if (Clock::now() >= deadline)
            return false;
          (void)::poll(nullptr, 0, 10);
        }
      };

      if (!wait_reap(timeouts.shutdown_grace)) {
        (void)::kill(-child_pid, SIGTERM);
        if (!wait_reap(timeouts.term_grace)) {
          (void)::kill(-child_pid, SIGKILL);
          int status = 0;
          pid_t rc = -1;
          do {
            rc = ::waitpid(child_pid, &status, 0);
          } while (rc < 0 && errno == EINTR);
          child_pid = -1;
        }
      }
    }
    stdout_fd.reset();
    stderr_fd.reset();
    return Result<void>::success();
  }

  Result<void> write_stdio_line(std::string_view line) {
    if (!stdin_fd.valid())
      return Result<void>::failure({ErrorCode::io});
    if (line.size() > max_payload_bytes)
      return Result<void>::failure({ErrorCode::capacity});
    if (!valid_utf8(line) || line.find('\n') != std::string_view::npos ||
        line.find('\r') != std::string_view::npos ||
        line.find('\0') != std::string_view::npos) {
      return Result<void>::failure({ErrorCode::invalid_range});
    }

    std::string payload;
    payload.reserve(line.size() + 1U);
    payload.append(line);
    payload.push_back('\n');

#ifndef F_SETNOSIGPIPE
    ThreadSigpipeGuard sigpipe_guard;
#endif
    const auto deadline = Clock::now() + timeouts.request;
    std::size_t written = 0U;
    while (written < payload.size()) {
      const auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
              .count();
      if (remaining <= 0)
        return Result<void>::failure({ErrorCode::io, ETIMEDOUT});
      pollfd pfd{stdin_fd.get(), POLLOUT, 0};
      const int prc =
          ::poll(&pfd, 1, static_cast<int>(std::min<std::int64_t>(remaining, 100)));
      if (prc < 0) {
        if (errno == EINTR)
          continue;
        return Result<void>::failure({ErrorCode::io, errno});
      }
      if (prc == 0)
        continue;
      if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        return Result<void>::failure({ErrorCode::io, EPIPE});

      const ssize_t n =
          ::write(stdin_fd.get(), payload.data() + written, payload.size() - written);
      if (n > 0) {
        written += static_cast<std::size_t>(n);
      } else if (n < 0 && errno != EINTR && errno != EAGAIN) {
        return Result<void>::failure({ErrorCode::io, errno});
      }
    }
    return Result<void>::success();
  }

  Result<std::string> read_stdio_line() {
    if (!stdout_fd.valid())
      return Result<std::string>::failure({ErrorCode::io});
    const auto deadline = Clock::now() + timeouts.request;

    while (true) {
      const std::size_t nl = stdout_buffer.find('\n');
      if (nl != std::string::npos) {
        if (nl > max_payload_bytes)
          return Result<std::string>::failure({ErrorCode::capacity});
        std::string line = stdout_buffer.substr(0U, nl);
        stdout_buffer.erase(0U, nl + 1U);
        if (!line.empty() && line.back() == '\r')
          line.pop_back();
        if (!valid_utf8(line))
          return Result<std::string>::failure({ErrorCode::corrupt});
        return Result<std::string>::success(std::move(line));
      }

      if (stdout_buffer.size() > max_payload_bytes)
        return Result<std::string>::failure({ErrorCode::capacity});

      const auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now())
              .count();
      if (remaining <= 0)
        return Result<std::string>::failure({ErrorCode::io, ETIMEDOUT});

      std::array<pollfd, 2> pfds{};
      nfds_t nfds = 0;
      pfds[nfds++] = pollfd{stdout_fd.get(), POLLIN, 0};
      if (stderr_fd.valid())
        pfds[nfds++] = pollfd{stderr_fd.get(), POLLIN, 0};

      const int prc = ::poll(pfds.data(), nfds,
                             static_cast<int>(std::min<std::int64_t>(remaining, 100)));
      if (prc < 0) {
        if (errno == EINTR)
          continue;
        return Result<std::string>::failure({ErrorCode::io, errno});
      }
      if (prc == 0)
        continue;

      if (nfds == 2 && (pfds[1].revents & (POLLIN | POLLHUP)) != 0)
        drain_stderr_nonblocking();

      if ((pfds[0].revents & (POLLIN | POLLHUP)) != 0) {
        std::array<char, 8192> chunk{};
        const ssize_t n = ::read(stdout_fd.get(), chunk.data(), chunk.size());
        if (n > 0) {
          const auto count = static_cast<std::size_t>(n);
          if (stdout_buffer.size() + count > max_payload_bytes + 2U)
            return Result<std::string>::failure({ErrorCode::capacity});
          stdout_buffer.append(chunk.data(), count);
        } else if (n == 0) {
          return Result<std::string>::failure({ErrorCode::incomplete});
        } else if (errno != EINTR && errno != EAGAIN) {
          return Result<std::string>::failure({ErrorCode::io, errno});
        }
      } else if ((pfds[0].revents & (POLLERR | POLLNVAL)) != 0) {
        return Result<std::string>::failure({ErrorCode::io});
      }
    }
  }

  void handle_incoming_notification(const Value &msg) {
    if (!notification_observer || !is_object(msg))
      return;
    const std::string method = get_string_or(msg, "method");
    if (method.empty())
      return;
    const Value *params = msg.find("params");
    notification_observer(
        McpNotification{method, params != nullptr ? *params : Value::object({})});
  }

  Result<Value> send_stdio_request(std::int64_t id, std::string_view method,
                                   Value params, std::string *raw_wire_out) {
    Value::Object req_obj;
    req_obj.emplace_back("jsonrpc", Value{"2.0"});
    req_obj.emplace_back("id", Value{Number{id}});
    req_obj.emplace_back("method", Value{std::string{method}});
    req_obj.emplace_back("params", std::move(params));
    const auto dumped = dump_json(Value::object(std::move(req_obj)));
    if (!dumped.has_value())
      return Result<Value>::failure(dumped.error());

    const auto sent = write_stdio_line(dumped.value());
    if (!sent.has_value())
      return Result<Value>::failure(sent.error());

    while (true) {
      auto line = read_stdio_line();
      if (!line.has_value())
        return Result<Value>::failure(line.error());
      if (line.value().empty())
        continue;
      auto parsed = parse_json(line.value());
      if (!parsed.has_value() || !is_object(parsed.value())) {
        last_error_detail = "malformed JSON-RPC response from stdio MCP server";
        return Result<Value>::failure({ErrorCode::corrupt});
      }
      const Value &msg = parsed.value();
      const Value *msg_id = msg.find("id");
      const Value *msg_method = msg.find("method");
      if (msg_id == nullptr && msg_method != nullptr) {
        handle_incoming_notification(msg);
        continue;
      }
      if (msg_id != nullptr && msg_method != nullptr) {
        // Unexpected server-initiated request: reply -32601 cleanly and continue.
        Value::Object err_obj;
        err_obj.emplace_back("code", Value{Number{kJsonRpcMethodNotFound}});
        err_obj.emplace_back("message", Value{"client does not handle server request"});
        Value::Object reply;
        reply.emplace_back("jsonrpc", Value{"2.0"});
        reply.emplace_back("id", *msg_id);
        reply.emplace_back("error", Value::object(std::move(err_obj)));
        if (const auto reply_json = dump_json(Value::object(std::move(reply)));
            reply_json.has_value()) {
          (void)write_stdio_line(reply_json.value());
        }
        continue;
      }
      if (msg_id == nullptr)
        continue;
      const auto resp_id = parse_int64_value(*msg_id);
      if (!resp_id.has_value() || *resp_id != id)
        continue;

      if (raw_wire_out != nullptr)
        *raw_wire_out = line.value();
      return extract_rpc_result(msg);
    }
  }

  Result<void> send_stdio_notification(std::string_view method, Value params) {
    Value::Object req_obj;
    req_obj.emplace_back("jsonrpc", Value{"2.0"});
    req_obj.emplace_back("method", Value{std::string{method}});
    req_obj.emplace_back("params", std::move(params));
    const auto dumped = dump_json(Value::object(std::move(req_obj)));
    if (!dumped.has_value())
      return Result<void>::failure(dumped.error());
    return write_stdio_line(dumped.value());
  }

  Result<Value> extract_rpc_result(const Value &msg) {
    if (const Value *err = msg.find("error"); err != nullptr && is_object(*err)) {
      std::int64_t code = kJsonRpcInternalError;
      if (const Value *c = err->find("code"); c != nullptr) {
        if (const auto parsed_code = parse_int64_value(*c); parsed_code.has_value())
          code = *parsed_code;
      }
      last_error_detail =
          get_string_default(*err, DefaultStrField{"message", "MCP JSON-RPC error"});
      return Result<Value>::failure({ErrorCode::external_unknown, code});
    }
    if (const Value *res = msg.find("result"); res != nullptr)
      return Result<Value>::success(*res);
    last_error_detail = "MCP JSON-RPC response missing result and error";
    return Result<Value>::failure({ErrorCode::corrupt});
  }

  McpHttpRequest build_http_post(std::string body) const {
    McpHttpRequest req;
    req.method = "POST";
    req.url = endpoint_url;
    req.body = std::move(body);
    req.timeout = timeouts.request;
    req.headers.emplace_back("Content-Type", "application/json");
    req.headers.emplace_back("Accept", "application/json, text/event-stream");
    req.headers.emplace_back("MCP-Protocol-Version", protocol_negotiated);
    if (!session_id.empty())
      req.headers.emplace_back("Mcp-Session-Id", session_id);
    for (const auto &[k, v] : default_headers) {
      if (!has_header(req.headers, k))
        req.headers.emplace_back(k, v);
    }
    return req;
  }

  Result<Value> send_http_request(std::int64_t id, std::string_view method,
                                  Value params, std::string *raw_wire_out) {
    if (!http_transport)
      return Result<Value>::failure({ErrorCode::unsupported});

    Value::Object req_obj;
    req_obj.emplace_back("jsonrpc", Value{"2.0"});
    req_obj.emplace_back("id", Value{Number{id}});
    req_obj.emplace_back("method", Value{std::string{method}});
    req_obj.emplace_back("params", std::move(params));
    const auto dumped = dump_json(Value::object(std::move(req_obj)));
    if (!dumped.has_value())
      return Result<Value>::failure(dumped.error());

    const McpHttpRequest http_req = build_http_post(dumped.value());
    auto resp = http_transport(http_req);
    if (!resp.has_value()) {
      last_error_detail = "HTTP transport error";
      return Result<Value>::failure(resp.error());
    }

    if (const auto sid = find_header_value(resp.value().headers, "Mcp-Session-Id");
        sid.has_value() && !sid->empty()) {
      if (!valid_mcp_header_token(*sid, 512U)) {
        last_error_detail = "rejected malformed Mcp-Session-Id header";
        return Result<Value>::failure({ErrorCode::corrupt});
      }
      session_id = std::string{*sid};
    }

    if (resp.value().status_code == 401 || resp.value().status_code == 403) {
      if (const auto auth_hdr =
              find_header_value(resp.value().headers, "WWW-Authenticate");
          auth_hdr.has_value()) {
        last_oauth_challenge =
            parse_mcp_www_authenticate(resp.value().status_code, *auth_hdr);
      } else {
        McpOAuthChallenge fallback;
        fallback.status_code = resp.value().status_code;
        fallback.scheme = "Bearer";
        last_oauth_challenge = std::move(fallback);
      }
      last_error_detail = "MCP server requires OAuth 2.1 authorization (HTTP " +
                          std::to_string(resp.value().status_code) + ")";
      return Result<Value>::failure(
          {ErrorCode::provider_auth, resp.value().status_code});
    }

    if (resp.value().status_code < 200 || resp.value().status_code >= 300) {
      last_error_detail =
          "MCP HTTP error status " + std::to_string(resp.value().status_code);
      return Result<Value>::failure(
          {ErrorCode::provider_transport, resp.value().status_code});
    }

    if (resp.value().body.size() > max_payload_bytes)
      return Result<Value>::failure({ErrorCode::capacity});

    const std::string content_type =
        ascii_lower(find_header_value(resp.value().headers, "Content-Type")
                        .value_or("application/json"));

    if (content_type.starts_with("text/event-stream")) {
      auto sse = parse_mcp_sse_stream(resp.value().body, max_payload_bytes);
      if (!sse.has_value())
        return Result<Value>::failure(sse.error());
      std::optional<Value> matched;
      std::string matched_raw;
      for (const auto &ev : sse.value()) {
        if (!ev.id.empty())
          last_event_id = ev.id;
        if (ev.data.empty())
          continue;
        auto parsed = parse_json(ev.data);
        if (!parsed.has_value() || !is_object(parsed.value()))
          continue;
        const Value &msg = parsed.value();
        const Value *msg_id = msg.find("id");
        const Value *msg_method = msg.find("method");
        if (msg_id == nullptr && msg_method != nullptr) {
          handle_incoming_notification(msg);
          continue;
        }
        if (msg_id != nullptr) {
          const auto resp_id = parse_int64_value(*msg_id);
          if (resp_id.has_value() && *resp_id == id) {
            matched = msg;
            matched_raw = ev.data;
          }
        }
      }
      if (!matched.has_value()) {
        last_error_detail = "SSE stream ended without matching JSON-RPC response id";
        return Result<Value>::failure({ErrorCode::incomplete});
      }
      if (raw_wire_out != nullptr)
        *raw_wire_out = std::move(matched_raw);
      return extract_rpc_result(*matched);
    }

    auto parsed = parse_json(resp.value().body);
    if (!parsed.has_value() || !is_object(parsed.value())) {
      last_error_detail = "malformed JSON-RPC response from HTTP MCP server";
      return Result<Value>::failure({ErrorCode::corrupt});
    }
    if (raw_wire_out != nullptr)
      *raw_wire_out = resp.value().body;
    return extract_rpc_result(parsed.value());
  }

  Result<void> send_http_notification(std::string_view method, Value params) {
    if (!http_transport)
      return Result<void>::failure({ErrorCode::unsupported});
    Value::Object req_obj;
    req_obj.emplace_back("jsonrpc", Value{"2.0"});
    req_obj.emplace_back("method", Value{std::string{method}});
    req_obj.emplace_back("params", std::move(params));
    const auto dumped = dump_json(Value::object(std::move(req_obj)));
    if (!dumped.has_value())
      return Result<void>::failure(dumped.error());

    const McpHttpRequest http_req = build_http_post(dumped.value());
    auto resp = http_transport(http_req);
    if (!resp.has_value())
      return Result<void>::failure(resp.error());
    if (const auto sid = find_header_value(resp.value().headers, "Mcp-Session-Id");
        sid.has_value() && !sid->empty()) {
      if (!valid_mcp_header_token(*sid, 512U)) {
        last_error_detail = "rejected malformed Mcp-Session-Id header";
        return Result<void>::failure({ErrorCode::corrupt});
      }
      session_id = std::string{*sid};
    }
    if (resp.value().status_code == 401 || resp.value().status_code == 403) {
      if (const auto auth_hdr =
              find_header_value(resp.value().headers, "WWW-Authenticate");
          auth_hdr.has_value()) {
        last_oauth_challenge =
            parse_mcp_www_authenticate(resp.value().status_code, *auth_hdr);
      }
      return Result<void>::failure(
          {ErrorCode::provider_auth, resp.value().status_code});
    }
    if (resp.value().status_code < 200 || resp.value().status_code >= 300) {
      return Result<void>::failure(
          {ErrorCode::provider_transport, resp.value().status_code});
    }
    return Result<void>::success();
  }
};

McpClient::McpClient(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
McpClient::McpClient(McpClient &&) noexcept = default;
McpClient &McpClient::operator=(McpClient &&) noexcept = default;
McpClient::~McpClient() = default;

Result<McpClient> McpClient::connect_stdio(const McpStdioConfig &config) {
  if (config.executable.empty())
    return Result<McpClient>::failure({ErrorCode::invalid_range});
  if (config.max_line_bytes < kMcpMinLineBytes ||
      config.max_line_bytes > kMcpMaxLineBytesLimit) {
    return Result<McpClient>::failure({ErrorCode::invalid_range});
  }

  OwnedFd in_r, in_w, out_r, out_w, err_r, err_w;
  if (auto r = make_cloexec_pipe(in_r, in_w); !r.has_value())
    return Result<McpClient>::failure(r.error());
  if (auto r = make_cloexec_pipe(out_r, out_w); !r.has_value())
    return Result<McpClient>::failure(r.error());
  if (auto r = make_cloexec_pipe(err_r, err_w); !r.has_value())
    return Result<McpClient>::failure(r.error());

  std::vector<std::string> argv_storage;
  argv_storage.reserve(1U + config.arguments.size());
  argv_storage.push_back(config.executable.string());
  for (const std::string &arg : config.arguments)
    argv_storage.push_back(arg);

  std::vector<char *> argv;
  argv.reserve(argv_storage.size() + 1U);
  for (std::string &arg : argv_storage)
    argv.push_back(arg.data());
  argv.push_back(nullptr);

  std::vector<std::string> env_storage = build_mcp_child_env(config);
  std::vector<char *> envp;
  envp.reserve(env_storage.size() + 1U);
  for (std::string &entry : env_storage)
    envp.push_back(entry.data());
  envp.push_back(nullptr);

  posix_spawn_file_actions_t actions{};
  posix_spawnattr_t attr{};
  int rc = ::posix_spawn_file_actions_init(&actions);
  if (rc != 0)
    return Result<McpClient>::failure({ErrorCode::io, rc});

  rc = ::posix_spawnattr_init(&attr);
  if (rc != 0) {
    (void)::posix_spawn_file_actions_destroy(&actions);
    return Result<McpClient>::failure({ErrorCode::io, rc});
  }

  pid_t pid = -1;
  if (rc == 0)
    rc = ::posix_spawn_file_actions_adddup2(&actions, in_r.get(), STDIN_FILENO);
  if (rc == 0)
    rc = ::posix_spawn_file_actions_adddup2(&actions, out_w.get(), STDOUT_FILENO);
  if (rc == 0)
    rc = ::posix_spawn_file_actions_adddup2(&actions, err_w.get(), STDERR_FILENO);
  if (rc == 0 && !config.cwd.empty()) {
#if defined(__APPLE__) && defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) &&    \
    __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 260000
    rc = ::posix_spawn_file_actions_addchdir(&actions, config.cwd.c_str());
#else
    rc = ::posix_spawn_file_actions_addchdir_np(&actions, config.cwd.c_str());
#endif
  }
  if (rc == 0) {
    rc = ::posix_spawnattr_setflags(&attr,
                                    POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK);
  }
  if (rc == 0)
    rc = ::posix_spawnattr_setpgroup(&attr, 0);
  if (rc == 0) {
    sigset_t empty_mask{};
    sigemptyset(&empty_mask);
    rc = ::posix_spawnattr_setsigmask(&attr, &empty_mask);
  }
  if (rc == 0) {
    rc = ::posix_spawnp(&pid, argv[0], &actions, &attr, argv.data(), envp.data());
  }
  (void)::posix_spawnattr_destroy(&attr);
  (void)::posix_spawn_file_actions_destroy(&actions);

  if (rc != 0)
    return Result<McpClient>::failure({ErrorCode::io, rc});

#ifdef F_SETNOSIGPIPE
  (void)::fcntl(in_w.get(), F_SETNOSIGPIPE, 1);
#endif
  if (::fcntl(in_w.get(), F_SETFL, O_NONBLOCK) < 0 ||
      ::fcntl(out_r.get(), F_SETFL, O_NONBLOCK) < 0 ||
      ::fcntl(err_r.get(), F_SETFL, O_NONBLOCK) < 0) {
    const int err = errno;
    (void)::kill(-pid, SIGKILL);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return Result<McpClient>::failure({ErrorCode::io, err});
  }

  auto impl = std::make_unique<Impl>();
  impl->transport = McpTransportKind::stdio;
  impl->open = true;
  impl->child_pid = pid;
  impl->stdin_fd = std::move(in_w);
  impl->stdout_fd = std::move(out_r);
  impl->stderr_fd = std::move(err_r);
  impl->timeouts = config.timeouts;
  impl->max_payload_bytes = config.max_line_bytes;
  impl->notification_observer = config.notification_observer;
  return Result<McpClient>::success(McpClient{std::move(impl)});
}

Result<McpClient> McpClient::connect_http(const McpHttpConfig &config) {
  if (!valid_mcp_endpoint_url(config.endpoint_url) || !config.transport)
    return Result<McpClient>::failure({ErrorCode::invalid_range});
  if (config.max_payload_bytes < kMcpMinLineBytes ||
      config.max_payload_bytes > kMcpMaxLineBytesLimit) {
    return Result<McpClient>::failure({ErrorCode::invalid_range});
  }
  const std::string proto = config.protocol_version.empty()
                                ? std::string{kMcpClientProtocolLatest}
                                : config.protocol_version;
  if (!valid_mcp_header_token(proto, 64U))
    return Result<McpClient>::failure({ErrorCode::invalid_range});
  for (const auto &[k, v] : config.default_headers) {
    if (!valid_mcp_header_name(k) || is_forbidden_mcp_default_header(k) ||
        !valid_mcp_header_value(v)) {
      return Result<McpClient>::failure({ErrorCode::invalid_range});
    }
  }
  auto impl = std::make_unique<Impl>();
  impl->transport = McpTransportKind::streamable_http;
  impl->open = true;
  impl->endpoint_url = config.endpoint_url;
  impl->protocol_requested = proto;
  impl->protocol_negotiated = impl->protocol_requested;
  impl->default_headers = config.default_headers;
  impl->http_transport = config.transport;
  impl->timeouts = config.timeouts;
  impl->max_payload_bytes = config.max_payload_bytes;
  impl->notification_observer = config.notification_observer;
  return Result<McpClient>::success(McpClient{std::move(impl)});
}

McpTransportKind McpClient::transport_kind() const noexcept { return impl_->transport; }
bool McpClient::is_open() const noexcept { return impl_ && impl_->open; }
bool McpClient::is_initialized() const noexcept { return impl_ && impl_->initialized; }
const std::string &McpClient::protocol_version() const noexcept {
  return impl_->protocol_negotiated;
}
const std::string &McpClient::session_id() const noexcept { return impl_->session_id; }
const std::string &McpClient::last_event_id() const noexcept {
  return impl_->last_event_id;
}
const std::string &McpClient::stderr_log() const noexcept { return impl_->stderr_log; }
const std::string &McpClient::last_error_detail() const noexcept {
  return impl_->last_error_detail;
}
const std::optional<McpOAuthChallenge> &
McpClient::last_oauth_challenge() const noexcept {
  return impl_->last_oauth_challenge;
}

Result<void> McpClient::close() {
  if (!impl_)
    return Result<void>::success();
  return impl_->close_transport();
}

Result<Value> McpClient::request_raw(std::string_view method, Value params,
                                     std::string *raw_wire_out) {
  if (!impl_ || !impl_->open)
    return Result<Value>::failure({ErrorCode::stale_handle});
  const std::int64_t id = impl_->next_request_id++;
  if (impl_->transport == McpTransportKind::stdio)
    return impl_->send_stdio_request(id, method, std::move(params), raw_wire_out);
  return impl_->send_http_request(id, method, std::move(params), raw_wire_out);
}

Result<void> McpClient::notify_raw(std::string_view method, Value params) {
  if (!impl_ || !impl_->open)
    return Result<void>::failure({ErrorCode::stale_handle});
  if (impl_->transport == McpTransportKind::stdio)
    return impl_->send_stdio_notification(method, std::move(params));
  return impl_->send_http_notification(method, std::move(params));
}

Result<McpInitializeResult> McpClient::initialize() {
  Value::Object client_info;
  client_info.emplace_back("name", Value{std::string{kMcpClientName}});
  client_info.emplace_back("version", Value{std::string{kMcpClientVersion}});

  Value::Object params;
  params.emplace_back("protocolVersion", Value{impl_->protocol_requested});
  params.emplace_back("capabilities", Value::object({}));
  params.emplace_back("clientInfo", Value::object(std::move(client_info)));

  auto resp = request_raw("initialize", Value::object(std::move(params)));
  if (!resp.has_value())
    return Result<McpInitializeResult>::failure(resp.error());
  if (!is_object(resp.value()))
    return Result<McpInitializeResult>::failure({ErrorCode::corrupt});

  McpInitializeResult out;
  out.protocol_requested = impl_->protocol_requested;
  out.protocol_negotiated = get_string_default(
      resp.value(), DefaultStrField{"protocolVersion", impl_->protocol_requested});
  if (!valid_mcp_header_token(out.protocol_negotiated, 64U)) {
    impl_->last_error_detail = "rejected malformed protocolVersion from MCP server";
    return Result<McpInitializeResult>::failure({ErrorCode::corrupt});
  }
  impl_->protocol_negotiated = out.protocol_negotiated;
  out.instructions = get_string_or(resp.value(), "instructions");
  out.session_id = impl_->session_id;
  if (const Value *caps = resp.value().find("capabilities"); caps != nullptr)
    out.capabilities = *caps;
  if (const Value *si = resp.value().find("serverInfo");
      si != nullptr && is_object(*si)) {
    out.server_name = get_string_or(*si, "name");
    out.server_version = get_string_or(*si, "version");
  }

  auto notified = notify_raw("notifications/initialized", Value::object({}));
  if (!notified.has_value())
    return Result<McpInitializeResult>::failure(notified.error());
  impl_->initialized = true;
  return Result<McpInitializeResult>::success(std::move(out));
}

Result<McpToolListPage> McpClient::list_tools(std::optional<std::string_view> cursor) {
  Value::Object params;
  if (cursor.has_value() && !cursor->empty())
    params.emplace_back("cursor", Value{std::string{*cursor}});

  auto resp = request_raw("tools/list", Value::object(std::move(params)));
  if (!resp.has_value())
    return Result<McpToolListPage>::failure(resp.error());
  if (!is_object(resp.value()))
    return Result<McpToolListPage>::failure({ErrorCode::corrupt});

  McpToolListPage page;
  if (const Value *nc = resp.value().find("nextCursor");
      nc != nullptr && is_string(*nc) && !nc->string().empty()) {
    page.next_cursor = nc->string();
  }
  if (const Value *tools = resp.value().find("tools");
      tools != nullptr && is_array(*tools)) {
    for (const Value &item : tools->array()) {
      if (!is_object(item))
        continue;
      McpToolDescriptor td;
      td.name = get_string_or(item, "name");
      if (td.name.empty())
        continue;
      td.title = get_string_or(item, "title");
      td.description = get_string_or(item, "description");
      if (const Value *schema = item.find("inputSchema"); schema != nullptr)
        td.input_schema = *schema;
      else
        td.input_schema = Value::object({});
      if (const Value *out_schema = item.find("outputSchema"); out_schema != nullptr)
        td.output_schema = *out_schema;
      td.annotations = parse_tool_annotations(item.find("annotations"));
      if (td.title.empty() && !td.annotations.title.empty())
        td.title = td.annotations.title;
      page.tools.push_back(std::move(td));
    }
  }
  return Result<McpToolListPage>::success(std::move(page));
}

Result<std::vector<McpToolDescriptor>> McpClient::list_all_tools() {
  std::vector<McpToolDescriptor> all;
  std::optional<std::string> cursor;
  std::set<std::string> seen_cursors;
  for (std::size_t page_num = 0; page_num < kMcpClientMaxPages; ++page_num) {
    auto page = list_tools(cursor.has_value() ? std::optional<std::string_view>{*cursor}
                                              : std::nullopt);
    if (!page.has_value())
      return Result<std::vector<McpToolDescriptor>>::failure(page.error());
    for (auto &td : page.value().tools)
      all.push_back(std::move(td));
    const auto &next_cursor = page.value().next_cursor;
    if (!next_cursor.has_value())
      break;
    if (!seen_cursors.insert(*next_cursor).second)
      break; // guard against infinite cursor loop
    cursor = *next_cursor;
  }
  return Result<std::vector<McpToolDescriptor>>::success(std::move(all));
}

Result<McpToolCallResult> McpClient::call_tool(std::string_view tool_name,
                                               Value arguments) {
  if (tool_name.empty())
    return Result<McpToolCallResult>::failure({ErrorCode::invalid_range});
  Value::Object params;
  params.emplace_back("name", Value{std::string{tool_name}});
  params.emplace_back("arguments", std::move(arguments));

  std::string raw_wire;
  auto resp = request_raw("tools/call", Value::object(std::move(params)), &raw_wire);
  if (!resp.has_value())
    return Result<McpToolCallResult>::failure(resp.error());
  if (!is_object(resp.value()))
    return Result<McpToolCallResult>::failure({ErrorCode::corrupt});

  McpToolCallResult out;
  out.raw_wire_json = std::move(raw_wire);
  out.is_error = get_opt_bool(resp.value(), "isError").value_or(false);
  if (const Value *sc = resp.value().find("structuredContent"); sc != nullptr)
    out.structured_content = *sc;
  if (const Value *content = resp.value().find("content");
      content != nullptr && is_array(*content)) {
    for (const Value &item : content->array())
      out.content.push_back(parse_content_block(item));
  }
  return Result<McpToolCallResult>::success(std::move(out));
}

Result<McpResourceListPage>
McpClient::list_resources(std::optional<std::string_view> cursor) {
  Value::Object params;
  if (cursor.has_value() && !cursor->empty())
    params.emplace_back("cursor", Value{std::string{*cursor}});

  auto resp = request_raw("resources/list", Value::object(std::move(params)));
  if (!resp.has_value())
    return Result<McpResourceListPage>::failure(resp.error());
  if (!is_object(resp.value()))
    return Result<McpResourceListPage>::failure({ErrorCode::corrupt});

  McpResourceListPage page;
  if (const Value *nc = resp.value().find("nextCursor");
      nc != nullptr && is_string(*nc) && !nc->string().empty()) {
    page.next_cursor = nc->string();
  }
  if (const Value *resources = resp.value().find("resources");
      resources != nullptr && is_array(*resources)) {
    for (const Value &item : resources->array()) {
      if (!is_object(item))
        continue;
      McpResourceDescriptor rd;
      rd.uri = get_string_or(item, "uri");
      if (rd.uri.empty())
        continue;
      rd.name = get_string_or(item, "name");
      rd.title = get_string_or(item, "title");
      rd.description = get_string_or(item, "description");
      rd.mime_type = get_string_or(item, "mimeType");
      page.resources.push_back(std::move(rd));
    }
  }
  return Result<McpResourceListPage>::success(std::move(page));
}

Result<std::vector<McpResourceDescriptor>> McpClient::list_all_resources() {
  std::vector<McpResourceDescriptor> all;
  std::optional<std::string> cursor;
  std::set<std::string> seen_cursors;
  for (std::size_t page_num = 0; page_num < kMcpClientMaxPages; ++page_num) {
    auto page = list_resources(
        cursor.has_value() ? std::optional<std::string_view>{*cursor} : std::nullopt);
    if (!page.has_value())
      return Result<std::vector<McpResourceDescriptor>>::failure(page.error());
    for (auto &rd : page.value().resources)
      all.push_back(std::move(rd));
    const auto &next_cursor = page.value().next_cursor;
    if (!next_cursor.has_value())
      break;
    if (!seen_cursors.insert(*next_cursor).second)
      break;
    cursor = *next_cursor;
  }
  return Result<std::vector<McpResourceDescriptor>>::success(std::move(all));
}

Result<McpResourceReadResult> McpClient::read_resource(std::string_view uri) {
  if (uri.empty())
    return Result<McpResourceReadResult>::failure({ErrorCode::invalid_range});
  Value::Object params;
  params.emplace_back("uri", Value{std::string{uri}});

  std::string raw_wire;
  auto resp =
      request_raw("resources/read", Value::object(std::move(params)), &raw_wire);
  if (!resp.has_value())
    return Result<McpResourceReadResult>::failure(resp.error());
  if (!is_object(resp.value()))
    return Result<McpResourceReadResult>::failure({ErrorCode::corrupt});

  McpResourceReadResult out;
  out.raw_wire_json = std::move(raw_wire);
  if (const Value *contents = resp.value().find("contents");
      contents != nullptr && is_array(*contents)) {
    for (const Value &item : contents->array()) {
      if (!is_object(item))
        continue;
      McpResourceContent rc;
      rc.uri = get_string_default(item, DefaultStrField{"uri", uri});
      rc.mime_type = get_string_or(item, "mimeType");
      rc.text = get_string_or(item, "text");
      rc.blob_base64 = get_string_or(item, "blob");
      out.contents.push_back(std::move(rc));
    }
  }
  return Result<McpResourceReadResult>::success(std::move(out));
}

Result<McpPromptListPage>
McpClient::list_prompts(std::optional<std::string_view> cursor) {
  Value::Object params;
  if (cursor.has_value() && !cursor->empty())
    params.emplace_back("cursor", Value{std::string{*cursor}});

  auto resp = request_raw("prompts/list", Value::object(std::move(params)));
  if (!resp.has_value())
    return Result<McpPromptListPage>::failure(resp.error());
  if (!is_object(resp.value()))
    return Result<McpPromptListPage>::failure({ErrorCode::corrupt});

  McpPromptListPage page;
  if (const Value *nc = resp.value().find("nextCursor");
      nc != nullptr && is_string(*nc) && !nc->string().empty()) {
    page.next_cursor = nc->string();
  }
  if (const Value *prompts = resp.value().find("prompts");
      prompts != nullptr && is_array(*prompts)) {
    for (const Value &item : prompts->array()) {
      if (!is_object(item))
        continue;
      McpPromptDescriptor pd;
      pd.name = get_string_or(item, "name");
      if (pd.name.empty())
        continue;
      pd.title = get_string_or(item, "title");
      pd.description = get_string_or(item, "description");
      if (const Value *args = item.find("arguments");
          args != nullptr && is_array(*args)) {
        for (const Value &a : args->array()) {
          if (!is_object(a))
            continue;
          McpPromptArgument pa;
          pa.name = get_string_or(a, "name");
          pa.description = get_string_or(a, "description");
          pa.required = get_opt_bool(a, "required").value_or(false);
          if (!pa.name.empty())
            pd.arguments.push_back(std::move(pa));
        }
      }
      page.prompts.push_back(std::move(pd));
    }
  }
  return Result<McpPromptListPage>::success(std::move(page));
}

Result<std::vector<McpPromptDescriptor>> McpClient::list_all_prompts() {
  std::vector<McpPromptDescriptor> all;
  std::optional<std::string> cursor;
  std::set<std::string> seen_cursors;
  for (std::size_t page_num = 0; page_num < kMcpClientMaxPages; ++page_num) {
    auto page = list_prompts(
        cursor.has_value() ? std::optional<std::string_view>{*cursor} : std::nullopt);
    if (!page.has_value())
      return Result<std::vector<McpPromptDescriptor>>::failure(page.error());
    for (auto &pd : page.value().prompts)
      all.push_back(std::move(pd));
    const auto &next_cursor = page.value().next_cursor;
    if (!next_cursor.has_value())
      break;
    if (!seen_cursors.insert(*next_cursor).second)
      break;
    cursor = *next_cursor;
  }
  return Result<std::vector<McpPromptDescriptor>>::success(std::move(all));
}

Result<McpPromptGetResult> McpClient::get_prompt(std::string_view prompt_name,
                                                 Value arguments) {
  if (prompt_name.empty())
    return Result<McpPromptGetResult>::failure({ErrorCode::invalid_range});
  Value::Object params;
  params.emplace_back("name", Value{std::string{prompt_name}});
  params.emplace_back("arguments", std::move(arguments));

  std::string raw_wire;
  auto resp = request_raw("prompts/get", Value::object(std::move(params)), &raw_wire);
  if (!resp.has_value())
    return Result<McpPromptGetResult>::failure(resp.error());
  if (!is_object(resp.value()))
    return Result<McpPromptGetResult>::failure({ErrorCode::corrupt});

  McpPromptGetResult out;
  out.raw_wire_json = std::move(raw_wire);
  out.description = get_string_or(resp.value(), "description");
  if (const Value *msgs = resp.value().find("messages");
      msgs != nullptr && is_array(*msgs)) {
    for (const Value &m : msgs->array()) {
      if (!is_object(m))
        continue;
      McpPromptMessage pm;
      pm.role = get_string_default(m, DefaultStrField{"role", "user"});
      if (const Value *content = m.find("content"); content != nullptr)
        pm.content = parse_content_block(*content);
      out.messages.push_back(std::move(pm));
    }
  }
  return Result<McpPromptGetResult>::success(std::move(out));
}

// ---------------------------------------------------------------------------
// Built-in Official Remote MCP Presets
// ---------------------------------------------------------------------------

const std::vector<McpServerPreset> &builtin_mcp_presets() {
  static const std::vector<McpServerPreset> presets = {
      McpServerPreset{
          McpServerId{1},
          "linear",
          "Linear",
          "https://mcp.linear.app/mcp",
          "https://mcp.linear.app/mcp/readonly",
          std::string{kMcpClientProtocolLatest},
          brakes::ToolEffectClass::outbound_network,
          false,
          {},
          "Linear official remote MCP server (issues, projects, cycles, comments).",
      },
      McpServerPreset{
          McpServerId{2},
          "slack",
          "Slack",
          "https://mcp.slack.com/mcp",
          "",
          std::string{kMcpClientProtocolLatest},
          brakes::ToolEffectClass::outbound_network,
          true,
          {},
          "Slack official remote MCP server (channels, search, threads, messaging).",
      },
      McpServerPreset{
          McpServerId{3},
          "notion",
          "Notion",
          "https://mcp.notion.com/mcp",
          "",
          std::string{kMcpClientProtocolLatest},
          brakes::ToolEffectClass::outbound_network,
          false,
          {},
          "Notion official remote MCP server (pages, databases, search, blocks).",
      },
      McpServerPreset{
          McpServerId{4},
          "github",
          "GitHub",
          "https://api.githubcopilot.com/mcp/",
          "https://api.githubcopilot.com/mcp/readonly",
          std::string{kMcpClientProtocolLatest},
          brakes::ToolEffectClass::outbound_network,
          true,
          {},
          "GitHub official remote MCP server (repos, issues, PRs, code search).",
      },
      McpServerPreset{
          McpServerId{5},
          "atlassian",
          "Atlassian (Jira & Confluence)",
          "https://mcp.atlassian.com/v2/mcp",
          "",
          std::string{kMcpClientProtocolLatest},
          brakes::ToolEffectClass::outbound_network,
          false,
          {},
          "Atlassian Rovo MCP v2 server (Jira issues, Confluence pages, search).",
      },
      McpServerPreset{
          McpServerId{6},
          "multiplayer",
          "Multiplayer",
          "https://multiplayer.tech/mcp",
          "",
          std::string{kMcpClientProtocolLatest},
          brakes::ToolEffectClass::outbound_network,
          true,
          {},
          "Multiplayer official remote MCP server (parties, friends, swarm boards).",
      },
  };
  return presets;
}

std::optional<McpServerPreset> find_mcp_preset(std::string_view name) {
  const std::string lower = ascii_lower(name);
  for (const auto &preset : builtin_mcp_presets()) {
    if (preset.name == lower)
      return preset;
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Untrusted ToolAnnotations Classification (Monotonic Tightening Only)
// ---------------------------------------------------------------------------

McpToolEffectClassification
classify_mcp_tool_effect(const McpServerPolicy &server_policy,
                         std::string_view tool_name,
                         const McpToolAnnotations &annotations) noexcept {
  McpToolEffectClassification out;

  // Baseline comes STRICTLY from trusted operator/server policy.
  // readOnlyHint=true from an untrusted MCP server NEVER downgrades this!
  bool explicitly_read_only = false;
  for (const std::string &allowed : server_policy.explicit_read_only_tools) {
    if (allowed == tool_name) {
      explicitly_read_only = true;
      break;
    }
  }
  out.effect_class = explicitly_read_only ? brakes::ToolEffectClass::read_only
                                          : server_policy.default_effect;
  if (out.effect_class == brakes::ToolEffectClass::auto_classify)
    out.effect_class = brakes::ToolEffectClass::outbound_network;

  // openWorldHint=true can only tighten open-world provenance, never clear it.
  out.open_world =
      server_policy.is_open_world || annotations.open_world_hint.value_or(false);

  // destructiveHint=true CAN tighten classification above the server baseline.
  if (annotations.destructive_hint.value_or(false)) {
    out.tightened_by_destructive_hint = true;
    if (out.effect_class == brakes::ToolEffectClass::read_only ||
        out.effect_class == brakes::ToolEffectClass::workspace_write ||
        out.effect_class == brakes::ToolEffectClass::outbound_network) {
      out.effect_class = brakes::ToolEffectClass::exec;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// BM25 Lazy Tool Router + Brakes Taint Gate
// ---------------------------------------------------------------------------

struct McpToolRouter::Impl {
  struct ServerRecord {
    McpServerId server_id{};
    std::string name;
    std::string endpoint_label;
    McpTransportKind transport = McpTransportKind::stdio;
    McpServerPolicy policy{};
    std::optional<McpClient> client;
    std::vector<McpToolId> tool_ids;
    std::vector<McpResourceDescriptor> resources;
    std::vector<McpPromptDescriptor> prompts;
  };

  struct ToolRecord {
    McpToolId tool_id{};
    McpServerId server_id{};
    std::string server_name;
    McpToolDescriptor descriptor;
    McpToolEffectClassification effect{};
    std::map<std::string, double> weighted_tf;
    double doc_length = 0.0;
    std::string lower_tool_name;
    std::string lower_server_name;
  };

  brakes::BrakesGate brakes_gate;
  ToolProjectionPolicy default_projection;
  AuditLog *audit_log = nullptr;
  std::uint64_t next_server_id = 1;
  std::uint64_t next_tool_id = 1;
  std::uint64_t next_audit_seq = 1;

  // Primary keys are strictly integer IDs (McpServerId / McpToolId).
  std::map<McpServerId, ServerRecord> servers;
  std::map<McpToolId, ToolRecord> tools;

  // Secondary lookup indexes from name -> integer PK.
  std::map<std::string, McpServerId, std::less<>> server_name_index;
  std::map<std::pair<McpServerId, std::string>, McpToolId> tool_name_index;

  // BM25 corpus statistics rebuilt on catalog mutation.
  std::map<std::string, std::size_t, std::less<>> doc_freq;
  double avg_doc_length = 1.0;

  explicit Impl(McpRouterConfig config)
      : brakes_gate(std::move(config.brakes_policy)),
        default_projection(config.default_projection), audit_log(config.audit_log) {}

  void rebuild_bm25_stats() {
    doc_freq.clear();
    double total_len = 0.0;
    for (const auto &[tid, rec] : tools) {
      (void)tid;
      total_len += rec.doc_length;
      for (const auto &[term, tf] : rec.weighted_tf) {
        (void)tf;
        ++doc_freq[term];
      }
    }
    avg_doc_length = tools.empty()
                         ? 1.0
                         : std::max(1.0, total_len / static_cast<double>(tools.size()));
  }

  void index_server_tools(ServerRecord &server,
                          const std::vector<McpToolDescriptor> &descriptors) {
    // Remove previous tools for this server.
    for (const McpToolId tid : server.tool_ids) {
      if (const auto it = tools.find(tid); it != tools.end()) {
        tool_name_index.erase({server.server_id, it->second.descriptor.name});
        tools.erase(it);
      }
    }
    server.tool_ids.clear();

    for (const auto &td : descriptors) {
      const McpToolId tid{next_tool_id++};
      ToolRecord rec;
      rec.tool_id = tid;
      rec.server_id = server.server_id;
      rec.server_name = server.name;
      rec.descriptor = td;
      rec.effect = classify_mcp_tool_effect(server.policy, td.name, td.annotations);
      rec.lower_tool_name = ascii_lower(td.name);
      rec.lower_server_name = ascii_lower(server.name);

      auto add_field = [&](std::string_view text, double weight) {
        for (const std::string &tok : tokenize_for_bm25(text)) {
          rec.weighted_tf[tok] += weight;
          rec.doc_length += weight;
        }
      };
      add_field(td.name, 3.0);
      add_field(td.title, 2.5);
      add_field(server.name, 2.0);
      add_field(td.description, 1.0);

      server.tool_ids.push_back(tid);
      tool_name_index[{server.server_id, td.name}] = tid;
      tools.emplace(tid, std::move(rec));
    }
    rebuild_bm25_stats();
  }

  Result<std::pair<std::string, std::string>>
  frame_and_taint(const ServerRecord &server, std::string_view sender_label,
                  std::string_view raw_payload, bool open_world,
                  const ToolProjectionPolicy &proj_policy,
                  ToolProjectionResult &projection_out) {
    const std::uint64_t audit_id = next_audit_seq++;
    std::string audit_ref;
    if (audit_log != nullptr) {
      Value::Object meta;
      meta.emplace_back("server", Value{server.name});
      meta.emplace_back("sender", Value{std::string{sender_label}});
      audit_ref = audit_log->original(
          OriginalCapture{"mcp.call.raw", raw_payload, Value::object(std::move(meta))});
    }

    projection_out = project_tool_output_for_context(
        ToolProjectionInput{
            "mcp:" + server.name + "/" + std::string{sender_label},
            std::string{raw_payload},
            std::nullopt,
            audit_id,
        },
        proj_policy);

    brakes::PeerProvenance prov;
    prov.origin = brakes::PeerOriginKind::external_mcp;
    prov.safety_number =
        server.policy.safety_number.empty()
            ? ("mcp:" + server.name +
               (server.endpoint_label.empty() ? "" : ":" + server.endpoint_label))
            : server.policy.safety_number;
    prov.is_external_guest = open_world;
    prov.effective_trust = server.policy.trust_profile;

    auto framed = brakes::format_untrusted_peer_envelope(
        prov, brakes::RoomScopeRef{"mcp/" + server.name},
        brakes::SenderRef{sender_label},
        brakes::MessageBodyRef{projection_out.projected_text});
    if (!framed.has_value())
      return Result<std::pair<std::string, std::string>>::failure(framed.error());

    // Immutable C++ turn taint latch!
    (void)brakes_gate.ingest_peer(prov);
    return Result<std::pair<std::string, std::string>>::success(
        {std::move(framed.value()), std::move(audit_ref)});
  }
};

McpToolRouter::McpToolRouter(McpRouterConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}
McpToolRouter::McpToolRouter(McpToolRouter &&) noexcept = default;
McpToolRouter &McpToolRouter::operator=(McpToolRouter &&) noexcept = default;
McpToolRouter::~McpToolRouter() = default;

Result<McpServerId> McpToolRouter::add_server(std::string_view server_name,
                                              McpClient client, McpServerPolicy policy,
                                              std::string_view endpoint_label) {
  if (server_name.empty())
    return Result<McpServerId>::failure({ErrorCode::invalid_range});
  if (impl_->server_name_index.contains(server_name))
    return Result<McpServerId>::failure({ErrorCode::conflict});

  if (!client.is_initialized()) {
    auto init = client.initialize();
    if (!init.has_value())
      return Result<McpServerId>::failure(init.error());
  }

  auto tools = client.list_all_tools();
  if (!tools.has_value())
    return Result<McpServerId>::failure(tools.error());

  std::vector<McpResourceDescriptor> resources;
  if (auto r = client.list_all_resources(); r.has_value())
    resources = std::move(r.value());

  std::vector<McpPromptDescriptor> prompts;
  if (auto p = client.list_all_prompts(); p.has_value())
    prompts = std::move(p.value());

  const McpServerId sid{impl_->next_server_id++};
  Impl::ServerRecord rec;
  rec.server_id = sid;
  rec.name = std::string{server_name};
  rec.endpoint_label = std::string{endpoint_label};
  rec.transport = client.transport_kind();
  rec.policy = std::move(policy);
  rec.client = std::move(client);
  rec.resources = std::move(resources);
  rec.prompts = std::move(prompts);

  auto [it, inserted] = impl_->servers.emplace(sid, std::move(rec));
  (void)inserted;
  impl_->server_name_index.emplace(it->second.name, sid);
  impl_->index_server_tools(it->second, tools.value());
  return Result<McpServerId>::success(sid);
}

Result<McpServerId> McpToolRouter::add_catalog_snapshot(
    std::string_view server_name, const std::vector<McpToolDescriptor> &tools,
    McpServerPolicy policy, std::string_view endpoint_label) {
  if (server_name.empty())
    return Result<McpServerId>::failure({ErrorCode::invalid_range});
  if (impl_->server_name_index.contains(server_name))
    return Result<McpServerId>::failure({ErrorCode::conflict});

  const McpServerId sid{impl_->next_server_id++};
  Impl::ServerRecord rec;
  rec.server_id = sid;
  rec.name = std::string{server_name};
  rec.endpoint_label = std::string{endpoint_label};
  rec.transport = McpTransportKind::streamable_http;
  rec.policy = std::move(policy);

  auto [it, inserted] = impl_->servers.emplace(sid, std::move(rec));
  (void)inserted;
  impl_->server_name_index.emplace(it->second.name, sid);
  impl_->index_server_tools(it->second, tools);
  return Result<McpServerId>::success(sid);
}

Result<void> McpToolRouter::refresh_server(McpServerId server_id) {
  const auto it = impl_->servers.find(server_id);
  if (it == impl_->servers.end())
    return Result<void>::failure({ErrorCode::stale_handle});
  if (!it->second.client.has_value())
    return Result<void>::failure({ErrorCode::unsupported});

  auto tools = it->second.client->list_all_tools();
  if (!tools.has_value())
    return Result<void>::failure(tools.error());
  if (auto r = it->second.client->list_all_resources(); r.has_value())
    it->second.resources = std::move(r.value());
  if (auto p = it->second.client->list_all_prompts(); p.has_value())
    it->second.prompts = std::move(p.value());
  impl_->index_server_tools(it->second, tools.value());
  return Result<void>::success();
}

Result<void> McpToolRouter::remove_server(McpServerId server_id) {
  const auto it = impl_->servers.find(server_id);
  if (it == impl_->servers.end())
    return Result<void>::failure({ErrorCode::stale_handle});
  for (const McpToolId tid : it->second.tool_ids) {
    if (const auto tit = impl_->tools.find(tid); tit != impl_->tools.end()) {
      impl_->tool_name_index.erase({server_id, tit->second.descriptor.name});
      impl_->tools.erase(tit);
    }
  }
  impl_->server_name_index.erase(it->second.name);
  impl_->servers.erase(it);
  impl_->rebuild_bm25_stats();
  return Result<void>::success();
}

std::optional<McpServerId>
McpToolRouter::find_server_id(std::string_view server_name) const {
  if (const auto it = impl_->server_name_index.find(server_name);
      it != impl_->server_name_index.end()) {
    return it->second;
  }
  return std::nullopt;
}

std::optional<McpToolId> McpToolRouter::find_tool_id(McpServerId server_id,
                                                     std::string_view tool_name) const {
  const auto it = impl_->tool_name_index.find({server_id, std::string{tool_name}});
  if (it != impl_->tool_name_index.end())
    return it->second;
  return std::nullopt;
}

std::vector<McpRegisteredServerInfo> McpToolRouter::list_servers() const {
  std::vector<McpRegisteredServerInfo> out;
  out.reserve(impl_->servers.size());
  for (const auto &[sid, rec] : impl_->servers) {
    out.push_back(McpRegisteredServerInfo{
        sid,
        rec.name,
        rec.endpoint_label,
        rec.transport,
        rec.tool_ids.size(),
        rec.resources.size(),
        rec.prompts.size(),
        rec.policy,
    });
  }
  return out;
}

std::string McpToolRouter::manifest_summary() const {
  if (impl_->servers.empty())
    return "Connected MCP servers: (none)";
  std::string out = "Connected MCP servers:";
  for (const auto &[sid, rec] : impl_->servers) {
    (void)sid;
    out.append("\n- ");
    out.append(rec.name);
    out.append(" (");
    out.append(std::to_string(rec.tool_ids.size()));
    out.append(" tools, ");
    out.append(std::to_string(rec.resources.size()));
    out.append(" resources, ");
    out.append(std::to_string(rec.prompts.size()));
    out.append(" prompts)");
  }
  return out;
}

std::vector<McpSearchHit> McpToolRouter::mcp_search(const McpSearchQuery &query) const {
  const std::size_t limit = std::clamp<std::size_t>(
      query.limit == 0U ? kMcpClientDefaultSearchLimit : query.limit, 1U,
      kMcpClientMaxSearchLimit);

  std::optional<McpServerId> filter_server;
  if (query.server_name.has_value() && !query.server_name->empty()) {
    filter_server = find_server_id(*query.server_name);
    if (!filter_server.has_value())
      return {};
  }

  const std::vector<std::string> q_tokens = tokenize_for_bm25(query.query);
  const std::string lower_query = ascii_lower(query.query);
  const double corpus_size = static_cast<double>(impl_->tools.size());
  constexpr double kK1 = 1.5;
  constexpr double kB = 0.75;

  std::vector<McpSearchHit> hits;
  for (const auto &[tid, rec] : impl_->tools) {
    if (filter_server.has_value() && rec.server_id != *filter_server)
      continue;

    double score = 0.0;
    if (q_tokens.empty()) {
      score = 1.0;
    } else {
      for (const std::string &tok : q_tokens) {
        const auto tf_it = rec.weighted_tf.find(tok);
        if (tf_it == rec.weighted_tf.end())
          continue;
        const auto df_it = impl_->doc_freq.find(tok);
        const double df =
            df_it != impl_->doc_freq.end() ? static_cast<double>(df_it->second) : 0.0;
        const double idf = std::log(((corpus_size - df + 0.5) / (df + 0.5)) + 1.0);
        const double tf = tf_it->second;
        const double norm =
            tf * (kK1 + 1.0) /
            (tf + kK1 * (1.0 - kB + kB * (rec.doc_length / impl_->avg_doc_length)));
        score += idf * norm;
      }
      if (!lower_query.empty()) {
        if (rec.lower_tool_name == lower_query)
          score += 10.0;
        else if (rec.lower_tool_name.find(lower_query) != std::string::npos)
          score += 3.0;
      }
      if (score <= 0.0)
        continue;
    }

    hits.push_back(McpSearchHit{
        rec.server_id,
        tid,
        rec.server_name,
        rec.descriptor.name,
        rec.descriptor.title,
        rec.descriptor.description,
        score,
        rec.descriptor.input_schema,
        rec.descriptor.annotations,
        rec.effect,
    });
  }

  std::ranges::sort(hits, [](const McpSearchHit &a, const McpSearchHit &b) {
    if (a.bm25_score != b.bm25_score)
      return a.bm25_score > b.bm25_score;
    if (a.server_id != b.server_id)
      return a.server_id < b.server_id;
    return a.tool_id < b.tool_id;
  });

  if (hits.size() > limit)
    hits.resize(limit);
  return hits;
}

Result<McpCallOutcome> McpToolRouter::mcp_call(const McpCallParams &params) {
  const auto sid = find_server_id(params.server_name);
  if (!sid.has_value())
    return Result<McpCallOutcome>::failure({ErrorCode::invalid_identity});
  const auto sit = impl_->servers.find(*sid);
  if (sit == impl_->servers.end())
    return Result<McpCallOutcome>::failure({ErrorCode::stale_handle});
  auto &client_opt = sit->second.client;
  if (!client_opt.has_value())
    return Result<McpCallOutcome>::failure({ErrorCode::stale_handle});
  McpClient &client = *client_opt;

  const auto tid = find_tool_id(*sid, params.tool_name);
  McpToolAnnotations annotations;
  if (tid.has_value()) {
    if (const auto tit = impl_->tools.find(*tid); tit != impl_->tools.end())
      annotations = tit->second.descriptor.annotations;
  }

  const McpToolEffectClassification effect =
      classify_mcp_tool_effect(sit->second.policy, params.tool_name, annotations);

  brakes::ToolCallRequest gate_req;
  gate_req.tool_name = "mcp_call:" + sit->second.name + "." + params.tool_name;
  gate_req.tool_op = params.tool_name;
  gate_req.effect_class = effect.effect_class;
  gate_req.requires_network =
      (sit->second.transport == McpTransportKind::streamable_http ||
       effect.effect_class == brakes::ToolEffectClass::outbound_network ||
       effect.open_world);

  const brakes::BrakesDecision decision =
      impl_->brakes_gate.evaluate_tool_call(gate_req);
  if (!decision.allow) {
    McpCallOutcome blocked;
    blocked.server_id = *sid;
    blocked.tool_id = tid.value_or(McpToolId{});
    blocked.blocked_by_brakes = true;
    blocked.brakes_decision = decision;
    blocked.effect = effect;
    return Result<McpCallOutcome>::success(std::move(blocked));
  }

  auto called = client.call_tool(params.tool_name, params.arguments);
  if (!called.has_value())
    return Result<McpCallOutcome>::failure(called.error());

  const std::string raw_text = render_tool_result_text(called.value());
  const ToolProjectionPolicy proj_policy =
      params.projection_policy.value_or(impl_->default_projection);

  McpCallOutcome out;
  out.server_id = *sid;
  out.tool_id = tid.value_or(McpToolId{});
  out.blocked_by_brakes = false;
  out.brakes_decision = decision;
  out.is_error = called.value().is_error;
  out.raw_payload = raw_text;
  out.effect = effect;

  auto framed = impl_->frame_and_taint(sit->second, params.tool_name, raw_text,
                                       effect.open_world, proj_policy, out.projection);
  if (!framed.has_value())
    return Result<McpCallOutcome>::failure(framed.error());
  out.framed_output = std::move(framed.value().first);
  out.audit_ref = std::move(framed.value().second);
  return Result<McpCallOutcome>::success(std::move(out));
}

Result<McpResourceOutcome>
McpToolRouter::mcp_resource(const McpResourceParams &params) {
  const auto sid = find_server_id(params.server_name);
  if (!sid.has_value())
    return Result<McpResourceOutcome>::failure({ErrorCode::invalid_identity});
  const auto sit = impl_->servers.find(*sid);
  if (sit == impl_->servers.end())
    return Result<McpResourceOutcome>::failure({ErrorCode::stale_handle});
  auto &client_opt = sit->second.client;
  if (!client_opt.has_value())
    return Result<McpResourceOutcome>::failure({ErrorCode::stale_handle});
  McpClient &client = *client_opt;

  McpResourceOutcome out;
  out.server_id = *sid;

  if (params.op == McpResourceOp::list) {
    if (sit->second.transport == McpTransportKind::streamable_http) {
      brakes::ToolCallRequest gate_req;
      gate_req.tool_name = "mcp_resource:" + sit->second.name;
      gate_req.tool_op = "list";
      gate_req.effect_class = brakes::ToolEffectClass::read_only;
      gate_req.requires_network = true;
      const brakes::BrakesDecision decision =
          impl_->brakes_gate.evaluate_tool_call(gate_req);
      if (!decision.allow) {
        out.blocked_by_brakes = true;
        out.brakes_decision = decision;
        return Result<McpResourceOutcome>::success(std::move(out));
      }
      out.brakes_decision = decision;
    }
    auto listed = client.list_all_resources();
    if (!listed.has_value())
      return Result<McpResourceOutcome>::failure(listed.error());
    sit->second.resources = listed.value();
    out.resources = std::move(listed.value());
    return Result<McpResourceOutcome>::success(std::move(out));
  }

  brakes::ToolCallRequest gate_req;
  gate_req.tool_name = "mcp_resource:" + sit->second.name;
  gate_req.tool_op = "read";
  gate_req.effect_class = brakes::ToolEffectClass::read_only;
  gate_req.requires_network =
      (sit->second.transport == McpTransportKind::streamable_http);
  const brakes::BrakesDecision decision =
      impl_->brakes_gate.evaluate_tool_call(gate_req);
  if (!decision.allow) {
    out.blocked_by_brakes = true;
    out.brakes_decision = decision;
    return Result<McpResourceOutcome>::success(std::move(out));
  }

  auto read_res = client.read_resource(params.uri);
  if (!read_res.has_value())
    return Result<McpResourceOutcome>::failure(read_res.error());

  const std::string raw_text = render_resource_read_text(read_res.value());
  const ToolProjectionPolicy proj_policy =
      params.projection_policy.value_or(impl_->default_projection);

  out.brakes_decision = decision;
  out.raw_payload = raw_text;

  auto framed = impl_->frame_and_taint(sit->second, params.uri, raw_text,
                                       sit->second.policy.is_open_world, proj_policy,
                                       out.projection);
  if (!framed.has_value())
    return Result<McpResourceOutcome>::failure(framed.error());
  out.framed_output = std::move(framed.value().first);
  out.audit_ref = std::move(framed.value().second);
  return Result<McpResourceOutcome>::success(std::move(out));
}

Result<McpPromptOutcome> McpToolRouter::mcp_prompt(const McpPromptParams &params) {
  const auto sid = find_server_id(params.server_name);
  if (!sid.has_value())
    return Result<McpPromptOutcome>::failure({ErrorCode::invalid_identity});
  const auto sit = impl_->servers.find(*sid);
  if (sit == impl_->servers.end())
    return Result<McpPromptOutcome>::failure({ErrorCode::stale_handle});
  auto &client_opt = sit->second.client;
  if (!client_opt.has_value())
    return Result<McpPromptOutcome>::failure({ErrorCode::stale_handle});
  McpClient &client = *client_opt;

  McpPromptOutcome out;
  out.server_id = *sid;
  if (params.op == McpPromptOp::list) {
    if (sit->second.transport == McpTransportKind::streamable_http) {
      brakes::ToolCallRequest gate_req;
      gate_req.tool_name = "mcp_prompt:" + sit->second.name;
      gate_req.tool_op = "list";
      gate_req.effect_class = brakes::ToolEffectClass::read_only;
      gate_req.requires_network = true;
      const brakes::BrakesDecision decision =
          impl_->brakes_gate.evaluate_tool_call(gate_req);
      if (!decision.allow) {
        out.blocked_by_brakes = true;
        out.brakes_decision = decision;
        return Result<McpPromptOutcome>::success(std::move(out));
      }
      out.brakes_decision = decision;
    }
    auto listed = client.list_all_prompts();
    if (!listed.has_value())
      return Result<McpPromptOutcome>::failure(listed.error());
    sit->second.prompts = listed.value();
    out.prompts = std::move(listed.value());
    return Result<McpPromptOutcome>::success(std::move(out));
  }

  brakes::ToolCallRequest gate_req;
  gate_req.tool_name = "mcp_prompt:" + sit->second.name;
  gate_req.tool_op = "get:" + params.prompt_name;
  gate_req.effect_class = brakes::ToolEffectClass::read_only;
  gate_req.requires_network =
      (sit->second.transport == McpTransportKind::streamable_http);
  const brakes::BrakesDecision decision =
      impl_->brakes_gate.evaluate_tool_call(gate_req);
  if (!decision.allow) {
    out.blocked_by_brakes = true;
    out.brakes_decision = decision;
    return Result<McpPromptOutcome>::success(std::move(out));
  }

  auto prompt_res = client.get_prompt(params.prompt_name, params.arguments);
  if (!prompt_res.has_value())
    return Result<McpPromptOutcome>::failure(prompt_res.error());

  std::string raw_text;
  if (!prompt_res.value().description.empty()) {
    raw_text.append("# ");
    raw_text.append(prompt_res.value().description);
  }
  for (const auto &msg : prompt_res.value().messages) {
    if (!raw_text.empty())
      raw_text.push_back('\n');
    raw_text.append("[");
    raw_text.append(msg.role);
    raw_text.append("] ");
    if (!msg.content.text.empty())
      raw_text.append(msg.content.text);
    else if (!msg.content.uri.empty())
      raw_text.append(msg.content.uri);
  }
  if (raw_text.empty())
    raw_text = prompt_res.value().raw_wire_json;

  const ToolProjectionPolicy proj_policy =
      params.projection_policy.value_or(impl_->default_projection);

  out.brakes_decision = decision;
  out.raw_payload = raw_text;
  out.prompt_result = std::move(prompt_res.value());

  auto framed = impl_->frame_and_taint(sit->second, "prompt:" + params.prompt_name,
                                       raw_text, sit->second.policy.is_open_world,
                                       proj_policy, out.projection);
  if (!framed.has_value())
    return Result<McpPromptOutcome>::failure(framed.error());
  out.framed_output = std::move(framed.value().first);
  out.audit_ref = std::move(framed.value().second);
  return Result<McpPromptOutcome>::success(std::move(out));
}

const brakes::BrakesGate &McpToolRouter::brakes_gate() const noexcept {
  return impl_->brakes_gate;
}
brakes::BrakesGate &McpToolRouter::mutable_brakes_gate() noexcept {
  return impl_->brakes_gate;
}

} // namespace blackbird
