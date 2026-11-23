#include "blackbird/net_http.hpp"

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

using namespace blackbird;
using namespace blackbird::net;

void require_ok(bool ok, std::source_location loc = std::source_location::current()) {
  if (!ok) {
    std::cerr << "net_http_test FAIL at " << loc.file_name() << ":" << loc.line()
              << "\n";
    std::abort();
  }
}

struct TempDir {
  std::filesystem::path path;
  explicit TempDir(std::string_view tag) {
    static std::atomic<std::uint64_t> counter{0U};
    const auto id = counter.fetch_add(1U, std::memory_order_relaxed);
    path = std::filesystem::temp_directory_path() /
           ("bb_net_http_test_" + std::string{tag} + "_" +
            std::to_string(static_cast<std::uint64_t>(::getpid())) + "_" +
            std::to_string(id));
    std::filesystem::create_directories(path);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

struct EphemeralCert {
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{nullptr, &EVP_PKEY_free};
  std::unique_ptr<X509, decltype(&X509_free)> cert{nullptr, &X509_free};
  std::filesystem::path pem_path;
};

EphemeralCert generate_self_signed_cert(const std::filesystem::path &out_pem,
                                        const char *san_ext) {
  EphemeralCert out;
  out.pem_path = out_pem;

  EVP_PKEY *raw_key = EVP_EC_gen("P-256");
  require_ok(raw_key != nullptr);
  out.key.reset(raw_key);

  X509 *raw_cert = X509_new();
  require_ok(raw_cert != nullptr);
  out.cert.reset(raw_cert);

  require_ok(X509_set_version(raw_cert, 2L) == 1);
  require_ok(ASN1_INTEGER_set(X509_get_serialNumber(raw_cert), 1L) == 1);
  require_ok(X509_gmtime_adj(X509_getm_notBefore(raw_cert), -3600L) != nullptr);
  require_ok(X509_gmtime_adj(X509_getm_notAfter(raw_cert), 86400L) != nullptr);
  require_ok(X509_set_pubkey(raw_cert, raw_key) == 1);

  X509_NAME *name = X509_get_subject_name(raw_cert);
  require_ok(name != nullptr);
  require_ok(X509_NAME_add_entry_by_txt(
                 name, "CN", MBSTRING_ASC,
                 reinterpret_cast<const unsigned char *>("api.blackbird.test"), -1, -1,
                 0) == 1);
  require_ok(X509_set_issuer_name(raw_cert, name) == 1);

  X509V3_CTX v3ctx{};
  X509V3_set_ctx_nodb(&v3ctx);
  X509V3_set_ctx(&v3ctx, raw_cert, raw_cert, nullptr, nullptr, 0);

  auto add_ext = [&](int nid, const char *val) {
    X509_EXTENSION *ext =
        X509V3_EXT_conf_nid(nullptr, &v3ctx, nid, const_cast<char *>(val));
    require_ok(ext != nullptr);
    require_ok(X509_add_ext(raw_cert, ext, -1) == 1);
    X509_EXTENSION_free(ext);
  };
  add_ext(NID_basic_constraints, "critical,CA:TRUE");
  add_ext(NID_key_usage, "critical,digitalSignature,keyCertSign");
  add_ext(NID_subject_alt_name, san_ext);

  require_ok(X509_sign(raw_cert, raw_key, EVP_sha256()) != 0);

  FILE *fp = std::fopen(out_pem.c_str(), "wb");
  require_ok(fp != nullptr);
  require_ok(PEM_write_X509(fp, raw_cert) == 1);
  require_ok(std::fclose(fp) == 0);
  return out;
}

struct ServerHttpRequest {
  std::string method;
  std::string target;
  std::map<std::string, std::string> headers;
  std::string body;
};

std::string lower_ascii(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (const char c : s) {
    out.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c);
  }
  return out;
}

void ssl_write_str(SSL *ssl, std::string_view data) {
  std::size_t off = 0U;
  while (off < data.size()) {
    const int n =
        SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
    if (n <= 0) {
      break;
    }
    off += static_cast<std::size_t>(n);
  }
}

void ssl_write_byte_by_byte(SSL *ssl, std::string_view data) {
  for (const char ch : data) {
    if (SSL_write(ssl, &ch, 1) <= 0) {
      break;
    }
  }
}

std::optional<ServerHttpRequest> read_server_request(SSL *ssl) {
  std::string raw;
  std::array<char, 2048> buf{};
  std::size_t header_end = std::string::npos;
  while (header_end == std::string::npos && raw.size() < 65536U) {
    const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
    if (n <= 0) {
      return std::nullopt;
    }
    raw.append(buf.data(), static_cast<std::size_t>(n));
    header_end = raw.find("\r\n\r\n");
  }
  if (header_end == std::string::npos) {
    return std::nullopt;
  }

  ServerHttpRequest req{};
  const std::string_view header_block{raw.data(), header_end};
  const std::size_t first_eol = header_block.find("\r\n");
  const std::string_view req_line = (first_eol == std::string_view::npos)
                                        ? header_block
                                        : header_block.substr(0U, first_eol);
  const std::size_t sp1 = req_line.find(' ');
  const std::size_t sp2 = (sp1 == std::string_view::npos)
                              ? std::string_view::npos
                              : req_line.find(' ', sp1 + 1U);
  if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
    return std::nullopt;
  }
  req.method = std::string{req_line.substr(0U, sp1)};
  req.target = std::string{req_line.substr(sp1 + 1U, sp2 - sp1 - 1U)};

  std::size_t content_length = 0U;
  if (first_eol != std::string_view::npos) {
    std::size_t pos = first_eol + 2U;
    while (pos < header_block.size()) {
      const std::size_t eol = header_block.find("\r\n", pos);
      const std::string_view line = (eol == std::string_view::npos)
                                        ? header_block.substr(pos)
                                        : header_block.substr(pos, eol - pos);
      const std::size_t colon = line.find(':');
      if (colon != std::string_view::npos) {
        const std::string k = lower_ascii(line.substr(0U, colon));
        std::string_view v = line.substr(colon + 1U);
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) {
          v.remove_prefix(1U);
        }
        req.headers[k] = std::string{v};
        if (k == "content-length") {
          content_length = static_cast<std::size_t>(
              std::strtoull(req.headers[k].c_str(), nullptr, 10));
        }
      }
      if (eol == std::string_view::npos) {
        break;
      }
      pos = eol + 2U;
    }
  }

  req.body = raw.substr(header_end + 4U);
  while (req.body.size() < content_length) {
    const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
    if (n <= 0) {
      break;
    }
    req.body.append(buf.data(), static_cast<std::size_t>(n));
  }
  if (req.body.size() > content_length) {
    req.body.resize(content_length);
  }
  return req;
}

class LoopbackTlsServer {
public:
  using Handler = std::function<void(SSL *, const ServerHttpRequest &)>;

  LoopbackTlsServer(const EphemeralCert &cert, Handler handler)
      : handler_(std::move(handler)) {
    ctx_.reset(SSL_CTX_new(TLS_server_method()));
    require_ok(ctx_ != nullptr);
    require_ok(SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_2_VERSION) == 1);
    require_ok(SSL_CTX_use_certificate(ctx_.get(), cert.cert.get()) == 1);
    require_ok(SSL_CTX_use_PrivateKey(ctx_.get(), cert.key.get()) == 1);

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    require_ok(listen_fd_ >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0U;
    require_ok(::bind(listen_fd_, reinterpret_cast<const sockaddr *>(&addr),
                      sizeof(addr)) == 0);
    require_ok(::listen(listen_fd_, 16) == 0);
    socklen_t len = sizeof(addr);
    require_ok(::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len) ==
               0);
    port_ = ntohs(addr.sin_port);

    thread_ = std::thread([this]() { run(); });
  }

  ~LoopbackTlsServer() {
    stop_.store(true, std::memory_order_relaxed);
    if (listen_fd_ >= 0) {
      ::shutdown(listen_fd_, SHUT_RDWR);
      ::close(listen_fd_);
      listen_fd_ = -1;
    }
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  std::uint16_t port() const noexcept { return port_; }

private:
  void run() {
    while (!stop_.load(std::memory_order_relaxed)) {
      pollfd pfd{listen_fd_, POLLIN, 0};
      const int rc = ::poll(&pfd, 1U, 50);
      if (rc <= 0) {
        continue;
      }
      const int client_fd = ::accept(listen_fd_, nullptr, nullptr);
      if (client_fd < 0) {
        continue;
      }
#ifdef SO_NOSIGPIPE
      const int one = 1;
      (void)::setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
      std::unique_ptr<SSL, decltype(&SSL_free)> ssl{SSL_new(ctx_.get()), &SSL_free};
      if (ssl && SSL_set_fd(ssl.get(), client_fd) == 1 && SSL_accept(ssl.get()) == 1) {
        if (const auto req = read_server_request(ssl.get()); req.has_value()) {
          handler_(ssl.get(), *req);
        }
        (void)SSL_shutdown(ssl.get());
      }
      ::close(client_fd);
    }
  }

  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx_{nullptr, &SSL_CTX_free};
  Handler handler_;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0U;
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

HttpClientConfig make_test_client_config(const std::filesystem::path &ca_pem,
                                         std::uint16_t port,
                                         std::vector<std::string> allowed_hosts) {
  HttpClientConfig cfg{};
  cfg.host_policy = AllowedHostPolicy::pinned(std::move(allowed_hosts));
  cfg.host_policy.allow_loopback = true;
  cfg.ca_bundle_path = ca_pem;
  cfg.connect_host_override = "127.0.0.1";
  cfg.connect_port_override = port;
  return cfg;
}

void test_url_and_ssrf_policy() {
  const auto parsed = parse_url("HTTPS://API.Example.COM:8443/v1/items?limit=10");
  require_ok(parsed.has_value());
  require_ok(parsed.value().scheme == "https");
  require_ok(parsed.value().host == "api.example.com");
  require_ok(parsed.value().port == 8443U);
  require_ok(parsed.value().path == "/v1/items");
  require_ok(parsed.value().query == "limit=10");
  require_ok(parsed.value().request_target() == "/v1/items?limit=10");

  // Reject userinfo, bad schemes, control chars, fragments.
  require_ok(!parse_url("https://user:pass@api.example.com/").has_value());
  require_ok(!parse_url("file:///etc/passwd").has_value());
  require_ok(!parse_url("https://api.example.com/a\r\nb").has_value());
  require_ok(!parse_url("https://api.example.com/a#frag").has_value());

  // SSRF literal checks.
  require_ok(is_loopback_ip_literal("127.0.0.1"));
  require_ok(is_loopback_ip_literal("::1"));
  require_ok(is_loopback_ip_literal("::ffff:127.0.0.1"));
  require_ok(is_private_or_special_ip_literal("10.0.0.1"));
  require_ok(is_private_or_special_ip_literal("172.16.0.1"));
  require_ok(is_private_or_special_ip_literal("192.168.1.1"));
  require_ok(is_private_or_special_ip_literal("169.254.169.254"));
  require_ok(is_private_or_special_ip_literal("::ffff:169.254.169.254"));
  require_ok(is_private_or_special_ip_literal("fc00::1"));
  require_ok(is_private_or_special_ip_literal("fe80::1"));
  require_ok(!is_private_or_special_ip_literal("1.1.1.1"));
  require_ok(!is_private_or_special_ip_literal("93.184.216.34"));

  // Default any_public_https blocks loopback, localhost, and cloud metadata.
  const auto pub = AllowedHostPolicy::any_public_https();
  require_ok(
      net_error_of(pub.validate_url(parse_url("https://127.0.0.1/").value()).error()) ==
      NetError::ssrf_blocked);
  require_ok(
      net_error_of(pub.validate_url(parse_url("https://localhost/").value()).error()) ==
      NetError::ssrf_blocked);
  require_ok(
      net_error_of(pub.validate_url(parse_url("https://169.254.169.254/latest").value())
                       .error()) == NetError::ssrf_blocked);
  require_ok(pub.validate_url(parse_url("https://api.linear.app/graphql").value())
                 .has_value());

  // Allowing loopback for tests STILL blocks 169.254.169.254 and 10.0.0.1!
  auto loop_only = AllowedHostPolicy::any_public_https();
  loop_only.allow_loopback = true;
  require_ok(
      loop_only.validate_url(parse_url("https://127.0.0.1/").value()).has_value());
  require_ok(
      net_error_of(loop_only.validate_url(parse_url("https://169.254.169.254/").value())
                       .error()) == NetError::ssrf_blocked);
  require_ok(net_error_of(loop_only.validate_url(parse_url("https://10.0.0.5/").value())
                              .error()) == NetError::ssrf_blocked);

  // Wildcard host pinning rules & empty-label hostname rejection.
  require_ok(host_matches_pin({"api.notion.com", "*.notion.com"}));
  require_ok(host_matches_pin({"a.b.notion.com", "*.notion.com"}));
  require_ok(!host_matches_pin({"notion.com", "*.notion.com"}));
  require_ok(!host_matches_pin({"evilnotion.com", "*.notion.com"}));
  require_ok(!host_matches_pin({"api.notion.com", "*"}));
  require_ok(!host_matches_pin({"api.notion.com", "*.com"}));
  require_ok(!host_matches_pin({"..notion.com", "*.notion.com"}));
  require_ok(!host_matches_pin({".notion.com", "*.notion.com"}));
  require_ok(!host_matches_pin({"a..notion.com", "*.notion.com"}));
  require_ok(!host_matches_pin({"api.notion.com.", "*.notion.com"}));

  require_ok(!parse_url("https://..example.com/").has_value());
  require_ok(!parse_url("https://.example.com/").has_value());
  require_ok(!parse_url("https://example.com./").has_value());
  require_ok(!parse_url("https://a..example.com/").has_value());

  // Relative redirect containing "://" inside query string resolves cleanly.
  const auto redir_base = parse_url("https://api.example.com/v1/start");
  require_ok(redir_base.has_value());
  const auto rel_with_scheme_query =
      resolve_redirect_url(redir_base.value(), "/login?next=https://other.example/cb");
  require_ok(rel_with_scheme_query.has_value());
  require_ok(rel_with_scheme_query.value().host == "api.example.com");
  require_ok(rel_with_scheme_query.value().path == "/login");
  require_ok(rel_with_scheme_query.value().query == "next=https://other.example/cb");

  const auto q_only_redir =
      resolve_redirect_url(redir_base.value(), "?return_to=https://other.example/cb");
  require_ok(q_only_redir.has_value());
  require_ok(q_only_redir.value().path == "/v1/start");
  require_ok(q_only_redir.value().query == "return_to=https://other.example/cb");
}

void test_sse_parser_unit() {
  using namespace std::string_view_literals;
  std::vector<SseEvent> events;
  SseParser parser{};
  constexpr std::string_view payload = "\xEF\xBB\xBF"
                                       ": initial comment\r\n"
                                       "id: evt-1\r\n"
                                       "retry: 2500\r\n"
                                       "event: progress\r\n"
                                       "data: line 1\r\n"
                                       "data: line 2\r\n"
                                       "\r\n"
                                       "data: bare-lf\n"
                                       "\n"
                                       "event: cr-only\r"
                                       "data: cr-data\r"
                                       "\r"
                                       "id: bad\0id\n"
                                       "data: keeps-prev-id\n\n"sv;

  // Feed strictly 1 byte at a time to stress CRLF / BOM / boundary handling.
  for (const char ch : payload) {
    const auto ok = parser.feed(std::string_view{&ch, 1U}, [&](SseEvent ev) {
      events.push_back(std::move(ev));
      return true;
    });
    require_ok(ok.has_value());
  }
  require_ok(parser.finish([](const SseEvent &) { return true; }).has_value());

  require_ok(events.size() == 4U);
  require_ok(events[0].event == "progress");
  require_ok(events[0].data == "line 1\nline 2");
  require_ok(events[0].id == "evt-1");
  require_ok(events[0].retry_ms == std::optional<std::uint64_t>{2500U});

  require_ok(events[1].event == "message");
  require_ok(events[1].data == "bare-lf");
  require_ok(events[1].id == "evt-1");

  require_ok(events[2].event == "cr-only");
  require_ok(events[2].data == "cr-data");

  require_ok(events[3].data == "keeps-prev-id");
  require_ok(events[3].id == "evt-1");

  // Enforce max_event_bytes cap.
  SseParser capped{SseParserConfig{.max_event_bytes = 16U, .max_line_bytes = 64U}};
  const auto over = capped.feed("data: 01234567890123456789\n\n",
                                [](const SseEvent &) { return true; });
  require_ok(!over.has_value());
  require_ok(net_error_of(over.error()) == NetError::sse_event_too_large);
}

void test_real_tls_methods_chunked_sse_redirects_and_caps() {
  const TempDir dir{"tls"};
  const auto cert = generate_self_signed_cert(dir.path / "server.pem",
                                              "DNS:api.blackbird.test,IP:127.0.0.1");
  const auto other_cert =
      generate_self_signed_cert(dir.path / "other_ca.pem", "DNS:other.blackbird.test");

  LoopbackTlsServer server{
      cert, [](SSL *ssl, const ServerHttpRequest &req) {
        if (req.target.starts_with("/echo")) {
          const std::string body = req.method + "|" + req.target + "|" +
                                   req.headers.at("x-test") + "|" + req.body;
          const std::string hdr =
              "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
              std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";
          ssl_write_str(ssl, hdr);
          if (req.method != "HEAD") {
            ssl_write_str(ssl, body);
          }
          return;
        }
        if (req.target == "/chunked") {
          ssl_write_str(ssl, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                             "Content-Type: text/plain\r\nConnection: close\r\n\r\n");
          ssl_write_str(ssl, "5;ext=1\r\nHello\r\n");
          ssl_write_str(ssl, "7\r\n, World\r\n");
          ssl_write_str(ssl, "1\r\n!\r\n0\r\nX-Trailer: ok\r\n\r\n");
          return;
        }
        if (req.target == "/smuggle") {
          ssl_write_str(
              ssl,
              "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
              "Content-Length: 5\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
          return;
        }
        if (req.target == "/sse-chunked") {
          ssl_write_str(ssl, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                             "Content-Type: text/event-stream; charset=utf-8\r\n"
                             "Connection: close\r\n\r\n");
          const std::string chunk1 =
              "event: tick\r\nid: 42\r\ndata: first\r\ndata: second\r\n\r\n";
          const std::string chunk2 = "retry: 500\ndata: done\n\n";
          auto send_chunk_1b = [&](const std::string &c) {
            std::array<char, 32> hex{};
            std::snprintf(hex.data(), hex.size(), "%zx\r\n", c.size());
            ssl_write_byte_by_byte(ssl, std::string{hex.data()} + c + "\r\n");
          };
          send_chunk_1b(chunk1);
          send_chunk_1b(chunk2);
          ssl_write_byte_by_byte(ssl, "0\r\n\r\n");
          return;
        }
        if (req.target == "/redirect-same") {
          ssl_write_str(ssl, "HTTP/1.1 302 Found\r\nLocation: /redirect-final\r\n"
                             "Content-Length: 0\r\nConnection: close\r\n\r\n");
          return;
        }
        if (req.target == "/redirect-final") {
          ssl_write_str(ssl, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: "
                             "close\r\n\r\nlanded");
          return;
        }
        if (req.target == "/redirect-evil") {
          ssl_write_str(
              ssl,
              "HTTP/1.1 302 Found\r\nLocation: https://evil.blackbird.test/steal\r\n"
              "Content-Length: 0\r\nConnection: close\r\n\r\n");
          return;
        }
        if (req.target == "/redirect-downgrade") {
          ssl_write_str(
              ssl, "HTTP/1.1 302 Found\r\nLocation: http://api.blackbird.test/plain\r\n"
                   "Content-Length: 0\r\nConnection: close\r\n\r\n");
          return;
        }
        if (req.target == "/redirect-loop") {
          ssl_write_str(ssl, "HTTP/1.1 302 Found\r\nLocation: /redirect-loop\r\n"
                             "Content-Length: 0\r\nConnection: close\r\n\r\n");
          return;
        }
        if (req.target == "/big-body") {
          const std::string big(2048U, 'A');
          ssl_write_str(
              ssl,
              "HTTP/1.1 200 OK\r\nContent-Length: 2048\r\nConnection: close\r\n\r\n" +
                  big);
          return;
        }
        if (req.target == "/big-header") {
          const std::string pad(2048U, 'X');
          ssl_write_str(ssl,
                        "HTTP/1.1 200 OK\r\nX-Pad: " + pad +
                            "\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
          return;
        }
        ssl_write_str(
            ssl,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      }};

  const HttpClient client{
      make_test_client_config(cert.pem_path, server.port(), {"api.blackbird.test"})};

  // 1. All 6 HTTP methods over real TLS.
  for (const auto method : {HttpMethod::get, HttpMethod::post, HttpMethod::put,
                            HttpMethod::patch, HttpMethod::del, HttpMethod::head}) {
    HttpRequest req{};
    req.method = method;
    req.url = "https://api.blackbird.test/echo?k=1";
    req.set_header({"X-Test", "bb"});
    if (method == HttpMethod::post || method == HttpMethod::put ||
        method == HttpMethod::patch) {
      req.set_body_string("payload-body");
    }
    const auto resp = client.request(req);
    require_ok(resp.has_value());
    require_ok(resp.value().status == 200);
    if (method == HttpMethod::head) {
      require_ok(resp.value().body.empty());
    } else {
      const std::string expected_body =
          std::string{http_method_name(method)} + "|/echo?k=1|bb|" +
          ((method == HttpMethod::post || method == HttpMethod::put ||
            method == HttpMethod::patch)
               ? "payload-body"
               : "");
      require_ok(resp.value().body_as_string() == expected_body);
    }
  }

  // 2. Chunked transfer decoding + smuggling rejection.
  {
    HttpRequest req{};
    req.url = "https://api.blackbird.test/chunked";
    const auto resp = client.request(req);
    require_ok(resp.has_value());
    require_ok(resp.value().status == 200);
    require_ok(resp.value().body_as_string() == "Hello, World!");
  }
  {
    HttpRequest req{};
    req.url = "https://api.blackbird.test/smuggle";
    const auto resp = client.request(req);
    require_ok(!resp.has_value());
    require_ok(net_error_of(resp.error()) == NetError::http_malformed_response);
  }

  // 3. SSE streaming split across 1-byte TLS writes inside chunked encoding.
  {
    HttpRequest req{};
    req.url = "https://api.blackbird.test/sse-chunked";
    req.set_header({"Accept", "text/event-stream"});
    std::vector<SseEvent> got;
    const auto resp = client.stream_sse(req, [&](SseEvent ev) {
      got.push_back(std::move(ev));
      return true;
    });
    require_ok(resp.has_value());
    require_ok(resp.value().status == 200);
    require_ok(got.size() == 2U);
    require_ok(got[0].event == "tick");
    require_ok(got[0].id == "42");
    require_ok(got[0].data == "first\nsecond");
    require_ok(got[1].event == "message");
    require_ok(got[1].data == "done");
    require_ok(got[1].retry_ms == std::optional<std::uint64_t>{500U});
  }

  // 4. Host-pinning refusal & redirect security.
  {
    HttpRequest req{};
    req.url = "https://unpinned.blackbird.test/echo";
    const auto resp = client.request(req);
    require_ok(!resp.has_value());
    require_ok(net_error_of(resp.error()) == NetError::host_not_allowed);
  }
  {
    HttpRequest req{};
    req.url = "https://api.blackbird.test/redirect-same";
    const auto resp = client.request(req);
    require_ok(resp.has_value());
    require_ok(resp.value().status == 200);
    require_ok(resp.value().body_as_string() == "landed");
    require_ok(resp.value().final_url == "https://api.blackbird.test/redirect-final");
  }
  {
    HttpRequest req{};
    req.url = "https://api.blackbird.test/redirect-evil";
    const auto resp = client.request(req);
    require_ok(!resp.has_value());
    require_ok(net_error_of(resp.error()) == NetError::redirect_blocked);
  }
  {
    HttpRequest req{};
    req.url = "https://api.blackbird.test/redirect-downgrade";
    const auto resp = client.request(req);
    require_ok(!resp.has_value());
    require_ok(net_error_of(resp.error()) == NetError::redirect_blocked);
  }
  {
    HttpRequest req{};
    req.url = "https://api.blackbird.test/echo?k=1";
    req.set_header({"Host", "evil.blackbird.test"});
    const auto resp = client.request(req);
    require_ok(!resp.has_value());
    require_ok(net_error_of(resp.error()) == NetError::invalid_request);
  }
  {
    HttpRequest req{};
    req.url = "https://api.blackbird.test/redirect-loop";
    const auto resp = client.request(req);
    require_ok(!resp.has_value());
    require_ok(net_error_of(resp.error()) == NetError::too_many_redirects);
  }

  // 5. Oversized body and header caps.
  {
    HttpRequest req{};
    req.url = "https://api.blackbird.test/big-body";
    req.max_body_bytes = 512U;
    const auto resp = client.request(req);
    require_ok(!resp.has_value());
    require_ok(net_error_of(resp.error()) == NetError::http_body_too_large);
  }
  {
    HttpRequest req{};
    req.url = "https://api.blackbird.test/big-header";
    req.max_header_bytes = 512U;
    const auto resp = client.request(req);
    require_ok(!resp.has_value());
    require_ok(net_error_of(resp.error()) == NetError::http_header_too_large);
  }

  // 6. TLS hostname/SAN mismatch & untrusted CA rejection.
  {
    const HttpClient wrong_host_client{make_test_client_config(
        cert.pem_path, server.port(), {"wrong.blackbird.test"})};
    HttpRequest req{};
    req.url = "https://wrong.blackbird.test/echo";
    const auto resp = wrong_host_client.request(req);
    require_ok(!resp.has_value());
    require_ok(net_error_of(resp.error()) == NetError::tls_verify_failed);
  }
  {
    const HttpClient untrusted_ca_client{make_test_client_config(
        other_cert.pem_path, server.port(), {"api.blackbird.test"})};
    HttpRequest req{};
    req.url = "https://api.blackbird.test/echo";
    const auto resp = untrusted_ca_client.request(req);
    require_ok(!resp.has_value());
    require_ok(net_error_of(resp.error()) == NetError::tls_verify_failed);
  }
}

} // namespace

int main() {
  test_url_and_ssrf_policy();
  test_sse_parser_unit();
  test_real_tls_methods_chunked_sse_redirects_and_caps();
  std::cout << "net_http_test: all tests passed\n";
  return 0;
}
