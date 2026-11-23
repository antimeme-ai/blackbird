#include "blackbird/mp_client.hpp"

#include "blackbird/json.hpp"
#include "blackbird/value.hpp"

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
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
using namespace blackbird::mp;

void require_ok(bool ok, std::source_location loc = std::source_location::current()) {
  if (!ok) {
    std::cerr << "mp_client_test FAIL at " << loc.file_name() << ":" << loc.line()
              << "\n";
    std::abort();
  }
}

template <typename T>
const T &require_opt(const std::optional<T> &opt,
                     std::source_location loc = std::source_location::current()) {
  if (!opt.has_value()) {
    std::cerr << "mp_client_test FAIL (empty optional) at " << loc.file_name() << ":"
              << loc.line() << "\n";
    std::abort();
  }
  return *opt;
}

// ---------------------------------------------------------------------------
// Temp directory RAII helper
// ---------------------------------------------------------------------------

struct TempDir {
  std::filesystem::path path;
  explicit TempDir(std::string_view tag) {
    static std::atomic<std::uint64_t> counter{0U};
    const auto id = counter.fetch_add(1U, std::memory_order_relaxed);
    path = std::filesystem::temp_directory_path() /
           ("bb_mp_client_test_" + std::string{tag} + "_" +
            std::to_string(static_cast<std::uint64_t>(::getpid())) + "_" +
            std::to_string(id));
    std::filesystem::create_directories(path);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

// ---------------------------------------------------------------------------
// Ephemeral OpenSSL 3 self-signed TLS 1.3 cert+key generator (in-process)
// ---------------------------------------------------------------------------

struct EphemeralCert {
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{nullptr, &EVP_PKEY_free};
  std::unique_ptr<X509, decltype(&X509_free)> cert{nullptr, &X509_free};
  std::filesystem::path pem_path;
};

EphemeralCert generate_self_signed_cert(const std::filesystem::path &out_pem,
                                        const char *san_dns) {
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
                 reinterpret_cast<const unsigned char *>(san_dns), -1, -1, 0) == 1);
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
  const std::string san_value = std::string{"DNS:"} + san_dns + ",IP:127.0.0.1";
  add_ext(NID_subject_alt_name, san_value.c_str());

  require_ok(X509_sign(raw_cert, raw_key, EVP_sha256()) != 0);

  FILE *fp = std::fopen(out_pem.c_str(), "wb");
  require_ok(fp != nullptr);
  require_ok(PEM_write_X509(fp, raw_cert) == 1);
  require_ok(std::fclose(fp) == 0);
  return out;
}

// ---------------------------------------------------------------------------
// Minimal helpers for server-side HTTP/1.1 + RFC 6455 handling
// ---------------------------------------------------------------------------

std::string base64_encode_test(std::span<const std::uint8_t> bytes) {
  static constexpr char kAlpha[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  std::size_t i = 0U;
  while (i + 3U <= bytes.size()) {
    const std::uint32_t t = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                            static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 6U) & 0x3fU]);
    out.push_back(kAlpha[t & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1U) {
    const std::uint32_t t = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t t = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

std::string ws_accept_for(std::string_view key) {
  std::string in{key};
  in.append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  std::array<unsigned char, 20> digest{};
  unsigned int len = 0U;
  require_ok(
      EVP_Digest(in.data(), in.size(), digest.data(), &len, EVP_sha1(), nullptr) == 1);
  return base64_encode_test(std::span<const std::uint8_t>{digest.data(), len});
}

std::string to_lower_ascii(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (const char ch : s) {
    if (ch >= 'A' && ch <= 'Z') {
      out.push_back(static_cast<char>(ch + ('a' - 'A')));
    } else {
      out.push_back(ch);
    }
  }
  return out;
}

std::string_view trim_spaces(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
    s.remove_prefix(1U);
  }
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
    s.remove_suffix(1U);
  }
  return s;
}

void ssl_write_all(SSL *ssl, std::span<const std::uint8_t> data) {
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

void ssl_write_str(SSL *ssl, std::string_view s) {
  ssl_write_all(ssl, std::span<const std::uint8_t>{
                         reinterpret_cast<const std::uint8_t *>(s.data()), s.size()});
}

std::vector<std::uint8_t> build_server_ws_frame(std::uint8_t opcode,
                                                std::span<const std::uint8_t> payload,
                                                bool fin = true, bool masked = false) {
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>((fin ? 0x80U : 0x00U) | (opcode & 0x0fU)));
  const std::uint8_t mask_bit = masked ? 0x80U : 0x00U;
  if (payload.size() <= 125U) {
    out.push_back(static_cast<std::uint8_t>(mask_bit | payload.size()));
  } else {
    out.push_back(static_cast<std::uint8_t>(mask_bit | 126U));
    out.push_back(static_cast<std::uint8_t>((payload.size() >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(payload.size() & 0xffU));
  }
  if (masked) {
    out.push_back(0x11U);
    out.push_back(0x22U);
    out.push_back(0x33U);
    out.push_back(0x44U);
  }
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

struct ServerWsFrame {
  bool fin = true;
  bool masked = false;
  std::uint8_t opcode = 0U;
  std::vector<std::uint8_t> payload;
};

std::optional<ServerWsFrame> read_client_ws_frame(SSL *ssl) {
  auto read_exact = [&](std::uint8_t *dst, std::size_t n) -> bool {
    std::size_t got = 0U;
    while (got < n) {
      const int rc = SSL_read(ssl, dst + got, static_cast<int>(n - got));
      if (rc <= 0) {
        return false;
      }
      got += static_cast<std::size_t>(rc);
    }
    return true;
  };
  std::array<std::uint8_t, 2> hdr{};
  if (!read_exact(hdr.data(), 2U)) {
    return std::nullopt;
  }
  ServerWsFrame f{};
  f.fin = (hdr[0] & 0x80U) != 0U;
  f.opcode = static_cast<std::uint8_t>(hdr[0] & 0x0fU);
  f.masked = (hdr[1] & 0x80U) != 0U;
  std::uint64_t len = static_cast<std::uint64_t>(hdr[1] & 0x7fU);
  if (len == 126U) {
    std::array<std::uint8_t, 2> ext{};
    if (!read_exact(ext.data(), 2U)) {
      return std::nullopt;
    }
    len = (static_cast<std::uint64_t>(ext[0]) << 8U) | ext[1];
  }
  std::array<std::uint8_t, 4> mask{};
  if (f.masked && !read_exact(mask.data(), 4U)) {
    return std::nullopt;
  }
  f.payload.resize(static_cast<std::size_t>(len));
  if (len > 0U && !read_exact(f.payload.data(), static_cast<std::size_t>(len))) {
    return std::nullopt;
  }
  if (f.masked) {
    for (std::size_t i = 0U; i < f.payload.size(); ++i) {
      f.payload[i] = static_cast<std::uint8_t>(f.payload[i] ^ mask[i % 4U]);
    }
  }
  return f;
}

int alpn_select_http11(SSL * /*ssl*/, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void * /*arg*/) {
  static constexpr std::array<unsigned char, 9> kSrvAlpn = {8U,  'h', 't', 't', 'p',
                                                            '/', '1', '.', '1'};
  unsigned char *selected = nullptr;
  unsigned char selected_len = 0U;
  if (SSL_select_next_proto(&selected, &selected_len, kSrvAlpn.data(),
                            static_cast<unsigned int>(kSrvAlpn.size()), in,
                            inlen) != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  *out = selected;
  *outlen = selected_len;
  return SSL_TLSEXT_ERR_OK;
}

// ---------------------------------------------------------------------------
// In-process TLS 1.3 Loopback Mock Control Plane Server
// ---------------------------------------------------------------------------

enum class WsTestMode : std::uint8_t {
  normal_party = 0,
  bad_accept = 1,
  bad_subprotocol = 2,
  masked_server_frame = 3,
  oversized_frame = 4,
  duplicate_accept = 5,
  duplicate_subprotocol = 6,
  unsolicited_extensions = 7,
  zero_byte_continuation_flood = 8,
};

enum class HealthTestMode : std::uint8_t {
  normal = 0,
  chunked = 1,
  bad_timestamp_zero = 2,
  bad_timestamp_overflow = 3,
  unsupported_te_gzip_chunked = 4,
  both_te_and_cl = 5,
  unsupported_ce_gzip = 6,
};

struct LoopbackServerState {
  std::mutex mu;
  std::string expected_authority = "localhost";
  Ed25519PubKey registered_root_pubkey{};
  Ed25519PubKey registered_device_pubkey{};
  std::vector<std::uint8_t> registered_cwt;
  std::uint64_t account_id = 1001U;
  std::uint64_t device_id = 2001U;
  std::uint64_t enrolled_device_id = 2002U;
  std::string handle = "alice_test";
  std::uint64_t party_id = 5001U;
  std::uint64_t party_epoch = 1U;
  std::uint64_t party_invite_id = 7001U;
  HealthTestMode health_mode = HealthTestMode::normal;
  bool chunked_401_errors = false;
  bool force_non_skew_expired_401 = false;
  int health_calls = 0;
  int clock_skew_rejections = 0;
  int verified_rfc9421_calls = 0;
  std::string last_web_approve_code;
  bool ws_received_masked_endpoint_update = false;
  bool ws_received_masked_ping = false;
  bool ws_received_masked_pong = false;
  WsTestMode ws_mode = WsTestMode::normal_party;
};

class LoopbackTlsServer {
public:
  LoopbackTlsServer(const EphemeralCert &cert, LoopbackServerState &state)
      : state_(state) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    require_ok(ctx_ != nullptr);
    require_ok(SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION) == 1);
    require_ok(SSL_CTX_use_certificate(ctx_, cert.cert.get()) == 1);
    require_ok(SSL_CTX_use_PrivateKey(ctx_, cert.key.get()) == 1);
    SSL_CTX_set_alpn_select_cb(ctx_, &alpn_select_http11, nullptr);

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    require_ok(listen_fd_ >= 0);
    const int one = 1;
    require_ok(::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ==
               0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0U;
    require_ok(::bind(listen_fd_, reinterpret_cast<const sockaddr *>(&addr),
                      sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    require_ok(::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len) ==
               0);
    port_ = ntohs(addr.sin_port);
    require_ok(::listen(listen_fd_, 16) == 0);

    thread_ = std::thread([this]() { serve_loop(); });
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
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
    }
  }

  std::uint16_t port() const noexcept { return port_; }

private:
  void serve_loop() {
    sigset_t sigpipe_set{};
    sigemptyset(&sigpipe_set);
    sigaddset(&sigpipe_set, SIGPIPE);
    (void)::pthread_sigmask(SIG_BLOCK, &sigpipe_set, nullptr);

    while (!stop_.load(std::memory_order_relaxed)) {
      pollfd pfd{};
      pfd.fd = listen_fd_;
      pfd.events = POLLIN;
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
      handle_client(client_fd);
      ::close(client_fd);
    }
  }

  void send_json(SSL *ssl, int status, const char *reason, std::string_view json,
                 bool chunked = false) {
    std::string resp =
        "HTTP/1.1 " + std::to_string(status) + " " + reason +
        "\r\nContent-Type: application/json; charset=utf-8\r\nConnection: close\r\n";
    if (chunked) {
      resp.append("Transfer-Encoding: chunked\r\n\r\n");
      const std::size_t half = json.size() / 2U;
      auto append_chunk = [&](std::string_view part) {
        char hex[32]{};
        std::snprintf(hex, sizeof(hex), "%zx", part.size());
        resp.append(hex);
        resp.append("\r\n");
        resp.append(part);
        resp.append("\r\n");
      };
      append_chunk(json.substr(0U, half));
      append_chunk(json.substr(half));
      resp.append("0\r\n\r\n");
    } else {
      resp.append("Content-Length: " + std::to_string(json.size()) + "\r\n\r\n");
      resp.append(json);
    }
    ssl_write_str(ssl, resp);
  }

  void handle_client(int client_fd) {
    SSL *ssl = SSL_new(ctx_);
    if (ssl == nullptr) {
      return;
    }
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) != 1) {
      SSL_free(ssl);
      return;
    }

    // Read HTTP request headers + body
    std::string raw;
    std::array<char, 4096> buf{};
    std::size_t hdr_end = std::string::npos;
    while (hdr_end == std::string::npos && raw.size() < 16384U) {
      const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
      if (n <= 0) {
        SSL_free(ssl);
        return;
      }
      raw.append(buf.data(), static_cast<std::size_t>(n));
      hdr_end = raw.find("\r\n\r\n");
    }
    if (hdr_end == std::string::npos) {
      SSL_free(ssl);
      return;
    }

    const std::string_view hdr_block{raw.data(), hdr_end};
    const std::size_t first_eol = hdr_block.find("\r\n");
    const std::string_view req_line = hdr_block.substr(0U, first_eol);
    const std::size_t sp1 = req_line.find(' ');
    const std::size_t sp2 = req_line.find(' ', sp1 + 1U);
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
      SSL_free(ssl);
      return;
    }
    const std::string method_str{req_line.substr(0U, sp1)};
    const std::string target{req_line.substr(sp1 + 1U, sp2 - sp1 - 1U)};

    std::string path = target;
    std::string query = "?";
    if (const std::size_t q = target.find('?'); q != std::string::npos) {
      path = target.substr(0U, q);
      query = target.substr(q);
    }

    std::map<std::string, std::string> headers;
    std::size_t pos = first_eol + 2U;
    while (pos < hdr_block.size()) {
      const std::size_t eol = hdr_block.find("\r\n", pos);
      const std::string_view line = (eol == std::string_view::npos)
                                        ? hdr_block.substr(pos)
                                        : hdr_block.substr(pos, eol - pos);
      if (const std::size_t col = line.find(':'); col != std::string_view::npos) {
        headers[to_lower_ascii(line.substr(0U, col))] =
            std::string{trim_spaces(line.substr(col + 1U))};
      }
      if (eol == std::string_view::npos) {
        break;
      }
      pos = eol + 2U;
    }

    std::size_t content_len = 0U;
    if (const auto it = headers.find("content-length"); it != headers.end()) {
      content_len = static_cast<std::size_t>(std::stoull(it->second));
    }
    std::string body_str = raw.substr(hdr_end + 4U);
    while (body_str.size() < content_len) {
      const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
      if (n <= 0) {
        break;
      }
      body_str.append(buf.data(), static_cast<std::size_t>(n));
    }
    if (body_str.size() > content_len) {
      body_str.resize(content_len);
    }

    const auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    const auto now_s = static_cast<std::int64_t>(now_ms / 1000U);

    // 1. Unauthenticated /v1/health
    if (method_str == "GET" && path == "/v1/health") {
      HealthTestMode hmode = HealthTestMode::normal;
      {
        std::lock_guard<std::mutex> lk{state_.mu};
        ++state_.health_calls;
        hmode = state_.health_mode;
      }
      const std::string ok_body =
          "{\"ok\":true,\"server_now_ms\":" + std::to_string(now_ms) + "}";
      if (hmode == HealthTestMode::bad_timestamp_zero) {
        send_json(ssl, 200, "OK", "{\"ok\":true,\"server_now_ms\":0}", false);
      } else if (hmode == HealthTestMode::bad_timestamp_overflow) {
        send_json(ssl, 200, "OK",
                  "{\"ok\":true,\"server_now_ms\":18446744073709551615}", false);
      } else if (hmode == HealthTestMode::unsupported_te_gzip_chunked) {
        ssl_write_str(
            ssl,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            "Transfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n0\r\n\r\n");
      } else if (hmode == HealthTestMode::both_te_and_cl) {
        ssl_write_str(ssl, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                           "Transfer-Encoding: chunked\r\nContent-Length: 2\r\n"
                           "Connection: close\r\n\r\n2\r\n{}\r\n0\r\n\r\n");
      } else if (hmode == HealthTestMode::unsupported_ce_gzip) {
        ssl_write_str(ssl, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                           "Content-Encoding: gzip\r\nContent-Length: " +
                               std::to_string(ok_body.size()) +
                               "\r\nConnection: close\r\n\r\n" + ok_body);
      } else {
        send_json(ssl, 200, "OK", ok_body, hmode == HealthTestMode::chunked);
      }
      SSL_shutdown(ssl);
      SSL_free(ssl);
      return;
    }

    const auto method = parse_http_method(method_str);
    require_ok(method.has_value());

    const std::span<const std::uint8_t> body_span{
        reinterpret_cast<const std::uint8_t *>(body_str.data()), body_str.size()};

    auto verify_request_with_key = [&](const Ed25519PubKey &pk) -> bool {
      Rfc9421Request r{};
      r.method = method.value();
      r.authority = headers["host"];
      r.path = path;
      r.query = query;
      if (const auto it = headers.find("content-type"); it != headers.end()) {
        r.content_type = it->second;
      }
      if (const auto it = headers.find("content-digest"); it != headers.end()) {
        r.content_digest = it->second;
      }
      r.has_content_encoding = headers.contains("content-encoding");
      r.body = body_span;
      r.signature_input = headers["signature-input"];
      r.signature = headers["signature"];

      std::string exp_auth;
      {
        std::lock_guard<std::mutex> lk{state_.mu};
        exp_auth = state_.expected_authority;
      }
      const auto verified =
          verify_rfc9421_request(Rfc9421VerifyInput{r, exp_auth, pk, now_s});
      if (!verified.has_value()) {
        if (mp_error_of(verified.error()) == MpError::rfc9421_clock_skew ||
            mp_error_of(verified.error()) == MpError::rfc9421_expired) {
          bool chunked_401 = false;
          {
            std::lock_guard<std::mutex> lk{state_.mu};
            ++state_.clock_skew_rejections;
            chunked_401 = state_.chunked_401_errors;
          }
          const char *err_code =
              (mp_error_of(verified.error()) == MpError::rfc9421_expired)
                  ? "expired"
                  : "clock_skew";
          send_json(ssl, 401, "Unauthorized",
                    std::string{"{\"error\":\""} + err_code +
                        "\",\"server_now_ms\":" + std::to_string(now_ms) + "}",
                    chunked_401);
          return false;
        }
        send_json(ssl, 401, "Unauthorized", "{\"error\":\"invalid_signature\"}");
        return false;
      }
      {
        std::lock_guard<std::mutex> lk{state_.mu};
        if (state_.force_non_skew_expired_401) {
          // Simulate genuine CWT expiry when client clock is accurate (within 30s).
          send_json(ssl, 401, "Unauthorized",
                    "{\"error\":\"expired\",\"server_now_ms\":" +
                        std::to_string(now_ms) + "}");
          return false;
        }
        ++state_.verified_rfc9421_calls;
      }
      return true;
    };

    // 2. POST /v1/accounts/register
    if (method_str == "POST" && path == "/v1/accounts/register") {
      require_ok(headers.contains("idempotency-key"));
      const auto json = parse_json(body_str);
      require_ok(json.has_value());
      const std::string &root_b64 = json.value().find("root_pubkey_b64")->string();
      const std::string &dev_b64 = json.value().find("device_pubkey_b64")->string();
      const std::string &cwt_b64 = json.value().find("device_cwt_b64")->string();
      (void)root_b64;
      (void)dev_b64;
      (void)cwt_b64;
      // Verify RFC 9421 using registered_root_pubkey stored in test harness.
      Ed25519PubKey root_pk{};
      {
        std::lock_guard<std::mutex> lk{state_.mu};
        root_pk = state_.registered_root_pubkey;
      }
      if (!verify_request_with_key(root_pk)) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
      }
      std::uint64_t aid = 0U;
      std::uint64_t did = 0U;
      std::string handle;
      {
        std::lock_guard<std::mutex> lk{state_.mu};
        aid = state_.account_id;
        did = state_.device_id;
        handle = json.value().find("handle")->string();
        state_.handle = handle;
      }
      send_json(ssl, 201, "Created",
                "{\"account_id\":" + std::to_string(aid) + ",\"device_id\":" +
                    std::to_string(did) + ",\"handle\":\"" + handle + "\"}");
      SSL_shutdown(ssl);
      SSL_free(ssl);
      return;
    }

    // Determine whether .root or device key signed this request.
    const auto parsed_si = parse_signature_input(headers["signature-input"]);
    require_ok(parsed_si.has_value());
    Ed25519PubKey verify_pk{};
    {
      std::lock_guard<std::mutex> lk{state_.mu};
      verify_pk = std::holds_alternative<RootKeyId>(parsed_si.value().keyid)
                      ? state_.registered_root_pubkey
                      : state_.registered_device_pubkey;
    }
    if (!verify_request_with_key(verify_pk)) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
      return;
    }

    // WebSocket upgrade routes
    if (method_str == "GET" && (path == "/v1/ws" || path.ends_with("/ws"))) {
      handle_ws_session(ssl, headers);
      SSL_shutdown(ssl);
      SSL_free(ssl);
      return;
    }

    // Authenticated REST routes
    std::lock_guard<std::mutex> lk{state_.mu};
    if (method_str == "GET" && path == "/v1/accounts/me") {
      const std::string body =
          "{\"account_id\":" + std::to_string(state_.account_id) + ",\"handle\":\"" +
          state_.handle + "\",\"root_pubkey_b64\":\"" +
          base64_encode_test(state_.registered_root_pubkey) +
          "\",\"devices\":[{\"device_id\":" + std::to_string(state_.device_id) +
          ",\"pubkey_b64\":\"" + base64_encode_test(state_.registered_device_pubkey) +
          "\",\"label\":\"laptop\",\"cwt_expires_ms\":" +
          std::to_string(now_ms + 86400000U) +
          ",\"generation\":1,\"pop_verified\":1,\"created_at_ms\":" +
          std::to_string(now_ms) + ",\"revoked_at_ms\":null}],\"active_party_ids\":[" +
          std::to_string(state_.party_id) + "]}";
      send_json(ssl, 200, "OK", body);
    } else if (method_str == "GET" && path == "/v1/accounts/resolve") {
      require_ok(query == "?handle=" + state_.handle);
      send_json(ssl, 200, "OK",
                "{\"account_id\":" + std::to_string(state_.account_id) +
                    ",\"handle\":\"" + state_.handle + "\",\"root_pubkey_b64\":\"" +
                    base64_encode_test(state_.registered_root_pubkey) + "\"}");
    } else if (method_str == "POST" && path == "/v1/devices") {
      require_ok(std::holds_alternative<RootKeyId>(parsed_si.value().keyid));
      send_json(ssl, 201, "Created",
                "{\"device_id\":" + std::to_string(state_.enrolled_device_id) +
                    ",\"cwt_expires_ms\":" + std::to_string(now_ms + 86400000U) + "}");
    } else if (method_str == "DELETE" && path.starts_with("/v1/devices/")) {
      require_ok(std::holds_alternative<RootKeyId>(parsed_si.value().keyid));
      send_json(ssl, 200, "OK",
                "{\"revoked\":true,\"evicted_parties\":[" +
                    std::to_string(state_.party_id) + "],\"pending_retries\":0}");
    } else if (method_str == "POST" && path == "/v1/web-sessions/approve") {
      require_ok(std::holds_alternative<DeviceKeyId>(parsed_si.value().keyid));
      const auto json = parse_json(body_str);
      require_ok(json.has_value());
      const Value *uc = json.value().find("user_code");
      require_ok(uc != nullptr && std::holds_alternative<std::string>(uc->value()));
      const std::string &code = uc->string();
      state_.last_web_approve_code = code;
      if (code == "ABCD-EFGH") {
        send_json(ssl, 200, "OK",
                  "{\"approved\":true,\"scope\":\"account:read\",\"expires_at_ms\":" +
                      std::to_string(now_ms + 3600000U) + "}");
      } else if (code == "4040-0000") {
        send_json(ssl, 404, "Not Found", "{\"error\":\"not_found\"}");
      } else if (code == "4100-0000") {
        send_json(ssl, 410, "Gone", "{\"error\":\"expired\"}");
      } else if (code == "4000-0000") {
        send_json(ssl, 400, "Bad Request", "{\"error\":\"invalid_user_code\"}");
      } else {
        send_json(ssl, 404, "Not Found", "{\"error\":\"not_found\"}");
      }
    } else if (method_str == "GET" && path == "/v1/friends") {
      send_json(
          ssl, 200, "OK",
          "{\"friends\":[{\"peer_account_id\":1002,\"state\":0,\"updated_at_ms\":" +
              std::to_string(now_ms) + "}]}");
    } else if (method_str == "POST" && path == "/v1/friends/requests") {
      send_json(ssl, 202, "Accepted", "{\"target_account_id\":1002,\"state\":1}");
    } else if (method_str == "POST" && path.ends_with("/block")) {
      send_json(ssl, 200, "OK", "{\"target_account_id\":1002,\"state\":3}");
    } else if (method_str == "DELETE" && path.starts_with("/v1/friends/")) {
      send_json(ssl, 200, "OK", "{\"removed\":true}");
    } else if (method_str == "POST" && path == "/v1/parties") {
      state_.party_epoch = 1U;
      send_json(ssl, 201, "Created",
                "{\"party_id\":" + std::to_string(state_.party_id) +
                    ",\"party_epoch\":1,\"pinned_relay_url\":\"https://"
                    "relay.multiplayer.tech\"}");
    } else if (method_str == "GET" &&
               path == "/v1/parties/" + std::to_string(state_.party_id)) {
      send_json(ssl, 200, "OK",
                "{\"party_id\":" + std::to_string(state_.party_id) +
                    ",\"party_epoch\":" + std::to_string(state_.party_epoch) +
                    ",\"leader_account_id\":" + std::to_string(state_.account_id) +
                    ",\"leader_device_id\":" + std::to_string(state_.device_id) +
                    ",\"visibility\":1,\"join_mode\":0,\"relay_policy\":1,"
                    "\"pinned_relay_url\":\"https://relay.multiplayer.tech\","
                    "\"max_members\":4,\"member_count\":2}");
    } else if (method_str == "POST" && path.ends_with("/invites")) {
      send_json(ssl, 201, "Created",
                "{\"party_invite_id\":" + std::to_string(state_.party_invite_id) +
                    ",\"expires_at_ms\":" + std::to_string(now_ms + 3600000U) +
                    ",\"invite_link\":\"mppi1_5001_testsecret\"}");
    } else if (method_str == "DELETE" && path.find("/invites/") != std::string::npos) {
      send_json(ssl, 200, "OK", "{\"revoked\":true}");
    } else if (method_str == "POST" && path.ends_with("/join")) {
      ++state_.party_epoch;
      send_json(ssl, 200, "OK",
                "{\"status\":\"joined\",\"party_epoch\":" +
                    std::to_string(state_.party_epoch) + "}");
    } else if (method_str == "POST" && path.ends_with("/kick")) {
      ++state_.party_epoch;
      send_json(ssl, 200, "OK",
                "{\"kicked\":true,\"party_epoch\":" +
                    std::to_string(state_.party_epoch) + "}");
    } else if (method_str == "POST" && path.ends_with("/leave")) {
      ++state_.party_epoch;
      send_json(ssl, 200, "OK",
                "{\"left\":true,\"party_epoch\":" + std::to_string(state_.party_epoch) +
                    "}");
    } else if (method_str == "POST" && path.ends_with("/disband")) {
      ++state_.party_epoch;
      send_json(ssl, 200, "OK",
                "{\"disbanded\":true,\"party_epoch\":" +
                    std::to_string(state_.party_epoch) + "}");
    } else {
      send_json(ssl, 404, "Not Found", "{\"error\":\"not_found\"}");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
  }

  void handle_ws_session(SSL *ssl, const std::map<std::string, std::string> &headers) {
    WsTestMode mode = WsTestMode::normal_party;
    PartyMemberRecord member{
        DeviceId::create(2001U).value(),
        AccountId::create(1001U).value(),
        {},
        {},
        {},
        EndpointDescriptor{
            TransportKind::iroh_quic, "https://relay.multiplayer.tech", {}},
        1U,
        true,
    };
    {
      std::lock_guard<std::mutex> lk{state_.mu};
      mode = state_.ws_mode;
      member.root_pubkey = state_.registered_root_pubkey;
      member.device_pubkey = state_.registered_device_pubkey;
      member.device_cwt = state_.registered_cwt;
    }

    const std::string &ws_key = headers.at("sec-websocket-key");
    std::string accept = ws_accept_for(ws_key);
    std::string proto = "mp1";
    if (mode == WsTestMode::bad_accept) {
      accept = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    } else if (mode == WsTestMode::bad_subprotocol) {
      proto = "wrongproto";
    }

    std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: " +
                       accept +
                       "\r\n"
                       "Sec-WebSocket-Protocol: " +
                       proto + "\r\n";
    if (mode == WsTestMode::duplicate_accept) {
      resp.append("Sec-WebSocket-Accept: " + accept + "\r\n");
    } else if (mode == WsTestMode::duplicate_subprotocol) {
      resp.append("Sec-WebSocket-Protocol: mp1\r\n");
    } else if (mode == WsTestMode::unsolicited_extensions) {
      resp.append("Sec-WebSocket-Extensions: permessage-deflate\r\n");
    }
    resp.append("\r\n");

    if (mode == WsTestMode::bad_accept || mode == WsTestMode::bad_subprotocol ||
        mode == WsTestMode::duplicate_accept ||
        mode == WsTestMode::duplicate_subprotocol ||
        mode == WsTestMode::unsolicited_extensions) {
      ssl_write_str(ssl, resp);
      return;
    }

    if (mode == WsTestMode::zero_byte_continuation_flood) {
      ssl_write_str(ssl, resp);
      const std::array<std::uint8_t, 1> first_byte = {0x01U};
      ssl_write_all(ssl,
                    build_server_ws_frame(0x02U, first_byte, /*fin=*/false, false));
      const std::span<const std::uint8_t> empty_span{};
      for (int i = 0; i < 70; ++i) {
        ssl_write_all(ssl,
                      build_server_ws_frame(0x00U, empty_span, /*fin=*/false, false));
      }
      return;
    }

    if (mode == WsTestMode::masked_server_frame) {
      ssl_write_str(ssl, resp);
      const std::array<std::uint8_t, 4> dummy = {1U, 2U, 3U, 4U};
      ssl_write_all(ssl, build_server_ws_frame(0x02U, dummy, true, /*masked=*/true));
      return;
    }

    if (mode == WsTestMode::oversized_frame) {
      ssl_write_str(ssl, resp);
      std::vector<std::uint8_t> big(kMaxMp1FrameBytes + 1U, 0x42U);
      ssl_write_all(ssl, build_server_ws_frame(0x02U, big, true, false));
      return;
    }

    // Normal mode: coalesce HELLO_ACK right behind 101, then send fragmented
    // PARTY_SNAPSHOT!
    const auto hello_bytes = encode_frame(
        0U, HelloAckMessage{SessionId::create(99U).value(), 1700000000000U, 20000U});
    require_ok(hello_bytes.has_value());
    const auto snap_bytes = encode_frame(0U, PartySnapshotMessage{
                                                 PartyId::create(5001U).value(),
                                                 2U,
                                                 AccountId::create(1001U).value(),
                                                 DeviceId::create(2001U).value(),
                                                 PartyVisibility::friends,
                                                 PartyJoinMode::invite_only,
                                                 RelayPolicy::force_relays,
                                                 4U,
                                                 "https://relay.multiplayer.tech",
                                                 {member},
                                             });
    require_ok(snap_bytes.has_value());

    // Coalesce 101 + HELLO_ACK in one write
    std::vector<std::uint8_t> initial(resp.begin(), resp.end());
    const auto hello_ws =
        build_server_ws_frame(0x02U, hello_bytes.value(), true, false);
    initial.insert(initial.end(), hello_ws.begin(), hello_ws.end());
    ssl_write_all(ssl, initial);

    // Send PARTY_SNAPSHOT split across 2 fragments with an interleaved RFC 6455 Ping!
    const std::size_t split = snap_bytes.value().size() / 2U;
    const std::span<const std::uint8_t> frag1{snap_bytes.value().data(), split};
    const std::span<const std::uint8_t> frag2{snap_bytes.value().data() + split,
                                              snap_bytes.value().size() - split};
    ssl_write_all(ssl, build_server_ws_frame(0x02U, frag1, /*fin=*/false, false));
    const std::array<std::uint8_t, 4> ping_payload = {'t', 'e', 's', 't'};
    ssl_write_all(ssl, build_server_ws_frame(0x09U, ping_payload, /*fin=*/true, false));
    ssl_write_all(ssl, build_server_ws_frame(0x00U, frag2, /*fin=*/true, false));

    // Read client frames: expect Pong for our RFC 6455 Ping, binary
    // PARTY_ENDPOINT_UPDATE, and text "MP1:PING" -> reply "MP1:PONG" -> send
    // Close(4403)!
    for (int i = 0; i < 6; ++i) {
      const auto f = read_client_ws_frame(ssl);
      if (!f.has_value()) {
        break;
      }
      require_ok(f->masked); // RFC 6455 client MUST mask!
      if (f->opcode == 0x0aU) {
        if (f->payload.size() == ping_payload.size() &&
            std::memcmp(f->payload.data(), ping_payload.data(), ping_payload.size()) ==
                0) {
          std::lock_guard<std::mutex> lk{state_.mu};
          state_.ws_received_masked_pong = true;
        }
      } else if (f->opcode == 0x02U) {
        const auto decoded = decode_frame(f->payload);
        require_ok(decoded.has_value());
        require_ok(decoded.value().header.opcode == Opcode::party_endpoint_update);
        std::lock_guard<std::mutex> lk{state_.mu};
        state_.ws_received_masked_endpoint_update = true;
      } else if (f->opcode == 0x01U) {
        const std::string_view text{reinterpret_cast<const char *>(f->payload.data()),
                                    f->payload.size()};
        if (text == "MP1:PING") {
          {
            std::lock_guard<std::mutex> lk{state_.mu};
            state_.ws_received_masked_ping = true;
          }
          const std::string_view pong = "MP1:PONG";
          ssl_write_all(
              ssl,
              build_server_ws_frame(
                  0x01U,
                  std::span<const std::uint8_t>{
                      reinterpret_cast<const std::uint8_t *>(pong.data()), pong.size()},
                  true, false));
          // Immediately follow with Close(4403) (kicked)
          const std::array<std::uint8_t, 2> close_4403 = {
              static_cast<std::uint8_t>((4403U >> 8U) & 0xffU),
              static_cast<std::uint8_t>(4403U & 0xffU)};
          ssl_write_all(ssl, build_server_ws_frame(0x08U, close_4403, true, false));
          break;
        }
      } else if (f->opcode == 0x08U) {
        break;
      }
    }
  }

  LoopbackServerState &state_;
  SSL_CTX *ctx_ = nullptr;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0U;
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

// ---------------------------------------------------------------------------
// Test 1: Local keystore 0700/0600, symlink/traversal rejection, cleanse
// ---------------------------------------------------------------------------

void test_identity_store() {
  TempDir tmp{"keystore"};
  const auto missing_dir = tmp.path / "does_not_exist";

  // 1. open_existing fails closed without creating directories/files.
  const auto missing = MpIdentityStore::open_existing(missing_dir);
  require_ok(!missing.has_value());
  require_ok(mp_client_error_of(missing.error()) == MpClientError::keystore_not_found);
  require_ok(!std::filesystem::exists(missing_dir));

  // 2. Reject `..` traversal path.
  const auto traversal = MpIdentityStore::open_existing(tmp.path / "a" / ".." / "b");
  require_ok(!traversal.has_value());
  require_ok(mp_client_error_of(traversal.error()) ==
             MpClientError::keystore_invalid_path);

  // 3. Save with root_seed + device_seed + metadata + CWT and check 0700/0600 perms.
  auto root_seed = CleansedSeed::generate().value();
  auto dev_seed = CleansedSeed::generate().value();
  const auto root_key = Ed25519SigningKey::from_seed(root_seed.bytes()).value();
  const auto dev_key = Ed25519SigningKey::from_seed(dev_seed.bytes()).value();
  const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  const auto cwt =
      encode_device_cwt(root_key, DeviceCwtMintRequest{dev_key.public_key(), now_s - 5,
                                                       now_s + 86400})
          .value();

  MpIdentityState state{};
  state.root_seed = root_seed;
  state.device_seed = dev_seed;
  state.account_id = AccountId::create(1001U).value();
  state.device_id = DeviceId::create(2001U).value();
  state.handle = "alice_ks";
  state.authority = "api.multiplayer.tech";
  state.device_cwt = cwt;

  const auto store_dir = tmp.path / "identity";
  auto saved = MpIdentityStore::save(store_dir, state);
  require_ok(saved.has_value());

  struct stat st{};
  require_ok(::stat(store_dir.c_str(), &st) == 0);
  require_ok((st.st_mode & 0777U) == 0700U);
  for (const char *fname :
       {"device.seed", "root.seed", "device.cwt", "identity.json"}) {
    const auto fpath = store_dir / fname;
    require_ok(::stat(fpath.c_str(), &st) == 0);
    require_ok((st.st_mode & 0777U) == 0600U);
  }

  // Round-trip reload
  auto reloaded = MpIdentityStore::open_existing(store_dir);
  require_ok(reloaded.has_value());
  require_ok(reloaded.value().state() == state);
  require_ok(reloaded.value().device_signing_key().value().public_key() ==
             dev_key.public_key());
  require_ok(reloaded.value().root_signing_key().value().public_key() ==
             root_key.public_key());

  // 4. Secondary device (no root_seed): root.seed removed cleanly!
  MpIdentityState secondary = state;
  secondary.root_seed.reset();
  require_ok(reloaded.value().update(secondary).has_value());
  require_ok(!std::filesystem::exists(store_dir / "root.seed"));
  const auto reloaded_sec = MpIdentityStore::open_existing(store_dir);
  require_ok(reloaded_sec.has_value());
  require_ok(!reloaded_sec.value().state().root_seed.has_value());
  require_ok(mp_client_error_of(reloaded_sec.value().root_signing_key().error()) ==
             MpClientError::missing_root_key);

  // 5. Reject symlink directory.
  const auto sym_dir = tmp.path / "sym_identity";
  std::filesystem::create_directory_symlink(store_dir, sym_dir);
  const auto sym_open = MpIdentityStore::open_existing(sym_dir);
  require_ok(!sym_open.has_value());
  require_ok(mp_client_error_of(sym_open.error()) ==
             MpClientError::keystore_symlink_rejected);
  const auto sym_save = MpIdentityStore::save(sym_dir, secondary);
  require_ok(!sym_save.has_value());
  require_ok(mp_client_error_of(sym_save.error()) ==
             MpClientError::keystore_symlink_rejected);

  // 6. Reject symlink file inside store directory.
  const auto fake_seed = tmp.path / "outside.seed";
  {
    std::ofstream ofs{fake_seed, std::ios::binary};
    ofs.write(reinterpret_cast<const char *>(dev_seed.bytes().data()), 32);
  }
  require_ok(::chmod(fake_seed.c_str(), mode_t{0600}) == 0);
  std::filesystem::remove(store_dir / "device.seed");
  std::filesystem::create_symlink(fake_seed, store_dir / "device.seed");
  const auto sym_file = MpIdentityStore::open_existing(store_dir);
  require_ok(!sym_file.has_value());
  require_ok(mp_client_error_of(sym_file.error()) ==
             MpClientError::keystore_symlink_rejected);

  // 7. Reject insecure permissions (0755 directory).
  const auto bad_perm_dir = tmp.path / "bad_perm";
  require_ok(MpIdentityStore::save(bad_perm_dir, secondary).has_value());
  require_ok(::chmod(bad_perm_dir.c_str(), mode_t{0755}) == 0);
  const auto bad_perm_open = MpIdentityStore::open_existing(bad_perm_dir);
  require_ok(!bad_perm_open.has_value());
  require_ok(mp_client_error_of(bad_perm_open.error()) ==
             MpClientError::keystore_insecure_permissions);

  // 8. Reject corrupted authority inside identity.json on open_existing().
  {
    const auto bad_auth_dir = tmp.path / "bad_auth";
    require_ok(MpIdentityStore::save(bad_auth_dir, secondary).has_value());
    const auto meta_path = bad_auth_dir / "identity.json";
    {
      std::ofstream ofs{meta_path, std::ios::binary | std::ios::trunc};
      ofs << "{\"version\":1,\"account_id\":1001,\"device_id\":2001,"
             "\"handle\":\"alice_ks\",\"authority\":\"evil.example/inject\"}";
    }
    require_ok(::chmod(meta_path.c_str(), mode_t{0600}) == 0);
    const auto bad_auth_open = MpIdentityStore::open_existing(bad_auth_dir);
    require_ok(!bad_auth_open.has_value());
    require_ok(mp_client_error_of(bad_auth_open.error()) ==
               MpClientError::keystore_corrupt);
  }

  // 9. Verify CleansedSeed zeroes moved-from buffer.
  CleansedSeed moved_from{dev_seed.bytes()};
  CleansedSeed moved_to{std::move(moved_from)};
  require_ok(moved_to.bytes() == dev_seed.bytes());
  Ed25519Seed all_zero{};
  // Verify cleanse() clears buffer deterministically.
  moved_to.cleanse();
  require_ok(moved_to.bytes() == all_zero);

  // 10. Secondary device store: open_or_init_device & install_cwt validation.
  {
    const auto sec_dir = tmp.path / "secondary_device";
    auto sec_store = MpIdentityStore::open_or_init_device(sec_dir, "api.example.test");
    require_ok(sec_store.has_value());
    require_ok(!sec_store.value().state().root_seed.has_value());
    require_ok(!sec_store.value().state().account_id.has_value());
    require_ok(!sec_store.value().state().device_id.has_value());
    require_ok(sec_store.value().state().device_cwt.empty());
    require_ok(sec_store.value().state().authority == "api.example.test");
    require_ok(!std::filesystem::exists(sec_dir / "root.seed"));
    const auto sec_dev_pk = sec_store.value().device_signing_key().value().public_key();

    // Calling open_or_init_device again preserves existing device key (never clobbers).
    auto reopened = MpIdentityStore::open_or_init_device(sec_dir, "other.example");
    require_ok(reopened.has_value());
    require_ok(reopened.value().device_signing_key().value().public_key() ==
               sec_dev_pk);
    require_ok(reopened.value().state().authority == "api.example.test");

    // Installing a CWT minted for a DIFFERENT device key MUST fail closed before disk
    // modification!
    const auto bad_install = reopened.value().install_cwt(InstallDeviceCwtRequest{
        AccountId::create(1001U).value(),
        DeviceId::create(2005U).value(),
        "alice_sec",
        cwt, // minted for dev_key, NOT sec_dev_pk!
        std::nullopt,
        std::nullopt,
        now_s,
    });
    require_ok(!bad_install.has_value());
    require_ok(mp_error_of(bad_install.error()) == MpError::cwt_device_key_mismatch);
    require_ok(!reopened.value().state().account_id.has_value());
    require_ok(reopened.value().state().device_cwt.empty());

    // Mint valid CWT for sec_dev_pk signed by root_key.
    const auto sec_cwt =
        encode_device_cwt(root_key,
                          DeviceCwtMintRequest{sec_dev_pk, now_s - 5, now_s + 86400})
            .value();

    // Wrong expected_root_pubkey MUST fail signature/issuer verification.
    const auto wrong_root_seed = CleansedSeed::generate().value();
    const auto wrong_root_key =
        Ed25519SigningKey::from_seed(wrong_root_seed.bytes()).value();
    const auto bad_sig_install = reopened.value().install_cwt(InstallDeviceCwtRequest{
        AccountId::create(1001U).value(),
        DeviceId::create(2005U).value(),
        "alice_sec",
        sec_cwt,
        std::nullopt,
        wrong_root_key.public_key(),
        now_s,
    });
    require_ok(!bad_sig_install.has_value());
    require_ok(!reopened.value().state().account_id.has_value());

    // Valid CWT with expected_root_pubkey succeeds and persists atomically.
    const auto ok_install = reopened.value().install_cwt(InstallDeviceCwtRequest{
        AccountId::create(1001U).value(),
        DeviceId::create(2005U).value(),
        "alice_sec",
        sec_cwt,
        std::nullopt,
        root_key.public_key(),
        now_s,
    });
    require_ok(ok_install.has_value());
    require_ok(!std::filesystem::exists(sec_dir / "root.seed"));
    const auto after_install = MpIdentityStore::open_existing(sec_dir);
    require_ok(after_install.has_value());
    require_ok(!after_install.value().state().root_seed.has_value());
    require_ok(after_install.value().state().account_id ==
               AccountId::create(1001U).value());
    require_ok(after_install.value().state().device_id ==
               DeviceId::create(2005U).value());
    require_ok(after_install.value().state().handle == "alice_sec");
    require_ok(after_install.value().state().device_cwt == sec_cwt);

    // Keystore with existing root_seed MUST reject install_cwt for a different account,
    // AND for a matching account MUST always verify against local root_seed (rejecting
    // forged CWTs and foreign expected_root_pubkey!).
    const auto root_dir = tmp.path / "root_conflict";
    auto root_store = MpIdentityStore::save(root_dir, state);
    require_ok(root_store.has_value());
    const auto conflict_install =
        root_store.value().install_cwt(InstallDeviceCwtRequest{
            AccountId::create(9999U).value(),
            DeviceId::create(2001U).value(),
            "other_acct",
            cwt,
            std::nullopt,
            std::nullopt,
            now_s,
        });
    require_ok(!conflict_install.has_value());
    require_ok(conflict_install.error().code == ErrorCode::conflict);

    // Forged CWT (signed by wrong_root_key for local dev_key) on matching account_id:
    const auto forged_cwt =
        encode_device_cwt(
            wrong_root_key,
            DeviceCwtMintRequest{dev_key.public_key(), now_s - 5, now_s + 86400})
            .value();
    const auto forged_no_root = root_store.value().install_cwt(InstallDeviceCwtRequest{
        AccountId::create(1001U).value(),
        DeviceId::create(2001U).value(),
        "alice_ks",
        forged_cwt,
        std::nullopt,
        std::nullopt,
        now_s,
    });
    require_ok(!forged_no_root.has_value());
    require_ok(root_store.value().state().device_cwt == cwt);

    const auto forged_foreign_root =
        root_store.value().install_cwt(InstallDeviceCwtRequest{
            AccountId::create(1001U).value(),
            DeviceId::create(2001U).value(),
            "alice_ks",
            forged_cwt,
            std::nullopt,
            wrong_root_key.public_key(),
            now_s,
        });
    require_ok(!forged_foreign_root.has_value());
    require_ok(forged_foreign_root.error().code == ErrorCode::conflict);
    require_ok(mp_error_of(forged_foreign_root.error()) ==
               MpError::cwt_issuer_mismatch);
    require_ok(root_store.value().state().device_cwt == cwt);

    // Legitimate renewed CWT signed by local root_key succeeds even when
    // expected_root_pubkey is omitted (verified against local root_seed).
    const auto renewed_cwt =
        encode_device_cwt(root_key, DeviceCwtMintRequest{dev_key.public_key(),
                                                         now_s - 2, now_s + 7200})
            .value();
    const auto renewed_ok = root_store.value().install_cwt(InstallDeviceCwtRequest{
        AccountId::create(1001U).value(),
        DeviceId::create(2001U).value(),
        "alice_ks",
        renewed_cwt,
        std::nullopt,
        std::nullopt,
        now_s,
    });
    require_ok(renewed_ok.has_value());
    require_ok(root_store.value().state().device_cwt == renewed_cwt);

    // Pre-existing empty 0700 directory: open_or_init_device succeeds.
    const auto empty_0700_dir = tmp.path / "empty_0700";
    require_ok(::mkdir(empty_0700_dir.c_str(), mode_t{0700}) == 0);
    const auto from_empty =
        MpIdentityStore::open_or_init_device(empty_0700_dir, "api.empty.test");
    require_ok(from_empty.has_value());
    require_ok(!from_empty.value().state().root_seed.has_value());
    require_ok(from_empty.value().state().authority == "api.empty.test");
    require_ok(std::filesystem::exists(empty_0700_dir / "device.seed"));

    // Partial directory containing ONLY root.seed: open_or_init_device MUST fail closed
    // with keystore_corrupt and preserve root.seed byte-for-byte!
    const auto partial_dir = tmp.path / "partial_root_only";
    require_ok(::mkdir(partial_dir.c_str(), mode_t{0700}) == 0);
    const auto partial_root_path = partial_dir / "root.seed";
    {
      std::ofstream ofs{partial_root_path, std::ios::binary};
      ofs.write(reinterpret_cast<const char *>(root_seed.bytes().data()), 32);
    }
    require_ok(::chmod(partial_root_path.c_str(), mode_t{0600}) == 0);
    const auto partial_res =
        MpIdentityStore::open_or_init_device(partial_dir, "api.partial.test");
    require_ok(!partial_res.has_value());
    require_ok(mp_client_error_of(partial_res.error()) ==
               MpClientError::keystore_corrupt);
    require_ok(!std::filesystem::exists(partial_dir / "device.seed"));
    {
      std::ifstream ifs{partial_root_path, std::ios::binary};
      Ed25519Seed after_bytes{};
      ifs.read(reinterpret_cast<char *>(after_bytes.data()), 32);
      require_ok(ifs.gcount() == 32);
      require_ok(after_bytes == root_seed.bytes());
    }
  }

  std::cout << "PASS test_identity_store\n";
}

// ---------------------------------------------------------------------------
// Test 2: TLS 1.3 CA pinning, REST API, RFC 9421 verify, clock_skew retry, WS
// ---------------------------------------------------------------------------

void test_loopback_tls_rest_and_ws() {
  TempDir tmp{"tls"};
  const auto server_cert =
      generate_self_signed_cert(tmp.path / "server_ca.pem", "localhost");
  const auto wrong_cert =
      generate_self_signed_cert(tmp.path / "wrong_ca.pem", "localhost");

  LoopbackServerState srv_state{};
  const auto root_seed = CleansedSeed::generate().value();
  const auto dev_seed = CleansedSeed::generate().value();
  const auto root_key = Ed25519SigningKey::from_seed(root_seed.bytes()).value();
  const auto dev_key = Ed25519SigningKey::from_seed(dev_seed.bytes()).value();
  const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  const auto cwt =
      encode_device_cwt(root_key, DeviceCwtMintRequest{dev_key.public_key(), now_s - 5,
                                                       now_s + 86400})
          .value();

  srv_state.registered_root_pubkey = root_key.public_key();
  srv_state.registered_device_pubkey = dev_key.public_key();
  srv_state.registered_cwt = cwt;

  LoopbackTlsServer server{server_cert, srv_state};

  MpClientConfig base_cfg{};
  base_cfg.authority = "localhost";
  base_cfg.connect_host = "127.0.0.1";
  base_cfg.port = server.port();
  base_cfg.ca_bundle_path = server_cert.pem_path;
  base_cfg.connect_timeout_ms = 5000;
  base_cfg.io_timeout_ms = 5000;

  // 1. CA mismatch MUST fail closed!
  {
    MpClientConfig bad_ca_cfg = base_cfg;
    bad_ca_cfg.ca_bundle_path = wrong_cert.pem_path;
    MpControlClient bad_client{bad_ca_cfg};
    const auto bad_health = bad_client.health();
    require_ok(!bad_health.has_value());
    const auto err = mp_client_error_of(bad_health.error());
    require_ok(err == MpClientError::tls_verify_failed ||
               err == MpClientError::tls_handshake_failed);
  }

  // 2. Hostname mismatch MUST fail closed!
  {
    MpClientConfig bad_host_cfg = base_cfg;
    bad_host_cfg.authority = "wrong.example.invalid";
    MpControlClient bad_client{bad_host_cfg};
    const auto bad_health = bad_client.health();
    require_ok(!bad_health.has_value());
    const auto err = mp_client_error_of(bad_health.error());
    require_ok(err == MpClientError::tls_verify_failed ||
               err == MpClientError::tls_handshake_failed);
  }

  // 3. health() with Content-Length AND Transfer-Encoding: chunked
  MpControlClient client{base_cfg};
  const auto h1 = client.health();
  require_ok(h1.has_value());
  require_ok(h1.value().ok);
  require_ok(h1.value().server_now_ms > 0U);

  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.health_mode = HealthTestMode::chunked;
  }
  const auto h2 = client.health();
  require_ok(h2.has_value());
  require_ok(h2.value().ok);

  // 3b. Reject corrupt /v1/health timestamps (0 or > kMaxSafeId) and malformed HTTP
  //     framing (unsupported TE, TE+CL together, non-identity Content-Encoding).
  for (const auto mode :
       {HealthTestMode::bad_timestamp_zero, HealthTestMode::bad_timestamp_overflow}) {
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.health_mode = mode;
    }
    const auto bad_h = client.health();
    require_ok(!bad_h.has_value());
    require_ok(mp_client_error_of(bad_h.error()) ==
               MpClientError::http_response_schema);
  }
  for (const auto mode :
       {HealthTestMode::unsupported_te_gzip_chunked, HealthTestMode::both_te_and_cl,
        HealthTestMode::unsupported_ce_gzip}) {
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.health_mode = mode;
    }
    const auto bad_h = client.health();
    require_ok(!bad_h.has_value());
    require_ok(mp_client_error_of(bad_h.error()) ==
               MpClientError::http_malformed_response);
  }
  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.health_mode = HealthTestMode::normal;
  }

  // 4. register_account() (server verifies RFC 9421 + RFC 9530 via
  // mp::verify_rfc9421_request!)
  RegisterAccountRequest reg_req{};
  reg_req.invite_secret = "mpinv1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  reg_req.handle = "alice_test";
  reg_req.device_pubkey = dev_key.public_key();
  reg_req.device_label = "laptop";
  reg_req.device_cwt = cwt;
  const auto reg_res = client.register_account(root_key, reg_req);
  require_ok(reg_res.has_value());
  require_ok(reg_res.value().account_id == AccountId::create(1001U).value());
  require_ok(reg_res.value().device_id == DeviceId::create(2001U).value());
  require_ok(reg_res.value().handle == "alice_test");

  // Bind client identity
  MpIdentityState id_state{};
  id_state.root_seed = root_seed;
  id_state.device_seed = dev_seed;
  id_state.account_id = reg_res.value().account_id;
  id_state.device_id = reg_res.value().device_id;
  id_state.handle = reg_res.value().handle;
  id_state.authority = base_cfg.authority;
  id_state.device_cwt = cwt;
  client.set_identity(std::move(id_state));

  // 5. clock_skew automatic self-healing retry!
  const int health_before = [&]() {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    return srv_state.health_calls;
  }();
  client.set_clock_offset_seconds(600); // 10 minutes skewed forward!
  const auto me = client.whoami();
  require_ok(me.has_value());
  require_ok(me.value().account_id == AccountId::create(1001U).value());
  require_ok(me.value().handle == "alice_test");
  require_ok(me.value().devices.size() == 1U);
  require_ok(me.value().devices[0].pop_verified);
  require_ok(!me.value().devices[0].revoked_at_ms.has_value());
  require_ok(me.value().active_party_ids.size() == 1U);
  require_ok(std::abs(client.clock_offset_seconds()) <= 5);
  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    require_ok(srv_state.clock_skew_rejections == 1);
    require_ok(srv_state.health_calls == health_before + 1);
  }

  // 5b. Backward clock skew (-600s -> server returns 401 {"error":"expired",
  //     "server_now_ms":...}) ALSO self-heals cleanly!
  {
    const int health_pre_back = [&]() {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      return srv_state.health_calls;
    }();
    client.set_clock_offset_seconds(-600);
    const auto me_back = client.whoami();
    require_ok(me_back.has_value());
    require_ok(std::abs(client.clock_offset_seconds()) <= 5);
    std::lock_guard<std::mutex> lk{srv_state.mu};
    require_ok(srv_state.clock_skew_rejections == 2);
    require_ok(srv_state.health_calls == health_pre_back + 1);
  }

  // 5c. Genuine 401 {"error":"expired","server_now_ms":now} with accurate clock
  //     MUST NOT retry as clock_skew (preserves CWT expiry http_unauthorized).
  {
    const int health_pre_cwt = [&]() {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.force_non_skew_expired_401 = true;
      return srv_state.health_calls;
    }();
    const auto cwt_exp = client.whoami();
    require_ok(!cwt_exp.has_value());
    require_ok(mp_client_error_of(cwt_exp.error()) == MpClientError::http_unauthorized);
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.force_non_skew_expired_401 = false;
    require_ok(srv_state.health_calls == health_pre_cwt);
  }

  // 5d. Extreme clock_offset_seconds (INT64_MAX / INT64_MIN) fails cleanly (zero UB!).
  {
    client.set_clock_offset_seconds(std::numeric_limits<std::int64_t>::max());
    const auto ovf1 = client.whoami();
    require_ok(!ovf1.has_value());
    require_ok(mp_client_error_of(ovf1.error()) == MpClientError::invalid_config);
    client.set_clock_offset_seconds(std::numeric_limits<std::int64_t>::min());
    const auto ovf2 = client.whoami();
    require_ok(!ovf2.has_value());
    require_ok(mp_client_error_of(ovf2.error()) == MpClientError::invalid_config);
    client.set_clock_offset_seconds(0);
  }

  // 6. resolve_handle (@query signed!)
  const auto resolved = client.resolve_handle("alice_test");
  require_ok(resolved.has_value());
  require_ok(resolved.value().account_id == AccountId::create(1001U).value());
  require_ok(resolved.value().root_pubkey == root_key.public_key());

  // 7. enroll_device + revoke_device (.root keyid)
  const auto enrolled = client.enroll_device(
      EnrollDeviceRequest{dev_key.public_key(), "wintermute", cwt});
  require_ok(enrolled.has_value());
  require_ok(enrolled.value().device_id == DeviceId::create(2002U).value());

  const auto revoked = client.revoke_device(enrolled.value().device_id);
  require_ok(revoked.has_value());
  require_ok(revoked.value().revoked);
  require_ok(revoked.value().evicted_parties.size() == 1U);

  // 7b. Web account portal approval: approve_web_session() validation, normalization,
  //     and 400/404/410 HTTP error mapping.
  {
    const auto ok_upper = client.approve_web_session("ABCD-EFGH");
    require_ok(ok_upper.has_value());
    require_ok(ok_upper.value().approved);
    require_ok(ok_upper.value().scope == "account:read");
    require_ok(ok_upper.value().expires_at_ms.has_value());

    const auto ok_lower_hyphen = client.approve_web_session("abcd-efgh");
    require_ok(ok_lower_hyphen.has_value());
    require_ok(ok_lower_hyphen.value().approved);
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      require_ok(srv_state.last_web_approve_code == "ABCD-EFGH");
    }

    const auto ok_lower_no_hyphen = client.approve_web_session("abcdefgh");
    require_ok(ok_lower_no_hyphen.has_value());
    require_ok(ok_lower_no_hyphen.value().approved);
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      require_ok(srv_state.last_web_approve_code == "ABCD-EFGH");
    }

    // Invalid codes MUST be rejected with ErrorCode::invalid_range BEFORE hitting the
    // network!
    const int calls_before_invalid = [&]() {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      return srv_state.verified_rfc9421_calls;
    }();
    for (const std::string_view bad_code : std::array<std::string_view, 9>{
             "",
             "123",
             "ABCD-EFGI",
             "ABCD-EFGL",
             "ABCD-EFGO",
             "ABCD-EFGU",
             "ABC-DEFGH",
             "ABCD-EFGH-1",
             "ABCD-EFG\n",
         }) {
      const auto bad = client.approve_web_session(bad_code);
      require_ok(!bad.has_value());
      require_ok(bad.error().code == ErrorCode::invalid_range);
    }
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      require_ok(srv_state.verified_rfc9421_calls == calls_before_invalid);
    }

    // HTTP 404, 410, and 400 error mapping
    const auto err_404 = client.approve_web_session("4040-0000");
    require_ok(!err_404.has_value());
    require_ok(mp_client_error_of(err_404.error()) == MpClientError::http_not_found);

    const auto err_410 = client.approve_web_session("4100-0000");
    require_ok(!err_410.has_value());
    require_ok(mp_client_error_of(err_410.error()) == MpClientError::http_gone);

    const auto err_400 = client.approve_web_session("4000-0000");
    require_ok(!err_400.has_value());
    require_ok(mp_client_error_of(err_400.error()) == MpClientError::http_bad_request);
  }

  // 8. Social graph (friends & blocks)
  const auto bob_id = AccountId::create(1002U).value();
  const auto freq = client.send_or_accept_friend(bob_id);
  require_ok(freq.has_value());
  require_ok(freq.value().http_status == 202);
  require_ok(freq.value().state == FriendEdgeState::invite_sent);

  const auto friends = client.list_friends();
  require_ok(friends.has_value());
  require_ok(friends.value().size() == 1U);
  require_ok(friends.value()[0].peer_account_id == bob_id);
  require_ok(friends.value()[0].state == FriendEdgeState::friend_edge);

  require_ok(client.block_account(bob_id).has_value());
  require_ok(client.remove_friend(bob_id).has_value());

  // 9. Party lifecycle (create, get, invite, revoke invite, join, kick, leave, disband)
  const EndpointDescriptor ep{
      TransportKind::iroh_quic, "https://relay.multiplayer.tech", {}};
  const auto created = client.create_party(CreatePartyRequest{
      PartyVisibility::friends,
      PartyJoinMode::invite_only,
      RelayPolicy::force_relays,
      4U,
      ep,
      "https://relay.multiplayer.tech",
  });
  require_ok(created.has_value());
  require_ok(created.value().party_id == PartyId::create(5001U).value());
  require_ok(created.value().party_epoch == 1U);

  const auto summary = client.get_party(created.value().party_id);
  require_ok(summary.has_value());
  require_ok(summary.value().party_id == created.value().party_id);
  require_ok(summary.value().relay_policy == RelayPolicy::force_relays);
  require_ok(summary.value().member_count == 2U);

  const auto inv = client.create_party_invite(
      CreatePartyInviteRequest{created.value().party_id, std::nullopt, 2U, 3600U});
  require_ok(inv.has_value());
  require_ok(inv.value().invite_link.has_value());
  require_ok(
      client.revoke_party_invite(created.value().party_id, inv.value().party_invite_id)
          .has_value());

  const auto joined = client.join_party(
      JoinPartyRequest{created.value().party_id, ep, inv.value().invite_link});
  require_ok(joined.has_value());
  require_ok(!joined.value().pending_approval);
  require_ok(joined.value().party_epoch == 2U);

  const auto kicked = client.kick_member(
      KickMemberRequest{created.value().party_id, bob_id, joined.value().party_epoch});
  require_ok(kicked.has_value());
  require_ok(kicked.value().party_epoch == 3U);

  const auto left = client.leave_party(created.value().party_id);
  require_ok(left.has_value());
  require_ok(left.value().party_epoch == 4U);

  const auto disbanded = client.disband_party(
      DisbandPartyRequest{created.value().party_id, left.value().party_epoch});
  require_ok(disbanded.has_value());
  require_ok(disbanded.value().party_epoch == 5U);

  // 10. Live TLS 1.3 RFC 6455 WebSocket upgrade + HELLO_ACK + fragmented PARTY_SNAPSHOT
  //     + RFC 6455 Ping->Pong + masked send_mp1 + MP1:PING->MP1:PONG + Close(4403)!
  {
    auto ws_res = client.connect_party_socket(created.value().party_id);
    require_ok(ws_res.has_value());
    MpControlSocket ws = std::move(ws_res).value();
    require_ok(ws.is_open());

    // Event 1: HELLO_ACK (coalesced directly after 101 headers!)
    const auto ev1 = ws.poll_event(3000);
    require_ok(ev1.has_value());
    const auto *f1 = std::get_if<MpWsMp1Frame>(&require_opt(ev1.value()));
    require_ok(f1 != nullptr);
    require_ok(f1->frame.header.opcode == Opcode::hello_ack);
    const auto *hello = std::get_if<HelloAckMessage>(&f1->frame.message);
    require_ok(hello != nullptr && hello->session_id == SessionId::create(99U).value());

    // Event 2: fragmented PARTY_SNAPSHOT with interleaved RFC 6455 Ping!
    const auto ev2 = ws.poll_event(3000);
    require_ok(ev2.has_value());
    const auto *f2 = std::get_if<MpWsMp1Frame>(&require_opt(ev2.value()));
    require_ok(f2 != nullptr);
    require_ok(f2->frame.header.opcode == Opcode::party_snapshot);
    const auto *snap = std::get_if<PartySnapshotMessage>(&f2->frame.message);
    require_ok(snap != nullptr);
    require_ok(snap->party_id == created.value().party_id);
    require_ok(snap->members.size() == 1U);

    // Send masked MP1 binary frame + "MP1:PING" heartbeat
    require_ok(ws.send_mp1(7U, PartyEndpointUpdateMessage{ep}).has_value());
    require_ok(ws.send_ping().has_value());

    // Event 3: "MP1:PONG"
    const auto ev3 = ws.poll_event(3000);
    require_ok(ev3.has_value());
    require_ok(std::holds_alternative<MpWsPong>(require_opt(ev3.value())));

    // Event 4: Close(4403)
    const auto ev4 = ws.poll_event(3000);
    require_ok(ev4.has_value());
    const auto *closed = std::get_if<MpWsClosed>(&require_opt(ev4.value()));
    require_ok(closed != nullptr && closed->code == 4403U);
    require_ok(!ws.is_open());

    std::lock_guard<std::mutex> lk{srv_state.mu};
    require_ok(srv_state.ws_received_masked_pong);
    require_ok(srv_state.ws_received_masked_endpoint_update);
    require_ok(srv_state.ws_received_masked_ping);
  }

  // 11. WebSocket negative security tests:
  // (a) Bad Sec-WebSocket-Accept
  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.ws_mode = WsTestMode::bad_accept;
  }
  {
    const auto ws_bad = client.connect_party_socket(created.value().party_id);
    require_ok(!ws_bad.has_value());
    require_ok(mp_client_error_of(ws_bad.error()) == MpClientError::ws_accept_mismatch);
  }

  // (b) Bad Sec-WebSocket-Protocol
  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.ws_mode = WsTestMode::bad_subprotocol;
  }
  {
    const auto ws_bad = client.connect_party_socket(created.value().party_id);
    require_ok(!ws_bad.has_value());
    require_ok(mp_client_error_of(ws_bad.error()) ==
               MpClientError::ws_subprotocol_mismatch);
  }

  // (c) Masked server->client frame rejected per RFC 6455 §5.1
  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.ws_mode = WsTestMode::masked_server_frame;
  }
  {
    auto ws_ok = client.connect_party_socket(created.value().party_id);
    require_ok(ws_ok.has_value());
    const auto ev = ws_ok.value().poll_event(3000);
    require_ok(!ev.has_value());
    require_ok(mp_client_error_of(ev.error()) == MpClientError::ws_masked_server_frame);
  }

  // (d) Oversized frame (> 8192 B) rejected!
  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.ws_mode = WsTestMode::oversized_frame;
  }
  {
    auto ws_ok = client.connect_party_socket(created.value().party_id);
    require_ok(ws_ok.has_value());
    const auto ev = ws_ok.value().poll_event(3000);
    require_ok(!ev.has_value());
    require_ok(mp_client_error_of(ev.error()) == MpClientError::ws_frame_too_large);
  }

  // (e) Duplicate Sec-WebSocket-Accept / Sec-WebSocket-Protocol & unsolicited
  // extensions
  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.ws_mode = WsTestMode::duplicate_accept;
  }
  {
    const auto ws_bad = client.connect_party_socket(created.value().party_id);
    require_ok(!ws_bad.has_value());
    require_ok(mp_client_error_of(ws_bad.error()) == MpClientError::ws_accept_mismatch);
  }
  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.ws_mode = WsTestMode::duplicate_subprotocol;
  }
  {
    const auto ws_bad = client.connect_party_socket(created.value().party_id);
    require_ok(!ws_bad.has_value());
    require_ok(mp_client_error_of(ws_bad.error()) ==
               MpClientError::ws_subprotocol_mismatch);
  }
  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.ws_mode = WsTestMode::unsolicited_extensions;
  }
  {
    const auto ws_bad = client.connect_party_socket(created.value().party_id);
    require_ok(!ws_bad.has_value());
    require_ok(mp_client_error_of(ws_bad.error()) == MpClientError::ws_protocol_error);
  }

  // (f) 0-byte continuation frame flood (> 64 fragments) rejected!
  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.ws_mode = WsTestMode::zero_byte_continuation_flood;
  }
  {
    auto ws_ok = client.connect_party_socket(created.value().party_id);
    require_ok(ws_ok.has_value());
    const auto ev = ws_ok.value().poll_event(3000);
    require_ok(!ev.has_value());
    require_ok(mp_client_error_of(ev.error()) == MpClientError::ws_protocol_error);
  }

  // (g) Chunked 401 clock_skew on WebSocket upgrade self-heals cleanly!
  {
    const int health_pre_ws = [&]() {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.ws_mode = WsTestMode::normal_party;
      srv_state.chunked_401_errors = true;
      return srv_state.health_calls;
    }();
    client.set_clock_offset_seconds(600);
    auto ws_healed = client.connect_party_socket(created.value().party_id);
    require_ok(ws_healed.has_value());
    require_ok(ws_healed.value().is_open());
    require_ok(std::abs(client.clock_offset_seconds()) <= 5);
    const auto ev = ws_healed.value().poll_event(3000);
    require_ok(ev.has_value());
    require_ok(ev.value().has_value());
    require_ok(ws_healed.value().close(1000U).has_value());
    std::lock_guard<std::mutex> lk{srv_state.mu};
    srv_state.chunked_401_errors = false;
    require_ok(srv_state.health_calls == health_pre_ws + 1);
  }

  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    require_ok(srv_state.verified_rfc9421_calls >= 15);
  }

  std::cout << "PASS test_loopback_tls_rest_and_ws\n";
}

} // namespace

int main() {
  test_identity_store();
  test_loopback_tls_rest_and_ws();
  std::cout << "ALL mp_client tests PASSED!\n";
  return 0;
}
