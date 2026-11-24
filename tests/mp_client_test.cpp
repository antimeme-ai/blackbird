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
  Ed25519PubKey link_device_pubkey{};
  std::string link_code = "W4K9-M2P7";
  std::string link_poll_token = "mpdl1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  std::string link_suggested_label;
  std::string link_claimed_label;
  std::string link_approved_cwt_b64;
  std::string last_poll_nonce;
  int link_status = 0; // 0=waiting_for_device, 1=pending_approval, 2=approved
  bool spoof_recover_root_pubkey = false;
  bool spoof_recover_safety_number = false;
  bool spoof_poll_wrong_device_cwt = false;
  bool spoof_poll_bad_root_cwt = false;
  bool spoof_poll_safety_number = false;
  std::string wrong_device_cwt_b64;
  Ed25519PubKey wrong_root_pubkey{};
  bool ws_received_masked_endpoint_update = false;
  bool ws_received_masked_ping = false;
  bool ws_received_masked_pong = false;
  WsTestMode ws_mode = WsTestMode::normal_party;
  bool enriched_friends_response = false;
  bool enriched_friends_alias_keys = false;
  bool mismatch_friend_handle_keys = false;
  bool spoof_friend_safety_number = false;
  bool bad_friend_handle = false;
  bool bad_friend_pubkey = false;
  Ed25519PubKey friend_root_pubkey{};
  std::string friend_handle = "bob_friend";
  int relay_ping_status = 200;
  std::string last_relay_ping_path;
  std::optional<std::string> get_party_override_json;
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

    // 1a. Unauthenticated relay /ping probe route
    if (method_str == "GET" && (path == "/ping" || path.ends_with("/ping"))) {
      int status = 200;
      {
        std::lock_guard<std::mutex> lk{state_.mu};
        state_.last_relay_ping_path = path;
        status = state_.relay_ping_status;
      }
      if (status == 204) {
        ssl_write_str(ssl, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
      } else if (status == 200) {
        ssl_write_str(ssl, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                           "Content-Length: 2\r\nConnection: close\r\n\r\nok");
      } else {
        ssl_write_str(ssl, "HTTP/1.1 " + std::to_string(status) +
                               " Service Unavailable\r\nContent-Length: 0\r\n"
                               "Connection: close\r\n\r\n");
      }
      SSL_shutdown(ssl);
      SSL_free(ssl);
      return;
    }

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

    // Determine which key signed this request (.root, rec., link., or device).
    const auto parsed_si = parse_signature_input(headers["signature-input"]);
    require_ok(parsed_si.has_value());
    Ed25519PubKey verify_pk{};
    {
      std::lock_guard<std::mutex> lk{state_.mu};
      if (std::holds_alternative<RootKeyId>(parsed_si.value().keyid) ||
          std::holds_alternative<RecoveryKeyId>(parsed_si.value().keyid)) {
        verify_pk = state_.registered_root_pubkey;
      } else if (std::holds_alternative<DeviceLinkKeyId>(parsed_si.value().keyid)) {
        verify_pk = state_.link_device_pubkey;
      } else {
        verify_pk = state_.registered_device_pubkey;
      }
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
    } else if (method_str == "POST" && path == "/v1/accounts/recover-lookup") {
      require_ok(std::holds_alternative<RecoveryKeyId>(parsed_si.value().keyid));
      const auto json = parse_json(body_str);
      require_ok(json.has_value());
      const Value *rpk_field = json.value().find("root_pubkey_b64");
      require_ok(rpk_field != nullptr &&
                 std::holds_alternative<std::string>(rpk_field->value()));
      const Ed25519PubKey resp_rpk = state_.spoof_recover_root_pubkey
                                         ? state_.wrong_root_pubkey
                                         : state_.registered_root_pubkey;
      const std::string sn =
          state_.spoof_recover_safety_number
              ? "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH"
              : compute_safety_number(AccountId::create(state_.account_id).value(),
                                      state_.registered_root_pubkey)
                    .value();
      const std::string body =
          "{\"account_id\":" + std::to_string(state_.account_id) + ",\"handle\":\"" +
          state_.handle + "\",\"root_pubkey_b64\":\"" + base64_encode_test(resp_rpk) +
          "\",\"safety_number\":\"" + sn +
          "\",\"devices\":[{\"device_id\":" + std::to_string(state_.device_id) +
          ",\"pubkey_b64\":\"" + base64_encode_test(state_.registered_device_pubkey) +
          "\",\"label\":\"laptop\",\"cwt_expires_ms\":" +
          std::to_string(now_ms + 86400000U) +
          ",\"generation\":1,\"pop_verified\":1,\"created_at_ms\":" +
          std::to_string(now_ms) + ",\"revoked_at_ms\":null}]}";
      send_json(ssl, 200, "OK", body);
    } else if (method_str == "POST" && path == "/v1/device-links/create") {
      require_ok(std::holds_alternative<RootKeyId>(parsed_si.value().keyid));
      const auto json = parse_json(body_str);
      require_ok(json.has_value());
      if (const Value *lbl = json.value().find("device_label");
          lbl != nullptr && std::holds_alternative<std::string>(lbl->value())) {
        state_.link_suggested_label = lbl->string();
      } else {
        state_.link_suggested_label.clear();
      }
      state_.link_status = 0;
      state_.link_claimed_label.clear();
      state_.link_approved_cwt_b64.clear();
      state_.last_poll_nonce.clear();
      send_json(ssl, 201, "Created",
                "{\"link_code\":\"" + state_.link_code +
                    "\",\"expires_at_ms\":" + std::to_string(now_ms + 300000U) + "}");
    } else if (method_str == "POST" && path == "/v1/device-links/claim") {
      require_ok(std::holds_alternative<DeviceLinkKeyId>(parsed_si.value().keyid));
      const auto json = parse_json(body_str);
      require_ok(json.has_value());
      const Value *lc = json.value().find("link_code");
      const Value *lbl = json.value().find("device_label");
      require_ok(lc != nullptr && std::holds_alternative<std::string>(lc->value()) &&
                 lc->string() == state_.link_code);
      require_ok(lbl != nullptr && std::holds_alternative<std::string>(lbl->value()));
      state_.link_claimed_label = lbl->string();
      state_.link_status = 1;
      // Deliberately return a spoofed server device_fingerprint to verify client
      // computes local_device_fingerprint locally!
      send_json(ssl, 200, "OK",
                "{\"poll_token\":\"" + state_.link_poll_token +
                    "\",\"device_fingerprint\":\"00000000-00000000-00000000-00000000\","
                    "\"expires_at_ms\":" +
                    std::to_string(now_ms + 300000U) + "}");
    } else if (method_str == "POST" && path == "/v1/device-links/inspect") {
      require_ok(std::holds_alternative<RootKeyId>(parsed_si.value().keyid));
      const auto json = parse_json(body_str);
      require_ok(json.has_value());
      const Value *lc = json.value().find("link_code");
      require_ok(lc != nullptr && std::holds_alternative<std::string>(lc->value()) &&
                 lc->string() == state_.link_code);
      if (state_.link_status == 0) {
        send_json(ssl, 200, "OK",
                  "{\"state\":\"waiting_for_device\",\"suggested_label\":\"" +
                      state_.link_suggested_label +
                      "\",\"created_at_ms\":" + std::to_string(now_ms) +
                      ",\"expires_at_ms\":" + std::to_string(now_ms + 300000U) + "}");
      } else {
        // Deliberately send a bogus server device_fingerprint to prove client computes
        // local_device_fingerprint from device_pubkey_b64!
        send_json(
            ssl, 200, "OK",
            "{\"state\":\"pending_approval\",\"device_pubkey_b64\":\"" +
                base64_encode_test(state_.link_device_pubkey) +
                "\",\"device_fingerprint\":\"ffffffff-ffffffff-ffffffff-ffffffff\","
                "\"device_label\":\"" +
                state_.link_claimed_label +
                "\",\"requester_country\":\"US\",\"created_at_ms\":" +
                std::to_string(now_ms) +
                ",\"expires_at_ms\":" + std::to_string(now_ms + 300000U) + "}");
      }
    } else if (method_str == "POST" && path == "/v1/device-links/approve") {
      require_ok(std::holds_alternative<RootKeyId>(parsed_si.value().keyid));
      const auto json = parse_json(body_str);
      require_ok(json.has_value());
      const Value *lc = json.value().find("link_code");
      const Value *cwt_f = json.value().find("device_cwt_b64");
      const Value *lbl_f = json.value().find("device_label");
      require_ok(lc != nullptr && lc->string() == state_.link_code);
      require_ok(cwt_f != nullptr &&
                 std::holds_alternative<std::string>(cwt_f->value()));
      require_ok(lbl_f != nullptr &&
                 std::holds_alternative<std::string>(lbl_f->value()));
      state_.link_approved_cwt_b64 = cwt_f->string();
      state_.link_claimed_label = lbl_f->string();
      state_.link_status = 2;
      const std::string fp =
          compute_device_fingerprint(state_.link_device_pubkey).value();
      send_json(
          ssl, 200, "OK",
          "{\"approved\":true,\"account_id\":" + std::to_string(state_.account_id) +
              ",\"device_id\":2099,\"device_label\":\"" + state_.link_claimed_label +
              "\",\"device_fingerprint\":\"" + fp +
              "\",\"cwt_expires_ms\":" + std::to_string(now_ms + 86400000U) + "}");
    } else if (method_str == "POST" && path == "/v1/device-links/poll") {
      require_ok(std::holds_alternative<DeviceLinkKeyId>(parsed_si.value().keyid));
      // Every poll MUST carry a fresh RFC 9421 nonce!
      require_ok(parsed_si.value().nonce != state_.last_poll_nonce);
      state_.last_poll_nonce = parsed_si.value().nonce;
      const auto json = parse_json(body_str);
      require_ok(json.has_value());
      const Value *lc = json.value().find("link_code");
      const Value *pt = json.value().find("poll_token");
      require_ok(lc != nullptr && lc->string() == state_.link_code);
      require_ok(pt != nullptr && pt->string() == state_.link_poll_token);
      if (state_.link_status < 2) {
        send_json(ssl, 202, "Accepted",
                  "{\"status\":\"pending\",\"expires_at_ms\":" +
                      std::to_string(now_ms + 300000U) + "}");
      } else {
        const Ed25519PubKey resp_rpk = state_.spoof_poll_bad_root_cwt
                                           ? state_.wrong_root_pubkey
                                           : state_.registered_root_pubkey;
        const std::string &resp_cwt_b64 = state_.spoof_poll_wrong_device_cwt
                                              ? state_.wrong_device_cwt_b64
                                              : state_.link_approved_cwt_b64;
        const std::string resp_sn =
            state_.spoof_poll_safety_number
                ? "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ"
                : compute_safety_number(AccountId::create(state_.account_id).value(),
                                        state_.registered_root_pubkey)
                      .value();
        send_json(ssl, 200, "OK",
                  "{\"status\":\"approved\",\"account_id\":" +
                      std::to_string(state_.account_id) + ",\"handle\":\"" +
                      state_.handle + "\",\"device_id\":2099,\"root_pubkey_b64\":\"" +
                      base64_encode_test(resp_rpk) + "\",\"device_cwt_b64\":\"" +
                      resp_cwt_b64 +
                      "\",\"cwt_expires_ms\":" + std::to_string(now_ms + 86400000U) +
                      ",\"safety_number\":\"" + resp_sn + "\"}");
      }
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
      if (state_.bad_friend_handle) {
        send_json(
            ssl, 200, "OK",
            "{\"friends\":[{\"peer_account_id\":1002,\"state\":0,\"updated_at_ms\":" +
                std::to_string(now_ms) + ",\"peer_handle\":\"bad\\u001b[31m\"}]}");
      } else if (state_.bad_friend_pubkey) {
        send_json(
            ssl, 200, "OK",
            "{\"friends\":[{\"peer_account_id\":1002,\"state\":0,\"updated_at_ms\":" +
                std::to_string(now_ms) +
                ",\"peer_root_pubkey_b64\":"
                "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}]}");
      } else if (state_.mismatch_friend_handle_keys) {
        send_json(
            ssl, 200, "OK",
            "{\"friends\":[{\"peer_account_id\":1002,\"state\":0,\"updated_at_ms\":" +
                std::to_string(now_ms) +
                ",\"peer_handle\":\"bob_friend\",\"handle\":\"mallory\"}]}");
      } else if (state_.enriched_friends_response) {
        const std::string h_key =
            state_.enriched_friends_alias_keys ? "handle" : "peer_handle";
        const std::string pk_key = state_.enriched_friends_alias_keys
                                       ? "root_pubkey_b64"
                                       : "peer_root_pubkey_b64";
        const std::string sn_key =
            state_.enriched_friends_alias_keys ? "safety_number" : "peer_safety_number";
        std::string body =
            "{\"friends\":[{\"peer_account_id\":1002,\"state\":0,\"updated_at_ms\":" +
            std::to_string(now_ms) + ",\"" + h_key + "\":\"" + state_.friend_handle +
            "\",\"" + pk_key + "\":\"" + base64_encode_test(state_.friend_root_pubkey) +
            "\"";
        if (state_.spoof_friend_safety_number) {
          body += ",\"" + sn_key + "\":\"AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH\"";
        }
        body += "},{\"peer_account_id\":1003,\"state\":3,\"updated_at_ms\":" +
                std::to_string(now_ms) + ",\"" + h_key + "\":\"blocked_peer\"}]}";
        send_json(ssl, 200, "OK", body);
      } else {
        send_json(
            ssl, 200, "OK",
            "{\"friends\":[{\"peer_account_id\":1002,\"state\":0,\"updated_at_ms\":" +
                std::to_string(now_ms) + "}]}");
      }
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
      if (state_.get_party_override_json.has_value()) {
        send_json(ssl, 200, "OK", *state_.get_party_override_json);
      } else {
        send_json(ssl, 200, "OK",
                  "{\"party_id\":" + std::to_string(state_.party_id) +
                      ",\"party_epoch\":" + std::to_string(state_.party_epoch) +
                      ",\"leader_account_id\":" + std::to_string(state_.account_id) +
                      ",\"leader_device_id\":" + std::to_string(state_.device_id) +
                      ",\"visibility\":1,\"join_mode\":0,\"relay_policy\":1,"
                      "\"pinned_relay_url\":\"https://relay.multiplayer.tech\","
                      "\"max_members\":4,\"member_count\":2}");
      }
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

  // 8. Social graph (friends & blocks): legacy + enriched FriendEdge + relay probe
  const auto bob_id = AccountId::create(1002U).value();
  const auto freq = client.send_or_accept_friend(bob_id);
  require_ok(freq.has_value());
  require_ok(freq.value().http_status == 202);
  require_ok(freq.value().state == FriendEdgeState::invite_sent);

  // 8a. Legacy /v1/friends payload (no handle/root_pubkey_b64 -> nullopt)
  const auto friends = client.list_friends();
  require_ok(friends.has_value());
  require_ok(friends.value().size() == 1U);
  require_ok(friends.value()[0].peer_account_id == bob_id);
  require_ok(friends.value()[0].state == FriendEdgeState::friend_edge);
  require_ok(!friends.value()[0].handle.has_value());
  require_ok(!friends.value()[0].root_pubkey.has_value());
  require_ok(!friends.value()[0].safety_number.has_value());

  // 8b. Enriched /v1/friends payload: live server peer_handle + peer_root_pubkey_b64
  //     (MUST ignore any spoofed server peer_safety_number; blocked edge has
  //     peer_handle only without pubkey/safety_number!) plus fallback alias keys.
  {
    const auto bob_root_key = Ed25519SigningKey::generate().value();
    const auto expected_bob_sn =
        compute_safety_number(bob_id, bob_root_key.public_key()).value();
    const auto blocked_id = AccountId::create(1003U).value();

    // Live server canonical keys: peer_handle, peer_root_pubkey_b64, peer_safety_number
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.enriched_friends_response = true;
      srv_state.enriched_friends_alias_keys = false;
      srv_state.spoof_friend_safety_number = true;
      srv_state.friend_root_pubkey = bob_root_key.public_key();
      srv_state.friend_handle = "bob_friend";
    }
    const auto enriched = client.list_friends();
    require_ok(enriched.has_value());
    require_ok(enriched.value().size() == 2U);
    require_ok(enriched.value()[0].peer_account_id == bob_id);
    require_ok(enriched.value()[0].handle == std::optional<std::string>{"bob_friend"});
    require_ok(enriched.value()[0].root_pubkey ==
               std::optional<Ed25519PubKey>{bob_root_key.public_key()});
    require_ok(enriched.value()[0].safety_number ==
               std::optional<std::string>{expected_bob_sn});
    // Blocked edge (state == 3): peer_handle present, pubkey/safety_number omitted
    require_ok(enriched.value()[1].peer_account_id == blocked_id);
    require_ok(enriched.value()[1].state == FriendEdgeState::blocked);
    require_ok(enriched.value()[1].handle ==
               std::optional<std::string>{"blocked_peer"});
    require_ok(!enriched.value()[1].root_pubkey.has_value());
    require_ok(!enriched.value()[1].safety_number.has_value());

    // Fallback alias keys: handle + root_pubkey_b64
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.enriched_friends_alias_keys = true;
    }
    const auto alias_enriched = client.list_friends();
    require_ok(alias_enriched.has_value());
    require_ok(alias_enriched.value().size() == 2U);
    require_ok(alias_enriched.value()[0].handle ==
               std::optional<std::string>{"bob_friend"});
    require_ok(alias_enriched.value()[0].safety_number ==
               std::optional<std::string>{expected_bob_sn});

    // Negative: conflicting peer_handle vs handle fails closed
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.mismatch_friend_handle_keys = true;
    }
    const auto mismatch_h = client.list_friends();
    require_ok(!mismatch_h.has_value());
    require_ok(mp_client_error_of(mismatch_h.error()) ==
               MpClientError::http_response_schema);

    // Negative: bad peer_handle with ANSI escape fails closed
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.mismatch_friend_handle_keys = false;
      srv_state.bad_friend_handle = true;
    }
    const auto bad_h = client.list_friends();
    require_ok(!bad_h.has_value());
    require_ok(mp_client_error_of(bad_h.error()) ==
               MpClientError::http_response_schema);

    // Negative: weak all-zero Ed25519 peer_root_pubkey_b64 fails closed
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.bad_friend_handle = false;
      srv_state.bad_friend_pubkey = true;
    }
    const auto bad_pk = client.list_friends();
    require_ok(!bad_pk.has_value());

    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.bad_friend_pubkey = false;
      srv_state.enriched_friends_response = false;
      srv_state.enriched_friends_alias_keys = false;
      srv_state.spoof_friend_safety_number = false;
    }
  }

  // 8c. Relay liveness probe (probe_relay: 200, 204, 503, custom base path, bad URLs)
  {
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.relay_ping_status = 200;
    }
    const auto probe_200 = client.probe_relay(
        "https://localhost", std::string_view{"127.0.0.1"}, server.port());
    require_ok(probe_200.has_value());
    require_ok(probe_200.value().ok);
    require_ok(probe_200.value().http_status == 200);
    require_ok(probe_200.value().url == "https://localhost/ping");
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      require_ok(srv_state.last_relay_ping_path == "/ping");
    }

    // Custom base path + 204 No Content
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.relay_ping_status = 204;
    }
    const auto probe_204 = client.probe_relay(
        "https://localhost/relay/", std::string_view{"127.0.0.1"}, server.port());
    require_ok(probe_204.has_value());
    require_ok(probe_204.value().ok);
    require_ok(probe_204.value().http_status == 204);
    require_ok(probe_204.value().url == "https://localhost/relay/ping");
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      require_ok(srv_state.last_relay_ping_path == "/relay/ping");
    }

    // 503 Service Unavailable -> Result succeeds with ok == false and http_status ==
    // 503
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.relay_ping_status = 503;
    }
    const auto probe_503 = client.probe_relay(
        "https://localhost", std::string_view{"127.0.0.1"}, server.port());
    require_ok(probe_503.has_value());
    require_ok(!probe_503.value().ok);
    require_ok(probe_503.value().http_status == 503);

    // Invalid relay URLs MUST be rejected locally before any network I/O!
    for (const std::string_view bad_url : std::array<std::string_view, 11>{
             "",
             "http://localhost",
             "https://",
             "https://localhost/bad path",
             "https://localhost\r\nEvil: 1",
             "https://localhost?q=1",
             "https://localhost#frag",
             "https://user@localhost",
             "https://localhost:99999",
             "https://localhost/p\xc3\xa9ng",
             "https://loc\x80lhost",
         }) {
      const auto bad_probe =
          client.probe_relay(bad_url, std::string_view{"127.0.0.1"}, server.port());
      require_ok(!bad_probe.has_value());
      require_ok(mp_client_error_of(bad_probe.error()) ==
                 MpClientError::invalid_config);
    }
    const auto bad_port =
        client.probe_relay("https://localhost", std::string_view{"127.0.0.1"}, 0U);
    require_ok(!bad_port.has_value());
    require_ok(mp_client_error_of(bad_port.error()) == MpClientError::invalid_config);
  }

  // 8d. connect_social_ws() connects cleanly to GET /v1/ws
  {
    auto social_ws = client.connect_social_ws();
    require_ok(social_ws.has_value());
    require_ok(social_ws.value().is_open());
    const auto hello_ev = social_ws.value().poll_event(3000);
    require_ok(hello_ev.has_value() && hello_ev.value().has_value());
    require_ok(social_ws.value().close(1000U).has_value());
  }

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
  require_ok(!summary.value().org_id.has_value());
  require_ok(!summary.value().group_id.has_value());
  require_ok(summary.value().external_guest_account_ids.empty());

  // 9b. Live Org-Scoped GET /v1/parties/:id metadata & fail-closed validation.
  {
    const std::string base_prefix =
        "{\"party_id\":5001,\"party_epoch\":1,\"leader_account_id\":1001,"
        "\"leader_device_id\":2001,\"visibility\":1,\"join_mode\":0,"
        "\"relay_policy\":1,\"pinned_relay_url\":\"https://relay.multiplayer.tech\","
        "\"max_members\":4,\"member_count\":3";

    auto set_party_json = [&](std::optional<std::string> body) {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.get_party_override_json = std::move(body);
    };

    // Org party with string org_id, group_id, and mixed integer + string guest IDs
    // (including duplicate that must be deduplicated cleanly).
    set_party_json(base_prefix +
                   ",\"org_id\":\"org_9000\",\"group_id\":\"grp_eng\","
                   "\"external_guest_account_ids\":[\"9001\",9002,\"9001\"]}");
    const auto org_summary = client.get_party(created.value().party_id);
    require_ok(org_summary.has_value());
    require_ok(org_summary.value().org_id == std::optional<std::string>{"org_9000"});
    require_ok(org_summary.value().group_id == std::optional<std::string>{"grp_eng"});
    require_ok(org_summary.value().external_guest_account_ids.size() == 2U);
    require_ok(org_summary.value().external_guest_account_ids[0] ==
               AccountId::create(9001U).value());
    require_ok(org_summary.value().external_guest_account_ids[1] ==
               AccountId::create(9002U).value());

    // Org party with uint64 org_id preserved as canonical decimal string + explicit
    // nulls ignored cleanly.
    set_party_json(base_prefix + ",\"org_id\":424242,\"group_id\":null,"
                                 "\"external_guest_account_ids\":null}");
    const auto org_u64 = client.get_party(created.value().party_id);
    require_ok(org_u64.has_value());
    require_ok(org_u64.value().org_id == std::optional<std::string>{"424242"});
    require_ok(!org_u64.value().group_id.has_value());
    require_ok(org_u64.value().external_guest_account_ids.empty());

    // Malformed org / external_guest_account_ids MUST fail closed!
    for (const std::string_view bad_suffix : std::array<std::string_view, 11>{
             ",\"external_guest_account_ids\":\"9001\"}",
             ",\"external_guest_account_ids\":9001}",
             ",\"external_guest_account_ids\":[\"not_a_number\"]}",
             ",\"external_guest_account_ids\":[\"0\"]}",
             ",\"external_guest_account_ids\":[\"-5\"]}",
             ",\"external_guest_account_ids\":[0]}",
             ",\"external_guest_account_ids\":[9007199254740992]}",
             ",\"external_guest_account_ids\":[true]}",
             ",\"org_id\":\"\"}",
             ",\"org_id\":0}",
             ",\"group_id\":123}",
         }) {
      set_party_json(base_prefix + std::string{bad_suffix});
      const auto bad = client.get_party(created.value().party_id);
      require_ok(!bad.has_value());
      require_ok(mp_client_error_of(bad.error()) ==
                 MpClientError::http_response_schema);
    }

    set_party_json(std::nullopt);
  }

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

  // 12. Identity Portability v1 REST endpoints (recover-lookup + full 5-step
  //     device-links flow + local CWT/pubkey/fingerprint/safety-number verification!)
  {
    // 12a. normalize_device_link_code (Crockford typo aliases O->0, I/L->1; reject U)
    require_ok(normalize_device_link_code("w4k9-m2p7").value() == "W4K9-M2P7");
    require_ok(normalize_device_link_code("w4k9m2p7").value() == "W4K9-M2P7");
    require_ok(normalize_device_link_code("oOiI-lL01").value() == "0011-1101");
    require_ok(!normalize_device_link_code("W4K9-M2PU").has_value());
    require_ok(!normalize_device_link_code("W4K9-M2P\n").has_value());

    const auto other_root_key = Ed25519SigningKey::generate().value();
    const auto new_dev_key = Ed25519SigningKey::generate().value();
    const auto expected_sn =
        compute_safety_number(AccountId::create(1001U).value(), root_key.public_key())
            .value();
    const auto expected_dev_fp =
        compute_device_fingerprint(new_dev_key.public_key()).value();
    const auto wrong_dev_cwt =
        encode_device_cwt(root_key, DeviceCwtMintRequest{dev_key.public_key(),
                                                         now_s - 5, now_s + 86400})
            .value();
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.link_device_pubkey = new_dev_key.public_key();
      srv_state.wrong_root_pubkey = other_root_key.public_key();
      srv_state.wrong_device_cwt_b64 = base64_encode_test(wrong_dev_cwt);
    }

    // 12b. recover_account_lookup: happy path + spoofed safety_number recomputed
    // locally
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.spoof_recover_safety_number = true;
      srv_state.spoof_recover_root_pubkey = false;
    }
    MpControlClient unauth_client{base_cfg};
    const auto rec_ok = unauth_client.recover_account_lookup(root_key);
    require_ok(rec_ok.has_value());
    require_ok(rec_ok.value().account_id == AccountId::create(1001U).value());
    require_ok(rec_ok.value().handle == "alice_test");
    require_ok(rec_ok.value().root_pubkey == root_key.public_key());
    require_ok(rec_ok.value().safety_number == expected_sn);
    require_ok(rec_ok.value().devices.size() == 1U);

    // 12c. recover_account_lookup MUST reject mismatched server root_pubkey!
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.spoof_recover_root_pubkey = true;
      srv_state.spoof_recover_safety_number = false;
    }
    const auto rec_bad_pk = unauth_client.recover_account_lookup(root_key);
    require_ok(!rec_bad_pk.has_value());
    require_ok(mp_client_error_of(rec_bad_pk.error()) ==
               MpClientError::http_response_schema);
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.spoof_recover_root_pubkey = false;
    }

    // 12d. Device-only client MUST be refused locally on .root-only create_device_link
    {
      MpIdentityState dev_only{};
      dev_only.device_seed = dev_seed;
      dev_only.account_id = AccountId::create(1001U).value();
      dev_only.device_id = DeviceId::create(2001U).value();
      dev_only.handle = "alice_test";
      dev_only.authority = base_cfg.authority;
      MpControlClient dev_client{base_cfg, std::move(dev_only)};
      const auto no_root = dev_client.create_device_link("wintermute");
      require_ok(!no_root.has_value());
      require_ok(mp_client_error_of(no_root.error()) ==
                 MpClientError::missing_root_key);
    }

    // 12e. Invalid device label rejected BEFORE hitting network
    const auto bad_lbl = client.create_device_link(std::string{"bad\x1b[31m"});
    require_ok(!bad_lbl.has_value());
    require_ok(mp_error_of(bad_lbl.error()) == MpError::invalid_device_label);

    // 12f. Step A: Primary (.root) creates device link
    const auto link_created = client.create_device_link(std::string{"wintermute"});
    require_ok(link_created.has_value());
    require_ok(link_created.value().link_code == "W4K9-M2P7");
    require_ok(link_created.value().expires_at_ms > 0U);

    // 12g. Step C (before claim): inspect returns waiting_for_device
    const auto insp_wait = client.inspect_device_link(link_created.value().link_code);
    require_ok(insp_wait.has_value());
    require_ok(insp_wait.value().state == DeviceLinkState::waiting_for_device);
    require_ok(insp_wait.value().suggested_label ==
               std::optional<std::string>{"wintermute"});
    require_ok(!insp_wait.value().device_pubkey.has_value());

    // 12h. Step B: New machine claims link (using lowercase without hyphen!)
    const auto claimed =
        unauth_client.claim_device_link("w4k9m2p7", new_dev_key, "wintermute");
    require_ok(claimed.has_value());
    require_ok(claimed.value().poll_token.starts_with("mpdl1_"));
    // Client MUST compute local_device_fingerprint locally (ignoring spoofed server
    // fp!)
    require_ok(claimed.value().server_device_fingerprint ==
               "00000000-00000000-00000000-00000000");
    require_ok(claimed.value().local_device_fingerprint == expected_dev_fp);

    // 12i. Step C (after claim): inspect returns pending_approval + local fingerprint
    const auto insp_pending =
        client.inspect_device_link(link_created.value().link_code);
    require_ok(insp_pending.has_value());
    require_ok(insp_pending.value().state == DeviceLinkState::pending_approval);
    require_ok(insp_pending.value().device_pubkey.has_value() &&
               *insp_pending.value().device_pubkey == new_dev_key.public_key());
    require_ok(insp_pending.value().local_device_fingerprint ==
               std::optional<std::string>{expected_dev_fp});
    require_ok(insp_pending.value().requester_country ==
               std::optional<std::string>{"US"});

    // 12j. Step E (before approve): poll returns 202 pending
    const auto poll_wait = unauth_client.poll_device_link(
        new_dev_key, PollDeviceLinkRequest{link_created.value().link_code,
                                           claimed.value().poll_token});
    require_ok(poll_wait.has_value());
    require_ok(poll_wait.value().pending);
    require_ok(!poll_wait.value().approved);
    require_ok(poll_wait.value().expires_at_ms.has_value());

    // 12k. Step D: Primary signs 30-day CWT locally and approves!
    const auto new_dev_cwt =
        encode_device_cwt(root_key, DeviceCwtMintRequest{new_dev_key.public_key(),
                                                         now_s - 5, now_s + 86400})
            .value();
    const auto approved = client.approve_device_link(ApproveDeviceLinkRequest{
        link_created.value().link_code,
        require_opt(insp_pending.value().device_pubkey),
        new_dev_cwt,
        "wintermute",
    });
    require_ok(approved.has_value());
    require_ok(approved.value().approved);
    require_ok(approved.value().account_id == AccountId::create(1001U).value());
    require_ok(approved.value().device_id == DeviceId::create(2099U).value());
    require_ok(approved.value().device_fingerprint == expected_dev_fp);

    // 12l. Step E negative tests: poll MUST reject CWT for wrong device_pubkey OR wrong
    //      root_pubkey!
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.spoof_poll_wrong_device_cwt = true;
    }
    const auto poll_bad_dev = unauth_client.poll_device_link(
        new_dev_key, PollDeviceLinkRequest{link_created.value().link_code,
                                           claimed.value().poll_token});
    require_ok(!poll_bad_dev.has_value());
    require_ok(mp_error_of(poll_bad_dev.error()) == MpError::cwt_device_key_mismatch);

    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.spoof_poll_wrong_device_cwt = false;
      srv_state.spoof_poll_bad_root_cwt = true;
    }
    const auto poll_bad_root = unauth_client.poll_device_link(
        new_dev_key, PollDeviceLinkRequest{link_created.value().link_code,
                                           claimed.value().poll_token});
    require_ok(!poll_bad_root.has_value());
    require_ok(mp_error_of(poll_bad_root.error()) == MpError::cwt_issuer_mismatch ||
               mp_error_of(poll_bad_root.error()) == MpError::invalid_signature);

    // 12m. Step E happy path: poll returns 200 approved, verifies CWT locally, and
    //      recomputes safety_number locally (ignoring spoofed server safety_number!)
    {
      std::lock_guard<std::mutex> lk{srv_state.mu};
      srv_state.spoof_poll_bad_root_cwt = false;
      srv_state.spoof_poll_safety_number = true;
    }
    const auto poll_ok = unauth_client.poll_device_link(
        new_dev_key, PollDeviceLinkRequest{link_created.value().link_code,
                                           claimed.value().poll_token});
    require_ok(poll_ok.has_value());
    require_ok(!poll_ok.value().pending);
    require_ok(poll_ok.value().approved);
    require_ok(poll_ok.value().account_id == AccountId::create(1001U).value());
    require_ok(poll_ok.value().device_id == DeviceId::create(2099U).value());
    require_ok(poll_ok.value().handle == std::optional<std::string>{"alice_test"});
    require_ok(poll_ok.value().root_pubkey ==
               std::optional<Ed25519PubKey>{root_key.public_key()});
    require_ok(poll_ok.value().device_cwt == new_dev_cwt);
    require_ok(poll_ok.value().safety_number ==
               std::optional<std::string>{expected_sn});
  }

  {
    std::lock_guard<std::mutex> lk{srv_state.mu};
    require_ok(srv_state.verified_rfc9421_calls >= 22);
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
