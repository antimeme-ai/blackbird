#include "blackbird/mp_room_v2.hpp"

#include "blackbird/json.hpp"
#include "blackbird/mp_client.hpp"
#include "blackbird/mp_protocol.hpp"
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
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
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
using namespace blackbird::mp;

void require_ok(bool ok, std::source_location loc = std::source_location::current()) {
  if (!ok) {
    std::cerr << "mp_room_v2_test FAIL at " << loc.file_name() << ":" << loc.line()
              << "\n";
    std::abort();
  }
}

template <typename T>
T require_val(Result<T> res,
              std::source_location loc = std::source_location::current()) {
  if (!res.has_value()) {
    std::cerr << "mp_room_v2_test FAIL (Result error code="
              << static_cast<int>(res.error().code) << " detail=" << res.error().detail
              << ") at " << loc.file_name() << ":" << loc.line() << "\n";
    std::abort();
  }
  return std::move(res).value();
}

template <typename T>
const T &require_opt(const std::optional<T> &opt,
                     std::source_location loc = std::source_location::current()) {
  if (!opt.has_value()) {
    std::cerr << "mp_room_v2_test FAIL (empty optional) at " << loc.file_name() << ":"
              << loc.line() << "\n";
    std::abort();
  }
  return *opt;
}

struct TempDir {
  std::filesystem::path path;
  explicit TempDir(std::string_view tag) {
    static std::atomic<std::uint64_t> counter{0U};
    const auto id = counter.fetch_add(1U, std::memory_order_relaxed);
    path = std::filesystem::temp_directory_path() /
           ("bb_mp_room_v2_test_" + std::string{tag} + "_" +
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

std::string b64_encode(std::span<const std::uint8_t> bytes) {
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
  return b64_encode(std::span<const std::uint8_t>{digest.data(), len});
}

std::string to_lower_ascii(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (const char ch : s) {
    out.push_back((ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch + ('a' - 'A')) : ch);
  }
  return out;
}

std::string_view trim_spaces(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
    s.remove_prefix(1U);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
    s.remove_suffix(1U);
  return s;
}

void ssl_write_all(SSL *ssl, std::span<const std::uint8_t> data) {
  std::size_t off = 0U;
  while (off < data.size()) {
    const int n =
        SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
    if (n <= 0)
      break;
    off += static_cast<std::size_t>(n);
  }
}

void ssl_write_str(SSL *ssl, std::string_view s) {
  ssl_write_all(ssl, std::span<const std::uint8_t>{
                         reinterpret_cast<const std::uint8_t *>(s.data()), s.size()});
}

void send_server_text_ws_frame(SSL *ssl, std::string_view text) {
  std::vector<std::uint8_t> out;
  out.push_back(0x81U); // FIN + text
  if (text.size() <= 125U) {
    out.push_back(static_cast<std::uint8_t>(text.size()));
  } else {
    out.push_back(126U);
    out.push_back(static_cast<std::uint8_t>((text.size() >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(text.size() & 0xffU));
  }
  out.insert(out.end(), text.begin(), text.end());
  ssl_write_all(ssl, out);
}

struct ClientWsFrame {
  std::uint8_t opcode = 0U;
  std::string payload;
};

std::optional<ClientWsFrame> read_client_ws_frame(SSL *ssl, int sock_fd,
                                                  std::chrono::milliseconds timeout) {
  if (SSL_pending(ssl) == 0) {
    pollfd pfd{sock_fd, POLLIN, 0};
    const int rc = ::poll(&pfd, 1U, static_cast<int>(timeout.count()));
    if (rc <= 0)
      return std::nullopt;
  }
  auto read_exact = [&](std::uint8_t *dst, std::size_t n) -> bool {
    std::size_t got = 0U;
    while (got < n) {
      const int rc = SSL_read(ssl, dst + got, static_cast<int>(n - got));
      if (rc <= 0)
        return false;
      got += static_cast<std::size_t>(rc);
    }
    return true;
  };
  std::array<std::uint8_t, 2> hdr{};
  if (!read_exact(hdr.data(), 2U))
    return std::nullopt;
  ClientWsFrame f{};
  f.opcode = static_cast<std::uint8_t>(hdr[0] & 0x0fU);
  const bool masked = (hdr[1] & 0x80U) != 0U;
  std::uint64_t len = static_cast<std::uint64_t>(hdr[1] & 0x7fU);
  if (len == 126U) {
    std::array<std::uint8_t, 2> ext{};
    if (!read_exact(ext.data(), 2U))
      return std::nullopt;
    len = (static_cast<std::uint64_t>(ext[0]) << 8U) | ext[1];
  }
  std::array<std::uint8_t, 4> mask{};
  if (masked && !read_exact(mask.data(), 4U))
    return std::nullopt;
  std::vector<std::uint8_t> buf(static_cast<std::size_t>(len));
  if (len > 0U && !read_exact(buf.data(), static_cast<std::size_t>(len)))
    return std::nullopt;
  if (masked) {
    for (std::size_t i = 0U; i < buf.size(); ++i)
      buf[i] = static_cast<std::uint8_t>(buf[i] ^ mask[i % 4U]);
  }
  f.payload.assign(reinterpret_cast<const char *>(buf.data()), buf.size());
  return f;
}

int alpn_select_http11(SSL *, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *) {
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
// Full Loopback TLS 1.3 Mock `mp2` Control & Room Server
// ---------------------------------------------------------------------------

class MockMp2Server {
public:
  MockMp2Server(const EphemeralCert &cert, const Ed25519SigningKey &root_key,
                const Ed25519PubKey &dev_pubkey)
      : root_key_(root_key), dev_pubkey_(dev_pubkey) {
    ctx_.reset(SSL_CTX_new(TLS_server_method()));
    require_ok(ctx_ != nullptr);
    require_ok(SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_3_VERSION) == 1);
    require_ok(SSL_CTX_use_certificate(ctx_.get(), cert.cert.get()) == 1);
    require_ok(SSL_CTX_use_PrivateKey(ctx_.get(), cert.key.get()) == 1);
    SSL_CTX_set_alpn_select_cb(ctx_.get(), &alpn_select_http11, nullptr);

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    require_ok(listen_fd_ >= 0);
    const int one = 1;
    (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    require_ok(::bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) ==
               0);
    require_ok(::listen(listen_fd_, 16) == 0);
    socklen_t len = sizeof(addr);
    require_ok(::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len) ==
               0);
    port_ = ntohs(addr.sin_port);

    thread_ = std::thread([this]() { serve_loop(); });
  }

  ~MockMp2Server() {
    stop_.store(true, std::memory_order_release);
    if (listen_fd_ >= 0) {
      ::shutdown(listen_fd_, SHUT_RDWR);
      ::close(listen_fd_);
      listen_fd_ = -1;
    }
    if (thread_.joinable())
      thread_.join();
  }

  std::uint16_t port() const noexcept { return port_; }

  void request_drop_ws_once() { drop_ws_once_.store(true, std::memory_order_release); }

  int ws_connections() const noexcept {
    return ws_conn_count_.load(std::memory_order_acquire);
  }
  int resume_frames_received() const noexcept {
    return resume_count_.load(std::memory_order_acquire);
  }
  int ping_frames_received() const noexcept {
    return ping_count_.load(std::memory_order_acquire);
  }
  int unique_client_msgs_accepted() const {
    std::lock_guard<std::mutex> lock(mu_);
    return static_cast<int>(seen_client_msg_ids_.size());
  }
  int duplicate_client_msgs_seen() const noexcept {
    return dup_msg_count_.load(std::memory_order_acquire);
  }
  std::uint64_t last_resume_seq() const noexcept {
    return last_resume_seq_.load(std::memory_order_acquire);
  }

private:
  void send_http_json(SSL *ssl, int status, std::string_view json) {
    const std::string hdr =
        "HTTP/1.1 " + std::to_string(status) +
        " OK\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(json.size()) + "\r\nConnection: close\r\n\r\n";
    ssl_write_str(ssl, hdr);
    ssl_write_str(ssl, json);
  }

  void serve_loop() {
    while (!stop_.load(std::memory_order_acquire)) {
      pollfd pfd{listen_fd_, POLLIN, 0};
      const int rc = ::poll(&pfd, 1U, 50);
      if (rc <= 0)
        continue;
      const int cfd = ::accept(listen_fd_, nullptr, nullptr);
      if (cfd < 0)
        continue;
      handle_conn(cfd);
      ::close(cfd);
    }
  }

  void handle_conn(int cfd) {
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl{SSL_new(ctx_.get()), &SSL_free};
    if (!ssl || SSL_set_fd(ssl.get(), cfd) != 1 || SSL_accept(ssl.get()) != 1)
      return;

    std::string raw;
    std::array<char, 4096> buf{};
    std::size_t hdr_end = std::string::npos;
    while (hdr_end == std::string::npos) {
      const int n = SSL_read(ssl.get(), buf.data(), static_cast<int>(buf.size()));
      if (n <= 0)
        return;
      raw.append(buf.data(), static_cast<std::size_t>(n));
      hdr_end = raw.find("\r\n\r\n");
    }

    const std::string_view hdr_block{raw.data(), hdr_end};
    const std::size_t first_eol = hdr_block.find("\r\n");
    const std::string_view req_line = (first_eol == std::string_view::npos)
                                          ? hdr_block
                                          : hdr_block.substr(0, first_eol);
    const std::size_t sp1 = req_line.find(' ');
    const std::size_t sp2 = req_line.find(' ', sp1 + 1U);
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos)
      return;
    const std::string method{req_line.substr(0, sp1)};
    const std::string path{req_line.substr(sp1 + 1U, sp2 - sp1 - 1U)};

    std::map<std::string, std::string> headers;
    std::size_t pos = first_eol + 2U;
    while (pos < hdr_block.size()) {
      const std::size_t eol = hdr_block.find("\r\n", pos);
      const std::string_view line = (eol == std::string_view::npos)
                                        ? hdr_block.substr(pos)
                                        : hdr_block.substr(pos, eol - pos);
      const std::size_t colon = line.find(':');
      if (colon != std::string_view::npos) {
        headers[to_lower_ascii(line.substr(0, colon))] =
            std::string{trim_spaces(line.substr(colon + 1U))};
      }
      if (eol == std::string_view::npos)
        break;
      pos = eol + 2U;
    }

    std::string body = raw.substr(hdr_end + 4U);
    if (const auto it = headers.find("content-length"); it != headers.end()) {
      const auto need = static_cast<std::size_t>(std::stoull(it->second));
      while (body.size() < need) {
        const int n = SSL_read(ssl.get(), buf.data(), static_cast<int>(buf.size()));
        if (n <= 0)
          break;
        body.append(buf.data(), static_cast<std::size_t>(n));
      }
      body.resize(need);
    }

    // WebSocket mp2 upgrade
    if (path == "/v1/parties/1234567890/ws") {
      const std::string proto = headers["sec-websocket-protocol"];
      require_ok(proto == "mp2");
      const std::string accept = ws_accept_for(headers["sec-websocket-key"]);
      const std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                               "Upgrade: websocket\r\n"
                               "Connection: Upgrade\r\n"
                               "Sec-WebSocket-Accept: " +
                               accept + "\r\nSec-WebSocket-Protocol: mp2\r\n\r\n";
      ssl_write_str(ssl.get(), resp);
      handle_mp2_ws(ssl.get(), cfd);
      return;
    }

    const std::int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();

    if (method == "POST" && path == "/v1/auth/session/start") {
      send_http_json(
          ssl.get(), 200,
          R"({"flow_id":"flow_abc","poll_token":"tok_secret_123","user_code":"ABCD-EFGH","verify_url":"https://multiplayer.tech/login?code=ABCD-EFGH","expires_at_ms":1999999999000})");
      return;
    }

    if (method == "POST" && path == "/v1/auth/session/poll") {
      const int n = auth_poll_count_.fetch_add(1, std::memory_order_acq_rel);
      if (n == 0) {
        send_http_json(ssl.get(), 200, R"({"status":"pending"})");
        return;
      }
      const auto cwt = require_val(encode_device_cwt(
          root_key_, DeviceCwtMintRequest{dev_pubkey_, now_s - 60, now_s + 86400 * 7}));
      const std::string resp =
          std::string{
              R"({"status":"approved","account_id":3541107795115782,"handle":"antimeme","device_id":9001,"root_pubkey_b64":")"} +
          b64_encode(root_key_.public_key()) + R"(","device_cwt_b64":")" +
          b64_encode(cwt) +
          R"(","cwt_expires_ms":1999999999000,"session_token":"sess_tok_secret"})";
      send_http_json(ssl.get(), 200, resp);
      return;
    }

    if (method == "POST" && path == "/v1/devices/me/renew") {
      const auto cwt = require_val(encode_device_cwt(
          root_key_, DeviceCwtMintRequest{dev_pubkey_, now_s - 5, now_s + 86400 * 7}));
      const std::string resp = std::string{R"({"device_cwt_b64":")"} + b64_encode(cwt) +
                               R"(","cwt_expires_ms":)" +
                               std::to_string((now_s + 86400 * 7) * 1000LL) + "}";
      send_http_json(ssl.get(), 200, resp);
      return;
    }

    if (method == "POST" && path == "/v1/rooms/invite") {
      send_http_json(
          ssl.get(), 200,
          R"({"party_id":1234567890,"room_code":"KAIH","share_url":"https://multiplayer.tech/p/KAIH","handle_url":"https://multiplayer.tech/@antimeme","ws_path":"/v1/parties/1234567890/ws","invited_handle":"phall"})");
      return;
    }

    if (method == "POST" && path == "/v1/rooms/enter") {
      send_http_json(
          ssl.get(), 200,
          R"({"party_id":1234567890,"room_code":"KAIH","name":"antimeme's party","share_url":"https://multiplayer.tech/p/KAIH","ws_path":"/v1/parties/1234567890/ws","members":[{"account_id":3541107795115782,"handle":"antimeme","client":"blackbird","agent_name":"Blackbird","status":"live"},{"account_id":285954035275878,"handle":"phall","client":"outpost","agent_name":"Claude Code","status":"live"}]})");
      return;
    }

    if (method == "POST" && path == "/v1/rooms/leave") {
      send_http_json(ssl.get(), 200, R"({"left":true,"party_id":1234567890})");
      return;
    }

    if (method == "GET" && path == "/v1/friends/live") {
      send_http_json(
          ssl.get(), 200,
          R"({"friends":[{"account_id":285954035275878,"handle":"phall","state":"friend","presence":"in_party","client":"outpost","party_room_code":"KAIH","joinable":true},{"account_id":285954035275879,"handle":"mei","state":"friend","presence":"online","client":"blackbird","joinable":false},{"account_id":285954035275880,"handle":"sam","state":"friend","presence":"offline","client":"","joinable":false}],"pending_invites":[{"party_id":1234567890,"room_code":"KAIH","from_handle":"phall","created_at_ms":1795495422986}]})");
      return;
    }

    send_http_json(ssl.get(), 404, R"({"error":"not_found"})");
  }

  void handle_mp2_ws(SSL *ssl, int cfd) {
    const int conn_num = ws_conn_count_.fetch_add(1, std::memory_order_acq_rel) + 1;

    // On first connect, include seq=1 history event from @phall.
    // On reconnect (conn_num >= 2), include latest_seq=3 so client resumes from
    // last_seq!
    if (conn_num == 1) {
      send_server_text_ws_frame(
          ssl,
          R"({"v":2,"t":"hello","party_id":"1234567890","room_code":"KAIH","name":"antimeme's party","self":{"account_id":"3541107795115782","handle":"antimeme","client":"blackbird"},"latest_seq":1,"members":[{"account_id":"3541107795115782","handle":"antimeme","client":"blackbird","agent_name":"Blackbird","agent_state":"idle","status":"live"},{"account_id":"285954035275878","handle":"phall","client":"outpost","agent_name":"Claude Code","agent_state":"working","status":"live"}],"history":[{"v":2,"t":"event","seq":1,"ts_ms":1795495430000,"client_msg_id":"phall-1","sender":{"account_id":"285954035275878","handle":"phall","client":"outpost","agent_name":"Claude Code"},"target":"@all","kind":"chat","body_encoding":"utf8","body":"yo can you see this?"}]})");
      // Also push an agent_card event at seq=2 right away.
      send_server_text_ws_frame(
          ssl,
          R"({"v":2,"t":"event","seq":2,"ts_ms":1795495431000,"client_msg_id":"phall-card-1","sender":{"account_id":"285954035275878","handle":"phall","client":"outpost","agent_name":"Claude Code"},"target":"@all","kind":"agent_card","body_encoding":"utf8","body":"{\"title\":\"Fixed auth test\",\"summary\":\"2 files changed\",\"files\":[\"src/auth.ts\",\"tests/auth.test.ts\"]}"})");
      // Push a plain-English recoverable error notice.
      send_server_text_ws_frame(
          ssl,
          R"({"v":2,"t":"error","code":"rate_limited","message":"Slow down — retrying in 50ms","retry_ms":50})");
    } else {
      send_server_text_ws_frame(
          ssl,
          R"({"v":2,"t":"hello","party_id":"1234567890","room_code":"KAIH","name":"antimeme's party","self":{"account_id":"3541107795115782","handle":"antimeme","client":"blackbird"},"latest_seq":10,"members":[{"account_id":"3541107795115782","handle":"antimeme","client":"blackbird","agent_name":"Blackbird","agent_state":"idle","status":"live"},{"account_id":"285954035275878","handle":"phall","client":"outpost","agent_name":"Claude Code","agent_state":"idle","status":"live"}],"history":[]})");
    }

    while (!stop_.load(std::memory_order_acquire)) {
      if (drop_ws_once_.exchange(false, std::memory_order_acq_rel)) {
        // Simulate abrupt network drop without close frame!
        return;
      }
      auto frame = read_client_ws_frame(ssl, cfd, std::chrono::milliseconds{40});
      if (!frame.has_value())
        continue;
      if (frame->opcode == 0x08U)
        return;
      if (frame->opcode != 0x01U)
        continue;

      if (frame->payload == "MP2:PING") {
        ping_count_.fetch_add(1, std::memory_order_acq_rel);
        send_server_text_ws_frame(ssl, "MP2:PONG");
        continue;
      }

      const auto parsed = parse_json(frame->payload);
      if (!parsed.has_value() ||
          !std::holds_alternative<Value::Object>(parsed.value().value())) {
        continue;
      }
      const Value &obj = parsed.value();
      const Value *t_field = obj.find("t");
      if (t_field == nullptr || !std::holds_alternative<std::string>(t_field->value()))
        continue;
      const std::string &t = std::get<std::string>(t_field->value());

      if (t == "send") {
        const std::string cid =
            std::get<std::string>(obj.find("client_msg_id")->value());
        std::uint64_t assigned_seq = 0U;
        {
          std::lock_guard<std::mutex> lock(mu_);
          if (const auto it = seen_client_msg_ids_.find(cid);
              it != seen_client_msg_ids_.end()) {
            dup_msg_count_.fetch_add(1, std::memory_order_acq_rel);
            assigned_seq = it->second;
          } else {
            assigned_seq = next_seq_++;
            seen_client_msg_ids_.emplace(cid, assigned_seq);
          }
        }
        const std::string ack = std::string{R"({"v":2,"t":"ack","client_msg_id":")"} +
                                cid + R"(","seq":)" + std::to_string(assigned_seq) +
                                R"(,"ts_ms":1795495440000})";
        send_server_text_ws_frame(ssl, ack);
      } else if (t == "resume") {
        const auto *ls = std::get_if<Number>(&obj.find("last_seq")->value());
        std::uint64_t req_seq = 0U;
        if (ls != nullptr) {
          if (const auto *u = std::get_if<std::uint64_t>(&ls->storage()))
            req_seq = *u;
          else if (const auto *i = std::get_if<std::int64_t>(&ls->storage()))
            req_seq = static_cast<std::uint64_t>(*i);
        }
        last_resume_seq_.store(req_seq, std::memory_order_release);
        resume_count_.fetch_add(1, std::memory_order_acq_rel);
        // Replay a missed event at seq=10 AND re-send already-seen seq=1 to verify
        // client-side dedup!
        send_server_text_ws_frame(
            ssl,
            R"({"v":2,"t":"event","seq":1,"ts_ms":1795495430000,"client_msg_id":"phall-1","sender":{"account_id":"285954035275878","handle":"phall","client":"outpost","agent_name":"Claude Code"},"target":"@all","kind":"chat","body_encoding":"utf8","body":"yo can you see this?"})");
        send_server_text_ws_frame(
            ssl,
            R"({"v":2,"t":"event","seq":10,"ts_ms":1795495450000,"client_msg_id":"phall-missed-10","sender":{"account_id":"285954035275878","handle":"phall","client":"outpost","agent_name":"Claude Code"},"target":"@all","kind":"chat","body_encoding":"utf8","body":"missed while laptop slept"})");
      }
    }
  }

  const Ed25519SigningKey &root_key_;
  Ed25519PubKey dev_pubkey_{};
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx_{nullptr, &SSL_CTX_free};
  int listen_fd_ = -1;
  std::uint16_t port_ = 0U;
  std::atomic<bool> stop_{false};
  std::atomic<bool> drop_ws_once_{false};
  std::atomic<int> ws_conn_count_{0};
  std::atomic<int> resume_count_{0};
  std::atomic<int> ping_count_{0};
  std::atomic<int> dup_msg_count_{0};
  std::atomic<int> auth_poll_count_{0};
  std::atomic<std::uint64_t> last_resume_seq_{0U};
  mutable std::mutex mu_;
  std::uint64_t next_seq_ = 3U;
  std::map<std::string, std::uint64_t> seen_client_msg_ids_;
  std::thread thread_;
};

template <typename Pred> bool wait_until(Pred pred, int timeout_ms = 5000) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
  while (std::chrono::steady_clock::now() < deadline) {
    if (pred())
      return true;
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
  }
  return pred();
}

} // namespace

int main() {
  TempDir tmp{"mp2"};
  const auto cert =
      generate_self_signed_cert(tmp.path / "ca.pem", "api.multiplayer.tech");

  auto root_key = require_val(Ed25519SigningKey::generate());
  auto store = require_val(MpIdentityStore::open_or_init_device(
      tmp.path / "online", "api.multiplayer.tech"));
  auto dev_key = require_val(store.device_signing_key());

  MockMp2Server srv{cert, root_key, dev_key.public_key()};

  MpClientConfig cfg{};
  cfg.authority = "api.multiplayer.tech";
  cfg.connect_host = "127.0.0.1";
  cfg.port = srv.port();
  cfg.ca_bundle_path = cert.pem_path;
  cfg.connect_timeout_ms = 3000;
  cfg.io_timeout_ms = 3000;

  // 1. Browser-first cloud login flow (auth_session_start -> pending -> approved ->
  // install_cwt)
  {
    MpControlClient unauth_client{cfg};
    const auto started = require_val(unauth_client.auth_session_start(
        AuthSessionStartRequest{dev_key.public_key(), "MacBook Pro", "blackbird"}));
    require_ok(started.flow_id == "flow_abc");
    require_ok(started.user_code == "ABCD-EFGH");
    require_ok(started.verify_url == "https://multiplayer.tech/login?code=ABCD-EFGH");

    const auto poll1 = require_val(unauth_client.auth_session_poll(
        AuthSessionPollRequest{started.flow_id, started.poll_token}));
    require_ok(poll1.pending && !poll1.approved);

    const auto poll2 = require_val(unauth_client.auth_session_poll(
        AuthSessionPollRequest{started.flow_id, started.poll_token}));
    require_ok(poll2.approved && !poll2.pending);
    const auto &acct = require_opt(poll2.account_id);
    const auto &dev = require_opt(poll2.device_id);
    const auto &handle = require_opt(poll2.handle);
    require_ok(handle == "antimeme");
    require_ok(!poll2.device_cwt.empty());

    require_ok(store
                   .install_cwt(InstallDeviceCwtRequest{
                       acct,
                       dev,
                       handle,
                       poll2.device_cwt,
                       cfg.authority,
                       poll2.root_pubkey,
                       std::nullopt,
                   })
                   .has_value());
  }

  // 2. Silent device CWT renewal + expiry extraction
  MpControlClient client{cfg, store.state()};
  {
    const auto exp_before =
        require_val(device_cwt_expiry_unix_seconds(store.state().device_cwt));
    require_ok(exp_before > 0);
    const auto renewed = require_val(client.renew_device_cwt());
    require_ok(!renewed.device_cwt.empty());
    require_ok(renewed.cwt_expires_ms > 0U);
    const auto &acct = require_opt(store.state().account_id);
    const auto &dev = require_opt(store.state().device_id);
    require_ok(store
                   .install_cwt(InstallDeviceCwtRequest{
                       acct,
                       dev,
                       store.state().handle,
                       renewed.device_cwt,
                       cfg.authority,
                       root_key.public_key(),
                       std::nullopt,
                   })
                   .has_value());
    client.set_identity(store.state());
  }

  // 3. v2 Room REST APIs: invite, enter, friends_live, leave
  const auto invited = require_val(client.room_invite(
      RoomInviteRequest{std::string{"@phall"}, std::nullopt, std::string{"Build"}}));
  require_ok(invited.party_id.value() == 1234567890ULL);
  require_ok(invited.room_code == "KAIH");
  require_ok(invited.share_url == "https://multiplayer.tech/p/KAIH");
  require_ok(invited.ws_path == "/v1/parties/1234567890/ws");
  require_ok(invited.invited_handle.has_value() && *invited.invited_handle == "phall");

  const auto entered = require_val(
      client.room_enter(RoomEnterRequest{"@phall", "blackbird", "Blackbird"}));
  require_ok(entered.party_id.value() == 1234567890ULL);
  require_ok(entered.room_code == "KAIH");
  require_ok(entered.members.size() == 2U);
  require_ok(entered.members[1].handle == "phall");

  const auto flive = require_val(client.friends_live());
  require_ok(flive.friends.size() == 3U);
  require_ok(flive.friends[0].handle == "phall" && flive.friends[0].joinable);
  require_ok(flive.pending_invites.size() == 1U &&
             flive.pending_invites[0].from_handle == "phall");

  // 4. Live MpRoomV2Session over `mp2` TLS 1.3 WebSocket
  MpRoomV2Config rcfg{};
  rcfg.client_config = cfg;
  rcfg.identity = store.state();
  rcfg.party_id = entered.party_id;
  rcfg.ws_path = entered.ws_path;
  rcfg.room_code = entered.room_code;
  rcfg.room_name = entered.name;
  rcfg.share_url = entered.share_url;
  rcfg.initial_members = entered.members;
  rcfg.poll_interval_ms = 20U;
  rcfg.ping_interval_ms = 1000U;
  rcfg.reconnect_base_ms = 60U;
  rcfg.reconnect_max_ms = 200U;

  auto session = require_val(MpRoomV2Session::start(std::move(rcfg)));
  require_ok(session->wake_fd() >= 0);

  // Wait for hello + initial history + agent_card + error notice
  require_ok(wait_until([&]() {
    return session->state() == MpRoomV2State::live && session->latest_seq() >= 2U;
  }));

  // Verify wake pipe signalled and drain works
  {
    pollfd pfd{session->wake_fd(), POLLIN, 0};
    require_ok(::poll(&pfd, 1U, 200) >= 0);
    session->drain_wake();
  }

  // Verify PartySnapshot has real @handle (client) names, structured agent_card,
  // and ZERO peer_<device_id> or 16-digit IDs!
  {
    const PartySnapshot ps = session->to_party_snapshot();
    require_ok(ps.room_scope == "room/KAIH");
    require_ok(ps.participants.size() == 2U);
    bool saw_phall = false;
    bool saw_antimeme = false;
    for (const auto &p : ps.participants) {
      require_ok(p.id.find("peer_") == std::string::npos);
      require_ok(p.display_name.find("peer_") == std::string::npos);
      require_ok(p.display_name.find("1234567890") == std::string::npos);
      if (p.id == "phall" &&
          p.display_name.find("@phall (outpost · Claude Code)") != std::string::npos) {
        saw_phall = true;
      }
      if (p.id == "antimeme" &&
          p.display_name.find("@antimeme (blackbird)") != std::string::npos) {
        saw_antimeme = true;
      }
    }
    require_ok(saw_phall && saw_antimeme);

    bool saw_chat = false;
    bool saw_card = false;
    for (const auto &m : ps.messages) {
      if (m.sender_id == "@phall" && m.body == "yo can you see this?")
        saw_chat = true;
      if (m.sender_id == "@phall" && m.kind == PartyMessageKind::leader_update &&
          m.body.find("[agent] Fixed auth test") != std::string::npos &&
          m.body.find("src/auth.ts") != std::string::npos) {
        saw_card = true;
      }
    }
    require_ok(saw_chat && saw_card);
  }

  // Verify plain-English error notice was captured
  {
    const auto snap = session->snapshot();
    bool saw_rate_msg = false;
    for (const auto &n : snap.notices) {
      if (n.find("Slow down") != std::string::npos)
        saw_rate_msg = true;
    }
    require_ok(saw_rate_msg);
  }

  // 5. Optimistic send_chat + ack -> delivered ✓
  const std::string cid1 = require_val(
      session->send_chat("hello from blackbird v2", MpRoomV2Target{"@all"}));
  require_ok(!cid1.empty());
  // Immediately present optimistically in to_party_snapshot()
  {
    const PartySnapshot ps = session->to_party_snapshot();
    bool found_opt = false;
    for (const auto &m : ps.messages) {
      if (m.id == cid1 && m.body.find("hello from blackbird v2") != std::string::npos)
        found_opt = true;
    }
    require_ok(found_opt);
  }
  // Wait for server ack -> delivered ✓
  require_ok(wait_until([&]() {
    const PartySnapshot ps = session->to_party_snapshot();
    for (const auto &m : ps.messages) {
      if (m.id == cid1 && m.body.find("✓") != std::string::npos)
        return true;
    }
    return false;
  }));

  // 6. Local send_agent_card + ack
  const std::string card_cid = require_val(session->send_agent_card(
      MpRoomV2AgentCard{"Shipped mp2", "Zero iroh required", {"src/mp_room_v2.cpp"}}));
  require_ok(wait_until([&]() {
    const auto snap = session->snapshot();
    for (const auto &m : snap.messages) {
      if (m.client_msg_id == card_cid && m.delivered)
        return true;
    }
    return false;
  }));

  // 7. Heartbeat MP2:PING / MP2:PONG
  require_ok(wait_until([&]() { return srv.ping_frames_received() >= 1; }, 3000));

  // 8. Abrupt server disconnect -> automatic reconnect -> resume(last_seq) -> dedup +
  //    missed seq=10 catch-up + queued send delivery!
  const std::uint64_t seq_before_drop = session->latest_seq();
  require_ok(seq_before_drop >= 4U);
  srv.request_drop_ws_once();

  // Wait for reconnect + resume
  require_ok(wait_until(
      [&]() {
        return srv.ws_connections() >= 2 && srv.resume_frames_received() >= 1 &&
               session->latest_seq() >= 10U;
      },
      5000));
  require_ok(srv.last_resume_seq() == seq_before_drop);

  // Queue another message right after reconnect and verify delivery + dedup of seq=1
  const std::string cid2 = require_val(session->send_chat("after reconnect!"));
  require_ok(wait_until([&]() {
    const PartySnapshot ps = session->to_party_snapshot();
    for (const auto &m : ps.messages) {
      if (m.id == cid2 && m.body.find("✓") != std::string::npos)
        return true;
    }
    return false;
  }));

  {
    const auto snap = session->snapshot();
    int phall_1_count = 0;
    bool saw_missed_10 = false;
    for (const auto &m : snap.messages) {
      if (m.client_msg_id == "phall-1")
        ++phall_1_count;
      if (m.client_msg_id == "phall-missed-10" &&
          m.rendered_body == "missed while laptop slept") {
        saw_missed_10 = true;
      }
    }
    require_ok(phall_1_count == 1); // deduped across resume replay!
    require_ok(saw_missed_10);
  }

  // 9. Clean stop & room_leave
  session->stop();
  require_ok(!session->is_active());
  require_ok(session->wake_fd() == -1);

  const auto left = require_val(client.room_leave(entered.party_id));
  require_ok(left.left && left.party_id == entered.party_id);

  std::cout << "mp_room_v2_test PASS\n";
  return 0;
}
