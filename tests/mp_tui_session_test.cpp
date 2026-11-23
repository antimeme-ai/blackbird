#include "blackbird/mp_tui_session.hpp"

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
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
#include <thread>
#include <unistd.h>
#include <utility>
#include <variant>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

using namespace blackbird;
using namespace blackbird::mp;

// Always-active checks (never compiled out under -DNDEBUG).
void require_ok(bool ok, std::string_view msg = "",
                std::source_location loc = std::source_location::current()) {
  if (!ok) {
    std::cerr << "mp_tui_session_test FAIL at " << loc.file_name() << ":" << loc.line();
    if (!msg.empty()) {
      std::cerr << " (" << msg << ")";
    }
    std::cerr << "\n";
    std::abort();
  }
}

template <typename T>
const T &require_opt(const std::optional<T> &opt, std::string_view msg = "",
                     std::source_location loc = std::source_location::current()) {
  if (!opt.has_value()) {
    std::cerr << "mp_tui_session_test FAIL (empty optional) at " << loc.file_name()
              << ":" << loc.line();
    if (!msg.empty()) {
      std::cerr << " (" << msg << ")";
    }
    std::cerr << "\n";
    std::abort();
  }
  return *opt;
}

template <typename T>
T require_val(Result<T> res, std::string_view msg = "",
              std::source_location loc = std::source_location::current()) {
  if (!res.has_value()) {
    std::cerr << "mp_tui_session_test FAIL (Result error code="
              << error_name(res.error().code) << " detail=" << res.error().detail
              << ") at " << loc.file_name() << ":" << loc.line();
    if (!msg.empty()) {
      std::cerr << " (" << msg << ")";
    }
    std::cerr << "\n";
    std::abort();
  }
  return std::move(res).value();
}

void require_void(const Result<void> &res, std::string_view msg = "",
                  std::source_location loc = std::source_location::current()) {
  if (!res.has_value()) {
    std::cerr << "mp_tui_session_test FAIL (Result<void> error code="
              << error_name(res.error().code) << " detail=" << res.error().detail
              << ") at " << loc.file_name() << ":" << loc.line();
    if (!msg.empty()) {
      std::cerr << " (" << msg << ")";
    }
    std::cerr << "\n";
    std::abort();
  }
}

void block_sigpipe_this_thread() noexcept {
  sigset_t sigpipe_set{};
  sigemptyset(&sigpipe_set);
  sigaddset(&sigpipe_set, SIGPIPE);
  (void)::pthread_sigmask(SIG_BLOCK, &sigpipe_set, nullptr);
}

std::size_t count_open_fds() noexcept {
  std::size_t count = 0U;
  for (int fd = 0; fd < 1024; ++fd) {
    if (::fcntl(fd, F_GETFD, 0) >= 0) {
      ++count;
    }
  }
  return count;
}

// ---------------------------------------------------------------------------
// TempDir + Ephemeral Self-Signed TLS 1.3 Certificate
// ---------------------------------------------------------------------------

struct TempDir {
  std::filesystem::path path;
  explicit TempDir(std::string_view tag) {
    static std::atomic<std::uint64_t> counter{0U};
    const auto id = counter.fetch_add(1U, std::memory_order_relaxed);
    path = std::filesystem::temp_directory_path() /
           ("bb_mp_tui_session_test_" + std::string{tag} + "_" +
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
  require_ok(raw_key != nullptr, "EVP_EC_gen");
  out.key.reset(raw_key);

  X509 *raw_cert = X509_new();
  require_ok(raw_cert != nullptr, "X509_new");
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
// Minimal RFC 6455 & TLS 1.3 Mock PartyDO Server
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

bool ssl_write_all(SSL *ssl, std::span<const std::uint8_t> data) {
  std::size_t off = 0U;
  while (off < data.size()) {
    const int n =
        SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
    if (n <= 0) {
      return false;
    }
    off += static_cast<std::size_t>(n);
  }
  return true;
}

bool ssl_write_str(SSL *ssl, std::string_view s) {
  return ssl_write_all(ssl,
                       std::span<const std::uint8_t>{
                           reinterpret_cast<const std::uint8_t *>(s.data()), s.size()});
}

std::vector<std::uint8_t> build_server_ws_frame(std::uint8_t opcode,
                                                std::span<const std::uint8_t> payload) {
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>(0x80U | (opcode & 0x0fU)));
  if (payload.size() <= 125U) {
    out.push_back(static_cast<std::uint8_t>(payload.size()));
  } else {
    out.push_back(126U);
    out.push_back(static_cast<std::uint8_t>((payload.size() >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(payload.size() & 0xffU));
  }
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
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

struct ParsedClientWsFrame {
  std::uint8_t opcode = 0U;
  bool masked = false;
  std::vector<std::uint8_t> payload;
};

std::optional<ParsedClientWsFrame>
try_pop_client_ws_frame(std::vector<std::uint8_t> &buf) {
  if (buf.size() < 2U) {
    return std::nullopt;
  }
  const std::uint8_t b0 = buf[0];
  const std::uint8_t b1 = buf[1];
  const bool masked = (b1 & 0x80U) != 0U;
  const std::uint8_t len7 = static_cast<std::uint8_t>(b1 & 0x7fU);
  std::size_t pos = 2U;
  std::uint64_t payload_len = len7;
  if (len7 == 126U) {
    if (buf.size() < 4U) {
      return std::nullopt;
    }
    payload_len = (static_cast<std::uint64_t>(buf[2]) << 8U) | buf[3];
    pos = 4U;
  } else if (len7 == 127U) {
    if (buf.size() < 10U) {
      return std::nullopt;
    }
    payload_len = 0U;
    for (std::size_t i = 0U; i < 8U; ++i) {
      payload_len = (payload_len << 8U) | buf[2U + i];
    }
    pos = 10U;
  }
  const std::size_t mask_len = masked ? 4U : 0U;
  if (buf.size() < pos + mask_len + payload_len) {
    return std::nullopt;
  }
  std::array<std::uint8_t, 4> mask{};
  if (masked) {
    std::memcpy(mask.data(), buf.data() + pos, 4U);
    pos += 4U;
  }
  ParsedClientWsFrame out{};
  out.opcode = static_cast<std::uint8_t>(b0 & 0x0fU);
  out.masked = masked;
  out.payload.assign(buf.begin() + static_cast<std::ptrdiff_t>(pos),
                     buf.begin() + static_cast<std::ptrdiff_t>(pos + payload_len));
  if (masked) {
    for (std::size_t i = 0U; i < out.payload.size(); ++i) {
      out.payload[i] = static_cast<std::uint8_t>(out.payload[i] ^ mask[i % 4U]);
    }
  }
  buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(pos + payload_len));
  return out;
}

struct RegisteredDevice {
  AccountId account_id;
  DeviceId device_id;
  Ed25519PubKey root_pubkey{};
  Ed25519PubKey device_pubkey{};
  std::vector<std::uint8_t> device_cwt;
};

enum class ServerActionKind : std::uint8_t {
  send_mp1 = 1,
  send_close = 2,
  drop_abruptly = 3,
};

struct ServerAction {
  ServerActionKind kind = ServerActionKind::send_mp1;
  std::optional<Mp1Message> message;
  std::uint16_t close_code = 1000U;
};

struct ClientSlot {
  std::uint64_t generation = 0U;
  bool connected = false;
  std::uint32_t connect_count = 0U;
  std::uint32_t ping_count = 0U;
  std::uint32_t endpoint_update_count = 0U;
  std::optional<EndpointDescriptor> latest_endpoint;
  std::deque<ServerAction> outbound;
};

class MockPartyDoServer {
public:
  MockPartyDoServer(const EphemeralCert &cert, std::string expected_authority,
                    std::uint32_t hello_ping_interval_ms = 20000U)
      : expected_authority_(std::move(expected_authority)),
        hello_ping_interval_ms_(hello_ping_interval_ms) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    require_ok(ctx_ != nullptr, "SSL_CTX_new");
    require_ok(SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION) == 1);
    require_ok(SSL_CTX_use_certificate(ctx_, cert.cert.get()) == 1);
    require_ok(SSL_CTX_use_PrivateKey(ctx_, cert.key.get()) == 1);
    SSL_CTX_set_alpn_select_cb(ctx_, &alpn_select_http11, nullptr);

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    require_ok(listen_fd_ >= 0, "socket");
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
    require_ok(::listen(listen_fd_, 32) == 0);

    accept_thread_ = std::thread([this]() { accept_loop(); });
  }

  ~MockPartyDoServer() {
    stop_.store(true, std::memory_order_release);
    cv_.notify_all();
    if (listen_fd_ >= 0) {
      ::shutdown(listen_fd_, SHUT_RDWR);
      ::close(listen_fd_);
      listen_fd_ = -1;
    }
    if (accept_thread_.joinable()) {
      accept_thread_.join();
    }
    std::vector<std::thread> workers;
    {
      std::lock_guard<std::mutex> lk{mu_};
      workers.swap(worker_threads_);
    }
    for (auto &t : workers) {
      if (t.joinable()) {
        t.join();
      }
    }
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  std::uint16_t port() const noexcept { return port_; }

  void register_device(RegisteredDevice dev) {
    std::lock_guard<std::mutex> lk{mu_};
    const std::uint64_t id = dev.device_id.value();
    devices_.insert_or_assign(id, std::move(dev));
  }

  void push_mp1(DeviceId device_id, Mp1Message msg) {
    {
      std::lock_guard<std::mutex> lk{mu_};
      auto &slot = slots_[device_id.value()];
      ServerAction act{};
      act.kind = ServerActionKind::send_mp1;
      act.message = std::move(msg);
      slot.outbound.push_back(std::move(act));
    }
    cv_.notify_all();
  }

  void send_ws_close(DeviceId device_id, std::uint16_t code) {
    {
      std::lock_guard<std::mutex> lk{mu_};
      auto &slot = slots_[device_id.value()];
      ServerAction act{};
      act.kind = ServerActionKind::send_close;
      act.close_code = code;
      slot.outbound.push_back(act);
    }
    cv_.notify_all();
  }

  void drop_connection_abruptly(DeviceId device_id) {
    {
      std::lock_guard<std::mutex> lk{mu_};
      auto &slot = slots_[device_id.value()];
      ServerAction act{};
      act.kind = ServerActionKind::drop_abruptly;
      slot.outbound.push_back(act);
    }
    cv_.notify_all();
  }

  std::optional<EndpointDescriptor> wait_for_endpoint_update(
      DeviceId device_id, std::uint32_t expected_count,
      std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) {
    std::unique_lock<std::mutex> lk{mu_};
    const bool ok = cv_.wait_for(lk, timeout, [&]() {
      const auto it = slots_.find(device_id.value());
      return it != slots_.end() && it->second.endpoint_update_count >= expected_count &&
             it->second.latest_endpoint.has_value();
    });
    if (!ok) {
      return std::nullopt;
    }
    return slots_.at(device_id.value()).latest_endpoint;
  }

  bool wait_for_ping_count(
      DeviceId device_id, std::uint32_t expected_count,
      std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) {
    std::unique_lock<std::mutex> lk{mu_};
    return cv_.wait_for(lk, timeout, [&]() {
      const auto it = slots_.find(device_id.value());
      return it != slots_.end() && it->second.ping_count >= expected_count;
    });
  }

private:
  void accept_loop() {
    block_sigpipe_this_thread();
    while (!stop_.load(std::memory_order_acquire)) {
      pollfd pfd{};
      pfd.fd = listen_fd_;
      pfd.events = POLLIN;
      const int rc = ::poll(&pfd, 1U, 25);
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
      std::lock_guard<std::mutex> lk{mu_};
      worker_threads_.emplace_back([this, client_fd]() { handle_client(client_fd); });
    }
  }

  void handle_client(int client_fd) {
    block_sigpipe_this_thread();
    struct FdCloser {
      int fd = -1;
      ~FdCloser() {
        if (fd >= 0) {
          ::close(fd);
        }
      }
    } fd_closer{client_fd};

    SSL *ssl = SSL_new(ctx_);
    if (ssl == nullptr) {
      return;
    }
    struct SslCloser {
      SSL *ptr = nullptr;
      bool clean_shutdown = true;
      ~SslCloser() {
        if (ptr != nullptr) {
          if (clean_shutdown) {
            SSL_shutdown(ptr);
          }
          SSL_free(ptr);
        }
      }
    } ssl_closer{ssl, true};

    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) != 1) {
      return;
    }

    std::string raw;
    std::array<char, 4096> buf{};
    std::size_t hdr_end = std::string::npos;
    while (hdr_end == std::string::npos && raw.size() < 16384U) {
      const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
      if (n <= 0) {
        return;
      }
      raw.append(buf.data(), static_cast<std::size_t>(n));
      hdr_end = raw.find("\r\n\r\n");
    }
    if (hdr_end == std::string::npos) {
      return;
    }

    const std::string_view hdr_block{raw.data(), hdr_end};
    const std::size_t first_eol = hdr_block.find("\r\n");
    if (first_eol == std::string_view::npos) {
      return;
    }
    const std::string_view req_line = hdr_block.substr(0U, first_eol);
    const std::size_t sp1 = req_line.find(' ');
    const std::size_t sp2 = req_line.find(' ', sp1 + 1U);
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
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

    const auto method = parse_http_method(method_str);
    if (!method.has_value() || method.value() != HttpMethod::get ||
        !path.ends_with("/ws")) {
      (void)ssl_write_str(ssl, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                               "Connection: close\r\n\r\n");
      return;
    }

    const auto parsed_si = parse_signature_input(headers["signature-input"]);
    if (!parsed_si.has_value() ||
        !std::holds_alternative<DeviceKeyId>(parsed_si.value().keyid)) {
      (void)ssl_write_str(ssl, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                               "Connection: close\r\n\r\n");
      return;
    }
    const auto dev_keyid = std::get<DeviceKeyId>(parsed_si.value().keyid);

    Ed25519PubKey verify_pk{};
    {
      std::lock_guard<std::mutex> lk{mu_};
      const auto it = devices_.find(dev_keyid.device_id.value());
      if (it == devices_.end() || it->second.account_id != dev_keyid.account_id) {
        (void)ssl_write_str(ssl, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                                 "Connection: close\r\n\r\n");
        return;
      }
      verify_pk = it->second.device_pubkey;
    }

    const auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    const auto now_s = static_cast<std::int64_t>(now_ms / 1000U);

    Rfc9421Request req{};
    req.method = HttpMethod::get;
    req.authority = headers["host"];
    req.path = path;
    req.query = query;
    req.signature_input = headers["signature-input"];
    req.signature = headers["signature"];
    const auto verified = verify_rfc9421_request(
        Rfc9421VerifyInput{req, expected_authority_, verify_pk, now_s});
    if (!verified.has_value()) {
      (void)ssl_write_str(ssl, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                               "Connection: close\r\n\r\n");
      return;
    }

    const std::string accept = ws_accept_for(headers.at("sec-websocket-key"));
    const std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Upgrade: websocket\r\n"
                             "Connection: Upgrade\r\n"
                             "Sec-WebSocket-Accept: " +
                             accept +
                             "\r\n"
                             "Sec-WebSocket-Protocol: mp1\r\n\r\n";

    const std::uint64_t session_num =
        next_session_id_.fetch_add(1U, std::memory_order_relaxed);
    const auto hello_bytes = encode_frame(
        0U, HelloAckMessage{require_val(SessionId::create(session_num), "session_id"),
                            now_ms, hello_ping_interval_ms_});
    require_ok(hello_bytes.has_value(), "encode HELLO_ACK");
    const auto hello_ws = build_server_ws_frame(0x02U, hello_bytes.value());

    std::vector<std::uint8_t> initial(resp.begin(), resp.end());
    initial.insert(initial.end(), hello_ws.begin(), hello_ws.end());
    if (!ssl_write_all(ssl, initial)) {
      return;
    }

    const std::uint64_t dev_raw = dev_keyid.device_id.value();
    std::uint64_t my_gen = 0U;
    {
      std::lock_guard<std::mutex> lk{mu_};
      auto &slot = slots_[dev_raw];
      ++slot.generation;
      my_gen = slot.generation;
      slot.connected = true;
      ++slot.connect_count;
    }
    cv_.notify_all();

    std::vector<std::uint8_t> recv_buf;
    if (hdr_end + 4U < raw.size()) {
      const auto *extra =
          reinterpret_cast<const std::uint8_t *>(raw.data() + hdr_end + 4U);
      recv_buf.insert(recv_buf.end(), extra, extra + (raw.size() - (hdr_end + 4U)));
    }

    while (!stop_.load(std::memory_order_acquire)) {
      std::deque<ServerAction> batch;
      {
        std::lock_guard<std::mutex> lk{mu_};
        auto &slot = slots_[dev_raw];
        if (slot.generation != my_gen) {
          break;
        }
        batch.swap(slot.outbound);
      }
      bool exit_loop = false;
      for (const auto &act : batch) {
        if (act.kind == ServerActionKind::send_mp1 && act.message.has_value()) {
          const auto enc = encode_frame(0U, *act.message);
          require_ok(enc.has_value(), "server encode_frame");
          if (!ssl_write_all(ssl, build_server_ws_frame(0x02U, enc.value()))) {
            exit_loop = true;
            break;
          }
        } else if (act.kind == ServerActionKind::send_close) {
          const std::array<std::uint8_t, 2> code_bytes = {
              static_cast<std::uint8_t>((act.close_code >> 8U) & 0xffU),
              static_cast<std::uint8_t>(act.close_code & 0xffU),
          };
          (void)ssl_write_all(ssl, build_server_ws_frame(0x08U, code_bytes));
          exit_loop = true;
          break;
        } else if (act.kind == ServerActionKind::drop_abruptly) {
          ssl_closer.clean_shutdown = false;
          exit_loop = true;
          break;
        }
      }
      if (exit_loop) {
        break;
      }

      bool readable = SSL_pending(ssl) > 0;
      if (!readable) {
        pollfd pfd{};
        pfd.fd = client_fd;
        pfd.events = POLLIN;
        const int prc = ::poll(&pfd, 1U, 10);
        if (prc < 0) {
          break;
        }
        readable = (prc > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0);
      }
      if (!readable) {
        continue;
      }

      std::array<std::uint8_t, 4096> rbuf{};
      const int n = SSL_read(ssl, rbuf.data(), static_cast<int>(rbuf.size()));
      if (n <= 0) {
        break;
      }
      recv_buf.insert(recv_buf.end(), rbuf.begin(), rbuf.begin() + n);

      while (auto frame = try_pop_client_ws_frame(recv_buf)) {
        require_ok(frame->masked, "RFC 6455 client frames must be masked");
        if (frame->opcode == 0x02U) {
          const auto dec = decode_frame(frame->payload);
          require_ok(dec.has_value(), "decode client MP1 frame");
          if (const auto *ep_upd =
                  std::get_if<PartyEndpointUpdateMessage>(&dec.value().message)) {
            {
              std::lock_guard<std::mutex> lk{mu_};
              auto &slot = slots_[dev_raw];
              slot.latest_endpoint = ep_upd->endpoint;
              ++slot.endpoint_update_count;
            }
            cv_.notify_all();
          }
        } else if (frame->opcode == 0x01U) {
          const std::string_view text{
              reinterpret_cast<const char *>(frame->payload.data()),
              frame->payload.size()};
          if (text == kMp1HeartbeatPing) {
            {
              std::lock_guard<std::mutex> lk{mu_};
              ++slots_[dev_raw].ping_count;
            }
            cv_.notify_all();
            const std::span<const std::uint8_t> pong_bytes{
                reinterpret_cast<const std::uint8_t *>(kMp1HeartbeatPong.data()),
                kMp1HeartbeatPong.size()};
            if (!ssl_write_all(ssl, build_server_ws_frame(0x01U, pong_bytes))) {
              exit_loop = true;
              break;
            }
          }
        } else if (frame->opcode == 0x09U) {
          (void)ssl_write_all(ssl, build_server_ws_frame(0x0aU, frame->payload));
        } else if (frame->opcode == 0x08U) {
          const std::array<std::uint8_t, 2> ok_close = {0x03U, 0xe8U};
          (void)ssl_write_all(ssl, build_server_ws_frame(0x08U, ok_close));
          exit_loop = true;
          break;
        }
      }
      if (exit_loop) {
        break;
      }
    }

    {
      std::lock_guard<std::mutex> lk{mu_};
      auto &slot = slots_[dev_raw];
      if (slot.generation == my_gen) {
        slot.connected = false;
      }
    }
    cv_.notify_all();
  }

  std::string expected_authority_;
  std::uint32_t hello_ping_interval_ms_ = 20000U;
  SSL_CTX *ctx_ = nullptr;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0U;
  std::atomic<bool> stop_{false};
  std::atomic<std::uint64_t> next_session_id_{200U};
  std::thread accept_thread_;

  std::mutex mu_;
  std::condition_variable cv_;
  std::vector<std::thread> worker_threads_;
  std::map<std::uint64_t, RegisteredDevice> devices_;
  std::map<std::uint64_t, ClientSlot> slots_;
};

// ---------------------------------------------------------------------------
// Identity & Test Fixtures
// ---------------------------------------------------------------------------

struct TestPeerIdentity {
  AccountId account_id;
  DeviceId device_id;
  CleansedSeed root_seed;
  CleansedSeed device_seed;
  Ed25519PubKey root_pubkey{};
  Ed25519PubKey device_pubkey{};
  std::vector<std::uint8_t> device_cwt;
  std::string handle;
};

struct PeerIdentitySpec {
  std::uint64_t account_raw = 0U;
  std::uint64_t device_raw = 0U;
  std::uint8_t seed_tag = 0U;
  std::string handle;
  std::int64_t iat_s = 0;
  std::int64_t exp_s = 0;
};

TestPeerIdentity make_test_identity(const PeerIdentitySpec &spec) {
  Ed25519Seed rseed{};
  Ed25519Seed dseed{};
  for (std::size_t i = 0U; i < rseed.size(); ++i) {
    rseed[i] = static_cast<std::uint8_t>(spec.seed_tag ^ (i + 1U));
    dseed[i] = static_cast<std::uint8_t>((spec.seed_tag + 0x40U) ^ (i + 3U));
  }
  const auto root_key = require_val(Ed25519SigningKey::from_seed(rseed), "root key");
  const auto dev_key = require_val(Ed25519SigningKey::from_seed(dseed), "dev key");
  const auto cwt = require_val(
      encode_device_cwt(
          root_key, DeviceCwtMintRequest{dev_key.public_key(), spec.iat_s, spec.exp_s}),
      "encode_device_cwt");

  return TestPeerIdentity{
      require_val(AccountId::create(spec.account_raw), "account_id"),
      require_val(DeviceId::create(spec.device_raw), "device_id"),
      CleansedSeed{rseed},
      CleansedSeed{dseed},
      root_key.public_key(),
      dev_key.public_key(),
      cwt,
      spec.handle,
  };
}

MpClientConfig make_client_config(std::uint16_t port,
                                  const std::filesystem::path &ca_path) {
  MpClientConfig cfg{};
  cfg.authority = "localhost";
  cfg.connect_host = "127.0.0.1";
  cfg.port = port;
  cfg.ca_bundle_path = ca_path;
  cfg.connect_timeout_ms = 3000;
  cfg.io_timeout_ms = 3000;
  return cfg;
}

MpIdentityState to_identity_state(const TestPeerIdentity &id) {
  MpIdentityState st{};
  st.device_seed = id.device_seed;
  st.account_id = id.account_id;
  st.device_id = id.device_id;
  st.handle = id.handle;
  st.authority = "localhost";
  st.device_cwt = id.device_cwt;
  return st;
}

RegisteredDevice to_registered_device(const TestPeerIdentity &id) {
  return RegisteredDevice{
      id.account_id, id.device_id, id.root_pubkey, id.device_pubkey, id.device_cwt,
  };
}

PartyMemberRecord make_member_record(const TestPeerIdentity &id,
                                     EndpointDescriptor endpoint,
                                     std::uint64_t joined_seq) {
  return PartyMemberRecord{
      id.device_id,  id.account_id,       id.root_pubkey, id.device_pubkey,
      id.device_cwt, std::move(endpoint), joined_seq,     true,
  };
}

EndpointDescriptor make_lan_endpoint(std::uint16_t port) {
  EndpointDescriptor ep{};
  ep.transport_kind = TransportKind::iroh_quic;
  ep.direct_addrs.push_back(DirectAddrV4{{192U, 168U, 1U, 50U}, port});
  return ep;
}

// Waits using POSIX poll() on session.wake_fd() until predicate() returns true.
template <typename Pred>
bool wait_via_wake_fd(MpTuiSession &session, Pred &&predicate, int timeout_ms = 6000) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
  for (;;) {
    if (predicate()) {
      return true;
    }
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      return false;
    }
    const int fd = session.wake_fd();
    if (fd < 0) {
      return predicate();
    }
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    const int slice = static_cast<int>(std::min<std::int64_t>(remaining, 100));
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    const int rc = ::poll(&pfd, 1U, std::max(1, slice));
    if (rc > 0 && (pfd.revents & POLLIN) != 0) {
      session.drain_wake();
    }
  }
}

// ---------------------------------------------------------------------------
// Test 1: Config validation & failed attach leak-free teardown
// ---------------------------------------------------------------------------

void test_config_validation_and_failed_attach() {
  const std::size_t fds_before = count_open_fds();
  const auto party_id = require_val(PartyId::create(5001U), "party_id");
  const std::int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
  const auto alice = make_test_identity(
      PeerIdentitySpec{1001U, 101U, 0x11U, "alice", now_s - 10, now_s + 3600});

  auto base_cfg = [&]() {
    MpPartyRuntimeConfig rt_cfg{MpClientConfig{}, to_identity_state(alice), party_id};
    rt_cfg.client_config.authority = "localhost";
    rt_cfg.client_config.connect_host = "127.0.0.1";
    rt_cfg.client_config.port = 1U;
    rt_cfg.client_config.connect_timeout_ms = 200;
    rt_cfg.local_relay_policy = RelayPolicy::no_relays;
    MpTuiSessionConfig cfg{std::move(rt_cfg)};
    cfg.pump_tick_ms = 10U;
    return cfg;
  };

  {
    auto cfg = base_cfg();
    cfg.max_retained_messages = 0U;
    const auto res = MpTuiSession::start(std::move(cfg));
    require_ok(!res.has_value() && mp_tui_session_error_of(res.error()) ==
                                       MpTuiSessionError::invalid_config,
               "max_retained_messages == 0 must fail");
  }
  {
    auto cfg = base_cfg();
    cfg.room_scope = std::string(kP2pPartyMaxRoomScopeBytes + 1U, 'a');
    const auto res = MpTuiSession::start(std::move(cfg));
    require_ok(!res.has_value() && mp_tui_session_error_of(res.error()) ==
                                       MpTuiSessionError::field_too_large,
               "oversized room_scope must fail");
  }
  {
    auto cfg = base_cfg();
    cfg.room_scope = std::string{"bad\xffutf8"};
    const auto res = MpTuiSession::start(std::move(cfg));
    require_ok(!res.has_value() && mp_tui_session_error_of(res.error()) ==
                                       MpTuiSessionError::invalid_utf8,
               "invalid utf-8 room_scope must fail");
  }
  {
    auto cfg = base_cfg();
    cfg.local_handle = "";
    const auto res = MpTuiSession::start(std::move(cfg));
    require_ok(!res.has_value() && mp_tui_session_error_of(res.error()) ==
                                       MpTuiSessionError::invalid_field,
               "empty local_handle override must fail");
  }
  {
    // Missing identity -> MpPartyRuntime::attach fails closed without leaking FDs.
    MpPartyRuntimeConfig rt_cfg{MpClientConfig{}, MpIdentityState{}, party_id};
    MpTuiSessionConfig cfg{std::move(rt_cfg)};
    const auto res = MpTuiSession::start(std::move(cfg));
    require_ok(!res.has_value() && mp_party_runtime_error_of(res.error()) ==
                                       MpPartyRuntimeError::missing_identity,
               "missing identity must fail cleanly");
  }

  require_ok(count_open_fds() == fds_before, "zero leaked FDs after failed starts");
  std::cout << "PASS test_config_validation_and_failed_attach\n";
}

// ---------------------------------------------------------------------------
// Test 2: Control-plane lifecycle, wake_fd poll(), metadata sanitization,
//         PartyChatPane rendering, reconnect/disband, and idempotent stop()
//         (runs under BOTH BLACKBIRD_HAS_IROH=1 and BLACKBIRD_HAS_IROH=0)
// ---------------------------------------------------------------------------

void test_control_lifecycle_wake_fd_and_party_snapshot() {
  TempDir tmp{"tui_ctrl"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const std::int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
  const auto party_id = require_val(PartyId::create(5001U), "party_id");
  const auto alice = make_test_identity(
      PeerIdentitySpec{1001U, 205U, 0x21U, "alice", now_s - 30, now_s + 3600});
  const auto bob = make_test_identity(
      PeerIdentitySpec{2002U, 202U, 0x22U, "bob", now_s - 30, now_s + 3600});
  const auto carol = make_test_identity(
      PeerIdentitySpec{3003U, 203U, 0x23U, "carol", now_s - 30, now_s + 3600});
  server.register_device(to_registered_device(alice));

  const std::size_t fds_before = count_open_fds();
  {
    MpPartyRuntimeConfig rt_cfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    rt_cfg.local_relay_policy = RelayPolicy::no_relays;
    rt_cfg.max_reconnect_attempts = 3U;
    rt_cfg.reconnect_base_ms = 20U;
    rt_cfg.reconnect_max_ms = 80U;
    rt_cfg.p2p_connect_timeout_ms = 150U;

    MpTuiSessionConfig cfg{std::move(rt_cfg)};
    cfg.room_scope = "party/ops";
    cfg.pump_tick_ms = 10U;
    cfg.max_retained_messages = 32U;

    auto session = require_val(MpTuiSession::start(std::move(cfg)), "start alice");

    // Verify wake_fd is non-blocking & close-on-exec.
    const int wfd = session->wake_fd();
    require_ok(wfd >= 0, "wake_fd valid");
    const int fd_flags = ::fcntl(wfd, F_GETFD, 0);
    const int st_flags = ::fcntl(wfd, F_GETFL, 0);
    require_ok((fd_flags & FD_CLOEXEC) != 0, "wake_fd has FD_CLOEXEC");
    require_ok((st_flags & O_NONBLOCK) != 0, "wake_fd has O_NONBLOCK");

    // Wait via wake_fd poll() for HELLO_ACK -> connected.
    require_ok(
        wait_via_wake_fd(
            *session, [&]() { return session->state() == MpRuntimeState::connected; }),
        "alice connected via wake_fd");

    // Draining wake leaves poll(..., 0) non-ready.
    session->drain_wake();
    pollfd check_pfd{wfd, POLLIN, 0};
    require_ok(::poll(&check_pfd, 1U, 0) == 0, "drain_wake emptied wake pipe");

    // Push PARTY_SNAPSHOT with Bob (no peer_metadata yet -> must use peer_<id>).
    server.push_mp1(alice.device_id,
                    Mp1Message{PartySnapshotMessage{
                        party_id,
                        3U,
                        alice.account_id,
                        alice.device_id,
                        PartyVisibility::private_party,
                        PartyJoinMode::invite_only,
                        RelayPolicy::no_relays,
                        4U,
                        "",
                        {
                            make_member_record(alice, make_lan_endpoint(4101U), 1U),
                            make_member_record(bob, make_lan_endpoint(4102U), 2U),
                        },
                    }});

    require_ok(
        wait_via_wake_fd(
            *session,
            [&]() { return session->to_party_snapshot().participants.size() == 2U; }),
        "snapshot updated participants via wake_fd");

    const MpTuiSessionSnapshot snap1 = session->snapshot();
    require_ok(snap1.active, "snapshot active");
    require_ok(snap1.state == MpRuntimeState::connected, "snapshot connected");
    require_ok(snap1.party_id == party_id, "party_id match");
    require_ok(snap1.party_epoch == 3U, "party_epoch == 3");
    require_ok(snap1.room_scope == "party/ops", "room_scope match");
    require_ok(snap1.status_summary ==
                   "online party #5001 (epoch 3, 1 peer, connected)",
               "status_summary format match");
    require_ok(!snap1.notices.empty(), "notices populated before drain");
    const MpTuiSessionSnapshot snap2 = session->snapshot();
    require_ok(snap2.notices.empty(), "snapshot() drains notices");

    // Check local + remote participant identity & fingerprint.
    require_ok(snap1.participants.size() == 2U, "2 participants");
    require_ok(snap1.participants[0].local_self && snap1.participants[0].id == "alice",
               "local self participant");
    const std::string expected_bob_fp =
        require_val(compute_device_fingerprint(bob.device_pubkey), "bob fp");
    require_ok(!snap1.participants[1].local_self, "remote participant not self");
    require_ok(snap1.participants[1].id == "peer_" + bob.device_id.to_decimal(),
               "unknown peer falls back to peer_<device_id>");
    require_ok(snap1.participants[1].fingerprint == expected_bob_fp,
               "peer fingerprint computed from authenticated pubkey");

    // Update peer metadata with hostile escapes -> immediately sanitized & wakes!
    session->drain_wake();
    session->update_peer_metadata(
        bob.device_id,
        MpPeerDisplayMetadata{"\x1b[31mbob_ops\x1b[0m", "host\x07label"});
    pollfd meta_pfd{wfd, POLLIN, 0};
    require_ok(::poll(&meta_pfd, 1U, 100) > 0 && (meta_pfd.revents & POLLIN) != 0,
               "update_peer_metadata signaled wake_fd");
    session->drain_wake();

    const PartySnapshot pane_snap = session->to_party_snapshot();
    require_ok(pane_snap.mode == PartyMode::multi_operator,
               "2 human operators -> multi_operator");
    require_ok(pane_snap.participants[1].id.find('\x1b') == std::string::npos,
               "no raw ESC in sanitized peer handle");
    require_ok(pane_snap.participants[1].host.find('\x07') == std::string::npos,
               "no raw BEL in sanitized peer host");
    require_ok(pane_snap.participants[1].id.find("bob_ops") != std::string::npos,
               "printable handle preserved");

    // Verify PartyChatPane renders the online snapshot cleanly.
    PartyChatPane pane{pane_snap};
    const std::string rendered = pane.render(100, 20, false);
    require_ok(rendered.find("party/ops") != std::string::npos,
               "PartyChatPane renders room_scope");
    require_ok(rendered.find("MULTI-OP") != std::string::npos,
               "PartyChatPane renders MULTI-OP badge");
    require_ok(rendered.find('\x1b') == std::string::npos,
               "rendered non-color pane has zero raw ESC");

    // Input validation on post_chat / post_pulse.
    {
      const auto r1 = session->post_chat("");
      require_ok(!r1.has_value() && mp_tui_session_error_of(r1.error()) ==
                                        MpTuiSessionError::invalid_field,
                 "empty body rejected");
      const auto r2 = session->post_chat("hi", std::string(100U, 'x'));
      require_ok(!r2.has_value() && mp_tui_session_error_of(r2.error()) ==
                                        MpTuiSessionError::field_too_large,
                 "oversized target rejected");
      const auto r3 = session->post_chat("bad\xfeutf8");
      require_ok(!r3.has_value() && mp_tui_session_error_of(r3.error()) ==
                                        MpTuiSessionError::invalid_utf8,
                 "invalid utf8 body rejected");
      const auto r4 =
          session->post_pulse(P2pPartyActivityState::working, std::string(300U, 'z'));
      require_ok(!r4.has_value() && mp_tui_session_error_of(r4.error()) ==
                                        MpTuiSessionError::field_too_large,
                 "oversized pulse status rejected");
    }

    // Non-blocking post_ping reaches MockPartyDoServer!
    require_void(session->post_ping(), "post_ping");
    require_ok(server.wait_for_ping_count(alice.device_id, 1U),
               "server received MP1:PING from worker");

    // Lifecycle events: member_joined, leader_changed, member_left, reconnect, disband!
    server.push_mp1(alice.device_id,
                    Mp1Message{PartyMemberJoinedMessage{
                        4U, make_member_record(carol, make_lan_endpoint(4103U), 3U)}});
    server.push_mp1(alice.device_id, Mp1Message{PartyLeaderChangedMessage{
                                         5U, bob.account_id, bob.device_id,
                                         PartyLeaderChangeReason::promoted}});
    server.push_mp1(alice.device_id, Mp1Message{PartyMemberLeftMessage{
                                         6U, carol.device_id, carol.account_id,
                                         MemberLeaveReason::left}});

    std::vector<std::string> collected_notices;
    auto collect_notices = [&]() {
      const auto s = session->snapshot();
      collected_notices.insert(collected_notices.end(), s.notices.begin(),
                               s.notices.end());
      return s.party_epoch >= 6U;
    };
    require_ok(wait_via_wake_fd(*session, collect_notices),
               "received joined/leader/left events");
    auto has_notice_substr = [&](std::string_view needle) {
      for (const auto &n : collected_notices) {
        if (n.find(needle) != std::string::npos) {
          return true;
        }
      }
      return false;
    };
    require_ok(has_notice_substr("peer joined:"), "member_joined notice");
    require_ok(has_notice_substr("leader changed to"), "leader_changed notice");
    require_ok(has_notice_substr("peer left:"), "member_left notice");

    // Transient WS drop -> reconnecting -> reconnected notices.
    server.drop_connection_abruptly(alice.device_id);
    require_ok(wait_via_wake_fd(*session,
                                [&]() {
                                  const auto s = session->snapshot();
                                  collected_notices.insert(collected_notices.end(),
                                                           s.notices.begin(),
                                                           s.notices.end());
                                  return has_notice_substr("reconnecting") &&
                                         has_notice_substr("reconnected") &&
                                         s.state == MpRuntimeState::connected;
                                }),
               "reconnecting + reconnected notices observed");

    // PARTY_DISBANDED -> active becomes false, disbanded notice emitted.
    server.push_mp1(alice.device_id, Mp1Message{PartyDisbandedMessage{
                                         7U, PartyDisbandReason::leader_disbanded}});
    require_ok(
        wait_via_wake_fd(*session,
                         [&]() {
                           const auto s = session->snapshot();
                           collected_notices.insert(collected_notices.end(),
                                                    s.notices.begin(), s.notices.end());
                           return !s.active && s.state == MpRuntimeState::disbanded;
                         }),
        "disbanded state observed via wake_fd");
    require_ok(has_notice_substr("party disbanded"), "disbanded notice");

    // Post-disband commands fail closed.
    const auto after_disband = session->post_chat("too late");
    require_ok(!after_disband.has_value() &&
                   mp_tui_session_error_of(after_disband.error()) ==
                       MpTuiSessionError::session_stopped,
               "post_chat fails closed after disband");

    // Idempotent stop().
    session->stop();
    session->stop();
    require_ok(session->wake_fd() == -1, "wake_fd closed after stop()");
    require_ok(!session->is_active(), "inactive after stop()");
  }

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
  // First P2pEndpoint initializes process-global tokio runtime FDs; verify zero
  // per-session FD leaks on a subsequent cycle.
  (void)fds_before;
  const std::size_t fds_cycle1 = count_open_fds();
  {
    MpPartyRuntimeConfig rt_cfg2{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    rt_cfg2.local_relay_policy = RelayPolicy::no_relays;
    rt_cfg2.p2p_connect_timeout_ms = 150U;
    MpTuiSessionConfig cfg2{std::move(rt_cfg2)};
    cfg2.pump_tick_ms = 10U;
    auto s2 = require_val(MpTuiSession::start(std::move(cfg2)), "start fd cycle 2");
    require_ok(wait_via_wake_fd(
                   *s2, [&]() { return s2->state() == MpRuntimeState::connected; }),
               "fd cycle 2 connected");
    s2->stop();
  }
  require_ok(count_open_fds() <= fds_cycle1,
             "zero leaked FDs after session lifecycle + stop()");
#else
  require_ok(count_open_fds() == fds_before,
             "zero leaked FDs after session lifecycle + stop()");
#endif
  std::cout << "PASS test_control_lifecycle_wake_fd_and_party_snapshot\n";
}

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH

// ---------------------------------------------------------------------------
// Test 3: Live 2-Peer iroh v1.5.0 QUIC Mutual RPK E2E Test
//         - Real non-blocking post_chat + wake_fd poll()
//         - Anti-spoofing (wire sender_handle NEVER overrides peer_metadata /
//         device_id)
//         - Hostile terminal-escape & bidi override sanitization
//         - Ephemeral pulse state transition + targeted chat + send_chat
//         - Bounded message ring eviction (max_retained_messages)
//         - Clean stop() with zero leaked FDs
// ---------------------------------------------------------------------------

void test_live_two_peer_iroh_e2e() {
  TempDir tmp{"tui_iroh_e2e"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const std::int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
  const auto party_id = require_val(PartyId::create(5009U), "party_id");
  const auto alice_id = make_test_identity(
      PeerIdentitySpec{1001U, 301U, 0x51U, "alice", now_s - 30, now_s + 3600});
  const auto bob_id = make_test_identity(
      PeerIdentitySpec{2002U, 302U, 0x52U, "bob", now_s - 30, now_s + 3600});
  server.register_device(to_registered_device(alice_id));
  server.register_device(to_registered_device(bob_id));

  const std::size_t fds_before = count_open_fds();
  {
    MpPartyRuntimeConfig a_rt{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice_id),
        party_id,
    };
    a_rt.local_relay_policy = RelayPolicy::no_relays;
    a_rt.allow_loopback_direct_addrs = true;

    MpTuiSessionConfig a_cfg{std::move(a_rt)};
    a_cfg.room_scope = "party/live";
    // Deliberately put a spoofed handle on Alice's wire frames so we prove Bob
    // NEVER trusts wire sender_handle!
    a_cfg.local_handle = "spoofed_root_admin";
    a_cfg.peer_metadata[bob_id.device_id.value()] =
        MpPeerDisplayMetadata{"bob_trusted", "bob-mac"};
    a_cfg.pump_tick_ms = 10U;
    a_cfg.max_retained_messages = 32U;

    MpPartyRuntimeConfig b_rt{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(bob_id),
        party_id,
    };
    b_rt.local_relay_policy = RelayPolicy::no_relays;
    b_rt.allow_loopback_direct_addrs = true;

    MpTuiSessionConfig b_cfg{std::move(b_rt)};
    b_cfg.room_scope = "party/live";
    b_cfg.local_handle = "bob_local";
    b_cfg.peer_metadata[alice_id.device_id.value()] =
        MpPeerDisplayMetadata{"alice_trusted", "alice-mac"};
    b_cfg.pump_tick_ms = 10U;
    // Small ring capacity to directly verify bounded ring eviction!
    b_cfg.max_retained_messages = 5U;

    auto alice = require_val(MpTuiSession::start(std::move(a_cfg)), "start alice");
    auto bob = require_val(MpTuiSession::start(std::move(b_cfg)), "start bob");

    const auto alice_ep =
        require_opt(server.wait_for_endpoint_update(alice_id.device_id, 1U),
                    "alice endpoint update");
    const auto bob_ep = require_opt(
        server.wait_for_endpoint_update(bob_id.device_id, 1U), "bob endpoint update");

    const PartySnapshotMessage snap{
        party_id,
        1U,
        alice_id.account_id,
        alice_id.device_id,
        PartyVisibility::private_party,
        PartyJoinMode::invite_only,
        RelayPolicy::no_relays,
        4U,
        "",
        {
            make_member_record(alice_id, alice_ep, 1U),
            make_member_record(bob_id, bob_ep, 2U),
        },
    };
    server.push_mp1(bob_id.device_id, Mp1Message{snap});
    server.push_mp1(alice_id.device_id, Mp1Message{snap});

    auto peer_online = [](const PartySnapshot &ps, std::string_view peer_id) {
      for (const auto &p : ps.participants) {
        if (!p.local_self && p.id == peer_id &&
            p.state == PartyParticipantState::online) {
          return true;
        }
      }
      return false;
    };
    require_ok(
        wait_via_wake_fd(
            *alice,
            [&]() { return peer_online(alice->to_party_snapshot(), "bob_trusted"); },
            10000),
        "alice sees bob online over live iroh");
    require_ok(
        wait_via_wake_fd(
            *bob,
            [&]() { return peer_online(bob->to_party_snapshot(), "alice_trusted"); },
            10000),
        "bob sees alice online over live iroh");

    // 3A. Non-blocking post_chat -> poll(bob->wake_fd()) -> verified sanitized message
    //     + strict anti-spoofing!
    bob->drain_wake();
    require_void(alice->post_chat("hello from TUI!"), "alice post_chat");

    require_ok(wait_via_wake_fd(
                   *bob, [&]() { return !bob->to_party_snapshot().messages.empty(); }),
               "bob woke on wake_fd and received live iroh chat");

    const PartySnapshot bob_snap1 = bob->to_party_snapshot();
    require_ok(bob_snap1.messages.size() == 1U, "bob has 1 chat message");
    const PartyMessage &m1 = bob_snap1.messages[0];
    require_ok(m1.body == "hello from TUI!", "body matches");
    require_ok(m1.verified_peer && m1.untrusted_remote,
               "verified_peer true via TLS 1.3 Mutual RPK + CWT; remote content stays "
               "untrusted_remote");
    require_ok(m1.sender_id == "alice_trusted",
               "anti-spoofing: sender_id strictly from authenticated peer_metadata");
    require_ok(m1.sender_id != "spoofed_root_admin",
               "wire sender_handle MUST be ignored");
    const std::string expected_alice_fp =
        require_val(compute_device_fingerprint(alice_id.device_pubkey), "alice fp");
    require_ok(m1.sender_fingerprint == expected_alice_fp,
               "sender_fingerprint matches authenticated pubkey");

    // Alice also retained her own local echo.
    require_ok(
        wait_via_wake_fd(
            *alice, [&]() { return !alice->to_party_snapshot().messages.empty(); }),
        "alice retained local echo");
    require_ok(alice->to_party_snapshot().messages[0].body == "hello from TUI!",
               "alice local echo body");

    // PartyChatPane renders Bob's live snapshot cleanly.
    PartyChatPane bob_pane{bob_snap1};
    const std::string rendered = bob_pane.render(100, 22, false);
    require_ok(rendered.find("alice_trusted") != std::string::npos,
               "pane shows authenticated handle");
    require_ok(rendered.find("hello from TUI!") != std::string::npos,
               "pane shows chat body");
    require_ok(rendered.find("spoofed_root_admin") == std::string::npos,
               "pane NEVER shows spoofed wire handle");

    // 3B. Clear Bob's peer_metadata for Alice -> anti-spoofing fallback MUST use
    //     "peer_<device_id>", NEVER wire "spoofed_root_admin"!
    bob->update_peer_metadata(alice_id.device_id, MpPeerDisplayMetadata{});
    require_void(alice->post_chat("fallback handle test"), "alice fallback chat");
    require_ok(
        wait_via_wake_fd(
            *bob, [&]() { return bob->to_party_snapshot().messages.size() >= 2U; }),
        "bob received fallback handle test");
    const PartySnapshot bob_snap2 = bob->to_party_snapshot();
    const PartyMessage &m2 = bob_snap2.messages.back();
    require_ok(m2.sender_id == "peer_" + alice_id.device_id.to_decimal(),
               "fallback sender_id is peer_<device_id>, never spoofed wire handle");
    require_ok(m2.verified_peer, "fallback sender still cryptographically verified");

    // Restore Bob's metadata for Alice.
    bob->update_peer_metadata(alice_id.device_id,
                              MpPeerDisplayMetadata{"alice_trusted", "alice-mac"});

    // 3C. Hostile terminal-escape & Unicode bidi override sanitization over live iroh.
    const std::string hostile_payload =
        std::string{"\x1b[31mRED\x1b[0m \xe2\x80\xae"} + "spoof" + "\x07" + "bell";
    require_void(alice->post_chat(hostile_payload, "@bob"), "alice hostile chat");
    require_ok(
        wait_via_wake_fd(
            *bob, [&]() { return bob->to_party_snapshot().messages.size() >= 3U; }),
        "bob received hostile payload");
    const PartySnapshot bob_snap3 = bob->to_party_snapshot();
    const PartyMessage &m3 = bob_snap3.messages.back();
    require_ok(m3.body.find('\x1b') == std::string::npos,
               "no raw ESC in sanitized remote chat body");
    require_ok(m3.body.find('\x07') == std::string::npos,
               "no raw BEL in sanitized remote chat body");
    require_ok(m3.body.find("\xe2\x80\xae") == std::string::npos,
               "no raw bidi RLO override in sanitized remote chat body");
    require_ok(m3.body == party_chat_sanitize(hostile_payload, kPartyMaxMessageBytes),
               "body matches exact party_chat_sanitize() output");

    // 3D. Ephemeral pulse + synchronous bounded-timeout send_chat!
    require_void(alice->post_pulse(P2pPartyActivityState::working, "building"),
                 "alice post_pulse");
    require_ok(wait_via_wake_fd(*bob,
                                [&]() {
                                  for (const auto &p :
                                       bob->to_party_snapshot().participants) {
                                    if (!p.local_self && p.id == "alice_trusted" &&
                                        p.state == PartyParticipantState::working) {
                                      return true;
                                    }
                                  }
                                  return false;
                                }),
               "bob saw alice state transition to working via ephemeral pulse");

    const auto bob_send =
        require_val(bob->send_chat("roger that", "@alice"), "bob send_chat");
    require_ok(bob_send.sent == 1U, "bob send_chat delivered to 1 peer");
    require_ok(
        wait_via_wake_fd(*alice,
                         [&]() {
                           for (const auto &m : alice->to_party_snapshot().messages) {
                             if (m.body == "roger that" &&
                                 m.sender_id == "bob_trusted" && m.verified_peer) {
                               return true;
                             }
                           }
                           return false;
                         }),
        "alice received bob's send_chat");

    // 3E. Bounded message ring eviction (Bob's max_retained_messages == 5).
    for (int i = 1; i <= 7; ++i) {
      require_void(alice->post_chat("ring-msg-" + std::to_string(i)), "ring post_chat");
    }
    require_ok(wait_via_wake_fd(*bob,
                                [&]() {
                                  const auto msgs = bob->to_party_snapshot().messages;
                                  return !msgs.empty() &&
                                         msgs.back().body == "ring-msg-7";
                                }),
               "bob received ring-msg-7");
    const auto bob_ring = bob->to_party_snapshot().messages;
    require_ok(bob_ring.size() == 5U, "message ring strictly bounded at 5");
    require_ok(bob_ring.front().body == "ring-msg-3" &&
                   bob_ring.back().body == "ring-msg-7",
               "oldest messages evicted FIFO from ring");

    // 3F. Clean idempotent stop() on both sessions.
    alice->stop();
    bob->stop();
    alice->stop();
    bob->stop();
    require_ok(alice->wake_fd() == -1 && bob->wake_fd() == -1,
               "wake FDs closed cleanly on stop()");
  }

  // Note: iroh's internal process-wide tokio runtime may keep a few global
  // kqueue/pipe FDs across endpoints once initialized, so verify zero per-session
  // FD growth across a second create/stop cycle!
  const std::size_t fds_after_first = count_open_fds();
  {
    MpPartyRuntimeConfig a_rt2{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice_id),
        party_id,
    };
    a_rt2.local_relay_policy = RelayPolicy::no_relays;
    a_rt2.allow_loopback_direct_addrs = true;
    MpTuiSessionConfig a_cfg2{std::move(a_rt2)};
    a_cfg2.pump_tick_ms = 10U;
    auto s2 = require_val(MpTuiSession::start(std::move(a_cfg2)), "start cycle 2");
    require_ok(wait_via_wake_fd(
                   *s2, [&]() { return s2->state() == MpRuntimeState::connected; }),
               "cycle 2 connected");
    s2->stop();
  }
  const std::size_t fds_after_second = count_open_fds();
  require_ok(fds_after_second <= fds_after_first,
             "zero leaked FDs across repeated live iroh MpTuiSession cycles");
  (void)fds_before;

  std::cout << "PASS test_live_two_peer_iroh_e2e\n";
}

#else

void test_without_iroh_post_chat_fails_gracefully() {
  TempDir tmp{"tui_no_iroh"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const std::int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
  const auto party_id = require_val(PartyId::create(5010U), "party_id");
  const auto alice = make_test_identity(
      PeerIdentitySpec{1001U, 401U, 0x61U, "alice", now_s - 30, now_s + 3600});
  server.register_device(to_registered_device(alice));

  MpPartyRuntimeConfig rt_cfg{
      make_client_config(server.port(), cert.pem_path),
      to_identity_state(alice),
      party_id,
  };
  rt_cfg.local_relay_policy = RelayPolicy::no_relays;
  MpTuiSessionConfig cfg{std::move(rt_cfg)};
  cfg.pump_tick_ms = 10U;

  auto session = require_val(MpTuiSession::start(std::move(cfg)), "start HAS_IROH=0");
  require_ok(
      wait_via_wake_fd(*session,
                       [&]() { return session->state() == MpRuntimeState::connected; }),
      "connected without iroh");

  server.push_mp1(alice.device_id,
                  Mp1Message{PartySnapshotMessage{
                      party_id,
                      1U,
                      alice.account_id,
                      alice.device_id,
                      PartyVisibility::private_party,
                      PartyJoinMode::invite_only,
                      RelayPolicy::no_relays,
                      4U,
                      "",
                      {make_member_record(alice, make_lan_endpoint(4201U), 1U)},
                  }});
  require_ok(wait_via_wake_fd(*session,
                              [&]() { return session->snapshot().party_epoch == 1U; }),
             "snapshot applied without iroh");

  const auto send_res = session->send_chat("offline p2p test");
  require_ok(!send_res.has_value() && send_res.error().code == ErrorCode::unsupported,
             "send_chat returns unsupported when BLACKBIRD_HAS_IROH=0");
  session->stop();
  std::cout << "PASS test_without_iroh_post_chat_fails_gracefully\n";
}

#endif

// ---------------------------------------------------------------------------
// Test 2b: Concurrent update_peer_metadata() + drain_wake() + FD-reuse stress
//          racing stop() (runs under BOTH HAS_IROH=1 and HAS_IROH=0)
// ---------------------------------------------------------------------------

void test_concurrent_metadata_drain_and_stop_race() {
  TempDir tmp{"tui_race"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const std::int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
  const auto party_id = require_val(PartyId::create(5012U), "party_id");
  const auto alice = make_test_identity(
      PeerIdentitySpec{1001U, 505U, 0x71U, "alice", now_s - 30, now_s + 3600});
  const auto bob = make_test_identity(
      PeerIdentitySpec{2002U, 502U, 0x72U, "bob", now_s - 30, now_s + 3600});
  server.register_device(to_registered_device(alice));

  for (int round = 0; round < 5; ++round) {
    MpPartyRuntimeConfig rt_cfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    rt_cfg.local_relay_policy = RelayPolicy::no_relays;
    rt_cfg.p2p_connect_timeout_ms = 150U;
    MpTuiSessionConfig cfg{std::move(rt_cfg)};
    cfg.pump_tick_ms = 5U;

    auto session =
        require_val(MpTuiSession::start(std::move(cfg)), "start race session");
    require_ok(
        wait_via_wake_fd(
            *session, [&]() { return session->state() == MpRuntimeState::connected; }),
        "race session connected");

    std::atomic<bool> stop_hammers{false};
    std::atomic<bool> stray_byte_seen{false};

    std::thread meta_thread([&]() {
      std::uint64_t iter = 0U;
      while (!stop_hammers.load(std::memory_order_acquire)) {
        session->update_peer_metadata(
            bob.device_id,
            MpPeerDisplayMetadata{"bob_" + std::to_string(iter++), "lab"});
      }
    });

    std::thread drain_thread([&]() {
      while (!stop_hammers.load(std::memory_order_acquire)) {
        session->drain_wake();
        (void)session->to_party_snapshot();
      }
    });

    // Aggressively reuse OS FD numbers and verify no stray wake byte ever lands
    // on a newly opened unrelated pipe descriptor.
    std::thread fd_reuse_thread([&]() {
      while (!stop_hammers.load(std::memory_order_acquire)) {
        int fds[2] = {-1, -1};
        if (::pipe(fds) == 0) {
          const int fl = ::fcntl(fds[0], F_GETFL, 0);
          if (fl >= 0) {
            (void)::fcntl(fds[0], F_SETFL, fl | O_NONBLOCK);
          }
          std::this_thread::yield();
          char ch = 0;
          if (::read(fds[0], &ch, 1U) > 0) {
            stray_byte_seen.store(true, std::memory_order_release);
          }
          (void)::close(fds[0]);
          (void)::close(fds[1]);
        }
      }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds{25});
    session->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
    stop_hammers.store(true, std::memory_order_release);

    meta_thread.join();
    drain_thread.join();
    fd_reuse_thread.join();

    require_ok(!stray_byte_seen.load(std::memory_order_acquire),
               "signal_wake must NEVER write into a reused unrelated FD");
    require_ok(session->wake_fd() == -1, "wake_fd == -1 after stop()");
    require_ok(!session->is_active(), "session inactive after stop()");
  }

  std::cout << "PASS test_concurrent_metadata_drain_and_stop_race\n";
}

} // namespace

int main() {
  block_sigpipe_this_thread();
  test_config_validation_and_failed_attach();
  test_control_lifecycle_wake_fd_and_party_snapshot();
  test_concurrent_metadata_drain_and_stop_race();
#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
  test_live_two_peer_iroh_e2e();
#else
  test_without_iroh_post_chat_fails_gracefully();
#endif
  std::cout << "mp_tui_session_test: ALL PASSED\n";
  return 0;
}
