#include "blackbird/mp_party_runtime.hpp"

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
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
    std::cerr << "mp_party_runtime_test FAIL at " << loc.file_name() << ":"
              << loc.line();
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
    std::cerr << "mp_party_runtime_test FAIL (empty optional) at " << loc.file_name()
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
    std::cerr << "mp_party_runtime_test FAIL (Result error code="
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
    std::cerr << "mp_party_runtime_test FAIL (Result<void> error code="
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

// ---------------------------------------------------------------------------
// TempDir + Ephemeral Self-Signed TLS 1.3 Certificate
// ---------------------------------------------------------------------------

struct TempDir {
  std::filesystem::path path;
  explicit TempDir(std::string_view tag) {
    static std::atomic<std::uint64_t> counter{0U};
    const auto id = counter.fetch_add(1U, std::memory_order_relaxed);
    path = std::filesystem::temp_directory_path() /
           ("bb_mp_party_runtime_test_" + std::string{tag} + "_" +
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
// Minimal RFC 6455 & TLS Helpers for Mock PartyDO Server
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

// Attempts to parse a complete client WS frame from `buf` starting at offset 0.
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

// ---------------------------------------------------------------------------
// Multi-Client In-Process TLS 1.3 Mock PartyDO Server
// ---------------------------------------------------------------------------

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

  bool wait_for_connect_count(
      DeviceId device_id, std::uint32_t expected_count,
      std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) {
    std::unique_lock<std::mutex> lk{mu_};
    return cv_.wait_for(lk, timeout, [&]() {
      const auto it = slots_.find(device_id.value());
      return it != slots_.end() && it->second.connect_count >= expected_count;
    });
  }

  std::uint32_t ping_count(DeviceId device_id) {
    std::lock_guard<std::mutex> lk{mu_};
    const auto it = slots_.find(device_id.value());
    return it == slots_.end() ? 0U : it->second.ping_count;
  }

  void set_hello_server_now_ms_override(std::optional<std::uint64_t> server_now_ms) {
    std::lock_guard<std::mutex> lk{mu_};
    hello_server_now_ms_override_ = server_now_ms;
  }

  void set_coalesced_initial_mp1(DeviceId device_id, std::optional<Mp1Message> msg) {
    std::lock_guard<std::mutex> lk{mu_};
    coalesced_initial_mp1_[device_id.value()] = std::move(msg);
  }

  void set_upgrade_reject_status(DeviceId device_id, std::optional<int> status) {
    std::lock_guard<std::mutex> lk{mu_};
    if (status.has_value()) {
      upgrade_reject_status_[device_id.value()] = *status;
    } else {
      upgrade_reject_status_.erase(device_id.value());
    }
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

    // Read HTTP/1.1 upgrade headers.
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

    // Authenticate RFC 9421 device signature.
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
    std::optional<int> reject_status;
    std::optional<std::uint64_t> hello_now_override;
    std::optional<Mp1Message> coalesced_msg;
    {
      std::lock_guard<std::mutex> lk{mu_};
      const auto it = devices_.find(dev_keyid.device_id.value());
      if (it == devices_.end() || it->second.account_id != dev_keyid.account_id) {
        (void)ssl_write_str(ssl, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                                 "Connection: close\r\n\r\n");
        return;
      }
      verify_pk = it->second.device_pubkey;
      if (const auto rej = upgrade_reject_status_.find(dev_keyid.device_id.value());
          rej != upgrade_reject_status_.end()) {
        reject_status = rej->second;
      }
      hello_now_override = hello_server_now_ms_override_;
      if (const auto c = coalesced_initial_mp1_.find(dev_keyid.device_id.value());
          c != coalesced_initial_mp1_.end()) {
        coalesced_msg = c->second;
      }
    }

    if (reject_status.has_value()) {
      if (*reject_status == 401) {
        const std::string body = "{\"error\":\"device_revoked\"}";
        (void)ssl_write_str(
            ssl, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n"
                 "Content-Length: " +
                     std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" +
                     body);
      } else {
        (void)ssl_write_str(ssl, "HTTP/1.1 " + std::to_string(*reject_status) +
                                     " Service Unavailable\r\nContent-Length: 0\r\n"
                                     "Connection: close\r\n\r\n");
      }
      return;
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

    // Complete RFC 6455 upgrade + coalesce HELLO_ACK (and optional initial MP1)!
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
    const std::uint64_t advertised_now_ms =
        hello_now_override.has_value() ? *hello_now_override : now_ms;
    const auto hello_bytes = encode_frame(
        0U, HelloAckMessage{require_val(SessionId::create(session_num), "session_id"),
                            advertised_now_ms, hello_ping_interval_ms_});
    require_ok(hello_bytes.has_value(), "encode HELLO_ACK");
    const auto hello_ws = build_server_ws_frame(0x02U, hello_bytes.value());

    std::vector<std::uint8_t> initial(resp.begin(), resp.end());
    initial.insert(initial.end(), hello_ws.begin(), hello_ws.end());
    if (coalesced_msg.has_value()) {
      const auto extra_enc = encode_frame(0U, *coalesced_msg);
      require_ok(extra_enc.has_value(), "encode coalesced initial MP1");
      const auto extra_ws = build_server_ws_frame(0x02U, extra_enc.value());
      initial.insert(initial.end(), extra_ws.begin(), extra_ws.end());
    }
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
      // 1. Drain outbound actions for this connection generation.
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

      // 2. Poll for incoming client frames (short 10ms slice).
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
  std::atomic<std::uint64_t> next_session_id_{100U};
  std::thread accept_thread_;

  std::mutex mu_;
  std::condition_variable cv_;
  std::vector<std::thread> worker_threads_;
  std::map<std::uint64_t, RegisteredDevice> devices_;
  std::map<std::uint64_t, ClientSlot> slots_;
  std::optional<std::uint64_t> hello_server_now_ms_override_;
  std::map<std::uint64_t, std::optional<Mp1Message>> coalesced_initial_mp1_;
  std::map<std::uint64_t, int> upgrade_reject_status_;
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

std::optional<MpRuntimeEvent>
pump_until_event(MpPartyRuntime &rt, MpRuntimeEventKind expected,
                 std::optional<std::int64_t> now_s_override, int max_wait_ms = 5000) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds{max_wait_ms};
  while (std::chrono::steady_clock::now() < deadline) {
    while (auto ev = rt.pop_event()) {
      if (ev->kind == expected) {
        return ev;
      }
    }
    (void)require_val(rt.pump_once(20U, now_s_override), "pump_once");
    while (auto ev = rt.pop_event()) {
      if (ev->kind == expected) {
        return ev;
      }
    }
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Test 1: Config validation, control WS attach, HELLO_ACK clamping, PING/PONG,
//         PARTY_SNAPSHOT CWT verification, leader change, PARTY_DISBANDED
//         (runs under BOTH HAS_IROH=1 and HAS_IROH=0)
// ---------------------------------------------------------------------------

void test_control_lifecycle_and_disband() {
  TempDir tmp{"ctrl"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  // Request ping_interval_ms = 1000 -> runtime MUST clamp to 5000ms minimum!
  MockPartyDoServer server{cert, "localhost", /*hello_ping_interval_ms=*/1000U};

  const std::int64_t t0 = 1764000000;
  const auto party_id = require_val(PartyId::create(5501U), "party_id");
  const auto alice = make_test_identity(
      PeerIdentitySpec{1001U, 200U, 0x11U, "alice", t0 - 10, t0 + 3600});
  const auto bob = make_test_identity(
      PeerIdentitySpec{2002U, 100U, 0x22U, "bob", t0 - 10, t0 + 3600});
  const auto mallory = make_test_identity(
      PeerIdentitySpec{3003U, 300U, 0x33U, "mallory", t0 - 10, t0 + 3600});
  server.register_device(to_registered_device(alice));

  // Config validation checks.
  {
    MpPartyRuntimeConfig bad_missing_id{
        make_client_config(server.port(), cert.pem_path),
        MpIdentityState{},
        party_id,
    };
    const auto r = MpPartyRuntime::attach(bad_missing_id);
    require_ok(!r.has_value() && mp_party_runtime_error_of(r.error()) ==
                                     MpPartyRuntimeError::missing_identity,
               "missing identity must fail closed");
  }
  {
    MpPartyRuntimeConfig bad_ttl{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    bad_ttl.max_lease_ttl_s = 61;
    const auto r = MpPartyRuntime::attach(bad_ttl);
    require_ok(!r.has_value() && mp_party_runtime_error_of(r.error()) ==
                                     MpPartyRuntimeError::invalid_config,
               "max_lease_ttl_s > 60 must fail closed");
  }
  {
    MpPartyRuntimeConfig bad_relay{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    bad_relay.local_relay_policy = RelayPolicy::force_relays;
    bad_relay.relay_url = std::nullopt;
    const auto r = MpPartyRuntime::attach(bad_relay);
    require_ok(!r.has_value() &&
                   mp_error_of(r.error()) == MpError::force_relays_violation,
               "force_relays without relay_url must fail closed");
  }

  MpPartyRuntimeConfig cfg{
      make_client_config(server.port(), cert.pem_path),
      to_identity_state(alice),
      party_id,
  };
  cfg.local_relay_policy = RelayPolicy::no_relays;
  cfg.max_lease_ttl_s = 60;
  cfg.allow_loopback_direct_addrs = true;

  auto rt = require_val(MpPartyRuntime::attach(std::move(cfg)), "attach alice");
  require_ok(rt.is_control_connected(), "control connected after attach");
  require_ok(!rt.is_terminated(), "not terminated after attach");
  require_ok(require_opt(rt.local_pubkey(), "local_pubkey") == alice.device_pubkey,
             "local_pubkey must match identity device key");

  // 1. Receive HELLO_ACK -> verify clamping to 5000ms and auto PARTY_ENDPOINT_UPDATE.
  const auto hello_ev = require_opt(
      pump_until_event(rt, MpRuntimeEventKind::hello_acked, t0), "hello_acked event");
  require_ok(hello_ev.session_id.has_value(), "session_id recorded");
  require_ok(rt.state() == MpRuntimeState::connected, "state == connected");
  require_ok(rt.ping_interval_ms() == kMpRuntimeMinPingIntervalMs,
             "ping_interval_ms clamped to 5000ms");
  const auto published_ep =
      require_opt(server.wait_for_endpoint_update(alice.device_id, 1U,
                                                  std::chrono::milliseconds{3000}),
                  "auto PARTY_ENDPOINT_UPDATE sent after HELLO_ACK");

  // 2. Push PARTY_SNAPSHOT with valid Bob + forged Mallory -> verify CWT gate.
  auto mallory_rec = make_member_record(mallory, make_lan_endpoint(4300U), 3U);
  mallory_rec.device_cwt.back() ^= 0xAAU; // Forge signature!
  PartySnapshotMessage snap{
      party_id,
      1U,
      alice.account_id,
      alice.device_id,
      PartyVisibility::private_party,
      PartyJoinMode::invite_only,
      RelayPolicy::no_relays,
      4U,
      "",
      {
          make_member_record(alice, published_ep, 1U),
          make_member_record(bob, make_lan_endpoint(4200U), 2U),
          mallory_rec,
      },
  };
  server.push_mp1(alice.device_id, Mp1Message{snap});

  const auto snap_ev =
      require_opt(pump_until_event(rt, MpRuntimeEventKind::snapshot_applied, t0),
                  "snapshot_applied");
  const auto &snap_rep = require_opt(snap_ev.snapshot_result, "snapshot_result");
  require_ok(snap_rep.admitted_peers.size() == 1U &&
                 snap_rep.admitted_peers[0] == bob.device_id,
             "only Bob admitted");
  require_ok(snap_rep.rejected_members.size() == 1U &&
                 snap_rep.rejected_members[0].device_id == mallory.device_id,
             "forged Mallory rejected");
  require_ok(rt.party_epoch() == 1U && rt.peer_count() == 1U, "roster == {bob}");

  // 3. Verify MP1:PING / MP1:PONG cadence and lease refresh!
  (void)require_val(rt.pump_once(10U, t0 + 4), "pump at t0+4 (before ping due)");
  require_ok(server.ping_count(alice.device_id) == 0U, "no ping before 5s interval");

  (void)require_val(rt.pump_once(20U, t0 + 5), "pump at t0+5 (triggers MP1:PING)");
  const auto pong_deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds{3000};
  while (rt.last_pong_ms() == 0U && std::chrono::steady_clock::now() < pong_deadline) {
    (void)require_val(rt.pump_once(20U, t0 + 6), "pump awaiting MP1:PONG");
  }
  require_ok(server.ping_count(alice.device_id) >= 1U, "server received MP1:PING");
  require_ok(rt.last_pong_ms() > 0U, "client received MP1:PONG");
  // Lease was refreshed at t0+6 -> still alive at t0+65 (60s after t0+5), evicted at
  // t0+67 (> 60s after t0+6)!
  const auto bob_peer = require_opt(rt.find_peer(bob.device_id), "bob in roster");
  require_ok(bob_peer.last_confirmed_s == t0 + 6, "PONG refreshed peer lease");

  // 4. Verify explicit send_endpoint_update() and PARTY_LEADER_CHANGED.
  require_void(rt.send_endpoint_update(), "explicit send_endpoint_update");
  require_ok(server
                 .wait_for_endpoint_update(alice.device_id, 2U,
                                           std::chrono::milliseconds{3000})
                 .has_value(),
             "server received explicit PARTY_ENDPOINT_UPDATE");
  server.push_mp1(alice.device_id, Mp1Message{PartyLeaderChangedMessage{
                                       2U, bob.account_id, bob.device_id,
                                       PartyLeaderChangeReason::promoted}});
  const auto leader_ev =
      require_opt(pump_until_event(rt, MpRuntimeEventKind::leader_changed, t0 + 7),
                  "leader_changed");
  require_ok(leader_ev.device_id == bob.device_id &&
                 rt.leader_device_id() == bob.device_id && rt.party_epoch() == 2U,
             "leader updated to bob at epoch 2");

  // 5. Verify PARTY_DISBANDED -> clean WS close (1000) + terminal disbanded state!
  server.push_mp1(alice.device_id, Mp1Message{PartyDisbandedMessage{
                                       3U, PartyDisbandReason::leader_disbanded}});
  const auto disband_ev =
      require_opt(pump_until_event(rt, MpRuntimeEventKind::party_disbanded, t0 + 8),
                  "party_disbanded");
  require_ok(disband_ev.disband_reason == PartyDisbandReason::leader_disbanded,
             "disband reason");
  require_ok(rt.state() == MpRuntimeState::disbanded, "state == disbanded");
  require_ok(rt.is_terminated(), "is_terminated == true");
  require_ok(!rt.is_control_connected(), "WS closed cleanly");
  require_ok(rt.peer_count() == 0U && !rt.has_p2p_endpoint(),
             "roster cleared and P2P endpoint closed on disband");

  const auto fail_send = rt.broadcast_chat(
      P2pPartyChatMessage{"party/main", "@all", "alice", 1LL, "after disband"});
  require_ok(!fail_send.has_value() && mp_party_runtime_error_of(fail_send.error()) ==
                                           MpPartyRuntimeError::runtime_terminated,
             "outbound send after disband must fail closed");

  std::cout << "PASS test_control_lifecycle_and_disband\n";
}

// ---------------------------------------------------------------------------
// Test 2: WS Close 4401 (device revoked) & 4403 (kicked/banned) hard teardown
//         (runs under BOTH HAS_IROH=1 and HAS_IROH=0)
// ---------------------------------------------------------------------------

void test_ws_close_4401_and_4403_hard_teardown() {
  TempDir tmp{"hard_teardown"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const std::int64_t t0 = 1764001000;
  const auto party_id = require_val(PartyId::create(5502U), "party_id");
  const auto alice = make_test_identity(
      PeerIdentitySpec{1001U, 200U, 0x41U, "alice", t0 - 10, t0 + 3600});
  const auto bob = make_test_identity(
      PeerIdentitySpec{2002U, 100U, 0x42U, "bob", t0 - 10, t0 + 3600});
  server.register_device(to_registered_device(alice));

  for (const std::uint16_t close_code :
       {kMpWsCloseDeviceRevoked, kMpWsCloseKickedOrBanned}) {
    MpPartyRuntimeConfig cfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    cfg.local_relay_policy = RelayPolicy::no_relays;
    cfg.max_reconnect_attempts = 5U;
    cfg.reconnect_base_ms = 20U;
    cfg.reconnect_max_ms = 100U;

    auto rt =
        require_val(MpPartyRuntime::attach(std::move(cfg)), "attach for close test");
    (void)require_opt(pump_until_event(rt, MpRuntimeEventKind::hello_acked, t0),
                      "hello_acked");

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
                        {make_member_record(bob, make_lan_endpoint(4200U), 1U)},
                    }});
    (void)require_opt(pump_until_event(rt, MpRuntimeEventKind::snapshot_applied, t0),
                      "snapshot_applied");
    require_ok(rt.peer_count() == 1U, "bob present before hard close");

    server.send_ws_close(alice.device_id, close_code);
    const auto kicked_ev =
        require_opt(pump_until_event(rt, MpRuntimeEventKind::kicked_or_revoked, t0 + 1),
                    "kicked_or_revoked");
    require_ok(kicked_ev.ws_close_code == close_code, "exact close code reported");
    require_ok(rt.state() == MpRuntimeState::terminated, "state == terminated");
    require_ok(rt.is_terminated(), "is_terminated");
    require_ok(!rt.is_control_connected(), "WS disconnected");
    require_ok(rt.peer_count() == 0U && !rt.has_p2p_endpoint(),
               "all peers revoked and P2P endpoint torn down");

    // Pump again: must NOT reconnect!
    const auto pumped =
        require_val(rt.pump_once(50U, t0 + 2), "pump after termination");
    require_ok(pumped == 0U && rt.is_terminated() && !rt.is_control_connected(),
               "must remain terminated and never reconnect");
  }

  std::cout << "PASS test_ws_close_4401_and_4403_hard_teardown\n";
}

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH

// Helper: pumps both Alice and Bob concurrently in short slices until predicate holds.
template <typename Pred>
bool pump_pair_until(MpPartyRuntime &alice, MpPartyRuntime &bob,
                     std::optional<std::int64_t> now_s_override, Pred &&pred,
                     int max_wait_ms = 8000) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds{max_wait_ms};
  while (std::chrono::steady_clock::now() < deadline) {
    if (pred()) {
      return true;
    }
    (void)require_val(alice.pump_once(15U, now_s_override), "alice pump_once");
    (void)require_val(bob.pump_once(15U, now_s_override), "bob pump_once");
    if (pred()) {
      return true;
    }
  }
  return pred();
}

// ---------------------------------------------------------------------------
// Test 3: Full 2-Peer Live Control WS <-> iroh v1.5.0 P2P End-to-End
// ---------------------------------------------------------------------------

void test_live_two_peer_control_and_iroh_p2p_end_to_end() {
  require_ok(p2p_iroh_compiled_in(), "p2p_iroh_compiled_in must be true");

  TempDir tmp{"live_e2e"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const std::int64_t t0 = 1764010000;
  const auto party_id = require_val(PartyId::create(7001U), "party_id");
  const auto alice_id = make_test_identity(
      PeerIdentitySpec{1001U, 100U, 0x51U, "alice", t0 - 10, t0 + 3600});
  const auto bob_id = make_test_identity(
      PeerIdentitySpec{2002U, 200U, 0x62U, "bob", t0 - 10, t0 + 3600});
  const auto mallory_id = make_test_identity(
      PeerIdentitySpec{3003U, 300U, 0x73U, "mallory", t0 - 10, t0 + 3600});

  server.register_device(to_registered_device(alice_id));
  server.register_device(to_registered_device(bob_id));

  auto make_cfg = [&](const TestPeerIdentity &id) {
    MpPartyRuntimeConfig cfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(id),
        party_id,
    };
    cfg.local_relay_policy = RelayPolicy::no_relays;
    cfg.max_lease_ttl_s = 10;
    cfg.allow_loopback_direct_addrs = true;
    return cfg;
  };

  auto alice = require_val(MpPartyRuntime::attach(make_cfg(alice_id)), "attach alice");
  auto bob = require_val(MpPartyRuntime::attach(make_cfg(bob_id)), "attach bob");

  // Verify TLS 1.3 Mutual RPK pubkeys match device CWT pubkeys 100%!
  require_ok(alice.has_p2p_endpoint() && bob.has_p2p_endpoint(),
             "both peers have live iroh endpoints");
  require_ok(require_opt(alice.local_pubkey()) == alice_id.device_pubkey,
             "alice iroh RPK == identity device_pubkey");
  require_ok(require_opt(bob.local_pubkey()) == bob_id.device_pubkey,
             "bob iroh RPK == identity device_pubkey");

  // 1. Pump until both receive HELLO_ACK and publish PARTY_ENDPOINT_UPDATE.
  bool alice_hello = false;
  bool bob_hello = false;
  require_ok(pump_pair_until(alice, bob, t0,
                             [&]() {
                               while (auto ev = alice.pop_event()) {
                                 if (ev->kind == MpRuntimeEventKind::hello_acked) {
                                   alice_hello = true;
                                 }
                               }
                               while (auto ev = bob.pop_event()) {
                                 if (ev->kind == MpRuntimeEventKind::hello_acked) {
                                   bob_hello = true;
                                 }
                               }
                               return alice_hello && bob_hello;
                             }),
             "both peers receive HELLO_ACK");

  const auto alice_ep =
      require_opt(server.wait_for_endpoint_update(alice_id.device_id, 1U,
                                                  std::chrono::milliseconds{3000}),
                  "alice PARTY_ENDPOINT_UPDATE");
  const auto bob_ep =
      require_opt(server.wait_for_endpoint_update(bob_id.device_id, 1U,
                                                  std::chrono::milliseconds{3000}),
                  "bob PARTY_ENDPOINT_UPDATE");
  require_ok(!alice_ep.direct_addrs.empty() && !bob_ep.direct_addrs.empty(),
             "live no_relays peers published reachable direct addrs");

  // 2. Mock PartyDO broadcasts PARTY_SNAPSHOT containing Alice + Bob + forged Mallory.
  auto mallory_rec = make_member_record(mallory_id, make_lan_endpoint(4999U), 3U);
  mallory_rec.device_cwt.back() ^= 0x55U;
  PartySnapshotMessage snapshot{
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
          mallory_rec,
      },
  };
  // Push snapshot to Bob first so Bob allowlists Alice, then push to Alice so Alice
  // (100 < 200) deterministically dials Bob over live iroh QUIC!
  server.push_mp1(bob_id.device_id, Mp1Message{snapshot});
  server.push_mp1(alice_id.device_id, Mp1Message{snapshot});

  bool alice_snap = false;
  bool bob_snap = false;
  bool alice_connected = false;
  bool bob_connected = false;
  require_ok(
      pump_pair_until(
          alice, bob, t0,
          [&]() {
            while (auto ev = alice.pop_event()) {
              if (ev->kind == MpRuntimeEventKind::snapshot_applied) {
                const auto &rep = require_opt(ev->snapshot_result);
                require_ok(rep.admitted_peers.size() == 1U &&
                           rep.admitted_peers[0] == bob_id.device_id);
                require_ok(rep.rejected_members.size() == 1U &&
                           rep.rejected_members[0].device_id == mallory_id.device_id);
                alice_snap = true;
              } else if (ev->kind == MpRuntimeEventKind::peer_connected) {
                require_ok(ev->sender_device_id == bob_id.device_id &&
                           ev->sender_account_id == bob_id.account_id &&
                           ev->peer_pubkey == bob_id.device_pubkey);
                alice_connected = true;
              }
            }
            while (auto ev = bob.pop_event()) {
              if (ev->kind == MpRuntimeEventKind::snapshot_applied) {
                const auto &rep = require_opt(ev->snapshot_result);
                require_ok(rep.admitted_peers.size() == 1U &&
                           rep.admitted_peers[0] == alice_id.device_id);
                require_ok(rep.rejected_members.size() == 1U &&
                           rep.rejected_members[0].device_id == mallory_id.device_id);
                bob_snap = true;
              } else if (ev->kind == MpRuntimeEventKind::peer_connected) {
                require_ok(ev->sender_device_id == alice_id.device_id &&
                           ev->sender_account_id == alice_id.account_id &&
                           ev->peer_pubkey == alice_id.device_pubkey);
                bob_connected = true;
              }
            }
            return alice_snap && bob_snap && alice_connected && bob_connected;
          },
          10000),
      "Alice and Bob connect over live iroh QUIC + TLS 1.3 Mutual RPK");

  // 3. Alice sends all 4 typed data-plane frames -> Bob receives all 4 with verified
  //    sender_device_id == 100 & sender_account_id == 1001!
  const P2pPartyChatMessage a_chat{
      "party/main", "@bob", "alice", 100001LL, "hello bob over live iroh!",
  };
  const P2pPartyBridgeEnvelope a_bridge{
      "party/bridge",
      std::vector<std::uint8_t>{0xdeU, 0xadU, 0xbeU, 0xefU, 0x42U},
  };
  const P2pPartyControlNotice a_notice{
      P2pPartyControlNoticeKind::sync_ack,
      1U,
      "epoch-1-ready",
  };
  const P2pPartyEphemeralPulse a_pulse{
      P2pPartyActivityState::working,
      100002LL,
      "wave-13a-live",
  };

  require_ok(require_val(alice.broadcast_chat(a_chat), "alice chat").sent == 1U);
  require_ok(
      require_val(alice.broadcast_bridge_envelope(a_bridge), "alice bridge").sent ==
      1U);
  require_ok(
      require_val(alice.broadcast_control_notice(a_notice), "alice notice").sent == 1U);
  require_ok(
      require_val(alice.broadcast_ephemeral_pulse(a_pulse), "alice pulse").sent == 1U);

  bool bob_got_chat = false;
  bool bob_got_bridge = false;
  bool bob_got_notice = false;
  bool bob_got_pulse = false;
  require_ok(
      pump_pair_until(
          alice, bob, t0,
          [&]() {
            (void)alice.drain_events();
            while (auto ev = bob.pop_event()) {
              if (ev->kind == MpRuntimeEventKind::chat_received) {
                require_ok(ev->sender_device_id == alice_id.device_id &&
                           ev->sender_account_id == alice_id.account_id &&
                           require_opt(ev->chat) == a_chat);
                bob_got_chat = true;
              } else if (ev->kind == MpRuntimeEventKind::bridge_envelope_received) {
                require_ok(ev->sender_device_id == alice_id.device_id &&
                           ev->sender_account_id == alice_id.account_id &&
                           require_opt(ev->bridge_envelope) == a_bridge);
                bob_got_bridge = true;
              } else if (ev->kind == MpRuntimeEventKind::control_notice_received) {
                require_ok(ev->sender_device_id == alice_id.device_id &&
                           ev->sender_account_id == alice_id.account_id &&
                           require_opt(ev->control_notice) == a_notice);
                bob_got_notice = true;
              } else if (ev->kind == MpRuntimeEventKind::ephemeral_pulse_received) {
                require_ok(ev->sender_device_id == alice_id.device_id &&
                           ev->sender_account_id == alice_id.account_id &&
                           require_opt(ev->ephemeral_pulse) == a_pulse);
                bob_got_pulse = true;
              }
            }
            return bob_got_chat && bob_got_bridge && bob_got_notice && bob_got_pulse;
          }),
      "Bob received all 4 typed frames from Alice");

  // 4. Bob replies with broadcast_chat + send_chat_to -> Alice receives with
  //    sender_device_id == 200!
  const P2pPartyChatMessage b_reply{
      "party/main", "@alice", "bob", 100003LL, "roger alice, loud and clear!",
  };
  require_ok(require_val(bob.broadcast_chat(b_reply), "bob reply").sent == 1U);
  const auto alice_got_reply =
      require_opt(pump_until_event(alice, MpRuntimeEventKind::chat_received, t0, 5000),
                  "alice received bob reply");
  require_ok(alice_got_reply.sender_device_id == bob_id.device_id &&
                 alice_got_reply.sender_account_id == bob_id.account_id &&
                 require_opt(alice_got_reply.chat) == b_reply,
             "bob reply attribution and payload match");

  const P2pPartyChatMessage b_direct{
      "party/main", "@alice", "bob", 100004LL, "direct unicast chat!",
  };
  require_void(bob.send_chat_to(alice_id.device_id, b_direct), "bob send_chat_to");
  const auto alice_got_direct =
      require_opt(pump_until_event(alice, MpRuntimeEventKind::chat_received, t0, 5000),
                  "alice received direct chat");
  require_ok(alice_got_direct.sender_device_id == bob_id.device_id &&
                 require_opt(alice_got_direct.chat) == b_direct,
             "direct chat attribution and payload match");

  // 4b. Verify PARTY_MEMBER_UPDATED advances epoch cleanly.
  server.push_mp1(alice_id.device_id,
                  Mp1Message{PartyMemberUpdatedMessage{2U, bob_id.device_id, true,
                                                       bob_id.device_cwt, bob_ep}});
  const auto upd_ev =
      require_opt(pump_until_event(alice, MpRuntimeEventKind::member_updated, t0 + 1),
                  "alice member_updated");
  require_ok(upd_ev.device_id == bob_id.device_id && alice.party_epoch() == 2U,
             "member_updated advanced epoch to 2");

  // 5. Server sends PARTY_MEMBER_LEFT(bob, device_revoked) to Alice ->
  //    Alice IMMEDIATELY revokes Bob (QUIC 4403), Bob observes disconnect,
  //    subsequent sends fail closed!
  server.push_mp1(alice_id.device_id, Mp1Message{PartyMemberLeftMessage{
                                          3U, bob_id.device_id, bob_id.account_id,
                                          MemberLeaveReason::device_revoked}});

  bool alice_saw_left = false;
  bool bob_saw_disc = false;
  require_ok(
      pump_pair_until(alice, bob, t0 + 1,
                      [&]() {
                        while (auto ev = alice.pop_event()) {
                          if (ev->kind == MpRuntimeEventKind::member_left) {
                            require_ok(ev->device_id == bob_id.device_id &&
                                       ev->leave_reason ==
                                           MemberLeaveReason::device_revoked);
                            alice_saw_left = true;
                          }
                        }
                        while (auto ev = bob.pop_event()) {
                          if (ev->kind == MpRuntimeEventKind::peer_disconnected) {
                            require_ok(ev->peer_pubkey == alice_id.device_pubkey &&
                                       ev->reason_code == 4403U);
                            bob_saw_disc = true;
                          }
                        }
                        return alice_saw_left && bob_saw_disc;
                      }),
      "PARTY_MEMBER_LEFT revoked Bob with QUIC 4403");

  require_ok(alice.peer_count() == 0U, "alice removed revoked bob from roster");
  const auto fail_send = alice.send_chat_to(bob_id.device_id, a_chat);
  require_ok(!fail_send.has_value() &&
                 p2p_party_error_of(fail_send.error()) == P2pPartyError::peer_not_found,
             "subsequent send to revoked bob fails closed");

  // 6. Verify RAII move semantics + PARTY_MEMBER_JOINED re-admits & redials Bob!
  MpPartyRuntime moved_alice = std::move(alice);
  require_ok(!moved_alice.is_terminated() && moved_alice.is_control_connected(),
             "moved-to runtime remains live and connected");
  server.push_mp1(alice_id.device_id, Mp1Message{PartyMemberJoinedMessage{
                                          4U, make_member_record(bob_id, bob_ep, 4U)}});
  bool alice_saw_joined = false;
  bool alice_reconn = false;
  bool bob_reconn = false;
  require_ok(pump_pair_until(moved_alice, bob, t0 + 2, [&]() {
    while (auto ev = moved_alice.pop_event()) {
      if (ev->kind == MpRuntimeEventKind::member_joined) {
        require_ok(ev->device_id == bob_id.device_id);
        alice_saw_joined = true;
      } else if (ev->kind == MpRuntimeEventKind::peer_connected) {
        alice_reconn = true;
      }
    }
    while (auto ev = bob.pop_event()) {
      if (ev->kind == MpRuntimeEventKind::peer_connected) {
        bob_reconn = true;
      }
    }
    return alice_saw_joined && alice_reconn && bob_reconn;
  }));

  std::cout << "PASS test_live_two_peer_control_and_iroh_p2p_end_to_end\n";
}

// ---------------------------------------------------------------------------
// Test 4: Transient WS drop (1006) preserves live P2P until TTL expiry,
//         bounded exponential WS reconnect, live 4403 teardown & PARTY_DISBANDED
// ---------------------------------------------------------------------------

void test_live_ws_drop_ttl_eviction_reconnect_and_teardown() {
  TempDir tmp{"live_resilience"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const std::int64_t t0 = 1764020000;
  const auto party_id = require_val(PartyId::create(7002U), "party_id");
  const auto alice_id = make_test_identity(
      PeerIdentitySpec{1001U, 100U, 0x81U, "alice", t0 - 10, t0 + 3600});
  const auto bob_id = make_test_identity(
      PeerIdentitySpec{2002U, 200U, 0x82U, "bob", t0 - 10, t0 + 3600});
  server.register_device(to_registered_device(alice_id));
  server.register_device(to_registered_device(bob_id));

  auto attach_and_connect_pair = [&](std::uint32_t alice_max_reconnects)
      -> std::pair<MpPartyRuntime, MpPartyRuntime> {
    MpPartyRuntimeConfig acfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice_id),
        party_id,
    };
    acfg.local_relay_policy = RelayPolicy::no_relays;
    acfg.max_lease_ttl_s = 10;
    acfg.max_reconnect_attempts = alice_max_reconnects;
    acfg.reconnect_base_ms = 40U;
    acfg.reconnect_max_ms = 200U;
    acfg.allow_loopback_direct_addrs = true;

    MpPartyRuntimeConfig bcfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(bob_id),
        party_id,
    };
    bcfg.local_relay_policy = RelayPolicy::no_relays;
    bcfg.max_lease_ttl_s = 60;
    bcfg.allow_loopback_direct_addrs = true;

    auto alice = require_val(MpPartyRuntime::attach(std::move(acfg)), "attach alice");
    auto bob = require_val(MpPartyRuntime::attach(std::move(bcfg)), "attach bob");

    bool a_hello = false;
    bool b_hello = false;
    require_ok(pump_pair_until(alice, bob, t0, [&]() {
      while (auto ev = alice.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::hello_acked) {
          a_hello = true;
        }
      }
      while (auto ev = bob.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::hello_acked) {
          b_hello = true;
        }
      }
      return a_hello && b_hello;
    }));

    const auto a_ep = require_val(alice.local_endpoint_descriptor(), "alice ep");
    const auto b_ep = require_val(bob.local_endpoint_descriptor(), "bob ep");
    PartySnapshotMessage snap{
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
            make_member_record(alice_id, a_ep, 1U),
            make_member_record(bob_id, b_ep, 2U),
        },
    };
    server.push_mp1(bob_id.device_id, Mp1Message{snap});
    server.push_mp1(alice_id.device_id, Mp1Message{snap});

    bool a_conn = false;
    bool b_conn = false;
    require_ok(pump_pair_until(
                   alice, bob, t0,
                   [&]() {
                     while (auto ev = alice.pop_event()) {
                       if (ev->kind == MpRuntimeEventKind::peer_connected) {
                         a_conn = true;
                       }
                     }
                     while (auto ev = bob.pop_event()) {
                       if (ev->kind == MpRuntimeEventKind::peer_connected) {
                         b_conn = true;
                       }
                     }
                     return a_conn && b_conn;
                   },
                   10000),
               "pair connected over live iroh");
    return {std::move(alice), std::move(bob)};
  };

  // Part A: Transient WS close (1006) preserves live P2P until TTL expiry, then evicts!
  {
    auto [alice, bob] = attach_and_connect_pair(/*alice_max_reconnects=*/0U);
    server.drop_connection_abruptly(alice_id.device_id);
    const auto disc_ev = require_opt(
        pump_until_event(alice, MpRuntimeEventKind::control_disconnected, t0 + 2),
        "alice control_disconnected on 1006");
    require_ok(disc_ev.ws_close_code == 1006U, "abrupt drop reported as 1006");
    require_ok(alice.state() == MpRuntimeState::reconnecting &&
                   !alice.is_control_connected() && !alice.is_terminated(),
               "alice in reconnecting state without terminating");

    // Within 10s lease TTL (t0+5): live P2P chat STILL flows!
    const P2pPartyChatMessage offline_chat{
        "party/main", "@bob", "alice", 200001LL, "p2p survives control blip",
    };
    require_ok(require_val(alice.broadcast_chat(offline_chat), "offline chat").sent ==
               1U);
    const auto bob_got = require_opt(
        pump_until_event(bob, MpRuntimeEventKind::chat_received, t0 + 5, 5000),
        "bob received chat during control blip");
    require_ok(require_opt(bob_got.chat) == offline_chat, "offline chat payload match");

    // Past 10s lease TTL (t0+11): Alice evicts Bob with QUIC 4403!
    bool alice_evicted = false;
    bool bob_disc = false;
    require_ok(pump_pair_until(alice, bob, t0 + 11, [&]() {
      while (auto ev = alice.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::peer_evicted) {
          require_ok(ev->device_id == bob_id.device_id && ev->reason_code == 4403U);
          alice_evicted = true;
        }
      }
      while (auto ev = bob.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::peer_disconnected) {
          require_ok(ev->reason_code == 4403U);
          bob_disc = true;
        }
      }
      return alice_evicted && bob_disc;
    }));
    require_ok(alice.peer_count() == 0U, "alice roster empty after TTL eviction");
    require_ok(!alice.send_chat_to(bob_id.device_id, offline_chat).has_value(),
               "send fails closed after TTL eviction");
  }

  // Part B: Bounded exponential reconnect succeeds after transient drop, AND live
  //         WS 4403 immediately tears down live iroh QUIC mesh!
  {
    auto [alice, bob] = attach_and_connect_pair(/*alice_max_reconnects=*/3U);
    server.drop_connection_abruptly(alice_id.device_id);
    (void)require_opt(
        pump_until_event(alice, MpRuntimeEventKind::control_disconnected, t0 + 1),
        "control_disconnected");

    bool reconnected = false;
    bool re_hello = false;
    require_ok(pump_pair_until(alice, bob, t0 + 2, [&]() {
      (void)bob.drain_events();
      while (auto ev = alice.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::control_reconnected) {
          reconnected = true;
        } else if (ev->kind == MpRuntimeEventKind::hello_acked) {
          re_hello = true;
        }
      }
      return reconnected && re_hello;
    }));
    require_ok(alice.state() == MpRuntimeState::connected &&
                   alice.is_control_connected(),
               "alice reconnected to PartyDO");

    // Now kick Alice with WS Close 4403 -> Bob observes immediate QUIC 4403!
    server.send_ws_close(alice_id.device_id, kMpWsCloseKickedOrBanned);
    bool alice_kicked = false;
    bool bob_disc = false;
    require_ok(pump_pair_until(alice, bob, t0 + 3, [&]() {
      while (auto ev = alice.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::kicked_or_revoked) {
          require_ok(ev->ws_close_code == kMpWsCloseKickedOrBanned);
          alice_kicked = true;
        }
      }
      while (auto ev = bob.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::peer_disconnected) {
          require_ok(ev->reason_code == 4403U);
          bob_disc = true;
        }
      }
      return alice_kicked && bob_disc;
    }));
    require_ok(alice.is_terminated() && !alice.has_p2p_endpoint(),
               "alice hard-terminated on 4403");
  }

  // Part C: PARTY_DISBANDED tears down live iroh mesh cleanly with 4403!
  {
    auto [alice, bob] = attach_and_connect_pair(/*alice_max_reconnects=*/2U);
    server.push_mp1(alice_id.device_id, Mp1Message{PartyDisbandedMessage{
                                            2U, PartyDisbandReason::leader_disbanded}});
    bool alice_disbanded = false;
    bool bob_disc = false;
    require_ok(pump_pair_until(alice, bob, t0 + 4, [&]() {
      while (auto ev = alice.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::party_disbanded) {
          alice_disbanded = true;
        }
      }
      while (auto ev = bob.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::peer_disconnected) {
          require_ok(ev->reason_code == 4403U);
          bob_disc = true;
        }
      }
      return alice_disbanded && bob_disc;
    }));
    require_ok(alice.state() == MpRuntimeState::disbanded && alice.is_terminated() &&
                   !alice.is_control_connected() && !alice.has_p2p_endpoint(),
               "PARTY_DISBANDED cleanly tore down WS + iroh mesh");
  }

  // Part D: Live endpoint roaming via PARTY_MEMBER_UPDATED on an ALREADY-CONNECTED
  //         peer re-dials the roamed UDP endpoint and delivers live chat; AND HTTP 401
  //         on reconnect immediately tears down live P2P peers with QUIC 4403!
  {
    auto [alice, bob] = attach_and_connect_pair(/*alice_max_reconnects=*/2U);
    require_ok(require_opt(alice.find_peer(bob_id.device_id)).connection_state ==
                   P2pPeerConnectionState::connected,
               "bob connected before roaming");

    // Shut down Bob #1's endpoint (closing Bob #1's QUIC connection while Alice has
    // NOT polled peer_disconnected, so Alice's P2pPartySession still has Bob marked
    // `connected`) and spin up Bob #2 on a fresh ephemeral UDP port with the exact
    // same bob_id device identity.
    bob.shutdown();
    MpPartyRuntimeConfig bcfg2{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(bob_id),
        party_id,
    };
    bcfg2.local_relay_policy = RelayPolicy::no_relays;
    bcfg2.max_lease_ttl_s = 60;
    bcfg2.allow_loopback_direct_addrs = true;
    auto bob2 = require_val(MpPartyRuntime::attach(std::move(bcfg2)), "attach bob2");
    (void)require_opt(pump_until_event(bob2, MpRuntimeEventKind::hello_acked, t0 + 1),
                      "bob2 hello_acked");
    const auto bob2_ep = require_val(bob2.local_endpoint_descriptor(), "bob2 ep");
    const auto alice_ep = require_val(alice.local_endpoint_descriptor(), "alice ep");
    server.push_mp1(bob_id.device_id,
                    Mp1Message{PartySnapshotMessage{
                        party_id,
                        2U,
                        alice_id.account_id,
                        alice_id.device_id,
                        PartyVisibility::private_party,
                        PartyJoinMode::invite_only,
                        RelayPolicy::no_relays,
                        4U,
                        "",
                        {
                            make_member_record(alice_id, alice_ep, 1U),
                            make_member_record(bob_id, bob2_ep, 2U),
                        },
                    }});
    (void)require_opt(
        pump_until_event(bob2, MpRuntimeEventKind::snapshot_applied, t0 + 1),
        "bob2 allowlisted alice");

    // Push PARTY_MEMBER_UPDATED to Alice with Bob #2's new UDP endpoint while Alice
    // still has Bob in `connected` state -> Alice MUST re-dial Bob #2 immediately!
    require_ok(require_opt(alice.find_peer(bob_id.device_id)).connection_state ==
                   P2pPeerConnectionState::connected,
               "alice still sees bob as connected before PARTY_MEMBER_UPDATED");
    server.push_mp1(alice_id.device_id,
                    Mp1Message{PartyMemberUpdatedMessage{2U, bob_id.device_id, true,
                                                         bob_id.device_cwt, bob2_ep}});
    bool alice_upd = false;
    bool bob2_conn = false;
    require_ok(
        pump_pair_until(
            alice, bob2, t0 + 2,
            [&]() {
              while (auto ev = alice.pop_event()) {
                if (ev->kind == MpRuntimeEventKind::member_updated) {
                  alice_upd = true;
                }
              }
              while (auto ev = bob2.pop_event()) {
                if (ev->kind == MpRuntimeEventKind::peer_connected) {
                  bob2_conn = true;
                }
              }
              return alice_upd && bob2_conn;
            },
            10000),
        "Alice re-dialed already-connected peer after PARTY_MEMBER_UPDATED roam");

    const P2pPartyChatMessage roamed_msg{
        "party/main", "@bob", "alice", 300001LL, "reached roamed endpoint!",
    };
    require_ok(require_val(alice.broadcast_chat(roamed_msg), "roamed chat").sent == 1U);
    const auto bob2_got = require_opt(
        pump_until_event(bob2, MpRuntimeEventKind::chat_received, t0 + 2, 5000),
        "bob2 received chat after roaming");
    require_ok(require_opt(bob2_got.chat) == roamed_msg, "roamed chat payload match");

    // Now simulate Alice's device being revoked while WS is offline:
    // drop WS + configure HTTP 401 on reconnect -> Alice hard-tears down immediately
    // and Bob #2 observes QUIC 4403!
    server.set_upgrade_reject_status(alice_id.device_id, 401);
    server.drop_connection_abruptly(alice_id.device_id);
    bool alice_revoked = false;
    bool bob2_disc_4403 = false;
    require_ok(pump_pair_until(alice, bob2, t0 + 3, [&]() {
      while (auto ev = alice.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::kicked_or_revoked) {
          require_ok(ev->ws_close_code == kMpWsCloseDeviceRevoked);
          alice_revoked = true;
        }
      }
      while (auto ev = bob2.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::peer_disconnected) {
          require_ok(ev->reason_code == 4403U);
          bob2_disc_4403 = true;
        }
      }
      return alice_revoked && bob2_disc_4403;
    }));
    require_ok(alice.is_terminated() && !alice.has_p2p_endpoint(),
               "HTTP 401 on reconnect hard-tore down Alice and severed Bob with 4403");
    server.set_upgrade_reject_status(alice_id.device_id, std::nullopt);
  }

  std::cout << "PASS test_live_ws_drop_ttl_eviction_reconnect_and_teardown\n";
}

#else

void test_without_iroh_detached_runtime_behavior() {
  require_ok(!p2p_iroh_compiled_in(), "p2p_iroh_compiled_in must be false");

  TempDir tmp{"no_iroh"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const std::int64_t t0 = 1764030000;
  const auto party_id = require_val(PartyId::create(5599U), "party_id");
  const auto alice = make_test_identity(
      PeerIdentitySpec{1001U, 100U, 0x91U, "alice", t0 - 10, t0 + 3600});
  const auto bob = make_test_identity(
      PeerIdentitySpec{2002U, 200U, 0x92U, "bob", t0 - 10, t0 + 3600});
  server.register_device(to_registered_device(alice));

  MpPartyRuntimeConfig cfg{
      make_client_config(server.port(), cert.pem_path),
      to_identity_state(alice),
      party_id,
  };
  cfg.local_relay_policy = RelayPolicy::no_relays;

  auto rt = require_val(MpPartyRuntime::attach(std::move(cfg)), "attach without iroh");
  require_ok(!rt.has_p2p_endpoint(), "detached session without iroh");
  (void)require_opt(pump_until_event(rt, MpRuntimeEventKind::hello_acked, t0),
                    "hello_acked");

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
                      {make_member_record(bob, make_lan_endpoint(4200U), 1U)},
                  }});
  (void)require_opt(pump_until_event(rt, MpRuntimeEventKind::snapshot_applied, t0),
                    "snapshot_applied");
  require_ok(rt.peer_count() == 1U, "CWT verified peer admitted without iroh");

  const auto send_res =
      rt.broadcast_chat(P2pPartyChatMessage{"party/main", "@all", "alice", 1LL, "hi"});
  require_ok(!send_res.has_value() && send_res.error().code == ErrorCode::unsupported,
             "broadcast_chat fails closed with unsupported when HAS_IROH=0");

  std::cout << "PASS test_without_iroh_detached_runtime_behavior\n";
}

#endif

// ---------------------------------------------------------------------------
// Test 2b: Reconnect HTTP 401 hard-teardown, reconnect_exhausted, skewed
//          HelloAck + coalesced PartySnapshot (now_s_override = nullopt),
//          and force_relays pinned_relay_url mismatch rejection
//          (runs under BOTH HAS_IROH=1 and HAS_IROH=0)
// ---------------------------------------------------------------------------

void test_reconnect_auth_exhaustion_skew_and_relay_pin() {
  TempDir tmp{"regressions"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const auto real_now_s = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();
  const auto party_id = require_val(PartyId::create(5503U), "party_id");
  const auto alice = make_test_identity(PeerIdentitySpec{
      1001U, 200U, 0xA1U, "alice", real_now_s - 700, real_now_s + 3600});

  // 1. Skewed HelloAck (-600s behind fast local clock) + coalesced PartySnapshot
  //    using now_s_override = std::nullopt: Bob's CWT expires at server_now + 120
  //    (already expired under unadjusted fast local clock!), so Bob is ONLY admitted
  //    and retained if pump_once recomputes now_s per frame after HelloAck without
  //    a premature pre-HelloAck floor.
  const std::int64_t skewed_server_s = real_now_s - 600;
  const auto bob_skewed = make_test_identity(PeerIdentitySpec{
      2002U, 100U, 0xA2U, "bob", skewed_server_s - 30, skewed_server_s + 120});
  server.register_device(to_registered_device(alice));
  server.set_hello_server_now_ms_override(static_cast<std::uint64_t>(skewed_server_s) *
                                          1000ULL);
  server.set_coalesced_initial_mp1(
      alice.device_id,
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
          {make_member_record(bob_skewed, make_lan_endpoint(4200U), 1U)},
      }});

  {
    MpPartyRuntimeConfig cfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    cfg.local_relay_policy = RelayPolicy::no_relays;
    cfg.max_lease_ttl_s = 60;
    auto rt = require_val(MpPartyRuntime::attach(std::move(cfg)), "attach skewed");

    bool saw_hello = false;
    bool saw_snap = false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{3000};
    while (!(saw_hello && saw_snap) && std::chrono::steady_clock::now() < deadline) {
      (void)require_val(rt.pump_once(50U, std::nullopt), "pump_once live clock");
      while (auto ev = rt.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::hello_acked) {
          saw_hello = true;
        } else if (ev->kind == MpRuntimeEventKind::snapshot_applied) {
          const auto &rep = require_opt(ev->snapshot_result, "skewed snap result");
          require_ok(
              rep.admitted_peers.size() == 1U &&
                  rep.admitted_peers[0] == bob_skewed.device_id,
              "coalesced snapshot must verify CWT using post-HelloAck server time");
          saw_snap = true;
        }
      }
    }
    require_ok(saw_hello && saw_snap, "received coalesced HELLO_ACK + PARTY_SNAPSHOT");
    require_ok(rt.clock_skew_seconds() <= -590 && rt.clock_skew_seconds() >= -610,
               "negative clock_skew_seconds recorded");
    require_ok(rt.peer_count() == 1U, "skewed peer retained after evict_expired_peers");
  }
  server.set_hello_server_now_ms_override(std::nullopt);
  server.set_coalesced_initial_mp1(alice.device_id, std::nullopt);

  // 2. HTTP 401 on reconnect triggers immediate hard teardown (kicked_or_revoked 4401).
  {
    MpPartyRuntimeConfig cfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    cfg.local_relay_policy = RelayPolicy::no_relays;
    cfg.max_reconnect_attempts = 3U;
    cfg.reconnect_base_ms = 20U;
    cfg.reconnect_max_ms = 80U;
    auto rt = require_val(MpPartyRuntime::attach(std::move(cfg)), "attach 401 reconn");
    (void)require_opt(pump_until_event(rt, MpRuntimeEventKind::hello_acked, real_now_s),
                      "hello_acked");

    server.set_upgrade_reject_status(alice.device_id, 401);
    server.drop_connection_abruptly(alice.device_id);
    const auto kicked =
        require_opt(pump_until_event(rt, MpRuntimeEventKind::kicked_or_revoked,
                                     real_now_s + 1, 3000),
                    "HTTP 401 reconnect must trigger kicked_or_revoked");
    require_ok(kicked.ws_close_code == kMpWsCloseDeviceRevoked, "close code == 4401");
    require_ok(rt.is_terminated() && !rt.has_p2p_endpoint(),
               "HTTP 401 reconnect hard-tears down runtime");
    server.set_upgrade_reject_status(alice.device_id, std::nullopt);
  }

  // 3. Transient HTTP 503 on reconnect exhausts attempts and emits reconnect_exhausted.
  {
    MpPartyRuntimeConfig cfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    cfg.local_relay_policy = RelayPolicy::no_relays;
    cfg.max_reconnect_attempts = 2U;
    cfg.reconnect_base_ms = 20U;
    cfg.reconnect_max_ms = 40U;
    auto rt = require_val(MpPartyRuntime::attach(std::move(cfg)), "attach 503 reconn");
    (void)require_opt(pump_until_event(rt, MpRuntimeEventKind::hello_acked, real_now_s),
                      "hello_acked");

    server.set_upgrade_reject_status(alice.device_id, 503);
    server.drop_connection_abruptly(alice.device_id);
    bool saw_exhausted = false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{3000};
    while (!saw_exhausted && std::chrono::steady_clock::now() < deadline) {
      (void)require_val(rt.pump_once(20U, real_now_s + 1), "pump 503 reconn");
      while (auto ev = rt.pop_event()) {
        if (ev->kind == MpRuntimeEventKind::control_error && ev->error.has_value() &&
            mp_party_runtime_error_of(*ev->error) ==
                MpPartyRuntimeError::reconnect_exhausted) {
          saw_exhausted = true;
        }
      }
    }
    require_ok(saw_exhausted, "reconnect_exhausted event emitted on final failure");
    require_ok(!rt.is_terminated() && rt.reconnect_attempts() == 2U,
               "transient exhaustion preserves non-terminated state until TTL expiry");
    server.set_upgrade_reject_status(alice.device_id, std::nullopt);
  }

  // 4. force_relays rejects PartySnapshotMessage whose pinned_relay_url does not match
  //    the runtime's configured relay_url.
  {
    MpPartyRuntimeConfig cfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    cfg.local_relay_policy = RelayPolicy::force_relays;
    cfg.relay_url = "https://relay-a.multiplayer.tech";
    auto rt =
        require_val(MpPartyRuntime::attach(std::move(cfg)), "attach force_relays");
    (void)require_opt(pump_until_event(rt, MpRuntimeEventKind::hello_acked, real_now_s),
                      "hello_acked force_relays");

    server.push_mp1(alice.device_id, Mp1Message{PartySnapshotMessage{
                                         party_id,
                                         1U,
                                         alice.account_id,
                                         alice.device_id,
                                         PartyVisibility::private_party,
                                         PartyJoinMode::invite_only,
                                         RelayPolicy::force_relays,
                                         4U,
                                         "https://relay-b.multiplayer.tech",
                                         {},
                                     }});
    const auto err_ev = require_opt(
        pump_until_event(rt, MpRuntimeEventKind::control_error, real_now_s + 1, 3000),
        "mismatched force_relays pinned_relay_url rejected");
    require_ok(err_ev.error.has_value() && p2p_party_error_of(*err_ev.error) ==
                                               P2pPartyError::relay_policy_mismatch,
               "error == relay_policy_mismatch");
    require_ok(rt.party_epoch() == 0U, "rejected snapshot must not bind session");
  }

  std::cout << "PASS test_reconnect_auth_exhaustion_skew_and_relay_pin\n";
}

} // namespace

int main() {
  block_sigpipe_this_thread();
  test_control_lifecycle_and_disband();
  test_ws_close_4401_and_4403_hard_teardown();
  test_reconnect_auth_exhaustion_skew_and_relay_pin();
#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
  test_live_two_peer_control_and_iroh_p2p_end_to_end();
  test_live_ws_drop_ttl_eviction_reconnect_and_teardown();
#else
  test_without_iroh_detached_runtime_behavior();
#endif
  std::cout << "mp_party_runtime_test: ALL PASSED\n";
  return 0;
}
