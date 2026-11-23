#include "blackbird/mp_social_runtime.hpp"

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
    std::cerr << "mp_social_runtime_test FAIL at " << loc.file_name() << ":"
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
    std::cerr << "mp_social_runtime_test FAIL (empty optional) at " << loc.file_name()
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
    std::cerr << "mp_social_runtime_test FAIL (Result error code="
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
    std::cerr << "mp_social_runtime_test FAIL (Result<void> error code="
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
           ("bb_mp_social_runtime_test_" + std::string{tag} + "_" +
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
// Minimal RFC 6455 & TLS Helpers for Mock AccountDO (/v1/ws) Server
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

// ---------------------------------------------------------------------------
// In-Process TLS 1.3 Mock AccountDO (/v1/ws) Server
// ---------------------------------------------------------------------------

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

struct SocialClientSlot {
  std::uint64_t generation = 0U;
  bool connected = false;
  std::uint32_t connect_count = 0U;
  std::uint32_t rejected_upgrade_count = 0U;
  std::uint32_t ping_count = 0U;
  std::vector<PresenceSetMessage> received_presence_sets;
  std::deque<ServerAction> outbound;
  std::deque<int> reject_queue;
};

class MockSocialServer {
public:
  MockSocialServer(const EphemeralCert &cert, std::string expected_authority,
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

  ~MockSocialServer() {
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

  void register_device(AccountId account_id, DeviceId device_id,
                       const Ed25519PubKey &device_pubkey) {
    std::lock_guard<std::mutex> lk{mu_};
    devices_.insert_or_assign(device_id.value(),
                              std::make_pair(account_id, device_pubkey));
  }

  void set_initial_snapshot(DeviceId device_id,
                            std::optional<PresenceSnapshotMessage> snapshot) {
    std::lock_guard<std::mutex> lk{mu_};
    initial_snapshots_[device_id.value()] = std::move(snapshot);
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

  void queue_upgrade_rejection(DeviceId device_id, int http_status) {
    std::lock_guard<std::mutex> lk{mu_};
    slots_[device_id.value()].reject_queue.push_back(http_status);
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

  bool wait_for_presence_sets(
      DeviceId device_id, std::size_t expected_count,
      std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) {
    std::unique_lock<std::mutex> lk{mu_};
    return cv_.wait_for(lk, timeout, [&]() {
      const auto it = slots_.find(device_id.value());
      return it != slots_.end() &&
             it->second.received_presence_sets.size() >= expected_count;
    });
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

  std::vector<PresenceSetMessage> received_presence_sets(DeviceId device_id) {
    std::lock_guard<std::mutex> lk{mu_};
    const auto it = slots_.find(device_id.value());
    return it == slots_.end() ? std::vector<PresenceSetMessage>{}
                              : it->second.received_presence_sets;
  }

  std::uint32_t connect_count(DeviceId device_id) {
    std::lock_guard<std::mutex> lk{mu_};
    const auto it = slots_.find(device_id.value());
    return it == slots_.end() ? 0U : it->second.connect_count;
  }

  std::uint32_t rejected_upgrade_count(DeviceId device_id) {
    std::lock_guard<std::mutex> lk{mu_};
    const auto it = slots_.find(device_id.value());
    return it == slots_.end() ? 0U : it->second.rejected_upgrade_count;
  }

  std::uint32_t ping_count(DeviceId device_id) {
    std::lock_guard<std::mutex> lk{mu_};
    const auto it = slots_.find(device_id.value());
    return it == slots_.end() ? 0U : it->second.ping_count;
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
    if (!method.has_value() || method.value() != HttpMethod::get || path != "/v1/ws") {
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
    const std::uint64_t dev_raw = dev_keyid.device_id.value();

    Ed25519PubKey verify_pk{};
    std::optional<int> reject_status;
    std::optional<PresenceSnapshotMessage> init_snap;
    {
      std::lock_guard<std::mutex> lk{mu_};
      const auto it = devices_.find(dev_raw);
      if (it == devices_.end() || it->second.first != dev_keyid.account_id) {
        (void)ssl_write_str(ssl, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                                 "Connection: close\r\n\r\n");
        return;
      }
      verify_pk = it->second.second;
      auto &slot = slots_[dev_raw];
      if (!slot.reject_queue.empty()) {
        reject_status = slot.reject_queue.front();
        slot.reject_queue.pop_front();
        ++slot.rejected_upgrade_count;
      }
      if (const auto sit = initial_snapshots_.find(dev_raw);
          sit != initial_snapshots_.end()) {
        init_snap = sit->second;
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
      } else if (*reject_status == 403) {
        const std::string body = "{\"error\":\"device_key_required\"}";
        (void)ssl_write_str(
            ssl, "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
                 "Content-Length: " +
                     std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" +
                     body);
      } else {
        (void)ssl_write_str(ssl, "HTTP/1.1 " + std::to_string(*reject_status) +
                                     " Service Unavailable\r\nContent-Length: 0\r\n"
                                     "Connection: close\r\n\r\n");
      }
      cv_.notify_all();
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
    if (init_snap.has_value()) {
      const auto snap_enc = encode_frame(0U, Mp1Message{*init_snap});
      require_ok(snap_enc.has_value(), "encode initial PRESENCE_SNAPSHOT");
      const auto snap_ws = build_server_ws_frame(0x02U, snap_enc.value());
      initial.insert(initial.end(), snap_ws.begin(), snap_ws.end());
    }
    if (!ssl_write_all(ssl, initial)) {
      return;
    }

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

      bool done = false;
      for (const auto &act : batch) {
        if (act.kind == ServerActionKind::send_mp1 && act.message.has_value()) {
          const auto enc = encode_frame(0U, *act.message);
          require_ok(enc.has_value(), "encode server MP1");
          const auto ws_frame = build_server_ws_frame(0x02U, enc.value());
          if (!ssl_write_all(ssl, ws_frame)) {
            done = true;
            break;
          }
        } else if (act.kind == ServerActionKind::send_close) {
          const std::array<std::uint8_t, 2> payload = {
              static_cast<std::uint8_t>((act.close_code >> 8U) & 0xffU),
              static_cast<std::uint8_t>(act.close_code & 0xffU),
          };
          const auto ws_frame = build_server_ws_frame(0x08U, payload);
          (void)ssl_write_all(ssl, ws_frame);
          done = true;
          break;
        } else if (act.kind == ServerActionKind::drop_abruptly) {
          ssl_closer.clean_shutdown = false;
          done = true;
          break;
        }
      }
      if (done) {
        break;
      }

      pollfd pfd{};
      pfd.fd = client_fd;
      pfd.events = POLLIN;
      const int rc = ::poll(&pfd, 1U, 15);
      if (rc < 0) {
        break;
      }
      if (rc == 0 && SSL_pending(ssl) == 0) {
        continue;
      }
      std::array<std::uint8_t, 4096> chunk{};
      const int n = SSL_read(ssl, chunk.data(), static_cast<int>(chunk.size()));
      if (n <= 0) {
        break;
      }
      recv_buf.insert(recv_buf.end(), chunk.begin(),
                      chunk.begin() + static_cast<std::ptrdiff_t>(n));

      while (auto frame = try_pop_client_ws_frame(recv_buf)) {
        require_ok(frame->masked, "client WS frames must be masked");
        if (frame->opcode == 0x08U) {
          done = true;
          break;
        }
        if (frame->opcode == 0x01U) {
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
            const auto pong_ws = build_server_ws_frame(0x01U, pong_bytes);
            if (!ssl_write_all(ssl, pong_ws)) {
              done = true;
              break;
            }
          }
        } else if (frame->opcode == 0x02U) {
          const auto dec = decode_frame(frame->payload);
          require_ok(dec.has_value(), "decode client MP1 frame");
          if (const auto *pset =
                  std::get_if<PresenceSetMessage>(&dec.value().message)) {
            {
              std::lock_guard<std::mutex> lk{mu_};
              slots_[dev_raw].received_presence_sets.push_back(*pset);
            }
            cv_.notify_all();
          }
        }
      }
      if (done) {
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
  std::map<std::uint64_t, std::pair<AccountId, Ed25519PubKey>> devices_;
  std::map<std::uint64_t, std::optional<PresenceSnapshotMessage>> initial_snapshots_;
  std::map<std::uint64_t, SocialClientSlot> slots_;
};

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

struct IdentitySpec {
  std::uint64_t account_id = 0U;
  std::uint64_t device_id = 0U;
  std::string handle;
};

MpIdentityState make_identity(const IdentitySpec &spec,
                              Ed25519PubKey &out_device_pubkey) {
  const auto root_seed = require_val(CleansedSeed::generate(), "root seed");
  const auto dev_seed = require_val(CleansedSeed::generate(), "dev seed");
  const auto root_key =
      require_val(Ed25519SigningKey::from_seed(root_seed.bytes()), "root key");
  const auto dev_key =
      require_val(Ed25519SigningKey::from_seed(dev_seed.bytes()), "dev key");
  out_device_pubkey = dev_key.public_key();

  const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  const auto cwt = require_val(
      encode_device_cwt(
          root_key, DeviceCwtMintRequest{out_device_pubkey, now_s - 10, now_s + 86400}),
      "mint device cwt");

  MpIdentityState id{};
  id.root_seed = root_seed;
  id.device_seed = dev_seed;
  id.account_id = require_val(AccountId::create(spec.account_id), "account_id");
  id.device_id = require_val(DeviceId::create(spec.device_id), "device_id");
  id.handle = spec.handle;
  id.authority = "localhost";
  id.device_cwt = cwt;
  return id;
}

MpSocialRuntimeConfig make_runtime_config(const EphemeralCert &cert, std::uint16_t port,
                                          MpIdentityState identity) {
  MpSocialRuntimeConfig cfg{};
  cfg.client_config.authority = "localhost";
  cfg.client_config.connect_host = "127.0.0.1";
  cfg.client_config.port = port;
  cfg.client_config.ca_bundle_path = cert.pem_path;
  cfg.client_config.connect_timeout_ms = 3000;
  cfg.client_config.io_timeout_ms = 3000;
  cfg.identity = std::move(identity);
  cfg.max_reconnect_attempts = 4U;
  cfg.reconnect_base_ms = 40U;
  cfg.reconnect_max_ms = 160U;
  return cfg;
}

std::vector<MpSocialEvent>
pump_until(MpSocialRuntime &rt,
           const std::function<bool(const std::vector<MpSocialEvent> &)> &pred,
           std::chrono::milliseconds budget = std::chrono::milliseconds{4000}) {
  std::vector<MpSocialEvent> all;
  const auto deadline = std::chrono::steady_clock::now() + budget;
  while (std::chrono::steady_clock::now() < deadline) {
    (void)require_val(rt.pump_once(40U), "pump_once");
    auto batch = rt.drain_events();
    for (auto &ev : batch) {
      all.push_back(std::move(ev));
    }
    if (pred(all)) {
      return all;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  return all;
}

bool has_kind(const std::vector<MpSocialEvent> &evs, MpSocialEventKind kind) {
  for (const auto &ev : evs) {
    if (ev.kind == kind) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Test 1: Config Validation & Terminal-Safe Notice Formatting
// ---------------------------------------------------------------------------

void test_config_validation_and_notice_sanitization() {
  // Missing account/device identity fails closed.
  {
    MpSocialRuntimeConfig bad{};
    const auto res = MpSocialRuntime::connect(std::move(bad));
    require_ok(!res.has_value());
    require_ok(mp_social_runtime_error_of(res.error()) ==
               MpSocialRuntimeError::missing_identity);
  }

  // Bad reconnect backoff bounds fail closed.
  {
    Ed25519PubKey dev_pk{};
    MpSocialRuntimeConfig bad{};
    bad.identity = make_identity({1001U, 2001U, "alice"}, dev_pk);
    bad.max_reconnect_attempts = 2U;
    bad.reconnect_base_ms = 0U;
    const auto res = MpSocialRuntime::connect(std::move(bad));
    require_ok(!res.has_value());
    require_ok(mp_social_runtime_error_of(res.error()) ==
               MpSocialRuntimeError::invalid_config);
  }

  // Hostile handle sanitization in format_mp_social_event_notice.
  const auto bob_id = require_val(AccountId::create(1002U), "bob_id");
  const auto party_id = require_val(PartyId::create(5001U), "party_id");
  const auto invite_id = require_val(PartyInviteId::create(7001U), "invite_id");

  const auto hostile_lookup = [](AccountId) -> std::optional<std::string> {
    return std::string{"@evil\x1b[31m\r\n\x07\xc2\x9b\xe2\x80\xae"
                       "bob"};
  };
  const auto clean_lookup = [](AccountId) -> std::optional<std::string> {
    return std::string{"bob_friend"};
  };

  MpSocialEvent req_ev{};
  req_ev.kind = MpSocialEventKind::social_event;
  req_ev.social = SocialEventMessage{SocialEventKind::friend_request, bob_id};

  const std::string hostile_notice =
      format_mp_social_event_notice(req_ev, hostile_lookup);
  require_ok(hostile_notice.find('\x1b') == std::string::npos, "no raw ESC");
  require_ok(hostile_notice.find('\r') == std::string::npos, "no raw CR");
  require_ok(hostile_notice.find('\n') == std::string::npos, "no raw LF");
  require_ok(hostile_notice.find('\x07') == std::string::npos, "no raw BEL");
  require_ok(hostile_notice.find("\xc2\x9b") == std::string::npos, "no UTF-8 C1");
  require_ok(hostile_notice.find("\xe2\x80\xae") == std::string::npos, "no bidi RLO");
  require_ok(hostile_notice.find("@@") == std::string::npos, "no double @");

  const std::string clean_notice = format_mp_social_event_notice(req_ev, clean_lookup);
  require_ok(clean_notice == "Friend request received from @bob_friend");

  const std::string fallback_notice = format_mp_social_event_notice(req_ev);
  require_ok(fallback_notice == "Friend request received from #1002");

  MpSocialEvent inv_ev{};
  inv_ev.kind = MpSocialEventKind::party_invite_notify;
  inv_ev.party_invite = PartyInviteNotifyMessage{invite_id, party_id, bob_id, 999999U};
  const std::string inv_notice = format_mp_social_event_notice(inv_ev, clean_lookup);
  require_ok(inv_notice.find("@bob_friend") != std::string::npos);
  require_ok(inv_notice.find("#5001") != std::string::npos);
  require_ok(inv_notice.find("#7001") != std::string::npos);

  MpSocialEvent rev_ev{};
  rev_ev.kind = MpSocialEventKind::device_revoked;
  rev_ev.ws_close_code = 4401U;
  require_ok(format_mp_social_event_notice(rev_ev).find("4401") != std::string::npos);

  std::cout << "PASS test_config_validation_and_notice_sanitization\n";
}

// ---------------------------------------------------------------------------
// Test 2: Full Live /v1/ws Flow (HELLO_ACK, Presence, Social, Invite, Ping)
// ---------------------------------------------------------------------------

void test_live_presence_social_events_and_heartbeat() {
  TempDir tmp{"live"};
  const EphemeralCert cert =
      generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockSocialServer server{cert, "localhost", 10000U};

  Ed25519PubKey alice_dev_pk{};
  MpIdentityState alice_id = make_identity({1001U, 2001U, "alice"}, alice_dev_pk);
  const auto alice_dev_id = require_opt(alice_id.device_id);
  server.register_device(require_opt(alice_id.account_id), alice_dev_id, alice_dev_pk);

  const auto bob_id = require_val(AccountId::create(1002U), "bob_id");
  const auto carol_id = require_val(AccountId::create(1003U), "carol_id");
  const auto dave_id = require_val(AccountId::create(1004U), "dave_id");
  const auto party_id = require_val(PartyId::create(5001U), "party_id");
  const auto invite_id = require_val(PartyInviteId::create(7001U), "invite_id");

  // Coalesce initial PRESENCE_SNAPSHOT right behind HELLO_ACK!
  PresenceSnapshotMessage init_snap{};
  init_snap.entries = {
      PresenceEntry{bob_id, PresenceVisibility::online, std::nullopt, 1000U},
      PresenceEntry{carol_id, PresenceVisibility::busy, party_id, 1001U},
      PresenceEntry{dave_id, PresenceVisibility::invisible, std::nullopt, 1002U},
  };
  server.set_initial_snapshot(alice_dev_id, init_snap);

  MpSocialRuntime rt = require_val(
      MpSocialRuntime::connect(make_runtime_config(cert, server.port(), alice_id)),
      "connect social runtime");
  require_ok(rt.is_connected());

  // Pump HELLO_ACK + coalesced PRESENCE_SNAPSHOT.
  const auto initial_evs = pump_until(rt, [](const std::vector<MpSocialEvent> &evs) {
    return has_kind(evs, MpSocialEventKind::hello_acked) &&
           has_kind(evs, MpSocialEventKind::presence_snapshot);
  });
  require_ok(has_kind(initial_evs, MpSocialEventKind::hello_acked));
  require_ok(has_kind(initial_evs, MpSocialEventKind::presence_snapshot));
  require_ok(rt.state() == MpSocialRuntimeState::connected);
  require_ok(rt.session_id().has_value());
  require_ok(rt.ping_interval_ms() == 10000U);
  require_ok(rt.online_friend_count() == 2U);
  require_ok(rt.tracked_presence_count() == 3U);
  require_ok(rt.presence_snapshot().size() == 3U);

  const auto bob_pres = require_opt(rt.find_presence(bob_id), "bob presence");
  require_ok(bob_pres.status == PresenceVisibility::online);
  require_ok(!bob_pres.joinable_party_id.has_value());
  const auto carol_pres = require_opt(rt.find_presence(carol_id), "carol presence");
  require_ok(carol_pres.status == PresenceVisibility::busy);
  require_ok(carol_pres.joinable_party_id == std::optional<PartyId>{party_id});

  // Push PRESENCE_DELTA (dave comes online with party, bob goes invisible),
  // SOCIAL_EVENT (friend_request + friend_accepted), PARTY_INVITE_NOTIFY, ERROR!
  server.push_mp1(alice_dev_id,
                  PresenceDeltaMessage{PresenceEntry{dave_id, PresenceVisibility::idle,
                                                     party_id, 2000U}});
  server.push_mp1(alice_dev_id,
                  PresenceDeltaMessage{PresenceEntry{
                      bob_id, PresenceVisibility::invisible, std::nullopt, 2001U}});
  server.push_mp1(alice_dev_id,
                  SocialEventMessage{SocialEventKind::friend_request, dave_id});
  server.push_mp1(alice_dev_id,
                  SocialEventMessage{SocialEventKind::friend_accepted, bob_id});
  server.push_mp1(alice_dev_id,
                  PartyInviteNotifyMessage{invite_id, party_id, carol_id, 9999999U});
  server.push_mp1(alice_dev_id, ErrorMessage{1U, 429U, 1500U});

  const auto live_evs = pump_until(
      rt, [](const std::vector<MpSocialEvent> &evs) { return evs.size() >= 6U; });
  require_ok(live_evs.size() == 6U);
  require_ok(live_evs[0].kind == MpSocialEventKind::presence_delta);
  require_ok(live_evs[1].kind == MpSocialEventKind::presence_delta);
  require_ok(live_evs[2].kind == MpSocialEventKind::social_event &&
             require_opt(live_evs[2].social).kind == SocialEventKind::friend_request);
  require_ok(live_evs[3].kind == MpSocialEventKind::social_event &&
             require_opt(live_evs[3].social).kind == SocialEventKind::friend_accepted);
  require_ok(live_evs[4].kind == MpSocialEventKind::party_invite_notify &&
             require_opt(live_evs[4].party_invite).party_invite_id == invite_id);
  require_ok(live_evs[5].kind == MpSocialEventKind::control_error &&
             require_opt(live_evs[5].server_error).code == 429U);

  require_ok(rt.online_friend_count() == 2U); // carol + dave online, bob invisible
  require_ok(require_opt(rt.find_presence(dave_id)).status == PresenceVisibility::idle);
  require_ok(require_opt(rt.find_presence(bob_id)).status ==
             PresenceVisibility::invisible);

  // Unfriended social event removes peer from friend_presence_.
  server.push_mp1(alice_dev_id,
                  SocialEventMessage{SocialEventKind::unfriended, carol_id});
  const auto unfriend_evs = pump_until(rt, [](const std::vector<MpSocialEvent> &evs) {
    return has_kind(evs, MpSocialEventKind::social_event);
  });
  require_ok(has_kind(unfriend_evs, MpSocialEventKind::social_event));
  require_ok(!rt.find_presence(carol_id).has_value());
  require_ok(rt.online_friend_count() == 1U);

  // Outbound set_presence() using BOTH overloads (PartyId optional & bool share_party).
  require_void(
      rt.set_presence(PresenceStatus::online, std::optional<PartyId>{party_id}),
      "set_presence with party_id");
  require_void(rt.set_presence(PresenceVisibility::busy, false),
               "set_presence busy no share");
  require_ok(server.wait_for_presence_sets(alice_dev_id, 2U),
             "server received 2 PRESENCE_SET frames");
  const auto psets = server.received_presence_sets(alice_dev_id);
  require_ok(psets.size() == 2U);
  require_ok(psets[0] == PresenceSetMessage{PresenceVisibility::online, true});
  require_ok(psets[1] == PresenceSetMessage{PresenceVisibility::busy, false});

  // Heartbeat keepalive ("MP1:PING" -> "MP1:PONG") via explicit ping + interval timer.
  require_void(rt.send_heartbeat_ping(), "send_heartbeat_ping");
  require_ok(server.wait_for_ping_count(alice_dev_id, 1U), "server got ping #1");
  (void)pump_until(
      rt, [&](const std::vector<MpSocialEvent> &) { return rt.last_pong_ms() > 0U; });
  require_ok(rt.last_pong_ms() > 0U, "received MP1:PONG");

  // Trigger automatic interval ping using now_s_override.
  (void)require_val(rt.pump_once(10U, 1000), "seed override clock");
  (void)require_val(rt.pump_once(10U, 1015), "advance override clock past 10s");
  require_ok(server.wait_for_ping_count(alice_dev_id, 2U), "server got auto ping #2");

  // Idempotent clean shutdown (WS close 1000).
  rt.shutdown();
  rt.shutdown();
  require_ok(rt.state() == MpSocialRuntimeState::terminated);
  require_ok(rt.is_terminated());
  require_ok(!rt.is_connected());
  const auto after_shutdown = rt.set_presence(PresenceVisibility::online);
  require_ok(!after_shutdown.has_value());
  require_ok(mp_social_runtime_error_of(after_shutdown.error()) ==
             MpSocialRuntimeError::runtime_terminated);

  std::cout << "PASS test_live_presence_social_events_and_heartbeat\n";
}

// ---------------------------------------------------------------------------
// Test 3: Transient Disconnect + Exponential Backoff Auto-Reconnect
// ---------------------------------------------------------------------------

void test_transient_disconnect_and_auto_reconnect() {
  TempDir tmp{"reconnect"};
  const EphemeralCert cert =
      generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockSocialServer server{cert, "localhost", 15000U};

  Ed25519PubKey dev_pk{};
  MpIdentityState id = make_identity({1010U, 2010U, "alice_reconn"}, dev_pk);
  const auto dev_id = require_opt(id.device_id);
  server.register_device(require_opt(id.account_id), dev_id, dev_pk);

  MpSocialRuntime rt = require_val(
      MpSocialRuntime::connect(make_runtime_config(cert, server.port(), id)),
      "connect initial");
  const auto hello_evs = pump_until(rt, [](const std::vector<MpSocialEvent> &evs) {
    return has_kind(evs, MpSocialEventKind::hello_acked);
  });
  require_ok(has_kind(hello_evs, MpSocialEventKind::hello_acked));

  // Set desired presence so we can verify it is republished after reconnect!
  const auto party_id = require_val(PartyId::create(5555U), "party_id");
  require_void(
      rt.set_presence(PresenceVisibility::online, std::optional<PartyId>{party_id}),
      "set_presence before drop");
  require_ok(server.wait_for_presence_sets(dev_id, 1U));

  // Reject first reconnect attempt with transient 503, then accept second attempt.
  server.queue_upgrade_rejection(dev_id, 503);
  server.drop_connection_abruptly(dev_id);

  const auto reconn_evs = pump_until(rt, [](const std::vector<MpSocialEvent> &evs) {
    return has_kind(evs, MpSocialEventKind::control_disconnected) &&
           has_kind(evs, MpSocialEventKind::control_reconnected) &&
           has_kind(evs, MpSocialEventKind::hello_acked);
  });
  require_ok(has_kind(reconn_evs, MpSocialEventKind::control_disconnected));
  require_ok(has_kind(reconn_evs, MpSocialEventKind::control_reconnected));
  require_ok(has_kind(reconn_evs, MpSocialEventKind::hello_acked));
  require_ok(rt.state() == MpSocialRuntimeState::connected);
  require_ok(server.rejected_upgrade_count(dev_id) == 1U);
  require_ok(server.connect_count(dev_id) == 2U);

  // Desired presence must have been republished on reconnect HELLO_ACK!
  require_ok(server.wait_for_presence_sets(dev_id, 2U),
             "desired presence republished on reconnect");
  const auto psets = server.received_presence_sets(dev_id);
  require_ok(psets.size() == 2U);
  require_ok(psets[1] == PresenceSetMessage{PresenceVisibility::online, true});

  rt.shutdown();
  std::cout << "PASS test_transient_disconnect_and_auto_reconnect\n";
}

// ---------------------------------------------------------------------------
// Test 4: Hard Terminal Stop on WS Close 4401 and Reconnect HTTP 401/403
// ---------------------------------------------------------------------------

void test_hard_stop_on_revoked_and_auth_reject() {
  TempDir tmp{"revoked"};
  const EphemeralCert cert =
      generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockSocialServer server{cert, "localhost", 15000U};

  // (a) WS close 4401 (device_revoked) -> immediate hard terminal stop!
  {
    Ed25519PubKey dev_pk{};
    MpIdentityState id = make_identity({1020U, 2020U, "alice_4401"}, dev_pk);
    const auto dev_id = require_opt(id.device_id);
    server.register_device(require_opt(id.account_id), dev_id, dev_pk);

    const auto friend_id = require_val(AccountId::create(1099U), "friend_id");
    PresenceSnapshotMessage snap{};
    snap.entries.push_back(
        PresenceEntry{friend_id, PresenceVisibility::online, std::nullopt, 5000U});
    server.set_initial_snapshot(dev_id, snap);

    MpSocialRuntime rt = require_val(
        MpSocialRuntime::connect(make_runtime_config(cert, server.port(), id)),
        "connect 4401 case");
    (void)pump_until(rt, [](const std::vector<MpSocialEvent> &evs) {
      return has_kind(evs, MpSocialEventKind::presence_snapshot);
    });
    require_ok(rt.online_friend_count() == 1U);

    server.send_ws_close(dev_id, 4401U);
    const auto evs = pump_until(rt, [](const std::vector<MpSocialEvent> &evs) {
      return has_kind(evs, MpSocialEventKind::device_revoked);
    });
    require_ok(has_kind(evs, MpSocialEventKind::device_revoked));
    require_ok(rt.is_revoked());
    require_ok(rt.is_terminated());
    require_ok(!rt.is_connected());
    require_ok(rt.online_friend_count() == 0U);
    require_ok(rt.tracked_presence_count() == 0U);

    // Further pumps must NOT attempt reconnect!
    for (int i = 0; i < 5; ++i) {
      require_ok(require_val(rt.pump_once(20U), "pump after 4401") == 0U);
    }
    require_ok(server.connect_count(dev_id) == 1U);

    const auto send_res = rt.set_presence(PresenceVisibility::online);
    require_ok(!send_res.has_value());
    require_ok(mp_social_runtime_error_of(send_res.error()) ==
               MpSocialRuntimeError::device_revoked);
  }

  // (b) Transient disconnect followed by HTTP 401 on reconnect -> hard stop!
  {
    Ed25519PubKey dev_pk{};
    MpIdentityState id = make_identity({1021U, 2021U, "alice_401"}, dev_pk);
    const auto dev_id = require_opt(id.device_id);
    server.register_device(require_opt(id.account_id), dev_id, dev_pk);

    MpSocialRuntime rt = require_val(
        MpSocialRuntime::connect(make_runtime_config(cert, server.port(), id)),
        "connect 401 case");
    (void)pump_until(rt, [](const std::vector<MpSocialEvent> &evs) {
      return has_kind(evs, MpSocialEventKind::hello_acked);
    });

    server.queue_upgrade_rejection(dev_id, 401);
    server.drop_connection_abruptly(dev_id);

    const auto evs = pump_until(rt, [](const std::vector<MpSocialEvent> &evs) {
      return has_kind(evs, MpSocialEventKind::device_revoked);
    });
    require_ok(has_kind(evs, MpSocialEventKind::control_disconnected));
    require_ok(has_kind(evs, MpSocialEventKind::device_revoked));
    require_ok(rt.is_revoked());
    require_ok(rt.is_terminated());
    require_ok(server.rejected_upgrade_count(dev_id) == 1U);
    require_ok(server.connect_count(dev_id) == 1U);
  }

  // (c) Transient disconnect followed by HTTP 403 on reconnect -> hard stop!
  {
    Ed25519PubKey dev_pk{};
    MpIdentityState id = make_identity({1022U, 2022U, "alice_403"}, dev_pk);
    const auto dev_id = require_opt(id.device_id);
    server.register_device(require_opt(id.account_id), dev_id, dev_pk);

    MpSocialRuntime rt = require_val(
        MpSocialRuntime::connect(make_runtime_config(cert, server.port(), id)),
        "connect 403 case");
    (void)pump_until(rt, [](const std::vector<MpSocialEvent> &evs) {
      return has_kind(evs, MpSocialEventKind::hello_acked);
    });

    server.queue_upgrade_rejection(dev_id, 403);
    server.drop_connection_abruptly(dev_id);

    const auto evs = pump_until(rt, [](const std::vector<MpSocialEvent> &evs) {
      return has_kind(evs, MpSocialEventKind::device_revoked);
    });
    require_ok(has_kind(evs, MpSocialEventKind::control_disconnected));
    require_ok(has_kind(evs, MpSocialEventKind::device_revoked));
    require_ok(rt.is_revoked());
    require_ok(rt.is_terminated());
    require_ok(server.rejected_upgrade_count(dev_id) == 1U);
    require_ok(server.connect_count(dev_id) == 1U);
  }

  std::cout << "PASS test_hard_stop_on_revoked_and_auth_reject\n";
}

} // namespace

int main() {
  block_sigpipe_this_thread();
  test_config_validation_and_notice_sanitization();
  test_live_presence_social_events_and_heartbeat();
  test_transient_disconnect_and_auto_reconnect();
  test_hard_stop_on_revoked_and_auth_reject();
  std::cout << "ALL mp_social_runtime tests PASSED!\n";
  return 0;
}
