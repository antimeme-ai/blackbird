#include "blackbird/net_http.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <optional>
#include <poll.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef SO_NOSIGPIPE
#include <pthread.h>
#include <signal.h>
#include <time.h>
#endif
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

namespace blackbird::net {

namespace {

using SteadyClock = std::chrono::steady_clock;

constexpr std::size_t kMaxUrlBytes = 4096U;
constexpr std::size_t kMaxHostBytes = 255U;
constexpr std::array<unsigned char, 9> kAlpnHttp11 = {8U,  'h', 't', 't', 'p',
                                                      '/', '1', '.', '1'};

template <typename T> Result<T> fail_n(ErrorCode code, NetError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_nv(ErrorCode code, NetError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

constexpr bool is_ascii_upper(char ch) noexcept { return ch >= 'A' && ch <= 'Z'; }

constexpr char to_ascii_lower(char ch) noexcept {
  return is_ascii_upper(ch) ? static_cast<char>(ch + ('a' - 'A')) : ch;
}

std::string ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    out.push_back(to_ascii_lower(ch));
  }
  return out;
}

bool ascii_iequals(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (std::size_t i = 0U; i < lhs.size(); ++i) {
    if (to_ascii_lower(lhs[i]) != to_ascii_lower(rhs[i])) {
      return false;
    }
  }
  return true;
}

std::string_view trim_ows(std::string_view text) noexcept {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
    text.remove_prefix(1U);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
    text.remove_suffix(1U);
  }
  return text;
}

bool contains_ctl(std::string_view text) noexcept {
  for (const char ch : text) {
    const auto b = static_cast<std::uint8_t>(ch);
    if (b < 0x20U || b == 0x7fU) {
      return true;
    }
  }
  return false;
}

bool is_valid_header_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > 256U) {
    return false;
  }
  for (const char ch : name) {
    const auto b = static_cast<std::uint8_t>(ch);
    const bool alpha_num =
        (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9');
    const bool tchar_punct = ch == '!' || ch == '#' || ch == '$' || ch == '%' ||
                             ch == '&' || ch == '\'' || ch == '*' || ch == '+' ||
                             ch == '-' || ch == '.' || ch == '^' || ch == '_' ||
                             ch == '`' || ch == '|' || ch == '~';
    if (!alpha_num && !tchar_punct) {
      return false;
    }
  }
  return true;
}

bool is_valid_header_value(std::string_view value) noexcept {
  if (value.size() > 16384U) {
    return false;
  }
  for (const char ch : value) {
    const auto b = static_cast<std::uint8_t>(ch);
    if ((b < 0x20U && ch != '\t') || b == 0x7fU) {
      return false;
    }
  }
  return true;
}

bool has_empty_hostname_label(std::string_view host) noexcept {
  return host.empty() || host.front() == '.' || host.back() == '.' ||
         host.find("..") != std::string_view::npos;
}

bool has_rfc3986_scheme_prefix(std::string_view text) noexcept {
  const std::size_t sep = text.find("://");
  if (sep == std::string_view::npos || sep == 0U) {
    return false;
  }
  const char first = text[0];
  if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z'))) {
    return false;
  }
  for (std::size_t i = 1U; i < sep; ++i) {
    const char c = text[i];
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
    if (!ok) {
      return false;
    }
  }
  return true;
}

bool is_valid_hostname_chars(std::string_view host) noexcept {
  if (host.empty() || host.size() > kMaxHostBytes) {
    return false;
  }
  for (const char ch : host) {
    const auto b = static_cast<std::uint8_t>(ch);
    const bool ok = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
                    (b >= '0' && b <= '9') || ch == '-' || ch == '.' || ch == ':';
    if (!ok) {
      return false;
    }
  }
  return true;
}

int remaining_timeout_ms(SteadyClock::time_point deadline) noexcept {
  const auto now = SteadyClock::now();
  if (now >= deadline) {
    return 0;
  }
  const auto rem =
      std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
  if (rem > std::numeric_limits<int>::max()) {
    return std::numeric_limits<int>::max();
  }
  return static_cast<int>(rem);
}

// ---------------------------------------------------------------------------
// RAII wrappers & thread-safe SIGPIPE suppression
// ---------------------------------------------------------------------------

class ScopedFd {
public:
  ScopedFd() noexcept = default;
  explicit ScopedFd(int fd) noexcept : fd_(fd) {}
  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;
  ScopedFd(ScopedFd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  ScopedFd &operator=(ScopedFd &&other) noexcept {
    if (this != &other) {
      reset();
      fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
  }
  ~ScopedFd() { reset(); }

  int get() const noexcept { return fd_; }
  explicit operator bool() const noexcept { return fd_ >= 0; }
  void reset(int next = -1) noexcept {
    if (fd_ >= 0) {
      (void)::close(fd_);
    }
    fd_ = next;
  }

private:
  int fd_ = -1;
};

struct AddrInfoDeleter {
  void operator()(addrinfo *ai) const noexcept {
    if (ai != nullptr) {
      ::freeaddrinfo(ai);
    }
  }
};
using UniqueAddrInfo = std::unique_ptr<addrinfo, AddrInfoDeleter>;

struct SslCtxDeleter {
  void operator()(SSL_CTX *ctx) const noexcept {
    if (ctx != nullptr) {
      SSL_CTX_free(ctx);
    }
  }
};
using UniqueSslCtx = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

struct SslDeleter {
  void operator()(SSL *ssl) const noexcept {
    if (ssl != nullptr) {
      SSL_free(ssl);
    }
  }
};
using UniqueSsl = std::unique_ptr<SSL, SslDeleter>;

struct X509Deleter {
  void operator()(X509 *cert) const noexcept {
    if (cert != nullptr) {
      X509_free(cert);
    }
  }
};
using UniqueX509 = std::unique_ptr<X509, X509Deleter>;

#ifndef SO_NOSIGPIPE
class ScopedSigpipeGuard {
public:
  ScopedSigpipeGuard() noexcept {
    sigemptyset(&blocked_);
    sigaddset(&blocked_, SIGPIPE);
    if (::pthread_sigmask(SIG_BLOCK, &blocked_, &previous_) == 0) {
      active_ = true;
      sigset_t pending{};
      if (::sigpending(&pending) == 0) {
        was_pending_ = (sigismember(&pending, SIGPIPE) == 1);
      }
    }
  }
  ScopedSigpipeGuard(const ScopedSigpipeGuard &) = delete;
  ScopedSigpipeGuard &operator=(const ScopedSigpipeGuard &) = delete;
  ~ScopedSigpipeGuard() {
    if (!active_) {
      return;
    }
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
#else
class ScopedSigpipeGuard {
public:
  ScopedSigpipeGuard() noexcept = default;
  ScopedSigpipeGuard(const ScopedSigpipeGuard &) = delete;
  ScopedSigpipeGuard &operator=(const ScopedSigpipeGuard &) = delete;
  ~ScopedSigpipeGuard() noexcept {}
};
#endif

// ---------------------------------------------------------------------------
// IPv4 / IPv6 SSRF address classification
// ---------------------------------------------------------------------------

bool is_ipv4_loopback(std::uint32_t ip) noexcept {
  return (ip & 0xFF000000U) == 0x7F000000U;
}

bool is_ipv4_private_or_special(std::uint32_t ip) noexcept {
  if (is_ipv4_loopback(ip)) {
    return true;
  }
  if ((ip & 0xFF000000U) == 0x00000000U) { // 0.0.0.0/8
    return true;
  }
  if ((ip & 0xFF000000U) == 0x0A000000U) { // 10.0.0.0/8
    return true;
  }
  if ((ip & 0xFFC00000U) == 0x64400000U) { // 100.64.0.0/10 (CGNAT)
    return true;
  }
  if ((ip & 0xFFFF0000U) == 0xA9FE0000U) { // 169.254.0.0/16 (link-local / metadata)
    return true;
  }
  if ((ip & 0xFFF00000U) == 0xAC100000U) { // 172.16.0.0/12
    return true;
  }
  if ((ip & 0xFFFFFF00U) == 0xC0000000U) { // 192.0.0.0/24
    return true;
  }
  if ((ip & 0xFFFFFF00U) == 0xC0000200U) { // 192.0.2.0/24 (TEST-NET-1)
    return true;
  }
  if ((ip & 0xFFFF0000U) == 0xC0A80000U) { // 192.168.0.0/16
    return true;
  }
  if ((ip & 0xFFFE0000U) == 0xC6120000U) { // 198.18.0.0/15 (benchmarking)
    return true;
  }
  if ((ip & 0xFFFFFF00U) == 0xC6336400U) { // 198.51.100.0/24 (TEST-NET-2)
    return true;
  }
  if ((ip & 0xFFFFFF00U) == 0xCB007100U) { // 203.0.113.0/24 (TEST-NET-3)
    return true;
  }
  if ((ip & 0xE0000000U) == 0xE0000000U) { // 224.0.0.0/4 multicast + 240.0.0.0/4
    return true;
  }
  return false;
}

std::optional<std::uint32_t> extract_embedded_ipv4(const in6_addr &v6) noexcept {
  const auto *b = v6.s6_addr;
  // IPv4-mapped ::ffff:0:0/96
  bool is_mapped = true;
  for (int i = 0; i < 10; ++i) {
    if (b[i] != 0U) {
      is_mapped = false;
      break;
    }
  }
  if (is_mapped && b[10] == 0xFFU && b[11] == 0xFFU) {
    return (static_cast<std::uint32_t>(b[12]) << 24U) |
           (static_cast<std::uint32_t>(b[13]) << 16U) |
           (static_cast<std::uint32_t>(b[14]) << 8U) |
           static_cast<std::uint32_t>(b[15]);
  }
  // NAT64 well-known prefix 64:ff9b::/96
  if (b[0] == 0x00U && b[1] == 0x64U && b[2] == 0xFFU && b[3] == 0x9BU) {
    bool mid_zero = true;
    for (int i = 4; i < 12; ++i) {
      if (b[i] != 0U) {
        mid_zero = false;
        break;
      }
    }
    if (mid_zero) {
      return (static_cast<std::uint32_t>(b[12]) << 24U) |
             (static_cast<std::uint32_t>(b[13]) << 16U) |
             (static_cast<std::uint32_t>(b[14]) << 8U) |
             static_cast<std::uint32_t>(b[15]);
    }
  }
  return std::nullopt;
}

bool is_ipv6_loopback(const in6_addr &v6) noexcept {
  const auto *b = v6.s6_addr;
  bool all_zero_prefix = true;
  for (int i = 0; i < 15; ++i) {
    if (b[i] != 0U) {
      all_zero_prefix = false;
      break;
    }
  }
  if (all_zero_prefix && b[15] == 1U) {
    return true;
  }
  if (const auto embedded = extract_embedded_ipv4(v6); embedded.has_value()) {
    return is_ipv4_loopback(*embedded);
  }
  return false;
}

bool is_ipv6_private_or_special(const in6_addr &v6) noexcept {
  const auto *b = v6.s6_addr;
  bool all_zero = true;
  for (int i = 0; i < 16; ++i) {
    if (b[i] != 0U) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) { // ::/128
    return true;
  }
  if (is_ipv6_loopback(v6)) {
    return true;
  }
  if (const auto embedded = extract_embedded_ipv4(v6); embedded.has_value()) {
    return is_ipv4_private_or_special(*embedded);
  }
  if ((b[0] & 0xFEU) == 0xFCU) { // fc00::/7 ULA
    return true;
  }
  if (b[0] == 0xFEU && (b[1] & 0xC0U) == 0x80U) { // fe80::/10 link-local
    return true;
  }
  if (b[0] == 0xFEU && (b[1] & 0xC0U) == 0xC0U) { // fec0::/10 site-local
    return true;
  }
  if (b[0] == 0xFFU) { // ff00::/8 multicast
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Socket poll + non-blocking TCP + optional OpenSSL 3 TLS 1.2+/1.3 stream
// ---------------------------------------------------------------------------

struct PollWaitSpec {
  int fd = -1;
  short events = 0;
  SteadyClock::time_point deadline{};
  const std::function<bool()> *cancelled = nullptr;
};

Result<void> wait_socket_ready(const PollWaitSpec &spec) {
  for (;;) {
    if (spec.cancelled != nullptr && *spec.cancelled && (*spec.cancelled)()) {
      return fail_nv(ErrorCode::interrupted, NetError::cancelled);
    }
    const int rem = remaining_timeout_ms(spec.deadline);
    if (rem == 0) {
      return fail_nv(ErrorCode::provider_transport, NetError::timeout);
    }
    const int slice =
        (spec.cancelled != nullptr && *spec.cancelled) ? std::min(rem, 50) : rem;
    pollfd pfd{};
    pfd.fd = spec.fd;
    pfd.events = spec.events;
    const int rc = ::poll(&pfd, 1U, slice);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      return fail_nv(ErrorCode::provider_transport, NetError::tls_io_failed);
    }
    if (rc == 0) {
      if (remaining_timeout_ms(spec.deadline) == 0) {
        return fail_nv(ErrorCode::provider_transport, NetError::timeout);
      }
      continue;
    }
    return Result<void>::success();
  }
}

struct TcpDialSpec {
  std::string host;
  std::uint16_t port = 0U;
  int connect_timeout_ms = kDefaultConnectTimeoutMs;
  const AllowedHostPolicy *policy = nullptr;
  const std::function<bool()> *cancelled = nullptr;
};

Result<ScopedFd> tcp_connect_bounded(const TcpDialSpec &spec) {
  if (spec.host.empty() || spec.port == 0U || spec.connect_timeout_ms <= 0) {
    return fail_n<ScopedFd>(ErrorCode::invalid_range, NetError::invalid_request);
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  const std::string port_str = std::to_string(spec.port);
  addrinfo *raw_res = nullptr;
  if (::getaddrinfo(spec.host.c_str(), port_str.c_str(), &hints, &raw_res) != 0 ||
      raw_res == nullptr) {
    return fail_n<ScopedFd>(ErrorCode::provider_transport, NetError::dns_failed);
  }
  UniqueAddrInfo res{raw_res};

  const auto deadline =
      SteadyClock::now() + std::chrono::milliseconds{spec.connect_timeout_ms};
  NetError last_err = NetError::connect_failed;
  bool any_allowed_addr = false;

  for (const addrinfo *ai = res.get(); ai != nullptr; ai = ai->ai_next) {
    if (spec.policy != nullptr) {
      const auto addr_ok = spec.policy->validate_resolved_address(ai->ai_addr);
      if (!addr_ok.has_value()) {
        last_err = net_error_of(addr_ok.error());
        continue;
      }
    }
    any_allowed_addr = true;

    const int sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) {
      continue;
    }
    ScopedFd owned{sock};

    const int flags = ::fcntl(owned.get(), F_GETFL, 0);
    if (flags < 0 || ::fcntl(owned.get(), F_SETFL, flags | O_NONBLOCK) != 0) {
      continue;
    }
    const int fd_flags = ::fcntl(owned.get(), F_GETFD, 0);
    if (fd_flags >= 0) {
      (void)::fcntl(owned.get(), F_SETFD, fd_flags | FD_CLOEXEC);
    }
    const int one = 1;
    (void)::setsockopt(owned.get(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    (void)::setsockopt(owned.get(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    const int rc = ::connect(owned.get(), ai->ai_addr, ai->ai_addrlen);
    if (rc == 0) {
      return Result<ScopedFd>::success(std::move(owned));
    }
    if (errno != EINPROGRESS) {
      last_err = NetError::connect_failed;
      continue;
    }

    const auto ready =
        wait_socket_ready({owned.get(), POLLOUT, deadline, spec.cancelled});
    if (!ready.has_value()) {
      if (net_error_of(ready.error()) == NetError::cancelled) {
        return Result<ScopedFd>::failure(ready.error());
      }
      last_err = net_error_of(ready.error());
      continue;
    }
    int so_err = 0;
    socklen_t so_len = sizeof(so_err);
    if (::getsockopt(owned.get(), SOL_SOCKET, SO_ERROR, &so_err, &so_len) != 0 ||
        so_err != 0) {
      last_err = NetError::connect_failed;
      continue;
    }
    return Result<ScopedFd>::success(std::move(owned));
  }

  if (!any_allowed_addr && last_err == NetError::ssrf_blocked) {
    return fail_n<ScopedFd>(ErrorCode::conflict, NetError::ssrf_blocked);
  }
  return fail_n<ScopedFd>(ErrorCode::provider_transport, last_err);
}

class HttpStream {
public:
  static Result<HttpStream> connect(const HttpClientConfig &config,
                                    const ParsedUrl &url, int connect_timeout_ms) {
    const std::string &tcp_host =
        config.connect_host_override.empty() ? url.host : config.connect_host_override;
    const std::uint16_t tcp_port = config.connect_port_override.value_or(url.port);

    auto fd_res = tcp_connect_bounded({tcp_host, tcp_port, connect_timeout_ms,
                                       &config.host_policy, &config.cancelled});
    if (!fd_res.has_value()) {
      return Result<HttpStream>::failure(fd_res.error());
    }
    ScopedFd fd = std::move(fd_res).value();

    if (url.scheme == "http") {
      return Result<HttpStream>::success(
          HttpStream{nullptr, nullptr, std::move(fd), &config.cancelled});
    }

    UniqueSslCtx ctx{SSL_CTX_new(TLS_client_method())};
    if (!ctx) {
      return fail_n<HttpStream>(ErrorCode::provider_transport,
                                NetError::tls_init_failed);
    }
    const int min_ver = std::max(config.min_tls_version, kTlsVersion12);
    if (SSL_CTX_set_min_proto_version(ctx.get(), min_ver) != 1) {
      return fail_n<HttpStream>(ErrorCode::provider_transport,
                                NetError::tls_init_failed);
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

    if (config.ca_bundle_path.has_value()) {
      const std::string ca_path = config.ca_bundle_path->string();
      if (ca_path.empty() ||
          SSL_CTX_load_verify_locations(ctx.get(), ca_path.c_str(), nullptr) != 1) {
        return fail_n<HttpStream>(ErrorCode::provider_transport,
                                  NetError::tls_ca_load_failed);
      }
    } else {
      const bool default_ok = SSL_CTX_set_default_verify_paths(ctx.get()) == 1;
#if defined(__APPLE__)
      const bool apple_ok =
          SSL_CTX_load_verify_locations(ctx.get(), "/etc/ssl/cert.pem", nullptr) == 1;
      if (!default_ok && !apple_ok) {
        return fail_n<HttpStream>(ErrorCode::provider_transport,
                                  NetError::tls_ca_load_failed);
      }
#else
      if (!default_ok) {
        return fail_n<HttpStream>(ErrorCode::provider_transport,
                                  NetError::tls_ca_load_failed);
      }
#endif
    }

    if (SSL_CTX_set_alpn_protos(ctx.get(), kAlpnHttp11.data(),
                                static_cast<unsigned int>(kAlpnHttp11.size())) != 0) {
      return fail_n<HttpStream>(ErrorCode::provider_transport,
                                NetError::tls_init_failed);
    }

    UniqueSsl ssl{SSL_new(ctx.get())};
    if (!ssl || SSL_set_fd(ssl.get(), fd.get()) != 1) {
      return fail_n<HttpStream>(ErrorCode::provider_transport,
                                NetError::tls_init_failed);
    }

    const bool ip_host = is_ip_literal(url.host);
    if (!ip_host) {
      if (SSL_ctrl(ssl.get(), SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
                   const_cast<char *>(url.host.c_str())) != 1) {
        return fail_n<HttpStream>(ErrorCode::provider_transport,
                                  NetError::tls_init_failed);
      }
    }

    X509_VERIFY_PARAM *param = SSL_get0_param(ssl.get());
    if (param == nullptr) {
      return fail_n<HttpStream>(ErrorCode::provider_transport,
                                NetError::tls_init_failed);
    }
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (ip_host) {
      if (X509_VERIFY_PARAM_set1_ip_asc(param, url.host.c_str()) != 1) {
        return fail_n<HttpStream>(ErrorCode::provider_transport,
                                  NetError::tls_init_failed);
      }
    } else {
      if (X509_VERIFY_PARAM_set1_host(param, url.host.c_str(), url.host.size()) != 1) {
        return fail_n<HttpStream>(ErrorCode::provider_transport,
                                  NetError::tls_init_failed);
      }
    }

    const auto deadline =
        SteadyClock::now() + std::chrono::milliseconds{connect_timeout_ms};
    for (;;) {
      ERR_clear_error();
      int rc = 0;
      {
        const ScopedSigpipeGuard sigpipe_guard;
        rc = SSL_connect(ssl.get());
      }
      if (rc == 1) {
        break;
      }
      const int ssl_err = SSL_get_error(ssl.get(), rc);
      if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
        const short ev = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
        const auto wait_res =
            wait_socket_ready({fd.get(), ev, deadline, &config.cancelled});
        if (!wait_res.has_value()) {
          return Result<HttpStream>::failure(wait_res.error());
        }
        continue;
      }
      if (SSL_get_verify_result(ssl.get()) != X509_V_OK) {
        return fail_n<HttpStream>(ErrorCode::provider_transport,
                                  NetError::tls_verify_failed);
      }
      return fail_n<HttpStream>(ErrorCode::provider_transport,
                                NetError::tls_handshake_failed);
    }

    if (SSL_version(ssl.get()) < min_ver) {
      return fail_n<HttpStream>(ErrorCode::provider_transport,
                                NetError::tls_handshake_failed);
    }
    UniqueX509 peer_cert{SSL_get1_peer_certificate(ssl.get())};
    if (!peer_cert || SSL_get_verify_result(ssl.get()) != X509_V_OK) {
      return fail_n<HttpStream>(ErrorCode::provider_transport,
                                NetError::tls_verify_failed);
    }

    return Result<HttpStream>::success(
        HttpStream{std::move(ctx), std::move(ssl), std::move(fd), &config.cancelled});
  }

  HttpStream(const HttpStream &) = delete;
  HttpStream &operator=(const HttpStream &) = delete;
  HttpStream(HttpStream &&) noexcept = default;
  HttpStream &operator=(HttpStream &&) noexcept = default;
  ~HttpStream() { shutdown_quiet(); }

  Result<void> write_all(std::span<const std::uint8_t> bytes,
                         SteadyClock::time_point deadline) {
    std::size_t offset = 0U;
    while (offset < bytes.size()) {
      const std::size_t chunk = std::min<std::size_t>(
          bytes.size() - offset, static_cast<std::size_t>(16U * 1024U));
      if (ssl_) {
        ERR_clear_error();
        int rc = 0;
        {
          const ScopedSigpipeGuard sigpipe_guard;
          rc = SSL_write(ssl_.get(), bytes.data() + offset, static_cast<int>(chunk));
        }
        if (rc > 0) {
          offset += static_cast<std::size_t>(rc);
          continue;
        }
        const int ssl_err = SSL_get_error(ssl_.get(), rc);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
          const short ev = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
          const auto wait_res =
              wait_socket_ready({fd_.get(), ev, deadline, cancelled_});
          if (!wait_res.has_value()) {
            return wait_res;
          }
          continue;
        }
        return fail_nv(ErrorCode::provider_transport, NetError::tls_io_failed);
      }

      ssize_t rc = 0;
      {
        const ScopedSigpipeGuard sigpipe_guard;
#ifdef MSG_NOSIGNAL
        rc = ::send(fd_.get(), bytes.data() + offset, chunk, MSG_NOSIGNAL);
#else
        rc = ::send(fd_.get(), bytes.data() + offset, chunk, 0);
#endif
      }
      if (rc > 0) {
        offset += static_cast<std::size_t>(rc);
        continue;
      }
      if (rc < 0 && errno == EINTR) {
        continue;
      }
      if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        const auto wait_res =
            wait_socket_ready({fd_.get(), POLLOUT, deadline, cancelled_});
        if (!wait_res.has_value()) {
          return wait_res;
        }
        continue;
      }
      return fail_nv(ErrorCode::provider_transport, NetError::tls_io_failed);
    }
    return Result<void>::success();
  }

  // Returns bytes read, 0 on clean EOF, or error on timeout/cancel/IO failure.
  Result<std::size_t> read_some(std::span<std::uint8_t> out,
                                SteadyClock::time_point deadline) {
    for (;;) {
      if (cancelled_ != nullptr && *cancelled_ && (*cancelled_)()) {
        return fail_n<std::size_t>(ErrorCode::interrupted, NetError::cancelled);
      }
      if (ssl_) {
        ERR_clear_error();
        int rc = 0;
        {
          const ScopedSigpipeGuard sigpipe_guard;
          rc = SSL_read(ssl_.get(), out.data(), static_cast<int>(out.size()));
        }
        if (rc > 0) {
          return Result<std::size_t>::success(static_cast<std::size_t>(rc));
        }
        const int ssl_err = SSL_get_error(ssl_.get(), rc);
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
          return Result<std::size_t>::success(std::size_t{0U});
        }
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
          const short ev = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
          const auto wait_res =
              wait_socket_ready({fd_.get(), ev, deadline, cancelled_});
          if (!wait_res.has_value()) {
            return Result<std::size_t>::failure(wait_res.error());
          }
          continue;
        }
        if (ssl_err == SSL_ERROR_SYSCALL && rc == 0) {
          return Result<std::size_t>::success(std::size_t{0U});
        }
        return fail_n<std::size_t>(ErrorCode::provider_transport,
                                   NetError::tls_io_failed);
      }

      const ssize_t rc = ::read(fd_.get(), out.data(), out.size());
      if (rc > 0) {
        return Result<std::size_t>::success(static_cast<std::size_t>(rc));
      }
      if (rc == 0) {
        return Result<std::size_t>::success(std::size_t{0U});
      }
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        const auto wait_res =
            wait_socket_ready({fd_.get(), POLLIN, deadline, cancelled_});
        if (!wait_res.has_value()) {
          return Result<std::size_t>::failure(wait_res.error());
        }
        continue;
      }
      return fail_n<std::size_t>(ErrorCode::provider_transport,
                                 NetError::tls_io_failed);
    }
  }

  void shutdown_quiet() noexcept {
    if (ssl_) {
      const ScopedSigpipeGuard sigpipe_guard;
      (void)SSL_shutdown(ssl_.get());
      ssl_.reset();
    }
    fd_.reset();
    ctx_.reset();
  }

private:
  HttpStream(UniqueSslCtx ctx, UniqueSsl ssl, ScopedFd fd,
             const std::function<bool()> *cancelled) noexcept
      : ctx_(std::move(ctx)), ssl_(std::move(ssl)), fd_(std::move(fd)),
        cancelled_(cancelled) {}

  UniqueSslCtx ctx_;
  UniqueSsl ssl_;
  ScopedFd fd_;
  const std::function<bool()> *cancelled_ = nullptr;
};

// ---------------------------------------------------------------------------
// HTTP/1.1 framing, header parsing & streaming body/chunked decoding
// ---------------------------------------------------------------------------

struct ParsedHeaderBlock {
  int status = 0;
  std::vector<HttpHeader> headers;
  std::size_t header_end_offset = 0U;
};

Result<ParsedHeaderBlock>
parse_http_response_headers(std::span<const std::uint8_t> buf) {
  const std::string_view text{reinterpret_cast<const char *>(buf.data()), buf.size()};
  const std::size_t header_end = text.find("\r\n\r\n");
  if (header_end == std::string_view::npos) {
    return fail_n<ParsedHeaderBlock>(ErrorCode::corrupt,
                                     NetError::http_malformed_response);
  }
  const std::string_view block = text.substr(0U, header_end);
  const std::size_t first_eol = block.find("\r\n");
  const std::string_view status_line =
      (first_eol == std::string_view::npos) ? block : block.substr(0U, first_eol);
  if ((!status_line.starts_with("HTTP/1.1 ") &&
       !status_line.starts_with("HTTP/1.0 ")) ||
      status_line.size() < 12U) {
    return fail_n<ParsedHeaderBlock>(ErrorCode::corrupt,
                                     NetError::http_malformed_response);
  }
  const std::string_view code_str = status_line.substr(9U, 3U);
  int status = 0;
  const auto [ptr, ec] =
      std::from_chars(code_str.data(), code_str.data() + code_str.size(), status);
  if (ec != std::errc{} || ptr != code_str.data() + code_str.size() || status < 100 ||
      status > 599) {
    return fail_n<ParsedHeaderBlock>(ErrorCode::corrupt,
                                     NetError::http_malformed_response);
  }

  std::vector<HttpHeader> headers;
  if (first_eol != std::string_view::npos) {
    std::size_t pos = first_eol + 2U;
    while (pos < block.size()) {
      const std::size_t eol = block.find("\r\n", pos);
      const std::string_view line = (eol == std::string_view::npos)
                                        ? block.substr(pos)
                                        : block.substr(pos, eol - pos);
      const std::size_t colon = line.find(':');
      if (colon == std::string_view::npos || colon == 0U) {
        return fail_n<ParsedHeaderBlock>(ErrorCode::corrupt,
                                         NetError::http_malformed_response);
      }
      const std::string_view raw_name = line.substr(0U, colon);
      if (!is_valid_header_name(raw_name)) {
        return fail_n<ParsedHeaderBlock>(ErrorCode::corrupt,
                                         NetError::http_malformed_response);
      }
      const std::string_view raw_val = trim_ows(line.substr(colon + 1U));
      headers.push_back(HttpHeader{ascii_lower(raw_name), std::string{raw_val}});
      if (eol == std::string_view::npos) {
        break;
      }
      pos = eol + 2U;
    }
  }
  return Result<ParsedHeaderBlock>::success(
      ParsedHeaderBlock{status, std::move(headers), header_end + 4U});
}

Result<void> read_until_headers_complete(HttpStream &stream,
                                         std::vector<std::uint8_t> &buf,
                                         std::size_t max_header_bytes,
                                         SteadyClock::time_point deadline) {
  std::array<std::uint8_t, 4096> tmp{};
  for (;;) {
    const std::string_view view{reinterpret_cast<const char *>(buf.data()), buf.size()};
    const std::size_t idx = view.find("\r\n\r\n");
    if (idx != std::string_view::npos) {
      if (idx + 4U > max_header_bytes) {
        return fail_nv(ErrorCode::overflow, NetError::http_header_too_large);
      }
      return Result<void>::success();
    }
    if (buf.size() >= max_header_bytes) {
      return fail_nv(ErrorCode::overflow, NetError::http_header_too_large);
    }
    const auto got = stream.read_some(tmp, deadline);
    if (!got.has_value()) {
      return Result<void>::failure(got.error());
    }
    if (got.value() == 0U) {
      return fail_nv(ErrorCode::corrupt, NetError::http_malformed_response);
    }
    buf.insert(buf.end(), tmp.begin(),
               tmp.begin() + static_cast<std::ptrdiff_t>(got.value()));
  }
}

struct BodyFraming {
  bool is_chunked = false;
  std::optional<std::size_t> content_length;
};

Result<BodyFraming> inspect_body_framing(const ParsedHeaderBlock &parsed_hdr,
                                         std::size_t max_body_bytes) {
  BodyFraming framing{};
  std::size_t te_coding_count = 0U;

  for (const auto &hdr : parsed_hdr.headers) {
    if (hdr.name == "transfer-encoding") {
      std::size_t pos = 0U;
      while (pos <= hdr.value.size()) {
        const std::size_t comma = hdr.value.find(',', pos);
        const std::string_view part =
            (comma == std::string_view::npos)
                ? std::string_view{hdr.value}.substr(pos)
                : std::string_view{hdr.value}.substr(pos, comma - pos);
        const std::string coding = ascii_lower(trim_ows(part));
        if (coding != "chunked" || te_coding_count > 0U) {
          return fail_n<BodyFraming>(ErrorCode::corrupt,
                                     NetError::http_malformed_response);
        }
        framing.is_chunked = true;
        ++te_coding_count;
        if (comma == std::string_view::npos) {
          break;
        }
        pos = comma + 1U;
      }
    } else if (hdr.name == "content-encoding") {
      const std::string ce = ascii_lower(trim_ows(hdr.value));
      if (!ce.empty() && ce != "identity") {
        return fail_n<BodyFraming>(ErrorCode::unsupported,
                                   NetError::http_unsupported_encoding);
      }
    } else if (hdr.name == "content-length") {
      std::uint64_t cl = 0U;
      const auto [ptr, ec] =
          std::from_chars(hdr.value.data(), hdr.value.data() + hdr.value.size(), cl);
      if (ec != std::errc{} || ptr != hdr.value.data() + hdr.value.size()) {
        return fail_n<BodyFraming>(ErrorCode::corrupt,
                                   NetError::http_malformed_response);
      }
      if (cl > max_body_bytes) {
        return fail_n<BodyFraming>(ErrorCode::overflow, NetError::http_body_too_large);
      }
      if (framing.content_length.has_value() &&
          *framing.content_length != static_cast<std::size_t>(cl)) {
        return fail_n<BodyFraming>(ErrorCode::corrupt,
                                   NetError::http_malformed_response);
      }
      framing.content_length = static_cast<std::size_t>(cl);
    }
  }

  // RFC 9112 §6.3: reject messages with both Transfer-Encoding and Content-Length.
  if (framing.is_chunked && framing.content_length.has_value()) {
    return fail_n<BodyFraming>(ErrorCode::corrupt, NetError::http_malformed_response);
  }
  return Result<BodyFraming>::success(framing);
}

using BodySink = std::function<Result<bool>(std::span<const std::uint8_t>)>;

struct BodyReadSpec {
  std::size_t max_header_bytes = kDefaultMaxHeaderBytes;
  std::size_t max_body_bytes = kDefaultMaxBodyBytes;
  bool enforce_total_body_cap = true;
  SteadyClock::time_point deadline{};
};

Result<void> stream_chunked_body(HttpStream &stream, std::vector<std::uint8_t> &wire,
                                 const BodyReadSpec &spec, const BodySink &sink) {
  std::size_t cursor = 0U;
  std::size_t total_decoded = 0U;
  std::array<std::uint8_t, 4096> tmp{};

  auto compact = [&]() {
    if (cursor > 4096U) {
      wire.erase(wire.begin(), wire.begin() + static_cast<std::ptrdiff_t>(cursor));
      cursor = 0U;
    }
  };

  auto fill_more = [&]() -> Result<void> {
    compact();
    const auto got = stream.read_some(tmp, spec.deadline);
    if (!got.has_value()) {
      return Result<void>::failure(got.error());
    }
    if (got.value() == 0U) {
      return fail_nv(ErrorCode::corrupt, NetError::http_chunked_malformed);
    }
    wire.insert(wire.end(), tmp.begin(),
                tmp.begin() + static_cast<std::ptrdiff_t>(got.value()));
    return Result<void>::success();
  };

  auto read_crlf_line = [&](std::size_t max_line) -> Result<std::string> {
    for (;;) {
      const std::string_view avail{reinterpret_cast<const char *>(wire.data() + cursor),
                                   wire.size() - cursor};
      const std::size_t pos = avail.find("\r\n");
      if (pos != std::string_view::npos) {
        if (pos > max_line) {
          return fail_n<std::string>(ErrorCode::corrupt,
                                     NetError::http_chunked_malformed);
        }
        std::string line{avail.substr(0U, pos)};
        cursor += pos + 2U;
        return Result<std::string>::success(std::move(line));
      }
      if (avail.size() > max_line) {
        return fail_n<std::string>(ErrorCode::corrupt,
                                   NetError::http_chunked_malformed);
      }
      if (const auto more = fill_more(); !more.has_value()) {
        return Result<std::string>::failure(more.error());
      }
    }
  };

  for (;;) {
    const auto size_line = read_crlf_line(128U);
    if (!size_line.has_value()) {
      return Result<void>::failure(size_line.error());
    }
    std::string_view hex_part = size_line.value();
    if (const std::size_t semi = hex_part.find(';'); semi != std::string_view::npos) {
      hex_part = hex_part.substr(0U, semi);
    }
    hex_part = trim_ows(hex_part);
    if (hex_part.empty() || hex_part.size() > 16U) {
      return fail_nv(ErrorCode::corrupt, NetError::http_chunked_malformed);
    }
    std::uint64_t chunk_len = 0U;
    const auto [ptr, ec] = std::from_chars(
        hex_part.data(), hex_part.data() + hex_part.size(), chunk_len, 16);
    if (ec != std::errc{} || ptr != hex_part.data() + hex_part.size()) {
      return fail_nv(ErrorCode::corrupt, NetError::http_chunked_malformed);
    }
    if (chunk_len == 0U) {
      std::size_t trailer_bytes = 0U;
      for (;;) {
        const auto trailer = read_crlf_line(spec.max_header_bytes);
        if (!trailer.has_value()) {
          return Result<void>::failure(trailer.error());
        }
        if (trailer.value().empty()) {
          break;
        }
        trailer_bytes += trailer.value().size() + 2U;
        if (trailer_bytes > spec.max_header_bytes) {
          return fail_nv(ErrorCode::overflow, NetError::http_header_too_large);
        }
      }
      return Result<void>::success();
    }
    if (spec.enforce_total_body_cap &&
        (chunk_len > spec.max_body_bytes ||
         total_decoded + chunk_len > spec.max_body_bytes)) {
      return fail_nv(ErrorCode::overflow, NetError::http_body_too_large);
    }
    if (chunk_len > std::numeric_limits<std::size_t>::max()) {
      return fail_nv(ErrorCode::overflow, NetError::http_body_too_large);
    }

    // Stream chunk payload incrementally to sink as bytes arrive.
    std::size_t remaining = static_cast<std::size_t>(chunk_len);
    while (remaining > 0U) {
      if (wire.size() == cursor) {
        if (const auto more = fill_more(); !more.has_value()) {
          return Result<void>::failure(more.error());
        }
      }
      const std::size_t take = std::min(remaining, wire.size() - cursor);
      const auto keep_going =
          sink(std::span<const std::uint8_t>{wire.data() + cursor, take});
      if (!keep_going.has_value()) {
        return Result<void>::failure(keep_going.error());
      }
      cursor += take;
      remaining -= take;
      total_decoded += take;
      if (!keep_going.value()) {
        return Result<void>::success();
      }
    }

    // Consume mandatory CRLF after chunk data.
    while (wire.size() - cursor < 2U) {
      if (const auto more = fill_more(); !more.has_value()) {
        return Result<void>::failure(more.error());
      }
    }
    if (wire[cursor] != '\r' || wire[cursor + 1U] != '\n') {
      return fail_nv(ErrorCode::corrupt, NetError::http_chunked_malformed);
    }
    cursor += 2U;
  }
}

Result<void> stream_http_body(HttpStream &stream, HttpMethod method,
                              const ParsedHeaderBlock &parsed_hdr,
                              std::vector<std::uint8_t> trailing,
                              const BodyReadSpec &spec, const BodySink &sink) {
  const auto framing_res =
      inspect_body_framing(parsed_hdr, spec.enforce_total_body_cap
                                           ? spec.max_body_bytes
                                           : std::numeric_limits<std::size_t>::max());
  if (!framing_res.has_value()) {
    return Result<void>::failure(framing_res.error());
  }
  const BodyFraming &framing = framing_res.value();

  if (method == HttpMethod::head || parsed_hdr.status == 204 ||
      parsed_hdr.status == 304 ||
      (parsed_hdr.status >= 100 && parsed_hdr.status < 200)) {
    return Result<void>::success();
  }

  if (framing.is_chunked) {
    return stream_chunked_body(stream, trailing, spec, sink);
  }

  std::array<std::uint8_t, 4096> tmp{};
  if (framing.content_length.has_value()) {
    const std::size_t need = *framing.content_length;
    std::size_t delivered = 0U;
    if (!trailing.empty()) {
      const std::size_t take = std::min(need, trailing.size());
      const auto keep_going =
          sink(std::span<const std::uint8_t>{trailing.data(), take});
      if (!keep_going.has_value()) {
        return Result<void>::failure(keep_going.error());
      }
      delivered += take;
      if (!keep_going.value()) {
        return Result<void>::success();
      }
    }
    while (delivered < need) {
      const std::size_t rem = need - delivered;
      const auto got = stream.read_some(
          std::span<std::uint8_t>{tmp.data(), std::min(rem, tmp.size())},
          spec.deadline);
      if (!got.has_value()) {
        return Result<void>::failure(got.error());
      }
      if (got.value() == 0U) {
        return fail_nv(ErrorCode::corrupt, NetError::http_malformed_response);
      }
      const auto keep_going =
          sink(std::span<const std::uint8_t>{tmp.data(), got.value()});
      if (!keep_going.has_value()) {
        return Result<void>::failure(keep_going.error());
      }
      delivered += got.value();
      if (!keep_going.value()) {
        return Result<void>::success();
      }
    }
    return Result<void>::success();
  }

  // EOF-delimited body.
  std::size_t delivered = 0U;
  if (!trailing.empty()) {
    if (spec.enforce_total_body_cap && trailing.size() > spec.max_body_bytes) {
      return fail_nv(ErrorCode::overflow, NetError::http_body_too_large);
    }
    const auto keep_going =
        sink(std::span<const std::uint8_t>{trailing.data(), trailing.size()});
    if (!keep_going.has_value()) {
      return Result<void>::failure(keep_going.error());
    }
    delivered += trailing.size();
    if (!keep_going.value()) {
      return Result<void>::success();
    }
  }
  for (;;) {
    const auto got = stream.read_some(tmp, spec.deadline);
    if (!got.has_value()) {
      return Result<void>::failure(got.error());
    }
    if (got.value() == 0U) {
      return Result<void>::success();
    }
    if (spec.enforce_total_body_cap && delivered + got.value() > spec.max_body_bytes) {
      return fail_nv(ErrorCode::overflow, NetError::http_body_too_large);
    }
    const auto keep_going =
        sink(std::span<const std::uint8_t>{tmp.data(), got.value()});
    if (!keep_going.has_value()) {
      return Result<void>::failure(keep_going.error());
    }
    delivered += got.value();
    if (!keep_going.value()) {
      return Result<void>::success();
    }
  }
}

bool is_redirect_status(int status) noexcept {
  return status == 301 || status == 302 || status == 303 || status == 307 ||
         status == 308;
}

bool is_event_stream_content_type(std::string_view value) noexcept {
  const std::size_t semi = value.find(';');
  const std::string_view media =
      trim_ows(semi == std::string_view::npos ? value : value.substr(0U, semi));
  return ascii_iequals(media, "text/event-stream");
}

Result<std::vector<std::uint8_t>>
serialize_http_request(const HttpRequest &req, const ParsedUrl &url,
                       std::string_view default_user_agent) {
  std::string wire;
  wire.reserve(512U + req.body.size());
  wire.append(http_method_name(req.method));
  wire.push_back(' ');
  wire.append(url.request_target());
  wire.append(" HTTP/1.1\r\n");

  bool has_connection = false;
  bool has_user_agent = false;
  bool has_accept_encoding = false;
  bool has_content_length = false;

  for (const auto &hdr : req.headers) {
    if (!is_valid_header_name(hdr.name) || !is_valid_header_value(hdr.value)) {
      return fail_n<std::vector<std::uint8_t>>(ErrorCode::invalid_range,
                                               NetError::invalid_request);
    }
    if (ascii_iequals(hdr.name, "host") ||
        ascii_iequals(hdr.name, "transfer-encoding")) {
      return fail_n<std::vector<std::uint8_t>>(ErrorCode::invalid_range,
                                               NetError::invalid_request);
    }
    if (ascii_iequals(hdr.name, "connection")) {
      has_connection = true;
    } else if (ascii_iequals(hdr.name, "user-agent")) {
      has_user_agent = true;
    } else if (ascii_iequals(hdr.name, "accept-encoding")) {
      has_accept_encoding = true;
    } else if (ascii_iequals(hdr.name, "content-length")) {
      has_content_length = true;
    }
  }

  wire.append("Host: ");
  wire.append(url.authority());
  wire.append("\r\n");
  if (!has_user_agent && !default_user_agent.empty()) {
    wire.append("User-Agent: ");
    wire.append(default_user_agent);
    wire.append("\r\n");
  }
  if (!has_accept_encoding) {
    wire.append("Accept-Encoding: identity\r\n");
  }
  if (!has_connection) {
    wire.append("Connection: close\r\n");
  }
  for (const auto &hdr : req.headers) {
    if (ascii_iequals(hdr.name, "content-length")) {
      continue;
    }
    wire.append(hdr.name);
    wire.append(": ");
    wire.append(hdr.value);
    wire.append("\r\n");
  }
  if (!req.body.empty() || has_content_length || req.method == HttpMethod::post ||
      req.method == HttpMethod::put || req.method == HttpMethod::patch) {
    wire.append("Content-Length: ");
    wire.append(std::to_string(req.body.size()));
    wire.append("\r\n");
  }
  wire.append("\r\n");

  std::vector<std::uint8_t> out(wire.size() + req.body.size());
  std::memcpy(out.data(), wire.data(), wire.size());
  if (!wire.empty()) {
    OPENSSL_cleanse(wire.data(), wire.size());
  }
  if (!req.body.empty()) {
    std::memcpy(out.data() + wire.size(), req.body.data(), req.body.size());
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(out));
}

struct CleanseBytesGuard {
  std::vector<std::uint8_t> &bytes;
  ~CleanseBytesGuard() {
    if (!bytes.empty()) {
      OPENSSL_cleanse(bytes.data(), bytes.size());
    }
  }
};

Result<HttpResponse> execute_http_request(const HttpClientConfig &config,
                                          const HttpRequest &initial_req,
                                          const SseParser::EventCallback *sse_callback,
                                          SseParserConfig sse_config) {
  if (initial_req.connect_timeout_ms <= 0 || initial_req.io_timeout_ms <= 0 ||
      initial_req.max_header_bytes == 0U ||
      initial_req.max_header_bytes > kHardMaxHeaderBytes ||
      initial_req.max_body_bytes > kHardMaxBodyBytes ||
      initial_req.body.size() > kHardMaxBodyBytes) {
    return fail_n<HttpResponse>(ErrorCode::invalid_range, NetError::invalid_request);
  }

  HttpRequest current_req = initial_req;
  auto parsed_res = parse_url(current_req.url);
  if (!parsed_res.has_value()) {
    return Result<HttpResponse>::failure(parsed_res.error());
  }
  ParsedUrl current_url = std::move(parsed_res).value();

  if (const auto ok = config.host_policy.validate_url(current_url); !ok.has_value()) {
    return Result<HttpResponse>::failure(ok.error());
  }

  for (std::uint8_t hops = 0U;; ++hops) {
    auto stream_res =
        HttpStream::connect(config, current_url, current_req.connect_timeout_ms);
    if (!stream_res.has_value()) {
      return Result<HttpResponse>::failure(stream_res.error());
    }
    HttpStream stream = std::move(stream_res).value();

    auto wire_res =
        serialize_http_request(current_req, current_url, config.default_user_agent);
    if (!wire_res.has_value()) {
      return Result<HttpResponse>::failure(wire_res.error());
    }
    const CleanseBytesGuard cleanse_wire{wire_res.value()};
    const auto io_deadline =
        SteadyClock::now() + std::chrono::milliseconds{current_req.io_timeout_ms};
    if (const auto sent = stream.write_all(wire_res.value(), io_deadline);
        !sent.has_value()) {
      return Result<HttpResponse>::failure(sent.error());
    }

    // Read headers, skipping any 1xx interim responses (e.g. 100 Continue).
    std::vector<std::uint8_t> buf;
    ParsedHeaderBlock parsed_hdr{};
    for (;;) {
      if (const auto hdr_ok = read_until_headers_complete(
              stream, buf, current_req.max_header_bytes, io_deadline);
          !hdr_ok.has_value()) {
        return Result<HttpResponse>::failure(hdr_ok.error());
      }
      auto block_res = parse_http_response_headers(buf);
      if (!block_res.has_value()) {
        return Result<HttpResponse>::failure(block_res.error());
      }
      parsed_hdr = std::move(block_res).value();
      buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(
                                               parsed_hdr.header_end_offset));
      if (parsed_hdr.status >= 100 && parsed_hdr.status < 200 &&
          parsed_hdr.status != 101) {
        continue;
      }
      break;
    }

    // Handle HTTP redirects with strict host-pinning & downgrade refusal.
    if (is_redirect_status(parsed_hdr.status)) {
      std::optional<std::string_view> location;
      for (const auto &hdr : parsed_hdr.headers) {
        if (hdr.name == "location") {
          location = hdr.value;
          break;
        }
      }
      if (location.has_value() && !location->empty()) {
        if (!config.host_policy.allow_redirects) {
          return fail_n<HttpResponse>(ErrorCode::conflict, NetError::redirect_blocked);
        }
        if (hops >= config.host_policy.max_redirects) {
          return fail_n<HttpResponse>(ErrorCode::conflict,
                                      NetError::too_many_redirects);
        }
        auto next_url_res = resolve_redirect_url(current_url, *location);
        if (!next_url_res.has_value()) {
          return Result<HttpResponse>::failure(next_url_res.error());
        }
        ParsedUrl next_url = std::move(next_url_res).value();
        if (const auto redir_ok =
                config.host_policy.validate_redirect({current_url, next_url});
            !redir_ok.has_value()) {
          return Result<HttpResponse>::failure(redir_ok.error());
        }
        const bool same_origin =
            (current_url.scheme == next_url.scheme &&
             current_url.host == next_url.host && current_url.port == next_url.port);
        if (!same_origin) {
          current_req.remove_header("authorization");
          current_req.remove_header("cookie");
          current_req.remove_header("proxy-authorization");
        }
        if (parsed_hdr.status == 303 ||
            ((parsed_hdr.status == 301 || parsed_hdr.status == 302) &&
             current_req.method == HttpMethod::post)) {
          current_req.method = HttpMethod::get;
          current_req.body.clear();
          current_req.remove_header("content-type");
          current_req.remove_header("content-length");
        }
        current_url = std::move(next_url);
        current_req.url = current_url.str();
        continue;
      }
    }

    HttpResponse response{};
    response.status = parsed_hdr.status;
    response.headers = parsed_hdr.headers;
    response.final_url = current_url.str();

    const auto ct = response.find_header("content-type");
    const bool use_sse = (sse_callback != nullptr && *sse_callback &&
                          parsed_hdr.status >= 200 && parsed_hdr.status < 300 &&
                          ct.has_value() && is_event_stream_content_type(*ct));

    if (use_sse) {
      SseParser parser{sse_config};
      BodyReadSpec spec{current_req.max_header_bytes, current_req.max_body_bytes, false,
                        io_deadline};
      const auto stream_ok =
          stream_http_body(stream, current_req.method, parsed_hdr, std::move(buf), spec,
                           [&](std::span<const std::uint8_t> chunk) -> Result<bool> {
                             const auto fed = parser.feed(chunk, *sse_callback);
                             if (!fed.has_value()) {
                               return Result<bool>::failure(fed.error());
                             }
                             return Result<bool>::success(!parser.stopped());
                           });
      if (!stream_ok.has_value()) {
        return Result<HttpResponse>::failure(stream_ok.error());
      }
      if (!parser.stopped()) {
        if (const auto done = parser.finish(*sse_callback); !done.has_value()) {
          return Result<HttpResponse>::failure(done.error());
        }
      }
      return Result<HttpResponse>::success(std::move(response));
    }

    std::vector<std::uint8_t> body;
    BodyReadSpec spec{current_req.max_header_bytes, current_req.max_body_bytes, true,
                      io_deadline};
    const auto body_ok = stream_http_body(
        stream, current_req.method, parsed_hdr, std::move(buf), spec,
        [&](std::span<const std::uint8_t> chunk) -> Result<bool> {
          if (body.size() + chunk.size() > current_req.max_body_bytes) {
            return fail_n<bool>(ErrorCode::overflow, NetError::http_body_too_large);
          }
          body.insert(body.end(), chunk.begin(), chunk.end());
          return Result<bool>::success(true);
        });
    if (!body_ok.has_value()) {
      return Result<HttpResponse>::failure(body_ok.error());
    }
    response.body = std::move(body);
    return Result<HttpResponse>::success(std::move(response));
  }
}

} // namespace

// ---------------------------------------------------------------------------
// Public API implementations
// ---------------------------------------------------------------------------

std::string_view net_error_name(NetError detail) noexcept {
  switch (detail) {
  case NetError::none:
    return "none";
  case NetError::invalid_url:
    return "invalid_url";
  case NetError::invalid_request:
    return "invalid_request";
  case NetError::host_not_allowed:
    return "host_not_allowed";
  case NetError::scheme_not_allowed:
    return "scheme_not_allowed";
  case NetError::ssrf_blocked:
    return "ssrf_blocked";
  case NetError::redirect_blocked:
    return "redirect_blocked";
  case NetError::too_many_redirects:
    return "too_many_redirects";
  case NetError::dns_failed:
    return "dns_failed";
  case NetError::connect_failed:
    return "connect_failed";
  case NetError::timeout:
    return "timeout";
  case NetError::cancelled:
    return "cancelled";
  case NetError::tls_init_failed:
    return "tls_init_failed";
  case NetError::tls_ca_load_failed:
    return "tls_ca_load_failed";
  case NetError::tls_verify_failed:
    return "tls_verify_failed";
  case NetError::tls_handshake_failed:
    return "tls_handshake_failed";
  case NetError::tls_io_failed:
    return "tls_io_failed";
  case NetError::http_malformed_response:
    return "http_malformed_response";
  case NetError::http_header_too_large:
    return "http_header_too_large";
  case NetError::http_body_too_large:
    return "http_body_too_large";
  case NetError::http_chunked_malformed:
    return "http_chunked_malformed";
  case NetError::http_unsupported_encoding:
    return "http_unsupported_encoding";
  case NetError::sse_event_too_large:
    return "sse_event_too_large";
  case NetError::sse_aborted:
    return "sse_aborted";
  }
  return "unknown";
}

std::string ParsedUrl::authority() const {
  const bool ipv6 = host.find(':') != std::string::npos;
  std::string out = ipv6 ? ("[" + host + "]") : host;
  const std::uint16_t default_port = (scheme == "https") ? 443U : 80U;
  if (explicit_port || port != default_port) {
    out.push_back(':');
    out.append(std::to_string(port));
  }
  return out;
}

std::string ParsedUrl::request_target() const {
  std::string out = path.empty() ? std::string{"/"} : path;
  if (!query.empty()) {
    out.push_back('?');
    out.append(query);
  }
  return out;
}

std::string ParsedUrl::canonical_origin() const { return scheme + "://" + authority(); }

std::string ParsedUrl::str() const { return canonical_origin() + request_target(); }

Result<ParsedUrl> parse_url(std::string_view url) {
  if (url.empty() || url.size() > kMaxUrlBytes || contains_ctl(url)) {
    return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
  }
  for (const char ch : url) {
    const auto b = static_cast<std::uint8_t>(ch);
    if (b <= 0x20U || b >= 0x7fU || ch == '\\') {
      return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
    }
  }

  const std::size_t scheme_end = url.find("://");
  if (scheme_end == std::string_view::npos || scheme_end == 0U) {
    return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
  }
  const std::string scheme = ascii_lower(url.substr(0U, scheme_end));
  if (scheme != "https" && scheme != "http") {
    return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::scheme_not_allowed);
  }

  std::string_view rest = url.substr(scheme_end + 3U);
  if (rest.empty()) {
    return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
  }
  // Reject fragment identifiers in request URLs.
  if (rest.find('#') != std::string_view::npos) {
    return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
  }

  const std::size_t path_pos = rest.find_first_of("/?");
  const std::string_view authority_sv =
      (path_pos == std::string_view::npos) ? rest : rest.substr(0U, path_pos);
  const std::string_view suffix_sv =
      (path_pos == std::string_view::npos) ? std::string_view{} : rest.substr(path_pos);

  // Reject empty authority or userinfo ('@') to prevent SSRF parser confusion.
  if (authority_sv.empty() || authority_sv.find('@') != std::string_view::npos) {
    return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
  }

  std::string_view host_sv = authority_sv;
  std::optional<std::string_view> port_sv;
  if (authority_sv.front() == '[') {
    const std::size_t close = authority_sv.find(']');
    if (close == std::string_view::npos || close <= 1U) {
      return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
    }
    host_sv = authority_sv.substr(1U, close - 1U);
    if (close + 1U < authority_sv.size()) {
      if (authority_sv[close + 1U] != ':') {
        return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
      }
      port_sv = authority_sv.substr(close + 2U);
    }
    in6_addr v6{};
    const std::string host_tmp{host_sv};
    if (::inet_pton(AF_INET6, host_tmp.c_str(), &v6) != 1) {
      return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
    }
  } else {
    const std::size_t colon = authority_sv.find(':');
    if (colon != std::string_view::npos) {
      if (authority_sv.find(':', colon + 1U) != std::string_view::npos) {
        return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
      }
      host_sv = authority_sv.substr(0U, colon);
      port_sv = authority_sv.substr(colon + 1U);
    }
    if (!is_valid_hostname_chars(host_sv) ||
        host_sv.find(':') != std::string_view::npos ||
        has_empty_hostname_label(host_sv)) {
      return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
    }
  }

  std::uint16_t port = (scheme == "https") ? 443U : 80U;
  bool explicit_port = false;
  if (port_sv.has_value()) {
    const std::string_view p = *port_sv;
    if (p.empty() || p.size() > 5U || p.front() == '0') {
      return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
    }
    std::uint32_t parsed_port = 0U;
    const auto [ptr, ec] = std::from_chars(p.data(), p.data() + p.size(), parsed_port);
    if (ec != std::errc{} || ptr != p.data() + p.size() || parsed_port == 0U ||
        parsed_port > 65535U) {
      return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
    }
    port = static_cast<std::uint16_t>(parsed_port);
    explicit_port = true;
  }

  std::string path = "/";
  std::string query;
  if (!suffix_sv.empty()) {
    const std::size_t qmark = suffix_sv.find('?');
    if (qmark == std::string_view::npos) {
      path = std::string{suffix_sv};
    } else {
      path = qmark == 0U ? std::string{"/"} : std::string{suffix_sv.substr(0U, qmark)};
      query = std::string{suffix_sv.substr(qmark + 1U)};
    }
  }
  if (path.empty() || path.front() != '/') {
    return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
  }

  ParsedUrl out{};
  out.scheme = scheme;
  out.host = ascii_lower(host_sv);
  out.port = port;
  out.explicit_port = explicit_port;
  out.path = std::move(path);
  out.query = std::move(query);
  return Result<ParsedUrl>::success(std::move(out));
}

Result<ParsedUrl> resolve_redirect_url(const ParsedUrl &base,
                                       std::string_view location) {
  location = trim_ows(location);
  if (location.empty() || location.size() > kMaxUrlBytes || contains_ctl(location)) {
    return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
  }
  // Strip optional fragment on redirect target.
  if (const std::size_t hash = location.find('#'); hash != std::string_view::npos) {
    location = location.substr(0U, hash);
  }
  if (location.empty()) {
    return fail_n<ParsedUrl>(ErrorCode::invalid_range, NetError::invalid_url);
  }
  if (location.starts_with("//")) {
    return parse_url(base.scheme + ":" + std::string{location});
  }
  if (location.front() == '/') {
    return parse_url(base.canonical_origin() + std::string{location});
  }
  if (location.front() == '?') {
    return parse_url(base.canonical_origin() + base.path + std::string{location});
  }
  if (has_rfc3986_scheme_prefix(location)) {
    return parse_url(location);
  }
  // Relative path resolution against base directory.
  const std::size_t last_slash = base.path.rfind('/');
  const std::string_view dir =
      (last_slash == std::string::npos)
          ? std::string_view{"/"}
          : std::string_view{base.path}.substr(0U, last_slash + 1U);
  return parse_url(base.canonical_origin() + std::string{dir} + std::string{location});
}

bool is_ip_literal(std::string_view host) noexcept {
  if (host.empty() || host.size() > 64U) {
    return false;
  }
  const std::string s{host};
  in_addr v4{};
  if (::inet_pton(AF_INET, s.c_str(), &v4) == 1) {
    return true;
  }
  in6_addr v6{};
  return ::inet_pton(AF_INET6, s.c_str(), &v6) == 1;
}

bool is_loopback_address(const sockaddr *addr) noexcept {
  if (addr == nullptr) {
    return false;
  }
  if (addr->sa_family == AF_INET) {
    const auto *sin = reinterpret_cast<const sockaddr_in *>(addr);
    return is_ipv4_loopback(ntohl(sin->sin_addr.s_addr));
  }
  if (addr->sa_family == AF_INET6) {
    const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(addr);
    return is_ipv6_loopback(sin6->sin6_addr);
  }
  return false;
}

bool is_private_or_special_address(const sockaddr *addr) noexcept {
  if (addr == nullptr) {
    return true;
  }
  if (addr->sa_family == AF_INET) {
    const auto *sin = reinterpret_cast<const sockaddr_in *>(addr);
    return is_ipv4_private_or_special(ntohl(sin->sin_addr.s_addr));
  }
  if (addr->sa_family == AF_INET6) {
    const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(addr);
    return is_ipv6_private_or_special(sin6->sin6_addr);
  }
  return true;
}

bool is_loopback_ip_literal(std::string_view host) noexcept {
  if (host.empty() || host.size() > 64U) {
    return false;
  }
  const std::string s{host};
  in_addr v4{};
  if (::inet_pton(AF_INET, s.c_str(), &v4) == 1) {
    return is_ipv4_loopback(ntohl(v4.s_addr));
  }
  in6_addr v6{};
  if (::inet_pton(AF_INET6, s.c_str(), &v6) == 1) {
    return is_ipv6_loopback(v6);
  }
  return false;
}

bool is_private_or_special_ip_literal(std::string_view host) noexcept {
  if (host.empty() || host.size() > 64U) {
    return false;
  }
  const std::string s{host};
  in_addr v4{};
  if (::inet_pton(AF_INET, s.c_str(), &v4) == 1) {
    return is_ipv4_private_or_special(ntohl(v4.s_addr));
  }
  in6_addr v6{};
  if (::inet_pton(AF_INET6, s.c_str(), &v6) == 1) {
    return is_ipv6_private_or_special(v6);
  }
  return false;
}

bool host_matches_pin(HostPinCheck check) noexcept {
  if (check.host.empty() || check.pin.empty()) {
    return false;
  }
  if (check.host.find(':') == std::string_view::npos &&
      has_empty_hostname_label(check.host)) {
    return false;
  }
  if (check.pin.starts_with("*.")) {
    const std::string_view suffix = check.pin.substr(2U);
    // Reject bare "*", single-label TLD wildcards like "*.com", or empty labels.
    if (suffix.empty() || suffix.find('.') == std::string_view::npos ||
        suffix.find('*') != std::string_view::npos ||
        has_empty_hostname_label(suffix)) {
      return false;
    }
    if (check.host.size() <= suffix.size() + 1U) {
      return false;
    }
    const std::size_t dot_pos = check.host.size() - suffix.size() - 1U;
    if (check.host[dot_pos] != '.') {
      return false;
    }
    return ascii_iequals(check.host.substr(dot_pos + 1U), suffix);
  }
  if (check.pin.find(':') == std::string_view::npos &&
      has_empty_hostname_label(check.pin)) {
    return false;
  }
  return ascii_iequals(check.host, check.pin);
}

AllowedHostPolicy AllowedHostPolicy::pinned(std::vector<std::string> hosts) {
  AllowedHostPolicy policy{};
  policy.allowed_hosts = std::move(hosts);
  policy.require_pinned_host = true;
  policy.require_https = true;
  policy.allow_loopback = false;
  policy.allow_private_network = false;
  policy.allow_redirects = true;
  policy.allow_cross_host_redirects = false;
  return policy;
}

AllowedHostPolicy AllowedHostPolicy::any_public_https() {
  AllowedHostPolicy policy{};
  policy.require_pinned_host = false;
  policy.require_https = true;
  policy.allow_loopback = false;
  policy.allow_private_network = false;
  policy.allow_redirects = true;
  policy.allow_cross_host_redirects = false;
  return policy;
}

Result<void> AllowedHostPolicy::validate_url(const ParsedUrl &url) const {
  if (require_https && url.scheme != "https") {
    return fail_nv(ErrorCode::conflict, NetError::scheme_not_allowed);
  }
  if (url.scheme != "https" && url.scheme != "http") {
    return fail_nv(ErrorCode::conflict, NetError::scheme_not_allowed);
  }

  // Block localhost / loopback / private IP literals before DNS resolution.
  if (url.host == "localhost" || url.host.ends_with(".localhost")) {
    if (!allow_loopback) {
      return fail_nv(ErrorCode::conflict, NetError::ssrf_blocked);
    }
  } else if (is_ip_literal(url.host)) {
    if (is_loopback_ip_literal(url.host)) {
      if (!allow_loopback) {
        return fail_nv(ErrorCode::conflict, NetError::ssrf_blocked);
      }
    } else if (is_private_or_special_ip_literal(url.host)) {
      if (!allow_private_network) {
        return fail_nv(ErrorCode::conflict, NetError::ssrf_blocked);
      }
    }
  }

  if (require_pinned_host) {
    bool matched = false;
    for (const auto &pin : allowed_hosts) {
      if (host_matches_pin({url.host, pin})) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      return fail_nv(ErrorCode::conflict, NetError::host_not_allowed);
    }
  }

  return Result<void>::success();
}

Result<void>
AllowedHostPolicy::validate_resolved_address(const sockaddr *addr) const noexcept {
  if (addr == nullptr) {
    return fail_nv(ErrorCode::conflict, NetError::ssrf_blocked);
  }
  if (is_loopback_address(addr)) {
    if (allow_loopback) {
      return Result<void>::success();
    }
    return fail_nv(ErrorCode::conflict, NetError::ssrf_blocked);
  }
  if (is_private_or_special_address(addr)) {
    if (allow_private_network) {
      return Result<void>::success();
    }
    return fail_nv(ErrorCode::conflict, NetError::ssrf_blocked);
  }
  return Result<void>::success();
}

Result<void> AllowedHostPolicy::validate_redirect(RedirectTransition transition) const {
  if (!allow_redirects) {
    return fail_nv(ErrorCode::conflict, NetError::redirect_blocked);
  }
  // Never permit HTTPS -> HTTP downgrade on redirect.
  if (transition.from.scheme == "https" && transition.to.scheme != "https") {
    return fail_nv(ErrorCode::conflict, NetError::redirect_blocked);
  }
  const bool host_changed = !ascii_iequals(transition.from.host, transition.to.host);
  if (host_changed && !allow_cross_host_redirects) {
    return fail_nv(ErrorCode::conflict, NetError::redirect_blocked);
  }
  const auto target_ok = validate_url(transition.to);
  if (!target_ok.has_value()) {
    if (net_error_of(target_ok.error()) == NetError::host_not_allowed ||
        net_error_of(target_ok.error()) == NetError::scheme_not_allowed) {
      return fail_nv(ErrorCode::conflict, NetError::redirect_blocked);
    }
    return target_ok;
  }
  return Result<void>::success();
}

std::string_view http_method_name(HttpMethod method) noexcept {
  switch (method) {
  case HttpMethod::get:
    return "GET";
  case HttpMethod::post:
    return "POST";
  case HttpMethod::put:
    return "PUT";
  case HttpMethod::patch:
    return "PATCH";
  case HttpMethod::del:
    return "DELETE";
  case HttpMethod::head:
    return "HEAD";
  }
  return "GET";
}

Result<HttpMethod> parse_http_method(std::string_view text) noexcept {
  if (ascii_iequals(text, "GET")) {
    return Result<HttpMethod>::success(HttpMethod::get);
  }
  if (ascii_iequals(text, "POST")) {
    return Result<HttpMethod>::success(HttpMethod::post);
  }
  if (ascii_iequals(text, "PUT")) {
    return Result<HttpMethod>::success(HttpMethod::put);
  }
  if (ascii_iequals(text, "PATCH")) {
    return Result<HttpMethod>::success(HttpMethod::patch);
  }
  if (ascii_iequals(text, "DELETE")) {
    return Result<HttpMethod>::success(HttpMethod::del);
  }
  if (ascii_iequals(text, "HEAD")) {
    return Result<HttpMethod>::success(HttpMethod::head);
  }
  return fail_n<HttpMethod>(ErrorCode::invalid_range, NetError::invalid_request);
}

void HttpRequest::set_header(HttpHeader header) {
  remove_header(header.name);
  headers.push_back(std::move(header));
}

void HttpRequest::add_header(HttpHeader header) {
  headers.push_back(std::move(header));
}

void HttpRequest::remove_header(std::string_view name) {
  headers.erase(
      std::remove_if(headers.begin(), headers.end(),
                     [&](const HttpHeader &h) { return ascii_iequals(h.name, name); }),
      headers.end());
}

void HttpRequest::set_body_string(std::string_view text) {
  body.assign(reinterpret_cast<const std::uint8_t *>(text.data()),
              reinterpret_cast<const std::uint8_t *>(text.data()) + text.size());
}

std::optional<std::string_view>
HttpRequest::find_header(std::string_view name) const noexcept {
  for (const auto &hdr : headers) {
    if (ascii_iequals(hdr.name, name)) {
      return hdr.value;
    }
  }
  return std::nullopt;
}

std::string HttpResponse::body_as_string() const {
  return std::string{reinterpret_cast<const char *>(body.data()), body.size()};
}

std::optional<std::string_view>
HttpResponse::find_header(std::string_view name) const noexcept {
  for (const auto &hdr : headers) {
    if (ascii_iequals(hdr.name, name)) {
      return hdr.value;
    }
  }
  return std::nullopt;
}

std::vector<std::string_view>
HttpResponse::find_all_headers(std::string_view name) const {
  std::vector<std::string_view> out;
  for (const auto &hdr : headers) {
    if (ascii_iequals(hdr.name, name)) {
      out.emplace_back(hdr.value);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Incremental SSE parser (WHATWG HTML §9.2.6)
// ---------------------------------------------------------------------------

void SseParser::reset() noexcept {
  line_buf_.clear();
  event_type_.clear();
  data_buf_.clear();
  last_event_id_.clear();
  last_retry_ms_.reset();
  bom_seen_ = 0U;
  bom_checked_ = false;
  pending_lf_ = false;
  has_data_ = false;
  stopped_ = false;
}

Result<void> SseParser::dispatch_event(const EventCallback &on_event) {
  if (!has_data_) {
    event_type_.clear();
    return Result<void>::success();
  }
  SseEvent ev{};
  ev.event = event_type_.empty() ? std::string{"message"} : std::move(event_type_);
  ev.data = std::move(data_buf_);
  ev.id = last_event_id_;
  ev.retry_ms = last_retry_ms_;
  event_type_.clear();
  data_buf_.clear();
  has_data_ = false;

  if (on_event && !on_event(std::move(ev))) {
    stopped_ = true;
  }
  return Result<void>::success();
}

Result<void> SseParser::process_line(std::string_view line,
                                     const EventCallback &on_event) {
  if (line.empty()) {
    return dispatch_event(on_event);
  }
  if (line.front() == ':') {
    return Result<void>::success();
  }
  const std::size_t colon = line.find(':');
  std::string_view field;
  std::string_view value;
  if (colon == std::string_view::npos) {
    field = line;
  } else {
    field = line.substr(0U, colon);
    value = line.substr(colon + 1U);
    if (!value.empty() && value.front() == ' ') {
      value.remove_prefix(1U);
    }
  }

  if (field == "event") {
    if (value.size() > config_.max_event_bytes) {
      return fail_nv(ErrorCode::overflow, NetError::sse_event_too_large);
    }
    event_type_.assign(value.data(), value.size());
  } else if (field == "data") {
    const std::size_t extra = (has_data_ ? 1U : 0U) + value.size();
    if (data_buf_.size() + extra > config_.max_event_bytes) {
      return fail_nv(ErrorCode::overflow, NetError::sse_event_too_large);
    }
    if (has_data_) {
      data_buf_.push_back('\n');
    }
    data_buf_.append(value.data(), value.size());
    has_data_ = true;
  } else if (field == "id") {
    if (value.find('\0') == std::string_view::npos) {
      if (value.size() > config_.max_line_bytes) {
        return fail_nv(ErrorCode::overflow, NetError::sse_event_too_large);
      }
      last_event_id_.assign(value.data(), value.size());
    }
  } else if (field == "retry") {
    if (!value.empty()) {
      bool all_digits = true;
      for (const char ch : value) {
        if (ch < '0' || ch > '9') {
          all_digits = false;
          break;
        }
      }
      if (all_digits) {
        std::uint64_t ms = 0U;
        const auto [ptr, ec] =
            std::from_chars(value.data(), value.data() + value.size(), ms);
        if (ec == std::errc{} && ptr == value.data() + value.size()) {
          last_retry_ms_ = ms;
        }
      }
    }
  }
  return Result<void>::success();
}

Result<void> SseParser::feed(std::span<const std::uint8_t> chunk,
                             const EventCallback &on_event) {
  static constexpr std::array<std::uint8_t, 3> kUtf8Bom = {0xEFU, 0xBBU, 0xBFU};

  for (const std::uint8_t byte : chunk) {
    if (stopped_) {
      return Result<void>::success();
    }
    if (!bom_checked_) {
      if (byte == kUtf8Bom[bom_seen_]) {
        ++bom_seen_;
        if (bom_seen_ == 3U) {
          bom_checked_ = true;
          bom_seen_ = 0U;
        }
        continue;
      }
      bom_checked_ = true;
      if (bom_seen_ > 0U) {
        for (std::size_t i = 0U; i < bom_seen_; ++i) {
          line_buf_.push_back(static_cast<char>(kUtf8Bom[i]));
        }
        bom_seen_ = 0U;
      }
    }

    if (pending_lf_) {
      pending_lf_ = false;
      if (byte == '\n') {
        continue;
      }
    }

    if (byte == '\r') {
      pending_lf_ = true;
      const auto ok = process_line(line_buf_, on_event);
      line_buf_.clear();
      if (!ok.has_value()) {
        return ok;
      }
      continue;
    }
    if (byte == '\n') {
      const auto ok = process_line(line_buf_, on_event);
      line_buf_.clear();
      if (!ok.has_value()) {
        return ok;
      }
      continue;
    }

    if (line_buf_.size() >= config_.max_line_bytes) {
      return fail_nv(ErrorCode::overflow, NetError::sse_event_too_large);
    }
    line_buf_.push_back(static_cast<char>(byte));
  }
  return Result<void>::success();
}

Result<void> SseParser::feed(std::string_view chunk, const EventCallback &on_event) {
  return feed(
      std::span<const std::uint8_t>{
          reinterpret_cast<const std::uint8_t *>(chunk.data()), chunk.size()},
      on_event);
}

Result<void> SseParser::finish(const EventCallback &on_event) {
  (void)on_event;
  // Per WHATWG HTML §9.2.6, EOF discards any incomplete/unterminated event block.
  line_buf_.clear();
  event_type_.clear();
  data_buf_.clear();
  has_data_ = false;
  pending_lf_ = false;
  return Result<void>::success();
}

// ---------------------------------------------------------------------------
// HttpClient
// ---------------------------------------------------------------------------

HttpClient::HttpClient(HttpClientConfig config) : config_(std::move(config)) {}

Result<HttpResponse> HttpClient::request(const HttpRequest &req) const {
  return execute_http_request(config_, req, nullptr, {});
}

Result<HttpResponse> HttpClient::stream_sse(const HttpRequest &req,
                                            const SseParser::EventCallback &on_event,
                                            SseParserConfig sse_config) const {
  return execute_http_request(config_, req, &on_event, sse_config);
}

} // namespace blackbird::net
