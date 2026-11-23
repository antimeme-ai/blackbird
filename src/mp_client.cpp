#include "blackbird/mp_client.hpp"

#include "blackbird/json.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
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
#include <sys/stat.h>
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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

namespace blackbird::mp {

namespace {

constexpr std::string_view kWsAcceptGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr std::array<unsigned char, 9> kAlpnHttp11 = {8U,  'h', 't', 't', 'p',
                                                      '/', '1', '.', '1'};
constexpr const char *kDeviceSeedFile = "device.seed";
constexpr const char *kRootSeedFile = "root.seed";
constexpr const char *kDeviceCwtFile = "device.cwt";
constexpr const char *kIdentityMetaFile = "identity.json";
constexpr std::size_t kMaxIdentityJsonBytes = 16U * 1024U;
constexpr std::size_t kMaxWsFramePayload = kMaxMp1FrameBytes;
constexpr std::size_t kMaxWsControlPayload = 125U;
constexpr std::size_t kMaxWsFragmentsPerMessage = 64U;
constexpr std::uint64_t kMinValidServerNowMs = 1000U;
constexpr std::int64_t kClockSkewHeuristicSecs = 30;

std::atomic<std::uint64_t> g_tmp_seq{0U};

template <typename T> Result<T> fail_c(ErrorCode code, MpClientError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_cv(ErrorCode code, MpClientError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

std::int64_t current_unix_seconds() noexcept {
  const auto now = std::chrono::system_clock::now();
  return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
      .count();
}

constexpr std::optional<std::int64_t> checked_add_i64(std::int64_t lhs,
                                                      std::int64_t rhs) noexcept {
  std::int64_t out = 0;
  if (__builtin_add_overflow(lhs, rhs, &out)) {
    return std::nullopt;
  }
  return out;
}

constexpr std::optional<std::int64_t> checked_sub_i64(std::int64_t lhs,
                                                      std::int64_t rhs) noexcept {
  std::int64_t out = 0;
  if (__builtin_sub_overflow(lhs, rhs, &out)) {
    return std::nullopt;
  }
  return out;
}

struct SigningWindow {
  std::int64_t now_s = 0;
  std::int64_t created = 0;
  std::int64_t expires = 0;
};

Result<SigningWindow> compute_signing_window(std::int64_t clock_offset_s) noexcept {
  const auto now_s = checked_add_i64(current_unix_seconds(), clock_offset_s);
  if (!now_s.has_value()) {
    return fail_c<SigningWindow>(ErrorCode::invalid_range,
                                 MpClientError::invalid_config);
  }
  const auto created = checked_sub_i64(*now_s, 5);
  const auto expires = checked_add_i64(*now_s, 55);
  if (!created.has_value() || !expires.has_value() || *created < 0) {
    return fail_c<SigningWindow>(ErrorCode::invalid_range,
                                 MpClientError::invalid_config);
  }
  return Result<SigningWindow>::success(SigningWindow{*now_s, *created, *expires});
}

struct CleanseStringGuard {
  std::string &text;
  ~CleanseStringGuard() {
    if (!text.empty()) {
      OPENSSL_cleanse(text.data(), text.size());
    }
  }
};

using SteadyClock = std::chrono::steady_clock;

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
// RAII wrappers (fd, addrinfo, SSL_CTX, SSL, X509, cleansed byte vector)
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
  int release() noexcept { return std::exchange(fd_, -1); }
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

struct CleanseSpanGuard {
  std::span<std::uint8_t> bytes;
  ~CleanseSpanGuard() {
    if (!bytes.empty()) {
      OPENSSL_cleanse(bytes.data(), bytes.size());
    }
  }
};

struct CleanseVectorGuard {
  std::vector<std::uint8_t> &bytes;
  ~CleanseVectorGuard() {
    if (!bytes.empty()) {
      OPENSSL_cleanse(bytes.data(), bytes.size());
    }
  }
};

#ifndef SO_NOSIGPIPE
// Thread-scoped SIGPIPE block + drain for OpenSSL socket I/O on platforms
// without SO_NOSIGPIPE (e.g. Linux), without mutating process signal handlers.
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
// ASCII / Base64 / SHA-1 helpers
// ---------------------------------------------------------------------------

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

std::string_view trim_ows(std::string_view text) noexcept {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
    text.remove_prefix(1U);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
    text.remove_suffix(1U);
  }
  return text;
}

bool contains_ctl_or_crlf(std::string_view text) noexcept {
  for (const char ch : text) {
    const auto byte = static_cast<std::uint8_t>(ch);
    if (byte < 0x20U || byte == 0x7fU) {
      return true;
    }
  }
  return false;
}

std::string base64_encode(std::span<const std::uint8_t> bytes) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((bytes.size() + 2U) / 3U) * 4U);
  std::size_t i = 0U;
  while (i + 3U <= bytes.size()) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                                 (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                                 static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
    out.push_back(kAlphabet[triple & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1U) {
    const std::uint32_t triple = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                                 (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

std::optional<std::uint8_t> base64_val(char ch) noexcept {
  if (ch >= 'A' && ch <= 'Z') {
    return static_cast<std::uint8_t>(ch - 'A');
  }
  if (ch >= 'a' && ch <= 'z') {
    return static_cast<std::uint8_t>(ch - 'a' + 26);
  }
  if (ch >= '0' && ch <= '9') {
    return static_cast<std::uint8_t>(ch - '0' + 52);
  }
  if (ch == '+') {
    return 62U;
  }
  if (ch == '/') {
    return 63U;
  }
  return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> base64_decode(std::string_view text) {
  if (text.empty()) {
    return std::vector<std::uint8_t>{};
  }
  if ((text.size() % 4U) != 0U) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> out;
  out.reserve((text.size() / 4U) * 3U);
  for (std::size_t i = 0U; i < text.size(); i += 4U) {
    const bool is_last = (i + 4U == text.size());
    const auto v0 = base64_val(text[i]);
    const auto v1 = base64_val(text[i + 1U]);
    if (!v0.has_value() || !v1.has_value()) {
      return std::nullopt;
    }
    const char c2 = text[i + 2U];
    const char c3 = text[i + 3U];
    if (c2 == '=' && c3 == '=') {
      if (!is_last || (*v1 & 0x0fU) != 0U) {
        return std::nullopt;
      }
      out.push_back(static_cast<std::uint8_t>((*v0 << 2U) | (*v1 >> 4U)));
      continue;
    }
    const auto v2 = base64_val(c2);
    if (!v2.has_value()) {
      return std::nullopt;
    }
    if (c3 == '=') {
      if (!is_last || (*v2 & 0x03U) != 0U) {
        return std::nullopt;
      }
      out.push_back(static_cast<std::uint8_t>((*v0 << 2U) | (*v1 >> 4U)));
      out.push_back(static_cast<std::uint8_t>(((*v1 & 0x0fU) << 4U) | (*v2 >> 2U)));
      continue;
    }
    const auto v3 = base64_val(c3);
    if (!v3.has_value()) {
      return std::nullopt;
    }
    out.push_back(static_cast<std::uint8_t>((*v0 << 2U) | (*v1 >> 4U)));
    out.push_back(static_cast<std::uint8_t>(((*v1 & 0x0fU) << 4U) | (*v2 >> 2U)));
    out.push_back(static_cast<std::uint8_t>(((*v2 & 0x03U) << 6U) | *v3));
  }
  return out;
}

Result<std::string> compute_ws_accept(std::string_view ws_key) {
  std::string input;
  input.reserve(ws_key.size() + kWsAcceptGuid.size());
  input.append(ws_key);
  input.append(kWsAcceptGuid);
  std::array<unsigned char, 20> digest{};
  unsigned int digest_len = 0U;
  if (EVP_Digest(input.data(), input.size(), digest.data(), &digest_len, EVP_sha1(),
                 nullptr) != 1 ||
      digest_len != digest.size()) {
    return fail_c<std::string>(ErrorCode::provider_transport,
                               MpClientError::tls_init_failed);
  }
  return Result<std::string>::success(
      base64_encode(std::span<const std::uint8_t>{digest.data(), digest.size()}));
}

bool is_ip_literal(const std::string &host) noexcept {
  in_addr v4{};
  if (::inet_pton(AF_INET, host.c_str(), &v4) == 1) {
    return true;
  }
  in6_addr v6{};
  return ::inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

Result<std::string> extract_tls_hostname(std::string_view authority) {
  if (authority.empty() || authority.size() > 256U || contains_ctl_or_crlf(authority) ||
      authority.find(' ') != std::string_view::npos ||
      authority.find('/') != std::string_view::npos ||
      authority.find('@') != std::string_view::npos) {
    return fail_c<std::string>(ErrorCode::invalid_identity,
                               MpClientError::invalid_config);
  }
  if (authority.front() == '[') {
    const std::size_t close = authority.find(']');
    if (close == std::string_view::npos || close <= 1U) {
      return fail_c<std::string>(ErrorCode::invalid_identity,
                                 MpClientError::invalid_config);
    }
    return Result<std::string>::success(std::string{authority.substr(1U, close - 1U)});
  }
  const std::size_t colon = authority.rfind(':');
  if (colon != std::string_view::npos) {
    if (colon == 0U) {
      return fail_c<std::string>(ErrorCode::invalid_identity,
                                 MpClientError::invalid_config);
    }
    return Result<std::string>::success(std::string{authority.substr(0U, colon)});
  }
  return Result<std::string>::success(std::string{authority});
}

// ---------------------------------------------------------------------------
// Local keystore filesystem primitives (0700 dir, 0600 files, O_NOFOLLOW)
// ---------------------------------------------------------------------------

Result<void> validate_keystore_path(const std::filesystem::path &dir) {
  const std::string raw = dir.string();
  if (raw.empty() || raw.find('\0') != std::string::npos) {
    return fail_cv(ErrorCode::invalid_range, MpClientError::keystore_invalid_path);
  }
  for (const auto &part : dir) {
    if (part == "..") {
      return fail_cv(ErrorCode::invalid_range, MpClientError::keystore_invalid_path);
    }
  }
  return Result<void>::success();
}

Result<void> check_dir_mode(int fd) noexcept {
  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
  }
  if (!S_ISDIR(st.st_mode)) {
    return fail_cv(ErrorCode::io, MpClientError::keystore_invalid_path);
  }
  if (st.st_uid != ::geteuid() || (st.st_mode & 0077U) != 0U) {
    return fail_cv(ErrorCode::io, MpClientError::keystore_insecure_permissions);
  }
  return Result<void>::success();
}

Result<void> check_file_mode(int fd) noexcept {
  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
  }
  if (!S_ISREG(st.st_mode) || st.st_nlink != 1U) {
    return fail_cv(ErrorCode::io, MpClientError::keystore_symlink_rejected);
  }
  if (st.st_uid != ::geteuid() || (st.st_mode & 0077U) != 0U) {
    return fail_cv(ErrorCode::io, MpClientError::keystore_insecure_permissions);
  }
  return Result<void>::success();
}

Result<void> fsync_fd(int fd) noexcept {
  while (::fsync(fd) != 0) {
    if (errno == EINTR) {
      continue;
    }
    return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
  }
  return Result<void>::success();
}

Result<ScopedFd> open_keystore_dir(const std::filesystem::path &dir, bool create,
                                   std::filesystem::path &normalized_dir) {
  if (const auto ok = validate_keystore_path(dir); !ok.has_value()) {
    return Result<ScopedFd>::failure(ok.error());
  }
  std::string path_str = dir.string();
  while (path_str.size() > 1U && path_str.back() == '/') {
    path_str.pop_back();
  }

  // Reject symlink at the leaf directory before creating or opening.
  struct stat lst{};
  if (::lstat(path_str.c_str(), &lst) == 0) {
    if (S_ISLNK(lst.st_mode)) {
      return fail_c<ScopedFd>(ErrorCode::io, MpClientError::keystore_symlink_rejected);
    }
  } else if (errno != ENOENT) {
    return fail_c<ScopedFd>(ErrorCode::io, MpClientError::keystore_io_failed);
  }

  bool created = false;
  if (create) {
    if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
      created = true;
    } else if (errno == ENOENT) {
      const auto parent = std::filesystem::path{path_str}.parent_path();
      if (!parent.empty()) {
        std::error_code ec;
        (void)std::filesystem::create_directories(parent, ec);
        if (ec) {
          return fail_c<ScopedFd>(ErrorCode::io, MpClientError::keystore_io_failed);
        }
      }
      if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
        created = true;
      } else if (errno != EEXIST) {
        return fail_c<ScopedFd>(ErrorCode::io, MpClientError::keystore_io_failed);
      }
    } else if (errno != EEXIST) {
      return fail_c<ScopedFd>(ErrorCode::io, MpClientError::keystore_io_failed);
    }
  }

  int fd = -1;
  do {
    fd = ::open(path_str.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ENOENT) {
      return fail_c<ScopedFd>(ErrorCode::io, MpClientError::keystore_not_found);
    }
    if (errno == ELOOP || errno == ENOTDIR) {
      return fail_c<ScopedFd>(ErrorCode::io, MpClientError::keystore_symlink_rejected);
    }
    return fail_c<ScopedFd>(ErrorCode::io, MpClientError::keystore_io_failed);
  }
  ScopedFd owned{fd};

  if (created && ::fchmod(owned.get(), mode_t{0700}) != 0) {
    return fail_c<ScopedFd>(ErrorCode::io, MpClientError::keystore_io_failed);
  }
  if (const auto ok = check_dir_mode(owned.get()); !ok.has_value()) {
    return Result<ScopedFd>::failure(ok.error());
  }
  normalized_dir = std::filesystem::path{std::move(path_str)};
  return Result<ScopedFd>::success(std::move(owned));
}

struct ReadFileBytes {
  bool exists = false;
  std::vector<std::uint8_t> bytes;
};

Result<ReadFileBytes> read_file_bounded(int dir_fd, const char *name,
                                        std::size_t max_bytes) {
  int fd = -1;
  do {
    fd = ::openat(dir_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ENOENT) {
      return Result<ReadFileBytes>::success(ReadFileBytes{false, {}});
    }
    if (errno == ELOOP) {
      return fail_c<ReadFileBytes>(ErrorCode::io,
                                   MpClientError::keystore_symlink_rejected);
    }
    return fail_c<ReadFileBytes>(ErrorCode::io, MpClientError::keystore_io_failed);
  }
  ScopedFd owned{fd};
  if (const auto ok = check_file_mode(owned.get()); !ok.has_value()) {
    return Result<ReadFileBytes>::failure(ok.error());
  }

  std::vector<std::uint8_t> buf;
  std::array<std::uint8_t, 4096> chunk{};
  CleanseSpanGuard chunk_guard{chunk};
  for (;;) {
    const ssize_t n = ::read(owned.get(), chunk.data(), chunk.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (!buf.empty()) {
        OPENSSL_cleanse(buf.data(), buf.size());
      }
      return fail_c<ReadFileBytes>(ErrorCode::io, MpClientError::keystore_io_failed);
    }
    if (n == 0) {
      break;
    }
    const auto got = static_cast<std::size_t>(n);
    if (buf.size() + got > max_bytes) {
      if (!buf.empty()) {
        OPENSSL_cleanse(buf.data(), buf.size());
      }
      return fail_c<ReadFileBytes>(ErrorCode::corrupt, MpClientError::keystore_corrupt);
    }
    buf.insert(buf.end(), chunk.begin(),
               chunk.begin() + static_cast<std::ptrdiff_t>(got));
  }
  return Result<ReadFileBytes>::success(ReadFileBytes{true, std::move(buf)});
}

Result<void> write_file_atomic_0600(int dir_fd, const char *name,
                                    std::span<const std::uint8_t> data) {
  const std::uint64_t seq = g_tmp_seq.fetch_add(1U, std::memory_order_relaxed);
  const std::string tmp_name = std::string{"."} + name + ".tmp." + std::to_string(seq) +
                               "." +
                               std::to_string(static_cast<std::uint64_t>(::getpid()));

  int fd = -1;
  do {
    fd = ::openat(dir_fd, tmp_name.c_str(),
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t{0600});
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
  }
  ScopedFd owned{fd};

  auto cleanup_tmp = [&]() noexcept {
    owned.reset();
    (void)::unlinkat(dir_fd, tmp_name.c_str(), 0);
  };

  if (::fchmod(owned.get(), mode_t{0600}) != 0) {
    cleanup_tmp();
    return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
  }

  std::size_t offset = 0U;
  while (offset < data.size()) {
    const ssize_t written =
        ::write(owned.get(), data.data() + offset, data.size() - offset);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      cleanup_tmp();
      return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
    }
    if (written == 0) {
      cleanup_tmp();
      return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
    }
    offset += static_cast<std::size_t>(written);
  }

  if (const auto ok = fsync_fd(owned.get()); !ok.has_value()) {
    cleanup_tmp();
    return ok;
  }
  owned.reset();

  if (::renameat(dir_fd, tmp_name.c_str(), dir_fd, name) != 0) {
    (void)::unlinkat(dir_fd, tmp_name.c_str(), 0);
    return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
  }
  return fsync_fd(dir_fd);
}

// ---------------------------------------------------------------------------
// JSON extraction helpers over blackbird::Value
// ---------------------------------------------------------------------------

Result<std::uint64_t> value_as_u64(const Value &v) {
  const auto *num = std::get_if<Number>(&v.value());
  if (num == nullptr) {
    return fail_c<std::uint64_t>(ErrorCode::corrupt,
                                 MpClientError::http_response_schema);
  }
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage())) {
    return Result<std::uint64_t>::success(*u);
  }
  if (const auto *i = std::get_if<std::int64_t>(&num->storage())) {
    if (*i < 0) {
      return fail_c<std::uint64_t>(ErrorCode::corrupt,
                                   MpClientError::http_response_schema);
    }
    return Result<std::uint64_t>::success(static_cast<std::uint64_t>(*i));
  }
  return fail_c<std::uint64_t>(ErrorCode::corrupt, MpClientError::http_response_schema);
}

Result<bool> value_as_bool_or_flag(const Value &v) {
  if (const auto *b = std::get_if<bool>(&v.value())) {
    return Result<bool>::success(*b);
  }
  const auto u = value_as_u64(v);
  if (u.has_value() && (u.value() == 0U || u.value() == 1U)) {
    return Result<bool>::success(u.value() == 1U);
  }
  return fail_c<bool>(ErrorCode::corrupt, MpClientError::http_response_schema);
}

Result<std::string> get_required_string(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (field == nullptr) {
    return fail_c<std::string>(ErrorCode::corrupt, MpClientError::http_response_schema);
  }
  const auto *s = std::get_if<std::string>(&field->value());
  if (s == nullptr) {
    return fail_c<std::string>(ErrorCode::corrupt, MpClientError::http_response_schema);
  }
  return Result<std::string>::success(*s);
}

Result<std::uint64_t> get_required_u64(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (field == nullptr) {
    return fail_c<std::uint64_t>(ErrorCode::corrupt,
                                 MpClientError::http_response_schema);
  }
  return value_as_u64(*field);
}

Result<Ed25519PubKey> get_required_pubkey_b64(const Value &obj, std::string_view key) {
  const auto b64 = get_required_string(obj, key);
  if (!b64.has_value()) {
    return Result<Ed25519PubKey>::failure(b64.error());
  }
  const auto decoded = base64_decode(b64.value());
  if (!decoded.has_value() || decoded->size() != 32U) {
    return fail_c<Ed25519PubKey>(ErrorCode::corrupt,
                                 MpClientError::http_response_schema);
  }
  Ed25519PubKey pk{};
  std::memcpy(pk.data(), decoded->data(), pk.size());
  if (const auto valid = validate_ed25519_pubkey_strict(pk); !valid.has_value()) {
    return Result<Ed25519PubKey>::failure(valid.error());
  }
  return Result<Ed25519PubKey>::success(pk);
}

Result<Value> parse_json_object_body(std::string_view body) {
  ValueLimits limits{};
  limits.bytes = kMaxHttpBodyBytes;
  limits.nodes = 32768U;
  limits.depth = 32U;
  auto parsed = parse_json(body, limits);
  if (!parsed.has_value()) {
    return fail_c<Value>(ErrorCode::corrupt, MpClientError::http_json_invalid);
  }
  if (!std::holds_alternative<Value::Object>(parsed.value().value())) {
    return fail_c<Value>(ErrorCode::corrupt, MpClientError::http_response_schema);
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// TLS 1.3 connection (non-blocking socket + poll() + OpenSSL 3 libssl)
// ---------------------------------------------------------------------------

struct PollWaitRequest {
  int fd = -1;
  short events = 0;
  SteadyClock::time_point deadline{};
};

Result<void> wait_socket_ready(const PollWaitRequest &req) noexcept {
  for (;;) {
    const int timeout = remaining_timeout_ms(req.deadline);
    if (timeout == 0) {
      return fail_cv(ErrorCode::provider_transport, MpClientError::timeout);
    }
    pollfd pfd{};
    pfd.fd = req.fd;
    pfd.events = req.events;
    const int rc = ::poll(&pfd, 1U, timeout);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      return fail_cv(ErrorCode::provider_transport, MpClientError::tls_io_failed);
    }
    if (rc == 0) {
      return fail_cv(ErrorCode::provider_transport, MpClientError::timeout);
    }
    return Result<void>::success();
  }
}

Result<ScopedFd> tcp_connect_bounded(const std::string &host, std::uint16_t port,
                                     int timeout_ms) {
  if (host.empty() || port == 0U || timeout_ms <= 0) {
    return fail_c<ScopedFd>(ErrorCode::invalid_range, MpClientError::invalid_config);
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  const std::string port_str = std::to_string(port);
  addrinfo *raw_res = nullptr;
  if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &raw_res) != 0 ||
      raw_res == nullptr) {
    return fail_c<ScopedFd>(ErrorCode::provider_transport, MpClientError::dns_failed);
  }
  UniqueAddrInfo res{raw_res};

  const auto deadline = SteadyClock::now() + std::chrono::milliseconds{timeout_ms};
  MpClientError last_err = MpClientError::connect_failed;

  for (const addrinfo *ai = res.get(); ai != nullptr; ai = ai->ai_next) {
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
      last_err = MpClientError::connect_failed;
      continue;
    }

    const auto ready = wait_socket_ready({owned.get(), POLLOUT, deadline});
    if (!ready.has_value()) {
      last_err = mp_client_error_of(ready.error());
      continue;
    }
    int so_err = 0;
    socklen_t so_len = sizeof(so_err);
    if (::getsockopt(owned.get(), SOL_SOCKET, SO_ERROR, &so_err, &so_len) != 0 ||
        so_err != 0) {
      last_err = MpClientError::connect_failed;
      continue;
    }
    return Result<ScopedFd>::success(std::move(owned));
  }

  return fail_c<ScopedFd>(ErrorCode::provider_transport, last_err);
}

class TlsConnection {
public:
  static Result<TlsConnection> connect(const MpClientConfig &config) {
    if (config.port == 0U || config.connect_timeout_ms <= 0 ||
        config.io_timeout_ms <= 0) {
      return fail_c<TlsConnection>(ErrorCode::invalid_range,
                                   MpClientError::invalid_config);
    }
    const auto tls_host_res = extract_tls_hostname(config.authority);
    if (!tls_host_res.has_value()) {
      return Result<TlsConnection>::failure(tls_host_res.error());
    }
    const std::string &tls_host = tls_host_res.value();
    const std::string &tcp_host =
        config.connect_host.empty() ? tls_host : config.connect_host;

    UniqueSslCtx ctx{SSL_CTX_new(TLS_client_method())};
    if (!ctx) {
      return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                   MpClientError::tls_init_failed);
    }
    if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1) {
      return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                   MpClientError::tls_init_failed);
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

    if (config.ca_bundle_path.has_value()) {
      const std::string ca_path = config.ca_bundle_path->string();
      if (ca_path.empty() ||
          SSL_CTX_load_verify_locations(ctx.get(), ca_path.c_str(), nullptr) != 1) {
        return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                     MpClientError::tls_ca_load_failed);
      }
    } else {
      const bool default_ok = SSL_CTX_set_default_verify_paths(ctx.get()) == 1;
#if defined(__APPLE__)
      const bool apple_ok =
          SSL_CTX_load_verify_locations(ctx.get(), "/etc/ssl/cert.pem", nullptr) == 1;
      if (!default_ok && !apple_ok) {
        return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                     MpClientError::tls_ca_load_failed);
      }
#else
      if (!default_ok) {
        return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                     MpClientError::tls_ca_load_failed);
      }
#endif
    }

    if (SSL_CTX_set_alpn_protos(ctx.get(), kAlpnHttp11.data(),
                                static_cast<unsigned int>(kAlpnHttp11.size())) != 0) {
      return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                   MpClientError::tls_init_failed);
    }

    auto fd_res = tcp_connect_bounded(tcp_host, config.port, config.connect_timeout_ms);
    if (!fd_res.has_value()) {
      return Result<TlsConnection>::failure(fd_res.error());
    }
    ScopedFd fd = std::move(fd_res).value();

    UniqueSsl ssl{SSL_new(ctx.get())};
    if (!ssl) {
      return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                   MpClientError::tls_init_failed);
    }
    if (SSL_set_fd(ssl.get(), fd.get()) != 1) {
      return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                   MpClientError::tls_init_failed);
    }

    const bool ip_host = is_ip_literal(tls_host);
    if (!ip_host) {
      if (SSL_ctrl(ssl.get(), SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
                   const_cast<char *>(tls_host.c_str())) != 1) {
        return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                     MpClientError::tls_init_failed);
      }
    }
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl.get());
    if (param == nullptr) {
      return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                   MpClientError::tls_init_failed);
    }
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (ip_host) {
      if (X509_VERIFY_PARAM_set1_ip_asc(param, tls_host.c_str()) != 1) {
        return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                     MpClientError::tls_init_failed);
      }
    } else {
      if (X509_VERIFY_PARAM_set1_host(param, tls_host.c_str(), tls_host.size()) != 1) {
        return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                     MpClientError::tls_init_failed);
      }
    }

    const auto deadline =
        SteadyClock::now() + std::chrono::milliseconds{config.connect_timeout_ms};
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
        const auto wait_res = wait_socket_ready({fd.get(), ev, deadline});
        if (!wait_res.has_value()) {
          return Result<TlsConnection>::failure(wait_res.error());
        }
        continue;
      }
      if (SSL_get_verify_result(ssl.get()) != X509_V_OK) {
        return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                     MpClientError::tls_verify_failed);
      }
      return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                   MpClientError::tls_handshake_failed);
    }

    if (SSL_version(ssl.get()) < TLS1_3_VERSION) {
      return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                   MpClientError::tls_handshake_failed);
    }
    UniqueX509 peer_cert{SSL_get1_peer_certificate(ssl.get())};
    if (!peer_cert || SSL_get_verify_result(ssl.get()) != X509_V_OK) {
      return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                   MpClientError::tls_verify_failed);
    }

    const unsigned char *alpn_proto = nullptr;
    unsigned int alpn_len = 0U;
    SSL_get0_alpn_selected(ssl.get(), &alpn_proto, &alpn_len);
    if (alpn_len > 0U) {
      const std::string_view negotiated{reinterpret_cast<const char *>(alpn_proto),
                                        alpn_len};
      if (negotiated != "http/1.1") {
        return fail_c<TlsConnection>(ErrorCode::provider_transport,
                                     MpClientError::tls_alpn_mismatch);
      }
    }

    return Result<TlsConnection>::success(
        TlsConnection{std::move(ctx), std::move(ssl), std::move(fd)});
  }

  TlsConnection(const TlsConnection &) = delete;
  TlsConnection &operator=(const TlsConnection &) = delete;
  TlsConnection(TlsConnection &&) noexcept = default;
  TlsConnection &operator=(TlsConnection &&) noexcept = default;
  ~TlsConnection() { shutdown_quiet(); }

  int fd() const noexcept { return fd_.get(); }
  bool has_pending() const noexcept { return ssl_ && SSL_pending(ssl_.get()) > 0; }

  Result<void> write_all(std::span<const std::uint8_t> bytes, int timeout_ms) {
    const auto deadline = SteadyClock::now() + std::chrono::milliseconds{timeout_ms};
    std::size_t offset = 0U;
    while (offset < bytes.size()) {
      const std::size_t chunk = std::min<std::size_t>(
          bytes.size() - offset, static_cast<std::size_t>(16U * 1024U));
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
        const auto wait_res = wait_socket_ready({fd_.get(), ev, deadline});
        if (!wait_res.has_value()) {
          return wait_res;
        }
        continue;
      }
      return fail_cv(ErrorCode::provider_transport, MpClientError::tls_io_failed);
    }
    return Result<void>::success();
  }

  // Returns bytes read, 0 on clean TLS EOF, or std::nullopt on non-fatal timeout.
  Result<std::optional<std::size_t>> read_some_until(std::span<std::uint8_t> out,
                                                     SteadyClock::time_point deadline) {
    for (;;) {
      ERR_clear_error();
      int rc = 0;
      {
        const ScopedSigpipeGuard sigpipe_guard;
        rc = SSL_read(ssl_.get(), out.data(), static_cast<int>(out.size()));
      }
      if (rc > 0) {
        return Result<std::optional<std::size_t>>::success(
            static_cast<std::size_t>(rc));
      }
      const int ssl_err = SSL_get_error(ssl_.get(), rc);
      if (ssl_err == SSL_ERROR_ZERO_RETURN) {
        return Result<std::optional<std::size_t>>::success(std::size_t{0U});
      }
      if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
        const int rem = remaining_timeout_ms(deadline);
        if (rem == 0) {
          return Result<std::optional<std::size_t>>::success(std::nullopt);
        }
        const short ev = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
        const auto wait_res = wait_socket_ready({fd_.get(), ev, deadline});
        if (!wait_res.has_value()) {
          if (mp_client_error_of(wait_res.error()) == MpClientError::timeout) {
            return Result<std::optional<std::size_t>>::success(std::nullopt);
          }
          return Result<std::optional<std::size_t>>::failure(wait_res.error());
        }
        continue;
      }
      if (ssl_err == SSL_ERROR_SYSCALL && rc == 0) {
        return Result<std::optional<std::size_t>>::success(std::size_t{0U});
      }
      return fail_c<std::optional<std::size_t>>(ErrorCode::provider_transport,
                                                MpClientError::tls_io_failed);
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
  TlsConnection(UniqueSslCtx ctx, UniqueSsl ssl, ScopedFd fd) noexcept
      : ctx_(std::move(ctx)), ssl_(std::move(ssl)), fd_(std::move(fd)) {}

  UniqueSslCtx ctx_;
  UniqueSsl ssl_;
  ScopedFd fd_;
};

// ---------------------------------------------------------------------------
// HTTP/1.1 parser & REST request engine
// ---------------------------------------------------------------------------

struct HttpHeader {
  std::string name_lower;
  std::string value;
};

struct HttpResponse {
  int status = 0;
  std::vector<HttpHeader> headers;
  std::vector<std::uint8_t> body;
};

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
    return fail_c<ParsedHeaderBlock>(ErrorCode::corrupt,
                                     MpClientError::http_malformed_response);
  }
  const std::string_view block = text.substr(0U, header_end);
  const std::size_t first_eol = block.find("\r\n");
  const std::string_view status_line =
      (first_eol == std::string_view::npos) ? block : block.substr(0U, first_eol);
  if (!status_line.starts_with("HTTP/1.1 ") && !status_line.starts_with("HTTP/1.0 ")) {
    return fail_c<ParsedHeaderBlock>(ErrorCode::corrupt,
                                     MpClientError::http_malformed_response);
  }
  if (status_line.size() < 12U) {
    return fail_c<ParsedHeaderBlock>(ErrorCode::corrupt,
                                     MpClientError::http_malformed_response);
  }
  const std::string_view code_str = status_line.substr(9U, 3U);
  int status = 0;
  const auto [ptr, ec] =
      std::from_chars(code_str.data(), code_str.data() + code_str.size(), status);
  if (ec != std::errc{} || ptr != code_str.data() + code_str.size() || status < 100 ||
      status > 599) {
    return fail_c<ParsedHeaderBlock>(ErrorCode::corrupt,
                                     MpClientError::http_malformed_response);
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
        return fail_c<ParsedHeaderBlock>(ErrorCode::corrupt,
                                         MpClientError::http_malformed_response);
      }
      const std::string_view raw_name = line.substr(0U, colon);
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

Result<void> read_until_headers_complete(TlsConnection &conn,
                                         std::vector<std::uint8_t> &buf,
                                         SteadyClock::time_point deadline) {
  std::array<std::uint8_t, 4096> tmp{};
  for (;;) {
    const std::string_view view{reinterpret_cast<const char *>(buf.data()), buf.size()};
    const std::size_t idx = view.find("\r\n\r\n");
    if (idx != std::string_view::npos) {
      if (idx + 4U > kMaxHttpHeaderBytes) {
        return fail_cv(ErrorCode::overflow, MpClientError::http_header_too_large);
      }
      return Result<void>::success();
    }
    if (buf.size() >= kMaxHttpHeaderBytes) {
      return fail_cv(ErrorCode::overflow, MpClientError::http_header_too_large);
    }
    const auto got = conn.read_some_until(tmp, deadline);
    if (!got.has_value()) {
      return Result<void>::failure(got.error());
    }
    if (!got.value().has_value()) {
      return fail_cv(ErrorCode::provider_transport, MpClientError::timeout);
    }
    if (got.value().value() == 0U) {
      return fail_cv(ErrorCode::provider_transport,
                     MpClientError::http_malformed_response);
    }
    const std::size_t n = got.value().value();
    buf.insert(buf.end(), tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(n));
  }
}

Result<std::vector<std::uint8_t>>
decode_chunked_stream(TlsConnection &conn, std::vector<std::uint8_t> &wire,
                      SteadyClock::time_point deadline) {
  std::vector<std::uint8_t> decoded;
  std::size_t cursor = 0U;
  std::array<std::uint8_t, 4096> tmp{};

  auto ensure_bytes = [&](std::size_t needed) -> Result<void> {
    while (wire.size() - cursor < needed) {
      if (cursor > 4096U) {
        wire.erase(wire.begin(), wire.begin() + static_cast<std::ptrdiff_t>(cursor));
        cursor = 0U;
      }
      if (wire.size() - cursor > kMaxHttpBodyBytes + kMaxHttpHeaderBytes) {
        return fail_cv(ErrorCode::overflow, MpClientError::http_body_too_large);
      }
      const auto got = conn.read_some_until(tmp, deadline);
      if (!got.has_value()) {
        return Result<void>::failure(got.error());
      }
      if (!got.value().has_value()) {
        return fail_cv(ErrorCode::provider_transport, MpClientError::timeout);
      }
      if (got.value().value() == 0U) {
        return fail_cv(ErrorCode::corrupt, MpClientError::http_chunked_malformed);
      }
      wire.insert(wire.end(), tmp.begin(),
                  tmp.begin() + static_cast<std::ptrdiff_t>(got.value().value()));
    }
    return Result<void>::success();
  };

  auto read_crlf_line = [&](std::size_t max_line) -> Result<std::string> {
    for (;;) {
      const std::string_view avail{reinterpret_cast<const char *>(wire.data() + cursor),
                                   wire.size() - cursor};
      const std::size_t pos = avail.find("\r\n");
      if (pos != std::string_view::npos) {
        if (pos > max_line) {
          return fail_c<std::string>(ErrorCode::corrupt,
                                     MpClientError::http_chunked_malformed);
        }
        std::string line{avail.substr(0U, pos)};
        cursor += pos + 2U;
        return Result<std::string>::success(std::move(line));
      }
      if (avail.size() > max_line) {
        return fail_c<std::string>(ErrorCode::corrupt,
                                   MpClientError::http_chunked_malformed);
      }
      const auto more = ensure_bytes(avail.size() + 1U);
      if (!more.has_value()) {
        return Result<std::string>::failure(more.error());
      }
    }
  };

  for (;;) {
    const auto size_line = read_crlf_line(128U);
    if (!size_line.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(size_line.error());
    }
    std::string_view hex_part = size_line.value();
    const std::size_t semi = hex_part.find(';');
    if (semi != std::string_view::npos) {
      hex_part = hex_part.substr(0U, semi);
    }
    hex_part = trim_ows(hex_part);
    if (hex_part.empty() || hex_part.size() > 16U) {
      return fail_c<std::vector<std::uint8_t>>(ErrorCode::corrupt,
                                               MpClientError::http_chunked_malformed);
    }
    std::uint64_t chunk_len = 0U;
    const auto [ptr, ec] = std::from_chars(
        hex_part.data(), hex_part.data() + hex_part.size(), chunk_len, 16);
    if (ec != std::errc{} || ptr != hex_part.data() + hex_part.size()) {
      return fail_c<std::vector<std::uint8_t>>(ErrorCode::corrupt,
                                               MpClientError::http_chunked_malformed);
    }
    if (chunk_len == 0U) {
      // Drain optional trailers until empty CRLF line, capped at header budget.
      std::size_t trailer_bytes = 0U;
      for (;;) {
        const auto trailer = read_crlf_line(kMaxHttpHeaderBytes);
        if (!trailer.has_value()) {
          return Result<std::vector<std::uint8_t>>::failure(trailer.error());
        }
        if (trailer.value().empty()) {
          break;
        }
        trailer_bytes += trailer.value().size() + 2U;
        if (trailer_bytes > kMaxHttpHeaderBytes) {
          return fail_c<std::vector<std::uint8_t>>(
              ErrorCode::overflow, MpClientError::http_header_too_large);
        }
      }
      return Result<std::vector<std::uint8_t>>::success(std::move(decoded));
    }
    if (chunk_len > kMaxHttpBodyBytes ||
        decoded.size() + chunk_len > kMaxHttpBodyBytes) {
      return fail_c<std::vector<std::uint8_t>>(ErrorCode::overflow,
                                               MpClientError::http_body_too_large);
    }
    const auto chunk_sz = static_cast<std::size_t>(chunk_len);
    if (const auto ok = ensure_bytes(chunk_sz + 2U); !ok.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(ok.error());
    }
    decoded.insert(decoded.end(), wire.begin() + static_cast<std::ptrdiff_t>(cursor),
                   wire.begin() + static_cast<std::ptrdiff_t>(cursor + chunk_sz));
    cursor += chunk_sz;
    if (wire[cursor] != '\r' || wire[cursor + 1U] != '\n') {
      return fail_c<std::vector<std::uint8_t>>(ErrorCode::corrupt,
                                               MpClientError::http_chunked_malformed);
    }
    cursor += 2U;
  }
}

struct RawHttpRequest {
  HttpMethod method = HttpMethod::get;
  std::string path;
  std::string query = "?";
  std::vector<std::pair<std::string, std::string>> headers;
  std::vector<std::uint8_t> body;
};

Result<std::vector<std::uint8_t>>
read_http_response_body(TlsConnection &conn, const ParsedHeaderBlock &parsed_hdr,
                        std::vector<std::uint8_t> trailing,
                        SteadyClock::time_point deadline) {
  bool is_chunked = false;
  std::size_t te_coding_count = 0U;
  std::optional<std::size_t> content_length;

  for (const auto &hdr : parsed_hdr.headers) {
    if (hdr.name_lower == "transfer-encoding") {
      std::size_t pos = 0U;
      while (pos <= hdr.value.size()) {
        const std::size_t comma = hdr.value.find(',', pos);
        const std::string_view part =
            (comma == std::string_view::npos)
                ? std::string_view{hdr.value}.substr(pos)
                : std::string_view{hdr.value}.substr(pos, comma - pos);
        const std::string coding = ascii_lower(trim_ows(part));
        if (coding != "chunked" || te_coding_count > 0U) {
          return fail_c<std::vector<std::uint8_t>>(
              ErrorCode::corrupt, MpClientError::http_malformed_response);
        }
        is_chunked = true;
        ++te_coding_count;
        if (comma == std::string_view::npos) {
          break;
        }
        pos = comma + 1U;
      }
    } else if (hdr.name_lower == "content-encoding") {
      const std::string ce = ascii_lower(trim_ows(hdr.value));
      if (ce != "identity") {
        return fail_c<std::vector<std::uint8_t>>(
            ErrorCode::corrupt, MpClientError::http_malformed_response);
      }
    } else if (hdr.name_lower == "content-length") {
      std::uint64_t cl = 0U;
      const auto [ptr, ec] =
          std::from_chars(hdr.value.data(), hdr.value.data() + hdr.value.size(), cl);
      if (ec != std::errc{} || ptr != hdr.value.data() + hdr.value.size()) {
        return fail_c<std::vector<std::uint8_t>>(
            ErrorCode::corrupt, MpClientError::http_malformed_response);
      }
      if (cl > kMaxHttpBodyBytes) {
        return fail_c<std::vector<std::uint8_t>>(ErrorCode::overflow,
                                                 MpClientError::http_body_too_large);
      }
      if (content_length.has_value() &&
          *content_length != static_cast<std::size_t>(cl)) {
        return fail_c<std::vector<std::uint8_t>>(
            ErrorCode::corrupt, MpClientError::http_malformed_response);
      }
      content_length = static_cast<std::size_t>(cl);
    }
  }

  // RFC 9112 §6.3: reject messages containing both Transfer-Encoding and
  // Content-Length.
  if (is_chunked && content_length.has_value()) {
    return fail_c<std::vector<std::uint8_t>>(ErrorCode::corrupt,
                                             MpClientError::http_malformed_response);
  }

  if (parsed_hdr.status == 204 || parsed_hdr.status == 304 ||
      (parsed_hdr.status >= 100 && parsed_hdr.status < 200)) {
    return Result<std::vector<std::uint8_t>>::success({});
  }
  if (is_chunked) {
    return decode_chunked_stream(conn, trailing, deadline);
  }
  if (content_length.has_value()) {
    const std::size_t need = *content_length;
    if (trailing.size() > need) {
      trailing.resize(need);
    }
    std::vector<std::uint8_t> body = std::move(trailing);
    body.reserve(need);
    std::array<std::uint8_t, 4096> tmp{};
    while (body.size() < need) {
      const std::size_t rem = need - body.size();
      const auto got = conn.read_some_until(
          std::span<std::uint8_t>{tmp.data(), std::min(rem, tmp.size())}, deadline);
      if (!got.has_value()) {
        return Result<std::vector<std::uint8_t>>::failure(got.error());
      }
      if (!got.value().has_value()) {
        return fail_c<std::vector<std::uint8_t>>(ErrorCode::provider_transport,
                                                 MpClientError::timeout);
      }
      if (got.value().value() == 0U) {
        return fail_c<std::vector<std::uint8_t>>(
            ErrorCode::corrupt, MpClientError::http_malformed_response);
      }
      body.insert(body.end(), tmp.begin(),
                  tmp.begin() + static_cast<std::ptrdiff_t>(got.value().value()));
    }
    return Result<std::vector<std::uint8_t>>::success(std::move(body));
  }

  std::vector<std::uint8_t> body = std::move(trailing);
  if (body.size() > kMaxHttpBodyBytes) {
    return fail_c<std::vector<std::uint8_t>>(ErrorCode::overflow,
                                             MpClientError::http_body_too_large);
  }
  std::array<std::uint8_t, 4096> tmp{};
  for (;;) {
    const auto got = conn.read_some_until(tmp, deadline);
    if (!got.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(got.error());
    }
    if (!got.value().has_value()) {
      return fail_c<std::vector<std::uint8_t>>(ErrorCode::provider_transport,
                                               MpClientError::timeout);
    }
    const std::size_t n = got.value().value();
    if (n == 0U) {
      break;
    }
    if (body.size() + n > kMaxHttpBodyBytes) {
      return fail_c<std::vector<std::uint8_t>>(ErrorCode::overflow,
                                               MpClientError::http_body_too_large);
    }
    body.insert(body.end(), tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(n));
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(body));
}

Result<HttpResponse> execute_http_once(const MpClientConfig &config,
                                       const RawHttpRequest &req) {
  auto conn_res = TlsConnection::connect(config);
  if (!conn_res.has_value()) {
    return Result<HttpResponse>::failure(conn_res.error());
  }
  TlsConnection conn = std::move(conn_res).value();

  std::string target = req.path;
  if (req.query.size() > 1U) {
    target.append(req.query);
  }
  if (contains_ctl_or_crlf(target) || contains_ctl_or_crlf(config.authority)) {
    return fail_c<HttpResponse>(ErrorCode::invalid_identity,
                                MpClientError::invalid_config);
  }

  std::string wire;
  CleanseStringGuard wire_cleanse{wire};
  wire.reserve(512U + req.body.size());
  wire.append(http_method_name(req.method));
  wire.push_back(' ');
  wire.append(target);
  wire.append(" HTTP/1.1\r\nHost: ");
  wire.append(config.authority);
  wire.append("\r\nConnection: close\r\nAccept-Encoding: identity\r\n");
  for (const auto &[k, v] : req.headers) {
    if (contains_ctl_or_crlf(k) || contains_ctl_or_crlf(v)) {
      return fail_c<HttpResponse>(ErrorCode::invalid_identity,
                                  MpClientError::invalid_config);
    }
    wire.append(k);
    wire.append(": ");
    wire.append(v);
    wire.append("\r\n");
  }
  if (method_requires_body_headers(req.method)) {
    wire.append("Content-Length: ");
    wire.append(std::to_string(req.body.size()));
    wire.append("\r\n");
  }
  wire.append("\r\n");

  std::vector<std::uint8_t> out_bytes;
  out_bytes.reserve(wire.size() + req.body.size());
  out_bytes.insert(out_bytes.end(), wire.begin(), wire.end());
  out_bytes.insert(out_bytes.end(), req.body.begin(), req.body.end());
  CleanseSpanGuard out_cleanse{out_bytes};

  if (const auto w = conn.write_all(out_bytes, config.io_timeout_ms); !w.has_value()) {
    return Result<HttpResponse>::failure(w.error());
  }

  const auto deadline =
      SteadyClock::now() + std::chrono::milliseconds{config.io_timeout_ms};
  std::vector<std::uint8_t> recv_buf;
  if (const auto ok = read_until_headers_complete(conn, recv_buf, deadline);
      !ok.has_value()) {
    return Result<HttpResponse>::failure(ok.error());
  }

  auto parsed_hdr = parse_http_response_headers(recv_buf);
  if (!parsed_hdr.has_value()) {
    return Result<HttpResponse>::failure(parsed_hdr.error());
  }

  std::vector<std::uint8_t> trailing(
      recv_buf.begin() +
          static_cast<std::ptrdiff_t>(parsed_hdr.value().header_end_offset),
      recv_buf.end());

  auto body_res =
      read_http_response_body(conn, parsed_hdr.value(), std::move(trailing), deadline);
  if (!body_res.has_value()) {
    return Result<HttpResponse>::failure(body_res.error());
  }

  return Result<HttpResponse>::success(HttpResponse{
      parsed_hdr.value().status,
      std::move(parsed_hdr.value().headers),
      std::move(body_res).value(),
  });
}

bool response_is_clock_skew(const HttpResponse &resp,
                            std::optional<std::int64_t> signed_now_s = std::nullopt) {
  if (resp.status != 401) {
    return false;
  }
  const std::string_view text{reinterpret_cast<const char *>(resp.body.data()),
                              resp.body.size()};
  const auto parsed = parse_json_object_body(text);
  if (!parsed.has_value()) {
    return false;
  }
  const auto err = get_required_string(parsed.value(), "error");
  if (!err.has_value()) {
    return false;
  }
  if (err.value() == "clock_skew") {
    return true;
  }
  if (err.value() == "expired" && signed_now_s.has_value()) {
    const auto srv_ms = get_required_u64(parsed.value(), "server_now_ms");
    if (!srv_ms.has_value() || srv_ms.value() < kMinValidServerNowMs ||
        srv_ms.value() > kMaxSafeId) {
      return false;
    }
    const auto srv_s = static_cast<std::int64_t>(srv_ms.value() / 1000U);
    const auto diff = checked_sub_i64(srv_s, *signed_now_s);
    if (!diff.has_value()) {
      return true;
    }
    return *diff > kClockSkewHeuristicSecs || *diff < -kClockSkewHeuristicSecs;
  }
  return false;
}

Error map_http_error(int status, bool is_clock_skew) noexcept {
  if (is_clock_skew) {
    return {ErrorCode::provider_auth,
            static_cast<std::int64_t>(MpClientError::http_clock_skew)};
  }
  switch (status) {
  case 400:
    return {ErrorCode::invalid_range,
            static_cast<std::int64_t>(MpClientError::http_bad_request)};
  case 401:
    return {ErrorCode::provider_auth,
            static_cast<std::int64_t>(MpClientError::http_unauthorized)};
  case 403:
    return {ErrorCode::provider_auth,
            static_cast<std::int64_t>(MpClientError::http_forbidden)};
  case 404:
    return {ErrorCode::invalid_identity,
            static_cast<std::int64_t>(MpClientError::http_not_found)};
  case 409:
    return {ErrorCode::conflict,
            static_cast<std::int64_t>(MpClientError::http_conflict)};
  case 410:
    return {ErrorCode::stale_handle,
            static_cast<std::int64_t>(MpClientError::http_gone)};
  case 429:
    return {ErrorCode::provider_rate_limit,
            static_cast<std::int64_t>(MpClientError::http_rate_limited)};
  default:
    if (status >= 500) {
      return {ErrorCode::provider_transport,
              static_cast<std::int64_t>(MpClientError::http_server_error)};
    }
    return {ErrorCode::external_unknown,
            static_cast<std::int64_t>(MpClientError::http_status_error)};
  }
}

Result<HealthResponse> parse_health_response(const HttpResponse &resp) {
  if (resp.status != 200) {
    return Result<HealthResponse>::failure(map_http_error(resp.status, false));
  }
  const std::string_view text{reinterpret_cast<const char *>(resp.body.data()),
                              resp.body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<HealthResponse>::failure(obj.error());
  }
  const Value *ok_field = obj.value().find("ok");
  if (ok_field == nullptr) {
    return fail_c<HealthResponse>(ErrorCode::corrupt,
                                  MpClientError::http_response_schema);
  }
  const auto ok_val = value_as_bool_or_flag(*ok_field);
  const auto server_now = get_required_u64(obj.value(), "server_now_ms");
  if (!ok_val.has_value() || !server_now.has_value() ||
      server_now.value() < kMinValidServerNowMs || server_now.value() > kMaxSafeId) {
    return fail_c<HealthResponse>(ErrorCode::corrupt,
                                  MpClientError::http_response_schema);
  }
  return Result<HealthResponse>::success(
      HealthResponse{ok_val.value(), server_now.value()});
}

Result<HttpResponse> signed_rest_call(const MpClientConfig &config,
                                      std::int64_t &clock_offset_s,
                                      const Ed25519SigningKey &signing_key,
                                      const KeyId &keyid,
                                      const RawHttpRequest &base_req) {
  std::int64_t last_signed_now_s = 0;
  auto send_signed = [&]() -> Result<HttpResponse> {
    const auto win = compute_signing_window(clock_offset_s);
    if (!win.has_value()) {
      return Result<HttpResponse>::failure(win.error());
    }
    last_signed_now_s = win.value().now_s;
    Rfc9421SignRequest sign_req{};
    sign_req.method = base_req.method;
    sign_req.authority = config.authority;
    sign_req.path = base_req.path;
    sign_req.query = base_req.query;
    if (method_requires_body_headers(base_req.method)) {
      sign_req.content_type = "application/json";
    }
    sign_req.body = base_req.body;
    sign_req.keyid = keyid;
    sign_req.created = win.value().created;
    sign_req.expires = win.value().expires;

    const auto signed_hdrs = sign_rfc9421_request(signing_key, sign_req);
    if (!signed_hdrs.has_value()) {
      return Result<HttpResponse>::failure(signed_hdrs.error());
    }

    RawHttpRequest req = base_req;
    CleanseSpanGuard body_cleanse{req.body};
    if (method_requires_body_headers(req.method)) {
      req.headers.emplace_back("Content-Type", "application/json");
      if (signed_hdrs.value().content_digest.has_value()) {
        req.headers.emplace_back("Content-Digest", *signed_hdrs.value().content_digest);
      }
    }
    req.headers.emplace_back("Signature-Input", signed_hdrs.value().signature_input);
    req.headers.emplace_back("Signature", signed_hdrs.value().signature);
    return execute_http_once(config, req);
  };

  auto resp = send_signed();
  if (!resp.has_value()) {
    return resp;
  }
  if (!response_is_clock_skew(resp.value(), last_signed_now_s)) {
    return resp;
  }

  // Automatic 1-retry clock-skew self-healing via GET /v1/health.
  RawHttpRequest health_req{};
  health_req.method = HttpMethod::get;
  health_req.path = "/v1/health";
  health_req.query = "?";
  const auto health_http = execute_http_once(config, health_req);
  if (!health_http.has_value()) {
    return Result<HttpResponse>::failure(health_http.error());
  }
  const auto health_parsed = parse_health_response(health_http.value());
  if (!health_parsed.has_value() || !health_parsed.value().ok) {
    return Result<HttpResponse>::failure(
        map_http_error(resp.value().status, /*is_clock_skew=*/true));
  }
  const auto server_s =
      static_cast<std::int64_t>(health_parsed.value().server_now_ms / 1000U);
  const auto next_offset = checked_sub_i64(server_s, current_unix_seconds());
  if (!next_offset.has_value()) {
    return Result<HttpResponse>::failure(
        map_http_error(resp.value().status, /*is_clock_skew=*/true));
  }
  clock_offset_s = *next_offset;

  return send_signed();
}

Result<std::vector<std::uint8_t>> dump_json_bytes(const Value &value) {
  auto dumped = dump_json(value);
  if (!dumped.has_value()) {
    return fail_c<std::vector<std::uint8_t>>(ErrorCode::corrupt,
                                             MpClientError::http_json_invalid);
  }
  std::string &text = dumped.value();
  CleanseStringGuard text_cleanse{text};
  return Result<std::vector<std::uint8_t>>::success(
      std::vector<std::uint8_t>(text.begin(), text.end()));
}

Result<FriendEdgeState> parse_friend_edge_state(std::uint64_t raw) {
  if (raw <= 3U) {
    return Result<FriendEdgeState>::success(static_cast<FriendEdgeState>(raw));
  }
  return fail_c<FriendEdgeState>(ErrorCode::corrupt,
                                 MpClientError::http_response_schema);
}

// ---------------------------------------------------------------------------
// RFC 6455 WebSocket frame helpers
// ---------------------------------------------------------------------------

Result<void> send_ws_masked_frame(TlsConnection &conn, std::uint8_t opcode,
                                  std::span<const std::uint8_t> payload,
                                  int timeout_ms) {
  if (payload.size() > kMaxWsFramePayload) {
    return fail_cv(ErrorCode::invalid_range, MpClientError::ws_frame_too_large);
  }
  std::array<std::uint8_t, 4> mask{};
  if (const auto rng = random_bytes(mask); !rng.has_value()) {
    return rng;
  }

  std::vector<std::uint8_t> frame;
  frame.reserve(14U + payload.size());
  frame.push_back(static_cast<std::uint8_t>(0x80U | (opcode & 0x0fU)));
  if (payload.size() <= 125U) {
    frame.push_back(static_cast<std::uint8_t>(0x80U | payload.size()));
  } else if (payload.size() <= 65535U) {
    frame.push_back(static_cast<std::uint8_t>(0x80U | 126U));
    frame.push_back(static_cast<std::uint8_t>((payload.size() >> 8U) & 0xffU));
    frame.push_back(static_cast<std::uint8_t>(payload.size() & 0xffU));
  } else {
    frame.push_back(static_cast<std::uint8_t>(0x80U | 127U));
    const auto len64 = static_cast<std::uint64_t>(payload.size());
    for (int shift = 56; shift >= 0; shift -= 8) {
      frame.push_back(
          static_cast<std::uint8_t>((len64 >> static_cast<unsigned>(shift)) & 0xffU));
    }
  }
  frame.insert(frame.end(), mask.begin(), mask.end());
  for (std::size_t i = 0U; i < payload.size(); ++i) {
    frame.push_back(static_cast<std::uint8_t>(payload[i] ^ mask[i % 4U]));
  }
  return conn.write_all(frame, timeout_ms);
}

constexpr bool is_reserved_ws_close_code(std::uint16_t code) noexcept {
  return code == 1005U || code == 1006U || code == 1015U;
}

struct HeaderTokenCheck {
  std::string_view header_value;
  std::string_view token_lower;
};

bool header_has_token_ci(const HeaderTokenCheck &check) {
  std::size_t pos = 0U;
  while (pos <= check.header_value.size()) {
    const std::size_t comma = check.header_value.find(',', pos);
    const std::string_view part = (comma == std::string_view::npos)
                                      ? check.header_value.substr(pos)
                                      : check.header_value.substr(pos, comma - pos);
    if (ascii_lower(trim_ows(part)) == check.token_lower) {
      return true;
    }
    if (comma == std::string_view::npos) {
      break;
    }
    pos = comma + 1U;
  }
  return false;
}

} // namespace

// ---------------------------------------------------------------------------
// Error names
// ---------------------------------------------------------------------------

const char *mp_client_error_name(MpClientError detail) noexcept {
  switch (detail) {
  case MpClientError::none:
    return "none";
  case MpClientError::invalid_config:
    return "invalid_config";
  case MpClientError::dns_failed:
    return "dns_failed";
  case MpClientError::connect_failed:
    return "connect_failed";
  case MpClientError::timeout:
    return "timeout";
  case MpClientError::tls_init_failed:
    return "tls_init_failed";
  case MpClientError::tls_ca_load_failed:
    return "tls_ca_load_failed";
  case MpClientError::tls_handshake_failed:
    return "tls_handshake_failed";
  case MpClientError::tls_verify_failed:
    return "tls_verify_failed";
  case MpClientError::tls_alpn_mismatch:
    return "tls_alpn_mismatch";
  case MpClientError::tls_io_failed:
    return "tls_io_failed";
  case MpClientError::tls_closed:
    return "tls_closed";
  case MpClientError::http_header_too_large:
    return "http_header_too_large";
  case MpClientError::http_body_too_large:
    return "http_body_too_large";
  case MpClientError::http_malformed_response:
    return "http_malformed_response";
  case MpClientError::http_chunked_malformed:
    return "http_chunked_malformed";
  case MpClientError::http_status_error:
    return "http_status_error";
  case MpClientError::http_unauthorized:
    return "http_unauthorized";
  case MpClientError::http_forbidden:
    return "http_forbidden";
  case MpClientError::http_not_found:
    return "http_not_found";
  case MpClientError::http_conflict:
    return "http_conflict";
  case MpClientError::http_rate_limited:
    return "http_rate_limited";
  case MpClientError::http_server_error:
    return "http_server_error";
  case MpClientError::http_clock_skew:
    return "http_clock_skew";
  case MpClientError::http_json_invalid:
    return "http_json_invalid";
  case MpClientError::http_response_schema:
    return "http_response_schema";
  case MpClientError::http_bad_request:
    return "http_bad_request";
  case MpClientError::http_gone:
    return "http_gone";
  case MpClientError::keystore_invalid_path:
    return "keystore_invalid_path";
  case MpClientError::keystore_not_found:
    return "keystore_not_found";
  case MpClientError::keystore_insecure_permissions:
    return "keystore_insecure_permissions";
  case MpClientError::keystore_symlink_rejected:
    return "keystore_symlink_rejected";
  case MpClientError::keystore_corrupt:
    return "keystore_corrupt";
  case MpClientError::keystore_io_failed:
    return "keystore_io_failed";
  case MpClientError::ws_upgrade_rejected:
    return "ws_upgrade_rejected";
  case MpClientError::ws_accept_mismatch:
    return "ws_accept_mismatch";
  case MpClientError::ws_subprotocol_mismatch:
    return "ws_subprotocol_mismatch";
  case MpClientError::ws_protocol_error:
    return "ws_protocol_error";
  case MpClientError::ws_masked_server_frame:
    return "ws_masked_server_frame";
  case MpClientError::ws_frame_too_large:
    return "ws_frame_too_large";
  case MpClientError::ws_unexpected_text_frame:
    return "ws_unexpected_text_frame";
  case MpClientError::ws_closed:
    return "ws_closed";
  case MpClientError::ws_not_open:
    return "ws_not_open";
  case MpClientError::missing_root_key:
    return "missing_root_key";
  case MpClientError::missing_device_key:
    return "missing_device_key";
  case MpClientError::missing_account_identity:
    return "missing_account_identity";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// CleansedSeed & MpIdentityStore
// ---------------------------------------------------------------------------

CleansedSeed &CleansedSeed::operator=(const CleansedSeed &other) noexcept {
  if (this != &other) {
    cleanse();
    seed_ = other.seed_;
  }
  return *this;
}

CleansedSeed::CleansedSeed(CleansedSeed &&other) noexcept : seed_(other.seed_) {
  other.cleanse();
}

CleansedSeed &CleansedSeed::operator=(CleansedSeed &&other) noexcept {
  if (this != &other) {
    cleanse();
    seed_ = other.seed_;
    other.cleanse();
  }
  return *this;
}

CleansedSeed::~CleansedSeed() { cleanse(); }

Result<CleansedSeed> CleansedSeed::generate() {
  CleansedSeed out{};
  if (const auto ok = random_bytes(out.seed_); !ok.has_value()) {
    out.cleanse();
    return Result<CleansedSeed>::failure(ok.error());
  }
  return Result<CleansedSeed>::success(std::move(out));
}

void CleansedSeed::cleanse() noexcept { OPENSSL_cleanse(seed_.data(), seed_.size()); }

bool CleansedSeed::operator==(const CleansedSeed &other) const noexcept {
  return constant_time_equal({seed_, other.seed_});
}

MpIdentityStore::MpIdentityStore(MpIdentityStore &&other) noexcept
    : dir_(std::move(other.dir_)), dir_fd_(std::exchange(other.dir_fd_, -1)),
      state_(std::move(other.state_)) {}

MpIdentityStore &MpIdentityStore::operator=(MpIdentityStore &&other) noexcept {
  if (this != &other) {
    if (dir_fd_ >= 0) {
      (void)::close(dir_fd_);
    }
    dir_ = std::move(other.dir_);
    dir_fd_ = std::exchange(other.dir_fd_, -1);
    state_ = std::move(other.state_);
  }
  return *this;
}

MpIdentityStore::~MpIdentityStore() {
  if (dir_fd_ >= 0) {
    (void)::close(dir_fd_);
    dir_fd_ = -1;
  }
}

Result<MpIdentityStore>
MpIdentityStore::open_existing(const std::filesystem::path &dir) {
  std::filesystem::path normalized;
  auto dir_fd_res = open_keystore_dir(dir, /*create=*/false, normalized);
  if (!dir_fd_res.has_value()) {
    return Result<MpIdentityStore>::failure(dir_fd_res.error());
  }
  ScopedFd dir_fd = std::move(dir_fd_res).value();

  auto dev_seed_res = read_file_bounded(dir_fd.get(), kDeviceSeedFile, 32U);
  if (!dev_seed_res.has_value()) {
    return Result<MpIdentityStore>::failure(dev_seed_res.error());
  }
  CleanseSpanGuard dev_guard{dev_seed_res.value().bytes};
  if (!dev_seed_res.value().exists || dev_seed_res.value().bytes.size() != 32U) {
    return fail_c<MpIdentityStore>(ErrorCode::corrupt, MpClientError::keystore_corrupt);
  }
  MpIdentityState state{};
  std::memcpy(state.device_seed.mutable_bytes().data(),
              dev_seed_res.value().bytes.data(), 32U);
  // Validate device seed produces a valid Ed25519 key.
  if (const auto key_check = Ed25519SigningKey::from_seed(state.device_seed.bytes());
      !key_check.has_value()) {
    return fail_c<MpIdentityStore>(ErrorCode::corrupt, MpClientError::keystore_corrupt);
  }

  auto root_seed_res = read_file_bounded(dir_fd.get(), kRootSeedFile, 32U);
  if (!root_seed_res.has_value()) {
    return Result<MpIdentityStore>::failure(root_seed_res.error());
  }
  CleanseSpanGuard root_guard{root_seed_res.value().bytes};
  if (root_seed_res.value().exists) {
    if (root_seed_res.value().bytes.size() != 32U) {
      return fail_c<MpIdentityStore>(ErrorCode::corrupt,
                                     MpClientError::keystore_corrupt);
    }
    CleansedSeed root_seed{};
    std::memcpy(root_seed.mutable_bytes().data(), root_seed_res.value().bytes.data(),
                32U);
    if (const auto key_check = Ed25519SigningKey::from_seed(root_seed.bytes());
        !key_check.has_value()) {
      return fail_c<MpIdentityStore>(ErrorCode::corrupt,
                                     MpClientError::keystore_corrupt);
    }
    state.root_seed = std::move(root_seed);
  }

  auto cwt_res = read_file_bounded(dir_fd.get(), kDeviceCwtFile, kMaxCwtBytes);
  if (!cwt_res.has_value()) {
    return Result<MpIdentityStore>::failure(cwt_res.error());
  }
  if (cwt_res.value().exists) {
    state.device_cwt = std::move(cwt_res.value().bytes);
  }

  auto meta_res =
      read_file_bounded(dir_fd.get(), kIdentityMetaFile, kMaxIdentityJsonBytes);
  if (!meta_res.has_value()) {
    return Result<MpIdentityStore>::failure(meta_res.error());
  }
  if (!meta_res.value().exists) {
    return fail_c<MpIdentityStore>(ErrorCode::corrupt, MpClientError::keystore_corrupt);
  }
  const std::string_view meta_text{
      reinterpret_cast<const char *>(meta_res.value().bytes.data()),
      meta_res.value().bytes.size()};
  const auto meta_json = parse_json_object_body(meta_text);
  if (!meta_json.has_value()) {
    return fail_c<MpIdentityStore>(ErrorCode::corrupt, MpClientError::keystore_corrupt);
  }

  const auto ver = get_required_u64(meta_json.value(), "version");
  if (!ver.has_value() || ver.value() != 1U) {
    return fail_c<MpIdentityStore>(ErrorCode::corrupt, MpClientError::keystore_corrupt);
  }
  const auto authority = get_required_string(meta_json.value(), "authority");
  const auto handle = get_required_string(meta_json.value(), "handle");
  if (!authority.has_value() || !handle.has_value() ||
      !extract_tls_hostname(authority.value()).has_value()) {
    return fail_c<MpIdentityStore>(ErrorCode::corrupt, MpClientError::keystore_corrupt);
  }
  state.authority = authority.value();
  state.handle = handle.value();

  if (const Value *acct_field = meta_json.value().find("account_id");
      acct_field != nullptr &&
      !std::holds_alternative<std::nullptr_t>(acct_field->value())) {
    const auto raw = value_as_u64(*acct_field);
    if (!raw.has_value()) {
      return fail_c<MpIdentityStore>(ErrorCode::corrupt,
                                     MpClientError::keystore_corrupt);
    }
    const auto id = AccountId::create(raw.value());
    if (!id.has_value()) {
      return fail_c<MpIdentityStore>(ErrorCode::corrupt,
                                     MpClientError::keystore_corrupt);
    }
    state.account_id = id.value();
  }
  if (const Value *dev_field = meta_json.value().find("device_id");
      dev_field != nullptr &&
      !std::holds_alternative<std::nullptr_t>(dev_field->value())) {
    const auto raw = value_as_u64(*dev_field);
    if (!raw.has_value()) {
      return fail_c<MpIdentityStore>(ErrorCode::corrupt,
                                     MpClientError::keystore_corrupt);
    }
    const auto id = DeviceId::create(raw.value());
    if (!id.has_value()) {
      return fail_c<MpIdentityStore>(ErrorCode::corrupt,
                                     MpClientError::keystore_corrupt);
    }
    state.device_id = id.value();
  }

  return Result<MpIdentityStore>::success(
      MpIdentityStore{std::move(normalized), dir_fd.release(), std::move(state)});
}

Result<void> MpIdentityStore::update(const MpIdentityState &state) {
  if (dir_fd_ < 0) {
    return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
  }
  if (const auto auth_ok = extract_tls_hostname(state.authority);
      !auth_ok.has_value()) {
    return fail_cv(ErrorCode::invalid_identity, MpClientError::invalid_config);
  }
  if (state.device_cwt.size() > kMaxCwtBytes) {
    return fail_cv(ErrorCode::invalid_range, MpClientError::keystore_corrupt);
  }
  if (const auto dk = Ed25519SigningKey::from_seed(state.device_seed.bytes());
      !dk.has_value()) {
    return Result<void>::failure(dk.error());
  }
  if (state.root_seed.has_value()) {
    if (const auto rk = Ed25519SigningKey::from_seed(state.root_seed->bytes());
        !rk.has_value()) {
      return Result<void>::failure(rk.error());
    }
  }

  // Copy seeds into stack buffers with guaranteed OPENSSL_cleanse on scope exit.
  Ed25519Seed dev_buf = state.device_seed.bytes();
  CleanseSpanGuard dev_guard{dev_buf};
  if (const auto w = write_file_atomic_0600(dir_fd_, kDeviceSeedFile, dev_buf);
      !w.has_value()) {
    return w;
  }

  if (state.root_seed.has_value()) {
    Ed25519Seed root_buf = state.root_seed->bytes();
    CleanseSpanGuard root_guard{root_buf};
    if (const auto w = write_file_atomic_0600(dir_fd_, kRootSeedFile, root_buf);
        !w.has_value()) {
      return w;
    }
  } else {
    if (::unlinkat(dir_fd_, kRootSeedFile, 0) != 0 && errno != ENOENT) {
      return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
    }
    if (const auto s = fsync_fd(dir_fd_); !s.has_value()) {
      return s;
    }
  }

  if (!state.device_cwt.empty()) {
    if (const auto w =
            write_file_atomic_0600(dir_fd_, kDeviceCwtFile, state.device_cwt);
        !w.has_value()) {
      return w;
    }
  } else {
    if (::unlinkat(dir_fd_, kDeviceCwtFile, 0) != 0 && errno != ENOENT) {
      return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
    }
  }

  Value::Object meta;
  meta.emplace_back("version", Value{Number{std::uint64_t{1U}}});
  if (state.account_id.has_value()) {
    meta.emplace_back("account_id", Value{Number{state.account_id->value()}});
  } else {
    meta.emplace_back("account_id", Value{nullptr});
  }
  if (state.device_id.has_value()) {
    meta.emplace_back("device_id", Value{Number{state.device_id->value()}});
  } else {
    meta.emplace_back("device_id", Value{nullptr});
  }
  meta.emplace_back("handle", Value{state.handle});
  meta.emplace_back("authority", Value{state.authority});

  const auto meta_bytes = dump_json_bytes(Value::object(std::move(meta)));
  if (!meta_bytes.has_value()) {
    return fail_cv(ErrorCode::corrupt, MpClientError::keystore_corrupt);
  }
  if (const auto w =
          write_file_atomic_0600(dir_fd_, kIdentityMetaFile, meta_bytes.value());
      !w.has_value()) {
    return w;
  }

  state_ = state;
  return Result<void>::success();
}

Result<MpIdentityStore> MpIdentityStore::save(const std::filesystem::path &dir,
                                              const MpIdentityState &state) {
  std::filesystem::path normalized;
  auto dir_fd_res = open_keystore_dir(dir, /*create=*/true, normalized);
  if (!dir_fd_res.has_value()) {
    return Result<MpIdentityStore>::failure(dir_fd_res.error());
  }
  MpIdentityStore store{std::move(normalized), dir_fd_res.value().release(), {}};
  if (const auto up = store.update(state); !up.has_value()) {
    return Result<MpIdentityStore>::failure(up.error());
  }
  return Result<MpIdentityStore>::success(std::move(store));
}

namespace {

// Strict deterministic CBOR reader for validating COSE_Sign1 / CWT structure and
// extracting embedded cnf device_pubkey before installing a secondary-device CWT.
struct CwtCborHead {
  std::uint8_t major = 0U;
  std::uint64_t arg = 0U;
};

template <typename T> Result<T> fail_mp(ErrorCode code, MpError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

class StrictCwtCborReader {
public:
  explicit StrictCwtCborReader(std::span<const std::uint8_t> bytes) noexcept
      : bytes_(bytes) {}

  Result<CwtCborHead> read_head(MpError err) {
    if (pos_ >= bytes_.size()) {
      return fail_mp<CwtCborHead>(ErrorCode::corrupt, err);
    }
    const std::uint8_t initial = bytes_[pos_++];
    const auto major = static_cast<std::uint8_t>((initial >> 5U) & 0x07U);
    const auto ai = static_cast<std::uint8_t>(initial & 0x1fU);
    if (ai < 24U) {
      return Result<CwtCborHead>::success(CwtCborHead{major, ai});
    }
    if (ai == 24U) {
      if (bytes_.size() - pos_ < 1U) {
        return fail_mp<CwtCborHead>(ErrorCode::corrupt, err);
      }
      const std::uint64_t val = bytes_[pos_++];
      if (val < 24U) {
        return fail_mp<CwtCborHead>(ErrorCode::corrupt, err);
      }
      return Result<CwtCborHead>::success(CwtCborHead{major, val});
    }
    if (ai == 25U) {
      if (bytes_.size() - pos_ < 2U) {
        return fail_mp<CwtCborHead>(ErrorCode::corrupt, err);
      }
      const std::uint64_t val = (static_cast<std::uint64_t>(bytes_[pos_]) << 8U) |
                                static_cast<std::uint64_t>(bytes_[pos_ + 1U]);
      pos_ += 2U;
      if (val <= 0xffU) {
        return fail_mp<CwtCborHead>(ErrorCode::corrupt, err);
      }
      return Result<CwtCborHead>::success(CwtCborHead{major, val});
    }
    if (ai == 26U) {
      if (bytes_.size() - pos_ < 4U) {
        return fail_mp<CwtCborHead>(ErrorCode::corrupt, err);
      }
      std::uint64_t val = 0U;
      for (std::size_t i = 0U; i < 4U; ++i) {
        val = (val << 8U) | static_cast<std::uint64_t>(bytes_[pos_ + i]);
      }
      pos_ += 4U;
      if (val <= 0xffffU) {
        return fail_mp<CwtCborHead>(ErrorCode::corrupt, err);
      }
      return Result<CwtCborHead>::success(CwtCborHead{major, val});
    }
    if (ai == 27U) {
      if (bytes_.size() - pos_ < 8U) {
        return fail_mp<CwtCborHead>(ErrorCode::corrupt, err);
      }
      std::uint64_t val = 0U;
      for (std::size_t i = 0U; i < 8U; ++i) {
        val = (val << 8U) | static_cast<std::uint64_t>(bytes_[pos_ + i]);
      }
      pos_ += 8U;
      if (val <= 0xffffffffULL) {
        return fail_mp<CwtCborHead>(ErrorCode::corrupt, err);
      }
      return Result<CwtCborHead>::success(CwtCborHead{major, val});
    }
    return fail_mp<CwtCborHead>(ErrorCode::corrupt, err);
  }

  Result<std::int64_t> read_i64(MpError err) {
    const auto head = read_head(err);
    if (!head.has_value()) {
      return Result<std::int64_t>::failure(head.error());
    }
    constexpr auto kMaxI64 =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (head.value().major == 0U) {
      if (head.value().arg > kMaxI64) {
        return fail_mp<std::int64_t>(ErrorCode::corrupt, err);
      }
      return Result<std::int64_t>::success(static_cast<std::int64_t>(head.value().arg));
    }
    if (head.value().major == 1U) {
      if (head.value().arg > kMaxI64) {
        return fail_mp<std::int64_t>(ErrorCode::corrupt, err);
      }
      return Result<std::int64_t>::success(-1 -
                                           static_cast<std::int64_t>(head.value().arg));
    }
    return fail_mp<std::int64_t>(ErrorCode::corrupt, err);
  }

  Result<std::span<const std::uint8_t>> read_bstr(MpError err) {
    const auto head = read_head(err);
    if (!head.has_value()) {
      return Result<std::span<const std::uint8_t>>::failure(head.error());
    }
    if (head.value().major != 2U || head.value().arg > bytes_.size() - pos_) {
      return fail_mp<std::span<const std::uint8_t>>(ErrorCode::corrupt, err);
    }
    const auto len = static_cast<std::size_t>(head.value().arg);
    const auto slice = bytes_.subspan(pos_, len);
    pos_ += len;
    return Result<std::span<const std::uint8_t>>::success(slice);
  }

  Result<std::string> read_tstr(MpError err) {
    const auto head = read_head(err);
    if (!head.has_value()) {
      return Result<std::string>::failure(head.error());
    }
    if (head.value().major != 3U || head.value().arg > bytes_.size() - pos_) {
      return fail_mp<std::string>(ErrorCode::corrupt, err);
    }
    const auto len = static_cast<std::size_t>(head.value().arg);
    const auto slice = bytes_.subspan(pos_, len);
    pos_ += len;
    std::string out;
    out.reserve(len);
    for (const std::uint8_t b : slice) {
      out.push_back(static_cast<char>(b));
    }
    return Result<std::string>::success(std::move(out));
  }

  bool at_end() const noexcept { return pos_ == bytes_.size(); }

private:
  std::span<const std::uint8_t> bytes_;
  std::size_t pos_ = 0U;
};

bool is_lower_hex_64(std::string_view text) noexcept {
  if (text.size() != 64U) {
    return false;
  }
  for (const char ch : text) {
    const bool ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    if (!ok) {
      return false;
    }
  }
  return true;
}

Result<Ed25519PubKey> parse_cwt_cnf_ed25519(StrictCwtCborReader &reader) {
  const auto cnf_head = reader.read_head(MpError::cwt_invalid_claims);
  if (!cnf_head.has_value()) {
    return Result<Ed25519PubKey>::failure(cnf_head.error());
  }
  if (cnf_head.value().major != 5U || cnf_head.value().arg != 1U) {
    return fail_mp<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }
  const auto cnf_key = reader.read_i64(MpError::cwt_invalid_claims);
  if (!cnf_key.has_value() || cnf_key.value() != 1) {
    return fail_mp<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }
  const auto key_head = reader.read_head(MpError::cwt_invalid_claims);
  if (!key_head.has_value()) {
    return Result<Ed25519PubKey>::failure(key_head.error());
  }
  if (key_head.value().major != 5U || key_head.value().arg > 16U) {
    return fail_mp<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }

  std::optional<std::int64_t> kty;
  std::optional<std::int64_t> alg;
  std::optional<std::int64_t> crv;
  std::optional<Ed25519PubKey> x;
  for (std::uint64_t i = 0U; i < key_head.value().arg; ++i) {
    const auto mk = reader.read_i64(MpError::cwt_invalid_claims);
    if (!mk.has_value()) {
      return Result<Ed25519PubKey>::failure(mk.error());
    }
    switch (mk.value()) {
    case 1: { // kty == OKP (1)
      if (kty.has_value()) {
        return fail_mp<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto mv = reader.read_i64(MpError::cwt_invalid_claims);
      if (!mv.has_value()) {
        return Result<Ed25519PubKey>::failure(mv.error());
      }
      kty = mv.value();
      break;
    }
    case 3: { // alg == Ed25519 (-19)
      if (alg.has_value()) {
        return fail_mp<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto mv = reader.read_i64(MpError::cwt_invalid_claims);
      if (!mv.has_value()) {
        return Result<Ed25519PubKey>::failure(mv.error());
      }
      alg = mv.value();
      break;
    }
    case -1: { // crv == Ed25519 (6)
      if (crv.has_value()) {
        return fail_mp<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto mv = reader.read_i64(MpError::cwt_invalid_claims);
      if (!mv.has_value()) {
        return Result<Ed25519PubKey>::failure(mv.error());
      }
      crv = mv.value();
      break;
    }
    case -2: { // x == 32-byte pubkey
      if (x.has_value()) {
        return fail_mp<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto mv = reader.read_bstr(MpError::cwt_invalid_claims);
      if (!mv.has_value() || mv.value().size() != 32U) {
        return fail_mp<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      Ed25519PubKey pub{};
      std::memcpy(pub.data(), mv.value().data(), pub.size());
      x = pub;
      break;
    }
    default:
      return fail_mp<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
    }
  }
  if (!kty.has_value() || *kty != 1 || !alg.has_value() || *alg != -19 ||
      !crv.has_value() || *crv != 6 || !x.has_value()) {
    return fail_mp<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }
  return Result<Ed25519PubKey>::success(*x);
}

Result<CwtClaims>
parse_device_cwt_unverified(std::span<const std::uint8_t> bytes,
                            const Ed25519PubKey &expected_device_pubkey,
                            std::int64_t now_s) {
  if (bytes.empty() || bytes.size() > kMaxCwtBytes) {
    return fail_mp<CwtClaims>(ErrorCode::capacity, MpError::cwt_too_large);
  }
  // Tag 18 (0xd2) + array(4) (0x84) + bstr(3) protected {1:-19} + empty map {} (0xa0).
  static constexpr std::array<std::uint8_t, 7> kSign1Prefix = {
      0xd2U, 0x84U, 0x43U, 0xa1U, 0x01U, 0x32U, 0xa0U};
  if (bytes.size() <= kSign1Prefix.size() ||
      std::memcmp(bytes.data(), kSign1Prefix.data(), kSign1Prefix.size()) != 0) {
    return fail_mp<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_envelope_shape);
  }

  StrictCwtCborReader outer{bytes.subspan(kSign1Prefix.size())};
  const auto payload_bytes = outer.read_bstr(MpError::cwt_invalid_cbor);
  if (!payload_bytes.has_value()) {
    return Result<CwtClaims>::failure(payload_bytes.error());
  }
  const auto sig_bytes = outer.read_bstr(MpError::cwt_invalid_cbor);
  if (!sig_bytes.has_value()) {
    return Result<CwtClaims>::failure(sig_bytes.error());
  }
  if (!outer.at_end()) {
    return fail_mp<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_cbor);
  }
  if (sig_bytes.value().size() != 64U) {
    return fail_mp<CwtClaims>(ErrorCode::corrupt,
                              MpError::cwt_invalid_signature_length);
  }

  StrictCwtCborReader payload_reader{payload_bytes.value()};
  const auto map_head = payload_reader.read_head(MpError::cwt_invalid_claims);
  if (!map_head.has_value()) {
    return Result<CwtClaims>::failure(map_head.error());
  }
  if (map_head.value().major != 5U || map_head.value().arg > 16U) {
    return fail_mp<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }

  std::optional<std::string> iss;
  std::optional<std::int64_t> exp;
  std::optional<std::int64_t> iat;
  std::optional<Ed25519PubKey> device_pubkey;
  for (std::uint64_t i = 0U; i < map_head.value().arg; ++i) {
    const auto key = payload_reader.read_i64(MpError::cwt_invalid_claims);
    if (!key.has_value()) {
      return Result<CwtClaims>::failure(key.error());
    }
    switch (key.value()) {
    case 1: { // iss
      if (iss.has_value()) {
        return fail_mp<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto val = payload_reader.read_tstr(MpError::cwt_invalid_claims);
      if (!val.has_value() || !is_lower_hex_64(val.value())) {
        return fail_mp<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      iss = val.value();
      break;
    }
    case 4: { // exp
      if (exp.has_value()) {
        return fail_mp<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto val = payload_reader.read_i64(MpError::cwt_invalid_claims);
      if (!val.has_value()) {
        return Result<CwtClaims>::failure(val.error());
      }
      exp = val.value();
      break;
    }
    case 6: { // iat
      if (iat.has_value()) {
        return fail_mp<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto val = payload_reader.read_i64(MpError::cwt_invalid_claims);
      if (!val.has_value()) {
        return Result<CwtClaims>::failure(val.error());
      }
      iat = val.value();
      break;
    }
    case 8: { // cnf
      if (device_pubkey.has_value()) {
        return fail_mp<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto val = parse_cwt_cnf_ed25519(payload_reader);
      if (!val.has_value()) {
        return Result<CwtClaims>::failure(val.error());
      }
      device_pubkey = val.value();
      break;
    }
    default:
      return fail_mp<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
    }
  }
  if (!payload_reader.at_end() || !iss.has_value() || !exp.has_value() ||
      !iat.has_value() || !device_pubkey.has_value()) {
    return fail_mp<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }
  if (const auto dev_ok = validate_ed25519_pubkey_strict(*device_pubkey);
      !dev_ok.has_value()) {
    return Result<CwtClaims>::failure(dev_ok.error());
  }
  if (!constant_time_equal({*device_pubkey, expected_device_pubkey})) {
    return fail_mp<CwtClaims>(ErrorCode::provider_auth,
                              MpError::cwt_device_key_mismatch);
  }
  if (*iat < 0) {
    return fail_mp<CwtClaims>(ErrorCode::invalid_range, MpError::cwt_invalid_claims);
  }
  const auto ttl = checked_sub_i64(*exp, *iat);
  if (!ttl.has_value() || *ttl <= 0 || *ttl > kMaxCwtTtlSecs) {
    return fail_mp<CwtClaims>(ErrorCode::invalid_range, MpError::cwt_ttl_exceeded);
  }
  const auto max_iat = checked_add_i64(now_s, kMaxCwtIatSkewSecs);
  if (max_iat.has_value() && *iat > *max_iat) {
    return fail_mp<CwtClaims>(ErrorCode::clock_regressed,
                              MpError::cwt_future_issued_at);
  }
  if (now_s >= *exp) {
    return fail_mp<CwtClaims>(ErrorCode::provider_auth, MpError::cwt_expired);
  }
  return Result<CwtClaims>::success(
      CwtClaims{std::move(*iss), *iat, *exp, *device_pubkey});
}

std::optional<char> normalize_crockford_base32_char(char ch) noexcept {
  if (ch >= '0' && ch <= '9') {
    return ch;
  }
  char up = ch;
  if (ch >= 'a' && ch <= 'z') {
    up = static_cast<char>(ch - ('a' - 'A'));
  }
  if (up < 'A' || up > 'Z') {
    return std::nullopt;
  }
  // Strict Crockford Base32 excludes I, L, O, U.
  if (up == 'I' || up == 'L' || up == 'O' || up == 'U') {
    return std::nullopt;
  }
  return up;
}

} // namespace

Result<MpIdentityStore>
MpIdentityStore::open_or_init_device(const std::filesystem::path &dir,
                                     std::string_view authority) {
  if (const auto auth_ok = extract_tls_hostname(authority); !auth_ok.has_value()) {
    return Result<MpIdentityStore>::failure(auth_ok.error());
  }
  auto existing = open_existing(dir);
  if (existing.has_value()) {
    return existing;
  }
  const auto err = mp_client_error_of(existing.error());
  if (err == MpClientError::keystore_corrupt) {
    // Allow initializing a pre-existing empty 0700 directory ONLY if all 4 keystore
    // files are absent (ENOENT); fail closed if any partial/corrupt file or symlink
    // exists.
    std::filesystem::path normalized;
    auto dir_fd = open_keystore_dir(dir, /*create=*/false, normalized);
    if (!dir_fd.has_value()) {
      return Result<MpIdentityStore>::failure(dir_fd.error());
    }
    for (const char *fname :
         {kRootSeedFile, kDeviceSeedFile, kDeviceCwtFile, kIdentityMetaFile}) {
      struct stat fst{};
      if (::fstatat(dir_fd.value().get(), fname, &fst, AT_SYMLINK_NOFOLLOW) == 0) {
        return existing;
      }
      if (errno != ENOENT) {
        return fail_c<MpIdentityStore>(ErrorCode::io,
                                       MpClientError::keystore_io_failed);
      }
    }
  } else if (err != MpClientError::keystore_not_found) {
    return existing;
  }

  auto dev_seed = CleansedSeed::generate();
  if (!dev_seed.has_value()) {
    return Result<MpIdentityStore>::failure(dev_seed.error());
  }
  MpIdentityState state{};
  state.root_seed = std::nullopt;
  state.device_seed = std::move(dev_seed).value();
  state.account_id = std::nullopt;
  state.device_id = std::nullopt;
  state.handle.clear();
  state.authority = std::string{authority};
  state.device_cwt.clear();
  return save(dir, state);
}

Result<void> MpIdentityStore::install_cwt(const InstallDeviceCwtRequest &request) {
  if (dir_fd_ < 0) {
    return fail_cv(ErrorCode::io, MpClientError::keystore_io_failed);
  }
  std::optional<Ed25519PubKey> effective_root_pk = request.expected_root_pubkey;
  if (state_.root_seed.has_value()) {
    if (!state_.account_id.has_value() || *state_.account_id != request.account_id) {
      return fail_cv(ErrorCode::conflict, MpClientError::invalid_config);
    }
    const auto local_root_key = root_signing_key();
    if (!local_root_key.has_value()) {
      return Result<void>::failure(local_root_key.error());
    }
    const Ed25519PubKey &local_root_pk = local_root_key.value().public_key();
    if (request.expected_root_pubkey.has_value() &&
        !constant_time_equal({*request.expected_root_pubkey, local_root_pk})) {
      return Result<void>::failure(
          {ErrorCode::conflict,
           static_cast<std::int64_t>(MpError::cwt_issuer_mismatch)});
    }
    effective_root_pk = local_root_pk;
  }
  if (const auto handle_ok = AccountHandle::parse(request.handle);
      !handle_ok.has_value()) {
    return Result<void>::failure(handle_ok.error());
  }
  if (request.authority.has_value()) {
    if (const auto auth_ok = extract_tls_hostname(*request.authority);
        !auth_ok.has_value()) {
      return Result<void>::failure(auth_ok.error());
    }
  }
  if (request.device_cwt.empty() || request.device_cwt.size() > kMaxCwtBytes) {
    return fail_cv(ErrorCode::invalid_range, MpClientError::keystore_corrupt);
  }

  const auto dev_key = device_signing_key();
  if (!dev_key.has_value()) {
    return Result<void>::failure(dev_key.error());
  }
  const std::int64_t now_s = request.now_s.value_or(current_unix_seconds());
  if (effective_root_pk.has_value()) {
    const auto verified = verify_device_cwt(DeviceCwtVerifyRequest{
        request.device_cwt,
        *effective_root_pk,
        dev_key.value().public_key(),
        now_s,
    });
    if (!verified.has_value()) {
      return Result<void>::failure(verified.error());
    }
  } else {
    const auto parsed = parse_device_cwt_unverified(
        request.device_cwt, dev_key.value().public_key(), now_s);
    if (!parsed.has_value()) {
      return Result<void>::failure(parsed.error());
    }
  }

  MpIdentityState next = state_;
  next.account_id = request.account_id;
  next.device_id = request.device_id;
  next.handle = request.handle;
  if (request.authority.has_value()) {
    next.authority = *request.authority;
  }
  next.device_cwt = request.device_cwt;
  return update(next);
}

Result<std::string> normalize_web_user_code(std::string_view user_code) {
  if (user_code.size() != 8U && user_code.size() != 9U) {
    return fail_c<std::string>(ErrorCode::invalid_range, MpClientError::invalid_config);
  }
  if (user_code.size() == 9U && user_code[4] != '-') {
    return fail_c<std::string>(ErrorCode::invalid_range, MpClientError::invalid_config);
  }
  std::string normalized;
  normalized.reserve(9U);
  for (std::size_t i = 0U; i < user_code.size(); ++i) {
    if (user_code.size() == 9U && i == 4U) {
      normalized.push_back('-');
      continue;
    }
    const auto ch = normalize_crockford_base32_char(user_code[i]);
    if (!ch.has_value()) {
      return fail_c<std::string>(ErrorCode::invalid_range,
                                 MpClientError::invalid_config);
    }
    normalized.push_back(*ch);
    if (user_code.size() == 8U && i == 3U) {
      normalized.push_back('-');
    }
  }
  return Result<std::string>::success(std::move(normalized));
}

Result<Ed25519SigningKey> MpIdentityStore::device_signing_key() const {
  return Ed25519SigningKey::from_seed(state_.device_seed.bytes());
}

Result<Ed25519SigningKey> MpIdentityStore::root_signing_key() const {
  if (!state_.root_seed.has_value()) {
    return fail_c<Ed25519SigningKey>(ErrorCode::provider_auth,
                                     MpClientError::missing_root_key);
  }
  return Ed25519SigningKey::from_seed(state_.root_seed->bytes());
}

// ---------------------------------------------------------------------------
// MpControlSocket (RFC 6455 over TLS 1.3 + HTTP/1.1 ALPN)
// ---------------------------------------------------------------------------

struct MpControlSocket::Impl {
  TlsConnection conn;
  int io_timeout_ms = 10000;
  bool open = true;
  bool close_sent = false;
  std::vector<std::uint8_t> recv_buf;
  std::size_t recv_pos = 0U;

  // RFC 6455 fragmentation reassembly state
  bool frag_active = false;
  std::uint8_t frag_opcode = 0U;
  std::size_t frag_count = 0U;
  std::vector<std::uint8_t> frag_buf;

  explicit Impl(TlsConnection connection, int timeout_ms,
                std::vector<std::uint8_t> initial_bytes) noexcept
      : conn(std::move(connection)), io_timeout_ms(timeout_ms),
        recv_buf(std::move(initial_bytes)) {}

  std::size_t available() const noexcept { return recv_buf.size() - recv_pos; }

  void compact_if_needed() {
    if (recv_pos > 4096U) {
      recv_buf.erase(recv_buf.begin(),
                     recv_buf.begin() + static_cast<std::ptrdiff_t>(recv_pos));
      recv_pos = 0U;
    } else if (recv_pos == recv_buf.size()) {
      recv_buf.clear();
      recv_pos = 0U;
    }
  }

  Result<bool> fill_bytes(std::size_t min_avail, SteadyClock::time_point deadline) {
    std::array<std::uint8_t, 4096> tmp{};
    while (available() < min_avail) {
      compact_if_needed();
      const auto got = conn.read_some_until(tmp, deadline);
      if (!got.has_value()) {
        open = false;
        return Result<bool>::failure(got.error());
      }
      if (!got.value().has_value()) {
        return Result<bool>::success(false); // timeout
      }
      const std::size_t n = got.value().value();
      if (n == 0U) {
        open = false;
        return fail_c<bool>(ErrorCode::provider_transport, MpClientError::ws_closed);
      }
      recv_buf.insert(recv_buf.end(), tmp.begin(),
                      tmp.begin() + static_cast<std::ptrdiff_t>(n));
    }
    return Result<bool>::success(true);
  }
};

MpControlSocket::MpControlSocket(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

MpControlSocket::MpControlSocket(MpControlSocket &&other) noexcept = default;
MpControlSocket &MpControlSocket::operator=(MpControlSocket &&other) noexcept = default;

MpControlSocket::~MpControlSocket() {
  if (impl_ && impl_->open) {
    (void)close(1000U);
  }
}

bool MpControlSocket::is_open() const noexcept { return impl_ && impl_->open; }

Result<MpControlSocket> MpControlSocket::connect(const MpSocketConnectRequest &request,
                                                 const Ed25519SigningKey &device_key) {
  if (request.path.empty() || contains_ctl_or_crlf(request.path)) {
    return fail_c<MpControlSocket>(ErrorCode::invalid_identity,
                                   MpClientError::invalid_config);
  }

  const auto win = compute_signing_window(request.clock_offset_s);
  if (!win.has_value()) {
    return Result<MpControlSocket>::failure(win.error());
  }
  Rfc9421SignRequest sign_req{};
  sign_req.method = HttpMethod::get;
  sign_req.authority = request.config.authority;
  sign_req.path = request.path;
  sign_req.query = "?";
  sign_req.keyid = DeviceKeyId{request.account_id, request.device_id};
  sign_req.created = win.value().created;
  sign_req.expires = win.value().expires;

  const auto signed_hdrs = sign_rfc9421_request(device_key, sign_req);
  if (!signed_hdrs.has_value()) {
    return Result<MpControlSocket>::failure(signed_hdrs.error());
  }

  std::array<std::uint8_t, 16> raw_ws_key{};
  if (const auto rng = random_bytes(raw_ws_key); !rng.has_value()) {
    return Result<MpControlSocket>::failure(rng.error());
  }
  const std::string ws_key = base64_encode(raw_ws_key);
  const auto expected_accept = compute_ws_accept(ws_key);
  if (!expected_accept.has_value()) {
    return Result<MpControlSocket>::failure(expected_accept.error());
  }

  auto conn_res = TlsConnection::connect(request.config);
  if (!conn_res.has_value()) {
    return Result<MpControlSocket>::failure(conn_res.error());
  }
  TlsConnection conn = std::move(conn_res).value();

  std::string upgrade_req;
  CleanseStringGuard upgrade_cleanse{upgrade_req};
  upgrade_req.reserve(512U);
  upgrade_req.append("GET ");
  upgrade_req.append(request.path);
  upgrade_req.append(" HTTP/1.1\r\nHost: ");
  upgrade_req.append(request.config.authority);
  upgrade_req.append("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Key: ");
  upgrade_req.append(ws_key);
  upgrade_req.append("\r\nSec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Protocol: mp1\r\nSignature-Input: ");
  upgrade_req.append(signed_hdrs.value().signature_input);
  upgrade_req.append("\r\nSignature: ");
  upgrade_req.append(signed_hdrs.value().signature);
  upgrade_req.append("\r\n\r\n");

  const std::span<const std::uint8_t> req_span{
      reinterpret_cast<const std::uint8_t *>(upgrade_req.data()), upgrade_req.size()};
  if (const auto w = conn.write_all(req_span, request.config.io_timeout_ms);
      !w.has_value()) {
    return Result<MpControlSocket>::failure(w.error());
  }

  const auto deadline =
      SteadyClock::now() + std::chrono::milliseconds{request.config.io_timeout_ms};
  std::vector<std::uint8_t> recv_buf;
  if (const auto ok = read_until_headers_complete(conn, recv_buf, deadline);
      !ok.has_value()) {
    return Result<MpControlSocket>::failure(ok.error());
  }
  const auto parsed = parse_http_response_headers(recv_buf);
  if (!parsed.has_value()) {
    return Result<MpControlSocket>::failure(parsed.error());
  }

  if (parsed.value().status != 101) {
    // Check for 401 clock_skew / backward-skew "expired" body using full HTTP/1.1
    // framing (handles Transfer-Encoding: chunked and Content-Length without stalling).
    if (parsed.value().status == 401) {
      std::vector<std::uint8_t> trailing(
          recv_buf.begin() +
              static_cast<std::ptrdiff_t>(parsed.value().header_end_offset),
          recv_buf.end());
      auto body_res =
          read_http_response_body(conn, parsed.value(), std::move(trailing), deadline);
      if (body_res.has_value()) {
        const HttpResponse err_resp{parsed.value().status, parsed.value().headers,
                                    std::move(body_res).value()};
        if (response_is_clock_skew(err_resp, win.value().now_s)) {
          return fail_c<MpControlSocket>(ErrorCode::provider_auth,
                                         MpClientError::http_clock_skew);
        }
      }
      return fail_c<MpControlSocket>(ErrorCode::provider_auth,
                                     MpClientError::http_unauthorized);
    }
    return fail_c<MpControlSocket>(ErrorCode::provider_transport,
                                   MpClientError::ws_upgrade_rejected);
  }

  bool saw_upgrade_ws = false;
  bool bad_upgrade = false;
  bool saw_conn_upgrade = false;
  std::size_t accept_count = 0U;
  std::string_view accept_val;
  std::size_t proto_count = 0U;
  std::string_view proto_val;
  for (const auto &hdr : parsed.value().headers) {
    if (hdr.name_lower == "upgrade") {
      if (ascii_lower(hdr.value) == "websocket") {
        saw_upgrade_ws = true;
      } else {
        bad_upgrade = true;
      }
    } else if (hdr.name_lower == "connection") {
      if (header_has_token_ci({hdr.value, "upgrade"})) {
        saw_conn_upgrade = true;
      }
    } else if (hdr.name_lower == "sec-websocket-accept") {
      ++accept_count;
      accept_val = hdr.value;
    } else if (hdr.name_lower == "sec-websocket-protocol") {
      ++proto_count;
      proto_val = hdr.value;
    } else if (hdr.name_lower == "sec-websocket-extensions") {
      if (!trim_ows(hdr.value).empty()) {
        // Client offered no extensions; RFC 6455 §9.1 forbids unsolicited extensions.
        return fail_c<MpControlSocket>(ErrorCode::corrupt,
                                       MpClientError::ws_protocol_error);
      }
    }
  }

  if (!saw_upgrade_ws || bad_upgrade || !saw_conn_upgrade) {
    return fail_c<MpControlSocket>(ErrorCode::corrupt,
                                   MpClientError::ws_upgrade_rejected);
  }
  if (accept_count != 1U) {
    return fail_c<MpControlSocket>(ErrorCode::corrupt,
                                   MpClientError::ws_accept_mismatch);
  }
  const std::span<const std::uint8_t> got_accept{
      reinterpret_cast<const std::uint8_t *>(accept_val.data()), accept_val.size()};
  const std::span<const std::uint8_t> exp_accept{
      reinterpret_cast<const std::uint8_t *>(expected_accept.value().data()),
      expected_accept.value().size()};
  if (!constant_time_equal({got_accept, exp_accept})) {
    return fail_c<MpControlSocket>(ErrorCode::corrupt,
                                   MpClientError::ws_accept_mismatch);
  }
  if (proto_count != 1U || proto_val != "mp1") {
    return fail_c<MpControlSocket>(ErrorCode::corrupt,
                                   MpClientError::ws_subprotocol_mismatch);
  }

  std::vector<std::uint8_t> initial_ws_bytes(
      recv_buf.begin() + static_cast<std::ptrdiff_t>(parsed.value().header_end_offset),
      recv_buf.end());
  auto impl = std::make_unique<Impl>(std::move(conn), request.config.io_timeout_ms,
                                     std::move(initial_ws_bytes));
  return Result<MpControlSocket>::success(MpControlSocket{std::move(impl)});
}

Result<void> MpControlSocket::send_mp1(std::uint32_t seq, const Mp1Message &message) {
  if (!impl_ || !impl_->open) {
    return fail_cv(ErrorCode::provider_transport, MpClientError::ws_not_open);
  }
  const auto encoded = encode_frame(seq, message);
  if (!encoded.has_value()) {
    return Result<void>::failure(encoded.error());
  }
  return send_ws_masked_frame(impl_->conn, /*opcode=*/0x02U, encoded.value(),
                              impl_->io_timeout_ms);
}

Result<void> MpControlSocket::send_ping() {
  if (!impl_ || !impl_->open) {
    return fail_cv(ErrorCode::provider_transport, MpClientError::ws_not_open);
  }
  const std::span<const std::uint8_t> ping_bytes{
      reinterpret_cast<const std::uint8_t *>(kMp1HeartbeatPing.data()),
      kMp1HeartbeatPing.size()};
  return send_ws_masked_frame(impl_->conn, /*opcode=*/0x01U, ping_bytes,
                              impl_->io_timeout_ms);
}

Result<void> MpControlSocket::close(std::uint16_t code) {
  if (!impl_) {
    return Result<void>::success();
  }
  if (impl_->open && !impl_->close_sent) {
    impl_->close_sent = true;
    std::vector<std::uint8_t> payload;
    if (!is_reserved_ws_close_code(code) && code >= 1000U) {
      payload.push_back(static_cast<std::uint8_t>((code >> 8U) & 0xffU));
      payload.push_back(static_cast<std::uint8_t>(code & 0xffU));
    }
    const auto send_res = send_ws_masked_frame(impl_->conn, /*opcode=*/0x08U, payload,
                                               impl_->io_timeout_ms);
    impl_->open = false;
    impl_->conn.shutdown_quiet();
    return send_res;
  }
  impl_->open = false;
  impl_->conn.shutdown_quiet();
  return Result<void>::success();
}

Result<std::optional<MpWsEvent>> MpControlSocket::poll_event(int timeout_ms) {
  if (!impl_ || !impl_->open) {
    return fail_c<std::optional<MpWsEvent>>(ErrorCode::provider_transport,
                                            MpClientError::ws_not_open);
  }
  const auto deadline =
      SteadyClock::now() + std::chrono::milliseconds{std::max(0, timeout_ms)};

  for (;;) {
    // 1. Read 2-byte RFC 6455 base header.
    const auto hdr_ok = impl_->fill_bytes(2U, deadline);
    if (!hdr_ok.has_value()) {
      return Result<std::optional<MpWsEvent>>::failure(hdr_ok.error());
    }
    if (!hdr_ok.value()) {
      return Result<std::optional<MpWsEvent>>::success(std::nullopt);
    }

    const std::uint8_t b0 = impl_->recv_buf[impl_->recv_pos];
    const std::uint8_t b1 = impl_->recv_buf[impl_->recv_pos + 1U];
    const bool fin = (b0 & 0x80U) != 0U;
    const std::uint8_t rsv = static_cast<std::uint8_t>(b0 & 0x70U);
    const std::uint8_t opcode = static_cast<std::uint8_t>(b0 & 0x0fU);
    const bool masked = (b1 & 0x80U) != 0U;
    const std::uint8_t len7 = static_cast<std::uint8_t>(b1 & 0x7fU);

    if (rsv != 0U) {
      impl_->open = false;
      return fail_c<std::optional<MpWsEvent>>(ErrorCode::corrupt,
                                              MpClientError::ws_protocol_error);
    }
    if (masked) {
      // RFC 6455 section 5.1: server MUST NOT mask frames sent to client.
      impl_->open = false;
      return fail_c<std::optional<MpWsEvent>>(ErrorCode::corrupt,
                                              MpClientError::ws_masked_server_frame);
    }

    const bool is_control = (opcode & 0x08U) != 0U;
    if (is_control && !fin) {
      impl_->open = false;
      return fail_c<std::optional<MpWsEvent>>(ErrorCode::corrupt,
                                              MpClientError::ws_protocol_error);
    }

    std::size_t header_len = 2U;
    if (len7 == 126U) {
      header_len = 4U;
    } else if (len7 == 127U) {
      header_len = 10U;
    }
    const auto ext_ok = impl_->fill_bytes(header_len, deadline);
    if (!ext_ok.has_value()) {
      return Result<std::optional<MpWsEvent>>::failure(ext_ok.error());
    }
    if (!ext_ok.value()) {
      return Result<std::optional<MpWsEvent>>::success(std::nullopt);
    }

    std::uint64_t payload_len64 = len7;
    if (len7 == 126U) {
      payload_len64 =
          (static_cast<std::uint64_t>(impl_->recv_buf[impl_->recv_pos + 2U]) << 8U) |
          static_cast<std::uint64_t>(impl_->recv_buf[impl_->recv_pos + 3U]);
    } else if (len7 == 127U) {
      if ((impl_->recv_buf[impl_->recv_pos + 2U] & 0x80U) != 0U) {
        impl_->open = false;
        return fail_c<std::optional<MpWsEvent>>(ErrorCode::corrupt,
                                                MpClientError::ws_protocol_error);
      }
      payload_len64 = 0U;
      for (std::size_t i = 0U; i < 8U; ++i) {
        payload_len64 =
            (payload_len64 << 8U) |
            static_cast<std::uint64_t>(impl_->recv_buf[impl_->recv_pos + 2U + i]);
      }
    }

    if (is_control && payload_len64 > kMaxWsControlPayload) {
      impl_->open = false;
      return fail_c<std::optional<MpWsEvent>>(ErrorCode::corrupt,
                                              MpClientError::ws_protocol_error);
    }
    if (payload_len64 > kMaxWsFramePayload) {
      impl_->open = false;
      return fail_c<std::optional<MpWsEvent>>(ErrorCode::overflow,
                                              MpClientError::ws_frame_too_large);
    }
    const auto payload_len = static_cast<std::size_t>(payload_len64);

    const auto body_ok = impl_->fill_bytes(header_len + payload_len, deadline);
    if (!body_ok.has_value()) {
      return Result<std::optional<MpWsEvent>>::failure(body_ok.error());
    }
    if (!body_ok.value()) {
      return Result<std::optional<MpWsEvent>>::success(std::nullopt);
    }

    const std::span<const std::uint8_t> payload{
        impl_->recv_buf.data() + impl_->recv_pos + header_len, payload_len};
    std::vector<std::uint8_t> frame_bytes(payload.begin(), payload.end());
    impl_->recv_pos += header_len + payload_len;
    impl_->compact_if_needed();

    // Control frames may be interleaved inside fragmented messages (RFC 6455 §5.4).
    if (opcode == 0x09U) { // Ping -> auto Pong
      const auto pong_res = send_ws_masked_frame(impl_->conn, /*opcode=*/0x0aU,
                                                 frame_bytes, impl_->io_timeout_ms);
      if (!pong_res.has_value()) {
        impl_->open = false;
        return Result<std::optional<MpWsEvent>>::failure(pong_res.error());
      }
      continue;
    }
    if (opcode == 0x0aU) { // Pong
      return Result<std::optional<MpWsEvent>>::success(MpWsEvent{MpWsPong{}});
    }
    if (opcode == 0x08U) { // Close
      std::uint16_t code = 1005U;
      if (frame_bytes.size() == 1U) {
        impl_->open = false;
        return fail_c<std::optional<MpWsEvent>>(ErrorCode::corrupt,
                                                MpClientError::ws_protocol_error);
      }
      if (frame_bytes.size() >= 2U) {
        code = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(frame_bytes[0]) << 8U) |
            static_cast<std::uint16_t>(frame_bytes[1]));
      }
      if (!impl_->close_sent) {
        const std::uint16_t echo_code = is_reserved_ws_close_code(code) ? 1000U : code;
        (void)close(echo_code);
      } else {
        impl_->open = false;
        impl_->conn.shutdown_quiet();
      }
      return Result<std::optional<MpWsEvent>>::success(MpWsEvent{MpWsClosed{code}});
    }

    // Data frames (0x00 continuation, 0x01 text, 0x02 binary)
    if (opcode == 0x00U) {
      if (!impl_->frag_active) {
        impl_->open = false;
        return fail_c<std::optional<MpWsEvent>>(ErrorCode::corrupt,
                                                MpClientError::ws_protocol_error);
      }
      ++impl_->frag_count;
      if (impl_->frag_count > kMaxWsFragmentsPerMessage) {
        impl_->open = false;
        return fail_c<std::optional<MpWsEvent>>(ErrorCode::corrupt,
                                                MpClientError::ws_protocol_error);
      }
      if (impl_->frag_buf.size() + frame_bytes.size() > kMaxWsFramePayload) {
        impl_->open = false;
        return fail_c<std::optional<MpWsEvent>>(ErrorCode::overflow,
                                                MpClientError::ws_frame_too_large);
      }
      impl_->frag_buf.insert(impl_->frag_buf.end(), frame_bytes.begin(),
                             frame_bytes.end());
      if (!fin) {
        continue;
      }
      const std::uint8_t msg_opcode = impl_->frag_opcode;
      std::vector<std::uint8_t> msg = std::move(impl_->frag_buf);
      impl_->frag_buf.clear();
      impl_->frag_active = false;
      impl_->frag_opcode = 0U;
      impl_->frag_count = 0U;

      if (msg_opcode == 0x01U) {
        const std::string_view text{reinterpret_cast<const char *>(msg.data()),
                                    msg.size()};
        if (text == kMp1HeartbeatPong) {
          return Result<std::optional<MpWsEvent>>::success(MpWsEvent{MpWsPong{}});
        }
        impl_->open = false;
        return fail_c<std::optional<MpWsEvent>>(
            ErrorCode::corrupt, MpClientError::ws_unexpected_text_frame);
      }
      auto decoded = decode_frame(msg);
      if (!decoded.has_value()) {
        return Result<std::optional<MpWsEvent>>::failure(decoded.error());
      }
      return Result<std::optional<MpWsEvent>>::success(
          MpWsEvent{MpWsMp1Frame{std::move(decoded).value()}});
    }

    if (opcode == 0x01U || opcode == 0x02U) {
      if (impl_->frag_active) {
        impl_->open = false;
        return fail_c<std::optional<MpWsEvent>>(ErrorCode::corrupt,
                                                MpClientError::ws_protocol_error);
      }
      if (!fin) {
        impl_->frag_active = true;
        impl_->frag_opcode = opcode;
        impl_->frag_count = 1U;
        impl_->frag_buf = std::move(frame_bytes);
        continue;
      }
      if (opcode == 0x01U) {
        const std::string_view text{reinterpret_cast<const char *>(frame_bytes.data()),
                                    frame_bytes.size()};
        if (text == kMp1HeartbeatPong) {
          return Result<std::optional<MpWsEvent>>::success(MpWsEvent{MpWsPong{}});
        }
        impl_->open = false;
        return fail_c<std::optional<MpWsEvent>>(
            ErrorCode::corrupt, MpClientError::ws_unexpected_text_frame);
      }
      auto decoded = decode_frame(frame_bytes);
      if (!decoded.has_value()) {
        return Result<std::optional<MpWsEvent>>::failure(decoded.error());
      }
      return Result<std::optional<MpWsEvent>>::success(
          MpWsEvent{MpWsMp1Frame{std::move(decoded).value()}});
    }

    // Unknown/reserved opcode
    impl_->open = false;
    return fail_c<std::optional<MpWsEvent>>(ErrorCode::corrupt,
                                            MpClientError::ws_protocol_error);
  }
}

// ---------------------------------------------------------------------------
// MpControlClient
// ---------------------------------------------------------------------------

MpControlClient::MpControlClient(MpClientConfig config) : config_(std::move(config)) {}

MpControlClient::MpControlClient(MpClientConfig config, MpIdentityState identity)
    : config_(std::move(config)), identity_(std::move(identity)) {}

Result<HealthResponse> MpControlClient::health() {
  RawHttpRequest req{};
  req.method = HttpMethod::get;
  req.path = "/v1/health";
  req.query = "?";
  const auto resp = execute_http_once(config_, req);
  if (!resp.has_value()) {
    return Result<HealthResponse>::failure(resp.error());
  }
  return parse_health_response(resp.value());
}

Result<RegisterAccountResponse>
MpControlClient::register_account(const Ed25519SigningKey &root_signing_key,
                                  const RegisterAccountRequest &request) {
  const auto handle_ok = AccountHandle::parse(request.handle);
  if (!handle_ok.has_value()) {
    return Result<RegisterAccountResponse>::failure(handle_ok.error());
  }
  if (const auto pk_ok = validate_ed25519_pubkey_strict(request.device_pubkey);
      !pk_ok.has_value()) {
    return Result<RegisterAccountResponse>::failure(pk_ok.error());
  }
  if (request.invite_secret.empty() || request.device_cwt.empty() ||
      request.device_cwt.size() > kMaxCwtBytes) {
    return fail_c<RegisterAccountResponse>(ErrorCode::invalid_range,
                                           MpClientError::invalid_config);
  }

  const auto reg_keyid = registration_key_id_for_pubkey(root_signing_key.public_key());
  if (!reg_keyid.has_value()) {
    return Result<RegisterAccountResponse>::failure(reg_keyid.error());
  }

  std::string idem_key = request.idempotency_key;
  if (idem_key.empty()) {
    const auto nonce = generate_nonce_b64url(24U);
    if (!nonce.has_value()) {
      return Result<RegisterAccountResponse>::failure(nonce.error());
    }
    idem_key = "mpreg_" + nonce.value();
  }
  if (idem_key.size() < 16U || idem_key.size() > 64U) {
    return fail_c<RegisterAccountResponse>(ErrorCode::invalid_range,
                                           MpClientError::invalid_config);
  }

  Value::Object body_obj;
  body_obj.emplace_back("invite_secret", Value{request.invite_secret});
  body_obj.emplace_back("handle", Value{request.handle});
  body_obj.emplace_back("root_pubkey_b64",
                        Value{base64_encode(root_signing_key.public_key())});
  body_obj.emplace_back("device_pubkey_b64",
                        Value{base64_encode(request.device_pubkey)});
  body_obj.emplace_back("device_label", Value{request.device_label});
  body_obj.emplace_back("device_cwt_b64", Value{base64_encode(request.device_cwt)});

  auto body_bytes = dump_json_bytes(Value::object(std::move(body_obj)));
  if (!body_bytes.has_value()) {
    return Result<RegisterAccountResponse>::failure(body_bytes.error());
  }

  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/accounts/register";
  req.query = "?";
  req.headers.emplace_back("Idempotency-Key", std::move(idem_key));
  req.body = std::move(body_bytes).value();
  CleanseVectorGuard body_cleanse{req.body};

  const auto resp = signed_rest_call(config_, clock_offset_s_, root_signing_key,
                                     KeyId{reg_keyid.value()}, req);
  if (!resp.has_value()) {
    return Result<RegisterAccountResponse>::failure(resp.error());
  }
  if (resp.value().status != 201) {
    return Result<RegisterAccountResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<RegisterAccountResponse>::failure(obj.error());
  }
  const auto acct_raw = get_required_u64(obj.value(), "account_id");
  const auto dev_raw = get_required_u64(obj.value(), "device_id");
  const auto handle = get_required_string(obj.value(), "handle");
  if (!acct_raw.has_value() || !dev_raw.has_value() || !handle.has_value()) {
    return fail_c<RegisterAccountResponse>(ErrorCode::corrupt,
                                           MpClientError::http_response_schema);
  }
  const auto acct_id = AccountId::create(acct_raw.value());
  const auto dev_id = DeviceId::create(dev_raw.value());
  if (!acct_id.has_value() || !dev_id.has_value()) {
    return fail_c<RegisterAccountResponse>(ErrorCode::corrupt,
                                           MpClientError::http_response_schema);
  }
  return Result<RegisterAccountResponse>::success(
      RegisterAccountResponse{acct_id.value(), dev_id.value(), handle.value()});
}

namespace {

struct DeviceAuthContext {
  AccountId account_id;
  DeviceId device_id;
  Ed25519SigningKey signing_key;
};

struct RootAuthContext {
  AccountId account_id;
  Ed25519SigningKey signing_key;
};

Result<DeviceAuthContext>
require_device_auth(const std::optional<MpIdentityState> &identity) {
  if (!identity.has_value() || !identity->account_id.has_value() ||
      !identity->device_id.has_value()) {
    return fail_c<DeviceAuthContext>(ErrorCode::provider_auth,
                                     MpClientError::missing_account_identity);
  }
  auto key = Ed25519SigningKey::from_seed(identity->device_seed.bytes());
  if (!key.has_value()) {
    return fail_c<DeviceAuthContext>(ErrorCode::provider_auth,
                                     MpClientError::missing_device_key);
  }
  return Result<DeviceAuthContext>::success(DeviceAuthContext{
      *identity->account_id, *identity->device_id, std::move(key).value()});
}

Result<RootAuthContext>
require_root_auth(const std::optional<MpIdentityState> &identity) {
  if (!identity.has_value() || !identity->account_id.has_value()) {
    return fail_c<RootAuthContext>(ErrorCode::provider_auth,
                                   MpClientError::missing_account_identity);
  }
  if (!identity->root_seed.has_value()) {
    return fail_c<RootAuthContext>(ErrorCode::provider_auth,
                                   MpClientError::missing_root_key);
  }
  auto key = Ed25519SigningKey::from_seed(identity->root_seed->bytes());
  if (!key.has_value()) {
    return fail_c<RootAuthContext>(ErrorCode::provider_auth,
                                   MpClientError::missing_root_key);
  }
  return Result<RootAuthContext>::success(
      RootAuthContext{*identity->account_id, std::move(key).value()});
}

} // namespace

Result<WhoamiResponse> MpControlClient::whoami() {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<WhoamiResponse>::failure(auth.error());
  }
  RawHttpRequest req{};
  req.method = HttpMethod::get;
  req.path = "/v1/accounts/me";
  req.query = "?";

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<WhoamiResponse>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<WhoamiResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<WhoamiResponse>::failure(obj.error());
  }
  const auto acct_raw = get_required_u64(obj.value(), "account_id");
  const auto handle = get_required_string(obj.value(), "handle");
  const auto root_pk = get_required_pubkey_b64(obj.value(), "root_pubkey_b64");
  if (!acct_raw.has_value() || !handle.has_value() || !root_pk.has_value()) {
    return fail_c<WhoamiResponse>(ErrorCode::corrupt,
                                  MpClientError::http_response_schema);
  }
  const auto acct_id = AccountId::create(acct_raw.value());
  if (!acct_id.has_value()) {
    return fail_c<WhoamiResponse>(ErrorCode::corrupt,
                                  MpClientError::http_response_schema);
  }

  std::vector<DeviceInfo> devices;
  if (const Value *devs_field = obj.value().find("devices"); devs_field != nullptr) {
    const auto *arr = std::get_if<Value::Array>(&devs_field->value());
    if (arr == nullptr) {
      return fail_c<WhoamiResponse>(ErrorCode::corrupt,
                                    MpClientError::http_response_schema);
    }
    for (const auto &entry : *arr) {
      if (!std::holds_alternative<Value::Object>(entry.value())) {
        return fail_c<WhoamiResponse>(ErrorCode::corrupt,
                                      MpClientError::http_response_schema);
      }
      const auto did_raw = get_required_u64(entry, "device_id");
      const auto dpk = get_required_pubkey_b64(entry, "pubkey_b64");
      const auto label = get_required_string(entry, "label");
      const auto cwt_exp = get_required_u64(entry, "cwt_expires_ms");
      const auto gen = get_required_u64(entry, "generation");
      const auto created_ms = get_required_u64(entry, "created_at_ms");
      const Value *pop_field = entry.find("pop_verified");
      if (!did_raw.has_value() || !dpk.has_value() || !label.has_value() ||
          !cwt_exp.has_value() || !gen.has_value() || !created_ms.has_value() ||
          pop_field == nullptr) {
        return fail_c<WhoamiResponse>(ErrorCode::corrupt,
                                      MpClientError::http_response_schema);
      }
      const auto did = DeviceId::create(did_raw.value());
      const auto pop = value_as_bool_or_flag(*pop_field);
      if (!did.has_value() || !pop.has_value()) {
        return fail_c<WhoamiResponse>(ErrorCode::corrupt,
                                      MpClientError::http_response_schema);
      }
      std::optional<std::uint64_t> revoked_ms;
      if (const Value *rev_field = entry.find("revoked_at_ms");
          rev_field != nullptr &&
          !std::holds_alternative<std::nullptr_t>(rev_field->value())) {
        const auto rev_u64 = value_as_u64(*rev_field);
        if (!rev_u64.has_value()) {
          return fail_c<WhoamiResponse>(ErrorCode::corrupt,
                                        MpClientError::http_response_schema);
        }
        revoked_ms = rev_u64.value();
      }
      devices.push_back(DeviceInfo{did.value(), dpk.value(), label.value(),
                                   cwt_exp.value(), gen.value(), pop.value(),
                                   created_ms.value(), revoked_ms});
    }
  }

  std::vector<PartyId> active_parties;
  if (const Value *parties_field = obj.value().find("active_party_ids");
      parties_field != nullptr) {
    const auto *arr = std::get_if<Value::Array>(&parties_field->value());
    if (arr == nullptr) {
      return fail_c<WhoamiResponse>(ErrorCode::corrupt,
                                    MpClientError::http_response_schema);
    }
    for (const auto &entry : *arr) {
      const auto raw_pid = value_as_u64(entry);
      if (!raw_pid.has_value()) {
        return fail_c<WhoamiResponse>(ErrorCode::corrupt,
                                      MpClientError::http_response_schema);
      }
      const auto pid = PartyId::create(raw_pid.value());
      if (!pid.has_value()) {
        return fail_c<WhoamiResponse>(ErrorCode::corrupt,
                                      MpClientError::http_response_schema);
      }
      active_parties.push_back(pid.value());
    }
  }

  return Result<WhoamiResponse>::success(
      WhoamiResponse{acct_id.value(), handle.value(), root_pk.value(),
                     std::move(devices), std::move(active_parties)});
}

Result<ResolvedAccount> MpControlClient::resolve_handle(std::string_view handle) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<ResolvedAccount>::failure(auth.error());
  }
  const auto parsed_handle = AccountHandle::parse(handle);
  if (!parsed_handle.has_value()) {
    return Result<ResolvedAccount>::failure(parsed_handle.error());
  }
  RawHttpRequest req{};
  req.method = HttpMethod::get;
  req.path = "/v1/accounts/resolve";
  req.query = "?handle=" + std::string{parsed_handle.value().display()};

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<ResolvedAccount>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<ResolvedAccount>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<ResolvedAccount>::failure(obj.error());
  }
  const auto acct_raw = get_required_u64(obj.value(), "account_id");
  const auto resolved_handle = get_required_string(obj.value(), "handle");
  const auto root_pk = get_required_pubkey_b64(obj.value(), "root_pubkey_b64");
  if (!acct_raw.has_value() || !resolved_handle.has_value() || !root_pk.has_value()) {
    return fail_c<ResolvedAccount>(ErrorCode::corrupt,
                                   MpClientError::http_response_schema);
  }
  const auto acct_id = AccountId::create(acct_raw.value());
  if (!acct_id.has_value()) {
    return fail_c<ResolvedAccount>(ErrorCode::corrupt,
                                   MpClientError::http_response_schema);
  }
  return Result<ResolvedAccount>::success(
      ResolvedAccount{acct_id.value(), resolved_handle.value(), root_pk.value()});
}

Result<EnrollDeviceResponse>
MpControlClient::enroll_device(const EnrollDeviceRequest &request) {
  auto auth = require_root_auth(identity_);
  if (!auth.has_value()) {
    return Result<EnrollDeviceResponse>::failure(auth.error());
  }
  if (const auto pk_ok = validate_ed25519_pubkey_strict(request.device_pubkey);
      !pk_ok.has_value()) {
    return Result<EnrollDeviceResponse>::failure(pk_ok.error());
  }
  if (request.device_cwt.empty() || request.device_cwt.size() > kMaxCwtBytes) {
    return fail_c<EnrollDeviceResponse>(ErrorCode::invalid_range,
                                        MpClientError::invalid_config);
  }

  Value::Object body_obj;
  body_obj.emplace_back("device_pubkey_b64",
                        Value{base64_encode(request.device_pubkey)});
  body_obj.emplace_back("device_label", Value{request.device_label});
  body_obj.emplace_back("device_cwt_b64", Value{base64_encode(request.device_cwt)});
  auto body_bytes = dump_json_bytes(Value::object(std::move(body_obj)));
  if (!body_bytes.has_value()) {
    return Result<EnrollDeviceResponse>::failure(body_bytes.error());
  }

  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/devices";
  req.query = "?";
  req.body = std::move(body_bytes).value();

  const auto resp = signed_rest_call(config_, clock_offset_s_, auth.value().signing_key,
                                     KeyId{RootKeyId{auth.value().account_id}}, req);
  if (!resp.has_value()) {
    return Result<EnrollDeviceResponse>::failure(resp.error());
  }
  if (resp.value().status != 201) {
    return Result<EnrollDeviceResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<EnrollDeviceResponse>::failure(obj.error());
  }
  const auto dev_raw = get_required_u64(obj.value(), "device_id");
  const auto exp_ms = get_required_u64(obj.value(), "cwt_expires_ms");
  if (!dev_raw.has_value() || !exp_ms.has_value()) {
    return fail_c<EnrollDeviceResponse>(ErrorCode::corrupt,
                                        MpClientError::http_response_schema);
  }
  const auto dev_id = DeviceId::create(dev_raw.value());
  if (!dev_id.has_value()) {
    return fail_c<EnrollDeviceResponse>(ErrorCode::corrupt,
                                        MpClientError::http_response_schema);
  }
  return Result<EnrollDeviceResponse>::success(
      EnrollDeviceResponse{dev_id.value(), exp_ms.value()});
}

Result<RevokeDeviceResponse> MpControlClient::revoke_device(DeviceId device_id) {
  auto auth = require_root_auth(identity_);
  if (!auth.has_value()) {
    return Result<RevokeDeviceResponse>::failure(auth.error());
  }
  RawHttpRequest req{};
  req.method = HttpMethod::del;
  req.path = "/v1/devices/" + device_id.to_decimal();
  req.query = "?";

  const auto resp = signed_rest_call(config_, clock_offset_s_, auth.value().signing_key,
                                     KeyId{RootKeyId{auth.value().account_id}}, req);
  if (!resp.has_value()) {
    return Result<RevokeDeviceResponse>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<RevokeDeviceResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<RevokeDeviceResponse>::failure(obj.error());
  }
  const Value *rev_field = obj.value().find("revoked");
  if (rev_field == nullptr) {
    return fail_c<RevokeDeviceResponse>(ErrorCode::corrupt,
                                        MpClientError::http_response_schema);
  }
  const auto rev_flag = value_as_bool_or_flag(*rev_field);
  const auto pending = get_required_u64(obj.value(), "pending_retries");
  if (!rev_flag.has_value() || !pending.has_value()) {
    return fail_c<RevokeDeviceResponse>(ErrorCode::corrupt,
                                        MpClientError::http_response_schema);
  }
  std::vector<PartyId> evicted;
  if (const Value *ev_field = obj.value().find("evicted_parties");
      ev_field != nullptr) {
    const auto *arr = std::get_if<Value::Array>(&ev_field->value());
    if (arr == nullptr) {
      return fail_c<RevokeDeviceResponse>(ErrorCode::corrupt,
                                          MpClientError::http_response_schema);
    }
    for (const auto &item : *arr) {
      const auto raw_pid = value_as_u64(item);
      if (!raw_pid.has_value()) {
        return fail_c<RevokeDeviceResponse>(ErrorCode::corrupt,
                                            MpClientError::http_response_schema);
      }
      const auto pid = PartyId::create(raw_pid.value());
      if (!pid.has_value()) {
        return fail_c<RevokeDeviceResponse>(ErrorCode::corrupt,
                                            MpClientError::http_response_schema);
      }
      evicted.push_back(pid.value());
    }
  }
  return Result<RevokeDeviceResponse>::success(
      RevokeDeviceResponse{rev_flag.value(), std::move(evicted), pending.value()});
}

Result<WebSessionApproveResponse>
MpControlClient::approve_web_session(std::string_view user_code) {
  auto normalized = normalize_web_user_code(user_code);
  if (!normalized.has_value()) {
    return Result<WebSessionApproveResponse>::failure(normalized.error());
  }
  CleanseStringGuard code_cleanse{normalized.value()};

  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<WebSessionApproveResponse>::failure(auth.error());
  }

  Value::Object body_obj;
  body_obj.emplace_back("user_code", Value{normalized.value()});
  auto body_bytes = dump_json_bytes(Value::object(std::move(body_obj)));
  if (!body_bytes.has_value()) {
    return Result<WebSessionApproveResponse>::failure(body_bytes.error());
  }

  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/web-sessions/approve";
  req.query = "?";
  req.body = std::move(body_bytes).value();
  CleanseVectorGuard body_cleanse{req.body};

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<WebSessionApproveResponse>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<WebSessionApproveResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<WebSessionApproveResponse>::failure(obj.error());
  }
  const Value *approved_field = obj.value().find("approved");
  if (approved_field == nullptr) {
    return fail_c<WebSessionApproveResponse>(ErrorCode::corrupt,
                                             MpClientError::http_response_schema);
  }
  const auto approved_val = value_as_bool_or_flag(*approved_field);
  if (!approved_val.has_value()) {
    return fail_c<WebSessionApproveResponse>(ErrorCode::corrupt,
                                             MpClientError::http_response_schema);
  }
  std::string scope;
  if (const Value *scope_field = obj.value().find("scope");
      scope_field != nullptr &&
      !std::holds_alternative<std::nullptr_t>(scope_field->value())) {
    const auto *s = std::get_if<std::string>(&scope_field->value());
    if (s == nullptr) {
      return fail_c<WebSessionApproveResponse>(ErrorCode::corrupt,
                                               MpClientError::http_response_schema);
    }
    scope = *s;
  }
  std::optional<std::uint64_t> expires_at_ms;
  if (const Value *exp_field = obj.value().find("expires_at_ms");
      exp_field != nullptr &&
      !std::holds_alternative<std::nullptr_t>(exp_field->value())) {
    const auto exp_u64 = value_as_u64(*exp_field);
    if (!exp_u64.has_value()) {
      return fail_c<WebSessionApproveResponse>(ErrorCode::corrupt,
                                               MpClientError::http_response_schema);
    }
    expires_at_ms = exp_u64.value();
  }
  return Result<WebSessionApproveResponse>::success(
      WebSessionApproveResponse{approved_val.value(), std::move(scope), expires_at_ms});
}

Result<std::vector<FriendEdge>> MpControlClient::list_friends() {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<std::vector<FriendEdge>>::failure(auth.error());
  }
  RawHttpRequest req{};
  req.method = HttpMethod::get;
  req.path = "/v1/friends";
  req.query = "?";

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<std::vector<FriendEdge>>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<std::vector<FriendEdge>>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<std::vector<FriendEdge>>::failure(obj.error());
  }
  const Value *friends_field = obj.value().find("friends");
  if (friends_field == nullptr) {
    return fail_c<std::vector<FriendEdge>>(ErrorCode::corrupt,
                                           MpClientError::http_response_schema);
  }
  const auto *arr = std::get_if<Value::Array>(&friends_field->value());
  if (arr == nullptr) {
    return fail_c<std::vector<FriendEdge>>(ErrorCode::corrupt,
                                           MpClientError::http_response_schema);
  }

  std::vector<FriendEdge> edges;
  edges.reserve(arr->size());
  for (const auto &item : *arr) {
    if (!std::holds_alternative<Value::Object>(item.value())) {
      return fail_c<std::vector<FriendEdge>>(ErrorCode::corrupt,
                                             MpClientError::http_response_schema);
    }
    const auto peer_raw = get_required_u64(item, "peer_account_id");
    const auto state_raw = get_required_u64(item, "state");
    const auto updated = get_required_u64(item, "updated_at_ms");
    if (!peer_raw.has_value() || !state_raw.has_value() || !updated.has_value()) {
      return fail_c<std::vector<FriendEdge>>(ErrorCode::corrupt,
                                             MpClientError::http_response_schema);
    }
    const auto peer_id = AccountId::create(peer_raw.value());
    const auto state = parse_friend_edge_state(state_raw.value());
    if (!peer_id.has_value() || !state.has_value()) {
      return fail_c<std::vector<FriendEdge>>(ErrorCode::corrupt,
                                             MpClientError::http_response_schema);
    }
    edges.push_back(FriendEdge{peer_id.value(), state.value(), updated.value()});
  }
  return Result<std::vector<FriendEdge>>::success(std::move(edges));
}

Result<FriendRequestResponse>
MpControlClient::send_or_accept_friend(AccountId target_account_id) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<FriendRequestResponse>::failure(auth.error());
  }
  Value::Object body_obj;
  body_obj.emplace_back("target_account_id", Value{Number{target_account_id.value()}});
  auto body_bytes = dump_json_bytes(Value::object(std::move(body_obj)));
  if (!body_bytes.has_value()) {
    return Result<FriendRequestResponse>::failure(body_bytes.error());
  }

  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/friends/requests";
  req.query = "?";
  req.body = std::move(body_bytes).value();

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<FriendRequestResponse>::failure(resp.error());
  }
  if (resp.value().status != 200 && resp.value().status != 202) {
    return Result<FriendRequestResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<FriendRequestResponse>::failure(obj.error());
  }
  const auto tid_raw = get_required_u64(obj.value(), "target_account_id");
  const auto state_raw = get_required_u64(obj.value(), "state");
  if (!tid_raw.has_value() || !state_raw.has_value()) {
    return fail_c<FriendRequestResponse>(ErrorCode::corrupt,
                                         MpClientError::http_response_schema);
  }
  const auto tid = AccountId::create(tid_raw.value());
  const auto state = parse_friend_edge_state(state_raw.value());
  if (!tid.has_value() || !state.has_value()) {
    return fail_c<FriendRequestResponse>(ErrorCode::corrupt,
                                         MpClientError::http_response_schema);
  }
  return Result<FriendRequestResponse>::success(
      FriendRequestResponse{tid.value(), state.value(), resp.value().status});
}

Result<void> MpControlClient::remove_friend(AccountId target_account_id) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<void>::failure(auth.error());
  }
  RawHttpRequest req{};
  req.method = HttpMethod::del;
  req.path = "/v1/friends/" + target_account_id.to_decimal();
  req.query = "?";

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<void>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<void>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }
  return Result<void>::success();
}

Result<void> MpControlClient::block_account(AccountId target_account_id) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<void>::failure(auth.error());
  }
  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/friends/" + target_account_id.to_decimal() + "/block";
  req.query = "?";

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<void>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<void>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }
  return Result<void>::success();
}

Result<CreatePartyResponse>
MpControlClient::create_party(const CreatePartyRequest &request) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<CreatePartyResponse>::failure(auth.error());
  }
  const auto ep_bytes = request.endpoint.encode();
  if (!ep_bytes.has_value()) {
    return Result<CreatePartyResponse>::failure(ep_bytes.error());
  }

  Value::Object body_obj;
  body_obj.emplace_back("visibility",
                        Value{Number{static_cast<std::uint64_t>(request.visibility)}});
  body_obj.emplace_back("join_mode",
                        Value{Number{static_cast<std::uint64_t>(request.join_mode)}});
  body_obj.emplace_back(
      "relay_policy", Value{Number{static_cast<std::uint64_t>(request.relay_policy)}});
  body_obj.emplace_back("max_members",
                        Value{Number{static_cast<std::uint64_t>(request.max_members)}});
  body_obj.emplace_back("endpoint_b64", Value{base64_encode(ep_bytes.value())});
  if (!request.relay_url.empty()) {
    body_obj.emplace_back("relay_url", Value{request.relay_url});
  }

  auto body_bytes = dump_json_bytes(Value::object(std::move(body_obj)));
  if (!body_bytes.has_value()) {
    return Result<CreatePartyResponse>::failure(body_bytes.error());
  }

  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/parties";
  req.query = "?";
  req.body = std::move(body_bytes).value();

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<CreatePartyResponse>::failure(resp.error());
  }
  if (resp.value().status != 201) {
    return Result<CreatePartyResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<CreatePartyResponse>::failure(obj.error());
  }
  const auto pid_raw = get_required_u64(obj.value(), "party_id");
  const auto epoch = get_required_u64(obj.value(), "party_epoch");
  const auto relay = get_required_string(obj.value(), "pinned_relay_url");
  if (!pid_raw.has_value() || !epoch.has_value() || !relay.has_value()) {
    return fail_c<CreatePartyResponse>(ErrorCode::corrupt,
                                       MpClientError::http_response_schema);
  }
  const auto pid = PartyId::create(pid_raw.value());
  if (!pid.has_value()) {
    return fail_c<CreatePartyResponse>(ErrorCode::corrupt,
                                       MpClientError::http_response_schema);
  }
  return Result<CreatePartyResponse>::success(
      CreatePartyResponse{pid.value(), epoch.value(), relay.value()});
}

Result<PartySummary> MpControlClient::get_party(PartyId party_id) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<PartySummary>::failure(auth.error());
  }
  RawHttpRequest req{};
  req.method = HttpMethod::get;
  req.path = "/v1/parties/" + party_id.to_decimal();
  req.query = "?";

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<PartySummary>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<PartySummary>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<PartySummary>::failure(obj.error());
  }
  const auto pid_raw = get_required_u64(obj.value(), "party_id");
  const auto epoch = get_required_u64(obj.value(), "party_epoch");
  const auto leader_acct_raw = get_required_u64(obj.value(), "leader_account_id");
  const auto leader_dev_raw = get_required_u64(obj.value(), "leader_device_id");
  const auto vis_raw = get_required_u64(obj.value(), "visibility");
  const auto jm_raw = get_required_u64(obj.value(), "join_mode");
  const auto rp_raw = get_required_u64(obj.value(), "relay_policy");
  const auto pinned_relay = get_required_string(obj.value(), "pinned_relay_url");
  const auto max_mem = get_required_u64(obj.value(), "max_members");
  const auto mem_cnt = get_required_u64(obj.value(), "member_count");
  if (!pid_raw.has_value() || !epoch.has_value() || !leader_acct_raw.has_value() ||
      !leader_dev_raw.has_value() || !vis_raw.has_value() || !jm_raw.has_value() ||
      !rp_raw.has_value() || !pinned_relay.has_value() || !max_mem.has_value() ||
      !mem_cnt.has_value()) {
    return fail_c<PartySummary>(ErrorCode::corrupt,
                                MpClientError::http_response_schema);
  }
  const auto pid = PartyId::create(pid_raw.value());
  const auto leader_acct = AccountId::create(leader_acct_raw.value());
  const auto leader_dev = DeviceId::create(leader_dev_raw.value());
  if (!pid.has_value() || !leader_acct.has_value() || !leader_dev.has_value() ||
      vis_raw.value() > 1U || jm_raw.value() > 1U || rp_raw.value() > 2U ||
      max_mem.value() > 255U || mem_cnt.value() > 255U) {
    return fail_c<PartySummary>(ErrorCode::corrupt,
                                MpClientError::http_response_schema);
  }
  return Result<PartySummary>::success(PartySummary{
      pid.value(),
      epoch.value(),
      leader_acct.value(),
      leader_dev.value(),
      static_cast<PartyVisibility>(vis_raw.value()),
      static_cast<PartyJoinMode>(jm_raw.value()),
      static_cast<RelayPolicy>(rp_raw.value()),
      pinned_relay.value(),
      static_cast<std::uint8_t>(max_mem.value()),
      static_cast<std::uint8_t>(mem_cnt.value()),
  });
}

Result<CreatePartyInviteResponse>
MpControlClient::create_party_invite(const CreatePartyInviteRequest &request) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<CreatePartyInviteResponse>::failure(auth.error());
  }

  Value::Object body_obj;
  if (request.target_account_id.has_value()) {
    body_obj.emplace_back("target_account_id",
                          Value{Number{request.target_account_id->value()}});
  }
  body_obj.emplace_back("max_uses",
                        Value{Number{static_cast<std::uint64_t>(request.max_uses)}});
  body_obj.emplace_back("ttl_sec",
                        Value{Number{static_cast<std::uint64_t>(request.ttl_sec)}});

  auto body_bytes = dump_json_bytes(Value::object(std::move(body_obj)));
  if (!body_bytes.has_value()) {
    return Result<CreatePartyInviteResponse>::failure(body_bytes.error());
  }

  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/parties/" + request.party_id.to_decimal() + "/invites";
  req.query = "?";
  req.body = std::move(body_bytes).value();

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<CreatePartyInviteResponse>::failure(resp.error());
  }
  if (resp.value().status != 201) {
    return Result<CreatePartyInviteResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<CreatePartyInviteResponse>::failure(obj.error());
  }
  const auto inv_raw = get_required_u64(obj.value(), "party_invite_id");
  const auto exp_ms = get_required_u64(obj.value(), "expires_at_ms");
  if (!inv_raw.has_value() || !exp_ms.has_value()) {
    return fail_c<CreatePartyInviteResponse>(ErrorCode::corrupt,
                                             MpClientError::http_response_schema);
  }
  const auto inv_id = PartyInviteId::create(inv_raw.value());
  if (!inv_id.has_value()) {
    return fail_c<CreatePartyInviteResponse>(ErrorCode::corrupt,
                                             MpClientError::http_response_schema);
  }
  std::optional<std::string> link;
  if (const Value *link_field = obj.value().find("invite_link");
      link_field != nullptr &&
      !std::holds_alternative<std::nullptr_t>(link_field->value())) {
    const auto *s = std::get_if<std::string>(&link_field->value());
    if (s == nullptr) {
      return fail_c<CreatePartyInviteResponse>(ErrorCode::corrupt,
                                               MpClientError::http_response_schema);
    }
    link = *s;
  }
  return Result<CreatePartyInviteResponse>::success(
      CreatePartyInviteResponse{inv_id.value(), exp_ms.value(), std::move(link)});
}

Result<void> MpControlClient::revoke_party_invite(PartyId party_id,
                                                  PartyInviteId invite_id) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<void>::failure(auth.error());
  }
  RawHttpRequest req{};
  req.method = HttpMethod::del;
  req.path =
      "/v1/parties/" + party_id.to_decimal() + "/invites/" + invite_id.to_decimal();
  req.query = "?";

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<void>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<void>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }
  return Result<void>::success();
}

Result<JoinPartyResponse> MpControlClient::join_party(const JoinPartyRequest &request) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<JoinPartyResponse>::failure(auth.error());
  }
  const auto ep_bytes = request.endpoint.encode();
  if (!ep_bytes.has_value()) {
    return Result<JoinPartyResponse>::failure(ep_bytes.error());
  }

  Value::Object body_obj;
  body_obj.emplace_back("endpoint_b64", Value{base64_encode(ep_bytes.value())});
  if (request.invite_link.has_value() && !request.invite_link->empty()) {
    body_obj.emplace_back("invite_link", Value{*request.invite_link});
  }
  auto body_bytes = dump_json_bytes(Value::object(std::move(body_obj)));
  if (!body_bytes.has_value()) {
    return Result<JoinPartyResponse>::failure(body_bytes.error());
  }

  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/parties/" + request.party_id.to_decimal() + "/join";
  req.query = "?";
  req.body = std::move(body_bytes).value();
  CleanseVectorGuard body_cleanse{req.body};

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<JoinPartyResponse>::failure(resp.error());
  }
  if (resp.value().status != 200 && resp.value().status != 202) {
    return Result<JoinPartyResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<JoinPartyResponse>::failure(obj.error());
  }
  const auto status_str = get_required_string(obj.value(), "status");
  if (!status_str.has_value()) {
    return fail_c<JoinPartyResponse>(ErrorCode::corrupt,
                                     MpClientError::http_response_schema);
  }
  if (status_str.value() == "pending_approval") {
    const auto req_raw = get_required_u64(obj.value(), "request_id");
    if (!req_raw.has_value()) {
      return fail_c<JoinPartyResponse>(ErrorCode::corrupt,
                                       MpClientError::http_response_schema);
    }
    const auto rid = RequestId::create(req_raw.value());
    if (!rid.has_value()) {
      return fail_c<JoinPartyResponse>(ErrorCode::corrupt,
                                       MpClientError::http_response_schema);
    }
    return Result<JoinPartyResponse>::success(JoinPartyResponse{true, 0U, rid.value()});
  }
  if (status_str.value() == "joined") {
    const auto epoch = get_required_u64(obj.value(), "party_epoch");
    if (!epoch.has_value()) {
      return fail_c<JoinPartyResponse>(ErrorCode::corrupt,
                                       MpClientError::http_response_schema);
    }
    return Result<JoinPartyResponse>::success(
        JoinPartyResponse{false, epoch.value(), std::nullopt});
  }
  return fail_c<JoinPartyResponse>(ErrorCode::corrupt,
                                   MpClientError::http_response_schema);
}

Result<PartyMutationResponse>
MpControlClient::kick_member(const KickMemberRequest &request) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<PartyMutationResponse>::failure(auth.error());
  }
  Value::Object body_obj;
  body_obj.emplace_back("target_account_id",
                        Value{Number{request.target_account_id.value()}});
  body_obj.emplace_back("expected_party_epoch",
                        Value{Number{request.expected_party_epoch}});
  auto body_bytes = dump_json_bytes(Value::object(std::move(body_obj)));
  if (!body_bytes.has_value()) {
    return Result<PartyMutationResponse>::failure(body_bytes.error());
  }

  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/parties/" + request.party_id.to_decimal() + "/kick";
  req.query = "?";
  req.body = std::move(body_bytes).value();

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<PartyMutationResponse>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<PartyMutationResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<PartyMutationResponse>::failure(obj.error());
  }
  const auto epoch = get_required_u64(obj.value(), "party_epoch");
  if (!epoch.has_value()) {
    return fail_c<PartyMutationResponse>(ErrorCode::corrupt,
                                         MpClientError::http_response_schema);
  }
  return Result<PartyMutationResponse>::success(PartyMutationResponse{epoch.value()});
}

Result<PartyMutationResponse> MpControlClient::leave_party(PartyId party_id) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<PartyMutationResponse>::failure(auth.error());
  }
  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/parties/" + party_id.to_decimal() + "/leave";
  req.query = "?";

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<PartyMutationResponse>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<PartyMutationResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<PartyMutationResponse>::failure(obj.error());
  }
  const auto epoch = get_required_u64(obj.value(), "party_epoch");
  if (!epoch.has_value()) {
    return fail_c<PartyMutationResponse>(ErrorCode::corrupt,
                                         MpClientError::http_response_schema);
  }
  return Result<PartyMutationResponse>::success(PartyMutationResponse{epoch.value()});
}

Result<PartyMutationResponse>
MpControlClient::disband_party(const DisbandPartyRequest &request) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<PartyMutationResponse>::failure(auth.error());
  }
  Value::Object body_obj;
  body_obj.emplace_back("expected_party_epoch",
                        Value{Number{request.expected_party_epoch}});
  auto body_bytes = dump_json_bytes(Value::object(std::move(body_obj)));
  if (!body_bytes.has_value()) {
    return Result<PartyMutationResponse>::failure(body_bytes.error());
  }

  RawHttpRequest req{};
  req.method = HttpMethod::post;
  req.path = "/v1/parties/" + request.party_id.to_decimal() + "/disband";
  req.query = "?";
  req.body = std::move(body_bytes).value();

  const auto resp = signed_rest_call(
      config_, clock_offset_s_, auth.value().signing_key,
      KeyId{DeviceKeyId{auth.value().account_id, auth.value().device_id}}, req);
  if (!resp.has_value()) {
    return Result<PartyMutationResponse>::failure(resp.error());
  }
  if (resp.value().status != 200) {
    return Result<PartyMutationResponse>::failure(
        map_http_error(resp.value().status, response_is_clock_skew(resp.value())));
  }

  const std::string_view text{reinterpret_cast<const char *>(resp.value().body.data()),
                              resp.value().body.size()};
  const auto obj = parse_json_object_body(text);
  if (!obj.has_value()) {
    return Result<PartyMutationResponse>::failure(obj.error());
  }
  const auto epoch = get_required_u64(obj.value(), "party_epoch");
  if (!epoch.has_value()) {
    return fail_c<PartyMutationResponse>(ErrorCode::corrupt,
                                         MpClientError::http_response_schema);
  }
  return Result<PartyMutationResponse>::success(PartyMutationResponse{epoch.value()});
}

Result<MpControlSocket> MpControlClient::connect_account_socket() {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<MpControlSocket>::failure(auth.error());
  }
  auto sock = MpControlSocket::connect(
      MpSocketConnectRequest{config_, "/v1/ws", auth.value().account_id,
                             auth.value().device_id, clock_offset_s_},
      auth.value().signing_key);
  if (sock.has_value() ||
      mp_client_error_of(sock.error()) != MpClientError::http_clock_skew) {
    return sock;
  }
  const auto h = health();
  if (!h.has_value() || !h.value().ok) {
    return sock;
  }
  const auto next_offset =
      checked_sub_i64(static_cast<std::int64_t>(h.value().server_now_ms / 1000U),
                      current_unix_seconds());
  if (!next_offset.has_value()) {
    return sock;
  }
  clock_offset_s_ = *next_offset;
  return MpControlSocket::connect(
      MpSocketConnectRequest{config_, "/v1/ws", auth.value().account_id,
                             auth.value().device_id, clock_offset_s_},
      auth.value().signing_key);
}

Result<MpControlSocket> MpControlClient::connect_party_socket(PartyId party_id) {
  auto auth = require_device_auth(identity_);
  if (!auth.has_value()) {
    return Result<MpControlSocket>::failure(auth.error());
  }
  const std::string path = "/v1/parties/" + party_id.to_decimal() + "/ws";
  auto sock = MpControlSocket::connect(
      MpSocketConnectRequest{config_, path, auth.value().account_id,
                             auth.value().device_id, clock_offset_s_},
      auth.value().signing_key);
  if (sock.has_value() ||
      mp_client_error_of(sock.error()) != MpClientError::http_clock_skew) {
    return sock;
  }
  const auto h = health();
  if (!h.has_value() || !h.value().ok) {
    return sock;
  }
  const auto next_offset =
      checked_sub_i64(static_cast<std::int64_t>(h.value().server_now_ms / 1000U),
                      current_unix_seconds());
  if (!next_offset.has_value()) {
    return sock;
  }
  clock_offset_s_ = *next_offset;
  return MpControlSocket::connect(
      MpSocketConnectRequest{config_, path, auth.value().account_id,
                             auth.value().device_id, clock_offset_s_},
      auth.value().signing_key);
}

} // namespace blackbird::mp
