#include "blackbird/party_lobby.hpp"

#include "blackbird/board_bridge.hpp"
#include "blackbird/json.hpp"
#include "blackbird/process_lifetime.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <limits>
#include <map>
#include <mutex>
#include <poll.h>
#include <ranges>
#include <set>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace blackbird {
namespace {

namespace fs = std::filesystem;
using SteadyClock = std::chrono::steady_clock;

constexpr std::string_view kLeaseSigningType = "blackbird.party_lease";
constexpr std::string_view kHeartbeatSigningType = "blackbird.party_heartbeat";
constexpr std::size_t kMaxHostBytes = 256U;
constexpr std::size_t kMaxModelBytes = 128U;
constexpr std::size_t kMaxSshTargetBytes = 256U;
constexpr std::size_t kMaxTargetBytes = 128U;
constexpr std::size_t kMaxConfigurableLineBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaxReadBytesPerTurn = 64U * 1024U;
constexpr std::size_t kMaxFramesPerTurn = 16U;
constexpr std::size_t kMaxEmptyLinesPerTurn = 16U;
constexpr int kPollSliceMs = 250;

Error native_error(int err) noexcept {
  if (err == EINTR)
    return {ErrorCode::interrupted, err};
  if (err == ENOTSUP)
    return {ErrorCode::unsupported, err};
  return {ErrorCode::io, err};
}

std::int64_t wall_now_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return ns <= 0 ? 1 : static_cast<std::int64_t>(ns);
}

char lower_ascii(char ch) noexcept {
  return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
}

struct CiLhs {
  std::string_view value;
};
struct CiRhs {
  std::string_view value;
};

bool equals_ci(CiLhs lhs, CiRhs rhs) noexcept {
  if (lhs.value.size() != rhs.value.size())
    return false;
  for (std::size_t i = 0; i < lhs.value.size(); ++i) {
    if (lower_ascii(lhs.value[i]) != lower_ascii(rhs.value[i]))
      return false;
  }
  return true;
}

bool is_ascii_space(char ch) noexcept {
  return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\v' ||
         ch == '\f';
}

std::string_view trim_ascii(std::string_view text) noexcept {
  while (!text.empty() && is_ascii_space(text.front()))
    text.remove_prefix(1);
  while (!text.empty() && is_ascii_space(text.back()))
    text.remove_suffix(1);
  return text;
}

struct DecodedUtf8 {
  char32_t scalar = 0;
  std::size_t length = 0;
};

DecodedUtf8 decode_utf8_at(std::string_view text, std::size_t offset) noexcept {
  if (offset >= text.size())
    return {};
  const auto b0 = static_cast<unsigned char>(text[offset]);
  if (b0 < 0x80U)
    return {static_cast<char32_t>(b0), 1U};
  if ((b0 & 0xe0U) == 0xc0U) {
    if (b0 < 0xc2U || offset + 1U >= text.size())
      return {};
    const auto b1 = static_cast<unsigned char>(text[offset + 1U]);
    if ((b1 & 0xc0U) != 0x80U)
      return {};
    return {(static_cast<char32_t>(b0 & 0x1fU) << 6U) |
                static_cast<char32_t>(b1 & 0x3fU),
            2U};
  }
  if ((b0 & 0xf0U) == 0xe0U) {
    if (offset + 2U >= text.size())
      return {};
    const auto b1 = static_cast<unsigned char>(text[offset + 1U]);
    const auto b2 = static_cast<unsigned char>(text[offset + 2U]);
    if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U)
      return {};
    if ((b0 == 0xe0U && b1 < 0xa0U) || (b0 == 0xedU && b1 >= 0xa0U))
      return {};
    return {(static_cast<char32_t>(b0 & 0x0fU) << 12U) |
                (static_cast<char32_t>(b1 & 0x3fU) << 6U) |
                static_cast<char32_t>(b2 & 0x3fU),
            3U};
  }
  if ((b0 & 0xf8U) == 0xf0U) {
    if (b0 > 0xf4U || offset + 3U >= text.size())
      return {};
    const auto b1 = static_cast<unsigned char>(text[offset + 1U]);
    const auto b2 = static_cast<unsigned char>(text[offset + 2U]);
    const auto b3 = static_cast<unsigned char>(text[offset + 3U]);
    if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U || (b3 & 0xc0U) != 0x80U)
      return {};
    if ((b0 == 0xf0U && b1 < 0x90U) || (b0 == 0xf4U && b1 >= 0x90U))
      return {};
    return {(static_cast<char32_t>(b0 & 0x07U) << 18U) |
                (static_cast<char32_t>(b1 & 0x3fU) << 12U) |
                (static_cast<char32_t>(b2 & 0x3fU) << 6U) |
                static_cast<char32_t>(b3 & 0x3fU),
            4U};
  }
  return {};
}

bool is_forbidden_control_scalar(char32_t cp) noexcept {
  if (cp < 0x20U || (cp >= 0x7fU && cp <= 0x9fU))
    return true;
  return (cp >= 0x202aU && cp <= 0x202eU) || (cp >= 0x2066U && cp <= 0x2069U) ||
         cp == 0x200eU || cp == 0x200fU || cp == 0x061cU || cp == 0xfeffU;
}

bool has_visible_content_after_stripping_escapes(std::string_view text) noexcept {
  std::size_t i = 0;
  while (i < text.size()) {
    const auto b0 = static_cast<unsigned char>(text[i]);
    // 7-bit ESC sequences (CSI, OSC, DCS/SOS/PM/APC, 2-byte ESC).
    if (b0 == 0x1bU) {
      ++i;
      if (i >= text.size())
        break;
      const auto b1 = static_cast<unsigned char>(text[i]);
      if (b1 == '[') {
        ++i;
        while (i < text.size()) {
          const auto c = static_cast<unsigned char>(text[i++]);
          if (c >= 0x40U && c <= 0x7eU)
            break;
        }
      } else if (b1 == ']' || b1 == 'P' || b1 == 'X' || b1 == '^' || b1 == '_') {
        ++i;
        while (i < text.size()) {
          const auto c = static_cast<unsigned char>(text[i++]);
          if (c == 0x07U)
            break;
          if (c == 0x1bU && i < text.size() && text[i] == '\\') {
            ++i;
            break;
          }
          if (c == 0x9cU)
            break;
        }
      } else {
        ++i;
      }
      continue;
    }
    // Raw 8-bit C1 CSI (0x9B) or OSC/DCS/SOS/PM/APC (0x9D/0x90/0x98/0x9E/0x9F).
    if (b0 == 0x9bU) {
      ++i;
      while (i < text.size()) {
        const auto c = static_cast<unsigned char>(text[i++]);
        if (c >= 0x40U && c <= 0x7eU)
          break;
      }
      continue;
    }
    if (b0 == 0x9dU || b0 == 0x90U || b0 == 0x98U || b0 == 0x9eU || b0 == 0x9fU) {
      ++i;
      while (i < text.size()) {
        const auto c = static_cast<unsigned char>(text[i++]);
        if (c == 0x07U || c == 0x9cU)
          break;
        if (c == 0x1bU && i < text.size() && text[i] == '\\') {
          ++i;
          break;
        }
      }
      continue;
    }
    // UTF-8 encoded C1 CSI (C2 9B) / OSC/DCS/SOS/PM/APC.
    if (b0 == 0xc2U && i + 1U < text.size()) {
      const auto b1 = static_cast<unsigned char>(text[i + 1U]);
      if (b1 == 0x9bU) {
        i += 2U;
        while (i < text.size()) {
          const auto c = static_cast<unsigned char>(text[i++]);
          if (c >= 0x40U && c <= 0x7eU)
            break;
        }
        continue;
      }
      if (b1 == 0x9dU || b1 == 0x90U || b1 == 0x98U || b1 == 0x9eU || b1 == 0x9fU) {
        i += 2U;
        while (i < text.size()) {
          const auto c = static_cast<unsigned char>(text[i++]);
          if (c == 0x07U || c == 0x9cU)
            break;
          if (c == 0x1bU && i < text.size() && text[i] == '\\') {
            ++i;
            break;
          }
          if (c == 0xc2U && i < text.size() &&
              static_cast<unsigned char>(text[i]) == 0x9cU) {
            ++i;
            break;
          }
        }
        continue;
      }
    }

    const DecodedUtf8 dec = decode_utf8_at(text, i);
    if (dec.length == 0U) {
      ++i;
      continue;
    }
    i += dec.length;
    if (is_forbidden_control_scalar(dec.scalar))
      continue;
    if (dec.scalar <= 0x20U && is_ascii_space(static_cast<char>(dec.scalar)))
      continue;
    return true;
  }
  return false;
}

bool valid_field_token(std::string_view text, std::size_t max_bytes,
                       bool allow_empty) noexcept {
  if (text.empty())
    return allow_empty;
  if (text.size() > max_bytes || !valid_utf8(text))
    return false;
  std::size_t i = 0;
  while (i < text.size()) {
    const DecodedUtf8 dec = decode_utf8_at(text, i);
    if (dec.length == 0U)
      return false;
    if (dec.scalar <= 0x20U || is_forbidden_control_scalar(dec.scalar))
      return false;
    i += dec.length;
  }
  return true;
}

bool valid_lease_role(PartyMemberRole role) noexcept {
  return role == PartyMemberRole::operator_human ||
         role == PartyMemberRole::platoon_leader || role == PartyMemberRole::worker;
}

std::optional<std::string> extract_trusted_ssh_target(std::string_view trust_note) {
  constexpr std::string_view kPrefix = "ssh_target=";
  std::size_t pos = 0;
  while (pos < trust_note.size()) {
    while (pos < trust_note.size() &&
           (is_ascii_space(trust_note[pos]) || trust_note[pos] == ';' ||
            trust_note[pos] == ',')) {
      ++pos;
    }
    const std::size_t start = pos;
    while (pos < trust_note.size() && !is_ascii_space(trust_note[pos]) &&
           trust_note[pos] != ';' && trust_note[pos] != ',') {
      ++pos;
    }
    const std::string_view token = trust_note.substr(start, pos - start);
    if (token.starts_with(kPrefix)) {
      const std::string_view value = token.substr(kPrefix.size());
      if (valid_field_token(value, kMaxSshTargetBytes, false) &&
          !value.starts_with('-')) {
        return std::string{value};
      }
    }
  }
  return std::nullopt;
}

std::string normalize_target_label(std::string_view raw) {
  const std::string_view trimmed = trim_ascii(raw);
  if (trimmed.empty() || equals_ci(CiLhs{trimmed}, CiRhs{"all"}) ||
      equals_ci(CiLhs{trimmed}, CiRhs{"@all"})) {
    return "@all";
  }
  std::string sanitized = party_chat_sanitize(trimmed, kMaxTargetBytes);
  if (sanitized.empty())
    return "@all";
  if (sanitized.front() != '@')
    sanitized.insert(sanitized.begin(), '@');
  return sanitized;
}

// ---------------------------------------------------------------------------
// Strict Base64 encoder/decoder for signature_b64
// ---------------------------------------------------------------------------

std::string base64_encode(std::string_view input) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((input.size() + 2U) / 3U) * 4U);
  std::size_t i = 0;
  while (i + 3U <= input.size()) {
    const std::uint32_t v =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1U])) << 8U) |
        static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 2U]));
    out.push_back(kAlphabet[(v >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(v >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(v >> 6U) & 0x3fU]);
    out.push_back(kAlphabet[v & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = input.size() - i;
  if (rem == 1U) {
    const std::uint32_t v =
        static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16U;
    out.push_back(kAlphabet[(v >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(v >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t v =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1U])) << 8U);
    out.push_back(kAlphabet[(v >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(v >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(v >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

int base64_value(char ch) noexcept {
  if (ch >= 'A' && ch <= 'Z')
    return ch - 'A';
  if (ch >= 'a' && ch <= 'z')
    return 26 + (ch - 'a');
  if (ch >= '0' && ch <= '9')
    return 52 + (ch - '0');
  if (ch == '+')
    return 62;
  if (ch == '/')
    return 63;
  return -1;
}

Result<std::string> base64_decode_strict(std::string_view encoded,
                                         std::size_t max_decoded_bytes) {
  if (encoded.empty() || encoded.size() > kPartyLobbyMaxSignatureB64Bytes ||
      (encoded.size() % 4U) != 0U) {
    return Result<std::string>::failure({ErrorCode::invalid_identity});
  }
  std::string out;
  out.reserve((encoded.size() / 4U) * 3U);
  for (std::size_t i = 0; i < encoded.size(); i += 4U) {
    const bool last_block = (i + 4U == encoded.size());
    const char c0 = encoded[i];
    const char c1 = encoded[i + 1U];
    const char c2 = encoded[i + 2U];
    const char c3 = encoded[i + 3U];
    const int v0 = base64_value(c0);
    const int v1 = base64_value(c1);
    if (v0 < 0 || v1 < 0)
      return Result<std::string>::failure({ErrorCode::invalid_identity});

    if (c2 == '=') {
      if (!last_block || c3 != '=')
        return Result<std::string>::failure({ErrorCode::invalid_identity});
      if ((v1 & 0x0f) != 0)
        return Result<std::string>::failure({ErrorCode::invalid_identity});
      const auto b0 = static_cast<unsigned char>((v0 << 2) | (v1 >> 4));
      if (out.size() + 1U > max_decoded_bytes)
        return Result<std::string>::failure({ErrorCode::capacity});
      out.push_back(static_cast<char>(b0));
    } else if (c3 == '=') {
      if (!last_block)
        return Result<std::string>::failure({ErrorCode::invalid_identity});
      const int v2 = base64_value(c2);
      if (v2 < 0 || (v2 & 0x03) != 0)
        return Result<std::string>::failure({ErrorCode::invalid_identity});
      if (out.size() + 2U > max_decoded_bytes)
        return Result<std::string>::failure({ErrorCode::capacity});
      out.push_back(static_cast<char>((v0 << 2) | (v1 >> 4)));
      out.push_back(static_cast<char>(((v1 & 0x0f) << 4) | (v2 >> 2)));
    } else {
      const int v2 = base64_value(c2);
      const int v3 = base64_value(c3);
      if (v2 < 0 || v3 < 0)
        return Result<std::string>::failure({ErrorCode::invalid_identity});
      if (out.size() + 3U > max_decoded_bytes)
        return Result<std::string>::failure({ErrorCode::capacity});
      out.push_back(static_cast<char>((v0 << 2) | (v1 >> 4)));
      out.push_back(static_cast<char>(((v1 & 0x0f) << 4) | (v2 >> 2)));
      out.push_back(static_cast<char>(((v2 & 0x03) << 6) | v3));
    }
  }
  return Result<std::string>::success(std::move(out));
}

// ---------------------------------------------------------------------------
// File descriptor & Unix socket helpers
// ---------------------------------------------------------------------------

class ScopedFd {
public:
  ScopedFd() = default;
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
      const int saved = errno;
      (void)::close(fd_);
      errno = saved;
    }
    fd_ = next;
  }

private:
  int fd_ = -1;
};

Result<ScopedFd> configure_socket_fd(int raw_fd) noexcept {
  if (raw_fd < 0)
    return Result<ScopedFd>::failure(native_error(errno));
  ScopedFd fd{raw_fd};
  const int fd_flags = ::fcntl(fd.get(), F_GETFD);
  const int fl_flags = ::fcntl(fd.get(), F_GETFL);
  if (fd_flags < 0 || fl_flags < 0 ||
      ::fcntl(fd.get(), F_SETFD, fd_flags | FD_CLOEXEC) < 0 ||
      ::fcntl(fd.get(), F_SETFL, fl_flags | O_NONBLOCK) < 0) {
    return Result<ScopedFd>::failure(native_error(errno));
  }
#ifdef SO_NOSIGPIPE
  const int enabled = 1;
  if (::setsockopt(fd.get(), SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) !=
      0) {
    return Result<ScopedFd>::failure(native_error(errno));
  }
#endif
  return Result<ScopedFd>::success(std::move(fd));
}

Result<ScopedFd> create_unix_stream_socket() noexcept {
  const std::lock_guard spawn{detail::process_spawn_mutex};
  return configure_socket_fd(::socket(AF_UNIX, SOCK_STREAM, 0));
}

Result<sockaddr_un> make_unix_address(const fs::path &socket_path) noexcept {
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  const std::string &native = socket_path.native();
  if (native.empty() || native.find('\0') != std::string::npos ||
      native.size() >= sizeof(addr.sun_path)) {
    return Result<sockaddr_un>::failure({ErrorCode::invalid_range});
  }
  std::memcpy(addr.sun_path, native.data(), native.size());
  addr.sun_path[native.size()] = '\0';
  return Result<sockaddr_un>::success(addr);
}

Result<void> verify_peer_same_uid(int fd) noexcept {
#if defined(__linux__)
  ucred credentials{};
  socklen_t len = sizeof(credentials);
  if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &len) != 0)
    return Result<void>::failure(native_error(errno));
  if (len != sizeof(credentials) || credentials.uid != ::geteuid())
    return Result<void>::failure({ErrorCode::invalid_identity});
  return Result<void>::success();
#else
  uid_t peer_uid = 0;
  gid_t peer_gid = 0;
  if (::getpeereid(fd, &peer_uid, &peer_gid) != 0)
    return Result<void>::failure(native_error(errno));
  if (peer_uid != ::geteuid())
    return Result<void>::failure({ErrorCode::invalid_identity});
  return Result<void>::success();
#endif
}

ssize_t send_nosigpipe(int fd, const void *data, std::size_t size) noexcept {
#ifdef MSG_NOSIGNAL
  return ::send(fd, data, size, MSG_NOSIGNAL);
#else
  return ::send(fd, data, size, 0);
#endif
}

Result<ScopedFd> open_or_create_private_dir(const fs::path &dir_path) {
  std::string path_str = dir_path.string();
  if (path_str.empty() || path_str.find('\0') != std::string::npos)
    return Result<ScopedFd>::failure({ErrorCode::invalid_range});
  while (path_str.size() > 1U && path_str.back() == '/')
    path_str.pop_back();

  bool created = false;
  if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
    created = true;
  } else if (errno == ENOENT) {
    const fs::path parent = fs::path{path_str}.parent_path();
    if (!parent.empty()) {
      std::error_code ec;
      (void)fs::create_directories(parent, ec);
      if (ec)
        return Result<ScopedFd>::failure({ErrorCode::io, ec.value()});
    }
    if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
      created = true;
    } else if (errno != EEXIST) {
      return Result<ScopedFd>::failure(native_error(errno));
    }
  } else if (errno != EEXIST) {
    return Result<ScopedFd>::failure(native_error(errno));
  }

  int raw_fd = -1;
  do {
    raw_fd = ::open(path_str.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (raw_fd < 0 && errno == EINTR);
  if (raw_fd < 0)
    return Result<ScopedFd>::failure(native_error(errno));
  ScopedFd dir_fd{raw_fd};

  if (created && ::fchmod(dir_fd.get(), mode_t{0700}) != 0)
    return Result<ScopedFd>::failure(native_error(errno));

  struct stat st{};
  if (::fstat(dir_fd.get(), &st) != 0)
    return Result<ScopedFd>::failure(native_error(errno));
  if (!S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 0077) != 0)
    return Result<ScopedFd>::failure({ErrorCode::io, EPERM});
  return Result<ScopedFd>::success(std::move(dir_fd));
}

Result<void> wait_fd_ready(int fd, short events,
                           SteadyClock::time_point deadline) noexcept {
  for (;;) {
    const auto now = SteadyClock::now();
    if (now >= deadline)
      return Result<void>::failure({ErrorCode::interrupted, ETIMEDOUT});
    const auto rem_ms =
        std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
    const int timeout_ms =
        static_cast<int>(std::clamp<std::int64_t>(rem_ms, 1, INT_MAX));
    pollfd entry{fd, events, 0};
    const int rc = ::poll(&entry, 1, timeout_ms);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
      return Result<void>::failure(native_error(errno));
    }
    if (rc == 0)
      continue;
    if ((entry.revents & POLLNVAL) != 0)
      return Result<void>::failure({ErrorCode::io, EBADF});
    return Result<void>::success();
  }
}

Result<void> write_all_timed(int fd, std::string_view payload,
                             SteadyClock::time_point deadline) noexcept {
  std::size_t offset = 0;
  while (offset < payload.size()) {
    const ssize_t written =
        send_nosigpipe(fd, payload.data() + offset, payload.size() - offset);
    if (written > 0) {
      offset += static_cast<std::size_t>(written);
      continue;
    }
    if (written == 0)
      return Result<void>::failure({ErrorCode::io, EPIPE});
    if (errno == EINTR)
      continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      auto ready = wait_fd_ready(fd, POLLOUT, deadline);
      if (!ready.has_value())
        return ready;
      continue;
    }
    return Result<void>::failure(native_error(errno));
  }
  return Result<void>::success();
}

Result<std::string> read_line_timed(int fd, std::string &buffer,
                                    std::size_t max_line_bytes,
                                    SteadyClock::time_point deadline) {
  std::array<char, 8192> chunk{};
  for (;;) {
    const std::size_t nl = buffer.find('\n');
    if (nl != std::string::npos) {
      if (nl + 1U > max_line_bytes) {
        buffer.clear();
        return Result<std::string>::failure({ErrorCode::capacity});
      }
      std::string line = buffer.substr(0, nl);
      buffer.erase(0, nl + 1U);
      if (!line.empty() && line.back() == '\r')
        line.pop_back();
      return Result<std::string>::success(std::move(line));
    }
    if (buffer.size() >= max_line_bytes) {
      buffer.clear();
      return Result<std::string>::failure({ErrorCode::capacity});
    }

    auto ready = wait_fd_ready(fd, POLLIN, deadline);
    if (!ready.has_value())
      return Result<std::string>::failure(ready.error());

    const std::size_t room = max_line_bytes - buffer.size();
    const std::size_t to_read = room < chunk.size() ? (room + 1U) : chunk.size();
    const ssize_t n = ::recv(fd, chunk.data(), to_read, 0);
    if (n > 0) {
      const auto count = static_cast<std::size_t>(n);
      if (buffer.size() + count > max_line_bytes) {
        const std::string_view piece{chunk.data(), count};
        const std::size_t piece_nl = piece.find('\n');
        if (piece_nl == std::string_view::npos ||
            buffer.size() + piece_nl + 1U > max_line_bytes) {
          buffer.clear();
          return Result<std::string>::failure({ErrorCode::capacity});
        }
      }
      buffer.append(chunk.data(), count);
      continue;
    }
    if (n == 0)
      return Result<std::string>::failure({ErrorCode::io, ECONNRESET});
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
      continue;
    return Result<std::string>::failure(native_error(errno));
  }
}

// ---------------------------------------------------------------------------
// JSON parsing & serialization helpers
// ---------------------------------------------------------------------------

Result<std::int64_t> parse_int64_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  const std::string text = num->text();
  std::int64_t out = 0;
  const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), out);
  if (ec != std::errc{} || ptr != text.data() + text.size())
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  return Result<std::int64_t>::success(out);
}

Result<std::uint64_t> parse_uint64_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return Result<std::uint64_t>::failure({ErrorCode::corrupt});
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return Result<std::uint64_t>::failure({ErrorCode::corrupt});
  const std::string text = num->text();
  std::uint64_t out = 0;
  const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), out);
  if (ec != std::errc{} || ptr != text.data() + text.size())
    return Result<std::uint64_t>::failure({ErrorCode::corrupt});
  return Result<std::uint64_t>::success(out);
}

Result<std::string> parse_string_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return Result<std::string>::failure({ErrorCode::corrupt});
  const auto *str = std::get_if<std::string>(&field->value());
  if (!str)
    return Result<std::string>::failure({ErrorCode::corrupt});
  return Result<std::string>::success(*str);
}

Result<bool> parse_bool_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return Result<bool>::failure({ErrorCode::corrupt});
  const auto *flag = std::get_if<bool>(&field->value());
  if (!flag)
    return Result<bool>::failure({ErrorCode::corrupt});
  return Result<bool>::success(*flag);
}

Result<std::optional<std::string>> parse_optional_string_field(const Value &obj,
                                                               std::string_view key) {
  const Value *field = obj.find(key);
  if (!field || std::holds_alternative<std::nullptr_t>(field->value()))
    return Result<std::optional<std::string>>::success(std::nullopt);
  const auto *str = std::get_if<std::string>(&field->value());
  if (!str)
    return Result<std::optional<std::string>>::failure({ErrorCode::corrupt});
  return Result<std::optional<std::string>>::success(*str);
}

Value lease_to_wire_value(const PartyLease &lease, bool include_ssh_target) {
  Value::Object obj{
      {"room_id", Value{lease.room_id}},
      {"actor_fingerprint", Value{lease.actor_fingerprint}},
      {"alias", Value{lease.alias}},
      {"role", Value{std::string{party_member_role_name(lease.role)}}},
      {"host", Value{lease.host}},
      {"model", Value{lease.model}},
      {"issued_ns", Value{Number{lease.issued_ns}}},
      {"expires_ns", Value{Number{lease.expires_ns}}},
      {"lease_seq", Value{Number{lease.lease_seq}}},
      {"revocation_epoch", Value{Number{lease.revocation_epoch}}},
      {"signature_b64", Value{lease.signature_b64}},
  };
  if (include_ssh_target && lease.ssh_target.has_value())
    obj.emplace_back("ssh_target", Value{*lease.ssh_target});
  return Value::object(std::move(obj));
}

Result<PartyLease> lease_from_wire_value(const Value &value,
                                         bool allow_trusted_ssh_target) {
  if (!std::holds_alternative<Value::Object>(value.value()))
    return Result<PartyLease>::failure({ErrorCode::corrupt});
  auto room_id = parse_string_field(value, "room_id");
  auto actor_fp = parse_string_field(value, "actor_fingerprint");
  auto alias = parse_string_field(value, "alias");
  auto role_str = parse_string_field(value, "role");
  auto host = parse_string_field(value, "host");
  auto model = parse_string_field(value, "model");
  auto issued_ns = parse_int64_field(value, "issued_ns");
  auto expires_ns = parse_int64_field(value, "expires_ns");
  auto lease_seq = parse_uint64_field(value, "lease_seq");
  auto rev_epoch = parse_uint64_field(value, "revocation_epoch");
  auto sig_b64 = parse_string_field(value, "signature_b64");
  if (!room_id.has_value() || !actor_fp.has_value() || !alias.has_value() ||
      !role_str.has_value() || !host.has_value() || !model.has_value() ||
      !issued_ns.has_value() || !expires_ns.has_value() || !lease_seq.has_value() ||
      !rev_epoch.has_value() || !sig_b64.has_value()) {
    return Result<PartyLease>::failure({ErrorCode::corrupt});
  }
  auto role = parse_party_member_role(role_str.value());
  if (!role.has_value() || !valid_lease_role(role.value()))
    return Result<PartyLease>::failure({ErrorCode::corrupt});

  std::optional<std::string> ssh_target;
  if (allow_trusted_ssh_target) {
    auto parsed_ssh = parse_optional_string_field(value, "ssh_target");
    if (!parsed_ssh.has_value())
      return Result<PartyLease>::failure({ErrorCode::corrupt});
    ssh_target = std::move(parsed_ssh).value();
  }
  // When allow_trusted_ssh_target is false (server ingest from wire), any
  // untrusted wire `ssh_target` field is intentionally ignored and dropped.

  return Result<PartyLease>::success(PartyLease{
      std::move(room_id).value(),
      std::move(actor_fp).value(),
      std::move(alias).value(),
      role.value(),
      std::move(host).value(),
      std::move(model).value(),
      std::move(ssh_target),
      issued_ns.value(),
      expires_ns.value(),
      lease_seq.value(),
      rev_epoch.value(),
      std::move(sig_b64).value(),
  });
}

Value participant_to_value(const PartyParticipant &p) {
  return Value::object({
      {"id", Value{p.id}},
      {"display_name", Value{p.display_name}},
      {"role", Value{std::string{party_member_role_name(p.role)}}},
      {"host", Value{p.host}},
      {"model", Value{p.model}},
      {"fingerprint", Value{p.fingerprint}},
      {"state", Value{std::string{party_participant_state_name(p.state)}}},
      {"last_seen_ns", Value{Number{p.last_seen_ns}}},
      {"ssh_target", p.ssh_target.has_value() ? Value{*p.ssh_target} : Value{nullptr}},
      {"remote_session",
       p.remote_session.has_value() ? Value{*p.remote_session} : Value{nullptr}},
      {"provider", p.provider.has_value() ? Value{*p.provider} : Value{nullptr}},
      {"remote_model",
       p.remote_model.has_value() ? Value{*p.remote_model} : Value{nullptr}},
      {"local_self", Value{p.local_self}},
  });
}

Result<PartyParticipant> participant_from_value(const Value &value) {
  if (!std::holds_alternative<Value::Object>(value.value()))
    return Result<PartyParticipant>::failure({ErrorCode::corrupt});
  auto id = parse_string_field(value, "id");
  auto display_name = parse_string_field(value, "display_name");
  auto role_str = parse_string_field(value, "role");
  auto host = parse_string_field(value, "host");
  auto model = parse_string_field(value, "model");
  auto fp = parse_string_field(value, "fingerprint");
  auto state_str = parse_string_field(value, "state");
  auto last_seen_ns = parse_int64_field(value, "last_seen_ns");
  auto ssh_target = parse_optional_string_field(value, "ssh_target");
  auto remote_session = parse_optional_string_field(value, "remote_session");
  auto provider = parse_optional_string_field(value, "provider");
  auto remote_model = parse_optional_string_field(value, "remote_model");
  auto local_self = parse_bool_field(value, "local_self");
  if (!id.has_value() || !display_name.has_value() || !role_str.has_value() ||
      !host.has_value() || !model.has_value() || !fp.has_value() ||
      !state_str.has_value() || !last_seen_ns.has_value() || !ssh_target.has_value() ||
      !remote_session.has_value() || !provider.has_value() ||
      !remote_model.has_value() || !local_self.has_value()) {
    return Result<PartyParticipant>::failure({ErrorCode::corrupt});
  }
  auto role = parse_party_member_role(role_str.value());
  auto state = parse_party_participant_state(state_str.value());
  if (!role.has_value() || !state.has_value())
    return Result<PartyParticipant>::failure({ErrorCode::corrupt});
  return Result<PartyParticipant>::success(PartyParticipant{
      std::move(id).value(),
      std::move(display_name).value(),
      role.value(),
      std::move(host).value(),
      std::move(model).value(),
      std::move(fp).value(),
      state.value(),
      last_seen_ns.value(),
      std::move(ssh_target).value(),
      std::move(remote_session).value(),
      std::move(provider).value(),
      std::move(remote_model).value(),
      local_self.value(),
  });
}

Value message_to_value(const PartyMessage &m) {
  return Value::object({
      {"id", Value{m.id}},
      {"timestamp_ns", Value{Number{m.timestamp_ns}}},
      {"sender_id", Value{m.sender_id}},
      {"sender_role", Value{std::string{party_member_role_name(m.sender_role)}}},
      {"sender_host", Value{m.sender_host}},
      {"sender_model", Value{m.sender_model}},
      {"sender_fingerprint", Value{m.sender_fingerprint}},
      {"verified_peer", Value{m.verified_peer}},
      {"target", Value{m.target}},
      {"kind", Value{std::string{party_message_kind_name(m.kind)}}},
      {"body", Value{m.body}},
      {"untrusted_remote", Value{m.untrusted_remote}},
  });
}

Result<PartyMessage> message_from_value(const Value &value) {
  if (!std::holds_alternative<Value::Object>(value.value()))
    return Result<PartyMessage>::failure({ErrorCode::corrupt});
  auto id = parse_string_field(value, "id");
  auto ts = parse_int64_field(value, "timestamp_ns");
  auto sender_id = parse_string_field(value, "sender_id");
  auto role_str = parse_string_field(value, "sender_role");
  auto sender_host = parse_string_field(value, "sender_host");
  auto sender_model = parse_string_field(value, "sender_model");
  auto sender_fp = parse_string_field(value, "sender_fingerprint");
  auto verified = parse_bool_field(value, "verified_peer");
  auto target = parse_string_field(value, "target");
  auto kind_str = parse_string_field(value, "kind");
  auto body = parse_string_field(value, "body");
  auto untrusted = parse_bool_field(value, "untrusted_remote");
  if (!id.has_value() || !ts.has_value() || !sender_id.has_value() ||
      !role_str.has_value() || !sender_host.has_value() || !sender_model.has_value() ||
      !sender_fp.has_value() || !verified.has_value() || !target.has_value() ||
      !kind_str.has_value() || !body.has_value() || !untrusted.has_value()) {
    return Result<PartyMessage>::failure({ErrorCode::corrupt});
  }
  auto role = parse_party_member_role(role_str.value());
  auto kind = parse_party_message_kind(kind_str.value());
  if (!role.has_value() || !kind.has_value())
    return Result<PartyMessage>::failure({ErrorCode::corrupt});
  return Result<PartyMessage>::success(PartyMessage{
      std::move(id).value(),
      ts.value(),
      std::move(sender_id).value(),
      role.value(),
      std::move(sender_host).value(),
      std::move(sender_model).value(),
      std::move(sender_fp).value(),
      verified.value(),
      std::move(target).value(),
      kind.value(),
      std::move(body).value(),
      untrusted.value(),
      std::nullopt,
  });
}

Value snapshot_to_value(const PartySnapshot &snap) {
  Value::Array participants;
  participants.reserve(snap.participants.size());
  for (const auto &p : snap.participants)
    participants.push_back(participant_to_value(p));

  Value::Array messages;
  messages.reserve(snap.messages.size());
  for (const auto &m : snap.messages)
    messages.push_back(message_to_value(m));

  Value::Array conflicts;
  conflicts.reserve(snap.conflicts.size());
  for (const auto &c : snap.conflicts) {
    conflicts.push_back(Value::object({
        {"resource_scope", Value{c.resource_scope}},
        {"first_event_hash", Value{c.first_event_hash}},
        {"second_event_hash", Value{c.second_event_hash}},
        {"first_actor_id", Value{c.first_actor_id}},
        {"second_actor_id", Value{c.second_actor_id}},
    }));
  }

  return Value::object({
      {"room_scope", Value{snap.room_scope}},
      {"mode", Value{std::string{party_mode_name(snap.mode)}}},
      {"mode_override",
       Value{std::string{party_mode_override_name(snap.mode_override)}}},
      {"participants", Value{std::move(participants)}},
      {"messages", Value{std::move(messages)}},
      {"conflicts", Value{std::move(conflicts)}},
      {"party_config_present", Value{snap.party_config_present}},
      {"platoon_present", Value{snap.platoon_present}},
      {"bridge_present", Value{snap.bridge_present}},
      {"known_peers_present", Value{snap.known_peers_present}},
  });
}

Result<PartySnapshot> snapshot_from_value(const Value &value) {
  if (!std::holds_alternative<Value::Object>(value.value()))
    return Result<PartySnapshot>::failure({ErrorCode::corrupt});
  auto room_scope = parse_string_field(value, "room_scope");
  auto mode_str = parse_string_field(value, "mode");
  auto override_str = parse_string_field(value, "mode_override");
  auto party_cfg = parse_bool_field(value, "party_config_present");
  auto platoon_present = parse_bool_field(value, "platoon_present");
  auto bridge_present = parse_bool_field(value, "bridge_present");
  auto known_peers_present = parse_bool_field(value, "known_peers_present");
  if (!room_scope.has_value() || !mode_str.has_value() || !override_str.has_value() ||
      !party_cfg.has_value() || !platoon_present.has_value() ||
      !bridge_present.has_value() || !known_peers_present.has_value()) {
    return Result<PartySnapshot>::failure({ErrorCode::corrupt});
  }
  PartyMode mode = PartyMode::single_operator;
  if (mode_str.value() == "single_operator")
    mode = PartyMode::single_operator;
  else if (mode_str.value() == "multi_operator")
    mode = PartyMode::multi_operator;
  else
    return Result<PartySnapshot>::failure({ErrorCode::corrupt});

  auto mode_override = parse_party_mode_override(override_str.value());
  if (!mode_override.has_value())
    return Result<PartySnapshot>::failure({ErrorCode::corrupt});

  const Value *p_field = value.find("participants");
  const Value *m_field = value.find("messages");
  const Value *c_field = value.find("conflicts");
  if (!p_field || !m_field || !c_field)
    return Result<PartySnapshot>::failure({ErrorCode::corrupt});
  const auto *p_arr = std::get_if<Value::Array>(&p_field->value());
  const auto *m_arr = std::get_if<Value::Array>(&m_field->value());
  const auto *c_arr = std::get_if<Value::Array>(&c_field->value());
  if (!p_arr || !m_arr || !c_arr)
    return Result<PartySnapshot>::failure({ErrorCode::corrupt});

  PartySnapshot snap{};
  snap.room_scope = std::move(room_scope).value();
  snap.mode = mode;
  snap.mode_override = mode_override.value();
  snap.party_config_present = party_cfg.value();
  snap.platoon_present = platoon_present.value();
  snap.bridge_present = bridge_present.value();
  snap.known_peers_present = known_peers_present.value();

  snap.participants.reserve(p_arr->size());
  for (const auto &entry : *p_arr) {
    auto p = participant_from_value(entry);
    if (!p.has_value())
      return Result<PartySnapshot>::failure(p.error());
    snap.participants.push_back(std::move(p).value());
  }
  snap.messages.reserve(m_arr->size());
  for (const auto &entry : *m_arr) {
    auto m = message_from_value(entry);
    if (!m.has_value())
      return Result<PartySnapshot>::failure(m.error());
    snap.messages.push_back(std::move(m).value());
  }
  snap.conflicts.reserve(c_arr->size());
  for (const auto &entry : *c_arr) {
    if (!std::holds_alternative<Value::Object>(entry.value()))
      return Result<PartySnapshot>::failure({ErrorCode::corrupt});
    auto scope = parse_string_field(entry, "resource_scope");
    auto h1 = parse_string_field(entry, "first_event_hash");
    auto h2 = parse_string_field(entry, "second_event_hash");
    auto a1 = parse_string_field(entry, "first_actor_id");
    auto a2 = parse_string_field(entry, "second_actor_id");
    if (!scope.has_value() || !h1.has_value() || !h2.has_value() || !a1.has_value() ||
        !a2.has_value()) {
      return Result<PartySnapshot>::failure({ErrorCode::corrupt});
    }
    snap.conflicts.push_back(ConcurrentClaimConflict{
        std::move(scope).value(),
        std::move(h1).value(),
        std::move(h2).value(),
        std::move(a1).value(),
        std::move(a2).value(),
    });
  }
  return Result<PartySnapshot>::success(std::move(snap));
}

Result<PinnedPeer> pinned_peer_from_value(const Value &value) {
  if (!std::holds_alternative<Value::Object>(value.value()))
    return Result<PinnedPeer>::failure({ErrorCode::corrupt});
  auto alias = parse_string_field(value, "alias");
  auto fp = parse_string_field(value, "fingerprint");
  auto pub = parse_string_field(value, "public_key");
  auto note = parse_string_field(value, "trust_note");
  auto pinned_at = parse_int64_field(value, "pinned_at_ns");
  auto revoked = parse_bool_field(value, "revoked");
  auto revoked_at = parse_int64_field(value, "revoked_at_ns");
  auto reason = parse_string_field(value, "revocation_reason");
  if (!alias.has_value() || !fp.has_value() || !pub.has_value() || !note.has_value() ||
      !pinned_at.has_value() || !revoked.has_value() || !revoked_at.has_value() ||
      !reason.has_value()) {
    return Result<PinnedPeer>::failure({ErrorCode::corrupt});
  }
  return Result<PinnedPeer>::success(PinnedPeer{
      std::move(alias).value(),
      std::move(fp).value(),
      std::move(pub).value(),
      std::move(note).value(),
      pinned_at.value(),
      revoked.value(),
      revoked_at.value(),
      std::move(reason).value(),
  });
}

Result<ErrorCode> parse_error_code_num(std::uint64_t code_num) noexcept {
  if (code_num > static_cast<std::uint64_t>(ErrorCode::provider_context_overflow))
    return Result<ErrorCode>::failure({ErrorCode::corrupt});
  return Result<ErrorCode>::success(static_cast<ErrorCode>(code_num));
}

Value make_ok_response(Value result) {
  return Value::object({
      {"v", Value{Number{kPartyLobbyProtocolVersion}}},
      {"ok", Value{true}},
      {"result", std::move(result)},
  });
}

Value make_error_response(Error err) {
  return Value::object({
      {"v", Value{Number{kPartyLobbyProtocolVersion}}},
      {"ok", Value{false}},
      {"error", Value::object({
                    {"code", Value{std::string{error_name(err.code)}}},
                    {"code_num", Value{Number{static_cast<std::uint64_t>(err.code)}}},
                    {"detail", Value{Number{err.detail}}},
                })},
  });
}

Result<void> validate_lease_shape(const PartyLease &lease) noexcept {
  if (!valid_party_room_id(lease.room_id))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_peer_fingerprint(lease.actor_fingerprint))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (!valid_party_alias(lease.alias) || !valid_peer_alias(lease.alias))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (!valid_lease_role(lease.role))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_field_token(lease.host, kMaxHostBytes, true) ||
      !valid_field_token(lease.model, kMaxModelBytes, true)) {
    return Result<void>::failure({ErrorCode::invalid_range});
  }
  if (lease.issued_ns <= 0 || lease.expires_ns <= lease.issued_ns)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (lease.expires_ns - lease.issued_ns > kPartyLobbyMaxTtlNs)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (lease.lease_seq == 0)
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

int role_sort_order(PartyMemberRole role) noexcept {
  switch (role) {
  case PartyMemberRole::operator_human:
    return 0;
  case PartyMemberRole::platoon_leader:
    return 1;
  case PartyMemberRole::worker:
    return 2;
  case PartyMemberRole::bridge_peer:
    return 3;
  }
  return 4;
}

} // namespace

// ---------------------------------------------------------------------------
// Public utility functions
// ---------------------------------------------------------------------------

std::filesystem::path
resolve_party_socket_path(std::optional<std::string_view> xdg_runtime_dir,
                          std::uint64_t uid) {
  const fs::path fallback =
      fs::path{"/tmp"} / ("blackbird-" + std::to_string(uid)) / "party.sock";
  if (xdg_runtime_dir.has_value() && !xdg_runtime_dir->empty() &&
      xdg_runtime_dir->front() == '/' && valid_utf8(*xdg_runtime_dir)) {
    bool safe_xdg = true;
    std::size_t i = 0;
    while (i < xdg_runtime_dir->size()) {
      const DecodedUtf8 dec = decode_utf8_at(*xdg_runtime_dir, i);
      if (dec.length == 0U || is_forbidden_control_scalar(dec.scalar)) {
        safe_xdg = false;
        break;
      }
      i += dec.length;
    }
    if (safe_xdg) {
      const fs::path base_dir{*xdg_runtime_dir};
      for (const auto &comp : base_dir) {
        if (comp == "..") {
          safe_xdg = false;
          break;
        }
      }
      if (safe_xdg) {
        fs::path candidate = base_dir / "blackbird" / "party.sock";
        sockaddr_un probe{};
        if (candidate.native().size() < sizeof(probe.sun_path))
          return candidate;
      }
    }
  }
  return fallback;
}

std::filesystem::path default_party_socket_path() {
  const char *xdg = std::getenv("XDG_RUNTIME_DIR");
  std::optional<std::string_view> xdg_opt;
  if (xdg != nullptr && xdg[0] != '\0')
    xdg_opt = std::string_view{xdg};
  return resolve_party_socket_path(xdg_opt, static_cast<std::uint64_t>(::geteuid()));
}

bool valid_party_room_id(std::string_view room_id) noexcept {
  if (room_id.empty() || room_id.size() > kPartyLobbyMaxRoomIdBytes)
    return false;
  if (equals_ci(CiLhs{room_id}, CiRhs{"solo"}) ||
      equals_ci(CiLhs{room_id}, CiRhs{"none"})) {
    return false;
  }
  const char first = room_id.front();
  const bool first_ok = (first >= 'a' && first <= 'z') ||
                        (first >= 'A' && first <= 'Z') ||
                        (first >= '0' && first <= '9');
  if (!first_ok)
    return false;
  if (room_id.find("..") != std::string_view::npos)
    return false;
  for (const char ch : room_id) {
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' ||
                    ch == '/' || ch == ':';
    if (!ok)
      return false;
  }
  return true;
}

Result<std::string> canonical_party_lease_payload(const PartyLease &lease) {
  auto valid = validate_lease_shape(lease);
  if (!valid.has_value())
    return Result<std::string>::failure(valid.error());
  const Value doc = Value::object({
      {"actor_fingerprint", Value{lease.actor_fingerprint}},
      {"alias", Value{lease.alias}},
      {"expires_ns", Value{Number{lease.expires_ns}}},
      {"host", Value{lease.host}},
      {"issued_ns", Value{Number{lease.issued_ns}}},
      {"lease_seq", Value{Number{lease.lease_seq}}},
      {"model", Value{lease.model}},
      {"revocation_epoch", Value{Number{lease.revocation_epoch}}},
      {"role", Value{std::string{party_member_role_name(lease.role)}}},
      {"room_id", Value{lease.room_id}},
      {"type", Value{std::string{kLeaseSigningType}}},
      {"version", Value{Number{kPartyLobbyProtocolVersion}}},
  });
  return dump_json(doc);
}

Result<std::string> canonical_party_heartbeat_payload(
    LobbyRoomRef room_id, LobbyActorFingerprintRef actor_fingerprint,
    std::int64_t new_expires_ns, std::uint64_t revocation_epoch) {
  if (!valid_party_room_id(room_id.value))
    return Result<std::string>::failure({ErrorCode::invalid_range});
  if (!valid_peer_fingerprint(actor_fingerprint.value))
    return Result<std::string>::failure({ErrorCode::invalid_identity});
  if (new_expires_ns <= 0)
    return Result<std::string>::failure({ErrorCode::invalid_range});
  const Value doc = Value::object({
      {"actor_fingerprint", Value{std::string{actor_fingerprint.value}}},
      {"new_expires_ns", Value{Number{new_expires_ns}}},
      {"revocation_epoch", Value{Number{revocation_epoch}}},
      {"room_id", Value{std::string{room_id.value}}},
      {"type", Value{std::string{kHeartbeatSigningType}}},
      {"version", Value{Number{kPartyLobbyProtocolVersion}}},
  });
  return dump_json(doc);
}

Result<PartyLease> sign_party_lease(const PeerIdentityStore &identity,
                                    PartyLease lease) {
  lease.actor_fingerprint = identity.identity().fingerprint;
  if (lease.issued_ns == 0)
    lease.issued_ns = wall_now_ns();
  if (lease.expires_ns == 0) {
    if (lease.issued_ns <= 0 ||
        lease.issued_ns >
            std::numeric_limits<std::int64_t>::max() - kPartyLobbyDefaultTtlNs) {
      return Result<PartyLease>::failure({ErrorCode::invalid_range});
    }
    lease.expires_ns = lease.issued_ns + kPartyLobbyDefaultTtlNs;
  }
  if (lease.lease_seq == 0)
    lease.lease_seq = 1;
  auto canonical = canonical_party_lease_payload(lease);
  if (!canonical.has_value())
    return Result<PartyLease>::failure(canonical.error());
  auto sig = identity.sign_bytes(canonical.value());
  if (!sig.has_value())
    return Result<PartyLease>::failure(sig.error());
  lease.signature_b64 = base64_encode(sig.value());
  return Result<PartyLease>::success(std::move(lease));
}

Result<std::string> sign_party_heartbeat(const PeerIdentityStore &identity,
                                         LobbyRoomRef room_id,
                                         std::int64_t new_expires_ns,
                                         std::uint64_t revocation_epoch) {
  auto canonical = canonical_party_heartbeat_payload(
      room_id, identity.identity().fingerprint, new_expires_ns, revocation_epoch);
  if (!canonical.has_value())
    return Result<std::string>::failure(canonical.error());
  auto sig = identity.sign_bytes(canonical.value());
  if (!sig.has_value())
    return Result<std::string>::failure(sig.error());
  return Result<std::string>::success(base64_encode(sig.value()));
}

std::uint64_t
compute_party_revocation_epoch(const std::vector<PinnedPeer> &peers,
                               const std::vector<RevokedGrantRecord> &revoked_grants) {
  std::vector<std::string> revoked_peer_fps;
  for (const auto &peer : peers) {
    if (peer.revoked)
      revoked_peer_fps.push_back(peer.fingerprint);
  }
  std::vector<std::string> revoked_grant_ids;
  revoked_grant_ids.reserve(revoked_grants.size());
  for (const auto &grant : revoked_grants)
    revoked_grant_ids.push_back(grant.grant_id);

  const std::uint64_t total_count =
      static_cast<std::uint64_t>(revoked_peer_fps.size() + revoked_grant_ids.size());
  if (total_count == 0U)
    return 0U;

  std::ranges::sort(revoked_peer_fps);
  std::ranges::sort(revoked_grant_ids);

  std::string canonical;
  for (const auto &fp : revoked_peer_fps) {
    canonical += "P:";
    canonical += fp;
    canonical.push_back('\n');
  }
  for (const auto &gid : revoked_grant_ids) {
    canonical += "G:";
    canonical += gid;
    canonical.push_back('\n');
  }
  const std::string digest_hex = board_bridge_sha256_hex(canonical);
  std::uint32_t low32 = 0U;
  for (std::size_t i = 0; i < 8U && i < digest_hex.size(); ++i) {
    const char ch = digest_hex[i];
    std::uint32_t nibble = 0U;
    if (ch >= '0' && ch <= '9')
      nibble = static_cast<std::uint32_t>(ch - '0');
    else if (ch >= 'a' && ch <= 'f')
      nibble = static_cast<std::uint32_t>(10 + (ch - 'a'));
    low32 = (low32 << 4U) | nibble;
  }
  return (total_count << 32U) | static_cast<std::uint64_t>(low32);
}

// ---------------------------------------------------------------------------
// PartyLobbyServer::Impl
// ---------------------------------------------------------------------------

struct PartyLobbyServer::Impl {
  struct ActiveMember {
    PartyLease lease;
    bool local_self = false;
    std::int64_t last_seen_ns = 0;
  };

  struct InvitedMember {
    std::string alias;
    std::string fingerprint;
    PartyMemberRole role = PartyMemberRole::platoon_leader;
    std::optional<std::string> ssh_target;
    std::int64_t invited_at_ns = 0;
  };

  struct Room {
    std::string room_id;
    std::map<std::string, ActiveMember> active;   // keyed by actor_fingerprint
    std::map<std::string, InvitedMember> invited; // keyed by actor_fingerprint
    std::deque<PartyMessage> messages;
    std::uint64_t next_message_seq = 0;
  };

  struct ClientConn {
    ScopedFd fd;
    std::string read_buf;
    std::string write_buf;
    std::size_t write_offset = 0;
    bool close_after_write = false;
    SteadyClock::time_point last_activity = SteadyClock::now();
  };

  struct TrustSnapshot {
    bool store_present = false;
    std::vector<PinnedPeer> peers;
    std::vector<RevokedGrantRecord> revoked_grants;
    std::unordered_set<std::string> revoked_fps;
    std::uint64_t revocation_epoch = 0;
  };

  PartyLobbyServerConfig config;
  fs::path socket_path;
  std::string socket_name;
  ScopedFd dir_fd;
  ScopedFd listen_fd;
  ScopedFd wake_read;
  ScopedFd wake_write;
  dev_t socket_dev = 0;
  ino_t socket_ino = 0;
  pid_t owner_pid = ::getpid();
  bool bound = false;

  std::optional<PeerIdentity> local_identity;

  mutable std::mutex state_mutex;
  std::map<std::string, Room> rooms;
  std::optional<std::string> active_room_id;
  TrustSnapshot trust;

  std::atomic_bool stop_requested{false};
  std::atomic_bool running_flag{false};
  bool shutdown_after_flush = false;
  SteadyClock::time_point shutdown_deadline{};
  std::vector<ClientConn> clients;
  std::thread worker;

  std::int64_t now_ns() const noexcept {
    if (config.clock_now_ns) {
      const std::int64_t custom = config.clock_now_ns();
      if (custom > 0)
        return custom;
    }
    return wall_now_ns();
  }

  void wake_loop() noexcept {
    if (!wake_write)
      return;
    const char byte = 1;
    (void)send_nosigpipe(wake_write.get(), &byte, 1U);
  }

  void unlink_owned_socket() noexcept {
    if (!bound || owner_pid != ::getpid() || !dir_fd)
      return;
    struct stat st{};
    if (::fstatat(dir_fd.get(), socket_name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISSOCK(st.st_mode) && st.st_uid == ::geteuid() && st.st_dev == socket_dev &&
        st.st_ino == socket_ino) {
      (void)::unlinkat(dir_fd.get(), socket_name.c_str(), 0);
    }
    bound = false;
  }

  Result<TrustSnapshot> load_trust_from_disk() const {
    TrustSnapshot out{};
    if (config.known_peers_dir.empty())
      return Result<TrustSnapshot>::success(std::move(out));

    struct stat st{};
    if (::lstat(config.known_peers_dir.c_str(), &st) != 0) {
      if (errno == ENOENT)
        return Result<TrustSnapshot>::success(std::move(out));
      return Result<TrustSnapshot>::failure(native_error(errno));
    }
    if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode))
      return Result<TrustSnapshot>::failure({ErrorCode::io, ELOOP});

    auto store =
        KnownPeersStore::open(config.known_peers_dir, config.peer_identity_config);
    if (!store.has_value())
      return Result<TrustSnapshot>::failure(store.error());

    auto peers = store.value().list_peers();
    if (!peers.has_value())
      return Result<TrustSnapshot>::failure(peers.error());
    auto grants = store.value().list_revoked_grants();
    if (!grants.has_value())
      return Result<TrustSnapshot>::failure(grants.error());

    out.store_present = true;
    out.peers = std::move(peers).value();
    out.revoked_grants = std::move(grants).value();
    for (const auto &p : out.peers) {
      if (p.revoked)
        out.revoked_fps.insert(p.fingerprint);
    }
    out.revocation_epoch =
        compute_party_revocation_epoch(out.peers, out.revoked_grants);
    return Result<TrustSnapshot>::success(std::move(out));
  }

  std::optional<std::string>
  resolve_trusted_ssh_target_locked(LobbyActorFingerprintRef fingerprint,
                                    LobbyAliasRef alias, bool is_local) const {
    if (is_local) {
      if (config.local_ssh_target.has_value() &&
          valid_field_token(*config.local_ssh_target, kMaxSshTargetBytes, false) &&
          !config.local_ssh_target->starts_with('-')) {
        return config.local_ssh_target;
      }
      return std::nullopt;
    }
    if (auto it = config.trusted_peer_ssh_targets.find(std::string{fingerprint.value});
        it != config.trusted_peer_ssh_targets.end()) {
      if (valid_field_token(it->second, kMaxSshTargetBytes, false) &&
          !it->second.starts_with('-')) {
        return it->second;
      }
    }
    if (auto it = config.trusted_peer_ssh_targets.find(std::string{alias.value});
        it != config.trusted_peer_ssh_targets.end()) {
      if (valid_field_token(it->second, kMaxSshTargetBytes, false) &&
          !it->second.starts_with('-')) {
        return it->second;
      }
    }
    for (const auto &peer : trust.peers) {
      if (!peer.revoked && peer.fingerprint == fingerprint.value)
        return extract_trusted_ssh_target(peer.trust_note);
    }
    return std::nullopt;
  }

  std::size_t evict_revoked_and_stale_locked() {
    std::size_t evicted = 0;
    const std::uint64_t current_epoch = trust.revocation_epoch;
    for (auto room_it = rooms.begin(); room_it != rooms.end();) {
      Room &room = room_it->second;
      bool evicted_local = false;
      for (auto it = room.active.begin(); it != room.active.end();) {
        const bool revoked = trust.revoked_fps.contains(it->first);
        const bool stale_epoch = (it->second.lease.revocation_epoch != current_epoch);
        if (revoked || stale_epoch) {
          evicted_local = evicted_local || it->second.local_self;
          it = room.active.erase(it);
          ++evicted;
        } else {
          ++it;
        }
      }
      for (auto it = room.invited.begin(); it != room.invited.end();) {
        if (trust.revoked_fps.contains(it->first)) {
          it = room.invited.erase(it);
          ++evicted;
        } else {
          ++it;
        }
      }
      bool any_local_left = false;
      for (const auto &[_, m] : room.active) {
        if (m.local_self) {
          any_local_left = true;
          break;
        }
      }
      if (room.active.empty() || (evicted_local && !any_local_left)) {
        if (active_room_id.has_value() && *active_room_id == room.room_id)
          active_room_id.reset();
        room_it = rooms.erase(room_it);
      } else {
        ++room_it;
      }
    }
    return evicted;
  }

  std::size_t reap_expired_locked(std::int64_t current_now_ns) {
    std::size_t reaped = 0;
    for (auto room_it = rooms.begin(); room_it != rooms.end();) {
      Room &room = room_it->second;
      bool reaped_local = false;
      for (auto it = room.active.begin(); it != room.active.end();) {
        if (it->second.lease.expires_ns <= current_now_ns) {
          reaped_local = reaped_local || it->second.local_self;
          it = room.active.erase(it);
          ++reaped;
        } else {
          ++it;
        }
      }
      bool any_local_left = false;
      for (const auto &[_, m] : room.active) {
        if (m.local_self) {
          any_local_left = true;
          break;
        }
      }
      if (room.active.empty() || (reaped_local && !any_local_left)) {
        if (active_room_id.has_value() && *active_room_id == room.room_id)
          active_room_id.reset();
        room_it = rooms.erase(room_it);
      } else {
        ++room_it;
      }
    }
    return reaped;
  }

  Result<std::uint64_t> refresh_revocations_sync() {
    auto loaded = load_trust_from_disk();
    if (!loaded.has_value())
      return Result<std::uint64_t>::failure(loaded.error());
    std::lock_guard lock{state_mutex};
    trust = std::move(loaded).value();
    (void)evict_revoked_and_stale_locked();
    return Result<std::uint64_t>::success(trust.revocation_epoch);
  }

  struct ResolvedSigner {
    std::string public_key;
    bool local_self = false;
  };

  Result<ResolvedSigner> resolve_signer_locked(std::string_view fingerprint) const {
    if (local_identity.has_value() && local_identity->fingerprint == fingerprint) {
      if (trust.revoked_fps.contains(std::string{fingerprint}))
        return Result<ResolvedSigner>::failure({ErrorCode::invalid_identity});
      return Result<ResolvedSigner>::success(
          ResolvedSigner{local_identity->public_key, true});
    }
    for (const auto &peer : trust.peers) {
      if (peer.fingerprint == fingerprint) {
        if (peer.revoked)
          return Result<ResolvedSigner>::failure({ErrorCode::invalid_identity});
        return Result<ResolvedSigner>::success(ResolvedSigner{peer.public_key, false});
      }
    }
    return Result<ResolvedSigner>::failure({ErrorCode::invalid_identity});
  }

  PartySnapshot build_snapshot_locked(std::optional<std::string_view> room_opt) const {
    PartySnapshot snap{};
    snap.room_scope.clear();
    snap.mode = PartyMode::single_operator;
    snap.mode_override = PartyModeOverride::auto_detect;
    snap.party_config_present = false;
    snap.platoon_present = false;
    snap.bridge_present = false;
    snap.known_peers_present = trust.store_present;

    std::string target_room;
    if (room_opt.has_value() && !room_opt->empty()) {
      target_room = std::string{*room_opt};
    } else if (active_room_id.has_value()) {
      target_room = *active_room_id;
    } else {
      return snap; // SOLO
    }

    const auto it = rooms.find(target_room);
    if (it == rooms.end())
      return snap;

    const Room &room = it->second;
    snap.room_scope = room.room_id;

    snap.participants.reserve(room.active.size() + room.invited.size());
    for (const auto &[_, member] : room.active) {
      PartyParticipant p{};
      p.id = member.lease.alias;
      p.display_name = member.lease.alias;
      p.role = member.lease.role;
      p.host = party_chat_sanitize(member.lease.host, kMaxHostBytes);
      p.model = party_chat_sanitize(member.lease.model, kMaxModelBytes);
      p.fingerprint = member.lease.actor_fingerprint;
      p.state = PartyParticipantState::online;
      p.last_seen_ns = member.last_seen_ns;
      p.ssh_target = member.lease.ssh_target;
      p.local_self = member.local_self;
      snap.participants.push_back(std::move(p));
    }
    for (const auto &[fp, inv] : room.invited) {
      if (room.active.contains(fp))
        continue;
      PartyParticipant p{};
      p.id = inv.alias;
      p.display_name = inv.alias;
      p.role = inv.role;
      p.fingerprint = inv.fingerprint;
      p.state = PartyParticipantState::offline;
      p.last_seen_ns = inv.invited_at_ns;
      p.ssh_target = inv.ssh_target;
      p.local_self = false;
      snap.participants.push_back(std::move(p));
    }

    std::ranges::sort(snap.participants,
                      [](const PartyParticipant &lhs, const PartyParticipant &rhs) {
                        if (lhs.local_self != rhs.local_self)
                          return lhs.local_self;
                        const int lr = role_sort_order(lhs.role);
                        const int rr = role_sort_order(rhs.role);
                        if (lr != rr)
                          return lr < rr;
                        return lhs.id < rhs.id;
                      });

    snap.mode = detect_party_mode(snap.participants, PartyModeOverride::auto_detect);
    snap.messages.assign(room.messages.begin(), room.messages.end());
    return snap;
  }

  Result<PartySnapshot> handle_create_or_join(std::string_view room_id,
                                              PartyLease wire_lease,
                                              bool allow_create) {
    if (!valid_party_room_id(room_id))
      return Result<PartySnapshot>::failure({ErrorCode::invalid_range});
    if (wire_lease.room_id != room_id)
      return Result<PartySnapshot>::failure({ErrorCode::invalid_identity});

    // Always drop untrusted wire ssh_target before doing anything else.
    wire_lease.ssh_target.reset();

    auto shape_ok = validate_lease_shape(wire_lease);
    if (!shape_ok.has_value())
      return Result<PartySnapshot>::failure(shape_ok.error());

    // Refresh trust before verifying so newly pinned or revoked peers are observed.
    auto refreshed = refresh_revocations_sync();
    if (!refreshed.has_value())
      return Result<PartySnapshot>::failure(refreshed.error());

    const std::int64_t current_now = now_ns();
    if (wire_lease.issued_ns > current_now &&
        wire_lease.issued_ns - current_now > kPartyLobbyMaxFutureSkewNs) {
      return Result<PartySnapshot>::failure({ErrorCode::invalid_range});
    }
    if (wire_lease.expires_ns <= current_now)
      return Result<PartySnapshot>::failure({ErrorCode::stale_handle});
    if (wire_lease.expires_ns - current_now >
        kPartyLobbyMaxTtlNs + kPartyLobbyMaxFutureSkewNs) {
      return Result<PartySnapshot>::failure({ErrorCode::invalid_range});
    }

    ResolvedSigner signer{};
    std::uint64_t expected_epoch = 0;
    {
      std::lock_guard lock{state_mutex};
      (void)reap_expired_locked(current_now);
      expected_epoch = trust.revocation_epoch;
      if (wire_lease.revocation_epoch != expected_epoch)
        return Result<PartySnapshot>::failure({ErrorCode::invalid_identity});
      auto resolved = resolve_signer_locked(wire_lease.actor_fingerprint);
      if (!resolved.has_value())
        return Result<PartySnapshot>::failure(resolved.error());
      signer = std::move(resolved).value();
    }

    auto canonical = canonical_party_lease_payload(wire_lease);
    if (!canonical.has_value())
      return Result<PartySnapshot>::failure(canonical.error());
    auto decoded_sig =
        base64_decode_strict(wire_lease.signature_b64, kPeerMaxSignatureBytes);
    if (!decoded_sig.has_value())
      return Result<PartySnapshot>::failure({ErrorCode::invalid_identity});

    auto verified = verify_detached_signature(
        DetachedSignatureVerification{
            wire_lease.actor_fingerprint,
            signer.public_key,
            canonical.value(),
            decoded_sig.value(),
        },
        config.peer_identity_config);
    if (!verified.has_value())
      return Result<PartySnapshot>::failure({ErrorCode::invalid_identity});

    // Re-check trust and fresh clock after subprocess verification closes concurrent
    // revocation and expiration windows.
    auto rechecked = refresh_revocations_sync();
    if (!rechecked.has_value())
      return Result<PartySnapshot>::failure(rechecked.error());
    const std::int64_t post_now = now_ns();
    if (wire_lease.issued_ns > post_now &&
        wire_lease.issued_ns - post_now > kPartyLobbyMaxFutureSkewNs) {
      return Result<PartySnapshot>::failure({ErrorCode::invalid_range});
    }
    if (wire_lease.expires_ns <= post_now)
      return Result<PartySnapshot>::failure({ErrorCode::stale_handle});
    if (wire_lease.expires_ns - post_now >
        kPartyLobbyMaxTtlNs + kPartyLobbyMaxFutureSkewNs) {
      return Result<PartySnapshot>::failure({ErrorCode::invalid_range});
    }

    std::lock_guard lock{state_mutex};
    (void)reap_expired_locked(post_now);
    if (wire_lease.revocation_epoch != trust.revocation_epoch ||
        trust.revoked_fps.contains(wire_lease.actor_fingerprint)) {
      return Result<PartySnapshot>::failure({ErrorCode::invalid_identity});
    }

    auto room_it = rooms.find(std::string{room_id});
    if (room_it == rooms.end()) {
      if (!allow_create)
        return Result<PartySnapshot>::failure({ErrorCode::stale_handle});
      if (rooms.size() >= config.max_rooms)
        return Result<PartySnapshot>::failure({ErrorCode::capacity});
      auto [inserted_it, _] = rooms.emplace(std::string{room_id}, Room{});
      inserted_it->second.room_id = std::string{room_id};
      room_it = inserted_it;
    }

    Room &room = room_it->second;
    const bool already_active = room.active.contains(wire_lease.actor_fingerprint);
    if (already_active) {
      const auto &existing = room.active.at(wire_lease.actor_fingerprint);
      if (wire_lease.lease_seq <= existing.lease.lease_seq)
        return Result<PartySnapshot>::failure({ErrorCode::stale_handle});
    } else {
      std::size_t distinct_count = room.active.size();
      for (const auto &[inv_fp, _] : room.invited) {
        if (!room.active.contains(inv_fp) && inv_fp != wire_lease.actor_fingerprint)
          ++distinct_count;
      }
      if (distinct_count >= config.max_members_per_room)
        return Result<PartySnapshot>::failure({ErrorCode::capacity});
    }

    // Reject alias collision with another distinct participant in the same room.
    for (const auto &[fp, member] : room.active) {
      if (fp != wire_lease.actor_fingerprint &&
          equals_ci(CiLhs{member.lease.alias}, CiRhs{wire_lease.alias})) {
        return Result<PartySnapshot>::failure({ErrorCode::conflict});
      }
    }
    for (const auto &[fp, inv] : room.invited) {
      if (fp != wire_lease.actor_fingerprint &&
          equals_ci(CiLhs{inv.alias}, CiRhs{wire_lease.alias})) {
        return Result<PartySnapshot>::failure({ErrorCode::conflict});
      }
    }

    wire_lease.ssh_target = resolve_trusted_ssh_target_locked(
        wire_lease.actor_fingerprint, wire_lease.alias, signer.local_self);

    const std::string actor_key = wire_lease.actor_fingerprint;
    room.invited.erase(actor_key);
    room.active[actor_key] =
        ActiveMember{std::move(wire_lease), signer.local_self, post_now};
    if (allow_create || !active_room_id.has_value())
      active_room_id = room.room_id;

    return Result<PartySnapshot>::success(build_snapshot_locked(room.room_id));
  }

  Result<PartyLease> handle_heartbeat(LobbyRoomRef room_id,
                                      LobbyActorFingerprintRef actor_fp,
                                      std::int64_t new_expires_ns,
                                      std::string_view signature_b64) {
    if (!valid_party_room_id(room_id.value))
      return Result<PartyLease>::failure({ErrorCode::invalid_range});
    if (!valid_peer_fingerprint(actor_fp.value))
      return Result<PartyLease>::failure({ErrorCode::invalid_identity});

    auto refreshed = refresh_revocations_sync();
    if (!refreshed.has_value())
      return Result<PartyLease>::failure(refreshed.error());

    const std::int64_t current_now = now_ns();
    if (new_expires_ns <= current_now ||
        new_expires_ns - current_now > kPartyLobbyMaxTtlNs) {
      return Result<PartyLease>::failure({ErrorCode::invalid_range});
    }

    ResolvedSigner signer{};
    std::uint64_t expected_epoch = 0;
    {
      std::lock_guard lock{state_mutex};
      (void)reap_expired_locked(current_now);
      expected_epoch = trust.revocation_epoch;
      auto room_it = rooms.find(std::string{room_id.value});
      if (room_it == rooms.end())
        return Result<PartyLease>::failure({ErrorCode::stale_handle});
      auto mem_it = room_it->second.active.find(std::string{actor_fp.value});
      if (mem_it == room_it->second.active.end())
        return Result<PartyLease>::failure({ErrorCode::stale_handle});
      if (new_expires_ns <= mem_it->second.lease.expires_ns)
        return Result<PartyLease>::failure({ErrorCode::stale_handle});
      auto resolved = resolve_signer_locked(actor_fp.value);
      if (!resolved.has_value())
        return Result<PartyLease>::failure(resolved.error());
      signer = std::move(resolved).value();
    }

    auto canonical = canonical_party_heartbeat_payload(room_id, actor_fp,
                                                       new_expires_ns, expected_epoch);
    if (!canonical.has_value())
      return Result<PartyLease>::failure(canonical.error());
    auto decoded_sig = base64_decode_strict(signature_b64, kPeerMaxSignatureBytes);
    if (!decoded_sig.has_value())
      return Result<PartyLease>::failure({ErrorCode::invalid_identity});

    auto verified = verify_detached_signature(
        DetachedSignatureVerification{
            actor_fp.value,
            signer.public_key,
            canonical.value(),
            decoded_sig.value(),
        },
        config.peer_identity_config);
    if (!verified.has_value())
      return Result<PartyLease>::failure({ErrorCode::invalid_identity});

    // Re-check trust and fresh clock after subprocess verification closes concurrent
    // revocation and expiration windows.
    auto rechecked = refresh_revocations_sync();
    if (!rechecked.has_value())
      return Result<PartyLease>::failure(rechecked.error());
    const std::int64_t post_now = now_ns();
    if (new_expires_ns <= post_now || new_expires_ns - post_now > kPartyLobbyMaxTtlNs)
      return Result<PartyLease>::failure({ErrorCode::invalid_range});

    std::lock_guard lock{state_mutex};
    (void)reap_expired_locked(post_now);
    if (expected_epoch != trust.revocation_epoch ||
        trust.revoked_fps.contains(std::string{actor_fp.value})) {
      return Result<PartyLease>::failure({ErrorCode::invalid_identity});
    }
    auto room_it = rooms.find(std::string{room_id.value});
    if (room_it == rooms.end())
      return Result<PartyLease>::failure({ErrorCode::stale_handle});
    auto mem_it = room_it->second.active.find(std::string{actor_fp.value});
    if (mem_it == room_it->second.active.end())
      return Result<PartyLease>::failure({ErrorCode::stale_handle});
    if (new_expires_ns <= mem_it->second.lease.expires_ns)
      return Result<PartyLease>::failure({ErrorCode::stale_handle});

    mem_it->second.lease.expires_ns = new_expires_ns;
    mem_it->second.lease.lease_seq += 1U;
    mem_it->second.lease.signature_b64 = std::string{signature_b64};
    mem_it->second.last_seen_ns = post_now;
    return Result<PartyLease>::success(mem_it->second.lease);
  }

  Result<void> handle_leave(LobbyRoomRef room_id, LobbyActorFingerprintRef actor_fp) {
    if (!valid_party_room_id(room_id.value))
      return Result<void>::failure({ErrorCode::invalid_range});
    if (!valid_peer_fingerprint(actor_fp.value))
      return Result<void>::failure({ErrorCode::invalid_identity});

    std::lock_guard lock{state_mutex};
    auto room_it = rooms.find(std::string{room_id.value});
    if (room_it == rooms.end())
      return Result<void>::failure({ErrorCode::stale_handle});
    Room &room = room_it->second;

    bool was_local = false;
    bool found = false;
    if (auto mem_it = room.active.find(std::string{actor_fp.value});
        mem_it != room.active.end()) {
      was_local = mem_it->second.local_self;
      room.active.erase(mem_it);
      found = true;
    }
    if (room.invited.erase(std::string{actor_fp.value}) > 0U)
      found = true;
    if (!found)
      return Result<void>::failure({ErrorCode::stale_handle});

    bool any_local_left = false;
    for (const auto &[_, m] : room.active) {
      if (m.local_self) {
        any_local_left = true;
        break;
      }
    }

    if ((was_local && !any_local_left) || room.active.empty()) {
      if (active_room_id.has_value() && *active_room_id == room.room_id)
        active_room_id.reset();
      rooms.erase(room_it);
    }
    return Result<void>::success();
  }

  Result<PartyParticipant> handle_invite_friend(LobbyRoomRef room_id,
                                                LobbyAliasRef friend_alias) {
    if (!valid_party_room_id(room_id.value))
      return Result<PartyParticipant>::failure({ErrorCode::invalid_range});
    if (!valid_peer_alias(friend_alias.value))
      return Result<PartyParticipant>::failure({ErrorCode::invalid_identity});

    auto refreshed = refresh_revocations_sync();
    if (!refreshed.has_value())
      return Result<PartyParticipant>::failure(refreshed.error());

    const std::int64_t current_now = now_ns();
    std::lock_guard lock{state_mutex};
    (void)reap_expired_locked(current_now);

    auto room_it = rooms.find(std::string{room_id.value});
    if (room_it == rooms.end())
      return Result<PartyParticipant>::failure({ErrorCode::stale_handle});

    const PinnedPeer *pinned = nullptr;
    for (const auto &peer : trust.peers) {
      if (equals_ci(CiLhs{peer.alias}, CiRhs{friend_alias.value})) {
        pinned = &peer;
        break;
      }
    }
    if (pinned == nullptr || pinned->revoked)
      return Result<PartyParticipant>::failure({ErrorCode::invalid_identity});

    Room &room = room_it->second;
    if (auto act_it = room.active.find(pinned->fingerprint);
        act_it != room.active.end()) {
      PartyParticipant p{};
      p.id = act_it->second.lease.alias;
      p.display_name = act_it->second.lease.alias;
      p.role = act_it->second.lease.role;
      p.host = act_it->second.lease.host;
      p.model = act_it->second.lease.model;
      p.fingerprint = act_it->second.lease.actor_fingerprint;
      p.state = PartyParticipantState::online;
      p.last_seen_ns = act_it->second.last_seen_ns;
      p.ssh_target = act_it->second.lease.ssh_target;
      p.local_self = act_it->second.local_self;
      return Result<PartyParticipant>::success(std::move(p));
    }

    // Reject alias collision with another distinct participant already in the room.
    for (const auto &[fp, member] : room.active) {
      if (fp != pinned->fingerprint &&
          equals_ci(CiLhs{member.lease.alias}, CiRhs{pinned->alias})) {
        return Result<PartyParticipant>::failure({ErrorCode::conflict});
      }
    }
    for (const auto &[fp, inv] : room.invited) {
      if (fp != pinned->fingerprint &&
          equals_ci(CiLhs{inv.alias}, CiRhs{pinned->alias})) {
        return Result<PartyParticipant>::failure({ErrorCode::conflict});
      }
    }

    if (!room.invited.contains(pinned->fingerprint)) {
      const std::size_t total = room.active.size() + room.invited.size();
      if (total >= config.max_members_per_room)
        return Result<PartyParticipant>::failure({ErrorCode::capacity});
    }

    std::optional<std::string> trusted_ssh =
        resolve_trusted_ssh_target_locked(pinned->fingerprint, pinned->alias, false);

    InvitedMember inv{
        pinned->alias, pinned->fingerprint, PartyMemberRole::platoon_leader,
        trusted_ssh,   current_now,
    };
    room.invited[pinned->fingerprint] = inv;

    PartyParticipant participant{};
    participant.id = inv.alias;
    participant.display_name = inv.alias;
    participant.role = inv.role;
    participant.fingerprint = inv.fingerprint;
    participant.state = PartyParticipantState::offline;
    participant.last_seen_ns = inv.invited_at_ns;
    participant.ssh_target = inv.ssh_target;
    participant.local_self = false;
    return Result<PartyParticipant>::success(std::move(participant));
  }

  Result<void> handle_kick(LobbyRoomRef room_id, LobbyAliasRef alias) {
    if (!valid_party_room_id(room_id.value))
      return Result<void>::failure({ErrorCode::invalid_range});
    if (!valid_party_alias(alias.value))
      return Result<void>::failure({ErrorCode::invalid_identity});

    std::lock_guard lock{state_mutex};
    auto room_it = rooms.find(std::string{room_id.value});
    if (room_it == rooms.end())
      return Result<void>::failure({ErrorCode::stale_handle});
    Room &room = room_it->second;

    bool removed = false;
    bool removed_local = false;
    for (auto it = room.active.begin(); it != room.active.end();) {
      if (equals_ci(CiLhs{it->second.lease.alias}, CiRhs{alias.value})) {
        removed_local = removed_local || it->second.local_self;
        it = room.active.erase(it);
        removed = true;
      } else {
        ++it;
      }
    }
    for (auto it = room.invited.begin(); it != room.invited.end();) {
      if (equals_ci(CiLhs{it->second.alias}, CiRhs{alias.value})) {
        it = room.invited.erase(it);
        removed = true;
      } else {
        ++it;
      }
    }
    if (!removed)
      return Result<void>::failure({ErrorCode::stale_handle});

    bool any_local_left = false;
    for (const auto &[_, m] : room.active) {
      if (m.local_self) {
        any_local_left = true;
        break;
      }
    }
    if ((removed_local && !any_local_left) || room.active.empty()) {
      if (active_room_id.has_value() && *active_room_id == room.room_id)
        active_room_id.reset();
      rooms.erase(room_it);
    }
    return Result<void>::success();
  }

  Result<std::uint64_t> handle_post_message(LobbyRoomRef room_id,
                                            LobbyAliasRef sender_alias,
                                            LobbyTargetRef target, LobbyBodyRef body,
                                            PartyMessageKind kind) {
    if (!valid_party_room_id(room_id.value))
      return Result<std::uint64_t>::failure({ErrorCode::invalid_range});
    if (!valid_party_alias(sender_alias.value))
      return Result<std::uint64_t>::failure({ErrorCode::invalid_identity});
    if (body.value.size() > kPartyMaxMessageBytes ||
        !has_visible_content_after_stripping_escapes(body.value)) {
      return Result<std::uint64_t>::failure({ErrorCode::invalid_range});
    }
    std::string sanitized_body = party_chat_sanitize(body.value, kPartyMaxMessageBytes);
    if (trim_ascii(sanitized_body).empty())
      return Result<std::uint64_t>::failure({ErrorCode::invalid_range});

    const std::int64_t current_now = now_ns();
    std::lock_guard lock{state_mutex};
    (void)reap_expired_locked(current_now);

    auto room_it = rooms.find(std::string{room_id.value});
    if (room_it == rooms.end())
      return Result<std::uint64_t>::failure({ErrorCode::stale_handle});

    Room &room = room_it->second;
    PartyMemberRole sender_role = PartyMemberRole::operator_human;
    std::string sender_host;
    std::string sender_model;
    std::string sender_fp;
    bool verified_peer = false;
    for (const auto &[_, member] : room.active) {
      if (equals_ci(CiLhs{member.lease.alias}, CiRhs{sender_alias.value})) {
        sender_role = member.lease.role;
        sender_host = member.lease.host;
        sender_model = member.lease.model;
        sender_fp = member.lease.actor_fingerprint;
        verified_peer = true;
        break;
      }
    }

    const std::uint64_t seq = ++room.next_message_seq;
    PartyMessage msg{};
    msg.id = "lobby-" + std::to_string(seq);
    msg.timestamp_ns = current_now;
    msg.sender_id = party_chat_sanitize(sender_alias.value, kPartyMaxAliasBytes);
    msg.sender_role = sender_role;
    msg.sender_host = party_chat_sanitize(sender_host, kMaxHostBytes);
    msg.sender_model = party_chat_sanitize(sender_model, kMaxModelBytes);
    msg.sender_fingerprint = std::move(sender_fp);
    msg.verified_peer = verified_peer;
    msg.target = normalize_target_label(target.value);
    msg.kind = kind;
    msg.body = std::move(sanitized_body);
    msg.untrusted_remote = !verified_peer;

    if (room.messages.size() >= config.max_messages_per_room)
      room.messages.pop_front();
    room.messages.push_back(std::move(msg));
    return Result<std::uint64_t>::success(seq);
  }

  Result<std::vector<PinnedPeer>> handle_list_friends() {
    auto refreshed = refresh_revocations_sync();
    if (!refreshed.has_value())
      return Result<std::vector<PinnedPeer>>::failure(refreshed.error());
    std::lock_guard lock{state_mutex};
    std::vector<PinnedPeer> friends;
    friends.reserve(trust.peers.size());
    for (const auto &peer : trust.peers) {
      if (!peer.revoked)
        friends.push_back(peer);
    }
    return Result<std::vector<PinnedPeer>>::success(std::move(friends));
  }

  Value dispatch_request(std::string_view line) {
    auto parsed = parse_json(line, {config.max_line_bytes, 100000, 32});
    if (!parsed.has_value())
      return make_error_response({ErrorCode::corrupt});
    const Value &req = parsed.value();
    if (!std::holds_alternative<Value::Object>(req.value()))
      return make_error_response({ErrorCode::corrupt});

    auto ver = parse_uint64_field(req, "v");
    auto op = parse_string_field(req, "op");
    if (!ver.has_value() || ver.value() != kPartyLobbyProtocolVersion ||
        !op.has_value()) {
      return make_error_response({ErrorCode::corrupt});
    }

    const Value empty_params = Value::object({});
    const Value *params_ptr = req.find("params");
    const Value &params = params_ptr ? *params_ptr : empty_params;
    if (!std::holds_alternative<Value::Object>(params.value()))
      return make_error_response({ErrorCode::corrupt});

    const std::string &op_name = op.value();
    if (op_name == "ping") {
      std::lock_guard lock{state_mutex};
      (void)reap_expired_locked(now_ns());
      return make_ok_response(Value::object({
          {"ok", Value{true}},
          {"protocol_version", Value{Number{kPartyLobbyProtocolVersion}}},
          {"revocation_epoch", Value{Number{trust.revocation_epoch}}},
          {"active_room_id",
           active_room_id.has_value() ? Value{*active_room_id} : Value{nullptr}},
          {"room_count", Value{Number{static_cast<std::uint64_t>(rooms.size())}}},
          {"server_pid", Value{Number{static_cast<std::int64_t>(::getpid())}}},
      }));
    }
    if (op_name == "shutdown") {
      shutdown_after_flush = true;
      shutdown_deadline = SteadyClock::now() + std::chrono::milliseconds{500};
      return make_ok_response(Value::object({{"stopping", Value{true}}}));
    }
    if (op_name == "create_room" || op_name == "join_room") {
      auto room_id = parse_string_field(params, "room_id");
      const Value *lease_val = params.find("lease");
      if (!room_id.has_value() || !lease_val)
        return make_error_response({ErrorCode::corrupt});
      auto lease = lease_from_wire_value(*lease_val, false);
      if (!lease.has_value())
        return make_error_response(lease.error());
      auto res = handle_create_or_join(room_id.value(), std::move(lease).value(),
                                       op_name == "create_room");
      if (!res.has_value())
        return make_error_response(res.error());
      return make_ok_response(snapshot_to_value(res.value()));
    }
    if (op_name == "heartbeat") {
      auto room_id = parse_string_field(params, "room_id");
      auto actor_fp = parse_string_field(params, "actor_fingerprint");
      auto new_exp = parse_int64_field(params, "new_expires_ns");
      auto sig_b64 = parse_string_field(params, "signature_b64");
      if (!room_id.has_value() || !actor_fp.has_value() || !new_exp.has_value() ||
          !sig_b64.has_value()) {
        return make_error_response({ErrorCode::corrupt});
      }
      auto res = handle_heartbeat(room_id.value(), actor_fp.value(), new_exp.value(),
                                  sig_b64.value());
      if (!res.has_value())
        return make_error_response(res.error());
      return make_ok_response(lease_to_wire_value(res.value(), true));
    }
    if (op_name == "leave_room") {
      auto room_id = parse_string_field(params, "room_id");
      auto actor_fp = parse_string_field(params, "actor_fingerprint");
      if (!room_id.has_value() || !actor_fp.has_value())
        return make_error_response({ErrorCode::corrupt});
      auto res = handle_leave(room_id.value(), actor_fp.value());
      if (!res.has_value())
        return make_error_response(res.error());
      return make_ok_response(Value::object({{"left", Value{true}}}));
    }
    if (op_name == "invite_friend") {
      auto room_id = parse_string_field(params, "room_id");
      auto friend_alias = parse_string_field(params, "friend_alias");
      if (!room_id.has_value() || !friend_alias.has_value())
        return make_error_response({ErrorCode::corrupt});
      auto res = handle_invite_friend(room_id.value(), friend_alias.value());
      if (!res.has_value())
        return make_error_response(res.error());
      return make_ok_response(participant_to_value(res.value()));
    }
    if (op_name == "kick_member") {
      auto room_id = parse_string_field(params, "room_id");
      auto alias = parse_string_field(params, "alias");
      if (!room_id.has_value() || !alias.has_value())
        return make_error_response({ErrorCode::corrupt});
      auto res = handle_kick(room_id.value(), alias.value());
      if (!res.has_value())
        return make_error_response(res.error());
      return make_ok_response(Value::object({{"kicked", Value{true}}}));
    }
    if (op_name == "post_message") {
      auto room_id = parse_string_field(params, "room_id");
      auto sender_alias = parse_string_field(params, "sender_alias");
      auto target = parse_string_field(params, "target");
      auto body = parse_string_field(params, "body");
      if (!room_id.has_value() || !sender_alias.has_value() || !target.has_value() ||
          !body.has_value()) {
        return make_error_response({ErrorCode::corrupt});
      }
      PartyMessageKind kind = PartyMessageKind::chat;
      if (const Value *kind_val = params.find("kind")) {
        const auto *kind_str = std::get_if<std::string>(&kind_val->value());
        if (!kind_str)
          return make_error_response({ErrorCode::corrupt});
        auto parsed_kind = parse_party_message_kind(*kind_str);
        if (!parsed_kind.has_value())
          return make_error_response({ErrorCode::corrupt});
        kind = parsed_kind.value();
      }
      auto res = handle_post_message(room_id.value(), sender_alias.value(),
                                     target.value(), body.value(), kind);
      if (!res.has_value())
        return make_error_response(res.error());
      return make_ok_response(Value::object({{"seq", Value{Number{res.value()}}}}));
    }
    if (op_name == "snapshot") {
      auto room_opt = parse_optional_string_field(params, "room_id");
      if (!room_opt.has_value())
        return make_error_response({ErrorCode::corrupt});
      std::lock_guard lock{state_mutex};
      (void)reap_expired_locked(now_ns());
      std::optional<std::string_view> room_sv;
      const auto &maybe_room = room_opt.value();
      if (maybe_room.has_value())
        room_sv = *maybe_room;
      return make_ok_response(snapshot_to_value(build_snapshot_locked(room_sv)));
    }
    if (op_name == "list_friends") {
      auto friends = handle_list_friends();
      if (!friends.has_value())
        return make_error_response(friends.error());
      Value::Array arr;
      arr.reserve(friends.value().size());
      for (const auto &peer : friends.value())
        arr.push_back(peer_to_value(peer));
      return make_ok_response(Value::object({{"friends", Value{std::move(arr)}}}));
    }
    if (op_name == "reap_expired") {
      std::int64_t target_now = now_ns();
      if (const Value *now_val = params.find("now_ns")) {
        if (!std::holds_alternative<std::nullptr_t>(now_val->value())) {
          auto parsed_now = parse_int64_field(params, "now_ns");
          if (!parsed_now.has_value() || parsed_now.value() <= 0)
            return make_error_response({ErrorCode::invalid_range});
          target_now = parsed_now.value();
        }
      }
      std::lock_guard lock{state_mutex};
      const std::size_t reaped = reap_expired_locked(target_now);
      return make_ok_response(Value::object(
          {{"reaped", Value{Number{static_cast<std::uint64_t>(reaped)}}}}));
    }
    if (op_name == "refresh_revocations") {
      auto refreshed = refresh_revocations_sync();
      if (!refreshed.has_value())
        return make_error_response(refreshed.error());
      return make_ok_response(
          Value::object({{"revocation_epoch", Value{Number{refreshed.value()}}}}));
    }
    return make_error_response({ErrorCode::unsupported});
  }

  void enqueue_response(ClientConn &client, const Value &response,
                        bool close_after = false) {
    auto dumped = dump_json(response, {config.max_line_bytes, 500000, 64});
    std::string frame;
    if (dumped.has_value() && dumped.value().size() + 1U <= config.max_line_bytes) {
      frame = std::move(dumped).value();
    } else {
      auto fallback = dump_json(make_error_response({ErrorCode::capacity}));
      frame =
          fallback.has_value()
              ? std::move(fallback).value()
              : std::string{
                    R"({"v":1,"ok":false,"error":{"code":"capacity","code_num":6,"detail":0}})"};
    }
    frame.push_back('\n');
    client.write_buf.append(frame);
    if (close_after)
      client.close_after_write = true;
  }

  void accept_ready_clients() {
    for (std::size_t i = 0; i < config.max_clients; ++i) {
      ScopedFd incoming;
      {
        const std::lock_guard spawn{detail::process_spawn_mutex};
        const int raw = ::accept(listen_fd.get(), nullptr, nullptr);
        if (raw < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return;
          return;
        }
        auto configured = configure_socket_fd(raw);
        if (!configured.has_value())
          continue;
        incoming = std::move(configured).value();
      }

      // Kernel peer-credential authentication: caller UID MUST match geteuid().
      if (!verify_peer_same_uid(incoming.get()).has_value())
        continue;

      if (clients.size() >= config.max_clients) {
        auto busy_resp = dump_json(make_error_response({ErrorCode::capacity}));
        if (busy_resp.has_value()) {
          std::string line = std::move(busy_resp).value();
          line.push_back('\n');
          (void)send_nosigpipe(incoming.get(), line.data(), line.size());
        }
        continue;
      }

      ClientConn conn{};
      conn.fd = std::move(incoming);
      conn.last_activity = SteadyClock::now();
      clients.push_back(std::move(conn));
    }
  }

  void handle_client_read(ClientConn &client) {
    if (client.close_after_write || shutdown_after_flush)
      return;
    std::array<char, 8192> chunk{};
    std::size_t bytes_read_turn = 0;
    std::size_t frames_turn = 0;
    std::size_t empty_lines_turn = 0;

    auto drain_buffered_lines = [&]() -> bool {
      while (frames_turn < kMaxFramesPerTurn &&
             empty_lines_turn < kMaxEmptyLinesPerTurn && !client.close_after_write &&
             !shutdown_after_flush) {
        const std::size_t nl = client.read_buf.find('\n');
        if (nl == std::string::npos) {
          if (client.read_buf.size() >= config.max_line_bytes) {
            client.read_buf.clear();
            enqueue_response(client, make_error_response({ErrorCode::capacity}), true);
            return false;
          }
          break;
        }
        if (nl + 1U > config.max_line_bytes) {
          client.read_buf.clear();
          enqueue_response(client, make_error_response({ErrorCode::capacity}), true);
          return false;
        }
        std::string line = client.read_buf.substr(0, nl);
        client.read_buf.erase(0, nl + 1U);
        if (!line.empty() && line.back() == '\r')
          line.pop_back();
        if (line.empty()) {
          ++empty_lines_turn;
          continue;
        }

        Value response = dispatch_request(line);
        enqueue_response(client, response, false);
        ++frames_turn;
        if (shutdown_after_flush)
          return false;
        if (client.write_buf.size() > config.max_line_bytes * 4U) {
          client.close_after_write = true;
          return false;
        }
      }
      return true;
    };

    if (!drain_buffered_lines())
      return;

    while (bytes_read_turn < kMaxReadBytesPerTurn && frames_turn < kMaxFramesPerTurn &&
           empty_lines_turn < kMaxEmptyLinesPerTurn && !client.close_after_write &&
           !shutdown_after_flush) {
      const std::size_t budget =
          std::min(chunk.size(), kMaxReadBytesPerTurn - bytes_read_turn);
      const ssize_t n = ::recv(client.fd.get(), chunk.data(), budget, 0);
      if (n < 0) {
        if (errno == EINTR)
          continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          break;
        client.fd.reset();
        return;
      }
      if (n == 0) {
        if (client.write_offset >= client.write_buf.size())
          client.fd.reset();
        else
          client.close_after_write = true;
        return;
      }
      client.last_activity = SteadyClock::now();
      const auto count = static_cast<std::size_t>(n);
      bytes_read_turn += count;

      // Guard against oversized lines before growing read_buf unboundedly.
      if (client.read_buf.size() + count > config.max_line_bytes) {
        const std::string_view piece{chunk.data(), count};
        const std::size_t nl = piece.find('\n');
        if (nl == std::string_view::npos ||
            client.read_buf.size() + nl + 1U > config.max_line_bytes) {
          client.read_buf.clear();
          enqueue_response(client, make_error_response({ErrorCode::capacity}), true);
          return;
        }
      }
      client.read_buf.append(chunk.data(), count);

      if (!drain_buffered_lines())
        return;
    }
  }

  void handle_client_write(ClientConn &client) {
    while (client.write_offset < client.write_buf.size()) {
      const ssize_t n =
          send_nosigpipe(client.fd.get(), client.write_buf.data() + client.write_offset,
                         client.write_buf.size() - client.write_offset);
      if (n > 0) {
        client.write_offset += static_cast<std::size_t>(n);
        client.last_activity = SteadyClock::now();
        continue;
      }
      if (n < 0 && errno == EINTR)
        continue;
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return;
      client.fd.reset();
      return;
    }
    client.write_buf.clear();
    client.write_offset = 0;
    if (client.close_after_write)
      client.fd.reset();
  }

  void serve_loop() noexcept {
    running_flag.store(true, std::memory_order_release);
    try {
      while (!stop_requested.load(std::memory_order_acquire)) {
        if (shutdown_after_flush) {
          bool any_pending_write = false;
          for (const auto &c : clients) {
            if (c.fd && c.write_offset < c.write_buf.size()) {
              any_pending_write = true;
              break;
            }
          }
          if (!any_pending_write || SteadyClock::now() >= shutdown_deadline)
            break;
        }

        std::vector<pollfd> fds;
        fds.reserve(2U + clients.size());
        fds.push_back(pollfd{wake_read.get(), POLLIN, 0});
        fds.push_back(pollfd{listen_fd.get(),
                             shutdown_after_flush ? short{0} : short{POLLIN}, 0});
        bool any_buffered_line = false;
        for (const auto &client : clients) {
          short ev = 0;
          if (!client.close_after_write && !shutdown_after_flush) {
            ev = static_cast<short>(ev | POLLIN);
            if (client.read_buf.find('\n') != std::string::npos)
              any_buffered_line = true;
          }
          if (client.write_offset < client.write_buf.size())
            ev = static_cast<short>(ev | POLLOUT);
          fds.push_back(pollfd{client.fd.get(), ev, 0});
        }

        const int poll_timeout = any_buffered_line ? 0 : kPollSliceMs;
        const int rc =
            ::poll(fds.data(), static_cast<nfds_t>(fds.size()), poll_timeout);
        if (rc < 0) {
          if (errno == EINTR)
            continue;
          break;
        }

        if ((fds[0].revents & POLLIN) != 0) {
          std::array<char, 64> drain{};
          while (::recv(wake_read.get(), drain.data(), drain.size(), 0) > 0) {
          }
        }

        if (!shutdown_after_flush && (fds[1].revents & POLLIN) != 0)
          accept_ready_clients();

        const auto now_steady = SteadyClock::now();
        const std::int64_t idle_ms = std::max<std::int64_t>(
            static_cast<std::int64_t>(config.io_timeout_ms) * 4LL, 30000LL);
        const auto idle_limit = std::chrono::milliseconds{idle_ms};

        for (std::size_t i = 0; i < clients.size() && (i + 2U) < fds.size(); ++i) {
          auto &client = clients[i];
          const short rev = fds[i + 2U].revents;
          if ((rev & (POLLERR | POLLNVAL)) != 0) {
            client.fd.reset();
            continue;
          }
          if (client.fd && !shutdown_after_flush &&
              ((rev & POLLIN) != 0 ||
               client.read_buf.find('\n') != std::string::npos)) {
            handle_client_read(client);
          }
          if (client.fd && client.write_offset < client.write_buf.size())
            handle_client_write(client);
          if (client.fd && (rev & POLLHUP) != 0 &&
              client.write_offset >= client.write_buf.size()) {
            client.fd.reset();
          }
          // Close stalled clients that hold partial unreadable frames past timeout.
          if (client.fd &&
              (!client.read_buf.empty() ||
               client.write_offset < client.write_buf.size()) &&
              now_steady - client.last_activity > idle_limit) {
            client.fd.reset();
          }
        }

        std::erase_if(clients,
                      [](const ClientConn &c) { return !static_cast<bool>(c.fd); });

        // Periodic automatic expiration reaping in RAM.
        {
          std::lock_guard lock{state_mutex};
          (void)reap_expired_locked(now_ns());
        }
      }
    } catch (...) {
      // Never let exceptions escape the daemon thread.
    }

    clients.clear();
    listen_fd.reset();
    unlink_owned_socket();
    running_flag.store(false, std::memory_order_release);
  }
};

// ---------------------------------------------------------------------------
// PartyLobbyServer public methods
// ---------------------------------------------------------------------------

PartyLobbyServer::PartyLobbyServer(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

PartyLobbyServer::~PartyLobbyServer() { stop(); }

Result<std::unique_ptr<PartyLobbyServer>>
PartyLobbyServer::start(PartyLobbyServerConfig config) {
  if (config.max_rooms == 0 || config.max_members_per_room == 0 ||
      config.max_messages_per_room == 0 || config.max_clients == 0 ||
      config.max_line_bytes < 1024U ||
      config.max_line_bytes > kMaxConfigurableLineBytes || config.io_timeout_ms <= 0) {
    return Result<std::unique_ptr<PartyLobbyServer>>::failure(
        {ErrorCode::invalid_range});
  }
  if (config.socket_path.empty())
    config.socket_path = default_party_socket_path();

  auto impl = std::make_unique<Impl>();
  impl->config = std::move(config);
  impl->socket_path = impl->config.socket_path;
  impl->socket_name = impl->socket_path.filename().string();
  const fs::path parent_dir = impl->socket_path.parent_path();
  if (impl->socket_name.empty() || parent_dir.empty()) {
    return Result<std::unique_ptr<PartyLobbyServer>>::failure(
        {ErrorCode::invalid_range});
  }

  auto addr_res = make_unix_address(impl->socket_path);
  if (!addr_res.has_value())
    return Result<std::unique_ptr<PartyLobbyServer>>::failure(addr_res.error());
  const sockaddr_un addr = addr_res.value();

  // Resolve local identity if provided.
  if (impl->config.local_identity.has_value()) {
    if (!valid_peer_fingerprint(impl->config.local_identity->fingerprint)) {
      return Result<std::unique_ptr<PartyLobbyServer>>::failure(
          {ErrorCode::invalid_identity});
    }
    auto canon =
        canonicalize_ed25519_public_key(impl->config.local_identity->public_key);
    auto derived =
        peer_fingerprint_from_public_key(impl->config.local_identity->public_key);
    if (!canon.has_value() || !derived.has_value() ||
        derived.value() != impl->config.local_identity->fingerprint) {
      return Result<std::unique_ptr<PartyLobbyServer>>::failure(
          {ErrorCode::invalid_identity});
    }
    impl->local_identity = PeerIdentity{derived.value(), canon.value()};
  } else if (!impl->config.local_identity_dir.empty()) {
    auto id_store = PeerIdentityStore::open_existing(impl->config.local_identity_dir,
                                                     impl->config.peer_identity_config);
    if (!id_store.has_value())
      return Result<std::unique_ptr<PartyLobbyServer>>::failure(id_store.error());
    impl->local_identity = id_store.value().identity();
  }

  // Load initial trust snapshot from KnownPeersStore (if present).
  auto initial_trust = impl->load_trust_from_disk();
  if (!initial_trust.has_value())
    return Result<std::unique_ptr<PartyLobbyServer>>::failure(initial_trust.error());
  impl->trust = std::move(initial_trust).value();

  // Pin 0700 parent directory owned by geteuid(), never symlink.
  auto dir_res = open_or_create_private_dir(parent_dir);
  if (!dir_res.has_value())
    return Result<std::unique_ptr<PartyLobbyServer>>::failure(dir_res.error());
  impl->dir_fd = std::move(dir_res).value();

  // Check existing path at socket_name.
  struct stat existing{};
  if (::fstatat(impl->dir_fd.get(), impl->socket_name.c_str(), &existing,
                AT_SYMLINK_NOFOLLOW) == 0) {
    if (!S_ISSOCK(existing.st_mode) || existing.st_uid != ::geteuid()) {
      return Result<std::unique_ptr<PartyLobbyServer>>::failure({ErrorCode::conflict});
    }
    // Probe whether a live daemon already owns the socket.
    auto probe = create_unix_stream_socket();
    if (!probe.has_value())
      return Result<std::unique_ptr<PartyLobbyServer>>::failure(probe.error());
    const int rc = ::connect(probe.value().get(),
                             reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
    if (rc == 0 || errno == EINPROGRESS || errno == EISCONN) {
      return Result<std::unique_ptr<PartyLobbyServer>>::failure({ErrorCode::conflict});
    }
    if (errno == ECONNREFUSED) {
      if (::unlinkat(impl->dir_fd.get(), impl->socket_name.c_str(), 0) != 0) {
        return Result<std::unique_ptr<PartyLobbyServer>>::failure(native_error(errno));
      }
    } else {
      return Result<std::unique_ptr<PartyLobbyServer>>::failure(native_error(errno));
    }
  } else if (errno != ENOENT) {
    return Result<std::unique_ptr<PartyLobbyServer>>::failure(native_error(errno));
  }

  // Create wakeup socketpair.
  {
    const std::lock_guard spawn{detail::process_spawn_mutex};
    std::array<int, 2> pair_fds{-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, pair_fds.data()) != 0)
      return Result<std::unique_ptr<PartyLobbyServer>>::failure(native_error(errno));
    auto wr = configure_socket_fd(pair_fds[0]);
    auto ww = configure_socket_fd(pair_fds[1]);
    if (!wr.has_value())
      return Result<std::unique_ptr<PartyLobbyServer>>::failure(wr.error());
    if (!ww.has_value())
      return Result<std::unique_ptr<PartyLobbyServer>>::failure(ww.error());
    impl->wake_read = std::move(wr).value();
    impl->wake_write = std::move(ww).value();
  }

  auto listen_res = create_unix_stream_socket();
  if (!listen_res.has_value())
    return Result<std::unique_ptr<PartyLobbyServer>>::failure(listen_res.error());
  impl->listen_fd = std::move(listen_res).value();

  if (::bind(impl->listen_fd.get(), reinterpret_cast<const sockaddr *>(&addr),
             sizeof(addr)) != 0) {
    return Result<std::unique_ptr<PartyLobbyServer>>::failure(native_error(errno));
  }

  struct stat bound_st{};
  if (::fstatat(impl->dir_fd.get(), impl->socket_name.c_str(), &bound_st,
                AT_SYMLINK_NOFOLLOW) != 0 ||
      !S_ISSOCK(bound_st.st_mode) || bound_st.st_uid != ::geteuid()) {
    return Result<std::unique_ptr<PartyLobbyServer>>::failure({ErrorCode::io, EPERM});
  }
  impl->socket_dev = bound_st.st_dev;
  impl->socket_ino = bound_st.st_ino;
  impl->bound = true;

  if (::fchmodat(impl->dir_fd.get(), impl->socket_name.c_str(), mode_t{0600}, 0) != 0 ||
      ::listen(impl->listen_fd.get(), static_cast<int>(std::min<std::size_t>(
                                          impl->config.max_clients, 128U))) != 0) {
    const int err = errno;
    impl->unlink_owned_socket();
    return Result<std::unique_ptr<PartyLobbyServer>>::failure(native_error(err));
  }

  impl->running_flag.store(true, std::memory_order_release);
  Impl *raw = impl.get();
  impl->worker = std::thread([raw]() { raw->serve_loop(); });

  return Result<std::unique_ptr<PartyLobbyServer>>::success(
      std::unique_ptr<PartyLobbyServer>{new PartyLobbyServer(std::move(impl))});
}

const std::filesystem::path &PartyLobbyServer::socket_path() const noexcept {
  return impl_->socket_path;
}

bool PartyLobbyServer::running() const noexcept {
  return impl_ && impl_->running_flag.load(std::memory_order_acquire);
}

std::size_t PartyLobbyServer::reap_expired(std::int64_t now_ns) {
  if (!impl_)
    return 0;
  std::lock_guard lock{impl_->state_mutex};
  return impl_->reap_expired_locked(now_ns);
}

Result<std::uint64_t> PartyLobbyServer::refresh_revocations() {
  if (!impl_)
    return Result<std::uint64_t>::failure({ErrorCode::stale_handle});
  return impl_->refresh_revocations_sync();
}

std::uint64_t PartyLobbyServer::revocation_epoch() const noexcept {
  if (!impl_)
    return 0;
  std::lock_guard lock{impl_->state_mutex};
  return impl_->trust.revocation_epoch;
}

PartySnapshot
PartyLobbyServer::snapshot(std::optional<std::string_view> room_id) const {
  if (!impl_)
    return PartySnapshot{};
  std::lock_guard lock{impl_->state_mutex};
  (void)impl_->reap_expired_locked(impl_->now_ns());
  return impl_->build_snapshot_locked(room_id);
}

void PartyLobbyServer::stop() {
  if (!impl_)
    return;
  impl_->stop_requested.store(true, std::memory_order_release);
  impl_->wake_loop();
  if (impl_->worker.joinable())
    impl_->worker.join();
  impl_->unlink_owned_socket();
}

// ---------------------------------------------------------------------------
// PartyLobbyClient
// ---------------------------------------------------------------------------

Result<PartyLobbyClient>
PartyLobbyClient::connect(const std::filesystem::path &socket_path,
                          PartyLobbyClientConfig config) {
  if (config.io_timeout_ms <= 0 || config.max_line_bytes < 1024U ||
      config.max_line_bytes > kMaxConfigurableLineBytes) {
    return Result<PartyLobbyClient>::failure({ErrorCode::invalid_range});
  }

  auto addr_res = make_unix_address(socket_path);
  if (!addr_res.has_value())
    return Result<PartyLobbyClient>::failure(addr_res.error());
  const sockaddr_un addr = addr_res.value();

  // Verify socket exists, is not a symlink, is owned by geteuid(), and is 0600.
  struct stat st{};
  if (::lstat(socket_path.c_str(), &st) != 0)
    return Result<PartyLobbyClient>::failure(native_error(errno));
  if (!S_ISSOCK(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 0077) != 0)
    return Result<PartyLobbyClient>::failure({ErrorCode::io, EPERM});

  auto sock_res = create_unix_stream_socket();
  if (!sock_res.has_value())
    return Result<PartyLobbyClient>::failure(sock_res.error());
  ScopedFd fd = std::move(sock_res).value();

  const auto deadline =
      SteadyClock::now() + std::chrono::milliseconds{config.io_timeout_ms};
  for (;;) {
    const int rc =
        ::connect(fd.get(), reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
    if (rc == 0)
      break;
    if (errno == EINTR)
      continue;
    if (errno == EINPROGRESS || errno == EAGAIN) {
      auto ready = wait_fd_ready(fd.get(), POLLOUT, deadline);
      if (!ready.has_value())
        return Result<PartyLobbyClient>::failure(ready.error());
      int so_err = 0;
      socklen_t len = sizeof(so_err);
      if (::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &so_err, &len) != 0)
        return Result<PartyLobbyClient>::failure(native_error(errno));
      if (so_err != 0)
        return Result<PartyLobbyClient>::failure(native_error(so_err));
      break;
    }
    return Result<PartyLobbyClient>::failure(native_error(errno));
  }

  auto cred_ok = verify_peer_same_uid(fd.get());
  if (!cred_ok.has_value())
    return Result<PartyLobbyClient>::failure(cred_ok.error());

  return Result<PartyLobbyClient>::success(PartyLobbyClient{fd.release(), config});
}

PartyLobbyClient::PartyLobbyClient(PartyLobbyClient &&other) noexcept
    : fd_(std::exchange(other.fd_, -1)), config_(other.config_),
      read_buffer_(std::move(other.read_buffer_)) {}

PartyLobbyClient &PartyLobbyClient::operator=(PartyLobbyClient &&other) noexcept {
  if (this != &other) {
    close();
    fd_ = std::exchange(other.fd_, -1);
    config_ = other.config_;
    read_buffer_ = std::move(other.read_buffer_);
  }
  return *this;
}

PartyLobbyClient::~PartyLobbyClient() { close(); }

void PartyLobbyClient::close() noexcept { invalidate_connection(); }

void PartyLobbyClient::invalidate_connection() const noexcept {
  if (fd_ >= 0) {
    (void)::close(fd_);
    fd_ = -1;
  }
  read_buffer_.clear();
}

Result<Value> PartyLobbyClient::invoke_rpc(std::string_view op, Value params) const {
  if (fd_ < 0)
    return Result<Value>::failure({ErrorCode::stale_handle});

  const Value req = Value::object({
      {"v", Value{Number{kPartyLobbyProtocolVersion}}},
      {"op", Value{std::string{op}}},
      {"params", std::move(params)},
  });
  auto dumped = dump_json(req, {config_.max_line_bytes, 100000, 32});
  if (!dumped.has_value())
    return Result<Value>::failure(dumped.error());
  std::string line = std::move(dumped).value();
  line.push_back('\n');
  if (line.size() > config_.max_line_bytes)
    return Result<Value>::failure({ErrorCode::capacity});

  const auto deadline =
      SteadyClock::now() + std::chrono::milliseconds{config_.io_timeout_ms};
  auto sent = write_all_timed(fd_, line, deadline);
  if (!sent.has_value()) {
    invalidate_connection();
    return Result<Value>::failure(sent.error());
  }

  auto resp_line = read_line_timed(fd_, read_buffer_, config_.max_line_bytes, deadline);
  if (!resp_line.has_value()) {
    invalidate_connection();
    return Result<Value>::failure(resp_line.error());
  }

  auto parsed = parse_json(resp_line.value(), {config_.max_line_bytes, 500000, 64});
  if (!parsed.has_value()) {
    invalidate_connection();
    return Result<Value>::failure({ErrorCode::corrupt});
  }
  const Value &resp = parsed.value();
  if (!std::holds_alternative<Value::Object>(resp.value())) {
    invalidate_connection();
    return Result<Value>::failure({ErrorCode::corrupt});
  }

  auto ver = parse_uint64_field(resp, "v");
  if (!ver.has_value() || ver.value() != kPartyLobbyProtocolVersion) {
    invalidate_connection();
    return Result<Value>::failure({ErrorCode::corrupt});
  }

  auto ok = parse_bool_field(resp, "ok");
  if (!ok.has_value()) {
    invalidate_connection();
    return Result<Value>::failure({ErrorCode::corrupt});
  }
  if (!ok.value()) {
    const Value *err_val = resp.find("error");
    if (!err_val || !std::holds_alternative<Value::Object>(err_val->value())) {
      invalidate_connection();
      return Result<Value>::failure({ErrorCode::corrupt});
    }
    auto code_num = parse_uint64_field(*err_val, "code_num");
    auto detail = parse_int64_field(*err_val, "detail");
    if (!code_num.has_value() || !detail.has_value()) {
      invalidate_connection();
      return Result<Value>::failure({ErrorCode::corrupt});
    }
    auto code = parse_error_code_num(code_num.value());
    if (!code.has_value()) {
      invalidate_connection();
      return Result<Value>::failure({ErrorCode::corrupt});
    }
    return Result<Value>::failure({code.value(), detail.value()});
  }
  const Value *result_val = resp.find("result");
  if (!result_val) {
    invalidate_connection();
    return Result<Value>::failure({ErrorCode::corrupt});
  }
  return Result<Value>::success(*result_val);
}

Result<PartyLobbyPing> PartyLobbyClient::ping() const {
  auto res = invoke_rpc("ping", Value::object({}));
  if (!res.has_value())
    return Result<PartyLobbyPing>::failure(res.error());
  const Value &v = res.value();
  auto ok = parse_bool_field(v, "ok");
  auto proto = parse_uint64_field(v, "protocol_version");
  auto epoch = parse_uint64_field(v, "revocation_epoch");
  auto active_room = parse_optional_string_field(v, "active_room_id");
  auto room_count = parse_uint64_field(v, "room_count");
  auto pid = parse_int64_field(v, "server_pid");
  if (!ok.has_value() || !proto.has_value() || !epoch.has_value() ||
      !active_room.has_value() || !room_count.has_value() || !pid.has_value()) {
    return Result<PartyLobbyPing>::failure({ErrorCode::corrupt});
  }
  return Result<PartyLobbyPing>::success(PartyLobbyPing{
      ok.value(),
      static_cast<std::uint32_t>(proto.value()),
      epoch.value(),
      std::move(active_room).value(),
      static_cast<std::size_t>(room_count.value()),
      pid.value(),
  });
}

Result<void> PartyLobbyClient::shutdown() {
  auto res = invoke_rpc("shutdown", Value::object({}));
  if (!res.has_value())
    return Result<void>::failure(res.error());
  return Result<void>::success();
}

Result<PartySnapshot> PartyLobbyClient::create_room(LobbyRoomRef room_id,
                                                    const PartyLease &host_lease) {
  auto res =
      invoke_rpc("create_room", Value::object({
                                    {"room_id", Value{std::string{room_id.value}}},
                                    {"lease", lease_to_wire_value(host_lease, false)},
                                }));
  if (!res.has_value())
    return Result<PartySnapshot>::failure(res.error());
  return snapshot_from_value(res.value());
}

Result<PartySnapshot> PartyLobbyClient::join_room(LobbyRoomRef room_id,
                                                  const PartyLease &lease) {
  auto res = invoke_rpc("join_room", Value::object({
                                         {"room_id", Value{std::string{room_id.value}}},
                                         {"lease", lease_to_wire_value(lease, false)},
                                     }));
  if (!res.has_value())
    return Result<PartySnapshot>::failure(res.error());
  return snapshot_from_value(res.value());
}

Result<PartyLease> PartyLobbyClient::heartbeat(
    LobbyRoomRef room_id, LobbyActorFingerprintRef actor_fingerprint,
    std::int64_t new_expires_ns, std::string_view signature_b64) {
  auto res =
      invoke_rpc("heartbeat",
                 Value::object({
                     {"room_id", Value{std::string{room_id.value}}},
                     {"actor_fingerprint", Value{std::string{actor_fingerprint.value}}},
                     {"new_expires_ns", Value{Number{new_expires_ns}}},
                     {"signature_b64", Value{std::string{signature_b64}}},
                 }));
  if (!res.has_value())
    return Result<PartyLease>::failure(res.error());
  return lease_from_wire_value(res.value(), true);
}

Result<void> PartyLobbyClient::leave_room(LobbyRoomRef room_id,
                                          LobbyActorFingerprintRef actor_fingerprint) {
  auto res =
      invoke_rpc("leave_room",
                 Value::object({
                     {"room_id", Value{std::string{room_id.value}}},
                     {"actor_fingerprint", Value{std::string{actor_fingerprint.value}}},
                 }));
  if (!res.has_value())
    return Result<void>::failure(res.error());
  return Result<void>::success();
}

Result<PartyParticipant> PartyLobbyClient::invite_friend(LobbyRoomRef room_id,
                                                         LobbyAliasRef friend_alias) {
  auto res = invoke_rpc("invite_friend",
                        Value::object({
                            {"room_id", Value{std::string{room_id.value}}},
                            {"friend_alias", Value{std::string{friend_alias.value}}},
                        }));
  if (!res.has_value())
    return Result<PartyParticipant>::failure(res.error());
  return participant_from_value(res.value());
}

Result<void> PartyLobbyClient::kick_member(LobbyRoomRef room_id, LobbyAliasRef alias) {
  auto res =
      invoke_rpc("kick_member", Value::object({
                                    {"room_id", Value{std::string{room_id.value}}},
                                    {"alias", Value{std::string{alias.value}}},
                                }));
  if (!res.has_value())
    return Result<void>::failure(res.error());
  return Result<void>::success();
}

Result<std::uint64_t> PartyLobbyClient::post_message(LobbyRoomRef room_id,
                                                     LobbyAliasRef sender_alias,
                                                     LobbyTargetRef target,
                                                     LobbyBodyRef body,
                                                     PartyMessageKind kind) {
  auto res = invoke_rpc("post_message",
                        Value::object({
                            {"room_id", Value{std::string{room_id.value}}},
                            {"sender_alias", Value{std::string{sender_alias.value}}},
                            {"target", Value{std::string{target.value}}},
                            {"body", Value{std::string{body.value}}},
                            {"kind", Value{std::string{party_message_kind_name(kind)}}},
                        }));
  if (!res.has_value())
    return Result<std::uint64_t>::failure(res.error());
  return parse_uint64_field(res.value(), "seq");
}

Result<PartySnapshot>
PartyLobbyClient::snapshot(std::optional<std::string_view> room_id) const {
  Value::Object params;
  if (room_id.has_value())
    params.emplace_back("room_id", Value{std::string{*room_id}});
  auto res = invoke_rpc("snapshot", Value::object(std::move(params)));
  if (!res.has_value())
    return Result<PartySnapshot>::failure(res.error());
  return snapshot_from_value(res.value());
}

Result<std::vector<PinnedPeer>> PartyLobbyClient::list_friends() const {
  auto res = invoke_rpc("list_friends", Value::object({}));
  if (!res.has_value())
    return Result<std::vector<PinnedPeer>>::failure(res.error());
  const Value *arr_val = res.value().find("friends");
  if (!arr_val)
    return Result<std::vector<PinnedPeer>>::failure({ErrorCode::corrupt});
  const auto *arr = std::get_if<Value::Array>(&arr_val->value());
  if (!arr)
    return Result<std::vector<PinnedPeer>>::failure({ErrorCode::corrupt});
  std::vector<PinnedPeer> out;
  out.reserve(arr->size());
  for (const auto &entry : *arr) {
    auto peer = pinned_peer_from_value(entry);
    if (!peer.has_value())
      return Result<std::vector<PinnedPeer>>::failure(peer.error());
    out.push_back(std::move(peer).value());
  }
  return Result<std::vector<PinnedPeer>>::success(std::move(out));
}

Result<std::size_t> PartyLobbyClient::reap_expired(std::optional<std::int64_t> now_ns) {
  Value::Object params;
  if (now_ns.has_value())
    params.emplace_back("now_ns", Value{Number{*now_ns}});
  auto res = invoke_rpc("reap_expired", Value::object(std::move(params)));
  if (!res.has_value())
    return Result<std::size_t>::failure(res.error());
  auto reaped = parse_uint64_field(res.value(), "reaped");
  if (!reaped.has_value())
    return Result<std::size_t>::failure(reaped.error());
  return Result<std::size_t>::success(static_cast<std::size_t>(reaped.value()));
}

Result<std::uint64_t> PartyLobbyClient::refresh_revocations() {
  auto res = invoke_rpc("refresh_revocations", Value::object({}));
  if (!res.has_value())
    return Result<std::uint64_t>::failure(res.error());
  return parse_uint64_field(res.value(), "revocation_epoch");
}

} // namespace blackbird
