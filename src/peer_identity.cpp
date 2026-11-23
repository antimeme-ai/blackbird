#include "blackbird/peer_identity.hpp"

#include "blackbird/json.hpp"
#include "native_process.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <limits>
#include <ranges>
#include <string>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace blackbird {
namespace {

constexpr const char *kPrivateKeyFile = "id_ed25519";
constexpr const char *kPublicKeyFile = "id_ed25519.pub";
constexpr const char *kIdentityLockFile = "identity.lock";
constexpr const char *kKnownPeersFile = "known_peers.json";
constexpr const char *kKnownPeersLockFile = "known_peers.lock";
constexpr std::uint64_t kKnownPeersSchemaVersion = 1;
constexpr std::size_t kMaxKnownPeersBytes = 16 * 1024 * 1024;
constexpr std::size_t kReadChunkBytes = 64 * 1024;
constexpr std::size_t kEd25519WireKeyBytes = 51;
constexpr std::size_t kEd25519CanonicalBase64Bytes = 68;
constexpr std::string_view kEd25519WirePrefix{"\x00\x00\x00\x0b"
                                              "ssh-ed25519"
                                              "\x00\x00\x00\x20",
                                              19};
constexpr std::string_view kEnvelopeSigningType = "blackbird.peer_envelope";
constexpr std::string_view kGrantSigningType = "blackbird.capability_grant";

std::atomic<std::uint64_t> g_tmp_counter{0};

Error native_error(int err) noexcept {
  if (err == EINTR)
    return {ErrorCode::interrupted, err};
  if (err == ENOTSUP)
    return {ErrorCode::unsupported, err};
  return {ErrorCode::io, err};
}

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
    if (fd_ >= 0)
      (void)::close(fd_);
    fd_ = next;
  }

private:
  int fd_ = -1;
};

struct RestrictedCheck {
  bool directory = false;
  bool require_single_link = false;
};

Result<void> check_restricted(int fd, RestrictedCheck check) noexcept {
  struct stat st{};
  if (::fstat(fd, &st) != 0)
    return Result<void>::failure(native_error(errno));
  const bool kind_ok = check.directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode);
  const bool link_ok =
      check.directory || !check.require_single_link || st.st_nlink == 1;
  if (!kind_ok || !link_ok || st.st_uid != ::geteuid() || (st.st_mode & 0077) != 0)
    return Result<void>::failure({ErrorCode::io, EPERM});
  return Result<void>::success();
}

Result<void> fsync_fd(int fd) noexcept {
  while (::fsync(fd) != 0) {
    if (errno == EINTR)
      continue;
    return Result<void>::failure(native_error(errno));
  }
  return Result<void>::success();
}

Result<void> write_all_fd(int fd, std::string_view data) noexcept {
  std::size_t offset = 0;
  while (offset < data.size()) {
    const ssize_t written = ::write(fd, data.data() + offset, data.size() - offset);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      return Result<void>::failure(native_error(errno));
    }
    if (written == 0)
      return Result<void>::failure({ErrorCode::io, EIO});
    offset += static_cast<std::size_t>(written);
  }
  return Result<void>::success();
}

Result<ScopedFd> open_or_create_restricted(int dir_fd, const char *name) noexcept {
  for (int attempt = 0; attempt < 32; ++attempt) {
    int fd = -1;
    do {
      fd = ::openat(dir_fd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      ScopedFd owned{fd};
      auto checked = check_restricted(owned.get(), {.directory = false});
      if (!checked.has_value())
        return Result<ScopedFd>::failure(checked.error());
      return Result<ScopedFd>::success(std::move(owned));
    }
    if (errno != ENOENT)
      return Result<ScopedFd>::failure(native_error(errno));

    do {
      fd = ::openat(dir_fd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    mode_t{0600});
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      ScopedFd owned{fd};
      auto checked = check_restricted(owned.get(), {.directory = false});
      if (!checked.has_value())
        return Result<ScopedFd>::failure(checked.error());
      return Result<ScopedFd>::success(std::move(owned));
    }
    if (errno != EEXIST && errno != ENOENT)
      return Result<ScopedFd>::failure(native_error(errno));
  }
  return Result<ScopedFd>::failure({ErrorCode::busy, EEXIST});
}

class ScopedFlock {
public:
  static Result<ScopedFlock> acquire(int dir_fd, const char *lock_name,
                                     bool shared) noexcept {
    auto opened = open_or_create_restricted(dir_fd, lock_name);
    if (!opened.has_value())
      return Result<ScopedFlock>::failure(opened.error());
    ScopedFd owned = std::move(opened).value();
    const int op = shared ? LOCK_SH : LOCK_EX;
    while (::flock(owned.get(), op) != 0) {
      if (errno == EINTR)
        continue;
      return Result<ScopedFlock>::failure(native_error(errno));
    }
    return Result<ScopedFlock>::success(ScopedFlock{std::move(owned)});
  }

  ScopedFlock(const ScopedFlock &) = delete;
  ScopedFlock &operator=(const ScopedFlock &) = delete;
  ScopedFlock(ScopedFlock &&other) noexcept = default;
  ScopedFlock &operator=(ScopedFlock &&other) noexcept = default;
  ~ScopedFlock() {
    if (fd_) {
      while (::flock(fd_.get(), LOCK_UN) != 0 && errno == EINTR) {
      }
    }
  }

private:
  explicit ScopedFlock(ScopedFd fd) noexcept : fd_(std::move(fd)) {}
  ScopedFd fd_;
};

Result<ScopedFd> open_pinned_directory(const std::filesystem::path &root, bool create,
                                       std::filesystem::path &normalized_root) {
  std::string path_str = root.string();
  if (path_str.empty() || path_str.find('\0') != std::string::npos)
    return Result<ScopedFd>::failure({ErrorCode::invalid_range});
  while (path_str.size() > 1 && path_str.back() == '/')
    path_str.pop_back();

  bool created = false;
  if (create) {
    if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
      created = true;
    } else if (errno == ENOENT) {
      const auto parent = std::filesystem::path{path_str}.parent_path();
      if (!parent.empty()) {
        std::error_code ec;
        (void)std::filesystem::create_directories(parent, ec);
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
  }

  int fd = -1;
  do {
    fd = ::open(path_str.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0)
    return Result<ScopedFd>::failure(native_error(errno));
  ScopedFd owned{fd};

  if (created && ::fchmod(owned.get(), mode_t{0700}) != 0)
    return Result<ScopedFd>::failure(native_error(errno));

  auto checked = check_restricted(owned.get(), {.directory = true});
  if (!checked.has_value())
    return Result<ScopedFd>::failure(checked.error());

  normalized_root = std::filesystem::path{std::move(path_str)};
  return Result<ScopedFd>::success(std::move(owned));
}

struct ReadFileResult {
  bool exists = false;
  std::string content;
};

Result<ReadFileResult> read_regular_file_bounded(int dir_fd, const char *name,
                                                 std::size_t max_bytes,
                                                 bool require_single_link = false) {
  ReadFileResult out;
  int fd = -1;
  do {
    fd = ::openat(dir_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ENOENT)
      return Result<ReadFileResult>::success(std::move(out));
    return Result<ReadFileResult>::failure(native_error(errno));
  }
  ScopedFd owned{fd};
  auto checked = check_restricted(
      owned.get(), {.directory = false, .require_single_link = require_single_link});
  if (!checked.has_value())
    return Result<ReadFileResult>::failure(checked.error());
  out.exists = true;

  std::array<char, kReadChunkBytes> buffer{};
  for (;;) {
    const ssize_t count = ::read(owned.get(), buffer.data(), buffer.size());
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return Result<ReadFileResult>::failure(native_error(errno));
    }
    if (count == 0)
      break;
    const auto bytes = static_cast<std::size_t>(count);
    if (bytes > max_bytes - out.content.size())
      return Result<ReadFileResult>::failure({ErrorCode::capacity});
    out.content.append(buffer.data(), bytes);
  }
  return Result<ReadFileResult>::success(std::move(out));
}

struct AtomicWriteSpec {
  const char *target_name = nullptr;
  const char *tmp_prefix = nullptr;
  std::string_view payload;
};

Result<void> write_file_atomic(int dir_fd, const AtomicWriteSpec &spec) {
  const auto pid = static_cast<unsigned long long>(::getpid());
  std::string tmp_name;
  ScopedFd tmp_fd;
  for (int attempt = 0; attempt < 64; ++attempt) {
    const auto seq = g_tmp_counter.fetch_add(1, std::memory_order_relaxed);
    tmp_name = std::string{spec.tmp_prefix} + "." + std::to_string(pid) + "." +
               std::to_string(seq);
    int fd = -1;
    do {
      fd = ::openat(dir_fd, tmp_name.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t{0600});
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      tmp_fd.reset(fd);
      break;
    }
    if (errno != EEXIST)
      return Result<void>::failure(native_error(errno));
  }
  if (!tmp_fd)
    return Result<void>::failure({ErrorCode::conflict, EEXIST});

  class TempFileGuard {
  public:
    TempFileGuard(int parent_fd, std::string name) noexcept
        : parent_fd_(parent_fd), name_(std::move(name)) {}
    TempFileGuard(const TempFileGuard &) = delete;
    TempFileGuard &operator=(const TempFileGuard &) = delete;
    ~TempFileGuard() {
      if (active_)
        (void)::unlinkat(parent_fd_, name_.c_str(), 0);
    }
    void dismiss() noexcept { active_ = false; }
    const char *c_str() const noexcept { return name_.c_str(); }

  private:
    int parent_fd_;
    std::string name_;
    bool active_ = true;
  } cleanup{dir_fd, std::move(tmp_name)};

  auto written = write_all_fd(tmp_fd.get(), spec.payload);
  if (!written.has_value())
    return written;
  auto synced = fsync_fd(tmp_fd.get());
  if (!synced.has_value())
    return synced;
  const int raw_fd = tmp_fd.release();
  if (::close(raw_fd) != 0)
    return Result<void>::failure(native_error(errno));

  if (::renameat(dir_fd, cleanup.c_str(), dir_fd, spec.target_name) != 0)
    return Result<void>::failure(native_error(errno));
  cleanup.dismiss();
  return fsync_fd(dir_fd);
}

class IsolatedTempDir {
public:
  static Result<IsolatedTempDir> create(const char *prefix) {
    const char *env_tmpdir = std::getenv("TMPDIR");
    std::string base = (env_tmpdir != nullptr && env_tmpdir[0] != '\0')
                           ? std::string{env_tmpdir}
                           : std::string{"/tmp"};
    while (base.size() > 1 && base.back() == '/')
      base.pop_back();
    std::string tmpl = base;
    if (tmpl.back() != '/')
      tmpl.push_back('/');
    tmpl += prefix;
    tmpl += "-XXXXXX";
    char *created = ::mkdtemp(tmpl.data());
    if (!created)
      return Result<IsolatedTempDir>::failure(native_error(errno));
    std::filesystem::path dir_path{created};
    int fd = -1;
    do {
      fd = ::open(dir_path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
      const int err = errno;
      std::error_code ec;
      (void)std::filesystem::remove_all(dir_path, ec);
      return Result<IsolatedTempDir>::failure(native_error(err));
    }
    ScopedFd owned{fd};
    if (::fchmod(owned.get(), mode_t{0700}) != 0) {
      const int err = errno;
      std::error_code ec;
      (void)std::filesystem::remove_all(dir_path, ec);
      return Result<IsolatedTempDir>::failure(native_error(err));
    }
    auto checked = check_restricted(owned.get(), {.directory = true});
    if (!checked.has_value()) {
      std::error_code ec;
      (void)std::filesystem::remove_all(dir_path, ec);
      return Result<IsolatedTempDir>::failure(checked.error());
    }
    return Result<IsolatedTempDir>::success(
        IsolatedTempDir{std::move(dir_path), std::move(owned)});
  }

  IsolatedTempDir(const IsolatedTempDir &) = delete;
  IsolatedTempDir &operator=(const IsolatedTempDir &) = delete;
  IsolatedTempDir(IsolatedTempDir &&other) noexcept
      : path_(std::move(other.path_)), dir_fd_(std::move(other.dir_fd_)),
        active_(std::exchange(other.active_, false)) {}
  IsolatedTempDir &operator=(IsolatedTempDir &&) = delete;
  ~IsolatedTempDir() {
    if (active_ && !path_.empty()) {
      dir_fd_.reset();
      std::error_code ec;
      (void)std::filesystem::remove_all(path_, ec);
    }
  }

  const std::filesystem::path &path() const noexcept { return path_; }
  int fd() const noexcept { return dir_fd_.get(); }

  Result<std::filesystem::path> write_file(const char *name,
                                           std::string_view content) const {
    int fd = -1;
    do {
      fd = ::openat(dir_fd_.get(), name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t{0600});
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
      return Result<std::filesystem::path>::failure(native_error(errno));
    ScopedFd owned{fd};
    auto written = write_all_fd(owned.get(), content);
    if (!written.has_value())
      return Result<std::filesystem::path>::failure(written.error());
    const int raw_fd = owned.release();
    if (::close(raw_fd) != 0)
      return Result<std::filesystem::path>::failure(native_error(errno));
    return Result<std::filesystem::path>::success(path_ / name);
  }

private:
  IsolatedTempDir(std::filesystem::path path, ScopedFd fd) noexcept
      : path_(std::move(path)), dir_fd_(std::move(fd)), active_(true) {}

  std::filesystem::path path_;
  ScopedFd dir_fd_;
  bool active_ = false;
};

std::int64_t wall_now_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return ns <= 0 ? 1 : static_cast<std::int64_t>(ns);
}

Result<std::string> random_id(const char *prefix) {
  std::array<unsigned char, 16> bytes{};
  if (::getentropy(bytes.data(), bytes.size()) != 0)
    return Result<std::string>::failure(native_error(errno));
  static constexpr std::string_view kHex = "0123456789abcdef";
  std::string out{prefix};
  out.reserve(out.size() + bytes.size() * 2);
  for (const unsigned char b : bytes) {
    out.push_back(kHex[(b >> 4U) & 0x0fU]);
    out.push_back(kHex[b & 0x0fU]);
  }
  return Result<std::string>::success(std::move(out));
}

// FIPS 180-4 SHA-256 over canonical public-key wire bytes.
constexpr std::array<std::uint32_t, 64> kShaK{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
};

constexpr std::uint32_t sha_rotr(std::uint32_t value, unsigned shift) noexcept {
  return (value >> shift) | (value << (32U - shift));
}

void sha_block(std::array<std::uint32_t, 8> &h, const unsigned char *block) noexcept {
  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16; ++i) {
    w[i] = (std::uint32_t{block[4 * i]} << 24U) |
           (std::uint32_t{block[(4 * i) + 1]} << 16U) |
           (std::uint32_t{block[(4 * i) + 2]} << 8U) |
           std::uint32_t{block[(4 * i) + 3]};
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const auto s0 =
        sha_rotr(w[i - 15], 7) ^ sha_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3U);
    const auto s1 = sha_rotr(w[i - 2], 17) ^ sha_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  auto a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
  for (std::size_t i = 0; i < 64; ++i) {
    const auto s1 = sha_rotr(e, 6) ^ sha_rotr(e, 11) ^ sha_rotr(e, 25);
    const auto choose = (e & f) ^ (~e & g);
    const auto t1 = k + s1 + choose + kShaK[i] + w[i];
    const auto s0 = sha_rotr(a, 2) ^ sha_rotr(a, 13) ^ sha_rotr(a, 22);
    const auto majority = (a & b) ^ (a & c) ^ (b & c);
    const auto t2 = s0 + majority;
    k = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
  h[5] += f;
  h[6] += g;
  h[7] += k;
}

std::string sha256_hex(std::string_view bytes) {
  std::array<std::uint32_t, 8> h{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  const auto *data = reinterpret_cast<const unsigned char *>(bytes.data());
  const std::size_t whole = bytes.size() - (bytes.size() % 64);
  for (std::size_t at = 0; at < whole; at += 64)
    sha_block(h, data + at);
  std::array<unsigned char, 128> tail{};
  const std::size_t rest = bytes.size() - whole;
  if (rest > 0)
    std::copy_n(data + whole, rest, tail.begin());
  tail[rest] = 0x80;
  const std::size_t blocks = rest < 56 ? 1 : 2;
  const std::uint64_t bits = static_cast<std::uint64_t>(bytes.size()) * 8U;
  for (std::size_t i = 0; i < 8; ++i) {
    tail[(blocks * 64) - 1 - i] =
        static_cast<unsigned char>((bits >> (8U * i)) & 0xffU);
  }
  for (std::size_t i = 0; i < blocks; ++i)
    sha_block(h, tail.data() + (i * 64));

  static constexpr std::string_view kHex = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (const auto word : h) {
    for (int shift = 28; shift >= 0; shift -= 4)
      out.push_back(kHex[(word >> static_cast<unsigned>(shift)) & 0x0fU]);
  }
  return out;
}

Result<std::string> base64_decode_strict(std::string_view input) {
  if (input.empty() || (input.size() % 4) != 0)
    return Result<std::string>::failure({ErrorCode::invalid_identity});

  auto decode_char = [](char ch) noexcept -> int {
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
  };

  std::string out;
  out.reserve((input.size() / 4) * 3);
  for (std::size_t i = 0; i < input.size(); i += 4) {
    const int a = decode_char(input[i]);
    const int b = decode_char(input[i + 1]);
    if (a < 0 || b < 0)
      return Result<std::string>::failure({ErrorCode::invalid_identity});
    const bool pad2 = input[i + 2] == '=';
    const bool pad3 = input[i + 3] == '=';
    if ((pad2 || pad3) && i + 4 != input.size())
      return Result<std::string>::failure({ErrorCode::invalid_identity});
    if (pad2 && !pad3)
      return Result<std::string>::failure({ErrorCode::invalid_identity});

    const int c = pad2 ? 0 : decode_char(input[i + 2]);
    const int d = pad3 ? 0 : decode_char(input[i + 3]);
    if (c < 0 || d < 0)
      return Result<std::string>::failure({ErrorCode::invalid_identity});

    if (pad2 && (b & 0x0f) != 0)
      return Result<std::string>::failure({ErrorCode::invalid_identity});
    if (pad3 && !pad2 && (c & 0x03) != 0)
      return Result<std::string>::failure({ErrorCode::invalid_identity});

    const auto triple = (static_cast<std::uint32_t>(a) << 18U) |
                        (static_cast<std::uint32_t>(b) << 12U) |
                        (static_cast<std::uint32_t>(c) << 6U) |
                        static_cast<std::uint32_t>(d);
    out.push_back(static_cast<char>((triple >> 16U) & 0xffU));
    if (!pad2)
      out.push_back(static_cast<char>((triple >> 8U) & 0xffU));
    if (!pad3)
      out.push_back(static_cast<char>(triple & 0xffU));
  }
  return Result<std::string>::success(std::move(out));
}

struct ParsedPublicKey {
  std::string canonical_line;
  std::string wire_blob;
  std::string fingerprint;
};

Result<ParsedPublicKey> parse_ed25519_public_key(std::string_view input) {
  if (input.empty() || input.size() > kPeerMaxPublicKeyBytes)
    return Result<ParsedPublicKey>::failure({ErrorCode::invalid_identity});
  while (!input.empty() && (input.back() == '\n' || input.back() == '\r' ||
                            input.back() == ' ' || input.back() == '\t')) {
    input.remove_suffix(1);
  }
  while (!input.empty() && (input.front() == ' ' || input.front() == '\t'))
    input.remove_prefix(1);
  if (input.empty() || !valid_utf8(input))
    return Result<ParsedPublicKey>::failure({ErrorCode::invalid_identity});
  for (const char ch : input) {
    const auto u = static_cast<unsigned char>(ch);
    if (u < 0x20 || u == 0x7f)
      return Result<ParsedPublicKey>::failure({ErrorCode::invalid_identity});
  }

  const std::size_t sp1 = input.find_first_of(" \t");
  if (sp1 == std::string_view::npos)
    return Result<ParsedPublicKey>::failure({ErrorCode::invalid_identity});
  const std::string_view key_type = input.substr(0, sp1);
  if (key_type != "ssh-ed25519")
    return Result<ParsedPublicKey>::failure({ErrorCode::invalid_identity});

  std::size_t key_start = sp1;
  while (key_start < input.size() &&
         (input[key_start] == ' ' || input[key_start] == '\t')) {
    ++key_start;
  }
  if (key_start >= input.size())
    return Result<ParsedPublicKey>::failure({ErrorCode::invalid_identity});
  const std::size_t sp2 = input.find_first_of(" \t", key_start);
  const std::string_view key_b64 = sp2 == std::string_view::npos
                                       ? input.substr(key_start)
                                       : input.substr(key_start, sp2 - key_start);
  if (key_b64.size() != kEd25519CanonicalBase64Bytes)
    return Result<ParsedPublicKey>::failure({ErrorCode::invalid_identity});

  auto decoded = base64_decode_strict(key_b64);
  if (!decoded.has_value())
    return Result<ParsedPublicKey>::failure({ErrorCode::invalid_identity});
  std::string wire = std::move(decoded).value();
  if (wire.size() != kEd25519WireKeyBytes ||
      std::string_view{wire}.substr(0, kEd25519WirePrefix.size()) !=
          kEd25519WirePrefix) {
    return Result<ParsedPublicKey>::failure({ErrorCode::invalid_identity});
  }

  std::string canonical = "ssh-ed25519 ";
  canonical.append(key_b64);
  std::string fp = "bb1-";
  fp.append(sha256_hex(wire), 0, 32);
  return Result<ParsedPublicKey>::success(
      ParsedPublicKey{std::move(canonical), std::move(wire), std::move(fp)});
}

bool valid_safe_token(std::string_view value, std::size_t max_len,
                      bool allow_empty) noexcept {
  if (value.empty())
    return allow_empty;
  if (value.size() > max_len)
    return false;
  for (const char ch : value) {
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' ||
                    ch == ':';
    if (!ok)
      return false;
  }
  return true;
}

Result<void> validate_utf8_text(std::string_view value, std::size_t max_bytes,
                                bool allow_empty) noexcept {
  if (!allow_empty && value.empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (value.size() > max_bytes)
    return Result<void>::failure({ErrorCode::capacity});
  if (value.find('\0') != std::string_view::npos || !valid_utf8(value))
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

Result<void> validate_config(const PeerIdentityConfig &config) {
  if (config.ssh_keygen_executable.empty() ||
      config.ssh_keygen_executable.find('\0') != std::string::npos ||
      !std::filesystem::path{config.ssh_keygen_executable}.is_absolute()) {
    return Result<void>::failure({ErrorCode::invalid_range});
  }
  if (!valid_safe_token(config.signature_namespace, 64, false))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (config.process_timeout_seconds < 1 || config.process_timeout_seconds > 300)
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

Result<void> validate_signature_armor(std::string_view signature) noexcept {
  if (signature.empty() || signature.size() > kPeerMaxSignatureBytes)
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (signature.find('\0') != std::string_view::npos || !valid_utf8(signature))
    return Result<void>::failure({ErrorCode::invalid_identity});
  constexpr std::string_view kBegin = "-----BEGIN SSH SIGNATURE-----";
  constexpr std::string_view kEnd = "-----END SSH SIGNATURE-----";
  if (!signature.starts_with(kBegin))
    return Result<void>::failure({ErrorCode::invalid_identity});
  const std::size_t end_pos = signature.find(kEnd, kBegin.size());
  if (end_pos == std::string_view::npos)
    return Result<void>::failure({ErrorCode::invalid_identity});
  const std::string_view trailer = signature.substr(end_pos + kEnd.size());
  if (!trailer.empty() && trailer != "\n" && trailer != "\r\n")
    return Result<void>::failure({ErrorCode::invalid_identity});
  return Result<void>::success();
}

Result<Value> canonicalize_json_value(const Value &value, std::size_t depth = 0) {
  if (depth > 128)
    return Result<Value>::failure({ErrorCode::capacity});
  if (const auto *arr = std::get_if<Value::Array>(&value.value())) {
    Value::Array out;
    out.reserve(arr->size());
    for (const auto &item : *arr) {
      auto canonical = canonicalize_json_value(item, depth + 1);
      if (!canonical.has_value())
        return canonical;
      out.push_back(std::move(canonical).value());
    }
    return Result<Value>::success(Value{std::move(out)});
  }
  if (const auto *obj = std::get_if<Value::Object>(&value.value())) {
    Value::Object out;
    out.reserve(obj->size());
    for (const auto &[k, v] : *obj) {
      auto canonical = canonicalize_json_value(v, depth + 1);
      if (!canonical.has_value())
        return canonical;
      out.emplace_back(k, std::move(canonical).value());
    }
    std::ranges::sort(
        out, {}, [](const auto &entry) -> const std::string & { return entry.first; });
    for (std::size_t i = 1; i < out.size(); ++i) {
      if (out[i - 1].first == out[i].first)
        return Result<Value>::failure({ErrorCode::corrupt});
    }
    return Result<Value>::success(Value::object(std::move(out)));
  }
  return Result<Value>::success(value);
}

struct ChildOutput {
  int exit_code = -1;
  std::string stdout_bytes;
  std::string stderr_bytes;
};

Result<ChildOutput> run_child_process(const PeerIdentityConfig &config,
                                      std::vector<std::string> args,
                                      std::string_view stdin_bytes) {
  auto valid = validate_config(config);
  if (!valid.has_value())
    return Result<ChildOutput>::failure(valid.error());
  try {
    detail::Child child;
    child.cancelled = config.cancelled;
    child.separate_error = true;
    child.child_environment.emplace_back("PATH=/usr/bin:/bin");
    auto copy_env = [&](const char *key) {
      if (const char *val = std::getenv(key); val != nullptr && val[0] != '\0')
        child.child_environment.emplace_back(std::string{key} + "=" + val);
    };
    copy_env("HOME");
    copy_env("TMPDIR");
    copy_env("TZ");
    child.start(std::move(args));
    const auto deadline =
        detail::Clock::now() + std::chrono::seconds{config.process_timeout_seconds};
    bool write_epipe = false;
    if (!stdin_bytes.empty()) {
      try {
        child.send(stdin_bytes, deadline);
      } catch (const Error &error) {
        if (error.code != ErrorCode::io || error.detail != EPIPE)
          throw;
        // Child exited before draining stdin (e.g. ssh-keygen -Y verify rejecting
        // corrupt signature armor on a large payload); collect its real exit status.
        write_epipe = true;
      }
    }
    child.close_input();
    int code = -1;
    std::string out = child.collect(deadline, kPeerMaxPayloadBytes, &code);
    if (write_epipe && code == 0)
      return Result<ChildOutput>::failure({ErrorCode::io, EPIPE});
    return Result<ChildOutput>::success(
        ChildOutput{code, std::move(out), std::move(child.error_bytes)});
  } catch (const Error &error) {
    return Result<ChildOutput>::failure(error);
  } catch (const std::bad_alloc &) {
    return Result<ChildOutput>::failure({ErrorCode::allocation});
  } catch (const std::length_error &) {
    return Result<ChildOutput>::failure({ErrorCode::capacity});
  }
}

Result<void> validate_envelope_fields(const PeerEnvelope &envelope,
                                      bool require_signature) {
  if (envelope.version != kPeerEnvelopeVersion)
    return Result<void>::failure({ErrorCode::unsupported});
  if (!valid_safe_token(envelope.envelope_id, kPeerMaxIdLength, false))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_peer_fingerprint(envelope.from_fingerprint))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (!valid_peer_recipient(envelope.to_fingerprint))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (!valid_safe_token(envelope.thread_id, kPeerMaxIdLength, true))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (peer_envelope_kind_name(envelope.kind).empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (envelope.timestamp_ns <= 0)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (require_signature) {
    auto sig_ok = validate_signature_armor(envelope.signature);
    if (!sig_ok.has_value())
      return sig_ok;
  }
  return Result<void>::success();
}

Result<void> validate_grant_fields(const CapabilityGrant &grant,
                                   bool require_signature) {
  if (grant.version != kCapabilityGrantVersion)
    return Result<void>::failure({ErrorCode::unsupported});
  if (!valid_safe_token(grant.grant_id, kPeerMaxIdLength, false))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (capability_grant_mode_name(grant.mode).empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_peer_fingerprint(grant.grantor_fingerprint))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (!valid_peer_fingerprint(grant.grantee_fingerprint))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (!valid_safe_token(grant.target_peer, kPeerMaxIdLength, false))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (grant.command_room.has_value()) {
    const std::string &room = *grant.command_room;
    if (!valid_safe_token(room, kPeerMaxIdLength, false))
      return Result<void>::failure({ErrorCode::invalid_range});
  } else if (grant.mode == CapabilityGrantMode::temporary_attachment) {
    return Result<void>::failure({ErrorCode::invalid_range});
  }
  if (grant.max_turns == 0 || grant.max_turns > kPeerMaxGrantTurns)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (grant.max_tokens == 0 || grant.max_tokens > kPeerMaxGrantTokens)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (grant.allowed_tools.size() > kPeerMaxAllowedTools)
    return Result<void>::failure({ErrorCode::capacity});
  for (std::size_t i = 0; i < grant.allowed_tools.size(); ++i) {
    if (!valid_safe_token(grant.allowed_tools[i], kPeerMaxIdLength, false))
      return Result<void>::failure({ErrorCode::invalid_range});
    for (std::size_t j = 0; j < i; ++j) {
      if (grant.allowed_tools[j] == grant.allowed_tools[i])
        return Result<void>::failure({ErrorCode::invalid_range});
    }
  }
  if (grant.issued_at_ns <= 0 || grant.expires_at_ns <= grant.issued_at_ns)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (require_signature) {
    auto sig_ok = validate_signature_armor(grant.signature);
    if (!sig_ok.has_value())
      return sig_ok;
  }
  return Result<void>::success();
}

Result<std::uint64_t> parse_uint64_field(const Value &object, std::string_view key) {
  const auto *field = object.find(key);
  if (!field)
    return Result<std::uint64_t>::failure({ErrorCode::corrupt});
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return Result<std::uint64_t>::failure({ErrorCode::corrupt});
  const std::string text = num->text();
  std::uint64_t parsed = 0;
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (ec != std::errc{} || ptr != text.data() + text.size())
    return Result<std::uint64_t>::failure({ErrorCode::corrupt});
  return Result<std::uint64_t>::success(parsed);
}

Result<std::int64_t> parse_int64_field(const Value &object, std::string_view key) {
  const auto *field = object.find(key);
  if (!field)
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  const std::string text = num->text();
  std::int64_t parsed = 0;
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (ec != std::errc{} || ptr != text.data() + text.size())
    return Result<std::int64_t>::failure({ErrorCode::corrupt});
  return Result<std::int64_t>::success(parsed);
}

Result<std::string> parse_string_field(const Value &object, std::string_view key) {
  const auto *field = object.find(key);
  if (!field)
    return Result<std::string>::failure({ErrorCode::corrupt});
  const auto *str = std::get_if<std::string>(&field->value());
  if (!str)
    return Result<std::string>::failure({ErrorCode::corrupt});
  return Result<std::string>::success(*str);
}

Result<bool> parse_bool_field(const Value &object, std::string_view key) {
  const auto *field = object.find(key);
  if (!field)
    return Result<bool>::failure({ErrorCode::corrupt});
  const auto *flag = std::get_if<bool>(&field->value());
  if (!flag)
    return Result<bool>::failure({ErrorCode::corrupt});
  return Result<bool>::success(*flag);
}

Result<void> validate_strict_object_keys(const Value::Object &object,
                                         std::span<const std::string_view> allowed) {
  for (std::size_t i = 0; i < object.size(); ++i) {
    const std::string_view key = object[i].first;
    bool known = false;
    for (const std::string_view candidate : allowed) {
      if (candidate == key) {
        known = true;
        break;
      }
    }
    if (!known)
      return Result<void>::failure({ErrorCode::corrupt});
    for (std::size_t j = 0; j < i; ++j) {
      if (object[j].first == key)
        return Result<void>::failure({ErrorCode::corrupt});
    }
  }
  return Result<void>::success();
}

struct KnownPeersDocument {
  std::vector<PinnedPeer> peers;
  std::vector<RevokedGrantRecord> revoked_grants;
};

Result<PinnedPeer> peer_from_value(const Value &value) {
  const auto *obj = std::get_if<Value::Object>(&value.value());
  if (!obj)
    return Result<PinnedPeer>::failure({ErrorCode::corrupt});
  static constexpr std::array<std::string_view, 8> kPeerKeys{
      "alias",        "fingerprint", "public_key",    "trust_note",
      "pinned_at_ns", "revoked",     "revoked_at_ns", "revocation_reason",
  };
  auto keys_ok = validate_strict_object_keys(*obj, kPeerKeys);
  if (!keys_ok.has_value())
    return Result<PinnedPeer>::failure(keys_ok.error());
  auto alias = parse_string_field(value, "alias");
  auto fingerprint = parse_string_field(value, "fingerprint");
  auto public_key = parse_string_field(value, "public_key");
  auto trust_note = parse_string_field(value, "trust_note");
  auto pinned_at_ns = parse_int64_field(value, "pinned_at_ns");
  auto revoked = parse_bool_field(value, "revoked");
  auto revoked_at_ns = parse_int64_field(value, "revoked_at_ns");
  auto revocation_reason = parse_string_field(value, "revocation_reason");
  if (!alias.has_value() || !fingerprint.has_value() || !public_key.has_value() ||
      !trust_note.has_value() || !pinned_at_ns.has_value() || !revoked.has_value() ||
      !revoked_at_ns.has_value() || !revocation_reason.has_value()) {
    return Result<PinnedPeer>::failure({ErrorCode::corrupt});
  }
  if (!valid_peer_alias(alias.value()))
    return Result<PinnedPeer>::failure({ErrorCode::corrupt});
  auto parsed_key = parse_ed25519_public_key(public_key.value());
  if (!parsed_key.has_value() || parsed_key.value().fingerprint != fingerprint.value())
    return Result<PinnedPeer>::failure({ErrorCode::corrupt});
  if (!validate_utf8_text(trust_note.value(), kPeerMaxTrustNoteBytes, true)
           .has_value() ||
      !validate_utf8_text(revocation_reason.value(), kPeerMaxReasonBytes, true)
           .has_value()) {
    return Result<PinnedPeer>::failure({ErrorCode::corrupt});
  }
  if (pinned_at_ns.value() < 0 || revoked_at_ns.value() < 0)
    return Result<PinnedPeer>::failure({ErrorCode::corrupt});
  ParsedPublicKey key = std::move(parsed_key).value();
  return Result<PinnedPeer>::success(PinnedPeer{
      std::move(alias).value(),
      std::move(key.fingerprint),
      std::move(key.canonical_line),
      std::move(trust_note).value(),
      pinned_at_ns.value(),
      revoked.value(),
      revoked_at_ns.value(),
      std::move(revocation_reason).value(),
  });
}

Value revoked_grant_to_value(const RevokedGrantRecord &record) {
  return Value::object({
      {"grant_id", Value{record.grant_id}},
      {"revoked_at_ns", Value{Number{record.revoked_at_ns}}},
      {"reason", Value{record.reason}},
  });
}

Result<RevokedGrantRecord> revoked_grant_from_value(const Value &value) {
  const auto *obj = std::get_if<Value::Object>(&value.value());
  if (!obj)
    return Result<RevokedGrantRecord>::failure({ErrorCode::corrupt});
  static constexpr std::array<std::string_view, 3> kRevokedGrantKeys{
      "grant_id",
      "revoked_at_ns",
      "reason",
  };
  auto keys_ok = validate_strict_object_keys(*obj, kRevokedGrantKeys);
  if (!keys_ok.has_value())
    return Result<RevokedGrantRecord>::failure(keys_ok.error());
  auto grant_id = parse_string_field(value, "grant_id");
  auto revoked_at_ns = parse_int64_field(value, "revoked_at_ns");
  auto reason = parse_string_field(value, "reason");
  if (!grant_id.has_value() || !revoked_at_ns.has_value() || !reason.has_value())
    return Result<RevokedGrantRecord>::failure({ErrorCode::corrupt});
  if (!valid_safe_token(grant_id.value(), kPeerMaxIdLength, false) ||
      revoked_at_ns.value() < 0 ||
      !validate_utf8_text(reason.value(), kPeerMaxReasonBytes, true).has_value()) {
    return Result<RevokedGrantRecord>::failure({ErrorCode::corrupt});
  }
  return Result<RevokedGrantRecord>::success(RevokedGrantRecord{
      std::move(grant_id).value(),
      revoked_at_ns.value(),
      std::move(reason).value(),
  });
}

Result<KnownPeersDocument> read_known_peers_locked(int dir_fd) {
  auto raw =
      read_regular_file_bounded(dir_fd, kKnownPeersFile, kMaxKnownPeersBytes, true);
  if (!raw.has_value())
    return Result<KnownPeersDocument>::failure(raw.error());
  if (!raw.value().exists)
    return Result<KnownPeersDocument>::success(KnownPeersDocument{});
  if (raw.value().content.empty())
    return Result<KnownPeersDocument>::failure({ErrorCode::corrupt});

  auto parsed = parse_json(raw.value().content);
  if (!parsed.has_value())
    return Result<KnownPeersDocument>::failure({ErrorCode::corrupt});
  const Value &root = parsed.value();
  if (!std::holds_alternative<Value::Object>(root.value()))
    return Result<KnownPeersDocument>::failure({ErrorCode::corrupt});
  auto version = parse_uint64_field(root, "version");
  if (!version.has_value() || version.value() != kKnownPeersSchemaVersion)
    return Result<KnownPeersDocument>::failure({ErrorCode::corrupt});

  const auto *peers_field = root.find("peers");
  if (!peers_field)
    return Result<KnownPeersDocument>::failure({ErrorCode::corrupt});
  const auto *peers_arr = std::get_if<Value::Array>(&peers_field->value());
  if (!peers_arr)
    return Result<KnownPeersDocument>::failure({ErrorCode::corrupt});

  KnownPeersDocument doc;
  doc.peers.reserve(peers_arr->size());
  for (const auto &entry : *peers_arr) {
    auto peer = peer_from_value(entry);
    if (!peer.has_value())
      return Result<KnownPeersDocument>::failure(peer.error());
    doc.peers.push_back(std::move(peer).value());
  }
  std::ranges::sort(doc.peers, {}, &PinnedPeer::alias);
  for (std::size_t i = 0; i < doc.peers.size(); ++i) {
    for (std::size_t j = 0; j < i; ++j) {
      if (doc.peers[j].alias == doc.peers[i].alias ||
          doc.peers[j].fingerprint == doc.peers[i].fingerprint) {
        return Result<KnownPeersDocument>::failure({ErrorCode::corrupt});
      }
    }
  }

  if (const auto *revoked_field = root.find("revoked_grants")) {
    const auto *revoked_arr = std::get_if<Value::Array>(&revoked_field->value());
    if (!revoked_arr)
      return Result<KnownPeersDocument>::failure({ErrorCode::corrupt});
    doc.revoked_grants.reserve(revoked_arr->size());
    for (const auto &entry : *revoked_arr) {
      auto rec = revoked_grant_from_value(entry);
      if (!rec.has_value())
        return Result<KnownPeersDocument>::failure(rec.error());
      doc.revoked_grants.push_back(std::move(rec).value());
    }
    std::ranges::sort(doc.revoked_grants, {}, &RevokedGrantRecord::grant_id);
    for (std::size_t i = 1; i < doc.revoked_grants.size(); ++i) {
      if (doc.revoked_grants[i - 1].grant_id == doc.revoked_grants[i].grant_id)
        return Result<KnownPeersDocument>::failure({ErrorCode::corrupt});
    }
  }

  return Result<KnownPeersDocument>::success(std::move(doc));
}

Result<void> write_known_peers_atomic_locked(int dir_fd,
                                             const KnownPeersDocument &doc) {
  Value::Array encoded_peers;
  encoded_peers.reserve(doc.peers.size());
  for (const auto &peer : doc.peers)
    encoded_peers.push_back(peer_to_value(peer));

  Value::Array encoded_revoked;
  encoded_revoked.reserve(doc.revoked_grants.size());
  for (const auto &rec : doc.revoked_grants)
    encoded_revoked.push_back(revoked_grant_to_value(rec));

  const Value document = Value::object({
      {"version", Value{Number{kKnownPeersSchemaVersion}}},
      {"peers", Value{std::move(encoded_peers)}},
      {"revoked_grants", Value{std::move(encoded_revoked)}},
  });
  auto json = dump_json(document);
  if (!json.has_value())
    return Result<void>::failure(json.error());
  std::string payload = std::move(json).value();
  payload.push_back('\n');

  return write_file_atomic(
      dir_fd, AtomicWriteSpec{kKnownPeersFile, ".known_peers.tmp", payload});
}

Result<PeerIdentity> load_existing_identity_locked(int dir_fd,
                                                   const std::filesystem::path &root,
                                                   const PeerIdentityConfig &config) {
  int priv_fd = -1;
  do {
    priv_fd = ::openat(dir_fd, kPrivateKeyFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (priv_fd < 0 && errno == EINTR);
  if (priv_fd < 0)
    return Result<PeerIdentity>::failure(native_error(errno));
  ScopedFd owned_priv{priv_fd};
  auto priv_ok = check_restricted(owned_priv.get(),
                                  {.directory = false, .require_single_link = true});
  if (!priv_ok.has_value())
    return Result<PeerIdentity>::failure(priv_ok.error());

  auto derived = run_child_process(
      config,
      {config.ssh_keygen_executable, "-y", "-f", (root / kPrivateKeyFile).string()},
      {});
  if (!derived.has_value())
    return Result<PeerIdentity>::failure(derived.error());
  if (derived.value().exit_code != 0)
    return Result<PeerIdentity>::failure(
        {ErrorCode::corrupt, derived.value().exit_code});

  auto parsed_derived = parse_ed25519_public_key(derived.value().stdout_bytes);
  if (!parsed_derived.has_value())
    return Result<PeerIdentity>::failure({ErrorCode::corrupt});

  auto pub_raw =
      read_regular_file_bounded(dir_fd, kPublicKeyFile, kPeerMaxPublicKeyBytes, true);
  if (!pub_raw.has_value())
    return Result<PeerIdentity>::failure(pub_raw.error());
  if (pub_raw.value().exists) {
    auto parsed_pub = parse_ed25519_public_key(pub_raw.value().content);
    if (!parsed_pub.has_value() ||
        parsed_pub.value().fingerprint != parsed_derived.value().fingerprint) {
      return Result<PeerIdentity>::failure({ErrorCode::corrupt});
    }
  }

  ParsedPublicKey derived_key = std::move(parsed_derived).value();
  return Result<PeerIdentity>::success(PeerIdentity{
      std::move(derived_key.fingerprint),
      std::move(derived_key.canonical_line),
  });
}

Result<PeerIdentity> generate_identity_locked(int dir_fd,
                                              const std::filesystem::path &root,
                                              const PeerIdentityConfig &config) {
  const auto pid = static_cast<unsigned long long>(::getpid());
  const auto seq = g_tmp_counter.fetch_add(1, std::memory_order_relaxed);
  const std::string stage_name =
      ".keygen." + std::to_string(pid) + "." + std::to_string(seq);
  if (::mkdirat(dir_fd, stage_name.c_str(), mode_t{0700}) != 0)
    return Result<PeerIdentity>::failure(native_error(errno));

  const std::filesystem::path stage_path = root / stage_name;
  class StageDirGuard {
  public:
    explicit StageDirGuard(std::filesystem::path path) noexcept
        : path_(std::move(path)) {}
    StageDirGuard(const StageDirGuard &) = delete;
    StageDirGuard &operator=(const StageDirGuard &) = delete;
    ~StageDirGuard() {
      std::error_code ec;
      (void)std::filesystem::remove_all(path_, ec);
    }

  private:
    std::filesystem::path path_;
  } cleanup{stage_path};

  int stage_fd = -1;
  do {
    stage_fd = ::openat(dir_fd, stage_name.c_str(),
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (stage_fd < 0 && errno == EINTR);
  if (stage_fd < 0)
    return Result<PeerIdentity>::failure(native_error(errno));
  ScopedFd owned_stage{stage_fd};
  if (::fchmod(owned_stage.get(), mode_t{0700}) != 0)
    return Result<PeerIdentity>::failure(native_error(errno));

  const std::filesystem::path staged_priv = stage_path / kPrivateKeyFile;
  auto generated =
      run_child_process(config,
                        {config.ssh_keygen_executable, "-q", "-t", "ed25519", "-N", "",
                         "-C", "blackbird", "-f", staged_priv.string()},
                        {});
  if (!generated.has_value())
    return Result<PeerIdentity>::failure(generated.error());
  if (generated.value().exit_code != 0)
    return Result<PeerIdentity>::failure({ErrorCode::io, generated.value().exit_code});

  auto tighten_and_sync = [&](const char *filename) -> Result<void> {
    int fd = -1;
    do {
      fd = ::openat(owned_stage.get(), filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
      return Result<void>::failure(native_error(errno));
    ScopedFd file{fd};
    if (::fchmod(file.get(), mode_t{0600}) != 0)
      return Result<void>::failure(native_error(errno));
    auto checked =
        check_restricted(file.get(), {.directory = false, .require_single_link = true});
    if (!checked.has_value())
      return checked;
    return fsync_fd(file.get());
  };

  auto priv_sync = tighten_and_sync(kPrivateKeyFile);
  if (!priv_sync.has_value())
    return Result<PeerIdentity>::failure(priv_sync.error());
  auto pub_sync = tighten_and_sync(kPublicKeyFile);
  if (!pub_sync.has_value())
    return Result<PeerIdentity>::failure(pub_sync.error());

  auto pub_raw = read_regular_file_bounded(owned_stage.get(), kPublicKeyFile,
                                           kPeerMaxPublicKeyBytes, true);
  if (!pub_raw.has_value() || !pub_raw.value().exists)
    return Result<PeerIdentity>::failure(pub_raw.has_value() ? Error{ErrorCode::corrupt}
                                                             : pub_raw.error());
  auto parsed = parse_ed25519_public_key(pub_raw.value().content);
  if (!parsed.has_value())
    return Result<PeerIdentity>::failure({ErrorCode::corrupt});

  const std::string canonical_pub_file = parsed.value().canonical_line + "\n";
  auto pub_written =
      write_file_atomic(dir_fd, AtomicWriteSpec{kPublicKeyFile, ".id_ed25519.pub.tmp",
                                                canonical_pub_file});
  if (!pub_written.has_value())
    return Result<PeerIdentity>::failure(pub_written.error());

  if (::renameat(owned_stage.get(), kPrivateKeyFile, dir_fd, kPrivateKeyFile) != 0) {
    const int err = errno;
    (void)::unlinkat(dir_fd, kPublicKeyFile, 0);
    return Result<PeerIdentity>::failure(native_error(err));
  }
  auto dir_sync = fsync_fd(dir_fd);
  if (!dir_sync.has_value())
    return Result<PeerIdentity>::failure(dir_sync.error());

  ParsedPublicKey generated_key = std::move(parsed).value();
  return Result<PeerIdentity>::success(PeerIdentity{
      std::move(generated_key.fingerprint),
      std::move(generated_key.canonical_line),
  });
}

} // namespace

std::string_view peer_envelope_kind_name(PeerEnvelopeKind kind) noexcept {
  switch (kind) {
  case PeerEnvelopeKind::mail:
    return "mail";
  case PeerEnvelopeKind::brief:
    return "brief";
  case PeerEnvelopeKind::handoff:
    return "handoff";
  case PeerEnvelopeKind::decision:
    return "decision";
  case PeerEnvelopeKind::artifact:
    return "artifact";
  case PeerEnvelopeKind::review:
    return "review";
  case PeerEnvelopeKind::recall:
    return "recall";
  }
  return {};
}

Result<PeerEnvelopeKind> parse_peer_envelope_kind(std::string_view name) noexcept {
  if (name == "mail")
    return Result<PeerEnvelopeKind>::success(PeerEnvelopeKind::mail);
  if (name == "brief")
    return Result<PeerEnvelopeKind>::success(PeerEnvelopeKind::brief);
  if (name == "handoff")
    return Result<PeerEnvelopeKind>::success(PeerEnvelopeKind::handoff);
  if (name == "decision")
    return Result<PeerEnvelopeKind>::success(PeerEnvelopeKind::decision);
  if (name == "artifact")
    return Result<PeerEnvelopeKind>::success(PeerEnvelopeKind::artifact);
  if (name == "review")
    return Result<PeerEnvelopeKind>::success(PeerEnvelopeKind::review);
  if (name == "recall")
    return Result<PeerEnvelopeKind>::success(PeerEnvelopeKind::recall);
  return Result<PeerEnvelopeKind>::failure({ErrorCode::invalid_range});
}

std::string_view capability_grant_mode_name(CapabilityGrantMode mode) noexcept {
  switch (mode) {
  case CapabilityGrantMode::direct_support:
    return "direct_support";
  case CapabilityGrantMode::temporary_attachment:
    return "temporary_attachment";
  }
  return {};
}

Result<CapabilityGrantMode>
parse_capability_grant_mode(std::string_view name) noexcept {
  if (name == "direct_support")
    return Result<CapabilityGrantMode>::success(CapabilityGrantMode::direct_support);
  if (name == "temporary_attachment") {
    return Result<CapabilityGrantMode>::success(
        CapabilityGrantMode::temporary_attachment);
  }
  return Result<CapabilityGrantMode>::failure({ErrorCode::invalid_range});
}

bool valid_peer_alias(std::string_view alias) noexcept {
  if (alias.empty() || alias.size() > kPeerMaxAliasLength || alias == "all")
    return false;
  const char first = alias.front();
  const bool first_ok = (first >= 'a' && first <= 'z') ||
                        (first >= 'A' && first <= 'Z') ||
                        (first >= '0' && first <= '9');
  if (!first_ok)
    return false;
  for (const char ch : alias) {
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
    if (!ok)
      return false;
  }
  return true;
}

bool valid_peer_fingerprint(std::string_view fingerprint) noexcept {
  if (fingerprint.size() != kPeerFingerprintLength || !fingerprint.starts_with("bb1-"))
    return false;
  for (std::size_t i = 4; i < fingerprint.size(); ++i) {
    const char ch = fingerprint[i];
    const bool hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    if (!hex)
      return false;
  }
  return true;
}

bool valid_peer_recipient(std::string_view recipient) noexcept {
  if (valid_peer_fingerprint(recipient))
    return true;
  if (!recipient.starts_with("room:"))
    return false;
  return valid_peer_alias(recipient.substr(5));
}

Result<std::string> canonicalize_ed25519_public_key(std::string_view public_key) {
  auto parsed = parse_ed25519_public_key(public_key);
  if (!parsed.has_value())
    return Result<std::string>::failure(parsed.error());
  return Result<std::string>::success(std::move(parsed).value().canonical_line);
}

Result<std::string> peer_fingerprint_from_public_key(std::string_view public_key) {
  auto parsed = parse_ed25519_public_key(public_key);
  if (!parsed.has_value())
    return Result<std::string>::failure(parsed.error());
  return Result<std::string>::success(std::move(parsed).value().fingerprint);
}

Value peer_to_value(const PinnedPeer &peer) {
  return Value::object({
      {"alias", Value{peer.alias}},
      {"fingerprint", Value{peer.fingerprint}},
      {"public_key", Value{peer.public_key}},
      {"trust_note", Value{peer.trust_note}},
      {"pinned_at_ns", Value{Number{peer.pinned_at_ns}}},
      {"revoked", Value{peer.revoked}},
      {"revoked_at_ns", Value{Number{peer.revoked_at_ns}}},
      {"revocation_reason", Value{peer.revocation_reason}},
  });
}

Value envelope_to_value(const PeerEnvelope &envelope) {
  return Value::object({
      {"version", Value{Number{envelope.version}}},
      {"envelope_id", Value{envelope.envelope_id}},
      {"from_fingerprint", Value{envelope.from_fingerprint}},
      {"to_fingerprint", Value{envelope.to_fingerprint}},
      {"thread_id", Value{envelope.thread_id}},
      {"kind", Value{std::string{peer_envelope_kind_name(envelope.kind)}}},
      {"timestamp_ns", Value{Number{envelope.timestamp_ns}}},
      {"payload", envelope.payload},
      {"signature", Value{envelope.signature}},
  });
}

Result<PeerEnvelope> envelope_from_value(const Value &value) {
  const auto *obj = std::get_if<Value::Object>(&value.value());
  if (!obj)
    return Result<PeerEnvelope>::failure({ErrorCode::corrupt});
  static constexpr std::array<std::string_view, 9> kEnvelopeKeys{
      "version", "envelope_id",  "from_fingerprint", "to_fingerprint", "thread_id",
      "kind",    "timestamp_ns", "payload",          "signature",
  };
  auto keys_ok = validate_strict_object_keys(*obj, kEnvelopeKeys);
  if (!keys_ok.has_value())
    return Result<PeerEnvelope>::failure(keys_ok.error());
  auto version = parse_uint64_field(value, "version");
  auto envelope_id = parse_string_field(value, "envelope_id");
  auto from_fp = parse_string_field(value, "from_fingerprint");
  auto to_fp = parse_string_field(value, "to_fingerprint");
  auto thread_id = parse_string_field(value, "thread_id");
  auto kind_str = parse_string_field(value, "kind");
  auto timestamp_ns = parse_int64_field(value, "timestamp_ns");
  const Value *payload = value.find("payload");
  auto signature = parse_string_field(value, "signature");
  if (!version.has_value() ||
      version.value() > std::numeric_limits<std::uint32_t>::max() ||
      !envelope_id.has_value() || !from_fp.has_value() || !to_fp.has_value() ||
      !thread_id.has_value() || !kind_str.has_value() || !timestamp_ns.has_value() ||
      !payload || !signature.has_value()) {
    return Result<PeerEnvelope>::failure({ErrorCode::corrupt});
  }
  auto payload_ok = canonicalize_json_value(*payload);
  if (!payload_ok.has_value())
    return Result<PeerEnvelope>::failure(payload_ok.error());
  auto kind = parse_peer_envelope_kind(kind_str.value());
  if (!kind.has_value())
    return Result<PeerEnvelope>::failure({ErrorCode::corrupt});
  PeerEnvelope env{
      static_cast<std::uint32_t>(version.value()),
      std::move(envelope_id).value(),
      std::move(from_fp).value(),
      std::move(to_fp).value(),
      std::move(thread_id).value(),
      kind.value(),
      timestamp_ns.value(),
      *payload,
      std::move(signature).value(),
  };
  auto valid = validate_envelope_fields(env, true);
  if (!valid.has_value())
    return Result<PeerEnvelope>::failure(valid.error());
  return Result<PeerEnvelope>::success(std::move(env));
}

Value grant_to_value(const CapabilityGrant &grant) {
  Value::Array tools;
  tools.reserve(grant.allowed_tools.size());
  for (const auto &tool : grant.allowed_tools)
    tools.emplace_back(tool);
  return Value::object({
      {"version", Value{Number{grant.version}}},
      {"grant_id", Value{grant.grant_id}},
      {"mode", Value{std::string{capability_grant_mode_name(grant.mode)}}},
      {"grantor_fingerprint", Value{grant.grantor_fingerprint}},
      {"grantee_fingerprint", Value{grant.grantee_fingerprint}},
      {"target_peer", Value{grant.target_peer}},
      {"command_room",
       grant.command_room.has_value() ? Value{*grant.command_room} : Value{nullptr}},
      {"max_turns", Value{Number{grant.max_turns}}},
      {"max_tokens", Value{Number{grant.max_tokens}}},
      {"allowed_tools", Value{std::move(tools)}},
      {"issued_at_ns", Value{Number{grant.issued_at_ns}}},
      {"expires_at_ns", Value{Number{grant.expires_at_ns}}},
      {"revocable", Value{grant.revocable}},
      {"signature", Value{grant.signature}},
  });
}

Result<CapabilityGrant> grant_from_value(const Value &value) {
  const auto *obj = std::get_if<Value::Object>(&value.value());
  if (!obj)
    return Result<CapabilityGrant>::failure({ErrorCode::corrupt});
  static constexpr std::array<std::string_view, 14> kGrantKeys{
      "version",
      "grant_id",
      "mode",
      "grantor_fingerprint",
      "grantee_fingerprint",
      "target_peer",
      "command_room",
      "max_turns",
      "max_tokens",
      "allowed_tools",
      "issued_at_ns",
      "expires_at_ns",
      "revocable",
      "signature",
  };
  auto keys_ok = validate_strict_object_keys(*obj, kGrantKeys);
  if (!keys_ok.has_value())
    return Result<CapabilityGrant>::failure(keys_ok.error());
  auto version = parse_uint64_field(value, "version");
  auto grant_id = parse_string_field(value, "grant_id");
  auto mode_str = parse_string_field(value, "mode");
  auto grantor_fp = parse_string_field(value, "grantor_fingerprint");
  auto grantee_fp = parse_string_field(value, "grantee_fingerprint");
  auto target_peer = parse_string_field(value, "target_peer");
  auto max_turns = parse_uint64_field(value, "max_turns");
  auto max_tokens = parse_uint64_field(value, "max_tokens");
  auto issued_at_ns = parse_int64_field(value, "issued_at_ns");
  auto expires_at_ns = parse_int64_field(value, "expires_at_ns");
  auto revocable = parse_bool_field(value, "revocable");
  auto signature = parse_string_field(value, "signature");
  if (!version.has_value() ||
      version.value() > std::numeric_limits<std::uint32_t>::max() ||
      !grant_id.has_value() || !mode_str.has_value() || !grantor_fp.has_value() ||
      !grantee_fp.has_value() || !target_peer.has_value() || !max_turns.has_value() ||
      max_turns.value() > std::numeric_limits<std::uint32_t>::max() ||
      !max_tokens.has_value() || !issued_at_ns.has_value() ||
      !expires_at_ns.has_value() || !revocable.has_value() || !signature.has_value()) {
    return Result<CapabilityGrant>::failure({ErrorCode::corrupt});
  }
  auto mode = parse_capability_grant_mode(mode_str.value());
  if (!mode.has_value())
    return Result<CapabilityGrant>::failure({ErrorCode::corrupt});

  std::optional<std::string> command_room;
  if (const auto *room_field = value.find("command_room")) {
    if (const auto *room_str = std::get_if<std::string>(&room_field->value()))
      command_room = *room_str;
    else if (!std::holds_alternative<std::nullptr_t>(room_field->value()))
      return Result<CapabilityGrant>::failure({ErrorCode::corrupt});
  }

  const auto *tools_field = value.find("allowed_tools");
  if (!tools_field)
    return Result<CapabilityGrant>::failure({ErrorCode::corrupt});
  const auto *tools_arr = std::get_if<Value::Array>(&tools_field->value());
  if (!tools_arr || tools_arr->size() > kPeerMaxAllowedTools)
    return Result<CapabilityGrant>::failure({ErrorCode::corrupt});
  std::vector<std::string> tools;
  tools.reserve(tools_arr->size());
  for (const auto &entry : *tools_arr) {
    const auto *tool = std::get_if<std::string>(&entry.value());
    if (!tool)
      return Result<CapabilityGrant>::failure({ErrorCode::corrupt});
    tools.push_back(*tool);
  }

  CapabilityGrant grant{
      static_cast<std::uint32_t>(version.value()),
      std::move(grant_id).value(),
      mode.value(),
      std::move(grantor_fp).value(),
      std::move(grantee_fp).value(),
      std::move(target_peer).value(),
      std::move(command_room),
      static_cast<std::uint32_t>(max_turns.value()),
      max_tokens.value(),
      std::move(tools),
      issued_at_ns.value(),
      expires_at_ns.value(),
      revocable.value(),
      std::move(signature).value(),
  };
  auto valid = validate_grant_fields(grant, true);
  if (!valid.has_value())
    return Result<CapabilityGrant>::failure(valid.error());
  return Result<CapabilityGrant>::success(std::move(grant));
}

Result<std::string> canonical_envelope_payload(const PeerEnvelope &envelope) {
  auto valid = validate_envelope_fields(envelope, false);
  if (!valid.has_value())
    return Result<std::string>::failure(valid.error());
  auto canonical_payload = canonicalize_json_value(envelope.payload);
  if (!canonical_payload.has_value())
    return Result<std::string>::failure(canonical_payload.error());

  const Value signing_doc = Value::object({
      {"envelope_id", Value{envelope.envelope_id}},
      {"from_fingerprint", Value{envelope.from_fingerprint}},
      {"kind", Value{std::string{peer_envelope_kind_name(envelope.kind)}}},
      {"payload", std::move(canonical_payload).value()},
      {"thread_id", Value{envelope.thread_id}},
      {"timestamp_ns", Value{Number{envelope.timestamp_ns}}},
      {"to_fingerprint", Value{envelope.to_fingerprint}},
      {"type", Value{std::string{kEnvelopeSigningType}}},
      {"version", Value{Number{envelope.version}}},
  });
  return dump_json(signing_doc, {kPeerMaxPayloadBytes, 500000, 128});
}

Result<std::string> canonical_grant_payload(const CapabilityGrant &grant) {
  auto valid = validate_grant_fields(grant, false);
  if (!valid.has_value())
    return Result<std::string>::failure(valid.error());

  Value::Array tools;
  tools.reserve(grant.allowed_tools.size());
  for (const auto &tool : grant.allowed_tools)
    tools.emplace_back(tool);

  const Value signing_doc = Value::object({
      {"allowed_tools", Value{std::move(tools)}},
      {"command_room",
       grant.command_room.has_value() ? Value{*grant.command_room} : Value{nullptr}},
      {"expires_at_ns", Value{Number{grant.expires_at_ns}}},
      {"grant_id", Value{grant.grant_id}},
      {"grantee_fingerprint", Value{grant.grantee_fingerprint}},
      {"grantor_fingerprint", Value{grant.grantor_fingerprint}},
      {"issued_at_ns", Value{Number{grant.issued_at_ns}}},
      {"max_tokens", Value{Number{grant.max_tokens}}},
      {"max_turns", Value{Number{grant.max_turns}}},
      {"mode", Value{std::string{capability_grant_mode_name(grant.mode)}}},
      {"revocable", Value{grant.revocable}},
      {"target_peer", Value{grant.target_peer}},
      {"type", Value{std::string{kGrantSigningType}}},
      {"version", Value{Number{grant.version}}},
  });
  return dump_json(signing_doc, {kPeerMaxPayloadBytes, 500000, 128});
}

Result<void> verify_detached_signature(const DetachedSignatureVerification &input,
                                       const PeerIdentityConfig &config) {
  auto cfg_ok = validate_config(config);
  if (!cfg_ok.has_value())
    return cfg_ok;
  if (!valid_peer_fingerprint(input.expected_fingerprint))
    return Result<void>::failure({ErrorCode::invalid_identity});
  auto parsed_key = parse_ed25519_public_key(input.public_key);
  if (!parsed_key.has_value() ||
      parsed_key.value().fingerprint != input.expected_fingerprint) {
    return Result<void>::failure({ErrorCode::invalid_identity});
  }
  auto sig_ok = validate_signature_armor(input.signature);
  if (!sig_ok.has_value())
    return sig_ok;
  if (input.payload.size() > kPeerMaxPayloadBytes)
    return Result<void>::failure({ErrorCode::capacity});

  try {
    auto temp = IsolatedTempDir::create("blackbird-verify");
    if (!temp.has_value())
      return Result<void>::failure(temp.error());

    std::string allowed_line{input.expected_fingerprint};
    allowed_line.push_back(' ');
    allowed_line.append(parsed_key.value().canonical_line);
    allowed_line.push_back('\n');
    auto allowed_path = temp.value().write_file("allowed_signers", allowed_line);
    if (!allowed_path.has_value())
      return Result<void>::failure(allowed_path.error());

    std::string sig_content{input.signature};
    if (sig_content.back() != '\n')
      sig_content.push_back('\n');
    auto sig_path = temp.value().write_file("payload.sig", sig_content);
    if (!sig_path.has_value())
      return Result<void>::failure(sig_path.error());

    auto verified = run_child_process(
        config,
        {config.ssh_keygen_executable, "-Y", "verify", "-f",
         allowed_path.value().string(), "-I", std::string{input.expected_fingerprint},
         "-n", config.signature_namespace, "-s", sig_path.value().string()},
        input.payload);
    if (!verified.has_value())
      return Result<void>::failure(verified.error());
    if (verified.value().exit_code != 0)
      return Result<void>::failure(
          {ErrorCode::invalid_identity, verified.value().exit_code});
    return Result<void>::success();
  } catch (const std::bad_alloc &) {
    return Result<void>::failure({ErrorCode::allocation});
  }
}

Result<PeerIdentityStore>
PeerIdentityStore::open_or_create(const std::filesystem::path &root,
                                  PeerIdentityConfig config) {
  auto cfg_ok = validate_config(config);
  if (!cfg_ok.has_value())
    return Result<PeerIdentityStore>::failure(cfg_ok.error());
  try {
    std::filesystem::path normalized_root;
    auto dir = open_pinned_directory(root, true, normalized_root);
    if (!dir.has_value())
      return Result<PeerIdentityStore>::failure(dir.error());
    ScopedFd owned_dir = std::move(dir).value();

    auto lock = ScopedFlock::acquire(owned_dir.get(), kIdentityLockFile, false);
    if (!lock.has_value())
      return Result<PeerIdentityStore>::failure(lock.error());

    int probe_fd = -1;
    do {
      probe_fd =
          ::openat(owned_dir.get(), kPrivateKeyFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    } while (probe_fd < 0 && errno == EINTR);

    Result<PeerIdentity> loaded = Result<PeerIdentity>::failure({ErrorCode::io});
    if (probe_fd >= 0) {
      ScopedFd close_probe{probe_fd};
      close_probe.reset();
      loaded = load_existing_identity_locked(owned_dir.get(), normalized_root, config);
    } else if (errno == ENOENT) {
      loaded = generate_identity_locked(owned_dir.get(), normalized_root, config);
    } else {
      return Result<PeerIdentityStore>::failure(native_error(errno));
    }
    if (!loaded.has_value())
      return Result<PeerIdentityStore>::failure(loaded.error());

    return Result<PeerIdentityStore>::success(
        PeerIdentityStore{std::move(normalized_root), owned_dir.release(),
                          std::move(loaded).value(), std::move(config)});
  } catch (const std::bad_alloc &) {
    return Result<PeerIdentityStore>::failure({ErrorCode::allocation});
  }
}

Result<PeerIdentityStore>
PeerIdentityStore::open_existing(const std::filesystem::path &root,
                                 PeerIdentityConfig config) {
  auto cfg_ok = validate_config(config);
  if (!cfg_ok.has_value())
    return Result<PeerIdentityStore>::failure(cfg_ok.error());
  try {
    std::filesystem::path normalized_root;
    auto dir = open_pinned_directory(root, false, normalized_root);
    if (!dir.has_value())
      return Result<PeerIdentityStore>::failure(dir.error());
    ScopedFd owned_dir = std::move(dir).value();

    auto lock = ScopedFlock::acquire(owned_dir.get(), kIdentityLockFile, true);
    if (!lock.has_value())
      return Result<PeerIdentityStore>::failure(lock.error());

    auto loaded =
        load_existing_identity_locked(owned_dir.get(), normalized_root, config);
    if (!loaded.has_value())
      return Result<PeerIdentityStore>::failure(loaded.error());

    return Result<PeerIdentityStore>::success(
        PeerIdentityStore{std::move(normalized_root), owned_dir.release(),
                          std::move(loaded).value(), std::move(config)});
  } catch (const std::bad_alloc &) {
    return Result<PeerIdentityStore>::failure({ErrorCode::allocation});
  }
}

PeerIdentityStore::PeerIdentityStore(PeerIdentityStore &&other) noexcept
    : root_(std::move(other.root_)), dir_fd_(std::exchange(other.dir_fd_, -1)),
      identity_(std::move(other.identity_)), config_(std::move(other.config_)) {}

PeerIdentityStore &PeerIdentityStore::operator=(PeerIdentityStore &&other) noexcept {
  if (this != &other) {
    if (dir_fd_ >= 0)
      (void)::close(dir_fd_);
    root_ = std::move(other.root_);
    dir_fd_ = std::exchange(other.dir_fd_, -1);
    identity_ = std::move(other.identity_);
    config_ = std::move(other.config_);
  }
  return *this;
}

PeerIdentityStore::~PeerIdentityStore() {
  if (dir_fd_ >= 0)
    (void)::close(dir_fd_);
}

Result<std::string> PeerIdentityStore::sign_bytes(std::string_view payload) const {
  if (dir_fd_ < 0)
    return Result<std::string>::failure({ErrorCode::stale_handle});
  if (payload.size() > kPeerMaxPayloadBytes)
    return Result<std::string>::failure({ErrorCode::capacity});

  int priv_fd = -1;
  do {
    priv_fd = ::openat(dir_fd_, kPrivateKeyFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (priv_fd < 0 && errno == EINTR);
  if (priv_fd < 0)
    return Result<std::string>::failure(native_error(errno));
  ScopedFd owned_priv{priv_fd};
  auto priv_ok = check_restricted(owned_priv.get(),
                                  {.directory = false, .require_single_link = true});
  if (!priv_ok.has_value())
    return Result<std::string>::failure(priv_ok.error());
  owned_priv.reset();

  auto signed_out = run_child_process(config_,
                                      {config_.ssh_keygen_executable, "-Y", "sign",
                                       "-n", config_.signature_namespace, "-f",
                                       (root_ / kPrivateKeyFile).string()},
                                      payload);
  if (!signed_out.has_value())
    return Result<std::string>::failure(signed_out.error());
  if (signed_out.value().exit_code != 0)
    return Result<std::string>::failure({ErrorCode::io, signed_out.value().exit_code});

  std::string sig = std::move(signed_out).value().stdout_bytes;
  auto sig_ok = validate_signature_armor(sig);
  if (!sig_ok.has_value())
    return Result<std::string>::failure({ErrorCode::corrupt});
  return Result<std::string>::success(std::move(sig));
}

Result<PeerEnvelope> PeerIdentityStore::sign_envelope(PeerEnvelopeDraft draft) const {
  if (dir_fd_ < 0)
    return Result<PeerEnvelope>::failure({ErrorCode::stale_handle});
  try {
    if (draft.envelope_id.empty()) {
      auto generated_id = random_id("env-");
      if (!generated_id.has_value())
        return Result<PeerEnvelope>::failure(generated_id.error());
      draft.envelope_id = std::move(generated_id).value();
    }
    if (draft.timestamp_ns == 0)
      draft.timestamp_ns = wall_now_ns();

    PeerEnvelope envelope{
        kPeerEnvelopeVersion,
        std::move(draft.envelope_id),
        identity_.fingerprint,
        std::move(draft.to_fingerprint),
        std::move(draft.thread_id),
        draft.kind,
        draft.timestamp_ns,
        std::move(draft.payload),
        {},
    };

    auto canonical = canonical_envelope_payload(envelope);
    if (!canonical.has_value())
      return Result<PeerEnvelope>::failure(canonical.error());
    auto sig = sign_bytes(canonical.value());
    if (!sig.has_value())
      return Result<PeerEnvelope>::failure(sig.error());
    envelope.signature = std::move(sig).value();
    return Result<PeerEnvelope>::success(std::move(envelope));
  } catch (const std::bad_alloc &) {
    return Result<PeerEnvelope>::failure({ErrorCode::allocation});
  }
}

Result<CapabilityGrant>
PeerIdentityStore::sign_grant(CapabilityGrantDraft draft) const {
  if (dir_fd_ < 0)
    return Result<CapabilityGrant>::failure({ErrorCode::stale_handle});
  try {
    if (draft.grant_id.empty()) {
      auto generated_id = random_id("grant-");
      if (!generated_id.has_value())
        return Result<CapabilityGrant>::failure(generated_id.error());
      draft.grant_id = std::move(generated_id).value();
    }
    if (draft.issued_at_ns == 0)
      draft.issued_at_ns = wall_now_ns();

    CapabilityGrant grant{
        kCapabilityGrantVersion,
        std::move(draft.grant_id),
        draft.mode,
        identity_.fingerprint,
        std::move(draft.grantee_fingerprint),
        std::move(draft.target_peer),
        std::move(draft.command_room),
        draft.max_turns,
        draft.max_tokens,
        std::move(draft.allowed_tools),
        draft.issued_at_ns,
        draft.expires_at_ns,
        draft.revocable,
        {},
    };

    auto canonical = canonical_grant_payload(grant);
    if (!canonical.has_value())
      return Result<CapabilityGrant>::failure(canonical.error());
    auto sig = sign_bytes(canonical.value());
    if (!sig.has_value())
      return Result<CapabilityGrant>::failure(sig.error());
    grant.signature = std::move(sig).value();
    return Result<CapabilityGrant>::success(std::move(grant));
  } catch (const std::bad_alloc &) {
    return Result<CapabilityGrant>::failure({ErrorCode::allocation});
  }
}

Result<KnownPeersStore> KnownPeersStore::open(const std::filesystem::path &root,
                                              PeerIdentityConfig config) {
  auto cfg_ok = validate_config(config);
  if (!cfg_ok.has_value())
    return Result<KnownPeersStore>::failure(cfg_ok.error());
  try {
    std::filesystem::path normalized_root;
    auto dir = open_pinned_directory(root, true, normalized_root);
    if (!dir.has_value())
      return Result<KnownPeersStore>::failure(dir.error());
    ScopedFd owned_dir = std::move(dir).value();
    return Result<KnownPeersStore>::success(KnownPeersStore{
        std::move(normalized_root), owned_dir.release(), std::move(config)});
  } catch (const std::bad_alloc &) {
    return Result<KnownPeersStore>::failure({ErrorCode::allocation});
  }
}

KnownPeersStore::KnownPeersStore(KnownPeersStore &&other) noexcept
    : root_(std::move(other.root_)), dir_fd_(std::exchange(other.dir_fd_, -1)),
      config_(std::move(other.config_)) {}

KnownPeersStore &KnownPeersStore::operator=(KnownPeersStore &&other) noexcept {
  if (this != &other) {
    if (dir_fd_ >= 0)
      (void)::close(dir_fd_);
    root_ = std::move(other.root_);
    dir_fd_ = std::exchange(other.dir_fd_, -1);
    config_ = std::move(other.config_);
  }
  return *this;
}

KnownPeersStore::~KnownPeersStore() {
  if (dir_fd_ >= 0)
    (void)::close(dir_fd_);
}

Result<PinnedPeer> KnownPeersStore::pin_peer(const PinPeerRequest &request) {
  if (dir_fd_ < 0)
    return Result<PinnedPeer>::failure({ErrorCode::stale_handle});
  if (!valid_peer_alias(request.alias))
    return Result<PinnedPeer>::failure({ErrorCode::invalid_identity});
  auto parsed_key = parse_ed25519_public_key(request.public_key);
  if (!parsed_key.has_value())
    return Result<PinnedPeer>::failure(parsed_key.error());
  auto note_ok = validate_utf8_text(request.trust_note, kPeerMaxTrustNoteBytes, true);
  if (!note_ok.has_value())
    return Result<PinnedPeer>::failure(note_ok.error());

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, kKnownPeersLockFile, false);
    if (!lock.has_value())
      return Result<PinnedPeer>::failure(lock.error());
    auto loaded = read_known_peers_locked(dir_fd_);
    if (!loaded.has_value())
      return Result<PinnedPeer>::failure(loaded.error());
    KnownPeersDocument doc = std::move(loaded).value();

    for (auto &existing : doc.peers) {
      if (existing.alias == request.alias) {
        // Explicit key-pinning protection against silent MITM key swap.
        if (existing.fingerprint != parsed_key.value().fingerprint)
          return Result<PinnedPeer>::failure({ErrorCode::conflict});
        if (existing.revoked)
          return Result<PinnedPeer>::failure({ErrorCode::conflict});
        existing.trust_note = request.trust_note;
        auto saved = write_known_peers_atomic_locked(dir_fd_, doc);
        if (!saved.has_value())
          return Result<PinnedPeer>::failure(saved.error());
        return Result<PinnedPeer>::success(existing);
      }
      if (existing.fingerprint == parsed_key.value().fingerprint)
        return Result<PinnedPeer>::failure({ErrorCode::conflict});
    }

    ParsedPublicKey pinned_key = std::move(parsed_key).value();
    PinnedPeer peer{
        request.alias,
        std::move(pinned_key.fingerprint),
        std::move(pinned_key.canonical_line),
        request.trust_note,
        wall_now_ns(),
        false,
        0,
        {},
    };
    doc.peers.push_back(peer);
    std::ranges::sort(doc.peers, {}, &PinnedPeer::alias);
    auto saved = write_known_peers_atomic_locked(dir_fd_, doc);
    if (!saved.has_value())
      return Result<PinnedPeer>::failure(saved.error());
    return Result<PinnedPeer>::success(std::move(peer));
  } catch (const std::bad_alloc &) {
    return Result<PinnedPeer>::failure({ErrorCode::allocation});
  }
}

Result<PinnedPeer> KnownPeersStore::revoke_peer(const PeerRevocationRequest &request) {
  if (dir_fd_ < 0)
    return Result<PinnedPeer>::failure({ErrorCode::stale_handle});
  if (!valid_peer_fingerprint(request.fingerprint))
    return Result<PinnedPeer>::failure({ErrorCode::invalid_identity});
  auto reason_ok = validate_utf8_text(request.reason, kPeerMaxReasonBytes, true);
  if (!reason_ok.has_value())
    return Result<PinnedPeer>::failure(reason_ok.error());

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, kKnownPeersLockFile, false);
    if (!lock.has_value())
      return Result<PinnedPeer>::failure(lock.error());
    auto loaded = read_known_peers_locked(dir_fd_);
    if (!loaded.has_value())
      return Result<PinnedPeer>::failure(loaded.error());
    KnownPeersDocument doc = std::move(loaded).value();

    for (auto &peer : doc.peers) {
      if (peer.fingerprint == request.fingerprint) {
        peer.revoked = true;
        peer.revoked_at_ns = wall_now_ns();
        peer.revocation_reason = request.reason;
        auto saved = write_known_peers_atomic_locked(dir_fd_, doc);
        if (!saved.has_value())
          return Result<PinnedPeer>::failure(saved.error());
        return Result<PinnedPeer>::success(peer);
      }
    }
    return Result<PinnedPeer>::failure({ErrorCode::invalid_identity});
  } catch (const std::bad_alloc &) {
    return Result<PinnedPeer>::failure({ErrorCode::allocation});
  }
}

Result<std::vector<PinnedPeer>> KnownPeersStore::list_peers() const {
  if (dir_fd_ < 0)
    return Result<std::vector<PinnedPeer>>::failure({ErrorCode::stale_handle});
  try {
    auto lock = ScopedFlock::acquire(dir_fd_, kKnownPeersLockFile, true);
    if (!lock.has_value())
      return Result<std::vector<PinnedPeer>>::failure(lock.error());
    auto loaded = read_known_peers_locked(dir_fd_);
    if (!loaded.has_value())
      return Result<std::vector<PinnedPeer>>::failure(loaded.error());
    return Result<std::vector<PinnedPeer>>::success(std::move(loaded).value().peers);
  } catch (const std::bad_alloc &) {
    return Result<std::vector<PinnedPeer>>::failure({ErrorCode::allocation});
  }
}

Result<std::optional<PinnedPeer>>
KnownPeersStore::find_by_fingerprint(std::string_view fingerprint) const {
  if (dir_fd_ < 0)
    return Result<std::optional<PinnedPeer>>::failure({ErrorCode::stale_handle});
  if (!valid_peer_fingerprint(fingerprint))
    return Result<std::optional<PinnedPeer>>::failure({ErrorCode::invalid_identity});
  auto peers = list_peers();
  if (!peers.has_value())
    return Result<std::optional<PinnedPeer>>::failure(peers.error());
  for (auto &peer : peers.value()) {
    if (peer.fingerprint == fingerprint)
      return Result<std::optional<PinnedPeer>>::success(std::move(peer));
  }
  return Result<std::optional<PinnedPeer>>::success(std::nullopt);
}

Result<std::optional<PinnedPeer>>
KnownPeersStore::find_by_alias(std::string_view alias) const {
  if (dir_fd_ < 0)
    return Result<std::optional<PinnedPeer>>::failure({ErrorCode::stale_handle});
  if (!valid_peer_alias(alias))
    return Result<std::optional<PinnedPeer>>::failure({ErrorCode::invalid_identity});
  auto peers = list_peers();
  if (!peers.has_value())
    return Result<std::optional<PinnedPeer>>::failure(peers.error());
  for (auto &peer : peers.value()) {
    if (peer.alias == alias)
      return Result<std::optional<PinnedPeer>>::success(std::move(peer));
  }
  return Result<std::optional<PinnedPeer>>::success(std::nullopt);
}

Result<RevokedGrantRecord>
KnownPeersStore::revoke_grant(const GrantRevocationRequest &request) {
  if (dir_fd_ < 0)
    return Result<RevokedGrantRecord>::failure({ErrorCode::stale_handle});
  if (!valid_safe_token(request.grant_id, kPeerMaxIdLength, false))
    return Result<RevokedGrantRecord>::failure({ErrorCode::invalid_range});
  auto reason_ok = validate_utf8_text(request.reason, kPeerMaxReasonBytes, true);
  if (!reason_ok.has_value())
    return Result<RevokedGrantRecord>::failure(reason_ok.error());

  try {
    auto lock = ScopedFlock::acquire(dir_fd_, kKnownPeersLockFile, false);
    if (!lock.has_value())
      return Result<RevokedGrantRecord>::failure(lock.error());
    auto loaded = read_known_peers_locked(dir_fd_);
    if (!loaded.has_value())
      return Result<RevokedGrantRecord>::failure(loaded.error());
    KnownPeersDocument doc = std::move(loaded).value();

    for (auto &existing : doc.revoked_grants) {
      if (existing.grant_id == request.grant_id) {
        existing.revoked_at_ns = wall_now_ns();
        existing.reason = request.reason;
        auto saved = write_known_peers_atomic_locked(dir_fd_, doc);
        if (!saved.has_value())
          return Result<RevokedGrantRecord>::failure(saved.error());
        return Result<RevokedGrantRecord>::success(existing);
      }
    }

    RevokedGrantRecord record{request.grant_id, wall_now_ns(), request.reason};
    doc.revoked_grants.push_back(record);
    std::ranges::sort(doc.revoked_grants, {}, &RevokedGrantRecord::grant_id);
    auto saved = write_known_peers_atomic_locked(dir_fd_, doc);
    if (!saved.has_value())
      return Result<RevokedGrantRecord>::failure(saved.error());
    return Result<RevokedGrantRecord>::success(std::move(record));
  } catch (const std::bad_alloc &) {
    return Result<RevokedGrantRecord>::failure({ErrorCode::allocation});
  }
}

Result<bool> KnownPeersStore::is_grant_revoked(std::string_view grant_id) const {
  if (dir_fd_ < 0)
    return Result<bool>::failure({ErrorCode::stale_handle});
  if (!valid_safe_token(grant_id, kPeerMaxIdLength, false))
    return Result<bool>::failure({ErrorCode::invalid_range});
  auto list = list_revoked_grants();
  if (!list.has_value())
    return Result<bool>::failure(list.error());
  for (const auto &rec : list.value()) {
    if (rec.grant_id == grant_id)
      return Result<bool>::success(true);
  }
  return Result<bool>::success(false);
}

Result<std::vector<RevokedGrantRecord>> KnownPeersStore::list_revoked_grants() const {
  if (dir_fd_ < 0)
    return Result<std::vector<RevokedGrantRecord>>::failure({ErrorCode::stale_handle});
  try {
    auto lock = ScopedFlock::acquire(dir_fd_, kKnownPeersLockFile, true);
    if (!lock.has_value())
      return Result<std::vector<RevokedGrantRecord>>::failure(lock.error());
    auto loaded = read_known_peers_locked(dir_fd_);
    if (!loaded.has_value())
      return Result<std::vector<RevokedGrantRecord>>::failure(loaded.error());
    return Result<std::vector<RevokedGrantRecord>>::success(
        std::move(loaded).value().revoked_grants);
  } catch (const std::bad_alloc &) {
    return Result<std::vector<RevokedGrantRecord>>::failure({ErrorCode::allocation});
  }
}

Result<void> KnownPeersStore::verify_envelope(const PeerEnvelope &envelope) const {
  if (dir_fd_ < 0)
    return Result<void>::failure({ErrorCode::stale_handle});
  auto valid = validate_envelope_fields(envelope, true);
  if (!valid.has_value())
    return valid;

  std::string sender_public_key;
  {
    auto found = find_by_fingerprint(envelope.from_fingerprint);
    if (!found.has_value())
      return Result<void>::failure(found.error());
    const auto &maybe_peer = found.value();
    if (!maybe_peer.has_value())
      return Result<void>::failure({ErrorCode::invalid_identity});
    if (maybe_peer->revoked)
      return Result<void>::failure({ErrorCode::conflict});
    sender_public_key = maybe_peer->public_key;
  }

  auto canonical = canonical_envelope_payload(envelope);
  if (!canonical.has_value())
    return Result<void>::failure(canonical.error());

  return verify_detached_signature(
      DetachedSignatureVerification{
          envelope.from_fingerprint,
          sender_public_key,
          canonical.value(),
          envelope.signature,
      },
      config_);
}

Result<void> KnownPeersStore::verify_grant(const CapabilityGrant &grant,
                                           std::int64_t now_ns) const {
  if (dir_fd_ < 0)
    return Result<void>::failure({ErrorCode::stale_handle});
  auto valid = validate_grant_fields(grant, true);
  if (!valid.has_value())
    return valid;
  if (now_ns < 0)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (now_ns >= grant.expires_at_ns)
    return Result<void>::failure({ErrorCode::stale_handle});
  if (now_ns < grant.issued_at_ns)
    return Result<void>::failure({ErrorCode::invalid_range});

  auto check_grant_trust = [&]() -> Result<std::string> {
    auto lock = ScopedFlock::acquire(dir_fd_, kKnownPeersLockFile, true);
    if (!lock.has_value())
      return Result<std::string>::failure(lock.error());
    auto loaded = read_known_peers_locked(dir_fd_);
    if (!loaded.has_value())
      return Result<std::string>::failure(loaded.error());
    const KnownPeersDocument &doc = loaded.value();

    const PinnedPeer *grantor = nullptr;
    for (const auto &peer : doc.peers) {
      if (peer.fingerprint == grant.grantor_fingerprint) {
        grantor = &peer;
        break;
      }
    }
    if (!grantor)
      return Result<std::string>::failure({ErrorCode::invalid_identity});
    if (grantor->revoked)
      return Result<std::string>::failure({ErrorCode::conflict});
    for (const auto &revoked : doc.revoked_grants) {
      if (revoked.grant_id == grant.grant_id)
        return Result<std::string>::failure({ErrorCode::conflict});
    }
    return Result<std::string>::success(grantor->public_key);
  };

  auto grantor_public_key = check_grant_trust();
  if (!grantor_public_key.has_value())
    return Result<void>::failure(grantor_public_key.error());

  auto canonical = canonical_grant_payload(grant);
  if (!canonical.has_value())
    return Result<void>::failure(canonical.error());

  auto verified = verify_detached_signature(
      DetachedSignatureVerification{
          grant.grantor_fingerprint,
          grantor_public_key.value(),
          canonical.value(),
          grant.signature,
      },
      config_);
  if (!verified.has_value())
    return verified;

  // Re-check peer and local grant revocation under shared flock after
  // ssh-keygen verification completes to close the concurrent revoke-vs-verify race.
  auto rechecked = check_grant_trust();
  if (!rechecked.has_value())
    return Result<void>::failure(rechecked.error());
  if (rechecked.value() != grantor_public_key.value())
    return Result<void>::failure({ErrorCode::conflict});
  return Result<void>::success();
}

} // namespace blackbird
