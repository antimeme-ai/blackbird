#include "blackbird/project_memory.hpp"
#include "blackbird/json.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <fcntl.h>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace blackbird {
namespace {

constexpr const char *kEntriesFile = "entries.jsonl";
constexpr const char *kMemoryLockFile = "memory.lock";
constexpr std::size_t kMaxEntryLineBytes = 1024 * 1024;
constexpr std::size_t kReadChunkBytes = 64 * 1024;
constexpr std::uint64_t kTitleWeight = 3;
constexpr std::uint64_t kTagWeight = 2;
constexpr std::uint64_t kBodyWeight = 1;

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

Result<void> check_restricted(int fd, bool directory) noexcept {
  struct stat st{};
  if (::fstat(fd, &st) != 0)
    return Result<void>::failure(native_error(errno));
  const bool kind_ok = directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode);
  if (!kind_ok || st.st_uid != ::geteuid() || (st.st_mode & 0077) != 0)
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
  // Bounded open-existing / create-exclusive loop avoids Darwin/APFS races on
  // concurrent O_CREAT | O_NOFOLLOW opens.
  for (int attempt = 0; attempt < 32; ++attempt) {
    int fd = -1;
    do {
      fd = ::openat(dir_fd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      ScopedFd owned{fd};
      auto checked = check_restricted(owned.get(), false);
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
      auto checked = check_restricted(owned.get(), false);
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

std::int64_t wall_now_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return ns < 0 ? 0 : static_cast<std::int64_t>(ns);
}

// FIPS 180-4 SHA-256 streaming hasher.
constexpr std::array<std::uint32_t, 64> kSha256K = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
    0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
    0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
    0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

constexpr std::uint32_t rotr32(std::uint32_t x, unsigned n) noexcept {
  return (x >> n) | (x << (32U - n));
}

void sha256_compress(std::array<std::uint32_t, 8> &state,
                     const unsigned char *block) noexcept {
  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16; ++i) {
    const std::size_t j = i * 4;
    w[i] = (static_cast<std::uint32_t>(block[j]) << 24U) |
           (static_cast<std::uint32_t>(block[j + 1]) << 16U) |
           (static_cast<std::uint32_t>(block[j + 2]) << 8U) |
           static_cast<std::uint32_t>(block[j + 3]);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 =
        rotr32(w[i - 15], 7U) ^ rotr32(w[i - 15], 18U) ^ (w[i - 15] >> 3U);
    const std::uint32_t s1 =
        rotr32(w[i - 2], 17U) ^ rotr32(w[i - 2], 19U) ^ (w[i - 2] >> 10U);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state[0];
  std::uint32_t b = state[1];
  std::uint32_t c = state[2];
  std::uint32_t d = state[3];
  std::uint32_t e = state[4];
  std::uint32_t f = state[5];
  std::uint32_t g = state[6];
  std::uint32_t h = state[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

class Sha256Hasher {
public:
  void update(const unsigned char *data, std::size_t len) noexcept {
    total_bytes_ += static_cast<std::uint64_t>(len);
    std::size_t offset = 0;
    if (buffered_ > 0) {
      const std::size_t take = std::min(len, std::size_t{64} - buffered_);
      std::copy_n(data, take, buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_));
      buffered_ += take;
      offset += take;
      if (buffered_ == 64) {
        sha256_compress(state_, buffer_.data());
        buffered_ = 0;
      }
    }
    while (len - offset >= 64) {
      sha256_compress(state_, data + offset);
      offset += 64;
    }
    if (offset < len) {
      const std::size_t rem = len - offset;
      std::copy_n(data + offset, rem, buffer_.begin());
      buffered_ = rem;
    }
  }

  std::string finalize_hex() {
    std::array<unsigned char, 128> tail{};
    if (buffered_ > 0)
      std::copy_n(buffer_.begin(), buffered_, tail.begin());
    tail[buffered_] = 0x80U;
    const std::size_t blocks = buffered_ < 56 ? 1U : 2U;
    const std::uint64_t bit_len = total_bytes_ * 8U;
    for (std::size_t i = 0; i < 8; ++i) {
      tail[(blocks * 64) - 1 - i] =
          static_cast<unsigned char>((bit_len >> (8U * i)) & 0xffU);
    }
    for (std::size_t i = 0; i < blocks; ++i)
      sha256_compress(state_, tail.data() + (i * 64));

    static constexpr std::string_view kHex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (const auto word : state_) {
      for (int shift = 28; shift >= 0; shift -= 4)
        out.push_back(kHex[(word >> static_cast<unsigned>(shift)) & 0xfU]);
    }
    return out;
  }

private:
  std::array<std::uint32_t, 8> state_{
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  std::array<unsigned char, 64> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
};

struct TextValidationOptions {
  std::size_t max_bytes = 0;
  bool allow_empty = false;
  bool allow_control = true;
};

Result<void> validate_text(std::string_view value,
                           TextValidationOptions opts) noexcept {
  if (!opts.allow_empty && value.empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (value.size() > opts.max_bytes)
    return Result<void>::failure({ErrorCode::capacity});
  if (value.find('\0') != std::string_view::npos)
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_utf8(value))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!opts.allow_control) {
    for (const char ch : value) {
      const auto byte = static_cast<unsigned char>(ch);
      if (byte < 0x20U || byte == 0x7fU)
        return Result<void>::failure({ErrorCode::invalid_range});
    }
  }
  return Result<void>::success();
}

bool split_normalized_segments(std::string_view path, std::vector<std::string> &out) {
  out.clear();
  std::size_t pos = 0;
  while (pos < path.size()) {
    while (pos < path.size() && path[pos] == '/')
      ++pos;
    if (pos >= path.size())
      break;
    const std::size_t end = path.find('/', pos);
    const std::string_view segment =
        end == std::string_view::npos ? path.substr(pos) : path.substr(pos, end - pos);
    if (segment == "..")
      return false;
    if (!segment.empty() && segment != ".")
      out.emplace_back(segment);
    if (end == std::string_view::npos)
      break;
    pos = end + 1;
  }
  return true;
}

bool has_dotdot_segment(std::string_view path) noexcept {
  std::size_t pos = 0;
  while (pos < path.size()) {
    while (pos < path.size() && path[pos] == '/')
      ++pos;
    if (pos >= path.size())
      break;
    const std::size_t end = path.find('/', pos);
    const std::string_view segment =
        end == std::string_view::npos ? path.substr(pos) : path.substr(pos, end - pos);
    if (segment == "..")
      return true;
    if (end == std::string_view::npos)
      break;
    pos = end + 1;
  }
  return false;
}

Result<void> validate_source_path(std::string_view path) noexcept {
  auto ok = validate_text(path, {kMemoryMaxPathBytes, false, false});
  if (!ok.has_value())
    return ok;
  if (has_dotdot_segment(path))
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
}

Result<ScopedFd> open_verify_root_dir(const std::filesystem::path &root) noexcept {
  std::string path_str = root.string();
  if (path_str.empty() || path_str.find('\0') != std::string::npos)
    return Result<ScopedFd>::failure({ErrorCode::invalid_range});
  if (has_dotdot_segment(path_str))
    return Result<ScopedFd>::failure({ErrorCode::invalid_range});
  while (path_str.size() > 1 && path_str.back() == '/')
    path_str.pop_back();

  int fd = -1;
  do {
    fd = ::open(path_str.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0)
    return Result<ScopedFd>::failure(native_error(errno));
  return Result<ScopedFd>::success(ScopedFd{fd});
}

bool strip_prefix_segments(const std::vector<std::string> &root_segs,
                           const std::vector<std::string> &target_segs,
                           std::vector<std::string> &relative) {
  if (target_segs.size() <= root_segs.size())
    return false;
  for (std::size_t i = 0; i < root_segs.size(); ++i) {
    if (target_segs[i] != root_segs[i])
      return false;
  }
  relative.assign(target_segs.begin() + static_cast<std::ptrdiff_t>(root_segs.size()),
                  target_segs.end());
  return !relative.empty();
}

Result<std::vector<std::string>>
resolve_contained_relative_segments(const std::filesystem::path &root,
                                    std::string_view source_path) {
  auto path_ok = validate_source_path(source_path);
  if (!path_ok.has_value())
    return Result<std::vector<std::string>>::failure(path_ok.error());

  std::vector<std::string> segments;
  if (!split_normalized_segments(source_path, segments))
    return Result<std::vector<std::string>>::failure({ErrorCode::invalid_range});
  if (segments.empty())
    return Result<std::vector<std::string>>::failure({ErrorCode::invalid_range});

  if (source_path.front() != '/')
    return Result<std::vector<std::string>>::success(std::move(segments));

  // Absolute path: must be strictly contained inside root (matching either the
  // lexical root or its canonical realpath to tolerate OS symlinks like /tmp ->
  // /private/tmp on macOS).
  const std::string root_str = root.string();
  std::vector<std::string> root_segs;
  if (!root_str.empty() && root_str.front() == '/' &&
      split_normalized_segments(root_str, root_segs)) {
    std::vector<std::string> relative;
    if (strip_prefix_segments(root_segs, segments, relative))
      return Result<std::vector<std::string>>::success(std::move(relative));
  }

  std::array<char, PATH_MAX> resolved_buf{};
  if (::realpath(root_str.c_str(), resolved_buf.data()) != nullptr) {
    std::vector<std::string> canon_root_segs;
    if (split_normalized_segments(std::string_view{resolved_buf.data()},
                                  canon_root_segs)) {
      std::vector<std::string> relative;
      if (strip_prefix_segments(canon_root_segs, segments, relative))
        return Result<std::vector<std::string>>::success(std::move(relative));
    }
  }

  return Result<std::vector<std::string>>::failure({ErrorCode::invalid_range});
}

Result<std::string> hash_source_under_fd(int root_fd, const std::filesystem::path &root,
                                         std::string_view source_path) {
  auto rel = resolve_contained_relative_segments(root, source_path);
  if (!rel.has_value())
    return Result<std::string>::failure(rel.error());
  const auto &segments = rel.value();

  int current_fd = root_fd;
  ScopedFd owned_dir;
  for (std::size_t i = 0; i + 1 < segments.size(); ++i) {
    int next_fd = -1;
    do {
      next_fd = ::openat(current_fd, segments[i].c_str(),
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (next_fd < 0 && errno == EINTR);
    if (next_fd < 0) {
      const int err = errno;
      if (err == ENOTDIR) {
        struct stat st{};
        if (::fstatat(current_fd, segments[i].c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISLNK(st.st_mode))
          return Result<std::string>::failure({ErrorCode::io, ELOOP});
      }
      return Result<std::string>::failure(native_error(err));
    }
    owned_dir.reset(next_fd);
    current_fd = owned_dir.get();
  }

  int file_fd = -1;
  do {
    file_fd = ::openat(current_fd, segments.back().c_str(),
                       O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (file_fd < 0 && errno == EINTR);
  if (file_fd < 0)
    return Result<std::string>::failure(native_error(errno));
  ScopedFd owned_file{file_fd};

  struct stat st{};
  if (::fstat(owned_file.get(), &st) != 0)
    return Result<std::string>::failure(native_error(errno));
  if (!S_ISREG(st.st_mode))
    return Result<std::string>::failure({ErrorCode::invalid_range});

  Sha256Hasher hasher;
  std::array<unsigned char, kReadChunkBytes> chunk{};
  for (;;) {
    const ssize_t count = ::read(owned_file.get(), chunk.data(), chunk.size());
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return Result<std::string>::failure(native_error(errno));
    }
    if (count == 0)
      break;
    hasher.update(chunk.data(), static_cast<std::size_t>(count));
  }
  return Result<std::string>::success(hasher.finalize_hex());
}

Result<void> validate_tags(const std::vector<std::string> &tags) noexcept {
  if (tags.size() > kMemoryMaxTags)
    return Result<void>::failure({ErrorCode::capacity});
  for (const auto &tag : tags) {
    auto ok = validate_text(tag, {kMemoryMaxTagBytes, false, false});
    if (!ok.has_value())
      return ok;
  }
  return Result<void>::success();
}

Result<void> validate_request_basics(const MemoryRecordRequest &req) noexcept {
  if (memory_kind_name(req.kind).empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  auto title_ok = validate_text(req.title, {kMemoryMaxTitleBytes, false, false});
  if (!title_ok.has_value())
    return title_ok;
  auto body_ok = validate_text(req.body, {kMemoryMaxBodyBytes, false, true});
  if (!body_ok.has_value())
    return body_ok;
  auto tags_ok = validate_tags(req.tags);
  if (!tags_ok.has_value())
    return tags_ok;
  if (!valid_memory_actor(req.actor))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (req.session_id.has_value()) {
    auto sid_ok =
        validate_text(*req.session_id, {kMemoryMaxSessionIdLength, false, false});
    if (!sid_ok.has_value())
      return sid_ok;
  }
  if (req.sources.size() > kMemoryMaxSources)
    return Result<void>::failure({ErrorCode::capacity});
  if (req.supersedes.has_value() && !valid_memory_id(*req.supersedes))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (req.created_ns < 0)
    return Result<void>::failure({ErrorCode::invalid_range});
  return Result<void>::success();
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

Result<std::optional<std::string>> parse_optional_string_field(const Value &object,
                                                               std::string_view key) {
  const auto *field = object.find(key);
  if (!field || std::holds_alternative<std::nullptr_t>(field->value()))
    return Result<std::optional<std::string>>::success(std::nullopt);
  const auto *str = std::get_if<std::string>(&field->value());
  if (!str)
    return Result<std::optional<std::string>>::failure({ErrorCode::corrupt});
  return Result<std::optional<std::string>>::success(*str);
}

Value entry_to_disk_value(const MemoryEntry &entry) {
  Value::Object fields{
      {"id", Value{entry.id}},
      {"kind", Value{std::string{memory_kind_name(entry.kind)}}},
      {"title", Value{entry.title}},
      {"body", Value{entry.body}},
      {"actor", Value{entry.actor}},
      {"created_ns", Value{Number{entry.created_ns}}},
  };
  if (!entry.tags.empty()) {
    Value::Array tags;
    tags.reserve(entry.tags.size());
    for (const auto &tag : entry.tags)
      tags.emplace_back(tag);
    fields.emplace_back("tags", Value{std::move(tags)});
  }
  if (entry.session_id.has_value())
    fields.emplace_back("session_id", Value{*entry.session_id});
  if (!entry.sources.empty()) {
    Value::Array sources;
    sources.reserve(entry.sources.size());
    for (const auto &pin : entry.sources)
      sources.push_back(to_value(pin));
    fields.emplace_back("sources", Value{std::move(sources)});
  }
  if (entry.supersedes.has_value())
    fields.emplace_back("supersedes", Value{*entry.supersedes});
  return Value::object(std::move(fields));
}

struct ParsedLineEntry {
  std::uint64_t id_num = 0;
  MemoryEntry entry;
};

Result<ParsedLineEntry> parse_entry_line(std::string_view line) {
  ValueLimits limits{};
  limits.bytes = kMaxEntryLineBytes;
  limits.nodes = 2048;
  limits.depth = 16;
  auto parsed = parse_json(line, limits);
  if (!parsed.has_value())
    return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
  const Value &object = parsed.value();
  if (!std::holds_alternative<Value::Object>(object.value()))
    return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});

  auto id = parse_string_field(object, "id");
  auto kind_str = parse_string_field(object, "kind");
  auto title = parse_string_field(object, "title");
  auto body = parse_string_field(object, "body");
  auto actor = parse_string_field(object, "actor");
  auto created_ns = parse_int64_field(object, "created_ns");
  auto session_id = parse_optional_string_field(object, "session_id");
  auto supersedes = parse_optional_string_field(object, "supersedes");
  if (!id.has_value() || !kind_str.has_value() || !title.has_value() ||
      !body.has_value() || !actor.has_value() || !created_ns.has_value() ||
      !session_id.has_value() || !supersedes.has_value())
    return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});

  auto id_num = parse_memory_id_number(id.value());
  auto kind = parse_memory_kind(kind_str.value());
  if (!id_num.has_value() || !kind.has_value())
    return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
  if (!valid_memory_actor(actor.value()) || created_ns.value() < 0)
    return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
  if (!validate_text(title.value(), {kMemoryMaxTitleBytes, false, false}).has_value())
    return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
  if (!validate_text(body.value(), {kMemoryMaxBodyBytes, false, true}).has_value())
    return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
  const auto &opt_session_id = session_id.value();
  if (opt_session_id.has_value() &&
      !validate_text(*opt_session_id, {kMemoryMaxSessionIdLength, false, false})
           .has_value())
    return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
  const auto &opt_supersedes = supersedes.value();
  if (opt_supersedes.has_value()) {
    auto sup_num = parse_memory_id_number(*opt_supersedes);
    if (!sup_num.has_value() || sup_num.value() >= id_num.value())
      return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
  }

  std::vector<std::string> tags;
  if (const auto *tags_field = object.find("tags")) {
    const auto *arr = std::get_if<Value::Array>(&tags_field->value());
    if (!arr || arr->size() > kMemoryMaxTags)
      return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
    tags.reserve(arr->size());
    for (const auto &item : *arr) {
      const auto *s = std::get_if<std::string>(&item.value());
      if (!s || !validate_text(*s, {kMemoryMaxTagBytes, false, false}).has_value())
        return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
      tags.push_back(*s);
    }
  }

  std::vector<MemorySourcePin> sources;
  if (const auto *sources_field = object.find("sources")) {
    const auto *arr = std::get_if<Value::Array>(&sources_field->value());
    if (!arr || arr->size() > kMemoryMaxSources)
      return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
    sources.reserve(arr->size());
    for (const auto &item : *arr) {
      if (!std::holds_alternative<Value::Object>(item.value()))
        return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
      auto pin_path = parse_string_field(item, "path");
      auto pin_sha = parse_string_field(item, "sha256");
      if (!pin_path.has_value() || !pin_sha.has_value())
        return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
      if (!validate_source_path(pin_path.value()).has_value() ||
          !valid_memory_sha256(pin_sha.value()))
        return Result<ParsedLineEntry>::failure({ErrorCode::corrupt});
      sources.push_back(
          MemorySourcePin{std::move(pin_path).value(), std::move(pin_sha).value()});
    }
  }

  MemoryEntry entry{
      std::move(id).value(),
      kind.value(),
      std::move(title).value(),
      std::move(body).value(),
      std::move(tags),
      std::move(actor).value(),
      std::move(session_id).value(),
      std::move(sources),
      std::move(supersedes).value(),
      std::nullopt,
      created_ns.value(),
  };
  return Result<ParsedLineEntry>::success(
      ParsedLineEntry{id_num.value(), std::move(entry)});
}

struct ReplayState {
  std::map<std::uint64_t, MemoryEntry> entries;
  std::uint64_t last_id_num = 0;
  bool empty = true;
  bool ends_with_newline = true;
};

Result<ReplayState> replay_entries_fd(int fd) {
  ReplayState state{};
  std::array<char, kReadChunkBytes> chunk{};
  std::string line;
  bool line_overflowed = false;
  off_t offset = 0;

  for (;;) {
    const ssize_t count = ::pread(fd, chunk.data(), chunk.size(), offset);
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return Result<ReplayState>::failure(native_error(errno));
    }
    if (count == 0)
      break;
    const auto bytes = static_cast<std::size_t>(count);
    offset += static_cast<off_t>(bytes);
    state.empty = false;
    state.ends_with_newline = (chunk[bytes - 1] == '\n');

    std::size_t cursor = 0;
    while (cursor < bytes) {
      const std::string_view remaining{chunk.data() + cursor, bytes - cursor};
      const std::size_t nl = remaining.find('\n');
      if (nl == std::string_view::npos) {
        if (!line_overflowed) {
          if (remaining.size() > kMaxEntryLineBytes - line.size()) {
            line.clear();
            line_overflowed = true;
          } else {
            line.append(remaining.data(), remaining.size());
          }
        }
        break;
      }

      if (!line_overflowed) {
        if (nl > kMaxEntryLineBytes - line.size()) {
          line.clear();
          line_overflowed = true;
        } else {
          line.append(remaining.data(), nl);
        }
      }

      if (!line_overflowed) {
        std::string_view view{line};
        if (!view.empty() && view.back() == '\r')
          view.remove_suffix(1);
        if (!view.empty()) {
          auto parsed = parse_entry_line(view);
          if (parsed.has_value() && parsed.value().id_num > state.last_id_num) {
            const std::uint64_t id_num = parsed.value().id_num;
            MemoryEntry entry = std::move(parsed).value().entry;
            if (entry.supersedes.has_value()) {
              auto sup_num = parse_memory_id_number(*entry.supersedes);
              if (sup_num.has_value()) {
                auto it = state.entries.find(sup_num.value());
                if (it != state.entries.end() && !it->second.superseded_by.has_value())
                  it->second.superseded_by = entry.id;
              }
            }
            state.last_id_num = id_num;
            state.entries.emplace(id_num, std::move(entry));
          }
        }
      }

      line.clear();
      line_overflowed = false;
      cursor += nl + 1;
    }
  }

  return Result<ReplayState>::success(std::move(state));
}

Result<ReplayState> load_entries_readonly(int dir_fd) {
  auto lock = ScopedFlock::acquire(dir_fd, kMemoryLockFile, true);
  if (!lock.has_value())
    return Result<ReplayState>::failure(lock.error());

  int fd = -1;
  do {
    fd = ::openat(dir_fd, kEntriesFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ENOENT)
      return Result<ReplayState>::success(ReplayState{});
    return Result<ReplayState>::failure(native_error(errno));
  }
  ScopedFd entries_fd{fd};
  auto checked = check_restricted(entries_fd.get(), false);
  if (!checked.has_value())
    return Result<ReplayState>::failure(checked.error());
  return replay_entries_fd(entries_fd.get());
}

char ascii_lower_char(char ch) noexcept {
  if (ch >= 'A' && ch <= 'Z')
    return static_cast<char>(ch + ('a' - 'A'));
  return ch;
}

std::string ascii_lower(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  for (const char ch : input)
    out.push_back(ascii_lower_char(ch));
  return out;
}

bool is_token_byte(unsigned char byte) noexcept {
  return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
         (byte >= '0' && byte <= '9') || byte >= 0x80U;
}

std::vector<std::string> tokenize(std::string_view text) {
  std::vector<std::string> tokens;
  std::string current;
  for (const char ch : text) {
    const auto byte = static_cast<unsigned char>(ch);
    if (is_token_byte(byte)) {
      current.push_back(ascii_lower_char(ch));
    } else if (!current.empty()) {
      tokens.push_back(std::move(current));
      current.clear();
    }
  }
  if (!current.empty())
    tokens.push_back(std::move(current));
  return tokens;
}

std::uint64_t count_query_matches(const std::vector<std::string> &field_tokens,
                                  const std::set<std::string> &query_tokens) noexcept {
  std::uint64_t hits = 0;
  for (const auto &tok : field_tokens) {
    if (query_tokens.contains(tok))
      ++hits;
  }
  return hits;
}

Result<MemoryFreshness>
verify_freshness_under_fd(int verify_fd, const std::filesystem::path &verify_root,
                          const MemoryEntry &entry) {
  if (entry.sources.empty())
    return Result<MemoryFreshness>::success(MemoryFreshness::unpinned);

  bool any_missing = false;
  bool any_stale = false;
  for (const auto &pin : entry.sources) {
    auto hashed = hash_source_under_fd(verify_fd, verify_root, pin.path);
    if (!hashed.has_value()) {
      const Error err = hashed.error();
      if (err.code == ErrorCode::io &&
          (err.detail == ENOENT || err.detail == ENOTDIR)) {
        any_missing = true;
        continue;
      }
      return Result<MemoryFreshness>::failure(err);
    }
    if (hashed.value() != pin.sha256)
      any_stale = true;
  }
  if (any_missing)
    return Result<MemoryFreshness>::success(MemoryFreshness::missing_source);
  if (any_stale)
    return Result<MemoryFreshness>::success(MemoryFreshness::stale);
  return Result<MemoryFreshness>::success(MemoryFreshness::fresh);
}

} // namespace

std::string_view memory_kind_name(MemoryKind kind) noexcept {
  switch (kind) {
  case MemoryKind::decision:
    return "decision";
  case MemoryKind::invariant:
    return "invariant";
  case MemoryKind::handoff:
    return "handoff";
  case MemoryKind::finding:
    return "finding";
  case MemoryKind::friction:
    return "friction";
  case MemoryKind::preference:
    return "preference";
  }
  return {};
}

Result<MemoryKind> parse_memory_kind(std::string_view name) noexcept {
  if (name == "decision")
    return Result<MemoryKind>::success(MemoryKind::decision);
  if (name == "invariant")
    return Result<MemoryKind>::success(MemoryKind::invariant);
  if (name == "handoff")
    return Result<MemoryKind>::success(MemoryKind::handoff);
  if (name == "finding")
    return Result<MemoryKind>::success(MemoryKind::finding);
  if (name == "friction")
    return Result<MemoryKind>::success(MemoryKind::friction);
  if (name == "preference")
    return Result<MemoryKind>::success(MemoryKind::preference);
  return Result<MemoryKind>::failure({ErrorCode::invalid_range});
}

std::string_view memory_freshness_name(MemoryFreshness freshness) noexcept {
  switch (freshness) {
  case MemoryFreshness::unchecked:
    return "unchecked";
  case MemoryFreshness::unpinned:
    return "unpinned";
  case MemoryFreshness::fresh:
    return "fresh";
  case MemoryFreshness::stale:
    return "stale";
  case MemoryFreshness::missing_source:
    return "missing_source";
  }
  return {};
}

Result<MemoryFreshness> parse_memory_freshness(std::string_view name) noexcept {
  if (name == "unchecked")
    return Result<MemoryFreshness>::success(MemoryFreshness::unchecked);
  if (name == "unpinned")
    return Result<MemoryFreshness>::success(MemoryFreshness::unpinned);
  if (name == "fresh")
    return Result<MemoryFreshness>::success(MemoryFreshness::fresh);
  if (name == "stale")
    return Result<MemoryFreshness>::success(MemoryFreshness::stale);
  if (name == "missing_source")
    return Result<MemoryFreshness>::success(MemoryFreshness::missing_source);
  return Result<MemoryFreshness>::failure({ErrorCode::invalid_range});
}

Result<std::uint64_t> parse_memory_id_number(std::string_view id) noexcept {
  constexpr std::string_view kPrefix = "mem-";
  if (id.size() <= kPrefix.size() || !id.starts_with(kPrefix))
    return Result<std::uint64_t>::failure({ErrorCode::invalid_identity});
  const std::string_view digits = id.substr(kPrefix.size());
  if (digits.empty() || digits.front() < '1' || digits.front() > '9')
    return Result<std::uint64_t>::failure({ErrorCode::invalid_identity});
  for (const char ch : digits) {
    if (ch < '0' || ch > '9')
      return Result<std::uint64_t>::failure({ErrorCode::invalid_identity});
  }
  std::uint64_t num = 0;
  const auto [ptr, ec] =
      std::from_chars(digits.data(), digits.data() + digits.size(), num);
  if (ec != std::errc{} || ptr != digits.data() + digits.size() || num == 0)
    return Result<std::uint64_t>::failure({ErrorCode::invalid_identity});
  return Result<std::uint64_t>::success(num);
}

bool valid_memory_id(std::string_view id) noexcept {
  return parse_memory_id_number(id).has_value();
}

bool valid_memory_actor(std::string_view actor) noexcept {
  if (actor.empty() || actor.size() > kMemoryMaxActorLength)
    return false;
  const char first = actor.front();
  if (!((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')))
    return false;
  for (const char ch : actor) {
    const bool ok =
        (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
    if (!ok)
      return false;
  }
  return true;
}

bool valid_memory_sha256(std::string_view sha256) noexcept {
  if (sha256.size() != 64)
    return false;
  for (const char ch : sha256) {
    const bool ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    if (!ok)
      return false;
  }
  return true;
}

std::string memory_sha256_hex(std::string_view bytes) {
  Sha256Hasher hasher;
  hasher.update(reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size());
  return hasher.finalize_hex();
}

Result<std::string> hash_memory_source_file(const std::filesystem::path &root,
                                            std::string_view source_path) {
  try {
    auto root_fd = open_verify_root_dir(root);
    if (!root_fd.has_value())
      return Result<std::string>::failure(root_fd.error());
    return hash_source_under_fd(root_fd.value().get(), root, source_path);
  } catch (const std::bad_alloc &) {
    return Result<std::string>::failure({ErrorCode::allocation});
  }
}

std::filesystem::path
default_project_memory_dir(const std::filesystem::path &project_root) {
  return project_root / ".blackbird" / "memory";
}

Result<MemoryFreshness>
verify_memory_freshness(const MemoryEntry &entry,
                        const std::filesystem::path &verify_root) {
  try {
    auto root_fd = open_verify_root_dir(verify_root);
    if (!root_fd.has_value())
      return Result<MemoryFreshness>::failure(root_fd.error());
    return verify_freshness_under_fd(root_fd.value().get(), verify_root, entry);
  } catch (const std::bad_alloc &) {
    return Result<MemoryFreshness>::failure({ErrorCode::allocation});
  }
}

Value to_value(const MemorySourcePin &pin) {
  return Value::object({
      {"path", Value{pin.path}},
      {"sha256", Value{pin.sha256}},
  });
}

Value to_value(const MemoryEntry &entry) {
  Value::Array tags;
  tags.reserve(entry.tags.size());
  for (const auto &tag : entry.tags)
    tags.emplace_back(tag);

  Value::Array sources;
  sources.reserve(entry.sources.size());
  for (const auto &pin : entry.sources)
    sources.push_back(to_value(pin));

  return Value::object({
      {"id", Value{entry.id}},
      {"kind", Value{std::string{memory_kind_name(entry.kind)}}},
      {"title", Value{entry.title}},
      {"body", Value{entry.body}},
      {"tags", Value{std::move(tags)}},
      {"actor", Value{entry.actor}},
      {"session_id",
       entry.session_id.has_value() ? Value{*entry.session_id} : Value{nullptr}},
      {"sources", Value{std::move(sources)}},
      {"supersedes",
       entry.supersedes.has_value() ? Value{*entry.supersedes} : Value{nullptr}},
      {"superseded_by",
       entry.superseded_by.has_value() ? Value{*entry.superseded_by} : Value{nullptr}},
      {"created_ns", Value{Number{entry.created_ns}}},
  });
}

Value to_value(const MemoryRecallHit &hit) {
  return Value::object({
      {"entry", to_value(hit.entry)},
      {"score", Value{Number{hit.score}}},
      {"freshness", Value{std::string{memory_freshness_name(hit.freshness)}}},
  });
}

Value to_value(const std::vector<MemoryEntry> &entries) {
  Value::Array arr;
  arr.reserve(entries.size());
  for (const auto &entry : entries)
    arr.push_back(to_value(entry));
  return Value{std::move(arr)};
}

Value to_value(const std::vector<MemoryRecallHit> &hits) {
  Value::Array arr;
  arr.reserve(hits.size());
  for (const auto &hit : hits)
    arr.push_back(to_value(hit));
  return Value{std::move(arr)};
}

Result<std::string> to_json(const MemorySourcePin &pin) {
  return dump_json(to_value(pin));
}

Result<std::string> to_json(const MemoryEntry &entry) {
  return dump_json(to_value(entry));
}

Result<std::string> to_json(const MemoryRecallHit &hit) {
  return dump_json(to_value(hit));
}

Result<std::string> to_json(const std::vector<MemoryEntry> &entries) {
  return dump_json(to_value(entries));
}

Result<std::string> to_json(const std::vector<MemoryRecallHit> &hits) {
  return dump_json(to_value(hits));
}

Result<ProjectMemoryStore> ProjectMemoryStore::open(const std::filesystem::path &root) {
  try {
    std::string path_str = root.string();
    if (path_str.empty() || path_str.find('\0') != std::string::npos ||
        has_dotdot_segment(path_str))
      return Result<ProjectMemoryStore>::failure({ErrorCode::invalid_range});
    while (path_str.size() > 1 && path_str.back() == '/')
      path_str.pop_back();

    bool created = false;
    if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
      created = true;
    } else if (errno == ENOENT) {
      const auto parent = std::filesystem::path{path_str}.parent_path();
      if (!parent.empty()) {
        std::error_code ec;
        (void)std::filesystem::create_directories(parent, ec);
        if (ec)
          return Result<ProjectMemoryStore>::failure({ErrorCode::io, ec.value()});
      }
      if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
        created = true;
      } else if (errno != EEXIST) {
        return Result<ProjectMemoryStore>::failure(native_error(errno));
      }
    } else if (errno != EEXIST) {
      return Result<ProjectMemoryStore>::failure(native_error(errno));
    }

    int fd = -1;
    do {
      fd = ::open(path_str.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
      return Result<ProjectMemoryStore>::failure(native_error(errno));
    ScopedFd owned{fd};

    if (created && ::fchmod(owned.get(), mode_t{0700}) != 0)
      return Result<ProjectMemoryStore>::failure(native_error(errno));

    auto checked = check_restricted(owned.get(), true);
    if (!checked.has_value())
      return Result<ProjectMemoryStore>::failure(checked.error());

    return Result<ProjectMemoryStore>::success(ProjectMemoryStore{
        std::filesystem::path{std::move(path_str)}, owned.release()});
  } catch (const std::bad_alloc &) {
    return Result<ProjectMemoryStore>::failure({ErrorCode::allocation});
  }
}

ProjectMemoryStore::ProjectMemoryStore(ProjectMemoryStore &&other) noexcept
    : root_(std::move(other.root_)), dir_fd_(std::exchange(other.dir_fd_, -1)) {}

ProjectMemoryStore &ProjectMemoryStore::operator=(ProjectMemoryStore &&other) noexcept {
  if (this != &other) {
    if (dir_fd_ >= 0)
      (void)::close(dir_fd_);
    root_ = std::move(other.root_);
    dir_fd_ = std::exchange(other.dir_fd_, -1);
  }
  return *this;
}

ProjectMemoryStore::~ProjectMemoryStore() {
  if (dir_fd_ >= 0)
    (void)::close(dir_fd_);
}

Result<MemoryEntry> ProjectMemoryStore::record(MemoryRecordRequest request) {
  if (dir_fd_ < 0)
    return Result<MemoryEntry>::failure({ErrorCode::stale_handle});
  auto basics_ok = validate_request_basics(request);
  if (!basics_ok.has_value())
    return Result<MemoryEntry>::failure(basics_ok.error());

  try {
    // Resolve and validate source pins before taking the store write lock.
    ScopedFd repo_fd;
    if (request.repo_root.has_value()) {
      auto opened_repo = open_verify_root_dir(*request.repo_root);
      if (!opened_repo.has_value())
        return Result<MemoryEntry>::failure(opened_repo.error());
      repo_fd = std::move(opened_repo).value();
    }

    for (auto &pin : request.sources) {
      auto path_ok = validate_source_path(pin.path);
      if (!path_ok.has_value())
        return Result<MemoryEntry>::failure(path_ok.error());
      if (pin.sha256.empty()) {
        if (!request.repo_root.has_value())
          return Result<MemoryEntry>::failure({ErrorCode::invalid_range});
        auto hashed = hash_source_under_fd(repo_fd.get(), *request.repo_root, pin.path);
        if (!hashed.has_value())
          return Result<MemoryEntry>::failure(hashed.error());
        pin.sha256 = std::move(hashed).value();
      } else if (!valid_memory_sha256(pin.sha256)) {
        return Result<MemoryEntry>::failure({ErrorCode::invalid_range});
      }
    }

    auto lock = ScopedFlock::acquire(dir_fd_, kMemoryLockFile, false);
    if (!lock.has_value())
      return Result<MemoryEntry>::failure(lock.error());

    bool created = false;
    int fd = -1;
    do {
      fd = ::openat(dir_fd_, kEntriesFile, O_RDWR | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0 && errno == ENOENT) {
      do {
        fd = ::openat(dir_fd_, kEntriesFile,
                      O_RDWR | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
                      mode_t{0600});
      } while (fd < 0 && errno == EINTR);
      created = (fd >= 0);
    }
    if (fd < 0)
      return Result<MemoryEntry>::failure(native_error(errno));
    ScopedFd entries_fd{fd};
    auto checked = check_restricted(entries_fd.get(), false);
    if (!checked.has_value())
      return Result<MemoryEntry>::failure(checked.error());

    auto replayed = replay_entries_fd(entries_fd.get());
    if (!replayed.has_value())
      return Result<MemoryEntry>::failure(replayed.error());
    const ReplayState &state = replayed.value();

    if (request.supersedes.has_value()) {
      auto sup_num = parse_memory_id_number(*request.supersedes);
      if (!sup_num.has_value())
        return Result<MemoryEntry>::failure({ErrorCode::invalid_identity});
      const auto it = state.entries.find(sup_num.value());
      if (it == state.entries.end())
        return Result<MemoryEntry>::failure({ErrorCode::invalid_identity, ENOENT});
      if (it->second.superseded_by.has_value())
        return Result<MemoryEntry>::failure({ErrorCode::conflict});
    }

    if (state.last_id_num == std::numeric_limits<std::uint64_t>::max())
      return Result<MemoryEntry>::failure({ErrorCode::overflow});

    const std::uint64_t next_num = state.last_id_num + 1;
    const std::int64_t timestamp =
        request.created_ns == 0 ? wall_now_ns() : request.created_ns;

    MemoryEntry committed{
        "mem-" + std::to_string(next_num),
        request.kind,
        std::move(request.title),
        std::move(request.body),
        std::move(request.tags),
        std::move(request.actor),
        std::move(request.session_id),
        std::move(request.sources),
        std::move(request.supersedes),
        std::nullopt,
        timestamp,
    };

    ValueLimits limits{};
    limits.bytes = kMaxEntryLineBytes;
    auto json = dump_json(entry_to_disk_value(committed), limits);
    if (!json.has_value())
      return Result<MemoryEntry>::failure(json.error());

    std::string record_bytes;
    const bool needs_recovery_newline = !state.empty && !state.ends_with_newline;
    record_bytes.reserve(json.value().size() + (needs_recovery_newline ? 3U : 1U));
    if (needs_recovery_newline) {
      // Terminate and invalidate any uncommitted trailing fragment (even one
      // that crashed immediately before its trailing newline) before writing
      // the new entry on a fresh line.
      record_bytes.append("!\n");
    }
    record_bytes.append(json.value());
    record_bytes.push_back('\n');

    auto written = write_all_fd(entries_fd.get(), record_bytes);
    if (!written.has_value())
      return Result<MemoryEntry>::failure(written.error());
    auto synced = fsync_fd(entries_fd.get());
    if (!synced.has_value())
      return Result<MemoryEntry>::failure(synced.error());
    if (created) {
      auto dir_synced = fsync_fd(dir_fd_);
      if (!dir_synced.has_value())
        return Result<MemoryEntry>::failure(dir_synced.error());
    }
    return Result<MemoryEntry>::success(std::move(committed));
  } catch (const std::bad_alloc &) {
    return Result<MemoryEntry>::failure({ErrorCode::allocation});
  }
}

Result<std::optional<MemoryEntry>> ProjectMemoryStore::get(std::string_view id) const {
  if (dir_fd_ < 0)
    return Result<std::optional<MemoryEntry>>::failure({ErrorCode::stale_handle});
  auto id_num = parse_memory_id_number(id);
  if (!id_num.has_value())
    return Result<std::optional<MemoryEntry>>::failure(id_num.error());
  try {
    auto loaded = load_entries_readonly(dir_fd_);
    if (!loaded.has_value())
      return Result<std::optional<MemoryEntry>>::failure(loaded.error());
    auto &entries = loaded.value().entries;
    auto it = entries.find(id_num.value());
    if (it == entries.end())
      return Result<std::optional<MemoryEntry>>::success(std::nullopt);
    return Result<std::optional<MemoryEntry>>::success(std::move(it->second));
  } catch (const std::bad_alloc &) {
    return Result<std::optional<MemoryEntry>>::failure({ErrorCode::allocation});
  }
}

Result<std::vector<MemoryRecallHit>>
ProjectMemoryStore::recall(const MemoryRecallQuery &query) const {
  if (dir_fd_ < 0)
    return Result<std::vector<MemoryRecallHit>>::failure({ErrorCode::stale_handle});
  if (query.kind.has_value() && memory_kind_name(*query.kind).empty())
    return Result<std::vector<MemoryRecallHit>>::failure({ErrorCode::invalid_range});
  auto query_ok = validate_text(query.query, {kMemoryMaxBodyBytes, true, true});
  if (!query_ok.has_value())
    return Result<std::vector<MemoryRecallHit>>::failure(query_ok.error());
  if (query.tag.has_value()) {
    auto tag_ok = validate_text(*query.tag, {kMemoryMaxTagBytes, false, false});
    if (!tag_ok.has_value())
      return Result<std::vector<MemoryRecallHit>>::failure(tag_ok.error());
  }

  try {
    ScopedFd verify_fd;
    if (query.verify_root.has_value()) {
      auto opened = open_verify_root_dir(*query.verify_root);
      if (!opened.has_value())
        return Result<std::vector<MemoryRecallHit>>::failure(opened.error());
      verify_fd = std::move(opened).value();
    }

    if (query.limit == 0)
      return Result<std::vector<MemoryRecallHit>>::success({});

    auto loaded = load_entries_readonly(dir_fd_);
    if (!loaded.has_value())
      return Result<std::vector<MemoryRecallHit>>::failure(loaded.error());

    const auto raw_q_tokens = tokenize(query.query);
    std::set<std::string> q_tokens(raw_q_tokens.begin(), raw_q_tokens.end());
    const std::optional<std::string> tag_filter =
        query.tag.has_value() ? std::optional<std::string>{ascii_lower(*query.tag)}
                              : std::nullopt;

    struct ScoredCandidate {
      std::uint64_t id_num = 0;
      std::uint64_t score = 0;
      MemoryEntry *entry = nullptr;
    };
    std::vector<ScoredCandidate> candidates;
    candidates.reserve(loaded.value().entries.size());

    for (auto &[id_num, entry] : loaded.value().entries) {
      if (!query.include_superseded && entry.superseded_by.has_value())
        continue;
      if (query.kind.has_value() && entry.kind != *query.kind)
        continue;
      if (tag_filter.has_value()) {
        bool tag_matched = false;
        for (const auto &t : entry.tags) {
          if (ascii_lower(t) == *tag_filter) {
            tag_matched = true;
            break;
          }
        }
        if (!tag_matched)
          continue;
      }

      std::uint64_t score = 0;
      if (!q_tokens.empty()) {
        const auto title_tokens = tokenize(entry.title);
        const auto body_tokens = tokenize(entry.body);
        std::uint64_t tag_hits = 0;
        for (const auto &t : entry.tags)
          tag_hits += count_query_matches(tokenize(t), q_tokens);
        const std::uint64_t title_hits = count_query_matches(title_tokens, q_tokens);
        const std::uint64_t body_hits = count_query_matches(body_tokens, q_tokens);
        score = (title_hits * kTitleWeight) + (tag_hits * kTagWeight) +
                (body_hits * kBodyWeight);
        if (score == 0)
          continue;
      }

      candidates.push_back(ScoredCandidate{id_num, score, &entry});
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const ScoredCandidate &lhs, const ScoredCandidate &rhs) {
                if (lhs.score != rhs.score)
                  return lhs.score > rhs.score;
                return lhs.id_num > rhs.id_num;
              });

    const std::size_t effective_limit = std::min(query.limit, kMemoryMaxLimit);
    if (candidates.size() > effective_limit)
      candidates.resize(effective_limit);

    std::vector<MemoryRecallHit> hits;
    hits.reserve(candidates.size());
    for (const auto &cand : candidates) {
      MemoryFreshness freshness = MemoryFreshness::unpinned;
      if (query.verify_root.has_value()) {
        auto verified =
            verify_freshness_under_fd(verify_fd.get(), *query.verify_root, *cand.entry);
        if (!verified.has_value())
          return Result<std::vector<MemoryRecallHit>>::failure(verified.error());
        freshness = verified.value();
      } else if (!cand.entry->sources.empty()) {
        freshness = MemoryFreshness::unchecked;
      }
      hits.push_back(MemoryRecallHit{std::move(*cand.entry), cand.score, freshness});
    }
    return Result<std::vector<MemoryRecallHit>>::success(std::move(hits));
  } catch (const std::bad_alloc &) {
    return Result<std::vector<MemoryRecallHit>>::failure({ErrorCode::allocation});
  }
}

Result<std::vector<MemoryEntry>>
ProjectMemoryStore::recent(std::size_t limit, bool include_superseded) const {
  if (dir_fd_ < 0)
    return Result<std::vector<MemoryEntry>>::failure({ErrorCode::stale_handle});
  if (limit == 0)
    return Result<std::vector<MemoryEntry>>::success({});
  try {
    auto loaded = load_entries_readonly(dir_fd_);
    if (!loaded.has_value())
      return Result<std::vector<MemoryEntry>>::failure(loaded.error());

    const std::size_t effective_limit = std::min(limit, kMemoryMaxLimit);
    std::vector<MemoryEntry> result;
    result.reserve(std::min(effective_limit, loaded.value().entries.size()));
    auto &entries = loaded.value().entries;
    for (auto it = entries.rbegin();
         it != entries.rend() && result.size() < effective_limit; ++it) {
      if (!include_superseded && it->second.superseded_by.has_value())
        continue;
      result.push_back(std::move(it->second));
    }
    return Result<std::vector<MemoryEntry>>::success(std::move(result));
  } catch (const std::bad_alloc &) {
    return Result<std::vector<MemoryEntry>>::failure({ErrorCode::allocation});
  }
}

} // namespace blackbird
