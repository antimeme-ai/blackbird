#include "blackbird/party_chat.hpp"

#include "blackbird/json.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <limits>
#include <map>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace blackbird {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kMaxPlatoonFileBytes = 16 * 1024 * 1024;
constexpr std::size_t kMaxBridgeFileBytes = 32 * 1024 * 1024;
constexpr std::size_t kMaxKnownPeersFileBytes = 4 * 1024 * 1024;
constexpr std::size_t kMaxPlatoonMessagesLoaded = 512;
constexpr std::size_t kMaxReadChunkBytes = 64 * 1024;
constexpr int kSplitLayoutMinWidth = 88;

std::atomic<std::uint64_t> g_party_tmp_counter{0};

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

std::int64_t wall_now_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return ns <= 0 ? 1 : static_cast<std::int64_t>(ns);
}

char lower_ascii(char ch) noexcept {
  return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
}

bool equals_ci(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size())
    return false;
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    if (lower_ascii(lhs[i]) != lower_ascii(rhs[i]))
      return false;
  }
  return true;
}

std::string to_lower_ascii(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  for (const char ch : input)
    out.push_back(lower_ascii(ch));
  return out;
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

// ---------------------------------------------------------------------------
// UTF-8 decoding, width calculation, and hostile terminal sanitization
// ---------------------------------------------------------------------------

struct DecodedUtf8 {
  char32_t scalar = 0;
  std::size_t length = 0;
};

DecodedUtf8 decode_utf8_at(std::string_view text, std::size_t offset) noexcept {
  if (offset >= text.size())
    return {};
  const auto b0 = static_cast<unsigned char>(text[offset]);
  if (b0 < 0x80U)
    return {static_cast<char32_t>(b0), 1};
  if ((b0 & 0xe0U) == 0xc0U) {
    if (b0 < 0xc2U || offset + 1 >= text.size())
      return {};
    const auto b1 = static_cast<unsigned char>(text[offset + 1]);
    if ((b1 & 0xc0U) != 0x80U)
      return {};
    const char32_t cp =
        (static_cast<char32_t>(b0 & 0x1fU) << 6U) | static_cast<char32_t>(b1 & 0x3fU);
    return {cp, 2};
  }
  if ((b0 & 0xf0U) == 0xe0U) {
    if (offset + 2 >= text.size())
      return {};
    const auto b1 = static_cast<unsigned char>(text[offset + 1]);
    const auto b2 = static_cast<unsigned char>(text[offset + 2]);
    if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U)
      return {};
    if (b0 == 0xe0U && b1 < 0xa0U)
      return {};
    if (b0 == 0xedU && b1 >= 0xa0U)
      return {};
    const char32_t cp = (static_cast<char32_t>(b0 & 0x0fU) << 12U) |
                        (static_cast<char32_t>(b1 & 0x3fU) << 6U) |
                        static_cast<char32_t>(b2 & 0x3fU);
    return {cp, 3};
  }
  if ((b0 & 0xf8U) == 0xf0U) {
    if (b0 > 0xf4U || offset + 3 >= text.size())
      return {};
    const auto b1 = static_cast<unsigned char>(text[offset + 1]);
    const auto b2 = static_cast<unsigned char>(text[offset + 2]);
    const auto b3 = static_cast<unsigned char>(text[offset + 3]);
    if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U || (b3 & 0xc0U) != 0x80U)
      return {};
    if (b0 == 0xf0U && b1 < 0x90U)
      return {};
    if (b0 == 0xf4U && b1 >= 0x90U)
      return {};
    const char32_t cp = (static_cast<char32_t>(b0 & 0x07U) << 18U) |
                        (static_cast<char32_t>(b1 & 0x3fU) << 12U) |
                        (static_cast<char32_t>(b2 & 0x3fU) << 6U) |
                        static_cast<char32_t>(b3 & 0x3fU);
    return {cp, 4};
  }
  return {};
}

bool is_bidi_or_format_control(char32_t cp) noexcept {
  return (cp >= 0x202aU && cp <= 0x202eU) || (cp >= 0x2066U && cp <= 0x2069U) ||
         cp == 0x200eU || cp == 0x200fU || cp == 0x061cU || cp == 0xfeffU;
}

std::size_t scalar_cell_width(char32_t cp) noexcept {
  if (cp < 0x20U || (cp >= 0x7fU && cp <= 0x9fU))
    return 0;
  if ((cp >= 0x0300U && cp <= 0x036fU) || (cp >= 0x1ab0U && cp <= 0x1affU) ||
      (cp >= 0x1dc0U && cp <= 0x1dffU) || (cp >= 0x20d0U && cp <= 0x20ffU) ||
      (cp >= 0xfe00U && cp <= 0xfe0fU) || (cp >= 0xfe20U && cp <= 0xfe2fU) ||
      cp == 0x200bU || cp == 0x200cU || cp == 0x200dU) {
    return 0;
  }
  if ((cp >= 0x1100U && cp <= 0x115fU) || cp == 0x2329U || cp == 0x232aU ||
      (cp >= 0x2e80U && cp <= 0xa4cfU && cp != 0x303fU) ||
      (cp >= 0xac00U && cp <= 0xd7a3U) || (cp >= 0xf900U && cp <= 0xfaffU) ||
      (cp >= 0xfe10U && cp <= 0xfe19U) || (cp >= 0xfe30U && cp <= 0xfe6fU) ||
      (cp >= 0xff00U && cp <= 0xff60U) || (cp >= 0xffe0U && cp <= 0xffe6U) ||
      (cp >= 0x1f300U && cp <= 0x1faffU) || (cp >= 0x20000U && cp <= 0x3fffdU)) {
    return 2;
  }
  return 1;
}

std::size_t utf8_display_cells(std::string_view text) noexcept {
  std::size_t cells = 0;
  std::size_t i = 0;
  while (i < text.size()) {
    const DecodedUtf8 dec = decode_utf8_at(text, i);
    if (dec.length == 0) {
      ++i;
      continue;
    }
    cells += scalar_cell_width(dec.scalar);
    i += dec.length;
  }
  return cells;
}

std::string hex_escape_byte(unsigned char byte) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out = "\\x";
  out += kHex[byte >> 4U];
  out += kHex[byte & 0x0fU];
  return out;
}

std::string clip_to_cells(std::string_view sanitized, std::size_t max_cols) {
  if (max_cols == 0)
    return {};
  if (utf8_display_cells(sanitized) <= max_cols)
    return std::string{sanitized};

  const bool use_ellipsis = max_cols >= 4;
  const std::size_t budget = use_ellipsis ? (max_cols - 3) : max_cols;
  std::string out;
  out.reserve(std::min(sanitized.size(), max_cols + 4));
  std::size_t used = 0;
  std::size_t i = 0;
  while (i < sanitized.size()) {
    const DecodedUtf8 dec = decode_utf8_at(sanitized, i);
    if (dec.length == 0) {
      ++i;
      continue;
    }
    const std::size_t w = scalar_cell_width(dec.scalar);
    if (used + w > budget)
      break;
    out.append(sanitized.data() + i, dec.length);
    used += w;
    i += dec.length;
  }
  if (use_ellipsis)
    out += "...";
  return out;
}

std::string tail_to_cells(std::string_view sanitized, std::size_t max_cols) {
  if (max_cols == 0)
    return {};
  if (utf8_display_cells(sanitized) <= max_cols)
    return std::string{sanitized};

  struct GlyphSlice {
    std::size_t offset;
    std::size_t len;
    std::size_t width;
  };
  std::vector<GlyphSlice> glyphs;
  std::size_t i = 0;
  while (i < sanitized.size()) {
    const DecodedUtf8 dec = decode_utf8_at(sanitized, i);
    if (dec.length == 0) {
      ++i;
      continue;
    }
    glyphs.push_back({i, dec.length, scalar_cell_width(dec.scalar)});
    i += dec.length;
  }
  std::size_t used = 0;
  std::size_t start_idx = glyphs.size();
  while (start_idx > 0) {
    const auto &g = glyphs[start_idx - 1];
    if (used + g.width > max_cols)
      break;
    used += g.width;
    --start_idx;
  }
  if (start_idx >= glyphs.size())
    return {};
  return std::string{sanitized.substr(glyphs[start_idx].offset)};
}

std::string pad_to_cells(std::string_view sanitized, std::size_t width) {
  std::string out = clip_to_cells(sanitized, width);
  const std::size_t used = utf8_display_cells(out);
  if (used < width)
    out.append(width - used, ' ');
  return out;
}

struct WordWrapSpec {
  std::size_t first_width = 0;
  std::size_t cont_width = 0;
};

std::vector<std::string> wrap_words_sanitized(std::string_view sanitized,
                                              WordWrapSpec spec) {
  std::vector<std::string> lines;
  if (spec.first_width == 0)
    return lines;
  const std::size_t cont_w = spec.cont_width > 0 ? spec.cont_width : spec.first_width;

  if (sanitized.empty()) {
    lines.emplace_back();
    return lines;
  }

  std::string current;
  std::size_t cur_cells = 0;
  std::size_t limit = spec.first_width;

  auto flush_line = [&]() {
    lines.push_back(std::move(current));
    current.clear();
    cur_cells = 0;
    limit = cont_w;
  };

  auto append_long_token = [&](std::string_view token) {
    std::size_t pos = 0;
    while (pos < token.size()) {
      const DecodedUtf8 dec = decode_utf8_at(token, pos);
      if (dec.length == 0) {
        ++pos;
        continue;
      }
      const std::size_t w = scalar_cell_width(dec.scalar);
      if (w > limit && cur_cells == 0) {
        // Single wide glyph wider than available width: skip to avoid infinite loop.
        pos += dec.length;
        continue;
      }
      if (cur_cells + w > limit)
        flush_line();
      current.append(token.data() + pos, dec.length);
      cur_cells += w;
      pos += dec.length;
    }
  };

  std::size_t i = 0;
  while (i < sanitized.size()) {
    while (i < sanitized.size() && sanitized[i] == ' ')
      ++i;
    if (i >= sanitized.size())
      break;
    const std::size_t start = i;
    while (i < sanitized.size() && sanitized[i] != ' ')
      ++i;
    const std::string_view word = sanitized.substr(start, i - start);
    const std::size_t word_cells = utf8_display_cells(word);

    if (cur_cells == 0) {
      if (word_cells <= limit) {
        current.append(word);
        cur_cells = word_cells;
      } else {
        append_long_token(word);
      }
    } else if (cur_cells + 1 + word_cells <= limit) {
      current.push_back(' ');
      current.append(word);
      cur_cells += 1 + word_cells;
    } else {
      flush_line();
      if (word_cells <= limit) {
        current.append(word);
        cur_cells = word_cells;
      } else {
        append_long_token(word);
      }
    }
  }
  if (!current.empty() || lines.empty())
    lines.push_back(std::move(current));
  return lines;
}

// ---------------------------------------------------------------------------
// Strictly passive read-only filesystem helpers (no mkdir, no lock creation)
// ---------------------------------------------------------------------------

enum class PathProbe : std::uint8_t {
  missing,
  regular_file,
  directory,
  symlink,
  other,
};

PathProbe probe_path_nofollow(const fs::path &path) noexcept {
  if (path.empty())
    return PathProbe::missing;
  std::error_code ec;
  const fs::file_status st = fs::symlink_status(path, ec);
  if (ec) {
    if (ec == std::errc::no_such_file_or_directory || ec == std::errc::not_a_directory)
      return PathProbe::missing;
    return PathProbe::other;
  }
  if (fs::is_symlink(st))
    return PathProbe::symlink;
  if (!fs::exists(st))
    return PathProbe::missing;
  if (fs::is_directory(st))
    return PathProbe::directory;
  if (fs::is_regular_file(st))
    return PathProbe::regular_file;
  return PathProbe::other;
}

// Checks every ancestor component between `root` (if prefix) and `path` is not a
// symlink, plus `path` itself.
bool path_or_parent_is_symlink(const fs::path &path) noexcept {
  if (path.empty())
    return false;
  if (probe_path_nofollow(path) == PathProbe::symlink)
    return true;
  const fs::path parent = path.parent_path();
  if (!parent.empty() && probe_path_nofollow(parent) == PathProbe::symlink)
    return true;
  return false;
}

Result<std::string> read_regular_file_strict_ro(const fs::path &path,
                                                std::size_t max_bytes) {
  const PathProbe probe = probe_path_nofollow(path);
  if (probe == PathProbe::symlink)
    return Result<std::string>::failure({ErrorCode::io, ELOOP});
  if (probe == PathProbe::missing)
    return Result<std::string>::failure({ErrorCode::io, ENOENT});
  if (probe != PathProbe::regular_file)
    return Result<std::string>::failure({ErrorCode::io, EINVAL});

  int fd = -1;
  do {
    fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0)
    return Result<std::string>::failure(native_error(errno));
  ScopedFd owned{fd};

  struct stat st{};
  if (::fstat(owned.get(), &st) != 0)
    return Result<std::string>::failure(native_error(errno));
  if (!S_ISREG(st.st_mode))
    return Result<std::string>::failure({ErrorCode::io, EINVAL});
  if (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) > max_bytes)
    return Result<std::string>::failure({ErrorCode::capacity});

  std::string out;
  out.reserve(static_cast<std::size_t>(st.st_size));
  std::array<char, kMaxReadChunkBytes> buf{};
  for (;;) {
    const ssize_t n = ::read(owned.get(), buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return Result<std::string>::failure(native_error(errno));
    }
    if (n == 0)
      break;
    const auto got = static_cast<std::size_t>(n);
    if (got > max_bytes - out.size())
      return Result<std::string>::failure({ErrorCode::capacity});
    out.append(buf.data(), got);
  }
  return Result<std::string>::success(std::move(out));
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

Result<void> fsync_fd(int fd) noexcept {
  while (::fsync(fd) != 0) {
    if (errno == EINTR)
      continue;
    return Result<void>::failure(native_error(errno));
  }
  return Result<void>::success();
}

// ---------------------------------------------------------------------------
// JSON field helpers & strict secret/config validation
// ---------------------------------------------------------------------------

std::optional<std::string> opt_string_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return std::nullopt;
  const auto *s = std::get_if<std::string>(&field->value());
  if (!s)
    return std::nullopt;
  return *s;
}

std::optional<std::int64_t> opt_int64_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return std::nullopt;
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return std::nullopt;
  if (const auto *s = std::get_if<std::int64_t>(&num->storage()))
    return *s;
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage())) {
    if (*u <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
      return static_cast<std::int64_t>(*u);
    return std::nullopt;
  }
  const std::string text = num->text();
  std::int64_t val = 0;
  const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), val);
  if (ec != std::errc{} || ptr != text.data() + text.size())
    return std::nullopt;
  return val;
}

std::optional<std::uint64_t> opt_uint64_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return std::nullopt;
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return std::nullopt;
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage()))
    return *u;
  if (const auto *s = std::get_if<std::int64_t>(&num->storage())) {
    if (*s >= 0)
      return static_cast<std::uint64_t>(*s);
    return std::nullopt;
  }
  const std::string text = num->text();
  std::uint64_t val = 0;
  const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), val);
  if (ec != std::errc{} || ptr != text.data() + text.size())
    return std::nullopt;
  return val;
}

std::optional<bool> opt_bool_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return std::nullopt;
  const auto *b = std::get_if<bool>(&field->value());
  if (!b)
    return std::nullopt;
  return *b;
}

Result<void>
validate_strict_object_keys(const Value &value,
                            std::span<const std::string_view> allowed_keys) {
  const auto *obj = std::get_if<Value::Object>(&value.value());
  if (!obj)
    return Result<void>::failure({ErrorCode::corrupt});
  std::unordered_set<std::string_view> seen;
  seen.reserve(obj->size());
  for (const auto &[key, _] : *obj) {
    if (!seen.insert(key).second)
      return Result<void>::failure({ErrorCode::corrupt});
    if (std::ranges::find(allowed_keys, std::string_view{key}) == allowed_keys.end())
      return Result<void>::failure({ErrorCode::corrupt});
  }
  return Result<void>::success();
}

bool looks_like_secret_value(std::string_view value) noexcept {
  if (value.empty())
    return false;
  static constexpr std::array<std::string_view, 9> kSecretPrefixes{
      "sk-",   "sk-ant-", "sk-or-", "ghp_",        "github_pat_",
      "xoxb-", "xoxp-",   "AIza",   "-----BEGIN ",
  };
  for (const std::string_view prefix : kSecretPrefixes) {
    if (value.starts_with(prefix))
      return true;
  }
  return false;
}

struct ConfigTextSpec {
  std::size_t max_bytes = kPartyMaxFieldBytes;
  bool allow_empty = true;
  bool forbid_whitespace = false;
};

Result<void> validate_config_text(std::string_view value,
                                  ConfigTextSpec spec) noexcept {
  if (!spec.allow_empty && value.empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (value.size() > spec.max_bytes)
    return Result<void>::failure({ErrorCode::capacity});
  if (!valid_utf8(value))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (looks_like_secret_value(value))
    return Result<void>::failure({ErrorCode::invalid_range});
  for (const char ch : value) {
    const auto b = static_cast<unsigned char>(ch);
    if (b < 0x20U || b == 0x7fU)
      return Result<void>::failure({ErrorCode::invalid_range});
    if (spec.forbid_whitespace && is_ascii_space(ch))
      return Result<void>::failure({ErrorCode::invalid_range});
  }
  return Result<void>::success();
}

Result<void> validate_party_roster_config(const PartyRosterConfig &config) {
  if (config.version != kPartyConfigVersion)
    return Result<void>::failure({ErrorCode::invalid_range});
  auto scope_ok = validate_config_text(
      config.room_scope,
      {.max_bytes = 128, .allow_empty = false, .forbid_whitespace = true});
  if (!scope_ok.has_value())
    return scope_ok;
  if (party_mode_override_name(config.mode_override).empty())
    return Result<void>::failure({ErrorCode::invalid_range});
  if (config.peers.size() > kPartyMaxPeers)
    return Result<void>::failure({ErrorCode::capacity});

  std::unordered_set<std::string> seen_aliases;
  seen_aliases.reserve(config.peers.size());
  for (const auto &peer : config.peers) {
    if (!valid_party_alias(peer.alias))
      return Result<void>::failure({ErrorCode::invalid_identity});
    const std::string lower_alias = to_lower_ascii(peer.alias);
    if (!seen_aliases.insert(lower_alias).second)
      return Result<void>::failure({ErrorCode::conflict});
    if (party_member_role_name(peer.role).empty())
      return Result<void>::failure({ErrorCode::invalid_range});
    auto host_ok = validate_config_text(
        peer.host, {.max_bytes = 256, .allow_empty = true, .forbid_whitespace = true});
    if (!host_ok.has_value())
      return host_ok;
    if (peer.ssh_target.has_value()) {
      auto ssh_ok = validate_config_text(
          *peer.ssh_target,
          {.max_bytes = 256, .allow_empty = false, .forbid_whitespace = true});
      if (!ssh_ok.has_value())
        return ssh_ok;
      if (peer.ssh_target->starts_with('-'))
        return Result<void>::failure({ErrorCode::invalid_range});
    }
    if (peer.provider.has_value()) {
      auto prov_ok = validate_config_text(
          *peer.provider,
          {.max_bytes = 128, .allow_empty = false, .forbid_whitespace = true});
      if (!prov_ok.has_value())
        return prov_ok;
    }
    if (peer.model.has_value()) {
      auto model_ok = validate_config_text(
          *peer.model,
          {.max_bytes = 128, .allow_empty = false, .forbid_whitespace = true});
      if (!model_ok.has_value())
        return model_ok;
    }
    if (peer.remote_session.has_value()) {
      auto sess_ok =
          validate_config_text(*peer.remote_session, {.max_bytes = kPartyMaxFieldBytes,
                                                      .allow_empty = false});
      if (!sess_ok.has_value())
        return sess_ok;
    }
    if (peer.display_name.has_value()) {
      auto dn_ok = validate_config_text(*peer.display_name,
                                        {.max_bytes = 128, .allow_empty = false});
      if (!dn_ok.has_value())
        return dn_ok;
    }
    if (peer.fingerprint.has_value() && !peer.fingerprint->empty()) {
      if (!valid_peer_fingerprint(*peer.fingerprint))
        return Result<void>::failure({ErrorCode::invalid_identity});
    }
  }
  return Result<void>::success();
}

Value party_roster_config_to_value(const PartyRosterConfig &config) {
  Value::Array peers_arr;
  peers_arr.reserve(config.peers.size());
  for (const auto &peer : config.peers) {
    Value::Object obj{
        {"alias", Value{peer.alias}},
        {"role", Value{std::string{party_member_role_name(peer.role)}}},
    };
    if (!peer.host.empty())
      obj.emplace_back("host", Value{peer.host});
    if (peer.ssh_target.has_value())
      obj.emplace_back("ssh_target", Value{*peer.ssh_target});
    if (peer.provider.has_value())
      obj.emplace_back("provider", Value{*peer.provider});
    if (peer.model.has_value())
      obj.emplace_back("model", Value{*peer.model});
    if (peer.remote_session.has_value())
      obj.emplace_back("remote_session", Value{*peer.remote_session});
    if (peer.display_name.has_value())
      obj.emplace_back("display_name", Value{*peer.display_name});
    if (peer.fingerprint.has_value() && !peer.fingerprint->empty())
      obj.emplace_back("fingerprint", Value{*peer.fingerprint});
    peers_arr.push_back(Value::object(std::move(obj)));
  }

  return Value::object({
      {"version", Value{Number{config.version}}},
      {"room_scope", Value{config.room_scope}},
      {"mode", Value{std::string{party_mode_override_name(config.mode_override)}}},
      {"peers", Value{std::move(peers_arr)}},
  });
}

Result<PartyRosterConfig> party_roster_config_from_value(const Value &root) {
  static constexpr std::array<std::string_view, 4> kRootKeys{
      "version",
      "room_scope",
      "mode",
      "peers",
  };
  auto root_ok = validate_strict_object_keys(root, kRootKeys);
  if (!root_ok.has_value())
    return Result<PartyRosterConfig>::failure(root_ok.error());

  PartyRosterConfig cfg{};
  if (const Value *ver_val = root.find("version")) {
    const auto ver = opt_uint64_field(root, "version");
    if (!ver.has_value() || *ver != kPartyConfigVersion)
      return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
    (void)ver_val;
    cfg.version = static_cast<std::uint32_t>(*ver);
  }
  if (const Value *scope_val = root.find("room_scope")) {
    const auto *s = std::get_if<std::string>(&scope_val->value());
    if (!s)
      return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
    cfg.room_scope = *s;
  }
  if (const Value *mode_val = root.find("mode")) {
    const auto *s = std::get_if<std::string>(&mode_val->value());
    if (!s)
      return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
    auto parsed_mode = parse_party_mode_override(*s);
    if (!parsed_mode.has_value())
      return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
    cfg.mode_override = parsed_mode.value();
  }
  if (const Value *peers_val = root.find("peers")) {
    const auto *arr = std::get_if<Value::Array>(&peers_val->value());
    if (!arr || arr->size() > kPartyMaxPeers)
      return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});

    static constexpr std::array<std::string_view, 9> kPeerKeys{
        "alias", "role",           "host",         "ssh_target",  "provider",
        "model", "remote_session", "display_name", "fingerprint",
    };
    cfg.peers.reserve(arr->size());
    for (const Value &item : *arr) {
      auto item_ok = validate_strict_object_keys(item, kPeerKeys);
      if (!item_ok.has_value())
        return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
      auto alias = opt_string_field(item, "alias");
      if (!alias.has_value())
        return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});

      PartyRosterPeerConfig peer{};
      peer.alias = std::move(*alias);
      if (const Value *rv = item.find("role")) {
        const auto *rs = std::get_if<std::string>(&rv->value());
        if (!rs)
          return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
        auto parsed_role = parse_party_member_role(*rs);
        if (!parsed_role.has_value())
          return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
        peer.role = parsed_role.value();
      }
      if (const Value *hv = item.find("host")) {
        const auto *hs = std::get_if<std::string>(&hv->value());
        if (!hs)
          return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
        peer.host = *hs;
      }
      auto read_opt_str = [&](std::string_view key,
                              std::optional<std::string> &dest) -> bool {
        const Value *v = item.find(key);
        if (!v || std::holds_alternative<std::nullptr_t>(v->value()))
          return true;
        const auto *s = std::get_if<std::string>(&v->value());
        if (!s)
          return false;
        dest = *s;
        return true;
      };
      if (!read_opt_str("ssh_target", peer.ssh_target) ||
          !read_opt_str("provider", peer.provider) ||
          !read_opt_str("model", peer.model) ||
          !read_opt_str("remote_session", peer.remote_session) ||
          !read_opt_str("display_name", peer.display_name) ||
          !read_opt_str("fingerprint", peer.fingerprint)) {
        return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
      }
      cfg.peers.push_back(std::move(peer));
    }
  }

  auto valid = validate_party_roster_config(cfg);
  if (!valid.has_value())
    return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
  return Result<PartyRosterConfig>::success(std::move(cfg));
}

// ---------------------------------------------------------------------------
// Pure read-only parsers for known_peers.json, platoon, and bridge.jsonl
// ---------------------------------------------------------------------------

struct KnownPeerInfo {
  std::string alias;
  std::string fingerprint;
  bool revoked = false;
};

Result<std::vector<KnownPeerInfo>>
read_known_peers_ro(const fs::path &known_peers_dir) {
  std::vector<KnownPeerInfo> out;
  const fs::path file = known_peers_dir / "known_peers.json";
  const PathProbe file_probe = probe_path_nofollow(file);
  if (file_probe == PathProbe::missing)
    return Result<std::vector<KnownPeerInfo>>::success(std::move(out));
  if (file_probe == PathProbe::symlink)
    return Result<std::vector<KnownPeerInfo>>::failure({ErrorCode::io, ELOOP});
  if (file_probe != PathProbe::regular_file)
    return Result<std::vector<KnownPeerInfo>>::failure({ErrorCode::io, EINVAL});

  auto content = read_regular_file_strict_ro(file, kMaxKnownPeersFileBytes);
  if (!content.has_value())
    return Result<std::vector<KnownPeerInfo>>::failure(content.error());
  if (trim_ascii(content.value()).empty())
    return Result<std::vector<KnownPeerInfo>>::success(std::move(out));

  auto parsed = parse_json(content.value(), {kMaxKnownPeersFileBytes, 200000, 32});
  if (!parsed.has_value())
    return Result<std::vector<KnownPeerInfo>>::failure({ErrorCode::corrupt});
  const Value &root = parsed.value();
  if (!std::holds_alternative<Value::Object>(root.value()))
    return Result<std::vector<KnownPeerInfo>>::failure({ErrorCode::corrupt});

  if (const Value *peers_val = root.find("peers")) {
    const auto *arr = std::get_if<Value::Array>(&peers_val->value());
    if (!arr)
      return Result<std::vector<KnownPeerInfo>>::failure({ErrorCode::corrupt});
    out.reserve(arr->size());
    for (const Value &entry : *arr) {
      if (!std::holds_alternative<Value::Object>(entry.value()))
        continue;
      auto alias = opt_string_field(entry, "alias");
      auto fp = opt_string_field(entry, "fingerprint");
      auto revoked = opt_bool_field(entry, "revoked");
      if (!alias.has_value() || !fp.has_value())
        continue;
      out.push_back(
          KnownPeerInfo{std::move(*alias), std::move(*fp), revoked.value_or(false)});
    }
  }
  return Result<std::vector<KnownPeerInfo>>::success(std::move(out));
}

PartyMemberRole infer_role_from_string(std::string_view role_str,
                                       PartyMemberRole fallback) noexcept {
  if (role_str.empty())
    return fallback;
  if (auto parsed = parse_party_member_role(role_str); parsed.has_value())
    return parsed.value();
  const std::string lower = to_lower_ascii(role_str);
  if (lower.find("operator") != std::string::npos || lower == "human")
    return PartyMemberRole::operator_human;
  if (lower.find("leader") != std::string::npos || lower == "coordinator" ||
      lower == "commander") {
    return PartyMemberRole::platoon_leader;
  }
  if (lower.find("peer") != std::string::npos || lower == "bridge")
    return PartyMemberRole::bridge_peer;
  return fallback;
}

PartyParticipantState map_platoon_state(PlatoonMemberState state) noexcept {
  switch (state) {
  case PlatoonMemberState::starting:
  case PlatoonMemberState::working:
    return PartyParticipantState::working;
  case PlatoonMemberState::waiting:
    return PartyParticipantState::idle;
  case PlatoonMemberState::completed:
  case PlatoonMemberState::failed:
  case PlatoonMemberState::stopped:
    return PartyParticipantState::offline;
  }
  return PartyParticipantState::offline;
}

PartyParticipantState infer_state_from_status(std::string_view status) noexcept {
  const std::string lower = to_lower_ascii(status);
  if (lower == "working" || lower == "busy" || lower == "running" ||
      lower == "active_work") {
    return PartyParticipantState::working;
  }
  if (lower == "idle" || lower == "waiting" || lower == "away")
    return PartyParticipantState::idle;
  if (lower == "offline" || lower == "stopped" || lower == "disconnected")
    return PartyParticipantState::offline;
  return PartyParticipantState::online;
}

Result<std::vector<PlatoonMember>> read_platoon_roster_ro(const fs::path &platoon_dir) {
  std::vector<PlatoonMember> out;
  const fs::path file = platoon_dir / "roster.json";
  const PathProbe probe = probe_path_nofollow(file);
  if (probe == PathProbe::missing)
    return Result<std::vector<PlatoonMember>>::success(std::move(out));
  if (probe == PathProbe::symlink)
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::io, ELOOP});
  if (probe != PathProbe::regular_file)
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::io, EINVAL});

  auto content = read_regular_file_strict_ro(file, kMaxPlatoonFileBytes);
  if (!content.has_value())
    return Result<std::vector<PlatoonMember>>::failure(content.error());
  if (trim_ascii(content.value()).empty())
    return Result<std::vector<PlatoonMember>>::success(std::move(out));

  auto parsed = parse_json(content.value(), {kMaxPlatoonFileBytes, 500000, 32});
  if (!parsed.has_value())
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::corrupt});
  const Value &root = parsed.value();
  if (!std::holds_alternative<Value::Object>(root.value()))
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::corrupt});

  const Value *members_val = root.find("members");
  if (!members_val)
    return Result<std::vector<PlatoonMember>>::success(std::move(out));
  const auto *arr = std::get_if<Value::Array>(&members_val->value());
  if (!arr)
    return Result<std::vector<PlatoonMember>>::failure({ErrorCode::corrupt});

  out.reserve(arr->size());
  for (const Value &item : *arr) {
    if (!std::holds_alternative<Value::Object>(item.value()))
      continue;
    auto id = opt_string_field(item, "id");
    auto state_str = opt_string_field(item, "state");
    if (!id.has_value() || !state_str.has_value())
      continue;
    auto state = parse_platoon_member_state(*state_str);
    if (!state.has_value())
      continue;
    PlatoonMember member{};
    member.id = std::move(*id);
    member.role = opt_string_field(item, "role").value_or(std::string{});
    member.provider = opt_string_field(item, "provider").value_or(std::string{});
    member.model = opt_string_field(item, "model").value_or(std::string{});
    member.workspace = opt_string_field(item, "workspace").value_or(std::string{});
    member.branch = opt_string_field(item, "branch").value_or(std::string{});
    member.state = state.value();
    member.pid = opt_int64_field(item, "pid").value_or(0);
    member.updated_ns = opt_int64_field(item, "updated_ns").value_or(0);
    member.brief = opt_string_field(item, "brief").value_or(std::string{});
    out.push_back(std::move(member));
  }
  return Result<std::vector<PlatoonMember>>::success(std::move(out));
}

Result<std::vector<PlatoonMessage>> read_platoon_board_ro(const fs::path &platoon_dir) {
  std::vector<PlatoonMessage> out;
  const fs::path file = platoon_dir / "board.jsonl";
  const PathProbe probe = probe_path_nofollow(file);
  if (probe == PathProbe::missing)
    return Result<std::vector<PlatoonMessage>>::success(std::move(out));
  if (probe == PathProbe::symlink)
    return Result<std::vector<PlatoonMessage>>::failure({ErrorCode::io, ELOOP});
  if (probe != PathProbe::regular_file)
    return Result<std::vector<PlatoonMessage>>::failure({ErrorCode::io, EINVAL});

  auto content = read_regular_file_strict_ro(file, kMaxPlatoonFileBytes);
  if (!content.has_value())
    return Result<std::vector<PlatoonMessage>>::failure(content.error());

  std::string_view remaining{content.value()};
  std::uint64_t last_seq = 0;
  while (!remaining.empty()) {
    const std::size_t nl = remaining.find('\n');
    if (nl == std::string_view::npos)
      break; // Ignore incomplete trailing line without newline.
    std::string_view line = remaining.substr(0, nl);
    remaining.remove_prefix(nl + 1);
    if (!line.empty() && line.back() == '\r')
      line.remove_suffix(1);
    if (line.empty() || line.back() == '!')
      continue;

    auto parsed = parse_json(line, {1024 * 1024, 2048, 16});
    if (!parsed.has_value())
      continue;
    const Value &obj = parsed.value();
    if (!std::holds_alternative<Value::Object>(obj.value()))
      continue;
    auto seq = opt_uint64_field(obj, "seq");
    auto ts = opt_int64_field(obj, "timestamp_ns");
    auto from = opt_string_field(obj, "from");
    auto to = opt_string_field(obj, "to");
    auto kind_str = opt_string_field(obj, "kind");
    auto text = opt_string_field(obj, "text");
    if (!seq.has_value() || *seq == 0 || *seq <= last_seq || !ts.has_value() ||
        !from.has_value() || !to.has_value() || !kind_str.has_value() ||
        !text.has_value()) {
      continue;
    }
    auto kind = parse_platoon_message_kind(*kind_str);
    if (!kind.has_value())
      continue;
    last_seq = *seq;

    PlatoonMessage msg{};
    msg.seq = *seq;
    msg.timestamp_ns = *ts;
    msg.from = std::move(*from);
    msg.to = std::move(*to);
    msg.kind = kind.value();
    msg.text = std::move(*text);
    out.push_back(std::move(msg));
  }

  if (out.size() > kMaxPlatoonMessagesLoaded) {
    out.erase(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(
                                             out.size() - kMaxPlatoonMessagesLoaded));
  }
  return Result<std::vector<PlatoonMessage>>::success(std::move(out));
}

struct BridgeReadOnlyReplay {
  std::vector<CausalEvent> events;
  std::vector<PeerEnvelope> envelopes;
  std::vector<PresenceRecord> active_presence;
  std::unordered_map<std::string, std::string> envelope_to_by_event;
};

Result<BridgeReadOnlyReplay> read_bridge_ro(const fs::path &bridge_dir,
                                            std::int64_t now_ns) {
  BridgeReadOnlyReplay replay{};
  const fs::path file = bridge_dir / "bridge.jsonl";
  const PathProbe probe = probe_path_nofollow(file);
  if (probe == PathProbe::missing)
    return Result<BridgeReadOnlyReplay>::success(std::move(replay));
  if (probe == PathProbe::symlink)
    return Result<BridgeReadOnlyReplay>::failure({ErrorCode::io, ELOOP});
  if (probe != PathProbe::regular_file)
    return Result<BridgeReadOnlyReplay>::failure({ErrorCode::io, EINVAL});

  auto content = read_regular_file_strict_ro(file, kMaxBridgeFileBytes);
  if (!content.has_value())
    return Result<BridgeReadOnlyReplay>::failure(content.error());

  std::unordered_set<std::string> seen_events;
  std::map<std::pair<std::string, std::string>, PresenceRecord> latest_presence;

  std::string_view remaining{content.value()};
  while (!remaining.empty()) {
    const std::size_t nl = remaining.find('\n');
    if (nl == std::string_view::npos)
      break;
    std::string_view line = remaining.substr(0, nl);
    remaining.remove_prefix(nl + 1);
    if (!line.empty() && line.back() == '\r')
      line.remove_suffix(1);
    if (line.empty() || line.back() == '!')
      continue;

    auto parsed = parse_json(line, {kBoardBridgeMaxLineBytes, 500000, 128});
    if (!parsed.has_value())
      continue;
    const Value &rec = parsed.value();
    if (!std::holds_alternative<Value::Object>(rec.value()))
      continue;
    auto rec_type = opt_string_field(rec, "record_type");
    if (!rec_type.has_value())
      continue;

    if (*rec_type == "causal_event") {
      if (const Value *ev_val = rec.find("event")) {
        auto ev = causal_event_from_value(*ev_val);
        if (ev.has_value() && seen_events.insert(ev.value().event_hash).second)
          replay.events.push_back(std::move(ev).value());
      }
    } else if (*rec_type == "envelope") {
      if (const Value *env_val = rec.find("envelope")) {
        auto env = envelope_from_value(*env_val);
        if (env.has_value()) {
          const PeerEnvelope &e = env.value();
          if (std::holds_alternative<Value::Object>(e.payload.value())) {
            if (const Value *ce = e.payload.find("causal_event")) {
              if (std::holds_alternative<Value::Object>(ce->value())) {
                if (auto hash = opt_string_field(*ce, "event_hash"); hash.has_value())
                  replay.envelope_to_by_event.try_emplace(*hash, e.to_fingerprint);
              }
            }
          }
          replay.envelopes.push_back(std::move(env).value());
        }
      }
    } else if (*rec_type == "presence") {
      if (const Value *p_val = rec.find("presence")) {
        auto pres = presence_from_value(*p_val);
        if (pres.has_value()) {
          const auto key =
              std::make_pair(pres.value().actor_id, pres.value().watching_scope);
          auto it = latest_presence.find(key);
          if (it == latest_presence.end() ||
              pres.value().updated_ns >= it->second.updated_ns) {
            latest_presence[key] = std::move(pres).value();
          }
        }
      }
    }
    // `receipt` records are intentionally observed passively and never mutated.
  }

  for (auto &[_, pres] : latest_presence) {
    if (pres.ttl_ns > 0 && pres.updated_ns <= now_ns &&
        now_ns - pres.updated_ns <= pres.ttl_ns) {
      replay.active_presence.push_back(std::move(pres));
    } else if (pres.ttl_ns > 0 && pres.updated_ns > now_ns &&
               pres.updated_ns - now_ns <= kBoardBridgeMaxFutureSkewNs) {
      replay.active_presence.push_back(std::move(pres));
    }
  }
  return Result<BridgeReadOnlyReplay>::success(std::move(replay));
}

std::string normalize_target_tag(std::string_view raw) {
  const std::string_view trimmed = trim_ascii(raw);
  if (trimmed.empty() || equals_ci(trimmed, "all") || equals_ci(trimmed, "@all"))
    return "@all";
  if (trimmed.starts_with('@'))
    return std::string{trimmed};
  return "@" + std::string{trimmed};
}

std::string short_fp(std::string_view fp) {
  if (fp.empty())
    return {};
  if (fp.size() <= 12)
    return std::string{fp};
  return std::string{fp.substr(0, 12)};
}

std::string extract_bridge_event_body(const CausalEvent &ev) {
  if (std::holds_alternative<Value::Object>(ev.payload.value())) {
    for (const std::string_view key : {"body", "text", "message", "summary", "note"}) {
      if (auto s = opt_string_field(ev.payload, key); s.has_value())
        return *s;
    }
  }
  auto dumped = dump_json(ev.payload);
  if (dumped.has_value())
    return std::move(dumped).value();
  return {};
}

PartyMessageKind map_platoon_msg_kind(PlatoonMessageKind kind,
                                      PartyMemberRole sender_role) noexcept {
  switch (kind) {
  case PlatoonMessageKind::blocker:
    return PartyMessageKind::blocker;
  case PlatoonMessageKind::decision:
    return PartyMessageKind::decision;
  case PlatoonMessageKind::status:
  case PlatoonMessageKind::handoff:
  case PlatoonMessageKind::artifact:
  case PlatoonMessageKind::review:
  case PlatoonMessageKind::brief:
    return PartyMessageKind::leader_update;
  case PlatoonMessageKind::message:
    return sender_role == PartyMemberRole::platoon_leader ? PartyMessageKind::chat
                                                          : PartyMessageKind::chat;
  }
  return PartyMessageKind::chat;
}

PartyMessageKind map_bridge_event_kind(std::string_view kind,
                                       PartyMemberRole sender_role) noexcept {
  if (auto parsed = parse_party_message_kind(kind); parsed.has_value())
    return parsed.value();
  const std::string lower = to_lower_ascii(kind);
  if (lower == "blocker" || lower == "blocked")
    return PartyMessageKind::blocker;
  if (lower == "decision")
    return PartyMessageKind::decision;
  if (lower == "conflict")
    return PartyMessageKind::conflict;
  if (lower == "system")
    return PartyMessageKind::system;
  if (lower == "status" || lower == "milestone" || lower == "update" ||
      lower == "progress" || lower == "handoff" || lower == "done") {
    return PartyMessageKind::leader_update;
  }
  if (sender_role == PartyMemberRole::platoon_leader && lower == "claim")
    return PartyMessageKind::leader_update;
  return PartyMessageKind::chat;
}

bool is_participant_online(PartyParticipantState state) noexcept {
  return state == PartyParticipantState::online ||
         state == PartyParticipantState::working ||
         state == PartyParticipantState::idle;
}

std::string_view state_dot(PartyParticipantState state) noexcept {
  switch (state) {
  case PartyParticipantState::online:
  case PartyParticipantState::working:
    return "●";
  case PartyParticipantState::idle:
    return "◐";
  case PartyParticipantState::offline:
    return "○";
  }
  return "○";
}

std::string_view role_badge(PartyMemberRole role) noexcept {
  switch (role) {
  case PartyMemberRole::operator_human:
    return "[OP]";
  case PartyMemberRole::platoon_leader:
    return "[LEADER]";
  case PartyMemberRole::worker:
    return "[WORKER]";
  case PartyMemberRole::bridge_peer:
    return "[PEER]";
  }
  return "[WORKER]";
}

int role_sort_rank(PartyMemberRole role) noexcept {
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

struct TimestampTagSpec {
  std::int64_t timestamp_ns = 0;
  std::size_t order_idx = 0;
};

std::string format_timestamp_tag(TimestampTagSpec spec) {
  // Real Unix epoch timestamps (>= year 2001 in ns) render deterministically in UTC.
  constexpr std::int64_t kEpoch2001Ns = 1'000'000'000'000'000'000LL;
  if (spec.timestamp_ns >= kEpoch2001Ns) {
    const auto secs = static_cast<std::time_t>(spec.timestamp_ns / 1'000'000'000LL);
    std::tm utc{};
    if (::gmtime_r(&secs, &utc) != nullptr) {
      std::array<char, 16> buf{};
      const auto n = std::snprintf(buf.data(), buf.size(), "%02d:%02d:%02d",
                                   utc.tm_hour, utc.tm_min, utc.tm_sec);
      if (n > 0)
        return std::string{buf.data(), static_cast<std::size_t>(n)};
    }
  }
  return "#" + std::to_string(spec.order_idx + 1);
}

// ---------------------------------------------------------------------------
// ANSI color helpers (used only when color == true, never on untrusted bytes)
// ---------------------------------------------------------------------------

enum class PartyInk : std::uint8_t {
  normal = 0,
  border,
  header,
  muted,
  op_badge,
  leader_badge,
  worker_badge,
  untrusted_badge,
  conflict_badge,
  target_pill,
  unread_badge,
  dot_online,
  dot_idle,
  dot_offline,
};

std::string_view sgr_for(PartyInk ink) noexcept {
  constexpr std::array<std::string_view, 14> kCodes{
      "\x1b[0m",                  // normal
      "\x1b[0;38;2;86;95;137m",   // border
      "\x1b[1;38;2;232;227;217m", // header
      "\x1b[0;38;2;122;134;156m", // muted
      "\x1b[1;38;2;125;207;255m", // op_badge
      "\x1b[1;38;2;158;206;106m", // leader_badge
      "\x1b[0;38;2;187;154;247m", // worker_badge
      "\x1b[1;38;2;224;175;104m", // untrusted_badge
      "\x1b[1;38;2;247;118;142m", // conflict_badge
      "\x1b[1;38;2;80;247;212m",  // target_pill
      "\x1b[1;38;2;255;158;100m", // unread_badge
      "\x1b[1;38;2;90;255;170m",  // dot_online
      "\x1b[0;38;2;224;175;104m", // dot_idle
      "\x1b[0;38;2;122;134;156m", // dot_offline
  };
  return kCodes[static_cast<std::size_t>(ink)];
}

std::string colorize(std::string_view text, PartyInk ink, bool color) {
  if (!color || ink == PartyInk::normal || text.empty())
    return std::string{text};
  std::string out;
  out.reserve(text.size() + 28);
  out.append(sgr_for(ink));
  out.append(text);
  out.append(sgr_for(PartyInk::normal));
  return out;
}

PartyInk ink_for_role(PartyMemberRole role) noexcept {
  switch (role) {
  case PartyMemberRole::operator_human:
    return PartyInk::op_badge;
  case PartyMemberRole::platoon_leader:
    return PartyInk::leader_badge;
  case PartyMemberRole::worker:
    return PartyInk::worker_badge;
  case PartyMemberRole::bridge_peer:
    return PartyInk::target_pill;
  }
  return PartyInk::normal;
}

PartyInk ink_for_state(PartyParticipantState state) noexcept {
  switch (state) {
  case PartyParticipantState::online:
  case PartyParticipantState::working:
    return PartyInk::dot_online;
  case PartyParticipantState::idle:
    return PartyInk::dot_idle;
  case PartyParticipantState::offline:
    return PartyInk::dot_offline;
  }
  return PartyInk::dot_offline;
}

std::string repeat_glyph(std::string_view glyph, std::size_t count) {
  std::string out;
  out.reserve(glyph.size() * count);
  for (std::size_t i = 0; i < count; ++i)
    out.append(glyph);
  return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Enum conversions & validators
// ---------------------------------------------------------------------------

std::string_view party_mode_name(PartyMode mode) noexcept {
  switch (mode) {
  case PartyMode::single_operator:
    return "single_operator";
  case PartyMode::multi_operator:
    return "multi_operator";
  }
  return "single_operator";
}

std::string_view party_mode_override_name(PartyModeOverride mode) noexcept {
  switch (mode) {
  case PartyModeOverride::auto_detect:
    return "auto";
  case PartyModeOverride::single_operator:
    return "single";
  case PartyModeOverride::multi_operator:
    return "multi";
  }
  return {};
}

Result<PartyModeOverride> parse_party_mode_override(std::string_view name) noexcept {
  if (equals_ci(name, "auto") || equals_ci(name, "auto_detect"))
    return Result<PartyModeOverride>::success(PartyModeOverride::auto_detect);
  if (equals_ci(name, "single") || equals_ci(name, "single_operator"))
    return Result<PartyModeOverride>::success(PartyModeOverride::single_operator);
  if (equals_ci(name, "multi") || equals_ci(name, "multi_operator"))
    return Result<PartyModeOverride>::success(PartyModeOverride::multi_operator);
  return Result<PartyModeOverride>::failure({ErrorCode::invalid_range});
}

std::string_view party_member_role_name(PartyMemberRole role) noexcept {
  switch (role) {
  case PartyMemberRole::operator_human:
    return "operator_human";
  case PartyMemberRole::platoon_leader:
    return "platoon_leader";
  case PartyMemberRole::worker:
    return "worker";
  case PartyMemberRole::bridge_peer:
    return "bridge_peer";
  }
  return {};
}

Result<PartyMemberRole> parse_party_member_role(std::string_view name) noexcept {
  if (equals_ci(name, "operator_human") || equals_ci(name, "operator") ||
      equals_ci(name, "op")) {
    return Result<PartyMemberRole>::success(PartyMemberRole::operator_human);
  }
  if (equals_ci(name, "platoon_leader") || equals_ci(name, "leader"))
    return Result<PartyMemberRole>::success(PartyMemberRole::platoon_leader);
  if (equals_ci(name, "worker"))
    return Result<PartyMemberRole>::success(PartyMemberRole::worker);
  if (equals_ci(name, "bridge_peer") || equals_ci(name, "peer"))
    return Result<PartyMemberRole>::success(PartyMemberRole::bridge_peer);
  return Result<PartyMemberRole>::failure({ErrorCode::invalid_range});
}

std::string_view party_participant_state_name(PartyParticipantState state) noexcept {
  switch (state) {
  case PartyParticipantState::online:
    return "online";
  case PartyParticipantState::working:
    return "working";
  case PartyParticipantState::idle:
    return "idle";
  case PartyParticipantState::offline:
    return "offline";
  }
  return {};
}

Result<PartyParticipantState>
parse_party_participant_state(std::string_view name) noexcept {
  if (equals_ci(name, "online"))
    return Result<PartyParticipantState>::success(PartyParticipantState::online);
  if (equals_ci(name, "working"))
    return Result<PartyParticipantState>::success(PartyParticipantState::working);
  if (equals_ci(name, "idle"))
    return Result<PartyParticipantState>::success(PartyParticipantState::idle);
  if (equals_ci(name, "offline"))
    return Result<PartyParticipantState>::success(PartyParticipantState::offline);
  return Result<PartyParticipantState>::failure({ErrorCode::invalid_range});
}

std::string_view party_message_kind_name(PartyMessageKind kind) noexcept {
  switch (kind) {
  case PartyMessageKind::chat:
    return "chat";
  case PartyMessageKind::leader_update:
    return "leader_update";
  case PartyMessageKind::blocker:
    return "blocker";
  case PartyMessageKind::decision:
    return "decision";
  case PartyMessageKind::conflict:
    return "conflict";
  case PartyMessageKind::system:
    return "system";
  }
  return {};
}

Result<PartyMessageKind> parse_party_message_kind(std::string_view name) noexcept {
  if (equals_ci(name, "chat"))
    return Result<PartyMessageKind>::success(PartyMessageKind::chat);
  if (equals_ci(name, "leader_update"))
    return Result<PartyMessageKind>::success(PartyMessageKind::leader_update);
  if (equals_ci(name, "blocker"))
    return Result<PartyMessageKind>::success(PartyMessageKind::blocker);
  if (equals_ci(name, "decision"))
    return Result<PartyMessageKind>::success(PartyMessageKind::decision);
  if (equals_ci(name, "conflict"))
    return Result<PartyMessageKind>::success(PartyMessageKind::conflict);
  if (equals_ci(name, "system"))
    return Result<PartyMessageKind>::success(PartyMessageKind::system);
  return Result<PartyMessageKind>::failure({ErrorCode::invalid_range});
}

std::string_view party_message_filter_name(PartyMessageFilter filter) noexcept {
  switch (filter) {
  case PartyMessageFilter::all:
    return "all";
  case PartyMessageFilter::operators:
    return "operators";
  case PartyMessageFilter::leaders:
    return "leaders";
  case PartyMessageFilter::conflicts:
    return "conflicts";
  }
  return "all";
}

Result<PartyMessageFilter> parse_party_message_filter(std::string_view name) noexcept {
  if (equals_ci(name, "all"))
    return Result<PartyMessageFilter>::success(PartyMessageFilter::all);
  if (equals_ci(name, "operators") || equals_ci(name, "ops"))
    return Result<PartyMessageFilter>::success(PartyMessageFilter::operators);
  if (equals_ci(name, "leaders"))
    return Result<PartyMessageFilter>::success(PartyMessageFilter::leaders);
  if (equals_ci(name, "conflicts"))
    return Result<PartyMessageFilter>::success(PartyMessageFilter::conflicts);
  return Result<PartyMessageFilter>::failure({ErrorCode::invalid_range});
}

bool valid_party_alias(std::string_view alias) noexcept {
  if (alias.empty() || alias.size() > kPartyMaxAliasBytes || equals_ci(alias, "all"))
    return false;
  for (const char ch : alias) {
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
    if (!ok)
      return false;
  }
  return alias.front() != '-' && alias.front() != '.';
}

// ---------------------------------------------------------------------------
// Hostile terminal-escape sanitizer
// ---------------------------------------------------------------------------

std::string party_chat_sanitize(std::string_view text, std::size_t max_bytes) {
  std::string out;
  out.reserve(std::min(text.size(), max_bytes));
  std::size_t written = 0;
  bool truncated = false;

  for (std::size_t i = 0; i < text.size(); ++i) {
    const auto b = static_cast<unsigned char>(text[i]);
    const bool is_utf8_c1 = b == 0xc2U && i + 1 < text.size() &&
                            static_cast<unsigned char>(text[i + 1]) >= 0x80U &&
                            static_cast<unsigned char>(text[i + 1]) <= 0x9fU;
    std::string chunk;
    if (b == '\n') {
      chunk = "\\n";
    } else if (b == '\r') {
      chunk = "\\r";
    } else if (b == '\t') {
      chunk = " ";
    } else if (b < 0x20U || b == 0x7fU || (b >= 0x80U && b <= 0x9fU)) {
      chunk = hex_escape_byte(b);
    } else if (is_utf8_c1) {
      const auto next = static_cast<unsigned char>(text[++i]);
      chunk = hex_escape_byte(b) + hex_escape_byte(next);
    } else {
      const DecodedUtf8 dec = decode_utf8_at(text, i);
      if (dec.length == 0) {
        chunk = hex_escape_byte(b);
      } else if (is_bidi_or_format_control(dec.scalar)) {
        for (std::size_t k = 0; k < dec.length; ++k)
          chunk += hex_escape_byte(static_cast<unsigned char>(text[i + k]));
        i += dec.length - 1;
      } else {
        chunk.assign(text.data() + i, dec.length);
        i += dec.length - 1;
      }
    }

    if (written + chunk.size() > max_bytes) {
      truncated = true;
      break;
    }
    out += chunk;
    written += chunk.size();
  }
  if (truncated)
    out += "...";
  return out;
}

// ---------------------------------------------------------------------------
// `.blackbird/party.json` loader & saver
// ---------------------------------------------------------------------------

Result<PartyRosterConfig> load_party_roster_config(const fs::path &path) {
  try {
    if (path_or_parent_is_symlink(path))
      return Result<PartyRosterConfig>::failure({ErrorCode::io, ELOOP});
    auto content = read_regular_file_strict_ro(path, kPartyConfigMaxBytes);
    if (!content.has_value())
      return Result<PartyRosterConfig>::failure(content.error());
    auto parsed = parse_json(content.value(), {kPartyConfigMaxBytes, 65536, 16});
    if (!parsed.has_value())
      return Result<PartyRosterConfig>::failure({ErrorCode::corrupt});
    return party_roster_config_from_value(parsed.value());
  } catch (const std::bad_alloc &) {
    return Result<PartyRosterConfig>::failure({ErrorCode::allocation});
  }
}

Result<void> save_party_roster_config(const fs::path &path,
                                      const PartyRosterConfig &config) {
  try {
    if (path.empty() || !path.has_filename())
      return Result<void>::failure({ErrorCode::invalid_range});
    if (path_or_parent_is_symlink(path))
      return Result<void>::failure({ErrorCode::io, ELOOP});

    auto valid = validate_party_roster_config(config);
    if (!valid.has_value())
      return valid;

    const Value doc = party_roster_config_to_value(config);
    auto dumped = dump_json(doc, {kPartyConfigMaxBytes, 65536, 16});
    if (!dumped.has_value())
      return Result<void>::failure(dumped.error());
    std::string payload = std::move(dumped).value();
    payload.push_back('\n');
    if (payload.size() > kPartyConfigMaxBytes)
      return Result<void>::failure({ErrorCode::capacity});

    const fs::path parent = path.parent_path();
    if (!parent.empty()) {
      const PathProbe parent_probe = probe_path_nofollow(parent);
      if (parent_probe == PathProbe::symlink)
        return Result<void>::failure({ErrorCode::io, ELOOP});
      if (parent_probe == PathProbe::missing) {
        std::error_code ec;
        (void)fs::create_directories(parent, ec);
        if (ec)
          return Result<void>::failure({ErrorCode::io, ec.value()});
        (void)::chmod(parent.c_str(), mode_t{0700});
      } else if (parent_probe != PathProbe::directory) {
        return Result<void>::failure({ErrorCode::io, ENOTDIR});
      }
    }

    const fs::path open_dir = parent.empty() ? fs::path{"."} : parent;
    int raw_dir_fd = -1;
    do {
      raw_dir_fd =
          ::open(open_dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } while (raw_dir_fd < 0 && errno == EINTR);
    if (raw_dir_fd < 0)
      return Result<void>::failure(native_error(errno));
    ScopedFd dir_fd{raw_dir_fd};

    const std::string target_name = path.filename().string();
    const auto pid = static_cast<unsigned long long>(::getpid());
    std::string tmp_name;
    ScopedFd tmp_fd;
    for (int attempt = 0; attempt < 64; ++attempt) {
      const auto seq = g_party_tmp_counter.fetch_add(1, std::memory_order_relaxed);
      tmp_name = ".party.json.tmp." + std::to_string(pid) + "." + std::to_string(seq);
      int fd = -1;
      do {
        fd = ::openat(dir_fd.get(), tmp_name.c_str(),
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      mode_t{0600});
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

    struct TempCleanup {
      int dfd = -1;
      std::string name;
      bool active = true;
      ~TempCleanup() {
        if (active && dfd >= 0 && !name.empty())
          (void)::unlinkat(dfd, name.c_str(), 0);
      }
    } cleanup{dir_fd.get(), tmp_name, true};

    if (::fchmod(tmp_fd.get(), mode_t{0600}) != 0)
      return Result<void>::failure(native_error(errno));
    auto written = write_all_fd(tmp_fd.get(), payload);
    if (!written.has_value())
      return written;
    auto synced = fsync_fd(tmp_fd.get());
    if (!synced.has_value())
      return synced;
    const int raw_tmp = tmp_fd.release();
    if (::close(raw_tmp) != 0)
      return Result<void>::failure(native_error(errno));

    // Re-check target is not a symlink right before atomic rename.
    if (probe_path_nofollow(path) == PathProbe::symlink)
      return Result<void>::failure({ErrorCode::io, ELOOP});
    if (::renameat(dir_fd.get(), cleanup.name.c_str(), dir_fd.get(),
                   target_name.c_str()) != 0) {
      return Result<void>::failure(native_error(errno));
    }
    cleanup.active = false;
    return fsync_fd(dir_fd.get());
  } catch (const std::bad_alloc &) {
    return Result<void>::failure({ErrorCode::allocation});
  }
}

// ---------------------------------------------------------------------------
// PartyConfig & PartySnapshot helpers
// ---------------------------------------------------------------------------

PartyConfig PartyConfig::for_project(const fs::path &project_root) {
  PartyConfig cfg{};
  cfg.project_root = project_root;
  cfg.platoon_dir = project_root / ".blackbird" / "platoon";
  cfg.bridge_dir = project_root / ".blackbird" / "bridge";
  cfg.party_config_path = project_root / ".blackbird" / "party.json";
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0')
    cfg.known_peers_dir = fs::path{home} / ".local" / "share" / "blackbird" / "peers";
  return cfg;
}

std::size_t PartySnapshot::operator_count() const noexcept {
  std::size_t count = 0;
  for (const auto &p : participants) {
    if (p.role == PartyMemberRole::operator_human)
      ++count;
  }
  return count;
}

std::size_t PartySnapshot::online_operator_count() const noexcept {
  std::size_t count = 0;
  for (const auto &p : participants) {
    if (p.role == PartyMemberRole::operator_human && is_participant_online(p.state))
      ++count;
  }
  return count;
}

std::size_t PartySnapshot::leader_count() const noexcept {
  std::size_t count = 0;
  for (const auto &p : participants) {
    if (p.role == PartyMemberRole::platoon_leader)
      ++count;
  }
  return count;
}

std::size_t PartySnapshot::online_leader_count() const noexcept {
  std::size_t count = 0;
  for (const auto &p : participants) {
    if (p.role == PartyMemberRole::platoon_leader && is_participant_online(p.state))
      ++count;
  }
  return count;
}

PartyMode detect_party_mode(const std::vector<PartyParticipant> &participants,
                            PartyModeOverride override_mode) noexcept {
  if (override_mode == PartyModeOverride::single_operator)
    return PartyMode::single_operator;
  if (override_mode == PartyModeOverride::multi_operator)
    return PartyMode::multi_operator;

  std::size_t distinct_ops = 0;
  for (std::size_t i = 0; i < participants.size(); ++i) {
    const auto &p = participants[i];
    if (p.role != PartyMemberRole::operator_human)
      continue;
    bool duplicate = false;
    for (std::size_t j = 0; j < i; ++j) {
      const auto &prev = participants[j];
      if (prev.role != PartyMemberRole::operator_human)
        continue;
      if (!p.fingerprint.empty() && p.fingerprint == prev.fingerprint) {
        duplicate = true;
        break;
      }
      if (!p.id.empty() && equals_ci(p.id, prev.id)) {
        duplicate = true;
        break;
      }
    }
    if (!duplicate) {
      ++distinct_ops;
      if (distinct_ops > 1)
        return PartyMode::multi_operator;
    }
  }
  return PartyMode::single_operator;
}

// ---------------------------------------------------------------------------
// Strictly passive read-only snapshot loader
// ---------------------------------------------------------------------------

Result<PartySnapshot> load_party_snapshot(const PartyConfig &config) {
  try {
    PartySnapshot snap{};
    snap.room_scope =
        config.room_scope.empty() ? std::string{kPartyDefaultScope} : config.room_scope;
    snap.mode_override = config.mode_override;

    // Indexed participant registry keyed by lowercase alias and by fingerprint.
    std::vector<PartyParticipant> roster;
    std::unordered_map<std::string, std::size_t> by_alias_lower;
    std::unordered_map<std::string, std::size_t> by_fp;

    auto find_participant_idx = [&](std::string_view id,
                                    std::string_view fp) -> std::optional<std::size_t> {
      if (!fp.empty()) {
        if (const auto it = by_fp.find(std::string{fp}); it != by_fp.end())
          return it->second;
      }
      if (!id.empty()) {
        if (const auto it = by_alias_lower.find(to_lower_ascii(id));
            it != by_alias_lower.end()) {
          return it->second;
        }
      }
      return std::nullopt;
    };

    auto register_indices = [&](std::size_t idx) {
      const auto &p = roster[idx];
      if (!p.id.empty())
        by_alias_lower[to_lower_ascii(p.id)] = idx;
      if (!p.fingerprint.empty())
        by_fp[p.fingerprint] = idx;
    };

    // 1. Optional `.blackbird/party.json` (read-only, never created, rejects symlinks).
    if (!config.party_config_path.empty()) {
      const PathProbe cfg_probe = probe_path_nofollow(config.party_config_path);
      if (cfg_probe == PathProbe::symlink)
        return Result<PartySnapshot>::failure({ErrorCode::io, ELOOP});
      if (cfg_probe == PathProbe::regular_file) {
        auto loaded = load_party_roster_config(config.party_config_path);
        if (!loaded.has_value())
          return Result<PartySnapshot>::failure(loaded.error());
        snap.party_config_present = true;
        const PartyRosterConfig &rc = loaded.value();
        if (config.room_scope.empty() && !rc.room_scope.empty())
          snap.room_scope = rc.room_scope;
        if (config.mode_override == PartyModeOverride::auto_detect)
          snap.mode_override = rc.mode_override;

        for (const auto &peer : rc.peers) {
          PartyParticipant p{};
          p.id = peer.alias;
          p.display_name = peer.display_name.value_or(peer.alias);
          p.role = peer.role;
          p.host = peer.host;
          p.ssh_target = peer.ssh_target;
          p.provider = peer.provider;
          p.remote_model = peer.model;
          p.model = peer.model.value_or(std::string{});
          p.remote_session = peer.remote_session;
          p.fingerprint = peer.fingerprint.value_or(std::string{});
          p.state = PartyParticipantState::offline;
          roster.push_back(std::move(p));
          register_indices(roster.size() - 1);
        }
      }
    }

    // 2. Local operator self (if supplied in config).
    if ((config.local_operator_id.has_value() && !config.local_operator_id->empty()) ||
        (config.local_actor_fp.has_value() && !config.local_actor_fp->empty())) {
      const std::string self_id =
          (config.local_operator_id.has_value() && !config.local_operator_id->empty())
              ? *config.local_operator_id
              : std::string{"operator"};
      const std::string self_fp = config.local_actor_fp.value_or(std::string{});
      if (auto idx = find_participant_idx(self_id, self_fp); idx.has_value()) {
        auto &p = roster[*idx];
        p.role = PartyMemberRole::operator_human;
        p.state = PartyParticipantState::online;
        p.local_self = true;
        if (!self_fp.empty() && p.fingerprint.empty())
          p.fingerprint = self_fp;
        if (!config.local_host.empty() && p.host.empty())
          p.host = config.local_host;
        if (config.local_operator_display_name.has_value() &&
            !config.local_operator_display_name->empty()) {
          p.display_name = *config.local_operator_display_name;
        }
        register_indices(*idx);
      } else {
        PartyParticipant p{};
        p.id = self_id;
        p.display_name = (config.local_operator_display_name.has_value() &&
                          !config.local_operator_display_name->empty())
                             ? *config.local_operator_display_name
                             : self_id;
        p.role = PartyMemberRole::operator_human;
        p.host = config.local_host;
        p.fingerprint = self_fp;
        p.state = PartyParticipantState::online;
        p.local_self = true;
        roster.push_back(std::move(p));
        register_indices(roster.size() - 1);
      }
    }

    // 3. Optional known peers store (read-only only when already present; never
    // creates).
    std::unordered_map<std::string, KnownPeerInfo> known_by_fp;
    if (!config.known_peers_dir.empty()) {
      if (path_or_parent_is_symlink(config.known_peers_dir))
        return Result<PartySnapshot>::failure({ErrorCode::io, ELOOP});
      const PathProbe kp_probe = probe_path_nofollow(config.known_peers_dir);
      if (kp_probe == PathProbe::symlink)
        return Result<PartySnapshot>::failure({ErrorCode::io, ELOOP});
      if (kp_probe == PathProbe::directory) {
        auto peers_res = read_known_peers_ro(config.known_peers_dir);
        if (!peers_res.has_value())
          return Result<PartySnapshot>::failure(peers_res.error());
        snap.known_peers_present = true;
        for (const auto &kp : peers_res.value()) {
          known_by_fp[kp.fingerprint] = kp;
          if (!kp.revoked) {
            if (auto idx = find_participant_idx(kp.alias, kp.fingerprint);
                idx.has_value()) {
              if (roster[*idx].fingerprint.empty()) {
                roster[*idx].fingerprint = kp.fingerprint;
                register_indices(*idx);
              }
            }
          }
        }
      }
    }

    // 4. Local `.blackbird/platoon` (pure read-only, never creates dirs or locks).
    if (!config.platoon_dir.empty()) {
      if (path_or_parent_is_symlink(config.platoon_dir))
        return Result<PartySnapshot>::failure({ErrorCode::io, ELOOP});
      const PathProbe pl_probe = probe_path_nofollow(config.platoon_dir);
      if (pl_probe == PathProbe::symlink)
        return Result<PartySnapshot>::failure({ErrorCode::io, ELOOP});
      if (pl_probe == PathProbe::directory) {
        snap.platoon_present = true;
        auto members_res = read_platoon_roster_ro(config.platoon_dir);
        if (!members_res.has_value())
          return Result<PartySnapshot>::failure(members_res.error());

        for (const auto &m : members_res.value()) {
          const PartyMemberRole inferred =
              infer_role_from_string(m.role, PartyMemberRole::worker);
          const PartyParticipantState st = map_platoon_state(m.state);
          if (auto idx = find_participant_idx(m.id, {}); idx.has_value()) {
            auto &p = roster[*idx];
            if (!m.role.empty())
              p.role = inferred;
            if (!m.model.empty())
              p.model = m.model;
            if (!m.provider.empty())
              p.provider = m.provider;
            p.state = st;
            p.last_seen_ns = std::max(p.last_seen_ns, m.updated_ns);
          } else {
            PartyParticipant p{};
            p.id = m.id;
            p.display_name = m.id;
            p.role = inferred;
            p.host = config.local_host;
            p.model = m.model;
            if (!m.provider.empty())
              p.provider = m.provider;
            p.state = st;
            p.last_seen_ns = m.updated_ns;
            roster.push_back(std::move(p));
            register_indices(roster.size() - 1);
          }
        }

        auto msgs_res = read_platoon_board_ro(config.platoon_dir);
        if (!msgs_res.has_value())
          return Result<PartySnapshot>::failure(msgs_res.error());

        for (const auto &pm : msgs_res.value()) {
          PartyMessage msg{};
          msg.id = "platoon#" + std::to_string(pm.seq);
          msg.timestamp_ns = pm.timestamp_ns;
          msg.sender_id = pm.from;
          msg.sender_role = PartyMemberRole::worker;
          msg.sender_host = config.local_host;
          if (auto idx = find_participant_idx(pm.from, {}); idx.has_value()) {
            const auto &p = roster[*idx];
            msg.sender_role = p.role;
            msg.sender_host = p.host;
            msg.sender_model = p.model;
            msg.sender_fingerprint = p.fingerprint;
          }
          msg.verified_peer = true;
          msg.untrusted_remote = false;
          msg.target = normalize_target_tag(pm.to);
          msg.kind = map_platoon_msg_kind(pm.kind, msg.sender_role);
          msg.body = pm.text;
          snap.messages.push_back(std::move(msg));
        }
      }
    }

    // 5. Signed `.blackbird/bridge` (pure read-only, never creates dirs/locks or
    //    advances receipts).
    if (!config.bridge_dir.empty()) {
      if (path_or_parent_is_symlink(config.bridge_dir))
        return Result<PartySnapshot>::failure({ErrorCode::io, ELOOP});
      const PathProbe br_probe = probe_path_nofollow(config.bridge_dir);
      if (br_probe == PathProbe::symlink)
        return Result<PartySnapshot>::failure({ErrorCode::io, ELOOP});
      if (br_probe == PathProbe::directory) {
        snap.bridge_present = true;
        const std::int64_t effective_now =
            config.now_ns > 0 ? config.now_ns : wall_now_ns();
        auto replay_res = read_bridge_ro(config.bridge_dir, effective_now);
        if (!replay_res.has_value())
          return Result<PartySnapshot>::failure(replay_res.error());
        const auto &replay = replay_res.value();

        const std::string_view local_fp = config.local_actor_fp.has_value()
                                              ? std::string_view{*config.local_actor_fp}
                                              : std::string_view{};

        auto is_verified_fp = [&](std::string_view fp) -> bool {
          if (fp.empty())
            return false;
          if (!local_fp.empty() && fp == local_fp)
            return true;
          const auto it = known_by_fp.find(std::string{fp});
          return it != known_by_fp.end() && !it->second.revoked;
        };

        struct BridgeLookup {
          std::string_view alias;
          std::string_view fp;
          bool verified = false;
          bool is_local = false;
        };
        auto find_bridge_participant_idx =
            [&](const BridgeLookup &q) -> std::optional<std::size_t> {
          if (!q.fp.empty()) {
            if (const auto it = by_fp.find(std::string{q.fp}); it != by_fp.end()) {
              const auto &existing = roster[it->second];
              if (existing.fingerprint == q.fp && (q.is_local || !existing.local_self))
                return it->second;
            }
          }
          // Unverified/revoked peers may NEVER bind by alias onto any existing row.
          if (!q.verified || q.alias.empty())
            return std::nullopt;
          if (const auto it = by_alias_lower.find(to_lower_ascii(q.alias));
              it != by_alias_lower.end()) {
            const auto &existing = roster[it->second];
            if (!q.is_local && existing.local_self)
              return std::nullopt;
            if (!existing.fingerprint.empty() && existing.fingerprint != q.fp)
              return std::nullopt;
            return it->second;
          }
          return std::nullopt;
        };

        // Merge live bridge presence heartbeats into participant roster.
        for (const auto &pres : replay.active_presence) {
          const bool verified = is_verified_fp(pres.actor_id);
          const bool is_local = !local_fp.empty() && pres.actor_id == local_fp;
          std::string resolved_id = pres.actor_id;
          if (verified) {
            if (const auto it = known_by_fp.find(pres.actor_id);
                it != known_by_fp.end() && !it->second.revoked &&
                !it->second.alias.empty()) {
              resolved_id = it->second.alias;
            }
          }
          if (auto idx = find_bridge_participant_idx(
                  {resolved_id, pres.actor_id, verified, is_local});
              idx.has_value()) {
            auto &p = roster[*idx];
            if (verified && !pres.display_name.empty())
              p.display_name = pres.display_name;
            if (p.fingerprint.empty())
              p.fingerprint = pres.actor_id;
            if (!verified)
              p.role = PartyMemberRole::bridge_peer;
            p.state = infer_state_from_status(pres.status);
            p.last_seen_ns = std::max(p.last_seen_ns, pres.updated_ns);
            register_indices(*idx);
          } else {
            PartyParticipant p{};
            p.id = resolved_id;
            p.display_name = (verified && !pres.display_name.empty())
                                 ? pres.display_name
                                 : resolved_id;
            p.role = verified ? infer_role_from_string(pres.status,
                                                       PartyMemberRole::bridge_peer)
                              : PartyMemberRole::bridge_peer;
            p.fingerprint = pres.actor_id;
            p.state = infer_state_from_status(pres.status);
            p.last_seen_ns = pres.updated_ns;
            p.local_self = is_local;
            roster.push_back(std::move(p));
            register_indices(roster.size() - 1);
          }
        }

        // Detect concurrent claim conflicts purely in memory.
        auto conflicts_res = detect_concurrent_claims(replay.events);
        if (!conflicts_res.has_value())
          return Result<PartySnapshot>::failure(conflicts_res.error());
        snap.conflicts = std::move(conflicts_res).value();

        std::unordered_map<std::string, const CausalEvent *> event_by_hash;
        event_by_hash.reserve(replay.events.size());
        for (const auto &ev : replay.events)
          event_by_hash.emplace(ev.event_hash, &ev);

        // Convert bridge causal events into unified PartyMessages.
        for (const auto &ev : replay.events) {
          const bool verified = is_verified_fp(ev.actor_id);
          const bool is_local = !local_fp.empty() && ev.actor_id == local_fp;

          std::string sender_alias = ev.actor_id;
          if (verified) {
            if (const auto kit = known_by_fp.find(ev.actor_id);
                kit != known_by_fp.end() && !kit->second.revoked &&
                !kit->second.alias.empty()) {
              sender_alias = kit->second.alias;
            }
          }

          // Optional metadata carried inside event payload.
          std::string payload_role;
          std::string payload_host;
          std::string payload_model;
          std::string payload_to;
          std::string payload_sender_id;
          if (std::holds_alternative<Value::Object>(ev.payload.value())) {
            payload_role = opt_string_field(ev.payload, "role").value_or(std::string{});
            payload_host = opt_string_field(ev.payload, "host").value_or(std::string{});
            payload_model =
                opt_string_field(ev.payload, "model").value_or(std::string{});
            payload_to = opt_string_field(ev.payload, "to").value_or(std::string{});
            payload_sender_id =
                opt_string_field(ev.payload, "sender_id").value_or(std::string{});
          }
          // Never honor self-declared sender_id from unverified or revoked peers.
          if (verified && !payload_sender_id.empty() && sender_alias == ev.actor_id)
            sender_alias = payload_sender_id;

          PartyMemberRole sender_role = PartyMemberRole::bridge_peer;
          std::string sender_host = payload_host;
          std::string sender_model = payload_model;
          if (auto idx = find_bridge_participant_idx(
                  {sender_alias, ev.actor_id, verified, is_local});
              idx.has_value()) {
            auto &p = roster[*idx];
            if (!verified) {
              p.role = PartyMemberRole::bridge_peer;
              sender_alias = ev.actor_id;
              sender_role = PartyMemberRole::bridge_peer;
            } else {
              if (!payload_role.empty() && p.role == PartyMemberRole::bridge_peer)
                p.role = infer_role_from_string(payload_role, p.role);
              sender_alias = p.id;
              sender_role = p.role;
            }
            if (sender_host.empty())
              sender_host = p.host;
            if (sender_model.empty())
              sender_model = p.model;
            p.last_seen_ns = std::max(p.last_seen_ns, ev.timestamp_ns);
          } else {
            // Only honor self-declared role metadata for verified peers or local self.
            if (verified && !payload_role.empty())
              sender_role =
                  infer_role_from_string(payload_role, PartyMemberRole::bridge_peer);
            PartyParticipant p{};
            p.id = sender_alias;
            p.display_name = sender_alias;
            p.role = sender_role;
            p.host = sender_host;
            p.model = sender_model;
            p.fingerprint = ev.actor_id;
            p.state = PartyParticipantState::online;
            p.last_seen_ns = ev.timestamp_ns;
            p.local_self = is_local;
            roster.push_back(std::move(p));
            register_indices(roster.size() - 1);
          }

          std::string target = "@all";
          if (!payload_to.empty()) {
            target = normalize_target_tag(payload_to);
          } else if (const auto eit = replay.envelope_to_by_event.find(ev.event_hash);
                     eit != replay.envelope_to_by_event.end() && !eit->second.empty() &&
                     eit->second != "*") {
            if (auto tidx = find_participant_idx({}, eit->second); tidx.has_value())
              target = normalize_target_tag(roster[*tidx].id);
            else if (const auto kit = known_by_fp.find(eit->second);
                     kit != known_by_fp.end() && !kit->second.revoked &&
                     !kit->second.alias.empty()) {
              target = normalize_target_tag(kit->second.alias);
            } else {
              target = normalize_target_tag(short_fp(eit->second));
            }
          }

          PartyMessage msg{};
          msg.id = "bridge:" + ev.event_hash;
          msg.timestamp_ns = ev.timestamp_ns;
          msg.sender_id = sender_alias;
          msg.sender_role = sender_role;
          msg.sender_host = sender_host;
          msg.sender_model = sender_model;
          msg.sender_fingerprint = ev.actor_id;
          msg.verified_peer = verified;
          msg.untrusted_remote = !is_local && !verified;
          msg.target = std::move(target);
          msg.kind = map_bridge_event_kind(ev.kind, sender_role);
          msg.body = extract_bridge_event_body(ev);
          snap.messages.push_back(std::move(msg));
        }

        // Emit structured [CONFLICT] alerts for every detected concurrent claim.
        for (const auto &conflict : snap.conflicts) {
          std::int64_t ts = effective_now;
          if (const auto it1 = event_by_hash.find(conflict.first_event_hash);
              it1 != event_by_hash.end()) {
            ts = it1->second->timestamp_ns;
          }
          if (const auto it2 = event_by_hash.find(conflict.second_event_hash);
              it2 != event_by_hash.end()) {
            ts = std::max(ts, it2->second->timestamp_ns);
          }

          auto actor_label = [&](std::string_view fp) -> std::string {
            if (auto idx = find_participant_idx({}, fp); idx.has_value())
              return roster[*idx].id;
            if (const auto kit = known_by_fp.find(std::string{fp});
                kit != known_by_fp.end() && !kit->second.revoked &&
                !kit->second.alias.empty()) {
              return kit->second.alias;
            }
            return short_fp(fp);
          };

          PartyMessage alert{};
          alert.id = "conflict:" + short_fp(conflict.first_event_hash) + ":" +
                     short_fp(conflict.second_event_hash);
          alert.timestamp_ns = ts;
          alert.sender_id = "bridge";
          alert.sender_role = PartyMemberRole::bridge_peer;
          alert.verified_peer = true;
          alert.untrusted_remote = false;
          alert.target = "@all";
          alert.kind = PartyMessageKind::conflict;
          alert.body = "Concurrent claim on " + conflict.resource_scope + ": " +
                       actor_label(conflict.first_actor_id) + " vs " +
                       actor_label(conflict.second_actor_id);
          snap.messages.push_back(std::move(alert));
        }
      }
    }

    // 6. Stable deterministic ordering for participants and chronological feed.
    std::stable_sort(roster.begin(), roster.end(),
                     [](const PartyParticipant &lhs, const PartyParticipant &rhs) {
                       const int lr = role_sort_rank(lhs.role);
                       const int rr = role_sort_rank(rhs.role);
                       if (lr != rr)
                         return lr < rr;
                       if (lhs.local_self != rhs.local_self)
                         return lhs.local_self && !rhs.local_self;
                       return to_lower_ascii(lhs.id) < to_lower_ascii(rhs.id);
                     });
    snap.participants = std::move(roster);

    std::stable_sort(snap.messages.begin(), snap.messages.end(),
                     [](const PartyMessage &lhs, const PartyMessage &rhs) {
                       if (lhs.timestamp_ns != rhs.timestamp_ns)
                         return lhs.timestamp_ns < rhs.timestamp_ns;
                       return lhs.id < rhs.id;
                     });

    snap.mode = detect_party_mode(snap.participants, snap.mode_override);
    return Result<PartySnapshot>::success(std::move(snap));
  } catch (const std::bad_alloc &) {
    return Result<PartySnapshot>::failure({ErrorCode::allocation});
  }
}

// ---------------------------------------------------------------------------
// Target routing parser
// ---------------------------------------------------------------------------

Result<ParsedPartyInput> parse_party_input(std::string_view input,
                                           const PartySnapshot &snap) {
  try {
    const std::string_view trimmed = trim_ascii(input);
    if (trimmed.empty())
      return Result<ParsedPartyInput>::failure({ErrorCode::invalid_range});

    ParsedPartyInput out{};
    out.mode = snap.mode;

    // Extract leading `@mention` tokens.
    std::string_view rest = trimmed;
    std::vector<std::string> raw_mentions;
    while (!rest.empty() && rest.front() == '@') {
      std::size_t end = 1;
      while (end < rest.size() && !is_ascii_space(rest[end]))
        ++end;
      std::string_view token = rest.substr(1, end - 1);
      // Strip common trailing punctuation like `@wintermute,` or `@wintermute:`.
      while (!token.empty() &&
             (token.back() == ',' || token.back() == ':' || token.back() == ';')) {
        token.remove_suffix(1);
      }
      if (token.empty())
        break;
      raw_mentions.emplace_back(token);
      rest = trim_ascii(rest.substr(end));
    }

    if (rest.empty())
      return Result<ParsedPartyInput>::failure({ErrorCode::invalid_range});
    out.body = std::string{rest};

    auto add_unique = [](std::vector<std::string> &vec, std::string_view val) {
      for (const auto &existing : vec) {
        if (equals_ci(existing, val))
          return;
      }
      vec.emplace_back(val);
    };

    auto resolve_broadcast_recipients = [&]() {
      if (snap.mode == PartyMode::single_operator) {
        // Prefer active (online/working/idle) platoon leaders; fall back to all
        // platoon leaders if all are currently offline.
        for (const auto &p : snap.participants) {
          if (p.role == PartyMemberRole::platoon_leader &&
              is_participant_online(p.state)) {
            add_unique(out.resolved_targets, p.id);
          }
        }
        if (out.resolved_targets.empty()) {
          for (const auto &p : snap.participants) {
            if (p.role == PartyMemberRole::platoon_leader)
              add_unique(out.resolved_targets, p.id);
          }
        }
      } else {
        // Multi-operator: broadcast to all operators (excluding local_self if other
        // recipients exist) + all platoon leaders.
        for (const auto &p : snap.participants) {
          if (p.role == PartyMemberRole::operator_human ||
              p.role == PartyMemberRole::platoon_leader) {
            if (!p.local_self)
              add_unique(out.resolved_targets, p.id);
          }
        }
      }
    };

    if (raw_mentions.empty()) {
      out.broadcast = true;
      out.explicit_all = false;
      out.target_label = "@all";
      resolve_broadcast_recipients();
      return Result<ParsedPartyInput>::success(std::move(out));
    }

    auto find_participant_by_token =
        [&](std::string_view tok) -> const PartyParticipant * {
      for (const auto &p : snap.participants) {
        if (equals_ci(p.id, tok) ||
            (!p.display_name.empty() && equals_ci(p.display_name, tok)) ||
            (!p.fingerprint.empty() && equals_ci(p.fingerprint, tok))) {
          return &p;
        }
      }
      return nullptr;
    };

    std::string label;
    for (const auto &mention : raw_mentions) {
      add_unique(out.mentioned_aliases, mention);
      if (equals_ci(mention, "all")) {
        out.broadcast = true;
        out.explicit_all = true;
        resolve_broadcast_recipients();
      } else if (const PartyParticipant *p = find_participant_by_token(mention)) {
        add_unique(out.resolved_targets, p->id);
        if (!label.empty())
          label.push_back(' ');
        label += "@" + p->id;
      } else {
        add_unique(out.unknown_targets, mention);
        if (!label.empty())
          label.push_back(' ');
        label += "@" + mention;
      }
    }

    out.target_label = out.broadcast ? std::string{"@all"}
                                     : (label.empty() ? std::string{"@all"} : label);
    return Result<ParsedPartyInput>::success(std::move(out));
  } catch (const std::bad_alloc &) {
    return Result<ParsedPartyInput>::failure({ErrorCode::allocation});
  }
}

// ---------------------------------------------------------------------------
// PartyChatFrame
// ---------------------------------------------------------------------------

std::string PartyChatFrame::text() const {
  std::string out;
  const auto est_width = width > 0 ? static_cast<std::size_t>(width) : std::size_t{80};
  out.reserve(lines.size() * (est_width + 1));
  for (const auto &line : lines) {
    out += line;
    out.push_back('\n');
  }
  return out;
}

// ---------------------------------------------------------------------------
// PartyChatPane state & rendering
// ---------------------------------------------------------------------------

PartyChatPane::PartyChatPane(PartySnapshot snapshot)
    : snapshot_(std::move(snapshot)), mode_override_(snapshot_.mode_override) {
  seen_message_ids_.reserve(snapshot_.messages.size());
  for (const auto &m : snapshot_.messages)
    seen_message_ids_.push_back(m.id);
  sync_selected_target();
}

Result<void> PartyChatPane::reload(const PartyConfig &config) {
  auto loaded = load_party_snapshot(config);
  if (!loaded.has_value())
    return Result<void>::failure(loaded.error());
  update(std::move(loaded).value());
  return Result<void>::success();
}

void PartyChatPane::update(PartySnapshot snapshot) {
  std::unordered_set<std::string_view> prev_seen;
  prev_seen.reserve(seen_message_ids_.size());
  for (const auto &id : seen_message_ids_)
    prev_seen.insert(id);

  std::size_t newly_arrived = 0;
  for (const auto &m : snapshot.messages) {
    if (!m.id.empty() && !prev_seen.contains(m.id))
      ++newly_arrived;
  }
  if (newly_arrived == 0 && snapshot.messages.size() > snapshot_.messages.size()) {
    // Fallback for messages without unique IDs.
    newly_arrived = snapshot.messages.size() - snapshot_.messages.size();
  }

  seen_message_ids_.clear();
  seen_message_ids_.reserve(snapshot.messages.size());
  for (const auto &m : snapshot.messages)
    seen_message_ids_.push_back(m.id);

  snapshot_ = std::move(snapshot);
  if (mode_override_ == PartyModeOverride::auto_detect &&
      snapshot_.mode_override != PartyModeOverride::auto_detect) {
    mode_override_ = snapshot_.mode_override;
  }
  snapshot_.mode = detect_party_mode(snapshot_.participants, mode_override_);

  if (newly_arrived > 0 && (!open_ || scroll_offset_ > 0))
    unread_count_ += newly_arrived;

  sync_selected_target();
}

void PartyChatPane::push_message(PartyMessage message) {
  const bool already_seen =
      !message.id.empty() &&
      std::find(seen_message_ids_.begin(), seen_message_ids_.end(), message.id) !=
          seen_message_ids_.end();
  if (!message.id.empty() && !already_seen)
    seen_message_ids_.push_back(message.id);
  snapshot_.messages.push_back(std::move(message));
  if (!already_seen && (!open_ || scroll_offset_ > 0))
    ++unread_count_;
}

void PartyChatPane::set_open(bool open) noexcept {
  open_ = open;
  if (open_ && focused_ && scroll_offset_ == 0)
    unread_count_ = 0;
}

void PartyChatPane::set_focused(bool focused) noexcept {
  focused_ = focused;
  if (focused_)
    unread_count_ = 0;
}

PartyMode PartyChatPane::mode() const noexcept {
  return detect_party_mode(snapshot_.participants, mode_override_);
}

void PartyChatPane::set_mode_override(PartyModeOverride override_mode) noexcept {
  mode_override_ = override_mode;
  snapshot_.mode_override = override_mode;
  snapshot_.mode = detect_party_mode(snapshot_.participants, mode_override_);
}

void PartyChatPane::set_filter(PartyMessageFilter filter) noexcept {
  filter_ = filter;
  scroll_offset_ = 0;
}

void PartyChatPane::cycle_filter() noexcept {
  switch (filter_) {
  case PartyMessageFilter::all:
    filter_ = PartyMessageFilter::operators;
    break;
  case PartyMessageFilter::operators:
    filter_ = PartyMessageFilter::leaders;
    break;
  case PartyMessageFilter::leaders:
    filter_ = PartyMessageFilter::conflicts;
    break;
  case PartyMessageFilter::conflicts:
    filter_ = PartyMessageFilter::all;
    break;
  }
  scroll_offset_ = 0;
}

std::vector<std::size_t> PartyChatPane::targetable_participant_indices() const {
  std::vector<std::size_t> indices;
  indices.reserve(snapshot_.participants.size());
  for (std::size_t i = 0; i < snapshot_.participants.size(); ++i) {
    if (!snapshot_.participants[i].local_self)
      indices.push_back(i);
  }
  return indices;
}

void PartyChatPane::sync_selected_target() {
  if (selected_target_ == "@all") {
    selected_target_index_ = std::nullopt;
    return;
  }
  std::string_view bare = selected_target_;
  if (bare.starts_with('@'))
    bare.remove_prefix(1);
  for (std::size_t i = 0; i < snapshot_.participants.size(); ++i) {
    if (equals_ci(snapshot_.participants[i].id, bare)) {
      selected_target_ = "@" + snapshot_.participants[i].id;
      selected_target_index_ = i;
      return;
    }
  }
  selected_target_ = "@all";
  selected_target_index_ = std::nullopt;
}

void PartyChatPane::cycle_target() {
  const auto candidates = targetable_participant_indices();
  if (candidates.empty()) {
    selected_target_ = "@all";
    selected_target_index_ = std::nullopt;
    return;
  }
  if (!selected_target_index_.has_value()) {
    const std::size_t first = candidates.front();
    selected_target_index_ = first;
    selected_target_ = "@" + snapshot_.participants[first].id;
    return;
  }
  const std::size_t cur = *selected_target_index_;
  const auto it = std::find(candidates.begin(), candidates.end(), cur);
  if (it == candidates.end() || std::next(it) == candidates.end()) {
    selected_target_ = "@all";
    selected_target_index_ = std::nullopt;
    return;
  }
  const std::size_t next_idx = *std::next(it);
  selected_target_index_ = next_idx;
  selected_target_ = "@" + snapshot_.participants[next_idx].id;
}

bool PartyChatPane::set_selected_target(std::string_view target) {
  const std::string_view trimmed = trim_ascii(target);
  if (trimmed.empty() || equals_ci(trimmed, "all") || equals_ci(trimmed, "@all")) {
    selected_target_ = "@all";
    selected_target_index_ = std::nullopt;
    return true;
  }
  std::string_view bare = trimmed;
  if (bare.starts_with('@'))
    bare.remove_prefix(1);
  for (std::size_t i = 0; i < snapshot_.participants.size(); ++i) {
    if (equals_ci(snapshot_.participants[i].id, bare)) {
      selected_target_ = "@" + snapshot_.participants[i].id;
      selected_target_index_ = i;
      return true;
    }
  }
  return false;
}

void PartyChatPane::scroll_up(std::size_t lines) noexcept {
  constexpr auto kMax = std::numeric_limits<std::size_t>::max();
  if (lines >= kMax - scroll_offset_)
    scroll_offset_ = kMax;
  else
    scroll_offset_ += lines;
}

void PartyChatPane::scroll_down(std::size_t lines) noexcept {
  if (lines >= scroll_offset_) {
    scroll_offset_ = 0;
    if (open_)
      unread_count_ = 0;
  } else {
    scroll_offset_ -= lines;
  }
}

void PartyChatPane::page_up(std::size_t page_lines) noexcept {
  scroll_up(std::max<std::size_t>(1, page_lines));
}

void PartyChatPane::page_down(std::size_t page_lines) noexcept {
  scroll_down(std::max<std::size_t>(1, page_lines));
}

void PartyChatPane::scroll_to_bottom() noexcept {
  scroll_offset_ = 0;
  unread_count_ = 0;
}

void PartyChatPane::set_composer_text(std::string text) {
  composer_text_ = std::move(text);
}

void PartyChatPane::append_composer_text(std::string_view text) {
  composer_text_.append(text);
}

void PartyChatPane::backspace_composer() noexcept {
  if (composer_text_.empty())
    return;
  // Pop one full UTF-8 codepoint from the end.
  while (!composer_text_.empty() &&
         (static_cast<unsigned char>(composer_text_.back()) & 0xc0U) == 0x80U) {
    composer_text_.pop_back();
  }
  if (!composer_text_.empty())
    composer_text_.pop_back();
}

Result<ParsedPartyInput> PartyChatPane::parse_composer() const {
  const std::string_view trimmed = trim_ascii(composer_text_);
  if (trimmed.empty())
    return Result<ParsedPartyInput>::failure({ErrorCode::invalid_range});
  PartySnapshot effective = snapshot_;
  effective.mode = mode();
  if (!trimmed.starts_with('@') && selected_target_ != "@all") {
    const std::string prefixed = selected_target_ + " " + std::string{trimmed};
    return parse_party_input(prefixed, effective);
  }
  return parse_party_input(trimmed, effective);
}

std::vector<PartyMessage> PartyChatPane::filtered_messages() const {
  std::vector<PartyMessage> out;
  out.reserve(snapshot_.messages.size());
  for (const auto &msg : snapshot_.messages) {
    switch (filter_) {
    case PartyMessageFilter::all:
      out.push_back(msg);
      break;
    case PartyMessageFilter::operators:
      if (msg.sender_role == PartyMemberRole::operator_human)
        out.push_back(msg);
      break;
    case PartyMessageFilter::leaders:
      if (msg.sender_role == PartyMemberRole::platoon_leader ||
          msg.kind == PartyMessageKind::leader_update) {
        out.push_back(msg);
      }
      break;
    case PartyMessageFilter::conflicts:
      if (msg.kind == PartyMessageKind::conflict ||
          msg.kind == PartyMessageKind::blocker) {
        out.push_back(msg);
      }
      break;
    }
  }
  return out;
}

PartyChatFrame PartyChatPane::render_frame(PartyPaneWidth width_arg,
                                           PartyPaneHeight height_arg,
                                           bool color) const {
  PartyChatFrame frame{};
  frame.mode = mode();
  frame.width = width_arg.value;
  frame.height = height_arg.value;
  frame.unread_count = unread_count_;
  frame.color_enabled = color;

  if (width_arg.value <= 0 || height_arg.value <= 0)
    return frame;

  const auto W = static_cast<std::size_t>(width_arg.value);
  const auto H = static_cast<std::size_t>(height_arg.value);
  const bool split = (width_arg.value >= kSplitLayoutMinWidth && H >= 8);
  frame.split_layout = split;
  frame.lines.reserve(H);

  const PartyMode cur_mode = frame.mode;
  const std::string mode_badge = cur_mode == PartyMode::multi_operator
                                     ? std::string{"[MULTI-OP]"}
                                     : std::string{"[SINGLE-OP · ALL LEADERS]"};
  const std::string safe_scope = party_chat_sanitize(
      snapshot_.room_scope.empty() ? std::string_view{kPartyDefaultScope}
                                   : std::string_view{snapshot_.room_scope},
      48);
  const std::string safe_target = party_chat_sanitize(selected_target_, 48);

  const std::size_t op_cnt = snapshot_.operator_count();
  const std::size_t leader_cnt = snapshot_.leader_count();
  const std::string counts = std::to_string(op_cnt) + (op_cnt == 1 ? " op" : " ops") +
                             " · " + std::to_string(leader_cnt) +
                             (leader_cnt == 1 ? " leader" : " leaders");

  const std::string unread_str =
      unread_count_ > 0 ? (" [+" + std::to_string(unread_count_) + " unread]")
                        : std::string{};
  const std::string_view key_hints = "Tab target · ↑↓ scroll · /party";

  // --- Row 0: Primary Header ---
  {
    std::string plain = "PARTY CHAT " + mode_badge + " " + safe_scope;
    if (split) {
      plain += " · " + counts + " | To: " + safe_target + unread_str;
    } else if (!unread_str.empty()) {
      plain += unread_str;
    }
    std::string line = pad_to_cells(plain, W);
    if (color)
      line = colorize(line, PartyInk::header, true);
    frame.lines.push_back(std::move(line));
    if (frame.lines.size() == H)
      return frame;
  }

  // --- Row 1: Sub-header (counts/target/filter + key hints) ---
  if (H >= 4) {
    const std::string filter_tag =
        "Filter: " + std::string{party_message_filter_name(filter_)};
    std::string left;
    if (split) {
      left = filter_tag;
      if (snapshot_.conflict_count() > 0)
        left += " · Conflicts: " + std::to_string(snapshot_.conflict_count());
    } else {
      left = counts + " · To: " + safe_target + " · " + filter_tag;
    }

    std::string row1;
    const std::size_t left_w = utf8_display_cells(left);
    const std::size_t hints_w = utf8_display_cells(key_hints);
    if (split && left_w + hints_w + 3 <= W) {
      row1 = left + std::string(W - left_w - hints_w, ' ') + std::string{key_hints};
    } else if (!split && left_w + hints_w + 2 <= W) {
      row1 = left + std::string(W - left_w - hints_w, ' ') + std::string{key_hints};
    } else {
      row1 = pad_to_cells(left, W);
    }
    if (color)
      row1 = colorize(row1, PartyInk::muted, true);
    frame.lines.push_back(std::move(row1));
    if (frame.lines.size() == H)
      return frame;
  }

  // Build wrapped chronological feed lines.
  const std::size_t roster_col_w =
      split ? std::clamp<std::size_t>(W / 4U, 24U, 34U) : 0U;
  const std::size_t feed_col_w =
      split ? (W > roster_col_w + 3U ? W - roster_col_w - 3U : 1U) : W;

  struct StyledFeedLine {
    std::string plain;
    PartyInk ink = PartyInk::normal;
  };
  std::vector<StyledFeedLine> feed_lines;
  const auto msgs = filtered_messages();
  if (msgs.empty()) {
    std::string empty_msg;
    if (snapshot_.messages.empty()) {
      empty_msg = "(no party messages yet — type below or use /party)";
    } else {
      empty_msg = "(no messages matching filter: " +
                  std::string{party_message_filter_name(filter_)} + ")";
    }
    for (auto &wline : wrap_words_sanitized(empty_msg, {feed_col_w, feed_col_w}))
      feed_lines.push_back({std::move(wline), PartyInk::muted});
  } else {
    for (std::size_t idx = 0; idx < msgs.size(); ++idx) {
      const auto &m = msgs[idx];
      const std::string ts = format_timestamp_tag({m.timestamp_ns, idx});
      const std::string rbadge{role_badge(m.sender_role)};
      const std::string sender =
          party_chat_sanitize(m.sender_id.empty() ? std::string_view{"unknown"}
                                                  : std::string_view{m.sender_id},
                              32);
      const std::string target =
          party_chat_sanitize(normalize_target_tag(m.target), 32);

      std::string prefix = ts + " " + rbadge;
      PartyInk line_ink = ink_for_role(m.sender_role);
      if (m.untrusted_remote) {
        prefix += " [PEER:UNTRUSTED]";
        line_ink = PartyInk::untrusted_badge;
      }
      if (m.kind == PartyMessageKind::conflict) {
        prefix += " [CONFLICT]";
        line_ink = PartyInk::conflict_badge;
      } else if (m.kind == PartyMessageKind::blocker) {
        prefix += " [BLOCKER]";
        line_ink = PartyInk::conflict_badge;
      } else if (m.kind == PartyMessageKind::decision) {
        prefix += " [DECISION]";
      } else if (m.kind == PartyMessageKind::system) {
        prefix += " [SYSTEM]";
        line_ink = PartyInk::muted;
      }

      prefix += " " + sender;
      if (!m.sender_model.empty() && feed_col_w >= 64)
        prefix += "(" + party_chat_sanitize(m.sender_model, 20) + ")";
      prefix += " -> " + target + ": ";

      if (m.agent_card.has_value()) {
        const auto &card = *m.agent_card;
        std::string status_tag = "[AGENT]";
        PartyInk card_ink = PartyInk::leader_badge;
        if (card.status == "done") {
          status_tag = "[DONE]";
          card_ink = PartyInk::dot_online;
        } else if (card.status == "working") {
          status_tag = "[WORKING]";
          card_ink = PartyInk::target_pill;
        } else if (card.status == "testing") {
          status_tag = "[TESTING]";
          card_ink = PartyInk::target_pill;
        } else if (card.status == "blocked") {
          status_tag = "[BLOCKED]";
          card_ink = PartyInk::untrusted_badge;
        } else if (card.status == "error") {
          status_tag = "[ERROR]";
          card_ink = PartyInk::conflict_badge;
        }

        // Sender attribution line above the card box.
        std::string hdr = prefix;
        if (hdr.size() >= 2U && hdr.ends_with(": ")) {
          hdr.pop_back();
        }
        for (auto &wline : wrap_words_sanitized(hdr, {feed_col_w, feed_col_w})) {
          feed_lines.push_back({std::move(wline), line_ink});
        }

        const std::string pad = feed_col_w >= 20U ? "  " : "";
        const std::size_t pad_w = pad.size();
        const std::string safe_agent = party_chat_sanitize(card.agent_name, 40U);
        const std::string safe_title =
            party_chat_sanitize(card.title.empty() ? std::string_view{"Agent update"}
                                                   : std::string_view{card.title},
                                160U);
        std::string card_top = pad + "┌─ " + status_tag + " ";
        if (!safe_agent.empty()) {
          card_top += safe_agent + " · ";
        }
        card_top += safe_title;
        if (card.diff_stat.has_value() && !card.diff_stat->empty()) {
          card_top += " (" + party_chat_sanitize(*card.diff_stat, 48U) + ")";
        }
        const std::string cont_prefix = pad + "│ ";
        const std::size_t cont_w =
            feed_col_w > pad_w + 2U ? (feed_col_w - pad_w - 2U) : feed_col_w;
        auto top_wrapped = wrap_words_sanitized(card_top, {feed_col_w, cont_w});
        for (std::size_t wi = 0; wi < top_wrapped.size(); ++wi) {
          if (wi == 0) {
            feed_lines.push_back({std::move(top_wrapped[wi]), card_ink});
          } else {
            feed_lines.push_back(
                {cont_prefix + std::move(top_wrapped[wi]), PartyInk::normal});
          }
        }

        if (!card.summary.empty()) {
          const std::string safe_summary = party_chat_sanitize(card.summary, 512U);
          auto sum_wrapped = wrap_words_sanitized(safe_summary, {cont_w, cont_w});
          for (auto &sline : sum_wrapped) {
            feed_lines.push_back({cont_prefix + std::move(sline), PartyInk::normal});
          }
        }

        if (!card.files.empty()) {
          std::string files_line = "files: ";
          const std::size_t shown = std::min<std::size_t>(card.files.size(), 6U);
          for (std::size_t fi = 0; fi < shown; ++fi) {
            if (fi > 0) {
              files_line += ", ";
            }
            files_line += party_chat_sanitize(card.files[fi], 96U);
          }
          if (card.files.size() > shown) {
            files_line += ", +" + std::to_string(card.files.size() - shown);
          }
          const std::string foot_prefix = pad + "└─ ";
          const std::size_t foot_w =
              feed_col_w > pad_w + 3U ? (feed_col_w - pad_w - 3U) : feed_col_w;
          auto files_wrapped = wrap_words_sanitized(files_line, {foot_w, foot_w});
          for (std::size_t wi = 0; wi < files_wrapped.size(); ++wi) {
            feed_lines.push_back(
                {(wi == 0 ? foot_prefix : (pad + "   ")) + std::move(files_wrapped[wi]),
                 PartyInk::muted});
          }
        } else if (feed_col_w >= pad_w + 4U) {
          feed_lines.push_back({pad + "└─", PartyInk::border});
        }
        continue;
      }

      const std::string safe_body = party_chat_sanitize(m.body, 2048);
      const std::string full = prefix + safe_body;
      const std::size_t indent_cols = feed_col_w >= 24 ? 4U : 0U;
      const std::size_t cont_w =
          feed_col_w > indent_cols ? (feed_col_w - indent_cols) : feed_col_w;
      auto wrapped = wrap_words_sanitized(full, {feed_col_w, cont_w});
      for (std::size_t wi = 0; wi < wrapped.size(); ++wi) {
        if (wi == 0) {
          feed_lines.push_back({std::move(wrapped[wi]), line_ink});
        } else {
          feed_lines.push_back({std::string(indent_cols, ' ') + std::move(wrapped[wi]),
                                PartyInk::normal});
        }
      }
    }
  }

  frame.total_feed_lines = feed_lines.size();

  // --- Narrow mode: compact top roster strip ---
  if (!split && H >= 6) {
    std::string strip = "ROSTER: ";
    if (snapshot_.participants.empty()) {
      strip += "(none)";
    } else {
      for (std::size_t i = 0; i < snapshot_.participants.size(); ++i) {
        const auto &p = snapshot_.participants[i];
        if (i > 0)
          strip += " · ";
        strip += std::string{state_dot(p.state)} + " " +
                 std::string{role_badge(p.role)} + " " + party_chat_sanitize(p.id, 20);
        if (!p.model.empty())
          strip += "(" + party_chat_sanitize(p.model, 14) + ")";
        else if (!p.host.empty())
          strip += "@" + party_chat_sanitize(p.host, 14);
        if (!p.fingerprint.empty())
          strip += "[" + party_chat_sanitize(short_fp(p.fingerprint), 12) + "]";
      }
    }
    const std::size_t strip_budget = H >= 14 ? 2U : 1U;
    auto strip_lines = wrap_words_sanitized(strip, {W, W});
    const std::size_t show_strip = std::min(strip_budget, strip_lines.size());
    for (std::size_t i = 0; i < show_strip && frame.lines.size() + 2 < H; ++i) {
      std::string row = pad_to_cells(strip_lines[i], W);
      if (color)
        row = colorize(row, PartyInk::target_pill, true);
      frame.lines.push_back(std::move(row));
    }
  }

  // --- Top Divider (with key hints on narrow so hints are always visible) ---
  if (frame.lines.size() + 2 < H) {
    std::string div;
    if (split) {
      div = repeat_glyph("─", roster_col_w + 1) + "┬" +
            repeat_glyph("─", W > roster_col_w + 2 ? W - roster_col_w - 2 : 0);
    } else {
      const std::string tag = " " + std::string{key_hints} + " ";
      const std::size_t tag_w = utf8_display_cells(tag);
      if (tag_w + 4 <= W) {
        const std::size_t rem = W - tag_w;
        const std::size_t left_d = rem / 2;
        const std::size_t right_d = rem - left_d;
        div = repeat_glyph("─", left_d) + tag + repeat_glyph("─", right_d);
      } else {
        div = repeat_glyph("─", W);
      }
    }
    div = clip_to_cells(div, W);
    if (color)
      div = colorize(div, PartyInk::border, true);
    frame.lines.push_back(std::move(div));
  }

  // Reserve bottom 2 rows for footer divider + composer (or 1 row if very short).
  const std::size_t footer_rows =
      (H >= frame.lines.size() + 2) ? 2U : (H > frame.lines.size() ? 1U : 0U);
  const std::size_t body_rows = (H > frame.lines.size() + footer_rows)
                                    ? (H - frame.lines.size() - footer_rows)
                                    : 0U;

  // Compute clamped bottom-anchored window into feed_lines.
  const std::size_t max_scroll =
      feed_lines.size() > body_rows ? (feed_lines.size() - body_rows) : 0U;
  frame.max_scroll_offset = max_scroll;
  const std::size_t eff_scroll = std::min(scroll_offset_, max_scroll);
  const std::size_t end_idx = feed_lines.size() - eff_scroll;
  const std::size_t start_idx = end_idx > body_rows ? (end_idx - body_rows) : 0U;

  // Build split left-column roster lines when split == true.
  std::vector<StyledFeedLine> roster_lines;
  if (split) {
    roster_lines.push_back(
        {"ROSTER (" + std::to_string(snapshot_.participants.size()) + ")",
         PartyInk::header});
    if (snapshot_.participants.empty()) {
      roster_lines.push_back({"(no participants)", PartyInk::muted});
    } else {
      for (std::size_t i = 0; i < snapshot_.participants.size(); ++i) {
        const auto &p = snapshot_.participants[i];
        const bool is_sel =
            selected_target_index_.has_value() && *selected_target_index_ == i;
        std::string l1 = (is_sel ? "> " : "  ") + std::string{state_dot(p.state)} +
                         " " + std::string{role_badge(p.role)} + " " +
                         party_chat_sanitize(p.id, 18);
        if (p.local_self)
          l1 += " (you)";
        roster_lines.push_back({std::move(l1), ink_for_state(p.state)});

        std::string meta;
        if (!p.host.empty())
          meta += party_chat_sanitize(p.host, 14);
        if (!p.model.empty()) {
          if (!meta.empty())
            meta += " · ";
          meta += party_chat_sanitize(p.model, 14);
        }
        if (!p.fingerprint.empty()) {
          if (!meta.empty())
            meta += " · ";
          meta += party_chat_sanitize(short_fp(p.fingerprint), 12);
        }
        if (!meta.empty())
          roster_lines.push_back({"    " + std::move(meta), PartyInk::muted});
      }
    }
  }

  // --- Body Rows ---
  for (std::size_t r = 0; r < body_rows; ++r) {
    const std::size_t feed_i = start_idx + r;
    const bool has_feed = feed_i < end_idx;
    const std::string feed_plain =
        has_feed ? pad_to_cells(feed_lines[feed_i].plain, feed_col_w)
                 : std::string(feed_col_w, ' ');
    const PartyInk feed_ink = has_feed ? feed_lines[feed_i].ink : PartyInk::normal;

    if (split) {
      const bool has_roster = r < roster_lines.size();
      const std::string r_plain =
          has_roster ? pad_to_cells(roster_lines[r].plain, roster_col_w)
                     : std::string(roster_col_w, ' ');
      const PartyInk r_ink = has_roster ? roster_lines[r].ink : PartyInk::normal;
      std::string combined;
      if (color) {
        combined = colorize(r_plain, r_ink, true) +
                   colorize(" │ ", PartyInk::border, true) +
                   colorize(feed_plain, feed_ink, true);
      } else {
        combined = r_plain + " │ " + feed_plain;
      }
      frame.lines.push_back(std::move(combined));
    } else {
      frame.lines.push_back(color ? colorize(feed_plain, feed_ink, true) : feed_plain);
    }
  }

  // --- Footer Divider ---
  if (footer_rows >= 2 && frame.lines.size() < H) {
    std::string fdiv;
    if (split) {
      fdiv = repeat_glyph("─", roster_col_w + 1) + "┴" +
             repeat_glyph("─", W > roster_col_w + 2 ? W - roster_col_w - 2 : 0);
    } else {
      fdiv = repeat_glyph("─", W);
    }
    fdiv = clip_to_cells(fdiv, W);
    if (color)
      fdiv = colorize(fdiv, PartyInk::border, true);
    frame.lines.push_back(std::move(fdiv));
  }

  // --- Footer Composer Line ---
  if (footer_rows >= 1 && frame.lines.size() < H) {
    const std::string prompt_prefix = "To: " + safe_target + " > ";
    const std::size_t prefix_w = utf8_display_cells(prompt_prefix);
    std::string footer_plain;
    if (focused_) {
      const std::string safe_input = party_chat_sanitize(composer_text_, 1024);
      if (W > prefix_w + 1) {
        const std::size_t input_budget = W - prefix_w - 1;
        footer_plain = prompt_prefix + tail_to_cells(safe_input, input_budget) + "_";
      } else {
        footer_plain = clip_to_cells(prompt_prefix + safe_input + "_", W);
      }
    } else {
      footer_plain = prompt_prefix + "[read-only · /party to focus · Tab target]";
    }
    footer_plain = pad_to_cells(footer_plain, W);
    if (color) {
      footer_plain = colorize(footer_plain,
                              focused_ ? PartyInk::target_pill : PartyInk::muted, true);
    }
    frame.lines.push_back(std::move(footer_plain));
  }

  return frame;
}

std::vector<std::string> PartyChatPane::render_lines(PartyPaneWidth width,
                                                     PartyPaneHeight height,
                                                     bool color) const {
  return render_frame(width, height, color).lines;
}

std::string PartyChatPane::render(PartyPaneWidth width, PartyPaneHeight height,
                                  bool color) const {
  return render_frame(width, height, color).text();
}

} // namespace blackbird
