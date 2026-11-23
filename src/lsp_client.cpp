#include "blackbird/lsp_client.hpp"
#include "blackbird/json.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <netinet/in.h>
#include <poll.h>
#include <spawn.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#ifndef F_SETNOSIGPIPE
#include <pthread.h>
#endif

extern char **environ;

namespace blackbird {
namespace {

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

constexpr std::size_t kMaxHeadersPerFrame = 64U;
constexpr std::size_t kMaxPendingResponses = 1024U;
constexpr std::size_t kMaxCachedDiagnosticUris = 4096U;
constexpr std::size_t kMaxDiagnosticsPerUri = 4096U;
constexpr std::size_t kMaxSymbolDepth = 64U;
constexpr std::size_t kMaxUnifiedDiffContextLines = 3U;
constexpr std::size_t kMaxReadableFileBytes = 16U * 1024U * 1024U;
constexpr std::size_t kRecvChunkBytes = 16U * 1024U;
constexpr std::size_t kRecvCompactThreshold = 64U * 1024U;

struct PathContainment {
  const fs::path &candidate;
  const fs::path &root;
};

struct RpcIdKey {
  std::variant<std::int64_t, std::string> value;
  auto operator<=>(const RpcIdKey &) const = default;
};

struct LineSpan {
  std::size_t start = 0;
  std::size_t content_end = 0;
  std::size_t full_end = 0;
};

struct ByteEdit {
  std::size_t start_byte = 0;
  std::size_t end_byte = 0;
  LspTextEdit edit;
};

struct HunkSpan {
  std::size_t old_start = 0;
  std::size_t old_end = 0;
  std::size_t new_start = 0;
  std::size_t new_end = 0;
};

struct DiffBuildInput {
  std::string_view relative_path;
  std::string_view before_text;
  std::string_view after_text;
  const std::vector<LineSpan> &before_lines;
  const std::vector<ByteEdit> &byte_edits;
};

#ifndef F_SETNOSIGPIPE
class ThreadSigpipeGuard {
public:
  ThreadSigpipeGuard() noexcept {
    sigemptyset(&blocked_);
    sigaddset(&blocked_, SIGPIPE);
    if (::pthread_sigmask(SIG_BLOCK, &blocked_, &previous_) == 0) {
      active_ = true;
      sigset_t pending{};
      if (::sigpending(&pending) == 0)
        was_pending_ = ::sigismember(&pending, SIGPIPE) == 1;
    }
  }
  ThreadSigpipeGuard(const ThreadSigpipeGuard &) = delete;
  ThreadSigpipeGuard &operator=(const ThreadSigpipeGuard &) = delete;
  ~ThreadSigpipeGuard() {
    if (!active_)
      return;
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
#endif

class OwnedFd {
public:
  OwnedFd() = default;
  explicit OwnedFd(int fd) noexcept : fd_(fd) {}
  OwnedFd(const OwnedFd &) = delete;
  OwnedFd &operator=(const OwnedFd &) = delete;
  OwnedFd(OwnedFd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  OwnedFd &operator=(OwnedFd &&other) noexcept {
    if (this != &other) {
      reset();
      fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
  }
  ~OwnedFd() { reset(); }

  int get() const noexcept { return fd_; }
  bool valid() const noexcept { return fd_ >= 0; }

  int release() noexcept { return std::exchange(fd_, -1); }

  void reset(int new_fd = -1) noexcept {
    if (fd_ >= 0) {
      while (::close(fd_) < 0 && errno == EINTR) {
      }
    }
    fd_ = new_fd;
  }

private:
  int fd_ = -1;
};

bool is_object(const Value &v) noexcept {
  return std::holds_alternative<Value::Object>(v.value());
}
bool is_array(const Value &v) noexcept {
  return std::holds_alternative<Value::Array>(v.value());
}
bool is_string(const Value &v) noexcept {
  return std::holds_alternative<std::string>(v.value());
}
bool is_bool(const Value &v) noexcept {
  return std::holds_alternative<bool>(v.value());
}
bool is_null(const Value &v) noexcept {
  return std::holds_alternative<std::nullptr_t>(v.value());
}
bool is_number(const Value &v) noexcept {
  return std::holds_alternative<Number>(v.value());
}

std::optional<std::int64_t> parse_int64(const Value &v) {
  if (!is_number(v))
    return std::nullopt;
  const auto &storage = v.number().storage();
  if (const auto *i = std::get_if<std::int64_t>(&storage))
    return *i;
  if (const auto *u = std::get_if<std::uint64_t>(&storage)) {
    if (*u > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
      return std::nullopt;
    return static_cast<std::int64_t>(*u);
  }
  const std::string text = v.number().text();
  if (text.empty())
    return std::nullopt;
  std::int64_t parsed = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

std::optional<std::uint32_t> parse_uint32(const Value &v) {
  const auto parsed = parse_int64(v);
  if (!parsed.has_value())
    return std::nullopt;
  if (parsed.value() < 0 ||
      parsed.value() >
          static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max()))
    return std::nullopt;
  return static_cast<std::uint32_t>(parsed.value());
}

bool valid_utf8_no_nul(std::string_view text) noexcept {
  return text.find('\0') == std::string_view::npos && valid_utf8(text);
}

bool has_ascii_control(std::string_view text) noexcept {
  for (const char ch : text) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7FU)
      return true;
  }
  return false;
}

std::string ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return out;
}

std::string_view trim_ascii_ows(std::string_view text) noexcept {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
    text.remove_prefix(1);
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
    text.remove_suffix(1);
  return text;
}

bool ascii_iequals(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size())
    return false;
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    const int a = std::tolower(static_cast<unsigned char>(lhs[i]));
    const int b = std::tolower(static_cast<unsigned char>(rhs[i]));
    if (a != b)
      return false;
  }
  return true;
}

int hex_nibble(char ch) noexcept {
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return 10 + (ch - 'a');
  if (ch >= 'A' && ch <= 'F')
    return 10 + (ch - 'A');
  return -1;
}

bool is_unreserved_uri_byte(unsigned char byte) noexcept {
  return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
         (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' ||
         byte == '~' || byte == '/';
}

bool path_within_root(PathContainment check) {
  auto cand_it = check.candidate.begin();
  auto root_it = check.root.begin();
  for (; root_it != check.root.end(); ++root_it, ++cand_it) {
    if (cand_it == check.candidate.end() || *cand_it != *root_it)
      return false;
  }
  return true;
}

Result<fs::path> canonicalize_workspace_root(const fs::path &root) {
  const std::string native = root.string();
  if (native.empty() || !valid_utf8_no_nul(native) || !root.is_absolute())
    return Result<fs::path>::failure({ErrorCode::invalid_range});
  std::error_code ec;
  const fs::path canonical = fs::canonical(root, ec);
  if (ec)
    return Result<fs::path>::failure({ErrorCode::invalid_range});
  const fs::file_status st = fs::status(canonical, ec);
  if (ec || !fs::is_directory(st))
    return Result<fs::path>::failure({ErrorCode::invalid_range});
  return Result<fs::path>::success(canonical);
}

// Rejects any ".." component before canonicalization, uses symlink_status during
// ancestor ascent so dangling symlinks cannot slip past canonicalization, and returns
// the symlink-resolved canonical path.
Result<fs::path> resolve_existing_prefix(const fs::path &input) {
  const std::string native = input.string();
  if (native.empty() || !valid_utf8_no_nul(native) || has_ascii_control(native) ||
      !input.is_absolute())
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  fs::path cleaned;
  for (const auto &part : input) {
    if (part == "..")
      return Result<fs::path>::failure({ErrorCode::invalid_range});
    if (part.empty() || part == ".")
      continue;
    cleaned /= part;
  }
  if (cleaned.empty() || !cleaned.is_absolute())
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  fs::path probe = cleaned;
  std::vector<fs::path> tail;
  while (true) {
    std::error_code ec;
    const fs::file_status st = fs::symlink_status(probe, ec);
    if (ec && ec != std::errc::no_such_file_or_directory)
      return Result<fs::path>::failure({ErrorCode::io});
    if (st.type() == fs::file_type::not_found) {
      const fs::path parent = probe.parent_path();
      if (parent == probe)
        return Result<fs::path>::failure({ErrorCode::invalid_range});
      tail.push_back(probe.filename());
      probe = parent;
      continue;
    }
    // Existing entry (including live or dangling symlinks): break and let canonical()
    // resolve live symlinks and reject dangling symlinks.
    break;
  }

  std::error_code ec;
  fs::path base = fs::canonical(probe, ec);
  if (ec)
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  for (auto it = tail.rbegin(); it != tail.rend(); ++it)
    base /= *it;
  return Result<fs::path>::success(base);
}

Result<fs::path> resolve_workspace_path_impl(const fs::path &canonical_root,
                                             const fs::path &input_path) {
  const std::string native = input_path.string();
  if (native.empty() || !valid_utf8_no_nul(native) || has_ascii_control(native))
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  fs::path combined =
      input_path.is_absolute() ? input_path : (canonical_root / input_path);
  auto resolved = resolve_existing_prefix(combined);
  if (!resolved.has_value())
    return Result<fs::path>::failure(resolved.error());
  if (!path_within_root({resolved.value(), canonical_root}))
    return Result<fs::path>::failure({ErrorCode::invalid_range});
  return resolved;
}

bool set_fd_cloexec(int fd) noexcept {
  const int flags = ::fcntl(fd, F_GETFD);
  if (flags < 0)
    return false;
  return ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

bool set_fd_nonblock(int fd) noexcept {
  const int flags = ::fcntl(fd, F_GETFL);
  if (flags < 0)
    return false;
  return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

void set_fd_nosigpipe(int fd) noexcept {
#ifdef F_SETNOSIGPIPE
  (void)::fcntl(fd, F_SETNOSIGPIPE, 1);
#else
  (void)fd;
#endif
}

void set_socket_nosigpipe(int fd) noexcept {
#ifdef SO_NOSIGPIPE
  int one = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
  (void)fd;
#endif
}

bool move_fd_above_stdio(OwnedFd &fd) noexcept {
  if (!fd.valid() || fd.get() > STDERR_FILENO)
    return true;
  const int moved = ::fcntl(fd.get(), F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
  if (moved < 0)
    return false;
  fd.reset(moved);
  return true;
}

int poll_timeout_ms(Clock::time_point deadline) noexcept {
  const auto now = Clock::now();
  if (now >= deadline)
    return 0;
  const auto remaining =
      std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
  if (remaining <= 0)
    return 1;
  if (remaining > static_cast<std::int64_t>(std::numeric_limits<int>::max()))
    return std::numeric_limits<int>::max();
  return static_cast<int>(remaining);
}

// Decodes a single UTF-8 scalar value starting at s[offset]. Returns codepoint and
// advances byte_len on success; returns std::nullopt on invalid UTF-8.
struct DecodedScalar {
  std::uint32_t scalar = 0;
  std::size_t byte_len = 0;
};

std::optional<DecodedScalar> decode_utf8_scalar(std::string_view s,
                                                std::size_t offset) noexcept {
  if (offset >= s.size())
    return std::nullopt;
  const auto first = static_cast<unsigned char>(s[offset]);
  if (first < 0x80U)
    return DecodedScalar{first, 1U};

  std::size_t extra = 0;
  std::uint32_t scalar = 0;
  std::uint32_t minimum = 0;
  if (first >= 0xC2U && first <= 0xDFU) {
    extra = 1U;
    scalar = first & 0x1FU;
    minimum = 0x80U;
  } else if (first >= 0xE0U && first <= 0xEFU) {
    extra = 2U;
    scalar = first & 0x0FU;
    minimum = 0x800U;
  } else if (first >= 0xF0U && first <= 0xF4U) {
    extra = 3U;
    scalar = first & 0x07U;
    minimum = 0x10000U;
  } else {
    return std::nullopt;
  }

  if (s.size() - offset <= extra)
    return std::nullopt;
  for (std::size_t j = 1; j <= extra; ++j) {
    const auto next = static_cast<unsigned char>(s[offset + j]);
    if ((next & 0xC0U) != 0x80U)
      return std::nullopt;
    scalar = (scalar << 6U) | (next & 0x3FU);
  }
  if (scalar < minimum || scalar > 0x10FFFFU ||
      (scalar >= 0xD800U && scalar <= 0xDFFFU))
    return std::nullopt;
  return DecodedScalar{scalar, extra + 1U};
}

std::vector<LineSpan> split_lines(std::string_view text) {
  std::vector<LineSpan> lines;
  std::size_t pos = 0;
  while (true) {
    const std::size_t nl = text.find('\n', pos);
    if (nl == std::string_view::npos) {
      const std::size_t content_end =
          (text.size() > pos && text.back() == '\r') ? (text.size() - 1U) : text.size();
      lines.push_back(LineSpan{pos, content_end, text.size()});
      break;
    }
    const std::size_t content_end =
        (nl > pos && text[nl - 1U] == '\r') ? (nl - 1U) : nl;
    lines.push_back(LineSpan{pos, content_end, nl + 1U});
    pos = nl + 1U;
  }
  return lines;
}

Result<std::size_t> position_to_byte_offset(std::string_view text,
                                            const std::vector<LineSpan> &lines,
                                            LspPosition pos,
                                            LspPositionEncoding encoding) {
  if (pos.line == lines.size() && pos.character == 0U)
    return Result<std::size_t>::success(text.size());
  if (pos.line >= lines.size())
    return Result<std::size_t>::failure({ErrorCode::invalid_range});
  const LineSpan &span = lines[pos.line];
  const std::string_view line_view =
      text.substr(span.start, span.content_end - span.start);
  auto col_bytes = lsp_column_to_utf8_byte_offset(line_view, pos.character, encoding);
  if (!col_bytes.has_value())
    return Result<std::size_t>::failure(col_bytes.error());
  return Result<std::size_t>::success(span.start + col_bytes.value());
}

Result<std::string> apply_text_edits_in_memory(std::string_view original,
                                               const std::vector<LspTextEdit> &edits,
                                               LspPositionEncoding encoding,
                                               std::vector<ByteEdit> *out_byte_edits) {
  const auto lines = split_lines(original);
  std::vector<ByteEdit> resolved;
  resolved.reserve(edits.size());

  for (const auto &edit : edits) {
    if (edit.range.end < edit.range.start)
      return Result<std::string>::failure({ErrorCode::invalid_range});
    if (!valid_utf8(edit.new_text))
      return Result<std::string>::failure({ErrorCode::corrupt});
    auto start_off =
        position_to_byte_offset(original, lines, edit.range.start, encoding);
    if (!start_off.has_value())
      return Result<std::string>::failure(start_off.error());
    auto end_off = position_to_byte_offset(original, lines, edit.range.end, encoding);
    if (!end_off.has_value())
      return Result<std::string>::failure(end_off.error());
    if (end_off.value() < start_off.value())
      return Result<std::string>::failure({ErrorCode::invalid_range});
    resolved.push_back(ByteEdit{start_off.value(), end_off.value(), edit});
  }

  std::stable_sort(resolved.begin(), resolved.end(),
                   [](const ByteEdit &lhs, const ByteEdit &rhs) {
                     if (lhs.start_byte != rhs.start_byte)
                       return lhs.start_byte < rhs.start_byte;
                     return lhs.end_byte < rhs.end_byte;
                   });

  for (std::size_t i = 1; i < resolved.size(); ++i) {
    if (resolved[i].start_byte < resolved[i - 1U].end_byte)
      return Result<std::string>::failure({ErrorCode::conflict});
  }

  std::string output;
  std::size_t expected_size = original.size();
  for (const auto &be : resolved) {
    expected_size =
        expected_size - (be.end_byte - be.start_byte) + be.edit.new_text.size();
  }
  output.reserve(expected_size);

  std::size_t cursor = 0;
  for (const auto &be : resolved) {
    output.append(original.substr(cursor, be.start_byte - cursor));
    output.append(be.edit.new_text);
    cursor = be.end_byte;
  }
  output.append(original.substr(cursor));

  if (out_byte_edits != nullptr)
    *out_byte_edits = std::move(resolved);
  return Result<std::string>::success(std::move(output));
}

std::string build_unified_diff(const DiffBuildInput &input) {
  if (input.before_text == input.after_text)
    return {};

  const auto after_lines = split_lines(input.after_text);
  const auto &before_lines = input.before_lines;

  // Strip trailing synthetic empty line caused by final '\n' when rendering line hunks.
  auto logical_count = [](std::string_view text, const std::vector<LineSpan> &spans) {
    if (text.empty())
      return std::size_t{0};
    if (!spans.empty() && text.back() == '\n')
      return spans.size() - 1U;
    return spans.size();
  };

  const std::size_t old_total = logical_count(input.before_text, before_lines);
  const std::size_t new_total = logical_count(input.after_text, after_lines);

  auto line_of_byte = [](const std::vector<LineSpan> &spans, std::size_t total,
                         std::size_t byte_pos) -> std::size_t {
    if (total == 0U)
      return 0U;
    auto it = std::upper_bound(
        spans.begin(), spans.begin() + static_cast<std::ptrdiff_t>(total), byte_pos,
        [](std::size_t pos, const LineSpan &span) { return pos < span.full_end; });
    const auto idx = static_cast<std::size_t>(it - spans.begin());
    return std::min(idx, total - 1U);
  };

  // Convert each ByteEdit into an affected [old_start, old_end) and [new_start,
  // new_end) line interval, then merge overlapping/nearby hunks.
  std::vector<HunkSpan> raw_hunks;
  raw_hunks.reserve(input.byte_edits.size());
  std::ptrdiff_t byte_delta = 0;

  for (const auto &be : input.byte_edits) {
    const std::size_t old_s =
        old_total == 0U ? 0U : line_of_byte(before_lines, old_total, be.start_byte);
    const std::size_t old_last_byte =
        (be.end_byte > be.start_byte) ? (be.end_byte - 1U) : be.start_byte;
    const std::size_t old_e =
        old_total == 0U
            ? 0U
            : std::min(old_total,
                       line_of_byte(before_lines, old_total, old_last_byte) + 1U);

    const auto new_start_byte = static_cast<std::size_t>(
        static_cast<std::ptrdiff_t>(be.start_byte) + byte_delta);
    const std::size_t new_end_byte = new_start_byte + be.edit.new_text.size();

    const std::size_t new_s =
        new_total == 0U ? 0U : line_of_byte(after_lines, new_total, new_start_byte);
    const std::size_t new_last_byte =
        (new_end_byte > new_start_byte) ? (new_end_byte - 1U) : new_start_byte;
    const std::size_t new_e =
        new_total == 0U
            ? 0U
            : std::min(new_total,
                       line_of_byte(after_lines, new_total, new_last_byte) + 1U);

    raw_hunks.push_back(HunkSpan{old_s, old_e, new_s, new_e});
    byte_delta += static_cast<std::ptrdiff_t>(be.edit.new_text.size()) -
                  static_cast<std::ptrdiff_t>(be.end_byte - be.start_byte);
  }

  if (raw_hunks.empty())
    return {};

  std::vector<HunkSpan> merged;
  for (const auto &h : raw_hunks) {
    const std::size_t ctx_old_s = h.old_start > kMaxUnifiedDiffContextLines
                                      ? (h.old_start - kMaxUnifiedDiffContextLines)
                                      : 0U;
    const std::size_t ctx_old_e =
        std::min(old_total, h.old_end + kMaxUnifiedDiffContextLines);
    const std::size_t ctx_new_s = h.new_start > kMaxUnifiedDiffContextLines
                                      ? (h.new_start - kMaxUnifiedDiffContextLines)
                                      : 0U;
    const std::size_t ctx_new_e =
        std::min(new_total, h.new_end + kMaxUnifiedDiffContextLines);

    if (!merged.empty() && ctx_old_s <= merged.back().old_end &&
        ctx_new_s <= merged.back().new_end) {
      merged.back().old_end = std::max(merged.back().old_end, ctx_old_e);
      merged.back().new_end = std::max(merged.back().new_end, ctx_new_e);
    } else {
      merged.push_back(HunkSpan{ctx_old_s, ctx_old_e, ctx_new_s, ctx_new_e});
    }
  }

  auto get_line = [](std::string_view text, const std::vector<LineSpan> &spans,
                     std::size_t idx) -> std::string_view {
    const LineSpan &s = spans[idx];
    return text.substr(s.start, s.content_end - s.start);
  };

  std::string out;
  out.append("--- a/");
  out.append(input.relative_path);
  out.append("\n+++ b/");
  out.append(input.relative_path);
  out.push_back('\n');

  for (const auto &h : merged) {
    const std::size_t old_count = h.old_end - h.old_start;
    const std::size_t new_count = h.new_end - h.new_start;
    const std::size_t old_header_line =
        old_count == 0U ? h.old_start : (h.old_start + 1U);
    const std::size_t new_header_line =
        new_count == 0U ? h.new_start : (h.new_start + 1U);

    out.append("@@ -");
    out.append(std::to_string(old_header_line));
    out.push_back(',');
    out.append(std::to_string(old_count));
    out.append(" +");
    out.append(std::to_string(new_header_line));
    out.push_back(',');
    out.append(std::to_string(new_count));
    out.append(" @@\n");

    // Emit shared leading context, changed lines, and shared trailing context.
    std::size_t prefix = 0;
    while (h.old_start + prefix < h.old_end && h.new_start + prefix < h.new_end &&
           get_line(input.before_text, before_lines, h.old_start + prefix) ==
               get_line(input.after_text, after_lines, h.new_start + prefix)) {
      ++prefix;
    }

    std::size_t suffix = 0;
    while (h.old_start + prefix + suffix < h.old_end &&
           h.new_start + prefix + suffix < h.new_end &&
           get_line(input.before_text, before_lines, h.old_end - 1U - suffix) ==
               get_line(input.after_text, after_lines, h.new_end - 1U - suffix)) {
      ++suffix;
    }

    for (std::size_t i = 0; i < prefix; ++i) {
      out.push_back(' ');
      out.append(get_line(input.before_text, before_lines, h.old_start + i));
      out.push_back('\n');
    }
    for (std::size_t i = h.old_start + prefix; i < h.old_end - suffix; ++i) {
      out.push_back('-');
      out.append(get_line(input.before_text, before_lines, i));
      out.push_back('\n');
    }
    for (std::size_t i = h.new_start + prefix; i < h.new_end - suffix; ++i) {
      out.push_back('+');
      out.append(get_line(input.after_text, after_lines, i));
      out.push_back('\n');
    }
    for (std::size_t i = 0; i < suffix; ++i) {
      out.push_back(' ');
      out.append(get_line(input.before_text, before_lines, h.old_end - suffix + i));
      out.push_back('\n');
    }
  }
  return out;
}

Result<std::string> read_regular_file_readonly(const fs::path &canonical_path) {
  std::error_code ec;
  const fs::file_status st = fs::symlink_status(canonical_path, ec);
  if (ec || !fs::is_regular_file(st))
    return Result<std::string>::failure({ErrorCode::io});

  const int fd = ::open(canonical_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return Result<std::string>::failure({ErrorCode::io, errno});
  OwnedFd guard{fd};

  struct stat sb{};
  if (::fstat(guard.get(), &sb) != 0 || !S_ISREG(sb.st_mode))
    return Result<std::string>::failure({ErrorCode::io, errno});
  if (sb.st_size < 0 || static_cast<std::uint64_t>(sb.st_size) > kMaxReadableFileBytes)
    return Result<std::string>::failure({ErrorCode::capacity});

  std::string content;
  content.reserve(static_cast<std::size_t>(sb.st_size));
  std::array<char, 8192> chunk{};
  while (true) {
    const ssize_t n = ::read(guard.get(), chunk.data(), chunk.size());
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return Result<std::string>::failure({ErrorCode::io, errno});
    }
    if (n == 0)
      break;
    if (content.size() + static_cast<std::size_t>(n) > kMaxReadableFileBytes)
      return Result<std::string>::failure({ErrorCode::capacity});
    content.append(chunk.data(), static_cast<std::size_t>(n));
  }
  if (!valid_utf8(content))
    return Result<std::string>::failure({ErrorCode::corrupt});
  return Result<std::string>::success(std::move(content));
}

Result<LspPosition> parse_position(const Value &v) {
  if (!is_object(v))
    return Result<LspPosition>::failure({ErrorCode::corrupt});
  const Value *line_val = v.find("line");
  const Value *char_val = v.find("character");
  if (line_val == nullptr || char_val == nullptr)
    return Result<LspPosition>::failure({ErrorCode::corrupt});
  const auto line = parse_uint32(*line_val);
  const auto character = parse_uint32(*char_val);
  if (!line.has_value() || !character.has_value())
    return Result<LspPosition>::failure({ErrorCode::corrupt});
  return Result<LspPosition>::success(LspPosition{line.value(), character.value()});
}

Result<LspRange> parse_range(const Value &v) {
  if (!is_object(v))
    return Result<LspRange>::failure({ErrorCode::corrupt});
  const Value *start_val = v.find("start");
  const Value *end_val = v.find("end");
  if (start_val == nullptr || end_val == nullptr)
    return Result<LspRange>::failure({ErrorCode::corrupt});
  auto start = parse_position(*start_val);
  auto end = parse_position(*end_val);
  if (!start.has_value())
    return Result<LspRange>::failure(start.error());
  if (!end.has_value())
    return Result<LspRange>::failure(end.error());
  if (end.value() < start.value())
    return Result<LspRange>::failure({ErrorCode::corrupt});
  return Result<LspRange>::success(LspRange{start.value(), end.value()});
}

Value serialize_position(LspPosition pos) {
  return Value::object({
      {"line", Value{Number{static_cast<std::uint64_t>(pos.line)}}},
      {"character", Value{Number{static_cast<std::uint64_t>(pos.character)}}},
  });
}

Value serialize_range(const LspRange &range) {
  return Value::object({
      {"start", serialize_position(range.start)},
      {"end", serialize_position(range.end)},
  });
}

Result<LspLocation> parse_location_in_workspace(const fs::path &workspace_root,
                                                const Value &v) {
  if (!is_object(v))
    return Result<LspLocation>::failure({ErrorCode::corrupt});
  // Support both Location {uri, range} and LocationLink {targetUri, targetRange, ...}.
  const Value *uri_val = v.find("uri");
  const Value *range_val = v.find("range");
  if (uri_val == nullptr) {
    uri_val = v.find("targetUri");
    range_val = v.find("targetSelectionRange");
    if (range_val == nullptr)
      range_val = v.find("targetRange");
  }
  if (uri_val == nullptr || !is_string(*uri_val) || range_val == nullptr)
    return Result<LspLocation>::failure({ErrorCode::corrupt});

  auto resolved = resolve_workspace_file_uri({workspace_root, uri_val->string()});
  if (!resolved.has_value())
    return Result<LspLocation>::failure(resolved.error());
  auto range = parse_range(*range_val);
  if (!range.has_value())
    return Result<LspLocation>::failure(range.error());

  return Result<LspLocation>::success(LspLocation{
      std::move(resolved).value(),
      uri_val->string(),
      range.value(),
  });
}

Result<LspTextEdit> parse_text_edit(const Value &v) {
  if (!is_object(v))
    return Result<LspTextEdit>::failure({ErrorCode::corrupt});
  const Value *range_val = v.find("range");
  const Value *new_text_val = v.find("newText");
  if (range_val == nullptr || new_text_val == nullptr || !is_string(*new_text_val))
    return Result<LspTextEdit>::failure({ErrorCode::corrupt});
  auto range = parse_range(*range_val);
  if (!range.has_value())
    return Result<LspTextEdit>::failure(range.error());
  return Result<LspTextEdit>::success(
      LspTextEdit{range.value(), new_text_val->string()});
}

Result<LspDocumentSymbol> parse_document_symbol_recursive(const Value &v,
                                                          std::size_t depth) {
  if (depth > kMaxSymbolDepth || !is_object(v))
    return Result<LspDocumentSymbol>::failure({ErrorCode::corrupt});
  const Value *name_val = v.find("name");
  const Value *kind_val = v.find("kind");
  if (name_val == nullptr || !is_string(*name_val) || kind_val == nullptr)
    return Result<LspDocumentSymbol>::failure({ErrorCode::corrupt});
  const auto kind = parse_uint32(*kind_val);
  if (!kind.has_value())
    return Result<LspDocumentSymbol>::failure({ErrorCode::corrupt});

  LspDocumentSymbol sym;
  sym.name = name_val->string();
  sym.kind = kind.value();
  if (const Value *detail_val = v.find("detail");
      detail_val != nullptr && is_string(*detail_val)) {
    sym.detail = detail_val->string();
  }

  // Hierarchical DocumentSymbol has range + selectionRange; flat SymbolInformation
  // has location.range.
  if (const Value *range_val = v.find("range"); range_val != nullptr) {
    auto range = parse_range(*range_val);
    if (!range.has_value())
      return Result<LspDocumentSymbol>::failure(range.error());
    sym.range = range.value();
    if (const Value *sel_val = v.find("selectionRange"); sel_val != nullptr) {
      auto sel = parse_range(*sel_val);
      if (!sel.has_value())
        return Result<LspDocumentSymbol>::failure(sel.error());
      sym.selection_range = sel.value();
    } else {
      sym.selection_range = sym.range;
    }
  } else if (const Value *loc_val = v.find("location");
             loc_val != nullptr && is_object(*loc_val)) {
    const Value *loc_range = loc_val->find("range");
    if (loc_range == nullptr)
      return Result<LspDocumentSymbol>::failure({ErrorCode::corrupt});
    auto range = parse_range(*loc_range);
    if (!range.has_value())
      return Result<LspDocumentSymbol>::failure(range.error());
    sym.range = range.value();
    sym.selection_range = range.value();
    if (const Value *container = v.find("containerName");
        container != nullptr && is_string(*container) && sym.detail.empty()) {
      sym.detail = container->string();
    }
  } else {
    return Result<LspDocumentSymbol>::failure({ErrorCode::corrupt});
  }

  if (const Value *children_val = v.find("children"); children_val != nullptr) {
    if (!is_array(*children_val))
      return Result<LspDocumentSymbol>::failure({ErrorCode::corrupt});
    sym.children.reserve(children_val->array().size());
    for (const auto &child : children_val->array()) {
      auto parsed_child = parse_document_symbol_recursive(child, depth + 1U);
      if (!parsed_child.has_value())
        return Result<LspDocumentSymbol>::failure(parsed_child.error());
      sym.children.push_back(std::move(parsed_child).value());
    }
  }
  return Result<LspDocumentSymbol>::success(std::move(sym));
}

Result<LspCallHierarchyItem> parse_call_hierarchy_item(const fs::path &workspace_root,
                                                       const Value &v) {
  if (!is_object(v))
    return Result<LspCallHierarchyItem>::failure({ErrorCode::corrupt});
  const Value *name_val = v.find("name");
  const Value *kind_val = v.find("kind");
  const Value *uri_val = v.find("uri");
  const Value *range_val = v.find("range");
  const Value *sel_val = v.find("selectionRange");
  if (name_val == nullptr || !is_string(*name_val) || kind_val == nullptr ||
      uri_val == nullptr || !is_string(*uri_val) || range_val == nullptr ||
      sel_val == nullptr) {
    return Result<LspCallHierarchyItem>::failure({ErrorCode::corrupt});
  }
  const auto kind = parse_uint32(*kind_val);
  if (!kind.has_value())
    return Result<LspCallHierarchyItem>::failure({ErrorCode::corrupt});
  auto resolved = resolve_workspace_file_uri({workspace_root, uri_val->string()});
  if (!resolved.has_value())
    return Result<LspCallHierarchyItem>::failure(resolved.error());
  auto range = parse_range(*range_val);
  auto sel = parse_range(*sel_val);
  if (!range.has_value())
    return Result<LspCallHierarchyItem>::failure(range.error());
  if (!sel.has_value())
    return Result<LspCallHierarchyItem>::failure(sel.error());

  LspCallHierarchyItem item;
  item.name = name_val->string();
  item.kind = kind.value();
  if (const Value *detail_val = v.find("detail");
      detail_val != nullptr && is_string(*detail_val)) {
    item.detail = detail_val->string();
  }
  item.path = std::move(resolved).value();
  item.uri = uri_val->string();
  item.range = range.value();
  item.selection_range = sel.value();
  if (const Value *data_val = v.find("data"); data_val != nullptr)
    item.data = *data_val;
  return Result<LspCallHierarchyItem>::success(std::move(item));
}

Value serialize_call_hierarchy_item(const LspCallHierarchyItem &item) {
  Value::Object obj{
      {"name", Value{item.name}},
      {"kind", Value{Number{static_cast<std::uint64_t>(item.kind)}}},
      {"uri", Value{item.uri}},
      {"range", serialize_range(item.range)},
      {"selectionRange", serialize_range(item.selection_range)},
  };
  if (!item.detail.empty())
    obj.emplace_back("detail", Value{item.detail});
  if (item.data.has_value())
    obj.emplace_back("data", item.data.value());
  return Value::object(std::move(obj));
}

bool capability_enabled(const Value *v) noexcept {
  if (v == nullptr || is_null(*v))
    return false;
  if (is_bool(*v))
    return std::get<bool>(v->value());
  return is_object(*v);
}

std::optional<RpcIdKey> parse_rpc_id_key(const Value &v) {
  if (is_string(v))
    return RpcIdKey{v.string()};
  if (const auto i = parse_int64(v); i.has_value())
    return RpcIdKey{i.value()};
  return std::nullopt;
}

Value serialize_rpc_id(const LspRequestId &id) {
  if (const auto *i = std::get_if<std::int64_t>(&id.value))
    return Value{Number{*i}};
  return Value{std::get<std::string>(id.value)};
}

RpcIdKey to_rpc_id_key(const LspRequestId &id) { return RpcIdKey{id.value}; }

Result<OwnedFd> connect_socket_with_timeout(int domain, const sockaddr *addr,
                                            socklen_t addr_len,
                                            std::chrono::milliseconds timeout) {
  OwnedFd fd{::socket(domain, SOCK_STREAM, 0)};
  if (!fd.valid())
    return Result<OwnedFd>::failure({ErrorCode::io, errno});
  if (!set_fd_cloexec(fd.get()) || !set_fd_nonblock(fd.get()))
    return Result<OwnedFd>::failure({ErrorCode::io, errno});
  set_socket_nosigpipe(fd.get());

  const int rc = ::connect(fd.get(), addr, addr_len);
  if (rc == 0)
    return Result<OwnedFd>::success(std::move(fd));
  if (errno != EINPROGRESS && errno != EINTR)
    return Result<OwnedFd>::failure({ErrorCode::io, errno});

  const auto deadline = Clock::now() + std::max(timeout, std::chrono::milliseconds{1});
  while (true) {
    const int wait_ms = poll_timeout_ms(deadline);
    if (wait_ms <= 0)
      return Result<OwnedFd>::failure({ErrorCode::io, ETIMEDOUT});
    pollfd pfd{};
    pfd.fd = fd.get();
    pfd.events = POLLOUT;
    const int prc = ::poll(&pfd, 1, wait_ms);
    if (prc < 0) {
      if (errno == EINTR)
        continue;
      return Result<OwnedFd>::failure({ErrorCode::io, errno});
    }
    if (prc == 0)
      return Result<OwnedFd>::failure({ErrorCode::io, ETIMEDOUT});

    int so_err = 0;
    socklen_t so_len = sizeof(so_err);
    if (::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &so_err, &so_len) != 0)
      return Result<OwnedFd>::failure({ErrorCode::io, errno});
    if (so_err != 0)
      return Result<OwnedFd>::failure({ErrorCode::io, so_err});
    return Result<OwnedFd>::success(std::move(fd));
  }
}

Result<std::size_t> parse_content_length_headers(std::string_view header_block,
                                                 std::size_t max_payload_bytes) {
  if (header_block.find('\0') != std::string_view::npos)
    return Result<std::size_t>::failure({ErrorCode::corrupt});

  std::optional<std::size_t> content_length;
  std::size_t header_count = 0;
  std::size_t pos = 0;

  while (pos < header_block.size()) {
    const std::size_t crlf = header_block.find("\r\n", pos);
    const std::string_view line = (crlf == std::string_view::npos)
                                      ? header_block.substr(pos)
                                      : header_block.substr(pos, crlf - pos);
    pos = (crlf == std::string_view::npos) ? header_block.size() : (crlf + 2U);

    if (line.empty())
      return Result<std::size_t>::failure({ErrorCode::corrupt});
    if (line.find('\r') != std::string_view::npos ||
        line.find('\n') != std::string_view::npos) {
      return Result<std::size_t>::failure({ErrorCode::corrupt});
    }
    ++header_count;
    if (header_count > kMaxHeadersPerFrame)
      return Result<std::size_t>::failure({ErrorCode::capacity});

    const std::size_t colon = line.find(':');
    if (colon == std::string_view::npos || colon == 0U)
      return Result<std::size_t>::failure({ErrorCode::corrupt});

    const std::string_view name = trim_ascii_ows(line.substr(0, colon));
    const std::string_view value = trim_ascii_ows(line.substr(colon + 1U));
    if (name.empty())
      return Result<std::size_t>::failure({ErrorCode::corrupt});

    if (ascii_iequals(name, "Content-Length")) {
      if (content_length.has_value())
        return Result<std::size_t>::failure({ErrorCode::corrupt});
      if (value.empty())
        return Result<std::size_t>::failure({ErrorCode::corrupt});
      for (const char ch : value) {
        if (ch < '0' || ch > '9')
          return Result<std::size_t>::failure({ErrorCode::corrupt});
      }
      std::uint64_t parsed = 0;
      const auto res =
          std::from_chars(value.data(), value.data() + value.size(), parsed);
      if (res.ec != std::errc{} || res.ptr != value.data() + value.size())
        return Result<std::size_t>::failure({ErrorCode::corrupt});
      if (parsed == 0U)
        return Result<std::size_t>::failure({ErrorCode::corrupt});
      if (parsed > static_cast<std::uint64_t>(max_payload_bytes))
        return Result<std::size_t>::failure({ErrorCode::capacity});
      content_length = static_cast<std::size_t>(parsed);
    }
  }

  if (!content_length.has_value())
    return Result<std::size_t>::failure({ErrorCode::corrupt});
  return Result<std::size_t>::success(content_length.value());
}

} // namespace

// ---------------------------------------------------------------------------
// Public pure UTF-8 <-> UTF-16 / LSP column helpers
// ---------------------------------------------------------------------------

Result<std::uint32_t> utf8_byte_offset_to_utf16_column(std::string_view line_utf8,
                                                       std::size_t byte_offset) {
  if (byte_offset > line_utf8.size() || !valid_utf8(line_utf8))
    return Result<std::uint32_t>::failure({ErrorCode::invalid_range});

  std::size_t pos = 0;
  std::uint64_t utf16_units = 0;
  while (pos < byte_offset) {
    const auto decoded = decode_utf8_scalar(line_utf8, pos);
    if (!decoded.has_value())
      return Result<std::uint32_t>::failure({ErrorCode::corrupt});
    if (pos + decoded.value().byte_len > byte_offset) {
      // byte_offset landed in the middle of a multi-byte UTF-8 code point.
      return Result<std::uint32_t>::failure({ErrorCode::invalid_range});
    }
    utf16_units += (decoded.value().scalar >= 0x10000U) ? 2U : 1U;
    pos += decoded.value().byte_len;
  }

  if (utf16_units >
      static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
    return Result<std::uint32_t>::failure({ErrorCode::overflow});
  return Result<std::uint32_t>::success(static_cast<std::uint32_t>(utf16_units));
}

Result<std::size_t> utf16_column_to_utf8_byte_offset(std::string_view line_utf8,
                                                     std::uint32_t utf16_column) {
  if (!valid_utf8(line_utf8))
    return Result<std::size_t>::failure({ErrorCode::corrupt});

  std::size_t pos = 0;
  std::uint64_t utf16_units = 0;
  while (utf16_units < static_cast<std::uint64_t>(utf16_column)) {
    if (pos >= line_utf8.size())
      return Result<std::size_t>::failure({ErrorCode::invalid_range});
    const auto decoded = decode_utf8_scalar(line_utf8, pos);
    if (!decoded.has_value())
      return Result<std::size_t>::failure({ErrorCode::corrupt});
    const std::uint64_t step = (decoded.value().scalar >= 0x10000U) ? 2U : 1U;
    if (utf16_units + step > static_cast<std::uint64_t>(utf16_column)) {
      // utf16_column landed in the middle of a surrogate pair.
      return Result<std::size_t>::failure({ErrorCode::invalid_range});
    }
    utf16_units += step;
    pos += decoded.value().byte_len;
  }
  return Result<std::size_t>::success(pos);
}

Result<std::uint32_t> utf8_byte_offset_to_lsp_column(std::string_view line_utf8,
                                                     std::size_t byte_offset,
                                                     LspPositionEncoding encoding) {
  if (byte_offset > line_utf8.size() || !valid_utf8(line_utf8))
    return Result<std::uint32_t>::failure({ErrorCode::invalid_range});

  if (encoding == LspPositionEncoding::utf8) {
    // Ensure byte_offset is on a UTF-8 code point boundary.
    if (byte_offset < line_utf8.size() &&
        (static_cast<unsigned char>(line_utf8[byte_offset]) & 0xC0U) == 0x80U) {
      return Result<std::uint32_t>::failure({ErrorCode::invalid_range});
    }
    if (byte_offset >
        static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
      return Result<std::uint32_t>::failure({ErrorCode::overflow});
    return Result<std::uint32_t>::success(static_cast<std::uint32_t>(byte_offset));
  }

  if (encoding == LspPositionEncoding::utf16)
    return utf8_byte_offset_to_utf16_column(line_utf8, byte_offset);

  // UTF-32: count Unicode scalar values.
  std::size_t pos = 0;
  std::uint64_t scalars = 0;
  while (pos < byte_offset) {
    const auto decoded = decode_utf8_scalar(line_utf8, pos);
    if (!decoded.has_value())
      return Result<std::uint32_t>::failure({ErrorCode::corrupt});
    if (pos + decoded.value().byte_len > byte_offset)
      return Result<std::uint32_t>::failure({ErrorCode::invalid_range});
    ++scalars;
    pos += decoded.value().byte_len;
  }
  if (scalars > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
    return Result<std::uint32_t>::failure({ErrorCode::overflow});
  return Result<std::uint32_t>::success(static_cast<std::uint32_t>(scalars));
}

Result<std::size_t> lsp_column_to_utf8_byte_offset(std::string_view line_utf8,
                                                   std::uint32_t lsp_column,
                                                   LspPositionEncoding encoding) {
  if (!valid_utf8(line_utf8))
    return Result<std::size_t>::failure({ErrorCode::corrupt});

  if (encoding == LspPositionEncoding::utf8) {
    if (static_cast<std::size_t>(lsp_column) > line_utf8.size())
      return Result<std::size_t>::failure({ErrorCode::invalid_range});
    if (static_cast<std::size_t>(lsp_column) < line_utf8.size() &&
        (static_cast<unsigned char>(line_utf8[lsp_column]) & 0xC0U) == 0x80U) {
      return Result<std::size_t>::failure({ErrorCode::invalid_range});
    }
    return Result<std::size_t>::success(static_cast<std::size_t>(lsp_column));
  }

  if (encoding == LspPositionEncoding::utf16)
    return utf16_column_to_utf8_byte_offset(line_utf8, lsp_column);

  // UTF-32: advance lsp_column Unicode scalar values.
  std::size_t pos = 0;
  for (std::uint32_t i = 0; i < lsp_column; ++i) {
    if (pos >= line_utf8.size())
      return Result<std::size_t>::failure({ErrorCode::invalid_range});
    const auto decoded = decode_utf8_scalar(line_utf8, pos);
    if (!decoded.has_value())
      return Result<std::size_t>::failure({ErrorCode::corrupt});
    pos += decoded.value().byte_len;
  }
  return Result<std::size_t>::success(pos);
}

// ---------------------------------------------------------------------------
// Public URI <-> workspace path helpers
// ---------------------------------------------------------------------------

Result<std::string> path_to_file_uri(const fs::path &absolute_path) {
  const std::string native = absolute_path.string();
  if (native.empty() || !absolute_path.is_absolute() || !valid_utf8_no_nul(native) ||
      has_ascii_control(native)) {
    return Result<std::string>::failure({ErrorCode::invalid_range});
  }

  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string uri = "file://";
  uri.reserve(uri.size() + native.size());
  for (const char ch : native) {
    const auto byte = static_cast<unsigned char>(ch);
    if (is_unreserved_uri_byte(byte)) {
      uri.push_back(ch);
    } else {
      uri.push_back('%');
      uri.push_back(kHex[byte >> 4U]);
      uri.push_back(kHex[byte & 0x0FU]);
    }
  }
  return Result<std::string>::success(std::move(uri));
}

Result<fs::path> resolve_workspace_file_uri(const LspWorkspaceUriInput &input) {
  auto root = canonicalize_workspace_root(input.workspace_root);
  if (!root.has_value())
    return Result<fs::path>::failure(root.error());

  const std::string_view uri = input.uri;
  if (uri.size() < 8U || has_ascii_control(uri) || !valid_utf8_no_nul(uri))
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  if (!ascii_iequals(uri.substr(0, 7U), "file://"))
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  const std::string_view rest = uri.substr(7U);
  const std::size_t slash = rest.find('/');
  if (slash == std::string_view::npos)
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  const std::string_view authority = rest.substr(0, slash);
  if (!authority.empty() && !ascii_iequals(authority, "localhost"))
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  const std::string_view raw_path = rest.substr(slash);
  if (raw_path.find('?') != std::string_view::npos ||
      raw_path.find('#') != std::string_view::npos) {
    return Result<fs::path>::failure({ErrorCode::invalid_range});
  }

  std::string decoded;
  decoded.reserve(raw_path.size());
  for (std::size_t i = 0; i < raw_path.size(); ++i) {
    if (raw_path[i] == '%') {
      if (i + 2U >= raw_path.size())
        return Result<fs::path>::failure({ErrorCode::invalid_range});
      const int hi = hex_nibble(raw_path[i + 1U]);
      const int lo = hex_nibble(raw_path[i + 2U]);
      if (hi < 0 || lo < 0)
        return Result<fs::path>::failure({ErrorCode::invalid_range});
      const auto byte = static_cast<unsigned char>((hi << 4) | lo);
      if (byte < 0x20U || byte == 0x7FU)
        return Result<fs::path>::failure({ErrorCode::invalid_range});
      decoded.push_back(static_cast<char>(byte));
      i += 2U;
    } else {
      decoded.push_back(raw_path[i]);
    }
  }

  if (decoded.empty() || decoded.front() != '/' || !valid_utf8_no_nul(decoded) ||
      has_ascii_control(decoded)) {
    return Result<fs::path>::failure({ErrorCode::invalid_range});
  }

  // Reject any lexical ".." segment in the decoded path before touching filesystem.
  std::size_t seg_start = 0;
  while (seg_start <= decoded.size()) {
    const std::size_t next_slash = decoded.find('/', seg_start);
    const std::string_view seg =
        (next_slash == std::string::npos)
            ? std::string_view{decoded}.substr(seg_start)
            : std::string_view{decoded}.substr(seg_start, next_slash - seg_start);
    if (seg == "..")
      return Result<fs::path>::failure({ErrorCode::invalid_range});
    if (next_slash == std::string::npos)
      break;
    seg_start = next_slash + 1U;
  }

  auto resolved = resolve_existing_prefix(fs::path{decoded});
  if (!resolved.has_value())
    return Result<fs::path>::failure(resolved.error());
  if (!path_within_root({resolved.value(), root.value()}))
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  return resolved;
}

// ---------------------------------------------------------------------------
// LspClient::Impl
// ---------------------------------------------------------------------------

struct LspClient::Impl {
  LspTransportKind kind = LspTransportKind::attached_fds;
  fs::path workspace_root;
  std::size_t max_payload_bytes = kLspDefaultMaxPayloadBytes;
  LspTimeouts timeouts{};

  // Transport FDs. If shared_single_fd == true, write_fd_raw == read_fd.get() and only
  // read_fd owns the descriptor to guarantee zero double-close.
  OwnedFd owned_read_fd;
  OwnedFd owned_write_fd;
  int read_fd_raw = -1;
  int write_fd_raw = -1;
  bool close_fds = true;
  bool allow_protocol_shutdown = false;

  // Owned child process state (only for stdio_spawn).
  pid_t child_pid = -1;
  bool owns_child = false;
  bool child_reaped = true;

  bool initialized = false;
  LspPositionEncoding position_encoding = LspPositionEncoding::utf16;
  std::int64_t next_request_id = 1;

  // Partial-read buffer with monotonic read offset to avoid O(N^2) erase.
  std::string recv_buf;
  std::size_t recv_offset = 0;

  // Out-of-order response cache keyed by int/string RPC ID.
  std::map<RpcIdKey, Value> pending_responses;

  // Cached textDocument/publishDiagnostics keyed by canonical path string.
  std::map<std::string, LspPublishedDiagnostics> diagnostics_cache;

  // In-memory open document snapshots (updated on did_open / did_change / did_close)
  // so rename() previews match active editor buffers without touching disk.
  std::map<std::string, std::string> open_documents;

  std::string last_error;
  std::size_t rejected_server_requests = 0;
  std::size_t dropped_diagnostics = 0;

  ~Impl() { close_transport_and_reap(); }

  bool is_open() const noexcept { return read_fd_raw >= 0 && write_fd_raw >= 0; }

  void close_fds_only() noexcept {
    if (close_fds) {
      owned_write_fd.reset();
      owned_read_fd.reset();
    } else {
      (void)owned_write_fd.release();
      (void)owned_read_fd.release();
    }
    read_fd_raw = -1;
    write_fd_raw = -1;
  }

  void close_write_fd_only() noexcept {
    if (write_fd_raw < 0)
      return;
    if (write_fd_raw == read_fd_raw) {
      // Bidirectional socket: half-close write direction if socket, else close.
      (void)::shutdown(write_fd_raw, SHUT_WR);
      write_fd_raw = -1;
      return;
    }
    if (close_fds)
      owned_write_fd.reset();
    else
      (void)owned_write_fd.release();
    write_fd_raw = -1;
  }

  bool poll_reap_child(std::chrono::milliseconds grace) noexcept {
    if (!owns_child || child_reaped || child_pid <= 0)
      return true;
    const auto deadline = Clock::now() + std::max(grace, std::chrono::milliseconds{0});
    while (true) {
      int status = 0;
      const pid_t rc = ::waitpid(child_pid, &status, WNOHANG);
      if (rc == child_pid || (rc < 0 && errno == ECHILD)) {
        child_reaped = true;
        child_pid = -1;
        return true;
      }
      if (rc < 0 && errno == EINTR)
        continue;
      if (Clock::now() >= deadline)
        return false;
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
  }

  void signal_child_group(int sig) const noexcept {
    if (child_pid <= 0)
      return;
    if (::kill(-child_pid, sig) < 0 && errno == ESRCH)
      (void)::kill(child_pid, sig);
  }

  void stop_owned_child() noexcept {
    if (!owns_child || child_reaped || child_pid <= 0)
      return;

    // Give child a chance to exit cleanly after EOF on stdin.
    if (poll_reap_child(timeouts.shutdown_grace))
      return;

    // Escalate to SIGTERM.
    signal_child_group(SIGTERM);
    if (poll_reap_child(timeouts.term_grace))
      return;

    // Final escalation to SIGKILL and blocking reap (never leave a zombie).
    signal_child_group(SIGKILL);
    int status = 0;
    pid_t rc = 0;
    do {
      rc = ::waitpid(child_pid, &status, 0);
    } while (rc < 0 && errno == EINTR);
    child_reaped = true;
    child_pid = -1;
  }

  void close_transport_and_reap() noexcept {
    close_fds_only();
    if (owns_child)
      stop_owned_child();
    initialized = false;
  }

  Result<void> write_all_with_deadline(std::string_view bytes,
                                       Clock::time_point deadline) {
    if (write_fd_raw < 0) {
      last_error = "transport write descriptor is closed";
      return Result<void>::failure({ErrorCode::io, EBADF});
    }
#ifndef F_SETNOSIGPIPE
    ThreadSigpipeGuard sigpipe_guard;
#endif
    std::size_t written = 0;
    while (written < bytes.size()) {
      const int wait_ms = poll_timeout_ms(deadline);
      if (wait_ms <= 0) {
        last_error = "timed out waiting to write to LSP transport";
        return Result<void>::failure({ErrorCode::io, ETIMEDOUT});
      }
      pollfd pfd{};
      pfd.fd = write_fd_raw;
      pfd.events = POLLOUT;
      const int prc = ::poll(&pfd, 1, wait_ms);
      if (prc < 0) {
        if (errno == EINTR)
          continue;
        const int err = errno;
        last_error = "poll(POLLOUT) failed on LSP transport";
        return Result<void>::failure({ErrorCode::io, err});
      }
      if (prc == 0) {
        last_error = "timed out waiting to write to LSP transport";
        return Result<void>::failure({ErrorCode::io, ETIMEDOUT});
      }
      if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 &&
          (pfd.revents & POLLOUT) == 0) {
        last_error = "LSP transport peer closed during write";
        close_fds_only();
        return Result<void>::failure({ErrorCode::io, EPIPE});
      }

      const ssize_t n =
          ::write(write_fd_raw, bytes.data() + written, bytes.size() - written);
      if (n < 0) {
        if (errno == EINTR)
          continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          continue;
        const int err = errno;
        last_error = "write failed on LSP transport";
        if (err == EPIPE || err == ECONNRESET || err == EBADF)
          close_fds_only();
        return Result<void>::failure({ErrorCode::io, err});
      }
      if (n == 0) {
        last_error = "zero-byte write on LSP transport";
        close_fds_only();
        return Result<void>::failure({ErrorCode::io, EPIPE});
      }
      written += static_cast<std::size_t>(n);
    }
    return Result<void>::success();
  }

  Result<void> send_frame(const Value &message, Clock::time_point deadline) {
    ValueLimits limits{};
    limits.bytes = max_payload_bytes;
    auto body = dump_json(message, limits);
    if (!body.has_value()) {
      last_error = "failed to serialize outgoing JSON-RPC frame";
      return Result<void>::failure(body.error());
    }
    if (body.value().size() > max_payload_bytes) {
      last_error = "outgoing JSON-RPC payload exceeds max_payload_bytes";
      return Result<void>::failure({ErrorCode::capacity});
    }

    std::string frame;
    frame.reserve(40U + body.value().size());
    frame.append("Content-Length: ");
    frame.append(std::to_string(body.value().size()));
    frame.append("\r\n\r\n");
    frame.append(body.value());
    return write_all_with_deadline(frame, deadline);
  }

  std::string_view buffered_view() const noexcept {
    return std::string_view{recv_buf}.substr(recv_offset);
  }

  void consume_buffered(std::size_t count) {
    recv_offset += count;
    if (recv_offset == recv_buf.size()) {
      recv_buf.clear();
      recv_offset = 0;
    } else if (recv_offset >= kRecvCompactThreshold &&
               recv_offset * 2U >= recv_buf.size()) {
      recv_buf.erase(0, recv_offset);
      recv_offset = 0;
    }
  }

  Result<bool> read_some_with_deadline(Clock::time_point deadline) {
    if (read_fd_raw < 0) {
      last_error = "transport read descriptor is closed";
      return Result<bool>::failure({ErrorCode::io, EBADF});
    }
    while (true) {
      const int wait_ms = poll_timeout_ms(deadline);
      pollfd pfd{};
      pfd.fd = read_fd_raw;
      pfd.events = POLLIN;
      const int prc = ::poll(&pfd, 1, wait_ms);
      if (prc < 0) {
        if (errno == EINTR)
          continue;
        const int err = errno;
        last_error = "poll(POLLIN) failed on LSP transport";
        return Result<bool>::failure({ErrorCode::io, err});
      }
      if (prc == 0) {
        last_error = "timed out waiting for LSP server frame";
        return Result<bool>::failure({ErrorCode::io, ETIMEDOUT});
      }
      if ((pfd.revents & POLLNVAL) != 0) {
        last_error = "invalid LSP transport descriptor";
        close_fds_only();
        return Result<bool>::failure({ErrorCode::io, EBADF});
      }

      std::array<char, kRecvChunkBytes> chunk{};
      const ssize_t n = ::read(read_fd_raw, chunk.data(), chunk.size());
      if (n < 0) {
        if (errno == EINTR)
          continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          if (Clock::now() >= deadline) {
            last_error = "timed out waiting for LSP server frame";
            return Result<bool>::failure({ErrorCode::io, ETIMEDOUT});
          }
          continue;
        }
        const int err = errno;
        last_error = "read failed on LSP transport";
        close_fds_only();
        return Result<bool>::failure({ErrorCode::io, err});
      }
      if (n == 0) {
        last_error = "LSP server closed connection (EOF)";
        close_fds_only();
        return Result<bool>::success(false);
      }
      recv_buf.append(chunk.data(), static_cast<std::size_t>(n));
      return Result<bool>::success(true);
    }
  }

  bool has_complete_buffered_frame() const noexcept {
    const std::string_view view = buffered_view();
    const std::size_t header_end = view.find("\r\n\r\n");
    if (header_end == std::string_view::npos || header_end > kLspMaxHeaderBytes)
      return false;
    const auto content_length =
        parse_content_length_headers(view.substr(0, header_end), max_payload_bytes);
    if (!content_length.has_value())
      return false;
    return view.size() >= header_end + 4U + content_length.value();
  }

  Result<Value> read_frame(Clock::time_point deadline) {
    // 1. Read until "\r\n\r\n" header terminator (bounded by kLspMaxHeaderBytes).
    std::size_t header_end = std::string_view::npos;
    while (true) {
      const std::string_view view = buffered_view();
      header_end = view.find("\r\n\r\n");
      if (header_end != std::string_view::npos) {
        if (header_end > kLspMaxHeaderBytes) {
          last_error = "LSP header block exceeds kLspMaxHeaderBytes";
          close_fds_only();
          return Result<Value>::failure({ErrorCode::capacity});
        }
        break;
      }
      if (view.size() > kLspMaxHeaderBytes) {
        last_error = "LSP header block exceeds kLspMaxHeaderBytes without terminator";
        close_fds_only();
        return Result<Value>::failure({ErrorCode::capacity});
      }
      auto got = read_some_with_deadline(deadline);
      if (!got.has_value())
        return Result<Value>::failure(got.error());
      if (!got.value())
        return Result<Value>::failure({ErrorCode::incomplete});
    }

    const std::string_view header_block = buffered_view().substr(0, header_end);
    auto content_length = parse_content_length_headers(header_block, max_payload_bytes);
    if (!content_length.has_value()) {
      last_error = (content_length.error().code == ErrorCode::capacity)
                       ? "LSP frame Content-Length exceeds max_payload_bytes"
                       : "malformed LSP Content-Length header";
      close_fds_only();
      return Result<Value>::failure(content_length.error());
    }

    const std::size_t needed = content_length.value();
    const std::size_t body_offset = header_end + 4U;
    const std::size_t total_frame_bytes = body_offset + needed;

    // 2. Read exact `needed` payload bytes BEFORE consuming the header so a
    // mid-payload timeout leaves the entire frame intact for the next read.
    while (buffered_view().size() < total_frame_bytes) {
      auto got = read_some_with_deadline(deadline);
      if (!got.has_value())
        return Result<Value>::failure(got.error());
      if (!got.value())
        return Result<Value>::failure({ErrorCode::incomplete});
    }

    const std::string_view payload = buffered_view().substr(body_offset, needed);
    ValueLimits limits{};
    limits.bytes = max_payload_bytes;
    auto parsed = parse_json(payload, limits);
    consume_buffered(total_frame_bytes);
    if (!parsed.has_value()) {
      last_error = "failed to parse incoming JSON-RPC payload";
      return Result<Value>::failure(parsed.error());
    }
    if (!is_object(parsed.value())) {
      last_error = "incoming JSON-RPC frame is not a JSON object";
      return Result<Value>::failure({ErrorCode::corrupt});
    }
    return parsed;
  }

  void handle_publish_diagnostics(const Value &params) {
    if (!is_object(params)) {
      ++dropped_diagnostics;
      return;
    }
    const Value *uri_val = params.find("uri");
    const Value *diags_val = params.find("diagnostics");
    if (uri_val == nullptr || !is_string(*uri_val) || diags_val == nullptr ||
        !is_array(*diags_val)) {
      ++dropped_diagnostics;
      return;
    }

    auto resolved = resolve_workspace_file_uri({workspace_root, uri_val->string()});
    if (!resolved.has_value()) {
      // Never cache diagnostics pointing outside workspace_root.
      ++dropped_diagnostics;
      return;
    }

    LspPublishedDiagnostics entry;
    entry.path = resolved.value();
    entry.uri = uri_val->string();
    if (const Value *ver_val = params.find("version"); ver_val != nullptr) {
      if (const auto ver = parse_int64(*ver_val); ver.has_value())
        entry.version = ver.value();
    }

    const auto &arr = diags_val->array();
    const std::size_t count = std::min(arr.size(), kMaxDiagnosticsPerUri);
    entry.diagnostics.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      const Value &d = arr[i];
      if (!is_object(d))
        continue;
      const Value *range_val = d.find("range");
      const Value *msg_val = d.find("message");
      if (range_val == nullptr || msg_val == nullptr || !is_string(*msg_val))
        continue;
      auto range = parse_range(*range_val);
      if (!range.has_value())
        continue;

      LspDiagnostic diag;
      diag.range = range.value();
      diag.message = msg_val->string();
      if (const Value *sev = d.find("severity"); sev != nullptr) {
        if (const auto s = parse_uint32(*sev); s.has_value())
          diag.severity = s.value();
      }
      if (const Value *src = d.find("source"); src != nullptr && is_string(*src))
        diag.source = src->string();
      if (const Value *code = d.find("code"); code != nullptr) {
        if (is_string(*code))
          diag.code = code->string();
        else if (is_number(*code))
          diag.code = code->number().text();
      }
      entry.diagnostics.push_back(std::move(diag));
    }

    const std::string key = entry.path.string();
    if (!diagnostics_cache.contains(key) &&
        diagnostics_cache.size() >= kMaxCachedDiagnosticUris) {
      ++dropped_diagnostics;
      return;
    }
    diagnostics_cache[key] = std::move(entry);
  }

  Result<void> respond_method_not_found(const Value &id, std::string_view method,
                                        Clock::time_point deadline) {
    ++rejected_server_requests;
    std::string msg = "Method not found: ";
    msg.append(method);
    Value err_resp = Value::object({
        {"jsonrpc", Value{"2.0"}},
        {"id", id},
        {"error", Value::object({
                      {"code", Value{Number{kLspJsonRpcMethodNotFound}}},
                      {"message", Value{std::move(msg)}},
                  })},
    });
    return send_frame(err_resp, deadline);
  }

  // Dispatches a non-response incoming message (server request or notification).
  // Returns true if the message was a response (and stored/returned via
  // `out_response_id`), false if it was a server request or notification.
  Result<bool> dispatch_incoming_message(Value msg, Clock::time_point deadline,
                                         std::optional<RpcIdKey> *out_response_id,
                                         Value *out_response_msg) {
    const Value *method_val = msg.find("method");
    const Value *id_val = msg.find("id");

    if (method_val != nullptr && is_string(*method_val)) {
      if (id_val != nullptr) {
        // Server-initiated request: immediately respond with -32601 MethodNotFound
        // so server never deadlocks and workspace/applyEdit is never auto-applied.
        auto reply = respond_method_not_found(*id_val, method_val->string(), deadline);
        if (!reply.has_value())
          return Result<bool>::failure(reply.error());
        return Result<bool>::success(false);
      }

      // Notification from server.
      if (method_val->string() == "textDocument/publishDiagnostics") {
        if (const Value *params = msg.find("params"); params != nullptr)
          handle_publish_diagnostics(*params);
      }
      return Result<bool>::success(false);
    }

    // Response frame: must have id and either result or error.
    if (id_val == nullptr) {
      last_error = "incoming JSON-RPC message missing both method and id";
      return Result<bool>::failure({ErrorCode::corrupt});
    }
    const auto key = parse_rpc_id_key(*id_val);
    if (!key.has_value()) {
      last_error = "incoming JSON-RPC response has non-int/non-string id";
      return Result<bool>::failure({ErrorCode::corrupt});
    }
    if (out_response_id != nullptr)
      *out_response_id = key.value();
    if (out_response_msg != nullptr)
      *out_response_msg = std::move(msg);
    return Result<bool>::success(true);
  }

  Result<Value> unwrap_rpc_response(const Value &response) {
    if (const Value *err_val = response.find("error");
        err_val != nullptr && !is_null(*err_val)) {
      std::int64_t code = 0;
      std::string message = "LSP server returned JSON-RPC error";
      if (is_object(*err_val)) {
        if (const Value *c = err_val->find("code"); c != nullptr) {
          if (const auto parsed = parse_int64(*c); parsed.has_value())
            code = parsed.value();
        }
        if (const Value *m = err_val->find("message"); m != nullptr && is_string(*m))
          message = m->string();
      }
      last_error = std::move(message);
      return Result<Value>::failure({ErrorCode::external_unknown, code});
    }
    if (const Value *res_val = response.find("result"); res_val != nullptr)
      return Result<Value>::success(*res_val);
    return Result<Value>::success(Value{nullptr});
  }

  Result<void> send_request_with_id_impl(const LspRequestId &id,
                                         std::string_view method, Value params) {
    if (!is_open()) {
      last_error = "LSP transport is not open";
      return Result<void>::failure({ErrorCode::io, EBADF});
    }
    if (method.empty() || !valid_utf8_no_nul(method))
      return Result<void>::failure({ErrorCode::invalid_range});
    if (const auto *s = std::get_if<std::string>(&id.value)) {
      if (s->empty() || !valid_utf8_no_nul(*s))
        return Result<void>::failure({ErrorCode::invalid_range});
    }

    Value msg = Value::object({
        {"jsonrpc", Value{"2.0"}},
        {"id", serialize_rpc_id(id)},
        {"method", Value{std::string{method}}},
        {"params", std::move(params)},
    });
    const auto deadline = Clock::now() + timeouts.request;
    return send_frame(msg, deadline);
  }

  Result<Value> wait_for_response_impl(const LspRequestId &id) {
    const RpcIdKey target = to_rpc_id_key(id);
    if (const auto it = pending_responses.find(target); it != pending_responses.end()) {
      Value cached = std::move(it->second);
      pending_responses.erase(it);
      return unwrap_rpc_response(cached);
    }

    if (!is_open()) {
      last_error = "LSP transport is not open";
      return Result<Value>::failure({ErrorCode::io, EBADF});
    }

    const auto deadline = Clock::now() + timeouts.request;
    while (true) {
      auto frame = read_frame(deadline);
      if (!frame.has_value())
        return Result<Value>::failure(frame.error());

      std::optional<RpcIdKey> resp_id;
      Value resp_msg;
      auto dispatched = dispatch_incoming_message(std::move(frame).value(), deadline,
                                                  &resp_id, &resp_msg);
      if (!dispatched.has_value())
        return Result<Value>::failure(dispatched.error());
      if (!dispatched.value() || !resp_id.has_value())
        continue;

      if (resp_id.value() == target)
        return unwrap_rpc_response(resp_msg);

      if (pending_responses.size() >= kMaxPendingResponses) {
        last_error = "too many unmatched out-of-order LSP responses buffered";
        return Result<Value>::failure({ErrorCode::capacity});
      }
      pending_responses.insert_or_assign(resp_id.value(), std::move(resp_msg));
    }
  }

  Result<Value> request_impl(std::string_view method, Value params) {
    const LspRequestId id{next_request_id++};
    auto sent = send_request_with_id_impl(id, method, std::move(params));
    if (!sent.has_value())
      return Result<Value>::failure(sent.error());
    return wait_for_response_impl(id);
  }

  Result<void> notify_impl(std::string_view method, Value params) {
    if (!is_open()) {
      last_error = "LSP transport is not open";
      return Result<void>::failure({ErrorCode::io, EBADF});
    }
    if (method.empty() || !valid_utf8_no_nul(method))
      return Result<void>::failure({ErrorCode::invalid_range});

    Value msg = Value::object({
        {"jsonrpc", Value{"2.0"}},
        {"method", Value{std::string{method}}},
        {"params", std::move(params)},
    });
    const auto deadline = Clock::now() + timeouts.request;
    return send_frame(msg, deadline);
  }

  Result<std::pair<fs::path, std::string>>
  resolve_and_encode_workspace_path(const fs::path &path) {
    auto resolved = resolve_workspace_path_impl(workspace_root, path);
    if (!resolved.has_value()) {
      last_error = "path is outside workspace_root or invalid";
      return Result<std::pair<fs::path, std::string>>::failure(resolved.error());
    }
    auto uri = path_to_file_uri(resolved.value());
    if (!uri.has_value())
      return Result<std::pair<fs::path, std::string>>::failure(uri.error());
    return Result<std::pair<fs::path, std::string>>::success(
        {std::move(resolved).value(), std::move(uri).value()});
  }
};

// ---------------------------------------------------------------------------
// LspClient lifecycle & factories
// ---------------------------------------------------------------------------

LspClient::LspClient(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
LspClient::LspClient(LspClient &&) noexcept = default;
LspClient &LspClient::operator=(LspClient &&) noexcept = default;
LspClient::~LspClient() = default;

Result<LspClient> LspClient::spawn_stdio(const LspStdioSpawnConfig &config) {
  auto root = canonicalize_workspace_root(config.workspace_root);
  if (!root.has_value())
    return Result<LspClient>::failure(root.error());

  if (config.max_payload_bytes == 0U ||
      config.max_payload_bytes > kLspMaxPayloadBytesLimit) {
    return Result<LspClient>::failure({ErrorCode::invalid_range});
  }

  const std::string exec_str = config.executable.string();
  if (exec_str.empty() || !config.executable.is_absolute() ||
      !valid_utf8_no_nul(exec_str)) {
    return Result<LspClient>::failure({ErrorCode::invalid_range});
  }
  std::error_code ec;
  if (!fs::is_regular_file(config.executable, ec) || ec ||
      ::access(exec_str.c_str(), X_OK) != 0) {
    return Result<LspClient>::failure({ErrorCode::io, errno});
  }

  for (const auto &arg : config.arguments) {
    if (!valid_utf8_no_nul(arg))
      return Result<LspClient>::failure({ErrorCode::invalid_range});
  }
  for (const auto &env_entry : config.environment) {
    if (env_entry.empty() || !valid_utf8_no_nul(env_entry) ||
        env_entry.find('=') == std::string::npos) {
      return Result<LspClient>::failure({ErrorCode::invalid_range});
    }
  }

  std::array<int, 2> to_child_raw{-1, -1};
  std::array<int, 2> from_child_raw{-1, -1};
  if (::pipe(to_child_raw.data()) != 0)
    return Result<LspClient>::failure({ErrorCode::io, errno});
  OwnedFd to_child_r{to_child_raw[0]};
  OwnedFd to_child_w{to_child_raw[1]};

  if (::pipe(from_child_raw.data()) != 0)
    return Result<LspClient>::failure({ErrorCode::io, errno});
  OwnedFd from_child_r{from_child_raw[0]};
  OwnedFd from_child_w{from_child_raw[1]};

  if (!set_fd_cloexec(to_child_r.get()) || !set_fd_cloexec(to_child_w.get()) ||
      !set_fd_cloexec(from_child_r.get()) || !set_fd_cloexec(from_child_w.get())) {
    return Result<LspClient>::failure({ErrorCode::io, errno});
  }

  // Ensure none of the pipe descriptors occupy 0/1/2 so adddup2 always clears CLOEXEC.
  if (!move_fd_above_stdio(to_child_r) || !move_fd_above_stdio(to_child_w) ||
      !move_fd_above_stdio(from_child_r) || !move_fd_above_stdio(from_child_w)) {
    return Result<LspClient>::failure({ErrorCode::io, errno});
  }

  if (!set_fd_nonblock(to_child_w.get()) || !set_fd_nonblock(from_child_r.get()))
    return Result<LspClient>::failure({ErrorCode::io, errno});
  set_fd_nosigpipe(to_child_w.get());

  std::vector<std::string> argv_storage;
  argv_storage.reserve(1U + config.arguments.size());
  argv_storage.push_back(exec_str);
  for (const auto &arg : config.arguments)
    argv_storage.push_back(arg);
  std::vector<char *> argv;
  argv.reserve(argv_storage.size() + 1U);
  for (auto &arg : argv_storage)
    argv.push_back(arg.data());
  argv.push_back(nullptr);

  std::vector<std::string> env_storage = config.environment;
  std::vector<char *> envp;
  char **spawn_env = environ;
  if (!env_storage.empty()) {
    envp.reserve(env_storage.size() + 1U);
    for (auto &entry : env_storage)
      envp.push_back(entry.data());
    envp.push_back(nullptr);
    spawn_env = envp.data();
  }

  posix_spawn_file_actions_t actions{};
  posix_spawnattr_t attr{};
  int spawn_rc = ::posix_spawn_file_actions_init(&actions);
  if (spawn_rc != 0)
    return Result<LspClient>::failure({ErrorCode::io, spawn_rc});

  pid_t child_pid = -1;
  int attr_rc = ::posix_spawnattr_init(&attr);
  if (attr_rc == 0) {
    sigset_t empty_mask{};
    sigemptyset(&empty_mask);
    sigset_t default_sigs{};
    sigemptyset(&default_sigs);
    sigaddset(&default_sigs, SIGPIPE);
    sigaddset(&default_sigs, SIGTERM);
    sigaddset(&default_sigs, SIGINT);

    short flags =
        POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
    spawn_rc = ::posix_spawnattr_setflags(&attr, flags);
    if (spawn_rc == 0)
      spawn_rc = ::posix_spawnattr_setpgroup(&attr, 0);
    if (spawn_rc == 0)
      spawn_rc = ::posix_spawnattr_setsigmask(&attr, &empty_mask);
    if (spawn_rc == 0)
      spawn_rc = ::posix_spawnattr_setsigdefault(&attr, &default_sigs);
    if (spawn_rc == 0)
      spawn_rc =
          ::posix_spawn_file_actions_adddup2(&actions, to_child_r.get(), STDIN_FILENO);
    if (spawn_rc == 0)
      spawn_rc = ::posix_spawn_file_actions_adddup2(&actions, from_child_w.get(),
                                                    STDOUT_FILENO);
    if (spawn_rc == 0)
      spawn_rc = ::posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
                                                    "/dev/null", O_WRONLY, 0);
    if (spawn_rc == 0) {
      // Strict posix_spawn (never shell, never posix_spawnp).
      spawn_rc = ::posix_spawn(&child_pid, exec_str.c_str(), &actions, &attr,
                               argv.data(), spawn_env);
    }
    (void)::posix_spawnattr_destroy(&attr);
  } else {
    spawn_rc = attr_rc;
  }
  (void)::posix_spawn_file_actions_destroy(&actions);

  if (spawn_rc != 0 || child_pid <= 0)
    return Result<LspClient>::failure({ErrorCode::io, spawn_rc});

  // Close child ends in parent immediately.
  to_child_r.reset();
  from_child_w.reset();

  auto impl = std::make_unique<Impl>();
  impl->kind = LspTransportKind::stdio_spawn;
  impl->workspace_root = std::move(root).value();
  impl->max_payload_bytes = config.max_payload_bytes;
  impl->timeouts = config.timeouts;
  impl->owned_read_fd = std::move(from_child_r);
  impl->owned_write_fd = std::move(to_child_w);
  impl->read_fd_raw = impl->owned_read_fd.get();
  impl->write_fd_raw = impl->owned_write_fd.get();
  impl->close_fds = true;
  impl->allow_protocol_shutdown = true;
  impl->child_pid = child_pid;
  impl->owns_child = true;
  impl->child_reaped = false;
  return Result<LspClient>::success(LspClient{std::move(impl)});
}

Result<LspClient> LspClient::attach_unix_socket(const LspUnixSocketConfig &config) {
  auto root = canonicalize_workspace_root(config.workspace_root);
  if (!root.has_value())
    return Result<LspClient>::failure(root.error());

  if (config.max_payload_bytes == 0U ||
      config.max_payload_bytes > kLspMaxPayloadBytesLimit) {
    return Result<LspClient>::failure({ErrorCode::invalid_range});
  }

  const std::string sock_str = config.socket_path.string();
  if (sock_str.empty() || !valid_utf8_no_nul(sock_str) || has_ascii_control(sock_str))
    return Result<LspClient>::failure({ErrorCode::invalid_range});

  sockaddr_un addr{};
  if (sock_str.size() >= sizeof(addr.sun_path))
    return Result<LspClient>::failure({ErrorCode::invalid_range});
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, sock_str.data(), sock_str.size());
  addr.sun_path[sock_str.size()] = '\0';

  auto connected =
      connect_socket_with_timeout(AF_UNIX, reinterpret_cast<const sockaddr *>(&addr),
                                  sizeof(addr), config.timeouts.connect);
  if (!connected.has_value())
    return Result<LspClient>::failure(connected.error());

  auto impl = std::make_unique<Impl>();
  impl->kind = LspTransportKind::unix_socket;
  impl->workspace_root = std::move(root).value();
  impl->max_payload_bytes = config.max_payload_bytes;
  impl->timeouts = config.timeouts;
  impl->owned_read_fd = std::move(connected).value();
  impl->read_fd_raw = impl->owned_read_fd.get();
  impl->write_fd_raw = impl->owned_read_fd.get();
  impl->close_fds = true;
  // Consumer-only boundary: NEVER terminate external shared daemons.
  impl->allow_protocol_shutdown = false;
  impl->owns_child = false;
  impl->child_reaped = true;
  return Result<LspClient>::success(LspClient{std::move(impl)});
}

Result<LspClient> LspClient::attach_tcp_loopback(const LspTcpLoopbackConfig &config) {
  auto root = canonicalize_workspace_root(config.workspace_root);
  if (!root.has_value())
    return Result<LspClient>::failure(root.error());

  if (config.max_payload_bytes == 0U ||
      config.max_payload_bytes > kLspMaxPayloadBytesLimit || config.port == 0U) {
    return Result<LspClient>::failure({ErrorCode::invalid_range});
  }

  const std::string host_lower = ascii_lower(config.host);
  const bool try_v4 = (host_lower == "127.0.0.1" || host_lower == "localhost");
  const bool try_v6 = (host_lower == "::1" || host_lower == "localhost");
  if (!try_v4 && !try_v6)
    return Result<LspClient>::failure({ErrorCode::invalid_range});

  Result<OwnedFd> connected = Result<OwnedFd>::failure({ErrorCode::io});
  if (try_v4) {
    sockaddr_in addr4{};
    addr4.sin_family = AF_INET;
    addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr4.sin_port = htons(config.port);
    connected =
        connect_socket_with_timeout(AF_INET, reinterpret_cast<const sockaddr *>(&addr4),
                                    sizeof(addr4), config.timeouts.connect);
  }
  if (!connected.has_value() && try_v6) {
    sockaddr_in6 addr6{};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_loopback;
    addr6.sin6_port = htons(config.port);
    connected = connect_socket_with_timeout(AF_INET6,
                                            reinterpret_cast<const sockaddr *>(&addr6),
                                            sizeof(addr6), config.timeouts.connect);
  }
  if (!connected.has_value())
    return Result<LspClient>::failure(connected.error());

  auto impl = std::make_unique<Impl>();
  impl->kind = LspTransportKind::tcp_loopback;
  impl->workspace_root = std::move(root).value();
  impl->max_payload_bytes = config.max_payload_bytes;
  impl->timeouts = config.timeouts;
  impl->owned_read_fd = std::move(connected).value();
  impl->read_fd_raw = impl->owned_read_fd.get();
  impl->write_fd_raw = impl->owned_read_fd.get();
  impl->close_fds = true;
  // Consumer-only boundary: NEVER terminate external shared daemons.
  impl->allow_protocol_shutdown = false;
  impl->owns_child = false;
  impl->child_reaped = true;
  return Result<LspClient>::success(LspClient{std::move(impl)});
}

Result<LspClient> LspClient::attach_fds(const LspAttachedFdsConfig &config) {
  auto root = canonicalize_workspace_root(config.workspace_root);
  if (!root.has_value())
    return Result<LspClient>::failure(root.error());

  if (config.read_fd < 0 || config.write_fd < 0 || config.max_payload_bytes == 0U ||
      config.max_payload_bytes > kLspMaxPayloadBytesLimit) {
    return Result<LspClient>::failure({ErrorCode::invalid_range});
  }

  if (!set_fd_nonblock(config.read_fd))
    return Result<LspClient>::failure({ErrorCode::io, errno});
  if (config.write_fd != config.read_fd && !set_fd_nonblock(config.write_fd))
    return Result<LspClient>::failure({ErrorCode::io, errno});

  set_fd_nosigpipe(config.write_fd);
  set_socket_nosigpipe(config.write_fd);

  auto impl = std::make_unique<Impl>();
  impl->kind = LspTransportKind::attached_fds;
  impl->workspace_root = std::move(root).value();
  impl->max_payload_bytes = config.max_payload_bytes;
  impl->timeouts = config.timeouts;
  impl->close_fds = config.close_fds_on_destroy;
  impl->allow_protocol_shutdown = config.allow_protocol_shutdown;
  if (config.close_fds_on_destroy) {
    impl->owned_read_fd = OwnedFd{config.read_fd};
    if (config.write_fd != config.read_fd)
      impl->owned_write_fd = OwnedFd{config.write_fd};
  }
  impl->read_fd_raw = config.read_fd;
  impl->write_fd_raw = config.write_fd;
  impl->owns_child = false;
  impl->child_reaped = true;
  return Result<LspClient>::success(LspClient{std::move(impl)});
}

// ---------------------------------------------------------------------------
// LspClient observers
// ---------------------------------------------------------------------------

LspTransportKind LspClient::transport_kind() const noexcept {
  return impl_ ? impl_->kind : LspTransportKind::attached_fds;
}
bool LspClient::owns_process() const noexcept { return impl_ && impl_->owns_child; }
bool LspClient::is_open() const noexcept { return impl_ && impl_->is_open(); }
bool LspClient::is_initialized() const noexcept { return impl_ && impl_->initialized; }
LspPositionEncoding LspClient::position_encoding() const noexcept {
  return impl_ ? impl_->position_encoding : LspPositionEncoding::utf16;
}
const fs::path &LspClient::workspace_root() const noexcept {
  static const fs::path empty;
  return impl_ ? impl_->workspace_root : empty;
}
const std::string &LspClient::last_error_detail() const noexcept {
  static const std::string empty;
  return impl_ ? impl_->last_error : empty;
}
std::size_t LspClient::rejected_server_request_count() const noexcept {
  return impl_ ? impl_->rejected_server_requests : 0U;
}
std::size_t LspClient::dropped_diagnostics_count() const noexcept {
  return impl_ ? impl_->dropped_diagnostics : 0U;
}

// ---------------------------------------------------------------------------
// Core lifecycle
// ---------------------------------------------------------------------------

Result<LspInitializeResult> LspClient::initialize() {
  if (!impl_ || !impl_->is_open())
    return Result<LspInitializeResult>::failure({ErrorCode::io, EBADF});

  auto root_uri = path_to_file_uri(impl_->workspace_root);
  if (!root_uri.has_value())
    return Result<LspInitializeResult>::failure(root_uri.error());

  std::string folder_name = impl_->workspace_root.filename().string();
  if (folder_name.empty())
    folder_name = "workspace";

  Value capabilities = Value::object({
      {"general",
       Value::object({
           {"positionEncodings", Value{Value::Array{Value{"utf-8"}, Value{"utf-16"}}}},
       })},
      {"textDocument",
       Value::object({
           {"synchronization", Value::object({
                                   {"didSave", Value{false}},
                                   {"willSave", Value{false}},
                               })},
           {"hover", Value::object({
                         {"contentFormat",
                          Value{Value::Array{Value{"markdown"}, Value{"plaintext"}}}},
                     })},
           {"definition", Value::object({{"linkSupport", Value{true}}})},
           {"references", Value::object({})},
           {"documentSymbol", Value::object({
                                  {"hierarchicalDocumentSymbolSupport", Value{true}},
                              })},
           {"callHierarchy", Value::object({})},
           {"rename", Value::object({{"prepareSupport", Value{true}}})},
           {"publishDiagnostics", Value::object({})},
       })},
      {"workspace",
       Value::object({
           {"symbol", Value::object({})},
           {"workspaceEdit", Value::object({{"documentChanges", Value{true}}})},
       })},
  });

  // Per LSP 3.17, a non-null processId tells the server to exit if this client dies.
  // Consumer-only transports (external Unix/TCP daemons and unowned FDs) MUST send
  // null.
  Value process_id = impl_->owns_child
                         ? Value{Number{static_cast<std::int64_t>(::getpid())}}
                         : Value{nullptr};
  Value params = Value::object({
      {"processId", std::move(process_id)},
      {"clientInfo", Value::object({
                         {"name", Value{"blackbird"}},
                         {"version", Value{"1.0"}},
                     })},
      {"rootUri", Value{root_uri.value()}},
      {"workspaceFolders", Value{Value::Array{Value::object({
                               {"uri", Value{root_uri.value()}},
                               {"name", Value{std::move(folder_name)}},
                           })}}},
      {"capabilities", std::move(capabilities)},
  });

  auto res = impl_->request_impl("initialize", std::move(params));
  if (!res.has_value())
    return Result<LspInitializeResult>::failure(res.error());
  if (!is_object(res.value()))
    return Result<LspInitializeResult>::failure({ErrorCode::corrupt});

  LspInitializeResult out;
  if (const Value *info = res.value().find("serverInfo");
      info != nullptr && is_object(*info)) {
    if (const Value *n = info->find("name"); n != nullptr && is_string(*n))
      out.server_name = n->string();
    if (const Value *v = info->find("version"); v != nullptr && is_string(*v))
      out.server_version = v->string();
  }

  // Per LSP 3.17, default positionEncoding is utf-16 when omitted.
  out.capabilities.position_encoding = LspPositionEncoding::utf16;
  if (const Value *caps = res.value().find("capabilities");
      caps != nullptr && is_object(*caps)) {
    if (const Value *enc = caps->find("positionEncoding");
        enc != nullptr && is_string(*enc)) {
      if (enc->string() == "utf-8") {
        out.capabilities.position_encoding = LspPositionEncoding::utf8;
      } else if (enc->string() == "utf-16") {
        out.capabilities.position_encoding = LspPositionEncoding::utf16;
      } else if (enc->string() == "utf-32") {
        out.capabilities.position_encoding = LspPositionEncoding::utf32;
      } else {
        impl_->last_error = "unsupported server positionEncoding: " + enc->string();
        return Result<LspInitializeResult>::failure({ErrorCode::unsupported});
      }
    }
    out.capabilities.definition_provider =
        capability_enabled(caps->find("definitionProvider"));
    out.capabilities.references_provider =
        capability_enabled(caps->find("referencesProvider"));
    out.capabilities.hover_provider = capability_enabled(caps->find("hoverProvider"));
    out.capabilities.document_symbol_provider =
        capability_enabled(caps->find("documentSymbolProvider"));
    out.capabilities.workspace_symbol_provider =
        capability_enabled(caps->find("workspaceSymbolProvider"));
    out.capabilities.call_hierarchy_provider =
        capability_enabled(caps->find("callHierarchyProvider"));
    const Value *rename_cap = caps->find("renameProvider");
    out.capabilities.rename_provider = capability_enabled(rename_cap);
    if (rename_cap != nullptr && is_object(*rename_cap)) {
      if (const Value *prep = rename_cap->find("prepareProvider");
          prep != nullptr && is_bool(*prep)) {
        out.capabilities.rename_prepare_provider = std::get<bool>(prep->value());
      }
    }
  }

  impl_->position_encoding = out.capabilities.position_encoding;

  auto notified = impl_->notify_impl("initialized", Value::object({}));
  if (!notified.has_value())
    return Result<LspInitializeResult>::failure(notified.error());

  impl_->initialized = true;
  return Result<LspInitializeResult>::success(std::move(out));
}

Result<void> LspClient::shutdown() {
  if (!impl_)
    return Result<void>::success();

  // Consumer-only boundary: external Unix/TCP sockets detach without sending
  // shutdown/exit or signaling any external daemon.
  if (!impl_->allow_protocol_shutdown) {
    impl_->close_fds_only();
    impl_->initialized = false;
    return Result<void>::success();
  }

  Result<void> protocol_status = Result<void>::success();
  if (impl_->is_open()) {
    auto resp = impl_->request_impl("shutdown", Value{nullptr});
    if (!resp.has_value())
      protocol_status = Result<void>::failure(resp.error());
    // Send exit notification regardless (best-effort if peer already hung up).
    if (impl_->is_open())
      (void)impl_->notify_impl("exit", Value{nullptr});
  }

  // Close write pipe first to deliver EOF, then close read pipe and reap owned child.
  impl_->close_write_fd_only();
  impl_->close_transport_and_reap();
  return protocol_status;
}

void LspClient::disconnect() noexcept {
  if (impl_)
    impl_->close_transport_and_reap();
}

// ---------------------------------------------------------------------------
// Document synchronization
// ---------------------------------------------------------------------------

Result<void> LspClient::did_open(const LspDidOpenParams &params) {
  if (!impl_ || !impl_->is_open())
    return Result<void>::failure({ErrorCode::io, EBADF});
  if (!valid_utf8(params.text) || !valid_utf8_no_nul(params.language_id))
    return Result<void>::failure({ErrorCode::invalid_range});

  auto resolved = impl_->resolve_and_encode_workspace_path(params.path);
  if (!resolved.has_value())
    return Result<void>::failure(resolved.error());

  Value rpc_params = Value::object({
      {"textDocument", Value::object({
                           {"uri", Value{resolved.value().second}},
                           {"languageId", Value{params.language_id}},
                           {"version", Value{Number{params.version}}},
                           {"text", Value{params.text}},
                       })},
  });
  auto sent = impl_->notify_impl("textDocument/didOpen", std::move(rpc_params));
  if (!sent.has_value())
    return sent;

  impl_->open_documents[resolved.value().first.string()] = params.text;
  return Result<void>::success();
}

Result<void> LspClient::did_change(const LspDidChangeParams &params) {
  if (!impl_ || !impl_->is_open())
    return Result<void>::failure({ErrorCode::io, EBADF});
  if (params.changes.empty())
    return Result<void>::failure({ErrorCode::invalid_range});

  auto resolved = impl_->resolve_and_encode_workspace_path(params.path);
  if (!resolved.has_value())
    return Result<void>::failure(resolved.error());

  Value::Array content_changes;
  content_changes.reserve(params.changes.size());
  for (const auto &change : params.changes) {
    if (!valid_utf8(change.text))
      return Result<void>::failure({ErrorCode::invalid_range});
    if (change.range.has_value()) {
      if (change.range.value().end < change.range.value().start)
        return Result<void>::failure({ErrorCode::invalid_range});
      content_changes.push_back(Value::object({
          {"range", serialize_range(change.range.value())},
          {"text", Value{change.text}},
      }));
    } else {
      content_changes.push_back(Value::object({
          {"text", Value{change.text}},
      }));
    }
  }

  Value rpc_params = Value::object({
      {"textDocument", Value::object({
                           {"uri", Value{resolved.value().second}},
                           {"version", Value{Number{params.version}}},
                       })},
      {"contentChanges", Value{std::move(content_changes)}},
  });
  auto sent = impl_->notify_impl("textDocument/didChange", std::move(rpc_params));
  if (!sent.has_value())
    return sent;

  // Keep in-memory document snapshot synchronized if this document is tracked.
  const std::string doc_key = resolved.value().first.string();
  if (auto it = impl_->open_documents.find(doc_key);
      it != impl_->open_documents.end()) {
    std::string updated = it->second;
    bool ok = true;
    for (const auto &change : params.changes) {
      if (!change.range.has_value()) {
        updated = change.text;
      } else {
        std::vector<LspTextEdit> single{LspTextEdit{change.range.value(), change.text}};
        auto applied = apply_text_edits_in_memory(updated, single,
                                                  impl_->position_encoding, nullptr);
        if (!applied.has_value()) {
          ok = false;
          break;
        }
        updated = std::move(applied).value();
      }
    }
    if (ok)
      it->second = std::move(updated);
    else
      impl_->open_documents.erase(it);
  }
  return Result<void>::success();
}

Result<void> LspClient::did_close(const fs::path &path) {
  if (!impl_ || !impl_->is_open())
    return Result<void>::failure({ErrorCode::io, EBADF});

  auto resolved = impl_->resolve_and_encode_workspace_path(path);
  if (!resolved.has_value())
    return Result<void>::failure(resolved.error());

  Value rpc_params = Value::object({
      {"textDocument", Value::object({{"uri", Value{resolved.value().second}}})},
  });
  auto sent = impl_->notify_impl("textDocument/didClose", std::move(rpc_params));
  impl_->open_documents.erase(resolved.value().first.string());
  return sent;
}

// ---------------------------------------------------------------------------
// Structural intelligence
// ---------------------------------------------------------------------------

Result<std::vector<LspLocation>>
LspClient::definition(const LspTextDocumentPosition &pos) {
  if (!impl_ || !impl_->is_open())
    return Result<std::vector<LspLocation>>::failure({ErrorCode::io, EBADF});

  auto resolved = impl_->resolve_and_encode_workspace_path(pos.path);
  if (!resolved.has_value())
    return Result<std::vector<LspLocation>>::failure(resolved.error());

  Value params = Value::object({
      {"textDocument", Value::object({{"uri", Value{resolved.value().second}}})},
      {"position", serialize_position(pos.position)},
  });
  auto res = impl_->request_impl("textDocument/definition", std::move(params));
  if (!res.has_value())
    return Result<std::vector<LspLocation>>::failure(res.error());

  std::vector<LspLocation> locations;
  if (is_null(res.value()))
    return Result<std::vector<LspLocation>>::success(std::move(locations));

  if (is_object(res.value())) {
    auto loc = parse_location_in_workspace(impl_->workspace_root, res.value());
    if (!loc.has_value())
      return Result<std::vector<LspLocation>>::failure(loc.error());
    locations.push_back(std::move(loc).value());
    return Result<std::vector<LspLocation>>::success(std::move(locations));
  }

  if (!is_array(res.value()))
    return Result<std::vector<LspLocation>>::failure({ErrorCode::corrupt});
  locations.reserve(res.value().array().size());
  for (const auto &entry : res.value().array()) {
    auto loc = parse_location_in_workspace(impl_->workspace_root, entry);
    if (!loc.has_value())
      return Result<std::vector<LspLocation>>::failure(loc.error());
    locations.push_back(std::move(loc).value());
  }
  return Result<std::vector<LspLocation>>::success(std::move(locations));
}

Result<std::vector<LspLocation>>
LspClient::references(const LspReferencesParams &params) {
  if (!impl_ || !impl_->is_open())
    return Result<std::vector<LspLocation>>::failure({ErrorCode::io, EBADF});

  auto resolved = impl_->resolve_and_encode_workspace_path(params.path);
  if (!resolved.has_value())
    return Result<std::vector<LspLocation>>::failure(resolved.error());

  Value rpc_params = Value::object({
      {"textDocument", Value::object({{"uri", Value{resolved.value().second}}})},
      {"position", serialize_position(params.position)},
      {"context",
       Value::object({{"includeDeclaration", Value{params.include_declaration}}})},
  });
  auto res = impl_->request_impl("textDocument/references", std::move(rpc_params));
  if (!res.has_value())
    return Result<std::vector<LspLocation>>::failure(res.error());

  std::vector<LspLocation> locations;
  if (is_null(res.value()))
    return Result<std::vector<LspLocation>>::success(std::move(locations));
  if (!is_array(res.value()))
    return Result<std::vector<LspLocation>>::failure({ErrorCode::corrupt});

  locations.reserve(res.value().array().size());
  for (const auto &entry : res.value().array()) {
    auto loc = parse_location_in_workspace(impl_->workspace_root, entry);
    if (!loc.has_value())
      return Result<std::vector<LspLocation>>::failure(loc.error());
    locations.push_back(std::move(loc).value());
  }
  return Result<std::vector<LspLocation>>::success(std::move(locations));
}

Result<std::optional<LspHover>> LspClient::hover(const LspTextDocumentPosition &pos) {
  if (!impl_ || !impl_->is_open())
    return Result<std::optional<LspHover>>::failure({ErrorCode::io, EBADF});

  auto resolved = impl_->resolve_and_encode_workspace_path(pos.path);
  if (!resolved.has_value())
    return Result<std::optional<LspHover>>::failure(resolved.error());

  Value params = Value::object({
      {"textDocument", Value::object({{"uri", Value{resolved.value().second}}})},
      {"position", serialize_position(pos.position)},
  });
  auto res = impl_->request_impl("textDocument/hover", std::move(params));
  if (!res.has_value())
    return Result<std::optional<LspHover>>::failure(res.error());
  if (is_null(res.value()))
    return Result<std::optional<LspHover>>::success(std::nullopt);
  if (!is_object(res.value()))
    return Result<std::optional<LspHover>>::failure({ErrorCode::corrupt});

  const Value *contents = res.value().find("contents");
  if (contents == nullptr)
    return Result<std::optional<LspHover>>::failure({ErrorCode::corrupt});

  LspHover out;
  auto append_marked_string = [&](const Value &item) -> bool {
    if (is_string(item)) {
      if (!out.value.empty())
        out.value.append("\n\n");
      out.value.append(item.string());
      if (out.kind.empty())
        out.kind = "markdown";
      return true;
    }
    if (is_object(item)) {
      const Value *val = item.find("value");
      if (val == nullptr || !is_string(*val))
        return false;
      if (const Value *kind = item.find("kind"); kind != nullptr && is_string(*kind)) {
        out.kind = kind->string();
        if (!out.value.empty())
          out.value.append("\n\n");
        out.value.append(val->string());
        return true;
      }
      if (const Value *lang = item.find("language");
          lang != nullptr && is_string(*lang)) {
        out.kind = "markdown";
        if (!out.value.empty())
          out.value.append("\n\n");
        out.value.append("```");
        out.value.append(lang->string());
        out.value.push_back('\n');
        out.value.append(val->string());
        out.value.append("\n```");
        return true;
      }
    }
    return false;
  };

  if (is_array(*contents)) {
    for (const auto &entry : contents->array()) {
      if (!append_marked_string(entry))
        return Result<std::optional<LspHover>>::failure({ErrorCode::corrupt});
    }
  } else {
    if (!append_marked_string(*contents))
      return Result<std::optional<LspHover>>::failure({ErrorCode::corrupt});
  }

  if (const Value *range_val = res.value().find("range");
      range_val != nullptr && !is_null(*range_val)) {
    auto range = parse_range(*range_val);
    if (!range.has_value())
      return Result<std::optional<LspHover>>::failure(range.error());
    out.range = range.value();
  }
  return Result<std::optional<LspHover>>::success(std::move(out));
}

Result<std::vector<LspDocumentSymbol>>
LspClient::document_symbols(const fs::path &path) {
  if (!impl_ || !impl_->is_open())
    return Result<std::vector<LspDocumentSymbol>>::failure({ErrorCode::io, EBADF});

  auto resolved = impl_->resolve_and_encode_workspace_path(path);
  if (!resolved.has_value())
    return Result<std::vector<LspDocumentSymbol>>::failure(resolved.error());

  Value params = Value::object({
      {"textDocument", Value::object({{"uri", Value{resolved.value().second}}})},
  });
  auto res = impl_->request_impl("textDocument/documentSymbol", std::move(params));
  if (!res.has_value())
    return Result<std::vector<LspDocumentSymbol>>::failure(res.error());

  std::vector<LspDocumentSymbol> out;
  if (is_null(res.value()))
    return Result<std::vector<LspDocumentSymbol>>::success(std::move(out));
  if (!is_array(res.value()))
    return Result<std::vector<LspDocumentSymbol>>::failure({ErrorCode::corrupt});

  out.reserve(res.value().array().size());
  for (const auto &entry : res.value().array()) {
    auto sym = parse_document_symbol_recursive(entry, 0U);
    if (!sym.has_value())
      return Result<std::vector<LspDocumentSymbol>>::failure(sym.error());
    out.push_back(std::move(sym).value());
  }
  return Result<std::vector<LspDocumentSymbol>>::success(std::move(out));
}

Result<std::vector<LspWorkspaceSymbol>>
LspClient::workspace_symbols(std::string_view query) {
  if (!impl_ || !impl_->is_open())
    return Result<std::vector<LspWorkspaceSymbol>>::failure({ErrorCode::io, EBADF});
  if (!valid_utf8_no_nul(query))
    return Result<std::vector<LspWorkspaceSymbol>>::failure({ErrorCode::invalid_range});

  Value params = Value::object({{"query", Value{std::string{query}}}});
  auto res = impl_->request_impl("workspace/symbol", std::move(params));
  if (!res.has_value())
    return Result<std::vector<LspWorkspaceSymbol>>::failure(res.error());

  std::vector<LspWorkspaceSymbol> out;
  if (is_null(res.value()))
    return Result<std::vector<LspWorkspaceSymbol>>::success(std::move(out));
  if (!is_array(res.value()))
    return Result<std::vector<LspWorkspaceSymbol>>::failure({ErrorCode::corrupt});

  out.reserve(res.value().array().size());
  for (const auto &entry : res.value().array()) {
    if (!is_object(entry))
      return Result<std::vector<LspWorkspaceSymbol>>::failure({ErrorCode::corrupt});
    const Value *name_val = entry.find("name");
    const Value *kind_val = entry.find("kind");
    const Value *loc_val = entry.find("location");
    if (name_val == nullptr || !is_string(*name_val) || kind_val == nullptr ||
        loc_val == nullptr || !is_object(*loc_val)) {
      return Result<std::vector<LspWorkspaceSymbol>>::failure({ErrorCode::corrupt});
    }
    const auto kind = parse_uint32(*kind_val);
    if (!kind.has_value())
      return Result<std::vector<LspWorkspaceSymbol>>::failure({ErrorCode::corrupt});

    LspLocation loc;
    const Value *uri_val = loc_val->find("uri");
    if (uri_val == nullptr || !is_string(*uri_val))
      return Result<std::vector<LspWorkspaceSymbol>>::failure({ErrorCode::corrupt});
    auto resolved =
        resolve_workspace_file_uri({impl_->workspace_root, uri_val->string()});
    if (!resolved.has_value())
      return Result<std::vector<LspWorkspaceSymbol>>::failure(resolved.error());
    loc.path = std::move(resolved).value();
    loc.uri = uri_val->string();
    if (const Value *range_val = loc_val->find("range"); range_val != nullptr) {
      auto range = parse_range(*range_val);
      if (!range.has_value())
        return Result<std::vector<LspWorkspaceSymbol>>::failure(range.error());
      loc.range = range.value();
    }

    LspWorkspaceSymbol sym;
    sym.name = name_val->string();
    sym.kind = kind.value();
    if (const Value *cont = entry.find("containerName");
        cont != nullptr && is_string(*cont)) {
      sym.container_name = cont->string();
    }
    sym.location = std::move(loc);
    out.push_back(std::move(sym));
  }
  return Result<std::vector<LspWorkspaceSymbol>>::success(std::move(out));
}

Result<std::vector<LspCallHierarchyItem>>
LspClient::prepare_call_hierarchy(const LspTextDocumentPosition &pos) {
  if (!impl_ || !impl_->is_open())
    return Result<std::vector<LspCallHierarchyItem>>::failure({ErrorCode::io, EBADF});

  auto resolved = impl_->resolve_and_encode_workspace_path(pos.path);
  if (!resolved.has_value())
    return Result<std::vector<LspCallHierarchyItem>>::failure(resolved.error());

  Value params = Value::object({
      {"textDocument", Value::object({{"uri", Value{resolved.value().second}}})},
      {"position", serialize_position(pos.position)},
  });
  auto res =
      impl_->request_impl("textDocument/prepareCallHierarchy", std::move(params));
  if (!res.has_value())
    return Result<std::vector<LspCallHierarchyItem>>::failure(res.error());

  std::vector<LspCallHierarchyItem> out;
  if (is_null(res.value()))
    return Result<std::vector<LspCallHierarchyItem>>::success(std::move(out));
  if (!is_array(res.value()))
    return Result<std::vector<LspCallHierarchyItem>>::failure({ErrorCode::corrupt});

  out.reserve(res.value().array().size());
  for (const auto &entry : res.value().array()) {
    auto item = parse_call_hierarchy_item(impl_->workspace_root, entry);
    if (!item.has_value())
      return Result<std::vector<LspCallHierarchyItem>>::failure(item.error());
    out.push_back(std::move(item).value());
  }
  return Result<std::vector<LspCallHierarchyItem>>::success(std::move(out));
}

Result<std::vector<LspCallHierarchyIncomingCall>>
LspClient::incoming_calls(const LspCallHierarchyItem &item) {
  if (!impl_ || !impl_->is_open()) {
    return Result<std::vector<LspCallHierarchyIncomingCall>>::failure(
        {ErrorCode::io, EBADF});
  }
  auto check_uri = resolve_workspace_file_uri({impl_->workspace_root, item.uri});
  if (!check_uri.has_value())
    return Result<std::vector<LspCallHierarchyIncomingCall>>::failure(
        check_uri.error());

  Value params = Value::object({{"item", serialize_call_hierarchy_item(item)}});
  auto res = impl_->request_impl("callHierarchy/incomingCalls", std::move(params));
  if (!res.has_value())
    return Result<std::vector<LspCallHierarchyIncomingCall>>::failure(res.error());

  std::vector<LspCallHierarchyIncomingCall> out;
  if (is_null(res.value()))
    return Result<std::vector<LspCallHierarchyIncomingCall>>::success(std::move(out));
  if (!is_array(res.value()))
    return Result<std::vector<LspCallHierarchyIncomingCall>>::failure(
        {ErrorCode::corrupt});

  out.reserve(res.value().array().size());
  for (const auto &entry : res.value().array()) {
    if (!is_object(entry)) {
      return Result<std::vector<LspCallHierarchyIncomingCall>>::failure(
          {ErrorCode::corrupt});
    }
    const Value *from_val = entry.find("from");
    const Value *ranges_val = entry.find("fromRanges");
    if (from_val == nullptr || ranges_val == nullptr || !is_array(*ranges_val)) {
      return Result<std::vector<LspCallHierarchyIncomingCall>>::failure(
          {ErrorCode::corrupt});
    }
    auto from_item = parse_call_hierarchy_item(impl_->workspace_root, *from_val);
    if (!from_item.has_value())
      return Result<std::vector<LspCallHierarchyIncomingCall>>::failure(
          from_item.error());

    LspCallHierarchyIncomingCall call;
    call.from = std::move(from_item).value();
    call.from_ranges.reserve(ranges_val->array().size());
    for (const auto &r : ranges_val->array()) {
      auto parsed = parse_range(r);
      if (!parsed.has_value())
        return Result<std::vector<LspCallHierarchyIncomingCall>>::failure(
            parsed.error());
      call.from_ranges.push_back(parsed.value());
    }
    out.push_back(std::move(call));
  }
  return Result<std::vector<LspCallHierarchyIncomingCall>>::success(std::move(out));
}

Result<std::vector<LspCallHierarchyOutgoingCall>>
LspClient::outgoing_calls(const LspCallHierarchyItem &item) {
  if (!impl_ || !impl_->is_open()) {
    return Result<std::vector<LspCallHierarchyOutgoingCall>>::failure(
        {ErrorCode::io, EBADF});
  }
  auto check_uri = resolve_workspace_file_uri({impl_->workspace_root, item.uri});
  if (!check_uri.has_value())
    return Result<std::vector<LspCallHierarchyOutgoingCall>>::failure(
        check_uri.error());

  Value params = Value::object({{"item", serialize_call_hierarchy_item(item)}});
  auto res = impl_->request_impl("callHierarchy/outgoingCalls", std::move(params));
  if (!res.has_value())
    return Result<std::vector<LspCallHierarchyOutgoingCall>>::failure(res.error());

  std::vector<LspCallHierarchyOutgoingCall> out;
  if (is_null(res.value()))
    return Result<std::vector<LspCallHierarchyOutgoingCall>>::success(std::move(out));
  if (!is_array(res.value()))
    return Result<std::vector<LspCallHierarchyOutgoingCall>>::failure(
        {ErrorCode::corrupt});

  out.reserve(res.value().array().size());
  for (const auto &entry : res.value().array()) {
    if (!is_object(entry)) {
      return Result<std::vector<LspCallHierarchyOutgoingCall>>::failure(
          {ErrorCode::corrupt});
    }
    const Value *to_val = entry.find("to");
    const Value *ranges_val = entry.find("fromRanges");
    if (to_val == nullptr || ranges_val == nullptr || !is_array(*ranges_val)) {
      return Result<std::vector<LspCallHierarchyOutgoingCall>>::failure(
          {ErrorCode::corrupt});
    }
    auto to_item = parse_call_hierarchy_item(impl_->workspace_root, *to_val);
    if (!to_item.has_value())
      return Result<std::vector<LspCallHierarchyOutgoingCall>>::failure(
          to_item.error());

    LspCallHierarchyOutgoingCall call;
    call.to = std::move(to_item).value();
    call.from_ranges.reserve(ranges_val->array().size());
    for (const auto &r : ranges_val->array()) {
      auto parsed = parse_range(r);
      if (!parsed.has_value())
        return Result<std::vector<LspCallHierarchyOutgoingCall>>::failure(
            parsed.error());
      call.from_ranges.push_back(parsed.value());
    }
    out.push_back(std::move(call));
  }
  return Result<std::vector<LspCallHierarchyOutgoingCall>>::success(std::move(out));
}

// ---------------------------------------------------------------------------
// Diagnostics cache & notification pump
// ---------------------------------------------------------------------------

Result<std::size_t> LspClient::poll_notifications(std::chrono::milliseconds timeout) {
  if (!impl_ || !impl_->is_open())
    return Result<std::size_t>::failure({ErrorCode::io, EBADF});

  const auto deadline = Clock::now() + std::max(timeout, std::chrono::milliseconds{0});
  std::size_t processed = 0;

  while (true) {
    // If no complete frame is buffered yet, poll with remaining deadline.
    if (!impl_->has_complete_buffered_frame()) {
      const int wait_ms = poll_timeout_ms(deadline);
      pollfd pfd{};
      pfd.fd = impl_->read_fd_raw;
      pfd.events = POLLIN;
      const int prc = ::poll(&pfd, 1, wait_ms);
      if (prc < 0) {
        if (errno == EINTR)
          continue;
        return Result<std::size_t>::failure({ErrorCode::io, errno});
      }
      if (prc == 0)
        break;
    }

    auto frame = impl_->read_frame(deadline);
    if (!frame.has_value()) {
      if (frame.error().code == ErrorCode::io && frame.error().detail == ETIMEDOUT)
        break;
      if (frame.error().code == ErrorCode::incomplete && processed > 0U &&
          impl_->buffered_view().empty()) {
        break;
      }
      return Result<std::size_t>::failure(frame.error());
    }

    std::optional<RpcIdKey> resp_id;
    Value resp_msg;
    auto dispatched = impl_->dispatch_incoming_message(std::move(frame).value(),
                                                       deadline, &resp_id, &resp_msg);
    if (!dispatched.has_value())
      return Result<std::size_t>::failure(dispatched.error());

    if (dispatched.value() && resp_id.has_value()) {
      if (impl_->pending_responses.size() >= kMaxPendingResponses)
        return Result<std::size_t>::failure({ErrorCode::capacity});
      impl_->pending_responses.insert_or_assign(resp_id.value(), std::move(resp_msg));
    } else {
      ++processed;
    }

    // After draining at least one message, continue only if another complete frame
    // is already buffered or immediate readable data is ready.
    if (!impl_->has_complete_buffered_frame()) {
      pollfd immediate{};
      immediate.fd = impl_->read_fd_raw;
      immediate.events = POLLIN;
      if (::poll(&immediate, 1, 0) <= 0)
        break;
    }
  }
  return Result<std::size_t>::success(processed);
}

Result<std::optional<LspPublishedDiagnostics>>
LspClient::cached_diagnostics(const fs::path &path) const {
  if (!impl_)
    return Result<std::optional<LspPublishedDiagnostics>>::failure(
        {ErrorCode::io, EBADF});
  auto resolved = resolve_workspace_path_impl(impl_->workspace_root, path);
  if (!resolved.has_value())
    return Result<std::optional<LspPublishedDiagnostics>>::failure(resolved.error());
  const auto it = impl_->diagnostics_cache.find(resolved.value().string());
  if (it == impl_->diagnostics_cache.end())
    return Result<std::optional<LspPublishedDiagnostics>>::success(std::nullopt);
  return Result<std::optional<LspPublishedDiagnostics>>::success(it->second);
}

std::vector<LspPublishedDiagnostics> LspClient::all_cached_diagnostics() const {
  std::vector<LspPublishedDiagnostics> out;
  if (!impl_)
    return out;
  out.reserve(impl_->diagnostics_cache.size());
  for (const auto &[key, val] : impl_->diagnostics_cache) {
    (void)key;
    out.push_back(val);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Safe read-only rename planning (NEVER writes disk)
// ---------------------------------------------------------------------------

Result<std::optional<LspPrepareRenameResult>>
LspClient::prepare_rename(const LspTextDocumentPosition &pos) {
  if (!impl_ || !impl_->is_open())
    return Result<std::optional<LspPrepareRenameResult>>::failure(
        {ErrorCode::io, EBADF});

  auto resolved = impl_->resolve_and_encode_workspace_path(pos.path);
  if (!resolved.has_value())
    return Result<std::optional<LspPrepareRenameResult>>::failure(resolved.error());

  Value params = Value::object({
      {"textDocument", Value::object({{"uri", Value{resolved.value().second}}})},
      {"position", serialize_position(pos.position)},
  });
  auto res = impl_->request_impl("textDocument/prepareRename", std::move(params));
  if (!res.has_value())
    return Result<std::optional<LspPrepareRenameResult>>::failure(res.error());
  if (is_null(res.value()))
    return Result<std::optional<LspPrepareRenameResult>>::success(std::nullopt);
  if (!is_object(res.value()))
    return Result<std::optional<LspPrepareRenameResult>>::failure({ErrorCode::corrupt});

  LspPrepareRenameResult out;
  if (const Value *def_beh = res.value().find("defaultBehavior");
      def_beh != nullptr && is_bool(*def_beh)) {
    out.default_behavior = std::get<bool>(def_beh->value());
    return Result<std::optional<LspPrepareRenameResult>>::success(std::move(out));
  }

  if (const Value *range_val = res.value().find("range"); range_val != nullptr) {
    auto range = parse_range(*range_val);
    if (!range.has_value())
      return Result<std::optional<LspPrepareRenameResult>>::failure(range.error());
    out.range = range.value();
    if (const Value *placeholder = res.value().find("placeholder");
        placeholder != nullptr && is_string(*placeholder)) {
      out.placeholder = placeholder->string();
    }
    return Result<std::optional<LspPrepareRenameResult>>::success(std::move(out));
  }

  // Plain Range object directly.
  auto range = parse_range(res.value());
  if (!range.has_value())
    return Result<std::optional<LspPrepareRenameResult>>::failure(range.error());
  out.range = range.value();
  return Result<std::optional<LspPrepareRenameResult>>::success(std::move(out));
}

Result<LspWorkspaceEditPlan> LspClient::rename(const LspRenameParams &params) {
  if (!impl_ || !impl_->is_open())
    return Result<LspWorkspaceEditPlan>::failure({ErrorCode::io, EBADF});
  if (params.new_name.empty() || !valid_utf8_no_nul(params.new_name))
    return Result<LspWorkspaceEditPlan>::failure({ErrorCode::invalid_range});

  auto resolved = impl_->resolve_and_encode_workspace_path(params.path);
  if (!resolved.has_value())
    return Result<LspWorkspaceEditPlan>::failure(resolved.error());

  Value rpc_params = Value::object({
      {"textDocument", Value::object({{"uri", Value{resolved.value().second}}})},
      {"position", serialize_position(params.position)},
      {"newName", Value{params.new_name}},
  });
  auto res = impl_->request_impl("textDocument/rename", std::move(rpc_params));
  if (!res.has_value())
    return Result<LspWorkspaceEditPlan>::failure(res.error());

  LspWorkspaceEditPlan plan;
  if (is_null(res.value()))
    return Result<LspWorkspaceEditPlan>::success(std::move(plan));
  if (!is_object(res.value()))
    return Result<LspWorkspaceEditPlan>::failure({ErrorCode::corrupt});

  struct RawFileEdits {
    fs::path path;
    std::string uri;
    std::vector<LspTextEdit> edits;
  };
  std::map<std::string, RawFileEdits> edits_by_file;

  auto collect_uri_edits = [&](std::string_view uri_str,
                               const Value::Array &raw_edits) -> Result<void> {
    auto file_path = resolve_workspace_file_uri({impl_->workspace_root, uri_str});
    if (!file_path.has_value()) {
      impl_->last_error = "rename edit URI escapes workspace_root or is invalid";
      return Result<void>::failure(file_path.error());
    }
    if (file_path.value() == impl_->workspace_root) {
      impl_->last_error = "rename edit targets workspace_root directory";
      return Result<void>::failure({ErrorCode::invalid_range});
    }

    const std::string key = file_path.value().string();
    auto &bucket = edits_by_file[key];
    if (bucket.path.empty()) {
      bucket.path = file_path.value();
      bucket.uri = std::string{uri_str};
    }
    bucket.edits.reserve(bucket.edits.size() + raw_edits.size());
    for (const auto &raw_edit : raw_edits) {
      auto parsed = parse_text_edit(raw_edit);
      if (!parsed.has_value())
        return Result<void>::failure(parsed.error());
      bucket.edits.push_back(std::move(parsed).value());
    }
    return Result<void>::success();
  };

  // Prefer documentChanges when present (per LSP spec), otherwise changes.
  if (const Value *doc_changes = res.value().find("documentChanges");
      doc_changes != nullptr && !is_null(*doc_changes)) {
    if (!is_array(*doc_changes))
      return Result<LspWorkspaceEditPlan>::failure({ErrorCode::corrupt});
    for (const auto &entry : doc_changes->array()) {
      if (!is_object(entry))
        return Result<LspWorkspaceEditPlan>::failure({ErrorCode::corrupt});
      if (entry.find("kind") != nullptr) {
        // CreateFile / RenameFile / DeleteFile are not plain text edits; refuse rather
        // than silently dropping or touching disk.
        impl_->last_error = "unsupported resource operation in WorkspaceEdit";
        return Result<LspWorkspaceEditPlan>::failure({ErrorCode::unsupported});
      }
      const Value *td = entry.find("textDocument");
      const Value *edits_val = entry.find("edits");
      if (td == nullptr || !is_object(*td) || edits_val == nullptr ||
          !is_array(*edits_val)) {
        return Result<LspWorkspaceEditPlan>::failure({ErrorCode::corrupt});
      }
      const Value *uri_val = td->find("uri");
      if (uri_val == nullptr || !is_string(*uri_val))
        return Result<LspWorkspaceEditPlan>::failure({ErrorCode::corrupt});
      auto collected = collect_uri_edits(uri_val->string(), edits_val->array());
      if (!collected.has_value())
        return Result<LspWorkspaceEditPlan>::failure(collected.error());
    }
  } else if (const Value *changes = res.value().find("changes");
             changes != nullptr && !is_null(*changes)) {
    if (!is_object(*changes))
      return Result<LspWorkspaceEditPlan>::failure({ErrorCode::corrupt});
    for (const auto &[uri_key, edits_val] : changes->object()) {
      if (!is_array(edits_val))
        return Result<LspWorkspaceEditPlan>::failure({ErrorCode::corrupt});
      auto collected = collect_uri_edits(uri_key, edits_val.array());
      if (!collected.has_value())
        return Result<LspWorkspaceEditPlan>::failure(collected.error());
    }
  }

  // Build deterministic, sorted, non-overlapping per-file edit plans and unified diff
  // previews purely in memory. ZERO disk writes!
  std::vector<LspFileEditPlan> file_plans;
  file_plans.reserve(edits_by_file.size());

  for (auto &[key, raw] : edits_by_file) {
    std::string before_text;
    if (const auto open_it = impl_->open_documents.find(key);
        open_it != impl_->open_documents.end()) {
      before_text = open_it->second;
    } else {
      auto disk = read_regular_file_readonly(raw.path);
      if (!disk.has_value()) {
        impl_->last_error = "unable to read target file for rename preview";
        return Result<LspWorkspaceEditPlan>::failure(disk.error());
      }
      before_text = std::move(disk).value();
    }

    std::vector<ByteEdit> byte_edits;
    auto after_text = apply_text_edits_in_memory(before_text, raw.edits,
                                                 impl_->position_encoding, &byte_edits);
    if (!after_text.has_value()) {
      impl_->last_error = (after_text.error().code == ErrorCode::conflict)
                              ? "server returned overlapping text edits in rename"
                              : "server returned out-of-range text edit in rename";
      return Result<LspWorkspaceEditPlan>::failure(after_text.error());
    }

    std::error_code rel_ec;
    fs::path rel_path = fs::relative(raw.path, impl_->workspace_root, rel_ec);
    if (rel_ec || rel_path.empty())
      rel_path = raw.path.filename();

    LspFileEditPlan fplan;
    fplan.path = raw.path;
    fplan.relative_path = rel_path;
    fplan.uri = std::move(raw.uri);
    fplan.edits.reserve(byte_edits.size());
    for (const auto &be : byte_edits)
      fplan.edits.push_back(be.edit);

    const auto before_lines = split_lines(before_text);
    fplan.unified_diff = build_unified_diff(DiffBuildInput{
        rel_path.generic_string(),
        before_text,
        after_text.value(),
        before_lines,
        byte_edits,
    });
    file_plans.push_back(std::move(fplan));
  }

  std::sort(file_plans.begin(), file_plans.end(),
            [](const LspFileEditPlan &lhs, const LspFileEditPlan &rhs) {
              return lhs.relative_path.generic_string() <
                     rhs.relative_path.generic_string();
            });

  for (const auto &fp : file_plans) {
    plan.total_edits += fp.edits.size();
    plan.unified_preview.append(fp.unified_diff);
  }
  plan.files = std::move(file_plans);
  return Result<LspWorkspaceEditPlan>::success(std::move(plan));
}

// ---------------------------------------------------------------------------
// Low-level JSON-RPC 2.0 correlation API
// ---------------------------------------------------------------------------

Result<void> LspClient::send_request_with_id(const LspRequestId &id,
                                             std::string_view method, Value params) {
  if (!impl_)
    return Result<void>::failure({ErrorCode::io, EBADF});
  return impl_->send_request_with_id_impl(id, method, std::move(params));
}

Result<Value> LspClient::wait_for_response(const LspRequestId &id) {
  if (!impl_)
    return Result<Value>::failure({ErrorCode::io, EBADF});
  return impl_->wait_for_response_impl(id);
}

Result<Value> LspClient::request_raw(std::string_view method, Value params) {
  if (!impl_)
    return Result<Value>::failure({ErrorCode::io, EBADF});
  return impl_->request_impl(method, std::move(params));
}

Result<void> LspClient::notify_raw(std::string_view method, Value params) {
  if (!impl_)
    return Result<void>::failure({ErrorCode::io, EBADF});
  return impl_->notify_impl(method, std::move(params));
}

} // namespace blackbird
