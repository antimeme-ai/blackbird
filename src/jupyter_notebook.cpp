#include "blackbird/jupyter_notebook.hpp"

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
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <set>
#include <span>
#include <spawn.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

extern char **environ;

namespace blackbird {
namespace {

constexpr std::string_view kWsAcceptGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr std::size_t kMaxWsControlPayload = 125U;
constexpr std::size_t kMaxWsFragmentsPerMessage = 256U;
constexpr std::size_t kMaxCellIdBytes = 64U;
constexpr std::size_t kMaxKernelIdBytes = 128U;
constexpr std::size_t kMaxKernelNameBytes = 128U;
constexpr std::size_t kMaxUrlBytes = 1024U;
constexpr std::size_t kMaxTokenBytes = 1024U;

using SteadyClock = std::chrono::steady_clock;

template <typename T> Result<T> fail_j(ErrorCode code, JupyterErrorDetail detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_jv(ErrorCode code, JupyterErrorDetail detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

struct CleanseStringGuard {
  std::string &text;
  ~CleanseStringGuard() {
    if (!text.empty()) {
      OPENSSL_cleanse(text.data(), text.size());
      text.clear();
    }
  }
};

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
      sigset_t pending{};
      if (::sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1) {
        timespec zero{};
        while (::sigtimedwait(&blocked_, nullptr, &zero) < 0 && errno == EINTR) {
        }
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

// ---------------------------------------------------------------------------
// String, UTF-8, Base64, Crypto, and JSON Value Helpers
// ---------------------------------------------------------------------------

char ascii_lower(char c) noexcept {
  if (c >= 'A' && c <= 'Z') {
    return static_cast<char>(c - 'A' + 'a');
  }
  return c;
}

std::string to_ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    out.push_back(ascii_lower(c));
  }
  return out;
}

std::string_view trim_ascii_ws(std::string_view text) noexcept {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t' ||
                           text.front() == '\r' || text.front() == '\n')) {
    text.remove_prefix(1U);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t' ||
                           text.back() == '\r' || text.back() == '\n')) {
    text.remove_suffix(1U);
  }
  return text;
}

bool contains_ctl_or_crlf(std::string_view text) noexcept {
  for (const char ch : text) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7fU) {
      return true;
    }
  }
  return false;
}

std::string truncate_utf8(std::string_view text, std::size_t max_bytes) {
  if (text.size() <= max_bytes) {
    return std::string{text};
  }
  std::size_t cut = max_bytes;
  while (cut > 0U && (static_cast<unsigned char>(text[cut]) & 0xc0U) == 0x80U) {
    --cut;
  }
  return std::string{text.substr(0U, cut)};
}

std::string base64_encode(std::span<const std::uint8_t> bytes) {
  static constexpr char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((bytes.size() + 2U) / 3U) * 4U);
  std::size_t i = 0U;
  while (i + 3U <= bytes.size()) {
    const std::uint32_t n = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                            static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kTable[(n >> 18U) & 0x3fU]);
    out.push_back(kTable[(n >> 12U) & 0x3fU]);
    out.push_back(kTable[(n >> 6U) & 0x3fU]);
    out.push_back(kTable[n & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1U) {
    const std::uint32_t n = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kTable[(n >> 18U) & 0x3fU]);
    out.push_back(kTable[(n >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t n = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kTable[(n >> 18U) & 0x3fU]);
    out.push_back(kTable[(n >> 12U) & 0x3fU]);
    out.push_back(kTable[(n >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

Result<std::string> compute_ws_accept(std::string_view ws_key) {
  std::string input;
  input.reserve(ws_key.size() + kWsAcceptGuid.size());
  input.append(ws_key);
  input.append(kWsAcceptGuid);
  std::array<unsigned char, 20U> digest{};
  unsigned int digest_len = 0U;
  if (EVP_Digest(input.data(), input.size(), digest.data(), &digest_len, EVP_sha1(),
                 nullptr) != 1 ||
      digest_len != digest.size()) {
    return fail_j<std::string>(ErrorCode::provider_transport,
                               JupyterErrorDetail::crypto_error);
  }
  return Result<std::string>::success(
      base64_encode(std::span<const std::uint8_t>{digest.data(), digest.size()}));
}

Result<std::string> generate_uuid_v4() {
  std::array<std::uint8_t, 16U> bytes{};
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
    return fail_j<std::string>(ErrorCode::provider_transport,
                               JupyterErrorDetail::crypto_error);
  }
  bytes[6U] = static_cast<std::uint8_t>((bytes[6U] & 0x0fU) | 0x40U);
  bytes[8U] = static_cast<std::uint8_t>((bytes[8U] & 0x3fU) | 0x80U);
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(36U);
  for (std::size_t i = 0U; i < bytes.size(); ++i) {
    if (i == 4U || i == 6U || i == 8U || i == 10U) {
      out.push_back('-');
    }
    out.push_back(kHex[(bytes[i] >> 4U) & 0x0fU]);
    out.push_back(kHex[bytes[i] & 0x0fU]);
  }
  return Result<std::string>::success(std::move(out));
}

std::string current_utc_iso8601() {
  const auto now = std::chrono::system_clock::now();
  const auto secs = std::chrono::time_point_cast<std::chrono::seconds>(now);
  const auto micros =
      std::chrono::duration_cast<std::chrono::microseconds>(now - secs).count();
  const std::time_t raw_time = std::chrono::system_clock::to_time_t(secs);
  std::tm utc_tm{};
  (void)::gmtime_r(&raw_time, &utc_tm);
  std::array<char, 64U> buf{};
  const std::size_t n =
      std::strftime(buf.data(), buf.size(), "%Y-%m-%dT%H:%M:%S", &utc_tm);
  std::string out(buf.data(), n);
  out.push_back('.');
  std::array<char, 16U> frac{};
  const int frac_len = std::snprintf(frac.data(), frac.size(), "%06lldZ",
                                     static_cast<long long>(micros < 0 ? 0 : micros));
  if (frac_len > 0) {
    out.append(frac.data(), static_cast<std::size_t>(frac_len));
  } else {
    out.append("000000Z");
  }
  return out;
}

std::optional<std::int64_t> extract_strict_int64(const Value &v) noexcept {
  if (!std::holds_alternative<Number>(v.value())) {
    return std::nullopt;
  }
  const auto &storage = v.number().storage();
  if (const auto *signed_v = std::get_if<std::int64_t>(&storage)) {
    return *signed_v;
  }
  if (const auto *unsigned_v = std::get_if<std::uint64_t>(&storage)) {
    if (*unsigned_v <=
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return static_cast<std::int64_t>(*unsigned_v);
    }
  }
  return std::nullopt;
}

std::optional<std::uint64_t> extract_strict_uint64(const Value &v) noexcept {
  if (!std::holds_alternative<Number>(v.value())) {
    return std::nullopt;
  }
  const auto &storage = v.number().storage();
  if (const auto *unsigned_v = std::get_if<std::uint64_t>(&storage)) {
    return *unsigned_v;
  }
  if (const auto *signed_v = std::get_if<std::int64_t>(&storage)) {
    if (*signed_v >= 0) {
      return static_cast<std::uint64_t>(*signed_v);
    }
  }
  return std::nullopt;
}

Result<std::string> normalize_nbformat_text(const Value &v) {
  if (std::holds_alternative<std::string>(v.value())) {
    return Result<std::string>::success(v.string());
  }
  if (std::holds_alternative<Value::Array>(v.value())) {
    const auto &arr = v.array();
    std::size_t total_len = 0U;
    for (const auto &elem : arr) {
      if (!std::holds_alternative<std::string>(elem.value())) {
        return fail_j<std::string>(ErrorCode::corrupt,
                                   JupyterErrorDetail::invalid_cell_schema);
      }
      total_len += elem.string().size();
    }
    std::string joined;
    joined.reserve(total_len);
    for (const auto &elem : arr) {
      joined.append(elem.string());
    }
    return Result<std::string>::success(std::move(joined));
  }
  return fail_j<std::string>(ErrorCode::corrupt,
                             JupyterErrorDetail::invalid_cell_schema);
}

Value split_nbformat_lines(std::string_view text) {
  Value::Array lines;
  if (text.empty()) {
    return Value{std::move(lines)};
  }
  std::size_t pos = 0U;
  while (pos < text.size()) {
    const std::size_t nl = text.find('\n', pos);
    if (nl == std::string_view::npos) {
      lines.emplace_back(std::string{text.substr(pos)});
      break;
    }
    lines.emplace_back(std::string{text.substr(pos, nl - pos + 1U)});
    pos = nl + 1U;
  }
  return Value{std::move(lines)};
}

bool valid_cell_id(std::string_view id) noexcept {
  if (id.empty() || id.size() > kMaxCellIdBytes || contains_ctl_or_crlf(id)) {
    return false;
  }
  return valid_utf8(id);
}

std::string generate_unique_cell_id(const std::set<std::string> &used_ids,
                                    std::size_t hint_index) {
  for (std::size_t attempt = hint_index;; ++attempt) {
    std::string candidate = "cell-" + std::to_string(attempt);
    if (!used_ids.contains(candidate)) {
      return candidate;
    }
  }
}

Result<std::vector<NotebookMimeEntry>> parse_mime_bundle(const Value &bundle_val) {
  if (!std::holds_alternative<Value::Object>(bundle_val.value())) {
    return fail_j<std::vector<NotebookMimeEntry>>(
        ErrorCode::corrupt, JupyterErrorDetail::invalid_output_schema);
  }
  std::vector<NotebookMimeEntry> entries;
  const auto &obj = bundle_val.object();
  entries.reserve(obj.size());
  for (const auto &[mime, val] : obj) {
    entries.push_back(NotebookMimeEntry{.mime_type = mime, .data = val});
  }
  return Result<std::vector<NotebookMimeEntry>>::success(std::move(entries));
}

Result<NotebookOutput> parse_notebook_output_value(const Value &out_val) {
  if (!std::holds_alternative<Value::Object>(out_val.value())) {
    return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                  JupyterErrorDetail::invalid_output_schema);
  }
  const Value *type_val = out_val.find("output_type");
  if (type_val == nullptr || !std::holds_alternative<std::string>(type_val->value())) {
    return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                  JupyterErrorDetail::invalid_output_schema);
  }
  const auto parsed_type = parse_notebook_output_type(type_val->string());
  if (!parsed_type.has_value()) {
    return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                  JupyterErrorDetail::invalid_output_schema);
  }

  NotebookOutput output;
  output.output_type = *parsed_type;

  switch (output.output_type) {
  case NotebookOutputType::stream: {
    const Value *name_val = out_val.find("name");
    const Value *text_val = out_val.find("text");
    if (name_val == nullptr ||
        !std::holds_alternative<std::string>(name_val->value()) ||
        text_val == nullptr) {
      return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                    JupyterErrorDetail::invalid_output_schema);
    }
    auto text_res = normalize_nbformat_text(*text_val);
    if (!text_res.has_value()) {
      return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                    JupyterErrorDetail::invalid_output_schema);
    }
    output.stream_name = name_val->string();
    output.text = std::move(text_res).value();
    return Result<NotebookOutput>::success(std::move(output));
  }
  case NotebookOutputType::execute_result:
  case NotebookOutputType::display_data: {
    const Value *data_val = out_val.find("data");
    if (data_val == nullptr) {
      return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                    JupyterErrorDetail::invalid_output_schema);
    }
    auto mime_res = parse_mime_bundle(*data_val);
    if (!mime_res.has_value()) {
      return Result<NotebookOutput>::failure(mime_res.error());
    }
    output.data = std::move(mime_res).value();
    if (const Value *meta_val = out_val.find("metadata")) {
      if (!std::holds_alternative<Value::Object>(meta_val->value())) {
        return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                      JupyterErrorDetail::invalid_output_schema);
      }
      output.metadata = *meta_val;
    }
    if (output.output_type == NotebookOutputType::execute_result) {
      if (const Value *exec_val = out_val.find("execution_count")) {
        if (!std::holds_alternative<std::nullptr_t>(exec_val->value())) {
          const auto count = extract_strict_int64(*exec_val);
          if (!count.has_value()) {
            return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                          JupyterErrorDetail::invalid_output_schema);
          }
          output.execution_count = *count;
        }
      }
    }
    return Result<NotebookOutput>::success(std::move(output));
  }
  case NotebookOutputType::error: {
    const Value *ename_val = out_val.find("ename");
    const Value *evalue_val = out_val.find("evalue");
    if (ename_val == nullptr ||
        !std::holds_alternative<std::string>(ename_val->value()) ||
        evalue_val == nullptr ||
        !std::holds_alternative<std::string>(evalue_val->value())) {
      return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                    JupyterErrorDetail::invalid_output_schema);
    }
    output.ename = ename_val->string();
    output.evalue = evalue_val->string();
    if (const Value *tb_val = out_val.find("traceback")) {
      if (!std::holds_alternative<Value::Array>(tb_val->value())) {
        return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                      JupyterErrorDetail::invalid_output_schema);
      }
      for (const auto &line : tb_val->array()) {
        if (!std::holds_alternative<std::string>(line.value())) {
          return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                        JupyterErrorDetail::invalid_output_schema);
        }
        output.traceback.push_back(line.string());
      }
    }
    return Result<NotebookOutput>::success(std::move(output));
  }
  }
  return fail_j<NotebookOutput>(ErrorCode::corrupt,
                                JupyterErrorDetail::invalid_output_schema);
}

Value serialize_notebook_output_value(const NotebookOutput &output) {
  Value::Object obj;
  obj.emplace_back("output_type",
                   Value{std::string{notebook_output_type_name(output.output_type)}});
  switch (output.output_type) {
  case NotebookOutputType::stream:
    obj.emplace_back("name", Value{output.stream_name});
    obj.emplace_back("text", split_nbformat_lines(output.text));
    break;
  case NotebookOutputType::execute_result: {
    Value::Object data_obj;
    data_obj.reserve(output.data.size());
    for (const auto &entry : output.data) {
      data_obj.emplace_back(entry.mime_type, entry.data);
    }
    obj.emplace_back("data", Value::object(std::move(data_obj)));
    if (output.execution_count.has_value()) {
      obj.emplace_back("execution_count", Value{Number{*output.execution_count}});
    } else {
      obj.emplace_back("execution_count", Value{nullptr});
    }
    obj.emplace_back("metadata",
                     std::holds_alternative<Value::Object>(output.metadata.value())
                         ? output.metadata
                         : Value::object({}));
    break;
  }
  case NotebookOutputType::display_data: {
    Value::Object data_obj;
    data_obj.reserve(output.data.size());
    for (const auto &entry : output.data) {
      data_obj.emplace_back(entry.mime_type, entry.data);
    }
    obj.emplace_back("data", Value::object(std::move(data_obj)));
    obj.emplace_back("metadata",
                     std::holds_alternative<Value::Object>(output.metadata.value())
                         ? output.metadata
                         : Value::object({}));
    break;
  }
  case NotebookOutputType::error: {
    obj.emplace_back("ename", Value{output.ename});
    obj.emplace_back("evalue", Value{output.evalue});
    Value::Array tb;
    tb.reserve(output.traceback.size());
    for (const auto &line : output.traceback) {
      tb.emplace_back(line);
    }
    obj.emplace_back("traceback", Value{std::move(tb)});
    break;
  }
  }
  return Value::object(std::move(obj));
}

bool is_binary_mime_type(std::string_view mime_type) noexcept {
  const std::string lower = to_ascii_lower(mime_type);
  if (lower == "image/svg+xml") {
    return false;
  }
  return lower.starts_with("image/") || lower.starts_with("audio/") ||
         lower.starts_with("video/") || lower.starts_with("font/") ||
         lower == "application/pdf" || lower == "application/octet-stream" ||
         lower == "application/zip" || lower == "application/gzip";
}

bool looks_like_base64_blob(std::string_view text) noexcept {
  std::size_t non_ws = 0U;
  for (const char c : text) {
    if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
      continue;
    }
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
                    c == '-' || c == '_';
    if (!ok) {
      return false;
    }
    ++non_ws;
  }
  return non_ws >= 64U;
}

std::size_t estimate_base64_decoded_bytes(std::string_view text) noexcept {
  std::size_t non_ws = 0U;
  std::size_t trailing_pad = 0U;
  bool ended_pad = false;
  for (auto it = text.rbegin(); it != text.rend(); ++it) {
    const char c = *it;
    if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
      continue;
    }
    if (!ended_pad && c == '=') {
      ++trailing_pad;
    } else {
      ended_pad = true;
    }
    ++non_ws;
  }
  if (non_ws == 0U) {
    return 0U;
  }
  const std::size_t raw =
      (non_ws / 4U) * 3U + ((non_ws % 4U) > 1U ? (non_ws % 4U) - 1U : 0U);
  const std::size_t pad = std::min<std::size_t>(trailing_pad, 2U);
  return raw >= pad ? (raw - pad) : 0U;
}

std::string mime_value_to_raw_text(const Value &val) {
  if (std::holds_alternative<std::string>(val.value())) {
    return val.string();
  }
  if (std::holds_alternative<Value::Array>(val.value())) {
    std::string out;
    bool all_strings = true;
    for (const auto &elem : val.array()) {
      if (!std::holds_alternative<std::string>(elem.value())) {
        all_strings = false;
        break;
      }
      out.append(elem.string());
    }
    if (all_strings) {
      return out;
    }
  }
  auto dumped = dump_json(val);
  return dumped.has_value() ? std::move(dumped).value() : std::string{};
}

std::string summarize_mime_entries(const std::vector<NotebookMimeEntry> &entries,
                                   const NotebookHygieneOptions &options) {
  if (entries.empty()) {
    return "(empty)";
  }
  std::string out;
  for (std::size_t i = 0U; i < entries.size(); ++i) {
    if (i > 0U) {
      out.append("; ");
    }
    const auto &entry = entries[i];
    const std::string raw_text = mime_value_to_raw_text(entry.data);
    const bool binary_mime = is_binary_mime_type(entry.mime_type);
    const bool large_b64 = raw_text.size() > options.max_base64_inline_bytes &&
                           looks_like_base64_blob(raw_text);
    if (binary_mime || large_b64) {
      const std::size_t decoded_bytes = looks_like_base64_blob(raw_text)
                                            ? estimate_base64_decoded_bytes(raw_text)
                                            : raw_text.size();
      out.push_back('[');
      out.append(entry.mime_type);
      out.append(": ");
      out.append(std::to_string(decoded_bytes));
      out.append(" bytes]");
      continue;
    }
    std::string cleaned =
        options.strip_ansi ? strip_ansi_and_control_sequences(raw_text) : raw_text;
    if (cleaned.size() > options.max_text_chars) {
      const std::size_t omitted = cleaned.size() - options.max_text_chars;
      cleaned = truncate_utf8(cleaned, options.max_text_chars);
      cleaned.append("... (+");
      cleaned.append(std::to_string(omitted));
      cleaned.append(" bytes)");
    }
    out.append(entry.mime_type);
    out.append(": ");
    out.append(cleaned);
  }
  return out;
}

// ---------------------------------------------------------------------------
// URL Parsing & Loopback Enforcement
// ---------------------------------------------------------------------------

struct ParsedJupyterUrl {
  bool use_tls = false;
  std::string host;
  bool is_ipv6_literal = false;
  std::uint16_t port = 80U;
  std::string base_path; // "" or "/prefix" without trailing slash
  std::string normalized_url;
};

bool is_loopback_hostname(std::string_view host) noexcept {
  const std::string lower = to_ascii_lower(host);
  return lower == "127.0.0.1" || lower == "localhost" || lower == "::1";
}

bool is_ip_literal(const std::string &host) noexcept {
  in_addr v4{};
  if (::inet_pton(AF_INET, host.c_str(), &v4) == 1) {
    return true;
  }
  in6_addr v6{};
  return ::inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

bool is_loopback_sockaddr(const sockaddr *sa) noexcept {
  if (sa == nullptr) {
    return false;
  }
  if (sa->sa_family == AF_INET) {
    sockaddr_in sin{};
    std::memcpy(&sin, sa, sizeof(sin));
    return ntohl(sin.sin_addr.s_addr) == INADDR_LOOPBACK;
  }
  if (sa->sa_family == AF_INET6) {
    sockaddr_in6 sin6{};
    std::memcpy(&sin6, sa, sizeof(sin6));
    return IN6_IS_ADDR_LOOPBACK(&sin6.sin6_addr) != 0;
  }
  return false;
}

Result<std::uint16_t> parse_port_str(std::string_view text) noexcept {
  if (text.empty() || text.size() > 5U) {
    return fail_j<std::uint16_t>(ErrorCode::invalid_identity,
                                 JupyterErrorDetail::invalid_url);
  }
  if (text.size() > 1U && text.front() == '0') {
    return fail_j<std::uint16_t>(ErrorCode::invalid_identity,
                                 JupyterErrorDetail::invalid_url);
  }
  std::uint32_t value = 0U;
  const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (ec != std::errc{} || ptr != text.data() + text.size() || value == 0U ||
      value > 65535U) {
    return fail_j<std::uint16_t>(ErrorCode::invalid_identity,
                                 JupyterErrorDetail::invalid_url);
  }
  return Result<std::uint16_t>::success(static_cast<std::uint16_t>(value));
}

Result<ParsedJupyterUrl> parse_jupyter_base_url(std::string_view raw_url) {
  if (raw_url.empty() || raw_url.size() > kMaxUrlBytes ||
      contains_ctl_or_crlf(raw_url) || raw_url.find(' ') != std::string_view::npos ||
      raw_url.find('@') != std::string_view::npos ||
      raw_url.find('?') != std::string_view::npos ||
      raw_url.find('#') != std::string_view::npos) {
    return fail_j<ParsedJupyterUrl>(ErrorCode::invalid_identity,
                                    JupyterErrorDetail::invalid_url);
  }

  ParsedJupyterUrl parsed;
  std::string_view rest;
  if (raw_url.starts_with("http://")) {
    parsed.use_tls = false;
    parsed.port = 80U;
    rest = raw_url.substr(7U);
  } else if (raw_url.starts_with("https://")) {
    parsed.use_tls = true;
    parsed.port = 443U;
    rest = raw_url.substr(8U);
  } else {
    return fail_j<ParsedJupyterUrl>(ErrorCode::unsupported,
                                    JupyterErrorDetail::invalid_url);
  }

  const std::size_t slash_pos = rest.find('/');
  const std::string_view authority =
      slash_pos == std::string_view::npos ? rest : rest.substr(0U, slash_pos);
  std::string_view path =
      slash_pos == std::string_view::npos ? std::string_view{} : rest.substr(slash_pos);

  if (authority.empty()) {
    return fail_j<ParsedJupyterUrl>(ErrorCode::invalid_identity,
                                    JupyterErrorDetail::invalid_url);
  }

  if (authority.front() == '[') {
    const std::size_t close = authority.find(']');
    if (close == std::string_view::npos || close <= 1U) {
      return fail_j<ParsedJupyterUrl>(ErrorCode::invalid_identity,
                                      JupyterErrorDetail::invalid_url);
    }
    parsed.host = std::string{authority.substr(1U, close - 1U)};
    parsed.is_ipv6_literal = true;
    in6_addr v6{};
    if (::inet_pton(AF_INET6, parsed.host.c_str(), &v6) != 1) {
      return fail_j<ParsedJupyterUrl>(ErrorCode::invalid_identity,
                                      JupyterErrorDetail::invalid_url);
    }
    const std::string_view tail = authority.substr(close + 1U);
    if (!tail.empty()) {
      if (tail.front() != ':') {
        return fail_j<ParsedJupyterUrl>(ErrorCode::invalid_identity,
                                        JupyterErrorDetail::invalid_url);
      }
      auto port_res = parse_port_str(tail.substr(1U));
      if (!port_res.has_value()) {
        return Result<ParsedJupyterUrl>::failure(port_res.error());
      }
      parsed.port = port_res.value();
    }
  } else {
    const std::size_t colon = authority.rfind(':');
    if (colon != std::string_view::npos) {
      if (colon == 0U || authority.find(':') != colon) {
        return fail_j<ParsedJupyterUrl>(ErrorCode::invalid_identity,
                                        JupyterErrorDetail::invalid_url);
      }
      parsed.host = std::string{authority.substr(0U, colon)};
      auto port_res = parse_port_str(authority.substr(colon + 1U));
      if (!port_res.has_value()) {
        return Result<ParsedJupyterUrl>::failure(port_res.error());
      }
      parsed.port = port_res.value();
    } else {
      parsed.host = std::string{authority};
    }
    if (parsed.host.empty()) {
      return fail_j<ParsedJupyterUrl>(ErrorCode::invalid_identity,
                                      JupyterErrorDetail::invalid_url);
    }
  }

  // Strictly reject non-loopback plain http:// URLs.
  if (!parsed.use_tls && !is_loopback_hostname(parsed.host)) {
    return fail_j<ParsedJupyterUrl>(ErrorCode::unsupported,
                                    JupyterErrorDetail::non_loopback_http_refused);
  }

  // Validate and normalize optional base path.
  while (!path.empty() && path.back() == '/') {
    path.remove_suffix(1U);
  }
  if (!path.empty()) {
    if (path.front() != '/' || path.find("/../") != std::string_view::npos ||
        path.ends_with("/..") || path == "/..") {
      return fail_j<ParsedJupyterUrl>(ErrorCode::invalid_identity,
                                      JupyterErrorDetail::invalid_url);
    }
    parsed.base_path = std::string{path};
  }

  parsed.normalized_url = parsed.use_tls ? "https://" : "http://";
  if (parsed.is_ipv6_literal) {
    parsed.normalized_url.push_back('[');
    parsed.normalized_url.append(parsed.host);
    parsed.normalized_url.push_back(']');
  } else {
    parsed.normalized_url.append(parsed.host);
  }
  const std::uint16_t default_port = parsed.use_tls ? 443U : 80U;
  if (parsed.port != default_port) {
    parsed.normalized_url.push_back(':');
    parsed.normalized_url.append(std::to_string(parsed.port));
  }
  parsed.normalized_url.append(parsed.base_path);
  return Result<ParsedJupyterUrl>::success(std::move(parsed));
}

bool valid_kernel_id(std::string_view id) noexcept {
  if (id.empty() || id.size() > kMaxKernelIdBytes) {
    return false;
  }
  for (const char c : id) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
    if (!ok) {
      return false;
    }
  }
  return id != "." && id != "..";
}

bool valid_kernel_name(std::string_view name) noexcept {
  if (name.size() > kMaxKernelNameBytes || contains_ctl_or_crlf(name)) {
    return false;
  }
  return valid_utf8(name);
}

std::string build_host_header(const ParsedJupyterUrl &url) {
  std::string out;
  if (url.is_ipv6_literal) {
    out.push_back('[');
    out.append(url.host);
    out.push_back(']');
  } else {
    out.append(url.host);
  }
  const std::uint16_t default_port = url.use_tls ? 443U : 80U;
  if (url.port != default_port) {
    out.push_back(':');
    out.append(std::to_string(url.port));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Bounded POSIX Socket + Optional OpenSSL TLS Stream
// ---------------------------------------------------------------------------

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

enum class PollWaitKind : std::uint8_t { readable, writable };

Result<void> wait_fd_ready(int fd, PollWaitKind kind,
                           SteadyClock::time_point deadline) noexcept {
  while (true) {
    const int rem = remaining_timeout_ms(deadline);
    if (rem <= 0) {
      return fail_jv(ErrorCode::interrupted, JupyterErrorDetail::execution_timeout);
    }
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = (kind == PollWaitKind::readable) ? POLLIN : POLLOUT;
    const int rc = ::poll(&pfd, 1U, rem);
    if (rc > 0) {
      if ((pfd.revents & POLLNVAL) != 0) {
        return fail_jv(ErrorCode::io, JupyterErrorDetail::connect_failed);
      }
      return Result<void>::success();
    }
    if (rc == 0) {
      return fail_jv(ErrorCode::interrupted, JupyterErrorDetail::execution_timeout);
    }
    if (errno == EINTR) {
      continue;
    }
    return fail_jv(ErrorCode::io, JupyterErrorDetail::connect_failed);
  }
}

class TransportStream {
public:
  TransportStream() noexcept = default;
  TransportStream(const TransportStream &) = delete;
  TransportStream &operator=(const TransportStream &) = delete;
  TransportStream(TransportStream &&) noexcept = default;
  TransportStream &operator=(TransportStream &&) noexcept = default;
  ~TransportStream() { close(); }

  static Result<TransportStream> connect(const ParsedJupyterUrl &url,
                                         std::chrono::milliseconds timeout) {
    const auto deadline = SteadyClock::now() + timeout;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (is_ip_literal(url.host)) {
      hints.ai_flags |= AI_NUMERICHOST;
    }
    addrinfo *raw_res = nullptr;
    const std::string port_str = std::to_string(url.port);
    if (::getaddrinfo(url.host.c_str(), port_str.c_str(), &hints, &raw_res) != 0 ||
        raw_res == nullptr) {
      return fail_j<TransportStream>(ErrorCode::provider_transport,
                                     JupyterErrorDetail::connect_failed);
    }
    UniqueAddrInfo res{raw_res};

    ScopedFd sock;
    bool connected = false;
    for (const addrinfo *it = res.get(); it != nullptr; it = it->ai_next) {
      if (!url.use_tls && !is_loopback_sockaddr(it->ai_addr)) {
        continue;
      }
      if (SteadyClock::now() >= deadline) {
        return fail_j<TransportStream>(ErrorCode::interrupted,
                                       JupyterErrorDetail::execution_timeout);
      }
      int sock_type = it->ai_socktype;
#ifdef SOCK_CLOEXEC
      sock_type |= SOCK_CLOEXEC;
#endif
      ScopedFd candidate{::socket(it->ai_family, sock_type, it->ai_protocol)};
      if (!candidate) {
        continue;
      }
      if (::fcntl(candidate.get(), F_SETFD, FD_CLOEXEC) != 0) {
        continue;
      }
      const int flags = ::fcntl(candidate.get(), F_GETFL, 0);
      if (flags < 0 || ::fcntl(candidate.get(), F_SETFL, flags | O_NONBLOCK) != 0) {
        continue;
      }
      const int one = 1;
#ifdef SO_NOSIGPIPE
      (void)::setsockopt(candidate.get(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
      (void)::setsockopt(candidate.get(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

      const int rc = ::connect(candidate.get(), it->ai_addr, it->ai_addrlen);
      if (rc == 0) {
        sock = std::move(candidate);
        connected = true;
        break;
      }
      if (errno == EINPROGRESS) {
        auto waited = wait_fd_ready(candidate.get(), PollWaitKind::writable, deadline);
        if (!waited.has_value()) {
          continue;
        }
        int so_err = 0;
        socklen_t so_len = sizeof(so_err);
        if (::getsockopt(candidate.get(), SOL_SOCKET, SO_ERROR, &so_err, &so_len) ==
                0 &&
            so_err == 0) {
          sock = std::move(candidate);
          connected = true;
          break;
        }
      }
    }

    if (!connected || !sock) {
      return fail_j<TransportStream>(ErrorCode::provider_transport,
                                     JupyterErrorDetail::connect_failed);
    }

    TransportStream stream;
    stream.fd_ = std::move(sock);

    if (url.use_tls) {
      UniqueSslCtx ctx{SSL_CTX_new(TLS_client_method())};
      if (!ctx) {
        return fail_j<TransportStream>(ErrorCode::provider_transport,
                                       JupyterErrorDetail::tls_failed);
      }
      if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION) != 1 ||
          SSL_CTX_set_default_verify_paths(ctx.get()) != 1) {
        return fail_j<TransportStream>(ErrorCode::provider_transport,
                                       JupyterErrorDetail::tls_failed);
      }
      SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

      UniqueSsl ssl{SSL_new(ctx.get())};
      if (!ssl) {
        return fail_j<TransportStream>(ErrorCode::provider_transport,
                                       JupyterErrorDetail::tls_failed);
      }
      if (is_ip_literal(url.host)) {
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl.get());
        if (param == nullptr ||
            X509_VERIFY_PARAM_set1_ip_asc(param, url.host.c_str()) != 1) {
          return fail_j<TransportStream>(ErrorCode::provider_transport,
                                         JupyterErrorDetail::tls_failed);
        }
      } else {
        if (SSL_set_tlsext_host_name(ssl.get(), url.host.c_str()) != 1 ||
            SSL_set1_host(ssl.get(), url.host.c_str()) != 1) {
          return fail_j<TransportStream>(ErrorCode::provider_transport,
                                         JupyterErrorDetail::tls_failed);
        }
      }
      if (SSL_set_fd(ssl.get(), stream.fd_.get()) != 1) {
        return fail_j<TransportStream>(ErrorCode::provider_transport,
                                       JupyterErrorDetail::tls_failed);
      }
      while (true) {
#ifndef SO_NOSIGPIPE
        ScopedSigpipeGuard sigpipe;
#endif
        const int hs = SSL_connect(ssl.get());
        if (hs == 1) {
          break;
        }
        const int ssl_err = SSL_get_error(ssl.get(), hs);
        if (ssl_err == SSL_ERROR_WANT_READ) {
          auto w = wait_fd_ready(stream.fd_.get(), PollWaitKind::readable, deadline);
          if (!w.has_value()) {
            return Result<TransportStream>::failure(w.error());
          }
          continue;
        }
        if (ssl_err == SSL_ERROR_WANT_WRITE) {
          auto w = wait_fd_ready(stream.fd_.get(), PollWaitKind::writable, deadline);
          if (!w.has_value()) {
            return Result<TransportStream>::failure(w.error());
          }
          continue;
        }
        return fail_j<TransportStream>(ErrorCode::provider_transport,
                                       JupyterErrorDetail::tls_failed);
      }
      stream.ssl_ctx_ = std::move(ctx);
      stream.ssl_ = std::move(ssl);
    }

    return Result<TransportStream>::success(std::move(stream));
  }

  Result<void> write_all(std::span<const std::uint8_t> data,
                         SteadyClock::time_point deadline) {
    std::size_t offset = 0U;
    while (offset < data.size()) {
      const std::size_t chunk =
          std::min<std::size_t>(data.size() - offset, 64U * 1024U);
      if (ssl_) {
#ifndef SO_NOSIGPIPE
        ScopedSigpipeGuard sigpipe;
#endif
        const int n =
            SSL_write(ssl_.get(), data.data() + offset, static_cast<int>(chunk));
        if (n > 0) {
          offset += static_cast<std::size_t>(n);
          continue;
        }
        const int ssl_err = SSL_get_error(ssl_.get(), n);
        if (ssl_err == SSL_ERROR_WANT_READ) {
          auto w = wait_fd_ready(fd_.get(), PollWaitKind::readable, deadline);
          if (!w.has_value()) {
            return w;
          }
          continue;
        }
        if (ssl_err == SSL_ERROR_WANT_WRITE) {
          auto w = wait_fd_ready(fd_.get(), PollWaitKind::writable, deadline);
          if (!w.has_value()) {
            return w;
          }
          continue;
        }
        return fail_jv(ErrorCode::provider_transport, JupyterErrorDetail::tls_failed);
      }

      int send_flags = 0;
#ifdef MSG_NOSIGNAL
      send_flags |= MSG_NOSIGNAL;
#endif
      const ssize_t n = ::send(fd_.get(), data.data() + offset, chunk, send_flags);
      if (n > 0) {
        offset += static_cast<std::size_t>(n);
        continue;
      }
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        auto w = wait_fd_ready(fd_.get(), PollWaitKind::writable, deadline);
        if (!w.has_value()) {
          return w;
        }
        continue;
      }
      return fail_jv(ErrorCode::provider_transport,
                     JupyterErrorDetail::http_protocol_error);
    }
    return Result<void>::success();
  }

  Result<void> write_text(std::string_view text, SteadyClock::time_point deadline) {
    return write_all(
        std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t *>(text.data()), text.size()},
        deadline);
  }

  // Returns 0 on clean EOF, >0 on bytes read into dst.
  Result<std::size_t> read_some(std::span<std::uint8_t> dst,
                                SteadyClock::time_point deadline) {
    if (dst.empty()) {
      return Result<std::size_t>::success(0U);
    }
    if (buf_pos_ < buf_.size()) {
      const std::size_t avail = buf_.size() - buf_pos_;
      const std::size_t take = std::min(avail, dst.size());
      std::memcpy(dst.data(), buf_.data() + buf_pos_, take);
      buf_pos_ += take;
      if (buf_pos_ == buf_.size()) {
        buf_.clear();
        buf_pos_ = 0U;
      }
      return Result<std::size_t>::success(take);
    }

    while (true) {
      if (ssl_) {
#ifndef SO_NOSIGPIPE
        ScopedSigpipeGuard sigpipe;
#endif
        const std::size_t chunk =
            std::min<std::size_t>(dst.size(), static_cast<std::size_t>(INT_MAX));
        const int n = SSL_read(ssl_.get(), dst.data(), static_cast<int>(chunk));
        if (n > 0) {
          return Result<std::size_t>::success(static_cast<std::size_t>(n));
        }
        const int ssl_err = SSL_get_error(ssl_.get(), n);
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
          return Result<std::size_t>::success(0U);
        }
        if (ssl_err == SSL_ERROR_WANT_READ) {
          auto w = wait_fd_ready(fd_.get(), PollWaitKind::readable, deadline);
          if (!w.has_value()) {
            return Result<std::size_t>::failure(w.error());
          }
          continue;
        }
        if (ssl_err == SSL_ERROR_WANT_WRITE) {
          auto w = wait_fd_ready(fd_.get(), PollWaitKind::writable, deadline);
          if (!w.has_value()) {
            return Result<std::size_t>::failure(w.error());
          }
          continue;
        }
        return fail_j<std::size_t>(ErrorCode::provider_transport,
                                   JupyterErrorDetail::tls_failed);
      }

      const ssize_t n = ::recv(fd_.get(), dst.data(), dst.size(), 0);
      if (n > 0) {
        return Result<std::size_t>::success(static_cast<std::size_t>(n));
      }
      if (n == 0) {
        return Result<std::size_t>::success(0U);
      }
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        auto w = wait_fd_ready(fd_.get(), PollWaitKind::readable, deadline);
        if (!w.has_value()) {
          return Result<std::size_t>::failure(w.error());
        }
        continue;
      }
      return fail_j<std::size_t>(ErrorCode::provider_transport,
                                 JupyterErrorDetail::http_protocol_error);
    }
  }

  Result<void> read_exact(std::span<std::uint8_t> dst,
                          SteadyClock::time_point deadline) {
    std::size_t offset = 0U;
    while (offset < dst.size()) {
      auto got = read_some(dst.subspan(offset), deadline);
      if (!got.has_value()) {
        return Result<void>::failure(got.error());
      }
      if (got.value() == 0U) {
        return fail_jv(ErrorCode::provider_transport,
                       JupyterErrorDetail::ws_closed_unexpectedly);
      }
      offset += got.value();
    }
    return Result<void>::success();
  }

  void push_back_unread(std::span<const std::uint8_t> extra) {
    if (extra.empty()) {
      return;
    }
    std::vector<std::uint8_t> next;
    next.reserve(extra.size() + (buf_.size() - buf_pos_));
    next.insert(next.end(), extra.begin(), extra.end());
    next.insert(next.end(), buf_.begin() + static_cast<std::ptrdiff_t>(buf_pos_),
                buf_.end());
    buf_ = std::move(next);
    buf_pos_ = 0U;
  }

  void close() noexcept {
    if (ssl_) {
#ifndef SO_NOSIGPIPE
      ScopedSigpipeGuard sigpipe;
#endif
      (void)SSL_shutdown(ssl_.get());
      ssl_.reset();
    }
    ssl_ctx_.reset();
    fd_.reset();
    buf_.clear();
    buf_pos_ = 0U;
  }

private:
  ScopedFd fd_;
  UniqueSslCtx ssl_ctx_;
  UniqueSsl ssl_;
  std::vector<std::uint8_t> buf_;
  std::size_t buf_pos_ = 0U;
};

// ---------------------------------------------------------------------------
// HTTP/1.1 Header & Body Parsing
// ---------------------------------------------------------------------------

struct HttpHeaderEntry {
  std::string name_lower;
  std::string value;
};

struct HttpResponseHead {
  int status_code = 0;
  std::vector<HttpHeaderEntry> headers;
};

std::optional<std::string_view>
find_header_value(const std::vector<HttpHeaderEntry> &headers,
                  std::string_view lower_name) noexcept {
  for (const auto &h : headers) {
    if (h.name_lower == lower_name) {
      return h.value;
    }
  }
  return std::nullopt;
}

struct HeaderTokenQuery {
  std::string_view header_val;
  std::string_view expected_lower_token;
};

bool header_contains_token_icase(HeaderTokenQuery query) noexcept {
  std::size_t pos = 0U;
  while (pos < query.header_val.size()) {
    const std::size_t comma = query.header_val.find(',', pos);
    const std::string_view part = comma == std::string_view::npos
                                      ? query.header_val.substr(pos)
                                      : query.header_val.substr(pos, comma - pos);
    if (to_ascii_lower(trim_ascii_ws(part)) == query.expected_lower_token) {
      return true;
    }
    if (comma == std::string_view::npos) {
      break;
    }
    pos = comma + 1U;
  }
  return false;
}

Result<HttpResponseHead> read_http_response_head(TransportStream &stream,
                                                 SteadyClock::time_point deadline) {
  std::string raw;
  raw.reserve(1024U);
  std::array<std::uint8_t, 4096U> chunk{};
  std::size_t header_end = std::string::npos;

  while (header_end == std::string::npos) {
    auto got = stream.read_some(chunk, deadline);
    if (!got.has_value()) {
      return Result<HttpResponseHead>::failure(got.error());
    }
    if (got.value() == 0U) {
      return fail_j<HttpResponseHead>(ErrorCode::provider_transport,
                                      JupyterErrorDetail::http_protocol_error);
    }
    if (raw.size() + got.value() > kJupyterDefaultMaxHeaderBytes + chunk.size()) {
      return fail_j<HttpResponseHead>(ErrorCode::capacity,
                                      JupyterErrorDetail::response_too_large);
    }
    raw.append(reinterpret_cast<const char *>(chunk.data()), got.value());
    header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos && raw.size() > kJupyterDefaultMaxHeaderBytes) {
      return fail_j<HttpResponseHead>(ErrorCode::capacity,
                                      JupyterErrorDetail::response_too_large);
    }
  }

  if (header_end > kJupyterDefaultMaxHeaderBytes) {
    return fail_j<HttpResponseHead>(ErrorCode::capacity,
                                    JupyterErrorDetail::response_too_large);
  }

  const std::size_t leftover_offset = header_end + 4U;
  if (leftover_offset < raw.size()) {
    stream.push_back_unread(std::span<const std::uint8_t>{
        reinterpret_cast<const std::uint8_t *>(raw.data() + leftover_offset),
        raw.size() - leftover_offset});
  }

  const std::string_view head_view{raw.data(), header_end};
  const std::size_t first_crlf = head_view.find("\r\n");
  const std::string_view status_line = first_crlf == std::string_view::npos
                                           ? head_view
                                           : head_view.substr(0U, first_crlf);
  if (!status_line.starts_with("HTTP/1.1 ") && !status_line.starts_with("HTTP/1.0 ")) {
    return fail_j<HttpResponseHead>(ErrorCode::provider_transport,
                                    JupyterErrorDetail::http_protocol_error);
  }
  const std::string_view status_rest = status_line.substr(9U);
  if (status_rest.size() < 3U) {
    return fail_j<HttpResponseHead>(ErrorCode::provider_transport,
                                    JupyterErrorDetail::http_protocol_error);
  }
  int status_code = 0;
  const auto [ptr, ec] =
      std::from_chars(status_rest.data(), status_rest.data() + 3U, status_code);
  if (ec != std::errc{} || ptr != status_rest.data() + 3U || status_code < 100 ||
      status_code > 599) {
    return fail_j<HttpResponseHead>(ErrorCode::provider_transport,
                                    JupyterErrorDetail::http_protocol_error);
  }

  HttpResponseHead parsed;
  parsed.status_code = status_code;

  if (first_crlf != std::string_view::npos) {
    std::size_t pos = first_crlf + 2U;
    while (pos < head_view.size()) {
      const std::size_t next = head_view.find("\r\n", pos);
      const std::string_view line = next == std::string_view::npos
                                        ? head_view.substr(pos)
                                        : head_view.substr(pos, next - pos);
      const std::size_t colon = line.find(':');
      if (colon == std::string_view::npos || colon == 0U) {
        return fail_j<HttpResponseHead>(ErrorCode::provider_transport,
                                        JupyterErrorDetail::http_protocol_error);
      }
      parsed.headers.push_back(HttpHeaderEntry{
          .name_lower = to_ascii_lower(trim_ascii_ws(line.substr(0U, colon))),
          .value = std::string{trim_ascii_ws(line.substr(colon + 1U))},
      });
      if (next == std::string_view::npos) {
        break;
      }
      pos = next + 2U;
    }
  }

  return Result<HttpResponseHead>::success(std::move(parsed));
}

Result<std::string> read_crlf_line(TransportStream &stream,
                                   SteadyClock::time_point deadline) {
  std::string line;
  while (true) {
    std::uint8_t byte = 0U;
    auto got = stream.read_some(std::span<std::uint8_t>{&byte, 1U}, deadline);
    if (!got.has_value()) {
      return Result<std::string>::failure(got.error());
    }
    if (got.value() == 0U) {
      return fail_j<std::string>(ErrorCode::provider_transport,
                                 JupyterErrorDetail::http_protocol_error);
    }
    line.push_back(static_cast<char>(byte));
    if (line.size() > 8192U) {
      return fail_j<std::string>(ErrorCode::capacity,
                                 JupyterErrorDetail::response_too_large);
    }
    if (line.size() >= 2U && line[line.size() - 2U] == '\r' && line.back() == '\n') {
      line.resize(line.size() - 2U);
      return Result<std::string>::success(std::move(line));
    }
  }
}

Result<std::string> read_chunked_http_body(TransportStream &stream,
                                           std::size_t max_bytes,
                                           SteadyClock::time_point deadline) {
  std::string body;
  while (true) {
    auto line_res = read_crlf_line(stream, deadline);
    if (!line_res.has_value()) {
      return Result<std::string>::failure(line_res.error());
    }
    std::string_view size_text = line_res.value();
    const std::size_t semi = size_text.find(';');
    if (semi != std::string_view::npos) {
      size_text = size_text.substr(0U, semi);
    }
    size_text = trim_ascii_ws(size_text);
    if (size_text.empty()) {
      return fail_j<std::string>(ErrorCode::provider_transport,
                                 JupyterErrorDetail::http_protocol_error);
    }
    std::size_t chunk_size = 0U;
    const auto [ptr, ec] = std::from_chars(
        size_text.data(), size_text.data() + size_text.size(), chunk_size, 16);
    if (ec != std::errc{} || ptr != size_text.data() + size_text.size()) {
      return fail_j<std::string>(ErrorCode::provider_transport,
                                 JupyterErrorDetail::http_protocol_error);
    }
    if (chunk_size == 0U) {
      // Drain trailing headers until empty line.
      while (true) {
        auto trailer = read_crlf_line(stream, deadline);
        if (!trailer.has_value()) {
          return Result<std::string>::failure(trailer.error());
        }
        if (trailer.value().empty()) {
          break;
        }
      }
      return Result<std::string>::success(std::move(body));
    }
    if (chunk_size > max_bytes || body.size() > max_bytes - chunk_size) {
      return fail_j<std::string>(ErrorCode::capacity,
                                 JupyterErrorDetail::response_too_large);
    }
    const std::size_t old_size = body.size();
    body.resize(old_size + chunk_size);
    auto read_res = stream.read_exact(
        std::span<std::uint8_t>{
            reinterpret_cast<std::uint8_t *>(body.data() + old_size), chunk_size},
        deadline);
    if (!read_res.has_value()) {
      return Result<std::string>::failure(read_res.error());
    }
    std::array<std::uint8_t, 2U> crlf{};
    auto end_res = stream.read_exact(crlf, deadline);
    if (!end_res.has_value() || crlf[0U] != '\r' || crlf[1U] != '\n') {
      return fail_j<std::string>(ErrorCode::provider_transport,
                                 JupyterErrorDetail::http_protocol_error);
    }
  }
}

Result<std::string> read_http_body(TransportStream &stream,
                                   const HttpResponseHead &head, std::size_t max_bytes,
                                   SteadyClock::time_point deadline) {
  if (head.status_code == 204 || head.status_code == 304 ||
      (head.status_code >= 100 && head.status_code < 200)) {
    return Result<std::string>::success(std::string{});
  }

  bool has_chunked = false;
  std::optional<std::size_t> content_length;
  for (const auto &h : head.headers) {
    if (h.name_lower == "transfer-encoding") {
      if (header_contains_token_icase({h.value, "chunked"})) {
        has_chunked = true;
      }
    } else if (h.name_lower == "content-length") {
      std::size_t len = 0U;
      const auto trimmed = trim_ascii_ws(h.value);
      const auto [ptr, ec] =
          std::from_chars(trimmed.data(), trimmed.data() + trimmed.size(), len);
      if (ec != std::errc{} || ptr != trimmed.data() + trimmed.size()) {
        return fail_j<std::string>(ErrorCode::provider_transport,
                                   JupyterErrorDetail::http_protocol_error);
      }
      if (content_length.has_value() && *content_length != len) {
        return fail_j<std::string>(ErrorCode::provider_transport,
                                   JupyterErrorDetail::http_protocol_error);
      }
      content_length = len;
    }
  }

  if (has_chunked && content_length.has_value()) {
    return fail_j<std::string>(ErrorCode::provider_transport,
                               JupyterErrorDetail::http_protocol_error);
  }
  if (has_chunked) {
    return read_chunked_http_body(stream, max_bytes, deadline);
  }
  if (content_length.has_value()) {
    if (*content_length > max_bytes) {
      return fail_j<std::string>(ErrorCode::capacity,
                                 JupyterErrorDetail::response_too_large);
    }
    std::string body(*content_length, '\0');
    if (*content_length > 0U) {
      auto r = stream.read_exact(
          std::span<std::uint8_t>{reinterpret_cast<std::uint8_t *>(body.data()),
                                  body.size()},
          deadline);
      if (!r.has_value()) {
        return Result<std::string>::failure(r.error());
      }
    }
    return Result<std::string>::success(std::move(body));
  }

  // Fallback for Connection: close without Content-Length.
  std::string body;
  std::array<std::uint8_t, 4096U> buf{};
  while (true) {
    auto got = stream.read_some(buf, deadline);
    if (!got.has_value()) {
      return Result<std::string>::failure(got.error());
    }
    if (got.value() == 0U) {
      break;
    }
    if (got.value() > max_bytes || body.size() > max_bytes - got.value()) {
      return fail_j<std::string>(ErrorCode::capacity,
                                 JupyterErrorDetail::response_too_large);
    }
    body.append(reinterpret_cast<const char *>(buf.data()), got.value());
  }
  return Result<std::string>::success(std::move(body));
}

// ---------------------------------------------------------------------------
// RFC 6455 WebSocket v13 Frame Writer & Reader
// ---------------------------------------------------------------------------

enum class WsOpcode : std::uint8_t {
  continuation = 0x0U,
  text = 0x1U,
  binary = 0x2U,
  close = 0x8U,
  ping = 0x9U,
  pong = 0xAU,
};

Result<void> write_ws_masked_frame(TransportStream &stream, WsOpcode opcode,
                                   std::span<const std::uint8_t> payload,
                                   SteadyClock::time_point deadline) {
  std::array<std::uint8_t, 4U> mask{};
  if (RAND_bytes(mask.data(), static_cast<int>(mask.size())) != 1) {
    return fail_jv(ErrorCode::provider_transport, JupyterErrorDetail::crypto_error);
  }
  std::vector<std::uint8_t> frame;
  frame.reserve(14U + payload.size());
  frame.push_back(static_cast<std::uint8_t>(0x80U | static_cast<std::uint8_t>(opcode)));
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
    frame.push_back(static_cast<std::uint8_t>(payload[i] ^ mask[i & 3U]));
  }
  return stream.write_all(frame, deadline);
}

struct WsMessage {
  WsOpcode opcode = WsOpcode::text;
  std::string payload;
};

Result<WsMessage> read_ws_message(TransportStream &stream, std::size_t max_frame_bytes,
                                  SteadyClock::time_point deadline) {
  bool in_fragment = false;
  WsOpcode message_opcode = WsOpcode::text;
  std::string assembled;
  std::size_t fragment_count = 0U;

  while (true) {
    std::array<std::uint8_t, 2U> hdr{};
    auto r = stream.read_exact(hdr, deadline);
    if (!r.has_value()) {
      return Result<WsMessage>::failure(r.error());
    }
    const bool fin = (hdr[0U] & 0x80U) != 0U;
    const std::uint8_t rsv = static_cast<std::uint8_t>(hdr[0U] & 0x70U);
    const std::uint8_t raw_opcode = static_cast<std::uint8_t>(hdr[0U] & 0x0fU);
    const bool masked = (hdr[1U] & 0x80U) != 0U;
    const std::uint8_t len7 = static_cast<std::uint8_t>(hdr[1U] & 0x7fU);

    // RFC 6455: RSV bits must be 0 without extensions; server frames must not be
    // masked.
    if (rsv != 0U || masked) {
      return fail_j<WsMessage>(ErrorCode::provider_transport,
                               JupyterErrorDetail::ws_protocol_error);
    }

    std::uint64_t payload_len = len7;
    if (len7 == 126U) {
      std::array<std::uint8_t, 2U> ext{};
      auto er = stream.read_exact(ext, deadline);
      if (!er.has_value()) {
        return Result<WsMessage>::failure(er.error());
      }
      payload_len = (static_cast<std::uint64_t>(ext[0U]) << 8U) |
                    static_cast<std::uint64_t>(ext[1U]);
    } else if (len7 == 127U) {
      std::array<std::uint8_t, 8U> ext{};
      auto er = stream.read_exact(ext, deadline);
      if (!er.has_value()) {
        return Result<WsMessage>::failure(er.error());
      }
      if ((ext[0U] & 0x80U) != 0U) {
        return fail_j<WsMessage>(ErrorCode::provider_transport,
                                 JupyterErrorDetail::ws_protocol_error);
      }
      payload_len = 0U;
      for (const std::uint8_t b : ext) {
        payload_len = (payload_len << 8U) | static_cast<std::uint64_t>(b);
      }
    }

    const bool is_control = (raw_opcode & 0x08U) != 0U;
    if (is_control) {
      if (!fin || payload_len > kMaxWsControlPayload) {
        return fail_j<WsMessage>(ErrorCode::provider_transport,
                                 JupyterErrorDetail::ws_protocol_error);
      }
      std::vector<std::uint8_t> ctrl_payload(static_cast<std::size_t>(payload_len));
      if (!ctrl_payload.empty()) {
        auto cr = stream.read_exact(ctrl_payload, deadline);
        if (!cr.has_value()) {
          return Result<WsMessage>::failure(cr.error());
        }
      }
      if (raw_opcode == static_cast<std::uint8_t>(WsOpcode::ping)) {
        auto pr = write_ws_masked_frame(stream, WsOpcode::pong, ctrl_payload, deadline);
        if (!pr.has_value()) {
          return Result<WsMessage>::failure(pr.error());
        }
        continue;
      }
      if (raw_opcode == static_cast<std::uint8_t>(WsOpcode::pong)) {
        continue;
      }
      if (raw_opcode == static_cast<std::uint8_t>(WsOpcode::close)) {
        std::array<std::uint8_t, 2U> close_code{0x03U, 0xe8U}; // 1000 normal closure
        (void)write_ws_masked_frame(stream, WsOpcode::close, close_code, deadline);
        return fail_j<WsMessage>(ErrorCode::provider_transport,
                                 JupyterErrorDetail::ws_closed_unexpectedly);
      }
      return fail_j<WsMessage>(ErrorCode::provider_transport,
                               JupyterErrorDetail::ws_protocol_error);
    }

    if (raw_opcode != static_cast<std::uint8_t>(WsOpcode::continuation) &&
        raw_opcode != static_cast<std::uint8_t>(WsOpcode::text) &&
        raw_opcode != static_cast<std::uint8_t>(WsOpcode::binary)) {
      return fail_j<WsMessage>(ErrorCode::provider_transport,
                               JupyterErrorDetail::ws_protocol_error);
    }

    if (raw_opcode == static_cast<std::uint8_t>(WsOpcode::continuation)) {
      if (!in_fragment) {
        return fail_j<WsMessage>(ErrorCode::provider_transport,
                                 JupyterErrorDetail::ws_protocol_error);
      }
    } else {
      if (in_fragment) {
        return fail_j<WsMessage>(ErrorCode::provider_transport,
                                 JupyterErrorDetail::ws_protocol_error);
      }
      message_opcode = static_cast<WsOpcode>(raw_opcode);
      in_fragment = true;
    }

    ++fragment_count;
    if (fragment_count > kMaxWsFragmentsPerMessage) {
      return fail_j<WsMessage>(ErrorCode::capacity,
                               JupyterErrorDetail::response_too_large);
    }
    if (payload_len > max_frame_bytes ||
        assembled.size() > max_frame_bytes - static_cast<std::size_t>(payload_len)) {
      return fail_j<WsMessage>(ErrorCode::capacity,
                               JupyterErrorDetail::response_too_large);
    }

    const std::size_t old_size = assembled.size();
    const auto frag_len = static_cast<std::size_t>(payload_len);
    assembled.resize(old_size + frag_len);
    if (frag_len > 0U) {
      auto fr = stream.read_exact(
          std::span<std::uint8_t>{
              reinterpret_cast<std::uint8_t *>(assembled.data() + old_size), frag_len},
          deadline);
      if (!fr.has_value()) {
        return Result<WsMessage>::failure(fr.error());
      }
    }

    if (fin) {
      return Result<WsMessage>::success(
          WsMessage{.opcode = message_opcode, .payload = std::move(assembled)});
    }
  }
}

// ---------------------------------------------------------------------------
// Jupyter REST / Wire JSON Helpers
// ---------------------------------------------------------------------------

Result<JupyterKernelInfo> parse_kernel_info_value(const Value &val) {
  if (!std::holds_alternative<Value::Object>(val.value())) {
    return fail_j<JupyterKernelInfo>(ErrorCode::corrupt,
                                     JupyterErrorDetail::http_protocol_error);
  }
  const Value *id_val = val.find("id");
  const Value *name_val = val.find("name");
  if (id_val == nullptr || !std::holds_alternative<std::string>(id_val->value()) ||
      name_val == nullptr || !std::holds_alternative<std::string>(name_val->value())) {
    return fail_j<JupyterKernelInfo>(ErrorCode::corrupt,
                                     JupyterErrorDetail::http_protocol_error);
  }
  JupyterKernelInfo info;
  info.id = id_val->string();
  info.name = name_val->string();
  if (const Value *state = val.find("execution_state");
      state != nullptr && std::holds_alternative<std::string>(state->value())) {
    info.execution_state = state->string();
  }
  if (const Value *last = val.find("last_activity");
      last != nullptr && std::holds_alternative<std::string>(last->value())) {
    info.last_activity = last->string();
  }
  if (const Value *conns = val.find("connections")) {
    if (const auto count = extract_strict_uint64(*conns)) {
      info.connections = *count;
    }
  }
  return Result<JupyterKernelInfo>::success(std::move(info));
}

// ---------------------------------------------------------------------------
// Passive Subprocess Probe Helpers
// ---------------------------------------------------------------------------

bool is_executable_regular_file(const std::string &path) noexcept {
  struct stat st{};
  if (::stat(path.c_str(), &st) != 0) {
    return false;
  }
  if (!S_ISREG(st.st_mode)) {
    return false;
  }
  return ::access(path.c_str(), X_OK) == 0;
}

std::optional<std::string> resolve_jupyter_executable(std::string_view override_path) {
  if (!override_path.empty()) {
    std::string candidate{override_path};
    if (is_executable_regular_file(candidate)) {
      return candidate;
    }
    return std::nullopt;
  }
  const char *path_env = std::getenv("PATH");
  if (path_env == nullptr || *path_env == '\0') {
    return std::nullopt;
  }
  std::string_view remaining{path_env};
  while (!remaining.empty()) {
    const std::size_t colon = remaining.find(':');
    const std::string_view dir =
        colon == std::string_view::npos ? remaining : remaining.substr(0U, colon);
    // Security: strictly ignore empty or relative PATH entries (e.g. ".") so passive
    // discovery never executes an untrusted ./jupyter from the current working
    // directory.
    if (!dir.empty() && dir.front() == '/') {
      std::string candidate{dir};
      if (candidate.back() != '/') {
        candidate.push_back('/');
      }
      candidate.append("jupyter");
      if (is_executable_regular_file(candidate)) {
        return candidate;
      }
    }
    if (colon == std::string_view::npos) {
      break;
    }
    remaining.remove_prefix(colon + 1U);
  }
  return std::nullopt;
}

std::vector<std::string> build_clean_probe_env() {
  static constexpr std::array<std::string_view, 12U> kAllowedVars = {
      "PATH",
      "HOME",
      "USER",
      "TMPDIR",
      "JUPYTER_PATH",
      "JUPYTER_DATA_DIR",
      "JUPYTER_CONFIG_DIR",
      "CONDA_PREFIX",
      "VIRTUAL_ENV",
      "LANG",
      "LC_ALL",
      "PYTHONUTF8",
  };
  std::vector<std::string> env;
  env.reserve(kAllowedVars.size());
  for (const std::string_view key : kAllowedVars) {
    const std::string key_str{key};
    const char *val = std::getenv(key_str.c_str());
    if (val != nullptr) {
      env.push_back(key_str + "=" + val);
    }
  }
  return env;
}

struct PipeFds {
  ScopedFd read_end;
  ScopedFd write_end;
};

std::optional<PipeFds> make_cloexec_pipe() noexcept {
  int fds[2] = {-1, -1};
  if (::pipe(fds) != 0) {
    return std::nullopt;
  }
  ScopedFd raw_r{fds[0]};
  ScopedFd raw_w{fds[1]};
  // Move both ends above STDERR_FILENO with FD_CLOEXEC so posix_spawn
  // adddup2(..., STDOUT_FILENO) can never collide with FD 1 as a no-op.
  ScopedFd r{::fcntl(raw_r.get(), F_DUPFD_CLOEXEC, STDERR_FILENO + 1)};
  ScopedFd w{::fcntl(raw_w.get(), F_DUPFD_CLOEXEC, STDERR_FILENO + 1)};
  if (!r || !w) {
    return std::nullopt;
  }
  return PipeFds{.read_end = std::move(r), .write_end = std::move(w)};
}

void kill_and_reap_pgroup(pid_t pid) noexcept {
  if (pid <= 0) {
    return;
  }
  int status = 0;
  if (::waitpid(pid, &status, WNOHANG) == pid) {
    return;
  }
  (void)::kill(-pid, SIGTERM);
  const auto grace_end = SteadyClock::now() + std::chrono::milliseconds{150};
  while (SteadyClock::now() < grace_end) {
    if (::waitpid(pid, &status, WNOHANG) == pid) {
      return;
    }
    pollfd dummy{};
    (void)::poll(&dummy, 0U, 10);
  }
  (void)::kill(-pid, SIGKILL);
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
}

} // namespace

// ---------------------------------------------------------------------------
// Public Part 1: .ipynb Structural Engine & Output Hygiene
// ---------------------------------------------------------------------------

std::string_view notebook_cell_type_name(NotebookCellType type) noexcept {
  switch (type) {
  case NotebookCellType::code:
    return "code";
  case NotebookCellType::markdown:
    return "markdown";
  case NotebookCellType::raw:
    return "raw";
  }
  return "code";
}

std::optional<NotebookCellType>
parse_notebook_cell_type(std::string_view name) noexcept {
  if (name == "code") {
    return NotebookCellType::code;
  }
  if (name == "markdown") {
    return NotebookCellType::markdown;
  }
  if (name == "raw") {
    return NotebookCellType::raw;
  }
  return std::nullopt;
}

std::string_view notebook_output_type_name(NotebookOutputType type) noexcept {
  switch (type) {
  case NotebookOutputType::stream:
    return "stream";
  case NotebookOutputType::execute_result:
    return "execute_result";
  case NotebookOutputType::display_data:
    return "display_data";
  case NotebookOutputType::error:
    return "error";
  }
  return "stream";
}

std::optional<NotebookOutputType>
parse_notebook_output_type(std::string_view name) noexcept {
  if (name == "stream") {
    return NotebookOutputType::stream;
  }
  if (name == "execute_result") {
    return NotebookOutputType::execute_result;
  }
  if (name == "display_data") {
    return NotebookOutputType::display_data;
  }
  if (name == "error") {
    return NotebookOutputType::error;
  }
  return std::nullopt;
}

Result<NotebookDocument> parse_ipynb(std::string_view json, ValueLimits limits) {
  auto parsed = parse_json(json, limits);
  if (!parsed.has_value()) {
    return fail_j<NotebookDocument>(parsed.error().code,
                                    JupyterErrorDetail::invalid_json);
  }
  const Value &root = parsed.value();
  if (!std::holds_alternative<Value::Object>(root.value())) {
    return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                    JupyterErrorDetail::invalid_notebook_schema);
  }

  const Value *nbformat_val = root.find("nbformat");
  if (nbformat_val == nullptr) {
    return fail_j<NotebookDocument>(ErrorCode::unsupported,
                                    JupyterErrorDetail::unsupported_nbformat);
  }
  const auto nbformat = extract_strict_int64(*nbformat_val);
  if (!nbformat.has_value() || *nbformat != 4) {
    return fail_j<NotebookDocument>(ErrorCode::unsupported,
                                    JupyterErrorDetail::unsupported_nbformat);
  }

  std::int64_t nbformat_minor = 0;
  if (const Value *minor_val = root.find("nbformat_minor")) {
    const auto parsed_minor = extract_strict_int64(*minor_val);
    if (!parsed_minor.has_value() || *parsed_minor < 0) {
      return fail_j<NotebookDocument>(ErrorCode::unsupported,
                                      JupyterErrorDetail::unsupported_nbformat);
    }
    nbformat_minor = *parsed_minor;
  } else {
    return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                    JupyterErrorDetail::invalid_notebook_schema);
  }

  NotebookDocument doc;
  doc.nbformat = *nbformat;
  doc.nbformat_minor = nbformat_minor;

  // Parse metadata.
  if (const Value *meta_val = root.find("metadata")) {
    if (!std::holds_alternative<Value::Object>(meta_val->value())) {
      return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                      JupyterErrorDetail::invalid_notebook_schema);
    }
    Value::Object extra_meta;
    for (const auto &[key, val] : meta_val->object()) {
      if (key == "kernelspec") {
        if (!std::holds_alternative<Value::Object>(val.value())) {
          return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                          JupyterErrorDetail::invalid_notebook_schema);
        }
        NotebookKernelSpec spec;
        Value::Object spec_extra;
        for (const auto &[sk, sv] : val.object()) {
          if (sk == "name" && std::holds_alternative<std::string>(sv.value())) {
            spec.name = sv.string();
          } else if (sk == "display_name" &&
                     std::holds_alternative<std::string>(sv.value())) {
            spec.display_name = sv.string();
          } else if (sk == "language" &&
                     std::holds_alternative<std::string>(sv.value())) {
            spec.language = sv.string();
          } else {
            spec_extra.emplace_back(sk, sv);
          }
        }
        spec.extra = Value::object(std::move(spec_extra));
        doc.metadata.kernelspec = std::move(spec);
      } else if (key == "language_info") {
        if (!std::holds_alternative<Value::Object>(val.value())) {
          return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                          JupyterErrorDetail::invalid_notebook_schema);
        }
        NotebookLanguageInfo lang;
        Value::Object lang_extra;
        for (const auto &[lk, lv] : val.object()) {
          if (lk == "name" && std::holds_alternative<std::string>(lv.value())) {
            lang.name = lv.string();
          } else if (lk == "version" &&
                     std::holds_alternative<std::string>(lv.value())) {
            lang.version = lv.string();
          } else if (lk == "mimetype" &&
                     std::holds_alternative<std::string>(lv.value())) {
            lang.mimetype = lv.string();
          } else if (lk == "file_extension" &&
                     std::holds_alternative<std::string>(lv.value())) {
            lang.file_extension = lv.string();
          } else {
            lang_extra.emplace_back(lk, lv);
          }
        }
        lang.extra = Value::object(std::move(lang_extra));
        doc.metadata.language_info = std::move(lang);
      } else {
        extra_meta.emplace_back(key, val);
      }
    }
    doc.metadata.extra = Value::object(std::move(extra_meta));
  }

  // Parse cells.
  const Value *cells_val = root.find("cells");
  if (cells_val == nullptr ||
      !std::holds_alternative<Value::Array>(cells_val->value())) {
    return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                    JupyterErrorDetail::invalid_notebook_schema);
  }
  doc.cells.reserve(cells_val->array().size());

  for (const auto &cell_val : cells_val->array()) {
    if (!std::holds_alternative<Value::Object>(cell_val.value())) {
      return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                      JupyterErrorDetail::invalid_cell_schema);
    }
    const Value *ct_val = cell_val.find("cell_type");
    if (ct_val == nullptr || !std::holds_alternative<std::string>(ct_val->value())) {
      return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                      JupyterErrorDetail::invalid_cell_schema);
    }
    const auto cell_type = parse_notebook_cell_type(ct_val->string());
    if (!cell_type.has_value()) {
      return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                      JupyterErrorDetail::invalid_cell_schema);
    }
    const Value *src_val = cell_val.find("source");
    if (src_val == nullptr) {
      return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                      JupyterErrorDetail::invalid_cell_schema);
    }
    auto source_res = normalize_nbformat_text(*src_val);
    if (!source_res.has_value()) {
      return Result<NotebookDocument>::failure(source_res.error());
    }

    NotebookCell cell;
    cell.cell_type = *cell_type;
    cell.source = std::move(source_res).value();

    if (const Value *id_val = cell_val.find("id")) {
      if (!std::holds_alternative<std::string>(id_val->value()) ||
          !valid_cell_id(id_val->string())) {
        return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                        JupyterErrorDetail::invalid_cell_schema);
      }
      cell.id = id_val->string();
    }

    if (const Value *cmeta = cell_val.find("metadata")) {
      if (!std::holds_alternative<Value::Object>(cmeta->value())) {
        return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                        JupyterErrorDetail::invalid_cell_schema);
      }
      cell.metadata = *cmeta;
    }

    if (const Value *att = cell_val.find("attachments")) {
      if (!std::holds_alternative<Value::Object>(att->value())) {
        return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                        JupyterErrorDetail::invalid_cell_schema);
      }
      cell.attachments = *att;
    }

    if (cell.cell_type == NotebookCellType::code) {
      if (const Value *exec_val = cell_val.find("execution_count")) {
        if (!std::holds_alternative<std::nullptr_t>(exec_val->value())) {
          const auto count = extract_strict_int64(*exec_val);
          if (!count.has_value()) {
            return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                            JupyterErrorDetail::invalid_cell_schema);
          }
          cell.execution_count = *count;
        }
      }
      if (const Value *outs_val = cell_val.find("outputs")) {
        if (!std::holds_alternative<Value::Array>(outs_val->value())) {
          return fail_j<NotebookDocument>(ErrorCode::corrupt,
                                          JupyterErrorDetail::invalid_output_schema);
        }
        cell.outputs.reserve(outs_val->array().size());
        for (const auto &out_item : outs_val->array()) {
          auto out_res = parse_notebook_output_value(out_item);
          if (!out_res.has_value()) {
            return Result<NotebookDocument>::failure(out_res.error());
          }
          cell.outputs.push_back(std::move(out_res).value());
        }
      }
    }

    doc.cells.push_back(std::move(cell));
  }

  return Result<NotebookDocument>::success(std::move(doc));
}

Result<std::string> serialize_ipynb(const NotebookDocument &doc, ValueLimits limits) {
  if (doc.nbformat != 4) {
    return fail_j<std::string>(ErrorCode::unsupported,
                               JupyterErrorDetail::unsupported_nbformat);
  }

  // Collect explicit cell IDs first so synthesized IDs never collide.
  std::set<std::string> used_ids;
  for (const auto &cell : doc.cells) {
    if (!cell.id.empty()) {
      if (!valid_cell_id(cell.id)) {
        return fail_j<std::string>(ErrorCode::corrupt,
                                   JupyterErrorDetail::invalid_cell_schema);
      }
      used_ids.insert(cell.id);
    }
  }

  Value::Array cells_arr;
  cells_arr.reserve(doc.cells.size());
  for (std::size_t i = 0U; i < doc.cells.size(); ++i) {
    const auto &cell = doc.cells[i];
    std::string cell_id = cell.id;
    if (cell_id.empty()) {
      cell_id = generate_unique_cell_id(used_ids, i);
      used_ids.insert(cell_id);
    }

    Value::Object cell_obj;
    cell_obj.emplace_back("cell_type",
                          Value{std::string{notebook_cell_type_name(cell.cell_type)}});
    if (cell.cell_type == NotebookCellType::code) {
      if (cell.execution_count.has_value()) {
        cell_obj.emplace_back("execution_count", Value{Number{*cell.execution_count}});
      } else {
        cell_obj.emplace_back("execution_count", Value{nullptr});
      }
    }
    cell_obj.emplace_back("id", Value{std::move(cell_id)});
    cell_obj.emplace_back("metadata",
                          std::holds_alternative<Value::Object>(cell.metadata.value())
                              ? cell.metadata
                              : Value::object({}));
    if (cell.attachments.has_value() &&
        std::holds_alternative<Value::Object>(cell.attachments->value())) {
      cell_obj.emplace_back("attachments", *cell.attachments);
    }
    if (cell.cell_type == NotebookCellType::code) {
      Value::Array outputs_arr;
      outputs_arr.reserve(cell.outputs.size());
      for (const auto &out : cell.outputs) {
        outputs_arr.push_back(serialize_notebook_output_value(out));
      }
      cell_obj.emplace_back("outputs", Value{std::move(outputs_arr)});
    }
    cell_obj.emplace_back("source", split_nbformat_lines(cell.source));
    cells_arr.push_back(Value::object(std::move(cell_obj)));
  }

  Value::Object meta_obj;
  if (doc.metadata.kernelspec.has_value()) {
    const auto &ks = *doc.metadata.kernelspec;
    Value::Object ks_obj;
    if (!ks.display_name.empty()) {
      ks_obj.emplace_back("display_name", Value{ks.display_name});
    }
    if (!ks.language.empty()) {
      ks_obj.emplace_back("language", Value{ks.language});
    }
    if (!ks.name.empty()) {
      ks_obj.emplace_back("name", Value{ks.name});
    }
    if (std::holds_alternative<Value::Object>(ks.extra.value())) {
      for (const auto &[k, v] : ks.extra.object()) {
        if (k != "display_name" && k != "language" && k != "name") {
          ks_obj.emplace_back(k, v);
        }
      }
    }
    meta_obj.emplace_back("kernelspec", Value::object(std::move(ks_obj)));
  }
  if (doc.metadata.language_info.has_value()) {
    const auto &li = *doc.metadata.language_info;
    Value::Object li_obj;
    if (!li.file_extension.empty()) {
      li_obj.emplace_back("file_extension", Value{li.file_extension});
    }
    if (!li.mimetype.empty()) {
      li_obj.emplace_back("mimetype", Value{li.mimetype});
    }
    if (!li.name.empty()) {
      li_obj.emplace_back("name", Value{li.name});
    }
    if (!li.version.empty()) {
      li_obj.emplace_back("version", Value{li.version});
    }
    if (std::holds_alternative<Value::Object>(li.extra.value())) {
      for (const auto &[k, v] : li.extra.object()) {
        if (k != "file_extension" && k != "mimetype" && k != "name" && k != "version") {
          li_obj.emplace_back(k, v);
        }
      }
    }
    meta_obj.emplace_back("language_info", Value::object(std::move(li_obj)));
  }
  if (std::holds_alternative<Value::Object>(doc.metadata.extra.value())) {
    for (const auto &[k, v] : doc.metadata.extra.object()) {
      if (k != "kernelspec" && k != "language_info") {
        meta_obj.emplace_back(k, v);
      }
    }
  }

  Value::Object root;
  root.emplace_back("cells", Value{std::move(cells_arr)});
  root.emplace_back("metadata", Value::object(std::move(meta_obj)));
  root.emplace_back("nbformat", Value{Number{std::int64_t{4}}});
  root.emplace_back("nbformat_minor", Value{Number{std::int64_t{5}}});
  return dump_json(Value::object(std::move(root)), limits);
}

std::string strip_ansi_and_control_sequences(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  std::size_t i = 0U;
  while (i < text.size()) {
    const auto ch = static_cast<unsigned char>(text[i]);
    if (ch == 0x1bU) { // ESC
      ++i;
      if (i >= text.size()) {
        break;
      }
      const auto next = static_cast<unsigned char>(text[i]);
      if (next == '[') {
        // CSI: ESC [ params (0x30..0x3F) intermediates (0x20..0x2F) final (0x40..0x7E)
        ++i;
        while (i < text.size()) {
          const auto b = static_cast<unsigned char>(text[i]);
          ++i;
          if (b >= 0x40U && b <= 0x7eU) {
            break;
          }
        }
      } else if (next == ']') {
        // OSC: ESC ] ... (BEL or ESC \)
        ++i;
        while (i < text.size()) {
          const auto b = static_cast<unsigned char>(text[i]);
          if (b == 0x07U) {
            ++i;
            break;
          }
          if (b == 0x1bU && i + 1U < text.size() && text[i + 1U] == '\\') {
            i += 2U;
            break;
          }
          ++i;
        }
      } else if (next == 'P' || next == 'X' || next == '^' || next == '_') {
        // DCS / SOS / PM / APC: terminated by ST (ESC \)
        ++i;
        while (i < text.size()) {
          if (static_cast<unsigned char>(text[i]) == 0x1bU && i + 1U < text.size() &&
              text[i + 1U] == '\\') {
            i += 2U;
            break;
          }
          ++i;
        }
      } else if (next >= 0x20U && next <= 0x2fU) {
        // nF escape sequence: intermediate bytes followed by final 0x30..0x7E
        ++i;
        while (i < text.size()) {
          const auto b = static_cast<unsigned char>(text[i]);
          ++i;
          if (b >= 0x30U && b <= 0x7eU) {
            break;
          }
        }
      } else {
        // Two-byte escape sequence.
        ++i;
      }
      continue;
    }

    // UTF-8 encoded C1 controls (U+0080..U+009F -> 0xC2 0x80..0x9F).
    if (ch == 0xc2U && i + 1U < text.size()) {
      const auto b2 = static_cast<unsigned char>(text[i + 1U]);
      if (b2 >= 0x80U && b2 <= 0x9fU) {
        i += 2U;
        continue;
      }
    }

    if (ch == '\r') {
      if (i + 1U < text.size() && text[i + 1U] == '\n') {
        out.push_back('\n');
        i += 2U;
      } else {
        ++i;
      }
      continue;
    }

    if (ch == '\n' || ch == '\t' || (ch >= 0x20U && ch != 0x7fU)) {
      out.push_back(static_cast<char>(ch));
    }
    ++i;
  }
  return out;
}

std::string summarize_notebook_output(const NotebookOutput &output,
                                      const NotebookHygieneOptions &options) {
  switch (output.output_type) {
  case NotebookOutputType::stream: {
    std::string text = options.strip_ansi
                           ? strip_ansi_and_control_sequences(output.text)
                           : output.text;
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
      text.pop_back();
    }
    if (text.size() > options.max_text_chars) {
      const std::size_t omitted = text.size() - options.max_text_chars;
      text = truncate_utf8(text, options.max_text_chars);
      text.append("... (+");
      text.append(std::to_string(omitted));
      text.append(" bytes)");
    }
    return "stream(" + output.stream_name + "): " + text;
  }
  case NotebookOutputType::execute_result: {
    std::string prefix = "execute_result";
    if (output.execution_count.has_value()) {
      prefix.push_back('[');
      prefix.append(std::to_string(*output.execution_count));
      prefix.push_back(']');
    }
    return prefix + ": " + summarize_mime_entries(output.data, options);
  }
  case NotebookOutputType::display_data:
    return "display_data: " + summarize_mime_entries(output.data, options);
  case NotebookOutputType::error: {
    std::string out =
        "error(" +
        (options.strip_ansi ? strip_ansi_and_control_sequences(output.ename)
                            : output.ename) +
        ": " +
        (options.strip_ansi ? strip_ansi_and_control_sequences(output.evalue)
                            : output.evalue) +
        ")";
    if (!output.traceback.empty() && options.max_traceback_lines > 0U) {
      const std::size_t show =
          std::min(output.traceback.size(), options.max_traceback_lines);
      for (std::size_t i = 0U; i < show; ++i) {
        std::string line = options.strip_ansi
                               ? strip_ansi_and_control_sequences(output.traceback[i])
                               : output.traceback[i];
        out.push_back('\n');
        out.append("  ");
        out.append(truncate_utf8(line, options.max_text_chars));
      }
      if (output.traceback.size() > show) {
        out.append("\n  ... (+");
        out.append(std::to_string(output.traceback.size() - show));
        out.append(" traceback lines)");
      }
    }
    return out;
  }
  }
  return {};
}

Result<void> replace_cell_source(NotebookDocument &doc, std::size_t cell_index,
                                 std::string new_source) {
  if (cell_index >= doc.cells.size()) {
    return fail_jv(ErrorCode::invalid_range, JupyterErrorDetail::invalid_cell_index);
  }
  if (!valid_utf8(new_source)) {
    return fail_jv(ErrorCode::corrupt, JupyterErrorDetail::invalid_cell_schema);
  }
  doc.cells[cell_index].source = std::move(new_source);
  return Result<void>::success();
}

Result<void> insert_cell(NotebookDocument &doc, std::size_t index, NotebookCell cell) {
  if (index > doc.cells.size()) {
    return fail_jv(ErrorCode::invalid_range, JupyterErrorDetail::invalid_cell_index);
  }
  if (!valid_utf8(cell.source)) {
    return fail_jv(ErrorCode::corrupt, JupyterErrorDetail::invalid_cell_schema);
  }
  std::set<std::string> used_ids;
  for (const auto &existing : doc.cells) {
    if (!existing.id.empty()) {
      used_ids.insert(existing.id);
    }
  }
  if (cell.id.empty()) {
    cell.id = generate_unique_cell_id(used_ids, doc.cells.size());
  } else if (!valid_cell_id(cell.id)) {
    return fail_jv(ErrorCode::corrupt, JupyterErrorDetail::invalid_cell_schema);
  }
  if (cell.cell_type != NotebookCellType::code) {
    cell.execution_count = std::nullopt;
    cell.outputs.clear();
  }
  doc.cells.insert(doc.cells.begin() + static_cast<std::ptrdiff_t>(index),
                   std::move(cell));
  return Result<void>::success();
}

Result<void> delete_cell(NotebookDocument &doc, std::size_t cell_index) {
  if (cell_index >= doc.cells.size()) {
    return fail_jv(ErrorCode::invalid_range, JupyterErrorDetail::invalid_cell_index);
  }
  doc.cells.erase(doc.cells.begin() + static_cast<std::ptrdiff_t>(cell_index));
  return Result<void>::success();
}

Result<void> update_cell_outputs(NotebookDocument &doc, std::size_t cell_index,
                                 std::vector<NotebookOutput> outputs,
                                 std::optional<std::int64_t> execution_count) {
  if (cell_index >= doc.cells.size()) {
    return fail_jv(ErrorCode::invalid_range, JupyterErrorDetail::invalid_cell_index);
  }
  if (doc.cells[cell_index].cell_type != NotebookCellType::code) {
    return fail_jv(ErrorCode::invalid_range, JupyterErrorDetail::invalid_cell_schema);
  }
  doc.cells[cell_index].outputs = std::move(outputs);
  doc.cells[cell_index].execution_count = execution_count;
  return Result<void>::success();
}

std::string format_notebook_outline(const NotebookDocument &doc,
                                    const NotebookOutlineOptions &options) {
  std::string out;
  out.append("Notebook nbformat ");
  out.append(std::to_string(doc.nbformat));
  out.push_back('.');
  out.append(std::to_string(doc.nbformat_minor));
  if (doc.metadata.kernelspec.has_value() && !doc.metadata.kernelspec->name.empty()) {
    out.append(" | kernel=");
    out.append(doc.metadata.kernelspec->name);
  }
  if (doc.metadata.language_info.has_value() &&
      !doc.metadata.language_info->name.empty()) {
    out.append(" | lang=");
    out.append(doc.metadata.language_info->name);
  }
  out.append(" | cells=");
  out.append(std::to_string(doc.cells.size()));
  out.push_back('\n');

  for (std::size_t i = 0U; i < doc.cells.size(); ++i) {
    const auto &cell = doc.cells[i];
    out.push_back('[');
    out.append(std::to_string(i));
    out.append("] ");
    out.append(notebook_cell_type_name(cell.cell_type));
    if (!cell.id.empty()) {
      out.append(" (");
      out.append(cell.id);
      if (cell.cell_type == NotebookCellType::code) {
        out.append(", exec=");
        if (cell.execution_count.has_value()) {
          out.append(std::to_string(*cell.execution_count));
        } else {
          out.push_back('-');
        }
      }
      out.push_back(')');
    } else if (cell.cell_type == NotebookCellType::code) {
      out.append(" (exec=");
      if (cell.execution_count.has_value()) {
        out.append(std::to_string(*cell.execution_count));
      } else {
        out.push_back('-');
      }
      out.push_back(')');
    }

    // First-line preview of cell source.
    std::string_view first_line = cell.source;
    const std::size_t nl = first_line.find('\n');
    const bool multiline = nl != std::string_view::npos;
    if (multiline) {
      first_line = first_line.substr(0U, nl);
    }
    std::string preview = strip_ansi_and_control_sequences(first_line);
    if (preview.size() > options.max_preview_chars) {
      preview = truncate_utf8(preview, options.max_preview_chars);
      preview.append("...");
    } else if (multiline) {
      preview.append(" ...");
    }
    out.append(": \"");
    out.append(preview);
    out.push_back('"');

    if (cell.cell_type == NotebookCellType::code) {
      out.append(" | outputs=");
      if (cell.outputs.empty()) {
        out.append("none");
      } else {
        out.append(std::to_string(cell.outputs.size()));
        out.append(" [");
        for (std::size_t j = 0U; j < cell.outputs.size(); ++j) {
          if (j > 0U) {
            out.append(" | ");
          }
          std::string summary =
              summarize_notebook_output(cell.outputs[j], options.hygiene);
          // Keep outline strictly single-line per cell.
          for (char &c : summary) {
            if (c == '\n' || c == '\r') {
              c = ' ';
            }
          }
          out.append(summary);
        }
        out.push_back(']');
      }
    }
    out.push_back('\n');
  }
  return out;
}

// ---------------------------------------------------------------------------
// Public Part 2: Service-Consumer Jupyter Server REST + WebSocket Client
// ---------------------------------------------------------------------------

struct JupyterClient::Impl {
  ParsedJupyterUrl url;
  std::string api_token;
  std::chrono::milliseconds connect_timeout{3000};
  std::chrono::milliseconds request_timeout{kJupyterDefaultTimeoutMs};
  std::size_t max_http_body_bytes = kJupyterDefaultMaxHttpBodyBytes;
  std::size_t max_ws_frame_bytes = kJupyterDefaultMaxWsFrameBytes;
  std::string last_error;

  ~Impl() {
    // Strictly consumer-only: NEVER shut down remote kernels in destructor.
    if (!api_token.empty()) {
      OPENSSL_cleanse(api_token.data(), api_token.size());
      api_token.clear();
    }
  }

  void set_error(std::string_view message) { last_error.assign(message); }

  struct RestRequest {
    std::string_view method;
    std::string path;
    std::string body;
  };

  struct RestResponse {
    int status_code = 0;
    std::string body;
  };

  Result<RestResponse> send_rest(const RestRequest &req) {
    const auto deadline = SteadyClock::now() + request_timeout;
    auto stream_res = TransportStream::connect(url, connect_timeout);
    if (!stream_res.has_value()) {
      set_error("failed to connect to Jupyter server");
      return Result<RestResponse>::failure(stream_res.error());
    }
    TransportStream stream = std::move(stream_res).value();

    const std::string host_hdr = build_host_header(url);
    const std::string content_len_str =
        req.body.empty() ? std::string{} : std::to_string(req.body.size());
    std::string wire;
    CleanseStringGuard wire_guard{wire};
    // Exact upper-bound reservation so wire never reallocates after appending
    // api_token.
    wire.reserve(256U + req.method.size() + url.base_path.size() + req.path.size() +
                 host_hdr.size() + api_token.size() + content_len_str.size() +
                 req.body.size());
    wire.append(req.method);
    wire.push_back(' ');
    wire.append(url.base_path);
    wire.append(req.path);
    wire.append(" HTTP/1.1\r\nHost: ");
    wire.append(host_hdr);
    wire.append("\r\nAccept: application/json\r\nConnection: close\r\n");
    if (!api_token.empty()) {
      wire.append("Authorization: token ");
      wire.append(api_token);
      wire.append("\r\n");
    }
    if (!req.body.empty()) {
      wire.append("Content-Type: application/json\r\nContent-Length: ");
      wire.append(content_len_str);
      wire.append("\r\n\r\n");
      wire.append(req.body);
    } else if (req.method == "POST" || req.method == "PUT" || req.method == "PATCH") {
      wire.append("Content-Length: 0\r\n\r\n");
    } else {
      wire.append("\r\n");
    }

    auto wr = stream.write_text(wire, deadline);
    if (!wr.has_value()) {
      set_error("failed to write HTTP request to Jupyter server");
      return Result<RestResponse>::failure(wr.error());
    }

    auto head_res = read_http_response_head(stream, deadline);
    if (!head_res.has_value()) {
      set_error("invalid HTTP response from Jupyter server");
      return Result<RestResponse>::failure(head_res.error());
    }
    const HttpResponseHead head = std::move(head_res).value();
    auto body_res = read_http_body(stream, head, max_http_body_bytes, deadline);
    if (!body_res.has_value()) {
      set_error("failed to read HTTP response body from Jupyter server");
      return Result<RestResponse>::failure(body_res.error());
    }

    if (head.status_code == 401 || head.status_code == 403) {
      set_error("Jupyter server rejected authentication (" +
                std::to_string(head.status_code) + ")");
      return fail_j<RestResponse>(ErrorCode::provider_auth,
                                  JupyterErrorDetail::auth_failed);
    }
    return Result<RestResponse>::success(RestResponse{
        .status_code = head.status_code, .body = std::move(body_res).value()});
  }
};

JupyterClient::JupyterClient(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

JupyterClient::JupyterClient(JupyterClient &&) noexcept = default;
JupyterClient &JupyterClient::operator=(JupyterClient &&) noexcept = default;
JupyterClient::~JupyterClient() = default;

Result<JupyterClient> JupyterClient::create(const JupyterClientConfig &config) {
  auto parsed_url = parse_jupyter_base_url(config.base_url);
  if (!parsed_url.has_value()) {
    return Result<JupyterClient>::failure(parsed_url.error());
  }
  if (config.api_token.size() > kMaxTokenBytes ||
      contains_ctl_or_crlf(config.api_token)) {
    return fail_j<JupyterClient>(ErrorCode::invalid_identity,
                                 JupyterErrorDetail::invalid_token);
  }
  if (config.connect_timeout.count() <= 0 || config.request_timeout.count() <= 0 ||
      config.max_http_body_bytes == 0U || config.max_ws_frame_bytes == 0U) {
    return fail_j<JupyterClient>(ErrorCode::invalid_range,
                                 JupyterErrorDetail::invalid_timeout);
  }

  auto impl = std::make_unique<Impl>();
  impl->url = std::move(parsed_url).value();
  impl->api_token = config.api_token;
  impl->connect_timeout = config.connect_timeout;
  impl->request_timeout = config.request_timeout;
  impl->max_http_body_bytes = config.max_http_body_bytes;
  impl->max_ws_frame_bytes = config.max_ws_frame_bytes;
  return Result<JupyterClient>::success(JupyterClient{std::move(impl)});
}

std::string_view JupyterClient::base_url() const noexcept {
  return impl_ ? std::string_view{impl_->url.normalized_url} : std::string_view{};
}

std::string_view JupyterClient::last_error_detail() const noexcept {
  return impl_ ? std::string_view{impl_->last_error} : std::string_view{};
}

Result<std::vector<JupyterKernelInfo>> JupyterClient::list_kernels() {
  if (!impl_) {
    return fail_j<std::vector<JupyterKernelInfo>>(ErrorCode::stale_handle,
                                                  JupyterErrorDetail::invalid_url);
  }
  impl_->last_error.clear();
  auto resp = impl_->send_rest({.method = "GET", .path = "/api/kernels", .body = {}});
  if (!resp.has_value()) {
    return Result<std::vector<JupyterKernelInfo>>::failure(resp.error());
  }
  if (resp.value().status_code != 200) {
    impl_->set_error("list_kernels failed with HTTP " +
                     std::to_string(resp.value().status_code));
    return fail_j<std::vector<JupyterKernelInfo>>(
        ErrorCode::provider_transport, JupyterErrorDetail::http_status_error);
  }
  auto parsed = parse_json(resp.value().body);
  if (!parsed.has_value() ||
      !std::holds_alternative<Value::Array>(parsed.value().value())) {
    impl_->set_error("list_kernels returned malformed JSON array");
    return fail_j<std::vector<JupyterKernelInfo>>(
        ErrorCode::corrupt, JupyterErrorDetail::http_protocol_error);
  }
  std::vector<JupyterKernelInfo> out;
  out.reserve(parsed.value().array().size());
  for (const auto &item : parsed.value().array()) {
    auto info = parse_kernel_info_value(item);
    if (!info.has_value()) {
      impl_->set_error("list_kernels returned malformed kernel object");
      return Result<std::vector<JupyterKernelInfo>>::failure(info.error());
    }
    out.push_back(std::move(info).value());
  }
  return Result<std::vector<JupyterKernelInfo>>::success(std::move(out));
}

Result<JupyterKernelInfo> JupyterClient::start_kernel(std::string_view kernel_name) {
  if (!impl_) {
    return fail_j<JupyterKernelInfo>(ErrorCode::stale_handle,
                                     JupyterErrorDetail::invalid_url);
  }
  impl_->last_error.clear();
  if (!valid_kernel_name(kernel_name)) {
    impl_->set_error("invalid kernel name");
    return fail_j<JupyterKernelInfo>(ErrorCode::invalid_identity,
                                     JupyterErrorDetail::invalid_kernel_name);
  }
  Value::Object body_obj;
  if (!kernel_name.empty()) {
    body_obj.emplace_back("name", Value{std::string{kernel_name}});
  }
  auto body_json = dump_json(Value::object(std::move(body_obj)));
  if (!body_json.has_value()) {
    return Result<JupyterKernelInfo>::failure(body_json.error());
  }
  auto resp = impl_->send_rest(
      {.method = "POST", .path = "/api/kernels", .body = std::move(body_json).value()});
  if (!resp.has_value()) {
    return Result<JupyterKernelInfo>::failure(resp.error());
  }
  if (resp.value().status_code != 201 && resp.value().status_code != 200) {
    impl_->set_error("start_kernel failed with HTTP " +
                     std::to_string(resp.value().status_code));
    return fail_j<JupyterKernelInfo>(ErrorCode::provider_transport,
                                     JupyterErrorDetail::http_status_error);
  }
  auto parsed = parse_json(resp.value().body);
  if (!parsed.has_value()) {
    impl_->set_error("start_kernel returned malformed JSON");
    return fail_j<JupyterKernelInfo>(ErrorCode::corrupt,
                                     JupyterErrorDetail::http_protocol_error);
  }
  auto info = parse_kernel_info_value(parsed.value());
  if (!info.has_value()) {
    impl_->set_error("start_kernel returned invalid kernel payload");
  }
  return info;
}

Result<void> JupyterClient::interrupt_kernel(std::string_view kernel_id) {
  if (!impl_) {
    return fail_jv(ErrorCode::stale_handle, JupyterErrorDetail::invalid_url);
  }
  impl_->last_error.clear();
  if (!valid_kernel_id(kernel_id)) {
    impl_->set_error("invalid kernel id");
    return fail_jv(ErrorCode::invalid_identity, JupyterErrorDetail::invalid_kernel_id);
  }
  auto resp =
      impl_->send_rest({.method = "POST",
                        .path = "/api/kernels/" + std::string{kernel_id} + "/interrupt",
                        .body = {}});
  if (!resp.has_value()) {
    return Result<void>::failure(resp.error());
  }
  if (resp.value().status_code != 204 && resp.value().status_code != 200 &&
      resp.value().status_code != 202) {
    impl_->set_error("interrupt_kernel failed with HTTP " +
                     std::to_string(resp.value().status_code));
    return fail_jv(ErrorCode::provider_transport,
                   JupyterErrorDetail::http_status_error);
  }
  return Result<void>::success();
}

Result<void> JupyterClient::shutdown_kernel(std::string_view kernel_id) {
  if (!impl_) {
    return fail_jv(ErrorCode::stale_handle, JupyterErrorDetail::invalid_url);
  }
  impl_->last_error.clear();
  if (!valid_kernel_id(kernel_id)) {
    impl_->set_error("invalid kernel id");
    return fail_jv(ErrorCode::invalid_identity, JupyterErrorDetail::invalid_kernel_id);
  }
  auto resp = impl_->send_rest({.method = "DELETE",
                                .path = "/api/kernels/" + std::string{kernel_id},
                                .body = {}});
  if (!resp.has_value()) {
    return Result<void>::failure(resp.error());
  }
  if (resp.value().status_code != 204 && resp.value().status_code != 200 &&
      resp.value().status_code != 202) {
    impl_->set_error("shutdown_kernel failed with HTTP " +
                     std::to_string(resp.value().status_code));
    return fail_jv(ErrorCode::provider_transport,
                   JupyterErrorDetail::http_status_error);
  }
  return Result<void>::success();
}

Result<JupyterExecutionResult>
JupyterClient::execute_code(const JupyterExecuteRequest &request) {
  if (!impl_) {
    return fail_j<JupyterExecutionResult>(ErrorCode::stale_handle,
                                          JupyterErrorDetail::invalid_url);
  }
  impl_->last_error.clear();
  if (!valid_kernel_id(request.kernel_id)) {
    impl_->set_error("invalid kernel id");
    return fail_j<JupyterExecutionResult>(ErrorCode::invalid_identity,
                                          JupyterErrorDetail::invalid_kernel_id);
  }
  if (request.timeout.count() <= 0) {
    impl_->set_error("execution timeout must be positive");
    return fail_j<JupyterExecutionResult>(ErrorCode::invalid_range,
                                          JupyterErrorDetail::invalid_timeout);
  }
  if (!valid_utf8(request.code)) {
    impl_->set_error("code must be valid UTF-8");
    return fail_j<JupyterExecutionResult>(ErrorCode::corrupt,
                                          JupyterErrorDetail::invalid_cell_schema);
  }

  const auto deadline = SteadyClock::now() + request.timeout;
  const auto connect_budget = std::min(impl_->connect_timeout, request.timeout);

  auto session_id_res = generate_uuid_v4();
  auto msg_id_res = generate_uuid_v4();
  if (!session_id_res.has_value() || !msg_id_res.has_value()) {
    impl_->set_error("CSPRNG failure generating Jupyter message identifiers");
    return fail_j<JupyterExecutionResult>(ErrorCode::provider_transport,
                                          JupyterErrorDetail::crypto_error);
  }
  const std::string session_id = std::move(session_id_res).value();
  const std::string msg_id = std::move(msg_id_res).value();

  std::array<std::uint8_t, 16U> ws_nonce{};
  if (RAND_bytes(ws_nonce.data(), static_cast<int>(ws_nonce.size())) != 1) {
    impl_->set_error("CSPRNG failure generating WebSocket handshake key");
    return fail_j<JupyterExecutionResult>(ErrorCode::provider_transport,
                                          JupyterErrorDetail::crypto_error);
  }
  const std::string ws_key = base64_encode(ws_nonce);
  auto expected_accept_res = compute_ws_accept(ws_key);
  if (!expected_accept_res.has_value()) {
    impl_->set_error("SHA-1 failure computing Sec-WebSocket-Accept");
    return Result<JupyterExecutionResult>::failure(expected_accept_res.error());
  }
  const std::string expected_accept = std::move(expected_accept_res).value();

  auto stream_res = TransportStream::connect(impl_->url, connect_budget);
  if (!stream_res.has_value()) {
    impl_->set_error("failed to connect to Jupyter kernel channels");
    return Result<JupyterExecutionResult>::failure(stream_res.error());
  }
  TransportStream stream = std::move(stream_res).value();

  // RFC 6455 HTTP/1.1 Upgrade request.
  {
    const std::string host_hdr = build_host_header(impl_->url);
    std::string upgrade_req;
    CleanseStringGuard req_guard{upgrade_req};
    // Exact upper-bound reservation so upgrade_req never reallocates after api_token.
    upgrade_req.reserve(256U + impl_->url.base_path.size() + request.kernel_id.size() +
                        session_id.size() + host_hdr.size() + ws_key.size() +
                        impl_->api_token.size());
    upgrade_req.append("GET ");
    upgrade_req.append(impl_->url.base_path);
    upgrade_req.append("/api/kernels/");
    upgrade_req.append(request.kernel_id);
    upgrade_req.append("/channels?session_id=");
    upgrade_req.append(session_id);
    upgrade_req.append(" HTTP/1.1\r\nHost: ");
    upgrade_req.append(host_hdr);
    upgrade_req.append("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n");
    upgrade_req.append("Sec-WebSocket-Key: ");
    upgrade_req.append(ws_key);
    upgrade_req.append("\r\nSec-WebSocket-Version: 13\r\n");
    if (!impl_->api_token.empty()) {
      upgrade_req.append("Authorization: token ");
      upgrade_req.append(impl_->api_token);
      upgrade_req.append("\r\n");
    }
    upgrade_req.append("\r\n");

    auto wr = stream.write_text(upgrade_req, deadline);
    if (!wr.has_value()) {
      impl_->set_error("failed to send WebSocket upgrade request");
      return Result<JupyterExecutionResult>::failure(wr.error());
    }
  }

  auto head_res = read_http_response_head(stream, deadline);
  if (!head_res.has_value()) {
    impl_->set_error("invalid WebSocket upgrade response");
    return Result<JupyterExecutionResult>::failure(head_res.error());
  }
  const HttpResponseHead &head = head_res.value();
  if (head.status_code == 401 || head.status_code == 403) {
    impl_->set_error("Jupyter WebSocket rejected authentication (" +
                     std::to_string(head.status_code) + ")");
    return fail_j<JupyterExecutionResult>(ErrorCode::provider_auth,
                                          JupyterErrorDetail::auth_failed);
  }
  if (head.status_code != 101) {
    impl_->set_error("WebSocket upgrade failed with HTTP " +
                     std::to_string(head.status_code));
    return fail_j<JupyterExecutionResult>(ErrorCode::provider_transport,
                                          JupyterErrorDetail::ws_handshake_failed);
  }
  const auto upgrade_hdr = find_header_value(head.headers, "upgrade");
  const auto conn_hdr = find_header_value(head.headers, "connection");
  const auto accept_hdr = find_header_value(head.headers, "sec-websocket-accept");
  if (!upgrade_hdr.has_value() || !conn_hdr.has_value() || !accept_hdr.has_value() ||
      !header_contains_token_icase({*upgrade_hdr, "websocket"}) ||
      !header_contains_token_icase({*conn_hdr, "upgrade"}) ||
      accept_hdr->size() != expected_accept.size() ||
      CRYPTO_memcmp(accept_hdr->data(), expected_accept.data(),
                    expected_accept.size()) != 0) {
    impl_->set_error("WebSocket handshake validation failed (Sec-WebSocket-Accept)");
    return fail_j<JupyterExecutionResult>(ErrorCode::provider_transport,
                                          JupyterErrorDetail::ws_handshake_failed);
  }

  // Build Jupyter Wire Protocol v5.3 execute_request envelope.
  Value::Object header_obj;
  header_obj.emplace_back("msg_id", Value{msg_id});
  header_obj.emplace_back("msg_type", Value{"execute_request"});
  header_obj.emplace_back("username", Value{"blackbird"});
  header_obj.emplace_back("session", Value{session_id});
  header_obj.emplace_back("date", Value{current_utc_iso8601()});
  header_obj.emplace_back("version", Value{"5.3"});

  Value::Object content_obj;
  content_obj.emplace_back("code", Value{request.code});
  content_obj.emplace_back("silent", Value{request.silent});
  content_obj.emplace_back("store_history", Value{request.store_history});
  content_obj.emplace_back("user_expressions", Value::object({}));
  content_obj.emplace_back("allow_stdin", Value{false});
  content_obj.emplace_back("stop_on_error", Value{request.stop_on_error});

  Value::Object envelope_obj;
  envelope_obj.emplace_back("header", Value::object(std::move(header_obj)));
  envelope_obj.emplace_back("parent_header", Value::object({}));
  envelope_obj.emplace_back("metadata", Value::object({}));
  envelope_obj.emplace_back("content", Value::object(std::move(content_obj)));
  envelope_obj.emplace_back("buffers", Value{Value::Array{}});
  envelope_obj.emplace_back("channel", Value{"shell"});

  auto req_json_res = dump_json(Value::object(std::move(envelope_obj)));
  if (!req_json_res.has_value()) {
    return Result<JupyterExecutionResult>::failure(req_json_res.error());
  }
  const std::string &req_json = req_json_res.value();

  auto send_res = write_ws_masked_frame(
      stream, WsOpcode::text,
      std::span<const std::uint8_t>{
          reinterpret_cast<const std::uint8_t *>(req_json.data()), req_json.size()},
      deadline);
  if (!send_res.has_value()) {
    impl_->set_error("failed to send execute_request over WebSocket");
    return Result<JupyterExecutionResult>::failure(send_res.error());
  }

  JupyterExecutionResult result;
  result.msg_id = msg_id;
  bool saw_iopub_idle = false;
  bool saw_shell_reply = false;

  while (!(saw_iopub_idle && saw_shell_reply)) {
    auto msg_res = read_ws_message(stream, impl_->max_ws_frame_bytes, deadline);
    if (!msg_res.has_value()) {
      if (msg_res.error().detail ==
          static_cast<std::int64_t>(JupyterErrorDetail::execution_timeout)) {
        impl_->set_error("kernel execution timed out");
      } else {
        impl_->set_error("WebSocket error while awaiting kernel outputs");
      }
      return Result<JupyterExecutionResult>::failure(msg_res.error());
    }
    if (msg_res.value().opcode != WsOpcode::text) {
      continue;
    }

    auto parsed_msg = parse_json(msg_res.value().payload);
    if (!parsed_msg.has_value() ||
        !std::holds_alternative<Value::Object>(parsed_msg.value().value())) {
      continue;
    }
    const Value &msg = parsed_msg.value();

    // Correlate strictly by parent_header.msg_id.
    const Value *parent_hdr = msg.find("parent_header");
    if (parent_hdr == nullptr ||
        !std::holds_alternative<Value::Object>(parent_hdr->value())) {
      continue;
    }
    const Value *parent_id = parent_hdr->find("msg_id");
    if (parent_id == nullptr ||
        !std::holds_alternative<std::string>(parent_id->value()) ||
        parent_id->string() != msg_id) {
      continue;
    }

    std::string_view msg_type;
    if (const Value *hdr = msg.find("header");
        hdr != nullptr && std::holds_alternative<Value::Object>(hdr->value())) {
      if (const Value *mt = hdr->find("msg_type");
          mt != nullptr && std::holds_alternative<std::string>(mt->value())) {
        msg_type = mt->string();
      }
    }
    if (msg_type.empty()) {
      if (const Value *mt = msg.find("msg_type");
          mt != nullptr && std::holds_alternative<std::string>(mt->value())) {
        msg_type = mt->string();
      }
    }

    std::string_view channel;
    if (const Value *ch = msg.find("channel");
        ch != nullptr && std::holds_alternative<std::string>(ch->value())) {
      channel = ch->string();
    }

    const Value *content = msg.find("content");
    if (content == nullptr ||
        !std::holds_alternative<Value::Object>(content->value())) {
      continue;
    }

    if (channel == "iopub") {
      if (msg_type == "status") {
        if (const Value *state = content->find("execution_state");
            state != nullptr && std::holds_alternative<std::string>(state->value()) &&
            state->string() == "idle") {
          saw_iopub_idle = true;
        }
      } else if (msg_type == "stream") {
        const Value *name_v = content->find("name");
        const Value *text_v = content->find("text");
        if (name_v != nullptr && std::holds_alternative<std::string>(name_v->value()) &&
            text_v != nullptr) {
          auto text_res = normalize_nbformat_text(*text_v);
          if (text_res.has_value()) {
            NotebookOutput out;
            out.output_type = NotebookOutputType::stream;
            out.stream_name = name_v->string();
            out.text = std::move(text_res).value();
            result.outputs.push_back(std::move(out));
          }
        }
      } else if (msg_type == "execute_result" || msg_type == "display_data") {
        if (const Value *data_v = content->find("data")) {
          auto mime_res = parse_mime_bundle(*data_v);
          if (mime_res.has_value()) {
            NotebookOutput out;
            out.output_type = (msg_type == "execute_result")
                                  ? NotebookOutputType::execute_result
                                  : NotebookOutputType::display_data;
            out.data = std::move(mime_res).value();
            if (const Value *meta_v = content->find("metadata");
                meta_v != nullptr &&
                std::holds_alternative<Value::Object>(meta_v->value())) {
              out.metadata = *meta_v;
            }
            if (out.output_type == NotebookOutputType::execute_result) {
              if (const Value *ec_v = content->find("execution_count")) {
                if (const auto ec = extract_strict_int64(*ec_v)) {
                  out.execution_count = *ec;
                }
              }
            }
            result.outputs.push_back(std::move(out));
          }
        }
      } else if (msg_type == "error") {
        NotebookOutput out;
        out.output_type = NotebookOutputType::error;
        if (const Value *en = content->find("ename");
            en != nullptr && std::holds_alternative<std::string>(en->value())) {
          out.ename = en->string();
        }
        if (const Value *ev = content->find("evalue");
            ev != nullptr && std::holds_alternative<std::string>(ev->value())) {
          out.evalue = ev->string();
        }
        if (const Value *tb = content->find("traceback");
            tb != nullptr && std::holds_alternative<Value::Array>(tb->value())) {
          for (const auto &line : tb->array()) {
            if (std::holds_alternative<std::string>(line.value())) {
              out.traceback.push_back(line.string());
            }
          }
        }
        result.outputs.push_back(std::move(out));
      }
    } else if (channel == "shell" && msg_type == "execute_reply") {
      saw_shell_reply = true;
      if (const Value *st = content->find("status");
          st != nullptr && std::holds_alternative<std::string>(st->value())) {
        result.status = st->string();
      }
      if (const Value *ec_v = content->find("execution_count")) {
        if (const auto ec = extract_strict_int64(*ec_v)) {
          result.execution_count = *ec;
        }
      }
      if (result.status == "error") {
        if (const Value *en = content->find("ename");
            en != nullptr && std::holds_alternative<std::string>(en->value())) {
          result.error_name = en->string();
        }
        if (const Value *ev = content->find("evalue");
            ev != nullptr && std::holds_alternative<std::string>(ev->value())) {
          result.error_value = ev->string();
        }
        if (const Value *tb = content->find("traceback");
            tb != nullptr && std::holds_alternative<Value::Array>(tb->value())) {
          result.traceback.clear();
          for (const auto &line : tb->array()) {
            if (std::holds_alternative<std::string>(line.value())) {
              result.traceback.push_back(line.string());
            }
          }
        }
      }
    }
  }

  // Send polite masked Close frame (1000 Normal Closure), best-effort.
  const std::array<std::uint8_t, 2U> close_code{0x03U, 0xe8U};
  (void)write_ws_masked_frame(stream, WsOpcode::close, close_code,
                              SteadyClock::now() + std::chrono::milliseconds{250});
  stream.close();
  return Result<JupyterExecutionResult>::success(std::move(result));
}

// ---------------------------------------------------------------------------
// Public Part 3: Passive Local Jupyter Capability Discovery
// ---------------------------------------------------------------------------

JupyterCapabilities probe_jupyter_capabilities(const JupyterProbeOptions &options) {
  JupyterCapabilities caps;
  const auto resolved = resolve_jupyter_executable(options.executable_override);
  if (!resolved.has_value()) {
    caps.diagnostic = "jupyter executable not found";
    return caps;
  }
  caps.jupyter_available = true;
  caps.jupyter_path = *resolved;

  const auto timeout =
      options.timeout.count() > 0 ? options.timeout : std::chrono::milliseconds{3000};
  const std::size_t max_output =
      options.max_output_bytes > 0U ? options.max_output_bytes : 256U * 1024U;

  auto pipe_fds = make_cloexec_pipe();
  if (!pipe_fds.has_value()) {
    caps.diagnostic = "failed to allocate probe pipe";
    return caps;
  }
  ScopedFd out_read = std::move(pipe_fds->read_end);
  ScopedFd out_write = std::move(pipe_fds->write_end);

  std::vector<std::string> argv_storage = {*resolved, "kernelspec", "list", "--json"};
  std::vector<char *> argv;
  argv.reserve(argv_storage.size() + 1U);
  for (std::string &arg : argv_storage) {
    argv.push_back(arg.data());
  }
  argv.push_back(nullptr);

  std::vector<std::string> env_storage = build_clean_probe_env();
  std::vector<char *> envp;
  envp.reserve(env_storage.size() + 1U);
  for (std::string &entry : env_storage) {
    envp.push_back(entry.data());
  }
  envp.push_back(nullptr);

  posix_spawn_file_actions_t actions{};
  posix_spawnattr_t attr{};
  pid_t child_pid = -1;
  int spawn_rc = ::posix_spawn_file_actions_init(&actions);
  if (spawn_rc == 0) {
    spawn_rc = ::posix_spawnattr_init(&attr);
    if (spawn_rc == 0) {
      spawn_rc = ::posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null",
                                                    O_RDONLY, 0);
      if (spawn_rc == 0) {
        spawn_rc = ::posix_spawn_file_actions_adddup2(&actions, out_write.get(),
                                                      STDOUT_FILENO);
      }
      if (spawn_rc == 0) {
        spawn_rc = ::posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
                                                      "/dev/null", O_WRONLY, 0);
      }
      if (spawn_rc == 0) {
        spawn_rc = ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP |
                                                         POSIX_SPAWN_SETSIGMASK);
      }
      if (spawn_rc == 0) {
        spawn_rc = ::posix_spawnattr_setpgroup(&attr, 0);
      }
      if (spawn_rc == 0) {
        sigset_t empty_mask{};
        sigemptyset(&empty_mask);
        spawn_rc = ::posix_spawnattr_setsigmask(&attr, &empty_mask);
      }
      if (spawn_rc == 0) {
        // Strict posix_spawn with explicit resolved path (never shell, never
        // posix_spawnp).
        spawn_rc = ::posix_spawn(&child_pid, resolved->c_str(), &actions, &attr,
                                 argv.data(), envp.data());
      }
      (void)::posix_spawnattr_destroy(&attr);
    }
    (void)::posix_spawn_file_actions_destroy(&actions);
  }
  out_write.reset();

  if (spawn_rc != 0 || child_pid <= 0) {
    caps.diagnostic = "failed to spawn jupyter kernelspec probe";
    return caps;
  }

  const int fd_flags = ::fcntl(out_read.get(), F_GETFL, 0);
  if (fd_flags >= 0) {
    (void)::fcntl(out_read.get(), F_SETFL, fd_flags | O_NONBLOCK);
  }

  const auto deadline = SteadyClock::now() + timeout;
  std::string stdout_buf;
  bool truncated = false;
  bool timed_out = false;
  std::array<char, 4096U> chunk{};

  while (true) {
    const int rem = remaining_timeout_ms(deadline);
    if (rem <= 0) {
      timed_out = true;
      break;
    }
    pollfd pfd{};
    pfd.fd = out_read.get();
    pfd.events = POLLIN;
    const int prc = ::poll(&pfd, 1U, rem);
    if (prc == 0) {
      timed_out = true;
      break;
    }
    if (prc < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    const ssize_t n = ::read(out_read.get(), chunk.data(), chunk.size());
    if (n > 0) {
      const auto count = static_cast<std::size_t>(n);
      if (count > max_output || stdout_buf.size() > max_output - count) {
        truncated = true;
        break;
      }
      stdout_buf.append(chunk.data(), count);
      continue;
    }
    if (n == 0) {
      break;
    }
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
      continue;
    }
    break;
  }
  out_read.reset();

  if (timed_out || truncated) {
    kill_and_reap_pgroup(child_pid);
    caps.diagnostic = timed_out ? "jupyter kernelspec probe timed out"
                                : "jupyter kernelspec probe exceeded output limit";
    return caps;
  }

  int wait_status = 0;
  bool reaped = false;
  while (true) {
    const pid_t wr = ::waitpid(child_pid, &wait_status, WNOHANG);
    if (wr == child_pid) {
      reaped = true;
      break;
    }
    if (wr < 0 && errno != EINTR) {
      break;
    }
    if (SteadyClock::now() >= deadline) {
      break;
    }
    pollfd dummy{};
    (void)::poll(&dummy, 0U, 10);
  }
  if (!reaped) {
    kill_and_reap_pgroup(child_pid);
    caps.diagnostic = "jupyter kernelspec probe timed out waiting for exit";
    return caps;
  }

  if (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0) {
    caps.diagnostic = "jupyter kernelspec list exited non-zero";
    return caps;
  }

  auto parsed = parse_json(stdout_buf);
  if (!parsed.has_value() ||
      !std::holds_alternative<Value::Object>(parsed.value().value())) {
    caps.diagnostic = "jupyter kernelspec list returned non-JSON output";
    return caps;
  }
  const Value *specs_val = parsed.value().find("kernelspecs");
  if (specs_val == nullptr ||
      !std::holds_alternative<Value::Object>(specs_val->value())) {
    caps.diagnostic = "jupyter kernelspec list missing kernelspecs object";
    return caps;
  }

  for (const auto &[name, entry] : specs_val->object()) {
    if (!std::holds_alternative<Value::Object>(entry.value())) {
      continue;
    }
    JupyterKernelSpecInfo info;
    info.name = name;
    if (const Value *res_dir = entry.find("resource_dir");
        res_dir != nullptr && std::holds_alternative<std::string>(res_dir->value())) {
      info.resource_dir = res_dir->string();
    }
    if (const Value *spec = entry.find("spec");
        spec != nullptr && std::holds_alternative<Value::Object>(spec->value())) {
      if (const Value *dn = spec->find("display_name");
          dn != nullptr && std::holds_alternative<std::string>(dn->value())) {
        info.display_name = dn->string();
      }
      if (const Value *lang = spec->find("language");
          lang != nullptr && std::holds_alternative<std::string>(lang->value())) {
        info.language = lang->string();
      }
    }
    caps.kernelspecs.push_back(std::move(info));
  }

  std::sort(caps.kernelspecs.begin(), caps.kernelspecs.end(),
            [](const JupyterKernelSpecInfo &a, const JupyterKernelSpecInfo &b) {
              return a.name < b.name;
            });
  return caps;
}

} // namespace blackbird
