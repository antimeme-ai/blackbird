#include "blackbird/integration_vault.hpp"

#include "blackbird/json.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace blackbird {

namespace {

constexpr std::string_view kStoreMagic = "bb.integrations.v1";
constexpr std::int64_t kStoreVersion = 1;
constexpr std::size_t kStoreMaxBytes = 2U * 1024U * 1024U;
constexpr std::size_t kMaxRecords = 512U;
constexpr std::size_t kMaxAllowedHostsPerRecord = 32U;
constexpr std::size_t kMaxScopesPerRecord = 64U;
constexpr std::size_t kMaxExtraMetaPerRecord = 32U;
constexpr std::size_t kMaxSecretBytes = 32U * 1024U;
constexpr std::int64_t kMaxExpiresInSeconds = 365LL * 86400LL;

std::mutex g_vault_mutex;

template <typename T> Result<T> fail_v(ErrorCode code, VaultError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_vv(ErrorCode code, VaultError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

struct CleanseStringGuard {
  std::string &text;
  ~CleanseStringGuard() {
    if (!text.empty()) {
      OPENSSL_cleanse(text.data(), text.size());
    }
  }
};

bool constant_time_equal(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) {
    return false;
  }
  if (a.empty()) {
    return true;
  }
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

constexpr char to_ascii_lower(char ch) noexcept {
  return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch + ('a' - 'A')) : ch;
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

bool is_valid_identifier(std::string_view s) noexcept {
  if (s.empty() || s.size() > 64U) {
    return false;
  }
  return std::all_of(s.begin(), s.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.' || c == '@';
  });
}

bool is_valid_secret_text(std::string_view s, bool allow_empty) noexcept {
  if (s.empty()) {
    return allow_empty;
  }
  if (s.size() > kMaxSecretBytes) {
    return false;
  }
  for (const char c : s) {
    if (c == '\r' || c == '\n' || c == '\0') {
      return false;
    }
  }
  return true;
}

bool is_valid_host_pin(std::string_view pin) noexcept {
  if (pin.empty() || pin.size() > 255U) {
    return false;
  }
  std::string_view body = pin;
  if (body.starts_with("*.")) {
    body.remove_prefix(2U);
    if (body.empty() || body.find('.') == std::string_view::npos ||
        body.find('*') != std::string_view::npos) {
      return false;
    }
  } else if (body.find('*') != std::string_view::npos) {
    return false;
  }
  for (const char c : body) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '.' || c == ':';
    if (!ok) {
      return false;
    }
  }
  return true;
}

bool is_valid_header_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > 128U) {
    return false;
  }
  for (const char c : name) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_';
    if (!ok) {
      return false;
    }
  }
  return true;
}

Result<void> require_https_url(std::string_view url) {
  const auto parsed = net::parse_url(url);
  if (!parsed.has_value()) {
    return fail_vv(ErrorCode::invalid_range, VaultError::invalid_url);
  }
  if (parsed.value().scheme != "https") {
    return fail_vv(ErrorCode::conflict, VaultError::https_required);
  }
  return Result<void>::success();
}

std::string base64url_encode(std::span<const std::uint8_t> bytes) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve(((bytes.size() * 4U) + 2U) / 3U);
  std::uint32_t bits = 0U;
  unsigned count = 0U;
  for (const std::uint8_t b : bytes) {
    bits = (bits << 8U) | b;
    count += 8U;
    while (count >= 6U) {
      count -= 6U;
      out.push_back(kAlphabet[(bits >> count) & 0x3FU]);
    }
  }
  if (count > 0U) {
    out.push_back(kAlphabet[(bits << (6U - count)) & 0x3FU]);
  }
  return out;
}

std::string base64_std_encode(std::string_view text) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const auto *bytes = reinterpret_cast<const std::uint8_t *>(text.data());
  const std::size_t n = text.size();
  std::string out;
  out.reserve(((n + 2U) / 3U) * 4U);
  std::size_t i = 0U;
  while (i + 3U <= n) {
    const std::uint32_t t = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                            static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kAlphabet[(t >> 18U) & 0x3FU]);
    out.push_back(kAlphabet[(t >> 12U) & 0x3FU]);
    out.push_back(kAlphabet[(t >> 6U) & 0x3FU]);
    out.push_back(kAlphabet[t & 0x3FU]);
    i += 3U;
  }
  const std::size_t rem = n - i;
  if (rem == 1U) {
    const std::uint32_t t = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kAlphabet[(t >> 18U) & 0x3FU]);
    out.push_back(kAlphabet[(t >> 12U) & 0x3FU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t t = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kAlphabet[(t >> 18U) & 0x3FU]);
    out.push_back(kAlphabet[(t >> 12U) & 0x3FU]);
    out.push_back(kAlphabet[(t >> 6U) & 0x3FU]);
    out.push_back('=');
  }
  return out;
}

std::string form_encode(std::string_view s) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(s.size());
  for (const char raw : s) {
    const auto c = static_cast<unsigned char>(raw);
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(kHex[c >> 4U]);
      out.push_back(kHex[c & 15U]);
    }
  }
  return out;
}

Result<std::string> form_decode(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0U; i < s.size(); ++i) {
    if (s[i] == '+') {
      out.push_back(' ');
    } else if (s[i] == '%') {
      if (i + 2U >= s.size()) {
        return fail_v<std::string>(ErrorCode::corrupt,
                                   VaultError::oauth_callback_rejected);
      }
      unsigned val = 0U;
      const auto [ptr, ec] =
          std::from_chars(s.data() + i + 1U, s.data() + i + 3U, val, 16);
      if (ec != std::errc{} || ptr != s.data() + i + 3U || val < 32U || val == 127U) {
        return fail_v<std::string>(ErrorCode::corrupt,
                                   VaultError::oauth_callback_rejected);
      }
      out.push_back(static_cast<char>(val));
      i += 2U;
    } else {
      out.push_back(s[i]);
    }
  }
  return Result<std::string>::success(std::move(out));
}

Result<std::map<std::string, std::string>> parse_query_params(std::string_view q) {
  std::map<std::string, std::string> out;
  while (!q.empty()) {
    const std::size_t amp = q.find('&');
    const std::string_view part =
        (amp == std::string_view::npos) ? q : q.substr(0U, amp);
    const std::size_t eq = part.find('=');
    if (eq == std::string_view::npos) {
      return fail_v<std::map<std::string, std::string>>(
          ErrorCode::corrupt, VaultError::oauth_callback_rejected);
    }
    auto k = form_decode(part.substr(0U, eq));
    if (!k.has_value()) {
      return Result<std::map<std::string, std::string>>::failure(k.error());
    }
    auto v = form_decode(part.substr(eq + 1U));
    if (!v.has_value()) {
      return Result<std::map<std::string, std::string>>::failure(v.error());
    }
    if (!out.emplace(std::move(k).value(), std::move(v).value()).second) {
      return fail_v<std::map<std::string, std::string>>(
          ErrorCode::corrupt, VaultError::oauth_callback_rejected);
    }
    if (amp == std::string_view::npos) {
      break;
    }
    q.remove_prefix(amp + 1U);
  }
  return Result<std::map<std::string, std::string>>::success(std::move(out));
}

std::int64_t now_seconds(const IntegrationVaultConfig &config) {
  if (config.now) {
    return config.now();
  }
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string default_prefix_for_scheme(AuthScheme scheme) {
  switch (scheme) {
  case AuthScheme::bearer_oauth2:
  case AuthScheme::bearer_pat:
    return "Bearer ";
  case AuthScheme::discord_bot:
    return "Bot ";
  case AuthScheme::header_key:
    return "";
  case AuthScheme::basic_token:
    return "Basic ";
  }
  return "Bearer ";
}

std::vector<std::string> split_space_scopes(std::string_view text) {
  std::vector<std::string> out;
  std::size_t i = 0U;
  while (i < text.size()) {
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) {
      ++i;
    }
    const std::size_t start = i;
    while (i < text.size() && text[i] != ' ' && text[i] != '\t') {
      ++i;
    }
    if (i > start) {
      out.emplace_back(text.substr(start, i - start));
    }
  }
  return out;
}

std::string join_space_scopes(const std::vector<std::string> &scopes) {
  std::string out;
  for (std::size_t i = 0U; i < scopes.size(); ++i) {
    if (i > 0U) {
      out.push_back(' ');
    }
    out.append(scopes[i]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Scoped POSIX FD & secure 0700/0600 file verification
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

Result<void> verify_fd_permissions(int fd, bool expect_dir) noexcept {
  struct stat st{};
  if (fd < 0 || ::fstat(fd, &st) != 0) {
    return fail_vv(ErrorCode::io, VaultError::io_failed);
  }
  if (expect_dir ? !S_ISDIR(st.st_mode) : (!S_ISREG(st.st_mode) || st.st_nlink != 1)) {
    return fail_vv(ErrorCode::conflict, VaultError::insecure_permissions);
  }
  if (st.st_uid != ::geteuid() || (st.st_mode & 0077) != 0) {
    return fail_vv(ErrorCode::conflict, VaultError::insecure_permissions);
  }
  return Result<void>::success();
}

// ---------------------------------------------------------------------------
// Internal binary packet store model (keyed by 64-bit integer CredentialId)
// ---------------------------------------------------------------------------

struct StoredRecord {
  CredentialId id{};
  std::string service;
  std::string account;
  AuthScheme scheme = AuthScheme::bearer_oauth2;
  std::string auth_header_name;
  std::string auth_header_prefix;
  CleansedSecret access_token;
  CleansedSecret refresh_token;
  CleansedSecret client_secret;
  std::vector<std::string> allowed_hosts;
  std::vector<std::string> scopes;
  std::string resource_uri;
  std::string authorization_server;
  std::string token_endpoint;
  std::string client_id;
  std::int64_t expires_at = 0;
  std::int64_t updated_at = 0;
  std::uint64_t revision = 0U;
  std::vector<std::pair<std::string, std::string>> extra_metadata;
};

struct VaultState {
  std::uint64_t next_id = 1U;
  // Primary storage keyed by 64-bit integer CredentialId.
  std::map<std::uint64_t, StoredRecord> records;
  // Secondary lookup index: service -> active CredentialId.
  std::map<std::string, std::uint64_t> active_by_service;
};

CredentialMetadata to_public_metadata(const StoredRecord &rec, bool is_active,
                                      std::int64_t clock_now) {
  CredentialMetadata meta{};
  meta.id = rec.id;
  meta.service = rec.service;
  meta.account = rec.account;
  meta.scheme = rec.scheme;
  meta.auth_header_name = rec.auth_header_name;
  meta.auth_header_prefix = rec.auth_header_prefix;
  meta.allowed_hosts = rec.allowed_hosts;
  meta.scopes = rec.scopes;
  meta.resource_uri = rec.resource_uri;
  meta.authorization_server = rec.authorization_server;
  meta.token_endpoint = rec.token_endpoint;
  meta.client_id = rec.client_id;
  meta.expires_at = rec.expires_at;
  meta.updated_at = rec.updated_at;
  meta.revision = rec.revision;
  meta.has_refresh_token = !rec.refresh_token.empty();
  meta.active = is_active;
  meta.expired = (rec.expires_at > 0 && clock_now >= rec.expires_at);
  meta.extra_metadata = rec.extra_metadata;
  return meta;
}

// Helpers for decoding Value fields cleanly.
Result<std::string> get_req_str(const Value &obj, std::string_view key) {
  const auto *p = obj.find(key);
  if (p == nullptr || !std::holds_alternative<std::string>(p->value())) {
    return fail_v<std::string>(ErrorCode::corrupt, VaultError::corrupt_store);
  }
  return Result<std::string>::success(p->string());
}

Result<std::string> get_opt_str(const Value &obj, std::string_view key) {
  const auto *p = obj.find(key);
  if (p == nullptr) {
    return Result<std::string>::success(std::string{});
  }
  if (!std::holds_alternative<std::string>(p->value())) {
    return fail_v<std::string>(ErrorCode::corrupt, VaultError::corrupt_store);
  }
  return Result<std::string>::success(p->string());
}

Result<std::int64_t> get_req_i64(const Value &obj, std::string_view key) {
  const auto *p = obj.find(key);
  if (p == nullptr || !std::holds_alternative<Number>(p->value())) {
    return fail_v<std::int64_t>(ErrorCode::corrupt, VaultError::corrupt_store);
  }
  const std::string s = p->number().text();
  std::int64_t v = 0;
  const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  if (ec != std::errc{} || ptr != s.data() + s.size()) {
    return fail_v<std::int64_t>(ErrorCode::corrupt, VaultError::corrupt_store);
  }
  return Result<std::int64_t>::success(v);
}

Result<std::uint64_t> get_req_u64(const Value &obj, std::string_view key) {
  const auto *p = obj.find(key);
  if (p == nullptr || !std::holds_alternative<Number>(p->value())) {
    return fail_v<std::uint64_t>(ErrorCode::corrupt, VaultError::corrupt_store);
  }
  const std::string s = p->number().text();
  std::uint64_t v = 0U;
  const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  if (ec != std::errc{} || ptr != s.data() + s.size()) {
    return fail_v<std::uint64_t>(ErrorCode::corrupt, VaultError::corrupt_store);
  }
  return Result<std::uint64_t>::success(v);
}

Result<std::vector<std::string>> get_str_array(const Value &obj, std::string_view key,
                                               std::size_t max_items) {
  const auto *p = obj.find(key);
  if (p == nullptr) {
    return Result<std::vector<std::string>>::success({});
  }
  if (!std::holds_alternative<Value::Array>(p->value())) {
    return fail_v<std::vector<std::string>>(ErrorCode::corrupt,
                                            VaultError::corrupt_store);
  }
  const auto &arr = p->array();
  if (arr.size() > max_items) {
    return fail_v<std::vector<std::string>>(ErrorCode::corrupt,
                                            VaultError::corrupt_store);
  }
  std::vector<std::string> out;
  out.reserve(arr.size());
  for (const auto &item : arr) {
    if (!std::holds_alternative<std::string>(item.value())) {
      return fail_v<std::vector<std::string>>(ErrorCode::corrupt,
                                              VaultError::corrupt_store);
    }
    out.push_back(item.string());
  }
  return Result<std::vector<std::string>>::success(std::move(out));
}

Value make_str_array(const std::vector<std::string> &items) {
  Value::Array arr;
  arr.reserve(items.size());
  for (const auto &s : items) {
    arr.emplace_back(s);
  }
  return Value{std::move(arr)};
}

Result<std::string> encode_vault_packet(const VaultState &state) {
  Value::Array rec_arr;
  rec_arr.reserve(state.records.size());
  for (const auto &[id_val, rec] : state.records) {
    Value::Array extra_arr;
    extra_arr.reserve(rec.extra_metadata.size());
    for (const auto &[k, v] : rec.extra_metadata) {
      extra_arr.push_back(Value::object({{"k", Value{k}}, {"v", Value{v}}}));
    }
    rec_arr.push_back(Value::object({
        {"id", Value{Number{id_val}}},
        {"service", Value{rec.service}},
        {"account", Value{rec.account}},
        {"scheme", Value{std::string{auth_scheme_name(rec.scheme)}}},
        {"auth_header_name", Value{rec.auth_header_name}},
        {"auth_header_prefix", Value{rec.auth_header_prefix}},
        {"access_token", Value{std::string{rec.access_token.view()}}},
        {"refresh_token", Value{std::string{rec.refresh_token.view()}}},
        {"client_secret", Value{std::string{rec.client_secret.view()}}},
        {"allowed_hosts", make_str_array(rec.allowed_hosts)},
        {"scopes", make_str_array(rec.scopes)},
        {"resource_uri", Value{rec.resource_uri}},
        {"authorization_server", Value{rec.authorization_server}},
        {"token_endpoint", Value{rec.token_endpoint}},
        {"client_id", Value{rec.client_id}},
        {"expires_at", Value{Number{rec.expires_at}}},
        {"updated_at", Value{Number{rec.updated_at}}},
        {"revision", Value{Number{rec.revision}}},
        {"extra_metadata", Value{std::move(extra_arr)}},
    }));
  }

  Value::Array active_arr;
  active_arr.reserve(state.active_by_service.size());
  for (const auto &[svc, cred_id] : state.active_by_service) {
    active_arr.push_back(
        Value::object({{"service", Value{svc}}, {"id", Value{Number{cred_id}}}}));
  }

  const Value root = Value::object({
      {"magic", Value{std::string{kStoreMagic}}},
      {"version", Value{Number{kStoreVersion}}},
      {"next_id", Value{Number{state.next_id}}},
      {"records", Value{std::move(rec_arr)}},
      {"active_ids", Value{std::move(active_arr)}},
  });

  auto encoded = encode_packet_string(root, {kStoreMaxBytes, 65536U, 32U});
  if (!encoded.has_value()) {
    return fail_v<std::string>(encoded.error().code, VaultError::io_failed);
  }
  return Result<std::string>::success(std::move(encoded).value());
}

Result<VaultState> decode_vault_packet(std::string_view bytes) {
  auto decoded = decode_packet_string(bytes, {kStoreMaxBytes, 65536U, 32U});
  if (!decoded.has_value() ||
      !std::holds_alternative<Value::Object>(decoded.value().value())) {
    return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
  }
  const Value &root = decoded.value();
  const auto magic = get_req_str(root, "magic");
  const auto ver = get_req_i64(root, "version");
  const auto next_id = get_req_u64(root, "next_id");
  if (!magic.has_value() || magic.value() != kStoreMagic || !ver.has_value() ||
      ver.value() != kStoreVersion || !next_id.has_value() || next_id.value() == 0U) {
    return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
  }

  const auto *recs_val = root.find("records");
  const auto *active_val = root.find("active_ids");
  if (recs_val == nullptr || active_val == nullptr ||
      !std::holds_alternative<Value::Array>(recs_val->value()) ||
      !std::holds_alternative<Value::Array>(active_val->value())) {
    return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
  }
  if (recs_val->array().size() > kMaxRecords) {
    return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
  }

  VaultState state{};
  state.next_id = next_id.value();
  std::set<std::pair<std::string, std::string>> seen_svc_acct;

  for (const auto &entry : recs_val->array()) {
    if (!std::holds_alternative<Value::Object>(entry.value())) {
      return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
    }
    const auto id = get_req_u64(entry, "id");
    const auto service = get_req_str(entry, "service");
    const auto account = get_req_str(entry, "account");
    const auto scheme_s = get_req_str(entry, "scheme");
    const auto hdr_name = get_req_str(entry, "auth_header_name");
    const auto hdr_prefix = get_opt_str(entry, "auth_header_prefix");
    const auto access = get_req_str(entry, "access_token");
    const auto refresh = get_opt_str(entry, "refresh_token");
    const auto csecret = get_opt_str(entry, "client_secret");
    const auto hosts = get_str_array(entry, "allowed_hosts", kMaxAllowedHostsPerRecord);
    const auto scopes = get_str_array(entry, "scopes", kMaxScopesPerRecord);
    const auto resource = get_opt_str(entry, "resource_uri");
    const auto auth_srv = get_opt_str(entry, "authorization_server");
    const auto tok_ep = get_opt_str(entry, "token_endpoint");
    const auto cid = get_opt_str(entry, "client_id");
    const auto exp = get_req_i64(entry, "expires_at");
    const auto upd = get_req_i64(entry, "updated_at");
    const auto rev = get_req_u64(entry, "revision");
    if (!id.has_value() || id.value() == 0U || id.value() >= state.next_id ||
        !service.has_value() || !account.has_value() || !scheme_s.has_value() ||
        !hdr_name.has_value() || !hdr_prefix.has_value() || !access.has_value() ||
        !refresh.has_value() || !csecret.has_value() || !hosts.has_value() ||
        hosts.value().empty() || !scopes.has_value() || !resource.has_value() ||
        !auth_srv.has_value() || !tok_ep.has_value() || !cid.has_value() ||
        !exp.has_value() || !upd.has_value() || !rev.has_value()) {
      return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
    }
    const auto scheme = parse_auth_scheme(scheme_s.value());
    if (!scheme.has_value() || !is_valid_identifier(service.value()) ||
        !is_valid_identifier(account.value()) ||
        !is_valid_header_name(hdr_name.value())) {
      return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
    }
    for (const auto &h : hosts.value()) {
      if (!is_valid_host_pin(h)) {
        return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
      }
    }
    if (!seen_svc_acct.emplace(service.value(), account.value()).second) {
      return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
    }

    StoredRecord rec{};
    rec.id = CredentialId{id.value()};
    rec.service = service.value();
    rec.account = account.value();
    rec.scheme = scheme.value();
    rec.auth_header_name = hdr_name.value();
    rec.auth_header_prefix = hdr_prefix.value();
    rec.access_token.assign(access.value());
    rec.refresh_token.assign(refresh.value());
    rec.client_secret.assign(csecret.value());
    rec.allowed_hosts = hosts.value();
    rec.scopes = scopes.value();
    rec.resource_uri = resource.value();
    rec.authorization_server = auth_srv.value();
    rec.token_endpoint = tok_ep.value();
    rec.client_id = cid.value();
    rec.expires_at = exp.value();
    rec.updated_at = upd.value();
    rec.revision = rev.value();

    if (const auto *extra_val = entry.find("extra_metadata"); extra_val != nullptr) {
      if (!std::holds_alternative<Value::Array>(extra_val->value()) ||
          extra_val->array().size() > kMaxExtraMetaPerRecord) {
        return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
      }
      for (const auto &pair_obj : extra_val->array()) {
        if (!std::holds_alternative<Value::Object>(pair_obj.value())) {
          return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
        }
        const auto k = get_req_str(pair_obj, "k");
        const auto v = get_req_str(pair_obj, "v");
        if (!k.has_value() || !v.has_value()) {
          return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
        }
        rec.extra_metadata.emplace_back(k.value(), v.value());
      }
    }

    if (!state.records.emplace(id.value(), std::move(rec)).second) {
      return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
    }
  }

  for (const auto &act : active_val->array()) {
    if (!std::holds_alternative<Value::Object>(act.value())) {
      return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
    }
    const auto svc = get_req_str(act, "service");
    const auto cid = get_req_u64(act, "id");
    if (!svc.has_value() || !cid.has_value()) {
      return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
    }
    const auto it = state.records.find(cid.value());
    if (it == state.records.end() || it->second.service != svc.value()) {
      return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
    }
    if (!state.active_by_service.emplace(svc.value(), cid.value()).second) {
      return fail_v<VaultState>(ErrorCode::corrupt, VaultError::corrupt_store);
    }
  }

  return Result<VaultState>::success(std::move(state));
}

// ---------------------------------------------------------------------------
// Locked binary store session (0700 dir, 0600 files, O_NOFOLLOW, flock, fsync)
// ---------------------------------------------------------------------------

class LockedStore {
public:
  static Result<LockedStore> open(const IntegrationVaultConfig &config, bool create) {
    if (config.directory.empty()) {
      return fail_v<LockedStore>(ErrorCode::invalid_range,
                                 VaultError::invalid_argument);
    }
    std::unique_lock<std::mutex> thread_lock{g_vault_mutex};

    if (create) {
      std::error_code ec;
      const auto parent = config.directory.parent_path();
      if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
          return fail_v<LockedStore>(ErrorCode::io, VaultError::io_failed);
        }
      }
      if (::mkdir(config.directory.c_str(), 0700) != 0 && errno != EEXIST) {
        return fail_v<LockedStore>(ErrorCode::io, VaultError::io_failed);
      }
    }

    const int raw_dir = ::open(config.directory.c_str(),
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (raw_dir < 0) {
      if (errno == ENOENT && !create) {
        return Result<LockedStore>::success(LockedStore{
            std::move(thread_lock), ScopedFd{-1}, ScopedFd{-1}, VaultState{}});
      }
      if (errno == ELOOP || errno == ENOTDIR) {
        return fail_v<LockedStore>(ErrorCode::conflict, VaultError::symlink_rejected);
      }
      return fail_v<LockedStore>(ErrorCode::io, VaultError::io_failed);
    }
    ScopedFd dir{raw_dir};
    if (const auto ok = verify_fd_permissions(dir.get(), true); !ok.has_value()) {
      return Result<LockedStore>::failure(ok.error());
    }

    const int raw_lock = ::openat(dir.get(), "integrations.lock",
                                  O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (raw_lock < 0) {
      if (errno == ELOOP) {
        return fail_v<LockedStore>(ErrorCode::conflict, VaultError::symlink_rejected);
      }
      return fail_v<LockedStore>(ErrorCode::io, VaultError::io_failed);
    }
    ScopedFd lock{raw_lock};
    if (const auto ok = verify_fd_permissions(lock.get(), false); !ok.has_value()) {
      return Result<LockedStore>::failure(ok.error());
    }

    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds{std::max(config.lock_timeout_ms, 100)};
    while (::flock(lock.get(), LOCK_EX | LOCK_NB) != 0) {
      if (errno != EWOULDBLOCK && errno != EAGAIN) {
        return fail_v<LockedStore>(ErrorCode::io, VaultError::io_failed);
      }
      if (config.cancelled && config.cancelled()) {
        return fail_v<LockedStore>(ErrorCode::interrupted, VaultError::cancelled);
      }
      if (std::chrono::steady_clock::now() >= deadline) {
        return fail_v<LockedStore>(ErrorCode::busy, VaultError::lock_timeout);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    VaultState state{};
    const int raw_file =
        ::openat(dir.get(), "integrations.bbm", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (raw_file < 0) {
      if (errno == ENOENT) {
        return Result<LockedStore>::success(LockedStore{
            std::move(thread_lock), std::move(dir), std::move(lock), std::move(state)});
      }
      if (errno == ELOOP) {
        return fail_v<LockedStore>(ErrorCode::conflict, VaultError::symlink_rejected);
      }
      return fail_v<LockedStore>(ErrorCode::io, VaultError::io_failed);
    }
    ScopedFd file{raw_file};
    if (const auto ok = verify_fd_permissions(file.get(), false); !ok.has_value()) {
      return Result<LockedStore>::failure(ok.error());
    }

    std::string bytes;
    const CleanseStringGuard cleanse_bytes{bytes};
    std::array<char, 4096> chunk{};
    off_t offset = 0;
    for (;;) {
      const ssize_t n = ::pread(file.get(), chunk.data(), chunk.size(), offset);
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n < 0) {
        OPENSSL_cleanse(chunk.data(), chunk.size());
        return fail_v<LockedStore>(ErrorCode::io, VaultError::io_failed);
      }
      if (n == 0) {
        break;
      }
      if (bytes.size() + static_cast<std::size_t>(n) > kStoreMaxBytes) {
        OPENSSL_cleanse(chunk.data(), chunk.size());
        return fail_v<LockedStore>(ErrorCode::capacity, VaultError::capacity_exceeded);
      }
      bytes.append(chunk.data(), static_cast<std::size_t>(n));
      offset += static_cast<off_t>(n);
    }
    OPENSSL_cleanse(chunk.data(), chunk.size());

    auto decoded = decode_vault_packet(bytes);
    if (!decoded.has_value()) {
      return Result<LockedStore>::failure(decoded.error());
    }
    state = std::move(decoded).value();
    return Result<LockedStore>::success(LockedStore{
        std::move(thread_lock), std::move(dir), std::move(lock), std::move(state)});
  }

  VaultState &state() noexcept { return state_; }
  const VaultState &state() const noexcept { return state_; }

  Result<void> commit() {
    if (!dir_) {
      return fail_vv(ErrorCode::io, VaultError::io_failed);
    }
    auto encoded = encode_vault_packet(state_);
    if (!encoded.has_value()) {
      return Result<void>::failure(encoded.error());
    }
    std::string bytes = std::move(encoded).value();
    const CleanseStringGuard cleanse_bytes{bytes};
    if (bytes.size() > kStoreMaxBytes) {
      return fail_vv(ErrorCode::capacity, VaultError::capacity_exceeded);
    }

    std::array<unsigned char, 16> rnd{};
    if (RAND_bytes(rnd.data(), static_cast<int>(rnd.size())) != 1) {
      return fail_vv(ErrorCode::io, VaultError::crypto_failed);
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string tmp_name = ".integrations-";
    for (const unsigned char b : rnd) {
      tmp_name.push_back(kHex[b >> 4U]);
      tmp_name.push_back(kHex[b & 15U]);
    }
    tmp_name.append(".tmp");

    const int raw_tmp =
        ::openat(dir_.get(), tmp_name.c_str(),
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (raw_tmp < 0) {
      return fail_vv(ErrorCode::io, VaultError::io_failed);
    }
    ScopedFd tmp{raw_tmp};
    std::size_t written = 0U;
    while (written < bytes.size()) {
      const ssize_t n =
          ::write(tmp.get(), bytes.data() + written, bytes.size() - written);
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n <= 0) {
        tmp.reset();
        (void)::unlinkat(dir_.get(), tmp_name.c_str(), 0);
        return fail_vv(ErrorCode::io, VaultError::io_failed);
      }
      written += static_cast<std::size_t>(n);
    }
    if (::fsync(tmp.get()) != 0) {
      tmp.reset();
      (void)::unlinkat(dir_.get(), tmp_name.c_str(), 0);
      return fail_vv(ErrorCode::io, VaultError::io_failed);
    }
    tmp.reset();

    if (::renameat(dir_.get(), tmp_name.c_str(), dir_.get(), "integrations.bbm") != 0) {
      (void)::unlinkat(dir_.get(), tmp_name.c_str(), 0);
      return fail_vv(ErrorCode::io, VaultError::io_failed);
    }
    if (::fsync(dir_.get()) != 0) {
      return fail_vv(ErrorCode::io, VaultError::io_failed);
    }
    return Result<void>::success();
  }

  StoredRecord *find_record_by_key(const ServiceAccountKey &key) {
    if (!is_valid_identifier(key.service)) {
      return nullptr;
    }
    if (key.account.empty()) {
      const auto act_it = state_.active_by_service.find(key.service);
      if (act_it == state_.active_by_service.end()) {
        return nullptr;
      }
      const auto rec_it = state_.records.find(act_it->second);
      return (rec_it == state_.records.end()) ? nullptr : &rec_it->second;
    }
    for (auto &[id_val, rec] : state_.records) {
      (void)id_val;
      if (rec.service == key.service && rec.account == key.account) {
        return &rec;
      }
    }
    return nullptr;
  }

  bool is_active(const StoredRecord &rec) const noexcept {
    const auto it = state_.active_by_service.find(rec.service);
    return it != state_.active_by_service.end() && it->second == rec.id.value;
  }

private:
  LockedStore(std::unique_lock<std::mutex> lock_guard, ScopedFd dir, ScopedFd lock_fd,
              VaultState state) noexcept
      : thread_lock_(std::move(lock_guard)), dir_(std::move(dir)),
        lock_(std::move(lock_fd)), state_(std::move(state)) {}

  std::unique_lock<std::mutex> thread_lock_;
  ScopedFd dir_;
  ScopedFd lock_;
  VaultState state_;
};

// ---------------------------------------------------------------------------
// JSON parsing helpers for OAuth 2.1 external wire boundaries
// ---------------------------------------------------------------------------

std::optional<std::string> json_opt_str(const Value &obj, std::string_view key) {
  const auto *p = obj.find(key);
  if (p == nullptr || !std::holds_alternative<std::string>(p->value())) {
    return std::nullopt;
  }
  return p->string();
}

std::optional<std::vector<std::string>> json_str_array(const Value &obj,
                                                       std::string_view key) {
  const auto *p = obj.find(key);
  if (p == nullptr || !std::holds_alternative<Value::Array>(p->value())) {
    return std::nullopt;
  }
  std::vector<std::string> out;
  for (const auto &item : p->array()) {
    if (!std::holds_alternative<std::string>(item.value())) {
      return std::nullopt;
    }
    out.push_back(item.string());
  }
  return out;
}

std::optional<std::int64_t> json_opt_i64(const Value &obj, std::string_view key) {
  const auto *p = obj.find(key);
  if (p == nullptr || !std::holds_alternative<Number>(p->value())) {
    return std::nullopt;
  }
  const std::string s = p->number().text();
  std::int64_t val = 0;
  const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val);
  if (ec != std::errc{} || ptr != s.data() + s.size()) {
    return std::nullopt;
  }
  return val;
}

Result<OAuthTokenResponse> parse_oauth_token_json(std::string_view body) {
  auto parsed = parse_json(body);
  if (!parsed.has_value() ||
      !std::holds_alternative<Value::Object>(parsed.value().value())) {
    return fail_v<OAuthTokenResponse>(ErrorCode::corrupt,
                                      VaultError::oauth_token_exchange_failed);
  }
  const Value &obj = parsed.value();
  const auto access = json_opt_str(obj, "access_token");
  if (!access.has_value() || !is_valid_secret_text(*access, false)) {
    return fail_v<OAuthTokenResponse>(ErrorCode::provider_auth,
                                      VaultError::oauth_token_exchange_failed);
  }
  const auto token_type = json_opt_str(obj, "token_type").value_or("Bearer");
  if (!ascii_iequals(token_type, "Bearer")) {
    return fail_v<OAuthTokenResponse>(ErrorCode::provider_auth,
                                      VaultError::oauth_token_exchange_failed);
  }
  const auto refresh = json_opt_str(obj, "refresh_token");
  if (refresh.has_value() && !is_valid_secret_text(*refresh, true)) {
    return fail_v<OAuthTokenResponse>(ErrorCode::provider_auth,
                                      VaultError::oauth_token_exchange_failed);
  }
  std::int64_t expires_in = 0;
  if (const auto exp = json_opt_i64(obj, "expires_in"); exp.has_value()) {
    if (*exp <= 0 || *exp > kMaxExpiresInSeconds) {
      return fail_v<OAuthTokenResponse>(ErrorCode::corrupt,
                                        VaultError::oauth_token_exchange_failed);
    }
    expires_in = *exp;
  }

  OAuthTokenResponse resp{};
  resp.access_token.assign(*access);
  if (refresh.has_value()) {
    resp.refresh_token.assign(*refresh);
  }
  resp.token_type = token_type;
  resp.expires_in = expires_in;
  resp.scope = json_opt_str(obj, "scope").value_or("");
  return Result<OAuthTokenResponse>::success(std::move(resp));
}

Result<CredentialMetadata> refresh_record_locked(LockedStore &store, StoredRecord &rec,
                                                 const IntegrationVaultConfig &config,
                                                 const net::HttpClient &http,
                                                 bool force) {
  const std::int64_t clock_now = now_seconds(config);
  if (!force && rec.expires_at > 0 &&
      clock_now + config.refresh_skew_seconds < rec.expires_at) {
    return Result<CredentialMetadata>::success(
        to_public_metadata(rec, store.is_active(rec), clock_now));
  }
  if (rec.refresh_token.empty() || rec.token_endpoint.empty()) {
    return fail_v<CredentialMetadata>(ErrorCode::provider_auth,
                                      VaultError::oauth_no_refresh_token);
  }

  OAuthTokenRefreshRequest req{};
  req.token_endpoint = rec.token_endpoint;
  req.client_id = rec.client_id;
  req.client_secret = rec.client_secret;
  req.refresh_token = rec.refresh_token;
  req.resource = rec.resource_uri;
  req.scope = join_space_scopes(rec.scopes);

  auto refreshed = refresh_oauth_token(http, req);
  if (!refreshed.has_value()) {
    return Result<CredentialMetadata>::failure(refreshed.error());
  }
  OAuthTokenResponse tok = std::move(refreshed).value();
  rec.access_token = std::move(tok.access_token);
  if (!tok.refresh_token.empty()) {
    rec.refresh_token = std::move(tok.refresh_token);
  }
  if (!tok.scope.empty()) {
    rec.scopes = split_space_scopes(tok.scope);
  }
  const std::int64_t updated_now = now_seconds(config);
  rec.expires_at = (tok.expires_in > 0) ? (updated_now + tok.expires_in) : 0;
  rec.updated_at = updated_now;
  ++rec.revision;

  if (const auto saved = store.commit(); !saved.has_value()) {
    return Result<CredentialMetadata>::failure(saved.error());
  }
  return Result<CredentialMetadata>::success(
      to_public_metadata(rec, store.is_active(rec), updated_now));
}

Result<CredentialMetadata>
authorize_record_locked(LockedStore &store, StoredRecord &rec,
                        const IntegrationVaultConfig &config, net::HttpRequest &request,
                        const AuthorizeRequestOptions &options) {
  // Step 1: Parse target URL and enforce mandatory HTTPS (no HTTP downgrade).
  auto parsed_res = net::parse_url(request.url);
  if (!parsed_res.has_value()) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_range,
                                      VaultError::invalid_url);
  }
  const net::ParsedUrl &url = parsed_res.value();
  if (url.scheme != "https") {
    return fail_v<CredentialMetadata>(ErrorCode::conflict, VaultError::https_required);
  }

  // Step 2: Enforce mandatory host pinning BEFORE touching request.headers.
  auto policy = net::AllowedHostPolicy::pinned(rec.allowed_hosts);
  policy.allow_loopback = options.allow_loopback_host_for_testing;
  if (const auto ok = policy.validate_url(url); !ok.has_value()) {
    return fail_v<CredentialMetadata>(ErrorCode::conflict, VaultError::host_not_pinned);
  }

  // Step 3: Proactive lock-serialized single-flight OAuth 2.1 refresh if near expiry.
  const std::int64_t clock_now = now_seconds(config);
  const bool needs_refresh =
      options.auto_refresh && rec.scheme == AuthScheme::bearer_oauth2 &&
      rec.expires_at > 0 && clock_now + config.refresh_skew_seconds >= rec.expires_at &&
      !rec.refresh_token.empty() && !rec.token_endpoint.empty();
  if (needs_refresh) {
    if (options.refresh_http != nullptr) {
      const auto ref =
          refresh_record_locked(store, rec, config, *options.refresh_http, false);
      if (!ref.has_value()) {
        return Result<CredentialMetadata>::failure(ref.error());
      }
    } else if (config.refresh_http_config.has_value()) {
      const net::HttpClient client{*config.refresh_http_config};
      const auto ref = refresh_record_locked(store, rec, config, client, false);
      if (!ref.has_value()) {
        return Result<CredentialMetadata>::failure(ref.error());
      }
    }
  }

  // Step 4: Construct auth header value safely and inject into request.
  std::string header_value;
  const CleanseStringGuard cleanse_hdr{header_value};
  if (rec.scheme == AuthScheme::basic_token) {
    std::string b64 = base64_std_encode(rec.access_token.view());
    const CleanseStringGuard cleanse_b64{b64};
    header_value = rec.auth_header_prefix + b64;
  } else {
    header_value.reserve(rec.auth_header_prefix.size() + rec.access_token.size());
    header_value.append(rec.auth_header_prefix);
    header_value.append(rec.access_token.view());
  }
  request.set_header({rec.auth_header_name, header_value});

  return Result<CredentialMetadata>::success(
      to_public_metadata(rec, store.is_active(rec), now_seconds(config)));
}

} // namespace

// ---------------------------------------------------------------------------
// VaultError & AuthScheme names
// ---------------------------------------------------------------------------

std::string_view vault_error_name(VaultError detail) noexcept {
  switch (detail) {
  case VaultError::none:
    return "none";
  case VaultError::invalid_argument:
    return "invalid_argument";
  case VaultError::invalid_url:
    return "invalid_url";
  case VaultError::not_found:
    return "not_found";
  case VaultError::already_exists:
    return "already_exists";
  case VaultError::insecure_permissions:
    return "insecure_permissions";
  case VaultError::symlink_rejected:
    return "symlink_rejected";
  case VaultError::corrupt_store:
    return "corrupt_store";
  case VaultError::lock_timeout:
    return "lock_timeout";
  case VaultError::io_failed:
    return "io_failed";
  case VaultError::host_not_pinned:
    return "host_not_pinned";
  case VaultError::https_required:
    return "https_required";
  case VaultError::crypto_failed:
    return "crypto_failed";
  case VaultError::oauth_challenge_invalid:
    return "oauth_challenge_invalid";
  case VaultError::oauth_metadata_invalid:
    return "oauth_metadata_invalid";
  case VaultError::oauth_pkce_unsupported:
    return "oauth_pkce_unsupported";
  case VaultError::oauth_registration_failed:
    return "oauth_registration_failed";
  case VaultError::oauth_callback_timeout:
    return "oauth_callback_timeout";
  case VaultError::oauth_callback_rejected:
    return "oauth_callback_rejected";
  case VaultError::oauth_token_exchange_failed:
    return "oauth_token_exchange_failed";
  case VaultError::oauth_refresh_failed:
    return "oauth_refresh_failed";
  case VaultError::oauth_no_refresh_token:
    return "oauth_no_refresh_token";
  case VaultError::cancelled:
    return "cancelled";
  case VaultError::capacity_exceeded:
    return "capacity_exceeded";
  }
  return "unknown";
}

std::string_view auth_scheme_name(AuthScheme scheme) noexcept {
  switch (scheme) {
  case AuthScheme::bearer_oauth2:
    return "bearer_oauth2";
  case AuthScheme::bearer_pat:
    return "bearer_pat";
  case AuthScheme::discord_bot:
    return "discord_bot";
  case AuthScheme::header_key:
    return "header_key";
  case AuthScheme::basic_token:
    return "basic_token";
  }
  return "bearer_oauth2";
}

Result<AuthScheme> parse_auth_scheme(std::string_view name) noexcept {
  if (name == "bearer_oauth2") {
    return Result<AuthScheme>::success(AuthScheme::bearer_oauth2);
  }
  if (name == "bearer_pat") {
    return Result<AuthScheme>::success(AuthScheme::bearer_pat);
  }
  if (name == "discord_bot") {
    return Result<AuthScheme>::success(AuthScheme::discord_bot);
  }
  if (name == "header_key") {
    return Result<AuthScheme>::success(AuthScheme::header_key);
  }
  if (name == "basic_token") {
    return Result<AuthScheme>::success(AuthScheme::basic_token);
  }
  return fail_v<AuthScheme>(ErrorCode::corrupt, VaultError::corrupt_store);
}

// ---------------------------------------------------------------------------
// CleansedSecret
// ---------------------------------------------------------------------------

CleansedSecret::CleansedSecret(const CleansedSecret &other) : value_(other.value_) {}

CleansedSecret &CleansedSecret::operator=(const CleansedSecret &other) {
  if (this != &other) {
    cleanse();
    value_ = other.value_;
  }
  return *this;
}

CleansedSecret::CleansedSecret(CleansedSecret &&other) noexcept
    : value_(std::move(other.value_)) {
  other.cleanse();
}

CleansedSecret &CleansedSecret::operator=(CleansedSecret &&other) noexcept {
  if (this != &other) {
    cleanse();
    value_ = std::move(other.value_);
    other.cleanse();
  }
  return *this;
}

CleansedSecret::~CleansedSecret() { cleanse(); }

void CleansedSecret::assign(std::string_view next) {
  cleanse();
  value_.assign(next.data(), next.size());
}

void CleansedSecret::clear() noexcept { cleanse(); }

void CleansedSecret::cleanse() noexcept {
  if (!value_.empty()) {
    OPENSSL_cleanse(value_.data(), value_.size());
    value_.clear();
  }
}

// ---------------------------------------------------------------------------
// PKCE S256 & CSRF state (in-process OpenSSL 3 libcrypto)
// ---------------------------------------------------------------------------

Result<std::string> compute_pkce_s256_challenge(std::string_view code_verifier) {
  if (code_verifier.size() < 43U || code_verifier.size() > 128U) {
    return fail_v<std::string>(ErrorCode::invalid_range, VaultError::invalid_argument);
  }
  for (const char c : code_verifier) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
                    c == '~';
    if (!ok) {
      return fail_v<std::string>(ErrorCode::invalid_range,
                                 VaultError::invalid_argument);
    }
  }
  std::array<std::uint8_t, 32> digest{};
  unsigned int digest_len = 0U;
  if (EVP_Digest(code_verifier.data(), code_verifier.size(), digest.data(), &digest_len,
                 EVP_sha256(), nullptr) != 1 ||
      digest_len != digest.size()) {
    return fail_v<std::string>(ErrorCode::io, VaultError::crypto_failed);
  }
  return Result<std::string>::success(base64url_encode(digest));
}

Result<OAuthPkcePair> generate_pkce_s256() {
  std::array<std::uint8_t, 32> raw{};
  if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
    return fail_v<OAuthPkcePair>(ErrorCode::io, VaultError::crypto_failed);
  }
  std::string verifier_str = base64url_encode(raw);
  OPENSSL_cleanse(raw.data(), raw.size());
  const CleanseStringGuard cleanse_v{verifier_str};

  auto challenge = compute_pkce_s256_challenge(verifier_str);
  if (!challenge.has_value()) {
    return Result<OAuthPkcePair>::failure(challenge.error());
  }
  OAuthPkcePair pair{};
  pair.code_verifier.assign(verifier_str);
  pair.code_challenge = std::move(challenge).value();
  pair.method = "S256";
  return Result<OAuthPkcePair>::success(std::move(pair));
}

Result<std::string> generate_oauth_state() {
  std::array<std::uint8_t, 32> raw{};
  if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
    return fail_v<std::string>(ErrorCode::io, VaultError::crypto_failed);
  }
  std::string state = base64url_encode(raw);
  OPENSSL_cleanse(raw.data(), raw.size());
  return Result<std::string>::success(std::move(state));
}

// ---------------------------------------------------------------------------
// RFC 9728 WWW-Authenticate Bearer & Protected Resource Metadata
// ---------------------------------------------------------------------------

Result<WwwAuthenticateChallenge>
parse_www_authenticate_bearer(std::string_view header_value) {
  auto skip_ws_and_commas = [&](std::size_t &pos) {
    while (pos < header_value.size() &&
           (header_value[pos] == ' ' || header_value[pos] == '\t' ||
            header_value[pos] == ',')) {
      ++pos;
    }
  };
  auto is_token_char = [](char c) noexcept {
    const auto b = static_cast<std::uint8_t>(c);
    return b > 0x20U && b < 0x7fU && c != '"' && c != ',' && c != '=' && c != ';';
  };

  std::size_t pos = 0U;
  while (pos < header_value.size()) {
    skip_ws_and_commas(pos);
    if (pos >= header_value.size()) {
      break;
    }
    const std::size_t scheme_start = pos;
    while (pos < header_value.size() && is_token_char(header_value[pos])) {
      ++pos;
    }
    const std::string_view scheme =
        header_value.substr(scheme_start, pos - scheme_start);
    if (scheme.empty()) {
      return fail_v<WwwAuthenticateChallenge>(ErrorCode::corrupt,
                                              VaultError::oauth_challenge_invalid);
    }

    WwwAuthenticateChallenge challenge{};
    challenge.scheme = std::string{scheme};

    while (pos < header_value.size()) {
      while (pos < header_value.size() &&
             (header_value[pos] == ' ' || header_value[pos] == '\t')) {
        ++pos;
      }
      if (pos >= header_value.size()) {
        break;
      }
      if (header_value[pos] == ',') {
        ++pos;
        while (pos < header_value.size() &&
               (header_value[pos] == ' ' || header_value[pos] == '\t')) {
          ++pos;
        }
        // Peek whether next token is a new auth-scheme (no '=') or another param.
        std::size_t peek = pos;
        while (peek < header_value.size() && is_token_char(header_value[peek])) {
          ++peek;
        }
        while (peek < header_value.size() &&
               (header_value[peek] == ' ' || header_value[peek] == '\t')) {
          ++peek;
        }
        if (peek >= header_value.size() || header_value[peek] != '=') {
          break; // New challenge starts at pos.
        }
      }

      const std::size_t key_start = pos;
      while (pos < header_value.size() && is_token_char(header_value[pos])) {
        ++pos;
      }
      const std::string_view raw_key = header_value.substr(key_start, pos - key_start);
      while (pos < header_value.size() &&
             (header_value[pos] == ' ' || header_value[pos] == '\t')) {
        ++pos;
      }
      if (raw_key.empty() || pos >= header_value.size() || header_value[pos] != '=') {
        return fail_v<WwwAuthenticateChallenge>(ErrorCode::corrupt,
                                                VaultError::oauth_challenge_invalid);
      }
      ++pos; // consume '='
      while (pos < header_value.size() &&
             (header_value[pos] == ' ' || header_value[pos] == '\t')) {
        ++pos;
      }
      if (pos >= header_value.size()) {
        return fail_v<WwwAuthenticateChallenge>(ErrorCode::corrupt,
                                                VaultError::oauth_challenge_invalid);
      }

      std::string val;
      if (header_value[pos] == '"') {
        ++pos;
        bool closed = false;
        while (pos < header_value.size()) {
          const char ch = header_value[pos++];
          if (ch == '\\') {
            if (pos >= header_value.size()) {
              return fail_v<WwwAuthenticateChallenge>(
                  ErrorCode::corrupt, VaultError::oauth_challenge_invalid);
            }
            val.push_back(header_value[pos++]);
          } else if (ch == '"') {
            closed = true;
            break;
          } else {
            val.push_back(ch);
          }
        }
        if (!closed) {
          return fail_v<WwwAuthenticateChallenge>(ErrorCode::corrupt,
                                                  VaultError::oauth_challenge_invalid);
        }
      } else {
        const std::size_t val_start = pos;
        while (pos < header_value.size() && is_token_char(header_value[pos])) {
          ++pos;
        }
        val.assign(header_value.substr(val_start, pos - val_start));
      }

      const std::string key = ascii_lower(raw_key);
      if (key == "resource_metadata") {
        challenge.resource_metadata = val;
      } else if (key == "scope") {
        challenge.scope = val;
      } else if (key == "error") {
        challenge.error = val;
      } else if (key == "error_description") {
        challenge.error_description = val;
      } else if (key == "realm") {
        challenge.realm = val;
      }
      challenge.params.emplace_back(key, std::move(val));
    }

    if (ascii_iequals(challenge.scheme, "Bearer")) {
      challenge.scheme = "Bearer";
      return Result<WwwAuthenticateChallenge>::success(std::move(challenge));
    }
  }

  return fail_v<WwwAuthenticateChallenge>(ErrorCode::corrupt,
                                          VaultError::oauth_challenge_invalid);
}

Result<ProtectedResourceMetadata>
parse_protected_resource_metadata(std::string_view json_body) {
  auto parsed = parse_json(json_body);
  if (!parsed.has_value() ||
      !std::holds_alternative<Value::Object>(parsed.value().value())) {
    return fail_v<ProtectedResourceMetadata>(ErrorCode::corrupt,
                                             VaultError::oauth_metadata_invalid);
  }
  const Value &obj = parsed.value();
  const auto resource = json_opt_str(obj, "resource");
  const auto auth_servers = json_str_array(obj, "authorization_servers");
  if (!resource.has_value() || !require_https_url(*resource).has_value() ||
      !auth_servers.has_value() || auth_servers->empty()) {
    return fail_v<ProtectedResourceMetadata>(ErrorCode::corrupt,
                                             VaultError::oauth_metadata_invalid);
  }
  for (const auto &as_url : *auth_servers) {
    if (!require_https_url(as_url).has_value()) {
      return fail_v<ProtectedResourceMetadata>(ErrorCode::conflict,
                                               VaultError::https_required);
    }
  }

  ProtectedResourceMetadata meta{};
  meta.resource = *resource;
  meta.authorization_servers = *auth_servers;
  if (const auto scopes = json_str_array(obj, "scopes_supported"); scopes.has_value()) {
    meta.scopes_supported = *scopes;
  }
  if (const auto methods = json_str_array(obj, "bearer_methods_supported");
      methods.has_value()) {
    meta.bearer_methods_supported = *methods;
  }
  meta.resource_name = json_opt_str(obj, "resource_name").value_or("");
  return Result<ProtectedResourceMetadata>::success(std::move(meta));
}

Result<ProtectedResourceMetadata>
fetch_protected_resource_metadata(const net::HttpClient &http,
                                  std::string_view metadata_url) {
  if (const auto ok = require_https_url(metadata_url); !ok.has_value()) {
    return Result<ProtectedResourceMetadata>::failure(ok.error());
  }
  net::HttpRequest req{};
  req.method = net::HttpMethod::get;
  req.url = std::string{metadata_url};
  req.set_header({"Accept", "application/json"});
  const auto resp = http.request(req);
  if (!resp.has_value()) {
    return Result<ProtectedResourceMetadata>::failure(resp.error());
  }
  if (resp.value().status < 200 || resp.value().status >= 300) {
    return fail_v<ProtectedResourceMetadata>(ErrorCode::provider_transport,
                                             VaultError::oauth_metadata_invalid);
  }
  return parse_protected_resource_metadata(resp.value().body_as_string());
}

// ---------------------------------------------------------------------------
// RFC 8414 Authorization Server Metadata (+ MCP 2025-11-25 CIMD)
// ---------------------------------------------------------------------------

Result<std::string> build_as_metadata_url(std::string_view issuer_url) {
  auto parsed = net::parse_url(issuer_url);
  if (!parsed.has_value()) {
    return fail_v<std::string>(ErrorCode::invalid_range, VaultError::invalid_url);
  }
  if (parsed.value().scheme != "https" || !parsed.value().query.empty()) {
    return fail_v<std::string>(ErrorCode::conflict, VaultError::https_required);
  }
  std::string path = parsed.value().path;
  while (path.size() > 1U && path.back() == '/') {
    path.pop_back();
  }
  if (path == "/") {
    return Result<std::string>::success(parsed.value().canonical_origin() +
                                        "/.well-known/oauth-authorization-server");
  }
  return Result<std::string>::success(parsed.value().canonical_origin() +
                                      "/.well-known/oauth-authorization-server" + path);
}

Result<AuthorizationServerMetadata>
parse_authorization_server_metadata(std::string_view json_body,
                                    bool require_pkce_s256) {
  auto parsed = parse_json(json_body);
  if (!parsed.has_value() ||
      !std::holds_alternative<Value::Object>(parsed.value().value())) {
    return fail_v<AuthorizationServerMetadata>(ErrorCode::corrupt,
                                               VaultError::oauth_metadata_invalid);
  }
  const Value &obj = parsed.value();
  const auto issuer = json_opt_str(obj, "issuer");
  const auto auth_ep = json_opt_str(obj, "authorization_endpoint");
  const auto token_ep = json_opt_str(obj, "token_endpoint");
  const auto reg_ep = json_opt_str(obj, "registration_endpoint");

  if (!issuer.has_value() || !auth_ep.has_value() || !token_ep.has_value()) {
    return fail_v<AuthorizationServerMetadata>(ErrorCode::corrupt,
                                               VaultError::oauth_metadata_invalid);
  }
  if (!require_https_url(*issuer).has_value() ||
      !require_https_url(*auth_ep).has_value() ||
      !require_https_url(*token_ep).has_value()) {
    return fail_v<AuthorizationServerMetadata>(ErrorCode::conflict,
                                               VaultError::https_required);
  }
  if (reg_ep.has_value() && !reg_ep->empty() &&
      !require_https_url(*reg_ep).has_value()) {
    return fail_v<AuthorizationServerMetadata>(ErrorCode::conflict,
                                               VaultError::https_required);
  }

  AuthorizationServerMetadata meta{};
  meta.issuer = *issuer;
  meta.authorization_endpoint = *auth_ep;
  meta.token_endpoint = *token_ep;
  if (reg_ep.has_value()) {
    meta.registration_endpoint = *reg_ep;
  }
  if (const auto s = json_str_array(obj, "scopes_supported"); s.has_value()) {
    meta.scopes_supported = *s;
  }
  if (const auto s = json_str_array(obj, "response_types_supported"); s.has_value()) {
    meta.response_types_supported = *s;
  }
  if (const auto s = json_str_array(obj, "grant_types_supported"); s.has_value()) {
    meta.grant_types_supported = *s;
  }
  if (const auto s = json_str_array(obj, "code_challenge_methods_supported");
      s.has_value()) {
    meta.code_challenge_methods_supported = *s;
  }
  if (const auto s = json_str_array(obj, "token_endpoint_auth_methods_supported");
      s.has_value()) {
    meta.token_endpoint_auth_methods_supported = *s;
  }
  if (const auto *cimd = obj.find("client_id_metadata_document_supported");
      cimd != nullptr && std::holds_alternative<bool>(cimd->value())) {
    meta.client_id_metadata_document_supported = std::get<bool>(cimd->value());
  }

  if (require_pkce_s256) {
    const bool has_s256 =
        std::find(meta.code_challenge_methods_supported.begin(),
                  meta.code_challenge_methods_supported.end(),
                  "S256") != meta.code_challenge_methods_supported.end();
    if (!has_s256) {
      return fail_v<AuthorizationServerMetadata>(ErrorCode::conflict,
                                                 VaultError::oauth_pkce_unsupported);
    }
  }
  return Result<AuthorizationServerMetadata>::success(std::move(meta));
}

Result<AuthorizationServerMetadata> fetch_authorization_server_metadata(
    const net::HttpClient &http, std::string_view issuer_url, bool require_pkce_s256) {
  auto url_res = build_as_metadata_url(issuer_url);
  if (!url_res.has_value()) {
    return Result<AuthorizationServerMetadata>::failure(url_res.error());
  }

  auto try_fetch = [&](const std::string &url) -> Result<net::HttpResponse> {
    net::HttpRequest req{};
    req.method = net::HttpMethod::get;
    req.url = url;
    req.set_header({"Accept", "application/json"});
    return http.request(req);
  };

  auto resp = try_fetch(url_res.value());
  if (!resp.has_value()) {
    return Result<AuthorizationServerMetadata>::failure(resp.error());
  }
  if (resp.value().status == 404) {
    // OIDC discovery fallback: <issuer>/.well-known/openid-configuration
    std::string fallback{issuer_url};
    while (fallback.size() > 8U && fallback.back() == '/') {
      fallback.pop_back();
    }
    fallback.append("/.well-known/openid-configuration");
    resp = try_fetch(fallback);
    if (!resp.has_value()) {
      return Result<AuthorizationServerMetadata>::failure(resp.error());
    }
  }
  if (resp.value().status < 200 || resp.value().status >= 300) {
    return fail_v<AuthorizationServerMetadata>(ErrorCode::provider_transport,
                                               VaultError::oauth_metadata_invalid);
  }

  auto meta = parse_authorization_server_metadata(resp.value().body_as_string(),
                                                  require_pkce_s256);
  if (!meta.has_value()) {
    return Result<AuthorizationServerMetadata>::failure(meta.error());
  }

  // RFC 8414 §3.3 mix-up defense: returned issuer must match requested issuer.
  auto strip_trailing_slash = [](std::string_view s) {
    while (s.size() > 8U && s.back() == '/') {
      s.remove_suffix(1U);
    }
    return s;
  };
  if (strip_trailing_slash(meta.value().issuer) != strip_trailing_slash(issuer_url)) {
    return fail_v<AuthorizationServerMetadata>(ErrorCode::conflict,
                                               VaultError::oauth_metadata_invalid);
  }
  return meta;
}

// ---------------------------------------------------------------------------
// RFC 7591 Dynamic Client Registration (DCR) + CIMD
// ---------------------------------------------------------------------------

Result<OAuthClientRegistration>
register_dynamic_client(const net::HttpClient &http,
                        std::string_view registration_endpoint,
                        const OAuthClientRegistrationRequest &req) {
  if (const auto ok = require_https_url(registration_endpoint); !ok.has_value()) {
    return Result<OAuthClientRegistration>::failure(ok.error());
  }
  if (req.client_name.empty() || req.redirect_uris.empty()) {
    return fail_v<OAuthClientRegistration>(ErrorCode::invalid_range,
                                           VaultError::invalid_argument);
  }

  Value::Object payload{
      {"client_name", Value{req.client_name}},
      {"redirect_uris", make_str_array(req.redirect_uris)},
      {"grant_types", make_str_array(req.grant_types)},
      {"response_types", make_str_array(req.response_types)},
      {"token_endpoint_auth_method", Value{req.token_endpoint_auth_method}},
  };
  if (!req.scope.empty()) {
    payload.emplace_back("scope", Value{req.scope});
  }
  auto json_res = dump_json(Value::object(std::move(payload)));
  if (!json_res.has_value()) {
    return fail_v<OAuthClientRegistration>(ErrorCode::invalid_range,
                                           VaultError::oauth_registration_failed);
  }

  net::HttpRequest http_req{};
  http_req.method = net::HttpMethod::post;
  http_req.url = std::string{registration_endpoint};
  http_req.set_header({"Content-Type", "application/json"});
  http_req.set_header({"Accept", "application/json"});
  http_req.set_body_string(json_res.value());

  const auto resp = http.request(http_req);
  if (!resp.has_value()) {
    return Result<OAuthClientRegistration>::failure(resp.error());
  }
  if (resp.value().status < 200 || resp.value().status >= 300) {
    return fail_v<OAuthClientRegistration>(ErrorCode::provider_auth,
                                           VaultError::oauth_registration_failed);
  }
  auto parsed = parse_json(resp.value().body_as_string());
  if (!parsed.has_value() ||
      !std::holds_alternative<Value::Object>(parsed.value().value())) {
    return fail_v<OAuthClientRegistration>(ErrorCode::corrupt,
                                           VaultError::oauth_registration_failed);
  }
  const Value &obj = parsed.value();
  const auto client_id = json_opt_str(obj, "client_id");
  if (!client_id.has_value() || client_id->empty() || client_id->size() > 512U) {
    return fail_v<OAuthClientRegistration>(ErrorCode::corrupt,
                                           VaultError::oauth_registration_failed);
  }
  OAuthClientRegistration out{};
  out.client_id = *client_id;
  if (const auto secret = json_opt_str(obj, "client_secret"); secret.has_value()) {
    if (!is_valid_secret_text(*secret, true)) {
      return fail_v<OAuthClientRegistration>(ErrorCode::corrupt,
                                             VaultError::oauth_registration_failed);
    }
    out.client_secret.assign(*secret);
  }
  out.token_endpoint_auth_method = json_opt_str(obj, "token_endpoint_auth_method")
                                       .value_or(req.token_endpoint_auth_method);
  out.via_cimd = false;
  return Result<OAuthClientRegistration>::success(std::move(out));
}

Result<OAuthClientRegistration>
resolve_oauth_client(const net::HttpClient &http,
                     const AuthorizationServerMetadata &as_meta,
                     const OAuthClientResolutionOptions &opts) {
  // 1. Pre-configured / static client_id.
  if (!opts.static_client_id.empty()) {
    OAuthClientRegistration out{};
    out.client_id = opts.static_client_id;
    out.client_secret = opts.static_client_secret;
    out.token_endpoint_auth_method =
        out.client_secret.empty() ? "none" : "client_secret_post";
    out.via_cimd = false;
    return Result<OAuthClientRegistration>::success(std::move(out));
  }

  // 2. Client ID Metadata Document (CIMD — MCP 2025-11-25 preferred).
  if (as_meta.client_id_metadata_document_supported &&
      !opts.cimd_client_id_url.empty()) {
    auto parsed = net::parse_url(opts.cimd_client_id_url);
    if (!parsed.has_value() || parsed.value().scheme != "https" ||
        parsed.value().path.size() <= 1U) {
      return fail_v<OAuthClientRegistration>(ErrorCode::invalid_range,
                                             VaultError::invalid_url);
    }
    OAuthClientRegistration out{};
    out.client_id = opts.cimd_client_id_url;
    out.token_endpoint_auth_method = "none";
    out.via_cimd = true;
    return Result<OAuthClientRegistration>::success(std::move(out));
  }

  // 3. RFC 7591 Dynamic Client Registration fallback.
  if (!as_meta.registration_endpoint.empty()) {
    return register_dynamic_client(http, as_meta.registration_endpoint,
                                   opts.dcr_request);
  }

  return fail_v<OAuthClientRegistration>(ErrorCode::unsupported,
                                         VaultError::oauth_registration_failed);
}

// ---------------------------------------------------------------------------
// Authorization URL builder & Token Exchange / Refresh (RFC 8707)
// ---------------------------------------------------------------------------

Result<std::string> build_oauth_authorize_url(const OAuthAuthorizeUrlParams &params) {
  if (const auto ok = require_https_url(params.authorization_endpoint);
      !ok.has_value()) {
    return Result<std::string>::failure(ok.error());
  }
  if (params.client_id.empty() || params.redirect_uri.empty() || params.state.empty() ||
      params.code_challenge.empty() || params.code_challenge_method != "S256") {
    return fail_v<std::string>(ErrorCode::invalid_range, VaultError::invalid_argument);
  }
  if (!params.resource.empty()) {
    if (const auto ok = require_https_url(params.resource); !ok.has_value()) {
      return Result<std::string>::failure(ok.error());
    }
  }

  std::string url = params.authorization_endpoint;
  url.push_back(url.find('?') == std::string::npos ? '?' : '&');
  url.append("response_type=code&client_id=");
  url.append(form_encode(params.client_id));
  url.append("&redirect_uri=");
  url.append(form_encode(params.redirect_uri));
  url.append("&state=");
  url.append(form_encode(params.state));
  url.append("&code_challenge=");
  url.append(form_encode(params.code_challenge));
  url.append("&code_challenge_method=S256");
  if (!params.scope.empty()) {
    url.append("&scope=");
    url.append(form_encode(params.scope));
  }
  if (!params.resource.empty()) {
    url.append("&resource=");
    url.append(form_encode(params.resource));
  }
  return Result<std::string>::success(std::move(url));
}

Result<OAuthTokenResponse>
exchange_oauth_authorization_code(const net::HttpClient &http,
                                  const OAuthTokenExchangeRequest &req) {
  if (const auto ok = require_https_url(req.token_endpoint); !ok.has_value()) {
    return Result<OAuthTokenResponse>::failure(ok.error());
  }
  if (req.client_id.empty() || req.code.empty() || req.redirect_uri.empty() ||
      req.code_verifier.empty()) {
    return fail_v<OAuthTokenResponse>(ErrorCode::invalid_range,
                                      VaultError::invalid_argument);
  }
  if (!req.resource.empty()) {
    if (const auto ok = require_https_url(req.resource); !ok.has_value()) {
      return Result<OAuthTokenResponse>::failure(ok.error());
    }
  }

  std::string body =
      "grant_type=authorization_code&client_id=" + form_encode(req.client_id) +
      "&code=" + form_encode(req.code) +
      "&redirect_uri=" + form_encode(req.redirect_uri) +
      "&code_verifier=" + form_encode(req.code_verifier.view());
  const CleanseStringGuard cleanse_body{body};
  if (!req.client_secret.empty()) {
    body.append("&client_secret=");
    body.append(form_encode(req.client_secret.view()));
  }
  if (!req.resource.empty()) {
    body.append("&resource=");
    body.append(form_encode(req.resource));
  }

  net::HttpRequest http_req{};
  http_req.method = net::HttpMethod::post;
  http_req.url = req.token_endpoint;
  http_req.set_header({"Content-Type", "application/x-www-form-urlencoded"});
  http_req.set_header({"Accept", "application/json"});
  http_req.set_body_string(body);

  const auto resp = http.request(http_req);
  if (!http_req.body.empty()) {
    OPENSSL_cleanse(http_req.body.data(), http_req.body.size());
  }
  if (!resp.has_value()) {
    return Result<OAuthTokenResponse>::failure(resp.error());
  }
  if (resp.value().status < 200 || resp.value().status >= 300) {
    return fail_v<OAuthTokenResponse>(ErrorCode::provider_auth,
                                      VaultError::oauth_token_exchange_failed);
  }
  std::string resp_body = resp.value().body_as_string();
  const CleanseStringGuard cleanse_resp{resp_body};
  return parse_oauth_token_json(resp_body);
}

Result<OAuthTokenResponse> refresh_oauth_token(const net::HttpClient &http,
                                               const OAuthTokenRefreshRequest &req) {
  if (const auto ok = require_https_url(req.token_endpoint); !ok.has_value()) {
    return Result<OAuthTokenResponse>::failure(ok.error());
  }
  if (req.refresh_token.empty()) {
    return fail_v<OAuthTokenResponse>(ErrorCode::invalid_range,
                                      VaultError::oauth_no_refresh_token);
  }
  if (!req.resource.empty()) {
    if (const auto ok = require_https_url(req.resource); !ok.has_value()) {
      return Result<OAuthTokenResponse>::failure(ok.error());
    }
  }

  std::string body =
      "grant_type=refresh_token&refresh_token=" + form_encode(req.refresh_token.view());
  const CleanseStringGuard cleanse_body{body};
  if (!req.client_id.empty()) {
    body.append("&client_id=");
    body.append(form_encode(req.client_id));
  }
  if (!req.client_secret.empty()) {
    body.append("&client_secret=");
    body.append(form_encode(req.client_secret.view()));
  }
  if (!req.resource.empty()) {
    body.append("&resource=");
    body.append(form_encode(req.resource));
  }
  if (!req.scope.empty()) {
    body.append("&scope=");
    body.append(form_encode(req.scope));
  }

  net::HttpRequest http_req{};
  http_req.method = net::HttpMethod::post;
  http_req.url = req.token_endpoint;
  http_req.set_header({"Content-Type", "application/x-www-form-urlencoded"});
  http_req.set_header({"Accept", "application/json"});
  http_req.set_body_string(body);

  const auto resp = http.request(http_req);
  if (!http_req.body.empty()) {
    OPENSSL_cleanse(http_req.body.data(), http_req.body.size());
  }
  if (!resp.has_value()) {
    return Result<OAuthTokenResponse>::failure(resp.error());
  }
  if (resp.value().status < 200 || resp.value().status >= 300) {
    return fail_v<OAuthTokenResponse>(ErrorCode::provider_auth,
                                      VaultError::oauth_refresh_failed);
  }
  std::string resp_body = resp.value().body_as_string();
  const CleanseStringGuard cleanse_resp{resp_body};
  auto parsed = parse_oauth_token_json(resp_body);
  if (!parsed.has_value()) {
    return fail_v<OAuthTokenResponse>(ErrorCode::provider_auth,
                                      VaultError::oauth_refresh_failed);
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// OAuthLoopbackListener (127.0.0.1:0 ephemeral HTTP callback)
// ---------------------------------------------------------------------------

Result<OAuthLoopbackListener> OAuthLoopbackListener::bind() {
  const int raw_fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (raw_fd < 0) {
    return fail_v<OAuthLoopbackListener>(ErrorCode::io, VaultError::io_failed);
  }
  ScopedFd sock{raw_fd};
  if (::fcntl(sock.get(), F_SETFD, FD_CLOEXEC) < 0 ||
      ::fcntl(sock.get(), F_SETFL, O_NONBLOCK) < 0) {
    return fail_v<OAuthLoopbackListener>(ErrorCode::io, VaultError::io_failed);
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0U;
  if (::bind(sock.get(), reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) !=
          0 ||
      ::listen(sock.get(), 4) != 0) {
    return fail_v<OAuthLoopbackListener>(ErrorCode::io, VaultError::io_failed);
  }
  socklen_t len = sizeof(addr);
  if (::getsockname(sock.get(), reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
    return fail_v<OAuthLoopbackListener>(ErrorCode::io, VaultError::io_failed);
  }
  OAuthLoopbackListener listener{BoundSocket{sock.release(), ntohs(addr.sin_port)}};
  return Result<OAuthLoopbackListener>::success(std::move(listener));
}

OAuthLoopbackListener::OAuthLoopbackListener(OAuthLoopbackListener &&other) noexcept
    : fd_(std::exchange(other.fd_, -1)), port_(std::exchange(other.port_, 0U)),
      rejected_count_(other.rejected_count_) {}

OAuthLoopbackListener &
OAuthLoopbackListener::operator=(OAuthLoopbackListener &&other) noexcept {
  if (this != &other) {
    close();
    fd_ = std::exchange(other.fd_, -1);
    port_ = std::exchange(other.port_, 0U);
    rejected_count_ = other.rejected_count_;
  }
  return *this;
}

OAuthLoopbackListener::~OAuthLoopbackListener() { close(); }

void OAuthLoopbackListener::close() noexcept {
  if (fd_ >= 0) {
    (void)::close(fd_);
    fd_ = -1;
  }
}

std::string OAuthLoopbackListener::redirect_uri() const {
  return "http://127.0.0.1:" + std::to_string(port_) + "/auth/callback";
}

Result<OAuthCallbackResult>
OAuthLoopbackListener::wait(const OAuthCallbackWaitOptions &options) {
  if (fd_ < 0 || options.expected_state.empty() || options.timeout_ms <= 0) {
    return fail_v<OAuthCallbackResult>(ErrorCode::invalid_range,
                                       VaultError::invalid_argument);
  }

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds{options.timeout_ms};
  while (std::chrono::steady_clock::now() < deadline) {
    if (options.cancelled && options.cancelled()) {
      close();
      return fail_v<OAuthCallbackResult>(ErrorCode::interrupted, VaultError::cancelled);
    }
    const auto rem_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - std::chrono::steady_clock::now())
                            .count();
    const int poll_ms = static_cast<int>(std::clamp<std::int64_t>(rem_ms, 1, 50));
    pollfd pfd{fd_, POLLIN, 0};
    const int ready = ::poll(&pfd, 1U, poll_ms);
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      return fail_v<OAuthCallbackResult>(ErrorCode::io, VaultError::io_failed);
    }
    if (ready == 0) {
      continue;
    }

    const int raw_client = ::accept(fd_, nullptr, nullptr);
    if (raw_client < 0) {
      continue;
    }
    ScopedFd client{raw_client};
    (void)::fcntl(client.get(), F_SETFD, FD_CLOEXEC);
    (void)::fcntl(client.get(), F_SETFL, O_NONBLOCK);
#ifdef SO_NOSIGPIPE
    const int one = 1;
    (void)::setsockopt(client.get(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    std::string req_text;
    const auto read_deadline =
        std::min(deadline, std::chrono::steady_clock::now() + std::chrono::seconds{3});
    while (req_text.find("\r\n\r\n") == std::string::npos && req_text.size() < 8192U &&
           std::chrono::steady_clock::now() < read_deadline) {
      pollfd cpfd{client.get(), POLLIN, 0};
      if (::poll(&cpfd, 1U, 50) <= 0) {
        continue;
      }
      std::array<char, 1024> buf{};
      const ssize_t n = ::read(client.get(), buf.data(), buf.size());
      if (n <= 0) {
        break;
      }
      req_text.append(buf.data(), static_cast<std::size_t>(n));
    }

    bool accepted = false;
    OAuthCallbackResult cb_result{};
    constexpr std::string_view kPrefix = "GET /auth/callback?";
    const std::size_t http_end = req_text.find(" HTTP/1.");
    if (req_text.starts_with(kPrefix) && http_end != std::string::npos &&
        http_end > kPrefix.size()) {
      const auto params = parse_query_params(
          std::string_view{req_text}.substr(kPrefix.size(), http_end - kPrefix.size()));
      if (params.has_value()) {
        const auto &m = params.value();
        const auto st_it = m.find("state");
        if (st_it != m.end() &&
            constant_time_equal(st_it->second, options.expected_state)) {
          accepted = true;
          cb_result.state = st_it->second;
          if (const auto it = m.find("code"); it != m.end()) {
            cb_result.code = it->second;
          }
          if (const auto it = m.find("error"); it != m.end()) {
            cb_result.error = it->second;
          }
          if (const auto it = m.find("error_description"); it != m.end()) {
            cb_result.error_description = it->second;
          }
        }
      }
    }

    const std::string_view resp =
        accepted ? "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: "
                   "close\r\n\r\nReturn to Blackbird to finish sign-in.\n"
                 : "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
                   "Connection: close\r\n\r\nInvalid OAuth callback.\n";
#ifdef MSG_NOSIGNAL
    (void)::send(client.get(), resp.data(), resp.size(), MSG_NOSIGNAL);
#else
    (void)::send(client.get(), resp.data(), resp.size(), 0);
#endif

    if (accepted) {
      close();
      return Result<OAuthCallbackResult>::success(std::move(cb_result));
    }
    ++rejected_count_;
    if (options.fail_fast_on_bad_state) {
      close();
      return fail_v<OAuthCallbackResult>(ErrorCode::provider_auth,
                                         VaultError::oauth_callback_rejected);
    }
  }

  close();
  return fail_v<OAuthCallbackResult>(ErrorCode::provider_transport,
                                     VaultError::oauth_callback_timeout);
}

// ---------------------------------------------------------------------------
// IntegrationVault
// ---------------------------------------------------------------------------

IntegrationVault::IntegrationVault(IntegrationVaultConfig config)
    : config_(std::move(config)) {
  if (config_.directory.empty()) {
    if (const auto *env = std::getenv("BLACKBIRD_AUTH_HOME"); env != nullptr && *env) {
      config_.directory = env;
    } else if (const auto *home = std::getenv("HOME"); home != nullptr && *home) {
      config_.directory = std::filesystem::path{home} / ".local/share/blackbird/auth";
    }
  }
}

std::filesystem::path IntegrationVault::store_path() const {
  return config_.directory / "integrations.bbm";
}

Result<CredentialMetadata>
IntegrationVault::save(const CredentialSaveInput &input) const {
  if (!is_valid_identifier(input.service) || !is_valid_identifier(input.account) ||
      !is_valid_header_name(input.auth_header_name) ||
      !is_valid_secret_text(input.access_token.view(), false) ||
      !is_valid_secret_text(input.refresh_token.view(), true) ||
      !is_valid_secret_text(input.client_secret.view(), true) ||
      input.allowed_hosts.empty() ||
      input.allowed_hosts.size() > kMaxAllowedHostsPerRecord ||
      input.scopes.size() > kMaxScopesPerRecord ||
      input.extra_metadata.size() > kMaxExtraMetaPerRecord) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_range,
                                      VaultError::invalid_argument);
  }
  std::vector<std::string> normalized_hosts;
  normalized_hosts.reserve(input.allowed_hosts.size());
  for (const auto &host : input.allowed_hosts) {
    if (!is_valid_host_pin(host)) {
      return fail_v<CredentialMetadata>(ErrorCode::invalid_range,
                                        VaultError::invalid_argument);
    }
    normalized_hosts.push_back(ascii_lower(host));
  }
  if (!input.resource_uri.empty()) {
    if (const auto ok = require_https_url(input.resource_uri); !ok.has_value()) {
      return Result<CredentialMetadata>::failure(ok.error());
    }
  }
  if (!input.authorization_server.empty()) {
    if (const auto ok = require_https_url(input.authorization_server);
        !ok.has_value()) {
      return Result<CredentialMetadata>::failure(ok.error());
    }
  }
  if (!input.token_endpoint.empty()) {
    if (const auto ok = require_https_url(input.token_endpoint); !ok.has_value()) {
      return Result<CredentialMetadata>::failure(ok.error());
    }
  }

  auto store_res = LockedStore::open(config_, true);
  if (!store_res.has_value()) {
    return Result<CredentialMetadata>::failure(store_res.error());
  }
  LockedStore &store = store_res.value();

  const std::int64_t clock_now = now_seconds(config_);
  const std::string prefix = input.auth_header_prefix.empty()
                                 ? default_prefix_for_scheme(input.scheme)
                                 : input.auth_header_prefix;

  StoredRecord *existing = store.find_record_by_key({input.service, input.account});
  CredentialId assigned_id{};
  if (existing != nullptr) {
    assigned_id = existing->id;
    existing->scheme = input.scheme;
    existing->auth_header_name = input.auth_header_name;
    existing->auth_header_prefix = prefix;
    existing->access_token = input.access_token;
    existing->refresh_token = input.refresh_token;
    existing->client_secret = input.client_secret;
    existing->allowed_hosts = std::move(normalized_hosts);
    existing->scopes = input.scopes;
    existing->resource_uri = input.resource_uri;
    existing->authorization_server = input.authorization_server;
    existing->token_endpoint = input.token_endpoint;
    existing->client_id = input.client_id;
    existing->expires_at = input.expires_at;
    existing->updated_at = clock_now;
    ++existing->revision;
    existing->extra_metadata = input.extra_metadata;
  } else {
    if (store.state().records.size() >= kMaxRecords) {
      return fail_v<CredentialMetadata>(ErrorCode::capacity,
                                        VaultError::capacity_exceeded);
    }
    assigned_id = CredentialId{store.state().next_id++};
    StoredRecord rec{};
    rec.id = assigned_id;
    rec.service = input.service;
    rec.account = input.account;
    rec.scheme = input.scheme;
    rec.auth_header_name = input.auth_header_name;
    rec.auth_header_prefix = prefix;
    rec.access_token = input.access_token;
    rec.refresh_token = input.refresh_token;
    rec.client_secret = input.client_secret;
    rec.allowed_hosts = std::move(normalized_hosts);
    rec.scopes = input.scopes;
    rec.resource_uri = input.resource_uri;
    rec.authorization_server = input.authorization_server;
    rec.token_endpoint = input.token_endpoint;
    rec.client_id = input.client_id;
    rec.expires_at = input.expires_at;
    rec.updated_at = clock_now;
    rec.revision = 1U;
    rec.extra_metadata = input.extra_metadata;
    store.state().records.emplace(assigned_id.value, std::move(rec));
  }

  if (input.set_active || !store.state().active_by_service.contains(input.service)) {
    store.state().active_by_service[input.service] = assigned_id.value;
  }

  if (const auto saved = store.commit(); !saved.has_value()) {
    return Result<CredentialMetadata>::failure(saved.error());
  }
  const auto &rec = store.state().records.at(assigned_id.value);
  return Result<CredentialMetadata>::success(
      to_public_metadata(rec, store.is_active(rec), clock_now));
}

Result<std::vector<CredentialMetadata>> IntegrationVault::list() const {
  auto store_res = LockedStore::open(config_, false);
  if (!store_res.has_value()) {
    return Result<std::vector<CredentialMetadata>>::failure(store_res.error());
  }
  const LockedStore &store = store_res.value();
  const std::int64_t clock_now = now_seconds(config_);

  std::vector<CredentialMetadata> out;
  out.reserve(store.state().records.size());
  for (const auto &[id_val, rec] : store.state().records) {
    (void)id_val;
    out.push_back(to_public_metadata(rec, store.is_active(rec), clock_now));
  }
  return Result<std::vector<CredentialMetadata>>::success(std::move(out));
}

Result<CredentialMetadata> IntegrationVault::find_by_id(CredentialId id) const {
  if (!id.valid()) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_range,
                                      VaultError::invalid_argument);
  }
  auto store_res = LockedStore::open(config_, false);
  if (!store_res.has_value()) {
    return Result<CredentialMetadata>::failure(store_res.error());
  }
  const LockedStore &store = store_res.value();
  const auto it = store.state().records.find(id.value);
  if (it == store.state().records.end()) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_identity,
                                      VaultError::not_found);
  }
  return Result<CredentialMetadata>::success(to_public_metadata(
      it->second, store.is_active(it->second), now_seconds(config_)));
}

Result<CredentialMetadata> IntegrationVault::find(const ServiceAccountKey &key) const {
  auto store_res = LockedStore::open(config_, false);
  if (!store_res.has_value()) {
    return Result<CredentialMetadata>::failure(store_res.error());
  }
  LockedStore &store = store_res.value();
  const StoredRecord *rec = store.find_record_by_key(key);
  if (rec == nullptr) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_identity,
                                      VaultError::not_found);
  }
  return Result<CredentialMetadata>::success(
      to_public_metadata(*rec, store.is_active(*rec), now_seconds(config_)));
}

Result<void> IntegrationVault::set_active(CredentialId id) const {
  if (!id.valid()) {
    return fail_vv(ErrorCode::invalid_range, VaultError::invalid_argument);
  }
  auto store_res = LockedStore::open(config_, true);
  if (!store_res.has_value()) {
    return Result<void>::failure(store_res.error());
  }
  LockedStore &store = store_res.value();
  const auto it = store.state().records.find(id.value);
  if (it == store.state().records.end()) {
    return fail_vv(ErrorCode::invalid_identity, VaultError::not_found);
  }
  store.state().active_by_service[it->second.service] = id.value;
  return store.commit();
}

Result<void> IntegrationVault::remove(CredentialId id) const {
  if (!id.valid()) {
    return fail_vv(ErrorCode::invalid_range, VaultError::invalid_argument);
  }
  auto store_res = LockedStore::open(config_, true);
  if (!store_res.has_value()) {
    return Result<void>::failure(store_res.error());
  }
  LockedStore &store = store_res.value();
  const auto it = store.state().records.find(id.value);
  if (it == store.state().records.end()) {
    return fail_vv(ErrorCode::invalid_identity, VaultError::not_found);
  }
  const std::string service = it->second.service;
  store.state().records.erase(it);

  const auto act_it = store.state().active_by_service.find(service);
  if (act_it != store.state().active_by_service.end() && act_it->second == id.value) {
    store.state().active_by_service.erase(act_it);
    for (const auto &[other_id, rec] : store.state().records) {
      if (rec.service == service) {
        store.state().active_by_service[service] = other_id;
        break;
      }
    }
  }
  return store.commit();
}

Result<CredentialMetadata>
IntegrationVault::authorize_request(const ServiceAccountKey &key,
                                    net::HttpRequest &request,
                                    const AuthorizeRequestOptions &options) const {
  auto store_res = LockedStore::open(config_, false);
  if (!store_res.has_value()) {
    return Result<CredentialMetadata>::failure(store_res.error());
  }
  LockedStore &store = store_res.value();
  StoredRecord *rec = store.find_record_by_key(key);
  if (rec == nullptr) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_identity,
                                      VaultError::not_found);
  }
  return authorize_record_locked(store, *rec, config_, request, options);
}

Result<CredentialMetadata>
IntegrationVault::authorize_request(CredentialId id, net::HttpRequest &request,
                                    const AuthorizeRequestOptions &options) const {
  if (!id.valid()) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_range,
                                      VaultError::invalid_argument);
  }
  auto store_res = LockedStore::open(config_, false);
  if (!store_res.has_value()) {
    return Result<CredentialMetadata>::failure(store_res.error());
  }
  LockedStore &store = store_res.value();
  const auto it = store.state().records.find(id.value);
  if (it == store.state().records.end()) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_identity,
                                      VaultError::not_found);
  }
  return authorize_record_locked(store, it->second, config_, request, options);
}

Result<CredentialMetadata>
IntegrationVault::refresh_credential(CredentialId id, const net::HttpClient &http,
                                     bool force) const {
  if (!id.valid()) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_range,
                                      VaultError::invalid_argument);
  }
  auto store_res = LockedStore::open(config_, true);
  if (!store_res.has_value()) {
    return Result<CredentialMetadata>::failure(store_res.error());
  }
  LockedStore &store = store_res.value();
  const auto it = store.state().records.find(id.value);
  if (it == store.state().records.end()) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_identity,
                                      VaultError::not_found);
  }
  return refresh_record_locked(store, it->second, config_, http, force);
}

Result<CredentialMetadata>
IntegrationVault::refresh_credential(const ServiceAccountKey &key,
                                     const net::HttpClient &http, bool force) const {
  auto store_res = LockedStore::open(config_, true);
  if (!store_res.has_value()) {
    return Result<CredentialMetadata>::failure(store_res.error());
  }
  LockedStore &store = store_res.value();
  StoredRecord *rec = store.find_record_by_key(key);
  if (rec == nullptr) {
    return fail_v<CredentialMetadata>(ErrorCode::invalid_identity,
                                      VaultError::not_found);
  }
  return refresh_record_locked(store, *rec, config_, http, force);
}

} // namespace blackbird
