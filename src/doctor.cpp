#include "blackbird/doctor.hpp"

#include "blackbird/brakes_policy.hpp"
#include "blackbird/mp_protocol.hpp"
#include "blackbird/os_sandbox.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/self_upgrade.hpp"

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
#include <filesystem>
#include <limits>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <optional>
#include <poll.h>
#include <set>
#include <signal.h>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace blackbird {
namespace {

using SteadyClock = std::chrono::steady_clock;
using SystemClock = std::chrono::system_clock;

constexpr std::int64_t kCwtExpiringSoonSeconds = 3LL * 24LL * 60LL * 60LL;
constexpr std::int64_t kMaxAcceptableClockSkewMs = 30000LL;
constexpr std::size_t kMaxProviderAuthStoreBytes = 1024U * 1024U;
constexpr std::size_t kMaxRelayHeaderBytes = 16U * 1024U;
constexpr int kPartyLobbyProbeTimeoutMs = 1500;
constexpr std::array<unsigned char, 9> kAlpnHttp11 = {8U,  'h', 't', 't', 'p',
                                                      '/', '1', '.', '1'};

// ---------------------------------------------------------------------------
// RAII & security hygiene helpers
// ---------------------------------------------------------------------------

struct ScopedFd {
  int fd = -1;
  ScopedFd() noexcept = default;
  explicit ScopedFd(int raw) noexcept : fd(raw) {}
  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;
  ScopedFd(ScopedFd &&other) noexcept : fd(std::exchange(other.fd, -1)) {}
  ScopedFd &operator=(ScopedFd &&other) noexcept {
    if (this != &other) {
      reset();
      fd = std::exchange(other.fd, -1);
    }
    return *this;
  }
  ~ScopedFd() { reset(); }

  int get() const noexcept { return fd; }
  bool valid() const noexcept { return fd >= 0; }
  void reset() noexcept {
    if (fd >= 0) {
      (void)::close(fd);
      fd = -1;
    }
  }
};

struct AddrInfoDeleter {
  void operator()(addrinfo *p) const noexcept {
    if (p != nullptr) {
      ::freeaddrinfo(p);
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

struct CleanseStringGuard {
  std::string &buf;
  ~CleanseStringGuard() noexcept {
    if (!buf.empty()) {
      OPENSSL_cleanse(buf.data(), buf.size());
      buf.clear();
    }
  }
};

class ScopedSigpipeGuard {
public:
  ScopedSigpipeGuard() noexcept {
    sigset_t mask{};
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    sigset_t pending{};
    sigemptyset(&pending);
    if (::sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1) {
      was_pending_ = true;
    }
    if (::pthread_sigmask(SIG_BLOCK, &mask, &old_mask_) == 0) {
      masked_ = true;
    }
  }
  ScopedSigpipeGuard(const ScopedSigpipeGuard &) = delete;
  ScopedSigpipeGuard &operator=(const ScopedSigpipeGuard &) = delete;
  ~ScopedSigpipeGuard() {
    if (!masked_) {
      return;
    }
    if (!was_pending_) {
      sigset_t pending{};
      sigemptyset(&pending);
      if (::sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1) {
        sigset_t pipe_set{};
        sigemptyset(&pipe_set);
        sigaddset(&pipe_set, SIGPIPE);
        int sig = 0;
        (void)::sigwait(&pipe_set, &sig);
      }
    }
    (void)::pthread_sigmask(SIG_SETMASK, &old_mask_, nullptr);
  }

private:
  sigset_t old_mask_{};
  bool masked_ = false;
  bool was_pending_ = false;
};

// ---------------------------------------------------------------------------
// Terminal text sanitization (strips ANSI CSI/OSC, C0/C1/DEL, and BiDi controls)
// ---------------------------------------------------------------------------

bool is_bidi_utf8_at(std::string_view s, std::size_t pos,
                     std::size_t &seq_len) noexcept {
  if (pos + 2U <= s.size()) {
    const auto b0 = static_cast<unsigned char>(s[pos]);
    const auto b1 = static_cast<unsigned char>(s[pos + 1U]);
    // U+061C (Arabic Letter Mark): D8 9C
    if (b0 == 0xD8U && b1 == 0x9CU) {
      seq_len = 2U;
      return true;
    }
    // C1 control characters U+0080..U+009F: C2 80..9F
    if (b0 == 0xC2U && b1 >= 0x80U && b1 <= 0x9FU) {
      seq_len = 2U;
      return true;
    }
  }
  if (pos + 3U <= s.size()) {
    const auto b0 = static_cast<unsigned char>(s[pos]);
    const auto b1 = static_cast<unsigned char>(s[pos + 1U]);
    const auto b2 = static_cast<unsigned char>(s[pos + 2U]);
    // U+200E..U+200F (LRM/RLM): E2 80 8E..8F
    // U+202A..U+202E (LRE/RLE/PDF/LRO/RLO): E2 80 AA..AE
    // U+2066..U+2069 (LRI/RLI/FSI/PDI): E2 81 A6..A9
    if (b0 == 0xE2U && b1 == 0x80U &&
        ((b2 >= 0x8EU && b2 <= 0x8FU) || (b2 >= 0xAAU && b2 <= 0xAEU))) {
      seq_len = 3U;
      return true;
    }
    if (b0 == 0xE2U && b1 == 0x81U && b2 >= 0xA6U && b2 <= 0xA9U) {
      seq_len = 3U;
      return true;
    }
  }
  seq_len = 0U;
  return false;
}

std::string sanitize_terminal_text(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (std::size_t i = 0U; i < text.size(); ++i) {
    const auto byte = static_cast<unsigned char>(text[i]);
    if (byte == 0x1BU) {
      if (i + 1U < text.size() && text[i + 1U] == '[') {
        i += 2U;
        while (i < text.size()) {
          const auto c = static_cast<unsigned char>(text[i]);
          if (c >= 0x40U && c <= 0x7EU) {
            break;
          }
          ++i;
        }
      } else if (i + 1U < text.size() && text[i + 1U] == ']') {
        i += 2U;
        while (i < text.size()) {
          const auto c = static_cast<unsigned char>(text[i]);
          if (c == 0x07U) {
            break;
          }
          if (c == 0x1BU && i + 1U < text.size() && text[i + 1U] == '\\') {
            ++i;
            break;
          }
          ++i;
        }
      }
      continue;
    }
    std::size_t bidi_len = 0U;
    if (is_bidi_utf8_at(text, i, bidi_len)) {
      i += bidi_len - 1U;
      continue;
    }
    if (byte < 0x20U || byte == 0x7FU) {
      if (byte == '\t') {
        out.push_back(' ');
      }
      continue;
    }
    out.push_back(text[i]);
  }
  return out;
}

bool has_forbidden_path_chars(std::string_view text) noexcept {
  for (std::size_t i = 0U; i < text.size(); ++i) {
    const auto byte = static_cast<unsigned char>(text[i]);
    if (byte < 0x20U || byte == 0x7FU) {
      return true;
    }
    std::size_t bidi_len = 0U;
    if (is_bidi_utf8_at(text, i, bidi_len)) {
      return true;
    }
  }
  return false;
}

bool valid_env_path(std::string_view raw) noexcept {
  if (raw.empty() || raw.size() > 4096U || has_forbidden_path_chars(raw)) {
    return false;
  }
  std::size_t pos = 0U;
  while (pos <= raw.size()) {
    const std::size_t slash = raw.find('/', pos);
    const std::string_view seg = (slash == std::string_view::npos)
                                     ? raw.substr(pos)
                                     : raw.substr(pos, slash - pos);
    if (seg == "..") {
      return false;
    }
    if (slash == std::string_view::npos) {
      break;
    }
    pos = slash + 1U;
  }
  return true;
}

std::string format_duration_seconds(std::int64_t seconds) {
  if (seconds <= 0) {
    return "0s";
  }
  const std::int64_t days = seconds / 86400LL;
  const std::int64_t hours = (seconds % 86400LL) / 3600LL;
  const std::int64_t mins = (seconds % 3600LL) / 60LL;
  if (days > 0) {
    return std::to_string(days) + "d " + std::to_string(hours) + "h";
  }
  if (hours > 0) {
    return std::to_string(hours) + "h " + std::to_string(mins) + "m";
  }
  if (mins > 0) {
    return std::to_string(mins) + "m " + std::to_string(seconds % 60LL) + "s";
  }
  return std::to_string(seconds) + "s";
}

std::string format_signed_ms(std::int64_t ms) {
  if (ms >= 0) {
    return "+" + std::to_string(ms) + "ms";
  }
  return std::to_string(ms) + "ms";
}

std::string format_mp_error(const Error &err) {
  const auto client_err = mp::mp_client_error_of(err);
  const char *client_name = mp::mp_client_error_name(client_err);
  if (client_name != nullptr && std::string_view{client_name} != "unknown" &&
      std::string_view{client_name} != "none") {
    return std::string{client_name};
  }
  const auto proto_err = mp::mp_error_of(err);
  const char *proto_name = mp::mp_error_name(proto_err);
  if (proto_name != nullptr && std::string_view{proto_name} != "unknown" &&
      std::string_view{proto_name} != "none") {
    return std::string{proto_name};
  }
  return std::string{error_name(err.code)};
}

std::int64_t now_epoch_seconds() noexcept {
  return std::chrono::duration_cast<std::chrono::seconds>(
             SystemClock::now().time_since_epoch())
      .count();
}

std::int64_t now_epoch_ms() noexcept {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             SystemClock::now().time_since_epoch())
      .count();
}

// ---------------------------------------------------------------------------
// Read-only path resolution (never creates directories or files)
// ---------------------------------------------------------------------------

std::optional<std::filesystem::path> resolve_install_prefix(const DoctorConfig &cfg) {
  if (!cfg.install_prefix.empty()) {
    return cfg.install_prefix;
  }
  const char *home = std::getenv("HOME");
  if (home != nullptr && home[0] != '\0' && valid_env_path(home)) {
    return std::filesystem::path{home} / ".local";
  }
  return std::nullopt;
}

std::optional<std::filesystem::path> resolve_online_state_dir(const DoctorConfig &cfg) {
  if (!cfg.online_state_dir.empty()) {
    return cfg.online_state_dir;
  }
  if (const char *env_dir = std::getenv("BLACKBIRD_ONLINE_DIR");
      env_dir != nullptr && env_dir[0] != '\0') {
    if (!valid_env_path(env_dir)) {
      return std::nullopt;
    }
    return std::filesystem::path{env_dir};
  }
  if (const char *xdg = std::getenv("XDG_CONFIG_HOME");
      xdg != nullptr && xdg[0] != '\0') {
    if (!valid_env_path(xdg)) {
      return std::nullopt;
    }
    return std::filesystem::path{xdg} / "blackbird" / "online";
  }
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
    if (!valid_env_path(home)) {
      return std::nullopt;
    }
    return std::filesystem::path{home} / ".config" / "blackbird" / "online";
  }
  return std::nullopt;
}

std::optional<std::filesystem::path>
resolve_provider_auth_home(const DoctorConfig &cfg) {
  if (cfg.provider_auth_home.has_value()) {
    if (cfg.provider_auth_home->empty()) {
      return std::nullopt;
    }
    return *cfg.provider_auth_home;
  }
  if (const char *env_auth = std::getenv("BLACKBIRD_AUTH_HOME");
      env_auth != nullptr && env_auth[0] != '\0') {
    if (!valid_env_path(env_auth)) {
      return std::nullopt;
    }
    return std::filesystem::path{env_auth};
  }
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
    if (!valid_env_path(home)) {
      return std::nullopt;
    }
    return std::filesystem::path{home} / ".local" / "share" / "blackbird" / "auth";
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Check 1: Binary & platform target
// ---------------------------------------------------------------------------

struct BinaryCheckOutcome {
  DoctorCheck check;
  std::string target;
  std::string version;
};

BinaryCheckOutcome check_binary(const DoctorConfig &cfg) {
  BinaryCheckOutcome out{};
  out.check.id = "binary";
  out.check.label = "Binary";

  std::string raw_version = cfg.current_version_string;
  if (raw_version.empty()) {
#ifdef BLACKBIRD_VERSION_STRING
    raw_version = BLACKBIRD_VERSION_STRING;
#else
    raw_version = "unknown";
#endif
  }
  out.version = sanitize_terminal_text(raw_version);
  if (out.version.empty()) {
    out.version = "unknown";
  }

  const auto target_res = detect_upgrade_target();
  if (target_res.has_value()) {
    out.target = sanitize_terminal_text(target_res.value().triplet);
    out.check.status = DoctorStatus::ok;
    out.check.summary = out.version + " [" + out.target + "]";
  } else {
    out.target = "unsupported";
    out.check.status = DoctorStatus::warn;
    out.check.summary = out.version + " [unsupported platform]";
    out.check.hint = "Supported targets are darwin-arm64 and linux-x86_64";
  }
  return out;
}

// ---------------------------------------------------------------------------
// Check 2: Upgrade status (read-only metadata check via check_for_upgrade)
// ---------------------------------------------------------------------------

DoctorCheck check_upgrade(const DoctorConfig &cfg) {
  DoctorCheck chk{};
  chk.id = "upgrade";
  chk.label = "Upgrade";

  if (cfg.offline) {
    chk.status = DoctorStatus::info;
    chk.summary = "skipped (--offline)";
    return chk;
  }
  if (!cfg.check_update) {
    chk.status = DoctorStatus::info;
    chk.summary = "skipped (--no-check-update)";
    return chk;
  }

  UpgradeConfig ucfg{};
  ucfg.version = "latest";
  ucfg.base_url = cfg.upgrade_base_url;
  if (const auto prefix = resolve_install_prefix(cfg); prefix.has_value()) {
    ucfg.prefix = *prefix;
  }
  ucfg.check_only = true;
  ucfg.current_version_string = cfg.current_version_string;

  const auto res = check_for_upgrade(ucfg);
  if (!res.has_value()) {
    chk.status = DoctorStatus::warn;
    chk.summary = "unable to check latest release (" +
                  std::string{error_name(res.error().code)} + ")";
    chk.hint = "Check internet connectivity or run: blackbird upgrade --check";
    return chk;
  }

  const UpgradeCheckResult &info = res.value();
  const std::string latest = sanitize_terminal_text(info.latest_version);
  if (!info.update_available) {
    chk.status = DoctorStatus::ok;
    chk.summary = "up to date (" + latest + ")";
    return chk;
  }

  std::string current = sanitize_terminal_text(info.current_version);
  if (current.empty()) {
    current = sanitize_terminal_text(info.current_commit);
  }
  if (current.empty()) {
    current = "current";
  }

  chk.status = DoctorStatus::info;
  chk.summary = "update available (" + current + " -> " + latest + ")";
  chk.hint = "Run: blackbird upgrade";
  return chk;
}

// ---------------------------------------------------------------------------
// Check 3: Provider auth (strictly passive, zero file/lock creation, zero secret leak)
// ---------------------------------------------------------------------------

struct BuiltinProviderEnv {
  std::string_view provider;
  std::string_view env_var;
};

constexpr std::array<BuiltinProviderEnv, 11> kBuiltinProviders = {{
    {"openai", "OPENAI_API_KEY"},
    {"anthropic", "ANTHROPIC_API_KEY"},
    {"openrouter", "OPENROUTER_API_KEY"},
    {"gemini", "GEMINI_API_KEY"},
    {"grok", "XAI_API_KEY"},
    {"moonshot", "MOONSHOT_API_KEY"},
    {"deepseek", "DEEPSEEK_API_KEY"},
    {"kimi", "KIMI_API_KEY"},
    {"mimo", "MIMO_API_KEY"},
    {"jev", "TYPESAFE_API_KEY"},
    {"clef", "CLEF_API_KEY"},
}};

struct PassiveProviderStoreRead {
  bool present = false;
  bool error = false;
  std::string error_reason;
  std::vector<std::string> ready_providers;
  std::vector<std::string> inactive_selected_providers;
  std::vector<std::pair<std::string, std::string>> custom_env_vars;
};

std::optional<std::string> value_str_field(const Value &obj, std::string_view key) {
  const Value *p = obj.find(key);
  if (p == nullptr) {
    return std::nullopt;
  }
  const auto *s = std::get_if<std::string>(&p->value());
  if (s == nullptr) {
    return std::nullopt;
  }
  return *s;
}

std::optional<std::int64_t> value_i64_field(const Value &obj, std::string_view key) {
  const Value *p = obj.find(key);
  if (p == nullptr) {
    return std::nullopt;
  }
  const auto *num = std::get_if<Number>(&p->value());
  if (num == nullptr) {
    return std::nullopt;
  }
  if (const auto *i = std::get_if<std::int64_t>(&num->storage())) {
    return *i;
  }
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage())) {
    if (*u <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return static_cast<std::int64_t>(*u);
    }
  }
  return std::nullopt;
}

// Reads credentials.bbm strictly O_RDONLY without creating directories or lock files.
// Never extracts or copies any secret token values; cleanses raw buffer on exit.
PassiveProviderStoreRead
read_provider_auth_store_passive(const std::filesystem::path &auth_dir) {
  PassiveProviderStoreRead out{};
  if (auth_dir.empty()) {
    return out;
  }

  ScopedFd dir_fd{
      ::open(auth_dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
  if (!dir_fd.valid()) {
    if (errno == ENOENT) {
      return out;
    }
    out.error = true;
    out.error_reason = (errno == ELOOP || errno == ENOTDIR) ? "symlink/invalid dir"
                                                            : "unreadable auth dir";
    return out;
  }

  struct stat dst{};
  if (::fstat(dir_fd.get(), &dst) != 0 || !S_ISDIR(dst.st_mode)) {
    out.error = true;
    out.error_reason = "invalid auth dir";
    return out;
  }
  if (dst.st_uid != ::geteuid() || (dst.st_mode & 0077U) != 0U) {
    out.error = true;
    out.error_reason = "insecure auth dir permissions";
    return out;
  }

  ScopedFd file_fd{
      ::openat(dir_fd.get(), "credentials.bbm", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
  if (!file_fd.valid()) {
    if (errno == ENOENT) {
      return out;
    }
    out.error = true;
    out.error_reason =
        (errno == ELOOP) ? "symlink credentials file" : "unreadable credentials file";
    return out;
  }

  struct stat fst{};
  if (::fstat(file_fd.get(), &fst) != 0 || !S_ISREG(fst.st_mode) ||
      fst.st_nlink != 1U) {
    out.error = true;
    out.error_reason = "invalid credentials file";
    return out;
  }
  if (fst.st_uid != ::geteuid() || (fst.st_mode & 0077U) != 0U) {
    out.error = true;
    out.error_reason = "insecure credentials permissions";
    return out;
  }

  std::string raw_bytes;
  CleanseStringGuard raw_guard{raw_bytes};
  std::array<char, 4096> chunk{};
  for (;;) {
    const ssize_t n = ::read(file_fd.get(), chunk.data(), chunk.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      OPENSSL_cleanse(chunk.data(), chunk.size());
      out.error = true;
      out.error_reason = "io error reading credentials";
      return out;
    }
    if (n == 0) {
      break;
    }
    const auto got = static_cast<std::size_t>(n);
    if (raw_bytes.size() + got > kMaxProviderAuthStoreBytes) {
      OPENSSL_cleanse(chunk.data(), chunk.size());
      out.error = true;
      out.error_reason = "credentials file too large";
      return out;
    }
    raw_bytes.append(chunk.data(), got);
  }
  OPENSSL_cleanse(chunk.data(), chunk.size());

  const auto decoded = decode_packet_string(
      raw_bytes, ValueLimits{kMaxProviderAuthStoreBytes, 32768U, 32U});
  if (!decoded.has_value() ||
      !std::holds_alternative<Value::Object>(decoded.value().value())) {
    out.error = true;
    out.error_reason = "corrupt credentials store";
    return out;
  }

  const Value &root = decoded.value();
  const auto ver = value_i64_field(root, "version");
  const Value *active_val = root.find("active");
  const Value *accounts_val = root.find("accounts");
  const Value *providers_val = root.find("providers");
  if (!ver.has_value() || *ver != 1 || active_val == nullptr ||
      accounts_val == nullptr || providers_val == nullptr ||
      !std::holds_alternative<Value::Object>(active_val->value()) ||
      !std::holds_alternative<Value::Array>(accounts_val->value()) ||
      !std::holds_alternative<Value::Object>(providers_val->value())) {
    out.error = true;
    out.error_reason = "unsupported credentials schema";
    return out;
  }

  out.present = true;

  for (const auto &[prov_id, desc] : providers_val->object()) {
    if (!std::holds_alternative<Value::Object>(desc.value())) {
      continue;
    }
    const std::string env_name = value_str_field(desc, "environment").value_or("");
    if (!prov_id.empty() && !env_name.empty()) {
      out.custom_env_vars.emplace_back(sanitize_terminal_text(prov_id), env_name);
    }
  }

  const std::int64_t now_s = now_epoch_seconds();
  for (const auto &[prov_id, sel_val] : active_val->object()) {
    const auto *sel_acct = std::get_if<std::string>(&sel_val.value());
    if (sel_acct == nullptr || sel_acct->empty()) {
      continue;
    }
    bool found_ready = false;
    for (const auto &acct : accounts_val->array()) {
      if (!std::holds_alternative<Value::Object>(acct.value())) {
        continue;
      }
      if (value_str_field(acct, "provider").value_or("") != prov_id ||
          value_str_field(acct, "account").value_or("") != *sel_acct) {
        continue;
      }
      const std::string state = value_str_field(acct, "state").value_or("ready");
      const std::string kind = value_str_field(acct, "kind").value_or("");
      if (state == "ready") {
        if (kind == "oauth") {
          const auto exp = value_i64_field(acct, "expires_at");
          if (exp.has_value() && *exp <= now_s) {
            break;
          }
        }
        found_ready = true;
      }
      break;
    }
    const std::string clean_prov = sanitize_terminal_text(prov_id);
    if (!clean_prov.empty()) {
      if (found_ready) {
        out.ready_providers.push_back(clean_prov);
      } else {
        out.inactive_selected_providers.push_back(clean_prov);
      }
    }
  }

  return out;
}

bool env_var_is_non_empty(const char *name) noexcept {
  if (name == nullptr || name[0] == '\0') {
    return false;
  }
  const char *val = std::getenv(name);
  return val != nullptr && val[0] != '\0';
}

DoctorCheck check_provider_auth(const DoctorConfig &cfg) {
  DoctorCheck chk{};
  chk.id = "provider_auth";
  chk.label = "Provider Auth";

  PassiveProviderStoreRead store_read{};
  if (const auto auth_dir = resolve_provider_auth_home(cfg); auth_dir.has_value()) {
    store_read = read_provider_auth_store_passive(*auth_dir);
  }

  std::set<std::string> stored_ready(store_read.ready_providers.begin(),
                                     store_read.ready_providers.end());
  std::set<std::string> stored_blocked(store_read.inactive_selected_providers.begin(),
                                       store_read.inactive_selected_providers.end());

  std::vector<std::string> configured;
  std::set<std::string> seen;

  for (const auto &prov : stored_ready) {
    if (seen.insert(prov).second) {
      configured.push_back(prov + " (stored)");
    }
  }

  for (const auto &entry : kBuiltinProviders) {
    const std::string name{entry.provider};
    if (seen.contains(name) || stored_blocked.contains(name)) {
      continue;
    }
    if (env_var_is_non_empty(entry.env_var.data())) {
      if (seen.insert(name).second) {
        configured.push_back(name + " (env)");
      }
    }
  }

  for (const auto &[prov, env_name] : store_read.custom_env_vars) {
    if (seen.contains(prov) || stored_blocked.contains(prov)) {
      continue;
    }
    if (env_var_is_non_empty(env_name.c_str())) {
      if (seen.insert(prov).second) {
        configured.push_back(prov + " (env)");
      }
    }
  }

  if (!configured.empty()) {
    std::string list;
    for (std::size_t i = 0U; i < configured.size(); ++i) {
      if (i > 0U) {
        list += ", ";
      }
      list += configured[i];
    }
    if (store_read.error) {
      chk.status = DoctorStatus::warn;
      chk.summary = "configured: " + list +
                    " (auth store warning: " + store_read.error_reason + ")";
      chk.hint = "Inspect provider auth store or run: blackbird auth status";
    } else {
      chk.status = DoctorStatus::ok;
      chk.summary = "configured: " + list;
    }
    return chk;
  }

  chk.status = DoctorStatus::warn;
  if (store_read.error) {
    chk.summary = "none configured (" + store_read.error_reason + ")";
  } else {
    chk.summary = "no provider credentials configured";
  }
  chk.hint = "Run: blackbird auth login";
  return chk;
}

// ---------------------------------------------------------------------------
// Check 4: Online identity (passive read-only MpIdentityStore + CWT + safety number)
// ---------------------------------------------------------------------------

// Minimal strict CBOR reader for passive CWT expiry/cnf inspection when the
// root key is offline on a linked secondary device (no signature verification
// possible without the root pubkey, but envelope, claims, cnf pubkey, and exp
// are strictly validated).
struct PassiveCwtClaims {
  std::int64_t iat = 0;
  std::int64_t exp = 0;
  mp::Ed25519PubKey device_pubkey{};
};

class MiniCborReader {
public:
  explicit MiniCborReader(std::span<const std::uint8_t> data) noexcept : data_(data) {}

  bool at_end() const noexcept { return pos_ == data_.size(); }

  struct Head {
    std::uint8_t major = 0U;
    std::uint64_t arg = 0U;
  };

  std::optional<Head> read_head() noexcept {
    if (pos_ >= data_.size()) {
      return std::nullopt;
    }
    const std::uint8_t first = data_[pos_++];
    const auto major = static_cast<std::uint8_t>(first >> 5U);
    const auto add = static_cast<std::uint8_t>(first & 0x1fU);
    if (add < 24U) {
      return Head{major, add};
    }
    if (add == 24U) {
      if (data_.size() - pos_ < 1U) {
        return std::nullopt;
      }
      const std::uint64_t v = data_[pos_++];
      if (v < 24U) {
        return std::nullopt;
      }
      return Head{major, v};
    }
    if (add == 25U) {
      if (data_.size() - pos_ < 2U) {
        return std::nullopt;
      }
      const std::uint64_t v =
          (static_cast<std::uint64_t>(data_[pos_]) << 8U) | data_[pos_ + 1U];
      pos_ += 2U;
      if (v <= 0xffU) {
        return std::nullopt;
      }
      return Head{major, v};
    }
    if (add == 26U) {
      if (data_.size() - pos_ < 4U) {
        return std::nullopt;
      }
      std::uint64_t v = 0U;
      for (std::size_t i = 0U; i < 4U; ++i) {
        v = (v << 8U) | data_[pos_ + i];
      }
      pos_ += 4U;
      if (v <= 0xffffU) {
        return std::nullopt;
      }
      return Head{major, v};
    }
    if (add == 27U) {
      if (data_.size() - pos_ < 8U) {
        return std::nullopt;
      }
      std::uint64_t v = 0U;
      for (std::size_t i = 0U; i < 8U; ++i) {
        v = (v << 8U) | data_[pos_ + i];
      }
      pos_ += 8U;
      if (v <= 0xffffffffULL) {
        return std::nullopt;
      }
      return Head{major, v};
    }
    return std::nullopt;
  }

  std::optional<std::int64_t> read_i64() noexcept {
    const auto h = read_head();
    if (!h.has_value()) {
      return std::nullopt;
    }
    if (h->major == 0U) {
      if (h->arg >
          static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return std::nullopt;
      }
      return static_cast<std::int64_t>(h->arg);
    }
    if (h->major == 1U) {
      if (h->arg >
          static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return std::nullopt;
      }
      return -1LL - static_cast<std::int64_t>(h->arg);
    }
    return std::nullopt;
  }

  std::optional<std::span<const std::uint8_t>> read_bstr() noexcept {
    const auto h = read_head();
    if (!h.has_value() || h->major != 2U || h->arg > data_.size() - pos_) {
      return std::nullopt;
    }
    const auto slice = data_.subspan(pos_, static_cast<std::size_t>(h->arg));
    pos_ += static_cast<std::size_t>(h->arg);
    return slice;
  }

  std::optional<std::string_view> read_tstr() noexcept {
    const auto h = read_head();
    if (!h.has_value() || h->major != 3U || h->arg > data_.size() - pos_) {
      return std::nullopt;
    }
    const auto slice = data_.subspan(pos_, static_cast<std::size_t>(h->arg));
    pos_ += static_cast<std::size_t>(h->arg);
    return std::string_view{reinterpret_cast<const char *>(slice.data()), slice.size()};
  }

private:
  std::span<const std::uint8_t> data_;
  std::size_t pos_ = 0U;
};

std::optional<PassiveCwtClaims>
parse_cwt_claims_offline(std::span<const std::uint8_t> cwt_bytes) noexcept {
  static constexpr std::array<std::uint8_t, 7> kPrefix = {0xd2U, 0x84U, 0x43U, 0xa1U,
                                                          0x01U, 0x32U, 0xa0U};
  if (cwt_bytes.size() <= kPrefix.size() || cwt_bytes.size() > mp::kMaxCwtBytes) {
    return std::nullopt;
  }
  if (std::memcmp(cwt_bytes.data(), kPrefix.data(), kPrefix.size()) != 0) {
    return std::nullopt;
  }
  MiniCborReader outer{cwt_bytes.subspan(kPrefix.size())};
  const auto payload = outer.read_bstr();
  const auto sig = outer.read_bstr();
  if (!payload.has_value() || !sig.has_value() || !outer.at_end() ||
      sig->size() != 64U) {
    return std::nullopt;
  }

  MiniCborReader r{*payload};
  const auto map_head = r.read_head();
  if (!map_head.has_value() || map_head->major != 5U || map_head->arg > 16U) {
    return std::nullopt;
  }

  bool seen_iss = false;
  std::optional<std::int64_t> exp;
  std::optional<std::int64_t> iat;
  std::optional<mp::Ed25519PubKey> dev_pk;

  for (std::uint64_t i = 0U; i < map_head->arg; ++i) {
    const auto k = r.read_i64();
    if (!k.has_value()) {
      return std::nullopt;
    }
    if (*k == 1LL) {
      if (seen_iss) {
        return std::nullopt;
      }
      const auto iss = r.read_tstr();
      if (!iss.has_value() || iss->size() != 64U) {
        return std::nullopt;
      }
      seen_iss = true;
    } else if (*k == 4LL) {
      if (exp.has_value()) {
        return std::nullopt;
      }
      exp = r.read_i64();
      if (!exp.has_value()) {
        return std::nullopt;
      }
    } else if (*k == 6LL) {
      if (iat.has_value()) {
        return std::nullopt;
      }
      iat = r.read_i64();
      if (!iat.has_value()) {
        return std::nullopt;
      }
    } else if (*k == 8LL) {
      if (dev_pk.has_value()) {
        return std::nullopt;
      }
      const auto cnf_head = r.read_head();
      if (!cnf_head.has_value() || cnf_head->major != 5U || cnf_head->arg != 1U) {
        return std::nullopt;
      }
      const auto cnf_k = r.read_i64();
      if (!cnf_k.has_value() || *cnf_k != 1LL) {
        return std::nullopt;
      }
      const auto cose_head = r.read_head();
      if (!cose_head.has_value() || cose_head->major != 5U ||
          (cose_head->arg != 3U && cose_head->arg != 4U)) {
        return std::nullopt;
      }
      bool ok_kty = false;
      bool ok_alg = false;
      bool ok_crv = false;
      std::optional<mp::Ed25519PubKey> pk;
      for (std::uint64_t j = 0U; j < cose_head->arg; ++j) {
        const auto ck = r.read_i64();
        if (!ck.has_value()) {
          return std::nullopt;
        }
        if (*ck == 1LL) {
          const auto v = r.read_i64();
          if (!v.has_value() || *v != 1LL || ok_kty) {
            return std::nullopt;
          }
          ok_kty = true;
        } else if (*ck == 3LL) {
          const auto v = r.read_i64();
          if (!v.has_value() || *v != -19LL || ok_alg) {
            return std::nullopt;
          }
          ok_alg = true;
        } else if (*ck == -1LL) {
          const auto v = r.read_i64();
          if (!v.has_value() || *v != 6LL || ok_crv) {
            return std::nullopt;
          }
          ok_crv = true;
        } else if (*ck == -2LL) {
          const auto x = r.read_bstr();
          if (!x.has_value() || x->size() != 32U || pk.has_value()) {
            return std::nullopt;
          }
          mp::Ed25519PubKey parsed{};
          std::memcpy(parsed.data(), x->data(), parsed.size());
          pk = parsed;
        } else {
          return std::nullopt;
        }
      }
      if (!ok_kty || !ok_crv || !pk.has_value()) {
        return std::nullopt;
      }
      if (cose_head->arg == 4U && !ok_alg) {
        return std::nullopt;
      }
      dev_pk = *pk;
    } else {
      return std::nullopt;
    }
  }

  if (!r.at_end() || !seen_iss || !exp.has_value() || !iat.has_value() ||
      !dev_pk.has_value()) {
    return std::nullopt;
  }
  return PassiveCwtClaims{*iat, *exp, *dev_pk};
}

DoctorCheck check_online_identity(const DoctorConfig &cfg) {
  DoctorCheck chk{};
  chk.id = "online_identity";
  chk.label = "Online Identity";

  const auto dir_opt = resolve_online_state_dir(cfg);
  if (!dir_opt.has_value()) {
    chk.status = DoctorStatus::info;
    chk.summary = "not configured (no online state directory resolved)";
    chk.hint = "Run: blackbird login";
    return chk;
  }

  // Strictly passive: check existence via lstat before open_existing, never create.
  struct stat st_dir{};
  if (::lstat(dir_opt->c_str(), &st_dir) != 0) {
    if (errno == ENOENT) {
      chk.status = DoctorStatus::info;
      chk.summary = "not configured";
      chk.hint = "Run: blackbird login";
      return chk;
    }
    chk.status = DoctorStatus::fail;
    chk.summary = "cannot inspect online identity directory (io error)";
    chk.hint = "Check permissions on " + sanitize_terminal_text(dir_opt->string());
    return chk;
  }

  auto store_res = mp::MpIdentityStore::open_existing(*dir_opt);
  if (!store_res.has_value()) {
    const auto err_kind = mp::mp_client_error_of(store_res.error());
    if (err_kind == mp::MpClientError::keystore_not_found) {
      chk.status = DoctorStatus::info;
      chk.summary = "not configured";
      chk.hint = "Run: blackbird login";
      return chk;
    }
    chk.status = DoctorStatus::fail;
    chk.summary = "keystore error (" + format_mp_error(store_res.error()) + ")";
    if (err_kind == mp::MpClientError::keystore_insecure_permissions) {
      chk.hint = "Fix permissions: chmod 700 " +
                 sanitize_terminal_text(dir_opt->string()) + " && chmod 600 " +
                 sanitize_terminal_text(dir_opt->string()) + "/*";
    } else {
      chk.hint = "Inspect or re-link your online identity store";
    }
    return chk;
  }

  const mp::MpIdentityStore &store = store_res.value();
  const mp::MpIdentityState &st = store.state();
  const bool has_root = st.root_seed.has_value();

  std::string handle_text =
      st.handle.empty() ? "(unset)" : ("@" + sanitize_terminal_text(st.handle));
  std::string acct_text =
      st.account_id.has_value() ? st.account_id->to_decimal() : "(unset)";
  std::string dev_text =
      st.device_id.has_value() ? st.device_id->to_decimal() : "(unset)";

  std::string safety_text;
  if (has_root && st.account_id.has_value()) {
    const auto root_key = store.root_signing_key();
    if (root_key.has_value()) {
      const auto sn =
          mp::compute_safety_number(*st.account_id, root_key.value().public_key());
      if (sn.has_value()) {
        safety_text = sn.value();
      }
    }
  }

  // Evaluate local device CWT status.
  DoctorStatus cwt_status = DoctorStatus::ok;
  std::string cwt_summary;
  std::optional<std::string> cwt_hint;

  const auto dev_key = store.device_signing_key();
  const std::int64_t now_s = now_epoch_seconds();

  if (st.device_cwt.empty()) {
    if (!st.account_id.has_value() && !st.device_id.has_value()) {
      cwt_status = DoctorStatus::info;
      cwt_summary = "unlinked device";
      cwt_hint = "Run: blackbird login";
    } else {
      cwt_status = DoctorStatus::fail;
      cwt_summary = "missing";
      cwt_hint = "Re-enroll or re-link this device to obtain a valid device CWT";
    }
  } else if (!dev_key.has_value()) {
    cwt_status = DoctorStatus::fail;
    cwt_summary = "corrupt (device key error)";
    cwt_hint = "Re-link this device";
  } else if (has_root) {
    const auto root_key = store.root_signing_key();
    if (!root_key.has_value()) {
      cwt_status = DoctorStatus::fail;
      cwt_summary = "corrupt (root key error)";
      cwt_hint = "Inspect or restore your online identity store";
    } else {
      const auto ver = mp::verify_device_cwt(mp::DeviceCwtVerifyRequest{
          st.device_cwt,
          root_key.value().public_key(),
          dev_key.value().public_key(),
          now_s,
      });
      if (ver.has_value()) {
        std::int64_t rem = 0;
        if (__builtin_sub_overflow(ver.value().exp, now_s, &rem)) {
          rem = std::numeric_limits<std::int64_t>::max();
        }
        if (rem <= kCwtExpiringSoonSeconds) {
          cwt_status = DoctorStatus::warn;
          cwt_summary = "expiring soon (" + format_duration_seconds(rem) + " left)";
          cwt_hint = "Refresh device CWT before expiry";
        } else {
          cwt_status = DoctorStatus::ok;
          cwt_summary = "valid (" + format_duration_seconds(rem) + " left)";
        }
      } else if (mp::mp_error_of(ver.error()) == mp::MpError::cwt_expired) {
        cwt_status = DoctorStatus::fail;
        cwt_summary = "expired";
        cwt_hint = "Re-enroll or re-link this device to refresh its expired CWT";
      } else {
        cwt_status = DoctorStatus::fail;
        cwt_summary = "corrupt (" + format_mp_error(ver.error()) + ")";
        cwt_hint = "Re-enroll or re-link this device";
      }
    }
  } else {
    // Secondary linked device (root key offline): verify CBOR structure, device key
    // binding, TTL, and expiry locally with overflow-safe signed arithmetic.
    const auto parsed = parse_cwt_claims_offline(st.device_cwt);
    std::int64_t max_iat = std::numeric_limits<std::int64_t>::max();
    if (__builtin_add_overflow(now_s, mp::kMaxCwtIatSkewSecs, &max_iat)) {
      max_iat = std::numeric_limits<std::int64_t>::max();
    }
    std::int64_t ttl = 0;
    const bool valid_claims = parsed.has_value() &&
                              mp::constant_time_equal({parsed->device_pubkey,
                                                       dev_key.value().public_key()}) &&
                              parsed->iat >= 0 && parsed->exp > 0 &&
                              !__builtin_sub_overflow(parsed->exp, parsed->iat, &ttl) &&
                              ttl > 0 && ttl <= mp::kMaxCwtTtlSecs &&
                              parsed->iat <= max_iat;
    if (!valid_claims) {
      cwt_status = DoctorStatus::fail;
      cwt_summary = "corrupt";
      cwt_hint = "Re-link this device with your primary device";
    } else if (now_s >= parsed->exp) {
      cwt_status = DoctorStatus::fail;
      cwt_summary = "expired";
      cwt_hint = "Re-link this device with your primary device to refresh its CWT";
    } else {
      std::int64_t rem = 0;
      if (__builtin_sub_overflow(parsed->exp, now_s, &rem)) {
        rem = std::numeric_limits<std::int64_t>::max();
      }
      if (rem <= kCwtExpiringSoonSeconds) {
        cwt_status = DoctorStatus::warn;
        cwt_summary = "expiring soon (" + format_duration_seconds(rem) + " left)";
        cwt_hint = "Re-link or refresh device CWT before expiry";
      } else {
        cwt_status = DoctorStatus::ok;
        cwt_summary = "valid (" + format_duration_seconds(rem) + " left)";
      }
    }
  }

  std::ostringstream summary;
  summary << handle_text << " (account " << acct_text << ", device " << dev_text
          << ", root_key: " << (has_root ? "yes" : "no");
  if (!safety_text.empty()) {
    summary << ", safety_number: " << safety_text;
  }
  summary << ", cwt: " << cwt_summary << ")";

  chk.status = cwt_status;
  chk.summary = summary.str();
  chk.hint = std::move(cwt_hint);
  return chk;
}

// ---------------------------------------------------------------------------
// Check 5: Control plane (/v1/health + RTT + clock skew)
// ---------------------------------------------------------------------------

DoctorCheck check_control_plane(const DoctorConfig &cfg) {
  DoctorCheck chk{};
  chk.id = "control_plane";
  chk.label = "Control Plane";

  if (cfg.offline) {
    chk.status = DoctorStatus::info;
    chk.summary = "skipped (--offline)";
    return chk;
  }

  const std::string authority = sanitize_terminal_text(cfg.mp_client_config.authority);
  mp::MpControlClient client{cfg.mp_client_config};

  const auto t0_steady = SteadyClock::now();
  const std::int64_t t0_wall_ms = now_epoch_ms();
  const auto res = client.health();
  const auto t1_steady = SteadyClock::now();
  const std::int64_t t1_wall_ms = now_epoch_ms();

  const auto elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(t1_steady - t0_steady)
          .count();
  const auto rtt_ms = static_cast<std::uint64_t>(elapsed < 0 ? 0 : elapsed);

  if (!res.has_value()) {
    chk.status = DoctorStatus::fail;
    chk.summary = authority + " unreachable (" + format_mp_error(res.error()) + ")";
    chk.hint = "Check internet connectivity and TLS settings for " + authority;
    return chk;
  }

  if (!res.value().ok) {
    chk.status = DoctorStatus::fail;
    chk.rtt_ms = rtt_ms;
    chk.summary = authority + " reported unhealthy (" + std::to_string(rtt_ms) + "ms)";
    chk.hint = "Control plane reported degraded status; retry shortly";
    return chk;
  }

  // Midpoint wall-clock minimizes half-RTT bias in skew estimation.
  const std::int64_t local_mid_ms = t0_wall_ms + ((t1_wall_ms - t0_wall_ms) / 2LL);
  const std::uint64_t server_u64 = res.value().server_now_ms;
  const std::int64_t server_ms =
      (server_u64 >
       static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
          ? std::numeric_limits<std::int64_t>::max()
          : static_cast<std::int64_t>(server_u64);
  std::int64_t skew_ms = 0;
  if (__builtin_sub_overflow(server_ms, local_mid_ms, &skew_ms)) {
    skew_ms = (server_ms >= 0) ? std::numeric_limits<std::int64_t>::max()
                               : std::numeric_limits<std::int64_t>::min();
  }

  chk.rtt_ms = rtt_ms;
  chk.clock_skew_ms = skew_ms;

  if (skew_ms >= -kMaxAcceptableClockSkewMs && skew_ms <= kMaxAcceptableClockSkewMs) {
    chk.status = DoctorStatus::ok;
    chk.summary = authority + " ok (" + std::to_string(rtt_ms) + "ms, skew " +
                  format_signed_ms(skew_ms) + ")";
  } else {
    chk.status = DoctorStatus::warn;
    chk.summary = authority + " ok but clock skew is " + format_signed_ms(skew_ms) +
                  " (" + std::to_string(rtt_ms) + "ms)";
    chk.hint = "Synchronize your system clock (NTP); skew exceeds 30s";
  }
  return chk;
}

// ---------------------------------------------------------------------------
// Check 6: Relay (lightweight self-contained OpenSSL 3 TLS 1.3 GET <url>/ping)
// ---------------------------------------------------------------------------

struct ParsedHttpsUrl {
  std::string tls_host;
  std::string http_host_header;
  std::uint16_t port = 443U;
  std::string ping_path;
};

bool is_ip_literal(const std::string &host) noexcept {
  in_addr v4{};
  if (::inet_pton(AF_INET, host.c_str(), &v4) == 1) {
    return true;
  }
  in6_addr v6{};
  return ::inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

std::optional<ParsedHttpsUrl> parse_relay_https_url(std::string_view raw_url) {
  constexpr std::string_view kHttps = "https://";
  if (!raw_url.starts_with(kHttps) || raw_url.size() <= kHttps.size() ||
      raw_url.size() > 2048U) {
    return std::nullopt;
  }
  for (const char ch : raw_url) {
    const auto u = static_cast<unsigned char>(ch);
    if (u <= 0x20U || u >= 0x7fU || ch == '@' || ch == '?' || ch == '#' || ch == '\\') {
      return std::nullopt;
    }
  }

  const std::string_view rest = raw_url.substr(kHttps.size());
  const std::size_t slash = rest.find('/');
  const std::string_view authority =
      (slash == std::string_view::npos) ? rest : rest.substr(0U, slash);
  std::string_view base_path =
      (slash == std::string_view::npos) ? std::string_view{} : rest.substr(slash);

  if (authority.empty()) {
    return std::nullopt;
  }
  if (base_path.find("..") != std::string_view::npos) {
    return std::nullopt;
  }

  ParsedHttpsUrl out{};
  out.http_host_header = std::string{authority};
  out.port = 443U;

  if (authority.front() == '[') {
    const std::size_t close = authority.find(']');
    if (close == std::string_view::npos || close <= 1U) {
      return std::nullopt;
    }
    out.tls_host = std::string{authority.substr(1U, close - 1U)};
    if (close + 1U < authority.size()) {
      if (authority[close + 1U] != ':') {
        return std::nullopt;
      }
      const std::string_view port_sv = authority.substr(close + 2U);
      std::uint16_t p = 0U;
      const auto [ptr, ec] =
          std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), p);
      if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size() || p == 0U) {
        return std::nullopt;
      }
      out.port = p;
    }
  } else {
    const std::size_t colon = authority.rfind(':');
    if (colon != std::string_view::npos) {
      if (colon == 0U || authority.find(':') != colon) {
        return std::nullopt;
      }
      out.tls_host = std::string{authority.substr(0U, colon)};
      const std::string_view port_sv = authority.substr(colon + 1U);
      std::uint16_t p = 0U;
      const auto [ptr, ec] =
          std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), p);
      if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size() || p == 0U) {
        return std::nullopt;
      }
      out.port = p;
    } else {
      out.tls_host = std::string{authority};
    }
  }

  if (out.tls_host.empty()) {
    return std::nullopt;
  }

  while (!base_path.empty() && base_path.back() == '/') {
    base_path.remove_suffix(1U);
  }
  out.ping_path = std::string{base_path} + "/ping";
  return out;
}

int remaining_ms_until(SteadyClock::time_point deadline) noexcept {
  const auto now = SteadyClock::now();
  if (now >= deadline) {
    return 0;
  }
  const auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
  if (ms <= 0) {
    return 1;
  }
  if (ms > std::numeric_limits<int>::max()) {
    return std::numeric_limits<int>::max();
  }
  return static_cast<int>(ms);
}

struct SocketPollSpec {
  int fd = -1;
  short events = 0;
  SteadyClock::time_point deadline{};
};

bool poll_socket_until(const SocketPollSpec &spec, std::string &err_out) {
  for (;;) {
    const int rem = remaining_ms_until(spec.deadline);
    if (rem == 0) {
      err_out = "timeout";
      return false;
    }
    pollfd pfd{};
    pfd.fd = spec.fd;
    pfd.events = spec.events;
    const int rc = ::poll(&pfd, 1U, rem);
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      err_out = "poll error";
      return false;
    }
    if (rc == 0) {
      err_out = "timeout";
      return false;
    }
    return true;
  }
}

struct RelayTcpTarget {
  std::string host;
  std::uint16_t port = 443U;
  SteadyClock::time_point deadline{};
};

ScopedFd tcp_connect_relay(const RelayTcpTarget &target, std::string &err_out) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  const std::string port_str = std::to_string(target.port);
  addrinfo *raw = nullptr;
  if (::getaddrinfo(target.host.c_str(), port_str.c_str(), &hints, &raw) != 0 ||
      raw == nullptr) {
    err_out = "dns failed";
    return {};
  }
  UniqueAddrInfo res{raw};
  err_out = "connect failed";

  for (const addrinfo *ai = res.get(); ai != nullptr; ai = ai->ai_next) {
    const int raw_fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (raw_fd < 0) {
      continue;
    }
    ScopedFd fd{raw_fd};
    const int fl = ::fcntl(fd.get(), F_GETFL, 0);
    if (fl < 0 || ::fcntl(fd.get(), F_SETFL, fl | O_NONBLOCK) != 0) {
      continue;
    }
    const int fdfl = ::fcntl(fd.get(), F_GETFD, 0);
    if (fdfl >= 0) {
      (void)::fcntl(fd.get(), F_SETFD, fdfl | FD_CLOEXEC);
    }
    const int one = 1;
    (void)::setsockopt(fd.get(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    (void)::setsockopt(fd.get(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    const int rc = ::connect(fd.get(), ai->ai_addr, ai->ai_addrlen);
    if (rc == 0) {
      err_out.clear();
      return fd;
    }
    if (errno != EINPROGRESS) {
      err_out = "connect refused";
      continue;
    }
    if (!poll_socket_until({fd.get(), POLLOUT, target.deadline}, err_out)) {
      continue;
    }
    int so_err = 0;
    socklen_t so_len = sizeof(so_err);
    if (::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &so_err, &so_len) != 0 ||
        so_err != 0) {
      err_out = "connect failed";
      continue;
    }
    err_out.clear();
    return fd;
  }
  return {};
}

struct RelayProbeOutcome {
  bool ok = false;
  int http_status = 0;
  std::uint64_t rtt_ms = 0U;
  std::string error_reason;
};

RelayProbeOutcome probe_relay_tls13(const DoctorConfig &cfg,
                                    const ParsedHttpsUrl &url) {
  RelayProbeOutcome out{};
  const int timeout_ms = cfg.relay_timeout_ms > 0 ? cfg.relay_timeout_ms : 5000;
  const auto t0 = SteadyClock::now();
  const auto deadline = t0 + std::chrono::milliseconds{timeout_ms};

  UniqueSslCtx ctx{SSL_CTX_new(TLS_client_method())};
  if (!ctx) {
    out.error_reason = "tls init failed";
    return out;
  }
  if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1) {
    out.error_reason = "tls 1.3 init failed";
    return out;
  }
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

  if (cfg.relay_ca_bundle_path.has_value()) {
    const std::string ca = cfg.relay_ca_bundle_path->string();
    if (ca.empty() ||
        SSL_CTX_load_verify_locations(ctx.get(), ca.c_str(), nullptr) != 1) {
      out.error_reason = "tls ca load failed";
      return out;
    }
  } else {
    const bool default_ok = SSL_CTX_set_default_verify_paths(ctx.get()) == 1;
#if defined(__APPLE__)
    const bool apple_ok =
        SSL_CTX_load_verify_locations(ctx.get(), "/etc/ssl/cert.pem", nullptr) == 1;
    if (!default_ok && !apple_ok) {
      out.error_reason = "tls ca load failed";
      return out;
    }
#else
    if (!default_ok) {
      out.error_reason = "tls ca load failed";
      return out;
    }
#endif
  }

  if (SSL_CTX_set_alpn_protos(ctx.get(), kAlpnHttp11.data(),
                              static_cast<unsigned int>(kAlpnHttp11.size())) != 0) {
    out.error_reason = "tls alpn init failed";
    return out;
  }

  const std::string tcp_host =
      cfg.relay_connect_host.empty() ? url.tls_host : cfg.relay_connect_host;
  const std::uint16_t tcp_port = (cfg.relay_port != 0U) ? cfg.relay_port : url.port;

  ScopedFd fd = tcp_connect_relay({tcp_host, tcp_port, deadline}, out.error_reason);
  if (!fd.valid()) {
    return out;
  }

  UniqueSsl ssl{SSL_new(ctx.get())};
  if (!ssl || SSL_set_fd(ssl.get(), fd.get()) != 1) {
    out.error_reason = "tls socket bind failed";
    return out;
  }

  const bool ip_host = is_ip_literal(url.tls_host);
  if (!ip_host) {
    if (SSL_ctrl(ssl.get(), SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
                 const_cast<char *>(url.tls_host.c_str())) != 1) {
      out.error_reason = "tls sni failed";
      return out;
    }
  }
  X509_VERIFY_PARAM *param = SSL_get0_param(ssl.get());
  if (param == nullptr) {
    out.error_reason = "tls verify param failed";
    return out;
  }
  X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
  if (ip_host) {
    if (X509_VERIFY_PARAM_set1_ip_asc(param, url.tls_host.c_str()) != 1) {
      out.error_reason = "tls ip verify setup failed";
      return out;
    }
  } else {
    if (X509_VERIFY_PARAM_set1_host(param, url.tls_host.c_str(), url.tls_host.size()) !=
        1) {
      out.error_reason = "tls host verify setup failed";
      return out;
    }
  }

  for (;;) {
    ERR_clear_error();
    int rc = 0;
    {
      const ScopedSigpipeGuard sig_guard;
      rc = SSL_connect(ssl.get());
    }
    if (rc == 1) {
      break;
    }
    const int ssl_err = SSL_get_error(ssl.get(), rc);
    if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
      const short ev = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
      if (!poll_socket_until({fd.get(), ev, deadline}, out.error_reason)) {
        return out;
      }
      continue;
    }
    if (SSL_get_verify_result(ssl.get()) != X509_V_OK) {
      out.error_reason = "tls certificate verify failed";
    } else {
      out.error_reason = "tls handshake failed";
    }
    return out;
  }

  if (SSL_version(ssl.get()) < TLS1_3_VERSION) {
    out.error_reason = "tls version below 1.3";
    return out;
  }
  UniqueX509 peer_cert{SSL_get1_peer_certificate(ssl.get())};
  if (!peer_cert || SSL_get_verify_result(ssl.get()) != X509_V_OK) {
    out.error_reason = "tls certificate verify failed";
    return out;
  }

  const unsigned char *alpn_proto = nullptr;
  unsigned int alpn_len = 0U;
  SSL_get0_alpn_selected(ssl.get(), &alpn_proto, &alpn_len);
  if (alpn_len > 0U) {
    const std::string_view negotiated{reinterpret_cast<const char *>(alpn_proto),
                                      alpn_len};
    if (negotiated != "http/1.1") {
      out.error_reason = "tls alpn mismatch";
      return out;
    }
  }

  const std::string req =
      "GET " + url.ping_path + " HTTP/1.1\r\n" + "Host: " + url.http_host_header +
      "\r\n" + "User-Agent: blackbird-doctor\r\n" + "Connection: close\r\n\r\n";

  std::size_t sent = 0U;
  while (sent < req.size()) {
    ERR_clear_error();
    int rc = 0;
    {
      const ScopedSigpipeGuard sig_guard;
      rc = SSL_write(ssl.get(), req.data() + sent, static_cast<int>(req.size() - sent));
    }
    if (rc > 0) {
      sent += static_cast<std::size_t>(rc);
      continue;
    }
    const int ssl_err = SSL_get_error(ssl.get(), rc);
    if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
      const short ev = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
      if (!poll_socket_until({fd.get(), ev, deadline}, out.error_reason)) {
        return out;
      }
      continue;
    }
    out.error_reason = "tls write failed";
    return out;
  }

  std::string response;
  response.reserve(1024U);
  std::array<char, 2048> buf{};
  for (;;) {
    if (response.find("\r\n\r\n") != std::string::npos) {
      break;
    }
    if (response.size() >= kMaxRelayHeaderBytes) {
      out.error_reason = "response headers too large";
      return out;
    }
    ERR_clear_error();
    int rc = 0;
    {
      const ScopedSigpipeGuard sig_guard;
      rc = SSL_read(ssl.get(), buf.data(), static_cast<int>(buf.size()));
    }
    if (rc > 0) {
      const auto got = static_cast<std::size_t>(rc);
      const std::size_t take = std::min(got, kMaxRelayHeaderBytes - response.size());
      response.append(buf.data(), take);
      continue;
    }
    const int ssl_err = SSL_get_error(ssl.get(), rc);
    if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
      const short ev = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
      if (!poll_socket_until({fd.get(), ev, deadline}, out.error_reason)) {
        return out;
      }
      continue;
    }
    if (ssl_err == SSL_ERROR_ZERO_RETURN || (ssl_err == SSL_ERROR_SYSCALL && rc == 0)) {
      break;
    }
    out.error_reason = "tls read failed";
    return out;
  }

  {
    const ScopedSigpipeGuard sig_guard;
    (void)SSL_shutdown(ssl.get());
  }

  const auto elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - t0)
          .count();
  out.rtt_ms = static_cast<std::uint64_t>(elapsed < 0 ? 0 : elapsed);

  const std::size_t first_eol = response.find("\r\n");
  if (first_eol == std::string::npos || first_eol < 12U) {
    out.error_reason = "malformed http response";
    return out;
  }
  const std::string_view status_line = std::string_view{response}.substr(0U, first_eol);
  if (!status_line.starts_with("HTTP/1.1 ") && !status_line.starts_with("HTTP/1.0 ")) {
    out.error_reason = "malformed http status";
    return out;
  }
  const std::string_view code_sv = status_line.substr(9U, 3U);
  int status = 0;
  const auto [ptr, ec] =
      std::from_chars(code_sv.data(), code_sv.data() + code_sv.size(), status);
  if (ec != std::errc{} || ptr != code_sv.data() + code_sv.size() || status < 100 ||
      status > 599) {
    out.error_reason = "invalid http status";
    return out;
  }

  out.http_status = status;
  if (status == 200 || status == 204) {
    out.ok = true;
  } else {
    out.error_reason = "HTTP " + std::to_string(status);
  }
  return out;
}

DoctorCheck check_relay(const DoctorConfig &cfg) {
  DoctorCheck chk{};
  chk.id = "relay";
  chk.label = "Relay";

  if (cfg.offline) {
    chk.status = DoctorStatus::info;
    chk.summary = "skipped (--offline)";
    return chk;
  }

  const std::string clean_url = sanitize_terminal_text(cfg.relay_url);
  const auto parsed = parse_relay_https_url(cfg.relay_url);
  if (!parsed.has_value()) {
    chk.status = DoctorStatus::warn;
    chk.summary = "invalid relay URL (" + clean_url + ")";
    chk.hint = "Relay URL must be a valid https:// URL";
    return chk;
  }

  const RelayProbeOutcome probe = probe_relay_tls13(cfg, *parsed);
  if (probe.ok) {
    chk.status = DoctorStatus::ok;
    chk.rtt_ms = probe.rtt_ms;
    chk.summary = clean_url + " ok (HTTP " + std::to_string(probe.http_status) + ", " +
                  std::to_string(probe.rtt_ms) + "ms)";
    return chk;
  }

  chk.status = DoctorStatus::warn;
  chk.summary = clean_url + " unreachable (" + probe.error_reason + ")";
  chk.hint = "Check firewall/TLS connectivity to " + clean_url;
  return chk;
}

// ---------------------------------------------------------------------------
// Check 7: Party Lobby (strictly passive lstat + ping)
// ---------------------------------------------------------------------------

DoctorCheck check_party_lobby(const DoctorConfig &cfg) {
  DoctorCheck chk{};
  chk.id = "party_lobby";
  chk.label = "Party Lobby";

  const std::filesystem::path sock_path = cfg.party_socket_path.empty()
                                              ? default_party_socket_path()
                                              : cfg.party_socket_path;

  struct stat st{};
  if (::lstat(sock_path.c_str(), &st) != 0) {
    chk.status = DoctorStatus::info;
    chk.summary = "not running (starts automatically when you open /party)";
    return chk;
  }

  PartyLobbyClientConfig client_cfg{};
  client_cfg.io_timeout_ms = kPartyLobbyProbeTimeoutMs;
  auto conn = PartyLobbyClient::connect(sock_path, client_cfg);
  if (!conn.has_value()) {
    chk.status = DoctorStatus::info;
    chk.summary = "not running (starts automatically when you open /party)";
    return chk;
  }

  const auto pong = conn.value().ping();
  if (!pong.has_value() || !pong.value().ok) {
    chk.status = DoctorStatus::info;
    chk.summary = "not running (starts automatically when you open /party)";
    return chk;
  }

  const std::size_t rooms = pong.value().room_count;
  chk.status = DoctorStatus::ok;
  chk.summary = "running (pid " + std::to_string(pong.value().server_pid) + ", " +
                std::to_string(rooms) + (rooms == 1U ? " room)" : " rooms)");
  return chk;
}

// ---------------------------------------------------------------------------
// Check 8: Brakes & OS containment (strictly passive policy + kernel probe)
// ---------------------------------------------------------------------------

DoctorCheck check_brakes() {
  DoctorCheck chk{};
  chk.id = "brakes";
  chk.label = "Brakes";

  const auto pol = brakes::load_effective_policy();
  const auto caps = sandbox::probe_os_sandbox_capabilities();

  const std::string backend =
      caps.available ? sanitize_terminal_text(caps.backend_name) : "unavailable";

  if (!pol.has_value()) {
    chk.status = DoctorStatus::fail;
    chk.summary =
        "policy load failed (" +
        std::string{brakes::brakes_error_name(brakes::brakes_error_of(pol.error()))} +
        ") · sandbox=" + backend;
    chk.hint =
        "Inspect /etc/multiplayer/policy.toml and ~/.config/blackbird/policy.toml "
        "(run: blackbird brakes status)";
    return chk;
  }

  const auto &eff = pol.value();
  std::string summary =
      std::string{brakes::brakes_profile_name(eff.effective_profile)} +
      " · sandbox=" + backend;
  if (caps.supports_network_airgap) {
    summary += " (airgap-ready)";
  }
  if (eff.system_policy_loaded) {
    summary += " · sys-floor=" +
               std::string{brakes::brakes_profile_name(eff.brakes.min_profile)};
  }

  if (brakes::is_contained_profile(eff.effective_profile) && !caps.available) {
    chk.status = DoctorStatus::warn;
    chk.summary = std::move(summary);
    chk.hint = "Active brakes profile requires OS containment, but kernel sandbox "
               "probe reported unavailable";
    return chk;
  }

  chk.status = caps.available ? DoctorStatus::ok : DoctorStatus::info;
  chk.summary = std::move(summary);
  return chk;
}

std::string_view status_badge_padded(DoctorStatus status) noexcept {
  switch (status) {
  case DoctorStatus::ok:
    return "[OK]  ";
  case DoctorStatus::info:
    return "[INFO]";
  case DoctorStatus::warn:
    return "[WARN]";
  case DoctorStatus::fail:
    return "[FAIL]";
  }
  return "[????]";
}

} // namespace

std::string_view doctor_status_name(DoctorStatus status) noexcept {
  switch (status) {
  case DoctorStatus::ok:
    return "ok";
  case DoctorStatus::info:
    return "info";
  case DoctorStatus::warn:
    return "warn";
  case DoctorStatus::fail:
    return "fail";
  }
  return "unknown";
}

DoctorReport run_blackbird_doctor(const DoctorConfig &cfg) {
  DoctorReport report{};
  report.checks.reserve(8U);

  auto binary = check_binary(cfg);
  report.target = std::move(binary.target);
  report.version = std::move(binary.version);
  report.checks.push_back(std::move(binary.check));

  report.checks.push_back(check_upgrade(cfg));
  report.checks.push_back(check_provider_auth(cfg));
  report.checks.push_back(check_online_identity(cfg));
  report.checks.push_back(check_control_plane(cfg));
  report.checks.push_back(check_relay(cfg));
  report.checks.push_back(check_party_lobby(cfg));
  report.checks.push_back(check_brakes());

  report.healthy = true;
  for (const auto &chk : report.checks) {
    if (chk.status == DoctorStatus::fail) {
      report.healthy = false;
      break;
    }
  }
  return report;
}

std::string format_doctor_report_human(const DoctorReport &report) {
  std::ostringstream oss;
  const std::string clean_version = sanitize_terminal_text(report.version);
  const std::string clean_target = sanitize_terminal_text(report.target);

  oss << "Blackbird Doctor";
  if (!clean_version.empty() || !clean_target.empty()) {
    oss << " (";
    if (!clean_version.empty()) {
      oss << clean_version;
    }
    if (!clean_version.empty() && !clean_target.empty()) {
      oss << ", ";
    }
    if (!clean_target.empty()) {
      oss << clean_target;
    }
    oss << ")";
  }
  oss << "\n\n";

  std::size_t label_width = 15U;
  for (const auto &chk : report.checks) {
    const std::string lbl = sanitize_terminal_text(chk.label);
    label_width = std::max(label_width, lbl.size());
  }
  label_width = std::min<std::size_t>(label_width, 24U);

  std::size_t ok_count = 0U;
  std::size_t info_count = 0U;
  std::size_t warn_count = 0U;
  std::size_t fail_count = 0U;

  const std::string hint_indent(2U + 6U + 1U + label_width + 2U, ' ');

  for (const auto &chk : report.checks) {
    switch (chk.status) {
    case DoctorStatus::ok:
      ++ok_count;
      break;
    case DoctorStatus::info:
      ++info_count;
      break;
    case DoctorStatus::warn:
      ++warn_count;
      break;
    case DoctorStatus::fail:
      ++fail_count;
      break;
    }

    const std::string lbl = sanitize_terminal_text(chk.label);
    const std::string sum = sanitize_terminal_text(chk.summary);
    oss << "  " << status_badge_padded(chk.status) << " " << lbl;
    if (lbl.size() < label_width) {
      oss << std::string(label_width - lbl.size(), ' ');
    }
    oss << "  " << sum << "\n";

    if (chk.hint.has_value()) {
      const std::string clean_hint = sanitize_terminal_text(*chk.hint);
      if (!clean_hint.empty()) {
        oss << hint_indent << "-> " << clean_hint << "\n";
      }
    }
  }

  oss << "\nSummary: " << ok_count << " ok, " << info_count << " info, " << warn_count
      << " warn, " << fail_count << " fail ("
      << (report.healthy ? "healthy" : "unhealthy") << ")\n";
  return oss.str();
}

Value doctor_report_to_json(const DoctorReport &report) {
  Value::Array checks_arr;
  checks_arr.reserve(report.checks.size());

  for (const auto &chk : report.checks) {
    Value::Object obj;
    obj.emplace_back("id", Value{sanitize_terminal_text(chk.id)});
    obj.emplace_back("label", Value{sanitize_terminal_text(chk.label)});
    obj.emplace_back("status", Value{std::string{doctor_status_name(chk.status)}});
    obj.emplace_back("summary", Value{sanitize_terminal_text(chk.summary)});
    if (chk.hint.has_value()) {
      obj.emplace_back("hint", Value{sanitize_terminal_text(*chk.hint)});
    }
    if (chk.rtt_ms.has_value()) {
      obj.emplace_back("rtt_ms", Value{Number{*chk.rtt_ms}});
    }
    if (chk.clock_skew_ms.has_value()) {
      obj.emplace_back("clock_skew_ms", Value{Number{*chk.clock_skew_ms}});
    }
    checks_arr.push_back(Value::object(std::move(obj)));
  }

  return Value::object({
      {"healthy", Value{report.healthy}},
      {"target", Value{sanitize_terminal_text(report.target)}},
      {"version", Value{sanitize_terminal_text(report.version)}},
      {"checks", Value{std::move(checks_arr)}},
  });
}

} // namespace blackbird
