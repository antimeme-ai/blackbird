#include "blackbird/mp_party_bridge.hpp"

#include "blackbird/json.hpp"
#include "blackbird/party_chat.hpp"
#include "blackbird/party_lobby.hpp"
#include "blackbird/peer_identity.hpp"

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <source_location>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <variant>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

using namespace blackbird;
using namespace blackbird::mp;
namespace fs = std::filesystem;

// Always-active checks (never compiled out under -DNDEBUG).
void require_true(bool ok, std::string_view msg = "",
                  std::source_location loc = std::source_location::current()) {
  if (!ok) {
    std::cerr << "mp_party_bridge_test FAIL at " << loc.file_name() << ":"
              << loc.line();
    if (!msg.empty()) {
      std::cerr << " (" << msg << ")";
    }
    std::cerr << "\n";
    std::abort();
  }
}

void require_ok(bool ok, std::string_view msg = "",
                std::source_location loc = std::source_location::current()) {
  require_true(ok, msg, loc);
}

template <typename T>
const T &require_opt(const std::optional<T> &opt, std::string_view msg = "",
                     std::source_location loc = std::source_location::current()) {
  if (!opt.has_value()) {
    std::cerr << "mp_party_bridge_test FAIL (empty optional) at " << loc.file_name()
              << ":" << loc.line();
    if (!msg.empty()) {
      std::cerr << " (" << msg << ")";
    }
    std::cerr << "\n";
    std::abort();
  }
  return *opt;
}

template <typename T>
T require_val(Result<T> res, std::string_view msg = "",
              std::source_location loc = std::source_location::current()) {
  if (!res.has_value()) {
    std::cerr << "mp_party_bridge_test FAIL (Result error code="
              << error_name(res.error().code) << " detail=" << res.error().detail
              << ") at " << loc.file_name() << ":" << loc.line();
    if (!msg.empty()) {
      std::cerr << " (" << msg << ")";
    }
    std::cerr << "\n";
    std::abort();
  }
  return std::move(res).value();
}

void block_sigpipe_this_thread() noexcept {
  sigset_t sigpipe_set{};
  sigemptyset(&sigpipe_set);
  sigaddset(&sigpipe_set, SIGPIPE);
  (void)::pthread_sigmask(SIG_BLOCK, &sigpipe_set, nullptr);
}

// Short `/tmp` path so AF_UNIX `party.sock` always stays well under macOS sun_path cap.
struct TempDir {
  fs::path path;
  explicit TempDir(const char *prefix) {
    std::string pattern = std::string{"/tmp/"} + prefix + "-XXXXXX";
    char *created = ::mkdtemp(pattern.data());
    require_true(created != nullptr, "mkdtemp failed");
    path = created;
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;
};

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
bool has_any_party_json(const fs::path &root) {
  if (!fs::exists(root)) {
    return false;
  }
  for (const auto &entry : fs::recursive_directory_iterator(root)) {
    if (entry.path().filename() == "party.json") {
      return true;
    }
  }
  return false;
}
#endif

bool contains_raw_terminal_hazard(std::string_view text) {
  for (std::size_t i = 0U; i < text.size(); ++i) {
    const auto b = static_cast<unsigned char>(text[i]);
    if (b < 0x20U || b == 0x7fU) {
      return true;
    }
    if (b >= 0x80U && b <= 0x9fU) {
      // Bare C1 byte (not a UTF-8 continuation byte following a valid lead byte).
      if (i == 0U || static_cast<unsigned char>(text[i - 1U]) < 0xc2U) {
        return true;
      }
    }
    if (b == 0xc2U && i + 1U < text.size()) {
      const auto next = static_cast<unsigned char>(text[i + 1U]);
      if (next >= 0x80U && next <= 0x9fU) {
        return true; // UTF-8 C1 control (including U+009B CSI)
      }
    }
    if (b == 0xe2U && i + 2U < text.size()) {
      const auto b1 = static_cast<unsigned char>(text[i + 1U]);
      const auto b2 = static_cast<unsigned char>(text[i + 2U]);
      if ((b1 == 0x80U &&
           (b2 == 0x8eU || b2 == 0x8fU || (b2 >= 0xaaU && b2 <= 0xaeU))) ||
          (b1 == 0x81U && (b2 >= 0xa6U && b2 <= 0xa9U))) {
        return true; // Unicode BiDi override/isolate
      }
    }
  }
  return false;
}

struct PipePair {
  int read_fd = -1;
  int write_fd = -1;

  PipePair() {
    std::array<int, 2> fds{-1, -1};
    require_true(::pipe(fds.data()) == 0, "pipe");
    read_fd = fds[0];
    write_fd = fds[1];
  }
  ~PipePair() {
    close_write();
    close_read();
  }
  PipePair(const PipePair &) = delete;
  PipePair &operator=(const PipePair &) = delete;

  void close_read() noexcept {
    if (read_fd >= 0) {
      (void)::close(read_fd);
      read_fd = -1;
    }
  }
  void close_write() noexcept {
    if (write_fd >= 0) {
      (void)::close(write_fd);
      write_fd = -1;
    }
  }
  void write_all(std::string_view data) const {
    require_true(write_fd >= 0, "pipe write_fd open");
    std::size_t off = 0U;
    while (off < data.size()) {
      const ssize_t n = ::write(write_fd, data.data() + off, data.size() - off);
      if (n < 0 && errno == EINTR) {
        continue;
      }
      require_true(n > 0, "pipe write succeeded");
      off += static_cast<std::size_t>(n);
    }
  }
};

class LineCollector {
public:
  void push(std::string_view line) {
    {
      std::lock_guard<std::mutex> lk{mu_};
      lines_.emplace_back(line);
    }
    cv_.notify_all();
  }

  std::function<void(std::string_view)> emitter() {
    return [this](std::string_view line) { push(line); };
  }

  template <typename Pred>
  std::optional<std::string> wait_for_line(Pred &&pred, int timeout_ms = 8000) {
    std::unique_lock<std::mutex> lk{mu_};
    std::optional<std::string> found;
    (void)cv_.wait_for(lk, std::chrono::milliseconds{timeout_ms}, [&]() {
      for (const auto &line : lines_) {
        if (pred(line)) {
          found = line;
          return true;
        }
      }
      return false;
    });
    return found;
  }

  std::optional<Value> wait_for_json_type(std::string_view expected_type,
                                          int timeout_ms = 8000) {
    std::unique_lock<std::mutex> lk{mu_};
    std::optional<Value> found;
    (void)cv_.wait_for(lk, std::chrono::milliseconds{timeout_ms}, [&]() {
      for (const auto &line : lines_) {
        const auto parsed = parse_json(line);
        if (!parsed.has_value()) {
          continue;
        }
        const Value *type_v = parsed.value().find("type");
        if (type_v == nullptr) {
          continue;
        }
        const auto *type_s = std::get_if<std::string>(&type_v->value());
        if (type_s != nullptr && *type_s == expected_type) {
          found = parsed.value();
          return true;
        }
      }
      return false;
    });
    return found;
  }

  std::vector<std::string> snapshot() const {
    std::lock_guard<std::mutex> lk{mu_};
    return lines_;
  }

private:
  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::vector<std::string> lines_;
};

std::string json_str(const Value &obj, std::string_view key) {
  const Value *v = obj.find(key);
  require_true(v != nullptr, "json key present");
  const auto *s = std::get_if<std::string>(&v->value());
  require_true(s != nullptr, "json string field");
  return *s;
}

std::uint64_t json_u64(const Value &obj, std::string_view key) {
  const Value *v = obj.find(key);
  require_true(v != nullptr, "json key present");
  const auto *num = std::get_if<Number>(&v->value());
  require_true(num != nullptr, "json number field");
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage())) {
    return *u;
  }
  const auto *i = std::get_if<std::int64_t>(&num->storage());
  require_true(i != nullptr && *i >= 0, "json non-negative integer");
  return static_cast<std::uint64_t>(*i);
}

bool json_bool(const Value &obj, std::string_view key) {
  const Value *v = obj.find(key);
  require_true(v != nullptr, "json key present");
  const auto *b = std::get_if<bool>(&v->value());
  require_true(b != nullptr, "json bool field");
  return *b;
}

// ---------------------------------------------------------------------------
// Minimal Ephemeral TLS 1.3 + Mock PartyDO Server (for Live Attach E2E)
// ---------------------------------------------------------------------------

struct EphemeralCert {
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{nullptr, &EVP_PKEY_free};
  std::unique_ptr<X509, decltype(&X509_free)> cert{nullptr, &X509_free};
  fs::path pem_path;
};

EphemeralCert generate_self_signed_cert(const fs::path &out_pem, const char *san_dns) {
  EphemeralCert out;
  out.pem_path = out_pem;

  EVP_PKEY *raw_key = EVP_EC_gen("P-256");
  require_ok(raw_key != nullptr, "EVP_EC_gen");
  out.key.reset(raw_key);

  X509 *raw_cert = X509_new();
  require_ok(raw_cert != nullptr, "X509_new");
  out.cert.reset(raw_cert);

  require_ok(X509_set_version(raw_cert, 2L) == 1);
  require_ok(ASN1_INTEGER_set(X509_get_serialNumber(raw_cert), 1L) == 1);
  require_ok(X509_gmtime_adj(X509_getm_notBefore(raw_cert), -3600L) != nullptr);
  require_ok(X509_gmtime_adj(X509_getm_notAfter(raw_cert), 86400L) != nullptr);
  require_ok(X509_set_pubkey(raw_cert, raw_key) == 1);

  X509_NAME *name = X509_get_subject_name(raw_cert);
  require_ok(name != nullptr);
  require_ok(X509_NAME_add_entry_by_txt(
                 name, "CN", MBSTRING_ASC,
                 reinterpret_cast<const unsigned char *>(san_dns), -1, -1, 0) == 1);
  require_ok(X509_set_issuer_name(raw_cert, name) == 1);

  X509V3_CTX v3ctx{};
  X509V3_set_ctx_nodb(&v3ctx);
  X509V3_set_ctx(&v3ctx, raw_cert, raw_cert, nullptr, nullptr, 0);

  auto add_ext = [&](int nid, const char *val) {
    X509_EXTENSION *ext =
        X509V3_EXT_conf_nid(nullptr, &v3ctx, nid, const_cast<char *>(val));
    require_ok(ext != nullptr);
    require_ok(X509_add_ext(raw_cert, ext, -1) == 1);
    X509_EXTENSION_free(ext);
  };
  add_ext(NID_basic_constraints, "critical,CA:TRUE");
  add_ext(NID_key_usage, "critical,digitalSignature,keyCertSign");
  const std::string san_value = std::string{"DNS:"} + san_dns + ",IP:127.0.0.1";
  add_ext(NID_subject_alt_name, san_value.c_str());

  require_ok(X509_sign(raw_cert, raw_key, EVP_sha256()) != 0);

  FILE *fp = std::fopen(out_pem.c_str(), "wb");
  require_ok(fp != nullptr);
  require_ok(PEM_write_X509(fp, raw_cert) == 1);
  require_ok(std::fclose(fp) == 0);
  return out;
}

std::string base64_encode_test(std::span<const std::uint8_t> bytes) {
  static constexpr char kAlpha[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  std::size_t i = 0U;
  while (i + 3U <= bytes.size()) {
    const std::uint32_t t = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                            static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 6U) & 0x3fU]);
    out.push_back(kAlpha[t & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1U) {
    const std::uint32_t t = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t t = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

std::string ws_accept_for(std::string_view key) {
  std::string in{key};
  in.append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  std::array<unsigned char, 20> digest{};
  unsigned int len = 0U;
  require_ok(
      EVP_Digest(in.data(), in.size(), digest.data(), &len, EVP_sha1(), nullptr) == 1);
  return base64_encode_test(std::span<const std::uint8_t>{digest.data(), len});
}

std::string to_lower_ascii(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (const char ch : s) {
    if (ch >= 'A' && ch <= 'Z') {
      out.push_back(static_cast<char>(ch + ('a' - 'A')));
    } else {
      out.push_back(ch);
    }
  }
  return out;
}

std::string_view trim_spaces(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
    s.remove_prefix(1U);
  }
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
    s.remove_suffix(1U);
  }
  return s;
}

bool ssl_write_all(SSL *ssl, std::span<const std::uint8_t> data) {
  std::size_t off = 0U;
  while (off < data.size()) {
    const int n =
        SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
    if (n <= 0) {
      return false;
    }
    off += static_cast<std::size_t>(n);
  }
  return true;
}

bool ssl_write_str(SSL *ssl, std::string_view s) {
  return ssl_write_all(ssl,
                       std::span<const std::uint8_t>{
                           reinterpret_cast<const std::uint8_t *>(s.data()), s.size()});
}

std::vector<std::uint8_t> build_server_ws_frame(std::uint8_t opcode,
                                                std::span<const std::uint8_t> payload) {
  std::vector<std::uint8_t> out;
  out.push_back(static_cast<std::uint8_t>(0x80U | (opcode & 0x0fU)));
  if (payload.size() <= 125U) {
    out.push_back(static_cast<std::uint8_t>(payload.size()));
  } else {
    out.push_back(126U);
    out.push_back(static_cast<std::uint8_t>((payload.size() >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(payload.size() & 0xffU));
  }
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

int alpn_select_http11(SSL * /*ssl*/, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void * /*arg*/) {
  static constexpr std::array<unsigned char, 9> kSrvAlpn = {8U,  'h', 't', 't', 'p',
                                                            '/', '1', '.', '1'};
  unsigned char *selected = nullptr;
  unsigned char selected_len = 0U;
  if (SSL_select_next_proto(&selected, &selected_len, kSrvAlpn.data(),
                            static_cast<unsigned int>(kSrvAlpn.size()), in,
                            inlen) != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  *out = selected;
  *outlen = selected_len;
  return SSL_TLSEXT_ERR_OK;
}

struct ParsedClientWsFrame {
  std::uint8_t opcode = 0U;
  bool masked = false;
  std::vector<std::uint8_t> payload;
};

std::optional<ParsedClientWsFrame>
try_pop_client_ws_frame(std::vector<std::uint8_t> &buf) {
  if (buf.size() < 2U) {
    return std::nullopt;
  }
  const std::uint8_t b0 = buf[0];
  const std::uint8_t b1 = buf[1];
  const bool masked = (b1 & 0x80U) != 0U;
  const std::uint8_t len7 = static_cast<std::uint8_t>(b1 & 0x7fU);
  std::size_t pos = 2U;
  std::uint64_t payload_len = len7;
  if (len7 == 126U) {
    if (buf.size() < 4U) {
      return std::nullopt;
    }
    payload_len = (static_cast<std::uint64_t>(buf[2]) << 8U) | buf[3];
    pos = 4U;
  } else if (len7 == 127U) {
    if (buf.size() < 10U) {
      return std::nullopt;
    }
    payload_len = 0U;
    for (std::size_t i = 0U; i < 8U; ++i) {
      payload_len = (payload_len << 8U) | buf[2U + i];
    }
    pos = 10U;
  }
  const std::size_t mask_len = masked ? 4U : 0U;
  if (buf.size() < pos + mask_len + payload_len) {
    return std::nullopt;
  }
  std::array<std::uint8_t, 4> mask{};
  if (masked) {
    std::memcpy(mask.data(), buf.data() + pos, 4U);
    pos += 4U;
  }
  ParsedClientWsFrame out{};
  out.opcode = static_cast<std::uint8_t>(b0 & 0x0fU);
  out.masked = masked;
  out.payload.assign(buf.begin() + static_cast<std::ptrdiff_t>(pos),
                     buf.begin() + static_cast<std::ptrdiff_t>(pos + payload_len));
  if (masked) {
    for (std::size_t i = 0U; i < out.payload.size(); ++i) {
      out.payload[i] = static_cast<std::uint8_t>(out.payload[i] ^ mask[i % 4U]);
    }
  }
  buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(pos + payload_len));
  return out;
}

struct RegisteredDevice {
  AccountId account_id;
  DeviceId device_id;
  Ed25519PubKey root_pubkey{};
  Ed25519PubKey device_pubkey{};
  std::vector<std::uint8_t> device_cwt;
};

enum class ServerActionKind : std::uint8_t {
  send_mp1 = 1,
  send_close = 2,
};

struct ServerAction {
  ServerActionKind kind = ServerActionKind::send_mp1;
  std::optional<Mp1Message> message;
  std::uint16_t close_code = 1000U;
};

struct ClientSlot {
  std::uint64_t generation = 0U;
  std::uint32_t ping_count = 0U;
  std::uint32_t endpoint_update_count = 0U;
  std::optional<EndpointDescriptor> latest_endpoint;
  std::deque<ServerAction> outbound;
};

class MockPartyDoServer {
public:
  MockPartyDoServer(const EphemeralCert &cert, std::string expected_authority)
      : expected_authority_(std::move(expected_authority)) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    require_ok(ctx_ != nullptr, "SSL_CTX_new");
    require_ok(SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION) == 1);
    require_ok(SSL_CTX_use_certificate(ctx_, cert.cert.get()) == 1);
    require_ok(SSL_CTX_use_PrivateKey(ctx_, cert.key.get()) == 1);
    SSL_CTX_set_alpn_select_cb(ctx_, &alpn_select_http11, nullptr);

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    require_ok(listen_fd_ >= 0, "socket");
    const int one = 1;
    require_ok(::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ==
               0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0U;
    require_ok(::bind(listen_fd_, reinterpret_cast<const sockaddr *>(&addr),
                      sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    require_ok(::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len) ==
               0);
    port_ = ntohs(addr.sin_port);
    require_ok(::listen(listen_fd_, 32) == 0);

    accept_thread_ = std::thread([this]() { accept_loop(); });
  }

  ~MockPartyDoServer() {
    stop_.store(true, std::memory_order_release);
    cv_.notify_all();
    if (listen_fd_ >= 0) {
      ::shutdown(listen_fd_, SHUT_RDWR);
      ::close(listen_fd_);
      listen_fd_ = -1;
    }
    if (accept_thread_.joinable()) {
      accept_thread_.join();
    }
    std::vector<std::thread> workers;
    {
      std::lock_guard<std::mutex> lk{mu_};
      workers.swap(worker_threads_);
    }
    for (auto &t : workers) {
      if (t.joinable()) {
        t.join();
      }
    }
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  std::uint16_t port() const noexcept { return port_; }

  void register_device(RegisteredDevice dev) {
    std::lock_guard<std::mutex> lk{mu_};
    const std::uint64_t id = dev.device_id.value();
    devices_.insert_or_assign(id, std::move(dev));
  }

  void push_mp1(DeviceId device_id, Mp1Message msg) {
    {
      std::lock_guard<std::mutex> lk{mu_};
      auto &slot = slots_[device_id.value()];
      ServerAction act{};
      act.kind = ServerActionKind::send_mp1;
      act.message = std::move(msg);
      slot.outbound.push_back(std::move(act));
    }
    cv_.notify_all();
  }

  void send_ws_close(DeviceId device_id, std::uint16_t code) {
    {
      std::lock_guard<std::mutex> lk{mu_};
      auto &slot = slots_[device_id.value()];
      ServerAction act{};
      act.kind = ServerActionKind::send_close;
      act.close_code = code;
      slot.outbound.push_back(act);
    }
    cv_.notify_all();
  }

  std::optional<EndpointDescriptor> wait_for_endpoint_update(
      DeviceId device_id, std::uint32_t expected_count,
      std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) {
    std::unique_lock<std::mutex> lk{mu_};
    const bool ok = cv_.wait_for(lk, timeout, [&]() {
      const auto it = slots_.find(device_id.value());
      return it != slots_.end() && it->second.endpoint_update_count >= expected_count &&
             it->second.latest_endpoint.has_value();
    });
    if (!ok) {
      return std::nullopt;
    }
    return slots_.at(device_id.value()).latest_endpoint;
  }

  bool wait_for_ping_count(
      DeviceId device_id, std::uint32_t expected_count,
      std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) {
    std::unique_lock<std::mutex> lk{mu_};
    return cv_.wait_for(lk, timeout, [&]() {
      const auto it = slots_.find(device_id.value());
      return it != slots_.end() && it->second.ping_count >= expected_count;
    });
  }

private:
  void accept_loop() {
    block_sigpipe_this_thread();
    while (!stop_.load(std::memory_order_acquire)) {
      pollfd pfd{};
      pfd.fd = listen_fd_;
      pfd.events = POLLIN;
      const int rc = ::poll(&pfd, 1U, 25);
      if (rc <= 0) {
        continue;
      }
      const int client_fd = ::accept(listen_fd_, nullptr, nullptr);
      if (client_fd < 0) {
        continue;
      }
#ifdef SO_NOSIGPIPE
      const int one = 1;
      (void)::setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
      std::lock_guard<std::mutex> lk{mu_};
      worker_threads_.emplace_back([this, client_fd]() { handle_client(client_fd); });
    }
  }

  void handle_client(int client_fd) {
    block_sigpipe_this_thread();
    struct FdCloser {
      int fd = -1;
      ~FdCloser() {
        if (fd >= 0) {
          ::close(fd);
        }
      }
    } fd_closer{client_fd};

    SSL *ssl = SSL_new(ctx_);
    if (ssl == nullptr) {
      return;
    }
    struct SslCloser {
      SSL *ptr = nullptr;
      ~SslCloser() {
        if (ptr != nullptr) {
          SSL_shutdown(ptr);
          SSL_free(ptr);
        }
      }
    } ssl_closer{ssl};

    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) != 1) {
      return;
    }

    std::string raw;
    std::array<char, 4096> buf{};
    std::size_t hdr_end = std::string::npos;
    while (hdr_end == std::string::npos && raw.size() < 16384U) {
      const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
      if (n <= 0) {
        return;
      }
      raw.append(buf.data(), static_cast<std::size_t>(n));
      hdr_end = raw.find("\r\n\r\n");
    }
    if (hdr_end == std::string::npos) {
      return;
    }

    const std::string_view hdr_block{raw.data(), hdr_end};
    const std::size_t first_eol = hdr_block.find("\r\n");
    if (first_eol == std::string_view::npos) {
      return;
    }
    const std::string_view req_line = hdr_block.substr(0U, first_eol);
    const std::size_t sp1 = req_line.find(' ');
    const std::size_t sp2 = req_line.find(' ', sp1 + 1U);
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
      return;
    }
    const std::string method_str{req_line.substr(0U, sp1)};
    const std::string target{req_line.substr(sp1 + 1U, sp2 - sp1 - 1U)};

    std::string path = target;
    std::string query = "?";
    if (const std::size_t q = target.find('?'); q != std::string::npos) {
      path = target.substr(0U, q);
      query = target.substr(q);
    }

    std::map<std::string, std::string> headers;
    std::size_t pos = first_eol + 2U;
    while (pos < hdr_block.size()) {
      const std::size_t eol = hdr_block.find("\r\n", pos);
      const std::string_view line = (eol == std::string_view::npos)
                                        ? hdr_block.substr(pos)
                                        : hdr_block.substr(pos, eol - pos);
      if (const std::size_t col = line.find(':'); col != std::string_view::npos) {
        headers[to_lower_ascii(line.substr(0U, col))] =
            std::string{trim_spaces(line.substr(col + 1U))};
      }
      if (eol == std::string_view::npos) {
        break;
      }
      pos = eol + 2U;
    }

    const auto method = parse_http_method(method_str);
    if (!method.has_value() || method.value() != HttpMethod::get ||
        !path.ends_with("/ws")) {
      (void)ssl_write_str(ssl, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                               "Connection: close\r\n\r\n");
      return;
    }

    const auto parsed_si = parse_signature_input(headers["signature-input"]);
    if (!parsed_si.has_value() ||
        !std::holds_alternative<DeviceKeyId>(parsed_si.value().keyid)) {
      (void)ssl_write_str(ssl, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                               "Connection: close\r\n\r\n");
      return;
    }
    const auto dev_keyid = std::get<DeviceKeyId>(parsed_si.value().keyid);

    Ed25519PubKey verify_pk{};
    {
      std::lock_guard<std::mutex> lk{mu_};
      const auto it = devices_.find(dev_keyid.device_id.value());
      if (it == devices_.end() || it->second.account_id != dev_keyid.account_id) {
        (void)ssl_write_str(ssl, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                                 "Connection: close\r\n\r\n");
        return;
      }
      verify_pk = it->second.device_pubkey;
    }

    const auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    const auto now_s = static_cast<std::int64_t>(now_ms / 1000U);

    Rfc9421Request req{};
    req.method = HttpMethod::get;
    req.authority = headers["host"];
    req.path = path;
    req.query = query;
    req.signature_input = headers["signature-input"];
    req.signature = headers["signature"];
    if (!verify_rfc9421_request(
             Rfc9421VerifyInput{req, expected_authority_, verify_pk, now_s})
             .has_value()) {
      (void)ssl_write_str(ssl, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
                               "Connection: close\r\n\r\n");
      return;
    }

    const std::string accept = ws_accept_for(headers.at("sec-websocket-key"));
    const std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Upgrade: websocket\r\n"
                             "Connection: Upgrade\r\n"
                             "Sec-WebSocket-Accept: " +
                             accept +
                             "\r\n"
                             "Sec-WebSocket-Protocol: mp1\r\n\r\n";

    const std::uint64_t session_num =
        next_session_id_.fetch_add(1U, std::memory_order_relaxed);
    const auto hello_bytes = encode_frame(
        0U, HelloAckMessage{require_val(SessionId::create(session_num), "session_id"),
                            now_ms, 20000U});
    require_ok(hello_bytes.has_value(), "encode HELLO_ACK");
    const auto hello_ws = build_server_ws_frame(0x02U, hello_bytes.value());

    std::vector<std::uint8_t> initial(resp.begin(), resp.end());
    initial.insert(initial.end(), hello_ws.begin(), hello_ws.end());
    if (!ssl_write_all(ssl, initial)) {
      return;
    }

    const std::uint64_t dev_raw = dev_keyid.device_id.value();
    std::uint64_t my_gen = 0U;
    {
      std::lock_guard<std::mutex> lk{mu_};
      auto &slot = slots_[dev_raw];
      ++slot.generation;
      my_gen = slot.generation;
    }
    cv_.notify_all();

    std::vector<std::uint8_t> recv_buf;
    if (hdr_end + 4U < raw.size()) {
      const auto *extra =
          reinterpret_cast<const std::uint8_t *>(raw.data() + hdr_end + 4U);
      recv_buf.insert(recv_buf.end(), extra, extra + (raw.size() - (hdr_end + 4U)));
    }

    while (!stop_.load(std::memory_order_acquire)) {
      std::deque<ServerAction> batch;
      {
        std::lock_guard<std::mutex> lk{mu_};
        auto &slot = slots_[dev_raw];
        if (slot.generation != my_gen) {
          break;
        }
        batch.swap(slot.outbound);
      }
      bool exit_loop = false;
      for (const auto &act : batch) {
        if (act.kind == ServerActionKind::send_mp1 && act.message.has_value()) {
          const auto enc = encode_frame(0U, *act.message);
          require_ok(enc.has_value(), "server encode_frame");
          if (!ssl_write_all(ssl, build_server_ws_frame(0x02U, enc.value()))) {
            exit_loop = true;
            break;
          }
        } else if (act.kind == ServerActionKind::send_close) {
          const std::array<std::uint8_t, 2> code_bytes = {
              static_cast<std::uint8_t>((act.close_code >> 8U) & 0xffU),
              static_cast<std::uint8_t>(act.close_code & 0xffU),
          };
          (void)ssl_write_all(ssl, build_server_ws_frame(0x08U, code_bytes));
          exit_loop = true;
          break;
        }
      }
      if (exit_loop) {
        break;
      }

      bool readable = SSL_pending(ssl) > 0;
      if (!readable) {
        pollfd pfd{};
        pfd.fd = client_fd;
        pfd.events = POLLIN;
        const int prc = ::poll(&pfd, 1U, 10);
        if (prc < 0) {
          break;
        }
        readable = (prc > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0);
      }
      if (!readable) {
        continue;
      }

      std::array<std::uint8_t, 4096> rbuf{};
      const int n = SSL_read(ssl, rbuf.data(), static_cast<int>(rbuf.size()));
      if (n <= 0) {
        break;
      }
      recv_buf.insert(recv_buf.end(), rbuf.begin(), rbuf.begin() + n);

      while (auto frame = try_pop_client_ws_frame(recv_buf)) {
        require_ok(frame->masked, "RFC 6455 client frames must be masked");
        if (frame->opcode == 0x02U) {
          const auto dec = decode_frame(frame->payload);
          require_ok(dec.has_value(), "decode client MP1 frame");
          if (const auto *ep_upd =
                  std::get_if<PartyEndpointUpdateMessage>(&dec.value().message)) {
            {
              std::lock_guard<std::mutex> lk{mu_};
              auto &slot = slots_[dev_raw];
              slot.latest_endpoint = ep_upd->endpoint;
              ++slot.endpoint_update_count;
            }
            cv_.notify_all();
          }
        } else if (frame->opcode == 0x01U) {
          const std::string_view text{
              reinterpret_cast<const char *>(frame->payload.data()),
              frame->payload.size()};
          if (text == kMp1HeartbeatPing) {
            {
              std::lock_guard<std::mutex> lk{mu_};
              ++slots_[dev_raw].ping_count;
            }
            cv_.notify_all();
            const std::span<const std::uint8_t> pong_bytes{
                reinterpret_cast<const std::uint8_t *>(kMp1HeartbeatPong.data()),
                kMp1HeartbeatPong.size()};
            if (!ssl_write_all(ssl, build_server_ws_frame(0x01U, pong_bytes))) {
              exit_loop = true;
              break;
            }
          }
        } else if (frame->opcode == 0x09U) {
          (void)ssl_write_all(ssl, build_server_ws_frame(0x0aU, frame->payload));
        } else if (frame->opcode == 0x08U) {
          const std::array<std::uint8_t, 2> ok_close = {0x03U, 0xe8U};
          (void)ssl_write_all(ssl, build_server_ws_frame(0x08U, ok_close));
          exit_loop = true;
          break;
        }
      }
      if (exit_loop) {
        break;
      }
    }
  }

  std::string expected_authority_;
  SSL_CTX *ctx_ = nullptr;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0U;
  std::atomic<bool> stop_{false};
  std::atomic<std::uint64_t> next_session_id_{100U};
  std::thread accept_thread_;

  std::mutex mu_;
  std::condition_variable cv_;
  std::vector<std::thread> worker_threads_;
  std::map<std::uint64_t, RegisteredDevice> devices_;
  std::map<std::uint64_t, ClientSlot> slots_;
};

struct TestPeerIdentity {
  AccountId account_id;
  DeviceId device_id;
  CleansedSeed root_seed;
  CleansedSeed device_seed;
  Ed25519PubKey root_pubkey{};
  Ed25519PubKey device_pubkey{};
  std::vector<std::uint8_t> device_cwt;
  std::string handle;
};

struct PeerIdentitySpec {
  std::uint64_t account_raw = 0U;
  std::uint64_t device_raw = 0U;
  std::uint8_t seed_tag = 0U;
  std::string handle;
  std::int64_t iat_s = 0;
  std::int64_t exp_s = 0;
};

TestPeerIdentity make_test_identity(const PeerIdentitySpec &spec) {
  Ed25519Seed rseed{};
  Ed25519Seed dseed{};
  for (std::size_t i = 0U; i < rseed.size(); ++i) {
    rseed[i] = static_cast<std::uint8_t>(spec.seed_tag ^ (i + 1U));
    dseed[i] = static_cast<std::uint8_t>((spec.seed_tag + 0x40U) ^ (i + 3U));
  }
  const auto root_key = require_val(Ed25519SigningKey::from_seed(rseed), "root key");
  const auto dev_key = require_val(Ed25519SigningKey::from_seed(dseed), "dev key");
  const auto cwt = require_val(
      encode_device_cwt(
          root_key, DeviceCwtMintRequest{dev_key.public_key(), spec.iat_s, spec.exp_s}),
      "encode_device_cwt");

  return TestPeerIdentity{
      require_val(AccountId::create(spec.account_raw), "account_id"),
      require_val(DeviceId::create(spec.device_raw), "device_id"),
      CleansedSeed{rseed},
      CleansedSeed{dseed},
      root_key.public_key(),
      dev_key.public_key(),
      cwt,
      spec.handle,
  };
}

MpClientConfig make_client_config(std::uint16_t port, const fs::path &ca_path) {
  MpClientConfig cfg{};
  cfg.authority = "localhost";
  cfg.connect_host = "127.0.0.1";
  cfg.port = port;
  cfg.ca_bundle_path = ca_path;
  cfg.connect_timeout_ms = 3000;
  cfg.io_timeout_ms = 3000;
  return cfg;
}

MpIdentityState to_identity_state(const TestPeerIdentity &id) {
  MpIdentityState st{};
  st.device_seed = id.device_seed;
  st.account_id = id.account_id;
  st.device_id = id.device_id;
  st.handle = id.handle;
  st.authority = "localhost";
  st.device_cwt = id.device_cwt;
  return st;
}

RegisteredDevice to_registered_device(const TestPeerIdentity &id) {
  return RegisteredDevice{
      id.account_id, id.device_id, id.root_pubkey, id.device_pubkey, id.device_cwt,
  };
}

PartyMemberRecord make_member_record(const TestPeerIdentity &id,
                                     EndpointDescriptor endpoint,
                                     std::uint64_t joined_seq) {
  return PartyMemberRecord{
      id.device_id,  id.account_id,       id.root_pubkey, id.device_pubkey,
      id.device_cwt, std::move(endpoint), joined_seq,     true,
  };
}

EndpointDescriptor make_lan_endpoint(std::uint16_t port) {
  EndpointDescriptor ep{};
  ep.transport_kind = TransportKind::iroh_quic;
  ep.direct_addrs.push_back(DirectAddrV4{{192U, 168U, 1U, 50U}, port});
  return ep;
}

// ---------------------------------------------------------------------------
// Test 1: Strict JSONL Command Parser
// ---------------------------------------------------------------------------

void test_jsonl_command_parser() {
  // 1a. `say` with defaults.
  {
    const auto cmd =
        require_val(parse_mp_attach_command(R"({"cmd":"say","body":"hello world"})"),
                    "parse say default");
    require_true(cmd.kind == MpAttachCommandKind::say);
    const auto &say = std::get<MpAttachSayCommand>(cmd.payload);
    require_true(say.body == "hello world");
    require_true(say.room_scope == kMpAttachDefaultRoomScope);
    require_true(say.target == kMpAttachDefaultTarget);
    require_true(!say.device_id.has_value());
  }

  // 1b. `say` with explicit room_scope, target, and targeted device_id.
  {
    const auto cmd = require_val(
        parse_mp_attach_command(
            R"({"cmd":"say","body":"direct ping","room_scope":"party/ops","target":"@bob","device_id":200})"),
        "parse say targeted");
    require_true(cmd.kind == MpAttachCommandKind::say);
    const auto &say = std::get<MpAttachSayCommand>(cmd.payload);
    require_true(say.body == "direct ping");
    require_true(say.room_scope == "party/ops");
    require_true(say.target == "@bob");
    require_true(require_opt(say.device_id).value() == 200U);
  }

  // 1c. `say` with explicit `device_id: null` treated as broadcast.
  {
    const auto cmd = require_val(
        parse_mp_attach_command(R"({"cmd":"say","body":"hi","device_id":null})"),
        "parse say null device_id");
    require_true(!std::get<MpAttachSayCommand>(cmd.payload).device_id.has_value());
  }

  // 1d. `pulse` across all 5 states.
  for (const auto &[name, expected] :
       std::array<std::pair<std::string_view, P2pPartyActivityState>, 5>{{
           {"offline", P2pPartyActivityState::offline},
           {"online", P2pPartyActivityState::online},
           {"working", P2pPartyActivityState::working},
           {"idle", P2pPartyActivityState::idle},
           {"typing", P2pPartyActivityState::typing},
       }}) {
    const std::string line = std::string{R"({"cmd":"pulse","state":")"} +
                             std::string{name} + R"(","status":"compiling"})";
    const auto cmd = require_val(parse_mp_attach_command(line), "parse pulse");
    require_true(cmd.kind == MpAttachCommandKind::pulse);
    const auto &p = std::get<MpAttachPulseCommand>(cmd.payload);
    require_true(p.state == expected && p.status == "compiling");
  }

  // 1e. `notice` across all 3 kinds.
  for (const auto &[name, expected] :
       std::array<std::pair<std::string_view, P2pPartyControlNoticeKind>, 3>{{
           {"sync_ack", P2pPartyControlNoticeKind::sync_ack},
           {"scope_changed", P2pPartyControlNoticeKind::scope_changed},
           {"status", P2pPartyControlNoticeKind::status},
       }}) {
    const std::string line = std::string{R"({"cmd":"notice","notice_kind":")"} +
                             std::string{name} + R"(","text":"epoch-ready"})";
    const auto cmd = require_val(parse_mp_attach_command(line), "parse notice");
    require_true(cmd.kind == MpAttachCommandKind::notice);
    const auto &n = std::get<MpAttachNoticeCommand>(cmd.payload);
    require_true(n.notice_kind == expected && n.text == "epoch-ready");
  }

  // 1f. `roster`, `ping`, `quit`.
  require_true(require_val(parse_mp_attach_command(R"({"cmd":"roster"})")).kind ==
               MpAttachCommandKind::roster);
  require_true(require_val(parse_mp_attach_command(R"({"cmd":"ping"})")).kind ==
               MpAttachCommandKind::ping);
  require_true(require_val(parse_mp_attach_command(R"({"cmd":"quit"})")).kind ==
               MpAttachCommandKind::quit);

  // 1g. Rejections: oversized line, invalid UTF-8, malformed JSON, non-object,
  // duplicate keys, missing/unknown cmd, oversized fields, bad enums, bad device_id.
  {
    const std::string huge(kMpAttachMaxCommandBytes + 1U, 'a');
    const auto r = parse_mp_attach_command(huge);
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::line_too_large);
  }
  {
    const std::string bad_utf8 = "{\"cmd\":\"say\",\"body\":\"bad\xff\xfe\"}";
    const auto r = parse_mp_attach_command(bad_utf8);
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::invalid_utf8);
  }
  {
    const auto r = parse_mp_attach_command("{not valid json");
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::invalid_json);
  }
  for (const std::string_view non_obj : {"[]", "42", "\"quit\"", "true", "null"}) {
    const auto r = parse_mp_attach_command(non_obj);
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::not_json_object);
  }
  {
    const auto r = parse_mp_attach_command(R"({"cmd":"ping","cmd":"quit"})");
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::invalid_json);
  }
  {
    const auto r = parse_mp_attach_command(R"({"body":"no cmd"})");
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::missing_command);
  }
  {
    const auto r = parse_mp_attach_command(R"({"cmd":"self_destruct"})");
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::unknown_command);
  }
  {
    const auto r = parse_mp_attach_command(R"({"cmd":"say","body":""})");
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::invalid_field);
  }
  {
    const std::string big_body = std::string{R"({"cmd":"say","body":")"} +
                                 std::string(kP2pPartyMaxChatBodyBytes + 1U, 'x') +
                                 R"("})";
    const auto r = parse_mp_attach_command(big_body);
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::field_too_large);
  }
  {
    const std::string big_scope =
        std::string{R"({"cmd":"say","body":"ok","room_scope":")"} +
        std::string(kP2pPartyMaxRoomScopeBytes + 1U, 's') + R"("})";
    const auto r = parse_mp_attach_command(big_scope);
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::field_too_large);
  }
  {
    const std::string big_target =
        std::string{R"({"cmd":"say","body":"ok","target":")"} +
        std::string(kP2pPartyMaxTargetSelectorBytes + 1U, 't') + R"("})";
    const auto r = parse_mp_attach_command(big_target);
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::field_too_large);
  }
  for (const std::string_view bad_dev : {
           R"({"cmd":"say","body":"hi","device_id":0})",
           R"({"cmd":"say","body":"hi","device_id":-5})",
           R"({"cmd":"say","body":"hi","device_id":9007199254740992})",
           R"({"cmd":"say","body":"hi","device_id":"100"})",
           R"({"cmd":"say","body":"hi","device_id":12.5})",
       }) {
    const auto r = parse_mp_attach_command(bad_dev);
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::invalid_device_id);
  }
  {
    const auto r = parse_mp_attach_command(R"({"cmd":"pulse","state":"dancing"})");
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::invalid_enum);
  }
  {
    const std::string big_status =
        std::string{R"({"cmd":"pulse","state":"working","status":")"} +
        std::string(kP2pPartyMaxEphemeralStatusBytes + 1U, 'z') + R"("})";
    const auto r = parse_mp_attach_command(big_status);
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::field_too_large);
  }
  {
    const auto r = parse_mp_attach_command(R"({"cmd":"notice","notice_kind":"bogus"})");
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::invalid_enum);
  }
  {
    const std::string big_notice =
        std::string{R"({"cmd":"notice","notice_kind":"status","text":")"} +
        std::string(kP2pPartyMaxControlNoticeBytes + 1U, 'n') + R"("})";
    const auto r = parse_mp_attach_command(big_notice);
    require_true(!r.has_value() && mp_party_bridge_error_of(r.error()) ==
                                       MpPartyBridgeError::field_too_large);
  }

  std::cout << "PASS test_jsonl_command_parser\n";
}

// ---------------------------------------------------------------------------
// Test 2: Plain-Line Interactive Parser
// ---------------------------------------------------------------------------

void test_plain_line_parser() {
  require_true(
      !require_val(parse_mp_attach_plain_line("", "party/online")).has_value());
  require_true(!require_val(parse_mp_attach_plain_line("   \t \r\n", "party/online"))
                    .has_value());

  const auto q1 =
      require_opt(require_val(parse_mp_attach_plain_line("/quit", "party/online")));
  require_true(q1.kind == MpAttachCommandKind::quit);

  const auto q2 =
      require_opt(require_val(parse_mp_attach_plain_line("  /exit  ", "party/online")));
  require_true(q2.kind == MpAttachCommandKind::quit);

  const auto ros =
      require_opt(require_val(parse_mp_attach_plain_line("/roster", "party/online")));
  require_true(ros.kind == MpAttachCommandKind::roster);

  const auto png =
      require_opt(require_val(parse_mp_attach_plain_line("/ping", "party/online")));
  require_true(png.kind == MpAttachCommandKind::ping);

  const auto st1 = require_opt(require_val(
      parse_mp_attach_plain_line("/status working compiling tests", "party/online")));
  require_true(st1.kind == MpAttachCommandKind::pulse);
  require_true(std::get<MpAttachPulseCommand>(st1.payload).state ==
                   P2pPartyActivityState::working &&
               std::get<MpAttachPulseCommand>(st1.payload).status == "compiling tests");

  const auto st2 = require_opt(
      require_val(parse_mp_attach_plain_line("/status idle", "party/online")));
  require_true(st2.kind == MpAttachCommandKind::pulse &&
               std::get<MpAttachPulseCommand>(st2.payload).state ==
                   P2pPartyActivityState::idle &&
               std::get<MpAttachPulseCommand>(st2.payload).status.empty());

  const auto chat = require_opt(
      require_val(parse_mp_attach_plain_line("hello party team!", "party/dev")));
  require_true(chat.kind == MpAttachCommandKind::say);
  const auto &say = std::get<MpAttachSayCommand>(chat.payload);
  require_true(say.body == "hello party team!" && say.room_scope == "party/dev" &&
               say.target == "@all" && !say.device_id.has_value());

  // Non-command slash text (e.g. path) goes through as normal chat.
  const auto path_chat = require_opt(
      require_val(parse_mp_attach_plain_line("/usr/bin/clang++", "party/online")));
  require_true(path_chat.kind == MpAttachCommandKind::say &&
               std::get<MpAttachSayCommand>(path_chat.payload).body ==
                   "/usr/bin/clang++");

  // Invalid /status arguments fail closed.
  require_true(!parse_mp_attach_plain_line("/status", "party/online").has_value());
  require_true(
      !parse_mp_attach_plain_line("/status teleporting", "party/online").has_value());
  const std::string bad_utf8 = "hello \x80\xff";
  require_true(!parse_mp_attach_plain_line(bad_utf8, "party/online").has_value());

  std::cout << "PASS test_plain_line_parser\n";
}

// ---------------------------------------------------------------------------
// Test 3: Hostile Terminal-Escape Sanitization, JSON Event & Roster Encoding
// ---------------------------------------------------------------------------

void test_sanitization_and_serialization() {
  TempDir tmp{"bb-bridge-fmt"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const std::int64_t t0 = 1764050000;
  const auto party_id = require_val(PartyId::create(8101U), "party_id");
  // Alice uses device_id=200 > Bob=100 so Alice does not auto-dial fake LAN addr.
  const auto alice = make_test_identity(
      PeerIdentitySpec{1001U, 200U, 0x15U, "alice", t0 - 10, t0 + 3600});
  const auto bob = make_test_identity(
      PeerIdentitySpec{2002U, 100U, 0x26U, "bob", t0 - 10, t0 + 3600});
  server.register_device(to_registered_device(alice));

  MpPartyRuntimeConfig cfg{
      make_client_config(server.port(), cert.pem_path),
      to_identity_state(alice),
      party_id,
  };
  cfg.local_relay_policy = RelayPolicy::no_relays;
  cfg.allow_loopback_direct_addrs = true;
  auto rt = require_val(MpPartyRuntime::attach(std::move(cfg)), "attach alice");

  // Push snapshot with Bob so roster + safety_number can be inspected.
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds{4000};
  bool saw_hello = false;
  while (!saw_hello && std::chrono::steady_clock::now() < deadline) {
    (void)require_val(rt.pump_once(20U, t0), "pump hello");
    for (const auto &ev : rt.drain_events()) {
      if (ev.kind == MpRuntimeEventKind::hello_acked) {
        saw_hello = true;
      }
    }
  }
  require_true(saw_hello, "hello_acked");

  server.push_mp1(alice.device_id,
                  Mp1Message{PartySnapshotMessage{
                      party_id,
                      3U,
                      bob.account_id,
                      bob.device_id,
                      PartyVisibility::private_party,
                      PartyJoinMode::invite_only,
                      RelayPolicy::no_relays,
                      4U,
                      "",
                      {make_member_record(bob, make_lan_endpoint(4200U), 1U)},
                  }});
  bool saw_snap = false;
  while (!saw_snap && std::chrono::steady_clock::now() < deadline) {
    (void)require_val(rt.pump_once(20U, t0), "pump snap");
    for (const auto &ev : rt.drain_events()) {
      if (ev.kind == MpRuntimeEventKind::snapshot_applied) {
        saw_snap = true;
      }
    }
  }
  require_true(saw_snap, "snapshot_applied");

  // Roster JSON must contain Bob with exact safety_number, pubkey_b64, is_leader=true.
  MpPeerMetadataMap meta;
  meta[bob.device_id.value()] = MpPeerDisplayMetadata{"bob", "bob-macbook"};
  const Value roster_val = mp_runtime_roster_to_json(rt, &meta);
  const auto *arr = std::get_if<Value::Array>(&roster_val.value());
  require_true(arr != nullptr && arr->size() == 1U, "roster has 1 peer");
  const Value &bob_entry = (*arr)[0];
  require_true(json_u64(bob_entry, "device_id") == bob.device_id.value());
  require_true(json_u64(bob_entry, "account_id") == bob.account_id.value());
  require_true(json_str(bob_entry, "handle") == "bob");
  require_true(json_str(bob_entry, "device_label") == "bob-macbook");
  require_true(json_str(bob_entry, "pubkey_b64") ==
               base64_encode_test(bob.device_pubkey));
  require_true(json_bool(bob_entry, "is_leader"));
  const std::string expected_sn = require_val(
      mp::compute_safety_number(bob.account_id, bob.root_pubkey), "safety number");
  require_true(json_str(bob_entry, "safety_number") == expected_sn);

  // Hostile terminal escape payloads in chat body, handle, room_scope, target,
  // pulse status, and notice text.
  const std::string hostile_body =
      std::string{"hi \x1b[31mRED\x1b[0m \x1b]0;pwned\x07 \xc2\x9b"
                  "2J "
                  "\xe2\x80\xae"
                  "rtl\xe2\x81\xa6"
                  "iso \x7f\x07 ok"};
  const std::string hostile_handle = "\x1b[1mbob\xe2\x80\xae";
  const std::string hostile_status = "\x1b]52;c;AAAA\x07compiling\r\nfake";
  const std::string hostile_notice = "\x1b[2J\x1b[Hcleared\xe2\x80\xae";

  MpRuntimeEvent chat_ev{};
  chat_ev.kind = MpRuntimeEventKind::chat_received;
  chat_ev.party_epoch = 3U;
  chat_ev.sender_device_id = bob.device_id;
  chat_ev.sender_account_id = bob.account_id;
  chat_ev.peer_pubkey = bob.device_pubkey;
  chat_ev.chat = P2pPartyChatMessage{
      "party/\x1b[31monline", "@all\x1b[0m", hostile_handle, 123456789LL, hostile_body,
  };
  const std::string chat_human = format_mp_runtime_event_human(chat_ev, rt);
  require_true(!contains_raw_terminal_hazard(chat_human),
               "human chat output must escape ESC/CSI/OSC/C1/DEL/BiDi");
  require_true(chat_human.find("\\x1b") != std::string::npos,
               "ESC sequence escaped visibly");

  const Value chat_json = mp_runtime_event_to_json(chat_ev, rt);
  require_true(json_str(chat_json, "type") == "chat");
  require_true(json_u64(chat_json, "party_id") == party_id.value());
  require_true(json_u64(chat_json, "sender_device_id") == bob.device_id.value());
  require_true(json_u64(chat_json, "sender_account_id") == bob.account_id.value());
  require_true(json_str(chat_json, "sender_pubkey_b64") ==
               base64_encode_test(bob.device_pubkey));
  require_true(!contains_raw_terminal_hazard(json_str(chat_json, "sanitized_body")),
               "JSON sanitized_body must escape terminal hazards");

  MpRuntimeEvent pulse_ev{};
  pulse_ev.kind = MpRuntimeEventKind::ephemeral_pulse_received;
  pulse_ev.sender_device_id = bob.device_id;
  pulse_ev.sender_account_id = bob.account_id;
  pulse_ev.peer_pubkey = bob.device_pubkey;
  pulse_ev.ephemeral_pulse =
      P2pPartyEphemeralPulse{P2pPartyActivityState::working, 999LL, hostile_status};
  const std::string pulse_human = format_mp_runtime_event_human(pulse_ev, rt);
  require_true(!contains_raw_terminal_hazard(pulse_human),
               "human pulse output must escape terminal hazards");

  MpRuntimeEvent notice_ev{};
  notice_ev.kind = MpRuntimeEventKind::control_notice_received;
  notice_ev.sender_device_id = bob.device_id;
  notice_ev.sender_account_id = bob.account_id;
  notice_ev.peer_pubkey = bob.device_pubkey;
  notice_ev.control_notice =
      P2pPartyControlNotice{P2pPartyControlNoticeKind::status, 3U, hostile_notice};
  const std::string notice_human = format_mp_runtime_event_human(notice_ev, rt);
  require_true(!contains_raw_terminal_hazard(notice_human),
               "human notice output must escape terminal hazards");

  // Verify max-size 1 MiB bridge_envelope serializes cleanly under 4 MiB JSON budget.
  {
    MpRuntimeEvent bridge_ev{};
    bridge_ev.kind = MpRuntimeEventKind::bridge_envelope_received;
    bridge_ev.party_epoch = 3U;
    bridge_ev.sender_device_id = bob.device_id;
    bridge_ev.sender_account_id = bob.account_id;
    bridge_ev.peer_pubkey = bob.device_pubkey;
    bridge_ev.bridge_envelope = P2pPartyBridgeEnvelope{
        "party/bridge",
        std::vector<std::uint8_t>(kP2pPartyMaxBridgePayloadBytes, 0x5aU),
    };
    const Value bridge_json = mp_runtime_event_to_json(bridge_ev, rt);
    require_true(json_str(bridge_json, "type") == "bridge_envelope");
    require_true(json_u64(bridge_json, "payload_bytes") ==
                 kP2pPartyMaxBridgePayloadBytes);
    require_true(json_str(bridge_json, "payload_b64").size() == 1398104U);
    const auto dumped = dump_json(
        bridge_json,
        ValueLimits{.bytes = 4U * 1024U * 1024U, .nodes = 100000U, .depth = 32U});
    require_true(dumped.has_value(), "1 MiB bridge_envelope dumps cleanly");
  }

  // Verify ostream emitter helper writes newline-delimited lines.
  std::ostringstream oss;
  auto ostream_emit = make_mp_attach_ostream_emitter(oss);
  ostream_emit("line-one");
  ostream_emit("line-two");
  require_true(oss.str() == "line-one\nline-two\n", "ostream emitter output");

  rt.shutdown();
  std::cout << "PASS test_sanitization_and_serialization\n";
}

// ---------------------------------------------------------------------------
// Test 4: Control-Plane Attach Lifecycle (disband, 4403 kick, stop_flag,
//         exit_on_eof plain mode, and oversized-line pipe recovery)
// ---------------------------------------------------------------------------

void test_attach_loop_lifecycle_and_stop_conditions() {
  TempDir tmp{"bb-bridge-life"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  const std::int64_t t0 = 1764060000;
  const auto party_id = require_val(PartyId::create(8201U), "party_id");
  const auto alice = make_test_identity(
      PeerIdentitySpec{1001U, 100U, 0x31U, "alice", t0 - 10, t0 + 3600});
  server.register_device(to_registered_device(alice));

  auto attach_alice = [&]() {
    MpPartyRuntimeConfig cfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(alice),
        party_id,
    };
    cfg.local_relay_policy = RelayPolicy::no_relays;
    cfg.allow_loopback_direct_addrs = true;
    return require_val(MpPartyRuntime::attach(std::move(cfg)), "attach alice");
  };

  // 4a. Oversized line recovery on real pipe + ping + PARTY_DISBANDED auto-stop.
  {
    auto rt = attach_alice();
    PipePair pipe;
    LineCollector out;

    MpAttachConfig acfg{};
    acfg.mode = MpAttachMode::jsonl;
    acfg.input_fd = pipe.read_fd;
    acfg.emit_line = out.emitter();
    acfg.tick_ms = 20U;
    acfg.now_s_override = t0;

    Result<MpAttachSummary> runner_res =
        Result<MpAttachSummary>::failure({ErrorCode::incomplete});
    std::thread th(
        [&]() { runner_res = run_mp_party_attach_loop(rt, std::move(acfg)); });

    require_true(out.wait_for_json_type("ready").has_value(), "ready emitted");
    require_true(out.wait_for_json_type("hello_acked").has_value(),
                 "hello_acked emitted");

    // Stream an oversized line (> 320 KiB) followed by a split/partial valid `ping`!
    std::string oversized(kMpAttachMaxCommandBytes + 512U, 'A');
    oversized.push_back('\n');
    pipe.write_all(oversized);
    pipe.write_all("{\"cmd\":");
    std::this_thread::sleep_for(std::chrono::milliseconds{30});
    pipe.write_all("\"ping\"}\n");

    const auto err_json = require_opt(out.wait_for_json_type("command_error"),
                                      "oversized pipe line emitted command_error");
    require_true(json_u64(err_json, "error_detail") ==
                 static_cast<std::uint64_t>(MpPartyBridgeError::line_too_large));
    require_true(out.wait_for_json_type("ack").has_value(),
                 "valid ping processed after oversized line");
    require_true(server.wait_for_ping_count(alice.device_id, 1U),
                 "server received heartbeat ping");

    // Push PARTY_DISBANDED -> loop must auto-stop cleanly and emit `closed`.
    server.push_mp1(alice.device_id, Mp1Message{PartyDisbandedMessage{
                                         1U, PartyDisbandReason::leader_disbanded}});
    th.join();

    const auto summary = require_val(std::move(runner_res), "disband runner summary");
    require_true(summary.final_state == MpRuntimeState::disbanded);
    require_true(summary.close_reason == "party_disbanded");
    require_true(summary.command_errors >= 1U && summary.commands_processed >= 1U);
    const auto closed_json =
        require_opt(out.wait_for_json_type("closed", 1000), "closed emitted");
    require_true(json_str(closed_json, "reason") == "party_disbanded" &&
                 json_str(closed_json, "state") == "disbanded");
  }

  // 4b. WS Close 4403 (`kicked_or_revoked`) auto-stop.
  {
    auto rt = attach_alice();
    LineCollector out;
    MpAttachConfig acfg{};
    acfg.mode = MpAttachMode::jsonl;
    acfg.input_fd = -1; // headless listen-only mode
    acfg.emit_line = out.emitter();
    acfg.tick_ms = 20U;
    acfg.now_s_override = t0;

    Result<MpAttachSummary> runner_res =
        Result<MpAttachSummary>::failure({ErrorCode::incomplete});
    std::thread th(
        [&]() { runner_res = run_mp_party_attach_loop(rt, std::move(acfg)); });

    require_true(out.wait_for_json_type("hello_acked").has_value(), "hello_acked 4403");
    server.send_ws_close(alice.device_id, kMpWsCloseKickedOrBanned);
    th.join();

    const auto summary = require_val(std::move(runner_res), "4403 summary");
    require_true(summary.final_state == MpRuntimeState::terminated &&
                 summary.close_reason == "kicked_or_revoked");
    const auto kicked =
        require_opt(out.wait_for_json_type("kicked_or_revoked", 1000), "kicked event");
    require_true(json_u64(kicked, "ws_close_code") == kMpWsCloseKickedOrBanned);
  }

  // 4c. External `stop_flag` (SIGINT/SIGTERM) exits cleanly and calls
  // runtime.shutdown().
  {
    auto rt = attach_alice();
    LineCollector out;
    std::atomic<bool> stop{false};

    MpAttachConfig acfg{};
    acfg.mode = MpAttachMode::jsonl;
    acfg.input_fd = -1;
    acfg.emit_line = out.emitter();
    acfg.stop_flag = &stop;
    acfg.tick_ms = 20U;
    acfg.now_s_override = t0;

    Result<MpAttachSummary> runner_res =
        Result<MpAttachSummary>::failure({ErrorCode::incomplete});
    std::thread th(
        [&]() { runner_res = run_mp_party_attach_loop(rt, std::move(acfg)); });

    require_true(out.wait_for_json_type("ready").has_value(), "ready stop_flag");
    stop.store(true, std::memory_order_release);
    th.join();

    const auto summary = require_val(std::move(runner_res), "stop_flag summary");
    require_true(summary.close_reason == "signal_stop" && rt.is_terminated());
    const auto closed =
        require_opt(out.wait_for_json_type("closed", 1000), "closed stop_flag");
    require_true(json_str(closed, "reason") == "signal_stop");
  }

  // 4d. Plain interactive mode + `exit_on_eof = true`.
  {
    auto rt = attach_alice();
    PipePair pipe;
    LineCollector out;

    MpAttachConfig acfg{};
    acfg.mode = MpAttachMode::plain;
    acfg.input_fd = pipe.read_fd;
    acfg.emit_line = out.emitter();
    acfg.exit_on_eof = true;
    acfg.tick_ms = 20U;
    acfg.now_s_override = t0;

    Result<MpAttachSummary> runner_res =
        Result<MpAttachSummary>::failure({ErrorCode::incomplete});
    std::thread th(
        [&]() { runner_res = run_mp_party_attach_loop(rt, std::move(acfg)); });

    require_true(
        out.wait_for_line([](std::string_view l) { return l.starts_with("[ready]"); })
            .has_value(),
        "plain ready emitted");
    pipe.write_all("/roster\n");
    pipe.close_write(); // EOF triggers clean exit!
    th.join();

    const auto summary = require_val(std::move(runner_res), "plain eof summary");
    require_true(summary.close_reason == "eof" && summary.commands_processed == 1U);
    require_true(
        out.wait_for_line([](std::string_view l) { return l.starts_with("[roster]"); },
                          1000)
            .has_value(),
        "plain roster emitted");
    require_true(out.wait_for_line(
                        [](std::string_view l) {
                          return l.starts_with("[closed]") &&
                                 l.find("reason=eof") != std::string_view::npos;
                        },
                        1000)
                     .has_value(),
                 "plain closed emitted");
  }

  std::cout << "PASS test_attach_loop_lifecycle_and_stop_conditions\n";
}

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH

// ---------------------------------------------------------------------------
// Test 5: Live 2-Peer E2E Attach Loop over Real iroh v1.5.0 QUIC Mutual RPK
//         + POSIX Pipes + Live In-RAM PartyLobbyServer (`party.sock`)
// ---------------------------------------------------------------------------

void test_live_two_peer_e2e_attach_loop_and_lobby_forward() {
  require_true(p2p_iroh_compiled_in(), "p2p_iroh_compiled_in must be true");

  TempDir tmp{"bb-bridge-e2e"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  // 1. Spin up a live in-RAM PartyLobbyServer (`party.sock`) with room `party/online`.
  auto lobby_id = require_val(PeerIdentityStore::open_or_create(tmp.path / "lobby-id"),
                              "lobby local identity");
  const fs::path sock_path = tmp.path / "run" / "party.sock";
  const std::int64_t lobby_now_ns =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  PartyLobbyServerConfig lcfg{};
  lcfg.socket_path = sock_path;
  lcfg.local_identity_dir = lobby_id.root();
  lcfg.clock_now_ns = [lobby_now_ns]() { return lobby_now_ns; };
  auto lobby_server = require_val(PartyLobbyServer::start(lcfg), "start lobby server");

  auto lobby_observer =
      require_val(PartyLobbyClient::connect(sock_path), "connect lobby observer");
  PartyLease host_lease{};
  host_lease.room_id = "party/online";
  host_lease.alias = "bob";
  host_lease.role = PartyMemberRole::operator_human;
  host_lease.host = "localhost";
  host_lease.model = "blackbird";
  host_lease.issued_ns = lobby_now_ns;
  host_lease.expires_ns = lobby_now_ns + kPartyLobbyDefaultTtlNs;
  host_lease.lease_seq = 1U;
  host_lease =
      require_val(sign_party_lease(lobby_id, std::move(host_lease)), "sign host lease");
  (void)require_val(lobby_observer.create_room("party/online", host_lease),
                    "create in-RAM lobby room");
  require_true(!has_any_party_json(tmp.path), "zero party.json before attach");

  // 2. Attach two real MpPartyRuntime instances (Alice & Bob) over loopback iroh QUIC.
  const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  const auto party_id = require_val(PartyId::create(9001U), "party_id");
  const auto alice_id = make_test_identity(
      PeerIdentitySpec{1001U, 100U, 0x55U, "alice", now_s - 60, now_s + 3600});
  const auto bob_id = make_test_identity(
      PeerIdentitySpec{2002U, 200U, 0x66U, "bob", now_s - 60, now_s + 3600});
  server.register_device(to_registered_device(alice_id));
  server.register_device(to_registered_device(bob_id));

  auto make_rt_cfg = [&](const TestPeerIdentity &id) {
    MpPartyRuntimeConfig rcfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(id),
        party_id,
    };
    rcfg.local_relay_policy = RelayPolicy::no_relays;
    rcfg.max_lease_ttl_s = 60;
    rcfg.allow_loopback_direct_addrs = true;
    return rcfg;
  };

  auto alice_rt =
      require_val(MpPartyRuntime::attach(make_rt_cfg(alice_id)), "attach alice");
  auto bob_rt = require_val(MpPartyRuntime::attach(make_rt_cfg(bob_id)), "attach bob");

  PipePair alice_pipe;
  PipePair bob_pipe;
  LineCollector alice_out;
  LineCollector bob_out;

  MpAttachConfig alice_cfg{};
  alice_cfg.mode = MpAttachMode::jsonl;
  alice_cfg.input_fd = alice_pipe.read_fd;
  alice_cfg.emit_line = alice_out.emitter();
  alice_cfg.tick_ms = 20U;
  // Point Alice at a non-existent local lobby socket to verify best-effort forwarding
  // is strictly non-fatal when the local lobby daemon is absent.
  alice_cfg.local_party_socket = tmp.path / "missing" / "party.sock";
  alice_cfg.local_party_room_id = "party/online";
  alice_cfg.peer_metadata[bob_id.device_id.value()] =
      MpPeerDisplayMetadata{"bob", "bob-dev"};

  MpAttachConfig bob_cfg{};
  bob_cfg.mode = MpAttachMode::jsonl;
  bob_cfg.input_fd = bob_pipe.read_fd;
  bob_cfg.emit_line = bob_out.emitter();
  bob_cfg.tick_ms = 20U;
  bob_cfg.local_party_socket = sock_path;
  bob_cfg.local_party_room_id = "party/online";
  bob_cfg.peer_metadata[alice_id.device_id.value()] =
      MpPeerDisplayMetadata{"alice", "alice-dev"};

  Result<MpAttachSummary> alice_summary_res =
      Result<MpAttachSummary>::failure({ErrorCode::incomplete});
  Result<MpAttachSummary> bob_summary_res =
      Result<MpAttachSummary>::failure({ErrorCode::incomplete});

  std::thread alice_thread([&]() {
    block_sigpipe_this_thread();
    alice_summary_res = run_mp_party_attach_loop(alice_rt, std::move(alice_cfg));
  });
  std::thread bob_thread([&]() {
    block_sigpipe_this_thread();
    bob_summary_res = run_mp_party_attach_loop(bob_rt, std::move(bob_cfg));
  });

  // 3. Wait for `ready` + `hello_acked` + auto `PARTY_ENDPOINT_UPDATE`.
  require_true(alice_out.wait_for_json_type("ready").has_value(), "alice ready");
  require_true(bob_out.wait_for_json_type("ready").has_value(), "bob ready");
  require_true(alice_out.wait_for_json_type("hello_acked").has_value(),
               "alice hello_acked");
  require_true(bob_out.wait_for_json_type("hello_acked").has_value(),
               "bob hello_acked");

  const auto alice_ep =
      require_opt(server.wait_for_endpoint_update(alice_id.device_id, 1U),
                  "alice endpoint published");
  const auto bob_ep = require_opt(server.wait_for_endpoint_update(bob_id.device_id, 1U),
                                  "bob endpoint published");

  // 4. Push PARTY_SNAPSHOT (Bob first to allowlist Alice, then Alice dials Bob).
  PartySnapshotMessage snapshot{
      party_id,
      1U,
      alice_id.account_id,
      alice_id.device_id,
      PartyVisibility::private_party,
      PartyJoinMode::invite_only,
      RelayPolicy::no_relays,
      4U,
      "",
      {
          make_member_record(alice_id, alice_ep, 1U),
          make_member_record(bob_id, bob_ep, 2U),
      },
  };
  server.push_mp1(bob_id.device_id, Mp1Message{snapshot});
  server.push_mp1(alice_id.device_id, Mp1Message{snapshot});

  require_true(alice_out.wait_for_json_type("peer_connected", 10000).has_value(),
               "alice peer_connected over live iroh");
  require_true(bob_out.wait_for_json_type("peer_connected", 10000).has_value(),
               "bob peer_connected over live iroh");

  // 5. Query Bob's roster via JSONL pipe and verify authenticated safety_number.
  bob_pipe.write_all("{\"cmd\":\"roster\"}\n");
  const auto bob_roster =
      require_opt(bob_out.wait_for_json_type("roster"), "bob roster event");
  const Value *peers_val = bob_roster.find("peers");
  require_true(peers_val != nullptr, "roster has peers array");
  const auto *peers_arr = std::get_if<Value::Array>(&peers_val->value());
  require_true(peers_arr != nullptr && peers_arr->size() == 1U, "bob sees Alice");
  require_true(json_u64((*peers_arr)[0], "device_id") == alice_id.device_id.value());
  require_true(json_bool((*peers_arr)[0], "is_leader"));
  require_true(json_bool((*peers_arr)[0], "connected"));
  const std::string alice_sn =
      require_val(mp::compute_safety_number(alice_id.account_id, alice_id.root_pubkey),
                  "alice safety number");
  require_true(json_str((*peers_arr)[0], "safety_number") == alice_sn);

  // 6. Send `{"cmd":"say","body":"hello over iroh!"}` into Alice's pipe!
  alice_pipe.write_all("{\"cmd\":\"say\",\"body\":\"hello over iroh!\"}\n");

  const auto bob_chat =
      require_opt(bob_out.wait_for_json_type("chat", 8000), "bob received chat JSONL");
  require_true(json_u64(bob_chat, "party_id") == party_id.value());
  require_true(json_u64(bob_chat, "sender_device_id") == alice_id.device_id.value());
  require_true(json_u64(bob_chat, "sender_account_id") == alice_id.account_id.value());
  require_true(json_str(bob_chat, "sender_pubkey_b64") ==
               base64_encode_test(alice_id.device_pubkey));
  require_true(json_str(bob_chat, "sender_handle") == "alice");
  require_true(json_str(bob_chat, "room_scope") == "party/online");
  require_true(json_str(bob_chat, "target") == "@all");
  require_true(json_str(bob_chat, "body") == "hello over iroh!");
  require_true(json_str(bob_chat, "sanitized_body") == "hello over iroh!");

  // 7. Verify Bob forwarded the authenticated chat into in-RAM `party.sock` with ZERO
  //    `party.json` on disk!
  bool found_in_lobby = false;
  const auto lobby_deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds{5000};
  while (!found_in_lobby && std::chrono::steady_clock::now() < lobby_deadline) {
    const auto snap =
        require_val(lobby_observer.snapshot("party/online"), "lobby snapshot");
    for (const auto &m : snap.messages) {
      if (m.sender_id == "alice" && m.body == "hello over iroh!") {
        found_in_lobby = true;
        break;
      }
    }
    if (!found_in_lobby) {
      std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
  }
  require_true(found_in_lobby,
               "verified P2P chat forwarded into live in-RAM party.sock");
  require_true(!has_any_party_json(tmp.path),
               "party.json must NEVER be created on disk");

  // 7b. Forward a >64 KiB chat message over live iroh into Bob's PartyLobbyServer
  //     and verify truncation stays <= kPartyMaxMessageBytes so forwarding succeeds!
  {
    const std::string big_body(kPartyMaxMessageBytes + 4096U, 'Z');
    alice_pipe.write_all(std::string{"{\"cmd\":\"say\",\"body\":\""} + big_body +
                         "\"}\n");
    bool found_big_in_lobby = false;
    const auto big_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{5000};
    while (!found_big_in_lobby && std::chrono::steady_clock::now() < big_deadline) {
      const auto snap =
          require_val(lobby_observer.snapshot("party/online"), "lobby big snapshot");
      for (const auto &m : snap.messages) {
        if (m.sender_id == "alice" && m.body.size() == kPartyMaxMessageBytes &&
            m.body.ends_with("...")) {
          found_big_in_lobby = true;
          break;
        }
      }
      if (!found_big_in_lobby) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
      }
    }
    require_true(found_big_in_lobby,
                 ">64 KiB P2P chat truncated cleanly and forwarded into party.sock");
  }

  // 7c. Send a max-size 1 MiB bridge_envelope over live iroh and verify Bob's attach
  //     loop emits full JSONL (never internal_serialize_failed).
  {
    const P2pPartyBridgeEnvelope max_env{
        "party/bridge",
        std::vector<std::uint8_t>(kP2pPartyMaxBridgePayloadBytes, 0x3cU),
    };
    const auto sent_env =
        require_val(alice_rt.broadcast_bridge_envelope(max_env), "send 1 MiB bridge");
    require_true(sent_env.sent == 1U, "1 MiB bridge_envelope sent over live iroh");
    const auto bob_bridge =
        require_opt(bob_out.wait_for_json_type("bridge_envelope", 8000),
                    "bob emitted 1 MiB bridge_envelope JSONL");
    require_true(json_u64(bob_bridge, "payload_bytes") ==
                 kP2pPartyMaxBridgePayloadBytes);
    require_true(json_str(bob_bridge, "payload_b64").size() == 1398104U);
  }

  // 8. Exercise `pulse`, `notice`, and targeted `say` with `device_id`.
  alice_pipe.write_all(
      "{\"cmd\":\"pulse\",\"state\":\"working\",\"status\":\"wave-14c\"}\n");
  alice_pipe.write_all(
      "{\"cmd\":\"notice\",\"notice_kind\":\"sync_ack\",\"text\":\"epoch-1-ok\"}\n");
  const auto bob_pulse =
      require_opt(bob_out.wait_for_json_type("pulse", 5000), "bob pulse");
  require_true(json_str(bob_pulse, "state") == "working" &&
               json_str(bob_pulse, "status") == "wave-14c" &&
               json_u64(bob_pulse, "sender_device_id") == alice_id.device_id.value());
  const auto bob_notice =
      require_opt(bob_out.wait_for_json_type("notice", 5000), "bob notice");
  require_true(json_str(bob_notice, "notice_kind") == "sync_ack" &&
               json_str(bob_notice, "text") == "epoch-1-ok" &&
               json_u64(bob_notice, "sender_device_id") == alice_id.device_id.value());

  bob_pipe.write_all(
      "{\"cmd\":\"say\",\"body\":\"targeted reply!\",\"device_id\":100}\n");
  const auto alice_chat =
      require_opt(alice_out.wait_for_json_type("chat", 5000), "alice targeted chat");
  require_true(json_u64(alice_chat, "sender_device_id") == bob_id.device_id.value() &&
               json_u64(alice_chat, "sender_account_id") == bob_id.account_id.value() &&
               json_str(alice_chat, "body") == "targeted reply!");

  // 9. Clean `{"cmd":"quit"}` shutdown on both peers.
  alice_pipe.write_all("{\"cmd\":\"quit\"}\n");
  bob_pipe.write_all("{\"cmd\":\"quit\"}\n");
  alice_thread.join();
  bob_thread.join();

  const auto alice_summary = require_val(std::move(alice_summary_res), "alice summary");
  const auto bob_summary = require_val(std::move(bob_summary_res), "bob summary");
  require_true(alice_summary.close_reason == "quit" &&
               alice_summary.final_state == MpRuntimeState::terminated &&
               alice_summary.lobby_forwards_failed >= 1U &&
               alice_summary.lobby_forwards_succeeded == 0U);
  require_true(bob_summary.close_reason == "quit" &&
               bob_summary.final_state == MpRuntimeState::terminated &&
               bob_summary.lobby_forwards_succeeded >= 1U);

  const auto alice_closed =
      require_opt(alice_out.wait_for_json_type("closed", 1000), "alice closed");
  const auto bob_closed =
      require_opt(bob_out.wait_for_json_type("closed", 1000), "bob closed");
  require_true(json_str(alice_closed, "reason") == "quit" &&
               json_str(alice_closed, "state") == "terminated");
  require_true(json_str(bob_closed, "reason") == "quit" &&
               json_str(bob_closed, "state") == "terminated");

  lobby_observer.close();
  lobby_server->stop();
  require_true(!has_any_party_json(tmp.path), "still zero party.json after teardown");

  std::cout << "PASS test_live_two_peer_e2e_attach_loop_and_lobby_forward\n";
}

// ---------------------------------------------------------------------------
// Test 6: Anti-Spoofing Lobby Forwarding Regression
//         Remote peer setting wire sender_handle == local lease alias ("bob")
//         without peer_metadata MUST be recorded as "peer_<device_id>" with
//         verified_peer == false & untrusted_remote == true.
// ---------------------------------------------------------------------------

void test_live_lobby_forward_blocks_handle_spoofing() {
  TempDir tmp{"bb-bridge-spoof"};
  const auto cert = generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockPartyDoServer server{cert, "localhost"};

  auto lobby_id =
      require_val(PeerIdentityStore::open_or_create(tmp.path / "lobby-id"), "lobby id");
  const fs::path sock_path = tmp.path / "run" / "party.sock";
  const std::int64_t lobby_now_ns =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  PartyLobbyServerConfig lcfg{};
  lcfg.socket_path = sock_path;
  lcfg.local_identity_dir = lobby_id.root();
  lcfg.clock_now_ns = [lobby_now_ns]() { return lobby_now_ns; };
  auto lobby_server = require_val(PartyLobbyServer::start(lcfg), "start spoof lobby");

  auto lobby_observer =
      require_val(PartyLobbyClient::connect(sock_path), "connect spoof observer");
  PartyLease bob_lease{};
  bob_lease.room_id = "party/online";
  bob_lease.alias = "bob";
  bob_lease.role = PartyMemberRole::operator_human;
  bob_lease.host = "localhost";
  bob_lease.model = "blackbird";
  bob_lease.issued_ns = lobby_now_ns;
  bob_lease.expires_ns = lobby_now_ns + kPartyLobbyDefaultTtlNs;
  bob_lease.lease_seq = 1U;
  bob_lease =
      require_val(sign_party_lease(lobby_id, std::move(bob_lease)), "sign bob lease");
  (void)require_val(lobby_observer.create_room("party/online", bob_lease),
                    "create spoof lobby room");

  const auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
  const auto party_id = require_val(PartyId::create(9002U), "party_id");
  const auto alice_id = make_test_identity(
      PeerIdentitySpec{1001U, 100U, 0x71U, "bob", now_s - 60, now_s + 3600});
  const auto bob_id = make_test_identity(
      PeerIdentitySpec{2002U, 200U, 0x72U, "bob", now_s - 60, now_s + 3600});
  server.register_device(to_registered_device(alice_id));
  server.register_device(to_registered_device(bob_id));

  auto make_rt_cfg = [&](const TestPeerIdentity &id) {
    MpPartyRuntimeConfig rcfg{
        make_client_config(server.port(), cert.pem_path),
        to_identity_state(id),
        party_id,
    };
    rcfg.local_relay_policy = RelayPolicy::no_relays;
    rcfg.max_lease_ttl_s = 60;
    rcfg.allow_loopback_direct_addrs = true;
    return rcfg;
  };

  auto alice_rt =
      require_val(MpPartyRuntime::attach(make_rt_cfg(alice_id)), "attach spoof alice");
  auto bob_rt =
      require_val(MpPartyRuntime::attach(make_rt_cfg(bob_id)), "attach spoof bob");

  PipePair alice_pipe;
  PipePair bob_pipe;
  LineCollector alice_out;
  LineCollector bob_out;

  MpAttachConfig alice_cfg{};
  alice_cfg.mode = MpAttachMode::jsonl;
  alice_cfg.input_fd = alice_pipe.read_fd;
  alice_cfg.emit_line = alice_out.emitter();
  alice_cfg.local_sender_handle = "bob"; // Untrusted remote claims local alias "bob"!
  alice_cfg.tick_ms = 20U;

  MpAttachConfig bob_cfg{};
  bob_cfg.mode = MpAttachMode::jsonl;
  bob_cfg.input_fd = bob_pipe.read_fd;
  bob_cfg.emit_line = bob_out.emitter();
  bob_cfg.tick_ms = 20U;
  bob_cfg.local_party_socket = sock_path;
  bob_cfg.local_party_room_id = "party/online";
  // Deliberately NO peer_metadata entry for Alice!

  Result<MpAttachSummary> alice_res =
      Result<MpAttachSummary>::failure({ErrorCode::incomplete});
  Result<MpAttachSummary> bob_res =
      Result<MpAttachSummary>::failure({ErrorCode::incomplete});

  std::thread alice_th([&]() {
    block_sigpipe_this_thread();
    alice_res = run_mp_party_attach_loop(alice_rt, std::move(alice_cfg));
  });
  std::thread bob_th([&]() {
    block_sigpipe_this_thread();
    bob_res = run_mp_party_attach_loop(bob_rt, std::move(bob_cfg));
  });

  require_true(alice_out.wait_for_json_type("hello_acked").has_value());
  require_true(bob_out.wait_for_json_type("hello_acked").has_value());
  const auto alice_ep =
      require_opt(server.wait_for_endpoint_update(alice_id.device_id, 1U));
  const auto bob_ep =
      require_opt(server.wait_for_endpoint_update(bob_id.device_id, 1U));

  PartySnapshotMessage snapshot{
      party_id,
      1U,
      alice_id.account_id,
      alice_id.device_id,
      PartyVisibility::private_party,
      PartyJoinMode::invite_only,
      RelayPolicy::no_relays,
      4U,
      "",
      {
          make_member_record(alice_id, alice_ep, 1U),
          make_member_record(bob_id, bob_ep, 2U),
      },
  };
  server.push_mp1(bob_id.device_id, Mp1Message{snapshot});
  server.push_mp1(alice_id.device_id, Mp1Message{snapshot});
  require_true(alice_out.wait_for_json_type("peer_connected", 10000).has_value());
  require_true(bob_out.wait_for_json_type("peer_connected", 10000).has_value());

  alice_pipe.write_all("{\"cmd\":\"say\",\"body\":\"spoof attempt\"}\n");
  require_true(bob_out.wait_for_json_type("chat", 8000).has_value());

  bool verified_anti_spoof = false;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds{5000};
  while (!verified_anti_spoof && std::chrono::steady_clock::now() < deadline) {
    const auto snap =
        require_val(lobby_observer.snapshot("party/online"), "spoof lobby snapshot");
    for (const auto &m : snap.messages) {
      if (m.body == "spoof attempt") {
        require_true(m.sender_id == "peer_100",
                     "untrusted wire sender_handle must NOT impersonate local 'bob'");
        require_true(!m.verified_peer && m.untrusted_remote,
                     "unmapped remote peer must stay unverified & untrusted_remote");
        verified_anti_spoof = true;
        break;
      }
    }
    if (!verified_anti_spoof) {
      std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
  }
  require_true(verified_anti_spoof, "anti-spoof lobby forward verified");

  alice_pipe.write_all("{\"cmd\":\"quit\"}\n");
  bob_pipe.write_all("{\"cmd\":\"quit\"}\n");
  alice_th.join();
  bob_th.join();
  (void)require_val(std::move(alice_res), "spoof alice summary");
  (void)require_val(std::move(bob_res), "spoof bob summary");

  lobby_observer.close();
  lobby_server->stop();
  require_true(!has_any_party_json(tmp.path), "zero party.json in spoof test");

  std::cout << "PASS test_live_lobby_forward_blocks_handle_spoofing\n";
}

#endif

} // namespace

int main() {
  block_sigpipe_this_thread();
  test_jsonl_command_parser();
  test_plain_line_parser();
  test_sanitization_and_serialization();
  test_attach_loop_lifecycle_and_stop_conditions();
#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
  test_live_two_peer_e2e_attach_loop_and_lobby_forward();
  test_live_lobby_forward_blocks_handle_spoofing();
#endif
  std::cout << "mp_party_bridge_test: ALL PASSED\n";
  return 0;
}
