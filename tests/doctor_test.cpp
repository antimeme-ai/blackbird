#include "blackbird/doctor.hpp"

#include "blackbird/json.hpp"
#include "blackbird/mp_client.hpp"
#include "blackbird/mp_protocol.hpp"
#include "blackbird/party_lobby.hpp"
#include "blackbird/provider_auth.hpp"
#include "blackbird/self_upgrade.hpp"

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <source_location>
#include <spawn.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

using namespace blackbird;

namespace {

namespace fs = std::filesystem;

const char *g_stage = "startup";

void require(bool condition, const char *message,
             std::source_location loc = std::source_location::current()) {
  if (!condition) {
    std::ostringstream oss;
    oss << g_stage << " (" << loc.file_name() << ":" << loc.line() << "): " << message;
    throw std::runtime_error(oss.str());
  }
}

template <typename T>
T must(Result<T> res, const char *context,
       std::source_location loc = std::source_location::current()) {
  if (!res.has_value()) {
    std::ostringstream oss;
    oss << g_stage << " [" << context << "] (" << loc.file_name() << ":" << loc.line()
        << "): " << error_name(res.error().code) << " (detail=" << res.error().detail
        << ")";
    throw std::runtime_error(oss.str());
  }
  return std::move(res).value();
}

struct TempDir {
  fs::path path;
  explicit TempDir(const char *prefix) {
    std::string pattern = std::string{"/tmp/"} + prefix + "-XXXXXX";
    char *created = ::mkdtemp(pattern.data());
    require(created != nullptr, "mkdtemp failed");
    path = fs::path{created};
  }
  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
};

struct ScopedEnvVar {
  std::string name;
  std::optional<std::string> prev;

  ScopedEnvVar(std::string var_name, std::optional<std::string> value)
      : name(std::move(var_name)) {
    if (const char *cur = std::getenv(name.c_str()); cur != nullptr) {
      prev = std::string{cur};
    }
    if (value.has_value()) {
      require(::setenv(name.c_str(), value->c_str(), 1) == 0, "setenv failed");
    } else {
      require(::unsetenv(name.c_str()) == 0, "unsetenv failed");
    }
  }
  ScopedEnvVar(const ScopedEnvVar &) = delete;
  ScopedEnvVar &operator=(const ScopedEnvVar &) = delete;
  ~ScopedEnvVar() {
    if (prev.has_value()) {
      (void)::setenv(name.c_str(), prev->c_str(), 1);
    } else {
      (void)::unsetenv(name.c_str());
    }
  }
};

const DoctorCheck &find_check(const DoctorReport &report, std::string_view id) {
  for (const auto &chk : report.checks) {
    if (chk.id == id) {
      return chk;
    }
  }
  throw std::runtime_error(std::string{g_stage} + ": missing check id " +
                           std::string{id});
}

// ---------------------------------------------------------------------------
// Ephemeral TLS 1.3 cert & dual-endpoint loopback server (/v1/health + /ping)
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
  require(raw_key != nullptr, "EVP_EC_gen failed");
  out.key.reset(raw_key);

  X509 *raw_cert = X509_new();
  require(raw_cert != nullptr, "X509_new failed");
  out.cert.reset(raw_cert);

  require(X509_set_version(raw_cert, 2L) == 1, "X509_set_version");
  require(ASN1_INTEGER_set(X509_get_serialNumber(raw_cert), 1L) == 1, "serial");
  require(X509_gmtime_adj(X509_getm_notBefore(raw_cert), -3600L) != nullptr,
          "notBefore");
  require(X509_gmtime_adj(X509_getm_notAfter(raw_cert), 86400L) != nullptr, "notAfter");
  require(X509_set_pubkey(raw_cert, raw_key) == 1, "set_pubkey");

  X509_NAME *name = X509_get_subject_name(raw_cert);
  require(name != nullptr, "subject name");
  require(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                     reinterpret_cast<const unsigned char *>(san_dns),
                                     -1, -1, 0) == 1,
          "CN");
  require(X509_set_issuer_name(raw_cert, name) == 1, "issuer");

  X509V3_CTX v3ctx{};
  X509V3_set_ctx_nodb(&v3ctx);
  X509V3_set_ctx(&v3ctx, raw_cert, raw_cert, nullptr, nullptr, 0);

  auto add_ext = [&](int nid, const char *val) {
    X509_EXTENSION *ext =
        X509V3_EXT_conf_nid(nullptr, &v3ctx, nid, const_cast<char *>(val));
    require(ext != nullptr, "X509V3_EXT_conf_nid");
    require(X509_add_ext(raw_cert, ext, -1) == 1, "X509_add_ext");
    X509_EXTENSION_free(ext);
  };
  add_ext(NID_basic_constraints, "critical,CA:TRUE");
  add_ext(NID_key_usage, "critical,digitalSignature,keyCertSign");
  const std::string san_value = std::string{"DNS:"} + san_dns + ",IP:127.0.0.1";
  add_ext(NID_subject_alt_name, san_value.c_str());

  require(X509_sign(raw_cert, raw_key, EVP_sha256()) != 0, "X509_sign");

  FILE *fp = std::fopen(out_pem.c_str(), "wb");
  require(fp != nullptr, "fopen pem");
  require(PEM_write_X509(fp, raw_cert) == 1, "PEM_write_X509");
  require(std::fclose(fp) == 0, "fclose pem");
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

struct MockTlsServerConfig {
  std::atomic<std::int64_t> health_skew_ms{0};
  std::atomic<int> relay_status{200};
  std::atomic<int> health_hits{0};
  std::atomic<int> ping_hits{0};
};

class MockTlsServer {
public:
  MockTlsServer(const EphemeralCert &cert, MockTlsServerConfig &state) : state_(state) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    require(ctx_ != nullptr, "SSL_CTX_new");
    require(SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION) == 1, "min TLS 1.3");
    require(SSL_CTX_use_certificate(ctx_, cert.cert.get()) == 1, "use cert");
    require(SSL_CTX_use_PrivateKey(ctx_, cert.key.get()) == 1, "use key");
    SSL_CTX_set_alpn_select_cb(ctx_, &alpn_select_http11, nullptr);

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    require(listen_fd_ >= 0, "socket");
    const int one = 1;
    (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    require(::bind(listen_fd_, reinterpret_cast<const sockaddr *>(&addr),
                   sizeof(addr)) == 0,
            "bind");
    require(::listen(listen_fd_, 16) == 0, "listen");

    socklen_t len = sizeof(addr);
    require(::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len) == 0,
            "getsockname");
    port_ = ntohs(addr.sin_port);

    thread_ = std::thread([this]() { serve_loop(); });
  }

  MockTlsServer(const MockTlsServer &) = delete;
  MockTlsServer &operator=(const MockTlsServer &) = delete;

  ~MockTlsServer() {
    stop_.store(true, std::memory_order_relaxed);
    if (listen_fd_ >= 0) {
      ::shutdown(listen_fd_, SHUT_RDWR);
      ::close(listen_fd_);
      listen_fd_ = -1;
    }
    if (thread_.joinable()) {
      thread_.join();
    }
    if (ctx_ != nullptr) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  std::uint16_t port() const noexcept { return port_; }

private:
  void serve_loop() {
    while (!stop_.load(std::memory_order_relaxed)) {
      pollfd pfd{};
      pfd.fd = listen_fd_;
      pfd.events = POLLIN;
      const int rc = ::poll(&pfd, 1U, 50);
      if (rc <= 0) {
        continue;
      }
      const int client_fd = ::accept(listen_fd_, nullptr, nullptr);
      if (client_fd < 0) {
        continue;
      }
      handle_client(client_fd);
      ::close(client_fd);
    }
  }

  void handle_client(int client_fd) {
    SSL *ssl = SSL_new(ctx_);
    if (ssl == nullptr) {
      return;
    }
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) != 1) {
      SSL_free(ssl);
      return;
    }

    std::string req;
    std::array<char, 2048> buf{};
    while (req.find("\r\n\r\n") == std::string::npos && req.size() < 8192U) {
      const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
      if (n <= 0) {
        break;
      }
      req.append(buf.data(), static_cast<std::size_t>(n));
    }

    std::string resp;
    if (req.starts_with("GET /v1/health ")) {
      state_.health_hits.fetch_add(1, std::memory_order_relaxed);
      const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();
      const auto server_ms =
          static_cast<std::uint64_t>(now_ms + state_.health_skew_ms.load());
      const std::string body =
          "{\"ok\":true,\"server_now_ms\":" + std::to_string(server_ms) + "}";
      resp = "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: " +
             std::to_string(body.size()) +
             "\r\n"
             "Connection: close\r\n\r\n" +
             body;
    } else if (req.starts_with("GET /ping ")) {
      state_.ping_hits.fetch_add(1, std::memory_order_relaxed);
      const int st = state_.relay_status.load();
      if (st == 204) {
        resp = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
      } else if (st == 200) {
        const std::string body = "pong\n";
        resp = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
               "\r\nConnection: close\r\n\r\n" + body;
      } else {
        resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
               "Connection: close\r\n\r\n";
      }
    } else {
      resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    }

    std::size_t off = 0U;
    while (off < resp.size()) {
      const int n =
          SSL_write(ssl, resp.data() + off, static_cast<int>(resp.size() - off));
      if (n <= 0) {
        break;
      }
      off += static_cast<std::size_t>(n);
    }
    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
  }

  MockTlsServerConfig &state_;
  SSL_CTX *ctx_ = nullptr;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0U;
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

// ---------------------------------------------------------------------------
// File-based upgrade fixture helper
// ---------------------------------------------------------------------------

void write_text_file(const fs::path &path, std::string_view content,
                     mode_t mode = 0644) {
  std::error_code ec;
  fs::create_directories(path.parent_path(), ec);
  require(!ec, "create_directories failed");
  std::ofstream ofs{path, std::ios::binary | std::ios::trunc};
  require(ofs.good(), "open write failed");
  ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
  ofs.close();
  require(ofs.good(), "write failed");
  require(::chmod(path.c_str(), mode) == 0, "chmod failed");
}

std::string sha256_file_hex(const fs::path &path) {
  std::ifstream ifs{path, std::ios::binary};
  require(ifs.good(), "open sha256 failed");
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  require(ctx != nullptr, "EVP_MD_CTX_new");
  require(EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1, "DigestInit");
  std::array<char, 4096> buf{};
  while (ifs.good()) {
    ifs.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    const auto n = ifs.gcount();
    if (n > 0) {
      require(EVP_DigestUpdate(ctx, buf.data(), static_cast<std::size_t>(n)) == 1,
              "DigestUpdate");
    }
  }
  std::array<unsigned char, EVP_MAX_MD_SIZE> dig{};
  unsigned int len = 0U;
  require(EVP_DigestFinal_ex(ctx, dig.data(), &len) == 1 && len == 32U, "DigestFinal");
  EVP_MD_CTX_free(ctx);

  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(64U);
  for (std::size_t i = 0U; i < 32U; ++i) {
    out.push_back(kHex[(dig[i] >> 4U) & 0x0FU]);
    out.push_back(kHex[dig[i] & 0x0FU]);
  }
  return out;
}

std::string build_upgrade_mirror(const fs::path &mirror_dir, const std::string &target,
                                 const std::string &version,
                                 const std::string &commit) {
  const std::string filename = "blackbird-" + version + "-" + target + ".tar.gz";
  const fs::path asset_path = mirror_dir / filename;
  write_text_file(asset_path, "dummy-release-archive-bytes", 0644);

  const std::string sha = sha256_file_hex(asset_path);
  std::error_code ec;
  const std::uint64_t sz = fs::file_size(asset_path, ec);
  require(!ec && sz > 0U, "asset size");

  std::ostringstream manifest;
  manifest << "{\n"
           << "  \"version\": \"" << version << "\",\n"
           << "  \"commit\": \"" << commit << "\",\n"
           << "  \"assets\": [\n"
           << "    {\n"
           << "      \"target\": \"" << target << "\",\n"
           << "      \"filename\": \"" << filename << "\",\n"
           << "      \"sha256\": \"" << sha << "\",\n"
           << "      \"size_bytes\": " << sz << "\n"
           << "    }\n"
           << "  ]\n"
           << "}\n";
  write_text_file(mirror_dir / "release-manifest.json", manifest.str(), 0644);
  write_text_file(mirror_dir / "SHA256SUMS.txt", sha + "  " + filename + "\n", 0644);
  return "file://" + mirror_dir.string();
}

// ---------------------------------------------------------------------------
// Test 1: Offline mode, zero disk creation, secret non-leakage
// ---------------------------------------------------------------------------

void test_offline_zero_disk_and_zero_secret_leak() {
  g_stage = "offline_zero_disk_and_zero_secret_leak";
  TempDir tmp("bb-doctor-offline");

  const fs::path non_existent_prefix = tmp.path / "no-such-prefix";
  const fs::path non_existent_online = tmp.path / "no-such-online";
  const fs::path non_existent_auth = tmp.path / "no-such-auth";
  const fs::path non_existent_sock = tmp.path / "no-such-run" / "party.sock";

  // Clear all provider env vars except one synthetic secret we verify NEVER leaks.
  const std::string dummy_secret = "sk-test-ULTRA-SECRET-NEVER-LEAK-9876543210";
  ScopedEnvVar e_openai("OPENAI_API_KEY", dummy_secret);
  ScopedEnvVar e_anthropic("ANTHROPIC_API_KEY", std::nullopt);
  ScopedEnvVar e_openrouter("OPENROUTER_API_KEY", std::nullopt);
  ScopedEnvVar e_gemini("GEMINI_API_KEY", std::nullopt);
  ScopedEnvVar e_xai("XAI_API_KEY", std::nullopt);
  ScopedEnvVar e_moonshot("MOONSHOT_API_KEY", std::nullopt);
  ScopedEnvVar e_deepseek("DEEPSEEK_API_KEY", std::nullopt);
  ScopedEnvVar e_kimi("KIMI_API_KEY", std::nullopt);
  ScopedEnvVar e_mimo("MIMO_API_KEY", std::nullopt);
  ScopedEnvVar e_typesafe("TYPESAFE_API_KEY", std::nullopt);
  ScopedEnvVar e_clef("CLEF_API_KEY", std::nullopt);

  DoctorConfig cfg{};
  cfg.current_version_string = "blackbird v0.1.0 (test)";
  cfg.install_prefix = non_existent_prefix;
  cfg.online_state_dir = non_existent_online;
  cfg.provider_auth_home = non_existent_auth;
  cfg.party_socket_path = non_existent_sock;
  cfg.offline = true;
  cfg.check_update = true;

  const DoctorReport report = run_blackbird_doctor(cfg);

  // Verify ZERO files or directories were created anywhere inside tmp.path.
  require(!fs::exists(non_existent_prefix), "doctor created install_prefix!");
  require(!fs::exists(non_existent_online), "doctor created online_state_dir!");
  require(!fs::exists(non_existent_auth), "doctor created provider_auth_home!");
  require(!fs::exists(non_existent_sock.parent_path()), "doctor created socket dir!");
  require(fs::is_empty(tmp.path), "doctor created unexpected files in tmp!");

  require(report.healthy, "clean offline report must be healthy");
  require(report.checks.size() == 7U, "expected 7 doctor checks");

  const auto &bin = find_check(report, "binary");
  require(bin.status == DoctorStatus::ok, "binary check must be ok");
  require(bin.summary.find("v0.1.0") != std::string::npos, "binary summary version");

  const auto &upg = find_check(report, "upgrade");
  require(upg.status == DoctorStatus::info, "offline upgrade must be info");
  require(upg.summary.find("offline") != std::string::npos, "offline upgrade text");

  const auto &auth = find_check(report, "provider_auth");
  require(auth.status == DoctorStatus::ok, "provider_auth must detect OPENAI_API_KEY");
  require(auth.summary.find("openai") != std::string::npos, "must report openai");

  const auto &online = find_check(report, "online_identity");
  require(online.status == DoctorStatus::info, "absent online identity must be info");
  require(online.hint.has_value() &&
              online.hint->find("blackbird online register") != std::string::npos,
          "online identity hint missing");

  const auto &cp = find_check(report, "control_plane");
  require(cp.status == DoctorStatus::info, "offline control_plane must be info");

  const auto &rel = find_check(report, "relay");
  require(rel.status == DoctorStatus::info, "offline relay must be info");

  const auto &lobby = find_check(report, "party_lobby");
  require(lobby.status == DoctorStatus::info, "absent party_lobby must be info");

  // Also test existing empty auth dir (must NOT create lock file inside!).
  const fs::path empty_auth_dir = tmp.path / "empty-auth-0700";
  require(::mkdir(empty_auth_dir.c_str(), mode_t{0700}) == 0, "mkdir empty_auth_dir");
  cfg.provider_auth_home = empty_auth_dir;
  (void)run_blackbird_doctor(cfg);
  require(fs::is_empty(empty_auth_dir),
          "doctor must NEVER create lock or files in existing provider_auth_home!");

  // Verify secret NEVER leaks into human output or JSON output.
  const std::string human = format_doctor_report_human(report);
  const Value json_val = doctor_report_to_json(report);
  const std::string json_str = must(dump_json(json_val), "dump_json");
  require(human.find(dummy_secret) == std::string::npos,
          "SECRET LEAKED in human output!");
  require(json_str.find(dummy_secret) == std::string::npos,
          "SECRET LEAKED in JSON output!");
  require(human.find("[OK]") != std::string::npos &&
              human.find("[INFO]") != std::string::npos,
          "human table badges missing");

  // Also verify warning & hint when NO provider auth is configured.
  ScopedEnvVar e_openai_unset("OPENAI_API_KEY", std::nullopt);
  const DoctorReport no_auth_report = run_blackbird_doctor(cfg);
  require(no_auth_report.healthy, "warn without fail must still be healthy");
  const auto &no_auth = find_check(no_auth_report, "provider_auth");
  require(no_auth.status == DoctorStatus::warn, "missing provider auth must warn");
  require(no_auth.hint.has_value() &&
              no_auth.hint->find("blackbird auth login") != std::string::npos,
          "missing provider auth hint");
}

// ---------------------------------------------------------------------------
// Test 2: Online identity CWT valid vs expiring-soon vs expired + stored auth
// ---------------------------------------------------------------------------

void test_identity_cwt_states_and_stored_provider_auth() {
  g_stage = "identity_cwt_states_and_stored_provider_auth";
  TempDir tmp("bb-doctor-cwt");

  // Save a real stored provider key (with a secret that must NEVER leak).
  const fs::path auth_dir = tmp.path / "auth-store";
  const std::string stored_secret = "sk-stored-SECRET-VALUE-DO-NOT-PRINT-55555";
  {
    ProviderAuthConfig pcfg{};
    pcfg.directory = auth_dir;
    ProviderAuth pa{pcfg};
    pa.set_key("anthropic", "work", stored_secret);
  }
  // Remove lock file created by set_key so we also verify doctor doesn't recreate it!
  std::error_code ec;
  fs::remove(auth_dir / "lock", ec);

  ScopedEnvVar e_openai("OPENAI_API_KEY", std::nullopt);
  ScopedEnvVar e_anthropic("ANTHROPIC_API_KEY", std::nullopt);
  ScopedEnvVar e_openrouter("OPENROUTER_API_KEY", std::nullopt);
  ScopedEnvVar e_gemini("GEMINI_API_KEY", std::nullopt);
  ScopedEnvVar e_xai("XAI_API_KEY", std::nullopt);
  ScopedEnvVar e_moonshot("MOONSHOT_API_KEY", std::nullopt);
  ScopedEnvVar e_deepseek("DEEPSEEK_API_KEY", std::nullopt);
  ScopedEnvVar e_kimi("KIMI_API_KEY", std::nullopt);
  ScopedEnvVar e_mimo("MIMO_API_KEY", std::nullopt);
  ScopedEnvVar e_typesafe("TYPESAFE_API_KEY", std::nullopt);
  ScopedEnvVar e_clef("CLEF_API_KEY", std::nullopt);

  const auto root_seed = must(mp::CleansedSeed::generate(), "root seed");
  const auto dev_seed = must(mp::CleansedSeed::generate(), "dev seed");
  const auto root_key =
      must(mp::Ed25519SigningKey::from_seed(root_seed.bytes()), "root key");
  const auto dev_key =
      must(mp::Ed25519SigningKey::from_seed(dev_seed.bytes()), "dev key");
  const auto acct_id = must(mp::AccountId::create(4242U), "acct id");
  const auto dev_id = must(mp::DeviceId::create(777U), "dev id");
  const std::string expected_sn =
      must(mp::compute_safety_number(acct_id, root_key.public_key()), "safety number");

  const std::int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();

  // Case A: Valid CWT (> 3 days remaining)
  const fs::path valid_dir = tmp.path / "online-valid";
  {
    mp::MpIdentityState st{};
    st.root_seed = root_seed;
    st.device_seed = dev_seed;
    st.account_id = acct_id;
    st.device_id = dev_id;
    st.handle = "pilot_ok";
    st.authority = "localhost";
    st.device_cwt =
        must(mp::encode_device_cwt(
                 root_key, mp::DeviceCwtMintRequest{dev_key.public_key(), now_s - 60,
                                                    now_s + 15LL * 86400LL}),
             "mint valid cwt");
    (void)must(mp::MpIdentityStore::save(valid_dir, st), "save valid store");
  }

  DoctorConfig cfg{};
  cfg.current_version_string = "blackbird v0.1.0";
  cfg.online_state_dir = valid_dir;
  cfg.provider_auth_home = auth_dir;
  cfg.party_socket_path = tmp.path / "no-party.sock";
  cfg.offline = true;

  const DoctorReport rep_valid = run_blackbird_doctor(cfg);
  require(!fs::exists(auth_dir / "lock"), "doctor recreated lock file in auth_dir!");
  require(rep_valid.healthy, "valid CWT report must be healthy");

  const auto &id_valid = find_check(rep_valid, "online_identity");
  require(id_valid.status == DoctorStatus::ok, "valid CWT must be ok");
  require(id_valid.summary.find("@pilot_ok") != std::string::npos, "handle missing");
  require(id_valid.summary.find("4242") != std::string::npos, "account_id missing");
  require(id_valid.summary.find("777") != std::string::npos, "device_id missing");
  require(id_valid.summary.find("root_key: yes") != std::string::npos, "root_key yes");
  require(id_valid.summary.find(expected_sn) != std::string::npos,
          "canonical safety number missing");

  const auto &pa_chk = find_check(rep_valid, "provider_auth");
  require(pa_chk.status == DoctorStatus::ok, "stored provider auth must be ok");
  require(pa_chk.summary.find("anthropic (stored)") != std::string::npos,
          "must report anthropic (stored)");
  const std::string human_valid = format_doctor_report_human(rep_valid);
  const std::string json_valid =
      must(dump_json(doctor_report_to_json(rep_valid)), "dump json");
  require(human_valid.find(stored_secret) == std::string::npos,
          "stored secret leaked in human!");
  require(json_valid.find(stored_secret) == std::string::npos,
          "stored secret leaked in json!");

  // Case B: Expiring-soon CWT (1 day remaining -> warn)
  const fs::path soon_dir = tmp.path / "online-soon";
  {
    mp::MpIdentityState st{};
    st.root_seed = root_seed;
    st.device_seed = dev_seed;
    st.account_id = acct_id;
    st.device_id = dev_id;
    st.handle = "pilot_soon";
    st.authority = "localhost";
    st.device_cwt =
        must(mp::encode_device_cwt(
                 root_key, mp::DeviceCwtMintRequest{dev_key.public_key(), now_s - 60,
                                                    now_s + 86400LL}),
             "mint soon cwt");
    (void)must(mp::MpIdentityStore::save(soon_dir, st), "save soon store");
  }
  cfg.online_state_dir = soon_dir;
  const DoctorReport rep_soon = run_blackbird_doctor(cfg);
  require(rep_soon.healthy, "expiring soon (warn) must still be healthy");
  require(find_check(rep_soon, "online_identity").status == DoctorStatus::warn,
          "expiring soon CWT must be warn");

  // Case C: Expired CWT -> fail & report.healthy == false
  const fs::path exp_dir = tmp.path / "online-expired";
  {
    mp::MpIdentityState st{};
    st.root_seed = root_seed;
    st.device_seed = dev_seed;
    st.account_id = acct_id;
    st.device_id = dev_id;
    st.handle = "pilot_expired";
    st.authority = "localhost";
    st.device_cwt =
        must(mp::encode_device_cwt(root_key,
                                   mp::DeviceCwtMintRequest{dev_key.public_key(),
                                                            now_s - 7200, now_s - 60}),
             "mint expired cwt");
    (void)must(mp::MpIdentityStore::save(exp_dir, st), "save expired store");
  }
  cfg.online_state_dir = exp_dir;
  const DoctorReport rep_exp = run_blackbird_doctor(cfg);
  require(!rep_exp.healthy, "expired CWT must mark report unhealthy");
  const auto &id_exp = find_check(rep_exp, "online_identity");
  require(id_exp.status == DoctorStatus::fail, "expired CWT must be fail");
  require(id_exp.summary.find("expired") != std::string::npos,
          "expired CWT summary text");

  // Case D: Secondary linked device (root_seed absent) with valid & expired CWT
  const fs::path sec_valid_dir = tmp.path / "online-sec-valid";
  {
    mp::MpIdentityState st{};
    st.device_seed = dev_seed;
    st.account_id = acct_id;
    st.device_id = dev_id;
    st.handle = "pilot_linked";
    st.authority = "localhost";
    st.device_cwt =
        must(mp::encode_device_cwt(
                 root_key, mp::DeviceCwtMintRequest{dev_key.public_key(), now_s - 60,
                                                    now_s + 10LL * 86400LL}),
             "mint linked valid cwt");
    (void)must(mp::MpIdentityStore::save(sec_valid_dir, st), "save sec valid store");
  }
  cfg.online_state_dir = sec_valid_dir;
  const DoctorReport rep_sec_valid = run_blackbird_doctor(cfg);
  require(rep_sec_valid.healthy, "linked valid CWT must be healthy");
  const auto &id_sec = find_check(rep_sec_valid, "online_identity");
  require(id_sec.status == DoctorStatus::ok, "linked valid CWT must be ok");
  require(id_sec.summary.find("root_key: no") != std::string::npos, "root_key no");

  const fs::path sec_exp_dir = tmp.path / "online-sec-expired";
  {
    mp::MpIdentityState st{};
    st.device_seed = dev_seed;
    st.account_id = acct_id;
    st.device_id = dev_id;
    st.handle = "pilot_linked_exp";
    st.authority = "localhost";
    st.device_cwt =
        must(mp::encode_device_cwt(root_key,
                                   mp::DeviceCwtMintRequest{dev_key.public_key(),
                                                            now_s - 7200, now_s - 10}),
             "mint linked expired cwt");
    (void)must(mp::MpIdentityStore::save(sec_exp_dir, st), "save sec exp store");
  }
  cfg.online_state_dir = sec_exp_dir;
  const DoctorReport rep_sec_exp = run_blackbird_doctor(cfg);
  require(!rep_sec_exp.healthy, "linked expired CWT must be unhealthy");
  require(find_check(rep_sec_exp, "online_identity").status == DoctorStatus::fail,
          "linked expired CWT must be fail");

  // Case E: Crafted secondary-device CWT with iat = -1, exp = INT64_MAX (must reject
  // cleanly without signed int64 subtraction overflow under UBSan!)
  const fs::path sec_ovf_dir = tmp.path / "online-sec-overflow";
  {
    std::vector<std::uint8_t> payload;
    payload.push_back(0xa4U); // 4-entry CBOR map
    // 1 (iss): 64-char tstr
    payload.push_back(0x01U);
    payload.push_back(0x78U);
    payload.push_back(64U);
    for (int i = 0; i < 64; ++i) {
      payload.push_back(static_cast<std::uint8_t>('a'));
    }
    // 4 (exp): INT64_MAX (0x7fffffffffffffff)
    payload.push_back(0x04U);
    payload.push_back(0x1bU);
    payload.push_back(0x7fU);
    for (int i = 0; i < 7; ++i) {
      payload.push_back(0xffU);
    }
    // 6 (iat): -1 (CBOR major 1, arg 0 -> 0x20)
    payload.push_back(0x06U);
    payload.push_back(0x20U);
    // 8 (cnf): { 1: { 1: 1, 3: -19, -1: 6, -2: bstr(32) } }
    payload.push_back(0x08U);
    payload.push_back(0xa1U);
    payload.push_back(0x01U);
    payload.push_back(0xa4U);
    payload.push_back(0x01U);
    payload.push_back(0x01U);
    payload.push_back(0x03U);
    payload.push_back(0x32U);
    payload.push_back(0x20U);
    payload.push_back(0x06U);
    payload.push_back(0x21U);
    payload.push_back(0x58U);
    payload.push_back(32U);
    const auto &dev_pk = dev_key.public_key();
    payload.insert(payload.end(), dev_pk.begin(), dev_pk.end());

    // Wrap in Tag 18 COSE_Sign1 canonical envelope
    std::vector<std::uint8_t> crafted = {0xd2U, 0x84U, 0x43U, 0xa1U,
                                         0x01U, 0x32U, 0xa0U};
    crafted.push_back(0x58U);
    crafted.push_back(static_cast<std::uint8_t>(payload.size()));
    crafted.insert(crafted.end(), payload.begin(), payload.end());
    crafted.push_back(0x58U);
    crafted.push_back(64U);
    crafted.insert(crafted.end(), 64U, 0x42U);

    mp::MpIdentityState st{};
    st.device_seed = dev_seed;
    st.account_id = acct_id;
    st.device_id = dev_id;
    st.handle = "pilot_ovf";
    st.authority = "localhost";
    st.device_cwt = std::move(crafted);
    (void)must(mp::MpIdentityStore::save(sec_ovf_dir, st), "save sec ovf store");
  }
  cfg.online_state_dir = sec_ovf_dir;
  const DoctorReport rep_sec_ovf = run_blackbird_doctor(cfg);
  require(!rep_sec_ovf.healthy, "overflow CWT must be unhealthy");
  const auto &id_ovf = find_check(rep_sec_ovf, "online_identity");
  require(id_ovf.status == DoctorStatus::fail, "overflow CWT must fail");
  require(id_ovf.summary.find("corrupt") != std::string::npos,
          "overflow CWT must report corrupt");
}

// ---------------------------------------------------------------------------
// Test 3: Online loopback (TLS 1.3 /v1/health + /ping, file:// upgrade, live
// PartyLobby)
// ---------------------------------------------------------------------------

void test_online_loopback_end_to_end() {
  g_stage = "online_loopback_end_to_end";
  TempDir tmp("bb-doctor-online");

  const auto target = must(detect_upgrade_target(), "detect_upgrade_target");
  const fs::path mirror_dir = tmp.path / "mirror";
  const std::string upgrade_url =
      build_upgrade_mirror(mirror_dir, target.triplet, "v9.9.9", "cafebabe1234");

  const EphemeralCert cert =
      generate_self_signed_cert(tmp.path / "ca.pem", "localhost");
  MockTlsServerConfig server_cfg{};
  server_cfg.health_skew_ms.store(250);
  server_cfg.relay_status.store(204);
  MockTlsServer tls_server{cert, server_cfg};

  const fs::path lobby_sock = tmp.path / "lobby" / "party.sock";
  PartyLobbyServerConfig lobby_cfg{};
  lobby_cfg.socket_path = lobby_sock;
  auto lobby = must(PartyLobbyServer::start(lobby_cfg), "start PartyLobbyServer");
  require(lobby->running(), "PartyLobbyServer not running");

  ScopedEnvVar e_openai("OPENAI_API_KEY", "sk-loopback-never-leak-xyz");

  DoctorConfig cfg{};
  cfg.current_version_string = "blackbird v0.1.0 (test)";
  cfg.install_prefix = tmp.path / "prefix";
  cfg.online_state_dir = tmp.path / "online-absent";
  cfg.provider_auth_home = tmp.path / "auth-absent";
  cfg.party_socket_path = lobby_sock;
  cfg.mp_client_config.authority = "localhost";
  cfg.mp_client_config.connect_host = "127.0.0.1";
  cfg.mp_client_config.port = tls_server.port();
  cfg.mp_client_config.ca_bundle_path = cert.pem_path;
  cfg.relay_url = "https://localhost";
  cfg.relay_connect_host = "127.0.0.1";
  cfg.relay_port = tls_server.port();
  cfg.relay_ca_bundle_path = cert.pem_path;
  cfg.upgrade_base_url = upgrade_url;
  cfg.offline = false;
  cfg.check_update = true;

  const DoctorReport report = run_blackbird_doctor(cfg);
  require(report.healthy, "loopback online report must be healthy");
  require(server_cfg.health_hits.load() >= 1, "mock /v1/health not hit");
  require(server_cfg.ping_hits.load() >= 1, "mock /ping not hit");

  const auto &upg = find_check(report, "upgrade");
  require(upg.status == DoctorStatus::info, "update available must be info");
  require(upg.summary.find("v9.9.9") != std::string::npos, "latest version missing");
  require(upg.hint.has_value() && *upg.hint == "Run: blackbird upgrade",
          "upgrade hint mismatch");

  const auto &cp = find_check(report, "control_plane");
  require(cp.status == DoctorStatus::ok, "control_plane must be ok");
  require(cp.rtt_ms.has_value(), "control_plane rtt_ms missing");
  require(cp.clock_skew_ms.has_value() && *cp.clock_skew_ms > -5000 &&
              *cp.clock_skew_ms < 5000,
          "clock skew out of expected loopback range");

  const auto &rel = find_check(report, "relay");
  require(rel.status == DoctorStatus::ok, "relay HTTP 204 must be ok");
  require(rel.rtt_ms.has_value(), "relay rtt_ms missing");

  const auto &pl = find_check(report, "party_lobby");
  require(pl.status == DoctorStatus::ok, "live party_lobby must be ok");
  require(pl.summary.find("running (pid ") != std::string::npos &&
              pl.summary.find("0 rooms)") != std::string::npos,
          "party_lobby running summary mismatch");

  // Verify JSON round-trip via dump_json -> parse_json!
  const Value json_val = doctor_report_to_json(report);
  const std::string json_text = must(dump_json(json_val), "dump_json");
  const Value parsed = must(parse_json(json_text), "parse_json");
  require(parsed == json_val, "doctor JSON round-trip mismatch");
  require(json_text.find("sk-loopback-never-leak-xyz") == std::string::npos,
          "secret leaked in online JSON!");

  // Verify large clock skew (> 30s) produces warn on control_plane!
  server_cfg.health_skew_ms.store(45000);
  server_cfg.relay_status.store(503);
  const DoctorReport skewed = run_blackbird_doctor(cfg);
  require(skewed.healthy, "warn checks still keep healthy == true");
  const auto &cp_skew = find_check(skewed, "control_plane");
  require(cp_skew.status == DoctorStatus::warn, "skew > 30s must warn");
  require(cp_skew.clock_skew_ms.has_value() && *cp_skew.clock_skew_ms > 30000,
          "skew value mismatch");
  const auto &rel_503 = find_check(skewed, "relay");
  require(rel_503.status == DoctorStatus::warn, "relay 503 must warn");

  // Verify ANSI/control sanitization in human formatter on malicious report inputs.
  DoctorReport dirty{};
  dirty.healthy = true;
  dirty.target = "darwin-arm64\x1b[31m";
  dirty.version = "v0.1.0\x1b]0;pwned\x07";
  DoctorCheck dchk{};
  dchk.id = "binary";
  dchk.label = "Bin\x1b[2Jary";
  dchk.status = DoctorStatus::ok;
  dchk.summary = "ok\r\n\x1b[32mclean\xe2\x80\xae";
  dchk.hint = "Run:\x1b[1m fix\x07";
  dirty.checks.push_back(std::move(dchk));
  const std::string clean_human = format_doctor_report_human(dirty);
  require(clean_human.find('\x1b') == std::string::npos, "ESC leaked in human output");
  require(clean_human.find('\x07') == std::string::npos, "BEL leaked in human output");
  require(clean_human.find("\xe2\x80\xae") == std::string::npos,
          "BiDi RLO leaked in human output");

  lobby->stop();
}

} // namespace

int main() {
  try {
    test_offline_zero_disk_and_zero_secret_leak();
    test_identity_cwt_states_and_stored_provider_auth();
    test_online_loopback_end_to_end();
    std::cout << "doctor_test: all tests passed\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "doctor_test FAILED: " << ex.what() << "\n";
    return 1;
  }
}
