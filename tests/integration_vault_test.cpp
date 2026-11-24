#include "blackbird/integration_vault.hpp"

#include "blackbird/json.hpp"
#include "blackbird/packet.hpp"

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
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <source_location>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

using namespace blackbird;

void require_ok(bool ok, std::source_location loc = std::source_location::current()) {
  if (!ok) {
    std::cerr << "integration_vault_test FAIL at " << loc.file_name() << ":"
              << loc.line() << "\n";
    std::abort();
  }
}

struct TempDir {
  std::filesystem::path path;
  explicit TempDir(std::string_view tag) {
    static std::atomic<std::uint64_t> counter{0U};
    const auto id = counter.fetch_add(1U, std::memory_order_relaxed);
    path = std::filesystem::temp_directory_path() /
           ("bb_vault_test_" + std::string{tag} + "_" +
            std::to_string(static_cast<std::uint64_t>(::getpid())) + "_" +
            std::to_string(id));
    std::filesystem::create_directories(path);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

struct EphemeralCert {
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{nullptr, &EVP_PKEY_free};
  std::unique_ptr<X509, decltype(&X509_free)> cert{nullptr, &X509_free};
  std::filesystem::path pem_path;
};

EphemeralCert generate_cert(const std::filesystem::path &out_pem, const char *san_ext) {
  EphemeralCert out;
  out.pem_path = out_pem;

  EVP_PKEY *raw_key = EVP_EC_gen("P-256");
  require_ok(raw_key != nullptr);
  out.key.reset(raw_key);

  X509 *raw_cert = X509_new();
  require_ok(raw_cert != nullptr);
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
                 reinterpret_cast<const unsigned char *>("mcp.blackbird.test"), -1, -1,
                 0) == 1);
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
  add_ext(NID_subject_alt_name, san_ext);

  require_ok(X509_sign(raw_cert, raw_key, EVP_sha256()) != 0);

  FILE *fp = std::fopen(out_pem.c_str(), "wb");
  require_ok(fp != nullptr);
  require_ok(PEM_write_X509(fp, raw_cert) == 1);
  require_ok(std::fclose(fp) == 0);
  return out;
}

struct RawRequest {
  std::string method;
  std::string target;
  std::map<std::string, std::string> headers;
  std::string body;
};

std::string lower_ascii(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (const char c : s) {
    out.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c);
  }
  return out;
}

void ssl_write_str(SSL *ssl, std::string_view data) {
  std::size_t off = 0U;
  while (off < data.size()) {
    const int n =
        SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
    if (n <= 0) {
      break;
    }
    off += static_cast<std::size_t>(n);
  }
}

std::optional<RawRequest> read_tls_request(SSL *ssl) {
  std::string raw;
  std::array<char, 2048> buf{};
  std::size_t header_end = std::string::npos;
  while (header_end == std::string::npos && raw.size() < 65536U) {
    const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
    if (n <= 0) {
      return std::nullopt;
    }
    raw.append(buf.data(), static_cast<std::size_t>(n));
    header_end = raw.find("\r\n\r\n");
  }
  if (header_end == std::string::npos) {
    return std::nullopt;
  }

  RawRequest req{};
  const std::string_view block{raw.data(), header_end};
  const std::size_t first_eol = block.find("\r\n");
  const std::string_view line0 =
      (first_eol == std::string_view::npos) ? block : block.substr(0U, first_eol);
  const std::size_t sp1 = line0.find(' ');
  const std::size_t sp2 = (sp1 == std::string_view::npos) ? std::string_view::npos
                                                          : line0.find(' ', sp1 + 1U);
  if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
    return std::nullopt;
  }
  req.method = std::string{line0.substr(0U, sp1)};
  req.target = std::string{line0.substr(sp1 + 1U, sp2 - sp1 - 1U)};

  std::size_t cl = 0U;
  if (first_eol != std::string_view::npos) {
    std::size_t pos = first_eol + 2U;
    while (pos < block.size()) {
      const std::size_t eol = block.find("\r\n", pos);
      const std::string_view line = (eol == std::string_view::npos)
                                        ? block.substr(pos)
                                        : block.substr(pos, eol - pos);
      const std::size_t colon = line.find(':');
      if (colon != std::string_view::npos) {
        const std::string k = lower_ascii(line.substr(0U, colon));
        std::string_view v = line.substr(colon + 1U);
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) {
          v.remove_prefix(1U);
        }
        req.headers[k] = std::string{v};
        if (k == "content-length") {
          cl = static_cast<std::size_t>(
              std::strtoull(req.headers[k].c_str(), nullptr, 10));
        }
      }
      if (eol == std::string_view::npos) {
        break;
      }
      pos = eol + 2U;
    }
  }
  req.body = raw.substr(header_end + 4U);
  while (req.body.size() < cl) {
    const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
    if (n <= 0) {
      break;
    }
    req.body.append(buf.data(), static_cast<std::size_t>(n));
  }
  if (req.body.size() > cl) {
    req.body.resize(cl);
  }
  return req;
}

class MockTlsServer {
public:
  using Handler = std::function<void(SSL *, const RawRequest &)>;

  MockTlsServer(const EphemeralCert &cert, Handler handler)
      : handler_(std::move(handler)) {
    ctx_.reset(SSL_CTX_new(TLS_server_method()));
    require_ok(ctx_ != nullptr);
    require_ok(SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_2_VERSION) == 1);
    require_ok(SSL_CTX_use_certificate(ctx_.get(), cert.cert.get()) == 1);
    require_ok(SSL_CTX_use_PrivateKey(ctx_.get(), cert.key.get()) == 1);

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    require_ok(listen_fd_ >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0U;
    require_ok(::bind(listen_fd_, reinterpret_cast<const sockaddr *>(&addr),
                      sizeof(addr)) == 0);
    require_ok(::listen(listen_fd_, 16) == 0);
    socklen_t len = sizeof(addr);
    require_ok(::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len) ==
               0);
    port_ = ntohs(addr.sin_port);
    thread_ = std::thread([this]() { run(); });
  }

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
  }

  std::uint16_t port() const noexcept { return port_; }

private:
  void run() {
    while (!stop_.load(std::memory_order_relaxed)) {
      pollfd pfd{listen_fd_, POLLIN, 0};
      if (::poll(&pfd, 1U, 50) <= 0) {
        continue;
      }
      const int cfd = ::accept(listen_fd_, nullptr, nullptr);
      if (cfd < 0) {
        continue;
      }
#ifdef SO_NOSIGPIPE
      const int one = 1;
      (void)::setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
      std::unique_ptr<SSL, decltype(&SSL_free)> ssl{SSL_new(ctx_.get()), &SSL_free};
      if (ssl && SSL_set_fd(ssl.get(), cfd) == 1 && SSL_accept(ssl.get()) == 1) {
        if (const auto req = read_tls_request(ssl.get()); req.has_value()) {
          handler_(ssl.get(), *req);
        }
        (void)SSL_shutdown(ssl.get());
      }
      ::close(cfd);
    }
  }

  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx_{nullptr, &SSL_CTX_free};
  Handler handler_;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0U;
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

std::string send_plain_loopback_http(std::uint16_t port, std::string_view raw_req) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  require_ok(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);
  require_ok(::connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) ==
             0);
  require_ok(::send(fd, raw_req.data(), raw_req.size(), 0) ==
             static_cast<ssize_t>(raw_req.size()));
  std::string out;
  std::array<char, 1024> buf{};
  for (;;) {
    const ssize_t n = ::read(fd, buf.data(), buf.size());
    if (n <= 0) {
      break;
    }
    out.append(buf.data(), static_cast<std::size_t>(n));
  }
  ::close(fd);
  return out;
}

std::map<std::string, std::string> parse_form_body(std::string_view body) {
  std::map<std::string, std::string> out;
  auto url_dec = [](std::string_view s) {
    std::string r;
    for (std::size_t i = 0U; i < s.size(); ++i) {
      if (s[i] == '+') {
        r.push_back(' ');
      } else if (s[i] == '%' && i + 2U < s.size()) {
        const std::string hx{s.substr(i + 1U, 2U)};
        r.push_back(static_cast<char>(std::strtol(hx.c_str(), nullptr, 16)));
        i += 2U;
      } else {
        r.push_back(s[i]);
      }
    }
    return r;
  };
  while (!body.empty()) {
    const std::size_t amp = body.find('&');
    const std::string_view part =
        (amp == std::string_view::npos) ? body : body.substr(0U, amp);
    if (const std::size_t eq = part.find('='); eq != std::string_view::npos) {
      out[url_dec(part.substr(0U, eq))] = url_dec(part.substr(eq + 1U));
    }
    if (amp == std::string_view::npos) {
      break;
    }
    body.remove_prefix(amp + 1U);
  }
  return out;
}

void test_pkce_and_state() {
  // Exact RFC 7636 Appendix B test vector.
  const auto challenge =
      compute_pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
  require_ok(challenge.has_value());
  require_ok(challenge.value() == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");

  const auto pair = generate_pkce_s256();
  require_ok(pair.has_value());
  require_ok(pair.value().code_verifier.size() == 43U);
  require_ok(pair.value().code_challenge.size() == 43U);
  require_ok(pair.value().method == "S256");
  const auto recomputed =
      compute_pkce_s256_challenge(pair.value().code_verifier.view());
  require_ok(recomputed.has_value() &&
             recomputed.value() == pair.value().code_challenge);

  const auto s1 = generate_oauth_state();
  const auto s2 = generate_oauth_state();
  require_ok(s1.has_value() && s2.has_value());
  require_ok(s1.value().size() == 43U && s1.value() != s2.value());
}

void test_binary_store_perms_and_corrupt_rejection() {
  const TempDir dir{"store"};
  const auto vault_dir = dir.path / "auth";
  std::int64_t fake_clock = 1'700'000'000;
  IntegrationVault vault{{.directory = vault_dir, .now = [&]() { return fake_clock; }}};

  CredentialSaveInput in1{};
  in1.service = "linear";
  in1.account = "work";
  in1.scheme = AuthScheme::bearer_oauth2;
  in1.access_token.assign("lin_secret_access_1");
  in1.refresh_token.assign("lin_secret_refresh_1");
  in1.allowed_hosts = {"api.linear.app", "mcp.linear.app"};
  in1.scopes = {"read", "write"};
  in1.resource_uri = "https://mcp.linear.app/mcp";
  in1.expires_at = fake_clock + 3600;
  in1.extra_metadata = {{"workspace", "acme"}};

  const auto saved1 = vault.save(in1);
  require_ok(saved1.has_value());
  require_ok(saved1.value().id == CredentialId{1U});
  require_ok(saved1.value().service == "linear");
  require_ok(saved1.value().account == "work");
  require_ok(saved1.value().has_refresh_token);
  require_ok(saved1.value().active);
  require_ok(!saved1.value().expired);
  require_ok(saved1.value().revision == 1U);

  // Verify 0700 directory and 0600 binary packet file permissions.
  struct stat dir_st{};
  require_ok(::stat(vault_dir.c_str(), &dir_st) == 0);
  require_ok((dir_st.st_mode & 0777) == 0700);

  const auto store_file = vault.store_path();
  struct stat file_st{};
  require_ok(::stat(store_file.c_str(), &file_st) == 0);
  require_ok((file_st.st_mode & 0777) == 0600);

  // Verify binary packet encoding (NOT JSON on disk!).
  {
    std::ifstream ifs(store_file, std::ios::binary);
    const std::string raw((std::istreambuf_iterator<char>(ifs)),
                          std::istreambuf_iterator<char>());
    require_ok(!raw.empty());
    require_ok(raw.front() != '{');
    require_ok(!parse_json(raw).has_value());
  }

  // Save a second account and verify integer ID monotonicity & reopen roundtrip.
  CredentialSaveInput in2{};
  in2.service = "linear";
  in2.account = "personal";
  in2.scheme = AuthScheme::bearer_pat;
  in2.access_token.assign("lin_pat_personal");
  in2.allowed_hosts = {"api.linear.app"};
  in2.set_active = false;
  const auto saved2 = vault.save(in2);
  require_ok(saved2.has_value());
  require_ok(saved2.value().id == CredentialId{2U});
  require_ok(!saved2.value().active);

  // Fresh IntegrationVault instance reads back from binary integrations.bbm.
  IntegrationVault reopened{
      {.directory = vault_dir, .now = [&]() { return fake_clock; }}};
  const auto listed = reopened.list();
  require_ok(listed.has_value() && listed.value().size() == 2U);
  const auto active_rec = reopened.find({.service = "linear", .account = ""});
  require_ok(active_rec.has_value() && active_rec.value().id == CredentialId{1U});

  // Switch active by integer CredentialId.
  require_ok(reopened.set_active(CredentialId{2U}).has_value());
  const auto active_after = reopened.find({.service = "linear", .account = ""});
  require_ok(active_after.has_value() && active_after.value().id == CredentialId{2U});

  // Reject insecure 0644 permissions.
  require_ok(::chmod(store_file.c_str(), 0644) == 0);
  const auto bad_perm = reopened.list();
  require_ok(!bad_perm.has_value());
  require_ok(vault_error_of(bad_perm.error()) == VaultError::insecure_permissions);
  require_ok(::chmod(store_file.c_str(), 0600) == 0);

  // Reject corrupt/truncated store file.
  {
    std::ofstream ofs(store_file, std::ios::binary | std::ios::trunc);
    ofs << "not-a-valid-bbm-packet";
  }
  const auto corrupt = reopened.list();
  require_ok(!corrupt.has_value());
  require_ok(vault_error_of(corrupt.error()) == VaultError::corrupt_store);

  // Reject symlinked store file.
  const auto decoy = dir.path / "decoy.bbm";
  {
    std::ofstream ofs(decoy, std::ios::binary);
    ofs << "decoy";
  }
  std::filesystem::remove(store_file);
  std::filesystem::create_symlink(decoy, store_file);
  const auto sym = reopened.list();
  require_ok(!sym.has_value());
  require_ok(vault_error_of(sym.error()) == VaultError::symlink_rejected);
}

void test_host_pinned_secret_injection() {
  const TempDir dir{"inject"};
  IntegrationVault vault{{.directory = dir.path / "auth"}};

  CredentialSaveInput linear{};
  linear.service = "linear";
  linear.account = "default";
  linear.scheme = AuthScheme::bearer_pat;
  linear.access_token.assign("lin_api_secret_xyz");
  linear.allowed_hosts = {"api.linear.app"};
  require_ok(vault.save(linear).has_value());

  CredentialSaveInput discord{};
  discord.service = "discord";
  discord.account = "bot";
  discord.scheme = AuthScheme::discord_bot;
  discord.access_token.assign("disc_bot_tok_123");
  discord.allowed_hosts = {"discord.com"};
  require_ok(vault.save(discord).has_value());

  CredentialSaveInput notion{};
  notion.service = "notion";
  notion.account = "team";
  notion.scheme = AuthScheme::header_key;
  notion.auth_header_name = "X-Api-Key";
  notion.access_token.assign("ntn_key_999");
  notion.allowed_hosts = {"*.notion.com"};
  require_ok(vault.save(notion).has_value());

  // 1. Pinned HTTPS host succeeds and injects Authorization: Bearer.
  {
    net::HttpRequest req{};
    req.url = "https://api.linear.app/graphql";
    const auto auth = vault.authorize_request({"linear", "default"}, req);
    require_ok(auth.has_value());
    const auto hdr = req.find_header("Authorization");
    require_ok(hdr.has_value() && *hdr == "Bearer lin_api_secret_xyz");
  }

  // 2. Evil host refused AND headers remain untouched!
  {
    net::HttpRequest req{};
    req.url = "https://evil.example/graphql";
    const auto auth = vault.authorize_request({"linear", "default"}, req);
    require_ok(!auth.has_value());
    require_ok(vault_error_of(auth.error()) == VaultError::host_not_pinned);
    require_ok(!req.find_header("Authorization").has_value());
  }

  // 3. Suffix-spoofed host refused.
  {
    net::HttpRequest req{};
    req.url = "https://api.linear.app.evil.com/graphql";
    const auto auth = vault.authorize_request({"linear", "default"}, req);
    require_ok(!auth.has_value());
    require_ok(vault_error_of(auth.error()) == VaultError::host_not_pinned);
    require_ok(!req.find_header("Authorization").has_value());
  }

  // 4. Plaintext HTTP downgrade refused AND headers remain untouched!
  {
    net::HttpRequest req{};
    req.url = "http://api.linear.app/graphql";
    const auto auth = vault.authorize_request({"linear", "default"}, req);
    require_ok(!auth.has_value());
    require_ok(vault_error_of(auth.error()) == VaultError::https_required);
    require_ok(!req.find_header("Authorization").has_value());
  }

  // 5. Discord Bot prefix and custom header key with wildcard pin.
  {
    net::HttpRequest req{};
    req.url = "https://discord.com/api/v10/users/@me";
    require_ok(vault.authorize_request({"discord", ""}, req).has_value());
    require_ok(req.find_header("Authorization") ==
               std::optional<std::string_view>{"Bot disc_bot_tok_123"});
  }
  {
    net::HttpRequest req{};
    req.url = "https://api.notion.com/v1/search";
    require_ok(vault.authorize_request({"notion", ""}, req).has_value());
    require_ok(req.find_header("X-Api-Key") ==
               std::optional<std::string_view>{"ntn_key_999"});

    net::HttpRequest bare{};
    bare.url = "https://notion.com/v1/search";
    const auto bad = vault.authorize_request({"notion", ""}, bare);
    require_ok(!bad.has_value());
    require_ok(vault_error_of(bad.error()) == VaultError::host_not_pinned);
  }

  // 6. Reject CRLF / oversized auth_header_prefix on save() and tampered store decode.
  {
    CredentialSaveInput bad_prefix{};
    bad_prefix.service = "evilhdr";
    bad_prefix.account = "a";
    bad_prefix.scheme = AuthScheme::header_key;
    bad_prefix.auth_header_name = "X-Auth";
    bad_prefix.auth_header_prefix = "Tok \r\nX-Injected: 1";
    bad_prefix.access_token.assign("secret_val");
    bad_prefix.allowed_hosts = {"api.linear.app"};
    const auto res = vault.save(bad_prefix);
    require_ok(!res.has_value());
    require_ok(vault_error_of(res.error()) == VaultError::invalid_argument);

    bad_prefix.auth_header_prefix = std::string(65U, 'A');
    const auto too_long = vault.save(bad_prefix);
    require_ok(!too_long.has_value());
    require_ok(vault_error_of(too_long.error()) == VaultError::invalid_argument);

    bad_prefix.auth_header_prefix = "Bearer ";
    bad_prefix.allowed_hosts = {"..linear.app"};
    const auto bad_pin = vault.save(bad_prefix);
    require_ok(!bad_pin.has_value());
    require_ok(vault_error_of(bad_pin.error()) == VaultError::invalid_argument);
  }
  {
    // Tampered BBM binary packet with CRLF inside auth_header_prefix must fail closed.
    const TempDir tamper_dir{"tamper_hdr"};
    const auto auth_dir = tamper_dir.path / "auth";
    IntegrationVault tvault{{.directory = auth_dir}};
    CredentialSaveInput seed{};
    seed.service = "svc";
    seed.account = "acct";
    seed.scheme = AuthScheme::bearer_pat;
    seed.access_token.assign("tok123");
    seed.allowed_hosts = {"api.example.com"};
    require_ok(tvault.save(seed).has_value());

    const Value bad_root = Value::object({
        {"magic", Value{"bb.integrations.v1"}},
        {"version", Value{Number{1}}},
        {"next_id", Value{Number{2U}}},
        {"records",
         Value{Value::Array{Value::object({
             {"id", Value{Number{1U}}},
             {"service", Value{"svc"}},
             {"account", Value{"acct"}},
             {"scheme", Value{"bearer_pat"}},
             {"auth_header_name", Value{"Authorization"}},
             {"auth_header_prefix", Value{"Bearer \r\nX-Smuggled: 1"}},
             {"access_token", Value{"tok123"}},
             {"refresh_token", Value{""}},
             {"client_secret", Value{""}},
             {"allowed_hosts", Value{Value::Array{Value{"api.example.com"}}}},
             {"scopes", Value{Value::Array{}}},
             {"resource_uri", Value{""}},
             {"authorization_server", Value{""}},
             {"token_endpoint", Value{""}},
             {"client_id", Value{""}},
             {"expires_at", Value{Number{0}}},
             {"updated_at", Value{Number{0}}},
             {"revision", Value{Number{1U}}},
             {"extra_metadata", Value{Value::Array{}}},
         })}}},
        {"active_ids", Value{Value::Array{}}},
    });
    const auto pkt = encode_packet_string(bad_root);
    require_ok(pkt.has_value());
    {
      std::ofstream ofs(tvault.store_path(), std::ios::binary | std::ios::trunc);
      ofs.write(pkt.value().data(), static_cast<std::streamsize>(pkt.value().size()));
    }
    const auto tampered = tvault.list();
    require_ok(!tampered.has_value());
    require_ok(vault_error_of(tampered.error()) == VaultError::corrupt_store);
  }
}

void test_rfc9728_and_rfc8414_parsing() {
  const auto ch = parse_www_authenticate_bearer(
      "Basic realm=\"legacy\", Bearer "
      "resource_metadata=\"https://mcp.linear.app/.well-known/"
      "oauth-protected-resource\", "
      "scope=\"read write\", error=\"insufficient_scope\"");
  require_ok(ch.has_value());
  require_ok(ch.value().scheme == "Bearer");
  require_ok(ch.value().resource_metadata ==
             "https://mcp.linear.app/.well-known/oauth-protected-resource");
  require_ok(ch.value().scope == "read write");
  require_ok(ch.value().error == "insufficient_scope");

  const auto as_url1 = build_as_metadata_url("https://auth.example.com");
  require_ok(as_url1.has_value() &&
             as_url1.value() ==
                 "https://auth.example.com/.well-known/oauth-authorization-server");
  const auto as_url2 = build_as_metadata_url("https://auth.example.com/tenant/a/");
  require_ok(
      as_url2.has_value() &&
      as_url2.value() ==
          "https://auth.example.com/.well-known/oauth-authorization-server/tenant/a");

  // Reject AS metadata missing PKCE S256.
  const auto no_s256 = parse_authorization_server_metadata(
      R"({"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/authorize","token_endpoint":"https://auth.example.com/token","code_challenge_methods_supported":["plain"]})");
  require_ok(!no_s256.has_value());
  require_ok(vault_error_of(no_s256.error()) == VaultError::oauth_pkce_unsupported);

  // Reject AS metadata with http:// token endpoint.
  const auto http_ep = parse_authorization_server_metadata(
      R"({"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/authorize","token_endpoint":"http://auth.example.com/token","code_challenge_methods_supported":["S256"]})");
  require_ok(!http_ep.has_value());
  require_ok(vault_error_of(http_ep.error()) == VaultError::https_required);
}

void test_loopback_callback_listener() {
  // 1. Rejects bad state with HTTP 400, then accepts good state with HTTP 200.
  {
    auto listener_res = OAuthLoopbackListener::bind();
    require_ok(listener_res.has_value());
    OAuthLoopbackListener listener = std::move(listener_res).value();
    const std::uint16_t port = listener.port();
    require_ok(port != 0U);
    require_ok(listener.redirect_uri() ==
               "http://127.0.0.1:" + std::to_string(port) + "/auth/callback");

    std::string resp_bad;
    std::string resp_good;
    std::thread browser([&]() {
      resp_bad =
          send_plain_loopback_http(port, "GET /auth/callback?code=evil&state=wrong "
                                         "HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
      resp_good = send_plain_loopback_http(
          port, "GET /auth/callback?code=good-code-123&state=expected-state "
                "HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    });

    const auto cb =
        listener.wait({.expected_state = "expected-state", .timeout_ms = 5000});
    browser.join();
    require_ok(cb.has_value());
    require_ok(cb.value().code == "good-code-123");
    require_ok(cb.value().state == "expected-state");
    require_ok(listener.rejected_count() == 1U);
    require_ok(resp_bad.find("400 Bad Request") != std::string::npos);
    require_ok(resp_good.find("200 OK") != std::string::npos);
  }

  // 2. Clean timeout.
  {
    auto listener = OAuthLoopbackListener::bind();
    require_ok(listener.has_value());
    const auto cb =
        listener.value().wait({.expected_state = "never", .timeout_ms = 80});
    require_ok(!cb.has_value());
    require_ok(vault_error_of(cb.error()) == VaultError::oauth_callback_timeout);
  }

  // 3. Clean cancel.
  {
    auto listener = OAuthLoopbackListener::bind();
    require_ok(listener.has_value());
    std::atomic<bool> cancel{false};
    std::thread stopper([&]() {
      std::this_thread::sleep_for(std::chrono::milliseconds{30});
      cancel.store(true, std::memory_order_relaxed);
    });
    const auto cb = listener.value().wait({
        .expected_state = "cancel-me",
        .timeout_ms = 5000,
        .cancelled = [&]() { return cancel.load(std::memory_order_relaxed); },
    });
    stopper.join();
    require_ok(!cb.has_value());
    require_ok(vault_error_of(cb.error()) == VaultError::cancelled);
  }
}

void test_end_to_end_oauth21_mcp_and_single_flight_refresh() {
  const TempDir dir{"e2e"};
  const auto cert =
      generate_cert(dir.path / "oauth_server.pem",
                    "DNS:mcp.blackbird.test,DNS:auth.blackbird.test,IP:127.0.0.1");

  std::mutex srv_mu;
  std::string expected_pkce_challenge;
  std::string registered_client_id;
  std::atomic<int> refresh_calls{0};
  std::string active_access_token = "at-initial-001";
  std::string active_refresh_token = "rt-initial-001";

  MockTlsServer server{
      cert, [&](SSL *ssl, const RawRequest &req) {
        auto send_json = [&](int status, std::string_view status_text,
                             std::string_view json_body,
                             std::string_view extra_hdrs = "") {
          std::string out =
              "HTTP/1.1 " + std::to_string(status) + " " + std::string{status_text} +
              "\r\nContent-Type: application/json\r\n" + std::string{extra_hdrs} +
              "Content-Length: " + std::to_string(json_body.size()) +
              "\r\nConnection: close\r\n\r\n" + std::string{json_body};
          ssl_write_str(ssl, out);
        };

        if (req.target == "/mcp") {
          std::lock_guard<std::mutex> lock{srv_mu};
          const auto it = req.headers.find("authorization");
          if (it == req.headers.end() ||
              it->second != ("Bearer " + active_access_token)) {
            send_json(401, "Unauthorized", R"({"error":"unauthorized"})",
                      "WWW-Authenticate: Bearer "
                      "resource_metadata=\"https://mcp.blackbird.test/.well-known/"
                      "oauth-protected-resource\", scope=\"mcp:tools\"\r\n");
            return;
          }
          send_json(200, "OK", R"({"ok":true,"tool_count":7})");
          return;
        }

        if (req.target == "/.well-known/oauth-protected-resource") {
          send_json(
              200, "OK",
              R"({"resource":"https://mcp.blackbird.test/mcp","authorization_servers":["https://auth.blackbird.test"],"scopes_supported":["mcp:tools","mcp:read"],"bearer_methods_supported":["header"]})");
          return;
        }

        if (req.target == "/.well-known/oauth-authorization-server") {
          send_json(
              200, "OK",
              R"({"issuer":"https://auth.blackbird.test","authorization_endpoint":"https://auth.blackbird.test/authorize","token_endpoint":"https://auth.blackbird.test/token","registration_endpoint":"https://auth.blackbird.test/register","code_challenge_methods_supported":["S256"],"grant_types_supported":["authorization_code","refresh_token"],"client_id_metadata_document_supported":true})");
          return;
        }

        if (req.target == "/register" && req.method == "POST") {
          const auto body = parse_json(req.body);
          require_ok(body.has_value());
          std::lock_guard<std::mutex> lock{srv_mu};
          registered_client_id = "dcr-client-98765";
          send_json(
              201, "Created",
              R"({"client_id":"dcr-client-98765","token_endpoint_auth_method":"none"})");
          return;
        }

        if (req.target == "/token" && req.method == "POST") {
          const auto form = parse_form_body(req.body);
          const auto gt = form.find("grant_type");
          if (gt == form.end()) {
            send_json(400, "Bad Request", R"({"error":"invalid_request"})");
            return;
          }
          if (gt->second == "authorization_code") {
            std::lock_guard<std::mutex> lock{srv_mu};
            const auto ver = form.find("code_verifier");
            const auto res = form.find("resource");
            const auto cid = form.find("client_id");
            const auto code = form.find("code");
            require_ok(ver != form.end() && res != form.end() && cid != form.end() &&
                       code != form.end());
            require_ok(cid->second == registered_client_id);
            require_ok(res->second == "https://mcp.blackbird.test/mcp");
            require_ok(code->second == "auth-code-xyz");
            const auto computed = compute_pkce_s256_challenge(ver->second);
            require_ok(computed.has_value() &&
                       computed.value() == expected_pkce_challenge);
            send_json(
                200, "OK",
                R"({"access_token":"at-initial-001","refresh_token":"rt-initial-001","token_type":"Bearer","expires_in":300,"scope":"mcp:tools"})");
            return;
          }
          if (gt->second == "refresh_token") {
            // Sleep slightly so concurrent callers genuinely contend on vault lock.
            std::this_thread::sleep_for(std::chrono::milliseconds{40});
            std::lock_guard<std::mutex> lock{srv_mu};
            const auto rt = form.find("refresh_token");
            const auto res = form.find("resource");
            require_ok(rt != form.end() && rt->second == active_refresh_token);
            require_ok(res != form.end() &&
                       res->second == "https://mcp.blackbird.test/mcp");
            refresh_calls.fetch_add(1, std::memory_order_relaxed);
            active_access_token = "at-rotated-002";
            active_refresh_token = "rt-rotated-002";
            send_json(
                200, "OK",
                R"({"access_token":"at-rotated-002","refresh_token":"rt-rotated-002","token_type":"Bearer","expires_in":3600,"scope":"mcp:tools"})");
            return;
          }
        }

        send_json(404, "Not Found", R"({"error":"not_found"})");
      }};

  net::HttpClientConfig http_cfg{};
  http_cfg.host_policy =
      net::AllowedHostPolicy::pinned({"mcp.blackbird.test", "auth.blackbird.test"});
  http_cfg.host_policy.allow_loopback = true;
  http_cfg.ca_bundle_path = cert.pem_path;
  http_cfg.connect_host_override = "127.0.0.1";
  http_cfg.connect_port_override = server.port();
  const net::HttpClient http{http_cfg};

  // Step 1: Probe MCP server -> 401 WWW-Authenticate (RFC 9728).
  net::HttpRequest probe{};
  probe.url = "https://mcp.blackbird.test/mcp";
  const auto probe_resp = http.request(probe);
  require_ok(probe_resp.has_value() && probe_resp.value().status == 401);
  const auto www = probe_resp.value().find_header("www-authenticate");
  if (!www.has_value()) {
    std::abort();
  }
  const auto challenge = parse_www_authenticate_bearer(www.value());
  require_ok(challenge.has_value());

  // Step 2: Fetch Protected Resource Metadata (RFC 9728).
  const auto prm =
      fetch_protected_resource_metadata(http, challenge.value().resource_metadata);
  require_ok(prm.has_value());
  require_ok(prm.value().resource == "https://mcp.blackbird.test/mcp");
  require_ok(prm.value().authorization_servers.size() == 1U);

  // Step 3: Fetch Authorization Server Metadata (RFC 8414 + S256 check).
  const auto as_meta =
      fetch_authorization_server_metadata(http, prm.value().authorization_servers[0]);
  require_ok(as_meta.has_value());
  require_ok(as_meta.value().client_id_metadata_document_supported);

  // Step 4a: Verify CIMD client resolution when CIMD URL is configured.
  {
    OAuthClientResolutionOptions cimd_opts{};
    cimd_opts.cimd_client_id_url =
        "https://blackbird.antimeme.ai/oauth/client-metadata.json";
    const auto cimd_client = resolve_oauth_client(http, as_meta.value(), cimd_opts);
    require_ok(cimd_client.has_value());
    require_ok(cimd_client.value().via_cimd);
    require_ok(cimd_client.value().client_id == cimd_opts.cimd_client_id_url);
  }

  // Step 4b: Bind loopback listener + RFC 7591 Dynamic Client Registration.
  auto listener_res = OAuthLoopbackListener::bind();
  require_ok(listener_res.has_value());
  OAuthLoopbackListener listener = std::move(listener_res).value();

  OAuthClientResolutionOptions dcr_opts{};
  dcr_opts.dcr_request.client_name = "Blackbird";
  dcr_opts.dcr_request.redirect_uris = {listener.redirect_uri()};
  dcr_opts.dcr_request.scope = challenge.value().scope;
  const auto dcr_client = resolve_oauth_client(http, as_meta.value(), dcr_opts);
  require_ok(dcr_client.has_value());
  require_ok(!dcr_client.value().via_cimd);
  require_ok(dcr_client.value().client_id == "dcr-client-98765");

  // Step 5: Generate PKCE S256 + state + RFC 8707 authorize URL + loopback callback.
  const auto pkce = generate_pkce_s256();
  const auto state = generate_oauth_state();
  require_ok(pkce.has_value() && state.has_value());
  {
    std::lock_guard<std::mutex> lock{srv_mu};
    expected_pkce_challenge = pkce.value().code_challenge;
  }

  const auto auth_url = build_oauth_authorize_url({
      .authorization_endpoint = as_meta.value().authorization_endpoint,
      .client_id = dcr_client.value().client_id,
      .redirect_uri = listener.redirect_uri(),
      .scope = challenge.value().scope,
      .state = state.value(),
      .code_challenge = pkce.value().code_challenge,
      .resource = prm.value().resource,
  });
  require_ok(auth_url.has_value());
  require_ok(auth_url.value().find("code_challenge_method=S256") != std::string::npos);
  require_ok(auth_url.value().find("resource=https%3A%2F%2Fmcp.blackbird.test%2Fmcp") !=
             std::string::npos);

  std::thread browser([port = listener.port(), st = state.value()]() {
    (void)send_plain_loopback_http(port,
                                   "GET /auth/callback?code=auth-code-xyz&state=" + st +
                                       " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
  });
  const auto cb = listener.wait({.expected_state = state.value(), .timeout_ms = 5000});
  browser.join();
  require_ok(cb.has_value() && cb.value().code == "auth-code-xyz");

  // Step 6: Exchange authorization code + PKCE verifier + RFC 8707 resource.
  OAuthTokenExchangeRequest ex_req{};
  ex_req.token_endpoint = as_meta.value().token_endpoint;
  ex_req.client_id = dcr_client.value().client_id;
  ex_req.code = cb.value().code;
  ex_req.redirect_uri = listener.redirect_uri();
  ex_req.code_verifier = pkce.value().code_verifier;
  ex_req.resource = prm.value().resource;
  const auto tokens = exchange_oauth_authorization_code(http, ex_req);
  require_ok(tokens.has_value());
  require_ok(tokens.value().access_token.view() == "at-initial-001");
  require_ok(tokens.value().refresh_token.view() == "rt-initial-001");
  require_ok(tokens.value().expires_in == 300);

  // Step 7: Persist into binary IntegrationVault and execute authenticated MCP call.
  std::atomic<std::int64_t> fake_clock{1'700'000'000};
  IntegrationVault vault{{
      .directory = dir.path / "vault",
      .now = [&]() { return fake_clock.load(std::memory_order_relaxed); },
      .refresh_skew_seconds = 60,
      .refresh_http_config = http_cfg,
  }};

  CredentialSaveInput save_in{};
  save_in.service = "mcp-demo";
  save_in.account = "primary";
  save_in.scheme = AuthScheme::bearer_oauth2;
  save_in.access_token = tokens.value().access_token;
  save_in.refresh_token = tokens.value().refresh_token;
  save_in.allowed_hosts = {"mcp.blackbird.test"};
  save_in.scopes = {"mcp:tools"};
  save_in.resource_uri = prm.value().resource;
  save_in.authorization_server = as_meta.value().issuer;
  save_in.token_endpoint = as_meta.value().token_endpoint;
  save_in.client_id = dcr_client.value().client_id;
  save_in.expires_at = fake_clock.load() + tokens.value().expires_in;
  const auto meta = vault.save(save_in);
  require_ok(meta.has_value() && meta.value().id == CredentialId{1U});

  {
    net::HttpRequest call{};
    call.url = "https://mcp.blackbird.test/mcp";
    const auto auth = vault.authorize_request(
        meta.value().id, call, {.allow_loopback_host_for_testing = true});
    require_ok(auth.has_value());
    const auto resp = http.request(call);
    require_ok(resp.has_value() && resp.value().status == 200);
    require_ok(resp.value().body_as_string().find("\"tool_count\":7") !=
               std::string::npos);
  }

  // Step 8: Advance clock into refresh skew window -> 4 concurrent threads race!
  // Single-flight vault lock MUST issue exactly ONE refresh call and rotate tokens!
  fake_clock.store(1'700'000'260, std::memory_order_relaxed);
  std::vector<std::thread> workers;
  std::atomic<int> successes{0};
  for (int i = 0; i < 4; ++i) {
    workers.emplace_back([&]() {
      net::HttpRequest call{};
      call.url = "https://mcp.blackbird.test/mcp";
      const auto auth = vault.authorize_request(
          {"mcp-demo", "primary"}, call,
          {.auto_refresh = true, .allow_loopback_host_for_testing = true});
      require_ok(auth.has_value());
      require_ok(call.find_header("Authorization") ==
                 std::optional<std::string_view>{"Bearer at-rotated-002"});
      const auto resp = http.request(call);
      require_ok(resp.has_value() && resp.value().status == 200);
      successes.fetch_add(1, std::memory_order_relaxed);
    });
  }
  for (auto &t : workers) {
    t.join();
  }
  require_ok(successes.load() == 4);
  require_ok(refresh_calls.load() == 1);

  const auto updated = vault.find_by_id(meta.value().id);
  require_ok(updated.has_value());
  require_ok(updated.value().revision == 2U);
  require_ok(!updated.value().expired);
  require_ok(updated.value().expires_at == 1'700'000'260 + 3600);
}

} // namespace

int main() {
  test_pkce_and_state();
  test_binary_store_perms_and_corrupt_rejection();
  test_host_pinned_secret_injection();
  test_rfc9728_and_rfc8414_parsing();
  test_loopback_callback_listener();
  test_end_to_end_oauth21_mcp_and_single_flight_refresh();
  std::cout << "integration_vault_test: all tests passed\n";
  return 0;
}
