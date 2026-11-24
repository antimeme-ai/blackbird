#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/net_http.hpp"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace blackbird {

// ---------------------------------------------------------------------------
// Error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

enum class VaultError : std::int64_t {
  none = 0,

  invalid_argument = 6000,
  invalid_url = 6001,
  not_found = 6002,
  already_exists = 6003,
  insecure_permissions = 6004,
  symlink_rejected = 6005,
  corrupt_store = 6006,
  lock_timeout = 6007,
  io_failed = 6008,

  host_not_pinned = 6009,
  https_required = 6010,
  crypto_failed = 6011,

  oauth_challenge_invalid = 6012,
  oauth_metadata_invalid = 6013,
  oauth_pkce_unsupported = 6014,
  oauth_registration_failed = 6015,
  oauth_callback_timeout = 6016,
  oauth_callback_rejected = 6017,
  oauth_token_exchange_failed = 6018,
  oauth_refresh_failed = 6019,
  oauth_no_refresh_token = 6020,

  cancelled = 6021,
  capacity_exceeded = 6022,
};

constexpr VaultError vault_error_of(const Error &error) noexcept {
  return static_cast<VaultError>(error.detail);
}

std::string_view vault_error_name(VaultError detail) noexcept;

// ---------------------------------------------------------------------------
// Primary integer identity & cleansed secret custody
// ---------------------------------------------------------------------------

// All stored credential records are keyed strictly by 64-bit integer IDs.
// Service/account names are indexed properties, never internal primary keys.
struct CredentialId {
  std::uint64_t value = 0U;

  constexpr bool valid() const noexcept { return value != 0U; }
  auto operator<=>(const CredentialId &) const = default;
};

// Secret string buffer wiped with OPENSSL_cleanse on destruction/reassignment.
class CleansedSecret {
public:
  CleansedSecret() noexcept = default;
  explicit CleansedSecret(std::string value) noexcept : value_(std::move(value)) {}
  explicit CleansedSecret(std::string_view value) : value_(value) {}
  CleansedSecret(const CleansedSecret &other);
  CleansedSecret &operator=(const CleansedSecret &other);
  CleansedSecret(CleansedSecret &&other) noexcept;
  CleansedSecret &operator=(CleansedSecret &&other) noexcept;
  ~CleansedSecret();

  bool empty() const noexcept { return value_.empty(); }
  std::size_t size() const noexcept { return value_.size(); }
  std::string_view view() const noexcept { return value_; }
  void assign(std::string_view next);
  void clear() noexcept;

private:
  void cleanse() noexcept;
  std::string value_;
};

// ---------------------------------------------------------------------------
// Credential metadata (ZERO secret fields exposed)
// ---------------------------------------------------------------------------

enum class AuthScheme : std::uint8_t {
  bearer_oauth2 = 0,
  bearer_pat = 1,
  discord_bot = 2,
  header_key = 3,
  basic_token = 4,
};

std::string_view auth_scheme_name(AuthScheme scheme) noexcept;
Result<AuthScheme> parse_auth_scheme(std::string_view name) noexcept;

struct ServiceAccountKey {
  std::string service;
  std::string account; // empty resolves to active account for service
};

struct CredentialMetadata {
  CredentialId id{};
  std::string service;
  std::string account;
  AuthScheme scheme = AuthScheme::bearer_oauth2;
  std::string auth_header_name;
  std::string auth_header_prefix;
  std::vector<std::string> allowed_hosts;
  std::vector<std::string> scopes;
  std::string resource_uri;
  std::string authorization_server;
  std::string token_endpoint;
  std::string client_id;
  std::int64_t expires_at = 0;
  std::int64_t updated_at = 0;
  std::uint64_t revision = 0U;
  bool has_refresh_token = false;
  bool active = false;
  bool expired = false;
  std::vector<std::pair<std::string, std::string>> extra_metadata;

  bool operator==(const CredentialMetadata &) const = default;
};

struct CredentialSaveInput {
  std::string service;
  std::string account;
  AuthScheme scheme = AuthScheme::bearer_oauth2;
  std::string auth_header_name = "Authorization";
  std::string auth_header_prefix; // auto-derived from scheme when empty
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
  std::vector<std::pair<std::string, std::string>> extra_metadata;
  bool set_active = true;
};

// ---------------------------------------------------------------------------
// OAuth 2.1 + MCP Authorization (2025-11-25) primitives
// ---------------------------------------------------------------------------

struct OAuthPkcePair {
  CleansedSecret code_verifier;
  std::string code_challenge;
  std::string method = "S256";
};

Result<OAuthPkcePair> generate_pkce_s256();
Result<std::string> compute_pkce_s256_challenge(std::string_view code_verifier);
Result<std::string> generate_oauth_state();

// RFC 9728 WWW-Authenticate Bearer challenge parser
struct WwwAuthenticateChallenge {
  std::string scheme;
  std::string resource_metadata;
  std::string scope;
  std::string error;
  std::string error_description;
  std::string realm;
  std::vector<std::pair<std::string, std::string>> params;

  bool operator==(const WwwAuthenticateChallenge &) const = default;
};

Result<WwwAuthenticateChallenge>
parse_www_authenticate_bearer(std::string_view header_value);

// RFC 9728 Protected Resource Metadata
struct ProtectedResourceMetadata {
  std::string resource;
  std::vector<std::string> authorization_servers;
  std::vector<std::string> scopes_supported;
  std::vector<std::string> bearer_methods_supported;
  std::string resource_name;

  bool operator==(const ProtectedResourceMetadata &) const = default;
};

Result<ProtectedResourceMetadata>
parse_protected_resource_metadata(std::string_view json_body);

Result<ProtectedResourceMetadata>
fetch_protected_resource_metadata(const net::HttpClient &http,
                                  std::string_view metadata_url);

// RFC 8414 Authorization Server Metadata (+ MCP 2025-11-25 CIMD flag)
struct AuthorizationServerMetadata {
  std::string issuer;
  std::string authorization_endpoint;
  std::string token_endpoint;
  std::string registration_endpoint;
  std::vector<std::string> scopes_supported;
  std::vector<std::string> response_types_supported;
  std::vector<std::string> grant_types_supported;
  std::vector<std::string> code_challenge_methods_supported;
  std::vector<std::string> token_endpoint_auth_methods_supported;
  bool client_id_metadata_document_supported = false;

  bool operator==(const AuthorizationServerMetadata &) const = default;
};

Result<std::string> build_as_metadata_url(std::string_view issuer_url);

Result<AuthorizationServerMetadata>
parse_authorization_server_metadata(std::string_view json_body,
                                    bool require_pkce_s256 = true);

Result<AuthorizationServerMetadata>
fetch_authorization_server_metadata(const net::HttpClient &http,
                                    std::string_view issuer_url,
                                    bool require_pkce_s256 = true);

// RFC 7591 Dynamic Client Registration + Client ID Metadata Document (CIMD)
struct OAuthClientRegistrationRequest {
  std::string client_name = "Blackbird";
  std::vector<std::string> redirect_uris;
  std::vector<std::string> grant_types = {"authorization_code", "refresh_token"};
  std::vector<std::string> response_types = {"code"};
  std::string token_endpoint_auth_method = "none";
  std::string scope;
};

struct OAuthClientRegistration {
  std::string client_id;
  CleansedSecret client_secret;
  std::string token_endpoint_auth_method = "none";
  bool via_cimd = false;
};

struct OAuthClientResolutionOptions {
  std::string static_client_id;
  CleansedSecret static_client_secret;
  std::string cimd_client_id_url;
  OAuthClientRegistrationRequest dcr_request;
};

Result<OAuthClientRegistration>
register_dynamic_client(const net::HttpClient &http,
                        std::string_view registration_endpoint,
                        const OAuthClientRegistrationRequest &req);

Result<OAuthClientRegistration>
resolve_oauth_client(const net::HttpClient &http,
                     const AuthorizationServerMetadata &as_meta,
                     const OAuthClientResolutionOptions &opts);

// Authorization URL & Token Exchange / Refresh (RFC 8707 resource bound)
struct OAuthAuthorizeUrlParams {
  std::string authorization_endpoint;
  std::string client_id;
  std::string redirect_uri;
  std::string scope;
  std::string state;
  std::string code_challenge;
  std::string code_challenge_method = "S256";
  std::string resource;
};

Result<std::string> build_oauth_authorize_url(const OAuthAuthorizeUrlParams &params);

struct OAuthTokenResponse {
  CleansedSecret access_token;
  CleansedSecret refresh_token;
  std::string token_type = "Bearer";
  std::int64_t expires_in = 0;
  std::string scope;
};

struct OAuthTokenExchangeRequest {
  std::string token_endpoint;
  std::string client_id;
  CleansedSecret client_secret;
  std::string code;
  std::string redirect_uri;
  CleansedSecret code_verifier;
  std::string resource;
};

Result<OAuthTokenResponse>
exchange_oauth_authorization_code(const net::HttpClient &http,
                                  const OAuthTokenExchangeRequest &req);

struct OAuthTokenRefreshRequest {
  std::string token_endpoint;
  std::string client_id;
  CleansedSecret client_secret;
  CleansedSecret refresh_token;
  std::string resource;
  std::string scope;
};

Result<OAuthTokenResponse> refresh_oauth_token(const net::HttpClient &http,
                                               const OAuthTokenRefreshRequest &req);

// ---------------------------------------------------------------------------
// Local loopback 127.0.0.1:0 ephemeral OAuth callback HTTP listener
// ---------------------------------------------------------------------------

struct OAuthCallbackResult {
  std::string code;
  std::string state;
  std::string error;
  std::string error_description;

  bool operator==(const OAuthCallbackResult &) const = default;
};

struct OAuthCallbackWaitOptions {
  std::string expected_state;
  int timeout_ms = 300'000;
  bool fail_fast_on_bad_state = false;
  std::function<bool()> cancelled = {};
};

class OAuthLoopbackListener {
public:
  static Result<OAuthLoopbackListener> bind();

  OAuthLoopbackListener(const OAuthLoopbackListener &) = delete;
  OAuthLoopbackListener &operator=(const OAuthLoopbackListener &) = delete;
  OAuthLoopbackListener(OAuthLoopbackListener &&other) noexcept;
  OAuthLoopbackListener &operator=(OAuthLoopbackListener &&other) noexcept;
  ~OAuthLoopbackListener();

  std::uint16_t port() const noexcept { return port_; }
  std::string redirect_uri() const;
  std::size_t rejected_count() const noexcept { return rejected_count_; }
  void close() noexcept;

  Result<OAuthCallbackResult> wait(const OAuthCallbackWaitOptions &options);

private:
  struct BoundSocket {
    int fd = -1;
    std::uint16_t port = 0U;
  };
  explicit OAuthLoopbackListener(BoundSocket sock) noexcept
      : fd_(sock.fd), port_(sock.port) {}

  int fd_ = -1;
  std::uint16_t port_ = 0U;
  std::size_t rejected_count_ = 0U;
};

// ---------------------------------------------------------------------------
// IntegrationVault (binary packet integrations.bbm + host-pinned injection)
// ---------------------------------------------------------------------------

struct IntegrationVaultConfig {
  std::filesystem::path directory;
  std::function<std::int64_t()> now = {};
  std::function<bool()> cancelled = {};
  std::int64_t refresh_skew_seconds = 60;
  int lock_timeout_ms = 30'000;
  // Optional HTTP client used when authorize_request triggers automatic
  // OAuth 2.1 refresh-token rotation.
  std::optional<net::HttpClientConfig> refresh_http_config = std::nullopt;
};

struct AuthorizeRequestOptions {
  bool auto_refresh = true;
  bool allow_loopback_host_for_testing = false;
  // Optional explicit HTTP client override for automatic token refresh.
  const net::HttpClient *refresh_http = nullptr;
};

class IntegrationVault {
public:
  explicit IntegrationVault(IntegrationVaultConfig config = {});

  const std::filesystem::path &directory() const noexcept { return config_.directory; }
  std::filesystem::path store_path() const;

  // Stores or updates a credential atomically in binary packet integrations.bbm.
  // Returns non-secret metadata including its assigned 64-bit CredentialId.
  Result<CredentialMetadata> save(const CredentialSaveInput &input) const;

  // Non-secret metadata queries (NEVER return tokens or client_secret).
  Result<std::vector<CredentialMetadata>> list() const;
  Result<CredentialMetadata> find_by_id(CredentialId id) const;
  Result<CredentialMetadata> find(const ServiceAccountKey &key) const;

  Result<void> set_active(CredentialId id) const;
  Result<void> remove(CredentialId id) const;

  // Host-pinned secret injection: verifies request.url is https:// and matches
  // the credential's pinned allowed_hosts BEFORE injecting the auth header.
  // Automatically performs lock-serialized single-flight OAuth refresh if near
  // expiry and a refresh token + token endpoint are present.
  Result<CredentialMetadata>
  authorize_request(const ServiceAccountKey &key, net::HttpRequest &request,
                    const AuthorizeRequestOptions &options = {}) const;

  Result<CredentialMetadata>
  authorize_request(CredentialId id, net::HttpRequest &request,
                    const AuthorizeRequestOptions &options = {}) const;

  // Explicit lock-serialized single-flight OAuth 2.1 refresh-token rotation.
  // If force == false and another thread/process already refreshed the token
  // beyond refresh_skew_seconds while waiting on the lock, skips redundant
  // network refresh and returns the fresh metadata.
  Result<CredentialMetadata> refresh_credential(CredentialId id,
                                                const net::HttpClient &http,
                                                bool force = false) const;

  Result<CredentialMetadata> refresh_credential(const ServiceAccountKey &key,
                                                const net::HttpClient &http,
                                                bool force = false) const;

private:
  IntegrationVaultConfig config_;
};

} // namespace blackbird
