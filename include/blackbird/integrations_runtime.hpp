#pragma once

#include "blackbird/brakes_policy.hpp"
#include "blackbird/foundation.hpp"
#include "blackbird/integration_vault.hpp"
#include "blackbird/mcp_client.hpp"
#include "blackbird/net_http.hpp"
#include "blackbird/saas_packs.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace blackbird {

struct LiveTransportTarget {
  std::string service;
  std::string account;
  // Allows loopback IP/host override during deterministic local TLS testing.
  bool allow_loopback_for_testing = false;
  // For MCP OAuth 2.1 discovery: when true and the vault has no credential yet
  // for `service`, sends the request unauthenticated so the server's 401
  // WWW-Authenticate RFC 9728 challenge propagates cleanly. When a credential
  // DOES exist, host-pinning and authorization failures ALWAYS fail closed.
  bool allow_unauthenticated_probe = false;
};

// Bridges McpClient's injectable McpHttpTransportFn directly onto owned
// blackbird::net::HttpClient + IntegrationVault::authorize_request() with
// strict host pinning, OPENSSL_cleanse on injected auth headers, sensitive
// response-header scrubbing, and RFC 9728 401/403 OAuth challenge propagation.
McpHttpTransportFn make_live_mcp_http_transport(const net::HttpClient &http,
                                                const IntegrationVault &vault,
                                                LiveTransportTarget target);

// Bridges SaasPackHost's injectable PinnedHttpFn directly onto owned
// blackbird::net::HttpClient + IntegrationVault::authorize_request() with
// triple-layer host pinning (SaasPackHost + IntegrationVault + HttpClient),
// OPENSSL_cleanse on injected auth headers, and zero token exposure to Lua.
PinnedHttpFn make_live_saas_http_transport(const net::HttpClient &http,
                                           const IntegrationVault &vault,
                                           LiveTransportTarget target);

// Resolves the default IntegrationVault directory (respects
// BLACKBIRD_INTEGRATIONS_VAULT_DIR, then XDG_DATA_HOME/blackbird/auth, then
// HOME/.local/share/blackbird/auth). Never creates directories.
std::filesystem::path default_integrations_vault_dir();

// Resolves the default builtin Lua 5.5.1 packs directory (respects
// BLACKBIRD_INTEGRATIONS_DIR, then runtime_resource("programs/integrations")).
std::filesystem::path default_integrations_packs_dir();

// Pure-C++ registration bridge allowing foundation-layer model tools
// (command_post_tools) to invoke the Lua 5.5.1 SaasPackHost in blackbird_coding
// without introducing a Lua dependency into blackbird_foundation.
struct SaasPackLiveCallRequest {
  std::string service;
  std::string operation;
  Value arguments = Value::object({});
  std::string account;
  std::filesystem::path vault_dir;
  std::filesystem::path packs_dir;
  brakes::EffectivePolicy brakes_policy{};
  std::optional<net::HttpClientConfig> http_config_override;
  bool allow_loopback_for_testing = false;
};

using SaasPackLiveExecutorFn =
    Result<SaasInvokeOutcome> (*)(const SaasPackLiveCallRequest &);

void register_saas_pack_live_executor(SaasPackLiveExecutorFn fn) noexcept;
Result<SaasInvokeOutcome>
invoke_registered_saas_pack_live(const SaasPackLiveCallRequest &req);

} // namespace blackbird
