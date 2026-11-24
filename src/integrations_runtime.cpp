#include "blackbird/integrations_runtime.hpp"
#include "blackbird/runtime_paths.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <openssl/crypto.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace blackbird {
namespace {

std::atomic<SaasPackLiveExecutorFn> g_saas_live_executor{nullptr};

std::string ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text)
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  return out;
}

bool valid_hostname(std::string_view host) noexcept {
  if (host.empty() || host.size() > 253U)
    return false;
  if (host.front() == '.' || host.back() == '.')
    return false;
  for (const char ch : host) {
    const unsigned char c = static_cast<unsigned char>(ch);
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '.';
    if (!ok)
      return false;
  }
  return host.find("..") == std::string_view::npos;
}

bool valid_relative_path(std::string_view path) noexcept {
  if (path.empty() || path.front() != '/')
    return false;
  if (path.size() >= 2U && path[0] == '/' && path[1] == '/')
    return false;
  if (path.find("://") != std::string_view::npos)
    return false;
  if (path.find('\\') != std::string_view::npos)
    return false;
  if (path.find('@') != std::string_view::npos)
    return false;
  if (path.find('?') != std::string_view::npos ||
      path.find('#') != std::string_view::npos) {
    return false;
  }
  for (const char ch : path) {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (c <= 0x20U || c >= 0x7FU)
      return false;
  }
  const std::string lower = ascii_lower(path);
  if (lower.find("%2e") != std::string::npos ||
      lower.find("%2f") != std::string::npos ||
      lower.find("%5c") != std::string::npos) {
    return false;
  }
  std::size_t pos = 0U;
  while (pos < path.size()) {
    const std::size_t next = path.find('/', pos);
    const std::string_view seg = next == std::string_view::npos
                                     ? path.substr(pos)
                                     : path.substr(pos, next - pos);
    if (seg == "..")
      return false;
    if (next == std::string_view::npos)
      break;
    pos = next + 1U;
  }
  return true;
}

bool is_forbidden_caller_header(std::string_view lower_name) noexcept {
  return lower_name == "authorization" || lower_name == "proxy-authorization" ||
         lower_name == "cookie" || lower_name == "host" ||
         lower_name == "transfer-encoding" || lower_name == "content-length";
}

bool is_sensitive_response_header(std::string_view lower_name) noexcept {
  return lower_name == "authorization" || lower_name == "proxy-authorization" ||
         lower_name == "cookie" || lower_name == "set-cookie" ||
         lower_name == "x-auth-token" || lower_name == "x-api-key";
}

// Ensures any injected Authorization / secret header values inside
// net::HttpRequest are wiped with OPENSSL_cleanse on scope exit.
class RequestAuthCleanseGuard {
public:
  explicit RequestAuthCleanseGuard(net::HttpRequest &req) noexcept : req_(req) {}
  RequestAuthCleanseGuard(const RequestAuthCleanseGuard &) = delete;
  RequestAuthCleanseGuard &operator=(const RequestAuthCleanseGuard &) = delete;
  ~RequestAuthCleanseGuard() {
    for (auto &hdr : req_.headers) {
      if (!hdr.value.empty())
        ::OPENSSL_cleanse(hdr.value.data(), hdr.value.size());
      hdr.value.clear();
    }
  }

private:
  net::HttpRequest &req_;
};

int clamp_timeout_ms(std::chrono::milliseconds timeout) noexcept {
  const auto ms = timeout.count();
  if (ms <= 0)
    return net::kDefaultIoTimeoutMs;
  if (ms > static_cast<std::int64_t>(std::numeric_limits<int>::max()))
    return std::numeric_limits<int>::max();
  return static_cast<int>(ms);
}

} // namespace

// ---------------------------------------------------------------------------
// Pure-C++ SaaS Pack Manifest & Pinned URL Helpers (zero Lua dependency)
// ---------------------------------------------------------------------------

std::string_view saas_effect_class_name(SaasEffectClass effect) noexcept {
  switch (effect) {
  case SaasEffectClass::read:
    return "read";
  case SaasEffectClass::write:
    return "write";
  case SaasEffectClass::send:
    return "send";
  case SaasEffectClass::del:
    return "delete";
  }
  return "write";
}

Result<SaasEffectClass> parse_saas_effect_class(std::string_view name) noexcept {
  if (name == "read" || name == "read_only")
    return Result<SaasEffectClass>::success(SaasEffectClass::read);
  if (name == "write")
    return Result<SaasEffectClass>::success(SaasEffectClass::write);
  if (name == "send")
    return Result<SaasEffectClass>::success(SaasEffectClass::send);
  if (name == "delete" || name == "del")
    return Result<SaasEffectClass>::success(SaasEffectClass::del);
  return Result<SaasEffectClass>::failure({ErrorCode::invalid_range});
}

Result<std::string> build_pinned_https_url(const PinnedUrlInput &input,
                                           std::string *resolved_host_out) {
  if (input.allowed_hosts.empty())
    return Result<std::string>::failure({ErrorCode::invalid_range});

  std::string chosen_host;
  if (input.requested_host.empty()) {
    chosen_host = ascii_lower(input.allowed_hosts.front());
    if (!valid_hostname(chosen_host))
      return Result<std::string>::failure({ErrorCode::invalid_range});
  } else {
    const std::string lower_req = ascii_lower(input.requested_host);
    if (!valid_hostname(lower_req))
      return Result<std::string>::failure({ErrorCode::invalid_range});
    bool matched = false;
    for (const std::string &allowed : input.allowed_hosts) {
      if (ascii_lower(allowed) == lower_req) {
        chosen_host = lower_req;
        matched = true;
        break;
      }
    }
    if (!matched)
      return Result<std::string>::failure({ErrorCode::unsupported});
  }

  if (!valid_relative_path(input.relative_path))
    return Result<std::string>::failure({ErrorCode::invalid_range});

  if (resolved_host_out != nullptr)
    *resolved_host_out = chosen_host;

  std::string url = "https://" + chosen_host;
  url.append(input.relative_path);
  if (!input.query_string.empty()) {
    for (const char ch : input.query_string) {
      const unsigned char c = static_cast<unsigned char>(ch);
      if (c <= 0x20U || c >= 0x7FU || c == '#')
        return Result<std::string>::failure({ErrorCode::invalid_range});
    }
    url.push_back('?');
    url.append(input.query_string);
  }
  return Result<std::string>::success(std::move(url));
}

const std::vector<SaasPackManifest> &builtin_saas_pack_manifests() {
  static const std::vector<SaasPackManifest> manifests = {
      SaasPackManifest{
          "linear",
          "Linear",
          {"api.linear.app"},
          {{"Accept", "application/json"}},
          {
              {"search_issues", SaasEffectClass::read},
              {"get_issue", SaasEffectClass::read},
              {"create_issue", SaasEffectClass::write},
              {"comment_issue", SaasEffectClass::send},
              {"update_issue", SaasEffectClass::write},
          },
          false,
          brakes::PartyTrustProfile::human_gated,
          "saas:linear:api.linear.app",
      },
      SaasPackManifest{
          "slack",
          "Slack",
          {"slack.com"},
          {{"Accept", "application/json"}},
          {
              {"list_channels", SaasEffectClass::read},
              {"channel_history", SaasEffectClass::read},
              {"read_thread", SaasEffectClass::read},
              {"post_message", SaasEffectClass::send},
          },
          true,
          brakes::PartyTrustProfile::human_gated,
          "saas:slack:slack.com",
      },
      SaasPackManifest{
          "gmail",
          "Gmail",
          {"gmail.googleapis.com"},
          {{"Accept", "application/json"}},
          {
              {"search_threads", SaasEffectClass::read},
              {"read_thread", SaasEffectClass::read},
              {"create_draft", SaasEffectClass::write},
              {"send_message", SaasEffectClass::send},
          },
          true,
          brakes::PartyTrustProfile::advisory,
          "saas:gmail:gmail.googleapis.com",
      },
      SaasPackManifest{
          "gcal",
          "Google Calendar",
          {"www.googleapis.com"},
          {{"Accept", "application/json"}},
          {
              {"list_events", SaasEffectClass::read},
              {"create_event", SaasEffectClass::write},
              {"free_busy", SaasEffectClass::read},
          },
          false,
          brakes::PartyTrustProfile::human_gated,
          "saas:gcal:www.googleapis.com",
      },
      SaasPackManifest{
          "notion",
          "Notion",
          {"api.notion.com"},
          {{"Notion-Version", "2025-09-03"}, {"Accept", "application/json"}},
          {
              {"search", SaasEffectClass::read},
              {"read_page", SaasEffectClass::read},
              {"append_block", SaasEffectClass::write},
          },
          false,
          brakes::PartyTrustProfile::human_gated,
          "saas:notion:api.notion.com",
      },
      SaasPackManifest{
          "github",
          "GitHub",
          {"api.github.com"},
          {{"Accept", "application/vnd.github+json"},
           {"X-GitHub-Api-Version", "2022-11-28"},
           {"User-Agent", "Blackbird/1.0"}},
          {
              {"list_items", SaasEffectClass::read},
              {"view_item", SaasEffectClass::read},
              {"create_issue", SaasEffectClass::write},
              {"comment_item", SaasEffectClass::send},
          },
          true,
          brakes::PartyTrustProfile::advisory,
          "saas:github:api.github.com",
      },
      SaasPackManifest{
          "discord",
          "Discord",
          {"discord.com"},
          {{"Accept", "application/json"}, {"User-Agent", "Blackbird/1.0"}},
          {
              {"list_channels", SaasEffectClass::read},
              {"get_messages", SaasEffectClass::read},
              {"send_message", SaasEffectClass::send},
          },
          true,
          brakes::PartyTrustProfile::advisory,
          "saas:discord:discord.com",
      },
  };
  return manifests;
}

std::optional<SaasPackManifest>
find_builtin_saas_pack_manifest(std::string_view service) {
  const std::string lower = ascii_lower(service);
  for (const auto &m : builtin_saas_pack_manifests()) {
    if (m.service == lower)
      return m;
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Live Transport Bridges (HttpClient + IntegrationVault -> McpClient / SaasPackHost)
// ---------------------------------------------------------------------------

McpHttpTransportFn make_live_mcp_http_transport(const net::HttpClient &http,
                                                const IntegrationVault &vault,
                                                LiveTransportTarget target) {
  return [&http, &vault, target = std::move(target)](
             const McpHttpRequest &req) -> Result<McpHttpResponse> {
    auto method = net::parse_http_method(req.method);
    if (!method.has_value())
      return Result<McpHttpResponse>::failure(method.error());

    net::HttpRequest net_req;
    net_req.method = method.value();
    net_req.url = req.url;
    net_req.io_timeout_ms = clamp_timeout_ms(req.timeout);
    net_req.connect_timeout_ms =
        std::min(net_req.io_timeout_ms, net::kDefaultConnectTimeoutMs);
    net_req.set_body_string(req.body);
    for (const auto &[k, v] : req.headers) {
      if (is_forbidden_caller_header(ascii_lower(k)))
        return Result<McpHttpResponse>::failure({ErrorCode::invalid_range});
      net_req.add_header(net::HttpHeader{k, v});
    }

    RequestAuthCleanseGuard cleanse_guard{net_req};

    if (!target.service.empty()) {
      AuthorizeRequestOptions opts;
      opts.allow_loopback_host_for_testing = target.allow_loopback_for_testing;
      opts.refresh_http = &http;
      auto auth = vault.authorize_request(
          ServiceAccountKey{target.service, target.account}, net_req, opts);
      if (!auth.has_value()) {
        const bool is_missing = vault_error_of(auth.error()) == VaultError::not_found;
        if (!(target.allow_unauthenticated_probe && is_missing))
          return Result<McpHttpResponse>::failure(auth.error());
      }
    }

    auto resp = http.request(net_req);
    if (!resp.has_value())
      return Result<McpHttpResponse>::failure(resp.error());

    McpHttpResponse out;
    out.status_code = resp.value().status;
    out.body = resp.value().body_as_string();
    out.headers.reserve(resp.value().headers.size());
    for (const auto &hdr : resp.value().headers) {
      if (is_sensitive_response_header(ascii_lower(hdr.name)))
        continue;
      out.headers.emplace_back(hdr.name, hdr.value);
    }
    return Result<McpHttpResponse>::success(std::move(out));
  };
}

PinnedHttpFn make_live_saas_http_transport(const net::HttpClient &http,
                                           const IntegrationVault &vault,
                                           LiveTransportTarget target) {
  return [&http, &vault, target = std::move(target)](
             const PinnedHttpRequest &req) -> Result<PinnedHttpResponse> {
    if (target.service.empty() || req.service != target.service) {
      return Result<PinnedHttpResponse>::failure(
          {ErrorCode::invalid_identity,
           static_cast<std::int64_t>(VaultError::host_not_pinned)});
    }
    auto method = net::parse_http_method(req.method);
    if (!method.has_value())
      return Result<PinnedHttpResponse>::failure(method.error());

    net::HttpRequest net_req;
    net_req.method = method.value();
    net_req.url = req.url;
    net_req.io_timeout_ms = clamp_timeout_ms(req.timeout);
    net_req.connect_timeout_ms =
        std::min(net_req.io_timeout_ms, net::kDefaultConnectTimeoutMs);
    net_req.set_body_string(req.body);
    for (const auto &[k, v] : req.headers) {
      if (is_forbidden_caller_header(ascii_lower(k)))
        return Result<PinnedHttpResponse>::failure({ErrorCode::invalid_range});
      net_req.add_header(net::HttpHeader{k, v});
    }

    RequestAuthCleanseGuard cleanse_guard{net_req};

    const std::string account = !req.account.empty() ? req.account : target.account;
    AuthorizeRequestOptions opts;
    opts.allow_loopback_host_for_testing = target.allow_loopback_for_testing;
    opts.refresh_http = &http;
    auto auth = vault.authorize_request(ServiceAccountKey{target.service, account},
                                        net_req, opts);
    if (!auth.has_value())
      return Result<PinnedHttpResponse>::failure(auth.error());

    auto resp = http.request(net_req);
    if (!resp.has_value())
      return Result<PinnedHttpResponse>::failure(resp.error());

    PinnedHttpResponse out;
    out.status_code = resp.value().status;
    out.body = resp.value().body_as_string();
    out.headers.reserve(resp.value().headers.size());
    for (const auto &hdr : resp.value().headers) {
      if (is_sensitive_response_header(ascii_lower(hdr.name)))
        continue;
      out.headers.emplace_back(hdr.name, hdr.value);
    }
    return Result<PinnedHttpResponse>::success(std::move(out));
  };
}

std::filesystem::path default_integrations_vault_dir() {
  if (const char *override_dir = std::getenv("BLACKBIRD_INTEGRATIONS_VAULT_DIR");
      override_dir != nullptr && override_dir[0] != '\0') {
    return std::filesystem::path{override_dir};
  }
  if (const char *xdg = std::getenv("XDG_DATA_HOME");
      xdg != nullptr && xdg[0] != '\0') {
    return std::filesystem::path{xdg} / "blackbird" / "auth";
  }
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
    return std::filesystem::path{home} / ".local" / "share" / "blackbird" / "auth";
  }
  return {};
}

std::filesystem::path default_integrations_packs_dir() {
  if (const char *override_dir = std::getenv("BLACKBIRD_INTEGRATIONS_DIR");
      override_dir != nullptr && override_dir[0] != '\0') {
    return std::filesystem::path{override_dir};
  }
#ifdef BLACKBIRD_INTEGRATIONS_DIR
  return runtime_resource(
      {.relative = "programs/integrations", .development = BLACKBIRD_INTEGRATIONS_DIR});
#else
  return runtime_resource({.relative = "programs/integrations", .development = {}});
#endif
}

void register_saas_pack_live_executor(SaasPackLiveExecutorFn fn) noexcept {
  g_saas_live_executor.store(fn, std::memory_order_release);
}

Result<SaasInvokeOutcome>
invoke_registered_saas_pack_live(const SaasPackLiveCallRequest &req) {
  const auto fn = g_saas_live_executor.load(std::memory_order_acquire);
  if (fn == nullptr)
    return Result<SaasInvokeOutcome>::failure({ErrorCode::unsupported});
  return fn(req);
}

} // namespace blackbird
