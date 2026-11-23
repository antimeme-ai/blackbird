#include "../src/native_process.hpp"
#include "blackbird/json.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/provider_auth.hpp"
#include "blackbird/tools.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
using namespace blackbird;
int reply(ProviderHttpResponseLease &response, int status, std::string body) {
  auto extent = response.prepare(body.size());
  std::copy(body.begin(), body.end(), extent.begin());
  response.commit(body.size());
  return status;
}

void check(bool b, const char *message) {
  if (!b)
    throw std::runtime_error{message};
}
template <class F> void rejects(F f) {
  try {
    f();
  } catch (const Error &) {
    return;
  }
  throw std::runtime_error{"accepted invalid identity"};
}
std::string run(std::vector<std::string> args, std::string_view bytes = {}) {
  detail::Child c;
  c.separate_error = true;
  c.start(std::move(args));
  auto until = detail::Clock::now() + std::chrono::seconds{10};
  c.send(bytes, until);
  c.close_input();
  int exit = 0;
  auto out = c.collect(until, 65536, &exit);
  check(exit == 0, "openssl fixture failed");
  return out;
}
std::string encode(std::string_view bytes) {
  constexpr char abc[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string s;
  for (std::size_t at = 0; at < bytes.size(); at += 3) {
    const auto a = static_cast<unsigned char>(bytes[at]);
    s += abc[a >> 2U];
    const auto b =
        at + 1 < bytes.size() ? static_cast<unsigned char>(bytes[at + 1]) : 0U;
    s += abc[((a & 3U) << 4U) | (b >> 4U)];
    if (at + 1 < bytes.size()) {
      const auto c =
          at + 2 < bytes.size() ? static_cast<unsigned char>(bytes[at + 2]) : 0U;
      s += abc[((b & 15U) << 2U) | (c >> 6U)];
      if (at + 2 < bytes.size())
        s += abc[c & 63U];
    }
  }
  return s;
}
std::string decode(std::string_view s) {
  std::string out;
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '+')
      out += ' ';
    else if (s[i] == '%') {
      unsigned v = 0;
      auto r = std::from_chars(s.data() + i + 1, s.data() + i + 3, v, 16);
      check(r.ec == std::errc{}, "fixture decode");
      out += static_cast<char>(v);
      i += 2;
    } else
      out += s[i];
  }
  return out;
}
std::map<std::string, std::string> params(std::string_view s) {
  std::map<std::string, std::string> out;
  while (!s.empty()) {
    const auto end = s.find('&'), eq = s.find('=');
    out.emplace(
        std::string{s.substr(0, eq)},
        decode(s.substr(eq + 1, end == std::string_view::npos ? end : end - eq - 1)));
    if (end == std::string_view::npos)
      break;
    s.remove_prefix(end + 1);
  }
  return out;
}
std::string text(const Value &value, std::string_view key) {
  const auto *field = value.find(key);
  check(field != nullptr, "missing fixture field");
  return field->string();
}
std::string header(const ProviderHttpRequest &request, std::string_view key) {
  std::string value;
  unsigned count = 0;
  for (const auto &[name, bytes] : request.headers)
    if (name == key) {
      value = bytes;
      ++count;
    }
  check(count <= 1, "duplicate auth header");
  return value;
}
template <class F> void rejects_with(F f, ErrorCode code, int detail = 0) {
  try {
    f();
  } catch (const Error &error) {
    check(error.code == code && error.detail == detail, "wrong OAuth failure");
    return;
  }
  throw std::runtime_error{"accepted invalid OAuth transition"};
}
std::string account_state(const ProviderAuth &auth, std::string_view provider,
                          std::string_view account) {
  const auto status = auth.status();
  const auto *accounts = status.find("accounts");
  check(accounts && accounts->array().size() == 1, "unexpected OAuth accounts");
  const auto &entry = accounts->array().front();
  check(text(entry, "provider") == provider && text(entry, "account") == account,
        "wrong OAuth account");
  return text(entry, "state");
}
void replace_field(Value &object, std::string_view key, Value value) {
  for (auto &[name, existing] : object.object())
    if (name == key) {
      existing = std::move(value);
      return;
    }
  object.object().emplace_back(std::string{key}, std::move(value));
}
// Anthropic is API-key only. Blackbird has no Anthropic OAuth client of its own and
// never presents itself to Anthropic as Claude Code.
void anthropic_key_only_checks(const std::filesystem::path &directory) {
  const auto body = unwrap(parse_json(
      R"({"model":"fixture-model","max_tokens":64,"messages":[{"role":"user","content":"fixture input"}]})"));
  unsigned requests = 0;
  ProviderAuthConfig config;
  config.directory = directory / "anthropic";
  config.now = [] { return std::int64_t{1000}; };
  config.http = [&](const ProviderHttpRequest &request,
                    ProviderHttpResponseLease &response) {
    ++requests;
    check(request.url == "https://api.anthropic.com/v1/messages" &&
              unwrap(parse_json(request.body)) == body &&
              header(request, "x-api-key") == "fixture-anthropic-key" &&
              header(request, "anthropic-version") == "2023-06-01" &&
              header(request, "Authorization").empty() &&
              header(request, "anthropic-beta").empty() &&
              header(request, "User-Agent").empty() && header(request, "x-app").empty(),
          "Anthropic API-key request differs");
    return reply(response, 200, R"({"fixture":"messages reply"})");
  };
  ProviderAuth auth{config};
  const auto descriptor = auth.descriptor("anthropic");
  check(text(descriptor, "login") == "none" && text(descriptor, "client_id").empty() &&
            text(descriptor, "token_url").empty() && text(descriptor, "scope").empty(),
        "Anthropic catalog still offers subscription OAuth");
  rejects_with(
      [&] {
        auth.browser_login(
            "anthropic", "max", [](std::string_view) {},
            [] { return std::string{"fixture-code"}; });
      },
      ErrorCode::unsupported);
  rejects_with([&] { (void)auth.device_begin("anthropic", "max"); },
               ErrorCode::unsupported);
  check(requests == 0 && !auth.selected("anthropic"),
        "refused Anthropic login made a request or selected an account");

  auth.set_key("anthropic", "work", "fixture-anthropic-key");
  const auto response = auth.request("anthropic", "messages", body, 10);
  check(response.status == 200 && response.body == R"({"fixture":"messages reply"})" &&
            requests == 1,
        "Anthropic API-key request failed");

  // A subscription credential saved by an earlier Blackbird is refused before any
  // request: it is never sent, never refreshed, and never replaced by an ambient key.
  std::int64_t clock = 1000;
  unsigned legacy_requests = 0;
  auto legacy_config = config;
  legacy_config.directory = directory / "anthropic-legacy";
  legacy_config.now = [&] { return clock; };
  legacy_config.http = [&](const ProviderHttpRequest &,
                           ProviderHttpResponseLease &legacy_response) {
    ++legacy_requests;
    return reply(legacy_response, 200, "{}");
  };
  {
    ProviderAuth seed{legacy_config};
    seed.set_key("anthropic", "max", "fixture-legacy-access");
  }
  const auto store = legacy_config.directory / "credentials.bbm";
  auto data = unwrap(decode_packet_string(read_file(store)));
  for (auto &[name, accounts] : data.object()) {
    if (name != "accounts")
      continue;
    for (auto &account : accounts.array()) {
      replace_field(account, "kind", Value{"oauth"});
      replace_field(account, "refresh", Value{"fixture-legacy-refresh"});
      replace_field(account, "expires_at", Value{Number{"1120"}});
      replace_field(account, "scope", Value{"user:inference"});
      replace_field(account, "client_id", Value{"fixture-legacy-client"});
      replace_field(account, "token_url",
                    Value{"https://console.anthropic.com/v1/oauth/token"});
      replace_field(account, "metadata", Value::object({}));
    }
  }
  {
    std::ofstream out{store, std::ios::binary | std::ios::trunc};
    out << unwrap(encode_packet_string(data));
    check(static_cast<bool>(out), "legacy credential fixture write failed");
  }
  check(::setenv("ANTHROPIC_API_KEY", "fixture-forbidden-fallback", 1) == 0,
        "fixture environment setup failed");
  ProviderAuth legacy{legacy_config};
  check(legacy.selected("anthropic") &&
            account_state(legacy, "anthropic", "max") == "ready",
        "legacy Anthropic OAuth fixture not loaded");
  for (const std::int64_t at : {1000, 1100}) {
    clock = at;
    rejects_with([&] { (void)legacy.request("anthropic", "messages", body, 10); },
                 ErrorCode::provider_auth);
  }
  check(legacy_requests == 0,
        "legacy Anthropic OAuth credential was sent, refreshed or replaced");
  legacy.logout("anthropic", "max");
  check(account_state(legacy, "anthropic", "max") == "logged_out" &&
            legacy_requests == 0,
        "legacy Anthropic OAuth credential could not be removed locally");
  check(::unsetenv("ANTHROPIC_API_KEY") == 0, "fixture environment cleanup failed");
}
// Refresh failure handling for a provider that does offer OAuth login.
void oauth_refresh_failure_checks(const std::filesystem::path &directory) {
  constexpr std::string_view client = "17e5f671-d194-4dfb-9706-5516cb48c098";
  constexpr std::string_view token_url = "https://auth.kimi.com/api/oauth/token";
  const auto body = unwrap(parse_json(
      R"({"model":"fixture-model","max_tokens":64,"messages":[{"role":"user","content":"fixture input"}]})"));
  std::int64_t clock = 1000;
  // A selected account blocks ambient API-key fallback in every failure state.
  check(::setenv("KIMI_API_KEY", "fixture-forbidden-fallback", 1) == 0,
        "fixture environment setup failed");
  for (const int outcome : {429, 503, 400, 200, 0}) {
    ProviderAuthConfig failure_config;
    failure_config.now = [&] { return clock; };
    failure_config.directory = directory / ("kimi-failure-" + std::to_string(outcome));
    unsigned refreshes = 0, application_requests = 0;
    failure_config.http = [&](const ProviderHttpRequest &request,
                              ProviderHttpResponseLease &response) {
      if (request.url != token_url) {
        ++application_requests;
        return reply(response, 200, "{}");
      }
      ++refreshes;
      auto fields = params(request.body);
      check(request.method == "POST" &&
                header(request, "Content-Type") ==
                    "application/x-www-form-urlencoded" &&
                header(request, "Accept") == "application/json" && fields.size() == 3 &&
                fields["grant_type"] == "refresh_token" &&
                fields["client_id"] == client &&
                fields["refresh_token"] == "fixture-failure-refresh",
            "OAuth failure refresh grant differs");
      if (refreshes > 1)
        return reply(
            response, 200,
            R"({"access_token":"fixture-recovered-access","refresh_token":"fixture-recovered-refresh","expires_in":120})");
      if (outcome == 0)
        throw Error{ErrorCode::external_unknown, 77};
      if (outcome == 200)
        return reply(
            response, 200,
            R"({"access_token":"fixture-invalid-access","refresh_token":"fixture-invalid-refresh","expires_in":0})");
      return reply(response, outcome, R"({"error":"fixture failure"})");
    };
    clock = 1000;
    ProviderAuth failed{failure_config};
    failed.save_oauth(
        "kimi", "coding",
        unwrap(parse_json(
            R"({"access_token":"fixture-failure-access","refresh_token":"fixture-failure-refresh","expires_in":120})")),
        std::string{client}, std::string{token_url});
    clock = 1060;
    const auto request = [&] { (void)failed.request("kimi", "messages", body, 10); };
    const bool transient = outcome == 429 || outcome == 503;
    const auto code = transient        ? ErrorCode::provider_rate_limit
                      : outcome == 0   ? ErrorCode::external_unknown
                      : outcome == 200 ? ErrorCode::corrupt
                                       : ErrorCode::provider_auth;
    rejects_with(request, code, outcome == 0 ? 77 : outcome == 200 ? 0 : -outcome);
    check(refreshes == 1 && application_requests == 0 &&
              account_state(failed, "kimi", "coding") == (transient ? "ready"
                                                          : outcome == 400
                                                              ? "reauthorize"
                                                              : "refresh_unknown"),
          "OAuth refresh failure state differs");
    rejects_with(request,
                 transient ? ErrorCode::provider_rate_limit : ErrorCode::provider_auth,
                 transient ? -429 : 0);
    check(refreshes == 1 && application_requests == 0,
          "OAuth failure retried HTTP or fell back to an API key");
    clock = 1119;
    if (transient) {
      rejects_with(request, ErrorCode::provider_rate_limit, -429);
      check(refreshes == 1 && application_requests == 0,
            "OAuth cooldown ended before its boundary");
    }
    clock = 1120;
    if (transient) {
      request();
      check(refreshes == 2 && application_requests == 1 &&
                account_state(failed, "kimi", "coding") == "ready",
            "OAuth cooldown did not recover at boundary");
    } else {
      rejects_with(request, ErrorCode::provider_auth);
      check(refreshes == 1 && application_requests == 0,
            "OAuth terminal failure silently resumed");
    }
  }
  check(::unsetenv("KIMI_API_KEY") == 0, "fixture environment cleanup failed");
}
int main() {
  char directory[] = "/tmp/blackbird-oauth-test-XXXXXX";
  const auto *tmp = ::mkdtemp(directory);
  if (!tmp)
    return 1;
  try {
    ProviderAuthConfig config;
    config.directory = std::filesystem::path{tmp} / "auth";
    config.now = [] { return 1000; };
    check(auth_pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", config) ==
              "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          "RFC7636 challenge mismatch");
    const auto private_file = std::filesystem::path{tmp} / "key.pem";
    write_file(private_file.string(), run({"/usr/bin/openssl", "genrsa", "2048"}));
    auto modulus = run({"/usr/bin/openssl", "rsa", "-in", private_file.string(),
                        "-modulus", "-noout"});
    check(modulus.starts_with("Modulus="), "RSA modulus absent");
    modulus = modulus.substr(8);
    while (modulus.ends_with('\n'))
      modulus.pop_back();
    std::string n;
    for (std::size_t i = 0; i < modulus.size(); i += 2) {
      unsigned v = 0;
      auto r = std::from_chars(modulus.data() + i, modulus.data() + i + 2, v, 16);
      check(r.ec == std::errc{}, "modulus hex");
      n += static_cast<char>(v);
    }
    const auto jwks = Value::object(
        {{"keys", Value{Value::Array{Value::object({{"kid", Value{"test"}},
                                                    {"kty", Value{"RSA"}},
                                                    {"n", Value{encode(n)}},
                                                    {"e", Value{"AQAB"}}})}}}});
    auto sign = [&](std::string nonce = "nonce", std::string client = "issued",
                    int expires = 2000) {
      const auto header = encode(R"({"alg":"RS256","kid":"test"})");
      const auto claims = unwrap(
          dump_json(Value::object({{"iss", Value{"https://auth.openai.com"}},
                                   {"aud", Value{std::move(client)}},
                                   {"nonce", Value{std::move(nonce)}},
                                   {"sub", Value{"subject"}},
                                   {"exp", Value{Number{std::to_string(expires)}}}})));
      const auto body = header + "." + encode(claims);
      return body + "." +
             encode(run({"/usr/bin/openssl", "dgst", "-sha256", "-sign",
                         private_file.string()},
                        body));
    };
    auto token = sign();
    check(
        auth_validate_openai_identity(
            {.token = token, .client = "issued", .nonce = "nonce"}, jwks, 1000, config)
                .find("sub")
                ->string() == "subject",
        "valid JWT failed");
    rejects([&] {
      (void)auth_validate_openai_identity(
          {.token = token, .client = "wrong", .nonce = "nonce"}, jwks, 1000, config);
    });
    rejects([&] {
      (void)auth_validate_openai_identity(
          {.token = token, .client = "issued", .nonce = "wrong"}, jwks, 1000, config);
    });
    rejects([&] {
      (void)auth_validate_openai_identity(
          {.token = sign("nonce", "issued", 900), .client = "issued", .nonce = "nonce"},
          jwks, 1000, config);
    });
    token[token.size() - 10] = token[token.size() - 10] == 'A' ? 'B' : 'A';
    rejects([&] {
      (void)auth_validate_openai_identity(
          {.token = token, .client = "issued", .nonce = "nonce"}, jwks, 1000, config);
    });
    rejects([&] {
      (void)auth_validate_openai_identity(
          {.token = "eyJhbGciOiJub25lIn0.e30.", .client = "issued", .nonce = "nonce"},
          jwks, 1000, config);
    });
    std::map<std::string, std::string> authorization;
    config.http = [&](const ProviderHttpRequest &r,
                      ProviderHttpResponseLease &response) {
      if (r.url.ends_with("jwks.json"))
        return reply(response, 200, unwrap(dump_json(jwks)));
      auto fields = params(r.body);
      check(fields["client_id"] == "issued", "dynamic client used for exchange");
      check(fields["redirect_uri"] == authorization["redirect_uri"],
            "redirect changed");
      check(auth_pkce_challenge(fields["code_verifier"], config) ==
                authorization["code_challenge"],
            "PKCE linkage");
      return reply(
          response, 200,
          unwrap(dump_json(Value::object(
              {{"access_token", Value{"fixture-access"}},
               {"refresh_token", Value{"fixture-refresh"}},
               {"expires_in", Value{Number{"3600"}}},
               {"id_token", Value{sign(authorization["nonce"])}},
               {"scope",
                Value{"openid resource.invoke chatgpt.tokens.use.direct"}}}))));
    };
    ProviderAuth auth{config};
    std::thread browser;
    try {
      auth.browser_login(
          "openai", "personal",
          [&](std::string_view notice) {
            const auto start = notice.find("https://auth.openai.com/");
            if (start == std::string_view::npos)
              return;
            const auto line = notice.substr(start, notice.find('\n', start) - start);
            authorization = params(line.substr(line.find('?') + 1));
            check(authorization["client_id"] == "dynamic_agent_client",
                  "initial registration wrong");
            browser = std::thread{[&] {
              const auto &uri = authorization["redirect_uri"];
              const auto colon = uri.find(':', 7), slash = uri.find('/', colon);
              const auto port = std::stoi(uri.substr(colon + 1, slash - colon - 1));
              for (const bool correct : {false, true}) {
                const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0)
                  throw Error{ErrorCode::io};
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                addr.sin_port = htons(static_cast<std::uint16_t>(port));
                check(::connect(fd, reinterpret_cast<sockaddr *>(&addr),
                                sizeof(addr)) == 0,
                      "callback connect");
                const auto req =
                    "GET /auth/callback?code=fixture&client_id=issued&state=" +
                    (correct ? authorization["state"] : "wrong") +
                    " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
                (void)::write(fd, req.data(), req.size());
                char bytes[512];
                const auto got = ::read(fd, bytes, sizeof(bytes));
                check(got > 0, "callback reply missing");
                const std::string_view response{bytes, static_cast<std::size_t>(got)};
                check(response.starts_with(correct ? "HTTP/1.1 200" : "HTTP/1.1 400"),
                      "callback state not checked");
                (void)::close(fd);
              }
            }};
          },
          [] { return std::string{}; });
    } catch (...) {
      if (browser.joinable())
        browser.join();
      throw;
    }
    browser.join();
    check(auth.selected("openai"), "browser account not selected");
    check(unwrap(dump_json(auth.status())).find("fixture-access") == std::string::npos,
          "status token leak");
    auto saved = auth.registration("openai", "personal");
    auth.logout("openai", "personal");
    const auto retained = auth.registration("openai", "personal");
    check(retained.find("client_id")->string() == "issued",
          "logout discarded registration");
    rejects([&] {
      auth.save_oauth(
          "openai", "personal",
          unwrap(parse_json(
              R"({"access_token":"a","refresh_token":"r","expires_in":3600})")),
          "issued", auth.descriptor("openai").find("token_url")->string(),
          Value::object({}),
          {.account_revision = std::stoll(saved.find("revision")->number().text())});
    });
    anthropic_key_only_checks(tmp);
    oauth_refresh_failure_checks(tmp);
    std::filesystem::remove_all(tmp);
    std::cout << "provider OAuth checks passed\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
  } catch (const Error &e) {
    std::cerr << error_name(e.code) << ':' << e.detail << '\n';
  }
  std::filesystem::remove_all(tmp);
  return 1;
}
