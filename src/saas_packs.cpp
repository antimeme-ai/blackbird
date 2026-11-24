#include "blackbird/saas_packs.hpp"
#include "blackbird/embedded_resources.hpp"
#include "blackbird/integrations_runtime.hpp"
#include "blackbird/json.hpp"

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace blackbird {
namespace {

std::string ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text)
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  return out;
}

std::string ascii_upper(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text)
    out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
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

bool valid_header_token(std::string_view text) noexcept {
  if (text.empty())
    return false;
  for (const char ch : text) {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (c <= 0x20U || c >= 0x7FU || c == ':')
      return false;
  }
  return true;
}

bool valid_header_value(std::string_view text) noexcept {
  for (const char ch : text) {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (c == '\r' || c == '\n' || c == '\0')
      return false;
  }
  return true;
}

bool is_forbidden_lua_header(std::string_view lower_name) noexcept {
  return lower_name == "authorization" || lower_name == "proxy-authorization" ||
         lower_name == "cookie" || lower_name == "set-cookie" || lower_name == "host" ||
         lower_name == "transfer-encoding" || lower_name == "content-length";
}

bool is_sensitive_response_header(std::string_view lower_name) noexcept {
  return lower_name == "authorization" || lower_name == "proxy-authorization" ||
         lower_name == "cookie" || lower_name == "set-cookie" ||
         lower_name == "x-auth-token" || lower_name == "x-api-key";
}

std::string url_percent_encode(std::string_view input) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(input.size() * 2U);
  for (const char ch : input) {
    const unsigned char c = static_cast<unsigned char>(ch);
    const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                            c == '.' || c == '~';
    if (unreserved) {
      out.push_back(ch);
    } else {
      out.push_back('%');
      out.push_back(kHex[(c >> 4U) & 0x0FU]);
      out.push_back(kHex[c & 0x0FU]);
    }
  }
  return out;
}

std::string base64url_encode(std::string_view input) {
  static constexpr char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve(((input.size() + 2U) / 3U) * 4U);
  std::size_t i = 0U;
  while (i + 2U < input.size()) {
    const std::uint32_t triple =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1U])) << 8U) |
        static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 2U]));
    out.push_back(kTable[(triple >> 18U) & 0x3FU]);
    out.push_back(kTable[(triple >> 12U) & 0x3FU]);
    out.push_back(kTable[(triple >> 6U) & 0x3FU]);
    out.push_back(kTable[triple & 0x3FU]);
    i += 3U;
  }
  const std::size_t rem = input.size() - i;
  if (rem == 1U) {
    const std::uint32_t val =
        static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16U;
    out.push_back(kTable[(val >> 18U) & 0x3FU]);
    out.push_back(kTable[(val >> 12U) & 0x3FU]);
  } else if (rem == 2U) {
    const std::uint32_t val =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1U])) << 8U);
    out.push_back(kTable[(val >> 18U) & 0x3FU]);
    out.push_back(kTable[(val >> 12U) & 0x3FU]);
    out.push_back(kTable[(val >> 6U) & 0x3FU]);
  }
  return out;
}

std::string base64url_decode(std::string_view input) {
  auto decode_char = [](unsigned char c) noexcept -> int {
    if (c >= 'A' && c <= 'Z')
      return c - 'A';
    if (c >= 'a' && c <= 'z')
      return 26 + (c - 'a');
    if (c >= '0' && c <= '9')
      return 52 + (c - '0');
    if (c == '-' || c == '+')
      return 62;
    if (c == '_' || c == '/')
      return 63;
    return -1;
  };
  std::string out;
  out.reserve((input.size() * 3U) / 4U);
  std::uint32_t buf = 0;
  int bits = 0;
  for (const char ch : input) {
    if (ch == '=' || ch == '\r' || ch == '\n' || ch == ' ')
      continue;
    const int val = decode_char(static_cast<unsigned char>(ch));
    if (val < 0)
      continue;
    buf = (buf << 6U) | static_cast<std::uint32_t>(val);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buf >> static_cast<unsigned>(bits)) & 0xFFU));
    }
  }
  return out;
}

bool text_contains_keyword_token(std::string_view lower_text,
                                 std::string_view keyword) noexcept {
  std::size_t pos = 0U;
  while ((pos = lower_text.find(keyword, pos)) != std::string_view::npos) {
    const bool left_ok =
        pos == 0U ||
        (std::isalnum(static_cast<unsigned char>(lower_text[pos - 1U])) == 0 &&
         lower_text[pos - 1U] != '_');
    const std::size_t end = pos + keyword.size();
    const bool right_ok =
        end >= lower_text.size() ||
        (std::isalnum(static_cast<unsigned char>(lower_text[end])) == 0 &&
         lower_text[end] != '_');
    if (left_ok && right_ok)
      return true;
    pos = end;
  }
  return false;
}

bool graphql_text_is_mutating(std::string_view text) {
  const std::string lower = ascii_lower(text);
  return text_contains_keyword_token(lower, "mutation") ||
         text_contains_keyword_token(lower, "subscription");
}

struct GraphqlInspectInput {
  std::string_view relative_path;
  std::string_view body;
};

// Inspects both decoded JSON "query" field (defeating \u006dutation Unicode
// escapes) and raw body. Fails closed (returns true -> upgrade to write) on
// unparseable or non-object POST bodies targeting a /graphql endpoint.
bool graphql_body_has_mutation(GraphqlInspectInput input) {
  if (graphql_text_is_mutating(input.body))
    return true;
  const bool is_graphql_path =
      ascii_lower(input.relative_path).find("graphql") != std::string::npos;
  auto parsed = parse_json(input.body);
  if (!parsed.has_value())
    return is_graphql_path;
  if (!std::holds_alternative<Value::Object>(parsed.value().value()))
    return is_graphql_path;
  if (const Value *q = parsed.value().find("query");
      q != nullptr && std::holds_alternative<std::string>(q->value())) {
    return graphql_text_is_mutating(q->string());
  }
  return is_graphql_path;
}

brakes::ToolEffectClass saas_effect_to_brakes(SaasEffectClass effect) noexcept {
  switch (effect) {
  case SaasEffectClass::read:
    return brakes::ToolEffectClass::read_only;
  case SaasEffectClass::write:
    return brakes::ToolEffectClass::outbound_network;
  case SaasEffectClass::send:
  case SaasEffectClass::del:
    return brakes::ToolEffectClass::exec;
  }
  return brakes::ToolEffectClass::exec;
}

// ---------------------------------------------------------------------------
// Lua <-> blackbird::Value Conversion (Safe, Bounded)
// ---------------------------------------------------------------------------

void push_value_to_lua(lua_State *L, const Value &v, std::size_t depth = 0) {
  if (depth > 64U) {
    lua_pushnil(L);
    return;
  }
  std::visit(
      [&](const auto &item) {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
          lua_pushnil(L);
        } else if constexpr (std::is_same_v<T, bool>) {
          lua_pushboolean(L, item ? 1 : 0);
        } else if constexpr (std::is_same_v<T, std::string>) {
          lua_pushlstring(L, item.data(), item.size());
        } else if constexpr (std::is_same_v<T, Number>) {
          std::visit(
              [&](const auto &n) {
                using N = std::decay_t<decltype(n)>;
                if constexpr (std::is_same_v<N, std::int64_t>) {
                  lua_pushinteger(L, n);
                } else if constexpr (std::is_same_v<N, std::uint64_t>) {
                  if (n <= static_cast<std::uint64_t>(INT64_MAX))
                    lua_pushinteger(L, static_cast<lua_Integer>(n));
                  else
                    lua_pushnumber(L, static_cast<lua_Number>(n));
                } else if constexpr (std::is_same_v<N, double>) {
                  lua_pushnumber(L, n);
                } else {
                  const std::string t = item.text();
                  lua_pushlstring(L, t.data(), t.size());
                }
              },
              item.storage());
        } else if constexpr (std::is_same_v<T, Value::Array>) {
          lua_createtable(
              L, static_cast<int>(std::min<std::size_t>(item.size(), INT_MAX)), 0);
          for (std::size_t i = 0U; i < item.size(); ++i) {
            push_value_to_lua(L, item[i], depth + 1U);
            lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1U));
          }
        } else {
          lua_createtable(
              L, 0, static_cast<int>(std::min<std::size_t>(item.size(), INT_MAX)));
          for (const auto &[k, val] : item) {
            lua_pushlstring(L, k.data(), k.size());
            push_value_to_lua(L, val, depth + 1U);
            lua_rawset(L, -3);
          }
        }
      },
      v.value());
}

struct LuaReadBudget {
  std::size_t depth = 0;
  std::size_t *nodes = nullptr;
};

Result<Value> read_value_from_lua(lua_State *L, int index, LuaReadBudget budget) {
  const std::size_t depth = budget.depth;
  std::size_t &nodes = *budget.nodes;
  if (depth > 64U || ++nodes > 200000U)
    return Result<Value>::failure({ErrorCode::capacity});
  index = lua_absindex(L, index);
  switch (lua_type(L, index)) {
  case LUA_TNIL:
    return Result<Value>::success(Value{});
  case LUA_TBOOLEAN:
    return Result<Value>::success(Value{lua_toboolean(L, index) != 0});
  case LUA_TSTRING: {
    std::size_t len = 0;
    const char *s = lua_tolstring(L, index, &len);
    return Result<Value>::success(Value{std::string{s, len}});
  }
  case LUA_TNUMBER:
    if (lua_isinteger(L, index))
      return Result<Value>::success(
          Value{Number{static_cast<std::int64_t>(lua_tointeger(L, index))}});
    return Result<Value>::success(
        Value{Number{static_cast<double>(lua_tonumber(L, index))}});
  case LUA_TTABLE: {
    const std::size_t arr_len = lua_rawlen(L, index);
    bool is_array_table = (arr_len > 0U);
    if (is_array_table) {
      std::size_t count = 0U;
      lua_pushnil(L);
      while (lua_next(L, index) != 0) {
        if (!lua_isinteger(L, -2)) {
          is_array_table = false;
          lua_pop(L, 2);
          break;
        }
        const lua_Integer k = lua_tointeger(L, -2);
        if (k < 1 || static_cast<std::size_t>(k) > arr_len) {
          is_array_table = false;
          lua_pop(L, 2);
          break;
        }
        ++count;
        lua_pop(L, 1);
      }
      if (count != arr_len)
        is_array_table = false;
    }

    if (is_array_table) {
      Value::Array arr;
      arr.reserve(arr_len);
      for (std::size_t i = 1U; i <= arr_len; ++i) {
        lua_rawgeti(L, index, static_cast<lua_Integer>(i));
        auto elem = read_value_from_lua(L, -1, LuaReadBudget{depth + 1U, &nodes});
        lua_pop(L, 1);
        if (!elem.has_value())
          return elem;
        arr.push_back(std::move(elem.value()));
      }
      return Result<Value>::success(Value{std::move(arr)});
    }

    Value::Object obj;
    lua_pushnil(L);
    while (lua_next(L, index) != 0) {
      if (lua_type(L, -2) != LUA_TSTRING) {
        lua_pop(L, 2);
        return Result<Value>::failure({ErrorCode::invalid_range});
      }
      std::size_t klen = 0;
      const char *kstr = lua_tolstring(L, -2, &klen);
      std::string key{kstr, klen};
      auto val = read_value_from_lua(L, -1, LuaReadBudget{depth + 1U, &nodes});
      lua_pop(L, 1);
      if (!val.has_value()) {
        lua_pop(L, 1);
        return val;
      }
      obj.emplace_back(std::move(key), std::move(val.value()));
    }
    std::ranges::sort(obj,
                      [](const auto &a, const auto &b) { return a.first < b.first; });
    return Result<Value>::success(Value::object(std::move(obj)));
  }
  default:
    return Result<Value>::failure({ErrorCode::unsupported});
  }
}

struct LuaSandboxContext {
  SaasPackId pack_id{};
  const SaasPackManifest *manifest = nullptr;
  std::string operation;
  std::string account;
  const PinnedHttpFn *http_transport = nullptr;
  brakes::BrakesGate *brakes_gate = nullptr;
  AuditLog *audit_log = nullptr;

  std::size_t heap_bytes = 0;
  std::size_t max_heap_bytes = kSaasPackMaxHeapBytes;
  std::uint64_t instructions = 0;
  std::uint64_t max_instructions = kSaasPackMaxLuaInstructions;
  std::size_t http_requests_made = 0;

  bool blocked_by_host_pin = false;
  bool blocked_by_brakes = false;
  bool instruction_budget_exceeded = false;
  brakes::BrakesDecision brakes_decision = brakes::BrakesDecision::make_allow();
  std::string error_detail;
  std::vector<std::string> raw_http_bodies;
  std::optional<brakes::PeerProvenance> pending_http_taint;
  bool tainted_via_http = false;
};

extern "C" {

static void *saas_lua_alloc(void *const ud, void *ptr, std::size_t osize,
                            std::size_t nsize) noexcept {
  auto *ctx = static_cast<LuaSandboxContext *>(ud);
  const std::size_t old_size = ptr != nullptr ? osize : 0U;
  if (nsize == 0U) {
    if (ptr != nullptr) {
      ctx->heap_bytes = ctx->heap_bytes >= old_size ? (ctx->heap_bytes - old_size) : 0U;
      std::free(ptr);
    }
    return nullptr;
  }
  if (nsize > old_size && (nsize - old_size) > (ctx->max_heap_bytes - ctx->heap_bytes))
    return nullptr;
  void *next = std::realloc(ptr, nsize);
  if (next != nullptr) {
    ctx->heap_bytes = ctx->heap_bytes - old_size + nsize;
  }
  return next;
}

void saas_lua_instruction_hook(lua_State *L, lua_Debug *ar) {
  (void)ar;
  auto *ctx = *static_cast<LuaSandboxContext **>(lua_getextraspace(L));
  if (ctx->blocked_by_host_pin || ctx->blocked_by_brakes ||
      ctx->instruction_budget_exceeded) {
    // Keep unwinding every VM instruction (count=1) so nested pcall() loops
    // cannot swallow security blocks or instruction budget exhaustion.
    lua_sethook(L, saas_lua_instruction_hook, LUA_MASKCOUNT, 1);
    luaL_error(L, "%s",
               ctx->error_detail.empty() ? "sandbox execution aborted"
                                         : ctx->error_detail.c_str());
  }
  ctx->instructions += 10000U;
  if (ctx->instructions > ctx->max_instructions) {
    ctx->instruction_budget_exceeded = true;
    ctx->error_detail = "Lua pack exceeded instruction budget";
    lua_sethook(L, saas_lua_instruction_hook, LUA_MASKCOUNT, 1);
    luaL_error(L, "instruction budget exceeded");
  }
}

int saas_lua_url_encode(lua_State *L) {
  std::size_t len = 0;
  const char *s = luaL_checklstring(L, 1, &len);
  const std::string encoded = url_percent_encode(std::string_view{s, len});
  lua_pushlstring(L, encoded.data(), encoded.size());
  return 1;
}

int saas_lua_base64url_encode(lua_State *L) {
  std::size_t len = 0;
  const char *s = luaL_checklstring(L, 1, &len);
  const std::string encoded = base64url_encode(std::string_view{s, len});
  lua_pushlstring(L, encoded.data(), encoded.size());
  return 1;
}

int saas_lua_base64url_decode(lua_State *L) {
  std::size_t len = 0;
  const char *s = luaL_checklstring(L, 1, &len);
  const std::string decoded = base64url_decode(std::string_view{s, len});
  lua_pushlstring(L, decoded.data(), decoded.size());
  return 1;
}

int saas_lua_json_encode(lua_State *L) {
  const char *err_msg = nullptr;
  {
    std::size_t nodes = 0;
    auto val = read_value_from_lua(L, 1, LuaReadBudget{0U, &nodes});
    if (!val.has_value()) {
      err_msg = "json.encode: unsupported value";
    } else {
      auto dumped = dump_json(val.value());
      if (!dumped.has_value()) {
        err_msg = "json.encode: serialization failed";
      } else {
        lua_pushlstring(L, dumped.value().data(), dumped.value().size());
      }
    }
  }
  if (err_msg != nullptr)
    return luaL_error(L, "%s", err_msg);
  return 1;
}

int saas_lua_json_decode(lua_State *L) {
  const char *err_msg = nullptr;
  {
    std::size_t len = 0;
    const char *s = luaL_checklstring(L, 1, &len);
    auto parsed = parse_json(std::string_view{s, len});
    if (!parsed.has_value()) {
      err_msg = "json.decode: invalid JSON";
    } else {
      push_value_to_lua(L, parsed.value());
    }
  }
  if (err_msg != nullptr)
    return luaL_error(L, "%s", err_msg);
  return 1;
}

int saas_lua_http_request_impl(lua_State *L, const char *&err_msg) {
  auto *ctx = *static_cast<LuaSandboxContext **>(lua_getextraspace(L));
  if (ctx->blocked_by_host_pin || ctx->blocked_by_brakes ||
      ctx->instruction_budget_exceeded) {
    lua_sethook(L, saas_lua_instruction_hook, LUA_MASKCOUNT, 1);
    err_msg = "sandbox request aborted";
    return -1;
  }
  if (lua_type(L, 1) != LUA_TTABLE) {
    err_msg = "http.request expects a table argument";
    return -1;
  }

  if (ctx->http_requests_made >= kSaasPackMaxHttpRequestsPerCall) {
    ctx->error_detail = "pack exceeded per-call HTTP request limit";
    err_msg = "per-call HTTP request limit exceeded";
    return -1;
  }

  // Reject arbitrary URL overrides immediately (SSRF / host-pin enforcement).
  lua_getfield(L, 1, "url");
  if (!lua_isnil(L, -1)) {
    lua_pop(L, 1);
    ctx->blocked_by_host_pin = true;
    ctx->error_detail =
        "SSRF host-pin violation: Lua packs must use pinned service + relative path, "
        "never arbitrary url";
    err_msg = "host-pin violation: arbitrary url rejected";
    return -1;
  }
  lua_pop(L, 1);

  // Verify service matches the executing pack's authoritative manifest.
  lua_getfield(L, 1, "service");
  if (!lua_isnil(L, -1)) {
    if (lua_type(L, -1) != LUA_TSTRING) {
      lua_pop(L, 1);
      ctx->blocked_by_host_pin = true;
      ctx->error_detail = "invalid service field type";
      err_msg = "invalid service field";
      return -1;
    }
    std::size_t slen = 0;
    const char *sptr = lua_tolstring(L, -1, &slen);
    const std::string_view req_service{sptr, slen};
    if (req_service != ctx->manifest->service) {
      lua_pop(L, 1);
      ctx->blocked_by_host_pin = true;
      ctx->error_detail = "SSRF/credential-isolation violation: pack cannot "
                          "impersonate another service";
      err_msg = "host-pin violation: service mismatch";
      return -1;
    }
  }
  lua_pop(L, 1);

  // Read optional host override (must still be in manifest.allowed_hosts!).
  std::string requested_host;
  lua_getfield(L, 1, "host");
  if (!lua_isnil(L, -1)) {
    if (lua_type(L, -1) != LUA_TSTRING) {
      lua_pop(L, 1);
      ctx->blocked_by_host_pin = true;
      ctx->error_detail = "host-pin violation: host must be a string";
      err_msg = "host-pin violation: invalid host";
      return -1;
    }
    std::size_t hlen = 0;
    const char *hptr = lua_tolstring(L, -1, &hlen);
    requested_host.assign(hptr, hlen);
  }
  lua_pop(L, 1);

  // Read required relative path.
  lua_getfield(L, 1, "path");
  if (lua_type(L, -1) != LUA_TSTRING) {
    lua_pop(L, 1);
    ctx->blocked_by_host_pin = true;
    ctx->error_detail = "host-pin violation: relative path string required";
    err_msg = "host-pin violation: path required";
    return -1;
  }
  std::size_t plen = 0;
  const char *pptr = lua_tolstring(L, -1, &plen);
  const std::string rel_path{pptr, plen};
  lua_pop(L, 1);

  // Build percent-encoded query string from optional query table.
  std::string query_str;
  lua_getfield(L, 1, "query");
  if (!lua_isnil(L, -1)) {
    if (lua_type(L, -1) != LUA_TTABLE) {
      lua_pop(L, 1);
      err_msg = "query must be a table";
      return -1;
    }
    std::vector<std::pair<std::string, std::string>> q_pairs;
    lua_pushnil(L);
    while (lua_next(L, -2) != 0) {
      if (lua_type(L, -2) == LUA_TSTRING && !lua_isnil(L, -1)) {
        std::size_t klen = 0;
        const char *kptr = lua_tolstring(L, -2, &klen);
        std::string k{kptr, klen};
        std::string v;
        if (lua_type(L, -1) == LUA_TSTRING) {
          std::size_t vlen = 0;
          const char *vptr = lua_tolstring(L, -1, &vlen);
          v.assign(vptr, vlen);
        } else if (lua_type(L, -1) == LUA_TBOOLEAN) {
          v = lua_toboolean(L, -1) != 0 ? "true" : "false";
        } else if (lua_type(L, -1) == LUA_TNUMBER) {
          if (lua_isinteger(L, -1))
            v = std::to_string(lua_tointeger(L, -1));
          else
            v = std::to_string(lua_tonumber(L, -1));
        }
        q_pairs.emplace_back(std::move(k), std::move(v));
      }
      lua_pop(L, 1);
    }
    std::ranges::sort(q_pairs);
    for (const auto &[k, v] : q_pairs) {
      if (!query_str.empty())
        query_str.push_back('&');
      query_str.append(url_percent_encode(k));
      query_str.push_back('=');
      query_str.append(url_percent_encode(v));
    }
  }
  lua_pop(L, 1);

  // Enforce C++ host pinning and path containment!
  std::string resolved_host;
  auto pinned_url = build_pinned_https_url(
      PinnedUrlInput{ctx->manifest->allowed_hosts, requested_host, rel_path, query_str},
      &resolved_host);
  if (!pinned_url.has_value()) {
    ctx->blocked_by_host_pin = true;
    ctx->error_detail =
        "SSRF host-pin violation: rejected host/path '" +
        (requested_host.empty() ? std::string{"<default>"} : requested_host) + "' '" +
        rel_path + "'";
    err_msg = "host-pin violation";
    return -1;
  }

  // Validate HTTP method.
  std::string method = "GET";
  lua_getfield(L, 1, "method");
  if (lua_type(L, -1) == LUA_TSTRING) {
    std::size_t mlen = 0;
    const char *mptr = lua_tolstring(L, -1, &mlen);
    method = ascii_upper(std::string_view{mptr, mlen});
  }
  lua_pop(L, 1);
  if (method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" &&
      method != "DELETE") {
    err_msg = "unsupported HTTP method";
    return -1;
  }

  // Read safe Lua headers, strictly blocking Authorization/Cookie/Host.
  std::vector<std::pair<std::string, std::string>> headers;
  auto has_hdr = [&](std::string_view lower_k) {
    for (const auto &[ek, ev] : headers) {
      (void)ev;
      if (ascii_lower(ek) == lower_k)
        return true;
    }
    return false;
  };

  lua_getfield(L, 1, "headers");
  if (!lua_isnil(L, -1)) {
    if (lua_type(L, -1) != LUA_TTABLE) {
      lua_pop(L, 1);
      err_msg = "headers must be a table";
      return -1;
    }
    lua_pushnil(L);
    while (lua_next(L, -2) != 0) {
      if (lua_type(L, -2) == LUA_TSTRING && lua_type(L, -1) == LUA_TSTRING) {
        std::size_t klen = 0, vlen = 0;
        const char *kptr = lua_tolstring(L, -2, &klen);
        const char *vptr = lua_tolstring(L, -1, &vlen);
        const std::string_view ksv{kptr, klen};
        const std::string_view vsv{vptr, vlen};
        const std::string lk = ascii_lower(ksv);
        if (!valid_header_token(ksv) || !valid_header_value(vsv) ||
            is_forbidden_lua_header(lk)) {
          lua_pop(L, 3);
          ctx->blocked_by_host_pin = true;
          ctx->error_detail =
              "security violation: Lua pack attempted to set forbidden header '" + lk +
              "'";
          err_msg = "forbidden header rejected";
          return -1;
        }
        headers.emplace_back(std::string{ksv}, std::string{vsv});
      }
      lua_pop(L, 1);
    }
  }
  lua_pop(L, 1);

  for (const auto &[dk, dv] : ctx->manifest->default_headers) {
    if (!has_hdr(ascii_lower(dk)))
      headers.emplace_back(dk, dv);
  }

  // Read optional json or raw body.
  std::string body;
  lua_getfield(L, 1, "json");
  if (!lua_isnil(L, -1)) {
    std::size_t nodes = 0;
    auto val = read_value_from_lua(L, -1, LuaReadBudget{0U, &nodes});
    lua_pop(L, 1);
    if (!val.has_value()) {
      err_msg = "invalid json body";
      return -1;
    }
    auto dumped = dump_json(val.value());
    if (!dumped.has_value()) {
      err_msg = "json serialization failed";
      return -1;
    }
    body = std::move(dumped.value());
    if (!has_hdr("content-type"))
      headers.emplace_back("Content-Type", "application/json");
  } else {
    lua_pop(L, 1);
    lua_getfield(L, 1, "body");
    if (lua_type(L, -1) == LUA_TSTRING) {
      std::size_t blen = 0;
      const char *bptr = lua_tolstring(L, -1, &blen);
      body.assign(bptr, blen);
    }
    lua_pop(L, 1);
  }

  // Authoritative effect verification (Lua can tighten, NEVER downgrade!).
  SaasEffectClass op_effect = SaasEffectClass::write;
  for (const auto &op_pol : ctx->manifest->operations) {
    if (op_pol.name == ctx->operation) {
      op_effect = op_pol.effect;
      break;
    }
  }
  SaasEffectClass effective_effect = op_effect;

  lua_getfield(L, 1, "effect");
  if (lua_type(L, -1) == LUA_TSTRING) {
    std::size_t elen = 0;
    const char *eptr = lua_tolstring(L, -1, &elen);
    if (const auto parsed = parse_saas_effect_class(std::string_view{eptr, elen});
        parsed.has_value()) {
      if (static_cast<std::uint8_t>(parsed.value()) >
          static_cast<std::uint8_t>(effective_effect)) {
        effective_effect = parsed.value();
      }
    }
  }
  lua_pop(L, 1);

  if (method == "DELETE")
    effective_effect = SaasEffectClass::del;
  else if ((method == "PUT" || method == "PATCH") &&
           effective_effect == SaasEffectClass::read)
    effective_effect = SaasEffectClass::write;
  else if (method == "POST" && effective_effect == SaasEffectClass::read &&
           graphql_body_has_mutation(GraphqlInspectInput{rel_path, body}))
    effective_effect = SaasEffectClass::write;

  // BrakesGate pre-flight check!
  if (ctx->brakes_gate != nullptr) {
    if (effective_effect != SaasEffectClass::read &&
        ctx->pending_http_taint.has_value()) {
      (void)ctx->brakes_gate->ingest_peer(*ctx->pending_http_taint);
      ctx->tainted_via_http = true;
    }
    brakes::ToolCallRequest gate_req;
    gate_req.tool_name = "saas:" + ctx->manifest->service + "." + ctx->operation;
    gate_req.tool_op = method + " " + rel_path;
    gate_req.effect_class = saas_effect_to_brakes(effective_effect);
    gate_req.requires_network = true;
    const brakes::BrakesDecision dec = ctx->brakes_gate->evaluate_tool_call(gate_req);
    if (!dec.allow) {
      ctx->blocked_by_brakes = true;
      ctx->brakes_decision = dec;
      ctx->error_detail = dec.reason;
      err_msg = "blocked by brakes policy";
      return -1;
    }
  }

  std::chrono::milliseconds timeout{15000};
  lua_getfield(L, 1, "timeout_ms");
  if (lua_isinteger(L, -1)) {
    const auto ms = lua_tointeger(L, -1);
    if (ms > 0 && ms <= 120000)
      timeout = std::chrono::milliseconds{ms};
  }
  lua_pop(L, 1);

  if (ctx->http_transport == nullptr || !(*ctx->http_transport)) {
    ctx->error_detail = "PinnedHttpFn transport not configured";
    err_msg = "HTTP transport unavailable";
    return -1;
  }

  PinnedHttpRequest pinned_req;
  pinned_req.pack_id = ctx->pack_id;
  pinned_req.service = ctx->manifest->service;
  pinned_req.account = ctx->account;
  pinned_req.method = method;
  pinned_req.host = resolved_host;
  pinned_req.path = rel_path;
  pinned_req.url = pinned_url.value();
  pinned_req.headers = std::move(headers);
  pinned_req.body = std::move(body);
  pinned_req.effect = effective_effect;
  pinned_req.timeout = timeout;

  ++ctx->http_requests_made;
  auto resp = (*ctx->http_transport)(pinned_req);
  if (!resp.has_value()) {
    ctx->error_detail = "HTTP transport failure";
    err_msg = "HTTP request failed";
    return -1;
  }

  // Record raw body & latch Brakes taint immediately upon external HTTP ingest.
  ctx->raw_http_bodies.push_back(resp.value().body);
  if (ctx->audit_log != nullptr) {
    Value::Object meta;
    meta.emplace_back("service", Value{ctx->manifest->service});
    meta.emplace_back("operation", Value{ctx->operation});
    meta.emplace_back("host", Value{resolved_host});
    meta.emplace_back("path", Value{rel_path});
    meta.emplace_back(
        "status", Value{Number{static_cast<std::int64_t>(resp.value().status_code)}});
    (void)ctx->audit_log->original(OriginalCapture{
        "http.response.raw", resp.value().body, Value::object(std::move(meta))});
  }
  if (ctx->brakes_gate != nullptr) {
    brakes::PeerProvenance prov;
    prov.origin = brakes::PeerOriginKind::external_mcp;
    prov.safety_number = ctx->manifest->safety_number.empty()
                             ? ("saas:" + ctx->manifest->service + ":" + resolved_host)
                             : ctx->manifest->safety_number;
    prov.is_external_guest = ctx->manifest->is_open_world;
    prov.effective_trust = ctx->manifest->trust_profile;
    ctx->pending_http_taint = std::move(prov);
  }

  // Construct response table for Lua (scrubbing all auth/cookie headers!).
  lua_createtable(L, 0, 4);
  lua_pushinteger(L, resp.value().status_code);
  lua_setfield(L, -2, "status");

  lua_createtable(L, 0, static_cast<int>(resp.value().headers.size()));
  for (const auto &[hk, hv] : resp.value().headers) {
    const std::string lhk = ascii_lower(hk);
    if (is_sensitive_response_header(lhk))
      continue;
    lua_pushlstring(L, lhk.data(), lhk.size());
    lua_pushlstring(L, hv.data(), hv.size());
    lua_rawset(L, -3);
  }
  lua_setfield(L, -2, "headers");

  lua_pushlstring(L, resp.value().body.data(), resp.value().body.size());
  lua_setfield(L, -2, "body");

  if (!resp.value().body.empty()) {
    if (auto parsed = parse_json(resp.value().body); parsed.has_value()) {
      push_value_to_lua(L, parsed.value());
      lua_setfield(L, -2, "json");
    }
  }
  return 1;
}

int saas_lua_http_request(lua_State *L) {
  const char *err_msg = nullptr;
  const int ret = saas_lua_http_request_impl(L, err_msg);
  if (ret < 0)
    return luaL_error(L, "%s", err_msg != nullptr ? err_msg : "http.request failed");
  return ret;
}

} // extern "C"

struct LuaStateGuard {
  lua_State *L = nullptr;
  explicit LuaStateGuard(lua_State *state) noexcept : L(state) {}
  LuaStateGuard(const LuaStateGuard &) = delete;
  LuaStateGuard &operator=(const LuaStateGuard &) = delete;
  ~LuaStateGuard() {
    if (L != nullptr)
      lua_close(L);
  }
};

void open_sandboxed_libs(lua_State *L) {
  static constexpr std::array<luaL_Reg, 6> kSafeLibs{{
      {LUA_GNAME, luaopen_base},
      {LUA_TABLIBNAME, luaopen_table},
      {LUA_STRLIBNAME, luaopen_string},
      {LUA_MATHLIBNAME, luaopen_math},
      {LUA_UTF8LIBNAME, luaopen_utf8},
      {LUA_COLIBNAME, luaopen_coroutine},
  }};
  for (const auto &lib : kSafeLibs) {
    luaL_requiref(L, lib.name, lib.func, 1);
    lua_pop(L, 1);
  }
  // Strip unsafe dynamic code loading and GC manipulation from base.
  for (const char *name : {"dofile", "loadfile", "load", "collectgarbage"}) {
    lua_pushnil(L);
    lua_setglobal(L, name);
  }

  // Install global blackbird table with pinned HTTP + JSON helpers ONLY.
  lua_createtable(L, 0, 2);

  lua_createtable(L, 0, 4);
  lua_pushcfunction(L, saas_lua_http_request);
  lua_setfield(L, -2, "request");
  lua_pushcfunction(L, saas_lua_url_encode);
  lua_setfield(L, -2, "url_encode");
  lua_pushcfunction(L, saas_lua_base64url_encode);
  lua_setfield(L, -2, "base64url_encode");
  lua_pushcfunction(L, saas_lua_base64url_decode);
  lua_setfield(L, -2, "base64url_decode");
  lua_setfield(L, -2, "http");

  lua_createtable(L, 0, 2);
  lua_pushcfunction(L, saas_lua_json_encode);
  lua_setfield(L, -2, "encode");
  lua_pushcfunction(L, saas_lua_json_decode);
  lua_setfield(L, -2, "decode");
  lua_setfield(L, -2, "json");

  lua_setglobal(L, "blackbird");
}

} // namespace

// ---------------------------------------------------------------------------
// Live Executor Registration (bridges command_post_tools -> Lua SaasPackHost)
// ---------------------------------------------------------------------------

namespace {

Result<SaasInvokeOutcome>
execute_live_saas_pack_impl(const SaasPackLiveCallRequest &req) {
  const auto manifest = find_builtin_saas_pack_manifest(req.service);
  if (!manifest.has_value())
    return Result<SaasInvokeOutcome>::failure({ErrorCode::invalid_identity});

  const std::filesystem::path vault_dir =
      req.vault_dir.empty() ? default_integrations_vault_dir() : req.vault_dir;
  const std::filesystem::path packs_dir =
      req.packs_dir.empty() ? default_integrations_packs_dir() : req.packs_dir;
  if (vault_dir.empty())
    return Result<SaasInvokeOutcome>::failure({ErrorCode::invalid_range});

  IntegrationVaultConfig vcfg;
  vcfg.directory = vault_dir;
  IntegrationVault vault{std::move(vcfg)};

  net::HttpClientConfig hcfg =
      req.http_config_override.value_or(net::HttpClientConfig{});
  hcfg.host_policy = net::AllowedHostPolicy::pinned(manifest->allowed_hosts);
  hcfg.host_policy.allow_loopback = req.allow_loopback_for_testing;
  net::HttpClient http{std::move(hcfg)};

  SaasHostConfig scfg;
  scfg.brakes_policy = req.brakes_policy;
  scfg.http_transport = make_live_saas_http_transport(
      http, vault,
      LiveTransportTarget{manifest->service, req.account,
                          req.allow_loopback_for_testing, false});
  SaasPackHost host{std::move(scfg)};

  Result<SaasPackId> pid = Result<SaasPackId>::failure({ErrorCode::io});
  bool disk_present = false;
  if (!packs_dir.empty()) {
    const std::filesystem::path pack_file = packs_dir / (manifest->service + ".lua");
    std::error_code ec;
    if (std::filesystem::is_regular_file(pack_file, ec)) {
      disk_present = true;
      pid = host.load_pack_file(*manifest, pack_file);
    }
  }
  if (!disk_present) {
    if (const auto embedded = find_embedded_saas_pack(manifest->service);
        embedded.has_value()) {
      pid = host.register_pack_source(*manifest, *embedded);
    }
  }
  if (!pid.has_value())
    return Result<SaasInvokeOutcome>::failure(pid.error());

  return host.invoke(SaasInvokeParams{
      manifest->service,
      req.operation,
      req.arguments,
      req.account,
      std::nullopt,
  });
}

struct SaasLiveExecutorRegistrar {
  SaasLiveExecutorRegistrar() noexcept {
    register_saas_pack_live_executor(&execute_live_saas_pack_impl);
  }
};

const SaasLiveExecutorRegistrar kSaasLiveExecutorRegistrar{};

} // namespace

void ensure_saas_pack_live_executor_registered() noexcept {
  register_saas_pack_live_executor(&execute_live_saas_pack_impl);
}

// ---------------------------------------------------------------------------
// SaasPackHost Implementation
// ---------------------------------------------------------------------------

struct SaasPackHost::Impl {
  struct PackRecord {
    SaasPackId pack_id{};
    SaasPackManifest manifest;
    std::string lua_source;
    std::vector<std::string> operation_names;
  };

  PinnedHttpFn http_transport;
  brakes::BrakesGate brakes_gate;
  ToolProjectionPolicy default_projection;
  AuditLog *audit_log = nullptr;
  std::size_t max_lua_heap_bytes = kSaasPackMaxHeapBytes;
  std::uint64_t max_lua_instructions = kSaasPackMaxLuaInstructions;

  std::uint64_t next_pack_id = 1;
  std::uint64_t next_audit_seq = 1;

  // Integer PKs internally; service names are indexed properties.
  std::map<SaasPackId, PackRecord> packs;
  std::map<std::string, SaasPackId, std::less<>> service_index;

  explicit Impl(SaasHostConfig config)
      : http_transport(std::move(config.http_transport)),
        brakes_gate(std::move(config.brakes_policy)),
        default_projection(config.default_projection), audit_log(config.audit_log),
        max_lua_heap_bytes(config.max_lua_heap_bytes),
        max_lua_instructions(config.max_lua_instructions) {}
};

SaasPackHost::SaasPackHost(SaasHostConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}
SaasPackHost::SaasPackHost(SaasPackHost &&) noexcept = default;
SaasPackHost &SaasPackHost::operator=(SaasPackHost &&) noexcept = default;
SaasPackHost::~SaasPackHost() = default;

Result<SaasPackId> SaasPackHost::register_pack_source(SaasPackManifest manifest,
                                                      std::string_view lua_source) {
  if (manifest.service.empty() || manifest.allowed_hosts.empty())
    return Result<SaasPackId>::failure({ErrorCode::invalid_range});
  for (const auto &h : manifest.allowed_hosts) {
    if (!valid_hostname(h))
      return Result<SaasPackId>::failure({ErrorCode::invalid_range});
  }
  for (const auto &[dk, dv] : manifest.default_headers) {
    if (!valid_header_token(dk) || !valid_header_value(dv) ||
        is_forbidden_lua_header(ascii_lower(dk))) {
      return Result<SaasPackId>::failure({ErrorCode::invalid_range});
    }
  }
  if (lua_source.empty() || lua_source.size() > kSaasPackMaxSourceBytes)
    return Result<SaasPackId>::failure({ErrorCode::capacity});
  if (impl_->service_index.contains(manifest.service))
    return Result<SaasPackId>::failure({ErrorCode::conflict});

  // Syntax-validate the Lua 5.5.1 chunk without executing it (or inspect
  // returned pack table operations safely in a zero-network validation VM).
  LuaSandboxContext val_ctx;
  val_ctx.manifest = &manifest;
  val_ctx.max_heap_bytes = impl_->max_lua_heap_bytes;
  val_ctx.max_instructions = impl_->max_lua_instructions;

  LuaStateGuard guard{lua_newstate(saas_lua_alloc, &val_ctx, luaL_makeseed(nullptr))};
  if (guard.L == nullptr)
    return Result<SaasPackId>::failure({ErrorCode::allocation});
  *static_cast<LuaSandboxContext **>(lua_getextraspace(guard.L)) = &val_ctx;
  open_sandboxed_libs(guard.L);
  lua_sethook(guard.L, saas_lua_instruction_hook, LUA_MASKCOUNT, 10000);

  const std::string chunk_name = "@saas:" + manifest.service;
  if (luaL_loadbufferx(guard.L, lua_source.data(), lua_source.size(),
                       chunk_name.c_str(), "t") != LUA_OK) {
    return Result<SaasPackId>::failure({ErrorCode::corrupt});
  }
  if (lua_pcall(guard.L, 0, 1, 0) != LUA_OK || lua_type(guard.L, -1) != LUA_TTABLE)
    return Result<SaasPackId>::failure({ErrorCode::corrupt});

  std::vector<std::string> op_names;
  lua_getfield(guard.L, -1, "operations");
  if (lua_type(guard.L, -1) != LUA_TTABLE)
    return Result<SaasPackId>::failure({ErrorCode::corrupt});
  lua_pushnil(guard.L);
  while (lua_next(guard.L, -2) != 0) {
    if (lua_type(guard.L, -2) == LUA_TSTRING &&
        lua_type(guard.L, -1) == LUA_TFUNCTION) {
      std::size_t klen = 0;
      const char *kptr = lua_tolstring(guard.L, -2, &klen);
      op_names.emplace_back(kptr, klen);
    }
    lua_pop(guard.L, 1);
  }
  std::ranges::sort(op_names);

  const SaasPackId pid{impl_->next_pack_id++};
  Impl::PackRecord rec;
  rec.pack_id = pid;
  rec.manifest = std::move(manifest);
  rec.lua_source = std::string{lua_source};
  rec.operation_names = std::move(op_names);

  auto [it, inserted] = impl_->packs.emplace(pid, std::move(rec));
  (void)inserted;
  impl_->service_index.emplace(it->second.manifest.service, pid);
  return Result<SaasPackId>::success(pid);
}

Result<SaasPackId> SaasPackHost::load_pack_file(SaasPackManifest manifest,
                                                const std::filesystem::path &lua_path) {
  std::ifstream in{lua_path, std::ios::binary};
  if (!in.good())
    return Result<SaasPackId>::failure({ErrorCode::io});
  std::ostringstream ss;
  ss << in.rdbuf();
  if (!in.good() && !in.eof())
    return Result<SaasPackId>::failure({ErrorCode::io});
  return register_pack_source(std::move(manifest), ss.str());
}

Result<std::vector<SaasPackId>>
SaasPackHost::load_builtin_packs(const std::filesystem::path &integrations_dir) {
  std::vector<SaasPackId> ids;
  const bool has_dir = [&] {
    if (integrations_dir.empty())
      return false;
    std::error_code ec;
    return std::filesystem::is_directory(integrations_dir, ec);
  }();
  for (const auto &manifest : builtin_saas_pack_manifests()) {
    Result<SaasPackId> id = Result<SaasPackId>::failure({ErrorCode::io});
    bool disk_present = false;
    if (has_dir) {
      const std::filesystem::path file = integrations_dir / (manifest.service + ".lua");
      std::error_code ec;
      if (std::filesystem::is_regular_file(file, ec)) {
        disk_present = true;
        id = load_pack_file(manifest, file);
      }
    }
    if (!disk_present) {
      if (const auto embedded = find_embedded_saas_pack(manifest.service);
          embedded.has_value()) {
        id = register_pack_source(manifest, *embedded);
      }
    }
    if (!id.has_value())
      return Result<std::vector<SaasPackId>>::failure(id.error());
    ids.push_back(id.value());
  }
  return Result<std::vector<SaasPackId>>::success(std::move(ids));
}

std::optional<SaasPackId> SaasPackHost::find_pack_id(std::string_view service) const {
  if (const auto it = impl_->service_index.find(service);
      it != impl_->service_index.end()) {
    return it->second;
  }
  return std::nullopt;
}

std::vector<SaasPackInfo> SaasPackHost::list_packs() const {
  std::vector<SaasPackInfo> out;
  out.reserve(impl_->packs.size());
  for (const auto &[pid, rec] : impl_->packs) {
    out.push_back(SaasPackInfo{
        pid,
        rec.manifest.service,
        rec.manifest.display_name,
        rec.manifest.allowed_hosts,
        rec.operation_names,
        rec.manifest.is_open_world,
    });
  }
  return out;
}

Result<SaasInvokeOutcome> SaasPackHost::invoke(const SaasInvokeParams &params) {
  const auto pid = find_pack_id(params.service);
  if (!pid.has_value())
    return Result<SaasInvokeOutcome>::failure({ErrorCode::invalid_identity});
  const auto it = impl_->packs.find(*pid);
  if (it == impl_->packs.end())
    return Result<SaasInvokeOutcome>::failure({ErrorCode::stale_handle});
  const Impl::PackRecord &pack = it->second;

  LuaSandboxContext ctx;
  ctx.pack_id = *pid;
  ctx.manifest = &pack.manifest;
  ctx.operation = params.operation;
  ctx.account = params.account;
  ctx.http_transport = &impl_->http_transport;
  ctx.brakes_gate = &impl_->brakes_gate;
  ctx.audit_log = impl_->audit_log;
  ctx.max_heap_bytes = impl_->max_lua_heap_bytes;
  ctx.max_instructions = impl_->max_lua_instructions;

  LuaStateGuard guard{lua_newstate(saas_lua_alloc, &ctx, luaL_makeseed(nullptr))};
  if (guard.L == nullptr)
    return Result<SaasInvokeOutcome>::failure({ErrorCode::allocation});
  *static_cast<LuaSandboxContext **>(lua_getextraspace(guard.L)) = &ctx;
  open_sandboxed_libs(guard.L);
  lua_sethook(guard.L, saas_lua_instruction_hook, LUA_MASKCOUNT, 10000);

  const std::string chunk_name = "@saas:" + pack.manifest.service;
  if (luaL_loadbufferx(guard.L, pack.lua_source.data(), pack.lua_source.size(),
                       chunk_name.c_str(), "t") != LUA_OK) {
    return Result<SaasInvokeOutcome>::failure({ErrorCode::corrupt});
  }
  if (lua_pcall(guard.L, 0, 1, 0) != LUA_OK || lua_type(guard.L, -1) != LUA_TTABLE)
    return Result<SaasInvokeOutcome>::failure({ErrorCode::corrupt});

  lua_getfield(guard.L, -1, "operations");
  if (lua_type(guard.L, -1) != LUA_TTABLE)
    return Result<SaasInvokeOutcome>::failure({ErrorCode::corrupt});

  lua_getfield(guard.L, -1, params.operation.c_str());
  if (lua_type(guard.L, -1) != LUA_TFUNCTION)
    return Result<SaasInvokeOutcome>::failure({ErrorCode::unsupported});

  push_value_to_lua(guard.L, params.arguments);

  SaasInvokeOutcome out;
  out.pack_id = *pid;
  out.service = pack.manifest.service;
  out.operation = params.operation;

  const int call_rc = lua_pcall(guard.L, 1, 1, 0);
  if (ctx.pending_http_taint.has_value() && !ctx.tainted_via_http &&
      (call_rc != LUA_OK || ctx.blocked_by_host_pin || ctx.blocked_by_brakes ||
       ctx.instruction_budget_exceeded)) {
    (void)impl_->brakes_gate.ingest_peer(*ctx.pending_http_taint);
    ctx.tainted_via_http = true;
  }
  if (ctx.instruction_budget_exceeded)
    return Result<SaasInvokeOutcome>::failure({ErrorCode::capacity});
  // Enforce sticky security blocks EVEN IF Lua wrapped the call in pcall() and
  // returned LUA_OK!
  if (ctx.blocked_by_host_pin || ctx.blocked_by_brakes) {
    out.blocked_by_host_pin = ctx.blocked_by_host_pin;
    out.blocked_by_brakes = ctx.blocked_by_brakes;
    out.brakes_decision = ctx.brakes_decision;
    out.error_detail = ctx.error_detail;
    out.raw_http_bodies = std::move(ctx.raw_http_bodies);
    return Result<SaasInvokeOutcome>::success(std::move(out));
  }
  if (call_rc != LUA_OK) {
    std::string lua_err;
    if (lua_type(guard.L, -1) == LUA_TSTRING) {
      std::size_t len = 0;
      const char *ptr = lua_tolstring(guard.L, -1, &len);
      lua_err.assign(ptr, len);
    }
    out.error_detail = !ctx.error_detail.empty() ? ctx.error_detail : lua_err;
    out.raw_http_bodies = std::move(ctx.raw_http_bodies);
    return Result<SaasInvokeOutcome>::failure({ErrorCode::external_unknown});
  }

  std::string raw_output;
  if (lua_type(guard.L, -1) == LUA_TSTRING) {
    std::size_t len = 0;
    const char *ptr = lua_tolstring(guard.L, -1, &len);
    raw_output.assign(ptr, len);
  } else {
    std::size_t nodes = 0;
    auto val = read_value_from_lua(guard.L, -1, LuaReadBudget{0U, &nodes});
    if (!val.has_value())
      return Result<SaasInvokeOutcome>::failure(val.error());
    auto dumped = dump_json(val.value());
    if (!dumped.has_value())
      return Result<SaasInvokeOutcome>::failure(dumped.error());
    raw_output = std::move(dumped.value());
  }

  out.raw_output = raw_output;
  out.raw_http_bodies = std::move(ctx.raw_http_bodies);

  const std::uint64_t audit_id = impl_->next_audit_seq++;
  if (impl_->audit_log != nullptr) {
    Value::Object meta;
    meta.emplace_back("service", Value{pack.manifest.service});
    meta.emplace_back("operation", Value{params.operation});
    out.audit_ref = impl_->audit_log->original(OriginalCapture{
        "saas.pack.output", raw_output, Value::object(std::move(meta))});
  }

  const ToolProjectionPolicy proj_policy =
      params.projection_policy.value_or(impl_->default_projection);
  out.projection = project_tool_output_for_context(
      ToolProjectionInput{
          "saas:" + pack.manifest.service + "." + params.operation,
          raw_output,
          std::nullopt,
          audit_id,
      },
      proj_policy);

  brakes::PeerProvenance prov;
  prov.origin = brakes::PeerOriginKind::external_mcp;
  prov.safety_number = pack.manifest.safety_number.empty()
                           ? ("saas:" + pack.manifest.service)
                           : pack.manifest.safety_number;
  prov.is_external_guest = pack.manifest.is_open_world;
  prov.effective_trust = pack.manifest.trust_profile;

  auto framed = brakes::format_untrusted_peer_envelope(
      prov, brakes::RoomScopeRef{"saas/" + pack.manifest.service},
      brakes::SenderRef{params.operation},
      brakes::MessageBodyRef{out.projection.projected_text});
  if (!framed.has_value())
    return Result<SaasInvokeOutcome>::failure(framed.error());
  out.framed_output = std::move(framed.value());

  if (!ctx.tainted_via_http)
    (void)impl_->brakes_gate.ingest_peer(prov);

  return Result<SaasInvokeOutcome>::success(std::move(out));
}

const brakes::BrakesGate &SaasPackHost::brakes_gate() const noexcept {
  return impl_->brakes_gate;
}
brakes::BrakesGate &SaasPackHost::mutable_brakes_gate() noexcept {
  return impl_->brakes_gate;
}

} // namespace blackbird
