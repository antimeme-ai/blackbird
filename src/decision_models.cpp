#include "blackbird/decision_models.hpp"
#include "blackbird/json.hpp"
#include "blackbird/provider_auth.hpp"
#include "blackbird/raw_caller.hpp"
#include "native_process.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <optional>
#include <set>

namespace blackbird {
namespace {
using detail::fail;
template <class T> T take(Result<T> value) {
  if (!value.has_value())
    throw value.error();
  return std::move(value).value();
}
bool object(const Value &v) { return std::holds_alternative<Value::Object>(v.value()); }
bool array(const Value &v) { return std::holds_alternative<Value::Array>(v.value()); }
bool text(const Value &v) { return std::holds_alternative<std::string>(v.value()); }
bool description(const Value &v, bool nullable = false) {
  return text(v) || object(v) || array(v) ||
         (nullable && std::holds_alternative<std::nullptr_t>(v.value()));
}
const Value &need(const Value &v, std::string_view key, ErrorCode code) {
  const auto *p = v.find(key);
  if (!p)
    fail(code);
  return *p;
}
std::string str(const Value &v, std::string_view key, ErrorCode code) {
  const auto &p = need(v, key, code);
  if (!text(p) || p.string().empty() || p.string().find('\0') != std::string::npos)
    fail(code);
  return p.string();
}
void unique(const Value &v, ErrorCode code) {
  if (!object(v))
    fail(code);
  std::set<std::string> seen;
  for (const auto &[k, value] : v.object()) {
    (void)value;
    if (k.empty() || !seen.insert(k).second)
      fail(code);
  }
}
double number(const Value &v) {
  if (!std::holds_alternative<Number>(v.value()))
    fail(ErrorCode::corrupt);
  double result = 0;
  const auto &s = v.number().text();
  const auto p = std::from_chars(s.data(), s.data() + s.size(), result);
  if (p.ec != std::errc{} || p.ptr != s.data() + s.size() || !std::isfinite(result))
    fail(ErrorCode::corrupt);
  return result;
}
double probability(const Value &v) {
  const auto n = number(v);
  if (n < 0 || n > 1)
    fail(ErrorCode::corrupt);
  return n;
}
void tokens(const Value &v) {
  if (!std::holds_alternative<Number>(v.value()))
    fail(ErrorCode::corrupt);
  std::uint64_t n = 0;
  const auto &s = v.number().text();
  auto p = std::from_chars(s.data(), s.data() + s.size(), n);
  if (p.ec != std::errc{} || p.ptr != s.data() + s.size())
    fail(ErrorCode::corrupt);
}
int timeout(const Value &args) {
  const auto *v = args.find("timeout_seconds");
  if (!v)
    return 30;
  if (!std::holds_alternative<Number>(v->value()))
    fail(ErrorCode::invalid_range);
  int n = 0;
  const auto &s = v->number().text();
  auto p = std::from_chars(s.data(), s.data() + s.size(), n);
  if (p.ec != std::errc{} || p.ptr != s.data() + s.size() || n < 1 || n > 3600)
    fail(ErrorCode::invalid_range);
  return n;
}
std::string quote(std::string_view value) {
  std::string out = "\"";
  for (char c : value) {
    if (static_cast<unsigned char>(c) < 32 || c == 127)
      fail(ErrorCode::invalid_range);
    if (c == '\\' || c == '"')
      out += '\\';
    out += c;
  }
  return out + '"';
}
std::string trim(const std::string &s) {
  const auto first = s.find_first_not_of(" \t\r");
  if (first == std::string::npos)
    return {};
  return s.substr(first, s.find_last_not_of(" \t\r") - first + 1);
}
std::string checked_key(std::string value) {
  if (value.empty() || value.size() > 8192)
    fail(ErrorCode::unsupported);
  for (char c : value)
    if (static_cast<unsigned char>(c) <= 32 || static_cast<unsigned char>(c) >= 127)
      fail(ErrorCode::unsupported);
  return value;
}
std::string credential(const DecisionModelConfig &config) {
  for (const char *name : {"TYPESAFE_API_KEY", "jev"})
    if (const auto *v = std::getenv(name); v && *v)
      return checked_key(v);
  auto path = config.credential_file;
  const bool explicit_file = !path.empty();
  if (!explicit_file) {
    if (const auto *v = std::getenv("BLACKBIRD_JEV_ENV_FILE"); v && *v)
      path = v;
  }
  if (!path.empty()) {
    std::ifstream file(path);
    if (file) {
      std::string input;
      char c;
      while (file.get(c)) {
        if (input.size() >= 65536)
          fail(ErrorCode::capacity);
        input += c;
      }
      if (!file.eof())
        fail(ErrorCode::io);
      std::string primary, alternate;
      std::size_t pos = 0;
      while (pos < input.size()) {
        auto end = input.find('\n', pos);
        if (end == std::string::npos)
          end = input.size();
        auto line = trim(input.substr(pos, end - pos));
        pos = end + 1;
        if (line.starts_with("export "))
          line = trim(line.substr(7));
        const auto equals = line.find('=');
        if (equals == std::string::npos)
          continue;
        const auto name = trim(line.substr(0, equals));
        if (name != "TYPESAFE_API_KEY" && name != "jev")
          continue;
        auto value = trim(line.substr(equals + 1));
        if (value.empty())
          fail(ErrorCode::unsupported);
        if (value.front() == '\'' || value.front() == '"') {
          const auto closing = value.find(value.front(), 1);
          if (closing == std::string::npos)
            fail(ErrorCode::unsupported);
          const auto remainder = trim(value.substr(closing + 1));
          if (!remainder.empty() && !remainder.starts_with('#'))
            fail(ErrorCode::unsupported);
          value = value.substr(1, closing - 1);
        } else {
          const auto comment = value.find_first_of(" \t#");
          if (comment != std::string::npos) {
            const auto remainder = trim(value.substr(comment));
            if (!remainder.empty() && !remainder.starts_with('#'))
              fail(ErrorCode::unsupported);
            value.resize(comment);
          }
        }
        (name == "TYPESAFE_API_KEY" ? primary : alternate) = checked_key(value);
      }
      if (!primary.empty() || !alternate.empty())
        return checked_key(primary.empty() ? alternate : primary);
      if (explicit_file)
        fail(ErrorCode::unsupported);
    } else if (explicit_file) {
      fail(ErrorCode::unsupported);
    }
  }
  if (!explicit_file) {
    if (auto stored = ProviderAuth{}.stored_key("jev"))
      return checked_key(std::move(*stored));
  }
  fail(ErrorCode::unsupported);
}
bool valid_model_name(std::string_view model) {
  if (model.empty() || model.size() > 128)
    return false;
  for (char c : model) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte < 32 || byte == 127)
      return false;
  }
  return true;
}
struct DecisionProviderMeta {
  std::string id;
  std::string base_url;
  std::string environment;
};
DecisionProviderMeta resolve_provider_meta(std::string_view provider) {
  if (provider == "jev")
    return {"jev", "https://api.typesafe.ai/v1", "TYPESAFE_API_KEY"};
  if (provider == "clef") {
    std::string base = "http://127.0.0.1:11435/v1";
    if (const auto *override_url = std::getenv("BLACKBIRD_CLEF_URL");
        override_url && *override_url)
      base = override_url;
    return {"clef", std::move(base), "CLEF_API_KEY"};
  }
  Value desc;
  try {
    desc = ProviderAuth{}.descriptor(provider);
  } catch (const Error &e) {
    if (e.code == ErrorCode::unsupported || e.code == ErrorCode::invalid_range)
      fail(ErrorCode::unsupported);
    throw;
  }
  const auto *proto = desc.find("protocol");
  if (!proto || !text(*proto) || proto->string() != "decision")
    fail(ErrorCode::unsupported);
  const auto *base = desc.find("base_url");
  if (!base || !text(*base) || base->string().empty())
    fail(ErrorCode::unsupported);
  std::string env_var;
  if (const auto *env = desc.find("environment"); env && text(*env))
    env_var = env->string();
  return {std::string{provider}, base->string(), std::move(env_var)};
}
bool valid_port(std::string_view port) {
  if (port.empty() || port.size() > 5 || port.front() == '0')
    return false;
  for (char c : port)
    if (c < '0' || c > '9')
      return false;
  int value = 0;
  const auto parsed = std::from_chars(port.data(), port.data() + port.size(), value);
  return parsed.ec == std::errc{} && parsed.ptr == port.data() + port.size() &&
         value >= 1 && value <= 65535;
}
bool parse_ipv4(std::string_view host, std::array<int, 4> &octets) {
  std::size_t pos = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    const auto dot = host.find('.', pos);
    if (i < 3 && dot == std::string_view::npos)
      return false;
    if (i == 3 && dot != std::string_view::npos)
      return false;
    const auto part =
        i < 3 ? host.substr(pos, dot - pos) : host.substr(pos, host.size() - pos);
    if (part.empty() || part.size() > 3 || (part.size() > 1 && part.front() == '0'))
      return false;
    for (char c : part)
      if (c < '0' || c > '9')
        return false;
    int val = 0;
    const auto parsed = std::from_chars(part.data(), part.data() + part.size(), val);
    if (parsed.ec != std::errc{} || parsed.ptr != part.data() + part.size() ||
        val < 0 || val > 255)
      return false;
    octets[i] = val;
    pos = dot + 1;
  }
  return true;
}
bool is_ascii_localhost(std::string_view host) {
  constexpr std::string_view target = "localhost";
  if (host.size() != target.size())
    return false;
  for (std::size_t i = 0; i < target.size(); ++i) {
    char c = host[i];
    if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c - 'A' + 'a');
    if (c != target[i])
      return false;
  }
  return true;
}
bool valid_authority(std::string_view authority, std::string_view &host_out,
                     bool &bracketed_out) {
  if (authority.empty())
    return false;
  if (authority.front() == '[') {
    const auto close = authority.find(']');
    if (close == std::string_view::npos || close <= 1)
      return false;
    const auto rest = authority.substr(close + 1);
    if (!rest.empty() && (rest.front() != ':' || !valid_port(rest.substr(1))))
      return false;
    host_out = authority.substr(1, close - 1);
    bracketed_out = true;
    return true;
  }
  bracketed_out = false;
  const auto colon = authority.find(':');
  if (colon != std::string_view::npos) {
    if (!valid_port(authority.substr(colon + 1)))
      return false;
    host_out = authority.substr(0, colon);
  } else {
    host_out = authority;
  }
  return !host_out.empty();
}
bool is_local_or_tailscale_http(std::string_view authority) {
  std::string_view host;
  bool bracketed = false;
  if (!valid_authority(authority, host, bracketed))
    return false;
  if (bracketed)
    return host == "::1";
  if (is_ascii_localhost(host))
    return true;
  std::array<int, 4> octets{};
  if (!parse_ipv4(host, octets))
    return false;
  const bool loopback =
      octets[0] == 127 && octets[1] == 0 && octets[2] == 0 && octets[3] == 1;
  const bool tailscale_cgnat = octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127;
  return loopback || tailscale_cgnat;
}
struct ResolvedEndpoint {
  std::string url;
  std::string proto;
};
ResolvedEndpoint resolve_endpoint(const DecisionProviderMeta &meta) {
  if (meta.id == "jev")
    return {"https://api.typesafe.ai/v1/systemone", "=https"};
  const std::string_view base = meta.base_url;
  if (base.empty() || base.size() > 2048)
    fail(ErrorCode::unsupported);
  for (char c : base) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte <= 32 || byte >= 127 || c == '?' || c == '#' || c == '\\' || c == '@')
      fail(ErrorCode::unsupported);
  }
  const bool is_https = base.starts_with("https://");
  const bool is_http = base.starts_with("http://");
  if (!is_https && !is_http)
    fail(ErrorCode::unsupported);
  const std::size_t prefix = is_https ? 8 : 7;
  const auto rest = base.substr(prefix);
  const auto slash = rest.find('/');
  const auto authority = rest.substr(0, slash);
  std::string_view host;
  bool bracketed = false;
  if (!valid_authority(authority, host, bracketed))
    fail(ErrorCode::unsupported);
  if (is_http && !is_local_or_tailscale_http(authority))
    fail(ErrorCode::unsupported);
  std::string url{base};
  while (url.size() > prefix + authority.size() && url.back() == '/')
    url.pop_back();
  if (!url.ends_with("/systemone"))
    url += "/systemone";
  if (url.size() > 2048)
    fail(ErrorCode::unsupported);
  return {std::move(url), is_https ? "=https" : "=http"};
}
std::optional<std::string> optional_credential(const DecisionProviderMeta &meta) {
  if (!meta.environment.empty()) {
    if (const auto *v = std::getenv(meta.environment.c_str()); v && *v)
      return checked_key(v);
  }
  try {
    if (auto stored = ProviderAuth{}.stored_key(meta.id); stored.has_value())
      return checked_key(std::move(*stored));
  } catch (const Error &) {
    return std::nullopt;
  }
  return std::nullopt;
}
std::string provider_from_args(const Value &args) {
  unique(args, ErrorCode::invalid_range);
  return args.find("provider") ? str(args, "provider", ErrorCode::invalid_range)
                               : std::string{"jev"};
}

// FIPS 180-4 SHA-256 over canonical JSON bytes for tamper-evident blind trials.
constexpr std::array<std::uint32_t, 64> sha_k{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};
constexpr std::uint32_t rotr(std::uint32_t x, unsigned n) {
  return (x >> n) | (x << (32U - n));
}
void sha_block(std::array<std::uint32_t, 8> &h, const unsigned char *block) {
  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16; ++i)
    w.at(i) = (std::uint32_t{block[4 * i]} << 24U) |
              (std::uint32_t{block[(4 * i) + 1]} << 16U) |
              (std::uint32_t{block[(4 * i) + 2]} << 8U) |
              std::uint32_t{block[(4 * i) + 3]};
  for (std::size_t i = 16; i < 64; ++i) {
    const auto s0 =
        rotr(w.at(i - 15), 7) ^ rotr(w.at(i - 15), 18) ^ (w.at(i - 15) >> 3U);
    const auto s1 =
        rotr(w.at(i - 2), 17) ^ rotr(w.at(i - 2), 19) ^ (w.at(i - 2) >> 10U);
    w.at(i) = w.at(i - 16) + s0 + w.at(i - 7) + s1;
  }
  auto a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
  for (std::size_t i = 0; i < 64; ++i) {
    const auto s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const auto choose = (e & f) ^ (~e & g);
    const auto t1 = k + s1 + choose + sha_k.at(i) + w.at(i);
    const auto s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const auto majority = (a & b) ^ (a & c) ^ (b & c);
    const auto t2 = s0 + majority;
    k = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
  h[5] += f;
  h[6] += g;
  h[7] += k;
}
std::string sha256_hex(std::string_view bytes) {
  std::array<std::uint32_t, 8> h{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  const auto *data = reinterpret_cast<const unsigned char *>(bytes.data());
  const std::size_t whole = bytes.size() - (bytes.size() % 64);
  for (std::size_t at = 0; at < whole; at += 64)
    sha_block(h, data + at);
  std::array<unsigned char, 128> tail{};
  const std::size_t rest = bytes.size() - whole;
  std::copy_n(data + whole, rest, tail.begin());
  tail.at(rest) = 0x80;
  const std::size_t blocks = rest < 56 ? 1 : 2;
  const std::uint64_t bits = static_cast<std::uint64_t>(bytes.size()) * 8U;
  for (std::size_t i = 0; i < 8; ++i)
    tail.at((blocks * 64) - 1 - i) =
        static_cast<unsigned char>((bits >> (8U * i)) & 0xffU);
  for (std::size_t i = 0; i < blocks; ++i)
    sha_block(h, tail.data() + (i * 64));
  static constexpr std::string_view hex = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (const auto word : h)
    for (int shift = 28; shift >= 0; shift -= 4)
      out.push_back(hex[(word >> static_cast<unsigned>(shift)) & 0xfU]);
  return out;
}
Value canonicalize_json(const Value &value, std::size_t depth = 0) {
  if (depth > 128)
    fail(ErrorCode::capacity);
  if (array(value)) {
    Value::Array out;
    out.reserve(value.array().size());
    for (const auto &item : value.array())
      out.push_back(canonicalize_json(item, depth + 1));
    return Value{std::move(out)};
  }
  if (object(value)) {
    Value::Object out;
    out.reserve(value.object().size());
    for (const auto &[k, v] : value.object())
      out.emplace_back(k, canonicalize_json(v, depth + 1));
    std::ranges::sort(
        out, {}, [](const auto &entry) -> const std::string & { return entry.first; });
    for (std::size_t i = 1; i < out.size(); ++i)
      if (out[i - 1].first == out[i].first)
        fail(ErrorCode::corrupt);
    return Value::object(std::move(out));
  }
  return value;
}
std::string sha256_canonical_value(const Value &canonical) {
  const auto bytes = take(dump_json(canonical, {16 * 1024 * 1024, 500000, 128}));
  return "sha256:" + sha256_hex(bytes);
}
std::string canonical_sha256(const Value &value) {
  return sha256_canonical_value(canonicalize_json(value));
}
struct SealDigests {
  std::string request_sha256;
  std::string result_sha256;
};
std::string seal_envelope_sha256(const SealDigests &digests) {
  return canonical_sha256(
      Value::object({{"algorithm", Value{"sha256"}},
                     {"request_sha256", Value{digests.request_sha256}},
                     {"result_sha256", Value{digests.result_sha256}},
                     {"version", Value{Number{1}}}}));
}
} // namespace

Value decision_request(const Value &args) {
  unique(args, ErrorCode::invalid_range);
  for (const auto &[k, v] : args.object()) {
    (void)v;
    if (k != "provider" && k != "model" && k != "state" && k != "questions" &&
        k != "timeout_seconds")
      fail(ErrorCode::invalid_range);
  }
  const auto provider =
      args.find("provider") ? str(args, "provider", ErrorCode::invalid_range) : "jev";
  (void)resolve_provider_meta(provider);
  std::string model;
  if (args.find("model")) {
    model = str(args, "model", ErrorCode::invalid_range);
  } else if (provider == "jev") {
    model = "jev-1.13.0";
  } else if (provider == "clef") {
    model = "clef-latest";
  } else {
    fail(ErrorCode::invalid_range);
  }
  if (!valid_model_name(model))
    fail(ErrorCode::invalid_range);
  if (provider == "jev" && !model.starts_with("jev-"))
    fail(ErrorCode::invalid_range);
  (void)timeout(args);
  const auto &state = need(args, "state", ErrorCode::invalid_range);
  if (!description(state))
    fail(ErrorCode::invalid_range);
  const auto &questions = need(args, "questions", ErrorCode::invalid_range);
  unique(questions, ErrorCode::invalid_range);
  if (questions.object().empty())
    fail(ErrorCode::invalid_range);
  for (const auto &[id, q] : questions.object()) {
    (void)id;
    unique(q, ErrorCode::invalid_range);
    const auto type = str(q, "type", ErrorCode::invalid_range);
    if (!description(need(q, "instructions", ErrorCode::invalid_range), true))
      fail(ErrorCode::invalid_range);
    for (const auto &[k, v] : q.object()) {
      (void)v;
      if (k != "type" && k != "instructions" && k != "criteria")
        fail(ErrorCode::invalid_range);
    }
    const auto *criteria = q.find("criteria");
    if (type == "choice") {
      if (!criteria)
        fail(ErrorCode::invalid_range);
      unique(*criteria, ErrorCode::invalid_range);
      if (criteria->object().empty() || criteria->object().size() > 255)
        fail(ErrorCode::invalid_range);
      for (const auto &[key, v] : criteria->object()) {
        (void)key;
        if (!description(v, true))
          fail(ErrorCode::invalid_range);
      }
    } else if (type == "score") {
      if (!criteria || !array(*criteria) || criteria->array().size() < 2 ||
          criteria->array().size() > 10)
        fail(ErrorCode::invalid_range);
      for (const auto &v : criteria->array())
        if (!description(v, true))
          fail(ErrorCode::invalid_range);
    } else if (type == "noul") {
      if (criteria) {
        unique(*criteria, ErrorCode::invalid_range);
        for (const auto &[key, v] : criteria->object())
          if ((key != "true" && key != "false") || !description(v, true))
            fail(ErrorCode::invalid_range);
      }
    } else
      fail(ErrorCode::invalid_range);
  }
  return Value::object(
      {{"model", Value{model}}, {"state", state}, {"questions", questions}});
}

Value jev_request(const Value &args) {
  unique(args, ErrorCode::invalid_range);
  if (args.find("provider") && str(args, "provider", ErrorCode::invalid_range) != "jev")
    fail(ErrorCode::unsupported);
  return decision_request(args);
}

void validate_decision_response(const Value &request, const Value &response,
                                std::string_view provider) {
  unique(response, ErrorCode::corrupt);
  const auto model = str(response, "model", ErrorCode::corrupt);
  const auto requested = str(request, "model", ErrorCode::corrupt);
  if (!valid_model_name(model))
    fail(ErrorCode::corrupt);
  if (provider == "jev") {
    if (!model.starts_with("jev-") || model == "jev-latest" || model == "jev-preview" ||
        ((requested != "jev-latest" && requested != "jev-preview") &&
         model != requested))
      fail(ErrorCode::corrupt);
  } else {
    const bool alias =
        requested.ends_with("-latest") || requested.ends_with("-preview");
    if (!alias && model != requested)
      fail(ErrorCode::corrupt);
  }
  const auto &answers = need(response, "answers", ErrorCode::corrupt);
  unique(answers, ErrorCode::corrupt);
  const auto &questions = need(request, "questions", ErrorCode::corrupt);
  if (answers.object().size() != questions.object().size())
    fail(ErrorCode::corrupt);
  const auto &usage = need(response, "usage", ErrorCode::corrupt);
  unique(usage, ErrorCode::corrupt);
  tokens(need(usage, "input_tokens", ErrorCode::corrupt));
  tokens(need(usage, "output_tokens", ErrorCode::corrupt));
  for (const auto &[id, q] : questions.object()) {
    const auto &a = need(answers, id, ErrorCode::corrupt);
    unique(a, ErrorCode::corrupt);
    const auto type = str(q, "type", ErrorCode::corrupt);
    if (str(a, "type", ErrorCode::corrupt) != type)
      fail(ErrorCode::corrupt);
    if (type == "noul") {
      (void)probability(need(a, "noul", ErrorCode::corrupt));
      continue;
    }
    (void)probability(need(a, "confidence", ErrorCode::corrupt));
    const auto &p = need(a, "probabilities", ErrorCode::corrupt);
    unique(p, ErrorCode::corrupt);
    const auto &criteria = need(q, "criteria", ErrorCode::corrupt);
    const auto count =
        type == "choice" ? criteria.object().size() : criteria.array().size();
    if (p.object().size() != count)
      fail(ErrorCode::corrupt);
    double sum = 0, weighted = 0, highest = 0;
    for (std::size_t i = 0; i < count; ++i) {
      const auto key =
          type == "choice" ? criteria.object()[i].first : std::to_string(i);
      const auto n = probability(need(p, key, ErrorCode::corrupt));
      sum += n;
      weighted += n * static_cast<double>(i);
      highest = std::max(highest, n);
    }
    if (std::abs(sum - 1) > 0.0001)
      fail(ErrorCode::corrupt);
    if (type == "choice") {
      const auto chosen = str(a, "choice", ErrorCode::corrupt);
      if (!criteria.find(chosen) ||
          probability(need(p, chosen, ErrorCode::corrupt)) < highest)
        fail(ErrorCode::corrupt);
    } else {
      const auto score = number(need(a, "score", ErrorCode::corrupt));
      if (score < 0 || score > static_cast<double>(count - 1) ||
          std::abs(score - weighted) > 0.0001)
        fail(ErrorCode::corrupt);
      const auto &legend = need(a, "legend", ErrorCode::corrupt);
      unique(legend, ErrorCode::corrupt);
      if (legend.object().size() != count)
        fail(ErrorCode::corrupt);
      for (std::size_t i = 0; i < count; ++i) {
        const auto &label = need(legend, std::to_string(i), ErrorCode::corrupt);
        if (!text(label) || (text(criteria.array()[i]) && label != criteria.array()[i]))
          fail(ErrorCode::corrupt);
      }
    }
  }
}

void validate_jev_response(const Value &request, const Value &response) {
  validate_decision_response(request, response, "jev");
}

Value decision_blind_seal(const Value &request, const Value &result) {
  const auto req_hash = canonical_sha256(request);
  const auto res_hash = canonical_sha256(result);
  const auto seal_hash = seal_envelope_sha256({req_hash, res_hash});
  return Value::object({{"version", Value{Number{1}}},
                        {"algorithm", Value{"sha256"}},
                        {"request_sha256", Value{req_hash}},
                        {"result_sha256", Value{res_hash}},
                        {"seal_sha256", Value{seal_hash}},
                        {"result", result}});
}

Result<Value> decision_blind_verify(const Value &seal, const Value &request,
                                    const Value &first_pass) {
  try {
    const auto canonical_seal = canonicalize_json(seal);
    const auto canonical_request = canonicalize_json(request);
    const auto canonical_first_pass = canonicalize_json(first_pass);
    unique(canonical_seal, ErrorCode::corrupt);
    const auto &version = need(canonical_seal, "version", ErrorCode::corrupt);
    if (!std::holds_alternative<Number>(version.value()) ||
        version.number().text() != "1")
      return Result<Value>::failure({ErrorCode::corrupt});
    if (str(canonical_seal, "algorithm", ErrorCode::corrupt) != "sha256")
      return Result<Value>::failure({ErrorCode::corrupt});
    const auto recorded_req = str(canonical_seal, "request_sha256", ErrorCode::corrupt);
    const auto recorded_res = str(canonical_seal, "result_sha256", ErrorCode::corrupt);
    const auto recorded_seal = str(canonical_seal, "seal_sha256", ErrorCode::corrupt);
    const auto &sealed_result = need(canonical_seal, "result", ErrorCode::corrupt);
    const auto actual_req = sha256_canonical_value(canonical_request);
    const auto actual_res = sha256_canonical_value(sealed_result);
    const auto expected_seal = seal_envelope_sha256({recorded_req, recorded_res});
    if (recorded_req != actual_req || recorded_res != actual_res ||
        recorded_seal != expected_seal)
      return Result<Value>::failure({ErrorCode::corrupt});
    const auto first_pass_hash = sha256_canonical_value(canonical_first_pass);
    const auto reveal_hash =
        canonical_sha256(Value::object({{"algorithm", Value{"sha256"}},
                                        {"first_pass_sha256", Value{first_pass_hash}},
                                        {"request_sha256", Value{actual_req}},
                                        {"result_sha256", Value{actual_res}},
                                        {"seal_sha256", Value{expected_seal}},
                                        {"version", Value{Number{1}}}}));
    return Result<Value>::success(
        Value::object({{"verified", Value{true}},
                       {"version", Value{Number{1}}},
                       {"algorithm", Value{"sha256"}},
                       {"request_sha256", Value{actual_req}},
                       {"result_sha256", Value{actual_res}},
                       {"seal_sha256", Value{expected_seal}},
                       {"first_pass_sha256", Value{first_pass_hash}},
                       {"reveal_sha256", Value{reveal_hash}},
                       {"first_pass", first_pass},
                       {"result", need(seal, "result", ErrorCode::corrupt)}}));
  } catch (const Error &error) {
    return Result<Value>::failure(error);
  } catch (const std::bad_alloc &) {
    return Result<Value>::failure({ErrorCode::allocation});
  } catch (const std::length_error &) {
    return Result<Value>::failure({ErrorCode::capacity});
  }
}

Value DecisionModels::evaluate(const Value &args, const RawAdapterContext *context) {
  RawCallerTrace trace{{3600, 3601},
                       context,
                       std::array{detail::raw_native_field(config_.request_limit),
                                  detail::raw_native_field(config_.response_limit)}};
  return trace.run([&] {
    trace.stage(1);
    const auto started = detail::Clock::now();
    const auto provider = provider_from_args(args);
    const auto request = decision_request(args);
    trace.stage(2);
    if (trace.enabled() && config_.request_limit > UINT32_MAX - 48)
      throw Error{ErrorCode::overflow};
    auto original = trace.data(48 + config_.request_limit);
    const auto encoded = take(dump_json(request, {config_.request_limit, 500000, 128}));
    trace.bytes(3602, encoded, original);
    original.reset();
    const auto seconds = timeout(args);
    const auto deadline = started + std::chrono::seconds{seconds};
    trace.stage(3);
    const auto meta = resolve_provider_meta(provider);
    const auto endpoint = resolve_endpoint(meta);
    std::optional<std::string> key;
    if (provider == "jev")
      key = credential(config_);
    else
      key = optional_credential(meta);
    trace.stage(4);
    std::string input = "url = " + quote(endpoint.url) + "\n";
    if (key.has_value())
      input += "header = " + quote("Authorization: Bearer " + *key) + "\n";
    input +=
        "header = \"Content-Type: application/json\"\ndata-binary = " + quote(encoded) +
        "\n";
    detail::Child child;
    child.cancelled = cancelled;
    child.deadline_error = {ErrorCode::provider_transport, 28};
    if (trace.enabled())
      child.raw_capture(trace.reference(), true, false);
    const auto notify = [&](std::uint8_t channel, std::string_view label,
                            std::string_view bytes) {
      const auto owner = trace.context();
      const auto child_ref = child.raw_reference();
      const bool child_present = child_ref.ordinal != 0;
      const bool present = static_cast<bool>(observer);
      const auto length = bytes.size();
      std::array<ByteView, 7> fields{};
      std::size_t count = 0;
      fields[count++] = detail::raw_native_field(channel);
      fields[count++] = detail::raw_native_field(child_present);
      if (child_present) {
        fields[count++] = child_ref.lane;
        fields[count++] = detail::raw_native_field(child_ref.ordinal);
      }
      fields[count++] = detail::raw_native_field(length);
      fields[count++] = detail::raw_native_field(present);
      RawCallerTrace callback{{3606, 3607}, &owner, std::span{fields}.first(count)};
      callback.run([&] {
        if (present)
          observer(label, bytes);
        else
          callback.finish(RawOperationBranch::absent);
      });
    };
    child.output_observer = [&](std::string_view chunk) {
      notify(1, "decision_model.response", chunk);
    };
    trace.stage(5);
    child.start({config_.curl_executable, "--disable", "--silent", "--max-time",
                 std::to_string(seconds), "--proto", endpoint.proto, "--max-redirs",
                 "0", "--write-out", "\n%{http_code}", "--config", "-"});
    child.send(input, deadline);
    child.close_input();
    notify(2, "decision_model.request", encoded);
    trace.stage(6);
    auto exit_credit = trace.control(68);
    int exit = 0;
    auto raw = child.collect(deadline, config_.response_limit, &exit);
    const auto child_ref = child.raw_reference();
    trace.event(3603,
                std::array{ByteView{child_ref.lane},
                           detail::raw_native_field(child_ref.ordinal),
                           detail::raw_native_field(exit)},
                exit_credit);
    trace.stage(7);
    if (exit != 0)
      fail(ErrorCode::provider_transport, exit);
    trace.stage(8);
    const auto owner = trace.context();
    RawCallerTrace http{{3604, 3605}, &owner, {}, sizeof(int)};
    const int status = http.run([&] {
      const auto split = raw.rfind('\n');
      if (split == std::string::npos || raw.size() - split != 4)
        fail(ErrorCode::corrupt);
      int observed = 0;
      const auto code = std::string_view{raw}.substr(split + 1);
      const auto parsed =
          std::from_chars(code.data(), code.data() + code.size(), observed);
      if (parsed.ec != std::errc{} || parsed.ptr != code.data() + code.size())
        fail(ErrorCode::corrupt);
      http.finish(RawOperationBranch::returned, nullptr,
                  std::array{detail::raw_native_field(observed)});
      raw.resize(split);
      return observed;
    });
    if (status < 200 || status >= 300)
      fail(ErrorCode::external_unknown, status);
    trace.stage(9);
    const auto input_size = raw.size();
    RawCallerTrace parser{{3608, 3609},
                          &owner,
                          std::array{detail::raw_native_field(input_size)},
                          sizeof(bool)};
    auto parsed = parser.run([&] {
      auto value = parse_json(raw, {config_.response_limit, 500000, 128});
      const bool ok = value.has_value();
      const auto error = ok ? Error{} : value.error();
      parser.finish(RawOperationBranch::returned, ok ? nullptr : &error,
                    std::array{detail::raw_native_field(ok)});
      return value;
    });
    auto response = take(std::move(parsed));
    trace.stage(10);
    RawCallerTrace validator{{3610, 3611}, &owner};
    validator.run([&] { validate_decision_response(request, response, provider); });
    trace.stage(11);
    return Value::object(
        {{"status", Value{"ok"}},
         {"provider", Value{provider}},
         {"requested_model", need(request, "model", ErrorCode::corrupt)},
         {"response", std::move(response)}});
  });
}
} // namespace blackbird
