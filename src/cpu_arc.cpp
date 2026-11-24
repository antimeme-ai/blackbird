#include "blackbird/cpu_arc.hpp"

#include "blackbird/json.hpp"

#include <openssl/evp.h>
#include <sqlite3.h>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace blackbird::arc {
namespace {

namespace fs = std::filesystem;
using SteadyClock = std::chrono::steady_clock;

template <typename T> Result<T> fail(ErrorCode code, ArcError detail) noexcept {
  return Result<T>::failure(Error{code, static_cast<std::int64_t>(detail)});
}

// Strong wrappers to keep clang-tidy bugprone-easily-swappable-parameters at 0.
struct QueryText {
  std::string_view value;
};

struct CandidateText {
  std::string_view value;
};

struct DtypeName {
  std::string_view value;
};

struct FunctionIdRef {
  std::string_view value;
};

struct CounterDelta {
  std::int64_t invocations = 0;
  std::int64_t successes = 0;
  std::int64_t failures = 0;
  std::int64_t fallbacks = 0;
};

constexpr std::uint64_t kArcCtxMagic = 0x4242415243435458ULL;
constexpr const char *kArcCtxMetatable = "blackbird.arc.ctx";
constexpr const char *kArcEnvMetatable = "blackbird.arc.env";
constexpr const char *kArcStringMetatable = "blackbird.arc.string";

bool has_control_or_nul(std::string_view text) noexcept {
  for (const char ch : text) {
    const auto b = static_cast<unsigned char>(ch);
    if (b < 0x20U || b == 0x7FU) {
      return true;
    }
  }
  return false;
}

std::string ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return out;
}

std::string_view trim_sv(std::string_view sv) noexcept {
  while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())) != 0) {
    sv.remove_prefix(1U);
  }
  while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())) != 0) {
    sv.remove_suffix(1U);
  }
  return sv;
}

bool is_stop_word(std::string_view tok) noexcept {
  static constexpr std::array<std::string_view, 22> kStops = {
      "the", "a",  "an",   "of", "to", "in", "for", "on",   "at",   "by",   "is",
      "are", "be", "from", "it", "as", "or", "and", "that", "this", "with", "into",
  };
  for (const auto sw : kStops) {
    if (tok == sw) {
      return true;
    }
  }
  return false;
}

std::vector<std::string> tokenize_text(std::string_view text) {
  std::vector<std::string> raw;
  std::string cur;
  for (const char ch : text) {
    const auto u = static_cast<unsigned char>(ch);
    if (std::isalnum(u) != 0) {
      cur.push_back(static_cast<char>(std::tolower(u)));
    } else if (!cur.empty()) {
      raw.push_back(std::move(cur));
      cur.clear();
    }
  }
  if (!cur.empty()) {
    raw.push_back(std::move(cur));
  }
  std::vector<std::string> filtered;
  filtered.reserve(raw.size());
  for (const auto &tok : raw) {
    if (!is_stop_word(tok)) {
      filtered.push_back(tok);
    }
  }
  return filtered.empty() ? raw : filtered;
}

bool tokens_soft_match(std::string_view a, std::string_view b) noexcept {
  if (a == b) {
    return true;
  }
  if (a.size() >= 4U && b.size() >= 4U) {
    const std::size_t min_len = std::min(a.size(), b.size());
    const std::size_t max_len = std::max(a.size(), b.size());
    if (min_len >= 4U && max_len - min_len <= 4U) {
      std::size_t prefix = 0U;
      while (prefix < min_len && a[prefix] == b[prefix]) {
        ++prefix;
      }
      if (prefix >= 4U && prefix * 2U >= max_len) {
        return true;
      }
    }
  }
  return false;
}

double compute_lexical_similarity(QueryText query, CandidateText candidate) {
  const std::string q_low = ascii_lower(trim_sv(query.value));
  const std::string c_low = ascii_lower(trim_sv(candidate.value));
  if (q_low.empty() || c_low.empty()) {
    return 0.0;
  }
  if (q_low == c_low) {
    return 1.0;
  }

  const auto q_toks_vec = tokenize_text(q_low);
  const auto c_toks_vec = tokenize_text(c_low);
  if (q_toks_vec.empty() || c_toks_vec.empty()) {
    return 0.0;
  }

  std::set<std::string> q_set(q_toks_vec.begin(), q_toks_vec.end());
  std::set<std::string> c_set(c_toks_vec.begin(), c_toks_vec.end());

  std::size_t matched_q = 0U;
  for (const auto &qt : q_set) {
    if (c_set.contains(qt)) {
      ++matched_q;
      continue;
    }
    for (const auto &ct : c_set) {
      if (tokens_soft_match(qt, ct)) {
        ++matched_q;
        break;
      }
    }
  }

  if (matched_q == 0U) {
    return 0.0;
  }

  const std::size_t union_sz = q_set.size() + c_set.size() - matched_q;
  const double coverage =
      static_cast<double>(matched_q) / static_cast<double>(q_set.size());
  const double jaccard =
      union_sz > 0U ? static_cast<double>(matched_q) / static_cast<double>(union_sz)
                    : 0.0;
  double score = 0.65 * coverage + 0.35 * jaccard;
  if (c_low.find(q_low) != std::string::npos ||
      q_low.find(c_low) != std::string::npos) {
    score = std::min(1.0, score + 0.12);
  }
  return std::clamp(score, 0.0, 1.0);
}

std::string build_safe_fts5_query(std::string_view raw_query) {
  const auto tokens = tokenize_text(raw_query);
  if (tokens.empty()) {
    return {};
  }
  std::set<std::string> uniq(tokens.begin(), tokens.end());
  std::string out;
  bool first = true;
  for (const auto &tok : uniq) {
    if (tok.empty()) {
      continue;
    }
    if (!first) {
      out += " OR ";
    }
    first = false;
    out.push_back('"');
    out += tok;
    out.push_back('"');
  }
  return out;
}

double compute_cosine_similarity(const std::vector<float> &lhs,
                                 const std::vector<float> &rhs) noexcept {
  if (lhs.empty() || lhs.size() != rhs.size()) {
    return 0.0;
  }
  double dot = 0.0;
  double norm_a = 0.0;
  double norm_b = 0.0;
  for (std::size_t i = 0U; i < lhs.size(); ++i) {
    const double a = static_cast<double>(lhs[i]);
    const double b = static_cast<double>(rhs[i]);
    dot += a * b;
    norm_a += a * a;
    norm_b += b * b;
  }
  if (norm_a <= 0.0 || norm_b <= 0.0) {
    return 0.0;
  }
  const double cos = dot / (std::sqrt(norm_a) * std::sqrt(norm_b));
  return std::clamp(cos, 0.0, 1.0);
}

std::vector<unsigned char> encode_embedding_blob(const std::vector<float> &vec) {
  std::vector<unsigned char> out;
  if (vec.empty()) {
    return out;
  }
  out.resize(vec.size() * sizeof(float));
  std::memcpy(out.data(), vec.data(), out.size());
  return out;
}

std::vector<float> decode_embedding_blob(const void *data, int byte_len) {
  std::vector<float> out;
  if (data == nullptr || byte_len <= 0 ||
      (static_cast<std::size_t>(byte_len) % sizeof(float)) != 0U) {
    return out;
  }
  const std::size_t count = static_cast<std::size_t>(byte_len) / sizeof(float);
  out.resize(count);
  std::memcpy(out.data(), data, static_cast<std::size_t>(byte_len));
  return out;
}

// ---------------------------------------------------------------------------
// SQLite RAII Wrappers & Path Hardening
// ---------------------------------------------------------------------------

struct ScopedSqliteDb {
  sqlite3 *db = nullptr;
  ScopedSqliteDb() noexcept = default;
  ~ScopedSqliteDb() { reset(); }
  ScopedSqliteDb(const ScopedSqliteDb &) = delete;
  ScopedSqliteDb &operator=(const ScopedSqliteDb &) = delete;
  ScopedSqliteDb(ScopedSqliteDb &&other) noexcept
      : db(std::exchange(other.db, nullptr)) {}
  ScopedSqliteDb &operator=(ScopedSqliteDb &&other) noexcept {
    if (this != &other) {
      reset();
      db = std::exchange(other.db, nullptr);
    }
    return *this;
  }
  void reset() noexcept {
    if (db != nullptr) {
      (void)sqlite3_close_v2(db);
      db = nullptr;
    }
  }
};

struct ScopedSqliteStmt {
  sqlite3_stmt *stmt = nullptr;
  ScopedSqliteStmt() noexcept = default;
  ~ScopedSqliteStmt() { reset(); }
  ScopedSqliteStmt(const ScopedSqliteStmt &) = delete;
  ScopedSqliteStmt &operator=(const ScopedSqliteStmt &) = delete;
  void reset() noexcept {
    if (stmt != nullptr) {
      (void)sqlite3_finalize(stmt);
      stmt = nullptr;
    }
  }
};

struct ScopedTransaction {
  sqlite3 *db = nullptr;
  bool active = false;

  explicit ScopedTransaction(sqlite3 *conn) : db(conn) {}
  ~ScopedTransaction() {
    if (active && db != nullptr) {
      (void)sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
    }
  }
  ScopedTransaction(const ScopedTransaction &) = delete;
  ScopedTransaction &operator=(const ScopedTransaction &) = delete;

  bool begin() {
    if (db == nullptr) {
      return false;
    }
    const int rc = sqlite3_exec(db, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr);
    if (rc == SQLITE_OK) {
      active = true;
      return true;
    }
    return false;
  }

  bool commit() {
    if (!active || db == nullptr) {
      return false;
    }
    const int rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    if (rc == SQLITE_OK) {
      active = false;
      return true;
    }
    return false;
  }
};

Result<void> ensure_secure_parent_dir(const fs::path &parent) {
  if (parent.empty()) {
    return Result<void>::success();
  }
  const std::string pstr = parent.string();
  if (has_control_or_nul(pstr)) {
    return fail<void>(ErrorCode::invalid_range, ArcError::insecure_path);
  }
  struct stat st{};
  if (::lstat(pstr.c_str(), &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      return fail<void>(ErrorCode::invalid_range, ArcError::insecure_path);
    }
    if (!S_ISDIR(st.st_mode)) {
      return fail<void>(ErrorCode::io, ArcError::insecure_path);
    }
    return Result<void>::success();
  }
  if (errno != ENOENT) {
    return fail<void>(ErrorCode::io, ArcError::io_failed);
  }

  const fs::path grand = parent.parent_path();
  if (!grand.empty() && grand != parent) {
    const auto rec = ensure_secure_parent_dir(grand);
    if (!rec.has_value()) {
      return rec;
    }
  }
  if (::mkdir(pstr.c_str(), 0700) != 0 && errno != EEXIST) {
    return fail<void>(ErrorCode::io, ArcError::io_failed);
  }
  if (::lstat(pstr.c_str(), &st) != 0 || S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode)) {
    return fail<void>(ErrorCode::invalid_range, ArcError::insecure_path);
  }
  (void)::chmod(pstr.c_str(), 0700);
  return Result<void>::success();
}

void tighten_file_0600(const fs::path &path) noexcept {
  const std::string pstr = path.string();
  struct stat st{};
  if (::lstat(pstr.c_str(), &st) == 0 && S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
    (void)::chmod(pstr.c_str(), 0600);
  }
}

void tighten_db_and_sidecars(const fs::path &db_path) noexcept {
  if (db_path.empty()) {
    return;
  }
  tighten_file_0600(db_path);
  tighten_file_0600(fs::path{db_path.string() + "-wal"});
  tighten_file_0600(fs::path{db_path.string() + "-shm"});
}

int bind_text(sqlite3_stmt *stmt, int index, std::string_view value) noexcept {
  return sqlite3_bind_text(stmt, index, value.data() != nullptr ? value.data() : "",
                           static_cast<int>(value.size()), SQLITE_TRANSIENT);
}

std::string col_text(sqlite3_stmt *stmt, int col) {
  const auto *ptr = reinterpret_cast<const char *>(sqlite3_column_text(stmt, col));
  const int len = sqlite3_column_bytes(stmt, col);
  if (ptr == nullptr || len <= 0) {
    return {};
  }
  return std::string{ptr, static_cast<std::size_t>(len)};
}

// ---------------------------------------------------------------------------
// JSON Serialization Helpers for Params & Return Keys
// ---------------------------------------------------------------------------

Result<std::string> serialize_params_json(const std::vector<ArcParamSpec> &params) {
  Value::Array arr;
  arr.reserve(params.size());
  for (const auto &p : params) {
    Value::Object obj;
    obj.emplace_back("name", Value{p.name});
    obj.emplace_back("description", Value{p.description});
    obj.emplace_back("d_type", Value{p.d_type});
    obj.emplace_back("example", Value{p.example});
    obj.emplace_back("required", Value{p.required});
    arr.push_back(Value::object(std::move(obj)));
  }
  return dump_json(Value{std::move(arr)});
}

std::vector<ArcParamSpec> deserialize_params_json(std::string_view json_text) {
  std::vector<ArcParamSpec> out;
  const auto parsed = parse_json(json_text);
  if (!parsed.has_value()) {
    return out;
  }
  const auto *arr = std::get_if<Value::Array>(&parsed.value().value());
  if (arr == nullptr) {
    return out;
  }
  out.reserve(arr->size());
  for (const auto &item : *arr) {
    if (!std::holds_alternative<Value::Object>(item.value())) {
      continue;
    }
    ArcParamSpec spec{};
    if (const Value *v = item.find("name")) {
      if (const auto *s = std::get_if<std::string>(&v->value())) {
        spec.name = *s;
      }
    }
    if (const Value *v = item.find("description")) {
      if (const auto *s = std::get_if<std::string>(&v->value())) {
        spec.description = *s;
      }
    }
    if (const Value *v = item.find("d_type")) {
      if (const auto *s = std::get_if<std::string>(&v->value())) {
        spec.d_type = *s;
      }
    }
    if (const Value *v = item.find("example")) {
      if (const auto *s = std::get_if<std::string>(&v->value())) {
        spec.example = *s;
      }
    }
    if (const Value *v = item.find("required")) {
      if (const auto *b = std::get_if<bool>(&v->value())) {
        spec.required = *b;
      }
    }
    out.push_back(std::move(spec));
  }
  return out;
}

Result<std::string> serialize_string_vec_json(const std::vector<std::string> &items) {
  Value::Array arr;
  arr.reserve(items.size());
  for (const auto &s : items) {
    arr.emplace_back(s);
  }
  return dump_json(Value{std::move(arr)});
}

std::vector<std::string> deserialize_string_vec_json(std::string_view json_text) {
  std::vector<std::string> out;
  const auto parsed = parse_json(json_text);
  if (!parsed.has_value()) {
    return out;
  }
  const auto *arr = std::get_if<Value::Array>(&parsed.value().value());
  if (arr == nullptr) {
    return out;
  }
  out.reserve(arr->size());
  for (const auto &item : *arr) {
    if (const auto *s = std::get_if<std::string>(&item.value())) {
      out.push_back(*s);
    }
  }
  return out;
}

std::string join_params_text(const std::vector<ArcParamSpec> &params) {
  std::string out;
  for (const auto &p : params) {
    if (!out.empty()) {
      out.push_back(' ');
    }
    out += p.name;
    if (!p.description.empty()) {
      out.push_back(' ');
      out += p.description;
    }
  }
  return out;
}

std::string join_strings(const std::vector<std::string> &items) {
  std::string out;
  for (const auto &s : items) {
    if (!out.empty()) {
      out.push_back(' ');
    }
    out += s;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Value <-> Type Coercion (CPU-ARC Section 2.1 Type Safety)
// ---------------------------------------------------------------------------

std::optional<double> number_to_double(const Number &num) noexcept {
  return std::visit(
      [](const auto &n) -> std::optional<double> {
        using T = std::decay_t<decltype(n)>;
        if constexpr (std::is_same_v<T, std::int64_t>) {
          return static_cast<double>(n);
        } else if constexpr (std::is_same_v<T, std::uint64_t>) {
          return static_cast<double>(n);
        } else if constexpr (std::is_same_v<T, double>) {
          return std::isfinite(n) ? std::optional<double>{n} : std::nullopt;
        } else {
          double d = 0.0;
          const std::string t = Number{n}.text();
          if (parse_decimal_double(t, d) == std::errc{} && std::isfinite(d)) {
            return d;
          }
          return std::nullopt;
        }
      },
      num.storage());
}

std::optional<std::int64_t> number_to_int64(const Number &num) noexcept {
  return std::visit(
      [](const auto &n) -> std::optional<std::int64_t> {
        using T = std::decay_t<decltype(n)>;
        if constexpr (std::is_same_v<T, std::int64_t>) {
          return n;
        } else if constexpr (std::is_same_v<T, std::uint64_t>) {
          if (n <=
              static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return static_cast<std::int64_t>(n);
          }
          return std::nullopt;
        } else if constexpr (std::is_same_v<T, double>) {
          if (!std::isfinite(n)) {
            return std::nullopt;
          }
          const double r = std::round(n);
          if (std::fabs(n - r) > 1e-9) {
            return std::nullopt;
          }
          if (r < -9223372036854775808.0 || r >= 9223372036854775808.0) {
            return std::nullopt;
          }
          return static_cast<std::int64_t>(r);
        } else {
          double d = 0.0;
          const std::string t = Number{n}.text();
          if (parse_decimal_double(t, d) != std::errc{} || !std::isfinite(d)) {
            return std::nullopt;
          }
          const double r = std::round(d);
          if (std::fabs(d - r) > 1e-9) {
            return std::nullopt;
          }
          return static_cast<std::int64_t>(r);
        }
      },
      num.storage());
}

Result<Value> coerce_value_to_type(const Value &input, DtypeName dtype) {
  const std::string kind = ascii_lower(trim_sv(dtype.value));
  if (kind.empty() || kind == "any") {
    return Result<Value>::success(input);
  }

  if (kind == "str" || kind == "string") {
    if (const auto *s = std::get_if<std::string>(&input.value())) {
      return Result<Value>::success(Value{*s});
    }
    if (const auto *b = std::get_if<bool>(&input.value())) {
      return Result<Value>::success(Value{std::string{*b ? "true" : "false"}});
    }
    if (const auto *n = std::get_if<Number>(&input.value())) {
      return Result<Value>::success(Value{n->text()});
    }
    if (std::holds_alternative<std::nullptr_t>(input.value())) {
      return Result<Value>::success(Value{std::string{""}});
    }
    const auto dumped = dump_json(input);
    if (!dumped.has_value()) {
      return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
    }
    return Result<Value>::success(Value{dumped.value()});
  }

  if (kind == "int" || kind == "integer") {
    if (const auto *n = std::get_if<Number>(&input.value())) {
      const auto iv = number_to_int64(*n);
      if (iv.has_value()) {
        return Result<Value>::success(Value{Number{*iv}});
      }
      return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
    }
    if (const auto *b = std::get_if<bool>(&input.value())) {
      return Result<Value>::success(Value{Number{std::int64_t{*b ? 1 : 0}}});
    }
    if (const auto *s = std::get_if<std::string>(&input.value())) {
      const std::string_view t = trim_sv(*s);
      if (t.empty()) {
        return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
      }
      const auto pn = parse_number(t);
      if (pn.has_value()) {
        const auto iv = number_to_int64(pn.value());
        if (iv.has_value()) {
          return Result<Value>::success(Value{Number{*iv}});
        }
      }
      double d = 0.0;
      if (parse_decimal_double(t, d) == std::errc{} && std::isfinite(d)) {
        const double r = std::round(d);
        if (std::fabs(d - r) <= 1e-9 && r >= -9223372036854775808.0 &&
            r < 9223372036854775808.0) {
          return Result<Value>::success(Value{Number{static_cast<std::int64_t>(r)}});
        }
      }
    }
    return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
  }

  if (kind == "float" || kind == "number") {
    if (const auto *n = std::get_if<Number>(&input.value())) {
      const auto dv = number_to_double(*n);
      if (dv.has_value()) {
        return Result<Value>::success(Value{Number{*dv}});
      }
      return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
    }
    if (const auto *b = std::get_if<bool>(&input.value())) {
      return Result<Value>::success(Value{Number{*b ? 1.0 : 0.0}});
    }
    if (const auto *s = std::get_if<std::string>(&input.value())) {
      const std::string_view t = trim_sv(*s);
      double d = 0.0;
      if (!t.empty() && parse_decimal_double(t, d) == std::errc{} && std::isfinite(d)) {
        return Result<Value>::success(Value{Number{d}});
      }
    }
    return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
  }

  if (kind == "bool" || kind == "boolean") {
    if (const auto *b = std::get_if<bool>(&input.value())) {
      return Result<Value>::success(Value{*b});
    }
    if (const auto *n = std::get_if<Number>(&input.value())) {
      const auto dv = number_to_double(*n);
      if (dv.has_value()) {
        return Result<Value>::success(Value{*dv != 0.0});
      }
      return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
    }
    if (const auto *s = std::get_if<std::string>(&input.value())) {
      const std::string low = ascii_lower(trim_sv(*s));
      if (low == "true" || low == "1" || low == "yes") {
        return Result<Value>::success(Value{true});
      }
      if (low == "false" || low == "0" || low == "no") {
        return Result<Value>::success(Value{false});
      }
    }
    return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
  }

  if (kind == "list" || kind == "array" || kind == "set") {
    auto deduplicate = [&](const Value::Array &arr) -> Value {
      if (kind != "set") {
        return Value{arr};
      }
      Value::Array uniq;
      for (const auto &elem : arr) {
        bool seen = false;
        for (const auto &u : uniq) {
          if (u == elem) {
            seen = true;
            break;
          }
        }
        if (!seen) {
          uniq.push_back(elem);
        }
      }
      return Value{std::move(uniq)};
    };
    if (const auto *arr = std::get_if<Value::Array>(&input.value())) {
      return Result<Value>::success(deduplicate(*arr));
    }
    if (const auto *obj = std::get_if<Value::Object>(&input.value())) {
      if (obj->empty()) {
        return Result<Value>::success(Value{Value::Array{}});
      }
      return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
    }
    if (const auto *s = std::get_if<std::string>(&input.value())) {
      const auto parsed = parse_json(trim_sv(*s));
      if (parsed.has_value()) {
        if (const auto *arr = std::get_if<Value::Array>(&parsed.value().value())) {
          return Result<Value>::success(deduplicate(*arr));
        }
      }
    }
    return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
  }

  if (kind == "dict" || kind == "object" || kind == "table") {
    if (std::holds_alternative<Value::Object>(input.value())) {
      return Result<Value>::success(input);
    }
    if (const auto *arr = std::get_if<Value::Array>(&input.value())) {
      if (arr->empty()) {
        return Result<Value>::success(Value::object({}));
      }
      return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
    }
    if (const auto *s = std::get_if<std::string>(&input.value())) {
      const auto parsed = parse_json(trim_sv(*s));
      if (parsed.has_value() &&
          std::holds_alternative<Value::Object>(parsed.value().value())) {
        return Result<Value>::success(parsed.value());
      }
    }
    return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
  }

  return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
}

// ---------------------------------------------------------------------------
// Lua 5.5.1 Allocator, Sandbox, Value Bridge & Runtime State
// ---------------------------------------------------------------------------

struct LuaAllocState {
  std::size_t used_bytes = 0U;
  std::size_t peak_bytes = 0U;
  std::size_t limit_bytes = kDefaultMaxLuaMemoryBytes;
  bool oom_triggered = false;
};

extern "C" {
static void *arc_lua_alloc(void *const ud, void *ptr, std::size_t osize,
                           std::size_t nsize) noexcept {
  auto *st = static_cast<LuaAllocState *>(ud);
  if (st == nullptr) {
    return nullptr;
  }
  if (ptr == nullptr) {
    osize = 0U;
  }
  if (nsize == 0U) {
    std::free(ptr);
    if (osize <= st->used_bytes) {
      st->used_bytes -= osize;
    } else {
      st->used_bytes = 0U;
    }
    return nullptr;
  }
  const std::size_t base_used =
      (osize <= st->used_bytes) ? (st->used_bytes - osize) : 0U;
  if (nsize > st->limit_bytes || base_used > st->limit_bytes - nsize) {
    st->oom_triggered = true;
    return nullptr;
  }
  void *next = std::realloc(ptr, nsize);
  if (next == nullptr) {
    st->oom_triggered = true;
    return nullptr;
  }
  st->used_bytes = base_used + nsize;
  if (st->used_bytes > st->peak_bytes) {
    st->peak_bytes = st->used_bytes;
  }
  return next;
}
}

static_assert(std::is_convertible_v<decltype(&arc_lua_alloc), lua_Alloc>);

std::int64_t monotonic_now_ns() noexcept {
  struct timespec ts{};
  if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return static_cast<std::int64_t>(ts.tv_sec) * 1000000000LL +
         static_cast<std::int64_t>(ts.tv_nsec);
}

struct ScopedLuaState {
  lua_State *L = nullptr;
  ScopedLuaState() noexcept = default;
  ~ScopedLuaState() {
    if (L != nullptr) {
      lua_close(L);
      L = nullptr;
    }
  }
  ScopedLuaState(const ScopedLuaState &) = delete;
  ScopedLuaState &operator=(const ScopedLuaState &) = delete;
};

struct ContextLayer {
  std::string function_id;
  std::vector<std::pair<std::string, Value>> entries;
  std::string lua_source;
  std::string chunk_name;
};

struct ArcRuntimeState {
  const ArcRegistry *registry = nullptr;
  const ArcRegistryConfig *registry_config = nullptr;
  const ArcRuntimeCallbacks *callbacks = nullptr;
  ArcExecutionLimits limits{};

  LuaAllocState alloc{};
  std::int64_t deadline_ns = 0;
  std::uint64_t instructions = 0U;
  int hook_step = 1000;

  std::vector<ContextLayer> layers;
  std::vector<ArcNarrationEntry> narrations;
  std::uint64_t search_calls = 0U;
  std::uint64_t load_search_calls = 0U;
  std::uint32_t do_calls = 0U;
  std::uint32_t lm_calls = 0U;
  std::uint32_t tool_calls = 0U;
  bool turn_tainted = false;

  // Heap-owned staging slots that outlive lua_pcall so no C++ RAII local is ever
  // live across a Lua C-API call that can allocate or longjmp.
  Value pending_value;
  std::string pending_string;
  std::string root_lua_source;
  std::string root_chunk_name;
  bool root_is_compiled = false;

  ArcError abort_error = ArcError::none;
  ErrorCode abort_code = ErrorCode::external_unknown;
  std::string last_error_msg;

  void record_abort(ErrorCode code, ArcError err, std::string msg) {
    if (abort_error == ArcError::none) {
      abort_error = err;
      abort_code = code;
      last_error_msg = std::move(msg);
    }
  }
};

struct ArcContextUserdata {
  std::uint64_t magic = kArcCtxMagic;
  ArcRuntimeState *state = nullptr;
};

ArcRuntimeState *runtime_from_lua(lua_State *L) noexcept {
  return *static_cast<ArcRuntimeState **>(lua_getextraspace(L));
}

ArcRuntimeState *check_ctx_userdata(lua_State *L, int idx) noexcept {
  void *raw = luaL_testudata(L, idx, kArcCtxMetatable);
  if (raw == nullptr) {
    return nullptr;
  }
  auto *ud = static_cast<ArcContextUserdata *>(raw);
  if (ud->magic != kArcCtxMagic || ud->state == nullptr) {
    return nullptr;
  }
  return ud->state;
}

bool is_forbidden_global(std::string_view key) noexcept {
  static constexpr std::array<std::string_view, 19> kForbidden = {
      "os",       "io",           "debug",        "package",    "require",
      "dofile",   "loadfile",     "load",         "loadstring", "collectgarbage",
      "_G",       "setmetatable", "getmetatable", "rawget",     "rawset",
      "rawequal", "rawlen",       "coroutine",    "arg",
  };
  for (const auto name : kForbidden) {
    if (key == name) {
      return true;
    }
  }
  return false;
}

extern "C" void arc_lua_hook(lua_State *L, lua_Debug * /*ar*/) {
  auto *st = runtime_from_lua(L);
  if (st == nullptr) {
    return;
  }
  if (st->alloc.oom_triggered) {
    st->record_abort(ErrorCode::allocation, ArcError::memory_limit_exceeded,
                     "Lua memory limit exceeded");
    lua_sethook(L, arc_lua_hook, LUA_MASKCOUNT, 1);
    luaL_error(L, "arc: memory limit exceeded");
    return;
  }
  if (st->abort_error != ArcError::none) {
    lua_sethook(L, arc_lua_hook, LUA_MASKCOUNT, 1);
    luaL_error(L, "arc: execution aborted");
    return;
  }
  st->instructions += static_cast<std::uint64_t>(st->hook_step);
  if (st->instructions > st->limits.max_lua_instructions) {
    st->record_abort(ErrorCode::capacity, ArcError::instruction_limit_exceeded,
                     "Lua instruction limit exceeded");
    lua_sethook(L, arc_lua_hook, LUA_MASKCOUNT, 1);
    luaL_error(L, "arc: instruction limit exceeded");
    return;
  }
  if (st->deadline_ns > 0 && monotonic_now_ns() >= st->deadline_ns) {
    st->record_abort(ErrorCode::interrupted, ArcError::timeout,
                     "Lua execution timed out");
    lua_sethook(L, arc_lua_hook, LUA_MASKCOUNT, 1);
    luaL_error(L, "arc: timeout exceeded");
    return;
  }
}

bool push_blackbird_value(lua_State *L, const Value &val, std::size_t depth = 0U) {
  if (depth > 64U) {
    return false;
  }
  luaL_checkstack(L, 8, "arc value push stack overflow");
  return std::visit(
      [&](const auto &v) -> bool {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
          lua_pushnil(L);
          return true;
        } else if constexpr (std::is_same_v<T, bool>) {
          lua_pushboolean(L, v ? 1 : 0);
          return true;
        } else if constexpr (std::is_same_v<T, std::string>) {
          lua_pushlstring(L, v.data(), v.size());
          return true;
        } else if constexpr (std::is_same_v<T, Number>) {
          return std::visit(
              [&](const auto &n) -> bool {
                using N = std::decay_t<decltype(n)>;
                if constexpr (std::is_same_v<N, std::int64_t>) {
                  lua_pushinteger(L, static_cast<lua_Integer>(n));
                  return true;
                } else if constexpr (std::is_same_v<N, std::uint64_t>) {
                  if (n <= static_cast<std::uint64_t>(
                               std::numeric_limits<lua_Integer>::max())) {
                    lua_pushinteger(L, static_cast<lua_Integer>(n));
                  } else {
                    lua_pushnumber(L, static_cast<lua_Number>(n));
                  }
                  return true;
                } else if constexpr (std::is_same_v<N, double>) {
                  lua_pushnumber(L, static_cast<lua_Number>(n));
                  return true;
                } else {
                  const auto dv = number_to_double(v);
                  lua_pushnumber(L, static_cast<lua_Number>(dv.value_or(0.0)));
                  return true;
                }
              },
              v.storage());
        } else if constexpr (std::is_same_v<T, Value::Array>) {
          lua_createtable(
              L, static_cast<int>(std::min<std::size_t>(v.size(), 1000000U)), 0);
          for (std::size_t i = 0U; i < v.size(); ++i) {
            if (!push_blackbird_value(L, v[i], depth + 1U)) {
              lua_pop(L, 1);
              return false;
            }
            lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1U));
          }
          return true;
        } else {
          lua_createtable(L, 0,
                          static_cast<int>(std::min<std::size_t>(v.size(), 1000000U)));
          for (const auto &[k, elem] : v) {
            lua_pushlstring(L, k.data(), k.size());
            if (!push_blackbird_value(L, elem, depth + 1U)) {
              lua_pop(L, 2);
              return false;
            }
            lua_rawset(L, -3);
          }
          return true;
        }
      },
      val.value());
}

struct LuaReadBudget {
  std::size_t depth = 0U;
  std::size_t *node_count = nullptr;
};

Result<Value> read_lua_value(lua_State *L, int index, LuaReadBudget budget = {}) {
  std::size_t local_nodes = 0U;
  std::size_t *node_count =
      budget.node_count != nullptr ? budget.node_count : &local_nodes;
  if (budget.depth > 64U || ++(*node_count) > 200000U) {
    return fail<Value>(ErrorCode::capacity, ArcError::type_conversion_failed);
  }
  index = lua_absindex(L, index);
  switch (lua_type(L, index)) {
  case LUA_TNIL:
    return Result<Value>::success(Value{nullptr});
  case LUA_TBOOLEAN:
    return Result<Value>::success(Value{lua_toboolean(L, index) != 0});
  case LUA_TSTRING: {
    std::size_t len = 0U;
    const char *ptr = lua_tolstring(L, index, &len);
    return Result<Value>::success(Value{std::string{ptr != nullptr ? ptr : "", len}});
  }
  case LUA_TNUMBER:
    if (lua_isinteger(L, index) != 0) {
      return Result<Value>::success(
          Value{Number{static_cast<std::int64_t>(lua_tointeger(L, index))}});
    } else {
      const double d = static_cast<double>(lua_tonumber(L, index));
      if (!std::isfinite(d)) {
        return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
      }
      return Result<Value>::success(Value{Number{d}});
    }
  case LUA_TTABLE: {
    bool has_string_key = false;
    bool has_int_key = false;
    lua_Integer max_int = 0;
    std::size_t total_keys = 0U;
    lua_pushnil(L);
    while (lua_next(L, index) != 0) {
      ++total_keys;
      const int kt = lua_type(L, -2);
      if (kt == LUA_TSTRING) {
        has_string_key = true;
      } else if (kt == LUA_TNUMBER && lua_isinteger(L, -2) != 0) {
        const lua_Integer ki = lua_tointeger(L, -2);
        if (ki >= 1) {
          has_int_key = true;
          if (ki > max_int) {
            max_int = ki;
          }
        } else {
          has_string_key = true;
        }
      } else {
        lua_pop(L, 2);
        return fail<Value>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
      }
      lua_pop(L, 1);
    }

    if (total_keys == 0U) {
      return Result<Value>::success(Value::object({}));
    }

    if (has_int_key && !has_string_key &&
        static_cast<std::size_t>(max_int) == total_keys) {
      Value::Array arr;
      arr.reserve(total_keys);
      for (std::size_t i = 1U; i <= total_keys; ++i) {
        lua_rawgeti(L, index, static_cast<lua_Integer>(i));
        auto elem = read_lua_value(L, -1, LuaReadBudget{budget.depth + 1U, node_count});
        lua_pop(L, 1);
        if (!elem.has_value()) {
          return elem;
        }
        arr.push_back(std::move(elem.value()));
      }
      return Result<Value>::success(Value{std::move(arr)});
    }

    Value::Object obj;
    obj.reserve(total_keys);
    lua_pushnil(L);
    while (lua_next(L, index) != 0) {
      std::string key;
      if (lua_type(L, -2) == LUA_TSTRING) {
        std::size_t klen = 0U;
        const char *kptr = lua_tolstring(L, -2, &klen);
        key.assign(kptr != nullptr ? kptr : "", klen);
      } else {
        key = std::to_string(lua_tointeger(L, -2));
      }
      auto val = read_lua_value(L, -1, LuaReadBudget{budget.depth + 1U, node_count});
      lua_pop(L, 1);
      if (!val.has_value()) {
        lua_pop(L, 1);
        return val;
      }
      obj.emplace_back(std::move(key), std::move(val.value()));
    }
    std::sort(obj.begin(), obj.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });
    return Result<Value>::success(Value::object(std::move(obj)));
  }
  default:
    return fail<Value>(ErrorCode::unsupported, ArcError::type_conversion_failed);
  }
}

// Forward declaration for sandboxed _ENV builder used by both root & arc.do_.
void push_sandbox_env(lua_State *L);

// Score a query against an in-memory map/list of (key, Value) entries.
std::optional<std::size_t>
find_best_semantic_key(const std::vector<std::pair<std::string, Value>> &entries,
                       QueryText query, double min_score,
                       const ArcEmbedCallback &embed_cb) {
  if (entries.empty()) {
    return std::nullopt;
  }
  const std::string q_low = ascii_lower(trim_sv(query.value));
  for (std::size_t i = 0U; i < entries.size(); ++i) {
    if (ascii_lower(trim_sv(entries[i].first)) == q_low) {
      return i;
    }
  }

  std::optional<std::vector<float>> q_emb;
  if (embed_cb) {
    auto emb = embed_cb(query.value);
    if (emb.has_value() && !emb.value().empty()) {
      q_emb = std::move(emb.value());
    }
  }

  std::optional<std::size_t> best_idx;
  double best_score = -1.0;
  for (std::size_t i = 0U; i < entries.size(); ++i) {
    const double lex =
        compute_lexical_similarity(query, CandidateText{entries[i].first});
    double score = lex;
    if (q_emb.has_value() && embed_cb) {
      auto c_emb = embed_cb(entries[i].first);
      if (c_emb.has_value() && c_emb.value().size() == q_emb->size()) {
        const double dense = compute_cosine_similarity(*q_emb, c_emb.value());
        score = std::clamp(0.45 * lex + 0.55 * dense, 0.0, 1.0);
      }
    }
    if (score >= min_score &&
        (score > best_score + 1e-12 ||
         (std::fabs(score - best_score) <= 1e-12 && best_idx.has_value() &&
          entries[i].first < entries[*best_idx].first))) {
      best_score = score;
      best_idx = i;
    }
  }
  return best_idx;
}

// ---------------------------------------------------------------------------
// Lua Sandbox Metamethods & 7 CPU-ARC Primitives
// ---------------------------------------------------------------------------

extern "C" int lua_env_index(lua_State *L) {
  const char *err_cstr = nullptr;
  {
    auto *st = runtime_from_lua(L);
    if (st != nullptr && lua_type(L, 2) == LUA_TSTRING) {
      std::size_t len = 0U;
      const char *ptr = lua_tolstring(L, 2, &len);
      const std::string_view key{ptr != nullptr ? ptr : "", len};
      if (is_forbidden_global(key)) {
        st->record_abort(ErrorCode::unsupported, ArcError::sandbox_violation,
                         "sandbox violation: access to forbidden global '" +
                             std::string{key} + "'");
        err_cstr = st->last_error_msg.c_str();
      }
    }
  }
  if (err_cstr != nullptr) {
    return luaL_error(L, "%s", err_cstr);
  }
  lua_pushnil(L);
  return 1;
}

extern "C" int lua_string_index(lua_State *L) {
  const char *err_cstr = nullptr;
  {
    auto *st = runtime_from_lua(L);
    if (st != nullptr && lua_type(L, 2) == LUA_TSTRING) {
      std::size_t len = 0U;
      const char *ptr = lua_tolstring(L, 2, &len);
      const std::string_view key{ptr != nullptr ? ptr : "", len};
      if (key == "dump") {
        st->record_abort(ErrorCode::unsupported, ArcError::sandbox_violation,
                         "sandbox violation: string.dump is forbidden");
        err_cstr = st->last_error_msg.c_str();
      }
    }
  }
  if (err_cstr != nullptr) {
    return luaL_error(L, "%s", err_cstr);
  }
  lua_pushnil(L);
  return 1;
}

extern "C" int lua_ctx_tostring(lua_State *L) {
  lua_pushliteral(L, "ArcContext");
  return 1;
}

extern "C" int lua_ctx_newindex(lua_State *L) {
  const char *err_cstr = nullptr;
  {
    auto *st = runtime_from_lua(L);
    if (st != nullptr) {
      st->record_abort(ErrorCode::unsupported, ArcError::sandbox_violation,
                       "sandbox violation: cannot mutate ArcContext userdata");
      err_cstr = st->last_error_msg.c_str();
    }
  }
  return luaL_error(L, "%s", err_cstr != nullptr ? err_cstr : "sandbox violation");
}

// 1) arc.load(ctx_or_table, query [, d_type [, ctx]])
// ZERO C++ RAII locals remain alive across push_blackbird_value or luaL_error.
extern "C" int lua_arc_load(lua_State *L) {
  auto *st = runtime_from_lua(L);
  const char *err_cstr = nullptr;
  bool ready_to_push = false;
  {
    if (st == nullptr) {
      err_cstr = "arc.load: missing runtime state";
    } else if (st->abort_error != ArcError::none) {
      err_cstr = st->last_error_msg.c_str();
    } else if (lua_gettop(L) < 2 || lua_type(L, 2) != LUA_TSTRING) {
      st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                       "arc.load expects (ctx_or_table, query_string [, d_type])");
      err_cstr = st->last_error_msg.c_str();
    } else {
      std::size_t qlen = 0U;
      const char *qptr = lua_tolstring(L, 2, &qlen);
      const std::string query{qptr != nullptr ? qptr : "", qlen};

      std::string dtype = "any";
      if (lua_gettop(L) >= 3 && lua_type(L, 3) == LUA_TSTRING) {
        std::size_t dlen = 0U;
        const char *dptr = lua_tolstring(L, 3, &dlen);
        dtype.assign(dptr != nullptr ? dptr : "", dlen);
      }

      ++st->load_search_calls;
      const ArcEmbedCallback empty_embed{};
      const ArcEmbedCallback &embed_cb = st->registry_config != nullptr
                                             ? st->registry_config->embed_callback
                                             : empty_embed;
      std::optional<Value> found;

      if (auto *ctx_st = check_ctx_userdata(L, 1); ctx_st != nullptr) {
        for (std::size_t rev = ctx_st->layers.size(); rev > 0U; --rev) {
          const auto &layer = ctx_st->layers[rev - 1U];
          const auto idx = find_best_semantic_key(layer.entries, QueryText{query},
                                                  st->limits.min_load_score, embed_cb);
          if (idx.has_value()) {
            found = layer.entries[*idx].second;
            break;
          }
        }
      } else if (lua_type(L, 1) == LUA_TTABLE) {
        const auto table_val = read_lua_value(L, 1);
        if (!table_val.has_value()) {
          st->record_abort(ErrorCode::invalid_range, ArcError::type_conversion_failed,
                           "arc.load: failed to read table dictionary");
          err_cstr = st->last_error_msg.c_str();
        } else if (const auto *obj =
                       std::get_if<Value::Object>(&table_val.value().value())) {
          const auto idx = find_best_semantic_key(*obj, QueryText{query},
                                                  st->limits.min_load_score, embed_cb);
          if (idx.has_value()) {
            found = (*obj)[*idx].second;
          }
        }
      } else {
        st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                         "arc.load: first argument must be ctx or dictionary table");
        err_cstr = st->last_error_msg.c_str();
      }

      if (err_cstr == nullptr) {
        if (!found.has_value()) {
          st->record_abort(ErrorCode::invalid_range, ArcError::load_not_found,
                           "arc.load: no matching entry for query '" + query + "'");
          err_cstr = st->last_error_msg.c_str();
        } else {
          auto coerced = coerce_value_to_type(*found, DtypeName{dtype});
          if (!coerced.has_value()) {
            st->record_abort(ErrorCode::invalid_range, ArcError::type_conversion_failed,
                             "arc.load: failed to coerce value to '" + dtype + "'");
            err_cstr = st->last_error_msg.c_str();
          } else {
            st->pending_value = std::move(coerced.value());
            ready_to_push = true;
          }
        }
      }
    }
  }
  if (!ready_to_push) {
    return luaL_error(L, "%s", err_cstr != nullptr ? err_cstr : "arc.load failed");
  }
  if (!push_blackbird_value(L, st->pending_value)) {
    st->pending_value = Value{nullptr};
    st->record_abort(ErrorCode::capacity, ArcError::type_conversion_failed,
                     "arc.load: failed to push coerced value");
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  st->pending_value = Value{nullptr};
  return 1;
}

// Protected trampoline for arc.do_: ZERO C++ RAII locals on stack.
extern "C" int lua_arc_do_trampoline(lua_State *L) {
  auto *st = check_ctx_userdata(L, 1);
  if (st == nullptr || st->layers.empty()) {
    return luaL_error(L, "arc.do_: missing runtime layer");
  }
  const ContextLayer &layer = st->layers.back();
  const char *src_ptr = layer.lua_source.data();
  const std::size_t src_len = layer.lua_source.size();
  const char *cname_ptr = layer.chunk_name.c_str();

  const int load_rc = luaL_loadbufferx(L, src_ptr, src_len, cname_ptr, "t");
  if (load_rc != LUA_OK) {
    return lua_error(L);
  }
  push_sandbox_env(L);
  const int env_idx = lua_gettop(L);
  lua_pushvalue(L, env_idx);
  (void)lua_setupvalue(L, env_idx - 1, 1); // sets chunk's _ENV
  lua_pushvalue(L, env_idx - 1);           // chunk on top
  lua_call(L, 0, 0);

  lua_getfield(L, env_idx, "semantic_function");
  if (lua_type(L, -1) != LUA_TFUNCTION) {
    return luaL_error(L, "callee does not define semantic_function");
  }
  lua_pushvalue(L, 1); // ctx userdata
  lua_call(L, 1, 1);

  if (lua_type(L, -1) != LUA_TTABLE) {
    return luaL_error(L, "callee semantic_function must return a table");
  }
  lua_remove(L, env_idx);
  lua_remove(L, env_idx - 1);
  return 1;
}

// 2) arc.do_(ctx, query, payloads)
// Runs all allocating/throwing Lua API calls inside lua_pcall(lua_arc_do_trampoline)
// with ZERO live C++ RAII locals so OOM longjmp can never leak or skip layer pop!
extern "C" int lua_arc_do(lua_State *L) {
  auto *st = runtime_from_lua(L);
  const char *err_cstr = nullptr;
  bool layer_pushed = false;
  {
    if (st == nullptr || st->registry == nullptr) {
      err_cstr = "arc.do_: missing runtime or registry";
    } else if (st->abort_error != ArcError::none) {
      err_cstr = st->last_error_msg.c_str();
    } else if (check_ctx_userdata(L, 1) == nullptr || lua_type(L, 2) != LUA_TSTRING) {
      st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                       "arc.do_ expects (ctx, query_string [, payloads_table])");
      err_cstr = st->last_error_msg.c_str();
    } else {
      const std::uint32_t next_depth = static_cast<std::uint32_t>(st->layers.size());
      if (next_depth > st->limits.max_call_depth) {
        st->record_abort(ErrorCode::capacity, ArcError::recursion_limit_exceeded,
                         "arc.do_: recursion depth limit exceeded");
        err_cstr = st->last_error_msg.c_str();
      } else if (st->do_calls >= st->limits.max_do_calls) {
        st->record_abort(ErrorCode::capacity, ArcError::step_limit_exceeded,
                         "arc.do_: max do_ calls exceeded");
        err_cstr = st->last_error_msg.c_str();
      } else {
        std::size_t qlen = 0U;
        const char *qptr = lua_tolstring(L, 2, &qlen);
        const std::string query{qptr != nullptr ? qptr : "", qlen};

        Value::Object child_entries;
        if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
          if (lua_type(L, 3) != LUA_TTABLE) {
            st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                             "arc.do_: payloads must be a table");
            err_cstr = st->last_error_msg.c_str();
          } else {
            auto pv = read_lua_value(L, 3);
            if (!pv.has_value()) {
              st->record_abort(ErrorCode::invalid_range,
                               ArcError::type_conversion_failed,
                               "arc.do_: failed to convert payloads table");
              err_cstr = st->last_error_msg.c_str();
            } else if (auto *obj = std::get_if<Value::Object>(&pv.value().value())) {
              child_entries = std::move(*obj);
            }
          }
        }

        if (err_cstr == nullptr) {
          ++st->search_calls;
          ++st->do_calls;
          const auto matches = st->registry->search_functions(query, 1U);
          if (!matches.has_value() || matches.value().empty() ||
              matches.value()[0].score < st->limits.min_do_score) {
            st->record_abort(ErrorCode::invalid_range, ArcError::function_not_found,
                             "arc.do_: no matching semantic function for '" + query +
                                 "'");
            err_cstr = st->last_error_msg.c_str();
          } else {
            const auto callee =
                st->registry->get_function(matches.value()[0].function_id);
            if (!callee.has_value()) {
              st->record_abort(ErrorCode::invalid_range, ArcError::function_not_found,
                               "arc.do_: callee disappeared from registry");
              err_cstr = st->last_error_msg.c_str();
            } else if (!callee.value().lua_source.empty() &&
                       callee.value().lua_source[0] == '\x1b') {
              st->record_abort(ErrorCode::unsupported, ArcError::sandbox_violation,
                               "arc.do_: binary bytecode forbidden");
              err_cstr = st->last_error_msg.c_str();
            } else {
              st->layers.push_back(
                  ContextLayer{callee.value().id, std::move(child_entries),
                               callee.value().lua_source, "@" + callee.value().id});
              layer_pushed = true;
            }
          }
        }
      }
    }
  }

  if (!layer_pushed) {
    return luaL_error(L, "%s", err_cstr != nullptr ? err_cstr : "arc.do_ failed");
  }

  // Zero C++ RAII locals on stack across protected callee execution!
  lua_pushcfunction(L, lua_arc_do_trampoline);
  lua_pushvalue(L, 1); // ctx userdata
  const int rc = lua_pcall(L, 1, 1, 0);

  // Guaranteed pop even on OOM or Lua error inside trampoline!
  if (!st->layers.empty()) {
    st->layers.pop_back();
  }

  if (rc != LUA_OK || st->alloc.oom_triggered || st->abort_error != ArcError::none) {
    if (st->alloc.oom_triggered || rc == LUA_ERRMEM) {
      st->record_abort(ErrorCode::allocation, ArcError::memory_limit_exceeded,
                       "Lua memory limit exceeded in callee");
    } else if (st->abort_error == ArcError::none) {
      const char *lerr =
          (lua_type(L, -1) == LUA_TSTRING) ? lua_tostring(L, -1) : nullptr;
      st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                       lerr != nullptr ? lerr : "callee execution error");
    }
    lua_pop(L, 1);
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  return 1;
}

// Frame synchronization helper passed ONLY to compiled modules (never on _ENV.arc)
// so compiled arc.narrate matches dynamic depth & function_id with guaranteed pop!
extern "C" int lua_arc_compiled_frame(lua_State *L) {
  auto *st = check_ctx_userdata(L, 1);
  if (st == nullptr || lua_type(L, 2) != LUA_TSTRING ||
      lua_type(L, 3) != LUA_TFUNCTION || lua_type(L, 4) != LUA_TTABLE) {
    return luaL_error(L, "arc compiled frame: invalid arguments");
  }
  if (st->abort_error != ArcError::none) {
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  const std::uint32_t next_depth = static_cast<std::uint32_t>(st->layers.size());
  if (next_depth > st->limits.max_call_depth) {
    st->record_abort(ErrorCode::capacity, ArcError::recursion_limit_exceeded,
                     "compiled call: recursion depth limit exceeded");
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  {
    std::size_t flen = 0U;
    const char *fptr = lua_tolstring(L, 2, &flen);
    st->layers.push_back(
        ContextLayer{std::string{fptr != nullptr ? fptr : "", flen}, {}, {}, {}});
  }
  // ZERO C++ RAII locals on stack across lua_pcall!
  lua_pushvalue(L, 3); // compiled callee function
  lua_pushvalue(L, 1); // ctx userdata
  lua_pushvalue(L, 4); // __arc_layers table
  const int rc = lua_pcall(L, 2, 1, 0);

  if (!st->layers.empty()) {
    st->layers.pop_back();
  }
  if (rc != LUA_OK || st->alloc.oom_triggered || st->abort_error != ArcError::none) {
    if (st->alloc.oom_triggered || rc == LUA_ERRMEM) {
      st->record_abort(ErrorCode::allocation, ArcError::memory_limit_exceeded,
                       "Lua memory limit exceeded in compiled callee");
    }
    return lua_error(L);
  }
  return 1;
}

// 3) arc.narrate(ctx, message)
extern "C" int lua_arc_narrate(lua_State *L) {
  auto *st = runtime_from_lua(L);
  if (st == nullptr) {
    return luaL_error(L, "arc.narrate: missing runtime");
  }
  if (st->abort_error != ArcError::none) {
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  if (check_ctx_userdata(L, 1) == nullptr || lua_gettop(L) < 2) {
    st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                     "arc.narrate expects (ctx, message)");
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  // Call luaL_tolstring BEFORE constructing any C++ RAII objects!
  std::size_t mlen = 0U;
  const char *mptr = luaL_tolstring(L, 2, &mlen);
  {
    if (st->narrations.size() < st->limits.max_narration_entries) {
      const std::uint32_t depth =
          st->layers.empty() ? 0U : static_cast<std::uint32_t>(st->layers.size() - 1U);
      const std::string fn_id =
          st->layers.empty() ? std::string{} : st->layers.back().function_id;
      st->narrations.push_back(ArcNarrationEntry{
          depth, fn_id, std::string{mptr != nullptr ? mptr : "", mlen}});
    }
  }
  lua_pop(L, 1);
  return 0;
}

// 4a) arc.convert(value, d_type)  [also accepts arc.convert(ctx, value, d_type)]
extern "C" int lua_arc_convert(lua_State *L) {
  auto *st = runtime_from_lua(L);
  const char *err_cstr = nullptr;
  bool ready_to_push = false;
  {
    if (st == nullptr) {
      err_cstr = "arc.convert: missing runtime";
    } else if (st->abort_error != ArcError::none) {
      err_cstr = st->last_error_msg.c_str();
    } else {
      int val_idx = 1;
      int type_idx = 2;
      if (lua_gettop(L) >= 3 && check_ctx_userdata(L, 1) != nullptr) {
        val_idx = 2;
        type_idx = 3;
      }
      if (lua_gettop(L) < type_idx || lua_type(L, type_idx) != LUA_TSTRING) {
        st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                         "arc.convert expects (value, d_type)");
        err_cstr = st->last_error_msg.c_str();
      } else {
        std::size_t dlen = 0U;
        const char *dptr = lua_tolstring(L, type_idx, &dlen);
        const std::string dtype{dptr != nullptr ? dptr : "", dlen};
        auto val = read_lua_value(L, val_idx);
        if (!val.has_value()) {
          st->record_abort(ErrorCode::invalid_range, ArcError::type_conversion_failed,
                           "arc.convert: unsupported Lua value");
          err_cstr = st->last_error_msg.c_str();
        } else {
          auto coerced = coerce_value_to_type(val.value(), DtypeName{dtype});
          if (!coerced.has_value()) {
            st->record_abort(ErrorCode::invalid_range, ArcError::type_conversion_failed,
                             "arc.convert: failed to coerce value to '" + dtype + "'");
            err_cstr = st->last_error_msg.c_str();
          } else {
            st->pending_value = std::move(coerced.value());
            ready_to_push = true;
          }
        }
      }
    }
  }
  if (!ready_to_push) {
    return luaL_error(L, "%s", err_cstr != nullptr ? err_cstr : "arc.convert failed");
  }
  if (!push_blackbird_value(L, st->pending_value)) {
    st->pending_value = Value{nullptr};
    st->record_abort(ErrorCode::capacity, ArcError::type_conversion_failed,
                     "arc.convert: failed to push value");
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  st->pending_value = Value{nullptr};
  return 1;
}

// 4b) arc.smart_convert(ctx, text, d_type)
extern "C" int lua_arc_smart_convert(lua_State *L) {
  auto *st = runtime_from_lua(L);
  const char *err_cstr = nullptr;
  int step = 0; // 1 = ready to push direct, 2 = run LM fallback, -1 = error
  {
    if (st == nullptr) {
      err_cstr = "arc.smart_convert: missing runtime";
      step = -1;
    } else if (st->abort_error != ArcError::none) {
      err_cstr = st->last_error_msg.c_str();
      step = -1;
    } else if (check_ctx_userdata(L, 1) == nullptr || lua_gettop(L) < 3 ||
               lua_type(L, 3) != LUA_TSTRING) {
      st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                       "arc.smart_convert expects (ctx, value_or_text, d_type)");
      err_cstr = st->last_error_msg.c_str();
      step = -1;
    } else {
      std::size_t dlen = 0U;
      const char *dptr = lua_tolstring(L, 3, &dlen);
      const std::string dtype{dptr != nullptr ? dptr : "", dlen};

      auto raw_val = read_lua_value(L, 2);
      if (raw_val.has_value()) {
        auto direct = coerce_value_to_type(raw_val.value(), DtypeName{dtype});
        if (direct.has_value()) {
          st->pending_value = std::move(direct.value());
          step = 1;
        }
      }
      if (step == 0) {
        if (st->callbacks == nullptr || !st->callbacks->lm) {
          st->record_abort(ErrorCode::unsupported, ArcError::lm_unavailable,
                           "arc.smart_convert: LM callback unavailable");
          err_cstr = st->last_error_msg.c_str();
          step = -1;
        } else if (st->lm_calls >= st->limits.max_lm_calls) {
          st->record_abort(ErrorCode::capacity, ArcError::step_limit_exceeded,
                           "arc.smart_convert: max LM calls exceeded");
          err_cstr = st->last_error_msg.c_str();
          step = -1;
        } else {
          step = 2;
        }
      }
    }
  }

  if (step == -1) {
    return luaL_error(L, "%s",
                      err_cstr != nullptr ? err_cstr : "arc.smart_convert failed");
  }

  if (step == 2) {
    // ZERO C++ RAII locals on stack during luaL_tolstring!
    std::size_t tlen = 0U;
    const char *tptr = luaL_tolstring(L, 2, &tlen);
    bool lm_ok = false;
    {
      std::size_t dlen = 0U;
      const char *dptr = lua_tolstring(L, 3, &dlen);
      const std::string dtype{dptr != nullptr ? dptr : "", dlen};
      const std::string text{tptr != nullptr ? tptr : "", tlen};

      ++st->lm_calls;
      const std::string prompt =
          "Convert the following value into a valid JSON literal "
          "of type '" +
          dtype + "'. Reply with JSON only.\nValue: " + text;
      const auto lm_res = st->callbacks->lm(prompt, "smart_convert");
      if (!lm_res.has_value()) {
        st->record_abort(lm_res.error().code, ArcError::lm_unavailable,
                         "arc.smart_convert: LM call failed");
        err_cstr = st->last_error_msg.c_str();
      } else {
        const auto parsed = parse_json(trim_sv(lm_res.value()));
        if (!parsed.has_value()) {
          st->record_abort(ErrorCode::invalid_range, ArcError::type_conversion_failed,
                           "arc.smart_convert: LM output is not valid JSON");
          err_cstr = st->last_error_msg.c_str();
        } else {
          auto coerced = coerce_value_to_type(parsed.value(), DtypeName{dtype});
          if (!coerced.has_value()) {
            st->record_abort(ErrorCode::invalid_range, ArcError::type_conversion_failed,
                             "arc.smart_convert: parsed JSON does not match '" + dtype +
                                 "'");
            err_cstr = st->last_error_msg.c_str();
          } else {
            st->pending_value = std::move(coerced.value());
            lm_ok = true;
          }
        }
      }
    }
    lua_pop(L, 1); // pop luaL_tolstring result
    if (!lm_ok) {
      return luaL_error(L, "%s",
                        err_cstr != nullptr ? err_cstr : "arc.smart_convert failed");
    }
  }

  // Push staged value with ZERO C++ RAII locals on stack!
  if (!push_blackbird_value(L, st->pending_value)) {
    st->pending_value = Value{nullptr};
    st->record_abort(ErrorCode::capacity, ArcError::type_conversion_failed,
                     "arc.smart_convert: failed to push value");
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  st->pending_value = Value{nullptr};
  return 1;
}

// 5) arc.lm(ctx, prompt)
extern "C" int lua_arc_lm(lua_State *L) {
  auto *st = runtime_from_lua(L);
  const char *err_cstr = nullptr;
  bool ready_to_push = false;
  {
    if (st == nullptr) {
      err_cstr = "arc.lm: missing runtime";
    } else if (st->abort_error != ArcError::none) {
      err_cstr = st->last_error_msg.c_str();
    } else if (check_ctx_userdata(L, 1) == nullptr || lua_type(L, 2) != LUA_TSTRING) {
      st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                       "arc.lm expects (ctx, prompt_string)");
      err_cstr = st->last_error_msg.c_str();
    } else if (st->callbacks == nullptr || !st->callbacks->lm) {
      st->record_abort(ErrorCode::unsupported, ArcError::lm_unavailable,
                       "arc.lm: LM callback unavailable");
      err_cstr = st->last_error_msg.c_str();
    } else if (st->lm_calls >= st->limits.max_lm_calls) {
      st->record_abort(ErrorCode::capacity, ArcError::step_limit_exceeded,
                       "arc.lm: max LM calls exceeded");
      err_cstr = st->last_error_msg.c_str();
    } else {
      std::size_t plen = 0U;
      const char *pptr = lua_tolstring(L, 2, &plen);
      const std::string prompt{pptr != nullptr ? pptr : "", plen};
      ++st->lm_calls;
      auto res = st->callbacks->lm(prompt, "lm");
      if (!res.has_value()) {
        st->record_abort(res.error().code, ArcError::lm_unavailable,
                         "arc.lm: callback failed");
        err_cstr = st->last_error_msg.c_str();
      } else {
        st->pending_string = std::move(res.value());
        ready_to_push = true;
      }
    }
  }
  if (!ready_to_push) {
    return luaL_error(L, "%s", err_cstr != nullptr ? err_cstr : "arc.lm failed");
  }
  lua_pushlstring(L, st->pending_string.data(), st->pending_string.size());
  st->pending_string.clear();
  return 1;
}

// 6) arc.extract(ctx, text, prompt [, d_type])
extern "C" int lua_arc_extract(lua_State *L) {
  auto *st = runtime_from_lua(L);
  if (st == nullptr) {
    return luaL_error(L, "arc.extract: missing runtime");
  }
  if (st->abort_error != ArcError::none) {
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  if (check_ctx_userdata(L, 1) == nullptr || lua_gettop(L) < 3 ||
      lua_type(L, 3) != LUA_TSTRING) {
    st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                     "arc.extract expects (ctx, text, prompt [, d_type])");
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  if (st->callbacks == nullptr || !st->callbacks->lm) {
    st->record_abort(ErrorCode::unsupported, ArcError::lm_unavailable,
                     "arc.extract: LM callback unavailable");
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  if (st->lm_calls >= st->limits.max_lm_calls) {
    st->record_abort(ErrorCode::capacity, ArcError::step_limit_exceeded,
                     "arc.extract: max LM calls exceeded");
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }

  // Call luaL_tolstring BEFORE constructing any C++ RAII locals!
  std::size_t tlen = 0U;
  const char *tptr = luaL_tolstring(L, 2, &tlen);
  const char *err_cstr = nullptr;
  bool ready_to_push = false;
  {
    const std::string text{tptr != nullptr ? tptr : "", tlen};
    std::size_t plen = 0U;
    const char *pptr = lua_tolstring(L, 3, &plen);
    const std::string prompt{pptr != nullptr ? pptr : "", plen};

    std::string dtype = "str";
    if (lua_gettop(L) >= 5 && lua_type(L, 4) == LUA_TSTRING) {
      // Note: luaL_tolstring pushed 1 extra value on top, so original 4th arg is still
      // at index 4!
      std::size_t dlen = 0U;
      const char *dptr = lua_tolstring(L, 4, &dlen);
      dtype.assign(dptr != nullptr ? dptr : "", dlen);
    }

    ++st->lm_calls;
    const std::string full_prompt =
        "Extract " + prompt + " from the following text:\n" + text;
    const auto res = st->callbacks->lm(full_prompt, "extract");
    if (!res.has_value()) {
      st->record_abort(res.error().code, ArcError::lm_unavailable,
                       "arc.extract: LM callback failed");
      err_cstr = st->last_error_msg.c_str();
    } else {
      auto coerced = coerce_value_to_type(Value{res.value()}, DtypeName{dtype});
      if (!coerced.has_value()) {
        st->record_abort(ErrorCode::invalid_range, ArcError::type_conversion_failed,
                         "arc.extract: failed to coerce extracted value to '" + dtype +
                             "'");
        err_cstr = st->last_error_msg.c_str();
      } else {
        st->pending_value = std::move(coerced.value());
        ready_to_push = true;
      }
    }
  }
  lua_pop(L, 1); // pop luaL_tolstring result
  if (!ready_to_push) {
    return luaL_error(L, "%s", err_cstr != nullptr ? err_cstr : "arc.extract failed");
  }
  if (!push_blackbird_value(L, st->pending_value)) {
    st->pending_value = Value{nullptr};
    st->record_abort(ErrorCode::capacity, ArcError::type_conversion_failed,
                     "arc.extract: failed to push value");
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  st->pending_value = Value{nullptr};
  return 1;
}

// 7) arc.invoke_tool(ctx, name, args)
extern "C" int lua_arc_invoke_tool(lua_State *L) {
  auto *st = runtime_from_lua(L);
  const char *err_cstr = nullptr;
  bool ready_to_push = false;
  {
    if (st == nullptr) {
      err_cstr = "arc.invoke_tool: missing runtime";
    } else if (st->abort_error != ArcError::none) {
      err_cstr = st->last_error_msg.c_str();
    } else if (check_ctx_userdata(L, 1) == nullptr || lua_type(L, 2) != LUA_TSTRING) {
      st->record_abort(ErrorCode::invalid_range, ArcError::invalid_lua,
                       "arc.invoke_tool expects (ctx, tool_name [, args_table])");
      err_cstr = st->last_error_msg.c_str();
    } else if (st->callbacks == nullptr || !st->callbacks->tool) {
      st->record_abort(ErrorCode::unsupported, ArcError::tool_unavailable,
                       "arc.invoke_tool: tool callback unavailable");
      err_cstr = st->last_error_msg.c_str();
    } else if (st->tool_calls >= st->limits.max_tool_calls) {
      st->record_abort(ErrorCode::capacity, ArcError::step_limit_exceeded,
                       "arc.invoke_tool: max tool calls exceeded");
      err_cstr = st->last_error_msg.c_str();
    } else {
      std::size_t nlen = 0U;
      const char *nptr = lua_tolstring(L, 2, &nlen);
      const std::string name{nptr != nullptr ? nptr : "", nlen};

      Value args = Value::object({});
      if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        auto av = read_lua_value(L, 3);
        if (!av.has_value()) {
          st->record_abort(ErrorCode::invalid_range, ArcError::type_conversion_failed,
                           "arc.invoke_tool: failed to convert args");
          err_cstr = st->last_error_msg.c_str();
        } else {
          args = std::move(av.value());
        }
      }

      if (err_cstr == nullptr) {
        ++st->tool_calls;
        if (st->callbacks->turn_taint != nullptr) {
          brakes::PeerProvenance prov{};
          prov.origin = brakes::PeerOriginKind::external_mcp;
          prov.peer_pubkey_b64 = "cpu-arc-tool";
          prov.safety_number = "arc:" + name;
          prov.effective_trust = brakes::PartyTrustProfile::advisory;
          (void)st->callbacks->turn_taint->ingest(prov,
                                                  st->callbacks->party_trust_policy);
          st->turn_tainted = st->callbacks->turn_taint->is_tainted();
        }
        auto res = st->callbacks->tool(name, args);
        if (!res.has_value()) {
          st->record_abort(res.error().code, ArcError::tool_unavailable,
                           "arc.invoke_tool: tool '" + name + "' failed");
          err_cstr = st->last_error_msg.c_str();
        } else {
          st->pending_value = std::move(res.value());
          ready_to_push = true;
        }
      }
    }
  }
  if (!ready_to_push) {
    return luaL_error(L, "%s",
                      err_cstr != nullptr ? err_cstr : "arc.invoke_tool failed");
  }
  if (!push_blackbird_value(L, st->pending_value)) {
    st->pending_value = Value{nullptr};
    st->record_abort(ErrorCode::capacity, ArcError::type_conversion_failed,
                     "arc.invoke_tool: failed to push tool result");
    return luaL_error(L, "%s", st->last_error_msg.c_str());
  }
  st->pending_value = Value{nullptr};
  return 1;
}

void setup_lua_sandbox_base(lua_State *L) {
  // Open ONLY base, math, string, table, utf8 (NEVER os, io, debug, package,
  // coroutine!).
  luaL_requiref(L, LUA_GNAME, luaopen_base, 1);
  lua_pop(L, 1);
  luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1);
  lua_pop(L, 1);
  luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1);
  // Strip string.dump in place (so ("x").dump is also nil!) and attach trap metatable!
  lua_pushnil(L);
  lua_setfield(L, -2, "dump");
  if (luaL_newmetatable(L, kArcStringMetatable) != 0) {
    lua_pushcfunction(L, lua_string_index);
    lua_setfield(L, -2, "__index");
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
  }
  lua_setmetatable(L, -2);
  lua_pop(L, 1);

  // Lock the string-type metatable so ("x") cannot be tampered with.
  lua_pushliteral(L, "");
  if (lua_getmetatable(L, -1) != 0) {
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_pop(L, 1);
  }
  lua_pop(L, 1);

  luaL_requiref(L, LUA_TABLIBNAME, luaopen_table, 1);
  lua_pop(L, 1);
  luaL_requiref(L, LUA_UTF8LIBNAME, luaopen_utf8, 1);
  lua_pop(L, 1);

  // Defense-in-depth: strip dangerous globals from _G too.
  static constexpr std::array<const char *, 15> kStripGlobals = {
      "dofile",       "loadfile", "load",   "collectgarbage", "getmetatable",
      "setmetatable", "rawget",   "rawset", "rawequal",       "rawlen",
      "print",        "warn",     "_G",     "require",        "package",
  };
  for (const char *g : kStripGlobals) {
    lua_pushnil(L);
    lua_setglobal(L, g);
  }

  // Register ctx metatable with __metatable = "locked".
  if (luaL_newmetatable(L, kArcCtxMetatable) != 0) {
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_pushcfunction(L, lua_ctx_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pushcfunction(L, lua_ctx_newindex);
    lua_setfield(L, -2, "__newindex");
  }
  lua_pop(L, 1);

  // Register env metatable to trap forbidden global accesses as sandbox_violation.
  if (luaL_newmetatable(L, kArcEnvMetatable) != 0) {
    lua_pushcfunction(L, lua_env_index);
    lua_setfield(L, -2, "__index");
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
  }
  lua_pop(L, 1);
}

void copy_shallow_table(lua_State *L, const char *global_name, bool attach_string_mt) {
  lua_getglobal(L, global_name);
  lua_newtable(L);
  if (lua_type(L, -2) == LUA_TTABLE) {
    lua_pushnil(L);
    while (lua_next(L, -3) != 0) {
      lua_pushvalue(L, -2); // key
      lua_pushvalue(L, -2); // val
      lua_rawset(L, -5);
      lua_pop(L, 1);
    }
  }
  if (attach_string_mt) {
    luaL_getmetatable(L, kArcStringMetatable);
    lua_setmetatable(L, -2);
  }
  lua_remove(L, -2); // remove original global table, leave fresh copy on top
}

void push_sandbox_env(lua_State *L) {
  lua_newtable(L); // env

  static constexpr std::array<const char *, 11> kAllowFuncs = {
      "tonumber", "tostring", "type",   "pairs", "ipairs", "next",
      "select",   "pcall",    "xpcall", "error", "assert",
  };
  for (const char *name : kAllowFuncs) {
    lua_getglobal(L, name);
    lua_setfield(L, -2, name);
  }

  copy_shallow_table(L, "math", false);
  lua_setfield(L, -2, "math");

  copy_shallow_table(L, "string", true);
  lua_setfield(L, -2, "string");

  copy_shallow_table(L, "table", false);
  lua_setfield(L, -2, "table");

  copy_shallow_table(L, "utf8", false);
  lua_setfield(L, -2, "utf8");

  // Build `arc` runtime primitives table.
  lua_newtable(L);
  lua_pushcfunction(L, lua_arc_load);
  lua_setfield(L, -2, "load");
  lua_pushcfunction(L, lua_arc_do);
  lua_setfield(L, -2, "do_");
  lua_pushcfunction(L, lua_arc_narrate);
  lua_setfield(L, -2, "narrate");
  lua_pushcfunction(L, lua_arc_convert);
  lua_setfield(L, -2, "convert");
  lua_pushcfunction(L, lua_arc_smart_convert);
  lua_setfield(L, -2, "smart_convert");
  lua_pushcfunction(L, lua_arc_lm);
  lua_setfield(L, -2, "lm");
  lua_pushcfunction(L, lua_arc_extract);
  lua_setfield(L, -2, "extract");
  lua_pushcfunction(L, lua_arc_invoke_tool);
  lua_setfield(L, -2, "invoke_tool");
  lua_setfield(L, -2, "arc");

  // Attach forbidden-global trap metatable to _ENV.
  luaL_getmetatable(L, kArcEnvMetatable);
  lua_setmetatable(L, -2);
}

// ---------------------------------------------------------------------------
// Lua 5.5.1 Static Lexer, Analyzer & Static DAG Compiler Helpers
// ---------------------------------------------------------------------------

enum class LuaTokKind : std::uint8_t {
  ident,
  string_lit,
  symbol,
  other,
};

struct LuaToken {
  LuaTokKind kind = LuaTokKind::other;
  std::string text; // raw source slice or decoded string for string_lit
  std::size_t start = 0U;
  std::size_t end = 0U;
};

bool is_ident_start(char c) noexcept {
  const auto u = static_cast<unsigned char>(c);
  return std::isalpha(u) != 0 || c == '_';
}

bool is_ident_cont(char c) noexcept {
  const auto u = static_cast<unsigned char>(c);
  return std::isalnum(u) != 0 || c == '_';
}

// Check for Lua long bracket opening `[=*[`, returns level >= 0 or -1.
int match_long_bracket_open(std::string_view src, std::size_t pos,
                            std::size_t &after_open) noexcept {
  if (pos >= src.size() || src[pos] != '[') {
    return -1;
  }
  std::size_t i = pos + 1U;
  int level = 0;
  while (i < src.size() && src[i] == '=') {
    ++level;
    ++i;
  }
  if (i < src.size() && src[i] == '[') {
    after_open = i + 1U;
    return level;
  }
  return -1;
}

struct BracketLevel {
  int value = 0;
};

std::size_t find_long_bracket_close(std::string_view src, std::size_t pos,
                                    BracketLevel level) noexcept {
  std::size_t i = pos;
  while (i < src.size()) {
    if (src[i] == ']') {
      std::size_t j = i + 1U;
      int eq = 0;
      while (j < src.size() && src[j] == '=' && eq < level.value) {
        ++eq;
        ++j;
      }
      if (eq == level.value && j < src.size() && src[j] == ']') {
        return j + 1U;
      }
    }
    ++i;
  }
  return src.size();
}

std::string decode_quoted_lua_string(std::string_view inner) {
  std::string out;
  out.reserve(inner.size());
  for (std::size_t i = 0U; i < inner.size(); ++i) {
    if (inner[i] == '\\' && i + 1U < inner.size()) {
      ++i;
      switch (inner[i]) {
      case 'n':
        out.push_back('\n');
        break;
      case 'r':
        out.push_back('\r');
        break;
      case 't':
        out.push_back('\t');
        break;
      case '\\':
        out.push_back('\\');
        break;
      case '"':
        out.push_back('"');
        break;
      case '\'':
        out.push_back('\'');
        break;
      default:
        out.push_back(inner[i]);
        break;
      }
    } else {
      out.push_back(inner[i]);
    }
  }
  return out;
}

std::vector<LuaToken> lex_lua_source(std::string_view src) {
  std::vector<LuaToken> tokens;
  std::size_t i = 0U;
  while (i < src.size()) {
    const char c = src[i];
    if (std::isspace(static_cast<unsigned char>(c)) != 0) {
      ++i;
      continue;
    }
    // Comments: --[[...]] or --...
    if (c == '-' && i + 1U < src.size() && src[i + 1U] == '-') {
      i += 2U;
      std::size_t after = 0U;
      const int lvl = match_long_bracket_open(src, i, after);
      if (lvl >= 0) {
        i = find_long_bracket_close(src, after, BracketLevel{lvl});
      } else {
        while (i < src.size() && src[i] != '\n') {
          ++i;
        }
      }
      continue;
    }
    // Long bracket string literal [[...]]
    if (c == '[') {
      std::size_t after = 0U;
      const int lvl = match_long_bracket_open(src, i, after);
      if (lvl >= 0) {
        const std::size_t close_end =
            find_long_bracket_close(src, after, BracketLevel{lvl});
        const std::size_t close_len = static_cast<std::size_t>(lvl) + 2U;
        std::size_t body_start = after;
        if (body_start < close_end && src[body_start] == '\n') {
          ++body_start;
        }
        const std::size_t body_end =
            close_end >= close_len ? close_end - close_len : body_start;
        std::string body =
            body_end > body_start
                ? std::string{src.substr(body_start, body_end - body_start)}
                : std::string{};
        tokens.push_back(
            LuaToken{LuaTokKind::string_lit, std::move(body), i, close_end});
        i = close_end;
        continue;
      }
    }
    // Quoted string literal
    if (c == '"' || c == '\'') {
      const char quote = c;
      const std::size_t start = i;
      ++i;
      while (i < src.size()) {
        if (src[i] == '\\' && i + 1U < src.size()) {
          i += 2U;
          continue;
        }
        if (src[i] == quote) {
          ++i;
          break;
        }
        ++i;
      }
      const std::size_t inner_len = (i >= start + 2U) ? (i - start - 2U) : 0U;
      tokens.push_back(LuaToken{
          LuaTokKind::string_lit,
          decode_quoted_lua_string(src.substr(start + 1U, inner_len)), start, i});
      continue;
    }
    // Identifier / keyword
    if (is_ident_start(c)) {
      const std::size_t start = i;
      ++i;
      while (i < src.size() && is_ident_cont(src[i])) {
        ++i;
      }
      tokens.push_back(LuaToken{LuaTokKind::ident,
                                std::string{src.substr(start, i - start)}, start, i});
      continue;
    }
    // Two-char concat operator `..`
    if (c == '.' && i + 1U < src.size() && src[i + 1U] == '.') {
      tokens.push_back(LuaToken{LuaTokKind::symbol, "..", i, i + 2U});
      i += 2U;
      continue;
    }
    // Single-char symbol
    tokens.push_back(LuaToken{LuaTokKind::symbol, std::string(1U, c), i, i + 1U});
    ++i;
  }
  return tokens;
}

// Try to fold a token slice representing a Lua string literal or `"a" .. "b"` concat.
std::optional<std::string> eval_string_literal_tokens(const std::vector<LuaToken> &toks,
                                                      std::size_t begin_idx,
                                                      std::size_t end_idx) {
  if (begin_idx >= end_idx) {
    return std::nullopt;
  }
  std::string out;
  bool expect_str = true;
  for (std::size_t i = begin_idx; i < end_idx; ++i) {
    if (expect_str) {
      if (toks[i].kind != LuaTokKind::string_lit) {
        return std::nullopt;
      }
      out += toks[i].text;
      expect_str = false;
    } else {
      if (toks[i].kind != LuaTokKind::symbol || toks[i].text != "..") {
        return std::nullopt;
      }
      expect_str = true;
    }
  }
  if (expect_str) {
    return std::nullopt;
  }
  return out;
}

struct ParsedCallArgs {
  std::size_t close_tok_idx = 0U;
  std::vector<std::pair<std::size_t, std::size_t>> arg_ranges; // [begin_tok, end_tok)
};

std::optional<ParsedCallArgs> parse_call_args(const std::vector<LuaToken> &toks,
                                              std::size_t open_paren_idx) {
  if (open_paren_idx >= toks.size() || toks[open_paren_idx].text != "(") {
    return std::nullopt;
  }
  ParsedCallArgs out{};
  int depth = 1;
  std::size_t arg_start = open_paren_idx + 1U;
  for (std::size_t i = open_paren_idx + 1U; i < toks.size(); ++i) {
    const auto &t = toks[i];
    if (t.kind == LuaTokKind::symbol) {
      if (t.text == "(" || t.text == "{" || t.text == "[") {
        ++depth;
      } else if (t.text == ")" || t.text == "}" || t.text == "]") {
        --depth;
        if (depth == 0) {
          if (i > arg_start) {
            out.arg_ranges.emplace_back(arg_start, i);
          }
          out.close_tok_idx = i;
          return out;
        }
      } else if (t.text == "," && depth == 1) {
        out.arg_ranges.emplace_back(arg_start, i);
        arg_start = i + 1U;
      }
    }
  }
  return std::nullopt;
}

std::string slice_source_for_tokens(std::string_view src,
                                    const std::vector<LuaToken> &toks,
                                    std::size_t begin_idx, std::size_t end_idx) {
  if (begin_idx >= end_idx || end_idx > toks.size()) {
    return {};
  }
  const std::size_t s = toks[begin_idx].start;
  const std::size_t e = toks[end_idx - 1U].end;
  if (e <= s || e > src.size()) {
    return {};
  }
  return std::string{trim_sv(src.substr(s, e - s))};
}

std::string sanitize_lua_ident(std::string_view id) {
  std::string out;
  out.reserve(id.size());
  for (const char ch : id) {
    if (std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_') {
      out.push_back(ch);
    } else {
      out.push_back('_');
    }
  }
  return out;
}

std::string quote_lua_string(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 2U);
  out.push_back('"');
  for (const char ch : text) {
    switch (ch) {
    case '\\':
      out += "\\\\";
      break;
    case '"':
      out += "\\\"";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      out.push_back(ch);
      break;
    }
  }
  out.push_back('"');
  return out;
}

// Extract literal string keys inside a payloads table expression like `{ ["key"] = val,
// foo = bar }`.
std::vector<std::string> extract_literal_payload_keys(std::string_view payloads_expr) {
  std::vector<std::string> keys;
  const auto toks = lex_lua_source(payloads_expr);
  int brace_depth = 0;
  for (std::size_t i = 0U; i < toks.size(); ++i) {
    if (toks[i].kind == LuaTokKind::symbol && toks[i].text == "{") {
      ++brace_depth;
      continue;
    }
    if (toks[i].kind == LuaTokKind::symbol && toks[i].text == "}") {
      --brace_depth;
      continue;
    }
    if (brace_depth != 1) {
      continue;
    }
    // Pattern: [ "literal" ] =
    if (toks[i].kind == LuaTokKind::symbol && toks[i].text == "[" &&
        i + 3U < toks.size() && toks[i + 1U].kind == LuaTokKind::string_lit &&
        toks[i + 2U].kind == LuaTokKind::symbol && toks[i + 2U].text == "]" &&
        toks[i + 3U].kind == LuaTokKind::symbol && toks[i + 3U].text == "=") {
      keys.push_back(toks[i + 1U].text);
      i += 3U;
      continue;
    }
    // Pattern: ident =
    if (toks[i].kind == LuaTokKind::ident && i + 1U < toks.size() &&
        toks[i + 1U].kind == LuaTokKind::symbol && toks[i + 1U].text == "=") {
      keys.push_back(toks[i].text);
      ++i;
      continue;
    }
  }
  return keys;
}

// Check Lua 5.5.1 syntax text-only in an ephemeral sandboxed state.
Result<void> check_lua_syntax_text_only(std::string_view lua_source) {
  if (!lua_source.empty() && lua_source[0] == '\x1b') {
    return fail<void>(ErrorCode::unsupported, ArcError::sandbox_violation);
  }
  LuaAllocState alloc{};
  alloc.limit_bytes = 4U * 1024U * 1024U;
  ScopedLuaState lua{};
  lua.L = lua_newstate(arc_lua_alloc, &alloc, luaL_makeseed(nullptr));
  if (lua.L == nullptr) {
    return fail<void>(ErrorCode::allocation, ArcError::memory_limit_exceeded);
  }
  const int rc =
      luaL_loadbufferx(lua.L, lua_source.data(), lua_source.size(), "=arc_syntax", "t");
  if (rc != LUA_OK) {
    return fail<void>(ErrorCode::invalid_range, ArcError::invalid_lua);
  }
  return Result<void>::success();
}

// Compare two Values with optional numeric tolerance (for perturbation verification).
struct CompareOptions {
  double numeric_tolerance = 1e-3;
};

bool values_equivalent(const Value &actual, const Value &expected,
                       CompareOptions opts) {
  if (actual == expected) {
    return true;
  }
  const auto *an = std::get_if<Number>(&actual.value());
  const auto *en = std::get_if<Number>(&expected.value());
  if (an != nullptr && en != nullptr) {
    const auto ad = number_to_double(*an);
    const auto ed = number_to_double(*en);
    if (ad.has_value() && ed.has_value()) {
      const double diff = std::fabs(*ad - *ed);
      const double scale = std::max(1.0, std::fabs(*ed));
      return diff <= opts.numeric_tolerance * scale;
    }
    return false;
  }
  const auto *aa = std::get_if<Value::Array>(&actual.value());
  const auto *ea = std::get_if<Value::Array>(&expected.value());
  if (aa != nullptr && ea != nullptr) {
    if (aa->size() != ea->size()) {
      return false;
    }
    for (std::size_t i = 0U; i < aa->size(); ++i) {
      if (!values_equivalent((*aa)[i], (*ea)[i], opts)) {
        return false;
      }
    }
    return true;
  }
  const auto *ao = std::get_if<Value::Object>(&actual.value());
  const auto *eo = std::get_if<Value::Object>(&expected.value());
  if (ao != nullptr && eo != nullptr) {
    if (ao->size() != eo->size()) {
      return false;
    }
    for (const auto &[k, ev] : *eo) {
      const Value *av = actual.find(k);
      if (av == nullptr || !values_equivalent(*av, ev, opts)) {
        return false;
      }
    }
    return true;
  }
  return false;
}

} // namespace

// ---------------------------------------------------------------------------
// Public Utility Functions
// ---------------------------------------------------------------------------

std::string_view arc_error_name(ArcError detail) noexcept {
  switch (detail) {
  case ArcError::none:
    return "none";
  case ArcError::invalid_id:
    return "invalid_id";
  case ArcError::invalid_lua:
    return "invalid_lua";
  case ArcError::sandbox_violation:
    return "sandbox_violation";
  case ArcError::memory_limit_exceeded:
    return "memory_limit_exceeded";
  case ArcError::instruction_limit_exceeded:
    return "instruction_limit_exceeded";
  case ArcError::timeout:
    return "timeout";
  case ArcError::recursion_limit_exceeded:
    return "recursion_limit_exceeded";
  case ArcError::step_limit_exceeded:
    return "step_limit_exceeded";
  case ArcError::function_not_found:
    return "function_not_found";
  case ArcError::entry_not_found:
    return "entry_not_found";
  case ArcError::load_not_found:
    return "load_not_found";
  case ArcError::type_conversion_failed:
    return "type_conversion_failed";
  case ArcError::lm_unavailable:
    return "lm_unavailable";
  case ArcError::tool_unavailable:
    return "tool_unavailable";
  case ArcError::compile_cycle_detected:
    return "compile_cycle_detected";
  case ArcError::compile_unresolved_call:
    return "compile_unresolved_call";
  case ArcError::sqlite_failed:
    return "sqlite_failed";
  case ArcError::io_failed:
    return "io_failed";
  case ArcError::insecure_path:
    return "insecure_path";
  }
  return "unknown";
}

bool valid_arc_id(std::string_view id) noexcept {
  if (id.empty() || id.size() > kMaxArcIdLength) {
    return false;
  }
  for (const char ch : id) {
    const auto u = static_cast<unsigned char>(ch);
    if (std::isalnum(u) == 0 && ch != '_' && ch != '-') {
      return false;
    }
  }
  return true;
}

std::string compute_trace_hash(std::string_view text) {
  std::array<unsigned char, 32> digest{};
  unsigned int digest_len = 0U;
  if (EVP_Digest(text.data(), text.size(), digest.data(), &digest_len, EVP_sha256(),
                 nullptr) != 1 ||
      digest_len != 32U) {
    return {};
  }
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(64U);
  for (const unsigned char b : digest) {
    out.push_back(kHex[(b >> 4U) & 0x0FU]);
    out.push_back(kHex[b & 0x0FU]);
  }
  return out;
}

std::string_view arc_granularity_name(ArcGranularity granularity) noexcept {
  switch (granularity) {
  case ArcGranularity::fine:
    return "fine";
  case ArcGranularity::medium:
    return "medium";
  case ArcGranularity::coarse:
    return "coarse";
  }
  return "medium";
}

Result<ArcGranularity> parse_arc_granularity(std::string_view text) noexcept {
  if (text == "fine") {
    return Result<ArcGranularity>::success(ArcGranularity::fine);
  }
  if (text == "medium") {
    return Result<ArcGranularity>::success(ArcGranularity::medium);
  }
  if (text == "coarse") {
    return Result<ArcGranularity>::success(ArcGranularity::coarse);
  }
  return fail<ArcGranularity>(ErrorCode::invalid_range, ArcError::invalid_id);
}

std::string_view arc_perturbation_mode_name(ArcPerturbationMode mode) noexcept {
  switch (mode) {
  case ArcPerturbationMode::golden:
    return "golden";
  case ArcPerturbationMode::phrasal:
    return "phrasal";
  case ArcPerturbationMode::parametric:
    return "parametric";
  case ArcPerturbationMode::combined:
    return "combined";
  }
  return "golden";
}

ArcCapabilities probe_cpu_arc_capabilities() {
  ArcCapabilities caps{};
  caps.available = true;
  caps.lua_version = LUA_VERSION_MAJOR "." LUA_VERSION_MINOR "." LUA_VERSION_RELEASE;
  caps.sqlite_version = sqlite3_libversion();
  caps.supports_wal = true;
  caps.supports_nofollow = true;
  caps.supports_compiled_execution = true;
  for (int i = 0;; ++i) {
    const char *opt = sqlite3_compileoption_get(i);
    if (opt == nullptr) {
      break;
    }
    if (std::string_view{opt} == "ENABLE_FTS5") {
      caps.supports_fts5 = true;
    }
  }
  return caps;
}

std::string format_narration_trace(const std::vector<ArcNarrationEntry> &entries) {
  std::string out;
  for (std::size_t i = 0U; i < entries.size(); ++i) {
    if (i > 0U) {
      out.push_back('\n');
    }
    const std::size_t indent = static_cast<std::size_t>(entries[i].depth) * 2U;
    out.append(indent, ' ');
    out += entries[i].message;
  }
  return out;
}

Result<ArcStaticAnalysis> analyze_lua_source(std::string_view lua_source) {
  ArcStaticAnalysis out{};
  if (!lua_source.empty() && lua_source[0] == '\x1b') {
    out.syntax_valid = false;
    out.diagnostic = "binary Lua bytecode is forbidden";
    return Result<ArcStaticAnalysis>::success(std::move(out));
  }

  const auto syn = check_lua_syntax_text_only(lua_source);
  if (!syn.has_value()) {
    out.syntax_valid = false;
    out.diagnostic = "Lua 5.5.1 syntax error";
    return Result<ArcStaticAnalysis>::success(std::move(out));
  }
  out.syntax_valid = true;

  const auto toks = lex_lua_source(lua_source);
  for (std::size_t i = 0U; i < toks.size(); ++i) {
    const auto &t = toks[i];
    if (t.kind == LuaTokKind::ident) {
      if (t.text == "if" || t.text == "elseif" || t.text == "for" ||
          t.text == "while" || t.text == "repeat") {
        ++out.control_flow_complexity;
      }
      // `function semantic_function(`
      if (t.text == "function" && i + 1U < toks.size() &&
          toks[i + 1U].kind == LuaTokKind::ident &&
          toks[i + 1U].text == "semantic_function") {
        out.defines_semantic_function = true;
      }
      // `semantic_function = function(`
      if (t.text == "semantic_function" && i + 2U < toks.size() &&
          toks[i + 1U].kind == LuaTokKind::symbol && toks[i + 1U].text == "=" &&
          toks[i + 2U].kind == LuaTokKind::ident && toks[i + 2U].text == "function") {
        out.defines_semantic_function = true;
      }
      // `arc.narrate(`, `arc.do_(`, `arc.load(`
      if (t.text == "arc" && i + 3U < toks.size() &&
          toks[i + 1U].kind == LuaTokKind::symbol && toks[i + 1U].text == "." &&
          toks[i + 2U].kind == LuaTokKind::ident &&
          toks[i + 3U].kind == LuaTokKind::symbol && toks[i + 3U].text == "(") {
        const std::string &prim = toks[i + 2U].text;
        const auto parsed = parse_call_args(toks, i + 3U);
        if (!parsed.has_value()) {
          continue;
        }
        if (prim == "narrate") {
          ++out.narration_count;
        } else if (prim == "do_") {
          ArcCallSite site{};
          site.primitive = "do_";
          site.start_offset = t.start;
          site.end_offset = toks[parsed->close_tok_idx].end;
          if (!parsed->arg_ranges.empty()) {
            site.target_expr =
                slice_source_for_tokens(lua_source, toks, parsed->arg_ranges[0].first,
                                        parsed->arg_ranges[0].second);
          }
          if (parsed->arg_ranges.size() >= 2U) {
            const auto lit = eval_string_literal_tokens(
                toks, parsed->arg_ranges[1].first, parsed->arg_ranges[1].second);
            if (lit.has_value()) {
              site.query_literal = *lit;
            }
          }
          if (parsed->arg_ranges.size() >= 3U) {
            site.payloads_expr =
                slice_source_for_tokens(lua_source, toks, parsed->arg_ranges[2].first,
                                        parsed->arg_ranges[2].second);
          } else {
            site.payloads_expr = "{}";
          }
          out.do_calls.push_back(std::move(site));
        } else if (prim == "load") {
          ArcCallSite site{};
          site.primitive = "load";
          site.start_offset = t.start;
          site.end_offset = toks[parsed->close_tok_idx].end;
          if (!parsed->arg_ranges.empty()) {
            site.target_expr =
                slice_source_for_tokens(lua_source, toks, parsed->arg_ranges[0].first,
                                        parsed->arg_ranges[0].second);
          }
          if (parsed->arg_ranges.size() >= 2U) {
            const auto lit = eval_string_literal_tokens(
                toks, parsed->arg_ranges[1].first, parsed->arg_ranges[1].second);
            if (lit.has_value()) {
              site.query_literal = *lit;
            }
          }
          if (parsed->arg_ranges.size() >= 3U) {
            const auto dlit = eval_string_literal_tokens(
                toks, parsed->arg_ranges[2].first, parsed->arg_ranges[2].second);
            if (dlit.has_value()) {
              site.d_type_literal = *dlit;
            }
          }
          out.load_calls.push_back(std::move(site));
        }
      }
    }
  }

  out.narration_commensurate =
      (out.narration_count >= 1U) &&
      (out.narration_count * 2U >= out.control_flow_complexity);
  return Result<ArcStaticAnalysis>::success(std::move(out));
}

// ---------------------------------------------------------------------------
// ArcRegistry::Impl (SQLite 3.54.1 FTS5 + Execution Engine + Compiler)
// ---------------------------------------------------------------------------

struct ArcRegistry::Impl {
  ScopedSqliteDb conn;
  fs::path db_path;
  bool is_memory = false;
  ArcRegistryConfig config{};

  ~Impl() {
    conn.reset();
    if (!is_memory && !db_path.empty()) {
      tighten_db_and_sidecars(db_path);
    }
  }

  Result<void> init_schema() {
    static constexpr const char *kSchemaSql = R"SQL(
      CREATE TABLE IF NOT EXISTS arc_functions (
        id TEXT PRIMARY KEY,
        description TEXT NOT NULL,
        params_json TEXT NOT NULL,
        return_keys_json TEXT NOT NULL,
        lua_source TEXT NOT NULL,
        provenance_trace_hash TEXT NOT NULL DEFAULT '',
        granularity TEXT NOT NULL DEFAULT 'medium',
        is_root INTEGER NOT NULL DEFAULT 0,
        compiled_lua TEXT,
        invocation_count INTEGER NOT NULL DEFAULT 0,
        success_count INTEGER NOT NULL DEFAULT 0,
        failure_count INTEGER NOT NULL DEFAULT 0,
        fallback_count INTEGER NOT NULL DEFAULT 0,
        total_source_cost_usd REAL NOT NULL DEFAULT 0.0,
        total_builder_cost_usd REAL NOT NULL DEFAULT 0.0,
        total_target_cost_usd REAL NOT NULL DEFAULT 0.0,
        embedding_blob BLOB
      );
      CREATE TABLE IF NOT EXISTS arc_entries (
        entry_id TEXT PRIMARY KEY,
        function_id TEXT NOT NULL REFERENCES arc_functions(id) ON DELETE CASCADE,
        template_text TEXT NOT NULL,
        is_template INTEGER NOT NULL DEFAULT 1,
        embedding_blob BLOB
      );
      CREATE VIRTUAL TABLE IF NOT EXISTS arc_functions_fts USING fts5(
        id UNINDEXED,
        description,
        params_text,
        return_keys_text,
        tokenize='porter unicode61'
      );
      CREATE VIRTUAL TABLE IF NOT EXISTS arc_entries_fts USING fts5(
        entry_id UNINDEXED,
        function_id UNINDEXED,
        template_text,
        tokenize='porter unicode61'
      );
    )SQL";

    char *err = nullptr;
    const int rc = sqlite3_exec(conn.db, kSchemaSql, nullptr, nullptr, &err);
    if (err != nullptr) {
      sqlite3_free(err);
    }
    if (rc != SQLITE_OK) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
    return Result<void>::success();
  }

  Result<void> upsert_entry_in_tx(const ArcEntryPointRecord &entry) {
    if (!valid_arc_id(entry.entry_id) || !valid_arc_id(entry.function_id)) {
      return fail<void>(ErrorCode::invalid_range, ArcError::invalid_id);
    }
    std::vector<unsigned char> emb_blob;
    if (config.embed_callback) {
      auto emb = config.embed_callback(entry.template_text);
      if (emb.has_value() && !emb.value().empty()) {
        emb_blob = encode_embedding_blob(emb.value());
      }
    }

    {
      ScopedSqliteStmt stmt{};
      static constexpr const char *kUpsertEntry = R"SQL(
        INSERT INTO arc_entries(entry_id, function_id, template_text, is_template, embedding_blob)
        VALUES(?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(entry_id) DO UPDATE SET
          function_id = excluded.function_id,
          template_text = excluded.template_text,
          is_template = excluded.is_template,
          embedding_blob = excluded.embedding_blob;
      )SQL";
      if (sqlite3_prepare_v2(conn.db, kUpsertEntry, -1, &stmt.stmt, nullptr) !=
          SQLITE_OK) {
        return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
      }
      (void)bind_text(stmt.stmt, 1, entry.entry_id);
      (void)bind_text(stmt.stmt, 2, entry.function_id);
      (void)bind_text(stmt.stmt, 3, entry.template_text);
      (void)sqlite3_bind_int(stmt.stmt, 4, entry.is_template ? 1 : 0);
      if (!emb_blob.empty()) {
        (void)sqlite3_bind_blob(stmt.stmt, 5, emb_blob.data(),
                                static_cast<int>(emb_blob.size()), SQLITE_TRANSIENT);
      } else {
        (void)sqlite3_bind_null(stmt.stmt, 5);
      }
      if (sqlite3_step(stmt.stmt) != SQLITE_DONE) {
        return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
      }
    }

    // Sync arc_entries_fts atomically
    {
      ScopedSqliteStmt del{};
      if (sqlite3_prepare_v2(conn.db,
                             "DELETE FROM arc_entries_fts WHERE entry_id = ?1;", -1,
                             &del.stmt, nullptr) != SQLITE_OK) {
        return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
      }
      (void)bind_text(del.stmt, 1, entry.entry_id);
      if (sqlite3_step(del.stmt) != SQLITE_DONE) {
        return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
      }
    }
    {
      ScopedSqliteStmt ins{};
      if (sqlite3_prepare_v2(
              conn.db,
              "INSERT INTO arc_entries_fts(entry_id, function_id, template_text) "
              "VALUES(?1, ?2, ?3);",
              -1, &ins.stmt, nullptr) != SQLITE_OK) {
        return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
      }
      (void)bind_text(ins.stmt, 1, entry.entry_id);
      (void)bind_text(ins.stmt, 2, entry.function_id);
      (void)bind_text(ins.stmt, 3, entry.template_text);
      if (sqlite3_step(ins.stmt) != SQLITE_DONE) {
        return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
      }
    }
    return Result<void>::success();
  }

  Result<void> bump_counters(FunctionIdRef fn_id, CounterDelta delta) {
    ScopedSqliteStmt stmt{};
    static constexpr const char *kUpdateSql = R"SQL(
      UPDATE arc_functions SET
        invocation_count = invocation_count + ?2,
        success_count = success_count + ?3,
        failure_count = failure_count + ?4,
        fallback_count = fallback_count + ?5
      WHERE id = ?1;
    )SQL";
    if (sqlite3_prepare_v2(conn.db, kUpdateSql, -1, &stmt.stmt, nullptr) != SQLITE_OK) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
    (void)bind_text(stmt.stmt, 1, fn_id.value);
    (void)sqlite3_bind_int64(stmt.stmt, 2, delta.invocations);
    (void)sqlite3_bind_int64(stmt.stmt, 3, delta.successes);
    (void)sqlite3_bind_int64(stmt.stmt, 4, delta.failures);
    (void)sqlite3_bind_int64(stmt.stmt, 5, delta.fallbacks);
    if (sqlite3_step(stmt.stmt) != SQLITE_DONE) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
    return Result<void>::success();
  }

  Result<void> save_compiled_lua(FunctionIdRef fn_id,
                                 std::string_view compiled_source) {
    ScopedSqliteStmt stmt{};
    if (sqlite3_prepare_v2(conn.db,
                           "UPDATE arc_functions SET compiled_lua = ?2 WHERE id = ?1;",
                           -1, &stmt.stmt, nullptr) != SQLITE_OK) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
    (void)bind_text(stmt.stmt, 1, fn_id.value);
    (void)bind_text(stmt.stmt, 2, compiled_source);
    if (sqlite3_step(stmt.stmt) != SQLITE_DONE) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
    return Result<void>::success();
  }

  std::vector<std::string> load_entries_for_function(std::string_view fn_id) const {
    std::vector<std::string> out;
    ScopedSqliteStmt stmt{};
    if (sqlite3_prepare_v2(
            conn.db,
            "SELECT template_text FROM arc_entries WHERE function_id = ?1 "
            "ORDER BY entry_id ASC;",
            -1, &stmt.stmt, nullptr) != SQLITE_OK) {
      return out;
    }
    (void)bind_text(stmt.stmt, 1, fn_id);
    while (sqlite3_step(stmt.stmt) == SQLITE_ROW) {
      out.push_back(col_text(stmt.stmt, 0));
    }
    return out;
  }

  ArcFunctionRecord read_function_row(sqlite3_stmt *stmt) const {
    ArcFunctionRecord rec{};
    rec.id = col_text(stmt, 0);
    rec.description = col_text(stmt, 1);
    rec.params = deserialize_params_json(col_text(stmt, 2));
    rec.return_keys = deserialize_string_vec_json(col_text(stmt, 3));
    rec.lua_source = col_text(stmt, 4);
    rec.provenance_trace_hash = col_text(stmt, 5);
    const auto g = parse_arc_granularity(col_text(stmt, 6));
    rec.granularity = g.has_value() ? g.value() : ArcGranularity::medium;
    rec.is_root = sqlite3_column_int(stmt, 7) != 0;
    if (sqlite3_column_type(stmt, 8) != SQLITE_NULL) {
      rec.compiled_lua = col_text(stmt, 8);
    }
    rec.invocation_count = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 9));
    rec.success_count = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 10));
    rec.failure_count = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 11));
    rec.fallback_count = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 12));
    rec.total_source_cost_usd = sqlite3_column_double(stmt, 13);
    rec.total_builder_cost_usd = sqlite3_column_double(stmt, 14);
    rec.total_target_cost_usd = sqlite3_column_double(stmt, 15);
    rec.entry_templates = load_entries_for_function(rec.id);
    return rec;
  }

  // Protected root execution trampoline: ZERO C++ RAII locals on stack so even OOM
  // during sandbox setup, chunk loading, or root payload push returns cleanly via
  // lua_pcall!
  static int lua_root_trampoline(lua_State *L) {
    auto *st = runtime_from_lua(L);
    if (st == nullptr) {
      return luaL_error(L, "arc: missing runtime state");
    }
    setup_lua_sandbox_base(L);
    lua_sethook(L, arc_lua_hook, LUA_MASKCOUNT, st->hook_step);

    const int load_rc =
        luaL_loadbufferx(L, st->root_lua_source.data(), st->root_lua_source.size(),
                         st->root_chunk_name.c_str(), "t");
    if (load_rc != LUA_OK) {
      return lua_error(L);
    }

    push_sandbox_env(L);
    const int env_idx = lua_gettop(L);
    lua_pushvalue(L, env_idx);
    (void)lua_setupvalue(L, env_idx - 1, 1);

    // Execute top-level module definition.
    lua_pushvalue(L, env_idx - 1);
    lua_call(L, 0, 0);

    lua_getfield(L, env_idx, "semantic_function");
    if (lua_type(L, -1) != LUA_TFUNCTION) {
      return luaL_error(L, "arc: semantic_function not defined");
    }

    auto *ud = static_cast<ArcContextUserdata *>(
        lua_newuserdatauv(L, sizeof(ArcContextUserdata), 0));
    ud->magic = kArcCtxMagic;
    ud->state = st;
    luaL_getmetatable(L, kArcCtxMetatable);
    lua_setmetatable(L, -2);

    int nargs = 1;
    if (st->root_is_compiled) {
      if (!push_blackbird_value(L, st->pending_value)) {
        st->pending_value = Value{nullptr};
        return luaL_error(L, "arc: failed to push compiled root payloads");
      }
      st->pending_value = Value{nullptr};
      lua_pushcfunction(L, lua_arc_compiled_frame);
      nargs = 3;
    }

    lua_call(L, nargs, 1);
    if (lua_type(L, -1) != LUA_TTABLE) {
      return luaL_error(L, "arc: semantic_function must return a table");
    }
    return 1;
  }

  Result<ArcExecutionResult>
  run_lua_chunk(const ArcRegistry *owner, FunctionIdRef root_id,
                std::string_view lua_source, const Value &payloads,
                const ArcRuntimeCallbacks &callbacks, const ArcExecutionLimits &limits,
                bool is_compiled) {
    const auto start_tp = SteadyClock::now();
    if (!lua_source.empty() && lua_source[0] == '\x1b') {
      return fail<ArcExecutionResult>(ErrorCode::unsupported,
                                      ArcError::sandbox_violation);
    }

    ArcRuntimeState rt{};
    rt.registry = owner;
    rt.registry_config = &config;
    rt.callbacks = &callbacks;
    rt.limits = limits;
    rt.alloc.limit_bytes = limits.max_lua_memory_bytes > 0U
                               ? limits.max_lua_memory_bytes
                               : kDefaultMaxLuaMemoryBytes;
    if (limits.timeout_ms > 0U) {
      rt.deadline_ns =
          monotonic_now_ns() + static_cast<std::int64_t>(limits.timeout_ms) * 1000000LL;
    }
    rt.hook_step = static_cast<int>(std::min<std::uint64_t>(
        1000U, std::max<std::uint64_t>(1U, limits.max_lua_instructions)));
    rt.root_lua_source = std::string{lua_source};
    rt.root_chunk_name = "@" + std::string{root_id.value};
    rt.root_is_compiled = is_compiled;

    Value::Object root_entries;
    if (const auto *obj = std::get_if<Value::Object>(&payloads.value())) {
      root_entries = *obj;
    }
    if (is_compiled) {
      rt.pending_value = Value::object(root_entries);
    }
    rt.layers.push_back(
        ContextLayer{std::string{root_id.value}, std::move(root_entries), {}, {}});

    ScopedLuaState lua{};
    lua.L = lua_newstate(arc_lua_alloc, &rt.alloc, luaL_makeseed(nullptr));
    if (lua.L == nullptr) {
      return fail<ArcExecutionResult>(ErrorCode::allocation,
                                      ArcError::memory_limit_exceeded);
    }
    *static_cast<ArcRuntimeState **>(lua_getextraspace(lua.L)) = &rt;

    lua_pushcfunction(lua.L, lua_root_trampoline);
    const int call_rc = lua_pcall(lua.L, 0, 1, 0);
    if (rt.alloc.oom_triggered || call_rc == LUA_ERRMEM) {
      return fail<ArcExecutionResult>(ErrorCode::allocation,
                                      ArcError::memory_limit_exceeded);
    }
    if (rt.abort_error != ArcError::none) {
      return fail<ArcExecutionResult>(rt.abort_code, rt.abort_error);
    }
    if (call_rc != LUA_OK) {
      return fail<ArcExecutionResult>(ErrorCode::invalid_range, ArcError::invalid_lua);
    }
    if (lua_type(lua.L, -1) != LUA_TTABLE) {
      return fail<ArcExecutionResult>(ErrorCode::invalid_range, ArcError::invalid_lua);
    }

    auto out_val = read_lua_value(lua.L, -1);
    if (!out_val.has_value()) {
      return fail<ArcExecutionResult>(out_val.error().code,
                                      arc_error_of(out_val.error()));
    }

    ArcExecutionResult res{};
    res.output = std::move(out_val.value());
    res.narrations = std::move(rt.narrations);
    res.narration_trace = format_narration_trace(res.narrations);
    res.root_function_id = std::string{root_id.value};
    res.used_compiled = is_compiled;
    res.search_calls = rt.search_calls;
    res.load_search_calls = rt.load_search_calls;
    res.do_calls = rt.do_calls;
    res.lm_calls = rt.lm_calls;
    res.tool_calls = rt.tool_calls;
    res.lua_instructions = rt.instructions;
    res.peak_lua_memory_bytes = rt.alloc.peak_bytes;
    res.turn_tainted = rt.turn_tainted || (callbacks.turn_taint != nullptr &&
                                           callbacks.turn_taint->is_tainted());
    res.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                          SteadyClock::now() - start_tp)
                          .count();
    return Result<ArcExecutionResult>::success(std::move(res));
  }
};

// ---------------------------------------------------------------------------
// ArcRegistry Construction & Lifecycle
// ---------------------------------------------------------------------------

ArcRegistry::ArcRegistry(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

ArcRegistry::~ArcRegistry() = default;
ArcRegistry::ArcRegistry(ArcRegistry &&other) noexcept = default;
ArcRegistry &ArcRegistry::operator=(ArcRegistry &&other) noexcept = default;

Result<ArcRegistry> ArcRegistry::open(const fs::path &db_path,
                                      ArcRegistryConfig config) {
  const std::string raw_path = db_path.string();
  if (raw_path.empty() || has_control_or_nul(raw_path) || raw_path == ":memory:") {
    return fail<ArcRegistry>(ErrorCode::invalid_range, ArcError::insecure_path);
  }

  // Reject symlink DB file before opening or touching permissions.
  {
    struct stat st{};
    if (::lstat(raw_path.c_str(), &st) == 0) {
      if (S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode)) {
        return fail<ArcRegistry>(ErrorCode::invalid_range, ArcError::insecure_path);
      }
    } else if (errno != ENOENT) {
      return fail<ArcRegistry>(ErrorCode::io, ArcError::io_failed);
    }
  }

  fs::path open_path = db_path;
  const fs::path parent = db_path.parent_path();
  if (!parent.empty()) {
    const auto dir_ok = ensure_secure_parent_dir(parent);
    if (!dir_ok.has_value()) {
      return Result<ArcRegistry>::failure(dir_ok.error());
    }
    std::error_code canon_ec;
    const fs::path canon_parent = fs::canonical(parent, canon_ec);
    if (!canon_ec && !canon_parent.empty()) {
      open_path = canon_parent / db_path.filename();
    }
  }

  const std::string open_raw = open_path.string();
  {
    struct stat st{};
    if (::lstat(open_raw.c_str(), &st) == 0) {
      if (S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode)) {
        return fail<ArcRegistry>(ErrorCode::invalid_range, ArcError::insecure_path);
      }
    } else if (errno != ENOENT) {
      return fail<ArcRegistry>(ErrorCode::io, ArcError::io_failed);
    }
  }

  auto impl = std::make_unique<Impl>();
  impl->db_path = open_path;
  impl->is_memory = false;
  impl->config = std::move(config);

  const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOFOLLOW;
  const int open_rc = sqlite3_open_v2(open_raw.c_str(), &impl->conn.db, flags, nullptr);
  if (open_rc != SQLITE_OK || impl->conn.db == nullptr) {
    struct stat st{};
    if (::lstat(open_raw.c_str(), &st) == 0 && S_ISLNK(st.st_mode)) {
      return fail<ArcRegistry>(ErrorCode::invalid_range, ArcError::insecure_path);
    }
    return fail<ArcRegistry>(ErrorCode::io, ArcError::sqlite_failed);
  }

  (void)sqlite3_db_config(impl->conn.db, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
  (void)sqlite3_db_config(impl->conn.db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr);
  (void)sqlite3_db_config(impl->conn.db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0,
                          nullptr);
  (void)sqlite3_busy_timeout(impl->conn.db, static_cast<int>(std::min<std::uint32_t>(
                                                impl->config.busy_timeout_ms, 60000U)));

  char *err = nullptr;
  const int pragma_rc = sqlite3_exec(impl->conn.db,
                                     "PRAGMA journal_mode = WAL; PRAGMA synchronous = "
                                     "NORMAL; PRAGMA foreign_keys = ON;",
                                     nullptr, nullptr, &err);
  if (err != nullptr) {
    sqlite3_free(err);
  }
  if (pragma_rc != SQLITE_OK) {
    return fail<ArcRegistry>(ErrorCode::io, ArcError::sqlite_failed);
  }

  const auto schema_res = impl->init_schema();
  if (!schema_res.has_value()) {
    return Result<ArcRegistry>::failure(schema_res.error());
  }

  tighten_db_and_sidecars(open_path);
  return Result<ArcRegistry>::success(ArcRegistry{std::move(impl)});
}

Result<ArcRegistry> ArcRegistry::open_in_memory(ArcRegistryConfig config) {
  auto impl = std::make_unique<Impl>();
  impl->is_memory = true;
  impl->config = std::move(config);

  const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MEMORY;
  const int open_rc = sqlite3_open_v2(":memory:", &impl->conn.db, flags, nullptr);
  if (open_rc != SQLITE_OK || impl->conn.db == nullptr) {
    return fail<ArcRegistry>(ErrorCode::io, ArcError::sqlite_failed);
  }

  (void)sqlite3_db_config(impl->conn.db, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
  (void)sqlite3_db_config(impl->conn.db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr);
  (void)sqlite3_db_config(impl->conn.db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0,
                          nullptr);
  (void)sqlite3_busy_timeout(impl->conn.db, static_cast<int>(std::min<std::uint32_t>(
                                                impl->config.busy_timeout_ms, 60000U)));
  (void)sqlite3_exec(impl->conn.db, "PRAGMA foreign_keys = ON;", nullptr, nullptr,
                     nullptr);

  const auto schema_res = impl->init_schema();
  if (!schema_res.has_value()) {
    return Result<ArcRegistry>::failure(schema_res.error());
  }
  return Result<ArcRegistry>::success(ArcRegistry{std::move(impl)});
}

// ---------------------------------------------------------------------------
// CRUD & Hybrid Semantic Search
// ---------------------------------------------------------------------------

Result<void> ArcRegistry::register_function(const ArcFunctionRecord &record) {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<void>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  if (!valid_arc_id(record.id)) {
    return fail<void>(ErrorCode::invalid_range, ArcError::invalid_id);
  }
  if (!record.lua_source.empty() && record.lua_source[0] == '\x1b') {
    return fail<void>(ErrorCode::unsupported, ArcError::sandbox_violation);
  }
  const auto analysis = analyze_lua_source(record.lua_source);
  if (!analysis.has_value() || !analysis.value().syntax_valid ||
      !analysis.value().defines_semantic_function) {
    return fail<void>(ErrorCode::invalid_range, ArcError::invalid_lua);
  }

  const auto params_json = serialize_params_json(record.params);
  const auto ret_json = serialize_string_vec_json(record.return_keys);
  if (!params_json.has_value() || !ret_json.has_value()) {
    return fail<void>(ErrorCode::invalid_range, ArcError::type_conversion_failed);
  }

  const std::string params_text = join_params_text(record.params);
  const std::string ret_text = join_strings(record.return_keys);

  std::vector<unsigned char> emb_blob;
  if (impl_->config.embed_callback) {
    const std::string combined =
        record.description + " " + params_text + " " + ret_text;
    auto emb = impl_->config.embed_callback(combined);
    if (emb.has_value() && !emb.value().empty()) {
      emb_blob = encode_embedding_blob(emb.value());
    }
  }

  ScopedTransaction tx{impl_->conn.db};
  if (!tx.begin()) {
    return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
  }

  {
    ScopedSqliteStmt stmt{};
    static constexpr const char *kUpsertFn = R"SQL(
      INSERT INTO arc_functions(
        id, description, params_json, return_keys_json, lua_source,
        provenance_trace_hash, granularity, is_root, compiled_lua,
        invocation_count, success_count, failure_count, fallback_count,
        total_source_cost_usd, total_builder_cost_usd, total_target_cost_usd,
        embedding_blob
      ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)
      ON CONFLICT(id) DO UPDATE SET
        description = excluded.description,
        params_json = excluded.params_json,
        return_keys_json = excluded.return_keys_json,
        lua_source = excluded.lua_source,
        provenance_trace_hash = excluded.provenance_trace_hash,
        granularity = excluded.granularity,
        is_root = excluded.is_root,
        compiled_lua = COALESCE(excluded.compiled_lua, arc_functions.compiled_lua),
        embedding_blob = excluded.embedding_blob;
    )SQL";
    if (sqlite3_prepare_v2(impl_->conn.db, kUpsertFn, -1, &stmt.stmt, nullptr) !=
        SQLITE_OK) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
    (void)bind_text(stmt.stmt, 1, record.id);
    (void)bind_text(stmt.stmt, 2, record.description);
    (void)bind_text(stmt.stmt, 3, params_json.value());
    (void)bind_text(stmt.stmt, 4, ret_json.value());
    (void)bind_text(stmt.stmt, 5, record.lua_source);
    (void)bind_text(stmt.stmt, 6, record.provenance_trace_hash);
    (void)bind_text(stmt.stmt, 7, arc_granularity_name(record.granularity));
    (void)sqlite3_bind_int(stmt.stmt, 8, record.is_root ? 1 : 0);
    if (record.compiled_lua.has_value()) {
      (void)bind_text(stmt.stmt, 9, *record.compiled_lua);
    } else {
      (void)sqlite3_bind_null(stmt.stmt, 9);
    }
    (void)sqlite3_bind_int64(stmt.stmt, 10,
                             static_cast<sqlite3_int64>(record.invocation_count));
    (void)sqlite3_bind_int64(stmt.stmt, 11,
                             static_cast<sqlite3_int64>(record.success_count));
    (void)sqlite3_bind_int64(stmt.stmt, 12,
                             static_cast<sqlite3_int64>(record.failure_count));
    (void)sqlite3_bind_int64(stmt.stmt, 13,
                             static_cast<sqlite3_int64>(record.fallback_count));
    (void)sqlite3_bind_double(stmt.stmt, 14, record.total_source_cost_usd);
    (void)sqlite3_bind_double(stmt.stmt, 15, record.total_builder_cost_usd);
    (void)sqlite3_bind_double(stmt.stmt, 16, record.total_target_cost_usd);
    if (!emb_blob.empty()) {
      (void)sqlite3_bind_blob(stmt.stmt, 17, emb_blob.data(),
                              static_cast<int>(emb_blob.size()), SQLITE_TRANSIENT);
    } else {
      (void)sqlite3_bind_null(stmt.stmt, 17);
    }
    if (sqlite3_step(stmt.stmt) != SQLITE_DONE) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
  }

  // Sync arc_functions_fts atomically
  {
    ScopedSqliteStmt del{};
    if (sqlite3_prepare_v2(impl_->conn.db,
                           "DELETE FROM arc_functions_fts WHERE id = ?1;", -1,
                           &del.stmt, nullptr) != SQLITE_OK) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
    (void)bind_text(del.stmt, 1, record.id);
    if (sqlite3_step(del.stmt) != SQLITE_DONE) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
  }
  {
    ScopedSqliteStmt ins{};
    if (sqlite3_prepare_v2(impl_->conn.db,
                           "INSERT INTO arc_functions_fts(id, description, "
                           "params_text, return_keys_text) "
                           "VALUES(?1, ?2, ?3, ?4);",
                           -1, &ins.stmt, nullptr) != SQLITE_OK) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
    (void)bind_text(ins.stmt, 1, record.id);
    (void)bind_text(ins.stmt, 2, record.description);
    (void)bind_text(ins.stmt, 3, params_text);
    (void)bind_text(ins.stmt, 4, ret_text);
    if (sqlite3_step(ins.stmt) != SQLITE_DONE) {
      return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
    }
  }

  // Register inline entry_templates (and default description entry for root functions).
  for (std::size_t i = 0U; i < record.entry_templates.size(); ++i) {
    std::string eid = record.id + "_e" + std::to_string(i);
    if (eid.size() > kMaxArcIdLength) {
      eid = compute_trace_hash(eid).substr(0U, 32U);
    }
    ArcEntryPointRecord ep{std::move(eid), record.id, record.entry_templates[i], true};
    const auto er = impl_->upsert_entry_in_tx(ep);
    if (!er.has_value()) {
      return er;
    }
  }
  if (record.is_root && record.entry_templates.empty() && !record.description.empty()) {
    std::string eid = record.id + "_root";
    if (eid.size() > kMaxArcIdLength) {
      eid = compute_trace_hash(eid).substr(0U, 32U);
    }
    ArcEntryPointRecord ep{std::move(eid), record.id, record.description, true};
    const auto er = impl_->upsert_entry_in_tx(ep);
    if (!er.has_value()) {
      return er;
    }
  }

  if (!tx.commit()) {
    return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
  }
  return Result<void>::success();
}

Result<void> ArcRegistry::register_entry_point(const ArcEntryPointRecord &entry) {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<void>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  if (!valid_arc_id(entry.entry_id) || !valid_arc_id(entry.function_id)) {
    return fail<void>(ErrorCode::invalid_range, ArcError::invalid_id);
  }
  const auto fn = get_function(entry.function_id);
  if (!fn.has_value()) {
    return fail<void>(ErrorCode::invalid_range, ArcError::function_not_found);
  }

  ScopedTransaction tx{impl_->conn.db};
  if (!tx.begin()) {
    return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
  }
  const auto res = impl_->upsert_entry_in_tx(entry);
  if (!res.has_value()) {
    return res;
  }
  if (!tx.commit()) {
    return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
  }
  return Result<void>::success();
}

Result<ArcFunctionRecord> ArcRegistry::get_function(std::string_view id) const {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<ArcFunctionRecord>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  if (!valid_arc_id(id)) {
    return fail<ArcFunctionRecord>(ErrorCode::invalid_range, ArcError::invalid_id);
  }
  ScopedSqliteStmt stmt{};
  static constexpr const char *kSelectSql = R"SQL(
    SELECT id, description, params_json, return_keys_json, lua_source,
           provenance_trace_hash, granularity, is_root, compiled_lua,
           invocation_count, success_count, failure_count, fallback_count,
           total_source_cost_usd, total_builder_cost_usd, total_target_cost_usd
    FROM arc_functions WHERE id = ?1;
  )SQL";
  if (sqlite3_prepare_v2(impl_->conn.db, kSelectSql, -1, &stmt.stmt, nullptr) !=
      SQLITE_OK) {
    return fail<ArcFunctionRecord>(ErrorCode::io, ArcError::sqlite_failed);
  }
  (void)bind_text(stmt.stmt, 1, id);
  const int rc = sqlite3_step(stmt.stmt);
  if (rc == SQLITE_DONE) {
    return fail<ArcFunctionRecord>(ErrorCode::invalid_range,
                                   ArcError::function_not_found);
  }
  if (rc != SQLITE_ROW) {
    return fail<ArcFunctionRecord>(ErrorCode::io, ArcError::sqlite_failed);
  }
  return Result<ArcFunctionRecord>::success(impl_->read_function_row(stmt.stmt));
}

Result<std::vector<ArcFunctionRecord>> ArcRegistry::list_functions() const {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<std::vector<ArcFunctionRecord>>(ErrorCode::stale_handle,
                                                ArcError::sqlite_failed);
  }
  ScopedSqliteStmt stmt{};
  static constexpr const char *kListSql = R"SQL(
    SELECT id, description, params_json, return_keys_json, lua_source,
           provenance_trace_hash, granularity, is_root, compiled_lua,
           invocation_count, success_count, failure_count, fallback_count,
           total_source_cost_usd, total_builder_cost_usd, total_target_cost_usd
    FROM arc_functions ORDER BY id ASC;
  )SQL";
  if (sqlite3_prepare_v2(impl_->conn.db, kListSql, -1, &stmt.stmt, nullptr) !=
      SQLITE_OK) {
    return fail<std::vector<ArcFunctionRecord>>(ErrorCode::io, ArcError::sqlite_failed);
  }
  std::vector<ArcFunctionRecord> out;
  for (;;) {
    const int rc = sqlite3_step(stmt.stmt);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      return fail<std::vector<ArcFunctionRecord>>(ErrorCode::io,
                                                  ArcError::sqlite_failed);
    }
    out.push_back(impl_->read_function_row(stmt.stmt));
  }
  return Result<std::vector<ArcFunctionRecord>>::success(std::move(out));
}

Result<void> ArcRegistry::remove_function(std::string_view id) {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<void>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  if (!valid_arc_id(id)) {
    return fail<void>(ErrorCode::invalid_range, ArcError::invalid_id);
  }

  ScopedTransaction tx{impl_->conn.db};
  if (!tx.begin()) {
    return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
  }

  auto exec_del = [&](const char *sql) -> bool {
    ScopedSqliteStmt stmt{};
    if (sqlite3_prepare_v2(impl_->conn.db, sql, -1, &stmt.stmt, nullptr) != SQLITE_OK) {
      return false;
    }
    (void)bind_text(stmt.stmt, 1, id);
    return sqlite3_step(stmt.stmt) == SQLITE_DONE;
  };

  if (!exec_del("DELETE FROM arc_entries_fts WHERE function_id = ?1;") ||
      !exec_del("DELETE FROM arc_entries WHERE function_id = ?1;") ||
      !exec_del("DELETE FROM arc_functions_fts WHERE id = ?1;") ||
      !exec_del("DELETE FROM arc_functions WHERE id = ?1;")) {
    return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
  }

  const int changed = sqlite3_changes(impl_->conn.db);
  if (!tx.commit()) {
    return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
  }
  if (changed == 0) {
    return fail<void>(ErrorCode::invalid_range, ArcError::function_not_found);
  }
  return Result<void>::success();
}

Result<std::vector<ArcSearchMatch>>
ArcRegistry::search_functions(std::string_view query, std::size_t limit) const {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<std::vector<ArcSearchMatch>>(ErrorCode::stale_handle,
                                             ArcError::sqlite_failed);
  }
  if (limit == 0U || trim_sv(query).empty()) {
    return Result<std::vector<ArcSearchMatch>>::success({});
  }

  // 1. Collect FTS5 BM25 scores (parameterized MATCH query).
  std::unordered_map<std::string, double> bm25_map;
  const std::string fts_q = build_safe_fts5_query(query);
  if (!fts_q.empty()) {
    ScopedSqliteStmt stmt{};
    static constexpr const char *kFtsSql = R"SQL(
      SELECT id, bm25(arc_functions_fts, 0.0, 2.0, 1.0, 0.5)
      FROM arc_functions_fts WHERE arc_functions_fts MATCH ?1;
    )SQL";
    if (sqlite3_prepare_v2(impl_->conn.db, kFtsSql, -1, &stmt.stmt, nullptr) ==
        SQLITE_OK) {
      (void)bind_text(stmt.stmt, 1, fts_q);
      while (sqlite3_step(stmt.stmt) == SQLITE_ROW) {
        const std::string id = col_text(stmt.stmt, 0);
        const double raw = sqlite3_column_double(stmt.stmt, 1);
        const double pos = std::max(0.0, -raw);
        bm25_map[id] = pos / (pos + 2.0);
      }
    }
  }

  // 2. Optional dense query embedding.
  std::optional<std::vector<float>> q_emb;
  if (impl_->config.embed_callback) {
    auto emb = impl_->config.embed_callback(query);
    if (emb.has_value() && !emb.value().empty()) {
      q_emb = std::move(emb.value());
    }
  }

  // 3. Score all functions deterministically.
  ScopedSqliteStmt all_stmt{};
  if (sqlite3_prepare_v2(
          impl_->conn.db,
          "SELECT id, description, params_json, return_keys_json, embedding_blob "
          "FROM arc_functions ORDER BY id ASC;",
          -1, &all_stmt.stmt, nullptr) != SQLITE_OK) {
    return fail<std::vector<ArcSearchMatch>>(ErrorCode::io, ArcError::sqlite_failed);
  }

  std::vector<ArcSearchMatch> matches;
  while (sqlite3_step(all_stmt.stmt) == SQLITE_ROW) {
    const std::string id = col_text(all_stmt.stmt, 0);
    const std::string desc = col_text(all_stmt.stmt, 1);
    const auto params = deserialize_params_json(col_text(all_stmt.stmt, 2));
    const auto rkeys = deserialize_string_vec_json(col_text(all_stmt.stmt, 3));

    const double bm25 = bm25_map.contains(id) ? bm25_map[id] : 0.0;
    const double lex_desc =
        compute_lexical_similarity(QueryText{query}, CandidateText{desc});
    const std::string full_text =
        desc + " " + join_params_text(params) + " " + join_strings(rkeys);
    const double lex_full =
        compute_lexical_similarity(QueryText{query}, CandidateText{full_text});
    const double lex = std::max(lex_desc, 0.9 * lex_full);

    double dense = 0.0;
    bool has_dense = false;
    if (q_emb.has_value() && sqlite3_column_type(all_stmt.stmt, 4) == SQLITE_BLOB) {
      const auto vec = decode_embedding_blob(sqlite3_column_blob(all_stmt.stmt, 4),
                                             sqlite3_column_bytes(all_stmt.stmt, 4));
      if (vec.size() == q_emb->size()) {
        dense = compute_cosine_similarity(*q_emb, vec);
        has_dense = true;
      }
    }

    double score = 0.0;
    if (ascii_lower(trim_sv(query)) == ascii_lower(trim_sv(desc)) ||
        ascii_lower(trim_sv(query)) == ascii_lower(id)) {
      score = 1.0;
    } else if (has_dense) {
      const double w_b = impl_->config.bm25_weight * 0.5;
      const double w_l = impl_->config.lexical_weight * 0.5;
      const double w_d = impl_->config.dense_weight;
      const double denom = w_b + w_l + w_d;
      score = denom > 0.0
                  ? std::clamp((w_b * bm25 + w_l * lex + w_d * dense) / denom, 0.0, 1.0)
                  : 0.0;
    } else {
      const double w_b = impl_->config.bm25_weight;
      const double w_l = impl_->config.lexical_weight;
      const double denom = w_b + w_l;
      const double blended = denom > 0.0 ? (w_b * bm25 + w_l * lex) / denom : lex;
      score = std::clamp(std::max(blended, lex * 0.85), 0.0, 1.0);
    }

    if (score > 0.0) {
      matches.push_back(ArcSearchMatch{id, id, desc, score, bm25, lex, dense});
    }
  }

  std::sort(matches.begin(), matches.end(), [](const auto &a, const auto &b) {
    if (std::fabs(a.score - b.score) > 1e-12) {
      return a.score > b.score;
    }
    return a.id < b.id;
  });
  if (matches.size() > limit) {
    matches.resize(limit);
  }
  return Result<std::vector<ArcSearchMatch>>::success(std::move(matches));
}

Result<std::vector<ArcSearchMatch>>
ArcRegistry::search_entry_points(std::string_view query, std::size_t limit) const {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<std::vector<ArcSearchMatch>>(ErrorCode::stale_handle,
                                             ArcError::sqlite_failed);
  }
  if (limit == 0U || trim_sv(query).empty()) {
    return Result<std::vector<ArcSearchMatch>>::success({});
  }

  std::unordered_map<std::string, double> bm25_map;
  const std::string fts_q = build_safe_fts5_query(query);
  if (!fts_q.empty()) {
    ScopedSqliteStmt stmt{};
    static constexpr const char *kFtsSql = R"SQL(
      SELECT entry_id, bm25(arc_entries_fts, 0.0, 0.0, 1.0)
      FROM arc_entries_fts WHERE arc_entries_fts MATCH ?1;
    )SQL";
    if (sqlite3_prepare_v2(impl_->conn.db, kFtsSql, -1, &stmt.stmt, nullptr) ==
        SQLITE_OK) {
      (void)bind_text(stmt.stmt, 1, fts_q);
      while (sqlite3_step(stmt.stmt) == SQLITE_ROW) {
        const std::string eid = col_text(stmt.stmt, 0);
        const double raw = sqlite3_column_double(stmt.stmt, 1);
        const double pos = std::max(0.0, -raw);
        bm25_map[eid] = pos / (pos + 2.0);
      }
    }
  }

  std::optional<std::vector<float>> q_emb;
  if (impl_->config.embed_callback) {
    auto emb = impl_->config.embed_callback(query);
    if (emb.has_value() && !emb.value().empty()) {
      q_emb = std::move(emb.value());
    }
  }

  ScopedSqliteStmt all_stmt{};
  if (sqlite3_prepare_v2(impl_->conn.db,
                         "SELECT entry_id, function_id, template_text, embedding_blob "
                         "FROM arc_entries ORDER BY entry_id ASC;",
                         -1, &all_stmt.stmt, nullptr) != SQLITE_OK) {
    return fail<std::vector<ArcSearchMatch>>(ErrorCode::io, ArcError::sqlite_failed);
  }

  std::vector<ArcSearchMatch> matches;
  while (sqlite3_step(all_stmt.stmt) == SQLITE_ROW) {
    const std::string eid = col_text(all_stmt.stmt, 0);
    const std::string fid = col_text(all_stmt.stmt, 1);
    const std::string tmpl = col_text(all_stmt.stmt, 2);

    const double bm25 = bm25_map.contains(eid) ? bm25_map[eid] : 0.0;
    const double lex =
        compute_lexical_similarity(QueryText{query}, CandidateText{tmpl});

    double dense = 0.0;
    bool has_dense = false;
    if (q_emb.has_value() && sqlite3_column_type(all_stmt.stmt, 3) == SQLITE_BLOB) {
      const auto vec = decode_embedding_blob(sqlite3_column_blob(all_stmt.stmt, 3),
                                             sqlite3_column_bytes(all_stmt.stmt, 3));
      if (vec.size() == q_emb->size()) {
        dense = compute_cosine_similarity(*q_emb, vec);
        has_dense = true;
      }
    }

    double score = 0.0;
    if (ascii_lower(trim_sv(query)) == ascii_lower(trim_sv(tmpl))) {
      score = 1.0;
    } else if (has_dense) {
      const double w_b = impl_->config.bm25_weight * 0.5;
      const double w_l = impl_->config.lexical_weight * 0.5;
      const double w_d = impl_->config.dense_weight;
      const double denom = w_b + w_l + w_d;
      score = denom > 0.0
                  ? std::clamp((w_b * bm25 + w_l * lex + w_d * dense) / denom, 0.0, 1.0)
                  : 0.0;
    } else {
      const double w_b = impl_->config.bm25_weight;
      const double w_l = impl_->config.lexical_weight;
      const double denom = w_b + w_l;
      const double blended = denom > 0.0 ? (w_b * bm25 + w_l * lex) / denom : lex;
      score = std::clamp(std::max(blended, lex * 0.85), 0.0, 1.0);
    }

    if (score > 0.0) {
      matches.push_back(ArcSearchMatch{eid, fid, tmpl, score, bm25, lex, dense});
    }
  }

  std::sort(matches.begin(), matches.end(), [](const auto &a, const auto &b) {
    if (std::fabs(a.score - b.score) > 1e-12) {
      return a.score > b.score;
    }
    return a.id < b.id;
  });
  if (matches.size() > limit) {
    matches.resize(limit);
  }
  return Result<std::vector<ArcSearchMatch>>::success(std::move(matches));
}

Result<ArcRegistryStats> ArcRegistry::stats() const {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<ArcRegistryStats>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  ArcRegistryStats st{};
  {
    ScopedSqliteStmt stmt{};
    static constexpr const char *kStatsSql = R"SQL(
      SELECT COUNT(*),
             COALESCE(SUM(CASE WHEN is_root != 0 THEN 1 ELSE 0 END), 0),
             COALESCE(SUM(CASE WHEN compiled_lua IS NOT NULL AND length(compiled_lua) > 0 THEN 1 ELSE 0 END), 0),
             COALESCE(SUM(invocation_count), 0),
             COALESCE(SUM(success_count), 0),
             COALESCE(SUM(failure_count), 0),
             COALESCE(SUM(fallback_count), 0),
             COALESCE(SUM(total_source_cost_usd), 0.0),
             COALESCE(SUM(total_builder_cost_usd), 0.0),
             COALESCE(SUM(total_target_cost_usd), 0.0)
      FROM arc_functions;
    )SQL";
    if (sqlite3_prepare_v2(impl_->conn.db, kStatsSql, -1, &stmt.stmt, nullptr) !=
            SQLITE_OK ||
        sqlite3_step(stmt.stmt) != SQLITE_ROW) {
      return fail<ArcRegistryStats>(ErrorCode::io, ArcError::sqlite_failed);
    }
    st.function_count = static_cast<std::size_t>(sqlite3_column_int64(stmt.stmt, 0));
    st.root_function_count =
        static_cast<std::size_t>(sqlite3_column_int64(stmt.stmt, 1));
    st.compiled_function_count =
        static_cast<std::size_t>(sqlite3_column_int64(stmt.stmt, 2));
    st.total_invocations =
        static_cast<std::uint64_t>(sqlite3_column_int64(stmt.stmt, 3));
    st.total_successes = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.stmt, 4));
    st.total_failures = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.stmt, 5));
    st.total_fallbacks = static_cast<std::uint64_t>(sqlite3_column_int64(stmt.stmt, 6));
    st.total_source_cost_usd = sqlite3_column_double(stmt.stmt, 7);
    st.total_builder_cost_usd = sqlite3_column_double(stmt.stmt, 8);
    st.total_target_cost_usd = sqlite3_column_double(stmt.stmt, 9);
  }
  {
    ScopedSqliteStmt stmt{};
    if (sqlite3_prepare_v2(impl_->conn.db, "SELECT COUNT(*) FROM arc_entries;", -1,
                           &stmt.stmt, nullptr) != SQLITE_OK ||
        sqlite3_step(stmt.stmt) != SQLITE_ROW) {
      return fail<ArcRegistryStats>(ErrorCode::io, ArcError::sqlite_failed);
    }
    st.entry_point_count = static_cast<std::size_t>(sqlite3_column_int64(stmt.stmt, 0));
  }
  return Result<ArcRegistryStats>::success(st);
}

Result<void> ArcRegistry::record_cost(std::string_view function_id,
                                      const ArcCostSample &cost) {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<void>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  if (!valid_arc_id(function_id)) {
    return fail<void>(ErrorCode::invalid_range, ArcError::invalid_id);
  }
  ScopedSqliteStmt stmt{};
  static constexpr const char *kCostSql = R"SQL(
    UPDATE arc_functions SET
      total_source_cost_usd = total_source_cost_usd + ?2,
      total_builder_cost_usd = total_builder_cost_usd + ?3,
      total_target_cost_usd = total_target_cost_usd + ?4
    WHERE id = ?1;
  )SQL";
  if (sqlite3_prepare_v2(impl_->conn.db, kCostSql, -1, &stmt.stmt, nullptr) !=
      SQLITE_OK) {
    return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
  }
  (void)bind_text(stmt.stmt, 1, function_id);
  (void)sqlite3_bind_double(stmt.stmt, 2, cost.source_cost_usd);
  (void)sqlite3_bind_double(stmt.stmt, 3, cost.builder_cost_usd);
  (void)sqlite3_bind_double(stmt.stmt, 4, cost.target_cost_usd);
  if (sqlite3_step(stmt.stmt) != SQLITE_DONE) {
    return fail<void>(ErrorCode::io, ArcError::sqlite_failed);
  }
  if (sqlite3_changes(impl_->conn.db) == 0) {
    return fail<void>(ErrorCode::invalid_range, ArcError::function_not_found);
  }
  return Result<void>::success();
}

// ---------------------------------------------------------------------------
// Execution (Dynamic, Compiled, Gated Serve)
// ---------------------------------------------------------------------------

Result<ArcExecutionResult>
ArcRegistry::invoke_function(std::string_view function_id, const Value &payloads,
                             const ArcRuntimeCallbacks &callbacks,
                             const ArcExecutionLimits &limits) {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<ArcExecutionResult>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  const auto fn = get_function(function_id);
  if (!fn.has_value()) {
    return Result<ArcExecutionResult>::failure(fn.error());
  }
  return impl_->run_lua_chunk(this, FunctionIdRef{fn.value().id}, fn.value().lua_source,
                              payloads, callbacks, limits, false);
}

Result<ArcExecutionResult>
ArcRegistry::invoke_compiled(std::string_view function_id, const Value &payloads,
                             const ArcRuntimeCallbacks &callbacks,
                             const ArcExecutionLimits &limits) {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<ArcExecutionResult>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  const auto fn = get_function(function_id);
  if (!fn.has_value()) {
    return Result<ArcExecutionResult>::failure(fn.error());
  }
  if (!fn.value().compiled_lua.has_value() || fn.value().compiled_lua->empty()) {
    return fail<ArcExecutionResult>(ErrorCode::invalid_range,
                                    ArcError::function_not_found);
  }
  return impl_->run_lua_chunk(this, FunctionIdRef{fn.value().id},
                              *fn.value().compiled_lua, payloads, callbacks, limits,
                              true);
}

Result<ArcExecutionResult> ArcRegistry::invoke_compiled_module(
    const ArcCompiledModule &module, const Value &payloads,
    const ArcRuntimeCallbacks &callbacks, const ArcExecutionLimits &limits) {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<ArcExecutionResult>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  return impl_->run_lua_chunk(this, FunctionIdRef{module.root_function_id},
                              module.lua_source, payloads, callbacks, limits, true);
}

Result<ArcExecutionResult> ArcRegistry::serve(std::string_view raw_request,
                                              const Value &explicit_payloads,
                                              const ArcRuntimeCallbacks &callbacks,
                                              const ArcExecutionLimits &limits) {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<ArcExecutionResult>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  const auto start_tp = SteadyClock::now();

  // IS1: Entry-point search
  const auto matches = search_entry_points(raw_request, 1U);
  if (!matches.has_value()) {
    return Result<ArcExecutionResult>::failure(matches.error());
  }
  if (matches.value().empty() || matches.value()[0].score < limits.min_entry_score) {
    if (callbacks.source_fallback) {
      auto fb = callbacks.source_fallback(raw_request);
      if (!fb.has_value()) {
        return Result<ArcExecutionResult>::failure(fb.error());
      }
      ArcExecutionResult res{};
      res.output = std::move(fb.value());
      res.cache_hit = false;
      res.fell_back_to_source = true;
      res.fallback_reason = "cache_miss";
      res.entry_score = matches.value().empty() ? 0.0 : matches.value()[0].score;
      res.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            SteadyClock::now() - start_tp)
                            .count();
      return Result<ArcExecutionResult>::success(std::move(res));
    }
    return fail<ArcExecutionResult>(ErrorCode::invalid_range,
                                    ArcError::entry_not_found);
  }

  const ArcSearchMatch best = matches.value()[0];
  const auto root_fn = get_function(best.function_id);
  if (!root_fn.has_value()) {
    return Result<ArcExecutionResult>::failure(root_fn.error());
  }

  // IS2: Populate payloads + extract missing required params via target LM if
  // available.
  Value::Object payloads_obj;
  if (const auto *explicit_obj =
          std::get_if<Value::Object>(&explicit_payloads.value())) {
    payloads_obj = *explicit_obj;
  }

  auto has_param = [&](const ArcParamSpec &p) -> bool {
    const std::string p_name_low = ascii_lower(trim_sv(p.name));
    const std::string p_desc_low = ascii_lower(trim_sv(p.description));
    for (const auto &[k, _] : payloads_obj) {
      const std::string k_low = ascii_lower(trim_sv(k));
      if ((!p_desc_low.empty() && k_low == p_desc_low) ||
          (!p_name_low.empty() && k_low == p_name_low)) {
        return true;
      }
    }
    return false;
  };

  std::vector<ArcParamSpec> missing_params;
  for (const auto &p : root_fn.value().params) {
    if (p.required && !has_param(p)) {
      missing_params.push_back(p);
    }
  }

  std::uint32_t extract_lm_calls = 0U;
  if (!missing_params.empty() && callbacks.lm) {
    std::string prompt = "Extract the following parameters as a JSON object from the "
                         "request.\nParameters:\n";
    for (const auto &p : missing_params) {
      prompt += "- \"" + (!p.description.empty() ? p.description : p.name) +
                "\" (name=" + p.name + ", type=" + p.d_type + ")\n";
    }
    prompt += "Request: " + std::string{raw_request};

    ++extract_lm_calls;
    const auto lm_res = callbacks.lm(prompt, "extract_params");
    if (lm_res.has_value()) {
      const auto parsed = parse_json(trim_sv(lm_res.value()));
      if (parsed.has_value()) {
        if (const auto *ext_obj = std::get_if<Value::Object>(&parsed.value().value())) {
          for (const auto &[k, v] : *ext_obj) {
            std::string canonical_key = k;
            std::string dtype = "any";
            for (const auto &p : missing_params) {
              if (ascii_lower(k) == ascii_lower(p.name) ||
                  ascii_lower(k) == ascii_lower(p.description)) {
                canonical_key = !p.description.empty() ? p.description : p.name;
                dtype = p.d_type;
                break;
              }
            }
            const auto coerced = coerce_value_to_type(v, DtypeName{dtype});
            payloads_obj.emplace_back(canonical_key,
                                      coerced.has_value() ? coerced.value() : v);
          }
        }
      }
    }
  }

  const Value merged_payloads = Value::object(std::move(payloads_obj));

  // IS3-IS4: Execute compiled module if preferred and present, else dynamic execution.
  const bool use_compiled = limits.prefer_compiled &&
                            root_fn.value().compiled_lua.has_value() &&
                            !root_fn.value().compiled_lua->empty();
  auto exec_res =
      use_compiled
          ? invoke_compiled(root_fn.value().id, merged_payloads, callbacks, limits)
          : invoke_function(root_fn.value().id, merged_payloads, callbacks, limits);
  if (exec_res.has_value()) {
    (void)impl_->bump_counters(FunctionIdRef{root_fn.value().id},
                               CounterDelta{1, 1, 0, 0});
    exec_res.value().cache_hit = true;
    exec_res.value().entry_score = best.score;
    exec_res.value().lm_calls += extract_lm_calls;
    return exec_res;
  }

  // Runtime error -> fallback to source model S if configured!
  if (callbacks.source_fallback) {
    (void)impl_->bump_counters(FunctionIdRef{root_fn.value().id},
                               CounterDelta{1, 0, 1, 1});
    auto fb = callbacks.source_fallback(raw_request);
    if (!fb.has_value()) {
      return Result<ArcExecutionResult>::failure(fb.error());
    }
    ArcExecutionResult res{};
    res.output = std::move(fb.value());
    res.root_function_id = root_fn.value().id;
    res.cache_hit = true;
    res.fell_back_to_source = true;
    res.fallback_reason = std::string{arc_error_name(arc_error_of(exec_res.error()))};
    res.entry_score = best.score;
    res.lm_calls = extract_lm_calls;
    res.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                          SteadyClock::now() - start_tp)
                          .count();
    return Result<ArcExecutionResult>::success(std::move(res));
  }

  (void)impl_->bump_counters(FunctionIdRef{root_fn.value().id},
                             CounterDelta{1, 0, 1, 0});
  return exec_res;
}

// ---------------------------------------------------------------------------
// Section 2.2.3 Static DAG Compiler
// ---------------------------------------------------------------------------

Result<ArcCompiledModule>
ArcRegistry::compile_network(std::string_view root_function_id, bool save_to_registry) {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<ArcCompiledModule>(ErrorCode::stale_handle, ArcError::sqlite_failed);
  }
  if (!valid_arc_id(root_function_id)) {
    return fail<ArcCompiledModule>(ErrorCode::invalid_range, ArcError::invalid_id);
  }

  struct CompiledNode {
    ArcFunctionRecord record;
    ArcStaticAnalysis analysis;
    std::vector<std::string> resolved_do_callees; // aligned with analysis.do_calls
    std::vector<std::string> caller_payload_keys; // keys passed by callers into this fn
  };

  std::unordered_map<std::string, CompiledNode> nodes;
  std::unordered_set<std::string> visiting;
  std::unordered_set<std::string> visited;
  std::vector<std::string> post_order;

  std::function<Result<void>(std::string_view)> dfs =
      [&](std::string_view fn_id) -> Result<void> {
    const std::string id_str{fn_id};
    if (visiting.contains(id_str)) {
      return fail<void>(ErrorCode::invalid_range, ArcError::compile_cycle_detected);
    }
    if (visited.contains(id_str)) {
      return Result<void>::success();
    }
    visiting.insert(id_str);

    const auto fn = get_function(fn_id);
    if (!fn.has_value()) {
      return Result<void>::failure(fn.error());
    }
    const auto ana = analyze_lua_source(fn.value().lua_source);
    if (!ana.has_value() || !ana.value().syntax_valid ||
        !ana.value().defines_semantic_function) {
      return fail<void>(ErrorCode::invalid_range, ArcError::invalid_lua);
    }

    CompiledNode node{};
    node.record = fn.value();
    node.analysis = ana.value();
    node.resolved_do_callees.reserve(node.analysis.do_calls.size());

    std::vector<std::pair<std::string, std::vector<std::string>>> callee_keys;
    for (const auto &site : node.analysis.do_calls) {
      if (site.query_literal.empty()) {
        return fail<void>(ErrorCode::invalid_range, ArcError::compile_unresolved_call);
      }
      const auto matches = search_functions(site.query_literal, 1U);
      if (!matches.has_value() || matches.value().empty() ||
          matches.value()[0].score < impl_->config.min_do_score) {
        return fail<void>(ErrorCode::invalid_range, ArcError::compile_unresolved_call);
      }
      const std::string callee_id = matches.value()[0].function_id;
      node.resolved_do_callees.push_back(callee_id);
      callee_keys.emplace_back(callee_id,
                               extract_literal_payload_keys(site.payloads_expr));
    }

    nodes[id_str] = std::move(node);

    for (const auto &[callee_id, passed_keys] : callee_keys) {
      const auto sub = dfs(callee_id);
      if (!sub.has_value()) {
        return sub;
      }
      auto &cnode = nodes[callee_id];
      for (const auto &k : passed_keys) {
        if (std::find(cnode.caller_payload_keys.begin(),
                      cnode.caller_payload_keys.end(),
                      k) == cnode.caller_payload_keys.end()) {
          cnode.caller_payload_keys.push_back(k);
        }
      }
    }

    visiting.erase(id_str);
    visited.insert(id_str);
    post_order.push_back(id_str);
    return Result<void>::success();
  };

  const auto dfs_res = dfs(root_function_id);
  if (!dfs_res.has_value()) {
    return Result<ArcCompiledModule>::failure(dfs_res.error());
  }

  // Assign unique, collision-free Lua identifiers for every compiled node
  // (prevents e.g. `foo-bar` vs `foo_bar` colliding on sanitize_lua_ident).
  std::unordered_map<std::string, std::string> lua_fn_names;
  for (std::size_t idx = 0U; idx < post_order.size(); ++idx) {
    const std::string &fn_id = post_order[idx];
    lua_fn_names[fn_id] =
        "__arc_fn_" + std::to_string(idx) + "_" + sanitize_lua_ident(fn_id);
  }

  // Build standalone Lua 5.5.1 module with ZERO registry/FTS5 searches at runtime.
  std::ostringstream out;
  out << "-- Blackbird CPU-ARC Statically Compiled Module\n";
  out << "-- Root function: " << root_function_id << "\n";
  out << "local __arc_frame_runner = nil\n\n";

  out << "local function __arc_exact_load(tbl, keys, d_type)\n";
  out << "  if type(tbl) ~= \"table\" then error(\"compiled load expects table\", 0) "
         "end\n";
  out << "  for i = 1, #keys do\n";
  out << "    local v = tbl[keys[i]]\n";
  out << "    if v ~= nil then\n";
  out << "      if d_type ~= nil then return arc.convert(v, d_type) end\n";
  out << "      return v\n";
  out << "    end\n";
  out << "  end\n";
  out << "  error(\"compiled load key not found: \" .. tostring(keys[1]), 0)\n";
  out << "end\n\n";

  out << "local function __arc_ctx_load(layers, keys, d_type)\n";
  out << "  for depth = #layers, 1, -1 do\n";
  out << "    local layer = layers[depth]\n";
  out << "    for i = 1, #keys do\n";
  out << "      local v = layer[keys[i]]\n";
  out << "      if v ~= nil then\n";
  out << "        if d_type ~= nil then return arc.convert(v, d_type) end\n";
  out << "        return v\n";
  out << "      end\n";
  out << "    end\n";
  out << "  end\n";
  out << "  error(\"compiled ctx load key not found: \" .. tostring(keys[1]), 0)\n";
  out << "end\n\n";

  out << "local function __arc_call(fn, ctx, layers, fn_id, payloads)\n";
  out << "  layers[#layers + 1] = payloads or {}\n";
  out << "  local ok, res\n";
  out << "  if __arc_frame_runner ~= nil then\n";
  out << "    ok, res = pcall(__arc_frame_runner, ctx, fn_id, fn, layers)\n";
  out << "  else\n";
  out << "    ok, res = pcall(fn, ctx, layers)\n";
  out << "  end\n";
  out << "  layers[#layers] = nil\n";
  out << "  if not ok then error(res, 0) end\n";
  out << "  return res\n";
  out << "end\n\n";

  std::size_t resolved_do_total = 0U;
  std::size_t resolved_load_total = 0U;

  // Helper to resolve a query against a candidate key pool and return top matching
  // exact keys.
  auto resolve_key_candidates =
      [](QueryText query,
         const std::vector<std::string> &pool) -> std::vector<std::string> {
    std::vector<std::pair<double, std::string>> scored;
    std::set<std::string> seen;
    for (const auto &k : pool) {
      if (k.empty() || !seen.insert(k).second) {
        continue;
      }
      const double s = compute_lexical_similarity(query, CandidateText{k});
      if (s > 0.0) {
        scored.emplace_back(s, k);
      }
    }
    std::sort(scored.begin(), scored.end(), [](const auto &a, const auto &b) {
      if (std::fabs(a.first - b.first) > 1e-12) {
        return a.first > b.first;
      }
      return a.second < b.second;
    });
    std::vector<std::string> keys;
    for (const auto &[_, k] : scored) {
      keys.push_back(k);
    }
    const std::string lit{query.value};
    if (!lit.empty() && std::find(keys.begin(), keys.end(), lit) == keys.end()) {
      keys.push_back(lit);
    }
    return keys;
  };

  auto format_lua_key_list = [](const std::vector<std::string> &keys) -> std::string {
    std::string s = "{";
    for (std::size_t i = 0U; i < keys.size(); ++i) {
      if (i > 0U) {
        s += ", ";
      }
      s += quote_lua_string(keys[i]);
    }
    s += "}";
    return s;
  };

  struct ByteSpan {
    std::size_t start = 0U;
    std::size_t end = 0U;
  };

  // Emit each function in post-order (callees first, root last).
  for (const auto &fn_id : post_order) {
    const auto &node = nodes.at(fn_id);
    const std::string &src = node.record.lua_source;
    const std::string &compiled_fn_name = lua_fn_names.at(fn_id);

    // Map each arc.do_ site's start_offset to its resolved callee ID.
    std::unordered_map<std::size_t, std::string> do_callee_by_offset;
    for (std::size_t idx = 0U; idx < node.analysis.do_calls.size(); ++idx) {
      do_callee_by_offset[node.analysis.do_calls[idx].start_offset] =
          node.resolved_do_callees[idx];
    }

    // Collect key pools for ctx loads and dict loads.
    std::vector<std::string> ctx_key_pool;
    for (const auto &p : node.record.params) {
      if (!p.description.empty()) {
        ctx_key_pool.push_back(p.description);
      }
      if (!p.name.empty()) {
        ctx_key_pool.push_back(p.name);
      }
    }
    for (const auto &ck : node.caller_payload_keys) {
      ctx_key_pool.push_back(ck);
    }

    std::vector<std::string> dict_key_pool;
    for (const auto &callee_id : node.resolved_do_callees) {
      for (const auto &rk : nodes.at(callee_id).record.return_keys) {
        dict_key_pool.push_back(rk);
      }
    }

    const auto toks = lex_lua_source(src);

    // Detect BOTH `function semantic_function(p)` AND `semantic_function = function(p)`
    // and capture the exact parameter name `ctx_param`!
    std::string ctx_param = "ctx";
    std::optional<ByteSpan> header_span;
    std::string header_replacement;
    for (std::size_t i = 0U; i < toks.size(); ++i) {
      // Form 1: `function semantic_function ( <params> )`
      if (toks[i].kind == LuaTokKind::ident && toks[i].text == "function" &&
          i + 3U < toks.size() && toks[i + 1U].kind == LuaTokKind::ident &&
          toks[i + 1U].text == "semantic_function" &&
          toks[i + 2U].kind == LuaTokKind::symbol && toks[i + 2U].text == "(") {
        const auto p = parse_call_args(toks, i + 2U);
        if (p.has_value()) {
          if (!p->arg_ranges.empty()) {
            ctx_param = slice_source_for_tokens(src, toks, p->arg_ranges[0].first,
                                                p->arg_ranges[0].second);
          }
          header_span = ByteSpan{toks[i].start, toks[p->close_tok_idx].end};
          header_replacement = "local function " + compiled_fn_name + "(" + ctx_param +
                               ", __arc_layers)";
          break;
        }
      }
      // Form 2: `semantic_function = function ( <params> )`
      if (toks[i].kind == LuaTokKind::ident && toks[i].text == "semantic_function" &&
          i + 4U < toks.size() && toks[i + 1U].kind == LuaTokKind::symbol &&
          toks[i + 1U].text == "=" && toks[i + 2U].kind == LuaTokKind::ident &&
          toks[i + 2U].text == "function" && toks[i + 3U].kind == LuaTokKind::symbol &&
          toks[i + 3U].text == "(") {
        const auto p = parse_call_args(toks, i + 3U);
        if (p.has_value()) {
          if (!p->arg_ranges.empty()) {
            ctx_param = slice_source_for_tokens(src, toks, p->arg_ranges[0].first,
                                                p->arg_ranges[0].second);
          }
          header_span = ByteSpan{toks[i].start, toks[p->close_tok_idx].end};
          header_replacement = "local " + compiled_fn_name + " = function(" +
                               ctx_param + ", __arc_layers)";
          break;
        }
      }
    }
    if (!header_span.has_value()) {
      return fail<ArcCompiledModule>(ErrorCode::invalid_range, ArcError::invalid_lua);
    }

    // Recursive top-down span rewriter: handles arbitrarily nested arc.do_ / arc.load
    // expressions without overlapping byte-offset corruption!
    std::function<Result<std::string>(ByteSpan)> rewrite_span =
        [&](ByteSpan span) -> Result<std::string> {
      std::string result;
      std::size_t cursor = span.start;

      for (std::size_t i = 0U; i < toks.size(); ++i) {
        if (toks[i].start < cursor) {
          continue;
        }
        if (toks[i].start >= span.end) {
          break;
        }

        // Emit header replacement when reaching the semantic_function header span.
        if (header_span.has_value() && toks[i].start == header_span->start &&
            header_span->end <= span.end) {
          result.append(src, cursor, header_span->start - cursor);
          result += header_replacement;
          cursor = header_span->end;
          continue;
        }

        // Check for `arc.do_(...)` or `arc.load(...)`
        if (toks[i].kind == LuaTokKind::ident && toks[i].text == "arc" &&
            i + 3U < toks.size() && toks[i + 1U].kind == LuaTokKind::symbol &&
            toks[i + 1U].text == "." && toks[i + 2U].kind == LuaTokKind::ident &&
            toks[i + 3U].kind == LuaTokKind::symbol && toks[i + 3U].text == "(") {
          const std::string &prim = toks[i + 2U].text;
          if (prim != "do_" && prim != "load") {
            continue;
          }
          const auto parsed = parse_call_args(toks, i + 3U);
          if (!parsed.has_value()) {
            continue;
          }
          const std::size_t call_start = toks[i].start;
          const std::size_t call_end = toks[parsed->close_tok_idx].end;
          if (call_end > span.end) {
            continue;
          }

          result.append(src, cursor, call_start - cursor);

          if (prim == "do_") {
            const auto callee_it = do_callee_by_offset.find(call_start);
            if (callee_it == do_callee_by_offset.end()) {
              return fail<std::string>(ErrorCode::invalid_range,
                                       ArcError::compile_unresolved_call);
            }
            const std::string &callee_id = callee_it->second;
            const std::string &callee_lua_fn = lua_fn_names.at(callee_id);

            std::string target_code = ctx_param;
            if (!parsed->arg_ranges.empty()) {
              const auto &r0 = parsed->arg_ranges[0];
              const auto rw = rewrite_span(
                  ByteSpan{toks[r0.first].start, toks[r0.second - 1U].end});
              if (!rw.has_value()) {
                return rw;
              }
              target_code = std::string{trim_sv(rw.value())};
            }

            std::string payloads_code = "{}";
            if (parsed->arg_ranges.size() >= 3U) {
              const auto &r2 = parsed->arg_ranges[2];
              const auto rw = rewrite_span(
                  ByteSpan{toks[r2.first].start, toks[r2.second - 1U].end});
              if (!rw.has_value()) {
                return rw;
              }
              payloads_code = std::string{trim_sv(rw.value())};
            }

            result += "__arc_call(" + callee_lua_fn + ", " + target_code +
                      ", __arc_layers, " + quote_lua_string(callee_id) + ", " +
                      payloads_code + ")";
            ++resolved_do_total;
          } else {
            // prim == "load"
            if (parsed->arg_ranges.size() < 2U) {
              return fail<std::string>(ErrorCode::invalid_range,
                                       ArcError::compile_unresolved_call);
            }
            const auto query_lit = eval_string_literal_tokens(
                toks, parsed->arg_ranges[1].first, parsed->arg_ranges[1].second);
            if (!query_lit.has_value() || query_lit->empty()) {
              return fail<std::string>(ErrorCode::invalid_range,
                                       ArcError::compile_unresolved_call);
            }
            std::string dtype_arg = "nil";
            if (parsed->arg_ranges.size() >= 3U) {
              const auto dlit = eval_string_literal_tokens(
                  toks, parsed->arg_ranges[2].first, parsed->arg_ranges[2].second);
              if (dlit.has_value()) {
                dtype_arg = quote_lua_string(*dlit);
              }
            }

            const auto &r0 = parsed->arg_ranges[0];
            const auto rw_target =
                rewrite_span(ByteSpan{toks[r0.first].start, toks[r0.second - 1U].end});
            if (!rw_target.has_value()) {
              return rw_target;
            }
            const std::string target_expr{trim_sv(rw_target.value())};

            if (target_expr == ctx_param) {
              const auto keys =
                  resolve_key_candidates(QueryText{*query_lit}, ctx_key_pool);
              result += "__arc_ctx_load(__arc_layers, " + format_lua_key_list(keys) +
                        ", " + dtype_arg + ")";
            } else {
              const auto keys =
                  resolve_key_candidates(QueryText{*query_lit}, dict_key_pool);
              result += "__arc_exact_load(" + target_expr + ", " +
                        format_lua_key_list(keys) + ", " + dtype_arg + ")";
            }
            ++resolved_load_total;
          }

          cursor = call_end;
          i = parsed->close_tok_idx;
        }
      }

      if (cursor < span.end) {
        result.append(src, cursor, span.end - cursor);
      }
      return Result<std::string>::success(std::move(result));
    };

    const auto rewritten = rewrite_span(ByteSpan{0U, src.size()});
    if (!rewritten.has_value()) {
      return Result<ArcCompiledModule>::failure(rewritten.error());
    }

    out << "-- Compiled function: " << fn_id << "\n";
    out << rewritten.value() << "\n\n";
  }

  const std::string &root_lua_fn = lua_fn_names.at(std::string{root_function_id});
  out << "function semantic_function(ctx, __arc_root_payloads, __arc_frame)\n";
  out << "  local __arc_prev_frame = __arc_frame_runner\n";
  out << "  __arc_frame_runner = __arc_frame\n";
  out << "  local __arc_layers = { __arc_root_payloads or {} }\n";
  out << "  local ok, res = pcall(" << root_lua_fn << ", ctx, __arc_layers)\n";
  out << "  __arc_frame_runner = __arc_prev_frame\n";
  out << "  if not ok then error(res, 0) end\n";
  out << "  return res\n";
  out << "end\n";

  ArcCompiledModule mod{};
  mod.root_function_id = std::string{root_function_id};
  mod.lua_source = out.str();
  mod.included_function_ids = std::move(post_order);
  mod.resolved_do_sites = resolved_do_total;
  mod.resolved_load_sites = resolved_load_total;

  // Validate compiled Lua 5.5.1 syntax before persisting or returning!
  const auto syn = check_lua_syntax_text_only(mod.lua_source);
  if (!syn.has_value()) {
    return fail<ArcCompiledModule>(ErrorCode::invalid_range, ArcError::invalid_lua);
  }

  if (save_to_registry) {
    const auto saved =
        impl_->save_compiled_lua(FunctionIdRef{root_function_id}, mod.lua_source);
    if (!saved.has_value()) {
      return Result<ArcCompiledModule>::failure(saved.error());
    }
  }

  return Result<ArcCompiledModule>::success(std::move(mod));
}

// ---------------------------------------------------------------------------
// Section 3.1 / 3.2 Perturbation & Equivalence Verification
// ---------------------------------------------------------------------------

Result<ArcVerificationReport>
ArcRegistry::verify_candidate(const std::vector<ArcVerificationCase> &cases,
                              const ArcRuntimeCallbacks &callbacks,
                              const ArcVerifyOptions &options) {
  if (!impl_ || impl_->conn.db == nullptr) {
    return fail<ArcVerificationReport>(ErrorCode::stale_handle,
                                       ArcError::sqlite_failed);
  }

  ArcVerificationReport report{};
  report.total_cases = cases.size();
  report.case_results.reserve(cases.size());

  std::vector<std::int64_t> latencies;
  latencies.reserve(cases.size());

  auto bump_mode = [&](ArcPerturbationMode mode, bool passed) {
    ArcModeSummary *target = &report.golden;
    switch (mode) {
    case ArcPerturbationMode::golden:
      target = &report.golden;
      break;
    case ArcPerturbationMode::phrasal:
      target = &report.phrasal;
      break;
    case ArcPerturbationMode::parametric:
      target = &report.parametric;
      break;
    case ArcPerturbationMode::combined:
      target = &report.combined;
      break;
    }
    ++target->total;
    if (passed) {
      ++target->passed;
    }
  };

  for (const auto &vc : cases) {
    const auto res =
        serve(vc.raw_request, vc.explicit_payloads, callbacks, options.limits);
    ArcCaseResult cr{};
    cr.case_id = vc.case_id;
    cr.mode = vc.mode;

    report.total_source_cost_usd += vc.source_cost_usd;
    report.total_target_cost_usd += vc.target_cost_usd;

    if (!res.has_value()) {
      cr.passed = false;
      cr.detail = std::string{"serve failed: "} +
                  std::string{arc_error_name(arc_error_of(res.error()))};
      bump_mode(vc.mode, false);
      report.case_results.push_back(std::move(cr));
      continue;
    }

    const auto &exec = res.value();
    cr.cache_hit = exec.cache_hit;
    cr.fell_back_to_source = exec.fell_back_to_source;
    cr.duration_ns = exec.duration_ns;
    latencies.push_back(exec.duration_ns);

    if (options.require_cache_hit && (!exec.cache_hit || exec.fell_back_to_source)) {
      cr.passed = false;
      cr.detail = exec.fell_back_to_source
                      ? ("fell back to source: " + exec.fallback_reason)
                      : "cache miss";
      bump_mode(vc.mode, false);
      report.case_results.push_back(std::move(cr));
      continue;
    }

    Value actual_cmp = exec.output;
    Value expected_cmp = vc.expected_output;
    if (vc.output_key.has_value()) {
      const Value *av = exec.output.find(*vc.output_key);
      if (av == nullptr) {
        cr.passed = false;
        cr.detail = "missing output_key '" + *vc.output_key + "'";
        bump_mode(vc.mode, false);
        report.case_results.push_back(std::move(cr));
        continue;
      }
      actual_cmp = *av;
      if (const Value *ev = vc.expected_output.find(*vc.output_key)) {
        expected_cmp = *ev;
      }
    }

    bool matched = false;
    if (options.judge) {
      const auto jr = options.judge(actual_cmp, expected_cmp, vc.case_id);
      if (jr.has_value()) {
        matched = jr.value();
      } else {
        cr.detail = "judge callback failed";
      }
    } else {
      matched = values_equivalent(actual_cmp, expected_cmp,
                                  CompareOptions{vc.numeric_tolerance});
      if (!matched) {
        cr.detail = "output mismatch";
      }
    }

    cr.passed = matched;
    if (matched) {
      ++report.passed_cases;
      cr.detail = "ok";
    }
    bump_mode(vc.mode, matched);
    report.case_results.push_back(std::move(cr));
  }

  auto finalize_mode = [](ArcModeSummary &m) {
    m.pass_rate = m.total > 0U
                      ? static_cast<double>(m.passed) / static_cast<double>(m.total)
                      : 0.0;
  };
  finalize_mode(report.golden);
  finalize_mode(report.phrasal);
  finalize_mode(report.parametric);
  finalize_mode(report.combined);

  report.overall_pass_rate = report.total_cases > 0U
                                 ? static_cast<double>(report.passed_cases) /
                                       static_cast<double>(report.total_cases)
                                 : 0.0;

  if (!latencies.empty()) {
    std::sort(latencies.begin(), latencies.end());
    report.min_latency_ns = latencies.front();
    report.median_latency_ns = latencies[latencies.size() / 2U];
    report.max_latency_ns = latencies.back();
  }

  if (report.total_source_cost_usd > 0.0) {
    report.cost_ratio = report.total_target_cost_usd / report.total_source_cost_usd;
  }
  if (report.total_target_cost_usd > 0.0) {
    report.savings_multiplier =
        report.total_source_cost_usd / report.total_target_cost_usd;
  }

  return Result<ArcVerificationReport>::success(std::move(report));
}

} // namespace blackbird::arc
