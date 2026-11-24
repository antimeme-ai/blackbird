#include "blackbird/cpu_arc_distiller.hpp"

#include "blackbird/json.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cmath>
#include <queue>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace blackbird::arc {
namespace {

using SteadyClock = std::chrono::steady_clock;

template <typename T>
Result<T> fail_distill(ErrorCode code, ArcDistillerError detail) noexcept {
  return Result<T>::failure(Error{code, static_cast<std::int64_t>(detail)});
}

// Strong wrappers to prevent swappable-parameter diagnostics.
struct LeftTemplate {
  std::string_view value;
};

struct RightTemplate {
  std::string_view value;
};

struct TokenLeft {
  std::string_view value;
};

struct TokenRight {
  std::string_view value;
};

struct ExpectedText {
  std::string_view value;
};

struct ContextNote {
  std::string_view value;
};

struct PhasePrompt {
  std::string_view value;
};

struct PhaseTag {
  std::string_view value;
};

struct NumericTol {
  double value;
};

struct SuffixTag {
  std::string_view value;
};

struct SaltText {
  std::string_view value;
};

std::string_view trim_sv(std::string_view sv) noexcept {
  while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())) != 0) {
    sv.remove_prefix(1U);
  }
  while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())) != 0) {
    sv.remove_suffix(1U);
  }
  return sv;
}

std::string ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return out;
}

std::string normalize_whitespace_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  bool prev_space = true;
  for (const char ch : text) {
    const auto u = static_cast<unsigned char>(ch);
    if (std::isspace(u) != 0) {
      if (!prev_space) {
        out.push_back(' ');
        prev_space = true;
      }
    } else {
      out.push_back(static_cast<char>(std::tolower(u)));
      prev_space = false;
    }
  }
  if (!out.empty() && out.back() == ' ') {
    out.pop_back();
  }
  return out;
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

bool tokens_soft_match(TokenLeft lhs, TokenRight rhs) noexcept {
  const std::string_view a = lhs.value;
  const std::string_view b = rhs.value;
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

// Normalizes concrete numeric literals and quoted strings into template placeholders
// so equirational queries cluster cleanly by structural reasoning template.
std::string normalize_query_template(std::string_view query) {
  std::string out;
  out.reserve(query.size());
  std::size_t i = 0U;
  const std::size_t n = query.size();
  bool prev_space = true;

  auto emit_space = [&]() {
    if (!prev_space && !out.empty()) {
      out.push_back(' ');
      prev_space = true;
    }
  };

  while (i < n) {
    const char ch = query[i];
    const auto u = static_cast<unsigned char>(ch);

    if (std::isspace(u) != 0) {
      emit_space();
      ++i;
      continue;
    }

    // Quoted string literal -> <str>
    if (ch == '"' || ch == '\'') {
      const char quote = ch;
      std::size_t j = i + 1U;
      while (j < n && query[j] != quote) {
        if (query[j] == '\\' && j + 1U < n) {
          j += 2U;
        } else {
          ++j;
        }
      }
      if (j < n && query[j] == quote) {
        emit_space();
        out += "<str>";
        prev_space = false;
        i = j + 1U;
        continue;
      }
    }

    // Numeric literal (optionally signed at token start, decimal, optional exponent)
    const bool starts_digit = std::isdigit(u) != 0;
    const bool starts_signed_digit =
        (ch == '-' || ch == '+') && prev_space && (i + 1U < n) &&
        std::isdigit(static_cast<unsigned char>(query[i + 1U])) != 0;
    if (starts_digit || starts_signed_digit) {
      std::size_t j = i + (starts_signed_digit ? 1U : 0U);
      while (j < n && std::isdigit(static_cast<unsigned char>(query[j])) != 0) {
        ++j;
      }
      if (j < n && query[j] == '.' && j + 1U < n &&
          std::isdigit(static_cast<unsigned char>(query[j + 1U])) != 0) {
        ++j;
        while (j < n && std::isdigit(static_cast<unsigned char>(query[j])) != 0) {
          ++j;
        }
      }
      if (j < n && (query[j] == 'e' || query[j] == 'E')) {
        std::size_t k = j + 1U;
        if (k < n && (query[k] == '+' || query[k] == '-')) {
          ++k;
        }
        if (k < n && std::isdigit(static_cast<unsigned char>(query[k])) != 0) {
          while (k < n && std::isdigit(static_cast<unsigned char>(query[k])) != 0) {
            ++k;
          }
          j = k;
        }
      }
      emit_space();
      out += "<num>";
      prev_space = false;
      i = j;
      continue;
    }

    if (std::isalnum(u) != 0 || ch == '_' || ch == '<' || ch == '>') {
      out.push_back(static_cast<char>(std::tolower(u)));
      prev_space = false;
    } else {
      emit_space();
    }
    ++i;
  }

  while (!out.empty() && out.back() == ' ') {
    out.pop_back();
  }
  return out;
}

std::vector<std::string> tokenize_template(std::string_view tmpl) {
  std::vector<std::string> raw;
  std::string cur;
  for (const char ch : tmpl) {
    const auto u = static_cast<unsigned char>(ch);
    if (std::isalnum(u) != 0 || ch == '<' || ch == '>' || ch == '_') {
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

double template_similarity(LeftTemplate lhs, RightTemplate rhs) {
  const std::string_view a = trim_sv(lhs.value);
  const std::string_view b = trim_sv(rhs.value);
  if (a.empty() || b.empty()) {
    return 0.0;
  }
  if (a == b) {
    return 1.0;
  }
  const auto a_toks = tokenize_template(a);
  const auto b_toks = tokenize_template(b);
  if (a_toks.empty() || b_toks.empty()) {
    return 0.0;
  }

  std::set<std::string> a_set(a_toks.begin(), a_toks.end());
  std::set<std::string> b_set(b_toks.begin(), b_toks.end());

  std::size_t matched = 0U;
  for (const auto &at : a_set) {
    if (b_set.contains(at)) {
      ++matched;
      continue;
    }
    for (const auto &bt : b_set) {
      if (tokens_soft_match(TokenLeft{at}, TokenRight{bt})) {
        ++matched;
        break;
      }
    }
  }
  if (matched == 0U) {
    return 0.0;
  }
  const std::size_t union_sz = a_set.size() + b_set.size() - matched;
  const double jaccard =
      union_sz > 0U ? static_cast<double>(matched) / static_cast<double>(union_sz)
                    : 0.0;
  const double dice = (2.0 * static_cast<double>(matched)) /
                      static_cast<double>(a_set.size() + b_set.size());
  return std::clamp(0.55 * jaccard + 0.45 * dice, 0.0, 1.0);
}

std::string value_to_display_string(const Value &val) {
  if (const auto *s = std::get_if<std::string>(&val.value())) {
    return *s;
  }
  if (const auto *n = std::get_if<Number>(&val.value())) {
    return n->text();
  }
  if (const auto *b = std::get_if<bool>(&val.value())) {
    return *b ? "true" : "false";
  }
  if (std::holds_alternative<std::nullptr_t>(val.value())) {
    return {};
  }
  const auto dumped = dump_json(val);
  if (dumped.has_value()) {
    return dumped.value();
  }
  return {};
}

double sanitize_non_negative_cost(double value) noexcept {
  return (std::isfinite(value) && value > 0.0) ? value : 0.0;
}

double sanitize_similarity_threshold(double value) noexcept {
  return std::isfinite(value) ? std::clamp(value, 0.0, 1.0) : 0.45;
}

double sanitize_tolerance(double value) noexcept {
  return (std::isfinite(value) && value >= 0.0) ? value : 1e-3;
}

std::optional<double> value_as_double(const Value &val) noexcept {
  if (const auto *n = std::get_if<Number>(&val.value())) {
    if (const auto *d = std::get_if<double>(&n->storage())) {
      return *d;
    }
    if (const auto *i = std::get_if<std::int64_t>(&n->storage())) {
      return static_cast<double>(*i);
    }
    if (const auto *u = std::get_if<std::uint64_t>(&n->storage())) {
      return static_cast<double>(*u);
    }
    double parsed = 0.0;
    if (parse_decimal_double(n->text(), parsed) == std::errc{}) {
      return parsed;
    }
  }
  if (const auto *s = std::get_if<std::string>(&val.value())) {
    double parsed = 0.0;
    if (parse_decimal_double(trim_sv(*s), parsed) == std::errc{}) {
      return parsed;
    }
  }
  return std::nullopt;
}

std::optional<std::uint64_t> value_as_u64(const Value &val) noexcept {
  const auto *n = std::get_if<Number>(&val.value());
  if (n == nullptr) {
    return std::nullopt;
  }
  if (const auto *u = std::get_if<std::uint64_t>(&n->storage())) {
    return *u;
  }
  if (const auto *i = std::get_if<std::int64_t>(&n->storage())) {
    if (*i >= 0) {
      return static_cast<std::uint64_t>(*i);
    }
    return std::nullopt;
  }
  const std::string text = n->text();
  if (text.empty()) {
    return std::nullopt;
  }
  std::uint64_t parsed = 0U;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (res.ec == std::errc{} && res.ptr == text.data() + text.size()) {
    return parsed;
  }
  return std::nullopt;
}

std::optional<std::string> get_optional_string(const Value &obj, std::string_view key) {
  const Value *v = obj.find(key);
  if (v == nullptr) {
    return std::nullopt;
  }
  if (const auto *s = std::get_if<std::string>(&v->value())) {
    return *s;
  }
  return std::nullopt;
}

std::optional<bool> get_optional_bool(const Value &obj, std::string_view key) {
  const Value *v = obj.find(key);
  if (v == nullptr) {
    return std::nullopt;
  }
  if (const auto *b = std::get_if<bool>(&v->value())) {
    return *b;
  }
  return std::nullopt;
}

std::vector<std::string> get_string_array(const Value &obj, std::string_view key) {
  std::vector<std::string> out;
  const Value *v = obj.find(key);
  if (v == nullptr) {
    return out;
  }
  const auto *arr = std::get_if<Value::Array>(&v->value());
  if (arr == nullptr) {
    return out;
  }
  out.reserve(arr->size());
  for (const auto &elem : *arr) {
    if (const auto *s = std::get_if<std::string>(&elem.value())) {
      if (!s->empty()) {
        out.push_back(*s);
      }
    }
  }
  return out;
}

std::string extract_item_text(const Value &item) {
  const Value *content = item.find("content");
  if (content != nullptr) {
    if (const auto *s = std::get_if<std::string>(&content->value())) {
      return *s;
    }
    if (const auto *arr = std::get_if<Value::Array>(&content->value())) {
      std::string out;
      for (const auto &part : *arr) {
        if (const auto *t = part.find("text");
            t != nullptr && std::holds_alternative<std::string>(t->value())) {
          if (!out.empty()) {
            out += '\n';
          }
          out += t->string();
        }
      }
      if (!out.empty()) {
        return out;
      }
    }
  }
  if (const auto *t = item.find("text");
      t != nullptr && std::holds_alternative<std::string>(t->value())) {
    return t->string();
  }
  if (const auto *sum = item.find("summary"); sum != nullptr) {
    if (const auto *s = std::get_if<std::string>(&sum->value())) {
      return *s;
    }
    if (const auto *arr = std::get_if<Value::Array>(&sum->value())) {
      std::string out;
      for (const auto &part : *arr) {
        if (const auto *ps = std::get_if<std::string>(&part.value())) {
          if (!out.empty()) {
            out += '\n';
          }
          out += *ps;
        } else if (const auto *pt = part.find("text");
                   pt != nullptr && std::holds_alternative<std::string>(pt->value())) {
          if (!out.empty()) {
            out += '\n';
          }
          out += pt->string();
        }
      }
      return out;
    }
  }
  return {};
}

void append_unique_tool(std::vector<std::string> &tools, std::string_view name) {
  if (name.empty()) {
    return;
  }
  for (const auto &existing : tools) {
    if (existing == name) {
      return;
    }
  }
  tools.emplace_back(name);
}

std::string compute_canonical_trace_hash(const ArcSourceTrace &trace) {
  std::string material;
  material.reserve(trace.user_query.size() + trace.source_transcript.size() +
                   trace.final_answer.size() + 32U);
  material += trace.user_query;
  material += "\n---transcript---\n";
  material += trace.source_transcript;
  material += "\n---answer---\n";
  material += trace.final_answer;
  return compute_trace_hash(material);
}

// Appends structured wire items (reasoning, tool calls/outputs, assistant messages)
// into a trace's transcript, tools_used, and final_answer.
void fold_exchange_items(const std::vector<Value> &items, ArcSourceTrace &trace) {
  for (const auto &item : items) {
    if (!std::holds_alternative<Value::Object>(item.value())) {
      continue;
    }
    const auto type = get_optional_string(item, "type");
    if (type.has_value()) {
      if (*type == "function_call") {
        const auto name = get_optional_string(item, "name").value_or("unknown_tool");
        const auto args = get_optional_string(item, "arguments").value_or("{}");
        append_unique_tool(trace.tools_used, name);
        if (!trace.source_transcript.empty()) {
          trace.source_transcript += '\n';
        }
        trace.source_transcript += "[tool_call:" + name + "] " + args;
        continue;
      }
      if (*type == "function_call_output") {
        const Value *out_v = item.find("output");
        const std::string out_text =
            out_v != nullptr ? value_to_display_string(*out_v) : std::string{};
        if (!trace.source_transcript.empty()) {
          trace.source_transcript += '\n';
        }
        trace.source_transcript += "[tool_output] " + out_text;
        continue;
      }
      if (*type == "reasoning") {
        const std::string rtext = extract_item_text(item);
        if (!rtext.empty()) {
          if (!trace.source_transcript.empty()) {
            trace.source_transcript += '\n';
          }
          trace.source_transcript += "[reasoning] " + rtext;
        }
        continue;
      }
    }

    const auto role = get_optional_string(item, "role");
    const std::string text = extract_item_text(item);
    if (text.empty()) {
      continue;
    }
    if (role.has_value() && *role == "assistant") {
      if (!trace.source_transcript.empty()) {
        trace.source_transcript += '\n';
      }
      trace.source_transcript += "[assistant] " + text;
      trace.final_answer = text;
    } else if (!role.has_value()) {
      if (!trace.source_transcript.empty()) {
        trace.source_transcript += '\n';
      }
      trace.source_transcript += text;
      if (trace.final_answer.empty()) {
        trace.final_answer = text;
      }
    }
  }
}

std::string extract_user_text_from_items(const std::vector<Value> &items) {
  std::string out;
  for (const auto &item : items) {
    if (!std::holds_alternative<Value::Object>(item.value())) {
      continue;
    }
    const auto role = get_optional_string(item, "role");
    if (role.has_value() && *role == "user") {
      const std::string text = extract_item_text(item);
      if (!text.empty()) {
        if (!out.empty()) {
          out += '\n';
        }
        out += text;
      }
    }
  }
  return out;
}

std::string_view strip_markdown_code_fence(std::string_view raw) noexcept {
  std::string_view sv = trim_sv(raw);
  if (!sv.starts_with("```")) {
    return sv;
  }
  const std::size_t first_nl = sv.find('\n');
  if (first_nl == std::string_view::npos) {
    return sv;
  }
  sv.remove_prefix(first_nl + 1U);
  sv = trim_sv(sv);
  if (sv.ends_with("```")) {
    sv.remove_suffix(3U);
  }
  return trim_sv(sv);
}

Result<Value> parse_builder_json_object(std::string_view raw) {
  const std::string_view cleaned = strip_markdown_code_fence(raw);
  if (cleaned.empty()) {
    return fail_distill<Value>(ErrorCode::corrupt, ArcDistillerError::parse_failed);
  }
  auto parsed = parse_json(cleaned, ValueLimits{});
  if (!parsed.has_value()) {
    return fail_distill<Value>(ErrorCode::corrupt, ArcDistillerError::parse_failed);
  }
  if (!std::holds_alternative<Value::Object>(parsed.value().value())) {
    return fail_distill<Value>(ErrorCode::corrupt, ArcDistillerError::parse_failed);
  }
  return parsed;
}

bool numbers_close(double lhs, double rhs, NumericTol tol) noexcept {
  if (!std::isfinite(lhs) || !std::isfinite(rhs)) {
    return false;
  }
  const double scale = std::max({1.0, std::fabs(lhs), std::fabs(rhs)});
  return std::fabs(lhs - rhs) <= tol.value * scale;
}

bool values_match_with_tolerance(const Value &actual, const Value &expected,
                                 NumericTol tol) {
  if (actual == expected) {
    return true;
  }
  const auto a_num = value_as_double(actual);
  const auto e_num = value_as_double(expected);
  if (a_num.has_value() && e_num.has_value()) {
    return numbers_close(*a_num, *e_num, tol);
  }
  if (const auto *a_str = std::get_if<std::string>(&actual.value())) {
    if (const auto *e_str = std::get_if<std::string>(&expected.value())) {
      return normalize_whitespace_lower(*a_str) == normalize_whitespace_lower(*e_str);
    }
  }
  if (const auto *a_arr = std::get_if<Value::Array>(&actual.value())) {
    if (const auto *e_arr = std::get_if<Value::Array>(&expected.value())) {
      if (a_arr->size() != e_arr->size()) {
        return false;
      }
      for (std::size_t i = 0U; i < a_arr->size(); ++i) {
        if (!values_match_with_tolerance((*a_arr)[i], (*e_arr)[i], tol)) {
          return false;
        }
      }
      return true;
    }
  }
  if (const auto *a_obj = std::get_if<Value::Object>(&actual.value())) {
    if (const auto *e_obj = std::get_if<Value::Object>(&expected.value())) {
      for (const auto &[ek, ev] : *e_obj) {
        const Value *av = actual.find(ek);
        if (av == nullptr || !values_match_with_tolerance(*av, ev, tol)) {
          return false;
        }
      }
      return !e_obj->empty() || a_obj->empty();
    }
  }
  return false;
}

// Deterministic fallback judge used when callbacks.judge is unset.
ArcJudgeVerdict run_deterministic_judge(ExpectedText expected, const Value &actual,
                                        NumericTol tol) {
  const std::string_view exp_trimmed = trim_sv(expected.value);
  if (exp_trimmed.empty()) {
    return ArcJudgeVerdict{true, "ok (no expected constraint)"};
  }

  // 1. Try parsing expected as structured JSON value first.
  const auto parsed_exp = parse_json(exp_trimmed, ValueLimits{});
  if (parsed_exp.has_value()) {
    if (values_match_with_tolerance(actual, parsed_exp.value(), tol)) {
      return ArcJudgeVerdict{true, "ok (structured match)"};
    }
    if (const auto *obj = std::get_if<Value::Object>(&actual.value())) {
      for (const auto &[_, v] : *obj) {
        if (values_match_with_tolerance(v, parsed_exp.value(), tol)) {
          return ArcJudgeVerdict{true, "ok (matched output field)"};
        }
      }
    }
  }

  // 2. Numeric tolerance check if expected is a number.
  double exp_num = 0.0;
  if (parse_decimal_double(exp_trimmed, exp_num) == std::errc{}) {
    if (const auto a_num = value_as_double(actual);
        a_num.has_value() && numbers_close(*a_num, exp_num, tol)) {
      return ArcJudgeVerdict{true, "ok (numeric match)"};
    }
    if (const auto *obj = std::get_if<Value::Object>(&actual.value())) {
      for (const auto &[_, v] : *obj) {
        if (const auto field_num = value_as_double(v);
            field_num.has_value() && numbers_close(*field_num, exp_num, tol)) {
          return ArcJudgeVerdict{true, "ok (numeric field match)"};
        }
      }
    }
  }

  // 3. Normalized string equality / field value match.
  const std::string exp_norm = normalize_whitespace_lower(exp_trimmed);
  const std::string act_disp =
      normalize_whitespace_lower(value_to_display_string(actual));
  if (act_disp == exp_norm) {
    return ArcJudgeVerdict{true, "ok (normalized string match)"};
  }
  if (const auto *obj = std::get_if<Value::Object>(&actual.value())) {
    for (const auto &[_, v] : *obj) {
      const std::string v_norm = normalize_whitespace_lower(value_to_display_string(v));
      if (!v_norm.empty() && v_norm == exp_norm) {
        return ArcJudgeVerdict{true, "ok (normalized field match)"};
      }
    }
  }

  return ArcJudgeVerdict{false, "deterministic judge mismatch: expected '" +
                                    std::string{exp_trimmed} +
                                    "', actual=" + value_to_display_string(actual)};
}

Result<ArcJudgeVerdict> evaluate_judge(const ArcDistillJudgeCallback &judge_cb,
                                       ExpectedText expected, const Value &actual,
                                       ContextNote context_note, NumericTol tol) {
  if (judge_cb) {
    auto res = judge_cb(expected.value, actual, context_note.value);
    if (!res.has_value()) {
      return fail_distill<ArcJudgeVerdict>(ErrorCode::unsupported,
                                           ArcDistillerError::judge_unavailable);
    }
    return res;
  }
  return Result<ArcJudgeVerdict>::success(
      run_deterministic_judge(expected, actual, tol));
}

ArcParamSpec parse_param_spec(const Value &item) {
  ArcParamSpec spec{};
  spec.name = get_optional_string(item, "name").value_or("");
  spec.description = get_optional_string(item, "description").value_or("");
  if (spec.name.empty()) {
    spec.name = spec.description;
  }
  if (spec.description.empty()) {
    spec.description = spec.name;
  }
  spec.d_type = get_optional_string(item, "d_type").value_or("any");
  if (spec.d_type.empty()) {
    spec.d_type = "any";
  }
  spec.example = get_optional_string(item, "example").value_or("");
  spec.required = get_optional_bool(item, "required").value_or(true);
  return spec;
}

Value build_root_payloads_from_recognized(
    const std::vector<ArcRecognizedParam> &params) {
  Value::Object obj;
  obj.reserve(params.size());
  for (const auto &p : params) {
    const std::string key = !p.description.empty() ? p.description : p.name;
    if (key.empty()) {
      continue;
    }
    if (!std::holds_alternative<std::nullptr_t>(p.original_value.value())) {
      obj.emplace_back(key, p.original_value);
    } else if (!p.example.empty()) {
      obj.emplace_back(key, Value{p.example});
    } else {
      obj.emplace_back(key, Value{""});
    }
  }
  return Value::object(std::move(obj));
}

Value coerce_example_value(const ArcParamSpec &spec) {
  const std::string dt = ascii_lower(spec.d_type);
  const std::string_view ex = trim_sv(spec.example);
  if (dt == "int" || dt == "float" || dt == "number" || dt == "bool" || dt == "list" ||
      dt == "dict" || dt == "object" || dt == "set") {
    if (!ex.empty()) {
      const auto parsed = parse_json(ex, ValueLimits{});
      if (parsed.has_value()) {
        return parsed.value();
      }
    }
  }
  return Value{spec.example};
}

Value synthesize_node_test_payloads(const ArcPlanNode &node,
                                    const std::vector<ArcRecognizedParam> &recognized,
                                    const Value &root_payloads) {
  if (const auto *tp = std::get_if<Value::Object>(&node.test_payloads.value());
      tp != nullptr && !tp->empty()) {
    return node.test_payloads;
  }
  if (node.is_root) {
    return root_payloads;
  }
  Value::Object obj;
  for (const auto &p : node.params) {
    const std::string key = !p.description.empty() ? p.description : p.name;
    if (key.empty()) {
      continue;
    }
    bool found = false;
    for (const auto &rp : recognized) {
      if ((!p.name.empty() && ascii_lower(p.name) == ascii_lower(rp.name)) ||
          (!p.description.empty() &&
           ascii_lower(p.description) == ascii_lower(rp.description))) {
        if (!std::holds_alternative<std::nullptr_t>(rp.original_value.value())) {
          obj.emplace_back(key, rp.original_value);
          found = true;
          break;
        }
      }
    }
    if (!found) {
      obj.emplace_back(key, coerce_example_value(p));
    }
  }
  return Value::object(std::move(obj));
}

std::string make_bounded_entry_id(std::string_view root_id, SuffixTag suffix,
                                  SaltText salt) {
  const std::string hash8 = compute_trace_hash(salt.value).substr(0U, 8U);
  std::string candidate =
      std::string{root_id} + "_" + std::string{suffix.value} + "_" + hash8;
  if (candidate.size() <= kMaxArcIdLength && valid_arc_id(candidate)) {
    return candidate;
  }
  return "ep_" + compute_trace_hash(candidate).substr(0U, 32U);
}

std::string build_json_prompt(const Value &payload) {
  const auto dumped = dump_json(payload);
  return dumped.has_value() ? dumped.value() : std::string{"{}"};
}

Value params_to_json(const std::vector<ArcParamSpec> &params) {
  Value::Array arr;
  arr.reserve(params.size());
  for (const auto &p : params) {
    arr.push_back(Value::object({
        {"name", Value{p.name}},
        {"description", Value{p.description}},
        {"d_type", Value{p.d_type}},
        {"example", Value{p.example}},
        {"required", Value{p.required}},
    }));
  }
  return Value{std::move(arr)};
}

Value strings_to_json(const std::vector<std::string> &items) {
  Value::Array arr;
  arr.reserve(items.size());
  for (const auto &s : items) {
    arr.emplace_back(s);
  }
  return Value{std::move(arr)};
}

Result<Value> call_builder_json(const ArcBuilderCallback &builder, PhasePrompt prompt,
                                PhaseTag phase) {
  auto raw = builder(prompt.value, phase.value);
  if (!raw.has_value()) {
    return fail_distill<Value>(ErrorCode::provider_transport,
                               ArcDistillerError::phase_failed);
  }
  return parse_builder_json_object(raw.value());
}

Result<std::vector<std::string>>
topological_sort_plan(const std::vector<ArcPlanNode> &nodes,
                      const ArcRegistry &existing_registry) {
  std::unordered_map<std::string, std::size_t> idx_by_id;
  idx_by_id.reserve(nodes.size());
  for (std::size_t i = 0U; i < nodes.size(); ++i) {
    if (!valid_arc_id(nodes[i].id) || trim_sv(nodes[i].description).empty()) {
      return fail_distill<std::vector<std::string>>(
          ErrorCode::invalid_range, ArcDistillerError::validation_failed);
    }
    if (!idx_by_id.emplace(nodes[i].id, i).second) {
      return fail_distill<std::vector<std::string>>(
          ErrorCode::invalid_range, ArcDistillerError::validation_failed);
    }
  }

  std::size_t root_count = 0U;
  for (const auto &n : nodes) {
    if (n.is_root) {
      ++root_count;
    }
  }
  if (root_count != 1U) {
    return fail_distill<std::vector<std::string>>(ErrorCode::invalid_range,
                                                  ArcDistillerError::validation_failed);
  }

  // Edge direction: dependency -> dependent (bottom-up: dependencies first, root last).
  std::vector<std::vector<std::size_t>> dependents(nodes.size());
  std::vector<std::size_t> in_degree(nodes.size(), 0U);
  for (std::size_t i = 0U; i < nodes.size(); ++i) {
    std::unordered_set<std::string> seen_deps;
    for (const auto &dep_id : nodes[i].depends_on) {
      if (!seen_deps.insert(dep_id).second) {
        continue;
      }
      if (dep_id == nodes[i].id) {
        return fail_distill<std::vector<std::string>>(
            ErrorCode::invalid_range, ArcDistillerError::validation_failed);
      }
      const auto it = idx_by_id.find(dep_id);
      if (it != idx_by_id.end()) {
        dependents[it->second].push_back(i);
        ++in_degree[i];
      } else {
        // Allow referencing an already-registered function in the registry.
        const auto existing = existing_registry.get_function(dep_id);
        if (!existing.has_value()) {
          return fail_distill<std::vector<std::string>>(
              ErrorCode::invalid_range, ArcDistillerError::validation_failed);
        }
      }
    }
  }

  // Deterministic Kahn's algorithm ordered by original plan index.
  std::priority_queue<std::size_t, std::vector<std::size_t>, std::greater<>> ready;
  for (std::size_t i = 0U; i < nodes.size(); ++i) {
    if (in_degree[i] == 0U) {
      ready.push(i);
    }
  }

  std::vector<std::string> order;
  order.reserve(nodes.size());
  while (!ready.empty()) {
    const std::size_t cur = ready.top();
    ready.pop();
    order.push_back(nodes[cur].id);
    for (const std::size_t next : dependents[cur]) {
      --in_degree[next];
      if (in_degree[next] == 0U) {
        ready.push(next);
      }
    }
  }

  if (order.size() != nodes.size()) {
    return fail_distill<std::vector<std::string>>(ErrorCode::invalid_range,
                                                  ArcDistillerError::validation_failed);
  }
  return Result<std::vector<std::string>>::success(std::move(order));
}

Result<Value> extract_params_via_target_lm(const ArcLmCallback &target_lm,
                                           const ArcFunctionRecord &root_fn,
                                           std::string_view raw_user_input) {
  if (root_fn.params.empty()) {
    return Result<Value>::success(Value::object({}));
  }

  std::string prompt = "Extract the following parameters as a JSON object from the "
                       "request.\nParameters:\n";
  for (const auto &p : root_fn.params) {
    prompt += "- \"" + (!p.description.empty() ? p.description : p.name) +
              "\" (name=" + p.name + ", type=" + p.d_type + ")\n";
  }
  prompt += "Request: " + std::string{raw_user_input};

  const auto lm_res = target_lm(prompt, "extract_params");
  if (!lm_res.has_value()) {
    return fail_distill<Value>(ErrorCode::provider_transport,
                               ArcDistillerError::extraction_robustness_failed);
  }
  const auto parsed = parse_builder_json_object(lm_res.value());
  if (!parsed.has_value()) {
    return fail_distill<Value>(ErrorCode::corrupt,
                               ArcDistillerError::extraction_robustness_failed);
  }
  const auto *ext_obj = std::get_if<Value::Object>(&parsed.value().value());
  if (ext_obj == nullptr) {
    return fail_distill<Value>(ErrorCode::corrupt,
                               ArcDistillerError::extraction_robustness_failed);
  }

  Value::Object payloads;
  std::unordered_set<std::string> filled_keys;
  for (const auto &[k, v] : *ext_obj) {
    std::string canonical_key = k;
    const std::string k_low = ascii_lower(trim_sv(k));
    for (const auto &p : root_fn.params) {
      const std::string p_name_low = ascii_lower(trim_sv(p.name));
      const std::string p_desc_low = ascii_lower(trim_sv(p.description));
      if ((!p_name_low.empty() && k_low == p_name_low) ||
          (!p_desc_low.empty() && k_low == p_desc_low)) {
        canonical_key = !p.description.empty() ? p.description : p.name;
        break;
      }
    }
    filled_keys.insert(ascii_lower(trim_sv(canonical_key)));
    payloads.emplace_back(std::move(canonical_key), v);
  }

  // Ensure every required root parameter was extracted.
  for (const auto &p : root_fn.params) {
    if (!p.required) {
      continue;
    }
    const std::string canon =
        ascii_lower(trim_sv(!p.description.empty() ? p.description : p.name));
    if (!filled_keys.contains(canon)) {
      return fail_distill<Value>(ErrorCode::invalid_range,
                                 ArcDistillerError::extraction_robustness_failed);
    }
  }

  return Result<Value>::success(Value::object(std::move(payloads)));
}

} // namespace

// ---------------------------------------------------------------------------
// Error & Status Names
// ---------------------------------------------------------------------------

std::string_view arc_distiller_error_name(ArcDistillerError detail) noexcept {
  switch (detail) {
  case ArcDistillerError::none:
    return "none";
  case ArcDistillerError::invalid_trace:
    return "invalid_trace";
  case ArcDistillerError::builder_unavailable:
    return "builder_unavailable";
  case ArcDistillerError::target_unavailable:
    return "target_unavailable";
  case ArcDistillerError::judge_unavailable:
    return "judge_unavailable";
  case ArcDistillerError::phase_failed:
    return "phase_failed";
  case ArcDistillerError::parse_failed:
    return "parse_failed";
  case ArcDistillerError::validation_failed:
    return "validation_failed";
  case ArcDistillerError::extraction_robustness_failed:
    return "extraction_robustness_failed";
  case ArcDistillerError::budget_exceeded:
    return "budget_exceeded";
  case ArcDistillerError::registry_failed:
    return "registry_failed";
  case ArcDistillerError::compile_failed:
    return "compile_failed";
  }
  return "unknown";
}

std::string_view arc_phase_status_name(ArcPhaseStatus status) noexcept {
  switch (status) {
  case ArcPhaseStatus::not_run:
    return "not_run";
  case ArcPhaseStatus::succeeded:
    return "succeeded";
  case ArcPhaseStatus::failed:
    return "failed";
  case ArcPhaseStatus::skipped:
    return "skipped";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Lossless Trace Extraction & Clustering
// ---------------------------------------------------------------------------

std::vector<ArcSourceTrace> extract_distillable_traces(const ContextStore &store) {
  std::vector<ArcSourceTrace> traces;
  const auto &blocks = store.blocks();

  bool has_active_turn = false;
  bool turn_has_open_exchange = false;
  bool turn_has_exchange = false;
  ArcSourceTrace current{};

  auto flush_turn = [&]() {
    if (has_active_turn && turn_has_exchange && !turn_has_open_exchange &&
        !trim_sv(current.user_query).empty() &&
        (!trim_sv(current.source_transcript).empty() ||
         !trim_sv(current.final_answer).empty())) {
      if (trim_sv(current.source_transcript).empty()) {
        current.source_transcript = current.final_answer;
      }
      current.provenance_hash = compute_canonical_trace_hash(current);
      traces.push_back(std::move(current));
    }
    has_active_turn = false;
    turn_has_open_exchange = false;
    turn_has_exchange = false;
    current = ArcSourceTrace{};
  };

  for (const auto &block : blocks) {
    if (block.kind == BlockKind::instruction) {
      const std::string user_text = extract_user_text_from_items(block.items);
      if (trim_sv(user_text).empty()) {
        continue;
      }
      flush_turn();
      has_active_turn = true;
      current.trace_id = "ctx-block-" + std::to_string(block.id);
      current.user_query = user_text;
      current.block_id = block.id;
      continue;
    }

    if (block.kind == BlockKind::exchange && has_active_turn) {
      if (block.open) {
        turn_has_open_exchange = true;
        continue;
      }
      turn_has_exchange = true;
      fold_exchange_items(block.items, current);
    }
  }

  flush_turn();
  return traces;
}

Result<std::vector<ArcSourceTrace>>
extract_distillable_traces_from_jsonl(std::string_view jsonl, std::size_t max_bytes) {
  if (jsonl.size() > max_bytes) {
    return fail_distill<std::vector<ArcSourceTrace>>(
        ErrorCode::capacity, ArcDistillerError::budget_exceeded);
  }

  std::vector<ArcSourceTrace> traces;
  std::size_t pos = 0U;
  std::size_t line_no = 0U;
  ValueLimits parse_limits{};
  parse_limits.bytes = std::min(max_bytes, parse_limits.bytes);

  while (pos < jsonl.size()) {
    const std::size_t nl = jsonl.find('\n', pos);
    const std::string_view raw_line =
        nl == std::string_view::npos ? jsonl.substr(pos) : jsonl.substr(pos, nl - pos);
    pos = nl == std::string_view::npos ? jsonl.size() : nl + 1U;
    ++line_no;

    if (line_no > kDefaultMaxJsonlLines) {
      return fail_distill<std::vector<ArcSourceTrace>>(
          ErrorCode::capacity, ArcDistillerError::budget_exceeded);
    }

    const std::string_view line = trim_sv(raw_line);
    if (line.empty()) {
      continue;
    }

    const auto parsed = parse_json(line, parse_limits);
    if (!parsed.has_value() ||
        !std::holds_alternative<Value::Object>(parsed.value().value())) {
      return fail_distill<std::vector<ArcSourceTrace>>(ErrorCode::corrupt,
                                                       ArcDistillerError::parse_failed);
    }
    const Value &obj = parsed.value();

    ArcSourceTrace trace{};
    trace.trace_id = get_optional_string(obj, "trace_id")
                         .value_or("jsonl-line-" + std::to_string(line_no));

    if (const Value *cost_v = obj.find("source_cost_usd"); cost_v != nullptr) {
      if (const auto c = value_as_double(*cost_v); c.has_value()) {
        trace.source_cost_usd = sanitize_non_negative_cost(*c);
      }
    } else if (const Value *alt_cost = obj.find("cost_usd"); alt_cost != nullptr) {
      if (const auto c = value_as_double(*alt_cost); c.has_value()) {
        trace.source_cost_usd = sanitize_non_negative_cost(*c);
      }
    }

    if (const Value *bid_v = obj.find("block_id"); bid_v != nullptr) {
      if (const auto b = value_as_u64(*bid_v); b.has_value()) {
        trace.block_id = *b;
      }
    }

    // Check message-array form (`messages` or `items`) first, then direct fields.
    const Value *items_v = obj.find("messages");
    if (items_v == nullptr) {
      items_v = obj.find("items");
    }
    if (items_v != nullptr) {
      if (const auto *arr = std::get_if<Value::Array>(&items_v->value())) {
        trace.user_query = extract_user_text_from_items(*arr);
        fold_exchange_items(*arr, trace);
      }
    }

    if (const auto uq = get_optional_string(obj, "user_query"); uq.has_value()) {
      trace.user_query = *uq;
    } else if (const auto q = get_optional_string(obj, "query");
               q.has_value() && trace.user_query.empty()) {
      trace.user_query = *q;
    } else if (const auto in = get_optional_string(obj, "input");
               in.has_value() && trace.user_query.empty()) {
      trace.user_query = *in;
    }

    if (const auto st = get_optional_string(obj, "source_transcript"); st.has_value()) {
      trace.source_transcript = *st;
    } else if (const auto tr = get_optional_string(obj, "transcript");
               tr.has_value() && trace.source_transcript.empty()) {
      trace.source_transcript = *tr;
    }

    if (const auto fa = get_optional_string(obj, "final_answer"); fa.has_value()) {
      trace.final_answer = *fa;
    } else if (const auto ans = get_optional_string(obj, "answer");
               ans.has_value() && trace.final_answer.empty()) {
      trace.final_answer = *ans;
    } else if (const auto out = get_optional_string(obj, "output");
               out.has_value() && trace.final_answer.empty()) {
      trace.final_answer = *out;
    }

    for (const auto &t : get_string_array(obj, "tools_used")) {
      append_unique_tool(trace.tools_used, t);
    }
    for (const auto &t : get_string_array(obj, "tools")) {
      append_unique_tool(trace.tools_used, t);
    }

    if (trim_sv(trace.user_query).empty()) {
      continue;
    }
    if (trim_sv(trace.source_transcript).empty()) {
      trace.source_transcript = trace.final_answer;
    }
    if (trim_sv(trace.source_transcript).empty() &&
        trim_sv(trace.final_answer).empty()) {
      continue;
    }

    if (const auto ph = get_optional_string(obj, "provenance_hash");
        ph.has_value() && ph->size() == 64U) {
      trace.provenance_hash = *ph;
    } else {
      trace.provenance_hash = compute_canonical_trace_hash(trace);
    }

    traces.push_back(std::move(trace));
  }

  return Result<std::vector<ArcSourceTrace>>::success(std::move(traces));
}

std::vector<ArcDistillCandidateCluster>
cluster_recurring_traces(const std::vector<ArcSourceTrace> &traces,
                         double min_similarity) {
  struct WorkingCluster {
    ArcDistillCandidateCluster cluster;
    double similarity_sum = 0.0;
  };

  const double threshold = sanitize_similarity_threshold(min_similarity);
  std::vector<WorkingCluster> working;

  for (const auto &trace : traces) {
    const std::string skeleton = normalize_query_template(trace.user_query);
    if (skeleton.empty()) {
      continue;
    }
    const double safe_cost = sanitize_non_negative_cost(trace.source_cost_usd);

    std::optional<std::size_t> best_idx;
    double best_sim = -1.0;
    for (std::size_t i = 0U; i < working.size(); ++i) {
      const double sim = template_similarity(
          LeftTemplate{skeleton}, RightTemplate{working[i].cluster.canonical_template});
      if (sim >= threshold && sim > best_sim + 1e-12) {
        best_sim = sim;
        best_idx = i;
      }
    }

    if (best_idx.has_value()) {
      auto &wc = working[*best_idx];
      wc.cluster.member_trace_ids.push_back(trace.trace_id);
      ++wc.cluster.occurrence_count;
      wc.cluster.total_source_cost_usd += safe_cost;
      wc.similarity_sum += best_sim;
      wc.cluster.average_similarity =
          wc.similarity_sum / static_cast<double>(wc.cluster.occurrence_count);
    } else {
      WorkingCluster wc{};
      wc.cluster.canonical_template = skeleton;
      wc.cluster.representative_trace_id = trace.trace_id;
      wc.cluster.member_trace_ids.push_back(trace.trace_id);
      wc.cluster.occurrence_count = 1U;
      wc.cluster.total_source_cost_usd = safe_cost;
      wc.cluster.average_similarity = 1.0;
      wc.similarity_sum = 1.0;
      working.push_back(std::move(wc));
    }
  }

  std::vector<ArcDistillCandidateCluster> out;
  out.reserve(working.size());
  for (auto &wc : working) {
    out.push_back(std::move(wc.cluster));
  }

  std::sort(out.begin(), out.end(), [](const auto &a, const auto &b) {
    if (a.occurrence_count != b.occurrence_count) {
      return a.occurrence_count > b.occurrence_count;
    }
    if (std::fabs(a.total_source_cost_usd - b.total_source_cost_usd) > 1e-12) {
      return a.total_source_cost_usd > b.total_source_cost_usd;
    }
    return a.canonical_template < b.canonical_template;
  });

  return out;
}

// ---------------------------------------------------------------------------
// 5-Phase CPU-ARC Construction State Machine (Section 2.2.1)
// ---------------------------------------------------------------------------

Result<ArcDistillReport> ArcDistiller::distill(ArcRegistry &registry,
                                               const ArcSourceTrace &trace,
                                               const ArcDistillerCallbacks &callbacks,
                                               const ArcDistillOptions &options) {
  const auto total_start = SteadyClock::now();

  const double safe_source_cost = sanitize_non_negative_cost(trace.source_cost_usd);
  const double safe_builder_cost = sanitize_non_negative_cost(options.builder_cost_usd);
  const double safe_tolerance = sanitize_tolerance(options.numeric_tolerance);

  ArcDistillReport report{};
  report.trace_id = trace.trace_id;
  report.provenance_hash = trace.provenance_hash.empty()
                               ? compute_canonical_trace_hash(trace)
                               : trace.provenance_hash;
  report.source_cost_usd = safe_source_cost;
  report.builder_cost_usd = safe_builder_cost;

  auto finish_fail = [&](ErrorCode code, ArcDistillerError detail,
                         std::string diag) -> Result<ArcDistillReport> {
    report.succeeded = false;
    report.diagnostic = std::move(diag);
    report.total_duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                   SteadyClock::now() - total_start)
                                   .count();
    last_report_ = report;
    return fail_distill<ArcDistillReport>(code, detail);
  };

  if (trim_sv(trace.user_query).empty() || (trim_sv(trace.source_transcript).empty() &&
                                            trim_sv(trace.final_answer).empty())) {
    return finish_fail(ErrorCode::invalid_range, ArcDistillerError::invalid_trace,
                       "trace requires non-empty user_query and transcript/answer");
  }
  if (!callbacks.builder) {
    return finish_fail(ErrorCode::unsupported, ArcDistillerError::builder_unavailable,
                       "builder callback is required");
  }
  if (options.extraction_round_trips > 0U && !callbacks.target_lm) {
    return finish_fail(
        ErrorCode::unsupported, ArcDistillerError::target_unavailable,
        "target_lm callback is required for Stage 2 extraction round-trips");
  }
  if (options.max_node_retries == 0U || options.max_plan_nodes == 0U) {
    return finish_fail(ErrorCode::invalid_range, ArcDistillerError::validation_failed,
                       "max_node_retries and max_plan_nodes must be >= 1");
  }

  // -------------------------------------------------------------------------
  // Phase 1: Input-Output Isolation
  // -------------------------------------------------------------------------
  {
    const auto p_start = SteadyClock::now();
    ArcPhaseRecord pr{"phase1_io_isolation", ArcPhaseStatus::not_run, 1U, 0, {}};
    const std::string prompt = build_json_prompt(Value::object({
        {"phase", Value{"phase1_io_isolation"}},
        {"trace_id", Value{trace.trace_id}},
        {"user_query", Value{trace.user_query}},
        {"source_transcript", Value{trace.source_transcript}},
        {"final_answer", Value{trace.final_answer}},
        {"expected_schema",
         Value{"{\"user_input\": string, \"expected_output\": string}"}},
    }));

    const auto parsed = call_builder_json(callbacks.builder, PhasePrompt{prompt},
                                          PhaseTag{"phase1_io_isolation"});
    pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         SteadyClock::now() - p_start)
                         .count();
    if (!parsed.has_value()) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "phase 1 builder call or JSON parse failed";
      report.phases.push_back(std::move(pr));
      return finish_fail(parsed.error().code, arc_distiller_error_of(parsed.error()),
                         "phase1_io_isolation failed");
    }

    const auto user_in = get_optional_string(parsed.value(), "user_input");
    const Value *exp_v = parsed.value().find("expected_output");
    const std::string exp_out =
        exp_v != nullptr ? value_to_display_string(*exp_v) : std::string{};
    if (!user_in.has_value() || trim_sv(*user_in).empty() || trim_sv(exp_out).empty()) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "missing non-empty user_input or expected_output";
      report.phases.push_back(std::move(pr));
      return finish_fail(ErrorCode::corrupt, ArcDistillerError::parse_failed,
                         "phase1_io_isolation missing required fields");
    }

    report.isolated_user_input = *user_in;
    report.isolated_expected_output = exp_out;
    pr.status = ArcPhaseStatus::succeeded;
    pr.detail = "isolated input and expected output";
    report.phases.push_back(std::move(pr));
  }

  // -------------------------------------------------------------------------
  // Phase 2: Decomposition
  // -------------------------------------------------------------------------
  {
    const auto p_start = SteadyClock::now();
    ArcPhaseRecord pr{"phase2_decomposition", ArcPhaseStatus::not_run, 1U, 0, {}};
    const std::string prompt = build_json_prompt(Value::object({
        {"phase", Value{"phase2_decomposition"}},
        {"granularity", Value{std::string{arc_granularity_name(options.granularity)}}},
        {"user_input", Value{report.isolated_user_input}},
        {"expected_output", Value{report.isolated_expected_output}},
        {"source_transcript", Value{trace.source_transcript}},
        {"tools_used", strings_to_json(trace.tools_used)},
        {"expected_schema",
         Value{"{\"steps\": [{\"id\": string, \"description\": string, \"inputs\": "
               "[string], \"reusable\": bool}]}"}},
    }));

    const auto parsed = call_builder_json(callbacks.builder, PhasePrompt{prompt},
                                          PhaseTag{"phase2_decomposition"});
    pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         SteadyClock::now() - p_start)
                         .count();
    if (!parsed.has_value()) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "phase 2 builder call or JSON parse failed";
      report.phases.push_back(std::move(pr));
      return finish_fail(parsed.error().code, arc_distiller_error_of(parsed.error()),
                         "phase2_decomposition failed");
    }

    const Value *steps_v = parsed.value().find("steps");
    const auto *steps_arr =
        steps_v != nullptr ? std::get_if<Value::Array>(&steps_v->value()) : nullptr;
    if (steps_arr == nullptr || steps_arr->empty() ||
        steps_arr->size() > options.max_plan_nodes * 4U) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "steps must be a non-empty bounded array";
      report.phases.push_back(std::move(pr));
      return finish_fail(ErrorCode::corrupt, ArcDistillerError::parse_failed,
                         "phase2_decomposition invalid steps array");
    }

    for (std::size_t idx = 0U; idx < steps_arr->size(); ++idx) {
      const Value &s = (*steps_arr)[idx];
      if (!std::holds_alternative<Value::Object>(s.value())) {
        pr.status = ArcPhaseStatus::failed;
        pr.detail = "step entry is not an object";
        report.phases.push_back(std::move(pr));
        return finish_fail(ErrorCode::corrupt, ArcDistillerError::parse_failed,
                           "phase2_decomposition malformed step");
      }
      ArcDecompositionStep step{};
      step.id =
          get_optional_string(s, "id").value_or("step_" + std::to_string(idx + 1U));
      step.description = get_optional_string(s, "description").value_or("");
      if (trim_sv(step.description).empty()) {
        pr.status = ArcPhaseStatus::failed;
        pr.detail = "step description is empty";
        report.phases.push_back(std::move(pr));
        return finish_fail(ErrorCode::corrupt, ArcDistillerError::parse_failed,
                           "phase2_decomposition step missing description");
      }
      step.inputs = get_string_array(s, "inputs");
      step.reusable = get_optional_bool(s, "reusable").value_or(false);
      report.decomposition_steps.push_back(std::move(step));
    }

    pr.status = ArcPhaseStatus::succeeded;
    pr.detail = "decomposed into " + std::to_string(report.decomposition_steps.size()) +
                " steps";
    report.phases.push_back(std::move(pr));
  }

  // -------------------------------------------------------------------------
  // Phase 3: Parameter Recognition
  // -------------------------------------------------------------------------
  {
    const auto p_start = SteadyClock::now();
    ArcPhaseRecord pr{"phase3_param_recognition", ArcPhaseStatus::not_run, 1U, 0, {}};
    Value::Array steps_json;
    steps_json.reserve(report.decomposition_steps.size());
    for (const auto &st : report.decomposition_steps) {
      steps_json.push_back(Value::object({
          {"id", Value{st.id}},
          {"description", Value{st.description}},
          {"inputs", strings_to_json(st.inputs)},
          {"reusable", Value{st.reusable}},
      }));
    }

    const std::string prompt = build_json_prompt(Value::object({
        {"phase", Value{"phase3_param_recognition"}},
        {"user_input", Value{report.isolated_user_input}},
        {"steps", Value{std::move(steps_json)}},
        {"expected_schema",
         Value{"{\"generic_template\": string, \"params\": [{\"name\": string, "
               "\"description\": string, \"d_type\": string, \"example\": string, "
               "\"validity_range\": string, \"original_value\": any}]}"}},
    }));

    const auto parsed = call_builder_json(callbacks.builder, PhasePrompt{prompt},
                                          PhaseTag{"phase3_param_recognition"});
    pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         SteadyClock::now() - p_start)
                         .count();
    if (!parsed.has_value()) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "phase 3 builder call or JSON parse failed";
      report.phases.push_back(std::move(pr));
      return finish_fail(parsed.error().code, arc_distiller_error_of(parsed.error()),
                         "phase3_param_recognition failed");
    }

    const auto tmpl = get_optional_string(parsed.value(), "generic_template");
    if (!tmpl.has_value() || trim_sv(*tmpl).empty()) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "missing non-empty generic_template";
      report.phases.push_back(std::move(pr));
      return finish_fail(ErrorCode::corrupt, ArcDistillerError::parse_failed,
                         "phase3_param_recognition missing generic_template");
    }
    report.generic_template = *tmpl;

    if (const Value *params_v = parsed.value().find("params"); params_v != nullptr) {
      const auto *params_arr = std::get_if<Value::Array>(&params_v->value());
      if (params_arr == nullptr) {
        pr.status = ArcPhaseStatus::failed;
        pr.detail = "params must be a JSON array";
        report.phases.push_back(std::move(pr));
        return finish_fail(ErrorCode::corrupt, ArcDistillerError::parse_failed,
                           "phase3_param_recognition invalid params");
      }
      for (const auto &p_item : *params_arr) {
        if (!std::holds_alternative<Value::Object>(p_item.value())) {
          pr.status = ArcPhaseStatus::failed;
          pr.detail = "param entry is not an object";
          report.phases.push_back(std::move(pr));
          return finish_fail(ErrorCode::corrupt, ArcDistillerError::parse_failed,
                             "phase3_param_recognition malformed param");
        }
        ArcRecognizedParam rp{};
        const auto spec = parse_param_spec(p_item);
        if (trim_sv(spec.name).empty()) {
          pr.status = ArcPhaseStatus::failed;
          pr.detail = "param missing name and description";
          report.phases.push_back(std::move(pr));
          return finish_fail(ErrorCode::corrupt, ArcDistillerError::parse_failed,
                             "phase3_param_recognition param missing name");
        }
        rp.name = spec.name;
        rp.description = spec.description;
        rp.d_type = spec.d_type;
        rp.example = spec.example;
        rp.required = spec.required;
        rp.validity_range = get_optional_string(p_item, "validity_range").value_or("");
        if (const Value *ov = p_item.find("original_value"); ov != nullptr) {
          rp.original_value = *ov;
        } else if (!rp.example.empty()) {
          rp.original_value = Value{rp.example};
        }
        report.recognized_params.push_back(std::move(rp));
      }
    }

    pr.status = ArcPhaseStatus::succeeded;
    pr.detail =
        "recognized " + std::to_string(report.recognized_params.size()) + " parameters";
    report.phases.push_back(std::move(pr));
  }

  // -------------------------------------------------------------------------
  // Phase 4: Planning (Bottom-Up Acyclic DAG Validation)
  // -------------------------------------------------------------------------
  std::unordered_map<std::string, std::size_t> node_index_by_id;
  {
    const auto p_start = SteadyClock::now();
    ArcPhaseRecord pr{"phase4_planning", ArcPhaseStatus::not_run, 1U, 0, {}};

    Value::Array steps_json;
    for (const auto &st : report.decomposition_steps) {
      steps_json.push_back(Value::object({
          {"id", Value{st.id}},
          {"description", Value{st.description}},
          {"inputs", strings_to_json(st.inputs)},
          {"reusable", Value{st.reusable}},
      }));
    }
    Value::Array rparams_json;
    for (const auto &rp : report.recognized_params) {
      rparams_json.push_back(Value::object({
          {"name", Value{rp.name}},
          {"description", Value{rp.description}},
          {"d_type", Value{rp.d_type}},
          {"example", Value{rp.example}},
          {"validity_range", Value{rp.validity_range}},
          {"original_value", rp.original_value},
      }));
    }

    const std::string prompt = build_json_prompt(Value::object({
        {"phase", Value{"phase4_planning"}},
        {"granularity", Value{std::string{arc_granularity_name(options.granularity)}}},
        {"generic_template", Value{report.generic_template}},
        {"steps", Value{std::move(steps_json)}},
        {"params", Value{std::move(rparams_json)}},
        {"tools_used", strings_to_json(trace.tools_used)},
        {"expected_schema",
         Value{"{\"nodes\": [{\"id\": string, \"description\": string, \"depends_on\": "
               "[string], \"params\": [...], \"return_keys\": [string], \"is_root\": "
               "bool}]}"}},
    }));

    const auto parsed = call_builder_json(callbacks.builder, PhasePrompt{prompt},
                                          PhaseTag{"phase4_planning"});
    pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         SteadyClock::now() - p_start)
                         .count();
    if (!parsed.has_value()) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "phase 4 builder call or JSON parse failed";
      report.phases.push_back(std::move(pr));
      return finish_fail(parsed.error().code, arc_distiller_error_of(parsed.error()),
                         "phase4_planning failed");
    }

    const Value *nodes_v = parsed.value().find("nodes");
    const auto *nodes_arr =
        nodes_v != nullptr ? std::get_if<Value::Array>(&nodes_v->value()) : nullptr;
    if (nodes_arr == nullptr || nodes_arr->empty() ||
        nodes_arr->size() > options.max_plan_nodes) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "nodes must be a non-empty bounded array";
      report.phases.push_back(std::move(pr));
      return finish_fail(ErrorCode::invalid_range, ArcDistillerError::validation_failed,
                         "phase4_planning invalid nodes array");
    }

    for (const auto &n_val : *nodes_arr) {
      if (!std::holds_alternative<Value::Object>(n_val.value())) {
        pr.status = ArcPhaseStatus::failed;
        pr.detail = "plan node is not an object";
        report.phases.push_back(std::move(pr));
        return finish_fail(ErrorCode::corrupt, ArcDistillerError::parse_failed,
                           "phase4_planning malformed node");
      }
      ArcPlanNode node{};
      node.id = get_optional_string(n_val, "id").value_or("");
      node.description = get_optional_string(n_val, "description").value_or("");
      node.depends_on = get_string_array(n_val, "depends_on");
      node.return_keys = get_string_array(n_val, "return_keys");
      node.is_root = get_optional_bool(n_val, "is_root").value_or(false);
      if (const Value *tp = n_val.find("test_payloads"); tp != nullptr) {
        node.test_payloads = *tp;
      }
      if (const Value *eo = n_val.find("expected_output"); eo != nullptr) {
        node.expected_output = value_to_display_string(*eo);
      }
      if (const Value *np = n_val.find("params"); np != nullptr) {
        if (const auto *np_arr = std::get_if<Value::Array>(&np->value())) {
          for (const auto &ps : *np_arr) {
            if (std::holds_alternative<Value::Object>(ps.value())) {
              auto spec = parse_param_spec(ps);
              if (!trim_sv(spec.name).empty()) {
                node.params.push_back(std::move(spec));
              }
            }
          }
        }
      }
      if (node.is_root && node.params.empty()) {
        for (const auto &rp : report.recognized_params) {
          node.params.push_back(ArcParamSpec{rp.name, rp.description, rp.d_type,
                                             rp.example, rp.required});
        }
      }
      report.plan_nodes.push_back(std::move(node));
    }

    const auto topo = topological_sort_plan(report.plan_nodes, registry);
    if (!topo.has_value()) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail =
          "plan DAG validation failed (cycle, duplicate/invalid ID, missing dep, "
          "or root count != 1)";
      report.phases.push_back(std::move(pr));
      return finish_fail(ErrorCode::invalid_range, ArcDistillerError::validation_failed,
                         "phase4_planning DAG validation failed");
    }

    report.topological_order = topo.value();
    for (std::size_t i = 0U; i < report.plan_nodes.size(); ++i) {
      node_index_by_id[report.plan_nodes[i].id] = i;
      if (report.plan_nodes[i].is_root) {
        report.root_function_id = report.plan_nodes[i].id;
      }
    }

    pr.status = ArcPhaseStatus::succeeded;
    pr.detail = "validated acyclic DAG with " +
                std::to_string(report.plan_nodes.size()) +
                " nodes; root=" + report.root_function_id;
    report.phases.push_back(std::move(pr));
  }

  // -------------------------------------------------------------------------
  // Phase 5: Isolated Staging Registry + Agentic Implementation & Verification
  // -------------------------------------------------------------------------
  auto staging_res = ArcRegistry::open_in_memory();
  if (!staging_res.has_value()) {
    return finish_fail(ErrorCode::io, ArcDistillerError::registry_failed,
                       "failed to open isolated staging registry");
  }
  ArcRegistry &staging = staging_res.value();

  // Seed staging registry with a lossless snapshot of all existing functions from
  // the persistent registry so reuse and arc.do_ resolution work identically
  // without mutating the persistent registry during candidate trials!
  const auto existing_fns = registry.list_functions();
  if (!existing_fns.has_value()) {
    return finish_fail(ErrorCode::io, ArcDistillerError::registry_failed,
                       "failed to snapshot existing registry functions");
  }
  std::unordered_map<std::string, ArcFunctionRecord> preexisting_records;
  preexisting_records.reserve(existing_fns.value().size());
  for (const auto &rec : existing_fns.value()) {
    preexisting_records.emplace(rec.id, rec);
    const auto reg_r = staging.register_function(rec);
    if (!reg_r.has_value()) {
      return finish_fail(ErrorCode::io, ArcDistillerError::registry_failed,
                         "failed to seed staging registry with function " + rec.id);
    }
  }

  const Value original_root_payloads =
      build_root_payloads_from_recognized(report.recognized_params);

  ArcRuntimeCallbacks run_cbs{};
  run_cbs.lm = callbacks.target_lm;
  run_cbs.tool = callbacks.tool;
  run_cbs.turn_taint = callbacks.turn_taint;
  run_cbs.party_trust_policy = callbacks.party_trust_policy;

  std::vector<ArcFunctionRecord> staged_new_records;
  std::unordered_map<std::string, ArcFunctionRecord> resolved_node_records;

  {
    const auto p_start = SteadyClock::now();
    ArcPhaseRecord pr{"phase5_implement", ArcPhaseStatus::not_run, 0U, 0, {}};

    for (const auto &node_id : report.topological_order) {
      const auto &node = report.plan_nodes[node_index_by_id.at(node_id)];
      ArcNodeDistillSummary summary{};
      summary.node_id = node.id;

      // 5.1 Search persistent registry for reusable existing functions.
      Value::Array reuse_candidates_json;
      if (const auto matches = registry.search_functions(node.description, 5U);
          matches.has_value()) {
        for (const auto &m : matches.value()) {
          const auto full = registry.get_function(m.function_id);
          if (!full.has_value()) {
            continue;
          }
          reuse_candidates_json.push_back(Value::object({
              {"id", Value{full.value().id}},
              {"description", Value{full.value().description}},
              {"score", Value{Number{m.score}}},
              {"params", params_to_json(full.value().params)},
              {"return_keys", strings_to_json(full.value().return_keys)},
              {"lua_source", Value{full.value().lua_source}},
          }));
        }
      }

      // Include already-resolved dependencies so caller knows exact descriptions &
      // keys.
      Value::Array dep_sigs_json;
      for (const auto &dep_id : node.depends_on) {
        if (const auto it = resolved_node_records.find(dep_id);
            it != resolved_node_records.end()) {
          dep_sigs_json.push_back(Value::object({
              {"plan_node_id", Value{dep_id}},
              {"function_id", Value{it->second.id}},
              {"description", Value{it->second.description}},
              {"params", params_to_json(it->second.params)},
              {"return_keys", strings_to_json(it->second.return_keys)},
          }));
        } else if (const auto ext = staging.get_function(dep_id); ext.has_value()) {
          dep_sigs_json.push_back(Value::object({
              {"plan_node_id", Value{dep_id}},
              {"function_id", Value{ext.value().id}},
              {"description", Value{ext.value().description}},
              {"params", params_to_json(ext.value().params)},
              {"return_keys", strings_to_json(ext.value().return_keys)},
          }));
        }
      }

      const Value node_test_payloads = synthesize_node_test_payloads(
          node, report.recognized_params, original_root_payloads);

      std::string last_feedback;
      bool node_succeeded = false;

      for (std::uint32_t attempt = 1U; attempt <= options.max_node_retries; ++attempt) {
        ++pr.attempts;
        summary.attempts = attempt;
        if (attempt > 1U) {
          summary.retries = attempt - 1U;
          ++report.total_retries;
        }

        const std::string prompt = build_json_prompt(Value::object({
            {"phase", Value{"phase5_implement"}},
            {"attempt", Value{Number{static_cast<std::int64_t>(attempt)}}},
            {"max_retries",
             Value{Number{static_cast<std::int64_t>(options.max_node_retries)}}},
            {"node", Value::object({
                         {"id", Value{node.id}},
                         {"description", Value{node.description}},
                         {"depends_on", strings_to_json(node.depends_on)},
                         {"params", params_to_json(node.params)},
                         {"return_keys", strings_to_json(node.return_keys)},
                         {"is_root", Value{node.is_root}},
                     })},
            {"dependencies", Value{dep_sigs_json}},
            {"reuse_candidates", Value{reuse_candidates_json}},
            {"previous_feedback", Value{last_feedback}},
            {"user_input", Value{report.isolated_user_input}},
            {"expected_output", Value{report.isolated_expected_output}},
            {"source_transcript", Value{trace.source_transcript}},
            {"expected_schema",
             Value{"{\"lua_source\": string} OR {\"reuse_function_id\": string}"}},
        }));

        const auto parsed = call_builder_json(callbacks.builder, PhasePrompt{prompt},
                                              PhaseTag{"phase5_implement"});
        if (!parsed.has_value()) {
          last_feedback = "builder output was not a valid JSON object";
          summary.last_feedback = last_feedback;
          continue;
        }

        // Option A: Builder chose to reuse an existing function in the registry.
        if (const auto reuse_id =
                get_optional_string(parsed.value(), "reuse_function_id");
            reuse_id.has_value() && !trim_sv(*reuse_id).empty()) {
          const auto existing = staging.get_function(*reuse_id);
          if (!existing.has_value()) {
            last_feedback =
                "reuse_function_id '" + *reuse_id + "' not found in registry";
            summary.last_feedback = last_feedback;
            continue;
          }

          // Verify reused function executes cleanly if test payloads exist.
          const auto exec = staging.invoke_function(
              existing.value().id, node_test_payloads, run_cbs, options.exec_limits);
          if (!exec.has_value()) {
            last_feedback = "reused function '" + existing.value().id +
                            "' failed runtime check: " +
                            std::string{arc_error_name(arc_error_of(exec.error()))};
            summary.last_feedback = last_feedback;
            continue;
          }

          const std::string expected_for_node =
              !node.expected_output.empty()
                  ? node.expected_output
                  : (node.is_root ? report.isolated_expected_output : std::string{});
          if (!expected_for_node.empty()) {
            const auto verdict = evaluate_judge(
                callbacks.judge, ExpectedText{expected_for_node}, exec.value().output,
                ContextNote{"reuse:" + existing.value().id},
                NumericTol{safe_tolerance});
            if (!verdict.has_value()) {
              pr.status = ArcPhaseStatus::failed;
              pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                   SteadyClock::now() - p_start)
                                   .count();
              report.phases.push_back(std::move(pr));
              return finish_fail(verdict.error().code,
                                 arc_distiller_error_of(verdict.error()),
                                 "judge callback failed during reuse check");
            }
            if (!verdict.value().passed) {
              last_feedback = "reused function '" + existing.value().id +
                              "' rejected by judge: " + verdict.value().critique;
              summary.last_feedback = last_feedback;
              continue;
            }
          }

          summary.reused_existing = true;
          summary.registered_function_id = existing.value().id;
          summary.passed = true;
          resolved_node_records[node.id] = existing.value();
          if (std::find(report.reused_function_ids.begin(),
                        report.reused_function_ids.end(),
                        existing.value().id) == report.reused_function_ids.end()) {
            report.reused_function_ids.push_back(existing.value().id);
          }
          if (node.is_root) {
            report.root_function_id = existing.value().id;
          }
          node_succeeded = true;
          break;
        }

        // Option B: Builder emitted candidate Lua source.
        const auto lua_src = get_optional_string(parsed.value(), "lua_source");
        if (!lua_src.has_value() || trim_sv(*lua_src).empty()) {
          last_feedback = "missing non-empty lua_source (or reuse_function_id)";
          summary.last_feedback = last_feedback;
          continue;
        }

        // Static analysis (syntax + semantic_function + optional narration check).
        const auto analysis = analyze_lua_source(*lua_src);
        if (!analysis.has_value() || !analysis.value().syntax_valid ||
            !analysis.value().defines_semantic_function) {
          last_feedback = "static analysis failed: " +
                          (analysis.has_value() ? analysis.value().diagnostic
                                                : std::string{"invalid lua"});
          summary.last_feedback = last_feedback;
          continue;
        }
        if (options.require_narration_commensurate &&
            !analysis.value().narration_commensurate) {
          last_feedback = "narration check failed: narration_count=" +
                          std::to_string(analysis.value().narration_count) +
                          " is not commensurate with control_flow_complexity=" +
                          std::to_string(analysis.value().control_flow_complexity) +
                          "; add arc.narrate(ctx, ...) calls";
          summary.last_feedback = last_feedback;
          continue;
        }

        // Build candidate function record.
        ArcFunctionRecord candidate{};
        candidate.id = node.id;
        candidate.description = get_optional_string(parsed.value(), "description")
                                    .value_or(node.description);
        if (trim_sv(candidate.description).empty()) {
          candidate.description = node.description;
        }
        candidate.params = node.params;
        if (const Value *ov_params = parsed.value().find("params");
            ov_params != nullptr) {
          if (const auto *pa = std::get_if<Value::Array>(&ov_params->value());
              pa != nullptr && !pa->empty()) {
            candidate.params.clear();
            for (const auto &ps : *pa) {
              if (std::holds_alternative<Value::Object>(ps.value())) {
                auto spec = parse_param_spec(ps);
                if (!trim_sv(spec.name).empty()) {
                  candidate.params.push_back(std::move(spec));
                }
              }
            }
          }
        }
        candidate.return_keys = node.return_keys;
        if (const auto ov_rk = get_string_array(parsed.value(), "return_keys");
            !ov_rk.empty()) {
          candidate.return_keys = ov_rk;
        }
        candidate.lua_source = *lua_src;
        candidate.provenance_trace_hash = report.provenance_hash;
        candidate.granularity = options.granularity;
        candidate.is_root = node.is_root;

        // Snapshot prior staging version (if any) so failed attempts roll back cleanly.
        const auto prior_in_staging = staging.get_function(candidate.id);
        auto restore_staging = [&]() {
          if (prior_in_staging.has_value()) {
            (void)staging.register_function(prior_in_staging.value());
          } else {
            (void)staging.remove_function(candidate.id);
          }
        };

        const auto stage_reg_res = staging.register_function(candidate);
        if (!stage_reg_res.has_value()) {
          last_feedback =
              "candidate staging registration failed: " +
              std::string{arc_error_name(arc_error_of(stage_reg_res.error()))};
          summary.last_feedback = last_feedback;
          continue;
        }

        // Dispatch candidate in isolated staging registry.
        const auto exec_res = staging.invoke_function(candidate.id, node_test_payloads,
                                                      run_cbs, options.exec_limits);
        if (!exec_res.has_value()) {
          restore_staging();
          last_feedback = "candidate runtime error: " +
                          std::string{arc_error_name(arc_error_of(exec_res.error()))};
          summary.last_feedback = last_feedback;
          continue;
        }

        // Verify returned value is an object containing declared return keys.
        const auto *out_obj =
            std::get_if<Value::Object>(&exec_res.value().output.value());
        if (out_obj == nullptr) {
          restore_staging();
          last_feedback =
              "semantic_function must return a table/object of named results";
          summary.last_feedback = last_feedback;
          continue;
        }
        bool missing_rk = false;
        std::string missing_key_name;
        for (const auto &rk : candidate.return_keys) {
          if (exec_res.value().output.find(rk) == nullptr) {
            missing_rk = true;
            missing_key_name = rk;
            break;
          }
        }
        if (missing_rk) {
          restore_staging();
          last_feedback =
              "output missing declared return key: '" + missing_key_name + "'";
          summary.last_feedback = last_feedback;
          continue;
        }

        // Judge candidate output against expected output / transcript fragment.
        const std::string expected_for_node =
            !node.expected_output.empty()
                ? node.expected_output
                : (node.is_root ? report.isolated_expected_output : std::string{});
        if (!expected_for_node.empty() || callbacks.judge) {
          const std::string judge_expected =
              !expected_for_node.empty() ? expected_for_node : node.description;
          const auto verdict = evaluate_judge(
              callbacks.judge, ExpectedText{judge_expected}, exec_res.value().output,
              ContextNote{"node:" + node.id}, NumericTol{safe_tolerance});
          if (!verdict.has_value()) {
            restore_staging();
            pr.status = ArcPhaseStatus::failed;
            pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                 SteadyClock::now() - p_start)
                                 .count();
            report.phases.push_back(std::move(pr));
            return finish_fail(verdict.error().code,
                               arc_distiller_error_of(verdict.error()),
                               "judge callback failed during phase 5");
          }
          if (!verdict.value().passed) {
            restore_staging();
            last_feedback = "judge rejected candidate: " + verdict.value().critique;
            summary.last_feedback = last_feedback;
            continue;
          }
        }

        summary.registered_function_id = candidate.id;
        summary.passed = true;
        resolved_node_records[node.id] = candidate;
        staged_new_records.push_back(std::move(candidate));
        node_succeeded = true;
        break;
      }

      report.node_summaries.push_back(std::move(summary));
      if (!node_succeeded) {
        pr.status = ArcPhaseStatus::failed;
        pr.detail = "node '" + node.id + "' exhausted " +
                    std::to_string(options.max_node_retries) +
                    " attempts: " + last_feedback;
        pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             SteadyClock::now() - p_start)
                             .count();
        report.phases.push_back(std::move(pr));
        return finish_fail(ErrorCode::invalid_range, ArcDistillerError::phase_failed,
                           "phase5_implement failed on node " + node.id + ": " +
                               last_feedback);
      }
    }

    pr.status = ArcPhaseStatus::succeeded;
    pr.detail = "implemented " + std::to_string(staged_new_records.size()) +
                " new functions, reused " +
                std::to_string(report.reused_function_ids.size());
    pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         SteadyClock::now() - p_start)
                         .count();
    report.phases.push_back(std::move(pr));
  }

  // -------------------------------------------------------------------------
  // 2-Stage Root E2E Verification (in isolated staging registry!)
  // -------------------------------------------------------------------------
  const auto staged_root_res = staging.get_function(report.root_function_id);
  if (!staged_root_res.has_value()) {
    return finish_fail(ErrorCode::invalid_range, ArcDistillerError::validation_failed,
                       "staged root function missing: " + report.root_function_id);
  }
  const ArcFunctionRecord &staged_root = staged_root_res.value();

  // Stage 1: Correctness with original parameters o.
  {
    const auto s_start = SteadyClock::now();
    ArcPhaseRecord pr{"e2e_stage1_correctness", ArcPhaseStatus::not_run, 1U, 0, {}};
    const auto exec = staging.invoke_function(staged_root.id, original_root_payloads,
                                              run_cbs, options.exec_limits);
    pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         SteadyClock::now() - s_start)
                         .count();
    if (!exec.has_value()) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "root execution failed: " +
                  std::string{arc_error_name(arc_error_of(exec.error()))};
      report.phases.push_back(std::move(pr));
      return finish_fail(ErrorCode::invalid_range, ArcDistillerError::validation_failed,
                         "e2e Stage 1 execution failed");
    }

    const auto verdict = evaluate_judge(
        callbacks.judge, ExpectedText{report.isolated_expected_output},
        exec.value().output, ContextNote{"e2e_stage1_correctness:" + staged_root.id},
        NumericTol{safe_tolerance});
    if (!verdict.has_value()) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "judge callback unavailable";
      report.phases.push_back(std::move(pr));
      return finish_fail(verdict.error().code, arc_distiller_error_of(verdict.error()),
                         "e2e Stage 1 judge failed");
    }
    if (!verdict.value().passed) {
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "judge rejected root output: " + verdict.value().critique;
      report.phases.push_back(std::move(pr));
      return finish_fail(ErrorCode::invalid_range, ArcDistillerError::validation_failed,
                         "e2e Stage 1 correctness failed: " + verdict.value().critique);
    }

    report.stage1_correctness_passed = true;
    pr.status = ArcPhaseStatus::succeeded;
    pr.detail = "root function passed Stage 1 correctness";
    report.phases.push_back(std::move(pr));
  }

  // Stage 2: Extraction Robustness (N round-trips via target_lm).
  {
    const auto s_start = SteadyClock::now();
    ArcPhaseRecord pr{"e2e_stage2_extraction_robustness",
                      ArcPhaseStatus::not_run,
                      options.extraction_round_trips,
                      0,
                      {}};
    if (options.extraction_round_trips == 0U) {
      report.extraction_pass_rate = 1.0;
      pr.status = ArcPhaseStatus::skipped;
      pr.detail = "extraction_round_trips=0";
      report.phases.push_back(std::move(pr));
    } else {
      std::string failure_note;
      for (std::uint32_t trial = 0U; trial < options.extraction_round_trips; ++trial) {
        ++report.stage2_trials_run;
        const auto ext_payloads = extract_params_via_target_lm(
            callbacks.target_lm, staged_root, report.isolated_user_input);
        if (!ext_payloads.has_value()) {
          failure_note = "trial " + std::to_string(trial + 1U) +
                         ": target_lm parameter extraction failed";
          continue;
        }
        const auto exec = staging.invoke_function(staged_root.id, ext_payloads.value(),
                                                  run_cbs, options.exec_limits);
        if (!exec.has_value()) {
          failure_note = "trial " + std::to_string(trial + 1U) +
                         ": root dispatch error: " +
                         std::string{arc_error_name(arc_error_of(exec.error()))};
          continue;
        }
        const auto verdict = evaluate_judge(
            callbacks.judge, ExpectedText{report.isolated_expected_output},
            exec.value().output,
            ContextNote{"e2e_stage2_extraction_trial_" + std::to_string(trial + 1U)},
            NumericTol{safe_tolerance});
        if (!verdict.has_value()) {
          pr.status = ArcPhaseStatus::failed;
          pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                               SteadyClock::now() - s_start)
                               .count();
          report.phases.push_back(std::move(pr));
          return finish_fail(verdict.error().code,
                             arc_distiller_error_of(verdict.error()),
                             "e2e Stage 2 judge callback failed");
        }
        if (!verdict.value().passed) {
          failure_note = "trial " + std::to_string(trial + 1U) +
                         ": judge rejected output: " + verdict.value().critique;
          continue;
        }
        ++report.stage2_trials_passed;
      }

      report.extraction_pass_rate =
          report.stage2_trials_run > 0U
              ? static_cast<double>(report.stage2_trials_passed) /
                    static_cast<double>(report.stage2_trials_run)
              : 0.0;
      pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           SteadyClock::now() - s_start)
                           .count();

      if (report.stage2_trials_passed < options.extraction_round_trips) {
        pr.status = ArcPhaseStatus::failed;
        pr.detail = "passed " + std::to_string(report.stage2_trials_passed) + "/" +
                    std::to_string(options.extraction_round_trips) + " trials (" +
                    failure_note + ")";
        report.phases.push_back(std::move(pr));
        return finish_fail(ErrorCode::invalid_range,
                           ArcDistillerError::extraction_robustness_failed,
                           "Stage 2 extraction robustness failed: " + failure_note);
      }

      pr.status = ArcPhaseStatus::succeeded;
      pr.detail = "passed " + std::to_string(report.stage2_trials_passed) + "/" +
                  std::to_string(options.extraction_round_trips) + " extraction trials";
      report.phases.push_back(std::move(pr));
    }
  }

  // -------------------------------------------------------------------------
  // Pre-Validate Static Compilation in Isolated Staging BEFORE Persistent Writes
  // -------------------------------------------------------------------------
  if (options.auto_compile) {
    const auto c_start = SteadyClock::now();
    const auto staged_comp = staging.compile_network(report.root_function_id, false);
    if (!staged_comp.has_value()) {
      ArcPhaseRecord pr{"auto_compile", ArcPhaseStatus::failed, 1U, 0, {}};
      pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           SteadyClock::now() - c_start)
                           .count();
      pr.detail = "staging compile_network failed: " +
                  std::string{arc_error_name(arc_error_of(staged_comp.error()))};
      report.phases.push_back(std::move(pr));
      return finish_fail(ErrorCode::invalid_range, ArcDistillerError::compile_failed,
                         "auto_compile failed for root " + report.root_function_id);
    }
  }

  // -------------------------------------------------------------------------
  // Atomic Commit to Persistent Registry + Entry Points + Optional Compile
  // -------------------------------------------------------------------------
  std::vector<std::string> committed_new_ids;
  auto rollback_persistent = [&]() {
    for (auto it = committed_new_ids.rbegin(); it != committed_new_ids.rend(); ++it) {
      if (const auto orig = preexisting_records.find(*it);
          orig != preexisting_records.end()) {
        (void)registry.register_function(orig->second);
      } else {
        (void)registry.remove_function(*it);
      }
    }
  };

  for (const auto &rec : staged_new_records) {
    const auto reg_res = registry.register_function(rec);
    if (!reg_res.has_value()) {
      rollback_persistent();
      return finish_fail(ErrorCode::io, ArcDistillerError::registry_failed,
                         "failed to commit function '" + rec.id + "' to registry");
    }
    committed_new_ids.push_back(rec.id);
    report.registered_function_ids.push_back(rec.id);
  }

  // Register both generic_template and original user_input as entry points.
  {
    const std::string tmpl_ep_id = make_bounded_entry_id(
        report.root_function_id, SuffixTag{"tmpl"}, SaltText{report.generic_template});
    const ArcEntryPointRecord tmpl_ep{tmpl_ep_id, report.root_function_id,
                                      report.generic_template, true};
    const auto ep1 = registry.register_entry_point(tmpl_ep);
    if (!ep1.has_value()) {
      rollback_persistent();
      return finish_fail(ErrorCode::io, ArcDistillerError::registry_failed,
                         "failed to register generic_template entry point");
    }
    report.registered_entry_ids.push_back(tmpl_ep_id);

    if (normalize_whitespace_lower(report.isolated_user_input) !=
        normalize_whitespace_lower(report.generic_template)) {
      const std::string orig_ep_id =
          make_bounded_entry_id(report.root_function_id, SuffixTag{"orig"},
                                SaltText{report.isolated_user_input});
      const ArcEntryPointRecord orig_ep{orig_ep_id, report.root_function_id,
                                        report.isolated_user_input, false};
      const auto ep2 = registry.register_entry_point(orig_ep);
      if (!ep2.has_value()) {
        rollback_persistent();
        return finish_fail(ErrorCode::io, ArcDistillerError::registry_failed,
                           "failed to register original user_input entry point");
      }
      report.registered_entry_ids.push_back(orig_ep_id);
    }
  }

  // Optional Section 2.2.3 Static Compilation (persisting compiled Lua to registry).
  if (options.auto_compile) {
    const auto c_start = SteadyClock::now();
    ArcPhaseRecord pr{"auto_compile", ArcPhaseStatus::not_run, 1U, 0, {}};
    const auto comp = registry.compile_network(report.root_function_id, true);
    pr.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         SteadyClock::now() - c_start)
                         .count();
    if (!comp.has_value()) {
      rollback_persistent();
      pr.status = ArcPhaseStatus::failed;
      pr.detail = "compile_network failed: " +
                  std::string{arc_error_name(arc_error_of(comp.error()))};
      report.phases.push_back(std::move(pr));
      return finish_fail(ErrorCode::invalid_range, ArcDistillerError::compile_failed,
                         "auto_compile failed for root " + report.root_function_id);
    }
    report.compiled = true;
    pr.status = ArcPhaseStatus::succeeded;
    pr.detail =
        "compiled " + std::to_string(comp.value().included_function_ids.size()) +
        " functions (resolved_do=" + std::to_string(comp.value().resolved_do_sites) +
        ")";
    report.phases.push_back(std::move(pr));
  }

  // Record distillation & source costs on the root function.
  if (safe_source_cost > 0.0 || safe_builder_cost > 0.0) {
    (void)registry.record_cost(report.root_function_id,
                               ArcCostSample{safe_source_cost, safe_builder_cost, 0.0});
  }

  report.succeeded = true;
  report.diagnostic = "ok";
  report.total_duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                 SteadyClock::now() - total_start)
                                 .count();
  last_report_ = report;
  return Result<ArcDistillReport>::success(std::move(report));
}

// ---------------------------------------------------------------------------
// Gated Turn Interceptor (CPU-ARC Figure 1)
// ---------------------------------------------------------------------------

ArcTurnGate::ArcTurnGate(ArcRegistry &registry, ArcTurnGateConfig config) noexcept
    : registry_(&registry), config_(std::move(config)) {}

void ArcTurnGate::enqueue_miss(ArcSourceTrace trace) {
  if (config_.max_queued_misses == 0U) {
    return;
  }
  while (missed_traces_.size() >= config_.max_queued_misses) {
    missed_traces_.pop_front();
  }
  trace.source_cost_usd = sanitize_non_negative_cost(trace.source_cost_usd);
  if (trace.trace_id.empty()) {
    trace.trace_id = "gate-miss-" + std::to_string(++miss_sequence_);
  }
  if (trace.provenance_hash.empty()) {
    trace.provenance_hash = compute_canonical_trace_hash(trace);
  }
  missed_traces_.push_back(std::move(trace));
}

Result<ArcExecutionResult>
ArcTurnGate::handle_turn(std::string_view raw_request, const Value &explicit_payloads,
                         const ArcRuntimeCallbacks &callbacks,
                         ArcTurnCostEstimate cost_estimate) {
  if (registry_ == nullptr) {
    return fail_distill<ArcExecutionResult>(ErrorCode::stale_handle,
                                            ArcDistillerError::registry_failed);
  }

  ++total_turns_;
  const double src_cost = sanitize_non_negative_cost(cost_estimate.source_cost_usd);
  const double tgt_cost = sanitize_non_negative_cost(cost_estimate.target_cost_usd);

  if (!config_.enabled) {
    ++cache_misses_;
    total_source_cost_usd_ += src_cost;
    total_actual_cost_usd_ += src_cost;
    if (callbacks.source_fallback) {
      const auto start_tp = SteadyClock::now();
      auto fb = callbacks.source_fallback(raw_request);
      if (!fb.has_value()) {
        return Result<ArcExecutionResult>::failure(fb.error());
      }
      ArcExecutionResult res{};
      res.output = std::move(fb.value());
      res.cache_hit = false;
      res.fell_back_to_source = true;
      res.fallback_reason = "gate_disabled";
      res.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            SteadyClock::now() - start_tp)
                            .count();
      return Result<ArcExecutionResult>::success(std::move(res));
    }
    return fail_distill<ArcExecutionResult>(ErrorCode::unsupported,
                                            ArcDistillerError::registry_failed);
  }

  auto serve_res =
      registry_->serve(raw_request, explicit_payloads, callbacks, config_.exec_limits);

  if (serve_res.has_value()) {
    const auto &exec = serve_res.value();
    if (exec.cache_hit && !exec.fell_back_to_source) {
      ++cache_hits_;
      total_source_cost_usd_ += src_cost;
      total_actual_cost_usd_ += tgt_cost;
      if (src_cost > tgt_cost) {
        estimated_saved_usd_ += (src_cost - tgt_cost);
      }
      return serve_res;
    }

    // Fallback to source S (either miss or runtime error fallback).
    if (exec.cache_hit) {
      ++error_fallbacks_;
    } else {
      ++cache_misses_;
    }
    total_source_cost_usd_ += src_cost;
    total_actual_cost_usd_ += src_cost;

    ArcSourceTrace miss{};
    miss.trace_id = "gate-miss-" + std::to_string(++miss_sequence_);
    miss.user_query = std::string{raw_request};
    miss.final_answer = value_to_display_string(exec.output);
    miss.source_transcript = miss.final_answer;
    miss.source_cost_usd = src_cost;
    enqueue_miss(std::move(miss));
    return serve_res;
  }

  // serve() returned an error (no source_fallback configured or hard failure).
  if (arc_error_of(serve_res.error()) == ArcError::entry_not_found) {
    ++cache_misses_;
  } else {
    ++error_fallbacks_;
  }
  total_source_cost_usd_ += src_cost;
  total_actual_cost_usd_ += src_cost;

  ArcSourceTrace miss{};
  miss.trace_id = "gate-miss-" + std::to_string(++miss_sequence_);
  miss.user_query = std::string{raw_request};
  miss.source_cost_usd = src_cost;
  enqueue_miss(std::move(miss));
  return serve_res;
}

void ArcTurnGate::record_miss(ArcSourceTrace trace) { enqueue_miss(std::move(trace)); }

std::vector<ArcSourceTrace> ArcTurnGate::queued_misses() const {
  return std::vector<ArcSourceTrace>(missed_traces_.begin(), missed_traces_.end());
}

std::vector<ArcDistillCandidateCluster> ArcTurnGate::pending_candidates() const {
  const auto all_clusters =
      cluster_recurring_traces(queued_misses(), config_.cluster_min_similarity);
  std::vector<ArcDistillCandidateCluster> ready;
  for (const auto &c : all_clusters) {
    if (c.occurrence_count >= config_.auto_distill_threshold) {
      ready.push_back(c);
    }
  }
  return ready;
}

std::size_t ArcTurnGate::consume_cluster(const ArcDistillCandidateCluster &cluster) {
  std::unordered_set<std::string> ids(cluster.member_trace_ids.begin(),
                                      cluster.member_trace_ids.end());
  const std::size_t before = missed_traces_.size();
  std::erase_if(missed_traces_,
                [&](const ArcSourceTrace &t) { return ids.contains(t.trace_id); });
  return before - missed_traces_.size();
}

void ArcTurnGate::clear_misses() noexcept { missed_traces_.clear(); }

ArcTurnGateTelemetry ArcTurnGate::telemetry() const {
  ArcTurnGateTelemetry t{};
  t.total_turns = total_turns_;
  t.cache_hits = cache_hits_;
  t.cache_misses = cache_misses_;
  t.error_fallbacks = error_fallbacks_;
  t.hit_rate = total_turns_ > 0U ? static_cast<double>(cache_hits_) /
                                       static_cast<double>(total_turns_)
                                 : 0.0;
  t.estimated_saved_usd = estimated_saved_usd_;
  t.total_source_cost_usd = total_source_cost_usd_;
  t.total_actual_cost_usd = total_actual_cost_usd_;
  if (total_actual_cost_usd_ > 0.0 && total_source_cost_usd_ > 0.0) {
    t.cost_savings_multiplier = total_source_cost_usd_ / total_actual_cost_usd_;
  }
  t.queued_miss_count = missed_traces_.size();
  t.ready_candidate_count = pending_candidates().size();
  return t;
}

} // namespace blackbird::arc
