#include "blackbird/hooks.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/tools.hpp"
#include <algorithm>
#include <charconv>
#include <set>

namespace blackbird {
namespace {

bool valid_hook_identifier(std::string_view name) noexcept {
  return !name.empty() && name.size() <= 64 &&
         std::all_of(name.begin(), name.end(), [](char ch) {
           return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
         });
}

bool printable_text(std::string_view text) noexcept {
  return std::none_of(text.begin(), text.end(), [](char ch) {
    const auto u = static_cast<unsigned char>(ch);
    return u < 32U || u == 127U;
  });
}

std::int64_t parse_order(const Value &value) {
  if (!std::holds_alternative<Number>(value.value()))
    throw Error{ErrorCode::invalid_range};
  const auto &text = value.number().text();
  std::int64_t out = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), out);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size())
    throw Error{ErrorCode::invalid_range};
  return out;
}

bool kind_allowed_for_event(HookKind kind, HookEvent event) noexcept {
  switch (kind) {
  case HookKind::observer:
    return true;
  case HookKind::context_transform:
    return event == HookEvent::turn_start || event == HookEvent::after_tool ||
           event == HookEvent::context_compact;
  case HookKind::admission:
    return event == HookEvent::before_tool;
  }
  return false;
}

} // namespace

std::string_view hook_event_name(HookEvent event) noexcept {
  switch (event) {
  case HookEvent::turn_start:
    return "turn_start";
  case HookEvent::turn_end:
    return "turn_end";
  case HookEvent::before_tool:
    return "before_tool";
  case HookEvent::after_tool:
    return "after_tool";
  case HookEvent::context_compact:
    return "context_compact";
  }
  return "turn_start";
}

std::optional<HookEvent> parse_hook_event(std::string_view name) noexcept {
  if (name == "turn_start")
    return HookEvent::turn_start;
  if (name == "turn_end")
    return HookEvent::turn_end;
  if (name == "before_tool")
    return HookEvent::before_tool;
  if (name == "after_tool")
    return HookEvent::after_tool;
  if (name == "context_compact")
    return HookEvent::context_compact;
  return std::nullopt;
}

std::string_view hook_kind_name(HookKind kind) noexcept {
  switch (kind) {
  case HookKind::observer:
    return "observer";
  case HookKind::context_transform:
    return "context_transform";
  case HookKind::admission:
    return "admission";
  }
  return "observer";
}

std::optional<HookKind> parse_hook_kind(std::string_view name) noexcept {
  if (name == "observer")
    return HookKind::observer;
  if (name == "context_transform")
    return HookKind::context_transform;
  if (name == "admission")
    return HookKind::admission;
  return std::nullopt;
}

std::string_view hook_outcome_name(HookOutcome outcome) noexcept {
  switch (outcome) {
  case HookOutcome::matched_ok:
    return "matched_ok";
  case HookOutcome::matched_denied:
    return "matched_denied";
  case HookOutcome::matched_failed:
    return "matched_failed";
  case HookOutcome::skipped:
    return "skipped";
  }
  return "matched_ok";
}

Value HookDefinition::to_value() const {
  Value::Object obj{{"name", Value{name}},
                    {"event", Value{std::string{hook_event_name(event)}}},
                    {"kind", Value{std::string{hook_kind_name(kind)}}},
                    {"enabled", Value{enabled}},
                    {"order", Value{Number{order}}},
                    {"source", Value{source}}};
  if (!description.empty())
    obj.emplace_back("description", Value{description});
  if (!match.tool.empty() || !match.prompt_prefix.empty()) {
    Value::Object filter;
    if (!match.tool.empty())
      filter.emplace_back("tool", Value{match.tool});
    if (!match.prompt_prefix.empty())
      filter.emplace_back("prompt_prefix", Value{match.prompt_prefix});
    obj.emplace_back("match", Value::object(std::move(filter)));
  }
  return Value::object(std::move(obj));
}

Value HookExplanation::to_value() const {
  return Value::object({{"name", Value{name}},
                        {"event", Value{std::string{hook_event_name(event)}}},
                        {"kind", Value{std::string{hook_kind_name(kind)}}},
                        {"order", Value{Number{order}}},
                        {"enabled", Value{enabled}},
                        {"matched", Value{matched}},
                        {"reason", Value{reason}}});
}

Value HookDispatchRecord::to_value() const {
  return Value::object({{"sequence", Value{Number{sequence}}},
                        {"hook", Value{hook_name}},
                        {"revision", Value{revision}},
                        {"event", Value{std::string{hook_event_name(event)}}},
                        {"kind", Value{std::string{hook_kind_name(kind)}}},
                        {"outcome", Value{std::string{hook_outcome_name(outcome)}}},
                        {"detail", Value{detail}},
                        {"duration_ms", Value{Number{duration_ms}}}});
}

HookRegistry::HookRegistry(const Value &config, std::string_view revision)
    : revision_(revision) {
  const auto *hooks = config.find("hooks");
  if (!hooks)
    return;
  if (!std::holds_alternative<Value::Array>(hooks->value()))
    throw Error{ErrorCode::invalid_range};
  const auto &entries = hooks->array();
  if (entries.size() > 32)
    throw Error{ErrorCode::capacity};
  const ValueLimits limits{65536, 500000, 128};
  if (unwrap(encode_packet_string(*hooks, limits)).size() > 65536)
    throw Error{ErrorCode::capacity};

  std::set<std::string> seen_names;
  definitions_.reserve(entries.size());
  for (const auto &entry : entries) {
    if (!std::holds_alternative<Value::Object>(entry.value()))
      throw Error{ErrorCode::invalid_range};
    for (const auto &[k, v] : entry.object()) {
      (void)v;
      if (k != "name" && k != "event" && k != "kind" && k != "enabled" &&
          k != "order" && k != "match" && k != "description" && k != "source")
        throw Error{ErrorCode::invalid_range};
    }
    HookDefinition def;
    def.name = string_field(entry, "name");
    if (!valid_hook_identifier(def.name) || !seen_names.insert(def.name).second)
      throw Error{ErrorCode::invalid_range};

    const auto parsed_event = parse_hook_event(string_field(entry, "event"));
    if (!parsed_event)
      throw Error{ErrorCode::invalid_range};
    def.event = *parsed_event;

    if (const auto *kind_val = entry.find("kind")) {
      if (!std::holds_alternative<std::string>(kind_val->value()))
        throw Error{ErrorCode::invalid_range};
      const auto parsed_kind = parse_hook_kind(kind_val->string());
      if (!parsed_kind)
        throw Error{ErrorCode::invalid_range};
      def.kind = *parsed_kind;
    }
    if (!kind_allowed_for_event(def.kind, def.event))
      throw Error{ErrorCode::invalid_range};

    if (const auto *en = entry.find("enabled")) {
      if (!std::holds_alternative<bool>(en->value()))
        throw Error{ErrorCode::invalid_range};
      def.enabled = std::get<bool>(en->value());
    }
    if (const auto *ord = entry.find("order"))
      def.order = parse_order(*ord);

    if (const auto *desc = entry.find("description")) {
      if (!std::holds_alternative<std::string>(desc->value()) ||
          desc->string().size() > 256 || !printable_text(desc->string()))
        throw Error{ErrorCode::invalid_range};
      def.description = desc->string();
    }

    if (const auto *match = entry.find("match")) {
      if (!std::holds_alternative<Value::Object>(match->value()))
        throw Error{ErrorCode::invalid_range};
      for (const auto &[mk, mv] : match->object()) {
        if (mk == "tool") {
          if (!std::holds_alternative<std::string>(mv.value()) ||
              mv.string().size() > 128 || !printable_text(mv.string()))
            throw Error{ErrorCode::invalid_range};
          def.match.tool = mv.string();
        } else if (mk == "prompt_prefix") {
          if (!std::holds_alternative<std::string>(mv.value()) ||
              mv.string().size() > 256 || !printable_text(mv.string()))
            throw Error{ErrorCode::invalid_range};
          def.match.prompt_prefix = mv.string();
        } else {
          throw Error{ErrorCode::invalid_range};
        }
      }
    }

    def.source = string_field(entry, "source");
    if (def.source.empty() || def.source.size() > 16384)
      throw Error{ErrorCode::invalid_range};
    definitions_.push_back(std::move(def));
  }

  std::stable_sort(definitions_.begin(), definitions_.end(),
                   [](const HookDefinition &a, const HookDefinition &b) {
                     if (a.order != b.order)
                       return a.order < b.order;
                     return a.name < b.name;
                   });

  Value::Array normalized;
  normalized.reserve(definitions_.size());
  for (const auto &def : definitions_)
    normalized.push_back(def.to_value());
  definitions_value_ = Value{std::move(normalized)};
}

std::vector<const HookDefinition *>
HookRegistry::matching(const HookMatchSample &sample) const {
  std::vector<const HookDefinition *> out;
  for (const auto &def : definitions_) {
    if (!def.enabled || def.event != sample.event)
      continue;
    if (!def.match.tool.empty() && def.match.tool != sample.tool)
      continue;
    if (!def.match.prompt_prefix.empty() &&
        !sample.prompt.starts_with(def.match.prompt_prefix))
      continue;
    out.push_back(&def);
  }
  return out;
}

std::vector<HookExplanation>
HookRegistry::explain(const HookMatchSample &sample) const {
  std::vector<HookExplanation> out;
  out.reserve(definitions_.size());
  for (const auto &def : definitions_) {
    HookExplanation item;
    item.name = def.name;
    item.event = def.event;
    item.kind = def.kind;
    item.order = def.order;
    item.enabled = def.enabled;
    if (!def.enabled) {
      item.matched = false;
      item.reason = "disabled";
    } else if (def.event != sample.event) {
      item.matched = false;
      item.reason = "event mismatch";
    } else if (!def.match.tool.empty() && def.match.tool != sample.tool) {
      item.matched = false;
      item.reason = "tool mismatch";
    } else if (!def.match.prompt_prefix.empty() &&
               !sample.prompt.starts_with(def.match.prompt_prefix)) {
      item.matched = false;
      item.reason = "prompt_prefix mismatch";
    } else {
      item.matched = true;
      item.reason = "matched";
    }
    out.push_back(std::move(item));
  }
  return out;
}

Value HookRegistry::discover() const {
  return Value::object(
      {{"revision", Value{revision_}}, {"definitions", definitions_value_}});
}

} // namespace blackbird
