#pragma once

#include "blackbird/value.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

enum class HookEvent : std::uint8_t {
  turn_start,
  turn_end,
  before_tool,
  after_tool,
  context_compact
};

enum class HookKind : std::uint8_t { observer, context_transform, admission };

enum class HookOutcome : std::uint8_t {
  matched_ok,
  matched_denied,
  matched_failed,
  skipped
};

std::string_view hook_event_name(HookEvent event) noexcept;
std::optional<HookEvent> parse_hook_event(std::string_view name) noexcept;
std::string_view hook_kind_name(HookKind kind) noexcept;
std::optional<HookKind> parse_hook_kind(std::string_view name) noexcept;
std::string_view hook_outcome_name(HookOutcome outcome) noexcept;

struct HookMatch {
  std::string tool;
  std::string prompt_prefix;
};

struct HookDefinition {
  std::string name;
  HookEvent event = HookEvent::turn_start;
  HookKind kind = HookKind::observer;
  bool enabled = true;
  std::int64_t order = 0;
  HookMatch match;
  std::string description;
  std::string source;

  Value to_value() const;
};

struct HookMatchSample {
  HookEvent event = HookEvent::turn_start;
  std::string tool;
  std::string prompt;
};

struct HookExplanation {
  std::string name;
  HookEvent event = HookEvent::turn_start;
  HookKind kind = HookKind::observer;
  std::int64_t order = 0;
  bool enabled = false;
  bool matched = false;
  std::string reason;

  Value to_value() const;
};

struct HookDispatchRecord {
  std::uint64_t sequence = 0;
  std::string hook_name;
  std::string revision;
  HookEvent event = HookEvent::turn_start;
  HookKind kind = HookKind::observer;
  HookOutcome outcome = HookOutcome::matched_ok;
  std::string detail;
  std::uint64_t duration_ms = 0;

  Value to_value() const;
};

// Immutable validated snapshot of session hooks, ordered deterministically by
// (order, name). Mirrors WorkflowRegistry turn-boundary activation semantics.
class HookRegistry {
public:
  HookRegistry() = default;
  HookRegistry(const Value &config, std::string_view revision);

  const std::vector<HookDefinition> &definitions() const noexcept {
    return definitions_;
  }
  const Value &definitions_value() const noexcept { return definitions_value_; }
  const std::string &revision() const noexcept { return revision_; }

  std::vector<const HookDefinition *> matching(const HookMatchSample &sample) const;
  std::vector<HookExplanation> explain(const HookMatchSample &sample) const;
  Value discover() const;

private:
  std::vector<HookDefinition> definitions_;
  Value definitions_value_ = Value{Value::Array{}};
  std::string revision_;
};

} // namespace blackbird
