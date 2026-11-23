#pragma once

#include "blackbird/decision_models.hpp"
#include "blackbird/value.hpp"

#include <functional>
#include <optional>
#include <string_view>

namespace blackbird {

struct RawAdapterContext;

struct CommandPostToolContext {
  DecisionModels *decision_models = nullptr;
  std::function<bool()> cancelled = {};
  const RawAdapterContext *raw_context = nullptr;
};

// Returns true when `name` is one of the 5 sovereign multiplayer command-post
// model tools: platoon_board, bridge_guard, project_issues, project_memory,
// companion_timing.
bool is_command_post_tool(std::string_view name) noexcept;

// Returns the JSON-Schema tool definitions array for all 5 command-post tools.
Value command_post_tool_definitions();

// Dispatches a command-post model tool call. Throws Error on schema/domain
// violations (invalid_range, invalid_identity, conflict, capacity, io, etc.).
Value run_command_post_tool(std::string_view name, const Value &arguments,
                            const CommandPostToolContext &context = {});

// Convenience single-call helper for CodingEngine::dispatch.
std::optional<Value>
try_dispatch_command_post_tool(std::string_view name, const Value &arguments,
                               const CommandPostToolContext &context = {});

} // namespace blackbird
