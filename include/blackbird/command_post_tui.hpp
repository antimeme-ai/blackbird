#pragma once

#include "blackbird/capabilities.hpp"
#include "blackbird/context.hpp"
#include "blackbird/decision_models.hpp"
#include "blackbird/provider_auth.hpp"
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

class MpRoomV2Session;

struct CommandPostTuiContext {
  std::filesystem::path project_root;
  std::filesystem::path session_dir;
  std::optional<std::filesystem::path> worktree_lease_root;
  std::optional<std::filesystem::path> user_capabilities_dir;
  std::vector<CapabilityDefinition> builtin_capabilities;
  bool include_default_user_capabilities = true;
  AuditLog *audit_log = nullptr;
  std::string actor = "operator";
  std::string session_id;
  DecisionModelConfig decision_config;
  std::optional<ProviderAuthConfig> provider_auth_config;
  std::function<Value(const Value &arguments)> decision_evaluator;
  bool tui = false;
  bool *party_cards_enabled = nullptr;
  MpRoomV2Session *mp_room_v2 = nullptr;
  std::function<void(std::string_view)> respond_turn_runner;
};

// Bounded, operator-controlled slash-command dispatcher for Command Post TUI
// and plain-mode surfaces:
//   /platoon [status|board|members|post <text>]
//   /issues [ready|list|create <title>|claim <id>|close <id>]
//   /memory [recent|recall <query>|record <kind> <title> :: <body>|verify]
//   /capabilities [list|show <id>]
//   /metrics [summary]
//   /companion [status|ask <question>]
// Returns std::nullopt when `line` does not start with one of these commands.
std::optional<std::string> handle_command_post_slash(std::string_view line,
                                                     const CommandPostTuiContext &ctx);

} // namespace blackbird
