#pragma once

#include "blackbird/decision_models.hpp"
#include "blackbird/value.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

struct RawAdapterContext;

struct LivePartyMemberInfo {
  std::string handle;
  std::optional<std::uint64_t> account_id;
  bool is_guest = false;
  bool is_self = false;
  std::string clients;
  std::string state;
  std::string agent_summary;
};

struct LivePartyCardInfo {
  std::string title;
  std::string summary;
  std::string status = "done";
  std::string agent_name;
  std::vector<std::string> files;
  std::optional<std::string> diff_stat;
};

struct LivePartyMessageInfo {
  std::uint64_t seq = 0U;
  std::uint64_t ts_ms = 0U;
  std::string sender_handle;
  std::optional<std::uint64_t> sender_account_id;
  bool sender_is_guest = false;
  std::string sender_client;
  std::string sender_agent_name;
  std::string target = "@all";
  std::string kind = "chat";
  std::string body;
  bool local_self = false;
  std::optional<LivePartyCardInfo> agent_card;
};

struct LivePartyRoomState {
  bool connected = false;
  std::string state_name;
  std::string room_code;
  std::string room_name;
  std::string share_url;
  std::uint64_t latest_seq = 0U;
  std::vector<LivePartyMemberInfo> members;
  std::vector<LivePartyMessageInfo> messages;
};

struct LivePartyBridge {
  std::function<LivePartyRoomState()> read_state;
  std::function<Result<void>(std::string_view text, std::string_view target)> send_chat;
  std::function<Result<void>(const LivePartyCardInfo &card)> send_card;
};

struct CommandPostToolContext {
  DecisionModels *decision_models = nullptr;
  std::function<bool()> cancelled = {};
  const RawAdapterContext *raw_context = nullptr;
  const LivePartyBridge *live_party = nullptr;
};

// Returns true when `name` is one of the sovereign multiplayer command-post
// model tools (platoon_board, party_chat, bridge_guard, project_issues, etc.).
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
