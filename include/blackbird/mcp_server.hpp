#pragma once

#include "blackbird/decision_models.hpp"
#include "blackbird/foundation.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/platoon_runner.hpp"
#include "blackbird/value.hpp"
#include "blackbird/worktree_lease.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::size_t kMcpDefaultMaxLineBytes = 1024U * 1024U;
inline constexpr std::size_t kMcpMinLineBytes = 256U;
inline constexpr std::size_t kMcpMaxLineBytesLimit = 16U * 1024U * 1024U;
inline constexpr std::size_t kMcpDefaultMaxTotalSpawns = 64U;
inline constexpr std::size_t kMcpMaxTotalSpawnsLimit = 1024U;

inline constexpr std::string_view kMcpProtocolVersion = "2025-03-26";
inline constexpr std::string_view kMcpServerName = "blackbird-command-post";
inline constexpr std::string_view kMcpServerVersion = "1.0.0";

inline constexpr std::int64_t kJsonRpcParseError = -32700;
inline constexpr std::int64_t kJsonRpcInvalidRequest = -32600;
inline constexpr std::int64_t kJsonRpcMethodNotFound = -32601;
inline constexpr std::int64_t kJsonRpcInvalidParams = -32602;
inline constexpr std::int64_t kJsonRpcInternalError = -32603;

struct McpPlatoonPeerConfig {
  std::size_t max_peers = PlatoonRunner::default_max_peers;
  // Cumulative lifetime peer spawn ceiling for this MCP server instance.
  std::size_t max_total_spawns = kMcpDefaultMaxTotalSpawns;
  // Optional binary override (host-configured only; never accepted from tool args).
  std::filesystem::path executable;
  // Optional default working directory when omitted from platoon_peer_spawn args.
  std::filesystem::path working_root;
  // Optional default session parent directory (<session_root>/<peer_id>) when omitted.
  std::filesystem::path session_root;
  // Optional explicit allowlist constraining working_dir, session_dir, and workflow.
  std::vector<std::filesystem::path> allowed_workspace_roots;
};

struct McpCommandPostConfig {
  std::size_t max_line_bytes = kMcpDefaultMaxLineBytes;
  std::optional<std::filesystem::path> board_root;
  std::optional<WorktreeLeaseConfig> worktree_lease;
  std::optional<McpPlatoonPeerConfig> platoon_runner;
  std::optional<DecisionModelConfig> decision_models;
};

// Native zero-dependency JSON-RPC 2.0 Stdio MCP server exposing Blackbird's
// Platoon Board, Worktree Leases, Peer Runner, and Decision Companion.
class McpCommandPostServer {
public:
  static Result<McpCommandPostServer> open(McpCommandPostConfig config);

  McpCommandPostServer(const McpCommandPostServer &) = delete;
  McpCommandPostServer &operator=(const McpCommandPostServer &) = delete;
  McpCommandPostServer(McpCommandPostServer &&) noexcept;
  McpCommandPostServer &operator=(McpCommandPostServer &&) noexcept;
  ~McpCommandPostServer();

  // Pure in-memory JSON-RPC 2.0 handler. Returns std::nullopt for notifications.
  std::optional<Value> handle_message(const Value &msg);

  // Parses and dispatches a single raw JSON-RPC line with UTF-8 and size checks.
  std::optional<Value> handle_line(std::string_view line);

  // Newline-delimited JSON-RPC 2.0 stdio loop. Returns 0 on clean EOF, non-zero on
  // output stream failure.
  int run_stdio(std::istream &in, std::ostream &out);

  std::vector<std::string> tool_names() const;
  std::size_t max_line_bytes() const noexcept;

private:
  struct Impl;
  explicit McpCommandPostServer(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

} // namespace blackbird
