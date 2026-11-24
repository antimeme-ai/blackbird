#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/value.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::uint64_t kAcpProtocolVersion = 1U;
inline constexpr std::string_view kAcpAgentName = "blackbird";
inline constexpr std::string_view kAcpAgentVersion = "0.3.0";

inline constexpr std::size_t kAcpMinLineBytes = 256U;
inline constexpr std::size_t kAcpDefaultMaxLineBytes = 1024U * 1024U;
inline constexpr std::size_t kAcpMaxLineBytesLimit = 16U * 1024U * 1024U;

inline constexpr std::int64_t kAcpJsonRpcParseError = -32700;
inline constexpr std::int64_t kAcpJsonRpcInvalidRequest = -32600;
inline constexpr std::int64_t kAcpJsonRpcMethodNotFound = -32601;
inline constexpr std::int64_t kAcpJsonRpcInvalidParams = -32602;
inline constexpr std::int64_t kAcpJsonRpcInternalError = -32603;

// Integer internal primary key per BLACKBIRD.md Tenet #6 (never keyed by string).
struct SessionHandleId {
  std::uint64_t value = 0U;

  friend constexpr bool operator==(SessionHandleId, SessionHandleId) noexcept = default;
  friend constexpr auto operator<=>(SessionHandleId,
                                    SessionHandleId) noexcept = default;
};

enum class AcpStopReason : std::uint8_t {
  end_turn,
  cancelled,
  max_tokens,
};

enum class AcpToolCallStatus : std::uint8_t {
  pending,
  in_progress,
  completed,
  failed,
};

struct AcpPromptBlock {
  std::string kind;
  std::string text;
};

struct AcpPromptRequest {
  SessionHandleId session_id;
  std::string cwd;
  std::vector<AcpPromptBlock> blocks;
};

struct AcpToolCallEvent {
  std::uint64_t tool_call_id = 0U;
  std::string title;
  std::string kind;
  AcpToolCallStatus status = AcpToolCallStatus::pending;
};

struct AcpToolCallUpdateEvent {
  std::uint64_t tool_call_id = 0U;
  AcpToolCallStatus status = AcpToolCallStatus::in_progress;
  std::string content;
};

struct AcpPromptResult {
  AcpStopReason stop_reason = AcpStopReason::end_turn;
  std::optional<std::string> error_message;
};

using AcpNotificationSink = std::function<void(const Value &notification)>;

// Structured streaming emitter handed to AcpPromptRunner for session/update
// notifications.
class AcpSessionEmitter {
public:
  AcpSessionEmitter(SessionHandleId session_id, AcpNotificationSink sink) noexcept;

  void emit_agent_message_chunk(std::string_view text) const;
  void emit_agent_thought_chunk(std::string_view text) const;
  void emit_tool_call(const AcpToolCallEvent &event) const;
  void emit_tool_call_update(const AcpToolCallUpdateEvent &event) const;

  SessionHandleId session_id() const noexcept { return session_id_; }

private:
  void emit_update(Value update_obj) const;

  SessionHandleId session_id_;
  AcpNotificationSink sink_;
};

using AcpPromptRunner = std::function<AcpPromptResult(
    const AcpPromptRequest &request, const AcpSessionEmitter &emitter,
    const std::atomic<bool> &cancelled)>;

struct AcpAgentConfig {
  std::size_t max_line_bytes = kAcpDefaultMaxLineBytes;
  std::string agent_name{kAcpAgentName};
  std::string agent_version{kAcpAgentVersion};
  AcpPromptRunner prompt_runner;
};

// Format/parse external ACP sessionId wire string <-> integer internal SessionHandleId.
std::string format_acp_session_id(SessionHandleId id);
std::optional<SessionHandleId> parse_acp_session_id(std::string_view wire_id) noexcept;
std::string_view acp_stop_reason_name(AcpStopReason reason) noexcept;
std::string_view acp_tool_call_status_name(AcpToolCallStatus status) noexcept;

// Native zero-dependency JSON-RPC 2.0 Stdio Agent Client Protocol (ACP) Agent server.
class AcpAgentServer {
public:
  static Result<AcpAgentServer> create(AcpAgentConfig config);

  AcpAgentServer(const AcpAgentServer &) = delete;
  AcpAgentServer &operator=(const AcpAgentServer &) = delete;
  AcpAgentServer(AcpAgentServer &&) noexcept;
  AcpAgentServer &operator=(AcpAgentServer &&) noexcept;
  ~AcpAgentServer();

  // Synchronous single-message JSON-RPC 2.0 dispatch. Returns std::nullopt for
  // notifications (no id). Streaming session/update notifications go to `sink`.
  std::optional<Value> handle_message(const Value &msg,
                                      const AcpNotificationSink &sink);

  // Parses and dispatches a single raw JSON-RPC line with UTF-8 and size checks.
  std::optional<Value> handle_line(std::string_view line,
                                   const AcpNotificationSink &sink);

  // Cooperative cancel trigger for an active session (safe to invoke from another
  // thread).
  bool cancel_session(SessionHandleId session_id) noexcept;

  // Newline-delimited JSON-RPC 2.0 stdio loop supporting concurrent session/cancel
  // while a session/prompt turn is executing. Returns 0 on clean EOF, non-zero on
  // output stream failure.
  int run_stdio(std::istream &in, std::ostream &out);

  std::size_t max_line_bytes() const noexcept;
  std::size_t session_count() const noexcept;
  bool has_session(SessionHandleId session_id) const noexcept;

private:
  struct Impl;
  explicit AcpAgentServer(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

} // namespace blackbird
