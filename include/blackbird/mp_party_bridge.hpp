#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/mp_party_runtime.hpp"
#include "blackbird/mp_protocol.hpp"
#include "blackbird/p2p_party_session.hpp"
#include "blackbird/value.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

namespace blackbird {

// ---------------------------------------------------------------------------
// Constants & error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMpAttachMaxCommandBytes = 320U * 1024U;
inline constexpr std::string_view kMpAttachDefaultRoomScope = "party/online";
inline constexpr std::string_view kMpAttachDefaultTarget = "@all";
inline constexpr std::uint32_t kMpAttachDefaultTickMs = 50U;
inline constexpr std::uint32_t kMpAttachMaxTickMs = 1000U;

enum class MpPartyBridgeError : std::int64_t {
  none = 0,
  line_too_large = 2100,
  invalid_utf8 = 2101,
  invalid_json = 2102,
  not_json_object = 2103,
  missing_command = 2104,
  unknown_command = 2105,
  invalid_field = 2106,
  field_too_large = 2107,
  invalid_enum = 2108,
  invalid_device_id = 2109,
  invalid_config = 2110,
  io_error = 2111,
};

constexpr MpPartyBridgeError mp_party_bridge_error_of(const Error &error) noexcept {
  return static_cast<MpPartyBridgeError>(error.detail);
}

std::string_view mp_party_bridge_error_name(MpPartyBridgeError detail) noexcept;

// ---------------------------------------------------------------------------
// Enum naming & parsing helpers
// ---------------------------------------------------------------------------

enum class MpAttachMode : std::uint8_t {
  jsonl = 0,
  plain = 1,
};

std::string_view mp_attach_mode_name(MpAttachMode mode) noexcept;
Result<MpAttachMode> parse_mp_attach_mode(std::string_view text) noexcept;

std::string_view p2p_party_activity_state_name(P2pPartyActivityState state) noexcept;
Result<P2pPartyActivityState>
parse_p2p_party_activity_state(std::string_view text) noexcept;

std::string_view
p2p_party_control_notice_kind_name(P2pPartyControlNoticeKind kind) noexcept;
Result<P2pPartyControlNoticeKind>
parse_p2p_party_control_notice_kind(std::string_view text) noexcept;

std::string_view mp_runtime_event_json_type(MpRuntimeEventKind kind) noexcept;

// ---------------------------------------------------------------------------
// Typed attach commands (strict JSONL + plain interactive line parsers)
// ---------------------------------------------------------------------------

enum class MpAttachCommandKind : std::uint8_t {
  say = 1,
  pulse = 2,
  notice = 3,
  roster = 4,
  ping = 5,
  quit = 6,
};

std::string_view mp_attach_command_kind_name(MpAttachCommandKind kind) noexcept;

struct MpAttachSayCommand {
  std::string body;
  std::string room_scope = std::string{kMpAttachDefaultRoomScope};
  std::string target = std::string{kMpAttachDefaultTarget};
  std::optional<mp::DeviceId> device_id = std::nullopt;

  bool operator==(const MpAttachSayCommand &) const = default;
};

struct MpAttachPulseCommand {
  P2pPartyActivityState state = P2pPartyActivityState::online;
  std::string status;

  bool operator==(const MpAttachPulseCommand &) const = default;
};

struct MpAttachNoticeCommand {
  P2pPartyControlNoticeKind notice_kind = P2pPartyControlNoticeKind::status;
  std::string text;

  bool operator==(const MpAttachNoticeCommand &) const = default;
};

struct MpAttachRosterCommand {
  bool operator==(const MpAttachRosterCommand &) const = default;
};

struct MpAttachPingCommand {
  bool operator==(const MpAttachPingCommand &) const = default;
};

struct MpAttachQuitCommand {
  bool operator==(const MpAttachQuitCommand &) const = default;
};

using MpAttachCommandPayload =
    std::variant<MpAttachSayCommand, MpAttachPulseCommand, MpAttachNoticeCommand,
                 MpAttachRosterCommand, MpAttachPingCommand, MpAttachQuitCommand>;

struct MpAttachCommand {
  MpAttachCommandKind kind = MpAttachCommandKind::quit;
  MpAttachCommandPayload payload = MpAttachQuitCommand{};

  bool operator==(const MpAttachCommand &) const = default;
};

// Distinct non-mutually-convertible wrapper for default room scope so callers
// can pass string literals, std::string_view, or std::string ergonomically.
struct MpAttachRoomScopeRef {
  std::string_view value;
  constexpr MpAttachRoomScopeRef(std::string_view scope) noexcept : value(scope) {}
  constexpr MpAttachRoomScopeRef(const char *scope) noexcept
      : value(scope != nullptr ? scope : "") {}
  MpAttachRoomScopeRef(const std::string &scope) noexcept : value(scope) {}
};

// Strict JSONL command parser. Rejects lines > kMpAttachMaxCommandBytes,
// invalid UTF-8, non-object JSON, duplicate keys, unknown commands, invalid
// enum values, invalid device_id values, or oversized fields matching
// p2p_party_session.hpp limits.
Result<MpAttachCommand> parse_mp_attach_command(std::string_view line);

// Interactive human plain-line parser:
// - `/quit` or `/exit` -> quit
// - `/roster` -> roster
// - `/ping` -> ping
// - `/status <state> [text]` -> pulse
// - Empty or whitespace-only -> std::nullopt (ignore)
// - Any other non-empty line -> broadcast `say` with default_room_scope & "@all"
Result<std::optional<MpAttachCommand>> parse_mp_attach_plain_line(
    std::string_view line,
    MpAttachRoomScopeRef default_room_scope = kMpAttachDefaultRoomScope);

// ---------------------------------------------------------------------------
// Optional peer display metadata (handle / device_label resolved externally)
// ---------------------------------------------------------------------------

struct MpPeerDisplayMetadata {
  std::string handle;
  std::string device_label;

  bool operator==(const MpPeerDisplayMetadata &) const = default;
};

using MpPeerMetadataMap = std::unordered_map<std::uint64_t, MpPeerDisplayMetadata>;

// ---------------------------------------------------------------------------
// Typed Event Serialization & Hostile-Text-Safe Human Formatting
// ---------------------------------------------------------------------------

Value mp_runtime_event_to_json(const MpRuntimeEvent &event,
                               const MpPartyRuntime &runtime,
                               const MpPeerMetadataMap *peer_metadata = nullptr);

Value mp_runtime_roster_to_json(const MpPartyRuntime &runtime,
                                const MpPeerMetadataMap *peer_metadata = nullptr);

// Formats any runtime event for terminal output. ALWAYS passes all untrusted
// remote text through party_chat_sanitize() to prevent terminal escape injection.
std::string
format_mp_runtime_event_human(const MpRuntimeEvent &event,
                              const MpPartyRuntime &runtime,
                              const MpPeerMetadataMap *peer_metadata = nullptr);

// ---------------------------------------------------------------------------
// Live Attach Loop Runner (POSIX poll + bounded line buffer + Lobby forward)
// ---------------------------------------------------------------------------

struct MpAttachConfig {
  MpAttachMode mode = MpAttachMode::jsonl;
  // POSIX file descriptor to read commands from, or -1 for listen-only mode.
  int input_fd = -1;
  // Callback receiving each emitted line (without trailing '\n').
  std::function<void(std::string_view)> emit_line;
  // Optional external stop flag (e.g. set by SIGINT/SIGTERM handler).
  std::atomic<bool> *stop_flag = nullptr;
  // Bounded pump/poll tick interval in milliseconds (clamped to [1, 1000]).
  std::uint32_t tick_ms = kMpAttachDefaultTickMs;
  // When true, EOF on input_fd terminates the loop cleanly; when false
  // (default interactive/daemon mode), EOF switches to listen-only mode.
  bool exit_on_eof = false;
  // Default room_scope used by plain-mode chat lines.
  std::string default_room_scope = std::string{kMpAttachDefaultRoomScope};
  // Optional sender_handle override for outbound chat messages.
  // Defaults to runtime.config().identity.handle when present.
  std::optional<std::string> local_sender_handle = std::nullopt;
  // Optional local in-RAM PartyLobbyServer socket + room_id. When both are set,
  // incoming verified chat_received events are forwarded best-effort via
  // PartyLobbyClient::post_message(...) without ever touching party.json.
  std::optional<std::filesystem::path> local_party_socket = std::nullopt;
  std::optional<std::string> local_party_room_id = std::nullopt;
  // Optional resolved handle/device_label metadata keyed by device_id.
  MpPeerMetadataMap peer_metadata;
  // Optional wall-clock override for deterministic runtime pump tests.
  std::optional<std::int64_t> now_s_override = std::nullopt;
};

struct MpAttachSummary {
  MpRuntimeState final_state = MpRuntimeState::terminated;
  std::string close_reason;
  std::uint64_t events_emitted = 0U;
  std::uint64_t commands_processed = 0U;
  std::uint64_t command_errors = 0U;
  std::uint64_t lobby_forwards_succeeded = 0U;
  std::uint64_t lobby_forwards_failed = 0U;

  bool operator==(const MpAttachSummary &) const = default;
};

// Convenience emitter that writes each line + '\n' and flushes the stream.
std::function<void(std::string_view)> make_mp_attach_ostream_emitter(std::ostream &out);

class MpPartyAttachRunner {
public:
  MpPartyAttachRunner(MpPartyRuntime &runtime, MpAttachConfig config);

  MpPartyAttachRunner(const MpPartyAttachRunner &) = delete;
  MpPartyAttachRunner &operator=(const MpPartyAttachRunner &) = delete;
  MpPartyAttachRunner(MpPartyAttachRunner &&) = delete;
  MpPartyAttachRunner &operator=(MpPartyAttachRunner &&) = delete;
  ~MpPartyAttachRunner() = default;

  Result<MpAttachSummary> run();

private:
  MpPartyRuntime &runtime_;
  MpAttachConfig config_;
};

Result<MpAttachSummary> run_mp_party_attach_loop(MpPartyRuntime &runtime,
                                                 MpAttachConfig config);

} // namespace blackbird
