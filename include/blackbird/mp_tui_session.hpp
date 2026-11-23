#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/mp_party_bridge.hpp"
#include "blackbird/mp_party_runtime.hpp"
#include "blackbird/mp_protocol.hpp"
#include "blackbird/p2p_party_session.hpp"
#include "blackbird/party_chat.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace blackbird {

// ---------------------------------------------------------------------------
// Constants & error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t kMpTuiMinPumpTickMs = 5U;
inline constexpr std::uint32_t kMpTuiMaxPumpTickMs = 250U;
inline constexpr std::uint32_t kMpTuiDefaultPumpTickMs = 35U;
inline constexpr std::size_t kMpTuiDefaultMaxRetainedMessages = 512U;
inline constexpr std::size_t kMpTuiMaxRetainedMessagesCap = 4096U;
inline constexpr std::size_t kMpTuiMaxRetainedNotices = 256U;
inline constexpr std::size_t kMpTuiMaxPendingCommands = 256U;
inline constexpr std::uint32_t kMpTuiDefaultSendTimeoutMs = 5000U;
inline constexpr std::string_view kMpTuiDefaultRoomScope = "party/online";

enum class MpTuiSessionError : std::int64_t {
  none = 0,
  invalid_config = 2200,
  session_stopped = 2201,
  queue_full = 2202,
  invalid_field = 2203,
  field_too_large = 2204,
  invalid_utf8 = 2205,
  wake_pipe_failed = 2206,
  send_timeout = 2207,
};

constexpr MpTuiSessionError mp_tui_session_error_of(const Error &error) noexcept {
  return static_cast<MpTuiSessionError>(error.detail);
}

std::string_view mp_tui_session_error_name(MpTuiSessionError detail) noexcept;

// Distinct non-mutually-convertible wrapper for chat target selector so callers
// can pass string literals, std::string_view, or std::string cleanly without
// swappable-parameter ambiguity next to the message body.
struct MpTuiChatTarget {
  std::string value;

  MpTuiChatTarget() : value("@all") {}
  MpTuiChatTarget(std::string target) : value(std::move(target)) {}
  MpTuiChatTarget(std::string_view target) : value(target) {}
  MpTuiChatTarget(const char *target) : value(target != nullptr ? target : "@all") {}
};

// ---------------------------------------------------------------------------
// Configuration & Snapshot DTOs
// ---------------------------------------------------------------------------

struct MpTuiSessionConfig {
  MpPartyRuntimeConfig runtime_config;
  std::string room_scope = std::string{kMpTuiDefaultRoomScope};
  std::optional<std::string> local_handle = std::nullopt;
  MpPeerMetadataMap peer_metadata{};
  // Background pump tick interval in milliseconds (clamped to [5, 250]).
  std::uint32_t pump_tick_ms = kMpTuiDefaultPumpTickMs;
  // Bounded ring capacity for retained PartyMessage entries ([1, 4096]).
  std::size_t max_retained_messages = kMpTuiDefaultMaxRetainedMessages;
  // Optional wall-clock override for deterministic tests (nullopt = live clock).
  std::optional<std::int64_t> now_s_override = std::nullopt;
};

struct MpTuiSessionSnapshot {
  bool active = false;
  MpRuntimeState state = MpRuntimeState::terminated;
  mp::PartyId party_id = mp::PartyId::create(1U).value();
  std::uint64_t party_epoch = 0U;
  std::string room_scope;
  std::vector<PartyParticipant> participants;
  std::vector<PartyMessage> messages;
  std::vector<std::string> notices;
  std::string status_summary;

  bool operator==(const MpTuiSessionSnapshot &) const = default;
};

// ---------------------------------------------------------------------------
// Live Non-Blocking Online Party TUI Session Controller
// ---------------------------------------------------------------------------

class MpTuiSession {
private:
  struct PrivateTag {};

  struct PendingCommand {
    enum class Kind : std::uint8_t {
      chat = 1,
      pulse = 2,
      ping = 3,
    };

    Kind kind = Kind::ping;
    std::string body;
    std::string target;
    std::optional<mp::DeviceId> target_device = std::nullopt;
    P2pPartyActivityState pulse_state = P2pPartyActivityState::online;
    std::string pulse_status;
    std::shared_ptr<std::promise<Result<P2pPartyBroadcastResult>>> chat_promise;
  };

  struct PeerPulseInfo {
    P2pPartyActivityState activity_state = P2pPartyActivityState::online;
    std::string status;
    std::int64_t updated_ns = 0;
  };

  struct InitParams {
    MpPartyRuntime runtime;
    std::string room_scope;
    std::string local_wire_handle;
    std::string local_display_handle;
    MpPeerMetadataMap peer_metadata{};
    std::uint32_t pump_tick_ms = kMpTuiDefaultPumpTickMs;
    std::size_t max_retained_messages = kMpTuiDefaultMaxRetainedMessages;
    std::optional<std::int64_t> now_s_override = std::nullopt;
    int wake_read_fd = -1;
    int wake_write_fd = -1;
  };

public:
  // Attaches MpPartyRuntime, creates the non-blocking wakeup pipe, and starts
  // the dedicated background worker std::jthread. Fails cleanly without leaking
  // threads or file descriptors if config is invalid or attach fails.
  static Result<std::unique_ptr<MpTuiSession>> start(MpTuiSessionConfig config);

  MpTuiSession(PrivateTag, InitParams params);

  MpTuiSession(const MpTuiSession &) = delete;
  MpTuiSession &operator=(const MpTuiSession &) = delete;
  MpTuiSession(MpTuiSession &&) = delete;
  MpTuiSession &operator=(MpTuiSession &&) = delete;
  ~MpTuiSession();

  // Read end of the non-blocking O_NONBLOCK|O_CLOEXEC wakeup self-pipe for
  // integration into terminal.cpp's poll() loop. Returns -1 after stop().
  int wake_fd() const noexcept;

  // Drains all pending wakeup bytes from wake_fd() without blocking.
  void drain_wake() noexcept;

  // Non-blocking outbound dispatch (enqueues to the worker thread; never blocks
  // the TUI event loop on network or iroh QUIC I/O).
  Result<void> post_chat(std::string body, MpTuiChatTarget target = MpTuiChatTarget{},
                         std::optional<mp::DeviceId> target_device = std::nullopt);
  Result<void> post_pulse(P2pPartyActivityState state, std::string status = {});
  Result<void> post_ping();

  // Bounded-timeout synchronous convenience wrapper around the worker queue.
  Result<P2pPartyBroadcastResult>
  send_chat(std::string body, MpTuiChatTarget target = MpTuiChatTarget{},
            std::uint32_t timeout_ms = kMpTuiDefaultSendTimeoutMs);

  // Thread-safe peer display metadata update (keyed by authenticated DeviceId).
  // Rebuilds participants immediately with hostile-escape sanitization and
  // signals wake_fd().
  void update_peer_metadata(mp::DeviceId device_id, MpPeerDisplayMetadata meta);

  // Returns a mutex-protected snapshot of current participants, bounded message
  // ring, status summary, and DRAINS any accumulated lifecycle notices.
  MpTuiSessionSnapshot snapshot();

  // Returns a PartyChatPane-compatible PartySnapshot without draining notices.
  PartySnapshot to_party_snapshot() const;

  // Thread-safe state & endpoint accessors.
  bool is_active() const noexcept;
  MpRuntimeState state() const noexcept;
  mp::PartyId party_id() const noexcept { return party_id_; }
  std::optional<P2pPubkey> local_pubkey() const noexcept { return local_pubkey_; }
  std::optional<mp::EndpointDescriptor> local_endpoint_descriptor() const;

  // Idempotent, noexcept shutdown: signals stop, joins the background worker
  // thread (which calls runtime_.shutdown()), and closes wakeup pipe FDs.
  void stop() noexcept;

private:
  void start_worker();
  void worker_loop(const std::stop_token &stop_token);
  bool execute_command(PendingCommand &cmd);
  void handle_runtime_event_locked(const MpRuntimeEvent &event);
  void sync_runtime_metadata_locked();
  void rebuild_participants_locked();
  void rebuild_status_summary_locked();
  void push_message_locked(PartyMessage message);
  void push_notice_locked(std::string_view notice);
  std::string resolve_authenticated_peer_handle_locked(mp::DeviceId device_id) const;
  std::string resolve_authenticated_peer_label_locked(mp::DeviceId device_id) const;
  std::string format_peer_label_locked(std::optional<mp::DeviceId> device_id) const;
  void fail_pending_commands_locked() noexcept;
  bool try_acquire_wake_user() noexcept;
  void release_wake_user() noexcept;
  void signal_wake() noexcept;
  void close_wake_pipe() noexcept;

  // Touched EXCLUSIVELY by worker_thread_ once start_worker() is called.
  MpPartyRuntime runtime_;

  // Immutable session configuration / identity metadata set during start().
  mp::PartyId party_id_;
  std::optional<mp::DeviceId> local_device_id_;
  std::optional<P2pPubkey> local_pubkey_;
  std::string local_fingerprint_;
  std::string room_scope_;
  std::string sanitized_room_scope_;
  std::string local_wire_handle_;
  std::string local_display_handle_;
  std::uint32_t pump_tick_ms_ = kMpTuiDefaultPumpTickMs;
  std::size_t max_retained_messages_ = kMpTuiDefaultMaxRetainedMessages;
  std::optional<std::int64_t> now_s_override_;

  // Lifecycle & wakeup pipe state.
  // `wake_users_` encodes a high closing bit + active in-flight non-blocking
  // wake FD user count so close_wake_pipe() strictly happens-after every
  // in-flight ::read()/::write() without risking FD-reuse corruption.
  std::mutex lifecycle_mu_;
  std::atomic<std::uint64_t> wake_users_{0U};
  std::atomic<int> wake_read_fd_{-1};
  std::atomic<int> wake_write_fd_{-1};
  std::atomic<bool> stop_requested_{false};
  std::atomic<bool> stopped_{false};

  // Shared TUI <-> worker state protected by state_mu_.
  mutable std::mutex state_mu_;
  MpRuntimeState state_ = MpRuntimeState::attaching;
  std::uint64_t party_epoch_ = 0U;
  std::optional<mp::DeviceId> leader_device_id_;
  std::optional<mp::EndpointDescriptor> local_endpoint_;
  MpPeerMetadataMap peer_metadata_;
  std::vector<P2pPartyPeer> last_roster_;
  std::unordered_map<std::uint64_t, PeerPulseInfo> peer_pulses_;
  P2pPartyActivityState local_activity_state_ = P2pPartyActivityState::online;
  std::vector<PartyParticipant> participants_;
  std::deque<PartyMessage> messages_;
  std::deque<std::string> notices_;
  std::string status_summary_;
  std::uint64_t next_message_seq_ = 1U;
  std::deque<PendingCommand> pending_commands_;

  // Declared last so it is destroyed first if anything bypasses stop().
  std::jthread worker_thread_;
};

} // namespace blackbird
