#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/mp_client.hpp"
#include "blackbird/mp_protocol.hpp"
#include "blackbird/party_chat.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

namespace blackbird {

// ---------------------------------------------------------------------------
// Constants & error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t kMpRoomV2DefaultPollMs = 40U;
inline constexpr std::uint32_t kMpRoomV2DefaultPingIntervalMs = 20000U;
inline constexpr std::uint32_t kMpRoomV2DefaultReconnectBaseMs = 250U;
inline constexpr std::uint32_t kMpRoomV2DefaultReconnectMaxMs = 15000U;
inline constexpr std::size_t kMpRoomV2DefaultMaxRetainedMessages = 512U;
inline constexpr std::size_t kMpRoomV2MaxRetainedMessagesCap = 4096U;
inline constexpr std::size_t kMpRoomV2MaxRetainedNotices = 256U;
inline constexpr std::size_t kMpRoomV2MaxPendingOutbox = 256U;

enum class MpRoomV2Error : std::int64_t {
  none = 0,
  invalid_config = 2300,
  session_stopped = 2301,
  queue_full = 2302,
  invalid_field = 2303,
  field_too_large = 2304,
  invalid_utf8 = 2305,
  wake_pipe_failed = 2306,
  protocol_error = 2307,
};

constexpr MpRoomV2Error mp_room_v2_error_of(const Error &error) noexcept {
  return static_cast<MpRoomV2Error>(error.detail);
}

std::string_view mp_room_v2_error_name(MpRoomV2Error detail) noexcept;

enum class MpRoomV2State : std::uint8_t {
  connecting = 0,
  live = 1,
  reconnecting = 2,
  disconnected = 3,
  stopped = 4,
};

std::string_view mp_room_v2_state_name(MpRoomV2State state) noexcept;

// Non-swappable target wrapper so callers can pass literals/strings cleanly.
struct MpRoomV2Target {
  std::string value;

  MpRoomV2Target() : value("@all") {}
  MpRoomV2Target(std::string target) : value(std::move(target)) {}
  MpRoomV2Target(std::string_view target) : value(target) {}
  MpRoomV2Target(const char *target) : value(target != nullptr ? target : "@all") {}
};

struct MpRoomV2AgentCard {
  std::string title;
  std::string summary;
  std::vector<std::string> files;

  bool operator==(const MpRoomV2AgentCard &) const = default;
};

struct MpRoomV2StatusUpdate {
  std::string client = "blackbird";
  std::string agent_name = "Blackbird";
  std::string agent_state = "idle";
  std::string agent_summary;

  bool operator==(const MpRoomV2StatusUpdate &) const = default;
};

struct MpRoomV2Member {
  mp::AccountId account_id = mp::AccountId::create(1U).value();
  std::string handle;
  std::string client;
  std::string agent_name;
  std::string agent_state;
  std::string agent_summary;
  std::string status = "live";
  bool is_self = false;

  bool operator==(const MpRoomV2Member &) const = default;
};

struct MpRoomV2Message {
  std::uint64_t seq = 0U;
  std::uint64_t ts_ms = 0U;
  std::string client_msg_id;
  std::optional<mp::AccountId> sender_account_id;
  std::string sender_handle;
  std::string sender_client;
  std::string sender_agent_name;
  std::string target = "@all";
  std::string kind = "chat";
  std::string body_encoding = "utf8";
  std::string body;
  std::string rendered_body;
  bool delivered = false;
  bool local_self = false;

  bool operator==(const MpRoomV2Message &) const = default;
};

struct MpRoomV2Config {
  mp::MpClientConfig client_config;
  mp::MpIdentityState identity;
  mp::PartyId party_id = mp::PartyId::create(1U).value();
  std::string ws_path;
  std::string room_code;
  std::string room_name;
  std::string share_url;
  std::string client_name = "blackbird";
  std::string agent_name = "Blackbird";
  std::vector<mp::RoomMemberInfo> initial_members;
  std::uint32_t poll_interval_ms = kMpRoomV2DefaultPollMs;
  std::uint32_t ping_interval_ms = kMpRoomV2DefaultPingIntervalMs;
  std::uint32_t reconnect_base_ms = kMpRoomV2DefaultReconnectBaseMs;
  std::uint32_t reconnect_max_ms = kMpRoomV2DefaultReconnectMaxMs;
  std::size_t max_retained_messages = kMpRoomV2DefaultMaxRetainedMessages;
};

struct MpRoomV2Snapshot {
  bool active = false;
  MpRoomV2State state = MpRoomV2State::stopped;
  mp::PartyId party_id = mp::PartyId::create(1U).value();
  std::string room_code;
  std::string room_name;
  std::string share_url;
  std::uint64_t latest_seq = 0U;
  std::size_t queued_send_count = 0U;
  std::vector<MpRoomV2Member> members;
  std::vector<MpRoomV2Message> messages;
  std::vector<std::string> notices;
  std::string status_summary;

  bool operator==(const MpRoomV2Snapshot &) const = default;
};

// ---------------------------------------------------------------------------
// Live Room Protocol v2 (`mp2`) Session Controller (Pure WSS over TLS 1.3)
// ---------------------------------------------------------------------------

class MpRoomV2Session {
private:
  struct PrivateTag {};

  struct OutboundMessage {
    std::string client_msg_id;
    std::string kind;
    std::string target;
    std::string body_encoding;
    std::string body;
    bool sent_on_current_socket = false;
  };

  struct InitParams {
    MpRoomV2Config config;
    mp::MpControlClient client;
    mp::MpControlSocket socket;
    std::string ws_path;
    std::string local_handle;
    int wake_read_fd = -1;
    int wake_write_fd = -1;
  };

public:
  // Connects the `mp2` TLS 1.3 WebSocket, initializes the non-blocking wake pipe,
  // and starts the dedicated background worker std::jthread.
  static Result<std::unique_ptr<MpRoomV2Session>> start(MpRoomV2Config config);

  MpRoomV2Session(PrivateTag, InitParams params);

  MpRoomV2Session(const MpRoomV2Session &) = delete;
  MpRoomV2Session &operator=(const MpRoomV2Session &) = delete;
  MpRoomV2Session(MpRoomV2Session &&) = delete;
  MpRoomV2Session &operator=(MpRoomV2Session &&) = delete;
  ~MpRoomV2Session();

  // Non-blocking wake pipe fd for TUI poll() integration. Returns -1 after stop().
  int wake_fd() const noexcept;
  void drain_wake() noexcept;

  // Optimistic idempotent sends: immediately render in local feed and queue for
  // guaranteed delivery (retrying across reconnects with the same client_msg_id).
  Result<std::string> send_chat(std::string body,
                                MpRoomV2Target target = MpRoomV2Target{});
  Result<std::string> send_agent_card(const MpRoomV2AgentCard &card,
                                      MpRoomV2Target target = MpRoomV2Target{});
  Result<void> update_status(MpRoomV2StatusUpdate status);

  // Thread-safe snapshots (snapshot() drains accumulated plain-English notices;
  // to_party_snapshot() renders PartyChatPane-compatible state with real @handles).
  MpRoomV2Snapshot snapshot();
  PartySnapshot to_party_snapshot() const;

  // Thread-safe accessors.
  bool is_active() const noexcept;
  MpRoomV2State state() const noexcept;
  mp::PartyId party_id() const noexcept { return party_id_; }
  std::string room_code() const;
  std::string share_url() const;
  std::uint64_t latest_seq() const noexcept;

  // Idempotent noexcept shutdown: closes socket, joins worker thread, closes pipe.
  void stop() noexcept;

private:
  using SteadyClock = std::chrono::steady_clock;

  struct FrameAction {
    bool need_send_resume = false;
    std::uint64_t resume_seq = 0U;
    bool need_flush_outbox = false;
    std::uint32_t retry_backoff_ms = 0U;
  };

  void start_worker();
  void worker_loop(const std::stop_token &stop_token);
  void handle_text_frame_locked(std::string_view json_text, FrameAction &action);
  void handle_hello_locked(const Value &obj, FrameAction &action);
  void handle_event_locked(const Value &obj);
  void handle_ack_locked(const Value &obj);
  void handle_presence_locked(const Value &obj);
  void handle_error_locked(const Value &obj, FrameAction &action);
  void apply_members_locked(const std::vector<MpRoomV2Member> &members);
  void upsert_message_locked(MpRoomV2Message msg);
  void push_notice_locked(std::string_view notice);
  void rebuild_status_summary_locked();
  bool send_resume_frame(mp::MpControlSocket &sock, std::uint64_t last_seq);
  bool flush_outbox(mp::MpControlSocket &sock);
  bool flush_pending_status(mp::MpControlSocket &sock);
  std::uint32_t compute_reconnect_backoff_ms(std::uint32_t attempt) const noexcept;
  bool try_acquire_wake_user() noexcept;
  void release_wake_user() noexcept;
  void signal_wake() noexcept;
  void close_wake_pipe() noexcept;

  // Owned exclusively by worker_thread_ once started.
  mp::MpControlClient client_;
  std::optional<mp::MpControlSocket> socket_;

  // Immutable session config.
  mp::PartyId party_id_;
  std::optional<mp::AccountId> local_account_id_;
  std::string ws_path_;
  std::string local_handle_;
  std::string client_name_;
  std::string agent_name_;
  std::size_t max_retained_messages_ = kMpRoomV2DefaultMaxRetainedMessages;
  std::uint32_t poll_interval_ms_ = kMpRoomV2DefaultPollMs;
  std::uint32_t ping_interval_ms_ = kMpRoomV2DefaultPingIntervalMs;
  std::uint32_t reconnect_base_ms_ = kMpRoomV2DefaultReconnectBaseMs;
  std::uint32_t reconnect_max_ms_ = kMpRoomV2DefaultReconnectMaxMs;

  // Wake pipe & lifecycle protection.
  std::mutex lifecycle_mu_;
  std::atomic<std::uint64_t> wake_users_{0U};

  // Shared state protected by state_mu_.
  mutable std::mutex state_mu_;
  MpRoomV2State state_ = MpRoomV2State::connecting;
  std::string room_code_;
  std::string room_name_;
  std::string share_url_;
  std::uint64_t latest_seq_ = 0U;
  std::vector<MpRoomV2Member> members_;
  std::deque<MpRoomV2Message> messages_;
  std::unordered_set<std::uint64_t> seen_seqs_;
  std::unordered_set<std::string> seen_client_msg_ids_;
  std::deque<OutboundMessage> outbox_;
  std::optional<MpRoomV2StatusUpdate> pending_status_;
  std::deque<std::string> notices_;
  std::string status_summary_;
  bool connected_once_ = false;
  std::uint64_t local_msg_counter_ = 0U;

  std::atomic<int> wake_read_fd_{-1};
  std::atomic<int> wake_write_fd_{-1};
  std::atomic<bool> stop_requested_{false};
  std::atomic<bool> stopped_{false};
  std::atomic<std::uint64_t> latest_seq_atomic_{0U};

  // Declared last so it joins first on destruction.
  std::jthread worker_thread_;
};

} // namespace blackbird
