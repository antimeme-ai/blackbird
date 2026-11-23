#pragma once

#include "blackbird/board_bridge.hpp"
#include "blackbird/foundation.hpp"
#include "blackbird/party_chat.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/platoon_runner.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace blackbird {

inline constexpr int kPartyDispatchDefaultTimeoutMs = 60000;
inline constexpr int kPartyDispatchMaxTimeoutMs = 3600000;
inline constexpr std::size_t kPartyDispatchMaxOutputBytes = 512U * 1024U;
inline constexpr std::size_t kPartyDispatchMaxConcurrency = 8U;
inline constexpr std::size_t kPartyWatcherDefaultMaxReplies = 8U;
inline constexpr std::size_t kPartyWatcherHardMaxReplies = 64U;

enum class PartyDeliveryStatus : std::uint8_t {
  delivered,
  replied,
  timeout,
  error,
};

std::string_view party_delivery_status_name(PartyDeliveryStatus status) noexcept;

// Strict POSIX single-quote shell escaping (`'...'` with `'` -> `'\''`).
// Safe against all shell metacharacters, command substitution, and newlines.
std::string posix_shell_quote(std::string_view arg);

// Builds a minimal secret-free environment for SSH subprocesses containing only
// PATH, HOME, USER, LANG, SSH_AUTH_SOCK, and TERM.
std::vector<std::string> build_sanitized_ssh_env();

struct RemotePeerDispatchRequest {
  PartyParticipant target;
  std::string prompt;
  std::string raw_body;
  std::string room_scope;
  std::string local_actor;
  std::optional<PeerEnvelope> signed_envelope;
  std::string ssh_binary = "/usr/bin/ssh";
  std::string remote_blackbird_path = "~/.local/bin/blackbird";
  int timeout_ms = kPartyDispatchDefaultTimeoutMs;
  std::size_t max_output_bytes = kPartyDispatchMaxOutputBytes;
};

struct RemotePeerDispatchResult {
  PartyDeliveryStatus status = PartyDeliveryStatus::error;
  std::string reply_text;
  std::string error_detail;
  int exit_code = -1;
  std::optional<PeerEnvelope> reply_envelope;
  bool operator==(const RemotePeerDispatchResult &) const = default;
};

using RemotePeerExecutor =
    std::function<RemotePeerDispatchResult(const RemotePeerDispatchRequest &)>;

struct OnboardLeaderDispatchRequest {
  PartyParticipant target;
  std::string prompt;
  std::string raw_body;
  std::string room_scope;
  std::string local_actor;
  std::uint64_t board_seq = 0;
  int timeout_ms = kPartyDispatchDefaultTimeoutMs;
};

struct OnboardLeaderDispatchResult {
  PartyDeliveryStatus status = PartyDeliveryStatus::delivered;
  std::string reply_text;
  std::string error_detail;
  bool operator==(const OnboardLeaderDispatchResult &) const = default;
};

using OnboardLeaderExecutor =
    std::function<OnboardLeaderDispatchResult(const OnboardLeaderDispatchRequest &)>;

// Builds the POSIX-shell-escaped remote command string executed over SSH.
Result<std::string>
build_remote_blackbird_command(const RemotePeerDispatchRequest &request);

// Default production SSH transport executor using absolute-path posix_spawn
// (no PATH lookup), `-T -o BatchMode=yes -o ConnectTimeout=10 -- <target>`,
// secret-free environment, bounded output cap <= 512 KiB, and hard timeout.
RemotePeerDispatchResult
execute_remote_peer_ssh(const RemotePeerDispatchRequest &request,
                        const std::function<bool()> &cancelled = {});

struct PartyDispatchConfig {
  std::filesystem::path platoon_dir;
  std::filesystem::path bridge_dir;
  std::filesystem::path peers_dir;
  std::filesystem::path party_config_path;
  std::string local_actor = "operator";
  std::string room_scope;
  std::string ssh_binary = "/usr/bin/ssh";
  std::string remote_blackbird_path = "~/.local/bin/blackbird";
  int timeout_ms = kPartyDispatchDefaultTimeoutMs;
  std::size_t max_output_bytes = kPartyDispatchMaxOutputBytes;
  std::size_t max_concurrency = kPartyDispatchMaxConcurrency;
  PeerIdentityConfig peer_identity_config{};
  std::function<bool()> cancelled;
  RemotePeerExecutor remote_executor;
  OnboardLeaderExecutor onboard_executor;
  // Optional live PlatoonRunner used when onboard_executor is unset.
  PlatoonRunner *platoon_runner = nullptr;
  std::filesystem::path working_dir;
  std::filesystem::path sessions_dir;

  static PartyDispatchConfig for_project(const std::filesystem::path &project_root);
};

struct PartyTargetOutcome {
  std::string target_id;
  bool remote = false;
  PartyDeliveryStatus status = PartyDeliveryStatus::delivered;
  std::string reply_text;
  std::string error_detail;
  std::optional<std::string> signed_outbound_envelope_id;
  std::optional<std::uint64_t> reply_board_seq;
  bool reply_verified = false;
  bool untrusted_remote = false;
  std::int64_t elapsed_ms = 0;
  bool operator==(const PartyTargetOutcome &) const = default;
};

struct PartyDispatchReport {
  PartyMode mode = PartyMode::single_operator;
  std::string room_scope;
  std::string target_label = "@all";
  std::string body;
  std::uint64_t operator_board_seq = 0;
  bool local_identity_available = false;
  std::vector<PartyTargetOutcome> outcomes;
  std::vector<std::string> unknown_targets;

  bool has_unknown_targets() const noexcept { return !unknown_targets.empty(); }
  std::size_t replied_count() const noexcept;
  std::size_t delivered_count() const noexcept;
  std::size_t failed_count() const noexcept;
  bool operator==(const PartyDispatchReport &) const = default;
};

// Unified Party Fan-Out Dispatcher for onboard local platoon leaders and
// remote SSH colleagues.
class PartyDispatcher {
public:
  PartyDispatcher() = default;
  explicit PartyDispatcher(PartyDispatchConfig config) noexcept
      : config_(std::move(config)) {}

  const PartyDispatchConfig &config() const noexcept { return config_; }

  Result<PartyDispatchReport> dispatch(std::string_view raw_input) const;

  static Result<PartyDispatchReport>
  dispatch_party_message(std::string_view raw_input, const PartyDispatchConfig &cfg);

private:
  PartyDispatchConfig config_{};
};

Result<PartyDispatchReport> dispatch_party_message(std::string_view raw_input,
                                                   const PartyDispatchConfig &cfg);

// ---------------------------------------------------------------------------
// Live Bridge Auto-Responder (`PartyBridgeWatcher`)
// ---------------------------------------------------------------------------

// Distinct non-mutually-convertible view wrappers for WatcherResponder so
// responder callbacks avoid adjacent swappable string parameters.
struct WatchPeerAlias {
  std::string_view value;
  constexpr WatchPeerAlias(std::string_view alias) noexcept : value(alias) {}
  constexpr WatchPeerAlias(const char *alias) noexcept : value(alias ? alias : "") {}
  WatchPeerAlias(const std::string &alias) noexcept : value(alias) {}
};

struct WatchFencedPrompt {
  std::string_view value;
  constexpr WatchFencedPrompt(std::string_view prompt) noexcept : value(prompt) {}
  constexpr WatchFencedPrompt(const char *prompt) noexcept
      : value(prompt ? prompt : "") {}
  WatchFencedPrompt(const std::string &prompt) noexcept : value(prompt) {}
};

using WatcherResponder = std::function<Result<std::string>(
    WatchPeerAlias peer_alias, WatchFencedPrompt fenced_prompt)>;

struct PartyWatcherConfig {
  std::filesystem::path bridge_dir;
  std::filesystem::path peers_dir;
  std::string scope = std::string{kPartyDefaultScope};
  std::size_t max_replies_per_cycle = kPartyWatcherDefaultMaxReplies;
  bool require_signed_envelope = true;
  PeerIdentityConfig peer_identity_config{};
};

struct PartyWatchReplyRecord {
  std::string incoming_event_hash;
  std::string peer_alias;
  std::string peer_fingerprint;
  std::string reply_event_hash;
  std::string reply_envelope_id;
  std::string receipt_envelope_id;
  std::string reply_text;
  bool operator==(const PartyWatchReplyRecord &) const = default;
};

struct PartyWatchCycleReport {
  std::string scope;
  std::string local_fingerprint;
  std::size_t inspected = 0;
  std::size_t answered = 0;
  std::size_t skipped_own = 0;
  std::size_t skipped_unverified = 0;
  std::size_t skipped_already_seen = 0;
  std::size_t responder_errors = 0;
  bool capped_by_limit = false;
  std::vector<PartyWatchReplyRecord> replies;
  std::vector<PeerEnvelope> outbound_envelopes;
  bool operator==(const PartyWatchCycleReport &) const = default;
};

class PartyBridgeWatcher {
public:
  PartyBridgeWatcher() = default;

  Result<PartyWatchCycleReport>
  poll_and_respond_once(const PartyWatcherConfig &cfg,
                        const WatcherResponder &responder);

  std::size_t seen_count() const noexcept { return seen_event_hashes_.size(); }
  void reset_seen() noexcept { seen_event_hashes_.clear(); }

private:
  std::unordered_set<std::string> seen_event_hashes_;
};

} // namespace blackbird
