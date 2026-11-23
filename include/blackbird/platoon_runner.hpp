#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/value.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace blackbird {

enum class PlatoonPeerState : std::uint8_t { running, completed, failed, stopped };

const char *platoon_peer_state_name(PlatoonPeerState state) noexcept;

enum class PlatoonPeerDriver : std::uint8_t {
  blackbird,
  claude_code,
  codex,
  pi,
  antigravity,
  acp,
};

const char *platoon_driver_name(PlatoonPeerDriver driver) noexcept;
Result<PlatoonPeerDriver> parse_platoon_driver(std::string_view name) noexcept;
bool valid_platoon_peer_id(std::string_view id) noexcept;

struct PlatoonPeerSpec {
  std::string peer_id;
  std::string role;
  std::string provider;
  std::string model;
  std::optional<std::string> effort;
  std::optional<std::filesystem::path> workflow;
  std::filesystem::path working_dir;
  std::filesystem::path session_dir;
  std::string prompt;
  std::filesystem::path executable;
  std::vector<std::pair<std::string, std::string>> extra_env;
  std::size_t max_output_bytes = 256U * 1024U;
  PlatoonPeerDriver driver = PlatoonPeerDriver::blackbird;
  std::string owner_actor = "local";
  std::string command_room;
  std::string tool_allowlist;
  std::vector<std::string> extra_args;
};

struct PlatoonPeerSnapshot {
  std::string peer_id;
  std::string role;
  std::string provider;
  std::string model;
  std::filesystem::path working_dir;
  std::filesystem::path session_dir;
  PlatoonPeerState state = PlatoonPeerState::running;
  std::int64_t pid = -1;
  std::optional<int> exit_code;
  std::string output_tail;
  std::size_t output_bytes = 0;
  std::int64_t started_ns = 0;
  std::int64_t finished_ns = 0;
  PlatoonPeerDriver driver = PlatoonPeerDriver::blackbird;
  std::string owner_actor = "local";
  std::string command_room;
  std::string tool_allowlist;
};

Value to_value(const PlatoonPeerSnapshot &snapshot);

// Launches and supervises bounded concurrent Blackbird and external harness peer
// processes in isolated process groups with non-blocking output tail capture and
// guaranteed teardown.
class PlatoonRunner {
public:
  static constexpr std::size_t default_max_peers = 8;
  static constexpr std::size_t max_peers_limit = 16;
  static constexpr std::size_t default_max_output_bytes = 256U * 1024U;
  static constexpr std::size_t max_output_bytes_limit = 4U * 1024U * 1024U;
  static constexpr std::size_t max_extra_args = 32;
  static constexpr std::size_t max_extra_arg_bytes = 4U * 1024U;

  explicit PlatoonRunner(std::size_t max_peers = default_max_peers);
  ~PlatoonRunner();

  PlatoonRunner(const PlatoonRunner &) = delete;
  PlatoonRunner &operator=(const PlatoonRunner &) = delete;
  PlatoonRunner(PlatoonRunner &&) = delete;
  PlatoonRunner &operator=(PlatoonRunner &&) = delete;

  Result<PlatoonPeerSnapshot> spawn(const PlatoonPeerSpec &spec);
  std::vector<PlatoonPeerSnapshot> list() const;
  Result<PlatoonPeerSnapshot> snapshot(std::string_view peer_id) const;
  std::size_t active_count() const;
  std::size_t max_peers() const noexcept;

  // Sends SIGTERM to the peer's process group, escalates to SIGKILL after grace_ms,
  // reaps the peer, and returns its final snapshot.
  Result<PlatoonPeerSnapshot> stop(std::string_view peer_id, int grace_ms = 1500);

  // Waits up to timeout_ms for the peer to settle. Returns the peer snapshot on
  // settlement or on timeout (with state == PlatoonPeerState::running).
  Result<PlatoonPeerSnapshot> wait(std::string_view peer_id, int timeout_ms);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace blackbird
