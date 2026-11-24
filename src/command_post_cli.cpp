#include "blackbird/command_post_cli.hpp"

#include "blackbird/board_bridge.hpp"
#include "blackbird/brakes_policy.hpp"
#include "blackbird/bridge_relay.hpp"
#include "blackbird/capabilities.hpp"
#include "blackbird/cpu_arc.hpp"
#include "blackbird/doctor.hpp"
#include "blackbird/flight_deck_hero.hpp"
#include "blackbird/integration_vault.hpp"
#include "blackbird/integrations_runtime.hpp"
#include "blackbird/issues.hpp"
#include "blackbird/json.hpp"
#include "blackbird/jupyter_notebook.hpp"
#include "blackbird/lan_party_runtime.hpp"
#include "blackbird/lsp_client.hpp"
#include "blackbird/mcp_client.hpp"
#include "blackbird/mcp_server.hpp"
#include "blackbird/measure_harness.hpp"
#include "blackbird/metrics_consumer.hpp"
#include "blackbird/mp_client.hpp"
#include "blackbird/mp_party_bridge.hpp"
#include "blackbird/nvim_rpc.hpp"
#include "blackbird/os_sandbox.hpp"
#include "blackbird/party_chat.hpp"
#include "blackbird/party_lobby.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/platoon_runner.hpp"
#include "blackbird/project_memory.hpp"
#include "blackbird/saas_packs.hpp"
#include "blackbird/self_upgrade.hpp"
#include "blackbird/sqlite_embedded.hpp"
#include "blackbird/sqlite_workbench.hpp"
#include "blackbird/value.hpp"
#include "blackbird/worktree_lease.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <istream>
#include <limits>
#include <map>
#include <openssl/crypto.h>
#include <optional>
#include <ostream>
#include <poll.h>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#ifdef __APPLE__
#include <libproc.h>
#include <sys/proc.h>
#endif

namespace blackbird {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kMaxCliInputBytes = 4U * 1024U * 1024U;
constexpr std::size_t kDefaultSparklineWidth = 32U;
constexpr std::size_t kMaxSparklineWidth = 512U;
constexpr int kDefaultSpawnWaitMs = 30000;
constexpr int kDefaultStopGraceMs = 1500;
constexpr int kMaxStopGraceMs = 60000;
constexpr int kDefaultWaitTimeoutMs = 10000;
constexpr int kDefaultWaitPollMs = 50;
constexpr std::int64_t kProcessStartSkewGraceNs = 2'000'000'000LL;
constexpr std::int64_t kNanosecondsPerSecond = 1'000'000'000LL;
constexpr std::int64_t kDefaultPresenceTtlSec = 300;
constexpr std::int64_t kDefaultGrantTtlSec = 3600;
constexpr std::int64_t kMaxGrantTtlSec = 365LL * 24LL * 3600LL;
constexpr std::int64_t kDefaultInviteTtlSec = 3600;
constexpr std::int64_t kMaxInviteTtlSec = 365LL * 24LL * 3600LL;
constexpr std::uint32_t kDefaultGrantMaxTurns = 8;
constexpr std::uint64_t kDefaultGrantMaxTokens = 100000;

struct CliIo {
  std::istream &in;
  std::ostream &out;
  std::ostream &err;
};

int emit_json(CliIo io, const Value &value) {
  auto dumped = dump_json(value);
  if (!dumped.has_value()) {
    io.err << "blackbird: failed to serialize JSON: " << error_name(dumped.error().code)
           << '\n';
    return 1;
  }
  io.out << dumped.value() << '\n';
  if (!io.out) {
    io.err << "blackbird: failed to write stdout\n";
    return 1;
  }
  return 0;
}

int fail_usage(CliIo io, std::string_view message) {
  io.err << "blackbird: " << message << '\n';
  return 2;
}

int fail_message(CliIo io, std::string_view message) {
  io.err << "blackbird: " << message << '\n';
  return 1;
}

int fail_error(CliIo io, std::string_view context, Error error) {
  io.err << "blackbird " << context << ": " << error_name(error.code);
  if (error.detail != 0)
    io.err << " (" << error.detail << ')';
  io.err << '\n';
  return 1;
}

std::optional<std::uint64_t> parse_u64(std::string_view text) noexcept {
  if (text.empty())
    return std::nullopt;
  std::uint64_t value = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), value);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size())
    return std::nullopt;
  return value;
}

std::optional<std::int64_t> parse_i64(std::string_view text) noexcept {
  if (text.empty())
    return std::nullopt;
  std::int64_t value = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), value);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size())
    return std::nullopt;
  return value;
}

std::optional<std::size_t> parse_size(std::string_view text) noexcept {
  const auto parsed = parse_u64(text);
  if (!parsed.has_value() || *parsed > std::numeric_limits<std::size_t>::max())
    return std::nullopt;
  return static_cast<std::size_t>(*parsed);
}

std::optional<double> parse_nonnegative_double(std::string_view text) noexcept {
  if (text.empty())
    return std::nullopt;
  const char first = text.front();
  if (first == ' ' || first == '\t' || first == '\n' || first == '\r' ||
      first == '\v' || first == '\f') {
    return std::nullopt;
  }
  const std::string copy{text};
  char *end = nullptr;
  errno = 0;
  const double value = std::strtod(copy.c_str(), &end);
  if (errno != 0 || end != copy.c_str() + copy.size() || !std::isfinite(value) ||
      value < 0.0) {
    return std::nullopt;
  }
  return value;
}

std::optional<std::string> take_flag_value(std::span<char *> args, std::size_t &index,
                                           std::string_view flag, CliIo io) {
  if (index + 1 >= args.size()) {
    io.err << "blackbird: missing value for " << flag << '\n';
    return std::nullopt;
  }
  ++index;
  return std::string{args[index]};
}

fs::path to_absolute_preserving_segments(const fs::path &path) {
  if (path.empty() || path.is_absolute())
    return path;
  std::error_code ec;
  const fs::path cwd = fs::current_path(ec);
  if (ec)
    return path;
  return cwd / path;
}

std::optional<fs::path> default_peers_dir(CliIo io) {
  const char *home = std::getenv("HOME");
  if (home == nullptr || home[0] == '\0') {
    io.err << "blackbird: HOME is unset; pass --root/--peers DIR\n";
    return std::nullopt;
  }
  return fs::path{home} / ".local" / "share" / "blackbird" / "peers";
}

std::optional<std::string> read_file_bounded(const fs::path &path,
                                             std::size_t max_bytes, CliIo io) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    io.err << "blackbird: unable to open file: " << path.string() << '\n';
    return std::nullopt;
  }
  std::string out;
  std::array<char, 8192> buf{};
  while (file) {
    file.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    const auto got = static_cast<std::size_t>(file.gcount());
    if (got > max_bytes - out.size()) {
      io.err << "blackbird: input file exceeds size limit\n";
      return std::nullopt;
    }
    out.append(buf.data(), got);
  }
  return out;
}

std::optional<std::string> read_stream_bounded(std::istream &in, std::size_t max_bytes,
                                               CliIo io) {
  std::string out;
  std::array<char, 8192> buf{};
  while (in) {
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    const auto got = static_cast<std::size_t>(in.gcount());
    if (got > max_bytes - out.size()) {
      io.err << "blackbird: stdin payload exceeds size limit\n";
      return std::nullopt;
    }
    out.append(buf.data(), got);
  }
  return out;
}

std::int64_t wall_now_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return ns <= 0 ? 1 : static_cast<std::int64_t>(ns);
}

Value member_to_value(const PlatoonMember &m) {
  return Value::object({
      {"id", Value{m.id}},
      {"role", Value{m.role}},
      {"provider", Value{m.provider}},
      {"model", Value{m.model}},
      {"workspace", Value{m.workspace}},
      {"branch", Value{m.branch}},
      {"state", Value{std::string{platoon_member_state_name(m.state)}}},
      {"pid", Value{Number{m.pid}}},
      {"updated_ns", Value{Number{m.updated_ns}}},
      {"brief", Value{m.brief}},
  });
}

Value message_to_value(const PlatoonMessage &m) {
  Value::Array refs;
  refs.reserve(m.refs.size());
  for (const auto &ref : m.refs)
    refs.emplace_back(ref);
  return Value::object({
      {"seq", Value{Number{m.seq}}},
      {"timestamp_ns", Value{Number{m.timestamp_ns}}},
      {"from", Value{m.from}},
      {"to", Value{m.to}},
      {"kind", Value{std::string{platoon_message_kind_name(m.kind)}}},
      {"text", Value{m.text}},
      {"refs", Value{std::move(refs)}},
  });
}

Value worktree_info_to_value(const WorktreeLeaseInfo &info) {
  return Value::object({
      {"lease_id", Value{info.lease_id}},
      {"branch", Value{info.branch}},
      {"base_ref", Value{info.base_ref}},
      {"base_sha", Value{info.base_sha}},
      {"owner_id", Value{info.owner_id}},
      {"owner_pid", Value{Number{info.owner_pid}}},
      {"created_ns", Value{Number{info.created_ns}}},
      {"path", Value{info.path.string()}},
      {"head_sha", Value{info.head_sha}},
      {"dirty", Value{info.dirty}},
      {"commits_ahead", Value{Number{info.commits_ahead}}},
      {"owner_alive", Value{info.owner_alive}},
      {"worktree_present", Value{info.worktree_present}},
  });
}

Value revoked_grant_to_value(const RevokedGrantRecord &rec) {
  return Value::object({
      {"grant_id", Value{rec.grant_id}},
      {"revoked_at_ns", Value{Number{rec.revoked_at_ns}}},
      {"reason", Value{rec.reason}},
  });
}

bool is_terminal_member_state(PlatoonMemberState state) noexcept {
  return state == PlatoonMemberState::completed ||
         state == PlatoonMemberState::failed || state == PlatoonMemberState::stopped;
}

bool valid_nonnegative_pid(std::int64_t pid) noexcept {
  return pid >= 0 &&
         pid <= static_cast<std::int64_t>(std::numeric_limits<pid_t>::max());
}

bool valid_signalable_pid(std::int64_t pid) noexcept {
  return pid > 1 && pid <= static_cast<std::int64_t>(std::numeric_limits<pid_t>::max());
}

bool pid_alive_local(std::int64_t pid) noexcept {
  if (!valid_signalable_pid(pid))
    return false;
  return ::kill(static_cast<pid_t>(pid), 0) == 0;
}

struct MemberProcessIdentity {
  std::int64_t pid = 0;
  std::int64_t updated_ns = 0;
};

#ifdef __linux__
std::optional<std::int64_t> read_linux_boot_time_sec() noexcept {
  std::ifstream in{"/proc/stat"};
  if (!in)
    return std::nullopt;
  std::string line;
  while (std::getline(in, line)) {
    if (line.starts_with("btime ")) {
      std::int64_t btime = 0;
      const char *begin = line.data() + 6;
      const char *end = line.data() + line.size();
      const auto [ptr, ec] = std::from_chars(begin, end, btime);
      if (ec == std::errc{} && ptr != begin)
        return btime;
      return std::nullopt;
    }
  }
  return std::nullopt;
}
#endif

// Fail-closed ownership and start-time verification for `platoon stop` so a
// recycled PID, far-future poisoned record, or foreign-UID process is never signaled.
bool verify_platoon_member_process(const MemberProcessIdentity &proc) noexcept {
  if (!valid_signalable_pid(proc.pid) || proc.updated_ns <= 0)
    return false;
  constexpr std::int64_t kMaxSafeUpdatedNs =
      std::numeric_limits<std::int64_t>::max() - kProcessStartSkewGraceNs;
  const std::int64_t now_ns = wall_now_ns();
  if (proc.updated_ns > kMaxSafeUpdatedNs)
    return false;
  if (now_ns <= kMaxSafeUpdatedNs &&
      proc.updated_ns > now_ns + kProcessStartSkewGraceNs)
    return false;
  const std::int64_t max_allowed_start_ns = proc.updated_ns + kProcessStartSkewGraceNs;

  const auto target_pid = static_cast<pid_t>(proc.pid);
  if (target_pid == ::getpid())
    return false;
  if (::kill(target_pid, 0) != 0)
    return false;

  const uid_t self_uid = ::geteuid();
#ifdef __APPLE__
  struct proc_bsdinfo bsd{};
  const int sz = ::proc_pidinfo(static_cast<int>(target_pid), PROC_PIDTBSDINFO, 0, &bsd,
                                sizeof(bsd));
  if (sz != static_cast<int>(sizeof(bsd)))
    return false;
  if (bsd.pbi_status == SZOMB || bsd.pbi_uid != self_uid)
    return false;
  constexpr std::uint64_t kMaxStartSec =
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max() -
                                 kNanosecondsPerSecond) /
      static_cast<std::uint64_t>(kNanosecondsPerSecond);
  if (bsd.pbi_start_tvsec > kMaxStartSec || bsd.pbi_start_tvusec >= 1'000'000ULL)
    return false;
  const std::int64_t proc_start_ns =
      static_cast<std::int64_t>(bsd.pbi_start_tvsec) * kNanosecondsPerSecond +
      static_cast<std::int64_t>(bsd.pbi_start_tvusec) * 1'000LL;
  return proc_start_ns <= max_allowed_start_ns;
#elif defined(__linux__)
  try {
    const std::string proc_dir = "/proc/" + std::to_string(proc.pid);
    struct stat st{};
    if (::stat(proc_dir.c_str(), &st) != 0 || st.st_uid != self_uid)
      return false;

    std::ifstream stat_file{proc_dir + "/stat"};
    std::string stat_line;
    if (!stat_file || !std::getline(stat_file, stat_line))
      return false;
    const auto close_paren = stat_line.rfind(')');
    if (close_paren == std::string::npos || close_paren + 2 >= stat_line.size())
      return false;
    const char state = stat_line[close_paren + 2];
    if (state == 'Z' || state == 'X')
      return false;

    std::istringstream fields{stat_line.substr(close_paren + 2)};
    std::string token;
    std::uint64_t start_ticks = 0;
    bool parsed_start = false;
    for (int idx = 1; idx <= 20; ++idx) {
      if (!(fields >> token))
        break;
      if (idx == 20) {
        const auto [ptr, ec] =
            std::from_chars(token.data(), token.data() + token.size(), start_ticks);
        parsed_start = (ec == std::errc{} && ptr == token.data() + token.size());
      }
    }
    const long ticks_per_sec = ::sysconf(_SC_CLK_TCK);
    const auto btime = read_linux_boot_time_sec();
    if (!parsed_start || ticks_per_sec <= 0 || !btime.has_value() || *btime < 0)
      return false;
    const auto tps = static_cast<std::uint64_t>(ticks_per_sec);
    const std::uint64_t start_sec =
        static_cast<std::uint64_t>(*btime) + (start_ticks / tps);
    constexpr std::uint64_t kMaxStartSec =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max() -
                                   kNanosecondsPerSecond) /
        static_cast<std::uint64_t>(kNanosecondsPerSecond);
    if (start_sec > kMaxStartSec)
      return false;
    const std::int64_t proc_start_ns =
        static_cast<std::int64_t>(start_sec) * kNanosecondsPerSecond +
        static_cast<std::int64_t>((start_ticks % tps) *
                                  static_cast<std::uint64_t>(kNanosecondsPerSecond) /
                                  tps);
    return proc_start_ns <= max_allowed_start_ns;
  } catch (...) {
    return false;
  }
#else
  return false;
#endif
}

PlatoonMemberState member_state_from_peer(PlatoonPeerState state) noexcept {
  switch (state) {
  case PlatoonPeerState::running:
    return PlatoonMemberState::working;
  case PlatoonPeerState::completed:
    return PlatoonMemberState::completed;
  case PlatoonPeerState::failed:
    return PlatoonMemberState::failed;
  case PlatoonPeerState::stopped:
    return PlatoonMemberState::stopped;
  }
  return PlatoonMemberState::failed;
}

// ============================================================================
// 1. blackbird mcp
// ============================================================================

int run_mcp_cli(std::span<char *> args, CliIo io) {
  McpCommandPostConfig config;
  std::optional<fs::path> repo_dir;
  std::optional<fs::path> leases_dir;
  bool enable_runner = false;
  McpPlatoonPeerConfig runner_cfg;

  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird mcp [--board DIR] [--repo DIR] [--leases DIR] "
                "[--allow-root DIR]... [--max-peers N] [--max-total-spawns N] "
                "[--max-line-bytes N] [--working-root DIR] [--session-root DIR] "
                "[--executable PATH]\n";
      return 0;
    }
    if (arg == "--board") {
      auto val = take_flag_value(args, i, arg, io);
      if (!val.has_value())
        return 2;
      config.board_root = to_absolute_preserving_segments(fs::path{*val});
    } else if (arg == "--repo") {
      auto val = take_flag_value(args, i, arg, io);
      if (!val.has_value())
        return 2;
      repo_dir = to_absolute_preserving_segments(fs::path{*val});
    } else if (arg == "--leases") {
      auto val = take_flag_value(args, i, arg, io);
      if (!val.has_value())
        return 2;
      leases_dir = to_absolute_preserving_segments(fs::path{*val});
    } else if (arg == "--allow-root") {
      auto val = take_flag_value(args, i, arg, io);
      if (!val.has_value())
        return 2;
      enable_runner = true;
      runner_cfg.allowed_workspace_roots.push_back(
          to_absolute_preserving_segments(fs::path{*val}));
    } else if (arg == "--working-root") {
      auto val = take_flag_value(args, i, arg, io);
      if (!val.has_value())
        return 2;
      enable_runner = true;
      runner_cfg.working_root = to_absolute_preserving_segments(fs::path{*val});
    } else if (arg == "--session-root") {
      auto val = take_flag_value(args, i, arg, io);
      if (!val.has_value())
        return 2;
      enable_runner = true;
      runner_cfg.session_root = to_absolute_preserving_segments(fs::path{*val});
    } else if (arg == "--executable") {
      auto val = take_flag_value(args, i, arg, io);
      if (!val.has_value())
        return 2;
      enable_runner = true;
      runner_cfg.executable = to_absolute_preserving_segments(fs::path{*val});
    } else if (arg == "--max-peers") {
      auto val = take_flag_value(args, i, arg, io);
      if (!val.has_value())
        return 2;
      const auto parsed = parse_size(*val);
      if (!parsed.has_value() || *parsed == 0 ||
          *parsed > PlatoonRunner::max_peers_limit) {
        return fail_usage(io, "mcp: --max-peers must be between 1 and 16");
      }
      enable_runner = true;
      runner_cfg.max_peers = *parsed;
    } else if (arg == "--max-total-spawns") {
      auto val = take_flag_value(args, i, arg, io);
      if (!val.has_value())
        return 2;
      const auto parsed = parse_size(*val);
      if (!parsed.has_value() || *parsed == 0 || *parsed > kMcpMaxTotalSpawnsLimit) {
        return fail_usage(io, "mcp: --max-total-spawns must be between 1 and 1024");
      }
      enable_runner = true;
      runner_cfg.max_total_spawns = *parsed;
    } else if (arg == "--max-line-bytes") {
      auto val = take_flag_value(args, i, arg, io);
      if (!val.has_value())
        return 2;
      const auto parsed = parse_size(*val);
      if (!parsed.has_value() || *parsed < kMcpMinLineBytes ||
          *parsed > kMcpMaxLineBytesLimit) {
        return fail_usage(io, "mcp: --max-line-bytes out of range");
      }
      config.max_line_bytes = *parsed;
    } else {
      return fail_usage(io, "mcp: unknown option: " + std::string{arg});
    }
  }

  if (repo_dir.has_value()) {
    WorktreeLeaseConfig wt;
    wt.repo_root = *repo_dir;
    wt.lease_root =
        leases_dir.has_value() ? *leases_dir : (*repo_dir / ".blackbird" / "worktrees");
    config.worktree_lease = std::move(wt);
  } else if (leases_dir.has_value()) {
    return fail_usage(io, "mcp: --leases requires --repo");
  }

  if (enable_runner)
    config.platoon_runner = std::move(runner_cfg);

  auto server = McpCommandPostServer::open(std::move(config));
  if (!server.has_value())
    return fail_error(io, "mcp", server.error());
  return server.value().run_stdio(io.in, io.out);
}

// ============================================================================
// 2. blackbird platoon
// ============================================================================

int run_platoon_post(std::span<char *> args, CliIo io) {
  fs::path board_dir = fs::path{".blackbird"} / "platoon";
  PlatoonPost post;
  std::string kind_name = "message";
  bool has_from = false;
  bool has_text = false;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--board") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      board_dir = fs::path{*v};
    } else if (arg == "--from") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      post.from = *v;
      has_from = true;
    } else if (arg == "--to") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      post.to = *v;
    } else if (arg == "--kind") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      kind_name = *v;
    } else if (arg == "--text") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      post.text = *v;
      has_text = true;
    } else if (arg == "--ref") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      post.refs.push_back(*v);
    } else {
      return fail_usage(io, "platoon post: unknown option: " + std::string{arg});
    }
  }
  if (!has_from || !has_text)
    return fail_usage(io, "platoon post: --from and --text are required");
  auto kind = parse_platoon_message_kind(kind_name);
  if (!kind.has_value())
    return fail_usage(io, "platoon post: invalid --kind: " + kind_name);
  post.kind = kind.value();

  auto board = PlatoonBoard::open(board_dir);
  if (!board.has_value())
    return fail_error(io, "platoon post", board.error());
  auto posted = board.value().post(std::move(post));
  if (!posted.has_value())
    return fail_error(io, "platoon post", posted.error());
  return emit_json(io, message_to_value(posted.value()));
}

int run_platoon_read(std::span<char *> args, CliIo io) {
  fs::path board_dir = fs::path{".blackbird"} / "platoon";
  std::uint64_t after_seq = 0;
  std::size_t limit = kPlatoonDefaultReadLimit;
  std::string recipient;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--board") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      board_dir = fs::path{*v};
    } else if (arg == "--after-seq") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_u64(*v);
      if (!parsed.has_value())
        return fail_usage(io, "platoon read: invalid --after-seq");
      after_seq = *parsed;
    } else if (arg == "--limit") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value() || *parsed == 0 || *parsed > 1024U)
        return fail_usage(io, "platoon read: --limit must be 1..1024");
      limit = *parsed;
    } else if (arg == "--recipient") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      recipient = *v;
    } else {
      return fail_usage(io, "platoon read: unknown option: " + std::string{arg});
    }
  }

  auto board = PlatoonBoard::open(board_dir);
  if (!board.has_value())
    return fail_error(io, "platoon read", board.error());
  auto msgs = board.value().read_since(after_seq, limit, recipient);
  if (!msgs.has_value())
    return fail_error(io, "platoon read", msgs.error());
  auto latest = board.value().latest_seq();
  if (!latest.has_value())
    return fail_error(io, "platoon read", latest.error());

  Value::Array arr;
  arr.reserve(msgs.value().size());
  for (const auto &m : msgs.value())
    arr.push_back(message_to_value(m));

  return emit_json(
      io, Value::object({
              {"messages", Value{std::move(arr)}},
              {"latest_seq", Value{Number{latest.value()}}},
              {"count", Value{Number{static_cast<std::uint64_t>(msgs.value().size())}}},
          }));
}

int run_platoon_members(std::span<char *> args, CliIo io) {
  fs::path board_dir = fs::path{".blackbird"} / "platoon";
  bool upsert = false;
  PlatoonMember member;
  std::string state_name = "starting";

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--board") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      board_dir = fs::path{*v};
    } else if (arg == "--upsert") {
      upsert = true;
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      member.id = *v;
      upsert = true;
    } else if (arg == "--role") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      member.role = *v;
    } else if (arg == "--provider") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      member.provider = *v;
    } else if (arg == "--model") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      member.model = *v;
    } else if (arg == "--workspace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      member.workspace = *v;
    } else if (arg == "--branch") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      member.branch = *v;
    } else if (arg == "--state") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      state_name = *v;
    } else if (arg == "--pid") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || !valid_nonnegative_pid(*parsed))
        return fail_usage(io, "platoon members: invalid --pid");
      member.pid = *parsed;
    } else if (arg == "--brief") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      member.brief = *v;
    } else {
      return fail_usage(io, "platoon members: unknown option: " + std::string{arg});
    }
  }

  auto board = PlatoonBoard::open(board_dir);
  if (!board.has_value())
    return fail_error(io, "platoon members", board.error());

  if (upsert) {
    if (member.id.empty())
      return fail_usage(io, "platoon members: --id is required for --upsert");
    auto parsed_state = parse_platoon_member_state(state_name);
    if (!parsed_state.has_value())
      return fail_usage(io, "platoon members: invalid --state: " + state_name);
    member.state = parsed_state.value();
    auto saved = board.value().upsert_member(member);
    if (!saved.has_value())
      return fail_error(io, "platoon members", saved.error());
    return emit_json(io, member_to_value(saved.value()));
  }

  auto list = board.value().members();
  if (!list.has_value())
    return fail_error(io, "platoon members", list.error());
  Value::Array arr;
  arr.reserve(list.value().size());
  for (const auto &m : list.value())
    arr.push_back(member_to_value(m));
  return emit_json(
      io, Value::object({
              {"members", Value{std::move(arr)}},
              {"count", Value{Number{static_cast<std::uint64_t>(list.value().size())}}},
          }));
}

int run_platoon_status(std::span<char *> args, CliIo io) {
  fs::path board_dir = fs::path{".blackbird"} / "platoon";
  std::optional<fs::path> repo_dir;
  std::optional<fs::path> leases_dir;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--board") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      board_dir = fs::path{*v};
    } else if (arg == "--repo") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      repo_dir = fs::path{*v};
    } else if (arg == "--leases") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      leases_dir = fs::path{*v};
    } else {
      return fail_usage(io, "platoon status: unknown option: " + std::string{arg});
    }
  }

  auto board = PlatoonBoard::open(board_dir);
  if (!board.has_value())
    return fail_error(io, "platoon status", board.error());
  auto members = board.value().members();
  if (!members.has_value())
    return fail_error(io, "platoon status", members.error());
  auto latest = board.value().latest_seq();
  if (!latest.has_value())
    return fail_error(io, "platoon status", latest.error());

  Value::Array members_arr;
  members_arr.reserve(members.value().size());
  for (const auto &m : members.value())
    members_arr.push_back(member_to_value(m));

  Value::Array leases_arr;
  if (repo_dir.has_value()) {
    const fs::path abs_repo = to_absolute_preserving_segments(*repo_dir);
    const fs::path abs_leases = leases_dir.has_value()
                                    ? to_absolute_preserving_segments(*leases_dir)
                                    : (abs_repo / ".blackbird" / "worktrees");
    auto wt =
        WorktreeLeaseManager::open({abs_repo, abs_leases, kDefaultMaxWorktreeLeases});
    if (!wt.has_value())
      return fail_error(io, "platoon status", wt.error());
    auto leases = wt.value().list();
    if (!leases.has_value())
      return fail_error(io, "platoon status", leases.error());
    leases_arr.reserve(leases.value().size());
    for (const auto &info : leases.value())
      leases_arr.push_back(worktree_info_to_value(info));
  }

  return emit_json(
      io,
      Value::object({
          {"board_root", Value{board.value().root().string()}},
          {"latest_seq", Value{Number{latest.value()}}},
          {"member_count",
           Value{Number{static_cast<std::uint64_t>(members.value().size())}}},
          {"members", Value{std::move(members_arr)}},
          {"lease_count", Value{Number{static_cast<std::uint64_t>(leases_arr.size())}}},
          {"leases", Value{std::move(leases_arr)}},
      }));
}

int run_platoon_lease_acquire(std::span<char *> args, CliIo io) {
  fs::path repo_dir = ".";
  std::optional<fs::path> leases_dir;
  std::size_t max_leases = kDefaultMaxWorktreeLeases;
  WorktreeLeaseRequest req;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--repo") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      repo_dir = fs::path{*v};
    } else if (arg == "--leases") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      leases_dir = fs::path{*v};
    } else if (arg == "--max-leases") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value() || *parsed < kMinWorktreeLeases ||
          *parsed > kMaxWorktreeLeases) {
        return fail_usage(io, "platoon lease-acquire: invalid --max-leases");
      }
      max_leases = *parsed;
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.lease_id = *v;
    } else if (arg == "--branch") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.branch = *v;
    } else if (arg == "--base-ref") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.base_ref = *v;
    } else if (arg == "--owner") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.owner_id = *v;
    } else if (arg == "--owner-pid") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || !valid_nonnegative_pid(*parsed))
        return fail_usage(io, "platoon lease-acquire: invalid --owner-pid");
      req.owner_pid = *parsed;
    } else if (arg == "--use-existing-branch") {
      req.use_existing_branch = true;
    } else {
      return fail_usage(io,
                        "platoon lease-acquire: unknown option: " + std::string{arg});
    }
  }
  if (req.lease_id.empty() || req.branch.empty())
    return fail_usage(io, "platoon lease-acquire: --id and --branch are required");

  const fs::path abs_repo = to_absolute_preserving_segments(repo_dir);
  const fs::path abs_leases = leases_dir.has_value()
                                  ? to_absolute_preserving_segments(*leases_dir)
                                  : (abs_repo / ".blackbird" / "worktrees");
  auto mgr = WorktreeLeaseManager::open({abs_repo, abs_leases, max_leases});
  if (!mgr.has_value())
    return fail_error(io, "platoon lease-acquire", mgr.error());
  auto info = mgr.value().acquire(req);
  if (!info.has_value())
    return fail_error(io, "platoon lease-acquire", info.error());
  return emit_json(io, worktree_info_to_value(info.value()));
}

int run_platoon_lease_list(std::span<char *> args, CliIo io) {
  fs::path repo_dir = ".";
  std::optional<fs::path> leases_dir;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--repo") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      repo_dir = fs::path{*v};
    } else if (arg == "--leases") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      leases_dir = fs::path{*v};
    } else {
      return fail_usage(io, "platoon lease-list: unknown option: " + std::string{arg});
    }
  }

  const fs::path abs_repo = to_absolute_preserving_segments(repo_dir);
  const fs::path abs_leases = leases_dir.has_value()
                                  ? to_absolute_preserving_segments(*leases_dir)
                                  : (abs_repo / ".blackbird" / "worktrees");
  auto mgr =
      WorktreeLeaseManager::open({abs_repo, abs_leases, kDefaultMaxWorktreeLeases});
  if (!mgr.has_value())
    return fail_error(io, "platoon lease-list", mgr.error());
  auto leases = mgr.value().list();
  if (!leases.has_value())
    return fail_error(io, "platoon lease-list", leases.error());

  Value::Array arr;
  arr.reserve(leases.value().size());
  for (const auto &info : leases.value())
    arr.push_back(worktree_info_to_value(info));
  return emit_json(
      io,
      Value::object({
          {"leases", Value{std::move(arr)}},
          {"count", Value{Number{static_cast<std::uint64_t>(leases.value().size())}}},
      }));
}

int run_platoon_lease_release(std::span<char *> args, CliIo io) {
  fs::path repo_dir = ".";
  std::optional<fs::path> leases_dir;
  std::string lease_id;
  bool force = false;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--repo") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      repo_dir = fs::path{*v};
    } else if (arg == "--leases") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      leases_dir = fs::path{*v};
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      lease_id = *v;
    } else if (arg == "--force") {
      force = true;
    } else if (!arg.starts_with('-') && lease_id.empty()) {
      lease_id = std::string{arg};
    } else {
      return fail_usage(io,
                        "platoon lease-release: unknown option: " + std::string{arg});
    }
  }
  if (lease_id.empty())
    return fail_usage(io, "platoon lease-release: --id is required");

  const fs::path abs_repo = to_absolute_preserving_segments(repo_dir);
  const fs::path abs_leases = leases_dir.has_value()
                                  ? to_absolute_preserving_segments(*leases_dir)
                                  : (abs_repo / ".blackbird" / "worktrees");
  auto mgr =
      WorktreeLeaseManager::open({abs_repo, abs_leases, kDefaultMaxWorktreeLeases});
  if (!mgr.has_value())
    return fail_error(io, "platoon lease-release", mgr.error());
  auto res = mgr.value().release(lease_id, force);
  if (!res.has_value())
    return fail_error(io, "platoon lease-release", res.error());
  return emit_json(io, Value::object({
                           {"released", Value{true}},
                           {"lease_id", Value{lease_id}},
                           {"forced", Value{force}},
                       }));
}

int run_platoon_lease_reclaim(std::span<char *> args, CliIo io) {
  fs::path repo_dir = ".";
  std::optional<fs::path> leases_dir;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--repo") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      repo_dir = fs::path{*v};
    } else if (arg == "--leases") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      leases_dir = fs::path{*v};
    } else {
      return fail_usage(io,
                        "platoon lease-reclaim: unknown option: " + std::string{arg});
    }
  }

  const fs::path abs_repo = to_absolute_preserving_segments(repo_dir);
  const fs::path abs_leases = leases_dir.has_value()
                                  ? to_absolute_preserving_segments(*leases_dir)
                                  : (abs_repo / ".blackbird" / "worktrees");
  auto mgr =
      WorktreeLeaseManager::open({abs_repo, abs_leases, kDefaultMaxWorktreeLeases});
  if (!mgr.has_value())
    return fail_error(io, "platoon lease-reclaim", mgr.error());
  auto report = mgr.value().reclaim_stale();
  if (!report.has_value())
    return fail_error(io, "platoon lease-reclaim", report.error());

  Value::Array reclaimed;
  reclaimed.reserve(report.value().reclaimed.size());
  for (const auto &id : report.value().reclaimed)
    reclaimed.emplace_back(id);

  Value::Array orphaned;
  orphaned.reserve(report.value().orphaned_dirty.size());
  for (const auto &info : report.value().orphaned_dirty)
    orphaned.push_back(worktree_info_to_value(info));

  return emit_json(io, Value::object({
                           {"reclaimed", Value{std::move(reclaimed)}},
                           {"orphaned_dirty", Value{std::move(orphaned)}},
                       }));
}

int run_platoon_spawn(std::span<char *> args, CliIo io) {
  std::optional<fs::path> board_dir;
  PlatoonPeerSpec spec;
  std::string driver_name = "blackbird";
  int wait_ms = kDefaultSpawnWaitMs;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--board") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      board_dir = fs::path{*v};
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.peer_id = *v;
    } else if (arg == "--role") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.role = *v;
    } else if (arg == "--provider") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.provider = *v;
    } else if (arg == "--model") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.model = *v;
    } else if (arg == "--prompt") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.prompt = *v;
    } else if (arg == "--working-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.working_dir = to_absolute_preserving_segments(fs::path{*v});
    } else if (arg == "--session-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.session_dir = to_absolute_preserving_segments(fs::path{*v});
    } else if (arg == "--driver") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      driver_name = *v;
    } else if (arg == "--executable") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.executable = to_absolute_preserving_segments(fs::path{*v});
    } else if (arg == "--effort") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.effort = *v;
    } else if (arg == "--workflow") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.workflow = to_absolute_preserving_segments(fs::path{*v});
    } else if (arg == "--wait-ms") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed < 0 || *parsed > 3600000)
        return fail_usage(io, "platoon spawn: invalid --wait-ms");
      wait_ms = static_cast<int>(*parsed);
    } else if (arg == "--max-output-bytes") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value() || *parsed == 0 ||
          *parsed > PlatoonRunner::max_output_bytes_limit) {
        return fail_usage(io, "platoon spawn: invalid --max-output-bytes");
      }
      spec.max_output_bytes = *parsed;
    } else if (arg == "--owner-actor") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.owner_actor = *v;
    } else if (arg == "--command-room") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.command_room = *v;
    } else if (arg == "--tool-allowlist") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.tool_allowlist = *v;
    } else if (arg == "--extra-arg") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      spec.extra_args.push_back(*v);
    } else {
      return fail_usage(io, "platoon spawn: unknown option: " + std::string{arg});
    }
  }

  if (spec.peer_id.empty() || spec.role.empty() || spec.provider.empty() ||
      spec.model.empty() || spec.prompt.empty()) {
    return fail_usage(
        io,
        "platoon spawn: --id, --role, --provider, --model, and --prompt are required");
  }
  auto driver = parse_platoon_driver(driver_name);
  if (!driver.has_value())
    return fail_usage(io, "platoon spawn: invalid --driver: " + driver_name);
  spec.driver = driver.value();

  if (spec.working_dir.empty()) {
    std::error_code ec;
    spec.working_dir = fs::current_path(ec);
  }
  if (spec.session_dir.empty()) {
    if (!valid_platoon_peer_id(spec.peer_id))
      return fail_usage(io, "platoon spawn: invalid --id");
    const fs::path base =
        board_dir.has_value()
            ? to_absolute_preserving_segments(*board_dir)
            : to_absolute_preserving_segments(fs::path{".blackbird"} / "platoon");
    spec.session_dir = base / "sessions" / spec.peer_id;
  }

  std::optional<PlatoonBoard> board;
  if (board_dir.has_value()) {
    auto opened = PlatoonBoard::open(*board_dir);
    if (!opened.has_value())
      return fail_error(io, "platoon spawn", opened.error());
    board.emplace(std::move(opened).value());
    spec.extra_env.emplace_back("BLACKBIRD_PLATOON_BOARD", board->root().string());
  }
  spec.extra_env.emplace_back("BLACKBIRD_PLATOON_PEER_ID", spec.peer_id);
  spec.extra_env.emplace_back("BLACKBIRD_PLATOON_ROLE", spec.role);

  PlatoonRunner runner{1};
  auto spawned = runner.spawn(spec);
  if (!spawned.has_value())
    return fail_error(io, "platoon spawn", spawned.error());
  PlatoonPeerSnapshot snap = std::move(spawned).value();

  if (board.has_value()) {
    PlatoonMember member{
        snap.peer_id,
        snap.role,
        snap.provider,
        snap.model,
        snap.working_dir.string(),
        {},
        member_state_from_peer(snap.state),
        snap.pid,
        0,
        spec.prompt.substr(0, std::min<std::size_t>(spec.prompt.size(), 256U)),
    };
    (void)board->upsert_member(member);
  }

  if (wait_ms > 0) {
    auto waited = runner.wait(spec.peer_id, wait_ms);
    if (!waited.has_value())
      return fail_error(io, "platoon spawn", waited.error());
    snap = std::move(waited).value();
  }

  if (board.has_value()) {
    PlatoonMember member{
        snap.peer_id,
        snap.role,
        snap.provider,
        snap.model,
        snap.working_dir.string(),
        {},
        member_state_from_peer(snap.state),
        snap.pid,
        0,
        spec.prompt.substr(0, std::min<std::size_t>(spec.prompt.size(), 256U)),
    };
    (void)board->upsert_member(member);
  }

  return emit_json(io, to_value(snap));
}

int run_platoon_wait(std::span<char *> args, CliIo io) {
  fs::path board_dir = fs::path{".blackbird"} / "platoon";
  std::string peer_id;
  int timeout_ms = kDefaultWaitTimeoutMs;
  int poll_ms = kDefaultWaitPollMs;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--board") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      board_dir = fs::path{*v};
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peer_id = *v;
    } else if (arg == "--timeout-ms") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed < 0 || *parsed > 3600000)
        return fail_usage(io, "platoon wait: invalid --timeout-ms");
      timeout_ms = static_cast<int>(*parsed);
    } else if (arg == "--poll-ms") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed < 5 || *parsed > 5000)
        return fail_usage(io, "platoon wait: invalid --poll-ms");
      poll_ms = static_cast<int>(*parsed);
    } else if (!arg.starts_with('-') && peer_id.empty()) {
      peer_id = std::string{arg};
    } else {
      return fail_usage(io, "platoon wait: unknown option: " + std::string{arg});
    }
  }
  if (peer_id.empty())
    return fail_usage(io, "platoon wait: --id is required");

  auto board = PlatoonBoard::open(board_dir);
  if (!board.has_value())
    return fail_error(io, "platoon wait", board.error());

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
  for (;;) {
    auto found = board.value().member(peer_id);
    if (!found.has_value())
      return fail_error(io, "platoon wait", found.error());
    const auto &maybe_member = found.value();
    if (!maybe_member.has_value())
      return fail_error(io, "platoon wait", {ErrorCode::invalid_identity});

    const PlatoonMember &member = *maybe_member;
    const bool process_exited = (member.pid > 1) && !pid_alive_local(member.pid);
    const bool settled = is_terminal_member_state(member.state) || process_exited;
    if (settled || std::chrono::steady_clock::now() >= deadline) {
      return emit_json(
          io,
          Value::object({
              {"peer_id", Value{member.id}},
              {"state", Value{std::string{platoon_member_state_name(member.state)}}},
              {"settled", Value{settled}},
              {"pid", Value{Number{member.pid}}},
              {"member", member_to_value(member)},
          }));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{poll_ms});
  }
}

int run_platoon_stop(std::span<char *> args, CliIo io) {
  fs::path board_dir = fs::path{".blackbird"} / "platoon";
  std::string peer_id;
  int grace_ms = kDefaultStopGraceMs;
  bool signal_group = false;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--board") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      board_dir = fs::path{*v};
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peer_id = *v;
    } else if (arg == "--grace-ms") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed < 0 || *parsed > kMaxStopGraceMs)
        return fail_usage(io, "platoon stop: --grace-ms must be 0..60000");
      grace_ms = static_cast<int>(*parsed);
    } else if (arg == "--group") {
      signal_group = true;
    } else if (!arg.starts_with('-') && peer_id.empty()) {
      peer_id = std::string{arg};
    } else {
      return fail_usage(io, "platoon stop: unknown option: " + std::string{arg});
    }
  }
  if (peer_id.empty())
    return fail_usage(io, "platoon stop: --id is required");

  auto board = PlatoonBoard::open(board_dir);
  if (!board.has_value())
    return fail_error(io, "platoon stop", board.error());
  auto found = board.value().member(peer_id);
  if (!found.has_value())
    return fail_error(io, "platoon stop", found.error());
  const auto &maybe_member = found.value();
  if (!maybe_member.has_value())
    return fail_error(io, "platoon stop", {ErrorCode::invalid_identity});

  PlatoonMember member = *maybe_member;
  const MemberProcessIdentity proc{member.pid, member.updated_ns};
  bool signaled = false;
  if (verify_platoon_member_process(proc)) {
    const auto target_pid = static_cast<pid_t>(member.pid);
    const pid_t self_pgid = ::getpgrp();
    pid_t kill_target = target_pid;
    if (signal_group) {
      const pid_t target_pgid = ::getpgid(target_pid);
      if (target_pgid != -1 && target_pgid != self_pgid && target_pgid == target_pid)
        kill_target = -target_pid;
    }
    if (::kill(kill_target, SIGTERM) == 0)
      signaled = true;

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{grace_ms};
    while (verify_platoon_member_process(proc) &&
           std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    if (verify_platoon_member_process(proc)) {
      pid_t force_target = target_pid;
      if (signal_group) {
        const pid_t cur_pgid = ::getpgid(target_pid);
        if (cur_pgid != -1 && cur_pgid != self_pgid && cur_pgid == target_pid)
          force_target = -target_pid;
      }
      (void)::kill(force_target, SIGKILL);
    }
  }

  member.state = PlatoonMemberState::stopped;
  member.updated_ns = 0;
  auto saved = board.value().upsert_member(member);
  if (!saved.has_value())
    return fail_error(io, "platoon stop", saved.error());

  return emit_json(io, Value::object({
                           {"peer_id", Value{saved.value().id}},
                           {"pid", Value{Number{saved.value().pid}}},
                           {"state", Value{"stopped"}},
                           {"signaled", Value{signaled}},
                           {"group", Value{signal_group}},
                           {"member", member_to_value(saved.value())},
                       }));
}

int run_platoon_cli(std::span<char *> args, CliIo io) {
  if (args.size() < 2) {
    return fail_usage(
        io, "platoon: expected action (post|read|members|status|lease-acquire|"
            "lease-list|lease-release|lease-reclaim|spawn|wait|stop)");
  }
  const std::string_view action{args[1]};
  if (action == "--help" || action == "-h") {
    io.err << "usage: blackbird platoon {post|read|members|status|lease-acquire|"
              "lease-list|lease-release|lease-reclaim|spawn|wait|stop} [options]\n";
    return 0;
  }
  if (action == "post")
    return run_platoon_post(args, io);
  if (action == "read")
    return run_platoon_read(args, io);
  if (action == "members")
    return run_platoon_members(args, io);
  if (action == "status")
    return run_platoon_status(args, io);
  if (action == "lease-acquire")
    return run_platoon_lease_acquire(args, io);
  if (action == "lease-list")
    return run_platoon_lease_list(args, io);
  if (action == "lease-release")
    return run_platoon_lease_release(args, io);
  if (action == "lease-reclaim")
    return run_platoon_lease_reclaim(args, io);
  if (action == "spawn")
    return run_platoon_spawn(args, io);
  if (action == "wait")
    return run_platoon_wait(args, io);
  if (action == "stop")
    return run_platoon_stop(args, io);
  return fail_usage(io, "platoon: unknown action: " + std::string{action});
}

// ============================================================================
// 3. blackbird issues
// ============================================================================

int run_issues_create(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "issues";
  IssueCreateRequest req;
  std::string kind_name = "task";

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--title") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.title = *v;
    } else if (arg == "--body") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.body = *v;
    } else if (arg == "--kind") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      kind_name = *v;
    } else if (arg == "--priority") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed > kIssueMaxPriority)
        return fail_usage(io, "issues create: --priority must be 0..3");
      req.priority = static_cast<std::uint8_t>(*parsed);
    } else if (arg == "--assignee") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.assignee = *v;
    } else if (arg == "--label") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.labels.push_back(*v);
    } else if (arg == "--depends-on") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.depends_on.push_back(*v);
    } else {
      return fail_usage(io, "issues create: unknown option: " + std::string{arg});
    }
  }
  if (req.title.empty())
    return fail_usage(io, "issues create: --title is required");
  auto kind = parse_issue_kind(kind_name);
  if (!kind.has_value())
    return fail_usage(io, "issues create: invalid --kind: " + kind_name);
  req.kind = kind.value();

  auto store = IssueStore::open(root);
  if (!store.has_value())
    return fail_error(io, "issues create", store.error());
  auto created = store.value().create(std::move(req));
  if (!created.has_value())
    return fail_error(io, "issues create", created.error());
  return emit_json(io, to_json(created.value()));
}

int run_issues_list(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "issues";
  IssueQuery query;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--status") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_issue_status(*v);
      if (!parsed.has_value())
        return fail_usage(io, "issues list: invalid --status: " + *v);
      query.status = parsed.value();
    } else if (arg == "--kind") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_issue_kind(*v);
      if (!parsed.has_value())
        return fail_usage(io, "issues list: invalid --kind: " + *v);
      query.kind = parsed.value();
    } else if (arg == "--assignee") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      query.assignee = *v;
    } else if (arg == "--label") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      query.label = *v;
    } else if (arg == "--limit") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value())
        return fail_usage(io, "issues list: invalid --limit");
      query.limit = *parsed;
    } else if (arg == "--offset") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value())
        return fail_usage(io, "issues list: invalid --offset");
      query.offset = *parsed;
    } else {
      return fail_usage(io, "issues list: unknown option: " + std::string{arg});
    }
  }

  auto store = IssueStore::open(root);
  if (!store.has_value())
    return fail_error(io, "issues list", store.error());
  auto listed = store.value().list(query);
  if (!listed.has_value())
    return fail_error(io, "issues list", listed.error());

  Value::Array arr;
  arr.reserve(listed.value().size());
  for (const auto &rec : listed.value())
    arr.push_back(to_json(rec));
  return emit_json(
      io,
      Value::object({
          {"issues", Value{std::move(arr)}},
          {"count", Value{Number{static_cast<std::uint64_t>(listed.value().size())}}},
      }));
}

int run_issues_ready(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "issues";
  std::size_t limit = kIssueDefaultReadyLimit;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--limit") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value())
        return fail_usage(io, "issues ready: invalid --limit");
      limit = *parsed;
    } else {
      return fail_usage(io, "issues ready: unknown option: " + std::string{arg});
    }
  }

  auto store = IssueStore::open(root);
  if (!store.has_value())
    return fail_error(io, "issues ready", store.error());
  auto ready = store.value().ready(limit);
  if (!ready.has_value())
    return fail_error(io, "issues ready", ready.error());

  Value::Array arr;
  arr.reserve(ready.value().size());
  for (const auto &rec : ready.value())
    arr.push_back(to_json(rec));
  return emit_json(
      io,
      Value::object({
          {"issues", Value{std::move(arr)}},
          {"count", Value{Number{static_cast<std::uint64_t>(ready.value().size())}}},
      }));
}

int run_issues_show(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "issues";
  std::string id;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      id = *v;
    } else if (!arg.starts_with('-') && id.empty()) {
      id = std::string{arg};
    } else {
      return fail_usage(io, "issues show: unknown option: " + std::string{arg});
    }
  }
  if (id.empty())
    return fail_usage(io, "issues show: issue ID is required");

  auto store = IssueStore::open(root);
  if (!store.has_value())
    return fail_error(io, "issues show", store.error());
  auto rec = store.value().get(id);
  if (!rec.has_value())
    return fail_error(io, "issues show", rec.error());
  return emit_json(io, to_json(rec.value()));
}

int run_issues_claim(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "issues";
  std::string id;
  std::string actor;
  std::optional<std::uint64_t> expected_rev;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      id = *v;
    } else if (arg == "--actor") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      actor = *v;
    } else if (arg == "--expected-revision") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_u64(*v);
      if (!parsed.has_value())
        return fail_usage(io, "issues claim: invalid --expected-revision");
      expected_rev = *parsed;
    } else if (!arg.starts_with('-') && id.empty()) {
      id = std::string{arg};
    } else {
      return fail_usage(io, "issues claim: unknown option: " + std::string{arg});
    }
  }
  if (id.empty() || actor.empty())
    return fail_usage(io, "issues claim: issue ID and --actor are required");

  auto store = IssueStore::open(root);
  if (!store.has_value())
    return fail_error(io, "issues claim", store.error());
  auto claimed = store.value().claim(id, actor, expected_rev);
  if (!claimed.has_value())
    return fail_error(io, "issues claim", claimed.error());
  return emit_json(io, to_json(claimed.value()));
}

int run_issues_close(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "issues";
  std::string id;
  std::string reason;
  std::optional<std::uint64_t> expected_rev;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      id = *v;
    } else if (arg == "--reason") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      reason = *v;
    } else if (arg == "--expected-revision") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_u64(*v);
      if (!parsed.has_value())
        return fail_usage(io, "issues close: invalid --expected-revision");
      expected_rev = *parsed;
    } else if (!arg.starts_with('-') && id.empty()) {
      id = std::string{arg};
    } else {
      return fail_usage(io, "issues close: unknown option: " + std::string{arg});
    }
  }
  if (id.empty())
    return fail_usage(io, "issues close: issue ID is required");

  auto store = IssueStore::open(root);
  if (!store.has_value())
    return fail_error(io, "issues close", store.error());
  auto closed = store.value().close(id, reason, expected_rev);
  if (!closed.has_value())
    return fail_error(io, "issues close", closed.error());
  return emit_json(io, to_json(closed.value()));
}

int run_issues_dep_add(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "issues";
  std::string id;
  std::string blocker;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      id = *v;
    } else if (arg == "--blocker") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      blocker = *v;
    } else if (!arg.starts_with('-') && id.empty()) {
      id = std::string{arg};
    } else if (!arg.starts_with('-') && blocker.empty()) {
      blocker = std::string{arg};
    } else {
      return fail_usage(io, "issues dep-add: unknown option: " + std::string{arg});
    }
  }
  if (id.empty() || blocker.empty())
    return fail_usage(io, "issues dep-add: issue ID and --blocker ID are required");

  auto store = IssueStore::open(root);
  if (!store.has_value())
    return fail_error(io, "issues dep-add", store.error());
  auto updated = store.value().add_dependency(id, blocker);
  if (!updated.has_value())
    return fail_error(io, "issues dep-add", updated.error());
  return emit_json(io, to_json(updated.value()));
}

int run_issues_cli(std::span<char *> args, CliIo io) {
  if (args.size() < 2)
    return fail_usage(
        io, "issues: expected action (create|list|ready|show|claim|close|dep-add)");
  const std::string_view action{args[1]};
  if (action == "--help" || action == "-h") {
    io.err << "usage: blackbird issues {create|list|ready|show|claim|close|dep-add} "
              "[options]\n";
    return 0;
  }
  if (action == "create")
    return run_issues_create(args, io);
  if (action == "list")
    return run_issues_list(args, io);
  if (action == "ready")
    return run_issues_ready(args, io);
  if (action == "show")
    return run_issues_show(args, io);
  if (action == "claim")
    return run_issues_claim(args, io);
  if (action == "close")
    return run_issues_close(args, io);
  if (action == "dep-add")
    return run_issues_dep_add(args, io);
  return fail_usage(io, "issues: unknown action: " + std::string{action});
}

// ============================================================================
// 4. blackbird memory
// ============================================================================

int run_memory_record(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "memory";
  MemoryRecordRequest req;
  std::string kind_name = "finding";

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--kind") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      kind_name = *v;
    } else if (arg == "--title") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.title = *v;
    } else if (arg == "--body") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.body = *v;
    } else if (arg == "--actor") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.actor = *v;
    } else if (arg == "--tag") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.tags.push_back(*v);
    } else if (arg == "--session-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.session_id = *v;
    } else if (arg == "--source") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.sources.push_back(MemorySourcePin{*v, {}});
    } else if (arg == "--repo-root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.repo_root = fs::path{*v};
    } else if (arg == "--supersedes") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.supersedes = *v;
    } else {
      return fail_usage(io, "memory record: unknown option: " + std::string{arg});
    }
  }
  if (req.title.empty() || req.body.empty() || req.actor.empty())
    return fail_usage(io, "memory record: --title, --body, and --actor are required");
  auto kind = parse_memory_kind(kind_name);
  if (!kind.has_value())
    return fail_usage(io, "memory record: invalid --kind: " + kind_name);
  req.kind = kind.value();
  if (!req.sources.empty() && !req.repo_root.has_value()) {
    std::error_code ec;
    req.repo_root = fs::current_path(ec);
  }

  auto store = ProjectMemoryStore::open(root);
  if (!store.has_value())
    return fail_error(io, "memory record", store.error());
  auto recorded = store.value().record(std::move(req));
  if (!recorded.has_value())
    return fail_error(io, "memory record", recorded.error());
  return emit_json(io, to_value(recorded.value()));
}

int run_memory_recall(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "memory";
  MemoryRecallQuery query;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--query") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      query.query = *v;
    } else if (arg == "--kind") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_memory_kind(*v);
      if (!parsed.has_value())
        return fail_usage(io, "memory recall: invalid --kind: " + *v);
      query.kind = parsed.value();
    } else if (arg == "--tag") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      query.tag = *v;
    } else if (arg == "--include-superseded") {
      query.include_superseded = true;
    } else if (arg == "--limit") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value())
        return fail_usage(io, "memory recall: invalid --limit");
      query.limit = *parsed;
    } else if (arg == "--verify-root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      query.verify_root = fs::path{*v};
    } else if (!arg.starts_with('-') && query.query.empty()) {
      query.query = std::string{arg};
    } else {
      return fail_usage(io, "memory recall: unknown option: " + std::string{arg});
    }
  }

  auto store = ProjectMemoryStore::open(root);
  if (!store.has_value())
    return fail_error(io, "memory recall", store.error());
  auto hits = store.value().recall(query);
  if (!hits.has_value())
    return fail_error(io, "memory recall", hits.error());
  return emit_json(
      io, Value::object({
              {"hits", to_value(hits.value())},
              {"count", Value{Number{static_cast<std::uint64_t>(hits.value().size())}}},
          }));
}

int run_memory_recent(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "memory";
  std::size_t limit = kMemoryDefaultLimit;
  bool include_superseded = false;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--limit") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value())
        return fail_usage(io, "memory recent: invalid --limit");
      limit = *parsed;
    } else if (arg == "--include-superseded") {
      include_superseded = true;
    } else {
      return fail_usage(io, "memory recent: unknown option: " + std::string{arg});
    }
  }

  auto store = ProjectMemoryStore::open(root);
  if (!store.has_value())
    return fail_error(io, "memory recent", store.error());
  auto entries = store.value().recent(limit, include_superseded);
  if (!entries.has_value())
    return fail_error(io, "memory recent", entries.error());
  return emit_json(
      io,
      Value::object({
          {"entries", to_value(entries.value())},
          {"count", Value{Number{static_cast<std::uint64_t>(entries.value().size())}}},
      }));
}

int run_memory_get(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "memory";
  std::string id;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      id = *v;
    } else if (!arg.starts_with('-') && id.empty()) {
      id = std::string{arg};
    } else {
      return fail_usage(io, "memory get: unknown option: " + std::string{arg});
    }
  }
  if (id.empty())
    return fail_usage(io, "memory get: memory ID is required");

  auto store = ProjectMemoryStore::open(root);
  if (!store.has_value())
    return fail_error(io, "memory get", store.error());
  auto entry = store.value().get(id);
  if (!entry.has_value())
    return fail_error(io, "memory get", entry.error());
  const auto &maybe_entry = entry.value();
  if (!maybe_entry.has_value())
    return fail_error(io, "memory get", {ErrorCode::invalid_identity, ENOENT});
  return emit_json(io, to_value(*maybe_entry));
}

int run_memory_verify(std::span<char *> args, CliIo io) {
  fs::path root = fs::path{".blackbird"} / "memory";
  std::optional<fs::path> verify_root;
  std::string id;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--verify-root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      verify_root = fs::path{*v};
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      id = *v;
    } else if (!arg.starts_with('-') && id.empty()) {
      id = std::string{arg};
    } else {
      return fail_usage(io, "memory verify: unknown option: " + std::string{arg});
    }
  }
  if (id.empty())
    return fail_usage(io, "memory verify: memory ID is required");

  auto store = ProjectMemoryStore::open(root);
  if (!store.has_value())
    return fail_error(io, "memory verify", store.error());
  auto entry = store.value().get(id);
  if (!entry.has_value())
    return fail_error(io, "memory verify", entry.error());
  const auto &maybe_entry = entry.value();
  if (!maybe_entry.has_value())
    return fail_error(io, "memory verify", {ErrorCode::invalid_identity, ENOENT});

  fs::path target_root;
  if (verify_root.has_value()) {
    target_root = *verify_root;
  } else {
    std::error_code ec;
    target_root = fs::current_path(ec);
  }
  auto freshness = verify_memory_freshness(*maybe_entry, target_root);
  if (!freshness.has_value())
    return fail_error(io, "memory verify", freshness.error());

  return emit_json(
      io,
      Value::object({
          {"id", Value{maybe_entry->id}},
          {"freshness", Value{std::string{memory_freshness_name(freshness.value())}}},
          {"entry", to_value(*maybe_entry)},
      }));
}

int run_memory_cli(std::span<char *> args, CliIo io) {
  if (args.size() < 2)
    return fail_usage(io, "memory: expected action (record|recall|recent|get|verify)");
  const std::string_view action{args[1]};
  if (action == "--help" || action == "-h") {
    io.err << "usage: blackbird memory {record|recall|recent|get|verify} [options]\n";
    return 0;
  }
  if (action == "record")
    return run_memory_record(args, io);
  if (action == "recall")
    return run_memory_recall(args, io);
  if (action == "recent")
    return run_memory_recent(args, io);
  if (action == "get")
    return run_memory_get(args, io);
  if (action == "verify")
    return run_memory_verify(args, io);
  return fail_usage(io, "memory: unknown action: " + std::string{action});
}

// ============================================================================
// 5. blackbird peer
// ============================================================================

int run_peer_id(std::span<char *> args, CliIo io) {
  std::optional<fs::path> root;
  bool existing_only = false;
  PeerIdentityConfig cfg;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--existing-only") {
      existing_only = true;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else {
      return fail_usage(io, "peer id: unknown option: " + std::string{arg});
    }
  }

  if (!root.has_value()) {
    root = default_peers_dir(io);
    if (!root.has_value())
      return 1;
  }

  auto store = existing_only ? PeerIdentityStore::open_existing(*root, cfg)
                             : PeerIdentityStore::open_or_create(*root, cfg);
  if (!store.has_value())
    return fail_error(io, "peer id", store.error());
  return emit_json(io, Value::object({
                           {"root", Value{store.value().root().string()}},
                           {"fingerprint", Value{store.value().identity().fingerprint}},
                           {"public_key", Value{store.value().identity().public_key}},
                       }));
}

int run_peer_pin(std::span<char *> args, CliIo io) {
  std::optional<fs::path> root;
  PinPeerRequest req;
  std::optional<fs::path> key_file;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--alias") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.alias = *v;
    } else if (arg == "--public-key") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.public_key = *v;
    } else if (arg == "--public-key-file") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      key_file = fs::path{*v};
    } else if (arg == "--trust-note") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.trust_note = *v;
    } else {
      return fail_usage(io, "peer pin: unknown option: " + std::string{arg});
    }
  }
  if (key_file.has_value()) {
    auto content = read_file_bounded(*key_file, kPeerMaxPublicKeyBytes, io);
    if (!content.has_value())
      return 1;
    req.public_key = *content;
  }
  if (req.alias.empty() || req.public_key.empty())
    return fail_usage(io, "peer pin: --alias and --public-key are required");
  if (!root.has_value()) {
    root = default_peers_dir(io);
    if (!root.has_value())
      return 1;
  }

  auto store = KnownPeersStore::open(*root);
  if (!store.has_value())
    return fail_error(io, "peer pin", store.error());
  auto pinned = store.value().pin_peer(req);
  if (!pinned.has_value())
    return fail_error(io, "peer pin", pinned.error());
  return emit_json(io, peer_to_value(pinned.value()));
}

int run_peer_list(std::span<char *> args, CliIo io) {
  std::optional<fs::path> root;
  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else {
      return fail_usage(io, "peer list: unknown option: " + std::string{arg});
    }
  }
  if (!root.has_value()) {
    root = default_peers_dir(io);
    if (!root.has_value())
      return 1;
  }

  auto store = KnownPeersStore::open(*root);
  if (!store.has_value())
    return fail_error(io, "peer list", store.error());
  auto peers = store.value().list_peers();
  if (!peers.has_value())
    return fail_error(io, "peer list", peers.error());
  auto revoked = store.value().list_revoked_grants();
  if (!revoked.has_value())
    return fail_error(io, "peer list", revoked.error());

  Value::Array peers_arr;
  peers_arr.reserve(peers.value().size());
  for (const auto &p : peers.value())
    peers_arr.push_back(peer_to_value(p));

  Value::Array grants_arr;
  grants_arr.reserve(revoked.value().size());
  for (const auto &g : revoked.value())
    grants_arr.push_back(revoked_grant_to_value(g));

  return emit_json(
      io, Value::object({
              {"peers", Value{std::move(peers_arr)}},
              {"peer_count",
               Value{Number{static_cast<std::uint64_t>(peers.value().size())}}},
              {"revoked_grants", Value{std::move(grants_arr)}},
              {"revoked_grant_count",
               Value{Number{static_cast<std::uint64_t>(revoked.value().size())}}},
          }));
}

int run_peer_revoke_peer(std::span<char *> args, CliIo io) {
  std::optional<fs::path> root;
  PeerRevocationRequest req;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--fingerprint") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.fingerprint = *v;
    } else if (arg == "--reason") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.reason = *v;
    } else if (!arg.starts_with('-') && req.fingerprint.empty()) {
      req.fingerprint = std::string{arg};
    } else {
      return fail_usage(io, "peer revoke-peer: unknown option: " + std::string{arg});
    }
  }
  if (req.fingerprint.empty())
    return fail_usage(io, "peer revoke-peer: --fingerprint is required");
  if (!root.has_value()) {
    root = default_peers_dir(io);
    if (!root.has_value())
      return 1;
  }

  auto store = KnownPeersStore::open(*root);
  if (!store.has_value())
    return fail_error(io, "peer revoke-peer", store.error());
  auto revoked = store.value().revoke_peer(req);
  if (!revoked.has_value())
    return fail_error(io, "peer revoke-peer", revoked.error());
  return emit_json(io, peer_to_value(revoked.value()));
}

int run_peer_revoke_grant(std::span<char *> args, CliIo io) {
  std::optional<fs::path> root;
  GrantRevocationRequest req;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--grant-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.grant_id = *v;
    } else if (arg == "--reason") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      req.reason = *v;
    } else if (!arg.starts_with('-') && req.grant_id.empty()) {
      req.grant_id = std::string{arg};
    } else {
      return fail_usage(io, "peer revoke-grant: unknown option: " + std::string{arg});
    }
  }
  if (req.grant_id.empty())
    return fail_usage(io, "peer revoke-grant: --grant-id is required");
  if (!root.has_value()) {
    root = default_peers_dir(io);
    if (!root.has_value())
      return 1;
  }

  auto store = KnownPeersStore::open(*root);
  if (!store.has_value())
    return fail_error(io, "peer revoke-grant", store.error());
  auto revoked = store.value().revoke_grant(req);
  if (!revoked.has_value())
    return fail_error(io, "peer revoke-grant", revoked.error());
  return emit_json(io, revoked_grant_to_value(revoked.value()));
}

int run_peer_sign(std::span<char *> args, CliIo io) {
  std::optional<fs::path> root;
  PeerIdentityConfig cfg;
  PeerEnvelopeDraft draft;
  std::string kind_name = "mail";
  std::optional<std::string> payload_json;
  std::optional<std::string> text_body;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--to") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      draft.to_fingerprint = *v;
    } else if (arg == "--kind") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      kind_name = *v;
    } else if (arg == "--thread-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      draft.thread_id = *v;
    } else if (arg == "--envelope-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      draft.envelope_id = *v;
    } else if (arg == "--timestamp-ns") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed <= 0)
        return fail_usage(io, "peer sign: invalid --timestamp-ns");
      draft.timestamp_ns = *parsed;
    } else if (arg == "--payload-json") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      payload_json = *v;
    } else if (arg == "--text") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      text_body = *v;
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "peer sign: unknown option: " + std::string{arg});
    }
  }
  if (draft.to_fingerprint.empty())
    return fail_usage(io, "peer sign: --to is required");
  if (payload_json.has_value() && text_body.has_value())
    return fail_usage(io, "peer sign: specify only one of --payload-json or --text");

  auto kind = parse_peer_envelope_kind(kind_name);
  if (!kind.has_value())
    return fail_usage(io, "peer sign: invalid --kind: " + kind_name);
  draft.kind = kind.value();

  if (payload_json.has_value()) {
    auto parsed = parse_json(*payload_json);
    if (!parsed.has_value())
      return fail_error(io, "peer sign", parsed.error());
    draft.payload = std::move(parsed).value();
  } else if (text_body.has_value()) {
    draft.payload = Value::object({{"text", Value{*text_body}}});
  }

  if (!root.has_value()) {
    root = default_peers_dir(io);
    if (!root.has_value())
      return 1;
  }

  auto store = PeerIdentityStore::open_or_create(*root, cfg);
  if (!store.has_value())
    return fail_error(io, "peer sign", store.error());
  auto signed_env = store.value().sign_envelope(std::move(draft));
  if (!signed_env.has_value())
    return fail_error(io, "peer sign", signed_env.error());
  return emit_json(io, envelope_to_value(signed_env.value()));
}

bool is_strict_grant_object(const Value &value) noexcept {
  if (!std::holds_alternative<Value::Object>(value.value()))
    return false;
  if (value.find("envelope_id") != nullptr)
    return false;
  static constexpr std::array<std::string_view, 13> kRequiredGrantKeys{
      "version",
      "grant_id",
      "mode",
      "grantor_fingerprint",
      "grantee_fingerprint",
      "target_peer",
      "max_turns",
      "max_tokens",
      "allowed_tools",
      "issued_at_ns",
      "expires_at_ns",
      "revocable",
      "signature",
  };
  for (const std::string_view key : kRequiredGrantKeys) {
    if (value.find(key) == nullptr)
      return false;
  }
  return true;
}

int run_peer_verify(std::span<char *> args, CliIo io) {
  std::optional<fs::path> root;
  PeerIdentityConfig cfg;
  std::optional<std::string> input_json;
  std::optional<fs::path> input_file;
  std::optional<std::int64_t> now_ns;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--root") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root = fs::path{*v};
    } else if (arg == "--envelope-json" || arg == "--json") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      input_json = *v;
    } else if (arg == "--envelope-file" || arg == "--file") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      input_file = fs::path{*v};
    } else if (arg == "--now-ns") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed < 0)
        return fail_usage(io, "peer verify: invalid --now-ns");
      now_ns = *parsed;
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "peer verify: unknown option: " + std::string{arg});
    }
  }

  std::string raw_json;
  if (input_json.has_value()) {
    raw_json = *input_json;
  } else if (input_file.has_value()) {
    auto loaded = read_file_bounded(*input_file, kMaxCliInputBytes, io);
    if (!loaded.has_value())
      return 1;
    raw_json = std::move(*loaded);
  } else {
    auto loaded = read_stream_bounded(io.in, kMaxCliInputBytes, io);
    if (!loaded.has_value())
      return 1;
    raw_json = std::move(*loaded);
  }

  auto parsed = parse_json(raw_json);
  if (!parsed.has_value())
    return fail_error(io, "peer verify", parsed.error());
  if (!root.has_value()) {
    root = default_peers_dir(io);
    if (!root.has_value())
      return 1;
  }

  auto store = KnownPeersStore::open(*root, cfg);
  if (!store.has_value())
    return fail_error(io, "peer verify", store.error());

  if (is_strict_grant_object(parsed.value())) {
    auto grant = grant_from_value(parsed.value());
    if (!grant.has_value())
      return fail_error(io, "peer verify", grant.error());
    const std::int64_t check_time = now_ns.has_value() ? *now_ns : wall_now_ns();
    auto verified = store.value().verify_grant(grant.value(), check_time);
    if (!verified.has_value())
      return fail_error(io, "peer verify", verified.error());
    return emit_json(
        io, Value::object({
                {"verified", Value{true}},
                {"type", Value{"grant"}},
                {"grant_id", Value{grant.value().grant_id}},
                {"grantor_fingerprint", Value{grant.value().grantor_fingerprint}},
                {"grantee_fingerprint", Value{grant.value().grantee_fingerprint}},
            }));
  }

  auto env = envelope_from_value(parsed.value());
  if (!env.has_value())
    return fail_error(io, "peer verify", env.error());
  auto verified = store.value().verify_envelope(env.value());
  if (!verified.has_value())
    return fail_error(io, "peer verify", verified.error());
  return emit_json(
      io, Value::object({
              {"verified", Value{true}},
              {"type", Value{"envelope"}},
              {"envelope_id", Value{env.value().envelope_id}},
              {"from_fingerprint", Value{env.value().from_fingerprint}},
              {"to_fingerprint", Value{env.value().to_fingerprint}},
              {"kind", Value{std::string{peer_envelope_kind_name(env.value().kind)}}},
          }));
}

int run_peer_cli(std::span<char *> args, CliIo io) {
  if (args.size() < 2) {
    return fail_usage(
        io, "peer: expected action (id|pin|list|revoke-peer|revoke-grant|sign|verify)");
  }
  const std::string_view action{args[1]};
  if (action == "--help" || action == "-h") {
    io.err
        << "usage: blackbird peer {id|pin|list|revoke-peer|revoke-grant|sign|verify} "
           "[options]\n";
    return 0;
  }
  if (action == "id")
    return run_peer_id(args, io);
  if (action == "pin")
    return run_peer_pin(args, io);
  if (action == "list")
    return run_peer_list(args, io);
  if (action == "revoke-peer")
    return run_peer_revoke_peer(args, io);
  if (action == "revoke-grant")
    return run_peer_revoke_grant(args, io);
  if (action == "sign")
    return run_peer_sign(args, io);
  if (action == "verify")
    return run_peer_verify(args, io);
  return fail_usage(io, "peer: unknown action: " + std::string{action});
}

// ============================================================================
// 6. blackbird capabilities
// ============================================================================

CapabilityCatalogConfig finalize_capability_config(std::optional<fs::path> project_dir,
                                                   std::optional<fs::path> user_dir,
                                                   bool no_user) {
  CapabilityCatalogConfig cfg;
  if (project_dir.has_value()) {
    cfg.project_dir = std::move(project_dir);
  } else {
    std::error_code ec;
    const fs::path cwd = fs::current_path(ec);
    if (!ec)
      cfg.project_dir = default_project_skills_dir(cwd);
  }
  if (!no_user) {
    if (user_dir.has_value())
      cfg.user_dir = std::move(user_dir);
    else
      cfg.user_dir = default_user_skills_dir();
  }
  return cfg;
}

int run_capabilities_list(std::span<char *> args, CliIo io) {
  std::optional<fs::path> project_dir;
  std::optional<fs::path> user_dir;
  bool no_user = false;
  CapabilityListQuery query;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--project-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      project_dir = fs::path{*v};
    } else if (arg == "--user-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      user_dir = fs::path{*v};
    } else if (arg == "--no-user") {
      no_user = true;
    } else if (arg == "--kind") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_capability_kind(*v);
      if (!parsed.has_value())
        return fail_usage(io, "capabilities list: invalid --kind: " + *v);
      query.kind = parsed.value();
    } else if (arg == "--scope") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_capability_scope(*v);
      if (!parsed.has_value())
        return fail_usage(io, "capabilities list: invalid --scope: " + *v);
      query.scope = parsed.value();
    } else if (arg == "--text") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      query.text = *v;
    } else if (arg == "--limit") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value())
        return fail_usage(io, "capabilities list: invalid --limit");
      query.limit = *parsed;
    } else if (arg == "--offset") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value())
        return fail_usage(io, "capabilities list: invalid --offset");
      query.offset = *parsed;
    } else {
      return fail_usage(io, "capabilities list: unknown option: " + std::string{arg});
    }
  }

  auto catalog = CapabilityCatalog::open(
      finalize_capability_config(std::move(project_dir), std::move(user_dir), no_user));
  if (!catalog.has_value())
    return fail_error(io, "capabilities list", catalog.error());
  auto page = catalog.value().list(query);
  if (!page.has_value())
    return fail_error(io, "capabilities list", page.error());
  return emit_json(io, to_value(page.value()));
}

int run_capabilities_show(std::span<char *> args, CliIo io) {
  std::optional<fs::path> project_dir;
  std::optional<fs::path> user_dir;
  bool no_user = false;
  std::string id;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--project-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      project_dir = fs::path{*v};
    } else if (arg == "--user-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      user_dir = fs::path{*v};
    } else if (arg == "--no-user") {
      no_user = true;
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      id = *v;
    } else if (!arg.starts_with('-') && id.empty()) {
      id = std::string{arg};
    } else {
      return fail_usage(io, "capabilities show: unknown option: " + std::string{arg});
    }
  }
  if (id.empty())
    return fail_usage(io, "capabilities show: capability ID is required");

  auto catalog = CapabilityCatalog::open(
      finalize_capability_config(std::move(project_dir), std::move(user_dir), no_user));
  if (!catalog.has_value())
    return fail_error(io, "capabilities show", catalog.error());
  auto found = catalog.value().get(id);
  if (!found.has_value())
    return fail_error(io, "capabilities show", found.error());
  const auto &maybe_found = found.value();
  if (!maybe_found.has_value())
    return fail_error(io, "capabilities show", {ErrorCode::invalid_identity, ENOENT});
  return emit_json(io, to_value(*maybe_found));
}

int run_capabilities_expand(std::span<char *> args, CliIo io) {
  std::optional<fs::path> project_dir;
  std::optional<fs::path> user_dir;
  bool no_user = false;
  std::string id;
  std::map<std::string, std::string> params;
  std::optional<std::string> expected_sha;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--project-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      project_dir = fs::path{*v};
    } else if (arg == "--user-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      user_dir = fs::path{*v};
    } else if (arg == "--no-user") {
      no_user = true;
    } else if (arg == "--id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      id = *v;
    } else if (arg == "--param") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const std::size_t eq = v->find('=');
      if (eq == std::string::npos || eq == 0)
        return fail_usage(io, "capabilities expand: --param must be KEY=VALUE");
      params[v->substr(0, eq)] = v->substr(eq + 1);
    } else if (arg == "--expected-sha256") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      expected_sha = *v;
    } else if (!arg.starts_with('-') && id.empty()) {
      id = std::string{arg};
    } else {
      return fail_usage(io, "capabilities expand: unknown option: " + std::string{arg});
    }
  }
  if (id.empty())
    return fail_usage(io, "capabilities expand: capability ID is required");

  auto catalog = CapabilityCatalog::open(
      finalize_capability_config(std::move(project_dir), std::move(user_dir), no_user));
  if (!catalog.has_value())
    return fail_error(io, "capabilities expand", catalog.error());
  std::optional<std::string_view> sha_view;
  if (expected_sha.has_value())
    sha_view = std::string_view{*expected_sha};
  auto resolved = catalog.value().resolve(id, params, sha_view);
  if (!resolved.has_value())
    return fail_error(io, "capabilities expand", resolved.error());
  return emit_json(io, to_value(resolved.value()));
}

int run_capabilities_cli(std::span<char *> args, CliIo io) {
  if (args.size() < 2)
    return fail_usage(io, "capabilities: expected action (list|show|expand)");
  const std::string_view action{args[1]};
  if (action == "--help" || action == "-h") {
    io.err << "usage: blackbird capabilities {list|show|expand} [options]\n";
    return 0;
  }
  if (action == "list")
    return run_capabilities_list(args, io);
  if (action == "show")
    return run_capabilities_show(args, io);
  if (action == "expand")
    return run_capabilities_expand(args, io);
  return fail_usage(io, "capabilities: unknown action: " + std::string{action});
}

// ============================================================================
// 7. blackbird metrics
// ============================================================================

const MetricsSeries *select_metrics_series(const MetricsSnapshot &snap,
                                           std::string_view name) noexcept {
  if (name == "ttft_ms")
    return &snap.operations.ttft_ms;
  if (name == "total_latency_ms")
    return &snap.operations.total_latency_ms;
  if (name == "tool_duration_ms")
    return &snap.operations.tool_duration_ms;
  if (name == "tokens" || name == "token_spend")
    return &snap.usage.token_spend_series;
  if (name == "charge_usd")
    return &snap.usage.charge_usd_series;
  if (name == "estimated_usd")
    return &snap.usage.estimated_usd_series;
  if (name == "live_bytes")
    return &snap.context.live_bytes_series;
  if (name == "archived_bytes")
    return &snap.context.archived_bytes_series;
  if (name == "decision_latency_ms")
    return &snap.decision_companion.latency_ms;
  return nullptr;
}

int run_metrics_cli(std::span<char *> args, CliIo io) {
  if (args.size() < 2)
    return fail_usage(io, "metrics: expected action (summary|sparkline)");
  const std::string_view action{args[1]};
  if (action == "--help" || action == "-h") {
    io.err << "usage: blackbird metrics {summary|sparkline} (--jsonl FILE | "
              "--session DIR) [--series NAME] [--width N]\n";
    return 0;
  }
  if (action != "summary" && action != "sparkline")
    return fail_usage(io, "metrics: unknown action: " + std::string{action});

  std::optional<fs::path> jsonl_file;
  std::optional<fs::path> session_dir;
  std::string series_name = "total_latency_ms";
  std::size_t width = kDefaultSparklineWidth;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--jsonl") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      jsonl_file = fs::path{*v};
    } else if (arg == "--session") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      session_dir = fs::path{*v};
    } else if (action == "sparkline" && arg == "--series") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      series_name = *v;
    } else if (action == "sparkline" && arg == "--width") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_size(*v);
      if (!parsed.has_value() || *parsed == 0 || *parsed > kMaxSparklineWidth)
        return fail_usage(io, "metrics sparkline: --width must be 1..512");
      width = *parsed;
    } else {
      return fail_usage(io, "metrics: unknown option: " + std::string{arg});
    }
  }

  if (jsonl_file.has_value() == session_dir.has_value())
    return fail_usage(io,
                      "metrics: specify exactly one of --jsonl FILE or --session DIR");

  MetricsConsumer consumer =
      jsonl_file.has_value()
          ? MetricsConsumer::from_jsonl_file(*jsonl_file)
          : MetricsConsumer::from_token_usage_directory(*session_dir);
  auto refreshed = consumer.refresh();
  if (!refreshed.has_value())
    return fail_error(io, "metrics", refreshed.error());

  if (action == "summary")
    return emit_json(io, to_value(consumer.snapshot()));

  const MetricsSeries *series = select_metrics_series(consumer.snapshot(), series_name);
  if (series == nullptr)
    return fail_usage(io, "metrics sparkline: unknown --series: " + series_name);
  const MetricsSparkline spark = metrics_sparkline(*series, width);
  return emit_json(io, Value::object({
                           {"series", Value{series_name}},
                           {"unit", Value{series->unit}},
                           {"width", Value{Number{static_cast<std::uint64_t>(width)}}},
                           {"sparkline", to_value(spark)},
                       }));
}

// ============================================================================
// 8. blackbird bridge
// ============================================================================

struct RecipientResolveRequest {
  std::string_view target;
  std::string_view context;
  bool allow_broadcast = true;
};

std::optional<std::string> resolve_peer_recipient(const RecipientResolveRequest &req,
                                                  const KnownPeersStore &known_peers,
                                                  CliIo io) {
  if (req.allow_broadcast && req.target == "*")
    return std::string{"*"};
  if (valid_peer_fingerprint(req.target))
    return std::string{req.target};
  auto found = known_peers.find_by_alias(req.target);
  if (!found.has_value()) {
    (void)fail_error(io, req.context, found.error());
    return std::nullopt;
  }
  const auto &maybe_peer = found.value();
  if (!maybe_peer.has_value()) {
    io.err << "blackbird " << req.context << ": unknown peer alias: " << req.target
           << '\n';
    return std::nullopt;
  }
  if (maybe_peer->revoked) {
    io.err << "blackbird " << req.context << ": peer alias is revoked: " << req.target
           << '\n';
    return std::nullopt;
  }
  return maybe_peer->fingerprint;
}

Value conflict_to_value(const ConcurrentClaimConflict &conflict) {
  return Value::object({
      {"resource_scope", Value{conflict.resource_scope}},
      {"first_event_hash", Value{conflict.first_event_hash}},
      {"second_event_hash", Value{conflict.second_event_hash}},
      {"first_actor_id", Value{conflict.first_actor_id}},
      {"second_actor_id", Value{conflict.second_actor_id}},
  });
}

Value action_guard_to_value(const ActionGuardVerdict &verdict) {
  Value::Array hashes;
  hashes.reserve(verdict.blocking_event_hashes.size());
  for (const auto &hash : verdict.blocking_event_hashes)
    hashes.emplace_back(hash);
  return Value::object({
      {"allowed", Value{verdict.allowed}},
      {"blocking_event_hashes", Value{std::move(hashes)}},
      {"reason", Value{verdict.reason}},
  });
}

struct PumpReportExtras {
  std::optional<Value::Array> quoted_frames;
  std::optional<std::size_t> replayed_outbound;
};

Value pump_report_to_value(const BridgePumpReport &report,
                           PumpReportExtras extras = {}) {
  Value::Array env_ids;
  env_ids.reserve(report.accepted_envelope_ids.size());
  for (const auto &id : report.accepted_envelope_ids)
    env_ids.emplace_back(id);

  Value::Array event_hashes;
  event_hashes.reserve(report.accepted_event_hashes.size());
  for (const auto &hash : report.accepted_event_hashes)
    event_hashes.emplace_back(hash);

  Value::Object obj{
      {"accepted", Value{Number{static_cast<std::uint64_t>(report.accepted)}}},
      {"duplicates", Value{Number{static_cast<std::uint64_t>(report.duplicates)}}},
      {"rejected", Value{Number{static_cast<std::uint64_t>(report.rejected)}}},
      {"incomplete_trailing_frame", Value{report.incomplete_trailing_frame}},
      {"accepted_envelope_ids", Value{std::move(env_ids)}},
      {"accepted_event_hashes", Value{std::move(event_hashes)}},
  };
  if (extras.quoted_frames.has_value())
    obj.emplace_back("quoted_frames", Value{std::move(*extras.quoted_frames)});
  if (extras.replayed_outbound.has_value()) {
    obj.emplace_back(
        "replayed_outbound",
        Value{Number{static_cast<std::uint64_t>(*extras.replayed_outbound)}});
  }
  return Value::object(std::move(obj));
}

int run_bridge_send(std::span<char *> args, CliIo io) {
  fs::path bridge_dir = fs::path{".blackbird"} / "bridge";
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;
  std::string to_spec;
  std::string kind_name = "mail";
  std::string scope;
  std::string body;
  std::string thread_id;
  std::string event_kind;
  std::string envelope_id;
  std::vector<std::string> parents;
  bool has_body = false;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--bridge") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      bridge_dir = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--to") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      to_spec = *v;
    } else if (arg == "--kind") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      kind_name = *v;
    } else if (arg == "--scope") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      scope = *v;
    } else if (arg == "--body") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      body = *v;
      has_body = true;
    } else if (arg == "--thread" || arg == "--thread-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      thread_id = *v;
    } else if (arg == "--event-kind") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      event_kind = *v;
    } else if (arg == "--parent") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      parents.push_back(*v);
    } else if (arg == "--envelope-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      envelope_id = *v;
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge send: unknown option: " + std::string{arg});
    }
  }

  if (to_spec.empty() || scope.empty() || !has_body)
    return fail_usage(io, "bridge send: --to, --scope, and --body are required");
  auto kind = parse_peer_envelope_kind(kind_name);
  if (!kind.has_value())
    return fail_usage(io, "bridge send: invalid --kind: " + kind_name);

  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  auto identity = PeerIdentityStore::open_or_create(*peers_dir, cfg);
  if (!identity.has_value())
    return fail_error(io, "bridge send", identity.error());
  auto known_peers = KnownPeersStore::open(*peers_dir, cfg);
  if (!known_peers.has_value())
    return fail_error(io, "bridge send", known_peers.error());
  auto resolved_to =
      resolve_peer_recipient({to_spec, "bridge send", true}, known_peers.value(), io);
  if (!resolved_to.has_value())
    return 1;

  auto bridge = BoardBridge::open(bridge_dir);
  if (!bridge.has_value())
    return fail_error(io, "bridge send", bridge.error());

  const std::string &local_fp = identity.value().identity().fingerprint;
  auto latest_seq = bridge.value().latest_actor_seq(local_fp);
  if (!latest_seq.has_value())
    return fail_error(io, "bridge send", latest_seq.error());
  if (latest_seq.value() == std::numeric_limits<std::uint64_t>::max())
    return fail_error(io, "bridge send", {ErrorCode::overflow});

  CausalEventDraft event_draft;
  event_draft.actor_id = local_fp;
  event_draft.actor_seq = latest_seq.value() + 1;
  event_draft.causal_parents = std::move(parents);
  event_draft.resource_scope = scope;
  event_draft.kind = event_kind.empty() ? kind_name : event_kind;
  event_draft.payload = Value::object({{"body", Value{body}}});

  auto event = make_causal_event(std::move(event_draft));
  if (!event.has_value())
    return fail_error(io, "bridge send", event.error());

  PeerEnvelopeMeta meta;
  meta.envelope_id = std::move(envelope_id);
  meta.to_fingerprint = std::move(*resolved_to);
  meta.thread_id = std::move(thread_id);
  meta.kind = kind.value();

  auto signed_env = BoardBridge::sign_causal_event_envelope(
      identity.value(), event.value(), meta, Value::object({{"body", Value{body}}}));
  if (!signed_env.has_value())
    return fail_error(io, "bridge send", signed_env.error());

  auto sent = bridge.value().send_envelope(io.out, signed_env.value());
  if (!sent.has_value())
    return fail_error(io, "bridge send", sent.error());
  return 0;
}

int run_bridge_receive(std::span<char *> args, CliIo io) {
  fs::path bridge_dir = fs::path{".blackbird"} / "bridge";
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--bridge") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      bridge_dir = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge receive: unknown option: " + std::string{arg});
    }
  }

  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  auto known_peers = KnownPeersStore::open(*peers_dir, cfg);
  if (!known_peers.has_value())
    return fail_error(io, "bridge receive", known_peers.error());
  auto bridge = BoardBridge::open(bridge_dir);
  if (!bridge.has_value())
    return fail_error(io, "bridge receive", bridge.error());

  std::string owner_actor = "local-operator";
  auto local_id = PeerIdentityStore::open_existing(*peers_dir, cfg);
  if (local_id.has_value())
    owner_actor = local_id.value().identity().fingerprint;

  auto report = bridge.value().pump_inbound(io.in, known_peers.value());
  if (!report.has_value())
    return fail_error(io, "bridge receive", report.error());

  Value::Array quoted_frames;
  if (!report.value().accepted_envelope_ids.empty()) {
    auto all_envelopes = bridge.value().envelopes();
    if (!all_envelopes.has_value())
      return fail_error(io, "bridge receive", all_envelopes.error());

    std::unordered_map<std::string_view, const PeerEnvelope *> by_id;
    by_id.reserve(all_envelopes.value().size());
    for (const auto &env : all_envelopes.value())
      by_id[env.envelope_id] = &env;

    quoted_frames.reserve(report.value().accepted_envelope_ids.size());
    for (const auto &env_id : report.value().accepted_envelope_ids) {
      const auto it = by_id.find(env_id);
      if (it == by_id.end())
        continue;
      const PeerEnvelope &env = *it->second;
      PeerProvenance prov;
      prov.owner_actor = owner_actor;
      prov.requested_by_actor = env.from_fingerprint;
      prov.untrusted_sources.push_back("peer:" + env.from_fingerprint);
      auto peer_info = known_peers.value().find_by_fingerprint(env.from_fingerprint);
      if (peer_info.has_value()) {
        const auto &maybe_peer = peer_info.value();
        if (maybe_peer.has_value()) {
          prov.trust_note = maybe_peer->trust_note;
          if (!maybe_peer->alias.empty())
            prov.untrusted_sources.push_back("alias:" + maybe_peer->alias);
        }
      }
      auto framed = format_quoted_peer_frame(env, prov);
      if (!framed.has_value())
        return fail_error(io, "bridge receive", framed.error());
      quoted_frames.emplace_back(std::move(framed).value());
    }
  }

  return emit_json(io, pump_report_to_value(report.value(),
                                            {.quoted_frames = std::move(quoted_frames),
                                             .replayed_outbound = std::nullopt}));
}

int run_bridge_serve(std::span<char *> args, CliIo io) {
  fs::path bridge_dir = fs::path{".blackbird"} / "bridge";
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--bridge") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      bridge_dir = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge serve: unknown option: " + std::string{arg});
    }
  }

  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  auto known_peers = KnownPeersStore::open(*peers_dir, cfg);
  if (!known_peers.has_value())
    return fail_error(io, "bridge serve", known_peers.error());
  auto bridge = BoardBridge::open(bridge_dir);
  if (!bridge.has_value())
    return fail_error(io, "bridge serve", bridge.error());

  auto replayed = bridge.value().replay_outbound(io.out);
  if (!replayed.has_value())
    return fail_error(io, "bridge serve", replayed.error());

  auto report = bridge.value().pump_inbound(io.in, known_peers.value());
  if (!report.has_value())
    return fail_error(io, "bridge serve", report.error());

  const Value summary =
      pump_report_to_value(report.value(), {.quoted_frames = std::nullopt,
                                            .replayed_outbound = replayed.value()});
  auto dumped = dump_json(summary);
  if (!dumped.has_value())
    return fail_error(io, "bridge serve", dumped.error());
  io.err << dumped.value() << '\n';
  return 0;
}

int run_bridge_events(std::span<char *> args, CliIo io) {
  fs::path bridge_dir = fs::path{".blackbird"} / "bridge";
  std::optional<std::string> scope;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--bridge") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      bridge_dir = fs::path{*v};
    } else if (arg == "--scope") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      scope = *v;
    } else {
      return fail_usage(io, "bridge events: unknown option: " + std::string{arg});
    }
  }

  auto bridge = BoardBridge::open(bridge_dir);
  if (!bridge.has_value())
    return fail_error(io, "bridge events", bridge.error());
  auto all_events = bridge.value().events();
  if (!all_events.has_value())
    return fail_error(io, "bridge events", all_events.error());

  Value::Array events_arr;
  events_arr.reserve(all_events.value().size());
  for (const auto &ev : all_events.value()) {
    if (scope.has_value() && !scope->empty() && ev.resource_scope != *scope)
      continue;
    events_arr.push_back(causal_event_to_value(ev));
  }

  Value::Array conflicts_arr;
  if (scope.has_value()) {
    auto conflicts = detect_concurrent_claims(all_events.value(), *scope);
    if (!conflicts.has_value())
      return fail_error(io, "bridge events", conflicts.error());
    conflicts_arr.reserve(conflicts.value().size());
    for (const auto &c : conflicts.value())
      conflicts_arr.push_back(conflict_to_value(c));
  }

  const auto event_count = static_cast<std::uint64_t>(events_arr.size());
  const auto conflict_count = static_cast<std::uint64_t>(conflicts_arr.size());
  return emit_json(io,
                   Value::object({
                       {"scope", scope.has_value() ? Value{*scope} : Value{nullptr}},
                       {"events", Value{std::move(events_arr)}},
                       {"count", Value{Number{event_count}}},
                       {"conflicts", Value{std::move(conflicts_arr)}},
                       {"conflict_count", Value{Number{conflict_count}}},
                   }));
}

int run_bridge_receipt(std::span<char *> args, CliIo io) {
  fs::path bridge_dir = fs::path{".blackbird"} / "bridge";
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;
  std::string event_hash;
  std::string stage_name;
  std::optional<std::string> request_hash;
  std::optional<std::string> brief_version;
  std::optional<std::string> action_ref;
  std::optional<std::string> to_spec;
  std::string thread_id;
  std::string envelope_id;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--bridge") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      bridge_dir = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--event") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      event_hash = *v;
    } else if (arg == "--stage") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      stage_name = *v;
    } else if (arg == "--request-hash") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      request_hash = *v;
    } else if (arg == "--brief-version") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      brief_version = *v;
    } else if (arg == "--action-ref") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      action_ref = *v;
    } else if (arg == "--to") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      to_spec = *v;
    } else if (arg == "--thread" || arg == "--thread-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      thread_id = *v;
    } else if (arg == "--envelope-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      envelope_id = *v;
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge receipt: unknown option: " + std::string{arg});
    }
  }

  if (event_hash.empty() || stage_name.empty())
    return fail_usage(io, "bridge receipt: --event and --stage are required");
  auto stage = parse_receipt_stage(stage_name);
  if (!stage.has_value())
    return fail_usage(io, "bridge receipt: invalid --stage: " + stage_name);
  if (stage.value() == ReceiptStage::included_in_request && !request_hash.has_value()) {
    return fail_usage(
        io, "bridge receipt: --request-hash is required for stage included_in_request");
  }
  if (stage.value() == ReceiptStage::acted && !action_ref.has_value()) {
    return fail_usage(io, "bridge receipt: --action-ref is required for stage acted");
  }

  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  auto identity = PeerIdentityStore::open_or_create(*peers_dir, cfg);
  if (!identity.has_value())
    return fail_error(io, "bridge receipt", identity.error());
  auto bridge = BoardBridge::open(bridge_dir);
  if (!bridge.has_value())
    return fail_error(io, "bridge receipt", bridge.error());

  MessageReceipt receipt;
  receipt.event_hash = std::move(event_hash);
  receipt.recipient_actor = identity.value().identity().fingerprint;
  receipt.stage = stage.value();
  receipt.request_hash = std::move(request_hash);
  receipt.brief_version = std::move(brief_version);
  receipt.action_ref = std::move(action_ref);

  auto recorded = bridge.value().record_receipt(std::move(receipt));
  if (!recorded.has_value())
    return fail_error(io, "bridge receipt", recorded.error());

  if (to_spec.has_value()) {
    auto known_peers = KnownPeersStore::open(*peers_dir, cfg);
    if (!known_peers.has_value())
      return fail_error(io, "bridge receipt", known_peers.error());
    auto resolved_to = resolve_peer_recipient({*to_spec, "bridge receipt", true},
                                              known_peers.value(), io);
    if (!resolved_to.has_value())
      return 1;

    PeerEnvelopeMeta meta;
    meta.envelope_id = std::move(envelope_id);
    meta.to_fingerprint = std::move(*resolved_to);
    meta.thread_id = std::move(thread_id);
    meta.kind = PeerEnvelopeKind::mail;

    auto signed_env =
        BoardBridge::sign_receipt_envelope(identity.value(), recorded.value(), meta);
    if (!signed_env.has_value())
      return fail_error(io, "bridge receipt", signed_env.error());
    auto sent = bridge.value().send_envelope(io.out, signed_env.value());
    if (!sent.has_value())
      return fail_error(io, "bridge receipt", sent.error());
    return 0;
  }

  return emit_json(io, receipt_to_value(recorded.value()));
}

int run_bridge_guard(std::span<char *> args, CliIo io) {
  fs::path bridge_dir = fs::path{".blackbird"} / "bridge";
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;
  std::string scope;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--bridge") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      bridge_dir = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--scope") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      scope = *v;
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge guard: unknown option: " + std::string{arg});
    }
  }

  if (scope.empty())
    return fail_usage(io, "bridge guard: --scope is required");
  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  auto identity = PeerIdentityStore::open_or_create(*peers_dir, cfg);
  if (!identity.has_value())
    return fail_error(io, "bridge guard", identity.error());
  auto bridge = BoardBridge::open(bridge_dir);
  if (!bridge.has_value())
    return fail_error(io, "bridge guard", bridge.error());

  auto verdict =
      bridge.value().check_action_guard(identity.value().identity().fingerprint, scope);
  if (!verdict.has_value())
    return fail_error(io, "bridge guard", verdict.error());

  if (emit_json(io, action_guard_to_value(verdict.value())) != 0)
    return 1;
  return verdict.value().allowed ? 0 : 2;
}

int run_bridge_presence(std::span<char *> args, CliIo io) {
  fs::path bridge_dir = fs::path{".blackbird"} / "bridge";
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;
  std::optional<std::string> scope;
  std::string status = "watching";
  std::optional<std::string> display_name;
  std::int64_t ttl_secs = kDefaultPresenceTtlSec;
  std::optional<std::string> to_spec;
  std::string thread_id;
  std::string envelope_id;
  bool list_only = false;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--bridge") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      bridge_dir = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--scope") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      scope = *v;
    } else if (arg == "--status") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      status = *v;
    } else if (arg == "--name") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      display_name = *v;
    } else if (arg == "--ttl") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      constexpr std::int64_t kMaxPresenceTtlSec =
          kBoardBridgeMaxTtlNs / kNanosecondsPerSecond;
      if (!parsed.has_value() || *parsed <= 0 || *parsed > kMaxPresenceTtlSec)
        return fail_usage(io, "bridge presence: --ttl must be 1..86400 seconds");
      ttl_secs = *parsed;
    } else if (arg == "--to") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      to_spec = *v;
    } else if (arg == "--thread" || arg == "--thread-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      thread_id = *v;
    } else if (arg == "--envelope-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      envelope_id = *v;
    } else if (arg == "--list") {
      list_only = true;
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge presence: unknown option: " + std::string{arg});
    }
  }

  auto bridge = BoardBridge::open(bridge_dir);
  if (!bridge.has_value())
    return fail_error(io, "bridge presence", bridge.error());

  if (list_only) {
    const std::string scope_filter = scope.value_or("");
    auto watchers = bridge.value().active_watchers(scope_filter, wall_now_ns());
    if (!watchers.has_value())
      return fail_error(io, "bridge presence", watchers.error());
    Value::Array arr;
    arr.reserve(watchers.value().size());
    for (const auto &rec : watchers.value())
      arr.push_back(presence_to_value(rec));
    return emit_json(
        io, Value::object({
                {"scope", scope.has_value() ? Value{*scope} : Value{nullptr}},
                {"watchers", Value{std::move(arr)}},
                {"count",
                 Value{Number{static_cast<std::uint64_t>(watchers.value().size())}}},
            }));
  }

  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  auto identity = PeerIdentityStore::open_or_create(*peers_dir, cfg);
  if (!identity.has_value())
    return fail_error(io, "bridge presence", identity.error());

  PresenceRecord rec;
  rec.actor_id = identity.value().identity().fingerprint;
  rec.display_name = display_name.value_or(identity.value().identity().fingerprint);
  rec.watching_scope = scope.value_or("*");
  rec.status = std::move(status);
  rec.ttl_ns = ttl_secs * kNanosecondsPerSecond;

  auto recorded = bridge.value().record_presence(std::move(rec));
  if (!recorded.has_value())
    return fail_error(io, "bridge presence", recorded.error());

  if (to_spec.has_value()) {
    auto known_peers = KnownPeersStore::open(*peers_dir, cfg);
    if (!known_peers.has_value())
      return fail_error(io, "bridge presence", known_peers.error());
    auto resolved_to = resolve_peer_recipient({*to_spec, "bridge presence", true},
                                              known_peers.value(), io);
    if (!resolved_to.has_value())
      return 1;

    PeerEnvelopeMeta meta;
    meta.envelope_id = std::move(envelope_id);
    meta.to_fingerprint = std::move(*resolved_to);
    meta.thread_id = std::move(thread_id);
    meta.kind = PeerEnvelopeKind::mail;

    auto signed_env =
        BoardBridge::sign_presence_envelope(identity.value(), recorded.value(), meta);
    if (!signed_env.has_value())
      return fail_error(io, "bridge presence", signed_env.error());
    auto sent = bridge.value().send_envelope(io.out, signed_env.value());
    if (!sent.has_value())
      return fail_error(io, "bridge presence", sent.error());
    return 0;
  }

  return emit_json(io, presence_to_value(recorded.value()));
}

int run_bridge_grant_issue(std::span<char *> args, CliIo io) {
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;
  std::string to_spec;
  std::string mode_name = "direct_support";
  CapabilityGrantDraft draft;
  draft.max_turns = kDefaultGrantMaxTurns;
  draft.max_tokens = kDefaultGrantMaxTokens;
  std::int64_t ttl_secs = kDefaultGrantTtlSec;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--to") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      to_spec = *v;
    } else if (arg == "--target-peer") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      draft.target_peer = *v;
    } else if (arg == "--mode") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      mode_name = *v;
    } else if (arg == "--tool") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      draft.allowed_tools.push_back(*v);
    } else if (arg == "--max-turns") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed == 0 || *parsed > kPeerMaxGrantTurns)
        return fail_usage(io, "bridge grant-issue: invalid --max-turns");
      draft.max_turns = static_cast<std::uint32_t>(*parsed);
    } else if (arg == "--max-tokens") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed == 0 || *parsed > kPeerMaxGrantTokens)
        return fail_usage(io, "bridge grant-issue: invalid --max-tokens");
      draft.max_tokens = *parsed;
    } else if (arg == "--ttl") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed <= 0 || *parsed > kMaxGrantTtlSec)
        return fail_usage(io, "bridge grant-issue: invalid --ttl");
      ttl_secs = *parsed;
    } else if (arg == "--room") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      draft.command_room = *v;
    } else if (arg == "--grant-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      draft.grant_id = *v;
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge grant-issue: unknown option: " + std::string{arg});
    }
  }

  if (to_spec.empty() || draft.target_peer.empty() || draft.allowed_tools.empty()) {
    return fail_usage(
        io, "bridge grant-issue: --to, --target-peer, and at least one --tool are "
            "required");
  }
  auto mode = parse_capability_grant_mode(mode_name);
  if (!mode.has_value())
    return fail_usage(io, "bridge grant-issue: invalid --mode: " + mode_name);
  draft.mode = mode.value();
  if (draft.mode == CapabilityGrantMode::temporary_attachment &&
      !draft.command_room.has_value()) {
    return fail_usage(
        io, "bridge grant-issue: --room is required for mode temporary_attachment");
  }

  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  auto identity = PeerIdentityStore::open_or_create(*peers_dir, cfg);
  if (!identity.has_value())
    return fail_error(io, "bridge grant-issue", identity.error());
  auto known_peers = KnownPeersStore::open(*peers_dir, cfg);
  if (!known_peers.has_value())
    return fail_error(io, "bridge grant-issue", known_peers.error());

  auto resolved_to = resolve_peer_recipient({to_spec, "bridge grant-issue", false},
                                            known_peers.value(), io);
  if (!resolved_to.has_value())
    return 1;

  draft.grantee_fingerprint = std::move(*resolved_to);
  draft.issued_at_ns = wall_now_ns();
  draft.expires_at_ns = draft.issued_at_ns + (ttl_secs * kNanosecondsPerSecond);
  draft.revocable = true;

  auto grant = identity.value().sign_grant(std::move(draft));
  if (!grant.has_value())
    return fail_error(io, "bridge grant-issue", grant.error());
  return emit_json(io, grant_to_value(grant.value()));
}

int run_bridge_grant_check(std::span<char *> args, CliIo io) {
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;
  std::optional<fs::path> grant_file;
  std::string tool_name;
  double projected_cost_usd = 0.0;
  std::optional<std::int64_t> now_ns;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--grant-file") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      grant_file = fs::path{*v};
    } else if (arg == "--tool") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      tool_name = *v;
    } else if (arg == "--cost") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_nonnegative_double(*v);
      if (!parsed.has_value())
        return fail_usage(io, "bridge grant-check: invalid --cost");
      projected_cost_usd = *parsed;
    } else if (arg == "--now-ns") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed < 0)
        return fail_usage(io, "bridge grant-check: invalid --now-ns");
      now_ns = *parsed;
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge grant-check: unknown option: " + std::string{arg});
    }
  }

  if (tool_name.empty())
    return fail_usage(io, "bridge grant-check: --tool is required");

  std::string raw_json;
  if (grant_file.has_value() && grant_file->string() != "-") {
    auto loaded = read_file_bounded(*grant_file, kMaxCliInputBytes, io);
    if (!loaded.has_value())
      return 1;
    raw_json = std::move(*loaded);
  } else {
    auto loaded = read_stream_bounded(io.in, kMaxCliInputBytes, io);
    if (!loaded.has_value())
      return 1;
    raw_json = std::move(*loaded);
  }

  auto parsed = parse_json(raw_json);
  if (!parsed.has_value())
    return fail_error(io, "bridge grant-check", parsed.error());
  auto grant = grant_from_value(parsed.value());
  if (!grant.has_value())
    return fail_error(io, "bridge grant-check", grant.error());

  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  auto known_peers = KnownPeersStore::open(*peers_dir, cfg);
  if (!known_peers.has_value())
    return fail_error(io, "bridge grant-check", known_peers.error());

  std::string local_fp;
  if (auto local_id = PeerIdentityStore::open_existing(*peers_dir, cfg);
      local_id.has_value()) {
    local_fp = local_id.value().identity().fingerprint;
  }

  const SpendLedger ledger{};
  const std::int64_t check_time = now_ns.has_value() ? *now_ns : wall_now_ns();
  auto auth = authorize_tool_call(known_peers.value(), grant.value(), tool_name,
                                  check_time, ledger, projected_cost_usd, local_fp);
  if (!auth.has_value())
    return fail_error(io, "bridge grant-check", auth.error());

  const ToolAuthorization &verdict = auth.value();
  const Value out_val = Value::object({
      {"allowed", Value{verdict.allowed}},
      {"grant_id", Value{grant.value().grant_id}},
      {"tool", Value{tool_name}},
      {"denial_code", verdict.denial_code.has_value()
                          ? Value{std::string{error_name(*verdict.denial_code)}}
                          : Value{nullptr}},
      {"reason", Value{verdict.reason}},
  });
  if (emit_json(io, out_val) != 0)
    return 1;
  return verdict.allowed ? 0 : 2;
}

Result<std::string> generate_invite_code() {
  std::array<std::uint8_t, 16> bytes{};
  if (::getentropy(bytes.data(), bytes.size()) != 0)
    return Result<std::string>::failure({ErrorCode::io, errno});
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const std::uint8_t byte : bytes) {
    out.push_back(kHex[(byte >> 4U) & 0x0fU]);
    out.push_back(kHex[byte & 0x0fU]);
  }
  return Result<std::string>::success(std::move(out));
}

int run_bridge_checkpoint(std::span<char *> args, CliIo io) {
  fs::path bridge_dir = fs::path{".blackbird"} / "bridge";
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;
  std::string room_id = "default";
  std::uint64_t checkpoint_seq = 0;
  std::int64_t created_ns = 0;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird bridge checkpoint [--room ID] [--checkpoint-seq N] "
                "[--bridge DIR] [--peers DIR] [--created-ns N]\n";
      return 0;
    }
    if (arg == "--room") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      room_id = *v;
    } else if (arg == "--checkpoint-seq") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_u64(*v);
      if (!parsed.has_value())
        return fail_usage(io, "bridge checkpoint: invalid --checkpoint-seq");
      checkpoint_seq = *parsed;
    } else if (arg == "--bridge") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      bridge_dir = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--created-ns") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed <= 0)
        return fail_usage(io, "bridge checkpoint: invalid --created-ns");
      created_ns = *parsed;
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge checkpoint: unknown option: " + std::string{arg});
    }
  }

  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  auto identity = PeerIdentityStore::open_or_create(*peers_dir, cfg);
  if (!identity.has_value())
    return fail_error(io, "bridge checkpoint", identity.error());
  auto known_peers = KnownPeersStore::open(*peers_dir, cfg);
  if (!known_peers.has_value())
    return fail_error(io, "bridge checkpoint", known_peers.error());

  std::vector<CausalEvent> all_events;
  std::error_code bridge_ec;
  const fs::file_status bridge_st = fs::symlink_status(bridge_dir, bridge_ec);
  const bool bridge_absent =
      bridge_ec == std::errc::no_such_file_or_directory ||
      (!bridge_ec && bridge_st.type() == fs::file_type::not_found);
  if (!bridge_absent) {
    auto bridge = BoardBridge::open(bridge_dir);
    if (!bridge.has_value())
      return fail_error(io, "bridge checkpoint", bridge.error());
    auto loaded_events = bridge.value().events();
    if (!loaded_events.has_value())
      return fail_error(io, "bridge checkpoint", loaded_events.error());
    all_events = std::move(loaded_events).value();
  }

  auto revoked = known_peers.value().list_revoked_grants();
  if (!revoked.has_value())
    return fail_error(io, "bridge checkpoint", revoked.error());

  BridgeCheckpointDraft draft;
  draft.room_id = std::move(room_id);
  draft.checkpoint_seq = checkpoint_seq;
  draft.created_ns = created_ns;
  draft.actor_watermarks = compute_actor_watermarks(all_events);
  draft.causal_frontier_hashes = compute_causal_frontier(all_events);
  draft.revoked_grant_ids.reserve(revoked.value().size());
  for (const auto &rec : revoked.value())
    draft.revoked_grant_ids.push_back(rec.grant_id);

  auto signed_cp = sign_checkpoint(identity.value(), std::move(draft));
  if (!signed_cp.has_value())
    return fail_error(io, "bridge checkpoint", signed_cp.error());
  return emit_json(io, checkpoint_to_value(signed_cp.value()));
}

int run_bridge_checkpoint_verify(std::span<char *> args, CliIo io) {
  std::optional<fs::path> file_path;
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err
          << "usage: blackbird bridge checkpoint-verify [--file PATH] [--peers DIR]\n";
      return 0;
    }
    if (arg == "--file") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      file_path = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge checkpoint-verify: unknown option: " +
                                std::string{arg});
    }
  }

  std::string raw_json;
  if (file_path.has_value() && file_path->string() != "-") {
    auto loaded = read_file_bounded(*file_path, kMaxCliInputBytes, io);
    if (!loaded.has_value())
      return 1;
    raw_json = std::move(*loaded);
  } else {
    auto loaded = read_stream_bounded(io.in, kMaxCliInputBytes, io);
    if (!loaded.has_value())
      return 1;
    raw_json = std::move(*loaded);
  }

  auto emit_invalid = [&](ErrorCode code, const BridgeCheckpoint *cp) -> int {
    const Value out_val = Value::object({
        {"valid", Value{false}},
        {"room_id", Value{cp != nullptr ? cp->room_id : std::string{}}},
        {"checkpoint_seq",
         Value{Number{cp != nullptr ? cp->checkpoint_seq : std::uint64_t{0}}}},
        {"signer_fingerprint",
         Value{cp != nullptr ? cp->signer_fingerprint : std::string{}}},
        {"watermarks_count",
         Value{Number{cp != nullptr
                          ? static_cast<std::uint64_t>(cp->actor_watermarks.size())
                          : std::uint64_t{0}}}},
        {"error", Value{std::string{error_name(code)}}},
    });
    if (emit_json(io, out_val) != 0)
      return 1;
    return 2;
  };

  auto parsed = parse_json(raw_json);
  if (!parsed.has_value())
    return emit_invalid(parsed.error().code, nullptr);
  auto cp = checkpoint_from_value(parsed.value());
  if (!cp.has_value())
    return emit_invalid(cp.error().code, nullptr);

  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  std::error_code peers_ec;
  const fs::file_status peers_st = fs::symlink_status(*peers_dir, peers_ec);
  if (peers_ec == std::errc::no_such_file_or_directory ||
      (!peers_ec && peers_st.type() == fs::file_type::not_found)) {
    return emit_invalid(ErrorCode::invalid_identity, &cp.value());
  }

  auto known_peers = KnownPeersStore::open(*peers_dir, cfg);
  if (!known_peers.has_value())
    return fail_error(io, "bridge checkpoint-verify", known_peers.error());

  auto verified = verify_checkpoint(known_peers.value(), cp.value(), cfg);
  if (!verified.has_value())
    return emit_invalid(verified.error().code, &cp.value());

  return emit_json(io,
                   Value::object({
                       {"valid", Value{true}},
                       {"room_id", Value{cp.value().room_id}},
                       {"checkpoint_seq", Value{Number{cp.value().checkpoint_seq}}},
                       {"signer_fingerprint", Value{cp.value().signer_fingerprint}},
                       {"watermarks_count", Value{Number{static_cast<std::uint64_t>(
                                                cp.value().actor_watermarks.size())}}},
                   }));
}

int run_bridge_invite(std::span<char *> args, CliIo io) {
  std::optional<fs::path> peers_dir;
  PeerIdentityConfig cfg;
  std::string room_id;
  std::string relay_url;
  std::int64_t ttl_secs = kDefaultInviteTtlSec;
  std::optional<std::int64_t> explicit_expires_ns;
  std::optional<std::string> explicit_code;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird bridge invite --room ID --relay URL [--ttl SECS] "
                "[--expires-ns N] [--code CODE] [--peers DIR]\n";
      return 0;
    }
    if (arg == "--room") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      room_id = *v;
    } else if (arg == "--relay") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      relay_url = *v;
    } else if (arg == "--ttl") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed <= 0 || *parsed > kMaxInviteTtlSec)
        return fail_usage(io, "bridge invite: invalid --ttl");
      ttl_secs = *parsed;
    } else if (arg == "--expires-ns") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed <= 0)
        return fail_usage(io, "bridge invite: invalid --expires-ns");
      explicit_expires_ns = *parsed;
    } else if (arg == "--code") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "bridge invite: --code must not be empty");
      explicit_code = std::move(*v);
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--namespace") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.signature_namespace = *v;
    } else if (arg == "--ssh-keygen") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.ssh_keygen_executable = *v;
    } else {
      return fail_usage(io, "bridge invite: unknown option: " + std::string{arg});
    }
  }

  if (room_id.empty() || relay_url.empty())
    return fail_usage(io, "bridge invite: --room and --relay are required");

  if (!peers_dir.has_value()) {
    peers_dir = default_peers_dir(io);
    if (!peers_dir.has_value())
      return 1;
  }

  auto identity = PeerIdentityStore::open_or_create(*peers_dir, cfg);
  if (!identity.has_value())
    return fail_error(io, "bridge invite", identity.error());

  std::string invite_code;
  if (explicit_code.has_value()) {
    invite_code = std::move(*explicit_code);
  } else {
    auto generated = generate_invite_code();
    if (!generated.has_value())
      return fail_error(io, "bridge invite", generated.error());
    invite_code = std::move(generated).value();
  }

  std::int64_t expires_ns = 0;
  if (explicit_expires_ns.has_value()) {
    expires_ns = *explicit_expires_ns;
  } else {
    const std::int64_t ttl_ns = ttl_secs * kNanosecondsPerSecond;
    const std::int64_t now_ns = wall_now_ns();
    if (now_ns > std::numeric_limits<std::int64_t>::max() - ttl_ns)
      return fail_error(io, "bridge invite", {ErrorCode::overflow});
    expires_ns = now_ns + ttl_ns;
  }

  RoomInvite invite;
  invite.room_id = std::move(room_id);
  invite.relay_url = std::move(relay_url);
  invite.creator_fingerprint = identity.value().identity().fingerprint;
  invite.creator_public_key = identity.value().identity().public_key;
  invite.invite_code = std::move(invite_code);
  invite.expires_ns = expires_ns;

  auto encoded = encode_room_invite(invite);
  if (!encoded.has_value())
    return fail_error(io, "bridge invite", encoded.error());

  return emit_json(io, Value::object({
                           {"invite_uri", Value{std::move(encoded).value()}},
                           {"room_id", Value{invite.room_id}},
                           {"relay_url", Value{invite.relay_url}},
                           {"creator_fingerprint", Value{invite.creator_fingerprint}},
                           {"expires_ns", Value{Number{invite.expires_ns}}},
                       }));
}

int run_bridge_cli(std::span<char *> args, CliIo io) {
  if (args.size() < 2) {
    return fail_usage(
        io, "bridge: expected action (send|receive|serve|events|receipt|guard|"
            "presence|grant-issue|grant-check|checkpoint|checkpoint-verify|invite)");
  }
  const std::string_view action{args[1]};
  if (action == "--help" || action == "-h") {
    io.err << "usage: blackbird bridge {send|receive|serve|events|receipt|guard|"
              "presence|grant-issue|grant-check|checkpoint|checkpoint-verify|invite} "
              "[options]\n";
    return 0;
  }
  if (action == "send")
    return run_bridge_send(args, io);
  if (action == "receive")
    return run_bridge_receive(args, io);
  if (action == "serve")
    return run_bridge_serve(args, io);
  if (action == "events")
    return run_bridge_events(args, io);
  if (action == "receipt")
    return run_bridge_receipt(args, io);
  if (action == "guard")
    return run_bridge_guard(args, io);
  if (action == "presence")
    return run_bridge_presence(args, io);
  if (action == "grant-issue")
    return run_bridge_grant_issue(args, io);
  if (action == "grant-check")
    return run_bridge_grant_check(args, io);
  if (action == "checkpoint")
    return run_bridge_checkpoint(args, io);
  if (action == "checkpoint-verify")
    return run_bridge_checkpoint_verify(args, io);
  if (action == "invite")
    return run_bridge_invite(args, io);
  return fail_usage(io, "bridge: unknown action: " + std::string{action});
}

// ============================================================================
// 9. blackbird join
// ============================================================================

int run_join_cli(std::span<char *> args, CliIo io) {
  std::string invite_uri;
  std::string creator_alias;
  std::optional<fs::path> peers_dir;
  std::optional<std::string> trust_note;
  std::optional<std::int64_t> now_ns;
  bool dry_run = false;
  bool allow_expired = false;

  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird join <bbjoin1:...> --alias NAME [--peers DIR] "
                "[--dry-run] [--allow-expired] [--trust-note TEXT] [--now-ns N]\n";
      return 0;
    }
    if (arg == "--alias") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      creator_alias = *v;
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--dry-run") {
      dry_run = true;
    } else if (arg == "--allow-expired") {
      allow_expired = true;
    } else if (arg == "--trust-note") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      trust_note = *v;
    } else if (arg == "--now-ns") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed = parse_i64(*v);
      if (!parsed.has_value() || *parsed < 0)
        return fail_usage(io, "join: invalid --now-ns");
      now_ns = *parsed;
    } else if (arg == "--uri") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      invite_uri = *v;
    } else if (!arg.starts_with('-') && invite_uri.empty()) {
      invite_uri = std::string{arg};
    } else {
      return fail_usage(io, "join: unknown option: " + std::string{arg});
    }
  }

  if (invite_uri.empty() || creator_alias.empty())
    return fail_usage(io, "join: <bbjoin1:...> URI and --alias are required");
  if (!valid_peer_alias(creator_alias))
    return fail_usage(io, "join: invalid --alias");

  auto parsed = parse_room_invite(invite_uri);
  if (!parsed.has_value())
    return fail_error(io, "join", parsed.error());
  const RoomInvite &invite = parsed.value();

  const std::int64_t check_time_ns = now_ns.has_value() ? *now_ns : wall_now_ns();
  if (!allow_expired && invite.expires_ns <= check_time_ns) {
    io.err << "blackbird join: invite expired (" << error_name(ErrorCode::invalid_range)
           << ")\n";
    return 1;
  }

  bool pinned = false;
  if (!dry_run) {
    if (!peers_dir.has_value()) {
      peers_dir = default_peers_dir(io);
      if (!peers_dir.has_value())
        return 1;
    }
    auto known_peers = KnownPeersStore::open(*peers_dir);
    if (!known_peers.has_value())
      return fail_error(io, "join", known_peers.error());

    PinPeerRequest req;
    req.alias = creator_alias;
    req.public_key = invite.creator_public_key;
    req.trust_note =
        trust_note.has_value()
            ? *trust_note
            : ("Joined room " + invite.room_id + " via " + invite.relay_url);
    auto pin_res = known_peers.value().pin_peer(req);
    if (!pin_res.has_value())
      return fail_error(io, "join", pin_res.error());
    pinned = true;
  }

  return emit_json(io, Value::object({
                           {"joined", Value{!dry_run}},
                           {"room_id", Value{invite.room_id}},
                           {"relay_url", Value{invite.relay_url}},
                           {"creator_alias", Value{creator_alias}},
                           {"creator_fingerprint", Value{invite.creator_fingerprint}},
                           {"pinned", Value{pinned}},
                       }));
}

// ============================================================================
// 10. blackbird party
// ============================================================================

bool valid_party_ssh_target(std::string_view ssh) noexcept {
  if (ssh.empty() || ssh.size() > 256 || !valid_utf8(ssh))
    return false;
  if (ssh.front() == '-')
    return false;
  std::size_t at_pos = std::string_view::npos;
  for (std::size_t i = 0; i < ssh.size(); ++i) {
    const auto b = static_cast<unsigned char>(ssh[i]);
    if (b <= 0x20U || b == 0x7fU)
      return false;
    if (ssh[i] == '@') {
      if (at_pos != std::string_view::npos)
        return false;
      at_pos = i;
    }
  }
  if (at_pos != std::string_view::npos) {
    if (at_pos == 0 || at_pos + 1 >= ssh.size())
      return false;
    if (ssh[at_pos + 1] == '-')
      return false;
  }
  return true;
}

Value party_participant_to_value(const PartyParticipant &p) {
  Value::Object obj{
      {"id", Value{p.id}},
      {"display_name", Value{p.display_name}},
      {"role", Value{std::string{party_member_role_name(p.role)}}},
      {"host", Value{p.host}},
      {"model", Value{p.model}},
      {"fingerprint", Value{p.fingerprint}},
      {"state", Value{std::string{party_participant_state_name(p.state)}}},
      {"last_seen_ns", Value{Number{p.last_seen_ns}}},
      {"local_self", Value{p.local_self}},
  };
  if (p.ssh_target.has_value())
    obj.emplace_back("ssh_target", Value{*p.ssh_target});
  if (p.provider.has_value())
    obj.emplace_back("provider", Value{*p.provider});
  if (p.remote_model.has_value())
    obj.emplace_back("remote_model", Value{*p.remote_model});
  if (p.remote_session.has_value())
    obj.emplace_back("remote_session", Value{*p.remote_session});
  return Value::object(std::move(obj));
}

int run_party_roster(std::span<char *> args, CliIo io) {
  PartyConfig cfg;
  cfg.party_config_path = fs::path{".blackbird"} / "party.json";
  cfg.platoon_dir = fs::path{".blackbird"} / "platoon";
  cfg.bridge_dir = fs::path{".blackbird"} / "bridge";
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0')
    cfg.known_peers_dir = fs::path{home} / ".local" / "share" / "blackbird" / "peers";

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird party roster [--party-file PATH] [--platoon DIR] "
                "[--bridge DIR] [--peers DIR] [--scope SCOPE]\n";
      return 0;
    }
    if (arg == "--party-file") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.party_config_path = fs::path{*v};
    } else if (arg == "--platoon") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.platoon_dir = fs::path{*v};
    } else if (arg == "--bridge") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.bridge_dir = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.known_peers_dir = fs::path{*v};
    } else if (arg == "--scope") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "party roster: --scope must not be empty");
      cfg.room_scope = *v;
    } else {
      return fail_usage(io, "party roster: unknown option: " + std::string{arg});
    }
  }

  auto snap_res = load_party_snapshot(cfg);
  if (!snap_res.has_value())
    return fail_error(io, "party roster", snap_res.error());
  const PartySnapshot &snap = snap_res.value();

  Value::Array participants;
  participants.reserve(snap.participants.size());
  for (const auto &p : snap.participants)
    participants.push_back(party_participant_to_value(p));

  Value::Array conflicts;
  conflicts.reserve(snap.conflicts.size());
  for (const auto &c : snap.conflicts)
    conflicts.push_back(conflict_to_value(c));

  return emit_json(
      io, Value::object({
              {"mode", Value{std::string{party_mode_name(snap.mode)}}},
              {"scope", Value{snap.room_scope}},
              {"participant_count",
               Value{Number{static_cast<std::uint64_t>(snap.participants.size())}}},
              {"message_count",
               Value{Number{static_cast<std::uint64_t>(snap.messages.size())}}},
              {"participants", Value{std::move(participants)}},
              {"conflicts", Value{std::move(conflicts)}},
          }));
}

int run_party_add_leader(std::span<char *> args, CliIo io) {
  fs::path party_file = fs::path{".blackbird"} / "party.json";
  std::string alias;
  std::optional<std::string> display_name;
  std::optional<PartyMemberRole> role_opt;
  std::optional<std::string> host;
  std::optional<std::string> ssh_target;
  std::optional<std::string> provider;
  std::optional<std::string> model;
  std::optional<std::string> remote_session;
  std::optional<std::string> fingerprint;
  std::optional<std::string> scope;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird party add-leader --alias NAME [--display-name TEXT] "
                "[--role leader|operator|worker] [--host HOST] [--ssh USER@HOST] "
                "[--provider ID] [--model NAME] [--remote-session PATH] "
                "[--fingerprint FP] [--party-file PATH] [--scope SCOPE]\n";
      return 0;
    }
    if (arg == "--alias") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      alias = *v;
    } else if (arg == "--display-name") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "party add-leader: --display-name must not be empty");
      display_name = *v;
    } else if (arg == "--role") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      auto parsed_role = parse_party_member_role(*v);
      if (!parsed_role.has_value())
        return fail_usage(io, "party add-leader: invalid --role: " + *v);
      role_opt = parsed_role.value();
    } else if (arg == "--host") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      host = *v;
    } else if (arg == "--ssh") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_party_ssh_target(*v))
        return fail_usage(io, "party add-leader: invalid --ssh target");
      ssh_target = *v;
    } else if (arg == "--provider") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "party add-leader: --provider must not be empty");
      provider = *v;
    } else if (arg == "--model") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "party add-leader: --model must not be empty");
      model = *v;
    } else if (arg == "--remote-session") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "party add-leader: --remote-session must not be empty");
      remote_session = *v;
    } else if (arg == "--fingerprint") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_peer_fingerprint(*v))
        return fail_usage(io, "party add-leader: invalid --fingerprint");
      fingerprint = *v;
    } else if (arg == "--party-file") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      party_file = fs::path{*v};
    } else if (arg == "--scope") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "party add-leader: --scope must not be empty");
      scope = *v;
    } else {
      return fail_usage(io, "party add-leader: unknown option: " + std::string{arg});
    }
  }

  if (alias.empty())
    return fail_usage(io, "party add-leader: --alias is required");
  if (!valid_party_alias(alias))
    return fail_usage(io, "party add-leader: invalid --alias");

  PartyRosterConfig config{};
  std::error_code st_ec;
  const fs::file_status st = fs::symlink_status(party_file, st_ec);
  if (!st_ec && fs::is_symlink(st))
    return fail_error(io, "party add-leader", {ErrorCode::io, ELOOP});
  if (!st_ec && st.type() != fs::file_type::not_found) {
    auto loaded = load_party_roster_config(party_file);
    if (!loaded.has_value())
      return fail_error(io, "party add-leader", loaded.error());
    config = std::move(loaded).value();
  } else if (st_ec && st_ec != std::errc::no_such_file_or_directory &&
             st_ec != std::errc::not_a_directory) {
    return fail_error(io, "party add-leader", {ErrorCode::io, st_ec.value()});
  }

  if (scope.has_value())
    config.room_scope = *scope;

  auto match_alias_ci = [&](const PartyRosterPeerConfig &peer) noexcept -> bool {
    if (peer.alias.size() != alias.size())
      return false;
    for (std::size_t i = 0; i < alias.size(); ++i) {
      const char a = (peer.alias[i] >= 'A' && peer.alias[i] <= 'Z')
                         ? static_cast<char>(peer.alias[i] - 'A' + 'a')
                         : peer.alias[i];
      const char b = (alias[i] >= 'A' && alias[i] <= 'Z')
                         ? static_cast<char>(alias[i] - 'A' + 'a')
                         : alias[i];
      if (a != b)
        return false;
    }
    return true;
  };

  PartyRosterPeerConfig *target = nullptr;
  if (auto it = std::ranges::find_if(config.peers, match_alias_ci);
      it != config.peers.end()) {
    target = &(*it);
    target->alias = alias;
    if (role_opt.has_value())
      target->role = *role_opt;
  } else {
    PartyRosterPeerConfig peer{};
    peer.alias = alias;
    peer.role = role_opt.value_or(PartyMemberRole::platoon_leader);
    config.peers.push_back(std::move(peer));
    target = &config.peers.back();
  }

  if (display_name.has_value())
    target->display_name = *display_name;
  if (host.has_value())
    target->host = *host;
  if (ssh_target.has_value())
    target->ssh_target = *ssh_target;
  if (provider.has_value())
    target->provider = *provider;
  if (model.has_value())
    target->model = *model;
  if (remote_session.has_value())
    target->remote_session = *remote_session;
  if (fingerprint.has_value())
    target->fingerprint = *fingerprint;

  const PartyMemberRole saved_role = target->role;
  auto saved = save_party_roster_config(party_file, config);
  if (!saved.has_value()) {
    if (saved.error().code == ErrorCode::invalid_range ||
        saved.error().code == ErrorCode::invalid_identity) {
      io.err << "blackbird party add-leader: invalid field value ("
             << error_name(saved.error().code) << ")\n";
      return 2;
    }
    return fail_error(io, "party add-leader", saved.error());
  }

  return emit_json(io,
                   Value::object({
                       {"saved", Value{true}},
                       {"alias", Value{alias}},
                       {"role", Value{std::string{party_member_role_name(saved_role)}}},
                       {"party_file", Value{party_file.string()}},
                       {"participant_count",
                        Value{Number{static_cast<std::uint64_t>(config.peers.size())}}},
                   }));
}

int run_party_create(std::span<char *> args, CliIo io) {
  fs::path party_file = fs::path{".blackbird"} / "party.json";
  std::optional<std::string> room;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird party create [--room SCOPE] [--party-file PATH]\n";
      return 0;
    }
    if (arg == "--room" || arg == "--scope") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "party create: --room must not be empty");
      room = *v;
    } else if (arg == "--party-file") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      party_file = fs::path{*v};
    } else {
      return fail_usage(io, "party create: unknown option: " + std::string{arg});
    }
  }

  PartyRosterConfig config{};
  const fs::path parent = party_file.parent_path();
  if (!parent.empty()) {
    std::error_code parent_ec;
    const fs::file_status pst = fs::symlink_status(parent, parent_ec);
    if (!parent_ec && fs::is_symlink(pst))
      return fail_error(io, "party create", {ErrorCode::io, ELOOP});
  }
  std::error_code st_ec;
  const fs::file_status st = fs::symlink_status(party_file, st_ec);
  if (!st_ec && fs::is_symlink(st))
    return fail_error(io, "party create", {ErrorCode::io, ELOOP});
  if (!st_ec && st.type() != fs::file_type::not_found) {
    auto loaded = load_party_roster_config(party_file);
    if (!loaded.has_value())
      return fail_error(io, "party create", loaded.error());
    config = std::move(loaded).value();
  } else if (st_ec && st_ec != std::errc::no_such_file_or_directory &&
             st_ec != std::errc::not_a_directory) {
    return fail_error(io, "party create", {ErrorCode::io, st_ec.value()});
  }

  if (room.has_value())
    config.room_scope = *room;

  auto saved = save_party_roster_config(party_file, config);
  if (!saved.has_value()) {
    if (saved.error().code == ErrorCode::invalid_range ||
        saved.error().code == ErrorCode::invalid_identity) {
      io.err << "blackbird party create: invalid room scope ("
             << error_name(saved.error().code) << ")\n";
      return 2;
    }
    return fail_error(io, "party create", saved.error());
  }

  return emit_json(io,
                   Value::object({
                       {"created", Value{true}},
                       {"active", Value{true}},
                       {"room", Value{config.room_scope}},
                       {"scope", Value{config.room_scope}},
                       {"party_file", Value{party_file.string()}},
                       {"participant_count",
                        Value{Number{static_cast<std::uint64_t>(config.peers.size())}}},
                   }));
}

int run_party_leave(std::span<char *> args, CliIo io) {
  fs::path party_file = fs::path{".blackbird"} / "party.json";

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird party leave [--party-file PATH]\n";
      return 0;
    }
    if (arg == "--party-file") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      party_file = fs::path{*v};
    } else {
      return fail_usage(io, "party leave: unknown option: " + std::string{arg});
    }
  }

  const fs::path parent = party_file.parent_path();
  if (!parent.empty()) {
    std::error_code parent_ec;
    const fs::file_status pst = fs::symlink_status(parent, parent_ec);
    if (!parent_ec && fs::is_symlink(pst))
      return fail_error(io, "party leave", {ErrorCode::io, ELOOP});
  }

  std::error_code st_ec;
  const fs::file_status st = fs::symlink_status(party_file, st_ec);
  if (st_ec == std::errc::no_such_file_or_directory ||
      st_ec == std::errc::not_a_directory ||
      (!st_ec && st.type() == fs::file_type::not_found)) {
    return emit_json(io, Value::object({
                             {"left", Value{true}},
                             {"active", Value{false}},
                             {"already_solo", Value{true}},
                             {"party_file", Value{party_file.string()}},
                         }));
  }
  if (st_ec)
    return fail_error(io, "party leave", {ErrorCode::io, st_ec.value()});
  if (fs::is_symlink(st))
    return fail_error(io, "party leave", {ErrorCode::io, ELOOP});
  if (!fs::is_regular_file(st))
    return fail_error(io, "party leave", {ErrorCode::io, EINVAL});

  std::string previous_room;
  if (auto loaded = load_party_roster_config(party_file); loaded.has_value())
    previous_room = loaded.value().room_scope;

  if (::unlink(party_file.c_str()) != 0) {
    if (errno == ENOENT) {
      return emit_json(io, Value::object({
                               {"left", Value{true}},
                               {"active", Value{false}},
                               {"already_solo", Value{true}},
                               {"party_file", Value{party_file.string()}},
                           }));
    }
    return fail_error(io, "party leave", {ErrorCode::io, errno});
  }

  return emit_json(io, Value::object({
                           {"left", Value{true}},
                           {"active", Value{false}},
                           {"already_solo", Value{false}},
                           {"previous_room", Value{previous_room}},
                           {"party_file", Value{party_file.string()}},
                       }));
}

int run_party_remove_leader(std::span<char *> args, CliIo io) {
  fs::path party_file = fs::path{".blackbird"} / "party.json";
  std::string alias;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err
          << "usage: blackbird party remove-leader --alias NAME [--party-file PATH]\n";
      return 0;
    }
    if (arg == "--alias") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      alias = *v;
    } else if (arg == "--party-file") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      party_file = fs::path{*v};
    } else {
      return fail_usage(io, "party remove-leader: unknown option: " + std::string{arg});
    }
  }

  if (alias.empty())
    return fail_usage(io, "party remove-leader: --alias is required");
  if (!valid_party_alias(alias))
    return fail_usage(io, "party remove-leader: invalid --alias");

  const fs::path parent = party_file.parent_path();
  if (!parent.empty()) {
    std::error_code parent_ec;
    const fs::file_status pst = fs::symlink_status(parent, parent_ec);
    if (!parent_ec && fs::is_symlink(pst))
      return fail_error(io, "party remove-leader", {ErrorCode::io, ELOOP});
  }

  std::error_code st_ec;
  const fs::file_status st = fs::symlink_status(party_file, st_ec);
  if (st_ec == std::errc::no_such_file_or_directory ||
      st_ec == std::errc::not_a_directory ||
      (!st_ec && st.type() == fs::file_type::not_found)) {
    return emit_json(io, Value::object({
                             {"removed", Value{false}},
                             {"alias", Value{alias}},
                             {"party_file", Value{party_file.string()}},
                             {"participant_count", Value{Number{std::uint64_t{0}}}},
                         }));
  }
  if (st_ec)
    return fail_error(io, "party remove-leader", {ErrorCode::io, st_ec.value()});
  if (fs::is_symlink(st))
    return fail_error(io, "party remove-leader", {ErrorCode::io, ELOOP});

  auto loaded = load_party_roster_config(party_file);
  if (!loaded.has_value())
    return fail_error(io, "party remove-leader", loaded.error());
  PartyRosterConfig config = std::move(loaded).value();

  auto match_alias_ci = [&](const PartyRosterPeerConfig &peer) noexcept -> bool {
    if (peer.alias.size() != alias.size())
      return false;
    for (std::size_t i = 0; i < alias.size(); ++i) {
      const char a = (peer.alias[i] >= 'A' && peer.alias[i] <= 'Z')
                         ? static_cast<char>(peer.alias[i] - 'A' + 'a')
                         : peer.alias[i];
      const char b = (alias[i] >= 'A' && alias[i] <= 'Z')
                         ? static_cast<char>(alias[i] - 'A' + 'a')
                         : alias[i];
      if (a != b)
        return false;
    }
    return true;
  };

  bool removed = false;
  if (auto it = std::ranges::find_if(config.peers, match_alias_ci);
      it != config.peers.end()) {
    config.peers.erase(it);
    removed = true;
    auto saved = save_party_roster_config(party_file, config);
    if (!saved.has_value())
      return fail_error(io, "party remove-leader", saved.error());
  }

  return emit_json(io,
                   Value::object({
                       {"removed", Value{removed}},
                       {"alias", Value{alias}},
                       {"party_file", Value{party_file.string()}},
                       {"participant_count",
                        Value{Number{static_cast<std::uint64_t>(config.peers.size())}}},
                   }));
}

int run_party_say(std::span<char *> args, CliIo io) {
  fs::path platoon_dir = fs::path{".blackbird"} / "platoon";
  fs::path party_file = fs::path{".blackbird"} / "party.json";
  fs::path bridge_dir = fs::path{".blackbird"} / "bridge";
  std::optional<fs::path> peers_dir;
  std::optional<std::string> scope;
  std::string from;
  std::string body;
  std::optional<std::string> to_target;
  bool has_body = false;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird party say --from ACTOR --body TEXT [--to TARGET] "
                "[--platoon DIR] [--party-file PATH] [--scope SCOPE]\n";
      return 0;
    }
    if (arg == "--from") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      from = *v;
    } else if (arg == "--body") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      body = *v;
      has_body = true;
    } else if (arg == "--to") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "party say: --to must not be empty");
      to_target = *v;
    } else if (arg == "--platoon") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      platoon_dir = fs::path{*v};
    } else if (arg == "--party-file") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      party_file = fs::path{*v};
    } else if (arg == "--bridge") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      bridge_dir = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      peers_dir = fs::path{*v};
    } else if (arg == "--scope") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "party say: --scope must not be empty");
      scope = *v;
    } else {
      return fail_usage(io, "party say: unknown option: " + std::string{arg});
    }
  }

  if (from.empty() || !has_body)
    return fail_usage(io, "party say: --from and --body are required");
  if (!valid_platoon_member_id(from))
    return fail_usage(io, "party say: invalid --from actor");

  std::string routed_input = body;
  if (to_target.has_value()) {
    std::string_view clean_to{*to_target};
    if (clean_to.starts_with('@'))
      clean_to.remove_prefix(1);
    if (clean_to.empty())
      return fail_usage(io, "party say: invalid --to target");
    for (const char ch : clean_to) {
      const auto b = static_cast<unsigned char>(ch);
      if (b <= 0x20U || b == 0x7fU)
        return fail_usage(io, "party say: invalid --to target");
    }
    routed_input = "@" + std::string{clean_to} + " " + body;
  }

  PartyConfig cfg;
  cfg.party_config_path = party_file;
  cfg.platoon_dir = platoon_dir;
  cfg.bridge_dir = bridge_dir;
  if (peers_dir.has_value()) {
    cfg.known_peers_dir = *peers_dir;
  } else if (const char *home = std::getenv("HOME");
             home != nullptr && home[0] != '\0') {
    cfg.known_peers_dir = fs::path{home} / ".local" / "share" / "blackbird" / "peers";
  }
  if (scope.has_value())
    cfg.room_scope = *scope;

  auto snap_res = load_party_snapshot(cfg);
  if (!snap_res.has_value())
    return fail_error(io, "party say", snap_res.error());

  auto parsed_res = parse_party_input(routed_input, snap_res.value());
  if (!parsed_res.has_value())
    return fail_usage(io, "party say: empty or invalid message body");
  const ParsedPartyInput &parsed = parsed_res.value();

  PlatoonPost post;
  post.from = from;
  post.kind = PlatoonMessageKind::message;
  if (!parsed.broadcast && parsed.resolved_targets.size() == 1 &&
      parsed.unknown_targets.empty() &&
      valid_platoon_member_id(parsed.resolved_targets[0])) {
    post.to = parsed.resolved_targets[0];
    post.text = parsed.body;
  } else if (!parsed.broadcast && parsed.resolved_targets.empty() &&
             parsed.unknown_targets.size() == 1 &&
             valid_platoon_member_id(parsed.unknown_targets[0])) {
    post.to = parsed.unknown_targets[0];
    post.text = parsed.body;
  } else {
    post.to = "all";
    post.text = parsed.broadcast ? parsed.body : routed_input;
  }

  auto board = PlatoonBoard::open(platoon_dir);
  if (!board.has_value())
    return fail_error(io, "party say", board.error());
  auto posted = board.value().post(std::move(post));
  if (!posted.has_value())
    return fail_error(io, "party say", posted.error());

  Value::Array targets_arr;
  targets_arr.reserve(parsed.resolved_targets.size());
  for (const auto &t : parsed.resolved_targets)
    targets_arr.emplace_back(t);

  Value::Array unknown_arr;
  unknown_arr.reserve(parsed.unknown_targets.size());
  for (const auto &u : parsed.unknown_targets)
    unknown_arr.emplace_back(u);

  return emit_json(io, Value::object({
                           {"posted", Value{true}},
                           {"seq", Value{Number{posted.value().seq}}},
                           {"from", Value{posted.value().from}},
                           {"targets", Value{std::move(targets_arr)}},
                           {"unknown_targets", Value{std::move(unknown_arr)}},
                           {"mode", Value{std::string{party_mode_name(parsed.mode)}}},
                       }));
}

volatile std::sig_atomic_t g_party_serve_stop = 0;

void party_serve_signal_handler(int /*signum*/) noexcept { g_party_serve_stop = 1; }

class PartyServeSignalGuard {
public:
  PartyServeSignalGuard() noexcept {
    g_party_serve_stop = 0;
    struct sigaction sa{};
    sa.sa_handler = party_serve_signal_handler;
    sigemptyset(&sa.sa_mask);
    if (::sigaction(SIGINT, &sa, &prev_int_) == 0)
      installed_int_ = true;
    if (::sigaction(SIGTERM, &sa, &prev_term_) == 0)
      installed_term_ = true;
  }

  PartyServeSignalGuard(const PartyServeSignalGuard &) = delete;
  PartyServeSignalGuard &operator=(const PartyServeSignalGuard &) = delete;

  ~PartyServeSignalGuard() {
    if (installed_int_)
      (void)::sigaction(SIGINT, &prev_int_, nullptr);
    if (installed_term_)
      (void)::sigaction(SIGTERM, &prev_term_, nullptr);
  }

private:
  struct sigaction prev_int_{};
  struct sigaction prev_term_{};
  bool installed_int_ = false;
  bool installed_term_ = false;
};

char32_t decode_utf8_scalar_cli(std::string_view text, std::size_t &offset) noexcept {
  const auto b0 = static_cast<unsigned char>(text[offset]);
  if (b0 < 0x80U) {
    ++offset;
    return static_cast<char32_t>(b0);
  }
  if ((b0 & 0xe0U) == 0xc0U && offset + 1U < text.size()) {
    const auto b1 = static_cast<unsigned char>(text[offset + 1U]);
    offset += 2U;
    return (static_cast<char32_t>(b0 & 0x1fU) << 6U) |
           static_cast<char32_t>(b1 & 0x3fU);
  }
  if ((b0 & 0xf0U) == 0xe0U && offset + 2U < text.size()) {
    const auto b1 = static_cast<unsigned char>(text[offset + 1U]);
    const auto b2 = static_cast<unsigned char>(text[offset + 2U]);
    offset += 3U;
    return (static_cast<char32_t>(b0 & 0x0fU) << 12U) |
           (static_cast<char32_t>(b1 & 0x3fU) << 6U) |
           static_cast<char32_t>(b2 & 0x3fU);
  }
  if ((b0 & 0xf8U) == 0xf0U && offset + 3U < text.size()) {
    const auto b1 = static_cast<unsigned char>(text[offset + 1U]);
    const auto b2 = static_cast<unsigned char>(text[offset + 2U]);
    const auto b3 = static_cast<unsigned char>(text[offset + 3U]);
    offset += 4U;
    return (static_cast<char32_t>(b0 & 0x07U) << 18U) |
           (static_cast<char32_t>(b1 & 0x3fU) << 12U) |
           (static_cast<char32_t>(b2 & 0x3fU) << 6U) |
           static_cast<char32_t>(b3 & 0x3fU);
  }
  offset = text.size();
  return 0x110000U;
}

bool is_forbidden_socket_scalar_cli(char32_t cp) noexcept {
  if (cp < 0x20U || (cp >= 0x7fU && cp <= 0x9fU) || cp > 0x10ffffU)
    return true;
  return (cp >= 0x202aU && cp <= 0x202eU) || (cp >= 0x2066U && cp <= 0x2069U) ||
         cp == 0x200eU || cp == 0x200fU || cp == 0x061cU || cp == 0xfeffU;
}

bool valid_party_socket_path_arg(std::string_view raw) noexcept {
  if (raw.empty() || !valid_utf8(raw))
    return false;
  std::size_t i = 0;
  while (i < raw.size()) {
    const char32_t cp = decode_utf8_scalar_cli(raw, i);
    if (is_forbidden_socket_scalar_cli(cp))
      return false;
  }
  const fs::path candidate{raw};
  if (candidate.filename().empty() || candidate.filename() == ".")
    return false;
  for (const auto &comp : candidate) {
    if (comp == "..")
      return false;
  }
  return true;
}

fs::path strip_trailing_slashes_party(const fs::path &path) {
  std::string text = path.string();
  while (text.size() > 1U && text.back() == '/')
    text.pop_back();
  return fs::path{std::move(text)};
}

bool has_existing_peer_identity_files(const fs::path &peers_dir) {
  if (peers_dir.empty())
    return false;
  const fs::path clean_dir = strip_trailing_slashes_party(peers_dir);
  std::error_code ec;
  const fs::file_status dir_st = fs::symlink_status(clean_dir, ec);
  if (ec || fs::is_symlink(dir_st) || !fs::is_directory(dir_st))
    return false;
  const fs::file_status key_st = fs::symlink_status(clean_dir / "id_ed25519", ec);
  if (ec || fs::is_symlink(key_st) || !fs::is_regular_file(key_st))
    return false;
  const fs::file_status pub_st = fs::symlink_status(clean_dir / "id_ed25519.pub", ec);
  return !ec && !fs::is_symlink(pub_st) && fs::is_regular_file(pub_st);
}

Value party_message_to_value(const PartyMessage &m) {
  return Value::object({
      {"id", Value{m.id}},
      {"timestamp_ns", Value{Number{m.timestamp_ns}}},
      {"sender_id", Value{m.sender_id}},
      {"sender_role", Value{std::string{party_member_role_name(m.sender_role)}}},
      {"sender_host", Value{m.sender_host}},
      {"sender_model", Value{m.sender_model}},
      {"sender_fingerprint", Value{m.sender_fingerprint}},
      {"verified_peer", Value{m.verified_peer}},
      {"target", Value{m.target}},
      {"kind", Value{std::string{party_message_kind_name(m.kind)}}},
      {"body", Value{m.body}},
      {"untrusted_remote", Value{m.untrusted_remote}},
  });
}

int run_party_serve(std::span<char *> args, CliIo io) {
  std::optional<fs::path> socket_path;
  std::optional<fs::path> peers_dir;
  std::optional<std::uint64_t> idle_timeout_ms;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird party serve [--socket PATH] [--peers DIR] "
                "[--idle-timeout-ms N]\n";
      return 0;
    }
    if (arg == "--socket") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_party_socket_path_arg(*v))
        return fail_usage(io, "party serve: invalid --socket path");
      socket_path = fs::path{*v};
    } else if (arg == "--peers") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "party serve: --peers must not be empty");
      peers_dir = strip_trailing_slashes_party(fs::path{*v});
    } else if (arg == "--idle-timeout-ms") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      constexpr std::uint64_t kMaxIdleTimeoutMs = 7ULL * 24ULL * 3600ULL * 1000ULL;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed == 0 || *parsed > kMaxIdleTimeoutMs) {
        return fail_usage(io, "party serve: --idle-timeout-ms must be between 1 and " +
                                  std::to_string(kMaxIdleTimeoutMs));
      }
      idle_timeout_ms = *parsed;
    } else {
      return fail_usage(io, "party serve: unknown option: " + std::string{arg});
    }
  }

  if (!socket_path.has_value()) {
    if (const char *env_sock = std::getenv("BLACKBIRD_PARTY_SOCKET");
        env_sock != nullptr && env_sock[0] != '\0') {
      if (!valid_party_socket_path_arg(env_sock))
        return fail_usage(io, "party serve: invalid BLACKBIRD_PARTY_SOCKET");
      socket_path = fs::path{env_sock};
    } else {
      socket_path = default_party_socket_path();
    }
  }

  if (!peers_dir.has_value()) {
    if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0')
      peers_dir = fs::path{home} / ".local" / "share" / "blackbird" / "peers";
  }

  PartyLobbyServerConfig cfg{};
  cfg.socket_path = *socket_path;
  if (peers_dir.has_value()) {
    cfg.known_peers_dir = *peers_dir;
    if (has_existing_peer_identity_files(*peers_dir))
      cfg.local_identity_dir = *peers_dir;
  }

  PartyServeSignalGuard signal_guard{};
  auto server_res = PartyLobbyServer::start(std::move(cfg));
  if (!server_res.has_value())
    return fail_error(io, "party serve", server_res.error());
  auto server = std::move(server_res).value();

  auto ready_json = dump_json(Value::object({
      {"listening", Value{true}},
      {"socket", Value{server->socket_path().string()}},
  }));
  if (!ready_json.has_value()) {
    server->stop();
    return fail_error(io, "party serve", ready_json.error());
  }
  io.out << ready_json.value() << '\n' << std::flush;
  if (!io.out) {
    server->stop();
    return fail_message(io, "party serve: failed to write stdout");
  }

  using SteadyClock = std::chrono::steady_clock;
  auto last_activity = SteadyClock::now();
  PartySnapshot last_snap = server->snapshot();

  while (g_party_serve_stop == 0 && server->running()) {
    int sleep_ms = 50;
    if (idle_timeout_ms.has_value()) {
      const auto now = SteadyClock::now();
      PartySnapshot cur = server->snapshot();
      if (cur != last_snap) {
        last_snap = std::move(cur);
        last_activity = now;
      } else {
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - last_activity)
                .count();
        const auto limit_ms = static_cast<std::int64_t>(*idle_timeout_ms);
        if (elapsed_ms >= limit_ms)
          break;
        sleep_ms =
            static_cast<int>(std::clamp<std::int64_t>(limit_ms - elapsed_ms, 1, 25));
      }
    }
    struct pollfd unused_pfd{};
    (void)::poll(&unused_pfd, 0, sleep_ms);
  }

  server->stop();
  return 0;
}

int run_party_lobby_status(std::span<char *> args, CliIo io) {
  std::optional<fs::path> socket_path;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird party lobby-status [--socket PATH]\n";
      return 0;
    }
    if (arg == "--socket") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_party_socket_path_arg(*v))
        return fail_usage(io, "party lobby-status: invalid --socket path");
      socket_path = fs::path{*v};
    } else {
      return fail_usage(io, "party lobby-status: unknown option: " + std::string{arg});
    }
  }

  if (!socket_path.has_value()) {
    if (const char *env_sock = std::getenv("BLACKBIRD_PARTY_SOCKET");
        env_sock != nullptr && env_sock[0] != '\0') {
      if (!valid_party_socket_path_arg(env_sock))
        return fail_usage(io, "party lobby-status: invalid BLACKBIRD_PARTY_SOCKET");
      socket_path = fs::path{env_sock};
    } else {
      socket_path = default_party_socket_path();
    }
  }

  auto client_res = PartyLobbyClient::connect(*socket_path);
  if (!client_res.has_value())
    return emit_json(io, Value::object({{"running", Value{false}}}));

  auto ping_res = client_res.value().ping();
  if (!ping_res.has_value() || !ping_res.value().ok)
    return emit_json(io, Value::object({{"running", Value{false}}}));

  auto snap_res = client_res.value().snapshot();
  if (!snap_res.has_value())
    return emit_json(io, Value::object({{"running", Value{false}}}));

  const PartyLobbyPing &pong = ping_res.value();
  const PartySnapshot &snap = snap_res.value();

  Value::Array participants;
  participants.reserve(snap.participants.size());
  for (const auto &p : snap.participants)
    participants.push_back(party_participant_to_value(p));

  Value::Array messages;
  messages.reserve(snap.messages.size());
  for (const auto &m : snap.messages)
    messages.push_back(party_message_to_value(m));

  Value::Array conflicts;
  conflicts.reserve(snap.conflicts.size());
  for (const auto &c : snap.conflicts)
    conflicts.push_back(conflict_to_value(c));

  return emit_json(
      io,
      Value::object({
          {"running", Value{true}},
          {"socket", Value{socket_path->string()}},
          {"protocol_version", Value{Number{pong.protocol_version}}},
          {"revocation_epoch", Value{Number{pong.revocation_epoch}}},
          {"server_pid", Value{Number{pong.server_pid}}},
          {"room_count", Value{Number{static_cast<std::uint64_t>(pong.room_count)}}},
          {"active_room_id", pong.active_room_id.has_value()
                                 ? Value{*pong.active_room_id}
                                 : Value{nullptr}},
          {"room_scope", Value{snap.room_scope}},
          {"scope", Value{snap.room_scope}},
          {"mode", Value{std::string{party_mode_name(snap.mode)}}},
          {"mode_override",
           Value{std::string{party_mode_override_name(snap.mode_override)}}},
          {"participant_count",
           Value{Number{static_cast<std::uint64_t>(snap.participants.size())}}},
          {"message_count",
           Value{Number{static_cast<std::uint64_t>(snap.messages.size())}}},
          {"participants", Value{std::move(participants)}},
          {"messages", Value{std::move(messages)}},
          {"conflicts", Value{std::move(conflicts)}},
          {"known_peers_present", Value{snap.known_peers_present}},
      }));
}

int run_party_cli(std::span<char *> args, CliIo io) {
  if (args.size() < 2) {
    return fail_usage(io, "party: expected action "
                          "(serve|lobby-status|roster|create|leave|add-leader|"
                          "remove-leader|say)");
  }
  const std::string_view action{args[1]};
  if (action == "--help" || action == "-h") {
    io.err << "usage: blackbird party {serve|lobby-status|roster|create|leave|"
              "add-leader|remove-leader|say} [options]\n";
    return 0;
  }
  if (action == "serve")
    return run_party_serve(args, io);
  if (action == "lobby-status")
    return run_party_lobby_status(args, io);
  if (action == "roster")
    return run_party_roster(args, io);
  if (action == "create")
    return run_party_create(args, io);
  if (action == "leave")
    return run_party_leave(args, io);
  if (action == "add-leader")
    return run_party_add_leader(args, io);
  if (action == "remove-leader")
    return run_party_remove_leader(args, io);
  if (action == "say")
    return run_party_say(args, io);
  return fail_usage(io, "party: unknown action: " + std::string{action});
}

// ============================================================================
// 11. blackbird flightdeck (Detachable Second-Window Hero v24 Cockpit)
// ============================================================================

volatile std::sig_atomic_t g_flightdeck_stop = 0;

void flightdeck_signal_handler(int /*signum*/) noexcept { g_flightdeck_stop = 1; }

void write_fd_all(int fd, std::string_view data) noexcept {
  std::size_t offset = 0;
  int retry_budget = 8;
  while (offset < data.size()) {
    const ssize_t n = ::write(fd, data.data() + offset, data.size() - offset);
    if (n > 0) {
      offset += static_cast<std::size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && retry_budget > 0) {
      --retry_budget;
      struct pollfd pfd{fd, POLLOUT, 0};
      (void)::poll(&pfd, 1, 25);
      continue;
    }
    break;
  }
}

struct FlightDeckViewportCells {
  std::size_t columns = 80;
  std::size_t rows = 24;
};

FlightDeckViewportCells query_flightdeck_viewport() noexcept {
  FlightDeckViewportCells cells{};
  struct winsize ws{};
  if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
    if (ws.ws_col >= 20)
      cells.columns = std::clamp<std::size_t>(ws.ws_col, 20, 400);
    if (ws.ws_row >= 8)
      cells.rows = std::clamp<std::size_t>(ws.ws_row, 8, 200);
  }
  return cells;
}

class FlightDeckSignalGuard {
public:
  FlightDeckSignalGuard() noexcept {
    g_flightdeck_stop = 0;
    struct sigaction sa{};
    sa.sa_handler = flightdeck_signal_handler;
    sigemptyset(&sa.sa_mask);
    if (::sigaction(SIGINT, &sa, &prev_int_) == 0)
      installed_int_ = true;
    if (::sigaction(SIGTERM, &sa, &prev_term_) == 0)
      installed_term_ = true;
  }

  FlightDeckSignalGuard(const FlightDeckSignalGuard &) = delete;
  FlightDeckSignalGuard &operator=(const FlightDeckSignalGuard &) = delete;

  ~FlightDeckSignalGuard() {
    if (installed_int_)
      (void)::sigaction(SIGINT, &prev_int_, nullptr);
    if (installed_term_)
      (void)::sigaction(SIGTERM, &prev_term_, nullptr);
  }

private:
  struct sigaction prev_int_{};
  struct sigaction prev_term_{};
  bool installed_int_ = false;
  bool installed_term_ = false;
};

class FlightDeckTerminalGuard {
public:
  explicit FlightDeckTerminalGuard(bool kitty_mode) noexcept : use_kitty_(kitty_mode) {
    if (::tcgetattr(STDIN_FILENO, &original_) != 0)
      return;
    struct termios raw = original_;
    raw.c_iflag &= static_cast<tcflag_t>(
        ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON));
    raw.c_lflag &= static_cast<tcflag_t>(~(ECHO | ECHONL | ICANON | ISIG | IEXTEN));
    raw.c_cflag &= static_cast<tcflag_t>(~(CSIZE | PARENB));
    raw.c_cflag |= static_cast<tcflag_t>(CS8);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0)
      return;
    active_ = true;
    write_fd_all(STDOUT_FILENO, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
  }

  FlightDeckTerminalGuard(const FlightDeckTerminalGuard &) = delete;
  FlightDeckTerminalGuard &operator=(const FlightDeckTerminalGuard &) = delete;

  ~FlightDeckTerminalGuard() {
    if (!active_)
      return;
    if (use_kitty_) {
      const std::string erase = encode_kitty_erase(hero_default_kitty_image_id);
      write_fd_all(STDOUT_FILENO, erase);
    }
    write_fd_all(STDOUT_FILENO, "\x1b[0m\x1b[?25h\x1b[?1049l");
    (void)::tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
  }

  bool active() const noexcept { return active_; }

private:
  bool active_ = false;
  bool use_kitty_ = false;
  struct termios original_{};
};

std::optional<fs::path> find_newest_flightdeck_session() {
  const char *home = std::getenv("HOME");
  if (home == nullptr || home[0] == '\0')
    return std::nullopt;
  const fs::path state_dir = fs::path{home} / ".local" / "state" / "blackbird";
  std::error_code ec;
  const fs::file_status st = fs::symlink_status(state_dir, ec);
  if (ec || fs::is_symlink(st) || !fs::is_directory(st))
    return std::nullopt;

  std::optional<fs::path> best;
  fs::file_time_type best_time{};
  bool has_best = false;
  for (fs::directory_iterator it{state_dir, ec}; !ec && it != fs::directory_iterator{};
       it.increment(ec)) {
    const fs::path candidate = it->path();
    const std::string name = candidate.filename().string();
    if (!name.starts_with("session-"))
      continue;
    std::error_code entry_ec;
    const fs::file_status est = fs::symlink_status(candidate, entry_ec);
    if (entry_ec || fs::is_symlink(est) || !fs::is_directory(est))
      continue;
    fs::file_time_type mtime{};
    const fs::path audit_path = candidate / "audit";
    std::error_code mtime_ec;
    const fs::file_status ast = fs::symlink_status(audit_path, mtime_ec);
    if (!mtime_ec && !fs::is_symlink(ast) && fs::is_regular_file(ast)) {
      mtime = fs::last_write_time(audit_path, mtime_ec);
    } else {
      mtime_ec.clear();
      mtime = fs::last_write_time(candidate, mtime_ec);
    }
    if (mtime_ec)
      continue;
    if (!has_best || mtime > best_time) {
      has_best = true;
      best_time = mtime;
      best = candidate;
    }
  }
  return best;
}

struct FlightDeckRateTracker {
  bool initialized = false;
  std::chrono::steady_clock::time_point last_time{};
  std::uint64_t last_total_tokens = 0;
  std::uint64_t last_out_rsn_tokens = 0;
  double total_tok_per_sec = 0.0;
  double out_rsn_tok_per_sec = 0.0;
  std::optional<fs::path> consumer_session;
  std::optional<MetricsConsumer> consumer;
};

fs::path strip_trailing_slashes(const fs::path &path) {
  std::string text = path.string();
  while (text.size() > 1 && text.back() == '/')
    text.pop_back();
  return fs::path{std::move(text)};
}

HeroTelemetryInput observe_flightdeck_telemetry(const std::optional<fs::path> &session,
                                                FlightDeckRateTracker &tracker) {
  HeroTelemetryInput telemetry{};
  telemetry.cache_hit_ratio = 0.85;
  telemetry.active_agents = 1;
  telemetry.total_agents = 1;

  if (!session.has_value()) {
    std::error_code ec;
    const fs::path cwd = strip_trailing_slashes(fs::current_path(ec));
    if (!ec && !cwd.empty()) {
      const std::string base = cwd.filename().string();
      telemetry.room_label = sanitize_hero_text(base.empty() ? cwd.string() : base, 32);
    }
    return telemetry;
  }

  const fs::path clean_session = strip_trailing_slashes(*session);
  const std::string base = clean_session.filename().string();
  telemetry.room_label =
      sanitize_hero_text(base.empty() ? clean_session.string() : base, 32);

  std::error_code ec;
  const fs::file_status st = fs::symlink_status(clean_session, ec);
  if (ec || fs::is_symlink(st) || !fs::is_directory(st))
    return telemetry;

  if (!tracker.consumer.has_value() || !tracker.consumer_session.has_value() ||
      *tracker.consumer_session != clean_session) {
    tracker.consumer = MetricsConsumer::from_token_usage_directory(clean_session);
    tracker.consumer_session = clean_session;
  }
  if (!tracker.consumer->refresh().has_value())
    return telemetry;

  const MetricsSnapshot &snap = tracker.consumer->snapshot();
  telemetry.input_tokens = snap.usage.total_input_tokens.value.value_or(0);
  telemetry.cached_tokens = snap.usage.total_cached_tokens.value.value_or(0);
  telemetry.reasoning_tokens = snap.usage.total_reasoning_tokens.value.value_or(0);
  telemetry.output_tokens = snap.usage.total_output_tokens.value.value_or(0);
  telemetry.cache_hit_ratio = snap.usage.cache_hit_ratio.value.value_or(0.85);
  telemetry.jev_calls = snap.decision_companion.batch_count.value.value_or(0);

  const std::uint64_t total_tokens = telemetry.input_tokens + telemetry.cached_tokens +
                                     telemetry.reasoning_tokens +
                                     telemetry.output_tokens;
  const std::uint64_t out_rsn_tokens =
      telemetry.reasoning_tokens + telemetry.output_tokens;

  const auto now = std::chrono::steady_clock::now();
  if (tracker.initialized) {
    const double dt = std::chrono::duration<double>(now - tracker.last_time).count();
    if (dt >= 0.05) {
      const std::uint64_t d_total = total_tokens > tracker.last_total_tokens
                                        ? (total_tokens - tracker.last_total_tokens)
                                        : 0;
      const std::uint64_t d_out = out_rsn_tokens > tracker.last_out_rsn_tokens
                                      ? (out_rsn_tokens - tracker.last_out_rsn_tokens)
                                      : 0;
      if (d_total > 0) {
        tracker.total_tok_per_sec = static_cast<double>(d_total) / dt;
        tracker.out_rsn_tok_per_sec = static_cast<double>(d_out) / dt;
        telemetry.busy = true;
      } else {
        tracker.total_tok_per_sec *= 0.65;
        tracker.out_rsn_tok_per_sec *= 0.65;
      }
      tracker.last_time = now;
      tracker.last_total_tokens = total_tokens;
      tracker.last_out_rsn_tokens = out_rsn_tokens;
    }
  } else {
    tracker.initialized = true;
    tracker.last_time = now;
    tracker.last_total_tokens = total_tokens;
    tracker.last_out_rsn_tokens = out_rsn_tokens;
  }

  telemetry.total_tok_per_sec = tracker.total_tok_per_sec;
  telemetry.out_rsn_tok_per_sec = tracker.out_rsn_tok_per_sec;

  for (const auto &prov : snap.usage.by_provider) {
    HeroPeerEntry entry{};
    entry.name = sanitize_hero_text(prov.provider, 20);
    entry.tokens = prov.input_tokens.value.value_or(0) +
                   prov.output_tokens.value.value_or(0) +
                   prov.reasoning_tokens.value.value_or(0);
    entry.active = telemetry.busy;
    telemetry.peers.push_back(std::move(entry));
  }
  if (telemetry.jev_calls > 0) {
    HeroPeerEntry jev_entry{};
    jev_entry.name = "jev";
    jev_entry.jev_calls = telemetry.jev_calls;
    jev_entry.is_jev = true;
    jev_entry.active = telemetry.busy;
    telemetry.peers.push_back(std::move(jev_entry));
  }
  if (!telemetry.peers.empty()) {
    telemetry.total_agents = telemetry.peers.size();
    telemetry.active_agents = telemetry.busy ? telemetry.peers.size() : 1;
  }
  return telemetry;
}

HeroQuestion sample_flightdeck_question() {
  return HeroQuestion{
      .from = "flightdeck",
      .text = "SELECT FLIGHT VECTOR",
      .detail = "Fly through gate or press 1-3 (g to dismiss)",
      .options = {"CRUISE", "AFTERBURNER", "STEALTH"},
  };
}

int emit_flightdeck_once(const HeroFrame &frame, bool use_kitty, CliIo io) {
  const FlightDeckViewportCells cells = ::isatty(STDOUT_FILENO) != 0
                                            ? query_flightdeck_viewport()
                                            : FlightDeckViewportCells{};
  if (use_kitty) {
    const std::string encoded = encode_kitty_rgba_frame(
        frame, HeroKittyPlacement{.row = 0,
                                  .column = 0,
                                  .columns = cells.columns,
                                  .rows = cells.rows,
                                  .image_id = hero_default_kitty_image_id,
                                  .placement_id = 1});
    io.out << encoded << '\n' << std::flush;
  } else {
    const auto lines = encode_truecolor_halfblock_frame(
        frame, HeroHalfBlockOptions{.columns = cells.columns, .rows = cells.rows});
    for (const auto &line : lines)
      io.out << line << '\n';
    io.out.flush();
  }
  if (!io.out)
    return fail_message(io, "flightdeck: failed to write frame to stdout");
  return 0;
}

int run_flightdeck_cli(std::span<char *> args, CliIo io) {
  std::optional<fs::path> explicit_session;
  HeroThemeId theme = HeroThemeId::synthwave;
  std::uint32_t fps = 24;
  std::uint32_t width = hero_default_width;
  std::uint32_t height = hero_default_height;
  bool once = false;
  bool halfblock = false;

  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird flightdeck [--session DIR] "
                "[--theme synthwave|tokyonight|gotham|kanagawa|nord|hackerman|"
                "retro82|dyingearth] [--fps 1..30] [--width PX] [--height PX] "
                "[--once] [--halfblock] [--help]\n";
      return 0;
    }
    if (arg == "--session") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty())
        return fail_usage(io, "flightdeck: --session must not be empty");
      explicit_session = strip_trailing_slashes(fs::path{*v});
    } else if (arg == "--theme") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_hero_theme(*v);
      if (!parsed.has_value())
        return fail_usage(io, "flightdeck: invalid --theme: " + *v);
      theme = *parsed;
    } else if (arg == "--fps") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed < 1 || *parsed > 30)
        return fail_usage(io, "flightdeck: --fps must be between 1 and 30");
      fps = static_cast<std::uint32_t>(*parsed);
    } else if (arg == "--width") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed < hero_min_width || *parsed > hero_max_width) {
        return fail_usage(io, "flightdeck: --width must be between " +
                                  std::to_string(hero_min_width) + " and " +
                                  std::to_string(hero_max_width));
      }
      width = static_cast<std::uint32_t>(*parsed);
    } else if (arg == "--height") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed < hero_min_height ||
          *parsed > hero_max_height) {
        return fail_usage(io, "flightdeck: --height must be between " +
                                  std::to_string(hero_min_height) + " and " +
                                  std::to_string(hero_max_height));
      }
      height = static_cast<std::uint32_t>(*parsed);
    } else if (arg == "--once") {
      once = true;
    } else if (arg == "--halfblock") {
      halfblock = true;
    } else {
      return fail_usage(io, "flightdeck: unknown option: " + std::string{arg});
    }
  }

  if (explicit_session.has_value()) {
    std::error_code sym_ec;
    const fs::file_status sym_st = fs::symlink_status(*explicit_session, sym_ec);
    if (!sym_ec && fs::is_symlink(sym_st))
      return fail_error(io, "flightdeck", {ErrorCode::io, ELOOP});
  }

  const std::optional<fs::path> observed_session =
      explicit_session.has_value() ? explicit_session
                                   : find_newest_flightdeck_session();

  HeroFlightDeckEngine engine{HeroCanvasConfig{
      .size = HeroSize{.width = width, .height = height},
      .theme = theme,
      .seed = 11,
  }};

  FlightDeckRateTracker rate_tracker{};
  engine.set_telemetry(observe_flightdeck_telemetry(observed_session, rate_tracker));

  const bool use_kitty = !halfblock && kitty_graphics_capable();
  const bool use_kitty_shm = use_kitty && kitty_shm_capable();
  const float nominal_dt = 1.0F / static_cast<float>(fps);

  const bool interactive_tty =
      !once && ::isatty(STDIN_FILENO) != 0 && ::isatty(STDOUT_FILENO) != 0;
  if (!interactive_tty) {
    const HeroFrame &frame = engine.step_and_render(nominal_dt);
    return emit_flightdeck_once(frame, use_kitty, io);
  }

  FlightDeckSignalGuard signal_guard{};
  FlightDeckTerminalGuard terminal_guard{use_kitty};
  if (!terminal_guard.active())
    return fail_message(io, "flightdeck: failed to initialize raw terminal");

  using SteadyClock = std::chrono::steady_clock;
  const auto frame_period =
      std::chrono::microseconds{1'000'000LL / static_cast<std::int64_t>(fps)};
  constexpr auto kKeyHoldDuration = std::chrono::milliseconds{180};
  constexpr auto kTelemetryRefreshInterval = std::chrono::milliseconds{500};
  constexpr auto kSessionRescanInterval = std::chrono::milliseconds{5000};
  constexpr auto kBareEscTimeout = std::chrono::milliseconds{25};
  constexpr std::size_t kMaxPendingInputBytes = 256U;

  auto last_frame_time = SteadyClock::now();
  auto next_frame_time = last_frame_time;
  auto last_telemetry_time = last_frame_time;
  auto last_session_scan_time = last_frame_time;
  std::optional<fs::path> active_session = observed_session;

  SteadyClock::time_point left_until{};
  SteadyClock::time_point right_until{};
  SteadyClock::time_point up_until{};
  SteadyClock::time_point down_until{};

  std::optional<FlightDeckViewportCells> prev_cells;
  std::vector<std::string> prev_hb_rows;
  std::string pending_input;
  std::optional<SteadyClock::time_point> esc_deadline;

  auto apply_arrow_code = [&](char code, SteadyClock::time_point ts) noexcept {
    if (code == 'A') {
      up_until = ts + kKeyHoldDuration;
      down_until = {};
    } else if (code == 'B') {
      down_until = ts + kKeyHoldDuration;
      up_until = {};
    } else if (code == 'C') {
      right_until = ts + kKeyHoldDuration;
      left_until = {};
    } else if (code == 'D') {
      left_until = ts + kKeyHoldDuration;
      right_until = {};
    }
  };

  bool quit = false;
  while (!quit && g_flightdeck_stop == 0) {
    const auto now = SteadyClock::now();

    if (now - last_telemetry_time >= kTelemetryRefreshInterval) {
      if (!explicit_session.has_value() &&
          now - last_session_scan_time >= kSessionRescanInterval) {
        active_session = find_newest_flightdeck_session();
        last_session_scan_time = now;
      }
      engine.set_telemetry(observe_flightdeck_telemetry(active_session, rate_tracker));
      last_telemetry_time = now;
    }

    HeroControlInput ctrl{};
    ctrl.left = now < left_until;
    ctrl.right = now < right_until;
    ctrl.up = now < up_until;
    ctrl.down = now < down_until;
    engine.steer_input(ctrl);

    const float dt = std::clamp(
        std::chrono::duration<float>(now - last_frame_time).count(), 0.005F, 0.1F);
    last_frame_time = now;

    const HeroFrame &frame = engine.step_and_render(dt);
    const FlightDeckViewportCells cells = query_flightdeck_viewport();
    const bool resized = !prev_cells.has_value() ||
                         prev_cells->columns != cells.columns ||
                         prev_cells->rows != cells.rows;
    prev_cells = cells;

    if (use_kitty) {
      const HeroKittyPlacement placement{.row = 0,
                                         .column = 0,
                                         .columns = cells.columns,
                                         .rows = cells.rows,
                                         .image_id = hero_default_kitty_image_id,
                                         .placement_id = 1};
      const std::string encoded = use_kitty_shm
                                      ? encode_kitty_shm_rgb_frame(frame, placement)
                                      : encode_kitty_rgb_frame(frame, placement);
      std::string out;
      out.reserve(encoded.size() + 64U);
      out += "\x1b[?2026h";
      if (resized) {
        out += encode_kitty_erase(hero_default_kitty_image_id);
        out += "\x1b[2J";
      }
      out += encoded;
      out += "\x1b[?2026l";
      write_fd_all(STDOUT_FILENO, out);
    } else {
      const auto lines = encode_truecolor_halfblock_frame(
          frame, HeroHalfBlockOptions{.columns = cells.columns, .rows = cells.rows});
      const std::string diff = encode_halfblock_diff(HeroHalfBlockDiff{
          .prev_rows = prev_hb_rows,
          .curr_rows = lines,
          .full_redraw = resized,
      });
      prev_hb_rows = lines;
      if (resized || !diff.empty()) {
        std::string out;
        out.reserve(diff.size() + 48U);
        out += "\x1b[?2026h";
        if (resized)
          out += "\x1b[2J";
        out += diff;
        if (resized)
          out += "\x1b[0m\x1b[J";
        out += "\x1b[?2026l";
        write_fd_all(STDOUT_FILENO, out);
      }
    }

    next_frame_time += frame_period;
    const auto after_render = SteadyClock::now();
    if (next_frame_time < after_render)
      next_frame_time = after_render;

    while (!quit && g_flightdeck_stop == 0) {
      const auto poll_now = SteadyClock::now();
      if (esc_deadline.has_value() && poll_now >= *esc_deadline) {
        esc_deadline.reset();
        if (pending_input == "\x1b") {
          pending_input.clear();
          quit = true;
          break;
        }
        // Discard a truncated incomplete escape sequence without quitting.
        pending_input.clear();
      }
      if (poll_now >= next_frame_time)
        break;
      const auto target_wake = esc_deadline.has_value()
                                   ? std::min(next_frame_time, *esc_deadline)
                                   : next_frame_time;
      const auto remain_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(target_wake - poll_now)
              .count();
      const int timeout_ms =
          static_cast<int>(std::clamp<std::int64_t>(remain_ms, 1, 50));
      struct pollfd pfd{STDIN_FILENO, POLLIN, 0};
      const int prc = ::poll(&pfd, 1, timeout_ms);
      if (prc <= 0) {
        if (prc < 0 && errno != EINTR)
          quit = true;
        continue;
      }
      if ((pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
        quit = true;
        break;
      }
      std::array<char, 64> buf{};
      const ssize_t got = ::read(STDIN_FILENO, buf.data(), buf.size());
      if (got < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
          continue;
        quit = true;
        break;
      }
      if (got == 0) {
        quit = true;
        break;
      }
      const auto input_now = SteadyClock::now();
      const auto got_len = static_cast<std::size_t>(got);
      if (pending_input.size() + got_len > kMaxPendingInputBytes) {
        pending_input.clear();
        esc_deadline.reset();
      }
      pending_input.append(buf.data(), got_len);

      while (!pending_input.empty() && !quit) {
        const unsigned char ch = static_cast<unsigned char>(pending_input[0]);
        if (ch == 0x1bU) {
          if (pending_input.size() == 1U) {
            if (!esc_deadline.has_value())
              esc_deadline = input_now + kBareEscTimeout;
            break;
          }
          const char next = pending_input[1];
          if (next == '[') {
            std::size_t pos = 2;
            bool embedded_esc = false;
            while (pos < pending_input.size()) {
              const auto sb = static_cast<unsigned char>(pending_input[pos]);
              if (sb == 0x1bU) {
                embedded_esc = true;
                break;
              }
              if (sb >= 0x40U && sb <= 0x7eU)
                break;
              ++pos;
            }
            if (embedded_esc) {
              esc_deadline.reset();
              pending_input.erase(0, pos);
              continue;
            }
            if (pos >= pending_input.size()) {
              if (pending_input.size() >= 32U) {
                pending_input.clear();
                esc_deadline.reset();
              } else {
                esc_deadline = input_now + kBareEscTimeout;
              }
              break;
            }
            esc_deadline.reset();
            apply_arrow_code(pending_input[pos], input_now);
            pending_input.erase(0, pos + 1U);
            continue;
          }
          if (next == 'O') {
            if (pending_input.size() < 3U) {
              esc_deadline = input_now + kBareEscTimeout;
              break;
            }
            esc_deadline.reset();
            apply_arrow_code(pending_input[2], input_now);
            pending_input.erase(0, 3U);
            continue;
          }
          esc_deadline.reset();
          if (next == 0x1b) {
            pending_input.erase(0, 2U);
            quit = true;
            break;
          }
          // Non-arrow Alt+key sequence (e.g. Alt+t): consume cleanly without quitting.
          pending_input.erase(0, 2U);
          continue;
        }

        esc_deadline.reset();
        pending_input.erase(0, 1U);
        if (ch == 0x03U || ch == 'q' || ch == 'Q') {
          quit = true;
          break;
        }
        if (ch == 'w' || ch == 'W') {
          up_until = input_now + kKeyHoldDuration;
          down_until = {};
        } else if (ch == 's' || ch == 'S') {
          down_until = input_now + kKeyHoldDuration;
          up_until = {};
        } else if (ch == 'a' || ch == 'A') {
          left_until = input_now + kKeyHoldDuration;
          right_until = {};
        } else if (ch == 'd' || ch == 'D') {
          right_until = input_now + kKeyHoldDuration;
          left_until = {};
        } else if (ch == 't' || ch == 'T') {
          engine.cycle_theme();
        } else if (ch == 'g' || ch == 'G') {
          if (engine.has_question())
            engine.set_question(std::nullopt);
          else
            engine.set_question(sample_flightdeck_question());
        } else if (ch == '1') {
          (void)engine.answer_by_key(0);
        } else if (ch == '2') {
          (void)engine.answer_by_key(1);
        } else if (ch == '3') {
          (void)engine.answer_by_key(2);
        }
      }
    }
  }

  return 0;
}

// ============================================================================
// 12. blackbird online (Signed TLS 1.3 Multiplayer Control-Plane CLI)
// ============================================================================

inline constexpr std::string_view kDefaultOnlineRelayUrl =
    "https://relay.multiplayer.tech";
inline constexpr std::string_view kDefaultOnlineDeviceLabel = "blackbird-cli";

struct OnlineCleanseStringGuard {
  std::string &text;
  ~OnlineCleanseStringGuard() {
    if (!text.empty())
      OPENSSL_cleanse(text.data(), text.size());
  }
};

struct OnlineCleanseOptStringGuard {
  std::optional<std::string> &text;
  ~OnlineCleanseOptStringGuard() {
    if (text.has_value() && !text->empty())
      OPENSSL_cleanse(text->data(), text->size());
  }
};

struct OnlineCleanseSeedGuard {
  mp::Ed25519Seed &seed;
  ~OnlineCleanseSeedGuard() { OPENSSL_cleanse(seed.data(), seed.size()); }
};

class TermiosEchoGuard {
public:
  explicit TermiosEchoGuard(int fd) noexcept : fd_(fd) {
    if (fd_ >= 0 && ::tcgetattr(fd_, &saved_) == 0) {
      termios noecho = saved_;
      noecho.c_lflag &= ~static_cast<tcflag_t>(ECHO);
      if (::tcsetattr(fd_, TCSANOW, &noecho) == 0)
        active_ = true;
    }
  }
  TermiosEchoGuard(const TermiosEchoGuard &) = delete;
  TermiosEchoGuard &operator=(const TermiosEchoGuard &) = delete;
  ~TermiosEchoGuard() {
    if (active_)
      (void)::tcsetattr(fd_, TCSANOW, &saved_);
  }

private:
  int fd_ = -1;
  termios saved_{};
  bool active_ = false;
};

std::string escape_terminal_display(std::string_view raw) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(raw.size());
  for (const char ch : raw) {
    const auto byte = static_cast<std::uint8_t>(ch);
    if (ch == '\\') {
      out.append("\\\\");
    } else if (byte >= 0x20U && byte <= 0x7eU) {
      out.push_back(ch);
    } else {
      out.append("\\x");
      out.push_back(kHex[(byte >> 4U) & 0x0fU]);
      out.push_back(kHex[byte & 0x0fU]);
    }
  }
  return out;
}

bool confirm_interactive_yes_no(CliIo io, std::string_view prompt) {
  io.err << prompt << std::flush;
  std::string reply;
  if (!std::getline(io.in, reply))
    return false;
  while (!reply.empty() &&
         (reply.back() == '\r' || reply.back() == ' ' || reply.back() == '\t')) {
    reply.pop_back();
  }
  std::size_t start = 0U;
  while (start < reply.size() && (reply[start] == ' ' || reply[start] == '\t'))
    ++start;
  std::string norm;
  for (std::size_t i = start; i < reply.size(); ++i) {
    norm.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(reply[i]))));
  }
  return norm == "y" || norm == "yes";
}

struct ReadSecretLineOpts {
  std::string_view prompt;
  std::size_t max_bytes = 4096U;
  bool force_stdin = false;
};

bool read_secret_line_bounded(CliIo io, const ReadSecretLineOpts &opts,
                              std::string &out) {
  if (!out.empty()) {
    OPENSSL_cleanse(out.data(), out.size());
    out.clear();
  }
  const bool interactive_tty =
      !opts.force_stdin && (&io.in == &std::cin) && (::isatty(STDIN_FILENO) != 0);
  if (interactive_tty) {
    io.err << opts.prompt << std::flush;
  }
  std::optional<TermiosEchoGuard> echo_guard;
  if (interactive_tty) {
    echo_guard.emplace(STDIN_FILENO);
  }

  auto fail_cleanse = [&]() noexcept -> bool {
    if (!out.empty()) {
      OPENSSL_cleanse(out.data(), out.size());
      out.clear();
    }
    return false;
  };

  // Pre-reserve heap storage directly on `out` so characters never bounce through a
  // local SSO buffer that could leave stack residue after std::move.
  out.reserve(std::min<std::size_t>(opts.max_bytes + 1U, 256U));
  char ch = '\0';
  bool saw_any = false;
  while (io.in.get(ch)) {
    saw_any = true;
    if (ch == '\n')
      break;
    if (out.size() >= opts.max_bytes + 1U) {
      if (interactive_tty)
        io.err << '\n' << std::flush;
      return fail_cleanse();
    }
    out.push_back(ch);
  }
  if (interactive_tty) {
    echo_guard.reset();
    io.err << '\n' << std::flush;
  }
  if (!saw_any && io.in.eof())
    return fail_cleanse();
  while (!out.empty() && out.back() == '\r') {
    out.back() = '\0';
    out.pop_back();
  }
  if (out.size() > opts.max_bytes)
    return fail_cleanse();
  return true;
}

std::optional<std::string> read_mpkey_file_bounded(const fs::path &path,
                                                   std::string_view ctx, CliIo io) {
  int fd = -1;
  do {
    fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ELOOP) {
      (void)fail_message(io, std::string{ctx} + ": refusing symlink .mpkey file");
    } else {
      (void)fail_message(io, std::string{ctx} +
                                 ": unable to open .mpkey file: " + path.string());
    }
    return std::nullopt;
  }
  struct FdCloser {
    int fd = -1;
    ~FdCloser() {
      if (fd >= 0)
        (void)::close(fd);
    }
  } closer{fd};

  struct stat st{};
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    (void)fail_message(io, std::string{ctx} + ": .mpkey path is not a regular file");
    return std::nullopt;
  }

  std::string out;
  std::array<char, 1024> buf{};
  for (;;) {
    const ssize_t n = ::read(fd, buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR)
        continue;
      (void)fail_message(io, std::string{ctx} + ": failed to read .mpkey file");
      return std::nullopt;
    }
    if (n == 0)
      break;
    const auto got = static_cast<std::size_t>(n);
    if (out.size() + got > mp::kMpKeyV1MaxPemBytes) {
      (void)fail_message(io,
                         std::string{ctx} + ": .mpkey file exceeds 4096-byte limit");
      return std::nullopt;
    }
    out.append(buf.data(), got);
  }
  return out;
}

bool write_mpkey_atomic_0600(const fs::path &out_path, std::string_view content,
                             CliIo io, std::string_view ctx) {
  struct stat lst{};
  if (::lstat(out_path.c_str(), &lst) == 0) {
    if (S_ISLNK(lst.st_mode)) {
      (void)fail_message(io, std::string{ctx} + ": refusing to overwrite symlink");
      return false;
    }
    if (S_ISDIR(lst.st_mode)) {
      (void)fail_message(io, std::string{ctx} + ": --out points to a directory");
      return false;
    }
  } else if (errno != ENOENT) {
    (void)fail_message(io, std::string{ctx} + ": unable to stat --out path");
    return false;
  }

  const fs::path parent =
      out_path.parent_path().empty() ? fs::path{"."} : out_path.parent_path();
  const std::string filename = out_path.filename().string();
  if (filename.empty() || filename == "." || filename == "..") {
    (void)fail_usage(io, std::string{ctx} + ": invalid --out filename");
    return false;
  }

  int dir_fd = -1;
  do {
    dir_fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  } while (dir_fd < 0 && errno == EINTR);
  if (dir_fd < 0) {
    (void)fail_message(io, std::string{ctx} +
                               ": parent directory does not exist: " + parent.string());
    return false;
  }
  struct FdCloser {
    int fd = -1;
    ~FdCloser() {
      if (fd >= 0)
        (void)::close(fd);
    }
  } dir_guard{dir_fd};

  static std::atomic<std::uint64_t> tmp_seq{0U};
  const std::uint64_t seq = tmp_seq.fetch_add(1U, std::memory_order_relaxed);
  const std::string tmp_name = "." + filename + ".tmp." + std::to_string(seq) + "." +
                               std::to_string(static_cast<std::uint64_t>(::getpid()));

  int tmp_fd = -1;
  do {
    tmp_fd =
        ::openat(dir_fd, tmp_name.c_str(),
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t{0600});
  } while (tmp_fd < 0 && errno == EINTR);
  if (tmp_fd < 0) {
    (void)fail_message(io,
                       std::string{ctx} + ": unable to create temporary .mpkey file");
    return false;
  }
  FdCloser tmp_guard{tmp_fd};
  auto cleanup_tmp = [&]() noexcept {
    if (tmp_guard.fd >= 0) {
      (void)::close(tmp_guard.fd);
      tmp_guard.fd = -1;
    }
    (void)::unlinkat(dir_fd, tmp_name.c_str(), 0);
  };

  if (::fchmod(tmp_guard.fd, mode_t{0600}) != 0) {
    cleanup_tmp();
    (void)fail_message(io, std::string{ctx} + ": failed to set 0600 permissions");
    return false;
  }

  std::size_t written_total = 0U;
  while (written_total < content.size()) {
    const ssize_t n = ::write(tmp_guard.fd, content.data() + written_total,
                              content.size() - written_total);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      cleanup_tmp();
      (void)fail_message(io, std::string{ctx} + ": failed to write .mpkey file");
      return false;
    }
    if (n == 0) {
      cleanup_tmp();
      (void)fail_message(io, std::string{ctx} + ": short write on .mpkey file");
      return false;
    }
    written_total += static_cast<std::size_t>(n);
  }

  while (::fsync(tmp_guard.fd) != 0) {
    if (errno == EINTR)
      continue;
    cleanup_tmp();
    (void)fail_message(io, std::string{ctx} + ": failed to fsync .mpkey file");
    return false;
  }
  (void)::close(tmp_guard.fd);
  tmp_guard.fd = -1;

  struct stat dst{};
  if (::fstatat(dir_fd, filename.c_str(), &dst, AT_SYMLINK_NOFOLLOW) == 0) {
    if (S_ISLNK(dst.st_mode) || S_ISDIR(dst.st_mode)) {
      cleanup_tmp();
      (void)fail_message(io, std::string{ctx} + ": refusing symlink/directory target");
      return false;
    }
  } else if (errno != ENOENT) {
    cleanup_tmp();
    (void)fail_message(io, std::string{ctx} + ": failed to stat target .mpkey path");
    return false;
  }

  if (::renameat(dir_fd, tmp_name.c_str(), dir_fd, filename.c_str()) != 0) {
    cleanup_tmp();
    (void)fail_message(io, std::string{ctx} + ": failed to atomically rename .mpkey");
    return false;
  }
  while (::fsync(dir_fd) != 0 && errno == EINTR) {
  }
  return true;
}

int fail_mp_error(CliIo io, std::string_view context, Error error) {
  io.err << "blackbird " << context << ": " << error_name(error.code);
  if (error.detail >= 1000 && error.detail < 2000) {
    io.err << " (" << mp::mp_client_error_name(mp::mp_client_error_of(error)) << ')';
  } else if (error.detail >= 100 && error.detail < 1000) {
    io.err << " (" << mp::mp_error_name(mp::mp_error_of(error)) << ')';
  } else if (error.detail != 0) {
    io.err << " (" << error.detail << ')';
  }
  io.err << '\n';
  return 1;
}

bool has_forbidden_online_scalar(std::string_view raw) noexcept {
  if (!valid_utf8(raw))
    return true;
  std::size_t i = 0;
  while (i < raw.size()) {
    const char32_t cp = decode_utf8_scalar_cli(raw, i);
    if (is_forbidden_socket_scalar_cli(cp))
      return true;
  }
  return false;
}

bool valid_online_path_arg(std::string_view raw, bool require_filename) noexcept {
  if (raw.empty() || has_forbidden_online_scalar(raw))
    return false;
  const fs::path candidate{raw};
  for (const auto &comp : candidate) {
    if (comp == "..")
      return false;
  }
  if (require_filename &&
      (candidate.filename().empty() || candidate.filename() == ".")) {
    return false;
  }
  return true;
}

bool valid_online_host_arg(std::string_view raw) noexcept {
  if (raw.empty() || raw.size() > 256U || has_forbidden_online_scalar(raw))
    return false;
  return raw.find_first_of(" \t/@?#\\") == std::string_view::npos;
}

bool valid_online_secret_arg(std::string_view raw) noexcept {
  if (raw.empty() || raw.size() > 256U || has_forbidden_online_scalar(raw))
    return false;
  return raw.find_first_of(" \t") == std::string_view::npos;
}

bool valid_online_label_arg(std::string_view raw) noexcept {
  return raw.size() <= 128U && !has_forbidden_online_scalar(raw);
}

std::string shell_quote_arg(std::string_view raw) {
  if (raw.empty())
    return "''";
  bool safe_unquoted = true;
  for (const char ch : raw) {
    const bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                    (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == ':' ||
                    ch == '@' || ch == '/' || ch == '+' || ch == '=' || ch == '-';
    if (!ok) {
      safe_unquoted = false;
      break;
    }
  }
  if (safe_unquoted)
    return std::string{raw};
  std::string out;
  out.reserve(raw.size() + 2U);
  out.push_back('\'');
  for (const char ch : raw) {
    if (ch == '\'')
      out.append("'\\''");
    else
      out.push_back(ch);
  }
  out.push_back('\'');
  return out;
}

std::string online_base64_encode(std::span<const std::uint8_t> bytes) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((bytes.size() + 2U) / 3U) * 4U);
  std::size_t i = 0U;
  while (i + 3U <= bytes.size()) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                                 (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                                 static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
    out.push_back(kAlphabet[triple & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1U) {
    const std::uint32_t triple = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                                 (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

std::optional<std::uint8_t> online_base64_val(char ch) noexcept {
  if (ch >= 'A' && ch <= 'Z')
    return static_cast<std::uint8_t>(ch - 'A');
  if (ch >= 'a' && ch <= 'z')
    return static_cast<std::uint8_t>(ch - 'a' + 26);
  if (ch >= '0' && ch <= '9')
    return static_cast<std::uint8_t>(ch - '0' + 52);
  if (ch == '+')
    return 62U;
  if (ch == '/')
    return 63U;
  return std::nullopt;
}

std::optional<std::vector<std::uint8_t>>
online_base64_decode(std::string_view text, std::size_t max_decoded_bytes) {
  if (text.empty() || (text.size() % 4U) != 0U)
    return std::nullopt;
  const std::size_t max_out = (text.size() / 4U) * 3U;
  if (max_out > max_decoded_bytes + 2U)
    return std::nullopt;
  std::vector<std::uint8_t> out;
  out.reserve(max_out);
  for (std::size_t i = 0U; i < text.size(); i += 4U) {
    const bool is_last = (i + 4U == text.size());
    const auto v0 = online_base64_val(text[i]);
    const auto v1 = online_base64_val(text[i + 1U]);
    if (!v0.has_value() || !v1.has_value())
      return std::nullopt;
    const char c2 = text[i + 2U];
    const char c3 = text[i + 3U];
    if (c2 == '=' && c3 == '=') {
      if (!is_last || (*v1 & 0x0fU) != 0U)
        return std::nullopt;
      out.push_back(static_cast<std::uint8_t>((*v0 << 2U) | (*v1 >> 4U)));
      continue;
    }
    const auto v2 = online_base64_val(c2);
    if (!v2.has_value())
      return std::nullopt;
    if (c3 == '=') {
      if (!is_last || (*v2 & 0x03U) != 0U)
        return std::nullopt;
      out.push_back(static_cast<std::uint8_t>((*v0 << 2U) | (*v1 >> 4U)));
      out.push_back(static_cast<std::uint8_t>(((*v1 & 0x0fU) << 4U) | (*v2 >> 2U)));
      continue;
    }
    const auto v3 = online_base64_val(c3);
    if (!v3.has_value())
      return std::nullopt;
    out.push_back(static_cast<std::uint8_t>((*v0 << 2U) | (*v1 >> 4U)));
    out.push_back(static_cast<std::uint8_t>(((*v1 & 0x0fU) << 4U) | (*v2 >> 2U)));
    out.push_back(static_cast<std::uint8_t>(((*v2 & 0x03U) << 6U) | *v3));
  }
  if (out.size() > max_decoded_bytes)
    return std::nullopt;
  return out;
}

std::optional<mp::Ed25519PubKey> online_decode_pubkey_b64(std::string_view text) {
  const auto out = online_base64_decode(text, 32U);
  if (!out.has_value() || out->size() != 32U)
    return std::nullopt;
  mp::Ed25519PubKey pk{};
  std::memcpy(pk.data(), out->data(), pk.size());
  return pk;
}

Result<std::string> online_pubkey_sha256_hex(const mp::Ed25519PubKey &pk) {
  const auto digest = mp::sha256(pk);
  if (!digest.has_value())
    return Result<std::string>::failure(digest.error());
  return Result<std::string>::success(mp::hex_lower(digest.value()));
}

Value::Array online_devices_to_json(const std::vector<mp::DeviceInfo> &devices) {
  Value::Array devices_arr;
  devices_arr.reserve(devices.size());
  for (const auto &d : devices) {
    devices_arr.push_back(Value::object({
        {"device_id", Value{Number{d.device_id.value()}}},
        {"pubkey_b64", Value{online_base64_encode(d.pubkey)}},
        {"label", Value{d.label}},
        {"cwt_expires_ms", Value{Number{d.cwt_expires_ms}}},
        {"generation", Value{Number{d.generation}}},
        {"pop_verified", Value{d.pop_verified}},
        {"created_at_ms", Value{Number{d.created_at_ms}}},
        {"revoked_at_ms", d.revoked_at_ms.has_value() ? Value{Number{*d.revoked_at_ms}}
                                                      : Value{nullptr}},
    }));
  }
  return devices_arr;
}

std::int64_t online_unix_seconds() noexcept {
  const auto now = std::chrono::system_clock::now();
  return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
      .count();
}

Result<std::vector<std::uint8_t>>
mint_online_device_cwt(const mp::Ed25519SigningKey &root_key,
                       const mp::Ed25519PubKey &device_pubkey,
                       std::int64_t clock_offset_s = 0) {
  const std::int64_t now_s = online_unix_seconds() + clock_offset_s;
  return mp::encode_device_cwt(root_key, mp::DeviceCwtMintRequest{
                                             .device_pubkey = device_pubkey,
                                             .issued_at_s = now_s,
                                             .expires_at_s = now_s + mp::kMaxCwtTtlSecs,
                                         });
}

constexpr std::string_view friend_edge_state_name(mp::FriendEdgeState state) noexcept {
  switch (state) {
  case mp::FriendEdgeState::friend_edge:
    return "friend";
  case mp::FriendEdgeState::invite_sent:
    return "invite_sent";
  case mp::FriendEdgeState::invite_received:
    return "invite_received";
  case mp::FriendEdgeState::blocked:
    return "blocked";
  }
  return "unknown";
}

constexpr std::string_view party_visibility_name(mp::PartyVisibility v) noexcept {
  switch (v) {
  case mp::PartyVisibility::private_party:
    return "private";
  case mp::PartyVisibility::friends:
    return "friends";
  }
  return "unknown";
}

constexpr std::string_view party_join_mode_name(mp::PartyJoinMode m) noexcept {
  switch (m) {
  case mp::PartyJoinMode::invite_only:
    return "invite";
  case mp::PartyJoinMode::approval_required:
    return "approval";
  }
  return "unknown";
}

constexpr std::string_view relay_policy_name(mp::RelayPolicy p) noexcept {
  switch (p) {
  case mp::RelayPolicy::allow_relays:
    return "allow";
  case mp::RelayPolicy::force_relays:
    return "force";
  case mp::RelayPolicy::no_relays:
    return "no";
  }
  return "unknown";
}

std::optional<mp::PartyVisibility>
parse_online_visibility(std::string_view raw) noexcept {
  if (raw == "private")
    return mp::PartyVisibility::private_party;
  if (raw == "friends")
    return mp::PartyVisibility::friends;
  return std::nullopt;
}

std::optional<mp::PartyJoinMode> parse_online_join_mode(std::string_view raw) noexcept {
  if (raw == "invite")
    return mp::PartyJoinMode::invite_only;
  if (raw == "approval")
    return mp::PartyJoinMode::approval_required;
  return std::nullopt;
}

std::optional<mp::RelayPolicy>
parse_online_relay_policy(std::string_view raw) noexcept {
  if (raw == "allow")
    return mp::RelayPolicy::allow_relays;
  if (raw == "force")
    return mp::RelayPolicy::force_relays;
  if (raw == "no")
    return mp::RelayPolicy::no_relays;
  return std::nullopt;
}

struct OnlineCommonOpts {
  std::optional<fs::path> state_dir;
  std::optional<std::string> authority;
  std::optional<std::string> connect_host;
  std::optional<std::uint16_t> port;
  std::optional<fs::path> ca_bundle;
};

// Returns 1 if flag matched and parsed, 0 if not a common flag, 2 on usage error.
int parse_online_common_flag(std::span<char *> args, std::size_t &index,
                             OnlineCommonOpts &opts, bool allow_state_dir, CliIo io) {
  const std::string_view arg{args[index]};
  if (allow_state_dir && arg == "--state-dir") {
    auto v = take_flag_value(args, index, arg, io);
    if (!v.has_value())
      return 2;
    if (!valid_online_path_arg(*v, /*require_filename=*/false))
      return fail_usage(io, "online: invalid --state-dir path");
    opts.state_dir = strip_trailing_slashes_party(fs::path{*v});
    return 1;
  }
  if (arg == "--authority") {
    auto v = take_flag_value(args, index, arg, io);
    if (!v.has_value())
      return 2;
    if (!valid_online_host_arg(*v))
      return fail_usage(io, "online: invalid --authority");
    opts.authority = std::move(*v);
    return 1;
  }
  if (arg == "--connect-host") {
    auto v = take_flag_value(args, index, arg, io);
    if (!v.has_value())
      return 2;
    if (!valid_online_host_arg(*v))
      return fail_usage(io, "online: invalid --connect-host");
    opts.connect_host = std::move(*v);
    return 1;
  }
  if (arg == "--port") {
    auto v = take_flag_value(args, index, arg, io);
    if (!v.has_value())
      return 2;
    const auto parsed = parse_u64(*v);
    if (!parsed.has_value() || *parsed == 0U || *parsed > 65535U)
      return fail_usage(io, "online: --port must be between 1 and 65535");
    opts.port = static_cast<std::uint16_t>(*parsed);
    return 1;
  }
  if (arg == "--ca-bundle") {
    auto v = take_flag_value(args, index, arg, io);
    if (!v.has_value())
      return 2;
    if (!valid_online_path_arg(*v, /*require_filename=*/true))
      return fail_usage(io, "online: invalid --ca-bundle path");
    opts.ca_bundle = fs::path{*v};
    return 1;
  }
  return 0;
}

std::optional<fs::path> resolve_online_state_dir(const OnlineCommonOpts &opts,
                                                 CliIo io) {
  if (opts.state_dir.has_value())
    return *opts.state_dir;
  if (const char *env_dir = std::getenv("BLACKBIRD_ONLINE_DIR");
      env_dir != nullptr && env_dir[0] != '\0') {
    if (!valid_online_path_arg(env_dir, /*require_filename=*/false)) {
      (void)fail_usage(io, "online: invalid BLACKBIRD_ONLINE_DIR path");
      return std::nullopt;
    }
    return strip_trailing_slashes_party(fs::path{env_dir});
  }
  if (const char *xdg = std::getenv("XDG_CONFIG_HOME");
      xdg != nullptr && xdg[0] != '\0') {
    if (!valid_online_path_arg(xdg, /*require_filename=*/false)) {
      (void)fail_usage(io, "online: invalid XDG_CONFIG_HOME path");
      return std::nullopt;
    }
    return strip_trailing_slashes_party(fs::path{xdg}) / "blackbird" / "online";
  }
  const char *home = std::getenv("HOME");
  if (home == nullptr || home[0] == '\0') {
    (void)fail_usage(io, "online: HOME is unset; pass --state-dir DIR");
    return std::nullopt;
  }
  if (!valid_online_path_arg(home, /*require_filename=*/false)) {
    (void)fail_usage(io, "online: invalid HOME path");
    return std::nullopt;
  }
  return strip_trailing_slashes_party(fs::path{home}) / ".config" / "blackbird" /
         "online";
}

std::optional<mp::MpClientConfig>
resolve_online_client_config(const OnlineCommonOpts &opts,
                             std::string_view fallback_authority, CliIo io) {
  mp::MpClientConfig cfg{};
  if (opts.authority.has_value()) {
    cfg.authority = *opts.authority;
  } else if (const char *env_auth = std::getenv("BLACKBIRD_ONLINE_AUTHORITY");
             env_auth != nullptr && env_auth[0] != '\0') {
    if (!valid_online_host_arg(env_auth)) {
      (void)fail_usage(io, "online: invalid BLACKBIRD_ONLINE_AUTHORITY");
      return std::nullopt;
    }
    cfg.authority = env_auth;
  } else if (!fallback_authority.empty()) {
    if (!valid_online_host_arg(fallback_authority)) {
      (void)fail_usage(io, "online: invalid stored authority");
      return std::nullopt;
    }
    cfg.authority = std::string{fallback_authority};
  } else {
    cfg.authority = std::string{mp::kDefaultMpAuthority};
  }

  if (opts.connect_host.has_value()) {
    cfg.connect_host = *opts.connect_host;
  } else if (const char *env_ch = std::getenv("BLACKBIRD_ONLINE_CONNECT_HOST");
             env_ch != nullptr && env_ch[0] != '\0') {
    if (!valid_online_host_arg(env_ch)) {
      (void)fail_usage(io, "online: invalid BLACKBIRD_ONLINE_CONNECT_HOST");
      return std::nullopt;
    }
    cfg.connect_host = env_ch;
  }

  if (opts.port.has_value()) {
    cfg.port = *opts.port;
  } else if (const char *env_port = std::getenv("BLACKBIRD_ONLINE_PORT");
             env_port != nullptr && env_port[0] != '\0') {
    const auto parsed = parse_u64(env_port);
    if (!parsed.has_value() || *parsed == 0U || *parsed > 65535U) {
      (void)fail_usage(io, "online: invalid BLACKBIRD_ONLINE_PORT");
      return std::nullopt;
    }
    cfg.port = static_cast<std::uint16_t>(*parsed);
  } else {
    cfg.port = mp::kDefaultMpPort;
  }

  if (opts.ca_bundle.has_value()) {
    cfg.ca_bundle_path = *opts.ca_bundle;
  } else if (const char *env_ca = std::getenv("BLACKBIRD_ONLINE_CA_BUNDLE");
             env_ca != nullptr && env_ca[0] != '\0') {
    if (!valid_online_path_arg(env_ca, /*require_filename=*/true)) {
      (void)fail_usage(io, "online: invalid BLACKBIRD_ONLINE_CA_BUNDLE path");
      return std::nullopt;
    }
    cfg.ca_bundle_path = fs::path{env_ca};
  }
  return cfg;
}

struct OpenedOnlineContext {
  mp::MpIdentityStore store;
  mp::MpControlClient client;
};

struct OpenOnlineOutcome {
  std::optional<OpenedOnlineContext> ctx;
  int exit_code = 0;
};

OpenOnlineOutcome open_online_context(const OnlineCommonOpts &opts,
                                      std::string_view context_name, CliIo io) {
  const auto state_dir = resolve_online_state_dir(opts, io);
  if (!state_dir.has_value())
    return {std::nullopt, 2};
  auto store = mp::MpIdentityStore::open_existing(*state_dir);
  if (!store.has_value())
    return {std::nullopt, fail_mp_error(io, context_name, store.error())};
  const auto cfg =
      resolve_online_client_config(opts, store.value().state().authority, io);
  if (!cfg.has_value())
    return {std::nullopt, 2};
  mp::MpIdentityState identity = store.value().state();
  return {OpenedOnlineContext{std::move(store).value(),
                              mp::MpControlClient{*cfg, std::move(identity)}},
          0};
}

struct BuiltOnlineEndpoint {
  mp::EndpointDescriptor endpoint;
  std::string relay_url;
};

std::optional<BuiltOnlineEndpoint>
build_online_endpoint(mp::RelayPolicy policy,
                      const std::optional<std::string> &explicit_relay_url,
                      std::string_view context_name, CliIo io) {
  BuiltOnlineEndpoint out{};
  if (policy == mp::RelayPolicy::no_relays) {
    if (explicit_relay_url.has_value() && !explicit_relay_url->empty()) {
      (void)fail_usage(io, std::string{context_name} +
                               ": --relay no cannot be combined with --relay-url");
      return std::nullopt;
    }
    out.endpoint.transport_kind = mp::TransportKind::direct_quic;
    out.endpoint.relay_url.clear();
    out.relay_url.clear();
  } else {
    out.relay_url = explicit_relay_url.has_value()
                        ? *explicit_relay_url
                        : std::string{kDefaultOnlineRelayUrl};
    if (policy == mp::RelayPolicy::force_relays && out.relay_url.empty()) {
      (void)fail_usage(io, std::string{context_name} +
                               ": --relay force requires a non-empty --relay-url");
      return std::nullopt;
    }
    out.endpoint.transport_kind = mp::TransportKind::iroh_quic;
    out.endpoint.relay_url = out.relay_url;
  }

  if (const auto ok = out.endpoint.validate_against_policy(policy, out.relay_url);
      !ok.has_value()) {
    (void)fail_usage(io, std::string{context_name} + ": invalid --relay-url");
    return std::nullopt;
  }
  return out;
}

bool is_all_ascii_digits(std::string_view text) noexcept {
  if (text.empty())
    return false;
  return std::ranges::all_of(text,
                             [](char ch) noexcept { return ch >= '0' && ch <= '9'; });
}

struct ParsedPartyJoinTarget {
  mp::PartyId party_id;
  std::optional<std::string> invite_link;
};

std::optional<ParsedPartyJoinTarget> parse_party_join_target(std::string_view raw) {
  constexpr std::string_view kPrefix = "mppi1_";
  if (raw.starts_with(kPrefix)) {
    const std::string_view rest = raw.substr(kPrefix.size());
    const std::size_t sep = rest.find('_');
    if (sep == std::string_view::npos || sep == 0U || sep + 1U >= rest.size())
      return std::nullopt;
    const std::string_view pid_text = rest.substr(0U, sep);
    const std::string_view secret = rest.substr(sep + 1U);
    if (!valid_online_secret_arg(secret))
      return std::nullopt;
    const auto pid = mp::PartyId::parse_decimal(pid_text);
    if (!pid.has_value())
      return std::nullopt;
    return ParsedPartyJoinTarget{pid.value(), std::string{raw}};
  }
  const auto pid = mp::PartyId::parse_decimal(raw);
  if (!pid.has_value())
    return std::nullopt;
  return ParsedPartyJoinTarget{pid.value(), std::nullopt};
}

int run_online_health(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online health [--authority HOST] "
                "[--connect-host HOST] [--port N] [--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, false, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    return fail_usage(io, "online health: unknown option: " + std::string{arg});
  }

  const auto cfg = resolve_online_client_config(opts, {}, io);
  if (!cfg.has_value())
    return 2;
  mp::MpControlClient client{*cfg};
  const auto res = client.health();
  if (!res.has_value())
    return fail_mp_error(io, "online health", res.error());

  return emit_json(io, Value::object({
                           {"ok", Value{res.value().ok}},
                           {"authority", Value{cfg->authority}},
                           {"server_now_ms", Value{Number{res.value().server_now_ms}}},
                       }));
}

int preflight_online_register_dir(const fs::path &state_dir,
                                  std::string_view context_name, CliIo io) {
  struct stat lst{};
  if (::lstat(state_dir.c_str(), &lst) != 0) {
    if (errno == ENOENT)
      return 0;
    return fail_mp_error(io, context_name,
                         {ErrorCode::io, static_cast<std::int64_t>(
                                             mp::MpClientError::keystore_io_failed)});
  }
  if (S_ISLNK(lst.st_mode)) {
    return fail_mp_error(
        io, context_name,
        {ErrorCode::io,
         static_cast<std::int64_t>(mp::MpClientError::keystore_symlink_rejected)});
  }
  if (!S_ISDIR(lst.st_mode)) {
    return fail_mp_error(
        io, context_name,
        {ErrorCode::io,
         static_cast<std::int64_t>(mp::MpClientError::keystore_invalid_path)});
  }
  int fd = -1;
  do {
    fd = ::open(state_dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    const auto detail = (errno == ELOOP || errno == ENOTDIR)
                            ? mp::MpClientError::keystore_symlink_rejected
                            : mp::MpClientError::keystore_io_failed;
    return fail_mp_error(io, context_name,
                         {ErrorCode::io, static_cast<std::int64_t>(detail)});
  }
  struct FdGuard {
    int dir_fd = -1;
    ~FdGuard() {
      if (dir_fd >= 0)
        (void)::close(dir_fd);
    }
  } fd_guard{fd};

  struct stat dst{};
  if (::fstat(fd, &dst) != 0) {
    return fail_mp_error(io, context_name,
                         {ErrorCode::io, static_cast<std::int64_t>(
                                             mp::MpClientError::keystore_io_failed)});
  }
  if (!S_ISDIR(dst.st_mode)) {
    return fail_mp_error(
        io, context_name,
        {ErrorCode::io,
         static_cast<std::int64_t>(mp::MpClientError::keystore_invalid_path)});
  }
  if (dst.st_uid != ::geteuid() || (dst.st_mode & 0077U) != 0U) {
    return fail_mp_error(
        io, context_name,
        {ErrorCode::io,
         static_cast<std::int64_t>(mp::MpClientError::keystore_insecure_permissions)});
  }
  for (const char *fname :
       {"root.seed", "device.seed", "device.cwt", "identity.json"}) {
    struct stat fst{};
    if (::fstatat(fd, fname, &fst, AT_SYMLINK_NOFOLLOW) == 0) {
      return fail_message(io, std::string{context_name} +
                                  ": keystore already exists in --state-dir; refusing "
                                  "to overwrite existing identity");
    }
    if (errno != ENOENT) {
      return fail_mp_error(io, context_name,
                           {ErrorCode::io, static_cast<std::int64_t>(
                                               mp::MpClientError::keystore_io_failed)});
    }
  }
  return 0;
}

int run_online_register(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::string invite_secret;
  OnlineCleanseStringGuard invite_guard{invite_secret};
  std::string handle;
  std::string device_label{kDefaultOnlineDeviceLabel};

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online register --invite <mpinv1_...> "
                "--handle <name> [--device-label <lbl>] [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--invite") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_secret_arg(*v)) {
        OPENSSL_cleanse(v->data(), v->size());
        return fail_usage(io, "online register: invalid --invite secret");
      }
      if (!invite_secret.empty())
        OPENSSL_cleanse(invite_secret.data(), invite_secret.size());
      invite_secret = std::move(*v);
    } else if (arg == "--handle") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      handle = std::move(*v);
    } else if (arg == "--device-label") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_label_arg(*v))
        return fail_usage(io, "online register: invalid --device-label");
      device_label = std::move(*v);
    } else {
      return fail_usage(io, "online register: unknown option: " + std::string{arg});
    }
  }

  if (invite_secret.empty())
    return fail_usage(io, "online register: --invite is required");
  if (handle.empty())
    return fail_usage(io, "online register: --handle is required");
  if (const auto parsed_handle = mp::AccountHandle::parse(handle);
      !parsed_handle.has_value()) {
    return fail_usage(io, "online register: invalid --handle");
  }

  const auto state_dir = resolve_online_state_dir(opts, io);
  if (!state_dir.has_value())
    return 2;
  const auto cfg = resolve_online_client_config(opts, {}, io);
  if (!cfg.has_value())
    return 2;

  // Preflight state_dir before generating keys or redeeming the single-use invite:
  // reject symlinks, non-directories, insecure modes, or an existing keystore.
  if (const int preflight_rc =
          preflight_online_register_dir(*state_dir, "online register", io);
      preflight_rc != 0) {
    return preflight_rc;
  }

  auto root_seed = mp::CleansedSeed::generate();
  if (!root_seed.has_value())
    return fail_mp_error(io, "online register", root_seed.error());
  auto device_seed = mp::CleansedSeed::generate();
  if (!device_seed.has_value())
    return fail_mp_error(io, "online register", device_seed.error());

  auto root_key = mp::Ed25519SigningKey::from_seed(root_seed.value().bytes());
  if (!root_key.has_value())
    return fail_mp_error(io, "online register", root_key.error());
  auto device_key = mp::Ed25519SigningKey::from_seed(device_seed.value().bytes());
  if (!device_key.has_value())
    return fail_mp_error(io, "online register", device_key.error());

  auto cwt = mint_online_device_cwt(root_key.value(), device_key.value().public_key());
  if (!cwt.has_value())
    return fail_mp_error(io, "online register", cwt.error());

  mp::RegisterAccountRequest req{};
  req.invite_secret = invite_secret;
  OnlineCleanseStringGuard req_invite_guard{req.invite_secret};
  req.handle = handle;
  req.device_pubkey = device_key.value().public_key();
  req.device_label = device_label;
  req.device_cwt = cwt.value();

  mp::MpControlClient client{*cfg};
  const auto reg = client.register_account(root_key.value(), req);
  if (!reg.has_value())
    return fail_mp_error(io, "online register", reg.error());

  mp::MpIdentityState identity{};
  identity.root_seed = std::move(root_seed).value();
  identity.device_seed = std::move(device_seed).value();
  identity.account_id = reg.value().account_id;
  identity.device_id = reg.value().device_id;
  identity.handle = reg.value().handle;
  identity.authority = cfg->authority;
  identity.device_cwt = std::move(cwt).value();

  auto saved = mp::MpIdentityStore::save(*state_dir, identity);
  if (!saved.has_value())
    return fail_mp_error(io, "online register", saved.error());

  // Per Identity Portability Spec §2 (mandatory UX rule): display the canonical
  // mprk1_... Recovery Key prominently on stderr and cleanse immediately after write.
  if (identity.root_seed.has_value()) {
    auto rec_key = mp::encode_recovery_key(identity.root_seed->bytes());
    if (!rec_key.has_value())
      return fail_mp_error(io, "online register", rec_key.error());
    OnlineCleanseStringGuard rec_key_guard{rec_key.value()};
    io.err
        << "\nIMPORTANT — SAVE YOUR RECOVERY KEY NOW (store in a password manager or "
           "offline backup):\n  "
        << rec_key.value()
        << "\nNever share this key or pass it on a command line. You can also export "
           "an "
           "encrypted backup:\n  blackbird online export-mpkey --out recovery.mpkey\n\n"
        << std::flush;
  }

  const auto root_sha = online_pubkey_sha256_hex(root_key.value().public_key());
  if (!root_sha.has_value())
    return fail_mp_error(io, "online register", root_sha.error());
  const auto safety_num =
      mp::compute_safety_number(reg.value().account_id, root_key.value().public_key());
  if (!safety_num.has_value())
    return fail_mp_error(io, "online register", safety_num.error());

  return emit_json(io,
                   Value::object({
                       {"registered", Value{true}},
                       {"account_id", Value{Number{reg.value().account_id.value()}}},
                       {"device_id", Value{Number{reg.value().device_id.value()}}},
                       {"handle", Value{reg.value().handle}},
                       {"authority", Value{cfg->authority}},
                       {"root_pubkey_sha256", Value{root_sha.value()}},
                       {"safety_number", Value{safety_num.value()}},
                   }));
}

int run_online_whoami(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  bool local_only = false;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online whoami [--local] [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--local") {
      local_only = true;
    } else {
      return fail_usage(io, "online whoami: unknown option: " + std::string{arg});
    }
  }

  if (local_only) {
    const auto state_dir = resolve_online_state_dir(opts, io);
    if (!state_dir.has_value())
      return 2;
    auto store = mp::MpIdentityStore::open_existing(*state_dir);
    if (!store.has_value())
      return fail_mp_error(io, "online whoami", store.error());
    const mp::MpIdentityState &st = store.value().state();

    auto dev_key = store.value().device_signing_key();
    if (!dev_key.has_value())
      return fail_mp_error(io, "online whoami", dev_key.error());
    const auto dev_sha = online_pubkey_sha256_hex(dev_key.value().public_key());
    if (!dev_sha.has_value())
      return fail_mp_error(io, "online whoami", dev_sha.error());

    Value root_b64{nullptr};
    Value root_sha_val{nullptr};
    Value safety_num_val{nullptr};
    bool has_root = false;
    if (st.root_seed.has_value()) {
      auto root_key = store.value().root_signing_key();
      if (!root_key.has_value())
        return fail_mp_error(io, "online whoami", root_key.error());
      const auto rsha = online_pubkey_sha256_hex(root_key.value().public_key());
      if (!rsha.has_value())
        return fail_mp_error(io, "online whoami", rsha.error());
      has_root = true;
      root_b64 = Value{online_base64_encode(root_key.value().public_key())};
      root_sha_val = Value{rsha.value()};
      if (st.account_id.has_value()) {
        if (const auto sn = mp::compute_safety_number(*st.account_id,
                                                      root_key.value().public_key());
            sn.has_value()) {
          safety_num_val = Value{sn.value()};
        }
      }
    }

    const bool registered = st.account_id.has_value() && st.device_id.has_value();
    return emit_json(
        io, Value::object({
                {"local", Value{true}},
                {"registered", Value{registered}},
                {"account_id", st.account_id.has_value()
                                   ? Value{Number{st.account_id->value()}}
                                   : Value{nullptr}},
                {"device_id", st.device_id.has_value()
                                  ? Value{Number{st.device_id->value()}}
                                  : Value{nullptr}},
                {"handle", Value{st.handle}},
                {"authority", Value{st.authority}},
                {"has_root_key", Value{has_root}},
                {"root_pubkey_b64", std::move(root_b64)},
                {"root_pubkey_sha256", std::move(root_sha_val)},
                {"safety_number", std::move(safety_num_val)},
                {"device_pubkey_b64",
                 Value{online_base64_encode(dev_key.value().public_key())}},
                {"device_pubkey_sha256", Value{dev_sha.value()}},
                {"device_cwt_bytes",
                 Value{Number{static_cast<std::uint64_t>(st.device_cwt.size())}}},
            }));
  }

  auto opened = open_online_context(opts, "online whoami", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  const auto me = opened.ctx->client.whoami();
  if (!me.has_value())
    return fail_mp_error(io, "online whoami", me.error());

  const auto root_sha = online_pubkey_sha256_hex(me.value().root_pubkey);
  if (!root_sha.has_value())
    return fail_mp_error(io, "online whoami", root_sha.error());
  const auto safety_num =
      mp::compute_safety_number(me.value().account_id, me.value().root_pubkey);
  if (!safety_num.has_value())
    return fail_mp_error(io, "online whoami", safety_num.error());

  Value::Array devices_arr;
  devices_arr.reserve(me.value().devices.size());
  for (const auto &d : me.value().devices) {
    devices_arr.push_back(Value::object({
        {"device_id", Value{Number{d.device_id.value()}}},
        {"pubkey_b64", Value{online_base64_encode(d.pubkey)}},
        {"label", Value{d.label}},
        {"cwt_expires_ms", Value{Number{d.cwt_expires_ms}}},
        {"generation", Value{Number{d.generation}}},
        {"pop_verified", Value{d.pop_verified}},
        {"created_at_ms", Value{Number{d.created_at_ms}}},
        {"revoked_at_ms", d.revoked_at_ms.has_value() ? Value{Number{*d.revoked_at_ms}}
                                                      : Value{nullptr}},
    }));
  }

  Value::Array parties_arr;
  parties_arr.reserve(me.value().active_party_ids.size());
  for (const auto &pid : me.value().active_party_ids)
    parties_arr.emplace_back(Number{pid.value()});

  return emit_json(
      io, Value::object({
              {"account_id", Value{Number{me.value().account_id.value()}}},
              {"handle", Value{me.value().handle}},
              {"authority", Value{opened.ctx->client.config().authority}},
              {"root_pubkey_b64", Value{online_base64_encode(me.value().root_pubkey)}},
              {"root_pubkey_sha256", Value{root_sha.value()}},
              {"safety_number", Value{safety_num.value()}},
              {"devices", Value{std::move(devices_arr)}},
              {"active_party_ids", Value{std::move(parties_arr)}},
          }));
}

int run_online_resolve(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> handle;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online resolve <handle> [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg.starts_with('-'))
      return fail_usage(io, "online resolve: unknown option: " + std::string{arg});
    if (handle.has_value())
      return fail_usage(io, "online resolve: unexpected extra argument");
    handle = std::string{arg};
  }

  if (!handle.has_value())
    return fail_usage(io, "online resolve: <handle> is required");
  if (const auto parsed = mp::AccountHandle::parse(*handle); !parsed.has_value())
    return fail_usage(io, "online resolve: invalid handle");

  auto opened = open_online_context(opts, "online resolve", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  const auto resolved = opened.ctx->client.resolve_handle(*handle);
  if (!resolved.has_value())
    return fail_mp_error(io, "online resolve", resolved.error());

  const auto root_sha = online_pubkey_sha256_hex(resolved.value().root_pubkey);
  if (!root_sha.has_value())
    return fail_mp_error(io, "online resolve", root_sha.error());
  const auto safety_num = mp::compute_safety_number(resolved.value().account_id,
                                                    resolved.value().root_pubkey);
  if (!safety_num.has_value())
    return fail_mp_error(io, "online resolve", safety_num.error());

  return emit_json(
      io, Value::object({
              {"account_id", Value{Number{resolved.value().account_id.value()}}},
              {"handle", Value{resolved.value().handle}},
              {"root_pubkey_b64",
               Value{online_base64_encode(resolved.value().root_pubkey)}},
              {"root_pubkey_sha256", Value{root_sha.value()}},
              {"safety_number", Value{safety_num.value()}},
          }));
}

int run_online_devices_init(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::string label{kDefaultOnlineDeviceLabel};

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online devices init [--label <lbl>] "
                "[--state-dir DIR] [--authority HOST]\n";
      return 0;
    }
    if (arg == "--state-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_path_arg(*v, /*require_filename=*/false))
        return fail_usage(io, "online devices init: invalid --state-dir path");
      opts.state_dir = strip_trailing_slashes_party(fs::path{*v});
    } else if (arg == "--authority") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_host_arg(*v))
        return fail_usage(io, "online devices init: invalid --authority");
      opts.authority = std::move(*v);
    } else if (arg == "--label") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_label_arg(*v) || v->empty())
        return fail_usage(io, "online devices init: invalid --label");
      label = std::move(*v);
    } else {
      return fail_usage(io, "online devices init: unknown option: " + std::string{arg});
    }
  }

  const auto state_dir = resolve_online_state_dir(opts, io);
  if (!state_dir.has_value())
    return 2;
  const auto cfg = resolve_online_client_config(opts, {}, io);
  if (!cfg.has_value())
    return 2;

  if (const int preflight_rc =
          preflight_online_register_dir(*state_dir, "online devices init", io);
      preflight_rc != 0) {
    return preflight_rc;
  }

  auto device_seed = mp::CleansedSeed::generate();
  if (!device_seed.has_value())
    return fail_mp_error(io, "online devices init", device_seed.error());
  auto device_key = mp::Ed25519SigningKey::from_seed(device_seed.value().bytes());
  if (!device_key.has_value())
    return fail_mp_error(io, "online devices init", device_key.error());

  mp::MpIdentityState identity{};
  identity.root_seed = std::nullopt;
  identity.device_seed = std::move(device_seed).value();
  identity.account_id = std::nullopt;
  identity.device_id = std::nullopt;
  identity.handle.clear();
  identity.authority = cfg->authority;
  identity.device_cwt.clear();

  auto saved = mp::MpIdentityStore::save(*state_dir, identity);
  if (!saved.has_value())
    return fail_mp_error(io, "online devices init", saved.error());

  const std::string dev_pub_b64 = online_base64_encode(device_key.value().public_key());
  const auto dev_sha = online_pubkey_sha256_hex(device_key.value().public_key());
  if (!dev_sha.has_value())
    return fail_mp_error(io, "online devices init", dev_sha.error());

  const std::string next_step =
      "On your root machine run: blackbird online devices enroll --label " +
      shell_quote_arg(label) + " --pubkey-b64 " + dev_pub_b64;

  return emit_json(io, Value::object({
                           {"initialized", Value{true}},
                           {"state_dir", Value{saved.value().directory().string()}},
                           {"authority", Value{cfg->authority}},
                           {"device_pubkey_b64", Value{dev_pub_b64}},
                           {"device_pubkey_sha256", Value{dev_sha.value()}},
                           {"next_step", Value{next_step}},
                       }));
}

int run_online_devices_install_cwt(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> account_id_arg;
  std::optional<std::string> device_id_arg;
  std::optional<std::string> handle_arg;
  std::optional<std::string> cwt_b64_arg;
  std::optional<std::string> root_pubkey_b64_arg;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online devices install-cwt --account-id <id> "
                "--device-id <id> --handle <handle> --cwt-b64 <b64> "
                "[--root-pubkey-b64 <b64>] [--authority HOST] [--state-dir DIR]\n";
      return 0;
    }
    if (arg == "--state-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_path_arg(*v, /*require_filename=*/false))
        return fail_usage(io, "online devices install-cwt: invalid --state-dir path");
      opts.state_dir = strip_trailing_slashes_party(fs::path{*v});
    } else if (arg == "--authority") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_host_arg(*v))
        return fail_usage(io, "online devices install-cwt: invalid --authority");
      opts.authority = std::move(*v);
    } else if (arg == "--account-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      account_id_arg = std::move(*v);
    } else if (arg == "--device-id") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      device_id_arg = std::move(*v);
    } else if (arg == "--handle") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      handle_arg = std::move(*v);
    } else if (arg == "--cwt-b64") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cwt_b64_arg = std::move(*v);
    } else if (arg == "--root-pubkey-b64") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      root_pubkey_b64_arg = std::move(*v);
    } else {
      return fail_usage(io, "online devices install-cwt: unknown option: " +
                                std::string{arg});
    }
  }

  if (!account_id_arg.has_value() || account_id_arg->empty())
    return fail_usage(io, "online devices install-cwt: --account-id is required");
  if (!device_id_arg.has_value() || device_id_arg->empty())
    return fail_usage(io, "online devices install-cwt: --device-id is required");
  if (!handle_arg.has_value() || handle_arg->empty())
    return fail_usage(io, "online devices install-cwt: --handle is required");
  if (!cwt_b64_arg.has_value() || cwt_b64_arg->empty())
    return fail_usage(io, "online devices install-cwt: --cwt-b64 is required");

  const auto account_id = mp::AccountId::parse_decimal(*account_id_arg);
  if (!account_id.has_value())
    return fail_usage(io, "online devices install-cwt: invalid --account-id");
  const auto device_id = mp::DeviceId::parse_decimal(*device_id_arg);
  if (!device_id.has_value())
    return fail_usage(io, "online devices install-cwt: invalid --device-id");
  const auto parsed_handle = mp::AccountHandle::parse(*handle_arg);
  if (!parsed_handle.has_value())
    return fail_usage(io, "online devices install-cwt: invalid --handle");

  const auto decoded_cwt = online_base64_decode(*cwt_b64_arg, mp::kMaxCwtBytes);
  if (!decoded_cwt.has_value() || decoded_cwt->empty())
    return fail_usage(io, "online devices install-cwt: invalid --cwt-b64");

  std::optional<mp::Ed25519PubKey> expected_root_pk;
  if (root_pubkey_b64_arg.has_value()) {
    const auto decoded_root = online_decode_pubkey_b64(*root_pubkey_b64_arg);
    if (!decoded_root.has_value() ||
        !mp::validate_ed25519_pubkey_strict(*decoded_root).has_value()) {
      return fail_usage(
          io, "online devices install-cwt: invalid --root-pubkey-b64 Ed25519 key");
    }
    expected_root_pk = *decoded_root;
  }

  const auto state_dir = resolve_online_state_dir(opts, io);
  if (!state_dir.has_value())
    return 2;

  auto store = mp::MpIdentityStore::open_existing(*state_dir);
  if (!store.has_value())
    return fail_mp_error(io, "online devices install-cwt", store.error());

  const auto installed = store.value().install_cwt(mp::InstallDeviceCwtRequest{
      .account_id = account_id.value(),
      .device_id = device_id.value(),
      .handle = std::string{parsed_handle.value().display()},
      .device_cwt = *decoded_cwt,
      .authority = opts.authority,
      .expected_root_pubkey = expected_root_pk,
      .now_s = std::nullopt,
  });
  if (!installed.has_value())
    return fail_mp_error(io, "online devices install-cwt", installed.error());

  const auto dev_key = store.value().device_signing_key();
  if (!dev_key.has_value())
    return fail_mp_error(io, "online devices install-cwt", dev_key.error());
  const auto dev_sha = online_pubkey_sha256_hex(dev_key.value().public_key());
  if (!dev_sha.has_value())
    return fail_mp_error(io, "online devices install-cwt", dev_sha.error());

  const mp::MpIdentityState &st = store.value().state();
  return emit_json(
      io, Value::object({
              {"installed", Value{true}},
              {"account_id", Value{Number{account_id.value().value()}}},
              {"device_id", Value{Number{device_id.value().value()}}},
              {"handle", Value{st.handle}},
              {"authority", Value{st.authority}},
              {"device_pubkey_sha256", Value{dev_sha.value()}},
              {"device_cwt_bytes",
               Value{Number{static_cast<std::uint64_t>(st.device_cwt.size())}}},
          }));
}

int run_online_devices_enroll(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> label;
  std::optional<std::string> pubkey_b64;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online devices enroll --label <lbl> "
                "--pubkey-b64 <b64> [--state-dir DIR] [--authority HOST] "
                "[--connect-host HOST] [--port N] [--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--label") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_label_arg(*v))
        return fail_usage(io, "online devices enroll: invalid --label");
      label = std::move(*v);
    } else if (arg == "--pubkey-b64") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      pubkey_b64 = std::move(*v);
    } else {
      return fail_usage(io,
                        "online devices enroll: unknown option: " + std::string{arg});
    }
  }

  if (!label.has_value() || label->empty())
    return fail_usage(io, "online devices enroll: --label is required");
  if (!pubkey_b64.has_value() || pubkey_b64->empty())
    return fail_usage(io, "online devices enroll: --pubkey-b64 is required");

  const auto decoded_pk = online_decode_pubkey_b64(*pubkey_b64);
  if (!decoded_pk.has_value() ||
      !mp::validate_ed25519_pubkey_strict(*decoded_pk).has_value()) {
    return fail_usage(io, "online devices enroll: invalid --pubkey-b64 Ed25519 key");
  }

  auto opened = open_online_context(opts, "online devices enroll", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  auto root_key = opened.ctx->store.root_signing_key();
  if (!root_key.has_value())
    return fail_mp_error(io, "online devices enroll", root_key.error());

  auto cwt = mint_online_device_cwt(root_key.value(), *decoded_pk);
  if (!cwt.has_value())
    return fail_mp_error(io, "online devices enroll", cwt.error());
  const std::string device_cwt_b64 = online_base64_encode(cwt.value());

  const auto enrolled = opened.ctx->client.enroll_device(mp::EnrollDeviceRequest{
      .device_pubkey = *decoded_pk,
      .device_label = *label,
      .device_cwt = std::move(cwt).value(),
  });
  if (!enrolled.has_value())
    return fail_mp_error(io, "online devices enroll", enrolled.error());

  const mp::MpIdentityState &st = opened.ctx->store.state();
  if (!st.account_id.has_value()) {
    return fail_mp_error(
        io, "online devices enroll",
        {ErrorCode::provider_auth,
         static_cast<std::int64_t>(mp::MpClientError::missing_account_identity)});
  }
  const std::string root_pubkey_b64 =
      online_base64_encode(root_key.value().public_key());
  const std::string &authority = opened.ctx->client.config().authority;
  std::string install_cmd = "blackbird online devices install-cwt --account-id " +
                            st.account_id->to_decimal() + " --device-id " +
                            enrolled.value().device_id.to_decimal() + " --handle " +
                            shell_quote_arg(st.handle) + " --cwt-b64 " +
                            device_cwt_b64 + " --root-pubkey-b64 " + root_pubkey_b64;
  if (authority != mp::kDefaultMpAuthority) {
    install_cmd += " --authority " + shell_quote_arg(authority);
  }

  return emit_json(
      io, Value::object({
              {"enrolled", Value{true}},
              {"account_id", Value{Number{st.account_id->value()}}},
              {"device_id", Value{Number{enrolled.value().device_id.value()}}},
              {"handle", Value{st.handle}},
              {"authority", Value{authority}},
              {"label", Value{*label}},
              {"pubkey_b64", Value{online_base64_encode(*decoded_pk)}},
              {"root_pubkey_b64", Value{root_pubkey_b64}},
              {"device_cwt_b64", Value{device_cwt_b64}},
              {"cwt_expires_ms", Value{Number{enrolled.value().cwt_expires_ms}}},
              {"install_cwt_command", Value{install_cmd}},
          }));
}

int run_online_devices_revoke(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> device_id_arg;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online devices revoke <device_id> [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg.starts_with('-')) {
      return fail_usage(io,
                        "online devices revoke: unknown option: " + std::string{arg});
    }
    if (device_id_arg.has_value())
      return fail_usage(io, "online devices revoke: unexpected extra argument");
    device_id_arg = std::string{arg};
  }

  if (!device_id_arg.has_value())
    return fail_usage(io, "online devices revoke: <device_id> is required");
  const auto dev_id = mp::DeviceId::parse_decimal(*device_id_arg);
  if (!dev_id.has_value())
    return fail_usage(io, "online devices revoke: invalid <device_id>");

  auto opened = open_online_context(opts, "online devices revoke", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  const auto res = opened.ctx->client.revoke_device(dev_id.value());
  if (!res.has_value())
    return fail_mp_error(io, "online devices revoke", res.error());

  Value::Array evicted;
  evicted.reserve(res.value().evicted_parties.size());
  for (const auto &pid : res.value().evicted_parties)
    evicted.emplace_back(Number{pid.value()});

  return emit_json(io,
                   Value::object({
                       {"device_id", Value{Number{dev_id.value().value()}}},
                       {"revoked", Value{res.value().revoked}},
                       {"evicted_parties", Value{std::move(evicted)}},
                       {"pending_retries", Value{Number{res.value().pending_retries}}},
                   }));
}

struct DeviceLinkApproveOutcome {
  int exit_code = 0;
  std::optional<Value> json;
};

DeviceLinkApproveOutcome approve_inspected_device_link(
    OpenedOnlineContext &ctx, const mp::Ed25519SigningKey &root_key,
    std::string_view link_code, const mp::InspectDeviceLinkResponse &inspected,
    const std::optional<std::string> &label_override, bool auto_yes, CliIo io,
    std::string_view cmd_ctx) {
  if (!inspected.device_pubkey.has_value() ||
      !inspected.local_device_fingerprint.has_value()) {
    return {fail_message(io, std::string{cmd_ctx} +
                                 ": server omitted claimed device pubkey"),
            std::nullopt};
  }
  std::string effective_label;
  if (label_override.has_value()) {
    effective_label = *label_override;
  } else if (inspected.device_label.has_value() && !inspected.device_label->empty()) {
    effective_label = *inspected.device_label;
  } else {
    effective_label = std::string{kDefaultOnlineDeviceLabel};
  }
  if (!mp::valid_device_label(effective_label)) {
    return {fail_usage(io, std::string{cmd_ctx} + ": invalid device label"),
            std::nullopt};
  }

  const std::string escaped_label = escape_terminal_display(effective_label);
  const std::string escaped_country =
      inspected.requester_country.has_value() && !inspected.requester_country->empty()
          ? escape_terminal_display(*inspected.requester_country)
          : std::string{"unknown"};

  io.err << "Device link claim received:\n"
         << "  Label:       " << escaped_label << "\n"
         << "  Country:     " << escaped_country << "\n"
         << "  Fingerprint: " << *inspected.local_device_fingerprint << "\n"
         << std::flush;

  if (!auto_yes) {
    if (!confirm_interactive_yes_no(
            io, "Verify the fingerprint matches the new machine. Approve this device? "
                "[y/N]: ")) {
      return {fail_message(io, std::string{cmd_ctx} + ": approval declined"),
              std::nullopt};
    }
  }

  auto cwt = mint_online_device_cwt(root_key, *inspected.device_pubkey,
                                    ctx.client.clock_offset_seconds());
  if (!cwt.has_value()) {
    return {fail_mp_error(io, cmd_ctx, cwt.error()), std::nullopt};
  }

  const auto approved = ctx.client.approve_device_link(mp::ApproveDeviceLinkRequest{
      .link_code = std::string{link_code},
      .device_pubkey = *inspected.device_pubkey,
      .device_cwt = std::move(cwt).value(),
      .device_label = effective_label,
  });
  if (!approved.has_value()) {
    return {fail_mp_error(io, cmd_ctx, approved.error()), std::nullopt};
  }

  return {0, Value::object({
                 {"approved", Value{approved.value().approved}},
                 {"link_code", Value{std::string{link_code}}},
                 {"account_id", Value{Number{approved.value().account_id.value()}}},
                 {"device_id", Value{Number{approved.value().device_id.value()}}},
                 {"device_label", Value{approved.value().device_label}},
                 {"device_fingerprint", Value{*inspected.local_device_fingerprint}},
                 {"requester_country", inspected.requester_country.has_value()
                                           ? Value{*inspected.requester_country}
                                           : Value{nullptr}},
                 {"cwt_expires_ms", Value{Number{approved.value().cwt_expires_ms}}},
             })};
}

int run_online_devices_link_create(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> suggested_label;
  bool no_wait = false;
  bool auto_yes = false;
  std::uint64_t timeout_s = 300U;
  std::uint64_t poll_ms = 2500U;

  for (std::size_t i = 4; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online devices link create [--label <suggested>] "
                "[--no-wait] [--yes] [--timeout-s N] [--poll-ms N] [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--label") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!mp::valid_device_label(*v)) {
        return fail_usage(io, "online devices link create: invalid --label (printable "
                              "ASCII 1..64 chars)");
      }
      suggested_label = std::move(*v);
    } else if (arg == "--no-wait") {
      no_wait = true;
    } else if (arg == "--yes" || arg == "-y") {
      auto_yes = true;
    } else if (arg == "--timeout-s") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed == 0U || *parsed > 600U)
        return fail_usage(io, "online devices link create: --timeout-s must be 1..600");
      timeout_s = *parsed;
    } else if (arg == "--poll-ms") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed < 50U || *parsed > 5000U)
        return fail_usage(io, "online devices link create: --poll-ms must be 50..5000");
      poll_ms = *parsed;
    } else {
      return fail_usage(io, "online devices link create: unknown option: " +
                                std::string{arg});
    }
  }

  auto opened = open_online_context(opts, "online devices link create", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  auto root_key = opened.ctx->store.root_signing_key();
  if (!root_key.has_value())
    return fail_mp_error(io, "online devices link create", root_key.error());

  auto created = opened.ctx->client.create_device_link(suggested_label);
  if (!created.has_value())
    return fail_mp_error(io, "online devices link create", created.error());

  std::string link_code = created.value().link_code;
  OnlineCleanseStringGuard code_guard{link_code};

  const std::string &authority = opened.ctx->client.config().authority;
  std::string join_cmd =
      "blackbird online devices link join " + link_code + " --label " +
      (suggested_label.has_value() ? shell_quote_arg(*suggested_label)
                                   : std::string{"<name>"});
  if (authority != mp::kDefaultMpAuthority) {
    join_cmd += " --authority " + shell_quote_arg(authority);
  }

  io.err << "Link code: " << link_code << "\n"
         << "On the new machine, run:\n  " << join_cmd << "\n"
         << std::flush;

  if (no_wait) {
    return emit_json(
        io, Value::object({
                {"link_code", Value{link_code}},
                {"expires_at_ms", Value{Number{created.value().expires_at_ms}}},
                {"join_command", Value{join_cmd}},
                {"waiting", Value{false}},
            }));
  }

  io.err << "Waiting for the new machine to claim link code...\n" << std::flush;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds{timeout_s};
  mp::InspectDeviceLinkResponse inspected{};
  std::uint64_t rate_limit_backoff_ms = std::min<std::uint64_t>(poll_ms * 2U, 10000U);
  for (;;) {
    auto res = opened.ctx->client.inspect_device_link(link_code);
    std::uint64_t sleep_ms = poll_ms;
    if (!res.has_value()) {
      if (res.error().code != ErrorCode::provider_rate_limit)
        return fail_mp_error(io, "online devices link create", res.error());
      sleep_ms = rate_limit_backoff_ms;
      rate_limit_backoff_ms =
          std::min<std::uint64_t>(rate_limit_backoff_ms * 2U, 10000U);
    } else {
      rate_limit_backoff_ms = std::min<std::uint64_t>(poll_ms * 2U, 10000U);
      if (res.value().state == mp::DeviceLinkState::pending_approval) {
        inspected = std::move(res).value();
        break;
      }
    }
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      return fail_message(
          io, "online devices link create: timed out waiting for device to claim link");
    }
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    std::this_thread::sleep_for(
        std::min(remaining, std::chrono::milliseconds{sleep_ms}));
  }

  auto outcome = approve_inspected_device_link(*opened.ctx, root_key.value(), link_code,
                                               inspected, std::nullopt, auto_yes, io,
                                               "online devices link create");
  if (!outcome.json.has_value())
    return outcome.exit_code != 0 ? outcome.exit_code : 1;
  return emit_json(io, *outcome.json);
}

int run_online_devices_link_approve(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> code_arg;
  OnlineCleanseOptStringGuard code_arg_guard{code_arg};
  std::optional<std::string> label_override;
  bool auto_yes = false;

  for (std::size_t i = 4; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online devices link approve <XXXX-XXXX> "
                "[--label <override>] [--yes] [--state-dir DIR] [--authority HOST] "
                "[--connect-host HOST] [--port N] [--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--label") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!mp::valid_device_label(*v)) {
        return fail_usage(io, "online devices link approve: invalid --label (printable "
                              "ASCII 1..64 chars)");
      }
      label_override = std::move(*v);
    } else if (arg == "--yes" || arg == "-y") {
      auto_yes = true;
    } else if (arg.starts_with('-')) {
      return fail_usage(io, "online devices link approve: unknown option: " +
                                std::string{arg});
    } else {
      if (code_arg.has_value())
        return fail_usage(io, "online devices link approve: unexpected extra argument");
      code_arg = std::string{arg};
    }
  }

  if (!code_arg.has_value() || code_arg->empty())
    return fail_usage(io,
                      "online devices link approve: <XXXX-XXXX> link code is required");
  auto normalized = mp::normalize_device_link_code(*code_arg);
  if (!normalized.has_value()) {
    return fail_usage(io, "online devices link approve: invalid link code (expected "
                          "Crockford Base32 XXXX-XXXX)");
  }
  OnlineCleanseStringGuard norm_guard{normalized.value()};

  auto opened = open_online_context(opts, "online devices link approve", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  auto root_key = opened.ctx->store.root_signing_key();
  if (!root_key.has_value())
    return fail_mp_error(io, "online devices link approve", root_key.error());

  const auto inspected = opened.ctx->client.inspect_device_link(normalized.value());
  if (!inspected.has_value())
    return fail_mp_error(io, "online devices link approve", inspected.error());
  if (inspected.value().state != mp::DeviceLinkState::pending_approval) {
    return fail_message(
        io, "online devices link approve: link is still waiting for the new device to "
            "claim it");
  }

  auto outcome = approve_inspected_device_link(
      *opened.ctx, root_key.value(), normalized.value(), inspected.value(),
      label_override, auto_yes, io, "online devices link approve");
  if (!outcome.json.has_value())
    return outcome.exit_code != 0 ? outcome.exit_code : 1;
  return emit_json(io, *outcome.json);
}

int run_online_devices_link_join(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> code_arg;
  OnlineCleanseOptStringGuard code_arg_guard{code_arg};
  std::string label{kDefaultOnlineDeviceLabel};
  std::uint64_t timeout_s = 300U;
  std::uint64_t poll_ms = 2000U;

  for (std::size_t i = 4; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err
          << "usage: blackbird online devices link join <XXXX-XXXX> [--label <name>] "
             "[--timeout-s N] [--poll-ms N] [--state-dir DIR] [--authority HOST] "
             "[--connect-host HOST] [--port N] [--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--label") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!mp::valid_device_label(*v)) {
        return fail_usage(io, "online devices link join: invalid --label (printable "
                              "ASCII 1..64 chars)");
      }
      label = std::move(*v);
    } else if (arg == "--timeout-s") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed == 0U || *parsed > 600U)
        return fail_usage(io, "online devices link join: --timeout-s must be 1..600");
      timeout_s = *parsed;
    } else if (arg == "--poll-ms") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed < 50U || *parsed > 5000U)
        return fail_usage(io, "online devices link join: --poll-ms must be 50..5000");
      poll_ms = *parsed;
    } else if (arg.starts_with('-')) {
      return fail_usage(io, "online devices link join: unknown option: " +
                                std::string{arg});
    } else {
      if (code_arg.has_value())
        return fail_usage(io, "online devices link join: unexpected extra argument");
      code_arg = std::string{arg};
    }
  }

  if (!code_arg.has_value() || code_arg->empty())
    return fail_usage(io,
                      "online devices link join: <XXXX-XXXX> link code is required");
  auto normalized = mp::normalize_device_link_code(*code_arg);
  if (!normalized.has_value()) {
    return fail_usage(io, "online devices link join: invalid link code (expected "
                          "Crockford Base32 XXXX-XXXX)");
  }
  OnlineCleanseStringGuard norm_guard{normalized.value()};

  const auto state_dir = resolve_online_state_dir(opts, io);
  if (!state_dir.has_value())
    return 2;
  const auto initial_cfg = resolve_online_client_config(opts, {}, io);
  if (!initial_cfg.has_value())
    return 2;

  auto store =
      mp::MpIdentityStore::open_or_init_device(*state_dir, initial_cfg->authority);
  if (!store.has_value())
    return fail_mp_error(io, "online devices link join", store.error());

  // Refuse to clobber an already registered keystore or a primary .root keystore!
  const mp::MpIdentityState &st = store.value().state();
  if (st.account_id.has_value() || st.device_id.has_value() ||
      st.root_seed.has_value() || !st.device_cwt.empty()) {
    return fail_message(
        io,
        "online devices link join: keystore in --state-dir is already registered or "
        "holds a root key; refusing to overwrite");
  }

  const auto cfg = resolve_online_client_config(opts, st.authority, io);
  if (!cfg.has_value())
    return 2;

  const auto device_key = store.value().device_signing_key();
  if (!device_key.has_value())
    return fail_mp_error(io, "online devices link join", device_key.error());

  mp::MpControlClient client{*cfg};
  auto claimed =
      client.claim_device_link(normalized.value(), device_key.value(), label);
  if (!claimed.has_value())
    return fail_mp_error(io, "online devices link join", claimed.error());
  OnlineCleanseStringGuard poll_token_guard{claimed.value().poll_token};

  io.err << "Claimed link code " << normalized.value() << ".\n"
         << "Device fingerprint (verify on your primary machine):\n  "
         << claimed.value().local_device_fingerprint << "\n"
         << "Waiting for approval on your primary machine...\n"
         << std::flush;

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds{timeout_s};
  mp::PollDeviceLinkResponse approved{};
  std::uint64_t rate_limit_backoff_ms = std::min<std::uint64_t>(poll_ms * 2U, 10000U);
  for (;;) {
    auto polled = client.poll_device_link(
        device_key.value(),
        mp::PollDeviceLinkRequest{normalized.value(), claimed.value().poll_token});
    std::uint64_t sleep_ms = poll_ms;
    if (!polled.has_value()) {
      if (polled.error().code != ErrorCode::provider_rate_limit)
        return fail_mp_error(io, "online devices link join", polled.error());
      sleep_ms = rate_limit_backoff_ms;
      rate_limit_backoff_ms =
          std::min<std::uint64_t>(rate_limit_backoff_ms * 2U, 10000U);
    } else {
      rate_limit_backoff_ms = std::min<std::uint64_t>(poll_ms * 2U, 10000U);
      if (polled.value().approved) {
        approved = std::move(polled).value();
        break;
      }
    }
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      return fail_message(
          io, "online devices link join: timed out waiting for primary approval");
    }
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    std::this_thread::sleep_for(
        std::min(remaining, std::chrono::milliseconds{sleep_ms}));
  }

  if (!approved.account_id.has_value() || !approved.device_id.has_value() ||
      !approved.handle.has_value() || !approved.root_pubkey.has_value() ||
      !approved.safety_number.has_value() || !approved.cwt_expires_ms.has_value() ||
      approved.device_cwt.empty()) {
    return fail_message(io, "online devices link join: incomplete approval payload");
  }

  const auto installed = store.value().install_cwt(mp::InstallDeviceCwtRequest{
      .account_id = *approved.account_id,
      .device_id = *approved.device_id,
      .handle = *approved.handle,
      .device_cwt = approved.device_cwt,
      .authority = cfg->authority,
      .expected_root_pubkey = *approved.root_pubkey,
      .now_s = online_unix_seconds() + client.clock_offset_seconds(),
  });
  if (!installed.has_value())
    return fail_mp_error(io, "online devices link join", installed.error());

  io.err << "Linked device #" << approved.device_id->to_decimal() << " to @"
         << *approved.handle << "\n"
         << "Safety Number: " << *approved.safety_number << "\n"
         << std::flush;

  return emit_json(
      io, Value::object({
              {"linked", Value{true}},
              {"account_id", Value{Number{approved.account_id->value()}}},
              {"device_id", Value{Number{approved.device_id->value()}}},
              {"handle", Value{*approved.handle}},
              {"authority", Value{cfg->authority}},
              {"device_label", Value{label}},
              {"device_fingerprint", Value{claimed.value().local_device_fingerprint}},
              {"safety_number", Value{*approved.safety_number}},
              {"cwt_expires_ms", Value{Number{*approved.cwt_expires_ms}}},
          }));
}

int run_online_devices_link(std::span<char *> args, CliIo io) {
  if (args.size() < 4) {
    return fail_usage(io, "online devices link: expected action (create|join|approve)");
  }
  const std::string_view action{args[3]};
  if (action == "--help" || action == "-h") {
    io.err << "usage: blackbird online devices link {create|join|approve} [options]\n";
    return 0;
  }
  if (action == "create")
    return run_online_devices_link_create(args, io);
  if (action == "join")
    return run_online_devices_link_join(args, io);
  if (action == "approve")
    return run_online_devices_link_approve(args, io);
  return fail_usage(io, "online devices link: unknown action: " + std::string{action});
}

int run_online_devices(std::span<char *> args, CliIo io) {
  if (args.size() < 3) {
    return fail_usage(
        io, "online devices: expected action (init|install-cwt|enroll|revoke|link)");
  }
  const std::string_view action{args[2]};
  if (action == "--help" || action == "-h") {
    io.err << "usage: blackbird online devices {init|install-cwt|enroll|revoke|link} "
              "[options]\n"
              "  link: blackbird online devices link {create|join|approve} [options]\n";
    return 0;
  }
  if (action == "init")
    return run_online_devices_init(args, io);
  if (action == "install-cwt")
    return run_online_devices_install_cwt(args, io);
  if (action == "enroll")
    return run_online_devices_enroll(args, io);
  if (action == "revoke")
    return run_online_devices_revoke(args, io);
  if (action == "link")
    return run_online_devices_link(args, io);
  return fail_usage(io, "online devices: unknown action: " + std::string{action});
}

int run_online_web_approve(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> user_code_arg;
  OnlineCleanseOptStringGuard code_arg_guard{user_code_arg};

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online web-approve <XXXX-XXXX> [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg.starts_with('-'))
      return fail_usage(io, "online web-approve: unknown option: " + std::string{arg});
    if (user_code_arg.has_value())
      return fail_usage(io, "online web-approve: unexpected extra argument");
    user_code_arg = std::string{arg};
  }

  if (!user_code_arg.has_value() || user_code_arg->empty())
    return fail_usage(io, "online web-approve: <XXXX-XXXX> user code is required");

  const auto normalized = mp::normalize_web_user_code(*user_code_arg);
  if (!normalized.has_value()) {
    return fail_usage(
        io, "online web-approve: invalid user code (expected Crockford Base32 "
            "XXXX-XXXX)");
  }

  auto opened = open_online_context(opts, "online web-approve", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  const auto res = opened.ctx->client.approve_web_session(normalized.value());
  if (!res.has_value())
    return fail_mp_error(io, "online web-approve", res.error());

  return emit_json(io,
                   Value::object({
                       {"approved", Value{res.value().approved}},
                       {"user_code", Value{normalized.value()}},
                       {"scope", Value{res.value().scope}},
                       {"expires_at_ms", res.value().expires_at_ms.has_value()
                                             ? Value{Number{*res.value().expires_at_ms}}
                                             : Value{nullptr}},
                   }));
}

int run_online_friends_list(std::span<char *> args, std::size_t start_idx, CliIo io) {
  OnlineCommonOpts opts{};
  for (std::size_t i = start_idx; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online friends list [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    return fail_usage(io, "online friends list: unknown option: " + std::string{arg});
  }

  auto opened = open_online_context(opts, "online friends list", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  const auto list = opened.ctx->client.list_friends();
  if (!list.has_value())
    return fail_mp_error(io, "online friends list", list.error());

  Value::Array arr;
  arr.reserve(list.value().size());
  std::uint64_t friend_count = 0;
  std::uint64_t pending_received_count = 0;
  std::uint64_t pending_sent_count = 0;
  std::uint64_t blocked_count = 0;
  for (const auto &edge : list.value()) {
    switch (edge.state) {
    case mp::FriendEdgeState::friend_edge:
      ++friend_count;
      break;
    case mp::FriendEdgeState::invite_received:
      ++pending_received_count;
      break;
    case mp::FriendEdgeState::invite_sent:
      ++pending_sent_count;
      break;
    case mp::FriendEdgeState::blocked:
      ++blocked_count;
      break;
    }
    Value::Object entry{
        {"peer_account_id", Value{Number{edge.peer_account_id.value()}}},
        {"state", Value{std::string{friend_edge_state_name(edge.state)}}},
        {"updated_at_ms", Value{Number{edge.updated_at_ms}}},
    };
    if (edge.handle.has_value())
      entry.emplace_back("peer_handle", Value{*edge.handle});
    if (edge.safety_number.has_value())
      entry.emplace_back("safety_number", Value{*edge.safety_number});
    arr.push_back(Value{std::move(entry)});
  }
  return emit_json(
      io, Value::object({
              {"friends", Value{std::move(arr)}},
              {"count", Value{Number{static_cast<std::uint64_t>(list.value().size())}}},
              {"friend_count", Value{Number{friend_count}}},
              {"pending_received_count", Value{Number{pending_received_count}}},
              {"pending_sent_count", Value{Number{pending_sent_count}}},
              {"blocked_count", Value{Number{blocked_count}}},
          }));
}

enum class OnlineFriendRequestMode : std::uint8_t {
  add,
  accept,
};

enum class OnlineFriendMutateMode : std::uint8_t {
  deny,
  remove,
  block,
};

struct ParsedOnlineFriendTarget {
  std::optional<mp::AccountId> account_id;
  std::string raw;
};

struct ResolvedOnlineFriendTarget {
  std::optional<mp::AccountId> account_id;
  std::optional<std::string> handle;
  int exit_code = 0;
};

// Returns 0 on success, -1 if --help was printed, or a non-zero CLI exit code.
int parse_online_friend_target_args(
    std::span<char *> args, std::string_view ctx, CliIo io, OnlineCommonOpts &opts,
    std::optional<ParsedOnlineFriendTarget> &out_target) {
  std::optional<std::string> target;
  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird " << ctx
             << " <handle|account_id> [--state-dir DIR] [--authority HOST] "
                "[--connect-host HOST] [--port N] [--ca-bundle PATH]\n";
      return -1;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg.starts_with('-'))
      return fail_usage(io, std::string{ctx} + ": unknown option: " + std::string{arg});
    if (target.has_value())
      return fail_usage(io, std::string{ctx} + ": unexpected extra argument");
    target = std::string{arg};
  }

  if (!target.has_value())
    return fail_usage(io, std::string{ctx} + ": <handle|account_id> is required");

  ParsedOnlineFriendTarget parsed{};
  parsed.raw = *target;
  if (is_all_ascii_digits(parsed.raw)) {
    const auto id = mp::AccountId::parse_decimal(parsed.raw);
    if (!id.has_value())
      return fail_usage(io, std::string{ctx} + ": invalid account_id");
    parsed.account_id = id.value();
  } else {
    if (const auto handle = mp::AccountHandle::parse(parsed.raw); !handle.has_value())
      return fail_usage(io, std::string{ctx} + ": invalid handle");
  }

  out_target = std::move(parsed);
  return 0;
}

ResolvedOnlineFriendTarget
resolve_online_friend_target(mp::MpControlClient &client,
                             const ParsedOnlineFriendTarget &parsed,
                             std::string_view ctx, CliIo io) {
  ResolvedOnlineFriendTarget out{};
  if (parsed.account_id.has_value()) {
    out.account_id = parsed.account_id;
    return out;
  }
  const auto resolved = client.resolve_handle(parsed.raw);
  if (!resolved.has_value()) {
    out.exit_code = fail_mp_error(io, ctx, resolved.error());
    return out;
  }
  out.account_id = resolved.value().account_id;
  out.handle = resolved.value().handle;
  return out;
}

int run_online_friends_request(std::span<char *> args, OnlineFriendRequestMode mode,
                               CliIo io) {
  const std::string_view ctx = mode == OnlineFriendRequestMode::accept
                                   ? "online friends accept"
                                   : "online friends add";
  OnlineCommonOpts opts{};
  std::optional<ParsedOnlineFriendTarget> parsed;
  const int parse_rc = parse_online_friend_target_args(args, ctx, io, opts, parsed);
  if (parse_rc == -1)
    return 0;
  if (parse_rc != 0 || !parsed.has_value())
    return parse_rc != 0 ? parse_rc : 2;

  auto opened = open_online_context(opts, ctx, io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  const auto resolved =
      resolve_online_friend_target(opened.ctx->client, *parsed, ctx, io);
  if (!resolved.account_id.has_value())
    return resolved.exit_code;

  const auto res = opened.ctx->client.send_or_accept_friend(*resolved.account_id);
  if (!res.has_value())
    return fail_mp_error(io, ctx, res.error());

  if (mode == OnlineFriendRequestMode::accept) {
    return emit_json(
        io,
        Value::object({
            {"account_id", Value{Number{res.value().target_account_id.value()}}},
            {"handle",
             resolved.handle.has_value() ? Value{*resolved.handle} : Value{nullptr}},
            {"state", Value{std::string{friend_edge_state_name(res.value().state)}}},
            {"action", Value{"accept"}},
            {"http_status",
             Value{Number{static_cast<std::int64_t>(res.value().http_status)}}},
        }));
  }

  Value::Object obj{
      {"target_account_id", Value{Number{res.value().target_account_id.value()}}},
      {"state", Value{std::string{friend_edge_state_name(res.value().state)}}},
      {"http_status",
       Value{Number{static_cast<std::int64_t>(res.value().http_status)}}},
  };
  if (resolved.handle.has_value())
    obj.emplace_back("handle", Value{*resolved.handle});
  return emit_json(io, Value::object(std::move(obj)));
}

int run_online_friends_mutate(std::span<char *> args, OnlineFriendMutateMode mode,
                              CliIo io) {
  std::string_view ctx = "online friends remove";
  if (mode == OnlineFriendMutateMode::block)
    ctx = "online friends block";
  else if (mode == OnlineFriendMutateMode::deny)
    ctx = "online friends deny";

  OnlineCommonOpts opts{};
  std::optional<ParsedOnlineFriendTarget> parsed;
  const int parse_rc = parse_online_friend_target_args(args, ctx, io, opts, parsed);
  if (parse_rc == -1)
    return 0;
  if (parse_rc != 0 || !parsed.has_value())
    return parse_rc != 0 ? parse_rc : 2;

  auto opened = open_online_context(opts, ctx, io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  const auto resolved =
      resolve_online_friend_target(opened.ctx->client, *parsed, ctx, io);
  if (!resolved.account_id.has_value())
    return resolved.exit_code;

  const mp::AccountId target_id = *resolved.account_id;
  const auto res = mode == OnlineFriendMutateMode::block
                       ? opened.ctx->client.block_account(target_id)
                       : opened.ctx->client.remove_friend(target_id);
  if (!res.has_value())
    return fail_mp_error(io, ctx, res.error());

  if (mode == OnlineFriendMutateMode::deny) {
    return emit_json(
        io, Value::object({
                {"account_id", Value{Number{target_id.value()}}},
                {"handle", resolved.handle.has_value() ? Value{*resolved.handle}
                                                       : Value{nullptr}},
                {"denied", Value{true}},
            }));
  }

  return emit_json(
      io,
      Value::object({
          {mode == OnlineFriendMutateMode::block ? "blocked" : "removed", Value{true}},
          {"target_account_id", Value{Number{target_id.value()}}},
          {"account_id", Value{Number{target_id.value()}}},
          {"handle",
           resolved.handle.has_value() ? Value{*resolved.handle} : Value{nullptr}},
      }));
}

int run_online_friends(std::span<char *> args, CliIo io) {
  if (args.size() < 3)
    return run_online_friends_list(args, 2, io);
  const std::string_view action{args[2]};
  if (action == "--help" || action == "-h") {
    io.err << "usage: blackbird online friends "
              "[list|add <handle|account_id>|accept <handle|account_id>|"
              "deny <handle|account_id>|remove <handle|account_id>|"
              "block <handle|account_id>] [options]\n"
              "  alias: decline <handle|account_id> (same as deny)\n";
    return 0;
  }
  if (action.starts_with('-'))
    return run_online_friends_list(args, 2, io);
  if (action == "list")
    return run_online_friends_list(args, 3, io);
  if (action == "add")
    return run_online_friends_request(args, OnlineFriendRequestMode::add, io);
  if (action == "accept")
    return run_online_friends_request(args, OnlineFriendRequestMode::accept, io);
  if (action == "deny" || action == "decline")
    return run_online_friends_mutate(args, OnlineFriendMutateMode::deny, io);
  if (action == "remove")
    return run_online_friends_mutate(args, OnlineFriendMutateMode::remove, io);
  if (action == "block")
    return run_online_friends_mutate(args, OnlineFriendMutateMode::block, io);
  return fail_usage(io, "online friends: unknown action: " + std::string{action});
}

int run_online_party_create(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  mp::PartyVisibility visibility = mp::PartyVisibility::friends;
  mp::PartyJoinMode join_mode = mp::PartyJoinMode::invite_only;
  mp::RelayPolicy relay_policy = mp::RelayPolicy::force_relays;
  std::uint8_t max_members = 4U;
  std::optional<std::string> explicit_relay_url;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online party create "
                "[--visibility private|friends] [--join-mode invite|approval] "
                "[--relay allow|force|no] [--max-members N] [--relay-url URL] "
                "[--state-dir DIR] [--authority HOST] [--connect-host HOST] "
                "[--port N] [--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--visibility") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_online_visibility(*v);
      if (!parsed.has_value())
        return fail_usage(io, "online party create: invalid --visibility");
      visibility = *parsed;
    } else if (arg == "--join-mode") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_online_join_mode(*v);
      if (!parsed.has_value())
        return fail_usage(io, "online party create: invalid --join-mode");
      join_mode = *parsed;
    } else if (arg == "--relay") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_online_relay_policy(*v);
      if (!parsed.has_value())
        return fail_usage(io, "online party create: invalid --relay");
      relay_policy = *parsed;
    } else if (arg == "--max-members") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed < 2U || *parsed > mp::kMaxPartyMembers) {
        return fail_usage(
            io, "online party create: --max-members must be between 2 and 12");
      }
      max_members = static_cast<std::uint8_t>(*parsed);
    } else if (arg == "--relay-url") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      explicit_relay_url = std::move(*v);
    } else {
      return fail_usage(io, "online party create: unknown option: " + std::string{arg});
    }
  }

  const auto built_ep = build_online_endpoint(relay_policy, explicit_relay_url,
                                              "online party create", io);
  if (!built_ep.has_value())
    return 2;

  auto opened = open_online_context(opts, "online party create", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  mp::CreatePartyRequest req{};
  req.visibility = visibility;
  req.join_mode = join_mode;
  req.relay_policy = relay_policy;
  req.max_members = max_members;
  req.endpoint = built_ep->endpoint;
  req.relay_url = built_ep->relay_url;

  const auto created = opened.ctx->client.create_party(req);
  if (!created.has_value())
    return fail_mp_error(io, "online party create", created.error());

  return emit_json(io,
                   Value::object({
                       {"party_id", Value{Number{created.value().party_id.value()}}},
                       {"party_epoch", Value{Number{created.value().party_epoch}}},
                       {"pinned_relay_url", Value{created.value().pinned_relay_url}},
                   }));
}

int run_online_party_info(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> party_arg;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online party info <party_id> [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg.starts_with('-'))
      return fail_usage(io, "online party info: unknown option: " + std::string{arg});
    if (party_arg.has_value())
      return fail_usage(io, "online party info: unexpected extra argument");
    party_arg = std::string{arg};
  }

  if (!party_arg.has_value())
    return fail_usage(io, "online party info: <party_id> is required");
  const auto pid = mp::PartyId::parse_decimal(*party_arg);
  if (!pid.has_value())
    return fail_usage(io, "online party info: invalid <party_id>");

  auto opened = open_online_context(opts, "online party info", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  const auto summary = opened.ctx->client.get_party(pid.value());
  if (!summary.has_value())
    return fail_mp_error(io, "online party info", summary.error());

  const mp::PartySummary &s = summary.value();
  return emit_json(
      io,
      Value::object({
          {"party_id", Value{Number{s.party_id.value()}}},
          {"party_epoch", Value{Number{s.party_epoch}}},
          {"leader_account_id", Value{Number{s.leader_account_id.value()}}},
          {"leader_device_id", Value{Number{s.leader_device_id.value()}}},
          {"visibility", Value{std::string{party_visibility_name(s.visibility)}}},
          {"join_mode", Value{std::string{party_join_mode_name(s.join_mode)}}},
          {"relay_policy", Value{std::string{relay_policy_name(s.relay_policy)}}},
          {"pinned_relay_url", Value{s.pinned_relay_url}},
          {"max_members", Value{Number{static_cast<std::uint64_t>(s.max_members)}}},
          {"member_count", Value{Number{static_cast<std::uint64_t>(s.member_count)}}},
      }));
}

int run_online_party_invite(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> party_arg;
  std::uint8_t max_uses = 1U;
  std::uint32_t ttl_sec = 3600U;
  std::optional<mp::AccountId> target_account;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online party invite <party_id> [--max-uses N] "
                "[--ttl-s N] [--target-account ID] [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--max-uses") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed == 0U || *parsed > 255U)
        return fail_usage(io, "online party invite: --max-uses must be 1..255");
      max_uses = static_cast<std::uint8_t>(*parsed);
    } else if (arg == "--ttl-s") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed == 0U ||
          *parsed > static_cast<std::uint64_t>(kMaxInviteTtlSec)) {
        return fail_usage(io, "online party invite: --ttl-s out of range");
      }
      ttl_sec = static_cast<std::uint32_t>(*parsed);
    } else if (arg == "--target-account") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = mp::AccountId::parse_decimal(*v);
      if (!parsed.has_value())
        return fail_usage(io, "online party invite: invalid --target-account");
      target_account = parsed.value();
    } else if (arg.starts_with('-')) {
      return fail_usage(io, "online party invite: unknown option: " + std::string{arg});
    } else {
      if (party_arg.has_value())
        return fail_usage(io, "online party invite: unexpected extra argument");
      party_arg = std::string{arg};
    }
  }

  if (!party_arg.has_value())
    return fail_usage(io, "online party invite: <party_id> is required");
  const auto pid = mp::PartyId::parse_decimal(*party_arg);
  if (!pid.has_value())
    return fail_usage(io, "online party invite: invalid <party_id>");

  auto opened = open_online_context(opts, "online party invite", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  const auto res = opened.ctx->client.create_party_invite(mp::CreatePartyInviteRequest{
      .party_id = pid.value(),
      .target_account_id = target_account,
      .max_uses = max_uses,
      .ttl_sec = ttl_sec,
  });
  if (!res.has_value())
    return fail_mp_error(io, "online party invite", res.error());

  return emit_json(
      io, Value::object({
              {"party_id", Value{Number{pid.value().value()}}},
              {"party_invite_id", Value{Number{res.value().party_invite_id.value()}}},
              {"expires_at_ms", Value{Number{res.value().expires_at_ms}}},
              {"invite_link", res.value().invite_link.has_value()
                                  ? Value{*res.value().invite_link}
                                  : Value{nullptr}},
          }));
}

int run_online_party_join(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> target_arg;
  OnlineCleanseOptStringGuard target_guard{target_arg};
  mp::RelayPolicy relay_policy = mp::RelayPolicy::force_relays;
  std::optional<std::string> explicit_relay_url;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online party join <party_id|mppi1_...> "
                "[--relay allow|force|no] [--relay-url URL] [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--relay") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_online_relay_policy(*v);
      if (!parsed.has_value())
        return fail_usage(io, "online party join: invalid --relay");
      relay_policy = *parsed;
    } else if (arg == "--relay-url") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      explicit_relay_url = std::move(*v);
    } else if (arg.starts_with('-')) {
      return fail_usage(io, "online party join: unknown option: " + std::string{arg});
    } else {
      if (target_arg.has_value())
        return fail_usage(io, "online party join: unexpected extra argument");
      target_arg = std::string{arg};
    }
  }

  if (!target_arg.has_value())
    return fail_usage(io, "online party join: <party_id|mppi1_...> is required");

  auto parsed_target = parse_party_join_target(*target_arg);
  if (!parsed_target.has_value())
    return fail_usage(io, "online party join: invalid party id or invite link");
  OnlineCleanseOptStringGuard link_guard{parsed_target->invite_link};

  const auto built_ep =
      build_online_endpoint(relay_policy, explicit_relay_url, "online party join", io);
  if (!built_ep.has_value())
    return 2;

  auto opened = open_online_context(opts, "online party join", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  mp::JoinPartyRequest req{
      .party_id = parsed_target->party_id,
      .endpoint = built_ep->endpoint,
      .invite_link = parsed_target->invite_link,
  };
  OnlineCleanseOptStringGuard req_link_guard{req.invite_link};

  const auto joined = opened.ctx->client.join_party(req);
  if (!joined.has_value())
    return fail_mp_error(io, "online party join", joined.error());

  return emit_json(
      io, Value::object({
              {"party_id", Value{Number{parsed_target->party_id.value()}}},
              {"status",
               Value{std::string{joined.value().pending_approval ? "pending_approval"
                                                                 : "joined"}}},
              {"pending_approval", Value{joined.value().pending_approval}},
              {"party_epoch", Value{Number{joined.value().party_epoch}}},
              {"request_id", joined.value().request_id.has_value()
                                 ? Value{Number{joined.value().request_id->value()}}
                                 : Value{nullptr}},
          }));
}

int run_online_party_kick(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> party_arg;
  std::optional<std::string> account_arg;
  std::optional<std::uint64_t> epoch;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online party kick <party_id> <account_id> "
                "[--epoch N] [--state-dir DIR] [--authority HOST] "
                "[--connect-host HOST] [--port N] [--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--epoch") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed == 0U || *parsed > mp::kMaxSafeId)
        return fail_usage(io, "online party kick: invalid --epoch");
      epoch = *parsed;
    } else if (arg.starts_with('-')) {
      return fail_usage(io, "online party kick: unknown option: " + std::string{arg});
    } else if (!party_arg.has_value()) {
      party_arg = std::string{arg};
    } else if (!account_arg.has_value()) {
      account_arg = std::string{arg};
    } else {
      return fail_usage(io, "online party kick: unexpected extra argument");
    }
  }

  if (!party_arg.has_value() || !account_arg.has_value())
    return fail_usage(io,
                      "online party kick: <party_id> and <account_id> are required");
  const auto pid = mp::PartyId::parse_decimal(*party_arg);
  if (!pid.has_value())
    return fail_usage(io, "online party kick: invalid <party_id>");
  const auto target_id = mp::AccountId::parse_decimal(*account_arg);
  if (!target_id.has_value())
    return fail_usage(io, "online party kick: invalid <account_id>");

  auto opened = open_online_context(opts, "online party kick", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  std::uint64_t expected_epoch = 0U;
  if (epoch.has_value()) {
    expected_epoch = *epoch;
  } else {
    const auto info = opened.ctx->client.get_party(pid.value());
    if (!info.has_value())
      return fail_mp_error(io, "online party kick", info.error());
    expected_epoch = info.value().party_epoch;
  }

  const auto kicked = opened.ctx->client.kick_member(mp::KickMemberRequest{
      .party_id = pid.value(),
      .target_account_id = target_id.value(),
      .expected_party_epoch = expected_epoch,
  });
  if (!kicked.has_value())
    return fail_mp_error(io, "online party kick", kicked.error());

  return emit_json(io,
                   Value::object({
                       {"kicked", Value{true}},
                       {"party_id", Value{Number{pid.value().value()}}},
                       {"target_account_id", Value{Number{target_id.value().value()}}},
                       {"party_epoch", Value{Number{kicked.value().party_epoch}}},
                   }));
}

int run_online_party_leave(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> party_arg;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online party leave <party_id> [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg.starts_with('-'))
      return fail_usage(io, "online party leave: unknown option: " + std::string{arg});
    if (party_arg.has_value())
      return fail_usage(io, "online party leave: unexpected extra argument");
    party_arg = std::string{arg};
  }

  if (!party_arg.has_value())
    return fail_usage(io, "online party leave: <party_id> is required");
  const auto pid = mp::PartyId::parse_decimal(*party_arg);
  if (!pid.has_value())
    return fail_usage(io, "online party leave: invalid <party_id>");

  auto opened = open_online_context(opts, "online party leave", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  const auto left = opened.ctx->client.leave_party(pid.value());
  if (!left.has_value())
    return fail_mp_error(io, "online party leave", left.error());

  return emit_json(io, Value::object({
                           {"left", Value{true}},
                           {"party_id", Value{Number{pid.value().value()}}},
                           {"party_epoch", Value{Number{left.value().party_epoch}}},
                       }));
}

int run_online_party_disband(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> party_arg;
  std::optional<std::uint64_t> epoch;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online party disband <party_id> [--epoch N] "
                "[--state-dir DIR] [--authority HOST] [--connect-host HOST] "
                "[--port N] [--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--epoch") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed == 0U || *parsed > mp::kMaxSafeId)
        return fail_usage(io, "online party disband: invalid --epoch");
      epoch = *parsed;
    } else if (arg.starts_with('-')) {
      return fail_usage(io,
                        "online party disband: unknown option: " + std::string{arg});
    } else {
      if (party_arg.has_value())
        return fail_usage(io, "online party disband: unexpected extra argument");
      party_arg = std::string{arg};
    }
  }

  if (!party_arg.has_value())
    return fail_usage(io, "online party disband: <party_id> is required");
  const auto pid = mp::PartyId::parse_decimal(*party_arg);
  if (!pid.has_value())
    return fail_usage(io, "online party disband: invalid <party_id>");

  auto opened = open_online_context(opts, "online party disband", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  std::uint64_t expected_epoch = 0U;
  if (epoch.has_value()) {
    expected_epoch = *epoch;
  } else {
    const auto info = opened.ctx->client.get_party(pid.value());
    if (!info.has_value())
      return fail_mp_error(io, "online party disband", info.error());
    expected_epoch = info.value().party_epoch;
  }

  const auto disbanded = opened.ctx->client.disband_party(mp::DisbandPartyRequest{
      .party_id = pid.value(),
      .expected_party_epoch = expected_epoch,
  });
  if (!disbanded.has_value())
    return fail_mp_error(io, "online party disband", disbanded.error());

  return emit_json(io,
                   Value::object({
                       {"disbanded", Value{true}},
                       {"party_id", Value{Number{pid.value().value()}}},
                       {"party_epoch", Value{Number{disbanded.value().party_epoch}}},
                   }));
}

std::atomic<bool> g_mp_attach_stop{false};

void mp_attach_signal_handler(int /*signum*/) noexcept {
  g_mp_attach_stop.store(true, std::memory_order_relaxed);
}

class MpAttachSignalGuard {
public:
  MpAttachSignalGuard() noexcept {
    g_mp_attach_stop.store(false, std::memory_order_relaxed);
    struct sigaction sa{};
    sa.sa_handler = mp_attach_signal_handler;
    sigemptyset(&sa.sa_mask);
    if (::sigaction(SIGINT, &sa, &prev_int_) == 0)
      installed_int_ = true;
    if (::sigaction(SIGTERM, &sa, &prev_term_) == 0)
      installed_term_ = true;
  }

  MpAttachSignalGuard(const MpAttachSignalGuard &) = delete;
  MpAttachSignalGuard &operator=(const MpAttachSignalGuard &) = delete;

  ~MpAttachSignalGuard() {
    if (installed_int_)
      (void)::sigaction(SIGINT, &prev_int_, nullptr);
    if (installed_term_)
      (void)::sigaction(SIGTERM, &prev_term_, nullptr);
  }

private:
  struct sigaction prev_int_{};
  struct sigaction prev_term_{};
  bool installed_int_ = false;
  bool installed_term_ = false;
};

int run_online_party_attach(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<std::string> party_arg;
  MpAttachMode mode = MpAttachMode::jsonl;
  std::optional<mp::RelayPolicy> explicit_relay_policy;
  std::optional<std::string> explicit_relay_url;
  std::string room_scope{kMpAttachDefaultRoomScope};
  std::optional<fs::path> party_socket;
  std::optional<std::string> party_room;
  bool listen_only = false;
  bool exit_on_eof = false;

  for (std::size_t i = 3; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online party attach <party_id|mppi1_...> "
                "[--mode jsonl|plain] [--plain] [--relay-policy allow|force|no] "
                "[--relay-url URL] [--room-scope SCOPE] "
                "[--party-socket PATH --party-room ROOM] [--listen-only] "
                "[--exit-on-eof] [--state-dir DIR] [--authority HOST] "
                "[--connect-host HOST] [--port N] [--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--mode") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_mp_attach_mode(*v);
      if (!parsed.has_value())
        return fail_usage(io, "online party attach: invalid --mode (jsonl|plain)");
      mode = parsed.value();
    } else if (arg == "--plain") {
      mode = MpAttachMode::plain;
    } else if (arg == "--relay-policy") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_online_relay_policy(*v);
      if (!parsed.has_value()) {
        return fail_usage(
            io, "online party attach: invalid --relay-policy (allow|force|no)");
      }
      explicit_relay_policy = *parsed;
    } else if (arg == "--relay-url") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty() || v->size() > 200U || !v->starts_with("https://"))
        return fail_usage(io, "online party attach: --relay-url must be https://...");
      explicit_relay_url = std::move(*v);
    } else if (arg == "--room-scope") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (v->empty() || v->size() > kP2pPartyMaxRoomScopeBytes)
        return fail_usage(io, "online party attach: invalid --room-scope");
      room_scope = std::move(*v);
    } else if (arg == "--party-socket") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_path_arg(*v, /*require_filename=*/true))
        return fail_usage(io, "online party attach: invalid --party-socket path");
      party_socket = fs::path{std::move(*v)};
    } else if (arg == "--party-room") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_party_room_id(*v))
        return fail_usage(io, "online party attach: invalid --party-room");
      party_room = std::move(*v);
    } else if (arg == "--listen-only") {
      listen_only = true;
    } else if (arg == "--exit-on-eof") {
      exit_on_eof = true;
    } else if (arg.starts_with('-')) {
      return fail_usage(io, "online party attach: unknown option: " + std::string{arg});
    } else {
      if (party_arg.has_value())
        return fail_usage(io, "online party attach: unexpected extra argument");
      party_arg = std::string{arg};
    }
  }

  OnlineCleanseOptStringGuard party_arg_guard{party_arg};
  if (!party_arg.has_value())
    return fail_usage(io, "online party attach: <party_id|mppi1_...> is required");
  const auto target = parse_party_join_target(*party_arg);
  if (!target.has_value())
    return fail_usage(io, "online party attach: invalid <party_id|mppi1_...>");
  const mp::PartyId pid = target->party_id;
  std::optional<std::string> attach_invite = target->invite_link;
  OnlineCleanseOptStringGuard attach_invite_guard{attach_invite};
  if (party_socket.has_value() != party_room.has_value()) {
    return fail_usage(
        io,
        "online party attach: --party-socket and --party-room must be set together");
  }

  auto opened = open_online_context(opts, "online party attach", io);
  if (!opened.ctx.has_value())
    return opened.exit_code;

  mp::RelayPolicy local_policy = mp::RelayPolicy::force_relays;
  std::optional<std::string> relay_url = explicit_relay_url;
  std::optional<mp::PartySummary> fetched_summary;
  std::optional<Error> party_info_err;
  auto party_info = opened.ctx->client.get_party(pid);
  if (!party_info.has_value() && attach_invite.has_value()) {
    const auto err_detail = mp::mp_client_error_of(party_info.error());
    if (err_detail == mp::MpClientError::http_not_found ||
        err_detail == mp::MpClientError::http_forbidden) {
      const std::string join_relay =
          explicit_relay_url.value_or(std::string{kDefaultOnlineRelayUrl});
      const mp::EndpointDescriptor join_ep{
          mp::TransportKind::iroh_quic, join_relay, {}};
      mp::JoinPartyRequest jreq{pid, join_ep, std::move(attach_invite)};
      OnlineCleanseOptStringGuard jreq_guard{jreq.invite_link};
      const auto joined = opened.ctx->client.join_party(jreq);
      if (!joined.has_value())
        return fail_mp_error(io, "online party attach (join)", joined.error());
      if (joined.value().pending_approval) {
        return fail_message(
            io, "online party attach: join request is pending leader approval");
      }
      party_info = opened.ctx->client.get_party(pid);
    }
  }
  if (party_info.has_value()) {
    fetched_summary = std::move(party_info).value();
  } else {
    party_info_err = party_info.error();
  }

  if (explicit_relay_policy.has_value()) {
    local_policy = *explicit_relay_policy;
    if (local_policy == mp::RelayPolicy::no_relays) {
      relay_url = std::nullopt;
    } else if (!relay_url.has_value()) {
      relay_url =
          (fetched_summary.has_value() && !fetched_summary->pinned_relay_url.empty())
              ? fetched_summary->pinned_relay_url
              : std::string{kDefaultOnlineRelayUrl};
    }
  } else {
    if (!fetched_summary.has_value()) {
      return fail_mp_error(
          io, "online party attach",
          party_info_err.value_or(Error{ErrorCode::provider_transport}));
    }
    local_policy = fetched_summary->relay_policy;
    if (local_policy == mp::RelayPolicy::no_relays) {
      relay_url = std::nullopt;
    } else if (!relay_url.has_value()) {
      relay_url = fetched_summary->pinned_relay_url.empty()
                      ? std::string{kDefaultOnlineRelayUrl}
                      : fetched_summary->pinned_relay_url;
    }
  }

  const auto resolved_cfg =
      resolve_online_client_config(opts, opened.ctx->store.state().authority, io);
  if (!resolved_cfg.has_value())
    return 2;

  MpPartyRuntimeConfig rt_cfg{
      .client_config = *resolved_cfg,
      .identity = opened.ctx->store.state(),
      .party_id = pid,
      .local_relay_policy = local_policy,
      .relay_url = relay_url,
  };

  auto runtime = MpPartyRuntime::attach(std::move(rt_cfg));
  if (!runtime.has_value()) {
    const auto &err = runtime.error();
    std::string detail_name;
    if (err.detail >= 2000) {
      detail_name =
          std::string{mp_party_runtime_error_name(mp_party_runtime_error_of(err))};
    } else if (err.detail >= 1000) {
      detail_name = std::string{mp::mp_client_error_name(mp::mp_client_error_of(err))};
    } else if (err.detail >= 100) {
      detail_name = std::string{mp::mp_error_name(mp::mp_error_of(err))};
    } else {
      detail_name = std::string{error_name(err.code)};
    }
    return fail_message(io, "online party attach: failed to attach (" +
                                std::string{error_name(err.code)} + ", " + detail_name +
                                ")");
  }

  MpAttachSignalGuard signal_guard{};
  MpAttachConfig attach_cfg{};
  attach_cfg.mode = mode;
  attach_cfg.input_fd = listen_only ? -1 : STDIN_FILENO;
  attach_cfg.emit_line = make_mp_attach_ostream_emitter(io.out);
  attach_cfg.stop_flag = &g_mp_attach_stop;
  attach_cfg.exit_on_eof = exit_on_eof;
  attach_cfg.default_room_scope = std::move(room_scope);
  attach_cfg.local_party_socket = std::move(party_socket);
  attach_cfg.local_party_room_id = std::move(party_room);

  const auto summary = run_mp_party_attach_loop(runtime.value(), std::move(attach_cfg));
  if (!summary.has_value()) {
    return fail_message(io, "online party attach: runtime loop failed (" +
                                std::string{error_name(summary.error().code)} + ")");
  }
  return 0;
}

int run_online_party(std::span<char *> args, CliIo io) {
  if (args.size() < 3) {
    return fail_usage(io, "online party: expected action "
                          "(create|info|invite|join|attach|kick|leave|disband)");
  }
  const std::string_view action{args[2]};
  if (action == "--help" || action == "-h") {
    io.err
        << "usage: blackbird online party {create|info|invite|join|attach|kick|leave|"
           "disband} [options]\n";
    return 0;
  }
  if (action == "create")
    return run_online_party_create(args, io);
  if (action == "info")
    return run_online_party_info(args, io);
  if (action == "invite")
    return run_online_party_invite(args, io);
  if (action == "join")
    return run_online_party_join(args, io);
  if (action == "attach")
    return run_online_party_attach(args, io);
  if (action == "kick")
    return run_online_party_kick(args, io);
  if (action == "leave")
    return run_online_party_leave(args, io);
  if (action == "disband")
    return run_online_party_disband(args, io);
  return fail_usage(io, "online party: unknown action: " + std::string{action});
}

int run_online_recovery_key(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online recovery-key [--state-dir DIR]\n";
      return 0;
    }
    if (arg == "--state-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_path_arg(*v, /*require_filename=*/false))
        return fail_usage(io, "online recovery-key: invalid --state-dir path");
      opts.state_dir = strip_trailing_slashes_party(fs::path{*v});
    } else {
      return fail_usage(io, "online recovery-key: unknown option: " + std::string{arg});
    }
  }

  const auto state_dir = resolve_online_state_dir(opts, io);
  if (!state_dir.has_value())
    return 2;
  auto store = mp::MpIdentityStore::open_existing(*state_dir);
  if (!store.has_value())
    return fail_mp_error(io, "online recovery-key", store.error());
  const mp::MpIdentityState &st = store.value().state();
  if (!st.root_seed.has_value()) {
    return fail_mp_error(
        io, "online recovery-key",
        {ErrorCode::provider_auth,
         static_cast<std::int64_t>(mp::MpClientError::missing_root_key)});
  }

  auto rec_key = mp::encode_recovery_key(st.root_seed->bytes());
  if (!rec_key.has_value())
    return fail_mp_error(io, "online recovery-key", rec_key.error());
  OnlineCleanseStringGuard rec_key_guard{rec_key.value()};

  io.err << "Keep this Recovery Key in a password manager or offline backup. Never "
            "share it or pass it on argv.\n"
         << std::flush;
  io.out << rec_key.value() << '\n' << std::flush;
  if (!io.out)
    return fail_message(io, "online recovery-key: failed to write stdout");
  return 0;
}

int run_online_export_mpkey(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<fs::path> out_path;
  bool passphrase_stdin = false;

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online export-mpkey --out <path.mpkey> "
                "[--passphrase-stdin] [--state-dir DIR]\n";
      return 0;
    }
    if (arg == "--state-dir") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_path_arg(*v, /*require_filename=*/false))
        return fail_usage(io, "online export-mpkey: invalid --state-dir path");
      opts.state_dir = strip_trailing_slashes_party(fs::path{*v});
    } else if (arg == "--out") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_path_arg(*v, /*require_filename=*/true))
        return fail_usage(io, "online export-mpkey: invalid --out path");
      out_path = fs::path{std::move(*v)};
    } else if (arg == "--passphrase-stdin") {
      passphrase_stdin = true;
    } else if (arg == "--passphrase" || arg == "-p") {
      return fail_usage(
          io, "online export-mpkey: passphrases are never accepted on argv; use "
              "interactive prompt or --passphrase-stdin");
    } else {
      return fail_usage(
          io,
          "online export-mpkey: unexpected option or argument (passphrases are never "
          "accepted on argv)");
    }
  }

  if (!out_path.has_value())
    return fail_usage(io, "online export-mpkey: --out <path.mpkey> is required");

  const auto state_dir = resolve_online_state_dir(opts, io);
  if (!state_dir.has_value())
    return 2;
  auto store = mp::MpIdentityStore::open_existing(*state_dir);
  if (!store.has_value())
    return fail_mp_error(io, "online export-mpkey", store.error());
  const mp::MpIdentityState &st = store.value().state();
  if (!st.root_seed.has_value()) {
    return fail_mp_error(
        io, "online export-mpkey",
        {ErrorCode::provider_auth,
         static_cast<std::int64_t>(mp::MpClientError::missing_root_key)});
  }

  std::string passphrase;
  OnlineCleanseStringGuard pass_guard{passphrase};
  const bool interactive_tty =
      !passphrase_stdin && (&io.in == &std::cin) && (::isatty(STDIN_FILENO) != 0);
  if (!read_secret_line_bounded(io,
                                ReadSecretLineOpts{
                                    .prompt = "Enter passphrase for .mpkey backup: ",
                                    .max_bytes = mp::kMpKeyV1MaxPassphraseBytes,
                                    .force_stdin = passphrase_stdin,
                                },
                                passphrase) ||
      passphrase.empty()) {
    return fail_usage(io, "online export-mpkey: non-empty passphrase is required");
  }
  if (interactive_tty) {
    std::string confirm;
    OnlineCleanseStringGuard confirm_guard{confirm};
    if (!read_secret_line_bounded(io,
                                  ReadSecretLineOpts{
                                      .prompt = "Confirm passphrase: ",
                                      .max_bytes = mp::kMpKeyV1MaxPassphraseBytes,
                                      .force_stdin = false,
                                  },
                                  confirm)) {
      return fail_message(io, "online export-mpkey: failed to read confirmation");
    }
    const std::span<const std::uint8_t> lhs{
        reinterpret_cast<const std::uint8_t *>(passphrase.data()), passphrase.size()};
    const std::span<const std::uint8_t> rhs{
        reinterpret_cast<const std::uint8_t *>(confirm.data()), confirm.size()};
    if (!mp::constant_time_equal({lhs, rhs}))
      return fail_message(io, "online export-mpkey: passphrases do not match");
  }
  if (passphrase.size() < 12U) {
    io.err << "blackbird online export-mpkey: warning: passphrase is shorter than 12 "
              "characters\n"
           << std::flush;
  }

  mp::MpKeyPayload payload{};
  OnlineCleanseSeedGuard payload_seed_guard{payload.root_seed};
  payload.account_id = st.account_id;
  if (!st.handle.empty())
    payload.handle = st.handle;
  payload.root_seed = st.root_seed->bytes();

  const auto armored = mp::encrypt_mpkey_v1(payload, passphrase);
  if (!armored.has_value())
    return fail_mp_error(io, "online export-mpkey", armored.error());

  if (!write_mpkey_atomic_0600(*out_path, armored.value(), io, "online export-mpkey"))
    return 1;

  return emit_json(
      io,
      Value::object({
          {"exported", Value{true}},
          {"path", Value{out_path->string()}},
          {"account_id", st.account_id.has_value()
                             ? Value{Number{st.account_id->value()}}
                             : Value{nullptr}},
          {"handle", !st.handle.empty() ? Value{st.handle} : Value{nullptr}},
          {"bytes", Value{Number{static_cast<std::uint64_t>(armored.value().size())}}},
      }));
}

int run_online_recover(std::span<char *> args, CliIo io) {
  OnlineCommonOpts opts{};
  std::optional<fs::path> mpkey_path;
  bool passphrase_stdin = false;
  std::string device_label{kDefaultOnlineDeviceLabel};

  for (std::size_t i = 2; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird online recover [--mpkey <path.mpkey>] "
                "[--passphrase-stdin] [--device-label <name>] [--state-dir DIR] "
                "[--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH]\n";
      return 0;
    }
    const int common = parse_online_common_flag(args, i, opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    if (arg == "--mpkey") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_path_arg(*v, /*require_filename=*/true))
        return fail_usage(io, "online recover: invalid --mpkey path");
      mpkey_path = fs::path{std::move(*v)};
    } else if (arg == "--passphrase-stdin") {
      passphrase_stdin = true;
    } else if (arg == "--device-label") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!mp::valid_device_label(*v)) {
        return fail_usage(io, "online recover: invalid --device-label (printable ASCII "
                              "1..64 chars)");
      }
      device_label = std::move(*v);
    } else if (arg == "--recovery-key" || arg == "--passphrase" || arg == "-p" ||
               arg == "--key") {
      return fail_usage(
          io,
          "online recover: recovery keys and passphrases are never accepted on argv; "
          "supply them via stdin or interactive prompt");
    } else {
      return fail_usage(
          io, "online recover: unexpected option or argument (recovery keys and "
              "passphrases are never accepted on argv)");
    }
  }

  if (passphrase_stdin && !mpkey_path.has_value()) {
    return fail_usage(io, "online recover: --passphrase-stdin requires --mpkey");
  }

  const auto state_dir = resolve_online_state_dir(opts, io);
  if (!state_dir.has_value())
    return 2;
  const auto cfg = resolve_online_client_config(opts, {}, io);
  if (!cfg.has_value())
    return 2;

  if (const int preflight_rc =
          preflight_online_register_dir(*state_dir, "online recover", io);
      preflight_rc != 0) {
    return preflight_rc;
  }

  mp::CleansedSeed root_seed{};
  if (mpkey_path.has_value()) {
    const auto armored = read_mpkey_file_bounded(*mpkey_path, "online recover", io);
    if (!armored.has_value())
      return 1;
    std::string passphrase;
    OnlineCleanseStringGuard pass_guard{passphrase};
    if (!read_secret_line_bounded(io,
                                  ReadSecretLineOpts{
                                      .prompt = "Enter passphrase for .mpkey file: ",
                                      .max_bytes = mp::kMpKeyV1MaxPassphraseBytes,
                                      .force_stdin = passphrase_stdin,
                                  },
                                  passphrase) ||
        passphrase.empty()) {
      return fail_usage(io, "online recover: non-empty passphrase is required");
    }
    auto decrypted = mp::decrypt_mpkey_v1(mp::MpKeyDecryptInput{*armored, passphrase});
    if (!decrypted.has_value())
      return fail_mp_error(io, "online recover", decrypted.error());
    OnlineCleanseSeedGuard dec_seed_guard{decrypted.value().root_seed};
    root_seed = mp::CleansedSeed{decrypted.value().root_seed};
  } else {
    std::string raw_recovery_key;
    OnlineCleanseStringGuard rec_guard{raw_recovery_key};
    if (!read_secret_line_bounded(io,
                                  ReadSecretLineOpts{
                                      .prompt = "Enter recovery key (mprk1_...): ",
                                      .max_bytes = mp::kMaxRecoveryKeyInputLength,
                                      .force_stdin = false,
                                  },
                                  raw_recovery_key) ||
        raw_recovery_key.empty()) {
      return fail_usage(io, "online recover: recovery key is required on stdin/TTY");
    }
    auto decoded = mp::decode_recovery_key(raw_recovery_key);
    if (!decoded.has_value())
      return fail_mp_error(io, "online recover", decoded.error());
    OnlineCleanseSeedGuard dec_seed_guard{decoded.value()};
    root_seed = mp::CleansedSeed{decoded.value()};
  }

  auto root_key = mp::Ed25519SigningKey::from_seed(root_seed.bytes());
  if (!root_key.has_value())
    return fail_mp_error(io, "online recover", root_key.error());

  mp::MpControlClient client{*cfg};
  const auto lookup = client.recover_account_lookup(root_key.value());
  if (!lookup.has_value())
    return fail_mp_error(io, "online recover", lookup.error());

  auto device_seed = mp::CleansedSeed::generate();
  if (!device_seed.has_value())
    return fail_mp_error(io, "online recover", device_seed.error());
  auto device_key = mp::Ed25519SigningKey::from_seed(device_seed.value().bytes());
  if (!device_key.has_value())
    return fail_mp_error(io, "online recover", device_key.error());

  auto cwt = mint_online_device_cwt(root_key.value(), device_key.value().public_key(),
                                    client.clock_offset_seconds());
  if (!cwt.has_value())
    return fail_mp_error(io, "online recover", cwt.error());

  mp::MpIdentityState identity{};
  identity.root_seed = std::move(root_seed);
  identity.device_seed = std::move(device_seed).value();
  identity.account_id = lookup.value().account_id;
  identity.handle = lookup.value().handle;
  identity.authority = cfg->authority;
  identity.device_cwt = cwt.value();
  client.set_identity(identity);

  const auto enrolled = client.enroll_device(mp::EnrollDeviceRequest{
      .device_pubkey = device_key.value().public_key(),
      .device_label = device_label,
      .device_cwt = std::move(cwt).value(),
  });
  if (!enrolled.has_value())
    return fail_mp_error(io, "online recover", enrolled.error());

  identity.device_id = enrolled.value().device_id;
  auto saved = mp::MpIdentityStore::save(*state_dir, identity);
  if (!saved.has_value())
    return fail_mp_error(io, "online recover", saved.error());

  const auto root_sha = online_pubkey_sha256_hex(root_key.value().public_key());
  if (!root_sha.has_value())
    return fail_mp_error(io, "online recover", root_sha.error());

  io.err << "Recovered @" << lookup.value().handle << " (account #"
         << lookup.value().account_id.to_decimal() << ", new device #"
         << enrolled.value().device_id.to_decimal() << ")\n"
         << "Safety Number: " << lookup.value().safety_number << "\n";
  bool has_active_prior = false;
  for (const auto &d : lookup.value().devices) {
    if (!d.revoked_at_ms.has_value()) {
      if (!has_active_prior) {
        io.err << "Existing active devices (revoke a lost device with "
                  "`blackbird online devices revoke <id>`):\n";
        has_active_prior = true;
      }
      io.err << "  - #" << d.device_id.to_decimal() << " ("
             << escape_terminal_display(d.label) << ")\n";
    }
  }
  io.err << std::flush;

  return emit_json(
      io, Value::object({
              {"recovered", Value{true}},
              {"account_id", Value{Number{lookup.value().account_id.value()}}},
              {"device_id", Value{Number{enrolled.value().device_id.value()}}},
              {"handle", Value{lookup.value().handle}},
              {"authority", Value{cfg->authority}},
              {"root_pubkey_sha256", Value{root_sha.value()}},
              {"safety_number", Value{lookup.value().safety_number}},
              {"cwt_expires_ms", Value{Number{enrolled.value().cwt_expires_ms}}},
              {"devices", Value{online_devices_to_json(lookup.value().devices)}},
          }));
}

int run_online_cli(std::span<char *> args, CliIo io) {
  if (args.size() < 2) {
    return fail_usage(
        io, "online: expected action (health|register|whoami|resolve|devices|friends|"
            "party|web-approve|recovery-key|export-mpkey|recover)");
  }
  const std::string_view action{args[1]};
  if (action == "--help" || action == "-h") {
    io.err
        << "usage: blackbird online "
           "{health|register|whoami|resolve|devices|friends|party|web-approve|"
           "recovery-key|export-mpkey|recover} [options]\n"
           "  devices: blackbird online devices {init|install-cwt|enroll|revoke|link} "
           "[options]\n"
           "  link:    blackbird online devices link {create|join|approve} [options]\n"
           "  friends: blackbird online friends "
           "{list|add|accept|deny|remove|block} <handle|account_id> [options]\n";
    return 0;
  }
  if (action == "health")
    return run_online_health(args, io);
  if (action == "register")
    return run_online_register(args, io);
  if (action == "whoami")
    return run_online_whoami(args, io);
  if (action == "resolve")
    return run_online_resolve(args, io);
  if (action == "devices")
    return run_online_devices(args, io);
  if (action == "friends")
    return run_online_friends(args, io);
  if (action == "party")
    return run_online_party(args, io);
  if (action == "web-approve")
    return run_online_web_approve(args, io);
  if (action == "recovery-key")
    return run_online_recovery_key(args, io);
  if (action == "export-mpkey")
    return run_online_export_mpkey(args, io);
  if (action == "recover")
    return run_online_recover(args, io);
  return fail_usage(io, "online: unknown action: " + std::string{action});
}

int run_upgrade_cli(std::span<char *> args, CliIo io) {
  UpgradeConfig cfg{};
#ifdef BLACKBIRD_VERSION_STRING
  cfg.current_version_string = BLACKBIRD_VERSION_STRING;
#endif
  bool restart_after = false;
  bool json_out = false;

  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird upgrade [--check] [--no-ask|-y|--yes] "
                "[--version vX.Y.Z|latest] [--prefix DIR] [--base-url URL] "
                "[--force] [--restart] [--json] [--help]\n";
      return 0;
    }
    if (arg == "--check") {
      cfg.check_only = true;
    } else if (arg == "--no-ask" || arg == "--yes" || arg == "-y") {
      cfg.no_ask = true;
    } else if (arg == "--force") {
      cfg.force = true;
    } else if (arg == "--restart") {
      restart_after = true;
    } else if (arg == "--json") {
      json_out = true;
    } else if (arg == "--version") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.version = std::move(*v);
    } else if (arg == "--prefix") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.prefix = fs::path{std::move(*v)};
    } else if (arg == "--base-url") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.base_url = std::move(*v);
    } else {
      return fail_usage(io, "upgrade: unknown option: " + std::string{arg});
    }
  }

  const bool tty_err = ::isatty(STDERR_FILENO) != 0;
  bool last_was_cr = false;
  auto on_progress = [&](const UpgradeProgress &p) {
    if (json_out)
      return;
    const std::string line = format_upgrade_progress_line(p);
    if (tty_err && p.stage == UpgradeStage::downloading) {
      io.err << '\r' << line << "   " << std::flush;
      last_was_cr = true;
    } else {
      if (last_was_cr) {
        io.err << '\n';
        last_was_cr = false;
      }
      io.err << line << '\n' << std::flush;
    }
  };

  auto clear_cr = [&] {
    if (last_was_cr) {
      io.err << '\n' << std::flush;
      last_was_cr = false;
    }
  };

  if (cfg.check_only) {
    const auto checked = check_for_upgrade(cfg, on_progress);
    clear_cr();
    if (!checked.has_value())
      return fail_error(io, "upgrade", checked.error());
    const UpgradeCheckResult &c = checked.value();
    if (json_out) {
      return emit_json(
          io, Value::object({
                  {"target", Value{c.target}},
                  {"current_version", Value{c.current_version}},
                  {"current_commit", Value{c.current_commit}},
                  {"latest_version", Value{c.latest_version}},
                  {"latest_commit", Value{c.latest_commit}},
                  {"asset_name", Value{c.asset_name}},
                  {"expected_sha256", Value{c.expected_sha256}},
                  {"expected_size_bytes", Value{Number{c.expected_size_bytes}}},
                  {"update_available", Value{c.update_available}},
              }));
    }
    if (!c.update_available && !cfg.force) {
      io.out << "Blackbird is already up to date ("
             << (c.latest_version.empty() ? c.latest_commit : c.latest_version) << ", "
             << c.target << ").\n";
      return 0;
    }
    const fs::path display_prefix =
        cfg.prefix.empty()
            ? (std::getenv("HOME") != nullptr ? fs::path{std::getenv("HOME")} / ".local"
                                              : fs::path{"~/.local"})
            : cfg.prefix;
    io.out
        << format_upgrade_prompt_summary(c, display_prefix)
        << "\nRun `blackbird upgrade` (or `blackbird upgrade --no-ask`) to install.\n";
    return 0;
  }

  auto confirm = [&](const UpgradeCheckResult &c) -> bool {
    clear_cr();
    const fs::path display_prefix =
        cfg.prefix.empty()
            ? (std::getenv("HOME") != nullptr ? fs::path{std::getenv("HOME")} / ".local"
                                              : fs::path{"~/.local"})
            : cfg.prefix;
    io.err
        << format_upgrade_prompt_summary(c, display_prefix)
        << "\nProceed with download, SHA-256 verification, and atomic install? [y/N]: "
        << std::flush;
    std::string reply;
    if (!std::getline(io.in, reply))
      return false;
    while (!reply.empty() &&
           (reply.back() == '\r' || reply.back() == ' ' || reply.back() == '\t')) {
      reply.pop_back();
    }
    std::size_t start = 0;
    while (start < reply.size() && (reply[start] == ' ' || reply[start] == '\t'))
      ++start;
    std::string norm;
    for (std::size_t i = start; i < reply.size(); ++i) {
      norm.push_back(
          static_cast<char>(std::tolower(static_cast<unsigned char>(reply[i]))));
    }
    return norm == "y" || norm == "yes";
  };

  const auto res = perform_upgrade(cfg, on_progress, confirm);
  clear_cr();
  if (!res.has_value())
    return fail_error(io, "upgrade", res.error());
  const UpgradeResult &r = res.value();

  if (json_out) {
    return emit_json(
        io, Value::object({
                {"upgraded", Value{r.upgraded}},
                {"already_up_to_date", Value{r.already_up_to_date}},
                {"cancelled_by_user", Value{r.cancelled_by_user}},
                {"target", Value{r.check.target}},
                {"latest_version", Value{r.check.latest_version}},
                {"latest_commit", Value{r.check.latest_commit}},
                {"installed_binary", Value{r.installed_binary.string()}},
                {"generation_dir", Value{r.generation_dir.string()}},
                {"installed_version_output", Value{r.installed_version_output}},
            }));
  }

  if (r.already_up_to_date) {
    io.out << "Blackbird is already up to date ("
           << (r.check.latest_version.empty() ? r.check.latest_commit
                                              : r.check.latest_version)
           << ", " << r.check.target << ").\n";
    return 0;
  }
  if (r.cancelled_by_user) {
    io.out << "Upgrade cancelled; existing installation untouched.\n";
    return 0;
  }
  io.out << "Upgraded Blackbird to " << r.check.latest_version << " (" << r.check.target
         << ")\n"
         << "  Binary:     " << r.installed_binary.string() << "\n"
         << "  Version:    " << r.installed_version_output << "\n"
         << "  Generation: " << r.generation_dir.string() << "\n";

  if (restart_after && !r.installed_binary.empty()) {
    io.err << "Restarting into " << r.installed_binary.string() << "...\n"
           << std::flush;
    std::string bin_path = r.installed_binary.string();
    char *exec_argv[] = {bin_path.data(), nullptr};
    ::execv(bin_path.c_str(), exec_argv);
    return fail_message(io, "upgrade: failed to execv upgraded binary (errno=" +
                                std::to_string(errno) + ")");
  }
  return 0;
}

int run_doctor_cli(std::span<char *> args, CliIo io) {
  DoctorConfig cfg{};
#ifdef BLACKBIRD_VERSION_STRING
  cfg.current_version_string = BLACKBIRD_VERSION_STRING;
#endif
  OnlineCommonOpts online_opts{};
  bool json_out = false;
  if (const char *env_relay = std::getenv("BLACKBIRD_ONLINE_RELAY_URL");
      env_relay != nullptr && env_relay[0] != '\0') {
    cfg.relay_url = env_relay;
  }

  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string_view arg{args[i]};
    if (arg == "--help" || arg == "-h") {
      io.err << "usage: blackbird doctor [--offline] [--no-update-check] [--json] "
                "[--state-dir DIR] [--authority HOST] [--connect-host HOST] [--port N] "
                "[--ca-bundle PATH] [--relay-url URL] [--relay-connect-host HOST] "
                "[--relay-port N] [--prefix DIR] [--base-url URL] "
                "[--party-socket PATH] [--help]\n";
      return 0;
    }
    if (arg == "--offline") {
      cfg.offline = true;
      continue;
    }
    if (arg == "--no-update-check") {
      cfg.check_update = false;
      continue;
    }
    if (arg == "--json") {
      json_out = true;
      continue;
    }
    if (arg == "--relay-url") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.relay_url = std::move(*v);
      continue;
    }
    if (arg == "--relay-connect-host") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_host_arg(*v))
        return fail_usage(io, "doctor: invalid --relay-connect-host");
      cfg.relay_connect_host = std::move(*v);
      continue;
    }
    if (arg == "--relay-port") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      const auto parsed = parse_u64(*v);
      if (!parsed.has_value() || *parsed == 0U || *parsed > 65535U)
        return fail_usage(io, "doctor: --relay-port must be between 1 and 65535");
      cfg.relay_port = static_cast<std::uint16_t>(*parsed);
      continue;
    }
    if (arg == "--prefix") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_path_arg(*v, /*require_filename=*/false))
        return fail_usage(io, "doctor: invalid --prefix path");
      cfg.install_prefix = fs::path{std::move(*v)};
      continue;
    }
    if (arg == "--base-url") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      cfg.upgrade_base_url = std::move(*v);
      continue;
    }
    if (arg == "--party-socket") {
      auto v = take_flag_value(args, i, arg, io);
      if (!v.has_value())
        return 2;
      if (!valid_online_path_arg(*v, /*require_filename=*/true))
        return fail_usage(io, "doctor: invalid --party-socket path");
      cfg.party_socket_path = fs::path{std::move(*v)};
      continue;
    }
    const int common = parse_online_common_flag(args, i, online_opts, true, io);
    if (common == 1)
      continue;
    if (common == 2)
      return 2;
    return fail_usage(io, "doctor: unknown option: " + std::string{arg});
  }

  if (online_opts.state_dir.has_value()) {
    cfg.online_state_dir = *online_opts.state_dir;
  } else if (const char *env_dir = std::getenv("BLACKBIRD_ONLINE_DIR");
             env_dir != nullptr && env_dir[0] != '\0') {
    if (!valid_online_path_arg(env_dir, /*require_filename=*/false))
      return fail_usage(io, "doctor: invalid BLACKBIRD_ONLINE_DIR path");
    cfg.online_state_dir = strip_trailing_slashes_party(fs::path{env_dir});
  }

  const auto client_cfg = resolve_online_client_config(online_opts, "", io);
  if (!client_cfg.has_value())
    return 2;
  cfg.mp_client_config = *client_cfg;
  if (cfg.mp_client_config.ca_bundle_path.has_value())
    cfg.relay_ca_bundle_path = cfg.mp_client_config.ca_bundle_path;

  const DoctorReport report = run_blackbird_doctor(cfg);
  if (json_out) {
    const int rc = emit_json(io, doctor_report_to_json(report));
    if (rc != 0)
      return rc;
    return report.healthy ? 0 : 1;
  }
  io.out << format_doctor_report_human(report);
  return report.healthy ? 0 : 1;
}

std::filesystem::path default_lan_state_dir() {
  if (const char *xdg = std::getenv("XDG_CONFIG_HOME");
      xdg != nullptr && xdg[0] != '\0') {
    return fs::path{xdg} / "blackbird" / "lan";
  }
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
    return fs::path{home} / ".config" / "blackbird" / "lan";
  }
  return fs::path{".blackbird"} / "lan";
}

std::filesystem::path default_lan_known_peers_path() {
  if (const char *xdg = std::getenv("XDG_CONFIG_HOME");
      xdg != nullptr && xdg[0] != '\0') {
    return fs::path{xdg} / "blackbird" / "known_peers.json";
  }
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
    return fs::path{home} / ".config" / "blackbird" / "known_peers.json";
  }
  return fs::path{".blackbird"} / "known_peers.json";
}

std::optional<fs::path> default_lan_online_state_dir_passive() {
  if (const char *env_dir = std::getenv("BLACKBIRD_ONLINE_DIR");
      env_dir != nullptr && env_dir[0] != '\0') {
    return fs::path{env_dir};
  }
  if (const char *xdg = std::getenv("XDG_CONFIG_HOME");
      xdg != nullptr && xdg[0] != '\0') {
    return fs::path{xdg} / "blackbird" / "online";
  }
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
    return fs::path{home} / ".config" / "blackbird" / "online";
  }
  return std::nullopt;
}

bool confirm_lan_peer_trust_cli(const lan::LanPeerTrustPrompt &prompt, CliIo io) {
  io.err << "\nUnpinned LAN " << (prompt.is_host ? "host" : "peer") << ":\n"
         << "  Name:          " << party_chat_sanitize(prompt.display_name, 48) << "\n"
         << "  Safety Number: " << prompt.safety_number << "\n";
  if (!prompt.source_addr.empty()) {
    io.err << "  Address:       " << party_chat_sanitize(prompt.source_addr, 64)
           << "\n";
  }
  io.err << "Verify this Safety Number out-of-band and trust/pin this peer? [y/N]: "
         << std::flush;
  std::string reply;
  if (!std::getline(io.in, reply))
    return false;
  while (!reply.empty() &&
         (reply.back() == '\r' || reply.back() == ' ' || reply.back() == '\t')) {
    reply.pop_back();
  }
  std::size_t s = 0U;
  while (s < reply.size() && (reply[s] == ' ' || reply[s] == '\t'))
    ++s;
  std::string norm;
  for (std::size_t i = s; i < reply.size(); ++i) {
    norm.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(reply[i]))));
  }
  return norm == "y" || norm == "yes";
}

int run_lan_cli(std::span<char *> args, CliIo io) {
  if (args.size() < 2U) {
    io.err << "usage: blackbird lan {status|scan|host|join} [options]\n";
    return 2;
  }
  const std::string_view sub{args[1]};
  if (sub == "--help" || sub == "-h" || sub == "help") {
    io.err
        << "usage: blackbird lan {status|scan|host|join} [options]\n"
           "  status [--json] [--lan-dir DIR]\n"
           "  scan   [--timeout 1..60] [--json]\n"
           "  host   [--name NAME] [--require-pin] [--pin-stdin] [--timeout 1..1800] "
           "[--no-mdns] [--lan-dir DIR] [--display-name NAME]\n"
           "  join   <lobby_id|ip:port> [--host-pk B64URL] [--pin-stdin] "
           "[--scan-timeout 1..60] [--lan-dir DIR] [--display-name NAME]\n"
           "Note: PINs are read via hidden TTY prompt or --pin-stdin (never --pin on "
           "argv).\n";
    return 0;
  }

  if (sub == "status") {
    bool json_out = false;
    fs::path lan_dir = default_lan_state_dir();
    for (std::size_t i = 2U; i < args.size(); ++i) {
      const std::string_view arg{args[i]};
      if (arg == "--help" || arg == "-h") {
        io.err << "usage: blackbird lan status [--json] [--lan-dir DIR]\n";
        return 0;
      }
      if (arg == "--json") {
        json_out = true;
      } else if (arg == "--lan-dir") {
        auto v = take_flag_value(args, i, arg, io);
        if (!v.has_value())
          return 2;
        lan_dir = fs::path{std::move(*v)};
      } else {
        return fail_usage(io, "lan status: unknown option: " + std::string{arg});
      }
    }
    const auto policy_res = lan::load_effective_lan_policy();
    if (!policy_res.has_value()) {
      return fail_error(io, "lan status", policy_res.error());
    }
    const lan::LanPolicyConfig &pol = policy_res.value();
    std::error_code ec;
    const bool has_lan_id = fs::exists(lan_dir / "identity.json", ec);
    if (json_out) {
      return emit_json(
          io, Value::object({
                  {"disabled", Value{pol.disabled}},
                  {"require_pin", Value{pol.require_pin}},
                  {"require_local_auth", Value{pol.require_local_auth}},
                  {"idle_timeout_sec",
                   Value{Number{static_cast<std::uint64_t>(pol.idle_timeout_sec)}}},
                  {"scan_timeout_sec",
                   Value{Number{static_cast<std::uint64_t>(pol.scan_timeout_sec)}}},
                  {"lan_state_dir", Value{lan_dir.string()}},
                  {"local_lan_identity_present", Value{has_lan_id}},
              }));
    }
    io.out << "LAN Party (mp1-lan/1) — strictly opt-in (zero sockets open):\n"
           << "  Status:            "
           << (pol.disabled ? "DISABLED (policy/env kill-switch)"
                            : "available (opt-in)")
           << "\n"
           << "  Require PIN:       " << (pol.require_pin ? "yes" : "no") << "\n"
           << "  Require OS Auth:   " << (pol.require_local_auth ? "yes" : "no") << "\n"
           << "  Host Idle Timeout: " << pol.idle_timeout_sec << "s (cap 1800s)\n"
           << "  Scan Timeout:      " << pol.scan_timeout_sec << "s (cap 60s)\n"
           << "  Local Identity:    "
           << (has_lan_id ? "present" : "created on first use") << " ("
           << lan_dir.string() << ")\n";
    return 0;
  }

  if (sub == "scan") {
    lan::LanScanConfig scfg{};
    bool json_out = false;
    for (std::size_t i = 2U; i < args.size(); ++i) {
      const std::string_view arg{args[i]};
      if (arg == "--help" || arg == "-h") {
        io.err << "usage: blackbird lan scan [--timeout 1..60] [--json]\n";
        return 0;
      }
      if (arg == "--json") {
        json_out = true;
      } else if (arg == "--timeout") {
        auto v = take_flag_value(args, i, arg, io);
        if (!v.has_value())
          return 2;
        const auto parsed = parse_u64(*v);
        if (!parsed.has_value() || *parsed < 1U ||
            *parsed > lan::kMaxLanScanTimeoutSec) {
          return fail_usage(io, "lan scan: --timeout must be between 1 and 60");
        }
        scfg.scan_timeout_sec = static_cast<std::uint32_t>(*parsed);
      } else {
        return fail_usage(io, "lan scan: unknown option: " + std::string{arg});
      }
    }
    if (!json_out) {
      io.err << "Scanning local network for _mp1-lan._udp.local. lobbies (up to "
             << scfg.scan_timeout_sec << "s)...\n"
             << std::flush;
    }
    const auto found = lan::scan_lan_lobbies(scfg);
    if (!found.has_value()) {
      return fail_error(io, "lan scan", found.error());
    }
    if (json_out) {
      Value::Array arr;
      for (const auto &item : found.value()) {
        Value::Array targets;
        for (const auto &t : item.direct_targets)
          targets.push_back(Value{t});
        arr.push_back(Value::object({
            {"lan_party_id", Value{item.lobby.beacon.lan_party_id}},
            {"name", Value{item.lobby.beacon.lobby_name}},
            {"host", Value{item.lobby.beacon.host_name}},
            {"host_pubkey_b64url",
             Value{encode_lan_pubkey_base64url(item.lobby.beacon.host_pubkey)}},
            {"safety_number", Value{item.safety_number}},
            {"pin_required", Value{item.lobby.beacon.require_pin}},
            {"direct_targets", Value{std::move(targets)}},
        }));
      }
      return emit_json(
          io, Value::object({
                  {"lobbies", Value{std::move(arr)}},
                  {"count",
                   Value{Number{static_cast<std::uint64_t>(found.value().size())}}},
              }));
    }
    if (found.value().empty()) {
      io.out << "No LAN Party lobbies found.\n";
      return 0;
    }
    io.out << "Discovered LAN Party lobbies (" << found.value().size() << "):\n";
    for (const auto &item : found.value()) {
      io.out << "  id=" << item.lobby.beacon.lan_party_id << "  name=\""
             << party_chat_sanitize(item.lobby.beacon.lobby_name, 32)
             << "\"  host=" << party_chat_sanitize(item.lobby.beacon.host_name, 32)
             << (item.lobby.beacon.require_pin ? "  [PIN]" : "  [open]") << "\n"
             << "    safety: " << item.safety_number << "\n";
      if (!item.direct_targets.empty()) {
        io.out << "    direct: " << item.direct_targets.front() << "\n";
      }
    }
    return 0;
  }

  if (sub == "host") {
    std::string lobby_name = "blackbird-lan";
    std::string display_name;
    fs::path lan_dir = default_lan_state_dir();
    bool require_pin = false;
    bool pin_stdin = false;
    bool enable_mdns = true;
    std::uint32_t idle_timeout_sec = lan::kDefaultLanIdleTimeoutSec;
    for (std::size_t i = 2U; i < args.size(); ++i) {
      const std::string_view arg{args[i]};
      if (arg == "--help" || arg == "-h") {
        io.err
            << "usage: blackbird lan host [--name NAME] [--require-pin] [--pin-stdin] "
               "[--timeout 1..1800] [--no-mdns] [--lan-dir DIR] "
               "[--display-name NAME]\n";
        return 0;
      }
      if (arg == "--pin" || arg.starts_with("--pin=")) {
        return fail_usage(io, "lan host: refusing --pin on argv (secrets must never be "
                              "passed via CLI args; use --require-pin or --pin-stdin)");
      }
      if (arg == "--name") {
        auto v = take_flag_value(args, i, arg, io);
        if (!v.has_value())
          return 2;
        lobby_name = std::move(*v);
      } else if (arg == "--display-name") {
        auto v = take_flag_value(args, i, arg, io);
        if (!v.has_value())
          return 2;
        display_name = std::move(*v);
      } else if (arg == "--lan-dir") {
        auto v = take_flag_value(args, i, arg, io);
        if (!v.has_value())
          return 2;
        lan_dir = fs::path{std::move(*v)};
      } else if (arg == "--require-pin") {
        require_pin = true;
      } else if (arg == "--pin-stdin") {
        require_pin = true;
        pin_stdin = true;
      } else if (arg == "--no-mdns") {
        enable_mdns = false;
      } else if (arg == "--timeout") {
        auto v = take_flag_value(args, i, arg, io);
        if (!v.has_value())
          return 2;
        const auto parsed = parse_u64(*v);
        if (!parsed.has_value() || *parsed < 1U ||
            *parsed > lan::kMaxLanIdleTimeoutSec) {
          return fail_usage(io, "lan host: --timeout must be between 1 and 1800");
        }
        idle_timeout_sec = static_cast<std::uint32_t>(*parsed);
      } else {
        return fail_usage(io, "lan host: unknown option: " + std::string{arg});
      }
    }

    const auto policy_res = lan::load_effective_lan_policy();
    if (!policy_res.has_value())
      return fail_error(io, "lan host", policy_res.error());
    if (policy_res.value().disabled)
      return fail_message(io,
                          "lan host: LAN mode is disabled by policy or environment");
    const bool need_pin = require_pin || policy_res.value().require_pin;

    std::string pin_buf;
    struct CleanseStr {
      std::string &s;
      ~CleanseStr() {
        if (!s.empty()) {
          OPENSSL_cleanse(s.data(), s.size());
          s.clear();
        }
      }
    } pin_guard{pin_buf};
    if (need_pin) {
      if (!read_secret_line_bounded(
              io,
              ReadSecretLineOpts{.prompt = "Enter LAN Party room PIN: ",
                                 .max_bytes = lan::kLanPinMaxBytes,
                                 .force_stdin = pin_stdin},
              pin_buf) ||
          pin_buf.empty()) {
        return fail_message(io, "lan host: room PIN is required");
      }
    }

    auto id_res = lan::load_or_create_lan_identity(lan::LanIdentityRequest{
        .online_state_dir = default_lan_online_state_dir_passive(),
        .lan_state_dir = lan_dir,
        .preferred_display_name = display_name,
    });
    if (!id_res.has_value())
      return fail_error(io, "lan host", id_res.error());

    lan::LanHostConfig hcfg{};
    hcfg.identity = std::move(id_res).value();
    hcfg.lobby_name = lobby_name;
    hcfg.pin = pin_buf;
    hcfg.require_pin = need_pin;
    hcfg.idle_timeout_sec = idle_timeout_sec;
    hcfg.enable_mdns = enable_mdns;
    hcfg.known_peers_path = default_lan_known_peers_path();
    hcfg.trust_callback = [io](const lan::LanPeerTrustPrompt &prompt) {
      return confirm_lan_peer_trust_cli(prompt, io);
    };

    auto host_res = lan::LanPartyHost::start(std::move(hcfg));
    if (!host_res.has_value())
      return fail_error(io, "lan host", host_res.error());
    lan::LanPartyHost host = std::move(host_res).value();

    io.out << "Hosting LAN Party \"" << party_chat_sanitize(host.lobby_name(), 32)
           << "\" (id=" << host.lan_party_id() << ")\n"
           << "  Safety Number: " << host.safety_number() << "\n"
           << "  PIN Required:  " << (host.pin_required() ? "yes" : "no") << "\n"
           << "  Idle Timeout:  " << host.effective_idle_timeout_sec() << "s\n";
    const std::string pk_b64u = encode_lan_pubkey_base64url(host.host_pubkey());
    for (const auto &dt : host.direct_targets()) {
      io.out << "  Direct Join:   blackbird lan join " << dt << " --host-pk " << pk_b64u
             << "\n";
    }
    io.out << "Type chat lines (or /lock, /members, /quit; Ctrl+C stops hosting).\n"
           << std::flush;

    FlightDeckSignalGuard sig_guard{};
    const bool stdin_tty = (&io.in == &std::cin) && (::isatty(STDIN_FILENO) != 0);
    std::string input_buf;
    while (host.active() && g_flightdeck_stop == 0) {
      (void)host.pump_once(50U);
      for (const auto &ev : host.drain_events()) {
        if (ev.kind == lan::LanEventKind::member_joined) {
          io.out << "[join] " << party_chat_sanitize(ev.sender_name, 32) << " ("
                 << ev.safety_number << ")\n"
                 << std::flush;
        } else if (ev.kind == lan::LanEventKind::member_left) {
          io.out << "[left] " << party_chat_sanitize(ev.sender_name, 32) << "\n"
                 << std::flush;
        } else if (ev.kind == lan::LanEventKind::chat_received && ev.chat.has_value()) {
          io.out << "[" << party_chat_sanitize(ev.sender_name, 32) << "] "
                 << party_chat_sanitize(ev.chat->body, 1024) << "\n"
                 << std::flush;
        } else if (ev.kind == lan::LanEventKind::lobby_timed_out) {
          io.out << "[lan] Host idle timeout reached with no peers; stopped.\n"
                 << std::flush;
        } else if (ev.kind == lan::LanEventKind::lobby_pin_locked_out) {
          io.out << "[lan] Lobby locked out due to repeated invalid PIN attempts.\n"
                 << std::flush;
        }
      }
      if (stdin_tty) {
        pollfd pfd{STDIN_FILENO, POLLIN, 0};
        if (::poll(&pfd, 1U, 0) > 0 && (pfd.revents & POLLIN) != 0) {
          char chunk[512];
          const ssize_t n = ::read(STDIN_FILENO, chunk, sizeof(chunk));
          if (n <= 0)
            break;
          input_buf.append(chunk, static_cast<std::size_t>(n));
          std::size_t nl = 0;
          while ((nl = input_buf.find('\n')) != std::string::npos) {
            std::string line = input_buf.substr(0, nl);
            input_buf.erase(0, nl + 1U);
            if (!line.empty() && line.back() == '\r')
              line.pop_back();
            if (line == "/quit" || line == "/exit") {
              host.stop();
              break;
            }
            if (line == "/lock") {
              (void)host.lock_lobby();
              io.out << "[lan] Lobby locked (mDNS stopped; current members kept).\n"
                     << std::flush;
            } else if (line == "/members") {
              io.out << "[lan] Members (" << host.members().size() << "):\n";
              for (const auto &m : host.members()) {
                io.out << "  - " << party_chat_sanitize(m.display_name, 32)
                       << (m.is_host ? " [host]" : " [member]") << "\n";
              }
              io.out << std::flush;
            } else if (!line.empty()) {
              (void)host.send_chat(line);
            }
          }
        }
      }
    }
    host.stop();
    return 0;
  }

  if (sub == "join") {
    std::string target;
    std::string host_pk_b64u;
    std::string display_name;
    fs::path lan_dir = default_lan_state_dir();
    bool pin_stdin = false;
    std::uint32_t scan_timeout_sec = lan::kDefaultLanScanTimeoutSec;
    for (std::size_t i = 2U; i < args.size(); ++i) {
      const std::string_view arg{args[i]};
      if (arg == "--help" || arg == "-h") {
        io.err << "usage: blackbird lan join <lobby_id|ip:port> [--host-pk B64URL] "
                  "[--pin-stdin] [--scan-timeout 1..60] [--lan-dir DIR] "
                  "[--display-name NAME]\n";
        return 0;
      }
      if (arg == "--pin" || arg.starts_with("--pin=")) {
        return fail_usage(io,
                          "lan join: refusing --pin on argv (use interactive prompt "
                          "or --pin-stdin)");
      }
      if (arg == "--host-pk") {
        auto v = take_flag_value(args, i, arg, io);
        if (!v.has_value())
          return 2;
        host_pk_b64u = std::move(*v);
      } else if (arg == "--display-name") {
        auto v = take_flag_value(args, i, arg, io);
        if (!v.has_value())
          return 2;
        display_name = std::move(*v);
      } else if (arg == "--lan-dir") {
        auto v = take_flag_value(args, i, arg, io);
        if (!v.has_value())
          return 2;
        lan_dir = fs::path{std::move(*v)};
      } else if (arg == "--pin-stdin") {
        pin_stdin = true;
      } else if (arg == "--scan-timeout") {
        auto v = take_flag_value(args, i, arg, io);
        if (!v.has_value())
          return 2;
        const auto parsed = parse_u64(*v);
        if (!parsed.has_value() || *parsed < 1U ||
            *parsed > lan::kMaxLanScanTimeoutSec) {
          return fail_usage(io, "lan join: --scan-timeout must be between 1 and 60");
        }
        scan_timeout_sec = static_cast<std::uint32_t>(*parsed);
      } else if (arg.starts_with('-')) {
        return fail_usage(io, "lan join: unknown option: " + std::string{arg});
      } else if (target.empty()) {
        target = std::string{arg};
      } else {
        return fail_usage(io, "lan join: unexpected extra argument");
      }
    }
    if (target.empty())
      return fail_usage(io, "lan join: <lobby_id|ip:port> is required");

    const auto policy_res = lan::load_effective_lan_policy();
    if (!policy_res.has_value())
      return fail_error(io, "lan join", policy_res.error());
    if (policy_res.value().disabled)
      return fail_message(io,
                          "lan join: LAN mode is disabled by policy or environment");

    lan::LanClientConfig ccfg{};
    bool need_pin = policy_res.value().require_pin || pin_stdin;

    if (const auto direct = parse_lan_direct_target(target); direct.has_value()) {
      if (host_pk_b64u.empty()) {
        return fail_usage(io, "lan join: direct ip:port requires --host-pk <b64url>");
      }
      const auto decoded_pk = decode_lan_pubkey_base64url(host_pk_b64u);
      if (!decoded_pk.has_value())
        return fail_usage(io, "lan join: invalid --host-pk base64url");
      ccfg.host_pubkey = decoded_pk.value();
      ccfg.host_addrs.push_back(direct.value());
    } else {
      lan::LanScanConfig scfg{};
      scfg.scan_timeout_sec = scan_timeout_sec;
      scfg.stop_when = [&](const std::vector<lan::DiscoveredLanLobbyInfo> &list) {
        for (const auto &it : list) {
          if (it.lobby.beacon.lan_party_id == target)
            return true;
        }
        return false;
      };
      const auto scanned = lan::scan_lan_lobbies(scfg);
      if (!scanned.has_value())
        return fail_error(io, "lan join", scanned.error());
      const lan::DiscoveredLanLobbyInfo *match = nullptr;
      for (const auto &it : scanned.value()) {
        if (it.lobby.beacon.lan_party_id == target) {
          match = &it;
          break;
        }
      }
      if (match == nullptr) {
        return fail_message(io, "lan join: lobby '" + party_chat_sanitize(target, 32) +
                                    "' not found on LAN");
      }
      ccfg.host_pubkey = match->lobby.beacon.host_pubkey;
      ccfg.host_addrs = match->lobby.addrs;
      ccfg.expected_lan_party_id = match->lobby.beacon.lan_party_id;
      ccfg.expected_host_name = match->lobby.beacon.host_name;
      need_pin = need_pin || match->lobby.beacon.require_pin;
    }

    std::string pin_buf;
    struct CleanseStr {
      std::string &s;
      ~CleanseStr() {
        if (!s.empty()) {
          OPENSSL_cleanse(s.data(), s.size());
          s.clear();
        }
      }
    } pin_guard{pin_buf};
    if (need_pin) {
      if (!read_secret_line_bounded(
              io,
              ReadSecretLineOpts{.prompt = "Enter LAN Party room PIN: ",
                                 .max_bytes = lan::kLanPinMaxBytes,
                                 .force_stdin = pin_stdin},
              pin_buf) ||
          pin_buf.empty()) {
        return fail_message(io, "lan join: room PIN is required");
      }
    }

    auto id_res = lan::load_or_create_lan_identity(lan::LanIdentityRequest{
        .online_state_dir = default_lan_online_state_dir_passive(),
        .lan_state_dir = lan_dir,
        .preferred_display_name = display_name,
    });
    if (!id_res.has_value())
      return fail_error(io, "lan join", id_res.error());

    ccfg.identity = std::move(id_res).value();
    ccfg.pin = pin_buf;
    ccfg.known_peers_path = default_lan_known_peers_path();
    ccfg.trust_callback = [io](const lan::LanPeerTrustPrompt &prompt) {
      return confirm_lan_peer_trust_cli(prompt, io);
    };

    auto client_res = lan::LanPartyClient::join(std::move(ccfg));
    if (!client_res.has_value())
      return fail_error(io, "lan join", client_res.error());
    lan::LanPartyClient client = std::move(client_res).value();

    FlightDeckSignalGuard sig_guard{};
    const bool stdin_tty = (&io.in == &std::cin) && (::isatty(STDIN_FILENO) != 0);
    std::string input_buf;
    while (client.state() != lan::LanSessionState::stopped &&
           client.state() != lan::LanSessionState::rejected &&
           client.state() != lan::LanSessionState::disconnected &&
           g_flightdeck_stop == 0) {
      (void)client.pump_once(50U);
      for (const auto &ev : client.drain_events()) {
        if (ev.kind == lan::LanEventKind::connected) {
          io.out << "[lan] Connected to \""
                 << party_chat_sanitize(client.lobby_name(), 32)
                 << "\" (members=" << client.members().size() << "). Type chat lines "
                 << "(or /quit).\n"
                 << std::flush;
        } else if (ev.kind == lan::LanEventKind::welcome_rejected) {
          io.err << "[lan] Join rejected: " << party_chat_sanitize(ev.reason, 64)
                 << "\n"
                 << std::flush;
        } else if (ev.kind == lan::LanEventKind::chat_received && ev.chat.has_value()) {
          io.out << "[" << party_chat_sanitize(ev.sender_name, 32) << "] "
                 << party_chat_sanitize(ev.chat->body, 1024) << "\n"
                 << std::flush;
        } else if (ev.kind == lan::LanEventKind::disconnected) {
          io.out << "[lan] Disconnected.\n" << std::flush;
        }
      }
      if (stdin_tty && client.connected()) {
        pollfd pfd{STDIN_FILENO, POLLIN, 0};
        if (::poll(&pfd, 1U, 0) > 0 && (pfd.revents & POLLIN) != 0) {
          char chunk[512];
          const ssize_t n = ::read(STDIN_FILENO, chunk, sizeof(chunk));
          if (n <= 0)
            break;
          input_buf.append(chunk, static_cast<std::size_t>(n));
          std::size_t nl = 0;
          while ((nl = input_buf.find('\n')) != std::string::npos) {
            std::string line = input_buf.substr(0, nl);
            input_buf.erase(0, nl + 1U);
            if (!line.empty() && line.back() == '\r')
              line.pop_back();
            if (line == "/quit" || line == "/exit") {
              client.stop();
              break;
            }
            if (!line.empty())
              (void)client.send_chat(line);
          }
        }
      }
    }
    const bool rejected = (client.state() == lan::LanSessionState::rejected);
    client.stop();
    return rejected ? 1 : 0;
  }

  return fail_usage(io, "lan: unknown subcommand: " + std::string{sub});
}

int run_brakes_cli(std::span<char *> args, CliIo io) {
  std::string_view sub = "status";
  bool json_out = false;
  std::size_t idx = 1U;
  if (idx < args.size()) {
    const std::string_view first{args[idx]};
    if (!first.starts_with('-')) {
      sub = first;
      ++idx;
    }
  }
  for (; idx < args.size(); ++idx) {
    const std::string_view arg{args[idx]};
    if (arg == "--json") {
      json_out = true;
    } else if (arg == "--help" || arg == "-h") {
      io.out << "Usage:\n"
                "  blackbird brakes [status|probe] [--json]\n"
                "Inspect unified Brakes policy floor (/etc/multiplayer/policy.toml +\n"
                "~/.config/blackbird/policy.toml) and OS kernel containment backend.\n";
      return 0;
    } else {
      return fail_usage(io, "brakes: unknown option: " + std::string{arg});
    }
  }

  if (sub != "status" && sub != "probe") {
    return fail_usage(io, "brakes: unknown subcommand: " + std::string{sub});
  }

  const auto caps = sandbox::probe_os_sandbox_capabilities();
  const auto pol = brakes::load_effective_policy();

  if (sub == "probe") {
    Value::Array caveats;
    for (const auto &c : caps.caveats) {
      caveats.emplace_back(c);
    }
    if (json_out) {
      const int rc = emit_json(
          io, Value::object({
                  {"platform", Value{caps.platform}},
                  {"available", Value{caps.available}},
                  {"backend", Value{caps.backend_name}},
                  {"landlock_abi_version",
                   Value{Number{static_cast<std::int64_t>(caps.landlock_abi_version)}}},
                  {"supports_network_airgap", Value{caps.supports_network_airgap}},
                  {"caveats", Value{std::move(caveats)}},
              }));
      if (rc != 0)
        return rc;
    } else {
      io.out << "OS Sandbox Probe\n"
             << "  Platform:       " << caps.platform << '\n'
             << "  Available:      " << (caps.available ? "yes" : "no") << '\n'
             << "  Backend:        " << caps.backend_name << '\n';
      if (caps.landlock_abi_version > 0) {
        io.out << "  Landlock ABI:   v" << caps.landlock_abi_version << '\n';
      }
      io.out << "  Network Airgap: " << (caps.supports_network_airgap ? "yes" : "no")
             << '\n';
      for (const auto &c : caps.caveats) {
        io.out << "  Caveat:         " << c << '\n';
      }
    }
    return caps.available ? 0 : 1;
  }

  if (!pol.has_value()) {
    return fail_error(io, "brakes", pol.error());
  }
  const auto &eff = pol.value();

  if (json_out) {
    return emit_json(
        io,
        Value::object({
            {"effective_profile",
             Value{std::string{brakes::brakes_profile_name(eff.effective_profile)}}},
            {"min_profile",
             Value{std::string{brakes::brakes_profile_name(eff.brakes.min_profile)}}},
            {"default_profile", Value{std::string{brakes::brakes_profile_name(
                                    eff.brakes.default_profile)}}},
            {"allow_escalation", Value{eff.brakes.allow_escalation}},
            {"require_local_auth_for_escalation",
             Value{eff.brakes.require_local_auth_for_escalation}},
            {"system_policy_loaded", Value{eff.system_policy_loaded}},
            {"user_policy_loaded", Value{eff.user_policy_loaded}},
            {"clamped_to_system_floor", Value{eff.clamped_to_system_floor}},
            {"party_trust_max_default",
             Value{std::string{brakes::party_trust_profile_name(
                 eff.party_trust.max_default_profile)}}},
            {"party_trust_max_external_guest",
             Value{std::string{brakes::party_trust_profile_name(
                 eff.party_trust.max_external_guest_profile)}}},
            {"sandbox_available", Value{caps.available}},
            {"sandbox_backend", Value{caps.backend_name}},
            {"sandbox_network_airgap", Value{caps.supports_network_airgap}},
        }));
  }

  io.out << "Blackbird Brakes & Containment\n"
         << "  Effective Profile: "
         << brakes::brakes_profile_name(eff.effective_profile)
         << (eff.clamped_to_system_floor ? " (clamped to system floor)" : "") << '\n'
         << "  System Floor:      "
         << (eff.system_policy_loaded
                 ? std::string{brakes::brakes_profile_name(eff.brakes.min_profile)} +
                       " (/etc/multiplayer/policy.toml)"
                 : "none (default black-flag YOLO)")
         << '\n'
         << "  User Policy:       " << (eff.user_policy_loaded ? "loaded" : "default")
         << '\n'
         << "  Party Trust Cap:   "
         << brakes::party_trust_profile_name(eff.party_trust.max_default_profile)
         << " (external guest cap: "
         << brakes::party_trust_profile_name(eff.party_trust.max_external_guest_profile)
         << ")\n"
         << "  OS Sandbox:        " << caps.backend_name << " ("
         << (caps.available ? "ready" : "unavailable")
         << (caps.supports_network_airgap ? ", airgap-ready" : "") << ")\n";
  return 0;
}

std::optional<std::string> find_executable_on_path(std::string_view exe) {
  const char *raw_path = std::getenv("PATH");
  if (raw_path == nullptr || raw_path[0] == '\0')
    return std::nullopt;
  std::string_view rem{raw_path};
  while (!rem.empty()) {
    const std::size_t sep = rem.find(':');
    const std::string_view dir =
        sep == std::string_view::npos ? rem : rem.substr(0U, sep);
    if (!dir.empty()) {
      std::error_code ec;
      const fs::path cand = fs::path{dir} / std::string{exe};
      if (fs::exists(cand, ec) && !fs::is_directory(cand, ec) &&
          ::access(cand.c_str(), X_OK) == 0) {
        return cand.string();
      }
    }
    if (sep == std::string_view::npos)
      break;
    rem.remove_prefix(sep + 1U);
  }
  return std::nullopt;
}

int run_superpowers_cli(std::span<char *> args, CliIo io) {
  std::string_view sub = "status";
  bool json_out = false;
  std::size_t idx = 1U;
  if (idx < args.size()) {
    const std::string_view first{args[idx]};
    if (!first.starts_with('-')) {
      sub = first;
      ++idx;
    }
  }
  for (; idx < args.size(); ++idx) {
    const std::string_view arg{args[idx]};
    if (arg == "--json") {
      json_out = true;
    } else if (arg == "--help" || arg == "-h") {
      io.out
          << "Usage:\n"
             "  blackbird superpowers [status|probe] [--json]\n"
             "Probe native zero-dependency model superpowers on this host:\n"
             "  - SQLite Workbench (ephemeral scratch + model-private DB, -safe, FTS5, "
             "JSON1)\n"
             "  - Headless Neovim MsgPack-RPC + embedded Tree-sitter AST engine\n"
             "  - Native C++23 LSP Client (installed language servers on PATH)\n"
             "  - Script Measurement & Tuning Harness (CLOCK_MONOTONIC_RAW + rusage)\n";
      return 0;
    } else {
      return fail_usage(io, "superpowers: unknown option: " + std::string{arg});
    }
  }
  if (sub != "status" && sub != "probe") {
    return fail_usage(io, "superpowers: unknown subcommand: " + std::string{sub});
  }

  const sqlite::SqliteCapabilities sql_caps =
      sqlite::probe_embedded_sqlite_capabilities();
  const arc::ArcCapabilities arc_caps = arc::probe_cpu_arc_capabilities();
  const NvimCapabilities nvim_caps = probe_nvim_capabilities();
  const JupyterCapabilities jupyter_caps = probe_jupyter_capabilities();
  const auto sandbox_caps = sandbox::probe_os_sandbox_capabilities();

  constexpr std::array<std::string_view, 4> kLspCandidates = {
      "clangd", "rust-analyzer", "lua-language-server", "pyright-langserver"};
  std::vector<std::pair<std::string, std::string>> lsp_found;
  for (std::string_view name : kLspCandidates) {
    if (const auto path = find_executable_on_path(name); path.has_value()) {
      lsp_found.emplace_back(std::string{name}, *path);
    }
  }

  if (json_out) {
    Value::Array ts_parsers;
    for (const auto &p : nvim_caps.treesitter_parsers)
      ts_parsers.emplace_back(p);
    Value::Object lsp_obj;
    for (const auto &[name, path] : lsp_found)
      lsp_obj.emplace_back(name, Value{path});
    Value::Array jup_specs;
    for (const auto &ks : jupyter_caps.kernelspecs)
      jup_specs.emplace_back(ks.name);
    return emit_json(
        io,
        Value::object({
            {"sqlite", Value::object({
                           {"available", Value{sql_caps.available}},
                           {"backend", Value{"embedded-sqlite3"}},
                           {"binary", Value{sql_caps.binary_path.string()}},
                           {"version", Value{sql_caps.version}},
                           {"safe_flag", Value{sql_caps.supports_safe_flag}},
                           {"fts5", Value{sql_caps.supports_fts5}},
                           {"json1", Value{sql_caps.supports_json1}},
                       })},
            {"cpu_arc",
             Value::object({
                 {"available", Value{arc_caps.available}},
                 {"lua_version", Value{arc_caps.lua_version}},
                 {"sqlite_version", Value{arc_caps.sqlite_version}},
                 {"fts5", Value{arc_caps.supports_fts5}},
                 {"compiled_execution", Value{arc_caps.supports_compiled_execution}},
             })},
            {"nvim_treesitter", Value::object({
                                    {"available", Value{nvim_caps.available}},
                                    {"binary", Value{nvim_caps.executable_path}},
                                    {"version", Value{nvim_caps.version_string}},
                                    {"has_treesitter", Value{nvim_caps.has_treesitter}},
                                    {"has_vim_diff", Value{nvim_caps.has_vim_diff}},
                                    {"parsers", Value{std::move(ts_parsers)}},
                                })},
            {"lsp_servers", Value::object(std::move(lsp_obj))},
            {"jupyter", Value::object({
                            {"available", Value{jupyter_caps.jupyter_available}},
                            {"binary", Value{jupyter_caps.jupyter_path}},
                            {"kernelspecs", Value{std::move(jup_specs)}},
                        })},
            {"measure_harness",
             Value::object({
                 {"available", Value{true}},
                 {"sandbox_backend", Value{sandbox_caps.backend_name}},
                 {"sandbox_available", Value{sandbox_caps.available}},
             })},
        }));
  }

  io.out << "Blackbird Model Superpowers\n"
         << "  SQLite Workbench:  "
         << (sql_caps.available
                 ? ("ready (embedded " + sql_caps.version +
                    (sql_caps.supports_fts5 ? ", FTS5" : "") +
                    (sql_caps.supports_json1 ? ", JSON1" : "") + ", authorizer)")
                 : "unavailable")
         << '\n'
         << "  Native CPU-ARC:    ready (Lua " << arc_caps.lua_version << " + SQLite "
         << arc_caps.sqlite_version << (arc_caps.supports_fts5 ? " FTS5" : "")
         << ", static O(1) compiler)\n"
         << "  Neovim Tree-sitter:"
         << (nvim_caps.available
                 ? (" ready (" + nvim_caps.version_string + ", " +
                    std::to_string(nvim_caps.treesitter_parsers.size()) + " parsers)")
                 : " unavailable (nvim not found)")
         << '\n'
         << "  Native LSP Client: ready (servers on PATH: ";
  if (lsp_found.empty()) {
    io.out << "none detected";
  } else {
    for (std::size_t i = 0; i < lsp_found.size(); ++i) {
      if (i > 0)
        io.out << ", ";
      io.out << lsp_found[i].first;
    }
  }
  io.out << ")\n"
         << "  Jupyter / .ipynb:  ready (nbformat v4 + WS v13 consumer";
  if (jupyter_caps.jupyter_available) {
    io.out << ", kernels: ";
    if (jupyter_caps.kernelspecs.empty()) {
      io.out << "none";
    } else {
      for (std::size_t i = 0; i < jupyter_caps.kernelspecs.size(); ++i) {
        if (i > 0)
          io.out << ", ";
        io.out << jupyter_caps.kernelspecs[i].name;
      }
    }
  } else {
    io.out << ", local jupyter CLI absent";
  }
  io.out << ")\n"
         << "  Measure Harness:   ready (CLOCK_MONOTONIC_RAW + wait4 rusage, sandbox="
         << sandbox_caps.backend_name << ")\n";
  return 0;
}

Value credential_metadata_to_json(const CredentialMetadata &meta) {
  Value::Array hosts;
  hosts.reserve(meta.allowed_hosts.size());
  for (const auto &h : meta.allowed_hosts)
    hosts.emplace_back(h);
  Value::Array scopes;
  scopes.reserve(meta.scopes.size());
  for (const auto &s : meta.scopes)
    scopes.emplace_back(s);
  return Value::object({
      {"id", Value{Number{meta.id.value}}},
      {"service", Value{meta.service}},
      {"account", Value{meta.account}},
      {"scheme", Value{std::string{auth_scheme_name(meta.scheme)}}},
      {"auth_header_name", Value{meta.auth_header_name}},
      {"allowed_hosts", Value{std::move(hosts)}},
      {"scopes", Value{std::move(scopes)}},
      {"active", Value{meta.active}},
      {"expired", Value{meta.expired}},
      {"has_refresh_token", Value{meta.has_refresh_token}},
      {"expires_at", Value{Number{meta.expires_at}}},
      {"updated_at", Value{Number{meta.updated_at}}},
      {"revision", Value{Number{meta.revision}}},
  });
}

std::vector<std::string>
default_hosts_for_integration_service(std::string_view service) {
  std::vector<std::string> hosts;
  auto push_unique = [&](std::string host) {
    if (host.empty())
      return;
    for (const auto &existing : hosts) {
      if (existing == host)
        return;
    }
    hosts.push_back(std::move(host));
  };
  if (const auto manifest = find_builtin_saas_pack_manifest(service);
      manifest.has_value()) {
    for (const auto &h : manifest->allowed_hosts)
      push_unique(h);
  }
  if (const auto preset = find_mcp_preset(service); preset.has_value()) {
    if (const auto parsed = net::parse_url(preset->endpoint_url); parsed.has_value())
      push_unique(parsed.value().host);
  }
  return hosts;
}

std::string_view strip_flag_value(std::string_view arg) noexcept {
  const std::size_t eq = arg.find('=');
  return eq == std::string_view::npos ? arg : arg.substr(0U, eq);
}

bool is_forbidden_secret_argv_flag(std::string_view arg) noexcept {
  const std::string_view flag = strip_flag_value(arg);
  return flag == "--token" || flag == "--secret" || flag == "--api-key" ||
         flag == "--apikey" || flag == "--password" || flag == "--bearer" ||
         flag == "--pat" || flag == "--access-token" || flag == "--refresh-token" ||
         flag == "--client-secret" || flag == "--auth" || flag == "-t" ||
         flag == "-p" || flag == "-k";
}

int run_integrations_connect(std::span<const std::string_view> sub_args, CliIo io) {
  std::string service;
  std::string account = "default";
  std::string scheme_str;
  fs::path vault_dir = default_integrations_vault_dir();
  std::vector<std::string> explicit_hosts;
  bool token_stdin = false;
  bool json_out = false;

  for (std::size_t i = 0; i < sub_args.size(); ++i) {
    const std::string_view arg = sub_args[i];
    if (is_forbidden_secret_argv_flag(arg)) {
      return fail_usage(
          io, "refusing secret on argv; supply credentials via --token-stdin");
    }
    if (arg == "--help" || arg == "-h") {
      io.out << "Usage: blackbird integrations connect <service> --token-stdin "
                "[--account NAME] [--scheme bearer_pat|discord_bot|bearer_oauth2|"
                "header_key|basic_token] [--host HOST]... [--vault-dir DIR] [--json]\n"
                "Alias: blackbird connect <service> --token-stdin ...\n"
                "Security: secrets on argv (--token/--secret/--api-key) are refused.\n";
      return 0;
    }
    if (arg == "--token-stdin") {
      token_stdin = true;
    } else if (arg == "--json") {
      json_out = true;
    } else if (arg == "--account") {
      if (i + 1 >= sub_args.size())
        return fail_usage(io, "--account requires a value");
      account = std::string{sub_args[++i]};
    } else if (arg == "--scheme") {
      if (i + 1 >= sub_args.size())
        return fail_usage(io, "--scheme requires a value");
      scheme_str = std::string{sub_args[++i]};
    } else if (arg == "--host") {
      if (i + 1 >= sub_args.size())
        return fail_usage(io, "--host requires a hostname");
      explicit_hosts.emplace_back(sub_args[++i]);
    } else if (arg == "--vault-dir") {
      if (i + 1 >= sub_args.size())
        return fail_usage(io, "--vault-dir requires a directory path");
      vault_dir = fs::path{sub_args[++i]};
    } else if (arg.starts_with('-')) {
      return fail_usage(io, "unknown flag for integrations connect: " +
                                std::string{strip_flag_value(arg)});
    } else if (service.empty()) {
      service = std::string{arg};
    } else {
      return fail_usage(io, "unexpected positional argument: " + std::string{arg});
    }
  }

  if (service.empty())
    return fail_usage(io, "integrations connect requires <service>");
  if (!token_stdin) {
    return fail_usage(
        io, "integrations connect requires --token-stdin (never pass secrets on argv)");
  }
  if (vault_dir.empty())
    return fail_message(io, "unable to resolve integrations vault directory");

  std::string raw_line;
  if (!std::getline(io.in, raw_line)) {
    return fail_usage(io, "expected credential token on stdin");
  }
  while (!raw_line.empty() && (raw_line.back() == '\r' || raw_line.back() == '\n'))
    raw_line.pop_back();
  CleansedSecret secret{raw_line};
  if (!raw_line.empty())
    ::OPENSSL_cleanse(raw_line.data(), raw_line.size());
  raw_line.clear();
  if (secret.empty())
    return fail_usage(io, "empty credential token on stdin");

  AuthScheme scheme = AuthScheme::bearer_pat;
  if (!scheme_str.empty()) {
    auto parsed = parse_auth_scheme(scheme_str);
    if (!parsed.has_value())
      return fail_usage(io, "invalid --scheme value: " + scheme_str);
    scheme = parsed.value();
  } else if (service == "discord") {
    scheme = AuthScheme::discord_bot;
  }

  std::vector<std::string> hosts = explicit_hosts.empty()
                                       ? default_hosts_for_integration_service(service)
                                       : std::move(explicit_hosts);
  if (hosts.empty()) {
    return fail_usage(io, "unknown service '" + service + "'; pass --host <hostname>");
  }

  IntegrationVaultConfig vcfg;
  vcfg.directory = vault_dir;
  IntegrationVault vault{std::move(vcfg)};

  CredentialSaveInput input;
  input.service = service;
  input.account = account;
  input.scheme = scheme;
  input.access_token = std::move(secret);
  input.allowed_hosts = std::move(hosts);
  input.set_active = true;

  auto saved = vault.save(input);
  if (!saved.has_value())
    return fail_error(io, "integrations connect", saved.error());

  const CredentialMetadata &meta = saved.value();
  if (json_out) {
    return emit_json(io, Value::object({
                             {"connected", Value{true}},
                             {"credential", credential_metadata_to_json(meta)},
                         }));
  }
  io.out << "Connected " << meta.service << " (account=" << meta.account
         << ", id=" << meta.id.value << ", scheme=" << auth_scheme_name(meta.scheme)
         << ", hosts=";
  for (std::size_t i = 0; i < meta.allowed_hosts.size(); ++i) {
    if (i > 0)
      io.out << ',';
    io.out << meta.allowed_hosts[i];
  }
  io.out << ")\n";
  return 0;
}

int run_integrations_cli(std::span<char *> args, CliIo io) {
  std::string_view sub = "status";
  std::size_t start_idx = 1U;
  if (args.size() > 1U) {
    const std::string_view first{args[1]};
    if (first == "--help" || first == "-h" || first == "help") {
      io.out << "Usage:\n"
                "  blackbird integrations [list|status] [--vault-dir DIR] [--json]\n"
                "  blackbird integrations presets [--json]\n"
                "  blackbird integrations packs [--json]\n"
                "  blackbird integrations connect <service> --token-stdin [--account "
                "NAME] [--scheme NAME] [--host HOST]... [--vault-dir DIR] [--json]\n"
                "  blackbird integrations disconnect <service> [--account NAME] [--id "
                "N] [--vault-dir DIR] [--json]\n"
                "  blackbird connect <service> --token-stdin ...\n";
      return 0;
    }
    if (!first.starts_with('-')) {
      sub = first;
      start_idx = 2U;
    }
  }

  if (sub == "connect") {
    std::vector<std::string_view> rest;
    for (std::size_t i = start_idx; i < args.size(); ++i)
      rest.emplace_back(args[i]);
    return run_integrations_connect(rest, io);
  }

  if (sub == "presets") {
    bool json_out = false;
    for (std::size_t i = start_idx; i < args.size(); ++i) {
      const std::string_view arg{args[i]};
      if (arg == "--json") {
        json_out = true;
      } else {
        return fail_usage(io, "unknown flag for integrations presets: " +
                                  std::string{strip_flag_value(arg)});
      }
    }
    const auto &presets = builtin_mcp_presets();
    if (json_out) {
      Value::Array arr;
      arr.reserve(presets.size());
      for (const auto &p : presets) {
        arr.push_back(Value::object({
            {"preset_id", Value{Number{p.preset_id.value}}},
            {"name", Value{p.name}},
            {"display_name", Value{p.display_name}},
            {"endpoint_url", Value{p.endpoint_url}},
            {"readonly_endpoint_url", Value{p.readonly_endpoint_url}},
            {"protocol_version", Value{p.protocol_version}},
            {"is_open_world", Value{p.is_open_world}},
            {"description", Value{p.description}},
        }));
      }
      return emit_json(io, Value::object({
                               {"count", Value{Number{presets.size()}}},
                               {"presets", Value{std::move(arr)}},
                           }));
    }
    io.out << "Official Remote MCP Presets (" << presets.size() << "):\n";
    for (const auto &p : presets) {
      io.out << "  " << p.name << " (" << p.display_name << ") -> " << p.endpoint_url
             << " [" << p.protocol_version << "]\n";
    }
    return 0;
  }

  if (sub == "packs") {
    bool json_out = false;
    for (std::size_t i = start_idx; i < args.size(); ++i) {
      const std::string_view arg{args[i]};
      if (arg == "--json") {
        json_out = true;
      } else {
        return fail_usage(io, "unknown flag for integrations packs: " +
                                  std::string{strip_flag_value(arg)});
      }
    }
    const auto &manifests = builtin_saas_pack_manifests();
    if (json_out) {
      Value::Array arr;
      arr.reserve(manifests.size());
      for (const auto &m : manifests) {
        Value::Array hosts;
        for (const auto &h : m.allowed_hosts)
          hosts.emplace_back(h);
        Value::Array ops;
        for (const auto &op : m.operations) {
          ops.push_back(Value::object({
              {"name", Value{op.name}},
              {"effect", Value{std::string{saas_effect_class_name(op.effect)}}},
          }));
        }
        arr.push_back(Value::object({
            {"service", Value{m.service}},
            {"display_name", Value{m.display_name}},
            {"allowed_hosts", Value{std::move(hosts)}},
            {"operations", Value{std::move(ops)}},
            {"is_open_world", Value{m.is_open_world}},
        }));
      }
      return emit_json(io, Value::object({
                               {"count", Value{Number{manifests.size()}}},
                               {"packs", Value{std::move(arr)}},
                           }));
    }
    io.out << "Builtin Lua 5.5.1 SaaS Packs (" << manifests.size() << "):\n";
    for (const auto &m : manifests) {
      io.out << "  " << m.service << " (" << m.display_name << ") hosts=[";
      for (std::size_t i = 0; i < m.allowed_hosts.size(); ++i) {
        if (i > 0)
          io.out << ',';
        io.out << m.allowed_hosts[i];
      }
      io.out << "] ops=" << m.operations.size() << '\n';
    }
    return 0;
  }

  if (sub == "list" || sub == "status") {
    fs::path vault_dir = default_integrations_vault_dir();
    bool json_out = false;
    for (std::size_t i = start_idx; i < args.size(); ++i) {
      const std::string_view arg{args[i]};
      if (arg == "--json") {
        json_out = true;
      } else if (arg == "--vault-dir") {
        if (i + 1 >= args.size())
          return fail_usage(io, "--vault-dir requires a directory path");
        vault_dir = fs::path{args[++i]};
      } else {
        return fail_usage(io, "unknown flag for integrations " + std::string{sub} +
                                  ": " + std::string{strip_flag_value(arg)});
      }
    }

    // Strictly passive zero-disk-write check when vault store does not exist yet.
    std::vector<CredentialMetadata> creds;
    bool store_present = false;
    if (!vault_dir.empty()) {
      IntegrationVaultConfig vcfg;
      vcfg.directory = vault_dir;
      IntegrationVault vault{std::move(vcfg)};
      std::error_code ec;
      store_present = fs::exists(vault.store_path(), ec) && !ec;
      if (store_present) {
        auto listed = vault.list();
        if (!listed.has_value())
          return fail_error(io, "integrations list", listed.error());
        creds = std::move(listed.value());
      }
    }

    const auto &presets = builtin_mcp_presets();
    const auto &packs = builtin_saas_pack_manifests();
    if (json_out) {
      Value::Array connected;
      connected.reserve(creds.size());
      for (const auto &c : creds)
        connected.push_back(credential_metadata_to_json(c));
      return emit_json(io, Value::object({
                               {"vault_dir", Value{vault_dir.string()}},
                               {"vault_present", Value{store_present}},
                               {"connected_count", Value{Number{creds.size()}}},
                               {"connected", Value{std::move(connected)}},
                               {"mcp_presets_count", Value{Number{presets.size()}}},
                               {"saas_packs_count", Value{Number{packs.size()}}},
                           }));
    }

    io.out << "Blackbird Integrations:\n"
           << "  Connected accounts: " << creds.size() << '\n';
    for (const auto &c : creds) {
      io.out << "    [" << c.id.value << "] " << c.service << " (" << c.account
             << ") scheme=" << auth_scheme_name(c.scheme)
             << (c.active ? " [active]" : "") << (c.expired ? " [expired]" : "")
             << '\n';
    }
    io.out << "  Official MCP presets: " << presets.size()
           << " (use `blackbird integrations presets`)\n"
           << "  Builtin SaaS packs:   " << packs.size()
           << " (use `blackbird integrations packs`)\n";
    return 0;
  }

  if (sub == "disconnect") {
    std::string service;
    std::string account;
    std::optional<std::uint64_t> id_opt;
    fs::path vault_dir = default_integrations_vault_dir();
    bool json_out = false;
    for (std::size_t i = start_idx; i < args.size(); ++i) {
      const std::string_view arg{args[i]};
      if (arg == "--json") {
        json_out = true;
      } else if (arg == "--account") {
        if (i + 1 >= args.size())
          return fail_usage(io, "--account requires a value");
        account = std::string{args[++i]};
      } else if (arg == "--id") {
        if (i + 1 >= args.size())
          return fail_usage(io, "--id requires an integer");
        const auto parsed = parse_u64(args[++i]);
        if (!parsed.has_value() || *parsed == 0U)
          return fail_usage(io, "invalid --id value");
        id_opt = *parsed;
      } else if (arg == "--vault-dir") {
        if (i + 1 >= args.size())
          return fail_usage(io, "--vault-dir requires a directory path");
        vault_dir = fs::path{args[++i]};
      } else if (arg.starts_with('-')) {
        return fail_usage(io, "unknown flag for integrations disconnect: " +
                                  std::string{arg});
      } else if (service.empty()) {
        service = std::string{arg};
      } else {
        return fail_usage(io, "unexpected positional argument: " + std::string{arg});
      }
    }
    if (!id_opt.has_value() && service.empty())
      return fail_usage(io, "integrations disconnect requires <service> or --id N");
    if (vault_dir.empty())
      return fail_message(io, "unable to resolve integrations vault directory");

    IntegrationVaultConfig vcfg;
    vcfg.directory = vault_dir;
    IntegrationVault vault{std::move(vcfg)};
    std::error_code ec;
    if (!fs::exists(vault.store_path(), ec) || ec)
      return fail_message(io, "no connected integrations found");

    CredentialId target_id{};
    if (id_opt.has_value()) {
      target_id = CredentialId{*id_opt};
    } else {
      auto found = vault.find(ServiceAccountKey{service, account});
      if (!found.has_value())
        return fail_error(io, "integrations disconnect", found.error());
      target_id = found.value().id;
    }

    auto removed = vault.remove(target_id);
    if (!removed.has_value())
      return fail_error(io, "integrations disconnect", removed.error());

    if (json_out) {
      return emit_json(io, Value::object({
                               {"disconnected", Value{true}},
                               {"id", Value{Number{target_id.value}}},
                               {"service", Value{service}},
                           }));
    }
    io.out << "Disconnected integration credential id=" << target_id.value;
    if (!service.empty())
      io.out << " (" << service << ")";
    io.out << '\n';
    return 0;
  }

  return fail_usage(io, "unknown integrations subcommand: " + std::string{sub});
}

int run_connect_alias_cli(std::span<char *> args, CliIo io) {
  std::vector<std::string_view> rest;
  for (std::size_t i = 1U; i < args.size(); ++i)
    rest.emplace_back(args[i]);
  return run_integrations_connect(rest, io);
}

} // namespace

bool is_command_post_subcommand(std::string_view arg) noexcept {
  return arg == "mcp" || arg == "platoon" || arg == "issues" || arg == "memory" ||
         arg == "peer" || arg == "capabilities" || arg == "metrics" ||
         arg == "bridge" || arg == "join" || arg == "party" || arg == "flightdeck" ||
         arg == "online" || arg == "upgrade" || arg == "doctor" || arg == "lan" ||
         arg == "brakes" || arg == "superpowers" || arg == "integrations" ||
         arg == "connect";
}

int command_post_cli(int argc, char **argv, std::istream &in, std::ostream &out,
                     std::ostream &err) {
  CliIo io{in, out, err};
  if (argc <= 0 || argv == nullptr)
    return fail_usage(io, "expected subcommand");

  const std::span<char *> args{argv, static_cast<std::size_t>(argc)};
  const std::string_view subcommand{args[0]};

  try {
    if (subcommand == "mcp")
      return run_mcp_cli(args, io);
    if (subcommand == "platoon")
      return run_platoon_cli(args, io);
    if (subcommand == "issues")
      return run_issues_cli(args, io);
    if (subcommand == "memory")
      return run_memory_cli(args, io);
    if (subcommand == "peer")
      return run_peer_cli(args, io);
    if (subcommand == "capabilities")
      return run_capabilities_cli(args, io);
    if (subcommand == "metrics")
      return run_metrics_cli(args, io);
    if (subcommand == "bridge")
      return run_bridge_cli(args, io);
    if (subcommand == "join")
      return run_join_cli(args, io);
    if (subcommand == "party")
      return run_party_cli(args, io);
    if (subcommand == "flightdeck")
      return run_flightdeck_cli(args, io);
    if (subcommand == "online")
      return run_online_cli(args, io);
    if (subcommand == "upgrade")
      return run_upgrade_cli(args, io);
    if (subcommand == "doctor")
      return run_doctor_cli(args, io);
    if (subcommand == "lan")
      return run_lan_cli(args, io);
    if (subcommand == "brakes")
      return run_brakes_cli(args, io);
    if (subcommand == "superpowers")
      return run_superpowers_cli(args, io);
    if (subcommand == "integrations")
      return run_integrations_cli(args, io);
    if (subcommand == "connect")
      return run_connect_alias_cli(args, io);
    return fail_usage(io, "unknown subcommand: " + std::string{subcommand});
  } catch (const Error &e) {
    return fail_error(io, subcommand, e);
  } catch (const std::exception &) {
    return fail_message(io, "command failed with unexpected error");
  }
}

} // namespace blackbird
