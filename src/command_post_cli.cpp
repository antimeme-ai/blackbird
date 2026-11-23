#include "blackbird/command_post_cli.hpp"

#include "blackbird/capabilities.hpp"
#include "blackbird/issues.hpp"
#include "blackbird/json.hpp"
#include "blackbird/mcp_server.hpp"
#include "blackbird/metrics_consumer.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/platoon_runner.hpp"
#include "blackbird/project_memory.hpp"
#include "blackbird/value.hpp"
#include "blackbird/worktree_lease.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <istream>
#include <limits>
#include <map>
#include <optional>
#include <ostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

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
    io.err << "blackbird peer: HOME is unset; pass --root DIR\n";
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
                "[--allow-root DIR]... [--max-peers N] [--max-line-bytes N] "
                "[--working-root DIR] [--session-root DIR] [--executable PATH]\n";
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
  fs::path board_dir = fs::path{".blackbird"} / "board";
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
  fs::path board_dir = fs::path{".blackbird"} / "board";
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
  fs::path board_dir = fs::path{".blackbird"} / "board";
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
  fs::path board_dir = fs::path{".blackbird"} / "board";
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
            : to_absolute_preserving_segments(fs::path{".blackbird"} / "board");
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
  fs::path board_dir = fs::path{".blackbird"} / "board";
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
  fs::path board_dir = fs::path{".blackbird"} / "board";
  std::string peer_id;
  int grace_ms = kDefaultStopGraceMs;

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
  bool signaled = false;
  if (valid_signalable_pid(member.pid)) {
    const auto target_pid = static_cast<pid_t>(member.pid);
    const pid_t self_pid = ::getpid();
    const pid_t self_pgid = ::getpgrp();
    const pid_t target_pgid = ::getpgid(target_pid);
    if (target_pid > 1 && target_pid != self_pid && target_pgid != -1 &&
        target_pgid != self_pgid && pid_alive_local(member.pid)) {
      const pid_t kill_target = (target_pgid == target_pid) ? -target_pid : target_pid;
      if (::kill(kill_target, SIGTERM) == 0)
        signaled = true;

      const auto deadline =
          std::chrono::steady_clock::now() + std::chrono::milliseconds{grace_ms};
      while (pid_alive_local(member.pid) &&
             std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
      }
      if (pid_alive_local(member.pid)) {
        const pid_t cur_pgid = ::getpgid(target_pid);
        if (cur_pgid != -1 && cur_pgid != self_pgid) {
          const pid_t force_target =
              (cur_pgid == target_pid) ? -target_pid : target_pid;
          (void)::kill(force_target, SIGKILL);
        }
      }
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

  if (parsed.value().find("grant_id") != nullptr) {
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

} // namespace

bool is_command_post_subcommand(std::string_view arg) noexcept {
  return arg == "mcp" || arg == "platoon" || arg == "issues" || arg == "memory" ||
         arg == "peer" || arg == "capabilities" || arg == "metrics";
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
    return fail_usage(io, "unknown subcommand: " + std::string{subcommand});
  } catch (const Error &e) {
    return fail_error(io, subcommand, e);
  } catch (const std::exception &) {
    return fail_message(io, "command failed with unexpected error");
  }
}

} // namespace blackbird
