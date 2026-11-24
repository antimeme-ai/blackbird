#include "../src/native_process.hpp"
#include "blackbird/board_bridge.hpp"
#include "blackbird/capabilities.hpp"
#include "blackbird/command_post_cli.hpp"
#include "blackbird/json.hpp"
#include "blackbird/mp_client.hpp"
#include "blackbird/party_lobby.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/value.hpp"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern char **environ;

using namespace blackbird;

namespace {

namespace fs = std::filesystem;

void check(bool condition, std::string_view message) {
  if (!condition)
    throw std::runtime_error(std::string{message});
}

class TempDir {
public:
  explicit TempDir(const char *prefix) {
    const fs::path base = fs::temp_directory_path();
    std::string pattern = (base / (std::string{prefix} + "-XXXXXX")).string();
    std::vector<char> buf(pattern.begin(), pattern.end());
    buf.push_back('\0');
    char *created = ::mkdtemp(buf.data());
    check(created != nullptr, "mkdtemp failed");
    path_ = fs::canonical(fs::path{created});
  }
  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  const fs::path &path() const noexcept { return path_; }

private:
  fs::path path_;
};

struct CliResult {
  int exit_code = -1;
  std::string out;
  std::string err;
};

CliResult run_cli(std::vector<std::string> args, const std::string &stdin_data = {}) {
  std::vector<char *> argv;
  argv.reserve(args.size() + 1);
  for (auto &arg : args)
    argv.push_back(arg.data());
  argv.push_back(nullptr);

  std::istringstream in{stdin_data};
  std::ostringstream out;
  std::ostringstream err;
  const int rc =
      command_post_cli(static_cast<int>(args.size()), argv.data(), in, out, err);
  return CliResult{rc, out.str(), err.str()};
}

Value parse_stdout_json(const CliResult &res, const char *context) {
  if (res.exit_code != 0) {
    throw std::runtime_error(std::string{context} + " failed (rc=" +
                             std::to_string(res.exit_code) + "): " + res.err);
  }
  auto parsed = parse_json(res.out);
  if (!parsed.has_value())
    throw std::runtime_error(std::string{context} +
                             " emitted invalid JSON: " + res.out);
  return std::move(parsed).value();
}

const Value &req_field(const Value &obj, std::string_view key) {
  const Value *found = obj.find(key);
  check(found != nullptr, "missing expected JSON field");
  return *found;
}

const std::string &req_str(const Value &obj, std::string_view key) {
  const Value &v = req_field(obj, key);
  check(std::holds_alternative<std::string>(v.value()), "expected string field");
  return v.string();
}

std::int64_t req_int(const Value &obj, std::string_view key) {
  const Value &v = req_field(obj, key);
  check(std::holds_alternative<Number>(v.value()), "expected numeric field");
  const auto &s = v.number().storage();
  if (const auto *i = std::get_if<std::int64_t>(&s))
    return *i;
  if (const auto *u = std::get_if<std::uint64_t>(&s))
    return static_cast<std::int64_t>(*u);
  throw std::runtime_error("expected integer number");
}

void write_text_file(const fs::path &path, std::string_view content) {
  fs::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  check(static_cast<bool>(out), "failed to open file for writing");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  check(static_cast<bool>(out), "failed to write file");
}

std::string run_git_checked(const fs::path &dir, std::vector<std::string> subargs) {
  std::vector<std::string> argv;
  argv.reserve(subargs.size() + 3);
  argv.emplace_back("git");
  argv.emplace_back("-C");
  argv.emplace_back(dir.string());
  for (auto &arg : subargs)
    argv.emplace_back(std::move(arg));

  detail::Child child;
  for (char **entry = environ; entry != nullptr && *entry != nullptr; ++entry) {
    if (!std::string_view{*entry}.starts_with("GIT_"))
      child.child_environment.emplace_back(*entry);
  }
  child.child_environment.emplace_back("GIT_TERMINAL_PROMPT=0");
  child.start(std::move(argv), {}, true);
  child.close_input();
  int code = 0;
  std::string out = child.collect(detail::Clock::now() + std::chrono::seconds{30},
                                  1024 * 1024, &code);
  if (code != 0)
    throw std::runtime_error("git failed: " + out);
  return out;
}

void init_temp_repo(const fs::path &repo_dir) {
  fs::create_directories(repo_dir);
  (void)run_git_checked(repo_dir, {"init", "-b", "main"});
  (void)run_git_checked(repo_dir, {"config", "user.name", "Blackbird CLI Test"});
  (void)run_git_checked(repo_dir, {"config", "user.email", "cli@blackbird.local"});
  (void)run_git_checked(repo_dir, {"config", "commit.gpgsign", "false"});
  write_text_file(repo_dir / "README.md", "cli wiring test repo\n");
  (void)run_git_checked(repo_dir, {"add", "README.md"});
  (void)run_git_checked(repo_dir, {"commit", "-m", "initial commit"});
}

int run_fake_peer_child(int argc, char **argv) {
  Value::Array args;
  for (int i = 1; i < argc; ++i)
    args.emplace_back(std::string{argv[i]});
  const auto encoded = dump_json(Value::object({
      {"status", Value{"peer_ok"}},
      {"argv", Value{std::move(args)}},
  }));
  if (!encoded.has_value())
    return 99;
  std::cout << encoded.value() << '\n' << std::flush;
  return 0;
}

int run_sleep_child() {
  if (::setpgid(0, 0) != 0)
    return 98;
  const pid_t grandchild = ::fork();
  if (grandchild < 0)
    return 97;
  if (grandchild == 0) {
    // Grandchild stays in the child's process group and sleeps until signaled.
    for (int i = 0; i < 600; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds{100});
    return 0;
  }
  std::cout << static_cast<long long>(::getpid()) << ' '
            << static_cast<long long>(grandchild) << '\n'
            << std::flush;
  for (int i = 0; i < 600; ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
  return 0;
}

int run_party_serve_child(int argc, char **argv) {
  if (argc < 4)
    return 96;
  std::vector<std::string> owned_args = {
      "party", "serve", "--socket", argv[2], "--peers", argv[3],
  };
  std::vector<char *> cargs;
  cargs.reserve(owned_args.size() + 1);
  for (auto &a : owned_args)
    cargs.push_back(a.data());
  cargs.push_back(nullptr);
  return command_post_cli(static_cast<int>(owned_args.size()), cargs.data(), std::cin,
                          std::cout, std::cerr);
}

struct ScopedCwd {
  fs::path previous;
  explicit ScopedCwd(const fs::path &next) : previous(fs::current_path()) {
    fs::current_path(next);
  }
  ScopedCwd(const ScopedCwd &) = delete;
  ScopedCwd &operator=(const ScopedCwd &) = delete;
  ~ScopedCwd() {
    std::error_code ec;
    fs::current_path(previous, ec);
  }
};

struct SpawnedSleepGroup {
  pid_t child = -1;
  pid_t grandchild = -1;
  int read_fd = -1;

  SpawnedSleepGroup() = default;
  SpawnedSleepGroup(const SpawnedSleepGroup &) = delete;
  SpawnedSleepGroup &operator=(const SpawnedSleepGroup &) = delete;
  ~SpawnedSleepGroup() {
    if (read_fd >= 0)
      (void)::close(read_fd);
    if (grandchild > 1)
      (void)::kill(grandchild, SIGKILL);
    if (child > 1) {
      (void)::kill(child, SIGKILL);
      int status = 0;
      (void)::waitpid(child, &status, 0);
    }
  }
};

bool wait_for_pid_exit(pid_t pid, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    int status = 0;
    const pid_t waited = ::waitpid(pid, &status, WNOHANG);
    if (waited == pid)
      return true;
    if (::kill(pid, 0) != 0)
      return true;
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
  }
  return ::kill(pid, 0) != 0;
}

void spawn_sleep_group(const fs::path &self_exe, SpawnedSleepGroup &out) {
  int pipefd[2]{-1, -1};
  check(::pipe(pipefd) == 0, "pipe failed for sleep child");
  const pid_t pid = ::fork();
  check(pid >= 0, "fork failed for sleep child");
  if (pid == 0) {
    (void)::close(pipefd[0]);
    (void)::dup2(pipefd[1], STDOUT_FILENO);
    (void)::close(pipefd[1]);
    std::string exe = self_exe.string();
    std::string flag = "--sleep-child";
    char *child_argv[] = {exe.data(), flag.data(), nullptr};
    ::execv(exe.c_str(), child_argv);
    ::_exit(127);
  }
  (void)::close(pipefd[1]);
  out.child = pid;
  out.read_fd = pipefd[0];

  std::string line;
  char ch = '\0';
  while (::read(out.read_fd, &ch, 1) == 1) {
    if (ch == '\n')
      break;
    line.push_back(ch);
  }
  (void)::close(out.read_fd);
  out.read_fd = -1;

  std::istringstream iss{line};
  long long reported_child = 0;
  long long reported_grandchild = 0;
  check(static_cast<bool>(iss >> reported_child >> reported_grandchild),
        "failed to parse sleep child pids");
  check(reported_child == static_cast<long long>(pid) && reported_grandchild > 1,
        "unexpected sleep child pid report");
  out.grandchild = static_cast<pid_t>(reported_grandchild);
}

void test_subcommand_dispatch_table() {
  for (const char *name :
       {"mcp", "platoon", "issues", "memory", "peer", "capabilities", "metrics",
        "bridge", "join", "party", "flightdeck", "online", "upgrade"}) {
    check(is_command_post_subcommand(name), "expected subcommand to be recognized");
  }
  for (const char *other : {"auth", "--version", "--application", "unknown", ""}) {
    check(!is_command_post_subcommand(other), "unexpected subcommand recognized");
  }
  const auto bad = run_cli({"unknown"});
  check(bad.exit_code != 0 && bad.out.empty() && !bad.err.empty(),
        "unknown subcommand must fail cleanly on stderr");
}

void test_mcp_subcommand(const fs::path &base) {
  const fs::path board_dir = base / "mcp-board";
  const fs::path allow_dir = base / "mcp-allow";
  fs::create_directories(allow_dir);

  const std::string stdin_rpc =
      R"({"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{}})"
      "\n"
      R"({"jsonrpc":"2.0","method":"notifications/initialized"})"
      "\n"
      R"({"jsonrpc":"2.0","id":"list-2","method":"tools/list","params":{}})"
      "\n";

  const auto res = run_cli({"mcp", "--board", board_dir.string(), "--allow-root",
                            allow_dir.string(), "--max-peers", "2",
                            "--max-total-spawns", "16", "--max-line-bytes", "65536"},
                           stdin_rpc);
  check(res.exit_code == 0, "mcp subcommand returned non-zero");

  // Verify invalid --max-total-spawns bounds fail with usage exit code 2.
  for (const char *bad_spawns : {"0", "1025"}) {
    const auto bad = run_cli(
        {"mcp", "--allow-root", allow_dir.string(), "--max-total-spawns", bad_spawns});
    check(bad.exit_code == 2 && bad.out.empty() && !bad.err.empty(),
          "out-of-range --max-total-spawns must fail with usage error");
  }

  std::istringstream iss{res.out};
  std::string line1;
  std::string line2;
  check(static_cast<bool>(std::getline(iss, line1)), "missing initialize reply");
  check(static_cast<bool>(std::getline(iss, line2)), "missing tools/list reply");
  const auto r1 = parse_json(line1);
  const auto r2 = parse_json(line2);
  check(r1.has_value() && r2.has_value(), "mcp emitted invalid JSON");
  check(req_str(r1.value(), "id") == "init-1", "mcp initialize string id mismatch");
  check(req_str(r2.value(), "id") == "list-2", "mcp tools/list string id mismatch");
  const auto &tools = req_field(req_field(r2.value(), "result"), "tools").array();
  // 4 board tools + 3 peer runner tools = 7 tools
  check(tools.size() == 7, "mcp expected 7 tools for board + runner");
}

struct PlatoonTestPaths {
  fs::path base;
  fs::path self_exe;
};

void test_platoon_subcommand(const PlatoonTestPaths &paths) {
  const fs::path &base = paths.base;
  const fs::path &self_exe = paths.self_exe;
  const fs::path board_dir = base / "platoon-board";
  const fs::path repo_dir = base / "platoon-repo";
  const fs::path leases_dir = base / "platoon-leases";
  const fs::path work_dir = base / "platoon-work";
  const fs::path sess_dir = base / "platoon-session";
  init_temp_repo(repo_dir);
  fs::create_directories(work_dir);
  fs::create_directories(sess_dir);

  // post & read
  const Value posted = parse_stdout_json(
      run_cli({"platoon", "post", "--board", board_dir.string(), "--from", "alpha",
               "--to", "dentist", "--kind", "handoff", "--text", "ready", "--ref",
               "src/command_post_cli.cpp"}),
      "platoon post");
  check(req_int(posted, "seq") == 1 && req_str(posted, "kind") == "handoff",
        "platoon post mismatch");

  const Value read =
      parse_stdout_json(run_cli({"platoon", "read", "--board", board_dir.string(),
                                 "--after-seq", "0", "--recipient", "dentist"}),
                        "platoon read");
  check(req_int(read, "count") == 1 && req_int(read, "latest_seq") == 1,
        "platoon read mismatch");

  // members upsert & list
  const Value upserted = parse_stdout_json(
      run_cli({"platoon", "members", "--board", board_dir.string(), "--upsert", "--id",
               "alpha", "--role", "builder", "--provider", "openai", "--model", "gpt-5",
               "--state", "working"}),
      "platoon members upsert");
  check(req_str(upserted, "id") == "alpha", "platoon member upsert mismatch");

  const Value members =
      parse_stdout_json(run_cli({"platoon", "members", "--board", board_dir.string()}),
                        "platoon members");
  check(req_int(members, "count") == 1, "platoon members count != 1");

  // lease-acquire, lease-list, status, lease-release, lease-reclaim
  const Value acq = parse_stdout_json(
      run_cli({"platoon", "lease-acquire", "--repo", repo_dir.string(), "--leases",
               leases_dir.string(), "--id", "wt-1", "--branch", "platoon/wt-1",
               "--owner", "alpha", "--owner-pid",
               std::to_string(static_cast<long long>(::getpid()))}),
      "platoon lease-acquire");
  check(req_str(acq, "lease_id") == "wt-1", "lease-acquire id mismatch");

  const Value lease_list =
      parse_stdout_json(run_cli({"platoon", "lease-list", "--repo", repo_dir.string(),
                                 "--leases", leases_dir.string()}),
                        "platoon lease-list");
  check(req_int(lease_list, "count") == 1, "lease-list count != 1");

  const Value status = parse_stdout_json(
      run_cli({"platoon", "status", "--board", board_dir.string(), "--repo",
               repo_dir.string(), "--leases", leases_dir.string()}),
      "platoon status");
  check(req_int(status, "member_count") == 1 && req_int(status, "lease_count") == 1,
        "platoon status counts mismatch");

  const Value released = parse_stdout_json(
      run_cli({"platoon", "lease-release", "--repo", repo_dir.string(), "--leases",
               leases_dir.string(), "--id", "wt-1"}),
      "platoon lease-release");
  check(std::get<bool>(req_field(released, "released").value()),
        "lease-release failed");

  const Value reclaimed =
      parse_stdout_json(run_cli({"platoon", "lease-reclaim", "--repo",
                                 repo_dir.string(), "--leases", leases_dir.string()}),
                        "platoon lease-reclaim");
  check(req_field(reclaimed, "reclaimed").array().empty(), "reclaimed not empty");

  // spawn, wait, stop
  const Value spawned = parse_stdout_json(run_cli({"platoon",       "spawn",
                                                   "--board",       board_dir.string(),
                                                   "--id",          "peer-1",
                                                   "--role",        "verifier",
                                                   "--provider",    "openai",
                                                   "--model",       "gpt-5",
                                                   "--prompt",      "check cli",
                                                   "--working-dir", work_dir.string(),
                                                   "--session-dir", sess_dir.string(),
                                                   "--executable",  self_exe.string(),
                                                   "--wait-ms",     "10000"}),
                                          "platoon spawn");
  check(req_str(spawned, "peer_id") == "peer-1" &&
            req_str(spawned, "state") == "completed",
        "platoon spawn did not complete cleanly");

  const Value waited =
      parse_stdout_json(run_cli({"platoon", "wait", "--board", board_dir.string(),
                                 "--id", "peer-1", "--timeout-ms", "1000"}),
                        "platoon wait");
  check(std::get<bool>(req_field(waited, "settled").value()),
        "platoon wait not settled");

  const Value stopped =
      parse_stdout_json(run_cli({"platoon", "stop", "--board", board_dir.string(),
                                 "--id", "peer-1", "--grace-ms", "500"}),
                        "platoon stop");
  check(req_str(stopped, "state") == "stopped", "platoon stop state mismatch");

  // Regression tests for int64_t -> pid_t truncation safety (#80):
  // 1. Out-of-range PIDs (> INT_MAX, e.g. 0xFFFFFFFF -> -1, 0x100000000 -> 0) must be
  //    rejected by `platoon members --pid` and `platoon lease-acquire --owner-pid`.
  for (const char *bad_pid : {"4294967295", "4294967296"}) {
    const auto bad_member =
        run_cli({"platoon", "members", "--board", board_dir.string(), "--upsert",
                 "--id", "bad-pid-member", "--pid", bad_pid});
    check(bad_member.exit_code != 0 && bad_member.out.empty() &&
              !bad_member.err.empty(),
          "out-of-range --pid must be rejected by platoon members");

    const auto bad_lease =
        run_cli({"platoon", "lease-acquire", "--repo", repo_dir.string(), "--leases",
                 leases_dir.string(), "--id", "wt-bad-pid", "--branch",
                 "platoon/wt-bad-pid", "--owner", "alpha", "--owner-pid", bad_pid});
    check(bad_lease.exit_code != 0 && bad_lease.out.empty() && !bad_lease.err.empty(),
          "out-of-range --owner-pid must be rejected by platoon lease-acquire");
  }

  // 2. If a roster record on disk already carries an out-of-range int64_t PID
  //    (4294967295 or 4294967296), `platoon stop` MUST NOT truncate and signal -1 or 0!
  auto board = PlatoonBoard::open(board_dir);
  check(board.has_value(), "PlatoonBoard::open failed for bad-pid regression test");
  for (const std::pair<const char *, std::int64_t> entry :
       std::vector<std::pair<const char *, std::int64_t>>{
           {"pid-trunc-neg1", 4294967295LL},
           {"pid-trunc-zero", 4294967296LL},
       }) {
    PlatoonMember poisoned;
    poisoned.id = entry.first;
    poisoned.role = "worker";
    poisoned.state = PlatoonMemberState::working;
    poisoned.pid = entry.second;
    check(board.value().upsert_member(poisoned).has_value(),
          "upsert poisoned roster record failed");

    const Value stop_res =
        parse_stdout_json(run_cli({"platoon", "stop", "--board", board_dir.string(),
                                   "--id", entry.first, "--grace-ms", "100"}),
                          "platoon stop out-of-range pid");
    check(req_str(stop_res, "state") == "stopped", "poisoned pid stop state mismatch");
    check(!std::get<bool>(req_field(stop_res, "signaled").value()),
          "out-of-range pid must NEVER be signaled");
  }

  // Verify default `platoon` board dir aligns with TUI `.blackbird/platoon`.
  const fs::path default_dir_sandbox = base / "platoon-default-dir";
  fs::create_directories(default_dir_sandbox);
  {
    ScopedCwd guard{default_dir_sandbox};
    const Value default_status =
        parse_stdout_json(run_cli({"platoon", "status"}), "platoon default status");
    const fs::path reported_root = fs::path{req_str(default_status, "board_root")};
    check(reported_root.filename() == "platoon" &&
              reported_root.parent_path().filename() == ".blackbird",
          "platoon default board dir must be .blackbird/platoon");
  }

  // Kimi Review #3 M6 regression tests for `platoon stop`:
  // 1. Recycled PID (member.updated_ns earlier than process start time) MUST NOT be
  //    signaled.
  // 2. Live verified PID WITHOUT `--group` signals ONLY the individual PID (grandchild
  // in
  //    same process group survives).
  // 3. Live verified PID WITH `--group` signals `-pid` (terminates entire process
  // group).
  {
    SpawnedSleepGroup proc_group;
    spawn_sleep_group(self_exe, proc_group);

    const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    PlatoonMember stale_recycled;
    stale_recycled.id = "m6-recycled";
    stale_recycled.role = "worker";
    stale_recycled.state = PlatoonMemberState::working;
    stale_recycled.pid = static_cast<std::int64_t>(proc_group.child);
    stale_recycled.updated_ns = now_ns - 60'000'000'000LL;
    check(board.value().upsert_member(stale_recycled).has_value(),
          "upsert stale recycled member failed");

    const Value recycled_res =
        parse_stdout_json(run_cli({"platoon", "stop", "--board", board_dir.string(),
                                   "--id", "m6-recycled", "--grace-ms", "100"}),
                          "platoon stop recycled pid");
    check(!std::get<bool>(req_field(recycled_res, "signaled").value()),
          "recycled PID with older updated_ns must NOT be signaled");
    check(::kill(proc_group.child, 0) == 0,
          "live process behind recycled PID must remain alive");

    // Poisoned INT64_MAX and far-future updated_ns MUST NOT overflow int64_t (UBSan)
    // or bypass recycled-PID start-time verification.
    for (const std::pair<const char *, std::int64_t> poisoned_ts :
         std::vector<std::pair<const char *, std::int64_t>>{
             {"m6-int64-max", std::numeric_limits<std::int64_t>::max()},
             {"m6-far-future", now_ns + 3600LL * 1'000'000'000LL},
         }) {
      PlatoonMember future_member;
      future_member.id = poisoned_ts.first;
      future_member.role = "worker";
      future_member.state = PlatoonMemberState::working;
      future_member.pid = static_cast<std::int64_t>(proc_group.child);
      future_member.updated_ns = poisoned_ts.second;
      check(board.value().upsert_member(future_member).has_value(),
            "upsert far-future member failed");

      const Value future_res =
          parse_stdout_json(run_cli({"platoon", "stop", "--board", board_dir.string(),
                                     "--id", poisoned_ts.first, "--grace-ms", "100"}),
                            "platoon stop poisoned updated_ns");
      check(!std::get<bool>(req_field(future_res, "signaled").value()),
            "poisoned INT64_MAX / far-future updated_ns must NOT signal process");
      check(::kill(proc_group.child, 0) == 0,
            "live process must survive poisoned updated_ns stop");
    }

    PlatoonMember live_single;
    live_single.id = "m6-single";
    live_single.role = "worker";
    live_single.state = PlatoonMemberState::working;
    live_single.pid = static_cast<std::int64_t>(proc_group.child);
    live_single.updated_ns = 0; // upsert_member stamps wall_now_ns() >= proc start time
    check(board.value().upsert_member(live_single).has_value(),
          "upsert live single member failed");

    const Value single_res =
        parse_stdout_json(run_cli({"platoon", "stop", "--board", board_dir.string(),
                                   "--id", "m6-single", "--grace-ms", "1000"}),
                          "platoon stop single pid");
    check(std::get<bool>(req_field(single_res, "signaled").value()),
          "verified live PID must be signaled");
    check(!std::get<bool>(req_field(single_res, "group").value()),
          "default platoon stop must not use --group");
    check(wait_for_pid_exit(proc_group.child, std::chrono::milliseconds{2000}),
          "signaled single PID did not exit");
    proc_group.child = -1;
    check(::kill(proc_group.grandchild, 0) == 0,
          "default platoon stop without --group must NOT kill sibling/grandchild in "
          "pgrp");
  }

  {
    SpawnedSleepGroup proc_group;
    spawn_sleep_group(self_exe, proc_group);

    PlatoonMember live_group;
    live_group.id = "m6-group";
    live_group.role = "worker";
    live_group.state = PlatoonMemberState::working;
    live_group.pid = static_cast<std::int64_t>(proc_group.child);
    live_group.updated_ns = 0;
    check(board.value().upsert_member(live_group).has_value(),
          "upsert live group member failed");

    const Value group_res = parse_stdout_json(
        run_cli({"platoon", "stop", "--board", board_dir.string(), "--id", "m6-group",
                 "--grace-ms", "1000", "--group"}),
        "platoon stop --group");
    check(std::get<bool>(req_field(group_res, "signaled").value()),
          "verified live group PID must be signaled");
    check(std::get<bool>(req_field(group_res, "group").value()),
          "platoon stop --group must report group=true");
    check(wait_for_pid_exit(proc_group.child, std::chrono::milliseconds{2000}),
          "signaled group leader did not exit");
    proc_group.child = -1;
    check(wait_for_pid_exit(proc_group.grandchild, std::chrono::milliseconds{2000}),
          "platoon stop --group must terminate grandchild in process group");
    proc_group.grandchild = -1;
  }
}

void test_issues_subcommand(const fs::path &base) {
  const fs::path root = base / "issues";

  const Value i1 =
      parse_stdout_json(run_cli({"issues", "create", "--root", root.string(), "--title",
                                 "Foundation task", "--body", "wire cli", "--kind",
                                 "task", "--priority", "1", "--label", "cli"}),
                        "issues create 1");
  const std::string id1 = req_str(i1, "id");

  const Value i2 =
      parse_stdout_json(run_cli({"issues", "create", "--root", root.string(), "--title",
                                 "Dependent task", "--kind", "bug"}),
                        "issues create 2");
  const std::string id2 = req_str(i2, "id");

  const Value dep = parse_stdout_json(
      run_cli({"issues", "dep-add", "--root", root.string(), id2, "--blocker", id1}),
      "issues dep-add");
  check(req_field(dep, "depends_on").array().size() == 1, "dep-add failed");

  const Value ready = parse_stdout_json(
      run_cli({"issues", "ready", "--root", root.string()}), "issues ready");
  check(req_int(ready, "count") == 1, "only unblocked issue should be ready");

  const Value claimed =
      parse_stdout_json(run_cli({"issues", "claim", "--root", root.string(), id1,
                                 "--actor", "cli_wiring"}),
                        "issues claim");
  check(req_str(claimed, "status") == "in_progress", "claim status mismatch");

  const Value shown = parse_stdout_json(
      run_cli({"issues", "show", "--root", root.string(), id1}), "issues show");
  check(req_str(shown, "id") == id1, "show id mismatch");

  const Value closed = parse_stdout_json(
      run_cli({"issues", "close", "--root", root.string(), id1, "--reason", "done"}),
      "issues close");
  check(req_str(closed, "status") == "closed", "close status mismatch");

  const Value listed = parse_stdout_json(
      run_cli({"issues", "list", "--root", root.string(), "--status", "closed"}),
      "issues list");
  check(req_int(listed, "count") == 1, "list closed count != 1");
}

void test_memory_subcommand(const fs::path &base) {
  const fs::path root = base / "memory";
  const fs::path repo = base / "memory-repo";
  write_text_file(repo / "src" / "note.txt", "version-1\n");

  const Value rec = parse_stdout_json(
      run_cli({"memory", "record", "--root", root.string(), "--kind", "invariant",
               "--title", "CLI outputs pure JSON", "--body",
               "All command post CLI subcommands emit JSON on stdout.", "--actor",
               "cli_wiring", "--tag", "cli", "--source", "src/note.txt", "--repo-root",
               repo.string()}),
      "memory record");
  const std::string mem_id = req_str(rec, "id");

  const Value got = parse_stdout_json(
      run_cli({"memory", "get", "--root", root.string(), mem_id}), "memory get");
  check(req_str(got, "id") == mem_id, "memory get id mismatch");

  const Value recent = parse_stdout_json(
      run_cli({"memory", "recent", "--root", root.string(), "--limit", "5"}),
      "memory recent");
  check(req_int(recent, "count") == 1, "memory recent count != 1");

  const Value recalled =
      parse_stdout_json(run_cli({"memory", "recall", "--root", root.string(), "--query",
                                 "JSON stdout", "--verify-root", repo.string()}),
                        "memory recall");
  check(req_int(recalled, "count") == 1, "memory recall count != 1");

  const Value fresh =
      parse_stdout_json(run_cli({"memory", "verify", "--root", root.string(), mem_id,
                                 "--verify-root", repo.string()}),
                        "memory verify fresh");
  check(req_str(fresh, "freshness") == "fresh", "expected fresh memory pin");

  write_text_file(repo / "src" / "note.txt", "version-2-mutated\n");
  const Value stale =
      parse_stdout_json(run_cli({"memory", "verify", "--root", root.string(), mem_id,
                                 "--verify-root", repo.string()}),
                        "memory verify stale");
  check(req_str(stale, "freshness") == "stale", "expected stale memory pin");
}

void test_peer_subcommand(const fs::path &base) {
  const fs::path alice_root = base / "peers-alice";
  const fs::path bob_root = base / "peers-bob";

  const Value alice_id = parse_stdout_json(
      run_cli({"peer", "id", "--root", alice_root.string()}), "peer id alice");
  const Value bob_id = parse_stdout_json(
      run_cli({"peer", "id", "--root", bob_root.string()}), "peer id bob");
  const std::string alice_fp = req_str(alice_id, "fingerprint");
  const std::string alice_pub = req_str(alice_id, "public_key");
  const std::string bob_fp = req_str(bob_id, "fingerprint");

  // Bob pins Alice.
  const Value pinned = parse_stdout_json(
      run_cli({"peer", "pin", "--root", bob_root.string(), "--alias", "alice",
               "--public-key", alice_pub, "--trust-note", "CLI test"}),
      "peer pin");
  check(req_str(pinned, "fingerprint") == alice_fp, "peer pin fingerprint mismatch");

  const Value listed = parse_stdout_json(
      run_cli({"peer", "list", "--root", bob_root.string()}), "peer list");
  check(req_int(listed, "peer_count") == 1, "peer list count != 1");

  // Alice signs an envelope to Bob; Bob verifies via stdin!
  const auto signed_res =
      run_cli({"peer", "sign", "--root", alice_root.string(), "--to", bob_fp, "--kind",
               "handoff", "--text", "hello bob"});
  const Value signed_env = parse_stdout_json(signed_res, "peer sign");
  check(req_str(signed_env, "from_fingerprint") == alice_fp, "signed from_fp mismatch");

  const Value verified = parse_stdout_json(
      run_cli({"peer", "verify", "--root", bob_root.string()}, signed_res.out),
      "peer verify");
  check(std::get<bool>(req_field(verified, "verified").value()), "peer verify failed");
  check(req_str(verified, "type") == "envelope", "peer verify envelope type mismatch");

  // Kimi Review #3 M7 regression tests for `peer verify`:
  // 1. Type-confused envelope carrying a spurious top-level "grant_id" MUST be
  // rejected.
  {
    const auto *obj = std::get_if<Value::Object>(&signed_env.value());
    check(obj != nullptr, "expected object for signed envelope");
    Value::Object mutated = *obj;
    mutated.emplace_back("grant_id", Value{"grant-spoof-m7"});
    auto dumped = dump_json(Value::object(std::move(mutated)));
    check(dumped.has_value(), "dump_json failed for confused envelope");
    const auto confused_res =
        run_cli({"peer", "verify", "--root", bob_root.string()}, dumped.value());
    check(confused_res.exit_code != 0 && confused_res.out.empty() &&
              !confused_res.err.empty(),
          "type-confused envelope carrying spurious grant_id must be rejected");
  }
  // 2. Partial object carrying only "grant_id" MUST be rejected.
  {
    const auto partial_res = run_cli({"peer", "verify", "--root", bob_root.string()},
                                     R"({"grant_id":"grant-partial"})");
    check(partial_res.exit_code != 0 && partial_res.out.empty() &&
              !partial_res.err.empty(),
          "partial grant_id-only object must be rejected by peer verify");
  }
  // 3. Valid grant passes strict grant schema; grant with spurious "envelope_id" fails.
  {
    const auto grant_res =
        run_cli({"bridge", "grant-issue", "--peers", alice_root.string(), "--to",
                 bob_fp, "--target-peer", "reviewer", "--mode", "direct_support",
                 "--tool", "platoon_read", "--grant-id", "grant-m7-valid"});
    const Value grant_val = parse_stdout_json(grant_res, "grant-issue for M7");

    const Value verified_grant = parse_stdout_json(
        run_cli({"peer", "verify", "--root", bob_root.string()}, grant_res.out),
        "peer verify valid grant");
    check(std::get<bool>(req_field(verified_grant, "verified").value()) &&
              req_str(verified_grant, "type") == "grant" &&
              req_str(verified_grant, "grant_id") == "grant-m7-valid",
          "peer verify valid grant mismatch");

    const auto *obj = std::get_if<Value::Object>(&grant_val.value());
    check(obj != nullptr, "expected object for signed grant");
    Value::Object mutated = *obj;
    mutated.emplace_back("envelope_id", Value{"env-spoof-m7"});
    auto dumped = dump_json(Value::object(std::move(mutated)));
    check(dumped.has_value(), "dump_json failed for confused grant");
    const auto confused_res =
        run_cli({"peer", "verify", "--root", bob_root.string()}, dumped.value());
    check(confused_res.exit_code != 0 && confused_res.out.empty() &&
              !confused_res.err.empty(),
          "type-confused grant carrying spurious envelope_id must be rejected");
  }

  // Revoke grant & revoke peer
  const Value rev_grant =
      parse_stdout_json(run_cli({"peer", "revoke-grant", "--root", bob_root.string(),
                                 "--grant-id", "grant-cli-01", "--reason", "done"}),
                        "peer revoke-grant");
  check(req_str(rev_grant, "grant_id") == "grant-cli-01", "revoke-grant mismatch");

  const Value rev_peer =
      parse_stdout_json(run_cli({"peer", "revoke-peer", "--root", bob_root.string(),
                                 "--fingerprint", alice_fp, "--reason", "rotated"}),
                        "peer revoke-peer");
  check(std::get<bool>(req_field(rev_peer, "revoked").value()), "revoke-peer failed");

  // Verification of Alice's envelope must now fail cleanly on stderr.
  const auto rejected =
      run_cli({"peer", "verify", "--root", bob_root.string()}, signed_res.out);
  check(rejected.exit_code != 0 && rejected.out.empty() && !rejected.err.empty(),
        "revoked peer envelope must be rejected");
}

void test_capabilities_subcommand(const fs::path &base) {
  const fs::path proj_dir = base / "skills";
  CapabilityCatalogConfig cfg;
  cfg.project_dir = proj_dir;
  auto opened = CapabilityCatalog::open(cfg);
  check(opened.has_value(), "CapabilityCatalog::open failed");

  CapabilityDefinition def;
  def.id = "greet-peer";
  def.kind = CapabilityKind::prompt_template;
  def.title = "Greet Peer";
  def.description = "Template greeting";
  def.body = "Hello {{name}} from {{team}}!";
  def.params.push_back(
      {"name", CapabilityParamType::string, true, std::nullopt, {}, "Peer name"});
  def.params.push_back({"team",
                        CapabilityParamType::string,
                        false,
                        std::string{"blackbird"},
                        {},
                        "Team"});
  auto saved = opened.value().save(CapabilityScope::project, def);
  check(saved.has_value(), "CapabilityCatalog::save failed");

  const Value listed =
      parse_stdout_json(run_cli({"capabilities", "list", "--project-dir",
                                 proj_dir.string(), "--no-user"}),
                        "capabilities list");
  check(req_int(listed, "total") == 1, "capabilities list total != 1");

  const Value shown =
      parse_stdout_json(run_cli({"capabilities", "show", "--project-dir",
                                 proj_dir.string(), "--no-user", "greet-peer"}),
                        "capabilities show");
  check(req_str(shown, "id") == "greet-peer", "capabilities show id mismatch");

  const Value expanded = parse_stdout_json(
      run_cli({"capabilities", "expand", "--project-dir", proj_dir.string(),
               "--no-user", "greet-peer", "--param", "name=Dentist",
               "--expected-sha256", req_str(shown, "sha256")}),
      "capabilities expand");
  check(req_str(expanded, "rendered_text") == "Hello Dentist from blackbird!",
        "capabilities expand rendered text mismatch");
  check(!std::get<bool>(req_field(expanded, "executed").value()),
        "capabilities expand must never execute");
}

void test_metrics_subcommand(const fs::path &base) {
  const fs::path jsonl = base / "metrics.jsonl";
  write_text_file(
      jsonl,
      R"({"kind":"provider_response","timestamp_ns":1000,"clock_domain":"utc_ns","provider":"openai","model":"gpt-5","ttft_ms":120.0,"total_latency_ms":450.0,"input_tokens":100,"output_tokens":50})"
      "\n"
      R"({"kind":"provider_response","timestamp_ns":2000,"clock_domain":"utc_ns","provider":"openai","model":"gpt-5","ttft_ms":180.0,"total_latency_ms":900.0,"input_tokens":200,"output_tokens":75})"
      "\n");

  const Value summary = parse_stdout_json(
      run_cli({"metrics", "summary", "--jsonl", jsonl.string()}), "metrics summary");
  check(std::get<bool>(req_field(summary, "has_data").value()),
        "metrics summary has_data false");
  const Value &ops = req_field(summary, "operations");
  check(req_int(req_field(ops, "provider_requests"), "value") == 2,
        "metrics provider_requests != 2");

  const Value spark =
      parse_stdout_json(run_cli({"metrics", "sparkline", "--jsonl", jsonl.string(),
                                 "--series", "total_latency_ms", "--width", "8"}),
                        "metrics sparkline");
  check(req_str(spark, "series") == "total_latency_ms", "sparkline series mismatch");
  const Value &sp_obj = req_field(spark, "sparkline");
  check(!req_str(sp_obj, "glyphs").empty() && req_int(sp_obj, "finite_count") == 2,
        "sparkline glyphs/count mismatch");
}

void test_bridge_subcommand(const fs::path &base) {
  const fs::path alice_peers = base / "bridge-peers-alice";
  const fs::path bob_peers = base / "bridge-peers-bob";
  const fs::path alice_bridge = base / "bridge-store-alice";
  const fs::path bob_bridge = base / "bridge-store-bob";

  const Value alice_id = parse_stdout_json(
      run_cli({"peer", "id", "--root", alice_peers.string()}), "bridge peer id alice");
  const Value bob_id = parse_stdout_json(
      run_cli({"peer", "id", "--root", bob_peers.string()}), "bridge peer id bob");
  const std::string alice_fp = req_str(alice_id, "fingerprint");
  const std::string alice_pub = req_str(alice_id, "public_key");
  const std::string bob_fp = req_str(bob_id, "fingerprint");
  const std::string bob_pub = req_str(bob_id, "public_key");

  // Out-of-band pinning on both sides.
  (void)parse_stdout_json(
      run_cli({"peer", "pin", "--root", alice_peers.string(), "--alias", "bob",
               "--public-key", bob_pub, "--trust-note", "alice->bob"}),
      "alice pins bob");
  (void)parse_stdout_json(
      run_cli({"peer", "pin", "--root", bob_peers.string(), "--alias", "alice",
               "--public-key", alice_pub, "--trust-note", "bob->alice"}),
      "bob pins alice");
  (void)parse_stdout_json(
      run_cli({"peer", "pin", "--root", bob_peers.string(), "--alias", "bob",
               "--public-key", bob_pub, "--trust-note", "bob-self"}),
      "bob pins self");

  // 1. Alice `bridge send` using alias `bob` -> emits ONE compact NDJSON line on
  // stdout.
  const auto send1 = run_cli({"bridge", "send", "--bridge", alice_bridge.string(),
                              "--peers", alice_peers.string(), "--to", "bob", "--kind",
                              "handoff", "--scope", "src/auth.cpp", "--body",
                              "Ready for Stage 0 review", "--thread", "thread-2p"});
  check(send1.exit_code == 0, "alice bridge send failed: " + send1.err);
  check(!send1.out.empty() && send1.out.back() == '\n',
        "bridge send must end with newline");
  check(send1.out.find('\n') == send1.out.size() - 1,
        "bridge send must emit exactly ONE compact NDJSON line");
  const Value env1 = parse_stdout_json(send1, "alice bridge send envelope");
  check(req_str(env1, "from_fingerprint") == alice_fp &&
            req_str(env1, "to_fingerprint") == bob_fp &&
            req_str(env1, "kind") == "handoff" &&
            req_str(env1, "thread_id") == "thread-2p",
        "bridge send envelope header mismatch");
  const Value &payload1 = req_field(env1, "payload");
  check(req_str(payload1, "body") == "Ready for Stage 0 review",
        "bridge send body mismatch");
  const Value &ev1 = req_field(payload1, "causal_event");
  check(req_int(ev1, "actor_seq") == 1 &&
            req_str(ev1, "resource_scope") == "src/auth.cpp",
        "bridge send causal_event mismatch");
  const std::string ev1_hash = req_str(ev1, "event_hash");

  // 2. Pipe Alice's NDJSON line directly into Bob `bridge receive`.
  const Value recv1 =
      parse_stdout_json(run_cli({"bridge", "receive", "--bridge", bob_bridge.string(),
                                 "--peers", bob_peers.string()},
                                send1.out),
                        "bob bridge receive");
  check(req_int(recv1, "accepted") == 1 && req_int(recv1, "duplicates") == 0 &&
            req_int(recv1, "rejected") == 0 &&
            !std::get<bool>(req_field(recv1, "incomplete_trailing_frame").value()),
        "bob bridge receive counts mismatch");
  const auto &quoted = req_field(recv1, "quoted_frames").array();
  check(quoted.size() == 1 &&
            quoted[0].string().find("UNTRUSTED FOREIGN PEER DATA ONLY") !=
                std::string::npos &&
            quoted[0].string().find("Ready for Stage 0 review") != std::string::npos,
        "bob bridge receive quoted_frames mismatch");

  // Replay of same frame is deduplicated idempotently.
  const Value recv1_dup =
      parse_stdout_json(run_cli({"bridge", "receive", "--bridge", bob_bridge.string(),
                                 "--peers", bob_peers.string()},
                                send1.out),
                        "bob bridge receive duplicate");
  check(req_int(recv1_dup, "accepted") == 0 && req_int(recv1_dup, "duplicates") == 1 &&
            req_field(recv1_dup, "quoted_frames").array().empty(),
        "duplicate frame must not emit new quoted frame");

  // 3. Bob `bridge guard` on `src/auth.cpp` is BLOCKED (exit 2).
  const auto guard_blocked =
      run_cli({"bridge", "guard", "--bridge", bob_bridge.string(), "--peers",
               bob_peers.string(), "--scope", "src/auth.cpp"});
  check(guard_blocked.exit_code == 2, "expected bridge guard exit code 2 when blocked");
  const auto guard_blocked_val = parse_json(guard_blocked.out);
  check(guard_blocked_val.has_value(), "bridge guard blocked output invalid JSON");
  check(!std::get<bool>(req_field(guard_blocked_val.value(), "allowed").value()),
        "expected allowed=false when blocked");
  const auto &blockers =
      req_field(guard_blocked_val.value(), "blocking_event_hashes").array();
  check(blockers.size() == 1 && blockers[0].string() == ev1_hash,
        "blocking_event_hashes mismatch");

  // 4. Bob `bridge receipt --stage included_in_request` requires --request-hash.
  const auto missing_req_hash = run_cli(
      {"bridge", "receipt", "--bridge", bob_bridge.string(), "--peers",
       bob_peers.string(), "--event", ev1_hash, "--stage", "included_in_request"});
  check(missing_req_hash.exit_code == 2 && missing_req_hash.out.empty() &&
            !missing_req_hash.err.empty(),
        "included_in_request without --request-hash must fail with usage error");

  const std::string req_hash = board_bridge_sha256_hex("bob-request-1");
  const auto rcpt_send =
      run_cli({"bridge", "receipt", "--bridge", bob_bridge.string(), "--peers",
               bob_peers.string(), "--event", ev1_hash, "--stage",
               "included_in_request", "--request-hash", req_hash, "--to", "alice"});
  check(rcpt_send.exit_code == 0, "bob bridge receipt failed: " + rcpt_send.err);
  check(rcpt_send.out.find('\n') == rcpt_send.out.size() - 1,
        "bridge receipt --to must emit ONE compact NDJSON line");
  (void)parse_stdout_json(rcpt_send, "bob bridge receipt envelope");

  // 5. Bob `bridge guard` on `src/auth.cpp` is now ALLOWED (exit 0).
  const auto guard_allowed =
      run_cli({"bridge", "guard", "--bridge", bob_bridge.string(), "--peers",
               bob_peers.string(), "--scope", "src/auth.cpp"});
  check(guard_allowed.exit_code == 0, "expected bridge guard exit code 0 when allowed");
  const Value guard_allowed_val =
      parse_stdout_json(guard_allowed, "bridge guard allowed");
  check(std::get<bool>(req_field(guard_allowed_val, "allowed").value()) &&
            req_field(guard_allowed_val, "blocking_event_hashes").array().empty(),
        "bridge guard allowed payload mismatch");

  // 6. Bidirectional `bridge serve`: Alice sends event #2 (with parent=ev1_hash),
  //    Bob `bridge serve` replays Bob's outbound receipt on stdout (pure NDJSON)
  //    and ingests Alice's event #2, printing JSON summary on stderr.
  const auto send2 =
      run_cli({"bridge", "send", "--bridge", alice_bridge.string(), "--peers",
               alice_peers.string(), "--to", "bob", "--kind", "review", "--scope",
               "src/auth.cpp", "--body", "Follow-up note", "--parent", ev1_hash});
  const Value env2 = parse_stdout_json(send2, "alice bridge send 2");
  check(req_int(req_field(req_field(env2, "payload"), "causal_event"), "actor_seq") ==
            2,
        "expected auto-incremented actor_seq == 2");

  const auto serve_bob = run_cli({"bridge", "serve", "--bridge", bob_bridge.string(),
                                  "--peers", bob_peers.string()},
                                 send2.out);
  check(serve_bob.exit_code == 0, "bob bridge serve failed: " + serve_bob.err);
  const auto serve_err_json = parse_json(serve_bob.err);
  check(serve_err_json.has_value(), "bridge serve stderr must be compact JSON report");
  check(req_int(serve_err_json.value(), "replayed_outbound") == 1 &&
            req_int(serve_err_json.value(), "accepted") == 1,
        "bridge serve counts mismatch");
  check(!serve_bob.out.empty() && serve_bob.out.back() == '\n',
        "bridge serve stdout must contain NDJSON outbound replay");

  // Pipe Bob's `bridge serve` stdout directly into Alice `bridge receive`.
  const Value alice_recv_rcpt =
      parse_stdout_json(run_cli({"bridge", "receive", "--bridge", alice_bridge.string(),
                                 "--peers", alice_peers.string()},
                                serve_bob.out),
                        "alice bridge receive from bob serve");
  check(req_int(alice_recv_rcpt, "accepted") == 1,
        "alice should accept bob's replayed receipt envelope");

  // 7. `bridge events --scope` + concurrent claim conflict detection.
  const auto alice_claim =
      run_cli({"bridge", "send", "--bridge", alice_bridge.string(), "--peers",
               alice_peers.string(), "--to", "bob", "--kind", "decision", "--scope",
               "src/conflict.cpp", "--body", "Alice claims conflict.cpp"});
  check(alice_claim.exit_code == 0, "alice conflict send failed");
  const auto bob_claim =
      run_cli({"bridge", "send", "--bridge", bob_bridge.string(), "--peers",
               bob_peers.string(), "--to", "alice", "--kind", "decision", "--scope",
               "src/conflict.cpp", "--body", "Bob concurrently claims conflict.cpp"});
  check(bob_claim.exit_code == 0, "bob conflict send failed");
  (void)parse_stdout_json(run_cli({"bridge", "receive", "--bridge", bob_bridge.string(),
                                   "--peers", bob_peers.string()},
                                  alice_claim.out),
                          "bob receives alice conflict");

  const Value events_res =
      parse_stdout_json(run_cli({"bridge", "events", "--bridge", bob_bridge.string(),
                                 "--scope", "src/conflict.cpp"}),
                        "bob bridge events conflict");
  check(req_int(events_res, "count") == 2 && req_int(events_res, "conflict_count") == 1,
        "bridge events should report 2 scoped events and 1 concurrent conflict");

  // 8. `bridge presence` heartbeat + signed transmission + `--list`.
  const auto pres_send =
      run_cli({"bridge", "presence", "--bridge", bob_bridge.string(), "--peers",
               bob_peers.string(), "--scope", "src/auth.cpp", "--status", "reviewing",
               "--name", "bob-op", "--ttl", "300", "--to", "alice"});
  check(pres_send.exit_code == 0, "bob bridge presence failed: " + pres_send.err);
  (void)parse_stdout_json(
      run_cli({"bridge", "receive", "--bridge", alice_bridge.string(), "--peers",
               alice_peers.string()},
              pres_send.out),
      "alice receives bob presence");

  const Value pres_list = parse_stdout_json(
      run_cli({"bridge", "presence", "--bridge", alice_bridge.string(), "--list",
               "--scope", "src/auth.cpp"}),
      "alice bridge presence --list");
  check(req_int(pres_list, "count") == 1, "expected 1 active watcher on alice bridge");
  const Value &watcher0 = req_field(pres_list, "watchers").array()[0];
  check(req_str(watcher0, "display_name") == "bob-op" &&
            req_str(watcher0, "status") == "reviewing",
        "presence watcher fields mismatch");

  // 9. `bridge grant-issue` -> `bridge grant-check` allowed -> `peer revoke-grant` ->
  //    `bridge grant-check` denied!
  const auto grant_issue = run_cli({"bridge",        "grant-issue",
                                    "--peers",       alice_peers.string(),
                                    "--to",          "bob",
                                    "--target-peer", "reviewer",
                                    "--mode",        "direct_support",
                                    "--tool",        "platoon_read",
                                    "--tool",        "platoon_post",
                                    "--max-turns",   "4",
                                    "--max-tokens",  "20000",
                                    "--ttl",         "3600",
                                    "--grant-id",    "grant-2p-01"});
  const Value grant_val = parse_stdout_json(grant_issue, "alice bridge grant-issue");
  check(req_str(grant_val, "grant_id") == "grant-2p-01" &&
            req_str(grant_val, "grantee_fingerprint") == bob_fp,
        "grant-issue output mismatch");
  const fs::path grant_path = base / "grant-2p-01.json";
  write_text_file(grant_path, grant_issue.out);

  const auto check_allowed =
      run_cli({"bridge", "grant-check", "--peers", bob_peers.string(), "--grant-file",
               grant_path.string(), "--tool", "platoon_read", "--cost", "0.10"});
  check(check_allowed.exit_code == 0,
        "expected grant-check exit 0 when allowed: " + check_allowed.err);
  const Value check_allowed_val =
      parse_stdout_json(check_allowed, "bob bridge grant-check allowed");
  check(std::get<bool>(req_field(check_allowed_val, "allowed").value()),
        "grant-check allowed field must be true");

  const auto check_wrong_tool =
      run_cli({"bridge", "grant-check", "--peers", bob_peers.string(), "--grant-file",
               grant_path.string(), "--tool", "shell_exec"});
  check(check_wrong_tool.exit_code == 2,
        "expected grant-check exit 2 for disallowed tool");
  const auto wrong_tool_val = parse_json(check_wrong_tool.out);
  check(wrong_tool_val.has_value() &&
            !std::get<bool>(req_field(wrong_tool_val.value(), "allowed").value()),
        "grant-check disallowed tool must emit allowed=false");

  (void)parse_stdout_json(
      run_cli({"peer", "revoke-grant", "--root", bob_peers.string(), "--grant-id",
               "grant-2p-01", "--reason", "finished"}),
      "bob revoke-grant");

  const auto check_revoked =
      run_cli({"bridge", "grant-check", "--peers", bob_peers.string(), "--grant-file",
               grant_path.string(), "--tool", "platoon_read"});
  check(check_revoked.exit_code == 2,
        "expected grant-check exit 2 after local revoke-grant");
  const auto revoked_val = parse_json(check_revoked.out);
  check(revoked_val.has_value() &&
            !std::get<bool>(req_field(revoked_val.value(), "allowed").value()) &&
            req_str(revoked_val.value(), "denial_code") == "conflict",
        "grant-check after revoke-grant must deny with conflict");
}

void test_bridge_checkpoint_and_join(const fs::path &base) {
  const fs::path alice_peers = base / "relay-peers-alice";
  const fs::path bob_peers = base / "relay-peers-bob";
  const fs::path charlie_peers = base / "relay-peers-charlie";
  const fs::path dave_peers = base / "relay-peers-dave";
  const fs::path mallory_peers = base / "relay-peers-mallory";
  const fs::path alice_bridge = base / "relay-bridge-alice";

  const Value alice_id = parse_stdout_json(
      run_cli({"peer", "id", "--root", alice_peers.string()}), "relay peer id alice");
  const Value bob_id = parse_stdout_json(
      run_cli({"peer", "id", "--root", bob_peers.string()}), "relay peer id bob");
  const Value mallory_id =
      parse_stdout_json(run_cli({"peer", "id", "--root", mallory_peers.string()}),
                        "relay peer id mallory");
  const std::string alice_fp = req_str(alice_id, "fingerprint");
  const std::string alice_pub = req_str(alice_id, "public_key");
  const std::string bob_pub = req_str(bob_id, "public_key");
  const std::string mallory_fp = req_str(mallory_id, "fingerprint");
  check(alice_fp != mallory_fp, "alice and mallory must have distinct fingerprints");

  // Alice pins Bob so she can emit local causal events; Bob pins Alice.
  (void)parse_stdout_json(
      run_cli({"peer", "pin", "--root", alice_peers.string(), "--alias", "bob",
               "--public-key", bob_pub, "--trust-note", "alice->bob"}),
      "relay alice pins bob");
  (void)parse_stdout_json(
      run_cli({"peer", "pin", "--root", bob_peers.string(), "--alias", "alice",
               "--public-key", alice_pub, "--trust-note", "bob->alice"}),
      "relay bob pins alice");

  // Emit 2 chained causal events + 1 revoked grant on Alice's side.
  const auto ev1_send = run_cli({"bridge", "send", "--bridge", alice_bridge.string(),
                                 "--peers", alice_peers.string(), "--to", "bob",
                                 "--scope", "src/relay.cpp", "--body", "step 1"});
  const Value ev1_env = parse_stdout_json(ev1_send, "relay bridge send 1");
  const std::string ev1_hash =
      req_str(req_field(req_field(ev1_env, "payload"), "causal_event"), "event_hash");

  const auto ev2_send =
      run_cli({"bridge", "send", "--bridge", alice_bridge.string(), "--peers",
               alice_peers.string(), "--to", "bob", "--scope", "src/relay.cpp",
               "--body", "step 2", "--parent", ev1_hash});
  const Value ev2_env = parse_stdout_json(ev2_send, "relay bridge send 2");
  const std::string ev2_hash =
      req_str(req_field(req_field(ev2_env, "payload"), "causal_event"), "event_hash");

  (void)parse_stdout_json(
      run_cli({"peer", "revoke-grant", "--root", alice_peers.string(), "--grant-id",
               "grant-cp-revoked", "--reason", "superseded"}),
      "relay alice revoke-grant");

  // 1. `bridge checkpoint` signs a checkpoint with watermarks, frontier & revocations.
  const auto cp_res =
      run_cli({"bridge", "checkpoint", "--room", "room-6b", "--checkpoint-seq", "3",
               "--bridge", alice_bridge.string(), "--peers", alice_peers.string()});
  const Value cp_val = parse_stdout_json(cp_res, "alice bridge checkpoint");
  check(req_str(cp_val, "room_id") == "room-6b" &&
            req_int(cp_val, "checkpoint_seq") == 3 &&
            req_str(cp_val, "signer_fingerprint") == alice_fp &&
            !req_str(cp_val, "signature").empty(),
        "bridge checkpoint core fields mismatch");
  const Value &watermarks = req_field(cp_val, "actor_watermarks");
  check(req_int(watermarks, alice_fp) == 2,
        "bridge checkpoint actor watermark for alice must be 2");
  const auto &frontier = req_field(cp_val, "causal_frontier_hashes").array();
  check(frontier.size() == 1 && frontier[0].string() == ev2_hash,
        "bridge checkpoint causal frontier must contain leaf ev2_hash");
  const auto &revoked_grants = req_field(cp_val, "revoked_grant_ids").array();
  check(revoked_grants.size() == 1 && revoked_grants[0].string() == "grant-cp-revoked",
        "bridge checkpoint revoked_grant_ids mismatch");

  // 2. `bridge checkpoint-verify` via stdin and via --file (valid -> exit 0).
  const auto cp_verify_stdin = run_cli(
      {"bridge", "checkpoint-verify", "--peers", bob_peers.string()}, cp_res.out);
  check(cp_verify_stdin.exit_code == 0,
        "checkpoint-verify valid stdin failed: " + cp_verify_stdin.err);
  const Value cp_verify_val =
      parse_stdout_json(cp_verify_stdin, "bob checkpoint-verify stdin");
  check(std::get<bool>(req_field(cp_verify_val, "valid").value()) &&
            req_str(cp_verify_val, "room_id") == "room-6b" &&
            req_int(cp_verify_val, "checkpoint_seq") == 3 &&
            req_str(cp_verify_val, "signer_fingerprint") == alice_fp &&
            req_int(cp_verify_val, "watermarks_count") == 1,
        "checkpoint-verify valid output fields mismatch");

  const fs::path cp_file = base / "checkpoint-6b.json";
  write_text_file(cp_file, cp_res.out);
  const auto cp_verify_file =
      run_cli({"bridge", "checkpoint-verify", "--file", cp_file.string(), "--peers",
               bob_peers.string()});
  check(cp_verify_file.exit_code == 0,
        "checkpoint-verify valid --file failed: " + cp_verify_file.err);
  const Value cp_verify_file_val =
      parse_stdout_json(cp_verify_file, "bob checkpoint-verify file");
  check(std::get<bool>(req_field(cp_verify_file_val, "valid").value()),
        "checkpoint-verify --file valid must be true");

  // 3. Tampered checkpoint -> exit 2 with valid=false.
  {
    const auto *obj = std::get_if<Value::Object>(&cp_val.value());
    check(obj != nullptr, "expected object for checkpoint");
    Value::Object tampered = *obj;
    for (auto &[k, v] : tampered) {
      if (k == "checkpoint_seq")
        v = Value{Number{std::uint64_t{99}}};
    }
    auto dumped = dump_json(Value::object(std::move(tampered)));
    check(dumped.has_value(), "dump_json failed for tampered checkpoint");

    const auto cp_bad = run_cli(
        {"bridge", "checkpoint-verify", "--peers", bob_peers.string()}, dumped.value());
    check(cp_bad.exit_code == 2, "tampered checkpoint must exit 2");
    const auto cp_bad_val = parse_json(cp_bad.out);
    check(cp_bad_val.has_value() &&
              !std::get<bool>(req_field(cp_bad_val.value(), "valid").value()),
          "tampered checkpoint must emit valid=false");
  }

  // Corrupt JSON checkpoint -> exit 2 with valid=false.
  {
    const auto cp_corrupt = run_cli(
        {"bridge", "checkpoint-verify", "--peers", bob_peers.string()}, "{not-json");
    check(cp_corrupt.exit_code == 2, "corrupt checkpoint JSON must exit 2");
    const auto cp_corrupt_val = parse_json(cp_corrupt.out);
    check(cp_corrupt_val.has_value() &&
              !std::get<bool>(req_field(cp_corrupt_val.value(), "valid").value()),
          "corrupt checkpoint JSON must emit valid=false");
  }

  // 4. `bridge invite` -> `blackbird join bbjoin1:... --alias alice`.
  const Value invite_val =
      parse_stdout_json(run_cli({"bridge", "invite", "--room", "room-6b", "--relay",
                                 "wss://relay.blackbird.local/v1", "--ttl", "3600",
                                 "--code", "code-6b", "--peers", alice_peers.string()}),
                        "alice bridge invite");
  const std::string invite_uri = req_str(invite_val, "invite_uri");
  check(invite_uri.starts_with("bbjoin1:") &&
            req_str(invite_val, "room_id") == "room-6b" &&
            req_str(invite_val, "relay_url") == "wss://relay.blackbird.local/v1" &&
            req_str(invite_val, "creator_fingerprint") == alice_fp &&
            req_int(invite_val, "expires_ns") > 0,
        "bridge invite output mismatch");

  // Also check auto-generated code when --code is omitted.
  const Value invite_auto = parse_stdout_json(
      run_cli({"bridge", "invite", "--room", "room-auto", "--relay",
               "https://relay.blackbird.local/v1", "--peers", alice_peers.string()}),
      "alice bridge invite auto-code");
  check(req_str(invite_auto, "invite_uri").starts_with("bbjoin1:"),
        "bridge invite without --code must emit bbjoin1: URI");

  // Charlie tests `--dry-run` first: validates without pinning.
  const Value dry_join =
      parse_stdout_json(run_cli({"join", invite_uri, "--alias", "alice", "--peers",
                                 charlie_peers.string(), "--dry-run"}),
                        "charlie join --dry-run");
  check(!std::get<bool>(req_field(dry_join, "joined").value()) &&
            !std::get<bool>(req_field(dry_join, "pinned").value()) &&
            req_str(dry_join, "room_id") == "room-6b" &&
            req_str(dry_join, "relay_url") == "wss://relay.blackbird.local/v1" &&
            req_str(dry_join, "creator_alias") == "alice" &&
            req_str(dry_join, "creator_fingerprint") == alice_fp,
        "join --dry-run output mismatch");

  // Charlie joins for real -> pins Alice's verified Ed25519 key cleanly.
  const Value real_join =
      parse_stdout_json(run_cli({"join", invite_uri, "--alias", "alice", "--peers",
                                 charlie_peers.string()}),
                        "charlie join");
  check(std::get<bool>(req_field(real_join, "joined").value()) &&
            std::get<bool>(req_field(real_join, "pinned").value()) &&
            req_str(real_join, "room_id") == "room-6b" &&
            req_str(real_join, "relay_url") == "wss://relay.blackbird.local/v1" &&
            req_str(real_join, "creator_alias") == "alice" &&
            req_str(real_join, "creator_fingerprint") == alice_fp,
        "join output mismatch");

  const Value charlie_list = parse_stdout_json(
      run_cli({"peer", "list", "--root", charlie_peers.string()}), "charlie peer list");
  check(req_int(charlie_list, "peer_count") == 1,
        "charlie should have exactly 1 pinned peer after join");

  // Charlie can immediately verify Alice's signed checkpoint using the pinned key!
  const auto charlie_cp_ok = run_cli(
      {"bridge", "checkpoint-verify", "--peers", charlie_peers.string()}, cp_res.out);
  check(charlie_cp_ok.exit_code == 0,
        "charlie checkpoint-verify after join failed: " + charlie_cp_ok.err);

  // 5. Reject expired invite by default; permit with --allow-expired.
  const Value expired_invite =
      parse_stdout_json(run_cli({"bridge", "invite", "--room", "room-old", "--relay",
                                 "wss://relay.blackbird.local/v1", "--expires-ns",
                                 "1000", "--peers", alice_peers.string()}),
                        "alice expired bridge invite");
  const std::string expired_uri = req_str(expired_invite, "invite_uri");

  const auto join_expired = run_cli(
      {"join", expired_uri, "--alias", "alice", "--peers", dave_peers.string()});
  check(join_expired.exit_code != 0 && join_expired.out.empty() &&
            !join_expired.err.empty(),
        "expired invite must be rejected by blackbird join");

  const Value join_expired_ok =
      parse_stdout_json(run_cli({"join", expired_uri, "--alias", "alice", "--peers",
                                 dave_peers.string(), "--allow-expired"}),
                        "dave join --allow-expired");
  check(std::get<bool>(req_field(join_expired_ok, "joined").value()) &&
            std::get<bool>(req_field(join_expired_ok, "pinned").value()),
        "join --allow-expired must succeed");

  // 6. Reject silent key swap for an already-pinned alias with ErrorCode::conflict!
  const Value mallory_invite = parse_stdout_json(
      run_cli({"bridge", "invite", "--room", "room-evil", "--relay",
               "wss://relay.blackbird.local/v1", "--peers", mallory_peers.string()}),
      "mallory bridge invite");
  const auto key_swap =
      run_cli({"join", req_str(mallory_invite, "invite_uri"), "--alias", "alice",
               "--peers", charlie_peers.string()});
  check(key_swap.exit_code != 0 && key_swap.out.empty() &&
            key_swap.err.find("conflict") != std::string::npos,
        "silent key swap for existing alias must be rejected with conflict");

  // Confirm Charlie's pinned `alice` key is still Alice's fingerprint.
  const Value charlie_after =
      parse_stdout_json(run_cli({"peer", "list", "--root", charlie_peers.string()}),
                        "charlie peer list after key swap");
  const auto &peers_arr = req_field(charlie_after, "peers").array();
  check(peers_arr.size() == 1 && req_str(peers_arr[0], "fingerprint") == alice_fp,
        "pinned alice fingerprint must remain unchanged after rejected key swap");

  // 7. Regression tests (#140): read-only absent-dir zero-creation invariants &
  //    explicit empty `--code ""` rejection.
  {
    const fs::path absent_peers = base / "absent-peers-verify";
    const auto verify_absent = run_cli(
        {"bridge", "checkpoint-verify", "--peers", absent_peers.string()}, cp_res.out);
    check(verify_absent.exit_code == 2,
          "checkpoint-verify with absent --peers must exit 2");
    const auto verify_absent_val = parse_json(verify_absent.out);
    check(verify_absent_val.has_value() &&
              !std::get<bool>(req_field(verify_absent_val.value(), "valid").value()),
          "checkpoint-verify with absent --peers must emit valid=false");
    check(!fs::exists(absent_peers),
          "checkpoint-verify must NEVER create absent --peers directory");
  }

  {
    const fs::path absent_bridge = base / "absent-bridge-dir";
    const Value empty_cp = parse_stdout_json(
        run_cli({"bridge", "checkpoint", "--room", "room-empty", "--checkpoint-seq",
                 "1", "--bridge", absent_bridge.string(), "--peers",
                 alice_peers.string()}),
        "bridge checkpoint absent bridge");
    const auto *wm_obj =
        std::get_if<Value::Object>(&req_field(empty_cp, "actor_watermarks").value());
    check(wm_obj != nullptr && wm_obj->empty() &&
              req_field(empty_cp, "causal_frontier_hashes").array().empty(),
          "checkpoint with absent bridge must have empty watermarks and frontier");
    check(!fs::exists(absent_bridge),
          "bridge checkpoint must NEVER create absent --bridge directory");
  }

  {
    const fs::path absent_dry_peers = base / "absent-peers-dry-run";
    const Value dry_absent =
        parse_stdout_json(run_cli({"join", invite_uri, "--alias", "alice", "--peers",
                                   absent_dry_peers.string(), "--dry-run"}),
                          "join --dry-run absent peers");
    check(!std::get<bool>(req_field(dry_absent, "joined").value()) &&
              !std::get<bool>(req_field(dry_absent, "pinned").value()),
          "join --dry-run absent peers output mismatch");
    check(!fs::exists(absent_dry_peers),
          "join --dry-run must NEVER create absent --peers directory");
  }

  {
    const auto empty_code = run_cli({"bridge", "invite", "--room", "room-bad",
                                     "--relay", "wss://relay.blackbird.local/v1",
                                     "--code", "", "--peers", alice_peers.string()});
    check(empty_code.exit_code == 2 && empty_code.out.empty() &&
              !empty_code.err.empty(),
          "bridge invite --code \"\" must fail with usage exit 2");
  }
}

void test_party_cli_roster_add_leader_and_say(const fs::path &base) {
  const fs::path sandbox = base / "party-cli-sandbox";
  const fs::path absent_peers = base / "party-absent-peers";
  fs::create_directories(sandbox);

  // 1. `--help` works cleanly on `party` and each subcommand.
  for (const std::vector<std::string> &help_cmd : std::vector<std::vector<std::string>>{
           {"party", "--help"},
           {"party", "roster", "--help"},
           {"party", "create", "--help"},
           {"party", "leave", "--help"},
           {"party", "add-leader", "--help"},
           {"party", "remove-leader", "--help"},
           {"party", "say", "--help"},
       }) {
    const auto help_res = run_cli(help_cmd);
    check(help_res.exit_code == 0 && help_res.out.empty() && !help_res.err.empty(),
          "party --help must exit 0 with usage on stderr");
  }

  // 2. `party roster` and `party leave` on absent `.blackbird` and absent `--peers`
  //    exit 0 cleanly and create ZERO directories on disk!
  {
    ScopedCwd guard{sandbox};
    const Value empty_roster = parse_stdout_json(
        run_cli({"party", "roster", "--peers", absent_peers.string()}),
        "party roster absent");
    check(req_str(empty_roster, "mode") == "single_operator" &&
              req_str(empty_roster, "scope") == "party/rollcall" &&
              req_int(empty_roster, "participant_count") == 0 &&
              req_int(empty_roster, "message_count") == 0 &&
              req_field(empty_roster, "participants").array().empty() &&
              req_field(empty_roster, "conflicts").array().empty(),
          "absent party roster payload mismatch");

    const Value solo_leave =
        parse_stdout_json(run_cli({"party", "leave"}), "party leave absent");
    check(std::get<bool>(req_field(solo_leave, "left").value()) &&
              !std::get<bool>(req_field(solo_leave, "active").value()) &&
              std::get<bool>(req_field(solo_leave, "already_solo").value()),
          "party leave on absent party.json must be a clean already_solo no-op");

    const Value absent_remove =
        parse_stdout_json(run_cli({"party", "remove-leader", "--alias", "nobody"}),
                          "party remove-leader absent");
    check(!std::get<bool>(req_field(absent_remove, "removed").value()) &&
              req_int(absent_remove, "participant_count") == 0,
          "party remove-leader on absent party.json must be a clean no-op");

    check(!fs::exists(sandbox / ".blackbird"),
          "party roster/leave/remove-leader must NEVER create .blackbird directory");
    check(!fs::exists(absent_peers),
          "party roster must NEVER create absent --peers directory");
  }

  // 3. Reject option-injection `--ssh` and secret-like field values (exit 2) before
  //    creating any files.
  {
    ScopedCwd guard{sandbox};
    for (const char *bad_ssh : {"-oProxyCommand=evil", "patrick@-oProxyCommand=evil",
                                "patrick@host with space", "patrick@host\nline2"}) {
      const auto bad =
          run_cli({"party", "add-leader", "--alias", "evil-ssh", "--ssh", bad_ssh});
      check(bad.exit_code == 2 && bad.out.empty() && !bad.err.empty(),
            "hostile --ssh value must fail with exit 2");
    }
    const auto secret_dn = run_cli({"party", "add-leader", "--alias", "secret-dn",
                                    "--display-name", "sk-ant-api03-verysecret"});
    check(secret_dn.exit_code == 2 && secret_dn.out.empty() && !secret_dn.err.empty(),
          "secret-like --display-name must fail with exit 2");
    const auto secret_model = run_cli({"party", "add-leader", "--alias", "secret-model",
                                       "--model", "ghp_1234567890secret"});
    check(secret_model.exit_code == 2 && secret_model.out.empty() &&
              !secret_model.err.empty(),
          "secret-like --model must fail with exit 2");
    check(!fs::exists(sandbox / ".blackbird"),
          "rejected add-leader calls must NOT create .blackbird directory");
  }

  // 4. `party add-leader` adds `wintermute` and `neuromancer`, verifies
  // case-insensitive
  //    upsert, verifies mode 0600 on `.blackbird/party.json`, and `party roster`
  //    reflects `single_operator` with 2 leaders.
  {
    ScopedCwd guard{sandbox};
    const Value add1 =
        parse_stdout_json(run_cli({"party", "add-leader", "--alias", "wintermute",
                                   "--ssh", "patrick@wintermute", "--provider",
                                   "deepseek", "--model", "deepseek-chat"}),
                          "party add-leader wintermute");
    check(std::get<bool>(req_field(add1, "saved").value()) &&
              req_str(add1, "alias") == "wintermute" &&
              req_str(add1, "role") == "platoon_leader" &&
              req_int(add1, "participant_count") == 1,
          "party add-leader wintermute output mismatch");

    // Case-insensitive upsert updates existing entry instead of duplicating.
    const Value upsert1 =
        parse_stdout_json(run_cli({"party", "add-leader", "--alias", "Wintermute",
                                   "--display-name", "Wintermute Lead"}),
                          "party add-leader wintermute upsert");
    check(std::get<bool>(req_field(upsert1, "saved").value()) &&
              req_int(upsert1, "participant_count") == 1,
          "case-insensitive upsert must not duplicate participant");

    // Restore canonical lowercase alias and add second leader `neuromancer`.
    (void)parse_stdout_json(run_cli({"party", "add-leader", "--alias", "wintermute"}),
                            "party add-leader wintermute canonical");
    const Value add2 = parse_stdout_json(
        run_cli({"party", "add-leader", "--alias", "neuromancer", "--provider",
                 "anthropic", "--model", "claude-sonnet-4-6"}),
        "party add-leader neuromancer");
    check(std::get<bool>(req_field(add2, "saved").value()) &&
              req_str(add2, "alias") == "neuromancer" &&
              req_str(add2, "role") == "platoon_leader" &&
              req_int(add2, "participant_count") == 2,
          "party add-leader neuromancer output mismatch");

    // Verify 0600 permissions on `.blackbird/party.json`.
    const fs::path party_json = sandbox / ".blackbird" / "party.json";
    struct stat st{};
    check(::stat(party_json.c_str(), &st) == 0, "party.json must exist after save");
    check((st.st_mode & mode_t{0777}) == mode_t{0600},
          "party.json must have strict 0600 permissions");

    // Verify `party roster` reports single_operator with 2 leaders and preserved
    // fields.
    const Value roster = parse_stdout_json(
        run_cli({"party", "roster", "--peers", absent_peers.string()}),
        "party roster two leaders");
    check(req_str(roster, "mode") == "single_operator" &&
              req_int(roster, "participant_count") == 2,
          "party roster must reflect single_operator with 2 leaders");
    const auto &parts = req_field(roster, "participants").array();
    check(parts.size() == 2, "expected 2 participants in party roster");
    bool saw_wintermute = false;
    bool saw_neuromancer = false;
    for (const Value &p : parts) {
      check(req_str(p, "role") == "platoon_leader", "expected platoon_leader role");
      if (req_str(p, "id") == "wintermute") {
        saw_wintermute = true;
        check(req_str(p, "ssh_target") == "patrick@wintermute" &&
                  req_str(p, "provider") == "deepseek" &&
                  req_str(p, "model") == "deepseek-chat" &&
                  req_str(p, "display_name") == "Wintermute Lead",
              "wintermute fields were not preserved across upsert");
      } else if (req_str(p, "id") == "neuromancer") {
        saw_neuromancer = true;
      }
    }
    check(saw_wintermute && saw_neuromancer,
          "expected both wintermute and neuromancer in roster");

    // 5. `party say --from patrick --body "@wintermute status check"` posts to
    //    PlatoonBoard and returns `targets: ["wintermute"]`.
    const Value say1 =
        parse_stdout_json(run_cli({"party", "say", "--from", "patrick", "--body",
                                   "@wintermute status check"}),
                          "party say @wintermute");
    check(std::get<bool>(req_field(say1, "posted").value()) &&
              req_int(say1, "seq") == 1 && req_str(say1, "from") == "patrick" &&
              req_str(say1, "mode") == "single_operator",
          "party say output core fields mismatch");
    const auto &targets1 = req_field(say1, "targets").array();
    check(targets1.size() == 1 && targets1[0].string() == "wintermute",
          "party say targets must be [\"wintermute\"]");
    check(req_field(say1, "unknown_targets").array().empty(),
          "party say unknown_targets must be empty for known leader");

    // Also verify `--to` prepending and unknown target reporting.
    const Value say2 =
        parse_stdout_json(run_cli({"party", "say", "--from", "patrick", "--to",
                                   "neuromancer", "--body", "sync check"}),
                          "party say --to neuromancer");
    check(req_int(say2, "seq") == 2, "second party say must increment seq to 2");
    const auto &targets2 = req_field(say2, "targets").array();
    check(targets2.size() == 1 && targets2[0].string() == "neuromancer",
          "party say --to neuromancer must resolve target");

    const Value say_unknown = parse_stdout_json(
        run_cli({"party", "say", "--from", "patrick", "--body", "@ghost ping"}),
        "party say unknown target");
    check(req_field(say_unknown, "targets").array().empty(),
          "unknown target must not appear in resolved targets");
    const auto &unknowns = req_field(say_unknown, "unknown_targets").array();
    check(unknowns.size() == 1 && unknowns[0].string() == "ghost",
          "unknown_targets must report ghost");

    // Verify messages landed on PlatoonBoard and appear in `party roster`
    // message_count.
    const Value board_read = parse_stdout_json(
        run_cli({"platoon", "read", "--board",
                 (sandbox / ".blackbird" / "platoon").string(), "--after-seq", "0"}),
        "platoon read after party say");
    check(req_int(board_read, "count") == 3, "expected 3 messages on PlatoonBoard");
    const Value &msg0 = req_field(board_read, "messages").array()[0];
    check(req_str(msg0, "from") == "patrick" && req_str(msg0, "to") == "wintermute" &&
              req_str(msg0, "text") == "status check",
          "PlatoonBoard message 1 mismatch");

    const Value roster_after = parse_stdout_json(
        run_cli({"party", "roster", "--peers", absent_peers.string()}),
        "party roster after say");
    check(req_int(roster_after, "message_count") == 3,
          "party roster message_count must reflect 3 PlatoonBoard messages");

    // 6. `party create`, `party remove-leader`, and `party leave` lifecycle!
    const Value created = parse_stdout_json(
        run_cli({"party", "create", "--room", "ops/war-room"}), "party create");
    check(std::get<bool>(req_field(created, "created").value()) &&
              std::get<bool>(req_field(created, "active").value()) &&
              req_str(created, "room") == "ops/war-room" &&
              req_int(created, "participant_count") == 2,
          "party create must activate room while preserving existing peers");
    struct stat create_st{};
    check(::stat(party_json.c_str(), &create_st) == 0 &&
              (create_st.st_mode & mode_t{0777}) == mode_t{0600},
          "party create must keep 0600 permissions on party.json");

    const Value roster_room = parse_stdout_json(
        run_cli({"party", "roster", "--peers", absent_peers.string()}),
        "party roster after create");
    check(req_str(roster_room, "scope") == "ops/war-room" &&
              req_int(roster_room, "participant_count") == 2,
          "party roster must reflect updated room scope");

    // Remove `neuromancer` (case-insensitive) and verify 0600 + remaining leader.
    const Value removed =
        parse_stdout_json(run_cli({"party", "remove-leader", "--alias", "Neuromancer"}),
                          "party remove-leader neuromancer");
    check(std::get<bool>(req_field(removed, "removed").value()) &&
              req_int(removed, "participant_count") == 1,
          "party remove-leader must remove neuromancer leaving 1 leader");
    struct stat rm_st{};
    check(::stat(party_json.c_str(), &rm_st) == 0 &&
              (rm_st.st_mode & mode_t{0777}) == mode_t{0600},
          "party remove-leader must preserve 0600 permissions on party.json");

    const Value removed_again =
        parse_stdout_json(run_cli({"party", "remove-leader", "--alias", "neuromancer"}),
                          "party remove-leader duplicate");
    check(!std::get<bool>(req_field(removed_again, "removed").value()) &&
              req_int(removed_again, "participant_count") == 1,
          "removing already-absent alias must report removed=false");

    // `party leave` clears active party without touching platoon history!
    const Value left = parse_stdout_json(run_cli({"party", "leave"}), "party leave");
    check(std::get<bool>(req_field(left, "left").value()) &&
              !std::get<bool>(req_field(left, "active").value()) &&
              !std::get<bool>(req_field(left, "already_solo").value()) &&
              req_str(left, "previous_room") == "ops/war-room",
          "party leave output mismatch");
    check(!fs::exists(party_json),
          "party leave must clear active .blackbird/party.json");
    check(fs::exists(sandbox / ".blackbird" / "platoon" / "board.jsonl"),
          "party leave must NOT delete PlatoonBoard history");

    const Value roster_left = parse_stdout_json(
        run_cli({"party", "roster", "--peers", absent_peers.string()}),
        "party roster after leave");
    check(req_int(roster_left, "participant_count") == 0 &&
              req_int(roster_left, "message_count") == 3,
          "party roster after leave must show 0 roster leaders while preserving 3 "
          "historical platoon messages");

    // Second `party leave` is an idempotent already_solo no-op.
    const Value left_again =
        parse_stdout_json(run_cli({"party", "leave"}), "party leave again");
    check(std::get<bool>(req_field(left_again, "left").value()) &&
              std::get<bool>(req_field(left_again, "already_solo").value()),
          "second party leave must report already_solo=true");
  }
}

void test_party_lobby_serve_and_status(const PlatoonTestPaths &paths) {
  const fs::path &base = paths.base;
  const fs::path &self_exe = paths.self_exe;

  // Unix domain socket sun_path is limited to 104 bytes on macOS; use a short
  // `/tmp` directory for socket files while keeping peers/absent dirs in `base`.
  struct ShortSocketTempDir {
    fs::path path;
    ShortSocketTempDir() {
      std::string pattern = "/tmp/bb-ps-XXXXXX";
      char *created = ::mkdtemp(pattern.data());
      check(created != nullptr, "mkdtemp for short socket dir failed");
      path = fs::path{created};
    }
    ~ShortSocketTempDir() {
      std::error_code ec;
      fs::remove_all(path, ec);
    }
    ShortSocketTempDir(const ShortSocketTempDir &) = delete;
    ShortSocketTempDir &operator=(const ShortSocketTempDir &) = delete;
  } sock_tmp;

  // 1. `--help` works cleanly on `party serve` and `party lobby-status`.
  for (const std::vector<std::string> &help_cmd : std::vector<std::vector<std::string>>{
           {"party", "serve", "--help"},
           {"party", "lobby-status", "--help"},
       }) {
    const auto help_res = run_cli(help_cmd);
    check(help_res.exit_code == 0 && help_res.out.empty() && !help_res.err.empty(),
          "party serve/lobby-status --help must exit 0 with usage on stderr");
  }

  // 2. `party lobby-status --socket <absent>` returns {"running":false} exit 0
  //    and creates ZERO files or directories!
  {
    const fs::path absent_dir = sock_tmp.path / "absent";
    const fs::path absent_sock = absent_dir / "party.sock";
    const Value status = parse_stdout_json(
        run_cli({"party", "lobby-status", "--socket", absent_sock.string()}),
        "party lobby-status absent");
    check(!std::get<bool>(req_field(status, "running").value()),
          "absent party.sock must report running=false");
    check(!fs::exists(absent_dir),
          "party lobby-status on absent socket must NEVER create directories");
  }

  // 3. Reject `..` traversal in --socket and invalid --idle-timeout-ms (exit 2).
  {
    const auto bad_status =
        run_cli({"party", "lobby-status", "--socket", "/tmp/../etc/party.sock"});
    check(bad_status.exit_code == 2 && bad_status.out.empty() &&
              !bad_status.err.empty(),
          "party lobby-status must reject .. traversal in --socket");

    const auto bad_serve =
        run_cli({"party", "serve", "--socket", "/tmp/../etc/party.sock"});
    check(bad_serve.exit_code == 2 && bad_serve.out.empty() && !bad_serve.err.empty(),
          "party serve must reject .. traversal in --socket");

    const auto bad_idle = run_cli({"party", "serve", "--idle-timeout-ms", "0"});
    check(bad_idle.exit_code == 2 && bad_idle.out.empty() && !bad_idle.err.empty(),
          "party serve must reject --idle-timeout-ms 0");

    // Valid non-ASCII UTF-8 socket paths containing continuation bytes in 0x80..0x9F
    // (e.g. É = C3 89, 日 = E6 97 A5) must be accepted (exit 0 running=false), while
    // Unicode C1 (U+009B = C2 9B) and BiDi override (U+202E = E2 80 AE) must fail
    // with exit 2.
    const fs::path utf8_absent_sock =
        sock_tmp.path / "caf\xc3\x89-\xe6\x97\xa5" / "p.sock";
    const Value utf8_status = parse_stdout_json(
        run_cli({"party", "lobby-status", "--socket", utf8_absent_sock.string()}),
        "party lobby-status valid utf8 path");
    check(!std::get<bool>(req_field(utf8_status, "running").value()),
          "valid UTF-8 absent socket path must return running=false");

    for (const char *bad_ctrl :
         {"/tmp/bb-\xc2\x9b/party.sock", "/tmp/bb-\xe2\x80\xae/party.sock"}) {
      const auto rejected_status =
          run_cli({"party", "lobby-status", "--socket", bad_ctrl});
      check(rejected_status.exit_code == 2 && rejected_status.out.empty() &&
                !rejected_status.err.empty(),
            "party lobby-status must reject C1/BiDi control scalars in --socket");
      const auto rejected_serve = run_cli({"party", "serve", "--socket", bad_ctrl});
      check(rejected_serve.exit_code == 2 && rejected_serve.out.empty() &&
                !rejected_serve.err.empty(),
            "party serve must reject C1/BiDi control scalars in --socket");
    }

    // Trailing-slash symlink `--peers` must be rejected (no POSIX lstat bypass).
    const fs::path real_peers = base / "party-real-peers";
    const fs::path sym_peers = base / "party-sym-peers";
    fs::create_directories(real_peers);
    fs::create_directory_symlink(real_peers, sym_peers);
    const fs::path sym_sock = sock_tmp.path / "sym" / "party.sock";
    const auto bad_sym =
        run_cli({"party", "serve", "--socket", sym_sock.string(), "--peers",
                 sym_peers.string() + "/", "--idle-timeout-ms", "150"});
    check(bad_sym.exit_code != 0 && bad_sym.out.empty() && !bad_sym.err.empty(),
          "party serve must reject trailing-slash symlink --peers");
  }

  // 4. `party serve --idle-timeout-ms 150` emits ready JSON, serves cleanly,
  //    exits 0 on idle timeout, unlinks socket, and creates ZERO peers dir or
  //    party.json!
  {
    const fs::path idle_sock = sock_tmp.path / "r1" / "party.sock";
    const fs::path absent_peers = base / "idle-absent-peers";
    const auto serve_res =
        run_cli({"party", "serve", "--socket", idle_sock.string(), "--peers",
                 absent_peers.string(), "--idle-timeout-ms", "150"});
    const Value ready = parse_stdout_json(serve_res, "party serve idle-timeout");
    check(std::get<bool>(req_field(ready, "listening").value()) &&
              req_str(ready, "socket") == idle_sock.string(),
          "party serve ready JSON mismatch");
    check(!fs::exists(idle_sock), "party serve must unlink socket on clean idle exit");
    check(!fs::exists(absent_peers),
          "party serve must NEVER create absent --peers directory");
  }

  // 5. Spawn live `blackbird party serve`, verify ready JSON, ping + live in-RAM
  //    snapshot via `blackbird party lobby-status`, then SIGTERM for graceful shutdown!
  {
    const fs::path live_dir = base / "live-lobby";
    const fs::path peers_dir = live_dir / "peers";
    const fs::path wm_dir = live_dir / "id-wintermute";
    const fs::path sock_path = sock_tmp.path / "r2" / "party.sock";

    auto local_id = PeerIdentityStore::open_or_create(peers_dir);
    check(local_id.has_value(), "open_or_create local peers identity failed");
    auto wm_id = PeerIdentityStore::open_or_create(wm_dir);
    check(wm_id.has_value(), "open_or_create wintermute identity failed");
    auto known = KnownPeersStore::open(peers_dir);
    check(known.has_value(), "KnownPeersStore::open failed");
    check(known.value()
              .pin_peer(PinPeerRequest{
                  .alias = "wintermute",
                  .public_key = wm_id.value().identity().public_key,
                  .trust_note = "ssh_target=pilot@wintermute",
              })
              .has_value(),
          "pin_peer wintermute failed");

    int pipefd[2]{-1, -1};
    check(::pipe(pipefd) == 0, "pipe failed for party serve child");
    const pid_t pid = ::fork();
    check(pid >= 0, "fork failed for party serve child");
    if (pid == 0) {
      (void)::close(pipefd[0]);
      (void)::dup2(pipefd[1], STDOUT_FILENO);
      (void)::close(pipefd[1]);
      std::string exe = self_exe.string();
      std::string flag = "--party-serve-child";
      std::string sock_arg = sock_path.string();
      std::string peers_arg = peers_dir.string();
      char *child_argv[] = {exe.data(), flag.data(), sock_arg.data(), peers_arg.data(),
                            nullptr};
      ::execv(exe.c_str(), child_argv);
      ::_exit(127);
    }
    (void)::close(pipefd[1]);

    struct ChildGuard {
      pid_t child_pid = -1;
      int fd = -1;
      ~ChildGuard() {
        if (fd >= 0)
          (void)::close(fd);
        if (child_pid > 1) {
          (void)::kill(child_pid, SIGKILL);
          int st = 0;
          (void)::waitpid(child_pid, &st, 0);
        }
      }
    } guard{pid, pipefd[0]};

    std::string ready_line;
    char ch = '\0';
    while (::read(guard.fd, &ch, 1) == 1) {
      if (ch == '\n')
        break;
      ready_line.push_back(ch);
    }
    (void)::close(guard.fd);
    guard.fd = -1;

    const auto parsed_ready = parse_json(ready_line);
    check(parsed_ready.has_value() &&
              std::get<bool>(req_field(parsed_ready.value(), "listening").value()) &&
              req_str(parsed_ready.value(), "socket") == sock_path.string(),
          "party serve child must flush ready JSON immediately");

    // Initial live lobby-status: running=true, SOLO (0 rooms, 0 participants).
    const Value solo_status = parse_stdout_json(
        run_cli({"party", "lobby-status", "--socket", sock_path.string()}),
        "party lobby-status live solo");
    check(std::get<bool>(req_field(solo_status, "running").value()) &&
              req_int(solo_status, "room_count") == 0 &&
              req_int(solo_status, "participant_count") == 0 &&
              req_str(solo_status, "room_scope").empty(),
          "live lobby-status initial solo payload mismatch");

    // Create a room, invite pinned friend, post a message via PartyLobbyClient.
    auto client = PartyLobbyClient::connect(sock_path);
    check(client.has_value(), "PartyLobbyClient::connect to party serve failed");
    const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    PartyLease draft{};
    draft.room_id = "ops/cli-live";
    draft.alias = "pilot";
    draft.role = PartyMemberRole::operator_human;
    draft.host = "workstation";
    draft.issued_ns = now_ns;
    draft.expires_ns = now_ns + kPartyLobbyDefaultTtlNs;
    draft.lease_seq = 1;
    auto signed_lease = sign_party_lease(local_id.value(), std::move(draft));
    check(signed_lease.has_value(), "sign_party_lease failed");
    check(client.value().create_room("ops/cli-live", signed_lease.value()).has_value(),
          "create_room failed");
    check(client.value().invite_friend("ops/cli-live", "wintermute").has_value(),
          "invite_friend wintermute failed");
    check(client.value()
              .post_message("ops/cli-live", "pilot", "@all", "hello live lobby")
              .has_value(),
          "post_message failed");
    client.value().close();

    // Verify `blackbird party lobby-status` reflects live in-RAM room, members &
    // message!
    const Value live_status = parse_stdout_json(
        run_cli({"party", "lobby-status", "--socket", sock_path.string()}),
        "party lobby-status populated");
    check(std::get<bool>(req_field(live_status, "running").value()) &&
              req_int(live_status, "room_count") == 1 &&
              req_str(live_status, "active_room_id") == "ops/cli-live" &&
              req_str(live_status, "room_scope") == "ops/cli-live" &&
              req_int(live_status, "participant_count") == 2 &&
              req_int(live_status, "message_count") == 1,
          "live lobby-status populated payload mismatch");

    // Graceful SIGTERM shutdown -> exit 0 and unlink party.sock!
    check(::kill(pid, SIGTERM) == 0, "SIGTERM to party serve failed");
    int wait_status = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    pid_t waited = 0;
    while (std::chrono::steady_clock::now() < deadline) {
      waited = ::waitpid(pid, &wait_status, WNOHANG);
      if (waited == pid)
        break;
      std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    check(waited == pid && WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0,
          "party serve must exit 0 cleanly on SIGTERM");
    guard.child_pid = -1;
    check(!fs::exists(sock_path), "party serve must unlink socket on SIGTERM");

    // Confirm zero `party.json` exists anywhere under live_dir.
    for (const auto &entry : fs::recursive_directory_iterator(live_dir)) {
      check(entry.path().filename() != "party.json",
            "live party.sock lobby must NEVER create party.json on disk");
    }

    const Value stopped_status = parse_stdout_json(
        run_cli({"party", "lobby-status", "--socket", sock_path.string()}),
        "party lobby-status after SIGTERM");
    check(!std::get<bool>(req_field(stopped_status, "running").value()),
          "lobby-status must report running=false after SIGTERM");
  }
}

void test_flightdeck_cli_once_and_themes(const fs::path &base) {
  const fs::path absent_session = base / "flightdeck-absent-session";

  // 1. `--help` exits 0 with usage on stderr and empty stdout.
  const auto help_res = run_cli({"flightdeck", "--help"});
  check(help_res.exit_code == 0 && help_res.out.empty() &&
            help_res.err.find("flightdeck") != std::string::npos,
        "flightdeck --help must exit 0 with usage on stderr");

  // 2. `--once --halfblock --theme synthwave` on absent session exits 0, outputs a
  //    24-bit ANSI half-block (`▀`) frame, and creates ZERO directories.
  const auto synth = run_cli({"flightdeck", "--once", "--halfblock", "--theme",
                              "synthwave", "--session", absent_session.string()});
  check(synth.exit_code == 0 && synth.err.empty(),
        "flightdeck --once --halfblock --theme synthwave must exit 0 cleanly");
  check(synth.out.find("\x1b[38;2;") != std::string::npos &&
            synth.out.find("\x1b[48;2;") != std::string::npos &&
            synth.out.find("\xE2\x96\x80") != std::string::npos,
        "flightdeck --once --halfblock must emit 24-bit ANSI half-block frame");
  check(!fs::exists(absent_session),
        "flightdeck must NEVER create absent --session directory");

  // 3. `--once --halfblock --theme tokyonight` exits 0 and renders a distinct theme.
  const auto tokyo = run_cli({"flightdeck", "--once", "--halfblock", "--theme",
                              "tokyonight", "--session", absent_session.string()});
  check(tokyo.exit_code == 0 && tokyo.err.empty(),
        "flightdeck --once --halfblock --theme tokyonight must exit 0 cleanly");
  check(tokyo.out.find("\xE2\x96\x80") != std::string::npos && tokyo.out != synth.out,
        "tokyonight frame must render distinct 24-bit half-block output");
  check(!fs::exists(absent_session),
        "flightdeck tokyonight must NEVER create absent --session directory");

  // 4. Invalid `--theme`, `--fps`, `--width`, `--height` fail cleanly with exit 2.
  const auto bad_theme =
      run_cli({"flightdeck", "--once", "--halfblock", "--theme", "not-a-theme"});
  check(bad_theme.exit_code == 2 && bad_theme.out.empty() && !bad_theme.err.empty(),
        "invalid --theme must exit 2 with error on stderr");

  for (const char *bad_fps : {"0", "31", "abc"}) {
    const auto bad = run_cli({"flightdeck", "--once", "--fps", bad_fps});
    check(bad.exit_code == 2 && bad.out.empty() && !bad.err.empty(),
          "invalid --fps must exit 2");
  }

  const auto bad_width = run_cli({"flightdeck", "--once", "--width", "50"});
  check(bad_width.exit_code == 2 && bad_width.out.empty() && !bad_width.err.empty(),
        "out-of-range --width must exit 2");

  for (const char *bad_height : {"50", "999", "abc"}) {
    const auto bad = run_cli({"flightdeck", "--once", "--height", bad_height});
    check(bad.exit_code == 2 && bad.out.empty() && !bad.err.empty(),
          "out-of-range --height must exit 2");
  }

  const auto empty_session = run_cli({"flightdeck", "--once", "--session", ""});
  check(empty_session.exit_code == 2 && empty_session.out.empty() &&
            !empty_session.err.empty(),
        "empty --session must exit 2");

  // 5. Trailing-slash symlink `--session` must be rejected (no POSIX lstat bypass).
  const fs::path real_session = base / "flightdeck-real-session";
  const fs::path sym_session = base / "flightdeck-sym-session";
  fs::create_directories(real_session);
  fs::create_directory_symlink(real_session, sym_session);
  const auto sym_slash = run_cli(
      {"flightdeck", "--once", "--halfblock", "--session", sym_session.string() + "/"});
  check(sym_slash.exit_code != 0 && sym_slash.out.empty() && !sym_slash.err.empty(),
        "trailing-slash symlink --session must be rejected");
}

struct ScopedEnvVar {
  std::string name;
  std::optional<std::string> previous;

  ScopedEnvVar(std::string var_name, std::optional<std::string> next_value)
      : name(std::move(var_name)) {
    if (const char *cur = std::getenv(name.c_str()); cur != nullptr)
      previous = std::string{cur};
    if (next_value.has_value())
      (void)::setenv(name.c_str(), next_value->c_str(), 1);
    else
      (void)::unsetenv(name.c_str());
  }
  ScopedEnvVar(const ScopedEnvVar &) = delete;
  ScopedEnvVar &operator=(const ScopedEnvVar &) = delete;
  ~ScopedEnvVar() {
    if (previous.has_value())
      (void)::setenv(name.c_str(), previous->c_str(), 1);
    else
      (void)::unsetenv(name.c_str());
  }
};

std::string test_base64_encode(std::span<const std::uint8_t> bytes) {
  static constexpr char kAlpha[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((bytes.size() + 2U) / 3U) * 4U);
  std::size_t i = 0U;
  while (i + 3U <= bytes.size()) {
    const std::uint32_t t = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                            static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 6U) & 0x3fU]);
    out.push_back(kAlpha[t & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1U) {
    const std::uint32_t t = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t t = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kAlpha[(t >> 18U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 12U) & 0x3fU]);
    out.push_back(kAlpha[(t >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

std::vector<std::uint8_t> read_binary_file(const fs::path &path) {
  std::ifstream in(path, std::ios::binary);
  check(static_cast<bool>(in), "failed to open binary file");
  return std::vector<std::uint8_t>{std::istreambuf_iterator<char>(in),
                                   std::istreambuf_iterator<char>()};
}

void run_command_checked(std::vector<std::string> argv) {
  detail::Child child;
  for (char **entry = environ; entry != nullptr && *entry != nullptr; ++entry)
    child.child_environment.emplace_back(*entry);
  child.start(std::move(argv), {}, true);
  child.close_input();
  int code = 0;
  const std::string out = child.collect(detail::Clock::now() + std::chrono::seconds{20},
                                        1024 * 1024, &code);
  if (code != 0)
    throw std::runtime_error("helper command failed (rc=" + std::to_string(code) +
                             "): " + out);
}

void test_online_cli_subcommand(const fs::path &base) {
  // Isolate environment overrides so host shell env never perturbs tests.
  ScopedEnvVar env_dir{"BLACKBIRD_ONLINE_DIR", std::nullopt};
  ScopedEnvVar env_auth{"BLACKBIRD_ONLINE_AUTHORITY", std::nullopt};
  ScopedEnvVar env_host{"BLACKBIRD_ONLINE_CONNECT_HOST", std::nullopt};
  ScopedEnvVar env_port{"BLACKBIRD_ONLINE_PORT", std::nullopt};
  ScopedEnvVar env_ca{"BLACKBIRD_ONLINE_CA_BUNDLE", std::nullopt};

  // 1. Help on top-level and subcommands exits 0 with usage on stderr and empty stdout.
  for (const std::vector<std::string> &cmd : std::vector<std::vector<std::string>>{
           {"online", "--help"},
           {"online", "health", "--help"},
           {"online", "register", "--help"},
           {"online", "whoami", "--help"},
           {"online", "resolve", "--help"},
           {"online", "devices", "--help"},
           {"online", "devices", "init", "--help"},
           {"online", "devices", "install-cwt", "--help"},
           {"online", "devices", "link", "--help"},
           {"online", "devices", "link", "create", "--help"},
           {"online", "devices", "link", "join", "--help"},
           {"online", "devices", "link", "approve", "--help"},
           {"online", "recovery-key", "--help"},
           {"online", "export-mpkey", "--help"},
           {"online", "recover", "--help"},
           {"online", "web-approve", "--help"},
           {"online", "friends", "--help"},
           {"online", "friends", "add", "--help"},
           {"online", "friends", "accept", "--help"},
           {"online", "friends", "deny", "--help"},
           {"online", "friends", "decline", "--help"},
           {"online", "friends", "remove", "--help"},
           {"online", "friends", "block", "--help"},
           {"online", "party", "--help"},
           {"online", "party", "create", "--help"},
           {"online", "party", "join", "--help"},
       }) {
    const auto help_res = run_cli(cmd);
    check(help_res.exit_code == 0 && help_res.out.empty() && !help_res.err.empty(),
          "online --help must exit 0 with usage on stderr");
  }
  {
    const auto top_help = run_cli({"online", "--help"});
    check(top_help.err.find("web-approve") != std::string::npos &&
              top_help.err.find("init") != std::string::npos &&
              top_help.err.find("install-cwt") != std::string::npos &&
              top_help.err.find("link") != std::string::npos &&
              top_help.err.find("recovery-key") != std::string::npos &&
              top_help.err.find("export-mpkey") != std::string::npos &&
              top_help.err.find("recover") != std::string::npos,
          "online --help must list web-approve, devices init|install-cwt|link, "
          "recovery-key, export-mpkey, recover");
    const auto dev_help = run_cli({"online", "devices", "--help"});
    check(dev_help.err.find("link") != std::string::npos,
          "online devices --help must list link");
    const auto friends_help = run_cli({"online", "friends", "--help"});
    check(friends_help.err.find("accept") != std::string::npos &&
              friends_help.err.find("deny") != std::string::npos &&
              friends_help.err.find("remove") != std::string::npos &&
              friends_help.err.find("block") != std::string::npos &&
              friends_help.err.find("<handle|account_id>") != std::string::npos,
          "online friends --help must list accept|deny|remove|block "
          "<handle|account_id>");
  }

  // 2. Invalid paths (.. traversal, C1, BiDi, BOM) fail closed with exit 2 and ZERO
  //    disk writes!
  const fs::path invalid_probe_parent = base / "online-invalid-probe";
  for (const char *bad_path : {
           "/tmp/../etc/online-state",
           "/tmp/bb-\xc2\x9b/online",
           "/tmp/bb-\xe2\x80\xae/online",
           "/tmp/bb-\xef\xbb\xbf/online",
       }) {
    const auto bad_state =
        run_cli({"online", "whoami", "--local", "--state-dir", bad_path});
    check(bad_state.exit_code == 2 && bad_state.out.empty() && !bad_state.err.empty(),
          "invalid --state-dir must exit 2");
    const auto bad_ca = run_cli({"online", "health", "--ca-bundle", bad_path});
    check(bad_ca.exit_code == 2 && bad_ca.out.empty() && !bad_ca.err.empty(),
          "invalid --ca-bundle must exit 2");
  }
  {
    ScopedEnvVar bad_env{"BLACKBIRD_ONLINE_DIR",
                         (invalid_probe_parent / ".." / "escape").string()};
    const auto res = run_cli({"online", "whoami", "--local"});
    check(res.exit_code == 2 && res.out.empty() && !res.err.empty(),
          "invalid BLACKBIRD_ONLINE_DIR must exit 2");
    check(!fs::exists(invalid_probe_parent),
          "invalid env path must create zero directories");
  }

  // 3. Read-only / unregistered commands against absent --state-dir fail non-zero and
  //    NEVER create directories or files!
  const fs::path absent_state = base / "online-absent-state";
  for (const std::vector<std::string> &cmd : std::vector<std::vector<std::string>>{
           {"online", "whoami", "--local", "--state-dir", absent_state.string()},
           {"online", "whoami", "--state-dir", absent_state.string()},
           {"online", "resolve", "wingman", "--state-dir", absent_state.string()},
           {"online", "friends", "list", "--state-dir", absent_state.string()},
           {"online", "friends", "accept", "wingman", "--state-dir",
            absent_state.string()},
           {"online", "friends", "deny", "wingman", "--state-dir",
            absent_state.string()},
           {"online", "friends", "remove", "wingman", "--state-dir",
            absent_state.string()},
           {"online", "friends", "block", "wingman", "--state-dir",
            absent_state.string()},
           {"online", "party", "info", "5001", "--state-dir", absent_state.string()},
           {"online", "web-approve", "ABCD-EFGH", "--state-dir", absent_state.string()},
       }) {
    const auto res = run_cli(cmd);
    check(res.exit_code != 0 && res.out.empty() && !res.err.empty(),
          "unregistered online command must fail cleanly on stderr");
    check(!fs::exists(absent_state),
          "read-only online command must NEVER create absent --state-dir");
  }
  for (const char *action : {"accept", "deny", "decline", "remove", "block"}) {
    for (const char *bad_target : {"0", "admin"}) {
      const auto bad = run_cli({"online", "friends", action, bad_target, "--state-dir",
                                absent_state.string()});
      check(bad.exit_code == 2 && bad.out.empty() && !bad.err.empty(),
            "invalid friends target must exit 2");
      check(!fs::exists(absent_state),
            "invalid friends target must create zero directories");
    }
  }

  // Invalid handle on register must exit 2, create zero dirs, and never leak invite.
  {
    const std::string secret = "mpinv1_secret_must_never_leak_invalid_handle";
    const auto res = run_cli({"online", "register", "--invite", secret, "--handle",
                              "admin", "--state-dir", absent_state.string()});
    check(res.exit_code == 2 && res.out.empty() && !res.err.empty(),
          "reserved handle must fail with exit 2");
    check(res.err.find(secret) == std::string::npos,
          "register error must never leak invite secret");
    check(!fs::exists(absent_state),
          "failed register validation must create zero directories");
  }

  // 4. Spin up an offline ephemeral loopback TLS 1.3 HTTPS mock server using openssl
  //    CLI + inline python3 (TLSv1.3 + ALPN http/1.1, zero external network).
  const fs::path tls_dir = base / "online-tls";
  fs::create_directories(tls_dir);
  const fs::path cnf_path = tls_dir / "openssl.cnf";
  const fs::path key_path = tls_dir / "server.key";
  const fs::path crt_path = tls_dir / "server.crt";
  const fs::path srv_path = tls_dir / "mock_mp_server.py";
  const fs::path req_log_path = tls_dir / "requests.log";

  write_text_file(cnf_path, "[req]\n"
                            "distinguished_name = dn\n"
                            "prompt = no\n"
                            "[dn]\n"
                            "CN = api.test.local\n"
                            "[v3_ext]\n"
                            "basicConstraints = critical,CA:TRUE\n"
                            "keyUsage = critical,digitalSignature,keyCertSign\n"
                            "subjectAltName = DNS:api.test.local,IP:127.0.0.1\n");

  run_command_checked({"openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
                       "-out", key_path.string()});
  run_command_checked({"openssl", "req", "-new", "-x509", "-key", key_path.string(),
                       "-out", crt_path.string(), "-days", "1", "-config",
                       cnf_path.string(), "-extensions", "v3_ext"});

  // Generate a deterministic valid Ed25519 pubkey for mocked `resolve_handle` responses
  // and `devices enroll`.
  const auto wingman_key = mp::Ed25519SigningKey::generate();
  check(wingman_key.has_value(), "Ed25519SigningKey::generate failed for wingman");
  const std::string wingman_pub_b64 =
      test_base64_encode(wingman_key.value().public_key());

  const auto extra_dev_key = mp::Ed25519SigningKey::generate();
  check(extra_dev_key.has_value(), "Ed25519SigningKey::generate failed for device");
  const std::string extra_dev_pub_b64 =
      test_base64_encode(extra_dev_key.value().public_key());

  const std::string mock_server_py = R"PY(
import json
import os
import signal
import socket
import ssl
import sys
import time
import urllib.parse

crt_path = sys.argv[1]
key_path = sys.argv[2]
wingman_pub_b64 = sys.argv[3]
req_log_path = sys.argv[4]
seed_friends_path = os.path.join(os.path.dirname(req_log_path), "seed_friends.json")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
ctx.set_alpn_protocols(["http/1.1"])
ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(32)
srv.settimeout(0.5)
port = srv.getsockname()[1]

running = True
def _stop(_signum, _frame):
    global running
    running = False

signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)

print(port, flush=True)

state = {
    "account_id": 1001,
    "device_id": 2001,
    "handle": "pilot_one",
    "root_pubkey_b64": wingman_pub_b64,
    "devices": [],
    "friends": {},
    "parties": {},
    "device_links": {},
    "link_codes": ["W4K9-M2P7", "A2B3-C4D5", "H6J7-K8M9"],
    "link_code_idx": 0,
    "poll_nonces": set(),
    "inject_429_inspect": {"A2B3-C4D5": True},
    "inject_429_poll": {"A2B3-C4D5": True},
    "next_device_id": 2002,
    "next_party_id": 5001,
    "next_invite_id": 7001,
}

def read_http_request(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 65536:
            return None
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 3:
        return None
    method, target = parts[0], parts[1]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    clen = int(headers.get("content-length", "0"))
    while len(rest) < clen:
        chunk = conn.recv(4096)
        if not chunk:
            break
        rest += chunk
    return method, target, headers, rest[:clen]

def send_json(conn, status, payload):
    body = json.dumps(payload).encode("utf-8")
    reason = {200: "OK", 201: "Created", 202: "Accepted", 400: "Bad Request",
              401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
              409: "Conflict", 410: "Gone", 429: "Too Many Requests"}.get(status, "Error")
    resp = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("latin1") + body
    conn.sendall(resp)

def handle_request(method, target, headers, body_bytes):
    now_ms = int(time.time() * 1000)
    parsed = urllib.parse.urlsplit(target)
    path = parsed.path
    query = urllib.parse.parse_qs(parsed.query)
    with open(req_log_path, "a", encoding="utf-8") as logf:
        logf.write(f"{method} {path}\n")

    if method == "GET" and path == "/v1/health":
        return 200, {"ok": True, "server_now_ms": now_ms}

    # Every non-health endpoint MUST carry RFC 9421 Signature-Input + Signature.
    if "signature-input" not in headers or "signature" not in headers:
        return 401, {"error": "missing_signature"}
    if method != "GET" and "content-digest" not in headers:
        return 400, {"error": "missing_content_digest"}

    body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}

    if method == "POST" and path == "/v1/accounts/register":
        if "idempotency-key" not in headers:
            return 400, {"error": "missing_idempotency_key"}
        state["handle"] = body["handle"]
        state["root_pubkey_b64"] = body["root_pubkey_b64"]
        state["devices"] = [{
            "device_id": state["device_id"],
            "pubkey_b64": body["device_pubkey_b64"],
            "label": body["device_label"],
            "cwt_expires_ms": now_ms + 30 * 86400 * 1000,
            "generation": 1,
            "pop_verified": True,
            "created_at_ms": now_ms,
            "revoked_at_ms": None,
        }]
        return 201, {
            "account_id": state["account_id"],
            "device_id": state["device_id"],
            "handle": state["handle"],
        }

    if method == "GET" and path == "/v1/accounts/me":
        return 200, {
            "account_id": state["account_id"],
            "handle": state["handle"],
            "root_pubkey_b64": state["root_pubkey_b64"],
            "devices": state["devices"],
            "active_party_ids": list(state["parties"].keys()),
        }

    if os.path.exists(seed_friends_path):
        with open(seed_friends_path, "r", encoding="utf-8") as sf:
            seeded = json.load(sf)
        os.remove(seed_friends_path)
        for k, v in seeded.items():
            state["friends"][int(k)] = int(v)

    if method == "GET" and path == "/v1/accounts/resolve":
        h = query.get("handle", [""])[0].lower()
        handles = {
            "wingman": (1002, "wingman"),
            "phall": (1005, "phall"),
            "rivet": (1006, "rivet"),
        }
        if h in handles:
            aid, disp = handles[h]
            return 200, {
                "account_id": aid,
                "handle": disp,
                "root_pubkey_b64": wingman_pub_b64,
            }
        return 404, {"error": "not_found"}

    if method == "POST" and path == "/v1/devices":
        did = state["next_device_id"]
        state["next_device_id"] += 1
        exp_ms = now_ms + 30 * 86400 * 1000
        state["devices"].append({
            "device_id": did,
            "pubkey_b64": body["device_pubkey_b64"],
            "label": body["device_label"],
            "cwt_expires_ms": exp_ms,
            "generation": 1,
            "pop_verified": True,
            "created_at_ms": now_ms,
            "revoked_at_ms": None,
        })
        return 201, {"device_id": did, "cwt_expires_ms": exp_ms}

    if method == "DELETE" and path.startswith("/v1/devices/"):
        did = int(path.split("/")[-1])
        for d in state["devices"]:
            if d["device_id"] == did:
                d["revoked_at_ms"] = now_ms
        return 200, {"revoked": True, "evicted_parties": [], "pending_retries": 0}

    if method == "POST" and path == "/v1/accounts/recover-lookup":
        if 'keyid="rec.' not in headers.get("signature-input", ""):
            return 401, {"error": "invalid_keyid"}
        if body.get("root_pubkey_b64") != state["root_pubkey_b64"]:
            return 404, {"error": "account_not_found"}
        return 200, {
            "account_id": state["account_id"],
            "handle": state["handle"],
            "root_pubkey_b64": state["root_pubkey_b64"],
            "safety_number": "SPOOF-IGNORED-BY-CLIENT",
            "devices": state["devices"],
        }

    if method == "POST" and path == "/v1/device-links/create":
        if '.root"' not in headers.get("signature-input", ""):
            return 403, {"error": "root_key_required"}
        idx = state["link_code_idx"]
        code = state["link_codes"][idx % len(state["link_codes"])]
        state["link_code_idx"] = idx + 1
        state["device_links"][code] = {
            "status": 0,
            "suggested_label": body.get("device_label"),
            "device_pubkey_b64": None,
            "device_label": None,
            "poll_token": f"mpdl1_tok_{idx}_ABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
            "device_id": None,
            "device_cwt_b64": None,
            "cwt_expires_ms": None,
            "created_at_ms": now_ms,
            "expires_at_ms": now_ms + 300000,
        }
        return 201, {"link_code": code, "expires_at_ms": now_ms + 300000}

    if method == "POST" and path == "/v1/device-links/claim":
        if 'keyid="link.' not in headers.get("signature-input", ""):
            return 401, {"error": "invalid_keyid"}
        code = body.get("link_code", "")
        rec = state["device_links"].get(code)
        if rec is None or rec["status"] != 0:
            return 404, {"error": "invalid_or_expired_link"}
        rec["status"] = 1
        rec["device_pubkey_b64"] = body["device_pubkey_b64"]
        rec["device_label"] = body["device_label"]
        return 200, {
            "poll_token": rec["poll_token"],
            "device_fingerprint": "00000000-00000000-00000000-00000000",
            "expires_at_ms": rec["expires_at_ms"],
        }

    if method == "POST" and path == "/v1/device-links/inspect":
        if '.root"' not in headers.get("signature-input", ""):
            return 403, {"error": "root_key_required"}
        code = body.get("link_code", "")
        if state["inject_429_inspect"].pop(code, False):
            with open(req_log_path, "a", encoding="utf-8") as logf:
                logf.write("429 /v1/device-links/inspect\n")
            return 429, {"error": "rate_limited"}
        rec = state["device_links"].get(code)
        if rec is None:
            return 404, {"error": "invalid_or_expired_link"}
        if rec["status"] == 0:
            return 200, {
                "state": "waiting_for_device",
                "suggested_label": rec["suggested_label"],
                "created_at_ms": rec["created_at_ms"],
                "expires_at_ms": rec["expires_at_ms"],
            }
        return 200, {
            "state": "pending_approval",
            "device_pubkey_b64": rec["device_pubkey_b64"],
            "device_fingerprint": "ffffffff-ffffffff-ffffffff-ffffffff",
            "device_label": rec["device_label"],
            "requester_country": "US",
            "created_at_ms": rec["created_at_ms"],
            "expires_at_ms": rec["expires_at_ms"],
        }

    if method == "POST" and path == "/v1/device-links/approve":
        if '.root"' not in headers.get("signature-input", ""):
            return 403, {"error": "root_key_required"}
        code = body.get("link_code", "")
        rec = state["device_links"].get(code)
        if rec is None or rec["status"] != 1:
            return 404, {"error": "invalid_or_expired_link"}
        if body.get("device_pubkey_b64") != rec["device_pubkey_b64"]:
            return 409, {"error": "device_pubkey_mismatch"}
        did = state["next_device_id"]
        state["next_device_id"] += 1
        exp_ms = now_ms + 30 * 86400 * 1000
        rec["status"] = 2
        rec["device_id"] = did
        rec["device_label"] = body["device_label"]
        rec["device_cwt_b64"] = body["device_cwt_b64"]
        rec["cwt_expires_ms"] = exp_ms
        state["devices"].append({
            "device_id": did,
            "pubkey_b64": rec["device_pubkey_b64"],
            "label": rec["device_label"],
            "cwt_expires_ms": exp_ms,
            "generation": 1,
            "pop_verified": True,
            "created_at_ms": now_ms,
            "revoked_at_ms": None,
        })
        return 200, {
            "approved": True,
            "account_id": state["account_id"],
            "device_id": did,
            "device_label": rec["device_label"],
            "device_fingerprint": "server-fp-ignored",
            "cwt_expires_ms": exp_ms,
        }

    if method == "POST" and path == "/v1/device-links/poll":
        si = headers.get("signature-input", "")
        if 'keyid="link.' not in si:
            return 401, {"error": "invalid_keyid"}
        nonce_marker = 'nonce="'
        n_pos = si.find(nonce_marker)
        if n_pos != -1:
            n_end = si.find('"', n_pos + len(nonce_marker))
            nonce = si[n_pos + len(nonce_marker):n_end]
            if nonce in state["poll_nonces"]:
                return 401, {"error": "replay"}
            state["poll_nonces"].add(nonce)
        code = body.get("link_code", "")
        if state["inject_429_poll"].pop(code, False):
            with open(req_log_path, "a", encoding="utf-8") as logf:
                logf.write("429 /v1/device-links/poll\n")
            return 429, {"error": "rate_limited"}
        rec = state["device_links"].get(code)
        if (rec is None or body.get("poll_token") != rec["poll_token"]
                or body.get("device_pubkey_b64") != rec["device_pubkey_b64"]):
            return 404, {"error": "invalid_or_expired_link"}
        if rec["status"] < 2:
            return 202, {"status": "pending", "expires_at_ms": rec["expires_at_ms"]}
        return 200, {
            "status": "approved",
            "account_id": state["account_id"],
            "handle": state["handle"],
            "device_id": rec["device_id"],
            "root_pubkey_b64": state["root_pubkey_b64"],
            "device_cwt_b64": rec["device_cwt_b64"],
            "cwt_expires_ms": rec["cwt_expires_ms"],
            "safety_number": "SPOOF-IGNORED-BY-CLIENT",
        }

    if method == "POST" and path == "/v1/web-sessions/approve":
        uc = body.get("user_code", "")
        if uc == "WXYZ-2345":
            return 200, {
                "approved": True,
                "scope": "account:manage",
                "expires_at_ms": now_ms + 3600 * 1000,
            }
        if uc == "9999-9999":
            return 410, {"error": "expired"}
        return 404, {"error": "not_found"}

    if method == "GET" and path == "/v1/friends":
        edges = [
            {"peer_account_id": pid, "state": st, "updated_at_ms": now_ms}
            for pid, st in sorted(state["friends"].items())
        ]
        return 200, {"friends": edges}

    if method == "POST" and path == "/v1/friends/requests":
        tid = int(body["target_account_id"])
        new_state = 0 if state["friends"].get(tid) == 2 else 1
        state["friends"][tid] = new_state
        return 200, {"target_account_id": tid, "state": new_state}

    if method == "POST" and path.startswith("/v1/friends/") and path.endswith("/block"):
        tid = int(path.split("/")[3])
        state["friends"][tid] = 3
        return 200, {"blocked": True}

    if method == "DELETE" and path.startswith("/v1/friends/"):
        tid = int(path.split("/")[3])
        state["friends"].pop(tid, None)
        return 200, {"removed": True}

    if method == "POST" and path == "/v1/parties":
        pid = state["next_party_id"]
        state["next_party_id"] += 1
        relay = body.get("relay_url", "")
        state["parties"][pid] = {
            "party_id": pid,
            "party_epoch": 1,
            "leader_account_id": state["account_id"],
            "leader_device_id": state["device_id"],
            "visibility": body["visibility"],
            "join_mode": body["join_mode"],
            "relay_policy": body["relay_policy"],
            "pinned_relay_url": relay,
            "max_members": body["max_members"],
            "member_count": 1,
        }
        return 201, {"party_id": pid, "party_epoch": 1, "pinned_relay_url": relay}

    if path.startswith("/v1/parties/"):
        segs = path.split("/")
        pid = int(segs[3])
        party = state["parties"].get(pid)
        if party is None:
            return 404, {"error": "party_not_found"}
        if method == "GET" and len(segs) == 4:
            return 200, party
        if method == "POST" and len(segs) == 5 and segs[4] == "invites":
            iid = state["next_invite_id"]
            state["next_invite_id"] += 1
            return 201, {
                "party_invite_id": iid,
                "expires_at_ms": now_ms + int(body.get("ttl_sec", 3600)) * 1000,
                "invite_link": f"mppi1_{pid}_testpartysecret42",
            }
        if method == "POST" and len(segs) == 5 and segs[4] == "join":
            if body.get("invite_link") != f"mppi1_{pid}_testpartysecret42":
                return 400, {"error": "invalid_invite_link"}
            party["party_epoch"] += 1
            party["member_count"] += 1
            return 200, {"status": "joined", "party_epoch": party["party_epoch"]}
        if method == "POST" and len(segs) == 5 and segs[4] == "kick":
            if body.get("expected_party_epoch") != party["party_epoch"]:
                return 409, {"error": "epoch_mismatch"}
            party["party_epoch"] += 1
            party["member_count"] = max(1, party["member_count"] - 1)
            return 200, {"party_epoch": party["party_epoch"]}
        if method == "POST" and len(segs) == 5 and segs[4] == "leave":
            party["party_epoch"] += 1
            return 200, {"party_epoch": party["party_epoch"]}
        if method == "POST" and len(segs) == 5 and segs[4] == "disband":
            if body.get("expected_party_epoch") != party["party_epoch"]:
                return 409, {"error": "epoch_mismatch"}
            party["party_epoch"] += 1
            epoch = party["party_epoch"]
            state["parties"].pop(pid, None)
            return 200, {"party_epoch": epoch}

    return 404, {"error": "unknown_route"}

deadline = time.monotonic() + 30.0
try:
    while running and time.monotonic() < deadline:
        try:
            raw_conn, _addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            raw_conn.settimeout(5.0)
            with ctx.wrap_socket(raw_conn, server_side=True) as tls_conn:
                req = read_http_request(tls_conn)
                if req is not None:
                    status, payload = handle_request(*req)
                    send_json(tls_conn, status, payload)
        except Exception:
            pass
finally:
    srv.close()
)PY";
  write_text_file(srv_path, mock_server_py);

  int pipefd[2]{-1, -1};
  check(::pipe(pipefd) == 0, "pipe failed for mock TLS server");
  const pid_t srv_pid = ::fork();
  check(srv_pid >= 0, "fork failed for mock TLS server");
  if (srv_pid == 0) {
    (void)::close(pipefd[0]);
    (void)::dup2(pipefd[1], STDOUT_FILENO);
    (void)::close(pipefd[1]);
    std::string py = "python3";
    std::string script = srv_path.string();
    std::string crt = crt_path.string();
    std::string key = key_path.string();
    std::string pub = wingman_pub_b64;
    std::string req_log = req_log_path.string();
    char *child_argv[] = {py.data(),  script.data(),  crt.data(), key.data(),
                          pub.data(), req_log.data(), nullptr};
    ::execvp(py.c_str(), child_argv);
    ::_exit(127);
  }
  (void)::close(pipefd[1]);

  struct MockServerGuard {
    pid_t pid = -1;
    int fd = -1;
    ~MockServerGuard() {
      if (fd >= 0)
        (void)::close(fd);
      if (pid > 1) {
        (void)::kill(pid, SIGTERM);
        if (!wait_for_pid_exit(pid, std::chrono::milliseconds{1500}))
          (void)::kill(pid, SIGKILL);
        int st = 0;
        (void)::waitpid(pid, &st, 0);
      }
    }
  } srv_guard{srv_pid, pipefd[0]};

  std::string port_line;
  char ch = '\0';
  while (::read(srv_guard.fd, &ch, 1) == 1) {
    if (ch == '\n')
      break;
    port_line.push_back(ch);
  }
  (void)::close(srv_guard.fd);
  srv_guard.fd = -1;
  check(!port_line.empty(), "mock TLS 1.3 server failed to report listening port");

  const std::string port_str = port_line;
  const fs::path state_dir = base / "online-keystore";

  // 5. `online health` succeeds over TLS 1.3 and creates zero state dir!
  {
    const Value h = parse_stdout_json(
        run_cli({"online", "health", "--authority", "api.test.local", "--connect-host",
                 "127.0.0.1", "--port", port_str, "--ca-bundle", crt_path.string()}),
        "online health");
    check(std::get<bool>(req_field(h, "ok").value()) &&
              req_str(h, "authority") == "api.test.local" &&
              req_int(h, "server_now_ms") > 1000,
          "online health payload mismatch");
    check(!fs::exists(state_dir), "online health must not create state dir");
  }

  // 6. `online register`: creates 0700/0600 keystore and leaks ZERO
  // seeds/invite_secret!
  const std::string reg_secret = "mpinv1_supersecret_do_not_leak_999";
  {
    const auto reg_res =
        run_cli({"online", "register", "--invite", reg_secret, "--handle", "pilot_one",
                 "--device-label", "test-rig", "--state-dir", state_dir.string(),
                 "--authority", "api.test.local", "--connect-host", "127.0.0.1",
                 "--port", port_str, "--ca-bundle", crt_path.string()});
    const Value reg = parse_stdout_json(reg_res, "online register");
    check(std::get<bool>(req_field(reg, "registered").value()) &&
              req_int(reg, "account_id") == 1001 && req_int(reg, "device_id") == 2001 &&
              req_str(reg, "handle") == "pilot_one" &&
              req_str(reg, "authority") == "api.test.local" &&
              req_str(reg, "root_pubkey_sha256").size() == 64U,
          "online register JSON mismatch");

    // Verify 0700 directory and 0600 keystore files.
    struct stat st{};
    check(::stat(state_dir.c_str(), &st) == 0 && (st.st_mode & 0777U) == 0700U,
          "online keystore directory must have mode 0700");
    for (const char *fname :
         {"root.seed", "device.seed", "device.cwt", "identity.json"}) {
      const fs::path fpath = state_dir / fname;
      check(::stat(fpath.c_str(), &st) == 0 && (st.st_mode & 0777U) == 0600U,
            "online keystore file must have mode 0600");
    }

    // Verify ZERO invite_secret or raw/hex/b64 private seeds appear in stdout or
    // stderr!
    const auto root_seed_bytes = read_binary_file(state_dir / "root.seed");
    const auto dev_seed_bytes = read_binary_file(state_dir / "device.seed");
    check(root_seed_bytes.size() == 32U && dev_seed_bytes.size() == 32U,
          "expected 32-byte raw seeds in keystore");
    // Verify `online register` prints canonical mprk1_... Recovery Key on stderr (Spec
    // §2) while keeping stdout JSON backward-compatible and NEVER leaking raw/hex/b64
    // seeds!
    mp::Ed25519Seed reg_root_seed{};
    std::memcpy(reg_root_seed.data(), root_seed_bytes.data(), 32U);
    const auto expected_mprk1 = mp::encode_recovery_key(reg_root_seed);
    check(expected_mprk1.has_value(), "encode_recovery_key failed");
    check(reg_res.err.find(expected_mprk1.value()) != std::string::npos,
          "online register must display canonical mprk1_ recovery key on stderr");
    check(reg_res.out.find("mprk1_") == std::string::npos,
          "online register must keep stdout JSON clean of recovery key");
    const std::string combined = reg_res.out + "\n" + reg_res.err;
    for (const std::string &forbidden : std::vector<std::string>{
             reg_secret,
             mp::hex_lower(root_seed_bytes),
             mp::hex_lower(dev_seed_bytes),
             test_base64_encode(root_seed_bytes),
             test_base64_encode(dev_seed_bytes),
         }) {
      check(combined.find(forbidden) == std::string::npos,
            "online register leaked secret material to stdout/stderr");
    }

    // 6b. Preflight regression tests (dentist-2 #256):
    //   - Re-registering into an existing keystore MUST fail closed BEFORE hitting the
    //     server and preserve existing root.seed / device.seed byte-for-byte!
    //   - Registering into an insecure 0755 directory or non-directory regular file
    //     MUST fail closed BEFORE hitting the server (zero burned invites)!
    const std::string log_before = [&]() {
      std::ifstream in(req_log_path);
      return std::string{std::istreambuf_iterator<char>(in),
                         std::istreambuf_iterator<char>()};
    }();

    const std::string second_secret = "mpinv1_do_not_burn_existing_keystore";
    const auto dup_reg =
        run_cli({"online", "register", "--invite", second_secret, "--handle",
                 "pilot_two", "--state-dir", state_dir.string(), "--authority",
                 "api.test.local", "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()});
    check(dup_reg.exit_code != 0 && dup_reg.out.empty() && !dup_reg.err.empty(),
          "register into existing keystore must fail closed");
    check(dup_reg.err.find(second_secret) == std::string::npos,
          "duplicate register error must never leak invite secret");
    check(read_binary_file(state_dir / "root.seed") == root_seed_bytes &&
              read_binary_file(state_dir / "device.seed") == dev_seed_bytes,
          "register into existing keystore must preserve existing seeds byte-for-byte");

    const fs::path insecure_dir = base / "online-insecure-0755";
    fs::create_directories(insecure_dir);
    check(::chmod(insecure_dir.c_str(), mode_t{0755}) == 0, "chmod 0755 failed");
    const auto insecure_reg =
        run_cli({"online", "register", "--invite", second_secret, "--handle",
                 "pilot_two", "--state-dir", insecure_dir.string(), "--authority",
                 "api.test.local", "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()});
    check(insecure_reg.exit_code != 0 && insecure_reg.out.empty() &&
              !insecure_reg.err.empty(),
          "register into 0755 directory must fail closed");
    check(fs::is_empty(insecure_dir),
          "failed register into 0755 dir must create zero files");

    const fs::path file_as_dir = base / "online-regular-file";
    write_text_file(file_as_dir, "not-a-directory\n");
    const auto file_reg =
        run_cli({"online", "register", "--invite", second_secret, "--handle",
                 "pilot_two", "--state-dir", file_as_dir.string(), "--authority",
                 "api.test.local", "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()});
    check(file_reg.exit_code != 0 && file_reg.out.empty() && !file_reg.err.empty(),
          "register into non-directory regular file must fail closed");

    const std::string log_after = [&]() {
      std::ifstream in(req_log_path);
      return std::string{std::istreambuf_iterator<char>(in),
                         std::istreambuf_iterator<char>()};
    }();
    check(
        log_before == log_after,
        "preflight register failures must make ZERO HTTP requests (no burned invites)");
  }

  // 7. `online whoami --local` works offline without hitting the network, and leaks no
  //    seeds.
  {
    const auto local_res =
        run_cli({"online", "whoami", "--local", "--state-dir", state_dir.string()});
    const Value loc = parse_stdout_json(local_res, "online whoami --local");
    check(std::get<bool>(req_field(loc, "local").value()) &&
              std::get<bool>(req_field(loc, "registered").value()) &&
              std::get<bool>(req_field(loc, "has_root_key").value()) &&
              req_int(loc, "account_id") == 1001 && req_int(loc, "device_id") == 2001 &&
              req_str(loc, "handle") == "pilot_one" &&
              req_str(loc, "authority") == "api.test.local",
          "online whoami --local mismatch");
    const auto root_seed_bytes = read_binary_file(state_dir / "root.seed");
    const auto dev_seed_bytes = read_binary_file(state_dir / "device.seed");
    check(local_res.out.find(mp::hex_lower(root_seed_bytes)) == std::string::npos &&
              local_res.out.find(mp::hex_lower(dev_seed_bytes)) == std::string::npos,
          "online whoami --local leaked seed");
  }

  // 8. `online whoami` (networked, using stored authority from keystore!).
  {
    const Value me = parse_stdout_json(
        run_cli({"online", "whoami", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online whoami");
    check(req_int(me, "account_id") == 1001 && req_str(me, "handle") == "pilot_one" &&
              req_field(me, "devices").array().size() == 1U,
          "online whoami response mismatch");
  }

  // 9. `online resolve wingman`
  {
    const Value resolved = parse_stdout_json(
        run_cli({"online", "resolve", "wingman", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online resolve");
    check(req_int(resolved, "account_id") == 1002 &&
              req_str(resolved, "handle") == "wingman" &&
              req_str(resolved, "root_pubkey_b64") == wingman_pub_b64,
          "online resolve mismatch");
  }

  // 10. `online devices enroll` & `online devices revoke`
  {
    const Value enrolled = parse_stdout_json(
        run_cli({"online", "devices", "enroll", "--label", "laptop", "--pubkey-b64",
                 extra_dev_pub_b64, "--state-dir", state_dir.string(), "--connect-host",
                 "127.0.0.1", "--port", port_str, "--ca-bundle", crt_path.string()}),
        "online devices enroll");
    check(std::get<bool>(req_field(enrolled, "enrolled").value()) &&
              req_int(enrolled, "device_id") == 2002 &&
              req_str(enrolled, "label") == "laptop",
          "online devices enroll mismatch");

    const Value revoked = parse_stdout_json(
        run_cli({"online", "devices", "revoke", "2002", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online devices revoke");
    check(std::get<bool>(req_field(revoked, "revoked").value()) &&
              req_int(revoked, "device_id") == 2002,
          "online devices revoke mismatch");
  }

  // 11. `online friends list / add / accept / deny / decline / block / remove`
  //     (both handles and numeric account_ids, plus summary counts)
  {
    const Value empty_list = parse_stdout_json(
        run_cli({"online", "friends", "list", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online friends list initial");
    check(req_int(empty_list, "count") == 0 &&
              req_int(empty_list, "friend_count") == 0 &&
              req_int(empty_list, "pending_received_count") == 0 &&
              req_int(empty_list, "pending_sent_count") == 0 &&
              req_int(empty_list, "blocked_count") == 0,
          "expected 0 initial friends and summary counts");

    // Add via handle (auto-resolves wingman -> 1002)
    const Value added_handle = parse_stdout_json(
        run_cli({"online", "friends", "add", "wingman", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online friends add handle");
    check(req_int(added_handle, "target_account_id") == 1002 &&
              req_str(added_handle, "state") == "invite_sent" &&
              req_str(added_handle, "handle") == "wingman",
          "online friends add by handle mismatch");

    // Add via numeric account_id
    const Value added_num = parse_stdout_json(
        run_cli({"online", "friends", "add", "1003", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online friends add numeric");
    check(req_int(added_num, "target_account_id") == 1003 &&
              req_str(added_num, "state") == "invite_sent",
          "online friends add numeric mismatch");

    const Value blocked = parse_stdout_json(
        run_cli({"online", "friends", "block", "1002", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online friends block");
    check(std::get<bool>(req_field(blocked, "blocked").value()) &&
              req_int(blocked, "target_account_id") == 1002 &&
              req_int(blocked, "account_id") == 1002,
          "online friends block mismatch");

    const Value removed = parse_stdout_json(
        run_cli({"online", "friends", "remove", "1003", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online friends remove");
    check(std::get<bool>(req_field(removed, "removed").value()) &&
              req_int(removed, "target_account_id") == 1003 &&
              req_int(removed, "account_id") == 1003,
          "online friends remove mismatch");

    const Value final_list = parse_stdout_json(
        run_cli({"online", "friends", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online friends default list");
    check(req_int(final_list, "count") == 1 &&
              req_int(final_list, "friend_count") == 0 &&
              req_int(final_list, "pending_received_count") == 0 &&
              req_int(final_list, "pending_sent_count") == 0 &&
              req_int(final_list, "blocked_count") == 1,
          "expected 1 blocked edge remaining");
    const auto &first_edge = req_field(final_list, "friends").array().at(0);
    check(req_int(first_edge, "peer_account_id") == 1002 &&
              req_str(first_edge, "state") == "blocked",
          "remaining friend edge mismatch");

    // Seed incoming pending requests (state=2) + outgoing pending (state=1) to verify
    // accept, deny, decline, remove-by-handle, block-by-handle, and summary counts.
    write_text_file(tls_dir / "seed_friends.json",
                    R"({"1005": 2, "1006": 2, "1007": 2, "1008": 2, "1009": 1})");

    const Value pending_list = parse_stdout_json(
        run_cli({"online", "friends", "list", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online friends list with pending");
    check(req_int(pending_list, "count") == 6 &&
              req_int(pending_list, "friend_count") == 0 &&
              req_int(pending_list, "pending_received_count") == 4 &&
              req_int(pending_list, "pending_sent_count") == 1 &&
              req_int(pending_list, "blocked_count") == 1,
          "friends list summary counts mismatch");

    // Accept incoming request by handle (phall -> 1005 -> state=friend)
    const Value acc_handle = parse_stdout_json(
        run_cli({"online", "friends", "accept", "phall", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online friends accept handle");
    check(req_int(acc_handle, "account_id") == 1005 &&
              req_str(acc_handle, "handle") == "phall" &&
              req_str(acc_handle, "state") == "friend" &&
              req_str(acc_handle, "action") == "accept",
          "online friends accept by handle mismatch");

    // Accept incoming request by numeric account_id (1007 -> state=friend)
    const Value acc_num = parse_stdout_json(
        run_cli({"online", "friends", "accept", "1007", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online friends accept numeric");
    check(req_int(acc_num, "account_id") == 1007 &&
              std::holds_alternative<std::nullptr_t>(
                  req_field(acc_num, "handle").value()) &&
              req_str(acc_num, "state") == "friend" &&
              req_str(acc_num, "action") == "accept",
          "online friends accept numeric mismatch");

    // Deny incoming request by handle (rivet -> 1006)
    const Value denied_handle = parse_stdout_json(
        run_cli({"online", "friends", "deny", "rivet", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online friends deny handle");
    check(req_int(denied_handle, "account_id") == 1006 &&
              req_str(denied_handle, "handle") == "rivet" &&
              std::get<bool>(req_field(denied_handle, "denied").value()),
          "online friends deny by handle mismatch");

    // Decline alias by numeric account_id (1008)
    const Value declined_num = parse_stdout_json(
        run_cli({"online", "friends", "decline", "1008", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online friends decline numeric");
    check(req_int(declined_num, "account_id") == 1008 &&
              std::holds_alternative<std::nullptr_t>(
                  req_field(declined_num, "handle").value()) &&
              std::get<bool>(req_field(declined_num, "denied").value()),
          "online friends decline numeric mismatch");

    const Value after_triage = parse_stdout_json(
        run_cli({"online", "friends", "list", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online friends list after triage");
    check(req_int(after_triage, "count") == 4 &&
              req_int(after_triage, "friend_count") == 2 &&
              req_int(after_triage, "pending_received_count") == 0 &&
              req_int(after_triage, "pending_sent_count") == 1 &&
              req_int(after_triage, "blocked_count") == 1,
          "friends list counts after accept/deny/decline mismatch");

    // Remove by handle (phall -> 1005)
    const Value removed_handle = parse_stdout_json(
        run_cli({"online", "friends", "remove", "phall", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online friends remove handle");
    check(std::get<bool>(req_field(removed_handle, "removed").value()) &&
              req_int(removed_handle, "target_account_id") == 1005 &&
              req_int(removed_handle, "account_id") == 1005 &&
              req_str(removed_handle, "handle") == "phall",
          "online friends remove by handle mismatch");

    // Block by handle (wingman -> 1002)
    const Value blocked_handle = parse_stdout_json(
        run_cli({"online", "friends", "block", "wingman", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online friends block handle");
    check(std::get<bool>(req_field(blocked_handle, "blocked").value()) &&
              req_int(blocked_handle, "target_account_id") == 1002 &&
              req_int(blocked_handle, "account_id") == 1002 &&
              req_str(blocked_handle, "handle") == "wingman",
          "online friends block by handle mismatch");
  }

  // 12. `online party create / info / invite / join / kick / leave / disband`
  {
    const Value created = parse_stdout_json(
        run_cli({"online", "party", "create", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online party create");
    check(req_int(created, "party_id") == 5001 &&
              req_int(created, "party_epoch") == 1 &&
              req_str(created, "pinned_relay_url") == "https://relay.multiplayer.tech",
          "online party create defaults mismatch");

    const Value info = parse_stdout_json(
        run_cli({"online", "party", "info", "5001", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online party info");
    check(req_int(info, "party_id") == 5001 && req_int(info, "party_epoch") == 1 &&
              req_str(info, "visibility") == "friends" &&
              req_str(info, "join_mode") == "invite" &&
              req_str(info, "relay_policy") == "force" &&
              req_int(info, "max_members") == 4,
          "online party info defaults mismatch");

    const Value inv = parse_stdout_json(
        run_cli({"online", "party", "invite", "5001", "--max-uses", "2", "--ttl-s",
                 "600", "--state-dir", state_dir.string(), "--connect-host",
                 "127.0.0.1", "--port", port_str, "--ca-bundle", crt_path.string()}),
        "online party invite");
    const std::string invite_link = req_str(inv, "invite_link");
    check(req_int(inv, "party_invite_id") == 7001 &&
              invite_link == "mppi1_5001_testpartysecret42",
          "online party invite mismatch");

    // Auto-parse `mppi1_<party_id>_<secret>` link cleanly, and never echo the secret
    // back!
    const auto join_res =
        run_cli({"online", "party", "join", invite_link, "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()});
    const Value joined = parse_stdout_json(join_res, "online party join");
    check(req_int(joined, "party_id") == 5001 &&
              req_str(joined, "status") == "joined" &&
              !std::get<bool>(req_field(joined, "pending_approval").value()) &&
              req_int(joined, "party_epoch") == 2,
          "online party join mismatch");
    check(join_res.out.find("testpartysecret42") == std::string::npos &&
              join_res.err.find("testpartysecret42") == std::string::npos,
          "online party join must not leak invite secret");

    // `--epoch 0` must fail closed with usage exit code 2 on both kick and disband.
    const auto bad_kick_epoch =
        run_cli({"online", "party", "kick", "5001", "1002", "--epoch", "0",
                 "--state-dir", state_dir.string()});
    check(bad_kick_epoch.exit_code == 2 && bad_kick_epoch.out.empty() &&
              !bad_kick_epoch.err.empty(),
          "online party kick --epoch 0 must exit 2");
    const auto bad_disband_epoch =
        run_cli({"online", "party", "disband", "5001", "--epoch", "0", "--state-dir",
                 state_dir.string()});
    check(bad_disband_epoch.exit_code == 2 && bad_disband_epoch.out.empty() &&
              !bad_disband_epoch.err.empty(),
          "online party disband --epoch 0 must exit 2");

    // `kick` without `--epoch` fetches current epoch (2) first and advances to 3!
    const Value kicked = parse_stdout_json(
        run_cli({"online", "party", "kick", "5001", "1002", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online party kick");
    check(std::get<bool>(req_field(kicked, "kicked").value()) &&
              req_int(kicked, "party_id") == 5001 &&
              req_int(kicked, "target_account_id") == 1002 &&
              req_int(kicked, "party_epoch") == 3,
          "online party kick auto-epoch mismatch");

    const Value left = parse_stdout_json(
        run_cli({"online", "party", "leave", "5001", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online party leave");
    check(std::get<bool>(req_field(left, "left").value()) &&
              req_int(left, "party_id") == 5001 && req_int(left, "party_epoch") == 4,
          "online party leave mismatch");

    // `disband` without `--epoch` fetches current epoch (4) first and advances to 5!
    const Value disbanded = parse_stdout_json(
        run_cli({"online", "party", "disband", "5001", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()}),
        "online party disband");
    check(std::get<bool>(req_field(disbanded, "disbanded").value()) &&
              req_int(disbanded, "party_id") == 5001 &&
              req_int(disbanded, "party_epoch") == 5,
          "online party disband auto-epoch mismatch");
  }

  // 13. `online web-approve`: lowercase normalization, invalid Crockford rejection
  //     before network, and 410 Gone error handling.
  {
    const Value approved = parse_stdout_json(
        run_cli({"online", "web-approve", "wxyz2345", "--state-dir", state_dir.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "online web-approve");
    check(std::get<bool>(req_field(approved, "approved").value()) &&
              req_str(approved, "user_code") == "WXYZ-2345" &&
              req_str(approved, "scope") == "account:manage" &&
              req_int(approved, "expires_at_ms") > 1000,
          "online web-approve JSON mismatch");

    const std::string log_before_bad = [&]() {
      std::ifstream in(req_log_path);
      return std::string{std::istreambuf_iterator<char>(in),
                         std::istreambuf_iterator<char>()};
    }();
    const auto bad_code =
        run_cli({"online", "web-approve", "ABCD-EFGI", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()});
    check(bad_code.exit_code == 2 && bad_code.out.empty() && !bad_code.err.empty(),
          "invalid Crockford code must fail with exit 2");
    const std::string log_after_bad = [&]() {
      std::ifstream in(req_log_path);
      return std::string{std::istreambuf_iterator<char>(in),
                         std::istreambuf_iterator<char>()};
    }();
    check(log_before_bad == log_after_bad,
          "invalid web-approve code must make ZERO HTTP requests");

    const auto expired =
        run_cli({"online", "web-approve", "9999-9999", "--state-dir",
                 state_dir.string(), "--connect-host", "127.0.0.1", "--port", port_str,
                 "--ca-bundle", crt_path.string()});
    check(expired.exit_code == 1 && expired.out.empty() &&
              expired.err.find("http_gone") != std::string::npos,
          "410 web-approve must report http_gone cleanly");
  }

  // 14. Full 2-machine secondary-device linking WITHOUT root-key copying:
  //     Machine B `devices init` -> Machine A `devices enroll` ->
  //     Machine B `devices install-cwt` -> Machine B `whoami --local` + live `whoami`
  //     (with ZERO root.seed on Machine B!), plus negative tests!
  {
    const fs::path state_dir_b = base / "online-machine-b";

    // Step A: Machine B runs `devices init` (offline, device_seed ONLY).
    const auto init_res =
        run_cli({"online", "devices", "init", "--label", "work-box", "--state-dir",
                 state_dir_b.string(), "--authority", "api.test.local"});
    const Value init_json = parse_stdout_json(init_res, "online devices init");
    const std::string dev_b_pub_b64 = req_str(init_json, "device_pubkey_b64");
    check(std::get<bool>(req_field(init_json, "initialized").value()) &&
              req_str(init_json, "authority") == "api.test.local" &&
              req_str(init_json, "device_pubkey_sha256").size() == 64U &&
              req_str(init_json, "next_step")
                      .find("blackbird online devices enroll --label work-box "
                            "--pubkey-b64 " +
                            dev_b_pub_b64) != std::string::npos,
          "online devices init JSON mismatch");

    // Verify 0700/0600 perms, NO root.seed, and ZERO raw seed leakage!
    struct stat st{};
    check(::stat(state_dir_b.c_str(), &st) == 0 && (st.st_mode & 0777U) == 0700U,
          "machine B keystore dir must be 0700");
    check(!fs::exists(state_dir_b / "root.seed"),
          "machine B must NOT have root.seed after devices init");
    const auto dev_b_seed = read_binary_file(state_dir_b / "device.seed");
    check(dev_b_seed.size() == 32U, "machine B device.seed must be 32 bytes");
    const std::string init_combined = init_res.out + "\n" + init_res.err;
    check(init_combined.find(mp::hex_lower(dev_b_seed)) == std::string::npos &&
              init_combined.find(test_base64_encode(dev_b_seed)) == std::string::npos,
          "devices init must NEVER leak raw device_seed");

    // Negative test: running `devices init` again on existing keystore MUST fail closed
    // and preserve device.seed byte-for-byte!
    const auto dup_init =
        run_cli({"online", "devices", "init", "--label", "clobber", "--state-dir",
                 state_dir_b.string(), "--authority", "api.test.local"});
    check(dup_init.exit_code != 0 && dup_init.out.empty() && !dup_init.err.empty(),
          "devices init must refuse existing keystore");
    check(read_binary_file(state_dir_b / "device.seed") == dev_b_seed,
          "duplicate devices init must preserve existing device.seed byte-for-byte");

    // Step B: Machine A (root keystore) enrolls Machine B's pubkey and emits
    // device_cwt_b64 + root_pubkey_b64 + copy-pasteable install_cwt_command (zero
    // root_seed!).
    const auto enroll_res =
        run_cli({"online", "devices", "enroll", "--label", "work-box", "--pubkey-b64",
                 dev_b_pub_b64, "--state-dir", state_dir.string(), "--connect-host",
                 "127.0.0.1", "--port", port_str, "--ca-bundle", crt_path.string()});
    const Value enroll_json = parse_stdout_json(enroll_res, "machine A devices enroll");
    const std::int64_t dev_b_id = req_int(enroll_json, "device_id");
    const std::string dev_b_cwt_b64 = req_str(enroll_json, "device_cwt_b64");
    const std::string root_pub_b64 = req_str(enroll_json, "root_pubkey_b64");
    const std::string install_cmd = req_str(enroll_json, "install_cwt_command");
    check(std::get<bool>(req_field(enroll_json, "enrolled").value()) &&
              req_int(enroll_json, "account_id") == 1001 &&
              req_str(enroll_json, "handle") == "pilot_one" && !dev_b_cwt_b64.empty() &&
              !root_pub_b64.empty() &&
              install_cmd.find("blackbird online devices install-cwt") !=
                  std::string::npos &&
              install_cmd.find(dev_b_cwt_b64) != std::string::npos,
          "devices enroll enhanced JSON mismatch");
    const auto root_seed_a = read_binary_file(state_dir / "root.seed");
    const std::string enroll_combined = enroll_res.out + "\n" + enroll_res.err;
    check(enroll_combined.find(mp::hex_lower(root_seed_a)) == std::string::npos &&
              enroll_combined.find(test_base64_encode(root_seed_a)) ==
                  std::string::npos,
          "devices enroll must NEVER leak root_seed");

    // Negative test: Machine B `devices install-cwt` MUST reject a CWT minted for a
    // DIFFERENT device_pubkey without modifying disk!
    const auto wrong_dev_enroll = parse_stdout_json(
        run_cli({"online", "devices", "enroll", "--label", "other-box", "--pubkey-b64",
                 extra_dev_pub_b64, "--state-dir", state_dir.string(), "--connect-host",
                 "127.0.0.1", "--port", port_str, "--ca-bundle", crt_path.string()}),
        "enroll mismatched device for negative test");
    const std::string wrong_cwt_b64 = req_str(wrong_dev_enroll, "device_cwt_b64");
    const auto bad_install =
        run_cli({"online", "devices", "install-cwt", "--account-id", "1001",
                 "--device-id", std::to_string(dev_b_id), "--handle", "pilot_one",
                 "--cwt-b64", wrong_cwt_b64, "--state-dir", state_dir_b.string()});
    check(bad_install.exit_code != 0 && bad_install.out.empty() &&
              !bad_install.err.empty(),
          "devices install-cwt must reject CWT for mismatched device_pubkey");
    const Value loc_after_bad = parse_stdout_json(
        run_cli({"online", "whoami", "--local", "--state-dir", state_dir_b.string()}),
        "machine B whoami --local after rejected install-cwt");
    check(!std::get<bool>(req_field(loc_after_bad, "registered").value()) &&
              req_int(loc_after_bad, "device_cwt_bytes") == 0,
          "rejected install-cwt must NOT modify machine B keystore on disk");

    // Negative test: wrong --root-pubkey-b64 MUST also be rejected!
    const auto bad_root_install = run_cli(
        {"online", "devices", "install-cwt", "--account-id", "1001", "--device-id",
         std::to_string(dev_b_id), "--handle", "pilot_one", "--cwt-b64", dev_b_cwt_b64,
         "--root-pubkey-b64", wingman_pub_b64, "--state-dir", state_dir_b.string()});
    check(bad_root_install.exit_code != 0 && bad_root_install.out.empty() &&
              !bad_root_install.err.empty(),
          "devices install-cwt must reject wrong --root-pubkey-b64");

    // Step C: Machine B installs its valid CWT (with full --root-pubkey-b64 signature
    // verification).
    const Value installed = parse_stdout_json(
        run_cli({"online", "devices", "install-cwt", "--account-id", "1001",
                 "--device-id", std::to_string(dev_b_id), "--handle", "pilot_one",
                 "--cwt-b64", dev_b_cwt_b64, "--root-pubkey-b64", root_pub_b64,
                 "--state-dir", state_dir_b.string()}),
        "machine B devices install-cwt");
    check(std::get<bool>(req_field(installed, "installed").value()) &&
              req_int(installed, "account_id") == 1001 &&
              req_int(installed, "device_id") == dev_b_id &&
              req_str(installed, "handle") == "pilot_one" &&
              req_str(installed, "authority") == "api.test.local" &&
              req_str(installed, "device_pubkey_sha256").size() == 64U &&
              req_int(installed, "device_cwt_bytes") > 0,
          "machine B devices install-cwt JSON mismatch");
    check(!fs::exists(state_dir_b / "root.seed"),
          "machine B must STILL have zero root.seed after install-cwt");

    // Step D: Machine B `whoami --local` + live `whoami` + live `web-approve` all work
    // with ZERO root key on Machine B!
    const Value loc_b = parse_stdout_json(
        run_cli({"online", "whoami", "--local", "--state-dir", state_dir_b.string()}),
        "machine B whoami --local");
    check(std::get<bool>(req_field(loc_b, "registered").value()) &&
              !std::get<bool>(req_field(loc_b, "has_root_key").value()) &&
              req_int(loc_b, "account_id") == 1001 &&
              req_int(loc_b, "device_id") == dev_b_id &&
              req_str(loc_b, "handle") == "pilot_one" &&
              req_int(loc_b, "device_cwt_bytes") > 0,
          "machine B whoami --local mismatch");

    const Value live_b = parse_stdout_json(
        run_cli({"online", "whoami", "--state-dir", state_dir_b.string(),
                 "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                 crt_path.string()}),
        "machine B live whoami");
    check(req_int(live_b, "account_id") == 1001 &&
              req_str(live_b, "handle") == "pilot_one",
          "machine B live whoami mismatch");

    const Value web_b = parse_stdout_json(
        run_cli({"online", "web-approve", "WXYZ-2345", "--state-dir",
                 state_dir_b.string(), "--connect-host", "127.0.0.1", "--port",
                 port_str, "--ca-bundle", crt_path.string()}),
        "machine B live web-approve");
    check(std::get<bool>(req_field(web_b, "approved").value()) &&
              req_str(web_b, "user_code") == "WXYZ-2345",
          "machine B live web-approve mismatch");

    // Regression test (dentist-2 #272): shell metacharacters, spaces, and single quotes
    // in `--label` MUST be POSIX single-quoted in `devices init`'s `next_step`!
    const fs::path state_dir_quoted = base / "online-machine-quoted";
    const Value quoted_init = parse_stdout_json(
        run_cli({"online", "devices", "init", "--label", "Work's $(id) Laptop",
                 "--state-dir", state_dir_quoted.string(), "--authority",
                 "api.test.local"}),
        "devices init shell-quoted label");
    const std::string quoted_pk = req_str(quoted_init, "device_pubkey_b64");
    check(
        req_str(quoted_init, "next_step")
                .find("--label 'Work'\\''s $(id) Laptop' --pubkey-b64 " + quoted_pk) !=
            std::string::npos,
        "devices init next_step must POSIX shell-quote --label with spaces/quotes/$()");

    // 15. Identity Portability v1 E2E:
    //     (a) `online recovery-key` (primary succeeds, secondary fails closed)
    //     (b) 2-step `devices link create --no-wait` <-> `devices link join` <->
    //     `approve` (c) 1-command concurrent `devices link create` <-> `devices link
    //     join` (d) `export-mpkey --passphrase-stdin` -> `recover --mpkey
    //     --passphrase-stdin` (e) `mprk1_...` stdin `recover` roundtrip (f) ZERO
    //     secrets accepted on argv (exit 2, zero echo!)
    {
      const auto orig_root_bytes = read_binary_file(state_dir / "root.seed");
      check(orig_root_bytes.size() == 32U, "expected 32-byte primary root.seed");
      mp::Ed25519Seed orig_root_seed{};
      std::memcpy(orig_root_seed.data(), orig_root_bytes.data(), 32U);
      const std::string expected_mprk = mp::encode_recovery_key(orig_root_seed).value();
      const auto orig_root_key =
          mp::Ed25519SigningKey::from_seed(orig_root_seed).value();
      const std::string expected_sn =
          mp::compute_safety_number(mp::AccountId::create(1001U).value(),
                                    orig_root_key.public_key())
              .value();

      // (a) `online recovery-key` displays exact mprk1_ on primary, refuses secondary!
      const auto rk_primary =
          run_cli({"online", "recovery-key", "--state-dir", state_dir.string()});
      check(rk_primary.exit_code == 0 && rk_primary.out == expected_mprk + "\n",
            "online recovery-key on primary must output exact mprk1_");
      const auto rk_secondary =
          run_cli({"online", "recovery-key", "--state-dir", state_dir_b.string()});
      check(rk_secondary.exit_code != 0 && rk_secondary.out.empty() &&
                rk_secondary.err.find("missing_root_key") != std::string::npos,
            "online recovery-key on secondary device must fail with missing_root_key");

      // (b) 2-step Device Linking: create --no-wait -> join (thread) -> approve --yes!
      const fs::path state_dir_c = base / "online-machine-c";
      const auto create_nw_res =
          run_cli({"online", "devices", "link", "create", "--label", "lap-c",
                   "--no-wait", "--state-dir", state_dir.string(), "--connect-host",
                   "127.0.0.1", "--port", port_str, "--ca-bundle", crt_path.string()});
      const Value create_nw =
          parse_stdout_json(create_nw_res, "devices link create --no-wait");
      const std::string code1 = req_str(create_nw, "link_code");
      check(code1 == "W4K9-M2P7" &&
                req_str(create_nw, "join_command")
                        .find("blackbird online devices link join W4K9-M2P7 --label "
                              "lap-c") != std::string::npos &&
                create_nw_res.err.find(code1) != std::string::npos,
            "devices link create --no-wait output mismatch");

      // Start `devices link join` in a background thread so it claims + polls 202->200!
      CliResult join_c_res{};
      std::thread join_c_thread([&]() {
        join_c_res = run_cli({"online",
                              "devices",
                              "link",
                              "join",
                              "w4k9m2p7",
                              "--label",
                              "lap-c",
                              "--poll-ms",
                              "50",
                              "--timeout-s",
                              "15",
                              "--state-dir",
                              state_dir_c.string(),
                              "--authority",
                              "api.test.local",
                              "--connect-host",
                              "127.0.0.1",
                              "--port",
                              port_str,
                              "--ca-bundle",
                              crt_path.string()});
      });

      // Wait briefly until the new machine has claimed, then run `devices link
      // approve`!
      CliResult approve_c_res{};
      for (int attempt = 0; attempt < 40; ++attempt) {
        approve_c_res =
            run_cli({"online", "devices", "link", "approve", code1, "--yes",
                     "--state-dir", state_dir.string(), "--connect-host", "127.0.0.1",
                     "--port", port_str, "--ca-bundle", crt_path.string()});
        if (approve_c_res.exit_code == 0)
          break;
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
      }
      join_c_thread.join();

      const Value approved_c =
          parse_stdout_json(approve_c_res, "devices link approve --yes");
      const Value joined_c = parse_stdout_json(join_c_res, "devices link join");
      const std::string fp_c_approve = req_str(approved_c, "device_fingerprint");
      const std::string fp_c_join = req_str(joined_c, "device_fingerprint");
      check(std::get<bool>(req_field(approved_c, "approved").value()) &&
                std::get<bool>(req_field(joined_c, "linked").value()) &&
                fp_c_approve.size() == mp::kDeviceFingerprintFormattedLength &&
                fp_c_approve == fp_c_join &&
                fp_c_join != "00000000-00000000-00000000-00000000" &&
                fp_c_approve != "ffffffff-ffffffff-ffffffff-ffffffff" &&
                req_str(joined_c, "handle") == "pilot_one" &&
                req_str(joined_c, "safety_number") == expected_sn &&
                join_c_res.err.find("@pilot_one") != std::string::npos &&
                join_c_res.err.find(expected_sn) != std::string::npos &&
                approve_c_res.err.find(fp_c_approve) != std::string::npos &&
                approve_c_res.err.find("US") != std::string::npos,
            "2-step device link create/join/approve verification mismatch");
      check(!fs::exists(state_dir_c / "root.seed"),
            "linked machine C must NEVER receive root.seed");

      // Machine C can immediately call live `whoami` with its installed CWT!
      const Value whoami_c = parse_stdout_json(
          run_cli({"online", "whoami", "--state-dir", state_dir_c.string(),
                   "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                   crt_path.string()}),
          "machine C live whoami after link join");
      check(req_int(whoami_c, "account_id") == 1001 &&
                req_str(whoami_c, "handle") == "pilot_one",
            "machine C live whoami mismatch");

      // Negative: `devices link join` MUST refuse to clobber existing registered
      // keystore!
      const auto clobber_join =
          run_cli({"online", "devices", "link", "join", "A2B3-C4D5", "--label", "nope",
                   "--state-dir", state_dir_c.string(), "--authority", "api.test.local",
                   "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                   crt_path.string()});
      check(clobber_join.exit_code != 0 && clobber_join.out.empty() &&
                !clobber_join.err.empty(),
            "devices link join must refuse to overwrite registered keystore");

      // Negative: secondary machine CANNOT run `devices link create`!
      const auto sec_create =
          run_cli({"online", "devices", "link", "create", "--no-wait", "--state-dir",
                   state_dir_c.string(), "--connect-host", "127.0.0.1", "--port",
                   port_str, "--ca-bundle", crt_path.string()});
      check(sec_create.exit_code != 0 && sec_create.out.empty() &&
                sec_create.err.find("missing_root_key") != std::string::npos,
            "devices link create on secondary device must fail with missing_root_key");

      // (c) 1-command concurrent waiting `devices link create` (interactive "y\n" on
      // io.in)
      //     <-> `devices link join` (next link code A2B3-C4D5)!
      const fs::path state_dir_d = base / "online-machine-d";
      CliResult create_d_res{};
      std::thread create_d_thread([&]() {
        create_d_res =
            run_cli({"online", "devices", "link", "create", "--label", "lap-d",
                     "--poll-ms", "50", "--timeout-s", "15", "--state-dir",
                     state_dir.string(), "--connect-host", "127.0.0.1", "--port",
                     port_str, "--ca-bundle", crt_path.string()},
                    "y\n");
      });

      CliResult join_d_res{};
      for (int attempt = 0; attempt < 40; ++attempt) {
        join_d_res = run_cli({"online",
                              "devices",
                              "link",
                              "join",
                              "A2B3-C4D5",
                              "--label",
                              "lap-d",
                              "--poll-ms",
                              "50",
                              "--timeout-s",
                              "15",
                              "--state-dir",
                              state_dir_d.string(),
                              "--authority",
                              "api.test.local",
                              "--connect-host",
                              "127.0.0.1",
                              "--port",
                              port_str,
                              "--ca-bundle",
                              crt_path.string()});
        if (join_d_res.exit_code == 0)
          break;
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
      }
      create_d_thread.join();

      const Value created_d =
          parse_stdout_json(create_d_res, "1-command devices link create");
      const Value joined_d =
          parse_stdout_json(join_d_res, "1-command devices link join");
      check(std::get<bool>(req_field(created_d, "approved").value()) &&
                std::get<bool>(req_field(joined_d, "linked").value()) &&
                req_str(created_d, "device_fingerprint") ==
                    req_str(joined_d, "device_fingerprint") &&
                req_str(joined_d, "safety_number") == expected_sn &&
                !fs::exists(state_dir_d / "root.seed"),
            "1-command concurrent devices link create/join mismatch");
      {
        std::ifstream log_in(req_log_path);
        const std::string req_log{std::istreambuf_iterator<char>(log_in),
                                  std::istreambuf_iterator<char>()};
        check(req_log.find("429 /v1/device-links/inspect") != std::string::npos &&
                  req_log.find("429 /v1/device-links/poll") != std::string::npos,
              "both inspect and poll must survive HTTP 429 rate_limited via backoff");
      }

      // (d) `export-mpkey` -> mode 0600 + symlink refusal -> `recover --mpkey`
      // roundtrip!
      const fs::path mpkey_path = base / "backup.mpkey";
      const std::string backup_pass = "correct-horse-battery-staple-42!";
      const auto export_res =
          run_cli({"online", "export-mpkey", "--out", mpkey_path.string(),
                   "--passphrase-stdin", "--state-dir", state_dir.string()},
                  backup_pass + "\n");
      const Value exported = parse_stdout_json(export_res, "online export-mpkey");
      check(std::get<bool>(req_field(exported, "exported").value()) &&
                req_int(exported, "account_id") == 1001 &&
                req_str(exported, "handle") == "pilot_one" &&
                req_int(exported, "bytes") > 100,
            "online export-mpkey JSON mismatch");
      struct stat mpkey_st{};
      check(::lstat(mpkey_path.c_str(), &mpkey_st) == 0 &&
                (mpkey_st.st_mode & 0777U) == 0600U,
            ".mpkey file must have mode 0600");
      check((export_res.out + export_res.err).find(backup_pass) == std::string::npos &&
                (export_res.out + export_res.err).find(expected_mprk) ==
                    std::string::npos,
            "export-mpkey must never leak passphrase or recovery key");

      // Symlink --out MUST be refused!
      const fs::path mpkey_symlink = base / "symlink.mpkey";
      fs::create_symlink(mpkey_path, mpkey_symlink);
      const auto bad_sym_export =
          run_cli({"online", "export-mpkey", "--out", mpkey_symlink.string(),
                   "--passphrase-stdin", "--state-dir", state_dir.string()},
                  backup_pass + "\n");
      check(bad_sym_export.exit_code != 0 && bad_sym_export.out.empty(),
            "export-mpkey must refuse symlink --out");

      // Recover from .mpkey into a fresh machine state dir!
      const fs::path recovered_mpkey_dir = base / "online-recovered-mpkey";
      const auto rec_mpkey_res =
          run_cli({"online", "recover", "--mpkey", mpkey_path.string(),
                   "--passphrase-stdin", "--device-label", "rescue-mpkey",
                   "--state-dir", recovered_mpkey_dir.string(), "--authority",
                   "api.test.local", "--connect-host", "127.0.0.1", "--port", port_str,
                   "--ca-bundle", crt_path.string()},
                  backup_pass + "\n");
      const Value rec_mpkey =
          parse_stdout_json(rec_mpkey_res, "online recover --mpkey");
      check(
          std::get<bool>(req_field(rec_mpkey, "recovered").value()) &&
              req_int(rec_mpkey, "account_id") == 1001 &&
              req_str(rec_mpkey, "handle") == "pilot_one" &&
              req_str(rec_mpkey, "safety_number") == expected_sn &&
              std::get<Value::Array>(req_field(rec_mpkey, "devices").value()).size() >=
                  2U,
          "online recover --mpkey JSON mismatch");
      check(read_binary_file(recovered_mpkey_dir / "root.seed") == orig_root_bytes,
            "recovered .mpkey keystore must restore exact root.seed byte-for-byte");
      check((rec_mpkey_res.out + rec_mpkey_res.err).find(backup_pass) ==
                std::string::npos,
            "recover --mpkey must never leak passphrase");

      // (e) `mprk1_...` stdin `recover` roundtrip into another fresh machine state dir!
      const fs::path recovered_mprk_dir = base / "online-recovered-mprk";
      const auto rec_mprk_res =
          run_cli({"online", "recover", "--device-label", "rescue-mprk", "--state-dir",
                   recovered_mprk_dir.string(), "--authority", "api.test.local",
                   "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                   crt_path.string()},
                  expected_mprk + "\n");
      const Value rec_mprk =
          parse_stdout_json(rec_mprk_res, "online recover mprk1 stdin");
      check(std::get<bool>(req_field(rec_mprk, "recovered").value()) &&
                req_int(rec_mprk, "account_id") == 1001 &&
                req_str(rec_mprk, "handle") == "pilot_one" &&
                req_str(rec_mprk, "safety_number") == expected_sn,
            "online recover mprk1 stdin JSON mismatch");
      check(read_binary_file(recovered_mprk_dir / "root.seed") == orig_root_bytes,
            "recovered mprk1 keystore must restore exact root.seed byte-for-byte");
      check((rec_mprk_res.out + rec_mprk_res.err).find(expected_mprk) ==
                std::string::npos,
            "recover must never echo recovery key");

      // Recovered machine can immediately call `whoami` and `devices revoke`!
      const Value rec_whoami = parse_stdout_json(
          run_cli({"online", "whoami", "--state-dir", recovered_mprk_dir.string(),
                   "--connect-host", "127.0.0.1", "--port", port_str, "--ca-bundle",
                   crt_path.string()}),
          "recovered machine whoami");
      check(req_int(rec_whoami, "account_id") == 1001,
            "recovered machine live whoami failed");

      // (f) ZERO secrets accepted on argv (exit 2 and NEVER echoed!)
      const std::string fake_pass = "supersecret_argv_pass_999";
      for (const std::vector<std::string> &bad_argv_cmd :
           std::vector<std::vector<std::string>>{
               {"online", "export-mpkey", "--out", (base / "x.mpkey").string(),
                "--passphrase", fake_pass, "--state-dir", state_dir.string()},
               {"online", "recover", "--recovery-key", expected_mprk, "--state-dir",
                (base / "no-dir").string()},
               {"online", "recover", expected_mprk, "--state-dir",
                (base / "no-dir").string()},
               {"online", "recover", "--mpkey", mpkey_path.string(), "--passphrase",
                fake_pass, "--state-dir", (base / "no-dir").string()},
           }) {
        const auto bad = run_cli(bad_argv_cmd);
        check(bad.exit_code == 2 && bad.out.empty() && !bad.err.empty(),
              "secrets on argv must exit 2");
        check(bad.err.find(fake_pass) == std::string::npos &&
                  bad.err.find(expected_mprk) == std::string::npos,
              "argv rejection error must NEVER echo secret material");
      }
      check(!fs::exists(base / "no-dir"),
            "rejected recover argv must create zero directories");
    }

    // online party attach CLI usage & fail-closed validation checks.
    const auto attach_help = run_cli({"online", "party", "attach", "--help"});
    check(attach_help.exit_code == 0 &&
              attach_help.err.find("blackbird online party attach") !=
                  std::string::npos,
          "online party attach --help must exit 0 with usage");
    const auto attach_no_id = run_cli({"online", "party", "attach"});
    check(attach_no_id.exit_code == 2 &&
              attach_no_id.err.find("<party_id> is required") != std::string::npos,
          "online party attach without party_id must fail usage");
    const auto attach_bad_mode =
        run_cli({"online", "party", "attach", "5001", "--mode", "bogus"});
    check(attach_bad_mode.exit_code == 2 &&
              attach_bad_mode.err.find("invalid --mode") != std::string::npos,
          "online party attach must reject invalid --mode");
    const auto attach_half_lobby = run_cli(
        {"online", "party", "attach", "5001", "--party-socket", "/tmp/test.sock"});
    check(attach_half_lobby.exit_code == 2 &&
              attach_half_lobby.err.find("must be set together") != std::string::npos,
          "online party attach must require --party-socket and --party-room together");
  }
}

} // namespace

int main(int argc, char **argv) {
  if (argc > 1 && std::string_view{argv[1]} == "--session")
    return run_fake_peer_child(argc, argv);
  if (argc > 1 && std::string_view{argv[1]} == "--sleep-child")
    return run_sleep_child();
  if (argc > 1 && std::string_view{argv[1]} == "--party-serve-child")
    return run_party_serve_child(argc, argv);

  try {
    const fs::path self_exe = fs::canonical(argv[0]);
    TempDir temp{"blackbird-command-post-cli-test"};

    test_subcommand_dispatch_table();
    test_mcp_subcommand(temp.path());
    test_platoon_subcommand({temp.path(), self_exe});
    test_issues_subcommand(temp.path());
    test_memory_subcommand(temp.path());
    test_peer_subcommand(temp.path());
    test_capabilities_subcommand(temp.path());
    test_metrics_subcommand(temp.path());
    test_bridge_subcommand(temp.path());
    test_bridge_checkpoint_and_join(temp.path());
    test_party_cli_roster_add_leader_and_say(temp.path());
    test_party_lobby_serve_and_status({temp.path(), self_exe});
    test_flightdeck_cli_once_and_themes(temp.path());
    test_online_cli_subcommand(temp.path());
    {
      const auto up_help = run_cli({"upgrade", "--help"});
      check(up_help.exit_code == 0 &&
                up_help.err.find("blackbird upgrade") != std::string::npos &&
                up_help.err.find("--no-ask") != std::string::npos,
            "upgrade --help must exit 0 with --no-ask usage");
      const auto up_bad = run_cli({"upgrade", "--bogus-flag"});
      check(up_bad.exit_code == 2 &&
                up_bad.err.find("unknown option") != std::string::npos,
            "upgrade must reject unknown options");
      const auto up_bad_url =
          run_cli({"upgrade", "--check", "--base-url", "http://insecure.example"});
      check(up_bad_url.exit_code != 0,
            "upgrade --check must refuse insecure http:// base URL");

      check(is_command_post_subcommand("doctor"),
            "doctor must be registered as a command_post subcommand");
      const auto doc_help = run_cli({"doctor", "--help"});
      check(doc_help.exit_code == 0 &&
                doc_help.err.find("blackbird doctor") != std::string::npos &&
                doc_help.err.find("--offline") != std::string::npos,
            "doctor --help must exit 0 with --offline usage");
      const auto doc_bad = run_cli({"doctor", "--bogus-flag"});
      check(doc_bad.exit_code == 2 &&
                doc_bad.err.find("unknown option") != std::string::npos,
            "doctor must reject unknown options");
      const fs::path doc_absent_state = temp.path() / "doctor_absent_online_state";
      const fs::path doc_absent_sock = temp.path() / "doctor_absent_party.sock";
      const auto doc_json = run_cli({"doctor", "--offline", "--json", "--state-dir",
                                     doc_absent_state.string(), "--party-socket",
                                     doc_absent_sock.string()});
      check(doc_json.exit_code == 0,
            "doctor --offline --json must exit 0 when healthy");
      check(!fs::exists(doc_absent_state),
            "doctor --offline must never create absent online state dir");
      const auto doc_val = parse_json(doc_json.out);
      check(doc_val.has_value() &&
                std::holds_alternative<Value::Object>(doc_val.value().value()) &&
                doc_val.value().find("healthy") != nullptr &&
                doc_val.value().find("checks") != nullptr,
            "doctor --offline --json must emit valid report JSON");

      check(is_command_post_subcommand("lan"),
            "lan must be registered as a command_post subcommand");
      const auto lan_help = run_cli({"lan", "--help"});
      check(lan_help.exit_code == 0 &&
                lan_help.err.find("blackbird lan") != std::string::npos &&
                lan_help.err.find("--pin-stdin") != std::string::npos,
            "lan --help must exit 0 with --pin-stdin guidance");
      const auto lan_pin_argv = run_cli({"lan", "host", "--pin", "1234"});
      check(lan_pin_argv.exit_code == 2 &&
                lan_pin_argv.err.find("refusing --pin on argv") != std::string::npos,
            "lan host must refuse --pin secret on argv");
      const fs::path lan_absent_dir = temp.path() / "lan_absent_state";
      const auto lan_status =
          run_cli({"lan", "status", "--json", "--lan-dir", lan_absent_dir.string()});
      check(lan_status.exit_code == 0 && !fs::exists(lan_absent_dir),
            "lan status --json must be passive and exit 0");
      const auto lan_val = parse_json(lan_status.out);
      check(lan_val.has_value() &&
                std::holds_alternative<Value::Object>(lan_val.value().value()) &&
                lan_val.value().find("disabled") != nullptr &&
                lan_val.value().find("idle_timeout_sec") != nullptr,
            "lan status --json must emit valid policy JSON");
    }

    // Brakes subcommand smoke (status & probe --json)
    {
      check(is_command_post_subcommand("brakes"),
            "brakes must be registered as a command_post subcommand");
      const auto brakes_help = run_cli({"brakes", "--help"});
      check(brakes_help.exit_code == 0 &&
                brakes_help.out.find("blackbird brakes") != std::string::npos,
            "brakes --help must exit 0");
      const auto brakes_status = run_cli({"brakes", "status", "--json"});
      check(brakes_status.exit_code == 0, "brakes status --json must exit 0");
      const auto bval = parse_json(brakes_status.out);
      check(bval.has_value() &&
                std::holds_alternative<Value::Object>(bval.value().value()) &&
                bval.value().find("effective_profile") != nullptr &&
                bval.value().find("sandbox_backend") != nullptr,
            "brakes status --json must emit valid JSON");
      const auto brakes_probe = run_cli({"brakes", "probe", "--json"});
      const auto pval = parse_json(brakes_probe.out);
      check(pval.has_value() &&
                std::holds_alternative<Value::Object>(pval.value().value()) &&
                pval.value().find("platform") != nullptr &&
                pval.value().find("backend") != nullptr,
            "brakes probe --json must emit valid JSON");
    }

    // Superpowers subcommand smoke (status --json)
    {
      check(is_command_post_subcommand("superpowers"),
            "superpowers must be registered as a command_post subcommand");
      const auto sp_help = run_cli({"superpowers", "--help"});
      check(sp_help.exit_code == 0 &&
                sp_help.out.find("blackbird superpowers") != std::string::npos,
            "superpowers --help must exit 0");
      const auto sp_json = run_cli({"superpowers", "status", "--json"});
      check(sp_json.exit_code == 0, "superpowers status --json must exit 0");
      const auto spv = parse_json(sp_json.out);
      check(spv.has_value() &&
                std::holds_alternative<Value::Object>(spv.value().value()) &&
                spv.value().find("sqlite") != nullptr &&
                spv.value().find("nvim_treesitter") != nullptr &&
                spv.value().find("lsp_servers") != nullptr &&
                spv.value().find("jupyter") != nullptr &&
                spv.value().find("measure_harness") != nullptr,
            "superpowers status --json must include all 5 superpower families");
    }

    // Integrations & connect subcommands (passive zero-disk-write + secret safety)
    {
      check(is_command_post_subcommand("integrations") &&
                is_command_post_subcommand("connect"),
            "integrations and connect must be registered command_post subcommands");

      const fs::path absent_vault = temp.path() / "integrations_absent_vault";
      const auto status_absent = run_cli(
          {"integrations", "status", "--vault-dir", absent_vault.string(), "--json"});
      check(status_absent.exit_code == 0 && !fs::exists(absent_vault),
            "integrations status must be strictly passive zero-disk-write");
      const auto sval = parse_json(status_absent.out);
      check(sval.has_value() &&
                !std::get<bool>(req_field(sval.value(), "vault_present").value()) &&
                req_int(sval.value(), "connected_count") == 0 &&
                req_int(sval.value(), "mcp_presets_count") == 6 &&
                req_int(sval.value(), "saas_packs_count") == 7,
            "integrations status JSON must report 0 connected, 6 presets, 7 packs");

      const auto presets_res = run_cli({"integrations", "presets", "--json"});
      check(presets_res.exit_code == 0, "integrations presets --json exits 0");
      const auto pval = parse_json(presets_res.out);
      check(pval.has_value() && req_int(pval.value(), "count") == 6,
            "integrations presets must list 6 official remote MCP presets");

      const auto packs_res = run_cli({"integrations", "packs", "--json"});
      check(packs_res.exit_code == 0, "integrations packs --json exits 0");
      const auto kval = parse_json(packs_res.out);
      check(kval.has_value() && req_int(kval.value(), "count") == 7,
            "integrations packs must list 7 builtin Lua 5.5.1 SaaS packs");

      // Refuse secrets on argv!
      const auto argv_refuse =
          run_cli({"connect", "linear", "--token", "secret_never_argv", "--vault-dir",
                   absent_vault.string()});
      check(argv_refuse.exit_code == 2 &&
                argv_refuse.err.find("refusing secret on argv") != std::string::npos &&
                !fs::exists(absent_vault),
            "connect must refuse --token secret on argv without writing disk");

      // Connect via --token-stdin using top-level `connect` alias; zero secret echo!
      const std::string test_secret = "lin_api_cli_secret_value_8899";
      const auto conn_res =
          run_cli({"connect", "linear", "--token-stdin", "--account", "ops",
                   "--vault-dir", absent_vault.string(), "--json"},
                  test_secret + "\n");
      check(conn_res.exit_code == 0, "connect linear --token-stdin must exit 0");
      check(conn_res.out.find(test_secret) == std::string::npos &&
                conn_res.err.find(test_secret) == std::string::npos,
            "connect must NEVER echo secret to stdout or stderr");
      const auto cval = parse_json(conn_res.out);
      check(cval.has_value() &&
                std::get<bool>(req_field(cval.value(), "connected").value()) &&
                req_str(req_field(cval.value(), "credential"), "service") == "linear" &&
                req_str(req_field(cval.value(), "credential"), "account") == "ops",
            "connect JSON must report connected metadata");

      // List shows connected account metadata and ZERO secrets.
      const auto list_res = run_cli(
          {"integrations", "list", "--vault-dir", absent_vault.string(), "--json"});
      check(list_res.exit_code == 0 &&
                list_res.out.find(test_secret) == std::string::npos,
            "integrations list must succeed and leak zero secrets");
      const auto lval = parse_json(list_res.out);
      check(lval.has_value() && req_int(lval.value(), "connected_count") == 1,
            "integrations list must report 1 connected account");

      // Disconnect removes credential cleanly.
      const auto disc_res =
          run_cli({"integrations", "disconnect", "linear", "--account", "ops",
                   "--vault-dir", absent_vault.string(), "--json"});
      check(disc_res.exit_code == 0, "integrations disconnect must exit 0");
      const auto dval = parse_json(disc_res.out);
      check(dval.has_value() &&
                std::get<bool>(req_field(dval.value(), "disconnected").value()),
            "integrations disconnect must confirm removal");

      const auto after_disc = run_cli(
          {"integrations", "list", "--vault-dir", absent_vault.string(), "--json"});
      const auto aval = parse_json(after_disc.out);
      check(aval.has_value() && req_int(aval.value(), "connected_count") == 0,
            "integrations list must report 0 accounts after disconnect");
    }

    std::cout << "PASS command_post_cli\n";
    return 0;
  } catch (const Error &e) {
    std::cerr << "FAIL command_post_cli Error: " << error_name(e.code) << " ("
              << e.detail << ")\n";
    return 1;
  } catch (const std::exception &e) {
    std::cerr << "FAIL command_post_cli: " << e.what() << '\n';
    return 1;
  }
}
