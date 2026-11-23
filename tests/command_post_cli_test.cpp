#include "../src/native_process.hpp"
#include "blackbird/board_bridge.hpp"
#include "blackbird/capabilities.hpp"
#include "blackbird/command_post_cli.hpp"
#include "blackbird/json.hpp"
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
  for (const char *name : {"mcp", "platoon", "issues", "memory", "peer", "capabilities",
                           "metrics", "bridge", "join", "party", "flightdeck"}) {
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

} // namespace

int main(int argc, char **argv) {
  if (argc > 1 && std::string_view{argv[1]} == "--session")
    return run_fake_peer_child(argc, argv);
  if (argc > 1 && std::string_view{argv[1]} == "--sleep-child")
    return run_sleep_child();

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
    test_flightdeck_cli_once_and_themes(temp.path());

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
