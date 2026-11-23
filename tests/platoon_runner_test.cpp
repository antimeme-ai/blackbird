#include "blackbird/json.hpp"
#include "blackbird/platoon_runner.hpp"
#include "blackbird/process_lifetime.hpp"
#include "blackbird/value.hpp"
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

const Value &require_field(const Value &object, std::string_view key) {
  const auto *found = object.find(key);
  check(found != nullptr, "missing required JSON field");
  return *found;
}

const std::string &require_string(const Value &object, std::string_view key) {
  const auto &item = require_field(object, key);
  check(std::holds_alternative<std::string>(item.value()), "expected string field");
  return item.string();
}

std::string env_or_empty(const char *name) {
  const char *value = std::getenv(name);
  return value ? std::string{value} : std::string{};
}

std::string current_working_dir() {
  std::string buffer(PATH_MAX, '\0');
  if (::getcwd(buffer.data(), buffer.size()) == nullptr)
    throw std::runtime_error("getcwd failed");
  return std::filesystem::canonical(buffer.c_str()).string();
}

int run_fake_peer(int argc, char **argv) {
  const std::string mode = env_or_empty("BLACKBIRD_PLATOON_TEST_MODE");
  if (mode == "sleep") {
    std::cout << "READY\n" << std::flush;
    for (int i = 0; i < 300; ++i)
      ::usleep(100000);
    return 0;
  }
  if (mode == "ignore_term") {
    (void)::signal(SIGTERM, SIG_IGN);
    const std::string gc_file = env_or_empty("BLACKBIRD_PLATOON_TEST_GC_PID_FILE");
    if (!gc_file.empty()) {
      const pid_t child = ::fork();
      if (child == 0) {
        (void)::signal(SIGTERM, SIG_IGN);
        for (int i = 0; i < 300; ++i)
          ::usleep(100000);
        ::_exit(0);
      }
      if (child > 0) {
        std::ofstream out{gc_file};
        out << child << '\n';
        out.flush();
      }
    }
    std::cout << "ARMED\n" << std::flush;
    for (int i = 0; i < 300; ++i)
      ::usleep(100000);
    return 0;
  }
  if (mode == "flood") {
    // Mix multi-byte UTF-8 glyphs with ASCII so ring wraparound cuts mid-codepoint.
    const std::string chunk = "λ🚀0123456789abcdef\n";
    for (int i = 0; i < 900; ++i)
      std::cout << chunk;
    std::cerr << "STDERR_LINE\n";
    std::cout << "TAIL_END_MARKER\n" << std::flush;
    return 0;
  }
  if (mode == "fail") {
    std::cerr << "simulated failure\n" << std::flush;
    return 42;
  }

  Value::Array args;
  for (int i = 1; i < argc; ++i)
    args.emplace_back(std::string{argv[i]});

  Value::Object report;
  report.emplace_back("argv", Value{std::move(args)});
  report.emplace_back("cwd", Value{current_working_dir()});
  report.emplace_back("pid", Value{Number{static_cast<std::int64_t>(::getpid())}});
  report.emplace_back("pgid", Value{Number{static_cast<std::int64_t>(::getpgrp())}});
  report.emplace_back("board", Value{env_or_empty("BLACKBIRD_PLATOON_BOARD")});
  report.emplace_back("peer_id", Value{env_or_empty("BLACKBIRD_PLATOON_PEER_ID")});
  report.emplace_back("role", Value{env_or_empty("BLACKBIRD_PLATOON_ROLE")});

  const auto json = dump_json(Value{std::move(report)});
  if (!json.has_value())
    return 99;
  std::cout << json.value() << '\n' << std::flush;
  std::cerr << "STDERR_MARKER_" << env_or_empty("BLACKBIRD_PLATOON_PEER_ID") << '\n'
            << std::flush;
  return 0;
}

struct OutputWait {
  std::string_view peer_id;
  std::string_view needle;
  std::chrono::milliseconds timeout;
};

bool wait_for_output_substring(const PlatoonRunner &runner, OutputWait query) {
  const auto deadline = std::chrono::steady_clock::now() + query.timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    const auto snap = runner.snapshot(query.peer_id);
    if (snap.has_value() &&
        snap.value().output_tail.find(query.needle) != std::string::npos)
      return true;
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  return false;
}

bool wait_for_process_gone(pid_t pid, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (::kill(pid, 0) != 0 && errno == ESRCH)
      return true;
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  return ::kill(pid, 0) != 0 && errno == ESRCH;
}

struct TempDir {
  std::filesystem::path path;
  explicit TempDir(const std::string &prefix) {
    path = std::filesystem::temp_directory_path() /
           (prefix + "-" + std::to_string(::getpid()));
    std::filesystem::remove_all(path);
    std::filesystem::create_directories(path);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

} // namespace

int main(int argc, char **argv) {
  if (argc > 1 && std::string_view{argv[1]} == "--session")
    return run_fake_peer(argc, argv);

  try {
    const auto self_exe = std::filesystem::canonical(argv[0]);
    TempDir temp{"blackbird-platoon-runner-test"};
    const auto work_a = std::filesystem::canonical(temp.path) / "work_a";
    const auto work_b = std::filesystem::canonical(temp.path) / "work_b";
    const auto sess_a = std::filesystem::canonical(temp.path) / "sess_a";
    const auto sess_b = std::filesystem::canonical(temp.path) / "sess_b";
    std::filesystem::create_directories(work_a);
    std::filesystem::create_directories(work_b);

    // 1. Concurrent heterogeneous peers with distinct providers, models, and working
    // dirs.
    {
      PlatoonRunner runner{4};
      check(runner.max_peers() == 4, "max_peers mismatch");
      check(runner.active_count() == 0, "expected zero active peers initially");

      PlatoonPeerSpec alpha;
      alpha.peer_id = "peer-alpha";
      alpha.role = "architect";
      alpha.provider = "openai";
      alpha.model = "gpt-6.1-sol";
      alpha.effort = "high";
      alpha.working_dir = work_a;
      alpha.session_dir = sess_a;
      alpha.prompt = "design slice alpha";
      alpha.executable = self_exe;
      alpha.extra_env = {{"BLACKBIRD_PLATOON_BOARD", "/tmp/board-1"},
                         {"BLACKBIRD_PLATOON_PEER_ID", "peer-alpha"},
                         {"BLACKBIRD_PLATOON_ROLE", "architect"}};

      PlatoonPeerSpec beta;
      beta.peer_id = "peer-beta";
      beta.role = "reviewer";
      beta.provider = "anthropic";
      beta.model = "claude-sonnet-4-5";
      beta.working_dir = work_b;
      beta.session_dir = sess_b;
      beta.prompt = "review slice beta";
      beta.executable = self_exe;
      beta.extra_env = {{"BLACKBIRD_PLATOON_BOARD", "/tmp/board-1"},
                        {"BLACKBIRD_PLATOON_PEER_ID", "peer-beta"},
                        {"BLACKBIRD_PLATOON_ROLE", "reviewer"}};

      const auto spawned_a = runner.spawn(alpha);
      const auto spawned_b = runner.spawn(beta);
      check(spawned_a.has_value(), "failed to spawn alpha");
      check(spawned_b.has_value(), "failed to spawn beta");
      check(spawned_a.value().pid > 0 && spawned_b.value().pid > 0, "invalid pid");
      check(spawned_a.value().pid != spawned_b.value().pid, "duplicate pids");

      const auto done_a = runner.wait("peer-alpha", 5000);
      const auto done_b = runner.wait("peer-beta", 5000);
      check(done_a.has_value() && done_b.has_value(), "wait failed");
      check(done_a.value().state == PlatoonPeerState::completed, "alpha not completed");
      check(done_b.value().state == PlatoonPeerState::completed, "beta not completed");
      check(done_a.value().exit_code.has_value() && *done_a.value().exit_code == 0,
            "alpha exit code != 0");
      check(done_b.value().exit_code.has_value() && *done_b.value().exit_code == 0,
            "beta exit code != 0");
      check(done_a.value().started_ns > 0 &&
                done_a.value().finished_ns >= done_a.value().started_ns,
            "alpha timestamps invalid");
      check(runner.active_count() == 0, "active count did not drop to 0");

      auto parse_first_line = [](const std::string &output) -> Value {
        const auto nl = output.find('\n');
        check(nl != std::string::npos, "missing json line in peer output");
        const auto parsed = parse_json(std::string_view{output.data(), nl});
        check(parsed.has_value(), "invalid json from peer");
        return parsed.value();
      };

      const Value report_a = parse_first_line(done_a.value().output_tail);
      const Value report_b = parse_first_line(done_b.value().output_tail);

      check(require_string(report_a, "cwd") == work_a.string(), "alpha wrong cwd");
      check(require_string(report_b, "cwd") == work_b.string(), "beta wrong cwd");
      check(require_string(report_a, "board") == "/tmp/board-1",
            "alpha missing board env");
      check(require_string(report_a, "peer_id") == "peer-alpha",
            "alpha missing peer env");
      check(require_string(report_a, "role") == "architect", "alpha missing role env");
      check(require_string(report_b, "peer_id") == "peer-beta",
            "beta missing peer env");
      check(require_string(report_b, "role") == "reviewer", "beta missing role env");
      check(require_field(report_a, "pid") == require_field(report_a, "pgid"),
            "alpha not process group leader");
      check(require_field(report_b, "pid") == require_field(report_b, "pgid"),
            "beta not process group leader");
      check(done_a.value().output_tail.find("STDERR_MARKER_peer-alpha") !=
                std::string::npos,
            "alpha stderr not merged");
      check(done_b.value().output_tail.find("STDERR_MARKER_peer-beta") !=
                std::string::npos,
            "beta stderr not merged");

      const auto &argv_a = require_field(report_a, "argv").array();
      const std::vector<std::string> expected_a = {
          "--session", sess_a.string(), "--provider",        "openai",
          "--model",   "gpt-6.1-sol",   "--effort",          "high",
          "--plain",   "--once",        "design slice alpha"};
      check(argv_a.size() == expected_a.size(), "alpha argv length mismatch");
      for (std::size_t i = 0; i < expected_a.size(); ++i)
        check(argv_a[i].string() == expected_a[i], "alpha argv element mismatch");

      const auto &argv_b = require_field(report_b, "argv").array();
      const std::vector<std::string> expected_b = {
          "--session", sess_b.string(), "--provider",
          "anthropic", "--model",       "claude-sonnet-4-5",
          "--plain",   "--once",        "review slice beta"};
      check(argv_b.size() == expected_b.size(), "beta argv length mismatch");
      for (std::size_t i = 0; i < expected_b.size(); ++i)
        check(argv_b[i].string() == expected_b[i], "beta argv element mismatch");

      // Non-zero exit transitions to failed.
      PlatoonPeerSpec failing = alpha;
      failing.peer_id = "peer-fail";
      failing.extra_env.emplace_back("BLACKBIRD_PLATOON_TEST_MODE", "fail");
      const auto spawned_fail = runner.spawn(failing);
      check(spawned_fail.has_value(), "failed to spawn failing peer");
      const auto done_fail = runner.wait("peer-fail", 5000);
      check(done_fail.has_value(), "wait on failing peer failed");
      check(done_fail.value().state == PlatoonPeerState::failed,
            "non-zero exit not marked failed");
      check(done_fail.value().exit_code.has_value() &&
                *done_fail.value().exit_code == 42,
            "unexpected exit code for failing peer");
    }

    // 2. Bounded UTF-8 output tail capture (`output_bytes` vs `output_tail` cap).
    {
      PlatoonRunner runner{2};
      PlatoonPeerSpec flood;
      flood.peer_id = "flooder";
      flood.role = "producer";
      flood.provider = "openai";
      flood.model = "gpt-6.1-sol";
      flood.working_dir = work_a;
      flood.session_dir = sess_a;
      flood.prompt = "emit lots of utf8 output";
      flood.executable = self_exe;
      flood.max_output_bytes = 1024;
      flood.extra_env = {{"BLACKBIRD_PLATOON_TEST_MODE", "flood"}};

      const auto spawned = runner.spawn(flood);
      check(spawned.has_value(), "failed to spawn flooder");
      const auto done = runner.wait("flooder", 5000);
      check(done.has_value(), "wait on flooder failed");
      check(done.value().state == PlatoonPeerState::completed, "flooder not completed");
      check(done.value().output_bytes > 16384U,
            "output_bytes did not track full volume");
      check(done.value().output_tail.size() <= 1024U, "output_tail exceeded cap");
      check(valid_utf8(done.value().output_tail), "output_tail is not valid UTF-8");
      check(done.value().output_tail.find("TAIL_END_MARKER") != std::string::npos,
            "output_tail lost final bytes");
      check(done.value().output_tail.find("STDERR_LINE") != std::string::npos,
            "output_tail lost stderr bytes");
    }

    // 3. stop() cleanly terminates long-sleeping peer via SIGTERM and marks stopped.
    {
      PlatoonRunner runner{2};
      PlatoonPeerSpec sleeper;
      sleeper.peer_id = "sleeper-1";
      sleeper.role = "worker";
      sleeper.provider = "anthropic";
      sleeper.model = "claude-sonnet-4-5";
      sleeper.working_dir = work_a;
      sleeper.session_dir = sess_a;
      sleeper.prompt = "sleep";
      sleeper.executable = self_exe;
      sleeper.extra_env = {{"BLACKBIRD_PLATOON_TEST_MODE", "sleep"}};

      const auto spawned = runner.spawn(sleeper);
      check(spawned.has_value(), "failed to spawn sleeper");
      check(wait_for_output_substring(
                runner, {"sleeper-1", "READY", std::chrono::milliseconds{3000}}),
            "sleeper did not become ready");

      const auto timed_out = runner.wait("sleeper-1", 50);
      check(timed_out.has_value() &&
                timed_out.value().state == PlatoonPeerState::running,
            "wait timeout did not return running snapshot");

      const auto stopped = runner.stop("sleeper-1", 1500);
      check(stopped.has_value(), "stop failed");
      check(stopped.value().state == PlatoonPeerState::stopped,
            "stopped peer not marked stopped");
      check(runner.active_count() == 0, "active_count non-zero after stop");
      check(wait_for_process_gone(static_cast<pid_t>(stopped.value().pid),
                                  std::chrono::milliseconds{1000}),
            "stopped peer pid still alive");
    }

    // 4. stop() escalates SIGTERM -> SIGKILL and kills process-group grandchildren.
    {
      PlatoonRunner runner{2};
      const auto gc_pid_file = std::filesystem::canonical(temp.path) / "gc.pid";
      PlatoonPeerSpec stubborn;
      stubborn.peer_id = "stubborn-1";
      stubborn.role = "worker";
      stubborn.provider = "openai";
      stubborn.model = "gpt-6.1-sol";
      stubborn.working_dir = work_a;
      stubborn.session_dir = sess_a;
      stubborn.prompt = "ignore term";
      stubborn.executable = self_exe;
      stubborn.extra_env = {
          {"BLACKBIRD_PLATOON_TEST_MODE", "ignore_term"},
          {"BLACKBIRD_PLATOON_TEST_GC_PID_FILE", gc_pid_file.string()}};

      const auto spawned = runner.spawn(stubborn);
      check(spawned.has_value(), "failed to spawn stubborn peer");
      check(wait_for_output_substring(
                runner, {"stubborn-1", "ARMED", std::chrono::milliseconds{3000}}),
            "stubborn peer did not arm");

      pid_t grandchild_pid = -1;
      {
        std::ifstream in{gc_pid_file};
        in >> grandchild_pid;
      }
      check(grandchild_pid > 0, "grandchild pid missing");

      const auto stopped = runner.stop("stubborn-1", 150);
      check(stopped.has_value(), "stop escalation failed");
      check(stopped.value().state == PlatoonPeerState::stopped,
            "escalated peer not marked stopped");
      check(stopped.value().exit_code.has_value() &&
                *stopped.value().exit_code == 128 + SIGKILL,
            "escalated peer did not die from SIGKILL");
      check(wait_for_process_gone(static_cast<pid_t>(stopped.value().pid),
                                  std::chrono::milliseconds{1000}),
            "stubborn leader still alive");
      check(wait_for_process_gone(grandchild_pid, std::chrono::milliseconds{1000}),
            "grandchild escaped process-group SIGKILL");
    }

    // 5. Capacity limit, duplicate active ID rejection, and settled ID reuse.
    {
      PlatoonRunner runner{2};
      PlatoonPeerSpec base;
      base.role = "worker";
      base.provider = "openai";
      base.model = "gpt-6.1-sol";
      base.working_dir = work_a;
      base.session_dir = sess_a;
      base.prompt = "sleep";
      base.executable = self_exe;
      base.extra_env = {{"BLACKBIRD_PLATOON_TEST_MODE", "sleep"}};

      base.peer_id = "slot-1";
      check(runner.spawn(base).has_value(), "slot-1 spawn failed");
      const auto dup = runner.spawn(base);
      check(!dup.has_value() && dup.error().code == ErrorCode::conflict,
            "duplicate active peer_id not rejected with conflict");

      base.peer_id = "slot-2";
      check(runner.spawn(base).has_value(), "slot-2 spawn failed");
      check(runner.active_count() == 2, "expected 2 active peers");
      check(runner.list().size() == 2, "expected 2 listed peers");

      base.peer_id = "slot-3";
      const auto over = runner.spawn(base);
      check(!over.has_value() && over.error().code == ErrorCode::capacity,
            "over-capacity spawn not rejected with capacity");

      check(runner.stop("slot-1", 500).has_value(), "failed to stop slot-1");
      check(runner.active_count() == 1,
            "active_count should be 1 after stopping slot-1");

      // Reusing a settled peer_id while at capacity must reject without erasing it.
      base.peer_id = "slot-3";
      check(runner.spawn(base).has_value(), "slot-3 spawn after stop failed");
      base.peer_id = "slot-1";
      const auto over_reuse = runner.spawn(base);
      check(!over_reuse.has_value() && over_reuse.error().code == ErrorCode::capacity,
            "settled peer_id reuse at capacity did not fail with capacity");
      const auto preserved = runner.snapshot("slot-1");
      check(preserved.has_value() &&
                preserved.value().state == PlatoonPeerState::stopped,
            "failed capacity reuse erased previous settled snapshot");
      check(runner.stop("slot-3", 500).has_value(), "failed to stop slot-3");

      // Reusing a settled peer_id succeeds once capacity is available.
      base.peer_id = "slot-1";
      base.extra_env = {};
      const auto reused = runner.spawn(base);
      check(reused.has_value(), "reusing settled peer_id failed");
      const auto reused_done = runner.wait("slot-1", 5000);
      check(reused_done.has_value() &&
                reused_done.value().state == PlatoonPeerState::completed,
            "reused peer did not complete");
      check(runner.stop("slot-2", 500).has_value(), "failed to stop slot-2");
    }

    // 6. Input validation and security rejections.
    {
      bool zero_rejected = false;
      try {
        PlatoonRunner bad{0};
      } catch (const Error &e) {
        zero_rejected = (e.code == ErrorCode::invalid_range);
      }
      check(zero_rejected, "max_peers=0 was accepted");

      bool over_max_rejected = false;
      try {
        PlatoonRunner bad{17};
      } catch (const Error &e) {
        over_max_rejected = (e.code == ErrorCode::invalid_range);
      }
      check(over_max_rejected, "max_peers=17 was accepted");

      PlatoonRunner runner{2};
      PlatoonPeerSpec valid;
      valid.peer_id = "ok-1";
      valid.role = "worker";
      valid.provider = "openai";
      valid.model = "gpt-6.1-sol";
      valid.working_dir = work_a;
      valid.session_dir = sess_a;
      valid.prompt = "hello";
      valid.executable = self_exe;

      for (const char *bad_id :
           {"", "BadUpper", "../escape", "has space",
            "01234567890123456789012345678901234567890123456789"}) {
        auto s = valid;
        s.peer_id = bad_id;
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "invalid peer_id accepted");
      }

      {
        auto s = valid;
        s.working_dir = "relative/path";
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "relative working_dir accepted");
      }
      {
        auto s = valid;
        s.working_dir = work_a / "does-not-exist";
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::io,
              "missing working_dir did not fail with io");
      }
      {
        auto s = valid;
        s.session_dir = "relative/session";
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "relative session_dir accepted");
      }
      for (const char *bad_env :
           {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "OPENAI_API_KEY", "MY_SECRET",
            "ACCESS_TOKEN", "BAD=KEY", "1STARTS_DIGIT"}) {
        auto s = valid;
        s.extra_env = {{bad_env, "x"}};
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "disallowed extra_env accepted");
      }
      {
        const auto r1 = runner.snapshot("missing");
        const auto r2 = runner.stop("missing", 100);
        const auto r3 = runner.wait("missing", 100);
        const auto r4 = runner.stop("ok-1", -1);
        const auto r5 = runner.wait("ok-1", -1);
        check(!r1.has_value() && r1.error().code == ErrorCode::invalid_range,
              "snapshot missing peer did not fail");
        check(!r2.has_value() && r2.error().code == ErrorCode::invalid_range,
              "stop missing peer did not fail");
        check(!r3.has_value() && r3.error().code == ErrorCode::invalid_range,
              "wait missing peer did not fail");
        check(!r4.has_value() && r4.error().code == ErrorCode::invalid_range,
              "negative stop grace_ms accepted");
        check(!r5.has_value() && r5.error().code == ErrorCode::invalid_range,
              "negative wait timeout_ms accepted");
      }
    }

    // 7. Destructor cleanly stops and reaps still-running peers without hanging.
    {
      pid_t pid_1 = -1;
      pid_t pid_2 = -1;
      const auto before = std::chrono::steady_clock::now();
      {
        PlatoonRunner runner{4};
        PlatoonPeerSpec sleeper;
        sleeper.role = "worker";
        sleeper.provider = "openai";
        sleeper.model = "gpt-6.1-sol";
        sleeper.working_dir = work_a;
        sleeper.session_dir = sess_a;
        sleeper.prompt = "sleep";
        sleeper.executable = self_exe;
        sleeper.extra_env = {{"BLACKBIRD_PLATOON_TEST_MODE", "sleep"}};

        sleeper.peer_id = "dtor-1";
        const auto s1 = runner.spawn(sleeper);
        check(s1.has_value(), "dtor-1 spawn failed");
        pid_1 = static_cast<pid_t>(s1.value().pid);

        sleeper.peer_id = "dtor-2";
        const auto s2 = runner.spawn(sleeper);
        check(s2.has_value(), "dtor-2 spawn failed");
        pid_2 = static_cast<pid_t>(s2.value().pid);

        check(wait_for_output_substring(
                  runner, {"dtor-1", "READY", std::chrono::milliseconds{3000}}),
              "dtor-1 not ready");
        check(wait_for_output_substring(
                  runner, {"dtor-2", "READY", std::chrono::milliseconds{3000}}),
              "dtor-2 not ready");
      }
      const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now() - before)
                                  .count();
      check(elapsed_ms < 5000, "destructor hung tearing down running peers");
      check(wait_for_process_gone(pid_1, std::chrono::milliseconds{1000}),
            "dtor-1 survived destructor");
      check(wait_for_process_gone(pid_2, std::chrono::milliseconds{1000}),
            "dtor-2 survived destructor");
      check(detail::owned_children.load() == 0,
            "owned_children leaked after PlatoonRunner destruction");
    }

    std::cout << "platoon_runner passed\n";
    return 0;
  } catch (const Error &e) {
    std::cerr << "Error: " << error_name(e.code) << " (" << e.detail << ")\n";
    return 1;
  } catch (const std::exception &e) {
    std::cerr << "Exception: " << e.what() << '\n';
    return 1;
  }
}
