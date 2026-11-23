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

int run_fake_acp_peer(int argc, char **argv, std::string_view mode) {
  auto send_json = [](const Value &v) -> bool {
    const auto dumped = dump_json(v);
    if (!dumped.has_value())
      return false;
    std::cout << dumped.value() << '\n' << std::flush;
    return true;
  };

  if (mode == "acp_early_exit") {
    std::cerr << "ACP_EARLY_EXIT\n" << std::flush;
    return 0;
  }

  std::string line;
  if (!std::getline(std::cin, line))
    return 11;
  const auto init_req = parse_json(line);
  if (!init_req.has_value())
    return 12;
  if (require_string(init_req.value(), "jsonrpc") != "2.0" ||
      require_string(init_req.value(), "method") != "initialize")
    return 13;

  std::cerr << "ACP_STDERR_DIAG\n" << std::flush;
  if (!send_json(Value::object(
          {{"jsonrpc", Value{"2.0"}},
           {"id", require_field(init_req.value(), "id")},
           {"result",
            Value::object(
                {{"protocolVersion", Value{Number{std::int64_t{1}}}},
                 {"agentInfo", Value::object({{"name", Value{"fake-acp"}}})}})}})))
    return 14;

  if (!std::getline(std::cin, line))
    return 21;
  const auto sess_req = parse_json(line);
  if (!sess_req.has_value())
    return 22;
  if (require_string(sess_req.value(), "method") != "session/new")
    return 23;
  const auto &sess_params = require_field(sess_req.value(), "params");
  const auto &cwd = require_string(sess_params, "cwd");
  if (cwd != current_working_dir())
    return 24;

  if (mode == "acp_error") {
    if (!send_json(Value::object(
            {{"jsonrpc", Value{"2.0"}},
             {"id", require_field(sess_req.value(), "id")},
             {"error", Value::object({{"code", Value{Number{std::int64_t{-32000}}}},
                                      {"message", Value{"session denied"}}})}})))
      return 25;
    // Wait for parent to close stdin on protocol failure.
    while (std::getline(std::cin, line)) {
    }
    std::cerr << "ACP_ERROR_EOF\n" << std::flush;
    return 0;
  }

  if (!send_json(Value::object(
          {{"jsonrpc", Value{"2.0"}},
           {"id", require_field(sess_req.value(), "id")},
           {"result", Value::object({{"sessionId", Value{"acp-sess-99"}}})}})))
    return 26;

  if (!std::getline(std::cin, line))
    return 31;
  const auto prompt_req = parse_json(line);
  if (!prompt_req.has_value())
    return 32;
  if (require_string(prompt_req.value(), "method") != "session/prompt")
    return 33;
  const auto &prompt_params = require_field(prompt_req.value(), "params");
  if (require_string(prompt_params, "sessionId") != "acp-sess-99")
    return 34;
  const auto &blocks = require_field(prompt_params, "prompt").array();
  if (blocks.empty())
    return 35;
  const auto &prompt_text = require_string(blocks[0], "text");

  Value::Array args;
  for (int i = 1; i < argc; ++i)
    args.emplace_back(std::string{argv[i]});

  Value::Array leaked;
  for (const char *secret_key :
       {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SECRET_TOKEN", "GEMINI_API_KEY",
        "CUSTOM_KEY", "XDG_SECRET_TOKEN", "UNRELATED_AMBIENT"}) {
    if (std::getenv(secret_key) != nullptr)
      leaked.emplace_back(secret_key);
  }

  if (!send_json(Value::object(
          {{"jsonrpc", Value{"2.0"}},
           {"method", Value{"session/update"}},
           {"params",
            Value::object({{"sessionId", Value{"acp-sess-99"}},
                           {"echo", Value{"acp:" + prompt_text}},
                           {"cwd", Value{cwd}},
                           {"argv", Value{std::move(args)}},
                           {"leaked_env", Value{std::move(leaked)}},
                           {"has_path", Value{std::getenv("PATH") != nullptr}},
                           {"xdg_config", Value{env_or_empty("XDG_CONFIG_HOME")}}})}})))
    return 36;

  if (!send_json(Value::object(
          {{"jsonrpc", Value{"2.0"}},
           {"id", require_field(prompt_req.value(), "id")},
           {"result", Value::object({{"stopReason", Value{"end_turn"}}})}})))
    return 37;

  // Expect clean stdin EOF from parent after prompt completion.
  if (std::getline(std::cin, line))
    return 38;
  std::cerr << "ACP_EOF_CLEAN\n" << std::flush;
  return 0;
}

int run_fake_peer(int argc, char **argv) {
  const std::string mode = env_or_empty("BLACKBIRD_PLATOON_TEST_MODE");
  if (mode == "acp" || mode == "acp_error" || mode == "acp_early_exit")
    return run_fake_acp_peer(argc, argv, mode);
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

  Value::Array leaked_env;
  for (const char *secret_key :
       {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SECRET_TOKEN", "GEMINI_API_KEY",
        "CUSTOM_KEY", "XDG_SECRET_TOKEN", "UNRELATED_AMBIENT"}) {
    if (std::getenv(secret_key) != nullptr)
      leaked_env.emplace_back(secret_key);
  }

  Value::Object report;
  report.emplace_back("argv", Value{std::move(args)});
  report.emplace_back("cwd", Value{current_working_dir()});
  report.emplace_back("pid", Value{Number{static_cast<std::int64_t>(::getpid())}});
  report.emplace_back("pgid", Value{Number{static_cast<std::int64_t>(::getpgrp())}});
  report.emplace_back("board", Value{env_or_empty("BLACKBIRD_PLATOON_BOARD")});
  report.emplace_back("peer_id", Value{env_or_empty("BLACKBIRD_PLATOON_PEER_ID")});
  report.emplace_back("role", Value{env_or_empty("BLACKBIRD_PLATOON_ROLE")});
  report.emplace_back("xdg_config", Value{env_or_empty("XDG_CONFIG_HOME")});
  report.emplace_back("has_path", Value{std::getenv("PATH") != nullptr});
  report.emplace_back("leaked_env", Value{std::move(leaked_env)});

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
  if (env_or_empty("BLACKBIRD_PLATOON_FAKE_PEER") == "1" ||
      (argc > 1 && std::string_view{argv[1]} == "--session"))
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
           {"", "-leading-dash", "BadUpper", "../escape", "has space",
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

    // 8. Driver name/parse helpers, valid_platoon_peer_id, and to_value().
    {
      for (const PlatoonPeerDriver driver :
           {PlatoonPeerDriver::blackbird, PlatoonPeerDriver::claude_code,
            PlatoonPeerDriver::codex, PlatoonPeerDriver::pi,
            PlatoonPeerDriver::antigravity, PlatoonPeerDriver::acp}) {
        const std::string_view name = platoon_driver_name(driver);
        const auto parsed = parse_platoon_driver(name);
        check(parsed.has_value() && parsed.value() == driver,
              "driver name/parse round-trip failed");
      }
      const auto dashed_claude = parse_platoon_driver("claude-code");
      check(dashed_claude.has_value() &&
                dashed_claude.value() == PlatoonPeerDriver::claude_code,
            "claude-code alias did not parse");
      for (const char *bad : {"", "unknown", "CLAUDE_CODE", "bash", "shell"}) {
        const auto parsed = parse_platoon_driver(bad);
        check(!parsed.has_value() && parsed.error().code == ErrorCode::invalid_range,
              "invalid driver name accepted");
      }

      check(valid_platoon_peer_id("peer-1_ok"), "valid peer id rejected");
      check(!valid_platoon_peer_id("-bad"), "leading dash peer id accepted");
      check(!valid_platoon_peer_id(""), "empty peer id accepted");
      check(!valid_platoon_peer_id("Bad"), "uppercase peer id accepted");

      PlatoonPeerSnapshot snap;
      snap.peer_id = "peer-val";
      snap.driver = PlatoonPeerDriver::pi;
      snap.role = "coder";
      snap.provider = "anthropic";
      snap.model = "claude-sonnet-4-5";
      snap.owner_actor = "alice@node-1";
      snap.command_room = "ops:room-7";
      snap.tool_allowlist = "read,bash,edit";
      snap.working_dir = work_a;
      snap.session_dir = sess_a;
      snap.state = PlatoonPeerState::completed;
      snap.pid = 12345;
      snap.exit_code = 0;
      snap.output_tail = "done";
      snap.output_bytes = 4;
      snap.started_ns = 100;
      snap.finished_ns = 200;

      const Value val = to_value(snap);
      check(require_string(val, "peer_id") == "peer-val", "to_value peer_id mismatch");
      check(require_string(val, "driver") == "pi", "to_value driver mismatch");
      check(require_string(val, "role") == "coder", "to_value role mismatch");
      check(require_string(val, "owner_actor") == "alice@node-1",
            "to_value owner_actor mismatch");
      check(require_string(val, "command_room") == "ops:room-7",
            "to_value command_room mismatch");
      check(require_string(val, "tool_allowlist") == "read,bash,edit",
            "to_value tool_allowlist mismatch");
      check(require_string(val, "state") == "completed", "to_value state mismatch");
      check(require_field(val, "exit_code") == Value{Number{std::int64_t{0}}},
            "to_value exit_code mismatch");
      snap.exit_code.reset();
      const Value running_val = to_value(snap);
      check(std::holds_alternative<std::nullptr_t>(
                require_field(running_val, "exit_code").value()),
            "to_value null exit_code mismatch");
    }

    // 9. External CLI drivers (claude_code, codex, pi, antigravity) + C2 propagation.
    {
      PlatoonRunner runner{4};
      auto parse_first_line = [](const std::string &output) -> Value {
        const auto nl = output.find('\n');
        check(nl != std::string::npos, "missing json line in external peer output");
        const auto parsed = parse_json(std::string_view{output.data(), nl});
        check(parsed.has_value(), "invalid json from external peer");
        return parsed.value();
      };
      auto assert_argv = [](const Value &report,
                            const std::vector<std::string> &expected) {
        const auto &actual = require_field(report, "argv").array();
        check(actual.size() == expected.size(), "external driver argv length mismatch");
        for (std::size_t i = 0; i < expected.size(); ++i)
          check(actual[i].string() == expected[i],
                "external driver argv element mismatch");
      };

      // claude_code with model and C2 metadata.
      {
        PlatoonPeerSpec spec;
        spec.peer_id = "peer-claude";
        spec.driver = PlatoonPeerDriver::claude_code;
        spec.role = "implementer";
        spec.model = "claude-opus-4-6";
        spec.owner_actor = "patrick@macbook";
        spec.command_room = "platoon:alpha";
        spec.working_dir = work_a;
        spec.prompt = "refactor parser";
        spec.executable = self_exe;
        spec.extra_args = {"--max-turns", "4"};
        spec.extra_env = {{"BLACKBIRD_PLATOON_FAKE_PEER", "1"}};

        const auto spawned = runner.spawn(spec);
        check(spawned.has_value(), "claude_code spawn failed");
        const auto done = runner.wait("peer-claude", 5000);
        check(done.has_value() && done.value().state == PlatoonPeerState::completed,
              "claude_code did not complete");
        check(done.value().driver == PlatoonPeerDriver::claude_code,
              "claude_code snapshot driver mismatch");
        check(done.value().owner_actor == "patrick@macbook",
              "claude_code owner_actor mismatch");
        check(done.value().command_room == "platoon:alpha",
              "claude_code command_room mismatch");
        const Value report = parse_first_line(done.value().output_tail);
        assert_argv(report,
                    {"-p", "refactor parser", "--output-format", "stream-json",
                     "--verbose", "--model", "claude-opus-4-6", "--max-turns", "4"});
        const Value snap_val = to_value(done.value());
        check(require_string(snap_val, "driver") == "claude_code",
              "claude_code to_value driver mismatch");
      }

      // codex without model (omits -m) and empty owner_actor normalized to "local".
      {
        PlatoonPeerSpec spec;
        spec.peer_id = "peer-codex";
        spec.driver = PlatoonPeerDriver::codex;
        spec.role = "reviewer";
        spec.owner_actor = "";
        spec.working_dir = work_b;
        spec.prompt = "audit diff";
        spec.executable = self_exe;
        spec.extra_env = {{"BLACKBIRD_PLATOON_FAKE_PEER", "1"}};

        const auto spawned = runner.spawn(spec);
        check(spawned.has_value(), "codex spawn failed");
        const auto done = runner.wait("peer-codex", 5000);
        check(done.has_value() && done.value().state == PlatoonPeerState::completed,
              "codex did not complete");
        check(done.value().owner_actor == "local",
              "empty owner_actor did not normalize to local");
        const Value report = parse_first_line(done.value().output_tail);
        assert_argv(report, {"exec", "--json", "audit diff"});
        check(require_string(report, "cwd") == work_b.string(), "codex wrong cwd");
      }

      // codex with model and extra_args.
      {
        PlatoonPeerSpec spec;
        spec.peer_id = "peer-codex-m";
        spec.driver = PlatoonPeerDriver::codex;
        spec.role = "reviewer";
        spec.model = "o4-mini";
        spec.working_dir = work_a;
        spec.prompt = "check tests";
        spec.executable = self_exe;
        spec.extra_args = {"--full-auto"};
        spec.extra_env = {{"BLACKBIRD_PLATOON_FAKE_PEER", "1"}};

        check(runner.spawn(spec).has_value(), "codex-m spawn failed");
        const auto done = runner.wait("peer-codex-m", 5000);
        check(done.has_value() && done.value().state == PlatoonPeerState::completed,
              "codex-m did not complete");
        const Value report = parse_first_line(done.value().output_tail);
        assert_argv(report,
                    {"exec", "--json", "-m", "o4-mini", "--full-auto", "check tests"});
      }

      // pi with provider, model, session_dir, and tool_allowlist.
      {
        PlatoonPeerSpec spec;
        spec.peer_id = "peer-pi";
        spec.driver = PlatoonPeerDriver::pi;
        spec.role = "scout";
        spec.provider = "anthropic";
        spec.model = "claude-sonnet-4-5";
        spec.session_dir = sess_a;
        spec.tool_allowlist = "read,grep,find,ls";
        spec.owner_actor = "bob@wintermute";
        spec.command_room = "lend-lease-1";
        spec.working_dir = work_a;
        spec.prompt = "scan headers";
        spec.executable = self_exe;
        spec.extra_env = {{"BLACKBIRD_PLATOON_FAKE_PEER", "1"}};

        check(runner.spawn(spec).has_value(), "pi spawn failed");
        const auto done = runner.wait("peer-pi", 5000);
        check(done.has_value() && done.value().state == PlatoonPeerState::completed,
              "pi did not complete");
        check(done.value().tool_allowlist == "read,grep,find,ls",
              "pi tool_allowlist not propagated");
        const Value report = parse_first_line(done.value().output_tail);
        assert_argv(report,
                    {"--mode", "json", "-p", "--provider", "anthropic", "--model",
                     "claude-sonnet-4-5", "--session-dir", sess_a.string(), "--tools",
                     "read,grep,find,ls", "scan headers"});
      }

      // antigravity with model and extra_args.
      {
        PlatoonPeerSpec spec;
        spec.peer_id = "peer-agy";
        spec.driver = PlatoonPeerDriver::antigravity;
        spec.role = "architect";
        spec.model = "gemini-3-pro";
        spec.working_dir = work_b;
        spec.prompt = "summarize architecture";
        spec.executable = self_exe;
        spec.extra_args = {"--yolo"};
        spec.extra_env = {{"BLACKBIRD_PLATOON_FAKE_PEER", "1"}};

        check(runner.spawn(spec).has_value(), "antigravity spawn failed");
        const auto done = runner.wait("peer-agy", 5000);
        check(done.has_value() && done.value().state == PlatoonPeerState::completed,
              "antigravity did not complete");
        const Value report = parse_first_line(done.value().output_tail);
        assert_argv(report, {"--non-interactive", "--model", "gemini-3-pro", "--yolo",
                             "summarize architecture"});
      }
    }

    // 10. Real stdio JSON-RPC ACP driver exchange (happy path + error + early exit).
    {
      PlatoonRunner runner{4};

      // Happy path: initialize -> session/new -> session/prompt -> clean stdin EOF.
      {
        PlatoonPeerSpec spec;
        spec.peer_id = "peer-acp";
        spec.driver = PlatoonPeerDriver::acp;
        spec.role = "acp-agent";
        spec.owner_actor = "alice@tailnet";
        spec.command_room = "opcon-room";
        spec.working_dir = work_a;
        spec.prompt = "run acp task";
        spec.executable = self_exe;
        spec.extra_args = {"--acp-stdio", "--profile", "strict"};
        spec.extra_env = {{"BLACKBIRD_PLATOON_FAKE_PEER", "1"},
                          {"BLACKBIRD_PLATOON_TEST_MODE", "acp"}};

        const auto spawned = runner.spawn(spec);
        check(spawned.has_value(), "acp spawn failed");
        const auto done = runner.wait("peer-acp", 5000);
        check(done.has_value(), "acp wait failed");
        check(done.value().state == PlatoonPeerState::completed,
              "acp peer did not complete");
        check(done.value().exit_code.has_value() && *done.value().exit_code == 0,
              "acp peer exit code != 0");
        check(done.value().driver == PlatoonPeerDriver::acp,
              "acp snapshot driver mismatch");
        check(done.value().owner_actor == "alice@tailnet", "acp owner_actor mismatch");
        check(done.value().command_room == "opcon-room", "acp command_room mismatch");
        const std::string &out = done.value().output_tail;
        check(out.find("fake-acp") != std::string::npos,
              "acp initialize response missing from output_tail");
        check(out.find("acp-sess-99") != std::string::npos,
              "acp session/new response missing from output_tail");
        check(out.find("acp:run acp task") != std::string::npos,
              "acp session/update notification missing from output_tail");
        check(out.find("--acp-stdio") != std::string::npos,
              "acp extra_args not passed to executable");
        check(out.find("end_turn") != std::string::npos,
              "acp session/prompt response missing from output_tail");
        check(out.find("ACP_STDERR_DIAG") != std::string::npos,
              "acp stderr missing from output_tail");
        check(out.find("ACP_EOF_CLEAN") != std::string::npos,
              "acp did not receive clean stdin EOF");
      }

      // JSON-RPC error during session/new marks peer failed and still closes stdin.
      {
        PlatoonPeerSpec spec;
        spec.peer_id = "peer-acp-err";
        spec.driver = PlatoonPeerDriver::acp;
        spec.role = "acp-agent";
        spec.working_dir = work_a;
        spec.prompt = "should fail";
        spec.executable = self_exe;
        spec.extra_env = {{"BLACKBIRD_PLATOON_FAKE_PEER", "1"},
                          {"BLACKBIRD_PLATOON_TEST_MODE", "acp_error"}};

        check(runner.spawn(spec).has_value(), "acp_error spawn failed");
        const auto done = runner.wait("peer-acp-err", 5000);
        check(done.has_value(), "acp_error wait failed");
        check(done.value().state == PlatoonPeerState::failed,
              "acp JSON-RPC error did not mark peer failed");
        check(done.value().output_tail.find("session denied") != std::string::npos,
              "acp error response missing from output_tail");
        check(done.value().output_tail.find("ACP_ERROR_EOF") != std::string::npos,
              "acp error path did not close stdin cleanly");
      }

      // Premature exit 0 before handshake completion marks peer failed.
      {
        PlatoonPeerSpec spec;
        spec.peer_id = "peer-acp-early";
        spec.driver = PlatoonPeerDriver::acp;
        spec.role = "acp-agent";
        spec.working_dir = work_a;
        spec.prompt = "early exit";
        spec.executable = self_exe;
        spec.extra_env = {{"BLACKBIRD_PLATOON_FAKE_PEER", "1"},
                          {"BLACKBIRD_PLATOON_TEST_MODE", "acp_early_exit"}};

        check(runner.spawn(spec).has_value(), "acp_early_exit spawn failed");
        const auto done = runner.wait("peer-acp-early", 5000);
        check(done.has_value(), "acp_early_exit wait failed");
        check(done.value().state == PlatoonPeerState::failed,
              "acp premature exit 0 did not mark peer failed");
      }
    }

    // 11. Validation rejections for C2 metadata, tool_allowlist, extra_args, and acp.
    {
      PlatoonRunner runner{2};
      PlatoonPeerSpec base;
      base.peer_id = "val-1";
      base.driver = PlatoonPeerDriver::pi;
      base.role = "worker";
      base.working_dir = work_a;
      base.prompt = "hi";
      base.executable = self_exe;

      for (const char *bad_actor :
           {"-bad", ".hidden", "../escape", "has space", "a/b",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}) {
        auto s = base;
        s.owner_actor = bad_actor;
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "invalid owner_actor accepted");
      }

      for (const char *bad_room : {"-room", ".room", "a..b", "bad room", "room/1"}) {
        auto s = base;
        s.command_room = bad_room;
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "invalid command_room accepted");
      }

      for (const char *bad_tools :
           {"-bash", "read, bash", "read;rm", ",read", "read,", "read,,edit",
            "read,-edit", "read\tbash", "read/file"}) {
        auto s = base;
        s.tool_allowlist = bad_tools;
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "invalid tool_allowlist accepted");
      }
      {
        auto s = base;
        s.tool_allowlist = std::string(1025, 'a');
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "oversized tool_allowlist accepted");
      }

      {
        auto s = base;
        s.extra_args.assign(PlatoonRunner::max_extra_args + 1U, "--flag");
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "too many extra_args accepted");
      }
      {
        auto s = base;
        s.extra_args = {std::string(PlatoonRunner::max_extra_arg_bytes + 1U, 'x')};
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "oversized extra_arg accepted");
      }
      {
        auto s = base;
        s.extra_args = {std::string{"abc\0def", 7}};
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "NUL in extra_arg accepted");
      }
      {
        auto s = base;
        s.driver = PlatoonPeerDriver::acp;
        s.executable.clear();
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "acp with empty executable accepted");
      }
      {
        auto s = base;
        s.model = "-leading";
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "leading dash model accepted");
      }
      {
        auto s = base;
        s.provider = "-leading";
        const auto r = runner.spawn(s);
        check(!r.has_value() && r.error().code == ErrorCode::invalid_range,
              "leading dash provider accepted");
      }
    }

    // 12. Ambient secret isolation for outside-agent drivers (allowlisted baseline
    // env).
    {
      struct ScopedEnv {
        std::string key;
        std::optional<std::string> previous;
        ScopedEnv(std::string env_key, const char *value) : key(std::move(env_key)) {
          if (const char *old = std::getenv(key.c_str()))
            previous = std::string{old};
          (void)::setenv(key.c_str(), value, 1);
        }
        ~ScopedEnv() {
          if (previous.has_value())
            (void)::setenv(key.c_str(), previous->c_str(), 1);
          else
            (void)::unsetenv(key.c_str());
        }
      };

      ScopedEnv env_ant{"ANTHROPIC_API_KEY", "sk-ant-do-not-leak"};
      ScopedEnv env_oai{"OPENAI_API_KEY", "sk-oai-do-not-leak"};
      ScopedEnv env_tok{"SECRET_TOKEN", "tok-do-not-leak"};
      ScopedEnv env_gem{"GEMINI_API_KEY", "gem-do-not-leak"};
      ScopedEnv env_key{"CUSTOM_KEY", "custom-do-not-leak"};
      ScopedEnv env_xdg_sec{"XDG_SECRET_TOKEN", "xdg-secret-do-not-leak"};
      ScopedEnv env_unrel{"UNRELATED_AMBIENT", "ambient-do-not-leak"};
      ScopedEnv env_xdg{"XDG_CONFIG_HOME", "/tmp/blackbird-xdg-test"};
      ScopedEnv env_board{"BLACKBIRD_PLATOON_BOARD", "/tmp/blackbird-board-allow"};

      PlatoonRunner runner{6};
      auto parse_first_line = [](const std::string &output) -> Value {
        const auto nl = output.find('\n');
        check(nl != std::string::npos, "missing json line in env-isolation peer");
        const auto parsed = parse_json(std::string_view{output.data(), nl});
        check(parsed.has_value(), "invalid json from env-isolation peer");
        return parsed.value();
      };

      for (const auto driver :
           {PlatoonPeerDriver::claude_code, PlatoonPeerDriver::codex,
            PlatoonPeerDriver::pi, PlatoonPeerDriver::antigravity}) {
        PlatoonPeerSpec spec;
        spec.peer_id = std::string{"env-"} + platoon_driver_name(driver);
        spec.driver = driver;
        spec.role = "external";
        spec.working_dir = work_a;
        spec.prompt = "check env isolation";
        spec.executable = self_exe;
        spec.extra_env = {{"BLACKBIRD_PLATOON_FAKE_PEER", "1"}};

        const auto spawned = runner.spawn(spec);
        check(spawned.has_value(), "env-isolation external peer spawn failed");
        const auto done = runner.wait(spec.peer_id, 5000);
        check(done.has_value() && done.value().state == PlatoonPeerState::completed,
              "env-isolation external peer did not complete");
        const Value report = parse_first_line(done.value().output_tail);
        check(require_field(report, "leaked_env").array().empty(),
              "ambient secret or non-allowlisted env leaked into external peer");
        check(require_field(report, "has_path") == Value{true},
              "allowlisted PATH missing in external peer");
        check(require_string(report, "xdg_config") == "/tmp/blackbird-xdg-test",
              "allowlisted XDG_CONFIG_HOME missing in external peer");
        check(require_string(report, "board") == "/tmp/blackbird-board-allow",
              "allowlisted BLACKBIRD_PLATOON_BOARD missing in external peer");
      }

      // Verify ACP driver also receives clean allowlisted baseline env with zero leaks.
      {
        PlatoonPeerSpec spec;
        spec.peer_id = "env-acp";
        spec.driver = PlatoonPeerDriver::acp;
        spec.role = "acp-external";
        spec.working_dir = work_a;
        spec.prompt = "check acp env isolation";
        spec.executable = self_exe;
        spec.extra_env = {{"BLACKBIRD_PLATOON_FAKE_PEER", "1"},
                          {"BLACKBIRD_PLATOON_TEST_MODE", "acp"}};

        check(runner.spawn(spec).has_value(), "env-acp spawn failed");
        const auto done = runner.wait("env-acp", 5000);
        check(done.has_value() && done.value().state == PlatoonPeerState::completed,
              "env-acp did not complete");
        const std::string &out = done.value().output_tail;
        check(out.find("\"leaked_env\":[]") != std::string::npos,
              "ambient secret leaked into acp peer");
        check(out.find("\"has_path\":true") != std::string::npos,
              "allowlisted PATH missing in acp peer");
        check(out.find("/tmp/blackbird-xdg-test") != std::string::npos,
              "allowlisted XDG_CONFIG_HOME missing in acp peer");
      }
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
