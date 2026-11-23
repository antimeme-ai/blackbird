#include "../src/native_process.hpp"
#include "blackbird/local_swarm.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

extern char **environ;

using namespace blackbird;

namespace {

namespace fs = std::filesystem;
using SteadyClock = std::chrono::steady_clock;

const char *g_stage = "startup";

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(std::string{g_stage} + ": " + message);
}

template <class T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + ": " + context + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
  return std::move(result).value();
}

void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + ": " + context + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
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

std::string run_git_checked(const fs::path &dir, std::vector<std::string> subargs) {
  std::vector<std::string> argv;
  argv.reserve(subargs.size() + 3U);
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
    throw std::runtime_error("git command failed: " + out);
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
    out.pop_back();
  return out;
}

void write_text_file(const fs::path &path, std::string_view content) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  check(static_cast<bool>(out), "failed to open file for writing");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  check(static_cast<bool>(out), "failed to write file");
}

void init_temp_repo(const fs::path &repo_dir) {
  fs::create_directories(repo_dir);
  (void)run_git_checked(repo_dir, {"init", "-b", "main"});
  (void)run_git_checked(repo_dir, {"config", "user.name", "Blackbird Test"});
  (void)run_git_checked(repo_dir, {"config", "user.email", "test@blackbird.local"});
  (void)run_git_checked(repo_dir, {"config", "commit.gpgsign", "false"});
  write_text_file(repo_dir / "README.md", "local swarm test repo\n");
  (void)run_git_checked(repo_dir, {"add", "README.md"});
  (void)run_git_checked(repo_dir, {"commit", "-m", "initial commit"});
}

void test_name_and_mention_validation() {
  g_stage = "name_and_mention_validation";

  check(valid_swarm_worker_name("a"), "single lowercase char rejected");
  check(valid_swarm_worker_name("0"), "single digit rejected");
  check(valid_swarm_worker_name("builder"), "builder rejected");
  check(valid_swarm_worker_name("audit-1"), "audit-1 rejected");
  check(valid_swarm_worker_name("dentist_2"), "dentist_2 rejected");
  check(valid_swarm_worker_name(std::string(24, 'a')), "24-char name rejected");

  check(!valid_swarm_worker_name(""), "empty name accepted");
  check(!valid_swarm_worker_name(std::string(25, 'a')), "25-char name accepted");
  check(!valid_swarm_worker_name("-lead"), "leading hyphen accepted");
  check(!valid_swarm_worker_name("_lead"), "leading underscore accepted");
  check(!valid_swarm_worker_name("Builder"), "uppercase accepted");
  check(!valid_swarm_worker_name("has space"), "space accepted");
  check(!valid_swarm_worker_name("dot.name"), "dot accepted");
  check(!valid_swarm_worker_name("all"), "reserved 'all' accepted");
  check(!valid_swarm_worker_name("coordinator"), "reserved 'coordinator' accepted");
  check(!valid_swarm_worker_name("coordinator-1"), "reserved 'coordinator-1' accepted");
  check(!valid_swarm_worker_name("coordinator-sub"),
        "reserved 'coordinator-sub' accepted");

  PlatoonMessage msg;
  msg.seq = 1;
  msg.from = "scout";
  msg.to = "other";
  msg.kind = PlatoonMessageKind::message;

  msg.text = "please inspect @builder-2 and user@builder or @builder_1 or @builder2";
  check(!swarm_message_mentions_agent(msg, "builder"),
        "false positive mention on non-boundary token");

  msg.text = "do not match @allow or @all-1 or email@all";
  check(!swarm_message_mentions_agent(msg, "builder"),
        "false positive @all mention on non-boundary token");

  msg.text = "hey (@builder): ready";
  check(swarm_message_mentions_agent(msg, "builder"),
        "failed to match @builder on punctuation boundaries");

  msg.text = "broadcast to @all!";
  check(swarm_message_mentions_agent(msg, "builder"), "failed to match @all broadcast");

  msg.text = "plain text without mention";
  msg.to = "builder";
  check(swarm_message_mentions_agent(msg, "builder"), "failed to match direct to==");

  msg.to = "all";
  check(swarm_message_mentions_agent(msg, "builder"), "failed to match to=='all'");
}

void test_wait_preexisting_and_reactive(const fs::path &base) {
  g_stage = "wait_preexisting_and_reactive";
  auto board = must(PlatoonBoard::open(base / "wait-board"), "open wait board");

  // 1. Pre-existing unread mention wakes immediately (0ms wait).
  const auto m1 = must(board.post({"coordinator",
                                   "other",
                                   PlatoonMessageKind::message,
                                   "first unrelated note",
                                   {}}),
                       "post m1");
  const auto m2 = must(board.post({"coordinator",
                                   "other",
                                   PlatoonMessageKind::message,
                                   "hey @builder pick this up",
                                   {}}),
                       "post m2");
  check(m1.seq == 1 && m2.seq == 2, "unexpected initial seqs");

  {
    const auto t0 = SteadyClock::now();
    const auto res = must(wait_for_board_mention(board,
                                                 SwarmBoardWaitOptions{
                                                     .agent_name = "builder",
                                                     .since_seq = 0,
                                                     .mentions_only = true,
                                                     .timeout_ms = 5000,
                                                 }),
                          "wait preexisting mention");
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - t0)
            .count();
    check(res.woken && !res.timed_out && !res.cancelled,
          "preexisting mention did not wake");
    check(elapsed_ms < 200, "preexisting mention took too long");
    check(res.latest_seq == 2, "preexisting latest_seq mismatch");
    check(res.messages.size() == 2 && res.messages[0].seq == 1 &&
              res.messages[1].seq == 2,
          "preexisting wake did not return all unread messages");
  }

  // 2. Background thread posts unrelated message (must stay asleep), then @builder
  //    (must wake immediately < 200ms returning ALL unread messages since seq 2).
  {
    std::atomic<std::int64_t> mention_post_ns{0};
    std::thread poster([&] {
      auto writer = PlatoonBoard::open(board.root());
      if (!writer.has_value())
        return;
      std::this_thread::sleep_for(std::chrono::milliseconds{40});
      (void)writer.value().post({"scout",
                                 "other",
                                 PlatoonMessageKind::message,
                                 "unrelated chatter mentioning @builder-2",
                                 {}});
      std::this_thread::sleep_for(std::chrono::milliseconds{80});
      mention_post_ns.store(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                SteadyClock::now().time_since_epoch())
                                .count(),
                            std::memory_order_release);
      (void)writer.value().post({"scout",
                                 "other",
                                 PlatoonMessageKind::handoff,
                                 "handoff for @builder right now",
                                 {}});
    });

    const auto res = must(wait_for_board_mention(board,
                                                 SwarmBoardWaitOptions{
                                                     .agent_name = "builder",
                                                     .since_seq = 2,
                                                     .mentions_only = true,
                                                     .timeout_ms = 5000,
                                                 }),
                          "wait reactive @builder");
    const auto wake_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             SteadyClock::now().time_since_epoch())
                             .count();
    poster.join();

    const std::int64_t posted_ns = mention_post_ns.load(std::memory_order_acquire);
    check(posted_ns > 0, "poster did not record mention timestamp");
    const auto latency_ms = (wake_ns - posted_ns) / 1'000'000LL;
    check(res.woken && !res.timed_out && !res.cancelled, "reactive wait did not wake");
    check(
        res.messages.size() == 2 && res.messages[0].seq == 3 &&
            res.messages[1].seq == 4,
        "reactive wake missed earlier unread message or woke early on unrelated post");
    check(res.latest_seq == 4, "reactive latest_seq mismatch");
    check(latency_ms < 200, "reactive wakeup latency exceeded 200ms");
  }

  // 3. @all wakes waiting worker immediately.
  {
    std::atomic<std::int64_t> broadcast_post_ns{0};
    std::thread poster([&] {
      auto writer = PlatoonBoard::open(board.root());
      if (!writer.has_value())
        return;
      std::this_thread::sleep_for(std::chrono::milliseconds{40});
      broadcast_post_ns.store(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                  SteadyClock::now().time_since_epoch())
                                  .count(),
                              std::memory_order_release);
      (void)writer.value().post({"coordinator",
                                 "other",
                                 PlatoonMessageKind::decision,
                                 "heads up @all freeze edits",
                                 {}});
    });

    const auto res = must(wait_for_board_mention(board,
                                                 SwarmBoardWaitOptions{
                                                     .agent_name = "builder",
                                                     .since_seq = 4,
                                                     .mentions_only = true,
                                                     .timeout_ms = 5000,
                                                 }),
                          "wait reactive @all");
    const auto wake_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             SteadyClock::now().time_since_epoch())
                             .count();
    poster.join();

    const auto latency_ms =
        (wake_ns - broadcast_post_ns.load(std::memory_order_acquire)) / 1'000'000LL;
    check(res.woken && res.messages.size() == 1 && res.messages[0].seq == 5,
          "@all did not wake waiting worker");
    check(latency_ms < 200, "@all wakeup latency exceeded 200ms");
  }

  // 4. mentions_only = false wakes on any post even when directed elsewhere.
  {
    std::thread poster([&] {
      auto writer = PlatoonBoard::open(board.root());
      if (!writer.has_value())
        return;
      std::this_thread::sleep_for(std::chrono::milliseconds{30});
      (void)writer.value().post(
          {"scout", "other", PlatoonMessageKind::status, "quiet update", {}});
    });

    const auto res = must(wait_for_board_mention(board,
                                                 SwarmBoardWaitOptions{
                                                     .agent_name = "builder",
                                                     .since_seq = 5,
                                                     .mentions_only = false,
                                                     .timeout_ms = 5000,
                                                 }),
                          "wait mentions_only=false");
    poster.join();
    check(res.woken && res.messages.size() == 1 && res.messages[0].seq == 6,
          "mentions_only=false did not wake on unrelated post");
  }

  // 5. Cancellation flag wakes immediately.
  {
    std::atomic_bool cancel{false};
    std::atomic<std::int64_t> cancel_set_ns{0};
    std::thread canceller([&] {
      std::this_thread::sleep_for(std::chrono::milliseconds{40});
      cancel_set_ns.store(std::chrono::duration_cast<std::chrono::nanoseconds>(
                              SteadyClock::now().time_since_epoch())
                              .count(),
                          std::memory_order_release);
      cancel.store(true, std::memory_order_release);
    });

    const auto res = must(wait_for_board_mention(board,
                                                 SwarmBoardWaitOptions{
                                                     .agent_name = "builder",
                                                     .since_seq = 6,
                                                     .mentions_only = true,
                                                     .timeout_ms = 5000,
                                                     .cancel = &cancel,
                                                 }),
                          "wait cancelled");
    const auto wake_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             SteadyClock::now().time_since_epoch())
                             .count();
    canceller.join();

    const auto latency_ms =
        (wake_ns - cancel_set_ns.load(std::memory_order_acquire)) / 1'000'000LL;
    check(!res.woken && !res.timed_out && res.cancelled,
          "cancellation flag did not return cancelled=true");
    check(latency_ms < 200, "cancellation wakeup took too long");
  }

  // 6. Timeout returns {woken: false, timed_out: true} cleanly.
  {
    const auto res = must(wait_for_board_mention(board,
                                                 SwarmBoardWaitOptions{
                                                     .agent_name = "builder",
                                                     .since_seq = 6,
                                                     .mentions_only = true,
                                                     .timeout_ms = 60,
                                                 }),
                          "wait timeout");
    check(!res.woken && res.timed_out && !res.cancelled,
          "timeout did not return {woken:false, timed_out:true}");
  }

  // 7. Extreme INT64_MAX timeout clamps safely without overflow when cancelled,
  //    and mismatched board root is rejected with wrong_environment.
  {
    std::atomic_bool cancel{true};
    const auto res =
        must(wait_for_board_mention(
                 board,
                 SwarmBoardWaitOptions{
                     .agent_name = "builder",
                     .since_seq = 6,
                     .mentions_only = true,
                     .timeout_ms = std::numeric_limits<std::int64_t>::max(),
                     .cancel = &cancel,
                 }),
             "wait INT64_MAX timeout with cancel");
    check(!res.woken && !res.timed_out && res.cancelled,
          "INT64_MAX timeout with pre-set cancel failed");

    auto other_board =
        must(PlatoonBoard::open(base / "other-wait-board"), "open other board");
    auto waiter = must(SwarmBoardWaiter::open(board.root()), "open waiter");
    const auto mismatch = waiter.wait(other_board, SwarmBoardWaitOptions{
                                                       .agent_name = "builder",
                                                       .since_seq = 0,
                                                       .mentions_only = true,
                                                       .timeout_ms = 0,
                                                   });
    check(!mismatch.has_value() &&
              mismatch.error().code == ErrorCode::wrong_environment,
          "mismatched board root was accepted by SwarmBoardWaiter::wait");
  }
}

void test_owned_files_disjoint_and_scope(const fs::path &base) {
  g_stage = "owned_files_disjoint_and_scope";
  auto coord = must(LocalSwarmCoordinator::open(LocalSwarmConfig{
                        .board_root = base / "swarm-owned",
                        .swarm_title = "wave-8c",
                    }),
                    "open coordinator");

  // Author 1 claims include/blackbird/a.hpp and src/sub.
  SwarmWorkerSpec author1;
  author1.name = "author-1";
  author1.role = "builder";
  author1.provider = "anthropic";
  author1.model = "claude-sonnet";
  author1.workspace_mode = SwarmWorkspaceMode::share;
  author1.owned_files = {"./include/blackbird//a.hpp", "src/sub"};
  author1.brief = "Implement A";
  const auto w1 = must(coord.add_worker(author1), "add author-1");
  check(w1.owned_files.size() == 2 && w1.owned_files[0] == "include/blackbird/a.hpp" &&
            w1.owned_files[1] == "src/sub",
        "owned_files were not normalized and sorted");
  check(w1.brief_seq == 1, "author-1 brief was not posted to board");

  // Overlapping exact path rejected with ErrorCode::conflict.
  SwarmWorkerSpec overlap_exact = author1;
  overlap_exact.name = "author-2";
  overlap_exact.owned_files = {"include/blackbird/a.hpp"};
  const auto exact_err = coord.add_worker(overlap_exact);
  check(!exact_err.has_value() && exact_err.error().code == ErrorCode::conflict,
        "overlapping exact owned_files was not rejected with conflict");

  // Overlapping nested path under owned directory rejected with ErrorCode::conflict.
  SwarmWorkerSpec overlap_nested = author1;
  overlap_nested.name = "author-2";
  overlap_nested.owned_files = {"src/sub/detail.cpp"};
  const auto nested_err = coord.add_worker(overlap_nested);
  check(!nested_err.has_value() && nested_err.error().code == ErrorCode::conflict,
        "overlapping nested owned_files was not rejected with conflict");

  // Path traversal in owned_files rejected with ErrorCode::invalid_range.
  SwarmWorkerSpec traversal = author1;
  traversal.name = "author-bad";
  traversal.owned_files = {"../outside.cpp"};
  const auto trav_err = coord.add_worker(traversal);
  check(!trav_err.has_value() && trav_err.error().code == ErrorCode::invalid_range,
        "path traversal in owned_files was accepted");

  // Disjoint files succeed (including prefix-similar non-overlapping path).
  SwarmWorkerSpec author2;
  author2.name = "author-2";
  author2.role = "builder";
  author2.provider = "openai";
  author2.model = "gpt-5";
  author2.workspace_mode = SwarmWorkspaceMode::share;
  author2.owned_files = {"include/blackbird/a.hpp.bak", "src/sub_extra/b.cpp"};
  author2.brief = "Implement B";
  const auto w2 = must(coord.add_worker(author2), "add disjoint author-2");
  check(w2.name == "author-2" && w2.brief_seq == 2, "disjoint author-2 failed");

  // verify_owned_files_scope accepts exact, normalized, and owned-dir children.
  const auto scope_ok =
      must(coord.verify_owned_files_scope(
               "author-1", {"include/blackbird/a.hpp", "./src//sub/nested/file.cpp"}),
           "verify in-scope files");
  check(scope_ok.ok && scope_ok.violations.empty() &&
            scope_ok.verified_paths.size() == 2,
        "valid in-scope paths were rejected");

  // verify_owned_files_scope rejects out-of-scope, sibling prefix, traversal, absolute.
  const auto scope_bad = must(
      coord.verify_owned_files_scope(
          "author-1", {"include/blackbird/a.hpp", "src/other.cpp",
                       "src/sub_extra/b.cpp", "../escape.cpp", "src/sub/../secret.cpp",
                       "/etc/passwd", "src\\sub\\win.cpp"}),
      "verify out-of-scope and traversal files");
  check(!scope_bad.ok, "out-of-scope/traversal edits were accepted");
  check(scope_bad.verified_paths.size() == 1 &&
            scope_bad.verified_paths[0] == "include/blackbird/a.hpp",
        "unexpected verified_paths count");
  check(scope_bad.violations.size() == 6, "expected exactly 6 scope violations");

  // Killing author-1 frees its owned_files so author-3 can claim them.
  (void)must(coord.kill_worker("author-1"), "kill author-1");
  SwarmWorkerSpec author3 = author1;
  author3.name = "author-3";
  author3.owned_files = {"include/blackbird/a.hpp"};
  author3.brief = "Take over A";
  const auto w3 = must(coord.add_worker(author3), "add author-3 after kill");
  check(w3.name == "author-3", "author-3 could not claim killed worker's files");
}

void test_sharded_group_and_dentist(const fs::path &base) {
  g_stage = "sharded_group_and_dentist";
  auto coord = must(LocalSwarmCoordinator::open(LocalSwarmConfig{
                        .board_root = base / "swarm-sharded",
                    }),
                    "open sharded coordinator");

  // Kimi-style sharded fan-out.
  SwarmWorkerSpec tmpl;
  tmpl.role = "scout";
  tmpl.provider = "moonshot";
  tmpl.model = "kimi-k2";
  tmpl.workspace_mode = SwarmWorkspaceMode::inherit;

  const auto group =
      must(coord.add_sharded_group("audit", {"a.cpp", "b.cpp", "c.cpp"},
                                   "Audit memory ownership and error paths", tmpl, 2),
           "add sharded group");
  check(group.size() == 3, "sharded group did not spawn 3 workers");
  check(group[0].name == "audit-1" && group[1].name == "audit-2" &&
            group[2].name == "audit-3",
        "sharded worker names mismatch");
  check(group[0].state == SwarmWorkerState::working &&
            group[1].state == SwarmWorkerState::working &&
            group[2].state == SwarmWorkerState::waiting,
        "max_concurrency=2 did not queue 3rd sharded worker as waiting");

  const auto board_msgs = must(coord.board().read_since(0, 32), "read sharded briefs");
  check(board_msgs.size() == 3, "expected 3 brief posts on board");
  check(board_msgs[0].to == "audit-1" &&
            board_msgs[0].text.find("@audit-1") != std::string::npos &&
            board_msgs[0].text.find("a.cpp") != std::string::npos,
        "audit-1 brief missing mention or target");
  check(board_msgs[1].to == "audit-2" &&
            board_msgs[1].text.find("b.cpp") != std::string::npos,
        "audit-2 brief missing target");
  check(board_msgs[2].to == "audit-3" &&
            board_msgs[2].text.find("c.cpp") != std::string::npos,
        "audit-3 brief missing target");

  // Reject > 32 tasks, 25-char derived names, and reserved coordinator-* prefix.
  std::vector<std::string> too_many(kSwarmMaxShardedTasks + 1U, "x.cpp");
  const auto cap_err = coord.add_sharded_group("cap", too_many, "audit", tmpl, 4);
  check(!cap_err.has_value() && cap_err.error().code == ErrorCode::capacity,
        "33 sharded tasks did not fail with capacity");

  const std::string long_base(23, 'z'); // + "-1" => 25 chars > 24
  const auto len_err = coord.add_sharded_group(long_base, {"x.cpp"}, "audit", tmpl, 1);
  check(!len_err.has_value() && len_err.error().code == ErrorCode::invalid_identity,
        "25-char sharded worker name was accepted");

  const auto reserved_err =
      coord.add_sharded_group("coordinator", {"x.cpp"}, "audit", tmpl, 1);
  check(!reserved_err.has_value() &&
            reserved_err.error().code == ErrorCode::invalid_identity,
        "coordinator-1 sharded name was accepted");

  // Built-in @dentist verifier preset.
  const auto dentist =
      must(coord.add_dentist_verifier("dentist-1",
                                      {"clang-format --dry-run --Werror", "clang-tidy"},
                                      SwarmDentistOptions{
                                          .provider = "anthropic",
                                          .model = "claude-opus",
                                      }),
           "add dentist-1");
  check(dentist.name == "dentist-1" && dentist.role == "dentist",
        "dentist name/role mismatch");
  check(dentist.workspace_mode == SwarmWorkspaceMode::inherit,
        "dentist must use inherit workspace");
  check(dentist.read_only && dentist.owned_files.empty(),
        "dentist must be read-only with empty owned_files");
  check(dentist.brief.find("clang-format --dry-run --Werror") != std::string::npos &&
            dentist.brief.find("clang-tidy") != std::string::npos,
        "dentist brief missing repo_checks");

  const auto dentist_clean =
      must(coord.verify_owned_files_scope("dentist-1", {}), "dentist empty diff");
  check(dentist_clean.ok, "dentist empty diff should be ok");
  const auto dentist_dirty =
      must(coord.verify_owned_files_scope("dentist-1", {"src/local_swarm.cpp"}),
           "dentist dirty diff");
  check(!dentist_dirty.ok && dentist_dirty.violations.size() == 1,
        "dentist modifying production file was not flagged");
}

void test_model_switch_and_kill_permanence(const fs::path &base) {
  g_stage = "model_switch_and_kill_permanence";
  auto coord = must(LocalSwarmCoordinator::open(LocalSwarmConfig{
                        .board_root = base / "swarm-lifecycle",
                    }),
                    "open lifecycle coordinator");

  SwarmWorkerSpec spec;
  spec.name = "builder-1";
  spec.role = "builder";
  spec.provider = "anthropic";
  spec.model = "claude-sonnet";
  spec.owned_files = {"src/foo.cpp"};
  spec.brief = "Build foo";
  spec.fork_from_session_dir = base / "parent-session";
  const auto initial = must(coord.add_worker(spec), "add builder-1");
  check(!initial.session_id.empty(), "auto-generated session_id is empty");
  check(initial.fork_from_session_dir == base / "parent-session",
        "fork_from_session_dir was not stored");

  // Reject model switch while working.
  const auto working_err = coord.switch_worker_model(SwarmModelSwitchRequest{
      .worker_name = "builder-1",
      .new_provider = "openai",
      .new_model = "gpt-5",
      .reason = "quota",
  });
  check(!working_err.has_value() && working_err.error().code == ErrorCode::conflict,
        "switch_worker_model succeeded on working worker");

  // Transition to waiting and switch model in-place.
  const auto waiting = must(
      coord.set_worker_state("builder-1", SwarmWorkerState::waiting), "set waiting");
  check(waiting.state == SwarmWorkerState::waiting, "worker state not waiting");

  const auto switched = must(coord.switch_worker_model(SwarmModelSwitchRequest{
                                 .worker_name = "builder-1",
                                 .new_provider = "openai",
                                 .new_model = "gpt-5",
                                 .reason = "quota-exhausted",
                             }),
                             "switch model on waiting worker");
  check(switched.provider == "openai" && switched.model == "gpt-5",
        "switched provider/model not updated");
  check(switched.session_id == initial.session_id,
        "switch_worker_model did not preserve session_id");

  const auto msgs = must(coord.board().read_since(0, 32), "read handoff messages");
  bool saw_handoff = false;
  for (const auto &msg : msgs) {
    if (msg.kind == PlatoonMessageKind::handoff && msg.to == "builder-1" &&
        msg.text.find(initial.session_id) != std::string::npos &&
        msg.text.find("openai/gpt-5") != std::string::npos &&
        msg.text.find("quota-exhausted") != std::string::npos) {
      saw_handoff = true;
    }
  }
  check(saw_handoff, "structured model-handoff message not found on board");

  // Permanently kill worker and verify irreversibility.
  const auto killed = must(coord.kill_worker("builder-1"), "kill builder-1");
  check(killed.state == SwarmWorkerState::killed, "killed worker state mismatch");

  const auto switch_killed = coord.switch_worker_model(SwarmModelSwitchRequest{
      .worker_name = "builder-1",
      .new_provider = "anthropic",
      .new_model = "claude-opus",
      .reason = "retry",
  });
  check(!switch_killed.has_value() && switch_killed.error().code == ErrorCode::conflict,
        "switch_worker_model succeeded on killed worker");

  const auto revive_err =
      coord.set_worker_state("builder-1", SwarmWorkerState::working);
  check(!revive_err.has_value() && revive_err.error().code == ErrorCode::conflict,
        "killed worker was revived via set_worker_state");

  const auto double_kill = coord.kill_worker("builder-1");
  check(!double_kill.has_value() && double_kill.error().code == ErrorCode::conflict,
        "double kill did not return conflict");

  const auto readd_err = coord.add_worker(spec);
  check(!readd_err.has_value() && readd_err.error().code == ErrorCode::conflict,
        "killed worker name was allowed to be re-added");
}

void test_worktree_lease_and_reopen_persistence(const fs::path &base) {
  g_stage = "worktree_lease_and_reopen_persistence";
  const fs::path repo_dir = base / "repo";
  const fs::path lease_root = base / "leases";
  const fs::path board_root = base / "board-wt";
  init_temp_repo(repo_dir);

  LocalSwarmConfig cfg;
  cfg.board_root = board_root;
  cfg.swarm_title = "native-swarm-wt";
  cfg.worktree_config = WorktreeLeaseConfig{
      .repo_root = repo_dir,
      .lease_root = lease_root,
      .max_leases = 4,
  };

  auto coord = must(LocalSwarmCoordinator::open(cfg), "open wt coordinator");

  SwarmWorkerSpec share_spec;
  share_spec.name = "wt-builder";
  share_spec.role = "builder";
  share_spec.provider = "anthropic";
  share_spec.model = "claude-sonnet";
  share_spec.workspace_mode = SwarmWorkspaceMode::share;
  share_spec.owned_files = {"README.md"};
  share_spec.brief = "Edit README in isolated worktree";
  const auto wt_worker = must(coord.add_worker(share_spec), "add share worker");
  check(!wt_worker.lease_id.empty() && !wt_worker.branch.empty(),
        "share worker did not acquire worktree lease");
  check(fs::exists(wt_worker.workspace_path / "README.md"),
        "acquired worktree directory missing repository files");

  const auto dentist =
      must(coord.add_dentist_verifier("dentist-wt"), "add inherit dentist");
  check(dentist.workspace_path == repo_dir && dentist.lease_id.empty(),
        "inherit dentist should point at repo_root with no lease");

  // Reopen coordinator and confirm state persisted cleanly.
  must_void(coord.set_title("native-swarm-wt-updated"), "set_title");
  check(coord.title() == "native-swarm-wt-updated", "updated swarm title mismatch");
  LocalSwarmConfig reopen_cfg = cfg;
  reopen_cfg.swarm_title.clear();
  auto reopened =
      must(LocalSwarmCoordinator::open(reopen_cfg), "reopen wt coordinator");
  check(reopened.title() == "native-swarm-wt-updated", "reopened swarm title mismatch");
  const auto roster = reopened.status();
  check(roster.size() == 2 && roster[0].name == "dentist-wt" &&
            roster[1].name == "wt-builder",
        "reopened roster mismatch");

  // Killing wt-builder releases and removes its worktree lease.
  const auto killed = must(reopened.kill_worker("wt-builder"), "kill wt-builder");
  check(killed.state == SwarmWorkerState::killed && killed.lease_id.empty(),
        "killed wt-builder retained lease_id");
  check(!fs::exists(wt_worker.workspace_path),
        "worktree directory still exists after kill_worker");

  auto wt_mgr = must(WorktreeLeaseManager::open(*cfg.worktree_config), "open wt_mgr");
  check(must(wt_mgr.list(), "list remaining leases").empty(),
        "worktree lease was not released on kill_worker");
}

void test_dentist_audit_regressions(const fs::path &base) {
  g_stage = "dentist_audit_regressions";

  // 1. Finding #1: wait_for_board_mention with max_messages=2 must NOT miss @builder
  //    at seq 4 after 3 unrelated messages (both pre-existing and reactive).
  {
    auto board = must(PlatoonBoard::open(base / "wait-paged"), "open paged wait board");
    (void)must(
        board.post({"scout", "other", PlatoonMessageKind::message, "noise 1", {}}),
        "post noise 1");
    (void)must(
        board.post({"scout", "other", PlatoonMessageKind::message, "noise 2", {}}),
        "post noise 2");
    (void)must(
        board.post({"scout", "other", PlatoonMessageKind::message, "noise 3", {}}),
        "post noise 3");

    // Pre-check timeout accurately reports latest_seq == 3 despite max_messages == 2.
    const auto empty_wait = must(wait_for_board_mention(board,
                                                        SwarmBoardWaitOptions{
                                                            .agent_name = "builder",
                                                            .since_seq = 0,
                                                            .mentions_only = true,
                                                            .timeout_ms = 0,
                                                            .max_messages = 2,
                                                        }),
                                 "paged non-matching check");
    check(!empty_wait.woken && empty_wait.timed_out && empty_wait.latest_seq == 3,
          "paged check did not advance latest_seq across all unread pages");

    // Reactive post of @builder at seq 4 wakes immediately and retains triggering msg.
    std::thread poster([&] {
      auto writer = PlatoonBoard::open(board.root());
      if (!writer.has_value())
        return;
      std::this_thread::sleep_for(std::chrono::milliseconds{30});
      (void)writer.value().post({"scout",
                                 "other",
                                 PlatoonMessageKind::handoff,
                                 "wake up @builder at seq 4",
                                 {}});
    });
    const auto woken = must(wait_for_board_mention(board,
                                                   SwarmBoardWaitOptions{
                                                       .agent_name = "builder",
                                                       .since_seq = 0,
                                                       .mentions_only = true,
                                                       .timeout_ms = 3000,
                                                       .max_messages = 2,
                                                   }),
                            "paged reactive wake");
    poster.join();
    check(woken.woken && !woken.timed_out && woken.latest_seq == 4,
          "paged wait missed mention past max_messages");
    check(
        woken.messages.size() == 2 && woken.messages[0].seq == 3 &&
            woken.messages[1].seq == 4,
        "paged wait did not return bounded tail window containing triggering mention");
  }

  // 2. Finding #2: add_sharded_group partial failure rolls back all earlier slices,
  //    their worktree leases, and persisted local_swarm.json cleanly.
  {
    const fs::path repo_dir = base / "repo-rollback";
    const fs::path lease_root = base / "leases-rollback";
    const fs::path board_root = base / "board-rollback";
    init_temp_repo(repo_dir);

    LocalSwarmConfig cfg;
    cfg.board_root = board_root;
    cfg.worktree_config = WorktreeLeaseConfig{
        .repo_root = repo_dir,
        .lease_root = lease_root,
        .max_leases = 1,
    };
    auto coord = must(LocalSwarmCoordinator::open(cfg), "open rollback coordinator");

    SwarmWorkerSpec tmpl;
    tmpl.role = "builder";
    tmpl.workspace_mode = SwarmWorkspaceMode::share;
    const auto res =
        coord.add_sharded_group("shard", {"a.cpp", "b.cpp"}, "work", tmpl, 2);
    check(!res.has_value(), "2 share workers with max_leases=1 unexpectedly succeeded");
    check(coord.status().empty(),
          "add_sharded_group partial failure leaked worker in memory");

    auto wt_mgr =
        must(WorktreeLeaseManager::open(*cfg.worktree_config), "open rollback wt_mgr");
    check(must(wt_mgr.list(), "list rollback leases").empty(),
          "add_sharded_group partial failure leaked git worktree lease");

    auto reopened =
        must(LocalSwarmCoordinator::open(cfg), "reopen rollback coordinator");
    check(reopened.status().empty(),
          "add_sharded_group partial failure leaked worker in local_swarm.json");
  }

  // 3. Finding #3: invalid spec.base_ref rejected in add_worker & add_sharded_group.
  {
    auto coord = must(LocalSwarmCoordinator::open(LocalSwarmConfig{
                          .board_root = base / "board-baseref",
                      }),
                      "open baseref coordinator");
    SwarmWorkerSpec bad_ref;
    bad_ref.name = "bad-ref-1";
    bad_ref.brief = "test";
    bad_ref.base_ref = std::string("HEAD\0bad", 8);
    const auto r1 = coord.add_worker(bad_ref);
    check(!r1.has_value() && r1.error().code == ErrorCode::invalid_range,
          "NUL base_ref was accepted by add_worker");

    const auto r2 = coord.add_sharded_group("grp", {"a.cpp"}, "shared", bad_ref, 1);
    check(!r2.has_value() && r2.error().code == ErrorCode::invalid_range,
          "NUL base_ref was accepted by add_sharded_group");
  }

  // 4. Finding #4: tampered local_swarm.json rejected with ErrorCode::corrupt
  //    (overlapping owned_files, > max_workers, duplicate owned_files, bad title).
  {
    const fs::path board_root = base / "board-tamper";
    auto coord = must(LocalSwarmCoordinator::open(LocalSwarmConfig{
                          .board_root = board_root,
                      }),
                      "open tamper coordinator");
    SwarmWorkerSpec w1;
    w1.name = "w1";
    w1.brief = "one";
    w1.owned_files = {"src/a.cpp"};
    SwarmWorkerSpec w2;
    w2.name = "w2";
    w2.brief = "two";
    w2.owned_files = {"src/b.cpp"};
    (void)must(coord.add_worker(w1), "add w1");
    (void)must(coord.add_worker(w2), "add w2");

    // 4a. Reject exceeding config.max_workers on reopen.
    const auto too_many = LocalSwarmCoordinator::open(LocalSwarmConfig{
        .board_root = board_root,
        .max_workers = 1,
    });
    check(!too_many.has_value() && too_many.error().code == ErrorCode::corrupt,
          "local_swarm.json exceeding max_workers was accepted");

    // 4b. Tamper w2's owned_files to overlap w1 ("src/a.cpp").
    const fs::path state_path = board_root / "local_swarm.json";
    std::string raw;
    {
      std::ifstream in(state_path, std::ios::binary);
      raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    const std::size_t pos = raw.find("src/b.cpp");
    check(pos != std::string::npos, "could not locate src/b.cpp in local_swarm.json");
    std::string overlap_json = raw;
    overlap_json.replace(pos, 9, "src/a.cpp");
    write_text_file(state_path, overlap_json);
    const auto overlap_open = LocalSwarmCoordinator::open(LocalSwarmConfig{
        .board_root = board_root,
    });
    check(!overlap_open.has_value() && overlap_open.error().code == ErrorCode::corrupt,
          "tampered overlapping owned_files in local_swarm.json was accepted");

    // 4c. Tamper duplicate owned_files within one worker.
    std::string dup_json = raw;
    const std::size_t a_pos = dup_json.find("\"src/a.cpp\"");
    check(a_pos != std::string::npos, "could not locate src/a.cpp in local_swarm.json");
    dup_json.replace(a_pos, 11, "\"src/a.cpp\",\"src/a.cpp\"");
    write_text_file(state_path, dup_json);
    const auto dup_open = LocalSwarmCoordinator::open(LocalSwarmConfig{
        .board_root = board_root,
    });
    check(!dup_open.has_value() && dup_open.error().code == ErrorCode::corrupt,
          "tampered duplicate owned_files in local_swarm.json was accepted");
  }
}

} // namespace

int main() {
  try {
    TempDir tmp{"blackbird-local-swarm-test"};
    test_name_and_mention_validation();
    test_wait_preexisting_and_reactive(tmp.path());
    test_owned_files_disjoint_and_scope(tmp.path());
    test_sharded_group_and_dentist(tmp.path());
    test_model_switch_and_kill_permanence(tmp.path());
    test_worktree_lease_and_reopen_persistence(tmp.path());
    test_dentist_audit_regressions(tmp.path());
    std::cout << "local_swarm_test: all checks passed\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "FAIL [" << g_stage << "]: " << ex.what() << "\n";
    return 1;
  }
}
