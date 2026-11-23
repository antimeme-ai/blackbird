#include "blackbird/platoon_board.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

const char *g_stage = "startup";

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

template <class T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{context} + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
  return std::move(result).value();
}

void test_directory_and_security(const std::filesystem::path &base) {
  g_stage = "directory_and_security";
  const auto board_dir = base / "nested" / "board-root";
  auto board = must(PlatoonBoard::open(board_dir), "open nested root");
  check(board.root() == board_dir, "board root mismatch");

  struct stat st{};
  check(::lstat(board_dir.c_str(), &st) == 0, "lstat board dir failed");
  check(S_ISDIR(st.st_mode), "board root is not a directory");
  check((st.st_mode & 0777) == 0700, "board root permissions are not 0700");

  // Reject symlink as root.
  const auto link_dir = base / "symlink-root";
  check(::symlink(board_dir.c_str(), link_dir.c_str()) == 0,
        "failed to create symlink");
  const auto symlink_open = PlatoonBoard::open(link_dir);
  check(!symlink_open.has_value(), "symlink root was accepted");

  // Reject overly-permissive existing directory.
  const auto open_dir = base / "world-readable";
  check(::mkdir(open_dir.c_str(), mode_t{0755}) == 0, "mkdir 0755 failed");
  check(::chmod(open_dir.c_str(), mode_t{0755}) == 0, "chmod 0755 failed");
  const auto permissive_open = PlatoonBoard::open(open_dir);
  check(!permissive_open.has_value() && permissive_open.error().code == ErrorCode::io,
        "0755 directory was accepted");

  // Reject empty path.
  const auto empty_open = PlatoonBoard::open(std::filesystem::path{});
  check(!empty_open.has_value() && empty_open.error().code == ErrorCode::invalid_range,
        "empty root path was accepted");

  // Move construction and move assignment transfer descriptor ownership cleanly.
  PlatoonBoard moved = std::move(board);
  check(must(moved.latest_seq(), "moved latest_seq") == 0,
        "moved board latest_seq != 0");
  auto replacement = must(PlatoonBoard::open(board_dir), "reopen board_dir");
  moved = std::move(replacement);
  check(must(moved.latest_seq(), "move-assigned latest_seq") == 0,
        "move-assigned board latest_seq != 0");
}

void test_roster_upsert_and_validation(const std::filesystem::path &base) {
  g_stage = "roster_upsert_and_validation";
  auto board = must(PlatoonBoard::open(base / "roster"), "open roster board");
  check(must(board.members(), "initial members").empty(), "initial roster not empty");
  check(!must(board.member("alpha"), "missing member").has_value(),
        "missing member returned value");

  const PlatoonMember alpha{
      "alpha-1",
      "implementer",
      "anthropic",
      "claude-sonnet",
      "/tmp/work-alpha",
      "platoon/alpha",
      PlatoonMemberState::starting,
      1001,
      0,
      "Implement slice 1.1",
  };
  const auto saved_alpha = must(board.upsert_member(alpha), "upsert alpha");
  check(saved_alpha.updated_ns > 0, "auto-populated updated_ns was not > 0");
  check(saved_alpha.id == alpha.id && saved_alpha.role == alpha.role &&
            saved_alpha.provider == alpha.provider &&
            saved_alpha.model == alpha.model &&
            saved_alpha.workspace == alpha.workspace &&
            saved_alpha.branch == alpha.branch &&
            saved_alpha.state == PlatoonMemberState::starting &&
            saved_alpha.pid == 1001 && saved_alpha.brief == alpha.brief,
        "saved alpha fields mismatch");

  const PlatoonMember beta{
      "beta_2",
      "reviewer",
      "openai",
      "gpt-5",
      "/tmp/work-beta",
      "platoon/beta",
      PlatoonMemberState::waiting,
      2002,
      123456789,
      "Adversarial review",
  };
  const auto saved_beta = must(board.upsert_member(beta), "upsert beta");
  check(saved_beta == beta, "explicit updated_ns was not preserved");

  // Update existing member in place across all states.
  for (const auto state : {PlatoonMemberState::starting, PlatoonMemberState::working,
                           PlatoonMemberState::waiting, PlatoonMemberState::completed,
                           PlatoonMemberState::failed, PlatoonMemberState::stopped}) {
    PlatoonMember updated = saved_alpha;
    updated.state = state;
    updated.pid = 3003;
    updated.updated_ns = 0;
    const auto stored = must(board.upsert_member(updated), "update alpha state");
    check(stored.state == state && stored.pid == 3003, "state update did not persist");
    const auto read_back = must(board.member("alpha-1"), "read back alpha");
    check(read_back.has_value() && *read_back == stored, "read back alpha mismatch");
  }

  const auto list = must(board.members(), "list members");
  check(list.size() == 2, "expected exactly 2 members after updates");
  check(list[0].id == "alpha-1" && list[1].id == "beta_2",
        "members not sorted deterministically by id");

  // Reject invalid IDs.
  const std::array<std::string, 10> bad_ids = {
      "",
      "all",
      "Upper",
      "has space",
      "bad/slash",
      "../escape",
      "dot.id",
      std::string(49, 'a'),
      std::string("nul\0byte", 8),
      "emoji-\xf0\x9f\x90\xa6",
  };
  for (const auto &bad_id : bad_ids) {
    PlatoonMember bad = beta;
    bad.id = bad_id;
    const auto res = board.upsert_member(bad);
    check(!res.has_value() && res.error().code == ErrorCode::invalid_identity,
          "invalid member id accepted on upsert");
    const auto lookup = board.member(bad_id);
    check(!lookup.has_value() && lookup.error().code == ErrorCode::invalid_identity,
          "invalid member id accepted on lookup");
  }

  // Max length 48 ID is valid.
  PlatoonMember max_id = beta;
  max_id.id = std::string(48, 'z');
  check(board.upsert_member(max_id).has_value(), "48-char id rejected");

  // Reject NUL byte in brief, negative pid, oversized brief.
  PlatoonMember bad_brief = beta;
  bad_brief.brief = std::string("hi\0there", 8);
  check(!board.upsert_member(bad_brief).has_value(), "NUL byte in brief accepted");

  PlatoonMember huge_brief = beta;
  huge_brief.brief.assign(kPlatoonMaxBriefBytes + 1, 'x');
  const auto huge_res = board.upsert_member(huge_brief);
  check(!huge_res.has_value() && huge_res.error().code == ErrorCode::capacity,
        "oversized brief accepted");

  PlatoonMember neg_pid = beta;
  neg_pid.pid = -1;
  check(!board.upsert_member(neg_pid).has_value(), "negative pid accepted");
}

void test_messages_filtering_and_pagination(const std::filesystem::path &base) {
  g_stage = "messages_filtering_and_pagination";
  auto board = must(PlatoonBoard::open(base / "messages"), "open message board");
  check(must(board.latest_seq(), "empty latest_seq") == 0,
        "empty board latest_seq != 0");
  check(must(board.read_since(0), "empty read_since").empty(),
        "empty board read_since not empty");

  // Exercise all 8 kinds, refs, multiline text, and unicode.
  const auto m1 = must(board.post({"coord",
                                   "all",
                                   PlatoonMessageKind::brief,
                                   "Start slice 1.1\nline two",
                                   {"include/blackbird/platoon_board.hpp"}}),
                       "post m1");
  check(m1.seq == 1 && m1.timestamp_ns > 0 && m1.refs.size() == 1,
        "m1 metadata mismatch");

  const auto m2 = must(board.post({"alpha",
                                   "beta",
                                   PlatoonMessageKind::handoff,
                                   "Ready for review",
                                   {"src/platoon_board.cpp"}}),
                       "post m2");
  const auto m3 = must(
      board.post(
          {"gamma", "coord", PlatoonMessageKind::blocker, "Need clarification", {}}),
      "post m3");
  const auto m4 = must(board.post({"beta",
                                   "alpha",
                                   PlatoonMessageKind::review,
                                   "Looks solid \xe2\x9c\x93",
                                   {}}),
                       "post m4");
  const auto m5 =
      must(board.post(
               {"coord", "all", PlatoonMessageKind::decision, "Proceed to merge", {}}),
           "post m5");
  const auto m6 = must(board.post({"alpha",
                                   "coord",
                                   PlatoonMessageKind::artifact,
                                   "Built target",
                                   {"build/debug/platoon_board_test"}}),
                       "post m6");
  const auto m7 = must(
      board.post({"gamma", "beta", PlatoonMessageKind::message, "Private note", {}}),
      "post m7");
  const auto m8 =
      must(board.post({"beta", "all", PlatoonMessageKind::status, "Standing by", {}}),
           "post m8");

  check(m2.seq == 2 && m3.seq == 3 && m4.seq == 4 && m5.seq == 5 && m6.seq == 6 &&
            m7.seq == 7 && m8.seq == 8,
        "non-monotonic sequence numbers");
  check(must(board.latest_seq(), "latest_seq 8") == 8, "latest_seq != 8");

  // Full unfiltered read and exact roundtrip check.
  const auto all_msgs = must(board.read_since(0, 64), "read all");
  check(all_msgs.size() == 8, "expected 8 messages");
  check(all_msgs[0] == m1 && all_msgs[1] == m2 && all_msgs[2] == m3 &&
            all_msgs[3] == m4 && all_msgs[4] == m5 && all_msgs[5] == m6 &&
            all_msgs[6] == m7 && all_msgs[7] == m8,
        "roundtrip message mismatch");

  // Recipient filtering for "alpha":
  // Matches to=="all" (1, 5, 8), to=="alpha" (4), from=="alpha" (2, 6).
  // Excludes (3: gamma->coord) and (7: gamma->beta).
  const auto alpha_msgs = must(board.read_since(0, 64, "alpha"), "read alpha");
  check(alpha_msgs.size() == 6, "alpha filter count mismatch");
  const std::array<std::uint64_t, 6> expected_alpha = {1, 2, 4, 5, 6, 8};
  for (std::size_t i = 0; i < expected_alpha.size(); ++i)
    check(alpha_msgs[i].seq == expected_alpha[i], "alpha filtered seq mismatch");

  // Pagination via after_seq and limit.
  const auto page1 = must(board.read_since(0, 2, "alpha"), "alpha page1");
  check(page1.size() == 2 && page1[0].seq == 1 && page1[1].seq == 2, "page1 mismatch");
  const auto page2 =
      must(board.read_since(page1.back().seq, 2, "alpha"), "alpha page2");
  check(page2.size() == 2 && page2[0].seq == 4 && page2[1].seq == 5, "page2 mismatch");
  const auto page3 =
      must(board.read_since(page2.back().seq, 2, "alpha"), "alpha page3");
  check(page3.size() == 2 && page3[0].seq == 6 && page3[1].seq == 8, "page3 mismatch");
  const auto page4 =
      must(board.read_since(page3.back().seq, 2, "alpha"), "alpha page4");
  check(page4.empty(), "page4 should be empty");
  check(must(board.read_since(0, 0), "limit 0").empty(), "limit 0 should return empty");

  // Validation rejections on post.
  const auto bad_from =
      board.post({"all", "alpha", PlatoonMessageKind::message, "bad", {}});
  check(!bad_from.has_value() && bad_from.error().code == ErrorCode::invalid_identity,
        "from='all' was accepted");

  const auto bad_to =
      board.post({"alpha", "../bad", PlatoonMessageKind::message, "bad", {}});
  check(!bad_to.has_value() && bad_to.error().code == ErrorCode::invalid_identity,
        "invalid recipient was accepted");

  const auto nul_text = board.post(
      {"alpha", "all", PlatoonMessageKind::message, std::string("a\0b", 3), {}});
  check(!nul_text.has_value() && nul_text.error().code == ErrorCode::invalid_range,
        "NUL byte in message text was accepted");

  const auto bad_utf8 =
      board.post({"alpha", "all", PlatoonMessageKind::message, "\xff\xfe", {}});
  check(!bad_utf8.has_value() && bad_utf8.error().code == ErrorCode::invalid_range,
        "invalid UTF-8 text was accepted");

  const auto max_ok = board.post({"alpha",
                                  "all",
                                  PlatoonMessageKind::message,
                                  std::string(kPlatoonMaxMessageBytes, 'k'),
                                  {}});
  check(max_ok.has_value() && max_ok.value().seq == 9, "exact 64 KiB text rejected");

  const auto over_max = board.post({"alpha",
                                    "all",
                                    PlatoonMessageKind::message,
                                    std::string(kPlatoonMaxMessageBytes + 1, 'k'),
                                    {}});
  check(!over_max.has_value() && over_max.error().code == ErrorCode::capacity,
        "64 KiB + 1 text accepted");

  const auto bad_filter = board.read_since(0, 10, "../evil");
  check(!bad_filter.has_value() &&
            bad_filter.error().code == ErrorCode::invalid_identity,
        "invalid recipient_filter accepted");

  const auto empty_ref =
      board.post({"alpha", "all", PlatoonMessageKind::artifact, "bad ref", {""}});
  check(!empty_ref.has_value() && empty_ref.error().code == ErrorCode::invalid_range,
        "empty ref accepted");

  std::vector<std::string> too_many_refs(kPlatoonMaxRefs + 1, "a.cpp");
  const auto refs_cap = board.post({"alpha", "all", PlatoonMessageKind::artifact,
                                    "too many refs", std::move(too_many_refs)});
  check(!refs_cap.has_value() && refs_cap.error().code == ErrorCode::capacity,
        "excessive refs count accepted");
}

void test_multithread_concurrent_appends(const std::filesystem::path &base) {
  g_stage = "multithread_concurrent_appends";
  const auto root = base / "concurrent-threads";
  // Pre-create root once, then let each thread open its own PlatoonBoard handle
  // (exercising independent open file descriptions + flock serialization).
  (void)must(PlatoonBoard::open(root), "open concurrent root");

  constexpr int kThreads = 4;
  constexpr int kPerThread = 25;
  std::atomic<int> failures{0};
  std::vector<std::thread> threads;
  threads.reserve(kThreads);

  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&, t] {
      auto handle = PlatoonBoard::open(root);
      if (!handle.has_value()) {
        std::cerr << "thread " << t
                  << " open failed: " << error_name(handle.error().code) << " ("
                  << handle.error().detail << ")\n";
        failures.fetch_add(1);
        return;
      }
      const std::string sender = "worker-" + std::to_string(t);
      const PlatoonMember self{
          sender,
          "worker",
          "anthropic",
          "claude",
          "/tmp/ws",
          "branch-" + std::to_string(t),
          PlatoonMemberState::working,
          static_cast<std::int64_t>(100 + t),
          0,
          "concurrent worker",
      };
      if (const auto up = handle.value().upsert_member(self); !up.has_value()) {
        std::cerr << "thread " << t << " upsert failed: " << error_name(up.error().code)
                  << " (" << up.error().detail << ")\n";
        failures.fetch_add(1);
        return;
      }
      for (int i = 0; i < kPerThread; ++i) {
        auto posted = handle.value().post({
            sender,
            "all",
            PlatoonMessageKind::message,
            "t=" + std::to_string(t) + " i=" + std::to_string(i),
            {},
        });
        if (!posted.has_value()) {
          std::cerr << "thread " << t << " post " << i
                    << " failed: " << error_name(posted.error().code) << " ("
                    << posted.error().detail << ")\n";
          failures.fetch_add(1);
          return;
        }
      }
    });
  }
  for (auto &th : threads)
    th.join();
  check(failures.load() == 0, "concurrent thread encountered error");

  auto verify = must(PlatoonBoard::open(root), "reopen concurrent root");
  check(must(verify.latest_seq(), "concurrent latest_seq") ==
            static_cast<std::uint64_t>(kThreads * kPerThread),
        "concurrent latest_seq != 100");
  const auto msgs = must(verify.read_since(0, 200), "read 100 concurrent msgs");
  check(msgs.size() == static_cast<std::size_t>(kThreads * kPerThread),
        "concurrent message count != 100");

  std::set<std::string> texts;
  for (std::size_t idx = 0; idx < msgs.size(); ++idx) {
    check(msgs[idx].seq == idx + 1, "concurrent seq gap or duplicate");
    check(texts.insert(msgs[idx].text).second, "duplicate payload text");
  }
  const auto roster = must(verify.members(), "concurrent roster read");
  check(roster.size() == static_cast<std::size_t>(kThreads),
        "concurrent roster lost a member");
}

void test_multiprocess_concurrent_appends(const std::filesystem::path &base) {
  g_stage = "multiprocess_concurrent_appends";
  const auto root = base / "concurrent-procs";
  (void)must(PlatoonBoard::open(root), "open proc root");

  constexpr int kChildren = 2;
  constexpr int kPerProc = 15;
  std::vector<pid_t> pids;
  pids.reserve(kChildren);

  for (int c = 0; c < kChildren; ++c) {
    const pid_t pid = ::fork();
    check(pid >= 0, "fork failed");
    if (pid == 0) {
      auto board = PlatoonBoard::open(root);
      if (!board.has_value())
        ::_exit(10);
      const std::string sender = "proc-" + std::to_string(c);
      for (int i = 0; i < kPerProc; ++i) {
        auto posted = board.value().post({
            sender,
            "all",
            PlatoonMessageKind::status,
            "p=" + std::to_string(c) + " i=" + std::to_string(i),
            {},
        });
        if (!posted.has_value())
          ::_exit(11);
      }
      ::_exit(0);
    }
    pids.push_back(pid);
  }

  for (const pid_t pid : pids) {
    int status = 0;
    check(::waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0,
          "child process failed");
  }

  auto verify = must(PlatoonBoard::open(root), "reopen proc root");
  const auto total = static_cast<std::size_t>(kChildren * kPerProc);
  check(must(verify.latest_seq(), "proc latest_seq") == total,
        "multiprocess latest_seq mismatch");
  const auto msgs = must(verify.read_since(0, 100), "read multiprocess msgs");
  check(msgs.size() == total, "multiprocess message count mismatch");
  for (std::size_t idx = 0; idx < msgs.size(); ++idx)
    check(msgs[idx].seq == idx + 1, "multiprocess seq not strictly 1..N");
}

void test_crash_resilience(const std::filesystem::path &base) {
  g_stage = "crash_resilience";
  const auto root = base / "crash";
  auto board = must(PlatoonBoard::open(root), "open crash board");

  const auto m1 =
      must(board.post({"alpha", "all", PlatoonMessageKind::message, "committed 1", {}}),
           "post committed 1");
  const auto m2 = must(
      board.post(
          {"beta", "alpha", PlatoonMessageKind::message, "committed 2", {"file.cpp"}}),
      "post committed 2");
  check(m1.seq == 1 && m2.seq == 2, "initial crash test seqs mismatch");

  // Simulate mid-write crash: append truncated JSON without trailing newline.
  const auto board_path = root / "board.jsonl";
  {
    const int fd = ::open(board_path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
    check(fd >= 0, "open board.jsonl for crash injection failed");
    const std::string_view partial =
        R"({"seq":3,"timestamp_ns":999,"from":"alpha","to":"all","text":"trunc)";
    const ssize_t wrote = ::write(fd, partial.data(), partial.size());
    (void)::close(fd);
    check(wrote == static_cast<ssize_t>(partial.size()), "crash partial write failed");
  }

  // Existing committed messages must still read cleanly and ignore trailing junk.
  check(must(board.latest_seq(), "latest_seq with partial") == 2,
        "latest_seq did not ignore partial trailing line");
  const auto before_recovery = must(board.read_since(0, 64), "read_since with partial");
  check(before_recovery.size() == 2 && before_recovery[0] == m1 &&
            before_recovery[1] == m2,
        "committed messages damaged by trailing partial line");

  // Subsequent post must recover cleanly on a fresh newline with seq == 3.
  const auto m3 = must(board.post({"gamma",
                                   "all",
                                   PlatoonMessageKind::decision,
                                   "recovered cleanly",
                                   {"recovery.md"}}),
                       "post recovery m3");
  check(m3.seq == 3, "recovered message did not receive seq 3");
  check(must(board.latest_seq(), "latest_seq after recovery") == 3,
        "latest_seq after recovery != 3");

  const auto after_recovery =
      must(board.read_since(0, 64), "read_since after recovery");
  check(after_recovery.size() == 3 && after_recovery[0] == m1 &&
            after_recovery[1] == m2 && after_recovery[2] == m3,
        "read_since after recovery mismatch");

  // Verify subsequent post after recovery also works seamlessly.
  const auto m4 =
      must(board.post({"alpha", "gamma", PlatoonMessageKind::status, "post 4", {}}),
           "post m4");
  check(m4.seq == 4, "post after recovery did not receive seq 4");
  const auto tail = must(board.read_since(2, 64), "read_since(2) after recovery");
  check(tail.size() == 2 && tail[0] == m3 && tail[1] == m4,
        "paginated read after recovery mismatch");

  // Also test worst-case crash: complete JSON object missing only its trailing '\n'.
  {
    const int fd = ::open(board_path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
    check(fd >= 0, "open board.jsonl for missing-nl crash failed");
    const std::string_view missing_nl =
        R"({"seq":5,"timestamp_ns":1000,"from":"alpha","to":"all","kind":"message","text":"uncommitted"})";
    const ssize_t wrote = ::write(fd, missing_nl.data(), missing_nl.size());
    (void)::close(fd);
    check(wrote == static_cast<ssize_t>(missing_nl.size()), "missing-nl write failed");
  }
  check(must(board.latest_seq(), "latest_seq before missing-nl recovery") == 4,
        "unterminated complete JSON was treated as committed");
  const auto m5 =
      must(board.post({"beta", "all", PlatoonMessageKind::decision, "committed 5", {}}),
           "post m5 after missing-nl crash");
  check(m5.seq == 5 && m5.text == "committed 5",
        "recovery after missing-nl crash assigned wrong seq");
  const auto final_msgs =
      must(board.read_since(0, 64), "read_since after missing-nl recovery");
  check(final_msgs.size() == 5 && final_msgs[4] == m5,
        "uncommitted missing-nl line resurrected or displaced m5");
}

void test_multiprocess_fresh_board_first_post_race(const std::filesystem::path &base) {
  g_stage = "multiprocess_fresh_board_first_post_race";
  // Exercise M1: multiple processes racing to open and post to a brand-new,
  // non-existent board root (creating board.jsonl concurrently for the first time).
  for (int round = 0; round < 4; ++round) {
    const auto root = base / ("fresh-race-" + std::to_string(round));
    constexpr int kChildren = 4;
    constexpr int kPerProc = 5;
    std::vector<pid_t> pids;
    pids.reserve(kChildren);

    for (int c = 0; c < kChildren; ++c) {
      const pid_t pid = ::fork();
      check(pid >= 0, "fork failed in fresh-board race");
      if (pid == 0) {
        auto board = PlatoonBoard::open(root);
        if (!board.has_value())
          ::_exit(20);
        const std::string sender = "racer-" + std::to_string(c);
        for (int i = 0; i < kPerProc; ++i) {
          auto posted = board.value().post({
              sender,
              "all",
              PlatoonMessageKind::message,
              "round=" + std::to_string(round) + " c=" + std::to_string(c) +
                  " i=" + std::to_string(i),
              {},
          });
          if (!posted.has_value())
            ::_exit(21);
        }
        ::_exit(0);
      }
      pids.push_back(pid);
    }

    for (const pid_t pid : pids) {
      int status = 0;
      check(::waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
                WEXITSTATUS(status) == 0,
            "fresh-board race child failed (possible EEXIST race)");
    }

    auto verify = must(PlatoonBoard::open(root), "reopen fresh-race root");
    const auto expected = static_cast<std::size_t>(kChildren * kPerProc);
    check(must(verify.latest_seq(), "fresh-race latest_seq") == expected,
          "fresh-race latest_seq mismatch");
    const auto msgs = must(verify.read_since(0, 100), "read fresh-race msgs");
    check(msgs.size() == expected, "fresh-race message count mismatch");
    for (std::size_t idx = 0; idx < msgs.size(); ++idx)
      check(msgs[idx].seq == idx + 1, "fresh-race seq not strictly 1..N");
  }
}

void test_roster_cap_and_corrupt_recovery(const std::filesystem::path &base) {
  g_stage = "roster_cap_and_corrupt_recovery";
  // M2: enforce bounded roster member count (kPlatoonMaxRosterMembers = 512).
  {
    const auto root = base / "roster-cap";
    auto board = must(PlatoonBoard::open(root), "open roster-cap board");
    for (std::size_t i = 0; i < kPlatoonMaxRosterMembers; ++i) {
      const PlatoonMember m{
          "m-" + std::to_string(i),
          "worker",
          "openai",
          "gpt-5",
          "/tmp/ws",
          "main",
          PlatoonMemberState::working,
          static_cast<std::int64_t>(i + 1),
          1000,
          "",
      };
      (void)must(board.upsert_member(m), "upsert within roster cap");
    }
    check(must(board.members(), "members at cap").size() == kPlatoonMaxRosterMembers,
          "roster size at cap mismatch");

    // Updating an existing member at cap must still succeed.
    const PlatoonMember update_existing{
        "m-0",
        "worker",
        "openai",
        "gpt-5",
        "/tmp/ws",
        "main",
        PlatoonMemberState::completed,
        1,
        2000,
        "done",
    };
    check(board.upsert_member(update_existing).has_value(),
          "updating existing member at cap was rejected");

    // Adding a 513th distinct member must fail with capacity.
    const PlatoonMember over_cap{
        "m-overflow",
        "worker",
        "openai",
        "gpt-5",
        "/tmp/ws",
        "main",
        PlatoonMemberState::starting,
        999,
        3000,
        "",
    };
    const auto overflow_res = board.upsert_member(over_cap);
    check(!overflow_res.has_value() && overflow_res.error().code == ErrorCode::capacity,
          "513th member did not fail with capacity");
  }

  // M3: corrupt/truncated roster.json is quarantined and rebuilt on upsert_member.
  {
    const auto root = base / "roster-corrupt";
    auto board = must(PlatoonBoard::open(root), "open roster-corrupt board");
    const auto roster_path = root / "roster.json";
    {
      const int fd =
          ::open(roster_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
      check(fd >= 0, "failed to create corrupt roster.json");
      const std::string_view garbage = R"({"version":1,"members":[{"id":"broken")";
      const ssize_t n = ::write(fd, garbage.data(), garbage.size());
      (void)::close(fd);
      check(n == static_cast<ssize_t>(garbage.size()),
            "failed to write corrupt roster");
    }

    const auto bad_read = board.members();
    check(!bad_read.has_value() && bad_read.error().code == ErrorCode::corrupt,
          "corrupt roster.json did not fail members() with corrupt");

    const PlatoonMember survivor{
        "rebuilt-1",
        "coord",
        "anthropic",
        "claude",
        "/tmp/ws",
        "main",
        PlatoonMemberState::working,
        42,
        1234,
        "recovered",
    };
    (void)must(board.upsert_member(survivor),
               "upsert_member must recover corrupt roster");

    const auto recovered = must(board.members(), "members after corrupt recovery");
    check(recovered.size() == 1 && recovered[0] == survivor,
          "rebuilt roster contents mismatch");

    bool found_quarantine = false;
    for (const auto &entry : std::filesystem::directory_iterator(root)) {
      if (entry.path().filename().string().starts_with("roster.corrupt."))
        found_quarantine = true;
    }
    check(found_quarantine, "corrupt roster was not quarantined to roster.corrupt.*");
  }

  // M3: oversized (>16 MiB) roster.json is also quarantined and rebuilt cleanly.
  {
    const auto root = base / "roster-oversized";
    auto board = must(PlatoonBoard::open(root), "open roster-oversized board");
    const auto roster_path = root / "roster.json";
    {
      const int fd =
          ::open(roster_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
      check(fd >= 0, "failed to create oversized roster.json");
      const std::string chunk(64 * 1024, ' ');
      constexpr std::size_t kTotalChunks = (17U * 1024U * 1024U) / (64U * 1024U);
      for (std::size_t i = 0; i < kTotalChunks; ++i) {
        const ssize_t n = ::write(fd, chunk.data(), chunk.size());
        check(n == static_cast<ssize_t>(chunk.size()),
              "failed writing oversized roster");
      }
      (void)::close(fd);
    }

    const auto bad_read = board.members();
    check(!bad_read.has_value() && bad_read.error().code == ErrorCode::capacity,
          "17 MiB roster.json did not fail members() with capacity");

    const PlatoonMember survivor{
        "rebuilt-big",
        "coord",
        "openai",
        "gpt-5",
        "/tmp/ws",
        "main",
        PlatoonMemberState::working,
        77,
        5678,
        "recovered from oversized",
    };
    (void)must(board.upsert_member(survivor),
               "upsert_member must recover oversized roster");
    const auto recovered = must(board.members(), "members after oversized recovery");
    check(recovered.size() == 1 && recovered[0] == survivor,
          "rebuilt roster after oversized quarantine mismatch");

    bool found_quarantine = false;
    for (const auto &entry : std::filesystem::directory_iterator(root)) {
      if (entry.path().filename().string().starts_with("roster.corrupt."))
        found_quarantine = true;
    }
    check(found_quarantine, "oversized roster was not quarantined to roster.corrupt.*");
  }
}

void test_board_overflow_line_recovery(const std::filesystem::path &base) {
  g_stage = "board_overflow_line_recovery";
  const auto root = base / "overflow-line";
  auto board = must(PlatoonBoard::open(root), "open overflow-line board");

  const auto m1 = must(
      board.post({"alpha", "all", PlatoonMessageKind::message, "before giant", {}}),
      "post m1 before giant");
  check(m1.seq == 1, "m1 seq != 1");

  // Append a 2 MiB single line ending in '\n' directly to board.jsonl.
  const auto board_path = root / "board.jsonl";
  {
    const int fd = ::open(board_path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
    check(fd >= 0, "open board.jsonl for 2 MiB injection failed");
    const std::string chunk(64 * 1024, 'x');
    for (int i = 0; i < 32; ++i) {
      const ssize_t n = ::write(fd, chunk.data(), chunk.size());
      check(n == static_cast<ssize_t>(chunk.size()), "failed writing 2 MiB line chunk");
    }
    const char nl = '\n';
    check(::write(fd, &nl, 1) == 1, "failed writing trailing newline for 2 MiB line");
    (void)::close(fd);
  }

  check(must(board.latest_seq(), "latest_seq with 2 MiB line") == 1,
        "2 MiB line corrupted latest_seq");

  const auto m2 =
      must(board.post({"beta", "all", PlatoonMessageKind::decision, "after giant", {}}),
           "post m2 after giant");
  check(m2.seq == 2, "post after 2 MiB line did not receive seq == 2");

  const auto msgs = must(board.read_since(0, 64), "read_since skipping 2 MiB line");
  check(msgs.size() == 2 && msgs[0] == m1 && msgs[1] == m2,
        "read_since did not cleanly skip 2 MiB overflow line");
}

} // namespace

int main() {
  char pattern[] = "/tmp/blackbird-platoon-board-XXXXXX";
  const char *raw_dir = ::mkdtemp(pattern);
  if (!raw_dir)
    return 2;
  const std::filesystem::path base{raw_dir};
  try {
    test_directory_and_security(base);
    test_roster_upsert_and_validation(base);
    test_messages_filtering_and_pagination(base);
    test_multithread_concurrent_appends(base);
    test_multiprocess_concurrent_appends(base);
    test_crash_resilience(base);
    test_multiprocess_fresh_board_first_post_race(base);
    test_roster_cap_and_corrupt_recovery(base);
    test_board_overflow_line_recovery(base);
    std::filesystem::remove_all(base);
    std::cout << "platoon_board: directory security, roster upsert/validation/cap, "
                 "corrupt/oversized roster recovery, message filtering/pagination, "
                 "multithread/multiprocess concurrency, fresh-board race, "
                 "2 MiB overflow-line skip, and crash recovery passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << g_stage << ": " << error.what() << '\n';
    std::filesystem::remove_all(base);
    return 1;
  }
}
