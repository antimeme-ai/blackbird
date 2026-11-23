#include "blackbird/issues.hpp"
#include "blackbird/json.hpp"

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

void test_directory_security_and_handle(const std::filesystem::path &base) {
  g_stage = "directory_security_and_handle";
  const auto root = base / "nested" / "issues";
  auto store = must(IssueStore::open(root), "open nested root");
  check(store.root() == root, "store root mismatch");

  struct stat st{};
  check(::lstat(root.c_str(), &st) == 0, "lstat issues dir failed");
  check(S_ISDIR(st.st_mode), "issues root is not a directory");
  check((st.st_mode & 0777) == 0700, "newly created root permissions are not 0700");

  // Git-friendly existing 0755 directory owned by current user is accepted.
  const auto git_dir = base / "git-tracked-issues";
  check(::mkdir(git_dir.c_str(), mode_t{0755}) == 0, "mkdir 0755 failed");
  check(::chmod(git_dir.c_str(), mode_t{0755}) == 0, "chmod 0755 failed");
  auto git_store = must(IssueStore::open(git_dir), "open 0755 git-friendly dir");
  check(must(git_store.list(), "empty list on 0755 dir").empty(),
        "expected empty list on fresh 0755 dir");

  // Reject world-writable directory.
  const auto writable_dir = base / "world-writable";
  check(::mkdir(writable_dir.c_str(), mode_t{0777}) == 0, "mkdir 0777 failed");
  check(::chmod(writable_dir.c_str(), mode_t{0777}) == 0, "chmod 0777 failed");
  const auto writable_open = IssueStore::open(writable_dir);
  check(!writable_open.has_value() && writable_open.error().code == ErrorCode::io,
        "world-writable dir was accepted");

  // Reject symlink as root.
  const auto link_dir = base / "symlink-root";
  check(::symlink(root.c_str(), link_dir.c_str()) == 0, "symlink creation failed");
  const auto link_open = IssueStore::open(link_dir);
  check(!link_open.has_value(), "symlink root was accepted");

  // Reject empty path.
  const auto empty_open = IssueStore::open(std::filesystem::path{});
  check(!empty_open.has_value() && empty_open.error().code == ErrorCode::invalid_range,
        "empty root path was accepted");

  // Move semantics and stale-handle rejection.
  IssueStore moved = std::move(store);
  check(must(moved.list(), "moved store list").empty(), "moved store list not empty");
  auto replacement = must(IssueStore::open(root), "reopen root");
  moved = std::move(replacement);
  check(must(moved.ready(), "move-assigned ready").empty(),
        "move-assigned ready not empty");
}

void test_crud_query_ready_and_json(const std::filesystem::path &base) {
  g_stage = "crud_query_ready_and_json";
  auto store = must(IssueStore::open(base / "crud"), "open crud store");

  const auto i1 = must(store.create({
                           "Implement parser",
                           "Parse JSONL event log\nwith recovery",
                           IssueKind::task,
                           2,
                           std::nullopt,
                           {"rock-6", "core", "core"},
                           {},
                       }),
                       "create bb-1");
  check(i1.id == "bb-1" && i1.status == IssueStatus::open && i1.priority == 2 &&
            i1.revision == 1 && i1.created_ns > 0 && i1.updated_ns == i1.created_ns &&
            i1.labels.size() == 2 && i1.labels[0] == "core" && i1.labels[1] == "rock-6",
        "bb-1 fields mismatch");

  const auto i2 = must(store.create({
                           "Urgent crash fix",
                           "Fix null dereference",
                           IssueKind::bug,
                           0,
                           std::nullopt,
                           {"rock-6", "p0"},
                           {},
                       }),
                       "create bb-2");
  check(i2.id == "bb-2" && i2.priority == 0 && i2.kind == IssueKind::bug,
        "bb-2 fields mismatch");

  // bb-3 depends on bb-1; bb-4 has same priority as bb-1 (P2) and no blockers.
  const auto i3 = must(store.create({
                           "Wire CLI commands",
                           "Expose issue tracker CLI",
                           IssueKind::epic,
                           0,
                           std::nullopt,
                           {"cli"},
                           {"bb-1"},
                       }),
                       "create bb-3");
  check(i3.id == "bb-3" && i3.depends_on.size() == 1 && i3.depends_on[0] == "bb-1",
        "bb-3 depends_on mismatch");

  const auto i4 = must(store.create({
                           "Investigate compaction",
                           "Benchmark replay cost",
                           IssueKind::research,
                           2,
                           "researcher-1",
                           {"perf"},
                           {},
                       }),
                       "create bb-4");
  check(i4.id == "bb-4" && i4.assignee.has_value() && *i4.assignee == "researcher-1",
        "bb-4 fields mismatch");

  const auto i5 = must(store.create({
                           "Reduce latency friction",
                           "",
                           IssueKind::friction,
                           1,
                           std::nullopt,
                           {"perf"},
                           {},
                       }),
                       "create bb-5");
  check(i5.id == "bb-5" && i5.kind == IssueKind::friction && i5.priority == 1,
        "bb-5 fields mismatch");

  // get() roundtrip matches exactly.
  check(must(store.get("bb-1"), "get bb-1") == i1, "get bb-1 mismatch");
  check(must(store.get("bb-3"), "get bb-3") == i3, "get bb-3 mismatch");

  // ready() excludes bb-3 (blocked by open bb-1) and orders by (priority asc, id asc):
  // bb-2 (P0), bb-5 (P1), bb-1 (P2), bb-4 (P2).
  const auto ready1 = must(store.ready(), "initial ready");
  check(ready1.size() == 4, "expected 4 ready issues");
  check(ready1[0].id == "bb-2" && ready1[1].id == "bb-5" && ready1[2].id == "bb-1" &&
            ready1[3].id == "bb-4",
        "ready ordering mismatch (priority asc, numeric id asc)");
  check(must(store.ready(2), "ready limit 2").size() == 2, "ready limit 2 failed");
  check(must(store.ready(0), "ready limit 0").empty(), "ready limit 0 not empty");

  // Claim bb-1 -> moves to in_progress (leaves ready()).
  const auto claimed1 = must(store.claim("bb-1", "worker-1", 1), "claim bb-1");
  check(claimed1.status == IssueStatus::in_progress && claimed1.assignee.has_value() &&
            *claimed1.assignee == "worker-1" && claimed1.revision == 2,
        "claimed bb-1 state mismatch");

  // Add comment on bb-1.
  const auto commented1 =
      must(store.add_comment("bb-1", "worker-1", "Parser implemented and tested"),
           "comment bb-1");
  check(commented1.revision == 3 && commented1.comments.size() == 1 &&
            commented1.comments[0].author == "worker-1" &&
            commented1.comments[0].text == "Parser implemented and tested" &&
            commented1.comments[0].timestamp_ns > 0,
        "comment bb-1 mismatch");

  // bb-3 is STILL hidden from ready() while bb-1 is in_progress.
  const auto ready_while_in_progress = must(store.ready(), "ready while bb-1 active");
  for (const auto &rec : ready_while_in_progress)
    check(rec.id != "bb-1" && rec.id != "bb-3",
          "in-progress bb-1 or blocked bb-3 appeared in ready()");

  // Close bb-1 -> bb-3 (P0) immediately appears in ready() after bb-2 (P0)!
  const auto closed1 = must(store.close("bb-1", "merged to main", 3), "close bb-1");
  check(closed1.status == IssueStatus::closed &&
            closed1.close_reason == "merged to main" && closed1.revision == 4,
        "closed bb-1 mismatch");

  const auto ready_after_close = must(store.ready(), "ready after bb-1 closed");
  check(ready_after_close.size() == 4, "expected 4 ready issues after bb-1 closed");
  check(ready_after_close[0].id == "bb-2" && ready_after_close[1].id == "bb-3" &&
            ready_after_close[2].id == "bb-5" && ready_after_close[3].id == "bb-4",
        "bb-3 did not immediately surface in priority order after blocker closed");

  // Update bb-4 fields and verify persistence across reopen.
  IssueUpdateRequest upd;
  upd.id = "bb-4";
  upd.expected_revision = 1;
  upd.title = "Investigate JSONL compaction";
  upd.status = IssueStatus::blocked;
  upd.priority = 1;
  upd.clear_assignee = true;
  upd.labels = std::vector<std::string>{"perf", "storage"};
  const auto updated4 = must(store.update(std::move(upd)), "update bb-4");
  check(updated4.revision == 2 && updated4.title == "Investigate JSONL compaction" &&
            updated4.status == IssueStatus::blocked && updated4.priority == 1 &&
            !updated4.assignee.has_value() && updated4.labels.size() == 2,
        "updated bb-4 mismatch");

  // list() filters: status, kind, assignee, label, offset/limit.
  IssueQuery q_closed;
  q_closed.status = IssueStatus::closed;
  const auto closed_list = must(store.list(q_closed), "list closed");
  check(closed_list.size() == 1 && closed_list[0].id == "bb-1", "list closed mismatch");

  IssueQuery q_kind;
  q_kind.kind = IssueKind::bug;
  const auto bug_list = must(store.list(q_kind), "list bugs");
  check(bug_list.size() == 1 && bug_list[0].id == "bb-2", "list bugs mismatch");

  IssueQuery q_assignee;
  q_assignee.assignee = "worker-1";
  const auto worker_list = must(store.list(q_assignee), "list worker-1");
  check(worker_list.size() == 1 && worker_list[0].id == "bb-1",
        "list assignee mismatch");

  IssueQuery q_label;
  q_label.label = "perf";
  const auto perf_list = must(store.list(q_label), "list perf label");
  check(perf_list.size() == 2 && perf_list[0].id == "bb-4" && perf_list[1].id == "bb-5",
        "list label mismatch");

  IssueQuery q_page;
  q_page.offset = 1;
  q_page.limit = 2;
  const auto page = must(store.list(q_page), "list page");
  check(page.size() == 2 && page[0].id == "bb-2" && page[1].id == "bb-3",
        "list offset/limit mismatch");

  // Verify to_json produces valid serializable Value with exact fields.
  const Value json_val = to_json(closed1);
  const auto dumped = must(dump_json(json_val), "dump_json IssueRecord");
  const auto reparsed = must(parse_json(dumped), "reparse IssueRecord json");
  check(reparsed == json_val, "to_json roundtrip mismatch");
  check(json_val.find("id") != nullptr && json_val.find("id")->string() == "bb-1",
        "to_json id mismatch");
  check(json_val.find("status") != nullptr &&
            json_val.find("status")->string() == "closed",
        "to_json status mismatch");
  check(json_val.find("close_reason") != nullptr &&
            json_val.find("close_reason")->string() == "merged to main",
        "to_json close_reason mismatch");
  check(json_val.find("comments") != nullptr &&
            json_val.find("comments")->array().size() == 1,
        "to_json comments mismatch");

  // Reopen store from disk and confirm full durability.
  auto reopened = must(IssueStore::open(base / "crud"), "reopen crud store");
  check(must(reopened.get("bb-1"), "reopened get bb-1") == closed1,
        "reopened bb-1 mismatch");
  check(must(reopened.get("bb-4"), "reopened get bb-4") == updated4,
        "reopened bb-4 mismatch");
}

void test_dependency_cycles_and_validation(const std::filesystem::path &base) {
  g_stage = "dependency_cycles_and_validation";
  auto store = must(IssueStore::open(base / "cycles"), "open cycles store");

  const auto a =
      must(store.create({"Issue A", "", IssueKind::task, 2, {}, {}, {}}), "A");
  const auto b =
      must(store.create({"Issue B", "", IssueKind::task, 2, {}, {}, {}}), "B");
  const auto c =
      must(store.create({"Issue C", "", IssueKind::task, 2, {}, {}, {}}), "C");

  // Direct self-dependency A -> A rejected.
  const auto self_dep = store.add_dependency(a.id, a.id);
  check(!self_dep.has_value() && self_dep.error().code == ErrorCode::conflict,
        "direct self-dependency A->A was accepted");

  // Valid A -> B.
  const auto ab = must(store.add_dependency(a.id, b.id), "A -> B");
  check(ab.depends_on.size() == 1 && ab.depends_on[0] == b.id && ab.revision == 2,
        "A -> B dependency not recorded");

  // Duplicate edge A -> B is idempotent.
  const auto ab_dup = must(store.add_dependency(a.id, b.id), "dup A -> B");
  check(ab_dup.depends_on.size() == 1 && ab_dup.revision == 2,
        "duplicate dependency mutated revision");

  // 2-node cycle B -> A rejected.
  const auto cycle2 = store.add_dependency(b.id, a.id);
  check(!cycle2.has_value() && cycle2.error().code == ErrorCode::conflict,
        "2-node cycle A->B->A was accepted");

  // Valid B -> C.
  (void)must(store.add_dependency(b.id, c.id), "B -> C");

  // 3-node cycle C -> A rejected.
  const auto cycle3 = store.add_dependency(c.id, a.id);
  check(!cycle3.has_value() && cycle3.error().code == ErrorCode::conflict,
        "3-node cycle A->B->C->A was accepted");

  // Missing target dependency rejected on create and add_dependency.
  const auto missing_create =
      store.create({"Bad dep", "", IssueKind::task, 2, {}, {}, {"bb-999"}});
  check(!missing_create.has_value() &&
            missing_create.error().code == ErrorCode::stale_handle,
        "create with missing depends_on target was accepted");

  const auto missing_add = store.add_dependency(a.id, "bb-999");
  check(!missing_add.has_value() && missing_add.error().code == ErrorCode::stale_handle,
        "add_dependency with missing blocker was accepted");

  // Input validation rejections.
  check(store.create({"", "", IssueKind::task, 2, {}, {}, {}}).error().code ==
            ErrorCode::invalid_range,
        "empty title accepted");
  check(store.create({std::string(kIssueMaxTitleBytes + 1, 'a'),
                      "",
                      IssueKind::task,
                      2,
                      {},
                      {},
                      {}})
                .error()
                .code == ErrorCode::capacity,
        "oversized title accepted");
  check(
      store.create({"line1\nline2", "", IssueKind::task, 2, {}, {}, {}}).error().code ==
          ErrorCode::invalid_range,
      "control char in title accepted");
  check(store.create({"ok", "\xff\xfe", IssueKind::task, 2, {}, {}, {}}).error().code ==
            ErrorCode::invalid_range,
        "invalid UTF-8 body accepted");
  check(store.create({"ok",
                      std::string(kIssueMaxBodyBytes + 1, 'x'),
                      IssueKind::task,
                      2,
                      {},
                      {},
                      {}})
                .error()
                .code == ErrorCode::capacity,
        "oversized body accepted");
  check(store.create({"ok", "", IssueKind::task, 4, {}, {}, {}}).error().code ==
            ErrorCode::invalid_range,
        "priority 4 accepted");
  check(
      store.create({"ok", "", IssueKind::task, 2, "Bad Actor", {}, {}}).error().code ==
          ErrorCode::invalid_identity,
      "invalid actor accepted");
  check(store.get("bb-0").error().code == ErrorCode::invalid_identity,
        "bb-0 accepted as valid id");
  check(store.get("bb-01").error().code == ErrorCode::invalid_identity,
        "bb-01 accepted as valid id");
  check(store.get("not-an-id").error().code == ErrorCode::invalid_identity,
        "malformed id accepted");
  check(store.add_comment(a.id, "worker-1", "").error().code ==
            ErrorCode::invalid_range,
        "empty comment accepted");
}

void test_cas_and_claim_conflicts(const std::filesystem::path &base) {
  g_stage = "cas_and_claim_conflicts";
  auto store = must(IssueStore::open(base / "cas"), "open cas store");

  const auto item =
      must(store.create({"Race target", "body", IssueKind::task, 1, {}, {}, {}}),
           "create race target");
  check(item.revision == 1, "initial revision != 1");

  // Stale expected_revision on update fails with conflict.
  IssueUpdateRequest stale_upd;
  stale_upd.id = item.id;
  stale_upd.expected_revision = 99;
  stale_upd.title = "Should fail";
  const auto stale_res = store.update(std::move(stale_upd));
  check(!stale_res.has_value() && stale_res.error().code == ErrorCode::conflict,
        "stale expected_revision on update was accepted");

  // First claim succeeds.
  const auto claimed = must(store.claim(item.id, "alice", 1), "alice claim");
  check(claimed.revision == 2 && claimed.assignee == "alice" &&
            claimed.status == IssueStatus::in_progress,
        "alice claim state mismatch");

  // Double-claim by another actor fails with conflict (even without expected_revision).
  const auto double_claim = store.claim(item.id, "bob");
  check(!double_claim.has_value() && double_claim.error().code == ErrorCode::conflict,
        "double-claim by bob was accepted");

  // Stale expected_revision on claim by same actor fails with conflict.
  const auto stale_claim = store.claim(item.id, "alice", 1);
  check(!stale_claim.has_value() && stale_claim.error().code == ErrorCode::conflict,
        "stale expected_revision on claim was accepted");

  // Stale expected_revision on close fails with conflict.
  const auto stale_close = store.close(item.id, "done", 1);
  check(!stale_close.has_value() && stale_close.error().code == ErrorCode::conflict,
        "stale expected_revision on close was accepted");

  // Close succeeds with matching revision.
  const auto closed = must(store.close(item.id, "completed", 2), "close with rev 2");
  check(closed.revision == 3 && closed.status == IssueStatus::closed, "close failed");

  // Claim on closed issue fails with conflict.
  const auto claim_closed = store.claim(item.id, "alice");
  check(!claim_closed.has_value() && claim_closed.error().code == ErrorCode::conflict,
        "claim on closed issue was accepted");

  // Second close fails with conflict.
  const auto close_again = store.close(item.id, "again");
  check(!close_again.has_value() && close_again.error().code == ErrorCode::conflict,
        "double close was accepted");
}

void test_multithread_concurrency(const std::filesystem::path &base) {
  g_stage = "multithread_concurrency";
  const auto root = base / "concurrent";
  auto initial = must(IssueStore::open(root), "open concurrent root");
  const auto contested =
      must(initial.create({"Contested issue", "", IssueKind::task, 0, {}, {}, {}}),
           "create contested bb-1");
  check(contested.id == "bb-1", "contested id != bb-1");

  // Part A: 4 threads racing to claim bb-1 -> exactly 1 winner, 3 conflicts.
  constexpr int kClaimers = 4;
  std::atomic<int> winners{0};
  std::atomic<int> conflicts{0};
  std::atomic<int> unexpected{0};
  std::atomic<bool> go{false};
  std::vector<std::thread> claim_threads;
  claim_threads.reserve(kClaimers);

  for (int t = 0; t < kClaimers; ++t) {
    claim_threads.emplace_back([&, t] {
      auto handle = IssueStore::open(root);
      if (!handle.has_value()) {
        unexpected.fetch_add(1);
        return;
      }
      while (!go.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      const std::string actor = "claimer-" + std::to_string(t);
      const auto res = handle.value().claim("bb-1", actor);
      if (res.has_value())
        winners.fetch_add(1);
      else if (res.error().code == ErrorCode::conflict)
        conflicts.fetch_add(1);
      else
        unexpected.fetch_add(1);
    });
  }
  go.store(true, std::memory_order_release);
  for (auto &th : claim_threads)
    th.join();

  check(unexpected.load() == 0, "unexpected error during concurrent claims");
  check(winners.load() == 1 && conflicts.load() == 3,
        "concurrent claim race did not yield 1 winner and 3 conflicts");

  // Part B: 4 threads x 20 creates = 80 unique monotonic IDs (bb-2 .. bb-81).
  constexpr int kCreators = 4;
  constexpr int kPerThread = 20;
  std::atomic<int> create_failures{0};
  std::vector<std::vector<std::string>> created_ids(kCreators);
  std::vector<std::thread> create_threads;
  create_threads.reserve(kCreators);

  for (int t = 0; t < kCreators; ++t) {
    create_threads.emplace_back([&, t] {
      auto handle = IssueStore::open(root);
      if (!handle.has_value()) {
        create_failures.fetch_add(1);
        return;
      }
      created_ids[static_cast<std::size_t>(t)].reserve(kPerThread);
      for (int i = 0; i < kPerThread; ++i) {
        auto res = handle.value().create({
            "t=" + std::to_string(t) + " i=" + std::to_string(i),
            "concurrent body",
            IssueKind::task,
            static_cast<std::uint8_t>(i % 4),
            std::nullopt,
            {"t-" + std::to_string(t)},
            {},
        });
        if (!res.has_value()) {
          create_failures.fetch_add(1);
          return;
        }
        created_ids[static_cast<std::size_t>(t)].push_back(res.value().id);
      }
    });
  }
  for (auto &th : create_threads)
    th.join();
  check(create_failures.load() == 0, "concurrent create encountered error");

  std::set<std::uint64_t> nums;
  for (const auto &batch : created_ids) {
    check(batch.size() == kPerThread, "thread created fewer than 20 issues");
    for (const auto &id : batch) {
      const auto n = must(parse_issue_number(id), "parse created id");
      check(nums.insert(n).second, "duplicate issue id assigned across threads");
    }
  }
  check(nums.size() == static_cast<std::size_t>(kCreators * kPerThread),
        "expected 80 unique created ids");
  check(*nums.begin() == 2 && *nums.rbegin() == 81,
        "concurrent ids are not contiguous bb-2..bb-81");

  auto verify = must(IssueStore::open(root), "reopen concurrent store");
  const auto all = must(verify.list(), "list all concurrent issues");
  check(all.size() == 81, "expected 81 total issues after concurrent creates");
  for (std::size_t i = 0; i < all.size(); ++i)
    check(all[i].id == "bb-" + std::to_string(i + 1),
          "concurrent list not monotonic bb-1..bb-81");
}

void test_multiprocess_concurrency(const std::filesystem::path &base) {
  g_stage = "multiprocess_concurrency";
  const auto root = base / "concurrent-procs";
  auto store = must(IssueStore::open(root), "open proc store");
  (void)must(store.create({"Proc race target", "", IssueKind::task, 0, {}, {}, {}}),
             "create proc race target");

  constexpr int kChildren = 2;
  constexpr int kPerProc = 15;
  std::vector<pid_t> pids;
  pids.reserve(kChildren);

  for (int c = 0; c < kChildren; ++c) {
    const pid_t pid = ::fork();
    check(pid >= 0, "fork failed");
    if (pid == 0) {
      auto handle = IssueStore::open(root);
      if (!handle.has_value())
        ::_exit(10);
      const std::string actor = "proc-" + std::to_string(c);
      const auto claim_res = handle.value().claim("bb-1", actor);
      if (!claim_res.has_value() && claim_res.error().code != ErrorCode::conflict)
        ::_exit(11);
      for (int i = 0; i < kPerProc; ++i) {
        auto created = handle.value().create({
            "p=" + std::to_string(c) + " i=" + std::to_string(i),
            "",
            IssueKind::task,
            2,
            std::nullopt,
            {},
            {},
        });
        if (!created.has_value())
          ::_exit(12);
      }
      ::_exit(claim_res.has_value() ? 0 : 2);
    }
    pids.push_back(pid);
  }

  int claim_winners = 0;
  int claim_conflicts = 0;
  for (const pid_t pid : pids) {
    int status = 0;
    check(::waitpid(pid, &status, 0) == pid && WIFEXITED(status),
          "child process terminated abnormally");
    const int code = WEXITSTATUS(status);
    check(code == 0 || code == 2, "child process reported unexpected error");
    if (code == 0)
      ++claim_winners;
    else
      ++claim_conflicts;
  }
  check(claim_winners == 1 && claim_conflicts == 1,
        "multiprocess claim race did not yield 1 winner and 1 conflict");

  auto verify = must(IssueStore::open(root), "reopen proc store");
  const auto total = static_cast<std::size_t>(1 + kChildren * kPerProc);
  const auto all = must(verify.list(), "list multiprocess issues");
  check(all.size() == total, "multiprocess issue count mismatch");
  for (std::size_t i = 0; i < all.size(); ++i)
    check(all[i].id == "bb-" + std::to_string(i + 1),
          "multiprocess ids not monotonic 1..N");
}

void test_crash_resilience(const std::filesystem::path &base) {
  g_stage = "crash_resilience";
  const auto root = base / "crash";
  auto store = must(IssueStore::open(root), "open crash store");

  const auto i1 =
      must(store.create({"Committed 1", "body 1", IssueKind::task, 1, {}, {}, {}}),
           "create committed 1");
  const auto i2 =
      must(store.create({"Committed 2", "body 2", IssueKind::bug, 0, {}, {}, {}}),
           "create committed 2");
  check(i1.id == "bb-1" && i2.id == "bb-2", "initial crash test ids mismatch");

  // Simulate mid-write crash: truncated JSON without trailing newline.
  const auto events_path = root / "events.jsonl";
  {
    const int fd = ::open(events_path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
    check(fd >= 0, "open events.jsonl for crash injection failed");
    const std::string_view partial =
        R"({"seq":3,"op":"create","id":"bb-3","timestamp_ns":999,"title":"trunc)";
    const ssize_t wrote = ::write(fd, partial.data(), partial.size());
    (void)::close(fd);
    check(wrote == static_cast<ssize_t>(partial.size()), "partial write failed");
  }

  // Existing committed records read cleanly; partial line is ignored.
  const auto before = must(store.list(), "list with trailing partial");
  check(before.size() == 2 && before[0] == i1 && before[1] == i2,
        "committed issues damaged by trailing partial line");

  // Next write recovers cleanly on a fresh line and assigns bb-3.
  const auto i3 =
      must(store.create({"Recovered 3", "clean", IssueKind::task, 2, {}, {}, {}}),
           "create recovered bb-3");
  check(i3.id == "bb-3", "recovered issue did not receive bb-3");

  const auto after = must(store.list(), "list after recovery");
  check(after.size() == 3 && after[0] == i1 && after[1] == i2 && after[2] == i3,
        "issues mismatch after recovery");

  // Worst-case crash: complete valid JSON object missing only its trailing '\n'.
  {
    const int fd = ::open(events_path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
    check(fd >= 0, "open events.jsonl for missing-nl crash failed");
    const std::string_view missing_nl =
        R"({"seq":4,"op":"create","id":"bb-4","timestamp_ns":1000,"revision":1,"title":"uncommitted","body":"","kind":"task","priority":2,"assignee":null,"labels":[],"depends_on":[]})";
    const ssize_t wrote = ::write(fd, missing_nl.data(), missing_nl.size());
    (void)::close(fd);
    check(wrote == static_cast<ssize_t>(missing_nl.size()), "missing-nl write failed");
  }
  check(must(store.list(), "list with unterminated complete JSON").size() == 3,
        "unterminated complete JSON line was treated as committed");

  const auto i4 =
      must(store.create({"Committed 4", "ok", IssueKind::research, 1, {}, {}, {}}),
           "create bb-4 after missing-nl crash");
  check(i4.id == "bb-4" && i4.title == "Committed 4",
        "recovery after missing-nl crash assigned wrong id");
  const auto final_list = must(store.list(), "list after missing-nl recovery");
  check(final_list.size() == 4 && final_list[3] == i4,
        "unterminated JSON line resurrected or displaced bb-4");
}

} // namespace

int main() {
  char pattern[] = "/tmp/blackbird-issues-XXXXXX";
  const char *raw_dir = ::mkdtemp(pattern);
  if (!raw_dir)
    return 2;
  const std::filesystem::path base{raw_dir};
  try {
    test_directory_security_and_handle(base);
    test_crud_query_ready_and_json(base);
    test_dependency_cycles_and_validation(base);
    test_cas_and_claim_conflicts(base);
    test_multithread_concurrency(base);
    test_multiprocess_concurrency(base);
    test_crash_resilience(base);
    std::filesystem::remove_all(base);
    std::cout << "issues: directory security, CRUD/ready/JSON, dependency cycle "
                 "rejection, CAS/claim conflicts, multithread concurrency, and "
                 "crash recovery passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << g_stage << ": " << error.what() << '\n';
    std::filesystem::remove_all(base);
    return 1;
  }
}
