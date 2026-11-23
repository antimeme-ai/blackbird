#include "../src/native_process.hpp"
#include "blackbird/worktree_lease.hpp"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

namespace fs = std::filesystem;

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
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

std::string init_temp_repo(const fs::path &repo_dir) {
  fs::create_directories(repo_dir);
  (void)run_git_checked(repo_dir, {"init", "-b", "main"});
  (void)run_git_checked(repo_dir, {"config", "user.name", "Blackbird Test"});
  (void)run_git_checked(repo_dir, {"config", "user.email", "test@blackbird.local"});
  (void)run_git_checked(repo_dir, {"config", "commit.gpgsign", "false"});
  write_text_file(repo_dir / "README.md", "initial repo content\n");
  (void)run_git_checked(repo_dir, {"add", "README.md"});
  (void)run_git_checked(repo_dir, {"commit", "-m", "initial commit"});
  return run_git_checked(repo_dir, {"rev-parse", "HEAD"});
}

std::int64_t spawn_and_reap_dead_pid() {
  const pid_t child = ::fork();
  check(child >= 0, "fork failed");
  if (child == 0)
    ::_exit(0);
  int status = 0;
  pid_t waited = -1;
  do {
    waited = ::waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  check(waited == child, "waitpid failed");
  check(::kill(child, 0) == -1 && errno == ESRCH, "reaped child PID must report ESRCH");
  return static_cast<std::int64_t>(child);
}

void test_config_validation() {
  TempDir tmp{"bb-wt-cfg"};
  const fs::path repo = tmp.path() / "repo";
  const fs::path leases = tmp.path() / "leases";
  (void)init_temp_repo(repo);

  auto zero_cap = WorktreeLeaseManager::open({repo, leases, 0});
  check(!zero_cap.has_value() && zero_cap.error().code == ErrorCode::invalid_range,
        "max_leases == 0 must be rejected");

  auto over_cap = WorktreeLeaseManager::open({repo, leases, 33});
  check(!over_cap.has_value() && over_cap.error().code == ErrorCode::invalid_range,
        "max_leases == 33 must be rejected");

  const fs::path not_git = tmp.path() / "not-a-repo";
  fs::create_directories(not_git);
  auto non_repo = WorktreeLeaseManager::open({not_git, leases, 4});
  check(!non_repo.has_value() && non_repo.error().code == ErrorCode::invalid_range,
        "non-git repo_root must be rejected");

  auto aliased = WorktreeLeaseManager::open({repo, repo, 4});
  check(!aliased.has_value() && aliased.error().code == ErrorCode::conflict,
        "lease_root == repo_root must be rejected");

  auto inside_git = WorktreeLeaseManager::open({repo, repo / ".git" / "leases", 4});
  check(!inside_git.has_value() && inside_git.error().code == ErrorCode::conflict,
        "lease_root inside .git must be rejected");
  check(!fs::exists(repo / ".git" / "leases"),
        "rejected open inside .git must not create directories on disk");

  auto parent_of_repo = WorktreeLeaseManager::open({repo, tmp.path(), 4});
  check(!parent_of_repo.has_value() &&
            parent_of_repo.error().code == ErrorCode::conflict,
        "lease_root containing repo_root must be rejected");
}

void test_lifecycle_dirty_protection_and_reopen() {
  TempDir tmp{"bb-wt-life"};
  const fs::path repo = tmp.path() / "repo";
  const fs::path leases = tmp.path() / "leases";
  const std::string base_head = init_temp_repo(repo);

  auto opened = WorktreeLeaseManager::open({repo, leases, 4});
  check(opened.has_value(), "WorktreeLeaseManager::open failed");
  WorktreeLeaseManager &mgr = opened.value();

  // Verify .leases directory was created with 0700 permissions.
  struct stat st{};
  check(::stat((mgr.lease_root() / ".leases").c_str(), &st) == 0,
        ".leases dir must exist");
  check((st.st_mode & 0777) == 0700, ".leases dir must have 0700 permissions");

  WorktreeLeaseRequest req;
  req.lease_id = "worker-1";
  req.branch = "platoon/worker-1";
  req.owner_id = "peer-alpha";
  req.owner_pid = static_cast<std::int64_t>(::getpid());

  auto acquired = mgr.acquire(req);
  check(acquired.has_value(), "acquire failed");
  const WorktreeLeaseInfo &info = acquired.value();
  check(info.lease_id == "worker-1", "unexpected lease_id");
  check(info.branch == "platoon/worker-1", "unexpected branch");
  check(info.base_ref == "HEAD", "unexpected base_ref");
  check(info.base_sha == base_head, "base_sha must match initial HEAD");
  check(info.head_sha == base_head, "head_sha must match initial HEAD");
  check(!info.dirty, "fresh worktree must be clean");
  check(info.commits_ahead == 0, "fresh worktree must have commits_ahead == 0");
  check(info.owner_alive, "current process owner must be alive");
  check(info.worktree_present, "worktree must exist on disk");
  check(fs::exists(info.path / "README.md"), "checkout must contain repo files");
  check(run_git_checked(info.path, {"branch", "--show-current"}) == "platoon/worker-1",
        "worktree branch mismatch");

  // Make uncommitted modification -> dirty must be detected and release(force=false)
  // refused.
  write_text_file(info.path / "work.txt", "in-progress agent edit\n");

  auto dirty_status = mgr.status("worker-1");
  check(dirty_status.has_value(), "status failed on dirty lease");
  check(dirty_status.value().dirty, "dirty worktree must report dirty == true");
  check(dirty_status.value().commits_ahead == 0, "uncommitted file is 0 commits ahead");

  auto refused = mgr.release("worker-1", false);
  check(!refused.has_value() && refused.error().code == ErrorCode::conflict,
        "release(force=false) on dirty worktree must fail with ErrorCode::conflict");
  check(fs::exists(info.path / "work.txt"),
        "refused dirty release must preserve uncommitted file");

  // Commit in lease worktree -> commits_ahead == 1, clean, main repo untouched.
  (void)run_git_checked(info.path, {"add", "work.txt"});
  (void)run_git_checked(info.path, {"commit", "-m", "agent commit in lease"});

  auto committed_status = mgr.status("worker-1");
  check(committed_status.has_value(), "status failed after commit");
  check(!committed_status.value().dirty, "committed worktree must be clean");
  check(committed_status.value().commits_ahead == 1,
        "committed worktree must have commits_ahead == 1");
  check(committed_status.value().head_sha != base_head,
        "worktree HEAD must have advanced");

  // Main repository must be completely untouched.
  check(run_git_checked(repo, {"rev-parse", "HEAD"}) == base_head,
        "main repo HEAD must remain untouched");
  check(run_git_checked(repo, {"status", "--porcelain"}).empty(),
        "main repo must remain clean");
  check(!fs::exists(repo / "work.txt"),
        "main repo working tree must not contain lease file");

  auto listed = mgr.list();
  check(listed.has_value() && listed.value().size() == 1,
        "list() must report 1 active lease");
  check(listed.value()[0].commits_ahead == 1, "list() commits_ahead mismatch");

  // Clean release must succeed and clean up directory + metadata.
  auto released = mgr.release("worker-1", false);
  check(released.has_value(), "clean release(force=false) must succeed");
  check(!fs::exists(info.path), "released worktree directory must be removed");
  check(!fs::exists(mgr.lease_root() / ".leases" / "worker-1.json"),
        "released lease metadata must be removed");

  auto empty_list = mgr.list();
  check(empty_list.has_value() && empty_list.value().empty(),
        "list() must be empty after release");

  auto missing = mgr.status("worker-1");
  check(!missing.has_value() && missing.error().code == ErrorCode::stale_handle,
        "status on released lease must fail with stale_handle");

  // Re-acquire existing branch cleanly and verify force release on dirty tree.
  WorktreeLeaseRequest reopen_req;
  reopen_req.lease_id = "worker-1-reopen";
  reopen_req.branch = "platoon/worker-1";
  reopen_req.owner_id = "peer-beta";
  reopen_req.owner_pid = static_cast<std::int64_t>(::getpid());
  reopen_req.use_existing_branch = true;

  auto reopened = mgr.acquire(reopen_req);
  check(reopened.has_value(), "acquire with use_existing_branch must succeed");
  check(reopened.value().commits_ahead == 1,
        "reopened branch must still be 1 commit ahead of main HEAD");
  check(fs::exists(reopened.value().path / "work.txt"),
        "reopened branch must contain previously committed file");

  // Dirty the reopened checkout and verify force=true removes it.
  write_text_file(reopened.value().path / "scratch.txt", "discard me\n");
  auto forced = mgr.release("worker-1-reopen", true);
  check(forced.has_value(), "release(force=true) must remove dirty worktree");
  check(!fs::exists(reopened.value().path),
        "force-released worktree directory must be removed");
}

void test_capacity_and_conflicts() {
  TempDir tmp{"bb-wt-cap"};
  const fs::path repo = tmp.path() / "repo";
  const fs::path leases = tmp.path() / "leases";
  (void)init_temp_repo(repo);

  auto opened = WorktreeLeaseManager::open({repo, leases, 2});
  check(opened.has_value(), "open with max_leases=2 failed");
  WorktreeLeaseManager &mgr = opened.value();

  auto l1 = mgr.acquire({"slot-1", "branch-1", "HEAD", "owner-1", 0, false});
  check(l1.has_value(), "first lease must succeed");

  // Duplicate lease_id must fail with conflict.
  auto dup_id = mgr.acquire({"slot-1", "branch-other", "HEAD", "owner-2", 0, false});
  check(!dup_id.has_value() && dup_id.error().code == ErrorCode::conflict,
        "duplicate lease_id must fail with conflict");

  // Duplicate branch with use_existing_branch=false must fail with conflict.
  auto dup_branch = mgr.acquire({"slot-2", "branch-1", "HEAD", "owner-2", 0, false});
  check(!dup_branch.has_value() && dup_branch.error().code == ErrorCode::conflict,
        "existing branch with use_existing_branch=false must fail with conflict");

  // Checked-out branch with use_existing_branch=true must also fail with conflict.
  auto checked_out = mgr.acquire({"slot-2", "branch-1", "HEAD", "owner-2", 0, true});
  check(!checked_out.has_value() && checked_out.error().code == ErrorCode::conflict,
        "already checked-out branch must fail with conflict");

  auto l2 = mgr.acquire({"slot-2", "branch-2", "HEAD", "owner-2", 0, false});
  check(l2.has_value(), "second lease must succeed");

  // 3rd lease must fail with capacity.
  auto l3 = mgr.acquire({"slot-3", "branch-3", "HEAD", "owner-3", 0, false});
  check(!l3.has_value() && l3.error().code == ErrorCode::capacity,
        "3rd lease at max_leases=2 must fail with ErrorCode::capacity");

  // Releasing one frees capacity.
  check(mgr.release("slot-1", false).has_value(), "release slot-1 failed");
  auto l3_retry = mgr.acquire({"slot-3", "branch-3", "HEAD", "owner-3", 0, false});
  check(l3_retry.has_value(), "3rd lease must succeed after releasing slot-1");

  check(mgr.release("slot-2", false).has_value(), "release slot-2 failed");
  check(mgr.release("slot-3", false).has_value(), "release slot-3 failed");
}

void test_input_validation_and_injection_rejection() {
  TempDir tmp{"bb-wt-val"};
  const fs::path repo = tmp.path() / "repo";
  const fs::path leases = tmp.path() / "leases";
  (void)init_temp_repo(repo);

  auto opened = WorktreeLeaseManager::open({repo, leases, 4});
  check(opened.has_value(), "open failed");
  WorktreeLeaseManager &mgr = opened.value();

  const std::vector<std::string> bad_ids = {
      "",
      "-foo",
      "../escape",
      "a/b",
      "Upper",
      "space id",
      "dot.id",
      std::string(49, 'a'),
      std::string("nul\0id", 6),
  };
  for (const auto &bad_id : bad_ids) {
    auto res = mgr.acquire({bad_id, "good-branch", "HEAD", "owner", 0, false});
    check(!res.has_value() && res.error().code == ErrorCode::invalid_identity,
          "invalid lease_id must be rejected with invalid_identity");
  }

  const std::vector<std::string> bad_branches = {
      "",
      "-foo",
      "--detach",
      "../escape",
      "a..b",
      "a//b",
      "bad branch",
      "bad\nbranch",
      "bad\tbranch",
      "ref@{0}",
      "foo.lock",
      "/leading-slash",
      "trailing-slash/",
      ".leading-dot",
      "a/.hidden",
      "a:b",
      "a~1",
      "a^1",
      "HEAD",
      std::string("nul\0br", 6),
  };
  for (const auto &bad_branch : bad_branches) {
    auto res = mgr.acquire({"valid-id", bad_branch, "HEAD", "owner", 0, false});
    check(!res.has_value() && res.error().code == ErrorCode::invalid_range,
          "invalid branch must be rejected with invalid_range");
  }

  const std::vector<std::string> bad_base_refs = {
      "-foo",
      "HEAD..HEAD",
      "bad ref",
      "bad\nref",
      std::string("HE\0AD", 5),
      "refs/heads/does-not-exist",
  };
  for (const auto &bad_ref : bad_base_refs) {
    auto res = mgr.acquire({"valid-id", "good-branch", bad_ref, "owner", 0, false});
    check(!res.has_value() && res.error().code == ErrorCode::invalid_range,
          "invalid base_ref must be rejected with invalid_range");
  }

  auto neg_pid = mgr.acquire({"valid-id", "good-branch", "HEAD", "owner", -1, false});
  check(!neg_pid.has_value() && neg_pid.error().code == ErrorCode::invalid_range,
        "negative owner_pid must be rejected");

  auto listed = mgr.list();
  check(listed.has_value() && listed.value().empty(),
        "rejected inputs must leave zero active leases");
}

void test_reclaim_stale() {
  TempDir tmp{"bb-wt-stale"};
  const fs::path repo = tmp.path() / "repo";
  const fs::path leases = tmp.path() / "leases";
  (void)init_temp_repo(repo);

  auto opened = WorktreeLeaseManager::open({repo, leases, 8});
  check(opened.has_value(), "open failed");
  WorktreeLeaseManager &mgr = opened.value();

  const std::int64_t live_pid = static_cast<std::int64_t>(::getpid());
  const std::int64_t dead_pid_clean = spawn_and_reap_dead_pid();
  const std::int64_t dead_pid_dirty = spawn_and_reap_dead_pid();
  const std::int64_t dead_pid_missing = spawn_and_reap_dead_pid();

  auto live = mgr.acquire({"live-owner", "br-live", "HEAD", "live", live_pid, false});
  check(live.has_value(), "acquire live-owner failed");

  auto no_pid = mgr.acquire({"no-pid", "br-nopid", "HEAD", "manual", 0, false});
  check(no_pid.has_value(), "acquire no-pid failed");

  auto stale_clean = mgr.acquire(
      {"stale-clean", "br-stale-clean", "HEAD", "dead1", dead_pid_clean, false});
  check(stale_clean.has_value(), "acquire stale-clean failed");
  check(!stale_clean.value().owner_alive, "dead PID must report owner_alive == false");

  auto stale_dirty = mgr.acquire(
      {"stale-dirty", "br-stale-dirty", "HEAD", "dead2", dead_pid_dirty, false});
  check(stale_dirty.has_value(), "acquire stale-dirty failed");
  write_text_file(stale_dirty.value().path / "unsaved.txt", "do not lose this\n");

  auto stale_missing = mgr.acquire(
      {"stale-missing", "br-stale-missing", "HEAD", "dead3", dead_pid_missing, false});
  check(stale_missing.has_value(), "acquire stale-missing failed");
  fs::remove_all(stale_missing.value().path);

  auto reclaimed = mgr.reclaim_stale();
  check(reclaimed.has_value(), "reclaim_stale failed");
  const WorktreeReclaimReport &report = reclaimed.value();

  check(report.reclaimed.size() == 2 &&
            std::find(report.reclaimed.begin(), report.reclaimed.end(),
                      "stale-clean") != report.reclaimed.end() &&
            std::find(report.reclaimed.begin(), report.reclaimed.end(),
                      "stale-missing") != report.reclaimed.end(),
        "reclaim_stale must reclaim stale-clean and stale-missing");
  check(report.orphaned_dirty.size() == 1 &&
            report.orphaned_dirty[0].lease_id == "stale-dirty",
        "reclaim_stale must report stale-dirty as orphaned_dirty");
  check(report.orphaned_dirty[0].dirty && !report.orphaned_dirty[0].owner_alive,
        "orphaned_dirty entry must report dirty && !owner_alive");

  // Verify stale-clean and stale-missing are gone while stale-dirty, live-owner, and
  // no-pid remain intact.
  check(!fs::exists(stale_clean.value().path),
        "reclaimed stale-clean directory must be removed");
  check(!fs::exists(mgr.lease_root() / ".leases" / "stale-missing.json"),
        "reclaimed stale-missing metadata must be removed");
  check(fs::exists(stale_dirty.value().path / "unsaved.txt"),
        "orphaned dirty lease files must be preserved");
  check(mgr.status("live-owner").has_value(), "live-owner lease must remain");
  check(mgr.status("no-pid").has_value(), "no-pid lease must remain");
  check(mgr.status("stale-dirty").has_value(), "stale-dirty lease must remain");

  // Explicit cleanup.
  check(mgr.release("stale-dirty", true).has_value(),
        "force release of stale-dirty failed");
  check(mgr.release("live-owner", false).has_value(), "release live-owner failed");
  check(mgr.release("no-pid", false).has_value(), "release no-pid failed");
}

void test_concurrent_acquire_capacity() {
  TempDir tmp{"bb-wt-conc"};
  const fs::path repo = tmp.path() / "repo";
  const fs::path leases = tmp.path() / "leases";
  (void)init_temp_repo(repo);

  auto opened = WorktreeLeaseManager::open({repo, leases, 3});
  check(opened.has_value(), "open failed");
  WorktreeLeaseManager &mgr = opened.value();

  constexpr int kThreads = 6;
  std::atomic<int> acquired_count{0};
  std::atomic<int> capacity_count{0};
  std::atomic<int> unexpected_count{0};

  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (int i = 0; i < kThreads; ++i) {
    workers.emplace_back([&, i]() {
      const std::string id = "race-" + std::to_string(i);
      const std::string branch = "platoon/race-" + std::to_string(i);
      auto res = mgr.acquire(
          {id, branch, "HEAD", "racer", static_cast<std::int64_t>(::getpid()), false});
      if (res.has_value()) {
        ++acquired_count;
      } else if (res.error().code == ErrorCode::capacity) {
        ++capacity_count;
      } else {
        ++unexpected_count;
      }
    });
  }
  for (auto &t : workers)
    t.join();

  check(unexpected_count.load() == 0,
        "concurrent acquire produced unexpected non-capacity error");
  check(acquired_count.load() == 3,
        "exactly max_leases (3) concurrent acquires must succeed");
  check(capacity_count.load() == 3,
        "remaining 3 concurrent acquires must fail with ErrorCode::capacity");

  auto listed = mgr.list();
  check(listed.has_value() && listed.value().size() == 3,
        "list() must report exactly 3 leases after race");

  for (const auto &item : listed.value())
    check(mgr.release(item.lease_id, false).has_value(),
          "cleanup release after concurrency test failed");
}

void test_corrupt_worktree_under_parent_repo_does_not_abort_reclaim() {
  TempDir tmp{"bb-wt-corrupt"};
  const fs::path repo = tmp.path() / "repo";
  (void)init_temp_repo(repo);
  // Place lease_root inside repo (ignored by git) so an unlinked lease dir would
  // otherwise walk up to the clean parent repo if rev-parse --show-toplevel wasn't
  // checked.
  write_text_file(repo / ".gitignore", ".leases-under-repo/\n");
  (void)run_git_checked(repo, {"add", ".gitignore"});
  (void)run_git_checked(repo, {"commit", "-m", "ignore local leases"});

  const fs::path leases = repo / ".leases-under-repo";
  auto opened = WorktreeLeaseManager::open({repo, leases, 4});
  check(opened.has_value(), "open under repo failed");
  WorktreeLeaseManager &mgr = opened.value();

  const std::int64_t dead_corrupt = spawn_and_reap_dead_pid();
  const std::int64_t dead_clean = spawn_and_reap_dead_pid();

  auto corrupt_lease =
      mgr.acquire({"a-corrupt", "br-corrupt", "HEAD", "dead1", dead_corrupt, false});
  check(corrupt_lease.has_value(), "acquire corrupt_lease failed");
  auto clean_lease =
      mgr.acquire({"z-clean", "br-clean", "HEAD", "dead2", dead_clean, false});
  check(clean_lease.has_value(), "acquire clean_lease failed");

  // Delete .git inside a-corrupt so git status would walk up to clean parent repo!
  fs::remove(corrupt_lease.value().path / ".git");

  auto st = mgr.status("a-corrupt");
  check(st.has_value(), "status on corrupt lease failed");
  check(
      st.value().worktree_present && st.value().dirty,
      "lease with missing .git must be reported dirty, not inherit parent cleanliness");

  auto non_force = mgr.release("a-corrupt", false);
  check(!non_force.has_value() && non_force.error().code == ErrorCode::conflict,
        "release(force=false) on corrupt lease must refuse with conflict");

  // reclaim_stale must preserve a-corrupt in orphaned_dirty AND still reclaim z-clean!
  auto report = mgr.reclaim_stale();
  check(report.has_value(), "reclaim_stale must not abort on corrupt lease dir");
  check(report.value().reclaimed.size() == 1 &&
            report.value().reclaimed[0] == "z-clean",
        "reclaim_stale must still reclaim z-clean after encountering a-corrupt");
  check(report.value().orphaned_dirty.size() == 1 &&
            report.value().orphaned_dirty[0].lease_id == "a-corrupt",
        "reclaim_stale must classify a-corrupt as orphaned_dirty");
  check(fs::exists(corrupt_lease.value().path),
        "corrupt lease directory must be preserved by reclaim_stale");
  check(!fs::exists(clean_lease.value().path),
        "z-clean directory must be removed by reclaim_stale");

  check(mgr.release("a-corrupt", true).has_value(),
        "force release must clean up corrupt lease");
}

} // namespace

int main() {
  try {
    test_config_validation();
    test_lifecycle_dirty_protection_and_reopen();
    test_capacity_and_conflicts();
    test_input_validation_and_injection_rejection();
    test_reclaim_stale();
    test_concurrent_acquire_capacity();
    test_corrupt_worktree_under_parent_repo_does_not_abort_reclaim();
    std::cout << "PASS worktree_lease\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "FAIL worktree_lease: " << ex.what() << "\n";
    return 1;
  }
}
