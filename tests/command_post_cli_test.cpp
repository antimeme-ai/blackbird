#include "../src/native_process.hpp"
#include "blackbird/capabilities.hpp"
#include "blackbird/command_post_cli.hpp"
#include "blackbird/json.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/value.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

extern char **environ;

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

void test_subcommand_dispatch_table() {
  for (const char *name :
       {"mcp", "platoon", "issues", "memory", "peer", "capabilities", "metrics"}) {
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

  const auto res =
      run_cli({"mcp", "--board", board_dir.string(), "--allow-root", allow_dir.string(),
               "--max-peers", "2", "--max-line-bytes", "65536"},
              stdin_rpc);
  check(res.exit_code == 0, "mcp subcommand returned non-zero");

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

} // namespace

int main(int argc, char **argv) {
  if (argc > 1 && std::string_view{argv[1]} == "--session")
    return run_fake_peer_child(argc, argv);

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
