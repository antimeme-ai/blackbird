#include "../src/native_process.hpp"
#include "blackbird/json.hpp"
#include "blackbird/mcp_server.hpp"
#include "blackbird/value.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
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

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

std::string env_or_empty(const char *name) {
  const char *val = std::getenv(name);
  return val != nullptr ? std::string{val} : std::string{};
}

int run_fake_peer(int argc, char **argv) {
  const std::string mode = env_or_empty("MCP_FAKE_PEER_MODE");
  if (mode == "sleep") {
    std::cout << "PEER_READY\n" << std::flush;
    for (int i = 0; i < 300; ++i)
      ::usleep(100000);
    return 0;
  }
  Value::Array args;
  for (int i = 1; i < argc; ++i)
    args.emplace_back(std::string{argv[i]});
  Value::Object report{
      {"argv", Value{std::move(args)}},
      {"board", Value{env_or_empty("BLACKBIRD_PLATOON_BOARD")}},
      {"peer_id", Value{env_or_empty("BLACKBIRD_PLATOON_PEER_ID")}},
      {"role", Value{env_or_empty("BLACKBIRD_PLATOON_ROLE")}},
  };
  const auto encoded = dump_json(Value::object(std::move(report)));
  if (!encoded.has_value())
    return 99;
  std::cout << encoded.value() << '\n' << std::flush;
  return 0;
}

int run_fake_curl() {
  // Drain stdin (curl --config - payload) without echoing any credentials.
  std::string body;
  std::string line;
  while (std::getline(std::cin, line))
    body += line + "\n";

  // Return a valid clef decision response matching the single choice question in tests.
  const std::string response =
      R"({"model":"clef-latest","answers":{"q1":{"type":"choice","choice":"yes","confidence":0.9,"probabilities":{"yes":0.9,"no":0.1}}},"usage":{"input_tokens":12,"output_tokens":4}})";
  std::cout << response << "\n200";
  std::cout.flush();
  return 0;
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
  check(static_cast<bool>(out), "failed to open file");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  check(static_cast<bool>(out), "failed to write file");
}

void init_temp_repo(const fs::path &repo_dir) {
  fs::create_directories(repo_dir);
  (void)run_git_checked(repo_dir, {"init", "-b", "main"});
  (void)run_git_checked(repo_dir, {"config", "user.name", "Blackbird MCP Test"});
  (void)run_git_checked(repo_dir, {"config", "user.email", "mcp@blackbird.local"});
  (void)run_git_checked(repo_dir, {"config", "commit.gpgsign", "false"});
  write_text_file(repo_dir / "README.md", "command post test repo\n");
  (void)run_git_checked(repo_dir, {"add", "README.md"});
  (void)run_git_checked(repo_dir, {"commit", "-m", "initial commit"});
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

bool req_bool(const Value &obj, std::string_view key) {
  const Value &v = req_field(obj, key);
  check(std::holds_alternative<bool>(v.value()), "expected bool field");
  return std::get<bool>(v.value());
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

std::string to_json_line(const Value &v) {
  const auto dumped = dump_json(v);
  check(dumped.has_value(), "dump_json failed");
  return dumped.value() + "\n";
}

Value parse_tool_payload(const Value &rpc_reply, bool expected_error) {
  const Value &result = req_field(rpc_reply, "result");
  check(req_bool(result, "isError") == expected_error, "unexpected isError flag");
  const Value &content = req_field(result, "content");
  check(std::holds_alternative<Value::Array>(content.value()) &&
            content.array().size() == 1,
        "expected single MCP content item");
  const Value &item = content.array()[0];
  check(req_str(item, "type") == "text", "expected text content item");
  const auto parsed = parse_json(req_str(item, "text"));
  check(parsed.has_value(), "tool text payload is not valid JSON");
  return parsed.value();
}

std::vector<Value> split_output_lines(const std::string &output) {
  std::vector<Value> replies;
  std::istringstream iss{output};
  std::string line;
  while (std::getline(iss, line)) {
    check(!line.empty(), "unexpected empty output line");
    const auto parsed = parse_json(line);
    check(parsed.has_value(), "server emitted invalid JSON");
    replies.push_back(parsed.value());
  }
  return replies;
}

Value rpc_request(std::int64_t id, std::string_view method, Value params) {
  return Value::object({
      {"jsonrpc", Value{"2.0"}},
      {"id", Value{Number{id}}},
      {"method", Value{std::string{method}}},
      {"params", std::move(params)},
  });
}

Value rpc_tool_call(std::int64_t id, std::string_view tool_name, Value arguments) {
  return rpc_request(id, "tools/call",
                     Value::object({
                         {"name", Value{std::string{tool_name}}},
                         {"arguments", std::move(arguments)},
                     }));
}

struct RoundtripPaths {
  fs::path base;
  fs::path self_exe;
};

Value require_reply(std::optional<Value> reply, const char *message) {
  if (!reply.has_value())
    throw std::runtime_error(message);
  return std::move(*reply);
}

void test_selective_exposure_and_config_validation(const fs::path &base) {
  // Invalid max_line_bytes rejected.
  {
    McpCommandPostConfig bad;
    bad.max_line_bytes = 64;
    const auto res = McpCommandPostServer::open(bad);
    check(!res.has_value() && res.error().code == ErrorCode::invalid_range,
          "too-small max_line_bytes accepted");
  }

  // Empty config exposes zero tools; calling an unconfigured tool returns isError:
  // true.
  {
    auto opened = McpCommandPostServer::open(McpCommandPostConfig{});
    check(opened.has_value(), "empty config open failed");
    auto &server = opened.value();
    check(server.tool_names().empty(), "empty config exposed tools");

    const Value list_reply = require_reply(
        server.handle_message(rpc_request(1, "tools/list", Value::object({}))),
        "tools/list missing reply");
    const auto &tools = req_field(req_field(list_reply, "result"), "tools").array();
    check(tools.empty(), "tools/list should be empty for empty config");

    const Value call_reply = require_reply(
        server.handle_message(rpc_tool_call(2, "worktree_list", Value::object({}))),
        "tools/call missing reply");
    const Value payload = parse_tool_payload(call_reply, true);
    check(req_str(payload, "error") == "unknown_tool",
          "unconfigured tool should return unknown_tool");
  }

  // Board-only config exposes exactly the 4 board tools.
  {
    McpCommandPostConfig cfg;
    cfg.board_root = base / "board-only";
    auto opened = McpCommandPostServer::open(std::move(cfg));
    check(opened.has_value(), "board-only open failed");
    const auto names = opened.value().tool_names();
    check(names.size() == 4, "board-only config should expose 4 tools");
  }
}

void test_full_stdio_roundtrip(const RoundtripPaths &paths) {
  const fs::path &base = paths.base;
  const fs::path &self_exe = paths.self_exe;
  const fs::path board_dir = base / "board";
  const fs::path repo_dir = base / "repo";
  const fs::path leases_dir = base / "leases";
  const fs::path peer_work = base / "peer-work";
  const fs::path peer_sessions = base / "peer-sessions";
  const fs::path forbidden_dir = base / "outside-root";
  init_temp_repo(repo_dir);
  fs::create_directories(peer_work);
  fs::create_directories(peer_sessions);
  fs::create_directories(forbidden_dir);

  McpCommandPostConfig cfg;
  cfg.max_line_bytes = 64U * 1024U;
  cfg.board_root = board_dir;
  cfg.worktree_lease = WorktreeLeaseConfig{repo_dir, leases_dir, 4};

  McpPlatoonPeerConfig peer_cfg;
  peer_cfg.max_peers = 4;
  peer_cfg.executable = self_exe;
  peer_cfg.working_root = peer_work;
  peer_cfg.session_root = peer_sessions;
  peer_cfg.allowed_workspace_roots = {peer_work, peer_sessions};
  cfg.platoon_runner = std::move(peer_cfg);

  DecisionModelConfig decision_cfg;
  decision_cfg.curl_executable = self_exe.string();
  cfg.decision_models = std::move(decision_cfg);

  auto opened = McpCommandPostServer::open(std::move(cfg));
  check(opened.has_value(), "full McpCommandPostServer::open failed");
  McpCommandPostServer &server = opened.value();
  check(server.tool_names().size() == 13, "expected 13 wired command post tools");

  // Phase 1: stdio round-trip covering handshake, silent notification, ping,
  // tools/list, board/roster, worktree lifecycle, peer spawn/list, decision_evaluate,
  // and protocol error paths.
  std::string input;

  // 1: initialize
  input += to_json_line(rpc_request(
      1, "initialize",
      Value::object({
          {"protocolVersion", Value{"2025-03-26"}},
          {"capabilities", Value::object({})},
          {"clientInfo",
           Value::object({{"name", Value{"test-client"}}, {"version", Value{"0.1"}}})},
      })));

  // Notification: notifications/initialized (MUST emit NO reply!)
  input += to_json_line(Value::object({
      {"jsonrpc", Value{"2.0"}},
      {"method", Value{"notifications/initialized"}},
  }));

  // 2: ping
  input += to_json_line(rpc_request(2, "ping", Value::object({})));

  // 3: tools/list
  input += to_json_line(rpc_request(3, "tools/list", Value::object({})));

  // 4: platoon_roster_upsert
  input += to_json_line(
      rpc_tool_call(4, "platoon_roster_upsert",
                    Value::object({
                        {"id", Value{"alpha"}},
                        {"role", Value{"implementer"}},
                        {"provider", Value{"anthropic"}},
                        {"model", Value{"claude-sonnet"}},
                        {"workspace", Value{peer_work.string()}},
                        {"branch", Value{"platoon/alpha"}},
                        {"state", Value{"working"}},
                        {"pid", Value{Number{static_cast<std::int64_t>(::getpid())}}},
                        {"brief", Value{"Build Command Post MCP server"}},
                    })));

  // 5: platoon_roster_list
  input += to_json_line(rpc_tool_call(5, "platoon_roster_list", Value::object({})));

  // 6: platoon_board_post
  input += to_json_line(
      rpc_tool_call(6, "platoon_board_post",
                    Value::object({
                        {"from", Value{"alpha"}},
                        {"to", Value{"dentist"}},
                        {"kind", Value{"handoff"}},
                        {"text", Value{"Ready for verification"}},
                        {"refs", Value{Value::Array{Value{"src/mcp_server.cpp"}}}},
                    })));

  // 7: platoon_board_read
  input += to_json_line(rpc_tool_call(7, "platoon_board_read",
                                      Value::object({
                                          {"after_seq", Value{Number{0}}},
                                          {"limit", Value{Number{10}}},
                                          {"recipient_filter", Value{"dentist"}},
                                      })));

  // 8: worktree_acquire
  input += to_json_line(rpc_tool_call(
      8, "worktree_acquire",
      Value::object({
          {"lease_id", Value{"wt-alpha"}},
          {"branch", Value{"platoon/wt-alpha"}},
          {"owner_id", Value{"alpha"}},
          {"owner_pid", Value{Number{static_cast<std::int64_t>(::getpid())}}},
      })));

  // 9: worktree_list
  input += to_json_line(rpc_tool_call(9, "worktree_list", Value::object({})));

  // 10: worktree_status
  input += to_json_line(rpc_tool_call(
      10, "worktree_status", Value::object({{"lease_id", Value{"wt-alpha"}}})));

  // 11: worktree_release (clean)
  input += to_json_line(rpc_tool_call(
      11, "worktree_release", Value::object({{"lease_id", Value{"wt-alpha"}}})));

  // 12: worktree_reclaim
  input += to_json_line(rpc_tool_call(12, "worktree_reclaim", Value::object({})));

  // 13: platoon_peer_spawn (quick self-exec peer)
  input += to_json_line(rpc_tool_call(13, "platoon_peer_spawn",
                                      Value::object({
                                          {"peer_id", Value{"peer-fast"}},
                                          {"role", Value{"reviewer"}},
                                          {"provider", Value{"openai"}},
                                          {"model", Value{"gpt-5"}},
                                          {"prompt", Value{"verify mcp"}},
                                      })));

  // 14: platoon_peer_list
  input += to_json_line(rpc_tool_call(14, "platoon_peer_list", Value::object({})));

  // 15: decision_evaluate (valid clef call through fake curl)
  input += to_json_line(rpc_tool_call(
      15, "decision_evaluate",
      Value::object({
          {"provider", Value{"clef"}},
          {"state", Value{"MCP server tests passing"}},
          {"questions",
           Value::object({
               {"q1", Value::object({
                          {"type", Value{"choice"}},
                          {"instructions", Value{"Ship it?"}},
                          {"criteria", Value::object({{"yes", Value{"ready"}},
                                                      {"no", Value{"not ready"}}})},
                      })},
           })},
      })));

  // 16: decision_evaluate rejects credential injection in arguments
  input += to_json_line(
      rpc_tool_call(16, "decision_evaluate",
                    Value::object({
                        {"provider", Value{"jev"}},
                        {"api_key", Value{"sk-secret-must-never-be-accepted"}},
                        {"state", Value{"test"}},
                        {"questions", Value::object({})},
                    })));

  // 17: unknown method (-32601)
  input += to_json_line(rpc_request(17, "nonexistent/method", Value::object({})));

  // 18: unknown tool (isError: true)
  input += to_json_line(rpc_tool_call(18, "does_not_exist", Value::object({})));

  // Malformed JSON (-32700) — must not crash loop!
  input += "{not valid json\n";

  // Invalid UTF-8 (-32700)
  input += std::string{"{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"\xff\xfe\"}\n"};

  // 19: Invalid params (-32602): tools/call missing name
  input += to_json_line(rpc_request(19, "tools/call", Value::object({})));

  // 20: Invalid params (-32602): tools/call non-object arguments
  input +=
      to_json_line(rpc_request(20, "tools/call",
                               Value::object({{"name", Value{"platoon_roster_list"}},
                                              {"arguments", Value{"not-an-object"}}})));

  // 21: Invalid request (-32600): wrong jsonrpc version
  input += to_json_line(Value::object({
      {"jsonrpc", Value{"1.0"}},
      {"id", Value{Number{21}}},
      {"method", Value{"ping"}},
  }));

  // 22: Verify loop recovered cleanly and still serves ping after errors!
  input += to_json_line(rpc_request(22, "ping", Value::object({})));

  std::istringstream in{input};
  std::ostringstream out;
  const int rc = server.run_stdio(in, out);
  check(rc == 0, "run_stdio returned non-zero");

  const auto replies = split_output_lines(out.str());
  // 22 numbered requests + 2 parse errors (malformed JSON + invalid UTF-8) = 24
  // replies. The notifications/initialized notification produced ZERO replies!
  check(replies.size() == 24, "unexpected reply count (notification must be silent)");

  std::size_t idx = 0;

  // Verify #1 initialize
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 1, "id 1 mismatch");
    const Value &res = req_field(r, "result");
    check(req_str(res, "protocolVersion") == "2025-03-26", "protocolVersion mismatch");
    const Value &caps = req_field(res, "capabilities");
    check(caps.find("tools") != nullptr, "capabilities.tools missing");
    const Value &info = req_field(res, "serverInfo");
    check(req_str(info, "name") == "blackbird-command-post",
          "serverInfo.name mismatch");
    check(req_str(info, "version") == "1.0.0", "serverInfo.version mismatch");
  }

  // Verify #2 ping (proves notifications/initialized emitted nothing between #1 and
  // #2!)
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 2,
          "expected ping reply id 2 immediately after initialize");
    const Value &res = req_field(r, "result");
    check(std::holds_alternative<Value::Object>(res.value()) && res.object().empty(),
          "ping must return empty object");
  }

  // Verify #3 tools/list
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 3, "id 3 mismatch");
    const auto &tools = req_field(req_field(r, "result"), "tools").array();
    check(tools.size() == 13, "tools/list must return 13 tools");
  }

  // Verify #4 platoon_roster_upsert
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 4, "id 4 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_str(p, "id") == "alpha", "roster upsert id mismatch");
    check(req_str(p, "state") == "working", "roster upsert state mismatch");
  }

  // Verify #5 platoon_roster_list
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 5, "id 5 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_int(p, "count") == 1, "roster list count != 1");
    const auto &members = req_field(p, "members").array();
    check(members.size() == 1 && req_str(members[0], "id") == "alpha",
          "roster list member mismatch");
  }

  // Verify #6 platoon_board_post
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 6, "id 6 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_int(p, "seq") == 1, "posted message seq != 1");
    check(req_str(p, "kind") == "handoff", "posted message kind mismatch");
    check(req_str(p, "text") == "Ready for verification", "posted text mismatch");
  }

  // Verify #7 platoon_board_read
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 7, "id 7 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_int(p, "latest_seq") == 1 && req_int(p, "count") == 1,
          "board read count/latest_seq mismatch");
    const auto &msgs = req_field(p, "messages").array();
    check(msgs.size() == 1 && req_str(msgs[0], "from") == "alpha",
          "board read message mismatch");
  }

  // Verify #8 worktree_acquire
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 8, "id 8 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_str(p, "lease_id") == "wt-alpha", "worktree lease_id mismatch");
    check(req_str(p, "branch") == "platoon/wt-alpha", "worktree branch mismatch");
    check(!req_bool(p, "dirty"), "fresh worktree must not be dirty");
  }

  // Verify #9 worktree_list
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 9, "id 9 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_int(p, "count") == 1, "worktree list count != 1");
  }

  // Verify #10 worktree_status
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 10, "id 10 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_bool(p, "worktree_present") && req_bool(p, "owner_alive"),
          "worktree status flags mismatch");
  }

  // Verify #11 worktree_release
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 11, "id 11 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_bool(p, "released") && !req_bool(p, "forced"),
          "clean worktree release payload mismatch");
  }

  // Verify #12 worktree_reclaim
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 12, "id 12 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_field(p, "reclaimed").array().empty() &&
              req_field(p, "orphaned_dirty").array().empty(),
          "worktree reclaim should report empty lists");
  }

  // Verify #13 platoon_peer_spawn
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 13, "id 13 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_str(p, "peer_id") == "peer-fast", "spawned peer_id mismatch");
    check(req_int(p, "pid") > 0, "spawned peer pid invalid");
  }

  // Verify #14 platoon_peer_list
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 14, "id 14 mismatch");
    const Value p = parse_tool_payload(r, false);
    const auto &peers = req_field(p, "peers").array();
    check(peers.size() == 1 && req_str(peers[0], "peer_id") == "peer-fast",
          "platoon_peer_list missing peer-fast");
  }

  // Verify #15 decision_evaluate success
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 15, "id 15 mismatch");
    const Value p = parse_tool_payload(r, false);
    check(req_str(p, "status") == "ok" && req_str(p, "provider") == "clef",
          "decision_evaluate result mismatch");
    const Value &resp = req_field(p, "response");
    const Value &q1 = req_field(req_field(resp, "answers"), "q1");
    check(req_str(q1, "choice") == "yes", "decision_evaluate choice mismatch");
  }

  // Verify #16 decision_evaluate credential rejection
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 16, "id 16 mismatch");
    const Value p = parse_tool_payload(r, true);
    check(req_str(p, "error") == "invalid_arguments",
          "credential argument in decision_evaluate must be rejected");
  }

  // Verify #17 unknown method (-32601)
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 17, "id 17 mismatch");
    const Value &err = req_field(r, "error");
    check(req_int(err, "code") == kJsonRpcMethodNotFound,
          "unknown method must return -32601");
  }

  // Verify #18 unknown tool (isError: true)
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 18, "id 18 mismatch");
    const Value p = parse_tool_payload(r, true);
    check(req_str(p, "error") == "unknown_tool", "unknown tool error code mismatch");
  }

  // Verify malformed JSON (-32700)
  {
    const Value &r = replies[idx++];
    check(std::holds_alternative<std::nullptr_t>(req_field(r, "id").value()),
          "parse error id must be null");
    check(req_int(req_field(r, "error"), "code") == kJsonRpcParseError,
          "malformed JSON must return -32700");
  }

  // Verify invalid UTF-8 (-32700)
  {
    const Value &r = replies[idx++];
    check(req_int(req_field(r, "error"), "code") == kJsonRpcParseError,
          "invalid UTF-8 must return -32700");
  }

  // Verify #19 invalid params (-32602)
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 19, "id 19 mismatch");
    check(req_int(req_field(r, "error"), "code") == kJsonRpcInvalidParams,
          "missing tools/call name must return -32602");
  }

  // Verify #20 invalid params (-32602)
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 20, "id 20 mismatch");
    check(req_int(req_field(r, "error"), "code") == kJsonRpcInvalidParams,
          "non-object tools/call arguments must return -32602");
  }

  // Verify #21 invalid request (-32600)
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 21, "id 21 mismatch");
    check(req_int(req_field(r, "error"), "code") == kJsonRpcInvalidRequest,
          "bad jsonrpc version must return -32600");
  }

  // Verify #22 ping recovery after errors
  {
    const Value &r = replies[idx++];
    check(req_int(r, "id") == 22, "id 22 mismatch");
    check(req_field(r, "result").object().empty(), "final ping failed");
  }

  // Phase 2: Direct handle_message security & lifecycle checks
  // A) Dirty worktree release MUST be refused without force=true, preserving dirty
  // file.
  {
    const Value acq = require_reply(
        server.handle_message(rpc_tool_call(
            101, "worktree_acquire",
            Value::object({
                {"lease_id", Value{"wt-dirty"}},
                {"branch", Value{"platoon/wt-dirty"}},
                {"owner_id", Value{"alpha"}},
                {"owner_pid", Value{Number{static_cast<std::int64_t>(::getpid())}}},
            }))),
        "dirty worktree acquire missing reply");
    const Value acq_payload = parse_tool_payload(acq, false);
    const fs::path wt_path{req_str(acq_payload, "path")};
    write_text_file(wt_path / "unsaved.txt", "precious uncommitted work\n");

    const Value refused = require_reply(
        server.handle_message(rpc_tool_call(
            102, "worktree_release", Value::object({{"lease_id", Value{"wt-dirty"}}}))),
        "dirty release missing reply");
    const Value ref_payload = parse_tool_payload(refused, true);
    check(req_str(ref_payload, "error") == "conflict",
          "dirty worktree release without force must return conflict");
    check(fs::exists(wt_path / "unsaved.txt"),
          "refused dirty release must preserve dirty file");

    // Explicit force=true succeeds.
    const Value forced = require_reply(
        server.handle_message(rpc_tool_call(
            103, "worktree_release",
            Value::object({{"lease_id", Value{"wt-dirty"}}, {"force", Value{true}}}))),
        "forced release missing reply");
    const Value force_payload = parse_tool_payload(forced, false);
    check(req_bool(force_payload, "released") && req_bool(force_payload, "forced"),
          "forced release payload mismatch");
  }

  // B) Peer stop on sleeping peer + security rejections (executable override & path
  // escape outside allowed_workspace_roots).
  {
    const Value exec_reject = require_reply(
        server.handle_message(rpc_tool_call(110, "platoon_peer_spawn",
                                            Value::object({
                                                {"peer_id", Value{"bad-exec"}},
                                                {"role", Value{"worker"}},
                                                {"provider", Value{"openai"}},
                                                {"model", Value{"gpt-5"}},
                                                {"prompt", Value{"hi"}},
                                                {"executable", Value{"/bin/sh"}},
                                            }))),
        "exec reject missing reply");
    const Value exec_payload = parse_tool_payload(exec_reject, true);
    check(req_str(exec_payload, "error") == "invalid_arguments",
          "executable override in tool arguments must be rejected");

    const Value escape_reject =
        require_reply(server.handle_message(rpc_tool_call(
                          111, "platoon_peer_spawn",
                          Value::object({
                              {"peer_id", Value{"bad-path"}},
                              {"role", Value{"worker"}},
                              {"provider", Value{"openai"}},
                              {"model", Value{"gpt-5"}},
                              {"prompt", Value{"hi"}},
                              {"working_dir", Value{forbidden_dir.string()}},
                          }))),
                      "escape reject missing reply");
    const Value esc_payload = parse_tool_payload(escape_reject, true);
    check(req_str(esc_payload, "error") == "forbidden_path",
          "working_dir outside allowed_workspace_roots must be rejected");

    // Symlink + ".." escape: /peer_work/sub/link -> forbidden_dir, then "..".
    const fs::path sub_dir = peer_work / "sub";
    fs::create_directories(sub_dir);
    const fs::path live_link = sub_dir / "link";
    fs::create_directory_symlink(forbidden_dir, live_link);
    const fs::path dangling_link = peer_work / "dangling";
    fs::create_directory_symlink(forbidden_dir / "nonexistent-dir", dangling_link);

    const Value dotdot_symlink_reject =
        require_reply(server.handle_message(rpc_tool_call(
                          114, "platoon_peer_spawn",
                          Value::object({
                              {"peer_id", Value{"bad-dotdot"}},
                              {"role", Value{"worker"}},
                              {"provider", Value{"openai"}},
                              {"model", Value{"gpt-5"}},
                              {"prompt", Value{"hi"}},
                              {"working_dir", Value{(live_link / "..").string()}},
                          }))),
                      "dotdot symlink reject missing reply");
    check(req_str(parse_tool_payload(dotdot_symlink_reject, true), "error") ==
              "forbidden_path",
          "symlink + '..' escape must be rejected");

    const Value live_symlink_reject =
        require_reply(server.handle_message(
                          rpc_tool_call(115, "platoon_peer_spawn",
                                        Value::object({
                                            {"peer_id", Value{"bad-live-link"}},
                                            {"role", Value{"worker"}},
                                            {"provider", Value{"openai"}},
                                            {"model", Value{"gpt-5"}},
                                            {"prompt", Value{"hi"}},
                                            {"working_dir", Value{live_link.string()}},
                                        }))),
                      "live symlink reject missing reply");
    check(req_str(parse_tool_payload(live_symlink_reject, true), "error") ==
              "forbidden_path",
          "live symlink pointing outside allowed_workspace_roots must be rejected");

    const Value dangling_reject =
        require_reply(server.handle_message(rpc_tool_call(
                          116, "platoon_peer_spawn",
                          Value::object({
                              {"peer_id", Value{"bad-dangling"}},
                              {"role", Value{"worker"}},
                              {"provider", Value{"openai"}},
                              {"model", Value{"gpt-5"}},
                              {"prompt", Value{"hi"}},
                              {"session_dir", Value{(dangling_link / "leaf").string()}},
                          }))),
                      "dangling symlink reject missing reply");
    check(req_str(parse_tool_payload(dangling_reject, true), "error") ==
              "forbidden_path",
          "dangling symlink escape must be rejected");

    // Reserved BLACKBIRD_PLATOON_* spoofing, exec-hijack, and
    // credential/config-redirect env vars (Kimi Review #2 M1) must all be rejected.
    std::int64_t env_test_id = 120;
    for (const char *bad_env : {"BLACKBIRD_PLATOON_BOARD",
                                "BLACKBIRD_PLATOON_PEER_ID",
                                "BLACKBIRD_PLATOON_ROLE",
                                "PATH",
                                "GIT_SSH_COMMAND",
                                "GIT_EXEC_PATH",
                                "GIT_CONFIG_COUNT",
                                "GIT_DIR",
                                "GIT_WORK_TREE",
                                "HOME",
                                "SSH_AUTH_SOCK",
                                "XDG_CONFIG_HOME",
                                "LD_PRELOAD",
                                "DYLD_INSERT_LIBRARIES",
                                "PERL5OPT",
                                "RUBYOPT",
                                "NPM_CONFIG_PREFIX",
                                "JAVA_TOOL_OPTIONS",
                                "_JAVA_OPTIONS",
                                "NODE_OPTIONS",
                                "PYTHONSTARTUP",
                                "PYTHONPATH",
                                "BASH_ENV",
                                "BASH_FUNC_x",
                                "ENV",
                                "GNUPGHOME",
                                "CARGO_HOME",
                                "RUSTUP_HOME",
                                "GEM_HOME",
                                "GCONV_PATH",
                                "LOCPATH",
                                "NLSPATH",
                                "IFS",
                                "CURL_HOME",
                                "ZDOTDIR",
                                "OPENAI_API_KEY"}) {
      const Value env_reject = require_reply(
          server.handle_message(rpc_tool_call(
              env_test_id++, "platoon_peer_spawn",
              Value::object({
                  {"peer_id", Value{"bad-env"}},
                  {"role", Value{"worker"}},
                  {"provider", Value{"openai"}},
                  {"model", Value{"gpt-5"}},
                  {"prompt", Value{"hi"}},
                  {"extra_env", Value::object({{bad_env, Value{"/tmp/evil"}}})},
              }))),
          "disallowed extra_env missing reply");
      check(req_str(parse_tool_payload(env_reject, true), "error") ==
                "invalid_arguments",
            "disallowed extra_env variable must be rejected");
    }

    // Invalid extra_env key syntax (empty, leading digit, '=', whitespace) rejected.
    for (const char *bad_key : {"", "1BAD", "FOO=BAR", "FOO BAR", "FOO\nBAR"}) {
      const Value key_reject =
          require_reply(server.handle_message(rpc_tool_call(
                            env_test_id++, "platoon_peer_spawn",
                            Value::object({
                                {"peer_id", Value{"bad-key"}},
                                {"role", Value{"worker"}},
                                {"provider", Value{"openai"}},
                                {"model", Value{"gpt-5"}},
                                {"prompt", Value{"hi"}},
                                {"extra_env", Value::object({{bad_key, Value{"val"}}})},
                            }))),
                        "invalid extra_env key missing reply");
      check(req_str(parse_tool_payload(key_reject, true), "error") ==
                "invalid_arguments",
            "invalid extra_env key syntax must be rejected");
    }

    // Post-decode \u0000 NUL in extra_env key and value (Kimi Review #2 L1) rejected!
    {
      const std::string nul_key_line =
          R"({"jsonrpc":"2.0","id":"nul-key","method":"tools/call","params":{"name":"platoon_peer_spawn","arguments":{"peer_id":"bad-nul-k","role":"worker","provider":"openai","model":"gpt-5","prompt":"hi","extra_env":{"SAFE\u0000EVIL":"ok"}}}})";
      const Value nul_key_reply =
          require_reply(server.handle_line(nul_key_line), "nul-key missing reply");
      check(req_str(nul_key_reply, "id") == "nul-key", "string id echo mismatch");
      check(req_str(parse_tool_payload(nul_key_reply, true), "error") ==
                "invalid_arguments",
            "decoded NUL in extra_env key must be rejected");

      const std::string nul_val_line =
          R"({"jsonrpc":"2.0","id":"nul-val","method":"tools/call","params":{"name":"platoon_peer_spawn","arguments":{"peer_id":"bad-nul-v","role":"worker","provider":"openai","model":"gpt-5","prompt":"hi","extra_env":{"SAFE_VAR":"ok\u0000evil"}}}})";
      const Value nul_val_reply =
          require_reply(server.handle_line(nul_val_line), "nul-val missing reply");
      check(req_str(nul_val_reply, "id") == "nul-val", "string id echo mismatch");
      check(req_str(parse_tool_payload(nul_val_reply, true), "error") ==
                "invalid_arguments",
            "decoded NUL in extra_env value must be rejected");
    }

    // Sibling prefix path rejection: /.../peer-work2 MUST NOT match /.../peer-work!
    {
      const fs::path sibling_dir = base / "peer-work2";
      fs::create_directories(sibling_dir);
      const Value sibling_reject =
          require_reply(server.handle_message(rpc_tool_call(
                            env_test_id++, "platoon_peer_spawn",
                            Value::object({
                                {"peer_id", Value{"bad-sibling"}},
                                {"role", Value{"worker"}},
                                {"provider", Value{"openai"}},
                                {"model", Value{"gpt-5"}},
                                {"prompt", Value{"hi"}},
                                {"working_dir", Value{sibling_dir.string()}},
                            }))),
                        "sibling prefix reject missing reply");
      check(req_str(parse_tool_payload(sibling_reject, true), "error") ==
                "forbidden_path",
            "sibling prefix path must be rejected");
    }

    // String JSON-RPC id echo on normal result and error replies.
    {
      const Value str_ping = require_reply(
          server.handle_line(
              R"({"jsonrpc":"2.0","id":"req-str-42","method":"ping","params":{}})"),
          "string id ping missing reply");
      check(req_str(str_ping, "id") == "req-str-42", "string id ping echo mismatch");
      check(req_field(str_ping, "result").object().empty(),
            "string id ping result not empty");

      const Value str_err = require_reply(
          server.handle_line(
              R"({"jsonrpc":"2.0","id":"err-str-99","method":"no/such","params":{}})"),
          "string id error missing reply");
      check(req_str(str_err, "id") == "err-str-99", "string id error echo mismatch");
      check(req_int(req_field(str_err, "error"), "code") == kJsonRpcMethodNotFound,
            "string id error code mismatch");
    }

    const Value spawned = require_reply(
        server.handle_message(rpc_tool_call(
            112, "platoon_peer_spawn",
            Value::object({
                {"peer_id", Value{"peer-sleep"}},
                {"role", Value{"worker"}},
                {"provider", Value{"openai"}},
                {"model", Value{"gpt-5"}},
                {"prompt", Value{"sleep"}},
                {"extra_env", Value::object({{"MCP_FAKE_PEER_MODE", Value{"sleep"}}})},
            }))),
        "sleep peer spawn missing reply");
    (void)parse_tool_payload(spawned, false);

    // Give sleeper a brief moment to emit PEER_READY before stopping it cleanly.
    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    const Value stopped =
        require_reply(server.handle_message(rpc_tool_call(
                          113, "platoon_peer_stop",
                          Value::object({{"peer_id", Value{"peer-sleep"}},
                                         {"grace_ms", Value{Number{1000}}}}))),
                      "peer stop missing reply");
    const Value stop_payload = parse_tool_payload(stopped, false);
    check(req_str(stop_payload, "state") == "stopped",
          "stopped peer state must be 'stopped'");
  }
}

void test_bounded_line_size_framing() {
  McpCommandPostConfig cfg;
  cfg.max_line_bytes = 256;
  auto opened = McpCommandPostServer::open(std::move(cfg));
  check(opened.has_value(), "bounded-line open failed");
  McpCommandPostServer &server = opened.value();
  check(server.max_line_bytes() == 256, "max_line_bytes accessor mismatch");

  std::string input;
  // Exact max_line_bytes (256) payload followed by \r\n must succeed.
  std::string exact_crlf = R"({"jsonrpc":"2.0","id":10,"method":"ping","params":{}})";
  check(exact_crlf.size() < 256, "base ping unexpectedly long");
  exact_crlf.append(256U - exact_crlf.size(), ' ');
  check(exact_crlf.size() == 256, "exact_crlf must be exact max_line_bytes");
  input += exact_crlf + "\r\n";

  // Oversized line (257 bytes + \n) followed by a valid ping.
  input +=
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + std::string(400, 'x') + "\"}\n";
  input += to_json_line(rpc_request(2, "ping", Value::object({})));

  std::istringstream in{input};
  std::ostringstream out;
  check(server.run_stdio(in, out) == 0, "bounded run_stdio failed");

  const auto replies = split_output_lines(out.str());
  check(replies.size() == 3, "expected exact-CRLF ping + parse error + ping reply");
  check(req_int(replies[0], "id") == 10 &&
            req_field(replies[0], "result").object().empty(),
        "exact max_line_bytes CRLF line must succeed");
  check(req_int(req_field(replies[1], "error"), "code") == kJsonRpcParseError,
        "oversized line must return -32700");
  check(req_int(replies[2], "id") == 2 &&
            req_field(replies[2], "result").object().empty(),
        "valid ping after oversized line must succeed");
}

} // namespace

int main(int argc, char **argv) {
  if (argc > 1 && std::string_view{argv[1]} == "--session")
    return run_fake_peer(argc, argv);
  if (argc > 1 && std::string_view{argv[1]} == "--disable")
    return run_fake_curl();

  try {
    const fs::path self_exe = fs::canonical(argv[0]);
    TempDir temp{"blackbird-mcp-server-test"};

    test_selective_exposure_and_config_validation(temp.path());
    test_full_stdio_roundtrip({temp.path(), self_exe});
    test_bounded_line_size_framing();

    std::cout << "PASS mcp_server\n";
    return 0;
  } catch (const Error &e) {
    std::cerr << "FAIL mcp_server Error: " << error_name(e.code) << " (" << e.detail
              << ")\n";
    return 1;
  } catch (const std::exception &e) {
    std::cerr << "FAIL mcp_server: " << e.what() << '\n';
    return 1;
  }
}
