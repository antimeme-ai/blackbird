#include "blackbird/acp_agent.hpp"
#include "blackbird/json.hpp"
#include "blackbird/value.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace blackbird;

namespace {

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

const Value &req_opt(const std::optional<Value> &opt, const char *message) {
  if (!opt.has_value())
    throw std::runtime_error(message);
  return *opt;
}

const Value &req_field(const Value &obj, std::string_view key) {
  const Value *found = obj.find(key);
  check(found != nullptr, "missing expected JSON field");
  return *found;
}

const std::string &req_str(const Value &obj, std::string_view key) {
  const Value &v = req_field(obj, key);
  check(std::holds_alternative<std::string>(v.value()), "expected JSON string field");
  return v.string();
}

std::int64_t req_i64(const Value &obj, std::string_view key) {
  const Value &v = req_field(obj, key);
  check(std::holds_alternative<Number>(v.value()), "expected JSON number field");
  const auto &storage = v.number().storage();
  if (const auto *i = std::get_if<std::int64_t>(&storage))
    return *i;
  if (const auto *u = std::get_if<std::uint64_t>(&storage))
    return static_cast<std::int64_t>(*u);
  throw std::runtime_error("expected integer JSON number field");
}

// Thread-safe pipe streambuf so run_stdio can receive session/cancel mid-prompt.
class BlockingPipeBuf : public std::streambuf {
public:
  void push(std::string_view data) {
    {
      std::lock_guard<std::mutex> lock(mu_);
      buf_.append(data);
    }
    cv_.notify_one();
  }

  void close() {
    {
      std::lock_guard<std::mutex> lock(mu_);
      eof_ = true;
    }
    cv_.notify_all();
  }

protected:
  int_type underflow() override {
    std::unique_lock<std::mutex> lock(mu_);
    cv_.wait(lock, [&]() { return pos_ < buf_.size() || eof_; });
    if (pos_ >= buf_.size())
      return traits_type::eof();
    current_ = buf_[pos_];
    setg(&current_, &current_, &current_ + 1);
    return traits_type::to_int_type(current_);
  }

  int_type uflow() override {
    std::unique_lock<std::mutex> lock(mu_);
    cv_.wait(lock, [&]() { return pos_ < buf_.size() || eof_; });
    if (pos_ >= buf_.size())
      return traits_type::eof();
    current_ = buf_[pos_++];
    setg(&current_, &current_ + 1, &current_ + 1);
    return traits_type::to_int_type(current_);
  }

private:
  std::mutex mu_;
  std::condition_variable cv_;
  std::string buf_;
  std::size_t pos_ = 0U;
  bool eof_ = false;
  char current_ = '\0';
};

void test_session_id_roundtrip() {
  check(format_acp_session_id(SessionHandleId{1U}) == "bb_acp_1",
        "unexpected session id format");
  check(format_acp_session_id(SessionHandleId{42U}) == "bb_acp_42",
        "unexpected session id format for 42");
  const auto parsed = parse_acp_session_id("bb_acp_42");
  check(parsed.has_value() && parsed->value == 42U, "failed to parse valid sessionId");
  check(!parse_acp_session_id("bb_acp_0").has_value(),
        "zero sessionId must be rejected");
  check(!parse_acp_session_id("bb_acp_01").has_value(),
        "leading-zero sessionId must be rejected");
  check(!parse_acp_session_id("other_1").has_value(), "wrong prefix must be rejected");
  check(!parse_acp_session_id("bb_acp_1x").has_value(),
        "trailing garbage must be rejected");
}

void test_initialize_new_and_streaming_prompt() {
  AcpAgentConfig cfg{};
  cfg.prompt_runner = [](const AcpPromptRequest &req, const AcpSessionEmitter &emitter,
                         const std::atomic<bool> &cancelled) -> AcpPromptResult {
    check(req.session_id.value == 1U, "expected integer session PK 1");
    check(req.cwd == "/tmp/workspace", "expected session cwd");
    check(req.blocks.size() == 1U && req.blocks[0].text == "ping",
          "expected prompt text");
    check(!cancelled.load(), "expected uncancelled prompt");

    emitter.emit_tool_call(
        {10U, "Read README.md", "read", AcpToolCallStatus::in_progress});
    emitter.emit_tool_call_update({10U, AcpToolCallStatus::completed, "README OK"});
    emitter.emit_agent_message_chunk("Hello ");
    emitter.emit_agent_message_chunk("world");
    return {AcpStopReason::end_turn, std::nullopt};
  };

  auto server_res = AcpAgentServer::create(std::move(cfg));
  check(server_res.has_value(), "AcpAgentServer::create failed");
  AcpAgentServer server = std::move(server_res).value();

  std::vector<Value> notes;
  auto sink = [&](const Value &n) { notes.push_back(n); };

  // 1. initialize
  const auto init_reply = server.handle_line(
      R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{},"clientInfo":{"name":"zed","version":"0.1.0"}}})",
      sink);
  const Value &init_res =
      req_field(req_opt(init_reply, "expected initialize reply"), "result");
  check(req_i64(init_res, "protocolVersion") == 1, "expected protocolVersion 1");
  check(req_str(req_field(init_res, "agentInfo"), "name") == "blackbird",
        "expected agentInfo.name == blackbird");
  check(init_res.find("agentCapabilities") != nullptr, "expected agentCapabilities");

  // 2. session/new
  const auto new_reply = server.handle_line(
      R"({"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/tmp/workspace","mcpServers":[]}})",
      sink);
  const std::string sid =
      req_str(req_field(req_opt(new_reply, "expected session/new reply"), "result"),
              "sessionId");
  check(sid == "bb_acp_1", "expected bb_acp_1");
  check(server.session_count() == 1U, "expected 1 active session");
  check(server.has_session(SessionHandleId{1U}), "expected session handle 1");

  // 3. session/prompt with streaming tool_call + tool_call_update + agent_message_chunk
  const auto prompt_reply = server.handle_line(
      R"({"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"bb_acp_1","prompt":[{"type":"text","text":"ping"}]}})",
      sink);
  check(req_str(
            req_field(req_opt(prompt_reply, "expected session/prompt reply"), "result"),
            "stopReason") == "end_turn",
        "expected end_turn stopReason");

  check(notes.size() == 4U, "expected 4 session/update notifications");
  for (const auto &n : notes) {
    check(req_str(n, "method") == "session/update", "expected session/update method");
    check(req_str(req_field(n, "params"), "sessionId") == "bb_acp_1",
          "expected sessionId in notification");
  }
  check(req_str(req_field(req_field(notes[0], "params"), "update"), "sessionUpdate") ==
            "tool_call",
        "expected tool_call update");
  check(req_str(req_field(req_field(notes[1], "params"), "update"), "sessionUpdate") ==
            "tool_call_update",
        "expected tool_call_update update");
  check(req_str(req_field(req_field(notes[2], "params"), "update"), "sessionUpdate") ==
            "agent_message_chunk",
        "expected first agent_message_chunk");
  check(
      req_str(req_field(req_field(req_field(notes[2], "params"), "update"), "content"),
              "text") == "Hello ",
      "expected first chunk text");
  check(
      req_str(req_field(req_field(req_field(notes[3], "params"), "update"), "content"),
              "text") == "world",
      "expected second chunk text");
}

void test_cancel_mid_prompt_over_stdio() {
  std::mutex ready_mu;
  std::condition_variable ready_cv;
  bool prompt_started = false;

  AcpAgentConfig cfg{};
  cfg.prompt_runner = [&](const AcpPromptRequest &req, const AcpSessionEmitter &emitter,
                          const std::atomic<bool> &cancelled) -> AcpPromptResult {
    (void)req;
    emitter.emit_agent_message_chunk("working...");
    {
      std::lock_guard<std::mutex> lock(ready_mu);
      prompt_started = true;
    }
    ready_cv.notify_one();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!cancelled.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return {cancelled.load(std::memory_order_acquire) ? AcpStopReason::cancelled
                                                      : AcpStopReason::end_turn,
            std::nullopt};
  };

  auto server_res = AcpAgentServer::create(std::move(cfg));
  check(server_res.has_value(), "AcpAgentServer::create failed");
  AcpAgentServer server = std::move(server_res).value();

  BlockingPipeBuf pipe_buf;
  std::istream in(&pipe_buf);
  std::ostringstream out;

  int exit_code = -1;
  std::thread runner([&]() { exit_code = server.run_stdio(in, out); });

  pipe_buf.push("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
                "\"protocolVersion\":1}}\n"
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"session/"
                "new\",\"params\":{\"cwd\":\"/tmp/ws\",\"mcpServers\":[]}}\n"
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"session/"
                "prompt\",\"params\":{\"sessionId\":\"bb_acp_1\",\"prompt\":[{\"type\":"
                "\"text\",\"text\":\"long task\"}]}}\n");

  {
    std::unique_lock<std::mutex> lock(ready_mu);
    const bool ok = ready_cv.wait_for(lock, std::chrono::seconds{5},
                                      [&]() { return prompt_started; });
    check(ok, "prompt did not start in time");
  }

  // Send cooperative session/cancel notification while session/prompt is blocked.
  pipe_buf.push("{\"jsonrpc\":\"2.0\",\"method\":\"session/"
                "cancel\",\"params\":{\"sessionId\":\"bb_acp_1\"}}\n");
  // Close stdin after a brief pause to verify clean EOF shutdown.
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  pipe_buf.close();

  runner.join();
  check(exit_code == 0, "expected clean EOF exit code 0");

  std::istringstream lines(out.str());
  std::string line;
  bool saw_chunk = false;
  bool saw_cancelled = false;
  while (std::getline(lines, line)) {
    if (line.empty())
      continue;
    const auto parsed = parse_json(line);
    check(parsed.has_value(), "invalid JSON emitted on stdout");
    const Value &obj = parsed.value();
    if (const Value *m = obj.find("method");
        m != nullptr && std::holds_alternative<std::string>(m->value()) &&
        m->string() == "session/update") {
      saw_chunk = true;
    }
    if (const Value *id = obj.find("id"); id != nullptr &&
                                          std::holds_alternative<Number>(id->value()) &&
                                          req_i64(obj, "id") == 3) {
      check(req_str(req_field(obj, "result"), "stopReason") == "cancelled",
            "expected stopReason == cancelled");
      saw_cancelled = true;
    }
  }
  check(saw_chunk, "expected streamed chunk before cancel");
  check(saw_cancelled, "expected cancelled prompt reply");
}

void test_errors_bounds_and_secret_hygiene() {
  AcpAgentConfig cfg{};
  cfg.max_line_bytes = 256U;
  cfg.prompt_runner = [](const AcpPromptRequest &, const AcpSessionEmitter &,
                         const std::atomic<bool> &) -> AcpPromptResult {
    return {
        AcpStopReason::end_turn,
        std::string{"leaked token mpinv1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}};
  };
  auto server_res = AcpAgentServer::create(std::move(cfg));
  check(server_res.has_value(), "create failed");
  AcpAgentServer server = std::move(server_res).value();
  auto noop_sink = [](const Value &) {};

  // Malformed JSON -> -32700
  const auto bad_json = server.handle_line("{bad json", noop_sink);
  check(req_i64(req_field(req_opt(bad_json, "expected parse error"), "error"),
                "code") == kAcpJsonRpcParseError,
        "expected -32700 for malformed JSON");

  // Oversized line -> -32700 (both direct handle_line and run_stdio draining)
  const std::string huge(512U, 'x');
  const auto big_reply = server.handle_line(huge, noop_sink);
  check(
      req_i64(req_field(req_opt(big_reply, "expected oversized parse error"), "error"),
              "code") == kAcpJsonRpcParseError,
      "expected -32700 for oversized line");

  // Invalid UTF-8 -> -32700
  const std::string bad_utf8{"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"\xFF\"}"};
  const auto utf8_reply = server.handle_line(bad_utf8, noop_sink);
  check(req_i64(req_field(req_opt(utf8_reply, "expected utf-8 parse error"), "error"),
                "code") == kAcpJsonRpcParseError,
        "expected -32700 for invalid UTF-8");

  // Invalid Request (missing jsonrpc 2.0) -> -32600
  const auto bad_req =
      server.handle_line(R"({"id":1,"method":"initialize"})", noop_sink);
  check(req_i64(req_field(req_opt(bad_req, "expected invalid request error"), "error"),
                "code") == kAcpJsonRpcInvalidRequest,
        "expected -32600");

  // Unknown method -> -32601
  const auto unknown_m = server.handle_line(
      R"({"jsonrpc":"2.0","id":2,"method":"unknown/op"})", noop_sink);
  check(req_i64(req_field(req_opt(unknown_m, "expected method not found"), "error"),
                "code") == kAcpJsonRpcMethodNotFound,
        "expected -32601");

  // Unknown session -> -32602
  const auto unknown_s = server.handle_line(
      R"({"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"bb_acp_999","prompt":[{"type":"text","text":"hi"}]}})",
      noop_sink);
  check(req_i64(req_field(req_opt(unknown_s, "expected unknown session invalid params"),
                          "error"),
                "code") == kAcpJsonRpcInvalidParams,
        "expected -32602 for unknown session");

  // Control characters in session/new cwd must be rejected (-32602)
  const auto bad_cwd = server.handle_line(
      R"({"jsonrpc":"2.0","id":40,"method":"session/new","params":{"cwd":"/tmp/bad\ncwd"}})",
      noop_sink);
  check(req_i64(req_field(req_opt(bad_cwd, "expected bad cwd error"), "error"),
                "code") == kAcpJsonRpcInvalidParams,
        "expected -32602 for control chars in cwd");

  // Secret leakage in prompt error must be scrubbed (case-insensitive)
  const auto snew = server.handle_line(
      R"({"jsonrpc":"2.0","id":4,"method":"session/new","params":{"cwd":"/tmp"}})",
      noop_sink);
  check(snew.has_value(), "expected session/new reply");
  const auto sec_reply = server.handle_line(
      R"({"jsonrpc":"2.0","id":5,"method":"session/prompt","params":{"sessionId":"bb_acp_1","prompt":[{"type":"text","text":"boom"}]}})",
      noop_sink);
  const Value &sec_err =
      req_field(req_opt(sec_reply, "expected internal error reply"), "error");
  check(req_i64(sec_err, "code") == kAcpJsonRpcInternalError, "expected -32603");
  const std::string &err_msg = req_str(sec_err, "message");
  check(err_msg.find("mpinv1_") == std::string::npos,
        "secret token must NEVER leak into JSON-RPC error message");

  // Oversized line followed by valid line over run_stdio
  std::istringstream stdio_in(huge +
                              "\n{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":"
                              "\"initialize\",\"params\":{\"protocolVersion\":1}}\n");
  std::ostringstream stdio_out;
  check(server.run_stdio(stdio_in, stdio_out) == 0,
        "expected clean EOF after oversized line");
  std::istringstream out_lines(stdio_out.str());
  std::string l1;
  std::string l2;
  check(static_cast<bool>(std::getline(out_lines, l1)), "expected first error line");
  check(static_cast<bool>(std::getline(out_lines, l2)),
        "expected second init reply line");
  const auto p1 = parse_json(l1);
  const auto p2 = parse_json(l2);
  check(p1.has_value() &&
            req_i64(req_field(p1.value(), "error"), "code") == kAcpJsonRpcParseError,
        "expected -32700 on oversized stdio frame");
  check(p2.has_value() &&
            req_i64(req_field(p2.value(), "result"), "protocolVersion") == 1,
        "expected server to recover cleanly on next frame");
}

} // namespace

int main() {
  try {
    test_session_id_roundtrip();
    test_initialize_new_and_streaming_prompt();
    test_cancel_mid_prompt_over_stdio();
    test_errors_bounds_and_secret_hygiene();
    std::cout << "acp_agent_test: all checks passed\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "acp_agent_test FAILED: " << ex.what() << '\n';
    return 1;
  }
}
