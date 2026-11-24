#include "blackbird/acp_agent.hpp"
#include "blackbird/json.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <istream>
#include <map>
#include <mutex>
#include <ostream>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace blackbird {
namespace {

constexpr std::size_t kAcpMaxJsonDepth = 128U;
constexpr std::size_t kAcpMaxJsonNodes = 500000U;
constexpr std::size_t kAcpMaxSessions = 256U;
constexpr std::size_t kAcpMaxErrorBytes = 256U;
constexpr std::string_view kSessionIdPrefix = "bb_acp_";

bool is_object(const Value &v) noexcept {
  return std::holds_alternative<Value::Object>(v.value());
}

bool is_array(const Value &v) noexcept {
  return std::holds_alternative<Value::Array>(v.value());
}

bool is_string(const Value &v) noexcept {
  return std::holds_alternative<std::string>(v.value());
}

bool is_null(const Value &v) noexcept {
  return std::holds_alternative<std::nullptr_t>(v.value());
}

bool is_number(const Value &v) noexcept {
  return std::holds_alternative<Number>(v.value());
}

bool valid_rpc_id(const Value &v) noexcept {
  return is_string(v) || is_number(v) || is_null(v);
}

bool has_duplicate_keys(const Value::Object &obj) {
  std::set<std::string_view> seen;
  for (const auto &[k, val] : obj) {
    (void)val;
    if (!seen.insert(k).second)
      return true;
  }
  return false;
}

bool valid_utf8_no_nul(std::string_view text) noexcept {
  return text.find('\0') == std::string_view::npos && valid_utf8(text);
}

std::optional<std::uint64_t> parse_uint64_value(const Value &v) {
  if (!is_number(v))
    return std::nullopt;
  const auto &storage = v.number().storage();
  if (const auto *u = std::get_if<std::uint64_t>(&storage))
    return *u;
  if (const auto *i = std::get_if<std::int64_t>(&storage)) {
    if (*i < 0)
      return std::nullopt;
    return static_cast<std::uint64_t>(*i);
  }
  const std::string text = v.number().text();
  if (text.empty() || text.front() == '-')
    return std::nullopt;
  std::uint64_t parsed = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

// Sanitize internal error messages so secrets/control bytes never leak over JSON-RPC.
std::string sanitize_error_message(std::string_view raw) {
  std::string lower;
  lower.reserve(raw.size());
  for (const char ch : raw) {
    const auto b = static_cast<unsigned char>(ch);
    lower.push_back((b >= 'A' && b <= 'Z') ? static_cast<char>(b - 'A' + 'a')
                                           : static_cast<char>(b));
  }
  static constexpr std::array<std::string_view, 12> secret_markers{
      "mpinv1_",     "mppi1_",     "mprk1_",        "mpdl1_",
      "private key", "secret key", "device_secret", "device_cwt",
      "bearer ",     "sk-ant-",    "ghp_",          "authorization:",
  };
  for (const auto marker : secret_markers) {
    if (lower.find(marker) != std::string::npos)
      return "internal prompt execution error";
  }
  std::string out;
  out.reserve(std::min(raw.size(), kAcpMaxErrorBytes));
  for (const char ch : raw) {
    if (out.size() >= kAcpMaxErrorBytes)
      break;
    const auto byte = static_cast<unsigned char>(ch);
    if (byte >= 0x20U && byte != 0x7FU)
      out.push_back(ch);
    else
      out.push_back(' ');
  }
  if (out.empty())
    return "internal prompt execution error";
  return out;
}

bool valid_session_cwd(std::string_view cwd) noexcept {
  if (cwd.empty() || cwd.size() > 4096U || !valid_utf8_no_nul(cwd))
    return false;
  for (const char ch : cwd) {
    const auto b = static_cast<unsigned char>(ch);
    if (b < 0x20U || b == 0x7FU)
      return false;
  }
  return true;
}

struct JsonRpcErrorSpec {
  std::int64_t code = kAcpJsonRpcInternalError;
  std::string message;
};

Value json_rpc_result(const Value &id, Value result) {
  return Value::object({
      {"jsonrpc", Value{"2.0"}},
      {"id", id},
      {"result", std::move(result)},
  });
}

Value json_rpc_error(const Value &id, JsonRpcErrorSpec err) {
  return Value::object({
      {"jsonrpc", Value{"2.0"}},
      {"id", id},
      {"error", Value::object({
                    {"code", Value{Number{err.code}}},
                    {"message", Value{std::move(err.message)}},
                })},
  });
}

Value json_rpc_notification(std::string_view method, Value params) {
  return Value::object({
      {"jsonrpc", Value{"2.0"}},
      {"method", Value{std::string{method}}},
      {"params", std::move(params)},
  });
}

struct AcpSessionState {
  SessionHandleId id;
  std::string cwd;
  std::shared_ptr<std::atomic<bool>> cancel_flag;
  bool prompt_active = false;
};

AcpPromptResult default_prompt_runner(const AcpPromptRequest &request,
                                      const AcpSessionEmitter &emitter,
                                      const std::atomic<bool> &cancelled) {
  if (cancelled.load(std::memory_order_acquire))
    return {AcpStopReason::cancelled, std::nullopt};
  std::string combined;
  for (const auto &block : request.blocks) {
    if (!combined.empty() && !block.text.empty())
      combined.push_back('\n');
    combined.append(block.text);
  }
  if (!combined.empty())
    emitter.emit_agent_message_chunk(combined);
  if (cancelled.load(std::memory_order_acquire))
    return {AcpStopReason::cancelled, std::nullopt};
  return {AcpStopReason::end_turn, std::nullopt};
}

} // namespace

std::string format_acp_session_id(SessionHandleId id) {
  return std::string{kSessionIdPrefix} + std::to_string(id.value);
}

std::optional<SessionHandleId> parse_acp_session_id(std::string_view wire_id) noexcept {
  if (!wire_id.starts_with(kSessionIdPrefix))
    return std::nullopt;
  const std::string_view digits = wire_id.substr(kSessionIdPrefix.size());
  if (digits.empty() || digits.front() == '0')
    return std::nullopt;
  std::uint64_t parsed = 0U;
  const auto res =
      std::from_chars(digits.data(), digits.data() + digits.size(), parsed);
  if (res.ec != std::errc{} || res.ptr != digits.data() + digits.size() || parsed == 0U)
    return std::nullopt;
  return SessionHandleId{parsed};
}

std::string_view acp_stop_reason_name(AcpStopReason reason) noexcept {
  switch (reason) {
  case AcpStopReason::end_turn:
    return "end_turn";
  case AcpStopReason::cancelled:
    return "cancelled";
  case AcpStopReason::max_tokens:
    return "max_tokens";
  }
  return "end_turn";
}

std::string_view acp_tool_call_status_name(AcpToolCallStatus status) noexcept {
  switch (status) {
  case AcpToolCallStatus::pending:
    return "pending";
  case AcpToolCallStatus::in_progress:
    return "in_progress";
  case AcpToolCallStatus::completed:
    return "completed";
  case AcpToolCallStatus::failed:
    return "failed";
  }
  return "pending";
}

AcpSessionEmitter::AcpSessionEmitter(SessionHandleId session_id,
                                     AcpNotificationSink sink) noexcept
    : session_id_(session_id), sink_(std::move(sink)) {}

void AcpSessionEmitter::emit_update(Value update_obj) const {
  if (!sink_)
    return;
  Value params = Value::object({
      {"sessionId", Value{format_acp_session_id(session_id_)}},
      {"update", std::move(update_obj)},
  });
  sink_(json_rpc_notification("session/update", std::move(params)));
}

void AcpSessionEmitter::emit_agent_message_chunk(std::string_view text) const {
  emit_update(Value::object({
      {"sessionUpdate", Value{"agent_message_chunk"}},
      {"content", Value::object({
                      {"type", Value{"text"}},
                      {"text", Value{std::string{text}}},
                  })},
  }));
}

void AcpSessionEmitter::emit_agent_thought_chunk(std::string_view text) const {
  emit_update(Value::object({
      {"sessionUpdate", Value{"agent_thought_chunk"}},
      {"content", Value::object({
                      {"type", Value{"text"}},
                      {"text", Value{std::string{text}}},
                  })},
  }));
}

void AcpSessionEmitter::emit_tool_call(const AcpToolCallEvent &event) const {
  emit_update(Value::object({
      {"sessionUpdate", Value{"tool_call"}},
      {"toolCallId", Value{"tc_" + std::to_string(event.tool_call_id)}},
      {"title", Value{event.title}},
      {"kind", Value{event.kind}},
      {"status", Value{std::string{acp_tool_call_status_name(event.status)}}},
  }));
}

void AcpSessionEmitter::emit_tool_call_update(
    const AcpToolCallUpdateEvent &event) const {
  Value::Object update{
      {"sessionUpdate", Value{"tool_call_update"}},
      {"toolCallId", Value{"tc_" + std::to_string(event.tool_call_id)}},
      {"status", Value{std::string{acp_tool_call_status_name(event.status)}}},
  };
  if (!event.content.empty()) {
    Value::Array content_arr;
    content_arr.push_back(Value::object({
        {"type", Value{"content"}},
        {"content", Value::object({
                        {"type", Value{"text"}},
                        {"text", Value{event.content}},
                    })},
    }));
    update.emplace_back("content", Value{std::move(content_arr)});
  }
  emit_update(Value::object(std::move(update)));
}

struct AcpAgentServer::Impl {
  std::size_t max_line_bytes = kAcpDefaultMaxLineBytes;
  std::string agent_name{kAcpAgentName};
  std::string agent_version{kAcpAgentVersion};
  AcpPromptRunner prompt_runner;

  mutable std::mutex state_mutex;
  bool initialized = false;
  std::uint64_t next_session_id = 1U;
  std::map<std::uint64_t, AcpSessionState> sessions;

  struct ParsedPromptCall {
    SessionHandleId session_id;
    std::string cwd;
    std::vector<AcpPromptBlock> blocks;
    std::shared_ptr<std::atomic<bool>> cancel_flag;
  };

  Result<ParsedPromptCall> prepare_prompt(const Value &params, std::string &err_out) {
    if (!is_object(params) || has_duplicate_keys(params.object())) {
      err_out = "Invalid params: session/prompt requires a JSON object";
      return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
    }
    const Value *sid_ptr = params.find("sessionId");
    if (sid_ptr == nullptr || !is_string(*sid_ptr)) {
      err_out = "Invalid params: session/prompt requires string sessionId";
      return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
    }
    const auto parsed_sid = parse_acp_session_id(sid_ptr->string());
    if (!parsed_sid.has_value()) {
      err_out = "Invalid params: unknown or malformed sessionId";
      return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
    }

    const Value *prompt_ptr = params.find("prompt");
    if (prompt_ptr == nullptr || !is_array(*prompt_ptr) ||
        prompt_ptr->array().empty()) {
      err_out = "Invalid params: session/prompt requires non-empty prompt array";
      return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
    }

    std::vector<AcpPromptBlock> blocks;
    blocks.reserve(prompt_ptr->array().size());
    for (const Value &item : prompt_ptr->array()) {
      if (!is_object(item) || has_duplicate_keys(item.object())) {
        err_out = "Invalid params: prompt block must be a JSON object";
        return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
      }
      const Value *type_ptr = item.find("type");
      if (type_ptr == nullptr || !is_string(*type_ptr) || type_ptr->string().empty()) {
        err_out = "Invalid params: prompt block requires non-empty type";
        return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
      }
      const std::string &kind = type_ptr->string();
      if (kind == "text") {
        const Value *text_ptr = item.find("text");
        if (text_ptr == nullptr || !is_string(*text_ptr)) {
          err_out = "Invalid params: text prompt block requires string text";
          return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
        }
        blocks.push_back(AcpPromptBlock{kind, text_ptr->string()});
      } else if (kind == "resource") {
        const Value *res_ptr = item.find("resource");
        if (res_ptr == nullptr || !is_object(*res_ptr)) {
          err_out = "Invalid params: resource block requires resource object";
          return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
        }
        const Value *text_ptr = res_ptr->find("text");
        if (text_ptr != nullptr && is_string(*text_ptr)) {
          blocks.push_back(AcpPromptBlock{kind, text_ptr->string()});
        } else {
          blocks.push_back(AcpPromptBlock{kind, {}});
        }
      } else {
        err_out = "Invalid params: unsupported prompt block type";
        return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
      }
    }

    std::lock_guard<std::mutex> lock(state_mutex);
    const auto it = sessions.find(parsed_sid->value);
    if (it == sessions.end()) {
      err_out = "Invalid params: session not found";
      return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
    }
    if (it->second.prompt_active) {
      err_out = "Invalid params: prompt already active for session";
      return Result<ParsedPromptCall>::failure({ErrorCode::invalid_range});
    }
    it->second.prompt_active = true;
    it->second.cancel_flag->store(false, std::memory_order_release);
    return Result<ParsedPromptCall>::success(ParsedPromptCall{
        it->second.id,
        it->second.cwd,
        std::move(blocks),
        it->second.cancel_flag,
    });
  }

  void finish_prompt(SessionHandleId session_id) noexcept {
    std::lock_guard<std::mutex> lock(state_mutex);
    const auto it = sessions.find(session_id.value);
    if (it != sessions.end())
      it->second.prompt_active = false;
  }

  Value execute_prepared_prompt(const Value &id, ParsedPromptCall call,
                                const AcpNotificationSink &sink) {
    struct ActiveGuard {
      Impl *self = nullptr;
      SessionHandleId sid{};
      ~ActiveGuard() {
        if (self != nullptr)
          self->finish_prompt(sid);
      }
    } guard{this, call.session_id};

    AcpPromptRequest req{
        call.session_id,
        std::move(call.cwd),
        std::move(call.blocks),
    };
    AcpSessionEmitter emitter(call.session_id, sink);

    AcpPromptResult result;
    try {
      result = prompt_runner(req, emitter, *call.cancel_flag);
    } catch (const std::exception &ex) {
      return json_rpc_error(
          id, {kAcpJsonRpcInternalError, sanitize_error_message(ex.what())});
    } catch (...) {
      return json_rpc_error(
          id, {kAcpJsonRpcInternalError, "internal prompt execution error"});
    }

    if (result.error_message.has_value()) {
      return json_rpc_error(id, {kAcpJsonRpcInternalError,
                                 sanitize_error_message(*result.error_message)});
    }
    const AcpStopReason final_reason = call.cancel_flag->load(std::memory_order_acquire)
                                           ? AcpStopReason::cancelled
                                           : result.stop_reason;
    return json_rpc_result(
        id, Value::object({{"stopReason",
                            Value{std::string{acp_stop_reason_name(final_reason)}}}}));
  }

  void cancel_all_sessions() noexcept {
    std::lock_guard<std::mutex> lock(state_mutex);
    for (auto &[key, sess] : sessions) {
      (void)key;
      if (sess.cancel_flag != nullptr)
        sess.cancel_flag->store(true, std::memory_order_release);
    }
  }
};

Result<AcpAgentServer> AcpAgentServer::create(AcpAgentConfig config) {
  if (config.max_line_bytes < kAcpMinLineBytes ||
      config.max_line_bytes > kAcpMaxLineBytesLimit) {
    return Result<AcpAgentServer>::failure({ErrorCode::invalid_range});
  }
  if (config.agent_name.empty() || !valid_utf8_no_nul(config.agent_name) ||
      config.agent_version.empty() || !valid_utf8_no_nul(config.agent_version)) {
    return Result<AcpAgentServer>::failure({ErrorCode::invalid_range});
  }

  auto impl = std::make_unique<Impl>();
  impl->max_line_bytes = config.max_line_bytes;
  impl->agent_name = std::move(config.agent_name);
  impl->agent_version = std::move(config.agent_version);
  impl->prompt_runner =
      config.prompt_runner ? std::move(config.prompt_runner) : default_prompt_runner;
  return Result<AcpAgentServer>::success(AcpAgentServer(std::move(impl)));
}

AcpAgentServer::AcpAgentServer(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

AcpAgentServer::AcpAgentServer(AcpAgentServer &&) noexcept = default;
AcpAgentServer &AcpAgentServer::operator=(AcpAgentServer &&) noexcept = default;
AcpAgentServer::~AcpAgentServer() = default;

bool AcpAgentServer::cancel_session(SessionHandleId session_id) noexcept {
  if (!impl_)
    return false;
  std::lock_guard<std::mutex> lock(impl_->state_mutex);
  const auto it = impl_->sessions.find(session_id.value);
  if (it == impl_->sessions.end() || it->second.cancel_flag == nullptr)
    return false;
  it->second.cancel_flag->store(true, std::memory_order_release);
  return true;
}

std::optional<Value> AcpAgentServer::handle_message(const Value &msg,
                                                    const AcpNotificationSink &sink) {
  if (!impl_) {
    return json_rpc_error(Value{nullptr},
                          {kAcpJsonRpcInternalError, "server is not initialized"});
  }
  if (!is_object(msg)) {
    return json_rpc_error(
        Value{nullptr},
        {kAcpJsonRpcInvalidRequest, "Invalid Request: message must be a JSON object"});
  }
  if (has_duplicate_keys(msg.object())) {
    return json_rpc_error(
        Value{nullptr}, {kAcpJsonRpcInvalidRequest, "Invalid Request: duplicate keys"});
  }

  const Value *id_ptr = msg.find("id");
  const bool has_id = (id_ptr != nullptr);
  Value id{nullptr};
  if (has_id) {
    if (!valid_rpc_id(*id_ptr)) {
      return json_rpc_error(Value{nullptr},
                            {kAcpJsonRpcInvalidRequest,
                             "Invalid Request: id must be string, number, or null"});
    }
    id = *id_ptr;
  }

  const Value *ver_ptr = msg.find("jsonrpc");
  if (ver_ptr == nullptr || !is_string(*ver_ptr) || ver_ptr->string() != "2.0") {
    return json_rpc_error(
        id, {kAcpJsonRpcInvalidRequest, "Invalid Request: jsonrpc must be \"2.0\""});
  }

  const Value *method_ptr = msg.find("method");
  if (method_ptr == nullptr || !is_string(*method_ptr) ||
      method_ptr->string().empty()) {
    return json_rpc_error(id, {kAcpJsonRpcInvalidRequest,
                               "Invalid Request: method must be a non-empty string"});
  }
  const std::string_view method = method_ptr->string();

  const Value *params_ptr = msg.find("params");
  if (params_ptr != nullptr && !is_object(*params_ptr) && !is_null(*params_ptr)) {
    if (!has_id)
      return std::nullopt;
    return json_rpc_error(
        id, {kAcpJsonRpcInvalidParams, "Invalid params: params must be an object"});
  }
  if (params_ptr != nullptr && is_object(*params_ptr) &&
      has_duplicate_keys(params_ptr->object())) {
    if (!has_id)
      return std::nullopt;
    return json_rpc_error(id,
                          {kAcpJsonRpcInvalidParams, "Invalid params: duplicate keys"});
  }

  if (method == "session/cancel") {
    if (params_ptr != nullptr && is_object(*params_ptr)) {
      if (const Value *sid_ptr = params_ptr->find("sessionId");
          sid_ptr != nullptr && is_string(*sid_ptr)) {
        const auto parsed_sid = parse_acp_session_id(sid_ptr->string());
        if (parsed_sid.has_value())
          (void)cancel_session(*parsed_sid);
      }
    }
    if (!has_id)
      return std::nullopt;
    return json_rpc_result(id, Value::object({}));
  }

  // Notifications without an id produce no JSON-RPC response.
  if (!has_id)
    return std::nullopt;

  if (method == "initialize") {
    if (params_ptr != nullptr && is_object(*params_ptr)) {
      if (const Value *pv_ptr = params_ptr->find("protocolVersion")) {
        const auto parsed_pv = parse_uint64_value(*pv_ptr);
        if (!parsed_pv.has_value() || *parsed_pv == 0U) {
          return json_rpc_error(
              id, {kAcpJsonRpcInvalidParams,
                   "Invalid params: protocolVersion must be a positive integer"});
        }
      }
    }
    {
      std::lock_guard<std::mutex> lock(impl_->state_mutex);
      impl_->initialized = true;
    }
    return json_rpc_result(
        id, Value::object({
                {"protocolVersion", Value{Number{kAcpProtocolVersion}}},
                {"agentInfo", Value::object({
                                  {"name", Value{impl_->agent_name}},
                                  {"version", Value{impl_->agent_version}},
                              })},
                {"agentCapabilities",
                 Value::object({
                     {"loadSession", Value{false}},
                     {"promptCapabilities", Value::object({
                                                {"image", Value{false}},
                                                {"audio", Value{false}},
                                                {"embeddedContext", Value{true}},
                                            })},
                     {"mcpCapabilities", Value::object({
                                             {"http", Value{true}},
                                             {"sse", Value{false}},
                                         })},
                 })},
            }));
  }

  if (method == "session/new") {
    if (params_ptr == nullptr || !is_object(*params_ptr)) {
      return json_rpc_error(id, {kAcpJsonRpcInvalidParams,
                                 "Invalid params: session/new requires params object"});
    }
    const Value *cwd_ptr = params_ptr->find("cwd");
    if (cwd_ptr == nullptr || !is_string(*cwd_ptr) ||
        !valid_session_cwd(cwd_ptr->string())) {
      return json_rpc_error(id, {kAcpJsonRpcInvalidParams,
                                 "Invalid params: session/new requires valid cwd"});
    }
    if (const Value *mcp_ptr = params_ptr->find("mcpServers");
        mcp_ptr != nullptr && !is_array(*mcp_ptr)) {
      return json_rpc_error(id, {kAcpJsonRpcInvalidParams,
                                 "Invalid params: mcpServers must be an array"});
    }

    SessionHandleId new_id{};
    {
      std::lock_guard<std::mutex> lock(impl_->state_mutex);
      if (impl_->sessions.size() >= kAcpMaxSessions) {
        return json_rpc_error(id, {kAcpJsonRpcInternalError, "session limit reached"});
      }
      new_id = SessionHandleId{impl_->next_session_id++};
      AcpSessionState state{
          new_id,
          cwd_ptr->string(),
          std::make_shared<std::atomic<bool>>(false),
          false,
      };
      impl_->sessions.emplace(new_id.value, std::move(state));
    }
    return json_rpc_result(
        id, Value::object({{"sessionId", Value{format_acp_session_id(new_id)}}}));
  }

  if (method == "session/prompt") {
    if (params_ptr == nullptr || !is_object(*params_ptr)) {
      return json_rpc_error(id,
                            {kAcpJsonRpcInvalidParams,
                             "Invalid params: session/prompt requires params object"});
    }
    std::string err_msg;
    auto prepared = impl_->prepare_prompt(*params_ptr, err_msg);
    if (!prepared.has_value())
      return json_rpc_error(id, {kAcpJsonRpcInvalidParams, std::move(err_msg)});
    return impl_->execute_prepared_prompt(id, std::move(prepared).value(), sink);
  }

  return json_rpc_error(
      id, {kAcpJsonRpcMethodNotFound, "Method not found: " + std::string{method}});
}

std::optional<Value> AcpAgentServer::handle_line(std::string_view line,
                                                 const AcpNotificationSink &sink) {
  if (!impl_) {
    return json_rpc_error(Value{nullptr},
                          {kAcpJsonRpcInternalError, "server is not initialized"});
  }
  if (!line.empty() && line.back() == '\r')
    line.remove_suffix(1);
  if (line.empty())
    return std::nullopt;
  if (line.size() > impl_->max_line_bytes) {
    return json_rpc_error(Value{nullptr}, {kAcpJsonRpcParseError,
                                           "Parse error: line exceeds maximum size"});
  }
  if (!valid_utf8_no_nul(line)) {
    return json_rpc_error(Value{nullptr},
                          {kAcpJsonRpcParseError, "Parse error: invalid UTF-8"});
  }
  const auto parsed =
      parse_json(line, {impl_->max_line_bytes, kAcpMaxJsonNodes, kAcpMaxJsonDepth});
  if (!parsed.has_value()) {
    return json_rpc_error(Value{nullptr},
                          {kAcpJsonRpcParseError, "Parse error: malformed JSON"});
  }
  return handle_message(parsed.value(), sink);
}

int AcpAgentServer::run_stdio(std::istream &in, std::ostream &out) {
  if (!impl_)
    return 1;
  std::streambuf *buf = in.rdbuf();
  if (buf == nullptr)
    return 1;

  std::mutex out_mutex;
  std::atomic<bool> out_failed{false};

  auto emit_frame = [&](const Value &frame) {
    std::lock_guard<std::mutex> lock(out_mutex);
    if (out_failed.load(std::memory_order_acquire))
      return;
    const auto encoded = dump_json(frame);
    if (!encoded.has_value()) {
      const auto fallback = dump_json(
          json_rpc_error(Value{nullptr}, {kAcpJsonRpcInternalError,
                                          "Internal error: encoding failed"}));
      if (!fallback.has_value()) {
        out_failed.store(true, std::memory_order_release);
        return;
      }
      out << fallback.value() << '\n' << std::flush;
    } else {
      out << encoded.value() << '\n' << std::flush;
    }
    if (!out)
      out_failed.store(true, std::memory_order_release);
  };

  struct PromptWorker {
    std::shared_ptr<std::atomic<bool>> done;
    std::thread thread;
  };
  std::vector<PromptWorker> prompt_workers;
  auto reap_finished_workers = [&]() {
    std::size_t write_idx = 0U;
    for (std::size_t i = 0U; i < prompt_workers.size(); ++i) {
      if (prompt_workers[i].done->load(std::memory_order_acquire)) {
        if (prompt_workers[i].thread.joinable())
          prompt_workers[i].thread.join();
      } else {
        if (write_idx != i)
          prompt_workers[write_idx] = std::move(prompt_workers[i]);
        ++write_idx;
      }
    }
    prompt_workers.resize(write_idx);
  };
  auto join_all_workers = [&]() {
    for (auto &worker : prompt_workers) {
      if (worker.thread.joinable())
        worker.thread.join();
    }
    prompt_workers.clear();
  };

  std::string line;
  while (!out_failed.load(std::memory_order_acquire)) {
    line.clear();
    bool saw_any = false;
    bool oversized = false;
    while (true) {
      const int ch = buf->sbumpc();
      if (ch == std::char_traits<char>::eof())
        break;
      saw_any = true;
      if (ch == '\n')
        break;
      if (!oversized) {
        if (line.size() <= impl_->max_line_bytes) {
          line.push_back(static_cast<char>(ch));
        } else {
          oversized = true;
          line.clear();
        }
      }
    }
    if (!saw_any)
      break;

    if (!oversized) {
      if (!line.empty() && line.back() == '\r')
        line.pop_back();
      if (line.size() > impl_->max_line_bytes)
        oversized = true;
    }

    if (oversized) {
      emit_frame(
          json_rpc_error(Value{nullptr}, {kAcpJsonRpcParseError,
                                          "Parse error: line exceeds maximum size"}));
      continue;
    }
    if (line.empty())
      continue;
    if (!valid_utf8_no_nul(line)) {
      emit_frame(json_rpc_error(Value{nullptr},
                                {kAcpJsonRpcParseError, "Parse error: invalid UTF-8"}));
      continue;
    }
    const auto parsed =
        parse_json(line, {impl_->max_line_bytes, kAcpMaxJsonNodes, kAcpMaxJsonDepth});
    if (!parsed.has_value()) {
      emit_frame(json_rpc_error(
          Value{nullptr}, {kAcpJsonRpcParseError, "Parse error: malformed JSON"}));
      continue;
    }

    const Value &msg = parsed.value();
    // Run valid session/prompt requests on a worker thread so session/cancel
    // arriving on a subsequent stdin line can cancel the active prompt cooperatively.
    if (is_object(msg) && !has_duplicate_keys(msg.object())) {
      const Value *ver_ptr = msg.find("jsonrpc");
      const Value *method_ptr = msg.find("method");
      const Value *id_ptr = msg.find("id");
      const Value *params_ptr = msg.find("params");
      if (ver_ptr != nullptr && is_string(*ver_ptr) && ver_ptr->string() == "2.0" &&
          method_ptr != nullptr && is_string(*method_ptr) &&
          method_ptr->string() == "session/prompt" && id_ptr != nullptr &&
          valid_rpc_id(*id_ptr) && params_ptr != nullptr && is_object(*params_ptr)) {
        std::string err_msg;
        auto prepared = impl_->prepare_prompt(*params_ptr, err_msg);
        if (!prepared.has_value()) {
          emit_frame(
              json_rpc_error(*id_ptr, {kAcpJsonRpcInvalidParams, std::move(err_msg)}));
        } else {
          reap_finished_workers();
          Value req_id = *id_ptr;
          auto call_state = std::move(prepared).value();
          auto done_flag = std::make_shared<std::atomic<bool>>(false);
          std::thread worker([this, req_id = std::move(req_id),
                              call_state = std::move(call_state), done_flag,
                              &emit_frame]() mutable {
            Value reply = impl_->execute_prepared_prompt(req_id, std::move(call_state),
                                                         emit_frame);
            emit_frame(reply);
            done_flag->store(true, std::memory_order_release);
          });
          prompt_workers.push_back(
              PromptWorker{std::move(done_flag), std::move(worker)});
        }
        continue;
      }
    }

    const auto reply = handle_message(msg, emit_frame);
    if (reply.has_value())
      emit_frame(*reply);
  }

  // On EOF or stream failure, cooperatively cancel any active turns and join cleanly.
  impl_->cancel_all_sessions();
  join_all_workers();
  return out_failed.load(std::memory_order_acquire) ? 1 : 0;
}

std::size_t AcpAgentServer::max_line_bytes() const noexcept {
  return impl_ ? impl_->max_line_bytes : 0U;
}

std::size_t AcpAgentServer::session_count() const noexcept {
  if (!impl_)
    return 0U;
  std::lock_guard<std::mutex> lock(impl_->state_mutex);
  return impl_->sessions.size();
}

bool AcpAgentServer::has_session(SessionHandleId session_id) const noexcept {
  if (!impl_)
    return false;
  std::lock_guard<std::mutex> lock(impl_->state_mutex);
  return impl_->sessions.contains(session_id.value);
}

} // namespace blackbird
