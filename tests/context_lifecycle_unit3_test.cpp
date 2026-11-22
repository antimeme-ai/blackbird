#include "blackbird/anthropic_provider.hpp"
#include "blackbird/coding.hpp"
#include "blackbird/context.hpp"
#include "blackbird/json.hpp"
#include "blackbird/openai.hpp"
#include "blackbird/openrouter.hpp"
#include "blackbird/provider_auth.hpp"
#include "blackbird/responses_provider.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

using namespace blackbird;
namespace {
void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
template <class T> T make_id(unsigned char n) {
  IdentityBytes bytes{};
  bytes[0] = std::byte{n};
  return unwrap(T::from_bytes(bytes));
}
struct TempDir {
  std::filesystem::path path;
  explicit TempDir(const char *prefix) {
    std::string pattern = std::string{"/tmp/"} + prefix + "-XXXXXX";
    char *created = ::mkdtemp(pattern.data());
    require(created != nullptr, "mkdtemp failed");
    path = created;
  }
  ~TempDir() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};
std::unique_ptr<RetainedState> make_state(const std::filesystem::path &dir,
                                          unsigned char seed) {
  const JournalHeader header{
      make_id<EnvironmentId>(seed),
      make_id<AuditStreamId>(static_cast<unsigned char>(seed + 1)),
      1,
      {8 * 1024 * 1024, 24 * 1024 * 1024},
      std::nullopt};
  return unwrap(RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                          NativeJournalDirectory::open(dir.string()))),
                                      "audit", header, {64 * 1024 * 1024, 10000}));
}
Value assistant_reply(std::string text) {
  return Value::object(
      {{"output", Value{Value::Array{Value::object(
                      {{"type", Value{"message"}},
                       {"role", Value{"assistant"}},
                       {"content", Value{Value::Array{Value::object(
                                       {{"type", Value{"output_text"}},
                                        {"text", Value{std::move(text)}}})}}}})}}}});
}

void test_lua_time_and_error_text() {
  TempDir dir{"bb-u3-lua"};
  auto root = make_state(dir.path, 21);
  AuditLog log{*root};
  ContextStore context{log};
  struct DummyProvider final : public CodingProvider {
    Value respond(const Value &,
                  const std::function<void(std::string_view)> &) override {
      throw std::runtime_error("unexpected provider call");
    }
  } provider;
  CodingEngine engine{log, context, provider, "test-model"};

  const auto time_res = engine.operator_call("lua", Value::object({{"code", Value{R"(
        assert(type(os) == 'table', 'os table missing')
        assert(type(os.time()) == 'number' and os.time() > 1700000000, 'os.time invalid')
        assert(type(os.clock()) == 'number' and os.clock() >= 0, 'os.clock invalid')
        assert(os.difftime(100, 40) == 60, 'os.difftime invalid')
        assert(os.execute == nil and os.remove == nil and os.getenv == nil, 'unsafe os leaked')
        local now = blackbird.now()
        assert(type(now.epoch_ms) == 'number' and type(now.monotonic_ms) == 'number', 'blackbird.now invalid')
        return 'OK_TIME'
      )"}}}));
  require(time_res == Value{"OK_TIME"}, "safe Lua time helpers must work");

  const auto err_res = engine.operator_call(
      "lua", Value::object({{"code", Value{"return nonexistent_tbl.field"}}}));
  const auto dumped = unwrap(dump_json(err_res));
  require(dumped.find("nonexistent_tbl") != std::string::npos,
          "Lua error must include lua_error message text");

  // Subsequent invalid lua call must NOT leak the previous call's lua_error.
  const auto bad_arg = engine.operator_call("lua", Value::object({}));
  require(bad_arg.find("lua_error") == nullptr,
          "stale lua_error must not leak onto unrelated lua error");

  // Overflow classifier must reject non-context parameter errors.
  require(!is_context_overflow_text("max_output_tokens exceeds the maximum allowed"),
          "parameter error must not false-positive as context overflow");
  require(is_context_overflow_text("maximum context length exceeded"),
          "real context length error must classify as overflow");
  require(is_context_overflow_text("input tokens exceed limit"),
          "tokens exceed error must classify as overflow");
}

void test_max_output_tokens_preserved() {
  const std::string openai_sse =
      "data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_trunc\","
      "\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":"
      "\"max_output_tokens\"},\"output\":[{\"id\":\"msg_1\",\"type\":\"message\","
      "\"role\":\"assistant\",\"status\":\"incomplete\",\"content\":[{\"type\":"
      "\"output_text\",\"text\":\"PARTIAL_SAVED_REPLY\"}]}],\"usage\":{"
      "\"input_tokens\":10,\"output_tokens\":20}}}\n\n";
  const std::string or_sse = openai_sse + "data: [DONE]\n\n";
  const auto openai_res = completed_response(openai_sse);
  require(openai_res.has_value(),
          "OpenAI completed_response must preserve max_output_tokens partial reply");
  require(unwrap(dump_json(openai_res.value())).find("PARTIAL_SAVED_REPLY") !=
              std::string::npos,
          "OpenAI partial text preserved");

  const auto or_res = openrouter_completed_response(or_sse);
  require(
      or_res.has_value(),
      "OpenRouter completed_response must preserve max_output_tokens partial reply");
  require(unwrap(dump_json(or_res.value())).find("PARTIAL_SAVED_REPLY") !=
              std::string::npos,
          "OpenRouter partial text preserved");

  // Bare response.incomplete (without valid max_output_tokens output) must still fail.
  const std::string bare_openai = "data: {\"type\":\"response.incomplete\"}\n\n";
  const std::string bare_or = bare_openai + "data: [DONE]\n\n";
  require(!completed_response(bare_openai).has_value() &&
              completed_response(bare_openai).error().code == ErrorCode::incomplete,
          "bare OpenAI response.incomplete must still fail");
  require(!openrouter_completed_response(bare_or).has_value() &&
              openrouter_completed_response(bare_or).error().code ==
                  ErrorCode::incomplete,
          "bare OpenRouter response.incomplete must still fail");

  // Truncated function_call must NOT be accepted.
  const std::string bad_call_openai =
      "data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_bad\","
      "\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":"
      "\"max_output_tokens\"},\"output\":[{\"id\":\"fc_1\",\"type\":\"function_call\","
      "\"status\":\"incomplete\",\"call_id\":\"c1\",\"name\":\"exec\","
      "\"arguments\":\"{\\\"cmd\\\":\"}]}}\n\n";
  const std::string bad_call_or = bad_call_openai + "data: [DONE]\n\n";
  require(!completed_response(bad_call_openai).has_value() &&
              completed_response(bad_call_openai).error().code == ErrorCode::incomplete,
          "incomplete function_call must not be accepted");
  require(!openrouter_completed_response(bad_call_or).has_value() &&
              openrouter_completed_response(bad_call_or).error().code ==
                  ErrorCode::incomplete,
          "OpenRouter incomplete function_call must not be accepted");
}

void test_foreign_reasoning_projection() {
  TempDir dir{"bb-u3-rebind"};
  auto root = make_state(dir.path, 31);
  AuditLog log{*root};
  ContextStore context{log};
  context.append(
      {Value::object({{"role", Value{"user"}}, {"content", Value{"hello"}}})}, "u1");
  context.append(
      {Value::object({{"type", Value{"reasoning"}},
                      {"anthropic_message_id", Value{"msg_claude_1"}},
                      {"anthropic_content",
                       Value::object({{"type", Value{"thinking"}},
                                      {"thinking", Value{"internal plan"}},
                                      {"signature", Value{"sig_opaque_123"}}})},
                      {"summary", Value{Value::Array{}}}}),
       Value::object(
           {{"role", Value{"assistant"}}, {"content", Value{"from claude"}}})},
      "a1");
  context.append({Value::object({{"type", Value{"reasoning"}},
                                 {"encrypted_content", Value{"opaque-openai=="}},
                                 {"summary", Value{Value::Array{}}}}),
                  Value::object({{"role", Value{"assistant"}},
                                 {"content", Value{"from openai"}}})},
                 "a2");

  struct ExportingOpenAiProvider final : public CodingProvider {
    std::string_view provider_identity() const noexcept override {
      return "openrouter-responses";
    }
    Value respond(const Value &request,
                  const std::function<void(std::string_view)> &capture) override {
      (void)export_openrouter_request(request);
      auto resp = assistant_reply("ok-openrouter");
      capture(unwrap(dump_json(resp)));
      return resp;
    }
  } or_provider;
  CodingEngine engine{log, context, or_provider, "deepseek/deepseek-v4.1-flash"};
  engine.turn({.prompt = "switch to deepseek", .program = "blackbird.request()"});
  const auto stored = unwrap(dump_json(Value{context.items()}));
  require(stored.find("anthropic_content") != std::string::npos &&
              stored.find("encrypted_content") != std::string::npos,
          "originals must not be mutated by OpenRouter wire projection");

  struct ExportingPortableResponsesProvider final : public CodingProvider {
    std::string_view provider_identity() const noexcept override { return "deepseek"; }
    Value respond(const Value &request,
                  const std::function<void(std::string_view)> &capture) override {
      (void)export_registered_responses_request(request, true);
      auto resp = assistant_reply("ok-portable");
      capture(unwrap(dump_json(resp)));
      return resp;
    }
  } portable_provider;
  CodingEngine portable_engine{log, context, portable_provider, "deepseek-chat"};
  portable_engine.effort("low");
  portable_engine.turn(
      {.prompt = "switch to portable", .program = "blackbird.request()"});

  struct RecordingAnthropicProvider final : public CodingProvider {
    std::string_view provider_identity() const noexcept override {
      return "anthropic-messages";
    }
    Value last_request;
    Value respond(const Value &request,
                  const std::function<void(std::string_view)> &capture) override {
      last_request = request;
      (void)export_anthropic_request(request, 4096, false);
      auto resp = assistant_reply("ok-anthropic");
      capture(unwrap(dump_json(resp)));
      return resp;
    }
  } anth_provider;
  CodingEngine anth_engine{log, context, anth_provider, "claude-opus-4-6"};
  anth_engine.turn(
      {.prompt = "switch back to claude", .program = "blackbird.request()"});
  const auto anth_input = unwrap(dump_json(field(anth_provider.last_request, "input")));
  require(anth_input.find("anthropic_content") != std::string::npos,
          "Anthropic target keeps native anthropic reasoning");
  require(anth_input.find("encrypted_content") == std::string::npos,
          "Anthropic target drops foreign OpenAI reasoning");
}

void test_mid_turn_cut_and_epoch_key() {
  TempDir dir{"bb-u3-epoch"};
  auto root = make_state(dir.path, 41);
  AuditLog log{*root};
  ContextStore context{log};
  context.append({Value::object({{"role", Value{"assistant"}},
                                 {"content", Value{"OLD_PAYLOAD_ALPHA"}}})},
                 "provider.branch:seed1", UnitClass::result);
  context.append({Value::object({{"role", Value{"assistant"}},
                                 {"content", Value{"KEEP_PAYLOAD_BETA"}}})},
                 "provider.branch:seed2", UnitClass::result);

  struct KeyProvider final : public CodingProvider {
    bool supports_prompt_cache_key() const noexcept override { return true; }
    std::vector<Value> requests;
    Value respond(const Value &request,
                  const std::function<void(std::string_view)> &capture) override {
      requests.push_back(request);
      auto resp = assistant_reply("step-" + std::to_string(requests.size()));
      capture(unwrap(dump_json(resp)));
      return resp;
    }
  } provider;

  CodingEngine engine{log, context, provider, "test-model"};
  engine.turn({.prompt = "run multi-step", .program = R"(
                 blackbird.request()
                 local u = blackbird.call('context_units', {})
                 assert(u.upstream_epoch == 0, 'expected epoch 0 initially')
                 local alpha_id = nil
                 local alpha_handle = nil
                 local view = blackbird.context()
                 for _, e in ipairs(view.entries) do
                   if e.item.content == 'OLD_PAYLOAD_ALPHA' then alpha_id = e.id end
                 end
                 for _, unit in ipairs(u.units) do
                   for _, id in ipairs(unit.ids) do
                     if id == alpha_id then alpha_handle = unit.handle end
                   end
                 end
                 assert(alpha_id and alpha_handle, 'alpha unit missing')
                 -- Pin then unpin via tools to verify both work end-to-end.
                 local p = blackbird.call('context_pin', {selection = alpha_handle})
                 assert(p.pinned == 1, 'pin failed')
                 local up = blackbird.call('context_unpin', {selection = alpha_handle})
                 assert(up.pinned == 0, 'unpin failed')
                 -- Mid-turn immediate cut.
                 local cut = blackbird.call('context_manage', {
                   apply = 'now',
                   proposal = {
                     mode = 'archive',
                     ids = {alpha_id},
                     reason = 'mid-turn-shrink',
                     source = 'unit3-test'
                   }
                 })
                 assert(cut.accepted == true, 'immediate cut must accept')
                 assert(cut.applied == 'now', 'applied flag must be now')
                 assert(cut.upstream_epoch == 1, 'epoch must advance to 1')
                 blackbird.request()
               )"});

  require(provider.requests.size() == 2, "expected 2 provider requests");
  const auto key0 = string_field(provider.requests[0], "prompt_cache_key");
  const auto key1 = string_field(provider.requests[1], "prompt_cache_key");
  require(key0.find(":e") == std::string::npos,
          "epoch 0 key keeps exact conversation hex");
  require(key1 == key0 + ":e1", "epoch 1 key must append :e1");
  const auto input0 = unwrap(dump_json(field(provider.requests[0], "input")));
  const auto input1 = unwrap(dump_json(field(provider.requests[1], "input")));
  require(input0.find("OLD_PAYLOAD_ALPHA") != std::string::npos,
          "request 0 includes alpha before cut");
  require(input1.find("OLD_PAYLOAD_ALPHA") == std::string::npos,
          "request 1 omits alpha after mid-turn cut");
  require(input1.find("KEEP_PAYLOAD_BETA") != std::string::npos,
          "request 1 retains beta");
  require(unwrap(dump_json(context.originals())).find("OLD_PAYLOAD_ALPHA") !=
              std::string::npos,
          "archived original must remain recoverable");

  const auto units_res = engine.operator_call("context_units", Value::object({}));
  require(units_res.find("revision") != nullptr && units_res.find("base") == nullptr &&
              units_res.find("note") != nullptr,
          "context_units exposes revision + note without misleading base key");

  // Also verify model function_call -> context_manage(apply="now") through turn.lua:
  // with an open tool call, commit defers cleanly until tool output appends, then
  // activates automatically before the very next provider request in the same turn.
  const auto beta_id = [&]() -> std::string {
    for (const auto &entry : field(context.view(), "entries").array()) {
      const auto &item = field(entry, "item");
      if (const auto *c = item.find("content"); c && *c == Value{"KEEP_PAYLOAD_BETA"})
        return string_field(entry, "id");
    }
    return {};
  }();
  require(!beta_id.empty(), "beta entry id missing");

  struct ModelToolCutProvider final : public CodingProvider {
    std::string target_id;
    bool supports_prompt_cache_key() const noexcept override { return true; }
    std::vector<Value> requests;
    Value respond(const Value &request,
                  const std::function<void(std::string_view)> &capture) override {
      requests.push_back(request);
      Value resp;
      if (requests.size() == 1) {
        const auto args = unwrap(dump_json(Value::object(
            {{"apply", Value{"now"}},
             {"proposal", Value::object({{"mode", Value{"archive"}},
                                         {"ids", Value{Value::Array{Value{target_id}}}},
                                         {"reason", Value{"model-tool-cut"}},
                                         {"source", Value{"unit3-model"}}})}})));
        resp = Value::object(
            {{"output",
              Value{Value::Array{Value::object({{"type", Value{"function_call"}},
                                                {"call_id", Value{"call_cut_1"}},
                                                {"name", Value{"context_manage"}},
                                                {"arguments", Value{args}}})}}}});
      } else {
        resp = assistant_reply("done-after-model-cut");
      }
      capture(unwrap(dump_json(resp)));
      return resp;
    }
  } tool_provider;
  tool_provider.target_id = beta_id;

  std::filesystem::path turn_path{"programs/turn.lua"};
  if (!std::filesystem::exists(turn_path))
    turn_path = "../../programs/turn.lua";
  std::ifstream turn_file{turn_path};
  require(turn_file.good(), "programs/turn.lua readable");
  std::ostringstream turn_buf;
  turn_buf << turn_file.rdbuf();
  CodingEngine tool_engine{log, context, tool_provider, "test-model"};
  const auto epoch_before = tool_engine.upstream_epoch();
  require(epoch_before >= 1,
          "reopened engine must reconstruct epoch from committed cuts");
  tool_engine.turn({.prompt = "compact via tool call", .program = turn_buf.str()});
  require(tool_provider.requests.size() == 2, "expected 2 tool-turn requests");
  const auto tkey0 = string_field(tool_provider.requests[0], "prompt_cache_key");
  const auto tkey1 = string_field(tool_provider.requests[1], "prompt_cache_key");
  require(tkey0 != tkey1 && tkey1.ends_with(":e" + std::to_string(epoch_before + 1)),
          "model tool context_manage(apply=now) must roll epoch before next request");
  require(
      unwrap(dump_json(field(tool_provider.requests[1], "input")))
              .find("KEEP_PAYLOAD_BETA") == std::string::npos,
      "model tool context_manage(apply=now) must omit archived entry on next request");
}

void test_cold_cache_free_flush() {
  TempDir dir{"bb-u3-cold"};
  auto root = make_state(dir.path, 51);
  AuditLog log{*root};
  ContextStore context{log};
  context.append({Value::object({{"role", Value{"assistant"}},
                                 {"content", Value{"STAGED_DROP_TARGET"}}})},
                 "provider.branch:seed1", UnitClass::result);

  struct ColdProvider final : public CodingProvider {
    CodingEngine *engine = nullptr;
    bool supports_prompt_cache_key() const noexcept override { return true; }
    std::vector<Value> requests;
    Value respond(const Value &request,
                  const std::function<void(std::string_view)> &capture) override {
      requests.push_back(request);
      // After request 2 (warm cache), force cache cold so request 3 flushes staged
      // work.
      if (requests.size() == 2 && engine != nullptr)
        engine->set_cache_ttl(std::chrono::seconds{0});
      auto resp = assistant_reply("cold-step-" + std::to_string(requests.size()));
      capture(unwrap(dump_json(resp)));
      return resp;
    }
  } provider;

  CodingEngine engine{log, context, provider, "test-model"};
  provider.engine = &engine;
  engine.set_cache_ttl(std::chrono::seconds{300});
  engine.turn({.prompt = "warm then cold", .program = R"(
                 blackbird.request()
                 local target_id = nil
                 for _, e in ipairs(blackbird.context().entries) do
                   if e.item.content == 'STAGED_DROP_TARGET' then target_id = e.id end
                 end
                 assert(target_id, 'target missing')
                 local res = blackbird.call('context_manage', {
                   proposal = {
                     mode = 'archive',
                     ids = {target_id},
                     reason = 'stage-while-warm',
                     source = 'unit3-test'
                   }
                 })
                 assert(res.staged == true, 'default manage must stage while warm')
                 -- Request 2: cache is warm -> stays staged, keeps prefix intact!
                 blackbird.request()
                 -- Request 3: provider set cache_ttl=0 -> cache is cold -> auto-flush!
                 blackbird.request()
               )"});

  require(provider.requests.size() == 3, "expected 3 requests");
  const auto key0 = string_field(provider.requests[0], "prompt_cache_key");
  const auto key1 = string_field(provider.requests[1], "prompt_cache_key");
  const auto key2 = string_field(provider.requests[2], "prompt_cache_key");
  require(key1 == key0, "warm request 2 keeps epoch 0 cache key");
  require(key2 == key0 + ":e1", "cold request 3 rolls to epoch 1");
  require(unwrap(dump_json(field(provider.requests[1], "input")))
                  .find("STAGED_DROP_TARGET") != std::string::npos,
          "warm request 2 keeps staged entry to preserve KV cache prefix");
  require(unwrap(dump_json(field(provider.requests[2], "input")))
                  .find("STAGED_DROP_TARGET") == std::string::npos,
          "cold request 3 automatically flushes staged drop");
}

void test_overflow_recovery() {
  TempDir dir{"bb-u3-overflow"};
  auto root = make_state(dir.path, 61);
  AuditLog log{*root};
  ContextStore context{log};
  context.append({Value::object({{"role", Value{"assistant"}},
                                 {"content", Value{"PINNED_CRITICAL_FACT"}}})},
                 "provider.branch:seed1", UnitClass::result);
  context.append({Value::object({{"role", Value{"assistant"}},
                                 {"content", Value{"EXPENDABLE_BULK_ONE"}}})},
                 "provider.branch:seed2", UnitClass::result);
  context.append({Value::object({{"role", Value{"assistant"}},
                                 {"content", Value{"EXPENDABLE_BULK_TWO"}}})},
                 "provider.branch:seed3", UnitClass::result);

  // Pin the first unit so automatic overflow archival must skip it.
  const auto units = context.units();
  require(!units.empty(), "expected seeded units");
  const auto pinned = context.pin(units.front().handle);
  require(field(pinned, "pinned") == Value{Number{1}}, "pin must succeed");

  struct OverflowOnceProvider final : public CodingProvider {
    bool supports_prompt_cache_key() const noexcept override { return true; }
    std::vector<Value> requests;
    Value respond(const Value &request,
                  const std::function<void(std::string_view)> &capture) override {
      requests.push_back(request);
      if (requests.size() == 1)
        throw Error{ErrorCode::provider_context_overflow, 400};
      auto resp = assistant_reply("recovered-after-overflow");
      capture(unwrap(dump_json(resp)));
      return resp;
    }
  } provider;

  CodingEngine engine{log, context, provider, "test-model"};
  engine.turn({.prompt = "trigger overflow", .program = "blackbird.request()"});

  require(provider.requests.size() == 2, "overflow must retry once automatically");
  require(engine.upstream_epoch() == 1,
          "overflow recovery must advance upstream epoch");
  const auto key0 = string_field(provider.requests[0], "prompt_cache_key");
  const auto key1 = string_field(provider.requests[1], "prompt_cache_key");
  require(key1 == key0 + ":e1", "overflow retry must roll prompt_cache_key");
  const auto retry_input = unwrap(dump_json(field(provider.requests[1], "input")));
  require(retry_input.find("PINNED_CRITICAL_FACT") != std::string::npos,
          "overflow recovery must preserve pinned units");
  require(retry_input.find("EXPENDABLE_BULK_ONE") == std::string::npos,
          "overflow recovery must archive oldest unpinned unit");
  require(unwrap(dump_json(context.originals())).find("EXPENDABLE_BULK_ONE") !=
              std::string::npos,
          "archived unit original must remain intact");
}
} // namespace

int main(int argc, char **argv) {
  const std::string_view selected = argc >= 2 ? std::string_view{argv[1]} : "all";
  const std::pair<std::string_view, void (*)()> cases[]{
      {"lua_time_and_error_text", test_lua_time_and_error_text},
      {"max_output_tokens_preserved", test_max_output_tokens_preserved},
      {"foreign_reasoning_projection", test_foreign_reasoning_projection},
      {"mid_turn_cut_and_epoch_key", test_mid_turn_cut_and_epoch_key},
      {"cold_cache_free_flush", test_cold_cache_free_flush},
      {"overflow_recovery", test_overflow_recovery},
  };
  bool failed = false;
  for (const auto &[name, fn] : cases) {
    if (selected != "all" && selected != name)
      continue;
    try {
      fn();
      std::cout << "PASS " << name << '\n';
    } catch (const std::exception &error) {
      std::cerr << "FAIL " << name << ": " << error.what() << '\n';
      failed = true;
    } catch (const Error &error) {
      std::cerr << "FAIL " << name << ": Error(" << error_name(error.code) << ":"
                << error.detail << ")\n";
      failed = true;
    }
  }
  return failed ? 1 : 0;
}
