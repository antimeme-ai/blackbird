#include "blackbird/anthropic_provider.hpp"
#include "blackbird/coding.hpp"
#include "blackbird/json.hpp"
#include "blackbird/openai.hpp"
#include "blackbird/openrouter.hpp"
#include "blackbird/provider_auth.hpp"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <unistd.h>

using namespace blackbird;

namespace {
void require(bool ok, std::string_view msg) {
  if (!ok)
    throw std::runtime_error(std::string{"context_lifecycle_unit3_test failed: "} +
                             std::string{msg});
}
template <class T> T make_id(unsigned char n) {
  IdentityBytes b{};
  b[0] = std::byte{n};
  return unwrap(T::from_bytes(b));
}
struct TempDir {
  std::filesystem::path path;
  TempDir() {
    char tmpl[] = "/tmp/bb-unit3-XXXXXX";
    const auto *p = mkdtemp(tmpl);
    require(p != nullptr, "mkdtemp");
    path = p;
  }
  ~TempDir() { std::filesystem::remove_all(path); }
};
struct ScriptedProvider final : public CodingProvider {
  std::string identity = "openai-codex";
  bool cache_key = true;
  std::vector<Value> requests;
  std::vector<std::function<Value(const Value &)>> handlers;
  std::size_t index = 0;

  std::string_view provider_identity() const noexcept override { return identity; }
  bool supports_prompt_cache_key() const noexcept override { return cache_key; }
  Value respond(const Value &request,
                const std::function<void(std::string_view)> &capture) override {
    requests.push_back(request);
    require(index < handlers.size(), "unexpected provider request");
    auto res = handlers[index++](request);
    capture(unwrap(dump_json(res)));
    return res;
  }
};
Value text_response(std::string_view text) {
  return Value::object(
      {{"output", Value{Value::Array{Value::object(
                      {{"type", Value{"message"}},
                       {"role", Value{"assistant"}},
                       {"content", Value{Value::Array{Value::object(
                                       {{"type", Value{"output_text"}},
                                        {"text", Value{std::string{text}}}})}}}})}}}});
}
Value tool_call_response(std::string_view call_id, std::string_view name,
                         const Value &args) {
  return Value::object(
      {{"output",
        Value{Value::Array{Value::object({{"type", Value{"function_call"}},
                                          {"call_id", Value{std::string{call_id}}},
                                          {"name", Value{std::string{name}}},
                                          {"arguments", args}})}}}});
}
std::string read_turn_lua() {
  return R"lua(
while true do
  local response = blackbird.request()
  local calls = 0
  for _, item in ipairs(response.output) do
    if item.type == "function_call" then
      calls = calls + 1
      local result = blackbird.call(item.name, item.arguments, { call_id = item.call_id })
      blackbird.append({{ type = "function_call_output", call_id = item.call_id, output = result }})
    elseif item.type == "message" then
      blackbird.present(item)
    end
  end
  if blackbird.restarting() or calls == 0 then
    return
  end
end
)lua";
}

// 1. Decoupled upstream epoch + apply="now" + cold-cache auto-flush + 3-tool surface.
void test_block_compaction_and_epochs() {
  TempDir dir;
  const JournalHeader h{make_id<EnvironmentId>(1),
                        make_id<AuditStreamId>(2),
                        3,
                        {1024 * 1024, 4 * 1024 * 1024},
                        std::nullopt};
  auto root = unwrap(
      RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                NativeJournalDirectory::open(dir.path.string()))),
                            "audit", h, {16 * 1024 * 1024, 4096}));
  AuditLog log{*root};
  ContextStore context{log};
  ScriptedProvider provider;
  CodingEngine engine{log, context, provider, "gpt-5"};

  const auto b1 = context.append(
      {Value::object({{"role", Value{"user"}}, {"content", Value{"initial prompt"}}})},
      "operator");
  const std::string long_alpha =
      std::string(120, 'A') + "OLD_ALPHA_PAST_PREVIEW_BOUNDARY";
  const auto b2 = context.append(
      {Value::object({{"role", Value{"assistant"}}, {"content", Value{long_alpha}}})},
      "provider.branch:seed1");
  const auto b3 = context.append(
      {Value::object({{"role", Value{"assistant"}}, {"content", Value{"OLD_BETA"}}})},
      "provider.branch:seed2");
  require(b1 == 1 && b2 == 2 && b3 == 3, "monotonic integer block ids");

  // Verify the 3-tool surface is registered (no old split-brain context_* tools).
  provider.handlers.push_back([&](const Value &req) {
    std::set<std::string> names;
    for (const auto &t : field(req, "tools").array())
      names.insert(string_field(t, "name"));
    require(names.contains("context_list") && names.contains("context_compact") &&
                names.contains("context_read"),
            "3 block context tools present");
    require(!names.contains("context_manage") && !names.contains("context_units") &&
                !names.contains("context_view") && !names.contains("context_edit"),
            "legacy split-brain context tools removed");
    require(string_field(req, "prompt_cache_key").find(":e") == std::string::npos,
            "epoch 0 has bare cache key");
    return tool_call_response("c_list", "context_list", Value::object({}));
  });
  provider.handlers.push_back([&](const Value &) {
    // Summarize block #2 mid-turn with apply="now" -> immediate epoch 1 rollover!
    return tool_call_response(
        "c_sum", "context_compact",
        Value::object({{"op", Value{"summarize"}},
                       {"ids", Value{Value::Array{Value{Number{2}}}}},
                       {"summary", Value{"Compacted alpha."}},
                       {"apply", Value{"now"}}}));
  });
  provider.handlers.push_back([&](const Value &req) {
    const auto key = string_field(req, "prompt_cache_key");
    require(key.ends_with(":e1"), "apply=now rolled upstream_epoch to :e1 mid-turn");
    const auto wire = unwrap(dump_json(field(req, "input")));
    require(wire.find("OLD_ALPHA_PAST_PREVIEW_BOUNDARY") == std::string::npos &&
                wire.find("Compacted alpha.") != std::string::npos,
            "summarized block replaced on wire immediately");
    return text_response("done");
  });

  engine.turn({"", read_turn_lua()});
  require(engine.upstream_epoch() == 1, "engine upstream_epoch == 1");

  // Archived original #2 stays readable via context_read!
  const auto read_res =
      engine.operator_call("context_read", Value::object({{"id", Value{Number{2}}}}));
  require(
      field(read_res, "archived") == Value{true} &&
          string_field(read_res, "content").find("OLD_ALPHA_PAST_PREVIEW_BOUNDARY") !=
              std::string::npos,
      "archived block #2 readable via context_read");

  // Reopen reconstructs upstream_epoch == 1 from journal tail.
  CodingEngine reopened{log, context, provider, "gpt-5"};
  require(reopened.upstream_epoch() == 1, "upstream_epoch reconstructed on reopen");
}

// 2. Deferred apply="auto" queues while cache warm and flushes free on cold cache.
void test_cold_cache_auto_flush() {
  TempDir dir;
  const JournalHeader h{make_id<EnvironmentId>(11),
                        make_id<AuditStreamId>(12),
                        3,
                        {1024 * 1024, 4 * 1024 * 1024},
                        std::nullopt};
  auto root = unwrap(
      RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                NativeJournalDirectory::open(dir.path.string()))),
                            "audit", h, {16 * 1024 * 1024, 4096}));
  AuditLog log{*root};
  ContextStore context{log};
  ScriptedProvider provider;
  CodingEngine engine{log, context, provider, "gpt-5"};
  engine.set_cache_ttl(std::chrono::seconds{1});

  context.append(
      {Value::object({{"role", Value{"user"}}, {"content", Value{"prompt"}}})},
      "operator");
  const std::string drop_payload = std::string(120, 'D') + "DROP_ME_PAST_PREVIEW";
  context.append(
      {Value::object({{"role", Value{"assistant"}}, {"content", Value{drop_payload}}})},
      "provider.branch:seed1");

  provider.handlers.push_back([](const Value &) {
    // Request 1 warms the cache, then queues drop with apply="auto".
    return tool_call_response(
        "c_drop", "context_compact",
        Value::object({{"op", Value{"drop"}},
                       {"ids", Value{Value::Array{Value{Number{2}}}}},
                       {"apply", Value{"auto"}}}));
  });
  provider.handlers.push_back([&](const Value &req) {
    // Request 2 happens immediately (cache still warm) -> still epoch 0, DROP_ME live!
    require(engine.upstream_epoch() == 0, "warm cache kept epoch 0");
    require(unwrap(dump_json(field(req, "input"))).find("DROP_ME_PAST_PREVIEW") !=
                std::string::npos,
            "deferred drop kept warm prefix intact");
    // Expire cache TTL so Request 3 sees a cold cache after Request 2 returns.
    engine.set_cache_ttl(std::chrono::seconds{0});
    return tool_call_response("c_list", "context_list", Value::object({}));
  });
  provider.handlers.push_back([&](const Value &req) {
    // Request 3 after cold cache auto-flushed the queued drop!
    require(engine.upstream_epoch() == 1, "cold cache auto-flushed to epoch 1");
    require(string_field(req, "prompt_cache_key").ends_with(":e1"),
            "cache key rolled on cold-cache flush");
    require(unwrap(dump_json(field(req, "input"))).find("DROP_ME_PAST_PREVIEW") ==
                std::string::npos,
            "DROP_ME dropped on cold-cache flush");
    return text_response("flushed");
  });

  engine.turn({"", read_turn_lua()});
}

// 3. Overflow recovery preserves pinned & instruction blocks, drops oldest unpinned,
// retries once.
void test_overflow_recovery_and_pin() {
  TempDir dir;
  const JournalHeader h{make_id<EnvironmentId>(21),
                        make_id<AuditStreamId>(22),
                        3,
                        {1024 * 1024, 4 * 1024 * 1024},
                        std::nullopt};
  auto root = unwrap(
      RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                NativeJournalDirectory::open(dir.path.string()))),
                            "audit", h, {16 * 1024 * 1024, 4096}));
  AuditLog log{*root};
  ContextStore context{log};
  ScriptedProvider provider;
  CodingEngine engine{log, context, provider, "gpt-5"};

  context.append(
      {Value::object({{"role", Value{"user"}}, {"content", Value{"KEEP_PROMPT"}}})},
      "operator");
  context.append({Value::object({{"role", Value{"assistant"}},
                                 {"content", Value{"PINNED_FACT"}}})},
                 "provider.branch:s1");
  context.append({Value::object({{"role", Value{"assistant"}},
                                 {"content", Value{"EXPENDABLE_1"}}})},
                 "provider.branch:s2");
  context.append({Value::object({{"role", Value{"assistant"}},
                                 {"content", Value{"EXPENDABLE_2"}}})},
                 "provider.branch:s3");

  // Pin block #2.
  const auto pin_res = engine.operator_call(
      "context_compact",
      Value::object(
          {{"op", Value{"pin"}}, {"ids", Value{Value::Array{Value{Number{2}}}}}}));
  require(field(pin_res, "ok") == Value{true}, "pin succeeded");

  provider.handlers.push_back([](const Value &) -> Value {
    throw Error{ErrorCode::provider_context_overflow, 400};
  });
  provider.handlers.push_back([](const Value &req) {
    const auto wire = unwrap(dump_json(field(req, "input")));
    require(wire.find("KEEP_PROMPT") != std::string::npos, "instruction preserved");
    require(wire.find("PINNED_FACT") != std::string::npos, "pinned block preserved");
    require(wire.find("EXPENDABLE_1") == std::string::npos,
            "oldest unpinned block dropped on overflow");
    require(string_field(req, "prompt_cache_key").ends_with(":e1"),
            "overflow recovery rolled cache epoch");
    return text_response("recovered");
  });

  engine.turn({"", read_turn_lua()});
  require(provider.requests.size() == 2, "retried once after overflow");
  const auto archived_read = context.read_block(3);
  require(field(archived_read, "archived") == Value{true} &&
              string_field(archived_read, "content").find("EXPENDABLE_1") !=
                  std::string::npos,
          "dropped block original preserved in journal");
}

// 4. Provider-scoped reasoning projection strips foreign reasoning on wire without
// mutating store.
void test_reasoning_projection() {
  TempDir dir;
  const JournalHeader h{make_id<EnvironmentId>(31),
                        make_id<AuditStreamId>(32),
                        3,
                        {1024 * 1024, 4 * 1024 * 1024},
                        std::nullopt};
  auto root = unwrap(
      RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                NativeJournalDirectory::open(dir.path.string()))),
                            "audit", h, {16 * 1024 * 1024, 4096}));
  AuditLog log{*root};
  ContextStore context{log};
  ScriptedProvider provider;
  provider.identity = "anthropic-messages";
  CodingEngine engine{log, context, provider, "claude-sonnet-4"};

  context.append({Value::object({{"role", Value{"user"}}, {"content", Value{"hi"}}})},
                 "operator");
  context.append(
      {Value::object(
           {{"type", Value{"reasoning"}}, {"encrypted_content", Value{"openai-blob"}}}),
       Value::object({{"type", Value{"reasoning"}},
                      {"anthropic_message_id", Value{"msg_1"}},
                      {"anthropic_content", Value{Value::Array{}}}}),
       Value::object({{"role", Value{"assistant"}}, {"content", Value{"hello"}}})},
      "provider.branch:mix");

  provider.handlers.push_back([](const Value &req) {
    const auto wire = unwrap(dump_json(field(req, "input")));
    require(wire.find("openai-blob") == std::string::npos,
            "OpenAI encrypted reasoning stripped for Anthropic");
    require(wire.find("anthropic_content") != std::string::npos,
            "Anthropic reasoning kept for Anthropic");
    return text_response("ok");
  });
  engine.turn({"", read_turn_lua()});
  require(unwrap(dump_json(Value{context.items()})).find("openai-blob") !=
              std::string::npos,
          "ContextStore originals untouched by wire projection");
}

// 5. Lua safe time + block helpers + verbatim lua_error + overflow text classifier.
void test_lua_helpers_and_classifiers() {
  TempDir dir;
  const JournalHeader h{make_id<EnvironmentId>(41),
                        make_id<AuditStreamId>(42),
                        3,
                        {1024 * 1024, 4 * 1024 * 1024},
                        std::nullopt};
  auto root = unwrap(
      RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                NativeJournalDirectory::open(dir.path.string()))),
                            "audit", h, {16 * 1024 * 1024, 4096}));
  AuditLog log{*root};
  ContextStore context{log};
  ScriptedProvider provider;
  CodingEngine engine{log, context, provider, "gpt-5"};

  engine.turn({"hello lua", R"lua(
    local t = os.time()
    local c = os.clock()
    local d = os.difftime(10, 3)
    local n = blackbird.now()
    assert(t > 1700000000 and c >= 0 and d == 7)
    assert(n.epoch_ms > 0 and n.monotonic_ms >= 0)
    assert(os.execute == nil and os.remove == nil and os.getenv == nil)
    local bs = blackbird.blocks()
    assert(#bs.blocks == 1 and bs.blocks[1].id == 1)
  )lua"});

  bool saw_error = false;
  try {
    engine.turn({"", "return missing_tbl.x"});
  } catch (const Error &) {
    saw_error = true;
  }
  require(saw_error, "nil-index lua error propagated");

  require(is_context_overflow_text("This model's maximum context length is 128000"),
          "overflow classifier matches maximum context length");
  require(!is_context_overflow_text("max_output_tokens exceeds limit"),
          "overflow classifier avoids max_output_tokens false positive");
}

} // namespace

int main() {
  const char *stage = "start";
  try {
    stage = "test_block_compaction_and_epochs";
    test_block_compaction_and_epochs();
    stage = "test_cold_cache_auto_flush";
    test_cold_cache_auto_flush();
    stage = "test_overflow_recovery_and_pin";
    test_overflow_recovery_and_pin();
    stage = "test_reasoning_projection";
    test_reasoning_projection();
    stage = "test_lua_helpers_and_classifiers";
    test_lua_helpers_and_classifiers();
    std::cout << "context_lifecycle_unit3_test passed\n";
    return 0;
  } catch (const Error &e) {
    std::cerr << stage << ": Error " << error_name(e.code) << " detail=" << e.detail
              << "\n";
    return 1;
  } catch (const std::exception &e) {
    std::cerr << stage << ": " << e.what() << "\n";
    return 1;
  }
}
