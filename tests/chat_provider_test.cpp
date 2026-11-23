#include "blackbird/anthropic_provider.hpp"
#include "blackbird/chat_provider.hpp"
#include "blackbird/coding.hpp"
#include "blackbird/json.hpp"
#include "blackbird/provider_auth.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

using namespace blackbird;

namespace {

void require(bool condition, const char *why) {
  if (!condition)
    throw std::runtime_error(why);
}

template <class T> T make_id(unsigned char n) {
  IdentityBytes bytes{};
  bytes[0] = std::byte{n};
  return unwrap(T::from_bytes(bytes));
}

class StubProvider final : public CodingProvider {
public:
  explicit StubProvider(std::string id) : id_(std::move(id)) {}
  std::string_view provider_identity() const noexcept override { return id_; }
  Value respond(const Value &,
                const std::function<void(std::string_view)> &capture) override {
    ++calls;
    auto out = Value::object(
        {{"output",
          Value{Value::Array{Value::object(
              {{"type", Value{"message"}},
               {"id", Value{"m1"}},
               {"role", Value{"assistant"}},
               {"status", Value{"completed"}},
               {"content", Value{Value::Array{Value::object(
                               {{"type", Value{"output_text"}},
                                {"text", Value{"hello from " + id_}}})}}}})}}}});
    capture(unwrap(dump_json(out)));
    return out;
  }
  int calls = 0;

private:
  std::string id_;
};

void test_chat_completions_export_and_parse() {
  const Value request = Value::object(
      {{"model", Value{"gemini-2.5-pro"}},
       {"instructions", Value{"You are Blackbird."}},
       {"stream", Value{true}},
       {"store", Value{false}},
       {"tools",
        Value{Value::Array{Value::object(
            {{"type", Value{"function"}},
             {"name", Value{"read_file"}},
             {"description", Value{"Read a file"}},
             {"parameters", Value::object({{"type", Value{"object"}},
                                           {"properties", Value::object({})}})}})}}},
       {"input", Value{Value::Array{
                     Value::object(
                         {{"role", Value{"user"}}, {"content", Value{"Check README"}}}),
                     Value::object({{"role", Value{"assistant"}},
                                    {"content", Value{"Reading now."}}}),
                     Value::object({{"type", Value{"function_call"}},
                                    {"call_id", Value{"call_1"}},
                                    {"name", Value{"read_file"}},
                                    {"arguments", Value{"{\"path\":\"README.md\"}"}}}),
                     Value::object({{"type", Value{"function_call_output"}},
                                    {"call_id", Value{"call_1"}},
                                    {"output", Value{"# Blackbird"}}})}}}});

  const auto wire = export_chat_completions_request(request);
  require(string_field(wire, "model") == "gemini-2.5-pro", "model preserved");
  require(field(wire, "stream") == Value{true}, "streaming enabled");
  const auto &msgs = field(wire, "messages").array();
  require(msgs.size() == 4, "system + user + coalesced assistant+tool_calls + tool");
  require(string_field(msgs[0], "role") == "system", "instructions become system");
  require(string_field(msgs[2], "role") == "assistant" &&
              field(msgs[2], "tool_calls").array().size() == 1,
          "assistant text and tool_calls coalesced");
  require(string_field(msgs[3], "role") == "tool" &&
              string_field(msgs[3], "tool_call_id") == "call_1",
          "tool output paired by tool_call_id");

  const std::string sse =
      "data: {\"id\":\"chatcmpl-1\",\"model\":\"gemini-2.5-pro\","
      "\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hel\"}"
      "}]}\n\n"
      "data: {\"id\":\"chatcmpl-1\",\"model\":\"gemini-2.5-pro\","
      "\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo!\"}}]}\n\n"
      "data: {\"id\":\"chatcmpl-1\",\"model\":\"gemini-2.5-pro\","
      "\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"tc_"
      "9\","
      "\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{"
      "\\\"path\\\":\"}}]}}]}\n\n"
      "data: {\"id\":\"chatcmpl-1\",\"model\":\"gemini-2.5-pro\","
      "\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,"
      "\"function\":{\"arguments\":\"\\\"a.txt\\\"}\"}}]}}],"
      "\"usage\":{\"prompt_tokens\":120,\"completion_tokens\":30,\"total_tokens\":150,"
      "\"prompt_tokens_details\":{\"cached_tokens\":40}}}\n\n"
      "data: [DONE]\n\n";

  // Verify ResponsePreview streams live text deltas matching chat_msg_0.
  ResponsePreview preview;
  const auto deltas = preview.feed(sse);
  require(deltas.size() == 2 && deltas[0].item_id == "chat_msg_0" &&
              deltas[0].text == "Hel" && deltas[1].text == "lo!",
          "ResponsePreview extracts live chat completion text deltas");

  const auto completed = unwrap(chat_completions_completed_response(sse));
  const auto &out = field(completed, "output").array();
  require(out.size() == 2, "assistant message + reconstructed function_call");
  require(string_field(out[0], "id") == "chat_msg_0" &&
              string_field(field(out[0], "content").array()[0], "text") == "Hello!",
          "assistant message reassembled with matching preview id");
  require(string_field(out[1], "type") == "function_call" &&
              string_field(out[1], "call_id") == "tc_9" &&
              string_field(out[1], "name") == "read_file" &&
              string_field(out[1], "arguments") == "{\"path\":\"a.txt\"}",
          "streamed tool_calls reassembled cleanly");
  const auto &usage = field(completed, "usage");
  require(field(usage, "input_tokens").number().text() == "120" &&
              field(usage, "output_tokens").number().text() == "30" &&
              field(field(usage, "input_tokens_details"), "cached_tokens")
                      .number()
                      .text() == "40",
          "usage normalized into Blackbird canonical shape");
}

void test_deepseek_reasoning_and_cache() {
  const std::string sse =
      "data: {\"id\":\"ds-1\",\"model\":\"deepseek-reasoner\","
      "\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\","
      "\"reasoning_content\":\"Check file first.\"}}]}\n\n"
      "data: {\"id\":\"ds-1\",\"model\":\"deepseek-reasoner\","
      "\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,"
      "\"id\":\"call_ds1\",\"type\":\"function\","
      "\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"a.cc\\\"}"
      "\"}}]}}],"
      "\"usage\":{\"prompt_tokens\":200,\"completion_tokens\":25,\"total_tokens\":225,"
      "\"prompt_cache_hit_tokens\":160}}\n\n"
      "data: [DONE]\n\n";

  const auto completed = unwrap(chat_completions_completed_response(sse));
  const auto &out = field(completed, "output").array();
  require(out.size() == 2, "reasoning item + function_call item");
  require(string_field(out[0], "type") == "reasoning" &&
              string_field(out[0], "chat_reasoning_content") == "Check file first.",
          "DeepSeek reasoning_content captured cleanly");
  require(field(field(completed, "usage"), "input_tokens_details")
                  .find("cached_tokens")
                  ->number()
                  .text() == "160",
          "DeepSeek prompt_cache_hit_tokens normalized to cached_tokens");

  // Round-trip back into the next request's assistant message.
  Value::Array input;
  input.push_back(Value::object({{"role", Value{"user"}}, {"content", Value{"go"}}}));
  input.push_back(out[0]);
  input.push_back(out[1]);
  input.push_back(Value::object({{"type", Value{"function_call_output"}},
                                 {"call_id", Value{"call_ds1"}},
                                 {"output", Value{"int main(){}"}}}));
  const auto wire = export_chat_completions_request(Value::object(
      {{"model", Value{"deepseek-reasoner"}}, {"input", Value{std::move(input)}}}));
  const auto &msgs = field(wire, "messages").array();
  require(msgs.size() == 3, "user + assistant(reasoning+tool_calls) + tool");
  require(string_field(msgs[1], "reasoning_content") == "Check file first." &&
              field(msgs[1], "tool_calls").array().size() == 1,
          "DeepSeek reasoning_content preserved on assistant tool-call message");
}

void test_catalog_kimi_and_live_provider_swap() {
  ProviderAuth auth;
  const auto cat = auth.catalog();
  bool has_gemini = false, has_kimi = false, has_grok = false, has_deepseek = false,
       has_jev = false;
  for (const auto &p : field(cat, "providers").array()) {
    const auto &id = string_field(p, "id");
    if (id == "gemini" && string_field(p, "protocol") == "chat")
      has_gemini = true;
    if (id == "kimi" && string_field(p, "protocol") == "messages")
      has_kimi = true;
    if (id == "grok" && string_field(p, "protocol") == "chat")
      has_grok = true;
    if (id == "deepseek" && string_field(p, "protocol") == "chat" &&
        string_field(p, "environment") == "DEEPSEEK_API_KEY")
      has_deepseek = true;
    if (id == "jev" && string_field(p, "protocol") == "decision" &&
        string_field(p, "environment") == "TYPESAFE_API_KEY")
      has_jev = true;
  }
  require(has_gemini && has_kimi && has_grok && has_deepseek && has_jev,
          "built-in catalog includes gemini, kimi, grok, deepseek, and jev");

  // Kimi Messages export skips Claude-only adaptive thinking / Claude Code prefix.
  const Value kimi_req = Value::object(
      {{"model", Value{"kimi-for-coding"}},
       {"instructions", Value{"Help the user."}},
       {"store", Value{false}},
       {"stream", Value{true}},
       {"tools", Value{Value::Array{}}},
       {"reasoning", Value::object({{"effort", Value{"medium"}}})},
       {"input", Value{Value::Array{Value::object(
                     {{"role", Value{"user"}}, {"content", Value{"hi"}}})}}}});
  const auto kimi_wire = export_anthropic_request(kimi_req, 8192, false);
  require(
      !kimi_wire.find("thinking") && !kimi_wire.find("output_config"),
      "non-Anthropic Messages provider omits Claude-specific thinking/output_config");
  require(string_field(kimi_wire, "system") == "Help the user.",
          "non-Anthropic Messages provider keeps instructions clean");

  // CodingEngine::set_provider hot-swaps providers cleanly between turns.
  char pattern[] = "/tmp/blackbird-swap-XXXXXX";
  const auto *path = ::mkdtemp(pattern);
  require(path != nullptr, "mkdtemp failed");
  struct Cleanup {
    std::filesystem::path dir;
    ~Cleanup() {
      std::error_code ignored;
      std::filesystem::remove_all(dir, ignored);
    }
  } cleanup{path};

  auto root =
      unwrap(RetainedState::create(std::make_unique<NativeJournalDirectory>(
                                       unwrap(NativeJournalDirectory::open(path))),
                                   "audit",
                                   {make_id<EnvironmentId>(1),
                                    make_id<AuditStreamId>(2),
                                    3,
                                    {1024 * 1024, 4 * 1024 * 1024},
                                    std::nullopt},
                                   {64 * 1024 * 1024, 10000}));
  AuditLog log{*root};
  ContextStore context{log};
  StubProvider first{"gemini"};
  StubProvider second{"grok"};
  CodingEngine engine{log, context, first, "gemini-2.5-pro"};

  engine.turn(
      {"first", "local r = blackbird.request(); blackbird.present(r.output[1])"});
  require(first.calls == 1 && second.calls == 0, "first turn used gemini");

  const auto epoch_before = engine.upstream_epoch();
  engine.set_provider(second);
  engine.model("grok-4");
  require(engine.upstream_epoch() == epoch_before + 1,
          "provider swap bumps upstream cache epoch");

  engine.turn(
      {"second", "local r = blackbird.request(); blackbird.present(r.output[1])"});
  require(first.calls == 1 && second.calls == 1, "second turn routed to grok");
}

} // namespace

int main() {
  try {
    test_chat_completions_export_and_parse();
    test_deepseek_reasoning_and_cache();
    test_catalog_kimi_and_live_provider_swap();
    return 0;
  } catch (const Error &e) {
    std::cerr << "chat_provider_test blackbird::Error: " << error_name(e.code) << " ("
              << e.detail << ")\n";
    return 1;
  } catch (const std::exception &e) {
    std::cerr << "chat_provider_test failed: " << e.what() << "\n";
    return 1;
  }
}
