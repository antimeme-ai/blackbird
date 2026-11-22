#include "blackbird/chat_provider.hpp"
#include "blackbird/json.hpp"
#include "blackbird/raw_auth.hpp"
#include <charconv>
#include <chrono>
#include <map>
#include <set>

namespace blackbird {
namespace {

std::string optional_string(const Value &obj, std::string_view key) {
  const auto *v = obj.find(key);
  if (!v || !std::holds_alternative<std::string>(v->value()))
    return {};
  return v->string();
}

std::string extract_content_text(const Value &item) {
  const auto *content = item.find("content");
  if (!content)
    return {};
  if (const auto *s = std::get_if<std::string>(&content->value()))
    return *s;
  if (const auto *arr = std::get_if<Value::Array>(&content->value())) {
    std::string out;
    for (const auto &part : *arr) {
      if (!std::holds_alternative<Value::Object>(part.value()))
        continue;
      const auto text = optional_string(part, "text");
      if (!text.empty()) {
        if (!out.empty())
          out += '\n';
        out += text;
      }
    }
    return out;
  }
  return {};
}

std::string serialize_output_field(const Value &output) {
  if (const auto *s = std::get_if<std::string>(&output.value()))
    return *s;
  if (auto dumped = dump_json(output); dumped.has_value())
    return std::move(dumped).value();
  return "{}";
}

Value normalize_chat_usage(const Value &raw) {
  if (!std::holds_alternative<Value::Object>(raw.value()))
    return Value{};
  Value::Object out;
  if (const auto *pt = raw.find("prompt_tokens"))
    out.emplace_back("input_tokens", *pt);
  else if (const auto *it = raw.find("input_tokens"))
    out.emplace_back("input_tokens", *it);
  if (const auto *ct = raw.find("completion_tokens"))
    out.emplace_back("output_tokens", *ct);
  else if (const auto *ot = raw.find("output_tokens"))
    out.emplace_back("output_tokens", *ot);
  if (const auto *tt = raw.find("total_tokens"))
    out.emplace_back("total_tokens", *tt);
  if (const auto *pd = raw.find("prompt_tokens_details");
      pd && std::holds_alternative<Value::Object>(pd->value())) {
    if (const auto *cached = pd->find("cached_tokens"))
      out.emplace_back("input_tokens_details",
                       Value::object({{"cached_tokens", *cached}}));
  }
  if (const auto *cd = raw.find("completion_tokens_details");
      cd && std::holds_alternative<Value::Object>(cd->value())) {
    if (const auto *reason = cd->find("reasoning_tokens"))
      out.emplace_back("output_tokens_details",
                       Value::object({{"reasoning_tokens", *reason}}));
  }
  return Value::object(std::move(out));
}

std::size_t parse_index(const Value &v, std::size_t fallback) {
  const auto *num = std::get_if<Number>(&v.value());
  if (!num)
    return fallback;
  std::size_t out = fallback;
  const auto &text = num->text();
  const auto res = std::from_chars(text.data(), text.data() + text.size(), out);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size())
    return fallback;
  return out;
}

} // namespace

Value export_chat_completions_request(const Value &request) {
  const auto &model = string_field(request, "model");
  if (model.empty() || model.size() > 256)
    throw Error{ErrorCode::invalid_range};

  Value::Array messages;
  if (const auto *inst = request.find("instructions");
      inst && std::holds_alternative<std::string>(inst->value()) &&
      !inst->string().empty()) {
    messages.push_back(Value::object({{"role", Value{"system"}}, {"content", *inst}}));
  }

  bool pending_assistant = false;
  std::string assistant_text;
  Value::Array assistant_calls;
  auto flush_assistant = [&] {
    if (!pending_assistant)
      return;
    Value::Object msg{{"role", Value{"assistant"}}};
    if (!assistant_text.empty() || assistant_calls.empty())
      msg.emplace_back("content", Value{assistant_text});
    else
      msg.emplace_back("content", Value{});
    if (!assistant_calls.empty())
      msg.emplace_back("tool_calls", Value{std::move(assistant_calls)});
    messages.push_back(Value::object(std::move(msg)));
    pending_assistant = false;
    assistant_text.clear();
    assistant_calls.clear();
  };

  if (const auto *input = request.find("input");
      input && std::holds_alternative<Value::Array>(input->value())) {
    for (const auto &item : input->array()) {
      if (!std::holds_alternative<Value::Object>(item.value()))
        continue;
      const auto type = optional_string(item, "type");
      if (type == "reasoning")
        continue;
      if (type == "function_call") {
        pending_assistant = true;
        const auto call_id = string_field(item, "call_id");
        const auto name = string_field(item, "name");
        const auto *args_val = item.find("arguments");
        std::string args_str = "{}";
        if (args_val) {
          if (const auto *s = std::get_if<std::string>(&args_val->value()))
            args_str = *s;
          else if (auto dumped = dump_json(*args_val); dumped.has_value())
            args_str = std::move(dumped).value();
        }
        assistant_calls.push_back(Value::object(
            {{"id", Value{call_id}},
             {"type", Value{"function"}},
             {"function",
              Value::object({{"name", Value{name}},
                             {"arguments", Value{std::move(args_str)}}})}}));
        continue;
      }
      if (type == "function_call_output") {
        flush_assistant();
        const auto call_id = string_field(item, "call_id");
        const auto *output = item.find("output");
        const auto content = output ? serialize_output_field(*output) : std::string{};
        messages.push_back(Value::object({{"role", Value{"tool"}},
                                          {"tool_call_id", Value{call_id}},
                                          {"content", Value{content}}}));
        continue;
      }
      const auto role = optional_string(item, "role");
      if (role == "assistant") {
        if (pending_assistant && !assistant_calls.empty())
          flush_assistant();
        pending_assistant = true;
        const auto text = extract_content_text(item);
        if (!text.empty()) {
          if (!assistant_text.empty())
            assistant_text += '\n';
          assistant_text += text;
        }
        continue;
      }
      if (role == "user" || role == "system" || role == "developer") {
        flush_assistant();
        const std::string wire_role = role == "developer" ? "system" : role;
        messages.push_back(
            Value::object({{"role", Value{wire_role}},
                           {"content", Value{extract_content_text(item)}}}));
      }
    }
  }
  flush_assistant();

  Value::Object body{
      {"model", Value{model}},
      {"messages", Value{std::move(messages)}},
      {"stream", Value{true}},
      {"stream_options", Value::object({{"include_usage", Value{true}}})}};

  if (const auto *tools = request.find("tools");
      tools && std::holds_alternative<Value::Array>(tools->value()) &&
      !tools->array().empty()) {
    Value::Array wire_tools;
    for (const auto &tool : tools->array()) {
      if (!std::holds_alternative<Value::Object>(tool.value()))
        continue;
      if (optional_string(tool, "type") != "function")
        continue;
      Value::Object fn{{"name", field(tool, "name")}};
      if (const auto *desc = tool.find("description"))
        fn.emplace_back("description", *desc);
      if (const auto *params = tool.find("parameters"))
        fn.emplace_back("parameters", *params);
      wire_tools.push_back(Value::object(
          {{"type", Value{"function"}}, {"function", Value::object(std::move(fn))}}));
    }
    if (!wire_tools.empty())
      body.emplace_back("tools", Value{std::move(wire_tools)});
  }

  return Value::object(std::move(body));
}

Result<Value> chat_completions_completed_response(std::string_view stream,
                                                  ValueLimits limits,
                                                  const RawAdapterContext *context) {
  try {
    RawProviderPhase phase{provider_link_credit};
    return phase.run([&]() -> Result<Value> {
      phase.start(6, context);
      if (context && context->receipt && context->receipt->response)
        phase.link(*context->receipt->response);
      if (stream.size() > limits.bytes)
        throw Error{ErrorCode::capacity};

      struct ToolCallAcc {
        std::string id;
        std::string name;
        std::string arguments;
      };
      std::string response_id;
      std::string response_model;
      std::string assistant_text;
      std::map<std::size_t, ToolCallAcc> tool_calls;
      Value usage;
      bool saw_chunk = false;

      auto ingest_chunk = [&](const Value &chunk) {
        if (!std::holds_alternative<Value::Object>(chunk.value()))
          throw Error{ErrorCode::corrupt};
        if (const auto *err = chunk.find("error"); err && *err != Value{}) {
          if (const auto dumped = dump_json(*err);
              dumped.has_value() && is_context_overflow_text(dumped.value()))
            throw Error{ErrorCode::provider_context_overflow};
          throw Error{ErrorCode::external_unknown};
        }
        saw_chunk = true;
        if (response_id.empty())
          response_id = optional_string(chunk, "id");
        if (response_model.empty())
          response_model = optional_string(chunk, "model");
        if (const auto *u = chunk.find("usage");
            u && std::holds_alternative<Value::Object>(u->value()))
          usage = normalize_chat_usage(*u);

        const auto *choices = chunk.find("choices");
        if (!choices || !std::holds_alternative<Value::Array>(choices->value()) ||
            choices->array().empty())
          return;
        const auto &choice = choices->array().front();
        if (!std::holds_alternative<Value::Object>(choice.value()))
          return;
        const auto *delta = choice.find("delta");
        if (!delta)
          delta = choice.find("message");
        if (!delta || !std::holds_alternative<Value::Object>(delta->value()))
          return;

        if (const auto *content = delta->find("content");
            content && std::holds_alternative<std::string>(content->value())) {
          assistant_text += content->string();
        }
        if (const auto *tcs = delta->find("tool_calls");
            tcs && std::holds_alternative<Value::Array>(tcs->value())) {
          std::size_t fallback_idx = 0;
          for (const auto &tc : tcs->array()) {
            if (!std::holds_alternative<Value::Object>(tc.value()))
              continue;
            const auto *idx_val = tc.find("index");
            const auto idx =
                idx_val ? parse_index(*idx_val, fallback_idx) : fallback_idx;
            ++fallback_idx;
            auto &acc = tool_calls[idx];
            if (const auto id = optional_string(tc, "id"); !id.empty())
              acc.id = id;
            if (const auto *fn = tc.find("function");
                fn && std::holds_alternative<Value::Object>(fn->value())) {
              if (const auto name = optional_string(*fn, "name"); !name.empty())
                acc.name += name;
              if (const auto args = optional_string(*fn, "arguments"); !args.empty())
                acc.arguments += args;
            }
          }
        }
      };

      // Trim leading whitespace to check for non-SSE single JSON fallback.
      auto trimmed = stream;
      while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t' ||
                                  trimmed.front() == '\r' || trimmed.front() == '\n'))
        trimmed.remove_prefix(1);

      if (trimmed.starts_with('{')) {
        ingest_chunk(unwrap(parse_json(trimmed, limits)));
      } else {
        std::string data;
        auto flush_event = [&] {
          if (data.empty())
            return;
          if (data == "[DONE]") {
            data.clear();
            return;
          }
          ingest_chunk(unwrap(parse_json(data, limits)));
          data.clear();
        };
        auto remaining = stream;
        while (!remaining.empty()) {
          const auto nl = remaining.find('\n');
          const auto line_raw =
              nl == std::string_view::npos ? remaining : remaining.substr(0, nl);
          remaining = nl == std::string_view::npos ? std::string_view{}
                                                   : remaining.substr(nl + 1);
          auto line = line_raw;
          if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
          if (line.empty()) {
            flush_event();
          } else if (line.starts_with("data:")) {
            line.remove_prefix(5);
            if (!line.empty() && line.front() == ' ')
              line.remove_prefix(1);
            if (!data.empty())
              data += '\n';
            data.append(line);
          }
        }
        flush_event();
      }

      if (!saw_chunk)
        throw Error{ErrorCode::incomplete};

      Value::Array output;
      if (!assistant_text.empty()) {
        output.push_back(Value::object(
            {{"type", Value{"message"}},
             {"id", Value{"chat_msg_0"}},
             {"role", Value{"assistant"}},
             {"status", Value{"completed"}},
             {"content", Value{Value::Array{Value::object(
                             {{"type", Value{"output_text"}},
                              {"text", Value{std::move(assistant_text)}}})}}}}));
      }

      std::set<std::string> seen_ids;
      for (auto &[idx, tc] : tool_calls) {
        if (tc.name.empty())
          throw Error{ErrorCode::corrupt};
        if (tc.id.empty())
          tc.id = "call_" + std::to_string(idx);
        if (!seen_ids.insert(tc.id).second)
          throw Error{ErrorCode::conflict};
        const std::string args = tc.arguments.empty() ? "{}" : tc.arguments;
        const auto parsed_args = unwrap(parse_json(args, limits));
        (void)parsed_args.object();
        output.push_back(Value::object({{"type", Value{"function_call"}},
                                        {"call_id", Value{std::move(tc.id)}},
                                        {"name", Value{std::move(tc.name)}},
                                        {"arguments", Value{args}},
                                        {"status", Value{"completed"}}}));
      }

      Value::Object resp{{"id", Value{response_id.empty() ? "chat_resp" : response_id}},
                         {"status", Value{"completed"}},
                         {"output", Value{std::move(output)}}};
      if (!response_model.empty())
        resp.emplace_back("model", Value{std::move(response_model)});
      if (usage != Value{})
        resp.emplace_back("usage", std::move(usage));
      return Result<Value>::success(Value::object(std::move(resp)));
    });
  } catch (const Error &error) {
    return Result<Value>::failure(error);
  } catch (const std::bad_alloc &) {
    return Result<Value>::failure({ErrorCode::allocation});
  } catch (const std::length_error &) {
    return Result<Value>::failure({ErrorCode::capacity});
  } catch (const std::bad_variant_access &) {
    return Result<Value>::failure({ErrorCode::corrupt});
  }
}

ChatCompletionsCodingProvider::ChatCompletionsCodingProvider(
    ChatCompletionsConfig config)
    : config_(std::move(config)) {}

void ChatCompletionsCodingProvider::begin_request_group(
    const Value &request, const RawAdapterContext *context) {
  if (group_ || responding_)
    throw Error{ErrorCode::busy};
  RawProviderPhase phase;
  phase.run([&] {
    phase.start(5, context);
    auto config = config_.auth;
    config.cancelled = cancelled;
    ProviderAuth auth{std::move(config)};
    const RawAuthParent parent{phase.reference()};
    binding_ = auth.binding(config_.provider, &parent);
    if (string_field(binding_, "protocol") != "chat")
      throw Error{ErrorCode::unsupported};
    const auto &model = string_field(request, "model");
    if (model.empty() || model.size() > 256)
      throw Error{ErrorCode::invalid_range};
    group_ = true;
    phase.finish(1);
  });
}

void ChatCompletionsCodingProvider::end_request_group() noexcept { group_ = false; }

Value ChatCompletionsCodingProvider::respond(
    const Value &request, const std::function<void(std::string_view)> &capture) {
  return respond(request, capture, nullptr, nullptr);
}

Value ChatCompletionsCodingProvider::respond(
    const Value &request, const std::function<void(std::string_view)> &capture,
    const RawProviderOwner *owner) {
  return respond(request, capture, owner, nullptr);
}

Value ChatCompletionsCodingProvider::respond(
    const Value &request, const std::function<void(std::string_view)> &capture,
    const RawProviderOwner *owner, const RawAdapterContext *context) {
  if (responding_)
    throw Error{ErrorCode::busy};
  const bool temporary = !group_;
  if (temporary)
    begin_request_group(request, context);
  struct End {
    ChatCompletionsCodingProvider *provider;
    bool &responding;
    ~End() {
      responding = false;
      if (provider)
        provider->end_request_group();
    }
  } end{temporary ? this : nullptr, responding_};
  responding_ = true;
  if (config_.timeout_seconds < 1 || config_.timeout_seconds > 3600)
    throw Error{ErrorCode::invalid_range};
  auto control = raw_wait_control();
  const auto outer =
      std::chrono::steady_clock::now() +
      std::chrono::seconds{std::max<int>(config_.timeout_seconds * 10, 1800)};
  control.deadline = control.deadline ? std::min(*control.deadline, outer) : outer;
  RawWaitScope deadline{control};
  RawProviderPhase phase;
  return phase.run([&] {
    phase.start(5, context);
    auto config = config_.auth;
    config.cancelled = cancelled;
    ProviderAuth auth{std::move(config)};
    const auto wire = export_chat_completions_request(request);
    const auto response =
        auth.request(config_.provider, "chat/completions", wire,
                     config_.timeout_seconds, capture, &binding_, owner, context);
    auto result =
        unwrap(chat_completions_completed_response(response.body, {}, context));
    phase.finish(1);
    return result;
  });
}

} // namespace blackbird
