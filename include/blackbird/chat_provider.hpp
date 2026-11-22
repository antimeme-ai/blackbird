#pragma once

#include "blackbird/coding.hpp"
#include "blackbird/provider_auth.hpp"
#include <string>

namespace blackbird {

struct ChatCompletionsConfig {
  std::string provider;
  ProviderAuthConfig auth;
  int timeout_seconds = 180;
};

// OpenAI Chat Completions coding adapter (POST /chat/completions, SSE streaming,
// tool_calls, usage normalization) over ProviderAuth. Supports Gemini
// OpenAI-compat, xAI Grok, Moonshot, MiMo, and custom OpenAI-compatible hosts.
class ChatCompletionsCodingProvider final : public CodingProvider {
public:
  explicit ChatCompletionsCodingProvider(ChatCompletionsConfig config);
  std::string_view provider_identity() const noexcept override {
    return config_.provider;
  }
  void begin_request_group(const Value &, const RawAdapterContext *) override;
  void end_request_group() noexcept override;
  const Value *group_binding() const noexcept override {
    return group_ ? &binding_ : nullptr;
  }
  Value respond(const Value &, const std::function<void(std::string_view)> &) override;
  Value respond(const Value &, const std::function<void(std::string_view)> &,
                const RawProviderOwner *) override;
  Value respond(const Value &, const std::function<void(std::string_view)> &,
                const RawProviderOwner *, const RawAdapterContext *) override;

private:
  ChatCompletionsConfig config_;
  Value binding_;
  bool group_ = false, responding_ = false;
};

Value export_chat_completions_request(const Value &request);
Result<Value>
chat_completions_completed_response(std::string_view stream, ValueLimits limits = {},
                                    const RawAdapterContext *context = nullptr);

} // namespace blackbird
