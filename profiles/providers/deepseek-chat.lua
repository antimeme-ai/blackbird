-- Profile `deepseek-chat`: DeepSeek native Chat Completions route
-- (https://api.deepseek.com/v1, src/provider_auth.cpp:314; deepseek-chat and
-- deepseek-reasoner, 128k context window, src/coding_provider.cpp:197-199).
-- Per docs/CONTEXT_LIFECYCLE.md §6.2 and provider_protocol.md F9, DeepSeek requires
-- `reasoning_content` on retained assistant turns with tools (`must_keep`), and whole-turn
-- removal cuts are refused until probed (`archival.mode = "refused_until_probed"`).
-- Automatic prefix caching on disk reports `prompt_cache_hit_tokens` (normalized to
-- `input_tokens_details.cached_tokens` in src/chat_provider.cpp:69-71).
return {
  schema = "blackbird.provider-profile/1",
  id = "deepseek-chat",
  revision = 1,
  match = { provider = "deepseek", protocol = "chat" },
  sources = {
    thinking_mode = {
      url = "https://api-docs.deepseek.com/guides/thinking_mode",
      read = "2026-10-20",
      title = "DeepSeek Thinking Mode",
    },
    context_caching = {
      url = "https://api-docs.deepseek.com/guides/kv_cache",
      read = "2026-10-20",
      title = "DeepSeek Context Caching on Disk",
    },
    tribunal = {
      path = "papers/clm-a1v-2026-10-19/design-tribunal/provider_protocol.md",
      read = "2026-10-20",
      note = "F9: DeepSeek reasoning_content rule and archival refusal until probed",
    },
  },
  pairing = {
    validator = "codec",
    basis = "conservative:ChatCompletionsCodingProvider pairs tool_calls and tool_call_id directly (src/chat_provider.cpp:146-175)",
  },
  reasoning = {
    at_cut = "must_keep",
    at_rebind = "drop_foreign",
    side_request_reasoning = "keep",
    basis = {
      at_cut = "cited:thinking_mode",
      at_rebind = "conservative:chat_reasoning_content is stripped across incompatible families (src/coding_provider.cpp:224-226)",
      side_request_reasoning = "cited:thinking_mode",
    },
  },
  turn = {
    start = "user_text",
    close = "none",
    open_turn = { "closed_only" },
    boundary = {
      form = "user_note",
      enabled = false,
      basis = "conservative:boundary note not probed on DeepSeek",
    },
    basis = "conservative:Chat Completions sends each user message distinctly; settle only at closed turns until probed",
  },
  request_state = {
    placement = "request_local",
    basis = "conservative:matches today: ChatCompletionsCodingProvider keeps retain_request_state() false (include/blackbird/coding.hpp:39)",
  },
  note = {
    role = "system",
    placement = "after_tool_results",
    basis = "conservative:matches today: ChatCompletionsCodingProvider renders developer items as system messages (src/chat_provider.cpp:191)",
  },
  archival = {
    mode = "refused_until_probed",
    basis = "conservative:§6.2 and F9: DeepSeek requires reasoning_content in all subsequent tool-enabled requests; removal cuts stay refused until probed",
  },
  cache = {
    capability = "implicit",
    read_multiplier = 0.1,
    basis = "cited:context_caching",
  },
  stop_reasons = {
    stop = "completed",
    tool_calls = "tool_calls",
    length = "output_limit",
    content_filter = "refusal",
    basis = "conservative:standard Chat Completions finish_reason mapping",
  },
  effort = {
    values = { "low", "medium", "high" },
    basis = "conservative:matches route_efforts for chat routes (src/main.cpp:844-845)",
  },
}
