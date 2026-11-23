-- Profile `gemini-chat`: Google Gemini OpenAI-compatible Chat Completions route
-- (https://generativelanguage.googleapis.com/v1beta/openai, src/provider_auth.cpp:310-312;
-- gemini-2.5-pro, gemini-2.5-flash, gemini-3-pro-preview, gemini-3-flash-preview,
-- 1M / 1,048,576-token context window, src/coding_provider.cpp:182-183).
-- Gemini validates thought signatures only within the current turn (starting at the most
-- recent user message with standard text content, docs/CONTEXT_LIFECYCLE.md §6.2, §7.1,
-- provider_protocol.md L4) and provides automatic implicit prompt caching.
return {
  schema = "blackbird.provider-profile/1",
  id = "gemini-chat",
  revision = 1,
  match = { provider = "gemini", protocol = "chat" },
  sources = {
    thought_signatures = {
      url = "https://ai.google.dev/gemini-api/docs/generate-content/thought-signatures",
      read = "2026-10-20",
      title = "Gemini Thought Signatures",
    },
    caching = {
      url = "https://ai.google.dev/gemini-api/docs/caching",
      read = "2026-10-20",
      title = "Gemini Context Caching",
    },
    tribunal = {
      path = "papers/clm-a1v-2026-10-19/design-tribunal/provider_protocol.md",
      read = "2026-10-20",
      note = "L4: Gemini current-turn validation and user-text turn start",
    },
  },
  pairing = {
    validator = "codec",
    basis = "conservative:ChatCompletionsCodingProvider pairs tool_calls and tool_call_id directly (src/chat_provider.cpp:146-175)",
  },
  reasoning = {
    at_cut = "keep",
    at_rebind = "drop_foreign",
    side_request_reasoning = "keep",
    basis = {
      at_cut = "cited:thought_signatures",
      at_rebind = "conservative:foreign reasoning items are stripped across provider families (src/coding_provider.cpp:224-226)",
      side_request_reasoning = "conservative:a side request repeats the main request",
    },
  },
  turn = {
    start = "user_text",
    close = "none",
    open_turn = { "retain_current_turn", "closed_only" },
    boundary = {
      form = "user_note",
      enabled = false,
      basis = "conservative:boundary note not probed on Gemini",
    },
    basis = {
      start = "cited:thought_signatures",
      close = "cited:thought_signatures",
      open_turn = "cited:tribunal",
    },
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
    mode = "allowed",
    basis = "cited:thought_signatures",
  },
  cache = {
    capability = "implicit",
    basis = "cited:caching",
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
