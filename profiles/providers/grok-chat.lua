-- Profile `grok-chat`: xAI Grok native Chat Completions route
-- (https://api.x.ai/v1, src/provider_auth.cpp:304-309; grok-4 and grok-code-fast-1 with
-- 256k context window, grok-3 and grok-3-mini with 131k / 131,072 context window,
-- src/coding_provider.cpp:190-196).
-- Per docs/CONTEXT_LIFECYCLE.md §6.2 and provider_protocol.md F7, xAI keeps retained
-- reasoning verbatim (`keep`), reports `context_length_exceeded` on overflow, and runs
-- automatic prefix caching.
return {
  schema = "blackbird.provider-profile/1",
  id = "grok-chat",
  revision = 1,
  match = { provider = "grok", protocol = "chat" },
  sources = {
    compaction = {
      url = "https://docs.x.ai/developers/advanced-api-usage/context-compaction.md",
      read = "2026-10-20",
      title = "xAI Context Compaction",
    },
    tribunal = {
      path = "papers/clm-a1v-2026-10-19/design-tribunal/provider_protocol.md",
      read = "2026-10-20",
      note = "F7 and Verified: xAI context_length_exceeded and keep reasoning rule",
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
      at_cut = "cited:tribunal",
      at_rebind = "conservative:foreign reasoning items are stripped across provider families (src/coding_provider.cpp:224-226)",
      side_request_reasoning = "conservative:a side request repeats the main request",
    },
  },
  turn = {
    start = "user_text",
    close = "none",
    open_turn = { "closed_only" },
    boundary = {
      form = "user_note",
      enabled = false,
      basis = "conservative:boundary note not probed on xAI Grok",
    },
    basis = "conservative:settle only at closed turns until probed",
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
    basis = "cited:tribunal",
  },
  cache = {
    capability = "implicit",
    basis = "unobserved:xAI automatic prefix caching reports prompt_tokens_details.cached_tokens; not yet live-probed",
  },
  errors = {
    {
      class = "context_overflow",
      code = "context_length_exceeded",
      basis = "cited:compaction",
    },
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
