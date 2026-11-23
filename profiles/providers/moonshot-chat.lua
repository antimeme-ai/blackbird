-- Profile `moonshot-chat`: Moonshot AI native Chat Completions route
-- (https://api.moonshot.ai/v1, src/provider_auth.cpp:316; kimi-k2-0905-preview and
-- kimi-k2-thinking, 256k context window, src/coding_provider.cpp:190-192).
-- Uses `must_keep` reasoning protection per docs/CONTEXT_LIFECYCLE.md §6.2 and
-- provider_protocol.md L2 for Moonshot Kimi thinking models, with automatic prefix caching.
return {
  schema = "blackbird.provider-profile/1",
  id = "moonshot-chat",
  revision = 1,
  match = { provider = "moonshot", protocol = "chat" },
  sources = {
    thinking = {
      url = "https://platform.kimi.ai/docs/guide/use-thinking-models",
      read = "2026-10-20",
      title = "Kimi Thinking Models",
    },
    tribunal = {
      path = "papers/clm-a1v-2026-10-19/design-tribunal/provider_protocol.md",
      read = "2026-10-20",
      note = "L2: Kimi/Moonshot must_keep reasoning_content protection",
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
      at_cut = "cited:thinking",
      at_rebind = "conservative:foreign reasoning items are stripped across provider families (src/coding_provider.cpp:224-226)",
      side_request_reasoning = "cited:thinking",
    },
  },
  turn = {
    start = "user_text",
    close = "none",
    open_turn = { "closed_only" },
    boundary = {
      form = "user_note",
      enabled = false,
      basis = "conservative:boundary note not probed on Moonshot",
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
    basis = "unobserved:Moonshot automatic prefix caching reports cached_tokens in usage; not yet live-probed",
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
