-- Profile `mimo-chat`: Xiaomi MiMo native Chat Completions route
-- (https://api.xiaomimimo.com/v1, src/provider_auth.cpp:303; mimo-v2-flash, 128k context
-- window, src/coding_provider.cpp:197-199).
-- Per docs/CONTEXT_LIFECYCLE.md §6.2 and provider_mechanisms.md Q4, MiMo recommends
-- keeping `reasoning_content` across tool turns (`keep`) and reports automatic prefix
-- caching via `prompt_tokens_details.cached_tokens`.
return {
  schema = "blackbird.provider-profile/1",
  id = "mimo-chat",
  revision = 1,
  match = { provider = "mimo", protocol = "chat" },
  sources = {
    openai_api = {
      url = "https://mimo.mi.com/static/docs/api/chat/openai-api.md",
      read = "2026-10-19",
      title = "MiMo OpenAI-compatible API",
    },
    tribunal = {
      path = "papers/clm-a1v-2026-10-19/design-tribunal/provider_protocol.md",
      read = "2026-10-20",
      note = "Verified: MiMo keeps reasoning_content across tool turns",
    },
  },
  pairing = {
    validator = "codec",
    basis = "cited:openai_api",
  },
  reasoning = {
    at_cut = "keep",
    at_rebind = "drop_foreign",
    side_request_reasoning = "keep",
    basis = {
      at_cut = "cited:openai_api",
      at_rebind = "conservative:foreign reasoning items are stripped across provider families (src/coding_provider.cpp:224-226)",
      side_request_reasoning = "cited:openai_api",
    },
  },
  turn = {
    start = "user_text",
    close = "none",
    open_turn = { "closed_only" },
    boundary = {
      form = "user_note",
      enabled = false,
      basis = "conservative:boundary note not probed on MiMo",
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
    basis = "conservative:matches today: ChatCompletionsCodingProvider renders developer items as system messages (src/chat_provider.cpp:191); note placement probe pending (§20)",
  },
  archival = {
    mode = "allowed",
    basis = "cited:tribunal",
  },
  cache = {
    capability = "implicit",
    basis = "cited:openai_api",
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
