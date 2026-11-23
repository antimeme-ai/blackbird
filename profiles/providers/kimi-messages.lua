-- Profile `kimi-messages`: Kimi Coding Messages route
-- (https://api.kimi.com/coding/v1, src/provider_auth.cpp:297-301; kimi-for-coding and
-- kimi-k2-thinking, 256k context window, src/coding_provider.cpp:190-192).
-- Routed through AnthropicCodingProvider (src/main.cpp:1016-1022) with `must_keep`
-- reasoning protection per docs/CONTEXT_LIFECYCLE.md §6.2 and provider_protocol.md L2.
return {
  schema = "blackbird.provider-profile/1",
  id = "kimi-messages",
  revision = 1,
  match = { provider = "kimi", protocol = "messages" },
  sources = {
    thinking = {
      url = "https://platform.kimi.ai/docs/guide/use-thinking-models",
      read = "2026-10-20",
      title = "Kimi Thinking Models",
    },
    tribunal = {
      path = "papers/clm-a1v-2026-10-19/design-tribunal/provider_protocol.md",
      read = "2026-10-20",
      note = "L2: Kimi must_keep reasoning_content protection",
    },
  },
  pairing = {
    validator = "anthropic-messages",
    basis = "conservative:Kimi Coding uses AnthropicCodingProvider Messages wire format (src/main.cpp:1016-1022)",
  },
  reasoning = {
    at_cut = "must_keep",
    at_rebind = "drop_foreign",
    side_request_reasoning = "keep",
    basis = {
      at_cut = "cited:thinking",
      at_rebind = "conservative:drop foreign reasoning across provider families",
      side_request_reasoning = "cited:thinking",
    },
  },
  turn = {
    start = "user_message_without_results",
    close = "reply_request",
    open_turn = { "closed_only" },
    boundary = {
      form = "reply_then_note",
      enabled = false,
      basis = "conservative:boundary note not probed on Kimi",
    },
    basis = {
      start = "conservative:AnthropicCodingProvider merges consecutive user-role blocks into one user message (src/anthropic_provider.cpp:346-351)",
      close = "unobserved:closing reply with tool_choice none to end an open Messages tool turn; not yet live-probed on Kimi",
      open_turn = "conservative:settle only at closed turns until probed",
    },
  },
  request_state = {
    placement = "retained_in_place",
    basis = "conservative:matches today: AnthropicCodingProvider::retain_request_state() is true (include/blackbird/anthropic_provider.hpp:18)",
  },
  note = {
    role = "developer_as_user_text",
    placement = "after_tool_results",
    basis = "conservative:matches today: AnthropicCodingProvider renders developer items as user text after tool results (src/anthropic_provider.cpp:428-434)",
  },
  archival = {
    mode = "allowed",
    basis = "cited:tribunal",
  },
  cache = {
    capability = "none",
    basis = "conservative:no Kimi Messages cache controls configured until probed",
  },
  effort = {
    values = { "low", "medium", "high" },
    basis = "conservative:matches route_efforts for non-Anthropic messages routes (src/main.cpp:844-845)",
  },
  output = {
    max_tokens = 16384,
    basis = "conservative:matches AnthropicConfig::max_tokens default (include/blackbird/anthropic_provider.hpp:9)",
  },
}
