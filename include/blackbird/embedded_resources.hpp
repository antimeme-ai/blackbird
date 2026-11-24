#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string_view>

namespace blackbird {

inline constexpr std::string_view embedded_turn_workflow_id = "builtin:turn.lua";
inline constexpr std::string_view embedded_results_instrument_id =
    "builtin:instruments/results.lua";
inline constexpr std::string_view embedded_profiles_location =
    "builtin:profiles/providers";

struct EmbeddedTextResource {
  std::string_view name;
  std::string_view content;
};

// All built-in shipped provider profiles (sorted by filename, e.g. "conservative.lua").
std::span<const EmbeddedTextResource> embedded_provider_profiles() noexcept;

// Built-in default turn workflow (programs/turn.lua).
std::string_view embedded_turn_workflow() noexcept;

// Built-in retained-result TUI instrument (programs/instruments/results.lua).
std::string_view embedded_results_instrument() noexcept;

// All built-in SaaS integration packs (sorted by service name, e.g. "linear").
std::span<const EmbeddedTextResource> embedded_saas_packs() noexcept;
std::optional<std::string_view>
find_embedded_saas_pack(std::string_view service) noexcept;

// Built-in SR-71 PNG asset (assets/sr71.png).
std::span<const std::byte> embedded_sr71_png() noexcept;

} // namespace blackbird
