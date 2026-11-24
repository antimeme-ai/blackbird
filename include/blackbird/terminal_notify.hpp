#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>

namespace blackbird {

inline constexpr std::size_t kDefaultTerminalNotifyMaxBytes = 512U;

enum class TerminalNotifyProtocol : std::uint8_t {
  none,
  osc9,
  osc777,
  osc99,
};

struct TerminalNotifyTarget {
  TerminalNotifyProtocol protocol = TerminalNotifyProtocol::none;
  bool tmux_passthrough = false;

  friend constexpr bool operator==(TerminalNotifyTarget,
                                   TerminalNotifyTarget) noexcept = default;
};

struct TerminalNotification {
  std::string title;
  std::string body;
  std::uint64_t id = 0U;
};

using EnvLookupFn = std::function<std::optional<std::string>(std::string_view)>;

// Detect terminal notification protocol and tmux DCS passthrough support from env.
TerminalNotifyTarget detect_terminal_notify_target(const EnvLookupFn &env);

// Default process environment lookup helper.
std::optional<std::string> process_env_lookup(std::string_view name);

// Strict sanitization stripping C0/DEL/C1/ESC/BEL/ST/BiDi/zero-width/Unicode-Tag
// codepoints and truncating cleanly at UTF-8 codepoint boundaries.
std::string
sanitize_terminal_notify_text(std::string_view raw,
                              std::size_t max_bytes = kDefaultTerminalNotifyMaxBytes);

// Format an OSC 9, OSC 777, or Kitty OSC 99 sequence (with optional tmux DCS
// passthrough ESC-doubling). Returns an empty string when target.protocol == none or
// content is empty.
std::string format_terminal_notification(TerminalNotifyTarget target,
                                         const TerminalNotification &note);

// Detect target, format, write, and flush to `out`. Returns true iff bytes were
// written.
bool emit_terminal_notification(std::ostream &out, const EnvLookupFn &env,
                                const TerminalNotification &note);

} // namespace blackbird
