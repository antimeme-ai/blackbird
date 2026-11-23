#include "blackbird/terminal_notify.hpp"
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <string>
#include <string_view>

namespace blackbird {
namespace {

bool env_non_empty(const EnvLookupFn &env, std::string_view key) {
  if (!env)
    return false;
  const auto val = env(key);
  return val.has_value() && !val->empty();
}

std::string env_value(const EnvLookupFn &env, std::string_view key) {
  if (!env)
    return {};
  const auto val = env(key);
  return val.has_value() ? *val : std::string{};
}

// Decode one UTF-8 scalar value starting at `pos`, advancing `pos`.
// Returns std::nullopt and advances by 1 byte on invalid UTF-8 sequences.
std::optional<std::uint32_t> decode_utf8_step(std::string_view input,
                                              std::size_t &pos) noexcept {
  if (pos >= input.size())
    return std::nullopt;
  const auto b0 = static_cast<unsigned char>(input[pos]);
  if (b0 < 0x80U) {
    ++pos;
    return static_cast<std::uint32_t>(b0);
  }
  if (b0 >= 0xC2U && b0 <= 0xDFU) {
    if (pos + 1U >= input.size()) {
      ++pos;
      return std::nullopt;
    }
    const auto b1 = static_cast<unsigned char>(input[pos + 1U]);
    if ((b1 & 0xC0U) != 0x80U) {
      ++pos;
      return std::nullopt;
    }
    pos += 2U;
    return (static_cast<std::uint32_t>(b0 & 0x1FU) << 6U) |
           static_cast<std::uint32_t>(b1 & 0x3FU);
  }
  if (b0 >= 0xE0U && b0 <= 0xEFU) {
    if (pos + 2U >= input.size()) {
      ++pos;
      return std::nullopt;
    }
    const auto b1 = static_cast<unsigned char>(input[pos + 1U]);
    const auto b2 = static_cast<unsigned char>(input[pos + 2U]);
    if ((b1 & 0xC0U) != 0x80U || (b2 & 0xC0U) != 0x80U) {
      ++pos;
      return std::nullopt;
    }
    if ((b0 == 0xE0U && b1 < 0xA0U) || (b0 == 0xEDU && b1 >= 0xA0U)) {
      ++pos;
      return std::nullopt;
    }
    pos += 3U;
    return (static_cast<std::uint32_t>(b0 & 0x0FU) << 12U) |
           (static_cast<std::uint32_t>(b1 & 0x3FU) << 6U) |
           static_cast<std::uint32_t>(b2 & 0x3FU);
  }
  if (b0 >= 0xF0U && b0 <= 0xF4U) {
    if (pos + 3U >= input.size()) {
      ++pos;
      return std::nullopt;
    }
    const auto b1 = static_cast<unsigned char>(input[pos + 1U]);
    const auto b2 = static_cast<unsigned char>(input[pos + 2U]);
    const auto b3 = static_cast<unsigned char>(input[pos + 3U]);
    if ((b1 & 0xC0U) != 0x80U || (b2 & 0xC0U) != 0x80U || (b3 & 0xC0U) != 0x80U) {
      ++pos;
      return std::nullopt;
    }
    if ((b0 == 0xF0U && b1 < 0x90U) || (b0 == 0xF4U && b1 >= 0x90U)) {
      ++pos;
      return std::nullopt;
    }
    pos += 4U;
    return (static_cast<std::uint32_t>(b0 & 0x07U) << 18U) |
           (static_cast<std::uint32_t>(b1 & 0x3FU) << 12U) |
           (static_cast<std::uint32_t>(b2 & 0x3FU) << 6U) |
           static_cast<std::uint32_t>(b3 & 0x3FU);
  }
  ++pos;
  return std::nullopt;
}

bool is_forbidden_notify_codepoint(std::uint32_t cp) noexcept {
  // C0 controls, DEL, C1 controls (including 8-bit ESC/CSI/OSC/ST 0x9B..0x9D)
  if (cp <= 0x1FU || cp == 0x7FU || (cp >= 0x80U && cp <= 0x9FU))
    return true;
  // Unicode line/paragraph separators
  if (cp == 0x2028U || cp == 0x2029U)
    return true;
  // BiDi controls and isolates
  if (cp == 0x061CU || cp == 0x200EU || cp == 0x200FU ||
      (cp >= 0x202AU && cp <= 0x202EU) || (cp >= 0x2066U && cp <= 0x2069U)) {
    return true;
  }
  // Zero-width characters and BOM
  if ((cp >= 0x200BU && cp <= 0x200DU) || cp == 0xFEFFU)
    return true;
  // Unicode Tag characters (invisible smuggling)
  if (cp >= 0xE0000U && cp <= 0xE007FU)
    return true;
  return false;
}

std::string sanitize_osc_field_value(std::string_view sanitized) {
  // Prevent `;` inside a title/field from forging extra OSC 777/99 parameters.
  std::string out;
  out.reserve(sanitized.size());
  for (const char ch : sanitized)
    out.push_back(ch == ';' ? ':' : ch);
  return out;
}

std::string wrap_tmux_passthrough(std::string_view osc_frame) {
  std::string out;
  out.reserve(osc_frame.size() + 16U);
  out.append("\x1bPtmux;");
  for (const char ch : osc_frame) {
    if (ch == '\x1b')
      out.push_back('\x1b');
    out.push_back(ch);
  }
  out.append("\x1b\\");
  return out;
}

} // namespace

std::optional<std::string> process_env_lookup(std::string_view name) {
  if (name.empty() || name.find('\0') != std::string_view::npos)
    return std::nullopt;
  const std::string key{name};
  const char *val = std::getenv(key.c_str());
  if (val == nullptr)
    return std::nullopt;
  return std::string{val};
}

TerminalNotifyTarget detect_terminal_notify_target(const EnvLookupFn &env) {
  TerminalNotifyTarget target{};
  if (!env)
    return target;

  const std::string term = env_value(env, "TERM");
  if (term == "dumb")
    return target;

  target.tmux_passthrough = env_non_empty(env, "TMUX");

  const std::string term_program = env_value(env, "TERM_PROGRAM");

  if (env_non_empty(env, "KITTY_WINDOW_ID") || term == "xterm-kitty") {
    target.protocol = TerminalNotifyProtocol::osc99;
    return target;
  }
  if (env_non_empty(env, "GHOSTTY_RESOURCES_DIR") || term_program == "ghostty" ||
      term == "xterm-ghostty") {
    target.protocol = TerminalNotifyProtocol::osc777;
    return target;
  }
  if (env_non_empty(env, "WEZTERM_PANE") || term_program == "WezTerm") {
    target.protocol = TerminalNotifyProtocol::osc777;
    return target;
  }
  if (env_non_empty(env, "ITERM_SESSION_ID") || term_program == "iTerm.app") {
    target.protocol = TerminalNotifyProtocol::osc9;
    return target;
  }
  if (term_program == "foot" || term.starts_with("foot")) {
    target.protocol = TerminalNotifyProtocol::osc777;
    return target;
  }

  target.protocol = TerminalNotifyProtocol::none;
  target.tmux_passthrough = false;
  return target;
}

std::string sanitize_terminal_notify_text(std::string_view raw, std::size_t max_bytes) {
  if (max_bytes == 0U || raw.empty())
    return {};

  std::string out;
  out.reserve(raw.size() < max_bytes ? raw.size() : max_bytes);

  std::size_t pos = 0U;
  while (pos < raw.size()) {
    const std::size_t start = pos;
    const auto cp = decode_utf8_step(raw, pos);
    if (!cp.has_value())
      continue;

    // Collapse line breaks and tabs to a single space so notifications stay
    // single-line.
    if (*cp == '\n' || *cp == '\r' || *cp == '\t') {
      if (!out.empty() && out.back() != ' ') {
        if (out.size() + 1U > max_bytes)
          break;
        out.push_back(' ');
      }
      continue;
    }

    if (is_forbidden_notify_codepoint(*cp))
      continue;

    const std::size_t seq_len = pos - start;
    if (out.size() + seq_len > max_bytes)
      break;
    out.append(raw.substr(start, seq_len));
  }

  while (!out.empty() && out.back() == ' ')
    out.pop_back();
  return out;
}

std::string format_terminal_notification(TerminalNotifyTarget target,
                                         const TerminalNotification &note) {
  if (target.protocol == TerminalNotifyProtocol::none)
    return {};

  const std::string title = sanitize_terminal_notify_text(note.title);
  const std::string body = sanitize_terminal_notify_text(note.body);
  if (title.empty() && body.empty())
    return {};

  auto maybe_wrap = [&](std::string_view frame) {
    return target.tmux_passthrough ? wrap_tmux_passthrough(frame) : std::string{frame};
  };

  switch (target.protocol) {
  case TerminalNotifyProtocol::none:
    return {};
  case TerminalNotifyProtocol::osc9: {
    std::string message;
    if (!title.empty() && !body.empty()) {
      message = title + ": " + body;
    } else if (!title.empty()) {
      message = title;
    } else {
      message = body;
    }
    const std::string frame = "\x1b]9;" + message + "\x1b\\";
    return maybe_wrap(frame);
  }
  case TerminalNotifyProtocol::osc777: {
    const std::string safe_title =
        sanitize_osc_field_value(title.empty() ? "Blackbird" : title);
    const std::string safe_body = sanitize_osc_field_value(body);
    const std::string frame =
        "\x1b]777;notify;" + safe_title + ";" + safe_body + "\x1b\\";
    return maybe_wrap(frame);
  }
  case TerminalNotifyProtocol::osc99: {
    const std::string id_prefix =
        note.id > 0U ? ("i=" + std::to_string(note.id) + ":") : std::string{};
    const std::string safe_title = sanitize_osc_field_value(title);
    const std::string safe_body = sanitize_osc_field_value(body);
    if (!safe_title.empty() && !safe_body.empty()) {
      const std::string title_frame =
          "\x1b]99;" + id_prefix + "d=0:p=title;" + safe_title + "\x1b\\";
      const std::string body_frame =
          "\x1b]99;" + id_prefix + "d=1:p=body;" + safe_body + "\x1b\\";
      return maybe_wrap(title_frame) + maybe_wrap(body_frame);
    }
    if (!safe_title.empty()) {
      const std::string title_frame =
          "\x1b]99;" + id_prefix + "d=1:p=title;" + safe_title + "\x1b\\";
      return maybe_wrap(title_frame);
    }
    const std::string body_frame =
        "\x1b]99;" + id_prefix + "d=1:p=body;" + safe_body + "\x1b\\";
    return maybe_wrap(body_frame);
  }
  }
  return {};
}

bool emit_terminal_notification(std::ostream &out, const EnvLookupFn &env,
                                const TerminalNotification &note) {
  const TerminalNotifyTarget target = detect_terminal_notify_target(env);
  const std::string seq = format_terminal_notification(target, note);
  if (seq.empty())
    return false;
  out.write(seq.data(), static_cast<std::streamsize>(seq.size()));
  out.flush();
  return static_cast<bool>(out);
}

} // namespace blackbird
