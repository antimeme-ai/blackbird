#include "blackbird/terminal_notify.hpp"
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace blackbird;

namespace {

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

EnvLookupFn make_env(std::map<std::string, std::string> values) {
  return
      [values = std::move(values)](std::string_view key) -> std::optional<std::string> {
        const auto it = values.find(std::string{key});
        if (it == values.end())
          return std::nullopt;
        return it->second;
      };
}

void test_terminal_detection_and_formatting() {
  // 1. Kitty -> OSC 99
  {
    const auto env = make_env({{"KITTY_WINDOW_ID", "4"}, {"TERM", "xterm-kitty"}});
    const auto target = detect_terminal_notify_target(env);
    check(target.protocol == TerminalNotifyProtocol::osc99,
          "expected OSC 99 for Kitty");
    check(!target.tmux_passthrough, "expected no tmux passthrough");
    const std::string seq =
        format_terminal_notification(target, {"Blackbird", "Turn complete", 7U});
    check(seq == "\x1b]99;i=7:d=0:p=title;Blackbird\x1b\\"
                 "\x1b]99;i=7:d=1:p=body;Turn complete\x1b\\",
          "unexpected Kitty OSC 99 frame");
  }

  // 2. Ghostty -> OSC 777
  {
    const auto env = make_env(
        {{"GHOSTTY_RESOURCES_DIR", "/Applications/Ghostty.app/Contents/Resources"}});
    const auto target = detect_terminal_notify_target(env);
    check(target.protocol == TerminalNotifyProtocol::osc777,
          "expected OSC 777 for Ghostty");
    const std::string seq =
        format_terminal_notification(target, {"Blackbird", "Party ping", 0U});
    check(seq == "\x1b]777;notify;Blackbird;Party ping\x1b\\",
          "unexpected Ghostty OSC 777 frame");
  }

  // 3. WezTerm -> OSC 777
  {
    const auto env = make_env({{"WEZTERM_PANE", "12"}});
    const auto target = detect_terminal_notify_target(env);
    check(target.protocol == TerminalNotifyProtocol::osc777,
          "expected OSC 777 for WezTerm");
  }

  // 4. iTerm2 -> OSC 9
  {
    const auto env = make_env({{"ITERM_SESSION_ID", "w0t0p0:1234"}});
    const auto target = detect_terminal_notify_target(env);
    check(target.protocol == TerminalNotifyProtocol::osc9, "expected OSC 9 for iTerm2");
    const std::string seq =
        format_terminal_notification(target, {"Blackbird", "Build finished", 0U});
    check(seq == "\x1b]9;Blackbird: Build finished\x1b\\",
          "unexpected iTerm2 OSC 9 frame");
  }

  // 5. tmux DCS passthrough with ESC doubling
  {
    const auto env = make_env({
        {"GHOSTTY_RESOURCES_DIR", "/opt/ghostty"},
        {"TMUX", "/tmp/tmux-1000/default,1234,0"},
    });
    const auto target = detect_terminal_notify_target(env);
    check(target.protocol == TerminalNotifyProtocol::osc777,
          "expected OSC 777 inside tmux");
    check(target.tmux_passthrough, "expected tmux passthrough enabled");
    const std::string seq =
        format_terminal_notification(target, {"Blackbird", "Ready", 0U});
    check(seq == "\x1bPtmux;\x1b\x1b]777;notify;Blackbird;Ready\x1b\x1b\\\x1b\\",
          "unexpected tmux DCS passthrough framing");
  }

  // 6. Kitty inside tmux wraps both OSC 99 chunks with doubled ESCs
  {
    const auto env = make_env({
        {"KITTY_WINDOW_ID", "1"},
        {"TMUX", "/tmp/tmux-1000/default,99,0"},
    });
    const auto target = detect_terminal_notify_target(env);
    const std::string seq = format_terminal_notification(target, {"T", "B", 3U});
    check(seq == "\x1bPtmux;\x1b\x1b]99;i=3:d=0:p=title;T\x1b\x1b\\\x1b\\"
                 "\x1bPtmux;\x1b\x1b]99;i=3:d=1:p=body;B\x1b\x1b\\\x1b\\",
          "unexpected tmux-wrapped Kitty OSC 99 framing");
  }

  // 7. Dumb or unknown terminal -> no-op
  {
    const auto dumb_env = make_env({{"TERM", "dumb"}, {"KITTY_WINDOW_ID", "1"}});
    const auto dumb_target = detect_terminal_notify_target(dumb_env);
    check(dumb_target.protocol == TerminalNotifyProtocol::none,
          "dumb terminal must disable notifications");
    std::ostringstream out;
    check(!emit_terminal_notification(out, dumb_env, {"Blackbird", "Hello", 0U}),
          "dumb terminal emit must return false");
    check(out.str().empty(), "dumb terminal must write zero bytes");

    const auto unknown_env = make_env({{"TERM", "xterm-256color"}});
    check(detect_terminal_notify_target(unknown_env).protocol ==
              TerminalNotifyProtocol::none,
          "unknown terminal must be no-op");
  }
}

void test_hostile_escape_and_bidi_sanitization() {
  // Attempt ESC, BEL, ST, C1 8-bit OSC/ST (U+009D, U+009C), BiDi RLO (U+202E),
  // zero-width space (U+200B), Unicode Tag (U+E0041), raw invalid UTF-8 0x9B, and `;`.
  const std::string hostile_title =
      "BB;\x1b]52;c;ZXZpbA==\x07\x1b\\\xC2\x9C\xC2\x9D\xE2\x80\xAE"
      "evil";
  static constexpr char kHostileBodyRaw[] = "ok\n\t\r\x00\x07\x1b[31mred\x7f\x9b"
                                            "\xE2\x80\x8B\xF3\xA0\x81\x81safe";
  const std::string hostile_body(kHostileBodyRaw, sizeof(kHostileBodyRaw) - 1U);

  const std::string clean_title = sanitize_terminal_notify_text(hostile_title);
  check(clean_title.find('\x1b') == std::string::npos, "ESC leaked into title");
  check(clean_title.find('\x07') == std::string::npos, "BEL leaked into title");
  check(clean_title.find("\xC2\x9C") == std::string::npos, "C1 ST leaked into title");
  check(clean_title.find("\xC2\x9D") == std::string::npos, "C1 OSC leaked into title");
  check(clean_title.find("\xE2\x80\xAE") == std::string::npos, "BiDi RLO leaked");

  const std::string clean_body = sanitize_terminal_notify_text(hostile_body);
  check(clean_body == "ok [31mredsafe", "unexpected sanitized body");

  // Verify OSC 777 frame has ZERO raw ESC/BEL inside payload and exact 3 semicolons.
  const std::string frame = format_terminal_notification(
      {TerminalNotifyProtocol::osc777, false}, {hostile_title, hostile_body, 0U});
  check(frame.starts_with("\x1b]777;notify;"), "missing OSC 777 prefix");
  check(frame.ends_with("\x1b\\"), "missing ST terminator");
  const std::string_view inner = std::string_view{frame}.substr(
      2U, frame.size() - 4U); // strip leading ESC] and trailing ESC\ .
  check(inner.find('\x1b') == std::string_view::npos,
        "raw ESC injected inside OSC 777 payload");
  check(inner.find('\x07') == std::string_view::npos,
        "raw BEL injected inside OSC 777 payload");

  std::size_t semicolons = 0U;
  for (const char ch : inner) {
    if (ch == ';')
      ++semicolons;
  }
  check(semicolons == 3U, "title/body semicolons forged extra OSC 777 fields");

  // UTF-8 safe truncation: 4-byte emoji must never be split mid-codepoint.
  const std::string emoji_text = "a\xF0\x9F\x9A\x80"
                                 "b"; // a + rocket (4B) + b
  check(sanitize_terminal_notify_text(emoji_text, 3U) == "a",
        "truncation must not split multi-byte UTF-8 sequence");
  check(sanitize_terminal_notify_text(emoji_text, 5U) == "a\xF0\x9F\x9A\x80",
        "truncation must preserve full 4-byte UTF-8 sequence when it fits");
}

void test_emit_writes_to_stream() {
  const auto env = make_env({{"GHOSTTY_RESOURCES_DIR", "/opt/ghostty"}});
  std::ostringstream out;
  const bool wrote = emit_terminal_notification(out, env, {"Blackbird", "Done", 0U});
  check(wrote, "expected emit_terminal_notification to return true");
  check(out.str() == "\x1b]777;notify;Blackbird;Done\x1b\\",
        "unexpected emitted stream content");
}

} // namespace

int main() {
  try {
    test_terminal_detection_and_formatting();
    test_hostile_escape_and_bidi_sanitization();
    test_emit_writes_to_stream();
    std::cout << "terminal_notify_test: all checks passed\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "terminal_notify_test FAILED: " << ex.what() << '\n';
    return 1;
  }
}
