#include "blackbird/terminal.hpp"
#include "blackbird/command_inspector.hpp"
#include "blackbird/display_text.hpp"
#include "blackbird/flight_deck_hero.hpp"
#include "blackbird/json.hpp"
#include "blackbird/local_timing.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/process_lifetime.hpp"
#include "blackbird/raw_command.hpp"
#include "blackbird/raw_file.hpp"
#include "blackbird/raw_runtime.hpp"
#include "blackbird/retained_state.hpp"
#include "blackbird/sprite.hpp"
#include "blackbird/task_view.hpp"
#include "blackbird/terminal_custody.hpp"
#include "blackbird/tools.hpp"
#include "blackbird/workflows.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <clocale>
#include <cmath>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <poll.h>
#include <spawn.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <thread>
#include <tuple>
#include <unistd.h>
extern char **environ;
namespace blackbird {
namespace {
using ChatCommand = ComposerChoice;
const std::array builtin_commands{
    ChatCommand{"/help", "", "Command guide (immediate in TUI)", "Chat"},
    ChatCommand{"/keys", "", "Keyboard guide (TUI only)", "Chat"},
    ChatCommand{"/commands", "",
                "Search command palette; Ctrl-Space or Ctrl-T (TUI only)", "Chat"},
    ChatCommand{"/views", "", "Switch local views; Ctrl-\\ preserves the draft",
                "View"},
    ChatCommand{"/mouse", "[on|off]",
                "Wheel scrolls transcript; default off keeps plain-drag selection "
                "(TUI only)",
                "View"},
    ChatCommand{
        "/edit", "",
        "Open a blank draft in $VISUAL/$EDITOR; Ctrl-G edits current draft (idle TUI)",
        "Chat"},
    ChatCommand{"/queue", "", "Show pending prompts (TUI only)", "Chat"},
    ChatCommand{"/cancel", "", "Request stop and clear pending queue (TUI only)",
                "Chat"},
    ChatCommand{"/clear", "", "Clear display, not model context (TUI only)", "Chat"},
    ChatCommand{"/copy", "[all|user]",
                "Copy last reply (or transcript/prompt) via OSC 52 (TUI only)", "Chat"},
    ChatCommand{"/drafts", "", "List recovered drafts (TUI only)", "Chat"},
    ChatCommand{"/draft", "NUMBER",
                "Load a recovered draft; explicit Enter sends (TUI only)", "Chat"},
    ChatCommand{"/quit", "", "Stop work and exit; preserve draft", "Chat"},
    ChatCommand{"/exit", "", "Alias for /quit", "Chat"},
    ChatCommand{"/provider", "[ID [MODEL]]",
                "Switch provider (and optional model) or pick interactively",
                "Session"},
    ChatCommand{"/model", "NAME",
                "Change model or pick interactively (empty opens list)", "Session"},
    ChatCommand{"/effort", "LEVEL", "Set low, medium, high, xhigh or max (empty picks)",
                "Session"},
    ChatCommand{"/session", "", "Current session and settings", "Session"},
    ChatCommand{"/cwd", "[PATH]", "Show or change the current working directory",
                "Session"},
    ChatCommand{"/new", "", "Start a fresh saved session; keep current settings",
                "Session"},
    ChatCommand{"/sessions", "",
                "Pick a neighbouring saved session (list in plain mode)", "Session"},
    ChatCommand{"/resume", "DIRECTORY",
                "Return to a saved session without sending a turn", "Session"},
    ChatCommand{"/name", "[NAME]", "Name this session; empty clears its name",
                "Session"},
    ChatCommand{"/checkpoint", "", "Save session state and retry maintenance",
                "Session"},
    ChatCommand{"/stats", "", "Context bytes and observed provider usage", "Session"},
    ChatCommand{"/profile", "", "Provider profile in force: layers, basis, digests",
                "Session"},
    ChatCommand{"/tasks",
                "[add TITLE | sub ID TITLE | done ID | block ID REASON | rename ID "
                "TITLE | read JSON | apply JSON]",
                "Shared tasks; up/down, fold ID, expand/show/hide control pane",
                "Tasks"},
    ChatCommand{"/context", "", "Inspect editable model context", "Context"},
    ChatCommand{"/originals", "", "Retained context originals", "Context"},
    ChatCommand{"/compact", "JSON", "Managed context transformation", "Context"},
    ChatCommand{"/inspect", "JSON", "Bounded retained context inspection", "Context"},
    ChatCommand{"/restore", "ENTRY", "Restore an original context entry", "Context"},
    ChatCommand{"/workbench", "",
                "Open interactive context block workbench (local TUI)", "Context"},
    ChatCommand{"/hooks",
                "[list | history | enable NAME | disable NAME | explain JSON]",
                "Inspect hooks, revisions and dispatch history (TUI view or plain)",
                "Programs"},
    ChatCommand{"/lua", "CODE", "Run a Lua workflow", "Programs"},
    ChatCommand{"/workflow", "FILE", "Select the turn workflow", "Programs"},
    ChatCommand{"/restart", "NOTE", "Request native restart; build replacement first",
                "Programs"},
    ChatCommand{"/decision", "JSON", "Evaluate a native decision-model batch (Jev)",
                "Tools"},
    ChatCommand{"/exec", "JSON", "Launch a command; yield_ms releases its wait",
                "Tools"},
    ChatCommand{"/instrument", "[reload|preview PATH]",
                "Authored retained-result comparison (local TUI)", "View"},
    ChatCommand{"/center", "",
                "Open current-session work; Ctrl-X preserves draft (TUI)", "TUI"},
    ChatCommand{"/jobs", "", "Open command results; Ctrl-O preserves draft (TUI)",
                "Tools"},
    ChatCommand{"/fg", "JOB", "Wait for the same command; PTY text input", "Tools"},
    ChatCommand{"/bg", "[JOB]",
                "Release foreground wait immediately; keep command running", "Tools"},
    ChatCommand{"/process", "JSON",
                "Shared command read/input/signal/resize/stop controls", "Tools"},
    ChatCommand{"/runs", "[ID | configure JSON | archive ID]",
                "Read observed participant runs, configure concurrency or archive a "
                "settled run",
                "Participants"},
    ChatCommand{"/run", "JSON",
                "Start a selected-context participant: request, optional task_id",
                "Participants"},
    ChatCommand{
        "/send", "JSON",
        "Address direction by run_id, message_id, from, text; next request boundary",
        "Participants"},
    ChatCommand{"/join", "JSON",
                "Seal run_ids, drain accepted directions, return in declared order",
                "Participants"},
    ChatCommand{
        "/await", "JSON",
        "Wait for run_id and accepted directions; keep run open. Optional timeout_ms",
        "Participants"},
    ChatCommand{"/stop", "ID",
                "Request participant cancellation; observe settlement separately",
                "Participants"},
    ChatCommand{"/auth", "status | providers",
                "Provider account metadata; sign in outside chat", "Configuration"},
    ChatCommand{"/colleagues", "",
                "Show installed colleague transports; authentication observed on call",
                "Tools"},
    ChatCommand{"/variables", "[JSON]", "Read central-variable point observations",
                "Tools"},
    ChatCommand{"/correlate", "[JSON]",
                "Plot timed work and variable observations on UTC lanes", "Tools"},
    ChatCommand{"/git-observe", "JSON",
                "Observe Git HEAD and optional bounded history; no changes", "Tools"},
    ChatCommand{"/trace", "[JSON]",
                "Read committed trajectory; bounded pages and attempt filter", "Tools"},
    ChatCommand{"/colleague", "JSON",
                "One selected-context colleague request; no tools or retries", "Tools"},
    ChatCommand{"/beads",
                "configure JSON | ready | list | show ID | select ID | cached",
                "Explicit native Beads refresh/selection (lazy binding)", "Tools"},
    ChatCommand{"/platoon", "[status|board|members|post TEXT]",
                "Inspect or post to the project platoon board and worktree leases",
                "Command Post"},
    ChatCommand{"/issues", "[ready|list|create TITLE|claim ID|close ID]",
                "Inspect or update project issues (.blackbird/issues)", "Command Post"},
    ChatCommand{"/memory", "[recent|recall QUERY|record KIND TITLE :: BODY|verify]",
                "Recall, record and SHA-256 verify project memory", "Command Post"},
    ChatCommand{"/capabilities", "[list|show ID]",
                "Inspect skills and recipes catalog (read-only; never executes)",
                "Command Post"},
    ChatCommand{"/metrics", "[summary]",
                "Read-only tertiary metrics summary and Unicode sparklines",
                "Command Post"},
    ChatCommand{"/companion", "[status|ask QUESTION]",
                "System One decision companions (jev/clef) status and advisory",
                "Command Post"},
    ChatCommand{"/swarmboard", "[all|mentions|conflicts|watchers]",
                "Live read-only swarm roster, mentions, conflicts and watchers",
                "Command Post"},
    ChatCommand{"/flightdeck", "[tick N|detach]",
                "SR-71 flight deck telemetry, Kitty cockpit (Alt+F) and detach",
                "Command Post"},
    ChatCommand{"/party",
                "[status|peers|add ALIAS|all|operators|leaders|conflicts|say TEXT|"
                "create [ROOM]|join URI|invite [URL]|close|leave|remove ALIAS]",
                "Open/inspect Party Chat, manage peers, or message @all / @leader",
                "Command Post"},
    ChatCommand{"/online",
                "[status|health|whoami|resolve HANDLE|friends|friend add/remove/block|"
                "party create/info/invite/join/leave/disband]",
                "Manage multiplayer.tech account, friends, and online P2P parties",
                "Command Post"}};

std::shared_ptr<const std::vector<ChatCommand>>
command_catalog(std::size_t *capture_bound = nullptr) {
  thread_local std::shared_ptr<const WorkflowRegistry> previous;
  thread_local std::shared_ptr<const std::vector<ChatCommand>> cached;
  thread_local std::size_t bound = 0;
  const auto registry = displayed_workflows();
  if (!cached || previous != registry) {
    auto next = std::make_shared<std::vector<ChatCommand>>();
    std::size_t next_bound = 0;
    auto append = [&](ChatCommand command) {
      next_bound = std::max(next_bound,
                            command.name.size() +
                                static_cast<std::size_t>(!command.arguments.empty()));
      next->push_back(std::move(command));
    };
    for (const auto &command : builtin_commands)
      append(command);
    if (registry)
      for (const auto &d : registry->definitions().array())
        for (const auto &alias : field(d, "aliases").array())
          append({"/" + registry->prefix() + alias.string(), "ARGS",
                  field(d, "description").string(), "Workflows"});
    cached = std::move(next);
    bound = next_bound;
    previous = registry;
  }
  if (capture_bound)
    *capture_bound = bound;
  return cached;
}

std::string search_text(std::string_view text) {
  std::string out{text};
  for (auto &c : out)
    if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c + ('a' - 'A'));
  return out;
}
std::vector<std::size_t> palette_matches(std::string_view query,
                                         const std::vector<ChatCommand> &commands) {
  std::vector<std::size_t> matches;
  const auto needle = search_text(query);
  for (std::size_t n = 0; n < commands.size(); ++n) {
    const auto &command = commands[n];
    const auto haystack =
        search_text(std::string{command.name} + " " + std::string{command.description} +
                    " " + std::string{command.group} + " " + command.label);
    if (haystack.find(needle) != std::string::npos)
      matches.push_back(n);
  }
  auto rank = [&](std::size_t n) {
    auto name = search_text(commands[n].view ? commands[n].label : commands[n].name);
    auto exact = needle;
    if (exact.starts_with("/"))
      exact.erase(0, 1);
    if (commands[n].view ? name == needle : name.substr(1) == exact)
      return 0;
    if (name.find(needle) != std::string::npos)
      return 1;
    if (search_text(commands[n].description).find(needle) != std::string::npos)
      return 2;
    return 3;
  };
  std::stable_sort(matches.begin(), matches.end(),
                   [&](auto a, auto b) { return rank(a) < rank(b); });
  return matches;
}
bool command_token(std::string_view text) {
  return text.starts_with("/") &&
         text.find_first_of(" \t\r\n") == std::string_view::npos;
}
std::string complete_command(std::string_view text,
                             const std::vector<ChatCommand> &commands) {
  if (!command_token(text))
    return std::string{text};
  // An exact command wins over longer names (/draft versus /drafts).
  for (const auto &command : commands)
    if (command.name == text)
      return std::string{text} + (command.arguments.empty() ? "" : " ");
  std::string prefix;
  const ChatCommand *only = nullptr;
  std::size_t count = 0;
  for (const auto &command : commands) {
    if (!command.name.starts_with(text))
      continue;
    if (count++ == 0) {
      prefix = command.name;
      only = &command;
    } else {
      std::size_t n = 0;
      while (n < prefix.size() && n < command.name.size() &&
             prefix[n] == command.name[n])
        ++n;
      prefix.resize(n);
    }
  }
  if (count == 0)
    return std::string{text};
  if (count == 1 && !only->arguments.empty())
    prefix += ' ';
  return prefix;
}
bool continuation(char byte) {
  return (static_cast<unsigned char>(byte) & 0xc0U) == 0x80U;
}
std::size_t previous(std::string_view s, std::size_t cursor) {
  if (cursor == 0)
    return 0;
  --cursor;
  while (cursor > 0 && continuation(s[cursor]))
    --cursor;
  return cursor;
}
std::size_t next(std::string_view s, std::size_t cursor) {
  if (cursor < s.size())
    ++cursor;
  while (cursor < s.size() && continuation(s[cursor]))
    ++cursor;
  return cursor;
}
std::size_t line_start(std::string_view text, std::size_t cursor) {
  const auto newline =
      cursor == 0 ? std::string_view::npos : text.rfind('\n', cursor - 1);
  return newline == std::string_view::npos ? 0 : newline + 1;
}
std::size_t line_end(std::string_view text, std::size_t cursor) {
  const auto newline = text.find('\n', cursor);
  return newline == std::string_view::npos ? text.size() : newline;
}
std::size_t display_width(std::string_view text) { return display_cells(text).value; }

bool word_space(std::string_view text, std::size_t position) {
  // Whitespace-delimited words, rather than imposing a language's punctuation rules.
  const auto c = static_cast<unsigned char>(text[position]);
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}
std::size_t word_left(std::string_view text, std::size_t cursor) {
  while (cursor > 0 && word_space(text, previous(text, cursor)))
    cursor = previous(text, cursor);
  while (cursor > 0 && !word_space(text, previous(text, cursor)))
    cursor = previous(text, cursor);
  return cursor;
}
std::size_t word_right(std::string_view text, std::size_t cursor) {
  while (cursor < text.size() && word_space(text, cursor))
    cursor = next(text, cursor);
  while (cursor < text.size() && !word_space(text, cursor))
    cursor = next(text, cursor);
  return cursor;
}
} // namespace
std::optional<std::string_view> terminal_process_join(TerminalProcessJoin chunks) {
  const auto [queued, next] = chunks;
  // Background chunks carry "\n[command J]\n"; markers ("\n[exit 0]" etc.)
  // start a line of their own. Bytes after a background chunk have no marker,
  // so a joined entry could not be split back into its streams.
  const auto background = [](std::string_view text) {
    constexpr std::string_view marker = "\n[command ";
    const auto close = text.find("]\n");
    return text.starts_with(marker) && close != std::string_view::npos
               ? text.substr(0, close + 2)
               : std::string_view{};
  };
  const auto queued_job = background(queued), next_job = background(next);
  if (!next_job.empty())
    return next_job == queued_job ? std::optional{next.substr(next_job.size())}
                                  : std::nullopt;
  if (next.starts_with("\n[") || !queued_job.empty())
    return std::nullopt;
  return next;
}
std::string terminal_context_badge(std::string_view kind,
                                   std::optional<std::size_t> measured_before,
                                   std::optional<std::size_t> measured_after) {
  if (!measured_before || !measured_after)
    return "◆ CONTEXT " + std::string{kind}; // Size unknown: no invented delta.
  const auto bytes_before = *measured_before, bytes_after = *measured_after;
  const auto delta = bytes_after >= bytes_before ? bytes_after - bytes_before
                                                 : bytes_before - bytes_after;
  const auto size = delta < 1024 ? std::to_string(delta) + " B"
                                 : std::to_string((delta + 512) / 1024) + " KiB";
  const auto sign = delta == 0 ? "±" : bytes_after > bytes_before ? "+" : "−";
  return "◆ CONTEXT " + std::string{kind} + " " + sign + size;
}
std::string terminal_format_tokens(std::uint64_t count) {
  if (count < 1000ULL)
    return std::to_string(count);
  if (count < 100000ULL) {
    const auto tenths = (count + 50ULL) / 100ULL;
    if (tenths >= 1000ULL)
      return "100k";
    std::string out = std::to_string(tenths / 10ULL);
    if (tenths % 10ULL != 0ULL)
      out += "." + std::to_string(tenths % 10ULL);
    return out + "k";
  }
  if (count < 1000000ULL) {
    const auto k = (count + 500ULL) / 1000ULL;
    if (k >= 1000ULL)
      return "1M";
    return std::to_string(k) + "k";
  }
  const auto tenths = count / 100000ULL + (count % 100000ULL >= 50000ULL ? 1ULL : 0ULL);
  std::string out = std::to_string(tenths / 10ULL);
  if (tenths % 10ULL != 0ULL)
    out += "." + std::to_string(tenths % 10ULL);
  return out + "M";
}
namespace {
struct RatioInput {
  std::uint64_t num, scale, den;
};
std::uint64_t rounded_ratio(RatioInput r) noexcept {
  if (r.den == 0)
    return 0;
  const unsigned __int128 scaled =
      static_cast<unsigned __int128>(r.num) * static_cast<unsigned __int128>(r.scale);
  const unsigned __int128 half = static_cast<unsigned __int128>(r.den / 2ULL);
  const unsigned __int128 result =
      (scaled + half) / static_cast<unsigned __int128>(r.den);
  return result > UINT64_MAX ? UINT64_MAX : static_cast<std::uint64_t>(result);
}
std::string format_usd(double amount) {
  if (!std::isfinite(amount) || amount < 0.0)
    return {};
  if (amount >= 1e12)
    return "$1T+";
  const auto cents = static_cast<std::uint64_t>(amount * 100.0 + 0.5);
  if (cents == 0 && amount > 0.0)
    return "<$0.01";
  const auto whole = cents / 100ULL;
  const auto frac = cents % 100ULL;
  return "$" + std::to_string(whole) + "." + (frac < 10ULL ? "0" : "") +
         std::to_string(frac);
}
std::string format_stream_bytes(std::size_t bytes) {
  if (bytes < 1024U)
    return std::to_string(bytes) + " B";
  if (bytes < 1024U * 1024U) {
    const auto whole = bytes / 1024U;
    const auto rem = bytes % 1024U;
    const auto tenths = whole * 10U + (rem * 10U + 512U) / 1024U;
    if (tenths >= 10240U)
      return "1 MiB";
    std::string out = std::to_string(tenths / 10U);
    if (tenths % 10U != 0U)
      out += "." + std::to_string(tenths % 10U);
    return out + " KiB";
  }
  const auto whole = bytes / (1024U * 1024U);
  const auto rem = bytes % (1024U * 1024U);
  const auto extra = (rem * 10U + 524288U) / (1024U * 1024U);
  const auto m_whole = whole + (extra >= 10U ? 1U : 0U);
  const auto m_frac = extra >= 10U ? 0U : extra;
  std::string out = std::to_string(m_whole);
  if (m_frac != 0U)
    out += "." + std::to_string(m_frac);
  return out + " MiB";
}
std::string context_gauge_bar(std::uint64_t pct, bool utf8_locale) {
  constexpr std::size_t width = 8;
  const auto clamped = std::min<std::uint64_t>(pct, 100ULL);
  const auto filled = static_cast<std::size_t>(
      (clamped * static_cast<std::uint64_t>(width) + 50ULL) / 100ULL);
  std::string bar;
  bar.reserve(width * (utf8_locale ? 3U : 1U));
  for (std::size_t i = 0; i < width; ++i)
    bar += i < filled ? (utf8_locale ? "▓" : "#") : (utf8_locale ? "░" : "-");
  return bar;
}
} // namespace
std::string terminal_usage_summary(const TelemetrySnapshot &t) {
  std::string out;
  auto add = [&](std::string_view part) {
    if (part.empty())
      return;
    if (!out.empty())
      out += " · ";
    out.append(part);
  };
  if (t.last_input > 0) {
    std::string in_part = terminal_format_tokens(t.last_input) + " in";
    if (t.last_cached > 0) {
      const auto pct = std::min<std::uint64_t>(
          100ULL,
          rounded_ratio({.num = t.last_cached, .scale = 100ULL, .den = t.last_input}));
      in_part += " (" + std::to_string(pct) + "% cached)";
    }
    add(in_part);
  }
  if (t.last_output > 0)
    add(terminal_format_tokens(t.last_output) + " out");
  if (t.last_output > 0 && t.last_duration_ms >= 50ULL) {
    const auto tok_s = rounded_ratio(
        {.num = t.last_output, .scale = 1000ULL, .den = t.last_duration_ms});
    if (tok_s > 0)
      add(std::to_string(tok_s) + " tok/s");
  }
  if (t.last_reasoning > 0)
    add(terminal_format_tokens(t.last_reasoning) + " reason");
  if (t.last_cost_usd)
    add(format_usd(*t.last_cost_usd));
  return out;
}
ChatRow terminal_avionics_rail(const TelemetrySnapshot &t, std::size_t max_cells) {
  if (t.requests == 0 || max_cells < 10)
    return {};
  const bool utf8_locale =
      display_width("·") > 0 && display_width("▓") > 0 && display_width("Σ") > 0;
  const std::string_view sep = utf8_locale ? " · " : " | ";
  struct Segment {
    std::string text;
    Ink ink;
  };
  struct RailOptions {
    bool bar;
    bool cache;
    bool rate;
    bool totals;
    bool epoch;
  };
  const auto render_segments = [&](const std::vector<Segment> &segs) -> ChatRow {
    ChatRow row;
    for (std::size_t i = 0; i < segs.size(); ++i) {
      if (i > 0)
        row.push_back({std::string{sep}, Ink::border});
      row.push_back({segs[i].text, segs[i].ink});
    }
    return row;
  };
  const auto row_cells = [](const ChatRow &row) {
    std::size_t cells = 0;
    for (const auto &s : row)
      cells += display_width(s.text);
    return cells;
  };
  const auto build = [&](const RailOptions &opts) -> ChatRow {
    std::vector<Segment> segs;
    if (t.context_window && *t.context_window > 0 && t.last_input > 0) {
      const auto pct = rounded_ratio(
          {.num = t.last_input, .scale = 100ULL, .den = *t.context_window});
      const Ink ink = pct >= 90ULL   ? Ink::failure
                      : pct >= 70ULL ? Ink::user
                                     : Ink::success;
      std::string text = "ctx " + terminal_format_tokens(t.last_input) + "/" +
                         terminal_format_tokens(*t.context_window) + " " +
                         std::to_string(pct) + "%";
      if (opts.bar)
        text += " " + context_gauge_bar(pct, utf8_locale);
      segs.push_back({std::move(text), ink});
    } else if (t.last_input > 0) {
      segs.push_back({"ctx " + terminal_format_tokens(t.last_input), Ink::muted});
    }
    if (opts.cache && t.last_input > 0 && t.last_cached > 0) {
      const auto pct = std::min<std::uint64_t>(
          100ULL,
          rounded_ratio({.num = t.last_cached, .scale = 100ULL, .den = t.last_input}));
      segs.push_back({"cache " + std::to_string(pct) + "%",
                      pct >= 50ULL ? Ink::success : Ink::user});
    }
    if (opts.rate && t.last_output > 0 && t.last_duration_ms >= 50ULL) {
      const auto tok_s = rounded_ratio(
          {.num = t.last_output, .scale = 1000ULL, .den = t.last_duration_ms});
      if (tok_s > 0)
        segs.push_back({std::to_string(tok_s) + " tok/s", Ink::assistant});
    }
    if (opts.totals && (t.requests > 1 || t.total_input > t.last_input || t.cost_usd)) {
      std::string tot = std::string{utf8_locale ? "Σ " : "tot "} +
                        terminal_format_tokens(t.total_input) + "/" +
                        terminal_format_tokens(t.total_output);
      if (t.cost_usd) {
        const auto usd = format_usd(*t.cost_usd);
        if (!usd.empty())
          tot += " " + usd;
      }
      segs.push_back({std::move(tot), Ink::muted});
    }
    if (opts.epoch && t.upstream_epoch > 0)
      segs.push_back({"e" + std::to_string(t.upstream_epoch), Ink::assistant});
    return render_segments(segs);
  };
  // Progressively shed lower-priority avionics segments so narrow viewports never clip.
  constexpr std::array<RailOptions, 6> tiers{{
      {true, true, true, true, true},
      {true, true, true, true, false},
      {true, true, true, false, false},
      {false, true, true, false, false},
      {false, true, false, false, false},
      {false, false, false, false, false},
  }};
  for (const auto &tier : tiers) {
    auto candidate = build(tier);
    if (!candidate.empty() && row_cells(candidate) <= max_cells)
      return candidate;
  }
  auto minimal = build({false, false, false, false, false});
  if (minimal.empty())
    return {};
  const auto clipped = terminal_lines(chat_plain(minimal), max_cells)[0];
  return {{clipped, minimal.front().ink}};
}
std::string terminal_key_help() {
  return "Keyboard\n"
         "  Enter        Send; while busy, queue for the next turn\n"
         "  Alt-Enter    Insert newline (also Ctrl-J; Shift-Enter where the\n"
         "               terminal reports it, e.g. Ghostty)\n"
         "  Tab          Complete a slash-command name; ambiguity never submits\n"
         "  Ctrl-G       Edit current draft in $VISUAL/$EDITOR (idle only)\n"
         "  Ctrl-Space/T Search commands; arrows select, Enter loads, Esc backs out\n"
         "  Up / Down    Move between draft lines; history at first/last line\n"
         "  Ctrl-P / N   Explicit history; restores your draft and cursor\n"
         "  Left / Right Move within the draft\n"
         "  Ctrl-A / E   Start / end of line (also Home / End)\n"
         "  Ctrl-Home/End Start / end of draft\n"
         "  Alt-B/Right  Back / forward word (also Ctrl-Left / Right)\n"
         "  Ctrl-W       Delete previous word; Alt-D deletes next word\n"
         "  Ctrl-K / Y   Kill to line end / yank last deletion\n"
         "  Ctrl-U       Clear draft; Ctrl-Y restores it\n"
         "  Esc          Stop active turn (keep queue), dismiss menu, or focus/close "
         "view\n"
         "  Ctrl-C       Request stop and clear pending queue; keep unsent draft\n"
         "  Ctrl-B       Background foreground command; preserve composer\n"
         "  Ctrl-O       Inspect command results; preserve draft/cursor\n"
         "  Ctrl-\\      View picker; switch views without replacing the draft\n"
         "  Ctrl-X       Current-session command center; preserve draft/cursor\n"
         "  Ctrl-]       Authored result lab; F6/F7 pin A/B; F8 request interrupt\n"
         "  Alt+F/P !cmd Alt+F flightdeck; Alt+P party (Shift hide); !cmd shell\n"
         "  Inspector    Arrows/Home/End/Page navigate; Tab focus; Esc draft/close\n"
         "  Center       T tasks, P participants, J command runs; + means more\n"
         "               Ctrl-Left/Right: list pages or output pages by focus\n"
         "  PTY input    Keys and Ctrl-C reach selected command; Ctrl-B returns\n"
         "  Ctrl-Q       Stop and exit; preserve unsent draft\n"
         "  PgUp / PgDn  Scroll transcript\n"
         "  Mouse / Copy Trackpad/wheel scrolls chat; drag in chat selects & copies\n"
         "               via OSC 52 (bounded to chat). /mouse off or "
         "BLACKBIRD_MOUSE=0\n"
         "               disables reporting; Shift-drag uses terminal selection.\n"
         "  Paste        Multiline text stays literal; Enter sends explicitly\n";
}
std::vector<std::string> terminal_builtin_names() {
  std::vector<std::string> names;
  for (const auto &c : builtin_commands)
    names.push_back(c.name);
  return names;
}
std::string terminal_help() {
  const auto catalog = command_catalog();
  const auto &commands = *catalog;
  std::string out = "Blackbird command guide\n";
  std::string_view group;
  for (const auto &command : commands) {
    if (command.group != group) {
      group = command.group;
      out += "\n" + std::string{group} + "\n";
    }
    out += "  " + std::string{command.name};
    if (!command.arguments.empty())
      out += " " + std::string{command.arguments};
    out += " — " + std::string{command.description} + "\n";
  }
  out +=
      "\nLocal TUI controls run immediately, even during work. Other commands queue\n"
      "behind the active turn; they do not mutate an in-flight provider request.\n\n";
  return out + "Keyboard: /keys · Tab completes commands · PgUp/PgDn browse · "
               "Alt+F cockpit · Alt+P party · !cmd shell\n";
}
bool terminal_is_bang_shell_command(std::string_view draft) noexcept {
  return !draft.empty() && draft.front() == '!';
}
std::string_view terminal_bang_shell_body(std::string_view draft) noexcept {
  if (!terminal_is_bang_shell_command(draft))
    return {};
  draft.remove_prefix(1);
  while (!draft.empty() && (draft.front() == ' ' || draft.front() == '\t'))
    draft.remove_prefix(1);
  while (!draft.empty() &&
         (draft.back() == ' ' || draft.back() == '\t' || draft.back() == '\r'))
    draft.remove_suffix(1);
  return draft;
}
int run_interactive_bang_shell(std::string_view command) {
  if (command.empty() || command.find('\0') != std::string_view::npos)
    return 2;
  std::string cmd{command};
  struct sigaction ignore_sa{};
  ignore_sa.sa_handler = SIG_IGN;
  sigemptyset(&ignore_sa.sa_mask);
  struct sigaction old_int{};
  struct sigaction old_quit{};
  const bool saved_int = ::sigaction(SIGINT, &ignore_sa, &old_int) == 0;
  const bool saved_quit = ::sigaction(SIGQUIT, &ignore_sa, &old_quit) == 0;
  auto restore_signals = [&]() noexcept {
    if (saved_int)
      (void)::sigaction(SIGINT, &old_int, nullptr);
    if (saved_quit)
      (void)::sigaction(SIGQUIT, &old_quit, nullptr);
  };
  const pid_t pid = ::fork();
  if (pid < 0) {
    restore_signals();
    return -1;
  }
  if (pid == 0) {
    struct sigaction def_sa{};
    def_sa.sa_handler = SIG_DFL;
    sigemptyset(&def_sa.sa_mask);
    (void)::sigaction(SIGINT, &def_sa, nullptr);
    (void)::sigaction(SIGQUIT, &def_sa, nullptr);
    char sh_path[] = "/bin/sh";
    char sh_flag[] = "-c";
    std::array<char *, 4> argv{sh_path, sh_flag, cmd.data(), nullptr};
    ::execv("/bin/sh", argv.data());
    ::_exit(127);
  }
  int status = 0;
  pid_t waited = -1;
  do {
    waited = ::waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);
  restore_signals();
  if (waited < 0)
    return -1;
  if (WIFEXITED(status))
    return WEXITSTATUS(status);
  if (WIFSIGNALED(status))
    return 128 + WTERMSIG(status);
  return -1;
}
TerminalPartyLayout terminal_party_pane_layout(TerminalViewport viewport) noexcept {
  TerminalPartyLayout layout{};
  if (viewport.cols == 0 || viewport.rows == 0)
    return layout;
  if (viewport.cols >= kTerminalPartyDockedMinCols) {
    const std::size_t pane_w = std::clamp<std::size_t>(viewport.cols / 3U, 42U, 48U);
    layout.docked = true;
    layout.main_width = viewport.cols - pane_w - 2U;
    layout.col = layout.main_width + 2U;
    layout.row = 0;
    layout.width = pane_w;
    layout.height = viewport.rows;
    return layout;
  }
  const std::size_t margin_x = viewport.cols >= 24U ? 2U : 0U;
  const std::size_t margin_y =
      viewport.rows >= 12U ? 2U : (viewport.rows >= 8U ? 1U : 0U);
  layout.docked = false;
  layout.main_width = viewport.cols;
  layout.col = margin_x;
  layout.row = margin_y;
  layout.width =
      viewport.cols > 2U * margin_x ? viewport.cols - 2U * margin_x : viewport.cols;
  layout.height =
      viewport.rows > 2U * margin_y ? viewport.rows - 2U * margin_y : viewport.rows;
  return layout;
}
void terminal_render_party_pane(ChatGrid &grid, const PartyChatPane &pane,
                                const TerminalPartyLayout &layout) {
  if (layout.width == 0 || layout.height == 0 || layout.col >= grid.width ||
      layout.row >= grid.height) {
    return;
  }
  const Ink border_ink = pane.is_focused() ? Ink::selected : Ink::border;
  const auto line_ink_for = [&](std::size_t idx, std::size_t total) noexcept -> Ink {
    if (idx == 0)
      return pane.is_focused() ? Ink::heading : Ink::assistant;
    if (idx == 1)
      return Ink::muted;
    if (total >= 2 && idx + 1 == total)
      return pane.is_focused() ? Ink::selected : Ink::muted;
    return Ink::normal;
  };
  if (layout.docked) {
    for (std::size_t r = 0; r < grid.height; ++r) {
      if (layout.main_width < grid.width)
        grid.line(r, {{"│", border_ink}}, layout.main_width);
      if (layout.main_width + 1 < grid.width)
        grid.line(r, {{" ", Ink::normal}}, layout.main_width + 1);
    }
    const auto frame = pane.render_frame(static_cast<int>(layout.width),
                                         static_cast<int>(layout.height), false);
    const std::size_t count = std::min(frame.lines.size(), layout.height);
    for (std::size_t r = 0; r < count && layout.row + r < grid.height; ++r) {
      grid.line(layout.row + r, {{frame.lines[r], line_ink_for(r, count)}}, layout.col);
    }
    return;
  }
  const bool boxed = layout.width >= 10 && layout.height >= 6;
  if (!boxed) {
    const auto frame = pane.render_frame(static_cast<int>(layout.width),
                                         static_cast<int>(layout.height), false);
    const std::size_t count = std::min(frame.lines.size(), layout.height);
    for (std::size_t r = 0; r < count && layout.row + r < grid.height; ++r) {
      grid.line(layout.row + r, {{frame.lines[r], line_ink_for(r, count)}}, layout.col);
    }
    return;
  }
  const std::size_t inner_w = layout.width - 2U;
  const std::size_t inner_h = layout.height - 2U;
  std::string top = "╭";
  std::string bot = "╰";
  const std::string_view label =
      pane.is_focused() ? " Party Chat · Esc back · Tab target " : " Party Chat ";
  const std::string clipped_label =
      inner_w > 2 ? terminal_lines(label, inner_w)[0] : std::string{};
  top += clipped_label;
  for (std::size_t c = display_width(clipped_label); c < inner_w; ++c)
    top += "─";
  top += "╮";
  for (std::size_t c = 0; c < inner_w; ++c)
    bot += "─";
  bot += "╯";
  grid.line(layout.row, {{top, border_ink}}, layout.col);
  const auto frame =
      pane.render_frame(static_cast<int>(inner_w), static_cast<int>(inner_h), false);
  for (std::size_t r = 0; r < inner_h && layout.row + 1U + r < grid.height; ++r) {
    const std::string content =
        r < frame.lines.size() ? frame.lines[r] : std::string(inner_w, ' ');
    const std::size_t used = display_width(content);
    const std::string pad =
        used < inner_w ? std::string(inner_w - used, ' ') : std::string{};
    grid.line(layout.row + 1U + r,
              {{"│", border_ink},
               {content, line_ink_for(r, inner_h)},
               {pad, Ink::normal},
               {"│", border_ink}},
              layout.col);
  }
  if (layout.row + layout.height - 1U < grid.height)
    grid.line(layout.row + layout.height - 1U, {{bot, border_ink}}, layout.col);
}
bool terminal_party_is_active(const PartySnapshot &snapshot) noexcept {
  if (snapshot.room_scope.empty())
    return false;
  auto eq_ci = [](std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size())
      return false;
    for (std::size_t i = 0; i < lhs.size(); ++i) {
      const char a = (lhs[i] >= 'A' && lhs[i] <= 'Z')
                         ? static_cast<char>(lhs[i] - 'A' + 'a')
                         : lhs[i];
      const char b = (rhs[i] >= 'A' && rhs[i] <= 'Z')
                         ? static_cast<char>(rhs[i] - 'A' + 'a')
                         : rhs[i];
      if (a != b)
        return false;
    }
    return true;
  };
  if (eq_ci(snapshot.room_scope, "solo") || eq_ci(snapshot.room_scope, "none"))
    return false;
  if (snapshot.party_config_present)
    return true;
  for (const auto &p : snapshot.participants) {
    if (!p.local_self)
      return true;
  }
  return false;
}
std::string terminal_party_status_pill(const PartyChatPane &pane, bool docked) {
  const auto &snap = pane.snapshot();
  const std::size_t unread = pane.unread_count();
  if (terminal_party_is_active(snap)) {
    std::size_t online = 0;
    std::size_t online_non_self = 0;
    std::size_t configured_leaders = 0;
    for (const auto &p : snap.participants) {
      const bool is_online = p.state == PartyParticipantState::online ||
                             p.state == PartyParticipantState::working ||
                             p.state == PartyParticipantState::idle;
      if (is_online) {
        ++online;
        if (!p.local_self)
          ++online_non_self;
      }
      if (p.role == PartyMemberRole::platoon_leader)
        ++configured_leaders;
    }
    std::string count_label;
    if (online > 0 && (online_non_self > 0 || configured_leaders == 0)) {
      count_label = std::to_string(online) + " online";
    } else if (configured_leaders > 0) {
      count_label = std::to_string(configured_leaders) +
                    (configured_leaders == 1U ? " leader" : " leaders");
    } else if (!snap.participants.empty()) {
      count_label = std::to_string(snap.participants.size()) +
                    (snap.participants.size() == 1U ? " peer" : " peers");
    } else {
      count_label = "ready";
    }
    std::string pill =
        "● PARTY " + party_chat_sanitize(snap.room_scope, 32) + " · " + count_label;
    if (unread > 0)
      pill += " (" + std::to_string(unread) + " unread)";
    pill += " · Alt+P";
    return pill;
  }
  if (unread > 0)
    return "Alt+P party (" + std::to_string(unread) + ")";
  if (docked)
    return "Alt+P party";
  return {};
}
std::string terminal_command_hint(std::string_view draft) {
  const auto catalog = command_catalog();
  const auto &commands = *catalog;
  if (!draft.starts_with("/") || draft.find_first_of("\r\n") != std::string_view::npos)
    return {};
  const auto token = draft.substr(0, draft.find_first_of(" \t"));
  std::string matches;
  for (const auto &command : commands) {
    if (command.name == token) {
      return std::string{command.name} +
             (command.arguments.empty() ? "" : " " + std::string{command.arguments}) +
             " — " + std::string{command.description};
    }
    if (command.name.starts_with(token) && token == draft) {
      if (!matches.empty())
        matches += " · ";
      matches += command.name;
    }
  }
  return matches.empty() ? "Unknown command · /help lists commands"
                         : "Tab complete · " + matches;
}
void Composer::insert(char byte) {
  if (palette_open_) {
    if (static_cast<unsigned char>(byte) >= 32 && byte != 127 &&
        palette_query_.size() < 128) {
      palette_query_ += byte;
      palette_selected_ = 0;
    }
    return;
  }
  goal_column_.reset();
  if (text_.size() >= 1024 * 1024)
    return;
  text_.insert(cursor_, 1, byte);
  ++cursor_;
  if (!pasted_) {
    slash_open_ = cursor_ == text_.size() && command_token(text_) &&
                  text_.find('/', 1) == std::string::npos;
    palette_query_ = slash_open_ ? text_.substr(1) : "";
    palette_selected_ = 0;
  }
}
namespace {
constexpr std::size_t ui_limit = 1024 * 1024;
void validate_state(const TerminalState &state, std::size_t *history_bound = nullptr) {
  if (state.draft.size() > ui_limit || state.cursor > state.draft.size())
    throw Error{ErrorCode::capacity};
  for (const auto *list : {&state.history, &state.queued}) {
    if (list->size() > 128)
      throw Error{ErrorCode::capacity};
    std::size_t size = 0;
    for (const auto &value : *list) {
      if (value.size() > ui_limit - size)
        throw Error{ErrorCode::capacity};
      size += value.size();
    }
    if (history_bound && list == &state.history)
      *history_bound = size;
  }
}
std::string ui_hex(std::string_view value, bool decode = false) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  if (!decode) {
    for (const char byte : value) {
      const auto c = static_cast<unsigned char>(byte);
      out += digits[c >> 4U];
      out += digits[c & 15U];
    }
  } else {
    if (value.size() % 2 != 0)
      throw Error{ErrorCode::corrupt};
    for (std::size_t i = 0; i < value.size(); i += 2) {
      unsigned n = 0;
      auto r = std::from_chars(value.data() + i, value.data() + i + 2, n, 16);
      if (r.ec != std::errc{} || r.ptr != value.data() + i + 2)
        throw Error{ErrorCode::corrupt};
      out += static_cast<char>(n);
    }
  }
  return out;
}
std::size_t trim_history(std::vector<std::string> &values) {
  std::size_t size = 0;
  for (const auto &value : values)
    size += value.size();
  while (values.size() > 128 || size > ui_limit) {
    size -= values.front().size();
    values.erase(values.begin());
  }
  return size;
}
} // namespace
std::string terminal_osc52_copy(std::string_view text) {
  constexpr std::size_t max_copy_bytes = 100 * 1024;
  constexpr char table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const auto bounded = text.substr(0, std::min(text.size(), max_copy_bytes));
  std::string out;
  out.reserve(10 + ((bounded.size() + 2) / 3) * 4);
  out += "\x1b]52;c;";
  std::size_t i = 0;
  while (i + 3 <= bounded.size()) {
    const std::uint32_t v =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bounded[i])) << 16) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bounded[i + 1])) << 8) |
        static_cast<std::uint32_t>(static_cast<unsigned char>(bounded[i + 2]));
    out.push_back(table[(v >> 18) & 63U]);
    out.push_back(table[(v >> 12) & 63U]);
    out.push_back(table[(v >> 6) & 63U]);
    out.push_back(table[v & 63U]);
    i += 3;
  }
  if (const auto rem = bounded.size() - i; rem == 1) {
    const std::uint32_t v =
        static_cast<std::uint32_t>(static_cast<unsigned char>(bounded[i])) << 16;
    out.push_back(table[(v >> 18) & 63U]);
    out.push_back(table[(v >> 12) & 63U]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2) {
    const std::uint32_t v =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bounded[i])) << 16) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(bounded[i + 1])) << 8);
    out.push_back(table[(v >> 18) & 63U]);
    out.push_back(table[(v >> 12) & 63U]);
    out.push_back(table[(v >> 6) & 63U]);
    out.push_back('=');
  }
  out.push_back('\x07');
  return out;
}
std::string terminal_extract_chat_selection(const std::vector<ChatRow> &rows,
                                            ChatSelectionRange range) {
  if (rows.empty())
    return {};
  if (range.start_line > range.end_line ||
      (range.start_line == range.end_line && range.start_col > range.end_col)) {
    std::swap(range.start_line, range.end_line);
    std::swap(range.start_col, range.end_col);
  }
  const auto first = std::min(range.start_line, rows.size() - 1);
  const auto last = std::min(range.end_line, rows.size() - 1);
  std::string out;
  for (std::size_t idx = first; idx <= last; ++idx) {
    if (idx > first)
      out += '\n';
    const std::size_t col_lo = idx == first ? range.start_col : std::size_t{0};
    const std::size_t col_hi =
        idx == last ? range.end_col : std::numeric_limits<std::size_t>::max();
    std::string line;
    DisplayCursor cursor{rows[idx]};
    DisplayCluster cluster;
    std::size_t cell_col = 0;
    while (cursor.next(cluster)) {
      if (!cluster.cells.value)
        continue;
      const auto next_col = cell_col + cluster.cells.value;
      // Columns 0..3 belong to the left rail ("  │ "); content starts at col 4.
      if (cell_col >= 4) {
        const auto content_col = cell_col - 4;
        if (content_col >= col_lo && content_col <= col_hi)
          cursor.append(line, cluster);
      }
      cell_col = next_col;
    }
    while (!line.empty() && line.back() == ' ')
      line.pop_back();
    out += line;
  }
  return out;
}
std::size_t terminal_scroll_after_output(const TerminalScrollUpdate &update) {
  if (update.scroll == 0)
    return 0;
  const auto growth =
      update.before_trim > update.previous ? update.before_trim - update.previous : 0;
  const auto maximum =
      update.after_trim > update.height ? update.after_trim - update.height : 0;
  if (update.scroll >= maximum || growth >= maximum - update.scroll)
    return maximum;
  return update.scroll + growth;
}
void trim_terminal_transcript(std::string &text) {
  if (text.size() > ui_limit) {
    constexpr std::string_view notice =
        "[Older display trimmed; full originals remain audited]\n";
    const auto minimum = text.size() - ui_limit + notice.size();
    const auto lf = text.find('\n', minimum);
    auto cut =
        lf == std::string::npos || lf - minimum > ui_limit / 8 ? minimum : lf + 1;
    while (cut < text.size() && continuation(text[cut]))
      ++cut;
    text.erase(0, cut);
    text.insert(0, notice);
  }
}
TerminalState load_terminal_state(const std::filesystem::path &path, bool capture) {
  const auto &native_path = path.native();
  const auto path_size = native_path.size();
  const std::uint8_t operation = 1;
  RawUiTrace trace{capture,
                   {4020, 4023},
                   std::array{detail::raw_native_field(operation),
                              detail::raw_native_field(path_size),
                              detail::raw_string_field(native_path)},
                   raw_ui_error_bytes + raw_envelope_size + 24 + 1 +
                       sizeof(std::size_t) + 85,
                   true};
  return trace.run([&] {
    const auto exists_request = trace.event(4082, {});
    std::error_code exists_error;
    const bool exists = std::filesystem::exists(path, exists_error);
    const int native_error = exists_error.value();
    (void)raw_ui_link(4083, exists_request,
                      std::array{detail::raw_native_field(exists),
                                 detail::raw_native_field(native_error)},
                      trace.credit());
    if (exists_error)
      throw std::filesystem::filesystem_error("terminal state status", path,
                                              exists_error);
    if (!exists) {
      const std::uint8_t branch = 0;
      const std::size_t cursor = 0;
      (void)trace.event(4022, std::array{detail::raw_native_field(branch),
                                         detail::raw_native_field(cursor)});
      trace.close();
      return TerminalState{};
    }
    auto source_credit = raw_ui_data(trace.enabled(), 7 * ui_limit + 48);
    RawAdapterContext context;
    if (trace.enabled())
      context.parent = trace.reference();
    const auto source =
        read_file(path, 7 * ui_limit, trace.enabled() ? &context : nullptr);
    if (source_credit) {
      const auto ref = trace.reference();
      const auto size = source.size();
      Error failure{ErrorCode::audit_unavailable};
      const auto emitted = raw_ui_emit(
          4021,
          std::array{ByteView{ref.lane}, detail::raw_native_field(ref.ordinal),
                     detail::raw_native_field(size), detail::raw_string_field(source)},
          RawPartition::data, &*source_credit, &failure);
      if (!emitted.ordinal)
        throw failure;
      source_credit.reset();
    }
    const auto packet = unwrap(decode_packet_string(source));
    if (string_field(packet, "encoding") != "hex-v1")
      throw Error{ErrorCode::corrupt};
    const auto fields =
        raw_ui_add(1, raw_ui_add(field(packet, "history").array().size(),
                                 field(packet, "queued").array().size()));
    constexpr auto field_overhead = raw_envelope_size + raw_ui_ref_bytes +
                                    sizeof(std::uint8_t) + 2 * sizeof(std::size_t);
    auto decoded_credit = raw_ui_data(
        trace.enabled(),
        raw_ui_add(source.size() / 2, raw_ui_multiply(fields, field_overhead)));
    auto decoded = [&](std::string_view encoded, std::uint8_t kind, std::size_t index) {
      auto value = ui_hex(encoded, true);
      const auto size = value.size();
      const auto ref = trace.reference();
      Error failure{ErrorCode::audit_unavailable};
      const auto body = raw_ui_emit(
          4052,
          std::array{ByteView{ref.lane}, detail::raw_native_field(ref.ordinal),
                     detail::raw_native_field(kind), detail::raw_native_field(index),
                     detail::raw_native_field(size), detail::raw_string_field(value)},
          RawPartition::data, decoded_credit ? &*decoded_credit : nullptr, &failure);
      if (trace.enabled() && !body.ordinal)
        throw failure;
      return std::pair{std::move(value), RawUiSource{body, 0, size}};
    };
    TerminalState state;
    auto draft = decoded(string_field(packet, "draft"), 1, 0);
    state.draft = std::move(draft.first);
    state.draft_source = draft.second;
    const auto &cursor = field(packet, "cursor").number().text();
    const auto r =
        std::from_chars(cursor.data(), cursor.data() + cursor.size(), state.cursor);
    if (r.ec != std::errc{} || r.ptr != cursor.data() + cursor.size())
      throw Error{ErrorCode::corrupt};
    for (const auto &[key, list, origins, kind] :
         {std::tuple{"history", &state.history, &state.history_sources,
                     std::uint8_t{2}},
          std::tuple{"queued", &state.queued, &state.queued_sources,
                     std::uint8_t{3}}}) {
      for (const auto &value : field(packet, key).array()) {
        auto item = decoded(value.string(), kind, list->size());
        list->push_back(std::move(item.first));
        origins->push_back(item.second);
      }
    }
    validate_state(state);
    while (state.cursor > 0 && state.cursor < state.draft.size() &&
           continuation(state.draft[state.cursor]))
      --state.cursor;
    const std::uint8_t branch = 1;
    (void)trace.event(4022, std::array{detail::raw_native_field(branch),
                                       detail::raw_native_field(state.cursor)});
    trace.close();
    return state;
  });
}
void save_terminal_state(const std::filesystem::path &path, const TerminalState &state,
                         bool capture) {
  const auto &native_path = path.native();
  const auto path_size = native_path.size();
  const std::uint8_t operation = 2;
  RawUiTrace trace{capture,
                   {4020, 4023},
                   std::array{detail::raw_native_field(operation),
                              detail::raw_native_field(path_size),
                              detail::raw_string_field(native_path)},
                   raw_ui_error_bytes + raw_envelope_size + 24 + 1 +
                       sizeof(std::size_t),
                   true};
  trace.run([&] {
    auto source_credit = raw_ui_data(trace.enabled(), ValueLimits{}.bytes + 48);
    validate_state(state);
    auto encode = [](const auto &values) {
      Value::Array out;
      for (const auto &value : values)
        out.emplace_back(ui_hex(value));
      return Value{std::move(out)};
    };
    const auto source = unwrap(
        encode_packet_string(Value::object({{"encoding", Value{"hex-v1"}},
                                            {"draft", Value{ui_hex(state.draft)}},
                                            {"cursor", Value{Number{state.cursor}}},
                                            {"history", encode(state.history)},
                                            {"queued", encode(state.queued)}})));
    RawEventRef body{};
    if (source_credit) {
      const auto ref = trace.reference();
      const auto size = source.size();
      Error failure{ErrorCode::audit_unavailable};
      body = raw_ui_emit(
          4021,
          std::array{ByteView{ref.lane}, detail::raw_native_field(ref.ordinal),
                     detail::raw_native_field(size), detail::raw_string_field(source)},
          RawPartition::data, &*source_credit, &failure);
      if (!body.ordinal)
        throw failure;
      source_credit.reset();
    }
    RawAdapterContext context;
    if (trace.enabled())
      context.parent = trace.reference();
    const RawFileInput original{body, source.size()};
    write_file(path, source, trace.enabled() ? &context : nullptr,
               trace.enabled() ? &original : nullptr);
    const std::uint8_t branch = 2;
    (void)trace.event(4022, std::array{detail::raw_native_field(branch),
                                       detail::raw_native_field(state.cursor)});
    trace.close();
  });
}
void Composer::restore(const TerminalState &state) {
  std::size_t history_bound = 0;
  validate_state(state, &history_bound);
  text_ = state.draft;
  cursor_ = state.cursor;
  history_ = state.history;
  history_capture_bound_ = history_bound;
  history_index_ = history_.size();
  draft_.clear();
  draft_cursor_ = 0;
  killed_.clear();
  goal_column_.reset();
  escape_.clear();
  pasted_ = false;
  pasted_cr_ = false;
  slash_open_ = false;
  palette_open_ = false;
  palette_query_.clear();
  palette_selected_ = 0;
}
TerminalState Composer::state() const {
  return {text_, cursor_, history_, {}, {}, {}, {}};
}
void Composer::draft(std::string text) {
  slash_open_ = false;
  if (text.size() > ui_limit)
    throw Error{ErrorCode::capacity};
  text_ = std::move(text);
  cursor_ = text_.size();
  history_index_ = history_.size();
  draft_.clear();
  draft_cursor_ = 0;
  goal_column_.reset();
}
std::vector<ComposerChoice> terminal_view_choices(tui::ViewRoute current) {
  std::vector<ComposerChoice> choices;
  choices.reserve(tui::view_descriptions.size());
  for (const auto &view : tui::view_descriptions)
    choices.push_back(
        {std::string{view.action}, "",
         std::string{view.description} +
             (view.route == current ? " (current view)" : "") +
             (view.binding.empty() ? "" : " · " + std::string{view.binding}),
         "Views", std::string{view.label}, view.route});
  return choices;
}
void Composer::views(tui::ViewRoute current) {
  choices(terminal_view_choices(current), "Views");
}
void Composer::choices(std::vector<ComposerChoice> entries, std::string heading) {
  std::size_t bound = 0;
  for (const auto &entry : entries)
    bound = std::max(bound, entry.name.size() + 1);
  choices_ = std::make_shared<const std::vector<ComposerChoice>>(std::move(entries));
  choice_capture_bound_ = bound;
  choices_heading_ = std::move(heading);
  palette_open_ = true;
  slash_open_ = false;
  palette_query_.clear();
  palette_selected_ = 0;
}
void Composer::palette_move(bool up) {
  const auto catalog = choices_ && palette_open_ ? choices_ : command_catalog();
  const auto &commands = *catalog;
  const auto matches = palette_matches(palette_query_, commands);
  if (matches.empty()) {
    palette_selected_ = 0;
    return;
  }
  palette_selected_ = std::min(palette_selected_, matches.size() - 1);
  if (up)
    palette_selected_ -= palette_selected_ > 0 ? 1U : 0U;
  else
    palette_selected_ = std::min(palette_selected_ + 1, matches.size() - 1);
}
bool Composer::flush_escape() {
  // Paste contents and its terminator can span reads without a timing bound.
  if (escape_.empty() || pasted_)
    return false;
  if (escape_ == "\x1b") {
    palette_open_ = false;
    slash_open_ = false;
  }
  // A report split across reads past the deadline must not type its tail.
  // A bare CSI M is also SCO F1, so only a started coordinate arms the X10 tail.
  if (escape_.starts_with("\x1b[<"))
    sgr_tail_ = true;
  else if (escape_.starts_with("\x1b[M") && escape_.size() > 3)
    x10_tail_ = 6 - std::min<std::size_t>(escape_.size(), 6);
  escape_.clear();
  return true;
}
void Composer::insert_pasted(char byte) {
  if (byte == '\r') {
    insert('\n');
    pasted_cr_ = true;
    return;
  }
  if (byte == '\n' && pasted_cr_) {
    pasted_cr_ = false;
    return;
  }
  pasted_cr_ = false;
  insert(byte);
}
TerminalInputDispatch
terminal_input_dispatch(Composer &composer, std::chrono::steady_clock::time_point now,
                        std::chrono::steady_clock::time_point escape_deadline,
                        short events) {
  const bool palette = composer.palette_open();
  const bool had_menu = palette || composer.slash_open();
  const bool was_bare = composer.bare_escape_pending();
  const bool redraw = now >= escape_deadline && composer.flush_escape();
  return {(events & (POLLIN | POLLHUP | POLLERR)) != 0, redraw, redraw && !palette,
          redraw && was_bare && !had_menu};
}
std::vector<std::string> Composer::palette_lines(std::size_t rows) const {
  const auto catalog = choices_ && palette_open_ ? choices_ : command_catalog();
  const auto &commands = *catalog;
  if ((!palette_open_ && !slash_open_) || rows == 0)
    return {};
  const auto matches = palette_matches(palette_query_, commands);
  std::vector<std::string> out{slash_open_
                                   ? "Commands"
                                   : (choices_ ? choices_heading_ : "Commands") +
                                         " / " + palette_query_ + "_"};
  if (rows == 1)
    return out;
  const auto count = rows > 2 ? rows - 2 : 1;
  if (matches.empty())
    out.emplace_back("  No matching commands");
  else {
    const auto selected = std::min(palette_selected_, matches.size() - 1);
    const auto first = selected >= count ? selected - count + 1 : 0;
    for (std::size_t n = first; n < matches.size() && n - first < count; ++n) {
      const auto &command = commands[matches[n]];
      out.push_back(
          (n == selected ? "> " : "  ") +
          (command.label.empty() ? command.name : command.label) +
          (command.arguments.empty() ? "" : " " + std::string{command.arguments}) +
          " — " + std::string{command.description});
    }
  }
  if (rows > 2)
    out.emplace_back(
        slash_open_ ? "↑↓ select · Tab fill · Enter run/fill · Esc dismiss"
        : choices_ && std::any_of(choices_->begin(), choices_->end(),
                                  [](const auto &c) { return c.view.has_value(); })
            ? "Type search · Up/Down select · Enter opens · Esc back"
        : choices_ && std::any_of(choices_->begin(), choices_->end(),
                                  [](const auto &c) { return c.answer; })
            ? "Type search · Up/Down select · Enter answers · Esc keeps draft"
            : "Type search · Up/Down select · Enter loads · Esc back");
  out.resize(rows);
  return out;
}
void Composer::history(bool older) {
  slash_open_ = false;
  if (older) {
    if (history_index_ == 0)
      return;
    if (history_index_ == history_.size()) {
      draft_ = text_;
      draft_cursor_ = cursor_;
    }
    text_ = history_[--history_index_];
    cursor_ = text_.size();
  } else {
    if (history_index_ == history_.size())
      return;
    ++history_index_;
    text_ = history_index_ == history_.size() ? draft_ : history_[history_index_];
    cursor_ = history_index_ == history_.size() ? draft_cursor_ : text_.size();
  }
  goal_column_.reset();
}
void Composer::vertical(bool up) {
  const auto begin = line_start(text_, cursor_);
  const auto end = line_end(text_, cursor_);
  if ((up && begin == 0) || (!up && end == text_.size())) {
    history(up);
    return;
  }
  if (!goal_column_)
    goal_column_ =
        terminal_caret(std::string_view{text_}.substr(begin, end - begin),
                       {cursor_ - begin}, {std::numeric_limits<std::size_t>::max()})
            .column.value;
  const auto target_begin = up ? line_start(text_, begin - 1) : end + 1;
  const auto target_end = line_end(text_, target_begin);
  cursor_ = target_begin +
            terminal_byte_at_column(
                std::string_view{text_}.substr(target_begin, target_end - target_begin),
                {*goal_column_})
                .value;
}
void Composer::kill(std::size_t begin, std::size_t end) {
  slash_open_ = false;
  if (begin == end)
    return;
  killed_ = text_.substr(begin, end - begin);
  text_.erase(begin, end - begin);
  cursor_ = begin;
  goal_column_.reset();
}
std::uint64_t Composer::capture_bound(std::size_t acquired_bytes) const {
  std::size_t catalog_bound = 0;
  capture_catalog_ = command_catalog(&catalog_bound);
  const auto source = std::max(
      {text_.size(), history_capture_bound_, choice_capture_bound_, catalog_bound});
  return raw_ui_add(raw_ui_multiply(acquired_bytes, raw_ui_add(source, acquired_bytes)),
                    raw_ui_multiply(acquired_bytes,
                                    raw_envelope_size + raw_ui_ref_bytes +
                                        4 * sizeof(std::size_t) + sizeof(InputAction)));
}
InputResult Composer::feed(char byte, RawUiInput *raw, bool inspecting) {
  if (!raw || !raw->enabled || !raw_enabled())
    return feed_impl(byte, nullptr, inspecting);
  if (!raw->data || !raw->control)
    throw Error{ErrorCode::invalid_range};
  RawUiBurst burst{raw->control};
  const bool known = raw->keyboard.has_value();
  std::array<ByteView, 5> request{};
  std::size_t fields = 0;
  request[fields++] = detail::raw_native_field(known);
  if (raw->keyboard) {
    request[fields++] = raw->keyboard->lane;
    request[fields++] = detail::raw_native_field(raw->keyboard->ordinal);
  }
  request[fields++] = detail::raw_native_field(raw->index);
  request[fields++] = detail::raw_native_field(byte);
  RawUiTrace trace{
      true, {4080, 4012}, std::span{request}.first(fields), raw_ui_feed_credit};
  raw->feed = trace.reference();
  return trace.run([&] {
    if (raw->keyboard && !raw_ui_source_valid(*raw->keyboard))
      throw Error{ErrorCode::invalid_identity};
    auto result = feed_impl(byte, raw, inspecting);
    if (!result.source.record.ordinal) {
      const auto action = result.action;
      const auto length = result.text.size();
      if (action == InputAction::choose_command || action == InputAction::submit ||
          action == InputAction::select_view ||
          action == InputAction::answer_question || action == InputAction::party_send) {
        const auto ref =
            raw_ui_emit(4010,
                        std::array{ByteView{raw->feed.lane},
                                   detail::raw_native_field(raw->feed.ordinal),
                                   detail::raw_native_field(raw->index),
                                   detail::raw_native_field(action),
                                   detail::raw_native_field(cursor_),
                                   detail::raw_native_field(text_.size()),
                                   detail::raw_native_field(length),
                                   detail::raw_string_field(result.text)},
                        RawPartition::data, raw->data);
        if (!ref.ordinal)
          throw Error{ErrorCode::audit_unavailable};
        result.source = {ref, 0, length};
      } else {
        const auto ref =
            raw_ui_emit(4010,
                        std::array{ByteView{raw->feed.lane},
                                   detail::raw_native_field(raw->feed.ordinal),
                                   detail::raw_native_field(raw->index),
                                   detail::raw_native_field(action),
                                   detail::raw_native_field(cursor_),
                                   detail::raw_native_field(text_.size())},
                        RawPartition::control, trace.credit());
        if (!ref.ordinal)
          throw Error{ErrorCode::audit_unavailable};
        result.source = {ref, 0, 0};
      }
    }
    trace.finish();
    return result;
  });
}
InputResult Composer::feed_impl(char byte, RawUiInput *raw, bool inspecting) {
  inspecting = inspecting && !palette_open_;
  const auto catalog = choices_ && palette_open_ ? choices_
                       : raw && capture_catalog_ ? capture_catalog_
                                                 : command_catalog();
  const auto &commands = *catalog;
  const auto c = static_cast<unsigned char>(byte);
  if (x10_tail_ && c != 27) {
    --x10_tail_;
    return {};
  }
  x10_tail_ = 0; // X10 coordinates are at least 32, so ESC starts new input.
  if (sgr_tail_) {
    if (c >= 0x30U && c <= 0x3fU)
      return {};
    sgr_tail_ = false;
    if (byte == 'M' || byte == 'm')
      return {};
  }
  if (!escape_.empty()) {
    escape_ += byte;
    if (escape_ == "\x1b[200~") {
      slash_open_ = false;
      pasted_ = true;
      pasted_cr_ = false;
      escape_.clear();
      return {inspecting ? InputAction::inspect_focus_editor : InputAction::none, {}};
    }
    if (escape_ == "\x1b[201~") {
      pasted_ = false;
      pasted_cr_ = false;
      escape_.clear();
      return {};
    }
    if (pasted_) {
      if (std::string_view{"\x1b[201~"}.starts_with(escape_))
        return {};
      for (const char v : escape_)
        insert_pasted(v);
      escape_.clear();
      return {};
    }
    // Alt-Enter, plus Shift/Alt/Ctrl-Enter as xterm modifyOtherKeys (Ghostty's
    // default for Shift) and kitty CSI-u report them.
    if (escape_ == "\x1b\r" || escape_ == "\x1b\n" || escape_ == "\x1b[27;2;13~" ||
        escape_ == "\x1b[13;2u" || escape_ == "\x1b[27;3;13~" ||
        escape_ == "\x1b[13;3u" || escape_ == "\x1b[27;5;13~" ||
        escape_ == "\x1b[13;5u") {
      if (!palette_open_)
        insert('\n');
      escape_.clear();
      return {};
    }
    if (escape_ == "\x1b"
                   "f" ||
        escape_ == "\x1b[102;3u") {
      palette_open_ = slash_open_ = false;
      escape_.clear();
      return {InputAction::flightdeck_toggle, {}};
    }
    if (escape_ == "\x1b"
                   "p" ||
        escape_ == "\x1b[112;3u") {
      palette_open_ = slash_open_ = false;
      escape_.clear();
      return {InputAction::party_toggle, {}};
    }
    if (escape_ == "\x1b"
                   "P" ||
        escape_ == "\x1b[80;3u" || escape_ == "\x1b[112;4u") {
      palette_open_ = slash_open_ = false;
      escape_.clear();
      return {InputAction::party_hide, {}};
    }
    // Mouse reports: SGR CSI < button ; column ; row M|m, or X10 CSI M Cb Cx Cy
    // from terminals that ignore ?1006. X10 coordinates are raw bytes, so this
    // precedes the parameter-byte rule. Only the wheel acts; modifier bits
    // (Shift 4, Meta 8, Ctrl 16) do not change its direction.
    const bool sgr = escape_.starts_with("\x1b[<") && (byte == 'M' || byte == 'm');
    if (escape_.starts_with("\x1b[M") && escape_.size() > 3 && c == 27) {
      escape_ = byte; // Not a report: X10 coordinates are at least 32.
      return {};
    }
    if (escape_.starts_with("\x1b[M") && escape_.size() < 6)
      return {};
    if (sgr || escape_.starts_with("\x1b[M")) {
      unsigned button = 0;
      std::size_t col = 0, row = 0;
      if (sgr) {
        const auto params = std::string_view{escape_}.substr(3);
        const auto s1 = params.find(';');
        const auto s2 = s1 == std::string_view::npos ? std::string_view::npos
                                                     : params.find(';', s1 + 1);
        (void)std::from_chars(params.data(),
                              params.data() +
                                  (s1 == std::string_view::npos ? params.size() : s1),
                              button);
        if (s1 != std::string_view::npos && s2 != std::string_view::npos) {
          (void)std::from_chars(params.data() + s1 + 1, params.data() + s2, col);
          (void)std::from_chars(params.data() + s2 + 1,
                                params.data() + params.size() - 1, row);
        }
      } else if (static_cast<unsigned char>(escape_[3]) >= 32U) {
        button = static_cast<unsigned char>(escape_[3]) - 32U;
        if (static_cast<unsigned char>(escape_[4]) >= 32U)
          col = static_cast<unsigned char>(escape_[4]) - 32U;
        if (static_cast<unsigned char>(escape_[5]) >= 32U)
          row = static_cast<unsigned char>(escape_[5]) - 32U;
      }
      escape_.clear();
      const bool wheel = !(sgr && byte == 'm') && (button & 0x43U) >= 0x40U &&
                         (button & 0x43U) <= 0x41U;
      if (wheel) {
        const bool up = (button & 0x43U) == 0x40U;
        // Same precedence as the arrows: palette, then inspector, then slash menu.
        if (palette_open_ || (!inspecting && slash_open_)) {
          palette_move(up);
          return {};
        }
        if (inspecting)
          return {up ? InputAction::inspect_previous : InputAction::inspect_next, {}};
        return {up ? InputAction::scroll_up : InputAction::scroll_down, {}};
      }
      if (sgr && !inspecting && !palette_open_ && !slash_open_) {
        const std::size_t col0 = col > 0 ? col - 1 : 0;
        const std::size_t row0 = row > 0 ? row - 1 : 0;
        const unsigned base_btn = button & 0x43U;
        const bool motion = (button & 0x20U) != 0U;
        if (byte == 'M' && base_btn == 0U && !motion)
          return {InputAction::mouse_press, {}, {}, {}, col0, row0};
        if (byte == 'M' && base_btn == 0U && motion)
          return {InputAction::mouse_drag, {}, {}, {}, col0, row0};
        if (byte == 'm' && base_btn == 0U)
          return {InputAction::mouse_release, {}, {}, {}, col0, row0};
      }
      return {};
    }
    if (escape_.size() == 2 && (byte == '[' || byte == 'O'))
      return {};
    if (escape_.size() >= 3 && c >= 0x30U && c <= 0x3fU)
      return {};
    if (inspecting && escape_ == "\x1b[15~") {
      escape_.clear();
      return {InputAction::workbench_action, "toggle_advisory"};
    }
    if (inspecting &&
        (escape_ == "\x1b[17~" || escape_ == "\x1b[18~" || escape_ == "\x1b[19~")) {
      const auto name = escape_ == "\x1b[17~"   ? "pin_a"
                        : escape_ == "\x1b[18~" ? "pin_b"
                                                : "interrupt";
      escape_.clear();
      return {InputAction::instrument_action, name};
    }
    if (inspecting && escape_ == "\x1b[20~") {
      escape_.clear();
      return {InputAction::workbench_action, "toggle_archived"};
    }
    if (inspecting) {
      const auto action =
          escape_ == "\x1b[A" || escape_ == "\x1bOA"   ? InputAction::inspect_previous
          : escape_ == "\x1b[B" || escape_ == "\x1bOB" ? InputAction::inspect_next
          : escape_ == "\x1b[D" || escape_ == "\x1bOD"
              ? InputAction::inspect_focus_collection
          : escape_ == "\x1b[C" || escape_ == "\x1bOC"
              ? InputAction::inspect_focus_detail
          : escape_ == "\x1b[H" || escape_ == "\x1bOH" || escape_ == "\x1b[1~" ||
                  escape_ == "\x1b[7~"
              ? InputAction::inspect_first
          : escape_ == "\x1b[F" || escape_ == "\x1bOF" || escape_ == "\x1b[4~" ||
                  escape_ == "\x1b[8~"
              ? InputAction::inspect_last
          : escape_ == "\x1b[5~"   ? InputAction::inspect_page_up
          : escape_ == "\x1b[6~"   ? InputAction::inspect_page_down
          : escape_ == "\x1b[1;5D" ? InputAction::inspect_previous_output
          : escape_ == "\x1b[1;5C" ? InputAction::inspect_next_output
                                   : InputAction::none;
      if (action != InputAction::none) {
        escape_.clear();
        return {action, {}};
      }
    }
    if (palette_open_) {
      if (escape_ == "\x1b[A" || escape_ == "\x1bOA")
        palette_move(true);
      if (escape_ == "\x1b[B" || escape_ == "\x1bOB")
        palette_move(false);
      escape_.clear();
      return {};
    }
    if (slash_open_ && (escape_ == "\x1b[A" || escape_ == "\x1bOA" ||
                        escape_ == "\x1b[B" || escape_ == "\x1bOB")) {
      palette_move(escape_ == "\x1b[A" || escape_ == "\x1bOA");
      escape_.clear();
      return {};
    }
    slash_open_ = false;
    const bool up = escape_ == "\x1b[A" || escape_ == "\x1bOA";
    const bool down = escape_ == "\x1b[B" || escape_ == "\x1bOB";
    if (up || down)
      vertical(up);
    else {
      goal_column_.reset();
      if (escape_ == "\x1b[D" || escape_ == "\x1bOD")
        cursor_ = previous(text_, cursor_);
      if (escape_ == "\x1b[C" || escape_ == "\x1bOC")
        cursor_ = next(text_, cursor_);
      if (escape_ == "\x1b[H" || escape_ == "\x1bOH" || escape_ == "\x1b[1~" ||
          escape_ == "\x1b[7~")
        cursor_ = line_start(text_, cursor_);
      if (escape_ == "\x1b[F" || escape_ == "\x1bOF" || escape_ == "\x1b[4~" ||
          escape_ == "\x1b[8~")
        cursor_ = line_end(text_, cursor_);
      if (escape_ == "\x1b[1;5H")
        cursor_ = 0;
      if (escape_ == "\x1b[1;5F")
        cursor_ = text_.size();
      if (escape_ == "\x1b"
                     "b" ||
          escape_ == "\x1b[1;5D" || escape_ == "\x1b[1;3D")
        cursor_ = word_left(text_, cursor_);
      if (escape_ == "\x1b[1;5C" || escape_ == "\x1b[1;3C")
        cursor_ = word_right(text_, cursor_);
      if (escape_ == "\x1b"
                     "d")
        kill(cursor_, word_right(text_, cursor_));
      if (escape_ == "\x1b\x7f" || escape_ == "\x1b\x08")
        kill(word_left(text_, cursor_), cursor_);
      if (escape_ == "\x1b[3~" && cursor_ < text_.size())
        text_.erase(cursor_, next(text_, cursor_) - cursor_);
    }
    const auto action = escape_ == "\x1b[5~"   ? InputAction::page_up
                        : escape_ == "\x1b[6~" ? InputAction::page_down
                                               : InputAction::none;
    escape_.clear();
    return {inspecting && action == InputAction::none
                ? InputAction::inspect_focus_editor
                : action,
            {}};
  }
  if (c == 27) {
    escape_ = byte;
    return {};
  }
  if (pasted_) {
    insert_pasted(byte);
    return {};
  }
  if (c == 28) {
    palette_open_ = slash_open_ = false;
    return {InputAction::select_view, "view.picker"};
  }
  if (c == 15) {
    palette_open_ = slash_open_ = false;
    return {InputAction::inspect_toggle, {}};
  }
  if (c == 29) {
    palette_open_ = slash_open_ = false;
    return {InputAction::instrument_toggle, {}};
  }
  if (c == 24) {
    palette_open_ = slash_open_ = false;
    return {InputAction::center_toggle, {}};
  }
  if (inspecting) {
    if (c == 9)
      return {InputAction::inspect_toggle_focus, {}};
    if (c == 13 || c == 10)
      return {InputAction::inspect_focus_detail, {}};
    if (c == 16 || c == 14)
      return {c == 16 ? InputAction::inspect_previous : InputAction::inspect_next, {}};
    auto result = feed_impl(byte, raw, false);
    if (result.action == InputAction::none)
      result.action = InputAction::inspect_focus_editor;
    return result;
  }
  if (c == 0 || c == 20) {
    slash_open_ = false;
    choices_.reset();
    palette_open_ = !palette_open_;
    palette_query_.clear();
    palette_selected_ = 0;
    return {};
  }
  if (palette_open_) {
    if (c == 3 || c == 17) {
      palette_open_ = false;
      return {c == 17 ? InputAction::quit : InputAction::none, {}};
    }
    if (c == 13) {
      const auto matches = palette_matches(palette_query_, commands);
      if (!matches.empty()) {
        const auto &command =
            commands[matches[std::min(palette_selected_, matches.size() - 1)]];
        palette_open_ = false;
        return {command.answer ? InputAction::answer_question
                : command.view ? InputAction::select_view
                               : InputAction::choose_command,
                std::string{command.name} + (command.arguments.empty() ? "" : " "),
                {},
                command.view};
      }
    } else if (c == 16 || c == 14 || c == 9)
      palette_move(c == 16);
    else if (c == 127 || c == 8) {
      palette_query_.erase(previous(palette_query_, palette_query_.size()));
      palette_selected_ = 0;
    } else
      insert(byte);
    return {};
  }
  if (c == 7)
    return {InputAction::edit, {}};
  if (c == 16 || c == 14) {
    history(c == 16);
    return {};
  }
  if (c == 23) {
    kill(word_left(text_, cursor_), cursor_);
    return {};
  }
  if (c == 11) {
    auto end = line_end(text_, cursor_);
    if (end == cursor_ && end < text_.size())
      ++end;
    kill(cursor_, end);
    return {};
  }
  if (c == 25) {
    if (killed_.size() <= ui_limit - text_.size()) {
      text_.insert(cursor_, killed_);
      cursor_ += killed_.size();
      goal_column_.reset();
    }
    return {};
  }
  if (c == 9) {
    if (slash_open_) {
      const auto matches = palette_matches(palette_query_, commands);
      if (!matches.empty()) {
        const auto &command =
            commands[matches[std::min(palette_selected_, matches.size() - 1)]];
        draft(std::string{command.name} + (command.arguments.empty() ? "" : " "));
      }
      return {};
    }
    if (cursor_ == text_.size()) {
      text_ = complete_command(text_, commands);
      cursor_ = text_.size();
      goal_column_.reset();
    }
    return {};
  }
  if (c == 3) {
    slash_open_ = false;
    return {InputAction::cancel, {}};
  }
  if (c == 17 || (c == 4 && text_.empty()))
    return {InputAction::quit, {}};
  if (c == 13) {
    if (slash_open_) {
      const auto matches = palette_matches(palette_query_, commands);
      if (!matches.empty()) {
        const auto &command =
            commands[matches[std::min(palette_selected_, matches.size() - 1)]];
        const bool arguments =
            !command.arguments.empty() && !command.arguments.starts_with("[");
        draft(std::string{command.name} + (arguments ? " " : ""));
        if (arguments)
          return {};
      }
      slash_open_ = false;
    }
    auto result = text_;
    if (raw && raw->enabled && raw_enabled()) {
      const auto action = InputAction::submit;
      const auto length = result.size();
      const auto ref = raw_ui_emit(
          4010,
          std::array{
              ByteView{raw->feed.lane}, detail::raw_native_field(raw->feed.ordinal),
              detail::raw_native_field(raw->index), detail::raw_native_field(action),
              detail::raw_native_field(cursor_), detail::raw_native_field(text_.size()),
              detail::raw_native_field(length), detail::raw_string_field(result)},
          RawPartition::data, raw->data);
      if (!ref.ordinal)
        throw Error{ErrorCode::audit_unavailable};
      raw->acquired = {ref, 0, length};
    }
    if (!result.empty() && result != "/quit" && result != "/exit" &&
        !terminal_is_bang_shell_command(result)) {
      history_.push_back(result);
      history_capture_bound_ = trim_history(history_);
    }
    text_.clear();
    cursor_ = 0;
    history_index_ = history_.size();
    draft_.clear();
    draft_cursor_ = 0;
    goal_column_.reset();
    return {InputAction::submit, std::move(result),
            raw ? raw->acquired : RawUiSource{}};
  }
  if (c == 10) {
    insert('\n');
    return {};
  }
  if (c == 1) {
    slash_open_ = false;
    goal_column_.reset();
    cursor_ = line_start(text_, cursor_);
    return {};
  }
  if (c == 5) {
    slash_open_ = false;
    goal_column_.reset();
    cursor_ = line_end(text_, cursor_);
    return {};
  }
  if (c == 21) {
    slash_open_ = false;
    kill(0, text_.size());
    cursor_ = 0;
    goal_column_.reset();
    return {};
  }
  if (c == 127 || c == 8) {
    goal_column_.reset();
    const auto p = previous(text_, cursor_);
    text_.erase(p, cursor_ - p);
    cursor_ = p;
    if (slash_open_) {
      slash_open_ = command_token(text_);
      palette_query_ = slash_open_ ? text_.substr(1) : "";
      palette_selected_ = 0;
    }
    return {};
  }
  if (c == 4 && cursor_ < text_.size()) {
    goal_column_.reset();
    text_.erase(cursor_, next(text_, cursor_) - cursor_);
    return {};
  }
  if (c >= 32 && text_.size() < 1024 * 1024)
    insert(byte);
  return {};
}
namespace {
std::size_t safe_scalar_bytes(unsigned char byte, const DisplayScalar &scalar) {
  if (byte == '\t')
    return 2;
  if (byte != '\n' && (byte < 32 || byte == 127 || scalar.cells < 0))
    return 4;
  return scalar.bytes;
}
struct SafeScalar {
  std::size_t source_bytes, emitted_bytes;
  bool changed;
};
SafeScalar safe_scalar(std::string_view source) {
  const auto byte = static_cast<unsigned char>(source.front());
  const auto scalar = display_scalar(source);
  const auto emitted = safe_scalar_bytes(byte, scalar);
  const bool changed = emitted != scalar.bytes || (scalar.cells < 0 && byte != '\n');
  return {changed ? 1 : scalar.bytes, emitted, changed};
}
void append_safe_scalar(std::string &out, std::string_view source,
                        const SafeScalar &scalar) {
  if (!scalar.changed) {
    out.append(source.substr(0, scalar.source_bytes));
    return;
  }
  const auto byte = static_cast<unsigned char>(source.front());
  if (byte == '\t')
    out += "  ";
  else {
    constexpr char hex[] = "0123456789abcdef";
    out += '\\';
    out += 'x';
    out += hex[byte >> 4U];
    out += hex[byte & 15U];
  }
}
std::string_view safe_terminal_text(std::string_view text, std::string &sanitized,
                                    ByteOffset *mapped = nullptr) {
  const auto source_cursor = mapped ? mapped->value : 0;
  bool copied = false;
  for (std::size_t offset = 0; offset < text.size();) {
    const auto source = text.substr(offset);
    const auto scalar = safe_scalar(source);
    if (scalar.changed && !copied) {
      sanitized.assign(text.substr(0, offset));
      copied = true;
    }
    if (copied)
      append_safe_scalar(sanitized, source, scalar);
    if (mapped && scalar.changed && offset < source_cursor)
      mapped->value += scalar.emitted_bytes - scalar.source_bytes;
    offset += scalar.source_bytes;
  }
  return copied ? std::string_view{sanitized} : text;
}
ChatRow safe_terminal_row(std::string_view source, const ChatRow &colors) {
  ChatRow safe;
  std::size_t index = 0, within = 0;
  while (!source.empty()) {
    while (index < colors.size() && within == colors[index].text.size()) {
      ++index;
      within = 0;
    }
    const auto ink = index < colors.size() ? colors[index].ink : Ink::normal;
    const auto scalar = safe_scalar(source);
    if (safe.empty() || safe.back().ink != ink)
      safe.push_back({{}, ink});
    append_safe_scalar(safe.back().text, source, scalar);
    // Decode the contiguous original, even if style metadata splits its UTF-8.
    // The first source byte supplies scalar ink; grapheme ink is resolved later.
    auto bytes = scalar.source_bytes;
    while (bytes && index < colors.size()) {
      const auto count = std::min(bytes, colors[index].text.size() - within);
      within += count;
      bytes -= count;
      if (within == colors[index].text.size()) {
        ++index;
        within = 0;
      }
    }
    source.remove_prefix(scalar.source_bytes);
  }
  return safe;
}
} // namespace
ByteOffset terminal_byte_at_column(std::string_view text, CellCount column) {
  std::string sanitized;
  const auto safe = safe_terminal_text(text, sanitized);
  DisplayCursor cursor{safe};
  DisplayCluster cluster;
  std::size_t cells = 0, boundary = 0;
  while (cursor.next(cluster)) {
    if (cells + cluster.cells.value > column.value)
      break;
    cells += cluster.cells.value;
    boundary = cluster.end.value;
  }
  if (sanitized.empty())
    return {boundary};
  // Invert the same sanitizer expansion at the selected display boundary.
  std::size_t source = 0, emitted = 0;
  while (source < text.size()) {
    const auto scalar = safe_scalar(text.substr(source));
    if (emitted + scalar.emitted_bytes > boundary)
      break;
    emitted += scalar.emitted_bytes;
    source += scalar.source_bytes;
  }
  return {source};
}
DisplayPosition terminal_caret(std::string_view text, ByteOffset source,
                               CellCount columns) {
  std::string sanitized;
  const auto safe = safe_terminal_text(text, sanitized, &source);
  return display_position(safe, source, columns);
}
std::vector<std::string> terminal_lines(std::string_view text, std::size_t columns) {
  columns = std::max<std::size_t>(columns, 1);
  std::string sanitized;
  text = safe_terminal_text(text, sanitized);
  std::vector<std::string> lines(1);
  do {
    const auto newline = text.find('\n');
    DisplayCursor cursor{text.substr(0, newline)};
    DisplayCluster cluster;
    std::size_t cells = 0;
    while (cursor.next(cluster)) {
      display_fit(cluster, {columns});
      if (cells && cells + cluster.cells.value > columns) {
        lines.emplace_back();
        cells = 0;
      }
      cursor.append(lines.back(), cluster);
      cells += cluster.cells.value;
    }
    if (newline == std::string_view::npos)
      break;
    lines.emplace_back();
    text.remove_prefix(newline + 1);
  } while (true);
  return lines;
}
std::vector<ChatRow> terminal_powerword_lines(std::string_view text,
                                              std::size_t columns) {
  const auto registry = displayed_workflows();
  std::vector<ChatRow> result;
  do {
    const auto end = text.find('\n');
    const auto raw = text.substr(0, end);
    const auto colors =
        registry ? registry->color(raw) : ChatRow{{std::string{raw}, Ink::normal}};
    const auto spans = safe_terminal_row(raw, colors);
    ChatRow row;
    std::size_t cells = 0;
    DisplayCursor cursor{spans};
    DisplayCluster cluster;
    while (cursor.next(cluster)) {
      if (!cluster.cells.value)
        continue;
      display_fit(cluster, {columns});
      if (cells && cells + cluster.cells.value > std::max<std::size_t>(columns, 1)) {
        result.push_back(std::move(row));
        row.clear();
        cells = 0;
      }
      if (row.empty() || row.back().ink != cluster.ink)
        row.push_back({{}, cluster.ink});
      cursor.append(row.back().text, cluster);
      cells += cluster.cells.value;
    }
    result.push_back(std::move(row));
    if (end == std::string_view::npos)
      break;
    text.remove_prefix(end + 1);
  } while (true);
  return result;
}
namespace {
struct UiPrompt {
  std::string text;
  RawUiSource source{};
  RawEventRef enqueue{};
};
void append_prompt_state(std::vector<std::string> &target,
                         const std::vector<UiPrompt> &prompts) {
  for (const auto &prompt : prompts)
    target.push_back(prompt.text);
}
RawEventRef enqueue_ui_prompt(bool enabled, std::vector<UiPrompt> &prompts,
                              std::string &text, RawUiSource source, std::uint8_t kind,
                              RawEventRef action, RawControlToken *borrowed = nullptr) {
  RawUiBurst burst{borrowed};
  RawUiTrace trace{
      enabled,
      {4013, 4016},
      std::array{ByteView{action.lane}, detail::raw_native_field(action.ordinal),
                 detail::raw_native_field(kind), ByteView{source.record.lane},
                 detail::raw_native_field(source.record.ordinal),
                 detail::raw_native_field(source.offset),
                 detail::raw_native_field(source.length)},
      raw_ui_enqueue_credit};
  return trace.run([&] {
    if (trace.enabled() &&
        (!raw_ui_source_valid(source.record) || source.length != text.size()))
      throw Error{ErrorCode::invalid_identity};
    prompts.reserve(prompts.size() + 1);
    const auto index = prompts.size();
    const auto request = trace.reference();
    prompts.push_back({std::move(text), source, request});
    const std::uint8_t branch = 1;
    (void)trace.event(4014, std::array{detail::raw_native_field(branch),
                                       detail::raw_native_field(index)});
    trace.close();
    return request;
  });
}
void withdraw_ui_prompts(bool enabled, std::vector<UiPrompt> &prompts,
                         std::uint8_t branch, RawEventRef target,
                         RawControlToken *borrowed = nullptr) {
  RawUiBurst burst{borrowed};
  auto credit = raw_ui_control(enabled, raw_ui_multiply(prompts.size(), 73));
  for (std::size_t index = 0; index < prompts.size(); ++index)
    (void)raw_ui_link(4015, prompts[index].enqueue,
                      std::array{detail::raw_native_field(branch),
                                 detail::raw_native_field(index), ByteView{target.lane},
                                 detail::raw_native_field(target.ordinal)},
                      credit ? &*credit : nullptr);
  prompts.clear();
}
} // namespace
TerminalUI::TerminalUI(std::string title) : title_(std::move(title)) {}
TerminalUI::~TerminalUI() = default;
void TerminalUI::post(Kind kind, std::string_view text, RawCapacityClaim *preheld_data,
                      std::shared_ptr<const TerminalQuestion> question,
                      std::shared_ptr<const TelemetrySnapshot> telemetry) {
  const auto size = text.size();
  const Ink outcome = Ink::muted;
  RawUiTrace trace{
      raw_capture_,
      {4000, 4002},
      std::array{detail::raw_native_field(kind), detail::raw_native_field(outcome),
                 detail::raw_native_field(size), detail::raw_string_field(text)},
      179,
      true,
      RawWaitControl{},
      preheld_data};
  trace.run([&] {
    const std::lock_guard lock{mutex_};
    std::uint8_t branch = 1;
    const auto join =
        messages_.empty() || messages_.back().kind != kind ? std::nullopt
        : kind == Kind::text                               ? std::optional{text}
        : kind == Kind::process
            ? terminal_process_join({.queued = messages_.back().text, .next = text})
            : std::nullopt;
    if (join) {
      messages_.back().text.append(*join);
      messages_.back().latest = trace.reference();
      branch = 2;
    } else {
      messages_.push_back({kind,
                           std::string{text},
                           Ink::muted,
                           Value{},
                           trace.reference(),
                           trace.reference(),
                           {},
                           {},
                           std::move(question),
                           std::move(telemetry)});
    }
    const auto &message = messages_.back();
    const auto current = message.text.size();
    (void)trace.event(4001,
                      std::array{ByteView{message.enqueue.lane},
                                 detail::raw_native_field(message.enqueue.ordinal),
                                 detail::raw_native_field(branch),
                                 detail::raw_native_field(current)});
    raw_ui_notify(trace, notification_);
    trace.close();
  });
}
void TerminalUI::question(std::optional<TerminalQuestion> value) {
  if (value)
    for (auto &choice : value->choices) {
      choice.answer = true;
      choice.view.reset();
    }
  auto pending = value ? std::make_shared<const TerminalQuestion>(std::move(*value))
                       : std::shared_ptr<const TerminalQuestion>{};
  post(Kind::question, pending ? pending->heading : "", nullptr, pending);
}
void TerminalUI::sessions(const Value &listing, RawUiValueOrigin origin) {
  auto trace = raw_ui_value_trace(raw_capture_, origin);
  trace.run([&] {
    if (trace.enabled() && (!origin.source || !raw_ui_source_valid(*origin.source)))
      throw Error{ErrorCode::invalid_identity};
    const std::lock_guard lock{mutex_};
    messages_.push_back({Kind::sessions, "", Ink::muted, listing, trace.reference(),
                         trace.reference(), origin});
    raw_ui_notify(trace, notification_);
    trace.finish();
  });
}
void TerminalUI::instrument_source(InstrumentSource source) {
  RawUiValueOrigin origin;
  origin.kind = 4;
  origin.source = source.original;
  auto trace = raw_ui_value_trace(raw_capture_, origin);
  trace.run([&] {
    if (trace.enabled() && !raw_ui_source_valid(source.original))
      throw Error{ErrorCode::invalid_identity};
    const std::lock_guard lock{mutex_};
    Message message{Kind::instrument_source, "",    Ink::muted, {}, trace.reference(),
                    trace.reference(),       origin};
    message.instrument.emplace(std::move(source));
    messages_.push_back(std::move(message));
    raw_ui_notify(trace, notification_);
    trace.finish();
  });
}
void TerminalUI::text(std::string_view value) { post(Kind::text, value); }
void TerminalUI::notice(std::string_view value) { post(Kind::notice, value); }
void TerminalUI::process_output(std::string_view value) { post(Kind::process, value); }
void TerminalUI::restore_message(ChatKind kind, std::string_view value) {
  post(kind == ChatKind::user ? Kind::user : Kind::assistant, value);
}
void TerminalUI::usage(std::string_view value) { post(Kind::usage, value); }
void TerminalUI::telemetry(const TelemetrySnapshot &snapshot) {
  post(Kind::telemetry, terminal_usage_summary(snapshot), nullptr, {},
       std::make_shared<const TelemetrySnapshot>(snapshot));
}
void TerminalUI::context_workbench(ContextWorkbenchSnapshot snapshot) {
  const std::lock_guard lock{mutex_};
  Message message{Kind::context_workbench, "", Ink::muted, {}, {}, {}, {}};
  message.workbench_snapshot =
      std::make_shared<const ContextWorkbenchSnapshot>(std::move(snapshot));
  messages_.push_back(std::move(message));
  if (notification_ >= 0) {
    const char byte = 1;
    (void)::write(notification_, &byte, 1);
  }
}
void TerminalUI::hooks_view(HooksViewSnapshot snapshot) {
  const std::lock_guard lock{mutex_};
  Message message{Kind::hooks_view, "", Ink::muted, {}, {}, {}, {}};
  message.hooks_snapshot =
      std::make_shared<const HooksViewSnapshot>(std::move(snapshot));
  messages_.push_back(std::move(message));
  if (notification_ >= 0) {
    const char byte = 1;
    (void)::write(notification_, &byte, 1);
  }
}
void TerminalUI::party_chat(PartySnapshot snapshot) {
  const std::lock_guard lock{mutex_};
  Message message{Kind::party_chat, "", Ink::muted, {}, {}, {}, {}};
  message.party_snapshot = std::make_shared<const PartySnapshot>(std::move(snapshot));
  messages_.push_back(std::move(message));
  if (notification_ >= 0) {
    const char byte = 1;
    (void)::write(notification_, &byte, 1);
  }
}
void TerminalUI::operation_started(bool provider) {
  post(provider ? Kind::provider_start : Kind::tool_start, {});
}
void TerminalUI::status(std::string_view value) { post(Kind::status, value); }
void TerminalUI::context_changed(std::string_view kind,
                                 std::optional<std::size_t> bytes_before,
                                 std::optional<std::size_t> bytes_after) {
  post(Kind::context_change, terminal_context_badge(kind, bytes_before, bytes_after));
}
void TerminalUI::operation_completed(std::string_view value, Ink outcome) {
  const auto kind = Kind::operation_complete;
  const auto size = value.size();
  RawUiTrace trace{
      raw_capture_,
      {4000, 4002},
      std::array{detail::raw_native_field(kind), detail::raw_native_field(outcome),
                 detail::raw_native_field(size), detail::raw_string_field(value)},
      179,
      true,
      RawWaitControl{}};
  trace.run([&] {
    const std::lock_guard lock{mutex_};
    messages_.push_back({kind,
                         std::string{value},
                         outcome,
                         Value{},
                         trace.reference(),
                         trace.reference(),
                         {}});
    const std::uint8_t branch = 1;
    const auto ref = trace.reference();
    (void)trace.event(4001, std::array{ByteView{ref.lane},
                                       detail::raw_native_field(ref.ordinal),
                                       detail::raw_native_field(branch),
                                       detail::raw_native_field(size)});
    raw_ui_notify(trace, notification_);
    trace.close();
  });
}
void TerminalUI::failed() { post(Kind::failure, {}); }
void TerminalUI::title(std::string_view value) { post(Kind::title, value); }
void TerminalUI::tasks(const Value &publication, RawUiValueOrigin origin) {
  try {
    auto trace = raw_ui_value_trace(raw_capture_, origin);
    trace.run([&] {
      if (trace.enabled() && (!origin.source || !raw_ui_source_valid(*origin.source)))
        throw Error{ErrorCode::invalid_identity};
      const bool snapshot = string_field(publication, "label") == "task-state-v1";
      auto task_credit = raw_ui_control(true, snapshot ? 221 : 552, RawWaitControl{});
      auto task_data =
          snapshot ? std::optional<RawCapacityClaim>{}
                   : raw_ui_data(true, ValueLimits{}.bytes + 48, RawWaitControl{});
      RawTaskOrigin task_origin{trace.enabled() ? std::optional{trace.reference()}
                                                : std::nullopt,
                                false, nullptr, task_data ? &*task_data : nullptr,
                                task_credit ? &*task_credit : nullptr};
      const std::lock_guard lock{mutex_};
      if (snapshot)
        task_state_.restore(publication, task_origin);
      else
        task_state_.replay(publication, task_origin);
      if (publication.find("order"))
        if (const auto position = task_state_.position(task_anchor_))
          task_offset_ = *position;
      if (const auto *removed = publication.find("removed"))
        for (const auto &id : removed->array()) {
          task_activity_.erase(id.string());
          task_runs_.erase(id.string());
          task_folded_.erase(id.string());
        }
      task_publication_initialized_ = true;
      if (snapshot)
        task_publication_failed_ = false;
      task_publication_origin_ = origin;
      task_publication_ingress_ = trace.reference();
      // One mutable derived view, not a queued snapshot per update.
      tasks_dirty_ = true;
      raw_ui_notify(trace, notification_);
      trace.finish();
    });
  } catch (...) {
    const std::lock_guard lock{mutex_};
    task_publication_failed_ = true;
    throw;
  }
}
TaskPublishedObservation
TerminalUI::try_observe_tasks(const TaskObservationQuery &query) noexcept {
  TaskPublishedObservation out;
  try {
    const std::unique_lock lock{mutex_, std::try_to_lock};
    if (!lock.owns_lock()) {
      out.publication = TaskPublicationStatus::busy;
      return out;
    }
    if (!task_publication_initialized_) {
      if (task_publication_failed_)
        out.publication = TaskPublicationStatus::stale;
      return out;
    }
    out.publication = task_publication_failed_ ? TaskPublicationStatus::stale
                                               : TaskPublicationStatus::ready;
    out.value = task_state_.observe(query);
    out.origin = task_publication_origin_;
    out.ingress = task_publication_ingress_;
  } catch (...) {
    out.publication = TaskPublicationStatus::stale;
  }
  return out;
}
void TerminalUI::task_activity(const Value &event, RawUiValueOrigin origin) {
  auto trace = raw_ui_value_trace(raw_capture_, origin);
  trace.run([&] {
    if (trace.enabled() && (!origin.source || !raw_ui_source_valid(*origin.source)))
      throw Error{ErrorCode::invalid_identity};
    const auto &id = string_field(event, "task_id");
    const auto &attempt = string_field(event, "attempt");
    const auto &phase = string_field(event, "phase");
    const std::lock_guard lock{mutex_};
    if (!task_state_.item(id)) {
      trace.finish();
      return;
    }
    auto &runs = task_runs_[id];
    if (phase == "running" || phase == "waiting")
      runs.insert_or_assign(attempt, event);
    else
      runs.erase(attempt);
    task_activity_.insert_or_assign(id, runs.empty() ? event : runs.begin()->second);
    if (runs.empty())
      task_runs_.erase(id);
    tasks_dirty_ = true;
    raw_ui_notify(trace, notification_);
    trace.finish();
  });
}
void TerminalUI::run(const std::function<void(std::string_view)> &perform,
                     std::atomic_bool &cancelled,
                     const std::function<bool()> &exit_requested, std::string initial,
                     std::filesystem::path state_path,
                     const std::function<void()> &idle_work,
                     std::shared_ptr<CommandJobs> commands, int interrupt_fd,
                     const std::function<Result<void>()> &reset_interrupt,
                     RetainedState *raw_root,
                     std::optional<CommandCenterContext> center_context,
                     std::optional<InstrumentSource> instrument_source,
                     const ContextDetailReader &context_detail_reader) {
  RawCaptureFailureScope ui_capture{raw_capture_ && raw_enabled()};
  const RawAdapterContext terminal_context{
      nullptr,
      raw_capture_ && raw_ui_source_valid(raw_parent_) ? std::optional{raw_parent_}
                                                       : std::nullopt,
      nullptr, nullptr};
  terminal_native_locale(&terminal_context);
  ui_capture.require();
  TerminalMode mode{&terminal_context};
  ChatPresenter output;
  output.raw_capture(raw_capture_);
  output.attach(STDOUT_FILENO);
  TerminalNotifications notifications{&terminal_context};
  resize_ = std::make_unique<TerminalResize>(&terminal_context);
  struct WakeCleanup {
    TerminalUI &ui;
    ~WakeCleanup() {
      ui.resize_->uninstall();
      const std::lock_guard lock{ui.mutex_};
      ui.notification_ = -1;
    }
  } wake{*this};
  resize_->install();
  {
    const std::lock_guard lock{mutex_};
    notification_ = notifications.write_fd();
  }
  RawCommandWake turn_cancel;
  RawWaitScope ui_wait{{{interrupt_fd, -1}, {}}};
  auto cancel_turn = [&] {
    cancelled.store(true);
    turn_cancel.notify();
  };
  RawRegion first_frame{raw_regions::terminal_first_frame};
  Composer composer;
  std::shared_ptr<const TerminalQuestion> question;
  std::unique_ptr<RawRetainedTransfer> transfer;
  std::jthread worker;
  std::optional<RawControlToken> joined_rearm_credit;
  std::exception_ptr worker_publication_failure;
  std::optional<Error> worker_capture_failure;
  struct WorkerCustody {
    std::jthread &worker;
    std::unique_ptr<RawRetainedTransfer> &transfer;
    RawCommandWake &wake;
    int interrupt;
    const std::function<Result<void>()> &reset_interrupt;
    std::optional<RawControlToken> &rearm_credit;
    Result<void> join() {
      if (!worker.joinable())
        return Result<void>::success();
      worker.join();
      // Only the actual joined worker permits retiring its sticky incarnation.
      // Rearm has held native credit; the cancellation flag remains truthful.
      wake.retire();
      auto reset = wake.clear(rearm_credit ? &*rearm_credit : nullptr);
      rearm_credit.reset();
      if (reset.has_value() && reset_interrupt)
        reset = reset_interrupt();
      if (!transfer)
        return reset;
      RawWaitScope wait{{{interrupt, wake.read_fd()}, {}}};
#if BLACKBIRD_DEBUG
      // Developer fault fixture: one SIGTERM inside the admission wait below,
      // which then refuses fresh owner admission and leaves joined-child debt.
      static bool fault_raised = false;
      if (!fault_raised && std::getenv("BLACKBIRD_FAULT_SIGTERM_IN_JOIN") != nullptr) {
        fault_raised = true;
        (void)::raise(SIGTERM);
      }
#endif
      auto result = transfer->joined(reset.has_value() ? std::nullopt
                                                       : std::optional{reset.error()});
      transfer.reset();
      return result;
    }
    ~WorkerCustody() { (void)join(); }
  } custody{worker,       transfer,        turn_cancel,
            interrupt_fd, reset_interrupt, joined_rearm_credit};
  struct StopOnExit {
    std::atomic_bool &flag;
    RawCommandWake &wake;
    ~StopOnExit() {
      flag.store(true);
      wake.notify();
    }
  } stop{cancelled, turn_cancel};
  auto queue_cleanup_credit = raw_ui_control(raw_capture_, 256 * 73);
  std::vector<UiPrompt> queued, recovered;
  struct PromptCleanup {
    std::vector<UiPrompt> &queued, &recovered;
    std::optional<RawControlToken> &credit;
    ~PromptCleanup() {
      const std::uint8_t branch = 5;
      const RawEventRef target{};
      for (const auto *list : {&queued, &recovered})
        for (std::size_t index = 0; index < list->size(); ++index)
          (void)raw_ui_link(4015, (*list)[index].enqueue,
                            std::array{detail::raw_native_field(branch),
                                       detail::raw_native_field(index),
                                       ByteView{target.lane},
                                       detail::raw_native_field(target.ordinal)},
                            credit ? &*credit : nullptr);
    }
  } prompt_cleanup{queued, recovered, queue_cleanup_credit};
  if (!state_path.empty()) {
    try {
      const auto saved = load_terminal_state(state_path, raw_capture_);
      composer.restore(saved);
      for (std::size_t index = 0; index < saved.queued.size(); ++index) {
        auto text = saved.queued[index];
        const auto source = index < saved.queued_sources.size()
                                ? saved.queued_sources[index]
                                : RawUiSource{};
        (void)enqueue_ui_prompt(raw_capture_, recovered, text, source, 2,
                                source.record);
      }
    } catch (...) {
      ui_capture.require();
      text("UI state damaged/unreadable; not restored. Audit untouched.\n");
    }
  }
  if (!recovered.empty())
    text("Recovered drafts: " + std::to_string(recovered.size()) +
         " · /drafts lists; /draft N loads without submitting.\n");
  bool save_failed = false;
  auto persist = [&] {
    if (state_path.empty())
      return true;
    auto saved = composer.state();
    append_prompt_state(saved.queued, recovered);
    append_prompt_state(saved.queued, queued);
    try {
      save_terminal_state(state_path, saved, raw_capture_);
      save_failed = false;
      return true;
    } catch (...) {
      ui_capture.require();
      if (!save_failed)
        text("UI state save failed; unsaved drafts retained in RAM. New work waits for "
             "a successful save.\n");
      save_failed = true;
      return false;
    }
  };

  std::unique_ptr<TuiInstrument> instrument;
  bool instrument_refused = false;
  if (center_context && commands) {
    auto created = TuiInstrument::create(
        center_context->scope, commands,
        instrument_source ? std::move(*instrument_source) : InstrumentSource{});
    if (created.has_value())
      instrument = std::move(created).value();
    else
      instrument_refused = true;
  }
  auto close_instrument = [&] {
    if (instrument && instrument->open())
      instrument->toggle();
  };
  std::unique_ptr<CommandInspector> inspector;
  bool inspector_refused = false;
  auto ensure_inspector = [&] {
    try {
      if (!inspector)
        inspector = std::make_unique<CommandInspector>();
      inspector_refused = false;
      return true;
    } catch (const Error &) {
      inspector_refused = true;
    } catch (const std::bad_alloc &) {
      inspector_refused = true;
    } catch (const std::length_error &) {
      inspector_refused = true;
    }
    return false;
  };
  std::unique_ptr<CommandCenter> center;
  bool center_refused = false;
  auto ensure_center = [&] {
    if (!center_context) {
      center_refused = true;
      return false;
    }
    try {
      if (!center)
        center = std::make_unique<CommandCenter>(center_context->scope);
      center_refused = false;
      return true;
    } catch (const Error &) {
      center_refused = true;
    } catch (const std::bad_alloc &) {
      center_refused = true;
    } catch (const std::length_error &) {
      center_refused = true;
    }
    return false;
  };
  CommandCenterSources center_sources{
      [this](const TaskObservationQuery &query) { return try_observe_tasks(query); },
      center_context ? center_context->participants : ParticipantObservationReader{},
      commands.get()};
  auto close_center = [&] {
    if (center && center->open())
      center->toggle();
  };
  auto close_inspector = [&] {
    if (inspector && inspector->open())
      inspector->toggle();
  };
  std::optional<ContextWorkbench> workbench;
  std::optional<ContextWorkbenchSnapshot> latest_workbench_snapshot;
  auto ensure_workbench = [&] {
    if (workbench)
      return true;
    try {
      workbench.emplace();
      if (latest_workbench_snapshot)
        workbench->update(*latest_workbench_snapshot);
      return true;
    } catch (...) {
      return false;
    }
  };
  auto close_workbench = [&] {
    if (workbench && workbench->open())
      workbench->toggle();
  };
  std::optional<HooksView> hooks_panel;
  std::optional<HooksViewSnapshot> latest_hooks_snapshot;
  auto ensure_hooks_panel = [&] {
    if (hooks_panel)
      return true;
    try {
      hooks_panel.emplace();
      if (latest_hooks_snapshot)
        hooks_panel->update(*latest_hooks_snapshot);
      return true;
    } catch (...) {
      return false;
    }
  };
  auto close_hooks_panel = [&] {
    if (hooks_panel && hooks_panel->open())
      hooks_panel->toggle();
  };
  auto is_user_owned_regular_file = [](const std::filesystem::path &path) noexcept {
    if (path.empty())
      return false;
    auto strip_trailing_slashes = [](std::string raw) {
      while (raw.size() > 1U && raw.back() == '/')
        raw.pop_back();
      return raw;
    };
    const std::string leaf_str = strip_trailing_slashes(path.string());
    struct stat st{};
    if (::lstat(leaf_str.c_str(), &st) != 0)
      return false;
    if (!S_ISREG(st.st_mode))
      return false;
    if (st.st_uid != ::geteuid())
      return false;
    if ((st.st_mode & 0022U) != 0U)
      return false;
    const std::filesystem::path parent = std::filesystem::path{leaf_str}.parent_path();
    if (!parent.empty()) {
      const std::string parent_str = strip_trailing_slashes(parent.string());
      struct stat parent_st{};
      if (::lstat(parent_str.c_str(), &parent_st) != 0)
        return false;
      if (!S_ISDIR(parent_st.st_mode))
        return false;
      if (parent_st.st_uid != ::geteuid())
        return false;
      if ((parent_st.st_mode & 0022U) != 0U)
        return false;
    }
    return true;
  };
  auto resolve_user_party_config_path = [&]() -> std::filesystem::path {
    if (const char *bb_home = std::getenv("BLACKBIRD_HOME");
        bb_home != nullptr && bb_home[0] != '\0') {
      return std::filesystem::path{bb_home} / "party.json";
    }
    if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
      return std::filesystem::path{home} / ".blackbird" / "party.json";
    }
    return {};
  };
  PartyChatPane party_pane;
  bool party_docked = false;
  bool party_user_hidden = false;
  bool party_auto_opened = false;
  bool party_snapshot_external = false;
  std::string party_escape;
  auto party_escape_deadline = std::chrono::steady_clock::time_point::max();
  auto refresh_party_passive = [&] {
    if (party_snapshot_external)
      return;
    std::error_code ec;
    const auto cwd = std::filesystem::current_path(ec);
    if (ec || cwd.empty())
      return;
    PartyConfig cfg = PartyConfig::for_project(cwd);
    const auto user_party_path = resolve_user_party_config_path();
    // Never silently auto-load untrusted repo-local `.blackbird/party.json`;
    // only load user-owned config under BLACKBIRD_HOME or ~/.blackbird/.
    cfg.party_config_path = is_user_owned_regular_file(user_party_path)
                                ? user_party_path
                                : std::filesystem::path{};
    cfg.local_operator_id = "operator";
    auto snap = load_party_snapshot(cfg);
    if (snap.has_value())
      party_pane.update(std::move(snap).value());
  };
  refresh_party_passive();
  const bool flightdeck_kitty_capable = kitty_graphics_capable();
  bool flightdeck_open = false;
  bool flightdeck_first_frame = true;
  bool flightdeck_kitty_emitted = false;
  bool flightdeck_pending_erase = false;
  bool flightdeck_restore_cursor = false;
  bool flightdeck_demo_gate_active = false;
  std::optional<HeroFlightDeckEngine> flightdeck_engine;
  HeroControlInput flightdeck_control{};
  auto flightdeck_steer_until = std::chrono::steady_clock::time_point::min();
  auto flightdeck_last_step = std::chrono::steady_clock::now();
  auto flightdeck_next_frame = std::chrono::steady_clock::time_point::min();
  std::string flightdeck_escape;
  auto flightdeck_escape_deadline = std::chrono::steady_clock::time_point::max();
  std::shared_ptr<const TerminalQuestion> flightdeck_synced_question;
  std::vector<std::string> flightdeck_prev_hb_rows;
  auto route = tui::ViewRoute::conversation;
  std::string_view route_notice;
  const auto select_view = [&](tui::ViewRoute requested, RawEventRef origin,
                               bool toggle, bool reset) {
    const auto next =
        toggle && route == requested ? tui::ViewRoute::conversation : requested;
    if (next == tui::ViewRoute::command_runs && !ensure_inspector()) {
      route_notice = "Command runs unavailable; native view could not be created";
      return false;
    }
    if (next == tui::ViewRoute::command_center && !ensure_center()) {
      route_notice =
          center_context
              ? "Command center unavailable; native view could not be created"
              : "Command center unavailable; no current-session owner";
      return false;
    }
    if (next == tui::ViewRoute::result_comparison && !instrument) {
      instrument_refused = true;
      route_notice =
          "Result comparison unavailable; no composition owner in this session";
      return false;
    }
    if (next == tui::ViewRoute::context_workbench && !ensure_workbench()) {
      route_notice = "Context workbench unavailable; native view could not be created";
      return false;
    }
    if (next == tui::ViewRoute::hooks_fabric && !ensure_hooks_panel()) {
      route_notice = "Hooks view unavailable; native view could not be created";
      return false;
    }
    if (next != tui::ViewRoute::command_runs)
      close_inspector();
    if (next != tui::ViewRoute::command_center)
      close_center();
    if (next != tui::ViewRoute::result_comparison)
      close_instrument();
    if (next != tui::ViewRoute::context_workbench)
      close_workbench();
    if (next != tui::ViewRoute::hooks_fabric)
      close_hooks_panel();
    const auto activate = [&](auto &view) {
      if (reset)
        view.first_page(origin);
      else {
        if (!view.open())
          view.toggle(origin);
        view.focus_view();
      }
    };
    if (next == tui::ViewRoute::command_runs)
      activate(*inspector);
    else if (next == tui::ViewRoute::command_center)
      activate(*center);
    else if (next == tui::ViewRoute::result_comparison)
      activate(*instrument);
    else if (next == tui::ViewRoute::context_workbench)
      activate(*workbench);
    else if (next == tui::ViewRoute::hooks_fabric)
      activate(*hooks_panel);
    route = next;
    route_notice = {};
    return true;
  };
  auto inspection_open = [&] { return route != tui::ViewRoute::conversation; };
  auto inspection_focused = [&] {
    return (instrument && instrument->open() && instrument->focused()) ||
           (center && center->open() && center->focused()) ||
           (inspector && inspector->open() && inspector->focused()) ||
           (workbench && workbench->open() && workbench->focused()) ||
           (hooks_panel && hooks_panel->open() && hooks_panel->focused());
  };
  auto visit_inspection = [&](auto &&action) {
    if (instrument && instrument->open())
      action(*instrument);
    else if (center && center->open())
      action(*center);
    else if (inspector && inspector->open())
      action(*inspector);
    else if (workbench && workbench->open())
      action(*workbench);
    else if (hooks_panel && hooks_panel->open())
      action(*hooks_panel);
  };
  auto instrument_refresh = std::chrono::steady_clock::time_point::min();
  auto center_refresh = std::chrono::steady_clock::time_point::min();
  auto inspector_refresh = std::chrono::steady_clock::time_point::min();
  ChatView transcript{raw_capture_};
  bool welcoming = initial.empty();
  std::vector<std::string> welcome_lines;
  auto &grid = output.grid();
  std::string activity = "Ready", observed_usage;
  TelemetrySnapshot live_telemetry;
  std::size_t stream_bytes = 0;
  Value task_page;
  std::map<std::string, Value> task_activity;
  std::vector<ChatRow> task_rows;
  bool task_rows_dirty = true, tasks_hidden = false, tasks_expanded = false,
       tasks_forced = false;
  std::size_t task_render_width = 0;
  bool live_provider = false;
  std::vector<bool> operations;
  bool busy = false, quitting = false, redraw = true, tool_active = false,
       turn_failed = false, viewport_invalidated = false;
  std::size_t scroll = 0, previous_lines = 0;
  std::uint64_t display_generation = 0;
  auto escape_deadline = std::chrono::steady_clock::time_point::max();
  unsigned short old_rows = 0, old_columns = 0;
  std::string foreground_job, foreground_epoch, detached_epoch, child_escape,
      child_input, child_input_job, command_error;
  auto child_escape_deadline = std::chrono::steady_clock::time_point::max();
  bool foreground_pty = false, child_pasted = false;
  unsigned short child_rows = 0, child_columns = 0;
  std::size_t refused_child_bytes = 0;
  RawEventRef keyboard_read;
  auto append_child_input = [&](std::string_view bytes) {
    const auto job_size = foreground_job.size(), epoch_size = foreground_epoch.size(),
               byte_size = bytes.size();
    const bool refused = (!child_input.empty() && child_input_job != foreground_job) ||
                         bytes.size() > 4096 - child_input.size();
    const std::uint8_t branch = refused ? 2 : 1;
    (void)raw_command_linked_data(
        2042, keyboard_read,
        std::array{detail::raw_native_field(job_size),
                   detail::raw_string_field(foreground_job),
                   detail::raw_native_field(epoch_size),
                   detail::raw_string_field(foreground_epoch),
                   detail::raw_native_field(byte_size), detail::raw_string_field(bytes),
                   detail::raw_native_field(branch),
                   detail::raw_native_field(child_input.size())});
    // Keep admitted/pending bytes with their original job. Excess keyboard
    // bytes are explicitly refused; lifecycle keys must remain readable.
    if ((!child_input.empty() && child_input_job != foreground_job) ||
        bytes.size() > 4096 - child_input.size()) {
      refused_child_bytes += bytes.size();
      return;
    }
    if (child_input.empty())
      child_input_job = foreground_job;
    child_input += bytes;
  };
  auto report_refused_input = [&] {
    if (!refused_child_bytes)
      return;
    transcript += "\nPTY input refused: " + std::to_string(refused_child_bytes) +
                  " excess bytes; pending bytes preserved. Ctrl-B still backgrounds.\n";
    refused_child_bytes = 0;
    redraw = true;
  };
  auto command_request = [&](Value request) {
    try {
      commands->request(std::move(request));
      command_error.clear();
      return true;
    } catch (const Error &error) {
      const std::string message{error_name(error.code)};
      if (message != command_error)
        transcript += "\nCommand control refused: " + message + "\n";
      command_error = message;
      redraw = true;
      return false;
    } catch (const std::exception &error) {
      const std::string message{error.what()};
      if (message != command_error)
        transcript += "\nCommand control refused: " + message + "\n";
      command_error = message;
      redraw = true;
      return false;
    }
  };
  auto flush_child_input = [&] {
    if (child_input.empty())
      return true;
    auto flush_credit = raw_command_claim(50);
    const auto job_size = child_input_job.size(), byte_size = child_input.size();
    const auto flush_request =
        raw_command_data(2043, std::array{detail::raw_native_field(job_size),
                                          detail::raw_string_field(child_input_job),
                                          detail::raw_native_field(byte_size),
                                          detail::raw_string_field(child_input)});
    const bool accepted =
        command_request(Value::object({{"op", Value{"input"}},
                                       {"job_id", Value{child_input_job}},
                                       {"bytes", Value{child_input}}}));
    const Error error{};
    (void)raw_command_linked(2044, flush_request,
                             std::array{detail::raw_native_field(accepted),
                                        detail::raw_native_field(error.code),
                                        detail::raw_native_field(error.detail)},
                             flush_credit ? &*flush_credit : nullptr);
    if (accepted) {
      child_input.clear();
      child_input_job.clear();
    }
    return accepted;
  };
  auto release_command = [&](std::string_view requested) {
    if (!commands || foreground_job.empty()) {
      transcript += "\nNo foreground command wait.\n";
      return;
    }
    if (!requested.empty() && requested != foreground_job) {
      transcript += "\nBackground requires the current foreground job ID.\n";
      return;
    }
    if (command_request(
            Value::object({{"op", Value{"background"}},
                           {"job_id", Value{foreground_job}},
                           {"wait_epoch", Value{Number{foreground_epoch}}}}))) {
      detached_epoch = foreground_epoch;
      foreground_job.clear();
      foreground_pty = false;
      child_pasted = false;
      child_escape.clear();
      redraw = true;
    }
  };
  const auto *mascot_setting = std::getenv("BLACKBIRD_MASCOT");
  const bool mascot_enabled =
      !mascot_setting || std::string_view{mascot_setting} != "0";
  const bool graphics_enabled = mascot_enabled && blackbird_graphics_available();
  bool image_loaded = false;
  std::array<std::size_t, 4> image_placement{};
  bool pending_image_loaded = false;
  std::array<std::size_t, 4> pending_image_placement{};
  // Context badge: blinks for context_blink after a change, steady until a turn.
  std::string context_badge;
  std::optional<std::chrono::steady_clock::time_point> context_changed_at;
  constexpr auto context_blink = std::chrono::milliseconds{2000};
  const auto context_blinking = [&](std::chrono::steady_clock::time_point at) {
    return !context_badge.empty() && context_changed_at &&
           at - *context_changed_at < context_blink + std::chrono::milliseconds{250};
  };
  // SGR wheel + button-drag reporting rides frame packets; emitted state commits
  // on completion. On by default so trackpad scroll and chat-bounded drag-select
  // with OSC 52 clipboard copy work out of the box (BLACKBIRD_MOUSE=0 disables).
  const auto *mouse_setting = std::getenv("BLACKBIRD_MOUSE");
  bool mouse_wanted = !(mouse_setting && std::string_view{mouse_setting} == "0");
  bool mouse_emitted = false, pending_mouse = false;
  std::string pending_osc52;
  constexpr std::string_view mouse_on = "\x1b[?1000h\x1b[?1002h\x1b[?1006h",
                             mouse_off = "\x1b[?1006l\x1b[?1002l\x1b[?1000l";
  struct ChatSelectionState {
    bool active = false, dragging = false;
    std::size_t anchor_line = 0, anchor_col = 0;
    std::size_t focus_line = 0, focus_col = 0;
  } chat_selection;
  std::size_t chat_begin_line = 0, chat_end_line = 0, chat_height = 0, chat_width = 0;
  auto service_output = [&] {
    try {
      if (!output.flush())
        return false;
    } catch (...) {
      image_loaded = false;
      image_placement = {};
      throw;
    }
    image_loaded = pending_image_loaded;
    image_placement = pending_image_placement;
    mouse_emitted = pending_mouse;
    first_frame.outcome(RawRegionOutcome::flushed);
    first_frame.finish();
    return true;
  };
  auto started = std::chrono::steady_clock::now();
  auto second = started, tool_started = started;
  bool wake_refused = false;
  RawEventRef last_launch{};
  auto start = [&](const std::string &source, RawUiSource original) {
    RawUiTrace launch{raw_capture_,
                      {4018, 4016},
                      std::array{ByteView{original.record.lane},
                                 detail::raw_native_field(original.record.ordinal),
                                 detail::raw_native_field(original.offset),
                                 detail::raw_native_field(original.length)},
                      148};
    last_launch = launch.reference();
    auto returned = [&](bool accepted) {
      if (accepted)
        context_badge.clear(); // A launched turn retires the previous badge.
      (void)launch.event(4070, std::array{detail::raw_native_field(accepted)});
      launch.close();
      return accepted;
    };
    return launch.run([&] {
      if (launch.enabled() &&
          (!raw_ui_source_valid(original.record) || original.length != source.size()))
        throw Error{ErrorCode::invalid_identity};
      launch.stage(1);
      welcoming = false;
      (void)custody.join();
      turn_cancel.retire();
      cancelled.store(false);
      launch.stage(2);
#if BLACKBIRD_DEBUG
      // Developer fault fixture: one SIGTERM after the loop's exit check and
      // before the rearm below clears its interrupt.
      static bool rearm_fault_raised = false;
      if (!rearm_fault_raised &&
          std::getenv("BLACKBIRD_FAULT_SIGTERM_BEFORE_REARM") != nullptr) {
        rearm_fault_raised = true;
        (void)::raise(SIGTERM);
      }
#endif
      auto reset = turn_cancel.clear();
      if (reset.has_value() && reset_interrupt)
        reset = reset_interrupt();
      if (!reset.has_value()) {
        const std::uint8_t branch = 1, stage = 2;
        (void)launch.event(4016,
                           std::array{detail::raw_native_field(branch),
                                      detail::raw_native_field(stage),
                                      detail::raw_native_field(reset.error().code),
                                      detail::raw_native_field(reset.error().detail)});
        cancelled.store(true);
        wake_refused = true;
        notice(std::string{"Cancellation rearm refused: "} +
               error_name(reset.error().code));
        return returned(false);
      }
      // An exit requested after the loop's check refuses the launch: a SIGTERM
      // whose interrupt the rearm just cleared, or a restart or new session that
      // became pending. The prompt stays queued, or in the composer for a direct
      // submission or an answer, and the loop exits at its next check.
      if (exit_requested && exit_requested())
        return returned(false);
      std::string prompt;
      RawThreadHandle context;
      RawWorkerDispatch dispatch{};
      launch.stage(3);
      try {
        prompt = source;
        context = unwrap(raw_prepare_thread());
        dispatch = raw_worker_dispatch();
        if (raw_root)
          transfer = unwrap(raw_root->prepare_raw_transfer(context, dispatch));
      } catch (...) {
        ui_capture.require();
        launch.capture_exception(4016);
        cancelled.store(true);
        wake_refused = true;
        notice("Turn admission refused; prompt retained.");
        return returned(false);
      }
      launch.stage(4);
      transcript.append(ChatKind::user, prompt, false, original.record);
      if (transfer)
        transfer->stage_before_launch();
      busy = true;
      tool_active = false;
      turn_failed = false;
      started = std::chrono::steady_clock::now();
      observed_usage.clear();
      stream_bytes = 0;
      operations.clear();
      scroll = 0;
      activity = "Starting";
      // Each worker owns a separately registered lane. Transfer facts reference
      // the UI lane and ordinal; neither producer nor region migrates threads.
      joined_rearm_credit = raw_ui_control(raw_capture_, raw_wake_lifecycle_credit +
                                                             raw_wake_rearm_credit +
                                                             raw_wake_notify_credit);
      turn_cancel.publish();
      launch.stage(5);
      try {
        auto *borrowed_transfer = transfer.get();
        worker = std::jthread([&, context = std::move(context), dispatch,
                               borrowed_transfer, original,
                               prompt = std::move(prompt)]() mutable {
          RawThreadBinding binding{std::move(context)};
          RawCaptureFailureScope worker_capture{raw_capture_ && raw_enabled()};
          std::optional<RawUiTrace> execution;
          try {
            // Actual request64, perform error51, terminal51, native wake106.
            constexpr std::uint64_t credit =
                raw_envelope_size + 2 * 24 + 2 * raw_ui_error_bytes +
                (raw_envelope_size + 24 + sizeof(int) + sizeof(std::size_t) +
                 sizeof(char)) +
                (raw_envelope_size + 24 + sizeof(ssize_t) + sizeof(bool) + sizeof(int));
            execution.emplace(
                raw_capture_, RawUiSites{4076, 4077},
                std::array{ByteView{original.record.lane},
                           detail::raw_native_field(original.record.ordinal),
                           ByteView{dispatch.lane},
                           detail::raw_native_field(dispatch.ordinal)},
                credit, false, RawWaitControl{});
            constexpr std::string_view failed_notice =
                "\nTurn failed; inspect the retained audit.\n";
            constexpr std::string_view interrupted_notice =
                "\nTurn interrupted; context/audit retained.\n";
            constexpr std::uint64_t ingress_bytes =
                raw_envelope_size + sizeof(Kind) + sizeof(Ink) + sizeof(std::size_t);
            auto completion_data =
                raw_ui_data(raw_capture_,
                            3 * ingress_bytes + std::max(failed_notice.size(),
                                                         interrupted_notice.size()),
                            RawWaitControl{});
            auto completion_control =
                raw_ui_control(raw_capture_, 3 * 179, RawWaitControl{});
            execution->stage(1);
            RawWaitScope wait{{{interrupt_fd, turn_cancel.read_fd()}, {}}};
            raw_worker_started(dispatch);
            RawRegion command{raw_regions::command_perform};
            bool perform_failed = false, perform_cancelled = false;
            try {
              RawStorageAuthorityScope authority{
                  borrowed_transfer ? borrowed_transfer->handoff() : nullptr,
                  {raw_lane_epoch(), command.begin_ordinal()}};
              try {
                execution->stage(2);
                perform(prompt);
              } catch (const Error &error) {
                authority.error(error);
                throw;
              }
              command.outcome(RawRegionOutcome::returned);
            } catch (const Error &error) {
              execution->capture_exception(4078);
              command.error(error);
              command.outcome(RawRegionOutcome::exception);
              perform_failed = true;
              // This owner has recorded the actual interrupted acquisition.
              // Consume only its matching cancellation origin after perform
              // has unwound; recorder/capacity failures still stop the UI.
              perform_cancelled = error == Error{ErrorCode::interrupted, ECANCELED} &&
                                  cancelled.load() && worker_capture.consume(error);
            } catch (...) {
              execution->capture_exception(4078);
              command.outcome(RawRegionOutcome::exception);
              perform_failed = true;
            }
            command.finish();
            worker_capture.require();
            execution->stage(3);
            std::optional<RawUiBurst> canceled_publication;
            RawCapacityClaim *paid_source = nullptr;
            if (cancelled.load()) {
              canceled_publication.emplace(completion_control ? &*completion_control
                                                              : nullptr);
              paid_source = completion_data ? &*completion_data : nullptr;
            }
            if (perform_failed) {
              post(Kind::failure, {}, paid_source);
              post(Kind::text, perform_cancelled ? interrupted_notice : failed_notice,
                   paid_source);
            }
            post(Kind::complete, {}, paid_source);
            worker_capture.require();
            execution->finish();
          } catch (...) {
            // No fresh diagnostic/complete retry after admission or publication
            // refusal. This native handoff belongs to the existing UI mutex.
            const auto failure = std::current_exception();
            {
              const std::lock_guard lock{mutex_};
              worker_publication_failure = failure;
              worker_capture_failure = worker_capture.error();
            }
            if (execution) {
              raw_ui_notify(*execution, notifications.write_fd());
              execution->capture_exception(4077);
              execution->close();
            }
          }
        });
        if (transfer)
          transfer->commit_launch();
      } catch (...) {
        launch.capture_exception(4016);
        if (transfer) {
          transfer->rollback_launch();
          transfer.reset();
        }
        turn_cancel.retire();
        cancelled.store(true);
        busy = false;
        wake_refused = true;
        if (ui_capture.error()) {
          launch.close();
          ui_capture.require();
        }
        notice("Worker launch refused; prompt retained.");
        return returned(false);
      }
      return returned(true);
    });
  };
  auto edit = [&] {
    if (busy) {
      transcript += "\nEditor waits for an idle turn; draft retained.\n";
      return false;
    }
    const auto handoff_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
    while (output.pending() && !service_output()) {
      if (std::chrono::steady_clock::now() >= handoff_deadline) {
        transcript += "\nTerminal busy; editor handoff deferred. Draft retained.\n";
        return false;
      }
      pollfd fd{STDOUT_FILENO, POLLOUT, 0};
      (void)terminal_native_poll(&terminal_context, std::span{&fd, std::size_t{1}}, 10,
                                 true);
    }
    if (!persist())
      return false;
    output.detach();
    mode.suspend();
    const auto edited = edit_terminal_draft(composer.text(), &terminal_context);
    mode.resume();
    image_loaded = false;
    image_placement = {};
    mouse_emitted = pending_mouse = false; // The suspend packet ended reporting.
    output.attach(STDOUT_FILENO);
    terminal_native_flush(&terminal_context); // Editor typeahead cannot send a draft.
    if (edited.accepted && edited.text != composer.text())
      composer.draft(edited.text);
    transcript += "\n" + edited.message + "\n";
    (void)persist();
    scroll = 0;
    redraw = true;
    return true;
  };
  auto run_bang_shell = [&](std::string_view command) {
    if (busy) {
      transcript += "\nShell escape waits for an idle turn.\n";
      return false;
    }
    const auto handoff_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
    while (output.pending() && !service_output()) {
      if (std::chrono::steady_clock::now() >= handoff_deadline) {
        transcript += "\nTerminal busy; shell handoff deferred.\n";
        return false;
      }
      pollfd fd{STDOUT_FILENO, POLLOUT, 0};
      (void)terminal_native_poll(&terminal_context, std::span{&fd, std::size_t{1}}, 10,
                                 true);
    }
    if (!persist())
      return false;
    output.detach();
    mode.suspend();
    const int exit_code = run_interactive_bang_shell(command);
    mode.resume();
    image_loaded = false;
    image_placement = {};
    mouse_emitted = pending_mouse = false; // The suspend packet ended reporting.
    output.attach(STDOUT_FILENO);
    terminal_native_flush(&terminal_context);
    viewport_invalidated = true;
    transcript += "\n[! exited " + std::to_string(exit_code) + "]\n";
    (void)persist();
    scroll = 0;
    redraw = true;
    return true;
  };
  if (!initial.empty())
    (void)enqueue_ui_prompt(raw_capture_, queued, initial, initial_source_, 1,
                            initial_source_.record);
  while (true) {
    std::exception_ptr publication_failure;
    std::optional<Error> capture_failure;
    {
      const std::lock_guard lock{mutex_};
      publication_failure = worker_publication_failure;
      capture_failure = worker_capture_failure;
    }
    if (publication_failure) {
      if (capture_failure)
        raw_capture_failed(*capture_failure);
      cancel_turn();
      (void)custody.join();
      std::rethrow_exception(publication_failure);
    }
    (void)service_output();
    std::vector<Message> incoming;
    RawUiTrace drain{raw_capture_, {4005, 4009}, {}, 171};
    auto task_read_credit = raw_ui_control(true, 222);
    drain.run([&] {
      {
        const std::lock_guard lock{mutex_};
        incoming.swap(messages_);
        const auto message_count = incoming.size();
        const RawEventRef first =
            incoming.empty() ? RawEventRef{} : incoming.front().enqueue;
        const RawEventRef last =
            incoming.empty() ? RawEventRef{} : incoming.back().enqueue;
        (void)drain.event(4008, std::array{detail::raw_native_field(message_count),
                                           ByteView{first.lane},
                                           detail::raw_native_field(first.ordinal),
                                           ByteView{last.lane},
                                           detail::raw_native_field(last.ordinal)});
        if (tasks_dirty_) {
          Value::Array folded;
          for (const auto &id : task_folded_)
            folded.push_back(Value{id});
          const auto count = task_state_.size();
          if (count)
            welcoming = false;
          task_offset_ = std::min(task_offset_, count ? count - 1 : 0);
          task_page = task_state_.read(
              Value::object({{"offset", Value{Number{task_offset_}}},
                             {"limit", Value{Number{"64"}}},
                             {"collapsed", Value{std::move(folded)}}}),
              RawTaskOrigin{drain.enabled() ? std::optional{drain.reference()}
                                            : std::nullopt,
                            false, nullptr, nullptr,
                            task_read_credit ? &*task_read_credit : nullptr});
          const auto &visible_tasks = field(task_page, "items").array();
          task_anchor_ =
              visible_tasks.empty() ? "" : string_field(visible_tasks.front(), "id");
          task_activity = task_activity_;
          tasks_dirty_ = false;
          task_rows_dirty = true;
          redraw = true;
        }
      }
      for (std::size_t message_index = 0; message_index < incoming.size();
           ++message_index) {
        const auto &message = incoming[message_index];
        const auto size = message.text.size();
        const auto batch = drain.reference();
        RawUiTrace apply{raw_capture_,
                         {4006, 4007},
                         std::array{ByteView{batch.lane},
                                    detail::raw_native_field(batch.ordinal),
                                    ByteView{message.enqueue.lane},
                                    detail::raw_native_field(message.enqueue.ordinal),
                                    ByteView{message.latest.lane},
                                    detail::raw_native_field(message.latest.ordinal),
                                    detail::raw_native_field(message.kind),
                                    detail::raw_native_field(message.outcome),
                                    detail::raw_native_field(size)},
                         152};
        apply.run([&] {
          if (message.kind == Kind::instrument_source && message.instrument) {
            if (instrument) {
              const auto applied_source =
                  instrument->source(*message.instrument, raw_capture_);
              if (!applied_source.has_value())
                transcript.append(ChatKind::notice,
                                  "Instrument source refused; last good retained");
            } else
              instrument_refused = true;
          }
          if (message.kind == Kind::question) {
            question = message.question;
            if (question) {
              welcoming = false;
              transcript.append(ChatKind::notice, question->heading);
              composer.choices(question->choices, question->heading);
            }
          }
          if (message.kind == Kind::sessions) {
            std::vector<ComposerChoice> entries;
            const auto &listing = message.data;
            for (const auto &entry : field(listing, "sessions").array()) {
              const auto &path = string_field(entry, "path");
              if (path.find_first_of("\r\n") != std::string::npos)
                continue;
              const auto &config = field(entry, "configuration");
              const auto *name = config.find("name");
              entries.push_back(
                  {"/resume " + path, "", path, "Session",
                   name && !name->string().empty()
                       ? name->string()
                       : std::filesystem::path{path}.filename().string()});
            }
            composer.choices(std::move(entries), "Sessions");
          }
          if (message.kind == Kind::text || message.kind == Kind::process ||
              message.kind == Kind::failure || message.kind == Kind::user ||
              message.kind == Kind::assistant)
            welcoming = false;
          if (message.kind == Kind::text) {
            if (busy && live_provider)
              stream_bytes += message.text.size();
            transcript.append(turn_failed ? ChatKind::error : ChatKind::assistant,
                              message.text, true, message.enqueue);
          }
          if (message.kind == Kind::notice)
            transcript.append(ChatKind::notice, message.text, true, message.enqueue);
          if (message.kind == Kind::process)
            transcript.tool_output(message.text, message.enqueue);
          if (message.kind == Kind::user || message.kind == Kind::assistant)
            transcript.append(message.kind == Kind::user ? ChatKind::user
                                                         : ChatKind::assistant,
                              message.text, false, message.enqueue);
          if (message.kind == Kind::usage)
            observed_usage = message.text;
          if (message.kind == Kind::telemetry && message.telemetry)
            live_telemetry = *message.telemetry;
          if (message.kind == Kind::context_workbench && message.workbench_snapshot) {
            latest_workbench_snapshot = *message.workbench_snapshot;
            if (workbench)
              workbench->update(*latest_workbench_snapshot);
          }
          if (message.kind == Kind::hooks_view && message.hooks_snapshot) {
            latest_hooks_snapshot = *message.hooks_snapshot;
            if (hooks_panel)
              hooks_panel->update(*latest_hooks_snapshot);
          }
          if (message.kind == Kind::party_chat && message.party_snapshot) {
            party_snapshot_external = true;
            party_pane.update(*message.party_snapshot);
          }
          if (message.kind == Kind::provider_start ||
              message.kind == Kind::tool_start) {
            live_provider = message.kind == Kind::provider_start;
            if (live_provider)
              stream_bytes = 0;
            operations.push_back(live_provider);
          }
          if (message.kind == Kind::status) {
            activity = message.text;
            tool_started = std::chrono::steady_clock::now();
            tool_active = !live_provider;
            if (!live_provider)
              transcript.tool_start("▸ " + message.text);
          }
          if (message.kind == Kind::operation_complete) {
            activity = message.text;
            tool_active = false;
            if (!live_provider)
              transcript.tool_complete(message.text, message.outcome);
            if (!operations.empty())
              operations.pop_back();
            live_provider = !operations.empty() && operations.back();
          }
          if (message.kind == Kind::failure)
            turn_failed = true;
          if (message.kind == Kind::context_change) {
            context_badge = message.text;
            context_changed_at = std::chrono::steady_clock::now();
          }
          if (message.kind == Kind::title)
            title_ = message.text;
          if (message.kind == Kind::complete) {
            const auto restored = custody.join();
            if (!restored.has_value()) {
              wake_refused = true;
              notice(std::string{"Product owner admission refused: "} +
                     error_name(restored.error().code));
            }
            turn_cancel.retire();
            busy = false;
            tool_active = false;
            activity = cancelled.load() ? "Turn cancelled"
                       : turn_failed    ? "Turn failed"
                                        : "Turn completed";
            activity += " · " +
                        std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                                           std::chrono::steady_clock::now() - started)
                                           .count()) +
                        "s";
            transcript.append(
                turn_failed ? ChatKind::error : ChatKind::summary,
                activity + (observed_usage.empty() ? "" : " · " + observed_usage));
            refresh_party_passive();
          }
          redraw = true;
          apply.finish();
        });
        drain.progress(message_index + 1);
      }
      drain.finish();
    });
    if (!busy && idle_work && (!raw_root || !raw_root->raw_owner_blocked()))
      idle_work();
    // Poll results even with the route closed: intents/results outlive a view.
    if (instrument && std::chrono::steady_clock::now() >= instrument_refresh) {
      redraw = instrument->refresh(raw_capture_) || redraw;
      instrument_refresh =
          std::chrono::steady_clock::now() + std::chrono::milliseconds(40);
    }
    // Bounded derived owner observations run outside keyboard handling/painting.
    if (center && center->open() &&
        (center->needs_refresh() ||
         std::chrono::steady_clock::now() >= center_refresh)) {
      redraw = center->refresh(center_sources, raw_capture_) || redraw;
      center_refresh = std::chrono::steady_clock::now() + std::chrono::milliseconds(80);
    }
    if (inspector && inspector->open() &&
        (inspector->needs_refresh() ||
         std::chrono::steady_clock::now() >= inspector_refresh)) {
      redraw = inspector->refresh(commands.get(), raw_capture_) || redraw;
      inspector_refresh =
          std::chrono::steady_clock::now() + std::chrono::milliseconds{80};
      ui_capture.require();
    }
    if (workbench && workbench->open() && workbench->needs_refresh()) {
      ContextDetailReader guarded_reader;
      if (!busy && context_detail_reader)
        guarded_reader = context_detail_reader;
      redraw = workbench->refresh(guarded_reader) || redraw;
    }
    if (hooks_panel && hooks_panel->open() && hooks_panel->needs_refresh()) {
      redraw = hooks_panel->refresh() || redraw;
    }
    if (commands) {
      pollfd child_input_ready{STDIN_FILENO, POLLIN, 0};
      if (foreground_pty && !child_escape.empty() &&
          std::chrono::steady_clock::now() >= child_escape_deadline &&
          terminal_native_poll(&terminal_context,
                               std::span{&child_input_ready, std::size_t{1}}, 0) == 0) {
        if (child_pasted || !child_escape.starts_with("\x1b[<"))
          append_child_input(child_escape); // An expired report prefix is dropped.
        child_escape.clear();
      }
      // Preserve the existing input batching despite bounded native reads.
      // Flush a full prefix or when the kernel has no further input ready.
      child_input_ready.revents = 0;
      const bool more_input =
          terminal_native_poll(&terminal_context,
                               std::span{&child_input_ready, std::size_t{1}}, 0) > 0;
      if (child_input.size() >= 4096 || !more_input)
        (void)flush_child_input();
      const auto lease = commands->foreground();
      auto job = string_field(lease, "job_id");
      const auto epoch = field(lease, "wait_epoch").number().text();
      if (epoch == detached_epoch)
        job.clear();
      const bool pty = !job.empty() && std::get<bool>(field(lease, "pty").value());
      if (job != foreground_job || epoch != foreground_epoch || pty != foreground_pty) {
        const bool held_report = !child_pasted && child_escape.starts_with("\x1b[<");
        if (!child_escape.empty()) {
          if (!held_report)
            append_child_input(child_escape);
          (void)flush_child_input();
        }
        // Neither owner may finish the other's partial escape or report.
        if (pty != foreground_pty)
          composer.reset_escape(held_report);
        foreground_job = std::move(job);
        foreground_epoch = epoch;
        foreground_pty = pty;
        child_rows = child_columns = 0;
        child_escape.clear();
        child_pasted = false;
        redraw = true;
      }
      report_refused_input();
    }
    if (!busy && exit_requested && exit_requested())
      break;
    if (!busy && quitting)
      break;
    if (!busy && !question && !wake_refused && !queued.empty()) {
      auto dispatch_credit = raw_ui_control(raw_capture_, 73);
      if (persist()) {
        if (start(queued.front().text, queued.front().source)) {
          const std::uint8_t branch = 1;
          const std::size_t index = 0;
          const auto target = last_launch;
          (void)raw_ui_link(4015, queued.front().enqueue,
                            std::array{detail::raw_native_field(branch),
                                       detail::raw_native_field(index),
                                       ByteView{target.lane},
                                       detail::raw_native_field(target.ordinal)},
                            dispatch_credit ? &*dispatch_credit : nullptr);
          queued.erase(queued.begin());
        }
      } else {
        auto credit = raw_ui_control(raw_capture_, raw_ui_multiply(queued.size(), 73));
        recovered.reserve(recovered.size() + queued.size());
        for (std::size_t index = 0; index < queued.size(); ++index) {
          const std::uint8_t branch = 3;
          const auto target = queued[index].enqueue;
          (void)raw_ui_link(4015, queued[index].enqueue,
                            std::array{detail::raw_native_field(branch),
                                       detail::raw_native_field(index),
                                       ByteView{target.lane},
                                       detail::raw_native_field(target.ordinal)},
                            credit ? &*credit : nullptr);
        }
        recovered.insert(recovered.end(), std::make_move_iterator(queued.begin()),
                         std::make_move_iterator(queued.end()));
        queued.clear();
      }
      redraw = true;
    }
    winsize dimensions{};
    {
      const int descriptor = STDOUT_FILENO;
      const unsigned long method = TIOCGWINSZ;
      auto dimensions_credit = raw_ui_control(
          raw_capture_, raw_envelope_size + sizeof(descriptor) + sizeof(method) +
                            raw_envelope_size + 24 + sizeof(int) + sizeof(bool) +
                            std::max(2 * sizeof(unsigned short), sizeof(int)));
      const auto request = raw_ui_emit(
          4048,
          std::array{detail::raw_native_field(descriptor),
                     detail::raw_native_field(method)},
          RawPartition::control, dimensions_credit ? &*dimensions_credit : nullptr);
      const int result = ioctl(STDOUT_FILENO, TIOCGWINSZ, &dimensions);
      const int error = errno;
      const bool valid = result == 0;
      if (valid)
        (void)raw_ui_link(4049, request,
                          std::array{detail::raw_native_field(result),
                                     detail::raw_native_field(valid),
                                     detail::raw_native_field(dimensions.ws_row),
                                     detail::raw_native_field(dimensions.ws_col)},
                          dimensions_credit ? &*dimensions_credit : nullptr);
      else
        (void)raw_ui_link(4049, request,
                          std::array{detail::raw_native_field(result),
                                     detail::raw_native_field(valid),
                                     detail::raw_native_field(error)},
                          dimensions_credit ? &*dimensions_credit : nullptr);
      errno = error;
    }
    const auto rows =
        dimensions.ws_row ? dimensions.ws_row : static_cast<unsigned short>(24);
    const auto columns =
        dimensions.ws_col ? dimensions.ws_col : static_cast<unsigned short>(80);
    if (foreground_pty && (rows != child_rows || columns != child_columns)) {
      if (command_request(Value::object(
              {{"op", Value{"resize"}},
               {"job_id", Value{foreground_job}},
               {"rows", Value{Number{std::min<unsigned short>(rows, 512)}}},
               {"columns", Value{Number{std::min<unsigned short>(columns, 512)}}}}))) {
        child_rows = rows;
        child_columns = columns;
      }
    }
    const auto now = std::chrono::steady_clock::now();
    if (now - second >= std::chrono::milliseconds{80}) {
      second = now;
      if (busy)
        redraw = true;
    }
    if (flightdeck_open) {
      if (now >= flightdeck_steer_until)
        flightdeck_control = {};
      if (now >= flightdeck_next_frame)
        redraw = true;
    }
    if (rows != old_rows || columns != old_columns)
      redraw = true;
    if (context_blinking(std::chrono::steady_clock::now()))
      redraw = true;
    if (redraw && !output.pending()) {
      RawRegion render{raw_regions::command_render};
      RawUiTrace layout{
          raw_capture_,
          {4074, 4075},
          std::array{detail::raw_native_field(rows), detail::raw_native_field(columns)},
          raw_envelope_size + 2 * sizeof(unsigned short) + raw_ui_error_bytes};
      try {
        const bool same_width = old_columns == columns;
        const bool geometry_changed = old_columns != columns || old_rows != rows;
        old_rows = rows;
        old_columns = columns;
        redraw = false;
        const auto width = static_cast<std::size_t>(columns);
        const auto &committed = output.geometry();
        // Foreground PTY input reaches the child verbatim, so reporting stays off.
        const bool mouse_target = mouse_wanted && !foreground_pty && !flightdeck_open;
        const bool mouse_change = mouse_target != mouse_emitted;
        // A recovering frame is never empty, so a mode or clipboard update always
        // has a packet.
        const bool recover = viewport_invalidated || committed.tiny ||
                             committed.rows != rows || committed.columns != width ||
                             mouse_change || !pending_osc52.empty() ||
                             flightdeck_pending_erase || flightdeck_restore_cursor;
        // A later resize wake must survive completion of this packet.
        viewport_invalidated = false;
        if (flightdeck_open) {
          if (!flightdeck_engine)
            flightdeck_engine.emplace(HeroCanvasConfig{});
          const std::uint32_t target_w =
              flightdeck_kitty_capable
                  ? std::clamp<std::uint32_t>(static_cast<std::uint32_t>(width) * 3U,
                                              hero_min_width, 384U)
                  : std::clamp<std::uint32_t>(static_cast<std::uint32_t>(width),
                                              hero_min_width, 320U);
          const std::uint32_t target_h =
              flightdeck_kitty_capable
                  ? std::clamp<std::uint32_t>(static_cast<std::uint32_t>(rows) * 6U,
                                              hero_min_height, 240U)
                  : std::clamp<std::uint32_t>(static_cast<std::uint32_t>(rows) * 2U,
                                              hero_min_height, 200U);
          if (flightdeck_engine->width() != target_w ||
              flightdeck_engine->height() != target_h) {
            flightdeck_engine->resize(HeroSize{.width = target_w, .height = target_h});
          }
          HeroTelemetryInput ht{};
          ht.busy = busy;
          ht.input_tokens = live_telemetry.total_input > 0 ? live_telemetry.total_input
                                                           : live_telemetry.last_input;
          ht.cached_tokens = live_telemetry.total_cached > 0
                                 ? live_telemetry.total_cached
                                 : live_telemetry.last_cached;
          ht.reasoning_tokens = live_telemetry.last_reasoning;
          ht.output_tokens = live_telemetry.total_output > 0
                                 ? live_telemetry.total_output
                                 : live_telemetry.last_output;
          if (live_telemetry.last_input > 0) {
            ht.cache_hit_ratio =
                std::clamp(static_cast<double>(live_telemetry.last_cached) /
                               static_cast<double>(live_telemetry.last_input),
                           0.0, 1.0);
          }
          if (live_telemetry.last_duration_ms >= 50ULL) {
            const double sec =
                static_cast<double>(live_telemetry.last_duration_ms) / 1000.0;
            ht.total_tok_per_sec = static_cast<double>(live_telemetry.last_input +
                                                       live_telemetry.last_output) /
                                   sec;
            ht.out_rsn_tok_per_sec =
                static_cast<double>(live_telemetry.last_output +
                                    live_telemetry.last_reasoning) /
                sec;
          } else if (busy && stream_bytes > 0) {
            const auto elapsed_ms = std::max<std::int64_t>(
                100,
                std::chrono::duration_cast<std::chrono::milliseconds>(now - started)
                    .count());
            const double approx_tok_s = (static_cast<double>(stream_bytes) / 4.0) /
                                        (static_cast<double>(elapsed_ms) / 1000.0);
            ht.out_rsn_tok_per_sec = approx_tok_s;
            ht.total_tok_per_sec = std::max(approx_tok_s * 3.0, 200.0);
          }
          if (live_telemetry.context_window && *live_telemetry.context_window > 0 &&
              live_telemetry.last_input > 0) {
            ht.main_context_fill =
                std::clamp(static_cast<double>(live_telemetry.last_input) /
                               static_cast<double>(*live_telemetry.context_window),
                           0.0, 1.0);
          }
          const auto &psnap = party_pane.snapshot();
          if (terminal_party_is_active(psnap)) {
            ht.room_label = psnap.room_scope;
            std::size_t active_p = 0;
            for (const auto &p : psnap.participants) {
              const bool is_act = p.state == PartyParticipantState::online ||
                                  p.state == PartyParticipantState::working ||
                                  p.state == PartyParticipantState::idle;
              if (is_act)
                ++active_p;
              HeroPeerEntry pe{};
              pe.name = p.id;
              pe.active = is_act;
              pe.tool_busy = p.state == PartyParticipantState::working;
              pe.silent = p.state == PartyParticipantState::offline;
              ht.peers.push_back(std::move(pe));
            }
            ht.active_agents = std::max<std::size_t>(1U, active_p);
            ht.total_agents = std::max<std::size_t>(1U, psnap.participants.size());
          } else {
            ht.room_label = title_;
            ht.active_agents = busy ? 1U : 0U;
            ht.total_agents = 1U;
          }
          flightdeck_engine->set_telemetry(ht);
          flightdeck_engine->steer_input(flightdeck_control);
          if (question && question != flightdeck_synced_question) {
            HeroQuestion hq{};
            hq.from = "blackbird";
            hq.text = question->heading;
            const std::size_t max_opts =
                std::min<std::size_t>(3U, question->choices.size());
            for (std::size_t oi = 0; oi < max_opts; ++oi) {
              const auto &ch = question->choices[oi];
              hq.options.push_back(ch.label.empty() ? ch.name : ch.label);
            }
            if (hq.options.size() >= 2U)
              flightdeck_engine->set_question(std::move(hq));
            flightdeck_synced_question = question;
            flightdeck_demo_gate_active = false;
          } else if (!question && !flightdeck_demo_gate_active &&
                     flightdeck_synced_question) {
            flightdeck_engine->set_question(std::nullopt);
            flightdeck_synced_question.reset();
          }
          const float dt = std::clamp(
              std::chrono::duration<float>(now - flightdeck_last_step).count(), 0.01F,
              0.10F);
          flightdeck_last_step = now;
          flightdeck_next_frame = now + std::chrono::milliseconds{33};
          const auto &hero_frame = flightdeck_engine->step_and_render(dt);
          if (const auto picked = flightdeck_engine->take_answered_index();
              picked.has_value()) {
            if (flightdeck_demo_gate_active) {
              flightdeck_demo_gate_active = false;
            } else if (question && !busy && *picked < question->choices.size()) {
              const std::string chosen = question->choices[*picked].name;
              const auto length = chosen.size();
              RawUiTrace answer_original{
                  raw_capture_,
                  {4071, 4016},
                  std::array{ByteView{keyboard_read.lane},
                             detail::raw_native_field(keyboard_read.ordinal),
                             detail::raw_native_field(length),
                             detail::raw_string_field(chosen)},
                  raw_ui_error_bytes,
                  true};
              answer_original.run([&] {
                const RawUiSource source{answer_original.reference(), 0, length};
                answer_original.finish();
                (void)start(chosen, source);
              });
            }
          }
          std::string payload = "\x1b[?2026h\x1b[?25l";
          if (mouse_change) {
            payload += mouse_target ? mouse_on : mouse_off;
            pending_mouse = mouse_target;
          }
          if (graphics_enabled && image_placement[2]) {
            payload += blackbird_graphics_erase();
            pending_image_placement = {};
          }
          if (flightdeck_first_frame || geometry_changed) {
            payload += "\x1b[H\x1b[0m\x1b[2J";
            pending_image_loaded = false;
          }
          if (flightdeck_kitty_capable) {
            payload += encode_kitty_rgb_frame(
                hero_frame, HeroKittyPlacement{.row = 0,
                                               .column = 0,
                                               .columns = width,
                                               .rows = rows,
                                               .image_id = hero_default_kitty_image_id,
                                               .placement_id = 1});
            flightdeck_kitty_emitted = true;
          } else {
            auto hb_rows = encode_truecolor_halfblock_frame(
                hero_frame, HeroHalfBlockOptions{.columns = width, .rows = rows});
            const std::string hb_diff = encode_halfblock_diff(HeroHalfBlockDiff{
                .prev_rows = flightdeck_prev_hb_rows,
                .curr_rows = hb_rows,
                .full_redraw = flightdeck_first_frame || geometry_changed,
            });
            if (!hb_diff.empty()) {
              payload += "\x1b[0m";
              payload += hb_diff;
            }
            flightdeck_prev_hb_rows = std::move(hb_rows);
          }
          payload += "\x1b[?2026l";
          flightdeck_first_frame = false;
          const auto bound =
              raw_capture_ && raw_enabled() ? raw_ui_add(payload.size(), 64) : 0;
          RawUiFrame captured{raw_capture_, bound};
          captured.run([&] {
            auto &fd_frame = output.prepare_tiny(rows, columns, 0, 0);
            fd_frame = std::move(payload);
            captured.capture(fd_frame);
            output.start(captured.handoff());
            (void)service_output();
            render.outcome(output.pending() ? RawRegionOutcome::queued
                                            : RawRegionOutcome::flushed);
          });
          layout.finish();
          continue;
        }
        if (rows < 8 || columns < 12) {
          const auto bound =
              raw_capture_ && raw_enabled()
                  ? raw_ui_add(raw_ui_multiply(composer.text().size() + 2, 4),
                               320 + pending_osc52.size())
                  : 0;
          RawUiFrame captured{raw_capture_, bound};
          captured.run([&] {
            const auto draft = terminal_lines("> " + composer.text(), width);
            const auto cursor_column = std::min(static_cast<std::size_t>(columns),
                                                display_width(draft.back()) + 1) -
                                       1;
            auto &small_frame = output.prepare_tiny(rows, columns, 0, cursor_column);
            small_frame = "\x1b[?2026h\x1b[H\x1b[0m\x1b[2J" + draft.back();
            small_frame += "\x1b[1;" + std::to_string(cursor_column + 1) + "H";
            pending_image_loaded = false; // ED2 also invalidates Kitty image data.
            pending_image_placement = image_placement;
            if (mouse_change) {
              small_frame += mouse_target ? mouse_on : mouse_off;
              pending_mouse = mouse_target;
            }
            if (!pending_osc52.empty()) {
              small_frame += pending_osc52;
              pending_osc52.clear();
            }
            if (graphics_enabled && image_placement[2]) {
              small_frame += blackbird_graphics_erase();
              pending_image_placement = {};
            }
            if (flightdeck_pending_erase) {
              small_frame += encode_kitty_erase(hero_default_kitty_image_id);
              flightdeck_pending_erase = false;
            }
            if (flightdeck_restore_cursor) {
              small_frame += "\x1b[?25h";
              flightdeck_restore_cursor = false;
            }
            small_frame += "\x1b[?2026l";
            captured.capture(small_frame);
            output.start(captured.handoff());
            (void)service_output();
            render.outcome(RawRegionOutcome::small_frame);
          });
          layout.finish();
          continue;
        }
        const bool inspecting = inspection_open();
        const auto party_layout = terminal_party_pane_layout({width, rows});
        if (!party_auto_opened && !party_user_hidden && !party_pane.is_open() &&
            party_layout.docked && terminal_party_is_active(party_pane.snapshot())) {
          party_pane.set_open(true);
          party_pane.set_focused(false);
          party_docked = true;
          party_auto_opened = true;
        }
        if (party_pane.is_open() && !party_pane.is_focused() && party_docked &&
            !party_layout.docked) {
          party_pane.set_open(false);
          party_docked = false;
        }
        const bool show_party_docked = party_pane.is_open() && party_layout.docked;
        const bool show_party_overlay = party_pane.is_open() && !party_layout.docked;
        const bool has_tasks = !field(task_page, "items").array().empty();
        const bool show_task_pane = !inspecting && !welcoming && !tasks_hidden &&
                                    !show_party_docked && (has_tasks || tasks_forced) &&
                                    width >= 90 && rows >= 18;
        const auto pane_width =
            show_task_pane ? std::clamp(width / 3, std::size_t{28}, std::size_t{36})
                           : 0;
        const auto main_width = show_party_docked ? party_layout.main_width
                                : show_task_pane  ? width - pane_width - 2
                                                  : width;
        const auto inner_width = main_width - 4;
        const auto composed =
            terminal_powerword_lines("> " + composer.text(), inner_width);
        const auto caret = terminal_caret("> " + composer.text(),
                                          {composer.cursor() + 2}, {inner_width});
        const auto draft_height = std::min<std::size_t>(
            {6, composed.size(), static_cast<std::size_t>(rows - 7)});
        const auto palette =
            composer.palette_lines(std::min<std::size_t>(8, rows - 5 - draft_height));
        const auto height =
            static_cast<std::size_t>(rows - 5) - draft_height - palette.size();
        const bool show_sprite = !inspecting && !welcoming && mascot_enabled &&
                                 !show_party_docked &&
                                 (!tasks_expanded || show_task_pane) &&
                                 width >= (graphics_enabled ? 70U : 90U) &&
                                 height + 2 >= blackbird_sprite_height;
        const auto header_width = (show_task_pane || show_party_docked) ? main_width
                                  : show_sprite ? width - blackbird_sprite_width - 2
                                                : width;
        // The square occupies a right gutter, including beside the first chat rows.
        // Wrap into the remaining columns so a sprite can never overwrite content.
        const std::vector<ChatRow> empty_lines;
        const auto &lines = inspecting ? empty_lines : transcript.rows(header_width);
        if (welcoming && (geometry_changed || welcome_lines.empty()))
          welcome_lines =
              blackbird_startup(width - 4, height > 2 ? height - 2 : 0, mascot_enabled);
        if (!inspecting && display_generation != transcript.cleared_generation()) {
          scroll = 0; // Explicit /clear returns to the live tail.
          display_generation = transcript.cleared_generation();
        }
        if (!inspecting && scroll > 0 && same_width)
          scroll = terminal_scroll_after_output({.scroll = scroll,
                                                 .previous = previous_lines,
                                                 .before_trim = lines.size(),
                                                 .after_trim = lines.size(),
                                                 .height = height});
        if (!inspecting) {
          previous_lines = lines.size();
          scroll = std::min(scroll, lines.size() > height ? lines.size() - height : 0);
        }
        const auto end = inspecting ? 0 : lines.size() - scroll;
        const auto begin = end > height ? end - height : 0;
        layout.stage(2);
        grid.reset(width, rows);
        auto title = title_;
        const auto path = title.rfind(" · /");
        if (path != std::string::npos)
          title = title.substr(0, path) + " · " +
                  std::filesystem::path(title.substr(path + 4)).filename().string();
        grid.line(0,
                  {{" " + terminal_lines(title, header_width - 1)[0], Ink::assistant}});
        std::string status_line;
        if (busy)
          status_line = "Turn " +
                        std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                                           now - started)
                                           .count()) +
                        "s · ";
        if (tool_active)
          status_line +=
              "Tool " +
              std::to_string(
                  std::chrono::duration_cast<std::chrono::seconds>(now - tool_started)
                      .count()) +
              "s · ";
        else if (busy && live_provider && stream_bytes > 0)
          status_line += "Streaming " + format_stream_bytes(stream_bytes) + " · ";
        if (!queued.empty())
          status_line += "queued " + std::to_string(queued.size()) + " · ";
        if (scroll > 0)
          status_line += "Up " + std::to_string(scroll) + " · ";
        status_line += activity;
        constexpr std::array<std::string_view, 10> spinner{"⠋", "⠙", "⠹", "⠸", "⠼",
                                                           "⠴", "⠦", "⠧", "⠇", "⠏"};
        const auto phase =
            static_cast<std::size_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(now - started)
                    .count() /
                80) %
            spinner.size();
        // No badge in a row too narrow to hold it beside the status text.
        const auto badge = context_badge.empty() || header_width < 24
                               ? std::string{}
                               : context_badge + " ";
        const auto badge_width = std::min(display_width(badge), header_width / 2);
        const auto raw_party_pill =
            terminal_party_status_pill(party_pane, show_party_docked);
        const auto party_pill = raw_party_pill.empty() || header_width < 28
                                    ? std::string{}
                                    : "· " + raw_party_pill + " ";
        const auto party_pill_budget =
            header_width > badge_width + 12 ? (header_width - badge_width) / 2 : 0U;
        const auto shown_party_pill =
            party_pill.empty() || party_pill_budget == 0
                ? std::string{}
                : terminal_lines(party_pill, party_pill_budget)[0];
        const auto party_pill_width = display_width(shown_party_pill);
        const auto status_budget = header_width > badge_width + party_pill_width
                                       ? header_width - badge_width - party_pill_width
                                       : std::size_t{1};
        const auto status_text = terminal_lines(
            std::string{busy ? spinner[phase] : "·"} + " " + status_line + " ",
            status_budget)[0];
        const auto shown_badge =
            badge.empty() ? std::string{} : terminal_lines(badge, badge_width)[0];
        // Alternate inks every 250 ms while blinking, then hold the steady ink.
        const auto since = context_changed_at
                               ? now - *context_changed_at
                               : std::chrono::steady_clock::duration::max();
        const bool lit =
            since >= context_blink || (since / std::chrono::milliseconds{250}) % 2 == 0;
        const Ink party_pill_ink = party_pane.unread_count() > 0 ? Ink::selected
                                   : terminal_party_is_active(party_pane.snapshot())
                                       ? Ink::assistant
                                       : Ink::muted;
        std::string rule;
        for (auto n = display_width(status_text) + display_width(shown_badge) +
                      party_pill_width;
             n < header_width; ++n)
          rule += "─";
        grid.line(1, {{status_text, busy ? Ink::user : Ink::muted},
                      {shown_badge, lit ? Ink::selected : Ink::muted},
                      {shown_party_pill, party_pill_ink},
                      {rule, Ink::border}});
        if (show_sprite) {
          const auto &sprite = blackbird_sprite(busy, phase / 2);
          const auto ink = turn_failed   ? Ink::failure
                           : tool_active ? Ink::user
                           : busy        ? Ink::assistant
                                         : Ink::muted;
          for (std::size_t row = 0; row < sprite.size(); ++row)
            if (graphics_enabled)
              grid.line(row, {{"│", ink}}, width - blackbird_sprite_width - 1);
            else
              grid.line(row, {{sprite[row], ink}}, width - blackbird_sprite_width);
        }
        std::array<std::size_t, 4> placement{};
        if (welcoming) {
          std::size_t lettering_row = 2, lettering_column = 2;
          if (graphics_enabled) {
            std::size_t lettering_width = 0;
            for (const auto &line : welcome_lines)
              lettering_width = std::max(lettering_width, display_width(line));
            const auto lettering_height = welcome_lines.size();
            const auto reserved = lettering_width + 6;
            if (width >= reserved + 24 &&
                height >= std::max<std::size_t>(12, lettering_height)) {
              const auto side = std::min(height, (width - reserved) / 2);
              placement = {2, 2, side * 2, side};
              lettering_column = side * 2 + 6;
              lettering_row += (side - lettering_height) / 2;
            } else if (height > lettering_height + 1) {
              const auto side =
                  std::min(height - lettering_height - 1, (width - 4) / 2);
              placement = {lettering_row + lettering_height + 1, 2, side * 2, side};
            }
          }
          for (std::size_t row = 0; row < std::min(height, welcome_lines.size()); ++row)
            grid.line(row + lettering_row, {{welcome_lines[row], Ink::assistant}},
                      lettering_column);
          if (!graphics_enabled && welcome_lines.size() + 1 < height)
            grid.line(welcome_lines.size() + 3,
                      {{"  Enter continues · / commands · Workflow reloads each turn.",
                        Ink::muted}});
        } else if (!inspecting && (!tasks_expanded || show_task_pane)) {
          chat_begin_line = begin;
          chat_end_line = end;
          chat_height = height;
          chat_width = main_width;
          ChatSelectionRange sel_norm{};
          if (chat_selection.active) {
            sel_norm = {chat_selection.anchor_line, chat_selection.anchor_col,
                        chat_selection.focus_line, chat_selection.focus_col};
            if (sel_norm.start_line > sel_norm.end_line ||
                (sel_norm.start_line == sel_norm.end_line &&
                 sel_norm.start_col > sel_norm.end_col)) {
              std::swap(sel_norm.start_line, sel_norm.end_line);
              std::swap(sel_norm.start_col, sel_norm.end_col);
            }
          }
          for (std::size_t row = 0; row < height; ++row) {
            if (begin + row < end) {
              grid.line(row + 2, lines[begin + row]);
              const auto line_idx = begin + row;
              if (chat_selection.active && line_idx >= sel_norm.start_line &&
                  line_idx <= sel_norm.end_line && main_width > 4) {
                const auto content_max = main_width - 5;
                const auto c_lo = line_idx == sel_norm.start_line ? sel_norm.start_col
                                                                  : std::size_t{0};
                const auto c_hi = line_idx == sel_norm.end_line
                                      ? std::min(sel_norm.end_col, content_max)
                                      : content_max;
                if (c_lo <= c_hi) {
                  for (std::size_t c = 4 + c_lo; c <= 4 + c_hi && c < grid.width; ++c)
                    grid.cells[(row + 2) * grid.width + c].ink = Ink::highlight;
                }
              }
            }
          }
        } else {
          chat_height = 0;
        }
        if (graphics_enabled && show_sprite)
          placement = {0, width - blackbird_sprite_width, blackbird_sprite_width,
                       blackbird_sprite_height};
        const auto task_width = show_task_pane ? pane_width : main_width;
        if (!inspecting && (task_rows_dirty || task_render_width != task_width)) {
          task_rows = task_pane_rows(task_page, task_width, task_activity);
          task_render_width = task_width;
          task_rows_dirty = false;
        }
        if (show_task_pane) {
          for (std::size_t row = 0; row < rows; ++row)
            grid.line(row, {{"│", Ink::border}}, main_width);
          const auto task_start = show_sprite ? blackbird_sprite_height + 1 : 2;
          for (std::size_t row = 0;
               row < task_rows.size() && row + task_start + 1 < rows; ++row)
            grid.line(row + task_start, task_rows[row], main_width + 2);
          grid.line(rows - 1, {{"/tasks up/down · fold ID", Ink::muted}},
                    main_width + 2);
        } else if (!inspecting && tasks_expanded && !welcoming) {
          for (std::size_t row = 0; row < height && row < task_rows.size(); ++row)
            grid.line(row + 2, task_rows[row]);
        } else if (!inspecting && !welcoming && !busy && !tasks_hidden &&
                   !field(task_page, "items").array().empty()) {
          grid.line(1, {{terminal_lines("Tasks: " + task_summary(task_page) +
                                            " · /tasks expand",
                                        header_width)[0],
                         Ink::muted}});
        }
        std::optional<tui::InspectorLayout> inspection_layout;
        if (inspecting) {
          const bool centered = center && center->open();
          const bool authored = instrument && instrument->open();
          const bool context_wb = workbench && workbench->open();
          const bool hooks_open = hooks_panel && hooks_panel->open();
          auto caption = context_wb   ? workbench->caption()
                         : hooks_open ? hooks_panel->caption()
                                      : std::string{authored   ? "RETAINED RESULT LAB"
                                                    : centered ? "COMMAND CENTER"
                                                               : "COMMAND RESULTS"};
          if (!route_notice.empty())
            caption = std::string{route_notice} + " · " + caption;
          visit_inspection([&](auto &view) {
            inspection_layout = unwrap(view.render(grid, {0, 2, main_width, height}));
            if (!context_wb && !hooks_open && !view.notice().empty())
              caption += " · " + std::string{view.notice()};
          });
          caption +=
              context_wb ? " · F5 advisory · F6 pin · F7 drop/restore · F8 flush · F9 "
                           "archived "
                           "· Tab focus · Esc draft"
              : hooks_open
                  ? " · F6 enable/disable · F9 defs/history · Tab focus · Esc draft"
              : authored ? " · F6 A · F7 B · F8 interrupt · Ctrl-] close"
              : centered ? " · Ctrl-X close · Tab focus · Esc draft"
                         : " · Ctrl-O close · Tab focus · Esc draft";
          grid.line(1, {{std::string(main_width, ' '), Ink::normal}});
          grid.line(1, {{terminal_lines(caption, main_width).front(), Ink::heading}});
        } else if (!route_notice.empty()) {
          grid.line(1,
                    {{terminal_lines(route_notice, main_width).front(), Ink::failure}});
        } else if (instrument_refused) {
          grid.line(1, {{"Instrument unavailable; draft retained", Ink::failure}});
        } else if (center_refused) {
          grid.line(1, {{std::string(main_width, ' '), Ink::normal}});
          grid.line(1, {{terminal_lines("Command center unavailable; draft retained",
                                        main_width)
                             .front(),
                         Ink::failure}});
        } else if (inspector_refused) {
          grid.line(1, {{std::string(main_width, ' '), Ink::normal}});
          grid.line(1, {{terminal_lines("Command inspector unavailable; draft retained",
                                        main_width)
                             .front(),
                         Ink::failure}});
        }
        std::size_t menu_row = height + 2;
        for (const auto &line : palette) {
          const auto text = terminal_lines(line, main_width)[0];
          const bool selected = text.starts_with("> ");
          if (selected || text.starts_with("  /")) {
            const auto name_end = text.find(' ', 2);
            const auto command_end =
                name_end == std::string::npos ? text.size() : name_end;
            grid.line(menu_row++, {{text.substr(0, command_end),
                                    selected ? Ink::selected : Ink::normal},
                                   {text.substr(command_end), Ink::muted}});
          } else {
            grid.line(menu_row++, {{text, line.starts_with("Commands") ? Ink::heading
                                                                       : Ink::muted}});
          }
        }
        std::string hint = composer.palette_open() ? " command palette "
                           : composer.slash_open() ? " commands "
                           : busy ? " Enter queue · Esc stop · Ctrl-C stop+clear "
                                  : " Enter send · / commands · Ctrl-G editor ";
        if (!foreground_job.empty())
          hint = std::string{foreground_pty ? " PTY input "
                                            : " Enter queue · Foreground command "} +
                 foreground_job + " · Ctrl-B background ";
        auto border = [&](std::pair<std::string_view, std::string_view> corners,
                          std::string_view label) {
          std::string out{corners.first};
          const auto clipped = terminal_lines(label, main_width - 2)[0];
          out += clipped;
          for (auto n = display_width(clipped); n < main_width - 2; ++n)
            out += "─";
          return out + std::string{corners.second};
        };
        grid.line(menu_row++, {{border({"╭", "╮"}, hint), Ink::border}});
        const auto cursor_row = caret.row;
        const auto draft_begin =
            cursor_row >= draft_height ? cursor_row - draft_height + 1 : 0;
        for (std::size_t row = 0; row < draft_height; ++row) {
          const auto line = draft_begin + row < composed.size()
                                ? chat_plain(composed[draft_begin + row])
                                : "";
          ChatRow content{{"│ ", Ink::border}};
          if (draft_begin + row < composed.size()) {
            const auto &colored = composed[draft_begin + row];
            content.insert(content.end(), colored.begin(), colored.end());
          }
          content.push_back(
              {std::string(inner_width - std::min(inner_width, display_width(line)),
                           ' ') +
                   " │",
               Ink::border});
          grid.line(menu_row++, content);
        }
        if (!welcoming && !inspecting && live_telemetry.requests > 0 &&
            main_width >= 20) {
          const auto rail = terminal_avionics_rail(live_telemetry, main_width - 5);
          if (!rail.empty()) {
            ChatRow bottom{{"╰ ", Ink::border}};
            std::size_t used = 2;
            for (const auto &seg : rail) {
              used += display_width(seg.text);
              bottom.push_back(seg);
            }
            std::string trail = " ";
            ++used;
            for (; used + 1 < main_width; ++used)
              trail += "─";
            trail += "╯";
            bottom.push_back({std::move(trail), Ink::border});
            grid.line(menu_row, std::move(bottom));
          } else {
            grid.line(menu_row, {{border({"╰", "╯"}, ""), Ink::border}});
          }
        } else {
          grid.line(menu_row, {{border({"╰", "╯"}, ""), Ink::border}});
        }
        if (show_party_docked || show_party_overlay) {
          terminal_render_party_pane(grid, party_pane, party_layout);
          if (show_party_overlay)
            chat_height = 0;
        }
        const auto cursor_line = height + palette.size() + 4 + cursor_row - draft_begin;
        const auto cells = caret.column.value;
        std::size_t display_cursor_line =
            inspecting && inspection_focused() && inspection_layout
                ? inspection_layout->bounds.y + 1
            : composer.palette_open() ? height + 3
                                      : cursor_line;
        std::size_t display_cursor_cells =
            inspecting && inspection_focused() ? 1
            : composer.palette_open()
                ? terminal_caret(palette.front(), {palette.front().size() - 1},
                                 {std::numeric_limits<std::size_t>::max()})
                          .column.value +
                      1
                : cells + 3;
        std::size_t cursor_max_col = main_width;
        if (party_pane.is_open() && party_pane.is_focused() &&
            party_layout.height > 0 && party_layout.width > 0) {
          const bool boxed = !party_layout.docked && party_layout.width >= 10 &&
                             party_layout.height >= 6;
          const std::size_t footer_row_0 =
              boxed ? party_layout.row + party_layout.height - 2U
                    : party_layout.row + party_layout.height - 1U;
          const std::size_t inner_col_0 =
              boxed ? party_layout.col + 1U : party_layout.col;
          const std::size_t inner_w =
              boxed ? party_layout.width - 2U : party_layout.width;
          const std::string prompt_text =
              "To: " + party_chat_sanitize(party_pane.selected_target(), 48) + " > " +
              party_chat_sanitize(party_pane.composer_text(), 1024);
          const std::size_t col_offset =
              std::min(display_width(prompt_text), inner_w > 0 ? inner_w - 1U : 0U);
          display_cursor_line =
              std::min(footer_row_0 + 1U, static_cast<std::size_t>(rows));
          display_cursor_cells = inner_col_0 + col_offset + 1U;
          cursor_max_col = width;
        }
        layout.stage(3);
        const auto bound =
            raw_capture_ && raw_enabled() ? raw_ui_owned_grid_bound(grid) : 0;
        RawUiFrame captured{raw_capture_,
                            {grid.width, grid.height, display_cursor_line - 1,
                             std::min(display_cursor_cells, cursor_max_col) - 1},
                            bound};
        auto &packet = captured.run([&]() -> std::string & {
          auto &result =
              output.prepare(display_cursor_line - 1,
                             std::min(display_cursor_cells, cursor_max_col) - 1, false,
                             recover ? ChatPaintPolicy::full : ChatPaintPolicy::erase);
          captured.capture(result);
          return result;
        });
        if (!packet.empty()) {
          pending_image_loaded = image_loaded && !recover;
          pending_image_placement = image_placement;
          const bool graphics_update =
              graphics_enabled && (recover || placement != image_placement);
          const bool osc52_update = !pending_osc52.empty();
          const bool flightdeck_cleanup =
              flightdeck_pending_erase || flightdeck_restore_cursor;
          if (graphics_update || mouse_change || osc52_update || flightdeck_cleanup) {
            layout.stage(4);
            constexpr auto digits = std::numeric_limits<std::size_t>::digits10 + 1;
            const auto image_bound =
                raw_capture_ && raw_enabled()
                    ? raw_ui_add(packet.size(), 4096 + 320 + 4 * digits +
                                                    mouse_on.size() +
                                                    pending_osc52.size())
                    : 0;
            RawUiFrame image{raw_capture_, image_bound};
            image.run([&] {
              // Insert image, mouse-mode, and OSC 52 commands before the existing
              // synchronized-update close.
              packet.resize(packet.size() - std::string_view{"\x1b[?2026l"}.size());
              if (mouse_change) {
                packet += mouse_target ? mouse_on : mouse_off;
                pending_mouse = mouse_target;
              }
              if (osc52_update) {
                packet += pending_osc52;
                pending_osc52.clear();
              }
              if (flightdeck_pending_erase) {
                packet += encode_kitty_erase(hero_default_kitty_image_id);
                flightdeck_pending_erase = false;
              }
              if (flightdeck_restore_cursor) {
                packet += "\x1b[?25h";
                flightdeck_restore_cursor = false;
              }
              if (graphics_update) {
                packet += blackbird_graphics_erase();
                if (placement[2] && placement[3]) {
                  if (!pending_image_loaded) {
                    packet += blackbird_graphics_load();
                    pending_image_loaded = true;
                  }
                  packet += blackbird_graphics_place(placement[0], placement[1],
                                                     placement[2], placement[3]);
                }
                pending_image_placement = placement;
              }
              packet += "\x1b[?2026l";
              image.capture(packet);
              output.start(image.handoff());
            });
            captured.discard();
          } else
            output.start(captured.handoff());
          (void)service_output();
        }
        if (packet.empty()) {
          captured.discard();
          output.abandon();
        }
        render.outcome(output.pending() ? RawRegionOutcome::queued
                                        : RawRegionOutcome::flushed);
        layout.finish();
      } catch (...) {
        layout.capture_exception(4075);
        layout.close();
        throw;
      }
    }
    std::array<pollfd, 4> inputs{
        {{STDIN_FILENO, POLLIN, 0},
         {notifications.read_fd(), POLLIN, 0},
         {STDOUT_FILENO, static_cast<short>(output.pending() ? POLLOUT : 0), 0},
         {resize_->read_fd(), POLLIN, 0}}};
    const int poll_timeout_ms = [&]() -> int {
      if (flightdeck_open) {
        const auto poll_now = std::chrono::steady_clock::now();
        auto next_wake = flightdeck_next_frame;
        if (!flightdeck_escape.empty() && flightdeck_escape_deadline < next_wake)
          next_wake = flightdeck_escape_deadline;
        if (next_wake <= poll_now)
          return 1;
        const auto remaining_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(next_wake - poll_now)
                .count();
        return static_cast<int>(std::clamp<std::int64_t>(remaining_ms, 1, 33));
      }
      if (composer.escape_pending() || !child_escape.empty() || !party_escape.empty())
        return 50;
      if (busy || commands)
        return 40;
      if (context_blinking(std::chrono::steady_clock::now()))
        return 125;
      return 1000;
    }();
    const auto ready = terminal_native_poll(&terminal_context, inputs, poll_timeout_ms);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      throw std::runtime_error("Terminal polling failed");
    }
    if (inputs[3].revents & (POLLIN | POLLHUP | POLLERR)) {
      resize_->observed();
      viewport_invalidated = true;
      redraw = true;
    }
    if (inputs[1].revents & POLLIN)
      terminal_notification_drain(&terminal_context, notifications.read_fd());
    ui_capture.require();
    auto close_flightdeck = [&] {
      flightdeck_open = false;
      flightdeck_escape.clear();
      flightdeck_control = {};
      flightdeck_prev_hb_rows.clear();
      if (flightdeck_kitty_emitted) {
        flightdeck_pending_erase = true;
        flightdeck_kitty_emitted = false;
      }
      flightdeck_restore_cursor = true;
      viewport_invalidated = true;
      redraw = true;
    };
    auto open_flightdeck = [&] {
      flightdeck_open = true;
      flightdeck_first_frame = true;
      flightdeck_escape.clear();
      flightdeck_control = {};
      flightdeck_prev_hb_rows.clear();
      flightdeck_last_step = std::chrono::steady_clock::now();
      flightdeck_next_frame = std::chrono::steady_clock::time_point::min();
      viewport_invalidated = true;
      redraw = true;
    };
    // Service the same deadline policy before either ready-input or idle dispatch.
    if (flightdeck_open && !flightdeck_escape.empty() &&
        std::chrono::steady_clock::now() >= flightdeck_escape_deadline) {
      if (flightdeck_escape == "\x1b")
        close_flightdeck();
      else
        flightdeck_escape.clear();
    }
    if (party_pane.is_focused() && !party_escape.empty() &&
        std::chrono::steady_clock::now() >= party_escape_deadline) {
      if (party_escape == "\x1b") {
        party_pane.set_focused(false);
        if (columns < kTerminalPartyDockedMinCols || !party_docked) {
          party_pane.set_open(false);
          party_docked = false;
        }
      }
      party_escape.clear();
      redraw = true;
    }
    const auto dispatch = terminal_input_dispatch(
        composer, std::chrono::steady_clock::now(), escape_deadline, inputs[0].revents);
    redraw = redraw || dispatch.redraw;
    if (dispatch.bare_escape) {
      if (inspection_open()) {
        if (inspection_focused())
          visit_inspection([](auto &view) { view.focus_editor(); });
        else
          (void)select_view(tui::ViewRoute::conversation, {}, false, false);
        redraw = true;
      } else if (busy) {
        cancel_turn();
        activity = queued.empty() ? "Stopping" : "Stopping (queue kept)";
        redraw = true;
      }
    } else if (dispatch.focus_editor) {
      visit_inspection([](auto &view) { view.focus_editor(); });
    }
    if (!dispatch.read_input)
      continue;
    char bytes[128];
    RawRegion input{raw_regions::command_input_save};
    std::optional<RawCapacityClaim> keyboard_data;
    if (raw_enabled())
      keyboard_data.emplace(unwrap(raw_claim_data(1155081)));
    auto keyboard_control = raw_command_claim(21950 + raw_wake_single_notify_credit);
    auto session_control = raw_ui_control(raw_capture_, raw_ui_keyboard_credit);
    const int ui_descriptor = STDIN_FILENO;
    const auto ui_requested = sizeof(bytes);
    RawUiTrace keyboard_process{raw_capture_,
                                {4085, 4084},
                                std::array{detail::raw_native_field(ui_descriptor),
                                           detail::raw_native_field(ui_requested)},
                                raw_ui_keyboard_batch_credit};
    std::optional<RawCommandBurstScope> keyboard_burst;
    keyboard_burst.emplace(
        RawCommandBurstCredits{keyboard_data ? &*keyboard_data : nullptr,
                               keyboard_control ? &*keyboard_control : nullptr});
    const auto requested = sizeof(bytes);
    const int descriptor = STDIN_FILENO;
    const auto keyboard_request =
        raw_command_record(2040,
                           std::array{detail::raw_native_field(descriptor),
                                      detail::raw_native_field(requested)},
                           keyboard_control ? &*keyboard_control : nullptr);
    const auto count = read(STDIN_FILENO, bytes, sizeof(bytes));
    const int read_error = errno;
    const auto literal =
        count > 0 ? std::as_bytes(std::span{bytes, static_cast<std::size_t>(count)})
                  : ByteView{};
    keyboard_read =
        raw_command_linked(2041, keyboard_request,
                           std::array{detail::raw_native_field(count),
                                      detail::raw_native_field(read_error), literal},
                           count > 0          ? nullptr
                           : keyboard_control ? &*keyboard_control
                                              : nullptr);
    keyboard_process.extent(count > 0 ? static_cast<std::size_t>(count) : 0);
    (void)keyboard_process.event(
        4086, std::array{ByteView{keyboard_read.lane},
                         detail::raw_native_field(keyboard_read.ordinal),
                         detail::raw_native_field(count)});
    if (count < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
        keyboard_process.finish();
        continue;
      }
      keyboard_process.finish(1, Error{ErrorCode::io, errno});
      throw Error{ErrorCode::io, errno};
    }
    if (count == 0) {
      quitting = true;
      cancel_turn();
      persist();
      keyboard_process.finish();
      continue;
    }
    bool saved_last_input = false;
    auto dispatch_synthetic_command = [&](const std::string &command,
                                          RawEventRef actor) {
      const auto length = command.size();
      RawUiTrace command_original{raw_capture_,
                                  {4071, 4016},
                                  std::array{ByteView{actor.lane},
                                             detail::raw_native_field(actor.ordinal),
                                             detail::raw_native_field(length),
                                             detail::raw_string_field(command)},
                                  raw_ui_error_bytes,
                                  true};
      command_original.run([&] {
        const RawUiSource source{command_original.reference(), 0, length};
        command_original.finish();
        if (busy || !queued.empty()) {
          auto copy = command;
          (void)enqueue_ui_prompt(raw_capture_, queued, copy, source, 1, actor,
                                  session_control ? &*session_control : nullptr);
        } else {
          (void)start(command, source);
        }
      });
    };
    for (ssize_t i = 0; i < count; ++i) {
      saved_last_input = false; // Later bytes can change the submitted state.
      if (foreground_pty) {
        const char byte = bytes[i];
        // The outer terminal's paste envelope is transport, not child input.
        // Parse across reads; controls inside it remain literal child bytes.
        if (byte == '\x02' && !child_pasted) {
          if (!child_escape.starts_with("\x1b[<"))
            append_child_input(child_escape);
          child_escape.clear();
          (void)flush_child_input();
          release_command({});
        } else if (!child_escape.empty() || byte == '\x1b') {
          if (child_escape.empty())
            child_escape_deadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
          child_escape += byte;
          const std::string_view begin{"\x1b[200~"}, end{"\x1b[201~"};
          // Child output is escaped text, so a child never enables outer mouse
          // reporting: an SGR report is always Blackbird's, possibly in flight
          // after the off packet. Hold it to its final byte, then drop it.
          const auto u = static_cast<unsigned char>(byte);
          const bool sgr_report = !child_pasted && child_escape.starts_with("\x1b[<");
          if (child_escape == begin) {
            child_pasted = true;
            child_escape.clear();
          } else if (child_escape == end) {
            child_pasted = false;
            child_escape.clear();
          } else if (sgr_report &&
                     (child_escape.size() == 3 || (u >= 0x30U && u <= 0x3fU))) {
            // Still inside the report: keep holding it.
          } else if (sgr_report && (byte == 'M' || byte == 'm')) {
            child_escape.clear();
          } else if (!begin.starts_with(child_escape) &&
                     !end.starts_with(child_escape)) {
            append_child_input(child_escape);
            child_escape.clear();
          }
        } else {
          append_child_input(std::string_view{&byte, 1});
        }
        redraw = true;
        keyboard_process.progress(static_cast<std::size_t>(i) + 1);
        continue;
      }
      if (bytes[i] == '\x02' && !foreground_job.empty() && !composer.pasted() &&
          !composer.escape_pending()) {
        release_command({});
        keyboard_process.progress(static_cast<std::size_t>(i) + 1);
        continue;
      }
      if (flightdeck_open) {
        const char byte = bytes[i];
        const auto u = static_cast<unsigned char>(byte);
        const auto input_now = std::chrono::steady_clock::now();
        auto steer = [&](HeroControlInput ctl) {
          flightdeck_control = ctl;
          flightdeck_steer_until = input_now + std::chrono::milliseconds{220};
          if (input_now >= flightdeck_next_frame)
            redraw = true;
        };
        if (!flightdeck_escape.empty()) {
          if (u == 27U) {
            flightdeck_escape = byte;
            flightdeck_escape_deadline = input_now + std::chrono::milliseconds{50};
            keyboard_process.progress(static_cast<std::size_t>(i) + 1);
            continue;
          }
          flightdeck_escape += byte;
          const bool sgr_mouse =
              flightdeck_escape.starts_with("\x1b[<") && (byte == 'M' || byte == 'm');
          if (flightdeck_escape == "\x1b"
                                   "f" ||
              flightdeck_escape == "\x1b[102;3u") {
            close_flightdeck();
          } else if (flightdeck_escape == "\x1b[A" || flightdeck_escape == "\x1bOA") {
            steer(HeroControlInput{.up = true, .stick_y = -1.0F});
            flightdeck_escape.clear();
          } else if (flightdeck_escape == "\x1b[B" || flightdeck_escape == "\x1bOB") {
            steer(HeroControlInput{.down = true, .stick_y = 1.0F});
            flightdeck_escape.clear();
          } else if (flightdeck_escape == "\x1b[D" || flightdeck_escape == "\x1bOD") {
            steer(HeroControlInput{.left = true, .stick_x = -1.0F});
            flightdeck_escape.clear();
          } else if (flightdeck_escape == "\x1b[C" || flightdeck_escape == "\x1bOC") {
            steer(HeroControlInput{.right = true, .stick_x = 1.0F});
            flightdeck_escape.clear();
          } else if (sgr_mouse) {
            flightdeck_escape.clear();
          } else if (flightdeck_escape.size() == 2 && (byte == '[' || byte == 'O')) {
            // Wait for CSI / SS3 parameters and final byte.
          } else if (flightdeck_escape.starts_with("\x1b[") &&
                     flightdeck_escape.size() >= 3U && flightdeck_escape.size() < 64U &&
                     u >= 0x20U && u <= 0x3fU) {
            // Accumulate bounded CSI parameter (0x30..0x3f) & intermediate (0x20..0x2f)
            // bytes until the final byte (0x40..0x7e).
          } else {
            flightdeck_escape.clear();
          }
          keyboard_process.progress(static_cast<std::size_t>(i) + 1);
          continue;
        }
        if (u == 27U) {
          flightdeck_escape = byte;
          flightdeck_escape_deadline = input_now + std::chrono::milliseconds{50};
        } else if (byte == 'q' || byte == 'Q' || u == 3U) {
          close_flightdeck();
        } else if (u == 17U) {
          close_flightdeck();
          quitting = true;
          cancel_turn();
        } else if (byte == 'w' || byte == 'W') {
          steer(HeroControlInput{.up = true, .stick_y = -1.0F});
        } else if (byte == 's' || byte == 'S') {
          steer(HeroControlInput{.down = true, .stick_y = 1.0F});
        } else if (byte == 'a' || byte == 'A') {
          steer(HeroControlInput{.left = true, .stick_x = -1.0F});
        } else if (byte == 'd' || byte == 'D') {
          steer(HeroControlInput{.right = true, .stick_x = 1.0F});
        } else if (byte == 't' || byte == 'T') {
          if (!flightdeck_engine)
            flightdeck_engine.emplace(HeroCanvasConfig{});
          flightdeck_engine->cycle_theme();
          redraw = true;
        } else if (byte == 'g' || byte == 'G') {
          if (!flightdeck_engine)
            flightdeck_engine.emplace(HeroCanvasConfig{});
          if (!question) {
            if (flightdeck_demo_gate_active) {
              flightdeck_engine->set_question(std::nullopt);
              flightdeck_demo_gate_active = false;
            } else {
              HeroQuestion demo{};
              demo.from = "flight-ops";
              demo.text = "Select flight profile";
              demo.detail = "Fly into gate for 1.5s or press 1/2/3";
              demo.options = {"MACH 3.2", "CRUISE", "STEALTH"};
              flightdeck_engine->set_question(std::move(demo));
              flightdeck_demo_gate_active = true;
            }
            redraw = true;
          }
        } else if (byte == '1' || byte == '2' || byte == '3') {
          if (flightdeck_engine &&
              flightdeck_engine->answer_by_key(static_cast<std::size_t>(byte - '1'))) {
            if (const auto picked = flightdeck_engine->take_answered_index();
                picked.has_value()) {
              if (flightdeck_demo_gate_active) {
                flightdeck_demo_gate_active = false;
              } else if (question && !busy && *picked < question->choices.size()) {
                dispatch_synthetic_command(question->choices[*picked].name,
                                           keyboard_read);
              }
            }
            redraw = true;
          }
        }
        keyboard_process.progress(static_cast<std::size_t>(i) + 1);
        continue;
      }
      if (party_pane.is_open() && party_pane.is_focused()) {
        const char byte = bytes[i];
        const auto u = static_cast<unsigned char>(byte);
        welcoming = false;
        redraw = true;
        if (!party_escape.empty()) {
          party_escape += byte;
          const bool sgr_mouse =
              party_escape.starts_with("\x1b[<") && (byte == 'M' || byte == 'm');
          if (party_escape == "\x1b"
                              "f" ||
              party_escape == "\x1b[102;3u") {
            party_pane.set_focused(false);
            party_escape.clear();
            open_flightdeck();
          } else if (party_escape == "\x1b"
                                     "p" ||
                     party_escape == "\x1b[112;3u") {
            party_pane.set_focused(false);
            if (columns < kTerminalPartyDockedMinCols || !party_docked) {
              party_pane.set_open(false);
              party_docked = false;
            }
            party_escape.clear();
          } else if (party_escape == "\x1b"
                                     "P" ||
                     party_escape == "\x1b[80;3u" || party_escape == "\x1b[112;4u") {
            party_pane.set_focused(false);
            party_pane.set_open(false);
            party_docked = false;
            party_user_hidden = true;
            party_escape.clear();
          } else if (party_escape == "\x1b[A" || party_escape == "\x1bOA") {
            party_pane.scroll_up(1);
            party_escape.clear();
          } else if (party_escape == "\x1b[B" || party_escape == "\x1bOB") {
            party_pane.scroll_down(1);
            party_escape.clear();
          } else if (party_escape == "\x1b[5~") {
            party_pane.page_up(10);
            party_escape.clear();
          } else if (party_escape == "\x1b[6~") {
            party_pane.page_down(10);
            party_escape.clear();
          } else if (sgr_mouse) {
            unsigned button = 0;
            const auto params = std::string_view{party_escape}.substr(3);
            const auto semi = params.find(';');
            (void)std::from_chars(
                params.data(),
                params.data() + (semi == std::string_view::npos ? params.size() : semi),
                button);
            if (byte == 'M' && (button & 0x43U) == 0x40U)
              party_pane.scroll_up(3);
            else if (byte == 'M' && (button & 0x43U) == 0x41U)
              party_pane.scroll_down(3);
            party_escape.clear();
          } else if (party_escape.size() == 2 && (byte == '[' || byte == 'O')) {
            // Wait for CSI / SS3 parameters and final byte.
          } else if (party_escape.size() >= 3U && party_escape.size() < 64U &&
                     (byte == '<' || (u >= 0x30U && u <= 0x3fU))) {
            // Still accumulating bounded CSI parameters.
          } else {
            party_escape.clear();
          }
          keyboard_process.progress(static_cast<std::size_t>(i) + 1);
          continue;
        }
        if (u == 27U) {
          party_escape = byte;
          party_escape_deadline =
              std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
        } else if (u == 9U) {
          party_pane.cycle_target();
        } else if (u == 13U || u == 10U) {
          std::string_view raw_text = party_pane.composer_text();
          while (!raw_text.empty() &&
                 (raw_text.front() == ' ' || raw_text.front() == '\t'))
            raw_text.remove_prefix(1);
          while (!raw_text.empty() &&
                 (raw_text.back() == ' ' || raw_text.back() == '\t' ||
                  raw_text.back() == '\r'))
            raw_text.remove_suffix(1);
          if (!raw_text.empty()) {
            const std::string target_prefix = raw_text.starts_with('@')
                                                  ? std::string{}
                                                  : party_pane.selected_target() + " ";
            const std::string cmd =
                "/party say " + target_prefix + std::string{raw_text};
            party_pane.clear_composer();
            dispatch_synthetic_command(cmd, keyboard_read);
          }
        } else if (u == 127U || u == 8U) {
          party_pane.backspace_composer();
        } else if (u == 3U) {
          if (!party_pane.composer_text().empty()) {
            party_pane.clear_composer();
          } else {
            party_pane.set_focused(false);
            if (columns < kTerminalPartyDockedMinCols || !party_docked) {
              party_pane.set_open(false);
              party_docked = false;
            }
          }
        } else if (u == 17U) {
          quitting = true;
          cancel_turn();
        } else if (u >= 32U) {
          if (party_pane.composer_text().size() < 4096U)
            party_pane.append_composer_text(std::string_view{&byte, 1});
        }
        keyboard_process.progress(static_cast<std::size_t>(i) + 1);
        continue;
      }
      const bool was_escape = composer.escape_pending();
      auto result = keyboard_process.run([&] {
        auto session_data = raw_ui_data(raw_capture_, composer.capture_bound(1));
        RawUiInput origin{raw_capture_,
                          keyboard_read,
                          static_cast<std::size_t>(i),
                          session_data ? &*session_data : nullptr,
                          session_control ? &*session_control : nullptr,
                          {}};
        auto outcome = composer.feed(bytes[i], &origin, inspection_focused());
        keyboard_process.progress(static_cast<std::size_t>(i) + 1);
        return outcome;
      });
      std::optional<RawUiTrace> handling;
      {
        RawUiBurst loan{session_control ? &*session_control : nullptr};
        const auto source = result.source.record;
        handling.emplace(
            raw_capture_ && result.action != InputAction::none, RawUiSites{4017, 4016},
            std::array{ByteView{source.lane}, detail::raw_native_field(source.ordinal)},
            raw_ui_handler_credit);
      }
      std::uint8_t action_branch = 1;
      RawEventRef action_target{};
      auto finish_action = [&] {
        (void)raw_ui_link(4011, result.source.record,
                          std::array{detail::raw_native_field(action_branch),
                                     ByteView{action_target.lane},
                                     detail::raw_native_field(action_target.ordinal)},
                          handling->credit());
        handling->close();
      };
      try {
        welcoming = false; // First operator input reveals retained chat and the avatar.
        if (!was_escape && composer.escape_pending())
          escape_deadline =
              std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
        redraw = true;
        if (result.action == InputAction::flightdeck_toggle) {
          open_flightdeck();
        }
        if (result.action == InputAction::party_toggle) {
          refresh_party_passive();
          party_user_hidden = false;
          party_pane.set_open(true);
          party_pane.set_focused(true);
          party_docked = columns >= kTerminalPartyDockedMinCols;
        }
        if (result.action == InputAction::party_hide) {
          party_pane.set_focused(false);
          party_pane.set_open(false);
          party_docked = false;
          party_user_hidden = true;
        }
        if (result.action == InputAction::select_view) {
          if (result.view) {
            if (!select_view(*result.view, result.source.record, false, false))
              transcript.append(ChatKind::notice,
                                "View unavailable; current view retained");
          } else if (result.text == "view.picker")
            composer.views(route);
        }
        if (result.action == InputAction::instrument_toggle)
          (void)select_view(tui::ViewRoute::result_comparison, result.source.record,
                            true, false);
        if (result.action == InputAction::instrument_action && instrument &&
            instrument->open() && instrument->focused()) {
          const auto acted =
              result.text == "pin_a"
                  ? instrument->pin(0, result.source.record, raw_capture_)
              : result.text == "pin_b"
                  ? instrument->pin(1, result.source.record, raw_capture_)
                  : instrument->request_interrupt(result.source.record, raw_capture_);
          if (!acted.has_value())
            transcript.append(ChatKind::notice,
                              std::string{"Instrument action unavailable: "} +
                                  error_name(acted.error().code));
        }
        auto start_view_command = [&](const std::string &command, RawEventRef actor) {
          const auto length = command.size();
          RawUiTrace command_original{
              raw_capture_,
              {4071, 4016},
              std::array{ByteView{actor.lane}, detail::raw_native_field(actor.ordinal),
                         detail::raw_native_field(length),
                         detail::raw_string_field(command)},
              raw_ui_error_bytes,
              true};
          command_original.run([&] {
            const RawUiSource source{command_original.reference(), 0, length};
            command_original.finish();
            (void)start(command, source);
          });
        };
        if ((result.action == InputAction::instrument_action ||
             result.action == InputAction::workbench_action) &&
            workbench && workbench->open() && workbench->focused()) {
          if (result.action == InputAction::workbench_action &&
              result.text == "toggle_advisory") {
            workbench->toggle_advisory();
          } else if (result.action == InputAction::workbench_action &&
                     result.text == "toggle_archived") {
            workbench->toggle_archived();
          } else if (result.action == InputAction::instrument_action) {
            const std::string_view verb = result.text == "pin_a"   ? "pin"
                                          : result.text == "pin_b" ? "drop_or_restore"
                                                                   : "flush";
            const auto action = workbench->action_command(verb);
            if (!action.command.empty()) {
              if (busy) {
                transcript.append(ChatKind::notice,
                                  "Turn running — wait for idle to mutate context\n");
              } else {
                start_view_command(action.command, result.source.record);
              }
            }
          }
        }
        if ((result.action == InputAction::instrument_action ||
             result.action == InputAction::workbench_action) &&
            hooks_panel && hooks_panel->open() && hooks_panel->focused()) {
          if (result.action == InputAction::workbench_action &&
              result.text == "toggle_archived") {
            hooks_panel->toggle_history();
          } else if (result.text == "pin_a") {
            const auto action = hooks_panel->action_command("toggle_enabled");
            if (!action.command.empty()) {
              if (busy) {
                transcript.append(ChatKind::notice,
                                  "Turn running — wait for idle to toggle hook\n");
              } else {
                start_view_command(action.command, result.source.record);
              }
            }
          }
        }
        if (result.action == InputAction::center_toggle)
          (void)select_view(tui::ViewRoute::command_center, result.source.record, true,
                            false);
        if (result.action == InputAction::inspect_toggle)
          (void)select_view(tui::ViewRoute::command_runs, result.source.record, true,
                            false);
        if (inspection_open()) {
          std::optional<tui::InspectorAction> navigation;
          switch (result.action) {
          case InputAction::inspect_previous:
            navigation = tui::InspectorAction::previous;
            break;
          case InputAction::inspect_next:
            navigation = tui::InspectorAction::next;
            break;
          case InputAction::inspect_first:
            navigation = tui::InspectorAction::first;
            break;
          case InputAction::inspect_last:
            navigation = tui::InspectorAction::last;
            break;
          case InputAction::inspect_page_up:
            navigation = tui::InspectorAction::page_previous;
            break;
          case InputAction::inspect_page_down:
            navigation = tui::InspectorAction::page_next;
            break;
          case InputAction::inspect_focus_collection:
            navigation = tui::InspectorAction::focus_collection;
            break;
          case InputAction::inspect_focus_detail:
            navigation = tui::InspectorAction::focus_detail;
            break;
          case InputAction::inspect_toggle_focus:
            navigation = tui::InspectorAction::toggle_focus;
            break;
          case InputAction::inspect_focus_editor:
            visit_inspection([](auto &view) { view.focus_editor(); });
            break;
          case InputAction::inspect_previous_output:
            if (instrument && instrument->open())
              instrument->page(false, result.source.record);
            else if (center && center->open())
              center->page(false, result.source.record);
            else if (inspector && inspector->open())
              inspector->page(false);
            else if (workbench && workbench->open())
              workbench->page(false);
            break;
          case InputAction::inspect_next_output:
            if (instrument && instrument->open())
              instrument->page(true, result.source.record);
            else if (center && center->open())
              center->page(true, result.source.record);
            else if (inspector && inspector->open())
              inspector->page(true);
            else if (workbench && workbench->open())
              workbench->page(true);
            break;
          default:
            break;
          }
          if (navigation) {
            auto moved = Result<void>::success();
            if (instrument && instrument->open())
              moved = instrument->act(*navigation, result.source.record);
            else if (center && center->open())
              moved = center->act(*navigation, result.source.record);
            else if (inspector && inspector->open())
              moved = inspector->act(*navigation);
            else if (workbench && workbench->open())
              moved = workbench->act(*navigation);
            else if (hooks_panel && hooks_panel->open())
              moved = hooks_panel->act(*navigation);
            if (!moved.has_value())
              transcript += std::string{"\nInspection navigation refused: "} +
                            error_name(moved.error().code) + "\n";
          }
        }
        if (result.action == InputAction::answer_question) {
          if (question && !busy &&
              std::any_of(
                  question->choices.begin(), question->choices.end(),
                  [&](const auto &choice) { return choice.name == result.text; })) {
            if (persist()) {
              saved_last_input = true;
              input.outcome(RawRegionOutcome::dispatch);
              input.finish();
              keyboard_burst.reset();
              keyboard_data.reset();
              keyboard_control.reset();
              // A refused launch keeps the answer in the composer.
              const bool launched = start(result.text, result.source);
              if (!launched)
                composer.draft(result.text);
              action_target = last_launch;
              action_branch = launched ? 3 : 4;
            }
          } else if (question)
            composer.choices(question->choices, question->heading);
        }
        if (result.action == InputAction::choose_command) {
          bool load = true;
          if (!composer.text().empty()) {
            auto candidate = composer.state();
            append_prompt_state(candidate.queued, recovered);
            append_prompt_state(candidate.queued, queued);
            candidate.queued.push_back(composer.text());
            try {
              validate_state(candidate);
              const auto length = composer.text().size();
              const auto draft_actor = result.source.record;
              RawUiTrace draft_original{
                  raw_capture_,
                  {4071, 4016},
                  std::array{ByteView{draft_actor.lane},
                             detail::raw_native_field(draft_actor.ordinal),
                             detail::raw_native_field(length),
                             detail::raw_string_field(composer.text())},
                  raw_ui_error_bytes,
                  true};
              draft_original.run([&] {
                auto draft = composer.text();
                const RawUiSource source{draft_original.reference(), 0, length};
                (void)enqueue_ui_prompt(raw_capture_, recovered, draft, source, 2,
                                        result.source.record);
                draft_original.finish();
              });
            } catch (const Error &) {
              ui_capture.require();
              load = false;
              transcript +=
                  "\nDraft storage full; original retained, command not loaded.\n";
            }
          }
          if (load) {
            const bool saved_draft = !composer.text().empty();
            composer.draft(std::move(result.text));
            transcript += saved_draft ? "\nCommand loaded; Enter sends explicitly. "
                                        "Previous draft in /drafts.\n"
                                      : "\nCommand loaded; Enter sends explicitly.\n";
          }
        }
        if (result.action == InputAction::edit && edit()) {
          finish_action();
          break;
        }
        if (result.action == InputAction::page_up)
          scroll += static_cast<std::size_t>(rows / 2);
        if (result.action == InputAction::page_down)
          scroll -= std::min(scroll, static_cast<std::size_t>(rows / 2));
        if (result.action == InputAction::scroll_up)
          scroll += 3;
        if (result.action == InputAction::scroll_down)
          scroll -= std::min(scroll, std::size_t{3});
        if (result.action == InputAction::mouse_press) {
          if (!inspection_open() && !welcoming && chat_height > 0 && chat_width > 4 &&
              chat_end_line > chat_begin_line && result.mouse_row >= 2 &&
              result.mouse_row < 2 + chat_height && result.mouse_col < chat_width) {
            const auto line =
                std::min(chat_begin_line + (result.mouse_row - 2), chat_end_line - 1);
            const auto col =
                result.mouse_col >= 4 ? result.mouse_col - 4 : std::size_t{0};
            chat_selection = {true, true, line, col, line, col};
          } else {
            chat_selection = {};
          }
        } else if (result.action == InputAction::mouse_drag) {
          if (chat_selection.dragging && chat_height > 0 && chat_width > 4 &&
              chat_end_line > chat_begin_line) {
            const auto clamped_row =
                std::clamp<std::size_t>(result.mouse_row, 2, 2 + chat_height - 1);
            const auto clamped_col =
                std::clamp<std::size_t>(result.mouse_col, 4, chat_width - 1);
            chat_selection.focus_line =
                std::min(chat_begin_line + (clamped_row - 2), chat_end_line - 1);
            chat_selection.focus_col = clamped_col - 4;
          }
        } else if (result.action == InputAction::mouse_release) {
          if (chat_selection.dragging) {
            chat_selection.dragging = false;
            const bool moved =
                chat_selection.anchor_line != chat_selection.focus_line ||
                chat_selection.anchor_col != chat_selection.focus_col;
            if (moved && chat_width > 4) {
              const auto &current_lines = transcript.rows(chat_width);
              const auto selected = terminal_extract_chat_selection(
                  current_lines, {chat_selection.anchor_line, chat_selection.anchor_col,
                                  chat_selection.focus_line, chat_selection.focus_col});
              if (!selected.empty()) {
                pending_osc52 = terminal_osc52_copy(selected);
                activity = "Copied " + std::to_string(selected.size()) + " B";
              }
            } else {
              chat_selection = {};
            }
          }
        } else if (result.action != InputAction::scroll_up &&
                   result.action != InputAction::scroll_down) {
          chat_selection = {};
        }
        if (result.action == InputAction::cancel) {
          action_branch = 5;
          withdraw_ui_prompts(raw_capture_, queued, 2, result.source.record,
                              session_control ? &*session_control : nullptr);
          if (busy) {
            cancel_turn();
            activity = "Stopping";
          }
        }
        if (result.action == InputAction::quit ||
            (result.action == InputAction::submit &&
             (result.text == "/quit" || result.text == "/exit"))) {
          action_branch = 6;
          quitting = true;
          cancel_turn();
        }
        if (result.action == InputAction::submit && !result.text.empty() && !quitting) {
          if (terminal_is_bang_shell_command(result.text)) {
            const auto body = terminal_bang_shell_body(result.text);
            if (body.empty()) {
              transcript +=
                  "\nUsage: !<shell command> (runs interactively on your TTY; "
                  "never sent to the model)\n";
              scroll = 0;
            } else if (run_bang_shell(body)) {
              finish_action();
              break;
            } else {
              composer.draft(std::move(result.text));
            }
          } else {
            const auto requested_view = std::find_if(
                tui::view_descriptions.begin(), tui::view_descriptions.end(),
                [&](const auto &view) {
                  return !view.command.empty() && result.text == view.command;
                });
            if (result.text == "/views") {
              composer.views(route);
            } else if (requested_view != tui::view_descriptions.end()) {
              if (!select_view(requested_view->route, result.source.record, false,
                               true))
                transcript.append(ChatKind::notice,
                                  "View unavailable; current view retained");
            } else if (commands &&
                       (result.text == "/bg" || result.text.starts_with("/bg "))) {
              release_command(result.text == "/bg"
                                  ? std::string_view{}
                                  : std::string_view{result.text}.substr(4));
            } else if (commands && busy && result.text.starts_with("/fg ") &&
                       !string_field(commands->foreground(), "job_id").empty()) {
              transcript +=
                  string_field(commands->foreground(), "job_id") ==
                          result.text.substr(4)
                      ? "\nThat command is already foreground.\n"
                      : "\nRelease the current turn before foregrounding another "
                        "command.\n";
            } else if (commands && busy && result.text.starts_with("/process ")) {
              try {
                auto request =
                    unwrap(parse_json(std::string_view{result.text}.substr(9)));
                const auto op = string_field(request, "op");
                if (op == "read")
                  transcript.append(ChatKind::assistant,
                                    unwrap(dump_json(commands->read(request))) + "\n");
                else if (op == "input" || op == "resize" || op == "signal" ||
                         op == "stop" || op == "background")
                  (void)command_request(std::move(request));
                else
                  transcript += "\nThat process operation requires an idle turn.\n";
              } catch (const Error &error) {
                transcript += std::string{"\nInvalid process control: "} +
                              error_name(error.code) + "\n";
              } catch (const std::exception &error) {
                transcript +=
                    std::string{"\nInvalid process control: "} + error.what() + "\n";
              }
            } else if (result.text == "/tasks up" || result.text == "/tasks down" ||
                       result.text == "/tasks expand" || result.text == "/tasks show" ||
                       result.text == "/tasks hide" ||
                       result.text.starts_with("/tasks fold ")) {
              const std::lock_guard lock{mutex_};
              task_anchor_.clear();
              if (result.text == "/tasks up")
                task_offset_ -= std::min(task_offset_, std::size_t{2});
              else if (result.text == "/tasks down")
                task_offset_ += 2;
              else if (result.text == "/tasks hide") {
                tasks_hidden = true;
                tasks_expanded = false;
                tasks_forced = false;
              } else if (result.text == "/tasks show") {
                tasks_hidden = false;
                tasks_expanded = false;
                tasks_forced = true;
              } else if (result.text == "/tasks expand") {
                tasks_hidden = false;
                tasks_expanded = !tasks_expanded;
              } else {
                const auto id = result.text.substr(12);
                if (const auto *row = task_state_.item(id);
                    row && string_field(*row, "parent").empty()) {
                  if (!task_folded_.erase(id))
                    task_folded_.insert(id);
                  task_offset_ = *task_state_.position(id);
                } else
                  transcript += "\nFold requires a top-level task ID.\n";
              }
              tasks_dirty_ = true;
            } else if (result.text == "/party close" || result.text == "/party hide") {
              party_pane.set_focused(false);
              party_pane.set_open(false);
              party_docked = false;
              party_user_hidden = true;
              transcript.append(ChatKind::notice, "Party Chat hidden (Alt+P reopens).");
              scroll = 0;
            } else if (result.text == "/commands") {
              (void)composer.feed(0);
            } else if (result.text == "/edit") {
              if (edit()) {
                finish_action();
                break;
              }
            } else if (result.text == "/help" || result.text == "/keys") {
              transcript += "\n" + (result.text == "/help" ? terminal_help()
                                                           : terminal_key_help());
              scroll = 0;
            } else if (result.text == "/queue") {
              transcript +=
                  "\nPending prompts: " + std::to_string(queued.size()) + "\n";
              for (std::size_t n = 0; n < queued.size(); ++n)
                transcript += std::to_string(n + 1) + ": " + queued[n].text + "\n";
              transcript += "Recovered drafts: " + std::to_string(recovered.size()) +
                            " (use /drafts)\n";
              scroll = 0;
            } else if (result.text == "/cancel") {
              action_branch = 5;
              withdraw_ui_prompts(raw_capture_, queued, 2, result.source.record,
                                  session_control ? &*session_control : nullptr);
              if (busy) {
                cancel_turn();
                activity = "Stopping";
              }
              transcript += busy ? "\nStop requested; pending queue cleared.\n"
                                 : "\nNo active turn; pending queue cleared.\n";
              scroll = 0;
            } else if (result.text == "/clear") {
              transcript.clear();
              scroll = 0;
            } else if (result.text == "/copy" || result.text == "/copy all" ||
                       result.text == "/copy user") {
              const auto payload = result.text == "/copy all"
                                       ? transcript.plain_transcript()
                                   : result.text == "/copy user"
                                       ? transcript.last_text(ChatKind::user)
                                       : transcript.last_text(ChatKind::assistant);
              if (payload.empty()) {
                transcript += "\nNothing to copy.\n";
              } else {
                pending_osc52 = terminal_osc52_copy(payload);
                const auto copied = std::min<std::size_t>(payload.size(), 100 * 1024);
                transcript += "\nCopied " + std::to_string(copied) +
                              " bytes to clipboard (OSC 52).\n";
              }
              scroll = 0;
            } else if (result.text == "/mouse" || result.text == "/mouse on" ||
                       result.text == "/mouse off") {
              if (result.text != "/mouse")
                mouse_wanted = result.text == "/mouse on";
              transcript +=
                  mouse_wanted
                      ? "\nMouse on: trackpad/wheel scrolls chat; drag in chat "
                        "selects and copies (OSC 52). Shift-drag uses terminal "
                        "selection. /mouse off disables reporting.\n"
                      : "\nMouse off: native terminal drag-select active. "
                        "/mouse on restores trackpad scroll and chat-bounded "
                        "selection.\n";
              scroll = 0;
            } else if (result.text == "/drafts") {
              transcript +=
                  "\nRecovered drafts: " + std::to_string(recovered.size()) + "\n";
              for (std::size_t n = 0; n < recovered.size(); ++n)
                transcript += std::to_string(n + 1) + ": " + recovered[n].text + "\n";
            } else if (result.text.starts_with("/draft ")) {
              std::size_t n = 0;
              const auto arg = std::string_view{result.text}.substr(7);
              const auto r = std::from_chars(arg.data(), arg.data() + arg.size(), n);
              if (r.ec != std::errc{} || r.ptr != arg.data() + arg.size() || n == 0 ||
                  n > recovered.size())
                transcript += "\nInvalid recovered draft number.\n";
              else {
                auto credit = raw_ui_control(raw_capture_, 73);
                const std::uint8_t branch = 4;
                const auto index = n - 1;
                const auto target = result.source.record;
                (void)raw_ui_link(4015, recovered[index].enqueue,
                                  std::array{detail::raw_native_field(branch),
                                             detail::raw_native_field(index),
                                             ByteView{target.lane},
                                             detail::raw_native_field(target.ordinal)},
                                  credit ? &*credit : nullptr);
                action_branch = 7;
                action_target = recovered[n - 1].enqueue;
                composer.draft(std::move(recovered[n - 1].text));
                recovered.erase(recovered.begin() + static_cast<std::ptrdiff_t>(n - 1));
                transcript += "\nLoaded recovered draft; Enter submits explicitly.\n";
              }
            } else if (question) {
              const bool answer = std::any_of(
                  question->choices.begin(), question->choices.end(),
                  [&](const auto &choice) { return choice.name == result.text; });
              if (answer && !busy) {
                if (persist()) {
                  saved_last_input = true;
                  input.outcome(RawRegionOutcome::dispatch);
                  input.finish();
                  keyboard_burst.reset();
                  keyboard_data.reset();
                  keyboard_control.reset();
                  // A refused launch keeps the answer in the composer.
                  const bool launched = start(result.text, result.source);
                  if (!launched)
                    composer.draft(result.text);
                  action_target = last_launch;
                  action_branch = launched ? 3 : 4;
                }
              } else {
                composer.draft(std::move(result.text));
                transcript.append(ChatKind::notice, question->heading);
                composer.choices(question->choices, question->heading);
              }
            } else if (busy || !queued.empty()) {
              wake_refused =
                  false; // An explicit submission permits the queued owner to retry.
              auto candidate = composer.state();
              append_prompt_state(candidate.queued, recovered);
              append_prompt_state(candidate.queued, queued);
              candidate.queued.push_back(result.text);
              try {
                validate_state(candidate);
                action_target =
                    enqueue_ui_prompt(raw_capture_, queued, result.text, result.source,
                                      1, result.source.record,
                                      session_control ? &*session_control : nullptr);
                action_branch = 2;
                {
                  const auto lf = result.text.find('\n');
                  const auto first_line = std::string_view{result.text}.substr(
                      0, lf == std::string::npos ? result.text.size() : lf);
                  const bool clipped = first_line.size() > 76;
                  std::size_t cut = clipped ? 76 : first_line.size();
                  if (clipped)
                    while (cut > 0 && (static_cast<unsigned char>(first_line[cut]) &
                                       0xc0U) == 0x80U)
                      --cut;
                  std::string preview{first_line.substr(0, cut)};
                  if (clipped)
                    preview += "...";
                  if (lf != std::string::npos) {
                    const auto extra = static_cast<std::size_t>(std::count(
                        result.text.begin() + static_cast<std::ptrdiff_t>(lf),
                        result.text.end(), '\n'));
                    preview += " (+" + std::to_string(extra) + " lines)";
                  }
                  transcript.append(ChatKind::notice,
                                    "Queued #" + std::to_string(queued.size()) + ": " +
                                        preview);
                }
              } catch (const Error &) {
                ui_capture.require();
                composer.draft(std::move(result.text));
                transcript += "\nQueue full; prompt retained in composer.\n";
              }
            } else {
              if (persist()) {
                saved_last_input = true;
                input.outcome(RawRegionOutcome::dispatch);
                input.finish();
                keyboard_burst.reset();
                keyboard_data.reset();
                keyboard_control.reset();
                wake_refused = false;
                const bool launched = start(result.text, result.source);
                if (!launched)
                  composer.draft(std::move(result.text));
                action_target = last_launch;
                action_branch = launched ? 3 : 4;
              } else {
                action_branch = 4;
                composer.draft(std::move(result.text));
              }
            }
          }
        }
        finish_action();
      } catch (...) {
        handling->capture_exception(4016);
        handling->close();
        keyboard_process.capture_exception(4084);
        keyboard_process.close();
        throw;
      }
    }
    pollfd next_input{STDIN_FILENO, POLLIN, 0};
    const bool more_stdin =
        (child_input.size() < 4096 || composer.pasted()) &&
        terminal_native_poll(&terminal_context, std::span{&next_input, std::size_t{1}},
                             0) > 0 &&
        (next_input.revents & POLLIN) != 0;
    if (child_input.size() >= 4096 || !more_stdin)
      (void)flush_child_input();
    report_refused_input();
    // A final-byte submission already saved this exact state before dispatch.
    // While an active bracketed paste still has bytes queued in stdin, coalesce
    // before serializing/fsyncing ui-state.bbm.
    if (!saved_last_input && !(composer.pasted() && more_stdin))
      persist();
    keyboard_process.finish();
  }
  if (flightdeck_kitty_emitted || flightdeck_pending_erase ||
      flightdeck_restore_cursor) {
    output.detach();
    std::string cleanup;
    if (flightdeck_kitty_emitted || flightdeck_pending_erase)
      cleanup += encode_kitty_erase(hero_default_kitty_image_id);
    cleanup += "\x1b[?25h";
    (void)::write(STDOUT_FILENO, cleanup.data(), cleanup.size());
  }
  persist();
}
} // namespace blackbird
