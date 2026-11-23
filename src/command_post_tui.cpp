#include "blackbird/command_post_tui.hpp"
#include "blackbird/bridge_relay.hpp"
#include "blackbird/flight_deck_view.hpp"
#include "blackbird/issues.hpp"
#include "blackbird/json.hpp"
#include "blackbird/metrics_consumer.hpp"
#include "blackbird/party_chat.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/project_memory.hpp"
#include "blackbird/swarmboard_view.hpp"
#include "blackbird/token_usage.hpp"
#include "blackbird/worktree_lease.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>
#include <sys/random.h>
#include <unistd.h>

namespace blackbird {
namespace {

constexpr std::size_t kMaxOutputBytes = 16 * 1024;
constexpr std::size_t kMaxListRows = 32;
constexpr std::size_t kMaxBoardRows = 20;
constexpr std::size_t kMaxStatusBoardRows = 5;
constexpr std::size_t kMaxPreviewBytes = 240;
constexpr std::size_t kMaxBodyPreviewBytes = 512;
constexpr std::size_t kMaxQuestionBytes = 2048;
constexpr std::size_t kSparklineWidth = 24;

std::string_view trim_view(std::string_view text) noexcept {
  while (!text.empty() &&
         (text.front() == ' ' || text.front() == '\t' || text.front() == '\r'))
    text.remove_prefix(1);
  while (!text.empty() &&
         (text.back() == ' ' || text.back() == '\t' || text.back() == '\r'))
    text.remove_suffix(1);
  return text;
}

struct SplitToken {
  std::string_view head;
  std::string_view rest;
};

SplitToken split_first_token(std::string_view input) noexcept {
  const auto trimmed = trim_view(input);
  const auto sep = trimmed.find_first_of(" \t");
  if (sep == std::string_view::npos)
    return {trimmed, {}};
  return {trimmed.substr(0, sep), trim_view(trimmed.substr(sep + 1))};
}

enum class SanitizeMode : std::uint8_t {
  inline_text,
  quoted_peer,
};

// Validate a single UTF-8 sequence starting at text[i], rejecting overlong
// forms, UTF-16 surrogates, out-of-range scalars, and bare continuation bytes.
std::size_t valid_utf8_seq_len(std::string_view text, std::size_t i) noexcept {
  if (i >= text.size())
    return 0;
  const auto b0 = static_cast<unsigned char>(text[i]);
  if (b0 < 0x80U)
    return 1;
  if ((b0 & 0xe0U) == 0xc0U) {
    if (b0 < 0xc2U || i + 1 >= text.size())
      return 0;
    const auto b1 = static_cast<unsigned char>(text[i + 1]);
    return (b1 & 0xc0U) == 0x80U ? 2 : 0;
  }
  if ((b0 & 0xf0U) == 0xe0U) {
    if (i + 2 >= text.size())
      return 0;
    const auto b1 = static_cast<unsigned char>(text[i + 1]);
    const auto b2 = static_cast<unsigned char>(text[i + 2]);
    if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U)
      return 0;
    if (b0 == 0xe0U && b1 < 0xa0U)
      return 0;
    if (b0 == 0xedU && b1 >= 0xa0U)
      return 0;
    return 3;
  }
  if ((b0 & 0xf8U) == 0xf0U) {
    if (b0 > 0xf4U || i + 3 >= text.size())
      return 0;
    const auto b1 = static_cast<unsigned char>(text[i + 1]);
    const auto b2 = static_cast<unsigned char>(text[i + 2]);
    const auto b3 = static_cast<unsigned char>(text[i + 3]);
    if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U || (b3 & 0xc0U) != 0x80U)
      return 0;
    if (b0 == 0xf0U && b1 < 0x90U)
      return 0;
    if (b0 == 0xf4U && b1 >= 0x90U)
      return 0;
    return 4;
  }
  return 0;
}

// Sanitize untrusted bytes for safe display in TUI notices and plain stdout:
// hex-escapes ASCII controls (<0x20), DEL (0x7F), raw single-byte C1 controls
// (0x80..0x9F, incl. 0x9B CSI), UTF-8 C1 controls (0xC2 0x80..0x9F), and any
// invalid/truncated UTF-8 bytes while preserving valid multi-byte UTF-8.
std::string sanitize_bytes(std::string_view text, std::size_t max_bytes,
                           SanitizeMode mode) {
  const bool escape_quotes = mode == SanitizeMode::quoted_peer;
  std::string out;
  out.reserve(std::min(text.size(), max_bytes) + (escape_quotes ? 2U : 0U));
  if (escape_quotes)
    out += '"';
  constexpr char kHex[] = "0123456789abcdef";
  auto hex_escape = [&](unsigned char byte) {
    std::string esc = "\\x";
    esc += kHex[byte >> 4U];
    esc += kHex[byte & 0x0fU];
    return esc;
  };
  std::size_t body_bytes = 0;
  bool truncated = false;
  for (std::size_t i = 0; i < text.size(); ++i) {
    const auto b = static_cast<unsigned char>(text[i]);
    const bool is_utf8_c1 = b == 0xc2U && i + 1 < text.size() &&
                            static_cast<unsigned char>(text[i + 1]) >= 0x80U &&
                            static_cast<unsigned char>(text[i + 1]) <= 0x9fU;
    std::string chunk;
    if (escape_quotes && b == '\\') {
      chunk = "\\\\";
    } else if (escape_quotes && b == '"') {
      chunk = "\\\"";
    } else if (b == '\n') {
      chunk = "\\n";
    } else if (b == '\r') {
      chunk = "\\r";
    } else if (b == '\t') {
      chunk = " ";
    } else if (b < 0x20U || b == 0x7fU || (b >= 0x80U && b <= 0x9fU)) {
      chunk = hex_escape(b);
    } else if (is_utf8_c1) {
      const auto next = static_cast<unsigned char>(text[++i]);
      chunk = hex_escape(b) + hex_escape(next);
    } else {
      const std::size_t seq_len = valid_utf8_seq_len(text, i);
      if (seq_len == 0) {
        chunk = hex_escape(b);
      } else {
        chunk.assign(text.data() + i, seq_len);
        i += seq_len - 1;
      }
    }
    if (body_bytes + chunk.size() > max_bytes) {
      truncated = true;
      break;
    }
    out += chunk;
    body_bytes += chunk.size();
  }
  if (truncated)
    out += "...";
  if (escape_quotes)
    out += '"';
  return out;
}

std::string sanitize_inline(std::string_view text, std::size_t max_bytes) {
  return sanitize_bytes(text, max_bytes, SanitizeMode::inline_text);
}

// Wrap untrusted peer text inside explicit quotes in a single pass so control
// escape sequences (e.g. \x1b, \x9b) are emitted cleanly without double-escaping.
std::string quote_untrusted_peer_text(std::string_view text, std::size_t max_bytes) {
  return sanitize_bytes(text, max_bytes, SanitizeMode::quoted_peer);
}

std::string bound_output(std::string text) {
  if (text.size() > kMaxOutputBytes) {
    text.resize(kMaxOutputBytes);
    while (!text.empty() && (static_cast<unsigned char>(text.back()) & 0xc0U) == 0x80U)
      text.pop_back();
    if (!text.empty() && (static_cast<unsigned char>(text.back()) & 0x80U) != 0U)
      text.pop_back();
    text += "\n... (output truncated)\n";
  }
  if (text.empty() || text.back() != '\n')
    text += '\n';
  return text;
}

std::filesystem::path resolve_project_root(const CommandPostTuiContext &ctx) {
  if (!ctx.project_root.empty())
    return ctx.project_root;
  std::error_code ec;
  auto cwd = std::filesystem::current_path(ec);
  if (ec || cwd.empty())
    return std::filesystem::path{"."};
  return cwd;
}

std::string safe_platoon_actor(std::string_view actor) {
  if (valid_platoon_member_id(actor))
    return std::string{actor};
  return "operator";
}

std::string safe_issue_actor(std::string_view actor) {
  if (valid_issue_actor_id(actor))
    return std::string{actor};
  return "operator";
}

std::string safe_memory_actor(std::string_view actor) {
  if (valid_memory_actor(actor))
    return std::string{actor};
  return "operator";
}

std::string format_bytes(std::uint64_t bytes) {
  std::ostringstream out;
  if (bytes < 1024U) {
    out << bytes << " B";
  } else if (bytes < 1024ULL * 1024ULL) {
    out << std::fixed << std::setprecision(1) << (static_cast<double>(bytes) / 1024.0)
        << " KiB";
  } else {
    out << std::fixed << std::setprecision(1)
        << (static_cast<double>(bytes) / (1024.0 * 1024.0)) << " MiB";
  }
  return out.str();
}

std::string format_double(double value, int precision) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(precision) << value;
  return out.str();
}

std::string format_tri_u64(const TriMetric<std::uint64_t> &metric) {
  if (metric.is_unknown() || !metric.value.has_value())
    return "unknown";
  if (metric.is_zero())
    return "0";
  std::string out = std::to_string(*metric.value);
  if (metric.is_known_subtotal()) {
    out += " (subtotal";
    if (metric.missing_count > 0)
      out += ", +" + std::to_string(metric.missing_count) + " missing";
    if (metric.overflow)
      out += ", overflow";
    out += ")";
  }
  return out;
}

std::string format_tri_bytes(const TriMetric<std::uint64_t> &metric) {
  if (metric.is_unknown() || !metric.value.has_value())
    return "unknown";
  if (metric.is_zero())
    return "0 B";
  std::string out = format_bytes(*metric.value);
  if (metric.is_known_subtotal())
    out += " (subtotal)";
  return out;
}

struct DoubleAffix {
  std::string_view prefix;
  std::string_view suffix;
};

std::string format_tri_double(const TriMetric<double> &metric, int precision,
                              DoubleAffix affix = {}) {
  if (metric.is_unknown() || !metric.value.has_value())
    return "unknown";
  if (metric.is_zero()) {
    return std::string{affix.prefix} + format_double(0.0, precision) +
           std::string{affix.suffix};
  }
  std::string out = std::string{affix.prefix} +
                    format_double(*metric.value, precision) + std::string{affix.suffix};
  if (metric.is_known_subtotal()) {
    out += " (subtotal";
    if (metric.missing_count > 0)
      out += ", +" + std::to_string(metric.missing_count) + " missing";
    out += ")";
  }
  return out;
}

std::string format_sparkline_line(std::string_view label, const MetricsSeries &series) {
  const auto spark = metrics_sparkline(series, kSparklineWidth);
  if (spark.finite_count == 0 || spark.glyphs.empty())
    return "  " + std::string{label} + ": (no samples)\n";
  std::string out = "  " + std::string{label} + ": " + spark.glyphs;
  if (spark.min_value.has_value() && spark.max_value.has_value()) {
    out += "  [" + format_double(*spark.min_value, 1) + ".." +
           format_double(*spark.max_value, 1);
    if (!series.unit.empty())
      out += " " + sanitize_inline(series.unit, 16);
    out += ", n=" + std::to_string(spark.finite_count) + "]";
  }
  out += '\n';
  return out;
}

bool valid_port_str(std::string_view port) {
  if (port.empty() || port.size() > 5 || port.front() == '0')
    return false;
  int value = 0;
  const auto parsed = std::from_chars(port.data(), port.data() + port.size(), value);
  return parsed.ec == std::errc{} && parsed.ptr == port.data() + port.size() &&
         value >= 1 && value <= 65535;
}

bool parse_ipv4_octets(std::string_view host, std::array<int, 4> &octets) {
  std::size_t pos = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    const auto dot = host.find('.', pos);
    if (i < 3 && dot == std::string_view::npos)
      return false;
    if (i == 3 && dot != std::string_view::npos)
      return false;
    const auto part =
        i < 3 ? host.substr(pos, dot - pos) : host.substr(pos, host.size() - pos);
    if (part.empty() || part.size() > 3 || (part.size() > 1 && part.front() == '0'))
      return false;
    int val = 0;
    const auto parsed = std::from_chars(part.data(), part.data() + part.size(), val);
    if (parsed.ec != std::errc{} || parsed.ptr != part.data() + part.size() ||
        val < 0 || val > 255)
      return false;
    octets[i] = val;
    pos = dot + 1;
  }
  return true;
}

struct TransportPolicyTarget {
  std::string_view provider;
  std::string_view base_url;
};

std::string describe_transport_policy(const TransportPolicyTarget &target) {
  if (target.provider == "jev")
    return "HTTPS-only (strict TLS)";
  if (target.base_url.starts_with("https://"))
    return "HTTPS (TLS)";
  if (target.base_url.starts_with("http://")) {
    const auto rest = target.base_url.substr(7);
    const auto slash = rest.find('/');
    const auto authority = rest.substr(0, slash);
    std::string_view host = authority;
    if (!authority.empty() && authority.front() == '[') {
      const auto close = authority.find(']');
      if (close != std::string_view::npos)
        host = authority.substr(1, close - 1);
      if (host == "::1")
        return "loopback HTTP (allowed: ::1)";
      return "non-local HTTP (blocked by transport policy)";
    }
    const auto colon = authority.find(':');
    if (colon != std::string_view::npos) {
      if (!valid_port_str(authority.substr(colon + 1)))
        return "invalid HTTP port (blocked)";
      host = authority.substr(0, colon);
    }
    std::string lower{host};
    for (char &ch : lower) {
      if (ch >= 'A' && ch <= 'Z')
        ch = static_cast<char>(ch - 'A' + 'a');
    }
    if (lower == "localhost")
      return "loopback HTTP (allowed: localhost)";
    std::array<int, 4> octets{};
    if (parse_ipv4_octets(host, octets)) {
      if (octets[0] == 127 && octets[1] == 0 && octets[2] == 0 && octets[3] == 1)
        return "loopback HTTP (allowed: 127.0.0.1)";
      if (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127)
        return "Tailscale CGNAT HTTP (allowed: 100.64.0.0/10)";
    }
    return "non-local HTTP (blocked by transport policy)";
  }
  return "unsupported scheme";
}

// --- /platoon ---
std::string handle_platoon(std::string_view args, const CommandPostTuiContext &ctx) {
  const auto root = resolve_project_root(ctx);
  const auto platoon_dir = root / ".blackbird" / "platoon";
  const auto lease_root = ctx.worktree_lease_root.has_value()
                              ? *ctx.worktree_lease_root
                              : (root / ".blackbird" / "worktrees");

  const auto [sub, rest] = split_first_token(args);
  const std::string_view cmd = sub.empty() ? std::string_view{"status"} : sub;

  if (cmd == "post") {
    if (rest.empty())
      return "Usage: /platoon post <text>\n";
    auto board_res = PlatoonBoard::open(platoon_dir);
    if (!board_res.has_value()) {
      return "Platoon board unavailable: " +
             std::string{error_name(board_res.error().code)} + "\n";
    }
    std::string recipient = "all";
    std::string body{rest};
    if (rest.starts_with('@')) {
      const auto [mention, after] = split_first_token(rest.substr(1));
      if (!after.empty() && valid_platoon_member_id(mention)) {
        recipient = std::string{mention};
        body = std::string{after};
      }
    }
    PlatoonPost post;
    post.from = safe_platoon_actor(ctx.actor);
    post.to = recipient;
    post.kind = PlatoonMessageKind::message;
    post.text = body;
    auto posted_res = board_res.value().post(std::move(post));
    if (!posted_res.has_value()) {
      return "Platoon post failed: " +
             std::string{error_name(posted_res.error().code)} + "\n";
    }
    const auto &posted = posted_res.value();
    return "Platoon posted #" + std::to_string(posted.seq) + " [" +
           std::string{platoon_message_kind_name(posted.kind)} +
           "] from=" + sanitize_inline(posted.from, 48) + " -> " +
           sanitize_inline(posted.to, 48) + ": " +
           quote_untrusted_peer_text(posted.text, kMaxPreviewBytes) + "\n";
  }

  if (cmd != "status" && cmd != "board" && cmd != "members") {
    return "Usage: /platoon [status|board|members|post <text>]\n";
  }

  std::error_code ec;
  const bool board_exists = std::filesystem::exists(platoon_dir, ec) && !ec;
  std::optional<PlatoonBoard> board;
  if (board_exists) {
    auto opened = PlatoonBoard::open(platoon_dir);
    if (!opened.has_value()) {
      return "Platoon board unreadable: " +
             std::string{error_name(opened.error().code)} + "\n";
    }
    board.emplace(std::move(opened).value());
  }

  auto load_leases = [&]() -> std::vector<WorktreeLeaseInfo> {
    std::error_code lec;
    if (!std::filesystem::exists(lease_root / ".leases", lec) || lec)
      return {};
    WorktreeLeaseConfig wcfg;
    wcfg.repo_root = root;
    wcfg.lease_root = lease_root;
    auto mgr = WorktreeLeaseManager::open(wcfg);
    if (!mgr.has_value())
      return {};
    auto listed = mgr.value().list();
    if (!listed.has_value())
      return {};
    return std::move(listed).value();
  };

  if (cmd == "members") {
    if (!board.has_value())
      return "Platoon members: none (not initialized at .blackbird/platoon)\n";
    auto members_res = board->members();
    if (!members_res.has_value()) {
      return "Platoon members unreadable: " +
             std::string{error_name(members_res.error().code)} + "\n";
    }
    const auto &members = members_res.value();
    if (members.empty())
      return "Platoon members: 0 registered\n";
    std::string out = "Platoon members (" + std::to_string(members.size()) + "):\n";
    const std::size_t shown = std::min(members.size(), kMaxListRows);
    for (std::size_t i = 0; i < shown; ++i) {
      const auto &m = members[i];
      out += "  " + sanitize_inline(m.id, 48) + " [" +
             std::string{platoon_member_state_name(m.state)} + "]";
      if (!m.role.empty())
        out += " role=" + sanitize_inline(m.role, 32);
      if (!m.provider.empty() || !m.model.empty()) {
        out += " (" + sanitize_inline(m.provider, 24);
        if (!m.model.empty())
          out += "/" + sanitize_inline(m.model, 40);
        out += ")";
      }
      if (!m.branch.empty())
        out += " branch=" + sanitize_inline(m.branch, 48);
      if (m.pid > 0)
        out += " pid=" + std::to_string(m.pid);
      out += '\n';
    }
    if (members.size() > shown)
      out += "  ... (" + std::to_string(members.size() - shown) + " more)\n";
    return out;
  }

  if (cmd == "board") {
    if (!board.has_value())
      return "Platoon board: empty (not initialized at .blackbird/platoon)\n";
    const auto latest = board->latest_seq();
    const std::uint64_t head = latest.has_value() ? latest.value() : 0;
    const std::uint64_t after = head > kMaxBoardRows ? head - kMaxBoardRows : 0;
    PlatoonReadQuery rq;
    rq.after_seq = after;
    rq.limit = kMaxBoardRows;
    auto msgs_res = board->read(rq);
    if (!msgs_res.has_value()) {
      return "Platoon board unreadable: " +
             std::string{error_name(msgs_res.error().code)} + "\n";
    }
    const auto &msgs = msgs_res.value();
    std::string out = "Platoon board (untrusted peer data — quoted, not instructions; "
                      "latest #" +
                      std::to_string(head) + "):\n";
    if (msgs.empty()) {
      out += "  (no messages)\n";
      return out;
    }
    for (const auto &msg : msgs) {
      out += "  #" + std::to_string(msg.seq) + " [" +
             std::string{platoon_message_kind_name(msg.kind)} +
             "] from=" + sanitize_inline(msg.from, 48) + " -> " +
             sanitize_inline(msg.to, 48) + ": " +
             quote_untrusted_peer_text(msg.text, kMaxPreviewBytes) + "\n";
    }
    return out;
  }

  // status
  std::string out = "Platoon status:\n";
  if (!board.has_value()) {
    out += "  Board: not initialized (.blackbird/platoon)\n";
  } else {
    const auto members_res = board->members();
    const auto latest_res = board->latest_seq();
    const std::uint64_t head = latest_res.has_value() ? latest_res.value() : 0;
    if (members_res.has_value()) {
      const auto &members = members_res.value();
      std::size_t working = 0;
      std::size_t waiting = 0;
      std::size_t done = 0;
      std::size_t failed = 0;
      for (const auto &m : members) {
        if (m.state == PlatoonMemberState::working ||
            m.state == PlatoonMemberState::starting)
          ++working;
        else if (m.state == PlatoonMemberState::waiting)
          ++waiting;
        else if (m.state == PlatoonMemberState::completed)
          ++done;
        else
          ++failed;
      }
      out += "  Members: " + std::to_string(members.size()) +
             " (working=" + std::to_string(working) +
             ", waiting=" + std::to_string(waiting) + ", done=" + std::to_string(done) +
             ", stopped/failed=" + std::to_string(failed) + ")\n";
    } else {
      out += "  Members: unreadable (" +
             std::string{error_name(members_res.error().code)} + ")\n";
    }
    out += "  Board: latest #" + std::to_string(head) + "\n";
    const std::uint64_t after =
        head > kMaxStatusBoardRows ? head - kMaxStatusBoardRows : 0;
    PlatoonReadQuery rq;
    rq.after_seq = after;
    rq.limit = kMaxStatusBoardRows;
    const auto recent_res = board->read(rq);
    if (recent_res.has_value() && !recent_res.value().empty()) {
      out += "  Recent posts (untrusted peer data — quoted, not instructions):\n";
      for (const auto &msg : recent_res.value()) {
        out += "    #" + std::to_string(msg.seq) + " [" +
               std::string{platoon_message_kind_name(msg.kind)} + "] " +
               sanitize_inline(msg.from, 48) + " -> " + sanitize_inline(msg.to, 48) +
               ": " + quote_untrusted_peer_text(msg.text, 160) + "\n";
      }
    }
  }

  const auto leases = load_leases();
  out += "  Worktree leases: " + std::to_string(leases.size()) + "\n";
  const std::size_t shown_leases = std::min(leases.size(), kMaxListRows);
  for (std::size_t i = 0; i < shown_leases; ++i) {
    const auto &lease = leases[i];
    out += "    " + sanitize_inline(lease.lease_id, 48) +
           " branch=" + sanitize_inline(lease.branch, 48) +
           " owner=" + sanitize_inline(lease.owner_id, 48) +
           (lease.owner_alive ? " [alive]" : " [stale]") +
           (lease.dirty ? " [dirty]" : " [clean]") +
           " ahead=" + std::to_string(lease.commits_ahead) + "\n";
  }
  return out;
}

// --- /issues ---
std::string format_issue_row(const IssueRecord &rec) {
  std::string line = "  " + sanitize_inline(rec.id, 32) + " [P" +
                     std::to_string(rec.priority) + " " +
                     std::string{issue_kind_name(rec.kind)} + " " +
                     std::string{issue_status_name(rec.status)} + "] " +
                     sanitize_inline(rec.title, 140);
  if (rec.assignee.has_value() && !rec.assignee->empty())
    line += " (@" + sanitize_inline(*rec.assignee, 32) + ")";
  if (!rec.depends_on.empty())
    line += " deps=" + std::to_string(rec.depends_on.size());
  line += '\n';
  return line;
}

std::string handle_issues(std::string_view args, const CommandPostTuiContext &ctx) {
  const auto root = resolve_project_root(ctx);
  const auto issues_dir = root / ".blackbird" / "issues";
  const auto [sub, rest] = split_first_token(args);
  const std::string_view cmd = sub.empty() ? std::string_view{"ready"} : sub;

  if (cmd == "ready" || cmd == "list") {
    std::error_code ec;
    if (!std::filesystem::exists(issues_dir, ec) || ec) {
      return "Project issues: none yet (.blackbird/issues). Use `/issues create "
             "<title>`.\n";
    }
    auto store = IssueStore::open(issues_dir);
    if (!store.has_value()) {
      return "Issue store unreadable: " + std::string{error_name(store.error().code)} +
             "\n";
    }
    if (cmd == "ready") {
      auto ready_res = store.value().ready(kMaxListRows);
      if (!ready_res.has_value()) {
        return "Issue ready query failed: " +
               std::string{error_name(ready_res.error().code)} + "\n";
      }
      const auto &ready = ready_res.value();
      if (ready.empty())
        return "Ready issues: 0\n";
      std::string out = "Ready issues (" + std::to_string(ready.size()) + "):\n";
      for (const auto &rec : ready)
        out += format_issue_row(rec);
      return out;
    }
    IssueQuery query;
    query.limit = kMaxListRows;
    auto listed_res = store.value().list(query);
    if (!listed_res.has_value()) {
      return "Issue list query failed: " +
             std::string{error_name(listed_res.error().code)} + "\n";
    }
    const auto &listed = listed_res.value();
    if (listed.empty())
      return "Project issues: 0\n";
    std::size_t open_n = 0;
    std::size_t in_prog_n = 0;
    std::size_t blocked_n = 0;
    std::size_t closed_n = 0;
    for (const auto &rec : listed) {
      if (rec.status == IssueStatus::open)
        ++open_n;
      else if (rec.status == IssueStatus::in_progress)
        ++in_prog_n;
      else if (rec.status == IssueStatus::blocked)
        ++blocked_n;
      else
        ++closed_n;
    }
    std::string out = "Project issues (" + std::to_string(listed.size()) +
                      "; open=" + std::to_string(open_n) +
                      ", in_progress=" + std::to_string(in_prog_n) +
                      ", blocked=" + std::to_string(blocked_n) +
                      ", closed=" + std::to_string(closed_n) + "):\n";
    for (const auto &rec : listed)
      out += format_issue_row(rec);
    return out;
  }

  if (cmd == "create") {
    if (rest.empty())
      return "Usage: /issues create <title>\n";
    auto store = IssueStore::open(issues_dir);
    if (!store.has_value()) {
      return "Issue store unavailable: " + std::string{error_name(store.error().code)} +
             "\n";
    }
    IssueCreateRequest req;
    req.title = std::string{rest};
    auto created_res = store.value().create(std::move(req));
    if (!created_res.has_value()) {
      return "Issue create failed: " +
             std::string{error_name(created_res.error().code)} + "\n";
    }
    const auto &created = created_res.value();
    return "Created issue " + sanitize_inline(created.id, 32) + ": " +
           sanitize_inline(created.title, 160) + "\n";
  }

  if (cmd == "claim") {
    const auto [id, extra] = split_first_token(rest);
    if (id.empty())
      return "Usage: /issues claim <id>\n";
    auto store = IssueStore::open(issues_dir);
    if (!store.has_value()) {
      return "Issue store unavailable: " + std::string{error_name(store.error().code)} +
             "\n";
    }
    const std::string actor =
        extra.empty() ? safe_issue_actor(ctx.actor) : safe_issue_actor(extra);
    auto claimed_res = store.value().claim(id, actor);
    if (!claimed_res.has_value()) {
      return "Issue claim failed (" + sanitize_inline(id, 32) +
             "): " + std::string{error_name(claimed_res.error().code)} + "\n";
    }
    const auto &claimed = claimed_res.value();
    return "Claimed issue " + sanitize_inline(claimed.id, 32) + " as " +
           sanitize_inline(actor, 48) + " [" +
           std::string{issue_status_name(claimed.status)} + "]\n";
  }

  if (cmd == "close") {
    const auto [id, reason_view] = split_first_token(rest);
    if (id.empty())
      return "Usage: /issues close <id> [reason]\n";
    auto store = IssueStore::open(issues_dir);
    if (!store.has_value()) {
      return "Issue store unavailable: " + std::string{error_name(store.error().code)} +
             "\n";
    }
    const std::string_view reason =
        reason_view.empty() ? std::string_view{"closed via command post"} : reason_view;
    auto closed_res = store.value().close(id, reason);
    if (!closed_res.has_value()) {
      return "Issue close failed (" + sanitize_inline(id, 32) +
             "): " + std::string{error_name(closed_res.error().code)} + "\n";
    }
    const auto &closed = closed_res.value();
    return "Closed issue " + sanitize_inline(closed.id, 32) + ": " +
           sanitize_inline(closed.title, 140) + "\n";
  }

  return "Usage: /issues [ready|list|create <title>|claim <id>|close <id>]\n";
}

// --- /memory ---
std::string freshness_badge(MemoryFreshness freshness) {
  return "[" + std::string{memory_freshness_name(freshness)} + "]";
}

std::string handle_memory(std::string_view args, const CommandPostTuiContext &ctx) {
  const auto root = resolve_project_root(ctx);
  const auto memory_dir = default_project_memory_dir(root);
  const auto [sub, rest] = split_first_token(args);
  const std::string_view cmd = sub.empty() ? std::string_view{"recent"} : sub;

  if (cmd == "record") {
    const auto [kind_tok, payload] = split_first_token(rest);
    if (kind_tok.empty() || payload.empty()) {
      return "Usage: /memory record <kind> <title> :: <body>\n"
             "  Kinds: decision | invariant | handoff | finding | friction | "
             "preference\n";
    }
    const auto kind_res = parse_memory_kind(kind_tok);
    if (!kind_res.has_value()) {
      return "Unknown memory kind '" + sanitize_inline(kind_tok, 32) +
             "'. Valid kinds: decision, invariant, handoff, finding, friction, "
             "preference.\n";
    }
    const auto sep = payload.find("::");
    if (sep == std::string_view::npos) {
      return "Usage: /memory record <kind> <title> :: <body>\n";
    }
    const auto title = trim_view(payload.substr(0, sep));
    const auto body = trim_view(payload.substr(sep + 2));
    if (title.empty() || body.empty()) {
      return "Usage: /memory record <kind> <title> :: <body> (both title and body "
             "required)\n";
    }
    auto store = ProjectMemoryStore::open(memory_dir);
    if (!store.has_value()) {
      return "Project memory store unavailable: " +
             std::string{error_name(store.error().code)} + "\n";
    }
    MemoryRecordRequest req;
    req.kind = kind_res.value();
    req.title = std::string{title};
    req.body = std::string{body};
    req.actor = safe_memory_actor(ctx.actor);
    if (!ctx.session_id.empty() && ctx.session_id.size() <= kMemoryMaxSessionIdLength)
      req.session_id = ctx.session_id;
    req.repo_root = root;
    auto recorded_res = store.value().record(std::move(req));
    if (!recorded_res.has_value()) {
      return "Memory record failed: " +
             std::string{error_name(recorded_res.error().code)} + "\n";
    }
    const auto &recorded = recorded_res.value();
    return "Recorded memory " + sanitize_inline(recorded.id, 32) + " [" +
           std::string{memory_kind_name(recorded.kind)} + "] " +
           sanitize_inline(recorded.title, 160) + "\n";
  }

  if (cmd != "recent" && cmd != "recall" && cmd != "verify") {
    return "Usage: /memory [recent|recall <query>|record <kind> <title> :: "
           "<body>|verify]\n";
  }

  std::error_code ec;
  if (!std::filesystem::exists(memory_dir, ec) || ec) {
    return "Project memory: none yet (.blackbird/memory). Use `/memory record <kind> "
           "<title> :: <body>`.\n";
  }
  auto store = ProjectMemoryStore::open(memory_dir);
  if (!store.has_value()) {
    return "Project memory unreadable: " + std::string{error_name(store.error().code)} +
           "\n";
  }

  if (cmd == "recent") {
    auto entries_res = store.value().recent(kMemoryDefaultLimit, false);
    if (!entries_res.has_value()) {
      return "Project memory recent failed: " +
             std::string{error_name(entries_res.error().code)} + "\n";
    }
    const auto &entries = entries_res.value();
    if (entries.empty())
      return "Project memory: 0 active entries\n";
    std::string out =
        "Project memory recent (" + std::to_string(entries.size()) + "):\n";
    for (const auto &entry : entries) {
      const auto checked = verify_memory_freshness(entry, root);
      const MemoryFreshness fresh =
          checked.has_value() ? checked.value() : MemoryFreshness::unchecked;
      out += "  " + sanitize_inline(entry.id, 32) + " [" +
             std::string{memory_kind_name(entry.kind)} + "] " + freshness_badge(fresh) +
             " " + sanitize_inline(entry.title, 140);
      if (!entry.sources.empty())
        out += " (pins=" + std::to_string(entry.sources.size()) + ")";
      out += '\n';
    }
    return out;
  }

  if (cmd == "recall") {
    if (rest.empty())
      return "Usage: /memory recall <query>\n";
    MemoryRecallQuery query;
    query.query = std::string{rest};
    query.limit = kMemoryDefaultLimit;
    query.verify_root = root;
    auto hits_res = store.value().recall(query);
    if (!hits_res.has_value()) {
      return "Project memory recall failed: " +
             std::string{error_name(hits_res.error().code)} + "\n";
    }
    const auto &hits = hits_res.value();
    if (hits.empty()) {
      return "Project memory recall '" + sanitize_inline(rest, 80) + "': 0 matches\n";
    }
    std::string out = "Project memory recall '" + sanitize_inline(rest, 80) + "' (" +
                      std::to_string(hits.size()) + " hits):\n";
    for (const auto &hit : hits) {
      out += "  " + sanitize_inline(hit.entry.id, 32) + " [" +
             std::string{memory_kind_name(hit.entry.kind)} + "] " +
             freshness_badge(hit.freshness) + " score=" + std::to_string(hit.score) +
             " " + sanitize_inline(hit.entry.title, 120) + "\n";
      out += "    " + sanitize_inline(hit.entry.body, kMaxPreviewBytes) + "\n";
    }
    return out;
  }

  // verify
  auto entries_res = store.value().recent(kMemoryMaxLimit, false);
  if (!entries_res.has_value()) {
    return "Project memory verify failed: " +
           std::string{error_name(entries_res.error().code)} + "\n";
  }
  const auto &entries = entries_res.value();
  if (entries.empty())
    return "Project memory verify: 0 active entries\n";
  std::size_t fresh_n = 0;
  std::size_t stale_n = 0;
  std::size_t missing_n = 0;
  std::size_t unpinned_n = 0;
  std::size_t err_n = 0;
  std::string rows;
  for (const auto &entry : entries) {
    const auto checked = verify_memory_freshness(entry, root);
    std::string badge;
    if (!checked.has_value()) {
      ++err_n;
      badge = "[verify_error:" + std::string{error_name(checked.error().code)} + "]";
    } else {
      switch (checked.value()) {
      case MemoryFreshness::fresh:
        ++fresh_n;
        break;
      case MemoryFreshness::stale:
        ++stale_n;
        break;
      case MemoryFreshness::missing_source:
        ++missing_n;
        break;
      case MemoryFreshness::unpinned:
        ++unpinned_n;
        break;
      case MemoryFreshness::unchecked:
        break;
      }
      badge = freshness_badge(checked.value());
    }
    rows += "  " + sanitize_inline(entry.id, 32) + " " + badge + " [" +
            std::string{memory_kind_name(entry.kind)} + "] " +
            sanitize_inline(entry.title, 120);
    if (!entry.sources.empty()) {
      rows += " <- ";
      for (std::size_t i = 0; i < entry.sources.size(); ++i) {
        if (i > 0)
          rows += ", ";
        rows += sanitize_inline(entry.sources[i].path, 64);
      }
    }
    rows += '\n';
  }
  std::string out = "Project memory SHA-256 verification (" +
                    std::to_string(entries.size()) +
                    " active; fresh=" + std::to_string(fresh_n) +
                    ", stale=" + std::to_string(stale_n) +
                    ", missing_source=" + std::to_string(missing_n) +
                    ", unpinned=" + std::to_string(unpinned_n);
  if (err_n > 0)
    out += ", error=" + std::to_string(err_n);
  out += "):\n" + rows;
  return out;
}

// --- /capabilities ---
std::string handle_capabilities(std::string_view args,
                                const CommandPostTuiContext &ctx) {
  const auto root = resolve_project_root(ctx);
  const auto [sub, rest] = split_first_token(args);
  const std::string_view cmd = sub.empty() ? std::string_view{"list"} : sub;

  if (cmd != "list" && cmd != "show")
    return "Usage: /capabilities [list|show <id>]\n";

  CapabilityCatalogConfig config;
  config.project_dir = default_project_skills_dir(root);
  if (ctx.user_capabilities_dir.has_value())
    config.user_dir = *ctx.user_capabilities_dir;
  else if (ctx.include_default_user_capabilities)
    config.user_dir = default_user_skills_dir();
  config.builtins = ctx.builtin_capabilities;

  auto catalog = CapabilityCatalog::open(std::move(config));
  if (!catalog.has_value()) {
    return "Capabilities catalog unavailable: " +
           std::string{error_name(catalog.error().code)} + "\n";
  }

  if (cmd == "list") {
    CapabilityListQuery query;
    query.text = std::string{rest};
    query.limit = kMaxListRows;
    query.allow_stale_on_error = true;
    auto page_res = catalog.value().list(query);
    if (!page_res.has_value()) {
      return "Capabilities list failed: " +
             std::string{error_name(page_res.error().code)} + "\n";
    }
    const auto &page = page_res.value();
    std::string out = "Capabilities catalog (precedence: project > user > builtin; "
                      "read-only, executed=false; total=" +
                      std::to_string(page.total) + "):\n";
    if (page.items.empty()) {
      out += "  (no capabilities found)\n";
      return out;
    }
    for (const auto &def : page.items) {
      const std::string short_sha =
          def.sha256.size() > 12 ? def.sha256.substr(0, 12) : def.sha256;
      out += "  " + sanitize_inline(def.id, 64) + " [" +
             std::string{capability_kind_name(def.kind)} + " | " +
             std::string{capability_scope_name(def.scope)} + "]";
      if (!short_sha.empty())
        out += " sha256:" + sanitize_inline(short_sha, 12);
      if (!def.shadowed.empty())
        out += " (shadows " + std::to_string(def.shadowed.size()) + ")";
      if (!def.title.empty())
        out += " — " + sanitize_inline(def.title, 100);
      out += '\n';
    }
    if (page.has_more)
      out += "  ... (more entries available)\n";
    return out;
  }

  // show <id>
  if (rest.empty())
    return "Usage: /capabilities show <id>\n";
  if (!valid_capability_id(rest)) {
    return "Invalid capability id: '" + sanitize_inline(rest, 64) + "'\n";
  }
  auto found_res = catalog.value().get(rest);
  if (!found_res.has_value()) {
    return "Capabilities lookup failed: " +
           std::string{error_name(found_res.error().code)} + "\n";
  }
  const auto &found = found_res.value();
  if (!found.has_value()) {
    return "Capability not found: " + sanitize_inline(rest, 64) + "\n";
  }
  const auto &def = *found;
  std::string out = "Capability " + sanitize_inline(def.id, 64) + " [" +
                    std::string{capability_kind_name(def.kind)} + " | " +
                    std::string{capability_scope_name(def.scope)} + "]\n";
  out += "  Executed:    false (read-only inspection; recipes are never executed)\n";
  if (!def.title.empty())
    out += "  Title:       " + sanitize_inline(def.title, 160) + "\n";
  if (!def.description.empty())
    out += "  Description: " + sanitize_inline(def.description, 240) + "\n";
  if (!def.sha256.empty())
    out += "  SHA-256:     " + sanitize_inline(def.sha256, 64) + "\n";
  if (!def.source_path.empty())
    out += "  Source:      " + sanitize_inline(def.source_path.string(), 200) + "\n";
  if (!def.shadowed.empty()) {
    out += "  Shadows:     ";
    for (std::size_t i = 0; i < def.shadowed.size(); ++i) {
      if (i > 0)
        out += ", ";
      out += std::string{capability_scope_name(def.shadowed[i].scope)};
    }
    out += '\n';
  }
  if (!def.params.empty()) {
    out += "  Params (" + std::to_string(def.params.size()) + "):\n";
    const std::size_t shown = std::min<std::size_t>(def.params.size(), 16);
    for (std::size_t i = 0; i < shown; ++i) {
      const auto &p = def.params[i];
      out += "    - " + sanitize_inline(p.name, 64) + " (" +
             std::string{capability_param_type_name(p.type)} +
             (p.required ? ", required" : ", optional") + ")";
      if (p.default_value.has_value())
        out += " default=" + sanitize_inline(*p.default_value, 48);
      out += '\n';
    }
  }
  if (!def.body.empty()) {
    out += "  Body preview: " + sanitize_inline(def.body, kMaxBodyPreviewBytes) + "\n";
  }
  return out;
}

// --- /metrics ---
std::string handle_metrics(std::string_view args, const CommandPostTuiContext &ctx) {
  const auto [sub, rest] = split_first_token(args);
  (void)rest;
  const std::string_view cmd = sub.empty() ? std::string_view{"summary"} : sub;
  if (cmd != "summary")
    return "Usage: /metrics [summary]\n";

  // Strictly read-only tertiary MetricsConsumer: never touches producer hot paths.
  MetricsConsumer consumer;
  std::vector<std::string> sources;
  std::vector<std::string> warnings;

  if (!ctx.session_dir.empty()) {
    std::error_code ec;
    if (std::filesystem::exists(ctx.session_dir, ec) && !ec) {
      auto report = read_token_usage(ctx.session_dir.string());
      if (report.has_value()) {
        (void)consumer.ingest_token_usage(report.value());
        sources.push_back("token_usage:" + ctx.session_dir.filename().string());
      } else {
        warnings.push_back("token_usage unavailable (" +
                           std::string{error_name(report.error().code)} + ")");
      }
    }
  }
  if (ctx.audit_log != nullptr) {
    auto res = consumer.ingest_audit_log(*ctx.audit_log);
    if (res.has_value()) {
      sources.emplace_back("audit_log");
    } else {
      warnings.push_back("audit_log unavailable (" +
                         std::string{error_name(res.error().code)} + ")");
    }
  }

  const auto &snap = consumer.snapshot();
  std::string out = "Metrics summary (tertiary read-only consumer; "
                    "complete_session_ledger=false):\n";
  if (!sources.empty()) {
    out += "  Sources: ";
    for (std::size_t i = 0; i < sources.size(); ++i) {
      if (i > 0)
        out += ", ";
      out += sanitize_inline(sources[i], 64);
    }
    out += '\n';
  }
  if (!warnings.empty()) {
    for (const auto &w : warnings)
      out += "  Note: " + sanitize_inline(w, 120) + "\n";
  }

  // Operations
  out += "  Operations: requests=" + format_tri_u64(snap.operations.provider_requests) +
         " | tools=" + format_tri_u64(snap.operations.tool_executions) +
         " | tool_failures=" + format_tri_u64(snap.operations.tool_failures) +
         " | errors=" + format_tri_u64(snap.operations.error_count) +
         " | retries=" + format_tri_u64(snap.operations.retry_count) + "\n";
  if (snap.operations.total_latency_stats.p50_ms.has_value() ||
      snap.operations.ttft_stats.p50_ms.has_value()) {
    out += "  Latency: ";
    if (snap.operations.ttft_stats.p50_ms.has_value()) {
      out += "TTFT p50=" + format_double(*snap.operations.ttft_stats.p50_ms, 1) + "ms";
      if (snap.operations.ttft_stats.p95_ms.has_value())
        out += " p95=" + format_double(*snap.operations.ttft_stats.p95_ms, 1) + "ms";
    }
    if (snap.operations.total_latency_stats.p50_ms.has_value()) {
      if (snap.operations.ttft_stats.p50_ms.has_value())
        out += " | ";
      out +=
          "Total p50=" + format_double(*snap.operations.total_latency_stats.p50_ms, 1) +
          "ms";
      if (snap.operations.total_latency_stats.p95_ms.has_value()) {
        out += " p95=" + format_double(*snap.operations.total_latency_stats.p95_ms, 1) +
               "ms";
      }
    }
    out += '\n';
  }

  // Usage
  out += "  Usage: in=" + format_tri_u64(snap.usage.total_input_tokens) +
         " | cached=" + format_tri_u64(snap.usage.total_cached_tokens) +
         " | out=" + format_tri_u64(snap.usage.total_output_tokens) +
         " | reasoning=" + format_tri_u64(snap.usage.total_reasoning_tokens) + "\n";
  const DoubleAffix usd_affix{"$", ""};
  out +=
      "  Cost: observed=" +
      format_tri_double(snap.usage.observed_charge_usd, 4, usd_affix) +
      " | estimated=" + format_tri_double(snap.usage.estimated_cost_usd, 4, usd_affix) +
      " | cache_hit=" + format_tri_double(snap.usage.cache_hit_ratio, 3) + "\n";

  // Context
  out += "  Context: live=" + format_tri_bytes(snap.context.latest_live_bytes) +
         " | peak=" + format_tri_bytes(snap.context.peak_live_bytes) +
         " | archived=" + format_tri_bytes(snap.context.latest_archived_bytes) +
         " | compactions=" + format_tri_u64(snap.context.compaction_events) + "\n";

  // Decision companion
  out += "  Decision Companion: batches=" +
         format_tri_u64(snap.decision_companion.batch_count) +
         " | failures=" + format_tri_u64(snap.decision_companion.failure_count) +
         " | tokens=" + format_tri_u64(snap.decision_companion.total_tokens) + "\n";

  // Sparklines
  out += format_sparkline_line("Sparkline latency", snap.operations.total_latency_ms);
  out += format_sparkline_line("Sparkline tokens", snap.usage.token_spend_series);
  out += format_sparkline_line("Sparkline context", snap.context.live_bytes_series);
  if (!snap.decision_companion.latency_ms.points.empty()) {
    out += format_sparkline_line("Sparkline companion",
                                 snap.decision_companion.latency_ms);
  }

  // Coverage
  out += "  Coverage: ingested=" + std::to_string(snap.coverage.records_ingested) +
         " | skipped_corrupt=" + std::to_string(snap.coverage.records_skipped_corrupt) +
         " | deduped=" + std::to_string(snap.coverage.duplicate_captures_deduped) +
         "\n";
  return out;
}

// --- /companion ---
struct CompanionAuthQuery {
  std::string_view provider;
  std::string_view env_var;
};

std::string check_companion_auth_status(const ProviderAuth &auth,
                                        const CompanionAuthQuery &query) {
  if (query.provider == "jev") {
    if (const auto *v = std::getenv("TYPESAFE_API_KEY"); v && *v)
      return "configured (env TYPESAFE_API_KEY)";
    if (const auto *v = std::getenv("jev"); v && *v)
      return "configured (env jev)";
    if (const auto *f = std::getenv("BLACKBIRD_JEV_ENV_FILE"); f && *f) {
      std::error_code ec;
      if (std::filesystem::exists(f, ec) && !ec)
        return "configured (env-file BLACKBIRD_JEV_ENV_FILE)";
    }
    try {
      if (auth.stored_key("jev").has_value())
        return "configured (stored key)";
    } catch (...) {
    }
    return "not configured";
  }
  if (!query.env_var.empty()) {
    const std::string env_name{query.env_var};
    if (const auto *v = std::getenv(env_name.c_str()); v && *v)
      return "configured (env " + sanitize_inline(query.env_var, 48) + ")";
  }
  try {
    if (auth.stored_key(query.provider).has_value())
      return "configured (stored key)";
  } catch (...) {
  }
  return query.provider == "clef" ? "optional (local/Tailscale)" : "not configured";
}

std::string handle_companion(std::string_view args, const CommandPostTuiContext &ctx) {
  const auto [sub, rest] = split_first_token(args);
  const std::string_view cmd = sub.empty() ? std::string_view{"status"} : sub;

  const ProviderAuth auth = ctx.provider_auth_config.has_value()
                                ? ProviderAuth{*ctx.provider_auth_config}
                                : ProviderAuth{};

  if (cmd == "status") {
    std::string out = "System One decision companions (advisory only):\n";

    // Built-in jev
    out += "  jev   [decision] https://api.typesafe.ai/v1/systemone"
           " | default=jev-1.13.0"
           " | policy=" +
           describe_transport_policy({"jev", "https://api.typesafe.ai/v1"}) +
           " | auth=" + check_companion_auth_status(auth, {"jev", "TYPESAFE_API_KEY"}) +
           "\n";

    // Built-in clef
    std::string clef_base = "http://127.0.0.1:11435/v1";
    if (const auto *override_url = std::getenv("BLACKBIRD_CLEF_URL");
        override_url && *override_url)
      clef_base = override_url;
    out += "  clef  [decision] " + sanitize_inline(clef_base, 128) +
           " | default=clef-latest"
           " | policy=" +
           describe_transport_policy({"clef", clef_base}) +
           " | auth=" + check_companion_auth_status(auth, {"clef", "CLEF_API_KEY"}) +
           "\n";

    // Custom registered decision providers
    try {
      const Value cat = auth.catalog();
      if (const auto *providers = cat.find("providers");
          providers != nullptr &&
          std::holds_alternative<Value::Array>(providers->value())) {
        std::size_t custom_count = 0;
        for (const auto &entry : providers->array()) {
          const auto *id_v = entry.find("id");
          const auto *proto_v = entry.find("protocol");
          if (!id_v || !proto_v ||
              !std::holds_alternative<std::string>(id_v->value()) ||
              !std::holds_alternative<std::string>(proto_v->value()))
            continue;
          if (proto_v->string() != "decision")
            continue;
          const auto &id = id_v->string();
          if (id == "jev" || id == "clef")
            continue;
          std::string base_url;
          if (const auto *b = entry.find("base_url");
              b && std::holds_alternative<std::string>(b->value()))
            base_url = b->string();
          std::string env_var;
          if (const auto *e = entry.find("environment");
              e && std::holds_alternative<std::string>(e->value()))
            env_var = e->string();
          out += "  " + sanitize_inline(id, 48) + " [decision] " +
                 sanitize_inline(base_url, 128) +
                 " | policy=" + describe_transport_policy({id, base_url}) +
                 " | auth=" + check_companion_auth_status(auth, {id, env_var}) + "\n";
          ++custom_count;
          if (custom_count >= kMaxListRows)
            break;
        }
      }
    } catch (...) {
      out += "  (custom provider catalog unavailable)\n";
    }

    out += "  Usage: /companion ask [--provider <id>] [--model <name>] <question>\n";
    return out;
  }

  if (cmd == "ask") {
    std::string provider = "jev";
    std::optional<std::string> model;
    std::string_view remaining = rest;

    while (!remaining.empty()) {
      const auto [tok, after] = split_first_token(remaining);
      if (tok == "--provider") {
        const auto [val, next] = split_first_token(after);
        if (val.empty())
          return "Usage: /companion ask [--provider <id>] [--model <name>] "
                 "<question>\n";
        provider = std::string{val};
        remaining = next;
      } else if (tok == "--model") {
        const auto [val, next] = split_first_token(after);
        if (val.empty())
          return "Usage: /companion ask [--provider <id>] [--model <name>] "
                 "<question>\n";
        model = std::string{val};
        remaining = next;
      } else {
        break;
      }
    }

    const auto question = trim_view(remaining);
    if (question.empty())
      return "Usage: /companion ask [--provider <id>] [--model <name>] <question>\n";
    if (question.size() > kMaxQuestionBytes)
      return "Companion question too long (max " + std::to_string(kMaxQuestionBytes) +
             " bytes).\n";

    const auto root = resolve_project_root(ctx);
    Value request_args = Value::object(
        {{"provider", Value{provider}},
         {"state", Value::object({{"question", Value{std::string{question}}},
                                  {"actor", Value{sanitize_inline(ctx.actor, 48)}},
                                  {"project", Value{sanitize_inline(
                                                  root.filename().string(), 64)}}})},
         {"questions",
          Value::object(
              {{"advisory",
                Value::object(
                    {{"type", Value{"choice"}},
                     {"instructions",
                      Value{"Recommend an operational posture for this operator "
                            "question."}},
                     {"criteria",
                      Value::object(
                          {{"proceed", Value{"Proceed with the proposed step."}},
                           {"verify_first",
                            Value{"Verify state, tests, or invariants first."}},
                           {"pause_and_review",
                            Value{"Pause and review risks or blockers."}}})}})},
               {"needs_caution",
                Value::object({{"type", Value{"noul"}},
                               {"instructions",
                                Value{"Does this question carry elevated operational "
                                      "risk?"}}})}})}});
    if (model.has_value())
      request_args.object().emplace_back("model", Value{*model});

    try {
      const Value response =
          ctx.decision_evaluator
              ? ctx.decision_evaluator(request_args)
              : DecisionModels{ctx.decision_config}.evaluate(request_args);
      std::string out = "Companion advisory (" + sanitize_inline(provider, 32);
      if (const auto *m = response.find("model");
          m && std::holds_alternative<std::string>(m->value()))
        out += "/" + sanitize_inline(m->string(), 64);
      out += "):\n";
      out += "  Question: " + sanitize_inline(question, 180) + "\n";
      if (const auto *answers = response.find("answers");
          answers && std::holds_alternative<Value::Object>(answers->value())) {
        if (const auto *adv = answers->find("advisory");
            adv && std::holds_alternative<Value::Object>(adv->value())) {
          std::string choice_str = "unknown";
          if (const auto *ch = adv->find("choice");
              ch && std::holds_alternative<std::string>(ch->value()))
            choice_str = sanitize_inline(ch->string(), 48);
          out += "  Posture:  " + choice_str;
          if (const auto *conf = adv->find("confidence");
              conf && std::holds_alternative<Number>(conf->value()))
            out += " (confidence=" + sanitize_inline(conf->number().text(), 16) + ")";
          out += '\n';
        }
        if (const auto *caution = answers->find("needs_caution");
            caution && std::holds_alternative<Value::Object>(caution->value())) {
          if (const auto *noul = caution->find("noul");
              noul && std::holds_alternative<Number>(noul->value())) {
            out += "  Caution:  p=" + sanitize_inline(noul->number().text(), 16) + "\n";
          }
        }
      }
      if (const auto *usage = response.find("usage");
          usage && std::holds_alternative<Value::Object>(usage->value())) {
        const auto *in_tok = usage->find("input_tokens");
        const auto *out_tok = usage->find("output_tokens");
        if (in_tok && out_tok && std::holds_alternative<Number>(in_tok->value()) &&
            std::holds_alternative<Number>(out_tok->value())) {
          out += "  Usage:    in=" + sanitize_inline(in_tok->number().text(), 16) +
                 " out=" + sanitize_inline(out_tok->number().text(), 16) + "\n";
        }
      }
      return out;
    } catch (const Error &err) {
      return "Companion query failed (" + sanitize_inline(provider, 32) +
             "): " + std::string{error_name(err.code)} +
             " (run `/companion status` to check provider configuration)\n";
    } catch (const std::exception &) {
      // Never leak raw exception strings that could originate from external transport.
      return "Companion query failed (" + sanitize_inline(provider, 32) +
             "): unexpected transport error"
             " (run `/companion status` to check provider configuration)\n";
    }
  }

  return "Usage: /companion [status|ask <question>]\n";
}

// --- /swarmboard & /flightdeck helpers ---
std::optional<std::string> try_load_local_peer_fingerprint() {
  const char *home = std::getenv("HOME");
  if (home == nullptr || home[0] == '\0')
    return std::nullopt;
  const std::filesystem::path peers_dir =
      std::filesystem::path{home} / ".local" / "share" / "blackbird" / "peers";
  std::error_code ec;
  const auto st = std::filesystem::symlink_status(peers_dir, ec);
  if (ec || std::filesystem::is_symlink(st) || !std::filesystem::is_directory(st))
    return std::nullopt;
  auto store = PeerIdentityStore::open_existing(peers_dir);
  if (!store.has_value())
    return std::nullopt;
  return store.value().identity().fingerprint;
}

SwarmboardConfig make_passive_swarmboard_config(const CommandPostTuiContext &ctx) {
  const auto root = resolve_project_root(ctx);
  SwarmboardConfig cfg = SwarmboardConfig::for_project(root);
  if (ctx.worktree_lease_root.has_value())
    cfg.leases_dir = *ctx.worktree_lease_root / ".leases";
  cfg.local_actor_fp = try_load_local_peer_fingerprint();
  if (!ctx.actor.empty())
    cfg.local_actor_id = ctx.actor;
  return cfg;
}

std::optional<std::uint64_t> parse_u64_strict(std::string_view token) noexcept {
  if (token.empty())
    return std::nullopt;
  for (const char ch : token) {
    if (ch < '0' || ch > '9')
      return std::nullopt;
  }
  std::uint64_t value = 0;
  const auto [ptr, ec] =
      std::from_chars(token.data(), token.data() + token.size(), value);
  if (ec != std::errc{} || ptr != token.data() + token.size())
    return std::nullopt;
  return value;
}

std::string derive_flight_deck_model_label(const MetricsSnapshot &snap) {
  const MetricsSourceRecord *best = nullptr;
  for (const auto &rec : snap.source_records) {
    if (rec.model.empty())
      continue;
    const bool rec_provider = (rec.kind == MetricsSampleKind::provider_response);
    if (best == nullptr) {
      best = &rec;
      continue;
    }
    const bool best_provider = (best->kind == MetricsSampleKind::provider_response);
    if (rec_provider != best_provider) {
      if (rec_provider)
        best = &rec;
    } else if (rec.timestamp_ns >= best->timestamp_ns) {
      best = &rec;
    }
  }
  if (best != nullptr)
    return best->model;
  if (!snap.usage.by_provider.empty())
    return snap.usage.by_provider.back().provider;
  return {};
}

// --- /swarmboard ---
std::string handle_swarmboard(std::string_view args, const CommandPostTuiContext &ctx) {
  const auto [sub, rest] = split_first_token(args);
  if (!rest.empty())
    return "Usage: /swarmboard [all|mentions|conflicts|watchers]\n";

  SwarmboardFilter filter = SwarmboardFilter::all;
  if (sub.empty() || sub == "all") {
    filter = SwarmboardFilter::all;
  } else if (sub == "mentions") {
    filter = SwarmboardFilter::mentions;
  } else if (sub == "conflicts") {
    filter = SwarmboardFilter::conflicts;
  } else if (sub == "watchers") {
    filter = SwarmboardFilter::watchers;
  } else {
    return "Usage: /swarmboard [all|mentions|conflicts|watchers]\n";
  }

  const SwarmboardConfig cfg = make_passive_swarmboard_config(ctx);
  auto snap_res = load_swarmboard_snapshot(cfg);
  if (!snap_res.has_value()) {
    return "Swarmboard unavailable: " + std::string{error_name(snap_res.error().code)} +
           "\n";
  }

  SwarmboardView view{std::move(snap_res).value()};
  view.set_filter(filter);
  return view.render(100, 24);
}

// --- /flightdeck ---
std::string handle_flightdeck(std::string_view args, const CommandPostTuiContext &ctx) {
  std::uint64_t tick = 0;
  const auto [sub, rest] = split_first_token(args);
  if (!sub.empty()) {
    if (sub == "tick") {
      const auto [tick_tok, extra] = split_first_token(rest);
      const auto parsed = parse_u64_strict(tick_tok);
      if (!parsed.has_value() || !extra.empty())
        return "Usage: /flightdeck [tick <N>]\n";
      tick = *parsed;
    } else if (rest.empty()) {
      const auto parsed = parse_u64_strict(sub);
      if (!parsed.has_value())
        return "Usage: /flightdeck [tick <N>]\n";
      tick = *parsed;
    } else {
      return "Usage: /flightdeck [tick <N>]\n";
    }
  }

  // Strictly read-only tertiary MetricsConsumer: zero producer hot-path interference.
  MetricsConsumer consumer;
  if (!ctx.session_dir.empty()) {
    std::error_code ec;
    if (std::filesystem::exists(ctx.session_dir, ec) && !ec) {
      auto report = read_token_usage(ctx.session_dir.string());
      if (report.has_value()) {
        (void)consumer.ingest_token_usage(report.value());
      } else {
        consumer.mark_stale("token_usage unavailable", report.error());
      }
    }
  }
  if (ctx.audit_log != nullptr) {
    auto res = consumer.ingest_audit_log(*ctx.audit_log);
    if (!res.has_value())
      consumer.mark_stale("audit_log unavailable", res.error());
  }

  const auto root = resolve_project_root(ctx);
  FlightDeckTelemetry telemetry;
  telemetry.snapshot = consumer.snapshot();
  telemetry.room_label = root.filename().string();
  telemetry.model_label = derive_flight_deck_model_label(telemetry.snapshot);
  telemetry.tick = tick;

  // Passive read-only swarm counts (only populate when backing store exists so
  // absent stores stay UNKNOWN rather than showing a fake 0).
  const SwarmboardConfig swarm_cfg = make_passive_swarmboard_config(ctx);
  auto swarm_res = load_swarmboard_snapshot(swarm_cfg);
  if (swarm_res.has_value()) {
    const auto &swarm = swarm_res.value();
    if (swarm.platoon_present) {
      telemetry.active_peers = swarm.working_peers();
      telemetry.waiting_peers = swarm.waiting_peers();
    }
    if (swarm.bridge_present) {
      telemetry.active_watchers = swarm.watchers.size();
      telemetry.guard_blocked = swarm.guard_checked && !swarm.guard_verdict.allowed;
    }
  }

  const FlightDeckView view;
  const FlightDeckRenderOptions opts{
      .width = 96, .height = 24, .color = false, .honor_no_color_env = true};
  return view.render(telemetry, opts).text();
}

// --- /party ---
constexpr std::string_view kPartyUsage =
    "Usage: /party [status|all|operators|leaders|conflicts|say <text>|create [room]|"
    "start [room]|join <room|bbjoin1:...> [--alias <name>]|invite [relay_url]|"
    "leave|remove <alias>]\n";

std::int64_t party_wall_now_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return ns <= 0 ? 1 : static_cast<std::int64_t>(ns);
}

bool party_eq_ci(std::string_view lhs, std::string_view rhs) noexcept {
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
}

bool is_solo_party_scope(std::string_view scope) noexcept {
  return scope.empty() || party_eq_ci(scope, "solo") || party_eq_ci(scope, "none");
}

std::optional<std::filesystem::path> resolve_peers_dir_from_home() {
  const char *home = std::getenv("HOME");
  if (home == nullptr || home[0] == '\0')
    return std::nullopt;
  return std::filesystem::path{home} / ".local" / "share" / "blackbird" / "peers";
}

PartyConfig make_passive_party_config(const CommandPostTuiContext &ctx) {
  const auto root = resolve_project_root(ctx);
  PartyConfig cfg = PartyConfig::for_project(root);
  cfg.local_operator_id = ctx.actor.empty() ? std::string{"operator"} : ctx.actor;
  cfg.local_actor_fp = try_load_local_peer_fingerprint();
  return cfg;
}

Result<PartyRosterConfig>
load_or_default_party_roster(const std::filesystem::path &path) {
  std::error_code ec;
  const auto st = std::filesystem::symlink_status(path, ec);
  if (ec) {
    if (ec == std::errc::no_such_file_or_directory || ec == std::errc::not_a_directory)
      return Result<PartyRosterConfig>::success(PartyRosterConfig{});
    return Result<PartyRosterConfig>::failure({ErrorCode::io, ec.value()});
  }
  if (std::filesystem::is_symlink(st))
    return Result<PartyRosterConfig>::failure({ErrorCode::io, ELOOP});
  if (!std::filesystem::exists(st))
    return Result<PartyRosterConfig>::success(PartyRosterConfig{});
  return load_party_roster_config(path);
}

std::string derive_creator_alias(std::string_view fingerprint) {
  std::string_view raw = fingerprint;
  if (raw.starts_with("SHA256:"))
    raw.remove_prefix(7);
  std::string out = "peer-";
  for (const char ch : raw) {
    if (out.size() >= 17)
      break;
    if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'))
      out.push_back(ch);
    else if (ch >= 'A' && ch <= 'Z')
      out.push_back(static_cast<char>(ch - 'A' + 'a'));
  }
  if (out.size() <= 5)
    out += "creator";
  return out;
}

std::string normalize_invite_room_id(std::string_view scope) {
  std::string out;
  out.reserve(scope.size());
  for (const char ch : scope) {
    if (ch == '/')
      out.push_back(':');
    else
      out.push_back(ch);
  }
  return out;
}

Result<std::string> generate_party_invite_code() {
  std::array<std::uint8_t, 16> bytes{};
  if (::getentropy(bytes.data(), bytes.size()) != 0)
    return Result<std::string>::failure({ErrorCode::io, errno});
  constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const std::uint8_t byte : bytes) {
    out.push_back(kHex[(byte >> 4U) & 0x0fU]);
    out.push_back(kHex[byte & 0x0fU]);
  }
  return Result<std::string>::success(std::move(out));
}

std::string handle_party(std::string_view args, const CommandPostTuiContext &ctx) {
  const auto root = resolve_project_root(ctx);
  const auto party_config_path = root / ".blackbird" / "party.json";
  const auto platoon_dir = root / ".blackbird" / "platoon";
  const auto [sub, rest] = split_first_token(args);

  // Passive read-only inspection & filter views (zero dirs created!).
  if (sub.empty() || sub == "status" || sub == "all" || sub == "operators" ||
      sub == "leaders" || sub == "conflicts") {
    if (!rest.empty())
      return std::string{kPartyUsage};
    PartyMessageFilter filter = PartyMessageFilter::all;
    if (sub == "operators")
      filter = PartyMessageFilter::operators;
    else if (sub == "leaders")
      filter = PartyMessageFilter::leaders;
    else if (sub == "conflicts")
      filter = PartyMessageFilter::conflicts;

    const PartyConfig cfg = make_passive_party_config(ctx);
    auto snap_res = load_party_snapshot(cfg);
    if (!snap_res.has_value()) {
      return "Party Chat unavailable: " +
             std::string{error_name(snap_res.error().code)} + "\n";
    }
    PartyChatPane pane{std::move(snap_res).value()};
    pane.set_filter(filter);
    return pane.render(100, 24);
  }

  // /party say <text>
  if (sub == "say") {
    if (rest.empty())
      return "Usage: /party say [@all|@alias ...] <message>\n";
    const PartyConfig cfg = make_passive_party_config(ctx);
    auto snap_res = load_party_snapshot(cfg);
    if (!snap_res.has_value()) {
      return "Party Chat unavailable: " +
             std::string{error_name(snap_res.error().code)} + "\n";
    }
    const PartySnapshot &snap = snap_res.value();
    auto parsed_res = parse_party_input(rest, snap);
    if (!parsed_res.has_value())
      return "Usage: /party say [@all|@alias ...] <message>\n";
    const ParsedPartyInput &parsed = parsed_res.value();

    std::string recipient = "all";
    std::string post_text = parsed.body;
    if (!parsed.broadcast) {
      if (parsed.resolved_targets.size() == 1 && parsed.unknown_targets.empty() &&
          valid_platoon_member_id(parsed.resolved_targets[0])) {
        recipient = parsed.resolved_targets[0];
      } else if (parsed.resolved_targets.empty() &&
                 parsed.mentioned_aliases.size() == 1 &&
                 valid_platoon_member_id(parsed.mentioned_aliases[0])) {
        recipient = parsed.mentioned_aliases[0];
      } else if (parsed.mentioned_aliases.size() > 1 ||
                 parsed.resolved_targets.size() > 1) {
        recipient = "all";
        post_text = parsed.target_label + " " + parsed.body;
      }
    }

    auto board_res = PlatoonBoard::open(platoon_dir);
    if (!board_res.has_value()) {
      return "Party board unavailable: " +
             std::string{error_name(board_res.error().code)} + "\n";
    }
    PlatoonPost post;
    post.from = safe_platoon_actor(ctx.actor);
    post.to = recipient;
    post.kind = PlatoonMessageKind::message;
    post.text = std::move(post_text);
    auto posted_res = board_res.value().post(std::move(post));
    if (!posted_res.has_value()) {
      return "Party say failed: " + std::string{error_name(posted_res.error().code)} +
             "\n";
    }
    const auto &posted = posted_res.value();
    std::string out = "Party posted #" + std::to_string(posted.seq) + " [" +
                      sanitize_inline(posted.from, 48) + " -> " +
                      sanitize_inline(parsed.target_label, 64) +
                      "]: " + quote_untrusted_peer_text(posted.text, kMaxPreviewBytes) +
                      "\n";
    if (!parsed.resolved_targets.empty()) {
      out += "  Routed: ";
      for (std::size_t i = 0; i < parsed.resolved_targets.size(); ++i) {
        if (i > 0)
          out += ", ";
        out += "@" + sanitize_inline(parsed.resolved_targets[i], 48);
      }
      out += '\n';
    }
    std::vector<std::string> remote_hints;
    for (const auto &target_id : parsed.resolved_targets) {
      for (const auto &p : snap.participants) {
        if (party_eq_ci(p.id, target_id) && p.ssh_target.has_value() &&
            !p.ssh_target->empty()) {
          remote_hints.push_back("@" + sanitize_inline(p.id, 48) + " (" +
                                 sanitize_inline(*p.ssh_target, 64) + ")");
          break;
        }
      }
    }
    if (!remote_hints.empty()) {
      out += "  Remote peer(s): ";
      for (std::size_t i = 0; i < remote_hints.size(); ++i) {
        if (i > 0)
          out += ", ";
        out += remote_hints[i];
      }
      out += " (use `blackbird party say` or bridge sync for remote delivery)\n";
    }
    if (parsed.has_unknown_targets()) {
      out += "  Unknown target(s): ";
      for (std::size_t i = 0; i < parsed.unknown_targets.size(); ++i) {
        if (i > 0)
          out += ", ";
        out += "@" + sanitize_inline(parsed.unknown_targets[i], 48);
      }
      out += '\n';
    }
    return out;
  }

  // /party create [room] | /party start [room]
  if (sub == "create" || sub == "start") {
    const auto [room_tok, extra] = split_first_token(rest);
    if (!extra.empty())
      return "Usage: /party create [room]\n";
    const std::string_view room = room_tok.empty() ? kPartyDefaultScope : room_tok;
    if (is_solo_party_scope(room))
      return "Invalid party room name: '" + sanitize_inline(room, 64) + "'\n";
    auto roster_res = load_or_default_party_roster(party_config_path);
    if (!roster_res.has_value()) {
      return "Party config unreadable: " +
             std::string{error_name(roster_res.error().code)} + "\n";
    }
    PartyRosterConfig cfg = std::move(roster_res).value();
    cfg.room_scope = std::string{room};
    cfg.mode_override = PartyModeOverride::auto_detect;
    auto saved = save_party_roster_config(party_config_path, cfg);
    if (!saved.has_value()) {
      return "Party create failed: " + std::string{error_name(saved.error().code)} +
             "\n";
    }
    return "Party room active: " + sanitize_inline(cfg.room_scope, 128) +
           " (saved to .blackbird/party.json; Alt+P opens Party Chat)\n";
  }

  // /party join <bbjoin1:...> [--alias <name>] | /party join <room> [--alias <name>]
  if (sub == "join") {
    const auto [target, after_target] = split_first_token(rest);
    if (target.empty())
      return "Usage: /party join <room|bbjoin1:...> [--alias <name>]\n";
    std::optional<std::string> explicit_alias;
    std::string_view rem = after_target;
    while (!rem.empty()) {
      const auto [flag, after_flag] = split_first_token(rem);
      if (flag == "--alias") {
        const auto [val, next] = split_first_token(after_flag);
        if (val.empty())
          return "Usage: /party join <room|bbjoin1:...> [--alias <name>]\n";
        explicit_alias = std::string{val};
        rem = next;
      } else {
        return "Usage: /party join <room|bbjoin1:...> [--alias <name>]\n";
      }
    }

    if (target.starts_with("bbjoin1:")) {
      const std::int64_t now_ns = party_wall_now_ns();
      auto parsed_res = parse_room_invite(target, now_ns);
      if (!parsed_res.has_value()) {
        if (parsed_res.error().code == ErrorCode::stale_handle)
          return "Party join failed: invite expired\n";
        return "Party join failed: " +
               std::string{error_name(parsed_res.error().code)} + "\n";
      }
      const RoomInvite &invite = parsed_res.value();
      const std::string creator_alias =
          explicit_alias.has_value() ? *explicit_alias
                                     : derive_creator_alias(invite.creator_fingerprint);
      if (!valid_peer_alias(creator_alias) || !valid_party_alias(creator_alias)) {
        return "Party join failed: invalid alias '" +
               sanitize_inline(creator_alias, 48) + "'\n";
      }
      const auto peers_dir = resolve_peers_dir_from_home();
      if (!peers_dir.has_value())
        return "Party join failed: HOME is not set\n";
      auto known_res = KnownPeersStore::open(*peers_dir);
      if (!known_res.has_value()) {
        return "Party join failed: known peers store unavailable (" +
               std::string{error_name(known_res.error().code)} + ")\n";
      }
      PinPeerRequest pin_req;
      pin_req.alias = creator_alias;
      pin_req.public_key = invite.creator_public_key;
      pin_req.trust_note =
          "Joined party room " + invite.room_id + " via " + invite.relay_url;
      auto pin_res = known_res.value().pin_peer(pin_req);
      if (!pin_res.has_value()) {
        if (pin_res.error().code == ErrorCode::conflict) {
          return "Party join rejected (conflict): key mismatch for pinned alias '" +
                 sanitize_inline(creator_alias, 48) + "'\n";
        }
        return "Party join failed: " + std::string{error_name(pin_res.error().code)} +
               "\n";
      }

      auto roster_res = load_or_default_party_roster(party_config_path);
      if (!roster_res.has_value()) {
        return "Party config unreadable: " +
               std::string{error_name(roster_res.error().code)} + "\n";
      }
      PartyRosterConfig cfg = std::move(roster_res).value();
      cfg.room_scope = invite.room_id;
      cfg.mode_override = PartyModeOverride::auto_detect;

      PartyRosterPeerConfig peer_entry{};
      peer_entry.alias = creator_alias;
      peer_entry.role = PartyMemberRole::operator_human;
      peer_entry.fingerprint = invite.creator_fingerprint;
      bool updated = false;
      for (auto &existing : cfg.peers) {
        if (party_eq_ci(existing.alias, creator_alias)) {
          existing = peer_entry;
          updated = true;
          break;
        }
      }
      if (!updated)
        cfg.peers.push_back(std::move(peer_entry));

      auto saved = save_party_roster_config(party_config_path, cfg);
      if (!saved.has_value()) {
        return "Party join save failed: " +
               std::string{error_name(saved.error().code)} + "\n";
      }
      return "Joined party room '" + sanitize_inline(invite.room_id, 128) +
             "' (pinned creator @" + sanitize_inline(creator_alias, 48) + " [" +
             sanitize_inline(invite.creator_fingerprint, 64) + "] via " +
             sanitize_inline(invite.relay_url, 128) + ")\n";
    }

    // Plain room join/switch.
    if (is_solo_party_scope(target))
      return "Invalid party room name: '" + sanitize_inline(target, 64) + "'\n";
    if (explicit_alias.has_value()) {
      return "Usage: /party join <bbjoin1:...> --alias <name> (--alias is only valid "
             "with bbjoin1: invites)\n";
    }
    auto roster_res = load_or_default_party_roster(party_config_path);
    if (!roster_res.has_value()) {
      return "Party config unreadable: " +
             std::string{error_name(roster_res.error().code)} + "\n";
    }
    PartyRosterConfig cfg = std::move(roster_res).value();
    cfg.room_scope = std::string{target};
    cfg.mode_override = PartyModeOverride::auto_detect;
    auto saved = save_party_roster_config(party_config_path, cfg);
    if (!saved.has_value()) {
      return "Party join failed: " + std::string{error_name(saved.error().code)} + "\n";
    }
    return "Joined party room: " + sanitize_inline(cfg.room_scope, 128) +
           " (saved to .blackbird/party.json)\n";
  }

  // /party invite [relay_url]
  if (sub == "invite") {
    const auto [relay_tok, extra] = split_first_token(rest);
    if (!extra.empty())
      return "Usage: /party invite [relay_url]\n";

    std::string room_scope{kPartyDefaultScope};
    {
      auto roster_res = load_or_default_party_roster(party_config_path);
      if (!roster_res.has_value()) {
        return "Party config unreadable: " +
               std::string{error_name(roster_res.error().code)} + "\n";
      }
      if (is_solo_party_scope(roster_res.value().room_scope))
        return "No active party room (run `/party create <room>` first).\n";
      room_scope = roster_res.value().room_scope;
    }

    const auto peers_dir = resolve_peers_dir_from_home();
    if (!peers_dir.has_value())
      return "Party invite failed: HOME is not set\n";
    std::error_code pec;
    const auto st = std::filesystem::symlink_status(*peers_dir, pec);
    if (pec || std::filesystem::is_symlink(st) || !std::filesystem::is_directory(st)) {
      return "Party invite failed: no peer identity found (run `blackbird peer init` "
             "first; invite never creates keys)\n";
    }
    const auto key_st = std::filesystem::symlink_status(*peers_dir / "id_ed25519", pec);
    if (pec || std::filesystem::is_symlink(key_st) ||
        !std::filesystem::is_regular_file(key_st)) {
      return "Party invite failed: no peer identity found (run `blackbird peer init` "
             "first; invite never creates keys)\n";
    }
    const auto pub_st =
        std::filesystem::symlink_status(*peers_dir / "id_ed25519.pub", pec);
    if (pec || std::filesystem::is_symlink(pub_st) ||
        !std::filesystem::is_regular_file(pub_st)) {
      return "Party invite failed: no peer identity found (run `blackbird peer init` "
             "first; invite never creates keys)\n";
    }
    auto identity_res = PeerIdentityStore::open_existing(*peers_dir);
    if (!identity_res.has_value()) {
      return "Party invite failed: peer identity unavailable (" +
             std::string{error_name(identity_res.error().code)} + ")\n";
    }

    std::string relay_url;
    if (!relay_tok.empty()) {
      relay_url = std::string{relay_tok};
    } else if (const char *env_relay = std::getenv("BLACKBIRD_RELAY_URL");
               env_relay != nullptr && env_relay[0] != '\0') {
      relay_url = env_relay;
    } else {
      relay_url = "https://relay.blackbird.local/v1";
    }

    auto code_res = generate_party_invite_code();
    if (!code_res.has_value()) {
      return "Party invite failed: entropy unavailable (" +
             std::string{error_name(code_res.error().code)} + ")\n";
    }

    constexpr std::int64_t kInviteTtlNs = 24LL * 3600LL * 1'000'000'000LL;
    const std::int64_t now_ns = party_wall_now_ns();
    if (now_ns > std::numeric_limits<std::int64_t>::max() - kInviteTtlNs)
      return "Party invite failed: clock overflow\n";

    RoomInvite invite;
    invite.room_id = normalize_invite_room_id(room_scope);
    invite.relay_url = std::move(relay_url);
    invite.creator_fingerprint = identity_res.value().identity().fingerprint;
    invite.creator_public_key = identity_res.value().identity().public_key;
    invite.invite_code = std::move(code_res).value();
    invite.expires_ns = now_ns + kInviteTtlNs;

    auto encoded = encode_room_invite(invite);
    if (!encoded.has_value()) {
      return "Party invite failed: " + std::string{error_name(encoded.error().code)} +
             "\n";
    }
    return "Party invite (valid 24h; share over a confidential channel):\n"
           "  Room:  " +
           sanitize_inline(invite.room_id, 128) +
           "\n"
           "  Relay: " +
           sanitize_inline(invite.relay_url, 128) +
           "\n"
           "  URI:   " +
           encoded.value() + "\n";
  }

  // /party leave
  if (sub == "leave") {
    if (!rest.empty())
      return "Usage: /party leave\n";
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(party_config_path, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        ec == std::errc::not_a_directory || (!ec && !std::filesystem::exists(st))) {
      return "Left party (already in solo mode; history and pinned peers untouched).\n";
    }
    if (ec || std::filesystem::is_symlink(st))
      return "Party leave failed: cannot access .blackbird/party.json\n";

    auto loaded = load_party_roster_config(party_config_path);
    const std::string prev_scope =
        loaded.has_value() ? loaded.value().room_scope : std::string{};
    PartyRosterConfig solo_cfg{};
    solo_cfg.room_scope = "solo";
    solo_cfg.mode_override = PartyModeOverride::single_operator;
    solo_cfg.peers.clear();
    auto saved = save_party_roster_config(party_config_path, solo_cfg);
    if (!saved.has_value()) {
      return "Party leave failed: " + std::string{error_name(saved.error().code)} +
             "\n";
    }
    if (!prev_scope.empty() && !is_solo_party_scope(prev_scope)) {
      return "Left party room '" + sanitize_inline(prev_scope, 64) +
             "' — returned to solo mode (history and pinned peers preserved).\n";
    }
    return "Left party — returned to solo mode (history and pinned peers preserved).\n";
  }

  // /party remove <alias>
  if (sub == "remove") {
    const auto [alias, extra] = split_first_token(rest);
    if (alias.empty() || !extra.empty())
      return "Usage: /party remove <alias>\n";
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(party_config_path, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        ec == std::errc::not_a_directory || (!ec && !std::filesystem::exists(st))) {
      return "Party participant not found: @" + sanitize_inline(alias, 48) +
             " (no .blackbird/party.json)\n";
    }
    if (ec || std::filesystem::is_symlink(st))
      return "Party remove failed: cannot access .blackbird/party.json\n";
    auto loaded = load_party_roster_config(party_config_path);
    if (!loaded.has_value()) {
      return "Party config unreadable: " +
             std::string{error_name(loaded.error().code)} + "\n";
    }
    PartyRosterConfig cfg = std::move(loaded).value();
    const auto before_count = cfg.peers.size();
    cfg.peers.erase(std::remove_if(cfg.peers.begin(), cfg.peers.end(),
                                   [&](const PartyRosterPeerConfig &p) {
                                     return party_eq_ci(p.alias, alias);
                                   }),
                    cfg.peers.end());
    if (cfg.peers.size() == before_count) {
      return "Party participant not found: @" + sanitize_inline(alias, 48) + "\n";
    }
    auto saved = save_party_roster_config(party_config_path, cfg);
    if (!saved.has_value()) {
      return "Party remove failed: " + std::string{error_name(saved.error().code)} +
             "\n";
    }
    return "Removed party participant @" + sanitize_inline(alias, 48) +
           " (remaining peers: " + std::to_string(cfg.peers.size()) + ")\n";
  }

  return std::string{kPartyUsage};
}

} // namespace

std::optional<std::string> handle_command_post_slash(std::string_view line,
                                                     const CommandPostTuiContext &ctx) {
  const auto trimmed = trim_view(line);
  if (!trimmed.starts_with('/'))
    return std::nullopt;
  const auto [cmd, args] = split_first_token(trimmed);
  try {
    if (cmd == "/platoon")
      return bound_output(handle_platoon(args, ctx));
    if (cmd == "/issues")
      return bound_output(handle_issues(args, ctx));
    if (cmd == "/memory")
      return bound_output(handle_memory(args, ctx));
    if (cmd == "/capabilities")
      return bound_output(handle_capabilities(args, ctx));
    if (cmd == "/metrics")
      return bound_output(handle_metrics(args, ctx));
    if (cmd == "/companion")
      return bound_output(handle_companion(args, ctx));
    if (cmd == "/swarmboard")
      return bound_output(handle_swarmboard(args, ctx));
    if (cmd == "/flightdeck")
      return bound_output(handle_flightdeck(args, ctx));
    if (cmd == "/party")
      return bound_output(handle_party(args, ctx));
  } catch (const Error &err) {
    return bound_output(std::string{cmd} + " error: " + error_name(err.code));
  } catch (const std::exception &) {
    return bound_output(std::string{cmd} + " error: unexpected internal error");
  }
  return std::nullopt;
}

} // namespace blackbird
