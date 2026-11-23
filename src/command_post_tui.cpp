#include "blackbird/command_post_tui.hpp"
#include "blackbird/bridge_relay.hpp"
#include "blackbird/flight_deck_view.hpp"
#include "blackbird/issues.hpp"
#include "blackbird/json.hpp"
#include "blackbird/metrics_consumer.hpp"
#include "blackbird/mp_client.hpp"
#include "blackbird/mp_protocol.hpp"
#include "blackbird/party_chat.hpp"
#include "blackbird/party_lobby.hpp"
#include "blackbird/peer_identity.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/project_memory.hpp"
#include "blackbird/swarmboard_view.hpp"
#include "blackbird/token_usage.hpp"
#include "blackbird/worktree_lease.hpp"
#include <algorithm>
#include <array>
#include <atomic>
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
#include <sys/stat.h>
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
    if (sub == "detach") {
      if (!rest.empty())
        return "Usage: /flightdeck [tick <N>|detach]\n";
      const std::string session_arg =
          ctx.session_dir.empty() ? std::string{"<dir>"}
                                  : sanitize_inline(ctx.session_dir.string(), 200);
      return "Run in a second Ghostty window/monitor: blackbird flightdeck --session " +
             session_arg +
             " (or press Alt+F inside Blackbird to toggle the live Kitty cockpit!)\n";
    }
    if (sub == "tick") {
      const auto [tick_tok, extra] = split_first_token(rest);
      const auto parsed = parse_u64_strict(tick_tok);
      if (!parsed.has_value() || !extra.empty())
        return "Usage: /flightdeck [tick <N>|detach]\n";
      tick = *parsed;
    } else if (rest.empty()) {
      const auto parsed = parse_u64_strict(sub);
      if (!parsed.has_value())
        return "Usage: /flightdeck [tick <N>|detach]\n";
      tick = *parsed;
    } else {
      return "Usage: /flightdeck [tick <N>|detach]\n";
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
  std::string out = view.render(telemetry, opts).text();
  if (!out.empty() && out.back() != '\n')
    out += '\n';
  out += "Tip: press Alt+F for live Ghostty Kitty Flight Deck, or run "
         "'blackbird flightdeck' in a second monitor window.\n";
  return out;
}

// --- /party ---
constexpr std::string_view kPartyUsage =
    "Usage: /party [status|peers|add <alias> [role=leader|operator] [ssh=user@host]|"
    "all|operators|leaders|conflicts|say <text>|create [room]|start [room]|"
    "join <room|bbjoin1:...> [--alias <name>]|invite [relay_url]|online <args...>|"
    "close|leave|remove <alias>]\n";

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

bool is_user_owned_regular_file(const std::filesystem::path &path) noexcept {
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
}

std::filesystem::path resolve_party_config_path(const CommandPostTuiContext &ctx) {
  if (!ctx.project_root.empty())
    return ctx.project_root / ".blackbird" / "party.json";
  if (const char *bb_home = std::getenv("BLACKBIRD_HOME");
      bb_home != nullptr && bb_home[0] != '\0') {
    return std::filesystem::path{bb_home} / "party.json";
  }
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0')
    return std::filesystem::path{home} / ".blackbird" / "party.json";
  return {};
}

std::string default_ssh_user() {
  const char *raw = std::getenv("USER");
  if (raw == nullptr || raw[0] == '\0')
    raw = std::getenv("LOGNAME");
  std::string out;
  if (raw != nullptr) {
    for (const char ch : std::string_view{raw}) {
      if (out.size() >= 64)
        break;
      const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                      (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
      if (ok)
        out.push_back(ch);
    }
  }
  while (!out.empty() && (out.front() == '-' || out.front() == '.'))
    out.erase(out.begin());
  if (out.empty())
    return "operator";
  return out;
}

std::string default_local_hostname() {
  std::array<char, 256> buf{};
  if (::gethostname(buf.data(), buf.size() - 1U) == 0) {
    buf.back() = '\0';
    std::string out;
    for (const char ch : std::string_view{buf.data()}) {
      if (out.size() >= 128)
        break;
      const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                      (ch >= '0' && ch <= '9') || ch == '.' || ch == '-';
      if (ok)
        out.push_back(ch);
    }
    while (!out.empty() && (out.front() == '.' || out.front() == '-'))
      out.erase(out.begin());
    while (!out.empty() && (out.back() == '.' || out.back() == '-'))
      out.pop_back();
    if (!out.empty())
      return out;
  }
  return "relay.blackbird.local";
}

std::string default_party_room_name(const std::filesystem::path &root) {
  std::filesystem::path normalized = root.lexically_normal();
  if (normalized.filename().empty() && normalized.has_parent_path())
    normalized = normalized.parent_path();
  std::string base = normalized.filename().string();
  if (base.empty() || base == "." || base == "..") {
    std::error_code ec;
    const auto cwd = std::filesystem::current_path(ec);
    if (!ec && !cwd.empty())
      base = cwd.filename().string();
  }
  std::string clean;
  clean.reserve(std::min<std::size_t>(base.size(), 64));
  for (const char ch : base) {
    if (clean.size() >= 64)
      break;
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' ||
                    ch == ':';
    if (ok) {
      if (ch == '.' && !clean.empty() && clean.back() == '.')
        continue;
      clean.push_back(ch);
    }
  }
  auto is_alnum = [](char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
  };
  while (!clean.empty() && !is_alnum(clean.front()))
    clean.erase(clean.begin());
  if (clean.empty() || is_solo_party_scope(clean) || !valid_party_room_id(clean))
    return std::string{kPartyDefaultScope};
  return clean;
}

std::optional<std::filesystem::path> resolve_peers_dir_from_home() {
  const char *home = std::getenv("HOME");
  if (home == nullptr || home[0] == '\0')
    return std::nullopt;
  return std::filesystem::path{home} / ".local" / "share" / "blackbird" / "peers";
}

struct KnownPeersReadResult {
  bool store_present = false;
  std::vector<PinnedPeer> peers;
  std::optional<Error> error;
};

// Strictly passive read-only KnownPeersStore probe: NEVER creates directories
// or lock files when `~/.local/share/blackbird/peers/known_peers.json` is absent.
KnownPeersReadResult read_known_peers_if_present() {
  KnownPeersReadResult out;
  const auto peers_dir = resolve_peers_dir_from_home();
  if (!peers_dir.has_value())
    return out;
  std::error_code ec;
  const auto dir_st = std::filesystem::symlink_status(*peers_dir, ec);
  if (ec || std::filesystem::is_symlink(dir_st) ||
      !std::filesystem::is_directory(dir_st))
    return out;
  const auto json_path = *peers_dir / "known_peers.json";
  const auto file_st = std::filesystem::symlink_status(json_path, ec);
  if (ec || std::filesystem::is_symlink(file_st) ||
      !std::filesystem::is_regular_file(file_st)) {
    return out;
  }
  out.store_present = true;
  auto store = KnownPeersStore::open(*peers_dir);
  if (!store.has_value()) {
    out.error = store.error();
    return out;
  }
  auto listed = store.value().list_peers();
  if (!listed.has_value()) {
    out.error = listed.error();
    return out;
  }
  out.peers = std::move(listed).value();
  return out;
}

std::string format_pinned_peers_list(const KnownPeersReadResult &res,
                                     bool show_add_usage) {
  std::string out;
  if (show_add_usage) {
    out += "Usage: /party add <alias> [role=leader|operator] [ssh=user@host]\n";
  }
  if (res.error.has_value()) {
    out +=
        "Pinned peers unreadable: " + std::string{error_name(res.error->code)} + "\n";
    return out;
  }
  if (!res.store_present) {
    out +=
        "Pinned peers: none (no known peers store yet).\n"
        "  Tip: pin a peer with `blackbird peer pin` or `/party join <bbjoin1:...>`, "
        "then run `/party add <alias>`.\n";
    return out;
  }
  std::vector<const PinnedPeer *> active;
  for (const auto &p : res.peers) {
    if (!p.revoked)
      active.push_back(&p);
  }
  if (active.empty()) {
    out +=
        "Pinned peers: 0 active.\n"
        "  Tip: pin a peer with `blackbird peer pin` or `/party join <bbjoin1:...>`, "
        "then run `/party add <alias>`.\n";
    return out;
  }
  out += "Pinned peers (" + std::to_string(active.size()) + "):\n";
  const std::size_t shown = std::min(active.size(), kMaxListRows);
  for (std::size_t i = 0; i < shown; ++i) {
    const auto &p = *active[i];
    const std::string alias = sanitize_inline(p.alias, 48);
    out += "  " + alias + " [" + sanitize_inline(p.fingerprint, 48) +
           "] — /party add " + alias;
    if (!p.trust_note.empty())
      out += " (" + sanitize_inline(p.trust_note, 64) + ")";
    out += '\n';
  }
  if (active.size() > shown)
    out += "  ... (" + std::to_string(active.size() - shown) + " more)\n";
  return out;
}

PartyConfig make_passive_party_config(const CommandPostTuiContext &ctx) {
  const auto root = resolve_project_root(ctx);
  PartyConfig cfg = PartyConfig::for_project(root);
  const auto cfg_path = resolve_party_config_path(ctx);
  cfg.party_config_path =
      is_user_owned_regular_file(cfg_path) ? cfg_path : std::filesystem::path{};
  cfg.local_operator_id = ctx.actor.empty() ? std::string{"operator"} : ctx.actor;
  cfg.local_actor_fp = try_load_local_peer_fingerprint();
  return cfg;
}

Result<PartyRosterConfig>
load_or_default_party_roster(const std::filesystem::path &path) {
  if (path.empty())
    return Result<PartyRosterConfig>::success(PartyRosterConfig{});
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
  else if (raw.starts_with("bb1-"))
    raw.remove_prefix(4);
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

char32_t decode_utf8_scalar_tui(std::string_view text, std::size_t &offset) noexcept {
  const auto b0 = static_cast<unsigned char>(text[offset]);
  if (b0 < 0x80U) {
    ++offset;
    return static_cast<char32_t>(b0);
  }
  if ((b0 & 0xe0U) == 0xc0U && offset + 1U < text.size()) {
    const auto b1 = static_cast<unsigned char>(text[offset + 1U]);
    offset += 2U;
    return (static_cast<char32_t>(b0 & 0x1fU) << 6U) |
           static_cast<char32_t>(b1 & 0x3fU);
  }
  if ((b0 & 0xf0U) == 0xe0U && offset + 2U < text.size()) {
    const auto b1 = static_cast<unsigned char>(text[offset + 1U]);
    const auto b2 = static_cast<unsigned char>(text[offset + 2U]);
    offset += 3U;
    return (static_cast<char32_t>(b0 & 0x0fU) << 12U) |
           (static_cast<char32_t>(b1 & 0x3fU) << 6U) |
           static_cast<char32_t>(b2 & 0x3fU);
  }
  if ((b0 & 0xf8U) == 0xf0U && offset + 3U < text.size()) {
    const auto b1 = static_cast<unsigned char>(text[offset + 1U]);
    const auto b2 = static_cast<unsigned char>(text[offset + 2U]);
    const auto b3 = static_cast<unsigned char>(text[offset + 3U]);
    offset += 4U;
    return (static_cast<char32_t>(b0 & 0x07U) << 18U) |
           (static_cast<char32_t>(b1 & 0x3fU) << 12U) |
           (static_cast<char32_t>(b2 & 0x3fU) << 6U) |
           static_cast<char32_t>(b3 & 0x3fU);
  }
  offset = text.size();
  return 0x110000U;
}

bool is_forbidden_socket_scalar_tui(char32_t cp) noexcept {
  if (cp < 0x20U || (cp >= 0x7fU && cp <= 0x9fU) || cp > 0x10ffffU)
    return true;
  return (cp >= 0x202aU && cp <= 0x202eU) || (cp >= 0x2066U && cp <= 0x2069U) ||
         cp == 0x200eU || cp == 0x200fU || cp == 0x061cU || cp == 0xfeffU;
}

bool valid_party_lobby_socket_env(std::string_view raw) noexcept {
  if (raw.empty() || !valid_utf8(raw))
    return false;
  std::size_t i = 0;
  while (i < raw.size()) {
    const char32_t cp = decode_utf8_scalar_tui(raw, i);
    if (is_forbidden_socket_scalar_tui(cp))
      return false;
  }
  const std::filesystem::path candidate{raw};
  if (candidate.filename().empty() || candidate.filename() == ".")
    return false;
  for (const auto &comp : candidate) {
    if (comp == "..")
      return false;
  }
  return true;
}

enum class PartyLobbyConnectState : std::uint8_t {
  connected,
  not_running,
  invalid_env,
};

struct PartyLobbyProbe {
  PartyLobbyConnectState state = PartyLobbyConnectState::not_running;
  std::optional<PartyLobbyClient> client;
};

constexpr std::string_view kInvalidPartySocketEnvMsg =
    "Party command failed: invalid BLACKBIRD_PARTY_SOCKET (traversal or forbidden "
    "control characters rejected)\n";

PartyLobbyProbe probe_party_lobby() {
  PartyLobbyProbe out{};
  if (const char *env_sock = std::getenv("BLACKBIRD_PARTY_SOCKET");
      env_sock != nullptr && env_sock[0] != '\0') {
    if (!valid_party_lobby_socket_env(env_sock)) {
      out.state = PartyLobbyConnectState::invalid_env;
      return out;
    }
    auto client = PartyLobbyClient::connect(std::filesystem::path{env_sock});
    if (client.has_value()) {
      out.state = PartyLobbyConnectState::connected;
      out.client.emplace(std::move(client).value());
    }
    return out;
  }
  auto client = PartyLobbyClient::connect(default_party_socket_path());
  if (client.has_value()) {
    out.state = PartyLobbyConnectState::connected;
    out.client.emplace(std::move(client).value());
  }
  return out;
}

std::string safe_party_lobby_alias(std::string_view actor) {
  if (valid_party_alias(actor) && valid_peer_alias(actor))
    return std::string{actor};
  return "operator";
}

struct LocalLobbyLeaseParams {
  std::string room_id;
  std::string actor;
};

struct SignedLocalLeaseOutcome {
  std::optional<PartyLease> lease;
  std::string error_reason;
};

SignedLocalLeaseOutcome sign_local_lobby_lease(PartyLobbyClient &lobby,
                                               const PeerIdentityStore &identity,
                                               const LocalLobbyLeaseParams &params) {
  SignedLocalLeaseOutcome out;
  std::uint64_t rev_epoch = 0;
  if (auto refreshed = lobby.refresh_revocations(); refreshed.has_value()) {
    rev_epoch = refreshed.value();
  } else if (auto pong = lobby.ping(); pong.has_value()) {
    rev_epoch = pong.value().revocation_epoch;
  } else {
    out.error_reason = std::string{error_name(pong.error().code)};
    return out;
  }
  const std::int64_t now_ns = party_wall_now_ns();
  if (now_ns > std::numeric_limits<std::int64_t>::max() - kPartyLobbyDefaultTtlNs) {
    out.error_reason = "clock overflow";
    return out;
  }
  static std::atomic<std::uint64_t> last_lobby_lease_seq{0};
  const auto now_seq = static_cast<std::uint64_t>(now_ns);
  std::uint64_t lease_seq = last_lobby_lease_seq.load(std::memory_order_relaxed);
  for (;;) {
    const std::uint64_t next = (now_seq > lease_seq) ? now_seq : (lease_seq + 1U);
    if (last_lobby_lease_seq.compare_exchange_weak(lease_seq, next,
                                                   std::memory_order_relaxed)) {
      lease_seq = next;
      break;
    }
  }
  PartyLease draft{};
  draft.room_id = params.room_id;
  draft.alias = safe_party_lobby_alias(params.actor);
  draft.role = PartyMemberRole::operator_human;
  draft.host = default_local_hostname();
  draft.issued_ns = now_ns;
  draft.expires_ns = now_ns + kPartyLobbyDefaultTtlNs;
  draft.lease_seq = lease_seq;
  draft.revocation_epoch = rev_epoch;
  auto signed_lease = sign_party_lease(identity, std::move(draft));
  if (!signed_lease.has_value()) {
    out.error_reason = std::string{error_name(signed_lease.error().code)};
    return out;
  }
  out.lease.emplace(std::move(signed_lease).value());
  return out;
}

struct LocalIdentityProbe {
  std::optional<PeerIdentityStore> store;
  std::string error_reason;
};

LocalIdentityProbe try_open_existing_local_identity() {
  LocalIdentityProbe out;
  const auto peers_dir = resolve_peers_dir_from_home();
  if (!peers_dir.has_value()) {
    out.error_reason = "HOME is not set";
    return out;
  }
  std::error_code pec;
  const auto st = std::filesystem::symlink_status(*peers_dir, pec);
  if (pec || std::filesystem::is_symlink(st) || !std::filesystem::is_directory(st)) {
    out.error_reason =
        "no peer identity found (run `blackbird peer init` first; never creates keys)";
    return out;
  }
  const auto key_st = std::filesystem::symlink_status(*peers_dir / "id_ed25519", pec);
  if (pec || std::filesystem::is_symlink(key_st) ||
      !std::filesystem::is_regular_file(key_st)) {
    out.error_reason =
        "no peer identity found (run `blackbird peer init` first; never creates keys)";
    return out;
  }
  const auto pub_st =
      std::filesystem::symlink_status(*peers_dir / "id_ed25519.pub", pec);
  if (pec || std::filesystem::is_symlink(pub_st) ||
      !std::filesystem::is_regular_file(pub_st)) {
    out.error_reason =
        "no peer identity found (run `blackbird peer init` first; never creates keys)";
    return out;
  }
  auto identity_res = PeerIdentityStore::open_existing(*peers_dir);
  if (!identity_res.has_value()) {
    out.error_reason = "peer identity unavailable (" +
                       std::string{error_name(identity_res.error().code)} + ")";
    return out;
  }
  out.store.emplace(std::move(identity_res).value());
  return out;
}

KnownPeersReadResult read_lobby_friends_if_available(PartyLobbyClient &lobby) {
  KnownPeersReadResult out;
  auto friends_res = lobby.list_friends();
  if (!friends_res.has_value()) {
    out.error = friends_res.error();
    return out;
  }
  out.peers = std::move(friends_res).value();
  auto snap_res = lobby.snapshot();
  out.store_present = !out.peers.empty() ||
                      (snap_res.has_value() && snap_res.value().known_peers_present);
  return out;
}

// --- /online (and /party online ...) ---
constexpr std::string_view kDefaultOnlineRelayUrl = "https://relay.multiplayer.tech";
constexpr std::size_t kMaxOnlinePathBytes = 4096U;
constexpr std::size_t kMaxOnlineHostBytes = 255U;

constexpr std::string_view kOnlineHelpText =
    "Online control plane (/online or /party online):\n"
    "  /online [status]                                   Local identity & CWT status\n"
    "  /online health                                     Live control-plane health\n"
    "  /online whoami                                     Account, devices & active "
    "parties\n"
    "  /online resolve <handle>                           Resolve handle & root "
    "fingerprint\n"
    "  /online friends                                    List friends, pending & "
    "blocked\n"
    "  /online friend add <handle|account_id>             Send or accept friend "
    "request\n"
    "  /online friend accept <handle|account_id>          Accept incoming friend "
    "request\n"
    "  /online friend deny <handle|account_id>            Deny incoming friend "
    "request (alias: decline)\n"
    "  /online friend remove <handle|account_id>          Remove friend\n"
    "  /online friend block <handle|account_id>           Block account\n"
    "  /online party create [private|friends] [force|allow|no]\n"
    "                                                     Create online party\n"
    "  /online party info <party_id>                      Inspect party summary\n"
    "  /online party invite <party_id>                    Create party invite link\n"
    "  /online party join <party_id|mppi1_...>            Join party by ID or invite\n"
    "  /online party leave <party_id>                     Leave party\n"
    "  /online party disband <party_id> [epoch]           Disband party\n"
    "  /online web-approve <XXXX-XXXX>                    Approve web portal sign-in\n"
    "  /online help                                       Show this usage summary\n";

bool valid_online_path_env(std::string_view raw, bool require_file_leaf) noexcept {
  if (raw.empty() || raw.size() > kMaxOnlinePathBytes || !valid_utf8(raw))
    return false;
  std::size_t i = 0;
  while (i < raw.size()) {
    const char32_t cp = decode_utf8_scalar_tui(raw, i);
    if (is_forbidden_socket_scalar_tui(cp))
      return false;
  }
  const std::filesystem::path candidate{raw};
  if (require_file_leaf &&
      (candidate.filename().empty() || candidate.filename() == ".")) {
    return false;
  }
  for (const auto &comp : candidate) {
    if (comp == "..")
      return false;
  }
  return true;
}

bool valid_online_host_env(std::string_view raw) noexcept {
  if (raw.empty() || raw.size() > kMaxOnlineHostBytes || raw.front() == '-' ||
      !valid_utf8(raw)) {
    return false;
  }
  for (const char ch : raw) {
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == ':' ||
                    ch == '[' || ch == ']';
    if (!ok)
      return false;
  }
  return true;
}

std::string format_mp_error_detail(const Error &err) {
  if (err.detail >= 1000) {
    return std::string{mp::mp_client_error_name(mp::mp_client_error_of(err))};
  }
  if (err.detail >= 100) {
    return std::string{mp::mp_error_name(mp::mp_error_of(err))};
  }
  return std::string{error_name(err.code)};
}

std::string format_online_onboarding_hint(std::string_view authority) {
  return "Online status: unregistered (no local identity found)\n"
         "  Authority: " +
         sanitize_inline(authority, 128) +
         "\n"
         "  Run: blackbird online register --invite <mpinv1_...> --handle <name>\n";
}

struct OnlineEnvConfig {
  mp::MpClientConfig client_cfg;
  bool authority_from_env = false;
  std::optional<std::filesystem::path> state_dir;
  std::string state_dir_error;
  std::string fatal_error;
};

OnlineEnvConfig load_online_env_config() {
  OnlineEnvConfig out{};
  out.client_cfg.authority = std::string{mp::kDefaultMpAuthority};
  out.client_cfg.port = mp::kDefaultMpPort;

  if (const char *env_dir = std::getenv("BLACKBIRD_ONLINE_DIR");
      env_dir != nullptr && env_dir[0] != '\0') {
    if (!valid_online_path_env(env_dir, false)) {
      out.fatal_error =
          "Online command failed: invalid BLACKBIRD_ONLINE_DIR (traversal or forbidden "
          "control/BiDi characters rejected)\n";
      return out;
    }
    out.state_dir = std::filesystem::path{env_dir};
  } else if (const char *xdg = std::getenv("XDG_CONFIG_HOME");
             xdg != nullptr && xdg[0] != '\0') {
    if (!valid_online_path_env(xdg, false)) {
      out.state_dir_error =
          "Online command failed: invalid XDG_CONFIG_HOME (traversal or forbidden "
          "control/BiDi characters rejected)\n";
    } else {
      out.state_dir = std::filesystem::path{xdg} / "blackbird" / "online";
    }
  } else if (const char *home = std::getenv("HOME");
             home != nullptr && home[0] != '\0') {
    if (!valid_online_path_env(home, false)) {
      out.state_dir_error =
          "Online command failed: invalid HOME (traversal or forbidden control/BiDi "
          "characters rejected)\n";
    } else {
      out.state_dir = std::filesystem::path{home} / ".config" / "blackbird" / "online";
    }
  } else {
    out.state_dir_error =
        "Online command failed: unable to resolve online state directory "
        "(set BLACKBIRD_ONLINE_DIR, XDG_CONFIG_HOME, or HOME)\n";
  }

  if (const char *env_ca = std::getenv("BLACKBIRD_ONLINE_CA_BUNDLE");
      env_ca != nullptr && env_ca[0] != '\0') {
    if (!valid_online_path_env(env_ca, true)) {
      out.fatal_error = "Online command failed: invalid BLACKBIRD_ONLINE_CA_BUNDLE "
                        "(traversal or forbidden control/BiDi characters rejected)\n";
      return out;
    }
    out.client_cfg.ca_bundle_path = std::filesystem::path{env_ca};
  }

  if (const char *env_auth = std::getenv("BLACKBIRD_ONLINE_AUTHORITY");
      env_auth != nullptr && env_auth[0] != '\0') {
    if (!valid_online_host_env(env_auth)) {
      out.fatal_error = "Online command failed: invalid BLACKBIRD_ONLINE_AUTHORITY\n";
      return out;
    }
    out.client_cfg.authority = env_auth;
    out.authority_from_env = true;
  }

  if (const char *env_host = std::getenv("BLACKBIRD_ONLINE_CONNECT_HOST");
      env_host != nullptr && env_host[0] != '\0') {
    if (!valid_online_host_env(env_host)) {
      out.fatal_error =
          "Online command failed: invalid BLACKBIRD_ONLINE_CONNECT_HOST\n";
      return out;
    }
    out.client_cfg.connect_host = env_host;
  }

  if (const char *env_port = std::getenv("BLACKBIRD_ONLINE_PORT");
      env_port != nullptr && env_port[0] != '\0') {
    const std::string_view port_sv{env_port};
    if (!valid_port_str(port_sv)) {
      out.fatal_error = "Online command failed: invalid BLACKBIRD_ONLINE_PORT "
                        "(expected 1..65535)\n";
      return out;
    }
    std::uint16_t port_num = 0;
    const auto [ptr, ec] =
        std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port_num);
    if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size() || port_num == 0U) {
      out.fatal_error = "Online command failed: invalid BLACKBIRD_ONLINE_PORT "
                        "(expected 1..65535)\n";
      return out;
    }
    out.client_cfg.port = port_num;
  }

  return out;
}

std::string_view friend_edge_state_name(mp::FriendEdgeState state) noexcept {
  switch (state) {
  case mp::FriendEdgeState::friend_edge:
    return "friend";
  case mp::FriendEdgeState::invite_sent:
    return "invite_sent";
  case mp::FriendEdgeState::invite_received:
    return "invite_received";
  case mp::FriendEdgeState::blocked:
    return "blocked";
  }
  return "unknown";
}

std::string_view party_visibility_name(mp::PartyVisibility vis) noexcept {
  switch (vis) {
  case mp::PartyVisibility::private_party:
    return "private";
  case mp::PartyVisibility::friends:
    return "friends";
  }
  return "unknown";
}

std::string_view party_join_mode_name(mp::PartyJoinMode mode) noexcept {
  switch (mode) {
  case mp::PartyJoinMode::invite_only:
    return "invite_only";
  case mp::PartyJoinMode::approval_required:
    return "approval_required";
  }
  return "unknown";
}

std::string_view relay_policy_name(mp::RelayPolicy policy) noexcept {
  switch (policy) {
  case mp::RelayPolicy::allow_relays:
    return "allow_relays";
  case mp::RelayPolicy::force_relays:
    return "force_relays";
  case mp::RelayPolicy::no_relays:
    return "no_relays";
  }
  return "unknown";
}

std::string format_duration_seconds(std::int64_t seconds) {
  if (seconds <= 0)
    return "0s";
  const std::int64_t days = seconds / 86400;
  const std::int64_t hours = (seconds % 86400) / 3600;
  const std::int64_t mins = (seconds % 3600) / 60;
  if (days > 0)
    return std::to_string(days) + "d " + std::to_string(hours) + "h";
  if (hours > 0)
    return std::to_string(hours) + "h " + std::to_string(mins) + "m";
  if (mins > 0)
    return std::to_string(mins) + "m " + std::to_string(seconds % 60) + "s";
  return std::to_string(seconds) + "s";
}

std::string format_pubkey_sha256_hex(const mp::Ed25519PubKey &pubkey) {
  const auto digest = mp::sha256(pubkey);
  if (!digest.has_value())
    return "(hash_error)";
  return mp::hex_lower(digest.value());
}

struct OpenedOnlineClient {
  std::optional<mp::MpControlClient> client;
  std::string error_output;
};

OpenedOnlineClient open_authenticated_online_client(const OnlineEnvConfig &env) {
  OpenedOnlineClient out{};
  if (!env.state_dir.has_value()) {
    out.error_output = env.state_dir_error;
    return out;
  }
  auto store_res = mp::MpIdentityStore::open_existing(*env.state_dir);
  if (!store_res.has_value()) {
    if (mp::mp_client_error_of(store_res.error()) ==
        mp::MpClientError::keystore_not_found) {
      out.error_output = format_online_onboarding_hint(env.client_cfg.authority);
      return out;
    }
    out.error_output =
        "Online identity unavailable: " + format_mp_error_detail(store_res.error()) +
        "\n";
    return out;
  }
  mp::MpClientConfig cfg = env.client_cfg;
  const mp::MpIdentityState &st = store_res.value().state();
  if (!env.authority_from_env && !st.authority.empty()) {
    cfg.authority = st.authority;
  }
  out.client.emplace(std::move(cfg), st);
  return out;
}

bool is_all_ascii_digits(std::string_view text) noexcept {
  if (text.empty())
    return false;
  for (const char ch : text) {
    if (ch < '0' || ch > '9')
      return false;
  }
  return true;
}

struct CleanseOptionalStringGuard {
  std::optional<std::string> &value;
  ~CleanseOptionalStringGuard() noexcept {
    if (value.has_value()) {
      volatile char *ptr = value->data();
      for (std::size_t i = 0; i < value->size(); ++i)
        ptr[i] = '\0';
      value->clear();
    }
  }
};

struct ParsedOnlineInviteLink {
  mp::PartyId party_id = mp::PartyId::create(1U).value();
  std::string invite_link;
};

std::optional<ParsedOnlineInviteLink>
parse_online_party_invite_link(std::string_view raw) {
  static constexpr std::string_view kPrefix = "mppi1_";
  if (!raw.starts_with(kPrefix) || raw.size() > 256U)
    return std::nullopt;
  const std::string_view body = raw.substr(kPrefix.size());
  const auto sep = body.find('_');
  if (sep == std::string_view::npos || sep == 0U || sep + 1U >= body.size())
    return std::nullopt;
  const auto pid = mp::PartyId::parse_decimal(body.substr(0U, sep));
  if (!pid.has_value())
    return std::nullopt;
  const std::string_view secret = body.substr(sep + 1U);
  if (secret.empty())
    return std::nullopt;
  for (const char ch : secret) {
    const auto u = static_cast<unsigned char>(ch);
    if (u <= 0x20U || u >= 0x7fU)
      return std::nullopt;
  }
  return ParsedOnlineInviteLink{pid.value(), std::string{raw}};
}

std::string handle_online_status(const OnlineEnvConfig &env) {
  if (!env.state_dir.has_value())
    return env.state_dir_error;
  auto store_res = mp::MpIdentityStore::open_existing(*env.state_dir);
  if (!store_res.has_value()) {
    if (mp::mp_client_error_of(store_res.error()) ==
        mp::MpClientError::keystore_not_found) {
      return format_online_onboarding_hint(env.client_cfg.authority);
    }
    return "Online status failed: " + format_mp_error_detail(store_res.error()) + "\n";
  }
  const mp::MpIdentityStore &store = store_res.value();
  const mp::MpIdentityState &st = store.state();
  const std::string &authority =
      env.authority_from_env
          ? env.client_cfg.authority
          : (!st.authority.empty() ? st.authority : env.client_cfg.authority);

  std::string cwt_summary;
  if (st.device_cwt.empty()) {
    cwt_summary = "absent";
  } else if (st.root_seed.has_value()) {
    const auto root_key = store.root_signing_key();
    const auto dev_key = store.device_signing_key();
    if (!root_key.has_value() || !dev_key.has_value()) {
      cwt_summary = "invalid (key derivation failed)";
    } else {
      const std::int64_t now_s =
          std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count();
      const auto ver = mp::verify_device_cwt(mp::DeviceCwtVerifyRequest{
          st.device_cwt,
          root_key.value().public_key(),
          dev_key.value().public_key(),
          now_s,
      });
      if (ver.has_value()) {
        const std::int64_t rem = ver.value().exp - now_s;
        cwt_summary = "valid (exp=" + std::to_string(ver.value().exp) + ", " +
                      format_duration_seconds(rem) + " left)";
      } else if (mp::mp_error_of(ver.error()) == mp::MpError::cwt_expired) {
        cwt_summary = "expired";
      } else {
        cwt_summary = "invalid (" + format_mp_error_detail(ver.error()) + ")";
      }
    }
  } else {
    cwt_summary = "present (" + std::to_string(st.device_cwt.size()) +
                  " bytes; root key offline)";
  }

  std::string out = "Online status:\n";
  out += "  Handle:     " +
         (st.handle.empty() ? std::string{"(unset)"} : sanitize_inline(st.handle, 64)) +
         "\n";
  out += "  Account ID: " +
         (st.account_id.has_value() ? st.account_id->to_decimal() : "(unset)") + "\n";
  out += "  Device ID:  " +
         (st.device_id.has_value() ? st.device_id->to_decimal() : "(unset)") + "\n";
  out += "  Authority:  " + sanitize_inline(authority, 128) + "\n";
  out += "  Root key:   " + std::string{st.root_seed.has_value() ? "yes" : "no"} + "\n";
  out += "  Local CWT:  " + cwt_summary + "\n";
  return out;
}

struct ResolvedTuiFriendTarget {
  std::optional<mp::AccountId> account_id;
  std::string resolved_handle;
  std::string error_output;
};

std::optional<std::string> validate_online_friend_target(std::string_view target) {
  if (is_all_ascii_digits(target)) {
    const auto parsed = mp::AccountId::parse_decimal(target);
    if (!parsed.has_value()) {
      return "Invalid account_id: '" + sanitize_inline(target, 64) + "'\n";
    }
    return std::nullopt;
  }
  const auto valid_handle = mp::AccountHandle::parse(target);
  if (!valid_handle.has_value()) {
    return "Invalid handle or account_id: '" + sanitize_inline(target, 64) + "'\n";
  }
  return std::nullopt;
}

ResolvedTuiFriendTarget resolve_online_friend_target(mp::MpControlClient &client,
                                                     std::string_view target) {
  ResolvedTuiFriendTarget out{};
  if (is_all_ascii_digits(target)) {
    const auto parsed = mp::AccountId::parse_decimal(target);
    if (!parsed.has_value()) {
      out.error_output = "Invalid account_id: '" + sanitize_inline(target, 64) + "'\n";
      return out;
    }
    out.account_id = parsed.value();
    return out;
  }
  const auto resolved = client.resolve_handle(target);
  if (!resolved.has_value()) {
    out.error_output = "Online resolve failed (" + sanitize_inline(target, 64) +
                       "): " + format_mp_error_detail(resolved.error()) + "\n";
    return out;
  }
  out.account_id = resolved.value().account_id;
  out.resolved_handle = resolved.value().handle;
  return out;
}

std::string handle_online_friend(std::string_view rest, const OnlineEnvConfig &env) {
  const auto [action, tail] = split_first_token(rest);
  if (action == "add" || action == "accept") {
    const bool is_accept = action == "accept";
    const auto [target, extra] = split_first_token(tail);
    if (target.empty() || !extra.empty()) {
      return is_accept ? "Usage: /online friend accept <handle|account_id>\n"
                       : "Usage: /online friend add <handle|account_id>\n";
    }
    if (const auto err = validate_online_friend_target(target); err.has_value())
      return *err;
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const auto resolved = resolve_online_friend_target(*opened.client, target);
    if (!resolved.account_id.has_value())
      return resolved.error_output;
    const auto res = opened.client->send_or_accept_friend(*resolved.account_id);
    if (!res.has_value()) {
      return std::string{is_accept ? "Online friend accept failed: "
                                   : "Online friend add failed: "} +
             format_mp_error_detail(res.error()) + "\n";
    }
    std::string out =
        std::string{is_accept ? "Accepted online friend request: account_id="
                              : "Online friend updated: account_id="} +
        res.value().target_account_id.to_decimal();
    if (!resolved.resolved_handle.empty())
      out += " handle=" + sanitize_inline(resolved.resolved_handle, 64);
    out += " state=" + std::string{friend_edge_state_name(res.value().state)} + "\n";
    return out;
  }

  if (action == "deny" || action == "decline") {
    const auto [target, extra] = split_first_token(tail);
    if (target.empty() || !extra.empty())
      return "Usage: /online friend deny <handle|account_id>\n";
    if (const auto err = validate_online_friend_target(target); err.has_value())
      return *err;
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const auto resolved = resolve_online_friend_target(*opened.client, target);
    if (!resolved.account_id.has_value())
      return resolved.error_output;
    const mp::AccountId target_id = *resolved.account_id;
    const auto res = opened.client->remove_friend(target_id);
    if (!res.has_value()) {
      return "Online friend deny failed: " + format_mp_error_detail(res.error()) + "\n";
    }
    std::string out =
        "Denied online friend request: account_id=" + target_id.to_decimal();
    if (!resolved.resolved_handle.empty())
      out += " handle=" + sanitize_inline(resolved.resolved_handle, 64);
    out += "\n";
    return out;
  }

  if (action == "remove") {
    const auto [target, extra] = split_first_token(tail);
    if (target.empty() || !extra.empty())
      return "Usage: /online friend remove <handle|account_id>\n";
    if (const auto err = validate_online_friend_target(target); err.has_value())
      return *err;
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const auto resolved = resolve_online_friend_target(*opened.client, target);
    if (!resolved.account_id.has_value())
      return resolved.error_output;
    const mp::AccountId target_id = *resolved.account_id;
    const auto res = opened.client->remove_friend(target_id);
    if (!res.has_value()) {
      return "Online friend remove failed: " + format_mp_error_detail(res.error()) +
             "\n";
    }
    std::string out = "Removed online friend: account_id=" + target_id.to_decimal();
    if (!resolved.resolved_handle.empty())
      out += " handle=" + sanitize_inline(resolved.resolved_handle, 64);
    out += "\n";
    return out;
  }

  if (action == "block") {
    const auto [target, extra] = split_first_token(tail);
    if (target.empty() || !extra.empty())
      return "Usage: /online friend block <handle|account_id>\n";
    if (const auto err = validate_online_friend_target(target); err.has_value())
      return *err;
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const auto resolved = resolve_online_friend_target(*opened.client, target);
    if (!resolved.account_id.has_value())
      return resolved.error_output;
    const mp::AccountId target_id = *resolved.account_id;
    const auto res = opened.client->block_account(target_id);
    if (!res.has_value()) {
      return "Online friend block failed: " + format_mp_error_detail(res.error()) +
             "\n";
    }
    std::string out = "Blocked online account: account_id=" + target_id.to_decimal();
    if (!resolved.resolved_handle.empty())
      out += " handle=" + sanitize_inline(resolved.resolved_handle, 64);
    out += "\n";
    return out;
  }

  return "Usage: /online friend [add <handle|account_id>|accept <handle|account_id>|"
         "deny <handle|account_id>|remove <handle|account_id>|"
         "block <handle|account_id>]\n";
}

std::string handle_online_party(std::string_view rest, const OnlineEnvConfig &env) {
  const auto [action, tail] = split_first_token(rest);

  if (action == "create") {
    mp::PartyVisibility vis = mp::PartyVisibility::friends;
    mp::RelayPolicy relay_pol = mp::RelayPolicy::force_relays;
    const auto [arg1, after1] = split_first_token(tail);
    if (!arg1.empty()) {
      if (arg1 == "private")
        vis = mp::PartyVisibility::private_party;
      else if (arg1 == "friends")
        vis = mp::PartyVisibility::friends;
      else
        return "Usage: /online party create [private|friends] [force|allow|no]\n";
      const auto [arg2, after2] = split_first_token(after1);
      if (!arg2.empty()) {
        if (!after2.empty())
          return "Usage: /online party create [private|friends] [force|allow|no]\n";
        if (arg2 == "force")
          relay_pol = mp::RelayPolicy::force_relays;
        else if (arg2 == "allow")
          relay_pol = mp::RelayPolicy::allow_relays;
        else if (arg2 == "no")
          relay_pol = mp::RelayPolicy::no_relays;
        else
          return "Usage: /online party create [private|friends] [force|allow|no]\n";
      }
    }
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;

    mp::CreatePartyRequest req{};
    req.visibility = vis;
    req.join_mode = mp::PartyJoinMode::invite_only;
    req.relay_policy = relay_pol;
    req.max_members = 4U;
    if (relay_pol == mp::RelayPolicy::no_relays) {
      req.relay_url.clear();
      req.endpoint = mp::EndpointDescriptor{mp::TransportKind::direct_quic, "", {}};
    } else {
      req.relay_url = std::string{kDefaultOnlineRelayUrl};
      req.endpoint = mp::EndpointDescriptor{
          mp::TransportKind::iroh_quic, std::string{kDefaultOnlineRelayUrl}, {}};
    }
    const auto created = opened.client->create_party(req);
    if (!created.has_value()) {
      return "Online party create failed: " + format_mp_error_detail(created.error()) +
             "\n";
    }
    std::string out = "Created online party:\n";
    out += "  party_id:         " + created.value().party_id.to_decimal() + "\n";
    out += "  party_epoch:      " + std::to_string(created.value().party_epoch) + "\n";
    out += "  visibility:       " + std::string{party_visibility_name(vis)} + "\n";
    out += "  join_mode:        " + std::string{party_join_mode_name(req.join_mode)} +
           "\n";
    out += "  relay_policy:     " + std::string{relay_policy_name(relay_pol)} + "\n";
    out += "  max_members:      " + std::to_string(req.max_members) + "\n";
    out += "  pinned_relay_url: " +
           (created.value().pinned_relay_url.empty()
                ? std::string{"(none)"}
                : sanitize_inline(created.value().pinned_relay_url, 128)) +
           "\n";
    return out;
  }

  if (action == "info") {
    const auto [pid_tok, extra] = split_first_token(tail);
    if (pid_tok.empty() || !extra.empty())
      return "Usage: /online party info <party_id>\n";
    const auto pid = mp::PartyId::parse_decimal(pid_tok);
    if (!pid.has_value())
      return "Invalid party_id: '" + sanitize_inline(pid_tok, 64) + "'\n";
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const auto info = opened.client->get_party(pid.value());
    if (!info.has_value()) {
      return "Online party info failed: " + format_mp_error_detail(info.error()) + "\n";
    }
    const mp::PartySummary &p = info.value();
    std::string out = "Online party " + p.party_id.to_decimal() + ":\n";
    out += "  party_epoch:      " + std::to_string(p.party_epoch) + "\n";
    out += "  leader_account:   " + p.leader_account_id.to_decimal() + "\n";
    out += "  leader_device:    " + p.leader_device_id.to_decimal() + "\n";
    out += "  visibility:       " + std::string{party_visibility_name(p.visibility)} +
           "\n";
    out +=
        "  join_mode:        " + std::string{party_join_mode_name(p.join_mode)} + "\n";
    out +=
        "  relay_policy:     " + std::string{relay_policy_name(p.relay_policy)} + "\n";
    out += "  members:          " + std::to_string(p.member_count) + "/" +
           std::to_string(p.max_members) + "\n";
    out += "  pinned_relay_url: " +
           (p.pinned_relay_url.empty() ? std::string{"(none)"}
                                       : sanitize_inline(p.pinned_relay_url, 128)) +
           "\n";
    return out;
  }

  if (action == "invite") {
    const auto [pid_tok, extra] = split_first_token(tail);
    if (pid_tok.empty() || !extra.empty())
      return "Usage: /online party invite <party_id>\n";
    const auto pid = mp::PartyId::parse_decimal(pid_tok);
    if (!pid.has_value())
      return "Invalid party_id: '" + sanitize_inline(pid_tok, 64) + "'\n";
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    mp::CreatePartyInviteRequest req{pid.value(), std::nullopt, 1U, 3600U};
    const auto inv = opened.client->create_party_invite(req);
    if (!inv.has_value()) {
      return "Online party invite failed: " + format_mp_error_detail(inv.error()) +
             "\n";
    }
    std::string out = "Created online party invite:\n";
    out += "  party_id:        " + pid.value().to_decimal() + "\n";
    out += "  party_invite_id: " + inv.value().party_invite_id.to_decimal() + "\n";
    out += "  expires_at_ms:   " + std::to_string(inv.value().expires_at_ms) + "\n";
    if (inv.value().invite_link.has_value() && !inv.value().invite_link->empty()) {
      out += "  invite_link:     " + sanitize_inline(*inv.value().invite_link, 256) +
             " (share over a confidential channel)\n";
    }
    return out;
  }

  if (action == "join") {
    const auto [target, extra] = split_first_token(tail);
    if (target.empty() || !extra.empty())
      return "Usage: /online party join <party_id|mppi1_...>\n";
    std::optional<mp::PartyId> pid;
    std::optional<std::string> invite_link;
    CleanseOptionalStringGuard invite_guard{invite_link};
    if (target.starts_with("mppi1_")) {
      auto parsed = parse_online_party_invite_link(target);
      if (!parsed.has_value()) {
        return "Invalid online party invite link (expected "
               "mppi1_<party_id>_<secret>)\n";
      }
      pid = parsed->party_id;
      invite_link = std::move(parsed->invite_link);
    } else {
      const auto parsed = mp::PartyId::parse_decimal(target);
      if (!parsed.has_value()) {
        return "Invalid party_id: '" + sanitize_inline(target, 64) + "'\n";
      }
      pid = parsed.value();
    }
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const mp::EndpointDescriptor ep{
        mp::TransportKind::iroh_quic, std::string{kDefaultOnlineRelayUrl}, {}};
    mp::JoinPartyRequest req{*pid, ep, std::move(invite_link)};
    CleanseOptionalStringGuard req_invite_guard{req.invite_link};
    const auto joined = opened.client->join_party(req);
    if (!joined.has_value()) {
      return "Online party join failed: " + format_mp_error_detail(joined.error()) +
             "\n";
    }
    if (joined.value().pending_approval) {
      std::string out =
          "Online party join pending approval: party_id=" + pid->to_decimal();
      if (joined.value().request_id.has_value())
        out += " request_id=" + joined.value().request_id->to_decimal();
      out += '\n';
      return out;
    }
    return "Joined online party " + pid->to_decimal() +
           " (party_epoch=" + std::to_string(joined.value().party_epoch) + ")\n";
  }

  if (action == "leave") {
    const auto [pid_tok, extra] = split_first_token(tail);
    if (pid_tok.empty() || !extra.empty())
      return "Usage: /online party leave <party_id>\n";
    const auto pid = mp::PartyId::parse_decimal(pid_tok);
    if (!pid.has_value())
      return "Invalid party_id: '" + sanitize_inline(pid_tok, 64) + "'\n";
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const auto left = opened.client->leave_party(pid.value());
    if (!left.has_value()) {
      return "Online party leave failed: " + format_mp_error_detail(left.error()) +
             "\n";
    }
    return "Left online party " + pid.value().to_decimal() +
           " (party_epoch=" + std::to_string(left.value().party_epoch) + ")\n";
  }

  if (action == "disband") {
    const auto [pid_tok, epoch_rest] = split_first_token(tail);
    if (pid_tok.empty())
      return "Usage: /online party disband <party_id> [epoch]\n";
    const auto pid = mp::PartyId::parse_decimal(pid_tok);
    if (!pid.has_value())
      return "Invalid party_id: '" + sanitize_inline(pid_tok, 64) + "'\n";
    std::optional<std::uint64_t> explicit_epoch;
    if (!epoch_rest.empty()) {
      const auto [ep_tok, extra] = split_first_token(epoch_rest);
      if (!extra.empty() || !is_all_ascii_digits(ep_tok))
        return "Usage: /online party disband <party_id> [epoch]\n";
      std::uint64_t parsed_epoch = 0;
      const auto [ptr, ec] =
          std::from_chars(ep_tok.data(), ep_tok.data() + ep_tok.size(), parsed_epoch);
      if (ec != std::errc{} || ptr != ep_tok.data() + ep_tok.size())
        return "Invalid party epoch: '" + sanitize_inline(ep_tok, 32) + "'\n";
      explicit_epoch = parsed_epoch;
    }
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    std::uint64_t expected_epoch = 0;
    if (explicit_epoch.has_value()) {
      expected_epoch = *explicit_epoch;
    } else {
      const auto summary = opened.client->get_party(pid.value());
      if (!summary.has_value()) {
        return "Online party disband failed (fetch epoch): " +
               format_mp_error_detail(summary.error()) + "\n";
      }
      expected_epoch = summary.value().party_epoch;
    }
    const auto disbanded = opened.client->disband_party(
        mp::DisbandPartyRequest{pid.value(), expected_epoch});
    if (!disbanded.has_value()) {
      return "Online party disband failed: " +
             format_mp_error_detail(disbanded.error()) + "\n";
    }
    return "Disbanded online party " + pid.value().to_decimal() +
           " (party_epoch=" + std::to_string(disbanded.value().party_epoch) + ")\n";
  }

  return "Usage: /online party [create [private|friends] [force|allow|no]|"
         "info <party_id>|invite <party_id>|join <party_id|mppi1_...>|"
         "leave <party_id>|disband <party_id> [epoch]]\n";
}

std::string handle_online(std::string_view args) {
  const auto [sub, rest] = split_first_token(args);
  const std::string_view cmd = sub.empty() ? std::string_view{"status"} : sub;

  if (cmd == "help" || cmd == "--help" || cmd == "-h") {
    if (!rest.empty())
      return "Usage: /online help\n";
    return std::string{kOnlineHelpText};
  }

  const OnlineEnvConfig env = load_online_env_config();
  if (!env.fatal_error.empty())
    return env.fatal_error;

  if (cmd == "status") {
    if (!rest.empty())
      return "Usage: /online [status]\n";
    return handle_online_status(env);
  }

  if (cmd == "health") {
    if (!rest.empty())
      return "Usage: /online health\n";
    mp::MpControlClient client{env.client_cfg};
    const auto res = client.health();
    if (!res.has_value()) {
      return "Online health failed: " + format_mp_error_detail(res.error()) + "\n";
    }
    return "Online health (" + sanitize_inline(env.client_cfg.authority, 128) + "):\n" +
           "  status:        " + (res.value().ok ? "ok" : "degraded") + "\n" +
           "  server_now_ms: " + std::to_string(res.value().server_now_ms) + "\n";
  }

  if (cmd == "whoami") {
    if (!rest.empty())
      return "Usage: /online whoami\n";
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const auto res = opened.client->whoami();
    if (!res.has_value()) {
      return "Online whoami failed: " + format_mp_error_detail(res.error()) + "\n";
    }
    const mp::WhoamiResponse &me = res.value();
    std::size_t active_devices = 0;
    for (const auto &d : me.devices) {
      if (!d.revoked_at_ms.has_value())
        ++active_devices;
    }
    std::string out = "Online identity:\n";
    out += "  handle:         " + sanitize_inline(me.handle, 64) + "\n";
    out += "  account_id:     " + me.account_id.to_decimal() + "\n";
    if (opened.client->identity().has_value() &&
        opened.client->identity()->device_id.has_value()) {
      out += "  device_id:      " + opened.client->identity()->device_id->to_decimal() +
             "\n";
    }
    out +=
        "  root_pubkey:    sha256:" + format_pubkey_sha256_hex(me.root_pubkey) + "\n";
    if (const auto sn = mp::compute_safety_number(me.account_id, me.root_pubkey);
        sn.has_value()) {
      out += "  safety_number:  " + sn.value() + "\n";
    }
    out += "  active_devices: " + std::to_string(active_devices) + "/" +
           std::to_string(me.devices.size()) + "\n";
    const std::size_t shown_devs = std::min(me.devices.size(), kMaxListRows);
    for (std::size_t i = 0; i < shown_devs; ++i) {
      const auto &d = me.devices[i];
      out += "    device_id=" + d.device_id.to_decimal() +
             " label=" + sanitize_inline(d.label, 64) +
             " gen=" + std::to_string(d.generation) +
             " pop=" + (d.pop_verified ? "yes" : "no") +
             " cwt_exp_ms=" + std::to_string(d.cwt_expires_ms);
      if (d.revoked_at_ms.has_value())
        out += " [revoked]";
      out += '\n';
    }
    if (me.devices.size() > shown_devs) {
      out += "    ... (" + std::to_string(me.devices.size() - shown_devs) + " more)\n";
    }
    out += "  active_parties: " + std::to_string(me.active_party_ids.size());
    if (!me.active_party_ids.empty()) {
      out += " [";
      const std::size_t shown_parties =
          std::min(me.active_party_ids.size(), kMaxListRows);
      for (std::size_t i = 0; i < shown_parties; ++i) {
        if (i > 0)
          out += ", ";
        out += me.active_party_ids[i].to_decimal();
      }
      if (me.active_party_ids.size() > shown_parties)
        out += ", ...";
      out += "]";
    }
    out += '\n';
    return out;
  }

  if (cmd == "resolve") {
    const auto [handle_tok, extra] = split_first_token(rest);
    if (handle_tok.empty() || !extra.empty())
      return "Usage: /online resolve <handle>\n";
    const auto valid_handle = mp::AccountHandle::parse(handle_tok);
    if (!valid_handle.has_value()) {
      return "Invalid handle '" + sanitize_inline(handle_tok, 64) +
             "': " + format_mp_error_detail(valid_handle.error()) + "\n";
    }
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const auto resolved = opened.client->resolve_handle(handle_tok);
    if (!resolved.has_value()) {
      return "Online resolve failed (" + sanitize_inline(handle_tok, 64) +
             "): " + format_mp_error_detail(resolved.error()) + "\n";
    }
    const mp::ResolvedAccount &acc = resolved.value();
    std::string out = "Resolved online account:\n"
                      "  handle:      " +
                      sanitize_inline(acc.handle, 64) +
                      "\n"
                      "  account_id:  " +
                      acc.account_id.to_decimal() +
                      "\n"
                      "  root_pubkey: sha256:" +
                      format_pubkey_sha256_hex(acc.root_pubkey) + "\n";
    if (const auto sn = mp::compute_safety_number(acc.account_id, acc.root_pubkey);
        sn.has_value()) {
      out += "  safety_number: " + sn.value() + "\n";
    }
    return out;
  }

  if (cmd == "friends") {
    if (!rest.empty() && rest != "list")
      return "Usage: /online friends\n";
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const auto res = opened.client->list_friends();
    if (!res.has_value()) {
      return "Online friends failed: " + format_mp_error_detail(res.error()) + "\n";
    }
    const auto &edges = res.value();
    std::size_t friend_n = 0;
    std::size_t pending_received_n = 0;
    std::size_t pending_sent_n = 0;
    std::size_t blocked_n = 0;
    for (const auto &e : edges) {
      switch (e.state) {
      case mp::FriendEdgeState::friend_edge:
        ++friend_n;
        break;
      case mp::FriendEdgeState::invite_received:
        ++pending_received_n;
        break;
      case mp::FriendEdgeState::invite_sent:
        ++pending_sent_n;
        break;
      case mp::FriendEdgeState::blocked:
        ++blocked_n;
        break;
      }
    }
    const std::size_t pending_n = pending_received_n + pending_sent_n;
    std::string out = "Online friends (friends=" + std::to_string(friend_n) +
                      ", pending=" + std::to_string(pending_n) +
                      ", blocked=" + std::to_string(blocked_n) + "):\n";
    if (edges.empty()) {
      out += "  (none)\n";
      return out;
    }
    if (pending_received_n > 0) {
      out += "  Pending incoming requests: " + std::to_string(pending_received_n) +
             " (use /online friend accept <handle|account_id> or "
             "/online friend deny <handle|account_id>)\n";
    }
    std::vector<std::size_t> order;
    order.reserve(edges.size());
    for (std::size_t i = 0; i < edges.size(); ++i) {
      if (edges[i].state == mp::FriendEdgeState::invite_received)
        order.push_back(i);
    }
    for (std::size_t i = 0; i < edges.size(); ++i) {
      if (edges[i].state != mp::FriendEdgeState::invite_received)
        order.push_back(i);
    }
    const std::size_t shown = std::min(order.size(), kMaxListRows);
    for (std::size_t i = 0; i < shown; ++i) {
      const auto &e = edges[order[i]];
      out += "  account_id=" + e.peer_account_id.to_decimal() + " [" +
             std::string{friend_edge_state_name(e.state)} +
             "] updated_ms=" + std::to_string(e.updated_at_ms) + "\n";
    }
    if (order.size() > shown) {
      out += "  ... (" + std::to_string(order.size() - shown) + " more)\n";
    }
    return out;
  }

  if (cmd == "web-approve") {
    const auto [code_tok, extra] = split_first_token(rest);
    if (code_tok.empty() || !extra.empty())
      return "Usage: /online web-approve <XXXX-XXXX>\n";
    const auto normalized = mp::normalize_web_user_code(code_tok);
    if (!normalized.has_value()) {
      return "Invalid web-approve code '" + sanitize_inline(code_tok, 32) +
             "' (expected 8 Crockford Base32 chars XXXX-XXXX, no I/L/O/U)\n";
    }
    auto opened = open_authenticated_online_client(env);
    if (!opened.client.has_value())
      return opened.error_output;
    const auto approved = opened.client->approve_web_session(normalized.value());
    if (!approved.has_value()) {
      return "Online web-approve failed: " + format_mp_error_detail(approved.error()) +
             "\n";
    }
    std::string out = "Approved web session:\n";
    out += "  user_code:     " + normalized.value() + "\n";
    out += "  approved:      " +
           std::string{approved.value().approved ? "true" : "false"} + "\n";
    if (!approved.value().scope.empty()) {
      out += "  scope:         " + sanitize_inline(approved.value().scope, 64) + "\n";
    }
    if (approved.value().expires_at_ms.has_value()) {
      out +=
          "  expires_at_ms: " + std::to_string(*approved.value().expires_at_ms) + "\n";
    }
    return out;
  }

  if (cmd == "friend")
    return handle_online_friend(rest, env);

  if (cmd == "party")
    return handle_online_party(rest, env);

  return "Unknown /online subcommand '" + sanitize_inline(cmd, 48) +
         "'. Run `/online help` for usage.\n";
}

std::string handle_party(std::string_view args, const CommandPostTuiContext &ctx) {
  const auto root = resolve_project_root(ctx);
  const auto party_config_path = resolve_party_config_path(ctx);
  const auto platoon_dir = root / ".blackbird" / "platoon";
  const auto [sub, rest] = split_first_token(args);

  // /party online <args...> -> route cleanly to /online handler!
  if (sub == "online")
    return handle_online(rest);

  // /party close | /party hide
  if (sub == "close" || sub == "hide") {
    if (!rest.empty())
      return "Usage: /party close\n";
    return "Party Chat closed (Alt+P reopens in TUI).\n";
  }

  // /party peers (zero directory creation if absent)
  if (sub == "peers") {
    if (!rest.empty())
      return "Usage: /party peers\n";
    auto lobby = probe_party_lobby();
    if (lobby.state == PartyLobbyConnectState::invalid_env)
      return std::string{kInvalidPartySocketEnvMsg};
    if (lobby.client.has_value()) {
      return format_pinned_peers_list(read_lobby_friends_if_available(*lobby.client),
                                      false);
    }
    return format_pinned_peers_list(read_known_peers_if_present(), false);
  }

  // /party add [<alias> [role=leader|operator] [ssh=user@host]]
  if (sub == "add") {
    if (rest.empty()) {
      auto lobby = probe_party_lobby();
      if (lobby.state == PartyLobbyConnectState::invalid_env)
        return std::string{kInvalidPartySocketEnvMsg};
      if (lobby.client.has_value()) {
        return format_pinned_peers_list(read_lobby_friends_if_available(*lobby.client),
                                        true);
      }
      return format_pinned_peers_list(read_known_peers_if_present(), true);
    }
    const auto [alias_tok, opt_rest] = split_first_token(rest);
    if (!valid_party_alias(alias_tok)) {
      return "Invalid party alias: '" + sanitize_inline(alias_tok, 48) + "'\n";
    }
    PartyMemberRole role = PartyMemberRole::platoon_leader;
    std::string host{alias_tok};
    std::optional<std::string> explicit_ssh;
    std::string_view rem = opt_rest;
    while (!rem.empty()) {
      const auto [kv, next] = split_first_token(rem);
      const auto eq = kv.find('=');
      if (eq == std::string_view::npos || eq == 0 || eq + 1 >= kv.size()) {
        return "Usage: /party add <alias> [role=leader|operator] [ssh=user@host]\n";
      }
      const auto key = kv.substr(0, eq);
      const auto val = kv.substr(eq + 1);
      if (key == "role") {
        auto parsed_role = parse_party_member_role(val);
        if (!parsed_role.has_value()) {
          return "Invalid role '" + sanitize_inline(val, 32) +
                 "' (use leader or operator)\n";
        }
        role = parsed_role.value();
      } else if (key == "ssh") {
        if (val.empty() || val.starts_with('-') || val.size() > 256U) {
          return "Invalid ssh target: '" + sanitize_inline(val, 64) + "'\n";
        }
        for (const char ch : val) {
          const auto u = static_cast<unsigned char>(ch);
          if (u <= 0x20U || u >= 0x7fU) {
            return "Invalid ssh target: '" + sanitize_inline(val, 64) + "'\n";
          }
        }
        explicit_ssh = std::string{val};
      } else if (key == "host") {
        if (val.empty() || val.starts_with('-') || val.size() > 256U) {
          return "Invalid host: '" + sanitize_inline(val, 64) + "'\n";
        }
        for (const char ch : val) {
          const auto u = static_cast<unsigned char>(ch);
          if (u <= 0x20U || u >= 0x7fU) {
            return "Invalid host: '" + sanitize_inline(val, 64) + "'\n";
          }
        }
        host = std::string{val};
      } else {
        return "Usage: /party add <alias> [role=leader|operator] [ssh=user@host]\n";
      }
      rem = next;
    }

    auto lobby = probe_party_lobby();
    if (lobby.state == PartyLobbyConnectState::invalid_env)
      return std::string{kInvalidPartySocketEnvMsg};
    if (lobby.client.has_value()) {
      auto snap_res = lobby.client->snapshot();
      if (!snap_res.has_value()) {
        return "Party add failed (live lobby): " +
               std::string{error_name(snap_res.error().code)} + "\n";
      }
      const std::string &room = snap_res.value().room_scope;
      if (room.empty()) {
        return "Party add failed (live lobby): no active room (run `/party create "
               "[room]` first)\n";
      }
      auto invited = lobby.client->invite_friend(room, alias_tok);
      if (!invited.has_value()) {
        if (invited.error().code == ErrorCode::invalid_identity) {
          return "Party add failed (live lobby): peer @" +
                 sanitize_inline(alias_tok, 48) +
                 " is not pinned or is revoked (run `blackbird peer pin` first)\n";
        }
        return "Party add failed (live lobby): " +
               std::string{error_name(invited.error().code)} + "\n";
      }
      const PartyParticipant &p = invited.value();
      std::string out = "Added party participant @" + sanitize_inline(p.id, 48) + " [" +
                        std::string{party_member_role_name(p.role)} + "]";
      if (p.ssh_target.has_value() && !p.ssh_target->empty())
        out += " ssh=" + sanitize_inline(*p.ssh_target, 64);
      if (!p.fingerprint.empty())
        out += " pinned=" + sanitize_inline(p.fingerprint, 48);
      out += " in room " + sanitize_inline(room, 64) + " (live in-RAM lobby)\n";
      return out;
    }

    if (party_config_path.empty())
      return "Party add failed: HOME or BLACKBIRD_HOME is not set\n";

    PartyRosterPeerConfig entry{};
    entry.alias = std::string{alias_tok};
    entry.role = role;
    entry.host = host;
    entry.ssh_target =
        explicit_ssh.has_value() ? *explicit_ssh : (default_ssh_user() + "@" + host);
    // Leave provider/model empty so the remote node uses its own configured defaults.

    // Auto-fill pinned fingerprint from KnownPeersStore if already present (zero dir
    // creation if absent).
    const auto known_res = read_known_peers_if_present();
    if (known_res.store_present && !known_res.error.has_value()) {
      for (const auto &kp : known_res.peers) {
        if (!kp.revoked && party_eq_ci(kp.alias, alias_tok)) {
          entry.fingerprint = kp.fingerprint;
          break;
        }
      }
    }

    auto roster_res = load_or_default_party_roster(party_config_path);
    if (!roster_res.has_value()) {
      return "Party config unreadable: " +
             std::string{error_name(roster_res.error().code)} + "\n";
    }
    PartyRosterConfig cfg = std::move(roster_res).value();
    if (is_solo_party_scope(cfg.room_scope)) {
      cfg.room_scope = default_party_room_name(root);
      cfg.mode_override = PartyModeOverride::auto_detect;
    }
    bool updated = false;
    for (auto &existing : cfg.peers) {
      if (party_eq_ci(existing.alias, entry.alias)) {
        existing = entry;
        updated = true;
        break;
      }
    }
    if (!updated)
      cfg.peers.push_back(entry);

    auto saved = save_party_roster_config(party_config_path, cfg);
    if (!saved.has_value()) {
      return "Party add failed: " + std::string{error_name(saved.error().code)} + "\n";
    }
    std::string out = "Added party participant @" + sanitize_inline(entry.alias, 48) +
                      " [" + std::string{party_member_role_name(entry.role)} +
                      "] ssh=" + sanitize_inline(*entry.ssh_target, 64);
    if (entry.fingerprint.has_value())
      out += " pinned=" + sanitize_inline(*entry.fingerprint, 48);
    else
      out += " (unpinned)";
    out += " in room " + sanitize_inline(cfg.room_scope, 64) + "\n";
    return out;
  }

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

    auto lobby = probe_party_lobby();
    if (lobby.state == PartyLobbyConnectState::invalid_env)
      return std::string{kInvalidPartySocketEnvMsg};
    if (lobby.client.has_value()) {
      auto snap_res = lobby.client->snapshot();
      if (!snap_res.has_value()) {
        return "Party Chat unavailable (live lobby): " +
               std::string{error_name(snap_res.error().code)} + "\n";
      }
      PartyChatPane pane{std::move(snap_res).value()};
      pane.set_filter(filter);
      return pane.render(100, 24);
    }

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

    auto lobby = probe_party_lobby();
    if (lobby.state == PartyLobbyConnectState::invalid_env)
      return std::string{kInvalidPartySocketEnvMsg};
    if (lobby.client.has_value()) {
      auto snap_res = lobby.client->snapshot();
      if (!snap_res.has_value()) {
        return "Party Chat unavailable (live lobby): " +
               std::string{error_name(snap_res.error().code)} + "\n";
      }
      const PartySnapshot &snap = snap_res.value();
      if (snap.room_scope.empty()) {
        return "Party say failed (live lobby): no active room (run `/party create "
               "[room]` first)\n";
      }
      auto parsed_res = parse_party_input(rest, snap);
      if (!parsed_res.has_value())
        return "Usage: /party say [@all|@alias ...] <message>\n";
      const ParsedPartyInput &parsed = parsed_res.value();

      std::string sender_alias = safe_party_lobby_alias(ctx.actor);
      for (const auto &p : snap.participants) {
        if (p.local_self && valid_party_alias(p.id)) {
          sender_alias = p.id;
          break;
        }
      }
      auto seq_res =
          lobby.client->post_message(snap.room_scope, sender_alias, parsed.target_label,
                                     parsed.body, PartyMessageKind::chat);
      if (!seq_res.has_value()) {
        return "Party say failed (live lobby): " +
               std::string{error_name(seq_res.error().code)} + "\n";
      }

      std::string out = "Party posted #" + std::to_string(seq_res.value()) + " [" +
                        sanitize_inline(sender_alias, 48) + " -> " +
                        sanitize_inline(parsed.target_label, 64) + "]: " +
                        quote_untrusted_peer_text(parsed.body, kMaxPreviewBytes) + "\n";
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
    const std::string room =
        room_tok.empty() ? default_party_room_name(root) : std::string{room_tok};
    if (is_solo_party_scope(room))
      return "Invalid party room name: '" + sanitize_inline(room, 64) + "'\n";

    auto lobby = probe_party_lobby();
    if (lobby.state == PartyLobbyConnectState::invalid_env)
      return std::string{kInvalidPartySocketEnvMsg};
    if (lobby.client.has_value()) {
      if (!valid_party_room_id(room))
        return "Invalid party room name: '" + sanitize_inline(room, 64) + "'\n";
      auto id_probe = try_open_existing_local_identity();
      if (!id_probe.store.has_value())
        return "Party create failed (live lobby): " + id_probe.error_reason + "\n";
      auto signed_lease = sign_local_lobby_lease(
          *lobby.client, *id_probe.store, LocalLobbyLeaseParams{room, ctx.actor});
      if (!signed_lease.lease.has_value()) {
        return "Party create failed (live lobby): " + signed_lease.error_reason + "\n";
      }
      auto created = lobby.client->create_room(room, *signed_lease.lease);
      if (!created.has_value()) {
        return "Party create failed (live lobby): " +
               std::string{error_name(created.error().code)} + "\n";
      }
      return "Party room active: " + sanitize_inline(created.value().room_scope, 128) +
             " (live in-RAM lobby; Alt+P opens Party Chat)\n";
    }

    if (party_config_path.empty())
      return "Party create failed: HOME or BLACKBIRD_HOME is not set\n";
    auto roster_res = load_or_default_party_roster(party_config_path);
    if (!roster_res.has_value()) {
      return "Party config unreadable: " +
             std::string{error_name(roster_res.error().code)} + "\n";
    }
    PartyRosterConfig cfg = std::move(roster_res).value();
    cfg.room_scope = room;
    cfg.mode_override = PartyModeOverride::auto_detect;
    auto saved = save_party_roster_config(party_config_path, cfg);
    if (!saved.has_value()) {
      return "Party create failed: " + std::string{error_name(saved.error().code)} +
             "\n";
    }
    return "Party room active: " + sanitize_inline(cfg.room_scope, 128) +
           " (saved to " + sanitize_inline(party_config_path.filename().string(), 64) +
           "; Alt+P opens Party Chat)\n";
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

    auto lobby = probe_party_lobby();
    if (lobby.state == PartyLobbyConnectState::invalid_env)
      return std::string{kInvalidPartySocketEnvMsg};

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
      if (lobby.client.has_value() && !valid_party_room_id(invite.room_id)) {
        return "Party join failed (live lobby): invalid room name '" +
               sanitize_inline(invite.room_id, 64) + "'\n";
      }
      if (!lobby.client.has_value() && party_config_path.empty())
        return "Party join failed: HOME or BLACKBIRD_HOME is not set\n";
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

      if (lobby.client.has_value()) {
        auto id_probe = try_open_existing_local_identity();
        if (!id_probe.store.has_value())
          return "Party join failed (live lobby): " + id_probe.error_reason + "\n";
        auto signed_lease =
            sign_local_lobby_lease(*lobby.client, *id_probe.store,
                                   LocalLobbyLeaseParams{invite.room_id, ctx.actor});
        if (!signed_lease.lease.has_value()) {
          return "Party join failed (live lobby): " + signed_lease.error_reason + "\n";
        }
        auto joined = lobby.client->join_room(invite.room_id, *signed_lease.lease);
        if (!joined.has_value() && joined.error().code == ErrorCode::stale_handle) {
          joined = lobby.client->create_room(invite.room_id, *signed_lease.lease);
        }
        if (!joined.has_value()) {
          return "Party join failed (live lobby): " +
                 std::string{error_name(joined.error().code)} + "\n";
        }
        if (invite.creator_fingerprint != id_probe.store->identity().fingerprint)
          (void)lobby.client->invite_friend(invite.room_id, creator_alias);
        return "Joined party room '" + sanitize_inline(invite.room_id, 128) +
               "' (pinned creator @" + sanitize_inline(creator_alias, 48) + " [" +
               sanitize_inline(invite.creator_fingerprint, 64) + "] via " +
               sanitize_inline(invite.relay_url, 128) + "; live in-RAM lobby)\n";
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
    if (lobby.client.has_value()) {
      if (!valid_party_room_id(target))
        return "Invalid party room name: '" + sanitize_inline(target, 64) + "'\n";
      auto id_probe = try_open_existing_local_identity();
      if (!id_probe.store.has_value())
        return "Party join failed (live lobby): " + id_probe.error_reason + "\n";
      auto signed_lease =
          sign_local_lobby_lease(*lobby.client, *id_probe.store,
                                 LocalLobbyLeaseParams{std::string{target}, ctx.actor});
      if (!signed_lease.lease.has_value()) {
        return "Party join failed (live lobby): " + signed_lease.error_reason + "\n";
      }
      auto joined = lobby.client->join_room(target, *signed_lease.lease);
      if (!joined.has_value()) {
        if (joined.error().code == ErrorCode::stale_handle) {
          return "Party join failed (live lobby): room '" +
                 sanitize_inline(target, 128) +
                 "' not found (run `/party create` first)\n";
        }
        return "Party join failed (live lobby): " +
               std::string{error_name(joined.error().code)} + "\n";
      }
      return "Joined party room: " + sanitize_inline(joined.value().room_scope, 128) +
             " (live in-RAM lobby)\n";
    }
    if (party_config_path.empty())
      return "Party join failed: HOME or BLACKBIRD_HOME is not set\n";
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
           " (saved to " + sanitize_inline(party_config_path.filename().string(), 64) +
           ")\n";
  }

  // /party invite [relay_url]
  if (sub == "invite") {
    const auto [relay_tok, extra] = split_first_token(rest);
    if (!extra.empty())
      return "Usage: /party invite [relay_url]\n";

    std::string room_scope = default_party_room_name(root);
    bool got_live_room = false;
    auto lobby = probe_party_lobby();
    if (lobby.state == PartyLobbyConnectState::invalid_env)
      return std::string{kInvalidPartySocketEnvMsg};
    if (lobby.client.has_value()) {
      if (auto snap_res = lobby.client->snapshot();
          snap_res.has_value() && !snap_res.value().room_scope.empty()) {
        room_scope = snap_res.value().room_scope;
        got_live_room = true;
      }
    }
    if (!got_live_room) {
      auto roster_res = load_or_default_party_roster(party_config_path);
      if (!roster_res.has_value()) {
        return "Party config unreadable: " +
               std::string{error_name(roster_res.error().code)} + "\n";
      }
      if (!is_solo_party_scope(roster_res.value().room_scope) &&
          roster_res.value().room_scope != kPartyDefaultScope) {
        room_scope = roster_res.value().room_scope;
      } else if (!party_config_path.empty() &&
                 is_user_owned_regular_file(party_config_path) &&
                 !is_solo_party_scope(roster_res.value().room_scope)) {
        room_scope = roster_res.value().room_scope;
      }
    }

    auto id_probe = try_open_existing_local_identity();
    if (!id_probe.store.has_value())
      return "Party invite failed: " + id_probe.error_reason + "\n";

    const std::string local_host = default_local_hostname();
    const std::string ssh_hint = "ssh://" + default_ssh_user() + "@" + local_host;
    std::string relay_url;
    if (!relay_tok.empty()) {
      relay_url = std::string{relay_tok};
    } else if (const char *env_relay = std::getenv("BLACKBIRD_RELAY_URL");
               env_relay != nullptr && env_relay[0] != '\0') {
      relay_url = env_relay;
    } else {
      relay_url = "https://" + local_host + "/party";
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
    invite.creator_fingerprint = id_probe.store->identity().fingerprint;
    invite.creator_public_key = id_probe.store->identity().public_key;
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
           "  SSH:   " +
           sanitize_inline(ssh_hint, 128) +
           "\n"
           "  URI:   " +
           encoded.value() + "\n";
  }

  // /party leave
  if (sub == "leave") {
    if (!rest.empty())
      return "Usage: /party leave\n";

    auto lobby = probe_party_lobby();
    if (lobby.state == PartyLobbyConnectState::invalid_env)
      return std::string{kInvalidPartySocketEnvMsg};
    if (lobby.client.has_value()) {
      auto snap_res = lobby.client->snapshot();
      if (!snap_res.has_value()) {
        return "Party leave failed (live lobby): " +
               std::string{error_name(snap_res.error().code)} + "\n";
      }
      const PartySnapshot &snap = snap_res.value();
      if (snap.room_scope.empty()) {
        return "Left party (already in solo mode; history and pinned peers "
               "untouched).\n";
      }
      std::string local_fp;
      for (const auto &p : snap.participants) {
        if (p.local_self && !p.fingerprint.empty()) {
          local_fp = p.fingerprint;
          break;
        }
      }
      if (local_fp.empty()) {
        if (const auto loaded_fp = try_load_local_peer_fingerprint();
            loaded_fp.has_value()) {
          local_fp = *loaded_fp;
        }
      }
      if (local_fp.empty()) {
        return "Party leave failed (live lobby): local peer fingerprint unavailable\n";
      }
      auto left = lobby.client->leave_room(snap.room_scope, local_fp);
      if (!left.has_value()) {
        return "Party leave failed (live lobby): " +
               std::string{error_name(left.error().code)} + "\n";
      }
      return "Left party room '" + sanitize_inline(snap.room_scope, 64) +
             "' — returned to solo mode (live in-RAM lobby cleared; history and pinned "
             "peers preserved).\n";
    }

    if (party_config_path.empty())
      return "Left party (already in solo mode; history and pinned peers untouched).\n";
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(party_config_path, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        ec == std::errc::not_a_directory || (!ec && !std::filesystem::exists(st))) {
      return "Left party (already in solo mode; history and pinned peers untouched).\n";
    }
    if (ec || std::filesystem::is_symlink(st))
      return "Party leave failed: cannot access " +
             sanitize_inline(party_config_path.filename().string(), 64) + "\n";

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

    auto lobby = probe_party_lobby();
    if (lobby.state == PartyLobbyConnectState::invalid_env)
      return std::string{kInvalidPartySocketEnvMsg};
    if (lobby.client.has_value()) {
      auto snap_res = lobby.client->snapshot();
      if (!snap_res.has_value()) {
        return "Party remove failed (live lobby): " +
               std::string{error_name(snap_res.error().code)} + "\n";
      }
      if (snap_res.value().room_scope.empty()) {
        return "Party participant not found: @" + sanitize_inline(alias, 48) +
               " (solo mode)\n";
      }
      auto kicked = lobby.client->kick_member(snap_res.value().room_scope, alias);
      if (!kicked.has_value()) {
        if (kicked.error().code == ErrorCode::stale_handle) {
          return "Party participant not found: @" + sanitize_inline(alias, 48) + "\n";
        }
        return "Party remove failed (live lobby): " +
               std::string{error_name(kicked.error().code)} + "\n";
      }
      auto after = lobby.client->snapshot();
      const std::size_t rem_count =
          after.has_value() ? after.value().participants.size() : 0U;
      return "Removed party participant @" + sanitize_inline(alias, 48) +
             " (remaining participants: " + std::to_string(rem_count) + ")\n";
    }

    if (party_config_path.empty()) {
      return "Party participant not found: @" + sanitize_inline(alias, 48) +
             " (no party config)\n";
    }
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(party_config_path, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        ec == std::errc::not_a_directory || (!ec && !std::filesystem::exists(st))) {
      return "Party participant not found: @" + sanitize_inline(alias, 48) + " (no " +
             sanitize_inline(party_config_path.filename().string(), 64) + ")\n";
    }
    if (ec || std::filesystem::is_symlink(st))
      return "Party remove failed: cannot access " +
             sanitize_inline(party_config_path.filename().string(), 64) + "\n";
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
    if (cmd == "/online")
      return bound_output(handle_online(args));
  } catch (const Error &err) {
    return bound_output(std::string{cmd} + " error: " + error_name(err.code));
  } catch (const std::exception &) {
    return bound_output(std::string{cmd} + " error: unexpected internal error");
  }
  return std::nullopt;
}

} // namespace blackbird
