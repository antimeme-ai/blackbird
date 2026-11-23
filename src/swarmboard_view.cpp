#include "blackbird/swarmboard_view.hpp"

#include "blackbird/display_text.hpp"
#include "blackbird/json.hpp"
#include "blackbird/platoon_board.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <fcntl.h>
#include <map>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace blackbird {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kMaxPlatoonMessagesLoaded = 512;
constexpr std::size_t kMaxLeaseMetadataBytes = 64 * 1024;
constexpr std::size_t kMaxMessageTextBytes = 512;
constexpr std::size_t kMaxFieldBytes = 128;

enum class SanitizeMode : std::uint8_t {
  inline_text,
  quoted_peer,
};

std::int64_t wall_now_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  return ns <= 0 ? 1 : static_cast<std::int64_t>(ns);
}

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

// Detect Unicode bidi override / isolate controls that can spoof terminal rows
// (U+061C, U+200E..U+200F, U+202A..U+202E, U+2066..U+2069).
bool is_bidi_control_seq(std::string_view text, std::size_t i,
                         std::size_t seq_len) noexcept {
  if (seq_len == 2 && i + 1 < text.size()) {
    const auto b0 = static_cast<unsigned char>(text[i]);
    const auto b1 = static_cast<unsigned char>(text[i + 1]);
    return b0 == 0xd8U && b1 == 0x9cU; // U+061C ALM
  }
  if (seq_len == 3 && i + 2 < text.size()) {
    const auto b0 = static_cast<unsigned char>(text[i]);
    const auto b1 = static_cast<unsigned char>(text[i + 1]);
    const auto b2 = static_cast<unsigned char>(text[i + 2]);
    if (b0 == 0xe2U && b1 == 0x80U &&
        (b2 == 0x8eU || b2 == 0x8fU || (b2 >= 0xaaU && b2 <= 0xaeU))) {
      return true;
    }
    if (b0 == 0xe2U && b1 == 0x81U && (b2 >= 0xa6U && b2 <= 0xa9U)) {
      return true;
    }
  }
  return false;
}

std::string hex_escape_byte(unsigned char byte) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string esc = "\\x";
  esc += kHex[byte >> 4U];
  esc += kHex[byte & 0x0fU];
  return esc;
}

std::string sanitize_bytes(std::string_view text, std::size_t max_bytes,
                           SanitizeMode mode) {
  const bool escape_quotes = mode == SanitizeMode::quoted_peer;
  std::string out;
  out.reserve(std::min(text.size(), max_bytes) + (escape_quotes ? 2U : 0U));
  if (escape_quotes)
    out += '"';

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
      chunk = hex_escape_byte(b);
    } else if (is_utf8_c1) {
      const auto next = static_cast<unsigned char>(text[++i]);
      chunk = hex_escape_byte(b) + hex_escape_byte(next);
    } else {
      const std::size_t seq_len = valid_utf8_seq_len(text, i);
      if (seq_len == 0) {
        chunk = hex_escape_byte(b);
      } else if (is_bidi_control_seq(text, i, seq_len)) {
        for (std::size_t k = 0; k < seq_len; ++k)
          chunk += hex_escape_byte(static_cast<unsigned char>(text[i + k]));
        i += seq_len - 1;
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

bool is_real_directory(const fs::path &path) noexcept {
  if (path.empty())
    return false;
  std::error_code ec;
  const fs::file_status st = fs::symlink_status(path, ec);
  return !ec && !fs::is_symlink(st) && fs::is_directory(st);
}

bool is_real_regular_file(const fs::path &path) noexcept {
  if (path.empty())
    return false;
  std::error_code ec;
  const fs::file_status st = fs::symlink_status(path, ec);
  return !ec && !fs::is_symlink(st) && fs::is_regular_file(st);
}

struct LeaseMeta {
  std::string lease_id;
  std::string branch;
  std::string owner_id;
};

std::optional<std::string> read_regular_file_ro(const fs::path &path,
                                                std::size_t max_bytes) {
  int fd = -1;
  do {
    fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0)
    return std::nullopt;

  struct stat st{};
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    (void)::close(fd);
    return std::nullopt;
  }

  std::string content;
  std::array<char, 8192> buf{};
  for (;;) {
    const ssize_t n = ::read(fd, buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR)
        continue;
      (void)::close(fd);
      return std::nullopt;
    }
    if (n == 0)
      break;
    const auto got = static_cast<std::size_t>(n);
    if (got > max_bytes - content.size()) {
      (void)::close(fd);
      return std::nullopt;
    }
    content.append(buf.data(), got);
  }
  (void)::close(fd);
  return content;
}

std::optional<std::string> json_string_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return std::nullopt;
  const auto *s = std::get_if<std::string>(&field->value());
  if (!s)
    return std::nullopt;
  return *s;
}

std::optional<std::int64_t> json_int64_field(const Value &obj, std::string_view key) {
  const Value *field = obj.find(key);
  if (!field)
    return std::nullopt;
  const auto *num = std::get_if<Number>(&field->value());
  if (!num)
    return std::nullopt;
  const std::string digits = num->text();
  std::int64_t val = 0;
  const auto [ptr, ec] =
      std::from_chars(digits.data(), digits.data() + digits.size(), val);
  if (ec != std::errc{} || ptr != digits.data() + digits.size())
    return std::nullopt;
  return val;
}

// Pure read-only scan of `<leases_dir>/*.json` without creating lock files,
// spawning git subprocesses, or quarantining corrupt files.
std::vector<LeaseMeta> read_leases_readonly(const fs::path &leases_dir) {
  std::vector<LeaseMeta> result;
  std::error_code ec;
  fs::directory_iterator it{leases_dir, ec};
  if (ec)
    return result;

  for (const auto &entry : it) {
    const std::string name = entry.path().filename().string();
    if (name == "leases.lock" || name.starts_with(".tmp-") || !name.ends_with(".json"))
      continue;
    if (!is_real_regular_file(entry.path()))
      continue;
    auto raw = read_regular_file_ro(entry.path(), kMaxLeaseMetadataBytes);
    if (!raw.has_value())
      continue;
    auto parsed = parse_json(*raw);
    if (!parsed.has_value())
      continue;
    const Value &root = parsed.value();
    if (!std::holds_alternative<Value::Object>(root.value()))
      continue;
    const auto version = json_int64_field(root, "version");
    if (!version.has_value() || *version != 1)
      continue;
    auto lease_id = json_string_field(root, "lease_id");
    auto branch = json_string_field(root, "branch");
    auto owner_id = json_string_field(root, "owner_id");
    if (!lease_id.has_value() || !branch.has_value() || !owner_id.has_value())
      continue;
    result.push_back(
        LeaseMeta{std::move(*lease_id), std::move(*branch), std::move(*owner_id)});
  }
  std::sort(result.begin(), result.end(),
            [](const LeaseMeta &lhs, const LeaseMeta &rhs) {
              return lhs.lease_id < rhs.lease_id;
            });
  return result;
}

PeerRosterState map_platoon_state(PlatoonMemberState state) noexcept {
  switch (state) {
  case PlatoonMemberState::starting:
  case PlatoonMemberState::working:
    return PeerRosterState::working;
  case PlatoonMemberState::waiting:
    return PeerRosterState::waiting;
  case PlatoonMemberState::completed:
  case PlatoonMemberState::stopped:
    return PeerRosterState::stopped;
  case PlatoonMemberState::failed:
    return PeerRosterState::failed;
  }
  return PeerRosterState::waiting;
}

std::string derive_driver_label(const PlatoonMember &member) {
  if (!member.provider.empty() && !member.model.empty())
    return member.provider + "/" + member.model;
  if (!member.provider.empty())
    return member.provider;
  if (!member.model.empty())
    return member.model;
  return "blackbird";
}

void add_unique_tag(std::vector<std::string> &tags, std::string_view tag) {
  if (std::find(tags.begin(), tags.end(), tag) == tags.end())
    tags.emplace_back(tag);
}

bool contains_ci(std::string_view haystack, std::string_view needle) noexcept {
  if (needle.empty() || needle.size() > haystack.size())
    return false;
  auto lower_ascii = [](char ch) noexcept -> char {
    return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
  };
  for (std::size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
    bool match = true;
    for (std::size_t j = 0; j < needle.size(); ++j) {
      if (lower_ascii(haystack[i + j]) != lower_ascii(needle[j])) {
        match = false;
        break;
      }
    }
    if (match)
      return true;
  }
  return false;
}

std::string extract_event_text(const CausalEvent &event) {
  if (std::holds_alternative<Value::Object>(event.payload.value())) {
    for (const std::string_view key : {"text", "message", "note", "summary", "body"}) {
      if (auto s = json_string_field(event.payload, key); s.has_value())
        return *s;
    }
  }
  auto dumped = dump_json(event.payload);
  if (dumped.has_value())
    return std::move(dumped).value();
  return {};
}

bool has_tag(const SwarmboardMessageRow &row, std::string_view tag) noexcept {
  return std::find(row.tags.begin(), row.tags.end(), tag) != row.tags.end();
}

struct MentionQuery {
  std::string_view text;
  std::string_view target;
};

bool text_mentions_target(MentionQuery query) noexcept {
  if (query.target.empty())
    return false;
  const std::string needle = "@" + std::string{query.target};
  std::size_t pos = 0;
  while ((pos = query.text.find(needle, pos)) != std::string_view::npos) {
    const bool start_ok = pos == 0 || query.text[pos - 1] == ' ' ||
                          query.text[pos - 1] == '\t' || query.text[pos - 1] == '"' ||
                          query.text[pos - 1] == '(' || query.text[pos - 1] == '[';
    const std::size_t after = pos + needle.size();
    const bool end_ok = after >= query.text.size() ||
                        !((query.text[after] >= 'a' && query.text[after] <= 'z') ||
                          (query.text[after] >= 'A' && query.text[after] <= 'Z') ||
                          (query.text[after] >= '0' && query.text[after] <= '9') ||
                          query.text[after] == '_' || query.text[after] == '-' ||
                          query.text[after] == ':' || query.text[after] == '.');
    if (start_ok && end_ok)
      return true;
    pos += 1;
  }
  return false;
}

bool message_matches_mentions(const SwarmboardMessageRow &row,
                              const SwarmboardSnapshot &snapshot) {
  const bool has_local_id =
      snapshot.local_actor_id.has_value() && !snapshot.local_actor_id->empty();
  const bool has_local_fp =
      snapshot.local_actor_fp.has_value() && !snapshot.local_actor_fp->empty();

  if (text_mentions_target({row.text, "all"}))
    return true;
  if (has_local_id) {
    if (row.to == *snapshot.local_actor_id ||
        text_mentions_target({row.text, *snapshot.local_actor_id})) {
      return true;
    }
  }
  if (has_local_fp) {
    if (row.to == *snapshot.local_actor_fp ||
        text_mentions_target({row.text, *snapshot.local_actor_fp})) {
      return true;
    }
  }
  if (!has_local_id) {
    if (row.source == SwarmboardMessageSource::platoon) {
      if ((!row.to.empty() && row.to != "all") ||
          row.text.find('@') != std::string::npos)
        return true;
    } else if (!has_local_fp) {
      if ((!row.to.empty() && row.to != "all") ||
          row.text.find('@') != std::string::npos)
        return true;
    }
  }
  return false;
}

// Clip a sanitized UTF-8 string cleanly to at most `max_cols` terminal cells
// without ever splitting a UTF-8 grapheme cluster.
std::string clip_cells(std::string_view sanitized, std::size_t max_cols) {
  if (max_cols == 0)
    return {};
  if (display_cells(sanitized).value <= max_cols)
    return std::string{sanitized};

  const bool use_ellipsis = max_cols >= 4;
  const std::size_t budget = use_ellipsis ? (max_cols - 3) : max_cols;
  std::string out;
  out.reserve(std::min(sanitized.size(), max_cols + 4));
  std::size_t used = 0;
  DisplayCursor cursor{sanitized};
  DisplayCluster cluster;
  while (cursor.next(cluster)) {
    if (used + cluster.cells.value > budget)
      break;
    cursor.append(out, cluster);
    used += cluster.cells.value;
  }
  if (use_ellipsis)
    out += "...";
  return out;
}

std::string pad_or_clip_cell(std::string_view sanitized, std::size_t col_width) {
  std::string clipped = clip_cells(sanitized, col_width);
  const std::size_t used = display_cells(clipped).value;
  if (used < col_width)
    clipped.append(col_width - used, ' ');
  return clipped;
}

std::string short_actor_display(std::string_view actor, std::size_t max_len) {
  std::string clean = swarmboard_sanitize_inline(actor, kMaxFieldBytes);
  if (clean.size() <= max_len)
    return clean;
  return clip_cells(clean, max_len);
}

struct RosterColumns {
  std::size_t peer = 14;
  std::size_t role = 10;
  std::size_t driver = 15;
  std::size_t owner = 11;
  std::size_t state = 8;
  std::size_t seq_lease = 17;
};

RosterColumns compute_roster_columns(std::size_t width) noexcept {
  constexpr std::size_t kSeparators = 5;
  if (width <= kSeparators + 6)
    return {1, 1, 1, 1, 1, 1};
  const std::size_t avail = width - kSeparators;
  RosterColumns cols{};
  cols.peer = std::max<std::size_t>(4, (avail * 18) / 100);
  cols.role = std::max<std::size_t>(4, (avail * 13) / 100);
  cols.driver = std::max<std::size_t>(6, (avail * 20) / 100);
  cols.owner = std::max<std::size_t>(5, (avail * 15) / 100);
  cols.state = std::max<std::size_t>(5, std::min<std::size_t>(10, (avail * 11) / 100));
  const std::size_t used =
      cols.peer + cols.role + cols.driver + cols.owner + cols.state;
  if (used >= avail) {
    cols.seq_lease = 1;
  } else {
    cols.seq_lease = avail - used;
  }
  return cols;
}

std::string format_roster_line(const RosterColumns &cols,
                               const std::array<std::string_view, 6> &cells,
                               std::size_t width) {
  std::string line;
  line.reserve(width + 16);
  line += pad_or_clip_cell(cells[0], cols.peer);
  line += ' ';
  line += pad_or_clip_cell(cells[1], cols.role);
  line += ' ';
  line += pad_or_clip_cell(cells[2], cols.driver);
  line += ' ';
  line += pad_or_clip_cell(cells[3], cols.owner);
  line += ' ';
  line += pad_or_clip_cell(cells[4], cols.state);
  line += ' ';
  line += pad_or_clip_cell(cells[5], cols.seq_lease);
  return clip_cells(line, width);
}

std::string format_divider(std::string_view title, std::size_t width) {
  if (width == 0)
    return {};
  if (title.empty())
    return std::string(width, '-');
  std::string line = "-- " + swarmboard_sanitize_inline(title, width) + " ";
  const std::size_t used = display_cells(line).value;
  if (used < width)
    line.append(width - used, '-');
  return clip_cells(line, width);
}

std::string format_message_row_line(const SwarmboardMessageRow &row,
                                    std::size_t width) {
  std::string id_str = swarmboard_sanitize_inline(row.seq_or_hash, 64);
  if (row.source == SwarmboardMessageSource::bridge && id_str.size() > 10)
    id_str = id_str.substr(0, 10);

  const std::string src_str = std::string{swarmboard_message_source_name(row.source)};
  const std::string kind_str = swarmboard_sanitize_inline(row.kind, 32);
  const std::string from_str = short_actor_display(row.from, 18);
  const std::string to_str =
      row.to.empty() ? std::string{"all"} : short_actor_display(row.to, 18);

  std::string line;
  line.reserve(width + 64);
  line += id_str;
  line += " [";
  line += src_str;
  if (!kind_str.empty()) {
    line += '/';
    line += kind_str;
  }
  line += "] ";
  line += from_str;
  line += " -> ";
  line += to_str;
  for (const auto &tag : row.tags) {
    line += ' ';
    line += swarmboard_sanitize_inline(tag, 32);
  }
  line += ' ';
  line += swarmboard_quote_untrusted(row.text, kMaxMessageTextBytes);
  return clip_cells(line, width);
}

std::string format_watcher_row_line(const WatcherRow &watcher, std::size_t width) {
  const std::string name = swarmboard_sanitize_inline(watcher.display_name, 32);
  const std::string actor = short_actor_display(watcher.actor_id, 24);
  const std::string scope = swarmboard_sanitize_inline(watcher.watching_scope, 48);
  const std::string status = swarmboard_sanitize_inline(watcher.status, 32);

  std::string line = "[watcher] " + (name.empty() ? actor : name);
  if (!name.empty() && !actor.empty() && name != actor)
    line += " (" + actor + ")";
  line += " scope=" + (scope.empty() ? std::string{"*"} : scope);
  line += " status=" + (status.empty() ? std::string{"active"} : status);
  return clip_cells(line, width);
}

std::string format_conflict_summary_line(const ConcurrentClaimConflict &conflict,
                                         std::size_t width) {
  std::string line =
      "[conflict] scope=" + swarmboard_sanitize_inline(conflict.resource_scope, 48) +
      " " + short_actor_display(conflict.first_actor_id, 18) + "(" +
      swarmboard_sanitize_inline(conflict.first_event_hash, 10) + ") vs " +
      short_actor_display(conflict.second_actor_id, 18) + "(" +
      swarmboard_sanitize_inline(conflict.second_event_hash, 10) + ")";
  return clip_cells(line, width);
}

} // namespace

std::string_view peer_roster_state_name(PeerRosterState state) noexcept {
  switch (state) {
  case PeerRosterState::working:
    return "working";
  case PeerRosterState::waiting:
    return "waiting";
  case PeerRosterState::stopped:
    return "stopped";
  case PeerRosterState::failed:
    return "failed";
  }
  return "waiting";
}

std::string_view
swarmboard_message_source_name(SwarmboardMessageSource source) noexcept {
  switch (source) {
  case SwarmboardMessageSource::platoon:
    return "platoon";
  case SwarmboardMessageSource::bridge:
    return "bridge";
  }
  return "platoon";
}

std::string_view swarmboard_filter_name(SwarmboardFilter filter) noexcept {
  switch (filter) {
  case SwarmboardFilter::all:
    return "all";
  case SwarmboardFilter::mentions:
    return "mentions";
  case SwarmboardFilter::conflicts:
    return "conflicts";
  case SwarmboardFilter::watchers:
    return "watchers";
  }
  return "all";
}

SwarmboardConfig SwarmboardConfig::for_project(const fs::path &project_root) {
  SwarmboardConfig cfg;
  cfg.platoon_dir = project_root / ".blackbird" / "platoon";
  cfg.leases_dir = project_root / ".blackbird" / "worktrees" / ".leases";
  cfg.bridge_dir = project_root / ".blackbird" / "bridge";
  if (!project_root.filename().empty())
    cfg.room_label = project_root.filename().string();
  return cfg;
}

std::size_t SwarmboardSnapshot::working_peers() const noexcept {
  std::size_t count = 0;
  for (const auto &row : roster) {
    if (row.state == PeerRosterState::working)
      ++count;
  }
  return count;
}

std::size_t SwarmboardSnapshot::waiting_peers() const noexcept {
  std::size_t count = 0;
  for (const auto &row : roster) {
    if (row.state == PeerRosterState::waiting)
      ++count;
  }
  return count;
}

std::size_t SwarmboardSnapshot::stopped_peers() const noexcept {
  std::size_t count = 0;
  for (const auto &row : roster) {
    if (row.state == PeerRosterState::stopped)
      ++count;
  }
  return count;
}

std::size_t SwarmboardSnapshot::failed_peers() const noexcept {
  std::size_t count = 0;
  for (const auto &row : roster) {
    if (row.state == PeerRosterState::failed)
      ++count;
  }
  return count;
}

std::string swarmboard_sanitize_inline(std::string_view text, std::size_t max_bytes) {
  return sanitize_bytes(text, max_bytes, SanitizeMode::inline_text);
}

std::string swarmboard_quote_untrusted(std::string_view text, std::size_t max_bytes) {
  return sanitize_bytes(text, max_bytes, SanitizeMode::quoted_peer);
}

Result<SwarmboardSnapshot> load_swarmboard_snapshot(const SwarmboardConfig &config) {
  try {
    SwarmboardSnapshot snapshot{};
    snapshot.room_label =
        !config.room_label.empty()
            ? swarmboard_sanitize_inline(config.room_label, 48)
            : (!config.scope.empty() ? swarmboard_sanitize_inline(config.scope, 48)
                                     : std::string{"swarmboard"});
    snapshot.scope = config.scope;
    snapshot.local_actor_fp = config.local_actor_fp;
    snapshot.local_actor_id = config.local_actor_id;

    // 1. Read worktree lease metadata purely read-only from `<leases_dir>/*.json`.
    std::unordered_map<std::string, LeaseMeta> lease_by_owner;
    std::unordered_map<std::string, LeaseMeta> lease_by_id;
    if (is_real_directory(config.leases_dir)) {
      snapshot.leases_present = true;
      auto leases = read_leases_readonly(config.leases_dir);
      for (const auto &lease : leases) {
        if (!lease.owner_id.empty())
          lease_by_owner.try_emplace(lease.owner_id, lease);
        if (!lease.lease_id.empty())
          lease_by_id.try_emplace(lease.lease_id, lease);
      }
    }

    // 2. Load PlatoonBoard members and board messages without creating any files.
    std::unordered_map<std::string, std::uint64_t> last_seq_by_peer;
    if (is_real_directory(config.platoon_dir)) {
      snapshot.platoon_present = true;
      const bool has_roster = is_real_regular_file(config.platoon_dir / "roster.json");
      const bool has_board = is_real_regular_file(config.platoon_dir / "board.jsonl");
      if (has_roster || has_board) {
        auto board_res = PlatoonBoard::open(config.platoon_dir);
        if (!board_res.has_value())
          return Result<SwarmboardSnapshot>::failure(board_res.error());
        const PlatoonBoard &board = board_res.value();

        if (has_board) {
          auto latest_res = board.latest_seq();
          if (!latest_res.has_value())
            return Result<SwarmboardSnapshot>::failure(latest_res.error());
          const std::uint64_t head = latest_res.value();
          const std::uint64_t after =
              head > kMaxPlatoonMessagesLoaded ? (head - kMaxPlatoonMessagesLoaded) : 0;
          PlatoonReadQuery rq;
          rq.after_seq = after;
          rq.limit = kMaxPlatoonMessagesLoaded;
          auto msgs_res = board.read(rq);
          if (!msgs_res.has_value())
            return Result<SwarmboardSnapshot>::failure(msgs_res.error());

          for (const auto &msg : msgs_res.value()) {
            auto &peer_seq = last_seq_by_peer[msg.from];
            if (msg.seq > peer_seq)
              peer_seq = msg.seq;

            SwarmboardMessageRow row{};
            row.source = SwarmboardMessageSource::platoon;
            row.seq_or_hash = "#" + std::to_string(msg.seq);
            row.from = msg.from;
            row.to = msg.to;
            row.kind = std::string{platoon_message_kind_name(msg.kind)};
            row.timestamp_ns = msg.timestamp_ns;
            row.text = swarmboard_sanitize_inline(msg.text, kMaxMessageTextBytes);

            if (contains_ci(msg.text, "[done]"))
              add_unique_tag(row.tags, "[done]");
            if (msg.kind == PlatoonMessageKind::blocker ||
                contains_ci(msg.text, "[blocked]")) {
              add_unique_tag(row.tags, "[blocked]");
            }
            if (contains_ci(msg.text, "[conflict]"))
              add_unique_tag(row.tags, "[conflict]");

            snapshot.messages.push_back(std::move(row));
          }
        }

        if (has_roster) {
          auto members_res = board.members();
          if (!members_res.has_value())
            return Result<SwarmboardSnapshot>::failure(members_res.error());
          snapshot.roster.reserve(members_res.value().size());
          for (const auto &m : members_res.value()) {
            PeerRosterRow row{};
            row.peer_id = m.id;
            row.role = m.role;
            row.driver = derive_driver_label(m);
            row.owner_actor =
                (config.local_actor_fp.has_value() && !config.local_actor_fp->empty())
                    ? *config.local_actor_fp
                    : std::string{"local"};
            row.state = map_platoon_state(m.state);
            if (const auto seq_it = last_seq_by_peer.find(m.id);
                seq_it != last_seq_by_peer.end()) {
              row.last_seq = seq_it->second;
            }
            row.lease_branch = m.branch;
            if (const auto lit = lease_by_owner.find(m.id);
                lit != lease_by_owner.end()) {
              if (row.lease_branch.empty())
                row.lease_branch = lit->second.branch;
            } else if (const auto id_it = lease_by_id.find(m.id);
                       id_it != lease_by_id.end()) {
              if (row.lease_branch.empty())
                row.lease_branch = id_it->second.branch;
              if (!id_it->second.owner_id.empty() && id_it->second.owner_id != m.id)
                row.owner_actor = id_it->second.owner_id;
            }
            row.updated_ns = m.updated_ns;
            snapshot.roster.push_back(std::move(row));
          }
        }
      }
    }

    // 3. Load BoardBridge events, receipts, active watchers, conflicts, and
    // read-only action guard without creating any files or advancing receipts.
    if (is_real_directory(config.bridge_dir)) {
      snapshot.bridge_present = true;
      const bool has_log = is_real_regular_file(config.bridge_dir / "bridge.jsonl");
      if (has_log) {
        auto bridge_res = BoardBridge::open(config.bridge_dir);
        if (!bridge_res.has_value())
          return Result<SwarmboardSnapshot>::failure(bridge_res.error());
        const BoardBridge &bridge = bridge_res.value();

        auto events_res = bridge.events();
        if (!events_res.has_value())
          return Result<SwarmboardSnapshot>::failure(events_res.error());
        const auto &events = events_res.value();

        auto receipts_res = bridge.receipts();
        if (!receipts_res.has_value())
          return Result<SwarmboardSnapshot>::failure(receipts_res.error());
        const auto &receipts = receipts_res.value();

        auto envelopes_res = bridge.envelopes();
        if (!envelopes_res.has_value())
          return Result<SwarmboardSnapshot>::failure(envelopes_res.error());

        // Map embedded causal_event_hash -> envelope recipient when available.
        std::unordered_map<std::string, std::string> envelope_to_by_event;
        for (const auto &env : envelopes_res.value()) {
          if (!std::holds_alternative<Value::Object>(env.payload.value()))
            continue;
          const Value *ce = env.payload.find("causal_event");
          if (!ce || !std::holds_alternative<Value::Object>(ce->value()))
            continue;
          if (auto hash = json_string_field(*ce, "event_hash"); hash.has_value())
            envelope_to_by_event.try_emplace(std::move(*hash), env.to_fingerprint);
        }

        const std::string_view scope_filter =
            config.scope == "*" ? std::string_view{} : std::string_view{config.scope};

        // Concurrent claims via BoardBridge's pure detect_concurrent_claims().
        auto conflicts_res = detect_concurrent_claims(events, scope_filter);
        if (!conflicts_res.has_value())
          return Result<SwarmboardSnapshot>::failure(conflicts_res.error());
        snapshot.concurrent_conflicts = std::move(conflicts_res).value();

        std::unordered_set<std::string> conflict_hashes;
        for (const auto &c : snapshot.concurrent_conflicts) {
          conflict_hashes.insert(c.first_event_hash);
          conflict_hashes.insert(c.second_event_hash);
        }

        // Read-only active watchers via BoardBridge::active_watchers(scope, now_ns).
        const std::int64_t effective_now =
            config.now_ns > 0 ? config.now_ns : wall_now_ns();
        auto watchers_res = bridge.active_watchers(scope_filter, effective_now);
        if (!watchers_res.has_value())
          return Result<SwarmboardSnapshot>::failure(watchers_res.error());
        snapshot.watchers.reserve(watchers_res.value().size());
        for (const auto &w : watchers_res.value()) {
          snapshot.watchers.push_back(WatcherRow{
              w.display_name,
              w.actor_id,
              w.watching_scope,
              w.status,
          });
        }

        // Read-only action guard via BoardBridge::check_action_guard().
        std::unordered_set<std::string> blocking_hashes;
        if (config.local_actor_fp.has_value() &&
            valid_peer_fingerprint(*config.local_actor_fp)) {
          const std::string_view guard_scope = config.scope.empty()
                                                   ? std::string_view{"*"}
                                                   : std::string_view{config.scope};
          auto verdict_res =
              bridge.check_action_guard(*config.local_actor_fp, guard_scope);
          if (!verdict_res.has_value())
            return Result<SwarmboardSnapshot>::failure(verdict_res.error());
          snapshot.guard_verdict = std::move(verdict_res).value();
          snapshot.guard_checked = true;
          for (const auto &h : snapshot.guard_verdict.blocking_event_hashes)
            blocking_hashes.insert(h);
        }

        // Index receipts by event_hash without mutating any receipt stage.
        std::unordered_map<std::string, std::vector<ReceiptStage>> stages_by_event;
        for (const auto &rcpt : receipts)
          stages_by_event[rcpt.event_hash].push_back(rcpt.stage);

        for (const auto &ev : events) {
          SwarmboardMessageRow row{};
          row.source = SwarmboardMessageSource::bridge;
          row.seq_or_hash = ev.event_hash;
          row.from = ev.actor_id;
          row.kind = ev.kind;
          row.resource_scope = ev.resource_scope;
          row.timestamp_ns = ev.timestamp_ns;

          if (std::holds_alternative<Value::Object>(ev.payload.value())) {
            if (auto to_val = json_string_field(ev.payload, "to"); to_val.has_value())
              row.to = std::move(*to_val);
          }
          if (row.to.empty()) {
            if (const auto eit = envelope_to_by_event.find(ev.event_hash);
                eit != envelope_to_by_event.end()) {
              row.to = eit->second;
            } else if (!ev.resource_scope.empty()) {
              row.to = ev.resource_scope;
            } else {
              row.to = "all";
            }
          }

          const std::string raw_text = extract_event_text(ev);
          row.text = swarmboard_sanitize_inline(raw_text, kMaxMessageTextBytes);

          if (ev.kind == "done" || ev.kind == "complete" ||
              contains_ci(raw_text, "[done]")) {
            add_unique_tag(row.tags, "[done]");
          }
          if (blocking_hashes.contains(ev.event_hash) || ev.kind == "blocker" ||
              contains_ci(raw_text, "[blocked]")) {
            add_unique_tag(row.tags, "[blocked]");
          }
          if (conflict_hashes.contains(ev.event_hash) ||
              contains_ci(raw_text, "[conflict]")) {
            add_unique_tag(row.tags, "[conflict]");
          }
          if (const auto sit = stages_by_event.find(ev.event_hash);
              sit != stages_by_event.end()) {
            bool has_included = false;
            bool has_acted = false;
            for (const ReceiptStage stage : sit->second) {
              if (receipt_stage_is_cognitive_inclusion(stage))
                has_included = true;
              if (stage == ReceiptStage::acted)
                has_acted = true;
            }
            if (has_included)
              add_unique_tag(row.tags, "[receipt:included]");
            if (has_acted)
              add_unique_tag(row.tags, "[receipt:acted]");
          }

          snapshot.messages.push_back(std::move(row));
        }
      }
    }

    // Stable chronological ordering across merged platoon + bridge messages.
    std::stable_sort(
        snapshot.messages.begin(), snapshot.messages.end(),
        [](const SwarmboardMessageRow &lhs, const SwarmboardMessageRow &rhs) {
          if (lhs.timestamp_ns != rhs.timestamp_ns)
            return lhs.timestamp_ns < rhs.timestamp_ns;
          if (lhs.source != rhs.source)
            return static_cast<int>(lhs.source) < static_cast<int>(rhs.source);
          return lhs.seq_or_hash < rhs.seq_or_hash;
        });

    return Result<SwarmboardSnapshot>::success(std::move(snapshot));
  } catch (const std::bad_alloc &) {
    return Result<SwarmboardSnapshot>::failure({ErrorCode::allocation});
  }
}

SwarmboardView::SwarmboardView(SwarmboardSnapshot snapshot)
    : snapshot_(std::move(snapshot)) {}

Result<void> SwarmboardView::reload(const SwarmboardConfig &config) {
  auto loaded = load_swarmboard_snapshot(config);
  if (!loaded.has_value())
    return Result<void>::failure(loaded.error());
  snapshot_ = std::move(loaded).value();
  clamp_scroll();
  return Result<void>::success();
}

void SwarmboardView::update(SwarmboardSnapshot snapshot) {
  snapshot_ = std::move(snapshot);
  clamp_scroll();
}

void SwarmboardView::set_filter(SwarmboardFilter filter) noexcept {
  filter_ = filter;
  scroll_offset_ = 0;
}

void SwarmboardView::scroll_up(std::size_t lines) noexcept {
  if (lines >= scroll_offset_)
    scroll_offset_ = 0;
  else
    scroll_offset_ -= lines;
}

void SwarmboardView::scroll_down(std::size_t lines) noexcept {
  const std::size_t count = lower_item_count();
  if (count <= 1) {
    scroll_offset_ = 0;
    return;
  }
  const std::size_t max_offset = count - 1;
  if (lines >= max_offset - scroll_offset_)
    scroll_offset_ = max_offset;
  else
    scroll_offset_ += lines;
}

void SwarmboardView::page_up(std::size_t page_lines) noexcept {
  scroll_up(std::max<std::size_t>(1, page_lines));
}

void SwarmboardView::page_down(std::size_t page_lines) noexcept {
  scroll_down(std::max<std::size_t>(1, page_lines));
}

void SwarmboardView::scroll_to_bottom() noexcept {
  const std::size_t count = lower_item_count();
  scroll_offset_ = count > 0 ? (count - 1) : 0;
}

std::vector<SwarmboardMessageRow> SwarmboardView::filtered_messages() const {
  std::vector<SwarmboardMessageRow> out;
  if (filter_ == SwarmboardFilter::watchers)
    return out;
  out.reserve(snapshot_.messages.size());
  for (const auto &msg : snapshot_.messages) {
    if (filter_ == SwarmboardFilter::all) {
      out.push_back(msg);
    } else if (filter_ == SwarmboardFilter::mentions) {
      if (message_matches_mentions(msg, snapshot_))
        out.push_back(msg);
    } else if (filter_ == SwarmboardFilter::conflicts) {
      if (has_tag(msg, "[conflict]") || has_tag(msg, "[blocked]"))
        out.push_back(msg);
    }
  }
  return out;
}

std::size_t SwarmboardView::lower_item_count() const noexcept {
  if (filter_ == SwarmboardFilter::watchers)
    return snapshot_.watchers.size();
  if (filter_ == SwarmboardFilter::all)
    return snapshot_.messages.size();
  std::size_t count = 0;
  for (const auto &msg : snapshot_.messages) {
    if (filter_ == SwarmboardFilter::mentions) {
      if (message_matches_mentions(msg, snapshot_))
        ++count;
    } else if (filter_ == SwarmboardFilter::conflicts) {
      if (has_tag(msg, "[conflict]") || has_tag(msg, "[blocked]"))
        ++count;
    }
  }
  if (filter_ == SwarmboardFilter::conflicts && count == 0)
    return snapshot_.concurrent_conflicts.size();
  return count;
}

void SwarmboardView::clamp_scroll() noexcept {
  const std::size_t count = lower_item_count();
  if (count == 0) {
    scroll_offset_ = 0;
  } else if (scroll_offset_ >= count) {
    scroll_offset_ = count - 1;
  }
}

std::vector<std::string>
SwarmboardView::render_lines(SwarmboardWidth width_arg,
                             SwarmboardHeight height_arg) const {
  const std::size_t width = width_arg.value;
  const std::size_t height = height_arg.value;
  std::vector<std::string> lines;
  if (width == 0 || height == 0)
    return lines;
  lines.reserve(height);

  // --- Top Header Bar ---
  const std::string room = snapshot_.room_label.empty()
                               ? std::string{"swarmboard"}
                               : swarmboard_sanitize_inline(snapshot_.room_label, 32);
  const std::string guard_badge =
      snapshot_.guard_verdict.allowed
          ? std::string{"GUARD: CLEAR"}
          : ("GUARD: BLOCKED(" +
             std::to_string(snapshot_.guard_verdict.blocking_event_hashes.size()) +
             ")");
  const std::string header1 =
      "SWARMBOARD " + room +
      " | Watchers: " + std::to_string(snapshot_.watchers.size()) + " | " +
      guard_badge + " | Conflicts: " + std::to_string(snapshot_.conflict_count());
  lines.push_back(clip_cells(header1, width));
  if (lines.size() == height)
    return lines;

  if (height >= 7) {
    const std::string header2 =
        "Peers: " + std::to_string(snapshot_.roster.size()) +
        " (working=" + std::to_string(snapshot_.working_peers()) +
        " waiting=" + std::to_string(snapshot_.waiting_peers()) +
        " stopped=" + std::to_string(snapshot_.stopped_peers()) +
        " failed=" + std::to_string(snapshot_.failed_peers()) +
        ") | Filter: " + std::string{swarmboard_filter_name(filter_)};
    lines.push_back(clip_cells(header2, width));
    if (lines.size() == height)
      return lines;
  }

  // --- Upper Pane: Peer Roster Strip ---
  const RosterColumns cols = compute_roster_columns(width);
  lines.push_back(format_roster_line(
      cols, {"PEER", "ROLE", "DRIVER", "OWNER", "STATE", "SEQ/LEASE"}, width));
  if (lines.size() == height)
    return lines;

  const bool has_footer = height >= 10;
  const std::size_t reserved_below =
      has_footer ? 3U : 2U; // divider + >=1 lower + footer
  const std::size_t remaining_after_header =
      height > lines.size() ? (height - lines.size()) : 0;
  const std::size_t max_roster_budget =
      remaining_after_header > reserved_below
          ? std::min<std::size_t>(
                8U, std::max<std::size_t>(
                        1U, (remaining_after_header - reserved_below) / 3U + 1U))
          : 0U;

  if (max_roster_budget > 0) {
    if (snapshot_.roster.empty()) {
      lines.push_back(clip_cells("(no peers registered)", width));
    } else {
      const bool overflow = snapshot_.roster.size() > max_roster_budget;
      const std::size_t rows_to_draw =
          overflow ? (max_roster_budget - 1) : snapshot_.roster.size();
      for (std::size_t i = 0; i < rows_to_draw; ++i) {
        const auto &peer = snapshot_.roster[i];
        const std::string peer_id = swarmboard_sanitize_inline(peer.peer_id, 48);
        const std::string role = peer.role.empty()
                                     ? std::string{"-"}
                                     : swarmboard_sanitize_inline(peer.role, 32);
        const std::string driver = peer.driver.empty()
                                       ? std::string{"blackbird"}
                                       : swarmboard_sanitize_inline(peer.driver, 48);
        const std::string owner =
            peer.owner_actor.empty() ? std::string{"local"}
                                     : swarmboard_sanitize_inline(peer.owner_actor, 32);
        const std::string_view state = peer_roster_state_name(peer.state);
        std::string seq_lease = "#" + std::to_string(peer.last_seq);
        if (!peer.lease_branch.empty())
          seq_lease += "/" + swarmboard_sanitize_inline(peer.lease_branch, 48);
        lines.push_back(format_roster_line(
            cols, {peer_id, role, driver, owner, state, seq_lease}, width));
      }
      if (overflow) {
        lines.push_back(clip_cells(
            "... (+" + std::to_string(snapshot_.roster.size() - rows_to_draw) +
                " more peers)",
            width));
      }
    }
  }
  if (lines.size() == height)
    return lines;

  // --- Lower Pane: Scrollable Board / Conflicts / Watchers ---
  std::vector<std::string> lower_rows;
  std::string pane_title;
  if (filter_ == SwarmboardFilter::watchers) {
    lower_rows.reserve(snapshot_.watchers.size());
    for (const auto &w : snapshot_.watchers)
      lower_rows.push_back(format_watcher_row_line(w, width));
    pane_title = "WATCHERS (" + std::to_string(lower_rows.size()) + " active)";
  } else {
    const auto msgs = filtered_messages();
    lower_rows.reserve(msgs.size() + snapshot_.concurrent_conflicts.size());
    for (const auto &msg : msgs)
      lower_rows.push_back(format_message_row_line(msg, width));
    if (filter_ == SwarmboardFilter::conflicts && lower_rows.empty()) {
      for (const auto &c : snapshot_.concurrent_conflicts)
        lower_rows.push_back(format_conflict_summary_line(c, width));
    }
    pane_title = "BOARD [" + std::string{swarmboard_filter_name(filter_)} + " | " +
                 std::to_string(lower_rows.size()) + " items | off " +
                 std::to_string(lower_rows.empty()
                                    ? 0U
                                    : std::min(scroll_offset_, lower_rows.size() - 1)) +
                 "]";
  }

  lines.push_back(format_divider(pane_title, width));
  if (lines.size() == height)
    return lines;

  const std::size_t footer_lines = has_footer ? 1U : 0U;
  const std::size_t lower_slots = height > lines.size() + footer_lines
                                      ? (height - lines.size() - footer_lines)
                                      : 0U;

  if (lower_slots > 0) {
    if (lower_rows.empty()) {
      const char *empty_msg = filter_ == SwarmboardFilter::watchers
                                  ? "(no active watchers)"
                                  : (filter_ == SwarmboardFilter::conflicts
                                         ? "(no conflicts or blocked items)"
                                         : (filter_ == SwarmboardFilter::mentions
                                                ? "(no matching @mentions)"
                                                : "(board empty)"));
      lines.push_back(clip_cells(empty_msg, width));
      while (lines.size() + footer_lines < height)
        lines.emplace_back();
    } else {
      const std::size_t start = std::min(scroll_offset_, lower_rows.size() - 1);
      const std::size_t end = std::min(lower_rows.size(), start + lower_slots);
      for (std::size_t i = start; i < end; ++i)
        lines.push_back(lower_rows[i]);
      while (lines.size() + footer_lines < height)
        lines.emplace_back();
    }
  }

  if (has_footer && lines.size() < height) {
    std::string footer;
    if (!snapshot_.guard_verdict.allowed) {
      footer = "GUARD BLOCKED: " +
               swarmboard_sanitize_inline(snapshot_.guard_verdict.reason, 160);
    } else {
      footer =
          "Filter:[1]all [2]mentions [3]conflicts [4]watchers | Scroll:j/k PgUp/PgDn";
    }
    lines.push_back(clip_cells(footer, width));
  }

  return lines;
}

std::string SwarmboardView::render(SwarmboardWidth width,
                                   SwarmboardHeight height) const {
  const auto lines = render_lines(width, height);
  std::string out;
  out.reserve(lines.size() * (width.value + 1));
  for (const auto &line : lines) {
    out += line;
    out.push_back('\n');
  }
  return out;
}

} // namespace blackbird
