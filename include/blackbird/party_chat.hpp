#pragma once

#include "blackbird/board_bridge.hpp"
#include "blackbird/foundation.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::uint32_t kPartyConfigVersion = 1;
inline constexpr std::size_t kPartyConfigMaxBytes = 256 * 1024;
inline constexpr std::size_t kPartyMaxPeers = 256;
inline constexpr std::size_t kPartyMaxAliasBytes = 64;
inline constexpr std::size_t kPartyMaxFieldBytes = 512;
inline constexpr std::size_t kPartyMaxMessageBytes = 64 * 1024;
inline constexpr std::string_view kPartyDefaultScope = "party/rollcall";

enum class PartyMode : std::uint8_t {
  single_operator,
  multi_operator,
};

enum class PartyModeOverride : std::uint8_t {
  auto_detect,
  single_operator,
  multi_operator,
};

enum class PartyMemberRole : std::uint8_t {
  operator_human,
  platoon_leader,
  worker,
  bridge_peer,
};

enum class PartyParticipantState : std::uint8_t {
  online,
  working,
  idle,
  offline,
};

enum class PartyMessageKind : std::uint8_t {
  chat,
  leader_update,
  blocker,
  decision,
  conflict,
  system,
  irc_action,
  irc_notice,
};

enum class PartyMessageFilter : std::uint8_t {
  all,
  operators,
  leaders,
  conflicts,
};

std::string_view party_mode_name(PartyMode mode) noexcept;
std::string_view party_mode_override_name(PartyModeOverride mode) noexcept;
Result<PartyModeOverride> parse_party_mode_override(std::string_view name) noexcept;

std::string_view party_member_role_name(PartyMemberRole role) noexcept;
Result<PartyMemberRole> parse_party_member_role(std::string_view name) noexcept;

std::string_view party_participant_state_name(PartyParticipantState state) noexcept;
Result<PartyParticipantState>
parse_party_participant_state(std::string_view name) noexcept;

std::string_view party_message_kind_name(PartyMessageKind kind) noexcept;
Result<PartyMessageKind> parse_party_message_kind(std::string_view name) noexcept;

std::string_view party_message_filter_name(PartyMessageFilter filter) noexcept;
Result<PartyMessageFilter> parse_party_message_filter(std::string_view name) noexcept;

bool valid_party_alias(std::string_view alias) noexcept;

// Validates a per-session IRC nick (`1..=32` printable UTF-8 codepoints, <= 64 bytes;
// forbids whitespace, leading `@` spoofing, C0/C1/DEL/ESC/ANSI, BiDi, zero-width,
// line/paragraph separators, Unicode Tag chars, and invalid UTF-8).
Result<std::string> validate_irc_nick(std::string_view raw);

// Formats a display identity that ALWAYS preserves the verified `@handle` badge
// alongside any optional session nick (`"<nick> (@<handle>)"` or `"@<handle>"`).
struct IrcDisplayNameInput {
  std::string_view nick;
  std::string_view handle;
};
std::string format_irc_display_name(IrcDisplayNameInput input);

// Hostile terminal-escape sanitizer: escapes all ESC (0x1B), C0 (0x00..0x1F),
// DEL (0x7F), bare C1 (0x80..0x9F including 0x9B CSI), UTF-8 C1 (C2 80..C2 9F),
// Unicode bidi overrides/isolates (U+202A..202E, U+2066..2069, U+200E, U+200F,
// U+061C), BOM, and invalid UTF-8 bytes while preserving valid printable UTF-8.
std::string party_chat_sanitize(std::string_view text, std::size_t max_bytes = 2048);

struct PartyParticipant {
  std::string id;
  std::string display_name;
  PartyMemberRole role = PartyMemberRole::worker;
  std::string host;
  std::string model;
  std::string fingerprint;
  PartyParticipantState state = PartyParticipantState::offline;
  std::int64_t last_seen_ns = 0;
  std::optional<std::string> ssh_target;
  std::optional<std::string> remote_session;
  std::optional<std::string> provider;
  std::optional<std::string> remote_model;
  bool local_self = false;
  std::string nick;

  bool operator==(const PartyParticipant &) const = default;
};

struct PartyAgentCard {
  std::string title;
  std::string summary;
  std::vector<std::string> files;
  std::string status = "done";
  std::string agent_name;
  std::optional<std::string> diff_stat;

  bool operator==(const PartyAgentCard &) const = default;
};

struct PartyPendingMention {
  std::string sender_handle;
  std::string preview;

  bool operator==(const PartyPendingMention &) const = default;
};

struct PartyMlsStatus {
  std::uint64_t mls_epoch = 0U;
  std::uint32_t trust_tier = 0U; // 0..3 (Tier 0..Tier 3)
  bool has_declared_agent = false;
  bool has_pending_removals = false;
  bool clone_detected = false;
  std::string epoch_authenticator; // 6x4 Crockford Base32 (29 chars)

  bool operator==(const PartyMlsStatus &) const = default;
};

struct PartyMessage {
  std::string id;
  std::int64_t timestamp_ns = 0;
  std::string sender_id;
  PartyMemberRole sender_role = PartyMemberRole::worker;
  std::string sender_host;
  std::string sender_model;
  std::string sender_fingerprint;
  bool verified_peer = false;
  std::string target = "@all";
  PartyMessageKind kind = PartyMessageKind::chat;
  std::string body;
  bool untrusted_remote = false;
  std::optional<PartyAgentCard> agent_card;
  std::string sender_nick;

  bool operator==(const PartyMessage &) const = default;
};

struct PartyRosterPeerConfig {
  std::string alias;
  PartyMemberRole role = PartyMemberRole::platoon_leader;
  std::string host;
  std::optional<std::string> ssh_target;
  std::optional<std::string> provider;
  std::optional<std::string> model;
  std::optional<std::string> remote_session;
  std::optional<std::string> display_name;
  std::optional<std::string> fingerprint;

  bool operator==(const PartyRosterPeerConfig &) const = default;
};

struct PartyRosterConfig {
  std::uint32_t version = kPartyConfigVersion;
  std::string room_scope = std::string{kPartyDefaultScope};
  PartyModeOverride mode_override = PartyModeOverride::auto_detect;
  std::vector<PartyRosterPeerConfig> peers;

  bool operator==(const PartyRosterConfig &) const = default;
};

// Strictly validated `.blackbird/party.json` loader & saver.
// Rejects symlinks, oversized files (> 256 KiB), unknown/secret keys, and
// secret-looking values. Writes atomically with mode 0600 on save.
Result<PartyRosterConfig> load_party_roster_config(const std::filesystem::path &path);
Result<void> save_party_roster_config(const std::filesystem::path &path,
                                      const PartyRosterConfig &config);

struct PartyConfig {
  std::filesystem::path project_root;
  std::filesystem::path platoon_dir;
  std::filesystem::path bridge_dir;
  std::filesystem::path party_config_path;
  std::filesystem::path known_peers_dir;
  std::string room_scope;
  PartyModeOverride mode_override = PartyModeOverride::auto_detect;
  std::optional<std::string> local_operator_id;
  std::optional<std::string> local_operator_display_name;
  std::optional<std::string> local_actor_fp;
  std::string local_host;
  // 0 => use current system wall clock nanoseconds for presence TTL checks.
  std::int64_t now_ns = 0;

  static PartyConfig for_project(const std::filesystem::path &project_root);
};

struct PartySnapshot {
  std::string room_scope = std::string{kPartyDefaultScope};
  PartyMode mode = PartyMode::single_operator;
  PartyModeOverride mode_override = PartyModeOverride::auto_detect;
  std::vector<PartyParticipant> participants;
  std::vector<PartyMessage> messages;
  std::vector<ConcurrentClaimConflict> conflicts;
  bool party_config_present = false;
  bool platoon_present = false;
  bool bridge_present = false;
  bool known_peers_present = false;
  bool compact_room_presentation = false;
  std::optional<PartyPendingMention> pending_mention;
  std::optional<PartyMlsStatus> mls_status;
  std::string room_topic;

  std::size_t operator_count() const noexcept;
  std::size_t online_operator_count() const noexcept;
  std::size_t leader_count() const noexcept;
  std::size_t online_leader_count() const noexcept;
  std::size_t conflict_count() const noexcept { return conflicts.size(); }

  bool operator==(const PartySnapshot &) const = default;
};

// Auto-detects single_operator vs multi_operator mode unless overridden:
// > 1 distinct operator_human participants => multi_operator;
// <= 1 operator_human participant => single_operator.
PartyMode detect_party_mode(
    const std::vector<PartyParticipant> &participants,
    PartyModeOverride override_mode = PartyModeOverride::auto_detect) noexcept;

// Strictly passive read-only snapshot loader. NEVER creates `.blackbird/`,
// `.blackbird/platoon`, `.blackbird/bridge`, lock files, or
// `~/.local/share/blackbird/peers`. Rejects symlinks via symlink_status and
// O_NOFOLLOW. NEVER advances BoardBridge receipts or clears action guards.
Result<PartySnapshot> load_party_snapshot(const PartyConfig &config);

struct ParsedPartyInput {
  bool broadcast = false;
  bool explicit_all = false;
  PartyMode mode = PartyMode::single_operator;
  std::vector<std::string> resolved_targets;
  std::vector<std::string> mentioned_aliases;
  std::vector<std::string> unknown_targets;
  std::string target_label = "@all";
  std::string body;

  bool has_unknown_targets() const noexcept { return !unknown_targets.empty(); }
  bool operator==(const ParsedPartyInput &) const = default;
};

// Target routing parser:
// - `@all <text>` or plain `<text>` broadcasts to all active platoon leaders
//   (single-operator) or all operators + leaders (multi-operator).
// - `@<alias> [@<alias2> ...] <text>` routes specifically to named
//   participant(s), recording unknown aliases in `unknown_targets`.
// - Rejects empty/whitespace-only inputs and inputs with no message body.
Result<ParsedPartyInput> parse_party_input(std::string_view input,
                                           const PartySnapshot &snap);

// Distinct non-mutually-convertible viewport dimension wrappers so callers can
// pass integer columns/rows directly (`render(120, 30, false)`) cleanly without
// triggering swappable-parameter diagnostics.
struct PartyPaneWidth {
  int value = 80;
  constexpr PartyPaneWidth(int cols) noexcept : value(cols) {}
};

struct PartyPaneHeight {
  int value = 24;
  constexpr PartyPaneHeight(int rows) noexcept : value(rows) {}
};

struct PartyChatFrame {
  std::vector<std::string> lines;
  PartyMode mode = PartyMode::single_operator;
  int width = 0;
  int height = 0;
  std::size_t unread_count = 0;
  std::size_t total_feed_lines = 0;
  std::size_t max_scroll_offset = 0;
  bool split_layout = false;
  bool color_enabled = false;

  std::string text() const;
};

// Interactive unified single/multi-operator Party Chat pane state & renderer.
class PartyChatPane {
public:
  PartyChatPane() = default;
  explicit PartyChatPane(PartySnapshot snapshot);

  Result<void> reload(const PartyConfig &config);
  void update(PartySnapshot snapshot);
  void push_message(PartyMessage message);

  const PartySnapshot &snapshot() const noexcept { return snapshot_; }

  bool is_open() const noexcept { return open_; }
  void set_open(bool open) noexcept;
  void toggle_open() noexcept { set_open(!open_); }

  bool is_focused() const noexcept { return focused_; }
  void set_focused(bool focused) noexcept;

  PartyMode mode() const noexcept;
  PartyModeOverride mode_override() const noexcept { return mode_override_; }
  void set_mode_override(PartyModeOverride override_mode) noexcept;

  PartyMessageFilter filter() const noexcept { return filter_; }
  void set_filter(PartyMessageFilter filter) noexcept;
  void cycle_filter() noexcept;

  const std::string &selected_target() const noexcept { return selected_target_; }
  std::optional<std::size_t> selected_target_index() const noexcept {
    return selected_target_index_;
  }
  void cycle_target();
  bool set_selected_target(std::string_view target);

  std::size_t scroll_offset() const noexcept { return scroll_offset_; }
  bool is_scrolled_up() const noexcept { return scroll_offset_ > 0; }
  void scroll_up(std::size_t lines = 1) noexcept;
  void scroll_down(std::size_t lines = 1) noexcept;
  void page_up(std::size_t page_lines = 10) noexcept;
  void page_down(std::size_t page_lines = 10) noexcept;
  void scroll_to_bottom() noexcept;

  std::size_t unread_count() const noexcept { return unread_count_; }
  void clear_unread() noexcept { unread_count_ = 0; }

  const std::string &composer_text() const noexcept { return composer_text_; }
  void set_composer_text(std::string text);
  void append_composer_text(std::string_view text);
  void backspace_composer() noexcept;
  void clear_composer() noexcept { composer_text_.clear(); }

  Result<ParsedPartyInput> parse_composer() const;

  std::vector<PartyMessage> filtered_messages() const;

  PartyChatFrame render_frame(PartyPaneWidth width, PartyPaneHeight height,
                              bool color = false) const;
  std::vector<std::string> render_lines(PartyPaneWidth width, PartyPaneHeight height,
                                        bool color = false) const;
  std::string render(PartyPaneWidth width, PartyPaneHeight height,
                     bool color = false) const;

private:
  void sync_selected_target();
  std::vector<std::size_t> targetable_participant_indices() const;

  PartySnapshot snapshot_{};
  bool open_ = false;
  bool focused_ = false;
  PartyModeOverride mode_override_ = PartyModeOverride::auto_detect;
  PartyMessageFilter filter_ = PartyMessageFilter::all;
  std::string selected_target_ = "@all";
  std::optional<std::size_t> selected_target_index_;
  std::size_t scroll_offset_ = 0;
  std::string composer_text_;
  std::size_t unread_count_ = 0;
  std::vector<std::string> seen_message_ids_;
};

} // namespace blackbird
