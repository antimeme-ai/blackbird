#pragma once

#include "blackbird/context.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

// Extra ceiling headroom above ToolProjectionPolicy::max_inline_bytes reserved
// for section dividers and the lossless audit pointer footer.
inline constexpr std::size_t kToolProjectionFooterHeadroomBytes = 512;

// Prefix emitted by deterministic lossless aging stubs.
inline constexpr std::string_view kAgedToolStubPrefix = "[aged tool #";

struct ToolProjectionPolicy {
  std::size_t max_inline_bytes = 4096;
  std::size_t max_inline_lines = 80;
  std::size_t head_lines = 15;
  std::size_t tail_lines = 25;
  std::size_t max_diagnostic_lines = 20;
};

struct ToolProjectionInput {
  std::string tool_name;
  std::string raw_output;
  std::optional<int> exit_code = std::nullopt;
  std::optional<std::uint64_t> audit_entry_id = std::nullopt;
};

struct ToolProjectionResult {
  std::string projected_text;
  bool was_compacted = false;
  std::size_t original_bytes = 0;
  std::size_t original_lines = 0;
  std::size_t projected_bytes = 0;
  std::size_t diagnostic_lines_extracted = 0;
};

// Projects raw tool output for live model context while keeping full verbatim
// bytes untouched in the append-only audit log.
//
// - Outputs within max_inline_bytes and max_inline_lines pass verbatim.
// - Larger outputs preserve head_lines, deduplicated high-signal diagnostic
//   lines from the middle (prioritizing errors/failures before warnings up to
//   max_diagnostic_lines), tail_lines, and a crisp lossless audit pointer.
// - projected_text.size() is strictly bounded to
//   policy.max_inline_bytes + kToolProjectionFooterHeadroomBytes and never
//   splits a valid UTF-8 codepoint.
ToolProjectionResult
project_tool_output_for_context(const ToolProjectionInput &input,
                                const ToolProjectionPolicy &policy = {});

struct ToolAgingPolicy {
  std::uint64_t keep_recent_turns = 3;
  std::size_t min_bytes_to_age = 512;
  std::size_t max_compactions_per_pass = 32;
  std::uint64_t preserve_errors_for_turns = 6;
};

struct ContextEntryView {
  std::string entry_id;
  std::string kind;
  std::string tool_name;
  std::uint64_t turn_index = 0;
  std::size_t bytes = 0;
  bool pinned = false;
  bool already_stubbed = false;
  bool failed = false;
  std::string preview;
  std::optional<std::uint64_t> audit_entry_id = std::nullopt;
};

struct AgedToolAction {
  std::string entry_id;
  std::string stub;
  std::size_t original_bytes = 0;
  std::size_t stub_bytes = 0;
  std::size_t bytes_reclaimed = 0;
  // Matches Blackbird's ContextStore::compact contract:
  // CompactOp::summarize replaces the target block(s) with `summary` while
  // archiving the verbatim original for `/restore <id>`.
  CompactRequest request;
};

struct ToolAgingPlan {
  std::vector<AgedToolAction> actions;
  std::size_t total_bytes_reclaimed = 0;
  std::size_t entries_aged = 0;
  std::size_t entries_skipped_pinned = 0;
  std::size_t entries_skipped_recent = 0;

  // Returns executable CompactRequests (those with at least one numeric block ID
  // or explicit from/to range suitable for ContextStore::compact).
  std::vector<CompactRequest> compact_requests() const;
};

// Returns true if text begins with the deterministic aged-tool stub marker.
bool is_aged_tool_stub(std::string_view text) noexcept;

// Pure sliding-window planner for aging older tool outputs into deterministic
// 1-line lossless stubs paired with ContextStore CompactRequest values.
// Never mutates AuditLog or retained originals.
ToolAgingPlan plan_tool_result_aging(const std::vector<ContextEntryView> &entries,
                                     std::uint64_t current_turn,
                                     const ToolAgingPolicy &policy = {});

} // namespace blackbird
