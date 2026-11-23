#include "blackbird/context_hygiene.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace blackbird;

void check(bool condition, int line, const char *expr) {
  if (!condition) {
    std::fprintf(stderr, "context_hygiene_test:%d FAILED: %s\n", line, expr);
    std::abort();
  }
}

#define CHECK(...) check((__VA_ARGS__), __LINE__, #__VA_ARGS__)

bool is_valid_utf8(std::string_view text) noexcept {
  std::size_t i = 0;
  while (i < text.size()) {
    const auto b0 = static_cast<unsigned char>(text[i]);
    if (b0 <= 0x7FU) {
      ++i;
      continue;
    }
    if (b0 >= 0xC2U && b0 <= 0xDFU) {
      if (i + 1 >= text.size())
        return false;
      const auto b1 = static_cast<unsigned char>(text[i + 1]);
      if ((b1 & 0xC0U) != 0x80U)
        return false;
      i += 2;
      continue;
    }
    if (b0 >= 0xE0U && b0 <= 0xEFU) {
      if (i + 2 >= text.size())
        return false;
      const auto b1 = static_cast<unsigned char>(text[i + 1]);
      const auto b2 = static_cast<unsigned char>(text[i + 2]);
      if ((b1 & 0xC0U) != 0x80U || (b2 & 0xC0U) != 0x80U)
        return false;
      if ((b0 == 0xE0U && b1 < 0xA0U) || (b0 == 0xEDU && b1 >= 0xA0U))
        return false;
      i += 3;
      continue;
    }
    if (b0 >= 0xF0U && b0 <= 0xF4U) {
      if (i + 3 >= text.size())
        return false;
      const auto b1 = static_cast<unsigned char>(text[i + 1]);
      const auto b2 = static_cast<unsigned char>(text[i + 2]);
      const auto b3 = static_cast<unsigned char>(text[i + 3]);
      if ((b1 & 0xC0U) != 0x80U || (b2 & 0xC0U) != 0x80U || (b3 & 0xC0U) != 0x80U)
        return false;
      if ((b0 == 0xF0U && b1 < 0x90U) || (b0 == 0xF4U && b1 > 0x8FU))
        return false;
      i += 4;
      continue;
    }
    return false;
  }
  return true;
}

void test_small_output_passes_verbatim() {
  ToolProjectionInput input;
  input.tool_name = "exec";
  input.raw_output = "line 1: ok\nline 2: all 14 tests passed\n";
  input.exit_code = 0;
  input.audit_entry_id = 101;

  const auto res = project_tool_output_for_context(input);
  CHECK(!res.was_compacted);
  CHECK(res.projected_text == input.raw_output);
  CHECK(res.original_bytes == input.raw_output.size());
  CHECK(res.projected_bytes == input.raw_output.size());
  CHECK(res.original_lines == 2);
  CHECK(res.diagnostic_lines_extracted == 0);
}

void test_build_log_preserves_head_middle_errors_tail_and_audit_pointer() {
  std::string log;
  log.reserve(60000);
  const std::string err1 =
      "src/engine.cpp:142:17: error: use of undeclared identifier 'missing_sym'";
  const std::string err2 =
      "src/planner.cpp:88:9: error: no matching function for call to 'plan_step'";

  for (int i = 0; i < 1000; ++i) {
    if (i == 0) {
      log += "[HEAD-0] cmake --build build/debug\n";
    } else if (i == 14) {
      log += "[HEAD-14] compiling core units...\n";
    } else if (i == 320) {
      log += err1 + "\n";
    } else if (i == 640) {
      log += err2 + "\n";
    } else if (i == 999) {
      log += "[TAIL-999] ninja: build stopped: subcommand failed.\n";
    } else {
      log += "[build] compiling translation_unit_" + std::to_string(i) +
             ".cpp (clang++ -std=c++23)\n";
    }
  }
  CHECK(log.size() > 50U * 1024U);

  ToolProjectionInput input;
  input.tool_name = "exec";
  input.raw_output = log;
  input.exit_code = 1;
  input.audit_entry_id = 777;

  const auto res = project_tool_output_for_context(input);
  CHECK(res.was_compacted);
  CHECK(res.original_bytes == log.size());
  CHECK(res.original_lines == 1000);
  CHECK(res.projected_bytes == res.projected_text.size());
  CHECK(res.projected_text.size() <= 4096U + kToolProjectionFooterHeadroomBytes);
  CHECK(res.diagnostic_lines_extracted == 2);
  CHECK(is_valid_utf8(res.projected_text));

  // Verify head, BOTH middle error lines, tail, and audit pointer are preserved.
  CHECK(res.projected_text.find("[HEAD-0]") != std::string::npos);
  CHECK(res.projected_text.find("[HEAD-14]") != std::string::npos);
  CHECK(res.projected_text.find(err1) != std::string::npos);
  CHECK(res.projected_text.find(err2) != std::string::npos);
  CHECK(res.projected_text.find("[TAIL-999]") != std::string::npos);
  CHECK(res.projected_text.find("audit #777") != std::string::npos);
  CHECK(res.projected_text.find("/restore 777") != std::string::npos);
  CHECK(res.projected_text.find("audit_inspect") != std::string::npos);
}

void test_errors_prioritized_over_warnings_and_deduplicated() {
  std::string log;
  log += "HEAD_ERROR: error: first line error already in head\n";
  for (int i = 1; i < 15; ++i)
    log += "head line " + std::to_string(i) + "\n";
  for (int i = 0; i < 40; ++i)
    log += "src/a.cpp:" + std::to_string(i) + ": warning: unused variable 'x'\n";
  log += "src/critical.cpp:7:1: AddressSanitizer: heap-buffer-overflow\n";
  log += "src/test.cpp:12:1: ***Failed test_context\n";
  for (int i = 0; i < 50; ++i)
    log += "filler line " + std::to_string(i) + "\n";
  log += "TAIL_ERROR: fatal: final summary failure\n";

  ToolProjectionInput input;
  input.tool_name = "ctest";
  input.raw_output = log;
  input.audit_entry_id = 12;

  ToolProjectionPolicy policy;
  policy.max_inline_lines = 40;
  policy.max_diagnostic_lines = 10;

  const auto res = project_tool_output_for_context(input, policy);
  CHECK(res.was_compacted);
  CHECK(res.projected_text.size() <=
        policy.max_inline_bytes + kToolProjectionFooterHeadroomBytes);
  // Both middle critical diagnostics must survive despite 40 warnings ahead of them.
  CHECK(res.projected_text.find("AddressSanitizer: heap-buffer-overflow") !=
        std::string::npos);
  CHECK(res.projected_text.find("***Failed test_context") != std::string::npos);
  // Head error and tail error must appear only once (deduplicated with head/tail).
  const auto first_head = res.projected_text.find("HEAD_ERROR:");
  CHECK(first_head != std::string::npos);
  CHECK(res.projected_text.find("HEAD_ERROR:", first_head + 1) == std::string::npos);
  const auto first_tail = res.projected_text.find("TAIL_ERROR:");
  CHECK(first_tail != std::string::npos);
  CHECK(res.projected_text.find("TAIL_ERROR:", first_tail + 1) == std::string::npos);
}

void test_minified_json_single_line_ceiling_and_utf8() {
  std::string json = "{\"items\":[";
  for (int i = 0; i < 8000; ++i) {
    if (i > 0)
      json += ",";
    json += "{\"id\":" + std::to_string(i) + ",\"v\":\"payload_" + std::to_string(i) +
            "\"}";
  }
  json += "],\"tail_marker\":\"END_JSON_OK\"}";
  CHECK(json.size() > 200U * 1024U);

  ToolProjectionInput input;
  input.tool_name = "http_get";
  input.raw_output = json;
  input.audit_entry_id = 55;

  const auto res = project_tool_output_for_context(input);
  CHECK(res.was_compacted);
  CHECK(res.original_lines == 1);
  CHECK(res.projected_text.size() <= 4096U + kToolProjectionFooterHeadroomBytes);
  CHECK(is_valid_utf8(res.projected_text));
  CHECK(res.projected_text.find("{\"items\":[") == 0);
  CHECK(res.projected_text.find("END_JSON_OK") != std::string::npos);
  CHECK(res.projected_text.find("audit #55") != std::string::npos);
}

void test_multibyte_utf8_never_splits_codepoints() {
  // 4-byte emoji (🚀 = F0 9F 9A 80) and 3-byte CJK (日 = E6 97 A5).
  std::string emoji_blob;
  emoji_blob.reserve(60000);
  for (int i = 0; i < 15000; ++i)
    emoji_blob += "\xF0\x9F\x9A\x80";

  // Test across odd and non-aligned budgets to hit every interior byte offset 1, 2, 3.
  for (std::size_t budget : {std::size_t{255}, std::size_t{257}, std::size_t{258},
                             std::size_t{259}, std::size_t{4095}, std::size_t{4097}}) {
    ToolProjectionPolicy policy;
    policy.max_inline_bytes = budget;
    ToolProjectionInput input;
    input.tool_name = "unicode_blob";
    input.raw_output = emoji_blob;
    input.audit_entry_id = 9;

    const auto res = project_tool_output_for_context(input, policy);
    CHECK(res.was_compacted);
    CHECK(res.projected_text.size() <= budget + kToolProjectionFooterHeadroomBytes);
    CHECK(is_valid_utf8(res.projected_text));
  }

  // Multi-line CJK with very long lines to stress per-line UTF-8 truncation too.
  std::string cjk_lines;
  for (int line = 0; line < 100; ++line) {
    for (int rep = 0; rep < 200; ++rep)
      cjk_lines += "\xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E";
    cjk_lines += "\n";
  }
  ToolProjectionInput cjk_input;
  cjk_input.tool_name = "read_file";
  cjk_input.raw_output = cjk_lines;
  ToolProjectionPolicy cjk_policy;
  cjk_policy.max_inline_bytes = 1025; // deliberately non-multiple of 3
  const auto cjk_res = project_tool_output_for_context(cjk_input, cjk_policy);
  CHECK(cjk_res.was_compacted);
  CHECK(cjk_res.projected_text.size() <=
        cjk_policy.max_inline_bytes + kToolProjectionFooterHeadroomBytes);
  CHECK(is_valid_utf8(cjk_res.projected_text));
}

void test_tool_result_aging_policy_and_idempotency() {
  const std::uint64_t current_turn = 10;

  std::vector<ContextEntryView> entries = {
      // 1. Non-tool entry: ignored even though old and huge.
      ContextEntryView{.entry_id = "1",
                       .kind = "instruction",
                       .tool_name = "",
                       .turn_index = 1,
                       .bytes = 10000,
                       .pinned = false,
                       .already_stubbed = false,
                       .failed = false,
                       .preview = "system brief"},
      // 2. Pinned old tool output: skipped, counted in entries_skipped_pinned.
      ContextEntryView{.entry_id = "2",
                       .kind = "tool_result",
                       .tool_name = "read_file",
                       .turn_index = 1,
                       .bytes = 8192,
                       .pinned = true,
                       .already_stubbed = false,
                       .failed = false,
                       .preview = "pinned architecture doc"},
      // 3. Recent tool output (age = 3 <= 3): skipped, counted in
      // entries_skipped_recent.
      ContextEntryView{.entry_id = "3",
                       .kind = "tool_result",
                       .tool_name = "exec",
                       .turn_index = 7,
                       .bytes = 4096,
                       .pinned = false,
                       .already_stubbed = false,
                       .failed = false,
                       .preview = "recent build ok"},
      // 4. Failed tool output at age 6 (10 - 4 = 6 <= 6): kept for 6 turns!
      ContextEntryView{.entry_id = "4",
                       .kind = "tool_result",
                       .tool_name = "exec",
                       .turn_index = 4,
                       .bytes = 4096,
                       .pinned = false,
                       .already_stubbed = false,
                       .failed = true,
                       .preview = "error: build failed"},
      // 5. Failed tool output at age 7 (10 - 3 = 7 > 6): aged!
      ContextEntryView{.entry_id = "5",
                       .kind = "tool_result",
                       .tool_name = "exec",
                       .turn_index = 3,
                       .bytes = 6144,
                       .pinned = false,
                       .already_stubbed = false,
                       .failed = true,
                       .preview = "\x1b[31merror: old failure\x1b[0m\nline two"},
      // 6. Normal old tool output (age 4 > 3): aged!
      ContextEntryView{.entry_id = "6",
                       .kind = "tool_result",
                       .tool_name = "search_files",
                       .turn_index = 6,
                       .bytes = 2048,
                       .pinned = false,
                       .already_stubbed = false,
                       .failed = false,
                       .preview = "found 42 matches across src/"},
      // 7. Already-stubbed old tool output: skipped (idempotent).
      ContextEntryView{.entry_id = "7",
                       .kind = "tool_result",
                       .tool_name = "exec",
                       .turn_index = 1,
                       .bytes = 2048,
                       .pinned = false,
                       .already_stubbed = true,
                       .failed = false,
                       .preview = "[aged tool #7 exec (2.0 KiB) ...]"},
      // 8. Small old tool output (< 512 bytes): skipped.
      ContextEntryView{.entry_id = "8",
                       .kind = "tool_result",
                       .tool_name = "pwd",
                       .turn_index = 1,
                       .bytes = 128,
                       .pinned = false,
                       .already_stubbed = false,
                       .failed = false,
                       .preview = "/workspace"},
  };

  const auto plan = plan_tool_result_aging(entries, current_turn);
  CHECK(plan.entries_aged == 2);
  CHECK(plan.actions.size() == 2);
  CHECK(plan.entries_skipped_pinned == 1);
  CHECK(plan.entries_skipped_recent == 2); // entries #3 (age 3) and #4 (failed age 6)

  // Verify entry #5 (failed, age 7) action & CompactRequest contract.
  const auto &a0 = plan.actions[0];
  CHECK(a0.entry_id == "5");
  CHECK(is_aged_tool_stub(a0.stub));
  CHECK(a0.stub.find("[aged tool #5 exec (6.0 KiB)") == 0);
  CHECK(a0.stub.find("error: old failure line two") != std::string::npos);
  CHECK(a0.stub.find("/restore 5 for verbatim original]") != std::string::npos);
  CHECK(a0.stub.find('\n') == std::string::npos);
  CHECK(a0.stub.find('\x1b') == std::string::npos);
  CHECK(is_valid_utf8(a0.stub));
  CHECK(a0.original_bytes == 6144);
  CHECK(a0.stub_bytes == a0.stub.size());
  CHECK(a0.bytes_reclaimed == 6144 - a0.stub.size());
  CHECK(a0.request.op == CompactOp::summarize);
  CHECK(a0.request.ids.size() == 1 && a0.request.ids[0] == 5);
  CHECK(a0.request.summary == a0.stub);

  // Verify entry #6 (normal, age 4) action & CompactRequest contract.
  const auto &a1 = plan.actions[1];
  CHECK(a1.entry_id == "6");
  CHECK(a1.stub.find("[aged tool #6 search_files (2.0 KiB)") == 0);
  CHECK(a1.stub.find("/restore 6 for verbatim original]") != std::string::npos);
  CHECK(a1.request.op == CompactOp::summarize);
  CHECK(a1.request.ids.size() == 1 && a1.request.ids[0] == 6);
  CHECK(a1.request.summary == a1.stub);

  // Accurate total_bytes_reclaimed & compact_requests helper.
  CHECK(plan.total_bytes_reclaimed == a0.bytes_reclaimed + a1.bytes_reclaimed);
  const auto reqs = plan.compact_requests();
  CHECK(reqs.size() == 2);
  CHECK(reqs[0].ids == a0.request.ids && reqs[1].ids == a1.request.ids);

  // Second pass after marking aged entries as stubbed must be a complete no-op!
  entries[4].already_stubbed = true;
  entries[4].bytes = a0.stub_bytes;
  entries[4].preview = a0.stub;
  entries[5].already_stubbed = true;
  entries[5].bytes = a1.stub_bytes;
  entries[5].preview = a1.stub;

  const auto second_pass = plan_tool_result_aging(entries, current_turn);
  CHECK(second_pass.entries_aged == 0);
  CHECK(second_pass.actions.empty());
  CHECK(second_pass.total_bytes_reclaimed == 0);
  CHECK(second_pass.entries_skipped_pinned == 1);
  CHECK(second_pass.entries_skipped_recent == 2);
}

void test_max_compactions_per_pass_and_turn_boundary() {
  std::vector<ContextEntryView> entries;
  for (std::uint64_t i = 1; i <= 10; ++i) {
    entries.push_back(
        ContextEntryView{.entry_id = std::to_string(i),
                         .kind = "tool_result",
                         .tool_name = "read_file",
                         .turn_index = 1,
                         .bytes = 1024,
                         .pinned = false,
                         .already_stubbed = false,
                         .failed = false,
                         .preview = "contents of file " + std::to_string(i)});
  }
  // Add a future-turn entry to ensure no unsigned underflow when turn_index > current.
  entries.push_back(ContextEntryView{.entry_id = "99",
                                     .kind = "tool_result",
                                     .tool_name = "exec",
                                     .turn_index = 50,
                                     .bytes = 2048,
                                     .pinned = false,
                                     .already_stubbed = false,
                                     .failed = false,
                                     .preview = "future turn"});

  ToolAgingPolicy policy;
  policy.max_compactions_per_pass = 4;

  const auto plan = plan_tool_result_aging(entries, 10, policy);
  CHECK(plan.entries_aged == 4);
  CHECK(plan.actions.size() == 4);
  CHECK(plan.actions[0].entry_id == "1");
  CHECK(plan.actions[3].entry_id == "4");
  CHECK(plan.entries_skipped_recent == 1); // future-turn entry #99 treated as age 0
}

void test_one_mib_minified_json_and_edge_cases() {
  // Empty output passes verbatim.
  const auto empty_res =
      project_tool_output_for_context({.tool_name = "exec", .raw_output = ""});
  CHECK(!empty_res.was_compacted);
  CHECK(empty_res.projected_text.empty());
  CHECK(empty_res.original_bytes == 0);
  CHECK(empty_res.original_lines == 0);

  // 1 MiB single-line minified JSON blob stays strictly bounded <= max_inline_bytes +
  // 512.
  std::string mib = "{\"blob\":\"";
  mib.append(1024U * 1024U, 'x');
  mib += "\",\"end\":true}";
  const auto mib_res = project_tool_output_for_context(
      {.tool_name = "curl", .raw_output = std::move(mib)});
  CHECK(mib_res.was_compacted);
  CHECK(mib_res.original_bytes > 1024U * 1024U);
  CHECK(mib_res.original_lines == 1);
  CHECK(mib_res.projected_text.size() <= 4096U + kToolProjectionFooterHeadroomBytes);
  CHECK(is_valid_utf8(mib_res.projected_text));
  CHECK(mib_res.projected_text.find("{\"blob\":\"") == 0);
  CHECK(mib_res.projected_text.find("\"end\":true}") != std::string::npos);
  CHECK(mib_res.projected_text.find("audit_inspect") != std::string::npos);

  // Also test function_call_output kind and prefixed block IDs ("b12", "#13",
  // non-numeric).
  std::vector<ContextEntryView> extra = {
      ContextEntryView{.entry_id = "b12",
                       .kind = "function_call_output",
                       .tool_name = "exec",
                       .turn_index = 1,
                       .bytes = 2048,
                       .preview = "ok"},
      ContextEntryView{.entry_id = "#13",
                       .kind = "tool_result",
                       .tool_name = "exec",
                       .turn_index = 1,
                       .bytes = 2048,
                       .preview = "ok"},
      ContextEntryView{.entry_id = "call_abc",
                       .kind = "tool_result",
                       .tool_name = "exec",
                       .turn_index = 1,
                       .bytes = 2048,
                       .preview = ""},
  };
  const auto extra_plan = plan_tool_result_aging(extra, 10);
  CHECK(extra_plan.entries_aged == 3);
  CHECK(extra_plan.actions[0].request.ids.size() == 1 &&
        extra_plan.actions[0].request.ids[0] == 12);
  CHECK(extra_plan.actions[1].request.ids.size() == 1 &&
        extra_plan.actions[1].request.ids[0] == 13);
  CHECK(extra_plan.actions[2].request.ids.empty());
  CHECK(extra_plan.actions[2].stub.find("(no preview)") != std::string::npos);
  // Canonicalized numeric IDs emit single '#' and executable /restore <id>.
  CHECK(extra_plan.actions[0].stub.find("[aged tool #12 exec") == 0);
  CHECK(extra_plan.actions[0].stub.find("/restore 12 for verbatim original]") !=
        std::string::npos);
  CHECK(extra_plan.actions[1].stub.find("[aged tool #13 exec") == 0);
  CHECK(extra_plan.actions[1].stub.find("##13") == std::string::npos);
  CHECK(extra_plan.actions[1].stub.find("/restore 13 for verbatim original]") !=
        std::string::npos);
  // compact_requests() filters out non-executable empty-ids requests ("call_abc").
  const auto executable = extra_plan.compact_requests();
  CHECK(executable.size() == 2);
  CHECK(executable[0].ids.size() == 1 && executable[0].ids[0] == 12);
  CHECK(executable[1].ids.size() == 1 && executable[1].ids[0] == 13);
}

void test_dentist_hardening_regressions() {
  // 1. SIZE_MAX max_inline_bytes with line-triggered compaction must not wrap
  // hard_ceiling or percentage budgets.
  std::string many_lines;
  for (int i = 0; i < 120; ++i) {
    if (i == 50)
      many_lines += "src/x.cpp:1:1: error: boom\n";
    else
      many_lines += "line_" + std::to_string(i) + "\n";
  }
  ToolProjectionPolicy huge_policy;
  huge_policy.max_inline_bytes = std::numeric_limits<std::size_t>::max();
  huge_policy.max_inline_lines = 40;
  const auto huge_res = project_tool_output_for_context(
      {.tool_name = "exec", .raw_output = many_lines, .audit_entry_id = 404},
      huge_policy);
  CHECK(huge_res.was_compacted);
  CHECK(huge_res.projected_text.find("error: boom") != std::string::npos);
  CHECK(huge_res.projected_text.find("audit #404") != std::string::npos);
  CHECK(huge_res.projected_text.find("/restore 404") != std::string::npos);

  // 2. UINT64_MAX bytes in format_human_bytes must not overflow uint64_t.
  std::vector<ContextEntryView> max_byte_entries = {
      ContextEntryView{.entry_id = "77",
                       .kind = "tool_result",
                       .tool_name = "exec",
                       .turn_index = 1,
                       .bytes = std::numeric_limits<std::size_t>::max(),
                       .preview = "huge"},
  };
  const auto max_plan = plan_tool_result_aging(max_byte_entries, 10);
  CHECK(max_plan.entries_aged == 1);
  CHECK(max_plan.actions[0].stub.find("GiB)") != std::string::npos);
  CHECK(max_plan.actions[0].bytes_reclaimed ==
        std::numeric_limits<std::size_t>::max() - max_plan.actions[0].stub.size());

  // 3. Complete escape/C1/BiDi sanitization in stubs (APC, DCS, PM, SOS, 2-byte ESC,
  // 8-bit C1, UTF-8 C1, and Unicode BiDi controls).
  const std::string hostile = "A"
                              "\x1b_APC_SECRET\x1b\\"
                              "\x1bP"
                              "DCS_SECRET\x1b\\"
                              "\x1b^PM_SECRET\x07"
                              "\x1bX"
                              "SOS_SECRET\x9c"
                              "\x1b"
                              "c"
                              "\x9b"
                              "2J"
                              "\xC2\x9B"
                              "31m"
                              "\xE2\x80\xAE" // U+202E RLO
                              "\xE2\x81\xA6" // U+2066 LRI
                              "\xE2\x80\x8F" // U+200F RLM
                              "\xD8\x9C"     // U+061C ALM
                              "SAFE";
  std::vector<ContextEntryView> hostile_entries = {
      ContextEntryView{.entry_id = "##bad id",
                       .kind = "tool_result",
                       .tool_name = "exec",
                       .turn_index = 1,
                       .bytes = 2048,
                       .preview = hostile},
  };
  const auto hostile_plan = plan_tool_result_aging(hostile_entries, 10);
  CHECK(hostile_plan.entries_aged == 1);
  const auto &stub = hostile_plan.actions[0].stub;
  CHECK(is_valid_utf8(stub));
  CHECK(stub.find("ASAFE") != std::string::npos);
  CHECK(stub.find("APC_SECRET") == std::string::npos);
  CHECK(stub.find("DCS_SECRET") == std::string::npos);
  CHECK(stub.find("PM_SECRET") == std::string::npos);
  CHECK(stub.find("SOS_SECRET") == std::string::npos);
  CHECK(stub.find("2J") == std::string::npos);
  CHECK(stub.find("31m") == std::string::npos);
  CHECK(stub.find("\xE2\x80\xAE") == std::string::npos);
  CHECK(stub.find("\xE2\x81\xA6") == std::string::npos);
  CHECK(stub.find("\xE2\x80\x8F") == std::string::npos);
  CHECK(stub.find("\xD8\x9C") == std::string::npos);
  CHECK(stub.find("##") == std::string::npos);
  CHECK(stub.find("/restore badid for verbatim original]") != std::string::npos);
  // Non-numeric entry_id is excluded from compact_requests().
  CHECK(hostile_plan.compact_requests().empty());

  // 4. Preview-based idempotency: already-aged stub text is skipped even if
  // already_stubbed was left false by caller.
  std::vector<ContextEntryView> stub_preview_only = {
      ContextEntryView{.entry_id = "88",
                       .kind = "tool_result",
                       .tool_name = "exec",
                       .turn_index = 1,
                       .bytes = 4096,
                       .already_stubbed = false,
                       .preview = "[aged tool #88 exec (4.0 KiB) \xe2\x80\x94 ok; "
                                  "/restore 88 for verbatim original]"},
  };
  const auto idemp_plan = plan_tool_result_aging(stub_preview_only, 10);
  CHECK(idemp_plan.entries_aged == 0);
  CHECK(idemp_plan.actions.empty());
}

} // namespace

int main() {
  test_small_output_passes_verbatim();
  test_build_log_preserves_head_middle_errors_tail_and_audit_pointer();
  test_errors_prioritized_over_warnings_and_deduplicated();
  test_minified_json_single_line_ceiling_and_utf8();
  test_multibyte_utf8_never_splits_codepoints();
  test_tool_result_aging_policy_and_idempotency();
  test_max_compactions_per_pass_and_turn_boundary();
  test_one_mib_minified_json_and_edge_cases();
  test_dentist_hardening_regressions();
  std::cout << "context_hygiene_test passed\n";
  return 0;
}
