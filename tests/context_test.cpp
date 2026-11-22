#include "blackbird/context.hpp"
#include "blackbird/json.hpp"
#include "blackbird/packet.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

using namespace blackbird;

namespace {
void check(bool ok, std::string_view why) {
  if (!ok)
    throw std::runtime_error(std::string{"context_test failed: "} + std::string{why});
}
template <class T> T make_id(unsigned char n) {
  IdentityBytes b{};
  b[0] = std::byte{n};
  return unwrap(T::from_bytes(b));
}
} // namespace

int main() {
  char pattern[] = "/tmp/bb-ctx-block-XXXXXX";
  const auto *path = mkdtemp(pattern);
  check(path != nullptr, "mkdtemp");
  const std::filesystem::path dir{path};
  struct Cleanup {
    std::filesystem::path p;
    ~Cleanup() { std::filesystem::remove_all(p); }
  } cleanup{dir};

  const JournalHeader h{make_id<EnvironmentId>(1),
                        make_id<AuditStreamId>(2),
                        3,
                        {1024 * 1024, 4 * 1024 * 1024},
                        std::nullopt};
  const JournalCapacity cap{64 * 1024 * 1024, 8192};

  // 1. Append, automatic exchange folding, close_open_exchanges.
  {
    auto root =
        unwrap(RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                         NativeJournalDirectory::open(dir.string()))),
                                     "audit", h, cap));
    AuditLog log{*root};
    ContextStore ctx{log};

    const auto b1 = ctx.append(
        {Value::object({{"role", Value{"user"}}, {"content", Value{"mission alpha"}}})},
        "operator");
    check(b1 == 1, "first block id == 1");
    check(ctx.blocks().size() == 1 && ctx.blocks()[0].kind == BlockKind::instruction,
          "operator prompt is instruction");
    check(ctx.live_origin("operator"), "live_origin matches");
    check(ctx.live_instruction(Value::object(
              {{"content", Value{"mission alpha"}}, {"role", Value{"user"}}})),
          "live_instruction ignores key order");

    // Provider response with function_call opens an exchange block.
    const auto b2 = ctx.append({Value::object({{"type", Value{"function_call"}},
                                               {"call_id", Value{"c1"}},
                                               {"name", Value{"exec"}},
                                               {"arguments", Value{"{}"}}})},
                               "provider.branch:1");
    check(b2 == 2 && ctx.blocks().size() == 2, "exchange block created");
    check(ctx.blocks()[1].kind == BlockKind::exchange && ctx.blocks()[1].open,
          "exchange with unanswered call is open");
    check(ctx.has_open_exchanges(), "has_open_exchanges true");

    // Appending matching function_call_output folds into block #2 and closes it.
    const auto b2_ext =
        ctx.append({Value::object({{"type", Value{"function_call_output"}},
                                   {"call_id", Value{"c1"}},
                                   {"output", Value{"ok"}}})},
                   "lua.synthetic");
    check(b2_ext == 2 && ctx.blocks().size() == 2, "output folded into exchange #2");
    check(!ctx.blocks()[1].open && !ctx.has_open_exchanges(),
          "exchange #2 closed once answered");
    check(ctx.blocks()[1].items.size() == 2, "exchange #2 holds call + output");

    // Unanswered exchange closed cleanly by close_open_exchanges.
    const auto b3 = ctx.append({Value::object({{"type", Value{"function_call"}},
                                               {"call_id", Value{"c2"}},
                                               {"name", Value{"read_file"}},
                                               {"arguments", Value{"{}"}}})},
                               "provider.branch:2");
    check(b3 == 3 && ctx.has_open_exchanges(), "block #3 open");
    const auto closed = ctx.close_open_exchanges(true);
    check(closed == 1 && !ctx.has_open_exchanges(), "close_open_exchanges closed c2");

    // 2. Pinning, range compaction, automatic skipping of instructions & pinned blocks.
    CompactRequest pin_req;
    pin_req.ids = {b3};
    pin_req.op = CompactOp::pin;
    check(field(ctx.compact(pin_req), "ok") == Value{true}, "pin b3");
    check(ctx.blocks()[2].pinned, "b3 is pinned");

    CompactRequest sum_req;
    sum_req.from = 1;
    sum_req.to = 3;
    sum_req.op = CompactOp::summarize;
    sum_req.summary = "Executed exec tool cleanly.";
    const auto sum_res = ctx.compact(sum_req);
    check(field(sum_res, "ok") == Value{true}, "summarize 1..3 ok");
    check(field(sum_res, "affected").array().size() == 1 &&
              field(sum_res, "affected").array()[0].number().text() == "2",
          "only unpinned closed exchange #2 summarized");
    check(field(sum_res, "skipped").array().size() == 2,
          "instruction #1 and pinned #3 skipped automatically");
    check(ctx.archived().size() == 1 && ctx.archived()[0].id == 2, "block #2 archived");

    // 3. Read archived original block directly by integer ID (with pagination).
    const auto read_arch = ctx.read_block(2, {.offset = 0, .limit = 32});
    check(field(read_arch, "archived") == Value{true}, "archived flag true");
    check(field(read_arch, "truncated") == Value{true},
          "truncated true for 32-byte limit");
    const auto read_full = ctx.read_block(2, {.offset = 0, .limit = 16384});
    check(string_field(read_full, "content").find("function_call_output") !=
              std::string::npos,
          "archived original preserves full call + output");

    // 4. Checkpoint + reopen + suffix replay + restore across checkpoint!
    unwrap(ctx.checkpoint());

    // Append one more block AFTER checkpoint so suffix replay is also exercised.
    const auto b_tail = ctx.append({Value::object({{"role", Value{"assistant"}},
                                                   {"content", Value{"tail note"}}})},
                                   "provider.branch:tail");
    check(b_tail == 5, "next_id incremented past summary #4 to #5");
  }

  // Reopen from snapshot + replay suffix + restore archived block #2.
  {
    auto root =
        unwrap(RetainedState::open(std::make_unique<NativeJournalDirectory>(unwrap(
                                       NativeJournalDirectory::open(dir.string()))),
                                   "audit", h, cap));
    unwrap(root->confirm_recovery());
    struct Empty final : CustodyVerifier {
      Result<void> verify(std::span<const AttemptState> a) override {
        return a.empty() ? Result<void>::success()
                         : Result<void>::failure({ErrorCode::conflict});
      }
    } custody;
    unwrap(root->reconcile(custody));
    AuditLog log{*root};
    ContextStore reopened{log};
    check(reopened.blocks().size() == 4, "1, summary 4, pinned 3, tail 5 live");
    check(reopened.archived().size() == 1 && reopened.archived()[0].id == 2,
          "archived #2 preserved across checkpoint");
    check(reopened.blocks()[2].pinned, "pin on #3 preserved across checkpoint");

    // Read archived #2 after reopen (loaded from journal on demand!).
    const auto after_read = reopened.read_block(2);
    check(field(after_read, "archived") == Value{true} &&
              string_field(after_read, "content").find("\"c1\"") != std::string::npos,
          "archived #2 readable from journal after reopen");

    // Restore archived #2 back into chronological position.
    CompactRequest restore_req;
    restore_req.ids = {2};
    restore_req.op = CompactOp::restore;
    check(field(reopened.compact(restore_req), "ok") == Value{true}, "restore #2 ok");
    check(reopened.archived().empty(), "archive empty after restore");
    check(reopened.blocks().size() == 5 && reopened.blocks()[1].id == 2,
          "restored #2 reinserted in chronological order");

    // 5. replace_blocks programmatic override.
    const auto rep = reopened.replace_blocks(Value{
        Value::Array{Value::object({{"id", Value{Number{1}}},
                                    {"kind", Value{"instruction"}},
                                    {"items", Value{reopened.blocks()[0].items}}})}});
    check(field(rep, "ok") == Value{true} && reopened.blocks().size() == 1,
          "replace_blocks updated live set");
    check(reopened.archived().size() >= 1,
          "blocks dropped by replace_blocks archived for history");
  }

  std::cout << "context_test passed\n";
  return 0;
}
